//! Real-time monitoring of sandbox denial events.
//!
//! Monitor artifacts live inside the trusted per-invocation runtime. The
//! terminal launcher receives paths as argv, never as interpolated shell or
//! AppleScript source, and every child started here is reaped during teardown.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

static NEXT_MONITOR_ID: AtomicU64 = AtomicU64::new(0);

const GUI_ENV_ALLOWLIST: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
    "XDG_CURRENT_DESKTOP",
    "__CF_USER_TEXT_ENCODING",
];

#[cfg(target_os = "linux")]
const LINUX_TERMINALS: &[(&str, &[&str])] = &[
    ("/usr/bin/xterm", &["-e"]),
    ("/usr/bin/gnome-terminal", &["--wait", "--"]),
    ("/usr/bin/konsole", &["--nofork", "-e"]),
];

#[cfg(target_os = "linux")]
const LINUX_TAIL: &str = "/usr/bin/tail";

#[cfg(target_os = "macos")]
const MACOS_TERMINAL_EXECUTABLE: &str =
    "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal";

/// Monitor for real-time sandbox denial logging.
pub struct Monitor {
    log_child: Option<Child>,
    term_child: Option<Child>,
    #[cfg(target_os = "macos")]
    terminal_window_id: Option<u64>,
    log_path: PathBuf,
    log_file: Arc<Mutex<File>>,
}

impl Monitor {
    /// Creates a monitor log below CDM's already-validated private runtime.
    pub fn new(runtime_dir: &Path) -> io::Result<Self> {
        crate::sandbox::validate_private_runtime_dir(runtime_dir)?;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let id = NEXT_MONITOR_ID.fetch_add(1, Ordering::Relaxed);
        let log_path = runtime_dir.join(format!("monitor-{}-{ts}-{id}.log", std::process::id()));

        let mut options = OpenOptions::new();
        options.write(true).append(true).create_new(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut log_file = options.open(&log_path)?;
        writeln!(log_file, "[cdm-monitor] session started")?;
        log_file.sync_all()?;

        Ok(Self {
            log_child: None,
            term_child: None,
            #[cfg(target_os = "macos")]
            terminal_window_id: None,
            log_path,
            log_file: Arc::new(Mutex::new(log_file)),
        })
    }

    pub fn log_handle(&self) -> Arc<Mutex<File>> {
        Arc::clone(&self.log_file)
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn start(&mut self) -> io::Result<()> {
        self.open_terminal()?;

        #[cfg(target_os = "macos")]
        self.start_macos()?;

        Ok(())
    }

    pub fn stop(&mut self) -> io::Result<()> {
        let mut failure = None;
        record_failure(&mut failure, reap(&mut self.log_child));
        record_failure(&mut failure, reap(&mut self.term_child));

        #[cfg(target_os = "macos")]
        if let Some(window_id) = self.terminal_window_id.take() {
            record_failure(&mut failure, close_macos_terminal(window_id));
        }
        match fs::remove_file(&self.log_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => record_failure(&mut failure, Err(error)),
        }
        failure.map_or(Ok(()), Err)
    }

    #[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
    pub fn log_event(&self, category: &str, message: &str) {
        if let Ok(mut file) = self.log_file.lock() {
            let category = one_line(category);
            let message = one_line(message);
            let _ = writeln!(file, "[cdm-monitor] [{category}] {message}");
        }
    }

    fn open_terminal(&mut self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            self.terminal_window_id = Some(open_macos_terminal(&self.log_path)?);
        }

        #[cfg(target_os = "linux")]
        {
            // Use only launch forms whose process remains attached to the
            // created terminal, so CDM can terminate and reap it reliably.
            // Absolute paths prevent an untrusted PATH from selecting a host
            // executable before the sandbox starts.
            let tail = crate::trusted_exec::fixed(Path::new(LINUX_TAIL), "monitor tail")?;
            for (terminal, prefix) in LINUX_TERMINALS {
                let executable =
                    match crate::trusted_exec::fixed(Path::new(terminal), "monitor terminal") {
                        Ok(executable) => executable,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(_) => continue,
                    };
                let mut command = executable.command()?;
                sanitize_gui_environment(&mut command);
                command
                    .args(*prefix)
                    .arg(tail.path()?)
                    .arg("-f")
                    .arg(&self.log_path);
                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                if let Ok(child) = command.spawn() {
                    self.term_child = Some(child);
                    break;
                }
            }
            if self.term_child.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no lifecycle-safe terminal emulator found (tried xterm, gnome-terminal, konsole)",
                ));
            }
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn start_macos(&mut self) -> io::Result<()> {
        let log_file = self.log_file.lock().map_err(|_| {
            io::Error::other("monitor log lock was poisoned before log stream startup")
        })?;
        let executable = crate::trusted_exec::fixed(Path::new("/usr/bin/log"), "macOS log")?;
        let mut command = executable.command()?;
        sanitize_gui_environment(&mut command);
        let child = command
            .arg("stream")
            .arg("--predicate")
            .arg("eventMessage CONTAINS \"deny\" AND subsystem == \"com.apple.sandbox\"")
            .arg("--style")
            .arg("compact")
            .stdout(Stdio::from(log_file.try_clone()?))
            .stderr(Stdio::from(log_file.try_clone()?))
            .spawn()?;
        drop(log_file);
        self.log_event("info", "streaming Seatbelt denials...");
        self.log_child = Some(child);
        Ok(())
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn reap(child: &mut Option<Child>) -> io::Result<()> {
    let mut failure = None;
    if let Some(mut child) = child.take() {
        match child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                record_kill_failure(&mut failure, child.kill());
                record_failure(&mut failure, child.wait().map(|_| ()));
            }
            Err(error) => {
                record_failure(&mut failure, Err(error));
                record_kill_failure(&mut failure, child.kill());
                record_failure(&mut failure, child.wait().map(|_| ()));
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

fn record_kill_failure(failure: &mut Option<io::Error>, result: io::Result<()>) {
    match result {
        // The child may exit between try_wait and kill; wait still reaps it.
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
        result => record_failure(failure, result),
    }
}

fn record_failure(failure: &mut Option<io::Error>, result: io::Result<()>) {
    if let Err(error) = result {
        if failure.is_none() {
            *failure = Some(error);
        }
    }
}

fn one_line(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\r' | '\n' => ' ',
            _ => character,
        })
        .collect()
}

fn sanitize_gui_environment(command: &mut Command) {
    crate::trusted_exec::sanitize_host_environment(command);
    for variable in GUI_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(variable) {
            command.env(variable, value);
        }
    }
}

#[cfg(target_os = "macos")]
const OPEN_TERMINAL_SCRIPT: &str = r#"on run argv
set logPath to item 1 of argv
tell application "/System/Applications/Utilities/Terminal.app"
    activate
    do script "exec /usr/bin/tail -f -- " & quoted form of logPath
    return id of front window
end tell
end run"#;

#[cfg(target_os = "macos")]
fn open_macos_terminal(log_path: &Path) -> io::Result<u64> {
    crate::trusted_exec::fixed(
        Path::new(MACOS_TERMINAL_EXECUTABLE),
        "Terminal monitor viewer",
    )?;
    crate::trusted_exec::fixed(Path::new("/usr/bin/tail"), "monitor tail")?;
    let executable =
        crate::trusted_exec::fixed(Path::new("/usr/bin/osascript"), "AppleScript launcher")?;
    let mut command = executable.command()?;
    sanitize_gui_environment(&mut command);
    let output = command
        .arg("-e")
        .arg(OPEN_TERMINAL_SCRIPT)
        .arg("--")
        .arg(log_path)
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Terminal monitor launcher exited with {}",
            output.status
        )));
    }
    let id = String::from_utf8(output.stdout)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Terminal window id"))?;
    id.trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Terminal window id"))
}

#[cfg(target_os = "macos")]
fn close_macos_terminal(window_id: u64) -> io::Result<()> {
    const SCRIPT: &str = r#"on run argv
set targetId to item 1 of argv as integer
tell application "/System/Applications/Utilities/Terminal.app"
    repeat with candidate in windows
        if id of candidate is targetId then
            close candidate
            exit repeat
        end if
    end repeat
end tell
end run"#;
    let executable =
        crate::trusted_exec::fixed(Path::new("/usr/bin/osascript"), "AppleScript cleanup")?;
    let mut command = executable.command()?;
    sanitize_gui_environment(&mut command);
    let status = command
        .arg("-e")
        .arg(SCRIPT)
        .arg("--")
        .arg(window_id.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "Terminal monitor cleanup exited with {status}"
        )))
    }
}

/// Writes a domain-block event to the monitor's trusted log handle.
pub fn write_block_event(log_handle: &Arc<Mutex<File>>, domain: &str, reason: &str) {
    if let Ok(mut file) = log_handle.lock() {
        let domain = one_line(domain);
        let reason = one_line(reason);
        let _ = writeln!(file, "[cdm-monitor] [network] BLOCKED {domain}: {reason}");
    }
}

#[cfg(test)]
mod tests;
