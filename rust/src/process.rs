//! Child-process supervision shared by every host sandbox adapter.
//!
//! The supervisor owns a process group, terminal foreground transfer, signal
//! forwarding, descendant teardown, and conversion of Unix wait status into
//! CDM's documented exit-code convention.  Adapters only construct a
//! [`Command`]; they do not implement lifecycle policy themselves.

use std::io;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Child;
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

const DEFAULT_SIGNAL_GRACE: Duration = Duration::from_secs(5);
const DEFAULT_DESCENDANT_GRACE: Duration = Duration::from_millis(250);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const FORWARDED_SIGNALS: [libc::c_int; 4] =
    [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

static ACTIVE_SIGNAL: AtomicI32 = AtomicI32::new(0);
static SIGNAL_COUNT: AtomicU32 = AtomicU32::new(0);
static SUPERVISOR_LOCK: Mutex<()> = Mutex::new(());

/// Observable child termination without losing the originating Unix signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildStatus {
    pub exit_code: i32,
    pub signal: Option<i32>,
}

impl ChildStatus {
    pub fn exited(exit_code: i32) -> Self {
        Self {
            exit_code,
            signal: None,
        }
    }
}

impl PartialEq<i32> for ChildStatus {
    fn eq(&self, other: &i32) -> bool {
        self.exit_code == *other
    }
}

/// Runs `command` in a dedicated process group and returns its exact CDM exit
/// code (`128 + signal` for signal termination) plus the originating signal.
pub fn run(command: &mut Command) -> io::Result<ChildStatus> {
    Supervisor::default().run(command)
}

#[derive(Clone, Copy)]
struct Supervisor {
    signal_grace: Duration,
    descendant_grace: Duration,
    poll_interval: Duration,
}

impl Default for Supervisor {
    fn default() -> Self {
        Self {
            signal_grace: DEFAULT_SIGNAL_GRACE,
            descendant_grace: DEFAULT_DESCENDANT_GRACE,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }
}

impl Supervisor {
    fn run(self, command: &mut Command) -> io::Result<ChildStatus> {
        let _exclusive = lock_supervisor()?;
        let signals = SignalHandlers::install()?;
        ACTIVE_SIGNAL.store(0, Ordering::SeqCst);
        SIGNAL_COUNT.store(0, Ordering::SeqCst);

        // CommandExt::process_group is implemented by the standard library's
        // spawn path and does not require CDM to run user code after fork.
        command.process_group(0);
        let child = command.spawn()?;
        let mut child = ChildGuard::new(child)?;
        let terminal = TerminalForeground::transfer(child.process_group())?;
        let status = self.wait(&mut child)?;

        // The group leader can exit while grandchildren remain alive. Always
        // drain the group before returning so proxy/runtime/worktree owners in
        // main.rs cannot be dropped while sandbox descendants still run.
        terminate_group(
            child.process_group(),
            self.descendant_grace,
            self.poll_interval,
        );
        child.disarm();
        drop(terminal);
        drop(signals);
        Ok(child_status(status))
    }

    fn wait(self, child: &mut ChildGuard) -> io::Result<ExitStatus> {
        let mut first_forwarded_at = None;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }

            let count = SIGNAL_COUNT.swap(0, Ordering::SeqCst);
            let signal = ACTIVE_SIGNAL.swap(0, Ordering::SeqCst);
            if signal != 0 {
                let force = count > 1 || first_forwarded_at.is_some();
                signal_group(
                    child.process_group(),
                    if force { libc::SIGKILL } else { signal },
                );
                first_forwarded_at.get_or_insert_with(Instant::now);
            }
            if first_forwarded_at.is_some_and(|started| started.elapsed() >= self.signal_grace) {
                signal_group(child.process_group(), libc::SIGKILL);
            }
            std::thread::sleep(self.poll_interval);
        }
    }
}

fn lock_supervisor() -> io::Result<MutexGuard<'static, ()>> {
    SUPERVISOR_LOCK
        .lock()
        .map_err(|_| io::Error::other("process supervisor lock was poisoned"))
}

extern "C" fn remember_signal(signal: libc::c_int) {
    ACTIVE_SIGNAL.store(signal, Ordering::SeqCst);
    SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst);
}

struct SignalHandlers(Vec<(libc::c_int, libc::sigaction)>);

impl SignalHandlers {
    fn install() -> io::Result<Self> {
        let mut previous = Vec::new();
        for signal in FORWARDED_SIGNALS {
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = remember_signal as usize;
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            if unsafe { libc::sigaction(signal, &action, &mut old) } != 0 {
                restore_signal_handlers(&previous);
                return Err(io::Error::last_os_error());
            }
            previous.push((signal, old));
        }
        Ok(Self(previous))
    }
}

impl Drop for SignalHandlers {
    fn drop(&mut self) {
        restore_signal_handlers(&self.0);
    }
}

fn restore_signal_handlers(previous: &[(libc::c_int, libc::sigaction)]) {
    for (signal, action) in previous.iter().rev() {
        unsafe { libc::sigaction(*signal, action, std::ptr::null_mut()) };
    }
}

struct ChildGuard {
    child: Child,
    process_group: libc::pid_t,
    armed: bool,
}

impl ChildGuard {
    fn new(child: Child) -> io::Result<Self> {
        let process_group = libc::pid_t::try_from(child.id())
            .map_err(|_| io::Error::other("child pid does not fit platform pid_t"))?;
        Ok(Self {
            child,
            process_group,
            armed: true,
        })
    }

    fn process_group(&self) -> libc::pid_t {
        self.process_group
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.armed {
            signal_group(self.process_group, libc::SIGKILL);
            loop {
                match self.child.wait() {
                    Ok(_) => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        }
    }
}

struct TerminalForeground {
    previous: Option<libc::pid_t>,
}

impl TerminalForeground {
    fn transfer(process_group: libc::pid_t) -> io::Result<Self> {
        if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
            return Ok(Self { previous: None });
        }
        let previous = unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) };
        if previous < 0 {
            return Err(io::Error::last_os_error());
        }
        if previous != unsafe { libc::getpgrp() } {
            return Ok(Self { previous: None });
        }
        set_terminal_process_group(process_group)?;
        Ok(Self {
            previous: Some(previous),
        })
    }
}

impl Drop for TerminalForeground {
    fn drop(&mut self) {
        if let Some(previous) = self.previous {
            let _ = set_terminal_process_group(previous);
        }
    }
}

fn set_terminal_process_group(process_group: libc::pid_t) -> io::Result<()> {
    let mut blocked: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut blocked);
        libc::sigaddset(&mut blocked, libc::SIGTTOU);
    }
    if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut old) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let result = unsafe { libc::tcsetpgrp(libc::STDIN_FILENO, process_group) };
    let error = io::Error::last_os_error();
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
    if result == 0 {
        Ok(())
    } else {
        Err(error)
    }
}

fn terminate_group(process_group: libc::pid_t, grace: Duration, poll: Duration) {
    if !group_exists(process_group) {
        return;
    }
    signal_group(process_group, libc::SIGTERM);
    let deadline = Instant::now() + grace;
    while group_exists(process_group) && Instant::now() < deadline {
        std::thread::sleep(poll);
    }
    if group_exists(process_group) {
        signal_group(process_group, libc::SIGKILL);
        let deadline = Instant::now() + grace;
        while group_exists(process_group) && Instant::now() < deadline {
            std::thread::sleep(poll);
        }
    }
}

fn group_exists(process_group: libc::pid_t) -> bool {
    let result = unsafe { libc::kill(-process_group, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn signal_group(process_group: libc::pid_t, signal: libc::c_int) {
    unsafe {
        libc::kill(-process_group, signal);
    }
}

fn child_status(status: ExitStatus) -> ChildStatus {
    if let Some(code) = status.code() {
        ChildStatus::exited(code)
    } else if let Some(signal) = status.signal() {
        ChildStatus {
            exit_code: 128 + signal,
            signal: Some(signal),
        }
    } else {
        ChildStatus::exited(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn test_supervisor() -> Supervisor {
        Supervisor {
            signal_grace: Duration::from_millis(100),
            descendant_grace: Duration::from_millis(100),
            poll_interval: Duration::from_millis(2),
        }
    }

    fn unique_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cdm-process-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    #[test]
    fn preserves_normal_and_signaled_exit_status() {
        let mut exit = Command::new("/bin/sh");
        exit.args(["-c", "exit 37"]);
        assert_eq!(test_supervisor().run(&mut exit).unwrap(), 37);

        let mut signal = Command::new("/bin/sh");
        signal.args(["-c", "kill -TERM $$"]);
        assert_eq!(test_supervisor().run(&mut signal).unwrap(), 143);
    }

    #[test]
    fn terminates_descendants_after_group_leader_exits() {
        let pid_file = unique_path("descendant");
        let probe_file = unique_path("descendant-probe");
        let script = format!(
            "(trap '' TERM; trap 'printf live > {}' USR1; while :; do sleep 1; done) & printf '%s' $! > '{}'; exit 23",
            probe_file.display(),
            pid_file.display(),
        );
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &script]);
        assert_eq!(test_supervisor().run(&mut command).unwrap(), 23);

        let pid = fs::read_to_string(&pid_file).unwrap();
        let pid: libc::pid_t = pid.parse().unwrap();
        unsafe { libc::kill(pid, libc::SIGUSR1) };
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            !probe_file.exists(),
            "descendant process remained executable"
        );
        fs::remove_file(pid_file).unwrap();
        let _ = fs::remove_file(probe_file);
    }

    #[test]
    fn spawn_failure_does_not_leave_signal_handlers_installed() {
        let mut command = Command::new("/definitely/not/a/cdm-command");
        assert_eq!(
            test_supervisor().run(&mut command).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );

        let mut valid = Command::new("/bin/sh");
        valid.args(["-c", "exit 0"]);
        assert_eq!(test_supervisor().run(&mut valid).unwrap(), 0);
    }
}
