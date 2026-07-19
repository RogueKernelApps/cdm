//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;
use std::os::unix::fs::PermissionsExt;

fn runtime() -> PathBuf {
    crate::sandbox::prepare_runtime_dir().unwrap()
}

#[test]
fn monitor_log_is_private_and_below_runtime() {
    let runtime = runtime();
    let monitor = Monitor::new(&runtime).unwrap();
    assert!(monitor.log_path().starts_with(&runtime));
    assert_eq!(
        fs::metadata(monitor.log_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(monitor);
    fs::remove_dir(runtime).unwrap();
}

#[test]
fn monitor_rejects_a_symlink_runtime() {
    use std::os::unix::fs::symlink;
    let runtime = runtime();
    let parent = runtime.parent().unwrap().to_path_buf();
    let link = parent.join(format!("monitor-hostile-{}", std::process::id()));
    symlink(&runtime, &link).unwrap();
    let error = match Monitor::new(&link) {
        Ok(_) => panic!("symlink runtime unexpectedly accepted"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    fs::remove_file(link).unwrap();
    fs::remove_dir(runtime).unwrap();
}

#[test]
fn monitor_rejects_a_runtime_with_unsafe_permissions() {
    let runtime = runtime();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o777)).unwrap();
    let error = match Monitor::new(&runtime) {
        Ok(_) => panic!("unsafe runtime permissions unexpectedly accepted"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir(runtime).unwrap();
}

#[test]
fn monitor_events_cannot_inject_extra_log_lines() {
    let runtime = runtime();
    let monitor = Monitor::new(&runtime).unwrap();
    monitor.log_event("network\nFORGED", "blocked\r\nFORGED");
    let content = fs::read_to_string(monitor.log_path()).unwrap();
    assert_eq!(content.lines().count(), 2);
    drop(monitor);
    fs::remove_dir(runtime).unwrap();
}

#[test]
fn explicit_stop_removes_the_log_and_is_idempotent() {
    let runtime = runtime();
    let mut monitor = Monitor::new(&runtime).unwrap();
    let log = monitor.log_path().to_path_buf();
    monitor.stop().unwrap();
    assert!(!log.exists());
    monitor.stop().unwrap();
    fs::remove_dir(runtime).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn hostile_path_is_only_an_osascript_argument() {
    let hostile = Path::new("/tmp/a'; do shell script \"touch /tmp/pwned\"; '");
    assert!(!OPEN_TERMINAL_SCRIPT.contains(hostile.to_string_lossy().as_ref()));
    assert!(OPEN_TERMINAL_SCRIPT.contains("quoted form of logPath"));
}

#[test]
fn monitor_helper_environment_is_allowlisted() {
    let mut command = Command::new("/usr/bin/env");
    sanitize_gui_environment(&mut command);
    let output = command.output().unwrap();
    assert!(output.status.success());
    let output = String::from_utf8(output.stdout).unwrap();
    for line in output.lines() {
        let key = line.split_once('=').unwrap().0;
        assert!(
            key == "LANG" || key == "LC_ALL" || GUI_ENV_ALLOWLIST.contains(&key),
            "unexpected host environment variable inherited: {key}"
        );
    }
    assert!(!output.lines().any(|line| line.starts_with("PATH=")));
    assert!(!output.lines().any(|line| line.starts_with("DYLD_")));
    assert!(!output.lines().any(|line| line.starts_with("LD_")));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_viewer_candidates_and_tail_are_fixed_absolute_paths() {
    assert!(Path::new(LINUX_TAIL).is_absolute());
    assert!(LINUX_TERMINALS
        .iter()
        .all(|(path, _)| Path::new(path).is_absolute()));
    crate::trusted_exec::fixed(Path::new(LINUX_TAIL), "monitor tail").unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn macos_monitor_helpers_are_fixed_trusted_executables() {
    for (path, label) in [
        (MACOS_TERMINAL_EXECUTABLE, "Terminal monitor viewer"),
        ("/usr/bin/osascript", "AppleScript launcher"),
        ("/usr/bin/log", "macOS log"),
        ("/usr/bin/tail", "monitor tail"),
    ] {
        crate::trusted_exec::fixed(Path::new(path), label).unwrap();
    }
}
