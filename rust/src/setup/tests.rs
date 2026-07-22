//! Unit tests for guided setup detection and registry orchestration.

use super::*;

fn test_home(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cdm-setup-{name}-{}", std::process::id()))
}

#[cfg(unix)]
#[test]
fn detection_is_catalog_ordered_and_never_executes_tools() {
    use std::os::unix::fs::PermissionsExt;

    let temp = test_home("detect");
    let home = temp.join("home");
    let bin = temp.join("bin");
    let sentinel = temp.join("executed");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(home.join(".pi/agent")).unwrap();
    for executable in ["copilot", "claude"] {
        let path = bin.join(executable);
        std::fs::write(&path, format!("#!/bin/sh\ntouch {:?}\n", sentinel)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let detected = detect_profiles(&home, bin.as_os_str());

    assert_eq!(
        detected
            .iter()
            .map(|profile| profile.id)
            .collect::<Vec<_>>(),
        ["pi", "claude", "copilot"]
    );
    assert!(!sentinel.exists());
    let _ = std::fs::remove_dir_all(temp);
}

#[cfg(unix)]
#[test]
fn selected_detected_profiles_are_persisted_with_all_defaults_checked() {
    use std::os::unix::fs::PermissionsExt;

    let temp = test_home("selection");
    let home = temp.join("home");
    let bin = temp.join("bin");
    std::fs::create_dir_all(home.join(".cdm")).unwrap();
    std::fs::set_permissions(home.join(".cdm"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let global_config = home.join(".cdm/config.json");
    std::fs::write(&global_config, b"keep global config bytes\n").unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    for executable in ["pi", "claude", "codex"] {
        let path = bin.join(executable);
        std::fs::write(&path, "#!/bin/sh\nexit 99\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut output = Vec::new();

    run_with(
        &home,
        bin.as_os_str(),
        true,
        |profiles, defaults| {
            assert_eq!(
                profiles
                    .iter()
                    .map(|profile| profile.id)
                    .collect::<Vec<_>>(),
                ["pi", "claude", "codex"]
            );
            assert_eq!(defaults, [true, true, true]);
            Ok(Some(vec![0, 2]))
        },
        &mut output,
    )
    .unwrap();

    assert_eq!(
        config::read_setup_profiles_in(&home).unwrap(),
        ["codex", "pi"]
    );
    assert_eq!(
        std::fs::read(&global_config).unwrap(),
        b"keep global config bytes\n"
    );
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Enabled profiles: codex, pi"));
    assert!(output.contains("setup-profiles.json"));
    let _ = std::fs::remove_dir_all(temp);
}

#[test]
fn no_detection_does_not_create_registry_state() {
    let temp = test_home("none");
    let home = temp.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut output = Vec::new();

    run_with(
        &home,
        OsStr::new(""),
        true,
        |_, _| panic!("selector must not be shown"),
        &mut output,
    )
    .unwrap();

    assert!(!config::setup_profiles_path(&home).exists());
    assert!(String::from_utf8(output)
        .unwrap()
        .contains("No supported coding harnesses detected"));
    let _ = std::fs::remove_dir_all(temp);
}

#[cfg(unix)]
#[test]
fn cancellation_and_non_tty_preserve_previous_registry_bytes() {
    use std::os::unix::fs::PermissionsExt;

    let temp = test_home("preserve");
    let home = temp.join("home");
    let bin = temp.join("bin");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    let executable = bin.join("pi");
    std::fs::write(&executable, "#!/bin/sh\nexit 99\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let registry = config::write_setup_profiles_in(&home, &["pi".into()]).unwrap();
    let before = std::fs::read(&registry).unwrap();

    let cancel = run_with(
        &home,
        bin.as_os_str(),
        true,
        |_, _| Ok(None),
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(cancel.kind(), io::ErrorKind::Interrupted);
    assert_eq!(std::fs::read(&registry).unwrap(), before);

    let non_tty = run_with(
        &home,
        bin.as_os_str(),
        false,
        |_, _| panic!("selector must not be shown"),
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(non_tty.kind(), io::ErrorKind::InvalidInput);
    assert!(non_tty.to_string().contains("interactive terminal"));
    assert_eq!(std::fs::read(&registry).unwrap(), before);
    let _ = std::fs::remove_dir_all(temp);
}
