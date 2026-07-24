//! Unit tests for bundled-profile setup orchestration.

use super::*;

fn test_home(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cdm-setup-{name}-{}", std::process::id()))
}

#[cfg(unix)]
#[test]
fn setup_detects_in_catalog_order_and_materializes_only_the_selection() {
    use std::os::unix::fs::PermissionsExt;

    let temp = test_home("selection");
    let home = temp.join("home");
    let bin = temp.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let executed = temp.join("candidate-executed");
    for executable in ["codex", "pi"] {
        let path = bin.join(executable);
        std::fs::write(
            &path,
            format!("#!/bin/sh\nprintf executed > {:?}\n", executed),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::create_dir_all(home.join(".copilot")).unwrap();
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
                ["pi", "codex", "copilot"]
            );
            assert_eq!(defaults, [true, true, true]);
            Ok(Some(vec![0, 1]))
        },
        &mut output,
    )
    .unwrap();

    let bundled = home.join(".cdm/profiles/bundled");
    assert!(bundled.join("pi.json").is_file());
    assert!(bundled.join("codex.json").is_file());
    assert!(!bundled.join("claude.json").exists());
    assert!(!bundled.join("copilot.json").exists());
    let base: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join(".cdm/base.json")).unwrap()).unwrap();
    assert_eq!(
        base["import"],
        serde_json::json!(["bundled/pi.json", "bundled/codex.json"])
    );
    assert!(!home.join(".cdm/setup-profiles.json").exists());
    assert!(!executed.exists(), "detection must not execute candidates");
    assert!(String::from_utf8(output)
        .unwrap()
        .contains("Enabled profiles: pi, codex"));
    let _ = std::fs::remove_dir_all(temp);
}

#[test]
fn setup_requires_a_terminal_before_detection_or_mutation() {
    let temp = test_home("non-terminal");
    let home = temp.join("home");
    std::fs::create_dir_all(&home).unwrap();

    let error = run_with(
        &home,
        std::ffi::OsStr::new(""),
        false,
        |_profiles, _defaults| -> io::Result<Option<Vec<usize>>> {
            panic!("selector must not run without a terminal")
        },
        &mut Vec::new(),
    )
    .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("interactive terminal"));
    assert!(!home.join(".cdm").exists());
    let _ = std::fs::remove_dir_all(temp);
}

#[test]
fn setup_with_no_detections_succeeds_without_mutation() {
    let temp = test_home("no-detections");
    let home = temp.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut output = Vec::new();

    run_with(
        &home,
        std::ffi::OsStr::new(""),
        true,
        |_profiles, _defaults| -> io::Result<Option<Vec<usize>>> {
            panic!("selector must not run without detections")
        },
        &mut output,
    )
    .unwrap();

    assert!(!home.join(".cdm").exists());
    assert!(String::from_utf8(output)
        .unwrap()
        .contains("nothing changed"));
    let _ = std::fs::remove_dir_all(temp);
}

#[cfg(unix)]
#[test]
fn setup_cancellation_preserves_managed_and_unrelated_bytes() {
    use std::os::unix::fs::PermissionsExt;

    let temp = test_home("cancel");
    let home = temp.join("home");
    let bin = temp.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let pi = bin.join("pi");
    std::fs::write(&pi, "#!/bin/sh\nexit 99\n").unwrap();
    std::fs::set_permissions(&pi, std::fs::Permissions::from_mode(0o700)).unwrap();
    config::materialize_setup_selection_in(&home, &["pi".into()]).unwrap();
    let base = home.join(".cdm/base.json");
    let bundled = home.join(".cdm/profiles/bundled/pi.json");
    let unrelated = home.join(".cdm/unrelated-state");
    std::fs::write(&unrelated, b"unrelated bytes\n").unwrap();
    let base_before = std::fs::read(&base).unwrap();
    let bundled_before = std::fs::read(&bundled).unwrap();

    let error = run_with(
        &home,
        bin.as_os_str(),
        true,
        |_profiles, _defaults| Ok(None),
        &mut Vec::new(),
    )
    .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert!(error.to_string().contains("cancelled; nothing changed"));
    assert_eq!(std::fs::read(base).unwrap(), base_before);
    assert_eq!(std::fs::read(bundled).unwrap(), bundled_before);
    assert_eq!(std::fs::read(unrelated).unwrap(), b"unrelated bytes\n");
    let _ = std::fs::remove_dir_all(temp);
}

#[cfg(unix)]
#[test]
fn setup_accepts_an_empty_selection_and_removes_known_profiles() {
    use std::os::unix::fs::PermissionsExt;

    let temp = test_home("empty-selection");
    let home = temp.join("home");
    let bin = temp.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let pi = bin.join("pi");
    std::fs::write(&pi, "#!/bin/sh\nexit 99\n").unwrap();
    std::fs::set_permissions(&pi, std::fs::Permissions::from_mode(0o700)).unwrap();
    config::materialize_setup_selection_in(&home, &["pi".into()]).unwrap();

    run_with(
        &home,
        bin.as_os_str(),
        true,
        |_profiles, _defaults| Ok(Some(Vec::new())),
        &mut Vec::new(),
    )
    .unwrap();

    assert!(!home.join(".cdm/profiles/bundled/pi.json").exists());
    let base: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join(".cdm/base.json")).unwrap()).unwrap();
    assert_eq!(base["import"], serde_json::json!([]));
    let _ = std::fs::remove_dir_all(temp);
}

#[cfg(unix)]
#[test]
fn setup_rerun_removes_deselected_known_files_and_preserves_user_files() {
    use std::os::unix::fs::PermissionsExt;

    let temp = test_home("rerun");
    let home = temp.join("home");
    let bin = temp.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    for executable in ["pi", "claude", "codex"] {
        let path = bin.join(executable);
        std::fs::write(&path, "#!/bin/sh\nexit 99\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    run_with(
        &home,
        bin.as_os_str(),
        true,
        |_profiles, _defaults| Ok(Some(vec![0, 2])),
        &mut Vec::new(),
    )
    .unwrap();
    let profiles = home.join(".cdm/profiles");
    let bundled = profiles.join("bundled");
    let global = home.join(".cdm/config.json");
    let personal = profiles.join("personal.json");
    let unknown = bundled.join("unknown.json");
    std::fs::write(&global, b"keep global bytes\n").unwrap();
    std::fs::write(&personal, b"keep personal bytes\n").unwrap();
    std::fs::write(&unknown, b"keep unknown bytes\n").unwrap();

    run_with(
        &home,
        bin.as_os_str(),
        true,
        |_profiles, _defaults| Ok(Some(vec![1])),
        &mut Vec::new(),
    )
    .unwrap();

    assert!(!bundled.join("pi.json").exists());
    assert!(bundled.join("claude.json").is_file());
    assert!(!bundled.join("codex.json").exists());
    assert_eq!(std::fs::read(&global).unwrap(), b"keep global bytes\n");
    assert_eq!(std::fs::read(&personal).unwrap(), b"keep personal bytes\n");
    assert_eq!(std::fs::read(&unknown).unwrap(), b"keep unknown bytes\n");
    let base: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join(".cdm/base.json")).unwrap()).unwrap();
    assert_eq!(base["import"], serde_json::json!(["bundled/claude.json"]));
    let _ = std::fs::remove_dir_all(temp);
}

#[cfg(unix)]
#[test]
fn setup_rejects_an_unrecognized_base_before_writing_profiles() {
    use std::os::unix::fs::PermissionsExt;

    let temp = test_home("unrecognized-base");
    let home = temp.join("home");
    let bundled = home.join(".cdm/profiles/bundled");
    let bin = temp.join("bin");
    std::fs::create_dir_all(&bundled).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    for directory in [
        home.join(".cdm"),
        home.join(".cdm/profiles"),
        bundled.clone(),
    ] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let base = home.join(".cdm/base.json");
    std::fs::write(&base, b"{\"import\":[\"personal.json\"]}\n").unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o600)).unwrap();
    let codex = bin.join("codex");
    std::fs::write(&codex, "#!/bin/sh\nexit 99\n").unwrap();
    std::fs::set_permissions(&codex, std::fs::Permissions::from_mode(0o700)).unwrap();

    let error = run_with(
        &home,
        bin.as_os_str(),
        true,
        |_profiles, _defaults| Ok(Some(vec![0])),
        &mut Vec::new(),
    )
    .unwrap_err();

    assert!(matches!(
        error.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::PermissionDenied
    ));
    assert_eq!(
        std::fs::read(&base).unwrap(),
        b"{\"import\":[\"personal.json\"]}\n"
    );
    assert!(!bundled.join("codex.json").exists());
    let _ = std::fs::remove_dir_all(temp);
}

#[cfg(unix)]
#[test]
fn setup_rejects_unsafe_existing_base_files_before_mutation() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, PermissionsExt};

    for case in ["parent-mode", "mode", "symlink", "hard-link", "fifo"] {
        let temp = test_home(&format!("unsafe-base-{case}"));
        let home = temp.join("home");
        let bin = temp.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let pi = bin.join("pi");
        std::fs::write(&pi, "#!/bin/sh\nexit 99\n").unwrap();
        std::fs::set_permissions(&pi, std::fs::Permissions::from_mode(0o700)).unwrap();
        config::materialize_setup_selection_in(&home, &["pi".into()]).unwrap();
        let base = home.join(".cdm/base.json");
        let pi_profile = home.join(".cdm/profiles/bundled/pi.json");
        let profile_before = std::fs::read(&pi_profile).unwrap();

        match case {
            "parent-mode" => {
                std::fs::set_permissions(home.join(".cdm"), std::fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
            "mode" => {
                std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            "symlink" => {
                let target = temp.join("base-target.json");
                std::fs::rename(&base, &target).unwrap();
                symlink(&target, &base).unwrap();
            }
            "hard-link" => {
                std::fs::hard_link(&base, temp.join("base-hard-link.json")).unwrap();
            }
            "fifo" => {
                std::fs::remove_file(&base).unwrap();
                let fifo = CString::new(base.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
            }
            _ => unreachable!(),
        }

        let error = run_with(
            &home,
            bin.as_os_str(),
            true,
            |_profiles, _defaults| Ok(Some(vec![0])),
            &mut Vec::new(),
        )
        .unwrap_err();

        if case == "symlink" {
            assert!(
                error.to_string().contains("cannot securely open"),
                "{case}: {error}"
            );
        } else {
            assert_eq!(
                error.kind(),
                io::ErrorKind::PermissionDenied,
                "{case}: {error}"
            );
        }
        assert_eq!(std::fs::read(&pi_profile).unwrap(), profile_before);
        let _ = std::fs::remove_dir_all(temp);
    }
}

#[cfg(unix)]
#[test]
fn setup_rejects_an_unsafe_bundled_directory_without_touching_its_target() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp = test_home("unsafe");
    let home = temp.join("home");
    let profiles = home.join(".cdm/profiles");
    let outside = temp.join("outside");
    let bin = temp.join("bin");
    std::fs::create_dir_all(&profiles).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    let pi = bin.join("pi");
    std::fs::write(&pi, "#!/bin/sh\nexit 99\n").unwrap();
    std::fs::set_permissions(&pi, std::fs::Permissions::from_mode(0o700)).unwrap();
    for directory in [home.join(".cdm"), profiles.clone()] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(outside.join("sentinel"), b"unchanged\n").unwrap();
    symlink(&outside, profiles.join("bundled")).unwrap();

    let error = run_with(
        &home,
        bin.as_os_str(),
        true,
        |_profiles, _defaults| Ok(Some(vec![0])),
        &mut Vec::new(),
    )
    .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(
        std::fs::read(outside.join("sentinel")).unwrap(),
        b"unchanged\n"
    );
    assert!(!outside.join("pi.json").exists());
    let _ = std::fs::remove_dir_all(temp);
}
