//! Unit tests for bundled-profile setup orchestration.

use super::*;

fn test_home(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cdm-setup-{name}-{}", std::process::id()))
}

#[cfg(unix)]
#[test]
fn setup_refreshes_the_complete_catalog_and_preserves_unmanaged_files() {
    use std::os::unix::fs::PermissionsExt;

    let temp = test_home("refresh");
    let home = temp.join("home");
    let profiles = home.join(".cdm/profiles");
    let bundled = profiles.join("bundled");
    std::fs::create_dir_all(&bundled).unwrap();
    for directory in [home.join(".cdm"), profiles.clone(), bundled.clone()] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let global = home.join(".cdm/config.json");
    let personal = profiles.join("personal.json");
    let unknown = bundled.join("unknown.json");
    std::fs::write(&global, b"keep global bytes\n").unwrap();
    std::fs::write(&personal, b"keep personal bytes\n").unwrap();
    std::fs::write(&unknown, b"keep unknown bytes\n").unwrap();
    std::fs::write(bundled.join("pi.json"), b"replace managed bytes\n").unwrap();
    let mut output = Vec::new();

    run_with(&home, &mut output).unwrap();

    assert_eq!(std::fs::read(&global).unwrap(), b"keep global bytes\n");
    assert_eq!(std::fs::read(&personal).unwrap(), b"keep personal bytes\n");
    assert_eq!(std::fs::read(&unknown).unwrap(), b"keep unknown bytes\n");
    for id in ["pi", "claude", "codex", "copilot"] {
        let path = bundled.join(format!("{id}.json"));
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(json["_warning"].as_str().unwrap().contains("may overwrite"));
    }
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Bundled profiles refreshed:"));
    assert!(output.contains("pi, claude, codex, copilot"));
    let _ = std::fs::remove_dir_all(temp);
}

#[cfg(unix)]
#[test]
fn setup_rejects_an_unsafe_bundled_directory_without_touching_its_target() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp = test_home("unsafe");
    let home = temp.join("home");
    let profiles = home.join(".cdm/profiles");
    let outside = temp.join("outside");
    std::fs::create_dir_all(&profiles).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    for directory in [home.join(".cdm"), profiles.clone()] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(outside.join("sentinel"), b"unchanged\n").unwrap();
    symlink(&outside, profiles.join("bundled")).unwrap();

    let error = run_with(&home, &mut Vec::new()).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(
        std::fs::read(outside.join("sentinel")).unwrap(),
        b"unchanged\n"
    );
    assert!(!outside.join("pi.json").exists());
    let _ = std::fs::remove_dir_all(temp);
}
