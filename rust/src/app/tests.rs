//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

fn fixture() -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "cdm-app-test-{}-{}",
        std::process::id(),
        FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let home = root.join("home");
    let bundle = root.join("Fixture Product.app");
    let contents = bundle.join("Contents");
    let executable = contents.join("MacOS/fixture-app");
    std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
    std::fs::create_dir_all(home.join("Library/Caches/fixture-product-runtime")).unwrap();
    std::fs::create_dir_all(home.join("Library/Caches/unrelated-product")).unwrap();
    std::fs::create_dir_all(home.join(".fixture")).unwrap();
    std::fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(
        contents.join("Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.cdm.fixture-product</string>
<key>CFBundleExecutable</key><string>fixture-app</string>
<key>CFBundleDisplayName</key><string>Fixture Product</string>
</dict></plist>"#,
    )
    .unwrap();
    (bundle, home)
}

#[test]
fn existing_app_bundle_as_command_activates_app_mode() {
    let (bundle, _) = fixture();
    let command = vec![
        bundle.clone().into_os_string(),
        "--project".into(),
        "fixture".into(),
    ];

    assert_eq!(bundle_from_command(&command), Some(bundle.clone()));
    let _ = std::fs::remove_dir_all(bundle.parent().unwrap());
}

#[test]
fn ordinary_commands_and_missing_app_paths_do_not_activate_app_mode() {
    let root = std::env::temp_dir().join(format!(
        "cdm-app-command-test-{}-{}",
        std::process::id(),
        FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let ordinary = vec![std::ffi::OsString::from("tool")];
    let missing = vec![root.join("Missing.app").into_os_string()];

    assert_eq!(bundle_from_command(&ordinary), None);
    assert_eq!(bundle_from_command(&missing), None);
}

#[test]
fn user_selected_bundle_receives_narrow_conventional_write_grants() {
    let (bundle, home) = fixture();
    let plan = discover(&bundle, &home).unwrap();

    assert_eq!(plan.bundle_id, "dev.cdm.fixture-product");
    let canonical_bundle = bundle.canonicalize().unwrap();
    assert_eq!(
        plan.executable,
        canonical_bundle.join("Contents/MacOS/fixture-app")
    );
    assert!(plan.allow_ro.contains(&canonical_bundle));
    let paths = plan
        .allow_rw
        .iter()
        .map(|grant| grant.path.as_path())
        .collect::<BTreeSet<_>>();
    let home = home.canonicalize().unwrap();
    for expected in [
        home.join("Library/Application Support/dev.cdm.fixture-product"),
        home.join("Library/Caches/dev.cdm.fixture-product"),
        home.join("Library/Containers/dev.cdm.fixture-product"),
        home.join("Library/Preferences/dev.cdm.fixture-product.plist"),
        home.join("Library/WebKit/dev.cdm.fixture-product"),
    ] {
        assert!(
            paths.contains(expected.as_path()),
            "missing {}",
            expected.display()
        );
    }
    let _ = std::fs::remove_dir_all(bundle.parent().unwrap());
}

#[test]
fn metadata_and_binary_references_discover_narrow_writable_state() {
    let (bundle, home) = fixture();
    let executable = bundle.join("Contents/MacOS/fixture-app");
    std::fs::write(
            &executable,
            b"embedded:$HOME/.fixture/** fixture-product-runtime fixture-product-toolchain- 4.8.1 fixture-product-helper- 3.2.0",
        )
        .unwrap();
    let metadata = BundleMetadata {
        bundle_id: "dev.cdm.fixture-product".to_string(),
        executable_name: "fixture-app".to_string(),
        display_name: Some("Fixture Product".to_string()),
    };
    for name in [
        "fixture",
        "fixture-product-toolchain-4.8.1",
        "fixture-product-helper-3.2.0",
        "fixture-product-helper-3.1.0",
    ] {
        std::fs::create_dir_all(home.join("Library/Caches").join(name)).unwrap();
    }
    std::fs::remove_dir_all(home.join(".fixture")).unwrap();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::create_dir_all(home.join("Library/Caches/unrelated-product")).unwrap();

    let grants = discover_metadata_rw_state(&home, &metadata, &executable).unwrap();
    let paths = grants
        .iter()
        .map(|grant| grant.path.as_path())
        .collect::<BTreeSet<_>>();
    let home = home.canonicalize().unwrap();

    for expected in [
        home.join(".fixture"),
        home.join("Library/Application Support/dev.cdm.fixture-product"),
        home.join("Library/Caches/dev.cdm.fixture-product"),
        home.join("Library/WebKit/dev.cdm.fixture-product"),
        home.join("Library/Preferences/dev.cdm.fixture-product.plist"),
        home.join("Library/Caches/fixture"),
        home.join("Library/Caches/fixture-product-runtime"),
        home.join("Library/Caches/fixture-product-toolchain-4.8.1"),
        home.join("Library/Caches/fixture-product-helper-3.2.0"),
    ] {
        assert!(
            paths.contains(expected.as_path()),
            "missing {}",
            expected.display()
        );
    }
    assert!(!paths.contains(home.join(".ssh").as_path()));
    assert!(!paths.contains(home.join("Library/Caches/unrelated-product").as_path()));
    assert!(!paths.contains(
        home.join("Library/Caches/fixture-product-helper-3.1.0")
            .as_path()
    ));
    let _ = std::fs::remove_dir_all(bundle.parent().unwrap());
}

#[test]
fn bundle_resource_references_can_identify_a_narrow_existing_cache() {
    let (bundle, home) = fixture();
    let executable = bundle.join("Contents/MacOS/fixture-app");
    let resources = bundle.join("Contents/Resources");
    std::fs::create_dir_all(&resources).unwrap();
    std::fs::write(
        resources.join("runtime.json"),
        r#"{"cacheDirectory":"fixture-product-render-cache"}"#,
    )
    .unwrap();
    std::fs::create_dir_all(home.join("Library/Caches/fixture-product-render-cache")).unwrap();
    let metadata = BundleMetadata {
        bundle_id: "dev.cdm.fixture-product".to_string(),
        executable_name: "fixture-app".to_string(),
        display_name: Some("Fixture Product".to_string()),
    };

    let grants = discover_metadata_rw_state(&home, &metadata, &executable).unwrap();

    assert!(grants.iter().any(|grant| {
        grant
            .path
            .ends_with("Library/Caches/fixture-product-render-cache")
            && grant.source == AppGrantSource::BundleReference
    }));
    let _ = std::fs::remove_dir_all(bundle.parent().unwrap());
}

#[test]
fn reference_scan_finds_overlapping_literals_across_chunk_boundaries() {
    let (bundle, _) = fixture();
    let path = bundle.join("Contents/Resources/references.bin");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut bytes = vec![b'x'; 64 * 1024 - 3];
    bytes.extend_from_slice(b"fixture-product-cache");
    std::fs::write(&path, bytes).unwrap();
    let patterns = vec!["fixture".to_string(), "fixture-product-cache".to_string()];

    let matched = scan_literal_references(&[path], &patterns).unwrap();

    assert_eq!(matched, patterns.into_iter().collect());
    let _ = std::fs::remove_dir_all(bundle.parent().unwrap());
}

#[test]
fn conventional_state_includes_the_bundle_container() {
    let (bundle, home) = fixture();
    let executable = bundle.join("Contents/MacOS/fixture-app");
    let metadata = BundleMetadata {
        bundle_id: "dev.cdm.fixture-product".to_string(),
        executable_name: "fixture-app".to_string(),
        display_name: Some("Fixture Product".to_string()),
    };
    let grants = discover_metadata_rw_state(&home, &metadata, &executable).unwrap();

    assert!(grants.iter().any(|grant| {
        grant
            .path
            .ends_with("Library/Containers/dev.cdm.fixture-product")
            && grant.source == AppGrantSource::BundleConvention
    }));
    let _ = std::fs::remove_dir_all(bundle.parent().unwrap());
}

#[test]
fn broad_or_sensitive_home_directories_are_never_inferred() {
    for reserved in [
        ".agents", ".aws", ".cache", ".cdm", ".codex", ".config", ".git", ".local", ".ssh",
    ] {
        assert!(
            !safe_direct_home_state(reserved),
            "{reserved} must remain explicit"
        );
    }
    assert!(safe_direct_home_state(".fixture"));
}

#[test]
fn conventional_state_symlinks_fail_closed() {
    let (bundle, home) = fixture();
    let outside = bundle.parent().unwrap().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let state = home.join("Library/Application Support/dev.cdm.fixture-product");
    std::fs::create_dir_all(state.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&outside, &state).unwrap();

    let error = discover(&bundle, &home).unwrap_err();
    assert!(error.to_string().contains("symbolic link"));
    let _ = std::fs::remove_dir_all(bundle.parent().unwrap());
}

#[test]
fn malformed_plist_is_an_error_not_missing_optional_metadata() {
    let (bundle, home) = fixture();
    std::fs::write(bundle.join("Contents/Info.plist"), "not a plist").unwrap();
    let error = discover(&bundle, &home).unwrap_err();
    assert!(error.to_string().contains("cannot parse"));
    let _ = std::fs::remove_dir_all(bundle.parent().unwrap());
}

#[test]
fn missing_optional_display_name_uses_executable_name() {
    let (bundle, home) = fixture();
    let info = bundle.join("Contents/Info.plist");
    std::fs::write(
        &info,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.cdm.fixture</string>
<key>CFBundleExecutable</key><string>fixture-app</string>
</dict></plist>"#,
    )
    .unwrap();
    let plan = discover(&bundle, &home).unwrap();
    assert_eq!(plan.bundle_id, "dev.cdm.fixture");
    assert!(!plan.allow_rw.is_empty());
    let _ = std::fs::remove_dir_all(bundle.parent().unwrap());
}

#[test]
fn rejects_executable_directory_symlink_escape() {
    let (bundle, home) = fixture();
    let outside = bundle.parent().unwrap().join("outside-bin");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("fixture-app"), "#!/bin/sh\n").unwrap();
    std::fs::remove_dir_all(bundle.join("Contents/MacOS")).unwrap();
    std::os::unix::fs::symlink(&outside, bundle.join("Contents/MacOS")).unwrap();
    let error = discover(&bundle, &home).unwrap_err();
    assert!(error.to_string().contains("escapes bundle"));
    let _ = std::fs::remove_dir_all(bundle.parent().unwrap());
}

#[test]
fn rejects_a_non_bundle_path() {
    let root = std::env::temp_dir().join("cdm-app-not-a-bundle");
    std::fs::create_dir_all(&root).unwrap();
    assert_eq!(
        discover(&root, &root).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    let _ = std::fs::remove_dir_all(root);
}
