//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;
use crate::project::PROJECT_CONFIG;
use std::os::unix::fs::PermissionsExt;

#[test]
fn test_default_config_matches_current() {
    let cfg = CdmConfig::default();

    // EnvConfig passthrough
    assert_eq!(
        cfg.env.passthrough,
        vec![
            "PATH",
            "HOME",
            "USER",
            "SHELL",
            "TERM",
            "LANG",
            "LC_ALL",
            "TZ",
            "EDITOR",
            "VISUAL",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
            "TMPDIR",
            "TEMP",
            "TMP",
            "NODE_OPTIONS",
            "NODE_ENV",
        ]
    );

    // EnvConfig dangerous_prefixes (macOS)
    #[cfg(target_os = "macos")]
    assert_eq!(cfg.env.dangerous_prefixes, vec!["DYLD_", "LD_"]);
    #[cfg(not(target_os = "macos"))]
    assert_eq!(cfg.env.dangerous_prefixes, vec!["LD_"]);

    // PathsConfig has no default external access grants.
    assert!(cfg.paths.allow_ro.is_empty());
    assert!(cfg.paths.allow_rw.is_empty());

    // Persistence-oriented denials belong to --sec, not the base config.
    assert!(cfg.paths.deny_write.is_empty());

    // PathsConfig staged_configs
    assert_eq!(
        cfg.paths.staged_configs.get(".aws/credentials").unwrap(),
        "AWS_SHARED_CREDENTIALS_FILE"
    );
    assert_eq!(
        cfg.paths.staged_configs.get(".aws/config").unwrap(),
        "AWS_CONFIG_FILE"
    );
    assert_eq!(
        cfg.paths.staged_configs.get(".docker/config.json").unwrap(),
        "DOCKER_CONFIG"
    );
    assert_eq!(
        cfg.paths.staged_configs.get(".kube/config").unwrap(),
        "KUBECONFIG"
    );
    assert_eq!(
        cfg.paths.staged_configs.get(".npmrc").unwrap(),
        "NPM_CONFIG_USERCONFIG"
    );
    assert_eq!(cfg.paths.staged_configs.len(), 5);

    // SecretsConfig
    assert_eq!(
        cfg.secrets.name_patterns,
        vec![
            "key",
            "secret",
            "token",
            "bearer",
            "password",
            "passwd",
            "credential",
            "api_key",
            "apikey",
            "auth",
            "private",
            "access_key",
            "oauth",
        ]
    );
    assert_eq!(cfg.secrets.min_length, 16);
    assert_eq!(cfg.secrets.min_char_classes, 2);
    assert_eq!(
        cfg.secrets.env_files,
        vec![
            ".env",
            ".env.local",
            ".env.development",
            ".env.production",
            ".env.staging",
            ".env.test",
        ]
    );

    // GuardConfig — check all 21 preflight patterns
    assert_eq!(cfg.guard.blocked_commands.len(), 21);
    assert_eq!(cfg.guard.blocked_commands[0].prefix, "sudo");
    assert_eq!(
        cfg.guard.blocked_commands[0].reason,
        "privilege-escalation command refused by preflight policy"
    );
    assert_eq!(cfg.guard.blocked_commands[3].prefix, "rm -rf /");
    assert_eq!(cfg.guard.blocked_commands[19].prefix, "nsenter");
    assert_eq!(cfg.guard.blocked_commands[20].prefix, "aws");

    // ProxyConfig
    assert_eq!(cfg.proxy.default_port, 18080);

    // VmConfig
    assert_eq!(cfg.vm.vcpus, 2);
    assert_eq!(cfg.vm.ram_mib, 512);
    assert_eq!(cfg.vm.max_layer_compressed_mib, 512);
    assert_eq!(cfg.vm.max_image_compressed_mib, 2_048);
    assert_eq!(cfg.vm.max_layer_expanded_mib, 4_096);
    assert_eq!(cfg.vm.max_image_expanded_mib, 8_192);
    assert_eq!(cfg.vm.max_layer_entries, 250_000);
    assert_eq!(cfg.vm.max_image_entries, 1_000_000);
    assert_eq!(cfg.vm.max_path_depth, 128);
}

#[test]
fn test_load_missing_file_uses_defaults() {
    let path = std::env::temp_dir().join(format!(
        "cdm-missing-config-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = std::fs::remove_file(&path);
    let project = ProjectContext {
        launch_dir: std::env::temp_dir(),
        root: std::env::temp_dir(),
        config_path: None,
    };
    let cfg = load_from_paths(
        &path,
        &project,
        &std::env::temp_dir(),
        &[],
        &std::env::temp_dir().join("cdm-missing-trust-store"),
    )
    .unwrap();
    let default = CdmConfig::default();
    assert_eq!(cfg.value.env.passthrough, default.env.passthrough);
    assert_eq!(cfg.value.secrets.min_length, default.secrets.min_length);
    assert_eq!(cfg.value.vm.vcpus, default.vm.vcpus);
}

#[test]
fn test_load_invalid_file_is_an_error() {
    let path = std::env::temp_dir().join(format!(
        "cdm-invalid-config-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    std::fs::write(&path, b"{ definitely not json").unwrap();
    let project = ProjectContext {
        launch_dir: std::env::temp_dir(),
        root: std::env::temp_dir(),
        config_path: None,
    };
    let error = load_from_paths(
        &path,
        &project,
        &std::env::temp_dir(),
        &[],
        &std::env::temp_dir().join("cdm-missing-trust-store"),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    let _ = std::fs::remove_file(path);
}

#[test]
fn test_partial_config_merges() {
    let json = r#"{
            "vm": {
                "ram_mib": 1024,
                "max_layer_compressed_mib": 256,
                "max_path_depth": 64
            }
        }"#;
    let cfg: CdmConfig = serde_json::from_str(json).unwrap();

    // Overridden field
    assert_eq!(cfg.vm.ram_mib, 1024);
    assert_eq!(cfg.vm.max_layer_compressed_mib, 256);
    assert_eq!(cfg.vm.max_path_depth, 64);
    // Non-overridden fields keep defaults
    assert_eq!(cfg.vm.vcpus, 2);
    assert_eq!(cfg.vm.max_image_compressed_mib, 2_048);
    assert_eq!(cfg.secrets.min_length, 16);
    assert_eq!(cfg.env.passthrough.len(), 18);
    assert_eq!(cfg.guard.blocked_commands.len(), 21);
}

#[test]
fn test_legacy_and_unknown_fields_are_rejected() {
    for json in [
        r#"{"paths":{"writable":[".codex"]}}"#,
        r#"{"paths":{"protected":[".git"]}}"#,
        r#"{"paths":{"allow_write":[".codex"]}}"#,
    ] {
        assert!(
            serde_json::from_str::<CdmConfig>(json).is_err(),
            "accepted {json}"
        );
    }
}

#[test]
fn test_save_and_reload() {
    // Test round-trip serialization without touching HOME env var
    // (modifying HOME in a parallel test causes race conditions with other tests)
    let temp = std::env::temp_dir().join(format!("cdm-config-roundtrip-{}", std::process::id()));
    std::fs::create_dir_all(&temp).unwrap();

    let config_file = temp.join("config.json");
    let default = CdmConfig::default();
    let json = serde_json::to_string_pretty(&default).unwrap();
    std::fs::write(&config_file, &json).unwrap();

    let data = std::fs::read_to_string(&config_file).unwrap();
    let cfg: CdmConfig = serde_json::from_str(&data).unwrap();

    assert_eq!(cfg.env.passthrough, default.env.passthrough);
    assert_eq!(cfg.secrets.min_length, default.secrets.min_length);
    assert_eq!(
        cfg.guard.blocked_commands.len(),
        default.guard.blocked_commands.len()
    );
    assert_eq!(cfg.vm.vcpus, default.vm.vcpus);
    assert_eq!(cfg.vm.ram_mib, default.vm.ram_mib);
    assert_eq!(cfg.proxy.default_port, default.proxy.default_port);

    let _ = std::fs::remove_dir_all(&temp);
}

#[test]
fn save_default_refuses_to_overwrite_an_existing_config() {
    let temp = std::env::temp_dir().join(format!("cdm-config-create-only-{}", std::process::id()));
    let path = temp.join("config.json");
    std::fs::create_dir_all(&temp).unwrap();
    std::fs::write(&path, "keep me").unwrap();

    let error = save_default_to(&path).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep me");
    let _ = std::fs::remove_dir_all(temp);
}

#[test]
fn save_default_creates_a_private_policy_directory() {
    let temp =
        std::env::temp_dir().join(format!("cdm-config-private-parent-{}", std::process::id()));
    let policy_dir = temp.join(".cdm");
    let path = policy_dir.join("config.json");
    let _ = std::fs::remove_dir_all(&temp);

    save_default_to(&path).unwrap();

    let mode = std::fs::metadata(&policy_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let _ = std::fs::remove_dir_all(temp);
}

#[test]
fn project_layer_overrides_scalars_and_adds_origin_aware_paths() {
    let temp = std::env::temp_dir().join(format!("cdm-layered-config-{}", std::process::id()));
    let home = temp.join("home");
    let project_root = temp.join("project");
    std::fs::create_dir_all(project_root.join(".cdm")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let global = temp.join("global.json");
    let project_path = project_root.join(".cdm/config.json");
    std::fs::write(
        &global,
        r#"{"proxy":{"default_port":18081},"paths":{"allow_rw":["global-state"]}}"#,
    )
    .unwrap();
    std::fs::write(
        &project_path,
        r#"{"proxy":{"default_port":18082},"paths":{"allow_rw":["project-state"]}}"#,
    )
    .unwrap();
    let context = ProjectContext {
        launch_dir: project_root.clone(),
        root: project_root.clone(),
        config_path: Some(project_path),
    };

    let trust_path = home.join(".cdm/trusted-projects.json");
    trust_project_in(&context, &trust_path).unwrap();
    let loaded = load_from_paths(&global, &context, &home, &[], &trust_path).unwrap();

    assert_eq!(loaded.value.proxy.default_port, 18082);
    assert!(loaded.paths.allow_rw.contains(&ConfiguredPath {
        value: "global-state".into(),
        relative_to: home.clone(),
        origin: Origin::Global,
    }));
    assert!(loaded.paths.allow_rw.contains(&ConfiguredPath {
        value: "project-state".into(),
        relative_to: project_root,
        origin: Origin::Project,
    }));
    let _ = std::fs::remove_dir_all(temp);
}

#[test]
fn project_layer_cannot_remove_global_configured_path_denials() {
    let temp = std::env::temp_dir().join(format!("cdm-layered-denials-{}", std::process::id()));
    let project_root = temp.join("project");
    std::fs::create_dir_all(project_root.join(".cdm")).unwrap();
    let global = temp.join("global.json");
    std::fs::write(&global, r#"{"paths":{"deny_write":[".zshrc"]}}"#).unwrap();
    let project_path = project_root.join(".cdm/config.json");
    std::fs::write(&project_path, r#"{"paths":{"deny_write":[]}}"#).unwrap();
    let context = ProjectContext {
        launch_dir: project_root.clone(),
        root: project_root,
        config_path: Some(project_path),
    };

    let trust_path = temp.join("trust/trusted-projects.json");
    trust_project_in(&context, &trust_path).unwrap();
    let loaded = load_from_paths(&global, &context, &temp, &[], &trust_path).unwrap();

    assert!(loaded
        .value
        .paths
        .deny_write
        .contains(&".zshrc".to_string()));
    let _ = std::fs::remove_dir_all(temp);
}

#[test]
fn project_config_requires_exact_byte_trust_and_edits_invalidate_it() {
    let temp = std::env::temp_dir().join(format!("cdm-project-trust-{}", std::process::id()));
    let project_root = temp.join("project");
    let config_path = project_root.join(PROJECT_CONFIG);
    let trust_path = temp.join("home/.cdm/trusted-projects.json");
    std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    std::fs::write(&config_path, r#"{"proxy":{"default_port":18081}}"#).unwrap();
    let project = ProjectContext {
        launch_dir: project_root.clone(),
        root: project_root,
        config_path: Some(config_path.clone()),
    };

    let error =
        load_from_paths(&temp.join("missing"), &project, &temp, &[], &trust_path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

    let receipt = trust_project_in(&project, &trust_path).unwrap();
    assert_eq!(receipt.config_path, config_path);
    assert_eq!(receipt.sha256.len(), 64);
    assert_eq!(
        load_from_paths(&temp.join("missing"), &project, &temp, &[], &trust_path)
            .unwrap()
            .value
            .proxy
            .default_port,
        18081
    );

    // Even a semantically equivalent byte edit invalidates exact-byte trust.
    std::fs::write(
        &config_path,
        b"{\n  \"proxy\": {\"default_port\": 18081}\n}\n",
    )
    .unwrap();
    let error =
        load_from_paths(&temp.join("missing"), &project, &temp, &[], &trust_path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("cdm trust"));
    let _ = std::fs::remove_dir_all(temp);
}

#[cfg(unix)]
#[test]
fn trust_store_is_private_and_symlinks_are_rejected() {
    use std::fs::hard_link;
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp = std::env::temp_dir().join(format!("cdm-private-trust-store-{}", std::process::id()));
    let project_root = temp.join("project");
    let config_path = project_root.join(PROJECT_CONFIG);
    let trust_path = temp.join("home/.cdm/trusted-projects.json");
    std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    std::fs::write(&config_path, "{}").unwrap();
    let project = ProjectContext {
        launch_dir: project_root.clone(),
        root: project_root,
        config_path: Some(config_path),
    };

    trust_project_in(&project, &trust_path).unwrap();
    let mode = std::fs::metadata(&trust_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    std::fs::set_permissions(&trust_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = trust_project_in(&project, &trust_path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

    std::fs::remove_file(&trust_path).unwrap();
    let real_store = temp.join("real-store.json");
    std::fs::write(&real_store, r#"{"version":1,"projects":{}}"#).unwrap();
    std::fs::set_permissions(&real_store, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&real_store, &trust_path).unwrap();
    assert!(trust_project_in(&project, &trust_path).is_err());

    let hard_link_root = temp.join("hard-link-project");
    let hard_link_path = hard_link_root.join(PROJECT_CONFIG);
    std::fs::create_dir_all(hard_link_path.parent().unwrap()).unwrap();
    hard_link(&real_store, &hard_link_path).unwrap();
    let hard_link_project = ProjectContext {
        launch_dir: hard_link_root.clone(),
        root: hard_link_root,
        config_path: Some(hard_link_path),
    };
    let separate_store = temp.join("separate/trusted-projects.json");
    let error = trust_project_in(&hard_link_project, &separate_store).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let _ = std::fs::remove_dir_all(temp);
}

#[test]
fn selected_global_presets_apply_in_order_before_project_config() {
    let temp = std::env::temp_dir().join(format!("cdm-config-presets-{}", std::process::id()));
    let home = temp.join("home");
    let global = temp.join("global.json");
    let project_root = temp.join("project");
    let project_path = project_root.join(PROJECT_CONFIG);
    let trust_path = home.join(".cdm/trusted-projects.json");
    std::fs::create_dir_all(project_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(global.parent().unwrap()).unwrap();
    std::fs::write(
        &global,
        r#"{
                "proxy":{"default_port":18080},
                "presets":{
                    "first":{"proxy":{"default_port":18081},"paths":{"allow_rw":["first-state"]}},
                    "second":{"proxy":{"default_port":18082},"paths":{"allow_rw":["second-state"]}}
                }
            }"#,
    )
    .unwrap();
    std::fs::write(&project_path, r#"{"proxy":{"default_port":18083}}"#).unwrap();
    let project = ProjectContext {
        launch_dir: project_root.clone(),
        root: project_root.clone(),
        config_path: Some(project_path),
    };
    trust_project_in(&project, &trust_path).unwrap();

    let loaded = load_from_paths(
        &global,
        &project,
        &home,
        &["second".into(), "first".into()],
        &trust_path,
    )
    .unwrap();
    // Project configuration follows presets, so it wins scalar conflicts.
    assert_eq!(loaded.value.proxy.default_port, 18083);
    for value in ["first-state", "second-state"] {
        assert!(loaded.paths.allow_rw.contains(&ConfiguredPath {
            value: value.into(),
            relative_to: home.clone(),
            origin: Origin::Preset(value.trim_end_matches("-state").into()),
        }));
    }

    let no_project = ProjectContext {
        launch_dir: project_root.clone(),
        root: project_root,
        config_path: None,
    };
    let loaded = load_from_paths(
        &global,
        &no_project,
        &home,
        &["second".into(), "first".into()],
        &trust_path,
    )
    .unwrap();
    assert_eq!(loaded.value.proxy.default_port, 18081);
    let error = load_from_paths(
        &global,
        &no_project,
        &home,
        &["unknown".into()],
        &trust_path,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let _ = std::fs::remove_dir_all(temp);
}

#[test]
fn policy_and_trust_files_are_always_hard_deny_write_inputs() {
    let temp =
        std::env::temp_dir().join(format!("cdm-protected-policy-files-{}", std::process::id()));
    let home = temp.join("home");
    let global = temp.join("global-policy/config.json");
    let project_root = temp.join("project");
    let project_path = project_root.join(PROJECT_CONFIG);
    let trust_path = home.join(".cdm/trusted-projects.json");
    std::fs::create_dir_all(project_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(global.parent().unwrap()).unwrap();
    std::fs::write(
        &global,
        format!(
            r#"{{"paths":{{"allow_rw":[{:?},{:?},{:?}]}}}}"#,
            global.to_string_lossy(),
            project_path.to_string_lossy(),
            trust_path.to_string_lossy()
        ),
    )
    .unwrap();
    std::fs::write(&project_path, "{}").unwrap();
    let project = ProjectContext {
        launch_dir: project_root.clone(),
        root: project_root,
        config_path: Some(project_path.clone()),
    };
    trust_project_in(&project, &trust_path).unwrap();

    let loaded = load_from_paths(&global, &project, &home, &[], &trust_path).unwrap();
    for path in [
        global.parent().unwrap(),
        &global,
        project_path.parent().unwrap(),
        &project_path,
        trust_path.parent().unwrap(),
        &trust_path,
    ] {
        assert!(loaded.paths.deny_write.iter().any(|configured| {
            configured.value == path.to_string_lossy()
                && configured.relative_to.as_os_str().is_empty()
        }));
    }
    let _ = std::fs::remove_dir_all(temp);
}

#[cfg(unix)]
#[test]
fn custom_global_config_requires_a_dedicated_secure_parent() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp =
        std::env::temp_dir().join(format!("cdm-custom-config-parent-{}", std::process::id()));
    let home = temp.join("home");
    let project = temp.join("project");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&project).unwrap();

    for broad in [
        PathBuf::from("/tmp/config.json"),
        home.join("config.json"),
        project.join("config.json"),
    ] {
        let error = validate_custom_config_parent(&broad, &home, &project).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("dedicated policy directory"));
    }

    let secure = temp.join("policy");
    std::fs::create_dir_all(&secure).unwrap();
    std::fs::set_permissions(&secure, std::fs::Permissions::from_mode(0o700)).unwrap();
    validate_custom_config_parent(&secure.join("config.json"), &home, &project).unwrap();

    std::fs::set_permissions(&secure, std::fs::Permissions::from_mode(0o722)).unwrap();
    let error =
        validate_custom_config_parent(&secure.join("config.json"), &home, &project).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("group/world writable"));

    let real = temp.join("real-policy");
    let linked = temp.join("linked-policy");
    std::fs::create_dir_all(&real).unwrap();
    symlink(&real, &linked).unwrap();
    let error =
        validate_custom_config_parent(&linked.join("config.json"), &home, &project).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("real directory"));
    let _ = std::fs::remove_dir_all(temp);
}

#[cfg(unix)]
#[test]
fn trust_store_keys_reject_non_utf8_paths() {
    use std::os::unix::ffi::OsStringExt;

    let path = PathBuf::from(std::ffi::OsString::from_vec(b"project-\xff".to_vec()));
    let error = path_key(&path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error
        .to_string()
        .contains("filesystem policy paths must be valid UTF-8"));
}

#[test]
fn built_in_profile_catalog_is_stable_and_splits_read_only_from_mutable_state() {
    let profiles = built_in_profiles();
    assert_eq!(
        profiles
            .iter()
            .map(|profile| profile.id)
            .collect::<Vec<_>>(),
        ["pi", "claude", "codex", "copilot"]
    );
    assert_eq!(
        profiles
            .iter()
            .map(|profile| profile.executable)
            .collect::<Vec<_>>(),
        ["pi", "claude", "codex", "copilot"]
    );
    for profile in profiles {
        assert!(
            !profile.allow_ro.is_empty(),
            "{} needs read-only inputs",
            profile.id
        );
        assert!(
            !profile.allow_rw.is_empty(),
            "{} needs mutable state",
            profile.id
        );
        assert!(
            !profile.markers.is_empty(),
            "{} needs a state marker",
            profile.id
        );
    }
}

#[cfg(unix)]
#[test]
fn setup_profile_registry_round_trips_privately_and_idempotently() {
    use std::os::unix::fs::PermissionsExt;

    let temp = std::env::temp_dir().join(format!("cdm-setup-registry-{}", std::process::id()));
    let home = temp.join("home");
    std::fs::create_dir_all(&home).unwrap();

    let path =
        write_setup_profiles_in(&home, &["pi".into(), "claude".into(), "pi".into()]).unwrap();
    assert_eq!(read_setup_profiles_in(&home).unwrap(), ["claude", "pi"]);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let before = std::fs::read(&path).unwrap();
    write_setup_profiles_in(&home, &["pi".into(), "claude".into()]).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let _ = std::fs::remove_dir_all(temp);
}

#[cfg(unix)]
#[test]
fn setup_profile_registry_rejects_malformed_unknown_and_unsafe_state_without_replacing_it() {
    use std::fs::hard_link;
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp =
        std::env::temp_dir().join(format!("cdm-unsafe-setup-registry-{}", std::process::id()));
    let home = temp.join("home");
    let parent = home.join(".cdm");
    let path = parent.join(SETUP_PROFILES_FILE);
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();

    for bytes in [
        br#"{"version":2,"enabled_profile_ids":[]}"#.as_slice(),
        br#"{"version":1,"enabled_profile_ids":["unknown"]}"#.as_slice(),
        br#"{"version":1,"enabled_profile_ids":["pi","pi"]}"#.as_slice(),
        br#"{"version":1,"enabled_profile_ids":[],"extra":true}"#.as_slice(),
    ] {
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_setup_profiles_in(&home).is_err());
        let before = std::fs::read(&path).unwrap();
        assert!(write_setup_profiles_in(&home, &["pi".into()]).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    std::fs::write(&path, br#"{"version":1,"enabled_profile_ids":["pi"]}"#).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(write_setup_profiles_in(&home, &["claude".into()]).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(write_setup_profiles_in(&home, &["claude".into()]).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();

    std::fs::remove_file(&path).unwrap();
    let target = temp.join("target.json");
    std::fs::write(&target, br#"{"version":1,"enabled_profile_ids":[]}"#).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, &path).unwrap();
    assert!(write_setup_profiles_in(&home, &["pi".into()]).is_err());
    std::fs::remove_file(&path).unwrap();

    hard_link(&target, &path).unwrap();
    assert!(write_setup_profiles_in(&home, &["pi".into()]).is_err());
    assert_eq!(
        std::fs::read(&target).unwrap(),
        br#"{"version":1,"enabled_profile_ids":[]}"#
    );
    let _ = std::fs::remove_dir_all(temp);
}

#[test]
fn explicit_enabled_profiles_apply_before_presets_and_project_with_distinct_origins() {
    let temp = std::env::temp_dir().join(format!("cdm-profile-layering-{}", std::process::id()));
    let home = temp.join("home");
    let global = temp.join("global.json");
    let project_root = temp.join("project");
    let project_path = project_root.join(PROJECT_CONFIG);
    let trust_path = home.join(".cdm/trusted-projects.json");
    std::fs::create_dir_all(project_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        &global,
        r#"{"presets":{"pi":{"paths":{"allow_rw":["preset-state"]}}}}"#,
    )
    .unwrap();
    std::fs::write(&project_path, r#"{"paths":{"allow_rw":["project-state"]}}"#).unwrap();
    let project = ProjectContext {
        launch_dir: project_root.clone(),
        root: project_root.clone(),
        config_path: Some(project_path),
    };
    trust_project_in(&project, &trust_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            trust_path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    write_setup_profiles_in(&home, &["pi".into(), "claude".into()]).unwrap();

    let loaded = load_from_paths_with_profiles(
        &global,
        &project,
        &home,
        &["claude".into(), "pi".into()],
        &["pi".into()],
        &trust_path,
        &setup_profiles_path(&home),
    )
    .unwrap();
    assert!(loaded.paths.allow_ro.iter().any(|path| {
        path.value == ".claude"
            && path.relative_to == home
            && path.origin == Origin::Profile("claude".into())
    }));
    let claude_position = loaded
        .paths
        .allow_ro
        .iter()
        .position(|path| path.origin == Origin::Profile("claude".into()))
        .unwrap();
    let pi_position = loaded
        .paths
        .allow_ro
        .iter()
        .position(|path| path.origin == Origin::Profile("pi".into()))
        .unwrap();
    assert!(claude_position < pi_position);
    assert!(loaded.paths.allow_ro.iter().any(|path| {
        path.value == ".pi/agent"
            && path.relative_to == home
            && path.origin == Origin::Profile("pi".into())
    }));
    assert!(loaded
        .paths
        .allow_rw
        .iter()
        .any(|path| path.origin == Origin::Preset("pi".into())));
    assert!(loaded
        .paths
        .allow_rw
        .iter()
        .any(|path| path.origin == Origin::Project));
    let registry = setup_profiles_path(&home);
    for protected in [registry.as_path(), registry.parent().unwrap()] {
        assert!(loaded.paths.deny_write.iter().any(|path| {
            path.value == protected.to_string_lossy() && path.relative_to.as_os_str().is_empty()
        }));
    }

    let error = load_from_paths_with_profiles(
        &global,
        &project,
        &home,
        &["codex".into()],
        &[],
        &trust_path,
        &setup_profiles_path(&home),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("cdm setup"));
    let _ = std::fs::remove_dir_all(temp);
}
