//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;

#[test]
fn test_resolve_work_dir_uses_pwd_when_current_dir_is_stale() {
    let temp_dir = std::env::temp_dir().join(format!("cdm-pwd-fallback-{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let resolved = resolve_work_dir(
        Err(io::Error::from_raw_os_error(libc::ENOENT)),
        Some(temp_dir.clone().into_os_string()),
    )
    .unwrap();
    assert_eq!(resolved, temp_dir);
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_resolve_work_dir_does_not_use_pwd_for_other_errors() {
    let temp_dir = std::env::temp_dir().join(format!("cdm-pwd-no-fallback-{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let err = resolve_work_dir(
        Err(io::Error::from_raw_os_error(libc::EACCES)),
        Some(temp_dir.clone().into_os_string()),
    )
    .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_sandbox_config_vm_defaults() {
    let cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    assert!(!cfg.use_vm);
    assert!(cfg.vm_image.is_none());
    assert_eq!(cfg.network, NetworkPolicy::Direct);
    assert!(!cfg.scramble);
    assert!(cfg
        .runtime_dir
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("session-"));
}

#[test]
fn access_snapshot_is_frozen_once_despite_later_filesystem_changes() {
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    let protected = cfg.runtime_dir.join("protected-entry");
    std::fs::write(&protected, "initial").unwrap();
    let protected_canonical = protected.canonicalize().unwrap();
    cfg.access.add_runtime_deny_write(protected.clone());

    let first = cfg.freeze_access().unwrap().clone();
    std::fs::remove_file(&protected).unwrap();
    std::fs::create_dir(&protected).unwrap();
    let second = cfg.freeze_access().unwrap();

    assert_eq!(first.deny_write_rules, second.deny_write_rules);
    let rule = second
        .deny_write_rules
        .iter()
        .find(|rule| rule.lexical == protected)
        .unwrap();
    assert_eq!(
        rule.canonical.as_deref(),
        Some(protected_canonical.as_path())
    );
    assert_eq!(rule.kind, crate::access::DeniedPathKind::File);
    assert!(rule.exists);
}

#[test]
fn test_build_env_owns_temporary_storage() {
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.injected_env
        .insert("TMPDIR".to_string(), "/tmp/untrusted".to_string());

    let env = cfg.build_env();
    for key in ["TMPDIR", "TMP", "TEMP"] {
        assert_eq!(env.get(key).map(String::as_str), cfg.runtime_dir.to_str());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cfg.runtime_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }
}

#[cfg(feature = "vm")]
#[test]
fn test_build_env_vm_remaps_stage_paths() {
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.use_vm = true;

    let mapping = crate::secrets::SecretMapping::new();
    let stage = crate::stage::FileStage::new_with_config(
        &cfg.runtime_dir,
        mapping,
        cfg.config.secrets.name_patterns.clone(),
        cfg.config.secrets.min_length,
        cfg.config.secrets.min_char_classes,
    )
    .unwrap();
    let host_stage_dir = stage.temp_dir_path().to_string_lossy().to_string();

    cfg.injected_env.insert(
        "AWS_SHARED_CREDENTIALS_FILE".to_string(),
        format!("{}/home/user/.aws/credentials", host_stage_dir),
    );
    cfg.file_stage = Some(stage);

    let env = cfg.build_env_vm();
    let aws_path = env.get("AWS_SHARED_CREDENTIALS_FILE").unwrap();
    assert!(
        aws_path.starts_with(GUEST_STAGE_MOUNT),
        "expected guest path, got: {}",
        aws_path
    );
    assert!(!aws_path.contains(&host_stage_dir));
}

#[cfg(feature = "vm")]
#[test]
fn test_build_env_vm_remaps_ca_paths() {
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.use_vm = true;
    cfg.network = NetworkPolicy::Proxied(Default::default());
    cfg.ca_cert_path = Some(PathBuf::from("/tmp/cdm-ca-12345.pem"));
    cfg.ca_bundle_path = Some(PathBuf::from("/tmp/cdm-ca-bundle-12345.pem"));

    let env = cfg.build_env_vm();

    let node_ca = env.get("NODE_EXTRA_CA_CERTS").unwrap();
    assert_eq!(node_ca, &format!("{}/cdm-ca-12345.pem", GUEST_CERTS_MOUNT));

    let ssl_cert = env.get("SSL_CERT_FILE").unwrap();
    assert_eq!(
        ssl_cert,
        &format!("{}/cdm-ca-bundle-12345.pem", GUEST_CERTS_MOUNT)
    );
}

#[cfg(feature = "vm")]
#[test]
fn test_build_env_vm_preserves_non_vm_paths() {
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.use_vm = true;
    cfg.injected_env
        .insert("MY_VAR".to_string(), "/some/path".to_string());

    let env = cfg.build_env_vm();
    assert_eq!(env.get("MY_VAR").unwrap(), "/some/path");
    assert_eq!(env.get("CDM").unwrap(), "1");
}

#[test]
fn test_build_env_appends_node_options() {
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.network = NetworkPolicy::Proxied(Default::default());
    cfg.ca_cert_path = Some(PathBuf::from("/tmp/cdm-test-ca.pem"));

    let env = cfg.build_env_from([(
        "NODE_OPTIONS".to_string(),
        "--max-old-space-size=4096".to_string(),
    )]);
    let node_opts = env.get("NODE_OPTIONS").unwrap();

    assert!(
        node_opts.contains("--max-old-space-size=4096"),
        "NODE_OPTIONS should preserve existing flags, got: {}",
        node_opts
    );
    assert!(
        node_opts.contains("--use-system-ca"),
        "NODE_OPTIONS should contain --use-system-ca, got: {}",
        node_opts
    );
}

#[test]
fn test_build_env_node_options_no_duplicate() {
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.network = NetworkPolicy::Proxied(Default::default());
    cfg.ca_cert_path = Some(PathBuf::from("/tmp/cdm-test-ca.pem"));

    let env = cfg.build_env_from([(
        "NODE_OPTIONS".to_string(),
        "--max-old-space-size=4096 --use-system-ca".to_string(),
    )]);
    let node_opts = env.get("NODE_OPTIONS").unwrap();

    let count = node_opts.matches("--use-system-ca").count();
    assert_eq!(
        count, 1,
        "NODE_OPTIONS should not duplicate --use-system-ca, got: {}",
        node_opts
    );
}

#[test]
fn test_build_env_drops_inherited_proxy_configuration_when_disabled() {
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.network = NetworkPolicy::Direct;
    let env = cfg.build_env_from(PROXY_ENV_VARS.map(|key| {
        (
            key.to_string(),
            "http://host-proxy.invalid:9999".to_string(),
        )
    }));

    for key in PROXY_ENV_VARS {
        assert!(!env.contains_key(key), "{key} must not be inherited");
    }
}

#[test]
fn adapter_dispatch_rejects_same_kind_workspace_replacement() {
    let root = std::env::temp_dir().join(format!(
        "cdm-frozen-workspace-dispatch-{}",
        std::process::id()
    ));
    let workspace = root.join("workspace");
    let moved = root.join("moved-workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    let runtime = cfg.runtime_dir.clone();
    cfg.work_dir = workspace.clone();
    cfg.command = vec!["true".into()];
    cfg.freeze_access().unwrap();
    std::fs::rename(&workspace, &moved).unwrap();
    std::fs::create_dir(&workspace).unwrap();

    let result = run(cfg).unwrap();
    let error = match result.child {
        Ok(_) => panic!("replacement workspace reached the adapter"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error
        .to_string()
        .contains("filesystem path identity changed"));
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(runtime);
}
