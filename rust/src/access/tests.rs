//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;

fn fixture() -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "cdm-access-test-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let work = root.join("work");
    let home = root.join("home");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    (work, home)
}

#[test]
fn workspace_mode_labels_are_stable() {
    assert_eq!(WorkspaceAccess::ReadWrite.label(), "rw");
    assert_eq!(WorkspaceAccess::ReadOnly.label(), "ro");
    assert_eq!(HostAccess::Normal.label(), "normal");
    assert_eq!(HostAccess::Isolated.label(), "isolated");
}

#[test]
fn resolves_tilde_and_workspace_relative_paths() {
    let work = Path::new("/tmp/project");
    let home = Path::new("/Users/test");
    assert_eq!(
        resolve_path(Path::new("cache"), work, home),
        work.join("cache")
    );
    assert_eq!(
        resolve_path(Path::new("~/.codex"), work, home),
        home.join(".codex")
    );
}

#[cfg(unix)]
#[test]
fn tilde_resolution_preserves_non_utf8_path_bytes_for_validation() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let path = PathBuf::from(std::ffi::OsString::from_vec(b"~/opaque-\xff".to_vec()));
    let resolved = resolve_path(&path, Path::new("/work"), Path::new("/home/user"));

    assert_eq!(resolved.as_os_str().as_bytes(), b"/home/user/opaque-\xff");
}

#[test]
fn resolves_config_from_home_and_cli_from_workspace() {
    let (work, home) = fixture();
    let config_dir = home.join("state");
    let cli_dir = work.join("cache");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(&cli_dir).unwrap();
    let paths = PathsConfig {
        allow_ro: vec!["state".to_string()],
        ..PathsConfig::default()
    };
    let mut policy = AccessPolicy::new(&paths);
    policy.add_allow_rw(PathBuf::from("cache"));
    let resolved = policy
        .resolve(&work, &home, &[], &[std::ffi::OsString::from("true")])
        .unwrap();
    assert!(resolved
        .allow_ro
        .contains(&config_dir.canonicalize().unwrap()));
    assert!(resolved.allow_rw.contains(&cli_dir.canonicalize().unwrap()));
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[test]
fn resolved_grant_kind_is_frozen_before_adapter_translation() {
    let (work, home) = fixture();
    let grant = work.join("grant");
    let moved = work.join("moved-grant");
    std::fs::create_dir(&grant).unwrap();
    let mut policy = AccessPolicy::new(&PathsConfig::default());
    policy.add_allow_ro(grant.clone());
    let resolved = policy
        .resolve(&work, &home, &[], &[std::ffi::OsString::from("true")])
        .unwrap();
    let grant = grant.canonicalize().unwrap();

    std::fs::rename(&grant, &moved).unwrap();
    std::fs::create_dir(&grant).unwrap();

    assert_eq!(resolved.kind(&grant), Some(DeniedPathKind::Directory));
    assert_eq!(
        resolved.verify_identities().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[cfg(unix)]
#[test]
fn rejects_non_utf8_filesystem_policy_paths_before_adapter_translation() {
    use std::os::unix::ffi::OsStringExt;

    let (work, home) = fixture();
    let opaque = work.join(std::ffi::OsString::from_vec(b"opaque-\xff".to_vec()));
    let mut policy = AccessPolicy::new(&PathsConfig::default());
    policy.add_runtime_deny_write(opaque);

    let error = policy
        .resolve(&work, &home, &[], &[std::ffi::OsString::from("true")])
        .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error
        .to_string()
        .contains("filesystem policy paths must be valid UTF-8"));
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[test]
fn resolves_each_configured_path_from_its_source_base() {
    let (work, home) = fixture();
    let root = work.parent().unwrap().to_path_buf();
    let project = root.join("project");
    let global_state = home.join("global-state");
    let project_state = project.join("project-state");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&global_state).unwrap();
    std::fs::create_dir_all(&project_state).unwrap();
    let paths = ConfiguredPaths {
        allow_rw: vec![
            ConfiguredPath {
                value: "global-state".into(),
                relative_to: home.clone(),
            },
            ConfiguredPath {
                value: "project-state".into(),
                relative_to: project.clone(),
            },
        ],
        ..ConfiguredPaths::default()
    };

    let resolved = AccessPolicy::from_configured_paths(&paths)
        .resolve(&project, &home, &[], &["echo".into()])
        .unwrap();

    assert!(resolved
        .allow_rw
        .contains(&global_state.canonicalize().unwrap()));
    assert!(resolved
        .allow_rw
        .contains(&project_state.canonicalize().unwrap()));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn secure_persistence_protections_are_opt_in_and_not_recursive() {
    let (work, home) = fixture();
    let active_mcp = work.join(".mcp.json");
    let nested_mcp = work.join(".scratch/worktrees/child/.mcp.json");
    let home_mcp = home.join(".mcp.json");
    std::fs::create_dir_all(nested_mcp.parent().unwrap()).unwrap();
    std::fs::write(&active_mcp, "{}").unwrap();
    std::fs::write(&nested_mcp, "{}").unwrap();
    std::fs::write(&home_mcp, "{}").unwrap();

    let normal = AccessPolicy::new(&PathsConfig::default())
        .resolve(&work, &home, &[], &["true".into()])
        .unwrap();
    assert!(!normal.denies_write(&active_mcp.canonicalize().unwrap()));
    assert!(!normal.denies_write(&home_mcp.canonicalize().unwrap()));

    let mut secure_policy = AccessPolicy::new(&PathsConfig::default());
    secure_policy.set_secure(true);
    let secure = secure_policy
        .resolve(&work, &home, &[], &["true".into()])
        .unwrap();
    assert!(secure.denies_write(&active_mcp.canonicalize().unwrap()));
    assert!(secure.denies_write(&home_mcp.canonicalize().unwrap()));
    assert!(!secure.denies_write(&nested_mcp.canonicalize().unwrap()));
    assert!(secure.deny_write_rules.iter().any(|rule| {
        rule.origin == DenyOrigin::SecurePersistence
            && rule.lexical == active_mcp.canonicalize().unwrap()
    }));
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[test]
fn missing_grants_fail_closed() {
    let (work, home) = fixture();
    let mut policy = AccessPolicy::new(&PathsConfig::default());
    policy.add_allow_rw(PathBuf::from("missing"));
    assert!(policy
        .resolve(&work, &home, &[], &[std::ffi::OsString::from("true")])
        .is_err());
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[test]
fn discovered_grants_may_name_application_state_created_on_first_launch() {
    let (work, home) = fixture();
    let state = home.join("Library/Application Support/example.app");
    let mut policy = AccessPolicy::new(&PathsConfig::default());
    policy.add_discovered_rw(state.clone());

    let resolved = policy
        .resolve(&work, &home, &[], &[std::ffi::OsString::from("true")])
        .unwrap();

    assert!(resolved.allow_rw.contains(&state));
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[test]
fn runtime_control_path_denial_overrides_writable_workspace() {
    let (work, home) = fixture();
    let control = work.join(".git");
    std::fs::write(&control, "gitdir: elsewhere\n").unwrap();
    let mut policy = AccessPolicy::new(&PathsConfig::default());
    policy.add_runtime_deny_write(control.clone());

    let resolved = policy
        .resolve(&work, &home, &[], &[std::ffi::OsString::from("true")])
        .unwrap();

    assert_eq!(resolved.workspace, WorkspaceAccess::ReadWrite);
    assert!(resolved.denies_write(&control.canonicalize().unwrap()));
    assert!(resolved
        .deny_write_rules
        .iter()
        .any(|rule| rule.origin == DenyOrigin::Builtin && rule.lexical == control));
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[test]
fn sensitive_paths_are_hard_read_and_write_denials() {
    let (work, home) = fixture();
    let secret = work.join(".env");
    std::fs::write(&secret, "TOKEN=secret").unwrap();
    let mut policy = AccessPolicy::new(&PathsConfig::default());
    policy.add_allow_rw(work.clone());
    let resolved = policy
        .resolve(
            &work,
            &home,
            std::slice::from_ref(&secret),
            &[std::ffi::OsString::from("true")],
        )
        .unwrap();
    let secret = secret.canonicalize().unwrap();
    assert!(resolved.denies_read(&secret));
    assert!(resolved.denies_write(&secret));
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[cfg(unix)]
#[test]
fn denial_snapshot_retains_lexical_symlink_and_canonical_target() {
    use std::os::unix::fs::symlink;

    let (work, home) = fixture();
    let target = work.join("target");
    let alias = home.join("protected-alias");
    std::fs::write(&target, "protected").unwrap();
    symlink(&target, &alias).unwrap();
    let paths = PathsConfig {
        deny_write: vec!["protected-alias".into()],
        ..PathsConfig::default()
    };

    let resolved = AccessPolicy::new(&paths)
        .resolve(&work, &home, &[], &["true".into()])
        .unwrap();
    let rule = resolved
        .deny_write_rules
        .iter()
        .find(|rule| rule.lexical == home.canonicalize().unwrap().join("protected-alias"))
        .unwrap();

    let canonical_target = target.canonicalize().unwrap();
    assert_eq!(rule.canonical.as_deref(), Some(canonical_target.as_path()));
    assert_eq!(rule.kind, DeniedPathKind::File);
    assert!(rule.lexical_exists);
    assert!(rule.exists);
    assert!(resolved.denies_write(&home.canonicalize().unwrap().join("protected-alias")));
    assert!(resolved.denies_write(&canonical_target));
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[test]
fn missing_denial_is_preserved_for_creation_blocking() {
    let (work, home) = fixture();
    let canonical_home = home.canonicalize().unwrap();
    let missing = canonical_home.join(".ssh/authorized_keys");
    let paths = PathsConfig {
        deny_write: vec![".ssh/authorized_keys".into()],
        ..PathsConfig::default()
    };

    let resolved = AccessPolicy::new(&paths)
        .resolve(&work, &home, &[], &["true".into()])
        .unwrap();
    let rule = resolved
        .deny_write_rules
        .iter()
        .find(|rule| rule.lexical == missing)
        .unwrap();

    assert_eq!(rule.kind, DeniedPathKind::Missing);
    assert!(!rule.lexical_exists);
    assert!(!rule.exists);
    assert_eq!(rule.canonical.as_deref(), Some(missing.as_path()));
    assert_eq!(rule.missing_parents, vec![canonical_home.join(".ssh")]);
    assert!(resolved.denies_write(&missing));
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[test]
fn custom_cache_root_is_absolute_and_scoped_to_rootfs() {
    let home = Path::new("/home/test");
    let root = validate_custom_cache_root(Some(PathBuf::from("/var/cache/cdm")), home).unwrap();
    assert_eq!(root, PathBuf::from("/var/cache/cdm/rootfs"));
    assert_eq!(
        validate_custom_cache_root(None, home).unwrap(),
        PathBuf::from("/home/test/.cdm/rootfs")
    );
    assert!(validate_custom_cache_root(Some(PathBuf::from("relative-cache")), home).is_err());
}

#[cfg(unix)]
#[test]
fn missing_denial_beneath_symlink_retains_would_be_canonical_target() {
    use std::os::unix::fs::symlink;

    let (work, home) = fixture();
    let real = work.join("real-home");
    std::fs::create_dir_all(&real).unwrap();
    symlink(&real, home.join("alias")).unwrap();
    let lexical = home.join("alias/new-protected-file");

    let rule = resolve_denials([(lexical.clone(), DenyOrigin::Configured)])
        .pop()
        .unwrap();

    assert_eq!(rule.lexical, lexical);
    let expected = real.canonicalize().unwrap().join("new-protected-file");
    assert_eq!(rule.canonical.as_deref(), Some(expected.as_path()));
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[cfg(unix)]
#[test]
fn dangling_symlink_denial_retains_entry_and_would_be_target() {
    use std::os::unix::fs::symlink;

    let (work, home) = fixture();
    let target = work.join("not-created-yet");
    let alias = home.join("protected-link");
    symlink(&target, &alias).unwrap();

    let rule = resolve_denials([(alias.clone(), DenyOrigin::Configured)])
        .pop()
        .unwrap();

    assert_eq!(rule.lexical, alias);
    assert!(rule.lexical_exists);
    assert!(!rule.exists);
    assert_eq!(rule.kind, DeniedPathKind::Missing);
    let expected = work.canonicalize().unwrap().join("not-created-yet");
    assert_eq!(rule.canonical.as_deref(), Some(expected.as_path()));
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[test]
fn runtime_cache_denial_is_hard_read_and_write_policy() {
    let cache = PathBuf::from("/var/cache/cdm/rootfs");
    let rules = resolve_denials([(cache.clone(), DenyOrigin::RuntimeCache)]);
    let paths = flatten_denials(&rules);
    assert_eq!(rules[0].origin, DenyOrigin::RuntimeCache);
    assert!(paths.contains(&cache));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_host_runtime_socket_tree_is_synthetic_not_readable() {
    let (work, home) = fixture();
    let resolved = AccessPolicy::new(&PathsConfig::default())
        .resolve(&work, &home, &[], &[std::ffi::OsString::from("true")])
        .unwrap();

    assert!(resolved.synthetic_dirs.contains(&PathBuf::from("/run")));
    assert!(resolved.synthetic_dirs.contains(&PathBuf::from("/var/run")));
    assert!(!resolved.runtime_ro.contains(&PathBuf::from("/run")));
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn direct_unix_socket_grant_is_rejected() {
    use std::os::unix::net::UnixListener;

    let (work, home) = fixture();
    let socket = work.parent().unwrap().join("deputy.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    let mut policy = AccessPolicy::new(&PathsConfig::default());
    policy.add_allow_rw(socket);

    let error = policy
        .resolve(&work, &home, &[], &[std::ffi::OsString::from("true")])
        .unwrap_err();
    assert!(error.to_string().contains("Unix socket"));
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[test]
fn workspace_git_metadata_is_writable_in_rw_mode() {
    let (work, home) = fixture();
    let git_dir = work.join(".git");
    std::fs::create_dir_all(&git_dir).unwrap();

    let resolved = AccessPolicy::new(&PathsConfig::default())
        .resolve(&work, &home, &[], &[std::ffi::OsString::from("true")])
        .unwrap();

    let git_dir = git_dir.canonicalize().unwrap();
    assert!(!resolved.denies_write(&git_dir));
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}
