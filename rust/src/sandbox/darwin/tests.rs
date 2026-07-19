//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;
use crate::config::CdmConfig;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

fn seatbelt_available() -> bool {
    Command::new("sandbox-exec")
        .args(["-p", "(version 1) (allow default)", "/usr/bin/true"])
        .status()
        .is_ok_and(|status| status.success())
}

/// Test fixture with isolated temp directories for sandbox tests.
struct TestFixture {
    root: PathBuf,
    work_dir: PathBuf,
    home_dir: PathBuf,
    out_dir: PathBuf,
    script_path: PathBuf,
}

impl TestFixture {
    fn new(label: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("cdm-darwin-test-{}-{}", label, std::process::id()));
        let fixture = TestFixture {
            work_dir: root.join("workspace"),
            home_dir: root.join("home"),
            out_dir: root.join("out"),
            script_path: root.join("runner"),
            root,
        };
        fs::create_dir_all(&fixture.work_dir).unwrap();
        fs::create_dir_all(&fixture.home_dir).unwrap();
        fs::create_dir_all(&fixture.out_dir).unwrap();
        fixture
    }

    /// Writes a shell script and makes it executable.
    fn write_script(&self, content: &str) {
        fs::write(&self.script_path, content).unwrap();
        let mut perms = fs::metadata(&self.script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&self.script_path, perms).unwrap();
    }

    /// Returns a base SandboxConfig pointing at this fixture's directories.
    fn sandbox_config(&self) -> SandboxConfig {
        let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
        cfg.command = vec![self.script_path.clone().into_os_string()];
        cfg.work_dir = self.work_dir.clone();
        cfg.home_dir = self.home_dir.clone();
        cfg.network = crate::network::NetworkPolicy::Disabled;
        cfg.access.add_allow_rw(self.out_dir.clone());
        cfg
    }
}

impl Drop for TestFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn test_seatbelt_denies_reads_to_sensitive_files() {
    if !seatbelt_available() {
        eprintln!("skipping: this process cannot apply a nested Seatbelt profile");
        return;
    }
    let fix = TestFixture::new("deny-read");
    let env_path = fix.work_dir.join(".env");
    let output_path = fix.out_dir.join("result.txt");

    fs::write(&env_path, "API_KEY=sk-ant-REAL1234567890abc\n").unwrap();

    fix.write_script(&format!(
            "#!/bin/sh\nif cat \"{}\" > /dev/null 2>&1; then echo READ_OK; else echo READ_DENIED; fi > \"{}\"\n",
            env_path.display(),
            output_path.display()
        ));

    let mut cfg = fix.sandbox_config();
    cfg.denied_read_paths.push(env_path);
    cfg.freeze_access().unwrap();

    let exit = run_darwin(cfg).unwrap();
    assert_eq!(exit, 0);

    let result = fs::read_to_string(&output_path).unwrap();
    assert!(
        result.trim().contains("READ_DENIED"),
        "expected seatbelt to deny read, got: {}",
        result.trim()
    );
}

#[test]
fn test_injected_env_vars_visible_in_sandbox() {
    if !seatbelt_available() {
        eprintln!("skipping: this process cannot apply a nested Seatbelt profile");
        return;
    }
    let fix = TestFixture::new("env-inject");
    let output_path = fix.out_dir.join("env.txt");

    fix.write_script(&format!(
        "#!/bin/sh\necho \"MY_VAR=$MY_VAR\" > \"{}\"\n",
        output_path.display()
    ));

    let mut cfg = fix.sandbox_config();
    cfg.injected_env
        .insert("MY_VAR".to_string(), "injected_value".to_string());
    cfg.freeze_access().unwrap();

    let exit = run_darwin(cfg).unwrap();
    assert_eq!(exit, 0);

    let result = fs::read_to_string(&output_path).unwrap();
    assert!(
        result.contains("MY_VAR=injected_value"),
        "expected injected env var, got: {}",
        result.trim()
    );
}

#[test]
fn profile_never_makes_home_writable() {
    let fix = TestFixture::new("profile-home");
    let mut cfg = fix.sandbox_config();
    cfg.freeze_access().unwrap();
    let access = cfg.resolved_access().unwrap();
    let profile = generate_sbpl_profile(&cfg).unwrap();
    let home_allow = format!(
        "(allow file-write* (subpath \"{}\"))",
        fix.home_dir.display()
    );
    assert!(!profile.contains(&home_allow));
    assert!(profile.contains(&format!(
        "(allow file-write* (subpath \"{}\"))",
        access.work_dir.display()
    )));
    assert!(profile.contains(&format!(
        "(allow file-write* (subpath \"{}\"))",
        cfg.runtime_dir.display()
    )));
    assert!(!profile.contains("(allow file-write* (subpath \"/tmp\"))"));
    assert!(!profile.contains("(allow file-write* (subpath \"/private/tmp\"))"));
}

#[test]
fn readonly_workspace_omits_workspace_write_allow() {
    let fix = TestFixture::new("profile-ro");
    let mut cfg = fix.sandbox_config();
    cfg.access.workspace = crate::access::WorkspaceAccess::ReadOnly;
    cfg.freeze_access().unwrap();
    let access = cfg.resolved_access().unwrap();
    let profile = generate_sbpl_profile(&cfg).unwrap();
    assert!(!profile.contains(&format!(
        "(allow file-write* (subpath \"{}\"))",
        access.work_dir.display()
    )));
}

#[test]
fn isolated_profile_uses_read_allowlist() {
    let fix = TestFixture::new("profile-iso");
    let mut cfg = fix.sandbox_config();
    cfg.access.host = crate::access::HostAccess::Isolated;
    cfg.freeze_access().unwrap();
    let access = cfg.resolved_access().unwrap();
    let profile = generate_sbpl_profile(&cfg).unwrap();
    assert!(profile.starts_with("(version 1)\n(deny default)"));
    assert!(profile.contains(&format!(
        "(allow file-read* (subpath \"{}\"))",
        access.work_dir.display()
    )));
}

#[test]
fn secure_profile_is_deny_first_and_limits_mach_ipc() {
    let fix = TestFixture::new("profile-secure");
    let mut cfg = fix.sandbox_config();
    cfg.secure = true;
    cfg.freeze_access().unwrap();

    let profile = generate_sbpl_profile(&cfg).unwrap();

    assert!(profile.starts_with("(version 1)\n(deny default)"));
    assert!(profile.contains("(allow mach-lookup"));
    assert!(profile.contains("com.apple.coreservices.launchservicesd"));
    assert!(!profile.contains("(allow mach-register"));
    assert!(!profile.contains("(allow mach-issue-extension"));
}

#[test]
fn compatibility_profile_remains_the_default() {
    let fix = TestFixture::new("profile-compatible");
    let mut cfg = fix.sandbox_config();
    cfg.freeze_access().unwrap();

    let profile = generate_sbpl_profile(&cfg).unwrap();

    assert!(profile.starts_with("(version 1)\n(allow default)"));
}

#[test]
fn proxied_profile_is_deny_first_and_only_allows_the_proxy_endpoint() {
    let fix = TestFixture::new("profile-proxied");
    let mut cfg = fix.sandbox_config();
    cfg.network = crate::network::NetworkPolicy::Proxied(Default::default());
    cfg.proxy_port = 23456;
    cfg.freeze_access().unwrap();

    let profile = generate_sbpl_profile(&cfg).unwrap();

    assert!(profile.starts_with("(version 1)\n(deny default)"));
    assert!(profile.contains("(deny network*)"));
    assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:23456\"))"));
    assert!(!profile.contains("(allow network*)"));
}

#[test]
fn canonical_private_paths_include_their_public_macos_alias() {
    assert_eq!(
        macos_path_alias(std::path::Path::new("/private/tmp/example/file")),
        Some(PathBuf::from("/tmp/example/file"))
    );
    assert_eq!(
        macos_path_alias(std::path::Path::new("/private/var/example")),
        Some(PathBuf::from("/var/example"))
    );
    assert_eq!(
        macos_path_alias(std::path::Path::new("/private/etc/hosts")),
        Some(PathBuf::from("/etc/hosts"))
    );
    assert_eq!(
        macos_path_alias(std::path::Path::new("/Users/example")),
        None
    );
}

#[test]
fn profile_enforces_lexical_and_canonical_hard_denial_spellings() {
    use std::os::unix::fs::symlink;

    let fix = TestFixture::new("profile-deny-alias");
    let target = fix.work_dir.join("protected-target");
    let alias = fix.work_dir.join("protected-alias");
    fs::write(&target, "protected").unwrap();
    symlink(&target, &alias).unwrap();
    let mut cfg = fix.sandbox_config();
    cfg.access.add_runtime_deny_write(alias.clone());
    cfg.freeze_access().unwrap();

    let rule = cfg
        .resolved_access()
        .unwrap()
        .deny_write_rules
        .iter()
        .find(|rule| rule.origin == crate::access::DenyOrigin::Builtin)
        .unwrap();
    let lexical = rule.lexical.clone();
    let canonical = rule.canonical.clone().unwrap();
    let profile = generate_sbpl_profile(&cfg).unwrap();
    assert!(profile.contains(&format!(
        "(deny file-write* (literal \"{}\"))",
        lexical.display()
    )));
    assert!(profile.contains(&format!(
        "(deny file-write* (literal \"{}\"))",
        canonical.display()
    )));
}

#[test]
fn profile_uses_captured_missing_and_directory_denial_kinds() {
    let fix = TestFixture::new("profile-deny-kinds");
    let missing = fix.work_dir.join("future-protected");
    let directory = fix.work_dir.join("secret-directory");
    fs::create_dir(&directory).unwrap();
    let mut cfg = fix.sandbox_config();
    cfg.access.add_runtime_deny_write(missing.clone());
    cfg.denied_read_paths.push(directory.clone());
    cfg.freeze_access().unwrap();

    let missing = cfg
        .resolved_access()
        .unwrap()
        .deny_write_rules
        .iter()
        .find(|rule| rule.origin == crate::access::DenyOrigin::Builtin)
        .unwrap()
        .lexical
        .clone();
    let profile = generate_sbpl_profile(&cfg).unwrap();
    assert!(profile.contains(&format!(
        "(deny file-write* (literal \"{}\"))",
        missing.display()
    )));
    assert!(profile.contains(&format!(
        "(deny file-read* (subpath \"{}\"))",
        directory.canonicalize().unwrap().display()
    )));
}

#[test]
fn hard_write_denials_pin_all_lexical_and_canonical_ancestors() {
    let fix = TestFixture::new("profile-deny-ancestor-rename");
    let nested = fix.work_dir.join("outer/inner/.env");
    fs::create_dir_all(nested.parent().unwrap()).unwrap();
    fs::write(&nested, "protected").unwrap();
    let mut cfg = fix.sandbox_config();
    cfg.access.add_runtime_deny_write(nested.clone());
    cfg.freeze_access().unwrap();

    let profile = generate_sbpl_profile(&cfg).unwrap();
    for path in [
        nested,
        fix.work_dir.join("outer/inner"),
        fix.work_dir.join("outer"),
    ] {
        assert!(profile.contains(&format!(
            "(deny file-write-unlink (literal \"{}\"))",
            path.display()
        )));
    }
}
