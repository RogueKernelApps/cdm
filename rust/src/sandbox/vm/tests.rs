//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;
use crate::config::CdmConfig;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::sync::Arc;

struct RootfsFixture {
    root: std::path::PathBuf,
    outside: std::path::PathBuf,
}

impl RootfsFixture {
    fn new(label: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "cdm-hostile-rootfs-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        Self { root, outside }
    }

    fn sentinel(&self, name: &str) -> std::path::PathBuf {
        let path = self.outside.join(name);
        std::fs::write(&path, "sentinel\n").unwrap();
        path
    }

    fn bundled_rootfs(&self) -> std::path::PathBuf {
        let bundled = self.root.parent().unwrap().join("bundled");
        std::fs::create_dir_all(bundled.join("bin")).unwrap();
        std::fs::create_dir_all(bundled.join("lib")).unwrap();
        std::fs::write(bundled.join("bin/busybox"), "trusted-busybox").unwrap();
        let musl_name = match std::env::consts::ARCH {
            "aarch64" => "ld-musl-aarch64.so.1",
            "x86_64" => "ld-musl-x86_64.so.1",
            architecture => panic!("unsupported test architecture: {architecture}"),
        };
        std::fs::write(bundled.join("lib").join(musl_name), "trusted-musl").unwrap();
        bundled
    }
}

impl Drop for RootfsFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.root.parent().unwrap());
    }
}

#[test]
fn test_to_cstring_valid() {
    assert_eq!(to_cstring("hello").unwrap().to_str().unwrap(), "hello");
}

#[test]
fn test_to_cstring_rejects_null() {
    assert!(to_cstring("hel\0lo").is_err());
}

#[test]
fn test_to_ptr_array_null_terminated() {
    let strings = vec![CString::new("a").unwrap(), CString::new("b").unwrap()];
    let ptrs = to_ptr_array(&strings);
    assert_eq!(ptrs.len(), 3);
    assert!(ptrs[2].is_null());
}

#[test]
fn test_krun_check_success() {
    assert!(krun_check(0, "test").is_ok());
}

#[test]
fn test_krun_check_failure() {
    let err = krun_check(-1, "test_op").unwrap_err();
    assert!(err.to_string().contains("test_op"));
}

#[test]
fn explicit_tsi_features_never_enable_host_unix_sockets() {
    const KRUN_TSI_HIJACK_UNIX: u32 = 1 << 1;
    assert_eq!(explicit_tsi_features(true), 0);
    assert_eq!(explicit_tsi_features(false), 1);
    assert_eq!(explicit_tsi_features(false) & KRUN_TSI_HIJACK_UNIX, 0);
}

#[test]
fn test_build_virtiofs_shares_includes_workdir() {
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.freeze_access().unwrap();
    let shares = build_virtiofs_shares(&cfg).unwrap();
    assert!(!shares.is_empty());
    assert_eq!(shares[0].tag, TAG_WORKDIR);
}

#[test]
fn test_build_virtiofs_shares_includes_stage() {
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    let mapping = crate::secrets::SecretMapping::new();
    cfg.file_stage = Some(
        crate::stage::FileStage::new_with_config(
            &cfg.runtime_dir,
            mapping,
            cfg.config.secrets.name_patterns.clone(),
            cfg.config.secrets.min_length,
            cfg.config.secrets.min_char_classes,
        )
        .unwrap(),
    );
    cfg.freeze_access().unwrap();
    assert!(build_virtiofs_shares(&cfg)
        .unwrap()
        .iter()
        .any(|share| share.tag == TAG_STAGE));
}

#[test]
fn test_build_virtiofs_shares_includes_certs() {
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.ca_cert_path = Some(std::path::PathBuf::from("/tmp/cdm-ca-test.pem"));
    cfg.freeze_access().unwrap();
    assert!(build_virtiofs_shares(&cfg)
        .unwrap()
        .iter()
        .any(|share| share.tag == TAG_CERTS));
}

#[test]
fn external_single_file_vm_grants_fail_closed() {
    let fixture = RootfsFixture::new("single-file-grant");
    let file = fixture.sentinel("only-this-file");
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.access.add_allow_ro(file.clone());
    cfg.freeze_access().unwrap();

    let error = build_virtiofs_shares(&cfg).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(error.to_string().contains("must name directories"));
    assert!(error.to_string().contains(&file.display().to_string()));
}

#[test]
fn test_run_vm_empty_command_errors() {
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.command = vec![];
    assert!(run_vm(cfg).is_err());
}

#[test]
fn launcher_supervisor_preserves_exit_and_signal_status() {
    let shell = Path::new("/bin/sh");
    let exited = posix_spawn_wait(shell, &["sh".into(), "-c".into(), "exit 37".into()]).unwrap();
    assert_eq!(exited.exit_code, 37);
    assert_eq!(exited.signal, None);

    let signaled =
        posix_spawn_wait(shell, &["sh".into(), "-c".into(), "kill -TERM $$".into()]).unwrap();
    assert_eq!(signaled.exit_code, 128 + libc::SIGTERM);
    assert_eq!(signaled.signal, Some(libc::SIGTERM));
}

#[test]
fn launcher_plan_creation_never_follows_or_replaces_a_symlink() {
    let fixture = RootfsFixture::new("launcher-plan-link");
    let victim = fixture.sentinel("plan-victim");
    let plan_path = fixture.root.join("plan.json");
    symlink(&victim, &plan_path).unwrap();
    let plan = LauncherPlan {
        rootfs: fixture.root.join("cdm-rootfs-test"),
        shares: Vec::new(),
        vcpus: 1,
        ram_mib: 128,
        disable_network: true,
        debug: false,
    };

    assert!(write_launcher_plan(&plan_path, &plan).is_err());
    assert_eq!(std::fs::read_to_string(victim).unwrap(), "sentinel\n");
}

#[test]
fn launcher_plan_rejects_unknown_fields_and_unsafe_bounds() {
    let fixture = RootfsFixture::new("launcher-plan-validation");
    let rootfs = fixture.root.join("cdm-rootfs-test");
    std::fs::create_dir(&rootfs).unwrap();
    let malformed = format!(
        r#"{{"rootfs":{},"shares":[],"vcpus":1,"ram_mib":128,"disable_network":true,"debug":false,"unexpected":true}}"#,
        serde_json::to_string(&rootfs).unwrap()
    );
    assert!(serde_json::from_str::<LauncherPlan>(&malformed).is_err());

    let plan = LauncherPlan {
        rootfs,
        shares: Vec::new(),
        vcpus: 0,
        ram_mib: 128,
        disable_network: true,
        debug: false,
    };
    assert!(validate_launcher_plan(&plan, &fixture.root).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn launcher_profile_is_deny_first_and_preserves_share_modes() {
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.network = crate::network::NetworkPolicy::Disabled;
    let fixture = RootfsFixture::new("launcher-profile");
    let rootfs = fixture.root.join("cdm-rootfs-test");
    let ro = fixture.root.join("read-only-share");
    let rw = fixture.root.join("read-write-share");
    for path in [&rootfs, &ro, &rw] {
        std::fs::create_dir(path).unwrap();
    }
    cfg.freeze_access().unwrap();
    let shares = vec![
        VirtioFsShare {
            tag: "ro".into(),
            host_path: ro.to_string_lossy().into_owned(),
            read_only: true,
        },
        VirtioFsShare {
            tag: "rw".into(),
            host_path: rw.to_string_lossy().into_owned(),
            read_only: false,
        },
    ];
    let profile =
        launcher_profile(&cfg, &std::env::current_exe().unwrap(), &rootfs, &shares).unwrap();
    assert!(profile.contains("(deny default)"));
    assert!(!profile.contains("(allow default)"));
    assert!(profile.contains("(deny network*)"));
    assert!(!profile.contains(&format!(
        "(allow file-write* (subpath \"{}\"))",
        ro.display()
    )));
    assert!(profile.contains(&format!(
        "(allow file-write* (subpath \"{}\"))",
        rw.display()
    )));
}

#[cfg(target_os = "macos")]
#[test]
fn launcher_profile_does_not_reresolve_frozen_share_paths() {
    use std::os::unix::fs::symlink;

    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    let fixture = RootfsFixture::new("launcher-frozen-share");
    let rootfs = fixture.root.join("rootfs");
    let share = fixture.root.join("share");
    let moved = fixture.root.join("moved-share");
    let outside = fixture.root.join("outside");
    for path in [&rootfs, &share, &outside] {
        std::fs::create_dir(path).unwrap();
    }
    cfg.freeze_access().unwrap();
    let frozen = share.canonicalize().unwrap();
    let shares = vec![VirtioFsShare {
        tag: "frozen".into(),
        host_path: frozen.to_str().unwrap().to_string(),
        read_only: true,
    }];
    std::fs::rename(&share, &moved).unwrap();
    symlink(&outside, &share).unwrap();

    let profile =
        launcher_profile(&cfg, &std::env::current_exe().unwrap(), &rootfs, &shares).unwrap();

    assert!(profile.contains(&frozen.display().to_string()));
    assert!(!profile.contains(&outside.display().to_string()));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_vm_launcher_arguments_confine_vmm_and_translate_network_mode() {
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.access.host = crate::access::HostAccess::Isolated;
    cfg.network = crate::network::NetworkPolicy::Disabled;
    let denied_directory = cfg.runtime_dir.join("denied-directory");
    let denied_file = cfg.runtime_dir.join("denied-input");
    std::fs::create_dir(&denied_directory).unwrap();
    std::fs::write(&denied_file, "secret").unwrap();
    cfg.denied_read_paths
        .extend([denied_directory.clone(), denied_file.clone()]);
    let fixture = RootfsFixture::new("linux-launcher-args");
    let rootfs = fixture.root.join("cdm-rootfs-test");
    std::fs::create_dir(&rootfs).unwrap();
    let plan_path = cfg.runtime_dir.join("vm-plan-test.json");
    let plan = LauncherPlan {
        rootfs: rootfs.clone(),
        shares: vec![VirtioFsShare {
            tag: "workspace".into(),
            host_path: cfg.work_dir.to_string_lossy().into_owned(),
            read_only: false,
        }],
        vcpus: 1,
        ram_mib: 128,
        disable_network: true,
        debug: false,
    };
    cfg.freeze_access().unwrap();
    let seccomp = crate::proxy_bridge::SeccompProgram::deny_host_socket_deputies().unwrap();
    let args = build_linux_launcher_arguments(
        &cfg,
        &std::env::current_exe().unwrap(),
        &rootfs,
        &plan_path,
        &plan,
        None,
        Some(&seccomp),
    )
    .unwrap();
    let args = args
        .iter()
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>();
    assert!(args.windows(2).any(|pair| pair == ["--tmpfs", "/"]));
    assert!(args.iter().any(|arg| arg == "--unshare-net"));
    assert!(args.windows(2).any(|pair| pair[0] == "--seccomp"));
    assert!(args.windows(4).any(|pair| {
        pair[0] == "--perms"
            && pair[1] == "000"
            && pair[2] == "--tmpfs"
            && pair[3] == denied_directory.to_string_lossy()
    }));
    assert!(args.windows(3).any(|pair| {
        pair[0] == "--ro-bind"
            && pair[1].ends_with("vmm-denied-file")
            && pair[2] == denied_file.to_string_lossy()
    }));
    assert!(args
        .windows(3)
        .any(|pair| pair == ["--dev-bind", "/dev/kvm", "/dev/kvm"]));
    assert!(!args.windows(3).any(|pair| pair == ["--ro-bind", "/", "/"]));
}

#[test]
fn test_write_init_script() {
    let temp = std::env::temp_dir().join(format!("cdm-init-test-{}", std::process::id()));
    std::fs::create_dir_all(&temp).unwrap();
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.command = vec![
        "printf".into(),
        "%s".into(),
        "argument with spaces and 'quotes'".into(),
    ];
    cfg.denied_read_paths
        .push(std::path::PathBuf::from("/home/user/.ssh/id_rsa"));
    cfg.freeze_access().unwrap();
    write_init_script(&temp, &cfg).unwrap();
    let content = std::fs::read_to_string(temp.join("cdm-init")).unwrap();
    // Must NOT reference cdm-env (env is now in .krun_config.json)
    assert!(
        !content.contains("cdm-env"),
        "init script should not reference cdm-env"
    );
    // Must contain cd to workdir (VirtioFS must be mounted first)
    assert!(
        content.contains("\ncd "),
        "init script should cd to workdir after mounting"
    );
    // The command is kept in a root-owned script and run as the unprivileged user.
    assert!(
        content.contains("exec /bin/su -m -s /cdm-command cdm"),
        "init must drop guest privileges before running the command"
    );
    let command = std::fs::read_to_string(temp.join("cdm-command")).unwrap();
    assert!(command.contains("exec 'printf' '%s' 'argument with spaces and '\"'\"'quotes'\"'\"''"));
    // Must contain hardcoded deny path
    assert!(content.contains("/home/user/.ssh/id_rsa"));
    let _ = std::fs::remove_dir_all(&temp);
}

#[test]
fn guest_plan_preserves_exact_argv_fake_env_identity_and_required_mounts() {
    let fixture = RootfsFixture::new("guest-plan");
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.command = vec![
        "printf".into(),
        "%s".into(),
        "argument with spaces and 'quotes'\n".into(),
        <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(vec![
            0xff, b'*', b'?', b'[', b']', b'\n',
        ]),
    ];
    let env = HashMap::from([
        ("API_TOKEN".into(), "cdm-fake-1".into()),
        ("PATH".into(), "/usr/bin:/bin".into()),
    ]);
    cfg.freeze_access().unwrap();
    write_guest_plan(&fixture.root, &cfg, &env).unwrap();
    let plan: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture.root.join(GUEST_PLAN.trim_start_matches('/'))).unwrap(),
    )
    .unwrap();
    assert_eq!(plan["schema"], 2);
    let expected = cfg
        .command
        .iter()
        .map(|argument| argument.as_bytes())
        .collect::<Vec<_>>();
    assert_eq!(plan["argv_bytes"], serde_json::json!(expected));
    assert_eq!(plan["fake_env"]["API_TOKEN"], "cdm-fake-1");
    let identity = guest_identity_for(unsafe { libc::getuid() }, unsafe { libc::getgid() });
    assert_eq!(plan["uid"], identity.0);
    assert_eq!(plan["gid"], identity.1);
    let mounts = plan["mounts"].as_array().unwrap();
    assert!(mounts
        .iter()
        .any(|mount| mount["kind"] == "proc" && mount["target"] == "/proc"));
    assert!(mounts.iter().any(|mount| {
        mount["kind"] == "virtiofs"
            && mount["source"] == TAG_WORKDIR
            && mount["target"] == cfg.work_dir.to_string_lossy().as_ref()
    }));
    let mode = std::fs::metadata(fixture.root.join(GUEST_PLAN.trim_start_matches('/')))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o400);
}

#[test]
fn guest_plan_contains_only_obfuscated_argv_bytes() {
    let fixture = RootfsFixture::new("guest-plan-secret");
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    let real = "sk-live-Secret1234567890";
    let fake = cfg.secrets.add(real.to_string()).unwrap();
    cfg.command = vec!["printf".into(), format!("--token={real}").into()];
    cfg.command = cfg
        .secrets
        .obfuscate_argv(&cfg.command, &cfg.config)
        .unwrap();

    cfg.freeze_access().unwrap();
    write_guest_plan(&fixture.root, &cfg, &HashMap::new()).unwrap();
    let bytes = std::fs::read(fixture.root.join(GUEST_PLAN.trim_start_matches('/'))).unwrap();
    assert!(!bytes
        .windows(real.len())
        .any(|window| window == real.as_bytes()));
    let plan: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let encoded_arg = plan["argv_bytes"][1]
        .as_array()
        .unwrap()
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect::<Vec<_>>();
    assert_eq!(encoded_arg, format!("--token={fake}").as_bytes());
}

#[test]
fn guest_plan_uses_a_deny_mask_instead_of_a_read_only_mount_for_sensitive_files() {
    let fixture = RootfsFixture::new("guest-plan-sensitive-file");
    let workspace = fixture.root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let protected = workspace.join(".env");
    std::fs::write(&protected, "SECRET=not-for-the-guest\n").unwrap();

    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.work_dir = workspace;
    cfg.denied_read_paths.push(protected.clone());
    cfg.command = vec!["true".into()];
    cfg.freeze_access().unwrap();
    let protected = protected.canonicalize().unwrap();

    write_guest_plan(&fixture.root, &cfg, &HashMap::new()).unwrap();
    let plan: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture.root.join(GUEST_PLAN.trim_start_matches('/'))).unwrap(),
    )
    .unwrap();

    assert!(
        plan["denies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|deny| deny["path"] == protected.to_string_lossy().as_ref()),
        "sensitive file is absent from deny masks: {plan:#}"
    );
    assert!(!plan["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|mount| mount["target"] == protected.to_string_lossy().as_ref()));
    let mount_targets = plan["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|mount| mount["target"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(plan["denies"]
        .as_array()
        .unwrap()
        .iter()
        .all(|deny| !mount_targets.contains(deny["path"].as_str().unwrap())));
}

#[test]
fn missing_vm_denial_under_rw_export_fails_without_host_mutation() {
    let fixture = RootfsFixture::new("missing-denial-no-host-mutation");
    let workspace = fixture.root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let protected = workspace.join("future-protected-file");
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.work_dir = workspace;
    cfg.access.add_runtime_deny_write(protected.clone());
    cfg.command = vec!["true".into()];
    cfg.freeze_access().unwrap();

    let error = write_guest_plan(&fixture.root, &cfg, &HashMap::new()).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(error.to_string().contains("without mutating the host"));
    assert!(!protected.exists());
}

#[test]
fn guest_plan_uses_frozen_grant_kind_after_path_replacement() {
    let fixture = RootfsFixture::new("frozen-grant-kind");
    let workspace = fixture.root.join("workspace");
    let grant = fixture.root.join("host-grant");
    let moved = fixture.root.join("moved-host-grant");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::create_dir(&grant).unwrap();
    let mut cfg = SandboxConfig::new(Arc::new(CdmConfig::default())).unwrap();
    cfg.work_dir = workspace;
    cfg.access.add_allow_ro(grant.clone());
    cfg.command = vec!["true".into()];
    cfg.freeze_access().unwrap();
    let frozen = grant.canonicalize().unwrap();

    std::fs::rename(&grant, &moved).unwrap();
    std::fs::write(&grant, "replacement").unwrap();
    write_guest_plan(&fixture.root, &cfg, &HashMap::new()).unwrap();

    let plan: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture.root.join(GUEST_PLAN.trim_start_matches('/'))).unwrap(),
    )
    .unwrap();
    assert!(plan["mounts"].as_array().unwrap().iter().any(|mount| {
        mount["target"].as_str() == frozen.to_str() && mount["kind"].as_str() == Some("virtiofs")
    }));
}

#[test]
fn root_host_identity_is_never_guest_root() {
    assert_eq!(guest_identity_for(0, 0), (65_534, 65_534));
    assert_eq!(guest_identity_for(501, 20), (501, 20));
    assert_eq!(guest_identity_for(501, 0), (501, 65_534));
}

#[test]
fn test_write_krun_config_basic() {
    let temp = std::env::temp_dir().join(format!("cdm-krun-cfg-{}", std::process::id()));
    std::fs::create_dir_all(&temp).unwrap();
    let mut env = HashMap::new();
    env.insert("FOO".to_string(), "bar".to_string());
    write_krun_config(&temp, &env).unwrap();
    let content = std::fs::read_to_string(temp.join(".krun_config.json")).unwrap();
    assert!(content.contains("\"Env\":["));
    assert!(content.contains("FOO=bar"));
    assert!(content.contains("\"WorkingDir\":\"/\""));
    let _ = std::fs::remove_dir_all(&temp);
}

#[test]
fn test_write_krun_config_escapes_values() {
    let temp = std::env::temp_dir().join(format!("cdm-krun-esc-{}", std::process::id()));
    std::fs::create_dir_all(&temp).unwrap();
    let mut env = HashMap::new();
    env.insert(
        "KEY".to_string(),
        "val\"with\\special\nnewline\ttab".to_string(),
    );
    write_krun_config(&temp, &env).unwrap();
    let content = std::fs::read_to_string(temp.join(".krun_config.json")).unwrap();
    // Quotes and backslashes must be escaped
    assert!(content.contains(r#"val\"with\\special\nnewline\ttab"#));
    // Verify the overall structure is valid-looking JSON
    assert!(content.starts_with("{\"Env\":["));
    assert!(content.ends_with('}'));
    let _ = std::fs::remove_dir_all(&temp);
}

#[test]
fn guest_user_setup_rejects_symlinked_etc_without_host_write() {
    let fixture = RootfsFixture::new("etc-link");
    let sentinel = fixture.sentinel("passwd");
    symlink(&fixture.outside, fixture.root.join("etc")).unwrap();

    assert!(prepare_guest_user(&fixture.root).is_err());
    assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "sentinel\n");
}

#[test]
fn guest_user_setup_safely_creates_missing_etc_directory() {
    let fixture = RootfsFixture::new("missing-etc");

    prepare_guest_user(&fixture.root).unwrap();

    let passwd = std::fs::read_to_string(fixture.root.join("etc/passwd")).unwrap();
    assert!(passwd.contains("cdm:x:"));
}

#[test]
fn guest_user_setup_rejects_linked_passwd_without_host_write() {
    for hardlink in [false, true] {
        let fixture = RootfsFixture::new(if hardlink {
            "passwd-hardlink"
        } else {
            "passwd-link"
        });
        std::fs::create_dir_all(fixture.root.join("etc")).unwrap();
        let sentinel = fixture.sentinel("passwd");
        if hardlink {
            std::fs::hard_link(&sentinel, fixture.root.join("etc/passwd")).unwrap();
        } else {
            symlink(&sentinel, fixture.root.join("etc/passwd")).unwrap();
        }

        assert!(prepare_guest_user(&fixture.root).is_err());
        assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "sentinel\n");
    }
}

#[test]
fn root_owned_files_reject_final_symlinks_without_host_write() {
    for name in [".krun_config.json", "cdm-command", "cdm-denied", "cdm-init"] {
        let fixture = RootfsFixture::new(name);
        std::fs::create_dir_all(fixture.root.join("etc")).unwrap();
        std::fs::write(fixture.root.join("etc/passwd"), "root:x:0:0::/:/bin/sh\n").unwrap();
        let sentinel = fixture.sentinel("victim");
        symlink(&sentinel, fixture.root.join(name)).unwrap();

        let result = if name == ".krun_config.json" {
            write_krun_config(&fixture.root, &HashMap::new())
        } else {
            SafeRoot::open(&fixture.root)
                .and_then(|root| root.write_file(Path::new(name), b"trusted", 0o600))
        };

        assert!(result.is_err(), "{name} symlink must be rejected");
        assert_eq!(
            std::fs::read_to_string(&sentinel).unwrap(),
            "sentinel\n",
            "{name} symlink must not modify its target"
        );
    }
}

#[test]
fn rootfs_preparation_rejects_tool_symlink_and_hardlink_targets() {
    for hardlink in [false, true] {
        let fixture = RootfsFixture::new(if hardlink {
            "tool-hardlink"
        } else {
            "tool-link"
        });
        let sentinel = fixture.sentinel("victim");
        if hardlink {
            std::fs::hard_link(&sentinel, fixture.root.join("cdm-busybox")).unwrap();
        } else {
            symlink(&sentinel, fixture.root.join("cdm-busybox")).unwrap();
        }

        assert!(prepare_rootfs_from(&fixture.root, &fixture.bundled_rootfs()).is_err());
        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "sentinel\n");
    }
}

#[test]
fn rootfs_preparation_rejects_symlinked_tool_directory() {
    let fixture = RootfsFixture::new("tool-dir-link");
    let sentinel = fixture.sentinel("mount");
    symlink(&fixture.outside, fixture.root.join("cdm-bin")).unwrap();

    assert!(prepare_rootfs_from(&fixture.root, &fixture.bundled_rootfs()).is_err());
    assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "sentinel\n");
}

#[test]
fn rootfs_preparation_rejects_preexisting_applet_symlink() {
    let fixture = RootfsFixture::new("applet-link");
    std::fs::create_dir_all(fixture.root.join("cdm-bin")).unwrap();
    let sentinel = fixture.sentinel("mount");
    symlink(&sentinel, fixture.root.join("cdm-bin/mount")).unwrap();

    assert!(prepare_rootfs_from(&fixture.root, &fixture.bundled_rootfs()).is_err());
    assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "sentinel\n");
}

#[test]
fn rootfs_preparation_rejects_lib_symlinks_that_leave_root() {
    for target in [
        fixture_absolute_target(),
        std::path::PathBuf::from("../outside"),
    ] {
        let fixture = RootfsFixture::new("lib-link");
        let sentinel = fixture.sentinel("ld-musl-aarch64.so.1");
        let target = if target.is_absolute() {
            fixture.outside.clone()
        } else {
            target
        };
        symlink(target, fixture.root.join("lib")).unwrap();

        assert!(prepare_rootfs_from(&fixture.root, &fixture.bundled_rootfs()).is_err());
        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "sentinel\n");
    }
}

#[test]
fn rootfs_preparation_allows_proven_contained_lib_symlink() {
    let fixture = RootfsFixture::new("contained-lib-link");
    std::fs::create_dir_all(fixture.root.join("usr/lib")).unwrap();
    symlink("usr/lib", fixture.root.join("lib")).unwrap();

    prepare_rootfs_from(&fixture.root, &fixture.bundled_rootfs()).unwrap();

    let musl_name = match std::env::consts::ARCH {
        "aarch64" => "ld-musl-aarch64.so.1",
        "x86_64" => "ld-musl-x86_64.so.1",
        architecture => panic!("unsupported test architecture: {architecture}"),
    };
    assert!(fixture.root.join("usr/lib").join(musl_name).is_file());
}

fn fixture_absolute_target() -> std::path::PathBuf {
    std::path::PathBuf::from("/")
}

#[test]
fn ephemeral_rootfs_is_private_and_below_runtime_directory() {
    let fixture = RootfsFixture::new("ephemeral");
    let base = fixture.root.join("base");
    let runtime = fixture.root.join("runtime");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::write(base.join("file"), "content").unwrap();

    let clone = EphemeralRootfs::clone_from(&base, &runtime).unwrap();

    assert!(clone.path().starts_with(&runtime));
    assert_eq!(
        std::fs::metadata(clone.path()).unwrap().mode() & 0o777,
        0o700
    );
    assert!(std::fs::metadata(clone.path()).unwrap().nlink() >= 1);
}

#[test]
fn ephemeral_rootfs_clone_preserves_untrusted_symlinks_without_following_them() {
    let fixture = RootfsFixture::new("ephemeral-link");
    let base = fixture.root.join("base");
    let runtime = fixture.root.join("runtime");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::create_dir_all(&runtime).unwrap();
    let sentinel = fixture.sentinel("victim");
    symlink(&sentinel, base.join("link")).unwrap();

    let clone = EphemeralRootfs::clone_from(&base, &runtime).unwrap();

    assert!(std::fs::symlink_metadata(clone.path().join("link"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "sentinel\n");
}
