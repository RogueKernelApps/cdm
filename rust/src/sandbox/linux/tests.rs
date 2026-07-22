//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;

fn denied_nodes() -> DeniedNodes {
    DeniedNodes {
        root: "/fixtures/denied".into(),
        denied_file: "/fixtures/denied/file".into(),
        denied_dir: "/fixtures/denied/dir".into(),
        read_only_file: "/fixtures/denied/read-only".into(),
        finished: false,
    }
}

fn rule(
    path: &str,
    kind: crate::access::DeniedPathKind,
    missing_parents: &[&str],
) -> crate::access::ResolvedDenyRule {
    crate::access::ResolvedDenyRule {
        lexical: path.into(),
        canonical: None,
        lexical_exists: kind != crate::access::DeniedPathKind::Missing,
        exists: kind != crate::access::DeniedPathKind::Missing,
        kind,
        origin: crate::access::DenyOrigin::Configured,
        missing_parents: missing_parents
            .iter()
            .map(std::path::PathBuf::from)
            .collect(),
    }
}

#[test]
fn missing_denial_ancestors_are_pinned_before_the_leaf_mask_and_deduplicated() {
    let mut args = Vec::new();
    let mountpoints = append_hard_denials(
        &mut args,
        &[
            rule(
                "/home/user/.ssh",
                crate::access::DeniedPathKind::Missing,
                &[],
            ),
            rule(
                "/home/user/.ssh/authorized_keys",
                crate::access::DeniedPathKind::Missing,
                &["/home/user/.ssh"],
            ),
        ],
        &[rule(
            "/home/user/.ssh/config",
            crate::access::DeniedPathKind::Missing,
            &["/home/user/.ssh"],
        )],
        &denied_nodes(),
        &[],
        |_| true,
        &[std::path::PathBuf::from("/home/user")],
    );

    let directory = args
        .windows(2)
        .position(|pair| pair == ["--tmpfs", "/home/user/.ssh"])
        .unwrap();
    let writable_parent = args
        .windows(3)
        .position(|triple| triple == ["--bind", "/home/user", "/home/user"])
        .unwrap();
    let leaf = args
        .windows(3)
        .position(|triple| {
            triple
                == [
                    "--ro-bind",
                    "/fixtures/denied/read-only",
                    "/home/user/.ssh/authorized_keys",
                ]
        })
        .unwrap();
    let protected_directory = args
        .windows(2)
        .position(|pair| pair == ["--remount-ro", "/home/user/.ssh"])
        .unwrap();
    assert!(writable_parent < directory);
    assert!(directory < leaf);
    assert!(leaf < protected_directory);
    assert!(!args
        .windows(2)
        .any(|pair| pair == ["--remount-ro", "/home/user"]));
    assert_eq!(
        args.windows(2)
            .filter(|pair| pair == &["--tmpfs", "/home/user/.ssh"])
            .count(),
        1
    );
    assert!(!args.windows(3).any(|triple| {
        triple == ["--ro-bind", "/fixtures/denied/read-only", "/home/user/.ssh"]
    }));
    assert!(mountpoints.contains(&(std::path::PathBuf::from("/home/user/.ssh/config"), false)));
}

#[test]
fn directory_read_denial_uses_an_inaccessible_directory_overlay() {
    let mut args = Vec::new();
    let _mountpoints = append_hard_denials(
        &mut args,
        &[],
        &[rule(
            "/home/user/private",
            crate::access::DeniedPathKind::Directory,
            &[],
        )],
        &denied_nodes(),
        &[],
        |_| true,
        &[],
    );

    assert!(args
        .windows(3)
        .any(|triple| { triple == ["--ro-bind", "/fixtures/denied/dir", "/home/user/private"] }));
}

#[test]
fn existing_writable_parent_is_not_rebound_over_earlier_mounts() {
    let mut args = Vec::new();
    let _mountpoints = append_hard_denials(
        &mut args,
        &[rule(
            "/workspace/protected",
            crate::access::DeniedPathKind::File,
            &[],
        )],
        &[],
        &denied_nodes(),
        &[],
        |_| true,
        &[std::path::PathBuf::from("/workspace")],
    );
    let leaf = args
        .windows(3)
        .position(|triple| triple == ["--ro-bind", "/workspace/protected", "/workspace/protected"])
        .unwrap();
    assert_eq!(leaf, 0);
    assert!(!args.windows(3).any(|triple| {
        triple == ["--bind", "/workspace", "/workspace"]
            || triple == ["--ro-bind", "/workspace", "/workspace"]
    }));
}

#[test]
fn existing_read_only_parent_is_not_rebound_over_writable_descendant_mounts() {
    let mut args = Vec::new();
    let _mountpoints = append_hard_denials(
        &mut args,
        &[rule(
            "/host/protected",
            crate::access::DeniedPathKind::File,
            &[],
        )],
        &[],
        &denied_nodes(),
        &[],
        |_| true,
        &[std::path::PathBuf::from("/host/writable")],
    );
    let leaf = args
        .windows(3)
        .position(|triple| triple == ["--ro-bind", "/host/protected", "/host/protected"])
        .unwrap();
    assert_eq!(leaf, 0);
    assert!(!args.windows(3).any(|triple| {
        triple == ["--bind", "/host", "/host"] || triple == ["--ro-bind", "/host", "/host"]
    }));
    assert!(!args
        .windows(2)
        .any(|pair| pair == ["--remount-ro", "/host"]));
}

#[test]
fn temporary_parent_rebind_restores_writable_descendant_before_read_only_remount() {
    let mut args = Vec::new();
    let _mountpoints = append_hard_denials(
        &mut args,
        &[rule(
            "/host/.cdm/rootfs",
            crate::access::DeniedPathKind::Missing,
            &["/host/.cdm"],
        )],
        &[],
        &denied_nodes(),
        &[],
        |_| true,
        &[std::path::PathBuf::from("/host/writable")],
    );

    let parent = args
        .windows(3)
        .position(|triple| triple == ["--bind", "/host", "/host"])
        .unwrap();
    let writable_descendant = args
        .windows(3)
        .position(|triple| triple == ["--bind", "/host/writable", "/host/writable"])
        .unwrap();
    let parent_remount = args
        .windows(2)
        .position(|pair| pair == ["--remount-ro", "/host"])
        .unwrap();
    assert!(parent < writable_descendant);
    assert!(writable_descendant < parent_remount);
}

#[test]
fn missing_leaf_below_read_only_parent_uses_the_parent_denial_without_a_placeholder() {
    let mut args = Vec::new();
    let _mountpoints = append_hard_denials(
        &mut args,
        &[
            rule(
                "/home/user/cache",
                crate::access::DeniedPathKind::Directory,
                &[],
            ),
            rule(
                "/home/user/cache/rootfs",
                crate::access::DeniedPathKind::Missing,
                &[],
            ),
        ],
        &[],
        &denied_nodes(),
        &[],
        |_| true,
        &[],
    );
    let parent = args
        .windows(3)
        .position(|triple| triple == ["--bind", "/home/user/cache", "/home/user/cache"])
        .unwrap();
    let protected_directory = args
        .windows(3)
        .position(|triple| triple == ["--ro-bind", "/home/user/cache", "/home/user/cache"])
        .unwrap();
    assert!(parent < protected_directory);
    assert!(!args
        .windows(2)
        .any(|pair| pair == ["--remount-ro", "/home/user/cache"]));
    assert!(!args.windows(3).any(|triple| {
        triple
            == [
                "--ro-bind",
                "/fixtures/denied/read-only",
                "/home/user/cache/rootfs",
            ]
    }));
}

#[test]
fn missing_leaf_below_writable_parent_uses_a_narrow_placeholder() {
    let mut args = Vec::new();
    let _mountpoints = append_hard_denials(
        &mut args,
        &[rule(
            "/workspace/future",
            crate::access::DeniedPathKind::Missing,
            &[],
        )],
        &[],
        &denied_nodes(),
        &[],
        |_| true,
        &[std::path::PathBuf::from("/workspace")],
    );
    assert!(args.windows(3).any(|triple| {
        triple
            == [
                "--ro-bind",
                "/fixtures/denied/read-only",
                "/workspace/future",
            ]
    }));
}

#[test]
fn synthetic_runtime_tree_does_not_recreate_denied_socket_placeholders() {
    let mut args = Vec::new();
    let _mountpoints = append_hard_denials(
        &mut args,
        &[rule(
            "/var/run/docker.sock",
            crate::access::DeniedPathKind::Missing,
            &[],
        )],
        &[rule(
            "/run/docker.sock",
            crate::access::DeniedPathKind::Missing,
            &[],
        )],
        &denied_nodes(),
        &[
            std::path::PathBuf::from("/run"),
            std::path::PathBuf::from("/var/run"),
        ],
        |_| true,
        &[],
    );
    assert!(args.is_empty());
}

#[test]
fn isolated_mode_does_not_expose_an_unreachable_denial_parent() {
    let mut args = Vec::new();
    let _mountpoints = append_hard_denials(
        &mut args,
        &[rule(
            "/home/user/.ssh/authorized_keys",
            crate::access::DeniedPathKind::Missing,
            &["/home/user/.ssh"],
        )],
        &[],
        &denied_nodes(),
        &[],
        |path| path.starts_with("/workspace"),
        &[],
    );
    assert!(args.is_empty());
}

#[test]
fn seccomp_program_fd_is_a_bwrap_policy_argument() {
    let mut args = vec!["--cap-drop".to_string(), "ALL".to_string()];
    append_seccomp(&mut args, 17);
    args.push("--".to_string());

    assert_eq!(args, ["--cap-drop", "ALL", "--seccomp", "17", "--"]);
}

#[test]
fn bwrap_signal_exit_convention_retains_the_originating_signal() {
    let status = preserve_bwrap_signal_status(crate::process::ChildStatus::exited(143));
    assert_eq!(status.exit_code, 143);
    assert_eq!(status.signal, Some(libc::SIGTERM));

    let ordinary = preserve_bwrap_signal_status(crate::process::ChildStatus::exited(42));
    assert_eq!(ordinary.signal, None);
}
