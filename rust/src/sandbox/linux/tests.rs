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
    append_hard_denials(
        &mut args,
        &[rule(
            "/home/user/.ssh/authorized_keys",
            crate::access::DeniedPathKind::Missing,
            &["/home/user/.ssh"],
        )],
        &[rule(
            "/home/user/.ssh/config",
            crate::access::DeniedPathKind::Missing,
            &["/home/user/.ssh"],
        )],
        &denied_nodes(),
        &[],
        |_| true,
        |_| false,
    );

    let directory = args
        .windows(2)
        .position(|pair| pair == ["--tmpfs", "/home/user/.ssh"])
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
    assert!(directory < leaf);
    assert_eq!(
        args.windows(2)
            .filter(|pair| pair == &["--tmpfs", "/home/user/.ssh"])
            .count(),
        1
    );
}

#[test]
fn directory_read_denial_uses_an_inaccessible_directory_overlay() {
    let mut args = Vec::new();
    append_hard_denials(
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
        |_| false,
    );

    assert!(args
        .windows(3)
        .any(|triple| { triple == ["--ro-bind", "/fixtures/denied/dir", "/home/user/private"] }));
}

#[test]
fn existing_writable_parent_is_pinned_before_its_denied_leaf() {
    let mut args = Vec::new();
    append_hard_denials(
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
        |path| path == Path::new("/workspace"),
    );
    let parent = args
        .windows(3)
        .position(|triple| triple == ["--bind", "/workspace", "/workspace"])
        .unwrap();
    let leaf = args
        .windows(3)
        .position(|triple| triple == ["--ro-bind", "/workspace/protected", "/workspace/protected"])
        .unwrap();
    assert!(parent < leaf);
}

#[test]
fn synthetic_runtime_tree_does_not_recreate_denied_socket_placeholders() {
    let mut args = Vec::new();
    append_hard_denials(
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
        |_| false,
    );
    assert!(args.is_empty());
}

#[test]
fn isolated_mode_does_not_expose_an_unreachable_denial_parent() {
    let mut args = Vec::new();
    append_hard_denials(
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
        |_| false,
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
