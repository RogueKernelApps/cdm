//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;

fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cdm-project-{name}-{}", std::process::id()))
}

#[test]
fn nearest_project_config_wins() {
    let root = temp("nearest");
    let nested_project = root.join("outer/inner");
    let launch = nested_project.join("src/deep");
    std::fs::create_dir_all(root.join("outer/.cdm")).unwrap();
    std::fs::create_dir_all(nested_project.join(".cdm")).unwrap();
    std::fs::create_dir_all(&launch).unwrap();
    std::fs::write(root.join("outer/.cdm/config.json"), "{}").unwrap();
    std::fs::write(nested_project.join(".cdm/config.json"), "{}").unwrap();

    let context = discover(&launch).unwrap();
    assert_eq!(context.root, nested_project.canonicalize().unwrap());
    assert_eq!(
        context.config_path,
        Some(
            nested_project
                .join(".cdm/config.json")
                .canonicalize()
                .unwrap()
        )
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn git_root_is_the_fallback() {
    let root = temp("git");
    let launch = root.join("src/deep");
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(&launch).unwrap();
    let context = discover(&launch).unwrap();
    assert_eq!(context.root, root.canonicalize().unwrap());
    assert_eq!(context.config_path, None);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn home_global_config_is_not_reinterpreted_as_project_policy() {
    let home = temp("home-boundary");
    let project = home.join("projects/example");
    let launch = project.join("src");
    std::fs::create_dir_all(home.join(".cdm")).unwrap();
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::create_dir_all(&launch).unwrap();
    std::fs::write(home.join(".cdm/config.json"), "{}").unwrap();

    let canonical_home = home.canonicalize().unwrap();
    let context = discover_with_home(&launch, Some(&canonical_home)).unwrap();

    assert_eq!(context.root, project.canonicalize().unwrap());
    assert_eq!(context.config_path, None);
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn account_home_remains_a_boundary_when_effective_home_is_overridden() {
    let account = temp("account-home-boundary");
    let effective = temp("effective-home-boundary");
    let project = account.join("projects/example");
    let launch = project.join("src");
    std::fs::create_dir_all(account.join(".cdm")).unwrap();
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::create_dir_all(&launch).unwrap();
    std::fs::create_dir_all(&effective).unwrap();
    std::fs::write(account.join(".cdm/config.json"), "{}").unwrap();

    let homes = vec![
        effective.canonicalize().unwrap(),
        account.canonicalize().unwrap(),
    ];
    let context = discover_with_homes(&launch, &homes).unwrap();

    assert_eq!(context.root, project.canonicalize().unwrap());
    assert_eq!(context.config_path, None);
    std::fs::remove_dir_all(account).unwrap();
    std::fs::remove_dir_all(effective).unwrap();
}

#[test]
fn project_kind_detection_is_deterministic_and_non_mutating() {
    let root = temp("kinds");
    std::fs::create_dir_all(root.join(".git")).unwrap();
    assert_eq!(detect_kind(&root), ProjectKind::Git);
    std::fs::write(root.join("package.json"), "{}").unwrap();
    assert_eq!(detect_kind(&root), ProjectKind::Node);
    std::fs::write(root.join("Cargo.toml"), "[package]").unwrap();
    assert_eq!(detect_kind(&root), ProjectKind::Rust);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn symlinked_project_config_is_rejected() {
    use std::os::unix::fs::symlink;
    let root = temp("symlink");
    std::fs::create_dir_all(root.join(".cdm")).unwrap();
    std::fs::write(root.join("outside.json"), "{}").unwrap();
    symlink(root.join("outside.json"), root.join(".cdm/config.json")).unwrap();
    let error = discover(&root).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let _ = std::fs::remove_dir_all(root);
}
