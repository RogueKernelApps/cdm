//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic counter to ensure unique temp dir names across parallel tests.
static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Creates a temporary git repo with one initial commit.
/// Returns the path to the repo root.
fn create_test_repo() -> PathBuf {
    let seq = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "cdm-test-repo-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        seq
    ));
    // Ensure clean slate
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    // Set up git config for this repo so tests don't need global config
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .current_dir(&dir)
            .env("GIT_AUTHOR_NAME", "CDM Test")
            .env("GIT_AUTHOR_EMAIL", "test@cdm.local")
            .env("GIT_COMMITTER_NAME", "CDM Test")
            .env("GIT_COMMITTER_EMAIL", "test@cdm.local")
            .output()
            .expect("git command failed");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    };

    git(&["init"]);
    git(&["config", "user.name", "CDM Test"]);
    git(&["config", "user.email", "test@cdm.local"]);

    // Create an initial file and commit
    fs::write(dir.join("README.md"), "# Test repo\n").unwrap();
    git(&["add", "README.md"]);
    git(&["commit", "-m", "initial commit"]);

    dir
}

/// Cleans up a test repo directory.
fn cleanup(dir: &Path) {
    // Remove any worktrees first to avoid git lock issues
    let _ = Command::new("git")
        .args(["worktree", "prune"])
        .current_dir(dir)
        .output();
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_find_git_root() {
    let repo = create_test_repo();

    // Create a subdirectory and verify root is found from it
    let subdir = repo.join("src");
    fs::create_dir_all(&subdir).unwrap();

    let root = find_git_root(&subdir).unwrap();
    assert_eq!(root, repo.canonicalize().unwrap_or(repo.clone()));

    cleanup(&repo);
}

#[test]
fn test_find_git_root_not_a_repo() {
    // Use a temp dir that is definitely not a git repo
    let dir = std::env::temp_dir().join(format!(
        "cdm-test-nogit-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();

    let result = find_git_root(&dir);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not a git repository"),
        "unexpected error: {}",
        err_msg
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_generate_branch_name() {
    let name = generate_branch_name("my-project");

    assert!(
        name.starts_with("CDM__"),
        "expected CDM__ prefix, got: {}",
        name
    );
    // Should contain the folder name
    assert!(
        name.contains("my-project"),
        "expected folder name in: {}",
        name
    );

    // Verify date component is present (YYYY-MM-DD format)
    let parts: Vec<&str> = name.split("__").collect();
    assert_eq!(parts.len(), 4, "expected 4 parts in: {}", name);
    assert_eq!(parts[0], "CDM");
    // parts[1] is the date
    assert_eq!(
        parts[1].len(),
        10,
        "date should be YYYY-MM-DD: {}",
        parts[1]
    );
    assert_eq!(&parts[1][4..5], "-");
    assert_eq!(&parts[1][7..8], "-");
    // parts[2] is the folder
    assert_eq!(parts[2], "my-project");
    // parts[3] is the user
    assert!(!parts[3].is_empty(), "user part should not be empty");
}

#[test]
fn test_create_worktree() {
    let repo = create_test_repo();

    let info = create_worktree(&repo).unwrap();

    // Worktree directory should exist and contain the repo files
    assert!(info.worktree_dir.exists(), "worktree dir should exist");
    assert_eq!(
        info.worktree_dir,
        info.worktree_dir.canonicalize().unwrap(),
        "worktree paths must use one physical spelling for VM plans"
    );
    assert!(
        info.worktree_dir.join("README.md").exists(),
        "README.md should exist in worktree"
    );

    // Read the file to verify content matches
    let content = fs::read_to_string(info.worktree_dir.join("README.md")).unwrap();
    assert_eq!(content, "# Test repo\n");

    // Branch name should follow the convention
    assert!(info.branch_name.starts_with("CDM__"));
    assert_eq!(info.execution_dir, info.worktree_dir);
    assert!(
        !info.execution_dir.as_os_str().as_bytes().ends_with(b"/"),
        "root-level execution paths must not retain a trailing separator"
    );

    // Clean up worktree
    let _ = run_git(
        &[
            "worktree",
            "remove",
            "--force",
            &info.worktree_dir.to_string_lossy(),
        ],
        &info.repo_root,
    );
    cleanup(&repo);
}

#[test]
fn test_create_worktree_preserves_nested_execution_directory() {
    let repo = create_test_repo();
    let nested = repo.join("src/nested");
    fs::create_dir_all(&nested).unwrap();
    let info = create_worktree(&nested).unwrap();

    assert_eq!(info.execution_dir, info.worktree_dir.join("src/nested"));

    run_git(
        &[
            "worktree",
            "remove",
            "--force",
            &info.worktree_dir.to_string_lossy(),
        ],
        &info.repo_root,
    )
    .unwrap();
    cleanup(&repo);
}

#[test]
fn test_repeated_worktrees_receive_unique_branch_names() {
    let repo = create_test_repo();
    let first = create_worktree(&repo).unwrap();
    fs::write(first.worktree_dir.join("first.txt"), "first\n").unwrap();
    let first_branch = first.branch_name.clone();
    finalize_worktree(&first).unwrap();

    let second = create_worktree(&repo).unwrap();
    assert_ne!(second.branch_name, first_branch);
    assert_eq!(second.branch_name, format!("{first_branch}__2"));
    finalize_worktree(&second).unwrap();
    cleanup(&repo);
}

#[test]
fn test_concurrent_worktrees_reserve_unique_branch_names() {
    let repo = create_test_repo();
    let first = create_worktree(&repo).unwrap();
    let second = create_worktree(&repo).unwrap();

    assert_ne!(first.branch_name, second.branch_name);

    discard_worktree(&first).unwrap();
    discard_worktree(&second).unwrap();
    cleanup(&repo);
}

#[test]
fn test_create_worktree_seeds_tracked_and_untracked_changes() {
    let repo = create_test_repo();
    fs::write(repo.join("README.md"), "# Dirty tracked\n").unwrap();
    fs::write(repo.join("untracked.txt"), "dirty untracked\n").unwrap();

    let info = create_worktree(&repo).unwrap();

    assert_eq!(
        fs::read_to_string(info.worktree_dir.join("README.md")).unwrap(),
        "# Dirty tracked\n"
    );
    assert_eq!(
        fs::read_to_string(info.worktree_dir.join("untracked.txt")).unwrap(),
        "dirty untracked\n"
    );
    assert_eq!(
        fs::read_to_string(repo.join("README.md")).unwrap(),
        "# Dirty tracked\n"
    );

    finalize_worktree(&info).unwrap();
    cleanup(&repo);
}

#[test]
fn tracked_deletion_is_preserved_in_the_result_tree() {
    let repo = create_test_repo();
    fs::remove_file(repo.join("README.md")).unwrap();
    let info = create_worktree(&repo).unwrap();
    assert!(!info.worktree_dir.join("README.md").exists());
    assert!(
        info.observed_tracked_paths
            .contains(b"README.md".as_slice()),
        "normal tracked deletion was classified as sparse"
    );
    let result = finalize_worktree(&info).unwrap();
    let branch = match result {
        WorktreeResult::Committed { branch, .. } => branch,
        WorktreeResult::NoChanges => panic!("tracked deletion was lost"),
    };

    assert!(run_git(&["cat-file", "-e", &format!("{branch}:README.md")], &repo).is_err());
    cleanup(&repo);
}

#[test]
fn test_branch_segments_are_valid_and_readable() {
    assert_eq!(
        sanitize_branch_segment("my project@2026"),
        "my-project-2026"
    );
    assert_eq!(sanitize_branch_segment("..."), "unknown");
}

#[test]
fn test_finalize_no_changes() {
    let repo = create_test_repo();

    let info = create_worktree(&repo).unwrap();

    // Don't modify anything — finalize should return NoChanges
    let result = finalize_worktree(&info).unwrap();
    assert!(
        matches!(result, WorktreeResult::NoChanges),
        "expected NoChanges when no files modified"
    );

    // Worktree directory should be cleaned up
    assert!(
        !info.worktree_dir.exists(),
        "worktree dir should be removed after finalize"
    );

    cleanup(&repo);
}

#[test]
fn test_finalize_with_changes() {
    let repo = create_test_repo();

    let info = create_worktree(&repo).unwrap();
    let branch_name = info.branch_name.clone();
    let repo_root = info.repo_root.clone();

    // Make changes in the worktree
    fs::write(info.worktree_dir.join("new_file.txt"), "hello from CDM\n").unwrap();
    fs::write(
        info.worktree_dir.join("README.md"),
        "# Test repo\n\nModified by CDM.\n",
    )
    .unwrap();

    // Set git identity for the commit inside the worktree
    let _ = Command::new("git")
        .args(["config", "user.name", "CDM Test"])
        .current_dir(&info.worktree_dir)
        .output();
    let _ = Command::new("git")
        .args(["config", "user.email", "test@cdm.local"])
        .current_dir(&info.worktree_dir)
        .output();

    let result = finalize_worktree(&info).unwrap();

    match result {
        WorktreeResult::Committed {
            ref branch,
            base_commit: _,
            files_changed,
            insertions,
            deletions,
        } => {
            assert_eq!(branch, &branch_name);
            assert!(files_changed > 0, "expected files_changed > 0");
            assert!(insertions > 0, "expected insertions > 0");
            // There should be at least some deletions (README was modified)
            // or at minimum, the stats should be non-negative
            let _ = deletions; // may be 0 depending on git's perspective
        }
        WorktreeResult::NoChanges => {
            panic!("expected Committed, got NoChanges");
        }
    }

    // Branch should exist in the original repo
    let branch_check = run_git(&["rev-parse", "--verify", &branch_name], &repo_root);
    assert!(
        branch_check.is_ok(),
        "branch {} should exist in original repo",
        branch_name
    );

    // Worktree directory should be cleaned up
    assert!(
        !info.worktree_dir.exists(),
        "worktree dir should be removed after finalize"
    );

    cleanup(&repo);
}

#[test]
fn finalize_never_runs_repository_hooks() {
    let repo = create_test_repo();
    let marker = repo.parent().unwrap().join(format!(
        "cdm-test-hook-fired-{}-{}",
        std::process::id(),
        TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let hooks = repo.join("hostile-hooks");
    fs::create_dir_all(&hooks).unwrap();
    let hook = hooks.join("pre-commit");
    fs::write(
        &hook,
        format!(
            "#!/bin/sh\nprintf fired > '{}'\nexit 73\n",
            marker.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    run_git(
        &["config", "core.hooksPath", &hooks.to_string_lossy()],
        &repo,
    )
    .unwrap();

    let info = create_worktree(&repo).unwrap();
    fs::write(info.worktree_dir.join("result.txt"), "safe\n").unwrap();
    let result = finalize_worktree(&info).unwrap();

    assert!(matches!(result, WorktreeResult::Committed { .. }));
    assert!(
        !marker.exists(),
        "trusted host finalization ran a repository hook"
    );
    cleanup(&repo);
    let _ = fs::remove_file(marker);
}

#[test]
fn finalize_never_runs_repository_clean_filters() {
    let repo = create_test_repo();
    let marker = repo.parent().unwrap().join(format!(
        "cdm-test-filter-fired-{}-{}",
        std::process::id(),
        TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let filter = repo.join("hostile-filter.sh");
    fs::write(
        &filter,
        format!(
            "#!/bin/sh\nprintf fired > '{}'\ncat\nexit 75\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&filter, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(repo.join(".gitattributes"), "*.victim filter=hostile\n").unwrap();
    run_git(
        &["config", "filter.hostile.clean", &filter.to_string_lossy()],
        &repo,
    )
    .unwrap();

    let info = create_worktree(&repo).unwrap();
    fs::write(info.worktree_dir.join("result.victim"), "unfiltered\n").unwrap();
    let result = finalize_worktree(&info).unwrap();
    let branch = match result {
        WorktreeResult::Committed { branch, .. } => branch,
        WorktreeResult::NoChanges => panic!("expected result commit"),
    };

    assert!(
        !marker.exists(),
        "trusted host finalization ran a clean filter"
    );
    assert_eq!(
        run_git(&["show", &format!("{branch}:result.victim")], &repo).unwrap(),
        "unfiltered\n"
    );
    cleanup(&repo);
    let _ = fs::remove_file(marker);
}

#[test]
fn creation_never_runs_repository_smudge_filters() {
    let repo = create_test_repo();
    let marker = repo.parent().unwrap().join(format!(
        "cdm-test-smudge-fired-{}-{}",
        std::process::id(),
        TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let filter = repo.join("hostile-smudge.sh");
    fs::write(
        &filter,
        format!(
            "#!/bin/sh\nprintf fired > '{}'\ncat\nexit 76\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&filter, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(repo.join(".gitattributes"), "*.victim filter=hostile\n").unwrap();
    fs::write(repo.join("tracked.victim"), "raw\n").unwrap();
    run_git(&["add", ".gitattributes", "tracked.victim"], &repo).unwrap();
    run_git(&["commit", "-m", "add filtered fixture"], &repo).unwrap();
    run_git(
        &["config", "filter.hostile.smudge", &filter.to_string_lossy()],
        &repo,
    )
    .unwrap();

    let info = create_worktree(&repo).unwrap();

    assert!(
        !marker.exists(),
        "trusted host creation ran a smudge filter"
    );
    assert_eq!(
        fs::read_to_string(info.worktree_dir.join("tracked.victim")).unwrap(),
        "raw\n"
    );
    discard_worktree(&info).unwrap();
    cleanup(&repo);
    let _ = fs::remove_file(marker);
}

#[test]
fn creation_copies_the_users_materialized_tracked_bytes() {
    let repo = create_test_repo();
    fs::write(repo.join("asset.bin"), "stored-pointer\n").unwrap();
    run_git(&["add", "asset.bin"], &repo).unwrap();
    run_git(&["commit", "-m", "add stored asset"], &repo).unwrap();
    fs::write(repo.join("asset.bin"), "materialized-working-copy\n").unwrap();

    let info = create_worktree(&repo).unwrap();

    assert_eq!(
        fs::read_to_string(info.worktree_dir.join("asset.bin")).unwrap(),
        "materialized-working-copy\n"
    );
    discard_worktree(&info).unwrap();
    cleanup(&repo);
}

#[test]
fn sparse_checkout_absence_is_preserved_without_becoming_a_deletion() {
    let repo = create_test_repo();
    fs::create_dir_all(repo.join("included")).unwrap();
    fs::create_dir_all(repo.join("excluded")).unwrap();
    fs::write(repo.join("included/file.txt"), "included\n").unwrap();
    fs::write(repo.join("excluded/file.txt"), "excluded\n").unwrap();
    run_git(&["add", "included", "excluded"], &repo).unwrap();
    run_git(&["commit", "-m", "add sparse fixture"], &repo).unwrap();
    run_git(&["sparse-checkout", "init", "--cone"], &repo).unwrap();
    run_git(&["sparse-checkout", "set", "included"], &repo).unwrap();
    assert!(!repo.join("excluded/file.txt").exists());

    let info = create_worktree(&repo).unwrap();

    assert!(info.worktree_dir.join("included/file.txt").exists());
    assert!(!info.worktree_dir.join("excluded/file.txt").exists());
    assert!(matches!(
        finalize_worktree(&info).unwrap(),
        WorktreeResult::NoChanges
    ));
    cleanup(&repo);
}

#[test]
fn workspace_lifecycle_never_runs_repository_process_filters() {
    let repo = create_test_repo();
    let marker = repo.parent().unwrap().join(format!(
        "cdm-test-process-filter-fired-{}-{}",
        std::process::id(),
        TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let filter = repo.join("hostile-process-filter.sh");
    fs::write(
        &filter,
        format!(
            "#!/bin/sh\nprintf fired > '{}'\nexit 77\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&filter, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(repo.join(".gitattributes"), "*.victim filter=hostile\n").unwrap();
    fs::write(repo.join("tracked.victim"), "raw\n").unwrap();
    run_git(&["add", ".gitattributes", "tracked.victim"], &repo).unwrap();
    run_git(&["commit", "-m", "add process-filter fixture"], &repo).unwrap();
    run_git(
        &[
            "config",
            "filter.hostile.process",
            &filter.to_string_lossy(),
        ],
        &repo,
    )
    .unwrap();
    run_git(&["config", "filter.hostile.required", "true"], &repo).unwrap();

    let info = create_worktree(&repo).unwrap();
    fs::write(info.worktree_dir.join("result.victim"), "raw-result\n").unwrap();
    let result = finalize_worktree(&info).unwrap();

    assert!(matches!(result, WorktreeResult::Committed { .. }));
    assert!(!marker.exists(), "trusted Git ran a process filter");
    cleanup(&repo);
    let _ = fs::remove_file(marker);
}

#[test]
fn finalize_rejects_a_replaced_worktree_gitfile() {
    let repo = create_test_repo();
    let info = create_worktree(&repo).unwrap();
    fs::write(info.worktree_dir.join("result.txt"), "unsafe\n").unwrap();
    fs::write(info.worktree_dir.join(".git"), "gitdir: /tmp/attacker\n").unwrap();

    let error = match finalize_worktree(&info) {
        Ok(_) => panic!("replaced gitfile was accepted"),
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("Git metadata changed"),
        "unexpected error: {error}"
    );
    // Cleanup through the original repository, never through the replaced
    // untrusted gitfile.
    let _ = Command::new("git")
        .args(["worktree", "remove", "--force"])
        .arg(&info.worktree_dir)
        .current_dir(&repo)
        .output();
    cleanup(&repo);
}

#[test]
fn finalize_rejects_a_replaced_actual_git_directory() {
    let repo = create_test_repo();
    let info = create_worktree(&repo).unwrap();
    fs::write(info.worktree_dir.join("result.txt"), "unsafe\n").unwrap();
    let git_dir = info.metadata.git_dir.path.clone();
    let original = git_dir.with_extension("cdm-original");
    fs::rename(&git_dir, &original).unwrap();
    fs::create_dir(&git_dir).unwrap();

    let error = match finalize_worktree(&info) {
        Ok(_) => panic!("replaced actual Git directory was accepted"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("Git metadata changed"));
    fs::remove_dir(&git_dir).unwrap();
    fs::rename(&original, &git_dir).unwrap();
    discard_worktree(&info).unwrap();
    cleanup(&repo);
}

#[test]
fn test_epoch_to_date() {
    // 2024-01-01 00:00:00 UTC = 1704067200
    assert_eq!(epoch_to_date(1704067200), "2024-01-01");
    // 2023-06-15 12:00:00 UTC = 1686830400
    assert_eq!(epoch_to_date(1686830400), "2023-06-15");
    // Unix epoch
    assert_eq!(epoch_to_date(0), "1970-01-01");
}

#[test]
fn test_run_git_not_a_repo() {
    let dir = std::env::temp_dir().join(format!(
        "cdm-test-rungit-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();

    let result = run_git(&["status"], &dir);
    assert!(result.is_err());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_print_summary_no_changes() {
    // Just verify it doesn't panic
    print_summary(&WorktreeResult::NoChanges);
}

#[test]
fn test_print_summary_committed() {
    // Just verify it doesn't panic
    print_summary(&WorktreeResult::Committed {
        branch: "CDM__2026-03-25__project__user".to_string(),
        base_commit: "0123456789abcdef".to_string(),
        files_changed: 3,
        insertions: 10,
        deletions: 2,
    });
}
