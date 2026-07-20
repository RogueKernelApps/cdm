//! Ephemeral Git worktree management.
//!
//! When `--worktree` mode is active, CDM creates a git worktree copy of the
//! current repo, sandboxes the command against the worktree (not the real
//! codebase), and on exit commits any changes to a named branch.
//!
//! All git operations use `std::process::Command` — no git library dependency.

use std::collections::BTreeSet;
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

enum WorktreeEntry {
    Missing,
    Regular { file: File, executable: bool },
    Symlink { relative: PathBuf, target: OsString },
    Directory,
}

struct WorktreeRoot {
    fd: OwnedFd,
}

impl WorktreeRoot {
    fn open(path: &Path) -> io::Result<Self> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "worktree path contains NUL")
        })?;
        // SAFETY: `path` is a valid NUL-terminated string and the returned fd
        // is immediately transferred into `OwnedFd`.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        Ok(Self { fd: owned_fd(fd)? })
    }

    fn inspect(&self, relative: &Path) -> io::Result<WorktreeEntry> {
        let components = relative
            .components()
            .map(|component| match component {
                std::path::Component::Normal(value) => c_name(value),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid Git snapshot path: {}", relative.display()),
                )),
            })
            .collect::<io::Result<Vec<_>>>()?;
        if components.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty Git snapshot path",
            ));
        }

        let mut parent = duplicate_fd(&self.fd)?;
        let mut prefix = PathBuf::new();
        for component in &components[..components.len() - 1] {
            prefix.push(OsStr::from_bytes(component.as_bytes()));
            match open_directory_at(&parent, component) {
                Ok(next) => parent = next,
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                    return Ok(WorktreeEntry::Missing);
                }
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ELOOP) | Some(libc::ENOTDIR)
                    ) =>
                {
                    let stat = stat_at(&parent, component)?;
                    if file_type(stat.st_mode) == libc::S_IFLNK {
                        return Ok(WorktreeEntry::Symlink {
                            relative: prefix,
                            target: read_link_at(&parent, component)?,
                        });
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "non-directory ancestor in Git snapshot path: {}",
                            relative.display()
                        ),
                    ));
                }
                Err(error) => return Err(error),
            }
        }

        let leaf = components
            .last()
            .expect("non-empty components checked above");
        let stat = match stat_at(&parent, leaf) {
            Ok(stat) => stat,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                return Ok(WorktreeEntry::Missing);
            }
            Err(error) => return Err(error),
        };
        match file_type(stat.st_mode) {
            libc::S_IFREG => {
                // SAFETY: `parent` and `leaf` are valid descriptors/strings;
                // `O_NOFOLLOW` prevents a raced leaf symlink from being opened.
                let fd = unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        leaf.as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    )
                };
                let fd = owned_fd(fd)?;
                let opened = fstat(&fd)?;
                if file_type(opened.st_mode) != libc::S_IFREG {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Git snapshot path changed type: {}", relative.display()),
                    ));
                }
                Ok(WorktreeEntry::Regular {
                    file: File::from(fd),
                    executable: opened.st_mode & 0o111 != 0,
                })
            }
            libc::S_IFLNK => Ok(WorktreeEntry::Symlink {
                relative: relative.to_path_buf(),
                target: read_link_at(&parent, leaf)?,
            }),
            libc::S_IFDIR => Ok(WorktreeEntry::Directory),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported file type in Git snapshot: {}",
                    relative.display()
                ),
            )),
        }
    }
}

fn c_name(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Git snapshot path component contains NUL",
        )
    })
}

fn duplicate_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
    // SAFETY: `fd` is valid and the duplicated descriptor is immediately owned.
    let duplicated = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    owned_fd(duplicated)
}

fn open_directory_at(parent: &OwnedFd, name: &CString) -> io::Result<OwnedFd> {
    // SAFETY: `parent` and `name` are valid; ownership of the result is
    // transferred immediately.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    owned_fd(fd)
}

fn owned_fd(fd: libc::c_int) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: a successful syscall returned a new descriptor owned here.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn stat_at(parent: &OwnedFd, name: &CString) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: pointers are valid and `stat` is initialized on success.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        // SAFETY: successful `fstatat` initialized the value.
        Ok(unsafe { stat.assume_init() })
    } else {
        Err(io::Error::last_os_error())
    }
}

fn fstat(fd: &OwnedFd) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the descriptor and output pointer are valid.
    let result = unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) };
    if result == 0 {
        // SAFETY: successful `fstat` initialized the value.
        Ok(unsafe { stat.assume_init() })
    } else {
        Err(io::Error::last_os_error())
    }
}

fn file_type(mode: libc::mode_t) -> libc::mode_t {
    mode & libc::S_IFMT
}

fn read_link_at(parent: &OwnedFd, name: &CString) -> io::Result<OsString> {
    let mut capacity = 256usize;
    loop {
        let mut buffer = vec![0u8; capacity];
        // SAFETY: the descriptor/name are valid and the buffer is writable for
        // exactly `capacity` bytes.
        let length = unsafe {
            libc::readlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        let length = length as usize;
        if length < buffer.len() {
            buffer.truncate(length);
            return Ok(OsString::from_vec(buffer));
        }
        capacity = capacity
            .checked_mul(2)
            .filter(|size| *size <= 65_536)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "worktree symlink target is too long",
                )
            })?;
    }
}

/// Information about an active worktree session.
pub struct WorktreeInfo {
    /// The ephemeral worktree directory (sandbox target).
    pub worktree_dir: PathBuf,
    /// Directory inside the worktree corresponding to the invocation cwd.
    pub execution_dir: PathBuf,
    /// Root of the git repository.
    pub repo_root: PathBuf,
    /// Branch name reserved at creation and moved atomically on finalization.
    pub branch_name: String,
    /// Commit from which the detached worktree was created.
    pub base_commit: String,
    git: TrustedGit,
    metadata: GitMetadataIdentity,
    /// Tracked paths visible (or deliberately deleted) in the caller's
    /// checkout. Missing sparse paths are excluded so finalization preserves
    /// their base-tree entries rather than misreporting deletions.
    observed_tracked_paths: BTreeSet<Vec<u8>>,
}

#[derive(Clone)]
struct TrustedGit {
    executable: crate::trusted_exec::TrustedExecutable,
    author_name: String,
    author_email: String,
}

struct GitMetadataIdentity {
    gitfile: PinnedNode,
    gitfile_contents: Vec<u8>,
    git_dir: PinnedNode,
    common_dir: PinnedNode,
}

struct PinnedNode {
    path: PathBuf,
    device: u64,
    inode: u64,
    kind: NodeKind,
}

#[derive(Clone, Copy)]
enum NodeKind {
    File,
    Directory,
}

/// Result of finalizing a worktree session.
pub enum WorktreeResult {
    /// No files were modified — worktree cleaned up silently.
    NoChanges,
    /// Changes were committed and saved to a branch.
    Committed {
        branch: String,
        base_commit: String,
        files_changed: usize,
        insertions: usize,
        deletions: usize,
    },
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Creates a detached git worktree for sandboxed execution.
///
/// 1. Finds the git repo root from `work_dir`.
/// 2. Generates a branch name: `CDM__YYYY-MM-DD__<folder>__<user>`.
/// 3. Creates a temp directory under `$TMPDIR`.
/// 4. Runs `git worktree add --no-checkout --detach <temp_dir> HEAD`.
/// 5. Copies the caller's filter-materialized tracked state and non-ignored
///    untracked files without invoking checkout, diff, or content filters.
/// 6. Pins the Git control metadata that must be immutable in the sandbox.
/// 7. Returns [`WorktreeInfo`] describing the session.
pub fn create_worktree(work_dir: &Path) -> io::Result<WorktreeInfo> {
    let mut git = TrustedGit::discover()?;
    let repo_root = find_git_root_with(&git, work_dir)?;
    let invocation_dir = work_dir.canonicalize()?;
    let relative_dir = invocation_dir.strip_prefix(&repo_root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace directory is outside the repository root",
        )
    })?;

    // Verify the repo has at least one commit
    let base_commit = git.run(&["rev-parse", "HEAD"], &repo_root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "repository has no commits (run git commit first)",
        )
    })?;
    let base_commit = base_commit.trim().to_string();
    let identity = git.run_bytes(&["show", "-s", "--format=%an%x00%ae", "HEAD"], &repo_root)?;
    let mut identity = identity.splitn(3, |byte| *byte == 0);
    git.author_name = String::from_utf8_lossy(identity.next().unwrap_or_default()).to_string();
    git.author_email = String::from_utf8_lossy(identity.next().unwrap_or_default())
        .trim_end()
        .to_string();
    if git.author_name.is_empty() || git.author_email.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cannot determine a safe Git author from HEAD",
        ));
    }

    let folder_name = repo_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("repo");
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_dir =
        std::env::temp_dir().join(format!("cdm-workspace-{}-{}", std::process::id(), nonce));
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir)?;
    }

    git.run(
        &[
            "worktree",
            "add",
            "--no-checkout",
            "--detach",
            &temp_dir.to_string_lossy(),
            "HEAD",
        ],
        &repo_root,
    )?;
    // macOS commonly reports its temporary directory through the public
    // /var alias. Persist one physical spelling so VM guest plans, VirtioFS
    // targets, Git metadata protection, and cleanup all name the same path.
    let temp_dir = temp_dir.canonicalize()?;

    let setup = (|| {
        let observed_tracked_paths = materialize_current_tracked(&git, &repo_root, &temp_dir)?;
        copy_current_untracked(&git, &repo_root, &temp_dir)?;
        // `Path::join("")` preserves a trailing separator in the underlying
        // bytes. Path equality hides that distinction, but the guest plan's
        // strict lexical validation correctly rejects it. Keep the root-level
        // case byte-for-byte normalized.
        let execution_dir = if relative_dir.as_os_str().is_empty() {
            temp_dir.clone()
        } else {
            temp_dir.join(relative_dir)
        };
        std::fs::create_dir_all(&execution_dir)?;
        let branch_name = reserve_unique_branch(&git, &repo_root, folder_name, &base_commit)?;
        let metadata = GitMetadataIdentity::capture(&git, &temp_dir)?;
        Ok::<_, io::Error>((execution_dir, branch_name, metadata, observed_tracked_paths))
    })();
    let (execution_dir, branch_name, metadata, observed_tracked_paths) = match setup {
        Ok(result) => result,
        Err(error) => {
            let _ = git.run(
                &["worktree", "remove", "--force", &temp_dir.to_string_lossy()],
                &repo_root,
            );
            return Err(error);
        }
    };

    Ok(WorktreeInfo {
        execution_dir,
        worktree_dir: temp_dir,
        repo_root,
        branch_name,
        base_commit,
        git,
        metadata,
        observed_tracked_paths,
    })
}

/// Finalizes a worktree session: commits changes (if any) and cleans up.
///
/// If no files were modified, the worktree is simply removed.
/// If files were changed:
///   1. Revalidates pinned Git metadata.
///   2. Hashes raw result bytes and builds a private index/tree from plumbing.
///   3. Creates a commit without hooks, filters, or signing helpers.
///   4. Compare-and-swaps the reserved branch to the result commit.
///   5. Parses diff stats and force-removes the worktree.
pub fn finalize_worktree(info: &WorktreeInfo) -> io::Result<WorktreeResult> {
    info.metadata.validate()?;
    // Build the result tree with plumbing commands. `git add` and `git commit`
    // are deliberately avoided: repository filters, hooks, signing programs,
    // and other porcelain configuration are untrusted after sandbox exit.
    let tree = build_result_tree(info)?;
    let base_tree_spec = format!("{}^{{tree}}", info.base_commit);
    let base_tree = info
        .git
        .run(&["rev-parse", &base_tree_spec], &info.repo_root)?;
    if tree.trim() == base_tree.trim() {
        discard_worktree(info)?;
        return Ok(WorktreeResult::NoChanges);
    }

    let commit_msg = format!("CDM workspace session {}", format_datetime_full());
    let commit_hash = info.git.run(
        &[
            "commit-tree",
            tree.trim(),
            "-p",
            &info.base_commit,
            "-m",
            &commit_msg,
        ],
        &info.repo_root,
    )?;
    let commit_hash = commit_hash.trim().to_string();

    // Atomically move only the branch reservation created by this session.
    let reference = format!("refs/heads/{}", info.branch_name);
    info.git.run(
        &["update-ref", &reference, &commit_hash, &info.base_commit],
        &info.repo_root,
    )?;

    // Parse diff stats
    let (files_changed, insertions, deletions) = parse_diff_stats(info);

    // Remove the worktree
    info.git.run(
        &[
            "worktree",
            "remove",
            "--force",
            &info.worktree_dir.to_string_lossy(),
        ],
        &info.repo_root,
    )?;

    Ok(WorktreeResult::Committed {
        branch: info.branch_name.clone(),
        base_commit: info.base_commit.clone(),
        files_changed,
        insertions,
        deletions,
    })
}

/// Removes an active worktree and its reserved result branch without saving
/// changes. Used for no-op sessions and setup failures before sandbox entry.
pub fn discard_worktree(info: &WorktreeInfo) -> io::Result<()> {
    info.metadata.validate()?;
    info.git.run(
        &[
            "worktree",
            "remove",
            "--force",
            &info.worktree_dir.to_string_lossy(),
        ],
        &info.repo_root,
    )?;
    let reference = format!("refs/heads/{}", info.branch_name);
    info.git.run(
        &["update-ref", "-d", &reference, &info.base_commit],
        &info.repo_root,
    )?;
    Ok(())
}

/// Git control paths that must remain immutable to the sandboxed child.
pub fn protected_metadata_paths(info: &WorktreeInfo) -> Vec<PathBuf> {
    let mut paths = vec![
        info.metadata.gitfile.path.clone(),
        info.metadata.git_dir.path.clone(),
        info.metadata.common_dir.path.clone(),
    ];
    paths.sort();
    paths.dedup();
    paths
}

/// Prints a human-readable summary of the workspace result to stderr.
pub fn print_summary(result: &WorktreeResult) {
    use std::io::Write;
    let stderr = io::stderr();
    let mut err = stderr.lock();

    match result {
        WorktreeResult::NoChanges => {
            let _ = writeln!(err, "[cdm] worktree: no changes, cleaned up");
        }
        WorktreeResult::Committed {
            branch,
            base_commit,
            files_changed,
            insertions,
            deletions,
        } => {
            let _ = writeln!(
                err,
                "[cdm] worktree: {} files changed, {} insertions(+), {} deletions(-)",
                files_changed, insertions, deletions
            );
            let _ = writeln!(err, "[cdm] worktree: changes saved to branch {}", branch);
            let _ = writeln!(err, "[cdm]");
            let _ = writeln!(
                err,
                "[cdm]   View changes:   git diff {}..{}",
                base_commit, branch
            );
            let _ = writeln!(err, "[cdm]   Apply changes:  git merge {}", branch);
            let _ = writeln!(
                err,
                "[cdm]   Open PR:        gh pr create --head {}",
                branch
            );
            let _ = writeln!(err, "[cdm]   Discard:        git branch -D {}", branch);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Finds the git repository root by running `git rev-parse --show-toplevel`.
#[cfg(test)]
fn find_git_root(dir: &Path) -> io::Result<PathBuf> {
    let git = TrustedGit::discover()?;
    find_git_root_with(&git, dir)
}

fn find_git_root_with(git: &TrustedGit, dir: &Path) -> io::Result<PathBuf> {
    let output = git
        .run(&["rev-parse", "--show-toplevel"], dir)
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not found") || msg.contains("No such file") {
                io::Error::new(io::ErrorKind::NotFound, "workspace requires git")
            } else {
                io::Error::new(io::ErrorKind::InvalidData, "not a git repository")
            }
        })?;
    Ok(PathBuf::from(output.trim()))
}

/// Generates a branch name in the format `CDM__YYYY-MM-DD__<folder>__<user>`.
fn generate_branch_name(folder_name: &str) -> String {
    let date = format_date();
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    format!(
        "CDM__{}__{}__{}",
        date,
        sanitize_branch_segment(folder_name),
        sanitize_branch_segment(&user)
    )
}

/// Returns a stable human-readable branch name with a numeric suffix when a
/// repository already contains a branch from the same project/user/day.
fn reserve_unique_branch(
    git: &TrustedGit,
    repo_root: &Path,
    folder_name: &str,
    base_commit: &str,
) -> io::Result<String> {
    let base = generate_branch_name(folder_name);
    for sequence in 1u64.. {
        let candidate = if sequence == 1 {
            base.clone()
        } else {
            format!("{base}__{sequence}")
        };
        let reference = format!("refs/heads/{candidate}");
        match git.run(&["update-ref", &reference, base_commit, ""], repo_root) {
            Ok(_) => return Ok(candidate),
            Err(_) if branch_exists(git, repo_root, &candidate)? => continue,
            Err(error) => return Err(error),
        }
    }
    unreachable!("the branch sequence is unbounded")
}

fn branch_exists(git: &TrustedGit, repo_root: &Path, branch: &str) -> io::Result<bool> {
    let mut command = git.command(repo_root)?;
    let status = command
        .args(["show-ref", "--verify", "--quiet"])
        .arg(format!("refs/heads/{branch}"))
        .status()?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(io::Error::other(format!(
            "git show-ref failed with status {status}"
        ))),
    }
}

fn sanitize_branch_segment(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let sanitized = sanitized.trim_matches('-');
    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized.to_string()
    }
}

/// Copies the caller's materialized tracked filesystem state without invoking
/// checkout, diff, or content filters. `S`/`s` entries are sparse and remain
/// absent when absent in the caller; other absent tracked paths are deliberate
/// deletions observed during finalization.
fn materialize_current_tracked(
    git: &TrustedGit,
    repo_root: &Path,
    worktree_dir: &Path,
) -> io::Result<BTreeSet<Vec<u8>>> {
    let listed = git.run_bytes(&["ls-files", "-v", "-z", "--"], repo_root)?;
    let mut observed = BTreeSet::new();
    for entry in listed
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        if entry.len() < 3 || entry[1] != b' ' {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Git returned an invalid tracked path entry",
            ));
        }
        let tag = entry[0];
        let encoded_path = &entry[2..];
        validate_git_relative_path(encoded_path)?;
        let relative = PathBuf::from(OsString::from_vec(encoded_path.to_vec()));
        let source = repo_root.join(&relative);
        let destination = worktree_dir.join(&relative);
        match std::fs::symlink_metadata(&source) {
            Ok(_) => {
                copy_tracked_path(&source, &destination)?;
                observed.insert(encoded_path.to_vec());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !matches!(tag, b'S' | b's') {
                    observed.insert(encoded_path.to_vec());
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(observed)
}

fn copy_tracked_path(source: &Path, destination: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(source)?;
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if metadata.file_type().is_symlink() {
        std::os::unix::fs::symlink(std::fs::read_link(source)?, destination)
    } else if metadata.is_file() {
        std::fs::copy(source, destination)?;
        let mode = if metadata.permissions().mode() & 0o111 != 0 {
            0o755
        } else {
            0o644
        };
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(mode))
    } else if metadata.is_dir() {
        // A tracked directory entry is a gitlink. Its nested repository is not
        // part of the parent repository snapshot.
        std::fs::create_dir(destination)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported tracked path type: {}", source.display()),
        ))
    }
}

/// Copies non-ignored untracked files after tracked state has been materialized.
fn copy_current_untracked(
    git: &TrustedGit,
    repo_root: &Path,
    worktree_dir: &Path,
) -> io::Result<()> {
    let untracked = git.run_bytes(
        &["ls-files", "--others", "--exclude-standard", "-z"],
        repo_root,
    )?;
    for encoded_path in untracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let relative = PathBuf::from(std::ffi::OsString::from_vec(encoded_path.to_vec()));
        if relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "git returned an unsafe untracked path: {}",
                    relative.display()
                ),
            ));
        }
        copy_untracked_path(&repo_root.join(&relative), &worktree_dir.join(relative))?;
    }
    Ok(())
}

fn copy_untracked_path(source: &Path, destination: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(source)?;
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if metadata.file_type().is_symlink() {
        std::os::unix::fs::symlink(std::fs::read_link(source)?, destination)
    } else if metadata.is_file() {
        std::fs::copy(source, destination).map(|_| ())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported untracked path type: {}", source.display()),
        ))
    }
}

impl TrustedGit {
    fn discover() -> io::Result<Self> {
        Ok(Self {
            executable: crate::trusted_exec::git()?,
            author_name: String::new(),
            author_email: String::new(),
        })
    }

    fn command(&self, cwd: &Path) -> io::Result<Command> {
        let mut command = self.executable.command()?;
        crate::trusted_exec::sanitize_host_environment(&mut command);
        command
            .current_dir(cwd)
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_PAGER", "cat")
            .env("GIT_EDITOR", "false")
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "commit.gpgSign=false",
                "-c",
                "tag.gpgSign=false",
                "-c",
                "core.pager=cat",
                "-c",
                "pager.diff=false",
                "-c",
                "pager.status=false",
            ]);
        if !self.author_name.is_empty() {
            command
                .env("GIT_AUTHOR_NAME", &self.author_name)
                .env("GIT_COMMITTER_NAME", &self.author_name);
        }
        if !self.author_email.is_empty() {
            command
                .env("GIT_AUTHOR_EMAIL", &self.author_email)
                .env("GIT_COMMITTER_EMAIL", &self.author_email);
        }
        Ok(command)
    }

    fn run(&self, args: &[&str], cwd: &Path) -> io::Result<String> {
        Ok(String::from_utf8_lossy(&self.run_bytes(args, cwd)?).to_string())
    }

    fn run_bytes(&self, args: &[&str], cwd: &Path) -> io::Result<Vec<u8>> {
        let output = self.command(cwd)?.args(args).output().map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                io::Error::new(io::ErrorKind::NotFound, "workspace requires git")
            } else {
                error
            }
        })?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ))
        }
    }

    fn run_with_input(
        &self,
        args: &[&str],
        cwd: &Path,
        index: Option<&Path>,
        mut input: impl io::Read,
    ) -> io::Result<Vec<u8>> {
        let mut command = self.command(cwd)?;
        if let Some(index) = index {
            command.env("GIT_INDEX_FILE", index);
        }
        let mut child = command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        io::copy(&mut input, child.stdin.as_mut().expect("piped Git stdin"))?;
        drop(child.stdin.take());
        let output = child.wait_with_output()?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ))
        }
    }
}

impl PinnedNode {
    fn capture(path: PathBuf, kind: NodeKind) -> io::Result<Self> {
        let metadata = std::fs::symlink_metadata(&path)?;
        let valid_kind = match kind {
            NodeKind::File => metadata.is_file() && !metadata.file_type().is_symlink(),
            NodeKind::Directory => metadata.is_dir() && !metadata.file_type().is_symlink(),
        };
        if !valid_kind || (matches!(kind, NodeKind::File) && metadata.nlink() != 1) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsafe Git metadata node: {}", path.display()),
            ));
        }
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            kind,
        })
    }

    fn validate(&self) -> io::Result<()> {
        let metadata = std::fs::symlink_metadata(&self.path).map_err(|_| metadata_changed())?;
        let valid_kind = match self.kind {
            NodeKind::File => metadata.is_file() && !metadata.file_type().is_symlink(),
            NodeKind::Directory => metadata.is_dir() && !metadata.file_type().is_symlink(),
        };
        if !valid_kind
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || (matches!(self.kind, NodeKind::File) && metadata.nlink() != 1)
        {
            return Err(metadata_changed());
        }
        Ok(())
    }
}

impl GitMetadataIdentity {
    fn capture(git: &TrustedGit, worktree: &Path) -> io::Result<Self> {
        let gitfile_path = worktree.join(".git");
        let gitfile = PinnedNode::capture(gitfile_path.clone(), NodeKind::File)?;
        let gitfile_contents = std::fs::read(&gitfile_path)?;
        let git_dir = canonical_git_path(
            worktree,
            git.run(&["rev-parse", "--absolute-git-dir"], worktree)?
                .trim(),
        )?;
        let common_dir = canonical_git_path(
            worktree,
            git.run(&["rev-parse", "--git-common-dir"], worktree)?
                .trim(),
        )?;
        Ok(Self {
            gitfile,
            gitfile_contents,
            git_dir: PinnedNode::capture(git_dir, NodeKind::Directory)?,
            common_dir: PinnedNode::capture(common_dir, NodeKind::Directory)?,
        })
    }

    fn validate(&self) -> io::Result<()> {
        self.gitfile.validate()?;
        self.git_dir.validate()?;
        self.common_dir.validate()?;
        if std::fs::read(&self.gitfile.path).map_err(|_| metadata_changed())?
            != self.gitfile_contents
        {
            return Err(metadata_changed());
        }
        Ok(())
    }
}

fn metadata_changed() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Git metadata changed during the sandboxed workspace session; refusing trusted host Git operations",
    )
}

fn canonical_git_path(cwd: &Path, value: &str) -> io::Result<PathBuf> {
    let path = Path::new(value);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    path.canonicalize()
}

fn build_result_tree(info: &WorktreeInfo) -> io::Result<String> {
    info.metadata.validate()?;
    let worktree = WorktreeRoot::open(&info.worktree_dir)?;
    let mut paths = BTreeSet::new();
    for args in [
        &["ls-files", "--cached", "-z", "--"][..],
        &["ls-files", "--others", "--exclude-standard", "-z", "--"][..],
    ] {
        for path in info
            .git
            .run_bytes(args, &info.worktree_dir)?
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
        {
            validate_git_relative_path(path)?;
            paths.insert(path.to_vec());
        }
    }
    paths.extend(info.observed_tracked_paths.iter().cloned());

    let index = info.metadata.git_dir.path.join(format!(
        "cdm-finalize-index-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let index_guard = TemporaryIndex(index.clone());
    if index.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "trusted Git index path already exists",
        ));
    }
    run_git_with_index(
        &info.git,
        &["read-tree", &info.base_commit],
        &info.repo_root,
        &index,
    )?;

    let mut index_info = Vec::new();
    let mut removals = Vec::new();
    let mut collapsed_symlinks: BTreeSet<Vec<u8>> = BTreeSet::new();
    for encoded in paths {
        let relative = PathBuf::from(OsString::from_vec(encoded.clone()));
        if collapsed_symlinks
            .iter()
            .any(|prefix| is_git_descendant(&encoded, prefix))
        {
            removals.push(relative);
            continue;
        }
        let (effective_path, mode, object_type, object) = match worktree.inspect(&relative)? {
            WorktreeEntry::Missing => {
                if info.observed_tracked_paths.contains(&encoded) {
                    removals.push(relative);
                }
                continue;
            }
            WorktreeEntry::Symlink { relative, target } => {
                let effective = relative.as_os_str().as_bytes().to_vec();
                validate_git_relative_path(&effective)?;
                if effective != encoded {
                    removals.push(PathBuf::from(OsString::from_vec(encoded)));
                }
                if !collapsed_symlinks.insert(effective.clone()) {
                    continue;
                }
                (
                    effective,
                    "120000",
                    "blob",
                    hash_bytes(&info.git, &info.repo_root, target.as_os_str().as_bytes())?,
                )
            }
            WorktreeEntry::Regular { file, executable } => (
                encoded,
                if executable { "100755" } else { "100644" },
                "blob",
                hash_file(&info.git, &info.repo_root, file)?,
            ),
            WorktreeEntry::Directory => {
                let entry = info.git.run_bytes(
                    &[
                        "ls-files",
                        "--stage",
                        "-z",
                        "--",
                        &relative.to_string_lossy(),
                    ],
                    &info.worktree_dir,
                )?;
                let entry = entry.split(|byte| *byte == 0).next().unwrap_or_default();
                let header = entry
                    .split(|byte| *byte == b'\t')
                    .next()
                    .unwrap_or_default();
                let mut fields = header.split(|byte| *byte == b' ');
                let mode = fields.next().unwrap_or_default();
                let object = fields.next().unwrap_or_default();
                if mode != b"160000" || object.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "unsupported directory in Git snapshot: {}",
                            relative.display()
                        ),
                    ));
                }
                (
                    encoded,
                    "160000",
                    "commit",
                    String::from_utf8_lossy(object).to_string(),
                )
            }
        };
        index_info.extend_from_slice(mode.as_bytes());
        index_info.push(b' ');
        index_info.extend_from_slice(object_type.as_bytes());
        index_info.push(b' ');
        index_info.extend_from_slice(object.trim().as_bytes());
        index_info.push(b'\t');
        index_info.extend_from_slice(effective_path.as_slice());
        index_info.push(0);
    }
    remove_index_paths(&info.git, &info.repo_root, &index, &removals)?;
    info.git.run_with_input(
        &["update-index", "-z", "--index-info"],
        &info.repo_root,
        Some(&index),
        &index_info[..],
    )?;
    let tree = run_git_with_index(&info.git, &["write-tree"], &info.repo_root, &index)?;
    index_guard.finish()?;
    Ok(tree)
}

fn is_git_descendant(path: &[u8], prefix: &[u8]) -> bool {
    path.len() > prefix.len() && path.starts_with(prefix) && path.get(prefix.len()) == Some(&b'/')
}

fn remove_index_paths(
    git: &TrustedGit,
    cwd: &Path,
    index: &Path,
    paths: &[PathBuf],
) -> io::Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let mut command = git.command(cwd)?;
    command
        .env("GIT_INDEX_FILE", index)
        .args(["update-index", "--force-remove", "--"]);
    for path in paths {
        command.arg(path);
    }
    let output = command.output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}

fn validate_git_relative_path(path: &[u8]) -> io::Result<()> {
    let relative = PathBuf::from(OsString::from_vec(path.to_vec()));
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        || relative
            .components()
            .next()
            .and_then(|component| match component {
                std::path::Component::Normal(value) => Some(value == OsStr::new(".git")),
                _ => None,
            })
            == Some(true)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Git returned an unsafe workspace path",
        ));
    }
    Ok(())
}

fn hash_file(git: &TrustedGit, cwd: &Path, file: File) -> io::Result<String> {
    let output = git.run_with_input(
        &["hash-object", "-w", "--stdin", "--no-filters"],
        cwd,
        None,
        file,
    )?;
    Ok(String::from_utf8_lossy(&output).trim().to_string())
}

fn hash_bytes(git: &TrustedGit, cwd: &Path, bytes: &[u8]) -> io::Result<String> {
    let output = git.run_with_input(
        &["hash-object", "-w", "--stdin", "--no-filters"],
        cwd,
        None,
        bytes,
    )?;
    Ok(String::from_utf8_lossy(&output).trim().to_string())
}

fn run_git_with_index(
    git: &TrustedGit,
    args: &[&str],
    cwd: &Path,
    index: &Path,
) -> io::Result<String> {
    let mut command = git.command(cwd)?;
    let output = command.env("GIT_INDEX_FILE", index).args(args).output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}

struct TemporaryIndex(PathBuf);

impl TemporaryIndex {
    fn finish(mut self) -> io::Result<()> {
        std::fs::remove_file(&self.0)?;
        self.0 = PathBuf::new();
        Ok(())
    }
}

impl Drop for TemporaryIndex {
    fn drop(&mut self) {
        if self.0.as_os_str().is_empty() {
            return;
        }
        match std::fs::remove_file(&self.0) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => eprintln!(
                "[cdm] error: cannot remove temporary Git index {}: {error}",
                self.0.display()
            ),
        }
    }
}

/// Runs a git command with the given arguments in the specified directory.
/// Returns the trimmed stdout on success, or an io::Error on failure.
#[cfg(test)]
fn run_git(args: &[&str], cwd: &Path) -> io::Result<String> {
    TrustedGit::discover()?.run(args, cwd)
}

/// Parses filter-free diff stats from the pinned base to the reserved result.
/// Returns (files_changed, insertions, deletions). Falls back to (0,0,0)
/// on any parse failure.
fn parse_diff_stats(info: &WorktreeInfo) -> (usize, usize, usize) {
    let stat_output = match info.git.run(
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--stat",
            &info.base_commit,
            &info.branch_name,
        ],
        &info.repo_root,
    ) {
        Ok(s) => s,
        Err(_) => return (0, 0, 0),
    };

    // The last line of --stat output looks like:
    //  "3 files changed, 10 insertions(+), 2 deletions(-)"
    // or variants with only insertions or only deletions.
    let last_line = match stat_output.lines().last() {
        Some(l) => l.trim(),
        None => return (0, 0, 0),
    };

    let mut files_changed = 0usize;
    let mut insertions = 0usize;
    let mut deletions = 0usize;

    for part in last_line.split(',') {
        let part = part.trim();
        let tokens: Vec<&str> = part.split_whitespace().collect();
        if tokens.len() >= 2 {
            if let Ok(n) = tokens[0].parse::<usize>() {
                if part.contains("file") {
                    files_changed = n;
                } else if part.contains("insertion") {
                    insertions = n;
                } else if part.contains("deletion") {
                    deletions = n;
                }
            }
        }
    }

    (files_changed, insertions, deletions)
}

/// Formats the current date as YYYY-MM-DD using SystemTime (no chrono).
fn format_date() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    epoch_to_date(secs)
}

/// Formats the current date+time as YYYY-MM-DD HH:MM using SystemTime.
fn format_datetime_full() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, m, d) = epoch_to_ymd(secs);
    let day_secs = secs % 86400;
    let hour = day_secs / 3600;
    let minute = (day_secs % 3600) / 60;
    format!("{:04}-{:02}-{:02} {:02}:{:02}", y, m, d, hour, minute)
}

/// Converts unix epoch seconds to a YYYY-MM-DD string.
fn epoch_to_date(secs: u64) -> String {
    let (y, m, d) = epoch_to_ymd(secs);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Converts unix epoch seconds to (year, month, day).
/// Civil calendar computation without external dependencies.
fn epoch_to_ymd(secs: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's civil_from_days
    let days = (secs / 86400) as i64;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u64, m, d)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
