//! Resolution and identity pinning for trusted host-side helper executables.
//!
//! Untrusted project commands inherit a useful `PATH`, but CDM itself must not
//! use that path to select programs which run before or outside confinement.

use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// A host helper selected only from a root-owned, non-writable path and pinned
/// to the filesystem identity observed during resolution.
#[derive(Clone, Debug)]
pub struct TrustedExecutable {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl TrustedExecutable {
    /// Return the pinned absolute path after confirming it still names the
    /// same trusted executable.
    pub fn path(&self) -> io::Result<&Path> {
        self.revalidate()?;
        Ok(&self.path)
    }

    /// Construct a command without resolving the executable through `PATH`.
    pub fn command(&self) -> io::Result<Command> {
        Ok(Command::new(self.path()?))
    }

    fn revalidate(&self) -> io::Result<()> {
        self.revalidate_as(0)
    }

    fn revalidate_as(&self, trusted_uid: u32) -> io::Result<()> {
        let current = validate_candidate(&self.path, trusted_uid)?;
        if current.device != self.device || current.inode != self.inode {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "trusted executable changed after resolution: {}",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }
}

/// Resolve the system Git used by trusted worktree lifecycle operations.
pub fn git() -> io::Result<TrustedExecutable> {
    resolve("git", &[Path::new("/usr/bin/git"), Path::new("/bin/git")])
}

/// Resolve Bubblewrap without trusting a project- or user-controlled `PATH`
/// entry. Conventional distribution locations are tried first.
#[cfg(target_os = "linux")]
pub fn bubblewrap() -> io::Result<TrustedExecutable> {
    resolve(
        "bwrap",
        &[Path::new("/usr/bin/bwrap"), Path::new("/bin/bwrap")],
    )
}

/// Validate a fixed platform tool. This is used for OS-provided binaries such
/// as `/usr/bin/sandbox-exec` and `/bin/cp`.
pub fn fixed(path: &Path, label: &str) -> io::Result<TrustedExecutable> {
    validate_candidate(path, 0).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "trusted {label} at {} is unavailable: {error}",
                path.display()
            ),
        )
    })
}

fn resolve(name: &str, fixed: &[&Path]) -> io::Result<TrustedExecutable> {
    let mut candidates = fixed
        .iter()
        .map(|path| (*path).to_path_buf())
        .collect::<Vec<_>>();
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(
            std::env::split_paths(&path)
                .filter(|directory| directory.is_absolute())
                .map(|directory| directory.join(name)),
        );
    }
    resolve_from_candidates(name, candidates, 0)
}

fn resolve_from_candidates(
    name: &str,
    candidates: impl IntoIterator<Item = PathBuf>,
    trusted_uid: u32,
) -> io::Result<TrustedExecutable> {
    let mut rejected = Vec::new();
    for candidate in candidates {
        match validate_candidate(&candidate, trusted_uid) {
            Ok(executable) => return Ok(executable),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => rejected.push(format!("{} ({error})", candidate.display())),
        }
    }
    let detail = if rejected.is_empty() {
        String::new()
    } else {
        format!("; rejected untrusted candidates: {}", rejected.join(", "))
    };
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("no trusted {name} executable was found{detail}"),
    ))
}

fn validate_candidate(path: &Path, trusted_uid: u32) -> io::Result<TrustedExecutable> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted executable path must be absolute",
        ));
    }

    let mut current = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(part) => current.push(part),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "trusted executable path must be lexically normalized",
                ));
            }
        }
        let metadata = std::fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "trusted executable path contains a symlink: {}",
                    current.display()
                ),
            ));
        }
        if (metadata.uid() != 0 && metadata.uid() != trusted_uid)
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "trusted executable path is writable by an untrusted principal or not owned by root/uid {trusted_uid}: {}",
                    current.display()
                ),
            ));
        }
    }

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "trusted executable is not an executable regular file: {}",
                path.display()
            ),
        ));
    }
    Ok(TrustedExecutable {
        path: path.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

/// Apply the deliberately tiny locale environment used for host-only helpers.
/// Callers may add narrowly scoped variables after this reset.
pub fn sanitize_host_environment(command: &mut Command) {
    command.env_clear().env("LANG", "C").env("LC_ALL", "C");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn temp(label: &str) -> PathBuf {
        std::env::current_dir().unwrap().join(format!(
            "cdm-trusted-exec-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn executable(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn project_owned_path_candidate_is_rejected_before_system_git() {
        let root = temp("path-hijack");
        let malicious = root.join("git");
        executable(&malicious);

        let resolved =
            resolve_from_candidates("git", [malicious, PathBuf::from("/usr/bin/git")], 0).unwrap();
        assert_eq!(resolved.path().unwrap(), Path::new("/usr/bin/git"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn symlinked_executable_is_rejected() {
        let root = temp("symlink");
        let target = root.join("target");
        let link = root.join("git");
        executable(&target);
        symlink(&target, &link).unwrap();
        let error = validate_candidate(&link, unsafe { libc::geteuid() }).unwrap_err();
        assert!(error.to_string().contains("symlink"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_identity_detects_replacement() {
        let root = temp("replace");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("helper");
        executable(&path);
        let uid = unsafe { libc::geteuid() };
        let pinned = validate_candidate(&path, uid).unwrap();
        fs::rename(&path, root.join("old")).unwrap();
        executable(&path);
        let error = pinned.revalidate_as(uid).unwrap_err();
        assert!(error.to_string().contains("changed after resolution"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn host_environment_drops_inherited_loader_and_path_values() {
        let mut command = Command::new("/usr/bin/true");
        command
            .env("PATH", "/project/bin")
            .env("LD_PRELOAD", "/project/evil.so");
        sanitize_host_environment(&mut command);
        let env = command.get_envs().collect::<Vec<_>>();
        assert!(env
            .iter()
            .any(|(key, value)| *key == "LANG" && value == &Some("C".as_ref())));
        assert!(!env
            .iter()
            .any(|(key, value)| *key == "PATH" && value.is_some()));
        assert!(!env
            .iter()
            .any(|(key, value)| *key == "LD_PRELOAD" && value.is_some()));
    }
}
