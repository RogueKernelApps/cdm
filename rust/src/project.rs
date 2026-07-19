//! Deterministic discovery of the project associated with the launch directory.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

pub const PROJECT_CONFIG: &str = ".cdm/config.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectContext {
    pub launch_dir: PathBuf,
    pub root: PathBuf,
    pub config_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectKind {
    Rust,
    Node,
    Python,
    Go,
    Git,
    Generic,
}

impl fmt::Display for ProjectKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rust => "rust",
            Self::Node => "node",
            Self::Python => "python",
            Self::Go => "go",
            Self::Git => "git",
            Self::Generic => "generic",
        })
    }
}

impl ProjectContext {
    pub fn kind(&self) -> ProjectKind {
        detect_kind(&self.root)
    }
}

pub fn discover(start: &Path) -> io::Result<ProjectContext> {
    let mut homes = std::env::var_os("HOME")
        .map(PathBuf::from)
        .and_then(|path| path.canonicalize().ok())
        .into_iter()
        .collect::<Vec<_>>();
    if let Some(home) = account_home().and_then(|path| path.canonicalize().ok()) {
        if !homes.contains(&home) {
            homes.push(home);
        }
    }
    discover_with_homes(start, &homes)
}

#[cfg(test)]
fn discover_with_home(start: &Path, home: Option<&Path>) -> io::Result<ProjectContext> {
    discover_with_homes(
        start,
        &home.into_iter().map(Path::to_path_buf).collect::<Vec<_>>(),
    )
}

fn discover_with_homes(start: &Path, homes: &[PathBuf]) -> io::Result<ProjectContext> {
    let launch_dir = start.canonicalize().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot resolve launch directory {}: {error}",
                start.display()
            ),
        )
    })?;

    let mut git_root = None;
    for ancestor in launch_dir.ancestors() {
        // ~/.cdm/config.json is the conventional global policy. It must never
        // be reinterpreted as a project policy merely because every project
        // below the home directory has HOME as an ancestor.
        if homes.iter().any(|home| home == ancestor) {
            break;
        }
        let config_path = ancestor.join(PROJECT_CONFIG);
        if config_path.is_file() {
            reject_symlink(&ancestor.join(".cdm"), "project config directory")?;
            reject_symlink(&config_path, "project config")?;
            return Ok(ProjectContext {
                launch_dir: launch_dir.clone(),
                root: ancestor.to_path_buf(),
                config_path: Some(config_path),
            });
        }
        if git_root.is_none() && ancestor.join(".git").exists() {
            git_root = Some(ancestor.to_path_buf());
        }
    }

    Ok(ProjectContext {
        root: git_root.unwrap_or_else(|| launch_dir.clone()),
        launch_dir,
        config_path: None,
    })
}

#[cfg(unix)]
fn account_home() -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;

    let mut entry = std::mem::MaybeUninit::<libc::passwd>::zeroed();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    let status = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            entry.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return None;
    }
    if unsafe { (*result).pw_dir }.is_null() {
        return None;
    }
    let directory = unsafe { CStr::from_ptr((*result).pw_dir) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(
        directory.to_bytes(),
    )))
}

#[cfg(not(unix))]
fn account_home() -> Option<PathBuf> {
    None
}

fn reject_symlink(path: &Path, label: &str) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{label} must not be a symlink: {}", path.display()),
        ));
    }
    Ok(())
}

fn detect_kind(root: &Path) -> ProjectKind {
    if root.join("Cargo.toml").is_file() {
        ProjectKind::Rust
    } else if root.join("package.json").is_file() {
        ProjectKind::Node
    } else if ["pyproject.toml", "setup.py", "requirements.txt"]
        .iter()
        .any(|marker| root.join(marker).is_file())
    {
        ProjectKind::Python
    } else if root.join("go.mod").is_file() {
        ProjectKind::Go
    } else if root.join(".git").exists() {
        ProjectKind::Git
    } else {
        ProjectKind::Generic
    }
}

#[cfg(test)]
mod tests;
