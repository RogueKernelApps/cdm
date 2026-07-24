//! Descriptor-relative, no-follow reads beneath a trusted directory root.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

pub(crate) struct AnchoredRoot {
    root: PathBuf,
    fd: OwnedFd,
}

impl AnchoredRoot {
    pub(crate) fn open(root: &Path) -> io::Result<Self> {
        let canonical = root.canonicalize()?;
        let name = c_path(canonical.as_os_str())?;
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        Ok(Self {
            root: root.to_path_buf(),
            fd: owned_fd(fd).map_err(|error| path_error("open trusted root", root, error))?,
        })
    }

    pub(crate) fn open_directory(&self, path: &Path) -> io::Result<Self> {
        let relative = self.relative(path)?;
        let fd = self.open_directory_optional(relative)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("trusted directory is missing: {}", path.display()),
            )
        })?;
        Ok(Self {
            root: path.to_path_buf(),
            fd,
        })
    }

    pub(crate) fn open_regular(&self, path: &Path) -> io::Result<Option<File>> {
        let relative = self.relative(path)?;
        let (parent, name) = split_relative(relative)?;
        let Some(parent) = self.open_directory_optional(parent)? else {
            return Ok(None);
        };
        let name = c_path(name)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(unsafe_path("open trusted file", path, error));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        ensure_regular(&fd, path)?;
        Ok(Some(File::from(fd)))
    }

    pub(crate) fn open_regular_directory(&self, path: &Path) -> io::Result<Vec<(PathBuf, File)>> {
        let relative = self.relative(path)?;
        let directory = match self.open_directory_optional(relative)? {
            Some(directory) => directory,
            None => return Ok(Vec::new()),
        };
        let iterator_fd = duplicate_fd(&directory)?;
        let raw = iterator_fd.into_raw_fd();
        let stream = unsafe { libc::fdopendir(raw) };
        if stream.is_null() {
            unsafe { libc::close(raw) };
            return Err(path_error(
                "read trusted directory",
                path,
                io::Error::last_os_error(),
            ));
        }
        let stream = DirectoryStream(stream);
        let mut files = Vec::new();
        loop {
            clear_errno();
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let error = last_errno();
                if error.raw_os_error() == Some(0) {
                    break;
                }
                return Err(path_error("read trusted directory", path, error));
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            let name = CString::new(name.to_bytes()).expect("directory entries contain no NUL");
            let entry_path = path.join(OsStr::from_bytes(name.as_bytes()));
            let metadata = entry_metadata(&directory, &name).map_err(|error| {
                unsafe_path("inspect trusted directory entry", &entry_path, error)
            })?;
            let kind = metadata.st_mode & libc::S_IFMT;
            if kind == libc::S_IFDIR {
                continue;
            }
            // Credential directories commonly contain SSH agent or control
            // sockets. They have no file content to inspect and must not make
            // regular-file discovery unusable.
            if kind == libc::S_IFSOCK {
                continue;
            }
            if kind != libc::S_IFREG {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "trusted directory entry is not a symlink-free regular file: {}",
                        entry_path.display()
                    ),
                ));
            }
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            let fd = owned_fd(fd)
                .map_err(|error| unsafe_path("open trusted directory entry", &entry_path, error))?;
            ensure_regular(&fd, &entry_path)?;
            files.push((entry_path, File::from(fd)));
        }
        Ok(files)
    }

    fn relative<'a>(&self, path: &'a Path) -> io::Result<&'a Path> {
        path.strip_prefix(&self.root).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("path is outside its trusted root: {}", path.display()),
            )
        })
    }

    fn open_directory_optional(&self, relative: &Path) -> io::Result<Option<OwnedFd>> {
        let mut current = duplicate_fd(&self.fd)?;
        for component in relative.components() {
            let Component::Normal(component) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "trusted path contains unsupported traversal",
                ));
            };
            let name = c_path(component)?;
            let fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if fd < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::NotFound {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("trusted path contains an unsafe ancestor: {error}"),
                ));
            }
            current = unsafe { OwnedFd::from_raw_fd(fd) };
        }
        Ok(Some(current))
    }
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

fn split_relative(path: &Path) -> io::Result<(&Path, &OsStr)> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "trusted file path is empty"))?;
    Ok((path.parent().unwrap_or(Path::new("")), name))
}

fn c_path(path: &OsStr) -> io::Result<CString> {
    CString::new(path.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "filesystem path contains an embedded NUL",
        )
    })
}

fn duplicate_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
    owned_fd(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })
}

fn owned_fd(fd: libc::c_int) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn entry_metadata(parent: &OwnedFd, name: &CString) -> io::Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { metadata.assume_init() })
}

fn ensure_regular(fd: &OwnedFd, path: &Path) -> io::Result<()> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        return Err(path_error(
            "inspect trusted file",
            path,
            io::Error::last_os_error(),
        ));
    }
    if unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("trusted path is not a regular file: {}", path.display()),
        ));
    }
    Ok(())
}

fn unsafe_path(operation: &str, path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{operation} {} without following symlinks: {error}",
            path.display()
        ),
    )
}

fn path_error(operation: &str, path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{operation} {}: {error}", path.display()),
    )
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    unsafe { *libc::__error() = 0 };
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

fn last_errno() -> io::Error {
    io::Error::last_os_error()
}
