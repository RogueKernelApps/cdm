//! Symlink-safe, descriptor-relative mutation of an untrusted VM rootfs.

use std::ffi::{CString, OsStr};
#[cfg(test)]
use std::io::Read;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub(super) fn require_real_directory(path: &Path, label: &str) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} is not a real directory: {}", path.display()),
        ));
    }
    Ok(())
}

pub(super) fn set_private_directory_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Capability-style access to an extracted rootfs.
///
/// OCI contents are untrusted. Every traversal starts from this pinned root
/// descriptor and rejects symlink components. Files are replaced through
/// `*at` syscalls without following final symlinks or mutating multiply-linked
/// inodes.
pub(super) struct SafeRoot {
    fd: OwnedFd,
}

impl SafeRoot {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let path = c_path(path.as_os_str())?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        Ok(Self {
            fd: owned_fd(fd, "open rootfs")?,
        })
    }

    #[cfg(test)]
    pub(super) fn read_file(&self, relative: &Path) -> io::Result<Option<String>> {
        let (parent, name) = split_relative(relative)?;
        let parent = match self.open_directory(parent, false) {
            Ok(parent) => parent,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
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
            return Err(path_error("open rootfs file", relative, error));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        ensure_single_regular_file(&fd, relative)?;
        let mut content = String::new();
        std::fs::File::from(fd).read_to_string(&mut content)?;
        Ok(Some(content))
    }

    pub(super) fn write_file(&self, relative: &Path, content: &[u8], mode: u32) -> io::Result<()> {
        let (parent_path, name) = split_relative(relative)?;
        let parent = self.open_directory(parent_path, true)?;
        let name = c_path(name)?;
        let original_mode = directory_mode(&parent)?;
        if original_mode & 0o200 == 0 {
            fchmod(&parent, original_mode | 0o200)?;
        }

        let result = (|| {
            match entry_metadata(&parent, &name)? {
                None => {}
                Some(metadata) if file_type(metadata.st_mode) == libc::S_IFREG => {
                    if metadata.st_nlink != 1 {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "refusing multiply-linked rootfs file {}",
                                relative.display()
                            ),
                        ));
                    }
                    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                        return Err(path_error(
                            "replace rootfs file",
                            relative,
                            io::Error::last_os_error(),
                        ));
                    }
                }
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "refusing non-regular or symlink rootfs file {}",
                            relative.display()
                        ),
                    ));
                }
            }

            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW,
                    mode as libc::c_uint,
                )
            };
            let fd = owned_fd(fd, "create rootfs file")?;
            ensure_single_regular_file(&fd, relative)?;
            fchmod(&fd, mode)?;
            let mut file = std::fs::File::from(fd);
            file.write_all(content)?;
            file.sync_all()
        })();

        if original_mode & 0o200 == 0 {
            let restore = fchmod(&parent, original_mode);
            if result.is_ok() {
                restore?;
            }
        }
        result
    }

    pub(super) fn copy_file(&self, source: &Path, relative: &Path, mode: u32) -> io::Result<()> {
        self.write_file(relative, &std::fs::read(source)?, mode)
    }

    pub(super) fn ensure_directory(&self, relative: &Path) -> io::Result<()> {
        self.open_directory(relative, true).map(drop)
    }

    #[cfg(test)]
    pub(super) fn replace_with_symlink(
        &self,
        relative: &Path,
        guest_target: &OsStr,
    ) -> io::Result<()> {
        let (parent_path, name) = split_relative(relative)?;
        let parent = self.open_directory(parent_path, false)?;
        let name = c_path(name)?;
        match entry_metadata(&parent, &name)? {
            None => {}
            Some(metadata) if file_type(metadata.st_mode) == libc::S_IFREG => {
                if metadata.st_nlink != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "refusing multiply-linked rootfs file {}",
                            relative.display()
                        ),
                    ));
                }
                if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "refusing existing non-regular or symlink rootfs entry {}",
                        relative.display()
                    ),
                ));
            }
        }
        let target = c_path(guest_target)?;
        if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) } != 0 {
            return Err(path_error(
                "create rootfs symlink",
                relative,
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn contained_directory_target(
        &self,
        relative: &Path,
    ) -> io::Result<std::path::PathBuf> {
        let (parent_path, name) = split_relative(relative)?;
        let parent = self.open_directory(parent_path, false)?;
        let name_c = c_path(name)?;
        match entry_metadata(&parent, &name_c)? {
            None => {
                self.ensure_directory(relative)?;
                Ok(relative.to_path_buf())
            }
            Some(metadata) if file_type(metadata.st_mode) == libc::S_IFDIR => {
                self.open_directory(relative, false)?;
                Ok(relative.to_path_buf())
            }
            Some(metadata) if file_type(metadata.st_mode) == libc::S_IFLNK => {
                let target = read_link_at(&parent, &name_c)?;
                validate_relative(&target)?;
                self.open_directory(&target, false)?;
                Ok(target)
            }
            Some(_) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "rootfs path is not a safe directory: {}",
                    relative.display()
                ),
            )),
        }
    }

    fn open_directory(&self, relative: &Path, create: bool) -> io::Result<OwnedFd> {
        let components = validate_relative(relative)?;
        let mut current = duplicate_fd(&self.fd)?;
        for component in components {
            let name = c_path(component)?;
            let mut fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if fd < 0 && create && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                if unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o755) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                fd = unsafe {
                    libc::openat(
                        current.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    )
                };
            }
            current = owned_fd(fd, "open rootfs directory")?;
        }
        Ok(current)
    }
}

fn c_path(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "rootfs path contains an embedded NUL",
        )
    })
}

fn validate_relative(path: &Path) -> io::Result<Vec<&OsStr>> {
    use std::path::Component;
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => components.push(value),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("rootfs path must remain relative: {}", path.display()),
                ));
            }
        }
    }
    Ok(components)
}

fn split_relative(path: &Path) -> io::Result<(&Path, &OsStr)> {
    validate_relative(path)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rootfs file path is empty"))?;
    Ok((path.parent().unwrap_or(Path::new("")), name))
}

fn duplicate_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
    let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    owned_fd(duplicate, "duplicate rootfs descriptor")
}

fn owned_fd(fd: libc::c_int, operation: &str) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("{operation}: {}", io::Error::last_os_error()),
        ))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn entry_metadata(parent: &OwnedFd, name: &CString) -> io::Result<Option<libc::stat>> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(Some(unsafe { metadata.assume_init() }))
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error)
        }
    }
}

fn file_type(mode: libc::mode_t) -> libc::mode_t {
    mode & libc::S_IFMT
}

fn ensure_single_regular_file(fd: &OwnedFd, relative: &Path) -> io::Result<()> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let metadata = unsafe { metadata.assume_init() };
    if file_type(metadata.st_mode) != libc::S_IFREG || metadata.st_nlink != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "rootfs file is not a private regular file: {}",
                relative.display()
            ),
        ));
    }
    Ok(())
}

fn directory_mode(fd: &OwnedFd) -> io::Result<u32> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u32::from(unsafe { metadata.assume_init() }.st_mode) & 0o7777)
}

fn fchmod(fd: &OwnedFd, mode: u32) -> io::Result<()> {
    if unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn read_link_at(parent: &OwnedFd, name: &CString) -> io::Result<std::path::PathBuf> {
    let mut buffer = vec![0_u8; 4096];
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
    if length as usize == buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rootfs symlink target is too long",
        ));
    }
    buffer.truncate(length as usize);
    Ok(std::path::PathBuf::from(OsStr::from_bytes(&buffer)))
}

fn path_error(operation: &str, path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{operation} {}: {error}", path.display()),
    )
}
