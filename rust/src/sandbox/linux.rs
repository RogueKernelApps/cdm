//! Linux sandbox implementation using Bubblewrap.

use crate::sandbox::{SandboxConfig, SandboxRun};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Runs a command in a bubblewrap sandbox on Linux.
pub fn run_linux(cfg: SandboxConfig) -> io::Result<SandboxRun> {
    if cfg.command.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no command specified",
        ));
    }
    // Build bwrap arguments — all owned Strings for uniform handling
    let mut args: Vec<String> = Vec::new();
    let access = cfg.resolved_access()?;
    let mut denied_nodes = DeniedNodes::create(&cfg.runtime_dir)?;
    let seccomp = if cfg.network.is_proxied() {
        None
    } else {
        Some(crate::proxy_bridge::SeccompProgram::deny_host_socket_deputies()?)
    };
    let mut bridge = if cfg.network.is_proxied() {
        Some(crate::proxy_bridge::ProxyBridge::start(
            &cfg.runtime_dir,
            cfg.proxy_port,
        )?)
    } else {
        None
    };

    if access.host == crate::access::HostAccess::Isolated {
        args.extend(["--tmpfs".to_string(), "/".to_string()]);
        for path in &access.runtime_ro {
            add_bind(&mut args, "--ro-bind", path);
        }
    } else {
        add_bind(&mut args, "--ro-bind", Path::new("/"));
    }

    // Pathname Unix sockets are not isolated by a network namespace. Replace
    // host runtime trees before restoring any approved paths so Docker,
    // containerd, D-Bus, SSH-agent, and similar sockets cannot act as deputies.
    let synthetic_targets = access.synthetic_mounts.clone();
    if access.host == crate::access::HostAccess::Normal {
        for path in &synthetic_targets {
            args.push("--tmpfs".to_string());
            args.push(path.to_string_lossy().into_owned());
        }
    }

    let work_dir_str = access.work_dir.to_string_lossy().to_string();
    let workspace_bind = if access.workspace == crate::access::WorkspaceAccess::ReadWrite {
        "--bind"
    } else {
        "--ro-bind"
    };
    add_bind(&mut args, workspace_bind, &access.work_dir);

    add_bind(&mut args, "--bind", &cfg.runtime_dir);
    const GUEST_PROXY_BRIDGE: &str = "/run/cdm-proxy-bridge";
    if let Some(ref bridge) = bridge {
        add_bind_from(
            &mut args,
            "--ro-bind",
            bridge.root(),
            Path::new(GUEST_PROXY_BRIDGE),
        );
    }
    let helper_executable = if cfg.network.is_proxied() {
        let executable = std::env::current_exe()?;
        if access.host == crate::access::HostAccess::Isolated {
            add_bind(&mut args, "--ro-bind", &executable);
        }
        Some(executable)
    } else {
        None
    };
    if access.host == crate::access::HostAccess::Isolated {
        for path in &access.allow_ro {
            add_bind(&mut args, "--ro-bind", path);
        }
    }
    for path in &access.allow_rw {
        add_bind(&mut args, "--bind", path);
    }

    // File stage overlays (ro-bind fakes over reals)
    if let Some(ref stage) = cfg.file_stage {
        for arg in stage.bwrap_args() {
            args.push(arg);
        }
    }

    let mut writable_paths = access.allow_rw.clone();
    if access.workspace == crate::access::WorkspaceAccess::ReadWrite {
        writable_paths.push(access.work_dir.clone());
    }
    let mountpoints = append_hard_denials(
        &mut args,
        &access.deny_write_rules,
        &access.deny_read_rules,
        &denied_nodes,
        &access.synthetic_dirs,
        |path| access.exposes(path, &cfg.runtime_dir),
        &writable_paths,
    );
    let mountpoint_lock_root = cfg
        .runtime_dir
        .parent()
        .ok_or_else(|| io::Error::other("CDM runtime directory has no private parent"))?;
    let mut prepared_mountpoints = PreparedMountpoints::create(mountpoints, mountpoint_lock_root)?;

    // Device and proc
    args.push("--dev".to_string());
    args.push("/dev".to_string());
    args.push("--proc".to_string());
    args.push("/proc".to_string());

    // PID namespace isolation
    args.push("--unshare-pid".to_string());

    // Network isolation if requested
    if !cfg.network.allows_network() || cfg.network.is_proxied() {
        args.push("--unshare-net".to_string());
    }

    // The shared process supervisor owns the process group and controlling
    // terminal. Bubblewrap must not create a second, unreachable session.
    args.push("--die-with-parent".to_string());
    args.push("--cap-drop".to_string());
    args.push("ALL".to_string());
    if let Some(ref seccomp) = seccomp {
        append_seccomp(&mut args, seccomp.as_raw_fd());
    }

    // Sanitize environment (belt-and-suspenders)
    args.push("--unsetenv".to_string());
    args.push("LD_PRELOAD".to_string());
    args.push("--unsetenv".to_string());
    args.push("LD_LIBRARY_PATH".to_string());

    // Change directory
    args.push("--chdir".to_string());
    args.push(work_dir_str);

    // Separator
    args.push("--".to_string());

    let child_command = if let Some(executable) = helper_executable {
        let mut command = vec![
            executable.into_os_string(),
            OsString::from("__linux-proxy-helper"),
            OsString::from(format!(
                "{GUEST_PROXY_BRIDGE}/{}",
                crate::proxy_bridge::BRIDGE_SOCKET_NAME
            )),
            OsString::from(cfg.proxy_port.to_string()),
            OsString::from("--"),
        ];
        command.extend(cfg.command.iter().cloned());
        command
    } else {
        cfg.command.clone()
    };

    // Build bwrap command
    let bwrap = crate::trusted_exec::bubblewrap()?;
    let mut cmd = bwrap.command()?;
    for arg in &args {
        cmd.arg(arg);
    }
    cmd.args(&child_command);

    // Set environment
    let env = cfg.build_env();
    cmd.env_clear();
    for (key, value) in env {
        cmd.env(key, value);
    }

    if cfg.debug {
        eprintln!(
            "[cdm] exec: bwrap <{} policy argv entries> <{} child argv entries>",
            args.len(),
            child_command.len()
        );
    }
    let child = crate::process::run(&mut cmd).map(preserve_bwrap_signal_status);
    let bridge_cleanup = bridge.as_mut().map_or(Ok(()), |bridge| bridge.stop());
    let denied_cleanup = denied_nodes.finish();
    let mountpoint_cleanup = prepared_mountpoints.finish();
    let cleanup = combine_cleanup(
        combine_cleanup(bridge_cleanup, denied_cleanup),
        mountpoint_cleanup,
    );
    Ok(SandboxRun {
        child,
        cleanup,
        staged_cleanup: Ok(()),
    })
}

fn preserve_bwrap_signal_status(
    mut status: crate::process::ChildStatus,
) -> crate::process::ChildStatus {
    if status.signal.is_none() && (129..=192).contains(&status.exit_code) {
        status.signal = Some(status.exit_code - 128);
    }
    status
}

fn combine_cleanup(first: io::Result<()>, second: io::Result<()>) -> io::Result<()> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(io::Error::new(
            first.kind(),
            format!("{first}; additional cleanup failure: {second}"),
        )),
    }
}

fn append_hard_denials(
    args: &mut Vec<String>,
    deny_write_rules: &[crate::access::ResolvedDenyRule],
    deny_read_rules: &[crate::access::ResolvedDenyRule],
    denied_nodes: &DeniedNodes,
    synthetic_dirs: &[std::path::PathBuf],
    path_is_exposed: impl Fn(&Path) -> bool,
    writable_paths: &[std::path::PathBuf],
) -> Vec<(std::path::PathBuf, bool)> {
    let path_is_writable = |path: &Path| {
        writable_paths
            .iter()
            .any(|root| path == root || path.starts_with(root))
    };
    let path_is_active = |path: &Path| {
        path_is_exposed(path) && !path_is_covered_by_synthetic_dir(path, synthetic_dirs)
    };
    let active_rules = deny_write_rules
        .iter()
        .chain(deny_read_rules)
        .filter(|rule| rule.paths().any(&path_is_active))
        .collect::<Vec<_>>();
    let missing_parents = active_rules
        .iter()
        .flat_map(|rule| {
            rule.missing_parents
                .iter()
                .filter(|path| path_is_exposed(path))
                .cloned()
        })
        .collect::<BTreeSet<_>>();
    let mut mountpoints = missing_parents
        .iter()
        .cloned()
        .map(|path| (path, true))
        .collect::<Vec<_>>();
    mountpoints.extend(
        deny_read_rules
            .iter()
            .filter(|rule| rule.kind == crate::access::DeniedPathKind::Missing)
            .flat_map(|rule| rule.paths())
            .filter(|path| path_is_active(path))
            .map(|path| (path.to_path_buf(), false)),
    );
    let denied_write_directories = deny_write_rules
        .iter()
        .filter(|rule| rule.kind == crate::access::DeniedPathKind::Directory)
        .flat_map(|rule| rule.paths())
        .filter(|path| path_is_active(path))
        .map(Path::to_path_buf)
        .collect::<BTreeSet<_>>();
    let mut temporary_writable_parents = missing_parents
        .iter()
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .filter(|path| !missing_parents.contains(path))
        .collect::<BTreeSet<_>>();
    temporary_writable_parents.extend(
        active_rules
            .iter()
            .filter(|rule| {
                rule.kind == crate::access::DeniedPathKind::Missing
                    && rule.missing_parents.is_empty()
            })
            .flat_map(|rule| rule.paths())
            .filter(|path| path_is_active(path))
            .filter_map(Path::parent)
            .map(Path::to_path_buf),
    );
    // Bubblewrap cannot create a mountpoint below a read-only bind. Make each
    // nearest existing parent writable only while missing mounts are assembled;
    // the child starts after the read-only remounts appended below.
    for parent in &temporary_writable_parents {
        add_bind(args, "--bind", parent);
    }
    // Every absent ancestor is a mountpoint, not a plain directory. This
    // prevents renaming any level of the path and recreating the denied leaf.
    for parent in &missing_parents {
        args.push("--tmpfs".to_string());
        args.push(parent.to_string_lossy().into_owned());
    }

    // Missing leaves must be materialized while their parent bind is still
    // writable. Existing directory masks are applied last and make the final
    // tree read-only before the child starts.
    for rule in [
        crate::access::DeniedPathKind::Missing,
        crate::access::DeniedPathKind::File,
        crate::access::DeniedPathKind::Other,
        crate::access::DeniedPathKind::Directory,
    ]
    .into_iter()
    .flat_map(|kind| {
        deny_write_rules
            .iter()
            .filter(move |rule| rule.kind == kind)
    }) {
        for path in rule.paths().filter(|path| path_is_active(path)) {
            match rule.kind {
                crate::access::DeniedPathKind::Directory => {
                    add_bind(args, "--ro-bind", path);
                }
                crate::access::DeniedPathKind::File | crate::access::DeniedPathKind::Other => {
                    add_bind(args, "--ro-bind", path);
                }
                crate::access::DeniedPathKind::Missing => {
                    let covered_by_directory = denied_write_directories
                        .iter()
                        .any(|directory| path != directory && path.starts_with(directory));
                    let writable_parent = path.parent().is_some_and(&path_is_writable);
                    if !missing_parents.contains(path) && !covered_by_directory && writable_parent {
                        mountpoints.push((path.to_path_buf(), false));
                        add_bind_from(args, "--ro-bind", &denied_nodes.read_only_file, path);
                    }
                }
            }
        }
    }
    for rule in deny_read_rules {
        let source = if rule.kind == crate::access::DeniedPathKind::Directory {
            &denied_nodes.denied_dir
        } else {
            &denied_nodes.denied_file
        };
        for path in rule.paths().filter(|path| path_is_active(path)) {
            add_bind_from(args, "--ro-bind", source, path);
        }
    }
    let mut missing_parents = missing_parents.into_iter().collect::<Vec<_>>();
    missing_parents.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for parent in missing_parents {
        args.push("--remount-ro".to_string());
        args.push(parent.to_string_lossy().into_owned());
    }
    let mut temporary_writable_parents = temporary_writable_parents.into_iter().collect::<Vec<_>>();
    temporary_writable_parents.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for parent in temporary_writable_parents {
        if !path_is_writable(&parent) && !denied_write_directories.contains(&parent) {
            args.push("--remount-ro".to_string());
            args.push(parent.to_string_lossy().into_owned());
        }
    }
    mountpoints
}

fn path_is_covered_by_synthetic_dir(path: &Path, synthetic_dirs: &[std::path::PathBuf]) -> bool {
    synthetic_dirs
        .iter()
        .any(|root| path == root || path.starts_with(root))
}

struct PreparedMountpoints {
    entries: Vec<(std::path::PathBuf, u64, u64, bool)>,
    _lock: Option<File>,
    finished: bool,
}

impl PreparedMountpoints {
    fn create(
        mut requested: Vec<(std::path::PathBuf, bool)>,
        lock_root: &Path,
    ) -> io::Result<Self> {
        requested.sort_by_key(|(path, is_dir)| (path.components().count(), !*is_dir));
        requested.dedup();
        let lock = if requested.is_empty() {
            None
        } else {
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(lock_root.join("mountpoints.lock"))?;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Some(lock)
        };
        let mut prepared = Self {
            entries: Vec::new(),
            _lock: lock,
            finished: false,
        };
        for (path, is_dir) in requested {
            if is_dir {
                fs::create_dir(&path)?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            } else {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o000)
                    .open(&path)?;
            }
            let metadata = fs::symlink_metadata(&path)?;
            prepared
                .entries
                .push((path, metadata.dev(), metadata.ino(), is_dir));
        }
        Ok(prepared)
    }

    fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        let mut failure: Option<io::Error> = None;
        for (path, device, inode, is_dir) in self.entries.iter().rev() {
            let result = (|| {
                let metadata = fs::symlink_metadata(path)?;
                if metadata.dev() != *device
                    || metadata.ino() != *inode
                    || metadata.is_dir() != *is_dir
                {
                    return Err(io::Error::other(format!(
                        "sandbox mountpoint changed before cleanup: {}",
                        path.display()
                    )));
                }
                let removal = if *is_dir {
                    fs::remove_dir(path)
                } else {
                    fs::remove_file(path)
                };
                removal.map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!(
                            "cannot remove sandbox mountpoint {}: {error}",
                            path.display()
                        ),
                    )
                })
            })();
            if let Err(error) = result {
                failure = Some(match failure.take() {
                    Some(first) => io::Error::new(
                        first.kind(),
                        format!("{first}; additional cleanup failure: {error}"),
                    ),
                    None => error,
                });
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for PreparedMountpoints {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

struct DeniedNodes {
    root: std::path::PathBuf,
    denied_file: std::path::PathBuf,
    denied_dir: std::path::PathBuf,
    read_only_file: std::path::PathBuf,
    finished: bool,
}

impl DeniedNodes {
    fn create(runtime_dir: &Path) -> io::Result<Self> {
        let root = runtime_dir.join(format!(
            "cdm-denied-nodes-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir(&root)?;
        let denied_file = root.join("denied-file");
        let denied_dir = root.join("denied-dir");
        let read_only_file = root.join("read-only-file");
        let nodes = Self {
            root,
            denied_file,
            denied_dir,
            read_only_file,
            finished: false,
        };
        fs::set_permissions(&nodes.root, fs::Permissions::from_mode(0o700))?;
        fs::write(&nodes.denied_file, [])?;
        fs::set_permissions(&nodes.denied_file, fs::Permissions::from_mode(0o000))?;
        fs::create_dir(&nodes.denied_dir)?;
        fs::set_permissions(&nodes.denied_dir, fs::Permissions::from_mode(0o000))?;
        fs::write(&nodes.read_only_file, [])?;
        fs::set_permissions(&nodes.read_only_file, fs::Permissions::from_mode(0o444))?;
        Ok(nodes)
    }

    fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        let permissions =
            match fs::set_permissions(&self.denied_dir, fs::Permissions::from_mode(0o700)) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            };
        let removal = match fs::remove_dir_all(&self.root) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
        combine_cleanup(permissions, removal)?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for DeniedNodes {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

fn add_bind(args: &mut Vec<String>, operation: &str, path: &Path) {
    let path = path.to_string_lossy().to_string();
    args.push(operation.to_string());
    args.push(path.clone());
    args.push(path);
}

fn add_bind_from(args: &mut Vec<String>, operation: &str, source: &Path, target: &Path) {
    args.push(operation.to_string());
    args.push(source.to_string_lossy().into_owned());
    args.push(target.to_string_lossy().into_owned());
}

fn append_seccomp(args: &mut Vec<String>, fd: std::os::fd::RawFd) {
    args.push("--seccomp".to_string());
    args.push(fd.to_string());
}

#[cfg(test)]
mod tests;
