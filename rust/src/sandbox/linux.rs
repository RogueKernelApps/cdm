//! Linux sandbox implementation using Bubblewrap.

use crate::sandbox::{SandboxConfig, SandboxRun};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
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
    let denied_nodes = DeniedNodes::create()?;
    let seccomp = if cfg.network.is_proxied() {
        None
    } else {
        Some(crate::proxy_bridge::SeccompProgram::deny_host_socket_deputies()?)
    };
    let mut bridge = if cfg.network.is_proxied() {
        let runtime_root = cfg
            .runtime_dir
            .parent()
            .ok_or_else(|| io::Error::other("CDM runtime directory has no private parent"))?;
        Some(crate::proxy_bridge::ProxyBridge::start(
            runtime_root,
            cfg.proxy_port,
        )?)
    } else {
        None
    };

    if access.host == crate::access::HostAccess::Isolated {
        args.extend(["--tmpfs".to_string(), "/".to_string()]);
        for path in &access.runtime_ro {
            if path.exists() {
                add_bind(&mut args, "--ro-bind", path);
            }
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

    append_hard_denials(
        &mut args,
        &access.deny_write_rules,
        &access.deny_read_rules,
        &denied_nodes,
        &access.synthetic_dirs,
        |path| path_is_exposed(path, access),
        |path| path_is_writable(path, access),
    );

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

    let child = crate::process::run(&mut cmd);
    let cleanup = bridge.as_mut().map_or(Ok(()), |bridge| bridge.stop());
    Ok(SandboxRun { child, cleanup })
}

fn append_hard_denials(
    args: &mut Vec<String>,
    deny_write_rules: &[crate::access::ResolvedDenyRule],
    deny_read_rules: &[crate::access::ResolvedDenyRule],
    denied_nodes: &DeniedNodes,
    synthetic_dirs: &[std::path::PathBuf],
    path_is_exposed: impl Fn(&Path) -> bool,
    path_is_writable: impl Fn(&Path) -> bool,
) {
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
    let pinned_existing_parents = active_rules
        .iter()
        .filter(|rule| rule.missing_parents.is_empty())
        .flat_map(|rule| {
            rule.paths()
                .filter(|path| path_is_active(path))
                .filter_map(Path::parent)
                .map(Path::to_path_buf)
        })
        .collect::<BTreeSet<_>>();
    for parent in pinned_existing_parents {
        add_bind(
            args,
            if path_is_writable(&parent) {
                "--bind"
            } else {
                "--ro-bind"
            },
            &parent,
        );
    }
    // Every absent ancestor is a mountpoint, not a plain directory. This
    // prevents renaming any level of the path and recreating the denied leaf.
    for parent in missing_parents {
        args.push("--tmpfs".to_string());
        args.push(parent.to_string_lossy().into_owned());
    }

    for rule in deny_write_rules {
        for path in rule.paths().filter(|path| path_is_active(path)) {
            match rule.kind {
                crate::access::DeniedPathKind::Directory => {
                    add_bind(&mut args, "--ro-bind", path);
                }
                crate::access::DeniedPathKind::File | crate::access::DeniedPathKind::Other => {
                    add_bind(&mut args, "--ro-bind", path);
                }
                crate::access::DeniedPathKind::Missing => {
                    add_bind_from(&mut args, "--ro-bind", &denied_nodes.read_only_file, path);
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
            add_bind_from(&mut args, "--ro-bind", source, path);
        }
    }
}

fn path_is_exposed(path: &Path, access: &crate::access::ResolvedAccessPolicy) -> bool {
    access.host == crate::access::HostAccess::Normal
        || std::iter::once(&access.work_dir)
            .chain(&access.runtime_ro)
            .chain(&access.allow_ro)
            .chain(&access.allow_rw)
            .any(|root| path == root || path.starts_with(root))
}

fn path_is_writable(path: &Path, access: &crate::access::ResolvedAccessPolicy) -> bool {
    (access.workspace == crate::access::WorkspaceAccess::ReadWrite
        && (path == access.work_dir || path.starts_with(&access.work_dir)))
        || access
            .allow_rw
            .iter()
            .any(|root| path == root || path.starts_with(root))
}

fn path_is_covered_by_synthetic_dir(path: &Path, synthetic_dirs: &[std::path::PathBuf]) -> bool {
    synthetic_dirs
        .iter()
        .any(|root| path == root || path.starts_with(root))
}

struct DeniedNodes {
    root: std::path::PathBuf,
    denied_file: std::path::PathBuf,
    denied_dir: std::path::PathBuf,
    read_only_file: std::path::PathBuf,
}

impl DeniedNodes {
    fn create() -> io::Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "cdm-denied-nodes-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let denied_file = root.join("denied-file");
        let denied_dir = root.join("denied-dir");
        let read_only_file = root.join("read-only-file");
        fs::write(&denied_file, [])?;
        fs::set_permissions(&denied_file, fs::Permissions::from_mode(0o000))?;
        fs::create_dir(&denied_dir)?;
        fs::set_permissions(&denied_dir, fs::Permissions::from_mode(0o000))?;
        fs::write(&read_only_file, [])?;
        fs::set_permissions(&read_only_file, fs::Permissions::from_mode(0o444))?;
        Ok(Self {
            root,
            denied_file,
            denied_dir,
            read_only_file,
        })
    }
}

impl Drop for DeniedNodes {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.denied_dir, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.root);
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
