//! Dedicated host VMM launcher boundary and libkrun integration.

use std::ffi::{c_char, CString, OsStr};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::ptr;

use super::super::safe_root::require_real_directory;
use super::{SandboxConfig, GUEST_INIT, GUEST_PLAN};

#[allow(dead_code)]
extern "C" {
    fn krun_set_log_level(level: u32) -> i32;
    fn krun_create_ctx() -> i32;
    fn krun_free_ctx(ctx_id: u32) -> i32;
    fn krun_set_vm_config(ctx_id: u32, num_vcpus: u8, ram_mib: u32) -> i32;
    fn krun_set_root(ctx_id: u32, root_path: *const c_char) -> i32;
    fn krun_add_virtiofs(ctx_id: u32, c_tag: *const c_char, c_path: *const c_char) -> i32;
    fn krun_add_virtiofs3(
        ctx_id: u32,
        c_tag: *const c_char,
        c_path: *const c_char,
        shm_size: u64,
        read_only: bool,
    ) -> i32;
    fn krun_set_exec(
        ctx_id: u32,
        exec_path: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> i32;
    fn krun_start_enter(ctx_id: u32) -> i32;
    fn krun_set_console_output(ctx_id: u32, c_filepath: *const c_char) -> i32;
    fn krun_setuid(ctx_id: u32, uid: libc::uid_t) -> i32;
    fn krun_setgid(ctx_id: u32, gid: libc::gid_t) -> i32;
    fn krun_disable_implicit_vsock(ctx_id: u32) -> i32;
    fn krun_add_vsock(ctx_id: u32, tsi_features: u32) -> i32;
}

pub(super) fn launch(
    cfg: &SandboxConfig,
    rootfs: &Path,
    shares: Vec<VirtioFsShare>,
) -> io::Result<super::super::SandboxRun> {
    let plan = LauncherPlan {
        rootfs: rootfs.to_path_buf(),
        shares,
        vcpus: cfg.config.vm.vcpus,
        ram_mib: cfg.config.vm.ram_mib,
        disable_network: !cfg.network.allows_network(),
        debug: cfg.debug,
    };
    let plan_path = cfg
        .runtime_dir
        .join(format!("vm-plan-{}.json", std::process::id()));
    write_launcher_plan(&plan_path, &plan)?;

    let executable = std::env::current_exe()?;
    #[cfg(target_os = "macos")]
    let (program, arguments) = {
        let profile = launcher_profile(cfg, &executable, rootfs, &plan.shares)?;
        (
            std::path::PathBuf::from("/usr/bin/sandbox-exec"),
            vec![
                std::ffi::OsString::from("sandbox-exec"),
                std::ffi::OsString::from("-p"),
                std::ffi::OsString::from(profile),
                executable.clone().into_os_string(),
                std::ffi::OsString::from("__vm-launcher"),
                plan_path.clone().into_os_string(),
            ],
        )
    };
    #[cfg(target_os = "linux")]
    let mut proxy_bridge = if cfg.network.is_proxied() {
        Some(crate::proxy_bridge::ProxyBridge::start(
            cfg.runtime_dir
                .parent()
                .ok_or_else(|| io::Error::other("runtime session has no private root"))?,
            cfg.proxy_port,
        )?)
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    let vmm_seccomp = if proxy_bridge.is_none() {
        Some(crate::proxy_bridge::SeccompProgram::deny_host_socket_deputies()?)
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    let (program, arguments) = linux_launcher_command(
        cfg,
        &executable,
        rootfs,
        &plan_path,
        &plan,
        proxy_bridge.as_ref(),
        vmm_seccomp.as_ref(),
    )?;
    // The parent already owns a Tokio proxy thread, so this boundary must never
    // fall back to fork-before-exec.
    let child = posix_spawn_wait(&program, &arguments);
    let plan_cleanup = remove_consumed_plan(&plan_path);
    #[cfg(target_os = "linux")]
    let bridge_cleanup = proxy_bridge.as_mut().map_or(Ok(()), |bridge| bridge.stop());
    #[cfg(not(target_os = "linux"))]
    let bridge_cleanup = Ok(());
    let cleanup = plan_cleanup.and(bridge_cleanup);
    Ok(super::super::SandboxRun { child, cleanup })
}

fn remove_consumed_plan(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn write_launcher_plan(path: &Path, plan: &LauncherPlan) -> io::Result<()> {
    let bytes = serde_json::to_vec(plan).map_err(io::Error::other)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()
}

#[cfg(target_os = "macos")]
pub(super) fn launcher_profile(
    cfg: &SandboxConfig,
    executable: &Path,
    rootfs: &Path,
    shares: &[VirtioFsShare],
) -> io::Result<String> {
    let access = cfg.resolved_access()?;
    let mut profile = String::from("(version 1)\n(deny default)\n");
    profile.push_str(super::super::darwin::SECURE_RUNTIME_BASELINE);

    // The launcher is a deliberately tiny VMM host process. It can load the
    // signed CDM runtime and Apple's system runtime, but it cannot inspect the
    // rest of the host filesystem. The mutable rootfs is the only broad write
    // grant; exported host paths retain their resolved RO/RW intent.
    for path in [
        Path::new("/System"),
        Path::new("/usr/lib"),
        Path::new("/Library/Apple/System/Library"),
        Path::new("/private/var/db/dyld"),
    ] {
        push_launcher_path(&mut profile, "allow file-read*", "subpath", path);
    }
    let executable_dir = executable
        .parent()
        .ok_or_else(|| io::Error::other("CDM executable has no runtime directory"))?;
    push_launcher_path(&mut profile, "allow file-read*", "subpath", executable_dir);
    // Packaged VM runtimes use <root>/bin/cdm + <root>/lib/cdm/*.dylib.
    // Grant exactly the bundled library directory rather than the package
    // root, which also contains documentation and release metadata.
    for packaged_lib in macos_runtime_library_dirs(executable)? {
        push_launcher_path(&mut profile, "allow file-read*", "subpath", &packaged_lib);
    }
    push_launcher_path(&mut profile, "allow file-read*", "literal", executable);
    push_launcher_path(&mut profile, "allow file-read*", "subpath", rootfs);
    push_launcher_path(&mut profile, "allow file-write*", "subpath", rootfs);
    push_launcher_path(
        &mut profile,
        "allow file-read*",
        "subpath",
        &cfg.runtime_dir,
    );
    push_launcher_path(
        &mut profile,
        "allow file-write*",
        "subpath",
        &cfg.runtime_dir,
    );
    for device in [
        "/dev/null",
        "/dev/zero",
        "/dev/random",
        "/dev/urandom",
        "/dev/tty",
    ] {
        push_launcher_path(
            &mut profile,
            "allow file-read* file-write*",
            "literal",
            Path::new(device),
        );
    }

    for share in shares {
        let path = Path::new(&share.host_path);
        push_launcher_path(&mut profile, "allow file-read*", "subpath", path);
        if !share.read_only {
            push_launcher_path(&mut profile, "allow file-write*", "subpath", path);
        }
    }

    // Hard denials are emitted last. A contradictory VM export therefore
    // remains denied even if an earlier broad grant included its ancestor.
    for rule in &access.deny_read_rules {
        for path in rule.paths() {
            push_launcher_denial(
                &mut profile,
                "deny file-read*",
                launcher_deny_filter(rule.kind),
                path,
            );
        }
    }
    for rule in &access.deny_write_rules {
        for path in rule.paths() {
            push_launcher_denial(
                &mut profile,
                "deny file-write*",
                launcher_deny_filter(rule.kind),
                path,
            );
            push_launcher_denial(&mut profile, "deny file-write-unlink", "literal", path);
        }
    }

    match cfg.network {
        crate::network::NetworkPolicy::Disabled => profile.push_str("(deny network*)\n"),
        crate::network::NetworkPolicy::Direct => profile.push_str("(allow network*)\n"),
        crate::network::NetworkPolicy::Proxied(_) => {
            profile.push_str("(deny network*)\n");
            profile.push_str(&format!(
                "(allow network-outbound (remote tcp \"localhost:{}\"))\n",
                cfg.proxy_port
            ));
        }
    }
    Ok(profile)
}

#[cfg(target_os = "macos")]
fn macos_runtime_library_dirs(executable: &Path) -> io::Result<Vec<std::path::PathBuf>> {
    let executable_dir = executable
        .parent()
        .ok_or_else(|| io::Error::other("CDM executable has no runtime directory"))?;
    let packaged = executable_dir
        .parent()
        .unwrap_or(executable_dir)
        .join("lib/cdm");
    let mut directories = Vec::new();
    if packaged.is_dir() {
        directories.push(packaged.canonicalize()?);
    }
    let otool = crate::trusted_exec::fixed(Path::new("/usr/bin/otool"), "macOS otool")?;
    let mut command = otool.command()?;
    crate::trusted_exec::sanitize_host_environment(&mut command);
    let output = command.args(["-l"]).arg(executable).output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            "failed to inspect CDM runtime library paths",
        ));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| io::Error::other("otool returned non-UTF-8 output"))?;
    for line in text.lines().map(str::trim) {
        let Some(path) = line.strip_prefix("path ") else {
            continue;
        };
        let path = path.split_whitespace().next().unwrap_or_default();
        if path.starts_with('/') {
            let path = std::path::PathBuf::from(path);
            if path.join("libkrun.1.dylib").is_file() && !directories.contains(&path) {
                directories.push(path.canonicalize()?);
            }
        }
    }
    if directories.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no validated libkrun runtime directory was found for the VM launcher",
        ));
    }
    Ok(directories)
}

#[cfg(target_os = "macos")]
fn launcher_deny_filter(kind: crate::access::DeniedPathKind) -> &'static str {
    if kind == crate::access::DeniedPathKind::Directory {
        "subpath"
    } else {
        "literal"
    }
}

#[cfg(target_os = "macos")]
fn push_launcher_path(profile: &mut String, operation: &str, filter: &str, path: &Path) {
    let escaped = path
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    profile.push_str(&format!("({operation} ({filter} \"{escaped}\"))\n"));
    if let Ok(canonical) = path.canonicalize() {
        if canonical != path {
            let escaped = canonical
                .to_string_lossy()
                .replace('\\', "\\\\")
                .replace('"', "\\\"");
            profile.push_str(&format!("({operation} ({filter} \"{escaped}\"))\n"));
        }
    }
}

#[cfg(target_os = "macos")]
fn push_launcher_denial(profile: &mut String, operation: &str, filter: &str, path: &Path) {
    let escaped = path
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    profile.push_str(&format!("({operation} ({filter} \"{escaped}\"))\n"));
}

#[cfg(target_os = "linux")]
fn linux_launcher_command(
    cfg: &SandboxConfig,
    executable: &Path,
    rootfs: &Path,
    plan_path: &Path,
    plan: &LauncherPlan,
    bridge: Option<&crate::proxy_bridge::ProxyBridge>,
    seccomp: Option<&crate::proxy_bridge::SeccompProgram>,
) -> io::Result<(std::path::PathBuf, Vec<std::ffi::OsString>)> {
    let bwrap = crate::trusted_exec::bubblewrap()?;
    let kvm = Path::new("/dev/kvm");
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(kvm)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("Linux VM mode cannot open /dev/kvm read-write: {error}"),
            )
        })?;
    Ok((
        bwrap.path()?.to_path_buf(),
        build_linux_launcher_arguments(cfg, executable, rootfs, plan_path, plan, bridge, seccomp)?,
    ))
}

#[cfg(target_os = "linux")]
pub(super) fn build_linux_launcher_arguments(
    cfg: &SandboxConfig,
    executable: &Path,
    rootfs: &Path,
    plan_path: &Path,
    plan: &LauncherPlan,
    bridge: Option<&crate::proxy_bridge::ProxyBridge>,
    seccomp: Option<&crate::proxy_bridge::SeccompProgram>,
) -> io::Result<Vec<std::ffi::OsString>> {
    use crate::access::HostAccess;
    let access = cfg.resolved_access()?;
    let mut args = vec![
        "bwrap".into(),
        "--die-with-parent".into(),
        "--unshare-pid".into(),
        "--unshare-ipc".into(),
        "--unshare-uts".into(),
        "--unshare-cgroup".into(),
        "--cap-drop".into(),
        "ALL".into(),
    ];
    match access.host {
        HostAccess::Normal => {
            push_bwrap_bind(&mut args, "--ro-bind", Path::new("/"), Path::new("/"))
        }
        HostAccess::Isolated => {
            args.extend(["--tmpfs".into(), "/".into()]);
            for path in ["/usr", "/lib", "/lib64"] {
                if Path::new(path).exists() {
                    push_bwrap_bind(&mut args, "--ro-bind", Path::new(path), Path::new(path));
                }
            }
            let executable_dir = executable
                .parent()
                .ok_or_else(|| io::Error::other("CDM executable has no runtime directory"))?;
            push_bwrap_bind(&mut args, "--ro-bind", executable_dir, executable_dir);
            let packaged_lib = executable_dir
                .parent()
                .unwrap_or(executable_dir)
                .join("lib/cdm");
            if packaged_lib.is_dir() {
                push_bwrap_bind(&mut args, "--ro-bind", &packaged_lib, &packaged_lib);
            }
        }
    }
    if access.host == HostAccess::Normal {
        for target in &access.synthetic_mounts {
            args.extend(["--tmpfs".into(), target.as_os_str().into()]);
        }
    }
    args.extend([
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
    ]);
    let kvm = Path::new("/dev/kvm");
    push_bwrap_bind(&mut args, "--dev-bind", kvm, kvm);

    push_bwrap_bind(&mut args, "--bind", &cfg.runtime_dir, &cfg.runtime_dir);
    let denied_file = prepare_vmm_denied_file(&cfg.runtime_dir)?;
    // Pin the inaccessible source read-only before using it for final masks;
    // the VMM cannot chmod or replace it through the otherwise writable
    // invocation runtime.
    push_bwrap_bind(&mut args, "--ro-bind", &denied_file, &denied_file);
    const GUEST_BRIDGE_ROOT: &str = "/run/cdm-proxy-bridge";
    if let Some(bridge) = bridge {
        push_bwrap_bind(
            &mut args,
            "--ro-bind",
            bridge.root(),
            Path::new(GUEST_BRIDGE_ROOT),
        );
    }
    push_bwrap_bind(&mut args, "--bind", rootfs, rootfs);
    for share in &plan.shares {
        let path = Path::new(&share.host_path);
        push_bwrap_bind(
            &mut args,
            if share.read_only {
                "--ro-bind"
            } else {
                "--bind"
            },
            path,
            path,
        );
    }
    for rule in &access.deny_write_rules {
        if rule.kind == crate::access::DeniedPathKind::Missing {
            continue;
        }
        for path in rule.paths() {
            if access.host == HostAccess::Normal || path_is_exposed(path, access) {
                push_bwrap_bind(&mut args, "--ro-bind", path, path);
            }
        }
    }
    for rule in &access.deny_read_rules {
        if rule.kind == crate::access::DeniedPathKind::Missing {
            continue;
        }
        for path in rule.paths() {
            if access.host != HostAccess::Normal && !path_is_exposed(path, access) {
                continue;
            }
            if rule.kind == crate::access::DeniedPathKind::Directory {
                args.extend([
                    "--perms".into(),
                    "000".into(),
                    "--tmpfs".into(),
                    path.as_os_str().into(),
                ]);
            } else {
                push_bwrap_bind(&mut args, "--ro-bind", &denied_file, path);
            }
        }
    }
    if matches!(
        cfg.network,
        crate::network::NetworkPolicy::Disabled | crate::network::NetworkPolicy::Proxied(_)
    ) {
        args.push("--unshare-net".into());
    }
    if let Some(seccomp) = seccomp {
        args.extend(["--seccomp".into(), seccomp.as_raw_fd().to_string().into()]);
    }
    args.push("--".into());
    if bridge.is_some() {
        args.extend([
            executable.as_os_str().into(),
            "__linux-proxy-helper".into(),
            format!(
                "{GUEST_BRIDGE_ROOT}/{}",
                crate::proxy_bridge::BRIDGE_SOCKET_NAME
            )
            .into(),
            cfg.proxy_port.to_string().into(),
            "--".into(),
        ]);
    }
    args.extend([
        executable.as_os_str().into(),
        "__vm-launcher".into(),
        plan_path.as_os_str().into(),
    ]);
    Ok(args)
}

#[cfg(target_os = "linux")]
fn prepare_vmm_denied_file(runtime_dir: &Path) -> io::Result<std::path::PathBuf> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let path = runtime_dir.join("vmm-denied-file");
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o000)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let metadata = match options.open(&path) {
        Ok(file) => file.metadata()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            std::fs::symlink_metadata(&path)?
        }
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VMM denial source must be a regular, single-link file",
        ));
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))?;
    Ok(path)
}

#[cfg(target_os = "linux")]
fn push_bwrap_bind(
    args: &mut Vec<std::ffi::OsString>,
    operation: &str,
    source: &Path,
    destination: &Path,
) {
    args.extend([
        operation.into(),
        source.as_os_str().into(),
        destination.as_os_str().into(),
    ]);
}

static FORWARDED_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
static SIGNAL_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

extern "C" fn remember_signal(signal: libc::c_int) {
    FORWARDED_SIGNAL.store(signal, std::sync::atomic::Ordering::SeqCst);
    SIGNAL_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

pub(super) fn posix_spawn_wait(
    program: &Path,
    arguments: &[std::ffi::OsString],
) -> io::Result<crate::process::ChildStatus> {
    let program = CString::new(program.as_os_str().as_bytes())?;
    let argv = arguments
        .iter()
        .map(|argument| CString::new(argument.as_os_str().as_bytes()).map_err(io::Error::from))
        .collect::<io::Result<Vec<_>>>()?;
    let mut argv_ptrs = argv.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
    argv_ptrs.push(ptr::null());
    let env = [ptr::null::<c_char>()];
    let mut previous = Vec::new();
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = remember_signal as usize;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        if unsafe { libc::sigaction(signal, &action, &mut old) } != 0 {
            restore_signals(&previous);
            return Err(io::Error::last_os_error());
        }
        previous.push((signal, old));
    }
    FORWARDED_SIGNAL.store(0, std::sync::atomic::Ordering::SeqCst);
    SIGNAL_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
    let mut attributes: libc::posix_spawnattr_t = unsafe { std::mem::zeroed() };
    let init_result = unsafe { libc::posix_spawnattr_init(&mut attributes) };
    if init_result != 0 {
        restore_signals(&previous);
        return Err(io::Error::from_raw_os_error(init_result));
    }
    let attribute_result = unsafe {
        libc::posix_spawnattr_setflags(&mut attributes, libc::POSIX_SPAWN_SETPGROUP as i16)
    };
    if attribute_result == 0 {
        // A pgroup value of zero creates a new process group whose id is the
        // spawned child's pid. Signals can then cover sandbox-exec and every
        // VMM descendant rather than only the immediate process.
        unsafe { libc::posix_spawnattr_setpgroup(&mut attributes, 0) };
    }
    if attribute_result != 0 {
        unsafe { libc::posix_spawnattr_destroy(&mut attributes) };
        restore_signals(&previous);
        return Err(io::Error::from_raw_os_error(attribute_result));
    }
    let mut pid = 0;
    let spawn_result = unsafe {
        libc::posix_spawn(
            &mut pid,
            program.as_ptr(),
            ptr::null(),
            &attributes,
            argv_ptrs.as_ptr() as *const *mut c_char,
            env.as_ptr() as *const *mut c_char,
        )
    };
    unsafe { libc::posix_spawnattr_destroy(&mut attributes) };
    if spawn_result != 0 {
        restore_signals(&previous);
        return Err(io::Error::from_raw_os_error(spawn_result));
    }
    let mut status = 0;
    let terminal = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;
    let previous_foreground = if terminal {
        let foreground = unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) };
        if foreground >= 0 {
            if unsafe { libc::tcsetpgrp(libc::STDIN_FILENO, pid) } != 0 {
                let error = io::Error::last_os_error();
                unsafe { libc::kill(-pid, libc::SIGKILL) };
                let _ = unsafe { libc::waitpid(pid, &mut status, 0) };
                restore_signals(&previous);
                return Err(error);
            }
            Some(foreground)
        } else {
            None
        }
    } else {
        None
    };
    let mut first_forwarded_at = None;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid {
            break;
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            let _ = unsafe { libc::waitpid(pid, &mut status, 0) };
            restore_foreground(previous_foreground);
            restore_signals(&previous);
            return Err(error);
        }
        let count = SIGNAL_COUNT.swap(0, std::sync::atomic::Ordering::SeqCst);
        let signal = FORWARDED_SIGNAL.swap(0, std::sync::atomic::Ordering::SeqCst);
        if signal != 0 {
            let escalated = count > 1 || first_forwarded_at.is_some();
            unsafe { libc::kill(-pid, if escalated { libc::SIGKILL } else { signal }) };
            first_forwarded_at.get_or_insert_with(std::time::Instant::now);
        }
        if first_forwarded_at.is_some_and(|at| at.elapsed() >= std::time::Duration::from_secs(5)) {
            unsafe { libc::kill(-pid, libc::SIGKILL) };
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    restore_foreground(previous_foreground);
    restore_signals(&previous);
    if libc::WIFEXITED(status) {
        Ok(crate::process::ChildStatus::exited(libc::WEXITSTATUS(
            status,
        )))
    } else if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        Ok(crate::process::ChildStatus {
            exit_code: 128 + signal,
            signal: Some(signal),
        })
    } else {
        Ok(crate::process::ChildStatus::exited(1))
    }
}

fn restore_foreground(previous: Option<libc::pid_t>) {
    if let Some(group) = previous {
        unsafe {
            let mut blocked: libc::sigset_t = std::mem::zeroed();
            let mut old: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut blocked);
            libc::sigaddset(&mut blocked, libc::SIGTTOU);
            libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut old);
            libc::tcsetpgrp(libc::STDIN_FILENO, group);
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, ptr::null_mut());
        }
    }
}

fn restore_signals(previous: &[(libc::c_int, libc::sigaction)]) {
    for (signal, action) in previous {
        unsafe { libc::sigaction(*signal, action, ptr::null_mut()) };
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LauncherPlan {
    pub(super) rootfs: std::path::PathBuf,
    pub(super) shares: Vec<VirtioFsShare>,
    pub(super) vcpus: u8,
    pub(super) ram_mib: u32,
    pub(super) disable_network: bool,
    pub(super) debug: bool,
}

pub(crate) fn run_launcher(path: &Path) -> io::Result<i32> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    let current_uid = unsafe { libc::getuid() };
    if !metadata.is_file()
        || metadata.uid() != current_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VM launcher plan must be a mode-0600, singly-linked regular file owned by the invoking user",
        ));
    }
    let session = path
        .parent()
        .ok_or_else(|| io::Error::other("VM launcher plan has no session directory"))?;
    let session_metadata = std::fs::symlink_metadata(session)?;
    if session_metadata.file_type().is_symlink()
        || !session_metadata.is_dir()
        || session_metadata.uid() != current_uid
        || session_metadata.permissions().mode() & 0o777 != 0o700
        || !session
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("session-"))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe VM launcher session directory",
        ));
    }
    let canonical_session = session.canonicalize()?;
    let runtime_root = canonical_session
        .parent()
        .ok_or_else(|| io::Error::other("VM launcher session has no runtime root"))?;
    if runtime_root.file_name() != Some(OsStr::new("cdm")) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VM launcher session is outside a private CDM runtime root",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(1024 * 1024)
        .read_to_end(&mut bytes)?;
    if bytes.len() == 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VM launcher plan exceeds the 1 MiB limit",
        ));
    }
    let plan: LauncherPlan = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    validate_launcher_plan(&plan, session)?;
    require_real_directory(&plan.rootfs, "launcher rootfs")?;
    std::fs::remove_file(path)?;
    drop(file);
    if plan.debug {
        unsafe {
            krun_set_log_level(4);
        }
    }
    let ctx = KrunContext::create()?;
    // Never accept libkrun's implicit TSI feature selection: setting a root
    // filesystem would otherwise enable AF_UNIX impersonation. CDM explicitly
    // enables only INET/INET6 TSI when networking is allowed.
    krun_check(
        unsafe { krun_disable_implicit_vsock(ctx.id()) },
        "krun_disable_implicit_vsock",
    )?;
    let tsi_features = explicit_tsi_features(plan.disable_network);
    krun_check(
        unsafe { krun_add_vsock(ctx.id(), tsi_features) },
        "krun_add_vsock",
    )?;
    if plan.debug {
        eprintln!("[cdm] vm: vcpus={}, ram={}MiB", plan.vcpus, plan.ram_mib);
    }
    krun_check(
        unsafe { krun_set_vm_config(ctx.id(), plan.vcpus, plan.ram_mib) },
        "krun_set_vm_config",
    )?;
    if plan.debug {
        let log_path = session.join("vm-console.log");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&log_path)?;
        let c_path = to_cstring(&log_path.to_string_lossy())?;
        krun_check(
            unsafe { krun_set_console_output(ctx.id(), c_path.as_ptr()) },
            "krun_set_console_output",
        )?;
    }
    let root = to_cstring(&plan.rootfs.to_string_lossy())?;
    krun_check(
        unsafe { krun_set_root(ctx.id(), root.as_ptr()) },
        "krun_set_root",
    )?;
    add_virtiofs_shares(ctx.id(), &plan.shares, plan.debug)?;
    set_exec(ctx.id(), GUEST_INIT, &[GUEST_PLAN.to_string()])?;
    let result = unsafe { krun_start_enter(ctx.id()) };
    if result < 0 {
        Err(io::Error::other(format!(
            "krun_start_enter failed: {result}"
        )))
    } else {
        Ok(result)
    }
}

pub(super) fn explicit_tsi_features(disable_network: bool) -> u32 {
    const KRUN_TSI_HIJACK_INET: u32 = 1 << 0;
    if disable_network {
        0
    } else {
        KRUN_TSI_HIJACK_INET
    }
}

pub(super) fn validate_launcher_plan(plan: &LauncherPlan, session: &Path) -> io::Result<()> {
    if !(1..=64).contains(&plan.vcpus) || !(64..=1_048_576).contains(&plan.ram_mib) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VM launcher resource bounds are invalid",
        ));
    }
    if plan.shares.len() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VM launcher has too many shares",
        ));
    }
    let mut tags = std::collections::HashSet::new();
    for share in &plan.shares {
        if !tags.insert(&share.tag)
            || share.tag.is_empty()
            || share.tag.len() > 64
            || !share
                .tag
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !Path::new(&share.host_path).is_absolute()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VM launcher share is malformed",
            ));
        }
        require_real_directory(Path::new(&share.host_path), "launcher share")?;
    }
    if plan.rootfs.parent() != Some(session)
        || !plan
            .rootfs
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("cdm-rootfs-"))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VM launcher rootfs is outside its private session",
        ));
    }
    Ok(())
}

struct KrunContext(u32);

impl KrunContext {
    fn create() -> io::Result<Self> {
        let ctx = unsafe { krun_create_ctx() };
        if ctx < 0 {
            return Err(io::Error::other(format!("krun_create_ctx failed: {ctx}")));
        }
        Ok(Self(ctx as u32))
    }

    fn id(&self) -> u32 {
        self.0
    }
}

impl Drop for KrunContext {
    fn drop(&mut self) {
        unsafe {
            krun_free_ctx(self.0);
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct VirtioFsShare {
    pub(super) tag: String,
    pub(super) host_path: String,
    pub(super) read_only: bool,
}

fn add_virtiofs_shares(ctx: u32, shares: &[VirtioFsShare], debug: bool) -> io::Result<()> {
    for share in shares {
        let c_tag = to_cstring(&share.tag)?;
        let c_path = to_cstring(&share.host_path)?;
        let ret =
            unsafe { krun_add_virtiofs3(ctx, c_tag.as_ptr(), c_path.as_ptr(), 0, share.read_only) };
        if ret < 0 {
            if debug {
                eprintln!("[cdm] vm: krun_add_virtiofs3({}) failed: {ret}", share.tag);
            }
            return Err(io::Error::other(format!(
                "krun_add_virtiofs3({}) failed: {ret}",
                share.tag
            )));
        }
    }
    Ok(())
}

fn set_exec(ctx: u32, init: &str, command: &[String]) -> io::Result<()> {
    let c_exec = to_cstring(init)?;
    let argv_strings = krun_exec_arguments(command);
    let c_argv: Vec<CString> = argv_strings
        .iter()
        .map(|a| to_cstring(a))
        .collect::<io::Result<Vec<_>>>()?;
    let c_argv_ptrs = to_ptr_array(&c_argv);
    let empty_envp: Vec<*const c_char> = vec![ptr::null()];

    krun_check(
        unsafe {
            krun_set_exec(
                ctx,
                c_exec.as_ptr(),
                c_argv_ptrs.as_ptr(),
                empty_envp.as_ptr(),
            )
        },
        "krun_set_exec",
    )
}

fn krun_exec_arguments(command: &[String]) -> Vec<String> {
    command.to_vec()
}

pub(super) fn krun_check(ret: i32, context: &str) -> io::Result<()> {
    if ret < 0 {
        Err(io::Error::other(format!("{context} failed: {ret}")))
    } else {
        Ok(())
    }
}

pub(super) fn to_cstring(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

pub(super) fn to_ptr_array(strings: &[CString]) -> Vec<*const c_char> {
    let mut ptrs: Vec<*const c_char> = strings.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(ptr::null());
    ptrs
}

#[cfg(test)]
mod exec_tests {
    use super::{krun_exec_arguments, remove_consumed_plan};

    #[test]
    fn libkrun_arguments_exclude_the_separate_exec_path() {
        assert_eq!(
            krun_exec_arguments(&["/cdm-plan.json".to_string()]),
            ["/cdm-plan.json"]
        );
    }

    #[test]
    fn launcher_plan_cleanup_accepts_the_child_having_consumed_it() {
        let missing =
            std::env::temp_dir().join(format!("cdm-consumed-launcher-plan-{}", std::process::id()));
        assert!(remove_consumed_plan(&missing).is_ok());
    }
}
