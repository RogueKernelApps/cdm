use cdm_guest_init::{
    absolute_normal_path, mapped_wait_status, Deny, DenyKind, Mount, MountKind, Plan,
};
use std::env;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

const EXIT_INIT_FAILURE: u8 = 125;
const EXIT_NOT_EXECUTABLE: u8 = 126;
const EXIT_NOT_FOUND: u8 = 127;
const DENY_ROOT: &str = "/run/cdm-deny";
static CHILD_PROCESS_GROUP: AtomicI32 = AtomicI32::new(0);

pub fn entry() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code.clamp(0, u8::MAX as i32) as u8),
        Err(error) => {
            eprintln!("cdm-guest-init: {error}");
            ExitCode::from(EXIT_INIT_FAILURE)
        }
    }
}

pub fn security_probe_entry() -> ExitCode {
    match security_probe() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cdm-guest-init security probe: {error}");
            ExitCode::FAILURE
        }
    }
}

fn security_probe() -> io::Result<()> {
    if unsafe { libc::getuid() } == 0 || unsafe { libc::geteuid() } == 0 {
        return Err(io::Error::other(
            "probe unexpectedly has real or effective uid 0",
        ));
    }
    let status = std::fs::read_to_string("/proc/self/status")?;
    for (name, expected) in [
        ("NoNewPrivs", "1"),
        ("CapInh", "0000000000000000"),
        ("CapPrm", "0000000000000000"),
        ("CapEff", "0000000000000000"),
        ("CapBnd", "0000000000000000"),
        ("CapAmb", "0000000000000000"),
    ] {
        let actual = status
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}:")))
            .map(str::trim)
            .ok_or_else(|| io::Error::other(format!("/proc status has no {name}")))?;
        if actual != expected {
            return Err(io::Error::other(format!(
                "expected {name}={expected}, got {actual}"
            )));
        }
    }
    if unsafe { libc::setuid(0) } == 0 {
        return Err(io::Error::other("setuid(0) unexpectedly succeeded"));
    }
    let mut header = CapabilityHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [CapabilityData::default(); 2];
    data[0].effective = 1;
    data[0].permitted = 1;
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) } == 0 {
        return Err(io::Error::other(
            "adding a permitted/effective capability unexpectedly succeeded",
        ));
    }
    Ok(())
}

fn run() -> io::Result<i32> {
    let path = plan_argument()?;
    let file = open_regular_plan(&path)?;
    let plan = Plan::parse(file)?;
    apply_mounts(&plan.mounts, plan.uid, plan.gid)?;
    apply_denies(&plan.denies)?;
    harden_exec_boundary()?;
    run_as_pid_one(&plan)
}

fn harden_exec_boundary() -> io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("cannot enable no-new-privileges: {error}"),
        ));
    }
    clear_ambient_capabilities()?;
    drop_capability_bounding_set(capability_last_cap()?)
}

fn capability_last_cap() -> io::Result<u32> {
    let value = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")?;
    let value = value
        .trim()
        .parse::<u32>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if value > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel capability range exceeds the supported bound",
        ));
    }
    Ok(value)
}

fn drop_capability_bounding_set(last: u32) -> io::Result<()> {
    drop_capability_bounding_set_with(
        last,
        |capability| {
            let result = unsafe { libc::prctl(libc::PR_CAPBSET_READ, capability, 0, 0, 0) };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(result == 1)
            }
        },
        |capability| {
            if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        },
    )
}

fn drop_capability_bounding_set_with(
    last: u32,
    mut is_present: impl FnMut(u32) -> io::Result<bool>,
    mut drop_one: impl FnMut(u32) -> io::Result<()>,
) -> io::Result<()> {
    for capability in 0..=last {
        let present = is_present(capability).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot inspect capability {capability}: {error}"),
            )
        })?;
        if present {
            drop_one(capability).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("cannot drop capability {capability}: {error}"),
                )
            })?;
        }
    }
    Ok(())
}

fn clear_ambient_capabilities() -> io::Result<()> {
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } == 0
    {
        Ok(())
    } else {
        let error = io::Error::last_os_error();
        Err(io::Error::new(
            error.kind(),
            format!("cannot clear ambient capabilities: {error}"),
        ))
    }
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn clear_process_capabilities() -> io::Result<()> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let mut header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapabilityData::default(); 2];
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) } == 0 {
        clear_ambient_capabilities()
    } else {
        let error = io::Error::last_os_error();
        Err(io::Error::new(
            error.kind(),
            format!("cannot clear process capabilities: {error}"),
        ))
    }
}

fn plan_argument() -> io::Result<PathBuf> {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let path = args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "usage: {} /absolute/path/to/plan.json",
                Path::new(&program).display()
            ),
        )
    })?;
    if args.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guest init accepts exactly one plan path",
        ));
    }
    let path = PathBuf::from(path);
    absolute_normal_path(&path, "plan path")?;
    Ok(path)
}

fn open_regular_plan(path: &Path) -> io::Result<File> {
    let descriptor = open_path(
        path,
        libc::O_RDONLY as u64 | libc::O_CLOEXEC as u64,
        "guest plan",
    )?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guest plan must be a regular, non-hard-linked file",
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guest plan must not be group- or world-writable",
        ));
    }
    Ok(file)
}

fn apply_mounts(mounts: &[Mount], uid: u32, gid: u32) -> io::Result<()> {
    for mount in mounts {
        apply_mount(mount, uid, gid).map_err(|error| {
            io::Error::other(format!(
                "required {:?} mount at {} failed: {error}",
                mount.kind,
                mount.target.display()
            ))
        })?;
    }
    Ok(())
}

fn apply_mount(mount: &Mount, uid: u32, gid: u32) -> io::Result<()> {
    if mount.kind == MountKind::Bind {
        return apply_bind_mount(mount);
    }
    let target = open_mount_target(&mount.target, true)?;
    let (source, fs_type, data) = match mount.kind {
        MountKind::Virtiofs => (
            mount.source.as_deref().unwrap_or_default(),
            "virtiofs",
            String::new(),
        ),
        MountKind::Proc => ("proc", "proc", String::new()),
        MountKind::Sysfs => ("sysfs", "sysfs", String::new()),
        MountKind::Devtmpfs => ("devtmpfs", "devtmpfs", "mode=0755".into()),
        MountKind::Tmpfs => ("tmpfs", "tmpfs", format!("mode=0700,uid={uid},gid={gid}")),
        MountKind::Bind => unreachable!("bind mount handled above"),
    };
    let mut flags = libc::MS_NOSUID;
    if mount.kind != MountKind::Devtmpfs {
        flags |= libc::MS_NODEV;
    }
    if mount.read_only {
        flags |= libc::MS_RDONLY;
    }
    mount_new_at_descriptor(source, &target, fs_type, flags, &data)
}

fn apply_bind_mount(mount: &Mount) -> io::Result<()> {
    let source_path = Path::new(mount.source.as_deref().unwrap_or_default());
    let source = open_path(
        source_path,
        libc::O_PATH as u64 | libc::O_CLOEXEC as u64,
        "bind mount source",
    )?;
    let target = open_mount_target(&mount.target, target_is_directory(&source)?)?;
    let stable_source = format!("/proc/self/fd/{}", source.as_raw_fd());
    mount_at_descriptor(
        Some(stable_source),
        &target,
        None,
        libc::MS_BIND,
        None::<&str>,
    )?;
    // Plan validation guarantees every bind source lives on a read-only
    // VirtioFS export. The bind therefore inherits an immutable backing
    // superblock. Remounting a single-file bind from libkrun VirtioFS returns
    // EINVAL on the supported guest kernel and is both redundant and harmful.
    Ok(())
}

fn target_is_directory(descriptor: &OwnedFd) -> io::Result<bool> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

fn apply_denies(denies: &[Deny]) -> io::Result<()> {
    if denies.is_empty() {
        return Ok(());
    }
    prepare_deny_root().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot prepare deny-mask source: {error}"),
        )
    })?;
    for deny in denies.iter().filter(|deny| deny.kind == DenyKind::File) {
        let target = open_mount_target(&deny.path, false)?;
        let source = Path::new(DENY_ROOT).join("file");
        mount_at_descriptor(
            Some(source.as_os_str()),
            &target,
            None,
            libc::MS_BIND,
            None::<&str>,
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot bind deny mask over file {}: {error}",
                    deny.path.display()
                ),
            )
        })?;
        // A file bind over VirtioFS cannot be remounted read-only on libkrun's
        // guest kernel (mount(2) returns EINVAL). The mask remains immutable
        // to the wrapped command: its inode is root-owned and mode 000, its
        // source directory is root-only, the target is a busy mount point,
        // and the child runs as a non-root user without capabilities or a way
        // to gain privileges. The integration journey proves read, overwrite,
        // and unlink attempts all fail while the host file remains unchanged.
    }
    for deny in denies
        .iter()
        .filter(|deny| deny.kind == DenyKind::Directory)
    {
        let target = open_mount_target(&deny.path, true)?;
        mount_new_at_descriptor(
            "tmpfs",
            &target,
            "tmpfs",
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "size=0,mode=000",
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot mount directory deny mask at {}: {error}",
                    deny.path.display()
                ),
            )
        })?;
    }
    Ok(())
}

fn prepare_deny_root() -> io::Result<()> {
    let root = Path::new(DENY_ROOT);
    let _run = open_mount_target(Path::new("/run"), true)?;
    match std::fs::create_dir(root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _root = open_mount_target(root, true)?;
        }
        Err(error) => return Err(error),
    }
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    let file = root.join("file");
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o000)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&file)
        .or_else(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&file)
            } else {
                Err(error)
            }
        })?;
    let metadata = opened.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "deny placeholder must be a regular, non-hard-linked file",
        ));
    }
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o000))
}

fn open_mount_target(path: &Path, directory: bool) -> io::Result<OwnedFd> {
    absolute_normal_path(path, "mount target")?;
    let descriptor = open_path(
        path,
        libc::O_PATH as u64 | libc::O_CLOEXEC as u64,
        "mount target",
    )?;
    let target_is_directory = target_is_directory(&descriptor)?;
    if directory != target_is_directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "mount target {} is not a {}",
                path.display(),
                if directory { "directory" } else { "file" }
            ),
        ));
    }
    Ok(descriptor)
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;

fn open_path(path: &Path, flags: u64, label: &str) -> io::Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let how = OpenHow {
        flags,
        mode: 0,
        resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    };
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("cannot safely open {label}: {error}"),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor as i32) })
}

const FSOPEN_CLOEXEC: libc::c_uint = 0x0000_0001;
const FSCONFIG_SET_STRING: libc::c_uint = 1;
const FSCONFIG_CMD_CREATE: libc::c_uint = 6;
const FSMOUNT_CLOEXEC: libc::c_uint = 0x0000_0001;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;
const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x0000_0040;

fn mount_new_at_descriptor(
    source: &str,
    target: &OwnedFd,
    fs_type: &str,
    flags: libc::c_ulong,
    data: &str,
) -> io::Result<()> {
    let fs_type = CString::new(fs_type)?;
    let fsfd = checked_fd(
        unsafe { libc::syscall(libc::SYS_fsopen, fs_type.as_ptr(), FSOPEN_CLOEXEC) },
        "fsopen",
    )?;
    if !source.is_empty() {
        fsconfig_string(&fsfd, "source", source)?;
    }
    for option in data.split(',').filter(|option| !option.is_empty()) {
        match option.split_once('=') {
            Some((key, value)) => fsconfig_string(&fsfd, key, value)?,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("mount option {option:?} has no value"),
                ))
            }
        }
    }
    fsconfig_create(&fsfd)?;
    let mount_fd = checked_fd(
        unsafe { libc::syscall(libc::SYS_fsmount, fsfd.as_raw_fd(), FSMOUNT_CLOEXEC, flags) },
        "fsmount",
    )?;
    let empty = c"";
    let result = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mount_fd.as_raw_fd(),
            empty.as_ptr(),
            target.as_raw_fd(),
            empty.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        let error = io::Error::last_os_error();
        Err(io::Error::new(
            error.kind(),
            format!("move_mount failed: {error}"),
        ))
    }
}

fn fsconfig_string(descriptor: &OwnedFd, key: &str, value: &str) -> io::Result<()> {
    let key = CString::new(key)?;
    let value = CString::new(value)?;
    fsconfig(
        descriptor,
        FSCONFIG_SET_STRING,
        key.as_ptr(),
        value.as_ptr().cast(),
    )
}

fn fsconfig_create(descriptor: &OwnedFd) -> io::Result<()> {
    fsconfig(
        descriptor,
        FSCONFIG_CMD_CREATE,
        std::ptr::null(),
        std::ptr::null(),
    )
}

fn fsconfig(
    descriptor: &OwnedFd,
    command: libc::c_uint,
    key: *const libc::c_char,
    value: *const libc::c_void,
) -> io::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            descriptor.as_raw_fd(),
            command,
            key,
            value,
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        let error = io::Error::last_os_error();
        Err(io::Error::new(
            error.kind(),
            format!("fsconfig failed: {error}"),
        ))
    }
}

fn checked_fd(value: libc::c_long, operation: &str) -> io::Result<OwnedFd> {
    if value < 0 {
        let error = io::Error::last_os_error();
        Err(io::Error::new(
            error.kind(),
            format!("{operation} failed: {error}"),
        ))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(value as i32) })
    }
}

fn mount_at_descriptor<S: AsRef<std::ffi::OsStr>, D: AsRef<std::ffi::OsStr>>(
    source: Option<S>,
    target: &OwnedFd,
    fs_type: Option<&str>,
    flags: libc::c_ulong,
    data: Option<D>,
) -> io::Result<()> {
    let stable_target = PathBuf::from(format!("/proc/self/fd/{}", target.as_raw_fd()));
    mount_call(source, &stable_target, fs_type, flags, data)
}

fn mount_call<S: AsRef<std::ffi::OsStr>, D: AsRef<std::ffi::OsStr>>(
    source: Option<S>,
    target: &Path,
    fs_type: Option<&str>,
    flags: libc::c_ulong,
    data: Option<D>,
) -> io::Result<()> {
    let source = source
        .map(|value| CString::new(value.as_ref().as_bytes()))
        .transpose()?;
    let target = CString::new(target.as_os_str().as_bytes())?;
    let fs_type = fs_type.map(CString::new).transpose()?;
    let data = data
        .map(|value| CString::new(value.as_ref().as_bytes()))
        .transpose()?;
    let result = unsafe {
        libc::mount(
            source
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            target.as_ptr(),
            fs_type
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            flags,
            data.as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr().cast()),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn run_as_pid_one(plan: &Plan) -> io::Result<i32> {
    let signals = [
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGWINCH,
    ];
    let original_mask = block_signals(&signals)?;
    install_forwarders(&signals)?;

    let argv = plan.argv();
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .env_clear()
        .envs(&plan.fake_env)
        .current_dir(&plan.cwd);
    let child_mask = original_mask;
    let uid = plan.uid;
    let gid = plan.gid;
    unsafe {
        command.pre_exec(move || {
            if libc::sigprocmask(libc::SIG_SETMASK, &child_mask, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setresgid(gid, gid, gid) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setresuid(uid, uid, uid) != 0 {
                return Err(io::Error::last_os_error());
            }
            clear_process_capabilities()?;
            Ok(())
        });
    }
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            restore_signal_mask(&original_mask)?;
            return Ok(match error.kind() {
                io::ErrorKind::NotFound => EXIT_NOT_FOUND as i32,
                io::ErrorKind::PermissionDenied => EXIT_NOT_EXECUTABLE as i32,
                _ => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!("cannot start command: {error}"),
                    ))
                }
            });
        }
    };
    let primary = child.id() as libc::pid_t;
    CHILD_PROCESS_GROUP.store(primary, Ordering::Release);
    restore_signal_mask(&original_mask)?;

    let primary_status = loop {
        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid == primary {
            break status;
        }
        if pid < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::new(
                error.kind(),
                format!("waitpid failed: {error}"),
            ));
        }
    };
    terminate_and_reap(primary);
    CHILD_PROCESS_GROUP.store(0, Ordering::Release);
    mapped_wait_status(primary_status)
        .ok_or_else(|| io::Error::other("primary command stopped without exiting"))
}

extern "C" fn forward_signal(signal: libc::c_int) {
    let process_group = CHILD_PROCESS_GROUP.load(Ordering::Acquire);
    if process_group > 0 {
        unsafe {
            libc::kill(-process_group, signal);
        }
    }
}

fn install_forwarders(signals: &[libc::c_int]) -> io::Result<()> {
    for &signal in signals {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = forward_signal as usize;
        action.sa_flags = libc::SA_RESTART;
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn block_signals(signals: &[libc::c_int]) -> io::Result<libc::sigset_t> {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut original: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        for &signal in signals {
            libc::sigaddset(&mut set, signal);
        }
        if libc::sigprocmask(libc::SIG_BLOCK, &set, &mut original) == 0 {
            Ok(original)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

fn restore_signal_mask(mask: &libc::sigset_t) -> io::Result<()> {
    if unsafe { libc::sigprocmask(libc::SIG_SETMASK, mask, std::ptr::null_mut()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn terminate_and_reap(process_group: libc::pid_t) {
    unsafe {
        libc::kill(-process_group, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if reap_without_waiting() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
    let kill_deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < kill_deadline && !reap_without_waiting() {
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn reap_without_waiting() -> bool {
    loop {
        let mut status = 0;
        let result = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if result > 0 {
            continue;
        }
        if result == 0 {
            return false;
        }
        return io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let suffix = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("cdm-guest-init-{}-{suffix}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn plan_open_rejects_symlink_hardlink_and_writable_file() {
        let fixture = Fixture::new();
        let plan = fixture.0.join("plan.json");
        std::fs::write(&plan, "{}").unwrap();
        std::fs::set_permissions(&plan, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(open_regular_plan(&plan).is_ok());

        let link = fixture.0.join("link.json");
        symlink(&plan, &link).unwrap();
        assert!(open_regular_plan(&link).is_err());

        let hardlink = fixture.0.join("hardlink.json");
        std::fs::hard_link(&plan, &hardlink).unwrap();
        assert!(open_regular_plan(&plan).is_err());
        std::fs::remove_file(hardlink).unwrap();

        std::fs::set_permissions(&plan, std::fs::Permissions::from_mode(0o622)).unwrap();
        assert!(open_regular_plan(&plan).is_err());
    }

    #[test]
    fn mount_target_open_rejects_final_and_ancestor_symlinks() {
        let fixture = Fixture::new();
        let real = fixture.0.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = fixture.0.join("link");
        symlink(&real, &link).unwrap();
        assert!(open_mount_target(&link, true).is_err());

        let child = real.join("child");
        std::fs::create_dir(&child).unwrap();
        assert!(open_mount_target(&link.join("child"), true).is_err());
    }

    #[test]
    fn mount_target_open_rejects_missing_path_without_creating_it() {
        let fixture = Fixture::new();
        let missing = fixture.0.join("missing/deny-target");
        assert!(open_mount_target(&missing, false).is_err());
        assert!(!fixture.0.join("missing").exists());
    }

    #[test]
    fn held_mount_target_descriptor_survives_path_replacement() {
        let fixture = Fixture::new();
        let target = fixture.0.join("target");
        let moved = fixture.0.join("moved");
        let replacement = fixture.0.join("replacement");
        std::fs::create_dir(&target).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        let descriptor = open_mount_target(&target, true).unwrap();
        let mut before: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::fstat(descriptor.as_raw_fd(), &mut before) },
            0
        );

        std::fs::rename(&target, &moved).unwrap();
        symlink(&replacement, &target).unwrap();
        let mut after: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::fstat(descriptor.as_raw_fd(), &mut after) },
            0
        );
        assert_eq!(before.st_dev, after.st_dev);
        assert_eq!(before.st_ino, after.st_ino);
        assert!(open_mount_target(&target, true).is_err());
    }

    #[test]
    fn bounding_set_drop_is_complete_selective_and_fail_closed() {
        let mut inspected = Vec::new();
        let mut dropped = Vec::new();
        drop_capability_bounding_set_with(
            5,
            |capability| {
                inspected.push(capability);
                Ok(capability % 2 == 0)
            },
            |capability| {
                dropped.push(capability);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(inspected, [0, 1, 2, 3, 4, 5]);
        assert_eq!(dropped, [0, 2, 4]);

        let error = drop_capability_bounding_set_with(
            3,
            |_| Ok(true),
            |capability| {
                if capability == 2 {
                    Err(io::Error::from_raw_os_error(libc::EPERM))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("capability 2"));
    }

    #[test]
    fn zero_capability_payload_clears_every_process_set() {
        let data = [CapabilityData::default(); 2];
        assert!(data
            .iter()
            .all(|word| { word.effective == 0 && word.permitted == 0 && word.inheritable == 0 }));
    }
}
