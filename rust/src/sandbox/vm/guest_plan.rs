//! Guest mount-plan construction and serialization.

use std::collections::HashMap;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::super::safe_root::SafeRoot;
use super::{path_is_exposed, SandboxConfig, GUEST_PLAN, TAG_CERTS, TAG_STAGE, TAG_WORKDIR};

#[derive(serde::Serialize)]
struct GuestPlan<'a> {
    schema: u32,
    /// Lossless Unix argv bytes. JSON strings would reject otherwise valid
    /// non-UTF-8 filenames and arguments.
    argv_bytes: Vec<Vec<u8>>,
    fake_env: &'a HashMap<String, String>,
    cwd: &'a Path,
    uid: u32,
    gid: u32,
    mounts: Vec<GuestMount>,
    denies: Vec<GuestDeny>,
}

#[derive(serde::Serialize)]
struct GuestMount {
    kind: GuestMountKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    target: std::path::PathBuf,
    read_only: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum GuestMountKind {
    Virtiofs,
    Bind,
    Proc,
    Sysfs,
    Devtmpfs,
    Tmpfs,
}

#[derive(serde::Serialize, PartialEq, Eq)]
struct GuestDeny {
    path: std::path::PathBuf,
    kind: GuestDenyKind,
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum GuestDenyKind {
    File,
    Directory,
}

pub(super) fn write(
    rootfs: &Path,
    cfg: &SandboxConfig,
    env: &HashMap<String, String>,
) -> io::Result<()> {
    let (guest_uid, guest_gid) =
        guest_identity_for(unsafe { libc::getuid() }, unsafe { libc::getgid() });
    let access = cfg.resolved_access()?;
    let safe = SafeRoot::open(rootfs)?;
    let mut mounts = vec![
        guest_mount(GuestMountKind::Proc, None, "/proc", false),
        guest_mount(GuestMountKind::Sysfs, None, "/sys", true),
        guest_mount(GuestMountKind::Devtmpfs, None, "/dev", false),
        guest_mount(GuestMountKind::Tmpfs, None, &cfg.runtime_dir, false),
        guest_mount(
            GuestMountKind::Virtiofs,
            Some(TAG_WORKDIR),
            &cfg.work_dir,
            access.workspace == crate::access::WorkspaceAccess::ReadOnly,
        ),
    ];
    if cfg.file_stage.is_some() {
        mounts.push(guest_mount(
            GuestMountKind::Virtiofs,
            Some(TAG_STAGE),
            super::super::GUEST_STAGE_MOUNT,
            true,
        ));
    }
    if cfg.ca_cert_path.is_some() {
        mounts.push(guest_mount(
            GuestMountKind::Virtiofs,
            Some(TAG_CERTS),
            super::super::GUEST_CERTS_MOUNT,
            true,
        ));
    }
    for (kind, paths, read_only) in [
        ("allow-ro", &access.allow_ro, true),
        ("allow-rw", &access.allow_rw, false),
    ] {
        for (index, path) in paths.iter().enumerate() {
            if path.starts_with(&access.work_dir)
                || access.denies_read(path)
                || access.denies_write(path)
            {
                continue;
            }
            if !path.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("VM grants must name directories: {}", path.display()),
                ));
            }
            mounts.push(guest_mount(
                GuestMountKind::Virtiofs,
                Some(&format!("cdm-{kind}-{index}")),
                path,
                read_only,
            ));
        }
    }
    let mut denies = Vec::new();
    for (index, rule) in access.deny_write_rules.iter().enumerate() {
        for (variant, path) in rule
            .paths()
            .filter(|path| path_is_exposed(path, access) && !access.denies_read(path))
            .enumerate()
        {
            if rule.kind == crate::access::DeniedPathKind::Missing {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "VM cannot safely protect missing path {} beneath a writable export without mutating the host; create the protected path on the trusted host or narrow the writable grant",
                        path.display()
                    ),
                ));
            }
            let tag = format!("cdm-deny-write-{index}-{variant}");
            if rule.kind == crate::access::DeniedPathKind::Directory {
                mounts.push(guest_mount(
                    GuestMountKind::Virtiofs,
                    Some(&tag),
                    path,
                    true,
                ));
            } else {
                let hidden = std::path::PathBuf::from(format!("/cdm-grants/{tag}"));
                mounts.push(guest_mount(
                    GuestMountKind::Virtiofs,
                    Some(&tag),
                    &hidden,
                    true,
                ));
                mounts.push(guest_mount(
                    GuestMountKind::Bind,
                    Some(
                        &hidden
                            .join(path.file_name().unwrap_or_default())
                            .to_string_lossy(),
                    ),
                    path,
                    true,
                ));
            }
        }
    }
    for mount in &mounts {
        if mount.kind != GuestMountKind::Bind {
            ensure_guest_directory(&safe, &mount.target)?;
        }
    }
    for rule in &access.deny_read_rules {
        for path in rule.paths().filter(|path| path_is_exposed(path, access)) {
            if rule.kind == crate::access::DeniedPathKind::Missing {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "VM cannot safely mask missing path {} beneath an exposed export without mutating the host",
                        path.display()
                    ),
                ));
            }
            denies.push(GuestDeny {
                path: path.to_path_buf(),
                kind: if rule.kind == crate::access::DeniedPathKind::Directory {
                    GuestDenyKind::Directory
                } else {
                    GuestDenyKind::File
                },
            });
        }
    }
    denies.sort_by(|left, right| left.path.cmp(&right.path));
    denies.dedup_by(|left, right| left.path == right.path && left.kind == right.kind);
    let plan = GuestPlan {
        schema: 2,
        argv_bytes: cfg
            .command
            .iter()
            .map(|argument| argument.as_bytes().to_vec())
            .collect(),
        fake_env: env,
        cwd: &cfg.work_dir,
        uid: guest_uid,
        gid: guest_gid,
        mounts,
        denies,
    };
    let bytes = serde_json::to_vec(&plan).map_err(io::Error::other)?;
    safe.write_file(Path::new(GUEST_PLAN.trim_start_matches('/')), &bytes, 0o400)
}

pub(super) fn guest_identity_for(host_uid: u32, host_gid: u32) -> (u32, u32) {
    const UNPRIVILEGED_GUEST_ID: u32 = 65_534;
    (
        if host_uid == 0 {
            UNPRIVILEGED_GUEST_ID
        } else {
            host_uid
        },
        if host_gid == 0 {
            UNPRIVILEGED_GUEST_ID
        } else {
            host_gid
        },
    )
}

fn guest_mount(
    kind: GuestMountKind,
    source: Option<&str>,
    target: impl AsRef<Path>,
    read_only: bool,
) -> GuestMount {
    GuestMount {
        kind,
        source: source.map(str::to_string),
        target: target.as_ref().to_path_buf(),
        read_only,
    }
}

fn ensure_guest_directory(safe: &SafeRoot, absolute: &Path) -> io::Result<()> {
    let relative = absolute.strip_prefix("/").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "guest mount target must be absolute: {}",
                absolute.display()
            ),
        )
    })?;
    safe.ensure_directory(relative)
}
