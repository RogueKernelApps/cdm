//! VM sandbox implementation using libkrun.
//!
//! Runs the command inside a lightweight microVM. CDM disables libkrun's
//! implicit socket policy and explicitly enables only INET/INET6 TSI when the
//! resolved network policy permits it; AF_UNIX impersonation is never enabled.
//!
//! Environment variables and working directory are written to
//! `/.krun_config.json` in the rootfs, which libkrun's built-in init
//! reads natively — no VirtioFS-shared env file needed.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use super::rootfs;
use super::safe_root::{require_real_directory, set_private_directory_permissions, SafeRoot};
use super::SandboxConfig;

mod guest_plan;
mod launcher;

use launcher::VirtioFsShare;

pub(crate) use launcher::run_launcher;

#[cfg(test)]
use guest_plan::guest_identity_for;
#[cfg(all(test, target_os = "linux"))]
use launcher::build_linux_launcher_arguments;
#[cfg(all(test, target_os = "macos"))]
use launcher::launcher_profile;
#[cfg(test)]
use launcher::{
    explicit_tsi_features, krun_check, posix_spawn_wait, to_cstring, to_ptr_array,
    validate_launcher_plan, write_launcher_plan, LauncherPlan,
};

/// VirtioFS tags for shared directories.
const TAG_STAGE: &str = "cdm-stage";
const TAG_CERTS: &str = "cdm-certs";
const TAG_WORKDIR: &str = "cdm-workdir";

const GUEST_INIT: &str = "/cdm-guest-init";
const GUEST_PLAN: &str = "/cdm-plan.json";
#[cfg(test)]
const LEGACY_INIT_SCRIPT: &str = "/cdm-init";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Runs a command inside a libkrun microVM.
pub fn run_vm(cfg: SandboxConfig) -> io::Result<super::SandboxRun> {
    if cfg.command.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no command specified",
        ));
    }

    run_vm_host(cfg)
}

fn run_vm_host(cfg: SandboxConfig) -> io::Result<super::SandboxRun> {
    let base_rootfs = rootfs::resolve(&cfg)?;
    let rootfs = EphemeralRootfs::clone_from(&base_rootfs, &cfg.runtime_dir)?;
    let rootfs_path = rootfs.path();
    prepare_rootfs(rootfs_path)?;
    let mut env = cfg.build_env_vm();
    if cfg.network.is_proxied() {
        install_guest_ca(rootfs_path, &cfg, &mut env)?;
    }
    let shares = build_virtiofs_shares(&cfg)?;
    write_guest_plan(rootfs_path, &cfg, &env)?;
    write_krun_config(rootfs_path, &HashMap::new())?;
    launcher::launch(&cfg, rootfs_path, shares)
}

fn install_guest_ca(
    rootfs: &Path,
    cfg: &SandboxConfig,
    env: &mut HashMap<String, String>,
) -> io::Result<()> {
    let cert = cfg
        .ca_cert_path
        .as_ref()
        .ok_or_else(|| io::Error::other("proxied VM has no CA certificate"))?;
    let bundle = cfg
        .ca_bundle_path
        .as_ref()
        .ok_or_else(|| io::Error::other("proxied VM has no CA bundle"))?;
    let safe = SafeRoot::open(rootfs)?;
    safe.copy_file(cert, Path::new("etc/cdm/ca.pem"), 0o444)?;
    safe.copy_file(bundle, Path::new("etc/cdm/ca-bundle.pem"), 0o444)?;
    env.insert("NODE_EXTRA_CA_CERTS".into(), "/etc/cdm/ca.pem".into());
    for name in [
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "CODEX_CA_CERTIFICATE",
    ] {
        env.insert(name.into(), "/etc/cdm/ca-bundle.pem".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Disposable rootfs
// ---------------------------------------------------------------------------

struct EphemeralRootfs {
    path: std::path::PathBuf,
}

impl EphemeralRootfs {
    fn clone_from(base: &Path, runtime_dir: &Path) -> io::Result<Self> {
        require_real_directory(base, "base rootfs")?;
        require_real_directory(runtime_dir, "private runtime directory")?;
        let path = runtime_dir.join(format!(
            "cdm-rootfs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir(&path)?;
        set_private_directory_permissions(&path)?;

        #[cfg(target_os = "macos")]
        let copier = crate::trusted_exec::fixed(Path::new("/bin/cp"), "system cp")?;
        #[cfg(target_os = "linux")]
        let copier = crate::trusted_exec::fixed(Path::new("/usr/bin/cp"), "system cp")?;
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let copier = crate::trusted_exec::fixed(Path::new("/bin/cp"), "system cp")?;
        let mut command = copier.command()?;
        crate::trusted_exec::sanitize_host_environment(&mut command);
        #[cfg(target_os = "macos")]
        command.args(["-cR"]);
        #[cfg(target_os = "linux")]
        command.args(["-a", "--reflink=auto"]);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        command.args(["-R"]);
        let status = command.arg(base.join(".")).arg(&path).status()?;
        if !status.success() {
            let _ = std::fs::remove_dir_all(&path);
            return Err(io::Error::other(format!(
                "failed to clone VM rootfs from {}",
                base.display()
            )));
        }
        set_private_directory_permissions(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for EphemeralRootfs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Environment & init script
// ---------------------------------------------------------------------------

fn prepare_rootfs(rootfs: &Path) -> io::Result<()> {
    #[cfg(cdm_guest_init_embedded)]
    {
        let bytes = include_bytes!(env!("CDM_GUEST_INIT_EMBEDDED_PATH"));
        let provenance = include_bytes!(env!("CDM_GUEST_INIT_PROVENANCE_PATH"));
        let safe = SafeRoot::open(rootfs)?;
        safe.write_file(Path::new(GUEST_INIT.trim_start_matches('/')), bytes, 0o555)?;
        safe.write_file(
            Path::new("cdm-guest-init.provenance.json"),
            provenance,
            0o444,
        )
    }
    #[cfg(not(cdm_guest_init_embedded))]
    {
        let _ = rootfs;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this VM build has no verified static guest init; package with CDM_GUEST_INIT_BIN, CDM_GUEST_INIT_SHA256, and CDM_GUEST_INIT_PROVENANCE",
        ))
    }
}

#[cfg(test)]
fn prepare_rootfs_from(rootfs: &Path, bundled: &Path) -> io::Result<()> {
    let musl_name = match std::env::consts::ARCH {
        "aarch64" => "ld-musl-aarch64.so.1",
        "x86_64" => "ld-musl-x86_64.so.1",
        architecture => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported VM architecture: {architecture}"),
            ));
        }
    };

    let safe = SafeRoot::open(rootfs)?;

    // Copy busybox and create applet symlinks in /cdm-bin/.
    // Busybox uses argv[0] to determine which applet to run.
    let bb_src = bundled.join("bin/busybox");
    if !bb_src.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("bundled BusyBox is missing: {}", bb_src.display()),
        ));
    }
    safe.copy_file(&bb_src, Path::new("cdm-busybox"), 0o755)
        .map_err(|error| vm_rootfs_error("install BusyBox", error))?;
    safe.ensure_directory(Path::new("cdm-bin"))
        .map_err(|error| vm_rootfs_error("create tool directory", error))?;
    for applet in ["mount", "sh", "mkdir", "chown", "chmod"] {
        safe.replace_with_symlink(
            &Path::new("cdm-bin").join(applet),
            std::ffi::OsStr::new("../cdm-busybox"),
        )
        .map_err(|error| vm_rootfs_error("install BusyBox applet", error))?;
    }

    // Copy musl dynamic linker (busybox needs it, glibc-based rootfs won't have it).
    // The ELF interpreter path is target-specific and must match BusyBox.
    // Some distros (Fedora) have /lib as a symlink to /usr/lib — follow it.
    let musl_src = bundled.join("lib").join(musl_name);
    if !musl_src.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("bundled musl linker is missing: {}", musl_src.display()),
        ));
    }
    let lib_dir = safe
        .contained_directory_target(Path::new("lib"))
        .map_err(|error| vm_rootfs_error("resolve guest library directory", error))?;
    safe.copy_file(&musl_src, &lib_dir.join(musl_name), 0o755)
        .map_err(|error| vm_rootfs_error("install musl linker", error))?;

    Ok(())
}

#[cfg(test)]
fn vm_rootfs_error(operation: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{operation}: {error}"))
}

#[cfg(test)]
fn prepare_guest_user(rootfs: &Path) -> io::Result<()> {
    let safe = SafeRoot::open(rootfs)?;
    let passwd_path = Path::new("etc/passwd");
    let existing = safe.read_file(passwd_path)?.unwrap_or_default();
    let mut passwd = existing
        .lines()
        .filter(|line| !line.starts_with("cdm:"))
        .collect::<Vec<_>>()
        .join("\n");
    if !passwd.ends_with('\n') && !passwd.is_empty() {
        passwd.push('\n');
    }
    passwd.push_str(&format!(
        "cdm:x:{}:{}:CDM sandbox user:/tmp:/bin/sh\n",
        unsafe { libc::getuid() },
        unsafe { libc::getgid() }
    ));
    safe.write_file(passwd_path, passwd.as_bytes(), 0o644)
}

/// Writes `/.krun_config.json` into the rootfs so libkrun's built-in init
/// sets up environment variables and working directory natively.
///
/// Format: `{"Env": ["KEY=val", ...], "WorkingDir": "/path"}`
fn write_krun_config(rootfs: &Path, env: &HashMap<String, String>) -> io::Result<()> {
    let mut buf = String::from("{\"Env\":[");
    let mut first = true;
    for (key, value) in env {
        if !first {
            buf.push(',');
        }
        first = false;
        buf.push('"');
        json_escape_into(&mut buf, key);
        buf.push('=');
        json_escape_into(&mut buf, value);
        buf.push('"');
    }
    // WorkingDir set to "/" — our init script cd's to the real workdir
    // after mounting VirtioFS shares (libkrun's init can't cd before mount).
    buf.push_str("],\"WorkingDir\":\"/\"}");

    SafeRoot::open(rootfs)?.write_file(Path::new(".krun_config.json"), buf.as_bytes(), 0o600)
}

/// Appends a JSON-escaped version of `s` into `buf`.
/// Handles `"`, `\`, and control characters (U+0000..U+001F).
fn json_escape_into(buf: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '"' => buf.push_str("\\\""),
            '\\' => buf.push_str("\\\\"),
            '\n' => buf.push_str("\\n"),
            '\r' => buf.push_str("\\r"),
            '\t' => buf.push_str("\\t"),
            c if c.is_control() => {
                // \u00XX for other control characters
                let code = c as u32;
                buf.push_str(&format!("\\u{:04x}", code));
            }
            c => buf.push(c),
        }
    }
}

fn write_guest_plan(
    rootfs: &Path,
    cfg: &SandboxConfig,
    env: &HashMap<String, String>,
) -> io::Result<()> {
    guest_plan::write(rootfs, cfg, env)
}

/// Writes the guest init script into the rootfs.
///
/// The init script mounts proc/sys/dev, VirtioFS shares (workdir, stage,
/// certs), and overlays an inaccessible inode over denied paths. Environment
/// variables and WorkingDir are handled by libkrun via `/.krun_config.json`.
#[cfg(test)]
fn write_init_script(rootfs: &Path, cfg: &SandboxConfig) -> io::Result<()> {
    let workdir = shell_quote(&cfg.work_dir.to_string_lossy());
    let runtime_dir = shell_quote(&cfg.runtime_dir.to_string_lossy());
    let runtime_uid = unsafe { libc::getuid() };
    let runtime_gid = unsafe { libc::getgid() };
    let access = cfg.resolved_access()?;
    let command = cfg
        .command
        .iter()
        .map(|arg| shell_quote(&arg.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ");

    // Build deny-path mount commands, embedded directly in the script.
    let mut deny_lines = String::new();
    for rule in &access.deny_read_rules {
        for path in rule.paths() {
            let p = shell_quote(&path.to_string_lossy());
            deny_lines.push_str(&format!(
                "[ -f {p} ] && {{ mount --bind /cdm-denied {p} 2>/dev/null || /cdm-bin/mount --bind /cdm-denied {p} 2>/dev/null; }}\n"
            ));
        }
    }
    let mut deny_write_lines = String::new();
    for (index, rule) in access.deny_write_rules.iter().enumerate() {
        if rule.kind == crate::access::DeniedPathKind::Missing {
            continue;
        }
        for (variant, path) in rule.paths().enumerate() {
            if path_is_exposed(path, access) {
                append_grant_mount(
                    &mut deny_write_lines,
                    path,
                    "deny-write",
                    index * 2 + variant,
                    true,
                );
            }
        }
    }

    let stage_mount = if cfg.file_stage.is_some() {
        format!(
            "mount -t virtiofs -o ro {TAG_STAGE} {} 2>/dev/null || /cdm-bin/mount -t virtiofs -o ro {TAG_STAGE} {} 2>/dev/null || true\ngrep -Fq '{TAG_STAGE} ' /proc/mounts || exit 70",
            super::GUEST_STAGE_MOUNT,
            super::GUEST_STAGE_MOUNT,
        )
    } else {
        String::new()
    };
    let cert_mount = if cfg.ca_cert_path.is_some() {
        format!(
            "mount -t virtiofs -o ro {TAG_CERTS} {} 2>/dev/null || /cdm-bin/mount -t virtiofs -o ro {TAG_CERTS} {} 2>/dev/null || true\ngrep -Fq '{TAG_CERTS} ' /proc/mounts || exit 70",
            super::GUEST_CERTS_MOUNT,
            super::GUEST_CERTS_MOUNT,
        )
    } else {
        String::new()
    };

    let workspace_mount_options = if access.workspace == crate::access::WorkspaceAccess::ReadOnly {
        "-o ro "
    } else {
        ""
    };
    let mut grant_mounts = String::new();
    for (index, path) in access.allow_ro.iter().enumerate() {
        if access.denies_read(path) {
            continue;
        }
        append_grant_mount(&mut grant_mounts, path, "allow-ro", index, true);
    }
    for (index, path) in access.allow_rw.iter().enumerate() {
        if access.denies_read(path) {
            continue;
        }
        append_grant_mount(&mut grant_mounts, path, "allow-rw", index, false);
    }

    let command_script = format!("#!/bin/sh\nexec {command}\n");
    let safe = SafeRoot::open(rootfs)?;
    safe.write_file(Path::new("cdm-command"), command_script.as_bytes(), 0o755)?;
    safe.write_file(Path::new("cdm-denied"), &[], 0o000)?;

    let script = format!(
        r#"#!/bin/sh
# CDM VM init — mounts VirtioFS shares, denies sensitive reads.
# Env vars and WorkingDir are set by libkrun via /.krun_config.json.
DBG={debug}
[ "$DBG" = "1" ] && set -x

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null

# macOS canonicalizes /tmp paths through /private/tmp. Preserve both spellings
# inside the Linux guest so absolute CLI grants still appear where requested.
mkdir -p /private
[ -e /private/tmp ] || ln -s /tmp /private/tmp

# CDM owns the child's private temporary directory in every adapter.
/cdm-bin/mkdir -p {runtime_dir}
/cdm-bin/chown {runtime_uid}:{runtime_gid} {runtime_dir}
/cdm-bin/chmod 700 {runtime_dir}

# Mount working directory and CDM shares
mkdir -p {stage} {certs} {workdir}
mount -t virtiofs {workspace_mount_options}{tag_workdir} {workdir} 2>/dev/null || /cdm-bin/mount -t virtiofs {workspace_mount_options}{tag_workdir} {workdir} 2>/dev/null || true
grep -Fq "{tag_workdir} " /proc/mounts || exit 71
{stage_mount}
{cert_mount}
{grant_mounts}

# Make protected paths host-enforced read-only, then hide secret contents.
{deny_write_lines}
# Deny reads and writes to sensitive files with an inaccessible empty inode.
{deny_lines}
[ "$DBG" = "1" ] && cat /proc/mounts | grep virtiofs >&2

cd {workdir}
exec /bin/su -m -s /cdm-command cdm
"#,
        debug = if cfg.debug { "1" } else { "0" },
        stage = super::GUEST_STAGE_MOUNT,
        certs = super::GUEST_CERTS_MOUNT,
        workdir = workdir,
        runtime_dir = runtime_dir,
        runtime_uid = runtime_uid,
        runtime_gid = runtime_gid,
        tag_workdir = TAG_WORKDIR,
        workspace_mount_options = workspace_mount_options,
        stage_mount = stage_mount,
        cert_mount = cert_mount,
        grant_mounts = grant_mounts,
        deny_lines = deny_lines,
        deny_write_lines = deny_write_lines,
    );

    safe.write_file(
        Path::new(LEGACY_INIT_SCRIPT.trim_start_matches('/')),
        script.as_bytes(),
        0o755,
    )
}

#[cfg(test)]
fn append_grant_mount(script: &mut String, path: &Path, kind: &str, index: usize, read_only: bool) {
    let tag = format!("cdm-{kind}-{index}");
    let mount_options = if read_only { "-o ro " } else { "" };
    if path.is_dir() {
        let guest = shell_quote(&path.to_string_lossy());
        script.push_str(&format!(
            "mkdir -p {guest}\nmount -t virtiofs {mount_options}{tag} {guest} 2>/dev/null || /cdm-bin/mount -t virtiofs {mount_options}{tag} {guest} 2>/dev/null || exit 76\n"
        ));
        return;
    }

    // VirtioFS exports directories. Mount a file's parent at a root-only
    // staging point, then bind only the requested file into its host path.
    let hidden = format!("/cdm-grants/{tag}");
    let hidden = shell_quote(&hidden);
    let guest = shell_quote(&path.to_string_lossy());
    let parent = shell_quote(&path.parent().unwrap_or(Path::new("/")).to_string_lossy());
    let source = shell_quote(&format!(
        "/cdm-grants/{tag}/{}",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    script.push_str(&format!(
        "mkdir -p /cdm-grants {hidden} {parent}\nchmod 700 /cdm-grants\nmount -t virtiofs {mount_options}{tag} {hidden} 2>/dev/null || /cdm-bin/mount -t virtiofs {mount_options}{tag} {hidden} 2>/dev/null || exit 76\n[ -e {guest} ] || touch {guest}\nmount --bind {source} {guest} 2>/dev/null || /cdm-bin/mount --bind {source} {guest} 2>/dev/null || exit 76\n"
    ));
}

#[cfg(test)]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

// ---------------------------------------------------------------------------
// FFI utilities
// ---------------------------------------------------------------------------

fn build_virtiofs_shares(cfg: &SandboxConfig) -> io::Result<Vec<VirtioFsShare>> {
    let access = cfg.resolved_access()?;
    for path in access.allow_ro.iter().chain(access.allow_rw.iter()) {
        if access.kind(path) == Some(crate::access::DeniedPathKind::File)
            && !path.starts_with(&access.work_dir)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "VM grants must name directories; exporting single file {} would expose its parent directory to the VMM",
                    path.display()
                ),
            ));
        }
    }
    let mut shares = Vec::new();
    shares.push(VirtioFsShare {
        tag: TAG_WORKDIR.to_string(),
        host_path: access.work_dir.to_string_lossy().to_string(),
        read_only: access.workspace == crate::access::WorkspaceAccess::ReadOnly,
    });

    if let Some(ref stage) = cfg.file_stage {
        shares.push(VirtioFsShare {
            tag: TAG_STAGE.to_string(),
            host_path: stage.temp_dir_path().to_string_lossy().to_string(),
            read_only: true,
        });
    }

    if let Some(ref cert_path) = cfg.ca_cert_path {
        if let Some(cert_dir) = cert_path.parent() {
            shares.push(VirtioFsShare {
                tag: TAG_CERTS.to_string(),
                host_path: cert_dir.to_string_lossy().to_string(),
                read_only: true,
            });
        }
    }

    for (index, path) in access.allow_ro.iter().enumerate() {
        if access.denies_read(path) {
            continue;
        }
        shares.push(VirtioFsShare {
            tag: format!("cdm-allow-ro-{index}"),
            host_path: path.to_string_lossy().to_string(),
            read_only: true,
        });
    }
    for (index, path) in access.allow_rw.iter().enumerate() {
        if access.denies_read(path) {
            continue;
        }
        shares.push(VirtioFsShare {
            tag: format!("cdm-allow-rw-{index}"),
            host_path: path.to_string_lossy().to_string(),
            read_only: false,
        });
    }
    for (index, rule) in access.deny_write_rules.iter().enumerate() {
        if rule.kind == crate::access::DeniedPathKind::Missing {
            continue;
        }
        for (variant, path) in rule
            .paths()
            .filter(|path| path_is_exposed(path, access) && !access.denies_read(path))
            .enumerate()
        {
            shares.push(VirtioFsShare {
                tag: format!("cdm-deny-write-{index}-{variant}"),
                host_path: virtiofs_source(path, rule.kind)
                    .to_string_lossy()
                    .to_string(),
                read_only: true,
            });
        }
    }

    Ok(shares)
}

fn virtiofs_source(path: &Path, kind: crate::access::DeniedPathKind) -> &Path {
    if kind == crate::access::DeniedPathKind::Directory {
        path
    } else {
        path.parent().unwrap_or(Path::new("/"))
    }
}

fn path_is_exposed(path: &Path, access: &crate::access::ResolvedAccessPolicy) -> bool {
    path.starts_with(&access.work_dir)
        || access
            .allow_ro
            .iter()
            .any(|granted| path == granted || path.starts_with(granted))
        || access
            .allow_rw
            .iter()
            .any(|granted| path == granted || path.starts_with(granted))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
