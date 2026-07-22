//! macOS sandbox implementation using Apple Seatbelt.

use crate::sandbox::SandboxConfig;
use std::fs;
use std::io;
use std::path::PathBuf;
#[cfg(test)]
use std::process::Command;

/// Runs a command in a Seatbelt sandbox on macOS.
pub fn run_darwin(cfg: SandboxConfig) -> io::Result<crate::process::ChildStatus> {
    if cfg.command.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no command specified",
        ));
    }

    // Generate SBPL profile
    let profile = generate_sbpl_profile(&cfg)?;

    // Write profile to temp file
    let profile_path = write_temp_profile(&profile, &cfg.runtime_dir)?;

    if cfg.debug {
        eprintln!("[cdm] seatbelt profile:\n{}", profile);
    }

    // Build sandbox-exec command
    let sandbox_exec = crate::trusted_exec::fixed(
        std::path::Path::new("/usr/bin/sandbox-exec"),
        "macOS sandbox-exec",
    )?;
    let mut cmd = sandbox_exec.command()?;
    cmd.arg("-f").arg(&profile_path);

    // Add command and args
    cmd.arg(&cfg.command[0]);
    for arg in &cfg.command[1..] {
        cmd.arg(arg);
    }

    // Set environment
    let env = cfg.build_env();
    cmd.env_clear();
    for (key, value) in env {
        cmd.env(key, value);
    }

    cmd.current_dir(&cfg.resolved_access()?.work_dir);

    if cfg.debug {
        eprintln!(
            "[cdm] exec: sandbox-exec -f {} <{} argv entries>",
            profile_path.display(),
            cfg.command.len()
        );
    }

    let status = crate::process::run(&mut cmd)?;

    if cfg.debug {
        eprintln!("[cdm] child exited with code {}", status.exit_code);
    }

    Ok(status)
}

/// Generates an SBPL profile for the sandbox.
///
/// Compatibility mode allows macOS facilities by default and subtracts file
/// writes. Secure mode starts from `deny default` and restores only the small
/// process/IPC baseline and the resolved filesystem/network policy.
fn generate_sbpl_profile(cfg: &SandboxConfig) -> io::Result<String> {
    let access = cfg.resolved_access()?;
    // Proxy-only networking also needs the narrow Mach/XPC baseline; a broad
    // compatibility baseline could otherwise expose network-capable deputies.
    let deny_first = cfg.secure
        || access.host == crate::access::HostAccess::Isolated
        || cfg.network.is_proxied();
    let mut profile = String::from("(version 1)\n");
    if deny_first {
        profile.push_str("(deny default)\n\n");
        profile.push_str(SECURE_RUNTIME_BASELINE);
    } else {
        profile.push_str("(allow default)\n\n");
    }

    // Writes are denied globally and restored only for the workspace mode,
    // temporary storage, and deliberate RW grants.
    if !deny_first {
        profile.push_str("(deny file-write* (subpath \"/\"))\n\n");
    }
    profile.push_str("(allow file-write* (subpath \"/dev\"))\n");
    push_sbpl_path_variants(
        &mut profile,
        "allow file-write*",
        "subpath",
        &cfg.runtime_dir,
    );
    if access.workspace == crate::access::WorkspaceAccess::ReadWrite {
        push_sbpl_path_variants(
            &mut profile,
            "allow file-write*",
            "subpath",
            &access.work_dir,
        );
    }
    for path in &access.allow_rw {
        push_sbpl_path_variants(
            &mut profile,
            "allow file-write*",
            path_filter(access, path),
            path,
        );
    }

    profile.push('\n');

    // Isolation is an allowlist for file contents. Metadata remains visible so
    // dynamic loaders and path lookup continue to function.
    if access.host == crate::access::HostAccess::Isolated {
        for path in access
            .runtime_ro
            .iter()
            .chain(std::iter::once(&access.work_dir))
            .chain(access.allow_ro.iter())
            .chain(access.allow_rw.iter())
        {
            push_sbpl_path_variants(
                &mut profile,
                "allow file-read*",
                path_filter(access, path),
                path,
            );
        }
        push_sbpl_path_variants(
            &mut profile,
            "allow file-read*",
            "subpath",
            &cfg.runtime_dir,
        );
        profile.push('\n');
    } else if deny_first {
        profile.push_str("(allow file-read*)\n\n");
    }

    // Hard denials are emitted last and cannot be reopened by broad grants.
    for rule in &access.deny_read_rules {
        push_denial_rule(&mut profile, "deny file-read*", rule);
    }
    for rule in &access.deny_write_rules {
        push_denial_rule(&mut profile, "deny file-write*", rule);
        for path in rule.paths() {
            push_unlink_anchors(&mut profile, path);
        }
    }

    profile.push('\n');

    // --- Network ---
    match cfg.network {
        crate::network::NetworkPolicy::Disabled => profile.push_str("(deny network*)\n"),
        crate::network::NetworkPolicy::Direct if deny_first => {
            profile.push_str("(allow network*)\n")
        }
        crate::network::NetworkPolicy::Direct => {}
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

/// Fence-compatible macOS capability baseline. In particular, this does not
/// permit `mach-register` or `mach-issue-extension`; only the named lookups
/// required by ordinary command-line programs are restored.
pub(super) const SECURE_RUNTIME_BASELINE: &str = r#"; Process lifecycle
(allow process-exec)
(allow process-fork)
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))
(allow mach-priv-task-port (target same-sandbox))

; Preferences and the small Mach/XPC lookup baseline used by Fence
(allow user-preference-read)
(allow mach-lookup
  (global-name "com.apple.audio.systemsoundserver")
  (global-name "com.apple.distributed_notifications@Uv3")
  (global-name "com.apple.FontObjectsServer")
  (global-name "com.apple.fonts")
  (global-name "com.apple.logd")
  (global-name "com.apple.lsd.mapdb")
  (global-name "com.apple.PowerManagement.control")
  (global-name "com.apple.system.logger")
  (global-name "com.apple.system.notification_center")
  (global-name "com.apple.trustd.agent")
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.bsd.dirhelper")
  (global-name "com.apple.securityd.xpc")
  (global-name "com.apple.coreservices.launchservicesd")
  (global-name "com.apple.FSEvents")
  (global-name "com.apple.fseventsd")
  (global-name "com.apple.SystemConfiguration.configd")
  (global-name "com.apple.SystemConfiguration.DNSConfiguration")
  (global-name "com.apple.SecurityServer"))

; Runtime facilities needed by normal CLI processes
(allow ipc-posix-shm)
(allow ipc-posix-sem)
(allow iokit-open
  (iokit-registry-entry-class "IOSurfaceRootUserClient")
  (iokit-registry-entry-class "RootDomainUserClient")
  (iokit-user-client-class "IOSurfaceSendRight"))
(allow iokit-get-properties)
(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))
(allow sysctl-read)
(allow distributed-notification-post)
(allow file-read-metadata)
(allow file-read-data (literal "/"))
(allow file-ioctl (regex #"^/dev/tty"))
(allow file-read-data file-write-data (regex #"^/dev/tty"))

"#;

fn path_filter(
    access: &crate::access::ResolvedAccessPolicy,
    path: &std::path::Path,
) -> &'static str {
    if access.kind(path) == Some(crate::access::DeniedPathKind::Directory) {
        "subpath"
    } else {
        "literal"
    }
}

fn push_sbpl_path(profile: &mut String, operation: &str, filter: &str, path: &std::path::Path) {
    let escaped = path
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    profile.push_str(&format!("({operation} ({filter} \"{escaped}\"))\n"));
}

fn push_sbpl_path_variants(
    profile: &mut String,
    operation: &str,
    filter: &str,
    path: &std::path::Path,
) {
    push_sbpl_path(profile, operation, filter, path);
    if let Some(alias) = macos_path_alias(path) {
        push_sbpl_path(profile, operation, filter, &alias);
    }
}

fn push_denial_rule(profile: &mut String, operation: &str, rule: &crate::access::ResolvedDenyRule) {
    let filter = match rule.kind {
        crate::access::DeniedPathKind::Directory => "subpath",
        crate::access::DeniedPathKind::Missing
        | crate::access::DeniedPathKind::File
        | crate::access::DeniedPathKind::Other => "literal",
    };
    for path in rule.paths() {
        push_sbpl_path(profile, operation, filter, path);
        if let Some(alias) = macos_path_alias(path) {
            push_sbpl_path(profile, operation, filter, &alias);
        }
    }
}

/// Pin the denied object and every pathname ancestor. Seatbelt path filters
/// follow the current pathname, so denying only the leaf would let a process
/// with a writable parent rename an ancestor and reopen the same object under
/// a different name.
fn push_unlink_anchors(profile: &mut String, path: &std::path::Path) {
    let mut variants = std::collections::BTreeSet::new();
    variants.insert(path.to_path_buf());
    if let Some(alias) = macos_path_alias(path) {
        variants.insert(alias);
    }
    for variant in variants {
        for ancestor in variant.ancestors() {
            push_sbpl_path(profile, "deny file-write-unlink", "literal", ancestor);
        }
    }
}

fn macos_path_alias(path: &std::path::Path) -> Option<PathBuf> {
    for (physical_root, public_root) in [
        ("/private/tmp", "/tmp"),
        ("/private/var", "/var"),
        ("/private/etc", "/etc"),
    ] {
        if let Ok(suffix) = path.strip_prefix(physical_root) {
            return Some(PathBuf::from(public_root).join(suffix));
        }
        if let Ok(suffix) = path.strip_prefix(public_root) {
            return Some(PathBuf::from(physical_root).join(suffix));
        }
    }
    None
}

/// Writes the SBPL profile to a temporary file.
fn write_temp_profile(profile: &str, temp_dir: &std::path::Path) -> io::Result<PathBuf> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let path = temp_dir.join(format!("cdm-seatbelt-{}.sb", timestamp));
    fs::write(&path, profile)?;
    Ok(path)
}

#[cfg(test)]
mod tests;
