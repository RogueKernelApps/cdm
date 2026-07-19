//! Sandbox execution orchestration and platform dispatch.
//!
//! Platform support:
//!   - macOS: Apple Seatbelt (sandbox-exec) — kernel-enforced sandbox profiles
//!   - Linux: Bubblewrap (bwrap) — namespace isolation
//!   - VM:    libkrun microVM + TSI — hardware virtualization (--vm flag)

#[cfg(target_os = "macos")]
pub mod darwin;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(feature = "vm")]
pub mod rootfs;
#[cfg(feature = "vm")]
mod safe_root;
#[cfg(feature = "vm")]
pub mod vm;

use crate::access::{AccessPolicy, ResolvedAccessPolicy};
use crate::config::{CdmConfig, LoadedConfig};
use crate::network::NetworkPolicy;
use crate::secrets::SecretMapping;
use crate::stage::FileStage;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Guest mount points for VirtioFS shares inside the VM.
#[cfg(feature = "vm")]
pub const GUEST_STAGE_MOUNT: &str = "/mnt/cdm-stage";
#[cfg(feature = "vm")]
pub const GUEST_CERTS_MOUNT: &str = "/mnt/cdm-certs";

const PROXY_ENV_VARS: [&str; 8] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

static SESSION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Sandbox configuration.
pub struct SandboxConfig {
    /// Exact operating-system argv. On Unix this preserves every non-NUL byte;
    /// it must never be joined, reparsed, or converted through UTF-8.
    pub command: Vec<OsString>,
    pub work_dir: PathBuf,
    pub home_dir: PathBuf,
    /// Private writable temporary storage exposed to the wrapped command.
    pub runtime_dir: PathBuf,
    pub denied_read_paths: Vec<PathBuf>,
    pub access: AccessPolicy,
    resolved_access: Option<ResolvedAccessPolicy>,
    pub network: NetworkPolicy,
    pub proxy_port: u16,
    pub secrets: SecretMapping,
    pub file_stage: Option<FileStage>,
    pub debug: bool,
    /// Use the deny-first macOS Seatbelt baseline instead of compatibility mode.
    pub secure: bool,
    /// Protect discovered secrets and credential files through CDM's proxy.
    pub scramble: bool,
    /// Extra env vars to inject (e.g. .env entries, config file redirects).
    pub injected_env: HashMap<String, String>,
    /// Path to the CDM CA certificate PEM (for NODE_EXTRA_CA_CERTS, NODE_USE_SYSTEM_CA, etc.).
    pub ca_cert_path: Option<PathBuf>,
    /// Path to a combined CA bundle (system CAs + CDM CA) for SSL_CERT_FILE.
    pub ca_bundle_path: Option<PathBuf>,
    /// Run inside a libkrun microVM instead of host sandbox.
    pub use_vm: bool,
    /// OCI image reference for VM rootfs (e.g. "ubuntu:22.04"). None = bundled Alpine.
    pub vm_image: Option<String>,
    /// Loaded CDM configuration.
    pub config: Arc<CdmConfig>,
}

/// Separates the wrapped command result from adapter teardown. A transport
/// cleanup failure must not erase a completed child's exit or signal identity.
pub struct SandboxRun {
    pub child: io::Result<crate::process::ChildStatus>,
    pub cleanup: io::Result<()>,
}

impl SandboxRun {
    fn completed(status: crate::process::ChildStatus) -> Self {
        Self {
            child: Ok(status),
            cleanup: Ok(()),
        }
    }
}

impl SandboxConfig {
    #[cfg(test)]
    pub fn new(config: Arc<CdmConfig>) -> io::Result<Self> {
        let access = AccessPolicy::new(&config.paths);
        Self::new_with_access(config, access)
    }

    pub fn from_loaded_config(config: LoadedConfig) -> io::Result<Self> {
        let access = AccessPolicy::from_configured_paths(&config.paths);
        Self::new_with_access(config.value, access)
    }

    fn new_with_access(config: Arc<CdmConfig>, access: AccessPolicy) -> io::Result<Self> {
        let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let work_dir = resolve_work_dir(std::env::current_dir(), std::env::var_os("PWD"))?;
        let runtime_dir = prepare_runtime_dir()?;

        let proxy_port = config.proxy.default_port;

        let home = PathBuf::from(&home_dir);

        Ok(SandboxConfig {
            command: Vec::new(),
            work_dir,
            home_dir: home,
            runtime_dir,
            denied_read_paths: Vec::new(),
            access,
            resolved_access: None,
            network: NetworkPolicy::Direct,
            proxy_port,
            secrets: SecretMapping::new(),
            file_stage: None,
            debug: false,
            secure: false,
            scramble: false,
            injected_env: HashMap::new(),
            ca_cert_path: None,
            ca_bundle_path: None,
            use_vm: false,
            vm_image: None,
            config,
        })
    }

    /// Builds the environment for the sandboxed process.
    pub fn build_env(&self) -> HashMap<String, String> {
        self.build_env_from(std::env::vars())
    }

    fn build_env_from(
        &self,
        host_environment: impl IntoIterator<Item = (String, String)>,
    ) -> HashMap<String, String> {
        let host_environment = host_environment.into_iter().collect::<HashMap<_, _>>();
        let mut env = HashMap::new();

        // Passthrough variables (from config)
        for var in &self.config.env.passthrough {
            if let Some(value) = host_environment.get(var) {
                env.insert(var.clone(), value.clone());
            }
        }

        // Copy remaining host env vars, skipping dangerous ones (from config)
        let dangerous_prefixes = &self.config.env.dangerous_prefixes;

        for (key, value) in host_environment {
            if env.contains_key(&key) {
                continue;
            }
            // Proxy configuration is policy owned by CDM. Inheriting a host
            // proxy would make --no-proxy ineffective; inheriting NO_PROXY
            // would bypass CDM's proxy and domain rules.
            if PROXY_ENV_VARS.contains(&key.as_str()) {
                continue;
            }
            if dangerous_prefixes
                .iter()
                .any(|prefix| key.starts_with(prefix))
            {
                continue;
            }
            // Obfuscate secrets in env values
            let obfuscated = self.secrets.obfuscate(&value);
            env.insert(key, obfuscated);
        }

        // CDM markers
        env.insert("CDM".to_string(), "1".to_string());

        // Injected env vars (.env entries, config file redirects).
        // Inserted after host env vars so they override host values.
        for (key, value) in &self.injected_env {
            env.insert(key.clone(), value.clone());
        }

        // Temporary storage is policy-owned. Do not inherit a broader host
        // TMPDIR or allow project .env files to redirect it.
        let runtime_dir = self.runtime_dir.to_string_lossy().to_string();
        for var in ["TMPDIR", "TMP", "TEMP"] {
            env.insert(var.to_string(), runtime_dir.clone());
        }

        // Proxy env vars
        if self.network.is_proxied() {
            let proxy_url = format!("http://127.0.0.1:{}", self.proxy_port);
            for var in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
                env.insert(var.to_string(), proxy_url.clone());
            }
        }

        // CA trust injection for MITM proxy.
        //
        // Multiple mechanisms cover different runtimes:
        //   Node.js:  NODE_EXTRA_CA_CERTS (adds CA to trust store)
        //   Bun:      NODE_USE_SYSTEM_CA=1 (Claude Code runs on Bun)
        //   Node 22+: NODE_OPTIONS --use-system-ca (belt-and-suspenders)
        //   OpenSSL:  SSL_CERT_FILE (combined bundle: system CAs + CDM CA)
        //   Python:   REQUESTS_CA_BUNDLE
        //   curl:     CURL_CA_BUNDLE
        //   Codex:    CODEX_CA_CERTIFICATE
        if let Some(ref ca_path) = self.ca_cert_path {
            env.insert(
                "NODE_EXTRA_CA_CERTS".to_string(),
                ca_path.display().to_string(),
            );
            // Claude Code runs on Bun which needs this standalone env var
            // to load certs from the macOS system keychain.
            env.insert("NODE_USE_SYSTEM_CA".to_string(), "1".to_string());
            // Append --use-system-ca to existing NODE_OPTIONS for Node.js 22.15+.
            let use_system_ca = "--use-system-ca";
            let node_opts = env
                .get("NODE_OPTIONS")
                .map(|existing| {
                    if existing.contains(use_system_ca) {
                        existing.clone()
                    } else {
                        format!("{} {}", existing, use_system_ca)
                    }
                })
                .unwrap_or_else(|| use_system_ca.to_string());
            env.insert("NODE_OPTIONS".to_string(), node_opts);
        }
        if let Some(ref bundle_path) = self.ca_bundle_path {
            let bundle = bundle_path.display().to_string();
            for var in [
                "SSL_CERT_FILE",
                "REQUESTS_CA_BUNDLE",
                "CURL_CA_BUNDLE",
                "CODEX_CA_CERTIFICATE",
            ] {
                env.insert(var.to_string(), bundle.clone());
            }
        }

        env
    }

    /// Freeze the complete filesystem policy after every invocation mutation.
    /// Adapters consume this immutable snapshot and never inspect live host
    /// path state or independently resolve policy.
    pub fn freeze_access(&mut self) -> io::Result<&ResolvedAccessPolicy> {
        if self.resolved_access.is_none() {
            self.resolved_access = Some(self.access.resolve(
                &self.work_dir,
                &self.home_dir,
                &self.denied_read_paths,
                &self.command,
            )?);
        }
        Ok(self
            .resolved_access
            .as_ref()
            .expect("snapshot was just set"))
    }

    pub fn resolved_access(&self) -> io::Result<&ResolvedAccessPolicy> {
        self.resolved_access.as_ref().ok_or_else(|| {
            io::Error::other("filesystem policy was not frozen before sandbox dispatch")
        })
    }

    /// Builds environment for VM mode. Calls build_env() then remaps
    /// host temp paths to guest VirtioFS mount points.
    #[cfg(feature = "vm")]
    pub fn build_env_vm(&self) -> HashMap<String, String> {
        let mut env = self.build_env();

        // Remap staged file paths: host staging dir → /mnt/cdm-stage
        if let Some(ref stage) = self.file_stage {
            let host_prefix = stage.temp_dir_path().to_string_lossy().to_string();
            for value in env.values_mut() {
                if value.starts_with(&host_prefix) {
                    *value = value.replacen(&host_prefix, GUEST_STAGE_MOUNT, 1);
                }
            }
        }

        // Remap CA cert path
        if let Some(ref cert_path) = self.ca_cert_path {
            let host_cert = cert_path.to_string_lossy().to_string();
            if let Some(filename) = cert_path.file_name() {
                let guest_cert = format!("{}/{}", GUEST_CERTS_MOUNT, filename.to_string_lossy());
                for value in env.values_mut() {
                    if *value == host_cert {
                        *value = guest_cert.clone();
                    }
                }
            }
        }

        // Remap CA bundle path
        if let Some(ref bundle_path) = self.ca_bundle_path {
            let host_bundle = bundle_path.to_string_lossy().to_string();
            if let Some(filename) = bundle_path.file_name() {
                let guest_bundle = format!("{}/{}", GUEST_CERTS_MOUNT, filename.to_string_lossy());
                for value in env.values_mut() {
                    if *value == host_bundle {
                        *value = guest_bundle.clone();
                    }
                }
            }
        }

        env
    }
}

pub(crate) fn prepare_runtime_dir() -> io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let base = trusted_user_temp_dir()?;
    let path = base.join("cdm");
    match fs::create_dir(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }

    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::other(format!(
            "runtime path is not a real directory: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let current_uid = unsafe { libc::getuid() };
        if metadata.uid() != current_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "runtime directory {} is owned by uid {}, expected {}",
                    path.display(),
                    metadata.uid(),
                    current_uid
                ),
            ));
        }
        if metadata.permissions().mode() & 0o777 != 0o700 {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
    }

    let session = loop {
        let candidate = path.join(format!(
            "session-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            SESSION_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };
    fs::set_permissions(&session, fs::Permissions::from_mode(0o700))?;
    validate_private_runtime_dir(&session)?;
    Ok(session)
}

pub(crate) fn validate_private_runtime_dir(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("runtime path is not a real directory: {}", path.display()),
        ));
    }
    let current_uid = unsafe { libc::getuid() };
    if metadata.uid() != current_uid || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "runtime directory must be owned by uid {current_uid} with mode 0700: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn trusted_user_temp_dir() -> io::Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let current_uid = unsafe { libc::getuid() };
    #[cfg(target_os = "linux")]
    // XDG_RUNTIME_DIR normally lives below /run. Linux sandboxes deliberately
    // replace that host tree with an empty tmpfs so pathname Unix sockets
    // cannot delegate to Docker, D-Bus, SSH agents, or other host daemons.
    // Keep CDM's own invocation directory in the validated system temp tree,
    // then bind only that exact private directory into the sandbox.
    let candidates = vec![std::env::temp_dir()];
    #[cfg(not(target_os = "linux"))]
    let candidates = vec![std::env::temp_dir()];
    for path in candidates {
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            let private = !metadata.file_type().is_symlink()
                && metadata.is_dir()
                && metadata.uid() == current_uid
                && metadata.mode() & 0o077 == 0;
            if private {
                return Ok(path);
            }
        }
    }

    // A private, user-specific child of the shared system temporary directory
    // is safe after ownership/type validation; never chmod an existing path
    // owned by another user.
    let fallback = PathBuf::from(format!("/tmp/cdm-runtime-{current_uid}"));
    match fs::create_dir(&fallback) {
        Ok(()) => fs::set_permissions(&fallback, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(&fallback)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != current_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unsafe runtime base: {}", fallback.display()),
        ));
    }
    if metadata.mode() & 0o777 != 0o700 {
        fs::set_permissions(&fallback, fs::Permissions::from_mode(0o700))?;
    }
    Ok(fallback)
}

fn resolve_work_dir(
    current_dir: io::Result<PathBuf>,
    pwd: Option<std::ffi::OsString>,
) -> io::Result<PathBuf> {
    match current_dir {
        Ok(path) => Ok(path),
        Err(err) => {
            let raw_os_error = err.raw_os_error();
            let is_stale_cwd = matches!(raw_os_error, Some(libc::ENOENT) | Some(libc::ESTALE));
            if is_stale_cwd {
                if let Some(pwd) = pwd.map(PathBuf::from) {
                    if pwd.is_dir() {
                        return Ok(pwd);
                    }
                }
            }
            Err(err)
        }
    }
}

// Filesystem policy defaults and path grants live in the access module.

/// Runs a command in the platform-appropriate sandbox.
pub fn run(cfg: SandboxConfig) -> io::Result<SandboxRun> {
    if cfg.use_vm {
        #[cfg(feature = "vm")]
        return vm::run_vm(cfg);

        #[cfg(not(feature = "vm"))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "VM support is not compiled in; rebuild with --features vm",
        ));
    }

    #[cfg(target_os = "macos")]
    {
        darwin::run_darwin(cfg).map(SandboxRun::completed)
    }

    #[cfg(target_os = "linux")]
    {
        linux::run_linux(cfg)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported platform: {}", std::env::consts::OS),
        ))
    }
}

#[cfg(test)]
mod tests;
