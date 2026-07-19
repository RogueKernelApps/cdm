//! VM rootfs management — bundled Alpine and OCI image support.
//!
//! Two rootfs sources:
//!   1. Bundled Alpine minirootfs (~3MB compressed, embedded in binary)
//!   2. OCI images (e.g. "ubuntu:24.04") pulled via oci-client

use std::collections::hash_map::DefaultHasher;
use std::fs::{File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use oci_client::manifest::ImageIndexEntry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWrite;

use super::SandboxConfig;

/// Target-matched Alpine minirootfs, embedded at compile time.
#[cfg(target_arch = "aarch64")]
const BUNDLED_ROOTFS: &[u8] =
    include_bytes!("../../assets/alpine-minirootfs-3.21.7-aarch64.tar.gz");
#[cfg(target_arch = "aarch64")]
const BUNDLED_SHA256: &str = "d1d1a3fae5f4d6146e9742790a47fcb116199622cfb8439f218a4d5fbe5000da";
#[cfg(target_arch = "x86_64")]
const BUNDLED_ROOTFS: &[u8] = include_bytes!("../../assets/alpine-minirootfs-3.21.7-x86_64.tar.gz");
#[cfg(target_arch = "x86_64")]
const BUNDLED_SHA256: &str = "8cba1ea3e8b500ea986a313d8eecf3d5952a2a0d23a69117bb81c023d9ceac05";
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("CDM VM support requires an aarch64 or x86_64 bundled rootfs");

const BUNDLED_ARCH: &str = std::env::consts::ARCH;
const COMPLETE_MARKER: &str = ".cdm-complete";
const CACHE_SCHEMA: u32 = 2;

#[derive(Debug, Deserialize, Serialize)]
struct CacheMarker {
    schema: u32,
    source: String,
    architecture: String,
    resolved_digest: String,
    tree_digest: String,
}

#[derive(Debug, Clone)]
struct RootfsLimits {
    max_layer_compressed_bytes: u64,
    max_total_compressed_bytes: u64,
    max_layer_expanded_bytes: u64,
    max_total_expanded_bytes: u64,
    max_layer_entries: u64,
    max_total_entries: u64,
    max_path_depth: usize,
}

impl RootfsLimits {
    fn from_config(config: &crate::config::VmConfig) -> io::Result<Self> {
        fn mib(value: u64, name: &str) -> io::Result<u64> {
            value.checked_mul(1024 * 1024).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("VM rootfs quota {name} is too large"),
                )
            })
        }
        let limits = Self {
            max_layer_compressed_bytes: mib(
                config.max_layer_compressed_mib,
                "max_layer_compressed_mib",
            )?,
            max_total_compressed_bytes: mib(
                config.max_image_compressed_mib,
                "max_image_compressed_mib",
            )?,
            max_layer_expanded_bytes: mib(config.max_layer_expanded_mib, "max_layer_expanded_mib")?,
            max_total_expanded_bytes: mib(config.max_image_expanded_mib, "max_image_expanded_mib")?,
            max_layer_entries: config.max_layer_entries,
            max_total_entries: config.max_image_entries,
            max_path_depth: config.max_path_depth,
        };
        if [
            limits.max_layer_compressed_bytes,
            limits.max_total_compressed_bytes,
            limits.max_layer_expanded_bytes,
            limits.max_total_expanded_bytes,
            limits.max_layer_entries,
            limits.max_total_entries,
            limits.max_path_depth as u64,
        ]
        .contains(&0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VM rootfs quotas must be greater than zero",
            ));
        }
        if limits.max_layer_compressed_bytes > limits.max_total_compressed_bytes
            || limits.max_layer_expanded_bytes > limits.max_total_expanded_bytes
            || limits.max_layer_entries > limits.max_total_entries
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "per-layer VM rootfs quotas cannot exceed image totals",
            ));
        }
        Ok(limits)
    }
}

#[derive(Debug, Default)]
struct ExtractionBudget {
    compressed_bytes: u64,
    expanded_bytes: u64,
    entries: u64,
}

/// Resolves the rootfs path for the VM.
/// Uses bundled Alpine if no image specified, or pulls the OCI image.
pub fn resolve(cfg: &SandboxConfig) -> io::Result<PathBuf> {
    let limits = RootfsLimits::from_config(&cfg.config.vm)?;
    resolve_in(cfg.vm_image.as_deref(), &cache_dir()?, &limits)
}

fn resolve_in(image: Option<&str>, cache: &Path, limits: &RootfsLimits) -> io::Result<PathBuf> {
    match image {
        Some(image) => pull_oci_image_in(image, cache, limits),
        None => extract_bundled_rootfs_in(cache),
    }
}

/// Returns the base cache directory for CDM rootfs images (~/.cdm/rootfs/).
fn cache_dir() -> io::Result<PathBuf> {
    cache_dir_from(
        std::env::var_os("HOME").map(PathBuf::from),
        std::env::var_os("CDM_CACHE_DIR").map(PathBuf::from),
    )
}

fn cache_dir_from(home: Option<PathBuf>, configured: Option<PathBuf>) -> io::Result<PathBuf> {
    if let Some(path) = configured {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CDM_CACHE_DIR must be an absolute path",
            ));
        }
        return Ok(path.join("rootfs"));
    }
    let home = home.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME not set"))?;
    Ok(home.join(".cdm").join("rootfs"))
}

struct CacheLock(File);

impl Drop for CacheLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn lock_cache(path: &Path) -> io::Result<CacheLock> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path.with_extension("lock"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        let uid = unsafe { libc::getuid() };
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VM rootfs cache lock must be a private, user-owned regular file",
            ));
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(CacheLock(file))
}

fn ensure_private_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("cache directory must be absolute: {}", path.display()),
        ));
    }
    let mut current = PathBuf::from("/");
    validate_cache_ancestor(&current, false)?;
    for component in path.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cache path traverses a symlink: {}", current.display()),
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cache path is not a directory: {}", current.display()),
                ));
            }
            Ok(_) => validate_cache_ancestor(&current, false)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match std::fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                let metadata = std::fs::symlink_metadata(&current)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("cache path is not a real directory: {}", current.display()),
                    ));
                }
                #[cfg(unix)]
                std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o700))?;
                validate_cache_ancestor(&current, true)?;
            }
            Err(error) => return Err(error),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(path)?;
        let uid = unsafe { libc::getuid() };
        if metadata.uid() != uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "cache directory {} is owned by uid {}, expected {uid}",
                    path.display(),
                    metadata.uid()
                ),
            ));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn validate_cache_ancestor(path: &Path, created: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(path)?;
        let uid = unsafe { libc::getuid() };
        let owner = metadata.uid();
        let mode = metadata.mode() & 0o7777;
        if owner != uid && owner != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "cache path ancestor {} is owned by uid {owner}, expected {uid} or root",
                    path.display()
                ),
            ));
        }
        if mode & 0o022 != 0 && !(owner == 0 && mode & 0o1000 != 0) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "cache path ancestor {} is writable by another user",
                    path.display()
                ),
            ));
        }
        if created && (owner != uid || mode != 0o700) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "new cache directory {} is not private and user-owned",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn read_marker(path: &Path) -> Option<CacheMarker> {
    let marker_path = path.join(COMPLETE_MARKER);
    let metadata = std::fs::symlink_metadata(&marker_path).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return None;
    }
    serde_json::from_slice(&std::fs::read(marker_path).ok()?).ok()
}

fn tree_digest(root: &Path) -> io::Result<String> {
    let mut hasher = Sha256::new();
    hash_tree_directory(root, Path::new(""), &mut hasher)?;
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn hash_tree_directory(root: &Path, relative: &Path, hasher: &mut Sha256) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let directory = root.join(relative);
    let mut entries = std::fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by(|left, right| {
        left.file_name()
            .as_bytes()
            .cmp(right.file_name().as_bytes())
    });
    for entry in entries {
        if relative.as_os_str().is_empty() && entry.file_name() == COMPLETE_MARKER {
            continue;
        }
        let entry_relative = relative.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(entry.path())?;
        let path_bytes = entry_relative.as_os_str().as_bytes();
        hasher.update((path_bytes.len() as u64).to_le_bytes());
        hasher.update(path_bytes);
        hasher.update((metadata.mode() & 0o7777).to_le_bytes());
        if metadata.is_dir() {
            hasher.update(b"d");
            hash_tree_directory(root, &entry_relative, hasher)?;
        } else if metadata.file_type().is_symlink() {
            hasher.update(b"l");
            let target = std::fs::read_link(entry.path())?;
            let target = target.as_os_str().as_bytes();
            hasher.update((target.len() as u64).to_le_bytes());
            hasher.update(target);
        } else if metadata.is_file() {
            hasher.update(b"f");
            hasher.update(metadata.len().to_le_bytes());
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(entry.path())?;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported file type in cached rootfs: {}",
                    entry.path().display()
                ),
            ));
        }
    }
    Ok(())
}

fn is_complete(path: &Path, source: &str) -> bool {
    let valid_directory = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata.is_dir() && !metadata.file_type().is_symlink(),
        Err(_) => false,
    };
    if !valid_directory || !path.join("bin").is_dir() {
        return false;
    }
    read_marker(path).is_some_and(|marker| {
        marker.schema == CACHE_SCHEMA
            && marker.source == source
            && marker.architecture == BUNDLED_ARCH
            && !marker.resolved_digest.is_empty()
            && !marker.tree_digest.is_empty()
            && tree_digest(path).is_ok_and(|digest| digest == marker.tree_digest)
    })
}

fn temporary_cache_path(path: &Path, purpose: &str) -> PathBuf {
    path.with_extension(format!(
        "{purpose}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

fn remove_stale_cache_paths(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(());
    };
    let prefixes = [format!("{name}.tmp-"), format!("{name}.previous-")];
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let entry_name = entry.file_name();
        let entry_name = entry_name.to_string_lossy();
        if !prefixes.iter().any(|prefix| entry_name.starts_with(prefix)) {
            continue;
        }
        remove_path(&entry.path())?;
    }
    Ok(())
}

fn publish_cache(temp: &Path, destination: &Path, marker: &CacheMarker) -> io::Result<()> {
    let marker = CacheMarker {
        schema: marker.schema,
        source: marker.source.clone(),
        architecture: marker.architecture.clone(),
        resolved_digest: marker.resolved_digest.clone(),
        tree_digest: tree_digest(temp)?,
    };
    let marker_data = serde_json::to_vec_pretty(&marker).map_err(io::Error::other)?;
    let marker_path = temp.join(COMPLETE_MARKER);
    let mut marker_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&marker_path)?;
    use std::io::Write;
    marker_file.write_all(&marker_data)?;
    marker_file.sync_all()?;
    File::open(temp)?.sync_all()?;

    let previous = temporary_cache_path(destination, "previous");
    let had_previous = match std::fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            std::fs::rename(destination, &previous)?;
            true
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cache destination is not a real directory: {}",
                    destination.display()
                ),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };

    if let Err(error) = std::fs::rename(temp, destination) {
        if had_previous {
            let _ = std::fs::rename(&previous, destination);
        }
        return Err(error);
    }
    if let Some(parent) = destination.parent() {
        File::open(parent)?.sync_all()?;
    }
    if had_previous {
        std::fs::remove_dir_all(previous)?;
    }
    Ok(())
}

fn extract_bundled_rootfs_in(cache: &Path) -> io::Result<PathBuf> {
    let dir = cache.join(format!("bundled-{BUNDLED_ARCH}"));
    ensure_private_directory(cache)?;
    let _lock = lock_cache(&dir)?;
    let source = format!("alpine-minirootfs-3.21.7-{BUNDLED_ARCH}");

    if is_complete(&dir, &source) {
        return Ok(dir);
    }

    remove_stale_cache_paths(&dir)?;
    let temp = temporary_cache_path(&dir, "tmp");
    ensure_private_directory(&temp)?;

    let decoder = flate2::read::GzDecoder::new(BUNDLED_ROOTFS);
    let mut archive = tar::Archive::new(decoder);
    archive.set_preserve_permissions(true);
    archive.set_overwrite(true);
    if let Err(error) = archive.unpack(&temp) {
        let _ = std::fs::remove_dir_all(&temp);
        return Err(error);
    }
    publish_cache(
        &temp,
        &dir,
        &CacheMarker {
            schema: CACHE_SCHEMA,
            source,
            architecture: BUNDLED_ARCH.to_string(),
            resolved_digest: format!("sha256:{BUNDLED_SHA256}"),
            tree_digest: String::new(),
        },
    )?;

    Ok(dir)
}

fn pull_oci_image_in(image_ref: &str, cache: &Path, limits: &RootfsLimits) -> io::Result<PathBuf> {
    let dir = cache.join(oci_cache_name(image_ref));
    ensure_private_directory(cache)?;
    let _lock = lock_cache(&dir)?;
    let source = format!("oci:{image_ref}");

    if is_complete(&dir, &source) {
        return Ok(dir);
    }

    remove_stale_cache_paths(&dir)?;
    let temp = temporary_cache_path(&dir, "tmp");
    ensure_private_directory(&temp)?;

    let rt = tokio::runtime::Runtime::new().map_err(io::Error::other)?;

    let digest = match rt.block_on(async { pull_and_extract(image_ref, &temp, limits).await }) {
        Ok(digest) => digest,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&temp);
            return Err(error);
        }
    };
    publish_cache(
        &temp,
        &dir,
        &CacheMarker {
            schema: CACHE_SCHEMA,
            source,
            architecture: BUNDLED_ARCH.to_string(),
            resolved_digest: digest,
            tree_digest: String::new(),
        },
    )?;

    Ok(dir)
}

/// Deterministic cache directory name from an image reference.
pub(crate) fn oci_cache_name(image_ref: &str) -> String {
    let sanitized = image_ref.replace(['/', ':'], "_");
    let mut hasher = DefaultHasher::new();
    image_ref.hash(&mut hasher);
    let hash = hasher.finish();
    format!("oci_{}_{:x}", sanitized, hash)
}

/// Platform resolver that selects linux/<host_arch> from image indexes.
/// VMs always run Linux, even when the host is macOS.
fn linux_platform_resolver(entries: &[ImageIndexEntry]) -> Option<String> {
    let arch = std::env::consts::ARCH;
    // Map Rust arch names to OCI arch names
    let oci_arch = match arch {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        _ => arch,
    };

    entries
        .iter()
        .find(|entry| {
            entry.platform.as_ref().is_some_and(|platform| {
                platform.os.to_string() == "linux" && platform.architecture.to_string() == oci_arch
            })
        })
        .map(|entry| entry.digest.clone())
}

fn validate_image_platform(config_json: &str) -> io::Result<()> {
    let config: oci_client::config::ConfigFile =
        serde_json::from_str(config_json).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid OCI image configuration: {error}"),
            )
        })?;
    let expected_arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        architecture => architecture,
    };
    if config.os.to_string() != "linux" || config.architecture.to_string() != expected_arch {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "OCI image platform is {}/{}, expected linux/{expected_arch}",
                config.os, config.architecture
            ),
        ));
    }
    Ok(())
}

fn layer_reader<'a, R: Read + 'a>(reader: R, media_type: &str) -> io::Result<Box<dyn Read + 'a>> {
    use oci_client::manifest::{
        IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE, IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
        IMAGE_LAYER_GZIP_MEDIA_TYPE, IMAGE_LAYER_MEDIA_TYPE,
    };

    match media_type {
        IMAGE_LAYER_GZIP_MEDIA_TYPE | IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE => {
            Ok(Box::new(flate2::read::GzDecoder::new(reader)))
        }
        IMAGE_LAYER_MEDIA_TYPE | IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE => Ok(Box::new(reader)),
        unsupported => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported OCI layer media type: {unsupported}"),
        )),
    }
}

struct QuotaReader<R> {
    inner: R,
    limit: u64,
    read: Arc<AtomicU64>,
}

impl<R> QuotaReader<R> {
    fn new(inner: R, limit: u64, read: Arc<AtomicU64>) -> Self {
        Self { inner, limit, read }
    }
}

impl<R: Read> Read for QuotaReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let consumed = self.read.load(Ordering::Relaxed);
        let remaining = self.limit.saturating_sub(consumed);
        let probe = remaining.saturating_add(1).min(buffer.len() as u64) as usize;
        if probe == 0 {
            return Ok(0);
        }
        let count = self.inner.read(&mut buffer[..probe])?;
        if count as u64 > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "OCI layer exceeds expanded byte quota of {} bytes",
                    self.limit
                ),
            ));
        }
        self.read.fetch_add(count as u64, Ordering::Relaxed);
        Ok(count)
    }
}

struct QuotaWriter<W> {
    inner: W,
    limit: u64,
    written: u64,
}

impl<W> QuotaWriter<W> {
    fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            limit,
            written: 0,
        }
    }

    fn written(&self) -> u64 {
        self.written
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for QuotaWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buffer.len() as u64 > this.limit.saturating_sub(this.written) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "OCI layer exceeds compressed byte quota of {} bytes",
                    this.limit
                ),
            )));
        }
        match Pin::new(&mut this.inner).poll_write(context, buffer) {
            Poll::Ready(Ok(count)) => {
                this.written += count as u64;
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

struct LayerTemp {
    path: PathBuf,
    file: Option<File>,
}

impl LayerTemp {
    fn create(extraction: &Path, index: usize) -> io::Result<Self> {
        let parent = extraction.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "OCI extraction path has no parent",
            )
        })?;
        let name = extraction.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "OCI extraction path has no name",
            )
        })?;
        let path = parent.join(format!(
            "{}.layer-{index}-{}",
            name.to_string_lossy(),
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW);
        let file = options.open(&path)?;
        Ok(Self {
            path,
            file: Some(file),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn take_file(&mut self) -> io::Result<File> {
        self.file
            .take()
            .ok_or_else(|| io::Error::other("OCI layer file already taken"))
    }
}

impl Drop for LayerTemp {
    fn drop(&mut self) {
        self.file.take();
        let _ = std::fs::remove_file(&self.path);
    }
}

fn remove_path(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn validated_relative(path: &Path) -> io::Result<PathBuf> {
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("OCI layer path escapes its root: {}", path.display()),
                ));
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OCI layer contains an empty path",
        ));
    }
    Ok(clean)
}

fn reject_symlink_ancestors(root: &Path, relative: &Path) -> io::Result<()> {
    if std::fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("OCI extraction root is a symlink: {}", root.display()),
        ));
    }

    let mut current = root.to_path_buf();
    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            let Component::Normal(part) = component else {
                continue;
            };
            current.push(part);
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("OCI layer path traverses a symlink: {}", current.display()),
                    ));
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "OCI layer ancestor is not a directory: {}",
                            current.display()
                        ),
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn extract_layer(data: &[u8], media_type: &str, destination: &Path) -> io::Result<()> {
    let limits = RootfsLimits {
        max_layer_compressed_bytes: u64::MAX,
        max_total_compressed_bytes: u64::MAX,
        max_layer_expanded_bytes: u64::MAX - 1,
        max_total_expanded_bytes: u64::MAX - 1,
        max_layer_entries: u64::MAX,
        max_total_entries: u64::MAX,
        max_path_depth: usize::MAX,
    };
    extract_layer_with_limits(
        data,
        media_type,
        destination,
        &limits,
        &mut ExtractionBudget::default(),
    )
}

#[cfg(test)]
fn extract_layer_with_limits(
    data: &[u8],
    media_type: &str,
    destination: &Path,
    limits: &RootfsLimits,
    budget: &mut ExtractionBudget,
) -> io::Result<()> {
    extract_layer_from(
        || layer_reader(data, media_type),
        destination,
        limits,
        budget,
    )
}

fn extract_layer_path(
    path: &Path,
    media_type: &str,
    destination: &Path,
    limits: &RootfsLimits,
    budget: &mut ExtractionBudget,
) -> io::Result<()> {
    extract_layer_from(
        || layer_reader(File::open(path)?, media_type),
        destination,
        limits,
        budget,
    )
}

fn extract_layer_from<'a, F>(
    mut open: F,
    destination: &Path,
    limits: &RootfsLimits,
    budget: &mut ExtractionBudget,
) -> io::Result<()>
where
    F: FnMut() -> io::Result<Box<dyn Read + 'a>>,
{
    let remaining_expanded = limits
        .max_total_expanded_bytes
        .checked_sub(budget.expanded_bytes)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "OCI image exceeds expanded byte quota",
            )
        })?;
    let expanded_limit = limits.max_layer_expanded_bytes.min(remaining_expanded);
    let scanned_bytes = Arc::new(AtomicU64::new(0));
    let reader = QuotaReader::new(open()?, expanded_limit, Arc::clone(&scanned_bytes));
    let mut scan = tar::Archive::new(reader);
    let mut whiteouts = Vec::new();
    let mut opaque_dirs = Vec::new();
    let mut markers = Vec::new();
    let mut layer_entries = 0_u64;
    let mut layer_logical_bytes = 0_u64;

    for entry in scan.entries()? {
        let entry = entry?;
        let path = validated_relative(&entry.path()?)?;
        let depth = path.components().count();
        if depth > limits.max_path_depth {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "OCI layer exceeds path depth quota of {}",
                    limits.max_path_depth
                ),
            ));
        }
        layer_entries = layer_entries.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "OCI layer entry quota overflow")
        })?;
        if layer_entries > limits.max_layer_entries
            || budget.entries.saturating_add(layer_entries) > limits.max_total_entries
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "OCI image exceeds entry quota",
            ));
        }
        layer_logical_bytes = layer_logical_bytes
            .checked_add(entry.size())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "OCI layer expanded byte quota overflow",
                )
            })?;
        if layer_logical_bytes > expanded_limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("OCI layer exceeds expanded byte quota of {expanded_limit} bytes"),
            ));
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(parent) = path.parent() else {
            continue;
        };
        if name == ".wh..wh..opq" {
            opaque_dirs.push(parent.to_path_buf());
            markers.push(path);
        } else if let Some(target) = name.strip_prefix(".wh.") {
            let target = validated_relative(&parent.join(target))?;
            whiteouts.push(target);
            markers.push(path);
        }
    }
    drop(scan);
    let expanded = scanned_bytes
        .load(Ordering::Relaxed)
        .max(layer_logical_bytes);
    budget.expanded_bytes = budget.expanded_bytes.checked_add(expanded).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "OCI image expanded byte quota overflow",
        )
    })?;
    budget.entries = budget.entries.checked_add(layer_entries).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "OCI image entry quota overflow")
    })?;

    // Whiteouts describe lower layers and must be applied before unpacking
    // this layer, otherwise a newly added entry could be deleted.
    for relative in opaque_dirs {
        reject_symlink_ancestors(destination, &relative.join("entry"))?;
        let directory = destination.join(relative);
        if let Ok(entries) = std::fs::read_dir(directory) {
            for entry in entries {
                remove_path(&entry?.path())?;
            }
        }
    }
    for relative in whiteouts {
        reject_symlink_ancestors(destination, &relative)?;
        remove_path(&destination.join(relative))?;
    }

    let unpacked_bytes = Arc::new(AtomicU64::new(0));
    let reader = QuotaReader::new(
        open()?,
        limits.max_layer_expanded_bytes,
        Arc::clone(&unpacked_bytes),
    );
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_overwrite(true);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let relative = validated_relative(&entry.path()?)?;
        if markers.contains(&relative) {
            continue;
        }
        reject_symlink_ancestors(destination, &relative)?;
        if entry.header().entry_type().is_hard_link() {
            let target = entry.link_name()?.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "hard link has no target")
            })?;
            let target = validated_relative(&target)?;
            reject_symlink_ancestors(destination, &target)?;
        }
        if !entry.unpack_in(destination)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("OCI layer path escapes its root: {}", relative.display()),
            ));
        }
    }
    Ok(())
}

/// Async pull + extract using oci-client.
async fn pull_and_extract(
    image_ref: &str,
    dest: &Path,
    limits: &RootfsLimits,
) -> io::Result<String> {
    use oci_client::client::ClientConfig;
    use oci_client::secrets::RegistryAuth;
    use oci_client::{Client, Reference};

    let reference: Reference = image_ref.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid image ref: {e}"),
        )
    })?;

    // VM always runs Linux — select linux/<host_arch> from image indexes.
    let config = ClientConfig {
        platform_resolver: Some(Box::new(linux_platform_resolver)),
        connect_timeout: Some(Duration::from_secs(30)),
        read_timeout: Some(Duration::from_secs(300)),
        ..Default::default()
    };
    let client = Client::try_from(config)
        .map_err(|e| io::Error::other(format!("create OCI client: {e}")))?;

    let auth = RegistryAuth::Anonymous;

    let (manifest, digest, config) = client
        .pull_manifest_and_config(&reference, &auth)
        .await
        .map_err(|e| io::Error::other(format!("pull image: {e}")))?;
    validate_image_platform(&config)?;

    let mut budget = ExtractionBudget::default();
    for (index, layer) in manifest.layers.iter().enumerate() {
        let remaining = limits
            .max_total_compressed_bytes
            .checked_sub(budget.compressed_bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "OCI image exceeds compressed byte quota",
                )
            })?;
        let layer_limit = limits.max_layer_compressed_bytes.min(remaining);
        let descriptor_size = u64::try_from(layer.size).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "OCI layer descriptor has a negative size",
            )
        })?;
        if descriptor_size > layer_limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("OCI layer exceeds compressed byte quota of {layer_limit} bytes"),
            ));
        }
        let mut temp = LayerTemp::create(dest, index)?;
        let file = tokio::fs::File::from_std(temp.take_file()?);
        let mut writer = QuotaWriter::new(file, layer_limit);
        client
            .pull_blob(&reference, layer, &mut writer)
            .await
            .map_err(|e| io::Error::other(format!("pull layer: {e}")))?;
        use tokio::io::AsyncWriteExt;
        writer.flush().await?;
        let written = writer.written();
        writer.into_inner().sync_all().await?;
        budget.compressed_bytes =
            budget
                .compressed_bytes
                .checked_add(written)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "OCI image compressed byte quota overflow",
                    )
                })?;
        extract_layer_path(temp.path(), &layer.media_type, dest, limits, &mut budget)?;
    }

    Ok(digest)
}

#[cfg(test)]
mod tests;
