//! macOS application-bundle discovery.
//!
//! The public workflow is intentionally one operation: inspect a bundle and
//! return the executable plus the smallest deterministic filesystem grants
//! derivable from its metadata, bundle contents, and macOS storage conventions.

#[cfg(target_os = "macos")]
use aho_corasick::AhoCorasick;
#[cfg(target_os = "macos")]
use std::collections::BTreeSet;
#[cfg(target_os = "macos")]
use std::fs::File;
use std::io;
#[cfg(target_os = "macos")]
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct AppPlan {
    pub bundle_id: String,
    pub executable: PathBuf,
    pub allow_ro: Vec<PathBuf>,
    pub allow_rw: Vec<AppWriteGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AppWriteGrant {
    pub path: PathBuf,
    pub source: AppGrantSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppGrantSource {
    BundleConvention,
    BundleReference,
}

impl AppGrantSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::BundleConvention => "bundle",
            Self::BundleReference => "bundle-reference",
        }
    }
}

/// Return the first command argument when it names an existing `.app` bundle.
///
/// Detection is deliberately structural and side-effect free. Full metadata,
/// containment, and executable validation remains centralized in [`discover`].
pub fn bundle_from_command(command: &[std::ffi::OsString]) -> Option<PathBuf> {
    let path = Path::new(command.first()?);
    (path.extension() == Some(std::ffi::OsStr::new("app"))
        && std::fs::metadata(path)
            .map(|metadata| metadata.is_dir())
            .unwrap_or(false))
    .then(|| path.to_path_buf())
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct BundleMetadata {
    bundle_id: String,
    executable_name: String,
    display_name: Option<String>,
}

#[cfg(target_os = "macos")]
pub fn discover(bundle: &Path, home: &Path) -> io::Result<AppPlan> {
    let bundle = bundle.canonicalize().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "application bundle {} cannot be resolved: {error}",
                bundle.display()
            ),
        )
    })?;
    if bundle.extension().and_then(|value| value.to_str()) != Some("app") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("--app expects a .app bundle: {}", bundle.display()),
        ));
    }

    let info = checked_file_inside(&bundle, &bundle.join("Contents/Info.plist"), "Info.plist")?;
    let metadata = read_metadata(&info)?;
    let executable_root = bundle
        .join("Contents/MacOS")
        .canonicalize()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("application executable directory cannot be resolved: {error}"),
            )
        })?;
    if !executable_root.starts_with(&bundle) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "application executable directory escapes bundle: {}",
                executable_root.display()
            ),
        ));
    }
    let executable = checked_file_inside(
        &executable_root,
        &executable_root.join(&metadata.executable_name),
        "application executable",
    )?;

    let allow_rw = discover_metadata_rw_state(home, &metadata, &executable)?;

    Ok(AppPlan {
        bundle_id: metadata.bundle_id,
        executable,
        allow_ro: vec![bundle],
        allow_rw,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn discover(_bundle: &Path, _home: &Path) -> io::Result<AppPlan> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "--app is currently supported only on macOS",
    ))
}

#[cfg(target_os = "macos")]
fn read_metadata(info: &Path) -> io::Result<BundleMetadata> {
    let mut command = trusted_plutil()?;
    let output = command
        .args(["-convert", "json", "-o", "-"])
        .arg(info)
        .output()
        .map_err(|error| io::Error::new(error.kind(), format!("cannot run plutil: {error}")))?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "cannot parse application Info.plist: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    let plist: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cannot parse application Info.plist JSON: {error}"),
        )
    })?;
    let required = |key: &str| -> io::Result<String> {
        plist
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("application Info.plist is missing string {key}"),
                )
            })
    };
    let bundle_id = required("CFBundleIdentifier")?;
    validate_bundle_id(&bundle_id)?;
    let executable_name = required("CFBundleExecutable")?;
    validate_filename(&executable_name, "CFBundleExecutable")?;
    let display_name = ["CFBundleDisplayName", "CFBundleName"]
        .into_iter()
        .find_map(|key| {
            plist
                .get(key)
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        });
    Ok(BundleMetadata {
        bundle_id,
        executable_name,
        display_name,
    })
}

#[cfg(target_os = "macos")]
fn trusted_plutil() -> io::Result<std::process::Command> {
    let executable = crate::trusted_exec::fixed(Path::new("/usr/bin/plutil"), "plutil")?;
    let mut command = executable.command()?;
    crate::trusted_exec::sanitize_host_environment(&mut command);
    Ok(command)
}

#[cfg(target_os = "macos")]
fn checked_file_inside(root: &Path, path: &Path, label: &str) -> io::Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("{label} not found at {}: {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} must not be a symbolic link: {}", path.display()),
        ));
    }
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} is not a regular file: {}", path.display()),
        ));
    }
    let root = root.canonicalize()?;
    let path = path.canonicalize()?;
    if path.parent().is_none() || !path.starts_with(&root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{label} escapes application bundle: {}", path.display()),
        ));
    }
    Ok(path)
}

#[cfg(target_os = "macos")]
fn validate_bundle_id(bundle_id: &str) -> io::Result<()> {
    if bundle_id.is_empty()
        || bundle_id.contains("..")
        || !bundle_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid CFBundleIdentifier: {bundle_id}"),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_filename(value: &str, key: &str) -> io::Result<()> {
    if value.is_empty() || value == "." || value == ".." || value.contains(['/', '\\']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {key}: {value}"),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn discover_metadata_rw_state(
    home: &Path,
    metadata: &BundleMetadata,
    executable: &Path,
) -> io::Result<Vec<AppWriteGrant>> {
    let home = home.canonicalize().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "home directory {} cannot be resolved: {error}",
                home.display()
            ),
        )
    })?;
    let library = prepare_direct_child(&home, "Library")?;
    let mut grants = BTreeSet::new();

    for (parent_name, leaf, expect_directory) in [
        ("Application Support", metadata.bundle_id.as_str(), true),
        ("Caches", metadata.bundle_id.as_str(), true),
        ("WebKit", metadata.bundle_id.as_str(), true),
    ] {
        let parent = prepare_direct_child(&library, parent_name)?;
        grants.insert(AppWriteGrant {
            path: checked_optional_child(&parent, leaf, expect_directory)?,
            source: AppGrantSource::BundleConvention,
        });
    }
    let preferences = prepare_direct_child(&library, "Preferences")?;
    grants.insert(AppWriteGrant {
        path: checked_optional_child(
            &preferences,
            &format!("{}.plist", metadata.bundle_id),
            false,
        )?,
        source: AppGrantSource::BundleConvention,
    });

    let containers = prepare_direct_child(&library, "Containers")?;
    grants.insert(AppWriteGrant {
        path: checked_optional_child(&containers, &metadata.bundle_id, true)?,
        source: AppGrantSource::BundleConvention,
    });
    grants.extend(discover_bundle_referenced_state(
        &home, metadata, executable,
    )?);

    Ok(grants.into_iter().collect())
}

#[cfg(target_os = "macos")]
fn discover_bundle_referenced_state(
    home: &Path,
    metadata: &BundleMetadata,
    executable: &Path,
) -> io::Result<Vec<AppWriteGrant>> {
    struct Candidate {
        path: PathBuf,
        required_references: Vec<String>,
    }

    let product_tokens = product_tokens(metadata);
    if product_tokens.is_empty() {
        return Ok(Vec::new());
    }

    let cache_root = prepare_direct_child(&prepare_direct_child(home, "Library")?, "Caches")?;
    let mut candidates = Vec::new();

    // A direct hidden directory is accepted only when it is named after a
    // product token and the executable literally references that name.
    for token in &product_tokens {
        let name = format!(".{token}");
        if !safe_direct_home_state(&name) {
            continue;
        }
        candidates.push(Candidate {
            path: home.join(&name),
            required_references: vec![name],
        });
    }

    // Existing cache children are candidates only when both their exact name
    // or its version-independent prefix and version occur in the executable,
    // and their name is related to the selected product name. This permits
    // narrow helper caches without granting all of ~/Library/Caches.
    for entry in std::fs::read_dir(&cache_root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !safe_state_component(&name)
            || !product_tokens
                .iter()
                .any(|token| name.to_ascii_lowercase().contains(token))
        {
            continue;
        }
        let required_references = if let Some((prefix, version)) = versioned_cache_parts(&name) {
            vec![prefix.to_string(), version.to_string()]
        } else {
            vec![name]
        };
        candidates.push(Candidate {
            path: entry.path(),
            required_references,
        });
    }

    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let patterns = candidates
        .iter()
        .flat_map(|candidate| candidate.required_references.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let matched = scan_literal_references(&bundle_reference_files(executable)?, &patterns)?;

    let mut grants = BTreeSet::new();
    for candidate in candidates {
        if !candidate
            .required_references
            .iter()
            .all(|reference| matched.contains(reference.as_str()))
        {
            continue;
        }
        let Some(parent) = candidate.path.parent() else {
            continue;
        };
        let Some(name) = candidate.path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let checked = checked_optional_child(parent, name, true)?;
        grants.insert(AppWriteGrant {
            path: checked,
            source: AppGrantSource::BundleReference,
        });
    }
    Ok(grants.into_iter().collect())
}

#[cfg(target_os = "macos")]
fn scan_literal_references(paths: &[PathBuf], patterns: &[String]) -> io::Result<BTreeSet<String>> {
    const CHUNK_BYTES: usize = 64 * 1024;

    if patterns.is_empty() {
        return Ok(BTreeSet::new());
    }
    let matcher = AhoCorasick::new(patterns).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cannot prepare application bundle inspection: {error}"),
        )
    })?;
    let longest = patterns.iter().map(String::len).max().unwrap_or(0);
    let mut matched = BTreeSet::new();
    for path in paths {
        let mut file = File::open(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot inspect application bundle file {}: {error}",
                    path.display()
                ),
            )
        })?;
        let mut tail = Vec::new();
        let mut chunk = vec![0u8; CHUNK_BYTES];
        loop {
            let count = file.read(&mut chunk).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cannot inspect application bundle file {}: {error}",
                        path.display()
                    ),
                )
            })?;
            if count == 0 {
                break;
            }
            let mut bytes = tail;
            bytes.extend_from_slice(&chunk[..count]);
            for found in matcher.find_overlapping_iter(&bytes) {
                matched.insert(patterns[found.pattern().as_usize()].clone());
            }
            if matched.len() == patterns.len() {
                return Ok(matched);
            }
            let retained = longest.saturating_sub(1).min(bytes.len());
            tail = bytes.split_off(bytes.len() - retained);
        }
    }
    Ok(matched)
}

#[cfg(target_os = "macos")]
fn bundle_reference_files(executable: &Path) -> io::Result<Vec<PathBuf>> {
    const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
    const MAX_TOTAL_CONFIG_BYTES: u64 = 128 * 1024 * 1024;
    const MAX_FILES: usize = 4096;
    const MAX_DEPTH: usize = 8;

    let contents = executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid app executable path"))?;
    let contents = contents.canonicalize()?;
    let mut files = vec![executable.to_path_buf()];
    let mut pending = vec![(contents, 0usize)];
    let mut config_bytes = 0u64;

    while let Some((directory, depth)) = pending.pop() {
        if depth > MAX_DEPTH || files.len() >= MAX_FILES {
            continue;
        }
        let mut entries = std::fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            if files.len() >= MAX_FILES {
                break;
            }
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                pending.push((entry.path(), depth + 1));
                continue;
            }
            if !file_type.is_file() || entry.path() == executable {
                continue;
            }
            let path = entry.path();
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .map(str::to_ascii_lowercase);
            let is_config = matches!(
                extension.as_deref(),
                Some(
                    "cjs"
                        | "conf"
                        | "config"
                        | "ini"
                        | "js"
                        | "json"
                        | "mjs"
                        | "plist"
                        | "toml"
                        | "yaml"
                        | "yml"
                )
            );
            if !is_config {
                continue;
            }
            let size = entry.metadata()?.len();
            if size > MAX_CONFIG_BYTES
                || config_bytes
                    .checked_add(size)
                    .is_none_or(|total| total > MAX_TOTAL_CONFIG_BYTES)
            {
                continue;
            }
            config_bytes += size;
            files.push(path);
        }
    }
    Ok(files)
}

#[cfg(target_os = "macos")]
fn product_tokens(metadata: &BundleMetadata) -> BTreeSet<String> {
    const GENERIC: &[&str] = &["application", "client", "desktop", "helper", "macos"];
    let bundle_tokens = metadata
        .bundle_id
        .split(['.', '-'])
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>();
    let mut tokens = BTreeSet::new();
    for value in metadata
        .display_name
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(metadata.executable_name.as_str()))
    {
        for token in value.split(|character: char| !character.is_ascii_alphanumeric()) {
            let token = token.to_ascii_lowercase();
            if token.len() >= 4
                && !GENERIC.contains(&token.as_str())
                && !bundle_tokens.contains(&token)
            {
                tokens.insert(token);
            }
        }
    }
    if tokens.is_empty() {
        tokens.extend(
            metadata
                .display_name
                .iter()
                .map(String::as_str)
                .chain(std::iter::once(metadata.executable_name.as_str()))
                .flat_map(|value| {
                    value
                        .split(|character: char| !character.is_ascii_alphanumeric())
                        .map(str::to_ascii_lowercase)
                })
                .filter(|token| token.len() >= 4 && !GENERIC.contains(&token.as_str())),
        );
    }
    tokens
}

#[cfg(target_os = "macos")]
fn safe_state_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

#[cfg(target_os = "macos")]
fn safe_direct_home_state(value: &str) -> bool {
    const RESERVED: &[&str] = &[
        ".agents", ".aws", ".azure", ".cache", ".cargo", ".cdm", ".codex", ".config", ".docker",
        ".git", ".gnupg", ".kube", ".local", ".npm", ".rustup", ".ssh",
    ];
    safe_state_component(value) && value.starts_with('.') && !RESERVED.contains(&value)
}

#[cfg(target_os = "macos")]
fn versioned_cache_parts(value: &str) -> Option<(&str, &str)> {
    value.match_indices('-').find_map(|(index, _)| {
        let suffix = &value[index + 1..];
        (!suffix.is_empty()
            && suffix.as_bytes()[0].is_ascii_digit()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b'-')))
        .then_some((&value[..=index], suffix))
    })
}

#[cfg(target_os = "macos")]
fn prepare_direct_child(parent: &Path, name: &str) -> io::Result<PathBuf> {
    validate_filename(name, "application state path component")?;
    let parent = parent.canonicalize()?;
    let path = parent.join(name);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(symlink_error(&path));
            }
            if !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "application state path is not a directory: {}",
                        path.display()
                    ),
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir(&path).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cannot prepare application state directory {}: {error}",
                        path.display()
                    ),
                )
            })?;
        }
        Err(error) => return Err(error),
    }
    checked_existing_child(&parent, name, true)
}

#[cfg(target_os = "macos")]
fn checked_optional_child(
    parent: &Path,
    name: &str,
    expect_directory: bool,
) -> io::Result<PathBuf> {
    validate_filename(name, "application state path component")?;
    let parent = parent.canonicalize()?;
    let path = parent.join(name);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(symlink_error(&path));
            }
            if expect_directory && !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "application state path is not a directory: {}",
                        path.display()
                    ),
                ));
            }
            if !expect_directory && !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "application state path is not a regular file: {}",
                        path.display()
                    ),
                ));
            }
            checked_existing_child(&parent, name, expect_directory)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "macos")]
fn checked_existing_child(
    parent: &Path,
    name: &str,
    expect_directory: bool,
) -> io::Result<PathBuf> {
    let parent = parent.canonicalize()?;
    let path = parent.join(name);
    let metadata = std::fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() {
        return Err(symlink_error(&path));
    }
    if expect_directory && !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "application state path is not a directory: {}",
                path.display()
            ),
        ));
    }
    let canonical = path.canonicalize()?;
    if canonical.parent() != Some(parent.as_path()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "application state path escapes its owned root: {}",
                path.display()
            ),
        ));
    }
    Ok(canonical)
}

#[cfg(target_os = "macos")]
fn symlink_error(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "automatic application state path must not be a symbolic link: {}",
            path.display()
        ),
    )
}

#[cfg(all(test, target_os = "macos"))]
mod tests;
