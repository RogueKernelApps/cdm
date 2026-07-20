//! File-level secret obfuscation and staging.
//!
//! Strategy: Create a temp directory with obfuscated copies of sensitive files.
//! On Linux: bwrap --ro-bind overlays copies on top of originals.
//! On macOS: seatbelt denies reads to originals; env vars redirect tools to copies.
//! Real files are NEVER modified.

use crate::anchored::AnchoredRoot;
use crate::secrets::{self, SecretMapping};
use std::fs;
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// FileStage — obfuscated copies of sensitive files
// ---------------------------------------------------------------------------

/// Represents an obfuscated copy of a sensitive file.
#[derive(Clone, Debug)]
pub struct StagedFile {
    /// Real file on disk (never modified).
    pub original_path: PathBuf,
    /// Obfuscated copy in temp dir.
    pub staged_path: PathBuf,
}

/// Manages obfuscated copies of sensitive files in a temp directory.
pub struct FileStage {
    staged_files: Vec<StagedFile>,
    temp_dir: PathBuf,
    mapping: SecretMapping,
    name_patterns: Vec<String>,
    min_length: usize,
    min_char_classes: usize,
    finished: bool,
    #[cfg(test)]
    owned_test_runtime: Option<PathBuf>,
}

impl FileStage {
    #[cfg(test)]
    pub fn new(mapping: SecretMapping) -> io::Result<Self> {
        let runtime_dir = crate::sandbox::prepare_runtime_dir()?;
        let defaults = crate::config::SecretsConfig::default();
        let mut stage = Self::new_with_config(
            &runtime_dir,
            mapping,
            defaults.name_patterns,
            defaults.min_length,
            defaults.min_char_classes,
        )?;
        stage.owned_test_runtime = Some(runtime_dir);
        Ok(stage)
    }

    pub fn new_with_config(
        runtime_dir: &Path,
        mapping: SecretMapping,
        name_patterns: Vec<String>,
        min_length: usize,
        min_char_classes: usize,
    ) -> io::Result<Self> {
        let temp_dir = private_stage_dir(runtime_dir)?;
        Ok(FileStage {
            staged_files: Vec::new(),
            temp_dir,
            mapping,
            name_patterns,
            min_length,
            min_char_classes,
            finished: false,
            #[cfg(test)]
            owned_test_runtime: None,
        })
    }

    /// Creates an obfuscated copy of a sensitive file in the temp dir.
    /// The original file is NEVER modified.
    #[cfg(test)]
    pub fn stage_file<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let path = path.as_ref();
        let original = read_regular_file(path)?;
        self.stage_content(path, &original)
    }

    pub fn stage_sensitive_file(&mut self, mut source: SensitiveFile) -> io::Result<()> {
        let mut original = String::new();
        source
            .file
            .read_to_string(&mut original)
            .map_err(|error| with_path("read sensitive file", &source.path, error))?;
        self.stage_content(&source.path, &original)
    }

    fn stage_content(&mut self, path: &Path, original: &str) -> io::Result<()> {
        let obfuscated = obfuscate_content_for_path(
            path,
            original,
            &self.mapping,
            &self.name_patterns,
            self.min_length,
            self.min_char_classes,
        )
        .map_err(|error| with_path("obfuscate sensitive file", path, error))?;

        let staged_path = self.temp_dir.join(staged_relative_path(path)?);
        if let Some(parent) = staged_path.parent() {
            fs::create_dir_all(parent)?;
        }

        write_private_file(&staged_path, obfuscated.as_bytes())?;

        self.staged_files.push(StagedFile {
            original_path: path.to_path_buf(),
            staged_path,
        });

        Ok(())
    }

    /// Returns bwrap arguments to overlay staged files on top of originals.
    /// Linux only.
    #[cfg(target_os = "linux")]
    pub fn bwrap_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        for sf in &self.staged_files {
            args.push("--ro-bind".to_string());
            args.push(sf.staged_path.to_string_lossy().to_string());
            args.push(sf.original_path.to_string_lossy().to_string());
        }
        args
    }

    pub fn staged_files(&self) -> &[StagedFile] {
        &self.staged_files
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        match fs::remove_dir_all(&self.temp_dir) {
            Ok(()) => {
                self.finished = true;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.finished = true;
                Ok(())
            }
            Err(error) => Err(with_path(
                "remove staged secret directory",
                &self.temp_dir,
                error,
            )),
        }
    }

    /// Returns the staging temp directory path (used by VM mode for VirtioFS sharing).
    #[cfg_attr(not(feature = "vm"), allow(dead_code))]
    pub fn temp_dir_path(&self) -> &Path {
        &self.temp_dir
    }

    #[cfg(test)]
    pub fn temp_dir(&self) -> &Path {
        self.temp_dir_path()
    }
}

impl Drop for FileStage {
    fn drop(&mut self) {
        let _ = self.finish();
        #[cfg(test)]
        if let Some(runtime_dir) = self.owned_test_runtime.take() {
            let _ = fs::remove_dir(runtime_dir);
        }
    }
}

// ---------------------------------------------------------------------------
// Sensitive file classification
// ---------------------------------------------------------------------------

/// How a sensitive file should be handled inside the sandbox.
pub enum SensitiveFileKind {
    /// .env file in working directory: inject as env vars, deny reads to original.
    EnvFile,
    /// Home directory config file (AWS, Docker, etc.): redirect via env var, deny reads.
    HomeConfig,
    /// SSH private key: deny reads only.
    SshKey,
}

#[derive(Debug)]
pub struct SensitiveFile {
    pub path: PathBuf,
    file: fs::File,
}

/// Classifies a sensitive file path into its obfuscation strategy.
pub fn classify_sensitive_file(path: &Path, work_dir: &Path, home_dir: &Path) -> SensitiveFileKind {
    if path.starts_with(work_dir) && is_env_file(path) {
        return SensitiveFileKind::EnvFile;
    }

    if path.starts_with(home_dir.join(".ssh")) {
        return SensitiveFileKind::SshKey;
    }

    SensitiveFileKind::HomeConfig
}

/// Parses a .env file and returns ALL key=value pairs (not just secrets).
/// Used to inject .env contents as environment variables into the sandbox.
pub fn parse_env_file_entries<P: AsRef<Path>>(path: P) -> io::Result<Vec<(String, String)>> {
    let path = path.as_ref();
    let content = read_regular_file(path)?;
    let mut entries = Vec::new();

    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Some(sep) = trimmed.find('=') else {
            return Err(malformed_env(path, index + 1, "missing '=' separator"));
        };
        let mut key = trimmed[..sep].trim();
        // Handle `export KEY=VALUE` syntax
        if let Some(rest) = key.strip_prefix("export ") {
            key = rest.trim();
        }
        if !is_env_key(key) {
            return Err(malformed_env(path, index + 1, "invalid variable name"));
        }
        let value = trimmed[sep + 1..].trim();
        let value = value.trim_matches('"').trim_matches('\'');
        entries.push((key.to_string(), value.to_string()));
    }

    Ok(entries)
}

/// Returns environment variable overrides that redirect a tool to an obfuscated copy.
/// Returns an empty vec for files without a known redirect variable.
pub fn redirect_env_for_staged_file_with_config(
    original_path: &Path,
    staged_path: &Path,
    home_dir: &Path,
    staged_configs: &std::collections::HashMap<String, String>,
) -> Vec<(String, String)> {
    let rel = original_path
        .strip_prefix(home_dir)
        .unwrap_or(original_path);
    let rel_str = rel.to_string_lossy();
    let staged_str = staged_path.display().to_string();

    if let Some(env_var) = staged_configs.get(rel_str.as_ref()) {
        // Special handling for DOCKER_CONFIG: point to parent directory, not file
        if env_var == "DOCKER_CONFIG" {
            return staged_path
                .parent()
                .map(|p| vec![(env_var.clone(), p.display().to_string())])
                .unwrap_or_default();
        }
        return vec![(env_var.clone(), staged_str)];
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Obfuscation helpers
// ---------------------------------------------------------------------------

/// Obfuscates file content by replacing secret values with fakes.
pub(crate) fn obfuscate_content_for_path(
    path: &Path,
    content: &str,
    mapping: &SecretMapping,
    name_patterns: &[String],
    min_length: usize,
    min_char_classes: usize,
) -> io::Result<String> {
    if content.contains("PRIVATE KEY") {
        return self_contained_obfuscation(content, mapping);
    }
    if path
        .extension()
        .is_some_and(|extension| extension == "json")
    {
        return obfuscate_json_content(
            content,
            mapping,
            name_patterns,
            min_length,
            min_char_classes,
        );
    }
    let mut result = String::new();
    let had_trailing_newline = content.ends_with('\n');
    let env_key_names_only = is_env_file(path);

    for (i, line) in content.lines().enumerate() {
        if i > 0 {
            result.push('\n');
        }

        let mapped_line = mapping.obfuscate(line);
        if mapped_line != line {
            result.push_str(&mapped_line);
            continue;
        }
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            result.push_str(line);
            continue;
        }

        // Skip [section] headers (INI-style)
        if trimmed.starts_with('[') {
            result.push_str(line);
            continue;
        }

        // Look for key=value or key:value patterns
        let sep_pos = line.find(['=', ':']);
        if let Some(sep) = sep_pos {
            let key = line[..sep].trim();
            let value_part = &line[sep + 1..];
            let value = value_part.trim();
            let unquoted = value.trim_matches('"').trim_matches('\'');

            let should_obfuscate = if env_key_names_only {
                secrets::is_secret_name_with_patterns(key, name_patterns)
                    || mapping.real_to_fake.contains_key(unquoted)
            } else {
                secrets::is_secret_name_with_patterns(key, name_patterns)
                    || secrets::looks_like_secret_with_config(
                        unquoted,
                        min_length,
                        min_char_classes,
                    )
            };

            let structural_literal = matches!(unquoted, "{" | "}" | "{}" | "[" | "]" | "[]");
            if !unquoted.is_empty() && !structural_literal && should_obfuscate {
                let fake = mapped_replacement(mapping, unquoted)?;
                let obfuscated_value = value.replace(unquoted, &fake);
                result.push_str(&line[..sep + 1]);
                result.push_str(&value_part.replace(value, &obfuscated_value));
            } else {
                result.push_str(line);
            }
        } else {
            // Check for multi-line secrets (SSH key material)
            if looks_like_base64_or_key_material(trimmed) {
                let fake = mapped_replacement(mapping, trimmed)?;
                result.push_str(&line.replace(trimmed, &fake));
            } else {
                result.push_str(line);
            }
        }
    }

    if had_trailing_newline {
        result.push('\n');
    }

    if mapping
        .real_to_fake
        .keys()
        .any(|real| !real.is_empty() && result.contains(real))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged content still contains a known real secret",
        ));
    }

    Ok(result)
}

fn obfuscate_json_content(
    content: &str,
    mapping: &SecretMapping,
    name_patterns: &[String],
    min_length: usize,
    min_char_classes: usize,
) -> io::Result<String> {
    let mut value: serde_json::Value = serde_json::from_str(content).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed staged JSON: {error}"),
        )
    })?;
    let original = value.clone();
    obfuscate_json_value(
        &mut value,
        None,
        mapping,
        name_patterns,
        min_length,
        min_char_classes,
    )?;
    if value == original {
        return Ok(content.to_string());
    }
    let mut result = serde_json::to_string(&value).map_err(io::Error::other)?;
    if content.ends_with('\n') {
        result.push('\n');
    }
    if mapping
        .real_to_fake
        .keys()
        .any(|real| !real.is_empty() && result.contains(real))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged JSON still contains a known real secret",
        ));
    }
    Ok(result)
}

fn obfuscate_json_value(
    value: &mut serde_json::Value,
    key: Option<&str>,
    mapping: &SecretMapping,
    name_patterns: &[String],
    min_length: usize,
    min_char_classes: usize,
) -> io::Result<()> {
    match value {
        serde_json::Value::Object(values) => {
            for (child_key, child) in values {
                obfuscate_json_value(
                    child,
                    Some(child_key),
                    mapping,
                    name_patterns,
                    min_length,
                    min_char_classes,
                )?;
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                obfuscate_json_value(
                    child,
                    key,
                    mapping,
                    name_patterns,
                    min_length,
                    min_char_classes,
                )?;
            }
        }
        serde_json::Value::String(text) => {
            let obfuscated = mapping.obfuscate(text);
            if obfuscated != *text {
                *text = obfuscated;
            } else if key
                .is_some_and(|key| secrets::is_secret_name_with_patterns(key, name_patterns))
                || secrets::looks_like_secret_with_config(text, min_length, min_char_classes)
            {
                *text = mapped_replacement(mapping, text)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn mapped_replacement(mapping: &SecretMapping, real: &str) -> io::Result<String> {
    mapping.real_to_fake.get(real).cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "sensitive content was discovered without a registered replacement",
        )
    })
}

fn self_contained_obfuscation(content: &str, mapping: &SecretMapping) -> io::Result<String> {
    mapping.real_to_fake.get(content).cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "private key content was discovered without a registered replacement",
        )
    })
}

fn is_env_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == ".env" || name.starts_with(".env."))
        .unwrap_or(false)
}

fn looks_like_base64_or_key_material(s: &str) -> bool {
    if s.len() < 20 {
        return false;
    }
    if s.contains("BEGIN") || s.contains("END") {
        return false;
    }
    let base64_chars = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();
    (base64_chars as f64) / (s.len() as f64) > 0.9
}

// ---------------------------------------------------------------------------
// Sensitive file discovery
// ---------------------------------------------------------------------------

/// Finds sensitive files that need obfuscation.
pub fn find_sensitive_files_with_config(
    work_dir: &Path,
    home_dir: &Path,
    env_files: &[String],
    staged_configs: &std::collections::HashMap<String, String>,
    allow_home_path: &dyn Fn(&Path) -> bool,
) -> io::Result<Vec<SensitiveFile>> {
    let mut files = Vec::new();
    let work_root = AnchoredRoot::open(work_dir)?;
    let home_root = AnchoredRoot::open(home_dir)?;

    // .env files in working directory
    for pattern in env_files {
        let path = secrets::resolve_relative_candidate(work_dir, pattern)?;
        if let Some(file) = work_root.open_regular(&path)? {
            files.push(SensitiveFile { path, file });
        }
    }

    // Home directory config files (keys from staged_configs map)
    for rel in staged_configs.keys() {
        let path = secrets::resolve_relative_candidate(home_dir, rel)?;
        if allow_home_path(&path) {
            if let Some(file) = home_root.open_regular(&path)? {
                files.push(SensitiveFile { path, file });
            }
        }
    }

    // SSH private keys
    let ssh_path = home_dir.join(".ssh");
    if allow_home_path(&ssh_path) {
        for (path, mut file) in home_root.open_regular_directory(&ssh_path)? {
            let mut content = String::new();
            file.read_to_string(&mut content)
                .map_err(|error| with_path("read SSH entry", &path, error))?;
            if content.contains("PRIVATE KEY") {
                file.seek(std::io::SeekFrom::Start(0))
                    .map_err(|error| with_path("rewind SSH entry", &path, error))?;
                files.push(SensitiveFile { path, file });
            }
        }
    }

    Ok(files)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn private_stage_dir(runtime_dir: &Path) -> io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    crate::sandbox::validate_private_runtime_dir(runtime_dir)
        .map_err(|error| with_path("validate private runtime directory", runtime_dir, error))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let pid = std::process::id();
    for attempt in 0..32 {
        let path = runtime_dir.join(format!("stage-{timestamp}-{pid}-{attempt}"));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(with_path("create staging directory", &path, error)),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique private staging directory",
    ))
}

fn write_private_file(path: &Path, content: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| with_path("create staged secret file", path, error))?;
    file.write_all(content)
        .map_err(|error| with_path("write staged secret file", path, error))?;
    file.sync_all()
        .map_err(|error| with_path("sync staged secret file", path, error))
}

fn staged_relative_path(path: &Path) -> io::Result<PathBuf> {
    use std::path::Component;

    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(component) => relative.push(component),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "sensitive file path contains unsupported traversal",
                ));
            }
        }
    }
    if relative.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sensitive file path has no filename",
        ));
    }
    Ok(relative)
}

fn read_regular_file(path: &Path) -> io::Result<String> {
    use std::io::Read;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| with_path("open sensitive file", path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| with_path("inspect opened sensitive file", path, error))?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("sensitive source is not a regular file: {}", path.display()),
        ));
    }
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|error| with_path("read sensitive file", path, error))?;
    Ok(content)
}

fn is_env_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn malformed_env(path: &Path, line: usize, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "malformed environment file {} at line {line}: {reason}",
            path.display()
        ),
    )
}

fn with_path(operation: &str, path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{operation} {}: {error}", path.display()),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
