//! CDM configuration — externalizes hardcoded defaults to `~/.cdm/config.json`
//! (or `CDM_CONFIG_PATH` if set).
//!
//! All fields use `#[serde(default)]` so a partial config file merges cleanly
//! with the built-in defaults. When no config file exists the defaults produce
//! identical behavior to the original hardcoded values.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::origin::Origin;
use crate::project::ProjectContext;

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CdmConfig {
    pub env: EnvConfig,
    pub paths: PathsConfig,
    pub secrets: SecretsConfig,
    pub guard: GuardConfig,
    pub proxy: ProxyConfig,
    pub vm: VmConfig,
}

// ---------------------------------------------------------------------------
// EnvConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvConfig {
    pub passthrough: Vec<String>,
    pub dangerous_prefixes: Vec<String>,
}

impl Default for EnvConfig {
    fn default() -> Self {
        EnvConfig {
            passthrough: vec![
                "PATH".into(),
                "HOME".into(),
                "USER".into(),
                "SHELL".into(),
                "TERM".into(),
                "LANG".into(),
                "LC_ALL".into(),
                "TZ".into(),
                "EDITOR".into(),
                "VISUAL".into(),
                "XDG_CONFIG_HOME".into(),
                "XDG_DATA_HOME".into(),
                "XDG_CACHE_HOME".into(),
                "TMPDIR".into(),
                "TEMP".into(),
                "TMP".into(),
                // Node.js config — not secrets, needed by AI tools
                "NODE_OPTIONS".into(),
                "NODE_ENV".into(),
            ],
            dangerous_prefixes: if cfg!(target_os = "macos") {
                vec!["DYLD_".into(), "LD_".into()]
            } else {
                vec!["LD_".into()]
            },
        }
    }
}

// ---------------------------------------------------------------------------
// PathsConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathsConfig {
    pub allow_ro: Vec<String>,
    pub allow_rw: Vec<String>,
    pub deny_read: Vec<String>,
    pub deny_write: Vec<String>,
    pub staged_configs: HashMap<String, String>,
}

impl Default for PathsConfig {
    fn default() -> Self {
        PathsConfig {
            allow_ro: Vec::new(),
            allow_rw: Vec::new(),
            deny_read: Vec::new(),
            // User-selected path policy is empty by default. Persistence-oriented
            // protections are owned by access.rs and activated only by --sec.
            deny_write: Vec::new(),
            staged_configs: {
                let mut m = HashMap::new();
                m.insert(
                    ".aws/credentials".into(),
                    "AWS_SHARED_CREDENTIALS_FILE".into(),
                );
                m.insert(".aws/config".into(), "AWS_CONFIG_FILE".into());
                m.insert(".docker/config.json".into(), "DOCKER_CONFIG".into());
                m.insert(".kube/config".into(), "KUBECONFIG".into());
                m.insert(".npmrc".into(), "NPM_CONFIG_USERCONFIG".into());
                m
            },
        }
    }
}

// ---------------------------------------------------------------------------
// SecretsConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecretsConfig {
    pub name_patterns: Vec<String>,
    pub min_length: usize,
    pub min_char_classes: usize,
    pub env_files: Vec<String>,
    /// Secret identifier (for example `OPENAI_API_KEY`) to allowed destination
    /// suffixes. Values are never used as identifiers and must not appear here.
    pub restore_destinations: HashMap<String, Vec<String>>,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        SecretsConfig {
            name_patterns: vec![
                "key".into(),
                "secret".into(),
                "token".into(),
                "bearer".into(),
                "password".into(),
                "passwd".into(),
                "credential".into(),
                "api_key".into(),
                "apikey".into(),
                "auth".into(),
                "private".into(),
                "access_key".into(),
                "oauth".into(),
            ],
            min_length: 16,
            min_char_classes: 2,
            env_files: vec![
                ".env".into(),
                ".env.local".into(),
                ".env.development".into(),
                ".env.production".into(),
                ".env.staging".into(),
                ".env.test".into(),
            ],
            restore_destinations: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// GuardConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GuardConfig {
    pub blocked_commands: Vec<BlockedCommandEntry>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedCommandEntry {
    /// Legacy field name for a tokenized preflight pattern. The first token
    /// matches an exact executable basename; it is not a string prefix and is
    /// not an execution-control security boundary.
    pub prefix: String,
    pub reason: String,
}

impl Default for GuardConfig {
    fn default() -> Self {
        GuardConfig {
            blocked_commands: vec![
                // Privilege escalation
                BlockedCommandEntry {
                    prefix: "sudo".into(),
                    reason: "privilege-escalation command refused by preflight policy".into(),
                },
                BlockedCommandEntry {
                    prefix: "su ".into(),
                    reason: "privilege-escalation command refused by preflight policy".into(),
                },
                BlockedCommandEntry {
                    prefix: "doas".into(),
                    reason: "privilege-escalation command refused by preflight policy".into(),
                },
                // Destructive filesystem operations
                BlockedCommandEntry {
                    prefix: "rm -rf /".into(),
                    reason: "recursive delete of root filesystem".into(),
                },
                BlockedCommandEntry {
                    prefix: "rm -fr /".into(),
                    reason: "recursive delete of root filesystem".into(),
                },
                // System control
                BlockedCommandEntry {
                    prefix: "shutdown".into(),
                    reason: "system-shutdown command refused by preflight policy".into(),
                },
                BlockedCommandEntry {
                    prefix: "reboot".into(),
                    reason: "system-reboot command refused by preflight policy".into(),
                },
                BlockedCommandEntry {
                    prefix: "halt".into(),
                    reason: "system-halt command refused by preflight policy".into(),
                },
                BlockedCommandEntry {
                    prefix: "poweroff".into(),
                    reason: "system-poweroff command refused by preflight policy".into(),
                },
                BlockedCommandEntry {
                    prefix: "init ".into(),
                    reason: "init-control command refused by preflight policy".into(),
                },
                BlockedCommandEntry {
                    prefix: "systemctl poweroff".into(),
                    reason: "system-poweroff command refused by preflight policy".into(),
                },
                BlockedCommandEntry {
                    prefix: "systemctl reboot".into(),
                    reason: "system-reboot command refused by preflight policy".into(),
                },
                // Disk/partition operations
                BlockedCommandEntry {
                    prefix: "mkfs".into(),
                    reason: "filesystem creation not allowed in sandbox".into(),
                },
                BlockedCommandEntry {
                    prefix: "fdisk".into(),
                    reason: "partition editing not allowed in sandbox".into(),
                },
                BlockedCommandEntry {
                    prefix: "dd if=".into(),
                    reason: "raw disk write not allowed in sandbox".into(),
                },
                // Container escape vectors
                BlockedCommandEntry {
                    prefix: "docker run --privileged".into(),
                    reason: "privileged-container command refused by preflight policy".into(),
                },
                BlockedCommandEntry {
                    prefix: "docker run -v /:/".into(),
                    reason: "root-volume command refused by preflight policy".into(),
                },
                // Namespace/sandbox escape
                BlockedCommandEntry {
                    prefix: "chroot".into(),
                    reason: "chroot command refused by preflight policy".into(),
                },
                BlockedCommandEntry {
                    prefix: "unshare".into(),
                    reason: "namespace command refused by preflight policy".into(),
                },
                BlockedCommandEntry {
                    prefix: "nsenter".into(),
                    reason: "namespace command refused by preflight policy".into(),
                },
                // Host cloud tooling. This catches direct operator mistakes;
                // child-process execution is constrained by enforceable
                // filesystem, network, and secret policies instead.
                BlockedCommandEntry {
                    prefix: "aws".into(),
                    reason: "AWS CLI direct invocation refused by preflight policy".into(),
                },
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// ProxyConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    pub default_port: u16,
    /// Opt in to proxy destinations that resolve to host-local or private IPs.
    pub allow_private_network: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            default_port: 18080,
            allow_private_network: false,
        }
    }
}

// ---------------------------------------------------------------------------
// VmConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct VmConfig {
    pub vcpus: u8,
    pub ram_mib: u32,
    pub max_layer_compressed_mib: u64,
    pub max_image_compressed_mib: u64,
    pub max_layer_expanded_mib: u64,
    pub max_image_expanded_mib: u64,
    pub max_layer_entries: u64,
    pub max_image_entries: u64,
    pub max_path_depth: usize,
}

impl Default for VmConfig {
    fn default() -> Self {
        VmConfig {
            vcpus: 2,
            ram_mib: 512,
            max_layer_compressed_mib: 512,
            max_image_compressed_mib: 2_048,
            max_layer_expanded_mib: 4_096,
            max_image_expanded_mib: 8_192,
            max_layer_entries: 250_000,
            max_image_entries: 1_000_000,
            max_path_depth: 128,
        }
    }
}

// ---------------------------------------------------------------------------
// Loading / saving
// ---------------------------------------------------------------------------

/// A configured filesystem path plus the directory from which a relative
/// spelling is resolved. `access.rs` remains the only module that performs the
/// actual resolution and canonicalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredPath {
    pub value: String,
    pub relative_to: PathBuf,
    pub origin: Origin,
}

#[derive(Debug, Clone, Default)]
pub struct ConfiguredPaths {
    pub allow_ro: Vec<ConfiguredPath>,
    pub allow_rw: Vec<ConfiguredPath>,
    pub deny_read: Vec<ConfiguredPath>,
    pub deny_write: Vec<ConfiguredPath>,
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub value: Arc<CdmConfig>,
    pub paths: ConfiguredPaths,
}

const TRUST_STORE_VERSION: u32 = 1;
const TRUST_STORE_FILE: &str = "trusted-projects.json";
const BUNDLED_PROFILE_WARNING: &str = "This is a CDM-managed bundled profile. CDM upgrades may overwrite this file. Extend or override it from a profile you own instead of editing it.";
const SETUP_BASE_WARNING: &str = "This is a CDM-managed base configuration. `cdm setup` may overwrite this file. Put user policy in `~/.cdm/config.json`.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltInProfile {
    pub id: &'static str,
    pub display_name: &'static str,
    pub executable: &'static str,
    pub markers: &'static [&'static str],
    pub allow_ro: &'static [&'static str],
    pub allow_rw: &'static [&'static str],
}

const BUILT_IN_PROFILES: &[BuiltInProfile] = &[
    BuiltInProfile {
        id: "pi",
        display_name: "Pi",
        executable: "pi",
        markers: &[".pi/agent"],
        allow_ro: &[".pi/agent", ".agents/skills"],
        allow_rw: &[
            ".pi/agent/auth.json",
            ".pi/agent/git",
            ".pi/agent/models-store.json",
            ".pi/agent/npm",
            ".pi/agent/pi-debug.log",
            ".pi/agent/sessions",
            ".pi/agent/settings.json",
            ".pi/agent/trust.json",
        ],
    },
    BuiltInProfile {
        id: "claude",
        display_name: "Claude Code",
        executable: "claude",
        markers: &[".claude", ".claude.json"],
        allow_ro: &[".claude"],
        allow_rw: &[
            ".claude.json",
            ".claude/backups",
            ".claude/cache",
            ".claude/debug",
            ".claude/history.jsonl",
            ".claude/plans",
            ".claude/projects",
            ".claude/session-env",
            ".claude/settings.json",
            ".claude/shell-snapshots",
            ".claude/statsig",
            ".claude/telemetry",
            ".claude/todos",
        ],
    },
    BuiltInProfile {
        id: "codex",
        display_name: "OpenAI Codex CLI",
        executable: "codex",
        markers: &[".codex"],
        allow_ro: &[".codex"],
        allow_rw: &[
            ".codex/.codex-global-state.json",
            ".codex/auth.json",
            ".codex/cache",
            ".codex/history.jsonl",
            ".codex/log",
            ".codex/logs",
            ".codex/sessions",
            ".codex/state_5.sqlite",
            ".codex/state_5.sqlite-shm",
            ".codex/state_5.sqlite-wal",
        ],
    },
    BuiltInProfile {
        id: "copilot",
        display_name: "GitHub Copilot CLI",
        executable: "copilot",
        markers: &[".copilot"],
        allow_ro: &[".copilot"],
        allow_rw: &[
            ".cache/copilot",
            ".copilot/command-history-state",
            ".copilot/config.json",
            ".copilot/ide",
            ".copilot/installed-plugins",
            ".copilot/logs",
            ".copilot/mcp-oauth-config",
            ".copilot/mcp-secrets",
            ".copilot/permissions-config.json",
            ".copilot/plugin-data",
            ".copilot/session-state",
            ".copilot/session-store.db",
            ".copilot/session-store.db-shm",
            ".copilot/session-store.db-wal",
            ".copilot/settings.json",
            "Library/Caches/copilot",
        ],
    },
];

pub fn built_in_profiles() -> &'static [BuiltInProfile] {
    BUILT_IN_PROFILES
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ConfigLayer {
    #[serde(rename = "_warning")]
    warning: Option<String>,
    #[serde(rename = "import")]
    imports: Vec<String>,
    #[serde(skip)]
    profile_id: Option<String>,
    env: Option<EnvLayer>,
    paths: Option<PathsLayer>,
    secrets: Option<SecretsLayer>,
    guard: Option<GuardLayer>,
    proxy: Option<ProxyLayer>,
    vm: Option<VmLayer>,
    presets: BTreeMap<String, ConfigLayer>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EnvLayer {
    passthrough: Option<Vec<String>>,
    dangerous_prefixes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PathsLayer {
    allow_ro: Option<Vec<String>>,
    allow_rw: Option<Vec<String>>,
    deny_read: Option<Vec<String>>,
    deny_write: Option<Vec<String>>,
    staged_configs: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SecretsLayer {
    name_patterns: Option<Vec<String>>,
    min_length: Option<usize>,
    min_char_classes: Option<usize>,
    env_files: Option<Vec<String>>,
    restore_destinations: Option<HashMap<String, Vec<String>>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GuardLayer {
    blocked_commands: Option<Vec<BlockedCommandEntry>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ProxyLayer {
    default_port: Option<u16>,
    allow_private_network: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VmLayer {
    vcpus: Option<u8>,
    ram_mib: Option<u32>,
    max_layer_compressed_mib: Option<u64>,
    max_image_compressed_mib: Option<u64>,
    max_layer_expanded_mib: Option<u64>,
    max_image_expanded_mib: Option<u64>,
    max_layer_entries: Option<u64>,
    max_image_entries: Option<u64>,
    max_path_depth: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustStore {
    version: u32,
    projects: BTreeMap<String, String>,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self {
            version: TRUST_STORE_VERSION,
            projects: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustReceipt {
    pub config_path: PathBuf,
    pub trust_store_path: PathBuf,
    pub sha256: String,
}

fn config_path() -> PathBuf {
    if let Some(path) = std::env::var_os("CDM_CONFIG_PATH") {
        return PathBuf::from(path);
    }
    let home = std::env::var_os("HOME").unwrap_or_else(|| "/root".into());
    PathBuf::from(home).join(".cdm").join("config.json")
}

/// Returns the config file path as a display string.
pub fn config_path_display() -> String {
    config_path().display().to_string()
}

/// Loads config from `CDM_CONFIG_PATH` (if set) or `~/.cdm/config.json`.
/// Falls back to defaults only when the file is missing. Invalid or
/// unreadable configuration is an error because silently weakening a
/// security policy would be surprising.
pub fn load_with_profiles(
    project: &ProjectContext,
    selected_profiles: &[String],
    selected_presets: &[String],
) -> io::Result<LoadedConfig> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    let trust_path = trust_store_path(&home);
    let global_path = absolute_path(&config_path())?;
    if std::env::var_os("CDM_CONFIG_PATH").is_some() {
        validate_custom_config_parent(&global_path, &home, &project.root)?;
    }
    load_from_paths_with_profiles(
        &global_path,
        project,
        &home,
        selected_profiles,
        selected_presets,
        &trust_path,
    )
}

fn load_layer(path: &std::path::Path) -> io::Result<Option<ConfigLayer>> {
    read_nofollow(path, false)?
        .map(|bytes| parse_layer(path, &bytes))
        .transpose()
}

fn load_setup_base_layer(home: &Path) -> io::Result<Option<ConfigLayer>> {
    let cdm = home.join(".cdm");
    let path = cdm.join("base.json");
    #[cfg(unix)]
    {
        let parent = match std::fs::symlink_metadata(&cdm) {
            Ok(parent) => parent,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if parent.file_type().is_symlink() || !parent.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "managed base parent must be a real directory: {}",
                    cdm.display()
                ),
            ));
        }
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                validate_existing_setup_directory(&cdm)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        }
    }
    #[cfg(unix)]
    let bytes = read_existing_managed_file(&path)?;
    #[cfg(not(unix))]
    let bytes = read_nofollow(&path, true)?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let document = serde_json::from_slice::<SetupBaseDocument>(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid managed base config {}: {error}", path.display()),
        )
    })?;
    validate_setup_base_document(&path, &document)?;
    parse_layer(&path, &bytes).map(Some)
}

#[cfg(test)]
fn load_from_paths(
    global_path: &std::path::Path,
    project: &ProjectContext,
    home: &std::path::Path,
    selected_presets: &[String],
    trust_path: &std::path::Path,
) -> io::Result<LoadedConfig> {
    load_from_paths_internal(
        global_path,
        project,
        home,
        &[],
        selected_presets,
        trust_path,
    )
}

fn load_from_paths_with_profiles(
    global_path: &std::path::Path,
    project: &ProjectContext,
    home: &std::path::Path,
    selected_profiles: &[String],
    selected_presets: &[String],
    trust_path: &std::path::Path,
) -> io::Result<LoadedConfig> {
    load_from_paths_internal(
        global_path,
        project,
        home,
        selected_profiles,
        selected_presets,
        trust_path,
    )
}

#[cfg(unix)]
fn profile_layers(
    home: &Path,
    imports: Vec<String>,
    paths: &mut ConfiguredPaths,
) -> io::Result<Vec<ConfigLayer>> {
    use crate::anchored::AnchoredRoot;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if imports.is_empty() {
        return Ok(Vec::new());
    }
    let root_path = home.join(".cdm/profiles");
    for directory in [home.join(".cdm"), root_path.clone()] {
        let metadata = std::fs::symlink_metadata(&directory).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "profile directory is missing: {}; run `cdm setup`",
                        directory.display()
                    ),
                )
            } else {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cannot inspect profile directory {}: {error}",
                        directory.display()
                    ),
                )
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "profile directory must be a real directory: {}",
                    directory.display()
                ),
            ));
        }
        if metadata.uid() != unsafe { libc::getuid() } || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "profile directory must be user-owned and not group/world writable: {}",
                    directory.display()
                ),
            ));
        }
    }
    let home_root = AnchoredRoot::open(home)?;
    let cdm_root = home_root.open_directory(&home.join(".cdm"))?;
    let root = cdm_root.open_directory(&root_path)?;
    let mut layers = Vec::new();
    let mut active = Vec::new();
    for import in imports {
        expand_profile_import(
            &root,
            &root_path,
            Path::new(""),
            &import,
            &mut active,
            &mut layers,
            paths,
        )?;
    }
    Ok(layers)
}

#[cfg(unix)]
fn expand_profile_import(
    root: &crate::anchored::AnchoredRoot,
    root_path: &Path,
    importing_directory: &Path,
    import: &str,
    active: &mut Vec<PathBuf>,
    layers: &mut Vec<ConfigLayer>,
    protected_paths: &mut ConfiguredPaths,
) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let (importing_directory, requested) = match import.strip_prefix("~/.cdm/profiles/") {
        Some(relative) => (Path::new(""), Path::new(relative)),
        None => (importing_directory, Path::new(import)),
    };
    if requested.is_absolute()
        || requested
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("profile import must be a contained relative path: {import:?}"),
        ));
    }
    let relative = importing_directory.join(requested);
    if let Some(position) = active.iter().position(|path| path == &relative) {
        let chain = active[position..]
            .iter()
            .chain(std::iter::once(&relative))
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(" -> ");
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("profile import cycle: {chain}"),
        ));
    }
    let path = root_path.join(&relative);
    let mut ancestor = root_path.to_path_buf();
    protect_policy_file(protected_paths, &ancestor);
    for component in relative.parent().unwrap_or(Path::new("")).components() {
        ancestor.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&ancestor).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot inspect profile directory {}: {error}",
                    ancestor.display()
                ),
            )
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != unsafe { libc::getuid() }
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "profile import has an unsafe directory: {}",
                    ancestor.display()
                ),
            ));
        }
        protect_policy_file(protected_paths, &ancestor);
    }
    let mut file = root.open_regular(&path)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "profile import is missing: {}; run `cdm setup` if it is bundled",
                path.display()
            ),
        )
    })?;
    let metadata = file.metadata()?;
    if metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("profile file must not have hard links: {}", path.display()),
        ));
    }
    if metadata.uid() != unsafe { libc::getuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "profile file is not owned by the current user: {}",
                path.display()
            ),
        ));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "profile file must not be group/world writable: {}",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let mut layer = parse_layer(&path, &bytes)?;
    if relative.parent() == Some(Path::new("bundled")) {
        if let Some(id) = relative.file_stem().and_then(|stem| stem.to_str()) {
            if built_in_profiles().iter().any(|profile| profile.id == id) {
                layer.profile_id = Some(id.to_owned());
            }
        }
    }
    protect_policy_file(protected_paths, &path);
    protect_policy_parent(protected_paths, &path);
    active.push(relative.clone());
    let directory = relative.parent().unwrap_or(Path::new(""));
    for nested in std::mem::take(&mut layer.imports) {
        expand_profile_import(
            root,
            root_path,
            directory,
            &nested,
            active,
            layers,
            protected_paths,
        )?;
    }
    active.pop();
    layers.push(layer);
    Ok(())
}

#[cfg(not(unix))]
fn profile_layers(
    _home: &Path,
    imports: Vec<String>,
    _paths: &mut ConfiguredPaths,
) -> io::Result<Vec<ConfigLayer>> {
    if imports.is_empty() {
        Ok(Vec::new())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure profile imports require a Unix host",
        ))
    }
}

fn document_layers(
    mut current: ConfigLayer,
    home: &Path,
    paths: &mut ConfiguredPaths,
) -> io::Result<Vec<ConfigLayer>> {
    let mut layers = profile_layers(home, std::mem::take(&mut current.imports), paths)?;
    layers.push(current);
    Ok(layers)
}

fn load_from_paths_internal(
    global_path: &std::path::Path,
    project: &ProjectContext,
    home: &std::path::Path,
    selected_profiles: &[String],
    selected_presets: &[String],
    trust_path: &std::path::Path,
) -> io::Result<LoadedConfig> {
    let base_path = home.join(".cdm/base.json");
    for path in [
        global_path,
        home,
        trust_path,
        project.root.as_path(),
        base_path.as_path(),
    ] {
        require_utf8_policy_path(path)?;
    }
    if let Some(path) = project.config_path.as_deref() {
        require_utf8_policy_path(path)?;
    }
    let mut value = CdmConfig::default();
    let mut paths = configured_defaults(&value.paths, home);
    protect_policy_file(&mut paths, &base_path);
    protect_policy_parent(&mut paths, &base_path);
    protect_policy_file(&mut paths, global_path);
    protect_policy_parent_if_narrow(&mut paths, global_path, home, &project.root);
    protect_policy_file(&mut paths, trust_path);
    protect_policy_parent(&mut paths, trust_path);

    if let Some(base_layer) = load_setup_base_layer(home)? {
        for layer in document_layers(base_layer, home, &mut paths)? {
            let origin = layer
                .profile_id
                .as_ref()
                .map(|id| Origin::Profile(id.clone()))
                .unwrap_or(Origin::Global);
            apply_layer(&mut value, &mut paths, layer, home, origin);
        }
    }

    let global_layer = load_layer(global_path)?.unwrap_or_default();
    let mut presets = BTreeMap::new();
    for mut layer in document_layers(global_layer, home, &mut paths)? {
        presets.extend(std::mem::take(&mut layer.presets));
        let origin = layer
            .profile_id
            .as_ref()
            .map(|id| Origin::Profile(id.clone()))
            .unwrap_or(Origin::Global);
        apply_layer(&mut value, &mut paths, layer, home, origin);
    }
    let mut applied_profiles = BTreeSet::new();
    for id in selected_profiles {
        if !built_in_profiles().iter().any(|profile| profile.id == id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown built-in profile {id:?}"),
            ));
        }
        if applied_profiles.insert(id.clone()) {
            for layer in profile_layers(home, vec![format!("bundled/{id}.json")], &mut paths)? {
                apply_layer(
                    &mut value,
                    &mut paths,
                    layer,
                    home,
                    Origin::Profile(id.clone()),
                );
            }
        }
    }
    for name in selected_presets {
        let preset = presets.get(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown preset {name:?} in {}", global_path.display()),
            )
        })?;
        if !preset.presets.is_empty() || !preset.imports.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("preset {name:?} must not contain imports or nested presets"),
            ));
        }
        apply_layer(
            &mut value,
            &mut paths,
            preset.clone(),
            home,
            Origin::Preset(name.clone()),
        );
    }
    if let Some(project_path) = project.config_path.as_deref() {
        protect_policy_file(&mut paths, project_path);
        protect_policy_parent(&mut paths, project_path);
        if project_path != global_path {
            let layer = load_trusted_project_layer(project_path, trust_path)?;
            let mut layers = document_layers(layer, home, &mut paths)?;
            if layers.iter().any(|layer| !layer.presets.is_empty()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "presets may be declared only in the global config",
                ));
            }
            let current = layers
                .pop()
                .expect("document layers include the current file");
            for imported in layers {
                let origin = imported
                    .profile_id
                    .as_ref()
                    .map(|id| Origin::Profile(id.clone()))
                    .unwrap_or(Origin::Project);
                apply_layer(&mut value, &mut paths, imported, home, origin);
            }
            apply_layer(
                &mut value,
                &mut paths,
                current,
                &project.root,
                Origin::Project,
            );
        }
    }

    Ok(LoadedConfig {
        value: Arc::new(value),
        paths,
    })
}

pub fn trust_project(project: &ProjectContext) -> io::Result<TrustReceipt> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    trust_project_in(project, &trust_store_path(&home))
}

fn trust_project_in(
    project: &ProjectContext,
    trust_path: &std::path::Path,
) -> io::Result<TrustReceipt> {
    let config_path = project.config_path.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no {} found from {}",
                crate::project::PROJECT_CONFIG,
                project.launch_dir.display()
            ),
        )
    })?;
    let bytes = read_nofollow(config_path, false)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("project config disappeared: {}", config_path.display()),
        )
    })?;
    let layer = parse_layer(config_path, &bytes)?;
    if !layer.presets.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "presets may be declared only in the global config",
        ));
    }
    let digest = sha256_hex(&bytes);
    let mut store = read_trust_store(trust_path)?;
    store
        .projects
        .insert(path_key(config_path)?, digest.clone());
    write_trust_store(trust_path, &store)?;
    Ok(TrustReceipt {
        config_path: config_path.to_path_buf(),
        trust_store_path: trust_path.to_path_buf(),
        sha256: digest,
    })
}

fn load_trusted_project_layer(
    project_path: &std::path::Path,
    trust_path: &std::path::Path,
) -> io::Result<ConfigLayer> {
    let bytes = read_nofollow(project_path, false)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("project config disappeared: {}", project_path.display()),
        )
    })?;
    let digest = sha256_hex(&bytes);
    let store = read_trust_store(trust_path)?;
    if store.projects.get(&path_key(project_path)?) != Some(&digest) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "project config is not trusted or has changed: {}; review it and run `cdm trust`",
                project_path.display()
            ),
        ));
    }
    parse_layer(project_path, &bytes)
}

fn parse_layer(path: &std::path::Path, bytes: &[u8]) -> io::Result<ConfigLayer> {
    serde_json::from_slice::<ConfigLayer>(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid config {}: {error}", path.display()),
        )
    })
}

fn trust_store_path(home: &std::path::Path) -> PathBuf {
    home.join(".cdm").join(TRUST_STORE_FILE)
}

fn absolute_path(path: &std::path::Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn protect_policy_file(paths: &mut ConfiguredPaths, path: &std::path::Path) {
    let value = path
        .to_str()
        .expect("policy paths are validated before protection");
    paths.deny_write.push(ConfiguredPath {
        value: value.to_string(),
        relative_to: PathBuf::new(),
        origin: Origin::Derived,
    });
}

fn protect_policy_parent(paths: &mut ConfiguredPaths, path: &std::path::Path) {
    if let Some(parent) = path.parent() {
        protect_policy_file(paths, parent);
    }
}

fn protect_policy_parent_if_narrow(
    paths: &mut ConfiguredPaths,
    path: &std::path::Path,
    home: &std::path::Path,
    project_root: &std::path::Path,
) {
    let Some(parent) = path.parent() else { return };
    let temp = std::env::temp_dir();
    let broad_roots = [
        PathBuf::from("/"),
        PathBuf::from("/tmp"),
        PathBuf::from("/private/tmp"),
        temp,
        home.to_path_buf(),
        project_root.to_path_buf(),
    ];
    if !broad_roots.iter().any(|root| parent == root) {
        protect_policy_file(paths, parent);
    }
}

#[cfg(unix)]
fn validate_custom_config_parent(
    path: &std::path::Path,
    home: &std::path::Path,
    project_root: &std::path::Path,
) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "CDM_CONFIG_PATH must have a dedicated parent directory",
        )
    })?;
    let broad_roots = [
        PathBuf::from("/"),
        PathBuf::from("/tmp"),
        PathBuf::from("/private/tmp"),
        std::env::temp_dir(),
        home.to_path_buf(),
        project_root.to_path_buf(),
    ];
    if broad_roots.iter().any(|root| parent == root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "CDM_CONFIG_PATH must be inside a dedicated policy directory, not {}",
                parent.display()
            ),
        ));
    }
    let metadata = std::fs::symlink_metadata(parent).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot inspect CDM_CONFIG_PATH directory {}: {error}",
                parent.display()
            ),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "CDM_CONFIG_PATH parent must be a real directory: {}",
                parent.display()
            ),
        ));
    }
    if metadata.uid() != unsafe { libc::getuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "CDM_CONFIG_PATH directory is not owned by the current user: {}",
                parent.display()
            ),
        ));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "CDM_CONFIG_PATH directory must not be group/world writable: {}",
                parent.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_custom_config_parent(
    _path: &std::path::Path,
    _home: &std::path::Path,
    _project_root: &std::path::Path,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure custom configuration requires a Unix host",
    ))
}

fn path_key(path: &std::path::Path) -> io::Result<String> {
    require_utf8_policy_path(path)?;
    Ok(path.to_str().expect("validated UTF-8 path").to_owned())
}

fn require_utf8_policy_path(path: &std::path::Path) -> io::Result<()> {
    if path.to_str().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "filesystem policy paths must be valid UTF-8",
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_trust_store(path: &std::path::Path) -> io::Result<TrustStore> {
    let Some(bytes) = read_nofollow(path, true)? else {
        return Ok(TrustStore::default());
    };
    let store = serde_json::from_slice::<TrustStore>(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid trust store {}: {error}", path.display()),
        )
    })?;
    if store.version != TRUST_STORE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported trust store version {}", store.version),
        ));
    }
    Ok(store)
}

#[cfg(unix)]
fn ensure_cdm_policy_directory(home: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    if !home.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HOME must be an absolute path for bundled profile state",
        ));
    }
    require_utf8_policy_path(home)?;
    let parent = home.join(".cdm");
    let metadata = match std::fs::symlink_metadata(&parent) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700).create(&parent)?;
            std::fs::symlink_metadata(&parent)?
        }
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "CDM policy directory must be a real directory: {}",
                parent.display()
            ),
        ));
    }
    if metadata.uid() != unsafe { libc::getuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "CDM policy directory is not owned by the current user: {}",
                parent.display()
            ),
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "CDM policy directory permissions must be 0700: {}",
                parent.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_cdm_policy_directory(_home: &std::path::Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure bundled profiles require a Unix host",
    ))
}

#[derive(Serialize)]
struct BundledProfileDocument<'a> {
    #[serde(rename = "_warning")]
    warning: &'static str,
    paths: BundledProfilePaths<'a>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SetupBaseDocument {
    #[serde(rename = "_warning")]
    warning: String,
    #[serde(rename = "import")]
    imports: Vec<String>,
}

#[derive(Serialize)]
struct BundledProfilePaths<'a> {
    allow_ro: &'a [&'static str],
    allow_rw: &'a [&'static str],
}

#[cfg(unix)]
fn ensure_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700).create(path)?;
            std::fs::symlink_metadata(path)?
        }
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "profile directory must be a real directory: {}",
                path.display()
            ),
        ));
    }
    if metadata.uid() != unsafe { libc::getuid() } || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "profile directory permissions must be 0700: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn atomic_private_write(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            let _ = read_nofollow(path, false)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("managed profile has no parent"))?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("profile.json");
    let temp = parent.join(format!(".{name}.{}.{nonce}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(data)?;
        file.sync_all()?;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn validate_setup_selection(selected_ids: &[String]) -> io::Result<Vec<&'static BuiltInProfile>> {
    let mut selected = Vec::with_capacity(selected_ids.len());
    let mut previous = None;
    for id in selected_ids {
        let index = built_in_profiles()
            .iter()
            .position(|profile| profile.id == id)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown built-in profile {id:?}"),
                )
            })?;
        if previous.is_some_and(|previous| index <= previous) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "setup profiles must be unique and in catalog order",
            ));
        }
        previous = Some(index);
        selected.push(&built_in_profiles()[index]);
    }
    Ok(selected)
}

fn validate_setup_base_document(path: &Path, base: &SetupBaseDocument) -> io::Result<()> {
    if base.warning != SETUP_BASE_WARNING {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to use unrecognized managed base config: {}",
                path.display()
            ),
        ));
    }
    let ids = base
        .imports
        .iter()
        .map(|import| {
            import
                .strip_prefix("bundled/")
                .and_then(|id| id.strip_suffix(".json"))
                .map(str::to_owned)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid managed base import {import:?}"),
                    )
                })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let profiles = validate_setup_selection(&ids)?;
    let expected = profiles
        .iter()
        .map(|profile| format!("bundled/{}.json", profile.id))
        .collect::<Vec<_>>();
    if base.imports != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid managed base imports in {}", path.display()),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_existing_setup_directory(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "setup directory must be a real directory: {}",
                path.display()
            ),
        ));
    }
    if metadata.uid() != unsafe { libc::getuid() } || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "setup directory permissions must be 0700: {}",
                path.display()
            ),
        ));
    }
    Ok(true)
}

#[cfg(unix)]
fn read_existing_managed_file(path: &Path) -> io::Result<Option<Vec<u8>>> {
    use std::os::unix::fs::PermissionsExt;

    let Some(bytes) = read_nofollow(path, true)? else {
        return Ok(None);
    };
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("managed file permissions must be 0600: {}", path.display()),
        ));
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn validate_existing_setup_state(home: &Path) -> io::Result<()> {
    let cdm = home.join(".cdm");
    if !validate_existing_setup_directory(&cdm)? {
        return Ok(());
    }
    let base_path = cdm.join("base.json");
    if let Some(bytes) = read_existing_managed_file(&base_path)? {
        let base = serde_json::from_slice::<SetupBaseDocument>(&bytes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid managed base config {}: {error}",
                    base_path.display()
                ),
            )
        })?;
        validate_setup_base_document(&base_path, &base)?;
    }

    let profiles = cdm.join("profiles");
    if !validate_existing_setup_directory(&profiles)? {
        return Ok(());
    }
    let bundled = profiles.join("bundled");
    if !validate_existing_setup_directory(&bundled)? {
        return Ok(());
    }
    for profile in built_in_profiles() {
        let _ = read_existing_managed_file(&bundled.join(format!("{}.json", profile.id)))?;
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn materialize_setup_selection_in(
    home: &Path,
    selected_ids: &[String],
) -> io::Result<()> {
    if !home.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HOME must be an absolute path for bundled profile state",
        ));
    }
    require_utf8_policy_path(home)?;
    let selected = validate_setup_selection(selected_ids)?;
    validate_existing_setup_state(home)?;
    ensure_cdm_policy_directory(home)?;
    let profiles = home.join(".cdm/profiles");
    let bundled = profiles.join("bundled");
    ensure_private_directory(&profiles)?;
    ensure_private_directory(&bundled)?;

    for profile in &selected {
        let document = BundledProfileDocument {
            warning: BUNDLED_PROFILE_WARNING,
            paths: BundledProfilePaths {
                allow_ro: profile.allow_ro,
                allow_rw: profile.allow_rw,
            },
        };
        let mut data = serde_json::to_vec_pretty(&document).map_err(io::Error::other)?;
        data.push(b'\n');
        atomic_private_write(&bundled.join(format!("{}.json", profile.id)), &data)?;
    }

    let base = SetupBaseDocument {
        warning: SETUP_BASE_WARNING.to_owned(),
        imports: selected
            .iter()
            .map(|profile| format!("bundled/{}.json", profile.id))
            .collect(),
    };
    let mut data = serde_json::to_vec_pretty(&base).map_err(io::Error::other)?;
    data.push(b'\n');
    atomic_private_write(&home.join(".cdm/base.json"), &data)?;

    for profile in built_in_profiles() {
        if !selected.iter().any(|selected| selected.id == profile.id) {
            let path = bundled.join(format!("{}.json", profile.id));
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "cannot remove deselected profile {}: {error}",
                            path.display()
                        ),
                    ))
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn materialize_setup_selection_in(
    _home: &Path,
    _selected_ids: &[String],
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure bundled profiles require a Unix host",
    ))
}

#[cfg(unix)]
fn read_nofollow(path: &std::path::Path, require_private: bool) -> io::Result<Option<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("cannot securely open {}: {error}", path.display()),
            ))
        }
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("policy path is not a regular file: {}", path.display()),
        ));
    }
    if metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("policy file must not have hard links: {}", path.display()),
        ));
    }
    if require_private {
        if metadata.uid() != unsafe { libc::getuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "private policy file is not owned by the current user: {}",
                    path.display()
                ),
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "private policy file permissions must be 0600: {}",
                    path.display()
                ),
            ));
        }
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

#[cfg(not(unix))]
fn read_nofollow(_path: &std::path::Path, _require_private: bool) -> io::Result<Option<Vec<u8>>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure project trust requires a Unix host",
    ))
}

#[cfg(unix)]
fn write_trust_store(path: &std::path::Path, store: &TrustStore) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("trust store has no parent"))?;
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "trust store directory is not a real directory: {}",
                    parent.display()
                ),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(parent)?;
        }
        Err(error) => return Err(error),
    }
    if path.exists() {
        let _ = read_nofollow(path, true)?;
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = parent.join(format!(
        ".{TRUST_STORE_FILE}.{}.{nonce}.tmp",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        let data = serde_json::to_vec_pretty(store).map_err(io::Error::other)?;
        file.write_all(&data)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(not(unix))]
fn write_trust_store(_path: &std::path::Path, _store: &TrustStore) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure project trust requires a Unix host",
    ))
}

fn configured_defaults(paths: &PathsConfig, home: &std::path::Path) -> ConfiguredPaths {
    ConfiguredPaths {
        allow_ro: configured(&paths.allow_ro, home),
        allow_rw: configured(&paths.allow_rw, home),
        deny_read: configured(&paths.deny_read, home),
        deny_write: configured(&paths.deny_write, home),
    }
}

fn configured(values: &[String], relative_to: &std::path::Path) -> Vec<ConfiguredPath> {
    values
        .iter()
        .map(|value| ConfiguredPath {
            value: value.clone(),
            relative_to: relative_to.to_path_buf(),
            origin: Origin::Default,
        })
        .collect()
}

fn apply_layer(
    target: &mut CdmConfig,
    configured_paths: &mut ConfiguredPaths,
    layer: ConfigLayer,
    relative_to: &std::path::Path,
    origin: Origin,
) {
    if let Some(env) = layer.env {
        if let Some(value) = env.passthrough {
            target.env.passthrough = value;
        }
        if let Some(value) = env.dangerous_prefixes {
            target.env.dangerous_prefixes = value;
        }
    }
    if let Some(paths) = layer.paths {
        append_paths(
            &mut target.paths.allow_ro,
            &mut configured_paths.allow_ro,
            paths.allow_ro,
            relative_to,
            &origin,
        );
        append_paths(
            &mut target.paths.allow_rw,
            &mut configured_paths.allow_rw,
            paths.allow_rw,
            relative_to,
            &origin,
        );
        append_paths(
            &mut target.paths.deny_read,
            &mut configured_paths.deny_read,
            paths.deny_read,
            relative_to,
            &origin,
        );
        append_paths(
            &mut target.paths.deny_write,
            &mut configured_paths.deny_write,
            paths.deny_write,
            relative_to,
            &origin,
        );
        if let Some(values) = paths.staged_configs {
            target.paths.staged_configs.extend(values);
        }
    }
    if let Some(secrets) = layer.secrets {
        if let Some(value) = secrets.name_patterns {
            target.secrets.name_patterns = value;
        }
        if let Some(value) = secrets.min_length {
            target.secrets.min_length = value;
        }
        if let Some(value) = secrets.min_char_classes {
            target.secrets.min_char_classes = value;
        }
        if let Some(value) = secrets.env_files {
            target.secrets.env_files = value;
        }
        if let Some(values) = secrets.restore_destinations {
            target.secrets.restore_destinations.extend(values);
        }
    }
    if let Some(guard) = layer.guard {
        if let Some(value) = guard.blocked_commands {
            target.guard.blocked_commands = value;
        }
    }
    if let Some(proxy) = layer.proxy {
        if let Some(value) = proxy.default_port {
            target.proxy.default_port = value;
        }
        if let Some(value) = proxy.allow_private_network {
            target.proxy.allow_private_network = value;
        }
    }
    if let Some(vm) = layer.vm {
        if let Some(value) = vm.vcpus {
            target.vm.vcpus = value;
        }
        if let Some(value) = vm.ram_mib {
            target.vm.ram_mib = value;
        }
        if let Some(value) = vm.max_layer_compressed_mib {
            target.vm.max_layer_compressed_mib = value;
        }
        if let Some(value) = vm.max_image_compressed_mib {
            target.vm.max_image_compressed_mib = value;
        }
        if let Some(value) = vm.max_layer_expanded_mib {
            target.vm.max_layer_expanded_mib = value;
        }
        if let Some(value) = vm.max_image_expanded_mib {
            target.vm.max_image_expanded_mib = value;
        }
        if let Some(value) = vm.max_layer_entries {
            target.vm.max_layer_entries = value;
        }
        if let Some(value) = vm.max_image_entries {
            target.vm.max_image_entries = value;
        }
        if let Some(value) = vm.max_path_depth {
            target.vm.max_path_depth = value;
        }
    }
}

fn append_paths(
    target: &mut Vec<String>,
    configured_paths: &mut Vec<ConfiguredPath>,
    values: Option<Vec<String>>,
    relative_to: &std::path::Path,
    origin: &Origin,
) {
    let Some(values) = values else { return };
    for value in values {
        if !target.contains(&value) {
            target.push(value.clone());
        }
        configured_paths.push(ConfiguredPath {
            value,
            relative_to: relative_to.to_path_buf(),
            origin: origin.clone(),
        });
    }
}

/// Writes the default configuration to `~/.cdm/config.json`.
/// Creates the `~/.cdm/` directory if it doesn't exist.
pub fn save_default() -> io::Result<()> {
    let path = config_path();
    if std::env::var_os("CDM_CONFIG_PATH").is_some() {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/root"));
        let current = std::env::current_dir()?;
        validate_custom_config_parent(&absolute_path(&path)?, &home, &current)?;
    }
    save_default_to(&path)
}

fn save_default_to(path: &std::path::Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(parent)?;
    }
    let cfg = CdmConfig::default();
    let json = serde_json::to_string_pretty(&cfg).map_err(io::Error::other)?;
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(
                    error.kind(),
                    format!("config already exists: {}", path.display()),
                )
            } else {
                error
            }
        })?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
