//! Filesystem access policy shared by every sandbox adapter.

#[cfg(test)]
use crate::config::PathsConfig;
use crate::config::{ConfiguredPath, ConfiguredPaths};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceAccess {
    ReadWrite,
    ReadOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAccess {
    Normal,
    Isolated,
}

impl HostAccess {
    pub fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Isolated => "isolated",
        }
    }
}

impl WorkspaceAccess {
    pub fn label(self) -> &'static str {
        match self {
            Self::ReadWrite => "rw",
            Self::ReadOnly => "ro",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessPolicy {
    pub workspace: WorkspaceAccess,
    pub host: HostAccess,
    secure_persistence: bool,
    config_allow_ro: Vec<ConfiguredPath>,
    config_allow_rw: Vec<ConfiguredPath>,
    config_deny_read: Vec<ConfiguredPath>,
    config_deny_write: Vec<ConfiguredPath>,
    cli_allow_ro: Vec<PathBuf>,
    cli_allow_rw: Vec<PathBuf>,
    discovered_allow_ro: Vec<PathBuf>,
    discovered_allow_rw: Vec<PathBuf>,
    runtime_deny_write: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ResolvedAccessPolicy {
    pub workspace: WorkspaceAccess,
    pub host: HostAccess,
    pub work_dir: PathBuf,
    pub allow_ro: Vec<PathBuf>,
    pub allow_rw: Vec<PathBuf>,
    pub deny_read_rules: Vec<ResolvedDenyRule>,
    pub deny_write_rules: Vec<ResolvedDenyRule>,
    pub runtime_ro: Vec<PathBuf>,
    #[cfg_attr(not(any(feature = "vm", test)), allow(dead_code))]
    path_kinds: BTreeMap<PathBuf, DeniedPathKind>,
    path_identities: BTreeMap<PathBuf, Option<PathIdentity>>,
    /// Host runtime trees replaced by empty, synthetic directories by adapters.
    /// These are policy decisions, not adapter-specific heuristics.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub synthetic_dirs: Vec<PathBuf>,
    /// Canonical, ancestor-collapsed mount targets captured with the policy.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub synthetic_mounts: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DenyOrigin {
    Builtin,
    SecurePersistence,
    Configured,
    Sensitive,
    RuntimeCache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeniedPathKind {
    Missing,
    File,
    Directory,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathIdentity {
    device: u64,
    inode: u64,
    kind: DeniedPathKind,
}

/// A hard denial resolved at a single point in time. Both path spellings are
/// retained because denying only a symlink's target leaves its lexical name
/// available for replacement, while denying only the name leaves the target
/// reachable through another alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDenyRule {
    pub lexical: PathBuf,
    pub canonical: Option<PathBuf>,
    pub lexical_exists: bool,
    pub exists: bool,
    pub kind: DeniedPathKind,
    pub origin: DenyOrigin,
    /// Missing ancestor directories captured during resolution, ordered from
    /// shallowest to deepest. Namespace adapters may create these as private
    /// mount-point placeholders before masking the protected leaf.
    pub missing_parents: Vec<PathBuf>,
}

impl ResolvedAccessPolicy {
    #[cfg_attr(not(any(feature = "vm", test)), allow(dead_code))]
    pub fn kind(&self, path: &Path) -> Option<DeniedPathKind> {
        self.path_kinds.get(path).copied()
    }

    pub fn verify_identities(&self) -> io::Result<()> {
        for (path, expected) in &self.path_identities {
            let current = path_identity_optional(path).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("resolved filesystem path changed before launch: {error}"),
                )
            })?;
            if &current != expected {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "resolved filesystem path identity changed before launch",
                ));
            }
        }
        Ok(())
    }

    #[cfg(any(feature = "vm", test))]
    pub fn denies_read(&self, path: &Path) -> bool {
        self.deny_read_rules
            .iter()
            .flat_map(ResolvedDenyRule::paths)
            .any(|denied| denied == path)
    }

    #[cfg(any(feature = "vm", test))]
    pub fn denies_write(&self, path: &Path) -> bool {
        self.deny_write_rules
            .iter()
            .flat_map(ResolvedDenyRule::paths)
            .any(|denied| denied == path)
    }
}

impl ResolvedDenyRule {
    pub fn paths(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.lexical.as_path()).chain(
            self.canonical
                .as_deref()
                .filter(|canonical| *canonical != self.lexical),
        )
    }
}

impl AccessPolicy {
    #[cfg(test)]
    pub fn new(paths: &PathsConfig) -> Self {
        let home_relative = |values: &[String]| {
            values
                .iter()
                .map(|value| ConfiguredPath {
                    value: value.clone(),
                    relative_to: PathBuf::new(),
                })
                .collect()
        };
        Self {
            workspace: WorkspaceAccess::ReadWrite,
            host: HostAccess::Normal,
            secure_persistence: false,
            config_allow_ro: home_relative(&paths.allow_ro),
            config_allow_rw: home_relative(&paths.allow_rw),
            config_deny_read: home_relative(&paths.deny_read),
            config_deny_write: home_relative(&paths.deny_write),
            cli_allow_ro: Vec::new(),
            cli_allow_rw: Vec::new(),
            discovered_allow_ro: Vec::new(),
            discovered_allow_rw: Vec::new(),
            runtime_deny_write: Vec::new(),
        }
    }

    pub fn from_configured_paths(paths: &ConfiguredPaths) -> Self {
        Self {
            workspace: WorkspaceAccess::ReadWrite,
            host: HostAccess::Normal,
            secure_persistence: false,
            config_allow_ro: paths.allow_ro.clone(),
            config_allow_rw: paths.allow_rw.clone(),
            config_deny_read: paths.deny_read.clone(),
            config_deny_write: paths.deny_write.clone(),
            cli_allow_ro: Vec::new(),
            cli_allow_rw: Vec::new(),
            discovered_allow_ro: Vec::new(),
            discovered_allow_rw: Vec::new(),
            runtime_deny_write: Vec::new(),
        }
    }

    pub fn set_secure(&mut self, secure: bool) {
        self.secure_persistence = secure;
    }

    pub fn add_allow_ro(&mut self, path: PathBuf) {
        self.cli_allow_ro.push(path);
    }

    pub fn add_allow_rw(&mut self, path: PathBuf) {
        self.cli_allow_rw.push(path);
    }

    /// Adds an application-owned path discovered from trusted bundle metadata.
    /// Unlike a CLI grant, the path may not exist until the application starts.
    pub(crate) fn add_discovered_ro(&mut self, path: PathBuf) {
        self.discovered_allow_ro.push(path);
    }

    pub(crate) fn add_discovered_rw(&mut self, path: PathBuf) {
        self.discovered_allow_rw.push(path);
    }

    /// Adds an invocation-owned control path that the sandboxed child must
    /// never mutate, even when it is nested beneath a writable workspace.
    pub(crate) fn add_runtime_deny_write(&mut self, path: PathBuf) {
        self.runtime_deny_write.push(path);
    }

    pub fn resolve(
        &self,
        work_dir: &Path,
        home_dir: &Path,
        sensitive_paths: &[PathBuf],
        command: &[OsString],
    ) -> io::Result<ResolvedAccessPolicy> {
        let work_dir = canonicalize_required(work_dir, "workspace")?;
        let home_dir = canonicalize_required(home_dir, "home directory")?;

        let mut allow_ro = resolve_grants(
            self.config_allow_ro
                .iter()
                .map(|path| resolve_config_path(path, &home_dir))
                .chain(
                    self.cli_allow_ro
                        .iter()
                        .map(|path| resolve_path(path, &work_dir, &home_dir)),
                ),
            &work_dir,
        )?;
        let mut allow_rw = resolve_grants(
            self.config_allow_rw
                .iter()
                .map(|path| resolve_config_path(path, &home_dir))
                .chain(
                    self.cli_allow_rw
                        .iter()
                        .map(|path| resolve_path(path, &work_dir, &home_dir)),
                ),
            &work_dir,
        )?;
        dedup_paths(&mut allow_ro);
        dedup_paths(&mut allow_rw);
        allow_ro.extend(self.discovered_allow_ro.iter().cloned());
        allow_rw.extend(self.discovered_allow_rw.iter().cloned());
        normalize_existing_paths(&mut allow_ro);
        normalize_existing_paths(&mut allow_rw);

        let cache_root = effective_cache_root(&home_dir)?;
        let mut deny_sources = resolve_optional_paths(&self.config_deny_read, &home_dir)
            .into_iter()
            .map(|path| (path, DenyOrigin::Configured))
            .chain(
                sensitive_paths
                    .iter()
                    .cloned()
                    .map(|path| (path, DenyOrigin::Sensitive)),
            )
            .collect::<Vec<_>>();
        #[cfg(target_os = "linux")]
        deny_sources.extend(
            linux_socket_deputy_paths(&home_dir)
                .into_iter()
                .map(|path| (path, DenyOrigin::Builtin)),
        );
        deny_sources.push((cache_root.clone(), DenyOrigin::RuntimeCache));
        let deny_read_rules = resolve_denials(deny_sources);

        let mut deny_sources = resolve_optional_paths(&self.config_deny_write, &home_dir)
            .into_iter()
            .map(|path| (path, DenyOrigin::Configured))
            .chain(
                sensitive_paths
                    .iter()
                    .cloned()
                    .map(|path| (path, DenyOrigin::Sensitive)),
            )
            .collect::<Vec<_>>();
        deny_sources.extend(
            self.runtime_deny_write
                .iter()
                .cloned()
                .map(|path| (path, DenyOrigin::Builtin)),
        );
        if self.secure_persistence {
            deny_sources.extend(
                secure_persistence_paths(&work_dir, &home_dir)
                    .into_iter()
                    .map(|path| (path, DenyOrigin::SecurePersistence)),
            );
        }
        #[cfg(target_os = "linux")]
        deny_sources.extend(
            linux_socket_deputy_paths(&home_dir)
                .into_iter()
                .map(|path| (path, DenyOrigin::Builtin)),
        );
        deny_sources.push((cache_root, DenyOrigin::RuntimeCache));
        let deny_write_rules = resolve_denials(deny_sources);
        let mut runtime_ro = runtime_roots();
        if let Some(executable) = resolve_executable(command.first().map(OsString::as_os_str)) {
            runtime_ro.push(executable);
        }
        normalize_existing_paths(&mut runtime_ro);
        let mut synthetic_dirs = synthetic_host_dirs();
        #[cfg(target_os = "linux")]
        if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
            let runtime = PathBuf::from(runtime);
            if runtime.is_absolute() {
                synthetic_dirs.push(runtime);
            }
        }
        for path in &mut synthetic_dirs {
            *path = lexical_normalize(path);
        }
        dedup_paths(&mut synthetic_dirs);
        let mut synthetic_mounts = synthetic_dirs
            .iter()
            .map(|path| path.canonicalize().unwrap_or_else(|_| path.clone()))
            .collect::<Vec<_>>();
        dedup_paths(&mut synthetic_mounts);
        let mut collapsed = Vec::<PathBuf>::new();
        for path in synthetic_mounts {
            if !collapsed.iter().any(|ancestor| path.starts_with(ancestor)) {
                collapsed.push(path);
            }
        }
        let synthetic_mounts = collapsed;

        validate_policy_paths(
            [&work_dir, &home_dir]
                .into_iter()
                .chain(allow_ro.iter())
                .chain(allow_rw.iter())
                .chain(runtime_ro.iter())
                .chain(synthetic_dirs.iter())
                .chain(synthetic_mounts.iter())
                .map(PathBuf::as_path)
                .chain(deny_read_rules.iter().flat_map(ResolvedDenyRule::paths))
                .chain(deny_write_rules.iter().flat_map(ResolvedDenyRule::paths))
                .chain(
                    deny_read_rules
                        .iter()
                        .chain(&deny_write_rules)
                        .flat_map(|rule| rule.missing_parents.iter().map(PathBuf::as_path)),
                ),
        )?;
        let path_kinds: BTreeMap<PathBuf, DeniedPathKind> = [&work_dir]
            .into_iter()
            .chain(allow_ro.iter())
            .chain(allow_rw.iter())
            .chain(runtime_ro.iter())
            .map(|path| (path.clone(), path_kind(path)))
            .collect();
        let mut path_identities = BTreeMap::new();
        for path in [&work_dir]
            .into_iter()
            .chain(allow_ro.iter())
            .chain(allow_rw.iter())
            .chain(runtime_ro.iter())
        {
            path_identities.insert(path.clone(), path_identity_optional(path)?);
        }

        Ok(ResolvedAccessPolicy {
            workspace: self.workspace,
            host: self.host,
            work_dir,
            allow_ro,
            allow_rw,
            deny_read_rules,
            deny_write_rules,
            runtime_ro,
            path_kinds,
            path_identities,
            synthetic_dirs,
            synthetic_mounts,
        })
    }

    /// Whether an explicit grant authorizes trusted-host discovery of `path`.
    pub fn explicitly_grants(&self, path: &Path, work_dir: &Path, home_dir: &Path) -> bool {
        let Ok(path) = path.canonicalize() else {
            return false;
        };
        self.config_allow_ro
            .iter()
            .chain(&self.config_allow_rw)
            .map(|grant| resolve_config_path(grant, home_dir))
            .chain(
                self.cli_allow_ro
                    .iter()
                    .map(|grant| resolve_path(grant, work_dir, home_dir)),
            )
            .chain(
                self.cli_allow_rw
                    .iter()
                    .map(|grant| resolve_path(grant, work_dir, home_dir)),
            )
            .chain(self.discovered_allow_ro.iter().cloned())
            .chain(self.discovered_allow_rw.iter().cloned())
            .filter_map(|grant| grant.canonicalize().ok())
            .any(|grant| path == grant || path.starts_with(grant))
    }
}

fn validate_policy_paths<'a>(paths: impl IntoIterator<Item = &'a Path>) -> io::Result<()> {
    if paths.into_iter().any(|path| path.to_str().is_none()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "filesystem policy paths must be valid UTF-8",
        ));
    }
    Ok(())
}

fn path_kind(path: &Path) -> DeniedPathKind {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => DeniedPathKind::File,
        Ok(metadata) if metadata.is_dir() => DeniedPathKind::Directory,
        Ok(_) => DeniedPathKind::Other,
        Err(_) => DeniedPathKind::Missing,
    }
}

fn path_identity(path: &Path) -> io::Result<PathIdentity> {
    let metadata = std::fs::metadata(path)?;
    Ok(PathIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        kind: if metadata.is_file() {
            DeniedPathKind::File
        } else if metadata.is_dir() {
            DeniedPathKind::Directory
        } else {
            DeniedPathKind::Other
        },
    })
}

fn path_identity_optional(path: &Path) -> io::Result<Option<PathIdentity>> {
    match path_identity(path) {
        Ok(identity) => Ok(Some(identity)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

const SECURE_HOME_WRITE_DENIALS: &[&str] = &[
    // Shell startup and logout files.
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".zlogout",
    ".profile",
    // Git and command/tool configuration.
    ".gitconfig",
    ".gitmodules",
    ".git/hooks",
    ".ripgreprc",
    ".mcp.json",
    // SSH access and client behavior.
    ".ssh/authorized_keys",
    ".ssh/authorized_keys2",
    ".ssh/config",
    // Agent-controlled host execution hooks.
    ".claude/commands",
    ".claude/agents",
    ".claude/hooks",
    ".cursor/hooks",
    ".codex/hooks",
    // Editor configuration that can execute tasks or alter trusted tooling.
    ".vscode",
    ".idea",
];

const SECURE_WORKSPACE_WRITE_DENIALS: &[&str] = &[
    ".gitmodules",
    ".ripgreprc",
    ".mcp.json",
    ".git/hooks",
    ".claude/commands",
    ".claude/agents",
    ".claude/hooks",
    ".cursor/hooks",
    ".codex/hooks",
    ".vscode",
    ".idea",
];

/// Returns persistence-capable control paths protected by `--sec`.
///
/// Workspace entries are exact and existing-only: a protected basename in a
/// nested fixture or Git worktree remains ordinary workspace content, and a
/// missing optional control file does not make a writable VM export unusable.
fn secure_persistence_paths(work_dir: &Path, home_dir: &Path) -> Vec<PathBuf> {
    let mut paths = SECURE_HOME_WRITE_DENIALS
        .iter()
        .map(|relative| home_dir.join(relative))
        .collect::<Vec<_>>();
    paths.extend([
        PathBuf::from("/var/spool/cron"),
        PathBuf::from("/etc/crontab"),
    ]);
    paths.extend(
        SECURE_WORKSPACE_WRITE_DENIALS
            .iter()
            .map(|relative| work_dir.join(relative))
            .filter(|path| std::fs::symlink_metadata(path).is_ok()),
    );
    paths
}

fn resolve_denials(
    paths: impl IntoIterator<Item = (PathBuf, DenyOrigin)>,
) -> Vec<ResolvedDenyRule> {
    let mut rules = paths
        .into_iter()
        .map(|(path, origin)| {
            let lexical = lexical_normalize(&path);
            let canonical = canonicalize_allow_missing(&lexical);
            let lexical_exists = std::fs::symlink_metadata(&lexical).is_ok();
            let kind = match std::fs::metadata(&lexical) {
                Ok(metadata) if metadata.is_file() => DeniedPathKind::File,
                Ok(metadata) if metadata.is_dir() => DeniedPathKind::Directory,
                Ok(_) => DeniedPathKind::Other,
                Err(_) => DeniedPathKind::Missing,
            };
            let mut missing_parents = missing_parent_directories(&lexical);
            if let Some(canonical) = canonical.as_deref() {
                missing_parents.extend(missing_parent_directories(canonical));
                dedup_paths(&mut missing_parents);
            }
            ResolvedDenyRule {
                lexical,
                canonical,
                lexical_exists,
                exists: kind != DeniedPathKind::Missing,
                kind,
                origin,
                missing_parents,
            }
        })
        .collect::<Vec<_>>();
    rules.sort_by(|left, right| (&left.lexical, left.origin).cmp(&(&right.lexical, right.origin)));
    rules.dedup_by(|left, right| left.lexical == right.lexical && left.origin == right.origin);
    rules
}

fn canonicalize_allow_missing(path: &Path) -> Option<PathBuf> {
    canonicalize_allow_missing_inner(path, 0)
}

fn canonicalize_allow_missing_inner(path: &Path, depth: usize) -> Option<PathBuf> {
    if depth >= 40 {
        return None;
    }
    if std::fs::symlink_metadata(path)
        .ok()
        .is_some_and(|metadata| metadata.file_type().is_symlink())
    {
        let target = std::fs::read_link(path).ok()?;
        let target = if target.is_absolute() {
            target
        } else {
            path.parent()?.join(target)
        };
        return canonicalize_allow_missing_inner(&lexical_normalize(&target), depth + 1);
    }
    let mut existing = path;
    let mut suffix = Vec::new();
    while !existing.exists() {
        suffix.push(existing.file_name()?.to_os_string());
        existing = existing.parent()?;
    }
    let mut canonical = existing.canonicalize().ok()?;
    for component in suffix.iter().rev() {
        canonical.push(component);
    }
    Some(canonical)
}

fn missing_parent_directories(path: &Path) -> Vec<PathBuf> {
    let mut missing = Vec::new();
    let mut parent = path.parent();
    while let Some(candidate) = parent {
        if candidate.exists() {
            break;
        }
        missing.push(candidate.to_path_buf());
        parent = candidate.parent();
    }
    missing.reverse();
    missing
}

#[cfg(test)]
fn flatten_denials(rules: &[ResolvedDenyRule]) -> Vec<PathBuf> {
    let mut paths = rules
        .iter()
        .flat_map(|rule| rule.paths().map(Path::to_path_buf))
        .collect::<Vec<_>>();
    dedup_paths(&mut paths);
    paths
}

fn effective_cache_root(home: &Path) -> io::Result<PathBuf> {
    validate_custom_cache_root(std::env::var_os("CDM_CACHE_DIR").map(PathBuf::from), home)
}

fn validate_custom_cache_root(root: Option<PathBuf>, home: &Path) -> io::Result<PathBuf> {
    let root = root.unwrap_or_else(|| home.join(".cdm"));
    if !root.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CDM_CACHE_DIR must be an absolute path",
        ));
    }
    Ok(lexical_normalize(&root).join("rootfs"))
}

fn resolve_grants(
    grants: impl IntoIterator<Item = PathBuf>,
    _work_dir: &Path,
) -> io::Result<Vec<PathBuf>> {
    grants
        .into_iter()
        .map(|path| {
            let canonical = canonicalize_required(&path, "allowed path")?;
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::FileTypeExt;
                if std::fs::symlink_metadata(&canonical)?.file_type().is_socket() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "allowed path {} is a Unix socket; host sockets cannot be delegated into the sandbox",
                            path.display()
                        ),
                    ));
                }
            }
            #[cfg(target_os = "linux")]
            if synthetic_host_dirs()
                .iter()
                .filter_map(|root| root.canonicalize().ok())
                .any(|root| canonical == root || canonical.starts_with(root))
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "allowed path {} is inside a protected host runtime tree",
                        path.display()
                    ),
                ));
            }
            Ok(canonical)
        })
        .collect()
}

fn resolve_optional_paths(values: &[ConfiguredPath], home_dir: &Path) -> Vec<PathBuf> {
    values
        .iter()
        .map(|path| resolve_config_path(path, home_dir))
        .collect()
}

fn resolve_config_path(path: &ConfiguredPath, home_dir: &Path) -> PathBuf {
    let value = Path::new(&path.value);
    let raw = value.to_string_lossy();
    if raw == "~" {
        return home_dir.to_path_buf();
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        return home_dir.join(rest);
    }
    if value.is_absolute() {
        value.to_path_buf()
    } else if path.relative_to.as_os_str().is_empty() {
        home_dir.join(value)
    } else {
        path.relative_to.join(value)
    }
}

fn resolve_path(path: &Path, work_dir: &Path, home_dir: &Path) -> PathBuf {
    if path == Path::new("~") {
        return home_dir.to_path_buf();
    }
    if let Ok(rest) = path.strip_prefix("~") {
        return home_dir.join(rest);
    }
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        work_dir.join(path)
    }
}

fn canonicalize_required(path: &Path, label: &str) -> io::Result<PathBuf> {
    path.canonicalize().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("{label} {} cannot be resolved: {error}", path.display()),
        )
    })
}

fn normalize_existing_paths(paths: &mut Vec<PathBuf>) {
    for path in paths.iter_mut() {
        if let Ok(canonical) = path.canonicalize() {
            *path = canonical;
        } else {
            *path = lexical_normalize(path);
        }
    }
    dedup_paths(paths);
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    result
}

fn dedup_paths(paths: &mut Vec<PathBuf>) {
    paths.sort();
    paths.dedup();
}

fn resolve_executable(program: Option<&OsStr>) -> Option<PathBuf> {
    let program = program?;
    let path = Path::new(program);
    if path.components().count() > 1 {
        return path.canonicalize().ok();
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| candidate.canonicalize().ok())
}

fn runtime_roots() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    let candidates = [
        "/System",
        "/usr",
        "/bin",
        "/sbin",
        "/Library/Frameworks",
        "/opt/homebrew/bin",
        "/opt/homebrew/lib",
        "/opt/homebrew/opt",
        "/opt/homebrew/Cellar",
        "/opt/homebrew/share",
        "/private/etc",
        "/private/var/db",
        "/private/var/run",
        "/dev",
    ];
    #[cfg(target_os = "linux")]
    let candidates = [
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/etc",
        "/opt",
        "/nix/store",
        "/dev",
        "/proc",
        "/sys",
    ];
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let candidates: [&str; 0] = [];

    candidates.iter().map(PathBuf::from).collect()
}

fn synthetic_host_dirs() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    let candidates = ["/run", "/var/run"];
    #[cfg(not(target_os = "linux"))]
    let candidates: [&str; 0] = [];

    candidates.iter().map(PathBuf::from).collect()
}

#[cfg(target_os = "linux")]
fn linux_socket_deputy_paths(home: &Path) -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("/run/docker.sock"),
        PathBuf::from("/var/run/docker.sock"),
        PathBuf::from("/run/containerd/containerd.sock"),
        PathBuf::from("/run/podman/podman.sock"),
        home.join(".docker/run/docker.sock"),
        home.join(".docker/desktop/docker.sock"),
    ];
    for variable in ["SSH_AUTH_SOCK", "GPG_AGENT_SOCK"] {
        if let Some(value) = std::env::var_os(variable) {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                paths.push(path);
            }
        }
    }
    for variable in ["DOCKER_HOST", "CONTAINER_HOST"] {
        if let Ok(value) = std::env::var(variable) {
            if let Some(path) = value.strip_prefix("unix://") {
                let path = PathBuf::from(path);
                if path.is_absolute() {
                    paths.push(path);
                }
            }
        }
    }
    if let Ok(value) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
        for address in value.split(';') {
            if let Some(path) = address.strip_prefix("unix:").and_then(|fields| {
                fields
                    .split(',')
                    .find_map(|field| field.strip_prefix("path="))
            }) {
                let path = PathBuf::from(path);
                if path.is_absolute() {
                    paths.push(path);
                }
            }
        }
    }
    paths
}

#[cfg(test)]
mod tests;
