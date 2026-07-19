//! Schema-versioned, secret-safe session reporting.
//!
//! Reports deliberately contain only bounded enums and numeric metadata. They
//! never contain argv, paths, domains, environment values, or error strings.
//! This makes the serialized format useful for automation without turning it
//! into a second diagnostic log or a secret exfiltration surface.

use serde::{Deserialize, Serialize};
use std::ffi::{CString, OsStr};
#[cfg(test)]
use std::fs;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_EVENTS: usize = 128;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReport {
    pub schema_version: u32,
    pub timing: Timing,
    pub execution: Execution,
    /// Absent only when validation failed before effective policy resolution.
    pub policy: Option<PolicySummary>,
    pub counters: Counters,
    pub events: Vec<ReportEvent>,
    pub outcome: SessionOutcome,
}

impl SessionReport {
    pub fn new(started_unix_ms: u64, backend: Backend, policy: PolicySummary) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            timing: Timing {
                started_unix_ms,
                duration_ms: 0,
            },
            execution: Execution {
                backend,
                argument_count: 0,
            },
            policy: Some(policy),
            counters: Counters::default(),
            events: Vec::new(),
            outcome: SessionOutcome::default(),
        }
    }

    pub fn provisional(started_unix_ms: u64, backend: Backend, argument_count: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            timing: Timing {
                started_unix_ms,
                duration_ms: 0,
            },
            execution: Execution {
                backend,
                argument_count,
            },
            policy: None,
            counters: Counters::default(),
            events: Vec::new(),
            outcome: SessionOutcome::default(),
        }
    }

    pub fn finish(&mut self, duration_ms: u64, child: ChildOutcome) {
        self.timing.duration_ms = duration_ms;
        self.outcome.child = child;
    }

    #[cfg(test)]
    pub fn observe_denial(&mut self, at_ms: u64, surface: DenialSurface, count: u64) {
        let policy = self
            .policy
            .as_mut()
            .expect("test report has resolved policy");
        let coverage = match surface {
            DenialSurface::Filesystem => &mut policy.coverage.filesystem,
            DenialSurface::Network => &mut policy.coverage.network,
        };
        coverage.observed_denials = coverage.observed_denials.saturating_add(count);
        self.push_event(ReportEvent {
            at_ms,
            kind: EventKind::DenialObserved { surface, count },
        });
    }

    pub fn record_phase(&mut self, at_ms: u64, phase: LifecyclePhase, state: PhaseState) {
        self.push_event(ReportEvent {
            at_ms,
            kind: EventKind::Lifecycle { phase, state },
        });
    }

    pub fn has_phase(&self, phase: LifecyclePhase) -> bool {
        self.events.iter().any(|event| {
            matches!(
                event.kind,
                EventKind::Lifecycle {
                    phase: event_phase,
                    ..
                } if event_phase == phase
            )
        })
    }

    fn push_event(&mut self, event: ReportEvent) {
        if self.events.len() < MAX_EVENTS {
            self.events.push(event);
        } else {
            self.counters.events_dropped = self.counters.events_dropped.saturating_add(1);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timing {
    pub started_unix_ms: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Execution {
    pub backend: Backend,
    /// Number of argv entries, including the executable. Values are omitted.
    pub argument_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Seatbelt,
    Bubblewrap,
    Vm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySummary {
    pub workspace: WorkspacePolicy,
    pub host: HostPolicy,
    pub network: NetworkPolicy,
    pub allow_ro_paths: u64,
    pub allow_rw_paths: u64,
    pub hard_denials: u64,
    pub coverage: Coverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspacePolicy {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostPolicy {
    Readable,
    Isolated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    Disabled,
    Direct,
    Proxied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub filesystem: DenialCoverage,
    pub network: DenialCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenialCoverage {
    /// Number of policy rules configured before sandbox entry.
    pub configured_rules: u64,
    /// Number of denials actually observed by the available instrumentation.
    pub observed_denials: u64,
    /// Whether the backend can observe none, some, or all relevant denials.
    pub observation: ObservationCoverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationCoverage {
    NotInstrumented,
    Partial,
    Complete,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub proxy: ProxyCounters,
    pub secrets: SecretCounters,
    /// Events omitted after [`MAX_EVENTS`] was reached.
    pub events_dropped: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyCounters {
    pub requests_allowed: u64,
    pub requests_blocked: u64,
    pub substitutions: u64,
    pub bytes_from_child: u64,
    pub bytes_to_upstream: u64,
    pub bytes_from_upstream: u64,
    pub bytes_to_child: u64,
    pub rejected_messages: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretCounters {
    pub configured: u64,
    pub staged_files: u64,
    pub injected_entries: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportEvent {
    /// Milliseconds since this session started.
    pub at_ms: u64,
    #[serde(flatten)]
    pub kind: EventKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    Lifecycle {
        phase: LifecyclePhase,
        state: PhaseState,
    },
    DenialObserved {
        surface: DenialSurface,
        count: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecyclePhase {
    Validation,
    Setup,
    Proxy,
    Sandbox,
    Child,
    Worktree,
    Cleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseState {
    Started,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialSurface {
    Filesystem,
    Network,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionOutcome {
    pub child: ChildOutcome,
    pub cleanup: CleanupOutcome,
    pub worktree: WorktreeOutcome,
}

impl Default for SessionOutcome {
    fn default() -> Self {
        Self {
            child: ChildOutcome::NotStarted,
            cleanup: CleanupOutcome::Pending,
            worktree: WorktreeOutcome::Disabled,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ChildOutcome {
    NotStarted,
    Exited { code: i32 },
    Signaled { signal: i32 },
    LaunchFailed { stage: LaunchStage },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchStage {
    Validation,
    Setup,
    Proxy,
    Sandbox,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CleanupOutcome {
    Pending,
    Succeeded,
    Failed { stage: CleanupStage },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStage {
    Monitor,
    Proxy,
    RuntimeDirectory,
    Transport,
    Worktree,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WorktreeOutcome {
    Disabled,
    Pending,
    NoChanges,
    Committed {
        files_changed: u64,
        insertions: u64,
        deletions: u64,
    },
    Discarded,
    Failed {
        stage: WorktreeStage,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeStage {
    Setup,
    Finalize,
    Remove,
}

/// Serializes and atomically installs a private report file.
///
/// `sensitive_values` is a final fail-closed check over the serialized bytes.
/// Empty values are ignored. The destination itself must not be a symlink;
/// replacing an existing regular file is supported.
#[cfg(test)]
pub fn write_json<'a, I>(path: &Path, report: &SessionReport, sensitive_values: I) -> io::Result<()>
where
    I: IntoIterator<Item = &'a str>,
{
    ReportDestination::prepare(path)?.write_json(report, sensitive_values)
}

/// A report destination pinned before untrusted child execution begins.
///
/// Holding the directory descriptor prevents a child from redirecting the
/// eventual host write by replacing a workspace directory with a symlink.
pub struct ReportDestination {
    directory: File,
    canonical_parent: PathBuf,
    file_name: CString,
}

impl ReportDestination {
    pub fn prepare(path: &Path) -> io::Result<Self> {
        let file_name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "report path has no file name")
        })?;
        let file_name = os_str_to_cstring(file_name, "report file name")?;
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = parent.canonicalize().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot resolve report directory {}: {error}",
                    parent.display()
                ),
            )
        })?;
        let parent_c = os_str_to_cstring(parent.as_os_str(), "report directory")?;
        let raw = unsafe {
            libc::open(
                parent_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let directory = File::from(unsafe { OwnedFd::from_raw_fd(raw) });
        reject_destination_symlink(directory.as_raw_fd(), &file_name)?;
        Ok(Self {
            directory,
            canonical_parent: parent,
            file_name,
        })
    }

    pub fn write_json<'a, I>(&self, report: &SessionReport, sensitive_values: I) -> io::Result<()>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut contents = serde_json::to_vec_pretty(report).map_err(io::Error::other)?;
        contents.push(b'\n');

        if sensitive_values
            .into_iter()
            .filter(|value| !value.is_empty())
            .any(|value| contains_bytes(&contents, value.as_bytes()))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "refusing to write a session report containing a sensitive value",
            ));
        }

        self.atomic_write_private(&contents)
    }

    fn atomic_write_private(&self, contents: &[u8]) -> io::Result<()> {
        self.verify_parent_identity()?;
        reject_destination_symlink(self.directory.as_raw_fd(), &self.file_name)?;

        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temp_name = temporary_name(&self.file_name, id)?;
        let raw = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                temp_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = File::from(unsafe { OwnedFd::from_raw_fd(raw) });
        let result = (|| {
            file.write_all(contents)?;
            file.sync_all()?;
            drop(file);
            self.verify_parent_identity()?;
            reject_destination_symlink(self.directory.as_raw_fd(), &self.file_name)?;
            let status = unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    temp_name.as_ptr(),
                    self.directory.as_raw_fd(),
                    self.file_name.as_ptr(),
                )
            };
            if status < 0 {
                return Err(io::Error::last_os_error());
            }
            self.directory.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), temp_name.as_ptr(), 0);
            }
        }
        result
    }

    fn verify_parent_identity(&self) -> io::Result<()> {
        let parent = os_str_to_cstring(self.canonical_parent.as_os_str(), "report directory")?;
        let raw = unsafe {
            libc::open(
                parent.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("report directory identity changed after it was prepared: {error}"),
            ));
        }
        let current = File::from(unsafe { OwnedFd::from_raw_fd(raw) });
        let pinned_metadata = self.directory.metadata()?;
        let current_metadata = current.metadata()?;
        if pinned_metadata.dev() != current_metadata.dev()
            || pinned_metadata.ino() != current_metadata.ino()
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "report directory identity changed after it was prepared",
            ));
        }
        Ok(())
    }
}

/// Writes a compact summary to a caller-provided stream.
///
/// The caller chooses stderr, a file, or an in-memory buffer; this module never
/// writes to process stdout.
pub fn write_stats(report: &SessionReport, writer: &mut impl Write) -> io::Result<()> {
    let filesystem_denials = report
        .policy
        .as_ref()
        .map(|policy| policy.coverage.filesystem.observed_denials)
        .unwrap_or(0);
    let network_denials = report
        .policy
        .as_ref()
        .map(|policy| policy.coverage.network.observed_denials)
        .unwrap_or(0);
    writeln!(
        writer,
        "[cdm] stats: duration={}ms backend={} child={} fs_denials={} network_denials={} proxy_allowed={} proxy_blocked={} substitutions={}",
        report.timing.duration_ms,
        backend_label(report.execution.backend),
        child_label(report.outcome.child),
        filesystem_denials,
        network_denials,
        report.counters.proxy.requests_allowed,
        report.counters.proxy.requests_blocked,
        report.counters.proxy.substitutions,
    )
}

fn backend_label(backend: Backend) -> &'static str {
    match backend {
        Backend::Seatbelt => "seatbelt",
        Backend::Bubblewrap => "bubblewrap",
        Backend::Vm => "vm",
    }
}

fn child_label(outcome: ChildOutcome) -> &'static str {
    match outcome {
        ChildOutcome::NotStarted => "not_started",
        ChildOutcome::Exited { .. } => "exited",
        ChildOutcome::Signaled { .. } => "signaled",
        ChildOutcome::LaunchFailed { .. } => "launch_failed",
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn reject_destination_symlink(directory: i32, file_name: &CString) -> io::Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let status = unsafe {
        libc::fstatat(
            directory,
            file_name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(error);
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "report destination must not be a symbolic link",
        ));
    }
    Ok(())
}

fn os_str_to_cstring(value: &OsStr, label: &str) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} contains a NUL byte"),
        )
    })
}

fn temporary_name(file_name: &CString, id: u64) -> io::Result<CString> {
    let mut name = Vec::with_capacity(file_name.as_bytes().len() + 40);
    name.push(b'.');
    name.extend_from_slice(file_name.as_bytes());
    name.extend_from_slice(format!(".cdm-{}-{id}.tmp", std::process::id()).as_bytes());
    CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "temporary report file name contains a NUL byte",
        )
    })
}

#[cfg(test)]
mod tests;
