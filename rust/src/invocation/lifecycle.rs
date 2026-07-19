//! Reporting and resource cleanup for one invocation.
//!
//! The command runner owns policy and launch ordering. This module owns the
//! complementary lifecycle: every acquired host resource is registered here,
//! every setup failure is unwound here, and normal completion aggregates all
//! cleanup failures before publishing the final report.

use std::io;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::{access, monitor, network, proxy, report, sandbox, workspace};

pub(super) struct InvocationLifecycle {
    runtime: Option<RuntimeCleanup>,
    worktree: Option<workspace::WorktreeInfo>,
    proxy: Option<proxy::ProxySession>,
    monitor: Option<monitor::Monitor>,
    // Keep the fail-safe publisher last so resource Drop implementations run
    // before an early-return report is emitted.
    report: InvocationReport,
}

impl InvocationLifecycle {
    pub(super) fn provisional(
        destination: Option<report::ReportDestination>,
        stats_requested: bool,
        requested_backend: report::Backend,
        argument_count: u64,
    ) -> Self {
        let started = Instant::now();
        let started_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            runtime: None,
            worktree: None,
            proxy: None,
            monitor: None,
            report: InvocationReport::new(
                destination,
                stats_requested,
                started,
                report::SessionReport::provisional(
                    started_unix_ms,
                    requested_backend,
                    argument_count,
                ),
            ),
        }
    }

    pub(super) fn elapsed_ms(&self) -> u64 {
        self.report.started.elapsed().as_millis() as u64
    }

    pub(super) fn record_phase_now(
        &mut self,
        phase: report::LifecyclePhase,
        state: report::PhaseState,
    ) {
        let elapsed = self.elapsed_ms();
        self.report.report.record_phase(elapsed, phase, state);
    }

    pub(super) fn set_failure_stage(&mut self, stage: report::LaunchStage) {
        self.report.failure_stage = stage;
    }

    pub(super) fn begin_setup_report(&mut self, cfg: &sandbox::SandboxConfig) {
        let started_unix_ms = self.report.report.timing.started_unix_ms;
        self.report.report = build_session_report(cfg, None, started_unix_ms);
        self.report.report.outcome.worktree = if self.worktree.is_some() {
            report::WorktreeOutcome::Pending
        } else {
            report::WorktreeOutcome::Disabled
        };
    }

    pub(super) fn complete_setup_report(
        &mut self,
        cfg: &sandbox::SandboxConfig,
        access: &access::ResolvedAccessPolicy,
    ) {
        let started_unix_ms = self.report.report.timing.started_unix_ms;
        let refreshed = build_session_report(cfg, Some(access), started_unix_ms);
        self.report.report.execution = refreshed.execution;
        self.report.report.policy = refreshed.policy;
        self.report.report.counters = refreshed.counters;
        self.report.report.record_phase(
            0,
            report::LifecyclePhase::Setup,
            report::PhaseState::Succeeded,
        );
    }

    pub(super) fn mark_worktree_setup_failed(&mut self) {
        self.record_phase_now(report::LifecyclePhase::Worktree, report::PhaseState::Failed);
        self.report.report.outcome.worktree = report::WorktreeOutcome::Failed {
            stage: report::WorktreeStage::Setup,
        };
    }

    pub(super) fn finish_child(&mut self, outcome: report::ChildOutcome) {
        let elapsed = self.elapsed_ms();
        self.report.report.finish(elapsed, outcome);
    }

    pub(super) fn record_transport_cleanup_failure(&mut self, exit_code: &mut i32) {
        self.record_cleanup_failure(report::CleanupStage::Transport, exit_code);
    }

    pub(super) fn attach_runtime(&mut self, path: PathBuf) {
        debug_assert!(self.runtime.is_none());
        self.runtime = Some(RuntimeCleanup::new(path));
    }

    pub(super) fn attach_worktree(&mut self, worktree: workspace::WorktreeInfo) {
        debug_assert!(self.worktree.is_none());
        self.worktree = Some(worktree);
    }

    pub(super) fn attach_proxy(&mut self, proxy: proxy::ProxySession) {
        debug_assert!(self.proxy.is_none());
        self.proxy = Some(proxy);
    }

    pub(super) fn attach_monitor(&mut self, monitor: monitor::Monitor) {
        debug_assert!(self.monitor.is_none());
        self.monitor = Some(monitor);
    }

    /// Unwinds everything acquired during setup and publishes the failure.
    ///
    /// Reporting failure cannot mask the already non-zero setup exit code.
    pub(super) fn fail_setup(
        &mut self,
        stage: report::LaunchStage,
        mut exit_code: i32,
        sensitive_values: Vec<String>,
    ) -> i32 {
        self.discard_worktree();
        let elapsed = self.elapsed_ms();
        self.report.report.record_phase(
            elapsed,
            report::LifecyclePhase::Setup,
            report::PhaseState::Failed,
        );
        self.report
            .report
            .finish(elapsed, report::ChildOutcome::LaunchFailed { stage });
        self.finish_monitor(&mut exit_code);
        self.finish_runtime();
        self.report.set_sensitive_values(sensitive_values);
        self.report.publish();
        exit_code
    }

    /// Finalizes all resources and publishes the completed invocation.
    ///
    /// Cleanup is deliberately exhaustive: a proxy failure does not prevent
    /// worktree finalization or runtime-directory cleanup. Any cleanup or
    /// publication failure upgrades a successful child exit to failure while
    /// preserving an existing non-zero child exit code.
    pub(super) fn complete(mut self, mut exit_code: i32, sensitive_values: Vec<String>) -> i32 {
        self.report.report.record_phase(
            self.elapsed_ms(),
            report::LifecyclePhase::Cleanup,
            report::PhaseState::Started,
        );

        if let Some(mut session) = self.proxy.take() {
            let stop_result = session.stop();
            apply_proxy_stats(&mut self.report.report, session.stats());
            if let Err(error) = stop_result {
                eprintln!("[cdm] error: proxy shutdown failed: {error}");
                self.record_cleanup_failure(report::CleanupStage::Proxy, &mut exit_code);
            }
        }

        self.finish_monitor(&mut exit_code);

        if let Some(worktree) = self.worktree.take() {
            self.report.report.record_phase(
                self.elapsed_ms(),
                report::LifecyclePhase::Worktree,
                report::PhaseState::Started,
            );
            eprintln!(
                "[cdm] workspace: finalizing {}...",
                worktree.worktree_dir.display()
            );
            match workspace::finalize_worktree(&worktree) {
                Ok(result) => {
                    self.report.report.outcome.worktree = report_worktree_outcome(&result);
                    workspace::print_summary(&result);
                    self.report.report.record_phase(
                        self.elapsed_ms(),
                        report::LifecyclePhase::Worktree,
                        report::PhaseState::Succeeded,
                    );
                }
                Err(error) => {
                    eprintln!("[cdm] error: workspace finalization: {error}");
                    self.report.report.outcome.worktree = report::WorktreeOutcome::Failed {
                        stage: report::WorktreeStage::Finalize,
                    };
                    self.report.report.record_phase(
                        self.elapsed_ms(),
                        report::LifecyclePhase::Worktree,
                        report::PhaseState::Failed,
                    );
                    self.record_cleanup_failure(report::CleanupStage::Worktree, &mut exit_code);
                }
            }
        }

        self.finish_runtime();
        if !matches!(
            self.report.report.outcome.cleanup,
            report::CleanupOutcome::Succeeded
        ) {
            exit_code = preserve_failure(exit_code);
        }
        let cleanup_state = if matches!(
            self.report.report.outcome.cleanup,
            report::CleanupOutcome::Succeeded
        ) {
            report::PhaseState::Succeeded
        } else {
            report::PhaseState::Failed
        };
        self.report.report.record_phase(
            self.elapsed_ms(),
            report::LifecyclePhase::Cleanup,
            cleanup_state,
        );

        self.report.set_sensitive_values(sensitive_values);
        if self.report.publish() {
            exit_code = preserve_failure(exit_code);
        }
        exit_code
    }

    fn discard_worktree(&mut self) {
        let Some(worktree) = self.worktree.take() else {
            return;
        };
        match workspace::discard_worktree(&worktree) {
            Ok(()) => self.report.report.outcome.worktree = report::WorktreeOutcome::Discarded,
            Err(error) => {
                eprintln!("[cdm] error: workspace cleanup: {error}");
                self.report.report.outcome.worktree = report::WorktreeOutcome::Failed {
                    stage: report::WorktreeStage::Remove,
                };
                self.report.report.outcome.cleanup = report::CleanupOutcome::Failed {
                    stage: report::CleanupStage::Worktree,
                };
            }
        }
    }

    fn finish_runtime(&mut self) {
        let Some(runtime) = self.runtime.as_mut() else {
            return;
        };
        if let Err(error) = runtime.finish() {
            eprintln!("[cdm] error: runtime cleanup: {error}");
            self.report.report.outcome.cleanup = report::CleanupOutcome::Failed {
                stage: report::CleanupStage::RuntimeDirectory,
            };
        } else if matches!(
            self.report.report.outcome.cleanup,
            report::CleanupOutcome::Pending
        ) {
            self.report.report.outcome.cleanup = report::CleanupOutcome::Succeeded;
        }
    }

    fn finish_monitor(&mut self, exit_code: &mut i32) {
        let Some(mut monitor) = self.monitor.take() else {
            return;
        };
        if let Err(error) = monitor.stop() {
            eprintln!("[cdm] error: monitor shutdown failed: {error}");
            self.record_cleanup_failure(report::CleanupStage::Monitor, exit_code);
        }
    }

    fn record_cleanup_failure(&mut self, stage: report::CleanupStage, exit_code: &mut i32) {
        record_cleanup_failure(&mut self.report.report, stage, exit_code);
    }
}

fn preserve_failure(exit_code: i32) -> i32 {
    if exit_code == 0 {
        1
    } else {
        exit_code
    }
}

fn record_cleanup_failure(
    report: &mut report::SessionReport,
    stage: report::CleanupStage,
    exit_code: &mut i32,
) {
    report.outcome.cleanup = report::CleanupOutcome::Failed { stage };
    *exit_code = preserve_failure(*exit_code);
}

struct InvocationReport {
    destination: Option<report::ReportDestination>,
    stats_requested: bool,
    started: Instant,
    report: report::SessionReport,
    sensitive_values: Vec<String>,
    failure_stage: report::LaunchStage,
    published: bool,
}

impl InvocationReport {
    fn new(
        destination: Option<report::ReportDestination>,
        stats_requested: bool,
        started: Instant,
        report: report::SessionReport,
    ) -> Self {
        Self {
            destination,
            stats_requested,
            started,
            report,
            sensitive_values: Vec::new(),
            failure_stage: report::LaunchStage::Validation,
            published: false,
        }
    }

    fn set_sensitive_values(&mut self, values: Vec<String>) {
        self.sensitive_values = values;
    }

    fn publish(&mut self) -> bool {
        if self.published {
            return false;
        }
        self.complete_unfinished_outcomes();
        self.report.timing.duration_ms = self.started.elapsed().as_millis() as u64;
        let mut failed = false;
        if let Some(destination) = &self.destination {
            let secrets = self.sensitive_values.iter().map(String::as_str);
            if let Err(error) = destination.write_json(&self.report, secrets) {
                eprintln!("[cdm] error: writing report: {error}");
                failed = true;
            }
        }
        if self.stats_requested {
            if let Err(error) = report::write_stats(&self.report, &mut io::stderr().lock()) {
                eprintln!("[cdm] error: writing stats: {error}");
                failed = true;
            }
        }
        self.published = true;
        failed
    }

    fn complete_unfinished_outcomes(&mut self) {
        if matches!(self.report.outcome.child, report::ChildOutcome::NotStarted) {
            let phase = if self.failure_stage == report::LaunchStage::Validation {
                report::LifecyclePhase::Validation
            } else {
                report::LifecyclePhase::Setup
            };
            let elapsed = self.started.elapsed().as_millis() as u64;
            self.report
                .record_phase(elapsed, phase, report::PhaseState::Failed);
            self.report.finish(
                elapsed,
                report::ChildOutcome::LaunchFailed {
                    stage: self.failure_stage,
                },
            );
        }
        if matches!(self.report.outcome.cleanup, report::CleanupOutcome::Pending) {
            self.report.outcome.cleanup = report::CleanupOutcome::Succeeded;
        }
        if !self.report.has_phase(report::LifecyclePhase::Cleanup) {
            let state = if matches!(
                self.report.outcome.cleanup,
                report::CleanupOutcome::Succeeded
            ) {
                report::PhaseState::Succeeded
            } else {
                report::PhaseState::Failed
            };
            self.report.record_phase(
                self.started.elapsed().as_millis() as u64,
                report::LifecyclePhase::Cleanup,
                state,
            );
        }
    }
}

impl Drop for InvocationReport {
    fn drop(&mut self) {
        self.publish();
    }
}

fn build_session_report(
    cfg: &sandbox::SandboxConfig,
    access: Option<&access::ResolvedAccessPolicy>,
    started_unix_ms: u64,
) -> report::SessionReport {
    let backend = if cfg.use_vm {
        report::Backend::Vm
    } else if cfg!(target_os = "macos") {
        report::Backend::Seatbelt
    } else {
        report::Backend::Bubblewrap
    };
    let Some(access) = access else {
        return report::SessionReport::provisional(
            started_unix_ms,
            backend,
            cfg.command.len() as u64,
        );
    };
    let (network, configured_network_rules, network_observation) = match &cfg.network {
        network::NetworkPolicy::Disabled => (
            report::NetworkPolicy::Disabled,
            1,
            report::ObservationCoverage::NotInstrumented,
        ),
        network::NetworkPolicy::Direct => (
            report::NetworkPolicy::Direct,
            0,
            report::ObservationCoverage::NotInstrumented,
        ),
        network::NetworkPolicy::Proxied(domains) => (
            report::NetworkPolicy::Proxied,
            domains.configured_rule_count() as u64,
            report::ObservationCoverage::Partial,
        ),
    };
    let mut report = report::SessionReport::new(
        started_unix_ms,
        backend,
        report::PolicySummary {
            workspace: match access.workspace {
                access::WorkspaceAccess::ReadOnly => report::WorkspacePolicy::ReadOnly,
                access::WorkspaceAccess::ReadWrite => report::WorkspacePolicy::ReadWrite,
            },
            host: match access.host {
                access::HostAccess::Normal => report::HostPolicy::Readable,
                access::HostAccess::Isolated => report::HostPolicy::Isolated,
            },
            network,
            allow_ro_paths: access.allow_ro.len() as u64,
            allow_rw_paths: access.allow_rw.len() as u64,
            hard_denials: (access.deny_read_rules.len() + access.deny_write_rules.len()) as u64,
            coverage: report::Coverage {
                filesystem: report::DenialCoverage {
                    configured_rules: (access.deny_read_rules.len() + access.deny_write_rules.len())
                        as u64,
                    observed_denials: 0,
                    observation: report::ObservationCoverage::NotInstrumented,
                },
                network: report::DenialCoverage {
                    configured_rules: configured_network_rules,
                    observed_denials: 0,
                    observation: network_observation,
                },
            },
        },
    );
    report.execution.argument_count = cfg.command.len() as u64;
    report.counters.secrets.configured = cfg.secrets.real_to_fake.len() as u64;
    report.counters.secrets.staged_files = cfg
        .file_stage
        .as_ref()
        .map(|stage| stage.staged_files().len() as u64)
        .unwrap_or(0);
    report.counters.secrets.injected_entries = cfg.injected_env.len() as u64;
    report
}

fn apply_proxy_stats(report: &mut report::SessionReport, stats: proxy::ProxyStats) {
    report.counters.proxy = report::ProxyCounters {
        requests_allowed: stats.requests_allowed,
        requests_blocked: stats.requests_blocked,
        substitutions: stats.substitutions,
        bytes_from_child: stats.bytes_from_child,
        bytes_to_upstream: stats.bytes_to_upstream,
        bytes_from_upstream: stats.bytes_from_upstream,
        bytes_to_child: stats.bytes_to_child,
        rejected_messages: stats.rejected_messages,
    };
    if let Some(policy) = report.policy.as_mut() {
        policy.coverage.network.observed_denials = stats.requests_blocked;
    }
}

fn report_worktree_outcome(result: &workspace::WorktreeResult) -> report::WorktreeOutcome {
    match result {
        workspace::WorktreeResult::NoChanges => report::WorktreeOutcome::NoChanges,
        workspace::WorktreeResult::Committed {
            files_changed,
            insertions,
            deletions,
            ..
        } => report::WorktreeOutcome::Committed {
            files_changed: *files_changed as u64,
            insertions: *insertions as u64,
            deletions: *deletions as u64,
        },
    }
}

struct RuntimeCleanup(Option<PathBuf>);

impl RuntimeCleanup {
    fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }

    fn finish(&mut self) -> io::Result<()> {
        let Some(path) = self.0.take() else {
            return Ok(());
        };
        std::fs::remove_dir_all(path)
    }
}

impl Drop for RuntimeCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{preserve_failure, record_cleanup_failure};
    use crate::report::{Backend, CleanupOutcome, CleanupStage, SessionReport};

    #[test]
    fn cleanup_failure_upgrades_only_successful_exit() {
        assert_eq!(preserve_failure(0), 1);
        assert_eq!(preserve_failure(2), 2);
        assert_eq!(preserve_failure(137), 137);
    }

    #[test]
    fn cleanup_aggregation_preserves_child_failure_and_reports_latest_stage() {
        let mut report = SessionReport::provisional(0, Backend::Seatbelt, 1);
        let mut exit_code = 23;

        record_cleanup_failure(&mut report, CleanupStage::Proxy, &mut exit_code);
        record_cleanup_failure(&mut report, CleanupStage::RuntimeDirectory, &mut exit_code);

        assert_eq!(exit_code, 23);
        assert_eq!(
            report.outcome.cleanup,
            CleanupOutcome::Failed {
                stage: CleanupStage::RuntimeDirectory
            }
        );
    }
}
