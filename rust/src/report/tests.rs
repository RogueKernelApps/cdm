//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn report() -> SessionReport {
    let policy = PolicySummary {
        workspace: WorkspacePolicy::ReadWrite,
        host: HostPolicy::Readable,
        network: NetworkPolicy::Proxied,
        allow_ro_paths: 3,
        allow_rw_paths: 2,
        hard_denials: 4,
        coverage: Coverage {
            filesystem: DenialCoverage {
                configured_rules: 4,
                observed_denials: 0,
                observation: ObservationCoverage::Partial,
            },
            network: DenialCoverage {
                configured_rules: 2,
                observed_denials: 0,
                observation: ObservationCoverage::Complete,
            },
        },
    };
    let mut report = SessionReport::new(1_700_000_000_000, Backend::Seatbelt, policy);
    report.execution.argument_count = 3;
    report.counters.proxy.requests_allowed = 8;
    report.counters.proxy.requests_blocked = 2;
    report.counters.proxy.substitutions = 4;
    report.counters.proxy.bytes_from_child = 120;
    report.counters.proxy.bytes_to_upstream = 100;
    report.counters.proxy.bytes_from_upstream = 300;
    report.counters.proxy.bytes_to_child = 240;
    report.counters.proxy.rejected_messages = 1;
    report.counters.secrets.configured = 2;
    report.counters.secrets.staged_files = 1;
    report.counters.secrets.injected_entries = 3;
    report.record_phase(1, LifecyclePhase::Setup, PhaseState::Started);
    report.observe_denial(9, DenialSurface::Network, 2);
    report.outcome.cleanup = CleanupOutcome::Succeeded;
    report.outcome.worktree = WorktreeOutcome::Committed {
        files_changed: 2,
        insertions: 7,
        deletions: 1,
    };
    report.finish(42, ChildOutcome::Exited { code: 0 });
    report
}

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "cdm-report-test-{}-{nonce}-{id}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn deterministic_schema_matches_golden_document() {
    let json = serde_json::to_string_pretty(&report()).unwrap();
    assert_eq!(
        json,
        include_str!("../../tests/fixtures/session-report-v1.json").trim_end()
    );
}

#[test]
fn configured_rules_and_observed_denials_are_distinct() {
    let report = report();
    let policy = report.policy.as_ref().unwrap();
    assert_eq!(policy.coverage.network.configured_rules, 2);
    assert_eq!(policy.coverage.network.observed_denials, 2);
    assert_eq!(
        policy.coverage.network.observation,
        ObservationCoverage::Complete
    );
}

#[test]
fn provisional_report_is_honest_before_policy_resolution() {
    let mut report = SessionReport::provisional(123, Backend::Seatbelt, 2);
    report.record_phase(1, LifecyclePhase::Validation, PhaseState::Failed);
    report.outcome.cleanup = CleanupOutcome::Succeeded;
    report.finish(
        2,
        ChildOutcome::LaunchFailed {
            stage: LaunchStage::Validation,
        },
    );
    let value = serde_json::to_value(report).unwrap();
    assert!(value["policy"].is_null());
    assert_eq!(value["outcome"]["child"]["stage"], "validation");
    assert_eq!(value["events"][0]["phase"], "validation");
}

#[test]
fn report_contains_exit_signal_cleanup_and_worktree_outcomes() {
    let mut report = report();
    report.finish(50, ChildOutcome::Signaled { signal: 15 });
    report.outcome.cleanup = CleanupOutcome::Failed {
        stage: CleanupStage::Worktree,
    };
    report.outcome.worktree = WorktreeOutcome::Failed {
        stage: WorktreeStage::Remove,
    };
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(value["outcome"]["child"]["status"], "signaled");
    assert_eq!(value["outcome"]["child"]["signal"], 15);
    assert_eq!(value["outcome"]["cleanup"]["stage"], "worktree");
    assert_eq!(value["outcome"]["worktree"]["stage"], "remove");
}

#[test]
fn hostile_event_volume_is_bounded_and_accounted_for() {
    let mut report = report();
    for index in 0..(MAX_EVENTS as u64 + 20) {
        report.record_phase(index, LifecyclePhase::Child, PhaseState::Started);
    }
    assert_eq!(report.events.len(), MAX_EVENTS);
    // The fixture starts with two events before this loop.
    assert_eq!(report.counters.events_dropped, 22);
    // Denial totals remain honest even if their detail event is dropped.
    report.observe_denial(999, DenialSurface::Filesystem, 7);
    assert_eq!(
        report
            .policy
            .as_ref()
            .unwrap()
            .coverage
            .filesystem
            .observed_denials,
        7
    );
    assert_eq!(report.events.len(), MAX_EVENTS);
    assert_eq!(report.counters.events_dropped, 23);
}

#[test]
fn sensitive_value_check_fails_closed_without_creating_report() {
    let dir = temp_dir();
    let path = dir.join("report.json");
    // Schema fields cannot accept arbitrary text. This check also protects
    // future schema additions from accidentally serializing known secrets.
    let serialized = serde_json::to_string(&report()).unwrap();
    let known_schema_value = "proxied";
    assert!(serialized.contains(known_schema_value));
    let error = write_json(&path, &report(), [known_schema_value]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!path.exists());
    fs::remove_dir(dir).unwrap();
}

#[test]
fn atomic_report_is_private_and_replaces_regular_file() {
    let dir = temp_dir();
    let path = dir.join("report.json");
    fs::write(&path, b"old").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    write_json(&path, &report(), std::iter::empty()).unwrap();

    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let parsed: SessionReport = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(parsed, report());
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn symlink_destination_is_rejected_without_touching_target() {
    let dir = temp_dir();
    let target = dir.join("sentinel");
    let path = dir.join("report.json");
    fs::write(&target, b"untouched").unwrap();
    symlink(&target, &path).unwrap();

    let error = write_json(&path, &report(), std::iter::empty()).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(fs::read(&target).unwrap(), b"untouched");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn prepared_directory_swap_fails_without_writing_to_either_location() {
    let dir = temp_dir();
    let original = dir.join("reports");
    let pinned = dir.join("reports-pinned");
    let attacker = dir.join("attacker");
    fs::create_dir(&original).unwrap();
    fs::create_dir(&attacker).unwrap();
    let destination = ReportDestination::prepare(&original.join("session.json")).unwrap();

    fs::rename(&original, &pinned).unwrap();
    symlink(&attacker, &original).unwrap();
    let error = destination
        .write_json(&report(), std::iter::empty())
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("report directory identity changed"));
    assert!(!pinned.join("session.json").exists());
    assert!(!attacker.join("session.json").exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn stats_only_touch_the_supplied_writer() {
    let mut output = Vec::new();
    write_stats(&report(), &mut output).unwrap();
    assert_eq!(
            String::from_utf8(output).unwrap(),
            "[cdm] stats: duration=42ms backend=seatbelt child=exited fs_denials=0 network_denials=2 proxy_allowed=8 proxy_blocked=2 substitutions=4\n"
        );
}
