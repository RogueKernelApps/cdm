//! Invocation lifecycle for one sandboxed command.

use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use crate::{
    access, app, cli, config, discover_launch_project, guard, monitor, network, proxy, report,
    sandbox, secrets, stage, workspace,
};

mod lifecycle;

use lifecycle::InvocationLifecycle;

pub fn run(args: cli::RunArgs) -> i32 {
    let report_destination = match args.report_json.as_deref() {
        Some(path) => match report::ReportDestination::prepare(path) {
            Ok(destination) => Some(destination),
            Err(error) => {
                eprintln!("[cdm] error: report destination: {error}");
                return 2;
            }
        },
        None => None,
    };
    let requested_backend = if args.vm || args.vmi.is_some() {
        report::Backend::Vm
    } else if cfg!(target_os = "macos") {
        report::Backend::Seatbelt
    } else {
        report::Backend::Bubblewrap
    };
    let mut lifecycle = InvocationLifecycle::provisional(
        report_destination,
        args.stats,
        requested_backend,
        args.command.len() as u64,
    );
    let project = match discover_launch_project() {
        Ok(project) => project,
        Err(error) => {
            eprintln!("[cdm] error: {error}");
            return 2;
        }
    };
    let cdm_config = match config::load_with_presets(&project, &args.preset) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("[cdm] error: {error}");
            return 2;
        }
    };
    let mut cfg = match sandbox::SandboxConfig::from_loaded_config(cdm_config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[cdm] error: {}", e);
            return 1;
        }
    };
    lifecycle.attach_runtime(cfg.runtime_dir.clone());

    cfg.debug = env::var("CDM_DEBUG").is_ok();

    let scramble = args.scramble || args.sec;
    cfg.network = match network::NetworkPolicy::from_cli(
        args.no_network,
        args.no_proxy,
        scramble,
        args.allow_domains.as_deref(),
        args.deny_domains.as_deref(),
        args.allow_private_network || (scramble && cfg.config.proxy.allow_private_network),
    ) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("[cdm] error: {error}");
            return 2;
        }
    };
    cfg.secure = args.sec;
    cfg.scramble = scramble;
    cfg.access.set_secure(args.sec);
    if args.ro {
        cfg.access.workspace = access::WorkspaceAccess::ReadOnly;
    }
    if args.iso {
        cfg.access.host = access::HostAccess::Isolated;
    }
    for path in args.allow_ro {
        cfg.access.add_allow_ro(path);
    }
    for path in args.allow_rw {
        cfg.access.add_allow_rw(path);
    }
    if args.vm || args.vmi.is_some() {
        #[cfg(feature = "vm")]
        {
            cfg.use_vm = true;
            cfg.vm_image = args.vmi;
        }
        #[cfg(not(feature = "vm"))]
        {
            eprintln!("[cdm] error: --vm and --vmi require a build compiled with --features vm");
            return 2;
        }
    }
    cfg.command = args.command;
    let explicit_bundle = args.app;
    let detected_bundle = explicit_bundle
        .is_none()
        .then(|| app::bundle_from_command(&cfg.command))
        .flatten();
    let bundle_is_command = detected_bundle.is_some();
    let app_bundle = explicit_bundle.or(detected_bundle);
    if app_bundle.is_some() && cfg.use_vm {
        eprintln!("[cdm] error: application bundles cannot be combined with --vm or --vmi");
        return 2;
    }
    if cfg.command.is_empty() && app_bundle.is_none() {
        let shell = env::var_os("SHELL").unwrap_or_else(|| OsString::from("/bin/bash"));
        cfg.command = vec![shell];
    }
    if let Some(bundle) = app_bundle {
        let plan = match app::discover(&bundle, &cfg.home_dir) {
            Ok(plan) => plan,
            Err(error) => {
                eprintln!("[cdm] error: app discovery: {error}");
                return 2;
            }
        };
        for path in plan.allow_ro {
            cfg.access.add_discovered_ro(path);
        }
        let write_path_count = plan.allow_rw.len();
        let write_grants = plan.allow_rw;
        for grant in &write_grants {
            cfg.access.add_discovered_rw(grant.path.clone());
        }
        if bundle_is_command {
            cfg.command.remove(0);
        }
        cfg.command.insert(0, plan.executable.into_os_string());
        eprintln!(
            "[cdm] app: {} ({} writable state paths discovered)",
            plan.bundle_id, write_path_count
        );
        for grant in write_grants {
            eprintln!(
                "[cdm] app rw [{}]: {}",
                grant.source.label(),
                grant.path.display()
            );
        }
    }

    // Validate the command before allocating a worktree or proxy session.
    if let Err(e) =
        guard::check_command_with_config(&cfg.command, &cfg.config.guard.blocked_commands)
    {
        eprintln!("[cdm] {}", e);
        return 2;
    }
    lifecycle.set_failure_stage(report::LaunchStage::Setup);

    // --- Workspace Mode ---
    if args.workspace {
        lifecycle.record_phase_now(
            report::LifecyclePhase::Worktree,
            report::PhaseState::Started,
        );
        match workspace::create_worktree(&cfg.work_dir) {
            Ok(info) => {
                lifecycle.record_phase_now(
                    report::LifecyclePhase::Worktree,
                    report::PhaseState::Succeeded,
                );
                let _ = writeln!(
                    io::stderr(),
                    "[cdm] workspace: {}",
                    info.worktree_dir.display()
                );
                for path in workspace::protected_metadata_paths(&info) {
                    cfg.access.add_runtime_deny_write(path);
                }
                cfg.work_dir = info.execution_dir.clone();
                lifecycle.attach_worktree(info);
            }
            Err(e) => {
                eprintln!("[cdm] error: workspace: {}", e);
                lifecycle.mark_worktree_setup_failed();
                return 1;
            }
        }
    }

    // The final filesystem snapshot cannot be resolved until sensitive-file
    // discovery and staging have finished. Early setup failures still receive
    // a bounded report built from typed modes, without inspecting paths twice.
    lifecycle.begin_setup_report(&cfg);

    if cfg.scramble {
        // --- Secret Scanning ---
        let _ = writeln!(io::stderr(), "[cdm] scanning for secrets...");
        let home_dir = cfg.home_dir.to_string_lossy().to_string();
        let allow_home_path = |path: &std::path::Path| {
            cfg.access.host == access::HostAccess::Normal
                || cfg
                    .access
                    .explicitly_grants(path, &cfg.work_dir, &cfg.home_dir)
        };
        cfg.secrets =
            match secrets::scan_host(&cfg.home_dir, &cfg.work_dir, &cfg.config, &allow_home_path) {
                Ok(mapping) => mapping,
                Err(error) => {
                    eprintln!("[cdm] error: secret scan failed: {error}");
                    return lifecycle.fail_setup(report::LaunchStage::Setup, 1, Vec::new());
                }
            };

        // Register credential-shaped textual argv values, then replace all known
        // secret byte sequences without changing argument boundaries or requiring
        // UTF-8. Raw argv values are discarded before diagnostics and VM planning.
        cfg.command = match cfg.secrets.obfuscate_argv(&cfg.command, &cfg.config) {
            Ok(command) => command,
            Err(error) => {
                eprintln!("[cdm] error: argv secret obfuscation failed: {error}");
                return lifecycle.fail_setup(report::LaunchStage::Setup, 1, Vec::new());
            }
        };

        // --- File Staging & Env Injection ---
        if let Err(error) = stage_sensitive_files(&mut cfg, &home_dir) {
            eprintln!("[cdm] error: secret staging failed: {error}");
            let sensitive_values = cfg.secrets.real_to_fake.keys().cloned().collect::<Vec<_>>();
            return lifecycle.fail_setup(report::LaunchStage::Setup, 1, sensitive_values);
        }

        let _ = writeln!(
            io::stderr(),
            "[cdm] {} secrets scrambled, {} env vars injected, {} paths denied",
            cfg.secrets.real_to_fake.len(),
            cfg.injected_env.len(),
            cfg.denied_read_paths.len(),
        );
    }

    // --- Monitor Mode ---
    let monitor_log = if args.monitor {
        match start_monitor(&cfg) {
            Ok(monitor) => {
                let handle = monitor.log_handle();
                lifecycle.attach_monitor(monitor);
                Some(handle)
            }
            Err(error) => {
                eprintln!("[cdm] error: monitor startup failed: {error}");
                let sensitive_values = cfg.secrets.real_to_fake.keys().cloned().collect::<Vec<_>>();
                return lifecycle.fail_setup(report::LaunchStage::Setup, 1, sensitive_values);
            }
        }
    } else {
        None
    };

    let resolved_access = match cfg.freeze_access() {
        Ok(policy) => policy.clone(),
        Err(error) => {
            eprintln!("[cdm] error: {error}");
            let sensitive_values = cfg.secrets.real_to_fake.keys().cloned().collect::<Vec<_>>();
            return lifecycle.fail_setup(report::LaunchStage::Setup, 2, sensitive_values);
        }
    };
    lifecycle.complete_setup_report(&cfg, &resolved_access);
    let sensitive_values = cfg.secrets.real_to_fake.keys().cloned().collect::<Vec<_>>();

    // --- Egress Proxy ---
    if let Some(domains) = cfg.network.domains().cloned() {
        lifecycle.set_failure_stage(report::LaunchStage::Proxy);
        lifecycle.record_phase_now(report::LifecyclePhase::Proxy, report::PhaseState::Started);
        let on_block: Option<proxy::BlockCallback> = monitor_log.as_ref().map(|log| {
            let handle = Arc::clone(log);
            Arc::new(move |domain: &str, reason: &str| {
                monitor::write_block_event(&handle, domain, reason);
            }) as proxy::BlockCallback
        });
        match proxy::ProxySession::start(proxy::ProxyOptions {
            preferred_port: cfg.proxy_port,
            mapping: cfg.secrets.clone(),
            domains,
            on_block,
            debug: cfg.debug,
            runtime_dir: cfg.runtime_dir.clone(),
        }) {
            Ok(session) => {
                lifecycle
                    .record_phase_now(report::LifecyclePhase::Proxy, report::PhaseState::Succeeded);
                cfg.proxy_port = session.port();
                cfg.ca_cert_path = Some(session.ca_cert_path().to_path_buf());
                cfg.ca_bundle_path = Some(session.ca_bundle_path().to_path_buf());
                lifecycle.attach_proxy(session);
            }
            Err(error) => {
                eprintln!("[cdm] error: proxy startup failed: {error}");
                lifecycle
                    .record_phase_now(report::LifecyclePhase::Proxy, report::PhaseState::Failed);
                return lifecycle.fail_setup(
                    report::LaunchStage::Proxy,
                    1,
                    sensitive_values.clone(),
                );
            }
        }
    }

    // --- Print Summary ---
    print_summary(&cfg);

    // --- Run Sandbox ---
    lifecycle.set_failure_stage(report::LaunchStage::Sandbox);
    lifecycle.record_phase_now(report::LifecyclePhase::Sandbox, report::PhaseState::Started);
    lifecycle.record_phase_now(report::LifecyclePhase::Child, report::PhaseState::Started);
    let mut transport_cleanup_error = None;
    let mut exit_code = match sandbox::run(cfg) {
        Ok(run) => {
            transport_cleanup_error = run.cleanup.err();
            match run.child {
                Ok(status) => {
                    lifecycle.record_phase_now(
                        report::LifecyclePhase::Sandbox,
                        report::PhaseState::Succeeded,
                    );
                    let child_outcome = match status.signal {
                        Some(signal) => report::ChildOutcome::Signaled { signal },
                        None => report::ChildOutcome::Exited {
                            code: status.exit_code,
                        },
                    };
                    lifecycle.finish_child(child_outcome);
                    lifecycle.record_phase_now(
                        report::LifecyclePhase::Child,
                        if status.exit_code == 0 {
                            report::PhaseState::Succeeded
                        } else {
                            report::PhaseState::Failed
                        },
                    );
                    status.exit_code
                }
                Err(error) => {
                    let _ = writeln!(io::stderr(), "[cdm] error: {error}");
                    lifecycle.finish_child(report::ChildOutcome::LaunchFailed {
                        stage: report::LaunchStage::Sandbox,
                    });
                    lifecycle.record_phase_now(
                        report::LifecyclePhase::Sandbox,
                        report::PhaseState::Failed,
                    );
                    lifecycle.record_phase_now(
                        report::LifecyclePhase::Child,
                        report::PhaseState::Failed,
                    );
                    1
                }
            }
        }
        Err(e) => {
            let _ = writeln!(io::stderr(), "[cdm] error: {}", e);
            lifecycle.finish_child(report::ChildOutcome::LaunchFailed {
                stage: report::LaunchStage::Sandbox,
            });
            lifecycle.record_phase_now(report::LifecyclePhase::Sandbox, report::PhaseState::Failed);
            lifecycle.record_phase_now(report::LifecyclePhase::Child, report::PhaseState::Failed);
            1
        }
    };

    if let Some(error) = transport_cleanup_error {
        eprintln!("[cdm] error: sandbox transport cleanup failed: {error}");
        lifecycle.record_transport_cleanup_failure(&mut exit_code);
    }

    lifecycle.complete(exit_code, sensitive_values)
}

/// Finds sensitive files, creates obfuscated copies, and sets up env injection
/// and read denial for each file.
fn stage_sensitive_files(cfg: &mut sandbox::SandboxConfig, home_dir: &str) -> io::Result<()> {
    let allow_home_path = |path: &std::path::Path| {
        cfg.access.host == access::HostAccess::Normal
            || cfg
                .access
                .explicitly_grants(path, &cfg.work_dir, &cfg.home_dir)
    };
    let sensitive_files = stage::find_sensitive_files_with_config(
        &cfg.work_dir.to_string_lossy(),
        home_dir,
        &cfg.config.secrets.env_files,
        &cfg.config.paths.staged_configs,
        &allow_home_path,
    )?;
    if sensitive_files.is_empty() {
        return Ok(());
    }

    let work_dir_str = cfg.work_dir.to_string_lossy().to_string();

    // Create obfuscated copies of all sensitive files
    let mut file_stage = stage::FileStage::new_with_config(
        &cfg.runtime_dir,
        cfg.secrets.clone(),
        cfg.config.secrets.name_patterns.clone(),
        cfg.config.secrets.min_length,
        cfg.config.secrets.min_char_classes,
    )?;
    for path in &sensitive_files {
        file_stage.stage_file(path)?;
    }
    cfg.file_stage = Some(file_stage);

    // Classify each sensitive file and set up env injection / read denial
    for path_str in &sensitive_files {
        let kind = stage::classify_sensitive_file(path_str, &work_dir_str, home_dir);

        match kind {
            stage::SensitiveFileKind::EnvFile => {
                inject_env_file_entries(cfg, path_str)?;
            }
            stage::SensitiveFileKind::HomeConfig => {
                inject_config_redirect(cfg, path_str, home_dir);
            }
            stage::SensitiveFileKind::SshKey => {}
        }

        cfg.denied_read_paths.push(PathBuf::from(path_str));
    }
    Ok(())
}

/// Parses a .env file and injects its entries into the sandbox environment,
/// obfuscating every value already recognized by the conservative scanner.
fn inject_env_file_entries(cfg: &mut sandbox::SandboxConfig, path: &str) -> io::Result<()> {
    for (key, value) in stage::parse_env_file_entries(path)? {
        let injected = cfg
            .secrets
            .real_to_fake
            .get(&value)
            .cloned()
            .unwrap_or(value);
        cfg.injected_env.insert(key, injected);
    }
    Ok(())
}

/// Redirects a home directory config file to its obfuscated staged copy
/// via environment variables.
fn inject_config_redirect(cfg: &mut sandbox::SandboxConfig, path: &str, home_dir: &str) {
    let Some(ref file_stage) = cfg.file_stage else {
        return;
    };
    let Some(sf) = file_stage
        .staged_files()
        .iter()
        .find(|sf| sf.original_path.to_string_lossy() == path)
    else {
        return;
    };

    for (key, value) in stage::redirect_env_for_staged_file_with_config(
        &sf.original_path,
        &sf.staged_path,
        home_dir,
        &cfg.config.paths.staged_configs,
    ) {
        cfg.injected_env.insert(key, value);
    }
}

/// Starts the explicitly requested monitor or fails the invocation setup.
fn start_monitor(cfg: &sandbox::SandboxConfig) -> io::Result<monitor::Monitor> {
    let mut monitor = monitor::Monitor::new(&cfg.runtime_dir)?;
    monitor.start()?;
    let _ = writeln!(
        io::stderr(),
        "[cdm] monitor: {}",
        monitor.log_path().display()
    );
    Ok(monitor)
}

/// Starts a per-run egress proxy. Real secret mappings remain in this
/// process's memory and are never serialized into sandbox-visible storage.
/// Prints the pre-launch summary to stderr.
fn print_summary(cfg: &sandbox::SandboxConfig) {
    let (sandbox_type, os_name) = if cfg.use_vm {
        let image = cfg.vm_image.as_deref().unwrap_or("bundled-alpine");
        ("libkrun VM".to_string(), format!("TSI, rootfs={}", image))
    } else if cfg!(target_os = "macos") {
        ("seatbelt".to_string(), "darwin".to_string())
    } else {
        ("bubblewrap".to_string(), "linux".to_string())
    };

    let _ = writeln!(
        io::stderr(),
        "[cdm] sandbox: {} ({})",
        sandbox_type,
        os_name
    );
    // Argv values can contain secrets and arbitrary Unix bytes. Never render
    // them in trusted-host diagnostics; only report the non-sensitive count.
    let _ = writeln!(
        io::stderr(),
        "[cdm] running: <{} argv entries>",
        cfg.command.len()
    );
    let _ = writeln!(
        io::stderr(),
        "[cdm] access: workspace={}, host={}",
        cfg.access.workspace.label(),
        cfg.access.host.label()
    );
    if cfg.secure {
        let _ = writeln!(
            io::stderr(),
            "[cdm] security: secure (deny-first, secrets scrambled)"
        );
    } else if cfg.scramble {
        let _ = writeln!(io::stderr(), "[cdm] secrets: scrambled");
    }

    if matches!(cfg.network, network::NetworkPolicy::Disabled) {
        let _ = writeln!(io::stderr(), "[cdm] network: disabled");
    } else if cfg.network.is_proxied() {
        let _ = writeln!(
            io::stderr(),
            "[cdm] network: proxied (port {}, MITM)",
            cfg.proxy_port
        );
    } else {
        let _ = writeln!(io::stderr(), "[cdm] network: direct");
    }

    if let Some(domains) = cfg.network.domains() {
        let allowed = domains.allowed_display();
        let denied = domains.denied_display();
        if !allowed.is_empty() {
            let _ = writeln!(io::stderr(), "[cdm] allowed domains: {}", allowed);
        }
        if !denied.is_empty() {
            let _ = writeln!(io::stderr(), "[cdm] denied domains: {}", denied);
        }
    }

    let _ = writeln!(io::stderr());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn explicit_monitor_setup_failure_is_returned() {
        let cfg = sandbox::SandboxConfig::new(Arc::new(config::CdmConfig::default())).unwrap();
        std::fs::set_permissions(&cfg.runtime_dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        let error = match start_monitor(&cfg) {
            Ok(_) => panic!("unsafe runtime unexpectedly accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        std::fs::set_permissions(&cfg.runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir(&cfg.runtime_dir).unwrap();
    }
}
