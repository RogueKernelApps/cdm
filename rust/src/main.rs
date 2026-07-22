//! CDM — Opinionated OS-native sandboxing for developer workflows.
//!
//! Wraps any command in an OS-native sandbox with automatic secret obfuscation.

use std::env;
use std::io;

mod access;
mod anchored;
mod app;
mod cli;
mod config;
mod guard;
mod invocation;
mod monitor;
mod network;
mod process;
mod project;
mod proxy;
#[cfg(any(target_os = "linux", test))]
mod proxy_bridge;
mod report;
mod sandbox;
mod secrets;
mod stage;
mod trusted_exec;
mod worktree;

const VERSION: &str = "0.1.4";

fn main() {
    let exit_code = run();
    std::process::exit(exit_code);
}

/// Runs CDM and returns the exit code. Structured so all locals are dropped
/// before process::exit() — this ensures proxy threads shut down, temp dirs
/// are cleaned, and ports are released.
fn run() -> i32 {
    #[cfg(target_os = "linux")]
    if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("__linux-proxy-helper")) {
        let arguments = env::args_os().skip(2).collect::<Vec<_>>();
        let Some(bridge) = arguments.first() else {
            eprintln!("[cdm] error: Linux proxy bridge path is missing");
            return 125;
        };
        let Some(port) = arguments.get(1).and_then(|value| value.to_str()) else {
            eprintln!("[cdm] error: Linux proxy bridge port is missing");
            return 125;
        };
        let Ok(port) = port.parse::<u16>() else {
            eprintln!("[cdm] error: Linux proxy bridge port is invalid");
            return 125;
        };
        if arguments.get(2).and_then(|value| value.to_str()) != Some("--") {
            eprintln!("[cdm] error: Linux proxy helper command separator is missing");
            return 125;
        }
        return match proxy_bridge::run_namespace_helper(
            std::path::Path::new(bridge),
            port,
            &arguments[3..],
        ) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("[cdm] error: Linux proxy helper: {error}");
                125
            }
        };
    }
    #[cfg(feature = "vm")]
    if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("__vm-launcher")) {
        let Some(plan) = env::args_os().nth(2) else {
            eprintln!("[cdm] error: VM launcher plan is missing");
            return 125;
        };
        return match sandbox::vm::run_launcher(std::path::Path::new(&plan)) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("[cdm] error: VM launcher: {error}");
                125
            }
        };
    }
    let action = match cli::parse(env::args_os().skip(1)) {
        Ok(action) => action,
        Err(error) => {
            let _ = error.print();
            return 2;
        }
    };

    match action {
        cli::Action::Capabilities => {
            println!("native");
            println!("strict-proxy");
            #[cfg(feature = "vm")]
            println!("vm");
            0
        }
        cli::Action::Run(args) => invocation::run(*args),
        cli::Action::WriteConfig => match config::save_default() {
            Ok(()) => {
                eprintln!("[cdm] config written to {}", config::config_path_display());
                0
            }
            Err(e) => {
                eprintln!("[cdm] error writing config: {}", e);
                1
            }
        },
        cli::Action::Trust => trust_project_config(),
        cli::Action::Project => report_project(),
        cli::Action::Version => {
            println!("cdm {}", VERSION);
            0
        }
        cli::Action::Help => {
            if let Err(error) = cli::write_help(&mut io::stdout()) {
                eprintln!("[cdm] error writing help: {error}");
                return 1;
            }
            0
        }
        cli::Action::Completions(shell) => {
            cli::write_completions(shell, &mut io::stdout());
            0
        }
    }
}

fn discover_launch_project() -> Result<project::ProjectContext, String> {
    let launch_dir = env::current_dir()
        .map_err(|error| format!("cannot determine launch directory: {error}"))?;
    project::discover(&launch_dir).map_err(|error| format!("project discovery: {error}"))
}

fn trust_project_config() -> i32 {
    let project = match discover_launch_project() {
        Ok(project) => project,
        Err(error) => {
            eprintln!("[cdm] error: {error}");
            return 2;
        }
    };
    match config::trust_project(&project) {
        Ok(receipt) => {
            println!("project: {}", project.root.display());
            println!("config: {}", receipt.config_path.display());
            println!("sha256: {}", receipt.sha256);
            println!("trust-store: {}", receipt.trust_store_path.display());
            0
        }
        Err(error) => {
            eprintln!("[cdm] error: cannot trust project config: {error}");
            2
        }
    }
}

fn report_project() -> i32 {
    match discover_launch_project() {
        Ok(project) => {
            println!("root: {}", project.root.display());
            println!("kind: {}", project.kind());
            match project.config_path {
                Some(path) => println!("config: {}", path.display()),
                None => println!("config: none"),
            }
            0
        }
        Err(error) => {
            eprintln!("[cdm] error: {error}");
            2
        }
    }
}
