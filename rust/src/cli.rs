//! Typed command-line parsing and generated shell completions.

use clap::{CommandFactory, Parser, ValueEnum};
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Run(Box<RunArgs>),
    WriteConfig,
    Setup,
    Trust,
    Project,
    Completions(CompletionShell),
    Help,
    Version,
    Capabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
#[command(
    name = "cdm",
    disable_help_flag = true,
    disable_version_flag = true,
    trailing_var_arg = true
)]
pub struct RunArgs {
    /// Apply a profile enabled by `cdm setup` (pi, claude, codex, or copilot). May be repeated.
    #[arg(long, value_name = "ID")]
    pub profile: Vec<String>,
    /// Apply a named global configuration preset. May be repeated.
    #[arg(long, value_name = "NAME")]
    pub preset: Vec<String>,
    /// Disable all networking.
    #[arg(long)]
    pub no_network: bool,
    /// Use direct networking even when scrambling secrets.
    #[arg(long)]
    pub no_proxy: bool,
    /// Enable deny-first hardening and imply --scramble.
    #[arg(long)]
    pub sec: bool,
    /// Scramble discovered secrets, hide credential files, and enable the egress proxy.
    #[arg(long)]
    pub scramble: bool,
    /// Make the workspace read-only; read/write is the default.
    #[arg(long)]
    pub ro: bool,
    /// Hide host user data outside explicit grants.
    #[arg(long)]
    pub iso: bool,
    /// Add a read-only path grant. May be repeated.
    #[arg(short = 'r', long, value_name = "PATH")]
    pub allow_ro: Vec<PathBuf>,
    /// Add a read/write path grant. May be repeated.
    #[arg(short = 'w', long, value_name = "PATH")]
    pub allow_rw: Vec<PathBuf>,
    /// Explicit alternative to automatic macOS .app command detection.
    #[arg(long, value_name = "PATH.APP")]
    pub app: Option<PathBuf>,
    /// Show sandbox denials in real time.
    #[arg(long)]
    pub monitor: bool,
    /// Only allow these comma-separated domains. Requires --scramble or --sec.
    #[arg(long, value_name = "DOMAINS")]
    pub allow_domains: Option<String>,
    /// Block these comma-separated domains. Requires --scramble or --sec.
    #[arg(long, value_name = "DOMAINS")]
    pub deny_domains: Option<String>,
    /// Permit proxy connections to private and host-local network addresses.
    #[arg(long)]
    pub allow_private_network: bool,
    /// Run inside the bundled libkrun microVM.
    #[arg(long, conflicts_with = "vmi")]
    pub vm: bool,
    /// Run inside a libkrun microVM using an OCI image.
    #[arg(long, value_name = "IMAGE", conflicts_with = "vm")]
    pub vmi: Option<String>,
    /// Run against a temporary Git worktree.
    #[arg(long)]
    pub worktree: bool,
    /// Write a schema-versioned, redacted JSON session report.
    #[arg(long, value_name = "PATH")]
    pub report_json: Option<PathBuf>,
    /// Print compact session statistics to stderr.
    #[arg(long)]
    pub stats: bool,
    /// Suppress routine CDM status output.
    #[arg(short, long)]
    pub quiet: bool,
    /// Command and arguments. Shell syntax requires an explicit shell.
    #[arg(value_name = "COMMAND", allow_hyphen_values = true)]
    pub command: Vec<OsString>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

impl CompletionShell {
    fn generator(self) -> clap_complete::Shell {
        match self {
            Self::Bash => clap_complete::Shell::Bash,
            Self::Zsh => clap_complete::Shell::Zsh,
            Self::Fish => clap_complete::Shell::Fish,
        }
    }
}

/// Parses CDM's built-ins or a sandboxed command without converting command
/// arguments to UTF-8.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Action, clap::Error> {
    let mut args = args.into_iter().collect::<Vec<_>>();
    let Some(first) = args.first().map(OsString::as_os_str) else {
        return Ok(Action::Help);
    };

    match first.to_str() {
        Some("help" | "--help" | "-h") => Ok(Action::Help),
        Some("version" | "--version" | "-v") => Ok(Action::Version),
        Some("__capabilities__") => Ok(Action::Capabilities),
        Some("config") if args.len() == 1 => Ok(Action::WriteConfig),
        Some("config") => Err(clap::Error::raw(
            clap::error::ErrorKind::TooManyValues,
            "cdm config does not accept arguments",
        )),
        Some("setup") if args.len() == 1 => Ok(Action::Setup),
        Some("setup") => Err(clap::Error::raw(
            clap::error::ErrorKind::TooManyValues,
            "cdm setup does not accept arguments",
        )),
        Some("trust") if args.len() == 1 => Ok(Action::Trust),
        Some("trust") => Err(clap::Error::raw(
            clap::error::ErrorKind::TooManyValues,
            "cdm trust does not accept arguments",
        )),
        Some("project") if args.len() == 1 => Ok(Action::Project),
        Some("project") => Err(clap::Error::raw(
            clap::error::ErrorKind::TooManyValues,
            "cdm project does not accept arguments",
        )),
        Some("completions") => parse_completions(&args[1..]),
        Some("run") => {
            args.remove(0);
            parse_run(args)
        }
        _ => parse_run(args),
    }
}

fn parse_run(args: Vec<OsString>) -> Result<Action, clap::Error> {
    let argv = std::iter::once(OsString::from("cdm")).chain(args);
    RunArgs::try_parse_from(argv).map(Box::new).map(Action::Run)
}

fn parse_completions(args: &[OsString]) -> Result<Action, clap::Error> {
    #[derive(Parser)]
    #[command(name = "cdm completions")]
    struct CompletionArgs {
        #[arg(value_enum)]
        shell: CompletionShell,
    }

    let argv = std::iter::once(OsString::from("cdm completions")).chain(args.iter().cloned());
    CompletionArgs::try_parse_from(argv).map(|parsed| Action::Completions(parsed.shell))
}

pub fn write_completions(shell: CompletionShell, writer: &mut dyn io::Write) {
    let mut command = completion_command();
    clap_complete::generate(shell.generator(), &mut command, "cdm", writer);
    // clap_complete currently omits positional possible values from Fish
    // output. Keep the values sourced from the same typed enum rather than
    // maintaining a second shell list.
    if shell == CompletionShell::Fish {
        let values = CompletionShell::value_variants()
            .iter()
            .filter_map(|value| value.to_possible_value())
            .map(|value| value.get_name().to_owned())
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(
            writer,
            "complete -c cdm -n '__fish_cdm_using_subcommand completions' -f -a '{values}'"
        );
    }
}

fn completion_command() -> clap::Command {
    let run = RunArgs::command().name("run").bin_name("cdm run");
    RunArgs::command()
        .subcommand(run)
        .subcommand(clap::Command::new("config"))
        .subcommand(clap::Command::new("setup"))
        .subcommand(clap::Command::new("trust"))
        .subcommand(clap::Command::new("project"))
        .subcommand(
            clap::Command::new("completions").arg(
                clap::Arg::new("shell")
                    .required(true)
                    .value_parser(clap::builder::EnumValueParser::<CompletionShell>::new()),
            ),
        )
        .subcommand(clap::Command::new("version"))
}

pub fn write_help(writer: &mut impl io::Write) -> io::Result<()> {
    writeln!(
        writer,
        "cdm - Opinionated OS-native sandboxing for developer workflows\n"
    )?;
    writeln!(writer, "USAGE:\n    cdm [FLAGS] [COMMAND] [ARGS]...")?;
    writeln!(writer, "    cdm run [FLAGS] [COMMAND] [ARGS]...")?;
    writeln!(writer, "    cdm config")?;
    writeln!(writer, "    cdm setup")?;
    writeln!(writer, "    cdm trust")?;
    writeln!(writer, "    cdm project")?;
    writeln!(writer, "    cdm help")?;
    writeln!(writer, "    cdm version")?;
    writeln!(writer, "    cdm completions <bash|zsh|fish>\n")?;
    writeln!(writer, "BUILT-IN COMMANDS:")?;
    writeln!(
        writer,
        "    setup       Interactively enable detected coding-harness profiles"
    )?;
    writeln!(writer, "                IDs: pi, claude, codex, copilot")?;
    writeln!(
        writer,
        "    config      Create the global configuration if absent"
    )?;
    writeln!(
        writer,
        "    trust       Approve the nearest project configuration"
    )?;
    writeln!(
        writer,
        "    project     Report the discovered project and configuration"
    )?;
    writeln!(writer, "    completions Generate shell completion source\n")?;
    let mut command = RunArgs::command();
    command.write_long_help(writer)?;
    Ok(())
}

#[cfg(test)]
mod tests;
