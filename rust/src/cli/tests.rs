//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;

fn strings(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn parses_shorthand_and_explicit_run_identically() {
    let shorthand = parse(strings(&["--ro", "echo", "--literal"])).unwrap();
    let explicit = parse(strings(&["run", "--ro", "echo", "--literal"])).unwrap();
    assert_eq!(shorthand, explicit);
}

#[test]
fn preserves_command_argument_boundaries() {
    let Action::Run(run) = parse(strings(&["--", "printf", "a b", "--flag"])).unwrap() else {
        panic!("expected run");
    };
    assert_eq!(run.command, strings(&["printf", "a b", "--flag"]));
}

#[cfg(unix)]
#[test]
fn preserves_non_utf8_command_arguments() {
    use std::os::unix::ffi::OsStringExt;
    let opaque = OsString::from_vec(vec![b'f', 0x80]);
    let Action::Run(run) = parse(vec![OsString::from("echo"), opaque.clone()]).unwrap() else {
        panic!("expected run");
    };
    assert_eq!(run.command[1], opaque);
}

#[test]
fn parses_short_path_grants() {
    let Action::Run(run) = parse(strings(&[
        "-r", "config", "-w", "output", "-r", "cache", "echo",
    ]))
    .unwrap() else {
        panic!("expected run");
    };
    assert_eq!(
        run.allow_ro,
        [PathBuf::from("config"), PathBuf::from("cache")]
    );
    assert_eq!(run.allow_rw, [PathBuf::from("output")]);
    assert_eq!(run.command, strings(&["echo"]));
}

#[test]
fn accepts_worktree_and_does_not_treat_workspace_as_a_flag() {
    let Action::Run(run) = parse(strings(&["--worktree", "echo"])).unwrap() else {
        panic!("expected run");
    };
    assert!(run.worktree);
    let Action::Run(old) = parse(strings(&["--workspace", "echo"])).unwrap() else {
        panic!("expected run");
    };
    assert!(!old.worktree);
    assert_eq!(old.command, strings(&["--workspace", "echo"]));
}

#[test]
fn parses_explicit_secret_scrambling() {
    let Action::Run(run) = parse(strings(&["--scramble", "echo", "ok"])).unwrap() else {
        panic!("expected run");
    };
    assert!(run.scramble);
}

#[test]
fn rejects_arguments_to_config_command() {
    assert!(parse(strings(&["config", "extra"])).is_err());
}

#[test]
fn parses_trust_and_project_as_argument_free_builtins() {
    assert_eq!(parse(strings(&["trust"])).unwrap(), Action::Trust);
    assert_eq!(parse(strings(&["project"])).unwrap(), Action::Project);
    assert!(parse(strings(&["trust", "extra"])).is_err());
    assert!(parse(strings(&["project", "extra"])).is_err());
}

#[test]
fn parses_repeatable_presets_in_order() {
    let Action::Run(run) = parse(strings(&[
        "--preset", "browser", "--preset", "python", "echo",
    ]))
    .unwrap() else {
        panic!("expected run");
    };
    assert_eq!(run.preset, ["browser", "python"]);
    assert_eq!(run.command, strings(&["echo"]));
}

#[test]
fn parses_repeatable_profiles_in_order_without_consuming_the_command() {
    let Action::Run(run) = parse(strings(&[
        "--profile",
        "pi",
        "--profile",
        "claude",
        "printf",
        "--literal",
    ]))
    .unwrap() else {
        panic!("expected run");
    };
    assert_eq!(run.profile, ["pi", "claude"]);
    assert_eq!(run.command, strings(&["printf", "--literal"]));
}

#[test]
fn parses_setup_as_an_argument_free_builtin() {
    assert_eq!(parse(strings(&["setup"])).unwrap(), Action::Setup);
    assert!(parse(strings(&["setup", "extra"])).is_err());
}

#[test]
fn parses_structured_report_options_without_consuming_the_command() {
    let Action::Run(run) = parse(strings(&[
        "--report-json",
        "reports/session.json",
        "--stats",
        "printf",
        "hello",
    ]))
    .unwrap() else {
        panic!("expected run");
    };
    assert_eq!(run.report_json, Some(PathBuf::from("reports/session.json")));
    assert!(run.stats);
    assert_eq!(run.command, strings(&["printf", "hello"]));
}

#[test]
fn generates_completions_from_the_typed_command() {
    for shell in [
        CompletionShell::Bash,
        CompletionShell::Zsh,
        CompletionShell::Fish,
    ] {
        let mut output = Vec::new();
        write_completions(shell, &mut output);
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("allow-rw"));
        assert!(output.contains("scramble"));
        assert!(output.contains("worktree"));
        assert!(!output.contains("--workspace"));
        assert!(output.contains("report-json"));
        assert!(output.contains("stats"));
        assert!(output.contains("quiet"));
        assert!(output.contains("preset"));
        assert!(output.contains("profile"));
        assert!(output.contains("setup"));
        assert!(output.contains("trust"));
        assert!(output.contains("project"));
    }
}

#[test]
fn completion_tree_assigns_run_flags_to_the_run_subcommand() {
    let command = completion_command();
    let run = command
        .find_subcommand("run")
        .expect("run subcommand must be present");
    assert!(run
        .get_arguments()
        .any(|argument| argument.get_id() == "allow_rw"));
    assert!(run
        .get_arguments()
        .any(|argument| argument.get_id() == "preset"));
    assert!(run
        .get_arguments()
        .any(|argument| argument.get_id() == "profile"));
    assert!(run
        .get_arguments()
        .any(|argument| argument.get_id() == "report_json"));
    let setup = command
        .find_subcommand("setup")
        .expect("setup subcommand must be present");
    assert!(!setup
        .get_arguments()
        .any(|argument| argument.get_id() == "profile"));
}

#[test]
fn completion_tree_describes_builtin_commands_and_shell_values() {
    let command = completion_command();
    for name in ["config", "setup", "trust", "project", "version"] {
        assert!(command.find_subcommand(name).is_some(), "missing {name}");
    }

    let completions = command
        .find_subcommand("completions")
        .expect("completions subcommand must be present");
    let shell = completions
        .get_arguments()
        .find(|argument| argument.get_id() == "shell")
        .expect("completions must describe its shell argument");
    let values = shell
        .get_value_parser()
        .possible_values()
        .expect("shell values must be enumerable")
        .map(|value| value.get_name().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(values, ["bash", "zsh", "fish"]);

    let mut fish = Vec::new();
    write_completions(CompletionShell::Fish, &mut fish);
    assert!(String::from_utf8(fish)
        .unwrap()
        .contains("-a 'bash zsh fish'"));
}

#[test]
fn generated_help_documents_structured_report_options() {
    let mut output = Vec::new();
    write_help(&mut output).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("--report-json <PATH>"));
    assert!(output.contains("--stats"));
    assert!(output.contains("-q, --quiet"));
    assert!(output.contains("stderr"));
    assert!(output.contains("--preset <NAME>"));
    assert!(output.contains("--profile <ID>"));
    assert!(output.contains("cdm setup"));
    assert!(output.contains("Refresh transparent bundled coding-harness profiles"));
    assert!(output.contains("pi, claude, codex, copilot"));
    assert!(output.contains("read/write is the default"));
    assert!(output.contains("cdm trust"));
    assert!(output.contains("cdm project"));
}

#[test]
fn parses_short_and_long_quiet_flags() {
    let Action::Run(short) = parse(strings(&["-q", "true"])).unwrap() else {
        panic!("expected run");
    };
    let Action::Run(long) = parse(strings(&["--quiet", "true"])).unwrap() else {
        panic!("expected run");
    };
    assert!(short.quiet);
    assert!(long.quiet);
    assert_eq!(short.command, strings(&["true"]));
    assert_eq!(long.command, strings(&["true"]));
}

#[test]
fn generated_help_matches_the_reviewed_cli_snapshot() {
    let mut output = Vec::new();
    write_help(&mut output).unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        include_str!("../../tests/fixtures/cli-help.txt")
    );
}
