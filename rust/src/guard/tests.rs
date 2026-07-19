//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;
use crate::config::CdmConfig;

fn default_blocked() -> Vec<crate::config::BlockedCommandEntry> {
    CdmConfig::default().guard.blocked_commands
}

#[test]
fn allows_unlisted_command() {
    assert!(
        check_command_with_config(&["echo".into(), "hello".into()], &default_blocked()).is_ok()
    );
}

#[test]
fn blocks_direct_exact_pattern() {
    assert!(check_command_with_config(
        &["sudo".into(), "rm".into(), "-rf".into(), "/".into()],
        &default_blocked()
    )
    .is_err());
    assert!(check_command_with_config(
        &["rm".into(), "-rf".into(), "/".into()],
        &default_blocked()
    )
    .is_err());
}

#[test]
fn empty_command_is_allowed() {
    assert!(check_command_with_config(&[], &default_blocked()).is_ok());
}

#[test]
fn blocks_literal_simple_command_inside_explicit_shell() {
    assert!(check_command_with_config(
        &["/bin/sh".into(), "-c".into(), "  sudo whoami".into()],
        &default_blocked()
    )
    .is_err());
}

#[test]
fn executable_matching_uses_an_exact_basename_boundary() {
    let blocked = aws_pattern();
    assert!(check_command_with_config(&["aws".into(), "s3".into()], &blocked).is_err());
    assert!(
        check_command_with_config(&["/opt/homebrew/bin/aws".into(), "s3".into()], &blocked)
            .is_err()
    );
    assert!(check_command_with_config(&["awesome-tool".into()], &blocked).is_ok());
    assert!(check_command_with_config(&["aws-vault".into()], &blocked).is_ok());
}

#[test]
fn opaque_argv_is_compared_safely_without_lossy_matching() {
    use std::os::unix::ffi::OsStringExt;

    let opaque_argument = OsString::from_vec(vec![0xff, b'a', b'w', b's']);
    assert!(
        check_command_with_config(&[OsString::from("echo"), opaque_argument], &aws_pattern(),)
            .is_ok()
    );

    // A non-UTF-8 executable cannot accidentally collapse onto a blocked
    // textual basename during lossy conversion.
    let opaque_executable = OsString::from_vec(vec![b'a', b'w', b's', 0xff]);
    assert!(check_command_with_config(&[opaque_executable], &aws_pattern()).is_ok());
}

#[test]
fn configured_argument_tokens_match_exactly() {
    let blocked = vec![crate::config::BlockedCommandEntry {
        prefix: "rm -rf /".into(),
        reason: "root deletion".into(),
    }];
    assert!(check_command_with_config(
        &["/bin/rm".into(), "-rf".into(), "/".into(), "extra".into()],
        &blocked
    )
    .is_err());
    assert!(
        check_command_with_config(&["rm".into(), "-rf".into(), "/tmp".into()], &blocked).is_ok()
    );
    assert!(check_command_with_config(
        &[
            "rm".into(),
            "--preserve-root=false".into(),
            "-rf".into(),
            "/".into()
        ],
        &blocked
    )
    .is_ok());
}

#[test]
fn simple_explicit_shell_commands_are_checked() {
    assert!(check_command_with_config(
        &[
            "/bin/zsh".into(),
            "-lc".into(),
            "AWS_PROFILE=dev /usr/local/bin/aws s3 ls".into(),
        ],
        &aws_pattern(),
    )
    .is_err());
}

#[test]
fn complex_shell_syntax_is_outside_the_preflight_boundary() {
    for script in [
        "echo ready; aws s3 ls",
        "echo ready | aws s3 cp - -",
        "$(printf aws) s3 ls",
        "command aws s3 ls",
    ] {
        assert!(
            check_command_with_config(&["sh".into(), "-c".into(), script.into()], &aws_pattern(),)
                .is_ok(),
            "preflight must not pretend to enforce complex script {script:?}",
        );
    }
}

#[test]
fn quoted_literal_words_are_parseable_but_expansions_are_not() {
    assert_eq!(
        parse_literal_simple_command("aws 's3 cp' \\\"literal\\\""),
        Some(vec!["aws".into(), "s3 cp".into(), "\"literal\"".into()])
    );
    assert!(parse_literal_simple_command("$PROGRAM s3 ls").is_none());
    assert!(parse_literal_simple_command("aws s3; echo bypass").is_none());
    assert!(parse_literal_simple_command("aws 'unterminated").is_none());
}

#[test]
fn invalid_configured_pattern_fails_closed() {
    let blocked = vec![crate::config::BlockedCommandEntry {
        prefix: "aws; true".into(),
        reason: "invalid".into(),
    }];
    let error = check_command_with_config(&["true".into()], &blocked).unwrap_err();
    assert!(error.executable.is_none());
}

fn aws_pattern() -> Vec<crate::config::BlockedCommandEntry> {
    vec![crate::config::BlockedCommandEntry {
        prefix: "aws".into(),
        reason: "cloud credentials are host-owned".into(),
    }]
}
