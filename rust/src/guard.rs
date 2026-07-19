//! Best-effort command preflight for catching obvious operator mistakes.
//!
//! This check is deliberately not a security boundary: a child can launch a
//! different executable after it starts, and shell programs can express more
//! than this module attempts to parse. Filesystem, network, and secret policy
//! are the enforcement boundaries.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::Path;

/// An invocation refused by the best-effort preflight guard.
#[derive(Debug)]
pub struct PreflightGuardError {
    pub executable: Option<String>,
    pub reason: String,
}

impl fmt::Display for PreflightGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.executable.is_some() {
            write!(
                f,
                "preflight guard refused a blocked executable — {}",
                self.reason
            )
        } else {
            write!(f, "invalid preflight pattern — {}", self.reason)
        }
    }
}

impl std::error::Error for PreflightGuardError {}

/// Checks the direct argv and, when unambiguous, a literal simple command
/// passed to an explicit `sh -c`-style invocation.
///
/// Despite the legacy config field name `prefix`, configured values are
/// tokenized patterns. The executable token matches an exact basename; every
/// configured argument token must match at the same argv position. A pattern
/// `aws` therefore matches `aws` and `/usr/bin/aws`, but not `aws-vault` or
/// `awesome-tool`.
pub fn check_command_with_config(
    command: &[OsString],
    blocked_commands: &[crate::config::BlockedCommandEntry],
) -> Result<(), PreflightGuardError> {
    let mut candidates = Vec::new();
    if !command.is_empty() {
        candidates.push(command.to_vec());
    }

    if command.first().is_some_and(|program| is_shell(program)) {
        if let Some(script) = shell_script(command) {
            if let Some(words) = parse_literal_simple_command(script) {
                candidates.push(words.into_iter().map(OsString::from).collect());
            }
        }
    }

    for blocked in blocked_commands {
        let pattern =
            parse_literal_simple_command(&blocked.prefix).ok_or_else(|| PreflightGuardError {
                executable: None,
                reason: "expected a literal simple command".into(),
            })?;
        for candidate in &candidates {
            let candidate = skip_assignments(candidate);
            if matches_pattern(candidate, &pattern) {
                return Err(PreflightGuardError {
                    executable: Some(
                        executable_basename(&candidate[0])
                            .to_str()
                            .unwrap_or("<non-UTF-8>")
                            .to_owned(),
                    ),
                    reason: blocked.reason.clone(),
                });
            }
        }
    }
    Ok(())
}

fn matches_pattern(command: &[OsString], pattern: &[String]) -> bool {
    let pattern = skip_pattern_assignments(pattern);
    if command.is_empty() || pattern.is_empty() || command.len() < pattern.len() {
        return false;
    }
    executable_basename(&command[0]) == executable_basename(OsStr::new(&pattern[0]))
        && command[1..pattern.len()]
            .iter()
            .zip(&pattern[1..])
            .all(|(actual, expected)| actual == OsStr::new(expected))
}

fn skip_pattern_assignments(mut words: &[String]) -> &[String] {
    while words
        .first()
        .is_some_and(|word| is_assignment(OsStr::new(word)))
    {
        words = &words[1..];
    }
    words
}

fn executable_basename(program: &OsStr) -> &OsStr {
    Path::new(program).file_name().unwrap_or(program)
}

fn skip_assignments(mut words: &[OsString]) -> &[OsString] {
    while words.first().is_some_and(|word| is_assignment(word)) {
        words = &words[1..];
    }
    words
}

fn is_assignment(word: &OsStr) -> bool {
    let Some(word) = word.to_str() else {
        return false;
    };
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn is_shell(program: &OsStr) -> bool {
    matches!(
        executable_basename(program).to_str(),
        Some("sh" | "bash" | "zsh" | "dash" | "ksh")
    )
}

fn shell_script(command: &[OsString]) -> Option<&str> {
    let mut args = command.iter().skip(1);
    while let Some(arg) = args.next() {
        let arg = arg.to_str()?;
        if arg == "--" {
            return None;
        }
        if arg == "-c" || (arg.starts_with('-') && arg[1..].chars().any(|c| c == 'c')) {
            return args.next()?.to_str();
        }
        if !arg.starts_with('-') {
            return None;
        }
    }
    None
}

/// Parses only a literal shell simple command. Anything involving expansion,
/// redirection, a control operator, a comment, or an unterminated escape/quote
/// is outside the preflight's intentionally narrow boundary.
fn parse_literal_simple_command(input: &str) -> Option<Vec<String>> {
    #[derive(Clone, Copy)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let mut quote = Quote::None;
    let mut escaped = false;
    let mut word = String::new();
    let mut word_started = false;
    let mut words = Vec::new();

    for ch in input.chars() {
        if escaped {
            if matches!(ch, '\n' | '\r') {
                return None;
            }
            word.push(ch);
            word_started = true;
            escaped = false;
            continue;
        }

        match quote {
            Quote::Single => {
                if ch == '\'' {
                    quote = Quote::None;
                } else {
                    word.push(ch);
                }
                word_started = true;
            }
            Quote::Double => match ch {
                '"' => {
                    quote = Quote::None;
                    word_started = true;
                }
                '\\' => escaped = true,
                '$' | '`' | '\n' | '\r' => return None,
                _ => {
                    word.push(ch);
                    word_started = true;
                }
            },
            Quote::None => match ch {
                '\'' => {
                    quote = Quote::Single;
                    word_started = true;
                }
                '"' => {
                    quote = Quote::Double;
                    word_started = true;
                }
                '\\' => escaped = true,
                c if c.is_ascii_whitespace() => {
                    if word_started {
                        words.push(std::mem::take(&mut word));
                        word_started = false;
                    }
                }
                // Shell-active syntax means this is not a literal simple
                // command. Rejecting it avoids pretending to parse a shell.
                ';' | '|' | '&' | '<' | '>' | '(' | ')' | '$' | '`' | '#' | '*' | '?' | '['
                | ']' | '{' | '}' | '~' | '\n' | '\r' => return None,
                _ => {
                    word.push(ch);
                    word_started = true;
                }
            },
        }
    }

    if escaped || !matches!(quote, Quote::None) {
        return None;
    }
    if word_started {
        words.push(word);
    }
    (!skip_pattern_assignments(&words).is_empty()).then_some(words)
}

#[cfg(test)]
mod tests;
