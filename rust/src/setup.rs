//! Guided discovery and selection of compiled coding-harness profiles.

use std::env;
use std::ffi::OsStr;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::config;

pub fn run() -> io::Result<()> {
    let terminal = io::stdin().is_terminal() && io::stderr().is_terminal();
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    let path = env::var_os("PATH").unwrap_or_default();
    let mut stdout = io::stdout().lock();
    run_with(
        &home,
        &path,
        terminal,
        |profiles, defaults| {
            let labels = profiles
                .iter()
                .map(|profile| profile.display_name)
                .collect::<Vec<_>>();
            dialoguer::MultiSelect::new()
                .with_prompt("Enable detected CDM profiles")
                .items(&labels)
                .defaults(defaults)
                .interact_opt()
                .map_err(io::Error::other)
        },
        &mut stdout,
    )
}

fn run_with<F>(
    home: &Path,
    path: &OsStr,
    terminal: bool,
    choose: F,
    writer: &mut impl Write,
) -> io::Result<()>
where
    F: FnOnce(&[&'static config::BuiltInProfile], &[bool]) -> io::Result<Option<Vec<usize>>>,
{
    if !terminal {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "`cdm setup` requires an interactive terminal on stdin and stderr",
        ));
    }

    // Validate any previous registry before prompting so malformed or unsafe
    // policy state can never be replaced by a success-shaped setup run.
    let _ = config::read_setup_profiles_in(home)?;
    let profiles = detect_profiles(home, path);
    if profiles.is_empty() {
        writeln!(
            writer,
            "No supported coding harnesses detected; nothing changed."
        )?;
        return Ok(());
    }

    let defaults = vec![true; profiles.len()];
    let selected = choose(&profiles, &defaults)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Interrupted,
            "setup cancelled; nothing changed",
        )
    })?;
    let mut ids = Vec::with_capacity(selected.len());
    for index in selected {
        let profile = profiles.get(index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "setup selector returned an invalid profile index",
            )
        })?;
        ids.push(profile.id.to_string());
    }
    let registry = config::write_setup_profiles_in(home, &ids)?;
    let enabled = config::read_setup_profiles_in(home)?;
    writeln!(writer, "Enabled profiles: {}", enabled.join(", "))?;
    writeln!(writer, "Registry: {}", registry.display())?;
    Ok(())
}

fn detect_profiles(home: &Path, path: &OsStr) -> Vec<&'static config::BuiltInProfile> {
    config::built_in_profiles()
        .iter()
        .filter(|profile| {
            executable_on_path(profile.executable, path)
                || profile
                    .markers
                    .iter()
                    .any(|marker| std::fs::symlink_metadata(home.join(marker)).is_ok())
        })
        .collect()
}

fn executable_on_path(executable: &str, path: &OsStr) -> bool {
    env::split_paths(path).any(|directory| is_executable(&directory.join(executable)))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests;
