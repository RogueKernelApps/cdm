//! Materialization of transparent bundled coding-harness profiles.

use std::env;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::config;

pub fn run() -> io::Result<()> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    let mut stdout = io::stdout().lock();
    run_with(&home, &mut stdout)
}

fn run_with(home: &Path, writer: &mut impl Write) -> io::Result<()> {
    let directory = config::materialize_bundled_profiles_in(home)?;
    let ids = config::built_in_profiles()
        .iter()
        .map(|profile| profile.id)
        .collect::<Vec<_>>()
        .join(", ");
    writeln!(writer, "Bundled profiles refreshed: {ids}")?;
    writeln!(writer, "Directory: {}", directory.display())?;
    Ok(())
}

#[cfg(test)]
mod tests;
