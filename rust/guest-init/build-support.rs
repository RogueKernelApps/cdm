use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::guest_init_artifact::load_verified_artifact;

#[cfg_attr(test, allow(dead_code))]
pub fn configure() {
    println!("cargo:rustc-check-cfg=cfg(cdm_guest_init_embedded)");
    for name in [
        "CDM_GUEST_INIT_BIN",
        "CDM_GUEST_INIT_SHA256",
        "CDM_GUEST_INIT_PROVENANCE",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    let Some(source) = std::env::var_os("CDM_GUEST_INIT_BIN").map(PathBuf::from) else {
        println!(
            "cargo:warning=VM build has no verified guest init; VM execution will fail clearly. Set CDM_GUEST_INIT_BIN, CDM_GUEST_INIT_SHA256, and CDM_GUEST_INIT_PROVENANCE."
        );
        return;
    };
    let expected_sha = required_env("CDM_GUEST_INIT_SHA256");
    let provenance = PathBuf::from(required_env("CDM_GUEST_INIT_PROVENANCE"));
    let architecture = std::env::var("CARGO_CFG_TARGET_ARCH")
        .expect("Cargo did not provide CARGO_CFG_TARGET_ARCH");
    let verified = load_verified_artifact(&source, &provenance, &expected_sha, &architecture)
        .unwrap_or_else(|error| panic!("invalid guest-init artifact: {error}"));

    let destination = PathBuf::from(required_env("OUT_DIR")).join("cdm-guest-init");
    let provenance_destination =
        PathBuf::from(required_env("OUT_DIR")).join("cdm-guest-init.provenance.json");
    publish_output(&destination, &verified.binary, 0o555)
        .expect("cannot copy guest init into OUT_DIR");
    publish_output(&provenance_destination, &verified.provenance, 0o444)
        .expect("cannot copy guest-init provenance into OUT_DIR");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed={}", provenance.display());
    println!("cargo:rustc-cfg=cdm_guest_init_embedded");
    println!(
        "cargo:rustc-env=CDM_GUEST_INIT_EMBEDDED_PATH={}",
        destination.display()
    );
    println!(
        "cargo:rustc-env=CDM_GUEST_INIT_PROVENANCE_PATH={}",
        provenance_destination.display()
    );
    println!(
        "cargo:rustc-env=CDM_GUEST_INIT_ARTIFACT_SHA256={}",
        verified.sha256
    );
}

/// Atomically replaces a generated build output, including an earlier
/// read-only copy from a previous Cargo invocation.
fn publish_output(destination: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output has no parent"))?;
    let name = destination
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output has no file name"))?;

    for attempt in 0..32_u8 {
        let temporary = parent.join(format!(
            ".{}.{}.{}.tmp",
            name.to_string_lossy(),
            std::process::id(),
            attempt
        ));
        let mut file = match OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            drop(file);
            fs::rename(&temporary, destination)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        return result;
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not reserve a temporary build output",
    ))
}

#[cfg_attr(test, allow(dead_code))]
fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required with CDM_GUEST_INIT_BIN"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn generated_output_can_replace_an_earlier_read_only_copy() {
        let root = std::env::temp_dir().join(format!(
            "cdm-build-output-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let output = root.join("cdm-guest-init");

        publish_output(&output, b"first", 0o555).unwrap();
        publish_output(&output, b"second", 0o555).unwrap();

        assert_eq!(fs::read(&output).unwrap(), b"second");
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o555
        );
        fs::remove_dir_all(root).unwrap();
    }
}
