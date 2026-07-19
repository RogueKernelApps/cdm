use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const ELF_HEADER_64_BYTES: usize = 64;
const PT_INTERP: u32 = 3;
const PT_DYNAMIC: u32 = 2;
const DT_NEEDED: u64 = 1;

pub struct VerifiedArtifact {
    pub binary: Vec<u8>,
    pub provenance: Vec<u8>,
    pub sha256: String,
}

pub fn load_verified_artifact(
    binary_path: &Path,
    provenance_path: &Path,
    expected_sha: &str,
    architecture: &str,
) -> io::Result<VerifiedArtifact> {
    let binary = read_secure_file(binary_path, true)?;
    let provenance = read_secure_file(provenance_path, false)?;
    let sha256 = hex_sha256(&binary);
    if sha256 != expected_sha {
        return Err(invalid(format!(
            "SHA-256 mismatch: expected {expected_sha}, got {sha256}"
        )));
    }
    validate_static_linux_elf(&binary, architecture)?;
    validate_provenance(
        &provenance,
        &sha256,
        binary.len(),
        &format!("{architecture}-unknown-linux-musl"),
    )?;
    Ok(VerifiedArtifact {
        binary,
        provenance,
        sha256,
    })
}

fn read_secure_file(path: &Path, executable: bool) -> io::Result<Vec<u8>> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(invalid("artifact must be a regular, non-hard-linked file"));
    }
    if metadata.uid() != unsafe { libc::getuid() } || metadata.mode() & 0o022 != 0 {
        return Err(invalid(
            "artifact must be owned by the builder and not group- or world-writable",
        ));
    }
    if executable && metadata.mode() & 0o111 == 0 {
        return Err(invalid("guest-init artifact is not executable"));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_provenance(bytes: &[u8], digest: &str, size: usize, target: &str) -> io::Result<()> {
    let document: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("invalid guest-init provenance: {error}")))?;
    if document.get("schema").and_then(|value| value.as_u64()) != Some(1) {
        return Err(invalid("unsupported guest-init provenance schema"));
    }
    let artifact = document
        .get("artifact")
        .and_then(|value| value.as_object())
        .ok_or_else(|| invalid("guest-init provenance has no artifact object"))?;
    if artifact.get("sha256").and_then(|value| value.as_str()) != Some(digest)
        || artifact.get("size").and_then(|value| value.as_u64()) != Some(size as u64)
        || artifact.get("target").and_then(|value| value.as_str()) != Some(target)
    {
        return Err(invalid(
            "guest-init provenance does not match artifact digest, size, and target",
        ));
    }
    let inputs = document
        .get("inputs")
        .and_then(|value| value.as_array())
        .ok_or_else(|| invalid("guest-init provenance has no source inputs"))?;
    for required in [
        "Cargo.lock",
        "Cargo.toml",
        "schema-v2.json",
        "src/lib.rs",
        "src/linux.rs",
        "src/main.rs",
    ] {
        let present = inputs.iter().any(|input| {
            input.get("path").and_then(|value| value.as_str()) == Some(required)
                && input
                    .get("sha256")
                    .and_then(|value| value.as_str())
                    .is_some_and(valid_digest)
        });
        if !present {
            return Err(invalid(format!(
                "guest-init provenance is missing source input {required}"
            )));
        }
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub fn validate_static_linux_elf(bytes: &[u8], architecture: &str) -> io::Result<()> {
    if bytes.len() < ELF_HEADER_64_BYTES || &bytes[..4] != b"\x7fELF" {
        return Err(invalid("guest init is not an ELF executable"));
    }
    if bytes[4] != 2 || bytes[5] != 1 {
        return Err(invalid(
            "guest init must be a little-endian 64-bit ELF executable",
        ));
    }
    let expected_machine = match architecture {
        "aarch64" => 183,
        "x86_64" => 62,
        other => return Err(invalid(format!("unsupported guest architecture {other}"))),
    };
    if little_u16(bytes, 18)? != expected_machine {
        return Err(invalid(format!(
            "guest init ELF architecture does not match {architecture}"
        )));
    }
    let program_offset = usize::try_from(little_u64(bytes, 32)?)
        .map_err(|_| invalid("guest init program-header offset overflows usize"))?;
    let entry_size = usize::from(little_u16(bytes, 54)?);
    let entry_count = usize::from(little_u16(bytes, 56)?);
    if entry_size < 8 {
        return Err(invalid("guest init has an invalid program-header size"));
    }
    let program_bytes = entry_size
        .checked_mul(entry_count)
        .and_then(|length| program_offset.checked_add(length))
        .ok_or_else(|| invalid("guest init program-header table overflows"))?;
    if program_bytes > bytes.len() {
        return Err(invalid("guest init program-header table is truncated"));
    }
    for index in 0..entry_count {
        let offset = program_offset + index * entry_size;
        let program_type = little_u32(bytes, offset)?;
        if program_type == PT_INTERP {
            return Err(invalid(
                "guest init is dynamically linked (PT_INTERP is present)",
            ));
        }
        if program_type == PT_DYNAMIC {
            reject_needed_entries(bytes, offset)?;
        }
    }
    Ok(())
}

fn reject_needed_entries(bytes: &[u8], program_header: usize) -> io::Result<()> {
    let dynamic_offset = usize::try_from(little_u64(bytes, program_header + 8)?)
        .map_err(|_| invalid("dynamic-table offset overflows usize"))?;
    let dynamic_size = usize::try_from(little_u64(bytes, program_header + 32)?)
        .map_err(|_| invalid("dynamic-table size overflows usize"))?;
    let end = dynamic_offset
        .checked_add(dynamic_size)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| invalid("dynamic table is truncated"))?;
    for entry in bytes[dynamic_offset..end].chunks_exact(16) {
        let tag = u64::from_le_bytes(entry[..8].try_into().expect("eight bytes"));
        if tag == DT_NEEDED {
            return Err(invalid("guest init has a DT_NEEDED dynamic dependency"));
        }
        if tag == 0 {
            break;
        }
    }
    Ok(())
}

fn little_u16(bytes: &[u8], offset: usize) -> io::Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| invalid("guest init ELF header is truncated"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn little_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| invalid("guest init ELF header is truncated"))?;
    Ok(u32::from_le_bytes(value.try_into().expect("four bytes")))
}

fn little_u64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| invalid("guest init ELF header is truncated"))?;
    Ok(u64::from_le_bytes(value.try_into().expect("eight bytes")))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn elf(machine: u16, program_type: u32) -> Vec<u8> {
        let mut bytes = vec![0; 128];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&program_type.to_le_bytes());
        bytes
    }

    #[test]
    fn accepts_matching_static_elfs() {
        validate_static_linux_elf(&elf(183, 1), "aarch64").unwrap();
        validate_static_linux_elf(&elf(62, 1), "x86_64").unwrap();
    }

    #[test]
    fn rejects_dynamic_wrong_architecture_and_malformed_artifacts() {
        assert!(validate_static_linux_elf(&elf(183, PT_INTERP), "aarch64").is_err());
        assert!(validate_static_linux_elf(&elf(62, 1), "aarch64").is_err());
        assert!(validate_static_linux_elf(b"not an elf", "aarch64").is_err());
        assert!(validate_static_linux_elf(&elf(183, 1), "riscv64").is_err());
    }

    #[test]
    fn rejects_truncated_program_header_table() {
        let mut bytes = elf(183, 1);
        bytes[32..40].copy_from_slice(&120_u64.to_le_bytes());
        assert!(validate_static_linux_elf(&bytes, "aarch64").is_err());
    }

    #[test]
    fn rejects_dt_needed_even_without_interpreter() {
        let mut bytes = elf(183, PT_DYNAMIC);
        bytes[72..80].copy_from_slice(&112_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&16_u64.to_le_bytes());
        bytes[112..120].copy_from_slice(&DT_NEEDED.to_le_bytes());
        assert!(validate_static_linux_elf(&bytes, "aarch64").is_err());
    }

    #[test]
    fn secure_open_rejects_symlink_hardlink_and_wrong_provenance() {
        let root = std::env::temp_dir().join(format!(
            "cdm-artifact-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let binary = root.join("guest-init");
        let provenance = root.join("provenance.json");
        let bytes = elf(183, 1);
        std::fs::write(&binary, &bytes).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let digest = hex_sha256(&bytes);
        std::fs::write(&provenance, provenance_json(&digest, bytes.len())).unwrap();
        std::fs::set_permissions(&provenance, std::fs::Permissions::from_mode(0o600)).unwrap();
        let verified = load_verified_artifact(&binary, &provenance, &digest, "aarch64").unwrap();
        assert_eq!(verified.binary, bytes);
        assert_eq!(verified.sha256, digest);
        assert!(!verified.provenance.is_empty());

        let link = root.join("link");
        symlink(&binary, &link).unwrap();
        assert!(load_verified_artifact(&link, &provenance, &digest, "aarch64").is_err());
        let hardlink = root.join("hardlink");
        std::fs::hard_link(&binary, &hardlink).unwrap();
        assert!(load_verified_artifact(&binary, &provenance, &digest, "aarch64").is_err());
        std::fs::remove_file(&hardlink).unwrap();

        std::fs::write(&provenance, provenance_json(&"0".repeat(64), bytes.len())).unwrap();
        assert!(load_verified_artifact(&binary, &provenance, &digest, "aarch64").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    fn provenance_json(digest: &str, size: usize) -> String {
        let inputs = [
            "Cargo.lock",
            "Cargo.toml",
            "schema-v2.json",
            "src/lib.rs",
            "src/linux.rs",
            "src/main.rs",
        ]
        .into_iter()
        .map(|path| serde_json::json!({"path": path, "sha256": "1".repeat(64)}))
        .collect::<Vec<_>>();
        serde_json::json!({
            "schema": 1,
            "artifact": {
                "name": "guest-init",
                "sha256": digest,
                "size": size,
                "target": "aarch64-unknown-linux-musl"
            },
            "inputs": inputs
        })
        .to_string()
    }
}
