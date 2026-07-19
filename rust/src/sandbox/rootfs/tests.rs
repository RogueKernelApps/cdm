//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;
use std::io::Cursor;

fn test_cache(label: &str) -> PathBuf {
    let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
    let path = temp.join(format!(
        "cdm-rootfs-test-{label}-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn layer(entries: &[(&str, tar::EntryType, Option<&str>, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut bytes);
        for (path, entry_type, link, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*entry_type);
            header.set_mode(0o644);
            header.set_size(contents.len() as u64);
            header.set_path(path).unwrap();
            if let Some(target) = link {
                header.set_link_name(target).unwrap();
            }
            header.set_cksum();
            builder.append(&header, Cursor::new(*contents)).unwrap();
        }
        builder.finish().unwrap();
    }
    bytes
}

fn restrictive_limits() -> RootfsLimits {
    RootfsLimits {
        max_layer_compressed_bytes: 1024,
        max_total_compressed_bytes: 2048,
        max_layer_expanded_bytes: 1024,
        max_total_expanded_bytes: 2048,
        max_layer_entries: 2,
        max_total_entries: 3,
        max_path_depth: 2,
    }
}

#[test]
fn test_rootfs_limits_reject_zero_and_per_layer_above_image_total() {
    let config = crate::config::VmConfig {
        max_layer_entries: 0,
        ..Default::default()
    };
    assert_eq!(
        RootfsLimits::from_config(&config).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );

    let defaults = crate::config::VmConfig::default();
    let config = crate::config::VmConfig {
        max_layer_compressed_mib: defaults.max_image_compressed_mib + 1,
        ..defaults
    };
    let error = RootfsLimits::from_config(&config).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("per-layer"));
}

#[test]
fn test_oci_cache_name_deterministic() {
    let name1 = oci_cache_name("ubuntu:22.04");
    let name2 = oci_cache_name("ubuntu:22.04");
    assert_eq!(name1, name2);
}

#[test]
fn test_oci_cache_name_different_images() {
    let name1 = oci_cache_name("ubuntu:22.04");
    let name2 = oci_cache_name("alpine:3.19");
    assert_ne!(name1, name2);
}

#[test]
fn test_oci_cache_name_contains_sanitized_ref() {
    let name = oci_cache_name("ubuntu:22.04");
    assert!(name.starts_with("oci_ubuntu_22.04_"));
}

#[test]
fn test_oci_config_rejects_wrong_architecture() {
    let wrong_arch = if std::env::consts::ARCH == "aarch64" {
        "amd64"
    } else {
        "arm64"
    };
    let config = format!(
        r#"{{"architecture":"{wrong_arch}","os":"linux","rootfs":{{"type":"layers","diff_ids":[]}}}}"#
    );
    assert_eq!(
        validate_image_platform(&config).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn test_oci_config_accepts_host_linux_architecture() {
    let arch = if std::env::consts::ARCH == "aarch64" {
        "arm64"
    } else {
        "amd64"
    };
    let config = format!(
        r#"{{"architecture":"{arch}","os":"linux","rootfs":{{"type":"layers","diff_ids":[]}}}}"#
    );
    validate_image_platform(&config).unwrap();
}

#[test]
fn test_extract_bundled_rootfs_creates_dir() {
    let cache = test_cache("extract");
    let result = extract_bundled_rootfs_in(&cache);
    assert!(result.is_ok(), "extraction failed: {:?}", result.err());
    let dir = result.unwrap();
    assert!(dir.join("bin").is_dir(), "rootfs should contain /bin");
    assert!(dir.join("etc").is_dir(), "rootfs should contain /etc");
    let interpreter = match std::env::consts::ARCH {
        "aarch64" => "lib/ld-musl-aarch64.so.1",
        "x86_64" => "lib/ld-musl-x86_64.so.1",
        architecture => panic!("unsupported test architecture: {architecture}"),
    };
    assert!(
        dir.join(interpreter).exists(),
        "bundled rootfs must match the host VM architecture"
    );
    assert!(dir.join(COMPLETE_MARKER).is_file());
    let _ = std::fs::remove_dir_all(cache);
}

#[test]
fn test_extract_bundled_rootfs_idempotent() {
    let cache = test_cache("idempotent");
    let dir1 = extract_bundled_rootfs_in(&cache).unwrap();
    let dir2 = extract_bundled_rootfs_in(&cache).unwrap();
    assert_eq!(dir1, dir2);
    let _ = std::fs::remove_dir_all(cache);
}

#[test]
fn test_extract_bundled_rootfs_repairs_tree_poisoning() {
    let cache = test_cache("tree-poisoning");
    let dir = extract_bundled_rootfs_in(&cache).unwrap();
    let passwd = dir.join("etc/passwd");
    let expected = std::fs::read(&passwd).unwrap();
    std::fs::write(&passwd, b"poisoned\n").unwrap();

    let repaired = extract_bundled_rootfs_in(&cache).unwrap();

    assert_eq!(
        std::fs::read(repaired.join("etc/passwd")).unwrap(),
        expected
    );
    assert!(is_complete(
        &repaired,
        &format!("alpine-minirootfs-3.21.7-{BUNDLED_ARCH}")
    ));
    let _ = std::fs::remove_dir_all(cache);
}

#[test]
fn test_extract_bundled_rootfs_serializes_concurrent_publishers() {
    let cache = test_cache("concurrent");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let threads = (0..4)
        .map(|_| {
            let cache = cache.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                extract_bundled_rootfs_in(&cache)
            })
        })
        .collect::<Vec<_>>();

    let paths = threads
        .into_iter()
        .map(|thread| thread.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert!(paths.windows(2).all(|pair| pair[0] == pair[1]));
    assert!(paths[0].join("bin/busybox").is_file());
    let _ = std::fs::remove_dir_all(cache);
}

#[test]
fn test_publish_cache_atomically_replaces_a_previous_tree() {
    let cache = test_cache("publish");
    let destination = cache.join("root");
    let temp = temporary_cache_path(&destination, "tmp");
    std::fs::create_dir_all(&destination).unwrap();
    std::fs::create_dir_all(&temp).unwrap();
    std::fs::write(destination.join("old"), b"old").unwrap();
    std::fs::write(temp.join("new"), b"new").unwrap();

    publish_cache(
        &temp,
        &destination,
        &CacheMarker {
            schema: CACHE_SCHEMA,
            source: "test".into(),
            architecture: BUNDLED_ARCH.into(),
            resolved_digest: "sha256:test".into(),
            tree_digest: String::new(),
        },
    )
    .unwrap();

    assert!(!destination.join("old").exists());
    assert_eq!(std::fs::read(destination.join("new")).unwrap(), b"new");
    assert!(read_marker(&destination).is_some());
    assert!(std::fs::read_dir(&cache).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("root.previous-")
    }));
    let _ = std::fs::remove_dir_all(cache);
}

#[test]
fn test_stale_cache_cleanup_does_not_follow_symlinks_or_remove_unrelated_paths() {
    use std::os::unix::fs::symlink;

    let cache = test_cache("stale-cleanup");
    let destination = cache.join("root");
    let outside = cache.join("outside");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("sentinel"), b"preserve").unwrap();
    std::fs::create_dir(cache.join("root.tmp-stale")).unwrap();
    symlink(&outside, cache.join("root.previous-hostile")).unwrap();
    std::fs::create_dir(cache.join("root-unrelated")).unwrap();

    remove_stale_cache_paths(&destination).unwrap();

    assert!(!cache.join("root.tmp-stale").exists());
    assert!(!cache.join("root.previous-hostile").exists());
    assert!(cache.join("root-unrelated").is_dir());
    assert_eq!(
        std::fs::read(outside.join("sentinel")).unwrap(),
        b"preserve"
    );
    let _ = std::fs::remove_dir_all(cache);
}

#[test]
fn test_extract_bundled_rootfs_repairs_forged_complete_marker() {
    let cache = test_cache("forged-marker");
    let destination = cache.join(format!("bundled-{BUNDLED_ARCH}"));
    std::fs::create_dir_all(&destination).unwrap();
    std::fs::write(destination.join(COMPLETE_MARKER), b"complete\n").unwrap();

    let repaired = extract_bundled_rootfs_in(&cache).unwrap();

    assert!(repaired.join("bin/busybox").is_file());
    let _ = std::fs::remove_dir_all(cache);
}

#[test]
fn test_extract_bundled_rootfs_rejects_symlink_cache_root() {
    use std::os::unix::fs::symlink;

    let root = test_cache("cache-symlink-root");
    let cache = root.join("cache");
    let outside = root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("sentinel"), b"preserve").unwrap();
    symlink(&outside, &cache).unwrap();

    assert!(extract_bundled_rootfs_in(&cache).is_err());
    assert_eq!(
        std::fs::read(outside.join("sentinel")).unwrap(),
        b"preserve"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn test_resolve_uses_bundled_when_no_image() {
    let cache = test_cache("resolve");
    let limits = RootfsLimits::from_config(&crate::config::VmConfig::default()).unwrap();
    let path = resolve_in(None, &cache, &limits).unwrap();
    assert!(path.to_string_lossy().contains("bundled"));
    let _ = std::fs::remove_dir_all(cache);
}

#[test]
fn test_cache_dir_under_home() {
    let dir = cache_dir().unwrap();
    let home = std::env::var("HOME").unwrap();
    assert!(dir.starts_with(&home));
    assert!(dir.to_string_lossy().contains(".cdm/rootfs"));
}

#[test]
fn test_cache_dir_rejects_relative_override_without_mutating_environment() {
    let error =
        cache_dir_from(Some(PathBuf::from("/home/test")), Some("relative".into())).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("absolute"));
}

#[test]
fn test_private_cache_rejects_symlink_ancestor() {
    use std::os::unix::fs::symlink;

    let root = test_cache("private-symlink-ancestor");
    let outside = root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    symlink(&outside, root.join("linked")).unwrap();

    let error = ensure_private_directory(&root.join("linked/rootfs")).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!outside.join("rootfs").exists());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn test_private_cache_rejects_non_sticky_cross_user_writable_ancestor() {
    let root = test_cache("unsafe-writable-ancestor");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
    let sentinel = root.join("sentinel");
    std::fs::write(&sentinel, b"preserve").unwrap();

    let error = ensure_private_directory(&root.join("cache/rootfs")).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(!root.join("cache").exists());
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"preserve");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn test_cache_lock_rejects_symlink_and_multiply_linked_file() {
    use std::os::unix::fs::symlink;

    let root = test_cache("hostile-lock");
    std::fs::create_dir_all(&root).unwrap();
    let destination = root.join("image");
    let lock = destination.with_extension("lock");
    let outside = root.join("outside");
    std::fs::write(&outside, b"sentinel").unwrap();
    symlink(&outside, &lock).unwrap();
    assert!(lock_cache(&destination).is_err());
    std::fs::remove_file(&lock).unwrap();
    std::fs::hard_link(&outside, &lock).unwrap();
    assert!(lock_cache(&destination).is_err());
    assert_eq!(std::fs::read(&outside).unwrap(), b"sentinel");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn test_layer_whiteout_removes_only_an_in_root_entry() {
    let destination = test_cache("whiteout-normal");
    std::fs::create_dir_all(destination.join("etc")).unwrap();
    std::fs::write(destination.join("etc/removed"), b"old").unwrap();
    let data = layer(&[("etc/.wh.removed", tar::EntryType::Regular, None, b"")]);

    extract_layer(
        &data,
        "application/vnd.oci.image.layer.v1.tar",
        &destination,
    )
    .unwrap();

    assert!(!destination.join("etc/removed").exists());
    assert!(!destination.join("etc/.wh.removed").exists());
    let _ = std::fs::remove_dir_all(destination);
}

#[test]
fn test_layer_whiteout_rejects_symlink_ancestor() {
    use std::os::unix::fs::symlink;

    let destination = test_cache("whiteout-symlink");
    let outside = test_cache("whiteout-outside");
    std::fs::create_dir_all(&destination).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("sentinel"), b"preserve").unwrap();
    symlink(&outside, destination.join("escape")).unwrap();
    let data = layer(&[("escape/.wh.sentinel", tar::EntryType::Regular, None, b"")]);

    assert!(extract_layer(
        &data,
        "application/vnd.oci.image.layer.v1.tar",
        &destination
    )
    .is_err());
    assert_eq!(
        std::fs::read(outside.join("sentinel")).unwrap(),
        b"preserve"
    );
    let _ = std::fs::remove_dir_all(destination);
    let _ = std::fs::remove_dir_all(outside);
}

#[test]
fn test_layer_opaque_whiteout_rejects_symlink_ancestor() {
    use std::os::unix::fs::symlink;

    let destination = test_cache("opaque-symlink");
    let outside = test_cache("opaque-outside");
    std::fs::create_dir_all(&destination).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("sentinel"), b"preserve").unwrap();
    symlink(&outside, destination.join("escape")).unwrap();
    let data = layer(&[("escape/.wh..wh..opq", tar::EntryType::Regular, None, b"")]);

    assert!(extract_layer(
        &data,
        "application/vnd.oci.image.layer.v1.tar",
        &destination
    )
    .is_err());
    assert_eq!(
        std::fs::read(outside.join("sentinel")).unwrap(),
        b"preserve"
    );
    let _ = std::fs::remove_dir_all(destination);
    let _ = std::fs::remove_dir_all(outside);
}

#[test]
fn test_layer_rejects_expanded_tar_bomb_before_writing_files() {
    let destination = test_cache("expanded-bomb");
    std::fs::create_dir_all(&destination).unwrap();
    let payload = vec![b'x'; 16 * 1024];
    let data = layer(&[("payload", tar::EntryType::Regular, None, payload.as_slice())]);
    let mut budget = ExtractionBudget::default();

    let error = extract_layer_with_limits(
        &data,
        "application/vnd.oci.image.layer.v1.tar",
        &destination,
        &restrictive_limits(),
        &mut budget,
    )
    .unwrap_err();

    assert!(error.to_string().contains("expanded byte quota"));
    assert!(!destination.join("payload").exists());
    let _ = std::fs::remove_dir_all(destination);
}

#[test]
fn test_layer_rejects_sparse_or_truncated_declared_size_before_unpacking() {
    let destination = test_cache("declared-size-bomb");
    std::fs::create_dir_all(&destination).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_size(16 * 1024);
    header.set_path("payload").unwrap();
    header.set_cksum();
    let mut data = header.as_bytes().to_vec();
    data.extend_from_slice(&[0_u8; 1024]);
    let mut budget = ExtractionBudget::default();

    let error = extract_layer_with_limits(
        &data,
        "application/vnd.oci.image.layer.v1.tar",
        &destination,
        &restrictive_limits(),
        &mut budget,
    )
    .unwrap_err();

    assert!(error.to_string().contains("expanded byte quota"));
    assert!(!destination.join("payload").exists());
    let _ = std::fs::remove_dir_all(destination);
}

#[test]
fn test_layer_rejects_gzip_bomb_before_writing_files() {
    use std::io::Write;

    let destination = test_cache("gzip-bomb");
    std::fs::create_dir_all(&destination).unwrap();
    let payload = vec![0_u8; 128 * 1024];
    let tar = layer(&[("payload", tar::EntryType::Regular, None, payload.as_slice())]);
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&tar).unwrap();
    let compressed = encoder.finish().unwrap();
    assert!(compressed.len() < restrictive_limits().max_layer_compressed_bytes as usize);
    let mut budget = ExtractionBudget::default();

    let error = extract_layer_with_limits(
        &compressed,
        "application/vnd.oci.image.layer.v1.tar+gzip",
        &destination,
        &restrictive_limits(),
        &mut budget,
    )
    .unwrap_err();

    assert!(error.to_string().contains("expanded byte quota"));
    assert!(!destination.join("payload").exists());
    let _ = std::fs::remove_dir_all(destination);
}

#[test]
fn test_layer_rejects_entry_and_depth_quotas() {
    let destination = test_cache("metadata-quotas");
    std::fs::create_dir_all(&destination).unwrap();
    let too_many = layer(&[
        ("one", tar::EntryType::Regular, None, b""),
        ("two", tar::EntryType::Regular, None, b""),
        ("three", tar::EntryType::Regular, None, b""),
    ]);
    let mut limits = restrictive_limits();
    limits.max_layer_expanded_bytes = too_many.len() as u64;
    limits.max_total_expanded_bytes = too_many.len() as u64 * 2;
    let mut budget = ExtractionBudget::default();
    assert!(extract_layer_with_limits(
        &too_many,
        "application/vnd.oci.image.layer.v1.tar",
        &destination,
        &limits,
        &mut budget,
    )
    .unwrap_err()
    .to_string()
    .contains("entry quota"));

    let too_deep = layer(&[("a/b/c", tar::EntryType::Regular, None, b"")]);
    let mut limits = restrictive_limits();
    limits.max_layer_expanded_bytes = too_deep.len() as u64;
    limits.max_total_expanded_bytes = too_deep.len() as u64 * 2;
    let mut budget = ExtractionBudget::default();
    assert!(extract_layer_with_limits(
        &too_deep,
        "application/vnd.oci.image.layer.v1.tar",
        &destination,
        &limits,
        &mut budget,
    )
    .unwrap_err()
    .to_string()
    .contains("path depth quota"));
    let _ = std::fs::remove_dir_all(destination);
}

#[test]
fn test_layer_rejects_total_expanded_and_entry_quotas_across_layers() {
    let destination = test_cache("total-quotas");
    std::fs::create_dir_all(&destination).unwrap();
    let one = layer(&[("one", tar::EntryType::Regular, None, b"")]);
    let mut limits = restrictive_limits();
    limits.max_layer_expanded_bytes = one.len() as u64;
    limits.max_total_expanded_bytes = one.len() as u64;
    limits.max_layer_entries = 2;
    limits.max_total_entries = 1;
    let mut budget = ExtractionBudget::default();
    extract_layer_with_limits(
        &one,
        "application/vnd.oci.image.layer.v1.tar",
        &destination,
        &limits,
        &mut budget,
    )
    .unwrap();

    let error = extract_layer_with_limits(
        &one,
        "application/vnd.oci.image.layer.v1.tar",
        &destination,
        &limits,
        &mut budget,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("expanded byte quota")
            || error.to_string().contains("entry quota")
    );
    let _ = std::fs::remove_dir_all(destination);
}

#[tokio::test]
async fn test_compressed_writer_rejects_oversize_without_partial_chunk() {
    use tokio::io::AsyncWriteExt;

    let mut writer = QuotaWriter::new(tokio::io::sink(), 4);
    writer.write_all(b"four").await.unwrap();
    let error = writer.write_all(b"!").await.unwrap_err();
    assert!(error.to_string().contains("compressed byte quota"));
    assert_eq!(writer.written(), 4);
}

#[test]
fn test_layer_temp_file_is_private_nofollow_and_removed_on_drop() {
    use std::os::unix::fs::PermissionsExt;

    let root = test_cache("layer-temp");
    std::fs::create_dir_all(&root).unwrap();
    let extraction = root.join("image.tmp-test");
    std::fs::create_dir(&extraction).unwrap();
    let temp = LayerTemp::create(&extraction, 0).unwrap();
    let path = temp.path().to_path_buf();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(temp);
    assert!(!path.exists());
    let _ = std::fs::remove_dir_all(root);
}
