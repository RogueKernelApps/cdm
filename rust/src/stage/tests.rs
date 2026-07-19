//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;

#[test]
fn test_file_stage_creation() {
    let mapping = SecretMapping::new();
    let stage = FileStage::new(mapping).unwrap();
    assert!(stage.temp_dir().exists());
}

#[test]
fn staging_is_contained_by_the_trusted_invocation_runtime() {
    use std::os::unix::fs::PermissionsExt;

    let runtime = crate::sandbox::prepare_runtime_dir().unwrap();
    let defaults = crate::config::SecretsConfig::default();
    let mut stage = FileStage::new_with_config(
        &runtime,
        SecretMapping::new(),
        defaults.name_patterns,
        defaults.min_length,
        defaults.min_char_classes,
    )
    .unwrap();
    assert!(stage.temp_dir().starts_with(&runtime));

    let source = runtime.join("source.env");
    fs::write(&source, "ORDINARY=value\n").unwrap();
    stage.stage_file(&source).unwrap();
    let staged = &stage.staged_files()[0].staged_path;
    assert!(staged.starts_with(&runtime));
    assert_eq!(
        fs::metadata(staged).unwrap().permissions().mode() & 0o777,
        0o600
    );

    drop(stage);
    fs::remove_file(source).unwrap();
    fs::remove_dir(runtime).unwrap();
}

#[test]
fn staging_rejects_an_untrusted_runtime_directory() {
    use std::os::unix::fs::PermissionsExt;

    let runtime = crate::sandbox::prepare_runtime_dir().unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o777)).unwrap();
    let defaults = crate::config::SecretsConfig::default();
    let error = match FileStage::new_with_config(
        &runtime,
        SecretMapping::new(),
        defaults.name_patterns,
        defaults.min_length,
        defaults.min_char_classes,
    ) {
        Ok(_) => panic!("unsafe runtime permissions unexpectedly accepted"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir(runtime).unwrap();
}

#[test]
fn test_stage_file_obfuscation() {
    let mut mapping = SecretMapping::new();
    mapping.add("sk-ant-REAL1234567890abc".to_string()).unwrap();

    let stage = FileStage::new(mapping).unwrap();
    let test_file = stage.temp_dir().join("test.env");
    {
        let mut f = fs::File::create(&test_file).unwrap();
        writeln!(f, "API_KEY=sk-ant-REAL1234567890abc").unwrap();
    }
    assert!(test_file.exists());
}

#[test]
fn test_stage_file_keeps_non_secret_env_values_readable() {
    let temp_root = std::env::temp_dir().join(format!("cdm-stage-test-{}", std::process::id()));
    fs::create_dir_all(&temp_root).unwrap();
    let env_path = temp_root.join(".env");

    {
        let mut f = fs::File::create(&env_path).unwrap();
        writeln!(f, "ANTHROPIC_MODEL=eu.anthropic.claude-opus-4-6-v1").unwrap();
        writeln!(
            f,
            "MODEL_URL=https://api.anthropic.com/v1/models/claude-sonnet-4-6"
        )
        .unwrap();
        writeln!(f, "API_KEY=sk-ant-REAL1234567890abc").unwrap();
    }

    let mut mapping = SecretMapping::new();
    mapping.add("sk-ant-REAL1234567890abc".to_string()).unwrap();

    let mut stage = FileStage::new(mapping).unwrap();
    stage.stage_file(&env_path).unwrap();

    let staged = fs::read_to_string(&stage.staged_files()[0].staged_path).unwrap();
    assert!(staged.contains("ANTHROPIC_MODEL=eu.anthropic.claude-opus-4-6-v1"));
    assert!(staged.contains("MODEL_URL=https://api.anthropic.com/v1/models/claude-sonnet-4-6"));
    assert!(!staged.contains("API_KEY=sk-ant-REAL1234567890abc"));

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn conservative_value_detection_obfuscates_credential_urls_in_env_files() {
    let secret = "postgres://admin:SuperSecretPass123@db.example.com:5432/app";
    let mut mapping = SecretMapping::new();
    mapping.add(secret.to_string()).unwrap();
    let defaults = crate::config::SecretsConfig::default();

    let obfuscated = obfuscate_content_for_path(
        Path::new(".env"),
        &format!("DATABASE_URL={secret}\n"),
        &mapping,
        &defaults.name_patterns,
        defaults.min_length,
        defaults.min_char_classes,
    )
    .unwrap();
    assert!(!obfuscated.contains(secret));
    assert!(obfuscated.starts_with("DATABASE_URL="));
}

#[test]
fn structured_config_containers_are_not_mistaken_for_secret_values() {
    let defaults = crate::config::SecretsConfig::default();
    let content = "{\n  \"auths\": {\n  }\n}\n";
    let obfuscated = obfuscate_content_for_path(
        Path::new("config.json"),
        content,
        &SecretMapping::new(),
        &defaults.name_patterns,
        defaults.min_length,
        defaults.min_char_classes,
    )
    .unwrap();
    assert_eq!(obfuscated, content);
}

#[test]
fn minified_json_is_obfuscated_by_value_not_as_one_key_value_line() {
    let defaults = crate::config::SecretsConfig::default();
    let content = r#"{"auths":{},"credsStore":"desktop","currentContext":"desktop-linux","features":{"hooks":"true"}}"#;
    let obfuscated = obfuscate_content_for_path(
        Path::new("config.json"),
        content,
        &SecretMapping::new(),
        &defaults.name_patterns,
        defaults.min_length,
        defaults.min_char_classes,
    )
    .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&obfuscated).unwrap(),
        serde_json::from_str::<serde_json::Value>(content).unwrap()
    );
}

#[test]
fn known_secrets_are_removed_from_comments_sections_and_structured_formats() {
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    let mut mapping = SecretMapping::new();
    mapping.add(secret.to_string()).unwrap();
    let defaults = crate::config::SecretsConfig::default();
    for (path, content) in [
        (
            "config.ini",
            format!("# token={secret}\n[section {secret}]\nvalue=ordinary\n"),
        ),
        (
            "config.json",
            format!("{{\"auths\":{{\"registry\":{{\"auth\":\"{secret}\"}}}}}}"),
        ),
        (
            "config.yaml",
            format!("users:\n  - token: {secret}\n# backup: {secret}\n"),
        ),
    ] {
        let staged = obfuscate_content_for_path(
            Path::new(path),
            &content,
            &mapping,
            &defaults.name_patterns,
            defaults.min_length,
            defaults.min_char_classes,
        )
        .unwrap();
        assert!(!staged.contains(secret), "real value remained in {path}");
    }
}

#[test]
fn longest_known_secret_is_replaced_before_overlapping_values() {
    let short = "TokenOverlap1234";
    let long = "TokenOverlap1234Extended5678";
    let mut mapping = SecretMapping::new();
    mapping.add(short.to_string()).unwrap();
    mapping.add(long.to_string()).unwrap();
    let defaults = crate::config::SecretsConfig::default();
    let staged = obfuscate_content_for_path(
        Path::new("config.ini"),
        &format!("TOKEN={long}\n# old={short}\n"),
        &mapping,
        &defaults.name_patterns,
        defaults.min_length,
        defaults.min_char_classes,
    )
    .unwrap();
    assert!(!staged.contains(short));
    assert!(!staged.contains(long));
}

#[test]
fn final_staged_byte_scan_fails_closed_if_a_replacement_retains_the_real_value() {
    let real = "KnownRealSecret123";
    let mut mapping = SecretMapping::new();
    mapping
        .real_to_fake
        .insert(real.into(), format!("fake-{real}"));
    let defaults = crate::config::SecretsConfig::default();
    let error = obfuscate_content_for_path(
        Path::new("config.ini"),
        &format!("TOKEN={real}\n"),
        &mapping,
        &defaults.name_patterns,
        defaults.min_length,
        defaults.min_char_classes,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!error.to_string().contains(real));
}

#[test]
fn test_obfuscate_content_preserves_trailing_newline() {
    let path = Path::new(".env");
    let mut mapping = SecretMapping::new();
    mapping.add("sk-ant-REAL1234567890abc".to_string()).unwrap();
    let defaults = crate::config::SecretsConfig::default();

    let content = "API_KEY=sk-ant-REAL1234567890abc\n";
    let obfuscated = obfuscate_content_for_path(
        path,
        content,
        &mapping,
        &defaults.name_patterns,
        defaults.min_length,
        defaults.min_char_classes,
    )
    .unwrap();

    assert!(obfuscated.ends_with('\n'));
    assert_eq!(obfuscated.len(), content.len());
}

#[test]
fn test_env_bearer_key_is_treated_as_secret() {
    let path = Path::new(".env");
    let mut mapping = SecretMapping::new();
    mapping
        .add("Bearer super-secret-token-value".to_string())
        .unwrap();
    let defaults = crate::config::SecretsConfig::default();

    let content = "AUTH_BEARER=Bearer super-secret-token-value\n";
    let obfuscated = obfuscate_content_for_path(
        path,
        content,
        &mapping,
        &defaults.name_patterns,
        defaults.min_length,
        defaults.min_char_classes,
    )
    .unwrap();

    assert!(!obfuscated.contains("Bearer super-secret-token-value"));
    assert!(obfuscated.starts_with("AUTH_BEARER="));
}

#[test]
fn test_parse_env_file_entries_returns_all_values() {
    let dir = std::env::temp_dir().join(format!("cdm-parse-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(".env");

    {
        let mut f = fs::File::create(&path).unwrap();
        writeln!(f, "# comment").unwrap();
        writeln!(f, "NODE_ENV=development").unwrap();
        writeln!(f, "API_KEY=sk-secret-12345678").unwrap();
        writeln!(f, "MODEL=claude-sonnet-4-6").unwrap();
        writeln!(f, "QUOTED=\"hello world\"").unwrap();
        writeln!(f, "export EXPORTED=yes").unwrap();
        writeln!(f).unwrap();
    }

    let entries = parse_env_file_entries(&path).unwrap();
    assert_eq!(entries.len(), 5);
    assert_eq!(entries[0], ("NODE_ENV".into(), "development".into()));
    assert_eq!(entries[1], ("API_KEY".into(), "sk-secret-12345678".into()));
    assert_eq!(entries[2], ("MODEL".into(), "claude-sonnet-4-6".into()));
    assert_eq!(entries[3], ("QUOTED".into(), "hello world".into()));
    assert_eq!(entries[4], ("EXPORTED".into(), "yes".into()));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn malformed_env_files_fail_without_echoing_content() {
    let stage = FileStage::new(SecretMapping::new()).unwrap();
    let path = stage.temp_dir().join(".env");
    let secret = "this-secret-must-not-appear";
    fs::write(&path, format!("BROKEN {secret}\n")).unwrap();

    let error = parse_env_file_entries(&path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("line 1"));
    assert!(!error.to_string().contains(secret));
}

#[test]
fn staging_requires_a_registered_replacement() {
    let defaults = crate::config::SecretsConfig::default();
    let secret = "missing-mapping-secret";
    let error = obfuscate_content_for_path(
        Path::new(".env"),
        &format!("API_KEY={secret}\n"),
        &SecretMapping::new(),
        &defaults.name_patterns,
        defaults.min_length,
        defaults.min_char_classes,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!error.to_string().contains(secret));
}

#[test]
fn staging_errors_identify_the_candidate_path_without_disclosing_content() {
    let mut stage = FileStage::new(SecretMapping::new()).unwrap();
    let path = stage.temp_dir().join("candidate.conf");
    let secret = "MissingMappedSecret123";
    fs::write(&path, format!("API_KEY={secret}\n")).unwrap();

    let error = stage.stage_file(&path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains(&path.display().to_string()));
    assert!(!error.to_string().contains(secret));
}

#[test]
fn staging_rejects_parent_traversal_in_destination_paths() {
    let mut stage = FileStage::new(SecretMapping::new()).unwrap();
    let source_dir = stage.temp_dir().join("source");
    fs::create_dir(&source_dir).unwrap();
    let source = stage.temp_dir().join("plain");
    fs::write(&source, "ordinary content\n").unwrap();
    let traversing = source_dir.join("..").join("plain");

    let error = stage.stage_file(&traversing).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(stage.staged_files().is_empty());
}

#[test]
fn missing_optional_candidates_are_ignored() {
    let stage = FileStage::new(SecretMapping::new()).unwrap();
    let work = stage.temp_dir().join("work");
    let home = stage.temp_dir().join("home");
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&home).unwrap();

    let files = find_sensitive_files_with_config(
        &work.to_string_lossy(),
        &home.to_string_lossy(),
        &[".env".into()],
        &std::collections::HashMap::from([(
            ".aws/credentials".into(),
            "AWS_SHARED_CREDENTIALS_FILE".into(),
        )]),
        &|_| true,
    )
    .unwrap();
    assert!(files.is_empty());
}

#[cfg(unix)]
#[test]
fn symlinked_sensitive_candidates_are_rejected_without_reading_targets() {
    use std::os::unix::fs::symlink;

    let stage = FileStage::new(SecretMapping::new()).unwrap();
    let work = stage.temp_dir().join("work");
    let home = stage.temp_dir().join("home");
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&home).unwrap();
    let secret = "target-secret-must-not-appear";
    let target = stage.temp_dir().join("external");
    fs::write(&target, format!("API_KEY={secret}\n")).unwrap();
    symlink(&target, work.join(".env")).unwrap();

    let error = find_sensitive_files_with_config(
        &work.to_string_lossy(),
        &home.to_string_lossy(),
        &[".env".into()],
        &std::collections::HashMap::new(),
        &|_| true,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!error.to_string().contains(secret));
}

#[test]
fn test_classify_sensitive_file() {
    let work = "/home/user/project";
    let home = "/home/user";

    assert!(matches!(
        classify_sensitive_file("/home/user/project/.env", work, home),
        SensitiveFileKind::EnvFile
    ));
    assert!(matches!(
        classify_sensitive_file("/home/user/.aws/credentials", work, home),
        SensitiveFileKind::HomeConfig
    ));
    assert!(matches!(
        classify_sensitive_file("/home/user/.ssh/id_rsa", work, home),
        SensitiveFileKind::SshKey
    ));
    assert!(matches!(
        classify_sensitive_file("/home/user/.docker/config.json", work, home),
        SensitiveFileKind::HomeConfig
    ));
}

#[test]
fn test_redirect_env_for_staged_file_with_config() {
    let home = "/home/user";
    let configs = crate::config::PathsConfig::default().staged_configs;

    let redirects = redirect_env_for_staged_file_with_config(
        Path::new("/home/user/.aws/credentials"),
        Path::new("/tmp/cdm-stage/home/user/.aws/credentials"),
        home,
        &configs,
    );
    assert_eq!(redirects.len(), 1);
    assert_eq!(redirects[0].0, "AWS_SHARED_CREDENTIALS_FILE");

    let redirects = redirect_env_for_staged_file_with_config(
        Path::new("/home/user/.docker/config.json"),
        Path::new("/tmp/cdm-stage/home/user/.docker/config.json"),
        home,
        &configs,
    );
    assert_eq!(redirects.len(), 1);
    assert_eq!(redirects[0].0, "DOCKER_CONFIG");
    assert_eq!(redirects[0].1, "/tmp/cdm-stage/home/user/.docker");

    // SSH keys have no redirect
    let redirects = redirect_env_for_staged_file_with_config(
        Path::new("/home/user/.ssh/id_rsa"),
        Path::new("/tmp/cdm-stage/home/user/.ssh/id_rsa"),
        home,
        &configs,
    );
    assert!(redirects.is_empty());
}
