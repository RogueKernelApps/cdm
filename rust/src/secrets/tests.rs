//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;

fn test_dir(label: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "cdm-secrets-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn test_secret_mapping_add() {
    let mut mapping = SecretMapping::new();
    let fake = mapping.add("my_secret_key_123".to_string()).unwrap();
    assert_eq!(fake.len(), "my_secret_key_123".len());
    assert_ne!(fake, "my_secret_key_123");
}

#[test]
fn test_secret_mapping_idempotent() {
    let mut mapping = SecretMapping::new();
    let fake1 = mapping.add("secret".to_string()).unwrap();
    let fake2 = mapping.add("secret".to_string()).unwrap();
    assert_eq!(fake1, fake2);
}

#[test]
fn test_obfuscate_and_deobfuscate() {
    let mut mapping = SecretMapping::new();
    let fake = mapping.add("real_secret".to_string()).unwrap();

    let obfuscated = mapping.obfuscate("my api key is real_secret");
    assert!(obfuscated.contains(&fake));
    assert!(!obfuscated.contains("real_secret"));

    let restored = mapping.deobfuscate(&obfuscated);
    assert!(restored.contains("real_secret"));
}

#[test]
fn restoration_is_destination_scoped_and_unknown_secrets_never_restore() {
    let mut mapping = SecretMapping::new();
    let github_fake = mapping
        .add_with_destinations("github-real-secret".into(), &["github.com"])
        .unwrap();
    let unknown_fake = mapping.add("unknown-real-secret".into()).unwrap();
    let payload = format!("{github_fake}:{unknown_fake}");

    let attacker = mapping
        .deobfuscate_for_authority(&payload, "attacker.example")
        .unwrap();
    assert_eq!(attacker, payload);
    let github = mapping
        .deobfuscate_for_authority(&payload, "api.github.com:443")
        .unwrap();
    assert!(github.contains("github-real-secret"));
    assert!(github.contains(&unknown_fake));
    assert!(!github.contains("unknown-real-secret"));
}

#[test]
fn provider_and_explicit_destination_rules_are_narrow_and_validated() {
    let mut config = CdmConfig::default();
    config.secrets.restore_destinations.insert(
        "INTERNAL_API_TOKEN".into(),
        vec!["api.internal.example".into()],
    );
    let rules = DestinationRules::from_config(&config).unwrap();
    let explicit = rules.destinations(Some("INTERNAL_API_TOKEN"), "GenericTokenValue1234", None);
    assert!(explicit
        .iter()
        .any(|rule| rule.matches_authority("api.internal.example").unwrap()));
    assert!(!explicit
        .iter()
        .any(|rule| rule.matches_authority("attacker.example").unwrap()));
    let github = rules.destinations(
        Some("GITHUB_TOKEN"),
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        None,
    );
    assert!(github
        .iter()
        .any(|rule| rule.matches_authority("api.github.com").unwrap()));
    assert!(!github
        .iter()
        .any(|rule| rule.matches_authority("api.openai.com").unwrap()));

    config
        .secrets
        .restore_destinations
        .insert("BAD".into(), vec!["https://attacker.example/path".into()]);
    assert!(DestinationRules::from_config(&config).is_err());

    let mut duplicate = CdmConfig::default();
    duplicate
        .secrets
        .restore_destinations
        .insert("TOKEN".into(), vec!["api.first.example".into()]);
    duplicate
        .secrets
        .restore_destinations
        .insert("--token".into(), vec!["api.second.example".into()]);
    assert!(DestinationRules::from_config(&duplicate).is_err());
}

#[test]
fn provider_token_scopes_require_complete_recognized_syntax() {
    let rules = DestinationRules::from_config(&CdmConfig::default()).unwrap();
    assert!(rules
        .destinations(None, "gh-not-a-complete-token", None)
        .is_empty());
    let stripe = rules.destinations(None, "sk_live_abcdefghijklmnop", None);
    assert!(stripe
        .iter()
        .any(|rule| rule.matches_authority("api.stripe.com").unwrap()));
    assert!(!stripe
        .iter()
        .any(|rule| rule.matches_authority("api.openai.com").unwrap()));
}

#[test]
fn repeated_discovery_of_the_same_value_unions_destination_scopes() {
    let mut mapping = SecretMapping::new();
    let fake = mapping
        .add_with_destinations("same-real-value".into(), &["api.first.example"])
        .unwrap();
    assert_eq!(
        mapping
            .add_with_destinations("same-real-value".into(), &["api.second.example"])
            .unwrap(),
        fake
    );
    assert_eq!(
        mapping
            .deobfuscate_for_authority(&fake, "api.first.example")
            .unwrap(),
        "same-real-value"
    );
    assert_eq!(
        mapping
            .deobfuscate_for_authority(&fake, "api.second.example")
            .unwrap(),
        "same-real-value"
    );
    assert_eq!(
        mapping
            .deobfuscate_for_authority(&fake, "attacker.example")
            .unwrap(),
        fake
    );
}

#[test]
fn argv_obfuscation_preserves_boundaries_and_registers_recognized_tokens() {
    let token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    let argv = vec![
        OsString::from("curl"),
        OsString::from(format!("--token={token}")),
        OsString::from("argument with spaces"),
    ];
    let mut mapping = SecretMapping::new();
    let obfuscated = mapping
        .obfuscate_argv(&argv, &CdmConfig::default())
        .unwrap();
    assert_eq!(obfuscated.len(), argv.len());
    assert_eq!(obfuscated[0], OsString::from("curl"));
    assert_eq!(obfuscated[2], OsString::from("argument with spaces"));
    let obfuscated_token = obfuscated[1].to_string_lossy();
    assert!(!obfuscated_token.contains(token));
    let restored = mapping
        .deobfuscate_for_authority(&obfuscated_token, "api.github.com")
        .unwrap();
    assert_eq!(restored, argv[1].to_string_lossy());
    assert_eq!(
        mapping
            .deobfuscate_for_authority(&obfuscated_token, "attacker.example")
            .unwrap(),
        obfuscated_token
    );
}

#[test]
fn test_is_secret_name() {
    let patterns = crate::config::SecretsConfig::default().name_patterns;
    assert!(is_secret_name_with_patterns("API_KEY", &patterns));
    assert!(is_secret_name_with_patterns("password", &patterns));
    assert!(is_secret_name_with_patterns("auth_token", &patterns));
    assert!(is_secret_name_with_patterns("bearer_token", &patterns));
    assert!(!is_secret_name_with_patterns("username", &patterns));
}

#[test]
fn test_looks_like_secret() {
    let defaults = crate::config::SecretsConfig::default();
    assert!(looks_like_secret_with_config(
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        defaults.min_length,
        defaults.min_char_classes
    ));
    assert!(!looks_like_secret_with_config(
        "abc",
        defaults.min_length,
        defaults.min_char_classes
    ));
    assert!(!looks_like_secret_with_config(
        "AAAAAAAAAAAAAAA",
        defaults.min_length,
        defaults.min_char_classes
    ));
}

#[test]
fn supported_token_formats_are_recognized_conservatively() {
    let defaults = crate::config::SecretsConfig::default();
    let positive = [
        "AKIA1234567890ABCDEF",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "github_pat_abcdefghijklmnopqrstuvwxyz0123456789",
        "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789",
        "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789",
        "npm_abcdefghijklmnopqrstuvwxyz0123456789",
        "glpat-abcdefghijklmnopqrst1234",
        "AIzaabcdefghijklmnopqrstuvwxyz012345678",
        "sk_live_abcdefghijklmnopqrst1234",
        "xoxb-1234567890-abcdefghijklmnop",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature0123456789",
        "postgres://admin:SuperSecretPass123@db.example.com:5432/app",
    ];
    for value in positive {
        assert!(
            looks_like_secret_with_config(value, defaults.min_length, defaults.min_char_classes),
            "expected recognized token format"
        );
    }

    let negative = [
        "MySecret1234567890",
        "550e8400-e29b-41d4-a716-446655440000",
        "eu.anthropic.claude-opus-4-6-v1",
        "0123456789abcdef0123456789abcdef01234567",
        "this-is-a-long-config-setting-123",
        "postgres://db.example.com:5432/app",
        "ghp_too-short-123",
        "AKIA1234567890ABCDE!",
    ];
    for value in negative {
        assert!(
            !looks_like_secret_with_config(value, defaults.min_length, defaults.min_char_classes),
            "expected ordinary value not to be classified"
        );
    }
}

struct FailingRandom;

impl RandomSource for FailingRandom {
    fn fill(&mut self, _bytes: &mut [u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected random failure",
        ))
    }
}

struct ConstantRandom(u8);

impl RandomSource for ConstantRandom {
    fn fill(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        bytes.fill(self.0);
        Ok(())
    }
}

struct IncrementingRandom(u8);

impl RandomSource for IncrementingRandom {
    fn fill(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        bytes.fill(self.0);
        self.0 = self.0.saturating_add(1);
        Ok(())
    }
}

#[test]
fn random_failures_are_returned_without_secret_values() {
    let secret = "do-not-print-this-secret";
    let error = generate_fake_with_random(secret, &mut FailingRandom).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(!error.to_string().contains(secret));
}

#[test]
fn unchanged_random_output_is_bounded_and_secret_safe() {
    let secret = "AAAA";
    let mut mapping = SecretMapping::new();
    let error = mapping
        .add_with_random(secret.to_string(), &mut ConstantRandom(0))
        .unwrap_err();
    assert!(!error.to_string().contains(secret));
    assert!(mapping.real_to_fake.is_empty());
}

#[test]
fn collision_retries_are_bounded_and_avoid_existing_reals() {
    let mut mapping = SecretMapping::new();
    mapping
        .add_with_random("BBBB".to_string(), &mut ConstantRandom(0))
        .unwrap();
    let fake = mapping
        .add_with_random("CCCC".to_string(), &mut IncrementingRandom(0))
        .unwrap();
    assert_eq!(fake, "DDDD");
    assert_ne!(fake, "CCCC");
    assert_ne!(fake, "AAAA");
}

#[test]
fn a_registered_fake_cannot_later_become_a_real_secret() {
    let mut mapping = SecretMapping::new();
    let first_fake = mapping
        .add_with_random("BBBB".to_string(), &mut ConstantRandom(0))
        .unwrap();

    let error = mapping
        .add_with_random(first_fake.clone(), &mut IncrementingRandom(2))
        .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!error.to_string().contains(&first_fake));
    assert_eq!(mapping.real_to_fake.len(), 1);
    assert_eq!(mapping.fake_to_real.len(), 1);
}

#[test]
fn replacements_never_rescan_generated_output() {
    let mut mapping = SecretMapping::new();
    mapping.real_to_fake.insert("A".into(), "B".into());
    mapping.real_to_fake.insert("BB".into(), "AA".into());
    mapping.fake_to_real.insert("B".into(), "A".into());
    mapping.fake_to_real.insert("AA".into(), "BB".into());

    assert_eq!(mapping.obfuscate("BB"), "AA");
    assert_eq!(mapping.deobfuscate("AA"), "BB");
}

#[test]
fn short_environment_secrets_are_replaced_only_in_their_originating_field() {
    let mut mapping = SecretMapping::new();
    let fake = mapping
        .add_environment_scoped("PIN".into(), "a".into(), Vec::new())
        .unwrap();

    assert_eq!(mapping.obfuscate_environment_value("PIN", "a"), fake);
    assert_eq!(mapping.obfuscate("cat"), "cat");
    assert_ne!(
        String::from_utf8(mapping.scrub_response_bytes(b"a")).unwrap(),
        "a"
    );
}

#[test]
fn values_without_replaceable_characters_fail_without_leaking() {
    let secret = "-----";
    let error = generate_fake_with_random(secret, &mut ConstantRandom(7)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(!error.to_string().contains(secret));
}

#[cfg(unix)]
#[test]
fn direct_file_detection_rejects_symlinks_without_reading_targets() {
    use std::os::unix::fs::symlink;

    let dir = test_dir("symlink");
    let target = dir.join("target");
    let link = dir.join("candidate");
    let secret = "secret-must-not-be-in-error";
    fs::write(&target, format!("API_KEY={secret}\n")).unwrap();
    symlink(&target, &link).unwrap();
    let defaults = crate::config::SecretsConfig::default();

    let error = detect_in_file(
        &link,
        &defaults.name_patterns,
        defaults.min_length,
        defaults.min_char_classes,
    )
    .unwrap_err();
    assert!(!error.to_string().contains(secret));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn invalid_utf8_is_propagated_without_file_content() {
    let dir = test_dir("utf8");
    let path = dir.join("candidate");
    fs::write(
        &path,
        [b'A', b'P', b'I', b'_', b'K', b'E', b'Y', b'=', 0xff],
    )
    .unwrap();
    let defaults = crate::config::SecretsConfig::default();

    let error = detect_in_file(
        &path,
        &defaults.name_patterns,
        defaults.min_length,
        defaults.min_char_classes,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!error.to_string().contains("API_KEY"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn minified_json_secret_values_are_detected_by_key() {
    let dir = test_dir("json");
    let path = dir.join("config.json");
    let token = "docker-auth-value-1234567890";
    fs::write(
        &path,
        format!("{{\"auths\":{{\"registry.example\":{{\"auth\":\"{token}\"}}}}}}"),
    )
    .unwrap();
    let defaults = CdmConfig::default();
    let found = detect_in_file(
        &path,
        &defaults.secrets.name_patterns,
        defaults.secrets.min_length,
        defaults.secrets.min_char_classes,
    )
    .unwrap();
    assert!(found.values().any(|value| value == token));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn host_scan_ignores_absent_optional_candidates() {
    let dir = test_dir("missing-scan");
    let home = dir.join("home");
    let work = dir.join("work");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&work).unwrap();
    let mut config = CdmConfig::default();
    config.secrets.name_patterns.clear();
    config.paths.staged_configs.clear();
    config.secrets.env_files = vec![".env".into()];

    let mapping = scan_host(&home, &work, &config, &|_| true).unwrap();
    assert!(mapping.real_to_fake.is_empty());
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn host_scan_ignores_ssh_sockets_while_scanning_private_keys() {
    use std::os::unix::net::UnixListener;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::path::PathBuf::from("/tmp")
        .join(format!("cdm-ssh-socket-{}-{nonce}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let home = dir.join("home");
    let work = dir.join("work");
    let ssh = home.join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    fs::create_dir(&work).unwrap();
    let key =
        "-----BEGIN PRIVATE KEY-----\nsynthetic-private-key-material\n-----END PRIVATE KEY-----\n";
    fs::write(ssh.join("id_test"), key).unwrap();
    let listener = UnixListener::bind(ssh.join("agent.sock")).unwrap();

    let mapping = scan_host(&home, &work, &CdmConfig::default(), &|_| true).unwrap();
    assert_ne!(mapping.obfuscate(key), key);

    drop(listener);
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn host_scan_rejects_secret_files_beneath_symlinked_ancestors() {
    use std::os::unix::fs::symlink;

    let dir = test_dir("ancestor-symlink-scan");
    let home = dir.join("home");
    let work = dir.join("work");
    let outside = dir.join("outside");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&work).unwrap();
    fs::create_dir(&outside).unwrap();
    let secret = "outside-secret-must-not-appear";
    fs::write(outside.join("candidate.env"), format!("API_KEY={secret}\n")).unwrap();
    symlink(&outside, work.join("linked")).unwrap();

    let mut config = CdmConfig::default();
    config.paths.staged_configs.clear();
    config.secrets.env_files = vec!["linked/candidate.env".into()];

    let error = match scan_host(&home, &work, &config, &|_| true) {
        Ok(_) => panic!("ancestor symlink was followed"),
        Err(error) => error,
    };
    assert!(matches!(
        error.kind(),
        io::ErrorKind::NotADirectory | io::ErrorKind::InvalidData
    ));
    assert!(!error.to_string().contains(secret));
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn host_scan_pins_a_legitimate_symlinked_category_root() {
    use std::os::unix::fs::symlink;

    let dir = test_dir("symlinked-category-root");
    let real_home = dir.join("real-home");
    let home = dir.join("home");
    let work = dir.join("work");
    fs::create_dir(&real_home).unwrap();
    fs::create_dir(&work).unwrap();
    symlink(&real_home, &home).unwrap();
    let mut config = CdmConfig::default();
    config.secrets.name_patterns.clear();
    config.paths.staged_configs.clear();
    config.secrets.env_files.clear();

    let mapping = scan_host(&home, &work, &config, &|_| true).unwrap();

    assert!(mapping.real_to_fake.is_empty());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn configured_secret_candidates_cannot_escape_their_base() {
    let dir = test_dir("candidate-traversal");
    let home = dir.join("home");
    let work = dir.join("work");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&work).unwrap();
    let mut config = CdmConfig::default();
    config.secrets.name_patterns.clear();
    config.paths.staged_configs.clear();
    config.secrets.env_files = vec!["../outside".into()];

    let error = match scan_host(&home, &work, &config, &|_| true) {
        Ok(_) => panic!("expected traversal rejection"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn host_scan_propagates_existing_symlink_candidate_errors_without_leaks() {
    use std::os::unix::fs::symlink;

    let dir = test_dir("scan-symlink");
    let home = dir.join("home");
    let work = dir.join("work");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&work).unwrap();
    let secret = "scan-target-secret-must-not-appear";
    let target = dir.join("target");
    fs::write(&target, format!("API_KEY={secret}\n")).unwrap();
    symlink(&target, work.join(".env")).unwrap();
    let mut config = CdmConfig::default();
    config.secrets.name_patterns.clear();
    config.paths.staged_configs.clear();
    config.secrets.env_files = vec![".env".into()];

    let error = match scan_host(&home, &work, &config, &|_| true) {
        Ok(_) => panic!("expected symlink candidate rejection"),
        Err(error) => error,
    };
    assert!(!error.to_string().contains(secret));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_looks_like_secret_skips_paths() {
    let defaults = crate::config::SecretsConfig::default();
    // macOS TMPDIR-style paths must not be detected as secrets
    assert!(!looks_like_secret_with_config(
        "/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T",
        defaults.min_length,
        defaults.min_char_classes
    ));
    assert!(!looks_like_secret_with_config(
        "/usr/local/bin/something123",
        defaults.min_length,
        defaults.min_char_classes
    ));
    assert!(!looks_like_secret_with_config(
        "./relative/path/with/Mixed123Case",
        defaults.min_length,
        defaults.min_char_classes
    ));
    assert!(!looks_like_secret_with_config(
        "~/config/SomeLongPath123456",
        defaults.min_length,
        defaults.min_char_classes
    ));
    assert!(!looks_like_secret_with_config(
        "https://api.example.com/v2/something",
        defaults.min_length,
        defaults.min_char_classes
    ));
}

#[test]
fn argv_obfuscation_preserves_opaque_bytes_and_boundaries() {
    let secret = "sk-known-Secret1234567890";
    let mut mapping = SecretMapping::new();
    let fake = mapping.add(secret.to_string()).unwrap();
    let mut bytes = vec![0xff, b'\n', b'*', b'?', b'[', b']'];
    bytes.extend_from_slice(b"--token=");
    bytes.extend_from_slice(secret.as_bytes());
    let argv = vec![
        OsString::from("program"),
        OsString::from_vec(bytes.clone()),
        OsString::new(),
    ];

    let rewritten = mapping
        .obfuscate_argv(&argv, &CdmConfig::default())
        .unwrap();
    assert_eq!(rewritten.len(), argv.len());
    assert_eq!(rewritten[2].as_bytes(), b"");
    assert_eq!(&rewritten[1].as_bytes()[..6], &bytes[..6]);
    assert!(!rewritten[1]
        .as_bytes()
        .windows(secret.len())
        .any(|window| window == secret.as_bytes()));
    assert!(rewritten[1]
        .as_bytes()
        .windows(fake.len())
        .any(|window| window == fake.as_bytes()));
}
