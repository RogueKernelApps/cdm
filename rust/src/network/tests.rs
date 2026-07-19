//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;

#[test]
fn invalid_network_combinations_are_rejected() {
    assert!(NetworkPolicy::from_cli(false, true, true, Some("example.com"), None, false).is_err());
    assert!(NetworkPolicy::from_cli(true, false, true, None, Some("example.com"), false).is_err());
    assert!(NetworkPolicy::from_cli(true, true, true, None, None, false).is_err());
    assert!(NetworkPolicy::from_cli(false, true, true, None, None, true).is_err());
    assert!(
        NetworkPolicy::from_cli(false, false, false, Some("example.com"), None, false).is_err()
    );
}

#[test]
fn direct_networking_is_default_and_scrambling_opts_into_the_proxy() {
    assert_eq!(
        NetworkPolicy::from_cli(false, false, false, None, None, false).unwrap(),
        NetworkPolicy::Direct
    );
    assert!(matches!(
        NetworkPolicy::from_cli(false, false, true, None, None, false).unwrap(),
        NetworkPolicy::Proxied(_)
    ));
}

#[test]
fn secret_destination_patterns_normalize_authorities_and_reject_lookalikes() {
    let github = DestinationPattern::parse("GitHub.COM.").unwrap();
    assert!(github.matches_authority("api.github.com:443").unwrap());
    assert!(github.matches_authority("github.com").unwrap());
    assert!(!github
        .matches_authority("github.com.attacker.example")
        .unwrap());
    assert!(!github.matches_authority("notgithub.com").unwrap());
    assert!(DestinationPattern::parse("https://github.com").is_err());
}

#[test]
fn domain_policy_normalizes_and_matches_subdomains() {
    let policy = DomainPolicy::parse(Some("Example.COM."), None, false).unwrap();
    assert!(!policy.is_blocked("api.example.com:443").unwrap());
    assert!(policy.is_blocked("notexample.com:443").unwrap());
}

#[test]
fn deny_precedes_allow_and_ips_are_exact() {
    let policy =
        DomainPolicy::parse(Some("example.com,127.0.0.1"), Some("api.example.com"), true).unwrap();
    assert!(policy.is_blocked("api.example.com:443").unwrap());
    assert!(!policy.is_blocked("127.0.0.1:80").unwrap());
    assert!(policy.is_blocked("127.0.0.2:80").unwrap());
}

#[test]
fn bracketed_ipv6_and_malformed_authorities_are_handled() {
    let policy = DomainPolicy::parse(Some("::1"), None, true).unwrap();
    assert!(!policy.is_blocked("[::1]:443").unwrap());
    assert!(policy.is_blocked("[::2]:443").unwrap());
    assert!(policy.is_blocked("[::1").is_err());
}

#[test]
fn malformed_domain_patterns_are_rejected() {
    for value in [
        "",
        "https://example.com",
        "example.com:443",
        "a..b",
        "münich.example",
    ] {
        assert!(
            DomainPolicy::parse(Some(value), None, false).is_err(),
            "{value}"
        );
    }
}

#[test]
fn private_and_non_routable_addresses_are_denied_by_default() {
    let policy = DomainPolicy::default();
    for authority in [
        "127.0.0.1:80",
        "10.0.0.1:443",
        "169.254.169.254:80",
        "0.0.0.0:80",
        "224.0.0.1:80",
        "[::1]:80",
        "[fe80::1]:80",
        "[fc00::1]:80",
        "[ff02::1]:80",
    ] {
        assert!(policy.is_blocked(authority).unwrap(), "{authority}");
    }
    assert!(!policy.is_blocked("93.184.216.34:443").unwrap());
    assert!(policy.allows_resolved_ip("example.com", "93.184.216.34".parse().unwrap()));
    assert!(!policy.allows_resolved_ip("example.com", "127.0.0.1".parse().unwrap()));
}

#[test]
fn private_network_requires_both_opt_in_and_an_explicit_destination() {
    let opt_in_without_allowlist = DomainPolicy::parse(None, None, true).unwrap();
    assert!(opt_in_without_allowlist.is_blocked("127.0.0.1:80").unwrap());
    assert!(!opt_in_without_allowlist.allows_resolved_ip("localhost", "127.0.0.1".parse().unwrap()));

    let allowed = DomainPolicy::parse(Some("dev.internal"), None, true).unwrap();
    assert!(allowed.allows_resolved_ip("api.dev.internal", "10.0.0.8".parse().unwrap()));
    assert!(!allowed.allows_resolved_ip("attacker.example", "10.0.0.8".parse().unwrap()));
}
