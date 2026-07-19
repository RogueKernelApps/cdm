//! Validated network and domain policy.

use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicy {
    Disabled,
    Direct,
    Proxied(DomainPolicy),
}

impl NetworkPolicy {
    pub fn from_cli(
        no_network: bool,
        no_proxy: bool,
        proxy_enabled: bool,
        allow_domains: Option<&str>,
        deny_domains: Option<&str>,
        allow_private_network: bool,
    ) -> Result<Self, String> {
        if no_network && no_proxy {
            return Err(
                "--no-network already disables the proxy; do not combine it with --no-proxy".into(),
            );
        }
        if (no_network || no_proxy)
            && (allow_domains.is_some() || deny_domains.is_some() || allow_private_network)
        {
            return Err("domain rules require proxied networking and cannot be combined with --no-network or --no-proxy".into());
        }
        if !proxy_enabled
            && (allow_domains.is_some() || deny_domains.is_some() || allow_private_network)
        {
            return Err("domain rules require proxied networking; add --scramble or --sec".into());
        }
        if no_network {
            return Ok(Self::Disabled);
        }
        if no_proxy || !proxy_enabled {
            return Ok(Self::Direct);
        }
        Ok(Self::Proxied(DomainPolicy::parse(
            allow_domains,
            deny_domains,
            allow_private_network,
        )?))
    }

    #[cfg_attr(not(feature = "vm"), allow(dead_code))]
    pub fn allows_network(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub fn is_proxied(&self) -> bool {
        matches!(self, Self::Proxied(_))
    }

    pub fn domains(&self) -> Option<&DomainPolicy> {
        match self {
            Self::Proxied(policy) => Some(policy),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainPolicy {
    allowed: Vec<DomainPattern>,
    denied: Vec<DomainPattern>,
    allow_private_network: bool,
}

/// A validated destination suffix used to scope restoration of one secret.
/// A DNS name matches itself and its subdomains; an IP address matches exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationPattern(DomainPattern);

impl DestinationPattern {
    pub fn parse(value: &str) -> Result<Self, String> {
        DomainPattern::parse(value).map(Self)
    }

    pub fn matches_authority(&self, authority: &str) -> Result<bool, String> {
        Ok(self.0.matches(&Host::parse_authority(authority)?))
    }
}

impl fmt::Display for DestinationPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl DomainPolicy {
    pub fn parse(
        allowed: Option<&str>,
        denied: Option<&str>,
        allow_private_network: bool,
    ) -> Result<Self, String> {
        Ok(Self {
            allowed: parse_list("--allow-domains", allowed)?,
            denied: parse_list("--deny-domains", denied)?,
            allow_private_network,
        })
    }

    pub fn is_blocked(&self, authority: &str) -> Result<bool, String> {
        let host = Host::parse_authority(authority)?;
        if let Host::Ip(ip) = &host {
            if !is_public_unicast(*ip)
                && !self.private_destination_is_explicitly_allowed(&Host::Ip(*ip))
            {
                return Ok(true);
            }
        }
        if self.denied.iter().any(|pattern| pattern.matches(&host)) {
            return Ok(true);
        }
        Ok(!self.allowed.is_empty() && !self.allowed.iter().any(|pattern| pattern.matches(&host)))
    }

    pub fn allowed_display(&self) -> String {
        display_patterns(&self.allowed)
    }

    pub fn denied_display(&self) -> String {
        display_patterns(&self.denied)
    }

    pub fn has_allowlist(&self) -> bool {
        !self.allowed.is_empty()
    }

    pub fn configured_rule_count(&self) -> usize {
        self.allowed.len() + self.denied.len()
    }

    /// Applies the address-class policy after every DNS resolution and again
    /// to the selected upstream socket address. Domain rules alone never opt
    /// a destination into host-local or private networking.
    pub fn allows_resolved_ip(&self, hostname: &str, ip: IpAddr) -> bool {
        if is_public_unicast(ip) {
            return true;
        }
        let Ok(host) = normalize_name(hostname).map(Host::Name) else {
            return false;
        };
        self.private_destination_is_explicitly_allowed(&host)
            || self.private_destination_is_explicitly_allowed(&Host::Ip(ip))
    }

    fn private_destination_is_explicitly_allowed(&self, host: &Host) -> bool {
        self.allow_private_network
            && !self.allowed.is_empty()
            && self.allowed.iter().any(|pattern| pattern.matches(host))
    }
}

fn is_public_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !matches!(
                (a, b, c),
                (0, _, _)
                    | (10, _, _)
                    | (100, 64..=127, _)
                    | (127, _, _)
                    | (169, 254, _)
                    | (172, 16..=31, _)
                    | (192, 0, 0)
                    | (192, 0, 2)
                    | (192, 88, 99)
                    | (192, 168, _)
                    | (198, 18..=19, _)
                    | (198, 51, 100)
                    | (203, 0, 113)
                    | (224..=255, _, _)
            )
        }
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                return is_public_unicast(IpAddr::V4(ipv4));
            }
            // Globally routed IPv6 unicast occupies 2000::/3. This excludes
            // unspecified, loopback, ULA, link-local, multicast, and reserved
            // ranges. The documentation prefix is not a real destination.
            let segments = ip.segments();
            (segments[0] & 0xe000) == 0x2000 && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

fn display_patterns(patterns: &[DomainPattern]) -> String {
    patterns
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn parse_list(flag: &str, value: Option<&str>) -> Result<Vec<DomainPattern>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value.split(',').map(str::trim).collect::<Vec<_>>();
    if values.is_empty() || values.iter().any(|value| value.is_empty()) {
        return Err(format!(
            "{flag} requires a non-empty comma-separated domain list"
        ));
    }
    values
        .into_iter()
        .map(|value| DomainPattern::parse(value).map_err(|error| format!("{flag}: {error}")))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DomainPattern {
    Name(String),
    Ip(IpAddr),
}

impl DomainPattern {
    fn parse(value: &str) -> Result<Self, String> {
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        Ok(Self::Name(normalize_name(value)?))
    }

    fn matches(&self, host: &Host) -> bool {
        match (self, host) {
            (Self::Ip(pattern), Host::Ip(host)) => pattern == host,
            (Self::Name(pattern), Host::Name(host)) => {
                host == pattern
                    || host
                        .strip_suffix(pattern)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
            _ => false,
        }
    }
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(value) => formatter.write_str(value),
            Self::Ip(value) => value.fmt(formatter),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Host {
    Name(String),
    Ip(IpAddr),
}

impl Host {
    fn parse_authority(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("request has no destination authority".into());
        }
        let host = if let Some(rest) = value.strip_prefix('[') {
            let end = rest.find(']').ok_or("malformed bracketed IPv6 authority")?;
            let host = &rest[..end];
            let suffix = &rest[end + 1..];
            if !suffix.is_empty()
                && (!suffix.starts_with(':') || suffix[1..].parse::<u16>().is_err())
            {
                return Err("malformed bracketed IPv6 port".into());
            }
            host
        } else if value.matches(':').count() == 1 {
            let (host, port) = value.rsplit_once(':').unwrap();
            if port.parse::<u16>().is_err() {
                return Err("malformed destination port".into());
            }
            host
        } else {
            value
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        Ok(Self::Name(normalize_name(host)?))
    }
}

fn normalize_name(value: &str) -> Result<String, String> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return Err(format!("invalid ASCII domain name: {value:?}"));
    }
    if value.contains(['/', '\\', '@', '[', ']', ':']) {
        return Err(format!(
            "domain must not contain a scheme, path, credentials, or port: {value:?}"
        ));
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!("invalid domain label in {value:?}"));
        }
    }
    Ok(value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests;
