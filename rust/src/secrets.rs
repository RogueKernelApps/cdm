//! Secret detection and obfuscation.
//!
//! Scans files and environment variables for secrets (API keys, tokens, private
//! keys, passwords). Replaces each with a fake value of the same length and
//! character class. Maintains a bidirectional mapping so the egress proxy can
//! swap fake→real on outbound network traffic.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

use crate::anchored::AnchoredRoot;
use crate::config::CdmConfig;
use crate::network::DestinationPattern;

/// Bidirectional fake↔real secret mapping.
#[derive(Clone)]
pub struct SecretMapping {
    /// fake value → real value (used by proxy)
    pub fake_to_real: HashMap<String, String>,
    /// real value → fake value (used during obfuscation)
    pub real_to_fake: HashMap<String, String>,
    restoration_scopes: HashMap<String, Vec<DestinationPattern>>,
    environment_replacements: HashMap<String, EnvironmentReplacement>,
}

#[derive(Clone)]
struct EnvironmentReplacement {
    real: String,
    fake: String,
}

impl SecretMapping {
    pub fn new() -> Self {
        SecretMapping {
            fake_to_real: HashMap::new(),
            real_to_fake: HashMap::new(),
            restoration_scopes: HashMap::new(),
            environment_replacements: HashMap::new(),
        }
    }

    /// Registers a real secret and generates a fake replacement.
    pub fn add(&mut self, real: String) -> io::Result<String> {
        self.add_scoped(real, Vec::new())
    }

    #[cfg(test)]
    pub(crate) fn add_with_destinations(
        &mut self,
        real: String,
        destinations: &[&str],
    ) -> io::Result<String> {
        let destinations = destinations
            .iter()
            .map(|value| {
                DestinationPattern::parse(value)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
            })
            .collect::<io::Result<Vec<_>>>()?;
        self.add_scoped(real, destinations)
    }

    fn add_scoped(
        &mut self,
        real: String,
        destinations: Vec<DestinationPattern>,
    ) -> io::Result<String> {
        if let Some(fake) = self.real_to_fake.get(&real) {
            merge_destinations(&mut self.restoration_scopes, fake, destinations);
            return Ok(fake.clone());
        }
        self.reject_fake_as_real(&real)?;
        for _ in 0..MAX_FAKE_ATTEMPTS {
            let fake = generate_fake(&real)?;
            if self.fake_is_available(&real, &fake) {
                self.fake_to_real.insert(fake.clone(), real.clone());
                self.real_to_fake.insert(real, fake.clone());
                merge_destinations(&mut self.restoration_scopes, &fake, destinations);
                return Ok(fake);
            }
        }
        Err(io::Error::other(
            "could not create a unique secret replacement after bounded retries",
        ))
    }

    fn add_environment_scoped(
        &mut self,
        name: String,
        real: String,
        destinations: Vec<DestinationPattern>,
    ) -> io::Result<String> {
        if real.len() >= MIN_GLOBAL_SECRET_LENGTH {
            return self.add_scoped(real, destinations);
        }
        if let Some(existing) = self.environment_replacements.get(&name) {
            if existing.real != real {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "secret environment value changed during preparation",
                ));
            }
            merge_destinations(&mut self.restoration_scopes, &existing.fake, destinations);
            return Ok(existing.fake.clone());
        }
        let mut random = OsRandom;
        for _ in 0..MAX_FAKE_ATTEMPTS {
            let fake = generate_environment_fake(&mut random)?;
            if self.fake_to_real.contains_key(&fake)
                || self.real_to_fake.contains_key(&fake)
                || self
                    .real_to_fake
                    .keys()
                    .any(|known_real| fake.contains(known_real))
            {
                continue;
            }
            self.fake_to_real.insert(fake.clone(), real.clone());
            merge_destinations(&mut self.restoration_scopes, &fake, destinations);
            self.environment_replacements.insert(
                name,
                EnvironmentReplacement {
                    real,
                    fake: fake.clone(),
                },
            );
            return Ok(fake);
        }
        Err(io::Error::other(
            "could not create a unique environment secret replacement after bounded retries",
        ))
    }

    #[cfg(test)]
    fn add_with_random(
        &mut self,
        real: String,
        random: &mut dyn RandomSource,
    ) -> io::Result<String> {
        if let Some(fake) = self.real_to_fake.get(&real) {
            return Ok(fake.clone());
        }
        self.reject_fake_as_real(&real)?;

        for _ in 0..MAX_FAKE_ATTEMPTS {
            let fake = generate_fake_with_random(&real, random)?;
            if self.fake_is_available(&real, &fake) {
                self.fake_to_real.insert(fake.clone(), real.clone());
                self.real_to_fake.insert(real, fake.clone());
                return Ok(fake);
            }
        }

        Err(io::Error::other(
            "could not create a unique secret replacement after bounded retries",
        ))
    }

    fn reject_fake_as_real(&self, real: &str) -> io::Result<()> {
        if self.fake_to_real.keys().any(|fake| fake.contains(real)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secret mapping real and replacement values overlap",
            ));
        }
        Ok(())
    }

    fn fake_is_available(&self, real: &str, fake: &str) -> bool {
        fake != real
            && !self.fake_to_real.contains_key(fake)
            && !self.real_to_fake.contains_key(fake)
            && !fake.contains(real)
            && !self
                .real_to_fake
                .keys()
                .any(|known_real| fake.contains(known_real))
    }

    /// Replaces all known real secrets in data with their fakes.
    pub fn obfuscate(&self, data: &str) -> String {
        String::from_utf8(replace_bytes(data.as_bytes(), self.real_to_fake.iter()))
            .expect("UTF-8 secret replacement preserves UTF-8")
    }

    pub fn obfuscate_environment_value(&self, name: &str, value: &str) -> String {
        if let Some(replacement) = self.environment_replacements.get(name) {
            if replacement.real == value {
                return replacement.fake.clone();
            }
        }
        self.obfuscate(value)
    }

    pub fn obfuscate_bytes(&self, data: &[u8]) -> Vec<u8> {
        replace_bytes(data, self.real_to_fake.iter())
    }

    pub fn scrub_response_bytes(&self, data: &[u8]) -> Vec<u8> {
        let mut replacements = self.real_to_fake.iter().collect::<Vec<_>>();
        replacements.extend(
            self.environment_replacements
                .values()
                .map(|replacement| (&replacement.real, &replacement.fake)),
        );
        replace_bytes(data, replacements)
    }

    /// Replaces all known fake secrets in data with their real values.
    /// Used by the egress proxy.
    #[cfg(test)]
    pub fn deobfuscate(&self, data: &str) -> String {
        String::from_utf8(replace_bytes(data.as_bytes(), self.fake_to_real.iter()))
            .expect("UTF-8 secret restoration preserves UTF-8")
    }

    /// Restores only secrets explicitly authorized for the normalized request
    /// authority. Unknown secrets have no destinations and are never restored.
    pub fn deobfuscate_for_authority(&self, data: &str, authority: &str) -> Result<String, String> {
        let replacements = self.authorized_replacements(authority)?;
        Ok(
            String::from_utf8(replace_bytes(data.as_bytes(), replacements))
                .expect("UTF-8 secret restoration preserves UTF-8"),
        )
    }

    pub fn deobfuscate_bytes_for_authority(
        &self,
        data: &[u8],
        authority: &str,
    ) -> Result<Vec<u8>, String> {
        let authorized = self.authorized_replacements(authority)?;
        Ok(replace_bytes(data, authorized))
    }

    fn authorized_replacements<'a>(
        &'a self,
        authority: &str,
    ) -> Result<Vec<(&'a String, &'a String)>, String> {
        let mut replacements = Vec::new();
        let mut authority_validated = false;
        for (fake, real) in &self.fake_to_real {
            let Some(patterns) = self.restoration_scopes.get(fake) else {
                continue;
            };
            for pattern in patterns {
                let matches = pattern.matches_authority(authority)?;
                authority_validated = true;
                if matches {
                    replacements.push((fake, real));
                    break;
                }
            }
        }
        if !authority_validated && !authority.trim().is_empty() {
            // No restorable mappings means there is nothing to parse or replace.
            return Ok(replacements);
        }
        replacements.sort_by(|(left, _), (right, _)| {
            right.len().cmp(&left.len()).then_with(|| left.cmp(right))
        });
        Ok(replacements)
    }

    /// Registers recognized token values in argv, then returns an argv vector
    /// with identical boundaries and every known real value replaced.
    pub fn obfuscate_argv(
        &mut self,
        argv: &[OsString],
        config: &CdmConfig,
    ) -> io::Result<Vec<OsString>> {
        let rules = DestinationRules::from_config(config)?;
        for argument in argv {
            let Some(argument) = argument.to_str() else {
                // Detection rules describe textual credential syntaxes. Opaque
                // arguments are still rewritten with every secret already
                // discovered from trusted host sources below.
                continue;
            };
            for (identifier, candidate) in command_secret_candidates(argument) {
                if looks_like_secret_with_config(
                    candidate,
                    config.secrets.min_length,
                    config.secrets.min_char_classes,
                ) {
                    let destinations = rules.destinations(identifier, candidate, None);
                    self.add_scoped(candidate.to_string(), destinations)?;
                }
            }
        }
        Ok(argv
            .iter()
            .map(|argument| OsString::from_vec(self.obfuscate_bytes(argument.as_bytes())))
            .collect())
    }
}

fn replace_bytes<'a, I>(data: &[u8], replacements: I) -> Vec<u8>
where
    I: IntoIterator<Item = (&'a String, &'a String)>,
{
    let mut replacements = replacements.into_iter().collect::<Vec<_>>();
    replacements.sort_by(|(left, _), (right, _)| {
        right.len().cmp(&left.len()).then_with(|| left.cmp(right))
    });
    let mut output = Vec::with_capacity(data.len());
    let mut offset = 0;
    while offset < data.len() {
        let replacement = replacements
            .iter()
            .find(|(from, _)| data[offset..].starts_with(from.as_bytes()));
        if let Some((from, to)) = replacement {
            output.extend_from_slice(to.as_bytes());
            offset += from.len();
            continue;
        }
        output.push(data[offset]);
        offset += 1;
    }
    output
}

fn merge_destinations(
    scopes: &mut HashMap<String, Vec<DestinationPattern>>,
    fake: &str,
    destinations: Vec<DestinationPattern>,
) {
    let target = scopes.entry(fake.to_string()).or_default();
    for destination in destinations {
        if !target.contains(&destination) {
            target.push(destination);
        }
    }
}

impl Default for SecretMapping {
    fn default() -> Self {
        Self::new()
    }
}

/// Checks if an environment variable name suggests it holds a secret,
/// using the provided list of name patterns.
pub fn is_secret_name_with_patterns(name: &str, patterns: &[String]) -> bool {
    let lower = name.to_lowercase();
    patterns.iter().any(|word| lower.contains(word.as_str()))
}

/// Checks if a value has characteristics of a secret, using provided thresholds.
pub fn looks_like_secret_with_config(
    value: &str,
    min_length: usize,
    min_char_classes: usize,
) -> bool {
    if value.len() < min_length || value.chars().any(char::is_whitespace) {
        return false;
    }

    // File paths and non-credential URLs are not secrets.
    if value.starts_with('/') || value.starts_with("./") || value.starts_with("~/") {
        return false;
    }
    if (value.starts_with("http://") || value.starts_with("https://")) && !is_credential_url(value)
    {
        return false;
    }

    let classes = character_classes(value);
    classes >= min_char_classes && is_supported_token_format(value)
}

fn character_classes(value: &str) -> usize {
    let upper = value.bytes().any(|byte| byte.is_ascii_uppercase());
    let lower = value.bytes().any(|byte| byte.is_ascii_lowercase());
    let digit = value.bytes().any(|byte| byte.is_ascii_digit());
    [upper, lower, digit]
        .into_iter()
        .filter(|present| *present)
        .count()
}

fn has_token_suffix(value: &str, prefix: &str, minimum: usize, allowed: fn(u8) -> bool) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|tail| tail.len() >= minimum && tail.bytes().all(allowed))
}

fn is_urlsafe_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn is_token_byte(byte: u8) -> bool {
    is_urlsafe_byte(byte) || byte == b'.'
}

fn is_aws_access_key(value: &str) -> bool {
    value.len() == 20
        && [
            "AKIA", "ASIA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASCA",
        ]
        .iter()
        .any(|prefix| value.starts_with(prefix))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn is_github_token(value: &str) -> bool {
    ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
        .iter()
        .any(|prefix| has_token_suffix(value, prefix, 36, is_urlsafe_byte))
        || has_token_suffix(value, "github_pat_", 22, is_urlsafe_byte)
}

/// Conservative, syntax-only recognition for common provider token formats.
/// Secret-like key names remain the primary detection mechanism.
fn is_supported_token_format(value: &str) -> bool {
    let jwt = {
        let parts: Vec<_> = value.split('.').collect();
        parts.len() == 3
            && parts[0].len() >= 8
            && parts[1].len() >= 8
            && parts[2].len() >= 16
            && parts.iter().all(|part| part.bytes().all(is_urlsafe_byte))
    };

    is_aws_access_key(value)
        || is_github_token(value)
        || is_credential_url(value)
        || has_token_suffix(value, "sk-proj-", 20, is_token_byte)
        || has_token_suffix(value, "sk-ant-", 20, is_token_byte)
        || has_token_suffix(value, "sk-", 20, is_token_byte)
        || has_token_suffix(value, "npm_", 36, is_urlsafe_byte)
        || has_token_suffix(value, "glpat-", 20, is_urlsafe_byte)
        || has_token_suffix(value, "AIza", 35, is_urlsafe_byte)
        || has_token_suffix(value, "sk_live_", 16, is_urlsafe_byte)
        || has_token_suffix(value, "rk_live_", 16, is_urlsafe_byte)
        || ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"]
            .iter()
            .any(|prefix| has_token_suffix(value, prefix, 20, is_token_byte))
        || jwt
}

fn is_credential_url(value: &str) -> bool {
    let Some((scheme, remainder)) = value.split_once("://") else {
        return false;
    };
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return false;
    }
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    let Some((userinfo, host)) = authority.rsplit_once('@') else {
        return false;
    };
    let Some((user, password)) = userinfo.split_once(':') else {
        return false;
    };
    !user.is_empty() && !password.is_empty() && !host.is_empty()
}

fn credential_url_host(value: &str) -> Option<&str> {
    let (_, remainder) = value.split_once("://")?;
    let authority = remainder.split(['/', '?', '#']).next()?;
    let (_, host_port) = authority.rsplit_once('@')?;
    if let Some(host) = host_port.strip_prefix('[') {
        return host.split(']').next();
    }
    Some(
        host_port
            .rsplit_once(':')
            .map_or(host_port, |(host, _)| host),
    )
}

struct DestinationRules {
    explicit: HashMap<String, Vec<DestinationPattern>>,
}

impl DestinationRules {
    fn from_config(config: &CdmConfig) -> io::Result<Self> {
        let mut explicit = HashMap::new();
        for (identifier, values) in &config.secrets.restore_destinations {
            let identifier = normalize_identifier(identifier)?;
            if values.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "secret destination rule requires at least one destination",
                ));
            }
            let patterns = values
                .iter()
                .map(|value| {
                    DestinationPattern::parse(value).map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("invalid secret destination rule: {error}"),
                        )
                    })
                })
                .collect::<io::Result<Vec<_>>>()?;
            if explicit.insert(identifier, patterns).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "secret destination rules contain duplicate normalized identifiers",
                ));
            }
        }
        Ok(Self { explicit })
    }

    fn destinations(
        &self,
        identifier: Option<&str>,
        real: &str,
        source: Option<&Path>,
    ) -> Vec<DestinationPattern> {
        let mut values = Vec::new();
        if let Some(identifier) = identifier.and_then(|value| normalize_identifier(value).ok()) {
            if let Some(explicit) = self.explicit.get(&identifier) {
                values.extend(explicit.iter().cloned());
            }
            values.extend(provider_destinations_for_identifier(&identifier));
        }
        values.extend(provider_destinations_for_token(real));
        if source.is_some_and(|path| path.file_name().is_some_and(|name| name == ".npmrc")) {
            values.extend(parse_destinations(&["registry.npmjs.org"]));
        }
        if is_credential_url(real) {
            if let Some(host) = credential_url_host(real) {
                if let Ok(pattern) = DestinationPattern::parse(host) {
                    values.push(pattern);
                }
            }
        }
        values.sort_by_key(ToString::to_string);
        values.dedup();
        values
    }
}

fn normalize_identifier(value: &str) -> io::Result<String> {
    let normalized = value
        .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    if normalized.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret destination rule has an empty identifier",
        ));
    }
    Ok(normalized)
}

fn provider_destinations_for_identifier(identifier: &str) -> Vec<DestinationPattern> {
    let values: &[&str] = if identifier.contains("OPENAI") {
        &["api.openai.com"]
    } else if identifier.contains("ANTHROPIC") {
        &["api.anthropic.com"]
    } else if identifier.contains("GITHUB") {
        &["github.com"]
    } else if identifier.contains("GITLAB") {
        &["gitlab.com"]
    } else if identifier.contains("NPM") {
        &["registry.npmjs.org"]
    } else if identifier.contains("STRIPE") {
        &["api.stripe.com"]
    } else if identifier.contains("SLACK") {
        &["api.slack.com"]
    } else if identifier.starts_with("AWS_") || identifier.contains("AWS_ACCESS") {
        &["amazonaws.com", "amazonaws.com.cn"]
    } else if identifier.contains("GOOGLE") || identifier.contains("GEMINI") {
        &["googleapis.com"]
    } else {
        &[]
    };
    parse_destinations(values)
}

fn provider_destinations_for_token(real: &str) -> Vec<DestinationPattern> {
    let values: &[&str] = if is_github_token(real) {
        &["github.com"]
    } else if has_token_suffix(real, "sk-ant-", 20, is_token_byte) {
        &["api.anthropic.com"]
    } else if has_token_suffix(real, "sk_live_", 16, is_urlsafe_byte)
        || has_token_suffix(real, "rk_live_", 16, is_urlsafe_byte)
    {
        &["api.stripe.com"]
    } else if has_token_suffix(real, "sk-proj-", 20, is_token_byte)
        || (has_token_suffix(real, "sk-", 20, is_token_byte) && !real.starts_with("sk_live_"))
    {
        &["api.openai.com"]
    } else if has_token_suffix(real, "npm_", 36, is_urlsafe_byte) {
        &["registry.npmjs.org"]
    } else if has_token_suffix(real, "glpat-", 20, is_urlsafe_byte) {
        &["gitlab.com"]
    } else if ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"]
        .iter()
        .any(|prefix| has_token_suffix(real, prefix, 20, is_token_byte))
    {
        &["api.slack.com"]
    } else if has_token_suffix(real, "AIza", 35, is_urlsafe_byte) {
        &["googleapis.com"]
    } else if is_aws_access_key(real) {
        &["amazonaws.com", "amazonaws.com.cn"]
    } else {
        &[]
    };
    parse_destinations(values)
}

fn parse_destinations(values: &[&str]) -> Vec<DestinationPattern> {
    values
        .iter()
        .map(|value| DestinationPattern::parse(value).expect("static destination is valid"))
        .collect()
}

fn command_secret_candidates(argument: &str) -> Vec<(Option<&str>, &str)> {
    let mut candidates = vec![(None, argument.trim_matches(['\'', '"']))];
    if let Some((identifier, value)) = argument.split_once('=') {
        candidates.push((
            Some(identifier.trim_start_matches('-')),
            value.trim_matches(['\'', '"']),
        ));
    }
    for word in argument.split_ascii_whitespace() {
        candidates.push((
            None,
            word.trim_matches(|character: char| {
                matches!(character, '\'' | '"' | ',' | ';' | '(' | ')')
            }),
        ));
    }
    candidates
}

/// Detects secrets in environment variables by matching variable names
/// against the provided name patterns (key, secret, token, auth, etc.).
pub fn detect_in_env(name_patterns: &[String]) -> io::Result<Vec<(String, String)>> {
    let mut found = Vec::new();

    // Env vars that should never be treated as secrets
    let skip_names = [
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "TERM",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "TEMP",
        "TMP",
        "PWD",
        "OLDPWD",
        "HOSTNAME",
        "LOGNAME",
        "DISPLAY",
        "EDITOR",
        "VISUAL",
        "PAGER",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
        "XDG_SESSION_TYPE",
        "HOMEBREW_PREFIX",
        "HOMEBREW_CELLAR",
        "HOMEBREW_REPOSITORY",
        "GOPATH",
        "GOROOT",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "NVM_DIR",
        "PYENV_ROOT",
        "VOLTA_HOME",
    ];

    for (name, value) in std::env::vars_os() {
        let name = name.into_string().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "environment contains a non-UTF-8 variable name",
            )
        })?;
        let value = value.into_string().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "environment contains a non-UTF-8 variable value",
            )
        })?;
        if value.is_empty() || skip_names.contains(&name.as_str()) {
            continue;
        }

        if is_secret_name_with_patterns(&name, name_patterns) {
            found.push((name, value));
        }
    }

    Ok(found)
}

/// Detects secrets in a file (key=value or key:value format).
#[cfg(test)]
pub fn detect_in_file<P: AsRef<Path>>(
    path: P,
    name_patterns: &[String],
    min_length: usize,
    min_char_classes: usize,
) -> io::Result<HashMap<String, String>> {
    let path = path.as_ref();
    let file = open_regular_file(path)?;
    detect_in_open_file(path, file, name_patterns, min_length, min_char_classes)
}

fn detect_in_open_file(
    path: &Path,
    mut file: fs::File,
    name_patterns: &[String],
    min_length: usize,
    min_char_classes: usize,
) -> io::Result<HashMap<String, String>> {
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|error| context("read secret file", path, error))?;
    let mut secrets = HashMap::new();

    if path
        .extension()
        .is_some_and(|extension| extension == "json")
    {
        let value: serde_json::Value = serde_json::from_str(&content).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("malformed JSON secret file {}: {error}", path.display()),
            )
        })?;
        collect_json_secrets(
            &value,
            None,
            name_patterns,
            min_length,
            min_char_classes,
            &mut secrets,
        );
        return Ok(secrets);
    }

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        if let Some(idx) = line.find(['=', ':']) {
            let key = line[..idx].trim();
            let value = line[idx + 1..].trim().trim_matches('"').trim_matches('\'');

            let structural_literal = matches!(value, "{" | "}" | "{}" | "[" | "]" | "[]");
            if !value.is_empty()
                && !structural_literal
                && (is_secret_name_with_patterns(key, name_patterns)
                    || looks_like_secret_with_config(value, min_length, min_char_classes))
            {
                secrets.insert(key.to_string(), value.to_string());
            }
        }
    }

    Ok(secrets)
}

fn collect_json_secrets(
    value: &serde_json::Value,
    key: Option<&str>,
    name_patterns: &[String],
    min_length: usize,
    min_char_classes: usize,
    secrets: &mut HashMap<String, String>,
) {
    match value {
        serde_json::Value::Object(values) => {
            for (child_key, child) in values {
                collect_json_secrets(
                    child,
                    Some(child_key),
                    name_patterns,
                    min_length,
                    min_char_classes,
                    secrets,
                );
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                collect_json_secrets(
                    child,
                    key,
                    name_patterns,
                    min_length,
                    min_char_classes,
                    secrets,
                );
            }
        }
        serde_json::Value::String(value)
            if key.is_some_and(|key| is_secret_name_with_patterns(key, name_patterns))
                || looks_like_secret_with_config(value, min_length, min_char_classes) =>
        {
            secrets.insert(key.unwrap_or("value").to_string(), value.clone());
        }
        _ => {}
    }
}

/// Scans the host for secrets in common locations and builds a complete mapping.
pub fn scan_host(
    home_dir: &Path,
    work_dir: &Path,
    config: &CdmConfig,
    allow_home_path: &dyn Fn(&Path) -> bool,
) -> io::Result<SecretMapping> {
    let mut mapping = SecretMapping::new();
    let destination_rules = DestinationRules::from_config(config)?;
    let home_root = AnchoredRoot::open(home_dir)?;
    let work_root = AnchoredRoot::open(work_dir)?;

    // Environment variables
    for (name, value) in detect_in_env(&config.secrets.name_patterns)? {
        let destinations = destination_rules.destinations(Some(&name), &value, None);
        mapping.add_environment_scoped(name, value, destinations)?;
    }

    // Config files: home dir configs (from staged_configs keys) + .env files in working directory
    let mut all_files = Vec::new();
    for relative in config.paths.staged_configs.keys() {
        let path = resolve_relative_candidate(home_dir, relative)?;
        if allow_home_path(&path) {
            all_files.push((&home_root, path));
        }
    }
    for relative in &config.secrets.env_files {
        all_files.push((&work_root, resolve_relative_candidate(work_dir, relative)?));
    }

    for (root, path) in all_files {
        let Some(file) = root.open_regular(&path)? else {
            continue;
        };
        let secrets = detect_in_open_file(
            &path,
            file,
            &config.secrets.name_patterns,
            config.secrets.min_length,
            config.secrets.min_char_classes,
        )?;
        for (name, value) in secrets {
            if value.len() < MIN_GLOBAL_SECRET_LENGTH {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "secret file value is too short for safe replacement: {}",
                        path.display()
                    ),
                ));
            }
            let destinations = destination_rules.destinations(Some(&name), &value, Some(&path));
            mapping.add_scoped(value, destinations)?;
        }
    }

    // ~/.ssh private keys
    let ssh_dir = home_dir.join(".ssh");
    if allow_home_path(&ssh_dir) {
        for (path, mut file) in home_root.open_regular_directory(&ssh_dir)? {
            let mut content = String::new();
            file.read_to_string(&mut content)
                .map_err(|error| context("read SSH key", &path, error))?;
            if !content.contains("PRIVATE KEY") {
                continue;
            }
            mapping.add(content)?;
        }
    }

    Ok(mapping)
}

/// Generates a fake value preserving length and character class per position.
pub(crate) fn generate_fake(real: &str) -> io::Result<String> {
    let mut random = OsRandom;
    for _ in 0..MAX_FAKE_ATTEMPTS {
        let fake = generate_fake_with_random(real, &mut random)?;
        if fake != real {
            return Ok(fake);
        }
    }
    Err(io::Error::other(
        "could not create a distinct secret replacement after bounded retries",
    ))
}

const MAX_FAKE_ATTEMPTS: usize = 32;
const MIN_GLOBAL_SECRET_LENGTH: usize = 8;

trait RandomSource {
    fn fill(&mut self, bytes: &mut [u8]) -> io::Result<()>;
}

struct OsRandom;

fn generate_environment_fake(random: &mut dyn RandomSource) -> io::Result<String> {
    let mut bytes = [0_u8; 16];
    random.fill(&mut bytes)?;
    Ok(format!("cdm_fake_{:032x}", u128::from_le_bytes(bytes)))
}

impl RandomSource for OsRandom {
    fn fill(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        let mut source = fs::File::open("/dev/urandom").map_err(|error| {
            io::Error::new(error.kind(), format!("open OS random source: {error}"))
        })?;
        source.read_exact(bytes).map_err(|error| {
            io::Error::new(error.kind(), format!("read OS random source: {error}"))
        })
    }
}

fn generate_fake_with_random(real: &str, random: &mut dyn RandomSource) -> io::Result<String> {
    let chars: Vec<char> = real.chars().collect();
    if !chars
        .iter()
        .any(|character| character.is_ascii_alphanumeric())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret replacement requires at least one ASCII alphanumeric character",
        ));
    }
    let mut rand_bytes = vec![0u8; chars.len()];
    random.fill(&mut rand_bytes)?;
    Ok(chars
        .iter()
        .zip(rand_bytes.iter())
        .map(|(&c, &b)| match c {
            'A'..='Z' => (b'A' + (b % 26)) as char,
            'a'..='z' => (b'a' + (b % 26)) as char,
            '0'..='9' => (b'0' + (b % 10)) as char,
            _ => c,
        })
        .collect())
}

#[cfg(test)]
fn open_regular_file(path: &Path) -> io::Result<fs::File> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|error| context("open secret file", path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| context("inspect opened secret file", path, error))?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("secret source is not a regular file: {}", path.display()),
        ));
    }
    Ok(file)
}

fn context(operation: &str, path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{operation} {}: {error}", path.display()),
    )
}

pub(crate) fn resolve_relative_candidate(
    base: &Path,
    configured: &str,
) -> io::Result<std::path::PathBuf> {
    use std::path::Component;

    let path = Path::new(configured);
    if configured.is_empty()
        || path.components().any(|component| {
            matches!(
                component,
                Component::RootDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret candidate must be a non-empty relative path without parent traversal",
        ));
    }
    Ok(base.join(path))
}

#[cfg(test)]
mod tests;
