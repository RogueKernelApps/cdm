//! Strict, versioned guest execution plans for CDM's microVM PID 1.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::{CString, OsString};
use std::io::{self, Read};
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

pub const PLAN_SCHEMA: u32 = 2;
pub const MAX_PLAN_BYTES: u64 = 1024 * 1024;
const MAX_ARGV: usize = 4096;
const MAX_ENV: usize = 4096;
const MAX_MOUNTS: usize = 1024;
const MAX_DENIES: usize = 4096;
const MAX_STRING_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    /// Exact Unix argument bytes. JSON text cannot represent arbitrary argv.
    pub argv_bytes: Vec<Vec<u8>>,
    #[serde(default, deserialize_with = "deserialize_env")]
    pub fake_env: BTreeMap<String, String>,
    pub cwd: PathBuf,
    pub uid: u32,
    pub gid: u32,
    #[serde(default)]
    pub mounts: Vec<Mount>,
    #[serde(default)]
    pub denies: Vec<Deny>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub kind: MountKind,
    #[serde(default)]
    pub source: Option<String>,
    pub target: PathBuf,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MountKind {
    Virtiofs,
    Bind,
    Proc,
    Sysfs,
    Devtmpfs,
    Tmpfs,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Deny {
    pub path: PathBuf,
    pub kind: DenyKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DenyKind {
    File,
    Directory,
}

impl Plan {
    pub fn parse(reader: impl Read) -> io::Result<Self> {
        let mut bytes = Vec::new();
        reader
            .take(MAX_PLAN_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| invalid(format!("cannot read guest plan: {error}")))?;
        if bytes.len() as u64 > MAX_PLAN_BYTES {
            return Err(invalid(format!(
                "guest plan exceeds the {MAX_PLAN_BYTES}-byte limit"
            )));
        }
        let plan: Self = serde_json::from_slice(&bytes)
            .map_err(|error| invalid(format!("invalid guest plan JSON: {error}")))?;
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> io::Result<()> {
        if self.schema != PLAN_SCHEMA {
            return Err(invalid(format!(
                "unsupported guest plan schema {}; expected {PLAN_SCHEMA}",
                self.schema
            )));
        }
        if self.argv_bytes.is_empty() {
            return Err(invalid("guest plan argv must not be empty"));
        }
        if self.uid == 0 || self.gid == 0 {
            return Err(invalid("guest uid and gid must both be nonzero"));
        }
        bounded("argv_bytes", self.argv_bytes.len(), MAX_ARGV)?;
        bounded("fake_env", self.fake_env.len(), MAX_ENV)?;
        bounded("mounts", self.mounts.len(), MAX_MOUNTS)?;
        bounded("denies", self.denies.len(), MAX_DENIES)?;
        absolute_normal_path(&self.cwd, "cwd")?;
        for value in &self.argv_bytes {
            bounded("argv byte value", value.len(), MAX_STRING_BYTES)?;
            if value.contains(&0) {
                return Err(invalid("argv byte value contains NUL"));
            }
        }
        for (key, value) in &self.fake_env {
            if key.is_empty() || key.contains('=') {
                return Err(invalid(format!("invalid environment name {key:?}")));
            }
            safe_c_string(key, "environment name")?;
            safe_c_string(value, "environment value")?;
        }
        let read_only_exports = self
            .mounts
            .iter()
            .filter(|mount| mount.kind == MountKind::Virtiofs && mount.read_only)
            .map(|mount| mount.target.as_path())
            .collect::<Vec<_>>();
        for mount in &self.mounts {
            absolute_normal_path(&mount.target, "mount target")?;
            if mount.target == Path::new("/") {
                return Err(invalid("mount target must not be /"));
            }
            if mount.target.starts_with("/proc")
                && !(mount.kind == MountKind::Proc && mount.target == Path::new("/proc"))
            {
                return Err(invalid("only the proc filesystem may target /proc"));
            }
            match mount.kind {
                MountKind::Virtiofs => {
                    let source = mount
                        .source
                        .as_deref()
                        .ok_or_else(|| invalid("virtiofs mount requires a non-empty source tag"))?;
                    safe_c_string(source, "virtiofs source tag")?;
                    if source.is_empty() || source.contains('/') {
                        return Err(invalid("virtiofs source must be a plain tag"));
                    }
                }
                MountKind::Bind => {
                    let source = mount
                        .source
                        .as_deref()
                        .ok_or_else(|| invalid("bind mount requires an absolute source"))?;
                    let source = Path::new(source);
                    absolute_normal_path(source, "bind mount source")?;
                    // Bind mounts only project individual protected files out
                    // of immutable VirtioFS exports. This invariant lets PID 1
                    // avoid a file-bind remount operation that libkrun's
                    // VirtioFS returns EINVAL for, without weakening the
                    // effective write denial.
                    if !mount.read_only
                        || !read_only_exports
                            .iter()
                            .any(|export| source.starts_with(export))
                    {
                        return Err(invalid(
                            "bind mount source must be backed by a read-only virtiofs export",
                        ));
                    }
                }
                _ if mount.source.is_some() => {
                    return Err(invalid("only virtiofs and bind mounts accept source"));
                }
                _ => {}
            }
        }
        for deny in &self.denies {
            absolute_normal_path(&deny.path, "deny path")?;
            if deny.path == Path::new("/") {
                return Err(invalid("deny path must not be /"));
            }
        }
        let mut mount_targets = BTreeSet::new();
        for mount in &self.mounts {
            if !mount_targets.insert(&mount.target) {
                return Err(invalid(format!(
                    "duplicate mount target {}",
                    mount.target.display()
                )));
            }
        }
        if !self
            .mounts
            .iter()
            .any(|mount| mount.kind == MountKind::Proc && mount.target == Path::new("/proc"))
        {
            return Err(invalid("guest plan must mount proc at /proc"));
        }
        let mut deny_targets = BTreeSet::new();
        for deny in &self.denies {
            if mount_targets.contains(&deny.path) || !deny_targets.insert(&deny.path) {
                return Err(invalid(format!(
                    "duplicate mount or deny target {}",
                    deny.path.display()
                )));
            }
        }
        Ok(())
    }

    /// Reconstructs the exact OS argv after validation.
    pub fn argv(&self) -> Vec<OsString> {
        self.argv_bytes
            .iter()
            .cloned()
            .map(OsString::from_vec)
            .collect()
    }
}

fn deserialize_env<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct EnvVisitor;

    impl<'de> serde::de::Visitor<'de> for EnvVisitor {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object containing unique environment names")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if values.insert(key.clone(), value).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate environment name {key:?}"
                    )));
                }
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(EnvVisitor)
}

fn bounded(label: &str, actual: usize, maximum: usize) -> io::Result<()> {
    if actual > maximum {
        Err(invalid(format!(
            "guest plan {label} contains {actual} entries; maximum is {maximum}"
        )))
    } else {
        Ok(())
    }
}

fn safe_c_string(value: &str, label: &str) -> io::Result<CString> {
    if value.len() > MAX_STRING_BYTES {
        return Err(invalid(format!("{label} exceeds {MAX_STRING_BYTES} bytes")));
    }
    CString::new(value).map_err(|_| invalid(format!("{label} contains a NUL byte")))
}

pub fn absolute_normal_path(path: &Path, label: &str) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(invalid(format!("{label} must be absolute")));
    }
    let text = path
        .to_str()
        .ok_or_else(|| invalid(format!("{label} must be valid UTF-8")))?;
    if text.len() > 1
        && (text.ends_with('/')
            || text
                .strip_prefix('/')
                .unwrap_or(text)
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == ".."))
    {
        return Err(invalid(format!("{label} must be normalized")));
    }
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::CurDir) {
            return Err(invalid(format!("{label} must be normalized")));
        }
    }
    if path.as_os_str().as_encoded_bytes().len() > MAX_STRING_BYTES {
        return Err(invalid(format!("{label} exceeds {MAX_STRING_BYTES} bytes")));
    }
    Ok(())
}

pub fn mapped_wait_status(status: i32) -> Option<i32> {
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Some(128 + libc::WTERMSIG(status))
    } else {
        None
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    fn valid_json() -> String {
        r#"{
          "schema":2,
          "argv_bytes":[[47,98,105,110,47,112,114,105,110,116,102],[37,115],[104,101,108,108,111,32,119,111,114,108,100]],
          "fake_env":{"API_TOKEN":"cdm-fake-1","PATH":"/usr/bin:/bin"},
          "cwd":"/workspace",
          "uid":1000,
          "gid":1000,
          "mounts":[
            {"kind":"proc","target":"/proc"},
            {"kind":"virtiofs","source":"cdm-workdir","target":"/workspace","read_only":false}
          ],
          "denies":[{"path":"/workspace/.git/config","kind":"file"}]
        }"#
        .into()
    }

    #[test]
    fn parses_strict_versioned_plan_and_preserves_argv() {
        let plan = Plan::parse(valid_json().as_bytes()).unwrap();
        assert_eq!(plan.schema, PLAN_SCHEMA);
        assert_eq!(
            plan.argv(),
            ["/bin/printf", "%s", "hello world"].map(OsString::from)
        );
        assert_eq!(plan.fake_env["API_TOKEN"], "cdm-fake-1");
    }

    #[test]
    fn preserves_non_utf8_argv_and_rejects_nul() {
        let json = valid_json().replace("[37,115]", "[255,32,10,42,63,91,93]");
        let plan = Plan::parse(json.as_bytes()).unwrap();
        assert_eq!(
            plan.argv()[1].as_bytes(),
            &[255, 32, 10, b'*', b'?', b'[', b']']
        );

        let nul = valid_json().replace("[37,115]", "[37,0,115]");
        assert!(Plan::parse(nul.as_bytes()).is_err());
    }

    #[test]
    fn rejects_unknown_fields_at_every_level() {
        for json in [
            valid_json().replace("\n        }", ",\n          \"surprise\":true\n        }"),
            valid_json().replace(
                "\"target\":\"/proc\"}",
                "\"target\":\"/proc\",\"surprise\":true}",
            ),
            valid_json().replace("\"kind\":\"file\"}", "\"kind\":\"file\",\"surprise\":true}"),
        ] {
            assert!(Plan::parse(json.as_bytes()).is_err(), "accepted {json}");
        }
    }

    #[test]
    fn rejects_wrong_schema_empty_argv_and_relative_paths() {
        assert!(Plan::parse(
            valid_json()
                .replace("\"schema\":2", "\"schema\":1")
                .as_bytes()
        )
        .is_err());
        assert!(Plan::parse(
            valid_json()
                .replace("[[47,98,105,110,47,112,114,105,110,116,102],[37,115],[104,101,108,108,111,32,119,111,114,108,100]]", "[]")
                .as_bytes()
        )
        .is_err());
        assert!(Plan::parse(
            valid_json()
                .replace("\"cwd\":\"/workspace\"", "\"cwd\":\"workspace\"")
                .as_bytes()
        )
        .is_err());
        assert!(Plan::parse(
            valid_json()
                .replace("\"/workspace/.git/config\"", "\"../outside\"")
                .as_bytes()
        )
        .is_err());
        for cwd in ["/workspace/./child", "/workspace//child", "/workspace/"] {
            assert!(Plan::parse(
                valid_json()
                    .replace("\"cwd\":\"/workspace\"", &format!("\"cwd\":\"{cwd}\""))
                    .as_bytes()
            )
            .is_err());
        }
        for field in ["uid", "gid"] {
            assert!(Plan::parse(
                valid_json()
                    .replace(&format!("\"{field}\":1000"), &format!("\"{field}\":0"))
                    .as_bytes()
            )
            .is_err());
        }
    }

    #[test]
    fn rejects_invalid_mount_sources_and_environment_names() {
        assert!(Plan::parse(valid_json().replace("cdm-workdir", "../host").as_bytes()).is_err());
        assert!(Plan::parse(valid_json().replace("API_TOKEN", "BAD=NAME").as_bytes()).is_err());
        assert!(Plan::parse(
            valid_json()
                .replace("\"kind\":\"proc\"", "\"kind\":\"proc\",\"source\":\"x\"")
                .as_bytes()
        )
        .is_err());
        let duplicate_env = valid_json().replace(
            "\"API_TOKEN\":\"cdm-fake-1\"",
            "\"API_TOKEN\":\"first\",\"API_TOKEN\":\"second\"",
        );
        assert!(Plan::parse(duplicate_env.as_bytes()).is_err());
    }

    #[test]
    fn bind_mounts_must_be_backed_by_a_read_only_virtiofs_export() {
        let protected = valid_json().replace(
            "{\"kind\":\"virtiofs\",\"source\":\"cdm-workdir\",\"target\":\"/workspace\",\"read_only\":false}",
            "{\"kind\":\"virtiofs\",\"source\":\"cdm-workdir\",\"target\":\"/workspace\",\"read_only\":false},\n            {\"kind\":\"virtiofs\",\"source\":\"cdm-protected\",\"target\":\"/cdm-grants/protected\",\"read_only\":true},\n            {\"kind\":\"bind\",\"source\":\"/cdm-grants/protected/.git\",\"target\":\"/workspace/.git\",\"read_only\":true}",
        );
        assert!(Plan::parse(protected.as_bytes()).is_ok());
        assert!(Plan::parse(
            protected
                .replace(
                    "\"target\":\"/workspace/.git\",\"read_only\":true",
                    "\"target\":\"/workspace/.git\",\"read_only\":false",
                )
                .as_bytes(),
        )
        .is_err());
        assert!(Plan::parse(
            protected
                .replace(
                    "\"source\":\"/cdm-grants/protected/.git\"",
                    "\"source\":\"/workspace/.git\"",
                )
                .as_bytes(),
        )
        .is_err());
    }

    #[test]
    fn all_mounts_are_required_and_targets_are_unambiguous() {
        assert!(Plan::parse(
            valid_json()
                .replace(
                    "\"target\":\"/proc\"}",
                    "\"target\":\"/proc\",\"required\":false}"
                )
                .as_bytes()
        )
        .is_err());
        let duplicate = valid_json().replace(
            "{\"kind\":\"proc\",\"target\":\"/proc\"}",
            "{\"kind\":\"proc\",\"target\":\"/workspace\"}",
        );
        assert!(Plan::parse(duplicate.as_bytes()).is_err());
        let missing_proc = valid_json().replace("{\"kind\":\"proc\",\"target\":\"/proc\"},", "");
        assert!(Plan::parse(missing_proc.as_bytes()).is_err());
        let proc_subtree =
            valid_json().replace("\"target\":\"/workspace\"", "\"target\":\"/proc/self/fd\"");
        assert!(Plan::parse(proc_subtree.as_bytes()).is_err());
    }

    #[test]
    fn rejects_plan_beyond_byte_limit_before_deserializing() {
        let bytes = vec![b' '; MAX_PLAN_BYTES as usize + 1];
        let error = Plan::parse(bytes.as_slice()).unwrap_err();
        assert!(error.to_string().contains("exceeds"));
    }

    #[test]
    fn maps_process_exit_and_signal_statuses() {
        assert_eq!(mapped_wait_status(7 << 8), Some(7));
        assert_eq!(mapped_wait_status(libc::SIGTERM), Some(143));
        assert_eq!(mapped_wait_status(0x7f), None);
    }
}
