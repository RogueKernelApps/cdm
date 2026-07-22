//! Compact, quiet-aware presentation for routine invocation status.

use std::io::{self, Write};

use crate::{
    access::{self, ResolvedGrant},
    network,
    origin::{terminal_safe, Origin},
    sandbox, worktree,
};

#[derive(Clone, Copy)]
pub struct Status {
    quiet: bool,
}

pub struct Detail {
    pub label: String,
    pub value: String,
    pub summary: String,
    pub origin: Origin,
}

#[derive(Clone)]
pub struct StartupOrigins {
    pub backend: Origin,
    pub global: Origin,
    pub workspace: Origin,
    pub network: Origin,
    pub secrets: Origin,
    pub security: Origin,
    pub worktree: Origin,
}

impl Default for StartupOrigins {
    fn default() -> Self {
        Self {
            backend: Origin::Default,
            global: Origin::Default,
            workspace: Origin::Default,
            network: Origin::Default,
            secrets: Origin::Default,
            security: Origin::Default,
            worktree: Origin::Default,
        }
    }
}

impl Status {
    pub fn new(quiet: bool) -> Self {
        Self { quiet }
    }

    pub fn startup(
        &self,
        cfg: &sandbox::SandboxConfig,
        resolved: &access::ResolvedAccessPolicy,
        worktree: bool,
        details: &[Detail],
        origins: &StartupOrigins,
    ) {
        if !self.quiet {
            let _ = write_startup(
                &mut io::stderr().lock(),
                cfg,
                resolved,
                worktree,
                details,
                origins,
            );
        }
    }

    pub fn worktree_result(&self, result: &worktree::WorktreeResult, exit_code: i32) {
        if !self.quiet {
            let _ = write_worktree_result(&mut io::stderr().lock(), result, exit_code);
        }
    }

    pub fn failure(&self, exit_code: i32) {
        if !self.quiet {
            let _ = write_failure(&mut io::stderr().lock(), exit_code);
        }
    }
}

fn write_startup(
    writer: &mut impl Write,
    cfg: &sandbox::SandboxConfig,
    resolved: &access::ResolvedAccessPolicy,
    worktree: bool,
    details: &[Detail],
    origins: &StartupOrigins,
) -> io::Result<()> {
    writeln!(writer, "cdm")?;

    let (sandbox_value, sandbox_summary) = if cfg.use_vm {
        match cfg.vm_image.as_deref() {
            Some(image) => ("libkrun", format!("OCI guest {image}")),
            None => ("libkrun", "Bundled Alpine microVM".to_string()),
        }
    } else if cfg!(target_os = "macos") {
        ("seatbelt", "macOS native sandbox".to_string())
    } else {
        ("bubblewrap", "Linux native sandbox".to_string())
    };
    writeln!(writer, "├─ Sandbox:")?;
    setting(writer, "│  └─", "Backend:", sandbox_value, &sandbox_summary)?;
    flag_line(writer, "│", "--vm | --vmi IMAGE", &origins.backend)?;

    let workspace_summary = match cfg.access.workspace {
        access::WorkspaceAccess::ReadWrite => "Project files are writable",
        access::WorkspaceAccess::ReadOnly => "Project files are read-only",
    };
    writeln!(writer, "├─ File permissions:")?;
    let (global_value, global_summary) = match cfg.access.host {
        access::HostAccess::Normal => ("ro", "Host readable; writes need a grant"),
        access::HostAccess::Isolated => ("isolated", "Host hidden; explicit grants only"),
    };
    setting(writer, "│  ├─", "Global:", global_value, global_summary)?;
    flag_line(writer, "│  │", "--iso | -w PATH", &origins.global)?;
    setting(
        writer,
        "│  ├─",
        "Workspace:",
        cfg.access.workspace.label(),
        workspace_summary,
    )?;
    flag_line(writer, "│  │", "--ro", &origins.workspace)?;
    render_grants(
        writer,
        "Read-only grants:",
        &resolved.allow_ro_grants,
        false,
        &cfg.home_dir,
        &cfg.work_dir,
    )?;
    render_grants(
        writer,
        "Read/write grants:",
        &resolved.allow_rw_grants,
        true,
        &cfg.home_dir,
        &cfg.work_dir,
    )?;

    let (network_value, network_summary) = match cfg.network {
        network::NetworkPolicy::Disabled => ("disabled", "No network access"),
        network::NetworkPolicy::Direct => ("direct", "Unrestricted host network"),
        network::NetworkPolicy::Proxied(_) => ("proxied", "Policy-filtered network"),
    };
    writeln!(writer, "├─ Network:")?;
    setting(writer, "│  └─", "Mode:", network_value, network_summary)?;
    flag_line(writer, "│", "--no-network | --scramble", &origins.network)?;

    if let Some(domains) = cfg.network.domains() {
        let allowed = domains.allowed_display();
        let denied = domains.denied_display();
        if !allowed.is_empty() {
            sourced_setting(
                writer,
                "│  ├─",
                "Allowed domains:",
                &allowed,
                &origins.network,
            )?;
        }
        if !denied.is_empty() {
            sourced_setting(
                writer,
                "│  ├─",
                "Denied domains:",
                &denied,
                &origins.network,
            )?;
        }
    }

    let (secrets_value, secrets_summary) = if cfg.scramble {
        (
            "scrambled",
            format!(
                "{} values, {} env, {} paths",
                cfg.secrets.fake_to_real.len(),
                cfg.injected_env.len(),
                cfg.denied_read_paths.len()
            ),
        )
    } else {
        ("unchanged", "Passed through as-is".to_string())
    };
    writeln!(writer, "├─ Secrets:")?;
    setting(writer, "│  └─", "Mode:", secrets_value, &secrets_summary)?;
    flag_line(writer, "│", "--scramble | --sec", &origins.secrets)?;

    writeln!(writer, "├─ Security:")?;
    setting(
        writer,
        "│  └─",
        "Persistence:",
        if cfg.secure { "hardened" } else { "standard" },
        if cfg.secure {
            "Deny-first persistence protections"
        } else {
            "Normal sandbox protections"
        },
    )?;
    flag_line(writer, "│", "--sec", &origins.security)?;

    for detail in details {
        sourced_setting(
            writer,
            "├─",
            &format!("{}:", detail.label),
            &detail.value,
            &detail.origin,
        )?;
        if !detail.summary.is_empty() {
            writeln!(writer, "│  {}", terminal_safe(&detail.summary))?;
        }
    }

    writeln!(writer, "├─ Worktree:")?;
    setting(
        writer,
        "│  └─",
        "Mode:",
        if worktree { "active" } else { "off" },
        if worktree {
            "Save changes to a new branch"
        } else {
            "Run in the current checkout"
        },
    )?;
    flag_line(writer, "│", "--worktree", &origins.worktree)?;

    let argument_count = cfg.command.len();
    writeln!(
        writer,
        "└─ {:<21}{:<13}Arguments hidden",
        "Run:",
        quoted_value(&format!(
            "{} {}",
            argument_count,
            if argument_count == 1 { "arg" } else { "args" }
        )),
    )?;
    writeln!(writer)
}

fn setting(
    writer: &mut impl Write,
    connector: &str,
    label: &str,
    value: &str,
    summary: &str,
) -> io::Result<()> {
    writeln!(
        writer,
        "{connector} {:<18}{:<13}{}",
        terminal_safe(label),
        quoted_value(value),
        terminal_safe(summary)
    )
}

fn flag_line(
    writer: &mut impl Write,
    connector: &str,
    flags: &str,
    origin: &Origin,
) -> io::Result<()> {
    let padding = 35usize.saturating_sub(connector.chars().count());
    let display = format!("flags: {}", code_value(flags));
    writeln!(
        writer,
        "{connector}{:padding$}{display:<39}{}",
        "",
        origin.tag()
    )
}

fn sourced_setting(
    writer: &mut impl Write,
    connector: &str,
    label: &str,
    value: &str,
    origin: &Origin,
) -> io::Result<()> {
    writeln!(
        writer,
        "{connector} {:<19}{:<45}{}",
        terminal_safe(label),
        quoted_value(value),
        origin.tag()
    )
}

fn render_grants(
    writer: &mut impl Write,
    label: &str,
    grants: &[ResolvedGrant],
    last: bool,
    home: &std::path::Path,
    workspace: &std::path::Path,
) -> io::Result<()> {
    let connector = if last { "│  └─" } else { "│  ├─" };
    if grants.is_empty() {
        return sourced_setting(writer, connector, label, "none", &Origin::Default);
    }

    let count = format!(
        "{} {}",
        grants.len(),
        if grants.len() == 1 { "path" } else { "paths" }
    );
    let mut tags = Vec::new();
    for grant in grants {
        for origin in &grant.origins {
            let tag = origin.tag();
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
    }
    writeln!(
        writer,
        "{connector} {label:<19}{:<45}{}",
        quoted_value(&count),
        tags.join(" ")
    )?;
    let rail = if last { "│     " } else { "│  │  " };
    for (index, grant) in grants.iter().enumerate() {
        let branch = if index + 1 == grants.len() {
            "└─"
        } else {
            "├─"
        };
        let path = display_path(&grant.path, home, workspace);
        let display = if grant.evidence.is_empty() {
            path
        } else {
            format!("{path} ({})", grant.evidence.join(", "))
        };
        let tags = grant
            .origins
            .iter()
            .map(Origin::tag)
            .collect::<Vec<_>>()
            .join(" ");
        writeln!(
            writer,
            "{rail}{branch} {:<61}{}",
            code_value(&display),
            tags
        )?;
    }
    Ok(())
}

fn display_path(
    path: &std::path::Path,
    home: &std::path::Path,
    workspace: &std::path::Path,
) -> String {
    if path == workspace {
        return "$WORKSPACE".to_string();
    }
    if let Ok(relative) = path.strip_prefix(workspace) {
        return terminal_safe(&format!("$WORKSPACE/{}", relative.display()));
    }
    if path == home {
        return "~".to_string();
    }
    if let Ok(relative) = path.strip_prefix(home) {
        return terminal_safe(&format!("~/{}", relative.display()));
    }
    terminal_safe(&path.display().to_string())
}

fn write_worktree_result(
    writer: &mut impl Write,
    result: &worktree::WorktreeResult,
    exit_code: i32,
) -> io::Result<()> {
    writeln!(writer, "cdm done")?;
    writeln!(writer, "├─ Exit:")?;
    completion_status(writer, "│  └─", exit_code)?;

    match result {
        worktree::WorktreeResult::NoChanges => {
            writeln!(writer, "└─ Worktree:")?;
            setting(
                writer,
                "   └─",
                "Result:",
                "clean",
                "Temporary worktree removed",
            )
        }
        worktree::WorktreeResult::Committed {
            branch,
            base_commit,
            files_changed,
            insertions,
            deletions,
        } => {
            writeln!(writer, "├─ Worktree:")?;
            setting(
                writer,
                "│  ├─",
                "Result:",
                "saved",
                "Changes preserved on a branch",
            )?;
            writeln!(writer, "│  ├─ {:<18}{}", "Branch:", code_value(branch))?;
            setting(
                writer,
                "│  └─",
                "Changes:",
                &format!(
                    "{} {}",
                    files_changed,
                    if *files_changed == 1 { "file" } else { "files" }
                ),
                &format!("+{insertions} -{deletions}"),
            )?;
            writeln!(writer, "└─ Next steps:")?;
            let short_base = &base_commit[..base_commit.len().min(7)];
            completion_command(
                writer,
                "   ├─",
                "Inspect:",
                &format!("git diff {short_base}..{branch}"),
            )?;
            completion_command(writer, "   ├─", "Merge:", &format!("git merge {branch}"))?;
            completion_command(
                writer,
                "   ├─",
                "Open PR:",
                &format!("gh pr create --head {branch}"),
            )?;
            completion_command(
                writer,
                "   └─",
                "Discard:",
                &format!("git branch -D {branch}"),
            )
        }
    }
}

fn write_failure(writer: &mut impl Write, exit_code: i32) -> io::Result<()> {
    writeln!(writer, "cdm done")?;
    writeln!(writer, "└─ Exit:")?;
    completion_status(writer, "   └─", exit_code)
}

fn completion_status(writer: &mut impl Write, connector: &str, exit_code: i32) -> io::Result<()> {
    setting(
        writer,
        connector,
        "Status:",
        if exit_code == 0 { "success" } else { "failed" },
        &format!("Command exited with code {exit_code}"),
    )
}

fn completion_command(
    writer: &mut impl Write,
    connector: &str,
    label: &str,
    command: &str,
) -> io::Result<()> {
    writeln!(
        writer,
        "{connector} {:<18}{}",
        terminal_safe(label),
        code_value(command)
    )
}

fn quoted_value(value: &str) -> String {
    format!("\"{}\"", terminal_safe(value).replace('"', "\\\""))
}

fn code_value(value: &str) -> String {
    format!("`{}`", terminal_safe(value).replace('`', "\\`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use std::sync::Arc;

    #[test]
    fn startup_renders_resolved_core_modes_without_argv_values() {
        let mut cfg = sandbox::SandboxConfig::new(Arc::new(config::CdmConfig::default())).unwrap();
        cfg.command = vec!["echo".into()];
        let resolved = cfg.freeze_access().unwrap().clone();
        let mut output = Vec::new();

        write_startup(
            &mut output,
            &cfg,
            &resolved,
            false,
            &[],
            &StartupOrigins::default(),
        )
        .unwrap();

        let (backend, backend_summary) = if cfg!(target_os = "macos") {
            ("seatbelt", "macOS native sandbox")
        } else {
            ("bubblewrap", "Linux native sandbox")
        };
        let backend_value = quoted_value(backend);

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("flags: `--vm | --vmi IMAGE`"));
        assert_eq!(
            output,
            format!(
                "cdm\n\
             ├─ Sandbox:\n\
             │  └─ Backend:          {backend_value:<13}{backend_summary}\n\
             │                                  flags: `--vm | --vmi IMAGE`            [default]\n\
             ├─ File permissions:\n\
             │  ├─ Global:           \"ro\"         Host readable; writes need a grant\n\
             │  │                               flags: `--iso | -w PATH`               [default]\n\
             │  ├─ Workspace:        \"rw\"         Project files are writable\n\
             │  │                               flags: `--ro`                          [default]\n\
             │  ├─ Read-only grants:  \"none\"                                       [default]\n\
             │  └─ Read/write grants: \"none\"                                       [default]\n\
             ├─ Network:\n\
             │  └─ Mode:             \"direct\"     Unrestricted host network\n\
             │                                  flags: `--no-network | --scramble`     [default]\n\
             ├─ Secrets:\n\
             │  └─ Mode:             \"unchanged\"  Passed through as-is\n\
             │                                  flags: `--scramble | --sec`            [default]\n\
             ├─ Security:\n\
             │  └─ Persistence:      \"standard\"   Normal sandbox protections\n\
             │                                  flags: `--sec`                         [default]\n\
             ├─ Worktree:\n\
             │  └─ Mode:             \"off\"        Run in the current checkout\n\
             │                                  flags: `--worktree`                    [default]\n\
             └─ Run:                 \"1 arg\"      Arguments hidden\n\n"
            )
        );
    }

    #[test]
    fn startup_abbreviates_resolved_grants_and_shows_their_source() {
        let mut cfg = sandbox::SandboxConfig::new(Arc::new(config::CdmConfig::default())).unwrap();
        cfg.command = vec!["true".into()];
        cfg.access.add_allow_rw(cfg.work_dir.clone());
        let resolved = cfg.freeze_access().unwrap().clone();
        let mut output = Vec::new();

        write_startup(
            &mut output,
            &cfg,
            &resolved,
            false,
            &[],
            &StartupOrigins::default(),
        )
        .unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Read/write grants:"));
        assert!(output.contains("1 path"));
        assert!(output.contains("└─ `$WORKSPACE`"));
        assert!(output.contains("[cli]"));
        assert!(!output.contains(&cfg.work_dir.display().to_string()));
    }

    #[test]
    fn displayed_paths_escape_terminal_controls() {
        let home = std::path::Path::new("/home/user");
        let workspace = home.join("project");

        assert_eq!(
            display_path(&workspace.join("bad\n\u{1b}[2J"), home, &workspace),
            "$WORKSPACE/bad\\n\\u{1b}[2J"
        );
    }

    #[test]
    fn displayed_values_cannot_break_their_visual_delimiters() {
        assert_eq!(quoted_value("bad\"\nvalue"), "\"bad\\\"\\nvalue\"");
        assert_eq!(code_value("bad`\nvalue"), "`bad\\`\\nvalue`");
    }

    #[test]
    fn committed_worktree_renders_one_completion_tree() {
        let mut output = Vec::new();
        write_worktree_result(
            &mut output,
            &worktree::WorktreeResult::Committed {
                branch: "CDM__2026-03-25__project__user".to_string(),
                base_commit: "0123456789abcdef".to_string(),
                files_changed: 3,
                insertions: 10,
                deletions: 2,
            },
            23,
        )
        .unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Status:           \"failed\""));
        assert!(output.contains("Merge:            `git merge CDM__2026-03-25__project__user`"));
        assert_eq!(
            output,
            concat!(
                "cdm done\n",
                "├─ Exit:\n",
                "│  └─ Status:           \"failed\"     Command exited with code 23\n",
                "├─ Worktree:\n",
                "│  ├─ Result:           \"saved\"      Changes preserved on a branch\n",
                "│  ├─ Branch:           `CDM__2026-03-25__project__user`\n",
                "│  └─ Changes:          \"3 files\"    +10 -2\n",
                "└─ Next steps:\n",
                "   ├─ Inspect:          `git diff 0123456..CDM__2026-03-25__project__user`\n",
                "   ├─ Merge:            `git merge CDM__2026-03-25__project__user`\n",
                "   ├─ Open PR:          `gh pr create --head CDM__2026-03-25__project__user`\n",
                "   └─ Discard:          `git branch -D CDM__2026-03-25__project__user`\n",
            )
        );
    }

    #[test]
    fn failed_command_renders_a_completion_tree_without_a_worktree() {
        let mut output = Vec::new();
        write_failure(&mut output, 7).unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            concat!(
                "cdm done\n",
                "└─ Exit:\n",
                "   └─ Status:           \"failed\"     Command exited with code 7\n",
            )
        );
    }
}
