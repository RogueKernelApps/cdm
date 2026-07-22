# CDM

> **Give coding agents room to work—without giving them your whole machine.**

CDM runs developer commands inside a host-native sandbox or an optional
libkrun microVM. Put `cdm` before an ordinary command, then add filesystem,
network, secret, or Git-worktree isolation when the command needs it.

## Start with any command

```bash
cd ~/my_dev_project/

cdm copilot --allow-all
cdm pi
cdm claude
```

The command after `cdm` keeps its original argument boundaries. In the first
example, `--allow-all` is passed to Copilot—not interpreted by CDM. The same
pattern works with package managers, test runners, scripts, and other developer
tools:

```bash
cdm npm test
cdm python3 ./project_acme/audit.py
```

### Run inside a microVM

```bash
cdm --vm sh -c 'uname -a'
cdm --vmi ubuntu:24.04 bash
```

`--vm` boots CDM's architecture-matched Alpine guest from a roughly 4 MiB
compressed image embedded in the binary—no image pull, Docker daemon, or VM
setup required. `--vmi` starts from an OCI image instead. Only the workspace
and explicit grants are exposed to the guest.

### Let CDM handle the worktree

Start on your normal branch:

```console
$ cd ~/projects/hello-world
$ git branch --list
* main
```

Then give an agent a disposable worktree:

```console
$ cdm --worktree claude

cdm
├─ Sandbox:
│  └─ Backend:          "seatbelt"   macOS native sandbox
│                                  flags: `--vm | --vmi IMAGE`            [default]
├─ File permissions:
│  ├─ Global:           "ro"         Host readable; writes need a grant
│  │                               flags: `--iso | -w PATH`               [default]
│  ├─ Workspace:        "rw"         Project files are writable
│  │                               flags: `--ro`                          [default]
│  ├─ Read-only grants:  "none"                                       [default]
│  └─ Read/write grants: "none"                                       [default]
├─ Network:
│  └─ Mode:             "direct"     Unrestricted host network
│                                  flags: `--no-network | --scramble`     [default]
├─ Secrets:
│  └─ Mode:             "unchanged"  Passed through as-is
│                                  flags: `--scramble | --sec`            [default]
├─ Security:
│  └─ Persistence:      "standard"   Normal sandbox protections
│                                  flags: `--sec`                         [default]
├─ Worktree:
│  └─ Mode:             "active"     Save changes to a new branch
│                                  flags: `--worktree`                    [cli]
└─ Run:                 "1 arg"      Arguments hidden

> Make a HELLO_WORLD.md file in this folder.

Created HELLO_WORLD.md.

> /quit

cdm done
├─ Exit:
│  └─ Status:           "success"    Command exited with code 0
├─ Worktree:
│  ├─ Result:           "saved"      Changes preserved on a branch
│  ├─ Branch:           `CDM__2026-07-22__hello-world__developer`
│  └─ Changes:          "1 file"     +1 -0
└─ Next steps:
   ├─ Inspect:          `git diff bafb04e..CDM__2026-07-22__hello-world__developer`
   ├─ Merge:            `git merge CDM__2026-07-22__hello-world__developer`
   ├─ Open PR:          `gh pr create --head CDM__2026-07-22__hello-world__developer`
   └─ Discard:          `git branch -D CDM__2026-07-22__hello-world__developer`
```

CDM removes the temporary worktree. Your checkout never moved, and the agent's
changes are waiting on their own branch:

```console
$ git branch --list
  CDM__2026-07-22__hello-world__developer
* main
```

**No checkout juggling—and no lost work.** CDM starts from the current
Git-visible state, and it preserves useful changes even when the agent exits
nonzero. Generated branch names include the date, project, and user, so yours
will differ from the example above.

CDM keeps these trees scannable by putting resolved values in speech marks and
terminal literals—flags, paths, branches, and commands—inside backticks.

### Add only the controls you need

| Command | Outcome |
|---|---|
| `cdm --ro claude` | Let the agent inspect the project without changing it. |
| `cdm --iso --ro ./untrusted-checker` | Hide other host user data and make the project read-only. |
| `cdm --no-network python3 ./project_acme/audit.py` | Run a script without network access. |
| `cdm --sec claude` | Apply CDM's one-flag hardened baseline. |
| `cdm --sec --worktree claude` | Combine the hardened baseline with an isolated Git workflow. |
| `cdm --sec --iso --ro --no-network ./untrusted-checker` | Compose the strongest native controls for a potentially hostile command. |
| `cdm -q npm test` | Hide routine CDM status while preserving command output and errors. |

Need to expose one specific path? Start isolated, then grant only what the tool
needs:

```bash
cdm --iso \
  -r ~/.config/tool \
  -w ./project_acme/output \
  tool
```

### Sandbox a macOS application

```bash
cdm "/Applications/Example.app"
```

CDM validates the app bundle and infers narrow, app-owned writable locations
instead of granting broad home-directory access. Selecting the bundle is the
trust decision: CDM does not run Gatekeeper, notarization, or code-signature
checks.

## Install

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/RogueKernelApps/cdm/releases/latest/download/cdm-install.sh | bash
```

The installer supports macOS 14+ on Apple silicon, Linux x86_64, and Linux
ARM64. It downloads the matching runtime, verifies it against the release's
`SHA256SUMS`, and installs it under `$HOME/.local`. Ensure
`$HOME/.local/bin` is on `PATH`.

Set `CDM_INSTALL_PREFIX` to choose another prefix or `CDM_INSTALL_VERSION` to
pin a release. See [Getting started](GETTING_STARTED.md) for manual installation,
version pinning, source builds, and artifact verification, or open the
[latest release](https://github.com/RogueKernelApps/cdm/releases/latest).

## Security

> [!WARNING]
> Plain `cdm command` prioritizes compatibility: the workspace is writable,
> other host user data is readable, networking is direct, and secrets are
> unchanged. It mainly prevents accidental writes outside the project; it is
> not an appropriate boundary for hostile code.

CDM's controls compose. The table shows what each control changes when added to
the defaults:

| Control | Workspace | Other host data | Network | Secrets | Additional effect |
|---|---|---|---|---|---|
| plain `cdm` | read/write | readable | direct | unchanged | Prevents writes outside allowed roots. |
| `--ro` | read-only | readable | direct | unchanged | Protects project files. |
| `--iso` | read/write | hidden except grants | direct | unchanged | Uses an isolated host-data policy. |
| `--no-network` | read/write | readable | disabled | unchanged | Removes network access. |
| `--scramble` | read/write | readable | proxied by default | fake in child | Hides and stages known credential files. |
| `--sec` | read/write | readable | proxied by default | fake in child | Implies `--scramble` and adds persistence protections. |
| `--vm` / `--vmi` | guest sees workspace and grants | not exposed to guest | follows selected policy | unchanged unless scrambling is selected | Adds stronger process and daemon containment. |

`--sec` is the easy one-flag baseline for riskier tools: it combines secret
scrambling, persistence protections, and the deny-first macOS capability
baseline. It does **not** imply `--ro`, `--iso`, or `--no-network`; add those
when the command should not write the project, read other host data, or use the
network.

With `--scramble` or `--sec`, the child receives stable fake secrets. Real
mappings stay in the trusted host process and CDM's fail-closed HTTP(S) proxy
restores them only for authorized destinations. Use an allowlist for a strict
destination set:

```bash
cdm --scramble \
  --allow-domains registry.npmjs.org \
  npm install
```

`--no-proxy` keeps direct networking while scrambling, but disables secret
restoration and domain filtering. The command preflight is only accident
prevention; filesystem, network, and VM controls provide the enforceable
boundaries.

## Configuration

CDM keeps editable policy separate from the state written by `cdm setup` and
`cdm trust`:

| Purpose | Path | Managed by |
|---|---|---|
| Global user policy and named presets | `~/.cdm/config.json` (or `CDM_CONFIG_PATH`) | You; `cdm config` creates the defaults once |
| Nearest project policy | `<project>/.cdm/config.json` | The repository; you approve it with `cdm trust` |
| Enabled built-in profile IDs | `~/.cdm/setup-profiles.json` | `cdm setup` |
| Approved project-config digests | `~/.cdm/trusted-projects.json` | `cdm trust` |

### Global and project policy

`cdm config` creates `~/.cdm/config.json` without overwriting an existing file.
On first use it creates the private `~/.cdm` policy directory with mode `0700`.
The generated file contains every default; a hand-edited file may contain only
the sections it changes. For example:

**`~/.cdm/config.json`** (excerpt)

```json
{
  "paths": {
    "allow_ro": [".config/team-tool"],
    "allow_rw": ["work-output"]
  },
  "presets": {
    "team-policy": {
      "secrets": {
        "restore_destinations": {
          "INTERNAL_API_TOKEN": ["api.internal.example"]
        }
      }
    }
  }
}
```

Global and preset relative paths resolve from `$HOME`. Explicit path targets
must already exist. Repeat `--preset <name>` to apply named global presets.

A repository can add narrower, shared policy in its nearest project config:

**`<project>/.cdm/config.json`** (excerpt)

```json
{
  "paths": {
    "allow_ro": ["docs"],
    "allow_rw": ["reports"]
  }
}
```

Project-relative paths resolve from the project root, and project configs
cannot define presets. Review the file, then approve its exact bytes:

```bash
cdm project
cdm trust
```

Any byte change requires `cdm trust` again. Policy precedence is built-in
defaults, global config, explicitly selected profiles, selected presets,
trusted project config, then CLI flags.

### Guided profile setup

Run `cdm setup` in an interactive terminal after installation. It detects Pi,
Claude Code, OpenAI Codex CLI, and GitHub Copilot CLI from executables and known
state markers without executing those tools. Use the arrow keys to move, Space
to toggle, and Enter to save; Escape or `q` cancels without changing the prior
selection. All detected tools start selected.

Setup saves IDs—not profile policy—and never rewrites the global config:

**`~/.cdm/setup-profiles.json`** (CDM-managed excerpt)

```json
{
  "version": 1,
  "enabled_profile_ids": ["claude", "pi"]
}
```

The available IDs are `pi`, `claude`, `codex`, and `copilot`. Enabling one only
makes it available; CDM never infers a profile from the wrapped executable.
Apply profiles explicitly, repeating `--profile` when they should compose:

```bash
cdm --profile pi pi
cdm --profile claude --preset team-policy claude
cdm --profile codex --profile copilot coding-agent-wrapper
```

Built-in profile names and user preset names are independent. Rerun `cdm setup`
to change the enabled list; clearing every checkbox and pressing Enter disables
all detected profiles.

For completeness, trusting a project updates the other managed state file:

**`~/.cdm/trusted-projects.json`** (CDM-managed excerpt)

```json
{
  "version": 1,
  "projects": {
    "/Users/alex/src/acme/.cdm/config.json": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }
}
```

Do not add entries by hand: `cdm trust` records the canonical config path and
SHA-256 digest atomically. Both managed files use mode `0600` and live under the
mode-`0700` `~/.cdm` directory.

## Reports and monitoring

```bash
cdm --report-json .cdm-session.json --stats npm test
cdm --monitor npm test
```

Reports contain bounded, redacted policy and lifecycle data—not arguments,
paths, domains, environment values, or secret material. `--monitor` streams
platform sandbox denials and fails closed if monitoring cannot start.

## Documentation

- [Getting started](GETTING_STARTED.md) — detailed installation and usage
- [Architecture](ARCHITECTURE.md) — runtime boundaries and trust model
- [Specification](specs/SPEC.md) — normative behavior
- [Dependencies](DEPENDENCIES.md) — pinned runtime and vendored dependency notes
- [Test organization](rust/tests/README.md) — unit and integration coverage
- [Packaging](rust/packaging/README.md) — release and corresponding-source runbook
- [Security policy](SECURITY.md) — supported scope and private reporting
- [Future work](FUTURE.md) — known gaps and planned work
- [Agent instructions](./AGENTS.md) — repository contribution constraints for coding agents

## Build and release status

The native build requires Rust 1.88 or newer:

```bash
cd rust
cargo build --release
cargo test --all-targets
```

VM feature compilation requires libkrun 1.19 or newer and verified guest-init
inputs. Build a runnable, signed local VM package with:

```bash
cd rust
./packaging/package.sh runtime
```

Production releases are built and tested on target-native macOS AArch64, Linux
x86_64, and Linux AArch64 runners. See the
[packaging and release runbook](rust/packaging/README.md) for signing, testing,
and source-distribution requirements.

CDM is licensed under the [MIT License](LICENSE).
