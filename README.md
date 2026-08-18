# CDM

> **Give coding agents room to work—without giving them your whole machine.**

CDM puts a sandbox around an ordinary command. By default, the command can read
host files and write inside the current workspace, but it cannot change files
elsewhere. Add flags when the command should see less—or when it needs access
to one more path.

## Install

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/RogueKernelApps/cdm/releases/latest/download/cdm-install.sh | bash
```

The installer supports macOS 14+ on Apple silicon, Linux x86_64, and Linux
ARM64. It downloads the matching runtime, verifies it against the release's
`SHA256SUMS`, and installs it under `$HOME/.local`. Ensure
`$HOME/.local/bin` is on `PATH`.

This README describes CDM 0.1.5 or newer. Run `cdm version` if `cdm setup` is
not recognized. See [Getting started](GETTING_STARTED.md) for custom prefixes,
version pinning, manual installation, source builds, and artifact verification.

## Set up CDM

After installing or upgrading, select the coding harnesses you use:

```console
$ cdm setup
```

CDM detects Pi, Claude Code, Codex, and Copilot without launching them. Keep the
tools you use selected and press Enter. Their compatibility profiles apply
automatically, and CDM shows every resulting permission when a command starts.
The profiles grant broad write access to harness-owned state; see
[Configuration](#configuration) for narrower alternatives.

## Run a command

Put `cdm` before the command you already use:

```bash
cd ~/my_dev_project/

cdm pi
cdm codex
cdm npm test
```

The command and its arguments pass through unchanged. Use an explicit shell for
shell syntax, for example `cdm sh -c 'npm test | tee test.log'`.

## Try the filesystem sandbox

Create a small example with one project folder and one folder outside it:

```console
$ mkdir -p ~/cdm-demo/workspace ~/cdm-demo/outside
$ printf 'project file\n' > ~/cdm-demo/workspace/project.txt
$ printf 'original\n' > ~/cdm-demo/outside/note.txt
$ cd ~/cdm-demo/workspace
```

The examples below all use this layout:

```text
~/cdm-demo/
├── workspace/              ← project folder; commands start here
│   └── project.txt
└── outside/                ← host data outside the project
    └── note.txt
```

### Plain CDM: write here, read elsewhere

With plain `cdm`, the same tree looks like this to the command:

```text
~/cdm-demo/
├── workspace/              [read/write]
│   └── project.txt
└── outside/                [read-only]
    └── note.txt
```

The command can therefore read `note.txt`:

```console
$ cdm -q cat ../outside/note.txt
original
```

It can also create and change files inside `workspace`:

```console
$ cdm -q sh -c 'printf "created by CDM\n" > result.txt'
$ cat result.txt
created by CDM
```

The project tree now contains the new file:

```text
~/cdm-demo/
├── workspace/              [read/write]
│   ├── project.txt
│   └── result.txt          ← created by the sandboxed command
└── outside/                [read-only]
    └── note.txt            ← still contains "original"
```

An attempt to overwrite `outside/note.txt` is blocked:

```console
$ cdm -q sh -c 'printf "changed\n" > ../outside/note.txt'
sh: ../outside/note.txt: Operation not permitted
$ cat ../outside/note.txt
original
```

The exact denial text varies by platform, but the command exits nonzero and
`note.txt` stays unchanged.

### Grant another writable folder

If the command genuinely needs to update `outside`, grant only that folder with
`-w`:

```text
~/cdm-demo/
├── workspace/              [read/write]
│   ├── project.txt
│   └── result.txt
└── outside/                [read/write via -w]
    └── note.txt
```

```console
$ cdm -q -w ../outside sh -c 'printf "changed\n" > ../outside/note.txt'
$ cat ../outside/note.txt
changed
```

### Hide other host user data

Use `--iso` when the command should not read other host user data:

```text
~/cdm-demo/
├── workspace/              [read/write]
│   ├── project.txt
│   └── result.txt
└── outside/                [hidden; contents not visible]
```

```console
$ cdm -q --iso cat ../outside/note.txt
cat: ../outside/note.txt: Operation not permitted
```

Add `-r` to reveal just that folder as read-only:

```text
~/cdm-demo/
├── workspace/              [read/write]
│   ├── project.txt
│   └── result.txt
└── outside/                [read-only via -r]
    └── note.txt
```

```console
$ cdm -q --iso -r ../outside cat ../outside/note.txt
changed
```

That is the basic CDM model: the project is writable, visible host user data is
read-only, and `--iso`, `-r`, and `-w` let you make the boundary explicit.

## Add only the controls you need

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

### Run inside a microVM

```bash
cdm --vm sh -c 'uname -a'
cdm --vmi ubuntu:24.04 bash
```

`--vm` boots CDM's architecture-matched Alpine guest from a roughly 4 MiB
compressed image embedded in the binary—no image pull, Docker daemon, or VM
setup required. `--vmi` starts from an OCI image instead. Only the workspace
and explicit grants are exposed to the guest.

### Sandbox a macOS application

```bash
cdm "/Applications/Example.app"
```

CDM validates the app bundle and infers narrow, app-owned writable locations
instead of granting broad home-directory access. Selecting the bundle is the
trust decision: CDM does not run Gatekeeper, notarization, or code-signature
checks.

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

## Optional: keep agent changes on a branch

For longer agent sessions in a Git repository, `--worktree` keeps changes out
of your current checkout:

```bash
cdm --worktree claude
```

CDM creates a temporary worktree from the current Git-visible state, runs the
command there, and removes the temporary directory afterward. If the command
changed files, CDM saves them on a generated `CDM__...` branch and prints exact
commands to inspect, merge, open a pull request, or discard it. Your current
branch and working tree do not move. Changes are preserved even when the
wrapped command exits nonzero.

This is optional Git workflow automation, not part of the basic filesystem
sandbox. See [Getting started](GETTING_STARTED.md) for its full lifecycle and
edge cases.

## Configuration

### Management commands

| Command | What it does |
|---|---|
| `cdm setup` | Select detected coding harnesses and refresh their bundled profiles. |
| `cdm config` | Create the editable global config if it does not exist. |
| `cdm project` | Report the discovered project root, kind, and project-config path without trusting it. |
| `cdm trust` | Approve the exact current bytes of the nearest project config. |
| `cdm help` | Show commands and sandbox flags. |
| `cdm version` | Print the installed CDM version. |
| `cdm completions bash` | Generate completion source; `zsh` and `fish` are also supported. |
| `cdm run npm test` | Explicit form of `cdm npm test`; both preserve the wrapped arguments. |

These commands manage or inspect CDM itself. You do not need a global config to
run commands. `cdm config` creates one only when you want custom defaults or
named presets, and it never overwrites an existing file.

### Configuration files

CDM keeps editable policy separate from the state written by `cdm setup` and
`cdm trust`:

| Purpose | Path | Managed by |
|---|---|---|
| Global user policy and named presets | `~/.cdm/config.json` (or `CDM_CONFIG_PATH`) | You; `cdm config` creates the defaults once |
| Nearest project policy | `<project>/.cdm/config.json` | The repository; you approve it with `cdm trust` |
| Setup-selected base policy | `~/.cdm/base.json` | `cdm setup`; imports exactly the selected bundled profiles |
| User-owned reusable profiles | `~/.cdm/profiles/*.json` | You |
| Bundled profile policy | `~/.cdm/profiles/bundled/{pi,claude,codex,copilot}.json` | `cdm setup`; only selected known files are retained |
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
Configuration documents may also import ordered user profiles beneath
`~/.cdm/profiles/`, for example `"import": ["personal.json", "work.json"]`.
Imports expand recursively depth-first and merge left-to-right; the importing
file merges last. Nested names are relative to their importing profile's
directory. A literal `~/.cdm/profiles/...` name is also accepted. Other
absolute, escaping, missing, malformed, unknown-field, linked, unsafe-permission,
or cyclic imports fail before the child starts. Imports from `bundled/` retain
their `[profile:ID]` provenance, so absent optional tool state remains optional
when a user base profile composes bundled profiles.

For example, a reusable stack can be expressed with ordinary JSON files:

**`~/.cdm/profiles/my-base.json`**

```json
{
  "import": [
    "bundled/pi.json",
    "bundled/claude.json",
    "bundled/codex.json"
  ],
  "paths": {
    "allow_ro": [".pi-lens"]
  }
}
```

**`~/.cdm/profiles/work-base.json`**

```json
{
  "import": ["my-base.json"],
  "paths": {
    "allow_ro": [".config/work-tool"]
  }
}
```

The project can then merge that host-owned stack before its own settings:

```json
{
  "import": ["~/.cdm/profiles/work-base.json"],
  "paths": {
    "allow_rw": ["reports"]
  }
}
```

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

Project-relative paths declared directly in this file resolve from the project
root. A project may import only user-owned files under `~/.cdm/profiles/`; paths
from those imports remain `$HOME`-relative. Project configs cannot define
presets. Review the file, including its ordered import names, then approve its
exact bytes:

```bash
cdm project
cdm trust
```

Any byte change requires `cdm trust` again. Each document's `import` entries apply
immediately before that document. Overall precedence is built-in defaults,
managed-base imports and `~/.cdm/base.json`, global imports and global config,
explicitly selected bundled profiles, selected presets, trusted project imports
and project config, then CLI flags.

### Bundled profile setup

Run `cdm setup` after installation or upgrade from an interactive terminal. CDM
structurally detects known harnesses from executable files on `PATH` and fixed
state markers under `$HOME`; it never launches a candidate. The toggle menu
shows only detected `pi`, `claude`, `codex`, and `copilot` entries in catalog
order, initially checked. Confirming materializes only the selected mode-`0600`
bundled JSON files and writes the transparent mode-`0600`
`~/.cdm/base.json`, whose ordered `import` array names exactly those files.
An accepted empty selection writes an empty array and removes known bundled
files. No detections make no change. Escape or `q` cancels with status 2 and no
change; non-terminal use is rejected before mutation.

Setup never rewrites `~/.cdm/config.json` (including a path selected through
`CDM_CONFIG_PATH`), user-owned profiles, unknown bundled files, the trust store,
or unrelated files. A rerun refreshes selected known
files and removes deselected known files. Existing `base.json` must be a private,
recognizable CDM-managed document containing only the exact warning and
catalog-ordered known imports; otherwise setup fails closed before changing
profile state. Each bundled profile contains a valid-JSON `_warning` stating
that upgrades may overwrite it; extend or override it from a user-owned profile
instead of editing it.

Selected profiles apply automatically through `base.json`. `--profile <id>`
remains available for an additional explicit selection, and built-in profile
names remain independent from user preset names:

```bash
cdm pi
cdm --profile claude --preset team-policy claude
cdm --profile codex --profile copilot coding-agent-wrapper
```

There is no opaque enablement registry, migration path, or accepted legacy
schema. CDM never infers policy from the wrapped executable. If a selected
bundled file is missing, invocation fails with an instruction to rerun
`cdm setup` rather than falling back to hidden compiled policy.

Bundled profiles deliberately grant broad read/write access to each selected
harness's owned state: `~/.pi`, `~/.claude` plus `~/.claude.json`,
`~/.codex`, and `~/.copilot` plus its platform cache locations. This avoids
depending on unstable internal filenames or write protocols such as adjacent
lock directories and atomic temporary files. Because setup-selected profiles
apply to every CDM invocation, use a narrower user-owned profile instead when
protecting harness customizations is more important than compatibility. The
shared `~/.agents` customization directory remains read-only for every bundled
profile.

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
SHA-256 digest atomically. The base config, trust store, and bundled profiles use
mode `0600` beneath mode-`0700` setup directories.

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
