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

`--vm` uses CDM's bundled Alpine guest. `--vmi` starts from an OCI image. Only
the workspace and explicit grants are exposed to the guest.

### Let CDM handle the worktree

```bash
cdm --worktree claude
```

**No checkout juggling.** CDM copies the current Git-visible working state into
a temporary worktree, lets the agent edit it, and saves the result on a unique
`CDM__...` branch. The original checkout stays untouched, and useful changes
survive even when the command exits nonzero.

### Add only the controls you need

| Command | Outcome |
|---|---|
| `cdm --ro claude` | Let the agent inspect the project without changing it. |
| `cdm --iso --ro ./untrusted-checker` | Hide other host user data and make the project read-only. |
| `cdm --no-network python3 ./project_acme/audit.py` | Run a script without network access. |
| `cdm --sec claude` | Apply CDM's one-flag hardened baseline. |
| `cdm --sec --worktree claude` | Combine the hardened baseline with an isolated Git workflow. |
| `cdm --sec --iso --ro --no-network ./untrusted-checker` | Compose the strongest native controls for a potentially hostile command. |

Need to expose one specific path? Start isolated, then grant only what the tool
needs:

```bash
cdm --iso \
  --allow-ro ~/.config/tool \
  --allow-rw ./project_acme/output \
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

`cdm config` creates `~/.cdm/config.json`. CDM also discovers the nearest
project `.cdm/config.json`, but ignores it until its exact bytes are approved
with `cdm trust`. `cdm project` reports the discovered project without granting
access. Repeat `--preset <name>` to apply named global presets.

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
- [Agent instructions](AGENTS.md) — repository contribution constraints for coding agents

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
