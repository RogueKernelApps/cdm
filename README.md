# CDM

CDM runs developer commands inside a host-native sandbox (Apple Seatbelt on
macOS or Bubblewrap on Linux) or an optional libkrun microVM. It can restrict
filesystem and network access, substitute fake values for detected secrets,
and restore real values only through a per-invocation HTTP(S) proxy.

> [!WARNING]
> CDM's defaults prioritize compatibility, not strong isolation. By default the
> workspace is writable, other host user data is readable, networking is
> direct, and secrets are unchanged. This is useful for preventing accidental
> writes outside a project, but it is not an appropriate boundary for hostile
> code. Use the hardening flags below when the command is not trusted.

## Quick start

```bash
cd rust
cargo build --release
./target/release/cdm npm test
```

CDM preserves argument boundaries exactly; it never joins or reparses argv.
Request shell syntax explicitly when needed:

```bash
cdm sh -c 'printf "%s\n" "$HOME" | sort'
```

## Features

| Feature | Command | What it does |
|---|---|---|
| Default sandbox | `cdm npm test` | Workspace read/write, other host data read-only, direct network |
| Read-only workspace | `cdm --ro npm test` | Prevents the command from changing project files |
| Host-data isolation | `cdm --iso --ro ./tool` | Hides host user data except the workspace and explicit grants |
| Explicit grants | `cdm --iso --allow-ro ~/.config/tool --allow-rw ./output tool` | Reopens only the named paths |
| No network | `cdm --no-network python3 script.py` | Denies network access |
| Secret scrambling | `cdm --scramble npm install` | Replaces detected secrets with stable-per-invocation fakes and uses the fail-closed proxy |
| Destination policy | `cdm --scramble --allow-domains registry.npmjs.org npm install` | Restricts proxied egress to an allowlist |
| Direct network while scrambling | `cdm --scramble --no-proxy tool` | Keeps fake values but disables restoration and domain filtering |
| Hardened mode | `cdm --sec ./untrusted-checker` | Implies scrambling and adds persistence protections; uses deny-first capabilities on macOS |
| Temporary Git worktree | `cdm --worktree agent` | Runs in an isolated worktree and saves changes to a generated `CDM__...` branch |
| macOS application mode | `cdm "/Applications/Example.app"` | Validates the bundle and infers narrow app-owned writable paths |
| Session report | `cdm --report-json .cdm-session.json --stats npm test` | Writes a redacted JSON report and compact stderr statistics |
| Denial monitor | `cdm --monitor npm test` | Streams platform sandbox denials; setup is fail-closed |
| MicroVM | `cdm --vm echo hello` | Uses the bundled Alpine guest in a VM-enabled package |
| OCI guest | `cdm --vmi ubuntu:24.04 bash` | Runs with an OCI image in a VM-enabled package |
| Shell completion | `cdm completions zsh > ~/.zfunc/_cdm` | Generates completion from the typed CLI |

Typical startup output summarizes the selected controls without printing the
wrapped arguments or secret values:

```text
[cdm] sandbox: seatbelt (darwin)
[cdm] network: proxied (port 18080, MITM)
[cdm] running: <2 argv entries>
```

## Choosing a security level

The controls are separate so you can apply only what a command needs:

- `--ro` protects the workspace from writes.
- `--iso` hides other host user data and, on macOS, requires a deny-first
  capability profile.
- `--no-network` removes network access.
- `--scramble` discovers secrets, hides known credential files, substitutes
  fake values, and normally enables the fail-closed proxy. Proxied mode also
  uses the deny-first macOS capability baseline. Add `--no-proxy` only when
  direct networking is required and secret restoration/domain filtering are
  not.
- `--sec` implies `--scramble` and adds hard write denials for shell profiles,
  Git and SSH control files, cron state, agent/editor hooks, and active control
  files at the workspace root.
- `--vm` or `--vmi` provides stronger process and daemon containment than the
  native adapters.

These controls are not all defaults because deny-first macOS policy can break
desktop/WebKit applications, proxy interception is incompatible with some
protocols and certificate-pinning schemes, read-only workspaces break normal
build/install workflows, and VMs require additional runtime support. Choose
compatibility deliberately; do not mistake it for confinement.

The preflight command guard is only an accident-prevention convenience. A
child can launch another executable after startup. Use filesystem, network,
and VM controls for enforcement.

## Configuration

`cdm config` creates `~/.cdm/config.json`. CDM also discovers the nearest
project `.cdm/config.json`, but ignores it until its exact bytes are approved
with `cdm trust`. `cdm project` reports the discovered project without granting
access. Named global presets are selected with repeatable `--preset <name>`.

See [Getting started](GETTING_STARTED.md) for installation, configuration,
examples, and integration testing.

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

Target-native packaged-VM and Linux release acceptance is not yet complete.
Do not present source publication or compile-only CI as proof that production
VM binaries are ready. Remaining work is tracked in
[`rust/guest-init/INTEGRATION.md`](rust/guest-init/INTEGRATION.md) and
[FUTURE.md](FUTURE.md).

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

CDM is licensed under the [MIT License](LICENSE).
