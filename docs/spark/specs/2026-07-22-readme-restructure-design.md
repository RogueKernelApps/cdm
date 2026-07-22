# README restructure design

## Goal

Make the CDM README immediately useful and persuasive to developers running AI coding agents, while remaining clear that CDM can wrap any developer command. The opening should balance productive agent autonomy with protection of the developer's machine.

## Audience and promise

The primary audience is developers who run Copilot, Pi, Claude, and similar coding agents locally. The secondary audience is any developer who wants to contain an unfamiliar or untrusted command.

Lead with this idea:

> Give coding agents room to work—without giving them your whole machine.

Follow with a two- or three-sentence overview: CDM places a host-native sandbox or optional microVM around an ordinary command, preserves argv boundaries, and lets the caller add filesystem, network, secret, and Git-worktree controls as needed.

## Information hierarchy

The README should use this order:

1. Promise and quick overview
2. Easy-to-advanced usage examples
3. Installation
4. Security model and control matrix
5. Configuration, reporting, and monitoring
6. Deeper documentation links
7. Build and contributor information

Detailed release mechanics and exhaustive usage belong in `GETTING_STARTED.md` or the existing specialist documents rather than interrupting the README's first-use path.

## Example progression

### Start with ordinary agent commands

Begin from an obvious project directory:

```bash
cd ~/my_dev_project/

cdm copilot --allow-all
cdm pi
cdm claude
```

State that `--allow-all` belongs to Copilot. CDM passes the command and its arguments without joining or reparsing them.

### Introduce microVMs

Use guest-available commands so the examples do not imply that host-installed agent binaries automatically exist inside a guest:

```bash
cdm --vm sh -c 'uname -a'
cdm --vmi ubuntu:24.04 bash
```

Describe `--vm` as the bundled Alpine guest and `--vmi` as an OCI-image guest.

### Feature the worktree workflow

Give this capability a prominent subsection:

```bash
cdm --worktree claude
```

Explain that CDM copies the current Git-visible working state into a temporary worktree, lets the command edit it, and saves changes to a uniquely named `CDM__...` branch. The original checkout remains untouched, and useful changes are retained even when the wrapped command exits nonzero. Emphasize that users do not need to create, switch, finalize, or clean up the worktree manually.

### Add focused controls

Progress to outcome-labelled examples such as:

```bash
cdm --ro claude
cdm --iso --ro ./untrusted-checker
cdm --no-network python3 ./project_acme/audit.py
cdm --sec claude
cdm --sec --worktree claude
```

Use `./project_acme` whenever an example requires a project-directory path.

### Give desktop application mode its own mini-section

```bash
cdm "/Applications/Example.app"
```

Explain that CDM validates the bundle and infers narrow app-owned writable locations. State that selecting the bundle is the caller's trust decision: CDM does not run Gatekeeper, notarization, or code-signature checks.

## Installation

Keep the verified release installer first:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/RogueKernelApps/cdm/releases/latest/download/cdm-install.sh | bash
```

Follow with only the supported platforms, the default `$HOME/.local` prefix, the `PATH` reminder, and links to detailed version-pinning, custom-prefix, manual-installation, and artifact-verification instructions. Preserve the required `SHA256SUMS` statement.

## Security section

Start with the honest default: plain `cdm command` is compatibility-oriented. The workspace is writable, host user data remains readable, networking is direct, and secrets are unchanged. This primarily prevents accidental writes outside the project and is not a boundary for hostile code.

Explain the secret design concisely: with `--scramble` enabled, the child receives stable fake values; real mappings remain in host memory; and CDM's per-invocation HTTP(S) proxy restores values only for authorized destinations.

Include a compact matrix that makes composition and implication visible. It should distinguish at least:

- `--ro`: workspace read-only
- `--iso`: hide other host user data except explicit grants
- `--no-network`: deny networking
- `--scramble`: discover and replace secrets, hide/stage credential files, and normally enable the fail-closed proxy
- `--sec`: imply `--scramble`, add persistence protections, and use the deny-first macOS capability baseline
- `--vm` / `--vmi`: stronger process and daemon containment

The matrix must not imply that `--sec` also enables `--ro`, `--iso`, or `--no-network`; those remain separate controls. Mention that strict destination allowlists require proxied scrambling and that `--no-proxy` disables restoration and domain filtering.

## Related documentation

Update `GETTING_STARTED.md` only where needed to remove needless README duplication or preserve a clear handoff to detailed instructions. Do not change architecture, specification, agent instructions, or rules unless the README work reveals a real contract mismatch or a durable repository convention that is not already documented.

## Verification

- Check every command against the typed CLI and documented flag semantics.
- Confirm security inheritance and defaults against `specs/SPEC.md` and `ARCHITECTURE.md`.
- Run `cd rust && python3 tests/validate_documentation.py`.
- Review the final diff for concise language, factual accuracy, and duplication.
