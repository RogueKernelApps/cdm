# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability or include real credentials in
a report. Use GitHub's private vulnerability-reporting flow:

<https://github.com/RogueKernel/cdm/security/advisories/new>

Include the affected commit or version, host platform, selected CDM flags and
backend, reproduction steps using synthetic credentials, and the expected and
observed boundary. Remove local paths, environment values, tokens, and other
personal information before submitting.

## Supported scope

Security fixes target the current `main` branch; no older release line currently
has a separate support window. Published binaries are gated by target-native
package, relocation, installation, real-VM, and integration acceptance on macOS
AArch64, Linux x86_64, and Linux AArch64. See the
[release runbook](rust/packaging/README.md) and
[`rust/guest-init/INTEGRATION.md`](rust/guest-init/INTEGRATION.md) for the exact
build and acceptance boundaries.

Repository tests intentionally use syntactically realistic but nonfunctional
credential examples to verify secret detection and redaction. They are labelled
as test fixtures and must never be replaced with real credentials.

## Security expectations

CDM's default mode is compatibility-oriented. It is primarily intended to
limit accidental writes outside the workspace; it leaves the workspace
writable, other host user data readable, networking direct, and secrets
unchanged. Use `--ro`, `--iso`, `--no-network`, `--scramble`, `--sec`, and the
VM backends according to the threat model described in [README.md](README.md)
and [ARCHITECTURE.md](ARCHITECTURE.md).

The command preflight guard is not an enforcement boundary. Do not report a
child launching a command that was not the original direct executable as a
guard bypass unless an actual filesystem, network, secret, or VM policy was
also bypassed.
