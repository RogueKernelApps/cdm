# Test organization

CDM keeps fast unit tests in the Rust module hierarchy and reserves this directory for observable command-line journeys across real sandbox adapters. Small focused test modules may remain inline. Larger modules live at `src/<module>/tests.rs` behind a private `#[cfg(test)] mod tests;`, keeping production responsibilities quick to inspect without exposing test-only interfaces. Tests are grouped by behavior; they do not mirror every private function mechanically.

## Layers

1. `cargo test --all-targets` runs native module and policy-generation tests.
2. `cargo test --all-targets --features vm` adds VM/rootfs unit tests, including hostile symlink/hard-link caches, native-to-VM cache poisoning, streamed-layer cleanup, and compressed/expanded/entry/depth quota bombs.
3. `python3 tests/validate_documentation.py` checks required docs/instructions (including `FUTURE.md`), version and CLI/spec alignment, the reviewed CLI-help snapshot, CI MSRV/VM/audit gates, relative links, historical labels, VM-testing guidance, and shell syntax.
4. `tests/integration.sh` runs numbered end-to-end suites against the exact binary provided through `CDM`.
5. `packaging/tests.sh` checks pinned release metadata, checksums, shell syntax, and relocatable lookup conventions; `packaging/package.sh verify-runtime` checks a local runtime package, while `package.sh verify` additionally enforces redistributable legal completeness.

## Integration suites

The numbered files under `tests/suites/` follow the runtime flow and feature ownership:

- `01_seatbelt.sh`: macOS Seatbelt startup, basic execution, and proxied CA artifacts; it skips on Linux.
- `02_vm.sh`: real VM boot, architecture/non-root UID/cwd (including host-root mapping to 65534), the no-new-privileges/setuid/capability probe, sensitive-file read/overwrite/unlink denial with host-integrity verification, argv/stdin/exit propagation, host workspace round-trips, RO enforcement, disposable rootfs, path spaces, and concurrent guests.
- `03_proxy.sh`: fail-closed HTTP(S) proxy lifecycle, certificates, normalized domain and private-address policy, and native raw-socket bypass denial on macOS and Linux.
- `04_worktree.sh`: materialized tracked and sparse-checkout snapshotting, non-ignored dirty state, original-checkout isolation, descriptor-relative no-follow finalization, tracked-directory-to-symlink replacement, plumbing-built result commits, compact/quiet completion status, normalized root/nested cwd, repeated/concurrent branch reservation, failed-command preservation, gitfile/actual-Git-dir write denial, hostile hooks/clean-smudge-process filters/signing/Git environment/PATH containment, cleanup, and combined worktree+VM journeys.
- `05_env.sh` and `06_config.sh`: developer-friendly default secret passthrough/readable `.env`, explicit `--scramble`, short secret-named values, `--sec` implication, SSH agent/control-socket compatibility, descriptor-relative ancestor-symlink rejection and other fail-closed secret preparation, exact-byte project trust/invalidation, explicit built-in profiles, profile/preset independence and precedence, origin-aware grants, policy-file mutation/rename/link containment, and the best-effort command preflight's exact token/basename boundary.
- `07_cross_mode.sh`: behavior shared by every available adapter, including direct/default and explicitly scrambled secret flows.
- `08_ai_tools.sh`: opt-in authenticated coding-harness compatibility.
- `09_cli_network.sh`: typed command-local CLI/completion validation including `setup`, `--profile`, short path grants, grouped effective-policy and failed-command completion status, quoted values, backticked terminal literals, exact provenance and abbreviated grant paths, quiet suppression, deterministic project reporting, direct/disabled/proxied controls, and VM TSI isolation.
- `10_filesystem_policy.sh`: workspace/host modes, grants, lexical/canonical hard denials, macOS public/physical temp aliases, inaccessible directory masks, missing-leaf rename/recreate containment, synthetic runtime aliases, and real pathname plus abstract AF_UNIX deputy probes.
- `11_security_mode.sh`: secure persistence denials, non-recursive nested-worktree compatibility, and the macOS deny-first Mach/XPC regression probes.
- `12_app_mode.sh`: unsigned/local-development bundle launch, automatic narrow state inference, reporting, and app-state containment; installed real-app inference is covered by the opt-in compatibility matrix.
- `13_argv_fidelity.sh`: exact empty, spaced, leading-option, literal, Unicode, newline, glob, and non-UTF-8 Unix argument boundaries across adapters.
- `14_input_validation.sh`: malformed CLI/configuration/profile registry, non-TTY setup preservation, non-UTF-8 filesystem-policy paths, and insecure custom-policy-parent failures before sandbox startup.
- `15_process_lifecycle.sh`: exact child exit/signal status, same-group teardown, Linux `setsid`/double-fork namespace containment, proxy-artifact cleanup, worktree finalization, and immediate reuse after cleanup.
- `16_compatibility_matrix.sh`: opt-in, credential-free probes of installed coding harnesses and macOS apps.
- `17_structured_reporting.sh`: schema, redaction, permissions, stdout preservation, explicit/incomplete cleanup outcomes, lifecycle outcomes, and proxy counters for JSON reports and compact statistics.

Cross-adapter helpers call the host adapter `native` regardless of whether it resolves to Seatbelt or Bubblewrap; platform-specific suites query the actual adapter separately. The runner gives CDM a fresh mode-0700 home, so mutable developer credentials and configuration cannot change acceptance results; opt-in compatibility probes must request any real external state explicitly. Proxy journeys run only when the exact artifact advertises `strict-proxy`. VM support may be explicitly omitted with `CDM_SKIP_VM=1`; otherwise a VM-capable artifact is expected to boot. On macOS, use the signed artifact emitted by `packaging/package.sh runtime`, not an unsigned direct Cargo build. `CDM_OCI_SMOKE_TESTS=1` pulls and boots the release-required Alpine 3.21 journey; `CDM_OCI_TESTS=1` adds the broader image matrix. Authenticated AI checks remain opt-in through `CDM_AI_TESTS=1`. Credential-free installed-tool checks use `CDM_COMPAT_TESTS=1`; optional desktop probes accept comma-separated bundle identifiers through `CDM_APP_SMOKE_BUNDLE_IDS`, run with a fresh empty home plus `--no-network`, and assert that inferred paths are individually reported without granting the home root. A suite must not silently replace the requested artifact with an installed binary.

Pull-request CI separately checks the declared Rust 1.88 MSRV and runs native plus VM-feature compile/test/clippy gates. Real Hypervisor/KVM execution remains a target-native packaged-artifact acceptance obligation rather than being inferred from a successful feature build.

Read `AGENTS.md` in this directory before modifying test behavior. A regression test must assert the real user-visible result and exit status; it must not hide failures simply to keep the suite green.
