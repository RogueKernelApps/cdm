# CDM agent instructions

These instructions are the canonical cross-harness guidance for this repository. Read the closest additional `AGENTS.md` before changing files below `rust/`, `rust/tests/`, or `rust/packaging/`.

## Product and architecture

CDM wraps developer commands in a host-native sandbox or an optional libkrun microVM. It keeps real secrets in the trusted host process, gives the child fake values that remain stable within one invocation, and restores real values only through the per-invocation HTTP(S) proxy.

Read only the references relevant to the task:

- `README.md` and `GETTING_STARTED.md` for supported user workflows.
- `ARCHITECTURE.md` before changing runtime boundaries, access policy, worktrees, VM lifecycle, proxying, or secret flow.
- `specs/SPEC.md` for the behavioral contract.
- `DEPENDENCIES.md` and `rust/packaging/README.md` for dependency or release work.
- `rust/tests/README.md` before changing test organization or integration behavior.

## Engineering rules

- Use TDD for behavior changes: demonstrate the failing expectation, make the smallest production change, then refactor with tests green.
- Prefer deep modules with narrow interfaces. Keep typed argument parsing and generated completion in `cli.rs`, top-level dispatch in `main.rs`, invocation orchestration in `invocation.rs`, and do not duplicate access, app-discovery, worktree, proxy, or VM policy there.
- Resolve filesystem policy once in `access.rs`. Native and VM adapters translate the resolved policy; they do not invent different policy. The configuration `import` array stays beneath the pinned user profile root, applies in document order before the current file, and keeps each declaring-file path anchor.
- Keep bundled profiles as transparent managed JSON refreshed by non-interactive `cdm setup`. Known IDs are directly selectable; do not add profile detection, enablement registries, migrations, or legacy schema handling.
- Keep real secret mappings in host memory and out of sandbox-visible files, logs, command lines, and errors.
- Preserve argv boundaries. Shell syntax requires the caller to request a shell explicitly.
- Surface malformed input, setup failures, and incomplete cleanup. Do not turn failures into warnings or success-shaped results.
- Keep the native build independent of VM headers, libraries, and optional crates.
- Never weaken unconditional integrity denials, worktree containment, rootfs immutability, or proxy fail-closed behavior merely to make a test pass. Persistence protections are an explicit `--sec` policy surface, not unconditional integrity invariants.
- Keep machine-specific configuration, plans, review transcripts, generated reports, and historical working notes under the ignored `.scratch/` tree. Do not add harness-specific runtime state to the public repository; checked-in agent guidance belongs in `AGENTS.md` and its scoped descendants.

## Documentation contract

Documentation is part of every behavior change. Update the user guide, architecture, specification, tests guide, and scoped instructions when their contract changes. Keep historical documents clearly labelled as superseded.

Advance the product version immediately after a release before merging new
user-visible behavior or documenting it on `main`. Keep Cargo, the lockfile,
`src/main.rs`, `specs/SPEC.md`, and versioned install/packaging examples aligned.
Every documented built-in must have exact-artifact dispatch coverage, and the
release workflow must rerun that coverage against the installed prefix before
publication.

Run the documentation validator after changing docs, CLI flags, versions, test layout, or agent instructions:

```bash
cd rust
python3 tests/validate_documentation.py
```

## Baseline verification

```bash
cd rust
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all-targets --features vm
cargo clippy --all-targets --features vm -- -D warnings
python3 tests/validate_documentation.py
bash packaging/tests.sh
```

An ordinary direct VM-feature Cargo build is compile-only unless it receives the verified static guest-init artifact, digest, and provenance inputs. On macOS it additionally lacks the Hypervisor entitlement required for real VM tests. Build a signed package with `./packaging/package.sh runtime` and point `CDM` at its `bin/cdm`. Use `CDM_SKIP_VM=1` only when intentionally running the native-only matrix. OCI pulls and authenticated AI-harness tests remain explicit opt-ins.

Do not edit generated files under `rust/target/` or commit local `.DS_Store`, temporary, cache, or manual-test artifacts.

On this development machine, `rm` on `PATH` may be an `rmtrash` wrapper. Never use
plain `rm` in repository scripts or manual validation. Use `command -p rm` (or an
absolute system binary) only after proving every operand is non-empty. In
particular, never interpolate an unchecked `mktemp` result into cleanup.
