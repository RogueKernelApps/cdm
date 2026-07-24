---
kind: rules
paths:
  - 'rust/tests/**/*'
summary: Adding or changing observable integration journeys, fixtures, helper behavior, or documentation validation.
triggers:
  - integration test
  - regression test
  - documentation validator
  - exact CDM artifact
---

# Integration Tests

This directory tests user-visible behavior through real sandbox adapters. Every run must use the exact executable supplied through `CDM`; never fall back to an installed binary. The runner supplies a fresh private home and policy directory so mutable developer state cannot affect acceptance. Use a signed packaged binary for real macOS VM journeys rather than treating a VM-feature Cargo build as runnable evidence.

### Patterns & Conventions

- Add a focused regression to the owning numbered suite before fixing a runtime defect. Assert output, host effects, and exit status explicitly.
- Do not hide failures with unconditional `|| true`. Capture and check expected failures. Import-validation journeys must also assert that the wrapped child never started.
- Create disposable fixtures under trusted temporary roots, set repository-local Git identity, and clean every created process, socket, worktree, branch, and file.
- Cleanup must go through `remove_test_path`; never call PATH-resolved `rm`.
- Keep assertions portable across supported architectures and public/physical temporary-path aliases.
- Run `tests/validate_documentation.py` when suite names, environment switches, commands, coverage descriptions, or CLI snapshots change.
- Keep `18_builtin_commands.sh` synchronized with every documented built-in and suitable for release acceptance against an installed prefix: assert status, representative output, and no sandbox dispatch.
- Profile coverage must use an isolated `HOME`/`PATH` and PTY to prove the exact artifact shows detected known apps, defaults them checked, honors toggles/cancellation, writes exact ordered `~/.cdm/base.json` imports, materializes only selected files, removes deselected known files, preserves user/unknown files, and fails closed on missing/unsafe state. Do not add obsolete-registry fixtures or compatibility expectations.

### Subdirectories

- **`suites/`** — Enter when adding or changing end-to-end coverage for a command, adapter, policy mode, security invariant, or compatibility journey.
- **`fixtures/` and `fixture/`** — Enter when a journey needs reviewed golden output or isolated command/environment input shared by suites.
