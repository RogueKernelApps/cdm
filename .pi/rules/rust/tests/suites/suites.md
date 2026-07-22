---
kind: rules
paths:
  - 'rust/tests/suites/**/*'
summary: Implementing numbered end-to-end journeys against native, VM, proxy, worktree, and security modes.
triggers:
  - add test suite
  - cross-adapter test
  - VM integration test
  - sandbox regression
---

# Numbered Test Suites

Suites are sourced in numeric order by `tests/integration.sh` and share counters and helpers from `helpers.sh`. Put adapter-independent contracts in `07_cross_mode.sh`; keep platform-specific or feature-specific behavior in its owning suite. Use `mode_exec` when argv boundaries matter, `mode_run` only for intentional shell text, and scrambled helpers only when secret substitution is part of the assertion.

### Patterns & Conventions

- Increment `PASS`, `FAIL`, or `SKIP` through the shared assertion/skip helpers so the runner's final status remains authoritative.
- Capture stderr only in focused status/error assertions; routine cross-mode checks intentionally discard diagnostics.
- Keep OCI registry pulls, authenticated harness checks, installed-tool compatibility, and real app probes behind their documented opt-in environment switches.
- `CDM_SKIP_VM=1` is an explicit native-only decision, not a fallback for a broken VM-capable artifact. If VM support is advertised and not skipped, the suite expects a real boot.
- Add new coverage to the existing owning suite when possible. Update `tests/README.md`, `integration.sh`, and the documentation validator when adding or renaming a numbered suite.
- Run a focused suite with `CDM=/absolute/path/to/cdm ./tests/integration.sh <suite-fragment>` before the complete matrix.
