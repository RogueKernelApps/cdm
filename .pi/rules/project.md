---
kind: rules
paths:
  - '**/*'
summary: Repository-wide guidance for changes that affect CDM behavior, architecture, documentation, or multiple subsystems.
triggers:
  - change CDM behavior
  - update architecture
  - cross-cutting security change
  - repository documentation
---

# CDM

CDM wraps developer commands in a host-native sandbox or optional libkrun microVM. Its trusted host process keeps real secrets in memory, gives the child stable fake values, and restores real values only through the per-invocation proxy. Treat malformed policy, setup, launch, and cleanup states as errors; never turn them into warnings or success-shaped outcomes. Preserve exact argv boundaries and require callers to request a shell explicitly when they need shell syntax.

### Patterns & Conventions

- Use TDD for behavior changes and keep every change as small as the contract allows. The JSON `import` array is ordered and current-file-last; keep every import contained beneath the pinned user profile root and fail closed before child execution.
- Bundled profiles are transparent files refreshed by non-interactive `cdm setup`; known IDs are directly selectable. Do not restore an enablement registry, detection checklist, migration layer, or legacy profile schema.
- Read `ARCHITECTURE.md` before changing runtime boundaries, filesystem policy, worktrees, VM lifecycle, proxying, or secret flow. `specs/SPEC.md` is the normative behavior contract.
- Documentation changes accompany behavior changes. Run `cd rust && python3 tests/validate_documentation.py` after changing documented behavior, CLI flags, versions, test layout, or agent guidance.
- Advance the product version before post-release behavior or documentation reaches `main`; keep Cargo, lockfile, source, specification, and versioned examples aligned. Every documented built-in must pass exact installed-artifact dispatch acceptance before release.
- Keep machine-local state, plans, generated reports, and review transcripts under ignored `.scratch/`; never commit harness runtime state or generated `rust/target/` content.
- On this development machine, use guarded `command -p rm` only after validating every operand; never invoke PATH-resolved `rm` for cleanup.

### Routed Areas

- **`rust/`** — Enter when implementing, testing, building, or releasing the CDM executable or guest helper.
- **`specs/`** — Enter when observable behavior, CLI semantics, policy precedence, security guarantees, or exit behavior changes.
- **`.github/workflows/`** — Enter when changing CI gates, target-native acceptance, release composition, attestations, or scheduled dependency checks.
