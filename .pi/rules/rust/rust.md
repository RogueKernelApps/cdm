---
kind: rules
paths:
  - 'rust/**/*'
summary: Building, implementing, testing, or packaging the host CLI and static guest helper.
triggers:
  - Rust implementation
  - cargo dependency
  - build CDM
  - package CDM
---

# Rust Workspace

The host CLI is one Rust binary with deep modules around policy and isolation boundaries. VM support is optional: the default feature set must compile without libkrun, OCI dependencies, VM headers, or a guest toolchain. The static Linux guest init is an independent crate and artifact rather than a host-crate dependency. Generated build output under `target/` is never a source surface.

### Patterns & Conventions

- Use `io::Result` with actionable context at process and filesystem boundaries; do not broadly catch or ignore failures.
- Keep VM-only dependencies and code behind the `vm` feature. Verify both native and `--features vm` builds when shared code changes.
- Keep focused unit tests beside their owning module; move a distinct or roughly 100-line trailing test module to the matching `src/<module>/tests.rs` without exposing test-only APIs. Test configuration graphs through the loader boundary and setup materialization through its orchestration boundary.
- Keep bundled-profile setup non-interactive and registry-free; remove obsolete schema code and dependencies rather than preserving compatibility layers.
- The baseline is formatting, native tests and Clippy, VM-feature tests and Clippy, documentation validation, and `packaging/tests.sh`. Observable runtime changes also need the owning real integration suite against the exact artifact.
- Built-in commands require typed CLI/help tests plus `tests/suites/18_builtin_commands.sh` coverage proving they do not fall through to sandbox execution. Advance the product version before post-release runtime work is documented or merged.

### Subdirectories

- **`src/`** — Enter when changing CLI parsing, invocation flow, policy resolution, secret/network behavior, adapters, reporting, worktrees, or process supervision.
- **`tests/`** — Enter when adding observable command-line journeys, adapter regressions, fixtures, or documentation-contract checks.
- **`guest-init/`** — Enter when changing the static guest PID 1, plan schema, mount/deny setup, guest identity, signal handling, or guest artifact provenance.
- **`packaging/`** — Enter when changing pinned runtime dependencies, release assembly, signing, licensing, provenance, installation, or package verification.
