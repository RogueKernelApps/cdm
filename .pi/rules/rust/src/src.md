---
kind: rules
paths:
  - 'rust/src/**/*.rs'
summary: Modifying the host runtime's typed CLI, orchestration, policy, security, reporting, or adapter-facing contracts.
triggers:
  - invocation lifecycle
  - access policy
  - secret proxy
  - worktree behavior
  - status output
---

# Host Runtime

Keep module interfaces narrow and leave top-level orchestration in `invocation.rs`. `cli.rs` owns typed parsing, help, and completions; `main.rs` dispatches typed actions; `invocation/lifecycle.rs` owns cleanup, report publication, and exit aggregation. Policy producers such as configuration, app discovery, setup profiles, and secure mode feed `access.rs`, which resolves filesystem policy once before any adapter translates it.

### Patterns & Conventions

- Never duplicate access, app-discovery, worktree, proxy, or VM policy in `main.rs` or `invocation.rs`.
- Adapters and presentation consume frozen resolved state. They must not canonicalize, reclassify, or independently infer policy paths after resolution.
- Keep real secret mappings in trusted host memory. Staged files, reports, status, launcher plans, and errors may contain only fake/public data or bounded aggregates.
- `network.rs` owns valid network/domain states; `secrets.rs`, `stage.rs`, and `proxy.rs` own discovery, obfuscation, scoped restoration, and response re-obfuscation. Proxied mode must never degrade to direct networking.
- `trusted_exec.rs` is the only place to add host helper resolution and identity pinning. `anchored.rs` owns descriptor-relative no-follow reads below pinned roots.
- `worktree.rs` owns snapshotting, branch reservation, descriptor-relative finalization, and cleanup without hooks, filters, signing helpers, or project-selected Git executables.
- `report.rs` is a bounded schema, not a logging channel. `status.rs` renders resolved values and typed origins without exposing argv values.

### Subdirectories

- **`sandbox/`** — Enter when translating frozen policy into Seatbelt, Bubblewrap, libkrun, rootfs, or guest-plan enforcement.
