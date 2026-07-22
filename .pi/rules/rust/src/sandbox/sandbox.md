---
kind: rules
paths:
  - 'rust/src/sandbox.rs'
  - 'rust/src/sandbox/**/*'
summary: Translating resolved access and network policy into native or microVM enforcement.
triggers:
  - Seatbelt adapter
  - Bubblewrap adapter
  - sandbox dispatch
  - rootfs cache
  - filesystem denial
---

# Sandbox Adapters

`sandbox.rs` owns the shared environment/runtime model and dispatches to platform adapters. Seatbelt and Bubblewrap enforce equivalent policy intent through different primitives: macOS emits public and physical path aliases, while Linux constructs bind/overlay namespaces and synthetic runtime trees. Apply captured hard denials last, and verify frozen object identity immediately before launch. Platform adapters translate policy; they do not decide it.

### Patterns & Conventions

- Compatibility mode remains the default. macOS `--iso`, proxied, and secure modes use the deny-first capability baseline rather than trying to reopen paths after a broad deny.
- Native writable roots are limited to the resolved workspace/runtime and explicit writable grants. Isolated mode builds a positive read set.
- Preserve captured lexical and canonical denial spellings, path kinds, and device/inode identities. Never follow a symlink or mutate the host to manufacture a missing denial target.
- Linux replaces host runtime socket trees with synthetic targets and confines proxy access through the descriptor bridge; do not expose deputy sockets through grants.
- Keep process supervision, signal forwarding, terminal ownership, and exact exit mapping in the shared process/launcher owners rather than adapter-specific ad hoc code.
- Rootfs and VM code treats cache paths, OCI manifests/layers, tar metadata, and guest plans as hostile input.

### Subdirectories

- **`vm/`** — Enter when changing disposable rootfs preparation, VirtioFS exports, guest plans, VMM confinement, launcher protocol, or libkrun execution.
