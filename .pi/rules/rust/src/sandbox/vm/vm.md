---
kind: rules
paths:
  - 'rust/src/sandbox/vm.rs'
  - 'rust/src/sandbox/vm/**/*'
  - 'rust/src/sandbox/rootfs.rs'
  - 'rust/src/sandbox/rootfs/**/*'
  - 'rust/src/sandbox/safe_root.rs'
summary: Changing libkrun orchestration, VMM confinement, guest-plan generation, VirtioFS translation, or immutable rootfs caching.
triggers:
  - libkrun
  - VirtioFS
  - guest plan
  - OCI rootfs
  - VM launcher
---

# MicroVM Runtime

`vm.rs` orchestrates the disposable rootfs and exports; it does not own libkrun FFI or guest-plan semantics. `vm/launcher.rs` exclusively owns the private launcher protocol, host VMM confinement, supervision, and libkrun context. `vm/guest_plan.rs` exclusively serializes the versioned mount/deny plan from resolved host policy. `rootfs.rs` owns bundled/OCI base resolution and the immutable cache.

### Patterns & Conventions

- The parent prepares and owns one disposable rootfs per invocation. Never run a guest directly from the persistent base cache or expose that cache writable to a child.
- Launcher plans may carry validated paths and VM settings, but never wrapped environment values or real secret maps. Guest plans carry exact argv bytes and fake environment only.
- Constrain the VMM itself using the resolved host-access and network intent. On macOS use a fresh exec'd deny-first Seatbelt launcher; on Linux use Bubblewrap with only required runtime roots, `/dev/kvm`, session state, rootfs, and exact shares.
- Disable libkrun's implicit TSI behavior and explicitly enable only the transport selected by policy. Disabled networking must have a zero TSI feature mask; proxied networking reaches only the exact bridge/proxy path.
- VirtioFS exports directories. Reject an external single-file grant rather than exporting its readable parent and pretending a guest bind mask constrains a compromised VMM.
- Individual write-denied files require a dedicated host-read-only export and a plan invariant proving immutable backing. Missing denials beneath writable exports fail before launch.
- Stream OCI layers to private no-follow files, enforce compressed/expanded/entry/depth quotas, verify digests and platform, validate whiteouts before extraction, tree-digest the result, and publish atomically under a cache lock.
- Test launcher-plan validation, rootfs poisoning/races, frozen path kinds, and guest-plan bounds with `--features vm`; prove actual VM behavior with the packaged artifact.
