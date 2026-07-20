# Rust implementation instructions

Read the repository-root `AGENTS.md` first.

- `src/cli.rs` owns typed argument parsing, help, and generated completion; `src/main.rs` owns top-level dispatch and internal launcher entry points; `src/invocation.rs` owns command ordering behind one `run` interface, while its private `invocation/lifecycle.rs` module owns resource cleanup, reporting, and exit-code aggregation.
- `src/project.rs` owns original-launch project root, project-config discovery, and deterministic kind reporting; detection must never grant access.
- `src/config.rs` owns exact-byte project trust and global preset layering. Project policy must remain untrusted after any byte edit, and policy/trust files plus their containing directories must remain hard write-denied. Custom global policy must fail closed unless its dedicated parent can be validated and denied in full.
- `src/access.rs` owns resolved filesystem policy, hard denials, frozen path
  kinds, and launch-time device/inode verification. Adapters must not
  canonicalize or reclassify policy paths after resolution.
- `src/app.rs` owns macOS application-bundle discovery.
- `src/worktree.rs` owns Git-visible state snapshotting, branch reservation, descriptor-relative no-follow finalization, and cleanup.
- `src/trusted_exec.rs` owns validation and identity pinning for host-side helper executables. Never add a PATH-resolved pre/post-sandbox helper elsewhere.
- `src/anchored.rs` owns descriptor-relative, no-follow reads beneath pinned
  category roots. Secret discovery and staging must pass opened descriptors
  through parsing and copying rather than reopening candidate pathnames.
- `src/sandbox/` owns adapter translation and VM/rootfs mechanics. Within VM
  mode, `sandbox/vm.rs` orchestrates the disposable rootfs,
  `sandbox/vm/launcher.rs` exclusively owns the private launcher protocol,
  VMM supervision, and libkrun FFI/context, and `sandbox/vm/guest_plan.rs`
  exclusively owns guest mount/deny plan construction and serialization.
- `src/network.rs` owns valid network/domain states; `src/secrets.rs`, `src/stage.rs`, and `src/proxy.rs` own the secret-obfuscation flow. Adapters may only translate the resolved network policy and must never silently degrade proxied mode to direct networking.

Keep the default feature set free of libkrun and OCI dependencies. Code behind the `vm` feature must preserve the native build. Use `io::Result` with actionable context at process and filesystem boundaries; do not broadly catch or ignore failures.

Treat OCI manifests, layers, tar metadata, and every cache path as hostile. Stream layers to private no-follow files, enforce all configured compressed/expanded/entry/depth quotas before publication, preserve registry digest verification, and publish only a tree-digest-verified cache. Never make a VM cache writable by the sandboxed child or follow a cache/extraction symlink to make a test pass.

Run formatting, unit tests, and Clippy for both the touched feature set and `--features vm`. Observable runtime changes also require the relevant real integration suite against the exact artifact under test.

Keep small, focused unit-test modules inline when that makes the behavior easier to follow. When a trailing test module grows to roughly 100 lines or becomes a distinct responsibility, move it without changing its module boundary to `src/<module>/tests.rs` (or the corresponding nested module path). Production files should expose only `#[cfg(test)] mod tests;`; integration journeys remain under `tests/suites/`. Organize tests by behavior rather than mirroring individual private functions.
