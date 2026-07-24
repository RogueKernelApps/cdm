# Rust implementation instructions

Read the repository-root `AGENTS.md` first.

- `src/cli.rs` owns typed argument parsing, help, and generated completion; `src/main.rs` owns top-level dispatch and internal launcher entry points; `src/invocation.rs` owns command ordering behind one `run` interface, while its private `invocation/lifecycle.rs` module owns resource cleanup, reporting, and exit-code aggregation.
- `src/project.rs` owns original-launch project root, project-config discovery, and deterministic kind reporting; detection must never grant access.
- `src/config.rs` owns exact-byte project trust, contained ordered current-file-last `import` expansion, bundled-profile materialization, and global preset layering. Project policy must remain untrusted after any byte edit; imports may resolve only to current-user-owned, non-group/world-writable files beneath the pinned user profile root; and policy/trust/profile files plus their narrow containing directories must remain hard write-denied. Custom global policy must fail closed unless its dedicated parent can be validated and denied in full.
- `src/access.rs` owns resolved filesystem policy, hard denials, frozen path
  kinds, and launch-time device/inode verification. Adapters must not
  canonicalize or reclassify policy paths after resolution.
- `src/app.rs` owns macOS application-bundle discovery.
- `src/setup.rs` is a non-interactive bundled-profile materialization command; `config.rs` owns the compiled catalog, generated JSON, secure imports, and layering. There is no enablement registry or legacy profile schema. Invocation loads materialized bundled policy and must not hide a missing file behind a compiled fallback.
- `src/worktree.rs` owns Git-visible state snapshotting, branch reservation, descriptor-relative no-follow finalization, and cleanup.
- `src/status.rs` owns routine startup and notable completion presentation. It renders typed provenance from `origin.rs` and the already-resolved grant metadata from `access.rs`; it must not resolve policy paths itself. Resolved scalar values use speech marks, while flags, paths, branch names, and actionable commands use escaped backticks. Quiet mode suppresses only routine status; errors, wrapped output, and explicitly requested diagnostics remain visible.
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

Adding or changing a built-in command requires typed-parser/help coverage and
an assertion in `tests/suites/18_builtin_commands.sh` that proves the exact
artifact handles it before sandbox dispatch. Post-release runtime work must
advance the product version in every version source before it is documented or
merged.

Keep small, focused unit-test modules inline when that makes the behavior easier to follow. When a trailing test module grows to roughly 100 lines or becomes a distinct responsibility, move it without changing its module boundary to `src/<module>/tests.rs` (or the corresponding nested module path). Production files should expose only `#[cfg(test)] mod tests;`; integration journeys remain under `tests/suites/`. Organize tests by behavior rather than mirroring individual private functions.
