# Future work

These capabilities are intentionally deferred. Implemented historical items were removed during the July 2026 project review; current constraints live in `ARCHITECTURE.md`.

## Security and networking

- Track [hudsucker upstream](https://github.com/omjadas/hudsucker) for a released equivalent of CDM's `should_tunnel_unknown_connect` hook, then remove the narrowly patched `rust/vendor/hudsucker-0.25.0` override after the fail-closed regression passes unchanged.
- Add SOCKS5 or another protocol-aware path for non-HTTP secret restoration.
- Add configurable read-denial tiers, Linux seccomp profiles, and richer audit/eBPF monitoring.
- Consolidate the VM launcher's explicit `posix_spawn` path onto the shared native process-supervision module without reintroducing fork-after-Tokio.
- Add an intermediate foreground supervisor or PTY relay so CDM can observe and escalate terminal-generated signals even when the complete VMM process group deliberately ignores them.

## VM runtime

- Expand the target-native packaged-VM coverage beyond the current release gate,
  with additional adversarial cases for malformed plans, mount-target races,
  supplementary groups, signal escalation, and exit statuses 126/127.
- Benchmark libkrun overlay-root APIs against the current disposable rootfs clone and OCI-layer merge before adding another storage path.

## Product and developer experience

- Add adapter-sourced filesystem denial events and interactive denied-operation handling. Current schema-versioned reports and statistics cover CDM-observed lifecycle and proxy events, not every kernel denial.
- Consider an explicit, user-approved app-state registry keyed by the app's exact designated requirement or code-directory hash. This could make repeat `--app` launches seamless without trusting self-selected bundle IDs or silently learning paths from an unsandboxed launch; approvals would need revocation, upgrade semantics, and fail-closed signature verification.
- Make the resolved platform and invocation-runtime baseline easier to inspect. In
  particular, report that CDM replaces `TMPDIR`, `TMP`, and `TEMP` with a
  private mode-0700 per-invocation directory, while keeping the shared host
  temporary tree read-only unless the user grants a narrower interchange path.
  Audit other compiled platform roots and exceptions, classify them as runtime
  necessities, adapter translations, or integrity invariants, and give each
  visible typed provenance rather than representing dynamic or non-overridable
  machinery as an editable OS profile.
- Consider a typed runtime temporary-root option for workflows that need a
  user-selected filesystem. The safe default should remain a validated private
  per-invocation child beneath that root with automatic cleanup. Shared
  interchange directories should continue to use explicit read-only or
  read/write path grants; a direct `TMPDIR` override must also define ownership,
  symlink, identity-replacement, cleanup, native/VM, and concurrent-invocation
  semantics before implementation.

## Recorded design decisions

- Keep temporary Git worktrees as the opt-in `--worktree` disposable-write workflow. Do not replace the normal read/write workspace semantics with an overlay that could obscure or lose expected edits.
- Keep OS Trash directories out of default policy, bundled profiles, and
  `cdm setup`. Users who need compatibility with safe-delete wrappers can add an
  explicit read/write grant, with the understanding that it permits reading,
  changing, deleting, and filling existing Trash contents; do not describe the
  current cross-backend grant model as write-only or deposit-only.
- Do not implement generic byte-stream secret rewriting. New restoration mechanisms must be protocol-specific credential brokers with explicit framing and fail-closed behavior.
- Defer VM rootfs overlays until cross-platform measurements demonstrate a material startup or storage benefit over the simpler clone-and-merge implementation.
