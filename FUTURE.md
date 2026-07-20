# Future work

These capabilities are intentionally deferred. Implemented historical items were removed during the July 2026 project review; current constraints live in `ARCHITECTURE.md`.

## Security and networking

- Track [hudsucker upstream](https://github.com/omjadas/hudsucker) for a released equivalent of CDM's `should_tunnel_unknown_connect` hook, then remove the narrowly patched `rust/vendor/hudsucker-0.25.0` override after the fail-closed regression passes unchanged.
- Add SOCKS5 or another protocol-aware path for non-HTTP secret restoration.
- Add configurable read-denial tiers, Linux seccomp profiles, and richer audit/eBPF monitoring.
- Consolidate the VM launcher's explicit `posix_spawn` path onto the shared native process-supervision module without reintroducing fork-after-Tokio.
- Add an intermediate foreground supervisor or PTY relay so CDM can observe and escalate terminal-generated signals even when the complete VMM process group deliberately ignores them.

## VM runtime

- Complete the target-native packaged-VM acceptance matrix for the static guest init, including malformed plans, mount-target races, supplementary groups, signal escalation, and exit statuses 126/127.
- Benchmark libkrun overlay-root APIs against the current disposable rootfs clone and OCI-layer merge before adding another storage path.

## Product and developer experience

- Add adapter-sourced filesystem denial events and interactive denied-operation handling. Current schema-versioned reports and statistics cover CDM-observed lifecycle and proxy events, not every kernel denial.
- Consider an explicit, user-approved app-state registry keyed by the app's exact designated requirement or code-directory hash. This could make repeat `--app` launches seamless without trusting self-selected bundle IDs or silently learning paths from an unsandboxed launch; approvals would need revocation, upgrade semantics, and fail-closed signature verification.

## Recorded design decisions

- Keep temporary Git worktrees as the opt-in `--worktree` disposable-write workflow. Do not replace normal `--rw` semantics with a workspace overlay that could obscure or lose expected edits.
- Do not implement generic byte-stream secret rewriting. New restoration mechanisms must be protocol-specific credential brokers with explicit framing and fail-closed behavior.
- Defer VM rootfs overlays until cross-platform measurements demonstrate a material startup or storage benefit over the simpler clone-and-merge implementation.
