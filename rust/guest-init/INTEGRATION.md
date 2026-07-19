# Guest-init integration design

This note records the implemented build/runtime boundary. Target-native packaged VM acceptance is still required before a target is publishable.

## Build boundary

Keep the helper outside the host Cargo dependency graph. Only VM-enabled builds need a guest artifact.

1. The package maps its host architecture to the same-architecture `*-unknown-linux-musl` target and rejects every unimplemented mapping.
2. `guest-init/build-static.sh` builds `guest-init/Cargo.toml` with `--locked --release` in its independent target directory and emits deterministic source/build provenance.
3. The host build accepts `CDM_GUEST_INIT_BIN` only together with `CDM_GUEST_INIT_SHA256` and `CDM_GUEST_INIT_PROVENANCE`. It opens each input once with `O_NOFOLLOW`, validates ownership/mode/link count, hashes the exact bytes in-process, rejects wrong architecture, `PT_INTERP`, and `DT_NEEDED`, validates provenance schema/digest/target/size/source inventory, then copies those exact bytes into `OUT_DIR`.
4. Gate all of this on the host crate's `vm` feature. A native build without `vm` must neither locate a musl target nor run guest tooling.
5. The verified bytes and provenance are embedded in the host executable for rootfs installation and also retained as auditable package evidence under `libexec/cdm/` and `share/cdm/`. There are no development-machine runtime lookup fallbacks.

The package build invokes `guest-init/build-static.sh` first and passes its verified result to the VM-enabled host build. A VM-feature development build with no artifact still compiles for unit testing but emits a warning and fails before VM entry; it never falls back to the old shell path. Production packaging always supplies and verifies the artifact. Ordinary native builds require no musl target or guest artifact.

## Runtime handoff

The generated shell and split command/config files are replaced by host-created, non-group/world-writable files in the private ephemeral rootfs:

- `/cdm-guest-init`, copied from the verified target-matching artifact with mode 0555;
- `/cdm-plan.json`, serialized once from resolved host policy with mode 0400;
- `/cdm-guest-init.provenance.json`, the exact validated provenance with mode 0444.

Set libkrun's exact exec to `/cdm-guest-init /cdm-plan.json`. Schema 2 must carry only fake environment values, exact argument byte arrays, guest cwd/identity, ordered mounts, and hard denies. Secret mappings remain exclusively in host memory. Serialization errors, NUL arguments, helper installation errors, schema mismatch, any declared mount/deny failure, or inability to set the complete guest identity must stop the invocation.

The host should write the plan through the existing safe-root abstraction, and the helper opens it with `openat2` no-symlink resolution before inspecting and reading the same descriptor. Filesystem mount targets are also held as descriptors; the helper uses the modern Linux mount API to attach new filesystems without a second path lookup. File-deny bind/remount operations address the held descriptor through the already-required `/proc` mount.

## Acceptance gate

Release acceptance is incomplete until the exact signed runtime package passes both architectures' target-native VM suite, including:

- arguments containing whitespace, quotes, wildcard characters, newlines, and non-UTF-8 Unix bytes arrive unchanged;
- the child sees only fake/explicit environment entries and the requested UID/GID with no supplementary groups;
- missing shares, malformed plans, unknown fields, wrong schema, symlink targets, and denied-target races fail before command execution;
- file and directory denies hide their underlying objects and cannot be bypassed through replacement paths;
- SIGINT/SIGTERM reach the command process group, orphaned descendants are reaped, remaining descendants are terminated, and normal/signal/not-found/not-executable exits map to 0-255/128+signal/127/126;
- the packaged helper is static, target-matching, relocation-independent, checksum verified, and accompanied by generated source/build provenance.
