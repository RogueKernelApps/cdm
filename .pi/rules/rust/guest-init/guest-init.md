---
kind: rules
paths:
  - 'rust/guest-init/**/*'
summary: Changing the static microVM PID 1, schema-2 plan enforcement, guest setup, or artifact provenance.
triggers:
  - guest init
  - guest plan schema
  - microVM PID 1
  - musl artifact
---

# Guest Init

The helper accepts one absolute path to a strict versioned JSON plan and exits before command launch if any declared setup step fails. The Rust parser is the enforcement authority; `schema-v2.json` is the machine-readable description. Plans carry exact argv byte arrays, fake environment only, guest cwd/identity, ordered mounts, and hard denies. Mount targets are held and resolved with no-follow Linux APIs rather than reopened by pathname.

### Patterns & Conventions

- Reject unknown fields, unsupported versions, NUL argv, non-normalized paths, invalid environment names, oversized input, excessive collections, zero UID/GID, and missing required mounts or denies.
- Retain setup privilege only until mounts and denies are complete, then enforce `no_new_privs`, clear groups and capabilities, and launch a non-root child. Host root maps to guest UID/GID 65534.
- Launch without a shell, preserve argument bytes, supervise one process group, forward signals, reap descendants, and preserve documented exit mappings.
- Build with the locked musl target and generate deterministic provenance covering artifact, lockfile, target, and sources. Never check generated binaries into Git.
- A development VM build without a verified helper may compile but must fail clearly before VM entry; there is no shell or BusyBox fallback.
- Run `guest-init/tests.sh` for the independent contract and the packaged real-VM suite for mounts, identity, capabilities, signals, argv, and exit behavior.
