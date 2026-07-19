# Dependency modernization

Dependencies were reviewed against their latest stable crates.io releases on 16 July 2026. `rust/Cargo.lock` is committed so application builds resolve the reviewed graph. The crate declares Rust 1.88 as its minimum supported version. Pre-release major versions, including `libc` 1.0 alphas, are intentionally excluded from “latest stable.”

| Dependency | Selected version | Relevant update |
|---|---:|---|
| `aho-corasick` | 1.1.4 | Bounded overlapping literal matching while streaming macOS bundle references |
| `clap` / `clap_complete` | 4.6.x | One typed parser generates validation, help, and Bash/Zsh/Fish completion without duplicating the flag contract |
| `libc` | 0.2.186 | Current platform constants and bindings |
| `serde` | 1.0.228 | Current derive and serialization fixes |
| `serde_json` | 1.0.150 | Current JSON parser/serializer fixes |
| `sha2` | 0.10.9 | SHA-256 exact-byte trust receipts for project configuration |
| `tokio` | 1.52.3 | Current runtime; `sync` and `time` are now declared because CDM uses them directly |
| `hudsucker` | 0.25.0 + local patch | Current Hyper/rustls proxy APIs; CDM uses the rustls client feature only. The published source is vendored with one fail-closed CONNECT hook; see `rust/vendor/hudsucker-0.25.0/CDM-PATCH.md`. |
| `http-body-util` | 0.1.4 | Added directly for bounded body collection; CDM now rejects bodies over 16 MiB |
| `oci-client` | 0.17.0 | Replaces the abandoned `oci-distribution` package under its maintained name; rustls-only TLS |
| `tar` | 0.4.46 | Current archive and extraction fixes; layer errors are propagated and OCI whiteouts are handled by CDM |
| `flate2` | 1.1.9 | Current gzip decoding fixes |
| `pkg-config` | 0.3.33 | Current build-time probing; libkrun is probed only for `--features vm` |
| `libkrun` | 1.19.4 | Latest stable 1.x VM ABI; 2.0 remains explicitly unstable upstream |
| `libkrunfw` | 5.5.0 | Latest stable firmware bundle; contains Linux 6.12.91 |

Primary release histories: [Tokio](https://github.com/tokio-rs/tokio/releases), [hudsucker](https://github.com/omjadas/hudsucker/releases), [oci-client](https://github.com/oras-project/rust-oci-client/releases), [Serde](https://github.com/serde-rs/serde/releases), and [tar-rs](https://github.com/alexcrichton/tar-rs/releases).

## Resulting design changes

- VM dependencies are optional. `cargo build --release` produces a native-only artifact; `--features vm` adds libkrun and OCI support.
- The proxy was updated to the current body API and made fail-closed for body read/size errors.
- Hudsucker 0.25.0 is pinned through `[patch.crates-io]` because upstream's unknown-protocol CONNECT path can silently fall back to an opaque tunnel after interception was requested. CDM's minimal licensed patch adds a handler decision at that edge; CDM always disables the fallback so upstream connections cannot bypass its per-resolution private-address policy. Track upstream releases and remove the vendor override once an equivalent hook is published; no other vendored source is modified.
- OCI cache writes are private, locked, tree-digest verified, and atomic. Authenticated layers stream to no-follow temporary files under configurable compressed/expanded/entry/depth quotas; extraction failures are never ignored, and overlay whiteouts are implemented only after validation.
- Default features were disabled where appropriate to avoid duplicate TLS stacks and native OpenSSL dependencies.
- The previous shared proxy daemon was removed. Every invocation owns an in-memory secret map and a short-lived proxy/CA artifact directory.
- The lockfile was refreshed to the latest compatible transitive graph, including current `bitflags`, `bstr`, `regex`, `syn`, and `uuid` releases.
- Compile-only VM feature checks can use a host libkrun installation. A runnable direct build must also provide a verified target-matching static guest init and provenance through the three `CDM_GUEST_INIT_*` build inputs; macOS additionally requires the Hypervisor entitlement. Release builds instead construct those inputs, re-extract and compile the pinned stable libkrun/libkrunfw sources for every invocation, verify downloaded checksums, build CDM in a fresh target-specific Cargo directory, and use an executable-relative `lib/cdm` runtime path. Package verification follows the transitive libkrun/libkrunfw edges, rejects build-host paths, checks signatures/entitlements or ELF RPATHs, and executes a relocated copy without loader override variables.
- VM runtime archives are target-specific and self-contained. macOS libraries and CDM are built for deployment target 14.0 and signed inside-out; Linux packages use the equivalent `$ORIGIN` layout.
- The committed `packaging/libkrun-relative-firmware.patch` changes only libkrun's runtime firmware filename to `@loader_path` on macOS or `$ORIGIN` on Linux. It is applied to checksum-verified upstream source, shipped in the source companion, and recorded in provenance so libkrun cannot silently load a host-installed libkrunfw.
- Because libkrunfw contains a Linux kernel, the release workflow emits a matching corresponding-source archive with libkrun, libkrunfw, and Linux 6.12.91 sources. It additionally refuses production release without a separately prepared Alpine payload containing each exact aports recipe and every `abuild fetch` checksum-verified distfile required by the embedded rootfs inventory. Redistribution without the verified companion is explicitly prohibited by the package notice.
