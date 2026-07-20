# Getting started

> [!WARNING]
> The default mode is compatibility-oriented: the workspace is writable,
> other host user data is readable, networking is direct, and secrets are
> unchanged. It mainly limits accidental writes outside the project. Use the
> hardening flags below for untrusted commands.

## Prerequisites

- Rust 1.88 or newer.
- macOS native mode: the built-in `/usr/bin/sandbox-exec`.
- Linux native mode: Bubblewrap (`bwrap`).
- Optional compile-only VM feature check: libkrun 1.19 or newer on the build host.
- Self-contained VM releases: macOS 14+ on Apple silicon, or Linux on x86_64/AArch64.

## Build and test

```bash
cd rust

# Native-only binary: no libkrun link or runtime requirement
cargo build --release
cargo test --all-targets

# Compile-only VM feature check; this is not a runnable VM artifact
cargo check --all-targets --features vm
cargo test --all-targets --features vm
python3 tests/validate_documentation.py
```

The native direct-build binary is `rust/target/release/cdm`. A direct VM Cargo build also requires verified `CDM_GUEST_INIT_BIN`, `CDM_GUEST_INIT_SHA256`, and `CDM_GUEST_INIT_PROVENANCE` inputs; without them VM execution fails closed. On macOS the binary additionally requires the Hypervisor entitlement. The packaging workflow supplies and verifies these inputs automatically.

For a self-contained local VM artifact, build the target-specific runtime bundle:

```bash
./packaging/package.sh runtime
tar -xzf target/dist/cdm-<version>-<target>.tar.gz
./target/dist/cdm-<version>-<target>/install.sh install
```

The package includes `lib/cdm/libkrun` and `lib/cdm/libkrunfw`; its executable-relative rpath keeps the installation relocatable and removes every end-user Homebrew or `DYLD_LIBRARY_PATH` requirement. macOS packaging targets 14.0 and signs the libraries before signing CDM with the Hypervisor entitlement. CDM is MIT-licensed, and production packages carry the root `LICENSE` with matching Cargo and SPDX metadata. Release maintainers need the upstream build toolchain described in [`packaging/README.md`](rust/packaging/README.md); the matching `cdm-vm-sources-*.tar.gz` must accompany redistributed runtime archives.

The installer defaults to `$HOME/.local`; pass a prefix after `install` when needed.
It records hashes for every file it owns, supports `verify` and `uninstall` with the
same optional prefix, preserves unrelated files, and uses staged promotion with
best-effort rollback for reinstalls and upgrades. See the
[`packaging` install lifecycle](rust/packaging/README.md#install-lifecycle) for the
complete command and modified-file behavior. Prefix ancestors and managed paths
must be owner-safe real directories/files; symlinks, cross-user-writable parents,
and multiply hard-linked owned files fail closed before mutation.

## Commands

```bash
cdm npm install
cdm run python3 script.py
cdm --monitor npm install
cdm --no-network python3 script.py
cdm --scramble npm install
cdm --scramble --allow-domains registry.npmjs.org,github.com npm install
cdm --scramble --deny-domains example.invalid bash
cdm --scramble --allow-domains dev.internal.example --allow-private-network internal-tool
cdm --worktree coding-agent
cdm --report-json .cdm-session.json --stats npm test
cdm --sec ./untrusted-checker            # deny-first baseline plus secret scrambling
cdm --rw npm install                 # explicit default: workspace read/write
cdm --ro npm test                    # workspace read-only
cdm --iso ./untrusted-checker        # no other host user data
cdm --iso --ro ./untrusted-checker   # isolated and workspace read-only
cdm --allow-ro ~/.config/tool tool   # repeatable read-only grant
cdm --allow-rw ./output tool         # repeatable read/write grant
cdm "/Applications/Example.app"
cdm completions bash > ~/.local/share/bash-completion/completions/cdm
cdm completions zsh > ~/.zfunc/_cdm

# VM-enabled build
cdm --vm echo hello
cdm --vm sh -c 'uname -a && pwd'
cdm --vmi alpine:3.21 sh
```

Flags are parsed before the command. Command arguments retain their exact Unix byte values and boundaries, including whitespace, newlines, globs, and non-UTF-8 bytes; use `sh -c` explicitly for redirects, pipes, variable expansion, and compound commands. CDM never joins or reparses argv.

`--monitor` is an explicit, fail-closed request. CDM creates a mode-`0600` log inside the private invocation runtime and starts the platform denial stream and viewer before launching your command. If any of that setup fails, CDM exits without running the command. Viewer paths are passed as arguments rather than interpolated into shell or AppleScript source, and viewer/stream processes are cleaned up before the runtime is removed.

Direct networking is the default, and CDM leaves `.env`, argv, and environment values alone. `--scramble` opts into secret discovery, hides and stages known credential files, substitutes values that are stable within one invocation, and enables the fail-closed HTTP(S) proxy. `--sec` implies `--scramble`. On macOS, proxied mode selects the deny-first capability baseline and lets the sandbox or VM launcher reach only CDM's exact loopback proxy. On Linux, an empty network namespace exposes only a validated loopback-TCP descriptor bridge to that proxy. Direct TCP/UDP cannot bypass domain rules on either platform. `--no-network` disables networking. `--no-proxy` keeps direct networking even when scrambling and cannot be combined with domain rules. Domain rules require `--scramble` or `--sec`. Proxy resolution rejects loopback, link-local, private, and other non-public addresses by default. To reach an intentional internal service, combine `--allow-private-network` with a non-empty allowlist that explicitly matches its hostname or literal IP; the flag alone grants nothing. Use an allowlist for a strict destination set because denylists cannot cover DNS aliases or equivalent literal IPs.

While scrambling is enabled, secret restoration is additionally scoped per credential. Recognized provider
tokens receive conservative provider destinations; unknown values remain fake.
For an internal credential, add an identifier rule without recording its value:

```json
{"secrets":{"restore_destinations":{"INTERNAL_API_TOKEN":["api.internal.example"]}}}
```

Global domain denies still take precedence. Responses are identity-encoded and
re-obfuscated so an upstream echo cannot reveal the restored value.

Filesystem modes compose around a small default: the effective workspace and a private per-invocation runtime directory beneath the invoking user's trusted temporary root are writable, and other host data is read-only. CDM overrides `TMPDIR`, `TMP`, and `TEMP` with that unique session directory, so tools can create temporary files without a path grant while other temporary paths stay read-only. `--ro` changes only the workspace to read-only. `--iso` hides other host user data; explicit path grants remain available. `--rw` is accepted as an explicit spelling of the default and conflicts with `--ro`.

`--sec` opts into secret scrambling and persistence hardening on every backend. It protects shell profiles, global Git/SSH control files, cron state, host agent hooks/configuration, and existing control entries at the effective workspace root. Workspace protection is exact rather than recursive, preserving nested Git worktree materialization. On macOS, `--sec` selects a deny-first Seatbelt profile with a narrow Mach lookup baseline and intentionally blocks Mach registration and sandbox-extension issuance. Direct normal mode remains compatibility-first for desktop and WebKit applications; `--scramble` with its normal proxy, `--iso`, and `--sec` are deny-first. `--iso` requires that baseline because Seatbelt cannot reopen a path after a broad deny; constructing the isolated read allowlist positively is the correct and enforceable formulation.

Pass an existing `.app` bundle as the command and CDM activates application mode automatically; the older `--app <path.app>` form remains supported. Selecting the bundle is the trust decision: CDM deliberately does not run Gatekeeper, notarization, or code-signature checks. It validates `Info.plist` and the contained executable, then infers narrow grants for exact bundle-ID locations under `Application Support`, `Caches`, `Containers`, `WebKit`, and `Preferences`, product-derived hidden state literally referenced by the bundle, and existing product-related cache directories whose exact name or version is referenced by the executable or bounded configuration resources. CDM prints each inferred grant and its evidence category.

Broad or sensitive home roots are never inferred, and automatic paths reject symlinks and escapes. Signed, unsigned, ad-hoc, and local development apps use the same discovery flow. Static inspection cannot predict every runtime-computed path, so add a narrow explicit `--allow-rw` when an app uses nonstandard state. CDM never launches the app unsandboxed to learn permissions.

`--worktree` starts from committed `HEAD`, creates a detached no-checkout worktree, and copies the caller's currently materialized tracked files/symlinks plus non-ignored untracked files without diff, checkout, smudge, or process filters. Sparse-excluded paths stay absent and are retained from the base tree during finalization. It preserves a nested invocation's relative directory. The sandbox may edit project files but cannot write its `.git` gitfile or the pinned actual/common Git directories. When the command exits, CDM revalidates those identities and constructs the result commit with non-hook, non-filter Git plumbing in a sanitized host environment, then updates the uniquely reserved `CDM__...` branch atomically and removes the temporary worktree. Finalization opens the worktree root once and reads every entry descriptor-relatively without following symlink ancestors; replacing a tracked directory with a symlink records the link itself and removes its former descendants rather than reading through it. Materialized content that differs from the stored blob, including a materialized Git LFS file, is saved as raw content because CDM will not execute its clean filter as trusted host code. The original checkout and its dirty state remain untouched. Failed commands still preserve their changes and retain their own exit status. Ignored files such as dependency directories are not copied, so install/build them inside the worktree when required.

`--report-json <path>` writes a private JSON report for automation, including early validation and setup failures. Schema version 1 records the selected backend, effective policy when resolution was reached, configured-versus-observed denial coverage, bounded directional proxy/secret counters, child status, and cleanup/worktree outcomes. Policy is `null` when validation or setup fails before resolution. It never records argv values, paths, domains, error messages, environment values, or secret material. Prepare the report's parent directory first; CDM refuses symlink destinations and fails if the child swaps the pinned parent directory. `--stats` writes a compact summary to stderr, leaving the wrapped command's stdout byte-for-byte untouched.

## Configuration and caches

`cdm config` creates defaults at `~/.cdm/config.json` and will not overwrite an existing file. To use `CDM_CONFIG_PATH=/path/policy/config.json`, first create `/path/policy` as a dedicated user-owned directory with no group/world write bits; broad parents such as `/tmp`, `$HOME`, and the project root are rejected. CDM then searches from the original launch directory upward for the nearest `.cdm/config.json`. Review that repository-controlled file and run `cdm trust` from the project: CDM records its exact SHA-256 digest in the mode-0600 `~/.cdm/trusted-projects.json`, and any byte edit requires review and trust again. Symlinked or hard-linked policy files are rejected. `cdm project` reports the root, detected kind, and config path without loading policy or granting access.

The global file may contain a top-level `presets` object. Repeat `--preset <name>` to apply named presets left-to-right. The effective order is built-ins, global file, selected presets, trusted project file, then CLI flags. Presets are trusted global policy only: project-defined and nested presets are rejected. Partial JSON objects merge with defaults; unknown names, malformed files, and changed/untrusted project files stop execution with exit status 2.

The `paths` section supports `allow_ro`, `allow_rw`, `deny_read`, `deny_write`, and `staged_configs`. Path lists are additive and deduplicated; explicit configured denials apply in every mode, while CDM's built-in persistence list is activated only by `--sec`. Global/preset relative paths resolve from `$HOME`, project relative paths resolve from the discovered project root, and CLI grant paths resolve from the effective workspace after `--worktree`. `~` is supported, and explicit grant targets must already exist so mistakes fail closed. The global/trust-store policy directory and the project `.cdm` directory are hard write-denied in the child, preventing file replacement and parent rename/swap attacks even when a broader RW grant exists. Internally discovered app-owned first-launch paths are the deliberate exception to the existence rule: their validated, bundle-ID-derived directories are prepared before policy resolution.

VM base images are cached under `~/.cdm/rootfs`. Set `CDM_CACHE_DIR` to an absolute path to move that cache, which is useful in CI or restricted host environments. The effective cache must be a real, current-user-owned directory; CDM makes it mode 0700, rejects symlink traversal, and prevents sandboxed children from modifying it. Cached trees carry a deterministic SHA-256 tree digest and are rebuilt if their contents no longer match.

The `vm` configuration section bounds untrusted OCI input. Defaults are 512 MiB compressed and 4 GiB expanded per layer, 2 GiB compressed and 8 GiB expanded per image, 250,000 entries per layer, 1,000,000 per image, and 128 path components. Override these with `max_layer_compressed_mib`, `max_image_compressed_mib`, `max_layer_expanded_mib`, `max_image_expanded_mib`, `max_layer_entries`, `max_image_entries`, and `max_path_depth`. Values must be non-zero and a per-layer value cannot exceed its image total.

`CDM_DEBUG=1` prints generated adapter/VM details. `cdm __capabilities__` is intended for the test harness and reports whether the artifact includes VM support.

## Integration tests

```bash
cd rust

# Native adapters only
CDM_SKIP_VM=1 CDM="$PWD/target/release/cdm" ./tests/integration.sh

# On macOS, build a signed VM artifact before testing --vm
./packaging/package.sh runtime
VERSION=$(awk -F '"' '/^version =/ {print $2; exit}' Cargo.toml)
TARGET=$(rustc -vV | awk '/^host:/ {print $2}')
PACKAGE_DIR="target/dist/cdm-$VERSION-$TARGET"
CDM="$PWD/$PACKAGE_DIR/bin/cdm" ./tests/integration.sh
```

The runner never substitutes an older installed binary. `CDM_SKIP_VM=1` is the explicit native-only opt-out. OCI image downloads and authenticated/networked AI-tool checks are disabled unless `CDM_OCI_TESTS=1` and `CDM_AI_TESTS=1` are set. A signed-package run boots real microVMs where the target host supports them, but it does not by itself close every release-acceptance obligation; track the remaining target-native cases in [`rust/guest-init/INTEGRATION.md`](rust/guest-init/INTEGRATION.md).

Read [README.md](README.md) for the security caveats and [ARCHITECTURE.md](ARCHITECTURE.md) for the detailed model.
Contributors and coding agents must also follow [AGENTS.md](AGENTS.md) and every closer scoped `AGENTS.md` for the files they touch.
