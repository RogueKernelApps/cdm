# CDM guest init

`cdm-guest-init` is a separately built, statically linked Linux helper intended to replace the generated shell init in CDM microVMs. It is deliberately not a dependency of the host `cdm` crate, so native-only builds remain independent of guest or VM toolchains.

## Status

The helper is connected to VM-feature builds through a verified build artifact. Development VM builds without that artifact still compile, but VM execution fails clearly rather than falling back to the removed shell/BusyBox path. `packaging/package.sh` always cross-builds, verifies, embeds, and packages the matching helper and provenance. Target-native packaged VM acceptance remains mandatory before publishing a target.

## Plan contract

The helper accepts exactly one absolute path to a JSON plan. `schema-v2.json` documents the machine-readable contract; the Rust parser remains the enforcement authority and additionally checks byte-oriented and cross-field invariants. Schema 2 contains:

- exact `argv_bytes` boundaries as lossless Unix byte arrays (including non-UTF-8 values, excluding NUL) and only the `fake_env` entries supplied by the trusted host;
- absolute working directory plus numeric UID and GID;
- ordered `proc`, `sysfs`, `devtmpfs`, `tmpfs`, and tagged `virtiofs` mounts;
- file and directory deny mounts applied after the shares they protect.

Unknown fields, unknown enum values, non-normalized paths, invalid environment names, unsupported schema versions, oversized strings, excessive collection sizes, and plans over 1 MiB are rejected. Every declared mount and deny is required; any setup failure exits 125 before the command starts. Plan and mount targets are opened with Linux `openat2` no-symlink resolution, and new filesystems are attached to the held target descriptor with the Linux mount API rather than re-resolving attacker-changeable paths. Deny targets must already exist: the helper never creates placeholders that could mutate a host-backed export, and a missing or unsafe target fails closed before command execution.

After all required mounts and denies succeed, the helper enables Linux `no_new_privs`, clears the ambient capability set, and drops every supported capability from the bounding set. In the child it clears supplementary groups, sets all real/effective/saved UID and GID values explicitly, and zeroes inheritable, permitted, and effective capability sets before `exec`. This preserves init's mount privileges only for setup while preventing setuid bits or file capabilities in an OCI rootfs from regaining guest root. Plans reject UID/GID zero; a CDM process invoked by host root maps the guest to UID/GID 65534.

The helper clears inherited environment state, launches the command without a shell, creates a dedicated process group, forwards common termination and terminal signals, reaps orphaned children, terminates descendants after the primary command exits, and maps normal exits directly and signals to `128 + signal`. Command lookup failure maps to 127 and permission failure to 126.

## Static build and provenance

Install the appropriate Rust musl target deliberately, then build one architecture at a time:

```bash
rustup target add aarch64-unknown-linux-musl
./build-static.sh aarch64 ../target/guest-init

rustup target add x86_64-unknown-linux-musl
./build-static.sh x86_64 ../target/guest-init
```

The script uses `cargo build --locked`, verifies static linkage when `file` is available, and writes a deterministic `.provenance.json` containing the artifact digest, target, lockfile digest, and source digests. Generated binaries and their build output stay ignored; no opaque binary is checked into the repository. The eventual runtime package must build the matching target, install it package-relatively, include this provenance, and verify the exact helper in a real VM.

Run the independent checks with `./tests.sh`. Linux runtime behavior—mount success/failure, signal forwarding, descendant reaping, UID/GID, exact argv/environment, and exit mapping—must additionally be exercised inside the packaged VM during integration.

The target-native VM suite runs `/cdm-guest-init --security-probe` as the wrapped child. It requires a non-root real/effective UID, `NoNewPrivs: 1`, zero inheritable/permitted/effective/bounding/ambient capability masks, and failures from both `setuid(0)` and an attempted capability grant. Run the same suite as host root to prove the 65534 mapping.
