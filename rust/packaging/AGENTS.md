# Release-packaging instructions

Read the repository-root and `rust/AGENTS.md` instructions first. `README.md` in this directory is the release runbook.

- `package.sh` is the sole public VM-release interface.
- Keep upstream versions and SHA-256 values pinned in `versions.env`; never replace verified inputs with floating downloads.
- Runtime lookup must remain package-relative. Release artifacts must not require Homebrew paths, build-host rpaths, or `DYLD_LIBRARY_PATH`/`LD_LIBRARY_PATH`.
- Sign macOS libraries before the CDM executable and retain the Hypervisor entitlement. Ad-hoc signing is only for local validation.
- A runtime containing libkrunfw must be accompanied by the exact corresponding-source archive and notices. Never describe `runtime` output alone as redistributable.
- Keep target claims limited to paths actually implemented and validated. Do not claim universal macOS or cross-architecture packages.
- Start release compilation from fresh extracted runtime sources and a fresh Cargo target directory. Reuse only checksum-verified downloads.
- Keep `verify-runtime.py` fail-closed for transitive bundled dependencies, loader paths, macOS entitlements, and relocated execution without loader override variables. `package.sh verify-runtime` validates a deliberately non-redistributable local runtime; `package.sh verify` additionally requires the complete source-derived legal payload.
- Reject release candidates whose version still matches the previous release after post-release development. Before uninstalling a target-native test prefix, run `tests/integration.sh 18_builtin_commands` with `CDM` pointing to that installed binary.

Run `bash packaging/tests.sh`, `package.sh verify`, checksum verification, relocation, linked-library inspection, and a real packaged VM smoke test before calling a release artifact complete.
