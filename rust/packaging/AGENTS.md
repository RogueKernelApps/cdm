# Release-packaging instructions

Read the repository-root and `rust/AGENTS.md` instructions first. `README.md` in this directory is the release runbook.

- `package.sh` is the sole public VM-release interface. Its `runner` command owns a foreground, one-job temporary GitHub runner; never install a persistent runner service. Keep administration credentials out of the job environment, bound session lifetime, and report incomplete cleanup. Local packaging must remain independent of GitHub runners.
- After deleting the old runner directory, follow [Recreate release capability](README.md#recreate-release-capability-after-deleting-the-old-runner). Reprovision through `package.sh runner`, not `svc.sh install` or the old Shared path. Fresh registration credentials are obtained through `gh`; do not back up or restore old runner credential files. Check documented host prerequisites and GitHub signing secrets before a release.
- A neutral home/path is a configuration and log-privacy measure, not a host sandbox. Verify the service host for each runner registration before retirement; Linux may be in a VM even when the operator is using a Mac.
- Keep the existing Linux ARM64 acceptance service and build arrangement unchanged until replacement is explicitly requested. Mac cleanup does not authorize Linux migration. `package.sh runner` does not provision a Linux VM; a future Mac-hosted replacement must prove nested KVM and pass exact-artifact acceptance before retiring the existing host. See [Linux acceptance findings](README.md#linux-acceptance-and-possible-future-mac-hosted-execution).
- Keep upstream versions and SHA-256 values pinned in `versions.env`; never replace verified inputs with floating downloads.
- Runtime lookup must remain package-relative. Release artifacts must not require Homebrew paths, build-host rpaths, or `DYLD_LIBRARY_PATH`/`LD_LIBRARY_PATH`.
- Sign macOS libraries before the CDM executable and retain the Hypervisor entitlement. Ad-hoc signing is only for local validation.
- A runtime containing libkrunfw must be accompanied by the exact corresponding-source archive and notices. Never describe `runtime` output alone as redistributable.
- Keep target claims limited to paths actually implemented and validated. Do not claim universal macOS or cross-architecture packages.
- Before either Linux target-native VM acceptance path runs, assign `/dev/kvm` to that job's runner UID/GID at mode `0600` and prove read/write access; never bypass the VM journey because a persistent runner lost device permissions.
- Start release compilation from fresh extracted runtime sources and a fresh Cargo target directory. Reuse only checksum-verified downloads.
- Keep `verify-runtime.py` fail-closed for transitive bundled dependencies, loader paths, macOS entitlements, and relocated execution without loader override variables. `package.sh verify-runtime` validates a deliberately non-redistributable local runtime; `package.sh verify` additionally requires the complete source-derived legal payload.
- Reject release candidates whose version still matches the previous release after post-release development. Before uninstalling a target-native test prefix, run `tests/integration.sh 18_builtin_commands` with `CDM` pointing to that installed binary.

Run `bash packaging/tests.sh`, `package.sh verify`, checksum verification, relocation, linked-library inspection, and a real packaged VM smoke test before calling a release artifact complete.
