# Integration-test instructions

Read the repository-root and `rust/AGENTS.md` instructions first. `README.md` in this directory is the test-suite index.

- Test observable user journeys through the real adapter. Unit tests may cover pure policy generation and parsing; integration tests must not replace runtime behavior with mocks.
- Always test the exact executable supplied through `CDM`. Never fall back to an installed or older binary.
- Do not mask command failures with unconditional `|| true`. Capture the exit status and assert it deliberately.
- Use disposable fixtures under `/tmp`, configure repository-local Git identity, and remove worktrees, branches, processes, sockets, and files created by the test.
- Remove test artifacts only through the guarded `remove_test_path` helper. Never invoke a PATH-resolved `rm`; this machine may provide an `rmtrash` wrapper with unsafe empty-operand behavior.
- Keep assertions portable across supported architectures and `/tmp` versus `/private/tmp` aliases.
- A compiled VM capability is not proof of a runnable macOS VM. Use the signed packaged binary for VM journeys; `CDM_SKIP_VM=1` is an explicit native-only opt-out.
- Keep the single release-required Alpine registry journey behind `CDM_OCI_SMOKE_TESTS=1`, the broader registry matrix behind `CDM_OCI_TESTS=1`, and authenticated external-harness checks behind `CDM_AI_TESTS=1`. Keep credential-free installed-tool checks behind `CDM_COMPAT_TESTS=1`; real app probes must identify apps by bundle identifier and use a fresh home with networking disabled.
- Add a focused regression to the owning numbered suite before fixing a runtime defect. Configuration journeys must prove imported policy ordering/path anchoring and that malformed or unsafe graphs fail before child execution. Keep cross-adapter contract tests in `07_cross_mode.sh` and adapter-specific behavior in its owning suite.
- Base-profile journeys that import `bundled/*.json` must prove profile provenance and missing optional harness state are preserved through the import graph.
- Keep `18_builtin_commands.sh` as the complete lightweight inventory of documented built-ins. Assert exit status, representative output, and absence of sandbox dispatch so target-native release acceptance can run it against both packaged and installed artifacts.

Run `python3 tests/validate_documentation.py` when suite names, environment switches, commands, or coverage descriptions change.
