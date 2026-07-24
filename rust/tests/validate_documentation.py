#!/usr/bin/env python3
"""Validate CDM's documentation, instructions, and shell-test contract."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "rust"

REQUIRED_FILES = (
    "AGENTS.md",
    "README.md",
    "GETTING_STARTED.md",
    "ARCHITECTURE.md",
    "DEPENDENCIES.md",
    "FUTURE.md",
    "SECURITY.md",
    "specs/SPEC.md",
    ".github/copilot-instructions.md",
    "rust/AGENTS.md",
    "rust/tests/AGENTS.md",
    "rust/tests/README.md",
    "rust/packaging/AGENTS.md",
    "rust/packaging/README.md",
    "install.sh",
)

PUBLIC_FLAGS = (
    "--no-network",
    "--no-proxy",
    "--sec",
    "--scramble",
    "--ro",
    "--iso",
    "--allow-ro",
    "--allow-rw",
    "--profile",
    "--preset",
    "--app",
    "--monitor",
    "--allow-domains",
    "--deny-domains",
    "--allow-private-network",
    "--vm",
    "--vmi",
    "--worktree",
    "--report-json",
    "--stats",
)

PROFILE_IDS = ("pi", "claude", "codex", "copilot")
PROFILE_CONTRACT_DOCUMENTS = ("README.md", "GETTING_STARTED.md", "specs/SPEC.md")

CURRENT_DOCS = (
    ROOT / "AGENTS.md",
    ROOT / "README.md",
    ROOT / "GETTING_STARTED.md",
    ROOT / "ARCHITECTURE.md",
    ROOT / "DEPENDENCIES.md",
    ROOT / "FUTURE.md",
    ROOT / "specs/SPEC.md",
    ROOT / "rust/tests/README.md",
    ROOT / "rust/packaging/README.md",
)


def capture(pattern: str, text: str, source: str) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise ValueError(f"cannot find version in {source}")
    return match.group(1)


def markdown_files() -> list[Path]:
    local_only = {".git", ".scratch", ".pi", ".pi-subagents", "target"}
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if not local_only.intersection(path.parts)
    )


def check_links(path: Path, errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    for raw_target in re.findall(r"!?(?:\[[^\]]*\])\(([^)]+)\)", text):
        target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
        if not target or target.startswith(("#", "http://", "https://", "mailto:")):
            continue
        relative = unquote(target.split("#", 1)[0])
        if relative and not (path.parent / relative).resolve().exists():
            errors.append(f"{path.relative_to(ROOT)}: broken relative link {target}")


def check_development_version(cargo_version: str, errors: list[str]) -> None:
    """Require development to advance beyond the highest release tag."""
    listed = subprocess.run(
        ["git", "tag", "--list", "v[0-9]*"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if listed.returncode != 0:
        return
    release_tags: list[tuple[tuple[int, int, int, int], str]] = []
    for tag in listed.stdout.splitlines():
        parsed = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)([-+].*)?", tag)
        if parsed is None:
            continue
        major, minor, patch = (int(part) for part in parsed.groups()[:3])
        stable = int(parsed.group(4) is None or parsed.group(4).startswith("+"))
        release_tags.append(((major, minor, patch, stable), tag))
    if not release_tags:
        return
    _, release_tag = max(release_tags)
    release_version = release_tag.removeprefix("v")
    exact = subprocess.run(
        ["git", "describe", "--tags", "--exact-match", "--match", "v[0-9]*"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if exact.returncode == 0 and exact.stdout.strip() == release_tag:
        if cargo_version == release_version:
            return
        errors.append(
            f"exact release tag {release_tag} does not match Cargo version {cargo_version}"
        )
        return
    cargo_core = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", cargo_version)
    release_core = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", release_version)
    if cargo_core is None or release_core is None:
        errors.append(
            f"cannot compare development version {cargo_version} with {release_tag}"
        )
        return
    cargo_order = tuple(int(part) for part in cargo_core.groups())
    release_order = tuple(int(part) for part in release_core.groups())
    if cargo_order <= release_order:
        errors.append(
            f"development version {cargo_version} is not newer than released {release_tag}; "
            "advance Cargo, source, lockfile, specification, and packaging examples "
            "before documenting or merging post-release behavior"
        )


def check_profile_contract(
    config_source: str,
    setup_source: str,
    documents: dict[str, str],
    errors: list[str],
) -> None:
    """Keep the materialized catalog and import syntax visible in current docs."""
    for marker, description in (
        ('#[serde(rename = "import")]', "singular JSON import key"),
        ("BUNDLED_PROFILE_WARNING", "bundled profile warning"),
    ):
        if marker not in config_source:
            errors.append(f"rust/src/config.rs missing {description}")
    source_ids = set(re.findall(r'\bid:\s*"([^"]+)"', config_source))
    if source_ids != set(PROFILE_IDS):
        errors.append(
            "built-in profile catalog mismatch: "
            f"expected {', '.join(PROFILE_IDS)}, found {', '.join(sorted(source_ids))}"
        )
    if "materialize_bundled_profiles_in" not in setup_source:
        errors.append("rust/src/setup.rs does not materialize bundled profiles")
    for marker in (
        "setup-profiles.json",
        "enabled_profile_ids",
        "SetupProfilesRegistry",
        "read_setup_profiles",
        "write_setup_profiles",
        "detect_profiles",
        "dialoguer",
        "IsTerminal",
    ):
        if marker in config_source or marker in setup_source:
            errors.append(f"legacy profile contract remains in source: {marker}")
    for name in PROFILE_CONTRACT_DOCUMENTS:
        text = documents.get(name)
        if text is None:
            errors.append(f"missing profile contract document: {name}")
            continue
        for marker in ("`import`", "_warning", "~/.cdm/profiles", *PROFILE_IDS):
            if marker not in text:
                errors.append(f"{name}: missing profile contract marker {marker}")
        for marker in ("setup-profiles.json", "enabled_profile_ids"):
            if marker in text:
                errors.append(f"legacy profile contract remains in {name}: {marker}")


def main() -> int:
    errors: list[str] = []

    for relative in REQUIRED_FILES:
        if not (ROOT / relative).is_file():
            errors.append(f"missing required documentation/instruction file: {relative}")

    try:
        cargo_version = capture(
            r'^version\s*=\s*"([^"]+)"',
            (RUST / "Cargo.toml").read_text(encoding="utf-8"),
            "rust/Cargo.toml",
        )
        source_version = capture(
            r'^const VERSION: &str = "([^"]+)";',
            (RUST / "src/main.rs").read_text(encoding="utf-8"),
            "rust/src/main.rs",
        )
        spec_version = capture(
            r'^Version:\s*([^\s]+)',
            (ROOT / "specs/SPEC.md").read_text(encoding="utf-8"),
            "specs/SPEC.md",
        )
        if len({cargo_version, source_version, spec_version}) != 1:
            errors.append(
                "version mismatch: "
                f"Cargo={cargo_version}, source={source_version}, spec={spec_version}"
            )
        else:
            check_development_version(cargo_version, errors)
    except (OSError, ValueError) as error:
        errors.append(str(error))

    cli_source = (RUST / "src/cli.rs").read_text(encoding="utf-8")
    config_source = (RUST / "src/config.rs").read_text(encoding="utf-8")
    setup_source = (RUST / "src/setup.rs").read_text(encoding="utf-8")
    specification = (ROOT / "specs/SPEC.md").read_text(encoding="utf-8")
    check_profile_contract(
        config_source,
        setup_source,
        {
            name: (ROOT / name).read_text(encoding="utf-8")
            for name in PROFILE_CONTRACT_DOCUMENTS
        },
        errors,
    )
    for flag in PUBLIC_FLAGS:
        field = flag.removeprefix("--").replace("-", "_")
        if not re.search(rf"^\s*pub\s+{re.escape(field)}\s*:", cli_source, re.MULTILINE):
            errors.append(f"public flag missing from CLI source: {flag}")
        if f"`{flag}" not in specification:
            errors.append(f"public flag missing from specification: {flag}")

    help_snapshot_path = RUST / "tests/fixtures/cli-help.txt"
    if not help_snapshot_path.is_file():
        errors.append("missing reviewed CLI help snapshot: rust/tests/fixtures/cli-help.txt")
    else:
        help_snapshot = help_snapshot_path.read_text(encoding="utf-8")
        for flag in PUBLIC_FLAGS:
            if not re.search(
                rf"^\s+(?:-[A-Za-z0-9],\s+)?{re.escape(flag)}(?:\s|$)",
                help_snapshot,
                re.MULTILINE,
            ):
                errors.append(f"CLI help snapshot missing public flag: {flag}")
        for command in (
            "run",
            "config",
            "setup",
            "trust",
            "project",
            "help",
            "version",
            "completions",
        ):
            if not re.search(rf"^\s+cdm {command}(?:\s|$)", help_snapshot, re.MULTILINE):
                errors.append(f"CLI help snapshot missing command: {command}")
        cli_test_source = (RUST / "src/cli/tests.rs").read_text(encoding="utf-8")
        if (
            'include_str!("../tests/fixtures/cli-help.txt")' not in cli_source
            and 'include_str!("../../tests/fixtures/cli-help.txt")'
            not in cli_test_source
        ):
            errors.append("CLI help snapshot is not enforced by a Rust test")

    future = (ROOT / "FUTURE.md").read_text(encoding="utf-8")
    implemented_future_claims = (
        "Build a small static guest init binary",
        "Support a bundled x86_64 rootfs",
        "Structured denial logs, end-of-run statistics",
        "Specific token-format detection",
    )
    for stale_claim in implemented_future_claims:
        if stale_claim in future:
            errors.append(f"FUTURE.md still defers implemented work: {stale_claim}")

    for guide in (ROOT / "README.md", ROOT / "GETTING_STARTED.md"):
        text = guide.read_text(encoding="utf-8")
        if "cargo build --release --features vm" in text and "compile-only" not in text:
            errors.append(
                f"{guide.relative_to(ROOT)}: direct VM Cargo build is not labelled compile-only"
            )
        if "complete native and bundled-VM acceptance suite" in text:
            errors.append(
                f"{guide.relative_to(ROOT)}: overstates packaged VM acceptance coverage"
            )

    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for marker, description in (
        ("fetch-depth: 0", "full release-tag history for version validation"),
        ("toolchain: 1.88.0", "MSRV 1.88 job"),
        ("--all-targets --features vm", "automatic VM feature gate"),
        ("cargo-audit --version", "pinned cargo-audit install"),
        ("tests/test_validate_documentation.py", "release-version validator tests"),
    ):
        if marker not in ci:
            errors.append(f"CI contract missing {description}")

    release_workflow = (
        ROOT / ".github/workflows/release-composition.yml"
    ).read_text(encoding="utf-8")
    acceptance_markers = (
        'CDM="$relocated/bin/cdm"',
        "CDM_REQUIRE_NATIVE=1",
        "CDM_REQUIRE_VM=1",
        "CDM_OCI_SMOKE_TESTS=1",
        '"$relocated/bin/cdm" --no-proxy --vm',
        '"$relocated/install.sh" install',
        '"$installed/bin/cdm" --no-proxy --vm',
        'CDM="$installed/bin/cdm" CDM_SKIP_VM=1',
        "./tests/integration.sh 18_builtin_commands",
        "./tests/integration.sh",
    )
    for marker in acceptance_markers:
        if marker not in release_workflow:
            errors.append(
                f"production release workflow missing exact-package acceptance marker: {marker}"
            )
    if release_workflow.count('CDM="$installed/bin/cdm" CDM_SKIP_VM=1') != 2:
        errors.append(
            "production release workflow must run built-in acceptance against "
            "both installed target-native paths"
        )
    if "python3 tests/validate_documentation.py" not in release_workflow:
        errors.append("production release preflight omits documentation/version validation")
    if "tests/test_validate_documentation.py" not in release_workflow:
        errors.append("production release preflight omits release-version validator tests")
    if "fetch-depth: 0" not in release_workflow:
        errors.append("production release preflight omits release-tag history")
    if release_workflow.find("./tests/integration.sh") > release_workflow.find(
        "Upload exact release outputs"
    ):
        errors.append("production release uploads outputs before exact-package acceptance")
    release_publication_markers = (
        'tags:',
        '- "v*"',
        'github.event_name == \'push\'',
        'needs: compose',
        'gh release create "$GITHUB_REF_NAME" --draft',
        'gh release upload "$GITHUB_REF_NAME"',
        'gh release edit "$GITHUB_REF_NAME" --draft=false',
        'GH_REPO: ${{ github.repository }}',
        'Cleanup release workspace',
        '"$GITHUB_WORKSPACE"/rust/guest-init/target) command -p rm -rf -- "$guest_init_target"',
        'runner: \'"ubuntu-22.04"\'',
        'runner: \'"ubuntu-22.04-arm"\'',
        'runs-on: ${{ fromJSON(\'["self-hosted","Linux","ARM64","cdm-release"]\') }}',
        'Install Linux release build dependencies',
        '            bubblewrap \\',
        'Enable hosted x86_64 KVM acceptance',
        'Upload compact Linux AArch64 runtime candidate',
        'Attest accepted Linux AArch64 outputs',
        'targets: ${{ matrix.guest_target }}',
        'Verify macOS signing access',
        'Prepare ephemeral macOS signing keychain',
        'CDM_CERTIFICATE_P12',
        "create-storage-record: ${{ github.repository_visibility == 'public' }}",
        'Preserve Sigstore attestation bundle',
        'python3 rust/packaging/assemble-release.py',
        '--installer install.sh',
        'sha256sum -c SHA256SUMS',
        'releases/latest/download/cdm-install.sh',
    )
    for marker in release_publication_markers:
        if marker not in release_workflow:
            errors.append(
                f"production release workflow missing tag publication marker: {marker}"
            )

    install_url = "https://github.com/RogueKernelApps/cdm/releases/latest/download/cdm-install.sh"
    for install_guide in (ROOT / "README.md", ROOT / "GETTING_STARTED.md"):
        guide = install_guide.read_text(encoding="utf-8")
        if install_url not in guide or "SHA256SUMS" not in guide:
            errors.append(
                f"{install_guide.relative_to(ROOT)}: missing verified release installation guidance"
            )

    test_index = (RUST / "tests/README.md").read_text(encoding="utf-8")
    runner = (RUST / "tests/integration.sh").read_text(encoding="utf-8")
    for suite in sorted((RUST / "tests/suites").glob("[0-9]*.sh")):
        if suite.name not in test_index:
            errors.append(f"test suite missing from rust/tests/README.md: {suite.name}")
        if suite.name not in runner:
            errors.append(f"test suite missing from integration runner index: {suite.name}")

    versions_text = (RUST / "packaging/versions.env").read_text(encoding="utf-8")
    dependencies_text = (ROOT / "DEPENDENCIES.md").read_text(encoding="utf-8")
    for variable in ("LIBKRUN_VERSION", "LIBKRUNFW_VERSION", "LINUX_VERSION"):
        version = capture(
            rf'^{variable}="?([^"\n]+)"?$',
            versions_text,
            "rust/packaging/versions.env",
        )
        if version not in dependencies_text:
            errors.append(f"DEPENDENCIES.md missing pinned {variable}={version}")

    for adapter in (ROOT / "CLAUDE.md", ROOT / ".github/copilot-instructions.md"):
        if adapter.is_file() and "AGENTS.md" not in adapter.read_text(encoding="utf-8"):
            errors.append(f"{adapter.relative_to(ROOT)} does not route to AGENTS.md")

    for path in CURRENT_DOCS:
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            if re.search(r'^\s*CDM="\$PWD/target/release/cdm"', text, re.MULTILINE):
                errors.append(
                    f"{path.relative_to(ROOT)}: unsigned direct Cargo binary used for VM-capable integration guidance"
                )

    for path in markdown_files():
        check_links(path, errors)

    shell_files = sorted(
        path for path in RUST.rglob("*.sh") if "target" not in path.parts
    )
    if shell_files:
        result = subprocess.run(
            ["bash", "-n", *(str(path) for path in shell_files)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            errors.append(f"shell syntax validation failed: {result.stderr.strip()}")

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print(
        f"documentation contract: ok ({len(markdown_files())} Markdown files, "
        f"{len(shell_files)} shell files)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
