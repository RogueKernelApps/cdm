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
)

PUBLIC_FLAGS = (
    "--no-network",
    "--no-proxy",
    "--sec",
    "--scramble",
    "--rw",
    "--ro",
    "--iso",
    "--allow-ro",
    "--allow-rw",
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
    except (OSError, ValueError) as error:
        errors.append(str(error))

    cli_source = (RUST / "src/cli.rs").read_text(encoding="utf-8")
    specification = (ROOT / "specs/SPEC.md").read_text(encoding="utf-8")
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
            if not re.search(rf"^\s+{re.escape(flag)}(?:\s|$)", help_snapshot, re.MULTILINE):
                errors.append(f"CLI help snapshot missing public flag: {flag}")
        for command in ("run", "config", "trust", "project", "help", "version", "completions"):
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
        ("toolchain: 1.88.0", "MSRV 1.88 job"),
        ("--all-targets --features vm", "automatic VM feature gate"),
        ("cargo-audit --version", "pinned cargo-audit install"),
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
        "./tests/integration.sh",
    )
    for marker in acceptance_markers:
        if marker not in release_workflow:
            errors.append(
                f"production release workflow missing exact-package acceptance marker: {marker}"
            )
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
    )
    for marker in release_publication_markers:
        if marker not in release_workflow:
            errors.append(
                f"production release workflow missing tag publication marker: {marker}"
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
