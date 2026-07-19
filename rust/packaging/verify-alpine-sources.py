#!/usr/bin/env python3
"""Create and verify CDM's deterministic Alpine corresponding-source manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any


MANIFEST_NAME = "alpine-sources.manifest.json"
RECEIPT_NAME = "receipt.json"
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]*$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


class VerificationError(ValueError):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read JSON {path}: {error}") from error


def expected_packages(lock_path: Path) -> tuple[str, dict[str, dict[str, Any]]]:
    lock = load_json(lock_path)
    if lock.get("schema") != 2:
        raise VerificationError("Alpine rootfs lock must use schema 2")
    alpine_version = lock.get("alpine_version")
    if not isinstance(alpine_version, str) or not alpine_version:
        raise VerificationError("Alpine rootfs lock has no version")

    expected: dict[str, dict[str, Any]] = {}
    rootfs = lock.get("rootfs")
    if not isinstance(rootfs, list) or not rootfs:
        raise VerificationError("Alpine rootfs lock has no architecture records")
    for architecture in rootfs:
        if not isinstance(architecture, dict):
            raise VerificationError("invalid Alpine architecture record")
        packages = architecture.get("packages")
        if not isinstance(packages, list):
            raise VerificationError("invalid Alpine package list")
        for package in packages:
            if not isinstance(package, dict):
                raise VerificationError("invalid Alpine package record")
            name = package.get("source_package")
            version = package.get("version")
            commit = package.get("build_commit")
            if not isinstance(name, str) or not SAFE_NAME.fullmatch(name):
                raise VerificationError(f"unsafe or missing source package name: {name!r}")
            if not isinstance(version, str) or not version:
                raise VerificationError(f"missing version for {name}")
            if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
                raise VerificationError(f"invalid build commit for {name}: {commit!r}")
            entry = expected.setdefault(name, {"build_commit": commit, "versions": set()})
            if entry["build_commit"] != commit:
                raise VerificationError(f"conflicting build commits for {name}")
            entry["versions"].add(version)
    for name, entry in expected.items():
        if len(entry["versions"]) != 1:
            raise VerificationError(
                f"one aports commit maps to conflicting versions for {name}: "
                f"{sorted(entry['versions'])}"
            )
    return alpine_version, expected


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package_files(payload: Path, name: str) -> list[dict[str, str]]:
    package_dir = payload / "packages" / name
    if not package_dir.is_dir():
        raise VerificationError(f"missing source payload for {name}")
    if not (package_dir / "aports" / "APKBUILD").is_file():
        raise VerificationError(f"missing exact APKBUILD for {name}")
    if not (package_dir / "distfiles").is_dir():
        raise VerificationError(f"missing distfiles directory for {name}")

    files: list[dict[str, str]] = []
    for path in sorted(package_dir.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            target_text = os.readlink(path)
            target = PurePosixPath(target_text)
            if target.is_absolute() or ".." in target.parts:
                raise VerificationError(f"source payload symlink escapes its package: {path}")
            target_path = path.parent.joinpath(*target.parts)
            if target_path.is_symlink() or not target_path.is_file():
                raise VerificationError(
                    f"source payload symlink must name a regular file in its package: {path}"
                )
            relative = path.relative_to(payload).as_posix()
            files.append({"path": relative, "symlink": target_text})
            continue
        if path.is_dir():
            continue
        if not path.is_file():
            raise VerificationError(f"unsupported source payload entry: {path}")
        relative = path.relative_to(payload).as_posix()
        files.append({"path": relative, "sha256": sha256(path)})
    return files


def apkbuild_identity(path: Path) -> tuple[str, str]:
    assignments: dict[str, str] = {}
    pattern = re.compile(r"^(pkgname|pkgver|pkgrel)=(['\"]?)([A-Za-z0-9+_.-]+)\2$")
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        match = pattern.fullmatch(raw_line.strip())
        if match:
            assignments[match.group(1)] = match.group(3)
    missing = {"pkgname", "pkgver", "pkgrel"} - assignments.keys()
    if missing:
        raise VerificationError(
            f"APKBUILD identity is not independently parseable; missing={sorted(missing)}: {path}"
        )
    return assignments["pkgname"], f"{assignments['pkgver']}-r{assignments['pkgrel']}"


def create_manifest(lock_path: Path, payload: Path) -> dict[str, Any]:
    alpine_version, expected = expected_packages(lock_path)
    packages: list[dict[str, Any]] = []
    packages_dir = payload / "packages"
    root_entries = {path.name for path in payload.iterdir()} if payload.is_dir() else set()
    unexpected_root = root_entries - {"packages", MANIFEST_NAME}
    if unexpected_root:
        raise VerificationError(f"unexpected payload-root entries: {sorted(unexpected_root)}")
    if not packages_dir.is_dir():
        raise VerificationError("source payload has no packages directory")
    non_directories = sorted(path.name for path in packages_dir.iterdir() if not path.is_dir())
    if non_directories:
        raise VerificationError(f"unexpected package entries: {non_directories}")
    actual_names = (
        {path.name for path in packages_dir.iterdir() if path.is_dir()}
        if packages_dir.is_dir()
        else set()
    )
    if actual_names != set(expected):
        missing = sorted(set(expected) - actual_names)
        extra = sorted(actual_names - set(expected))
        raise VerificationError(f"source-package coverage mismatch; missing={missing}, extra={extra}")

    for name, details in sorted(expected.items()):
        receipt_path = payload / "packages" / name / RECEIPT_NAME
        receipt = load_json(receipt_path)
        wanted_receipt = {
            "source_package": name,
            "versions": sorted(details["versions"]),
            "build_commit": details["build_commit"],
        }
        if receipt != wanted_receipt:
            raise VerificationError(f"receipt does not match rootfs lock for {name}")
        apk_name, apk_version = apkbuild_identity(
            payload / "packages" / name / "aports" / "APKBUILD"
        )
        if apk_name != name or apk_version not in details["versions"]:
            raise VerificationError(
                f"APKBUILD identity does not match rootfs lock for {name}: "
                f"{apk_name} {apk_version}"
            )
        packages.append(
            {
                **wanted_receipt,
                "files": package_files(payload, name),
            }
        )
    return {
        "schema": 1,
        "alpine_version": alpine_version,
        "source_packages": packages,
    }


def encoded_manifest(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_manifest(lock_path: Path, payload: Path) -> None:
    manifest_path = payload / MANIFEST_NAME
    if manifest_path.exists():
        raise VerificationError(f"refusing to replace existing manifest: {manifest_path}")
    content = encoded_manifest(create_manifest(lock_path, payload))
    temporary = manifest_path.with_name(f".{manifest_path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(content)
        os.replace(temporary, manifest_path)
    finally:
        temporary.unlink(missing_ok=True)


def verify(lock_path: Path, payload: Path) -> None:
    manifest_path = payload / MANIFEST_NAME
    actual = manifest_path.read_bytes()
    expected = encoded_manifest(create_manifest(lock_path, payload))
    if actual != expected:
        raise VerificationError(f"manifest or source payload verification failed: {manifest_path}")


def emit_expected(lock_path: Path) -> None:
    _, expected = expected_packages(lock_path)
    for name, details in sorted(expected.items()):
        print(f"{name}\t{','.join(sorted(details['versions']))}\t{details['build_commit']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    expected_parser = subparsers.add_parser("expected")
    expected_parser.add_argument("lock", type=Path)
    for command in ("write-manifest", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("lock", type=Path)
        subparser.add_argument("payload", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "expected":
            emit_expected(args.lock)
        elif args.command == "write-manifest":
            write_manifest(args.lock, args.payload)
        else:
            verify(args.lock, args.payload)
    except (OSError, VerificationError) as error:
        print(f"Alpine source verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
