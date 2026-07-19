#!/usr/bin/env python3
"""Regenerate the embedded Alpine rootfs inventory from the pinned archives."""

from __future__ import annotations

import base64
import hashlib
import json
import tarfile
from pathlib import Path


ASSETS = Path(__file__).resolve().parent
VERSIONS = ASSETS.parent / "packaging" / "versions.env"
OUTPUT = ASSETS / "alpine-rootfs.lock.json"
ARCHITECTURES = ("aarch64", "x86_64")


def version_value(name: str) -> str:
    for line in VERSIONS.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key == name:
            return value.strip().strip('"')
    raise SystemExit(f"missing {name} in {VERSIONS}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def installed_database(archive: Path) -> str:
    with tarfile.open(archive, "r:gz") as rootfs:
        member = next(
            (
                candidate
                for candidate in rootfs.getmembers()
                if candidate.name.removeprefix("./") == "lib/apk/db/installed"
            ),
            None,
        )
        if member is None:
            raise SystemExit(f"missing Alpine package database in {archive}")
        stream = rootfs.extractfile(member)
        if stream is None:
            raise SystemExit(f"missing Alpine package database in {archive}")
        return stream.read().decode("utf-8")


def parse_packages(database: str) -> list[dict[str, str]]:
    fields = {
        "P": "name",
        "V": "version",
        "A": "architecture",
        "T": "description",
        "U": "source_url",
        "L": "license",
        "o": "source_package",
        "c": "build_commit",
        "C": "apk_checksum",
    }
    packages: list[dict[str, str]] = []
    for paragraph in database.split("\n\n"):
        package: dict[str, str] = {}
        for line in paragraph.splitlines():
            key, separator, value = line.partition(":")
            if separator and key in fields:
                package[fields[key]] = value
        if not package:
            continue
        missing = {"name", "version", "architecture", "license"} - package.keys()
        if missing:
            raise SystemExit(f"incomplete installed-package record: {sorted(missing)}")
        checksum = package.get("apk_checksum")
        if checksum and checksum.startswith("Q1"):
            # APK v2 stores a SHA-1 checksum as base64 after the Q1 algorithm tag.
            decoded = base64.b64decode(checksum[2:], validate=True)
            if len(decoded) != 20:
                raise SystemExit(f"invalid APK checksum for {package['name']}")
        packages.append(package)
    return sorted(packages, key=lambda item: item["name"])


def main() -> None:
    version = version_value("ALPINE_VERSION")
    entries = []
    package_identity: list[tuple[tuple[str, str], ...]] | None = None
    for architecture in ARCHITECTURES:
        archive = ASSETS / f"alpine-minirootfs-{version}-{architecture}.tar.gz"
        if not archive.is_file():
            raise SystemExit(f"missing pinned rootfs: {archive}")
        packages = parse_packages(installed_database(archive))
        identity = [
            tuple(
                sorted(
                    (key, value)
                    for key, value in package.items()
                    if key not in {"architecture", "apk_checksum"}
                )
            )
            for package in packages
        ]
        if package_identity is not None and identity != package_identity:
            raise SystemExit("Alpine architectures contain different package inventories")
        package_identity = identity
        entries.append(
            {
                "architecture": architecture,
                "url": (
                    "https://dl-cdn.alpinelinux.org/alpine/"
                    f"v{version.rsplit('.', 1)[0]}/releases/{architecture}/{archive.name}"
                ),
                "sha256": sha256(archive),
                "packages": packages,
            }
        )

    document = {
        "schema": 2,
        "alpine_version": version,
        "rootfs": entries,
    }
    OUTPUT.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
