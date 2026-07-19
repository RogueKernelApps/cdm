#!/usr/bin/env python3
"""Build a deterministic legal-material bundle for CDM's embedded Alpine rootfs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
from typing import Any, BinaryIO
import zipfile


LEGAL_NAME = re.compile(
    r"^(?:copying|copyrights?|licen[cs]es?|notices?)(?:[._-].*)?$", re.IGNORECASE
)
LICENSE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")
OPERATORS = {"AND", "OR", "WITH"}
MAX_NOTICE_SIZE = 8 * 1024 * 1024
MAX_TOTAL_NOTICE_SIZE = 64 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 100_000
MAX_SOURCE_FILES = 250_000
MAX_ARCHIVES = 2_000
MAX_NOTICES = 20_000
MAX_PATH_LENGTH = 4_096


class BundleError(ValueError):
    pass


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BundleError(f"cannot read JSON {path}: {error}") from error


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def load_license_texts(directory: Path) -> tuple[str, dict[str, bytes]]:
    manifest = read_json(directory / "manifest.json")
    if manifest.get("schema") != 1:
        raise BundleError("canonical license-text manifest must use schema 1")
    version = manifest.get("spdx_license_list_version")
    commit = manifest.get("spdx_license_list_commit")
    if not isinstance(version, str) or not version or not isinstance(commit, str):
        raise BundleError("canonical license-text provenance is incomplete")
    entries = manifest.get("licenses")
    if not isinstance(entries, list) or not entries:
        raise BundleError("canonical license-text manifest is empty")
    result: dict[str, bytes] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise BundleError("invalid canonical license-text record")
        identifier, filename, expected = (
            entry.get("id"),
            entry.get("file"),
            entry.get("sha256"),
        )
        if (
            not isinstance(identifier, str)
            or not LICENSE_TOKEN.fullmatch(identifier)
            or filename != f"{identifier}.txt"
            or not isinstance(expected, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected)
        ):
            raise BundleError(f"invalid canonical license-text record: {entry!r}")
        path = directory / filename
        if path.is_symlink() or not path.is_file():
            raise BundleError(f"canonical license text is missing or unsafe: {path}")
        content = path.read_bytes()
        if sha256_bytes(content) != expected:
            raise BundleError(f"canonical license text checksum mismatch: {identifier}")
        result[identifier] = content
    return version, result


def package_inventory(lock_path: Path) -> tuple[str, list[dict[str, str]], set[str]]:
    lock = read_json(lock_path)
    if lock.get("schema") != 2:
        raise BundleError("Alpine rootfs lock must use schema 2")
    alpine_version = lock.get("alpine_version")
    roots = lock.get("rootfs")
    if not isinstance(alpine_version, str) or not alpine_version or not isinstance(roots, list):
        raise BundleError("Alpine rootfs lock is incomplete")
    packages: list[dict[str, str]] = []
    license_ids: set[str] = set()
    required = (
        "apk_checksum",
        "architecture",
        "build_commit",
        "description",
        "license",
        "name",
        "source_package",
        "source_url",
        "version",
    )
    for root in roots:
        if not isinstance(root, dict) or not isinstance(root.get("packages"), list):
            raise BundleError("invalid Alpine rootfs architecture record")
        root_arch = root.get("architecture")
        for raw in root["packages"]:
            if not isinstance(raw, dict) or any(not isinstance(raw.get(key), str) for key in required):
                raise BundleError("Alpine package metadata is incomplete")
            package = {key: raw[key] for key in required}
            if package["architecture"] != root_arch:
                raise BundleError(f"architecture mismatch for {package['name']}")
            expression_tokens = LICENSE_TOKEN.findall(package["license"])
            identifiers = [token for token in expression_tokens if token not in OPERATORS]
            if not identifiers:
                raise BundleError(f"package has no declared license: {package['name']}")
            license_ids.update(identifiers)
            packages.append(package)
    packages.sort(key=lambda item: (item["architecture"], item["name"], item["version"]))
    return alpine_version, packages, license_ids


def safe_member_path(value: str) -> PurePosixPath:
    if len(value.encode("utf-8", errors="surrogateescape")) > MAX_PATH_LENGTH:
        raise BundleError("upstream archive member path is too long")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise BundleError(f"unsafe upstream archive member path: {value!r}")
    return path


def is_legal_name(path: PurePosixPath) -> bool:
    return bool(LEGAL_NAME.fullmatch(path.name))


def bounded_read(stream: BinaryIO, label: str) -> bytes:
    content = stream.read(MAX_NOTICE_SIZE + 1)
    if len(content) > MAX_NOTICE_SIZE:
        raise BundleError(f"upstream legal file is too large: {label}")
    return content


def archive_notices(path: Path) -> list[tuple[PurePosixPath, bytes]]:
    notices: list[tuple[PurePosixPath, bytes]] = []
    if tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as archive:
            for index, member in enumerate(archive, start=1):
                if index > MAX_ARCHIVE_ENTRIES:
                    raise BundleError(f"upstream archive has too many entries: {path}")
                member_path = safe_member_path(member.name)
                if not is_legal_name(member_path):
                    continue
                if not member.isfile():
                    raise BundleError(f"upstream legal archive entry is not a regular file: {member.name}")
                if member.size > MAX_NOTICE_SIZE:
                    raise BundleError(f"upstream legal file is too large: {path}:{member.name}")
                stream = archive.extractfile(member)
                if stream is None:
                    raise BundleError(f"cannot read upstream legal archive entry: {member.name}")
                with stream:
                    notices.append((member_path, bounded_read(stream, f"{path}:{member.name}")))
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                raise BundleError(f"upstream archive has too many entries: {path}")
            for info in infos:
                member_path = safe_member_path(info.filename)
                if not is_legal_name(member_path):
                    continue
                mode = info.external_attr >> 16
                if info.is_dir() or stat.S_ISLNK(mode):
                    raise BundleError(f"upstream legal ZIP entry is not a regular file: {info.filename}")
                if info.file_size > MAX_NOTICE_SIZE:
                    raise BundleError(f"upstream legal file is too large: {path}:{info.filename}")
                with archive.open(info) as stream:
                    notices.append((member_path, bounded_read(stream, f"{path}:{info.filename}")))
    return notices


def collect_notices(source: Path, source_packages: set[str]) -> list[dict[str, str | bytes]]:
    result: list[dict[str, str | bytes]] = []
    source_file_count = 0
    archive_count = 0
    for package in sorted(source_packages):
        package_dir = source / "packages" / package
        if package_dir.is_symlink() or not package_dir.is_dir():
            raise BundleError(f"verified corresponding source is missing package: {package}")
        for path in sorted(package_dir.rglob("*"), key=lambda item: item.as_posix()):
            if path.is_symlink():
                # The source verifier has already constrained links to regular
                # files within this package. Process the target's real entry
                # once rather than duplicating a notice under its link name.
                continue
            if not path.is_file():
                continue
            source_file_count += 1
            if source_file_count > MAX_SOURCE_FILES:
                raise BundleError("corresponding source contains too many files")
            relative = PurePosixPath(path.relative_to(package_dir).as_posix())
            if is_legal_name(relative):
                with path.open("rb") as stream:
                    content = bounded_read(stream, str(path))
                result.append({"source_package": package, "path": relative.as_posix(), "content": content})
            elif relative.parts[0] == "distfiles":
                archive_count += 1
                if archive_count > MAX_ARCHIVES:
                    raise BundleError("corresponding source contains too many distfiles")
                archive_name = safe_member_path(relative.as_posix())
                for member, content in archive_notices(path):
                    result.append(
                        {
                            "source_package": package,
                            "path": f"{archive_name.as_posix()}.contents/{member.as_posix()}",
                            "content": content,
                        }
                    )
                    if len(result) > MAX_NOTICES:
                        raise BundleError("corresponding source contains too many legal files")
    if len(result) > MAX_NOTICES:
        raise BundleError("corresponding source contains too many legal files")
    total = sum(len(item["content"]) for item in result if isinstance(item["content"], bytes))
    if total > MAX_TOTAL_NOTICE_SIZE:
        raise BundleError("upstream legal files exceed the bundle size limit")
    return result


def verify_corresponding_source(lock: Path, source: Path) -> None:
    verifier = Path(__file__).resolve().with_name("verify-alpine-sources.py")
    namespace: dict[str, Any] = {"__name__": "cdm_alpine_source_verifier"}
    try:
        exec(compile(verifier.read_bytes(), str(verifier), "exec"), namespace)
        namespace["verify"](lock, source)
    except Exception as error:
        raise BundleError("corresponding source does not match the Alpine rootfs lock") from error


def write_bundle(
    lock: Path, source: Path | None, output: Path, license_text_directory: Path
) -> None:
    if output.exists() or output.is_symlink():
        raise BundleError(f"refusing to replace output: {output}")
    version, packages, license_ids = package_inventory(lock)
    spdx_version, canonical = load_license_texts(license_text_directory)
    missing = sorted(license_ids - canonical.keys())
    if missing:
        raise BundleError(f"no verified canonical text for declared licenses: {missing}")
    if source is not None:
        verify_corresponding_source(lock, source)
        notices = collect_notices(source, {item["source_package"] for item in packages})
    else:
        notices = []
    output.mkdir(mode=0o755)
    try:
        licenses_dir = output / "LICENSES"
        notices_dir = output / "upstream-notices"
        licenses_dir.mkdir()
        notices_dir.mkdir()
        for identifier in sorted(license_ids):
            (licenses_dir / f"{identifier}.txt").write_bytes(canonical[identifier])
        notice_inventory: list[dict[str, str]] = []
        for item in notices:
            source_package = str(item["source_package"])
            relative = safe_member_path(str(item["path"]))
            content = item["content"]
            if not isinstance(content, bytes):
                raise BundleError("internal notice representation is invalid")
            destination = notices_dir / source_package / Path(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                raise BundleError(f"duplicate upstream legal file destination: {destination}")
            destination.write_bytes(content)
            notice_inventory.append(
                {
                    "path": destination.relative_to(output).as_posix(),
                    "sha256": sha256_bytes(content),
                    "source_package": source_package,
                }
            )
        inventory = {
            "alpine_version": version,
            "license_ids": sorted(license_ids),
            "notice_discovery": {
                "archive_formats": ["tar", "zip"],
                "filename_rule": LEGAL_NAME.pattern,
                "scheme": "conventional-legal-filenames-v1",
            },
            "packages": packages,
            "schema": 1,
            "spdx_license_list_version": spdx_version,
            "source_verified": source is not None,
            "upstream_notices": notice_inventory,
        }
        (output / "inventory.json").write_text(
            json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except Exception:
        shutil.rmtree(output)
        raise


def verify_bundle(
    lock: Path, bundle: Path, license_text_directory: Path, require_source_notices: bool
) -> None:
    version, packages, license_ids = package_inventory(lock)
    spdx_version, canonical = load_license_texts(license_text_directory)
    inventory = read_json(bundle / "inventory.json")
    expected_fixed = {
        "alpine_version": version,
        "license_ids": sorted(license_ids),
        "packages": packages,
        "schema": 1,
        "spdx_license_list_version": spdx_version,
    }
    for key, expected in expected_fixed.items():
        if inventory.get(key) != expected:
            raise BundleError(f"Alpine legal inventory mismatch: {key}")
    source_verified = inventory.get("source_verified")
    if not isinstance(source_verified, bool) or (require_source_notices and not source_verified):
        raise BundleError("Alpine legal bundle lacks verified source-derived notices")
    expected_discovery = {
        "archive_formats": ["tar", "zip"],
        "filename_rule": LEGAL_NAME.pattern,
        "scheme": "conventional-legal-filenames-v1",
    }
    if inventory.get("notice_discovery") != expected_discovery:
        raise BundleError("Alpine notice-discovery contract mismatch")
    licenses_dir = bundle / "LICENSES"
    actual_license_files = {
        path.name for path in licenses_dir.iterdir() if path.is_file() and not path.is_symlink()
    }
    expected_license_files = {f"{identifier}.txt" for identifier in license_ids}
    if actual_license_files != expected_license_files:
        raise BundleError("canonical Alpine license-text coverage mismatch")
    for identifier in sorted(license_ids):
        path = licenses_dir / f"{identifier}.txt"
        if path.read_bytes() != canonical[identifier]:
            raise BundleError(f"packaged canonical license text mismatch: {identifier}")
    records = inventory.get("upstream_notices")
    if not isinstance(records, list):
        raise BundleError("Alpine upstream-notice inventory is invalid")
    expected_notice_paths: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise BundleError("invalid Alpine upstream-notice record")
        relative = record.get("path")
        expected = record.get("sha256")
        if not isinstance(relative, str) or not relative.startswith("upstream-notices/"):
            raise BundleError("unsafe Alpine upstream-notice inventory path")
        safe = safe_member_path(relative)
        path = bundle / Path(*safe.parts)
        if path.is_symlink() or not path.is_file() or sha256_bytes(path.read_bytes()) != expected:
            raise BundleError(f"packaged Alpine upstream notice mismatch: {relative}")
        if relative in expected_notice_paths:
            raise BundleError(f"duplicate Alpine upstream notice: {relative}")
        expected_notice_paths.add(relative)
    notices_dir = bundle / "upstream-notices"
    actual_notice_paths = {
        path.relative_to(bundle).as_posix()
        for path in notices_dir.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    if actual_notice_paths != expected_notice_paths:
        raise BundleError("packaged Alpine upstream-notice coverage mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--license-texts",
        type=Path,
        default=Path(__file__).resolve().parent / "alpine-license-texts",
    )
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--require-source-notices", action="store_true")
    parser.add_argument("lock", type=Path)
    parser.add_argument("source_or_bundle")
    parser.add_argument("output", type=Path, nargs="?")
    args = parser.parse_args()
    try:
        if args.verify:
            if args.output is not None:
                raise BundleError("verify mode takes only a lock and bundle")
            verify_bundle(
                args.lock,
                Path(args.source_or_bundle),
                args.license_texts,
                args.require_source_notices,
            )
        else:
            if args.output is None:
                raise BundleError("bundle generation requires an output directory")
            source = None if args.source_or_bundle == "-" else Path(args.source_or_bundle)
            write_bundle(args.lock, source, args.output, args.license_texts)
    except (BundleError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"Alpine legal bundle failed: {error}", file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
