#!/usr/bin/env python3
import argparse
import gzip
import hashlib
import pathlib
import re
import shutil
import tarfile
import tempfile


TARGETS = {
    "aarch64-apple-darwin": "macos-arm64",
    "x86_64-unknown-linux-gnu": "linux-x86_64",
    "aarch64-unknown-linux-gnu": "linux-arm64",
}


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_one(paths: list[pathlib.Path], description: str) -> pathlib.Path:
    if len(paths) != 1:
        raise SystemExit(f"expected exactly one {description}, found {len(paths)}")
    return paths[0]


def verify_checksum(path: pathlib.Path) -> None:
    checksum_path = path.with_name(f"{path.name}.sha256")
    if not checksum_path.is_file() or checksum_path.is_symlink():
        raise SystemExit(f"missing checksum for {path.name}")
    fields = checksum_path.read_text(encoding="utf-8").strip().split()
    if len(fields) != 2 or fields[1] != path.name or not re.fullmatch(r"[0-9a-f]{64}", fields[0]):
        raise SystemExit(f"invalid checksum file for {path.name}")
    if sha256(path) != fields[0]:
        raise SystemExit(f"checksum mismatch for {path.name}")


def write_verification_archive(
    output: pathlib.Path,
    version: str,
    metadata: list[pathlib.Path],
    mappings: list[tuple[str, str]],
) -> None:
    root_name = f"cdm-{version}-verification"
    with tempfile.TemporaryDirectory(prefix="cdm-verification-") as temporary:
        root = pathlib.Path(temporary) / root_name
        root.mkdir()
        readme = [
            "# CDM release verification files",
            "",
            "These files are optional verification evidence; they are not required to install CDM.",
            "The public archives below are byte-identical copies of the target-triple build outputs",
            "named in the provenance and Sigstore bundles.",
            "",
        ]
        readme.extend(f"- `{public}` → `{original}`" for public, original in mappings)
        readme.append("")
        (root / "README.md").write_text("\n".join(readme), encoding="utf-8")
        for source in metadata:
            shutil.copy2(source, root / source.name)
        checksums = [
            f"{sha256(path)}  {path.name}"
            for path in sorted(root.iterdir(), key=lambda item: item.name)
            if path.name != "SHA256SUMS"
        ]
        (root / "SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="utf-8")

        with output.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
                        relative = pathlib.Path(root_name) / path.relative_to(root)
                        info = archive.gettarinfo(str(path), arcname=relative.as_posix())
                        info.uid = 0
                        info.gid = 0
                        info.uname = "root"
                        info.gname = "root"
                        info.mtime = 0
                        if info.isfile():
                            info.mode = 0o644
                            with path.open("rb") as source:
                                archive.addfile(info, source)
                        else:
                            info.mode = 0o755
                            archive.addfile(info)


def assemble(version: str, artifacts: pathlib.Path, installer: pathlib.Path, output: pathlib.Path) -> None:
    version = version.removeprefix("v")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[+-][0-9A-Za-z.-]+)?", version):
        raise SystemExit(f"invalid release version: {version}")
    if output.exists():
        raise SystemExit(f"release output already exists: {output}")
    if not artifacts.is_dir() or artifacts.is_symlink():
        raise SystemExit(f"invalid artifact directory: {artifacts}")
    if not installer.is_file() or installer.is_symlink():
        raise SystemExit(f"invalid release installer: {installer}")
    output.mkdir(parents=True)

    files = [
        path
        for artifact in artifacts.iterdir()
        if artifact.is_dir() and not artifact.is_symlink()
        for path in artifact.iterdir()
        if path.is_file() and not path.is_symlink()
    ]
    metadata: list[pathlib.Path] = []
    mappings: list[tuple[str, str]] = []
    for target, platform in TARGETS.items():
        runtime_name = f"cdm-{version}-{target}.tar.gz"
        provenance_name = f"cdm-{version}-{target}.provenance.intoto.json"
        sigstore_name = f"cdm-{version}-{target}.sigstore.jsonl"
        runtime = require_one([path for path in files if path.name == runtime_name], runtime_name)
        provenance = require_one([path for path in files if path.name == provenance_name], provenance_name)
        sigstore = require_one([path for path in files if path.name == sigstore_name], sigstore_name)
        source = require_one(
            [
                path
                for path in files
                if path.name.startswith("cdm-vm-sources-")
                and path.name.endswith(f"-{target}.tar.gz")
            ],
            f"corresponding source for {target}",
        )
        for checked in (runtime, provenance, source):
            verify_checksum(checked)

        public_runtime = f"cdm-{version}-{platform}.tar.gz"
        public_source = f"cdm-{version}-source-{platform}.tar.gz"
        shutil.copy2(runtime, output / public_runtime)
        shutil.copy2(source, output / public_source)
        mappings.extend(((public_runtime, runtime.name), (public_source, source.name)))
        metadata.extend((provenance, sigstore))
        notarization = [path for path in files if path.name == f"{runtime_name}.notarization.json"]
        if len(notarization) > 1:
            raise SystemExit(f"duplicate notarization response for {target}")
        metadata.extend(notarization)

    verification = output / f"cdm-{version}-verification.tar.gz"
    write_verification_archive(verification, version, metadata, mappings)
    public_installer = output / "cdm-install.sh"
    shutil.copy2(installer, public_installer)
    public_installer.chmod(0o755)
    checksum_entries = [
        f"{sha256(path)}  {path.name}"
        for path in sorted(output.iterdir(), key=lambda item: item.name)
        if path.name != "SHA256SUMS"
    ]
    (output / "SHA256SUMS").write_text("\n".join(checksum_entries) + "\n", encoding="utf-8")
    expected_count = 9
    if len(list(output.iterdir())) != expected_count:
        raise SystemExit(f"expected {expected_count} public release files")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--artifacts", required=True, type=pathlib.Path)
    parser.add_argument("--installer", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    assemble(arguments.version, arguments.artifacts, arguments.installer, arguments.output)


if __name__ == "__main__":
    main()
