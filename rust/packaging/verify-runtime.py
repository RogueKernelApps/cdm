#!/usr/bin/env python3
"""Verify a packaged runtime's dependency closure and relocated execution."""

from __future__ import annotations

import argparse
import os
import plistlib
import shutil
import subprocess
import tempfile
from pathlib import Path


SYSTEM_DYLIB_PREFIXES = ("/System/Library/", "/usr/lib/")
LINUX_BUNDLED_NAMES = ("libkrun.so", "libkrunfw.so")
SYSTEM_ELF_PREFIXES = ("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/")
MAX_TOOL_OUTPUT = 1024 * 1024


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"cdm runtime verification: {message}")


def output(*command: str | Path, stderr: bool = False) -> str:
    environment = os.environ.copy()
    environment.pop("DYLD_LIBRARY_PATH", None)
    environment.pop("LD_LIBRARY_PATH", None)
    result = subprocess.run(
        [str(item) for item in command],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if stderr else subprocess.PIPE,
        text=True,
        env=environment,
        timeout=30,
    )
    if len(result.stdout) > MAX_TOOL_OUTPUT:
        fail(f"tool output exceeds {MAX_TOOL_OUTPUT} bytes: {command[0]}")
    return result.stdout


def package_file(package: Path, candidate: Path) -> Path:
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(package):
        fail(f"dependency resolves outside package: {candidate}")
    return resolved


def macos_dependencies(path: Path) -> list[str]:
    lines = output("otool", "-L", path).splitlines()[1:]
    return [line.strip().split(" (", 1)[0] for line in lines if line.strip()]


def macos_rpaths(path: Path) -> list[str]:
    lines = output("otool", "-l", path).splitlines()
    result: list[str] = []
    for index, line in enumerate(lines):
        if line.strip() == "cmd LC_RPATH":
            for following in lines[index + 1 : index + 5]:
                fields = following.strip().split()
                if fields[:1] == ["path"] and len(fields) >= 2:
                    result.append(fields[1])
                    break
    return result


def resolve_macos_reference(
    package: Path, executable: Path, loader: Path, reference: str, rpaths: list[str]
) -> Path | None:
    if reference.startswith(SYSTEM_DYLIB_PREFIXES):
        return None
    if reference.startswith("/"):
        fail(f"non-system absolute dependency: {reference}")
    if reference.startswith("@loader_path/"):
        return package_file(package, loader.parent / reference.removeprefix("@loader_path/"))
    if reference.startswith("@executable_path/"):
        return package_file(
            package, executable.parent / reference.removeprefix("@executable_path/")
        )
    if reference.startswith("@rpath/"):
        suffix = reference.removeprefix("@rpath/")
        candidates: list[Path] = []
        for item in rpaths:
            if item.startswith("@loader_path/"):
                candidates.append(loader.parent / item.removeprefix("@loader_path/") / suffix)
            elif item.startswith("@executable_path/"):
                candidates.append(
                    executable.parent / item.removeprefix("@executable_path/") / suffix
                )
            elif item.startswith("/"):
                fail(f"absolute LC_RPATH: {item}")
            else:
                fail(f"unsupported LC_RPATH: {item}")
        for candidate in candidates:
            if candidate.exists():
                return package_file(package, candidate)
        fail(f"unresolved packaged dependency: {reference}")
    fail(f"unsupported dependency reference: {reference}")


def verify_macos(package: Path) -> None:
    executable = package / "bin/cdm"
    libraries = sorted((package / "lib/cdm").glob("*.dylib"))
    if not libraries:
        fail("package has no dylibs")
    queue = [executable]
    visited: set[Path] = set()
    executable_rpaths = macos_rpaths(executable)
    for path in queue:
        if path in visited:
            continue
        visited.add(path)
        environment = os.environ.copy()
        environment.pop("DYLD_LIBRARY_PATH", None)
        environment.pop("LD_LIBRARY_PATH", None)
        subprocess.run(
            ["codesign", "--verify", "--strict", str(path)],
            check=True,
            env=environment,
            timeout=30,
        )
        own_rpaths = macos_rpaths(path)
        if path.name.startswith("libkrun."):
            firmware = package / "lib/cdm/libkrunfw.5.dylib"
            if b"@loader_path/libkrunfw.5.dylib" not in path.read_bytes():
                fail("libkrun does not use package-relative firmware lookup")
            if not firmware.is_file():
                fail("missing package-relative libkrun firmware")
            queue.append(firmware)
        for rpath in own_rpaths:
            if rpath.startswith("/"):
                fail(f"absolute LC_RPATH in {path.name}: {rpath}")
        for reference in macos_dependencies(path):
            resolved = resolve_macos_reference(
                package, executable, path, reference, [*own_rpaths, *executable_rpaths]
            )
            if resolved is not None and resolved.suffix == ".dylib" and resolved not in visited:
                queue.append(resolved)
    if not any(path.name.startswith("libkrunfw.") for path in visited):
        fail("libkrunfw is not in the transitive dependency closure")
    unused = set(libraries) - visited
    if unused:
        fail(f"unreferenced bundled dylib: {sorted(path.name for path in unused)[0]}")
    entitlements_raw = output(
        "codesign", "-d", "--entitlements", ":-", executable, stderr=True
    )
    start = entitlements_raw.find("<?xml")
    if start < 0:
        start = entitlements_raw.find("<plist")
    if start < 0:
        fail("CDM executable has no readable entitlements")
    entitlements = plistlib.loads(entitlements_raw[start:].encode())
    if entitlements.get("com.apple.security.hypervisor") is not True:
        fail("CDM executable is missing the Hypervisor entitlement")


def verify_linux(package: Path) -> None:
    executable = package / "bin/cdm"
    libraries = sorted((package / "lib/cdm").glob("*.so*"))
    by_name = {path.name: path for path in libraries if not path.is_symlink()}
    queue = [executable]
    visited: set[Path] = set()
    for path in queue:
        if path in visited:
            continue
        visited.add(path)
        rpath = output("patchelf", "--print-rpath", path).strip()
        if path.name.startswith("libkrun.so"):
            firmware = by_name.get("libkrunfw.so.5")
            if b"$ORIGIN/libkrunfw.so.5" not in path.read_bytes():
                fail("libkrun does not use package-relative firmware lookup")
            if firmware is None:
                fail("missing package-relative libkrun firmware")
            queue.append(firmware)
        if path == executable and rpath != "$ORIGIN/../lib/cdm":
            fail(f"unexpected executable rpath: {rpath}")
        if path != executable and rpath not in ("", "$ORIGIN"):
            fail(f"unexpected library rpath in {path.name}: {rpath}")
        for needed in output("patchelf", "--print-needed", path).splitlines():
            needed = needed.strip()
            if needed.startswith(LINUX_BUNDLED_NAMES):
                dependency = by_name.get(needed)
                if dependency is None:
                    fail(f"missing bundled dependency: {needed}")
                queue.append(dependency)
    if not any(path.name.startswith("libkrunfw.so") for path in visited):
        fail("libkrunfw is not in the transitive dependency closure")
    unused = set(by_name.values()) - visited
    if unused:
        fail(f"unreferenced bundled ELF library: {sorted(path.name for path in unused)[0]}")
    ldd = output("ldd", executable, stderr=True)
    if "not found" in ldd:
        fail("ldd reports an unresolved runtime dependency")
    for line in ldd.splitlines():
        fields = line.strip().split()
        if not fields:
            continue
        if "=>" in fields:
            index = fields.index("=>")
            if index + 1 >= len(fields):
                fail(f"malformed ldd result: {line}")
            resolved = fields[index + 1]
            if resolved == "not":
                fail("ldd reports an unresolved runtime dependency")
            resolved_path = Path(resolved).resolve(strict=True)
            if not resolved_path.is_relative_to(package) and not str(resolved_path).startswith(
                SYSTEM_ELF_PREFIXES
            ):
                fail(f"dependency resolved outside package/system roots: {resolved}")
            if fields[0].startswith(LINUX_BUNDLED_NAMES) and not resolved_path.is_relative_to(
                package
            ):
                fail(f"bundled dependency resolved outside package: {fields[0]}")
        elif fields[0].startswith("/"):
            resolved_path = Path(fields[0]).resolve(strict=True)
            if not str(resolved_path).startswith(SYSTEM_ELF_PREFIXES):
                fail(f"unexpected absolute loader dependency: {fields[0]}")


def verify_relocated_execution(package: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="cdm-relocation-") as temporary:
        relocated = Path(temporary) / "relocated package with spaces"
        shutil.copytree(package, relocated, symlinks=True)
        environment = os.environ.copy()
        environment.pop("DYLD_LIBRARY_PATH", None)
        environment.pop("LD_LIBRARY_PATH", None)
        result = subprocess.run(
            [str(relocated / "bin/cdm"), "--version"],
            cwd=temporary,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            fail(f"relocated executable failed with status {result.returncode}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("package", type=Path)
    args = parser.parse_args()
    package = args.package.resolve(strict=True)
    if args.target.endswith("apple-darwin"):
        verify_macos(package)
    elif args.target.endswith("unknown-linux-gnu"):
        verify_linux(package)
    else:
        fail(f"unsupported target: {args.target}")
    verify_relocated_execution(package)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
