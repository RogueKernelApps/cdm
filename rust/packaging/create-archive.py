#!/usr/bin/env python3
"""Create a byte-reproducible gzip-compressed tar archive."""

from __future__ import annotations

import gzip
import os
import sys
import tarfile
from pathlib import Path


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"cdm archive: {message}")


def main() -> int:
    if len(sys.argv) != 4:
        fail("usage: create-archive.py <source-directory> <archive> <root-name>")
    source = Path(sys.argv[1]).resolve()
    archive = Path(sys.argv[2]).resolve()
    root_name = sys.argv[3].strip("/")
    if not source.is_dir() or not root_name or "/" in root_name:
        fail("source must be a directory and root-name a single path component")

    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    archive.parent.mkdir(parents=True, exist_ok=True)
    temporary = archive.with_name(f".{archive.name}.{os.getpid()}.tmp")
    with temporary.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as output:
                paths = [source, *sorted(source.rglob("*"), key=lambda path: path.as_posix())]
                for path in paths:
                    relative = path.relative_to(source)
                    archive_path = Path(root_name) / relative
                    info = output.gettarinfo(str(path), arcname=archive_path.as_posix())
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "root"
                    info.mtime = epoch
                    if info.isdir():
                        info.mode = 0o755
                    elif info.issym():
                        info.mode = 0o777
                    elif info.isfile():
                        info.mode = 0o755 if info.mode & 0o111 else 0o644
                    else:
                        fail(f"unsupported archive entry type: {relative}")
                    if info.isfile():
                        with path.open("rb") as contents:
                            output.addfile(info, contents)
                    else:
                        output.addfile(info)
    os.replace(temporary, archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
