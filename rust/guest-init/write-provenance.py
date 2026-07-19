#!/usr/bin/env python3
"""Write deterministic build-input provenance beside a guest-init binary."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit("usage: write-provenance.py BINARY TARGET CARGO_LOCK")
    binary = Path(sys.argv[1]).resolve(strict=True)
    target = sys.argv[2]
    lock = Path(sys.argv[3]).resolve(strict=True)
    source_root = Path(__file__).resolve().parent
    sources = [
        source_root / "Cargo.toml",
        lock,
        source_root / "build-static.sh",
        source_root / "schema-v2.json",
        source_root / "write-provenance.py",
        *sorted((source_root / "src").glob("*.rs")),
    ]
    document = {
        "schema": 1,
        "artifact": {
            "name": binary.name,
            "sha256": digest(binary),
            "size": binary.stat().st_size,
            "target": target,
        },
        "inputs": [
            {
                "path": source.relative_to(source_root).as_posix(),
                "sha256": digest(source),
            }
            for source in sources
        ],
        "source_date_epoch": int(os.environ.get("SOURCE_DATE_EPOCH", "0")),
    }
    output = binary.with_suffix(binary.suffix + ".provenance.json")
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
