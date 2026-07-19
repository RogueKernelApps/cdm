#!/usr/bin/env python3
"""Emit a deterministic in-toto/SLSA provenance statement for a CDM release set."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def key_value(value: str) -> tuple[str, str]:
    key, separator, item = value.partition("=")
    if not separator or not key or not item:
        raise argparse.ArgumentTypeError("expected NAME=VALUE")
    return key, item


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--subject", action="append", required=True, type=Path)
    parser.add_argument("--material", action="append", default=[], type=key_value)
    parser.add_argument("--tool", action="append", default=[], type=key_value)
    parser.add_argument("--evidence", action="append", default=[], type=key_value)
    args = parser.parse_args()

    subjects = [
        {"name": path.name, "digest": {"sha256": sha256(path)}}
        for path in sorted(args.subject, key=lambda item: item.name)
    ]
    materials = [
        {"uri": uri, "digest": {"sha256": digest}}
        for uri, digest in sorted(args.material)
    ]
    materials.append(
        {
            "uri": "urn:cdm:source:git",
            "digest": {"gitCommit": args.source_revision},
        }
    )
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://cdm.dev/buildtypes/release/v1",
                "externalParameters": {
                    "sourceDateEpoch": args.source_date_epoch,
                    "target": args.target,
                    "version": args.version,
                },
                "internalParameters": {
                    "evidenceDigests": dict(sorted(args.evidence)),
                    "toolchain": dict(sorted(args.tool)),
                },
                "resolvedDependencies": sorted(materials, key=lambda item: item["uri"]),
            },
            "runDetails": {
                "builder": {"id": "https://cdm.dev/builders/package.sh/v1"},
                "metadata": {},
            },
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(f".{args.output.name}.tmp")
    temporary.write_text(json.dumps(statement, indent=2, sort_keys=True) + "\n")
    temporary.replace(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
