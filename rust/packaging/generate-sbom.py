#!/usr/bin/env python3
"""Generate a deterministic SPDX 2.3 SBOM for a target CDM runtime."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def spdx_id(kind: str, name: str, version: str) -> str:
    digest = hashlib.sha256(f"{kind}\0{name}\0{version}".encode()).hexdigest()[:16]
    safe_name = re.sub(r"[^A-Za-z0-9.-]", "-", name)
    return f"SPDXRef-{kind}-{safe_name}-{digest}"


def package(kind: str, name: str, version: str, license_name: str, purl: str) -> dict:
    return {
        "SPDXID": spdx_id(kind, name, version),
        "name": name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": license_name or "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ],
    }


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: generate-sbom.py <target-triple> <output.json>")
    target, output_name = sys.argv[1:]
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=ROOT
        )
    )
    rootfs = json.loads((ROOT / "assets/alpine-rootfs.lock.json").read_text())
    selected_arch = "aarch64" if target.startswith("aarch64-") else "x86_64"
    alpine = next(item for item in rootfs["rootfs"] if item["architecture"] == selected_arch)

    packages = []
    root_package_id = metadata["resolve"]["root"]
    for item in sorted(metadata["packages"], key=lambda value: (value["name"], value["version"])):
        license_name = item.get("license") or "NOASSERTION"
        if item["id"] == root_package_id and not item.get("license") and item.get("license_file"):
            if Path(item["license_file"]).resolve() == (ROOT.parent / "LICENSE").resolve():
                license_name = "LicenseRef-CDM"
        packages.append(
            package(
                "Cargo",
                item["name"],
                item["version"],
                license_name,
                f"pkg:cargo/{item['name']}@{item['version']}",
            )
        )
    for item in alpine["packages"]:
        packages.append(
            package(
                "Alpine",
                item["name"],
                item["version"],
                item["license"],
                f"pkg:apk/alpine/{item['name']}@{item['version']}?arch={selected_arch}",
            )
        )

    versions = {}
    for line in (ROOT / "packaging/versions.env").read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            versions[key] = value
    packages.extend(
        [
            package("Runtime", "libkrun", versions["LIBKRUN_VERSION"], "Apache-2.0", f"pkg:github/containers/libkrun@{versions['LIBKRUN_VERSION']}"),
            package("Runtime", "libkrunfw", versions["LIBKRUNFW_VERSION"], "GPL-2.0-only AND LGPL-2.1-only", f"pkg:github/containers/libkrunfw@{versions['LIBKRUNFW_VERSION']}"),
            package("Runtime", "linux", versions["LINUX_VERSION"], "GPL-2.0-only", f"pkg:generic/linux@{versions['LINUX_VERSION']}"),
        ]
    )

    cdm = next(item for item in packages if item["name"] == "cdm")
    fingerprint = hashlib.sha256(
        json.dumps(packages, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    created = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    relationships = [
        {
            "spdxElementId": cdm["SPDXID"],
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": item["SPDXID"],
        }
        for item in packages
        if item["SPDXID"] != cdm["SPDXID"]
    ]
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"cdm-{cdm['versionInfo']}-{target}",
        "documentNamespace": f"https://spdx.org/spdxdocs/cdm-{cdm['versionInfo']}-{target}-{fingerprint}",
        "creationInfo": {"created": created, "creators": ["Tool: cdm-generate-sbom"]},
        "documentDescribes": [cdm["SPDXID"]],
        "packages": packages,
        "relationships": relationships,
    }
    first_party_license = ROOT.parent / "LICENSE"
    if first_party_license.is_file() and not first_party_license.is_symlink():
        license_id = "SPDXRef-File-LICENSE"
        document["files"] = [
            {
                "SPDXID": license_id,
                "fileName": "./LICENSE",
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": hashlib.sha256(first_party_license.read_bytes()).hexdigest(),
                    }
                ],
                "licenseConcluded": "NOASSERTION",
                "licenseInfoInFiles": ["NOASSERTION"],
                "copyrightText": "NOASSERTION",
                "fileTypes": ["TEXT"],
            }
        ]
        relationships.append(
            {
                "spdxElementId": cdm["SPDXID"],
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": license_id,
            }
        )
        if cdm["licenseDeclared"] == "LicenseRef-CDM":
            document["hasExtractedLicensingInfos"] = [
                {
                    "licenseId": "LicenseRef-CDM",
                    "extractedText": first_party_license.read_text(encoding="utf-8"),
                    "name": "CDM first-party license",
                }
            ]
    Path(output_name).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
