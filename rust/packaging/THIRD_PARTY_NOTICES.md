# VM runtime notices

The VM-enabled CDM package contains:

- `libkrun`, licensed under Apache-2.0.
- `libkrunfw`, whose generated library code is LGPL-2.1-only and whose bundled Linux kernel and patches are GPL-2.0-only.
- An Alpine Linux 3.21.7 minirootfs. Its exact per-architecture binary-package
  inventory, declared license expressions, APK checksums, source-package
  identities, and build commits are recorded in
  `share/licenses/alpine/inventory.json`.

CDM builds libkrun from the pinned upstream source with the accompanying
`libkrun-relative-firmware.patch`. The patch changes only the libkrunfw lookup
filename to a package-relative loader path; it is included, checksummed, and
described in the corresponding-source archive.

For Alpine, `share/licenses/alpine/LICENSES/` contains the canonical SPDX text
for every license identifier declared by the embedded packages. Exact copyright,
license, and notice files found in the verified aports directories and upstream
distfiles are preserved byte-for-byte under
`share/licenses/alpine/upstream-notices/`; their SHA-256 values and source-package
attribution are in the inventory. The canonical texts are pinned to SPDX License
List 3.28.0. The package build verifies both their committed checksums and the
generated legal bundle before publication.

The matching `cdm-<version>-source-<platform>.tar.gz` release asset distributed
beside the runtime package contains the exact libkrun, libkrunfw, Linux kernel,
and Alpine package sources used for the build. Do not redistribute the runtime
archive without its matching source archive. See the license files under
`share/licenses/` and the source archive's `MANIFEST.txt`.

Upstream projects:

- https://github.com/libkrun/libkrun
- https://github.com/libkrun/libkrunfw
- https://kernel.org/
- https://alpinelinux.org/
- https://github.com/spdx/license-list-data/tree/v3.28.0
