# VM release packaging

`package.sh` is the sole release interface for VM-enabled CDM artifacts. It downloads checksum-pinned stable upstream inputs, builds the host target, creates a relocatable prefix layout, verifies it, and emits the corresponding-source archive required by libkrunfw's licenses.

## Implemented release targets

| Host/target | Minimum | Runtime lookup |
|---|---:|---|
| macOS AArch64 | macOS 14 | executable `@rpath`; libkrun firmware `@loader_path` |
| Linux x86_64 | Distribution-provided glibc compatible with the release builder | executable and firmware `$ORIGIN` paths |
| Linux AArch64 | Distribution-provided glibc compatible with the release builder | executable and firmware `$ORIGIN` paths |

Native-only CDM is not restricted to this VM matrix. libkrun supports macOS VM execution only on Apple silicon, so the packager rejects macOS x86_64 rather than producing a misleading artifact. Each architecture gets its own archive; these are not universal binaries.

The production GitHub Actions workflow builds each target on its matching host
architecture and requires package verification, relocation, installation, a real
VM boot, and the credential-free integration suite before publication.

## Build

```bash
cd rust
./packaging/prepare-alpine-sources-container.sh
export CDM_ALPINE_SOURCE_DIR="$PWD/target/alpine-corresponding-source-3.21.7"
./packaging/package.sh release  # runtime and verified corresponding source
./packaging/package.sh runtime  # local validation only; do not redistribute alone
./packaging/package.sh sources  # incomplete unless CDM_ALPINE_SOURCE_DIR is set
./packaging/package.sh verify-runtime target/dist/cdm-0.1.0-aarch64-apple-darwin aarch64-apple-darwin
./packaging/package.sh verify target/dist/cdm-0.1.0-aarch64-apple-darwin aarch64-apple-darwin # redistributable completeness
```

The output and adjacent `.sha256` files are under `target/dist/`. Downloads and upstream builds are cached under `target/package-work/` and remain ignored by Git.

Upstream libkrun loads libkrunfw by a bare filename. CDM applies the committed
`libkrun-relative-firmware.patch` to checksum-verified source before building,
using `@loader_path` on macOS and `$ORIGIN` on Linux. This prevents fallback to
Homebrew or another host installation. The exact patch is included in the
source companion and recorded as a provenance material.

Production `release` requires a clean Git worktree. On macOS it also requires an
explicit, non-ad-hoc `CDM_CODESIGN_IDENTITY`; an absent identity or `-` fails before
the build. Each signature makes up to three bounded attempts so an intermittent
Apple secure-timestamp response does not discard an otherwise valid build. CDM's
owner-approved MIT terms are recorded in the root `LICENSE` and
matching Cargo metadata. Third-party inventory and corresponding-source duties
remain independently enforceable.

The runtime archive contains the owner-approved root
`LICENSE` byte-for-byte. Package verification compares that copy with the source
and checks that the SPDX document declares the root crate's Cargo license metadata
and records the packaged license's SHA-256. `release` fails closed if any of those
three representations are absent or disagree.

Production `release` also requires `CDM_ALPINE_SOURCE_DIR` to name a prepared
payload that passes `verify-alpine-sources.py` against the committed schema-2
rootfs lock. The release copies that payload into the source companion and records
its manifest digest in provenance. Missing, stale, incomplete, extra, or modified
source-package content fails closed.

The same verified payload is used to build the Alpine legal-material bundle in
the runtime archive. `package-alpine-licenses.py` emits the exact binary-package
inventory, copies a checksum-pinned canonical SPDX text for every declared
license identifier, and recovers exact copyright, license, and notice files from
conventionally named files in the pinned aports directories and supported
checksum-verified upstream tar/ZIP distfiles. The inventory records this bounded
discovery rule rather than claiming arbitrary source files were legal notices. Release
verification rejects missing declarations, unknown license identifiers, changed
canonical texts, modified notices, extra notice files, or an incomplete bundle.
The source companion is still required: the extracted legal bundle complements,
but does not replace, complete corresponding source.

`runtime` retains ad-hoc signing for local Hypervisor-entitlement tests and must not
be published. If a release builder explicitly sets
`CDM_NOTARY_PROFILE`, CDM submits a temporary ZIP with `xcrun notarytool` using that
keychain profile, requires an `Accepted` response, and records the response beside
the archive. Command-line tarballs cannot carry a stapled ticket, so this is online
notarization rather than stapling.

macOS release builders need Rust, a C toolchain, `pkg-config`, `xz`, LLVM/libclang, `ld.lld`, and the matching `aarch64-unknown-linux-musl` Rust target used for the static guest init. The script uses `llvm-config`/`ld.lld` from `PATH`, with Homebrew discovery only as a release-builder convenience. End users do not need Homebrew.

Linux release builders need Rust, a C toolchain, `pkg-config`, and `patchelf`. Build on the oldest glibc baseline the release intends to support.

## Layout and signing

```text
cdm-<version>-<target>/
├── LICENSE
├── SBOM.spdx.json
├── bin/cdm
├── lib/cdm/libkrun...
├── lib/cdm/libkrunfw...
├── libexec/cdm/cdm-guest-init
├── share/cdm/guest-init.provenance.json
├── share/licenses/alpine/inventory.json
├── share/licenses/alpine/LICENSES/...
├── share/licenses/alpine/upstream-notices/...
├── share/licenses/libkrun/...
├── share/licenses/libkrunfw/...
├── THIRD_PARTY_NOTICES.md
└── install.sh
```

macOS install names are rewritten to `@rpath`; absolute development rpaths are removed. Libraries are signed first, then CDM is signed with `com.apple.security.hypervisor`. `package.sh` verifies the signatures and runtime paths before creating the archive.

The separately emitted `cdm-vm-sources-*.tar.gz` contains the exact checksum-pinned libkrun, libkrunfw, Linux kernel, and verified Alpine package sources. Publish it beside every runtime archive.

It also carries the exact embedded Alpine binary rootfs archives and their generated
schema-2 inventory. That inventory records installed packages, source-package
names, APK checksums, and Alpine build commits. For every unique source package,
the prepared source payload contains its aports directory from that exact build
commit and every upstream distfile downloaded and checksum-verified by the
official `abuild fetch` path. The independent verifier requires exact lock
coverage and validates a deterministic SHA-256 manifest before release.

The committed canonical Alpine texts under `packaging/alpine-license-texts/` are
pinned to SPDX License List 3.28.0 and a specific upstream commit; their manifest
records every SHA-256. They are not a hand-maintained claim about the contents of
the rootfs: the generator selects them only from the exact license expressions in
`assets/alpine-rootfs.lock.json`. Package-specific legal files come only from the
verified corresponding-source payload and remain byte-exact.

### Preparing Alpine sources

The host wrapper runs the acquisition tool in the official Alpine 3.21.7 image,
pinned by multi-architecture OCI digest in `versions.env`:

```bash
cd rust
./packaging/prepare-alpine-sources-container.sh
python3 packaging/verify-alpine-sources.py verify \
  assets/alpine-rootfs.lock.json \
  target/alpine-corresponding-source-3.21.7
```

The output path must not already exist. The tool derives and clones the official
Alpine `3.21-stable` aports branch from the pinned `3.21.7` environment, checks
out each exact per-package commit from the rootfs lock, runs `abuild validate`,
validates `pkgname` and `pkgver-pkgrel`, copies the complete APKBUILD directory,
and runs `abuild fetch` (with three bounded attempts for transient network
failure) followed by `abuild verify` with a package-private `SRCDEST`. Any
checkout, version, exhausted download, checksum, coverage, or manifest
failure removes only the newly created output and exits unsuccessfully.

To run without Docker, install `abuild`, `git`, and `python3` in an exact Alpine
3.21.7 environment and invoke the Alpine-native tool directly:

```sh
packaging/fetch-alpine-sources.sh \
  assets/alpine-rootfs.lock.json \
  target/alpine-corresponding-source-3.21.7
```

Do not substitute a floating Alpine tag or a different release. Do not describe a
standalone `package.sh sources` result as complete unless the verified Alpine
payload was supplied.

The manual **Alpine corresponding source** GitHub Actions workflow runs the same
pinned container path, re-verifies the result, and uploads a deterministic archive
plus checksum. It is an acquisition aid, not a release bypass: production
`package.sh release` still verifies the unpacked payload supplied locally.

## Reproducibility and provenance

Release builds start from freshly extracted libkrun/libkrunfw source trees and a
fresh, target-specific Cargo output directory. Downloaded inputs may be reused only
after their pinned SHA-256 is rechecked; compiled runtime or CDM artifacts are never
reused across package invocations. Cargo incremental compilation is disabled and
the checkout, Cargo-home, and builder-home paths are remapped before compiling.
Verification rejects a binary that still contains the absolute repository path.
Runtime and source tarballs use sorted entries, normalized root ownership,
canonical modes (`0755` for directories and executables, `0644` for other regular
files, and `0777` for symlinks), and `SOURCE_DATE_EPOCH` (zero by default) for tar
and gzip timestamps. Their bytes therefore do not depend on the builder's umask.

After both archives are complete, `release` writes
`cdm-<version>-<target>.provenance.intoto.json` and its checksum. The deterministic
in-toto Statement v1 / SLSA provenance v1 document names both archives as subjects
with their SHA-256 values and records the Git revision, root and guest-init Cargo
inputs, pinned Rust toolchain file, build script, owner-approved first-party
license, libkrun, libkrunfw, firmware, Linux, per-architecture Alpine inputs, and
the verified Alpine source manifest as resolved materials. It also records the
actual `rustc`, Cargo, and Make version strings, `SOURCE_DATE_EPOCH`, and SHA-256
evidence for the packaged SBOM and guest-init provenance. `SBOM.spdx.json` inside
the runtime package inventories Cargo, VM runtime, and selected Alpine packages.
The provenance file is an attestation payload, not by itself a signature. The
production workflow passes the archives, provenance, and checksums to the pinned
`actions/attest` action after target-native acceptance. GitHub uses a short-lived
OIDC-backed Sigstore certificate, so this step needs workflow permissions rather
than a long-lived signing secret. Each target publishes a
`cdm-<version>-<target>.sigstore.jsonl` bundle beside its artifacts. Consumers can
verify an archive directly with, for example:

```bash
gh attestation verify cdm-<version>-<target>.tar.gz \
  --repo RogueKernel/cdm \
  --bundle cdm-<version>-<target>.sigstore.jsonl \
  --signer-workflow RogueKernel/cdm/.github/workflows/release-composition.yml
```

Public repositories additionally persist the attestation in GitHub's API, where
the bundle flag is optional. GitHub does not provide that storage API for a
user-owned private repository, so the production workflow disables only the
storage record in that state; OIDC signing and the downloadable bundle remain
mandatory.

The **Production release composition** workflow runs the metadata tests, acquires
and verifies Alpine corresponding source, composes the complete release, checks
dependency closure and relocation, validates every checksum and provenance field,
then runs the credential-free integration matrix against that exact package with
both native and VM adapters required. Only accepted outputs are cryptographically
attested and uploaded.

A manual workflow run stops after uploading the accepted Actions artifacts. A tag
push matching `v*` additionally verifies that the tag is exactly `v` plus the
version in `rust/Cargo.toml`. After all three target jobs succeed, the workflow
creates a draft GitHub Release, verifies and uploads the complete runtime,
corresponding-source, provenance, checksum, and optional notarization-response
asset set plus each target's Sigstore bundle, and publishes the release. A failed target
therefore cannot produce a partial public release. Release binaries are generated
artifacts and must not be committed to Git.

### GitHub release setup

The Linux x86_64 and AArch64 packages build on GitHub-hosted `ubuntu-22.04` and
`ubuntu-22.04-arm` runners. Ubuntu 22.04 supplies a deliberate, older glibc
release baseline instead of inheriting a maintainer workstation's distribution
version. The x86_64 runner exposes KVM after the workflow grants its ephemeral
runner user access to `/dev/kvm`, so it accepts the exact package in place.

GitHub-hosted Linux AArch64 does not expose nested KVM. Register one dedicated
Linux AArch64 acceptance runner with the exact labels `self-hosted`, `Linux`,
`ARM64`, and `cdm-release`. It needs a trusted `/usr/bin/bwrap`, read/write
`/dev/kvm`, and enough temporary space to download and unpack one candidate. The
hosted runner still performs the expensive build. GitHub stores that output as an
immutable candidate artifact; the AArch64 runner verifies its checksums, unpacks
and accepts the exact package, and a hosted finalizer downloads that same
candidate for Sigstore attestation and release upload. A failed or unavailable
acceptance runner therefore cannot produce a publishable Linux AArch64 artifact.

GitHub-hosted ARM macOS runners cannot provide the nested virtualization needed
to boot CDM's libkrun package. Register one Apple-silicon runner with the exact
labels `self-hosted`, `macOS`, `ARM64`, and `cdm-release`. It needs the macOS build
tools documented above, Docker for acquiring exact Alpine corresponding source,
and permission to run a real libkrun microVM. Keep it dedicated and ephemeral
where practical because release jobs execute repository code.

Install self-hosted runners beneath a neutral, non-personal work path and give
their service a neutral `HOME`; GitHub publishes action logs for public
repositories, including paths printed by checkout and build tools. Keep runner
registration credentials mode 0600 and never place signing material in the
runner directory. The workflow imports the macOS identity from encrypted Actions
secrets into a disposable keychain instead. The maintained runner layout uses
`/Users/Shared/cdm-github-runners/cdm-macos-arm64` on macOS with
`/Users/Shared/cdm-github-runners/home` as its service `HOME`, and
`/opt/cdm-github-runners/cdm-linux-arm64` on Linux AArch64 with
`/opt/cdm-github-runners/home` as its service `HOME`.

The workflow uses a run-specific Cargo home and always removes its Cargo cache,
package target tree, and temporary release journeys after accepted artifacts have
been uploaded or after a failed job. The Linux AArch64 acceptance job likewise
removes downloaded candidates and release journeys. This cleanup prevents build
products from accumulating on persistent runners.

Export only the Developer ID Application certificate and private key as a
password-protected PKCS #12 file. Add its single-line Base64 representation as the
`CDM_CERTIFICATE_P12` repository Actions secret and its export password as
`CDM_CERTIFICATE_PASSWORD`. The workflow imports that identity into a run-specific
keychain, derives its non-personal SHA-1 identity from the imported keychain,
grants only Apple's signing tools access, verifies a timestamped probe signature
before the expensive build, and deletes the keychain after success or failure.
It suppresses certificate labels in public action logs and does not depend on the
runner user's login keychain or a separate identity-name secret. Both the probe
and package signer pass that disposable keychain explicitly through
`CDM_CODESIGN_KEYCHAIN`, so signing does not depend on per-user keychain search
preferences.

To require Apple notarization, store credentials on the runner with
`xcrun notarytool store-credentials`, then add the optional
`CDM_NOTARY_PROFILE` repository secret containing that keychain profile name.
With no notary-profile secret, the package is still Developer ID signed but is
not submitted for notarization.

The publish job alone requests `contents: write`; keep the repository-wide default
token permission read-only. The repository or organization policy must permit that
job-level grant. GitHub OIDC supplies the short-lived Sigstore identity used by
`actions/attest`; no long-lived Linux signing key is required.

For a release, update `rust/Cargo.toml` and `rust/Cargo.lock` together, merge that
change, then create and push the matching tag. For example, version `0.2.0` must be
tagged `v0.2.0`. The tag workflow performs all builds, signing, verification,
attestation, and publication; maintainers do not build or commit release binaries.

## Install lifecycle

The bundled installer owns only `bin/cdm`, the runtime libraries it records, and
`lib/cdm/install-manifest.sha256` under the selected prefix. The manifest records
the SHA-256 of every owned payload, so verification and removal do not rely on a
filename glob.

```bash
./install.sh install                 # $HOME/.local (also the no-argument default)
./install.sh install "/custom/prefix"
./install.sh verify "/custom/prefix"
./install.sh uninstall "/custom/prefix"
```

`./install.sh PREFIX` remains a shorthand for installation. Reinstalling the same
package repairs its owned files; installing a different package upgrades them and
removes files owned only by the previous manifest. Unrelated files are preserved,
and an unowned destination collision stops before promotion. Installation stages
payloads on the prefix filesystem, backs up the previous owned set, promotes
libraries before the executable, and performs best-effort rollback on failure or
interruption. Uninstall refuses to remove an owned file whose hash changed; repair
it with `install` first if replacement is intentional.

Before install, verify, upgrade, or removal, the installer walks the prefix without
following symlinks. Every existing component must be a directory owned by root or
the invoking user and must not be group/other writable (root-owned sticky temporary
roots are the narrow exception). Managed directories and files must not be
symlinks; managed files, including the ownership manifest, must have exactly one
hard link and be owned by the invoking user. These checks make the prefix an
exclusive rename boundary and reject hostile parent paths before staging or
promotion. The shell transaction revalidates the managed tree immediately before
promotion; it assumes processes running as the same UID are trusted, while
preventing a different local user from winning a path-replacement race.

## Verification

```bash
cd rust
bash packaging/tests.sh
./packaging/package.sh verify target/dist/cdm-<version>-<target> <target>
(cd target/dist && shasum -a 256 -c ./*.sha256) # macOS
for provenance in target/dist/*.provenance.intoto.json; do
  python3 -m json.tool "$provenance" >/dev/null
done
```

`package.sh verify` recursively checks bundled libkrun/libkrunfw dependency edges,
rejects absolute or unresolved package references and build-host rpaths, verifies
macOS signatures and the Hypervisor entitlement, checks Linux `DT_NEEDED`/RPATH,
and runs `cdm --version` from a copied path containing spaces with loader override
variables removed. Also install the package into a disposable prefix and run a
real `--vm` command from the relocated binary. Production composition also
sets `CDM_OCI_SMOKE_TESTS=1`, requiring an Alpine 3.21 registry pull and boot
through the exact package; the broader OCI matrix remains opt-in. Follow `AGENTS.md` in this
directory for the release invariants.
