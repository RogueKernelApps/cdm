---
kind: rules
paths:
  - 'rust/packaging/**/*'
summary: Building, verifying, signing, licensing, installing, or publishing target-specific VM runtime packages.
triggers:
  - release packaging
  - sign macOS runtime
  - corresponding source
  - package verification
  - installer change
---

# Release Packaging

`package.sh` is the sole public interface for VM-enabled release artifacts. Keep every upstream version and digest pinned in `versions.env`, and begin release compilation from fresh extracted sources and a fresh target-specific Cargo directory. Runtime lookup must remain package-relative with no Homebrew/build-host rpaths or loader-override requirements. Supported artifacts are target-specific, not universal.

### Patterns & Conventions

- `runtime` is for local validation and is not redistributable alone. A publishable release also requires exact corresponding source, notices, legal inventory, SBOM, checksums, and provenance.
- Verify downloaded inputs before reuse; never replace pinned acquisition with floating tags or unverified fallbacks.
- Sign macOS libraries before the CDM executable and retain the Hypervisor entitlement. Ad-hoc signing is local-only.
- Keep guest-init bytes, digest, target, static-link evidence, and provenance matched through build, embedding, package layout, and verification.
- Preserve deterministic archives, canonical modes, normalized ownership/timestamps, path remapping, and exact first-party license agreement across Cargo metadata, package contents, and SBOM.
- Installer operations must reject unsafe parents, links, ownership, permissions, and modified owned files; preserve unrelated files and rollback best-effort on interrupted promotion.
- Before calling an artifact complete, run packaging metadata tests, full package verification, checksum/relocation/linkage inspection, installation tests, and a real packaged VM smoke test.
