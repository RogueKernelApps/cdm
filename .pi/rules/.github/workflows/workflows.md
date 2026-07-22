---
kind: rules
paths:
  - '.github/workflows/**/*'
summary: Changing CI, guest-init checks, dependency freshness, or target-native release composition.
triggers:
  - GitHub Actions
  - CI failure
  - release workflow
  - dependency freshness
---

# GitHub Workflows

Workflows separate fast repository contracts from target-native release acceptance. `ci.yml` owns native/VM-feature compile, test, lint, MSRV, integration, and audit gates; `guest-init.yml` checks the independent guest artifact contract. Release composition builds target-specific candidates, requires exact-package acceptance, then attests and publishes only complete outputs. Scheduled freshness checks report drift but do not silently update pinned runtime inputs.

### Patterns & Conventions

- Keep repository-wide token permissions read-only; grant write permissions only to the job that requires them.
- Never infer runnable VM support from feature compilation. macOS and Linux AArch64 release candidates require their designated target-native acceptance runners.
- Preserve checksum/provenance verification between build, acceptance, finalization, attestation, and publication jobs so each stage consumes the exact accepted bytes.
- Tag releases only as `v` plus the Cargo version. A failed target must prevent partial publication.
- Follow `rust/packaging/` rules when workflow changes alter release inputs, package composition, signing, legal payloads, or public assets.
