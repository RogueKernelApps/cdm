---
kind: rules
paths:
  - 'specs/**/*'
summary: Maintaining CDM's versioned, normative observable-behavior contract.
triggers:
  - update the spec
  - change CLI semantics
  - change sandbox behavior
  - change security guarantees
---

# Specifications

`SPEC.md` defines expected behavior rather than implementation structure. Update it whenever a change affects commands, flags, configuration precedence, filesystem or network policy, secret handling, adapter guarantees, VM behavior, reports, monitoring, exit codes, or documented defaults. Keep claims enforceable across the supported adapters, and label limitations instead of implying guarantees the runtime cannot provide.

### Patterns & Conventions

- Keep the specification version aligned with the Cargo package version and release documentation.
- Describe externally observable outcomes and fail-closed behavior; put module ownership and trust-boundary explanations in `ARCHITECTURE.md` instead.
- Update the relevant tests and user guide with contract changes, then run the documentation validator.
- Preserve explicit distinctions between defaults, opt-in hardening, unconditional integrity invariants, and platform-specific constraints.
