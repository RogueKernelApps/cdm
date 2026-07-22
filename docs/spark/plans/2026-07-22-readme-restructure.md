# README Restructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use spark:subagent-driven-development (recommended) or spark:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the CDM README so developers can understand and try the tool quickly, beginning with AI coding-agent workflows and progressing to stronger isolation controls.

**Architecture:** Keep `README.md` as the concise product and first-use page. Preserve `GETTING_STARTED.md`, `ARCHITECTURE.md`, and `specs/SPEC.md` as the detailed operational, architectural, and normative references; change them only if the README rewrite exposes a factual mismatch.

**Tech Stack:** Markdown, CDM's typed Rust CLI contract, Python documentation validator

## Global Constraints

- Lead with developers running AI coding agents while making clear that CDM wraps any developer command.
- Begin examples with `cd ~/my_dev_project/` and use `./project_acme` for project-directory arguments.
- Progress from ordinary commands to `--vm`/`--vmi`, then `--worktree`, then focused security controls.
- Give worktree and macOS desktop application modes distinct subsections.
- State that plain CDM is compatibility-oriented and is not a hostile-code boundary.
- State precisely that `--sec` implies `--scramble`; it does not imply `--ro`, `--iso`, or `--no-network`.
- Preserve the verified installer URL and the required `SHA256SUMS` statement.
- Do not alter architecture, specification, agent instructions, or rules without a concrete contract mismatch or missing durable convention.

---

### Task 1: Rewrite the README around progressive workflows

**Files:**

- Modify: `README.md:1-145`
- Reference: `docs/spark/specs/2026-07-22-readme-restructure-design.md`
- Reference: `specs/SPEC.md`
- Reference: `ARCHITECTURE.md`

**Interfaces:**

- Consumes: Existing documented CDM commands and flag semantics
- Produces: A concise first-use README that links to the existing detailed documents

- [ ] **Step 1: Replace the opening with the product promise and quick overview**

Use this message and keep the overview to one short paragraph:

```markdown
# CDM

> **Give coding agents room to work—without giving them your whole machine.**

CDM runs developer commands inside a host-native sandbox or an optional
libkrun microVM. Put `cdm` before an ordinary command, then add filesystem,
network, secret, or Git-worktree isolation when the command needs it.
```

Do not place the compatibility warning before the first examples; retain it prominently at the start of the later Security section.

- [ ] **Step 2: Add the easy first-use examples**

Insert this first example block:

````markdown
## Start with any command

```bash
cd ~/my_dev_project/

cdm copilot --allow-all
cdm pi
cdm claude
```

The command after `cdm` keeps its original argument boundaries. In the first
example, `--allow-all` is passed to Copilot—not interpreted by CDM.
````

Follow it with one sentence stating that CDM works with agents, package managers, test runners, scripts, and other developer tools.

- [ ] **Step 3: Add progressively stronger workflow examples**

Use separate, outcome-labelled subsections in this exact order:

````markdown
### Run inside a microVM

```bash
cdm --vm sh -c 'uname -a'
cdm --vmi ubuntu:24.04 bash
```

`--vm` uses CDM's bundled Alpine guest. `--vmi` starts from an OCI image.
Only the workspace and explicit grants are exposed to the guest.

### Let CDM handle the worktree

```bash
cdm --worktree claude
```

**No checkout juggling.** CDM copies the current Git-visible working state into
a temporary worktree, lets the agent edit it, and saves the result on a unique
`CDM__...` branch. The original checkout stays untouched, and useful changes
survive even when the command exits nonzero.

### Add only the controls you need

```bash
cdm --ro claude
cdm --iso --ro ./untrusted-checker
cdm --no-network python3 ./project_acme/audit.py
cdm --sec claude
cdm --sec --worktree claude
cdm --sec --iso --ro --no-network ./untrusted-checker
```
````

Give each command a concise explanation immediately below the block or in a small two-column table. Do not reintroduce the current exhaustive feature table before installation.

- [ ] **Step 4: Add a dedicated desktop application subsection**

Use this content:

````markdown
### Sandbox a macOS application

```bash
cdm "/Applications/Example.app"
```

CDM validates the app bundle and infers narrow, app-owned writable locations
instead of granting broad home-directory access. Selecting the bundle is the
trust decision: CDM does not run Gatekeeper, notarization, or code-signature
checks.
````

- [ ] **Step 5: Move installation after the examples and shorten it**

Retain the installer verbatim:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/RogueKernelApps/cdm/releases/latest/download/cdm-install.sh | bash
```

State:

- macOS 14+ on Apple silicon, Linux x86_64, and Linux ARM64 are supported.
- The installer verifies the selected runtime against the release's `SHA256SUMS`.
- The default prefix is `$HOME/.local`, and `$HOME/.local/bin` must be on `PATH`.
- `CDM_INSTALL_PREFIX` chooses a prefix and `CDM_INSTALL_VERSION` pins a release.
- Manual asset selection and verification details are in `GETTING_STARTED.md` and the latest GitHub Release.

Remove the large per-platform runtime asset table from the README; the detailed guide remains authoritative for manual installation.

- [ ] **Step 6: Rewrite Security with an explicit composition matrix**

Begin with a warning that plainly states the defaults:

```markdown
> [!WARNING]
> Plain `cdm command` prioritizes compatibility: the workspace is writable,
> other host user data is readable, networking is direct, and secrets are
> unchanged. It mainly prevents accidental writes outside the project; it is
> not an appropriate boundary for hostile code.
```

Then add a matrix with these semantics:

| Control | Workspace | Other host data | Network | Secrets | Additional effect |
|---|---|---|---|---|---|
| plain `cdm` | read/write | readable | direct | unchanged | prevents writes outside allowed roots |
| `--ro` | read-only | readable | direct | unchanged | protects project files |
| `--iso` | read/write | hidden except grants | direct | unchanged | uses isolated host-data policy |
| `--no-network` | read/write | readable | disabled | unchanged | removes network access |
| `--scramble` | read/write | readable | proxied by default | fake in child | hides/stages known credential files |
| `--sec` | read/write | readable | proxied by default | fake in child | implies `--scramble` and adds persistence protections |
| `--vm` / `--vmi` | guest sees workspace and grants | not exposed to guest | follows selected policy | unchanged unless scrambling is selected | stronger process and daemon containment |

Immediately present `--sec` as CDM's one-flag hardened baseline for riskier tools: it combines secret scrambling, persistence protections, and the deny-first macOS capability baseline. Keep the boundary visible rather than hiding it: `--sec` does **not** imply `--ro`, `--iso`, or `--no-network`; those controls compose separately. Use `cdm --sec --iso --ro --no-network ./untrusted-checker` as the stronger example for a potentially hostile command.

Follow the matrix with no more than three short paragraphs covering:

1. With scrambling enabled, real mappings remain in trusted host memory while the child gets stable fake values; the fail-closed HTTP(S) proxy restores values only for authorized destinations.
2. `--allow-domains` provides the strict destination set in proxied mode; `--no-proxy` keeps direct networking but disables restoration and domain filtering.
3. The command preflight is accident prevention, not enforcement; filesystem, network, and VM controls provide containment.

- [ ] **Step 7: Compress the remainder into clear next steps**

Keep concise sections for:

- Configuration: `cdm config`, trusted project `.cdm/config.json`, `cdm trust`, and presets.
- Reports and monitoring: one example for `--report-json`/`--stats` and one sentence for `--monitor`.
- Build and release status: retain Rust 1.88, package command, and release verification summary, but keep it below user-facing documentation links.
- Documentation: retain all current authoritative links.
- License: retain the MIT License statement.

Remove repetitive explanations already covered by `GETTING_STARTED.md`, `ARCHITECTURE.md`, or `specs/SPEC.md`.

- [ ] **Step 8: Review the README diff for factual and editorial quality**

Run:

```bash
git diff --check
git diff -- README.md
```

Expected: no whitespace errors; the diff follows the approved ordering; every command uses flags before the wrapped command; no paragraph contradicts the security defaults or implication rules.

- [ ] **Step 9: Commit the README rewrite**

```bash
git add README.md
git commit -m "Rewrite README around agent workflows"
```

### Task 2: Verify the documentation contract and align related docs only if necessary

**Files:**

- Inspect: `GETTING_STARTED.md`
- Inspect: `ARCHITECTURE.md`
- Inspect: `specs/SPEC.md`
- Inspect: `AGENTS.md`
- Inspect: `.pi/rules/` if present
- Test: `rust/tests/validate_documentation.py`

**Interfaces:**

- Consumes: The rewritten `README.md`
- Produces: A validated documentation set without unnecessary duplicated edits

- [ ] **Step 1: Check related documents against the rewritten claims**

Verify these exact facts:

- `GETTING_STARTED.md` retains detailed release installation and manual installation guidance.
- `ARCHITECTURE.md` agrees that real secret maps stay in host memory and restoration occurs at the proxy boundary.
- `specs/SPEC.md` agrees that `--sec` implies only `--scramble`, while `--ro`, `--iso`, and `--no-network` remain independent.
- `AGENTS.md` already requires documentation updates and validation for behavior changes.
- No `.pi/rules` convention is required solely for this one-time README structure.

Expected: no related-file edit unless one of these checks reveals an actual mismatch.

- [ ] **Step 2: Run proactive Markdown diagnostics**

Run diagnostics for:

```text
README.md
GETTING_STARTED.md
docs/spark/specs/2026-07-22-readme-restructure-design.md
docs/spark/plans/2026-07-22-readme-restructure.md
```

Expected: no Markdown errors.

- [ ] **Step 3: Run the repository documentation validator**

```bash
cd rust
python3 tests/validate_documentation.py
```

Expected: `documentation validation passed` and exit status 0.

- [ ] **Step 4: Inspect the complete session diff and repository status**

```bash
git diff --check
git status --short
git log -3 --oneline
```

Expected: no whitespace errors; only intentional documentation files are changed or committed; no generated, cache, or machine-specific artifacts are present.

- [ ] **Step 5: Commit any necessary related-document corrections**

Only if Step 1 found a real mismatch:

```bash
git add GETTING_STARTED.md ARCHITECTURE.md specs/SPEC.md AGENTS.md
git commit -m "Align documentation with README security guidance"
```

If no mismatch exists, do not create an empty or drive-by documentation commit.
