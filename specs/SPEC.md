# CDM — Specification

Version: 0.1.0

Updated 16 July 2026. `ARCHITECTURE.md` defines the component and trust model; this file defines expected behavior.

## Overview

CDM wraps any command in an OS-native sandbox. By default it uses direct networking and leaves `.env`, argv, and environment values unchanged. `--scramble` opts into secret discovery and replacement; the sandboxed process then sees fake secrets and an egress proxy restores real values on authorized outbound HTTP(S) traffic. `--sec` implies `--scramble`.

---

## 1. CLI Interface

### Binary Name
`cdm`

### Invocation

```
cdm <command> [args...]           # Shorthand: run command in sandbox
cdm run [flags] <command> [args]  # Explicit run with flags
cdm config                        # Generate default config at ~/.cdm/config.json
cdm trust                         # Trust the nearest project config's exact bytes
cdm project                       # Report discovered root, kind, and config
cdm completions <bash|zsh|fish>   # Write shell completion source to stdout
cdm version                       # Print version string
cdm help                          # Print usage
```

If no command is given, CDM prints help and exits successfully. `cdm run` without a command launches the user's `$SHELL` (fallback: `/bin/bash`).

`cdm config` is create-only and must not overwrite an existing configuration. `cdm trust` requires a nearest project config and atomically records its exact SHA-256 digest outside the workspace. `cdm project` is observational only: it reports a deterministic marker-based kind (`rust`, `node`, `python`, `go`, `git`, or `generic`) and never grants access. CDM parses command arguments without lossy UTF-8 conversion and generates help and shell completion from the same typed command definition.

Configuration precedence is built-in defaults, the global file (`~/.cdm/config.json` or `CDM_CONFIG_PATH`), named global presets selected left-to-right, the trusted nearest project `.cdm/config.json` discovered from the original launch directory, then CLI flags. Path arrays are additive and deduplicated; other explicitly supplied fields replace the lower layer. Global/preset relative paths resolve from `$HOME`, project relative paths from the project root, and CLI relative paths from the effective workspace. Project and nested presets are invalid. Unknown presets are errors. Hard denials cannot be removed by a higher layer.

The project config is loaded only when its exact bytes match `~/.cdm/trusted-projects.json`. The trust store must be owned by the current user, mode 0600, and updated by create-and-rename from a mode-0600 temporary file. Policy reads use one `O_NOFOLLOW` descriptor for regular-file metadata, bytes, hashing, and parsing; files with multiple hard links are rejected. Any project-config byte edit invalidates trust. The global config, trust store, project config, and their dedicated containing policy directories are write-denied inside the child sandbox so explicit grants cannot replace them or rename/swap their parents. A custom global config parent must already be a real directory owned by the invoking UID with no group/world write bits. Direct placement beneath `/`, `/tmp`, `/private/tmp`, `$HOME`, the trusted temporary root, or the project root is rejected because CDM cannot safely deny those broad parents in full.

### Flags

| Flag | Effect |
|------|--------|
| `--no-network` | Disable all network access. Conflicts with `--no-proxy` and domain rules. |
| `--no-proxy` | Keep direct network access when scrambling, without secret restoration or domain filtering. Conflicts with domain rules. |
| `--sec` | Imply `--scramble`, enable secure persistence denials on every backend, and on macOS use the deny-first capability baseline. |
| `--scramble` | Discover and replace secrets, hide/stage credential files, and enable the fail-closed egress proxy unless networking is direct or disabled. |
| `--rw` | Make the effective workspace read/write (the default). Conflicts with `--ro`. |
| `--ro` | Make the effective workspace read-only. Conflicts with `--rw`. |
| `--iso` | Hide host user data outside the workspace and explicit grants. Composes with `--ro`. |
| `--allow-ro <path>` | Add a read-only path grant (repeatable). |
| `--allow-rw <path>` | Add a read/write path grant (repeatable). |
| `--preset <name>` | Apply a named global configuration preset (repeatable, left-to-right). |
| `--app <path.app>` | Explicit compatibility spelling for automatic macOS `.app` command detection. |
| `--monitor` | Stream sandbox denial events to a private log shown in a separate terminal viewer. |
| `--allow-domains <list>` | Comma-separated allowlist. Only these domains reachable. Requires `--scramble` or `--sec`. |
| `--deny-domains <list>` | Comma-separated denylist. Block these domains. Requires `--scramble` or `--sec`. |
| `--allow-private-network` | Permit private or host-local proxy destinations only when a non-empty domain allowlist explicitly matches the requested host or IP. |
| `--vm` | Run inside a libkrun microVM (bundled Alpine rootfs); requires a `--features vm` build. |
| `--vmi <image>` | Run inside a libkrun microVM with an OCI image (e.g. `ubuntu:24.04`); requires a `--features vm` build. |
| `--worktree` | Run against a temporary Git worktree and save resulting changes on a generated branch. |
| `--report-json <path>` | Atomically write a private, schema-versioned, redacted session report. |
| `--stats` | Write compact aggregate session statistics to stderr without changing child stdout. |

### Environment Variables

| Variable | Effect |
|----------|--------|
| `CDM_DEBUG=1` | Print sandbox configuration details to stderr. |
| `CDM_CONFIG_PATH` | Override config file location (default: `~/.cdm/config.json`). |
| `CDM_CACHE_DIR` | Override the persistent VM rootfs cache location; must be absolute, user-owned, private, and symlink-safe. |

### Exit Behaviour

CDM exits with the sandboxed command's exit code. CLI, configuration, trust, and preflight validation refusals use status 2. Other CDM failures (for example sandbox setup) exit non-zero with a log message to stderr.

Every native host adapter command runs in a dedicated supervised process group. CDM
hands an interactive terminal to that group, forwards parent-delivered
`SIGINT`, `SIGTERM`, `SIGHUP`, and `SIGQUIT` to the group, restores terminal ownership afterward,
and maps signal termination to `128 + signal`. A repeated signal or five-second
grace expiry forces the group down with `SIGKILL`. If the immediate adapter
process exits while descendants remain, CDM sends the group `SIGTERM`, waits a
short bounded grace period, and then sends `SIGKILL`. Proxy shutdown, runtime
removal, report publication, and worktree finalization begin only after this
supervisor returns. The VM launcher uses the same exit and parent-signal
conventions through its explicit `posix_spawn` supervisor.

Process-group membership alone is not the descendant security boundary. Linux
native mode relies on Bubblewrap's PID namespace and `--die-with-parent`, so a
new session or double-fork remains inside a namespace that is destroyed with
the adapter. macOS native mode has no equivalent supported primitive (the
kernel's historical recursive `NOTE_TRACK` flags have been unsupported since
macOS 10.5), so its guarantee ends at the supervised process group. A process
that deliberately calls `setsid` can outlive the invocation, although it
retains the inherited Seatbelt policy. Callers requiring malicious-daemon
containment on macOS must select VM mode.

As with a conventional Unix shell, terminal-generated signals are delivered
directly to the foreground sandbox group rather than duplicated to the
background CDM parent. Thus the bounded parent-side escalation timer applies
to signals received by CDM; a foreground group that deliberately ignores every
terminal-generated signal requires an external signal to CDM for forced
escalation.

### Structured reporting

`--report-json` prepares its destination before untrusted execution and publishes only after child supervision, proxy shutdown, worktree finalization, and runtime cleanup. The version-1 document must include:

- schema version, elapsed timing, backend, and argv count without argv values;
- effective workspace, host, and network policy plus path/rule counts without paths or domains, or `null` policy if validation or setup failed before resolution;
- separate configured-rule, observed-denial, and observation-coverage fields;
- bounded proxy traffic/substitution/rejection counters, with explicit child-to-proxy, proxy-to-upstream, upstream-to-proxy, and proxy-to-child byte directions, plus secret/staging/injection counts;
- bounded typed lifecycle events with an explicit dropped-event count; and
- typed child, cleanup, and worktree outcomes.

Cleanup is `succeeded` only after every explicitly owned cleanup operation
completes. A fail-safe report emitted during an unexpected unwind records
`incomplete`, never success; an observed cleanup error records its typed failed
stage and upgrades an otherwise successful invocation to failure.

It must not include argv values, filesystem paths, domains, environment values, free-form diagnostics, branch names, or secret material. Before writing, CDM scans the serialized bytes for every known real secret and fails closed on a match. The destination is installed atomically with mode `0600` using a directory descriptor pinned before sandbox entry. CDM rejects a symlink destination and revalidates the parent device/inode before publication; replacement of the parent is an error, not a redirected or silently lost write. File and parent directory are synced before success is reported.

Detailed events are capped at 128; aggregate counters continue saturating after that cap. Validation, setup, proxy, sandbox, child, worktree, and cleanup phases are typed. Nonzero and signaled children are failed child phases while retaining their exact outcome. Observation metadata must remain honest: the current filesystem-denial count is `not_instrumented`, and proxied request observation is `partial`. `--stats` renders a compact aggregate view to stderr through a caller-provided writer and must not write to stdout.

### macOS application launch

An existing `.app` directory in command position activates application mode automatically; `--app` accepts the same bundle as an explicit compatibility spelling. Remaining command arguments are passed to its `CFBundleExecutable`. CDM must:

1. Canonicalize the bundle, parse `Contents/Info.plist` as one validated document, and validate `CFBundleIdentifier` and `CFBundleExecutable`. Reject symlinked metadata or executables and executable paths that escape `Contents/MacOS`.
2. Grant the bundle read-only.
3. Treat either bundle selection form as the caller's trust decision. Do not invoke Gatekeeper, notarization checks, or code-signature verification, and do not distinguish signed, unsigned, ad-hoc, or local development bundles.
4. Derive exact conventional leaves from `CFBundleIdentifier` beneath `~/Library/Application Support`, `~/Library/Caches`, `~/Library/Containers`, `~/Library/WebKit`, and `~/Library/Preferences`.
5. Perform bounded literal-reference inspection of the contained executable and regular configuration/resource files with an approved extension. Candidate paths are limited to safe product-token-derived hidden home directories and existing immediate cache children related to those tokens. A versioned cache requires both its exact version and version-independent prefix to appear. Reserved or broad home roots, arbitrary absolute paths supplied by bundle content, unbounded recursion, symlinks, and parent-directory grants are forbidden.
6. Reject any automatic path that is a symlink, has the wrong file type, or resolves outside its direct expected root. Do not make a broad parent such as the home directory or `~/Library` writable.
7. Report the validated bundle identifier, writable-state count, and each automatic path with its evidence category before launch.

Discovery is deterministic and static. Optional plist keys may be absent, but malformed or unreadable plist data is an error rather than an absent-key fallback. CDM does not run the application unsandboxed, trace unrelated processes, or honor arbitrary path declarations from bundle content. Explicit grants remain the contract for state whose location is computed only at runtime. `--app` does not alter proxy/network policy and is macOS-only.

### Git worktree lifecycle

`--worktree` requires a Git repository with at least one commit. CDM must:

1. Create a detached `--no-checkout` worktree from the original repository's `HEAD`, then copy the caller's materialized tracked regular files, executable bits, symlinks, and gitlink directories directly from the filesystem. Creation must not invoke diff, checkout hooks, or clean/smudge/process filters. Missing sparse `S`/`s` index entries remain absent and retain their base-tree entries; other missing tracked entries are recorded as deletions.
2. Copy every non-ignored untracked file. Git-ignored paths remain excluded. Filter-materialized bytes that differ from their stored blob, including materialized Git LFS content, are raw result bytes; CDM must not execute a clean filter in the trusted host to recreate a pointer or transformed blob.
3. Preserve the invocation directory relative to the repository root.
4. Atomically reserve a human-readable `CDM__<date>__<project>__<user>` result branch, adding a numeric suffix for repeated or concurrent sessions.
5. Run the chosen native or VM sandbox against the temporary worktree without modifying the original checkout.
6. Before sandbox entry, capture the exact identity of the worktree `.git` gitfile, its resolved actual Git directory, the common Git directory, and the trusted system Git executable. Hard write-deny every metadata path in native and VM policy and reject finalization if any pinned identity or gitfile bytes changed.
7. If there are changes, open the worktree root once and inspect every Git-visible path descriptor-relatively without following symlink ancestors. Hash regular files from already-open no-follow descriptors; hash symlink target bytes without following them. Replacing a tracked directory with a symlink removes its former descendants and records one mode-`120000` entry. Use plumbing to write a private temporary index/tree, create a single-parent commit without porcelain hooks, filters, signing, prompts, pagers, or fsmonitor, and compare-and-swap only the reserved ref. Every trusted Git process must use the pinned executable and a cleared, narrowly rebuilt environment. Preserve changes even when the sandboxed command exits nonzero.
8. If there are no changes, delete the reserved branch. In both cases, remove the temporary worktree.
9. Return the sandboxed command's exit status unless worktree finalization itself fails; an otherwise successful command then becomes a CDM error.

The summary uses the exact original commit when showing the result diff. A setup failure must remove both the worktree and reserved branch.

---

## 2. Command Preflight Guard

**When**: Before any sandbox setup, before secret scanning.

**Behaviour**: Tokenize each configured `guard.blocked_commands[].prefix` value as
a literal simple-command pattern. Despite the legacy field name, matching is
not string-prefix matching: the first token matches the direct executable's
exact basename and every configured argument token matches at the same argv
position. Thus `aws` matches `aws` and `/opt/bin/aws`, but not `awesome-tool`
or `aws-vault`. An explicit `sh -c`-style invocation is also checked only when
its script is a literal simple command that can be parsed without expansion,
redirection, control operators, or comments.
Malformed configured patterns fail the invocation before sandbox setup rather
than being silently ignored.

This is operator mistake prevention, not an execution-control security
boundary. A command can launch another program after startup, and deliberately
complex shell syntax is outside this preflight. CDM does not claim that an
executable name such as `aws` is universally denied. Filesystem policy, network
transport policy, and secret isolation/restoration are the enforcement
boundaries. To prevent AWS network effects, select `--no-network` or a strict
domain allowlist; command-name preflight alone is insufficient.

### Default preflight patterns

| Category | Prefixes |
|----------|----------|
| Privilege escalation | `sudo`, `su `, `doas` |
| Destructive filesystem | `rm -rf /`, `rm -fr /` |
| System control | `shutdown`, `reboot`, `halt`, `poweroff`, `init `, `systemctl poweroff`, `systemctl reboot` |
| Disk operations | `mkfs`, `fdisk`, `dd if=` |
| Container escape | `docker run --privileged`, `docker run -v /:/` |
| Namespace escape | `chroot`, `unshare`, `nsenter` |
| Host cloud tooling | `aws` |

### Expected Outcome
```
$ cdm sudo rm -rf /
[cdm] preflight guard refused a blocked executable — privilege-escalation command refused by preflight policy
```

---

## 3. Secret Detection & Obfuscation

This entire section is active only for `--scramble` or `--sec`. Without either flag, CDM does not scan secrets, alter argv or environment values, inspect or stage candidate credential files, inject `.env` entries, or deny reads to `.env`.

### 3.1 Detection

Scan these sources in order:
1. **Environment variables** — flag every nonempty value by name only (contains: `key`, `secret`, `token`, `bearer`, `password`, `passwd`, `credential`, `api_key`, `apikey`, `auth`, `private`, `access_key`, `oauth`), regardless of value length. Skip known non-secret vars (PATH, HOME, TMPDIR, etc.). Value-based heuristic detection is NOT used for env var scanning.
2. **~/.aws/credentials** and **~/.aws/config** — parse key=value lines.
3. **~/.ssh/** — scan for files containing `PRIVATE KEY`.
4. **.env files** in working directory — `.env`, `.env.local`, `.env.development`, `.env.production`, `.env.staging`, `.env.test`.
5. **Other config files** — `~/.kube/config`, `~/.npmrc`, `~/.docker/config.json`.

Under `--iso`, home-directory credential discovery and staging are disabled unless an explicit `--allow-ro`/`--allow-rw` grant covers the path. When scrambling is enabled, environment variables and project `.env*` files remain in scope.

Configured candidate files are optional when absent. CDM pins the workspace and
home category roots, opens every descendant directory component descriptor-
relatively with no-follow semantics, and reads a regular leaf only through the
already-open descriptor that is passed into parsing and staging. An ancestor or
leaf symlink, concurrent replacement, unreadable entry, decode error, parse error,
random-generation failure, or staging failure stops preparation before the child
or proxy-facing workload launches. Diagnostics identify the operation and path
without including file contents or secret values. SSH directory traversal follows
the same descriptor-relative rule; an absent directory is optional, but an
existing unsafe or malformed entry is an error.
Configured candidate names must be non-empty relative paths without `..`; they
cannot escape the workspace or home base used for their category.

### Conservative token-format detection

Secret-like key names are the primary signal. Value-only detection is deliberately
limited to recognizable provider syntax so ordinary UUIDs, hashes, model names,
URLs, paths, and long mixed-case configuration values are not rewritten.

A value-only candidate must meet the configured minimum length and character-class
threshold, contain no whitespace, and match one of these formats:

- AWS access-key IDs (`AKIA`, `ASIA`, `AIDA`, `AROA`, `AIPA`, `ANPA`, `ANVA`, or
  `ASCA`, followed by the standard 16 uppercase letters/digits)
- GitHub classic tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) and fine-grained
  `github_pat_` tokens
- OpenAI `sk-`/`sk-proj-` and Anthropic `sk-ant-` tokens
- npm `npm_`, GitLab `glpat-`, Google API `AIza`, Stripe live `sk_live_`/`rk_live_`,
  and Slack `xox*` tokens
- three-part base64url JWTs with non-trivial header, payload, and signature lengths
- credential-bearing URLs whose authority contains non-empty `user:password@host`

This is syntax recognition, not provider-side validation. Unknown formats are
still protected when their key name matches the configured secret-name patterns.

### Detection Scope

| Source | Name matching | Value heuristic (`looks_like_secret`) |
|--------|---------------|---------------------------------------|
| Environment variables | Yes | No |
| File-based (`.env`, config files) | Yes | Conservative known formats only |

### 3.2 Fake Generation

For each detected secret value:
1. Generate a fake of **identical length** for ordinary global replacements.
   Secret-named environment values shorter than eight bytes instead receive a
   long random sentinel that is substituted only in that originating field;
   their short raw value is never used as an unrestricted substring pattern.
2. Each character replaced by a random character of the **same class**: uppercase→uppercase, lowercase→lowercase, digit→digit, special chars preserved as-is.
3. Use cryptographically secure random (`/dev/urandom`). Random-source failures
   abort preparation; they never panic or fall back to predictable bytes.
4. Require fake != real, require the complete real-value and fake-value sets to
   remain disjoint (including when a newly discovered real equals an existing
   fake), and reject collisions with bounded retry attempts.
5. Store bidirectional mapping: `real↔fake` in host memory only.
6. Idempotent: adding the same real value twice returns the same fake.

Replacement is a longest-match, single pass over the original input. Generated
output is never scanned again, so overlapping real/fake strings cannot form a
replacement chain that reconstructs a real value. Short environment sentinels
remain restorable by the authorized proxy and are included in upstream-response
scrubbing. A secret-named file value shorter than eight bytes fails preparation
because raw substring replacement would be ambiguous.

### Expected Outcome
```
Real:  sk-ant-api03-REAL1234567890abcdef
Fake:  sk-ant-api03-BNZQ8472910345lmnopq
       ^^^^^^^^^^^^ preserved (special chars)
                    ^^^^^^^^^^^^^^^^^^^^^^ randomized (same char class)
```

---

## 4. File Staging

File staging is performed only for `--scramble` or `--sec`. In the default mode, `.env` and configured credential files follow ordinary filesystem policy and CDM does not source `.env`.

### Behaviour

1. Create a temp directory (`cdm-stage-*`).
2. For each sensitive file: read original, replace every known real value longest-first across the complete file, then apply format-aware checks and write the staged copy while preserving directory structure. **Never modify originals.**
3. Obfuscation rules for file content:
   - Comments (`#`, `//`), section headers (`[...]`), minified JSON, YAML, and INI are not exemptions: known real values are replaced everywhere.
   - JSON files are parsed for both key-aware discovery and value-level staging, so minified objects are never reinterpreted as one line-oriented key/value pair; malformed JSON fails closed. Unchanged JSON retains its original bytes.
   - For `.env*` files: for `key=value` or `key: value` lines, obfuscate the value when the key name is secret-like or the scan registered the exact value through conservative token-format detection. Non-secret config values (for example model identifiers and non-credential URLs) remain readable.
   - For other config files: for `key=value` or `key: value` lines, obfuscate the value if the key is secret-like OR the value looks like a secret.
   - Preserve quoting and whitespace.
   - For lines that look like base64/key material (>90% base64 chars, length>=20): obfuscate the entire line.
4. Scan final staged bytes for every known real value; any remainder aborts preparation without including the value in diagnostics.
5. Clean up temp directory on exit (Drop impl).

### Platform-Specific Mechanisms

| Platform | .env files | Home configs (AWS, Docker, etc.) | SSH keys |
|----------|-----------|----------------------------------|----------|
| Linux | bwrap bind-mounts obfuscated copy over original | bwrap bind-mount | bwrap bind-mount |
| macOS | Entries injected as env vars + seatbelt denies reads to original | Redirected to obfuscated copy via env var (e.g. `AWS_SHARED_CREDENTIALS_FILE`) + seatbelt denies reads | Seatbelt denies reads |

### macOS File Obfuscation Detail

On macOS, file obfuscation works without any extra dependencies:

1. **`.env` files in working directory**: All key=value entries are parsed and injected as environment variables into the sandbox process. Secret-named keys (containing `password`, `token`, `key`, `secret`, `bearer`, `auth`, `credential`, `oauth`, etc.) and exact values registered by conservative token-format detection get obfuscated values; other entries pass through as-is. The seatbelt profile denies reads to the real `.env` file.

2. **Home config files** (~/.aws/credentials, ~/.aws/config, ~/.docker/config.json, ~/.kube/config, ~/.npmrc): Obfuscated copies are created in a temp directory. Environment variables redirect tools to the copies (`AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE`, `DOCKER_CONFIG`, `KUBECONFIG`, `NPM_CONFIG_USERCONFIG`). The seatbelt profile denies reads to the originals.

3. **SSH private keys**: The seatbelt profile denies reads. The sandbox cannot access private key material.

### Config Redirect Environment Variables

| Original File | Redirect Env Var |
|---------------|-----------------|
| `~/.aws/credentials` | `AWS_SHARED_CREDENTIALS_FILE` |
| `~/.aws/config` | `AWS_CONFIG_FILE` |
| `~/.docker/config.json` | `DOCKER_CONFIG` (points to directory) |
| `~/.kube/config` | `KUBECONFIG` |
| `~/.npmrc` | `NPM_CONFIG_USERCONFIG` |

---

## 5. Environment Sanitization

### Behaviour

Before constructing the sandboxed environment, strip these variables:

| Platform | Stripped Variables | Reason |
|----------|-------------------|--------|
| Linux | All `LD_*` | Prevents `LD_PRELOAD` shared library injection |
| macOS | All `DYLD_*` and all `LD_*` | Prevents dyld injection |

### Environment Construction

1. Start with passthrough vars: `PATH`, `HOME`, `USER`, `SHELL`, `TERM`, `LANG`, `LC_ALL`, `TZ`, `EDITOR`, `VISUAL`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`, `TMPDIR`, `TEMP`, `TMP`, `NODE_OPTIONS`, `NODE_ENV`.
2. Copy remaining host env vars, skipping dangerous vars (above). Obfuscate detected secrets only when `--scramble` or `--sec` is active.
3. Set `CDM=1`.
4. Set `TMPDIR`, `TMP`, and `TEMP` to a private per-invocation runtime directory beneath the invoking user's trusted temporary root. It must be a real directory owned by the invoking UID and is forced to mode `0700`.
5. If proxy enabled: set `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` to `http://127.0.0.1:<port>`.
6. If MITM CA available: set trust injection env vars (see Section 7.2).

---

## 6. Sandbox Execution

### macOS — Apple Seatbelt

Generate an SBPL profile and run via `sandbox-exec -f <profile> <command>`.

**Compatibility profile:**
1. `(allow default)` preserves host-native CLI and desktop compatibility.
2. `(deny file-write* (subpath "/"))` denies all writes globally. Seatbelt denials cannot be reopened by later allows, so this explicit deny is used only for write containment where no exceptions must cross it.
3. Allow writes to essential runtime paths:
   - `/dev` — devices, pseudo-ttys, unix sockets
   - the unique mode-0700 invocation directory beneath the invoking user's validated private temporary root
4. Allow writes to the working directory only in RW mode, plus explicit `allow_rw` grants. The home directory is never broadly writable.
5. In `--iso`, switch to the deny-first profile and allow file-content reads only for system/runtime roots, the workspace, temp, explicit grants, and discovered app grants. Seatbelt denies are final; a positive allowlist is required because a broad deny cannot later be reopened.
6. When scrambling is active, deny reads to discovered sensitive files (`.env`, `~/.aws/credentials`, SSH private keys, etc.) via `(deny file-read-data (literal "..."))`.
7. When `--sec` is active, add the persistence hard-denied paths below even if they are inside a writable grant:
   - Shell configs: `.bashrc`, `.zshrc`, `.bash_profile`, `.zprofile`, `.profile`, `.bash_login`, `.bash_logout`, `.zshenv`, `.zlogin`, `.zlogout`
   - Git: `.gitconfig`, `.git/hooks`
   - SSH: `.ssh/authorized_keys`, `.ssh/authorized_keys2`, `.ssh/config`
   - AI agents: `.claude/hooks`, `.cursor/hooks`, `.codex/hooks`
   - System: `/var/spool/cron`, `/etc/crontab`
   - For each: `deny file-write*` (subpath + literal) and `deny file-write-unlink` (literal) for move-blocking.
8. Network: direct mode keeps compatibility behavior; disabled mode denies `network*`; proxied mode denies `network*` and restores outbound TCP only to `localhost:<per-run proxy port>`.

**Secure profile (`--sec`, which implies secret scrambling):**
1. `(deny default)` denies every operation not explicitly restored.
2. Restore process execution/forking, same-sandbox process information/signals, preferences, POSIX IPC, required IOKit/sysctl/terminal operations, and Fence's named Mach lookup baseline.
3. Do not restore `mach-register` or `mach-issue-extension`.
4. Apply the same resolved filesystem write policy as compatibility mode. In normal host mode allow reads; in `--iso` restore only the read allowlist.
5. Restore `network*` only in deliberate direct mode. Proxied mode restores only outbound TCP to the exact loopback proxy port. Proxied mode uses this deny-first capability baseline even without `--sec`, preventing broad Mach/XPC access from becoming an indirect network deputy.

Direct normal mode uses the compatibility profile. Proxied, isolated, and secure modes use the deny-first capability baseline and deliberately trade GUI/WebKit compatibility for a smaller macOS capability surface.

### Trusted host helpers

Programs which implement CDM policy or mutate trusted host state must not be
selected from the sandboxed command's project-controlled environment. CDM uses
the fixed `/usr/bin/sandbox-exec` on macOS and a fixed system `cp` for disposable
rootfs cloning. Git and Bubblewrap are resolved centrally: candidates with a
relative path, a symlink in any path component, non-root ownership, or
group/world-writable components are rejected. CDM pins the accepted
executable's device/inode identity, revalidates it before launch, clears the
host-helper environment, and adds back only explicitly required values. A
project-local executable earlier in `PATH` must never run as a trusted helper.

### Linux — Bubblewrap

Run via `bwrap` with these arguments:
1. Normal mode: `--ro-bind / /` supplies a read-only host root. Isolated mode: `--tmpfs /` starts empty and read-only binds only required system/runtime roots.
2. Bind the workspace RW by default or RO for `--ro`.
3. Bind the resolved temporary directory writable.
4. Bind `allow_ro` grants read-only and `allow_rw` grants read/write. Never bind the whole home directory writable.
5. File stage overlays: `--ro-bind <staged> <original>` for each.
6. Hard write denials: re-bind exposed paths read-only; hard read denials use an inaccessible overlay.
7. `--dev /dev`, `--proc /proc`, and `--cap-drop ALL`.
8. `--unshare-pid` — PID namespace isolation.
9. Proxied and disabled modes use `--unshare-net`; proxied mode exposes only a private descriptor bridge to CDM's trusted loopback proxy.
10. Apply a seccomp program after bridge setup that denies AF_UNIX socket creation and dangerous descriptor-acquisition syscalls; direct and disabled commands receive the same filter directly.
11. `--new-session`, `--die-with-parent`.
12. `--unsetenv LD_PRELOAD`, `--unsetenv LD_LIBRARY_PATH` (belt-and-suspenders).
13. `--chdir <workdir>` and execute the command.

Normal Linux mode replaces `/run`, its `/var/run` alias, and the captured user runtime with empty synthetic mounts before deliberate capabilities are restored. Known Docker/containerd/D-Bus/SSH/GPG agent paths are hard denied, and direct socket/runtime-tree grants fail before launch. Proxied mode is transport-enforced rather than cooperative: only loopback TCP accepted inside the empty namespace can cross the exact private bridge to CDM's proxy.

---

## 6.3 VM — libkrun microVM

When `--vm` or `--vmi <image>` is specified, CDM runs the command inside a libkrun microVM
instead of a host-level sandbox.

### Architecture

- **libkrun** provides the VMM (Virtual Machine Monitor) using Apple Hypervisor.framework (macOS ARM64) or KVM (Linux)
- **TSI** (Transparent Socket Impersonation) is configured explicitly rather than left implicit. CDM disables libkrun's implicit vsock, enables only `KRUN_TSI_HIJACK_INET` when networking is allowed, and never enables `KRUN_TSI_HIJACK_UNIX`. The VMM launcher is host-filesystem-confined in every mode. Linux proxied VMs additionally enter an empty network namespace and use the private descriptor bridge; direct and disabled Linux VMMs receive the host-deputy seccomp filter through Bubblewrap.
- **VirtioFS** exposes only the working directory, explicit directory grants, staged files, and CA certs. Read-only exports use libkrun's host-enforced read-only flag. External single-file grants are unsupported because VirtioFS would export the parent directory to the VMM; guest bind masking is not treated as VMM containment.

### Rootfs

| Mode | Rootfs Source |
|------|---------------|
| `--vm` | Bundled Alpine minirootfs (~3.7MB, embedded in binary via `include_bytes!`) |
| `--vmi <image>` | OCI image pulled via `oci-client`, extracted atomically under `~/.cdm/rootfs/` (or `CDM_CACHE_DIR`) |

OCI images are pulled with a `linux/<host_arch>` platform resolver (always Linux, even on macOS host).

OCI blobs are authenticated by `oci-client` while streaming to private mode-0600, no-follow, exclusive temporary files. Defaults limit compressed data to 512 MiB per layer and 2 GiB per image, expanded tar data (including declared logical file sizes) to 4 GiB per layer and 8 GiB per image, entries to 250,000 per layer and 1,000,000 per image, and paths to 128 components. The corresponding `vm` configuration keys are `max_layer_compressed_mib`, `max_image_compressed_mib`, `max_layer_expanded_mib`, `max_image_expanded_mib`, `max_layer_entries`, `max_image_entries`, and `max_path_depth`; all must be non-zero and per-layer limits cannot exceed image totals. Quota, digest, archive-validation, platform, or cleanup failure prevents cache publication.

The effective cache directory is mode 0700, owned by the invoking user, reached without symlink traversal, and hard read- and write-denied to native and VM children even when relocated. A complete marker binds the source and resolved image digest to a deterministic SHA-256 digest of file paths, types, modes, link targets, and regular-file bytes. A missing, forged, or mismatched marker causes an atomic rebuild rather than execution from the suspect tree.

### Static Guest Init

VM release builds embed a target-matching, statically linked Linux-musl `/cdm-guest-init` plus its source/build provenance. A strict mode-0400 `/cdm-plan.json` carries schema version 2, exact Unix argv byte arrays (including non-UTF-8 values but never NUL), fake environment values, cwd, UID/GID, ordered mounts, and hard denies. Unknown fields, wrong versions, unsafe paths, duplicate targets, excessive sizes, and any declared mount failure are fatal before the command starts.

The helper mounts `/proc`, `/sys`, `/dev`, the private temporary filesystem, and exact VirtioFS shares; overlays host-enforced read-only exports; and hides denied files/directories. A read-denied file receives a root-owned mode-000 placeholder from a root-only guest directory as a bind mount over the captured target. An individual write-denied file is sourced from a dedicated host-read-only VirtioFS export, and plan validation rejects any bind that is writable or lacks that immutable backing export. Each resulting target is a busy mount point; the capability-free non-root child can neither access a read-deny placeholder nor overwrite, unlink, or replace a protected host entry. CDM deliberately does not issue a read-only remount for either single-file bind because libkrun's VirtioFS guest mount rejects it with `EINVAL`; the read-only source superblock already enforces write denial. Exact-package VM acceptance verifies read, overwrite, unlink, and unchanged-host-file outcomes. Only after mount setup the helper enables `no_new_privs`, clears ambient capabilities, and empties the capability bounding set. The child clears supplementary groups, sets real/effective/saved UID/GID, zeroes inheritable/permitted/effective capabilities, and executes without a shell. UID/GID zero are invalid plan values; host-root VM launches map to guest UID/GID 65534. Thus setuid and file-capability executables in caller-selected OCI images cannot recover guest root. As guest PID 1 the helper forwards signals to the command process group, reaps descendants, terminates leftovers, and preserves normal and `128 + signal` exit mapping. Descriptor-pinned `openat2` and modern mount APIs prevent mount-target path replacement. BusyBox, a guest shell, and a copied dynamic linker are not part of this path.

### Environment Variables

`/.krun_config.json` remains minimal for libkrun bootstrap. The wrapped command's exact fake environment and working directory come only from the bounded guest plan; real secret mappings remain in trusted host memory.

### Security

- Sensitive files receive an unreadable/unwritable empty overlay; the host originals remain untouched.
- The workspace and grants are host-enforced RW/RO VirtioFS exports, and the wrapped command does not run as guest root.
- The parent prepares the disposable rootfs, copies only public CA material into `/etc/cdm`, and writes a mode-0600 launcher plan containing paths and VM settings but no environment or secret map.
- A fresh hidden launcher process configures libkrun and calls `krun_start_enter`; the parent retains proxy, rootfs, workspace, and cleanup ownership. The plan is created atomically with `O_NOFOLLOW|O_EXCL`, parsed from one validated descriptor, strictly rejects unknown fields and unsafe bounds, and is unlinked before VM entry.
- On macOS the launcher always uses a deny-first Seatbelt filesystem profile exposing only the executable/bundled runtime, required Apple runtime, disposable rootfs, private invocation session, and exact RO/RW exports. Network rules are independently disabled, direct, or exact-proxy-only. On Linux, Bubblewrap provides the corresponding host confinement for direct and disabled modes and exposes only `/dev/kvm` beyond its minimal device set. `/dev/kvm` is preflighted read/write; the launcher preserves the invoking user's supplementary `kvm` group rather than adding a nested user namespace that could discard it.
- The launcher runs in a supervised process group. Signals received by CDM cover all descendants, a repeated received signal or five-second grace expiry escalates to `SIGKILL`, terminal ownership is restored, and signaled exits use `128 + signal`. Terminal-generated signals go directly to the foreground VMM group; if the entire group deliberately ignores one, the parent cannot observe it for escalation until an intermediate foreground supervisor or PTY relay is implemented.
- VM guest filesystem semantics are explicit: the guest receives its Linux rootfs, workspace, staged public artifacts, and explicit VirtioFS grants. Native normal-mode host paths are not implicitly mirrored into a Linux guest; commands must exist in the guest image and portable host data requires an explicit grant.
- With `--scramble` or `--sec`, the guest sees only scrambled values in environment variables and staged files. Without those flags, caller-supplied environment values and ordinary workspace files pass through unchanged.
- Target-native VM acceptance runs the built-in setuid/capability probe and, when the host runner is root, verifies the fixed 65534 guest mapping.

---

## 7. Egress Proxy

### 7.1 Behaviour

When `--scramble` or `--sec` is active and networking is neither direct nor disabled, CDM starts a per-invocation HTTP forward proxy listening on `127.0.0.1:<port>` (default preference: 18080, with an ephemeral fallback when occupied). `ProxySession` owns one runtime thread, readiness, shutdown, joining, and its private CA artifacts. Binding, CA/bundle generation, runtime creation, or readiness failure stops the invocation before the command starts. The real/fake mapping and validated per-secret destination scopes remain in trusted host memory.

Restoration is deny-by-default per secret. Known provider token syntax and provider-specific names derive conservative destination suffixes. Unknown secrets receive no restoration scope. Explicit rules name identifiers, never values:

```json
{"secrets":{"restore_destinations":{"INTERNAL_API_TOKEN":["api.internal.example"]}}}
```

Entries are validated ASCII DNS suffixes or exact IP literals. Malformed or empty rules fail before child launch.

**HTTP requests:**
1. Normalize the authority and apply global domain denies/allows first; deny precedence is unchanged.
2. Restore a fake in the request target, headers, or at most 16 MiB body only when that mapping authorizes the authority. Attacker domains and other providers retain fakes.
3. Force `Accept-Encoding: identity` while response scrubbing is active and forward upstream.
4. Reject non-identity upstream content encoding and oversized/malformed bodies. Replace every known real value longest-first in response headers and body before returning it.
5. Repair content-length/transfer metadata after rewriting. Failures are rejected, never returned as success-shaped empty traffic.

WebSocket frames do not use the bounded HTTP body-rewrite path, and hudsucker's
separate WebSocket connector cannot share CDM's per-resolution address policy.
Every WebSocket upgrade is therefore rejected, whether or not a secret mapping
exists, until that path supports both address filtering and bidirectional
scrubbing.

**HTTPS CONNECT requests (MITM mode — default):**
1. Validate the CONNECT authority and apply the global domain policy before returning `200 Connection Established`.
2. When mappings exist, require a TLS ClientHello and accept TLS from the child using a forged certificate for the requested server name, signed by the ephemeral CDM CA.
3. Process the decrypted HTTP request through the same destination-scoped restoration path as plain HTTP, then connect upstream with certificate verification against the system root store.
4. Process the upstream response through the same encoding checks and real-to-fake scrub before returning it to the child.
5. Client TLS setup, generated-certificate, or verified upstream TLS failures close or reject the intercepted exchange; they never retry as an opaque tunnel.

CONNECT is always kept on the inspected HTTP/TLS path so every upstream socket uses CDM's address-filtering resolver; it never becomes an opaque tunnel. When mappings exist, the same path performs scoped restoration and response scrubbing. Unknown protocols are not authorized. Encoding a fake does not authorize or decode it; only the exact fake bytes are eligible. Proxy startup and intercepted TLS failures never fall back to direct networking.

### 7.2 MITM Certificate Authority

At startup, CDM generates an **ephemeral CA certificate** (valid only for this session). This CA signs per-domain certificates on the fly for HTTPS interception.

**CA trust injection** — the CA cert is made available to the sandboxed process via environment variables:

| Variable | Scope | Behaviour |
|----------|-------|-----------|
| `NODE_EXTRA_CA_CERTS` | Node.js (copilot, npm, gh) | **Additive** — appends CDM CA to Node's trust store. |
| `NODE_USE_SYSTEM_CA` | Bun (Claude Code) | Set to `1` to load certs from the system keychain. |
| `NODE_OPTIONS` | Node.js 22.15+ | Appends `--use-system-ca` (belt-and-suspenders, deduped). |
| `SSL_CERT_FILE` | OpenSSL-based tools (Go, Python, curl on Linux) | **Replacement** — combined bundle of system CAs + CDM CA. |
| `REQUESTS_CA_BUNDLE` | Python `requests` library | Same combined bundle as `SSL_CERT_FILE`. |
| `CURL_CA_BUNDLE` | curl (OpenSSL-linked) | Same combined bundle as `SSL_CERT_FILE`. |
| `CODEX_CA_CERTIFICATE` | OpenAI Codex CLI | Same combined bundle as `SSL_CERT_FILE`. |

**Combined CA bundle creation:**
- **macOS**: Exports system root certificates via `security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain`, appends CDM CA cert.
- **Linux**: Reads system CA bundle from standard paths (`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`), appends CDM CA cert.

**Limitations:**
- macOS system `curl` uses SecureTransport, which reads the Keychain directly — it does not honour `SSL_CERT_FILE` or `CURL_CA_BUNDLE`. MITM does not apply to SecureTransport-based tools.
- CA cert and bundle files are written to a private per-run directory and removed only after proxy shutdown is joined. Proxied VM guests receive public cert/bundle copies in their disposable `/etc/cdm`; no CA private key or real secret map enters the guest.

### 7.3 Domain Filtering

Applied before any proxying:
1. Parse and normalize the actual request authority. ASCII DNS names are lowercased and one trailing dot is removed; IP literals are exact, including bracketed IPv6 authorities. Invalid or missing authorities are blocked.
2. Check denylist first: if host matches any denied domain → return `403 Forbidden`.
3. Check allowlist: if allowlist is non-empty AND host matches no allowed domain → return `403 Forbidden`.
4. Domain matching: exact match OR suffix match (e.g., `example.com` matches `api.example.com`).
5. Denylist takes precedence over allowlist (more conservative).
6. Resolve the selected host and reject loopback, link-local, private, unspecified, multicast, and other non-public addresses before connecting. Revalidate the selected socket address to close DNS-rebinding races. `--allow-private-network` (or `proxy.allow_private_network`) relaxes this address-class check only when a non-empty `--allow-domains`/configured allowlist explicitly matches the requested hostname or literal IP; the flag alone never grants broad private-network reachability.

Proxied mode enforces transport below the proxy, so raw TCP/UDP bypass is denied. macOS permits only the exact invocation loopback proxy port. Linux enters an empty network namespace and passes only validated loopback TCP descriptors over a private, single-peer bridge to that proxy; AF_UNIX and descriptor-acquisition deputies are denied after setup. A denylist cannot cover aliases or a hostname reached through literal IP; use an allowlist for a strict destination set. Generic non-HTTP protocols receive neither forwarding nor secret restoration.

### 7.4 OnBlock Callback
When a domain is blocked, invoke the `OnBlock` callback (if set) with domain and reason. Used by monitor mode.

---

## 8. Monitor Mode

### Behaviour

When `--monitor` is passed:

**macOS:**
- Start `log stream --predicate 'eventMessage CONTAINS "deny" AND subsystem == "com.apple.sandbox"' --style compact` in background.
- Append matching lines to the private monitor log and show that log in a separately launched Terminal viewer.

**Linux:**
- Append proxy-level events (domain blocks, etc.) to the private monitor log and show it with a lifecycle-attached terminal emulator.
- Full audit log integration deferred to v2.

**All platforms:**
- Proxy domain block events logged via `OnBlock` callback → `[cdm-monitor] [network] BLOCKED <domain>: <reason>`.
- Create the monitor log exclusively below the trusted per-invocation runtime with mode `0600` and no symlink following.
- Pass the log path to any viewer as a distinct argument; never interpolate paths or wrapped-command argv into shell or AppleScript source.
- Resolve monitor helpers and viewers only from validated fixed absolute platform paths. Clear their inherited environment and restore only fixed locale plus the minimum user/display/session variables required for GUI launch; never inherit `PATH` or loader-control variables.
- Reap launcher and denial-stream children and close the viewer before removing the runtime.
- Treat an explicit `--monitor` setup failure as fatal; the wrapped command must not start with monitoring silently disabled.

---

## 9. Hard Denials and Path Resolution

CDM integrity paths are always read-only inside the sandbox, even if they fall inside a writable directory tree or explicit grant. Discovered sensitive files are also hard read- and write-denied. Persistence-oriented control paths are added only by `--sec`; explicit configured denials continue to apply in every mode. In `--worktree` mode, the ephemeral `.git` gitfile plus its pinned actual and common Git directories are invocation-specific hard write denials even though ordinary workspace content is RW. The effective VM rootfs cache (`$CDM_CACHE_DIR/rootfs`, or `~/.cdm/rootfs`) is hard read- and write-denied to the child.

| Path | Reason |
|------|--------|
| Global config/trust-store directory and project `.cdm` directory | Always: prevent policy mutation or parent replacement |
| Private invocation runtime and effective VM rootfs cache | Always: preserve trusted runtime state |
| Discovered sensitive files | When discovered by `--scramble` or `--sec`: prevent real secret disclosure or mutation |
| `--worktree` gitfile, actual Git directory, and common Git directory | Always: prevent post-sandbox Git redirection, hooks, filters, ref/index mutation, and host execution |
| Shell startup/logout files | `--sec`: prevent shell injection and persistence |
| Global `.gitconfig`, `.gitmodules`, `.ripgreprc`, `.mcp.json`, and Git hooks | `--sec`: prevent trusted-tool and Git execution-policy mutation |
| `.ssh/authorized_keys`, `.ssh/authorized_keys2`, `.ssh/config` | `--sec`: prevent SSH access modification |
| `.claude/{commands,agents,hooks}`, `.cursor/hooks`, `.codex/hooks`, `.vscode`, `.idea` | `--sec`: prevent agent/editor persistence and task injection |
| `/var/spool/cron`, `/etc/crontab` | `--sec`: prevent cron persistence |
| Existing control entries at the effective workspace root | `--sec`: protect exact active `.mcp.json`, `.gitmodules`, `.ripgreprc`, Git hooks, and editor/agent configuration without recursively banning those basenames in nested worktrees |

Relative paths are resolved relative to `$HOME`. Absolute paths used as-is.

For global and preset `paths.allow_ro`, `paths.allow_rw`, `paths.deny_read`, and `paths.deny_write`, relative paths resolve from `$HOME`; trusted project paths resolve from its discovered root. CLI grant paths resolve from the effective workspace after `--worktree`; `~` resolves from `$HOME`. Explicit grants must exist and are canonicalized before sandbox setup. Unknown or legacy JSON fields are errors.

Resolution happens exactly once after application discovery, worktree selection, secret discovery, and staging. Each hard-denial rule records its source, lexical directory entry, then-current canonical target (including a would-be target beneath a symlinked ancestor), existence, and captured file/directory kind. The workspace, grants, and runtime roots also retain captured device/inode identity and kind so adapters select file-versus-directory enforcement without consulting live host state. Every filesystem-policy path must be valid UTF-8 because Seatbelt, VM plans, and launcher protocols are textual; an unrepresentable path fails before child launch rather than being converted lossily. This restriction does not apply to wrapped-command argv bytes. Immediately before adapter dispatch CDM fails if a captured identity changed. Adapters consume the immutable snapshot and enforce its exact spellings; they do not re-run `canonicalize`, `exists`, or `is_dir` during launch.

On macOS, Seatbelt emits captured literal/subpath denials plus move-blocking `deny file-write-unlink` rules. On Linux, Bubblewrap overlays an inaccessible file or directory for read denials, a read-only bind for existing write denials, and a namespace-only read-only placeholder for a missing protected leaf; missing ancestors exist only in the new mount namespace. VM launcher and guest policy enforce captured existing paths at both boundaries. A missing protected leaf beneath a writable VM export is rejected before launch because creating its guest mount point through VirtioFS would mutate the host and could leave crash residue. CDM never creates persistent host placeholders for this purpose.

---

## 10. Output Format

All CDM status output goes to **stderr** (never stdout — stdout belongs to the wrapped command).

### Startup Messages
```
[cdm] scanning for secrets...
[cdm] 12 secrets scrambled, 8 env vars injected, 5 paths denied
[cdm] sandbox: seatbelt (darwin)
[cdm] running: <3 argv entries>
[cdm] network: proxied (port 18080, MITM)
```

The scanning and scrambling lines appear only for `--scramble` or `--sec`. A default invocation reports `network: direct` instead.

### Debug Mode (`CDM_DEBUG=1`)
```
[cdm] seatbelt profile:
(version 1)
(allow default)
...
[cdm] exec: sandbox-exec -f /tmp/cdm-seatbelt-xxx.sb <command>
[cdm] child exited with code 0
```

### Monitor Mode
```
[cdm-monitor] streaming Seatbelt denials...
[cdm-monitor] [network] BLOCKED evil.com: in deny list
```

### Proxy
```
[cdm-proxy] listening on :18080
[cdm-proxy] HTTP GET http://example.com               (debug only)
[cdm-proxy] CONNECT example.com:443                    (debug only)
[cdm-proxy] MITM example.com (server TLS verified)     (debug only)
[cdm-proxy] MITM example.com active (both TLS sessions up) (debug only)
[cdm-proxy] MITM setup failed: <reason>; connection rejected (debug only)
```

---

## 11. Defaults

| Setting | Default |
|---------|---------|
| Network | Direct; `--no-network` disables it, while `--scramble` or `--sec` opts into proxied networking unless paired with `--no-proxy` |
| Secret handling | Unchanged argv/environment and ordinary readable `.env`; `--scramble` and `--sec` opt into discovery, replacement, staging, and read denial |
| Proxy | Disabled; enabled and fail-closed by `--scramble` or `--sec` unless direct/disabled transport is selected |
| Proxy port | 18080 |
| Monitor | Disabled |
| Domain filtering | None (all domains allowed) |
| macOS capability baseline | Compatibility-first for direct/disabled normal mode; secure, isolated, and proxied modes are deny-first |
| Workspace access | Read/write (`--rw`); `--ro` is opt-in |
| Other host data | Read-only in normal mode; hidden in `--iso` |
| Writable paths | Workspace, private per-invocation runtime storage, explicit `allow_rw` grants, and paths derived by application mode |
| Config files | Global `~/.cdm/config.json` (override with `CDM_CONFIG_PATH`) plus nearest project `.cdm/config.json` |
| Protected paths | Integrity invariants always; persistence hardening under `--sec`; see Section 9 |
| Debug | Disabled |

---

## 12. Platforms

| Platform | Sandbox Mechanism | File Obfuscation | Minimum Requirement |
|----------|-------------------|-------------------|---------------------|
| macOS | Apple Seatbelt (`sandbox-exec`) | Env var injection + seatbelt read denial + config redirection | A Rust-supported macOS host with `/usr/bin/sandbox-exec`; tested on macOS 26.6 |
| Linux | Bubblewrap (`bwrap`) | bwrap bind mounts (automatic) | `bwrap` installed |
| VM macOS | libkrun microVM + TSI | Disposable rootfs + VirtioFS shares + denied-file mounts | macOS 14+, Apple silicon, target-specific bundled runtime signed with the Hypervisor entitlement |
| VM Linux | libkrun microVM + TSI | Disposable rootfs + VirtioFS shares + denied-file mounts | x86_64 or AArch64 target-specific bundled runtime |

Unsupported platforms exit with: `unsupported platform: <os>`.

The macOS AArch64 native and bundled-VM paths are acceptance-tested locally. Linux x86_64/AArch64 native and release paths are implemented contracts, but each release must be validated on its target architecture and glibc baseline before publication. Optional OCI-image and authenticated AI-harness matrices are not implied by the default test run.

---

## 13. Dependencies

**Runtime:** The default build has no libkrun dependency. A compile-only VM feature build requires libkrun 1.19+ on the build host. A runnable direct VM build must also receive a verified target-matching static guest init, digest, and provenance through the three `CDM_GUEST_INIT_*` build inputs; macOS additionally requires the Hypervisor entitlement. Release packages construct and verify those inputs, pin libkrun 1.19.4 and libkrunfw 5.5.0 beside CDM under `lib/cdm`, use only executable- or loader-relative runtime lookup, and require no end-user package manager or library-path environment variable. The checksum-verified libkrun source receives the committed filename-only firmware lookup patch, using `@loader_path` on macOS and `$ORIGIN` on Linux, so a host installation cannot satisfy the firmware load. macOS packages target 14.0 and carry the entitlement.

**Distribution:** `rust/packaging/package.sh release` emits a target-specific runtime archive and a corresponding-source archive containing the exact libkrun, libkrunfw, Linux 6.12.91 sources, and the applied package-relative firmware patch. The source archive must be published beside every runtime archive containing libkrunfw.

**Build:** See `rust/Cargo.toml`, `rust/Cargo.lock`, and `DEPENDENCIES.md`. OCI, tar, and gzip dependencies are optional under the `vm` feature.

---

## 14. Module Structure

[`ARCHITECTURE.md`](../ARCHITECTURE.md#modules-and-interfaces) is the canonical
module-ownership map. This specification defines observable behavior rather
than duplicating implementation boundaries.
