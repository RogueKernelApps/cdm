# CDM architecture

## Runtime flow

```text
CLI/config
   │
   ├─ validate command and flags
   ├─ load the private enabled-profile registry and apply explicit profiles
   ├─ for an app command, derive executable and narrow state from bundle evidence
   ├─ optionally allocate Git worktree
   ├─ resolve one access policy (workspace mode, isolation, grants, denials)
   ├─ with --scramble/--sec, scan secrets and build sandbox-visible staged files
   ├─ with --scramble/--sec, optionally start an ephemeral HTTP(S) proxy
   └─ dispatch
       ├─ macOS → Seatbelt profile → child process
       ├─ Linux → Bubblewrap namespace → child process
       └─ VM → cached base rootfs → disposable clone → libkrun guest
                                                        │
                                                        └─ VirtioFS: workdir, stage, CA

child exit → stop proxy → remove per-run artifacts → finalize worktree
```

The orchestration order is deliberate: the best-effort command preflight runs before allocating a worktree or proxy; when scrambling is selected, secrets are scanned from the effective worktree; and cleanup occurs before returning the child exit code. Without `--scramble` or `--sec`, secret discovery and staging are skipped entirely. The preflight catches obvious direct-invocation mistakes by exact executable basename and token boundaries; it is not an execution-control security boundary. Workspace setup snapshots Git-visible tracked and untracked state, reserves its result branch atomically, preserves the invocation's repo-relative directory, and pins the worktree gitfile, actual/common Git directories, and trusted Git executable. Those metadata paths are added to the resolved hard write denials. Finalization validates the pinned identities, builds a tree through filter-free plumbing and a private index, creates a commit without porcelain hooks or signing helpers, atomically moves only the reserved ref, and removes the temporary worktree; setup failures discard both resources.

## Modules and interfaces

| Module | Responsibility | Main boundary |
|---|---|---|
| `main.rs` | Top-level dispatch and private helper entry points | Typed action, exit status |
| `invocation.rs`, `invocation/lifecycle.rs` | Complete command lifecycle behind one `run` interface; private resource owner unwinds proxy, worktree, runtime, and report publication | Typed invocation, exit status |
| `cli.rs` | Typed argv parsing, help, and generated completions | `OsString` argv → `Action` |
| `project.rs` | Discover the nearest project config/root and report deterministic project kind | Launch path → `ProjectContext` |
| `app.rs` | Resolve a macOS app executable and verified, narrowly inferred writable state | `.app` + trusted home root → `AppPlan` |
| `access.rs` | Resolve filesystem modes, grants, runtime roots, and hard denials | `ResolvedAccessPolicy` |
| `config.rs` | Defaults, trusted preset/project layering, exact-byte project trust store | Global + presets + trusted `.cdm/config.json` → `LoadedConfig` |
| `setup.rs` | Detect supported coding harnesses without execution, own the interactive checklist, and atomically update enabled profile IDs | TTY + compiled catalog → private registry |
| `origin.rs` | Name the exact source of an effective policy value | Built-in, CLI, config-layer, derived, or app provenance |
| `guard.rs` | Best-effort exact-token command preflight | Command argv |
| `secrets.rs` | Detect secrets and create deterministic real/fake maps | Host env and discovered values |
| `stage.rs` | Obfuscate readable config copies and inject `.env` entries | Per-run temporary directory |
| `network.rs` | Construct valid disabled/direct/proxied states and normalize request authorities | `NetworkPolicy`, `DomainPolicy` |
| `proxy.rs` | MITM HTTP(S), global domain policy, scoped request restoration, response re-obfuscation | Loopback HTTP proxy and ephemeral CA |
| `process.rs` | Supervise host adapter process groups, terminal ownership, signals, descendants, and wait status | `Command` → exact CDM exit code |
| `sandbox.rs` | Shared environment and policy model; platform dispatch | `SandboxConfig` |
| `sandbox/darwin.rs` | Generate and execute a Seatbelt profile | `/usr/bin/sandbox-exec` |
| `sandbox/linux.rs` | Generate Bubblewrap arguments | `bwrap` |
| `sandbox/vm.rs` | Orchestrate disposable rootfs preparation and VM filesystem exports | VM launcher and guest-plan modules |
| `sandbox/vm/launcher.rs` | Validate the private launcher protocol, supervise the host VMM, and own the libkrun FFI/context | libkrun C API, Seatbelt/Bubblewrap |
| `sandbox/vm/guest_plan.rs` | Translate resolved access into the versioned guest mount/deny plan | Static guest init JSON contract |
| `rust/guest-init/` | Static Linux PID 1, strict guest plan, mounts/denies, identity, signals | Versioned JSON plan |
| `sandbox/rootfs.rs` | Bundled/OCI rootfs resolution and immutable cache | OCI registry API, tar layers |
| `worktree.rs` | Snapshot current Git-visible state into a temporary worktree and own its reserved result branch lifecycle | `git` CLI plus descriptor-relative no-follow filesystem reads |
| `trusted_exec.rs` | Resolve, validate, and identity-pin host helper executables before trusted operations | Root-owned system tools only |
| `report.rs` | Own the bounded, schema-versioned report model and descriptor-pinned atomic publication | `serde_json`, host filesystem |
| `status.rs` | Render grouped, quiet-aware effective-policy and notable completion status | Resolved invocation state, typed provenance, child exit, and worktree result |
| `monitor.rs` | Platform denial-log streaming | OS log facilities |

The project is intentionally one binary with deep modules around isolation backends. `app.rs` hides application-specific metadata and convention logic behind one plan; the CLI does not reproduce it. `origin.rs` provides the small typed provenance vocabulary shared by configuration, access resolution, invocation, and status. Configuration records the layer that contributed each path, and `access.rs` carries that source through its one-time canonicalization so `status.rs` never resolves filesystem policy independently. Status presentation quotes resolved scalar values and wraps flags, paths, branch names, and actionable commands in backticks; delimiter characters and terminal controls are escaped before rendering. VM-only OCI and archive code is behind the `vm` Cargo feature; a native build contains no VM SDK dependency. Release-only library acquisition, relocation, signing, and source compliance live behind the single `packaging/package.sh` interface rather than leaking into runtime code.

`report.rs` is deliberately not a general logging interface. Its public schema accepts bounded enums and numeric aggregates, caps detailed events, and omits resource names and free-form diagnostics. `invocation.rs` creates a provisional report before project/config/guard validation, replaces its optional policy with the effective snapshot once available, then explicitly completes child, proxy, worktree, staged-file, runtime, and cleanup outcomes. A fail-safe unwind report records pending cleanup as `incomplete`, never success. This guarantees early failures are published without inventing unresolved policy or successful teardown. A report destination is prepared before child execution with a pinned directory descriptor; publication revalidates device/inode identity, uses `openat`/`renameat`, fsyncs file and directory, and refuses symlinks. Known real secret values receive a final serialized-byte scan. Filesystem denial observation remains explicitly `not_instrumented`; configured policy is never presented as observed enforcement telemetry. Proxy counters distinguish `bytes_from_child`, `bytes_to_upstream`, `bytes_from_upstream`, and `bytes_to_child`.

## External SDKs and protocols

- **libkrun C API (VM feature):** context lifecycle, VM resources, root, VirtioFS, exec, vsock/TSI policy, and guest entry. Release packages pin libkrun 1.19.4 and libkrunfw 5.5.0. CDM links libkrun through an executable-relative `lib/cdm` rpath; libkrun loads the adjacent firmware library. No package contains a build-host or Homebrew runtime path.
- **OCI Distribution API (VM feature):** `oci-client` authenticates, pulls manifests and layers, and feeds the rootfs cache. Layer whiteouts are applied before safe extraction.
- **HTTP proxy stack:** hudsucker, Hyper body utilities, Tokio, and rustls implement HTTP forwarding and generated MITM certificates. HTTP/2 remains disabled because CONNECT handling uses the HTTP/1 path.
- **Host adapters:** Seatbelt and Bubblewrap are command-line boundaries, not linked SDKs.
- **Git:** disposable project isolation is implemented with worktree and branch commands.

Host helpers are part of CDM's trusted computing base, not project tooling.
CDM therefore never selects Git, Bubblewrap, Seatbelt, or rootfs-copy helpers
from a project- or user-writable path. Conventional absolute system paths are
preferred; the small resolver accepts a `PATH` fallback only when every path
component and the executable are root-owned, non-group/world-writable, and
non-symlinked. The selected device/inode identity is checked again before each
launch, and host-only helpers receive a cleared, narrowly rebuilt environment.

## State and lifetime

| State | Lifetime | Contains real secrets? | Sandbox-visible? |
|---|---|---:|---:|
| `SecretMapping` | One invocation, memory only | Yes | No |
| Proxy CA/bundle | One invocation | No | Yes, read-only in VM |
| Obfuscated stage | One invocation | No | Yes, read-only where possible |
| Base rootfs cache | Across invocations | No | Cloned, never run directly |
| Disposable VM rootfs | One invocation | Fake env/config only | Guest root |
| Git worktree | One worktree invocation | Project-dependent | Yes; tracked and non-ignored untracked state |
| Setup profile registry | Across invocations | No | No; file and parent are hard write-denied |

Worktree sessions begin at the original `HEAD`, create a no-checkout worktree, copy the caller's materialized tracked filesystem entries plus non-ignored untracked files without Git diff/checkout filters, and create the equivalent relative execution directory. Sparse `S`/`s` paths absent from the caller stay absent and retain their base-index entries; ordinary absent tracked paths remain observed deletions. Ignored paths are not copied. A branch is reserved before sandbox entry, so repeated and concurrent sessions cannot collide. The sandbox receives ordinary project data at the selected workspace access level, while its `.git` gitfile and the pinned actual/common Git directories remain hard write-denied. No-change sessions delete the reservation. Changed sessions pin the worktree root as a directory descriptor, walk every relative path with no-follow descriptor operations, hash regular files from already-open descriptors, and hash symlink target bytes without following them. A tracked directory replaced by a symlink becomes one mode-`120000` entry and its former descendants are removed. The resulting entries and observed deletions are overlaid onto a private index initialized from the base commit, then written as a tree and single-parent `commit-tree` commit before compare-and-swapping the reserved ref. Every trusted Git process uses the identity-pinned system executable and a cleared environment; repository hooks, clean/smudge/process filters, signing helpers, fsmonitor, prompts, optional locks, and pagers cannot become post-sandbox host execution. This deliberately means filter-materialized bytes that differ from the stored blob, such as Git LFS content, are committed raw rather than passed through an untrusted clean filter. Command failure does not discard useful changes, while metadata drift or another finalization failure changes an otherwise successful CDM exit into an error.

## Filesystem access model

The typed CLI and layered JSON configuration are translated once into `ResolvedAccessPolicy`, after every invocation mutation and sensitive-path discovery; adapters borrow that immutable snapshot rather than reinterpreting flags or live filesystem state. Project discovery happens from the original launch directory before `--worktree` creates a temporary worktree. `cdm project` reports the discovered root plus a fixed marker-based kind and never changes policy. Configuration precedence is built-ins, global configuration (`~/.cdm/config.json` or `CDM_CONFIG_PATH`), explicitly selected built-in profiles in CLI order, repeatable global named presets in CLI order, the trusted nearest project `.cdm/config.json`, then CLI flags. Path lists are additive. Their origin is retained until `access.rs` resolves global/profile/preset relatives from `$HOME`, project relatives from the project root, and CLI relatives from the effective workspace. Missing optional profile-state paths are omitted; missing explicit config or CLI grants still fail closed. Hard-denial snapshots retain origin, existence/kind, the lexical name, and its canonical or would-be canonical target; the workspace, grants, and runtime roots retain captured device/inode identity and kind as well. Both denial spellings are applied last. Access resolution rejects non-UTF-8 policy paths before dispatch because not every backend can represent them exactly; command argv remains byte-preserving. Immediately before dispatch CDM rejects any frozen object whose identity changed. Adapters then use the captured path and kind and never re-run filesystem classification or canonicalization.

Project policy is an explicit trust boundary. `cdm trust` opens a regular, single-link project config with `O_NOFOLLOW`, verifies and parses bytes read from that same descriptor, and atomically records their SHA-256 digest in a mode-0600 store outside the workspace. Loading repeats the one-open read/hash/parse flow; any byte change invalidates trust. Global presets are trusted host policy, so project files cannot declare them and presets cannot nest. Policy files and their dedicated containing directories are hard write-denied in the child, preventing direct writes, symlink/hard-link substitution, and parent rename/swap bypasses. A custom global config is accepted only beneath a real, user-owned, non-group/world-writable dedicated directory; direct broad-root placement fails before sandbox startup.

The setup registry is a separate host-owned policy input. `setup.rs` checks only
bounded `PATH` candidates and fixed user-state markers, presents the four-entry
compiled catalog, and sends selected IDs to `config.rs`; detection never grants
access or executes a tool. `config.rs` validates the version and every ID from
one no-follow, regular, single-link, mode-0600 read beneath a real mode-0700
`~/.cdm`, then applies only IDs also named by `--profile`. Updates use a private
temporary file, file sync, and atomic rename, preserving prior bytes on every
pre-publication failure. Built-in profile and user preset namespaces remain
independent. The registry file and its narrow parent join unconditional hard
write denials.

The effective workspace is read/write by default and read-only under `--ro`. Host access is normal by default—readable but not writable outside explicit writable roots—and allowlisted under `--iso`. `--iso --ro` therefore isolates host data and makes the workspace read-only. Independently, CDM creates a unique mode-0700 session beneath an invoking-user-owned private runtime root and overrides `TMPDIR`, `TMP`, and `TEMP` for every child. When requested, staged secret files and proxy material join VM plans and monitor logs beneath this session rather than becoming independent raw-temp artifacts. Adapters expose the session as one resolved runtime capability, so `--iso` can consume exact staged files without granting their host originals.

Monitor mode creates its log with exclusive, no-symlink, mode-0600 semantics. Viewer paths are passed as argv; macOS AppleScript receives the path as an argument and applies `quoted form` rather than embedding it in source. Host helpers and terminal viewers are fixed, validated absolute executables and receive only a small GUI/session environment allowlist rather than the wrapped command's `PATH`, loader variables, or broader environment. Launcher, denial-stream, and viewer children are explicitly reaped or closed before runtime cleanup. Because `--monitor` is an explicit request, any setup failure aborts before untrusted execution rather than degrading to a warning.

Secure mode is also a filesystem policy producer. On every backend, `--sec` implies secret scrambling and adds `SecurePersistence` denials for home-level shell, Git, SSH, editor, agent, and cron control paths plus existing control entries at the effective workspace root. Workspace entries are exact and existing-only rather than recursive basename matches: active `.mcp.json`, `.gitmodules`, `.ripgreprc`, hook directories, and editor/agent configuration can be protected without blocking the same tracked names from being materialized in nested worktrees or fixtures. CDM integrity invariants—policy/trust paths, private runtime/cache state, and CDM-owned worktree metadata—remain unconditional; discovered credential files become denials only during a scrambled invocation.

macOS has two capability baselines. Compatibility mode remains the default and begins with `(allow default)` before subtracting writes. `--sec` begins with `(deny default)` and restores only process lifecycle operations, Fence's named Mach lookup baseline, required runtime facilities, the resolved filesystem policy, and the chosen network policy. Mach registration and sandbox-extension issuance remain denied. macOS `--iso` uses the same deny-first baseline because explicit file-read exceptions cannot override an earlier Seatbelt deny; its filesystem allowlist remains independently controlled by `HostAccess::Isolated`.

Application mode is a policy producer, not another sandbox adapter. An existing `.app` in command position activates it transparently; `--app` is the equivalent explicit compatibility form. Selecting the bundle is an explicit caller trust decision, so CDM does not invoke Gatekeeper or codesign. It parses `.app` metadata once, resolves a contained executable, and derives a read-only bundle grant. Automatic RW combines two narrow evidence sources: exact bundle-ID leaves beneath fixed macOS state roots, including the conventional container; and literal bundle references to product-derived hidden state or existing product-related cache children. Versioned cache grants require the exact referenced version. The reference scan is bounded by file type, count, depth, per-file size, and aggregate bytes.

The selected bundle is evidence only about narrow app-shaped state, never authority to request an arbitrary path. Reserved home roots are excluded, broad parents are never granted, and every inferred grant carries a source label printed before launch. Symlinks and containment escapes fail closed. Runtime-computed nonstandard state requires a manual grant. Discovery never observes an unsandboxed execution.

`-r`/`--allow-ro` and `-w`/`--allow-rw` are repeatable. Config equivalents are `paths.allow_ro` and `paths.allow_rw`; global/preset paths use `$HOME`, trusted project paths use the project root, and CLI-relative paths use the effective workspace. Grants are canonicalized and must exist. Hard read/write denials are applied last. Integrity denials for policy files/directories, private runtime/cache state, and CDM-owned worktree metadata apply in every mode. Discovered secret files are denied only with `--scramble` or `--sec`. Persistence denials for shell and global Git configuration, hooks, SSH configuration, cron state, and active workspace control files apply only under `--sec`. Ordinary `.git` metadata inside a normal RW workspace follows the workspace policy. When `--worktree` is selected, its invocation-specific gitfile plus pinned actual/common Git metadata remain hard write-denied because trusted host finalization owns them.

Adapter enforcement is equivalent in intent:

- Seatbelt starts with a global write denial and restores only the private invocation runtime, the RW workspace, and explicit RW grants. Isolated mode also uses a read allowlist. macOS path rules include both public and physical spellings for `/tmp`/`/private/tmp`, `/var`/`/private/var`, and `/etc`/`/private/etc`, so tools can create nested files beneath an injected public `TMPDIR`. Captured lexical/canonical denial rules and unlink rules are emitted last.
- Bubblewrap uses a read-only host root in normal mode and an allowlisted empty root in isolated mode, then binds the private invocation runtime, the workspace, and grants at their resolved access levels. Existing denied directories receive inaccessible overlays; missing protected names receive namespace-only mount-point placeholders and never mutate the host.
- libkrun exposes only the workspace and explicit grants. Guest init creates its own mode-0700 per-invocation runtime path; VirtioFS exports carry host-enforced read-only flags, hard-denied existing paths receive narrower read-only or inaccessible masks, and the command runs as an unprivileged guest UID after root performs mount setup. An individual write-denied file is exported through a dedicated host-read-only VirtioFS directory and bind-mounted at its captured target; strict plan validation requires that immutable backing export. Missing denied names under RW exports fail before launch rather than creating crash-persistent placeholders through VirtioFS.

Rootfs cache population is locked, extracted into a private temporary directory, cryptographically bound to a deterministic tree digest, and atomically promoted. The absolute effective cache is current-user-owned, mode 0700, symlink-safe, and part of the child's final hard-read and hard-write denial set. Authenticated OCI layers stream into mode-0600 `O_NOFOLLOW|O_EXCL` files instead of process memory; independent per-layer and per-image compressed-byte, expanded-byte, entry-count, and path-depth quotas bound gzip/tar resource use. OCI whiteouts and opaque directories are handled explicitly only after the complete layer passes validation. Failed and stale temporary artifacts are removed without following symlinks. Each VM clones the verified complete base into the private invocation runtime and removes the clone on drop, preventing native-to-VM cache poisoning and one guest from mutating later runs.

## Network model

`NetworkPolicy` has three valid states: disabled, direct, or proxied with a parsed `DomainPolicy`. Direct is the default. `--scramble` or `--sec` selects proxied networking unless `--no-network` or `--no-proxy` overrides transport. Domain flags require scrambling and are invalid with direct or disabled networking. Proxy creation, CA export, binding, and runtime readiness are fail-closed. `ProxySession` owns its thread, shutdown channel, CA files, and listener lifetime and joins before removing artifacts.

On macOS, proxied commands use the deny-first Mach/XPC baseline and may connect only to the exact per-run loopback proxy port. Raw TCP and UDP therefore cannot bypass domain rules. Every macOS VM VMM enters through a fresh exec'd launcher under a deny-first Seatbelt profile: it can read the signed executable, bundled libkrun runtime, Apple runtime, disposable rootfs, and exact VirtioFS sources; it can write only the rootfs, invocation runtime, and resolved RW exports. Hard denials are emitted last. Network rules then select disabled, direct, or exact-proxy transport, so libkrun TSI inherits the chosen restriction. The parent prepares and owns the disposable rootfs; its private launcher plan contains paths and VM settings but no environment or real secret map. Public CA material is copied safely into `/etc/cdm` in the disposable guest. `--no-network` replaces libkrun's implicit TSI-enabled vsock with an explicit vsock whose TSI feature mask is zero.

While scrambling is selected, secret restoration has a second, independent authorization layer after global
domain policy. Each fake-to-real mapping carries validated destination suffixes;
unknown mappings carry none. Deny rules run first, then only mappings matching
the normalized request authority may rewrite the target, headers, or body. The
proxy forces identity response encoding, rejects encoded upstream bodies, and
re-obfuscates all known real values before returning headers or bounded bodies.
Real maps and scopes never enter native argv, VM plans, staged files, or reports.

Secret discovery pins the effective home and workspace roots and traverses
candidate files and SSH entries with descriptor-relative, no-follow operations.
Parsing and staging consume the opened descriptors rather than reopening
pathnames. Real and fake mapping sets remain disjoint, and every nonempty value
whose environment name is secret-like is replaced regardless of length. Values
shorter than eight bytes use long origin-bound environment sentinels rather than
ambiguous global substring replacement; all global replacement and restoration
is longest-match and single-pass.

The trusted host retains wrapped commands as `OsString` values. Native adapters
pass those values directly to the operating system. VM plans use schema 2 byte
arrays, and the static guest init reconstructs `OsString` values only after
bounded validation and NUL rejection. No adapter joins, UTF-8-normalizes, or
shell-reparses argv; shell syntax is available only through an explicitly
requested shell. Diagnostics and structured reports expose counts, never argv
values.

Linux replaces host runtime socket trees such as `/run` with frozen synthetic mount targets and rejects grants that directly expose pathname sockets or known deputy locations. Proxied mode enters an empty network namespace; an exact private AF_UNIX control channel passes only validated loopback TCP descriptors to the trusted host proxy bridge. A seccomp filter denies AF_UNIX creation plus dangerous descriptor-acquisition syscalls after bridge setup. Direct and disabled modes apply the same filter directly to the wrapped process or VMM. The Linux VM launcher runs inside Bubblewrap: normal host mode supplies a read-only host root, isolated mode supplies only system loader/runtime roots, and both modes restore only the disposable rootfs, private session, exact VirtioFS sources, `/proc`, Bubblewrap's minimal `/dev`, and `/dev/kvm`. CDM preflights read/write access to `/dev/kvm` and does not add a nested user namespace that could discard the invoking user's supplementary `kvm` group. Hard denials are overlaid last with inaccessible sources. Libkrun implicit TSI is disabled in every mode and re-added with only INET/INET6 support when networking is enabled; guest AF_UNIX impersonation is never enabled.

VM filesystem translation is intentionally narrower than native translation. The guest sees its Linux rootfs, workspace, staged public material, and explicit VirtioFS grants; normal host-readable paths are not automatically mirrored at identical guest paths because macOS paths and host binaries do not form a valid Linux guest filesystem. Use `-r`/`-w` (or `--allow-ro`/`--allow-rw`) for portable directory exports and commands installed in the selected guest image. VirtioFS exports directories, so an external single-file VM grant is rejected: guest-side bind masking would hide siblings from the command but would not constrain a compromised VMM from reading the exported parent. The VMM host process is still confined according to the resolved host-access intent.

By default, `.env` remains an ordinary readable workspace file, is not sourced by CDM, and environment/argv values pass through unchanged. With `--scramble` or `--sec`, sensitive `.env` entries are injected into the child environment with recognized values scrambled and the original file remains hidden. Structured JSON credentials are then discovered and staged by parsed value rather than line heuristics, including minified Docker configuration. VM read denials bind a root-owned mode-000 placeholder from a root-only guest directory over the captured target. Individual write denials bind from a dedicated host-read-only VirtioFS export instead. In both cases the target is a busy mount point, and the wrapped command is a capability-free non-root process that cannot replace it; writes through the latter also fail at its immutable backing superblock. The guest does not attempt a read-only remount of either single-file bind because libkrun's VirtioFS guest mount rejects that operation with `EINVAL`; real-VM acceptance proves reads, overwrites, and unlinks fail as applicable and that the host file remains byte-identical.

## Trust model and remaining constraints

CDM protects the host from a developer command; it is not a general multi-tenant container runtime. The host CDM process, host kernel, sandbox adapter, libkrun, and proxy are trusted. The child command and its dependencies are untrusted.

Current constraints:

- Command-name preflight is mistake prevention only. Neither Seatbelt nor Bubblewrap/libkrun provides a portable executable-name denial: path rules miss copied or alternate binaries, and a started interpreter or helper can perform a later `exec`. Enforceable containment comes from resolved filesystem policy, adapter network policy, and host-only secret restoration. Use `--no-network` or a strict domain allowlist when a command must not reach AWS; the default `aws` preflight pattern is not that guarantee.

- VM release archives are target-specific: macOS 14+ on Apple silicon, Linux x86_64, or Linux AArch64. OCI images must match the host/guest architecture.
- Runtime archives containing libkrunfw must be distributed with their matching corresponding-source archive.
- Native adapter availability depends on the host. In particular, macOS may reject nested `sandbox-exec` from an already restricted parent process.
- Native adapters run under the shared host process supervisor in a dedicated process group without user code after fork. On Linux, Bubblewrap's PID namespace and `--die-with-parent` make the namespace lifecycle the containment boundary, so `setsid` and double-fork cannot survive Bubblewrap. macOS has no supported PID namespace, subreaper, or recursive process-tracking API: Apple's `NOTE_TRACK` kqueue flags have explicitly been unsupported since macOS 10.5. CDM therefore guarantees cleanup only for the original macOS process group; a child that deliberately creates a new session can outlive native supervision while retaining its inherited Seatbelt restrictions. Use VM mode where malicious daemon containment is required. The VM launcher uses the same process-group principles with explicit `posix_spawn`, avoiding fork-after-Tokio. Supervisors poll without an interrupt race, forward signals received by CDM to the whole group, restore terminal ownership, and preserve normal or signaled exit status. Interactive terminal ownership currently goes to the foreground child group so reads work; consequently, a terminal-generated signal deliberately ignored by the entire group is not observable by the parent for escalation. Closing that edge requires an intermediate foreground supervisor or PTY relay.
- Denylists match request authorities, not every DNS alias or equivalent literal IP. Allowlists are the strict destination mechanism. Non-HTTP protocols do not receive secret restoration.
- VM mode is inherently host-isolated; `--iso` still controls host-side credential discovery and reports the same resolved policy as native adapters.
