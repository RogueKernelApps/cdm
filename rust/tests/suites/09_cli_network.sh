#!/bin/bash
# CLI validation and network-policy regressions.

section "CLI Validation"

for shell in bash zsh fish; do
    OUT=$("$CDM" completions "$shell" 2>/dev/null)
    if [ "$?" -eq 0 ] && grep -Fq "allow-rw" <<<"$OUT" && \
        grep -Fq "preset" <<<"$OUT" && grep -Fq "profile" <<<"$OUT" && \
        grep -Fq "scramble" <<<"$OUT" && grep -Fq "setup" <<<"$OUT" && \
        grep -Fq "trust" <<<"$OUT" && \
        grep -Fq "project" <<<"$OUT" && grep -Fq "version" <<<"$OUT" && \
        grep -Fq "bash" <<<"$OUT" && grep -Fq "zsh" <<<"$OUT" && \
        grep -Fq "fish" <<<"$OUT"; then
        printf "  ${GREEN}PASS${NC} completions/%s derive flags and subcommands from typed CLI\n" "$shell"; PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} completions/%s include --allow-rw\n" "$shell"; FAIL=$((FAIL + 1))
    fi
done

ZSH_COMPLETIONS=$("$CDM" completions zsh 2>/dev/null)
RUN_COMPLETIONS=$(printf '%s\n' "$ZSH_COMPLETIONS" | awk '
    /^[[:space:]]*\(run\)/ { capture=1 }
    capture { print }
    capture && /^[[:space:]]*;;/ { exit }
')
COMPLETION_SHELLS=$(printf '%s\n' "$ZSH_COMPLETIONS" | awk '
    /^[[:space:]]*\(completions\)/ { capture=1 }
    capture { print }
    capture && /^[[:space:]]*;;/ { exit }
')
if grep -Fq -- '--allow-rw' <<<"$RUN_COMPLETIONS" && \
    grep -Fq -- '--report-json' <<<"$RUN_COMPLETIONS" && \
    grep -Fq -- '--profile' <<<"$RUN_COMPLETIONS" && \
    grep -Fq -- '--scramble' <<<"$RUN_COMPLETIONS"; then
    printf "  ${GREEN}PASS${NC} zsh run subcommand owns the typed run flags\n"; PASS=$((PASS + 1))
else
    printf "  ${RED}FAIL${NC} zsh run subcommand owns the typed run flags\n"; FAIL=$((FAIL + 1))
fi
if grep -Fq 'bash zsh fish' <<<"$COMPLETION_SHELLS"; then
    printf "  ${GREEN}PASS${NC} zsh completions subcommand enumerates supported shells\n"; PASS=$((PASS + 1))
else
    printf "  ${RED}FAIL${NC} zsh completions subcommand enumerates supported shells\n"; FAIL=$((FAIL + 1))
fi

for args in \
    "--allow-domains example.com" \
    "--scramble --no-proxy --allow-domains example.com" \
    "--scramble --no-network --deny-domains example.com" \
    "--no-network --no-proxy"; do
    STDERR=$("$CDM" $args true 2>&1 >/dev/null)
    RC=$?
    if [ "$RC" -eq 2 ] && grep -Eq "cannot be combined|do not combine|domain rules require" <<<"$STDERR"; then
        printf "  ${GREEN}PASS${NC} invalid network state is rejected: %s\n" "$args"; PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} invalid network state is rejected: %s (rc=%s, stderr=%s)\n" "$args" "$RC" "$STDERR"
        FAIL=$((FAIL + 1))
    fi
done

for flag in --allow-ro --allow-rw --allow-domains --deny-domains --profile --preset; do
    STDERR=$("$CDM" "$flag" 2>&1 >/dev/null)
    RC=$?
    if [ "$RC" -eq 2 ] && grep -Eq "requires|required" <<<"$STDERR"; then
        printf "  ${GREEN}PASS${NC} %s rejects a missing value\n" "$flag"; PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} %s rejects a missing value (rc=%s, stderr=%s)\n" "$flag" "$RC" "$STDERR"
        FAIL=$((FAIL + 1))
    fi
done

STDERR=$("$CDM" --preset does-not-exist true 2>&1 >/dev/null)
if [ "$?" -eq 2 ] && grep -Fq 'unknown preset' <<<"$STDERR"; then
    printf "  ${GREEN}PASS${NC} unknown configuration preset is rejected\n"; PASS=$((PASS + 1))
else
    printf "  ${RED}FAIL${NC} unknown configuration preset is rejected\n"; FAIL=$((FAIL + 1))
fi

PROFILE_ERROR_HOME=$(mktemp -d "${TMPDIR:-/tmp}/cdm_profile_error.XXXXXX")
STDERR=$(HOME="$PROFILE_ERROR_HOME" "$CDM" --profile does-not-exist true 2>&1 >/dev/null)
if [ "$?" -eq 2 ] && grep -Fq 'unknown built-in profile' <<<"$STDERR"; then
    printf "  ${GREEN}PASS${NC} unknown built-in profile is rejected\n"; PASS=$((PASS + 1))
else
    printf "  ${RED}FAIL${NC} unknown built-in profile is rejected\n"; FAIL=$((FAIL + 1))
fi
STDERR=$(HOME="$PROFILE_ERROR_HOME" "$CDM" --profile pi true 2>&1 >/dev/null)
if [ "$?" -eq 2 ] && grep -Fq 'cdm setup' <<<"$STDERR"; then
    printf "  ${GREEN}PASS${NC} known but disabled profile points to setup\n"; PASS=$((PASS + 1))
else
    printf "  ${RED}FAIL${NC} known but disabled profile points to setup\n"; FAIL=$((FAIL + 1))
fi
remove_test_path "$PROFILE_ERROR_HOME"

if has_native; then
    section "Status Output"

    STATUS_STDERR=$(cd "$FIXTURE" && "$CDM" true 2>&1 >/dev/null)
    check "status: startup uses the compact tree" "$STATUS_STDERR" 'cdm'
    check "status: startup groups the native sandbox" "$STATUS_STDERR" '├─ Sandbox:'
    check "status: startup distinguishes backend field and value" "$STATUS_STDERR" '└─ Backend:          "seatbelt"'
    check "status: startup groups file permissions" "$STATUS_STDERR" '├─ File permissions:'
    check "status: startup reports the resolved workspace mode" "$STATUS_STDERR" '├─ Workspace:        "rw"'
    check "status: startup reports default provenance" "$STATUS_STDERR" 'flags: `--ro`                          [default]'
    check "status: startup reports the resolved network mode" "$STATUS_STDERR" '└─ Mode:             "direct"'
    check "status: startup reports unchanged secrets" "$STATUS_STDERR" 'Mode:             "unchanged"'
    check "status: startup reports disabled worktree mode" "$STATUS_STDERR" 'Run in the current checkout'
    check "status: startup reports only the argv count" "$STATUS_STDERR" '└─ Run:                 "1 arg"      Arguments hidden'
    check_not "status: startup omits the old scattered prefix" "$STATUS_STDERR" '[cdm] sandbox:'

    STATUS_GRANT=$(cd "$FIXTURE" && "$CDM" -w "$FIXTURE/hello.sh" true 2>&1 >/dev/null)
    check "status: CLI grants show their exact source" "$STATUS_GRANT" 'Read/write grants: "1 path"'
    check "status: workspace grants are abbreviated" "$STATUS_GRANT" '└─ `$WORKSPACE/hello.sh`'
    check "status: CLI grant provenance is visible" "$STATUS_GRANT" '[cli]'
    check_not "status: abbreviated grants do not expose the workspace path" "$STATUS_GRANT" "$FIXTURE/hello.sh"

    FAILURE_STDERR=$(cd "$FIXTURE" && "$CDM" sh -c 'exit 7' 2>&1 >/dev/null)
    check "status: failed commands receive a completion tree" \
        "$FAILURE_STDERR" '└─ Status:           "failed"     Command exited with code 7'

    QUIET_STDERR=$(cd "$FIXTURE" && "$CDM" -q true 2>&1 >/dev/null)
    check_empty "quiet: short flag suppresses routine CDM status" "$QUIET_STDERR"
    QUIET_STDERR=$(cd "$FIXTURE" && "$CDM" --quiet true 2>&1 >/dev/null)
    check_empty "quiet: long flag suppresses routine CDM status" "$QUIET_STDERR"
    QUIET_STDERR=$(cd "$FIXTURE" && "$CDM" --quiet sh -c 'exit 7' 2>&1 >/dev/null)
    check_empty "quiet: failed command suppresses routine completion status" "$QUIET_STDERR"

    QUIET_CHILD_STDERR=$(cd "$FIXTURE" && \
        "$CDM" --quiet sh -c 'printf "child-stderr\n" >&2' 2>&1 >/dev/null)
    check_eq "quiet: wrapped stderr passes through unchanged" \
        "$QUIET_CHILD_STDERR" "child-stderr"

    QUIET_ERROR=$(cd "$FIXTURE" && \
        "$CDM" --quiet --no-network --no-proxy true 2>&1 >/dev/null)
    check "quiet: CDM errors remain visible" "$QUIET_ERROR" '[cdm] error:'
fi

PROJECT_TEST=$(mktemp -d "${TMPDIR:-/tmp}/cdm_project_report.XXXXXX")
mkdir -p "$PROJECT_TEST/.cdm" "$PROJECT_TEST/src/deep"
printf '[package]\nname="fixture"\nversion="0.1.0"\n' > "$PROJECT_TEST/Cargo.toml"
printf '{}\n' > "$PROJECT_TEST/.cdm/config.json"
PROJECT_ROOT=$(CDPATH= cd -- "$PROJECT_TEST" && pwd -P)
PROJECT_OUTPUT=$(cd "$PROJECT_TEST/src/deep" && "$CDM" project 2>&1)
if [ "$?" -eq 0 ] && grep -Fq "root: $PROJECT_ROOT" <<<"$PROJECT_OUTPUT" && \
    grep -Fq 'kind: rust' <<<"$PROJECT_OUTPUT" && \
    grep -Fq "config: $PROJECT_ROOT/.cdm/config.json" <<<"$PROJECT_OUTPUT"; then
    printf "  ${GREEN}PASS${NC} project reports deterministic nearest root, kind, and config without trusting it\n"; PASS=$((PASS + 1))
else
    printf "  ${RED}FAIL${NC} project reports deterministic nearest root, kind, and config\n"; FAIL=$((FAIL + 1))
fi
remove_test_path "$PROJECT_TEST"

if ! has_vm; then
    skip "VM network policy" "VM support is not compiled into this artifact"
    return 0 2>/dev/null || exit 0
fi

section "VM Network Policy"

# Host proxy variables must not survive --no-proxy.
OUT=$(cd "$FIXTURE" && \
    HTTP_PROXY=http://inherited.invalid:9999 \
    HTTPS_PROXY=http://inherited.invalid:9999 \
    ALL_PROXY=http://inherited.invalid:9999 \
    NO_PROXY='*' \
    "$CDM" --vm --no-proxy sh -c \
    'test -z "$HTTP_PROXY$HTTPS_PROXY$ALL_PROXY$NO_PROXY$http_proxy$https_proxy$all_proxy$no_proxy" && echo clean' \
    2>/dev/null)
check "vm: --no-proxy removes inherited proxy variables" "$OUT" "clean"

if ! command -v python3 >/dev/null 2>&1; then
    skip "vm: --no-network blocks TSI" "python3 is unavailable for the host listener"
    return 0 2>/dev/null || exit 0
fi

PORT=19317
python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 0.3

OUT=$(run_cdm --vm sh -c \
    "wget -q -T 3 -O - http://127.0.0.1:$PORT >/dev/null 2>&1 && echo reachable")
check "vm: direct networking is the default and reaches host listener" "$OUT" "reachable"

OUT=$(run_cdm --vm --no-network sh -c \
    "if wget -q -T 2 -O - http://127.0.0.1:$PORT >/dev/null 2>&1; then echo reachable; else echo blocked; fi")
check "vm: --no-network keeps guest execution working" "$OUT" "blocked"
check_not "vm: --no-network cannot reach host listener" "$OUT" "reachable"

kill "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null
