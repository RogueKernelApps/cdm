#!/bin/bash
# CLI and configuration failures must be explicit and occur before sandboxing.

section "Malformed CLI input"

for dangerous_path in "" / . .. "$PWD" "${TMPDIR:-/tmp}" /tmp/cdm; do
    if remove_test_path "$dangerous_path" 2>/dev/null; then
        check_eq "cleanup helper refuses dangerous operand" "accepted" "refused"
    else
        check_eq "cleanup helper refuses dangerous operand" "refused" "refused"
    fi
done

REMOVE_HELPER_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdm-cleanup-helper.XXXXXX")
touch "$REMOVE_HELPER_ROOT/removable"
remove_test_path "$REMOVE_HELPER_ROOT/removable"
check_eq "cleanup helper removes a CDM-owned temporary file" \
    "$(test ! -e "$REMOVE_HELPER_ROOT/removable"; echo $?)" "0"
remove_test_path "$REMOVE_HELPER_ROOT"

expect_cli_error() {
    local name="$1"; shift
    local output status
    output=$("$CDM" "$@" 2>&1 >/dev/null)
    status=$?
    check_eq "$name: exits with usage status" "$status" "2"
    check_nonempty "$name: explains the failure" "$output"
}

for flag in --allow-ro --allow-rw --app --allow-domains --deny-domains --vmi --report-json; do
    expect_cli_error "$flag missing value" "$flag"
done
expect_cli_error "conflicting --rw/--ro" --rw --ro true
expect_cli_error "conflicting --vm/--vmi" --vm --vmi alpine:3.21 true
expect_cli_error "config rejects arguments" config unexpected
expect_cli_error "completions requires a shell" completions
expect_cli_error "completions rejects an unknown shell" completions powershell
expect_cli_error "empty allow-domain list" --allow-domains ,,, true
expect_cli_error "empty deny-domain list" --deny-domains ,,, true

section "Malformed configuration"

CONFIG_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdm-input-config.XXXXXX")

OUT=$(CDM_CONFIG_PATH="/tmp/cdm-insecure-config-$$.json" "$CDM" --no-network true 2>&1 >/dev/null)
RC=$?
check_eq "custom config directly under a broad temporary root is rejected" "$RC" "2"
check "insecure custom config explains dedicated-directory requirement" "$OUT" "dedicated policy directory"

INSECURE_DIR="$CONFIG_ROOT/world-writable"
mkdir -p "$INSECURE_DIR"
chmod 733 "$INSECURE_DIR"
OUT=$(CDM_CONFIG_PATH="$INSECURE_DIR/config.json" "$CDM" --no-network true 2>&1 >/dev/null)
RC=$?
check_eq "custom config under a writable policy directory is rejected" "$RC" "2"
check "writable custom config parent explains permission requirement" "$OUT" "group/world writable"

printf '{ definitely not json' > "$CONFIG_ROOT/malformed.json"
OUT=$(CDM_CONFIG_PATH="$CONFIG_ROOT/malformed.json" "$CDM" --no-network true 2>&1 >/dev/null)
RC=$?
check_eq "malformed global config exits with usage status" "$RC" "2"
check "malformed global config identifies configuration failure" "$OUT" "config"

printf '{"unknown_contract_field":true}\n' > "$CONFIG_ROOT/unknown.json"
OUT=$(CDM_CONFIG_PATH="$CONFIG_ROOT/unknown.json" "$CDM" --no-network true 2>&1 >/dev/null)
RC=$?
check_eq "unknown global config field exits with usage status" "$RC" "2"
check_nonempty "unknown global config field explains the failure" "$OUT"

mkdir -p "$CONFIG_ROOT/project/.cdm"
printf '{ malformed project json' > "$CONFIG_ROOT/project/.cdm/config.json"
OUT=$(cd "$CONFIG_ROOT/project" && \
    CDM_CONFIG_PATH="$CONFIG_ROOT/missing-global.json" "$CDM" trust 2>&1 >/dev/null)
RC=$?
check_eq "malformed project config exits with usage status" "$RC" "2"
check "malformed project config identifies its path" "$OUT" ".cdm/config.json"

NON_UTF8_MARKER="$CONFIG_ROOT/non-utf8-child-marker"
OUT=$(python3 - "$CDM" "$NON_UTF8_MARKER" <<'PY'
import os
import subprocess
import sys

environment = os.environb.copy()
environment[b"CDM_CACHE_DIR"] = b"/tmp/cdm-policy-\xff"
result = subprocess.run(
    [
        os.fsencode(sys.argv[1]),
        b"--no-network",
        b"--",
        b"sh",
        b"-c",
        b'printf child-ran > "$1"',
        b"sh",
        os.fsencode(sys.argv[2]),
    ],
    env=environment,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.PIPE,
)
sys.stdout.buffer.write(result.stderr)
raise SystemExit(result.returncode)
PY
)
RC=$?
check_eq "non-UTF-8 policy path exits with usage status" "$RC" "2"
check "non-UTF-8 policy path fails closed" "$OUT" \
    "filesystem policy paths must be valid UTF-8"
check_eq "non-UTF-8 policy path never launches the child" \
    "$(test ! -e "$NON_UTF8_MARKER"; echo $?)" "0"

remove_test_path "$CONFIG_ROOT"
