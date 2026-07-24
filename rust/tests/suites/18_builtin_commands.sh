#!/bin/bash
# Every documented built-in must dispatch before the sandbox on the exact artifact.

section "Built-in command dispatch"

BUILTIN_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdm-builtins.XXXXXX")
mkdir -p "$BUILTIN_ROOT/home" "$BUILTIN_ROOT/policy" "$BUILTIN_ROOT/project"
chmod 700 "$BUILTIN_ROOT/home" "$BUILTIN_ROOT/policy"
BUILTIN_CONFIG="$BUILTIN_ROOT/policy/config.json"
EXPECTED_VERSION=$(awk -F '"' '/^version =/ {print $2; exit}' "$SCRIPT_DIR/../Cargo.toml")

assert_builtin() {
    local name=$1 expected_status=$2 expected_text=$3
    shift 3
    local output status
    output=$(HOME="$BUILTIN_ROOT/home" CDM_CONFIG_PATH="$BUILTIN_CONFIG" \
        "$CDM" "$@" </dev/null 2>&1)
    status=$?
    check_eq "$name: exits with the built-in status" "$status" "$expected_status"
    check "$name: returns built-in output" "$output" "$expected_text"
    check_not "$name: omits legacy sandbox dispatch" "$output" "[cdm] sandbox:"
    check_not "$name: omits current sandbox dispatch" "$output" "├─ Sandbox:"
}

assert_builtin "help" 0 "USAGE:" help
assert_builtin "implicit help" 0 "USAGE:"
assert_builtin "version" 0 "cdm $EXPECTED_VERSION" version

for shell in bash zsh fish; do
    assert_builtin "completions/$shell" 0 "setup" completions "$shell"
done

assert_builtin "setup without a terminal" 2 "requires an interactive terminal" setup

SETUP_BIN="$BUILTIN_ROOT/detected-bin"
mkdir -p "$SETUP_BIN"
for executable in pi codex copilot; do
    printf '#!/bin/sh\nexit 99\n' > "$SETUP_BIN/$executable"
    chmod 700 "$SETUP_BIN/$executable"
done
PYTHON_BIN=$(python3 -c 'import sys; print(sys.executable)')
SETUP_OUTPUT=$(HOME="$BUILTIN_ROOT/home" PATH="$SETUP_BIN" \
    "$PYTHON_BIN" "$SCRIPT_DIR/setup_pty.py" "$CDM" "1b5b421b5b42200d" 2>&1)
SETUP_STATUS=$?
check_eq "setup menu: exits successfully" "$SETUP_STATUS" "0"
for label in "Pi" "OpenAI Codex CLI" "GitHub Copilot CLI"; do
    check "setup menu: displays detected $label" "$SETUP_OUTPUT" "$label"
done
check "setup menu: reports selected profiles" "$SETUP_OUTPUT" "Enabled profiles: pi, codex"
check_not "setup menu: omits sandbox dispatch" "$SETUP_OUTPUT" "├─ Sandbox:"
check_eq "setup menu: materializes pi" \
    "$(test -f "$BUILTIN_ROOT/home/.cdm/profiles/bundled/pi.json"; echo $?)" "0"
check_eq "setup menu: materializes codex" \
    "$(test -f "$BUILTIN_ROOT/home/.cdm/profiles/bundled/codex.json"; echo $?)" "0"
check_eq "setup menu: leaves copilot unmaterialized" \
    "$(test ! -e "$BUILTIN_ROOT/home/.cdm/profiles/bundled/copilot.json"; echo $?)" "0"
BASE_IMPORTS=$("$PYTHON_BIN" - "$BUILTIN_ROOT/home/.cdm/base.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["import"])
PY
)
check_eq "setup menu: writes exact ordered base imports" "$BASE_IMPORTS" \
    "['bundled/pi.json', 'bundled/codex.json']"
check_eq "setup menu: does not create an opaque registry" \
    "$(test ! -e "$BUILTIN_ROOT/home/.cdm/setup-profiles.json"; echo $?)" "0"
BASE_BEFORE=$(cat "$BUILTIN_ROOT/home/.cdm/base.json")
PI_BEFORE=$(cat "$BUILTIN_ROOT/home/.cdm/profiles/bundled/pi.json")
CANCEL_OUTPUT=$(HOME="$BUILTIN_ROOT/home" PATH="$SETUP_BIN" \
    "$PYTHON_BIN" "$SCRIPT_DIR/setup_pty.py" "$CDM" "1b" 2>&1)
CANCEL_STATUS=$?
check_eq "setup cancellation: exits with usage status" "$CANCEL_STATUS" "2"
check "setup cancellation: reports no changes" "$CANCEL_OUTPUT" "cancelled; nothing changed"
check_eq "setup cancellation: preserves base bytes" \
    "$(cat "$BUILTIN_ROOT/home/.cdm/base.json")" "$BASE_BEFORE"
check_eq "setup cancellation: preserves profile bytes" \
    "$(cat "$BUILTIN_ROOT/home/.cdm/profiles/bundled/pi.json")" "$PI_BEFORE"
Q_CANCEL_OUTPUT=$(HOME="$BUILTIN_ROOT/home" PATH="$SETUP_BIN" \
    "$PYTHON_BIN" "$SCRIPT_DIR/setup_pty.py" "$CDM" "71" 2>&1)
Q_CANCEL_STATUS=$?
check_eq "setup q cancellation: exits with usage status" "$Q_CANCEL_STATUS" "2"
check "setup q cancellation: reports no changes" "$Q_CANCEL_OUTPUT" "cancelled; nothing changed"
check_eq "setup q cancellation: preserves base bytes" \
    "$(cat "$BUILTIN_ROOT/home/.cdm/base.json")" "$BASE_BEFORE"
check_eq "setup q cancellation: preserves profile bytes" \
    "$(cat "$BUILTIN_ROOT/home/.cdm/profiles/bundled/pi.json")" "$PI_BEFORE"

CONFIG_OUTPUT=$(HOME="$BUILTIN_ROOT/home" CDM_CONFIG_PATH="$BUILTIN_CONFIG" \
    "$CDM" config 2>&1)
CONFIG_STATUS=$?
check_eq "config: exits successfully" "$CONFIG_STATUS" "0"
check "config: reports the created policy" "$CONFIG_OUTPUT" "config written"
check_eq "config: creates the requested policy" \
    "$(test -f "$BUILTIN_CONFIG"; echo $?)" "0"
check_not "config: omits legacy sandbox dispatch" "$CONFIG_OUTPUT" "[cdm] sandbox:"
check_not "config: omits current sandbox dispatch" "$CONFIG_OUTPUT" "├─ Sandbox:"

PROJECT_OUTPUT=$(cd "$BUILTIN_ROOT/project" && \
    HOME="$BUILTIN_ROOT/home" CDM_CONFIG_PATH="$BUILTIN_CONFIG" \
    "$CDM" project 2>&1)
PROJECT_STATUS=$?
check_eq "project: exits successfully" "$PROJECT_STATUS" "0"
check "project: reports a root" "$PROJECT_OUTPUT" "root:"
check_not "project: omits legacy sandbox dispatch" "$PROJECT_OUTPUT" "[cdm] sandbox:"
check_not "project: omits current sandbox dispatch" "$PROJECT_OUTPUT" "├─ Sandbox:"

TRUST_OUTPUT=$(cd "$BUILTIN_ROOT/project" && \
    HOME="$BUILTIN_ROOT/home" CDM_CONFIG_PATH="$BUILTIN_CONFIG" \
    "$CDM" trust 2>&1)
TRUST_STATUS=$?
check_eq "trust without project policy: exits with usage status" "$TRUST_STATUS" "2"
check "trust without project policy: explains the refusal" "$TRUST_OUTPUT" \
    "cannot trust project config"
check_not "trust: omits legacy sandbox dispatch" "$TRUST_OUTPUT" "[cdm] sandbox:"
check_not "trust: omits current sandbox dispatch" "$TRUST_OUTPUT" "├─ Sandbox:"

remove_test_path "$BUILTIN_ROOT"
