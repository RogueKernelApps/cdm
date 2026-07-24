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

assert_builtin "setup" 0 "Bundled profiles refreshed:" setup
for profile in pi claude codex copilot; do
    check_eq "setup: materializes $profile" \
        "$(test -f "$BUILTIN_ROOT/home/.cdm/profiles/bundled/$profile.json"; echo $?)" "0"
done

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
