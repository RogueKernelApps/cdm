#!/bin/bash
# CDM Integration Tests: Config file (~/.cdm/config.json)
# Runs across all sandbox modes where applicable
# Helpers inherited from integration.sh runner

section "Config File (cross-mode)"
TEST_TMP="${TMPDIR:-/tmp}"

# Test: default behavior — all modes work without a config file
cross_check 'echo $CDM' "1" "defaults work without config"

# Test: cdm config creates the requested config file
HELP_OUTPUT=$("$CDM" help 2>&1)
if echo "$HELP_OUTPUT" | grep -q "config"; then
    CDM_CONFIG_TEST=$(mktemp -d "$TEST_TMP/cdm_config_test.XXXXXX")
    CDM_CONFIG_FILE="$CDM_CONFIG_TEST/config.json"
    if ! CDM_CONFIG_PATH="$CDM_CONFIG_FILE" "$CDM" config 2>/dev/null; then
        printf "  ${RED}FAIL${NC} config: cdm config command succeeds\n"; FAIL=$((FAIL + 1))
    fi
    if [ -f "$CDM_CONFIG_FILE" ]; then
        printf "  ${GREEN}PASS${NC} config: cdm config creates config.json\n"; PASS=$((PASS + 1))
        if python3 -c "import json; json.load(open('$CDM_CONFIG_FILE'))" 2>/dev/null; then
            printf "  ${GREEN}PASS${NC} config: generated config is valid JSON\n"; PASS=$((PASS + 1))
        else
            printf "  ${RED}FAIL${NC} config: generated config is valid JSON\n"; FAIL=$((FAIL + 1))
        fi
        HAS_KEYS=$(python3 -c "
import json
c = json.load(open('$CDM_CONFIG_FILE'))
for k in ['env', 'paths', 'secrets', 'guard', 'proxy', 'vm']:
    assert k in c, f'missing key: {k}'
print('ok')
" 2>/dev/null)
        check "config: has all expected sections" "$HAS_KEYS" "ok"
    else
        printf "  ${RED}FAIL${NC} config: cdm config creates config.json\n"; FAIL=$((FAIL + 1))
    fi
    remove_test_path "$CDM_CONFIG_TEST"
else
    skip "config: cdm config" "config subcommand not available"
fi

# Test: config creation is non-destructive
CDM_CONFIG_TEST=$(mktemp -d "$TEST_TMP/cdm_config_existing.XXXXXX")
CDM_CONFIG_FILE="$CDM_CONFIG_TEST/config.json"
echo '{"sentinel":true}' > "$CDM_CONFIG_FILE"
if CDM_CONFIG_PATH="$CDM_CONFIG_FILE" "$CDM" config >/dev/null 2>&1; then
    printf "  ${RED}FAIL${NC} config: existing config is not overwritten\n"; FAIL=$((FAIL + 1))
else
    check_eq "config: existing config is not overwritten" "$(cat "$CDM_CONFIG_FILE")" '{"sentinel":true}'
fi
remove_test_path "$CDM_CONFIG_TEST"

# Test: nearest project config layers grants over the global config, and each
# relative path is anchored to the file that declared it.
if has_native; then
    LAYER_ROOT=$(mktemp -d "$TEST_TMP/cdm_config_layers.XXXXXX")
    TEST_HOME="$LAYER_ROOT/home"
    PROJECT="$LAYER_ROOT/project"
    GLOBAL_STATE="$LAYER_ROOT/global-state"
    PROJECT_STATE="$LAYER_ROOT/project-state"
    mkdir -p "$TEST_HOME/.cdm" "$PROJECT/.cdm" "$GLOBAL_STATE" "$PROJECT_STATE"
    GLOBAL_CONFIG="$TEST_HOME/.cdm/config.json"
    printf '{"paths":{"allow_rw":["%s","%s"]},"presets":{"first":{"guard":{"blocked_commands":[{"prefix":"echo first","reason":"first preset"}]}},"second":{"guard":{"blocked_commands":[{"prefix":"echo second","reason":"second preset"}]}}}}\n' \
        "$GLOBAL_STATE" "$TEST_HOME/.cdm" > "$GLOBAL_CONFIG"
    printf '{"paths":{"allow_rw":["../project-state"]}}\n' > "$PROJECT/.cdm/config.json"

    UNTRUSTED=$(cd "$PROJECT" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$GLOBAL_CONFIG" \
        "$CDM" --no-proxy true 2>&1)
    if [ "$?" -eq 2 ] && echo "$UNTRUSTED" | grep -Fq 'cdm trust'; then
        printf "  ${GREEN}PASS${NC} config: project config is rejected before explicit trust\n"; PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} config: untrusted project config was not rejected\n"; FAIL=$((FAIL + 1))
    fi

    TRUST_OUTPUT=$(cd "$PROJECT" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$GLOBAL_CONFIG" "$CDM" trust 2>&1)
    if [ "$?" -eq 0 ] && echo "$TRUST_OUTPUT" | grep -Fq 'sha256:' && \
        [ "$(stat -f '%Lp' "$TEST_HOME/.cdm/trusted-projects.json" 2>/dev/null || stat -c '%a' "$TEST_HOME/.cdm/trusted-projects.json")" = 600 ]; then
        printf "  ${GREEN}PASS${NC} config: cdm trust records an exact private trust receipt\n"; PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} config: cdm trust failed or trust store is not mode 0600\n"; FAIL=$((FAIL + 1))
    fi

    if (cd "$PROJECT" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$GLOBAL_CONFIG" \
        "$CDM" --preset first --preset second --no-proxy sh -c \
        "touch '$GLOBAL_STATE/from-global' '$PROJECT_STATE/from-project'") >/dev/null 2>&1; then
        if [ -f "$GLOBAL_STATE/from-global" ] && [ -f "$PROJECT_STATE/from-project" ]; then
            printf "  ${GREEN}PASS${NC} config: global and project grants merge with source-relative paths\n"; PASS=$((PASS + 1))
        else
            printf "  ${RED}FAIL${NC} config: layered grants did not create expected files\n"; FAIL=$((FAIL + 1))
        fi
    else
        printf "  ${RED}FAIL${NC} config: layered project config invocation failed\n"; FAIL=$((FAIL + 1))
    fi

    PRESET_ERROR=$(cd "$PROJECT" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$GLOBAL_CONFIG" \
        "$CDM" --preset first --preset second echo second 2>&1)
    if [ "$?" -ne 0 ] && echo "$PRESET_ERROR" | grep -Fq 'second preset'; then
        printf "  ${GREEN}PASS${NC} config: repeatable presets apply left-to-right\n"; PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} config: preset precedence is not left-to-right\n"; FAIL=$((FAIL + 1))
    fi

    printf '\n' >> "$PROJECT/.cdm/config.json"
    CHANGED=$(cd "$PROJECT" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$GLOBAL_CONFIG" \
        "$CDM" --no-proxy true 2>&1)
    if [ "$?" -eq 2 ] && echo "$CHANGED" | grep -Fq 'has changed'; then
        printf "  ${GREEN}PASS${NC} config: byte edits invalidate project trust\n"; PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} config: edited project config retained trust\n"; FAIL=$((FAIL + 1))
    fi

    # Re-trust, then prove neither an explicit broad grant nor workspace RW can
    # mutate or replace policy inputs. Denying parent directories prevents a
    # rename/swap from bypassing the individual-file denial.
    (cd "$PROJECT" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$GLOBAL_CONFIG" "$CDM" trust) >/dev/null 2>&1
    for ATTEMPT in \
        "printf tampered > '$PROJECT/.cdm/config.json'" \
        "mv '$PROJECT/.cdm' '$PROJECT/.cdm-swapped'" \
        "printf tampered > '$GLOBAL_CONFIG'" \
        "printf tampered > '$TEST_HOME/.cdm/trusted-projects.json'" \
        "ln '$GLOBAL_CONFIG' '$PROJECT/global-hardlink'"; do
        if (cd "$PROJECT" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$GLOBAL_CONFIG" \
            "$CDM" --no-proxy sh -c "$ATTEMPT") >/dev/null 2>&1; then
            printf "  ${RED}FAIL${NC} config: protected policy mutation succeeded: %s\n" "$ATTEMPT"; FAIL=$((FAIL + 1))
        else
            printf "  ${GREEN}PASS${NC} config: protected policy mutation blocked: %s\n" "$ATTEMPT"; PASS=$((PASS + 1))
        fi
    done

    SYMLINK_PROJECT="$LAYER_ROOT/symlink-project"
    mkdir -p "$SYMLINK_PROJECT/.cdm"
    printf '{}\n' > "$SYMLINK_PROJECT/config-target.json"
    ln -s "$SYMLINK_PROJECT/config-target.json" "$SYMLINK_PROJECT/.cdm/config.json"
    if (cd "$SYMLINK_PROJECT" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$GLOBAL_CONFIG" \
        "$CDM" trust) >/dev/null 2>&1; then
        printf "  ${RED}FAIL${NC} config: symlinked project policy was trusted\n"; FAIL=$((FAIL + 1))
    else
        printf "  ${GREEN}PASS${NC} config: symlinked project policy is rejected\n"; PASS=$((PASS + 1))
    fi

    HARDLINK_PROJECT="$LAYER_ROOT/hardlink-project"
    mkdir -p "$HARDLINK_PROJECT/.cdm"
    printf '{}\n' > "$HARDLINK_PROJECT/config-target.json"
    ln "$HARDLINK_PROJECT/config-target.json" "$HARDLINK_PROJECT/.cdm/config.json"
    if (cd "$HARDLINK_PROJECT" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$GLOBAL_CONFIG" \
        "$CDM" trust) >/dev/null 2>&1; then
        printf "  ${RED}FAIL${NC} config: hard-linked project policy was trusted\n"; FAIL=$((FAIL + 1))
    else
        printf "  ${GREEN}PASS${NC} config: hard-linked project policy is rejected\n"; PASS=$((PASS + 1))
    fi
    remove_test_path "$LAYER_ROOT"
else
    skip "config: global and project grant layering" "native sandbox unavailable"
fi

# Test: custom config overrides VM defaults — both VM modes
VM_FLAGS=""
has_vm && VM_FLAGS="--vm"
[ "${CDM_OCI_TESTS:-0}" = "1" ] && VM_FLAGS="$VM_FLAGS|--vmi alpine:3.21"
OLD_IFS="$IFS"; IFS='|'
for vm_flag in $VM_FLAGS; do
    short=$(echo "$vm_flag" | sed 's/--//' | cut -d' ' -f1)
    CDM_CONFIG_DIR=$(mktemp -d "$TEST_TMP/cdm_vcpu_test.XXXXXX")
    CDM_CONFIG_FILE="$CDM_CONFIG_DIR/config.json"
    echo '{"vm":{"vcpus":4,"ram_mib":256}}' > "$CDM_CONFIG_FILE"
    STDERR=$(CDM_CONFIG_PATH="$CDM_CONFIG_FILE" CDM_DEBUG=1 \
        "$CDM" $vm_flag echo hello 2>&1 >/dev/null)
    RC=$?
    if grep -q "vcpus=4" <<<"$STDERR"; then
        printf "  ${GREEN}PASS${NC} config/$short: VM vcpus override\n"; PASS=$((PASS + 1))
    elif [ "$RC" -ne 0 ]; then
        printf "  ${RED}FAIL${NC} config/%s: VM config invocation failed (rc=%s)\n" "$short" "$RC"; FAIL=$((FAIL + 1))
    else
        printf "  ${RED}FAIL${NC} config/%s: VM debug output omitted vcpus\n" "$short"; FAIL=$((FAIL + 1))
    fi
    remove_test_path "$CDM_CONFIG_DIR"
done
IFS="$OLD_IFS"

# Test: custom command preflight — all modes. This is exact token/basename
# mistake prevention, not a child-execution security boundary.
for mode in $MODES; do
    CDM_CONFIG_DIR=$(mktemp -d "$TEST_TMP/cdm_guard_test.XXXXXX")
    CDM_CONFIG_FILE="$CDM_CONFIG_DIR/config.json"
    echo '{"guard":{"blocked_commands":[{"prefix":"echo blocked","reason":"test block"}]}}' > "$CDM_CONFIG_FILE"
    OUT=$(cd "$FIXTURE" && CDM_CONFIG_PATH="$CDM_CONFIG_FILE" mode_run "$mode" 'echo blocked')
    check_empty "config/$mode: custom preflight refuses configured token pattern" "$OUT"

    OUT=$(cd "$FIXTURE" && CDM_CONFIG_PATH="$CDM_CONFIG_FILE" mode_exec "$mode" echo blocked-more)
    check "config/$mode: preflight uses an exact argument-token boundary" "$OUT" "blocked-more"

    OUT=$(cd "$FIXTURE" && CDM_CONFIG_PATH="$CDM_CONFIG_FILE" mode_exec "$mode" sh -c 'echo blocked')
    check_empty "config/$mode: preflight checks a literal shell simple command" "$OUT"

    OUT=$(cd "$FIXTURE" && CDM_CONFIG_PATH="$CDM_CONFIG_FILE" mode_exec "$mode" sh -c 'echo pass; echo blocked')
    check "config/$mode: complex shell remains outside preflight boundary" "$OUT" "pass
blocked"
    remove_test_path "$CDM_CONFIG_DIR"
done

# Test: custom path grants — all modes
for mode in $MODES; do
    CDM_CONFIG_DIR=$(mktemp -d "$TEST_TMP/cdm_wr_test.XXXXXX")
    CDM_CONFIG_FILE="$CDM_CONFIG_DIR/config.json"
    echo '{"paths":{"allow_rw":[]}}' > "$CDM_CONFIG_FILE"
    OUT=$(cd "$FIXTURE" && CDM_CONFIG_PATH="$CDM_CONFIG_FILE" mode_run "$mode" 'echo $CDM')
    check "config/$mode: custom path grants" "$OUT" "1"
    remove_test_path "$CDM_CONFIG_DIR"
done
