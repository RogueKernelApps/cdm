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
    chmod 700 "$TEST_HOME/.cdm"
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
    TRUST_STATUS=$?
    case "$(uname -s)" in
        Darwin) TRUST_MODE=$(stat -f '%Lp' "$TEST_HOME/.cdm/trusted-projects.json" 2>/dev/null) ;;
        *) TRUST_MODE=$(stat -c '%a' "$TEST_HOME/.cdm/trusted-projects.json" 2>/dev/null) ;;
    esac
    if [ "$TRUST_STATUS" -eq 0 ] && grep -Fq 'sha256:' <<<"$TRUST_OUTPUT" && \
        [ "$TRUST_MODE" = 600 ]; then
        printf "  ${GREEN}PASS${NC} config: cdm trust records an exact private trust receipt\n"; PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} config: cdm trust failed or trust store is not mode 0600\n"; FAIL=$((FAIL + 1))
    fi

    LAYER_STATUS=$(cd "$PROJECT" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$GLOBAL_CONFIG" \
        "$CDM" --no-proxy true 2>&1)
    check "config: startup identifies global grant provenance" "$LAYER_STATUS" "[global]"
    check "config: startup identifies trusted project grant provenance" "$LAYER_STATUS" "[project]"

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

# Test: setup-selected profiles load automatically and remain independent from
# same-named user presets and explicit --profile selections.
if has_native; then
    PYTHON_BIN=$(python3 -c 'import sys; print(sys.executable)')
    SETUP_PROFILE_HOME=$(mktemp -d "$TEST_TMP/cdm_profile_setup_test.XXXXXX")
    SETUP_BIN="$SETUP_PROFILE_HOME/detected-bin"
    mkdir -p "$SETUP_BIN"
    for executable in pi codex; do
        printf '#!/bin/sh\nexit 99\n' > "$SETUP_BIN/$executable"
        chmod 700 "$SETUP_BIN/$executable"
    done
    SETUP_OUTPUT=$(HOME="$SETUP_PROFILE_HOME" PATH="$SETUP_BIN" \
        "$PYTHON_BIN" "$SCRIPT_DIR/setup_pty.py" "$CDM" "0d" 2>&1)
    SETUP_STATUS=$?
    SETUP_IMPORTS=$("$PYTHON_BIN" - "$SETUP_PROFILE_HOME/.cdm/base.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["import"])
PY
)
    if [ "$SETUP_STATUS" -eq 0 ] && grep -Fq 'Enabled profiles: pi, codex' <<<"$SETUP_OUTPUT" && \
        [ -f "$SETUP_PROFILE_HOME/.cdm/profiles/bundled/pi.json" ] && \
        [ -f "$SETUP_PROFILE_HOME/.cdm/profiles/bundled/codex.json" ] && \
        [ ! -e "$SETUP_PROFILE_HOME/.cdm/profiles/bundled/claude.json" ] && \
        [ "$SETUP_IMPORTS" = "['bundled/pi.json', 'bundled/codex.json']" ]; then
        printf "  ${GREEN}PASS${NC} config: setup materializes and imports only selected profiles\n"; PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} config: setup selection did not produce exact profile state\n"; FAIL=$((FAIL + 1))
    fi
    mkdir -p "$SETUP_PROFILE_HOME/.pi/agent" "$SETUP_PROFILE_HOME/.codex"
    AUTO_OUTPUT=$(cd "$SETUP_PROFILE_HOME" && env -u CDM_CONFIG_PATH \
        HOME="$SETUP_PROFILE_HOME" "$CDM" --no-proxy true 2>&1)
    AUTO_STATUS=$?
    if [ "$AUTO_STATUS" -eq 0 ] && grep -Fq '[profile:pi]' <<<"$AUTO_OUTPUT" && \
        grep -Fq '[profile:codex]' <<<"$AUTO_OUTPUT"; then
        printf "  ${GREEN}PASS${NC} config: managed base applies selected profiles without CLI flags\n"; PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} config: managed base did not apply selected profiles automatically\n"; FAIL=$((FAIL + 1))
    fi
    printf 'user global bytes\n' > "$SETUP_PROFILE_HOME/.cdm/config.json"
    printf 'personal bytes\n' > "$SETUP_PROFILE_HOME/.cdm/profiles/personal.json"
    printf 'unknown bytes\n' > "$SETUP_PROFILE_HOME/.cdm/profiles/bundled/unknown.json"
    printf 'modified managed bytes\n' > "$SETUP_PROFILE_HOME/.cdm/profiles/bundled/pi.json"
    remove_test_path "$SETUP_BIN/pi"
    remove_test_path "$SETUP_BIN/codex"
    printf '#!/bin/sh\nexit 99\n' > "$SETUP_BIN/claude"
    chmod 700 "$SETUP_BIN/claude"
    HOME="$SETUP_PROFILE_HOME" PATH="$SETUP_BIN" \
        "$PYTHON_BIN" "$SCRIPT_DIR/setup_pty.py" "$CDM" "201b5b421b5b42200d" >/dev/null
    if [ "$(cat "$SETUP_PROFILE_HOME/.cdm/config.json")" = "user global bytes" ] && \
        [ "$(cat "$SETUP_PROFILE_HOME/.cdm/profiles/personal.json")" = "personal bytes" ] && \
        [ "$(cat "$SETUP_PROFILE_HOME/.cdm/profiles/bundled/unknown.json")" = "unknown bytes" ] && \
        [ -f "$SETUP_PROFILE_HOME/.cdm/profiles/bundled/claude.json" ] && \
        [ ! -e "$SETUP_PROFILE_HOME/.cdm/profiles/bundled/pi.json" ] && \
        [ ! -e "$SETUP_PROFILE_HOME/.cdm/profiles/bundled/codex.json" ]; then
        printf "  ${GREEN}PASS${NC} config: setup rerun removes deselected known files and preserves user files\n"; PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} config: setup rerun damaged or retained the wrong profile state\n"; FAIL=$((FAIL + 1))
    fi
    remove_test_path "$SETUP_PROFILE_HOME"

    PROFILE_ROOT=$(mktemp -d "$TEST_TMP/cdm_profile_test.XXXXXX")
    PROFILE_HOME="$PROFILE_ROOT/home"
    PROFILE_PROJECT="$PROFILE_ROOT/project"
    PROFILE_PRESET_STATE="$PROFILE_ROOT/preset-state"
    PROFILE_PERSONAL_STATE="$PROFILE_ROOT/personal-state"
    PROFILE_WORK_STATE="$PROFILE_ROOT/work-state"
    mkdir -p "$PROFILE_HOME/.cdm" "$PROFILE_HOME/.pi/agent/sessions" \
        "$PROFILE_PROJECT" "$PROFILE_PRESET_STATE" "$PROFILE_PERSONAL_STATE" "$PROFILE_WORK_STATE"
    chmod 700 "$PROFILE_HOME/.cdm"
    PROFILE_SETUP_BIN="$PROFILE_ROOT/detected-bin"
    mkdir -p "$PROFILE_SETUP_BIN"
    for executable in pi codex; do
        printf '#!/bin/sh\nexit 99\n' > "$PROFILE_SETUP_BIN/$executable"
        chmod 700 "$PROFILE_SETUP_BIN/$executable"
    done
    HOME="$PROFILE_HOME" PATH="$PROFILE_SETUP_BIN" \
        "$PYTHON_BIN" "$SCRIPT_DIR/setup_pty.py" "$CDM" "0d" >/dev/null
    printf 'profile instructions\n' > "$PROFILE_HOME/.pi/agent/AGENTS.md"
    printf '{"import":["bundled/codex.json"],"paths":{"allow_rw":["%s"]}}\n' "$PROFILE_PERSONAL_STATE" \
        > "$PROFILE_HOME/.cdm/profiles/personal.json"
    printf '{"import":["personal.json"],"paths":{"allow_rw":["%s"]}}\n' \
        "$PROFILE_WORK_STATE" > "$PROFILE_HOME/.cdm/profiles/work.json"
    printf '{"import":["work.json"],"paths":{"allow_rw":[".cdm/profiles"]},"presets":{"pi":{"paths":{"allow_rw":["%s"]}}}}\n' \
        "$PROFILE_PRESET_STATE" > "$PROFILE_HOME/.cdm/config.json"
    CONFIG_BEFORE=$(cat "$PROFILE_HOME/.cdm/config.json")

    PROFILE_OUTPUT=$(cd "$PROFILE_PROJECT" && HOME="$PROFILE_HOME" \
        CDM_CONFIG_PATH="$PROFILE_HOME/.cdm/config.json" \
        "$CDM" --profile pi --preset pi --no-proxy sh -c \
        "touch '$PROFILE_HOME/.pi/agent/sessions/from-profile' '$PROFILE_PRESET_STATE/from-preset' '$PROFILE_PERSONAL_STATE/from-personal' '$PROFILE_WORK_STATE/from-work'" \
        2>&1)
    PROFILE_RC=$?
    if [ "$PROFILE_RC" -eq 0 ] && \
        [ -f "$PROFILE_HOME/.pi/agent/sessions/from-profile" ] && \
        [ -f "$PROFILE_PRESET_STATE/from-preset" ] && \
        [ -f "$PROFILE_PERSONAL_STATE/from-personal" ] && \
        [ -f "$PROFILE_WORK_STATE/from-work" ] && \
        grep -Fq '[profile:pi]' <<<"$PROFILE_OUTPUT"; then
        printf "  ${GREEN}PASS${NC} config: explicit profile and same-named preset apply independently\n"; PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} config: explicit profile and same-named preset did not both apply\n"; FAIL=$((FAIL + 1))
    fi
    check_eq "config: profile invocation does not rewrite global config" \
        "$(cat "$PROFILE_HOME/.cdm/config.json")" "$CONFIG_BEFORE"

    if (cd "$PROFILE_PROJECT" && HOME="$PROFILE_HOME" \
        CDM_CONFIG_PATH="$PROFILE_HOME/.cdm/config.json" \
        "$CDM" --no-proxy sh -c \
        "printf tampered > '$PROFILE_HOME/.cdm/profiles/personal.json'") >/dev/null 2>&1; then
        printf "  ${RED}FAIL${NC} config: loaded imported policy was writable through a broad grant\n"; FAIL=$((FAIL + 1))
    else
        printf "  ${GREEN}PASS${NC} config: loaded imported policy overrides a broad writable grant\n"; PASS=$((PASS + 1))
    fi

    if (cd "$PROFILE_PROJECT" && HOME="$PROFILE_HOME" \
        CDM_CONFIG_PATH="$PROFILE_HOME/.cdm/config.json" \
        "$CDM" --no-proxy sh -c \
        "touch '$PROFILE_HOME/.pi/agent/sessions/setup-profile'") >/dev/null 2>&1; then
        printf "  ${GREEN}PASS${NC} config: setup-selected profile applies without --profile\n"; PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} config: setup-selected profile was not applied automatically\n"; FAIL=$((FAIL + 1))
    fi

    if (cd "$PROFILE_PROJECT" && HOME="$PROFILE_HOME" \
        CDM_CONFIG_PATH="$PROFILE_HOME/.cdm/config.json" \
        "$CDM" --profile pi --no-proxy sh -c \
        "printf tampered > '$PROFILE_HOME/.pi/agent/AGENTS.md'") >/dev/null 2>&1; then
        printf "  ${RED}FAIL${NC} config: profile read-only customization was writable\n"; FAIL=$((FAIL + 1))
    else
        check_eq "config: profile customization stays read-only" \
            "$(cat "$PROFILE_HOME/.pi/agent/AGENTS.md")" "profile instructions"
    fi
    remove_test_path "$PROFILE_ROOT"
else
    skip "config: explicit built-in profiles" "native sandbox unavailable"
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
