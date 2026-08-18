#!/bin/bash
# Credential-free compatibility probes for locally installed real tools/apps.

if [ "${CDM_COMPAT_TESTS:-0}" != "1" ]; then
    skip "real compatibility matrix" "set CDM_COMPAT_TESTS=1 to run it"
    return 0 2>/dev/null || exit 0
fi

section "Credential-free coding harness matrix"

if ! has_native; then
    skip "coding harness matrix" "native sandbox adapter is unavailable"
elif ! command -v python3 >/dev/null 2>&1; then
    skip "coding harness matrix" "python3 timeout helper is unavailable"
else
    mkdir -p "$HOME/.agents" "$HOME/.claude" "$HOME/.codex" "$HOME/.copilot" \
        "$HOME/.pi" "$HOME/.cache/copilot" "$HOME/Library/Caches/copilot"
    python3 "$SCRIPT_DIR/setup_pty.py" "$CDM" "0d" >/dev/null 2>&1
    SETUP_RC=$?
    check_eq "compatibility matrix materializes detected profiles through setup" "$SETUP_RC" "0"
    for harness in claude codex copilot pi; do
        if ! command -v "$harness" >/dev/null 2>&1; then
            skip "$harness offline version probe" "$harness is not installed"
            continue
        fi
        HOST_HOME=$(mktemp -d "${TMPDIR:-/tmp}/cdm-harness-host-smoke.XXXXXX")
        HOST_OUT=$(cd "$FIXTURE" && HOME="$HOST_HOME" run_with_timeout 15 \
            "$harness" --version < /dev/null 2>&1)
        HOST_RC=$?
        remove_test_path "$HOST_HOME"
        check_nonempty "$harness host version probe returns a version" "$HOST_OUT"
        OUT=$(cd "$FIXTURE" && run_with_timeout 15 "$CDM" --no-network \
            "$harness" --version < /dev/null 2>&1)
        RC=$?
        check_eq "$harness offline version probe preserves host exit status" "$RC" "$HOST_RC"
        check_nonempty "$harness offline version probe returns a version" "$OUT"
    done
fi

# Desktop apps are opt-in by bundle identifier, not by user-specific paths.
# Each app receives a fresh empty HOME and no network, so the probe cannot use
# credentials or mutate the operator's real application state.
if [ -n "${CDM_APP_SMOKE_BUNDLE_IDS:-}" ]; then
    section "Credential-free desktop app matrix"
    if [ "$(uname -s)" != "Darwin" ] || ! has_native; then
        skip "desktop app matrix" "native macOS Seatbelt is unavailable"
    elif ! command -v mdfind >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
        skip "desktop app matrix" "Spotlight or Python timeout helper is unavailable"
    else
        OLD_IFS="$IFS"; IFS=','
        for bundle_id in $CDM_APP_SMOKE_BUNDLE_IDS; do
            IFS="$OLD_IFS"
            if ! echo "$bundle_id" | grep -Eq '^[A-Za-z0-9._-]+$'; then
                printf "  ${RED}FAIL${NC} invalid app bundle identifier: %s\n" "$bundle_id"
                FAIL=$((FAIL + 1))
                IFS=','
                continue
            fi
            BUNDLE=$(mdfind "kMDItemCFBundleIdentifier == '$bundle_id'" | \
                grep -E '\.app$' | head -1)
            if [ -z "$BUNDLE" ]; then
                skip "$bundle_id app version probe" "bundle is not installed or indexed"
                IFS=','
                continue
            fi
            APP_HOME=$(mktemp -d "${TMPDIR:-/tmp}/cdm-app-smoke.XXXXXX")
            mkdir -p "$APP_HOME/.copilot" \
                "$APP_HOME/Library/Application Support" \
                "$APP_HOME/Library/Caches" \
                "$APP_HOME/Library/Containers" \
                "$APP_HOME/Library/Preferences" \
                "$APP_HOME/Library/WebKit"
            OUT=$(cd "$FIXTURE" && HOME="$APP_HOME" run_with_timeout 8 "$CDM" \
                --no-network --ro -- "$BUNDLE" --version < /dev/null 2>&1)
            RC=$?
            if [ "$RC" -eq 0 ]; then
                printf "  ${GREEN}PASS${NC} %s app version probe exits successfully\n" "$bundle_id"
                PASS=$((PASS + 1))
            elif [ "$RC" -eq 124 ]; then
                printf "  ${GREEN}PASS${NC} %s GUI app remains live until bounded shutdown\n" "$bundle_id"
                PASS=$((PASS + 1))
            else
                printf "  ${RED}FAIL${NC} %s app launch probe exits with %s\n" "$bundle_id" "$RC"
                FAIL=$((FAIL + 1))
            fi
            STATUS_OUT=${OUT%%$'\n\n'*}
            check "$bundle_id app probe reports the resolved bundle identity" \
                "$STATUS_OUT" "Application:       \"$bundle_id\""
            check "$bundle_id app probe reports each inferred state grant" \
                "$STATUS_OUT" "(bundle convention)"
            check "$bundle_id app probe reports app grant provenance" \
                "$STATUS_OUT" "[app]"
            check_not "$bundle_id app probe abbreviates inferred home paths" \
                "$STATUS_OUT" "$APP_HOME"
            remove_test_path "$APP_HOME"
            IFS=','
        done
        IFS="$OLD_IFS"
    fi
fi
