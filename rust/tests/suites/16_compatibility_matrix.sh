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
    for harness in claude codex copilot pi; do
        if ! command -v "$harness" >/dev/null 2>&1; then
            skip "$harness offline version probe" "$harness is not installed"
            continue
        fi
        OUT=$(cd "$FIXTURE" && run_with_timeout 15 "$CDM" --no-network \
            "$harness" --version < /dev/null 2>&1)
        RC=$?
        check_eq "$harness offline version probe exits successfully" "$RC" "0"
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
            OUT=$(cd "$FIXTURE" && HOME="$APP_HOME" run_with_timeout 20 "$CDM" \
                --no-network --ro -- "$BUNDLE" --version < /dev/null 2>&1)
            RC=$?
            check_eq "$bundle_id app version probe exits successfully" "$RC" "0"
            check "$bundle_id app probe reports the resolved bundle identity" \
                "$OUT" "Application:       \"$bundle_id\""
            check "$bundle_id app probe reports each inferred state grant" \
                "$OUT" "(bundle convention)"
            check "$bundle_id app probe reports app grant provenance" \
                "$OUT" "[app]"
            check_not "$bundle_id app probe abbreviates inferred home paths" \
                "$OUT" "$APP_HOME"
            remove_test_path "$APP_HOME"
            IFS=','
        done
        IFS="$OLD_IFS"
    fi
fi
