#!/bin/bash
# Authenticated/networked coding-harness compatibility.
# Helpers inherited from integration.sh runner.

section "Node runtime compatibility"

# These checks are local and credential-free, so they run in the default
# matrix rather than being hidden behind the authenticated-test switch.
if [ -n "$MODES" ]; then
    CUSTOM_FLAG="--max-old-space-size=4096"
    for mode in $MODES; do
        OUT=$(cd "$FIXTURE" && export NODE_OPTIONS="$CUSTOM_FLAG" && \
            mode_exec "$mode" --no-network -- sh -c 'printf "%s" "$NODE_OPTIONS"' \
            2>/dev/null)
        RC=$?
        check_eq "$mode: NODE_OPTIONS sandbox command succeeds" "$RC" "0"
        check_eq "$mode: --no-network preserves NODE_OPTIONS exactly" "$OUT" "$CUSTOM_FLAG"
        check_not "$mode: --no-network does not invent CA options" "$OUT" "--use-system-ca"

        OUT=$(cd "$FIXTURE" && unset NODE_OPTIONS && \
            mode_exec "$mode" --no-network -- sh -c \
            'printf "%s" "$NODE_OPTIONS"' 2>/dev/null)
        RC=$?
        check_eq "$mode: unset NODE_OPTIONS input still succeeds" "$RC" "0"
        check_empty "$mode: --no-network leaves unset NODE_OPTIONS unset" "$OUT"

        if mode_supports_proxy "$mode"; then
            OUT=$(cd "$FIXTURE" && export NODE_OPTIONS="$CUSTOM_FLAG" && \
                mode_exec "$mode" --scramble -- sh -c 'printf "%s" "$NODE_OPTIONS"' \
                2>/dev/null)
            RC=$?
            check_eq "$mode: proxied NODE_OPTIONS command succeeds" "$RC" "0"
            check "$mode: proxied NODE_OPTIONS preserves existing flags" "$OUT" "$CUSTOM_FLAG"
            check "$mode: proxied NODE_OPTIONS appends --use-system-ca" "$OUT" "--use-system-ca"
        fi
    done
else
    skip "NODE_OPTIONS runtime compatibility" "no runnable sandbox adapter is available"
fi

if [ "${CDM_AI_TESTS:-0}" != "1" ]; then
    skip "authenticated AI harness tests" "set CDM_AI_TESTS=1 to run them"
    return 0 2>/dev/null || exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    skip "authenticated AI harness tests" "python3 timeout helper is unavailable"
    return 0 2>/dev/null || exit 0
fi
if ! has_native; then
    skip "authenticated AI harness tests" "native sandbox adapter is unavailable"
    return 0 2>/dev/null || exit 0
fi
if ! mode_supports_proxy native; then
    skip "authenticated AI harness tests" "strict proxy transport is unavailable"
    return 0 2>/dev/null || exit 0
fi

authenticated_prompt() {
    local name="$1" executable="$2"; shift 2
    if ! command -v "$executable" >/dev/null 2>&1; then
        skip "$name through proxy" "$executable is not installed"
        return
    fi

    local output status
    output=$(cd "$FIXTURE" && run_with_timeout 60 "$CDM" --scramble "$executable" "$@" \
        < /dev/null 2>&1)
    status=$?
    if [ "$status" -ne 0 ]; then
        printf "  ${RED}FAIL${NC} %s through proxy (rc=%s)\n" "$name" "$status"
        echo "    $(echo "$output" | head -3)"
        FAIL=$((FAIL + 1))
    elif echo "$output" | grep -Fiq "pong"; then
        printf "  ${GREEN}PASS${NC} %s through proxy\n" "$name"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} %s through proxy returned no pong\n" "$name"
        echo "    $(echo "$output" | head -3)"
        FAIL=$((FAIL + 1))
    fi
}

section "Authenticated AI harness compatibility"

authenticated_prompt "Claude Code" claude -p "Respond with just the word pong"
authenticated_prompt "GitHub Copilot CLI" copilot -p "Respond with just the word pong"

section "Node.js HTTPS through proxy"

if ! command -v node >/dev/null 2>&1; then
    skip "node fetch HTTPS through proxy" "node is not installed"
else
    NODE_PROBE="fetch('https://httpbin.org/get').then(r=>r.json()).then(d=>console.log(d.url))"
    HOST_OUT=$(run_with_timeout 15 node -e "$NODE_PROBE" 2>/dev/null)
    HOST_RC=$?
    if [ "$HOST_RC" -ne 0 ]; then
        skip "node fetch HTTPS through proxy" "external endpoint is unavailable outside CDM"
    else
        OUT=$(cd "$FIXTURE" && run_with_timeout 15 "$CDM" --scramble node -e "$NODE_PROBE" 2>&1)
        RC=$?
        check_eq "node fetch HTTPS through proxy exits successfully" "$RC" "0"
        check "node fetch HTTPS through proxy" "$OUT" "https://httpbin.org/get"
    fi
fi
