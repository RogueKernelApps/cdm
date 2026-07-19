#!/bin/bash
# CDM Integration Tests: Cross-mode comparison
#
# Runs the same assertions across native, --vm, and --vmi to ensure
# consistent behavior regardless of sandbox mode.
# Helpers inherited from integration.sh runner

section "Cross-Mode: Basic Execution"

cross_check "echo hello" "hello" "echo hello"
cross_check "pwd" "$FIXTURE" "pwd returns fixture dir"

section "Cross-Mode: Developer-Friendly Secret Defaults"

cross_check 'grep ^API_KEY= .env' "$REAL_SECRET" ".env is readable by default"
cross_check 'echo ${API_KEY:-unset}' "unset" ".env is not implicitly sourced"

section "Cross-Mode: Explicit Secret Scrambling"

for mode in $MODES; do
    OUT=$(mode_exec "$mode" --scramble --no-network sh -c 'printf "%s" "$API_KEY"')
    check_nonempty "$mode: --scramble injects API_KEY" "$OUT"
    check_not "$mode: --scramble does not expose API_KEY" "$OUT" "sk-test-a1b2c3d4"
    check_empty "$mode: --scramble hides .env" \
        "$(mode_exec "$mode" --scramble --no-network sh -c 'cat .env 2>/dev/null')"
done

section "Cross-Mode: Non-Secret Passthrough"

cross_check 'grep ^APP_NAME= .env' "APP_NAME=my-test-app" "non-secret .env content is readable"

section "Cross-Mode: CDM Markers"

cross_check 'echo $CDM' "1" "CDM marker set"

section "Cross-Mode: File Access"

cross_check 'ls README.md' "README.md" "workdir files visible"
cross_check 'test -r .env && echo readable' "readable" ".env remains readable"

section "Cross-Mode: Multi-Command"

cross_check 'pwd && ls README.md && echo DONE' "DONE" "multi-command works"
