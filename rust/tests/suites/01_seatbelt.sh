#!/bin/bash
# CDM Integration Tests: Seatbelt-specific behaviors
# Most basic assertions are in 07_cross_mode.sh (which tests all modes).
# This suite covers seatbelt-unique behaviors.
# Helpers inherited from integration.sh runner

section "Seatbelt Specific"

if [ "$(native_adapter)" != "seatbelt" ] || ! has_native; then
    skip "Seatbelt-specific tests" "the macOS Seatbelt adapter is unavailable"
    return 0 2>/dev/null || exit 0
fi

# Exit code propagation
run_cdm bash -c 'exit 0' >/dev/null 2>&1; RC=$?
if [ "$RC" = "0" ]; then
    printf "  ${GREEN}PASS${NC} native/Seatbelt: exit 0 propagates\n"; PASS=$((PASS + 1))
else
    printf "  ${RED}FAIL${NC} native/Seatbelt: exit 0 propagates (got $RC)\n"; FAIL=$((FAIL + 1))
fi

# Seatbelt can read files in workdir
OUT=$(run_cdm bash -c 'wc -l < README.md')
check_nonempty "native/Seatbelt: can read workdir files" "$OUT"

# Verify proxy env vars point to valid CA files
OUT=$(run_cdm --scramble bash -c 'test -s "$NODE_EXTRA_CA_CERTS" && echo ok')
check "native/Seatbelt: CA cert file is non-empty" "$OUT" "ok"

OUT=$(run_cdm --scramble bash -c 'test -s "$SSL_CERT_FILE" && echo ok')
check "native/Seatbelt: CA bundle file is non-empty" "$OUT" "ok"
