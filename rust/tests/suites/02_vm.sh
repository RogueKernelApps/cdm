#!/bin/bash
# CDM Integration Tests: real libkrun VM user journeys.
# Shared cross-mode behavior remains in 07_cross_mode.sh.

if ! has_vm; then
    skip "VM tests" "VM support is unavailable or explicitly skipped"
    return 0 2>/dev/null || exit 0
fi

section "VM boot, process, and guest identity"

OUT=$(run_cdm --no-proxy --vm uname -s)
STATUS=$?
check_eq "vm: boots successfully" "$STATUS" "0"
check_eq "vm: runs Linux" "$OUT" "Linux"

case "$(uname -m)" in
    arm64|aarch64) EXPECTED_VM_ARCH=aarch64 ;;
    x86_64|amd64) EXPECTED_VM_ARCH=x86_64 ;;
    *) EXPECTED_VM_ARCH=$(uname -m) ;;
esac
OUT=$(run_cdm --no-proxy --vm uname -m)
check_eq "vm: guest architecture matches host target" "$OUT" "$EXPECTED_VM_ARCH"

OUT=$(run_cdm --no-proxy --vm id -u)
if [ "$(id -u)" = 0 ]; then
    EXPECTED_GUEST_UID=65534
else
    EXPECTED_GUEST_UID=$(id -u)
fi
check_eq "vm: guest uses a non-root mapped invoking uid" "$OUT" "$EXPECTED_GUEST_UID"
check_eq "vm: guest process is not root" "$(test "$OUT" != 0; echo $?)" "0"

run_cdm --no-proxy --vm /cdm-guest-init --security-probe >/dev/null 2>&1
STATUS=$?
check_eq "vm: no-new-privileges/setuid/capability probe passes" "$STATUS" "0"

OUT=$(run_cdm --no-proxy --vm pwd)
check_eq "vm: guest starts in requested workspace" "$OUT" "$FIXTURE"

ENV_DIGEST_BEFORE=$(shasum -a 256 "$FIXTURE/.env" | awk '{print $1}')
set +e
OUT=$(run_cdm --scramble --no-proxy --vm sh -c \
    'cat .env >/dev/null 2>&1; status=$?; printf "guest-ran"; exit "$status"')
STATUS=$?
check_not "vm: sensitive workspace file cannot be read" "$STATUS" "0"
check_eq "vm: sensitive-file read probe reached the guest" "$OUT" "guest-ran"
OUT=$(run_cdm --scramble --no-proxy --vm sh -c \
    'printf "replaced\n" > .env 2>/dev/null; status=$?; printf "guest-ran"; exit "$status"')
STATUS=$?
check_not "vm: sensitive workspace file cannot be overwritten" "$STATUS" "0"
check_eq "vm: sensitive-file write probe reached the guest" "$OUT" "guest-ran"
OUT=$(run_cdm --scramble --no-proxy --vm sh -c \
    'unlink .env 2>/dev/null; status=$?; printf "guest-ran"; exit "$status"')
STATUS=$?
check_not "vm: sensitive workspace file cannot be unlinked" "$STATUS" "0"
check_eq "vm: sensitive-file unlink probe reached the guest" "$OUT" "guest-ran"
ENV_DIGEST_AFTER=$(shasum -a 256 "$FIXTURE/.env" | awk '{print $1}')
check_eq "vm: sensitive host file remains unchanged" "$ENV_DIGEST_AFTER" "$ENV_DIGEST_BEFORE"

OUT=$(run_cdm --no-proxy --vm printf '<%s>' 'argument with spaces')
check_eq "vm: preserves argv boundaries" "$OUT" "<argument with spaces>"

OUT=$(cd "$FIXTURE" && printf 'stdin-roundtrip\n' | "$CDM" --no-proxy --vm cat 2>/dev/null)
STATUS=$?
check_eq "vm: stdin pipeline exits successfully" "$STATUS" "0"
check_eq "vm: forwards stdin to guest process" "$OUT" "stdin-roundtrip"

set +e
(cd "$FIXTURE" && "$CDM" --no-proxy --vm sh -c 'exit 37') >/dev/null 2>&1
STATUS=$?
check_eq "vm: propagates guest exit status" "$STATUS" "37"

echo ""
section "VM workspace round-trip and isolation"

VM_REPO=$(mktemp -d "${TMPDIR:-/tmp}/cdm vm journey.XXXXXX")
printf 'host-input\n' > "$VM_REPO/input.txt"
(cd "$VM_REPO" && "$CDM" --no-proxy --vm sh -c \
    'test "$(id -u)" != 0; cat input.txt; mkdir -p build/deep; printf "vm-output\n" > build/deep/result.txt') \
    >"$VM_REPO/guest.stdout" 2>"$VM_REPO/guest.stderr"
STATUS=$?
check_eq "vm: path-with-spaces journey succeeds" "$STATUS" "0"
check_eq "vm: guest reads host workspace file" "$(cat "$VM_REPO/guest.stdout")" "host-input"
check_eq "vm: nested guest write persists to host" \
    "$(cat "$VM_REPO/build/deep/result.txt" 2>/dev/null)" "vm-output"

remove_test_path "$VM_REPO/blocked.txt"
set +e
(cd "$VM_REPO" && "$CDM" --no-proxy --ro --vm sh -c \
    'printf "blocked\n" > blocked.txt') >/dev/null 2>&1
STATUS=$?
check_not "vm: read-only workspace rejects write" "$STATUS" "0"
check_eq "vm: denied read-only write does not reach host" \
    "$(test ! -e "$VM_REPO/blocked.txt"; echo $?)" "0"

# Each invocation must receive a fresh disposable guest rootfs.
(cd "$VM_REPO" && "$CDM" --no-proxy --vm sh -c \
    'test ! -e /tmp/cdm-ephemeral-marker; touch /tmp/cdm-ephemeral-marker') >/dev/null 2>&1
FIRST_STATUS=$?
(cd "$VM_REPO" && "$CDM" --no-proxy --vm sh -c \
    'test ! -e /tmp/cdm-ephemeral-marker') >/dev/null 2>&1
SECOND_STATUS=$?
check_eq "vm: first disposable-rootfs probe succeeds" "$FIRST_STATUS" "0"
check_eq "vm: rootfs changes do not persist between runs" "$SECOND_STATUS" "0"

remove_test_path "$VM_REPO"

echo ""
section "VM concurrent invocation"

VM_CONCURRENT=$(mktemp -d "${TMPDIR:-/tmp}/cdm-vm-concurrent.XXXXXX")
(cd "$VM_CONCURRENT" && "$CDM" --no-proxy --vm sh -c \
    'sleep 1; printf "one\n" > one.txt') >"$VM_CONCURRENT/one.stdout" 2>"$VM_CONCURRENT/one.stderr" &
PID_ONE=$!
(cd "$VM_CONCURRENT" && "$CDM" --no-proxy --vm sh -c \
    'sleep 1; printf "two\n" > two.txt') >"$VM_CONCURRENT/two.stdout" 2>"$VM_CONCURRENT/two.stderr" &
PID_TWO=$!
wait "$PID_ONE"; STATUS_ONE=$?
wait "$PID_TWO"; STATUS_TWO=$?
check_eq "vm: first concurrent guest succeeds" "$STATUS_ONE" "0"
check_eq "vm: second concurrent guest succeeds" "$STATUS_TWO" "0"
check_eq "vm: first concurrent write persists" "$(cat "$VM_CONCURRENT/one.txt" 2>/dev/null)" "one"
check_eq "vm: second concurrent write persists" "$(cat "$VM_CONCURRENT/two.txt" 2>/dev/null)" "two"
remove_test_path "$VM_CONCURRENT"

echo ""

if [ "${CDM_OCI_SMOKE_TESTS:-0}" = "1" ] || [ "${CDM_OCI_TESTS:-0}" = "1" ]; then
    section "VM OCI images"
    OCI_IMAGES="alpine:3.21"
    if [ "${CDM_OCI_TESTS:-0}" = "1" ]; then
        OCI_IMAGES="$OCI_IMAGES ubuntu:24.04 fedora:41 python:3.13-slim debian:bookworm-slim"
    fi
    for IMAGE in $OCI_IMAGES; do
        SHORT=${IMAGE%%:*}
        OUT=$(run_cdm --no-proxy --vmi "$IMAGE" sh -c 'printf "%s:%s:%s\n" "$(uname -s)" "$(uname -m)" "$(id -u)"')
        STATUS=$?
        check_eq "vmi/$SHORT: image boots" "$STATUS" "0"
        check "vmi/$SHORT: Linux guest identity" "$OUT" "Linux:$EXPECTED_VM_ARCH:$EXPECTED_GUEST_UID"

        OUT=$(run_cdm --no-proxy --vmi "$IMAGE" cat README.md)
        check "vmi/$SHORT: workspace files visible" "$OUT" "Test Project"
    done
    echo ""
fi
