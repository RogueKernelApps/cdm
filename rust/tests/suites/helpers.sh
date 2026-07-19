#!/bin/bash
# Shared test helpers for CDM integration tests.
# Source this file from individual test suites.

# integration.sh exports the exact artifact under test.
CDM="${CDM:-$(pwd)/target/release/cdm}"
FIXTURE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../fixture" && pwd)"

# Counters (exported so suites can increment)
export PASS=${PASS:-0}
export FAIL=${FAIL:-0}
export SKIP=${SKIP:-0}

# Known real secrets from fixture/.env
export REAL_SECRET="sk-test-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'
export RED GREEN YELLOW BOLD NC

check() {
    local name="$1" actual="$2" expect="$3"
    if echo "$actual" | grep -Fq -- "$expect"; then
        printf "  ${GREEN}PASS${NC} %s\n" "$name"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} %s\n" "$name"
        echo "    expected to contain: $expect"
        echo "    got: $(echo "$actual" | head -3)"
        FAIL=$((FAIL + 1))
    fi
}

check_eq() {
    local name="$1" actual="$2" expect="$3"
    if [ "$actual" = "$expect" ]; then
        printf "  ${GREEN}PASS${NC} %s\n" "$name"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} %s\n" "$name"
        echo "    expected exactly: $expect"
        echo "    got: $actual"
        FAIL=$((FAIL + 1))
    fi
}

check_not() {
    local name="$1" actual="$2" reject="$3"
    if echo "$actual" | grep -Fq -- "$reject"; then
        printf "  ${RED}FAIL${NC} %s\n" "$name"
        echo "    should NOT contain: $reject"
        FAIL=$((FAIL + 1))
    else
        printf "  ${GREEN}PASS${NC} %s\n" "$name"
        PASS=$((PASS + 1))
    fi
}

check_empty() {
    local name="$1" actual="$2"
    if [ -z "$actual" ]; then
        printf "  ${GREEN}PASS${NC} %s\n" "$name"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} %s\n" "$name"
        echo "    expected empty, got: $(echo "$actual" | head -3)"
        FAIL=$((FAIL + 1))
    fi
}

check_nonempty() {
    local name="$1" actual="$2"
    if [ -n "$actual" ]; then
        printf "  ${GREEN}PASS${NC} %s\n" "$name"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC} %s\n" "$name"
        echo "    expected non-empty output"
        FAIL=$((FAIL + 1))
    fi
}

skip() {
    local name="$1" reason="$2"
    printf "  ${YELLOW}SKIP${NC} %s (%s)\n" "$name" "$reason"
    SKIP=$((SKIP + 1))
}

# Remove only CDM-owned test artifacts beneath a temporary directory. The
# user's `rm` may be an alias or an rmtrash wrapper, so always select the
# platform utility through `command -p`. Refuse empty, relative, root-like,
# current-directory, traversal, and CDM runtime-directory operands.
remove_test_path() {
    if [ "$#" -eq 0 ]; then
        echo "refusing test cleanup without an operand" >&2
        return 2
    fi

    local path temp_root allowed physical_cwd physical_path
    physical_cwd=$(pwd -P)
    for path in "$@"; do
        case "$path" in
            ""|/|.|..|./|../|"$PWD"|"$PWD/"|"$physical_cwd"|"$physical_cwd/")
                echo "refusing dangerous test cleanup operand" >&2
                return 2
                ;;
            /*) ;;
            *)
                echo "refusing relative test cleanup operand: $path" >&2
                return 2
                ;;
        esac
        case "$path" in
            */../*|*/..|*/./*|*/.)
                echo "refusing non-normalized test cleanup operand: $path" >&2
                return 2
                ;;
        esac

        if [ -d "$path" ]; then
            physical_path=$(CDPATH= cd -- "$path" 2>/dev/null && pwd -P)
            if [ -n "$physical_path" ] && [ "$physical_path" = "$physical_cwd" ]; then
                echo "refusing cleanup of the current directory through an alias" >&2
                return 2
            fi
        fi

        allowed=0
        for temp_root in "${TMPDIR:-/tmp}" /tmp /private/tmp; do
            temp_root=${temp_root%/}
            case "$path" in
                "$temp_root"/cdm-*|"$temp_root"/cdm_*|"$temp_root"/cdm\ *)
                    allowed=1
                    break
                    ;;
            esac
        done
        if [ "$allowed" -ne 1 ]; then
            echo "refusing cleanup outside a CDM test path: $path" >&2
            return 2
        fi
    done

    command -p rm -rf -- "$@"
}

# Run CDM from the fixture. Most cross-mode assertions intentionally discard
# diagnostics; focused stderr assertions opt in without bypassing this helper.
run_cdm() {
    if [ "${CDM_TEST_CAPTURE_STDERR:-0}" = "1" ]; then
        (cd "$FIXTURE" && "$CDM" "$@")
    else
        (cd "$FIXTURE" && "$CDM" "$@" 2>/dev/null)
    fi
}

has_native() {
    case "$(uname -s)" in
        Darwin)
            /usr/bin/sandbox-exec -p '(version 1) (allow default)' /usr/bin/true >/dev/null 2>&1
            ;;
        Linux)
            command -v bwrap >/dev/null 2>&1
            ;;
        *) return 1 ;;
    esac
}

host_platform() {
    case "$(uname -s)" in
        Darwin) printf '%s\n' darwin ;;
        Linux) printf '%s\n' linux ;;
        *) printf '%s\n' unsupported ;;
    esac
}

native_adapter() {
    case "$(host_platform)" in
        darwin) printf '%s\n' seatbelt ;;
        linux) printf '%s\n' bubblewrap ;;
        *) printf '%s\n' unavailable ;;
    esac
}

mode_supports_proxy() {
    local mode=$1
    case "$mode" in
        native|vm|vmi/*)
            "$CDM" __capabilities__ 2>/dev/null | grep -Fxq strict-proxy
            ;;
        *) return 1 ;;
    esac
}

has_vm() {
    [ "${CDM_SKIP_VM:-0}" != "1" ] && "$CDM" __capabilities__ 2>/dev/null | grep -Fxq vm
}

# Helper: create a temp git repo for workspace tests
make_test_repo() {
    local dir=$(mktemp -d "${TMPDIR:-/tmp}/cdm_ws_test.XXXXXX")
    git -C "$dir" init -q
    git -C "$dir" config user.name "cdm-test"
    git -C "$dir" config user.email "test@cdm"
    printf '*.stderr\n*.stdout\n' >> "$dir/.git/info/exclude"
    echo "original" > "$dir/file.txt"
    git -C "$dir" add . && git -C "$dir" commit -q -m "initial"
    echo "$dir"
}

section() {
    echo -e "${BOLD}--- $1 ---${NC}"
}

# ---------------------------------------------------------------------------
# Cross-mode testing
# ---------------------------------------------------------------------------

# Build the list of sandbox modes to test.
# Include only modes available for this exact artifact and host. OCI pulls are
# opt-in because they require external registry access and mutate the image cache.
MODES=""
has_native && MODES="native"
has_vm && MODES="${MODES:+$MODES }vm"
if has_vm && [ "${CDM_OCI_TESTS:-0}" = "1" ]; then
    MODES="${MODES:+$MODES }vmi/alpine:3.21"
fi
export MODES

# Run a cdm command in a specific mode.
# For the native adapter, shell commands (containing $, &&, |) are wrapped in
# bash -c. The mode name is intentionally platform-neutral: it represents
# Seatbelt on macOS and Bubblewrap on Linux.
# For VM modes, the init script handles shell interpretation natively.
mode_run() {
    local mode="$1"; shift
    local cmd="$*"

    case "$mode" in
        native)
            # Native adapters use execvp — shell syntax needs bash -c wrapping.
            if echo "$cmd" | grep -qE '[$&|;>]'; then
                mode_exec native bash -c "$cmd"
            else
                mode_exec native $cmd
            fi
            ;;
        vm)       mode_exec vm sh -c "$cmd" ;;
        vmi/*)    mode_exec "$mode" sh -c "$cmd" ;;
    esac
}

# Run an argv vector without joining or re-parsing its arguments. Use this for
# command-line fidelity tests; mode_run intentionally accepts shell text.
mode_exec() {
    local mode="$1"; shift

    case "$mode" in
        native) run_cdm "$@" ;;
        vm) run_cdm --vm "$@" ;;
        vmi/*) run_cdm --vmi "${mode#vmi/}" "$@" ;;
    esac
}

# Run shell text with explicit secret scrambling in a specific mode.
mode_run_scrambled() {
    local mode="$1"; shift
    local cmd="$*"

    case "$mode" in
        native) mode_exec native --scramble bash -c "$cmd" ;;
        vm) mode_exec vm --scramble sh -c "$cmd" ;;
        vmi/*) mode_exec "$mode" --scramble sh -c "$cmd" ;;
    esac
}

# Portable process-group timeout used by opt-in compatibility tests. The
# Python helper terminates the whole group so a timed-out harness or desktop
# app cannot be left running after the suite.
run_with_timeout() {
    local seconds="$1"; shift
    python3 "$SCRIPT_DIR/run_with_timeout.py" "$seconds" "$@"
}

# Run the same assertion across all modes.
#   cross_check "echo hello" "hello"           → tests output contains "hello"
#   cross_check_not "echo \$API_KEY" "sk-test" → tests output does NOT contain real secret
#   cross_check_empty "cat .env"               → tests output is empty
#
# The first arg is the command (passed to sh -c if it contains $).
# Remaining args are the expected value / rejection pattern.
cross_check() {
    local cmd="$1" expect="$2" label="${3:-$cmd}"
    for mode in $MODES; do
        local out=$(mode_run "$mode" "$cmd")
        check "$mode: $label" "$out" "$expect"
    done
}

cross_check_not() {
    local cmd="$1" reject="$2" label="${3:-$cmd}"
    for mode in $MODES; do
        local out=$(mode_run "$mode" "$cmd")
        check_not "$mode: $label" "$out" "$reject"
    done
}

cross_check_empty() {
    local cmd="$1" label="${2:-$cmd}"
    for mode in $MODES; do
        local out=$(mode_run "$mode" "$cmd")
        check_empty "$mode: $label" "$out"
    done
}

cross_check_nonempty() {
    local cmd="$1" label="${2:-$cmd}"
    for mode in $MODES; do
        local out=$(mode_run "$mode" "$cmd")
        check_nonempty "$mode: $label" "$out"
    done
}

cross_check_scrambled() {
    local cmd="$1" expect="$2" label="${3:-$cmd}"
    for mode in $MODES; do
        local out=$(mode_run_scrambled "$mode" "$cmd")
        check "$mode: $label" "$out" "$expect"
    done
}

cross_check_scrambled_not() {
    local cmd="$1" reject="$2" label="${3:-$cmd}"
    for mode in $MODES; do
        local out=$(mode_run_scrambled "$mode" "$cmd")
        check_not "$mode: $label" "$out" "$reject"
    done
}

cross_check_scrambled_empty() {
    local cmd="$1" label="${2:-$cmd}"
    for mode in $MODES; do
        local out=$(mode_run_scrambled "$mode" "$cmd")
        check_empty "$mode: $label" "$out"
    done
}

cross_check_scrambled_nonempty() {
    local cmd="$1" label="${2:-$cmd}"
    for mode in $MODES; do
        local out=$(mode_run_scrambled "$mode" "$cmd")
        check_nonempty "$mode: $label" "$out"
    done
}
