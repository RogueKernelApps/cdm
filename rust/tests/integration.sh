#!/bin/bash
# CDM Integration Test Runner
#
# Runs all test suites from tests/suites/ in order.
# Each suite sources helpers.sh for shared functions.
#
# Usage:
#   ./tests/integration.sh              # run all suites
#   ./tests/integration.sh 01_seatbelt  # run one suite
#
# Test suites:
#   01_seatbelt.sh  — macOS Seatbelt sandbox
#   02_vm.sh        — real libkrun VM lifecycle and optional OCI images
#   03_proxy.sh     — HTTP/HTTPS proxy deobfuscation
#   04_worktree.sh  — Git state snapshot, worktree, branch, and VM composition
#   05_env.sh       — Environment, secrets, command blocking
#   06_config.sh    — Global/project configuration and precedence
#   07_cross_mode.sh — Cross-mode tests
#   08_ai_tools.sh  — AI coding tool compatibility
#   09_cli_network.sh — CLI parsing and network policy
#   10_filesystem_policy.sh — filesystem access modes and hard denials
#   11_security_mode.sh — secure persistence policy and deny-first macOS baseline
#   12_app_mode.sh — macOS application bundle discovery and launch
#   13_argv_fidelity.sh — exact argv preservation across adapters
#   14_input_validation.sh — malformed CLI and configuration failures
#   15_process_lifecycle.sh — child status, signals, and cleanup
#   16_compatibility_matrix.sh — opt-in credential-free real-tool probes
#   17_structured_reporting.sh — redacted JSON reports and stderr-only stats
#   18_builtin_commands.sh — built-in dispatch on the exact tested artifact

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUITES_DIR="$SCRIPT_DIR/suites"

# Colors
BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Source helpers (makes functions + vars available to all suites)
source "$SUITES_DIR/helpers.sh"

# Acceptance must be independent of the runner's credentials and mutable home
# configuration. Normalize a trailing slash first so guarded cleanup compares
# the same spelling that mktemp returns on macOS.
TMPDIR=${TMPDIR:-/tmp}
TMPDIR=${TMPDIR%/}
# macOS commonly exports TMPDIR through the /var -> /private/var alias. CDM's
# hostile-cache validation deliberately rejects symlink traversal, so create
# the isolated test home beneath the physical spelling used by the kernel.
TMPDIR=$(cd -P "$TMPDIR" && pwd)
export TMPDIR
CDM_TEST_REAL_HOME=${HOME:-}
CDM_TEST_HOME_ROOT=$(mktemp -d "$TMPDIR/cdm-integration-home.XXXXXX")
mkdir -p "$CDM_TEST_HOME_ROOT/home"
chmod 700 "$CDM_TEST_HOME_ROOT" "$CDM_TEST_HOME_ROOT/home"
export CDM_TEST_REAL_HOME CDM_TEST_HOME_ROOT
export HOME="$CDM_TEST_HOME_ROOT/home"
cleanup_integration_home() {
    remove_test_path "$CDM_TEST_HOME_ROOT"
}
trap cleanup_integration_home EXIT

echo -e "${BOLD}=== CDM Integration Tests ===${NC}"

# Determine which suites to run
if [ -n "$1" ]; then
    # Run specific suite(s)
    SUITES=""
    for arg in "$@"; do
        match=$(ls "$SUITES_DIR"/*"$arg"*.sh 2>/dev/null | head -1)
        if [ -n "$match" ]; then
            SUITES="$SUITES $match"
        else
            echo "Suite not found: $arg"
            exit 1
        fi
    done
else
    # Run all suites in order
    SUITES=$(ls "$SUITES_DIR"/[0-9]*.sh 2>/dev/null | sort)
fi

if [ -z "$SUITES" ]; then
    echo "No test suites found in $SUITES_DIR"
    exit 1
fi

# Test the requested artifact, never an unrelated installed copy.
CDM_BIN="${CDM:-$(pwd)/target/release/cdm}"
if [ ! -x "$CDM_BIN" ]; then
    echo "Binary is not executable: $CDM_BIN"
    echo "Build it first or set CDM=/absolute/path/to/cdm"
    exit 1
fi
export CDM="$CDM_BIN"
if [ -z "${CDM_CONFIG_PATH:-}" ]; then
    CDM_TEST_POLICY_DIR="$CDM_TEST_HOME_ROOT/policy"
    mkdir -p "$CDM_TEST_POLICY_DIR"
    chmod 700 "$CDM_TEST_POLICY_DIR"
    export CDM_CONFIG_PATH="$CDM_TEST_POLICY_DIR/no-config.json"
else
    export CDM_CONFIG_PATH
fi
export CDM_CACHE_DIR="${CDM_CACHE_DIR:-$CDM_TEST_HOME_ROOT/cache}"
echo "Binary: $CDM_BIN"
echo ""

if [ "${CDM_REQUIRE_NATIVE:-0}" = "1" ] && ! has_native; then
    echo "Required native sandbox adapter is unavailable"
    exit 1
fi
if [ "${CDM_REQUIRE_VM:-0}" = "1" ] && ! has_vm; then
    echo "Required VM adapter is unavailable for the exact test artifact"
    exit 1
fi

# Run each suite
for suite in $SUITES; do
    source "$suite"
    echo ""
done

# Summary
echo -e "${BOLD}=== Results ===${NC}"
TOTAL=$((PASS + FAIL + SKIP))
echo -e "${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC} (of $TOTAL)"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
