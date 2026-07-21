#!/bin/bash
# CDM Integration Tests: Environment variables, secrets, command blocking
# Runs across all sandbox modes (native, --vm, --vmi)
# Helpers inherited from integration.sh runner

section "Secret preparation fails closed before adapter launch"

assert_secret_prelaunch_failure() {
    local name="$1" workspace="$2" secret_text="$3" config_path="${4:-$CDM_CONFIG_PATH}"
    local stderr status

    stderr=$(cd "$workspace" && CDM_CONFIG_PATH="$config_path" \
        "$CDM" --rw --scramble --no-network -- sh -c \
        'printf "child-ran\n" > child-marker' 2>&1 >/dev/null)
    status=$?

    if [ "$status" -ne 0 ]; then
        check_eq "$name: CDM rejects unsafe secret input" "nonzero" "nonzero"
    else
        check_eq "$name: CDM rejects unsafe secret input" "zero" "nonzero"
    fi
    check_eq "$name: child never creates its marker" \
        "$(test ! -e "$workspace/child-marker"; echo $?)" "0"
    if echo "$stderr" | grep -Eiq -- 'secret scan|secret staging|staging|sensitive|environment file'; then
        check_eq "$name: stderr identifies secret preparation" "identified" "identified"
    else
        check_eq "$name: stderr identifies secret preparation" "missing diagnostic" "identified"
    fi
    check_not "$name: stderr does not disclose secret contents" "$stderr" "$secret_text"
}

SECRET_FAILURE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdm-secret-failclosed.XXXXXX")

SYMLINK_WORK="$SECRET_FAILURE_ROOT/symlink-work"
SYMLINK_SECRET="symlink-secret-content-4f87d630"
mkdir -p "$SYMLINK_WORK"
printf 'API_KEY=%s\n' "$SYMLINK_SECRET" > "$SECRET_FAILURE_ROOT/external.env"
ln -s "$SECRET_FAILURE_ROOT/external.env" "$SYMLINK_WORK/.env"
assert_secret_prelaunch_failure "symlinked .env" "$SYMLINK_WORK" "$SYMLINK_SECRET"

ANCESTOR_WORK="$SECRET_FAILURE_ROOT/ancestor-work"
ANCESTOR_OUTSIDE="$SECRET_FAILURE_ROOT/ancestor-outside"
ANCESTOR_POLICY="$SECRET_FAILURE_ROOT/ancestor-policy"
ANCESTOR_SECRET="ancestor-secret-content-2d5480c7"
mkdir -p "$ANCESTOR_WORK" "$ANCESTOR_OUTSIDE" "$ANCESTOR_POLICY"
chmod 700 "$ANCESTOR_POLICY"
printf 'API_KEY=%s\n' "$ANCESTOR_SECRET" > "$ANCESTOR_OUTSIDE/candidate.env"
ln -s "$ANCESTOR_OUTSIDE" "$ANCESTOR_WORK/linked"
printf '{"secrets":{"env_files":["linked/candidate.env"]}}\n' \
    > "$ANCESTOR_POLICY/config.json"
assert_secret_prelaunch_failure \
    "ancestor-symlinked environment file" \
    "$ANCESTOR_WORK" \
    "$ANCESTOR_SECRET" \
    "$ANCESTOR_POLICY/config.json"

MALFORMED_WORK="$SECRET_FAILURE_ROOT/malformed-work"
MALFORMED_SECRET="malformed-secret-content-8c12e9a4"
mkdir -p "$MALFORMED_WORK"
printf 'API_KEY=%s\n\377\376' "$MALFORMED_SECRET" > "$MALFORMED_WORK/.env"
assert_secret_prelaunch_failure "malformed .env" "$MALFORMED_WORK" "$MALFORMED_SECRET"

remove_test_path "$SECRET_FAILURE_ROOT"

section "Credential directory sockets"

SOCKET_HOME=$(mktemp -d "/tmp/cdm-ssh-home.XXXXXX")
chmod 700 "$SOCKET_HOME"
mkdir -p "$SOCKET_HOME/.ssh"
chmod 700 "$SOCKET_HOME/.ssh"
python3 - "$SOCKET_HOME/.ssh/control.sock" <<'PY'
import socket
import sys

with socket.socket(socket.AF_UNIX) as listener:
    listener.bind(sys.argv[1])
PY
SOCKET_STATUS=0
(cd "$FIXTURE" && HOME="$SOCKET_HOME" "$CDM" --scramble --no-network -- true \
    >/dev/null 2>&1) || SOCKET_STATUS=$?
check_eq "SSH sockets do not block secret preparation" "$SOCKET_STATUS" "0"
remove_test_path "$SOCKET_HOME"

section "Environment Sanity (cross-mode)"

cross_check 'echo $CDM' "1" "CDM marker set"
cross_check 'echo ${DYLD_INSERT_LIBRARIES:-unset}' "unset" "DYLD_INSERT_LIBRARIES stripped"

# Direct networking is the default. It must not invent CDM proxy or CA state.
for mode in $MODES; do
    check_empty "$mode: direct default has no HTTP_PROXY" "$(mode_run "$mode" 'echo ${HTTP_PROXY:-}')"
    check_empty "$mode: direct default has no injected NODE_OPTIONS" "$(mode_run "$mode" 'echo ${NODE_OPTIONS:-}')"
    check_eq "$mode: direct default has no NODE_EXTRA_CA_CERTS" \
        "$(mode_run "$mode" 'echo ${NODE_EXTRA_CA_CERTS:-missing}')" "missing"
done

echo ""
section "Developer-friendly secret defaults (cross-mode)"

cross_check 'grep ^API_KEY= .env' "$REAL_SECRET" ".env remains readable by default"
cross_check 'echo ${API_KEY:-unset}' "unset" ".env is not implicitly sourced"

for mode in $MODES; do
    OUT=$(cd "$FIXTURE" && DEFAULT_SECRET="$REAL_SECRET" \
        mode_exec "$mode" sh -c 'printf "%s" "$DEFAULT_SECRET"')
    check_eq "$mode: host environment secrets pass through by default" "$OUT" "$REAL_SECRET"
done

echo ""
section "Explicit secret scrambling (cross-mode)"

for mode in $MODES; do
    OUT=$(ONE_CHAR_API_KEY=a mode_exec "$mode" --scramble --no-network sh -c \
        'printf "%s|%s" "$ONE_CHAR_API_KEY" "$1"' sh cat)
    check_eq "$mode: one-character secret leaves unrelated argv unchanged" \
        "${OUT#*|}" "cat"
    check_eq "$mode: one-character secret is not exposed" \
        "$(test "${OUT%%|*}" != a; echo $?)" "0"

    OUT=$(SHORT_API_KEY=abc mode_exec "$mode" --scramble --no-network sh -c \
        'printf "%s" "$SHORT_API_KEY"')
    check_nonempty "$mode: --scramble injects a short secret-named value" "$OUT"
    check_eq "$mode: --scramble hides a short secret-named value" \
        "$(test "$OUT" != abc; echo $?)" "0"

    OUT=$(mode_exec "$mode" --scramble --no-network sh -c 'printf "%s" "$API_KEY"')
    check_nonempty "$mode: --scramble injects API_KEY" "$OUT"
    check_not "$mode: --scramble hides the real API_KEY" "$OUT" "sk-test-a1b2c3d4"

    OUT=$(mode_exec "$mode" --scramble --no-network sh -c 'printf "%s" "$AWS_SECRET_ACCESS_KEY"')
    check_nonempty "$mode: --scramble injects AWS_SECRET_ACCESS_KEY" "$OUT"
    check_not "$mode: --scramble hides the real AWS secret" "$OUT" "wJalrXUtnFEMI"

    OUT=$(mode_exec "$mode" --scramble --no-network sh -c 'printf "%s" "$GITHUB_TOKEN"')
    check_nonempty "$mode: --scramble injects GITHUB_TOKEN" "$OUT"
    check_not "$mode: --scramble hides the real GitHub token" "$OUT" "ghp_ABCDEFGH"

    OUT=$(mode_exec "$mode" --scramble --no-network sh -c 'printf "%s" "$STRIPE_SECRET_KEY"')
    check_nonempty "$mode: --scramble injects STRIPE_SECRET_KEY" "$OUT"
    check_not "$mode: --scramble hides the real Stripe secret" "$OUT" "sk_test_51HG8vL"

    check_empty "$mode: --scramble blocks direct .env reads" \
        "$(mode_exec "$mode" --scramble --no-network sh -c 'cat .env 2>/dev/null')"
    check_eq "$mode: --scramble still injects non-secret .env entries" \
        "$(mode_exec "$mode" --scramble --no-network sh -c 'printf "%s" "$APP_NAME"')" \
        "my-test-app"

    OUT=$(mode_exec "$mode" --sec --no-network sh -c 'printf "%s" "$API_KEY"')
    check_nonempty "$mode: --sec implies secret scrambling" "$OUT"
    check_not "$mode: --sec does not expose the real API_KEY" "$OUT" "sk-test-a1b2c3d4"
done

for mode in $MODES; do
    if mode_supports_proxy "$mode"; then
        check "$mode: --scramble enables HTTP_PROXY" \
            "$(mode_exec "$mode" --scramble sh -c 'printf "%s" "$HTTP_PROXY"')" \
            "http://127.0.0.1:"
        check "$mode: --scramble injects CA options" \
            "$(mode_exec "$mode" --scramble sh -c 'printf "%s" "$NODE_OPTIONS"')" \
            "use-system-ca"
    else
        skip "$mode: --scramble proxy environment" "strict proxy transport is unavailable"
    fi
done

echo ""
section "Ordinary file access (cross-mode)"

for mode in $MODES; do
    OUT=$(mode_run "$mode" "ls README.md")
    check "$mode: non-secret files accessible" "$OUT" "README.md"
done

echo ""
section "Command Preflight (cross-mode)"

# The default preflight should refuse a direct sudo mistake in all modes.
for mode in $MODES; do
    OUT=$(mode_run "$mode" "sudo echo hello")
    check_empty "$mode: sudo refused by preflight" "$OUT"

    OUT=$(mode_run "$mode" "aws --version")
    check_empty "$mode: direct AWS CLI refused by preflight" "$OUT"
done

cross_check 'echo safe' "safe" "safe command allowed"
