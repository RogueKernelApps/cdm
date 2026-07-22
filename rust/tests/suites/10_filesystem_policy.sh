#!/bin/bash
# CDM Integration Tests: filesystem access policy
# Helpers inherited from integration.sh runner

section "Filesystem access policy"

policy_run() {
    local mode="$1" cwd="$2"; shift 2
    case "$mode" in
        native) (cd "$cwd" && HOME="${POLICY_HOME:-$HOME}" "$CDM" --no-proxy "$@") ;;
        vm) (cd "$cwd" && HOME="${POLICY_HOME:-$HOME}" "$CDM" --vm --no-proxy "$@") ;;
        vmi/*) (cd "$cwd" && HOME="${POLICY_HOME:-$HOME}" "$CDM" --vmi "${mode#vmi/}" --no-proxy "$@") ;;
    esac
}

for mode in $MODES; do
    ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdm_policy_test.XXXXXX")
    WORK="$ROOT/work"
    EXTRA_RW="$ROOT/extra-rw"
    EXTRA_RO="$ROOT/extra-ro"
    OUTSIDE="$ROOT/outside"
    mkdir -p "$WORK/.git" "$EXTRA_RW" "$EXTRA_RO" "$OUTSIDE/delete-me"
    echo original > "$WORK/.git/config"
    echo readable > "$EXTRA_RO/data.txt"
    echo preserve > "$OUTSIDE/delete-me/data.txt"
    echo original > "$OUTSIDE/file.txt"
    echo 'SECRET_TOKEN=host-secret-value-123456' > "$WORK/.env"

    OUT=$(policy_run "$mode" "$WORK" -- sh -c \
        'test -n "$TMPDIR" && test -d "$TMPDIR" && test -w "$TMPDIR" && touch "$TMPDIR/runtime-write" && printf private-temp-ok' \
        2>/dev/null)
    check_eq "$mode: TMPDIR is a writable invocation-private directory" "$OUT" "private-temp-ok"

    policy_run "$mode" "$WORK" -- sh -c 'echo created > created.txt' >/dev/null 2>&1
    check "$mode: default workspace is writable" "$(cat "$WORK/created.txt" 2>/dev/null)" "created"

    policy_run "$mode" "$WORK" --ro -- sh -c 'echo blocked > ro-created.txt' >/dev/null 2>&1
    if [ $? -ne 0 ] && [ ! -e "$WORK/ro-created.txt" ]; then
        check "$mode: --ro blocks workspace writes" "blocked" "blocked"
    else
        check "$mode: --ro blocks workspace writes" "write unexpectedly succeeded" "blocked"
    fi

    policy_run "$mode" "$WORK" --ro --allow-rw "$EXTRA_RW" -- sh -c "echo allowed > '$EXTRA_RW/result.txt'" >/dev/null 2>&1
    check "$mode: --allow-rw creates a writable hole" "$(cat "$EXTRA_RW/result.txt" 2>/dev/null)" "allowed"

    OUT=$(policy_run "$mode" "$WORK" --iso -- sh -c "cat '$EXTRA_RO/data.txt'" 2>/dev/null)
    check_empty "$mode: --iso hides ungranted host data" "$OUT"

    OUT=$(policy_run "$mode" "$WORK" --iso --allow-ro "$EXTRA_RO/data.txt" -- sh -c "cat '$EXTRA_RO/data.txt'" 2>/dev/null)
    RC=$?
    case "$mode" in
        native)
            check_eq "$mode: --allow-ro exposes one file" "$RC" "0"
            check "$mode: --allow-ro reads the granted file" "$OUT" "readable"
            ;;
        vm|vmi/*)
            if [ "$RC" -ne 0 ] && [ -z "$OUT" ]; then
                check "$mode: external single-file grant fails closed" "blocked" "blocked"
            else
                check "$mode: external single-file grant fails closed" "rc=$RC output=$OUT" "blocked"
            fi
            ;;
    esac

    policy_run "$mode" "$WORK" --iso --ro -- sh -c 'echo blocked > iso-ro.txt' >/dev/null 2>&1
    if [ $? -ne 0 ] && [ ! -e "$WORK/iso-ro.txt" ]; then
        check "$mode: --iso --ro composes" "blocked" "blocked"
    else
        check "$mode: --iso --ro composes" "write unexpectedly succeeded" "blocked"
    fi

    policy_run "$mode" "$WORK" -- sh -c 'echo changed > .git/config' >/dev/null 2>&1
    check "$mode: .git follows RW workspace policy" "$(cat "$WORK/.git/config")" "changed"

    policy_run "$mode" "$WORK" -- sh -c "rm -rf '$OUTSIDE/delete-me'" >/dev/null 2>&1
    check "$mode: cannot delete an outside directory" "$(cat "$OUTSIDE/delete-me/data.txt" 2>/dev/null)" "preserve"

    ln -s "$OUTSIDE/file.txt" "$WORK/outside-symlink.txt"
    policy_run "$mode" "$WORK" -- sh -c 'echo symlink-escape > outside-symlink.txt' >/dev/null 2>&1
    check "$mode: workspace symlink cannot write outside" "$(cat "$OUTSIDE/file.txt")" "original"

    policy_run "$mode" "$WORK" -- sh -c "ln '$OUTSIDE/file.txt' outside-hardlink.txt && echo hardlink-escape > outside-hardlink.txt" >/dev/null 2>&1
    check "$mode: cannot hard-link and write an outside file" "$(cat "$OUTSIDE/file.txt")" "original"

    policy_run "$mode" "$WORK" -- sh -c 'echo changed > .env' >/dev/null 2>&1
    check_eq "$mode: default mode leaves .env writable with its workspace" \
        "$(cat "$WORK/.env")" "changed"
    echo 'SECRET_TOKEN=host-secret-value-123456' > "$WORK/.env"
    OUT=$(policy_run "$mode" "$WORK" --scramble -- sh -c \
        'cat .env >/dev/null 2>&1; read_status=$?; echo changed > .env 2>/dev/null; write_status=$?; printf guest-ran; test "$read_status" -ne 0 && test "$write_status" -ne 0' \
        2>/dev/null)
    check_eq "$mode: scrambled secret denial probe reaches the child" "$OUT" "guest-ran"
    check "$mode: scrambled secret file remains immutable" \
        "$(cat "$WORK/.env")" "host-secret-value-123456"

    TEST_HOME="$ROOT/home"
    mkdir -p "$TEST_HOME/.aws"
    cat > "$TEST_HOME/.aws/credentials" <<'EOF'
[default]
aws_access_key_id=AKIAEXAMPLE12345678
aws_secret_access_key=host-secret-value-123456
EOF
    OUT=$(POLICY_HOME="$TEST_HOME" policy_run "$mode" "$WORK" --scramble --iso --allow-ro "$TEST_HOME/.aws" -- sh -c 'cat "$AWS_SHARED_CREDENTIALS_FILE"' 2>/dev/null)
    check "$mode: --iso reads staged config from private runtime" "$OUT" "[default]"
    check_not "$mode: --iso staged config hides the real value" "$OUT" "host-secret-value-123456"

    remove_test_path "$ROOT"
done

if [ "$(uname -s)" = "Darwin" ] && has_native; then
    PHYSICAL_TMP=${TMPDIR%/}
    case "$PHYSICAL_TMP" in
        /private/var/*) PUBLIC_TMP="/var/${PHYSICAL_TMP#/private/var/}" ;;
        *) PUBLIC_TMP=$PHYSICAL_TMP ;;
    esac
    OUT=$(cd "$FIXTURE" && TMPDIR="$PUBLIC_TMP/" "$CDM" --no-proxy -- sh -c \
        'mkdir -p "$TMPDIR/nested/tool/runtime" && printf nested-temp-ok' 2>/dev/null)
    check_eq "macOS: public temp alias permits nested tool directories" \
        "$OUT" "nested-temp-ok"

    ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdm_macos_denial_rename_test.XXXXXX")
    WORK="$ROOT/work"
    CONFIG_DIR="$ROOT/config"
    DENIED="$WORK/outer/inner/.env"
    MISSING="$WORK/future/inner/protected"
    mkdir -p "$WORK/outer/inner"
    mkdir -p "$WORK/future/inner"
    printf 'classified\n' > "$DENIED"
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    printf '{"paths":{"deny_read":["%s"],"deny_write":["%s","%s"]}}\n' \
        "$DENIED" "$DENIED" "$MISSING" > "$CONFIG_DIR/config.json"
    chmod 600 "$CONFIG_DIR/config.json"

    (cd "$WORK" && CDM_CONFIG_PATH="$CONFIG_DIR/config.json" \
        "$CDM" --no-network -- sh -c \
        'mv outer/inner outer/moved; cat outer/moved/.env; printf escaped > outer/moved/.env') \
        >"$ROOT/immediate.out" 2>/dev/null
    RC=$?
    if [ "$RC" -ne 0 ] && [ -e "$DENIED" ] && [ ! -e "$WORK/outer/moved/.env" ]; then
        check "macOS: hard denial pins the immediate parent against rename" "blocked" "blocked"
    else
        check "macOS: hard denial pins the immediate parent against rename" "escaped" "blocked"
    fi

    (cd "$WORK" && CDM_CONFIG_PATH="$CONFIG_DIR/config.json" \
        "$CDM" --no-network -- sh -c \
        'mv outer outer-moved; cat outer-moved/inner/.env; printf escaped > outer-moved/inner/.env') \
        >"$ROOT/higher.out" 2>/dev/null
    RC=$?
    if [ "$RC" -ne 0 ] && [ -e "$DENIED" ] && [ ! -e "$WORK/outer-moved/inner/.env" ]; then
        check "macOS: hard denial pins higher ancestors against rename" "blocked" "blocked"
    else
        check "macOS: hard denial pins higher ancestors against rename" "escaped" "blocked"
    fi
    check "macOS: denied content remains unchanged after rename attempts" "$(cat "$DENIED")" "classified"

    (cd "$WORK" && CDM_CONFIG_PATH="$CONFIG_DIR/config.json" \
        "$CDM" --no-network -- sh -c \
        'mv future future-moved; mkdir -p future/inner; printf escaped > future/inner/protected') \
        >"$ROOT/missing.out" 2>/dev/null
    RC=$?
    if [ "$RC" -ne 0 ] && [ ! -e "$MISSING" ] && [ ! -e "$WORK/future-moved/inner/protected" ]; then
        check "macOS: missing hard-denial ancestors cannot be renamed and recreated" "blocked" "blocked"
    else
        check "macOS: missing hard-denial ancestors cannot be renamed and recreated" "escaped" "blocked"
    fi
    remove_test_path "$ROOT"
fi

if [ "$(uname -s)" = "Linux" ] && has_native; then
    ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdm_socket_deputy_test.XXXXXX")
    WORK="$ROOT/work"
    SOCKET="$ROOT/ssh-agent.sock"
    MARKER="$ROOT/deputy-reached"
    READY="$ROOT/ready"
    TEST_HOME="$ROOT/home"
    CONFIG_DIR="$ROOT/config"
    PRIVATE_DIR="$WORK/private"
    MISSING_LEAF="$WORK/future/protected"
    mkdir -p "$WORK" "$TEST_HOME" "$CONFIG_DIR" "$PRIVATE_DIR"
    printf 'classified\n' > "$PRIVATE_DIR/data"
    printf '{"paths":{"deny_read":["%s"],"deny_write":["%s"]}}\n' \
        "$PRIVATE_DIR" "$MISSING_LEAF" > "$CONFIG_DIR/config.json"

    OUT=$(cd "$WORK" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$CONFIG_DIR/config.json" \
        "$CDM" --no-network -- sh -c "cat '$PRIVATE_DIR/data'" 2>/dev/null)
    check_empty "linux: directory hard-read denial masks all descendants" "$OUT"

    (cd "$WORK" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$CONFIG_DIR/config.json" \
        "$CDM" --no-network -- sh -c "printf escaped > '$MISSING_LEAF'") >/dev/null 2>&1
    if [ $? -ne 0 ] && [ ! -e "$MISSING_LEAF" ]; then
        check "linux: missing hard-write leaf cannot be created" "blocked" "blocked"
    else
        check "linux: missing hard-write leaf cannot be created" "created" "blocked"
    fi

    (cd "$WORK" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$CONFIG_DIR/config.json" \
        "$CDM" --no-network -- sh -c \
        "mv '$WORK/future' '$WORK/future-moved' 2>/dev/null || true; mkdir -p '$WORK/future'; printf escaped > '$MISSING_LEAF'") \
        >/dev/null 2>&1
    if [ ! -e "$MISSING_LEAF" ] && [ ! -e "$WORK/future-moved/protected" ]; then
        check "linux: denied missing ancestor cannot be renamed and recreated" "blocked" "blocked"
    else
        check "linux: denied missing ancestor cannot be renamed and recreated" "escaped" "blocked"
    fi

    python3 - "$SOCKET" "$MARKER" "$READY" <<'PY' &
import os
import socket
import sys

socket_path, marker, ready = sys.argv[1:]
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(socket_path)
server.listen(1)
open(ready, "w", encoding="utf-8").close()
connection, _ = server.accept()
with connection:
    if connection.recv(1):
        open(marker, "w", encoding="utf-8").close()
PY
    DEPUTY_PID=$!
    attempts=0
    while [ ! -e "$READY" ] && [ "$attempts" -lt 100 ]; do
        sleep 0.01
        attempts=$((attempts + 1))
    done

    (cd "$WORK" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$CONFIG_DIR/config.json" \
        SSH_AUTH_SOCK="$SOCKET" "$CDM" --no-network -- python3 -c \
        'import os,socket; s=socket.socket(socket.AF_UNIX); s.connect(os.environ["SSH_AUTH_SOCK"]); s.sendall(b"x")' \
        >/dev/null 2>&1)
    sleep 0.05
    if [ ! -e "$MARKER" ]; then
        check "linux: --no-network blocks a real host Unix-socket deputy" "blocked" "blocked"
    else
        check "linux: --no-network blocks a real host Unix-socket deputy" "deputy reached" "blocked"
    fi

    (cd "$WORK" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$CONFIG_DIR/config.json" \
        "$CDM" --no-network -- sh -c \
        'test -z "$(find /run -mindepth 1 -print -quit 2>/dev/null)" && test -z "$(find /var/run -mindepth 1 -print -quit 2>/dev/null)"' \
        >/dev/null 2>&1)
    if [ $? -eq 0 ]; then
        check "linux: host /run and /var/run are synthetic and empty" "empty" "empty"
    else
        check "linux: host /run and /var/run are synthetic and empty" "host runtime exposed" "empty"
    fi

    (cd "$WORK" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$CONFIG_DIR/config.json" \
        "$CDM" --no-network --allow-rw "$SOCKET" -- true) >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        check "linux: direct Unix-socket grants fail closed" "rejected" "rejected"
    else
        check "linux: direct Unix-socket grants fail closed" "accepted" "rejected"
    fi

    kill "$DEPUTY_PID" >/dev/null 2>&1 || true
    wait "$DEPUTY_PID" >/dev/null 2>&1 || true

    ABSTRACT_NAME="cdm-deputy-$$"
    ABSTRACT_MARKER="$ROOT/abstract-deputy-reached"
    ABSTRACT_READY="$ROOT/abstract-ready"
    python3 - "$ABSTRACT_NAME" "$ABSTRACT_MARKER" "$ABSTRACT_READY" <<'PY' &
import socket
import sys

name, marker, ready = sys.argv[1:]
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind("\0" + name)
server.listen(1)
open(ready, "w", encoding="utf-8").close()
connection, _ = server.accept()
with connection:
    if connection.recv(1):
        open(marker, "w", encoding="utf-8").close()
PY
    DEPUTY_PID=$!
    attempts=0
    while [ ! -e "$ABSTRACT_READY" ] && [ "$attempts" -lt 100 ]; do
        sleep 0.01
        attempts=$((attempts + 1))
    done
    (cd "$WORK" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$CONFIG_DIR/config.json" \
        CDM_TEST_ABSTRACT_SOCKET="$ABSTRACT_NAME" "$CDM" --no-proxy -- python3 -c \
        'import os,socket; s=socket.socket(socket.AF_UNIX); s.connect("\0"+os.environ["CDM_TEST_ABSTRACT_SOCKET"]); s.sendall(b"x")' \
        >/dev/null 2>&1)
    sleep 0.05
    if [ ! -e "$ABSTRACT_MARKER" ]; then
        check "linux: direct mode blocks an abstract Unix-socket deputy" "blocked" "blocked"
    else
        check "linux: direct mode blocks an abstract Unix-socket deputy" "deputy reached" "blocked"
    fi
    (cd "$WORK" && HOME="$TEST_HOME" CDM_CONFIG_PATH="$CONFIG_DIR/config.json" \
        CDM_TEST_ABSTRACT_SOCKET="$ABSTRACT_NAME" "$CDM" --scramble -- python3 -c \
        'import os,socket; s=socket.socket(socket.AF_UNIX); s.connect("\0"+os.environ["CDM_TEST_ABSTRACT_SOCKET"]); s.sendall(b"x")' \
        >/dev/null 2>&1)
    sleep 0.05
    if [ ! -e "$ABSTRACT_MARKER" ]; then
        check "linux: proxied mode blocks an abstract Unix-socket deputy" "blocked" "blocked"
    else
        check "linux: proxied mode blocks an abstract Unix-socket deputy" "deputy reached" "blocked"
    fi
    kill "$DEPUTY_PID" >/dev/null 2>&1 || true
    wait "$DEPUTY_PID" >/dev/null 2>&1 || true
    remove_test_path "$ROOT"
fi
