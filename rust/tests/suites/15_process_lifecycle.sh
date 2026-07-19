#!/bin/bash
# Child status and normal parent cleanup after child termination.

section "Process lifecycle and cleanup"

if [ -z "$MODES" ]; then
    skip "process lifecycle" "no runnable sandbox adapter is available"
    return 0 2>/dev/null || exit 0
fi

LIFECYCLE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdm-lifecycle.XXXXXX") || {
    echo "could not create lifecycle test directory" >&2
    return 1 2>/dev/null || exit 1
}

for mode in $MODES; do
    mode_exec "$mode" --no-proxy -- sh -c 'exit 42' >/dev/null 2>&1
    RC=$?
    check_eq "$mode: ordinary nonzero child status propagates" "$RC" "42"

    MODE_FILE=$(printf '%s' "$mode" | tr '/:' '__')
    PROXY_ARGS=()
    mode_supports_proxy "$mode" && PROXY_ARGS=(--scramble)
    OUT=$(mode_exec "$mode" "${PROXY_ARGS[@]}" -- sh -c \
        'printf "%s\n" "$SSL_CERT_FILE"; kill -TERM $$' \
        2>"$LIFECYCLE_ROOT/$MODE_FILE.stderr")
    RC=$?
    CERT_PATH=$(printf '%s\n' "$OUT" | tail -1)
    check_eq "$mode: child signal maps to 128 + SIGTERM" "$RC" "143"
    if mode_supports_proxy "$mode"; then
        check_nonempty "$mode: proxied child received a CA path" "$CERT_PATH"
    else
        check_empty "$mode: direct child received no synthetic CA path" "$CERT_PATH"
    fi
    if [ "$mode" = "native" ] && mode_supports_proxy "$mode" && [ -n "$CERT_PATH" ]; then
        check_eq "$mode: proxy CA artifact is removed after child signal" \
            "$(test ! -e "$CERT_PATH"; echo $?)" "0"
        check_eq "$mode: proxy artifact directory is removed after child signal" \
            "$(test ! -d "$(dirname "$CERT_PATH")"; echo $?)" "0"
    fi

    mode_exec "$mode" "${PROXY_ARGS[@]}" -- true >/dev/null 2>&1
    check_eq "$mode: an equivalent invocation succeeds immediately after signal cleanup" "$?" "0"
done

section "Worktree cleanup after child signal"

if has_native && command -v git >/dev/null 2>&1; then
    SIGNAL_REPO=$(make_test_repo)
    (cd "$SIGNAL_REPO" && "$CDM" --no-proxy --workspace -- sh -c \
        'printf "preserved\n" > signalled.txt; kill -TERM $$') \
        >/dev/null 2>"$LIFECYCLE_ROOT/worktree-signal.stderr"
    RC=$?
    check_eq "workspace: child signal maps to 128 + SIGTERM" "$RC" "143"

    SIGNAL_BRANCH=""
    for branch in $(git -C "$SIGNAL_REPO" for-each-ref \
        --format='%(refname:short)' 'refs/heads/CDM__*'); do
        if git -C "$SIGNAL_REPO" cat-file -e "${branch}:signalled.txt" 2>/dev/null; then
            SIGNAL_BRANCH="$branch"
            break
        fi
    done
    check_nonempty "workspace: changes survive child signal" "$SIGNAL_BRANCH"
    if [ -n "$SIGNAL_BRANCH" ]; then
        check_eq "workspace: signalled result is committed" \
            "$(git -C "$SIGNAL_REPO" show "${SIGNAL_BRANCH}:signalled.txt")" "preserved"
    fi
    check_eq "workspace: signalled run leaves original checkout unchanged" \
        "$(test ! -e "$SIGNAL_REPO/signalled.txt"; echo $?)" "0"
    check_eq "workspace: signalled run removes temporary worktree" \
        "$(git -C "$SIGNAL_REPO" worktree list --porcelain | grep -c '^worktree ')" "1"
    remove_test_path "$SIGNAL_REPO"
else
    skip "workspace cleanup after child signal" "native sandbox or git is unavailable"
fi

section "Parent-targeted signal forwarding"

for signal_mode in native vm; do
    if { [ "$signal_mode" = native ] && ! has_native; } || \
       { [ "$signal_mode" = vm ] && ! has_vm; }; then
        skip "$signal_mode: parent-targeted signal forwarding" "adapter is unavailable"
        continue
    fi
    SIGNAL_ROOT="$LIFECYCLE_ROOT/cdm-$signal_mode-signal"
    mkdir -p "$SIGNAL_ROOT"
    VM_ARG=()
    [ "$signal_mode" = vm ] && VM_ARG=(--vm)
    (
        cd "$SIGNAL_ROOT" || exit 125
        exec "$CDM" "${VM_ARG[@]}" --no-proxy -- sh -c \
            '(trap '\''printf live > probe'\'' USR1; while :; do sleep 1; done) & printf "%s\n" "$!" > child.pid; printf ready > ready; wait'
    ) >"$LIFECYCLE_ROOT/$signal_mode-parent-signal.stdout" \
      2>"$LIFECYCLE_ROOT/$signal_mode-parent-signal.stderr" &
    CDM_PID=$!
    READY=0
    for _ in $(seq 1 200); do
        if [ -f "$SIGNAL_ROOT/ready" ]; then
            READY=1
            break
        fi
        sleep 0.05
    done
    check_eq "$signal_mode: child became ready before parent signal" "$READY" "1"
    kill -TERM "$CDM_PID" 2>/dev/null
    wait "$CDM_PID"
    RC=$?
    check_eq "$signal_mode: parent-targeted SIGTERM maps to 143" "$RC" "143"

    if [ "$signal_mode" = native ]; then
        CHILD_PID=$(cat "$SIGNAL_ROOT/child.pid" 2>/dev/null)
        if [ -n "$CHILD_PID" ]; then
            kill -USR1 "$CHILD_PID" 2>/dev/null
            sleep 0.05
            check_eq "native: forwarded signal leaves no executable descendant" \
                "$(test ! -e "$SIGNAL_ROOT/probe"; echo $?)" "0"
        else
            check_nonempty "native: child pid was captured" "$CHILD_PID"
        fi
    fi
    mode_exec "$signal_mode" --no-proxy -- true >/dev/null 2>&1
    check_eq "$signal_mode: immediate reuse succeeds after parent-targeted signal" "$?" "0"
done

section "Session-escape containment"

if [ "$(uname -s)" = "Linux" ] && has_native && command -v python3 >/dev/null 2>&1; then
    ESCAPE_ROOT="$LIFECYCLE_ROOT/cdm-setsid-double-fork"
    mkdir -p "$ESCAPE_ROOT"
    cat >"$ESCAPE_ROOT/double_fork.py" <<'PY'
import os
import time

ready_read, ready_write = os.pipe()
if os.fork():
    os.close(ready_write)
    os.read(ready_read, 1)
    os._exit(0)
os.close(ready_read)
os.setsid()
if os.fork():
    os._exit(0)
with open("heartbeat", "ab", buffering=0) as heartbeat:
    heartbeat.write(b"1")
    os.write(ready_write, b"1")
    os.close(ready_write)
    while True:
        heartbeat.write(b"1")
        time.sleep(0.05)
PY
    (
        cd "$ESCAPE_ROOT" || exit 125
        "$CDM" --no-proxy -- python3 double_fork.py
    ) >"$LIFECYCLE_ROOT/session-escape.stdout" \
      2>"$LIFECYCLE_ROOT/session-escape.stderr"
    RC=$?
    check_eq "native: setsid double-fork invocation returns normally" "$RC" "0"
    if [ -f "$ESCAPE_ROOT/heartbeat" ]; then
        BEFORE=$(wc -c <"$ESCAPE_ROOT/heartbeat" | tr -d ' ')
        sleep 0.2
        AFTER=$(wc -c <"$ESCAPE_ROOT/heartbeat" | tr -d ' ')
        check_eq "native: setsid double-fork cannot outlive cleanup" "$AFTER" "$BEFORE"
    else
        check_eq "native: setsid double-fork produced readiness heartbeat" "missing" "present"
    fi
else
    skip "session-escape containment" "requires Linux Bubblewrap and python3"
fi

remove_test_path "$LIFECYCLE_ROOT"
