#!/bin/bash
# CDM Integration Tests: deny-first macOS security mode
# Helpers inherited from integration.sh runner

section "Secure mode"

if [ "$(uname -s)" != "Darwin" ] || ! has_native; then
    skip "secure mode" "native macOS Seatbelt is unavailable"
else
    ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdm_secure_test.XXXXXX")
    WORK="$ROOT/work"
    OUTSIDE="$ROOT/outside"
    mkdir -p "$WORK" "$OUTSIDE"
    echo readable > "$OUTSIDE/readable.txt"
    echo preserve > "$OUTSIDE/preserve.txt"

    OUT=$(cd "$WORK" && "$CDM" --sec --no-proxy -- /bin/echo secure 2>/dev/null)
    check "secure: ordinary CLI command runs" "$OUT" "secure"

    (cd "$WORK" && "$CDM" --sec --no-proxy -- /bin/sh -c 'echo created > created.txt') >/dev/null 2>&1
    check "secure: workspace remains writable" "$(cat "$WORK/created.txt" 2>/dev/null)" "created"

    printf 'original\n' > "$WORK/.mcp.json"
    mkdir -p "$WORK/.scratch/worktrees/child"
    printf 'nested-original\n' > "$WORK/.scratch/worktrees/child/.mcp.json"
    (cd "$WORK" && "$CDM" --no-proxy -- /bin/sh -c 'printf normal > .mcp.json') >/dev/null 2>&1
    check "normal: active .mcp.json follows RW workspace policy" "$(cat "$WORK/.mcp.json")" "normal"
    (cd "$WORK" && "$CDM" --sec --no-proxy -- /bin/sh -c 'printf secure > .mcp.json') >/dev/null 2>&1
    check "secure: active .mcp.json is protected" "$(cat "$WORK/.mcp.json")" "normal"
    (cd "$WORK" && "$CDM" --sec --no-proxy -- /bin/sh -c \
        'printf nested-secure > .scratch/worktrees/child/.mcp.json') >/dev/null 2>&1
    check "secure: protected basenames are not recursive across nested worktrees" \
        "$(cat "$WORK/.scratch/worktrees/child/.mcp.json")" "nested-secure"

    /usr/bin/git -C "$WORK" init -q
    /usr/bin/git -C "$WORK" config user.name "CDM Test"
    /usr/bin/git -C "$WORK" config user.email "cdm-test@example.invalid"
    /usr/bin/git -C "$WORK" add .
    /usr/bin/git -C "$WORK" commit -q -m initial
    (cd "$WORK" && "$CDM" --sec --no-proxy -- /usr/bin/git worktree add \
        .scratch/worktrees/materialized -b cdm-secure-worktree-test HEAD) >/dev/null 2>&1
    if [ $? -eq 0 ] && [ -e "$WORK/.scratch/worktrees/materialized/.mcp.json" ]; then
        check "secure: git worktree materializes tracked .mcp.json" "materialized" "materialized"
    else
        check "secure: git worktree materializes tracked .mcp.json" "blocked" "materialized"
    fi
    /usr/bin/git -C "$WORK" worktree remove --force .scratch/worktrees/materialized >/dev/null 2>&1 || true
    /usr/bin/git -C "$WORK" branch -D cdm-secure-worktree-test >/dev/null 2>&1 || true

    OUT=$(cd "$WORK" && "$CDM" --sec --no-proxy -- /bin/cat "$OUTSIDE/readable.txt" 2>/dev/null)
    check "secure: host reads retain compatibility" "$OUT" "readable"

    (cd "$WORK" && "$CDM" --sec --no-proxy -- /bin/sh -c "echo changed > '$OUTSIDE/preserve.txt'") >/dev/null 2>&1
    check "secure: outside writes remain blocked" "$(cat "$OUTSIDE/preserve.txt")" "preserve"

    PROFILE=$(cd "$WORK" && CDM_DEBUG=1 "$CDM" --sec --no-proxy -- /usr/bin/true 2>&1)
    check "secure: profile is deny-first" "$PROFILE" "(deny default)"
    check_not "secure: profile does not allow Mach registration" "$PROFILE" "(allow mach-register"
    check_not "secure: profile does not allow Mach extension issuance" "$PROFILE" "(allow mach-issue-extension"

    if /usr/bin/mdls /etc/hosts 2>&1 | grep -Fq "kMDItem"; then
        OUT=$(cd "$WORK" && "$CDM" --sec --no-proxy -- /usr/bin/mdls /etc/hosts 2>&1)
        if [ $? -ne 0 ] && echo "$OUT" | grep -Fqi "could not find"; then
            check "secure: non-baseline Spotlight Mach service is blocked" "blocked" "blocked"
        else
            check "secure: non-baseline Spotlight Mach service is blocked" "unexpectedly allowed" "blocked"
        fi
    else
        skip "secure: non-baseline Spotlight Mach service is blocked" "Spotlight metadata probe unavailable"
    fi

    remove_test_path "$ROOT"
fi
