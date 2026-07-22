#!/bin/bash
# CDM Integration Tests: real Git-worktree user journeys.
# Helpers inherited from integration.sh runner.

cdm_branches() {
    git -C "$1" for-each-ref --format='%(refname:short)' 'refs/heads/CDM__*'
}

worktree_count() {
    git -C "$1" worktree list --porcelain | grep -c '^worktree '
}

branch_with_path() {
    local repo="$1" path="$2" branch
    for branch in $(cdm_branches "$repo"); do
        if git -C "$repo" cat-file -e "${branch}:${path}" 2>/dev/null; then
            printf '%s\n' "$branch"
            return 0
        fi
    done
    return 1
}

section "Worktree (native lifecycle)"

if has_native; then
    WS_REPO=$(make_test_repo)
    ORIGINAL_HEAD=$(git -C "$WS_REPO" rev-parse HEAD)
    ORIGINAL_BRANCH=$(git -C "$WS_REPO" branch --show-current)

    (cd "$WS_REPO" && "$CDM" --no-proxy --worktree sh -c \
        'printf "changed\n" >> file.txt; mkdir -p output; printf "first\n" > output/result.txt') \
        >/dev/null 2>"$WS_REPO/first.stderr"
    STATUS=$?
    FIRST_BRANCH=$(branch_with_path "$WS_REPO" output/result.txt || true)

    check_eq "ws/native: successful command exit status" "$STATUS" "0"
    check_eq "ws/native: original branch remains checked out" \
        "$(git -C "$WS_REPO" branch --show-current)" "$ORIGINAL_BRANCH"
    check_eq "ws/native: original tracked file is unchanged" \
        "$(cat "$WS_REPO/file.txt")" "original"
    check_eq "ws/native: generated file is absent from original" \
        "$(test ! -e "$WS_REPO/output/result.txt"; echo $?)" "0"
    check_eq "ws/native: result is committed on a CDM branch" \
        "$(git -C "$WS_REPO" show "${FIRST_BRANCH}:output/result.txt" 2>/dev/null)" "first"
    check_eq "ws/native: branch commit is based on original HEAD" \
        "$(git -C "$WS_REPO" rev-parse "${FIRST_BRANCH}^")" "$ORIGINAL_HEAD"
    check_eq "ws/native: ephemeral worktree is removed" "$(worktree_count "$WS_REPO")" "1"
    check "ws/native: completion tree names saved branch" \
        "$(cat "$WS_REPO/first.stderr")" "│  ├─ Branch:           \`$FIRST_BRANCH\`"
    check "ws/native: completion tree reports changes" \
        "$(cat "$WS_REPO/first.stderr")" '│  └─ Changes:          "2 files"'
    check "ws/native: completion tree includes inspect action" \
        "$(cat "$WS_REPO/first.stderr")" '├─ Inspect:          `git diff'
    check "ws/native: completion tree includes discard action" \
        "$(cat "$WS_REPO/first.stderr")" '└─ Discard:          `git branch -D'

    # A second session on the same day must not collide with the first branch.
    (cd "$WS_REPO" && "$CDM" --no-proxy --worktree sh -c \
        'printf "second\n" > second.txt') >/dev/null 2>"$WS_REPO/second.stderr"
    STATUS=$?
    SECOND_BRANCH=$(branch_with_path "$WS_REPO" second.txt || true)
    check_eq "ws/native: repeated session succeeds" "$STATUS" "0"
    check_eq "ws/native: repeated session creates another branch" \
        "$(cdm_branches "$WS_REPO" | wc -l | tr -d ' ')" "2"
    check_eq "ws/native: repeated session uses a unique branch" \
        "$(test "$SECOND_BRANCH" != "$FIRST_BRANCH"; echo $?)" "0"
    check_eq "ws/native: repeated result is committed" \
        "$(git -C "$WS_REPO" show "${SECOND_BRANCH}:second.txt" 2>/dev/null)" "second"
    check_eq "ws/native: repeated session leaves no worktree" "$(worktree_count "$WS_REPO")" "1"

    # Starting below the repository root should preserve the relative cwd.
    mkdir -p "$WS_REPO/src/nested"
    printf 'nested\n' > "$WS_REPO/src/nested/input.txt"
    git -C "$WS_REPO" add src/nested/input.txt
    git -C "$WS_REPO" commit -q -m 'add nested fixture'
    (cd "$WS_REPO/src/nested" && "$CDM" --no-proxy --worktree sh -c \
        'test "$(basename "$PWD")" = nested && cat input.txt && printf "nested-output\n" > result.txt') \
        >"$WS_REPO/nested.stdout" 2>"$WS_REPO/nested.stderr"
    STATUS=$?
    NESTED_BRANCH=$(branch_with_path "$WS_REPO" src/nested/result.txt || true)
    check_eq "ws/native: nested invocation preserves relative cwd" "$STATUS" "0"
    check "ws/native: nested invocation sees local files" \
        "$(cat "$WS_REPO/nested.stdout")" "nested"
    check_eq "ws/native: nested output is committed at the same relative path" \
        "$(git -C "$WS_REPO" show "${NESTED_BRANCH}:src/nested/result.txt" 2>/dev/null)" \
        "nested-output"
    check_eq "ws/native: nested session leaves no worktree" "$(worktree_count "$WS_REPO")" "1"

    # Command failures still preserve useful changes and propagate the command status.
    (cd "$WS_REPO" && "$CDM" --no-proxy --worktree sh -c \
        'printf "failure-artifact\n" > failure.txt; exit 23') >/dev/null 2>"$WS_REPO/failure.stderr"
    STATUS=$?
    FAILURE_BRANCH=$(branch_with_path "$WS_REPO" failure.txt || true)
    check_eq "ws/native: command failure status propagates" "$STATUS" "23"
    check_eq "ws/native: changes from failed command are preserved" \
        "$(git -C "$WS_REPO" show "${FAILURE_BRANCH}:failure.txt" 2>/dev/null)" \
        "failure-artifact"
    check_eq "ws/native: failed command leaves no worktree" "$(worktree_count "$WS_REPO")" "1"

    # Exercise the no-op journey in a clean repository. Earlier assertions
    # deliberately capture diagnostics in the fixture repository, and those
    # untracked captures are real workspace input rather than a no-op.
    remove_test_path "$WS_REPO"
    WS_REPO=$(make_test_repo)
    BRANCH_COUNT=$(cdm_branches "$WS_REPO" | wc -l | tr -d ' ')
    NO_CHANGES_STDERR=$(mktemp "${TMPDIR:-/tmp}/cdm-ws-no-changes.XXXXXX")
    (cd "$WS_REPO" && "$CDM" --no-proxy --worktree true) \
        >/dev/null 2>"$NO_CHANGES_STDERR"
    STATUS=$?
    check_eq "ws/native: no-change session succeeds" "$STATUS" "0"
    check_eq "ws/native: no-change session creates no branch" \
        "$(cdm_branches "$WS_REPO" | wc -l | tr -d ' ')" "$BRANCH_COUNT"
    check_eq "ws/native: no-change session leaves no worktree" "$(worktree_count "$WS_REPO")" "1"
    check "ws/native: no-change completion tree confirms cleanup" \
        "$(cat "$NO_CHANGES_STDERR")" '└─ Result:           "clean"      Temporary worktree removed'
    remove_test_path "$NO_CHANGES_STDERR"

    remove_test_path "$WS_REPO"

    # Quiet mode suppresses setup and completion status without discarding the
    # result branch.
    WS_REPO=$(make_test_repo)
    QUIET_STDERR=$(mktemp "${TMPDIR:-/tmp}/cdm-ws-quiet.XXXXXX")
    (cd "$WS_REPO" && "$CDM" --quiet --no-proxy --worktree sh -c \
        'printf "quiet-result\n" > quiet.txt') >/dev/null 2>"$QUIET_STDERR"
    STATUS=$?
    QUIET_BRANCH=$(branch_with_path "$WS_REPO" quiet.txt || true)
    check_eq "ws/native: quiet worktree session succeeds" "$STATUS" "0"
    check_nonempty "ws/native: quiet worktree still saves a result branch" "$QUIET_BRANCH"
    check_empty "ws/native: quiet worktree suppresses all routine status" \
        "$(cat "$QUIET_STDERR")"
    check_eq "ws/native: quiet worktree leaves no temporary worktree" \
        "$(worktree_count "$WS_REPO")" "1"
    remove_test_path "$QUIET_STDERR" "$WS_REPO"

    # Repository Git metadata, config, environment, and PATH are all hostile
    # inputs. They must not turn trusted post-sandbox finalization into code
    # execution or let the child redirect the worktree Git control plane.
    WS_REPO=$(make_test_repo)
    mkdir -p "$WS_REPO/hostile-hooks" "$WS_REPO/env-hooks" "$WS_REPO/fake-bin"
    HOOK_MARKER="$WS_REPO/hook-fired"
    ENV_MARKER="$WS_REPO/env-hook-fired"
    FILTER_MARKER="$WS_REPO/filter-fired"
    SIGN_MARKER="$WS_REPO/signing-fired"
    PATH_MARKER="$WS_REPO/path-git-fired"
    cat >"$WS_REPO/hostile-hooks/pre-commit" <<EOF
#!/bin/sh
printf fired > '$HOOK_MARKER'
exit 81
EOF
    cat >"$WS_REPO/env-hooks/pre-commit" <<EOF
#!/bin/sh
printf fired > '$ENV_MARKER'
exit 82
EOF
    cat >"$WS_REPO/hostile-filter" <<EOF
#!/bin/sh
printf fired > '$FILTER_MARKER'
cat
exit 83
EOF
    cat >"$WS_REPO/fake-bin/git" <<EOF
#!/bin/sh
printf fired > '$PATH_MARKER'
exec /usr/bin/git "\$@"
EOF
    cat >"$WS_REPO/hostile-signer" <<EOF
#!/bin/sh
printf fired > '$SIGN_MARKER'
exit 84
EOF
    chmod +x "$WS_REPO/hostile-hooks/pre-commit" "$WS_REPO/env-hooks/pre-commit" \
        "$WS_REPO/hostile-filter" "$WS_REPO/hostile-signer" "$WS_REPO/fake-bin/git"
    printf '*.victim filter=hostile\n' > "$WS_REPO/.gitattributes"
    printf 'raw-tracked\n' > "$WS_REPO/tracked.victim"
    git -C "$WS_REPO" add .gitattributes tracked.victim
    git -C "$WS_REPO" commit -q -m 'add hostile-filter fixture'
    git -C "$WS_REPO" config core.hooksPath "$WS_REPO/hostile-hooks"
    git -C "$WS_REPO" config filter.hostile.clean "$WS_REPO/hostile-filter"
    git -C "$WS_REPO" config filter.hostile.smudge "$WS_REPO/hostile-filter"
    git -C "$WS_REPO" config commit.gpgSign true
    git -C "$WS_REPO" config gpg.program "$WS_REPO/hostile-signer"

    (cd "$WS_REPO" && \
        PATH="$WS_REPO/fake-bin:$PATH" \
        GIT_CONFIG_COUNT=1 \
        GIT_CONFIG_KEY_0=core.hooksPath \
        GIT_CONFIG_VALUE_0="$WS_REPO/env-hooks" \
        "$CDM" --no-proxy --worktree sh -c '
            gitdir=$(sed -n "s/^gitdir: //p" .git)
            common=$(cd "$gitdir" && cd "$(cat commondir)" && pwd -P)
            if printf redirected > .git 2>/dev/null; then exit 91; fi
            if printf poisoned > "$gitdir/config" 2>/dev/null; then exit 92; fi
            if printf poisoned > "$common/config" 2>/dev/null; then exit 93; fi
            printf unfiltered > result.victim
        ') >/dev/null 2>"$WS_REPO/hostile.stderr"
    STATUS=$?
    HOSTILE_BRANCH=$(branch_with_path "$WS_REPO" result.victim || true)
    check_eq "ws/security: hostile metadata/config/env/PATH journey succeeds safely" "$STATUS" "0"
    check_eq "ws/security: repository hook never runs" "$(test ! -e "$HOOK_MARKER"; echo $?)" "0"
    check_eq "ws/security: environment-injected hook never runs" "$(test ! -e "$ENV_MARKER"; echo $?)" "0"
    check_eq "ws/security: clean filter never runs" "$(test ! -e "$FILTER_MARKER"; echo $?)" "0"
    check_eq "ws/security: signing helper never runs" "$(test ! -e "$SIGN_MARKER"; echo $?)" "0"
    check_eq "ws/security: PATH Git replacement is not trusted" "$(test ! -e "$PATH_MARKER"; echo $?)" "0"
    check_eq "ws/security: raw child bytes are committed without filters" \
        "$(git -C "$WS_REPO" show "${HOSTILE_BRANCH}:result.victim" 2>/dev/null)" "unfiltered"
    check_eq "ws/security: worktree control file remains protected" \
        "$(worktree_count "$WS_REPO")" "1"
    remove_test_path "$WS_REPO"

    # An isolated child may create a symlink naming a host path it cannot read.
    # Trusted finalization must record the link itself without following it.
    WS_REPO=$(make_test_repo)
    mkdir -p "$WS_REPO/tracked"
    printf 'tracked-first\n' > "$WS_REPO/tracked/first.txt"
    printf 'tracked-second\n' > "$WS_REPO/tracked/second.txt"
    git -C "$WS_REPO" add tracked
    git -C "$WS_REPO" commit -q -m 'add symlink replacement fixture'
    OUTSIDE=$(mktemp -d "${TMPDIR:-/tmp}/cdm-worktree-outside.XXXXXX")
    printf 'outside-secret-sentinel\n' > "$OUTSIDE/first.txt"
    printf 'another-outside-sentinel\n' > "$OUTSIDE/second.txt"
    (cd "$WS_REPO" && OUTSIDE="$OUTSIDE" "$CDM" --no-proxy --iso --worktree sh -c '
        test ! -r "$OUTSIDE/first.txt"
        command -p rm -rf -- tracked
        ln -s "$OUTSIDE" tracked
    ') >/dev/null 2>"$WS_REPO/symlink.stderr"
    STATUS=$?
    SYMLINK_BRANCH=$(branch_with_path "$WS_REPO" tracked || true)
    SYMLINK_MODE=$(git -C "$WS_REPO" ls-tree "$SYMLINK_BRANCH" -- tracked | awk '{print $1}')
    check_eq "ws/security: isolated ancestor-symlink journey succeeds" "$STATUS" "0"
    check_eq "ws/security: directory replacement is one Git symlink" "$SYMLINK_MODE" "120000"
    check_eq "ws/security: finalizer does not commit outside descendant bytes" \
        "$(if git -C "$WS_REPO" cat-file -e "${SYMLINK_BRANCH}:tracked/first.txt" 2>/dev/null; then echo 0; else echo 1; fi)" \
        "1"
    check_eq "ws/security: finalizer records the link target bytes" \
        "$(git -C "$WS_REPO" show "${SYMLINK_BRANCH}:tracked" 2>/dev/null)" "$OUTSIDE"
    check_eq "ws/security: ancestor-symlink session leaves no worktree" \
        "$(worktree_count "$WS_REPO")" "1"
    remove_test_path "$OUTSIDE"
    remove_test_path "$WS_REPO"

    # The isolated copy should represent the user's current Git-visible work,
    # not silently fall back to a stale HEAD when tracked/untracked edits exist.
    WS_REPO=$(make_test_repo)
    printf 'original\ndirty-tracked\n' > "$WS_REPO/file.txt"
    printf 'dirty-untracked\n' > "$WS_REPO/untracked.txt"
    (cd "$WS_REPO" && "$CDM" --no-proxy --worktree sh -c \
        'grep -q dirty-tracked file.txt && grep -q dirty-untracked untracked.txt && printf "agent\n" > agent.txt') \
        >/dev/null 2>"$WS_REPO/dirty.stderr"
    STATUS=$?
    DIRTY_BRANCH=$(branch_with_path "$WS_REPO" agent.txt || true)
    check_eq "ws/native: dirty-worktree journey succeeds" "$STATUS" "0"
    check "ws/native: original tracked edit remains untouched" \
        "$(cat "$WS_REPO/file.txt")" "dirty-tracked"
    check_eq "ws/native: original untracked file remains untouched" \
        "$(cat "$WS_REPO/untracked.txt")" "dirty-untracked"
    check "ws/native: result branch includes initial tracked edit" \
        "$(git -C "$WS_REPO" show "${DIRTY_BRANCH}:file.txt" 2>/dev/null)" "dirty-tracked"
    check_eq "ws/native: result branch includes initial untracked file" \
        "$(git -C "$WS_REPO" show "${DIRTY_BRANCH}:untracked.txt" 2>/dev/null)" \
        "dirty-untracked"
    check_eq "ws/native: result branch includes agent output" \
        "$(git -C "$WS_REPO" show "${DIRTY_BRANCH}:agent.txt" 2>/dev/null)" "agent"
    check_eq "ws/native: dirty session leaves no worktree" "$(worktree_count "$WS_REPO")" "1"
    remove_test_path "$WS_REPO"

    # Sparse entries absent from the caller must remain absent in the isolated
    # workspace without becoming deletions in an otherwise unchanged result.
    WS_REPO=$(make_test_repo)
    mkdir -p "$WS_REPO/included" "$WS_REPO/excluded"
    printf 'included\n' > "$WS_REPO/included/file.txt"
    printf 'excluded\n' > "$WS_REPO/excluded/file.txt"
    git -C "$WS_REPO" add included excluded
    git -C "$WS_REPO" commit -q -m 'add sparse fixture'
    git -C "$WS_REPO" sparse-checkout init --cone
    git -C "$WS_REPO" sparse-checkout set included
    SPARSE_BRANCH_COUNT=$(cdm_branches "$WS_REPO" | wc -l | tr -d ' ')
    (cd "$WS_REPO" && "$CDM" --no-proxy --worktree sh -c \
        'test -f included/file.txt && test ! -e excluded/file.txt') \
        >/dev/null 2>"$WS_REPO/sparse.stderr"
    STATUS=$?
    check_eq "ws/native: sparse checkout preserves included/absent paths" "$STATUS" "0"
    check_eq "ws/native: sparse absence does not create a result branch" \
        "$(cdm_branches "$WS_REPO" | wc -l | tr -d ' ')" "$SPARSE_BRANCH_COUNT"
    check_eq "ws/native: sparse session leaves no worktree" "$(worktree_count "$WS_REPO")" "1"
    remove_test_path "$WS_REPO"

    # Branch allocation must also be safe when two agents start before either
    # session has finalized.
    WS_REPO=$(make_test_repo)
    (cd "$WS_REPO" && "$CDM" --no-proxy --worktree sh -c \
        'sleep 1; printf "parallel-one\n" > parallel-one.txt') \
        >/dev/null 2>"$WS_REPO/parallel-one.stderr" &
    PID_ONE=$!
    (cd "$WS_REPO" && "$CDM" --no-proxy --worktree sh -c \
        'sleep 1; printf "parallel-two\n" > parallel-two.txt') \
        >/dev/null 2>"$WS_REPO/parallel-two.stderr" &
    PID_TWO=$!
    wait "$PID_ONE"; STATUS_ONE=$?
    wait "$PID_TWO"; STATUS_TWO=$?
    PARALLEL_ONE_BRANCH=$(branch_with_path "$WS_REPO" parallel-one.txt || true)
    PARALLEL_TWO_BRANCH=$(branch_with_path "$WS_REPO" parallel-two.txt || true)
    check_eq "ws/native: first concurrent session succeeds" "$STATUS_ONE" "0"
    check_eq "ws/native: second concurrent session succeeds" "$STATUS_TWO" "0"
    check_eq "ws/native: concurrent sessions use distinct branches" \
        "$(test "$PARALLEL_ONE_BRANCH" != "$PARALLEL_TWO_BRANCH"; echo $?)" "0"
    check_eq "ws/native: first concurrent result is committed" \
        "$(git -C "$WS_REPO" show "${PARALLEL_ONE_BRANCH}:parallel-one.txt" 2>/dev/null)" \
        "parallel-one"
    check_eq "ws/native: second concurrent result is committed" \
        "$(git -C "$WS_REPO" show "${PARALLEL_TWO_BRANCH}:parallel-two.txt" 2>/dev/null)" \
        "parallel-two"
    check_eq "ws/native: concurrent sessions leave no worktrees" "$(worktree_count "$WS_REPO")" "1"
    remove_test_path "$WS_REPO"
else
    skip "workspace/native" "host cannot launch the native sandbox adapter"
fi

echo ""

if has_vm; then
    section "Worktree + VM lifecycle"

    WS_REPO=$(make_test_repo)
    ORIGINAL_HEAD=$(git -C "$WS_REPO" rev-parse HEAD)
    (cd "$WS_REPO" && "$CDM" --no-proxy --worktree --vm sh -c \
        'cat file.txt; if printf "tampered\n" > .git 2>/dev/null; then exit 90; fi; mkdir -p vm-output; printf "vm-change\n" > vm-output/result.txt') \
        >"$WS_REPO/vm.stdout" 2>"$WS_REPO/vm.stderr"
    STATUS=$?
    VM_BRANCH=$(branch_with_path "$WS_REPO" vm-output/result.txt || true)
    check_eq "ws/vm: combined journey succeeds" "$STATUS" "0"
    check "ws/vm: guest reads committed workspace" "$(cat "$WS_REPO/vm.stdout")" "original"
    check_eq "ws/vm: original repository remains unchanged" \
        "$(test ! -e "$WS_REPO/vm-output/result.txt"; echo $?)" "0"
    check_eq "ws/vm: guest output is committed to branch" \
        "$(git -C "$WS_REPO" show "${VM_BRANCH}:vm-output/result.txt" 2>/dev/null)" \
        "vm-change"
    check_eq "ws/vm: branch is based on original HEAD" \
        "$(git -C "$WS_REPO" rev-parse "${VM_BRANCH}^")" "$ORIGINAL_HEAD"
    check_eq "ws/vm: ephemeral worktree is removed" "$(worktree_count "$WS_REPO")" "1"
    remove_test_path "$WS_REPO"

    if [ "${CDM_OCI_TESTS:-0}" = "1" ]; then
        WS_REPO=$(make_test_repo)
        (cd "$WS_REPO" && "$CDM" --no-proxy --worktree --vmi alpine:3.21 sh -c \
            'printf "oci-change\n" > oci.txt') >/dev/null 2>"$WS_REPO/oci.stderr"
        STATUS=$?
        OCI_BRANCH=$(branch_with_path "$WS_REPO" oci.txt || true)
        check_eq "ws/vmi: combined journey succeeds" "$STATUS" "0"
        check_eq "ws/vmi: guest output is committed" \
            "$(git -C "$WS_REPO" show "${OCI_BRANCH}:oci.txt" 2>/dev/null)" "oci-change"
        check_eq "ws/vmi: ephemeral worktree is removed" "$(worktree_count "$WS_REPO")" "1"
        remove_test_path "$WS_REPO"
    fi

    echo ""
fi
