#!/bin/bash
# Schema-versioned reports and stderr-only compact statistics.

section "Structured reporting"

REPORT_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdm-reporting.XXXXXX")

SENTINEL="$REPORT_ROOT/sentinel"
printf 'untouched\n' > "$SENTINEL"
ln -s "$SENTINEL" "$REPORT_ROOT/symlink-report.json"
"$CDM" --no-network --report-json "$REPORT_ROOT/symlink-report.json" true \
    >"$REPORT_ROOT/symlink.stdout" 2>"$REPORT_ROOT/symlink.stderr"
RC=$?
check_eq "report: symlink destination is rejected before sandbox startup" "$RC" "2"
check_eq "report: symlink target remains untouched" "$(cat "$SENTINEL")" "untouched"

VALIDATION_REPORT="$REPORT_ROOT/validation.json"
"$CDM" --report-json "$VALIDATION_REPORT" -- sudo true \
    >"$REPORT_ROOT/validation.stdout" 2>"$REPORT_ROOT/validation.stderr"
RC=$?
check_eq "report: guard failure keeps its validation status" "$RC" "2"
VALIDATION_RESULT=$(python3 - "$VALIDATION_REPORT" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["policy"] is None
assert value["outcome"]["child"] == {
    "status": "launch_failed",
    "stage": "validation",
}
assert any(
    event.get("phase") == "validation" and event.get("state") == "failed"
    for event in value["events"]
)
print("ok")
PY
)
check_eq "report: early validation failure is published honestly" "$VALIDATION_RESULT" "ok"

printf '{ malformed report test config' > "$REPORT_ROOT/malformed-config.json"
CONFIG_REPORT="$REPORT_ROOT/config-validation.json"
CDM_CONFIG_PATH="$REPORT_ROOT/malformed-config.json" \
    "$CDM" --report-json "$CONFIG_REPORT" true \
    >"$REPORT_ROOT/config-validation.stdout" 2>"$REPORT_ROOT/config-validation.stderr"
RC=$?
check_eq "report: malformed config keeps its validation status" "$RC" "2"
CONFIG_RESULT=$(python3 - "$CONFIG_REPORT" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["policy"] is None
assert value["outcome"]["child"] == {
    "status": "launch_failed",
    "stage": "validation",
}
print("ok")
PY
)
check_eq "report: config validation failure is published" "$CONFIG_RESULT" "ok"

WORKTREE_REPORT="$REPORT_ROOT/worktree-setup.json"
(cd "$REPORT_ROOT" && "$CDM" --no-network --workspace \
    --report-json "$WORKTREE_REPORT" true) \
    >"$REPORT_ROOT/worktree-setup.stdout" 2>"$REPORT_ROOT/worktree-setup.stderr"
RC=$?
check_eq "report: worktree setup failure remains nonzero" "$RC" "1"
WORKTREE_RESULT=$(python3 - "$WORKTREE_REPORT" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["outcome"]["child"] == {"status": "launch_failed", "stage": "setup"}
assert value["outcome"]["worktree"] == {"status": "failed", "stage": "setup"}
print("ok")
PY
)
check_eq "report: worktree setup failure has typed outcomes" "$WORKTREE_RESULT" "ok"

if [ -z "$MODES" ]; then
    skip "structured reporting runtime journeys" "no runnable sandbox adapter is available"
    remove_test_path "$REPORT_ROOT"
    return 0 2>/dev/null || exit 0
fi

for mode in $MODES; do
    MODE_FILE=$(printf '%s' "$mode" | tr '/:' '__')
    REPORT="$REPORT_ROOT/$MODE_FILE.json"
    STDOUT_FILE="$REPORT_ROOT/$MODE_FILE.stdout"
    STDERR_FILE="$REPORT_ROOT/$MODE_FILE.stderr"
    CDM_TEST_CAPTURE_STDERR=1 REPORT_TEST_TOKEN="cdm-report-secret-1234567890" \
        mode_exec "$mode" --no-network --report-json "$REPORT" --stats -- \
        sh -c 'printf "child-stdout\n"; exit 23' \
        >"$STDOUT_FILE" 2>"$STDERR_FILE"
    RC=$?

    check_eq "$mode report: child status is preserved" "$RC" "23"
    check_eq "$mode report: child stdout is untouched" "$(cat "$STDOUT_FILE")" "child-stdout"
    check "$mode report: stats are written to stderr" "$(cat "$STDERR_FILE")" "[cdm] stats:"
    check_eq "$mode report: JSON file exists" "$(test -f "$REPORT"; echo $?)" "0"

    if [ -f "$REPORT" ]; then
        case "$(uname -s)" in
            Darwin) MODE_BITS=$(stat -f '%Lp' "$REPORT") ;;
            *) MODE_BITS=$(stat -c '%a' "$REPORT") ;;
        esac
        check_eq "$mode report: JSON file is private" "$MODE_BITS" "600"

        JSON_RESULT=$(python3 - "$REPORT" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["schema_version"] == 1
assert value["outcome"]["child"] == {"status": "exited", "code": 23}
assert value["outcome"]["cleanup"]["status"] == "succeeded"
assert value["execution"]["argument_count"] == 3
assert value["policy"]["coverage"]["filesystem"]["observation"] == "not_instrumented"
assert "command" not in value["execution"]
assert any(
    event.get("phase") == "child" and event.get("state") == "failed"
    for event in value["events"]
)
assert any(
    event.get("phase") == "cleanup" and event.get("state") == "succeeded"
    for event in value["events"]
)
assert set(value["counters"]["proxy"]) >= {
    "bytes_from_child",
    "bytes_to_upstream",
    "bytes_from_upstream",
    "bytes_to_child",
}
print("ok")
PY
        )
        check_eq "$mode report: schema and outcomes are machine-readable" "$JSON_RESULT" "ok"
        check_not "$mode report: known secret is absent" "$(cat "$REPORT")" "cdm-report-secret-1234567890"
        check_not "$mode report: argv values are absent" "$(cat "$REPORT")" "child-stdout"
    fi

    if mode_supports_proxy "$mode" && command -v curl >/dev/null 2>&1; then
        PROXY_REPORT="$REPORT_ROOT/$MODE_FILE-proxy.json"
        case "$mode" in
            native) BLOCKED_REQUEST='curl --max-time 3 --fail http://blocked.invalid/ >/dev/null 2>&1 || :' ;;
            vm|vmi/*) BLOCKED_REQUEST='wget -qO- -T 3 -Y on http://blocked.invalid/ >/dev/null 2>&1 || :' ;;
        esac
        mode_exec "$mode" --scramble --allow-domains allowed.invalid --report-json "$PROXY_REPORT" -- \
            sh -c "$BLOCKED_REQUEST" \
            >/dev/null 2>"$REPORT_ROOT/$MODE_FILE-proxy.stderr"
        RC=$?
        check_eq "$mode report: blocked proxy request leaves child successful" "$RC" "0"
        BLOCKED=$(python3 -c \
            'import json,sys; print(json.load(open(sys.argv[1]))["counters"]["proxy"]["requests_blocked"])' \
            "$PROXY_REPORT")
        if [ "$BLOCKED" -ge 1 ] 2>/dev/null; then
            check_eq "$mode report: blocked proxy request is counted" "counted" "counted"
        else
            check_eq "$mode report: blocked proxy request is counted" "$BLOCKED" ">=1"
        fi
    else
        skip "$mode report: proxy counters" "strict proxy capability or curl is unavailable"
    fi

    if [ "$mode" = "native" ]; then
        SIGNAL_REPORT="$REPORT_ROOT/$MODE_FILE-signal.json"
        mode_exec "$mode" --no-network --report-json "$SIGNAL_REPORT" -- \
            sh -c 'kill -TERM $$' >/dev/null 2>"$REPORT_ROOT/$MODE_FILE-signal.stderr"
        RC=$?
        check_eq "$mode report: signal exit convention is preserved" "$RC" "143"
        SIGNAL=$(python3 -c \
            'import json,sys; print(json.load(open(sys.argv[1]))["outcome"]["child"].get("signal"))' \
            "$SIGNAL_REPORT")
        check_eq "$mode report: originating child signal is retained" "$SIGNAL" "15"
    fi
done

remove_test_path "$REPORT_ROOT"
