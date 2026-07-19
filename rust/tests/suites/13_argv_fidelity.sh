#!/bin/bash
# Preserve command argv exactly across every available adapter.

section "Command argv fidelity"

if [ -z "$MODES" ]; then
    skip "argv fidelity" "no runnable sandbox adapter is available"
    return 0 2>/dev/null || exit 0
fi

NEWLINE_ARG='line-one
line-two'
EXPECTED='argc=6
1=<>
2=<space value>
3=<--leading-option>
4=<$HOME;*?[literal]>
5=<unicode-☃>
6=<line-one
line-two>'

PROBE='printf "argc=%s\n" "$#"; i=1; for arg do printf "%s=<%s>\n" "$i" "$arg"; i=$((i + 1)); done'

for mode in $MODES; do
    OUT=$(mode_exec "$mode" --no-proxy -- sh -c "$PROBE" argv-probe \
        "" "space value" "--leading-option" '$HOME;*?[literal]' "unicode-☃" "$NEWLINE_ARG" \
        2>/dev/null)
    RC=$?
    check_eq "$mode: argv probe exits successfully" "$RC" "0"
    check_eq "$mode: preserves empty, spaced, leading, literal, Unicode, and newline args" \
        "$OUT" "$EXPECTED"

    python3 "$SCRIPT_DIR/argv_bytes_probe.py" "$CDM" "$mode"
    check_eq "$mode: preserves non-UTF-8 Unix argument bytes" "$?" "0"
done
