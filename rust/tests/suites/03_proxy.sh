#!/bin/bash
# Deterministic strict-proxy journeys plus an external HTTPS smoke test.

section "Destination-scoped proxy round-trip (cross-mode)"

if [ -z "$MODES" ]; then
    skip "proxy round-trip" "no runnable sandbox adapter is available"
elif ! command -v curl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    skip "proxy round-trip" "curl and python3 are required"
else
    PROXY_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdm-proxy-integration.XXXXXX")
    PROXY_POLICY_DIR="$PROXY_ROOT/policy"
    PROXY_CONFIG="$PROXY_POLICY_DIR/config.json"
    mkdir -p "$PROXY_POLICY_DIR"
    chmod 700 "$PROXY_POLICY_DIR"
    printf '%s\n' '{"secrets":{"restore_destinations":{"API_KEY":["127.0.0.1"]}}}' > "$PROXY_CONFIG"
    chmod 600 "$PROXY_CONFIG"

    LISTEN_PORT=0
    for CANDIDATE in 19285 19286 19287 19288 19289; do
        if ! (echo >/dev/tcp/127.0.0.1/$CANDIDATE) 2>/dev/null; then
            LISTEN_PORT=$CANDIDATE
            break
        fi
    done

    if [ "$LISTEN_PORT" -eq 0 ]; then
        skip "proxy round-trip" "no free local port found"
    else
        for mode in $MODES; do
            if ! mode_supports_proxy "$mode"; then
                skip "$mode: proxy round-trip" "strict proxy transport is unavailable"
                continue
            fi

            MODE_FILE=$(printf '%s' "$mode" | tr '/:' '__')
            CAPTURE_FILE="$PROXY_ROOT/$MODE_FILE.capture"
            READY_FILE="$PROXY_ROOT/$MODE_FILE.ready"

            python3 -c "
import http.server, pathlib, threading
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        value = self.headers.get('X-CDM-Secret', '').encode()
        pathlib.Path('$CAPTURE_FILE').write_bytes(value)
        self.send_response(200)
        self.send_header('Content-Length', str(len(value)))
        self.end_headers()
        self.wfile.write(value)
        threading.Thread(target=self.server.shutdown, daemon=True).start()
    def log_message(self, *args):
        pass
server = http.server.HTTPServer(('127.0.0.1', $LISTEN_PORT), Handler)
pathlib.Path('$READY_FILE').touch()
server.serve_forever()
" >"$PROXY_ROOT/$MODE_FILE.server.stdout" 2>"$PROXY_ROOT/$MODE_FILE.server.stderr" &
            HTTP_PID=$!
            for _i in $(seq 1 100); do
                [ -f "$READY_FILE" ] && break
                sleep 0.05
            done
            check_eq "$mode: deterministic proxy listener becomes ready" \
                "$(test -f "$READY_FILE"; echo $?)" "0"

            case "$mode" in
                native)
                    REQUEST="printf 'FAKE=%s\\n' \"\$API_KEY\"; curl -sf --max-time 5 --noproxy '' -H \"X-CDM-Secret: \$API_KEY\" http://127.0.0.1:$LISTEN_PORT/test"
                    ;;
                vm|vmi/*)
                    REQUEST="printf 'FAKE=%s\\n' \"\$API_KEY\"; wget -qO- -T 5 -Y on --header \"X-CDM-Secret: \$API_KEY\" http://127.0.0.1:$LISTEN_PORT/test"
                    ;;
            esac
            RESPONSE=$(CDM_CONFIG_PATH="$PROXY_CONFIG" mode_exec "$mode" \
                --scramble --allow-private-network --allow-domains 127.0.0.1 -- \
                sh -c "$REQUEST")
            RC=$?
            check_eq "$mode: scoped proxy request succeeds" "$RC" "0"

            FAKE_SECRET=$(printf '%s\n' "$RESPONSE" | sed -n '1s/^FAKE=//p')
            OUT=$(printf '%s\n' "$RESPONSE" | sed -n '2,$p')
            check_not "$mode: child receives an obfuscated API_KEY" "$FAKE_SECRET" "$REAL_SECRET"
            check_nonempty "$mode: child receives a nonempty fake API_KEY" "$FAKE_SECRET"

            if [ "$RC" -ne 0 ]; then
                kill "$HTTP_PID" 2>/dev/null
            fi
            wait "$HTTP_PID"
            SERVER_RC=$?
            check_eq "$mode: deterministic proxy listener exits cleanly" "$SERVER_RC" "0"
            RECEIVED=$(cat "$CAPTURE_FILE" 2>/dev/null)
            check_eq "$mode: authorized upstream receives the real secret" "$RECEIVED" "$REAL_SECRET"
            check_eq "$mode: upstream echo is re-obfuscated for the child" "$OUT" "$FAKE_SECRET"
            check_not "$mode: child-visible echo never contains the real secret" "$OUT" "$REAL_SECRET"

            # Ignoring proxy variables must not create a raw-TCP escape.
            python3 -m http.server "$LISTEN_PORT" --bind 127.0.0.1 \
                >"$PROXY_ROOT/$MODE_FILE.bypass.stdout" 2>"$PROXY_ROOT/$MODE_FILE.bypass.stderr" &
            BYPASS_PID=$!
            sleep 0.2
            case "$mode" in
                native) BYPASS="curl -sf --noproxy '*' --max-time 2 http://127.0.0.1:$LISTEN_PORT/" ;;
                vm|vmi/*) BYPASS="wget -qO- -T 2 -Y off http://127.0.0.1:$LISTEN_PORT/" ;;
            esac
            CDM_CONFIG_PATH="$PROXY_CONFIG" mode_exec "$mode" \
                --scramble --allow-private-network --allow-domains 127.0.0.1 -- \
                sh -c "$BYPASS" >/dev/null 2>&1
            BYPASS_RC=$?
            check_eq "$mode: strict transport blocks raw TCP bypass" \
                "$(test "$BYPASS_RC" -ne 0; echo $?)" "0"
            kill "$BYPASS_PID" 2>/dev/null
            wait "$BYPASS_PID" 2>/dev/null
        done
    fi
    remove_test_path "$PROXY_ROOT"
fi

echo ""
section "HTTPS MITM Proxy (cross-mode)"

# This is an external availability smoke test, not the deterministic security
# contract above. Network unavailability may skip it; a started local journey
# never turns a CDM failure into a skip.
for mode in $MODES; do
    if ! mode_supports_proxy "$mode"; then
        skip "$mode: HTTPS through MITM" "strict proxy transport is unavailable"
        continue
    fi
    OUT=$(mode_run_scrambled "$mode" 'curl -sf -m 10 https://httpbin.org/get 2>/dev/null | head -1')
    RC=$?
    if [ "$RC" -eq 0 ] && [ -n "$OUT" ]; then
        check "$mode: HTTPS through MITM" "$OUT" "{"
    else
        skip "$mode: HTTPS through MITM" "external endpoint is unavailable"
    fi
done
