#!/bin/bash
# macOS application discovery and launch journey.

echo -e "${BOLD}--- macOS application mode ---${NC}"

if [ "$(uname -s)" != "Darwin" ] || ! has_native; then
    skip "app mode" "native macOS Seatbelt is unavailable"
    return 0 2>/dev/null || exit 0
fi

APP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdm-app-integration.XXXXXX")
APP_HOME="$APP_ROOT/home"
APP_BUNDLE="$APP_ROOT/Fixture App.app"
APP_EXEC="$APP_BUNDLE/Contents/MacOS/fixture-app"
APP_ID="dev.cdm.fixture-app"

APP_STATE_DIR="$APP_HOME/Library/Application Support/$APP_ID"
APP_CACHE_DIR="$APP_HOME/Library/Caches/fixture-app-renderer"
mkdir -p "$APP_STATE_DIR" "$APP_CACHE_DIR" \
    "$APP_HOME/.fixture" "$(dirname "$APP_EXEC")"
cat > "$APP_BUNDLE/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$APP_ID</string>
<key>CFBundleExecutable</key><string>fixture-app</string>
<key>CFBundleDisplayName</key><string>CDM Fixture</string>
</dict></plist>
EOF
cat > "$APP_EXEC" <<'EOF'
#!/bin/sh
set -eu
state="$HOME/Library/Application Support/dev.cdm.fixture-app"
mkdir -p "$state"
printf '%s' "$1" > "$state/result.txt"
printf cache > "$HOME/Library/Caches/fixture-app-renderer/result.txt"
EOF
chmod +x "$APP_EXEC"

# The synthetic bundle is deliberately unsigned. Selecting it as the command
# is the user's trust decision, so local apps use the same narrow discovery.
APP_OUTPUT=$(HOME="$APP_HOME" "$CDM" --no-proxy --iso \
    -- "$APP_BUNDLE" app-argument 2>&1)
APP_STATUS=$?

APP_STATE=$(cat "$APP_HOME/Library/Application Support/$APP_ID/result.txt" 2>/dev/null)
check_eq "app: exits successfully" "$APP_STATUS" "0"
check "app: resolves bundle executable and creates conventional state" "$APP_STATE" "app-argument"

check "app: bundle reference permits a narrow helper cache" \
    "$(cat "$APP_HOME/Library/Caches/fixture-app-renderer/result.txt" 2>/dev/null)" "cache"

check "app: reports the discovered bundle identity" "$APP_OUTPUT" "Application:       \"$APP_ID\""
check "app: reports conventional grant evidence" "$APP_OUTPUT" "(bundle convention)"
check "app: reports bundle-reference evidence" "$APP_OUTPUT" "(bundle reference)"
check "app: reports app grant provenance" "$APP_OUTPUT" "[app]"
check_not "app: abbreviates inferred paths instead of exposing the home root" "$APP_OUTPUT" "$APP_HOME"

EXPLICIT_OUTPUT=$(HOME="$APP_HOME" "$CDM" --no-proxy --iso \
    --app "$APP_BUNDLE" -- explicit-argument 2>&1)
EXPLICIT_STATUS=$?
check_eq "app: explicit compatibility form exits successfully" "$EXPLICIT_STATUS" "0"
check "app: explicit compatibility form preserves arguments" \
    "$(cat "$APP_STATE_DIR/result.txt" 2>/dev/null)" "explicit-argument"
check "app: explicit compatibility form reports discovery" \
    "$EXPLICIT_OUTPUT" "Application:       \"$APP_ID\""

remove_test_path "$APP_ROOT"
