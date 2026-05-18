#!/usr/bin/env bash
# Install NetScan as a per-user LaunchAgent.
set -euo pipefail

PROJ="$(cd "$(dirname "$0")" && pwd)"
PY="$PROJ/.venv/bin/python3"
APP="$PROJ/app.py"
PLIST_DST="$HOME/Library/LaunchAgents/com.wifiscanner.plist"

if [[ ! -x "$PY" ]]; then
  echo "error: $PY not found. Create the venv first: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 1
fi
if [[ ! -f "$APP" ]]; then
  echo "error: $APP not found." >&2
  exit 1
fi

mkdir -p "$(dirname "$PLIST_DST")"
sed -e "s|__PYTHON__|$PY|" -e "s|__APP__|$APP|" \
  "$PROJ/com.wifiscanner.plist.tmpl" > "$PLIST_DST"

launchctl unload "$PLIST_DST" 2>/dev/null || true
launchctl load "$PLIST_DST"

echo "installed: $PLIST_DST"
echo "logs:      /tmp/netscan.log  /tmp/netscan.err"
