#!/usr/bin/env bash
# Install Inglorious Network Scanner as a per-user LaunchAgent.
set -euo pipefail

PROJ="$(cd "$(dirname "$0")" && pwd)"
PY="$PROJ/.venv/bin/python3"
APP="$PROJ/app.py"
LABEL="co.ingloriouslabs.netscan"
PLIST_DST="$HOME/Library/LaunchAgents/$LABEL.plist"
TMPL="$PROJ/$LABEL.plist.tmpl"

if [[ ! -x "$PY" ]]; then
  echo "error: $PY not found. Create the venv first: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 1
fi
if [[ ! -f "$APP" ]]; then
  echo "error: $APP not found." >&2
  exit 1
fi
if [[ ! -f "$TMPL" ]]; then
  echo "error: plist template not found at $TMPL" >&2
  exit 1
fi

# Stop and remove any old wifiscanner LaunchAgent left behind by v1.x.
OLD_PLIST="$HOME/Library/LaunchAgents/com.wifiscanner.plist"
if [[ -f "$OLD_PLIST" ]]; then
  echo "→ Removing legacy LaunchAgent (com.wifiscanner)"
  launchctl unload "$OLD_PLIST" 2>/dev/null || true
  rm -f "$OLD_PLIST"
fi

mkdir -p "$(dirname "$PLIST_DST")"
sed -e "s|__PYTHON__|$PY|" -e "s|__APP__|$APP|" "$TMPL" > "$PLIST_DST"

launchctl unload "$PLIST_DST" 2>/dev/null || true
launchctl load "$PLIST_DST"

echo "installed: $PLIST_DST"
echo "logs:      /tmp/ins.log  /tmp/ins.err"
