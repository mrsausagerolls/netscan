#!/usr/bin/env bash
# Pull the latest source and restart the LaunchAgent.
# Designed to survive the parent app being killed by launchctl kickstart -k.
set -euo pipefail

PROJ="$(cd "$(dirname "$0")" && pwd)"
LOG="/tmp/netscan-update.log"
LABEL="com.wifiscanner"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

cd "$PROJ"
{
  echo "── $(date -u +%Y-%m-%dT%H:%M:%SZ) update start ──"
  git fetch --quiet origin
  before="$(git rev-parse HEAD)"
  git pull --ff-only
  after="$(git rev-parse HEAD)"
  echo "$before → $after"

  if [[ "$before" == "$after" ]]; then
    echo "already up to date"
    exit 0
  fi

  # If requirements changed, refresh deps in the venv.
  if git diff --name-only "$before" "$after" | grep -q '^requirements\.txt$'; then
    if [[ -x "$PROJ/.venv/bin/python3" ]]; then
      "$PROJ/.venv/bin/python3" -m pip install -r requirements.txt
    fi
  fi

  # Restart via launchd. kickstart -k stops and restarts the job atomically.
  if [[ -f "$PLIST" ]]; then
    uid="$(id -u)"
    launchctl kickstart -k "gui/$uid/$LABEL" 2>/dev/null \
      || { launchctl unload "$PLIST" 2>/dev/null || true; launchctl load "$PLIST"; }
    echo "restarted via launchd"
  else
    echo "no LaunchAgent installed at $PLIST — start NetScan manually"
  fi
} >> "$LOG" 2>&1
