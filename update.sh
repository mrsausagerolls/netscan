#!/usr/bin/env bash
# Pull the latest source and restart the LaunchAgent.
# Designed to survive the parent app being killed by launchctl kickstart -k.
set -euo pipefail

PROJ="$(cd "$(dirname "$0")" && pwd)"
LOG="/tmp/ins-update.log"
LABEL="co.ingloriouslabs.netscan"
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

  CLI_SRC="$PROJ/tools/ins"
  if [[ -x "$CLI_SRC" ]]; then
    mkdir -p "$HOME/.local/bin"
    ln -sf "$CLI_SRC" "$HOME/.local/bin/ins" && echo "cli refreshed: $HOME/.local/bin/ins"
  fi

  # When install.sh, the LaunchAgent template, or the launcher .app changed,
  # re-run install.sh — it regenerates the plist (and re-embeds Python in the
  # .app for TCC bundle identity) and reloads launchd in one shot. Otherwise
  # just refresh the launcher and bounce the agent.
  changed_files="$(git diff --name-only "$before" "$after")"
  if echo "$changed_files" | grep -qE '^(install\.sh|co\.ingloriouslabs\.netscan\.plist\.tmpl|launcher/)'; then
    echo "install-affecting files changed — re-running install.sh"
    ./install.sh
  else
    LAUNCHER_SRC="$PROJ/launcher/Inglorious Network Scanner.app"
    LAUNCHER_DST="/Applications/Inglorious Network Scanner.app"
    if [[ -d "$LAUNCHER_SRC" && -w "/Applications" ]]; then
      rm -rf "$LAUNCHER_DST"
      cp -R "$LAUNCHER_SRC" "$LAUNCHER_DST" && echo "launcher refreshed: $LAUNCHER_DST"
    fi
    if [[ -f "$PLIST" ]]; then
      uid="$(id -u)"
      launchctl kickstart -k "gui/$uid/$LABEL" 2>/dev/null \
        || { launchctl unload "$PLIST" 2>/dev/null || true; launchctl load "$PLIST"; }
      echo "restarted via launchd"
    else
      echo "no LaunchAgent installed at $PLIST — start manually"
    fi
  fi
} >> "$LOG" 2>&1
