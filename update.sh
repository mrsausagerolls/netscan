#!/usr/bin/env bash
# Pull the latest source and restart the LaunchAgent.
# Designed to survive the parent app being killed by launchctl kickstart -k.
set -euo pipefail

PROJ="$(cd "$(dirname "$0")" && pwd)"
LOG="/tmp/ins-update.log"
STATUS="/tmp/ins-update.status"
LABEL="co.ingloriouslabs.netscan"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

# The release tag the app asked us to install (e.g. "2.4.13"); empty when run
# by hand, in which case we track origin/main.
TARGET_TAG="${1:-}"

# Surface the outcome via a one-line status file so a failed update (diverged
# tree, transient pip/PyPI failure) is visible instead of silently swallowed
# into the log — otherwise the menubar keeps showing "Update available" with no
# feedback. The ERR trap fires on any uncaught failure under `set -e`.
trap 'echo "fail: update failed — see $LOG" > "$STATUS"' ERR

cd "$PROJ"
{
  echo "── $(date -u +%Y-%m-%dT%H:%M:%SZ) update start ──"
  git fetch --quiet --tags origin
  before="$(git rev-parse HEAD)"

  # Resolve what to land on. Prefer the exact released tag the user was shown
  # ("Update to vX.Y.Z"), so the applied code matches their consent. Fall back
  # to origin/main if the tag isn't fetchable yet.
  ref="origin/main"
  if [[ -n "$TARGET_TAG" ]]; then
    cand="v${TARGET_TAG#v}"
    if git rev-parse -q --verify "refs/tags/$cand^{commit}" >/dev/null 2>&1; then
      ref="$cand"
    fi
  fi

  # ~/.ins is a MANAGED checkout — the user shouldn't be hand-editing it. Hard
  # reset onto the target so a stray local change (which made the old
  # `git pull --ff-only` fail with "Aborting", stranding the update) can't block
  # it. Ignored files — the .venv and data/ins.db — are untouched by reset.
  git reset --hard --quiet
  git checkout --quiet main 2>/dev/null || git checkout --quiet -B main origin/main
  git reset --hard --quiet "$ref"
  after="$(git rev-parse HEAD)"
  echo "$before → $after (target $ref)"

  if [[ "$before" == "$after" ]]; then
    echo "already up to date"
    echo "ok: already up to date" > "$STATUS"
    exit 0
  fi

  # If requirements changed, refresh deps in the venv. A dep-install failure
  # aborts here (via set -e + ERR trap) BEFORE the launchd restart, so we never
  # relaunch new code against stale dependencies — the tree stays on the new
  # commit but the failure is reported and the user can re-run update.sh.
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

  echo "ok: updated $before → $after" > "$STATUS"
} >> "$LOG" 2>&1
