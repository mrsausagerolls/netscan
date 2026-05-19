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

PY_VER="$("$PY" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
SITE_PACKAGES="$PROJ/.venv/lib/python$PY_VER/site-packages"

LAUNCHER_SRC="$PROJ/launcher/Inglorious Network Scanner.app"
LAUNCHER_DST="/Applications/Inglorious Network Scanner.app"
LAUNCHER_INSTALLED=false
if [[ -d "$LAUNCHER_SRC" ]]; then
    if [[ -w "/Applications" ]]; then
        rm -rf "$LAUNCHER_DST"
        cp -R "$LAUNCHER_SRC" "$LAUNCHER_DST"
        LAUNCHER_INSTALLED=true
        echo "launcher: $LAUNCHER_DST  (double-click to open the dashboard)"
    else
        echo "launcher: /Applications isn't writable; drag '$LAUNCHER_SRC' there yourself."
    fi
fi

# When the launcher .app is installed, run a copy of the Python interpreter
# from inside it. macOS infers a process's bundle identity by walking up from
# the executable path to the nearest Info.plist — placing python3.X inside
# the .app makes Location Services (and any other TCC prompt) label the app
# "Inglorious Network Scanner" instead of "Python". PYTHONPATH is set in the
# plist so the in-app Python still finds the venv's site-packages.
if [[ "$LAUNCHER_INSTALLED" == "true" ]]; then
    REAL_PY="$("$PY" -c 'import sys; print(getattr(sys, "_base_executable", sys.executable))')"
    PROG_PY="$LAUNCHER_DST/Contents/MacOS/python$PY_VER"
    cp "$REAL_PY" "$PROG_PY"
    chmod +x "$PROG_PY"
else
    PROG_PY="$PY"
fi

mkdir -p "$(dirname "$PLIST_DST")"
sed -e "s|__PYTHON__|$PROG_PY|" \
    -e "s|__APP__|$APP|" \
    -e "s|__PYTHONPATH__|$SITE_PACKAGES|" \
    "$TMPL" > "$PLIST_DST"

launchctl unload "$PLIST_DST" 2>/dev/null || true
launchctl load "$PLIST_DST"

echo "installed: $PLIST_DST"
echo "logs:      /tmp/ins.log  /tmp/ins.err"

CLI_SRC="$PROJ/tools/ins"
CLI_LOCAL_BIN="$HOME/.local/bin"
CLI_LINK="$CLI_LOCAL_BIN/ins"
if [[ -x "$CLI_SRC" ]]; then
    mkdir -p "$CLI_LOCAL_BIN"
    ln -sf "$CLI_SRC" "$CLI_LINK"
    echo "cli:       $CLI_LINK -> $CLI_SRC"
    case ":$PATH:" in
        *":$CLI_LOCAL_BIN:"*) ;;
        *) echo "           (add $CLI_LOCAL_BIN to your PATH to use 'ins' as a command)";;
    esac
fi
