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
    # Copy the GUI Python binary (Python.app/Contents/MacOS/Python), not the
    # `bin/python3.X` CLI stub. The CLI stub posix_spawns the framework's
    # Python.app at startup, which would re-execute the process there and
    # erase the .app bundle identity we're setting up here. The GUI binary
    # runs in-place and keeps the bundle/TCC identity intact.
    BIN_PY="$("$PY" -c 'import sys; print(getattr(sys, "_base_executable", sys.executable))')"
    GUI_PY="$("$PY" -c '
import os, sys
exe = getattr(sys, "_base_executable", sys.executable)
real = os.path.realpath(exe)
# .../Python.framework/Versions/<V>/bin/pythonX.Y  →  .../Resources/Python.app/Contents/MacOS/Python
version_root = os.path.dirname(os.path.dirname(real))
candidate = os.path.join(version_root, "Resources", "Python.app", "Contents", "MacOS", "Python")
print(candidate if os.path.isfile(candidate) else exe)
')"
    PROG_PY="$LAUNCHER_DST/Contents/MacOS/python$PY_VER"
    # This injected binary is what the LaunchAgent execs — it MUST exist, or the
    # agent can't start. Fail loudly if the copy doesn't land rather than writing
    # a plist that points at a missing binary.
    if ! cp "$GUI_PY" "$PROG_PY"; then
        echo "error: failed to copy in-app Python to $PROG_PY" >&2
        exit 1
    fi
    chmod +x "$PROG_PY"
    if [[ ! -x "$PROG_PY" ]]; then
        echo "error: in-app Python missing/not executable at $PROG_PY" >&2
        exit 1
    fi
    # Re-sign ad-hoc with the bundle's identifier. macOS TCC keys permissions
    # by the binary's code-signing identity, not its enclosing .app path —
    # without this, requests would still be attributed to the original
    # "python3-<hash>" identifier instead of the bundle.
    codesign --force --sign - --identifier "co.ingloriouslabs.netscan" "$PROG_PY" 2>/dev/null \
        && echo "signed:    $PROG_PY (identifier co.ingloriouslabs.netscan)"
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
