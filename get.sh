#!/usr/bin/env bash
# Inglorious Network Scanner — one-line installer for macOS.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/mrsausagerolls/netscan/main/get.sh | bash
#
# Environment overrides:
#   INS_DIR              install location (default: ~/.ins)
#   INS_NO_AUTOSTART=1   skip the LaunchAgent install
#
# Backwards-compatible aliases (v1.x): NETSCAN_DIR, NETSCAN_NO_AUTOSTART.

set -euo pipefail

REPO="https://github.com/mrsausagerolls/netscan.git"
DEST="${INS_DIR:-${NETSCAN_DIR:-$HOME/.ins}}"
NO_AUTOSTART="${INS_NO_AUTOSTART:-${NETSCAN_NO_AUTOSTART:-0}}"

b()  { printf "\033[1m%s\033[0m\n" "$*"; }
g()  { printf "\033[32m%s\033[0m\n" "$*"; }
y()  { printf "\033[33m%s\033[0m\n" "$*"; }
err(){ printf "\033[31merror:\033[0m %s\n" "$*" >&2; exit 1; }

# ── Pre-flight checks ───────────────────────────────────────────────────────

[[ "$(uname -s)" == "Darwin" ]] \
  || err "Inglorious Network Scanner only runs on macOS (detected: $(uname -s))."

command -v git >/dev/null 2>&1 \
  || err "git not found. Install Xcode CLT: xcode-select --install"

command -v python3 >/dev/null 2>&1 \
  || err "python3 not found. Install via https://python.org or 'brew install python'."

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3,11) else 0)')
[[ "$PY_OK" == "1" ]] \
  || err "Python 3.11+ required (found $PY_VER)."

# ── Clone or update ─────────────────────────────────────────────────────────

b "→ Installing Inglorious Network Scanner to $DEST"
if [[ -d "$DEST/.git" ]]; then
  y "  existing install detected — pulling latest"
  git -C "$DEST" fetch --quiet origin
  git -C "$DEST" pull --ff-only --quiet
else
  if [[ -e "$DEST" ]]; then
    err "$DEST exists and is not a git repo. Move it aside or set INS_DIR."
  fi
  git clone --quiet "$REPO" "$DEST"
fi

cd "$DEST"

# ── Python environment ──────────────────────────────────────────────────────

b "→ Setting up Python environment (this may take a minute)"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
./.venv/bin/python -m pip install --quiet --no-cache-dir --upgrade pip
./.venv/bin/python -m pip install --quiet --no-cache-dir -r requirements.txt

# ── LaunchAgent ─────────────────────────────────────────────────────────────

if [[ "$NO_AUTOSTART" != "1" ]]; then
  b "→ Installing LaunchAgent (auto-start on login)"
  ./install.sh
else
  y "→ Skipping LaunchAgent (INS_NO_AUTOSTART=1). Start manually: sudo $DEST/.venv/bin/python $DEST/app.py"
fi

# ── Done ────────────────────────────────────────────────────────────────────

VERSION=$(./.venv/bin/python -c 'from version import __version__; print(__version__)' 2>/dev/null || echo "?")

echo
g "✓ Inglorious Network Scanner v$VERSION installed."
echo "  Look for 📡 in your menubar."
echo
echo "  Dashboard:  http://localhost:8765"
echo "  Launcher:   /Applications/Inglorious Network Scanner.app  (double-click to open the dashboard)"
echo "  CLI:        ins   (in ~/.local/bin — add to PATH if not already)"
echo "  Source:     $DEST"
echo "  Update:     $DEST/update.sh    (or run 'ins update' or click the menubar update item)"
echo "  Uninstall:  launchctl unload ~/Library/LaunchAgents/co.ingloriouslabs.netscan.plist && rm -rf $DEST"
