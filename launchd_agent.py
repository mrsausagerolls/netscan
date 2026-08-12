"""Tiny launchd helper — read / rewrite the INS LaunchAgent plist.

Used for the "Keep INS in menubar" toggle. When the user enables it, INS
flips `KeepAlive=true` in its own LaunchAgent plist and reloads launchd so
the change takes effect immediately. When disabled, flips back to false.

Why this is a separate module: surgical plist edits are easy to get wrong
(blowing away the user's ProgramArguments paths, for example). Centralising
the read-modify-write here lets every caller share the same plistlib-based
implementation rather than reaching for `sed` or `defaults`.

The plist lives at:
    ~/Library/LaunchAgents/co.ingloriouslabs.netscan.plist

We only touch the KeepAlive key. Everything else is left as-is.
"""

from __future__ import annotations

import os
import plistlib
import shlex
import subprocess
from pathlib import Path

LABEL = "co.ingloriouslabs.netscan"
PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def plist_exists() -> bool:
    return PLIST_PATH.is_file()


def get_keep_alive() -> bool:
    if not plist_exists():
        return False
    try:
        with PLIST_PATH.open("rb") as fp:
            data = plistlib.load(fp)
    except (OSError, plistlib.InvalidFileException):
        return False
    val = data.get("KeepAlive", False)
    if isinstance(val, bool):
        return val
    # Dict form — true if any sub-condition is true. We only ever WRITE the
    # bool form, but be tolerant of plists hand-edited to use the dict form.
    if isinstance(val, dict):
        return any(bool(v) for v in val.values())
    return False


def set_keep_alive(enabled: bool) -> dict:
    """Rewrite the plist with KeepAlive flipped, then reload launchd.

    Returns {ok: bool, message: str} so the dashboard can surface the result
    inline instead of dropping it on the floor.
    """
    if not plist_exists():
        return {"ok": False,
                "message": f"LaunchAgent plist not found at {PLIST_PATH}. "
                           f"Install INS via get.sh or install.sh first."}

    try:
        with PLIST_PATH.open("rb") as fp:
            data = plistlib.load(fp)
    except (OSError, plistlib.InvalidFileException) as e:
        return {"ok": False, "message": f"Couldn't read plist: {e}"}

    data["KeepAlive"] = bool(enabled)

    try:
        with PLIST_PATH.open("wb") as fp:
            plistlib.dump(data, fp)
    except OSError as e:
        return {"ok": False, "message": f"Couldn't write plist: {e}"}

    # Reload launchd so it re-reads the new KeepAlive flag (a load-time
    # property; kickstart -k wouldn't re-read the plist). But `launchctl unload`
    # boots out THIS job — the app runs under it — which SIGTERMs the current
    # process. Running unload+load synchronously here (as before) meant the app
    # died mid-call: this return value never reached the browser, and if the
    # `load` line lost the race with SIGTERM nothing relaunched INS (plist
    # KeepAlive default is false), so the menubar icon vanished until next login.
    #
    # Instead spawn a DETACHED helper that outlives our teardown. It sleeps
    # briefly so the HTTP response below flushes to the dashboard first, then
    # unload+load — and because it's in its own session, the `load` runs to
    # completion even as the app is being SIGTERM'd, bringing INS right back
    # (RunAtLoad=true). Mirrors update.sh's detached-restart pattern.
    q = shlex.quote(str(PLIST_PATH))
    try:
        subprocess.Popen(
            ["/bin/sh", "-c",
             f"sleep 0.7; launchctl unload {q} 2>/dev/null; exec launchctl load {q}"],
            start_new_session=True, close_fds=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError as e:
        return {"ok": False, "message": f"Plist updated but reload failed to start: {e}"}

    return {"ok": True,
            "message": ("KeepAlive enabled — INS is restarting now and will "
                        "auto-relaunch whenever you Quit."
                        if enabled else
                        "KeepAlive disabled — INS is restarting now; Quit will "
                        "stay quit until next login.")}
