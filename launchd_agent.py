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

    # Reload so launchd picks up the new KeepAlive flag. unload + load is
    # safer than kickstart here because kickstart doesn't re-read the plist.
    unload = subprocess.run(
        ["launchctl", "unload", str(PLIST_PATH)],
        capture_output=True, text=True,
    )
    load = subprocess.run(
        ["launchctl", "load", str(PLIST_PATH)],
        capture_output=True, text=True,
    )
    if load.returncode != 0:
        return {"ok": False,
                "message": f"Plist updated but launchctl load failed: "
                           f"{(load.stderr or load.stdout).strip()}"}

    return {"ok": True,
            "message": ("KeepAlive enabled — INS will auto-restart on quit."
                        if enabled else
                        "KeepAlive disabled — Quit means quit until next login.")}
