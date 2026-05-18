"""Event-driven side actions: voice announcements + Apple Shortcuts triggers.

Subscribers fire from the event bus alongside notifications and webhooks.
Both are opt-in (off by default), configured via the dashboard Settings tab,
and persist in the store's `settings` table.

Voice: `say` is the macOS built-in. Works under launchd without any extra
permission. We pass the alert title because the message is usually too long
to speak meaningfully.

Shortcuts: `shortcuts run <name>` invokes a user's Apple Shortcuts shortcut.
The shortcut receives the alert payload as JSON on stdin. On first invocation
the system may prompt the user for Automation permission — INS can't predict
this, so we warn in the dashboard help text.
"""

import json
import shlex
import subprocess
import threading

import events


# ── Voice ────────────────────────────────────────────────────────────────────

def _speak(text: str):
    """Fire-and-forget. Short timeout because `say` can hang on bad audio devices."""
    try:
        subprocess.Popen(
            ["say", "--", text[:200]],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True,
        )
    except (FileNotFoundError, OSError):
        pass


# ── Shortcuts ────────────────────────────────────────────────────────────────

def _run_shortcut(name: str, payload: dict):
    """Fire-and-forget. Pipes the payload JSON to stdin so the shortcut can
    parse it via the "Get Contents of Input" action."""
    if not name.strip():
        return
    try:
        body = json.dumps(payload, default=str).encode()
        p = subprocess.Popen(
            ["shortcuts", "run", name],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True,
        )
        threading.Thread(target=p.communicate, args=(body,), daemon=True).start()
    except (FileNotFoundError, OSError):
        pass


# ── Event subscribers ────────────────────────────────────────────────────────

def _on_alert_raised(payload: dict, *, store):
    if not store:
        return
    if store.get_setting("voice_enabled", "0") == "1":
        sev = payload.get("severity", "info")
        if sev in ("warning", "critical"):
            _speak(payload.get("title", "Network alert"))
    shortcut = store.get_setting("shortcut_on_alert", "").strip()
    if shortcut:
        _run_shortcut(shortcut, payload)


def _on_device_joined(payload: dict, *, store):
    if not store:
        return
    shortcut = store.get_setting("shortcut_on_new_device", "").strip()
    if shortcut:
        _run_shortcut(shortcut, payload)


def wire(store):
    """Hook into the event bus. Idempotent — guards against double-wiring."""
    global _wired
    if _wired:
        return
    _wired = True
    events.subscribe(events.ALERT_RAISED,
                     lambda p: _on_alert_raised(p, store=store))
    events.subscribe(events.DEVICE_JOINED,
                     lambda p: _on_device_joined(p, store=store))


_wired = False
