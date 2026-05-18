"""Native macOS notifications via osascript.

Why osascript? It requires no signed bundle and no entitlements, so it works
in our unsigned source-install model. The trade-off is that notifications are
attributed to "Script Editor" / "Terminal" rather than to Inglorious Network
Scanner — fixable once we have a signed .app.

Two behaviors:

  * Throttling: at most one notification every 30 s, and never the same alert
    kind for the same MAC within 5 minutes (avoids spamming on rescan loops).
  * Burst-coalescing: if a flurry of `new_device` alerts arrives within a few
    seconds — typical when a household reconnects after a router reboot — they
    are collapsed into a single banner ("5 new devices joined — review now").
    Critical alerts always fire individually; coalescing is for informational
    `new_device` only.
"""

import shlex
import subprocess
import threading
import time

from version import __app_name__

_MIN_INTERVAL_S = 30
_DEDUP_WINDOW_S = 300
_BURST_WINDOW_S = 8       # collapse same-kind alerts inside this window
_COALESCE_KINDS = {"new_device"}

_last_emit_ts: float = 0.0
_recent: dict[str, float] = {}     # key → ts
_burst_queue: list[dict] = []      # alerts pending coalescing
_burst_timer: threading.Timer | None = None
_lock = threading.Lock()


def _osascript_notify(title: str, message: str, subtitle: str = ""):
    """Use osascript to fire a native banner. Silently no-op on non-macOS."""
    def q(s: str) -> str:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

    parts = [f"display notification {q(message)}",
             f"with title {q(title)}"]
    if subtitle:
        parts.append(f"subtitle {q(subtitle)}")
    script = " ".join(parts)

    try:
        subprocess.run(
            ["osascript", "-e", script],
            timeout=3, check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def _emit(title: str, message: str, severity: str = "info") -> bool:
    """Throttle + dedup gate. Returns True if a banner was actually sent."""
    global _last_emit_ts
    now = time.time()
    with _lock:
        if now - _last_emit_ts < _MIN_INTERVAL_S:
            return False
        _last_emit_ts = now

    icon = {"critical": "🚨", "warning": "⚠️", "info": "📡"}.get(severity, "📡")
    subtitle = f"{icon}  {__app_name__}"

    msg = message
    if len(msg) > 240:
        msg = msg[:237] + "…"

    _osascript_notify(title, msg, subtitle)
    return True


def _flush_burst():
    """Coalesce pending burst alerts into one banner, then clear the queue."""
    global _burst_queue, _burst_timer
    with _lock:
        pending = list(_burst_queue)
        _burst_queue = []
        _burst_timer = None

    if not pending:
        return
    if len(pending) == 1:
        a = pending[0]
        _emit(a.get("title", "Alert"), a.get("message", ""),
              a.get("severity", "info"))
        return

    titles = []
    for a in pending[:5]:
        t = a.get("title", "").replace("New ", "").replace("joined: ", "")
        titles.append(t)
    extra = "" if len(pending) <= 5 else f" and {len(pending) - 5} more"
    summary = ", ".join(titles) + extra
    _emit(
        f"{len(pending)} new devices joined",
        f"{summary}. Open the dashboard to review.",
        severity="info",
    )


def notify_alert(alert: dict) -> bool:
    """Send a banner for an alert dict {kind, severity, title, message, mac}.

    Returns True if sent, False if throttled, deduped, or queued for coalescing.
    """
    now = time.time()
    key = f"{alert.get('mac') or '-'}::{alert.get('kind', '')}"

    with _lock:
        last = _recent.get(key, 0)
        if now - last < _DEDUP_WINDOW_S:
            return False
        _recent[key] = now
        cutoff = now - _DEDUP_WINDOW_S
        for k in [k for k, t in _recent.items() if t < cutoff]:
            _recent.pop(k, None)

    kind = alert.get("kind", "")
    severity = alert.get("severity", "info")

    # Coalesce only for low-stakes "new device" bursts. Critical alerts get
    # their own banner immediately so the user can't miss them.
    if kind in _COALESCE_KINDS and severity == "info":
        global _burst_timer
        with _lock:
            _burst_queue.append(alert)
            if _burst_timer is None:
                _burst_timer = threading.Timer(_BURST_WINDOW_S, _flush_burst)
                _burst_timer.daemon = True
                _burst_timer.start()
        return True

    return _emit(alert.get("title", "Alert"),
                 alert.get("message", ""),
                 severity)
