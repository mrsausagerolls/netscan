"""Local web dashboard — serves on http://localhost:8765.

Architecture:
  - Static assets (HTML/CSS/JS) live in `static/` so they're easy to edit.
  - When packaged with py2app, those files ship inside the bundle and we
    resolve them relative to this module's __file__.
  - Origin/Referer check still gates every mutating endpoint — the same-origin
    rule is what prevents a malicious webpage from silently installing a hook.
"""

import json
import mimetypes
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

PORT = 8765

_HERE = Path(__file__).parent.resolve()
_STATIC_DIR = _HERE / "static"


def _read_static(rel_path: str) -> bytes | None:
    """Return the bytes of static/<rel_path>, or None if it isn't under static/."""
    p = (_STATIC_DIR / rel_path).resolve()
    try:
        p.relative_to(_STATIC_DIR)
    except ValueError:
        return None  # path-traversal attempt
    if not p.is_file():
        return None
    return p.read_bytes()


def _ctype(path: str) -> str:
    return mimetypes.guess_type(path)[0] or "application/octet-stream"


class _Handler(BaseHTTPRequestHandler):
    store = None
    get_state = None       # callable → dict
    on_known_change = None # callable → triggers menu redraw
    allowed_origins: set = set()  # populated in start()

    # ── auth ──────────────────────────────────────────────────────────────

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin") or self.headers.get("Referer", "")
        if not origin:
            return False
        return any(origin == a or origin.startswith(a + "/") for a in self.allowed_origins)

    # ── GET ───────────────────────────────────────────────────────────────

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/state":
            self._send(200, "application/json", json.dumps(self.get_state()).encode())
            return
        if path == "/api/history":
            self._send(200, "application/json", json.dumps(self.store.history).encode())
            return
        if path == "/api/alerts":
            self._send(200, "application/json", json.dumps(self.store.alerts(limit=200)).encode())
            return
        if path == "/api/webhooks":
            self._send(200, "application/json", json.dumps(self.store.webhooks()).encode())
            return
        if path == "/api/health":
            snap = self.store.latest_health() or {"score": None, "reasons": []}
            self._send(200, "application/json", json.dumps(snap).encode())
            return
        if path == "/api/wan_mappings":
            self._send(200, "application/json",
                       json.dumps(self.store.wan_mappings()).encode())
            return
        if path == "/favicon.ico":
            self._send(204, "image/x-icon", b"")
            return
        if path.startswith("/api/"):
            self._send(404, "application/json", b'{"error":"not found"}')
            return

        # Static assets
        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            data = _read_static(rel)
            if data is None:
                self._send(404, "text/plain", b"not found")
            else:
                self._send(200, _ctype(rel), data)
            return

        # Anything else → dashboard SPA shell. Stale bookmarks still land here.
        html = _read_static("index.html") or _FALLBACK_HTML.encode()
        self._send(200, "text/html", html)

    # ── POST ──────────────────────────────────────────────────────────────

    def do_POST(self):
        if not self._origin_ok():
            self._send(403, "application/json", b'{"error":"forbidden origin"}')
            return

        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")

        if path == "/api/known/add":
            self.store.add_known(body.get("mac", ""), body.get("name", ""))
            if self.on_known_change:
                self.on_known_change()
            self._ok()
            return
        if path == "/api/known/remove":
            self.store.remove_known(body.get("mac", ""))
            if self.on_known_change:
                self.on_known_change()
            self._ok()
            return
        if path == "/api/hook":
            self.store.set_hook_script(body.get("script", ""))
            self._ok()
            return
        if path == "/api/wol":
            try:
                from wol import wake
                wake(body.get("mac", ""))
                self._ok()
            except Exception as e:
                self._send(500, "application/json", json.dumps({"error": str(e)}).encode())
            return
        if path == "/api/alerts/ack":
            self.store.acknowledge_alert(int(body.get("id", 0)))
            self._ok()
            return
        if path == "/api/alerts/ack_all":
            self.store.acknowledge_all_alerts()
            self._ok()
            return
        if path == "/api/webhooks/add":
            url = (body.get("url") or "").strip()
            if not url.startswith(("http://", "https://")):
                self._send(400, "application/json", b'{"error":"url must be http(s)"}')
                return
            self.store.add_webhook(
                url=url,
                label=body.get("label", ""),
                min_severity=body.get("min_severity", "info"),
            )
            self._ok()
            return
        if path == "/api/webhooks/remove":
            self.store.remove_webhook(int(body.get("id", 0)))
            self._ok()
            return
        if path == "/api/webhooks/toggle":
            self.store.set_webhook_enabled(
                int(body.get("id", 0)), bool(body.get("enabled", False))
            )
            self._ok()
            return
        if path == "/api/devices/no_probe":
            self.store.set_no_probe(
                body.get("mac", ""), bool(body.get("no_probe", False))
            )
            self._ok()
            return
        if path == "/api/triage/bulk_known":
            for entry in body.get("entries", []):
                mac = (entry or {}).get("mac")
                if mac:
                    self.store.add_known(mac, (entry or {}).get("name", ""))
            if self.on_known_change:
                self.on_known_change()
            self._ok()
            return

        self._send(404, "application/json", b'{"error":"not found"}')

    # ── helpers ───────────────────────────────────────────────────────────

    def _ok(self):
        self._send(200, "application/json", b'{"ok":true}')

    def _send(self, code: int, ctype: str, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class _Server(HTTPServer):
    """HTTPServer with SO_REUSEPORT so a restarted process can bind immediately."""
    allow_reuse_address = True
    allow_reuse_port    = True


def start(store, get_state, on_known_change=None, port: int = PORT):
    _Handler.store            = store
    _Handler.get_state        = get_state
    _Handler.on_known_change  = on_known_change
    _Handler.allowed_origins  = {
        f"http://127.0.0.1:{port}",
        f"http://localhost:{port}",
    }

    # Retry binding for up to 15 s in case the previous instance's socket is
    # still in TIME_WAIT after a rapid launchd restart.
    deadline = time.monotonic() + 15
    while True:
        try:
            server = _Server(("127.0.0.1", port), _Handler)
            break
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)

    threading.Thread(target=server.serve_forever, daemon=True).start()
    return port


# Fallback if static/index.html went missing — keeps the dashboard at least loadable.
_FALLBACK_HTML = """<!DOCTYPE html><html><head><title>Inglorious Network Scanner</title>
<style>body{background:#07090D;color:#D8E2F0;font-family:system-ui;padding:40px;text-align:center}</style>
</head><body><h1>📡 Inglorious Network Scanner</h1>
<p>Dashboard assets missing. Reinstall or run <code>git pull</code>.</p></body></html>"""
