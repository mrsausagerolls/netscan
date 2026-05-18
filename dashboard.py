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
import queue
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

import events

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


# ── SSE broadcaster ──────────────────────────────────────────────────────────
#
# Each connected /api/stream client gets a thread-safe Queue. The event bus
# publishes into every queue; the per-connection handler thread drains its
# queue and writes SSE frames to its client. Dead clients are detected on
# write and dropped.

_sse_clients: list[queue.Queue] = []
_sse_lock    = threading.Lock()


def _sse_publish(event_name: str, payload: dict) -> None:
    """Fan an event out to every connected SSE client. Drops nothing — slow
    clients have a small bounded buffer; if their queue is full, the new event
    is silently discarded for them (their next /api/state poll will catch up)."""
    frame = (event_name, payload)
    with _sse_lock:
        for q in list(_sse_clients):
            try:
                q.put_nowait(frame)
            except queue.Full:
                pass


def _wire_event_bus_once():
    """Subscribe the SSE broadcaster to the event bus. Idempotent."""
    global _bus_wired
    if _bus_wired:
        return
    _bus_wired = True
    for evt in (events.SCAN_COMPLETED, events.ALERT_RAISED,
                events.DEVICE_JOINED, events.DEVICE_LEFT,
                events.PORTS_CHANGED, events.VENDOR_CHANGED):
        events.subscribe(evt, lambda payload, e=evt: _sse_publish(e, payload))


_bus_wired = False


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
        if path.startswith("/api/device/"):
            self._send_device_story(path[len("/api/device/"):])
            return
        if path == "/api/stream":
            self._serve_sse()
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
        if path == "/api/settings/save":
            allowed = {
                "voice_enabled", "shortcut_on_new_device",
                "shortcut_on_alert", "first_run_done",
                "router_kind", "router_host", "router_user", "router_pass",
                "router_site", "router_ssh_port", "router_iface",
            }
            for key, val in (body or {}).items():
                if key in allowed:
                    self.store.set_setting(key, str(val))
            self._ok()
            return
        if path == "/api/router/test":
            import routerctl
            self._send(200, "application/json",
                       json.dumps(routerctl.get_backend(self.store).test()).encode())
            return
        if path == "/api/router/block":
            import routerctl
            mac = (body.get("mac") or "").strip()
            if not mac:
                self._send(400, "application/json", b'{"error":"mac required"}')
                return
            try:
                routerctl.get_backend(self.store).block(mac)
                self._ok()
            except routerctl.RouterError as e:
                self._send(502, "application/json",
                           json.dumps({"error": str(e)}).encode())
            return
        if path == "/api/router/unblock":
            import routerctl
            mac = (body.get("mac") or "").strip()
            if not mac:
                self._send(400, "application/json", b'{"error":"mac required"}')
                return
            try:
                routerctl.get_backend(self.store).unblock(mac)
                self._ok()
            except routerctl.RouterError as e:
                self._send(502, "application/json",
                           json.dumps({"error": str(e)}).encode())
            return

        self._send(404, "application/json", b'{"error":"not found"}')

    # ── /api/device/<mac> — per-device story ─────────────────────────────

    def _send_device_story(self, mac: str):
        mac = (mac or "").upper().replace("-", ":")
        device = self.store.get_device(mac)
        if not device:
            self._send(404, "application/json", b'{"error":"unknown mac"}')
            return
        sightings = self.store._q(
            "SELECT ip, ts, latency_ms FROM sightings WHERE mac=? "
            "ORDER BY ts DESC LIMIT 200", (mac,),
        )
        alerts = self.store._q(
            "SELECT id, ts, kind, severity, title, message, acknowledged "
            "FROM alerts WHERE mac=? ORDER BY ts DESC LIMIT 100", (mac,),
        )
        story = {
            "device":    device,
            "is_known":  self.store.is_known(mac),
            "known_name": self.store.known_name(mac),
            "wan_exposed": self.store.wan_mappings_for(device.get("ip") or ""),
            "sightings": [dict(r) for r in sightings],
            "alerts":    [dict(r) for r in alerts],
            "bandwidth": self.store.bandwidth_for(mac, since_seconds=3600),
            "dns":       self.store.dns_queries_for(mac, limit=100),
        }
        self._send(200, "application/json", json.dumps(story).encode())

    # ── /api/stream — Server-Sent Events ─────────────────────────────────

    def _serve_sse(self):
        """Long-lived SSE connection. Streams events from the bus + heartbeats
        every 15s so reverse-proxies and the browser keep the socket open."""
        self.send_response(200)
        self.send_header("Content-Type",  "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection",    "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        q: queue.Queue = queue.Queue(maxsize=64)
        with _sse_lock:
            _sse_clients.append(q)

        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    event_name, payload = q.get(timeout=15)
                    msg = (f"event: {event_name}\n"
                           f"data: {json.dumps(payload, default=str)}\n\n")
                    self.wfile.write(msg.encode())
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with _sse_lock:
                if q in _sse_clients:
                    _sse_clients.remove(q)

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
    """HTTPServer with SO_REUSEPORT + threaded so SSE connections don't block
    the regular request path."""
    allow_reuse_address = True
    allow_reuse_port    = True


from socketserver import ThreadingMixIn

class _ThreadedServer(ThreadingMixIn, _Server):
    daemon_threads = True


def start(store, get_state, on_known_change=None, port: int = PORT):
    _Handler.store            = store
    _Handler.get_state        = get_state
    _Handler.on_known_change  = on_known_change
    _Handler.allowed_origins  = {
        f"http://127.0.0.1:{port}",
        f"http://localhost:{port}",
    }

    _wire_event_bus_once()

    deadline = time.monotonic() + 15
    while True:
        try:
            server = _ThreadedServer(("127.0.0.1", port), _Handler)
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
