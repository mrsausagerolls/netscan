"""Local web dashboard — serves on http://localhost:8765.

Architecture:
  - Static assets (HTML/CSS/JS) live in `static/` so they're easy to edit.
  - When packaged with py2app, those files ship inside the bundle and we
    resolve them relative to this module's __file__.
  - Origin/Referer check still gates every mutating endpoint — the same-origin
    rule is what prevents a malicious webpage from silently installing a hook.
"""

import hmac
import json
import mimetypes
import os
import queue
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs, unquote

import events

PORT = 8765

_LOOPBACK = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}

# The ONLY endpoints an authenticated LAN client (the iOS companion) may reach.
# Everything else — mutations, the token-bearing /api/remote endpoints, the
# webhook list, and the static SPA — stays loopback-only. Keeping this an
# explicit read allowlist (not a blocklist) means a newly-added endpoint is
# LAN-invisible by default.
_LAN_READ_PREFIXES = (
    "/api/state", "/api/stream", "/api/health", "/api/history",
    "/api/alerts", "/api/wan_mappings", "/api/device/",
)

# Reject bodies larger than this on POST — the dashboard only ever sends small
# JSON control messages, so anything bigger is a mistake or abuse.
MAX_BODY_BYTES = 1_048_576  # 1 MiB

_HERE = Path(__file__).parent.resolve()
if getattr(sys, "frozen", False):
    # py2app bundle: assets live in Contents/Resources/static (see setup.py
    # "resources"), not next to this module inside the read-only .app.
    _RES = os.environ.get("RESOURCEPATH") or str(Path(sys.executable).resolve().parent.parent / "Resources")
    _STATIC_DIR = Path(_RES) / "static"
else:
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
    on_rescan = None       # callable → triggers a fresh scan
    on_lan_change = None    # callable → app re-applies bind + Bonjour
    get_remote_info = None  # callable → dict (loopback-only remote-access info)
    allowed_origins: set = set()  # populated in start()
    allowed_hosts:   set = set()  # populated in start()
    lan_enabled: bool = False     # is the LAN listener authorized to serve?
    lan_token:   str | None = None

    # ── auth ──────────────────────────────────────────────────────────────

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin") or self.headers.get("Referer", "")
        if not origin:
            return False
        return any(origin == a or origin.startswith(a + "/") for a in self.allowed_origins)

    def _is_loopback(self) -> bool:
        """True when the request came in over the loopback interface. The local
        browser (even when we're bound to 0.0.0.0 for LAN access) always connects
        from 127.0.0.1, so this cleanly separates the trusted local dashboard from
        untrusted LAN clients."""
        addr = getattr(self, "client_address", None)
        return (addr[0] if addr else "") in _LOOPBACK

    def _lan_authorized(self) -> bool:
        """A LAN client must present a Bearer token equal to the stored one.
        Constant-time compare so a timing side-channel can't leak the token."""
        token = _Handler.lan_token
        if not token:
            return False
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        return hmac.compare_digest(auth[len("Bearer "):], token)

    def _lan_gate(self) -> bool:
        """Authorize a non-loopback request, or send the rejection and return
        False. LAN access must be enabled, the token must match, the method must
        be GET, and the path must be in the read allowlist — so the phone can
        never mutate state or read the token/webhook endpoints even with a valid
        token."""
        if not _Handler.lan_enabled:
            self._send(403, "application/json", b'{"error":"remote access disabled"}')
            return False
        if not self._lan_authorized():
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer realm="INS"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False
        if self.command != "GET":
            self._send(403, "application/json", b'{"error":"remote access is read-only"}')
            return False
        path = urlparse(self.path).path
        if not any(path == p or path.startswith(p) for p in _LAN_READ_PREFIXES):
            self._send(403, "application/json", b'{"error":"endpoint not available remotely"}')
            return False
        return True

    @staticmethod
    def _as_int(v, default: int = 0) -> int:
        """Coerce a JSON body field to int without raising on bad input."""
        try:
            return int(v)
        except (ValueError, TypeError):
            return default

    def _host_ok(self) -> bool:
        """Reject any request whose Host header isn't one of our loopback names.

        This is the anti-DNS-rebinding gate. The server binds 127.0.0.1, but
        without checking Host it would happily answer requests for *any*
        hostname that resolves to loopback — letting a malicious page rebind
        its own domain to 127.0.0.1 and then read /api/* responses same-origin.
        A real browser hitting http://localhost:8765 always sends a Host that
        includes the port, so the allowlist below is exact. Enforced on every
        GET and POST before any routing or data access happens.
        """
        return self.headers.get("Host", "") in self.allowed_hosts

    # ── GET ───────────────────────────────────────────────────────────────

    def do_GET(self):
        # Loopback (the local browser) keeps the DNS-rebinding Host guard; a LAN
        # client (the iOS app) is authorized by token + read allowlist instead.
        if self._is_loopback():
            if not self._host_ok():
                self._send(403, "application/json", b'{"error":"forbidden host"}')
                return
        elif not self._lan_gate():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/state":
            self._send(200, "application/json", json.dumps(self.get_state()).encode())
            return
        if path == "/api/history":
            # Optional ?limit=N returns only the most recent N scans so the
            # dashboard doesn't ship the full (capped-at-5000) table on every
            # poll. No limit → full history (back-compat).
            qs = parse_qs(parsed.query)
            try:
                limit = int((qs.get("limit") or ["0"])[0])
            except (ValueError, TypeError):
                limit = 0
            data = self.store.recent_scans(limit) if limit > 0 else self.store.history
            self._send(200, "application/json", json.dumps(data).encode())
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
        if path == "/api/remote":
            # Carries the LAN token — loopback only (the LAN read allowlist
            # already excludes it, but guard explicitly).
            if not self._is_loopback() or not self.get_remote_info:
                self._send(403, "application/json", b'{"error":"forbidden"}')
                return
            self._send(200, "application/json",
                       json.dumps(self.get_remote_info()).encode())
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
        # Mutations are loopback-only. A LAN client can never POST — _lan_gate
        # rejects any non-GET from a non-loopback address even with a valid token.
        if self._is_loopback():
            if not self._host_ok():
                self._send(403, "application/json", b'{"error":"forbidden host"}')
                return
            if not self._origin_ok():
                self._send(403, "application/json", b'{"error":"forbidden origin"}')
                return
        elif not self._lan_gate():
            return

        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (ValueError, TypeError):
            self._send(400, "application/json", b'{"error":"bad content-length"}')
            return
        if length > MAX_BODY_BYTES:
            self._send(413, "application/json", b'{"error":"body too large"}')
            return
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, TypeError):
            self._send(400, "application/json", b'{"error":"invalid json body"}')
            return
        # Every endpoint does body.get(...) / body.items(); a JSON array/string/
        # number parses fine but would raise AttributeError downstream and drop
        # the connection with no response. Require a JSON object.
        if not isinstance(body, dict):
            self._send(400, "application/json", b'{"error":"body must be a json object"}')
            return

        if path == "/api/rescan":
            if self.on_rescan:
                self.on_rescan()
            self._ok()
            return
        if path == "/api/wifi/scan":
            try:
                import wifi
                neighbors = wifi.scan_neighbors()
            except Exception as e:
                self._send(500, "application/json",
                           json.dumps({"error": str(e)}).encode())
                return
            self._send(200, "application/json",
                       json.dumps({"neighbors": neighbors}).encode())
            return
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
            self.store.acknowledge_alert(self._as_int(body.get("id")))
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
            self.store.remove_webhook(self._as_int(body.get("id")))
            self._ok()
            return
        if path == "/api/webhooks/toggle":
            self.store.set_webhook_enabled(
                self._as_int(body.get("id")), bool(body.get("enabled", False))
            )
            self._ok()
            return
        if path == "/api/devices/no_probe":
            self.store.set_no_probe(
                body.get("mac", ""), bool(body.get("no_probe", False))
            )
            self._ok()
            return
        if path == "/api/remote":
            # Enable/disable LAN remote access (loopback-only; LAN can't POST).
            enabled = bool(body.get("enabled", False))
            self.store.set_setting("lan_access_enabled", "1" if enabled else "0")
            if enabled and not self.store.get_setting("lan_access_token", ""):
                self.store.set_setting("lan_access_token", secrets.token_urlsafe(24))
            if self.on_lan_change:
                self.on_lan_change()
            info = self.get_remote_info() if self.get_remote_info else {"ok": True}
            self._send(200, "application/json", json.dumps(info).encode())
            return
        if path == "/api/remote/regenerate":
            # Rotate the token; the old one stops working once set_lan applies it.
            self.store.set_setting("lan_access_token", secrets.token_urlsafe(24))
            if self.on_lan_change:
                self.on_lan_change()
            info = self.get_remote_info() if self.get_remote_info else {"ok": True}
            self._send(200, "application/json", json.dumps(info).encode())
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
                "router_verify_tls",
                "keep_alive",
            }
            keep_alive_change = None
            for key, val in (body or {}).items():
                if key in allowed:
                    if key == "keep_alive":
                        keep_alive_change = (str(val) == "1")
                    self.store.set_setting(key, str(val))
            if keep_alive_change is not None:
                import launchd_agent
                result = launchd_agent.set_keep_alive(keep_alive_change)
                if not result["ok"]:
                    self._send(502, "application/json",
                               json.dumps({"error": result["message"]}).encode())
                    return
            self._ok()
            return
        if path == "/api/router/test":
            import routerctl
            self._send(200, "application/json",
                       json.dumps(routerctl.get_backend(self.store).test()).encode())
            return
        if path in ("/api/router/block", "/api/router/unblock"):
            import routerctl
            raw = (body.get("mac") or "").strip()
            if not raw:
                self._send(400, "application/json", b'{"error":"mac required"}')
                return
            if not routerctl._MAC_RE.match(raw):
                self._send(400, "application/json", b'{"error":"invalid mac"}')
                return
            action = "block" if path.endswith("/block") else "unblock"
            try:
                getattr(routerctl.get_backend(self.store), action)(raw)
                self._ok()
            except routerctl.RouterError as e:
                self._send(502, "application/json",
                           json.dumps({"error": str(e)}).encode())
            return

        self._send(404, "application/json", b'{"error":"not found"}')

    # ── /api/device/<mac> — per-device story ─────────────────────────────

    def _send_device_story(self, mac: str):
        # The SPA encodeURIComponent()s the MAC, so colons arrive as %3A —
        # decode before normalizing or every lookup 404s (and the frontend
        # swallows the error, so the drawer just silently never opens).
        mac = unquote(mac or "").upper().replace("-", ":")
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

        # Bound each write so a wedged client (full TCP receive window, dead
        # but un-reset socket) can't pin this daemon thread + fd forever. The
        # timeout comfortably exceeds the 15s heartbeat, so a healthy idle
        # connection never trips it; a stuck write raises socket.timeout
        # (an OSError) which the loop's except handles via the finally cleanup.
        try:
            self.connection.settimeout(20)
        except OSError:
            pass

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


class _ThreadedServer(ThreadingMixIn, _Server):
    """Threaded server so /api/stream (SSE) connections don't block GET/POST
    requests. We override handle_error to drop the routine
    ConnectionResetError / BrokenPipeError noise that fills /tmp/ins.err
    whenever a browser tab closes its SSE connection. Real exceptions still
    get logged via the parent implementation."""
    daemon_threads = True

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


# Module-level server handle so set_lan() can rebind loopback ⇄ LAN at runtime.
_srv_lock  = threading.Lock()
_srv       = None
_srv_host  = "127.0.0.1"
_srv_port  = PORT


def _bind_server(host: str, port: int):
    """Create + start a serving thread bound to (host, port), retrying briefly
    while the previous socket lingers in TIME_WAIT."""
    deadline = time.monotonic() + 15
    while True:
        try:
            server = _ThreadedServer((host, port), _Handler)
            break
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def start(store, get_state, on_known_change=None, on_rescan=None,
          on_lan_change=None, get_remote_info=None, port: int = PORT,
          lan_enabled: bool = False, lan_token: str | None = None):
    global _srv, _srv_host, _srv_port
    _Handler.store            = store
    _Handler.get_state        = get_state
    _Handler.on_known_change  = on_known_change
    _Handler.on_rescan        = on_rescan
    _Handler.on_lan_change    = on_lan_change
    _Handler.get_remote_info  = get_remote_info
    _Handler.lan_enabled      = bool(lan_enabled)
    _Handler.lan_token        = lan_token or None
    _Handler.allowed_origins  = {
        f"http://127.0.0.1:{port}",
        f"http://localhost:{port}",
    }
    _Handler.allowed_hosts    = {
        f"127.0.0.1:{port}",
        f"localhost:{port}",
    }

    _wire_event_bus_once()

    # Bind 0.0.0.0 only when remote access is on at startup; otherwise stay
    # loopback-only so the "nothing is reachable off this machine" default holds.
    host = "0.0.0.0" if lan_enabled else "127.0.0.1"
    with _srv_lock:
        _srv = _bind_server(host, port)
        _srv_host, _srv_port = host, port
    return port


def set_lan(enabled: bool, token: str | None):
    """Apply a change to remote-access state. Updates the auth token/enabled flag
    live, and rebinds the listener loopback ⇄ 0.0.0.0 only when the reachable
    surface actually changes. Safe to call from a worker thread (never the
    serving thread). Returns the host now bound."""
    global _srv, _srv_host
    _Handler.lan_enabled = bool(enabled)
    _Handler.lan_token   = token or None
    desired = "0.0.0.0" if enabled else "127.0.0.1"
    with _srv_lock:
        if _srv is None or desired == _srv_host:
            return _srv_host
        old = _srv
        try:
            old.shutdown()
            old.server_close()
        except Exception:
            pass
        _srv = _bind_server(desired, _srv_port)
        _srv_host = desired
    return _srv_host


# Fallback if static/index.html went missing — keeps the dashboard at least loadable.
_FALLBACK_HTML = """<!DOCTYPE html><html><head><title>Inglorious Network Scanner</title>
<style>body{background:#07090D;color:#D8E2F0;font-family:system-ui;padding:40px;text-align:center}</style>
</head><body><h1>📡 Inglorious Network Scanner</h1>
<p>Dashboard assets missing. Reinstall or run <code>git pull</code>.</p></body></html>"""
