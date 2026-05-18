"""Router-control adapters — block / unblock devices on the user's home router.

INS doesn't know how to do this from the LAN side alone (the device IS on the
LAN; you can't kick it off without router cooperation). Each supported router
exposes a different control surface:

  * Unifi (UDM-Pro / Cloud Key / Dream Machine) — REST API with login cookie.
  * OpenWrt — SSH + `uci` to flip `wireless.@wifi-iface[N].macfilter` and
    rewrite the `maclist` option, then `wifi reload`.
  * Eero — unofficial Cognito-auth API. Brittle (Amazon changes auth flow);
    deferred to a later release.

Every backend implements two operations: `block(mac)` and `unblock(mac)`.
Both are idempotent — re-blocking an already-blocked MAC is a no-op, not an
error. Backends raise `RouterError` for unrecoverable failures (auth failed,
unreachable, unknown response shape). The dashboard surfaces these directly
so the user can fix configuration mistakes.

Configuration lives in the store's `settings` table under namespaced keys:

  router_kind   = "unifi" | "openwrt" | "none"
  router_host   = e.g. "https://10.0.0.1:8443" (unifi) or "10.0.0.1" (openwrt)
  router_user   = admin username (unifi: site account; openwrt: ssh user)
  router_pass   = password (kept in plain text in the local SQLite — same trust
                  level as the rest of INS, see SECURITY.md)
  router_site   = unifi site name, default "default"
  router_ssh_port = openwrt only, default 22
  router_iface  = openwrt only, wireless interface index (default 0)

`get_backend(store)` reads the config and returns a configured backend or
`NoopBackend()` if router control isn't set up.
"""

from __future__ import annotations

import json
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request


class RouterError(RuntimeError):
    """Backend couldn't complete the requested action."""


# ── Base ────────────────────────────────────────────────────────────────────

class Backend:
    name: str = "base"

    def block(self, mac: str) -> None:
        raise NotImplementedError

    def unblock(self, mac: str) -> None:
        raise NotImplementedError

    def test(self) -> dict:
        """Validate config + reachability. Returns {ok, message, details}."""
        return {"ok": False, "message": "not implemented", "details": {}}


# ── No-op (router control disabled) ─────────────────────────────────────────

class NoopBackend(Backend):
    name = "none"

    def block(self, mac: str) -> None:
        raise RouterError(
            "Router control isn't configured. Open Settings → Router and "
            "pick a supported router kind first."
        )

    unblock = block

    def test(self) -> dict:
        return {"ok": False, "message": "Router control disabled.", "details": {}}


# ── Unifi (REST) ────────────────────────────────────────────────────────────
#
# Unifi controllers (UDM-Pro / Dream Machine / Cloud Key) speak the same REST
# API. The "block / unblock" verbs go to /api/s/<site>/cmd/stamgr with a
# JSON body `{cmd: "block-sta", mac: "..."}` (or "unblock-sta").

class UnifiBackend(Backend):
    name = "unifi"

    def __init__(self, host: str, user: str, password: str, site: str = "default",
                 verify_tls: bool = False):
        self.host     = host.rstrip("/")
        self.user     = user
        self.password = password
        self.site     = site or "default"
        self._cookie: str | None = None
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        url = f"{self.host}{path}"
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if self._cookie:
            headers["Cookie"] = self._cookie
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=8, context=self._ctx) as resp:
                set_cookie = resp.headers.get("Set-Cookie", "")
                if set_cookie and not self._cookie:
                    self._cookie = set_cookie.split(";", 1)[0]
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raise RouterError(
                f"Unifi controller returned HTTP {e.code} for {method} {path}"
            ) from e
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise RouterError(
                f"Couldn't reach Unifi controller at {self.host}: {e}"
            ) from e

        try:
            return json.loads(raw) if raw else {}
        except json.JSONDecodeError as e:
            raise RouterError(f"Unifi response wasn't JSON: {raw[:120]!r}") from e

    def _login(self) -> None:
        if self._cookie:
            return
        # Newer Unifi OS (UDM-Pro): /api/auth/login
        # Older controllers:        /api/login
        # Try the new one first; fall back on 404/401.
        for path in ("/api/auth/login", "/api/login"):
            try:
                self._request("POST", path,
                              {"username": self.user, "password": self.password})
                if self._cookie:
                    return
            except RouterError:
                continue
        raise RouterError("Unifi login failed at both /api/auth/login and /api/login")

    def _stamgr(self, cmd: str, mac: str) -> None:
        self._login()
        path = f"/api/s/{self.site}/cmd/stamgr"
        self._request("POST", path, {"cmd": cmd, "mac": mac.lower()})

    def block(self, mac: str) -> None:
        self._stamgr("block-sta", mac)

    def unblock(self, mac: str) -> None:
        self._stamgr("unblock-sta", mac)

    def test(self) -> dict:
        try:
            self._login()
        except RouterError as e:
            return {"ok": False, "message": str(e), "details": {}}
        try:
            sysinfo = self._request("GET", f"/api/s/{self.site}/stat/sysinfo")
        except RouterError as e:
            return {"ok": False, "message": f"login OK but stat/sysinfo failed: {e}",
                    "details": {}}
        version = ""
        data = sysinfo.get("data") or []
        if data and isinstance(data, list):
            version = data[0].get("version", "")
        return {"ok": True,
                "message": f"Connected to Unifi controller (v{version or 'unknown'})",
                "details": {"site": self.site, "version": version}}


# ── OpenWrt (SSH) ───────────────────────────────────────────────────────────
#
# Implementation strategy: shell into the router and edit
#   wireless.@wifi-iface[N].macfilter = 'deny'
#   wireless.@wifi-iface[N].maclist = <comma-list>
# then `uci commit wireless && wifi reload`. Keys are read back before write
# so we don't blow away an existing manually-managed allow list.

class OpenWrtBackend(Backend):
    name = "openwrt"

    def __init__(self, host: str, user: str, password: str | None,
                 ssh_port: int = 22, iface_index: int = 0,
                 ssh_options: list[str] | None = None):
        self.host      = host
        self.user      = user
        self.password  = password
        self.ssh_port  = ssh_port
        self.iface_idx = iface_index
        # ConnectTimeout cuts the wait when the router is unreachable.
        # BatchMode disables password prompts so we never hang on stdin.
        # StrictHostKeyChecking=accept-new auto-trusts first connection.
        self.ssh_options = ssh_options or [
            "-o", "ConnectTimeout=6",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "LogLevel=ERROR",
        ]

    def _ssh(self, remote_cmd: str) -> str:
        """Run a command on the router via SSH. Raises RouterError on failure."""
        cmd = ["ssh", "-p", str(self.ssh_port), *self.ssh_options,
               f"{self.user}@{self.host}", remote_cmd]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            raise RouterError(f"SSH to OpenWrt failed: {e}") from e
        if r.returncode != 0:
            raise RouterError(
                f"OpenWrt SSH command exited {r.returncode}: "
                f"{(r.stderr or r.stdout).strip()[:200]}"
            )
        return r.stdout

    def _macfilter_path(self) -> str:
        return f"wireless.@wifi-iface[{self.iface_idx}]"

    def _read_maclist(self) -> list[str]:
        try:
            raw = self._ssh(f"uci -q get {self._macfilter_path()}.maclist || true")
        except RouterError:
            return []
        return [m.strip() for m in raw.replace("\n", " ").split() if m.strip()]

    def _write_maclist(self, macs: list[str]) -> None:
        unique = sorted({m.lower() for m in macs if m})
        joined = " ".join(unique)
        # set macfilter mode + maclist, commit, reload wifi
        script = (
            f"uci set {self._macfilter_path()}.macfilter='deny' && "
            f"uci -q delete {self._macfilter_path()}.maclist; "
            + (f"uci add_list {self._macfilter_path()}.maclist='{joined}' && "
               if joined else "")
            + f"uci commit wireless && wifi reload"
        )
        self._ssh(script)

    def block(self, mac: str) -> None:
        macs = self._read_maclist()
        if mac.lower() in [m.lower() for m in macs]:
            return
        macs.append(mac.lower())
        self._write_maclist(macs)

    def unblock(self, mac: str) -> None:
        macs = [m for m in self._read_maclist() if m.lower() != mac.lower()]
        self._write_maclist(macs)

    def test(self) -> dict:
        try:
            uci_version = self._ssh("uci -v 2>&1 || true").strip()
            board = self._ssh("cat /tmp/sysinfo/model 2>/dev/null || echo unknown").strip()
        except RouterError as e:
            return {"ok": False, "message": str(e), "details": {}}
        return {"ok": True,
                "message": f"SSH OK to OpenWrt ({board})",
                "details": {"board": board, "uci": uci_version}}


# ── Factory ─────────────────────────────────────────────────────────────────

def get_backend(store) -> Backend:
    """Read router config from the store; return a configured backend."""
    kind = (store.get_setting("router_kind", "none") or "none").lower()
    host = store.get_setting("router_host", "")
    user = store.get_setting("router_user", "")
    pwd  = store.get_setting("router_pass", "")
    if kind == "unifi" and host and user and pwd:
        return UnifiBackend(host, user, pwd,
                            site=store.get_setting("router_site", "default") or "default")
    if kind == "openwrt" and host and user:
        port = int(store.get_setting("router_ssh_port", "22") or "22")
        idx  = int(store.get_setting("router_iface", "0") or "0")
        return OpenWrtBackend(host, user, pwd or None,
                              ssh_port=port, iface_index=idx)
    return NoopBackend()
