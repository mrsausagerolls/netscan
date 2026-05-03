"""Device registry — persistence for allowlist, seen devices, scan history, hooks."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from threading import Lock

# When running as a py2app bundle __file__ is inside the read-only .app;
# use Application Support so data survives updates.
if getattr(sys, "frozen", False):
    _DATA = Path.home() / "Library" / "Application Support" / "NetScan"
else:
    _DATA = Path(__file__).parent / "data"


class DeviceStore:
    def __init__(self):
        _DATA.mkdir(exist_ok=True)
        self._lock    = Lock()
        self._known   = self._load("known.json",   {})   # mac → {name, added}
        self._seen    = self._load("seen.json",    {})   # mac → {first_seen, …}
        self._history = self._load("history.json", [])   # [{ts, count, ssid}]
        self._hook    = self._load("hook.json",    {"on_join": ""})

    # ── Allowlist ────────────────────────────────────────────────────────────

    def is_known(self, mac: str) -> bool:
        return mac in self._known

    def known_name(self, mac: str) -> str:
        return self._known.get(mac, {}).get("name", "")

    def add_known(self, mac: str, name: str = ""):
        with self._lock:
            self._known[mac] = {"name": name, "added": time.time()}
            self._save("known.json", self._known)

    def remove_known(self, mac: str):
        with self._lock:
            self._known.pop(mac, None)
            self._save("known.json", self._known)

    @property
    def known(self) -> dict:
        with self._lock:
            return dict(self._known)

    # ── Seen devices ─────────────────────────────────────────────────────────

    def touch(self, device: dict) -> dict:
        """Record this sighting; return device enriched with history fields."""
        mac = device["mac"]
        now = time.time()
        with self._lock:
            rec = self._seen.get(mac, {})
            rec.update({
                "mac":        mac,
                "ip":         device["ip"],
                "hostname":   device.get("hostname", "—"),
                "vendor":     device.get("vendor",   "—"),
                "last_seen":  now,
                "first_seen": rec.get("first_seen", now),
                "seen_count": rec.get("seen_count", 0) + 1,
            })
            self._seen[mac] = rec
            self._save("seen.json", self._seen)
        device["first_seen"] = rec["first_seen"]
        device["is_known"]   = self.is_known(mac)
        device["known_name"] = self.known_name(mac)
        return device

    def update_ports(self, mac: str, ports: list[int]):
        with self._lock:
            if mac in self._seen:
                self._seen[mac]["ports"] = ports
                self._save("seen.json", self._seen)

    def update_fingerprint(self, mac: str, hints: dict):
        with self._lock:
            if mac in self._seen:
                self._seen[mac]["fingerprint"] = hints
                self._save("seen.json", self._seen)

    @property
    def all_seen(self) -> dict:
        with self._lock:
            return dict(self._seen)

    # ── Scan history ─────────────────────────────────────────────────────────

    def record_scan(self, count: int, ssid: str):
        with self._lock:
            self._history.append({"ts": time.time(), "count": count, "ssid": ssid or ""})
            if len(self._history) > 2000:
                self._history = self._history[-2000:]
            self._save("history.json", self._history)

    @property
    def history(self) -> list:
        with self._lock:
            return list(self._history)

    # ── Hook ─────────────────────────────────────────────────────────────────

    @property
    def hook_script(self) -> str:
        with self._lock:
            return self._hook.get("on_join", "")

    def set_hook_script(self, script: str):
        with self._lock:
            self._hook["on_join"] = script
            self._save("hook.json", self._hook)

    def run_hook(self, device: dict, ssid: str):
        script = self.hook_script.strip()
        if not script:
            return
        env = {**os.environ,
               "DEVICE_IP":       device["ip"],
               "DEVICE_MAC":      device["mac"],
               "DEVICE_VENDOR":   device.get("vendor", ""),
               "DEVICE_HOSTNAME": device.get("hostname", ""),
               "SSID":            ssid or ""}
        subprocess.Popen(script, shell=True, env=env)

    # ── Internal ─────────────────────────────────────────────────────────────

    def _load(self, name: str, default):
        try:
            return json.loads((_DATA / name).read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return default

    def _save(self, name: str, data):
        (_DATA / name).write_text(json.dumps(data, indent=2))
