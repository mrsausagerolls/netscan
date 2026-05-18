"""Device registry — persistence for allowlist, seen devices, scan history, hooks."""

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from threading import Lock

# When running as a py2app bundle __file__ is inside the read-only .app;
# use Application Support so data survives updates.
if getattr(sys, "frozen", False):
    _DATA = Path.home() / "Library" / "Application Support" / "NetScan"
else:
    _DATA = Path(__file__).parent / "data"

_FLUSH_INTERVAL = 5  # seconds — batches `seen.json` / `history.json` writes


class DeviceStore:
    def __init__(self):
        _DATA.mkdir(exist_ok=True)
        self._lock    = Lock()
        self._known   = self._load("known.json",   {})   # mac → {name, added}
        self._seen    = self._load("seen.json",    {})   # mac → {first_seen, …}
        self._history = self._load("history.json", [])   # [{ts, count, ssid}]
        self._hook    = self._load("hook.json",    {"on_join": ""})
        self._dirty: set[str] = set()
        threading.Thread(target=self._flush_loop, daemon=True).start()

    # ── Allowlist ────────────────────────────────────────────────────────────

    def is_known(self, mac: str) -> bool:
        return mac in self._known

    def known_name(self, mac: str) -> str:
        return self._known.get(mac, {}).get("name", "")

    def add_known(self, mac: str, name: str = ""):
        with self._lock:
            self._known[mac] = {"name": name, "added": time.time()}
        # User-initiated — flush immediately so UI feedback is consistent.
        self._save_now("known.json", self._known)

    def remove_known(self, mac: str):
        with self._lock:
            self._known.pop(mac, None)
        self._save_now("known.json", self._known)

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
            self._dirty.add("seen.json")
        device["first_seen"] = rec["first_seen"]
        device["is_known"]   = self.is_known(mac)
        device["known_name"] = self.known_name(mac)
        return device

    def update_ports(self, mac: str, ports: list[int]):
        with self._lock:
            if mac in self._seen:
                self._seen[mac]["ports"] = ports
                self._dirty.add("seen.json")

    def update_fingerprint(self, mac: str, hints: dict):
        with self._lock:
            if mac in self._seen:
                self._seen[mac]["fingerprint"] = hints
                self._dirty.add("seen.json")

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
            self._dirty.add("history.json")

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
        self._save_now("hook.json", self._hook)

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

    def _snapshot(self, name: str):
        if name == "seen.json":    return dict(self._seen)
        if name == "history.json": return list(self._history)
        if name == "known.json":   return dict(self._known)
        if name == "hook.json":    return dict(self._hook)
        raise KeyError(name)

    def _write_atomic(self, name: str, data):
        target = _DATA / name
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        os.replace(tmp, target)

    def _save_now(self, name: str, data):
        with self._lock:
            snapshot = json.loads(json.dumps(data))  # deep copy via JSON
            self._dirty.discard(name)
        self._write_atomic(name, snapshot)

    def _flush_loop(self):
        while True:
            time.sleep(_FLUSH_INTERVAL)
            try:
                self._flush_now()
            except Exception:
                pass

    def _flush_now(self):
        with self._lock:
            dirty = self._dirty
            self._dirty = set()
            snapshots = {n: self._snapshot(n) for n in dirty}
        for name, data in snapshots.items():
            self._write_atomic(name, data)
