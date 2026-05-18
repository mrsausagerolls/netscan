#!/usr/bin/env python3
"""WiFi Scanner — macOS menubar app."""

import os
import re
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rumps
import dashboard
from scanner import do_scan, enrich, scan_ports, probe_device, best_fingerprint, get_wifi_info
from store import DeviceStore
from wol import wake

POLL_INTERVAL = 5
AUTO_RESCAN   = 5
ICON          = "📡"
DASH_PORT     = 8765

store = DeviceStore()


def _wifi_iface() -> str:
    """Return the active WiFi interface name (e.g. 'en0', 'en1')."""
    lines = subprocess.run(
        ["networksetup", "-listallhardwareports"],
        capture_output=True, text=True,
    ).stdout.splitlines()
    for i, line in enumerate(lines):
        if "Wi-Fi" in line or "AirPort" in line:
            for nearby in lines[i:i + 4]:
                m = re.search(r"Device:\s+(en\d+)", nearby)
                if m:
                    return m.group(1)
            break
    return "en0"


_loc_mgr = None  # keep a reference so it isn't GC'd before the callback fires

def _location_authorized() -> bool:
    """Return True if Location Services are granted."""
    try:
        from CoreLocation import CLLocationManager
        # macOS: 0=notDetermined, 1=restricted, 2=denied, 3=authorizedAlways, 4=authorizedWhenInUse
        return CLLocationManager.authorizationStatus() in (3, 4)
    except Exception:
        return False

def _request_location_permission():
    """Call requestWhenInUseAuthorization so NetScan appears in System Settings → Location Services."""
    global _loc_mgr
    try:
        from CoreLocation import CLLocationManager, kCLAuthorizationStatusNotDetermined
        if CLLocationManager.authorizationStatus() == kCLAuthorizationStatusNotDetermined:
            _loc_mgr = CLLocationManager.alloc().init()
            _loc_mgr.requestWhenInUseAuthorization()
    except Exception:
        pass


def _current_ssid() -> str | None:
    try:
        from CoreWLAN import CWWiFiClient
        ssid = CWWiFiClient.sharedWiFiClient().interface().ssid()
        if ssid:
            return ssid
    except Exception:
        pass

    iface = _wifi_iface()
    out = subprocess.run(
        ["networksetup", "-getairportnetwork", iface],
        capture_output=True, text=True,
    ).stdout
    m = re.search(r"Current Wi-Fi Network: (.+)", out)
    return m.group(1).strip() if m else None


def _copy(text: str):
    subprocess.run(["pbcopy"], input=text.encode(), check=True)


class WiFiScannerApp(rumps.App):
    def __init__(self):
        super().__init__(ICON, quit_button=None)

        self._lock             = threading.Lock()
        self._ssid:  str | None = None
        self._net:   str | None = None
        self._devices: list[dict] = []
        self._scanning           = False
        self._last_scan: float   = 0
        self._use_fallback       = False
        self._pending: tuple | None = None  # (devices, network, ssid)
        self._loc_item_added     = False

        # Static menu items
        self._status    = rumps.MenuItem("Not connected")
        self._scan_time = rumps.MenuItem("Last scan: —")
        self._dash_item = rumps.MenuItem(
            f"Open Dashboard  ↗  localhost:{DASH_PORT}",
            callback=self._open_dashboard,
        )
        self._rescan   = rumps.MenuItem("Rescan Now", callback=self._on_rescan)
        self._loc_item = rumps.MenuItem(
            "⚠️  Allow Location Access for SSID →",
            callback=self._open_location_settings,
        )
        self._quit = rumps.MenuItem("Quit", callback=rumps.quit_application)

        self._build_menu()

        # Start HTTP dashboard
        dashboard.start(store, self._dash_state,
                        on_known_change=self._refresh_devices_and_redraw,
                        port=DASH_PORT)

        # Main-thread timer to safely update NSMenu
        rumps.Timer(self._flush_pending, 0.5).start()
        rumps.Timer(self._check_location, 5).start()

        _request_location_permission()
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        self._trigger_scan()

    # ── Menu helpers ─────────────────────────────────────────────────────────

    def _build_menu(self):
        items = [self._status, self._scan_time, None, self._dash_item, None, self._rescan]
        self._loc_item_added = not _location_authorized()
        if self._loc_item_added:
            items += [None, self._loc_item]
        items += [None, self._quit]
        self.menu.clear()
        for item in items:
            self.menu.add(item)

    def _open_location_settings(self, _=None):
        subprocess.run(["open",
            "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices"])

    def _check_location(self, _=None):
        """Periodically remove the location warning item once permission is granted."""
        if self._loc_item_added and _location_authorized():
            self._build_menu()

    # ── Dashboard state ───────────────────────────────────────────────────────

    def _dash_state(self) -> dict:
        with self._lock:
            devices = list(self._devices)
            ssid    = self._ssid
            last    = self._last_scan
        enriched = []
        seen = store.all_seen
        for d in sorted(devices, key=lambda x: tuple(int(p) for p in x["ip"].split("."))):
            rec = seen.get(d["mac"], {})
            fp_hints = rec.get("fingerprint", {})
            enriched.append({
                "ip":          d["ip"],
                "mac":         d["mac"],
                "hostname":    d.get("hostname", "—"),
                "vendor":      d.get("vendor", "—"),
                "fingerprint": best_fingerprint(fp_hints),
                "latency":     d.get("latency"),
                "ports":       rec.get("ports", []),
                "first_seen":  rec.get("first_seen"),
                "is_known":    store.is_known(d["mac"]),
                "known_name":  store.known_name(d["mac"]),
                "me":          d.get("me", False),
            })
        return {
            "ssid":      ssid or "",
            "network":   self._net or "",
            "count":     len(devices),
            "last_scan": time.strftime("%H:%M:%S", time.localtime(last)) if last else "—",
            "devices":   enriched,
            "known":     store.known,
            "hook":      store.hook_script,
        }

    # ── Main-thread timer ─────────────────────────────────────────────────────

    def _flush_pending(self, _):
        with self._lock:
            pending = self._pending
            self._pending = None
        if pending:
            self._rebuild_menu(*pending)

    # ── SSID monitor ─────────────────────────────────────────────────────────

    def _monitor_loop(self):
        while True:
            ssid = _current_ssid()
            with self._lock:
                changed    = ssid != self._ssid
                self._ssid = ssid
                last       = self._last_scan

            if changed:
                if ssid:
                    self._trigger_scan()
                else:
                    self.title            = ICON
                    self._status.title    = "Not connected"
                    self._scan_time.title = "Last scan: —"
            elif ssid and (time.time() - last) > AUTO_RESCAN:
                self._trigger_scan()

            time.sleep(POLL_INTERVAL)

    # ── Scan lifecycle ────────────────────────────────────────────────────────

    def _trigger_scan(self):
        with self._lock:
            if self._scanning:
                return
            self._scanning = True
        self.title = f"{ICON} ···"
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self):
        try:
            iface, local_ip, network = get_wifi_info()
            with self._lock:
                ssid         = self._ssid
                use_fallback = self._use_fallback
                self._net    = network

            devices, use_fallback = do_scan(
                network, timeout=3, use_fallback=use_fallback, quiet=True
            )
            devices = enrich(devices, local_ip, skip_vendor=False)

            # Persist to store, detect new arrivals
            for d in devices:
                store.touch(d)

            with self._lock:
                prev_ips         = {d["ip"] for d in self._devices}
                self._devices    = devices
                self._last_scan  = time.time()
                self._use_fallback = use_fallback
                self._pending    = (devices, network, ssid or "Unknown")

            store.record_scan(len(devices), ssid or "")

            joined = {d["ip"] for d in devices} - prev_ips
            if joined and prev_ips:
                for ip in sorted(joined):
                    d = next((x for x in devices if x["ip"] == ip), {})
                    store.run_hook(d, ssid or "")

            self.title = f"{ICON} {len(devices)}"

            # Port scan in background — doesn't block menu update
            threading.Thread(
                target=self._bg_port_scan,
                args=(list(devices),),
                daemon=True,
            ).start()

        except Exception as e:
            self.title = f"{ICON} !"
        finally:
            with self._lock:
                self._scanning = False

    def _bg_port_scan(self, devices: list[dict]):
        seen = store.all_seen
        for d in devices:
            try:
                ports = scan_ports(d["ip"])
                store.update_ports(d["mac"], ports)
                # Skip identification probes if we already have a fingerprint —
                # avoids mDNS/SSDP/SMB chatter on every 5 s rescan.
                if seen.get(d["mac"], {}).get("fingerprint"):
                    continue
                hints = probe_device(d["ip"], d["mac"], ports)
                if hints:
                    store.update_fingerprint(d["mac"], hints)
            except Exception:
                pass

    # ── Menu rebuild (main thread only) ──────────────────────────────────────

    def _rebuild_menu(self, devices: list[dict], network: str, ssid: str):
        count = len(devices)
        self._status.title    = f"🌐  {ssid}  —  {network}"
        self._scan_time.title = f"Last scan: {time.strftime('%H:%M:%S')}  ·  {count} device(s)"

        sorted_devs = sorted(
            devices, key=lambda d: tuple(int(x) for x in d["ip"].split("."))
        )

        device_items = []
        for d in sorted_devs:
            ip      = d["ip"]
            is_known = d.get("is_known", False)
            is_me    = d.get("me", False)

            # Status emoji
            if is_me:       icon = "🔵"
            elif is_known:  icon = "🟢"
            else:           icon = "🔴"

            # Label
            name = d.get("known_name") or d.get("hostname", "")
            if name and name != "—":
                label = f"{icon}  {ip}  —  {name}"
            else:
                vendor = d.get("vendor", "")
                label  = f"{icon}  {ip}  —  {vendor}" if vendor and vendor != "—" else f"{icon}  {ip}"

            latency = d.get("latency")
            if latency is not None:
                label += f"  ({latency}ms)"

            # Each row has a submenu: copy IP, copy MAC, WoL, toggle known
            row = rumps.MenuItem(label)
            row["Copy IP"]  = rumps.MenuItem(f"Copy IP  {ip}",  callback=lambda _, v=ip:  _copy(v))
            row["Copy MAC"] = rumps.MenuItem(f"Copy MAC  {d['mac']}", callback=lambda _, v=d["mac"]: _copy(v))
            row["sep1"] = None

            if not is_me:
                if is_known:
                    row["unmark"] = rumps.MenuItem(
                        "Remove from Known",
                        callback=lambda _, m=d["mac"]: self._unmark_known(m),
                    )
                else:
                    row["mark"] = rumps.MenuItem(
                        "Mark as Known",
                        callback=lambda _, m=d["mac"], h=d.get("hostname", ""):
                            self._mark_known(m, h if h != "—" else ""),
                    )
                row["wol"] = rumps.MenuItem(
                    "Wake on LAN",
                    callback=lambda _, m=d["mac"]: self._send_wol(m),
                )

            device_items.append(row)

        self.menu.clear()
        self.menu.update(
            [self._status, self._scan_time, None]
            + device_items
            + [None, self._dash_item, None, self._rescan, None, self._quit]
        )

    # ── Known-device helpers (update store + immediately redraw menu) ─────────

    def _mark_known(self, mac: str, name: str = ""):
        store.add_known(mac, name)
        self._refresh_devices_and_redraw()

    def _unmark_known(self, mac: str):
        store.remove_known(mac)
        self._refresh_devices_and_redraw()

    def _refresh_devices_and_redraw(self):
        """Re-enrich in-memory devices with updated store data, then queue rebuild."""
        with self._lock:
            devices = list(self._devices)
            network = self._net or ""
            ssid    = self._ssid or "Unknown"
        for d in devices:
            d["is_known"]   = store.is_known(d["mac"])
            d["known_name"] = store.known_name(d["mac"])
        with self._lock:
            self._devices = devices
            self._pending = (devices, network, ssid)

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def _send_wol(self, mac: str):
        try:
            wake(mac)
        except Exception:
            pass

    def _open_dashboard(self, _):
        subprocess.run(["open", f"http://localhost:{DASH_PORT}"], check=False)

    def _on_rescan(self, _):
        self._trigger_scan()


if __name__ == "__main__":
    WiFiScannerApp().run()
