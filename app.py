#!/usr/bin/env python3
"""Inglorious Network Scanner — macOS menubar app."""

import os
import re
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Promote this Python process to a "menubar-only accessory" before anything
# else creates an NSApplication. Without this, the running process shows up
# as "Python" in the Dock, the app switcher (⌘-Tab), and the Force Quit
# dialog — confusing for an app that's only supposed to live in the menubar.
# Accessory policy = no Dock entry, no app switcher entry, menubar only.
try:
    from AppKit import NSApplication                                    # type: ignore
    NSApplication.sharedApplication().setActivationPolicy_(1)  # NSApplicationActivationPolicyAccessory
except ImportError:
    pass

import rumps
import actions
import classify
import dashboard
import detect
import events
import health
import igd
import notify
import security
import sniffer
import webhooks
from scanner import (
    do_scan, enrich, scan_ports, probe_device, best_fingerprint, get_wifi_info,
    clear_caches as clear_scanner_caches, NoNetworkError,
)
from store import DeviceStore
from updater import check_for_update
from version import GITHUB_REPO, __app_name__, __version__
from wol import wake

POLL_INTERVAL    = 5            # how often we re-check the SSID / scan timer
AUTO_RESCAN      = 30           # full rescan cadence on a quiescent network
PRESENCE_GRACE   = 300          # keep a device listed this long after it last responded
ICON             = "📡"
DASH_PORT        = 8765
UPDATE_INTERVAL  = 6 * 60 * 60  # check GitHub Releases every 6 h
WAN_REFRESH_INTERVAL = 30 * 60  # re-walk router IGD mappings every 30 min

# Subscribe alert notifications + webhooks at import time so they fire for
# any alert raised during a scan, no matter which thread raises it.
def _on_alert_raised(payload: dict):
    notify.notify_alert(payload)
    webhooks.dispatch(store, payload)

events.subscribe(events.ALERT_RAISED, _on_alert_raised)

IS_FROZEN = getattr(sys, "frozen", False)
PROJ_DIR  = os.path.dirname(os.path.abspath(__file__))


def _ensure_launchagent_uses_in_app_python():
    """Self-heal: when the launcher .app is installed but the LaunchAgent
    plist still points at the venv Python (pre-2.4.6 layout), re-run
    install.sh. macOS labels Location/TCC entries by the bundle containing
    the running executable — embedding Python inside the .app gets the
    proper "Inglorious Network Scanner" label instead of "Python".

    No-ops once install.sh has rewritten the plist to use the in-app Python.
    """
    if IS_FROZEN or sys.platform != "darwin":
        return
    bundle = "/Applications/Inglorious Network Scanner.app"
    plist  = os.path.expanduser("~/Library/LaunchAgents/co.ingloriouslabs.netscan.plist")
    install_sh = os.path.join(PROJ_DIR, "install.sh")
    if not (os.path.isdir(bundle) and os.path.isfile(plist) and os.path.isfile(install_sh)):
        return
    if not os.access("/Applications", os.W_OK):
        return  # install.sh wouldn't be able to refresh the in-app Python — avoid restart loop
    try:
        if bundle in open(plist).read():
            return
    except OSError:
        return
    subprocess.Popen(
        [install_sh], cwd=PROJ_DIR, start_new_session=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
    )
    sys.exit(0)


_ensure_launchagent_uses_in_app_python()

store = DeviceStore()
actions.wire(store)


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
    """Call requestWhenInUseAuthorization so INS appears in System Settings → Location Services."""
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


def _read_keep_alive_status() -> bool:
    """Source of truth for the "Keep in menubar" toggle: read the actual
    LaunchAgent plist rather than trusting the settings table. Lets us catch
    out-of-band edits made by an admin or by a previous install."""
    try:
        import launchd_agent
        return launchd_agent.get_keep_alive()
    except Exception:
        return False


def _local_computer_name() -> str:
    """Return this Mac's user-set Computer Name (e.g. "Sam's MacBook Pro").

    Falls back to `hostname` and finally an empty string. Never raises.
    """
    for cmd in (["scutil", "--get", "ComputerName"], ["hostname", "-s"]):
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=2, check=False,
            ).stdout.strip()
            if out:
                return out
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return ""


def _has_internal_battery() -> bool:
    """True if this Mac has a built-in battery (i.e. it's a laptop)."""
    try:
        out = subprocess.run(
            ["pmset", "-g", "batt"],
            capture_output=True, text=True, timeout=2, check=False,
        ).stdout
        return "InternalBattery" in out
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _local_mac_model() -> tuple[str, str]:
    """Return (device_type, vendor) for the running Mac.

    Wi-Fi MAC randomization (private addresses) means the OUI lookup yields
    nothing for the host running INS, and no fingerprint traffic is captured
    from self — so the generic classifier falls back to "unknown" for the
    user's own machine. `sysctl hw.model` + battery presence are the
    authoritative signals.
    """
    try:
        model = subprocess.run(
            ["sysctl", "-n", "hw.model"],
            capture_output=True, text=True, timeout=2, check=False,
        ).stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        model = ""
    if not model:
        return ("unknown", "")
    if model.startswith("MacBook"):
        return ("laptop", "Apple")
    # Apple Silicon Macs all report unified "MacN,M" identifiers regardless of
    # form factor (MacBook Air M2 = Mac14,2; Mac mini = Mac14,3), so the model
    # prefix alone can't tell a laptop from a desktop — every M-series MacBook
    # would otherwise be mislabeled "desktop". Battery presence is the reliable
    # discriminator: only laptops have an internal battery.
    if _has_internal_battery():
        return ("laptop", "Apple")
    if model.startswith(("iMac", "Macmini", "MacPro", "MacStudio", "Mac")):
        return ("desktop", "Apple")
    return ("computer", "Apple")


class InsApp(rumps.App):
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
        self._update_info: dict | None = None
        self._update_dirty       = False
        self._public_ip: str | None = None
        # AppKit menu-bar mutations must happen on the main thread. Worker
        # threads stage the desired title / status-item titles here; the
        # _flush_pending main-thread timer applies them. See _set_title.
        self._pending_title:  str | None = None
        self._pending_status: tuple | None = None  # (status_title, scan_time_title)
        self._last_scan_error: float = 0.0
        self._last_traceback_ts: float = 0.0   # rate-limits scan-failure tracebacks
        self._keep_alive_cache: bool | None = None  # cached LaunchAgent plist read
        self._keep_alive_ts: float = 0.0

        # Static menu items
        self._status    = rumps.MenuItem("Not connected")
        self._scan_time = rumps.MenuItem("Last scan: —")
        self._dash_item = rumps.MenuItem(
            f"Open Dashboard  ↗  localhost:{DASH_PORT}",
            callback=self._open_dashboard,
        )
        self._rescan    = rumps.MenuItem("Rescan Now", callback=self._on_rescan)
        self._alerts_item = rumps.MenuItem(
            "🚨  Open Security Alerts",
            callback=self._open_alerts,
        )
        self._loc_item = rumps.MenuItem(
            "⚠️  Allow Location Access for SSID →",
            callback=self._open_location_settings,
        )
        self._update_item = rumps.MenuItem(
            f"⬆️  Update available", callback=self._on_update_clicked,
        )
        self._quit = rumps.MenuItem(
            f"Quit  ·  {__app_name__} v{__version__}", callback=rumps.quit_application,
        )

        self._build_menu()

        # Start HTTP dashboard
        dashboard.start(store, self._dash_state,
                        on_known_change=self._refresh_devices_and_redraw,
                        on_rescan=self._trigger_scan,
                        port=DASH_PORT)

        # Main-thread timer to safely update NSMenu
        rumps.Timer(self._flush_pending, 0.5).start()
        rumps.Timer(self._check_location, 5).start()
        rumps.Timer(self._flush_update_item, 1).start()

        _request_location_permission()
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        threading.Thread(target=self._update_loop, daemon=True).start()
        threading.Thread(target=self._wan_refresh_loop, daemon=True).start()
        threading.Thread(target=self._start_sniffer_when_ready, daemon=True).start()
        self._trigger_scan()

    # ── Main-thread-safe menu-bar mutations ──────────────────────────────────

    def _set_title(self, title: str):
        """Stage a menu-bar title change for the main thread. Setting
        self.title directly mutates an NSStatusItem (AppKit), which is undefined
        behavior off the main thread — so every worker-thread title write goes
        through here and is applied by _flush_pending."""
        with self._lock:
            self._pending_title = title

    # ── Menu helpers ─────────────────────────────────────────────────────────

    def _build_menu(self):
        items = []
        if self._update_info:
            items += [self._update_item, None]
        items += [
            self._status, self._scan_time, None,
            self._alerts_item, self._dash_item, None,
            self._rescan,
        ]
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
        # Batch-fetch everything once per state build instead of issuing 3
        # queries per device: bandwidth in one query, the known-device map once,
        # and the WAN mappings once (grouped by internal IP). The per-device
        # is_known/known_name/wan_mappings_for round-trips this replaces were the
        # hot cost of /api/state, which rebuilds on every scan (~30s) per tab.
        bw_recent = store.bandwidth_recent(since_seconds=1800)
        known_map = store.known                 # {mac: {name, added}}
        wan_all   = store.wan_mappings()         # list incl. internal_ip
        wan_by_ip: dict[str, list] = {}
        for m in wan_all:
            wan_by_ip.setdefault(m.get("internal_ip"), []).append(m)
        for d in sorted(devices, key=lambda x: tuple(int(p) for p in x["ip"].split("."))):
            rec = seen.get(d["mac"], {})
            fp_hints = rec.get("fingerprint", {})
            dtype = rec.get("device_type", "unknown")
            samples = bw_recent.get((d["mac"] or "").upper(), [])
            kn = known_map.get(d["mac"])
            enriched.append({
                "ip":              d["ip"],
                "mac":             d["mac"],
                "hostname":        d.get("hostname", "—"),
                "vendor":          d.get("vendor", "—"),
                "fingerprint":     best_fingerprint(fp_hints),
                "latency":         d.get("latency"),
                "ports":           rec.get("ports", []),
                "first_seen":      rec.get("first_seen"),
                "is_known":        kn is not None,
                "known_name":      kn["name"] if kn else "",
                "me":              d.get("me", False),
                "device_type":     dtype,
                "type_label":      classify.label(dtype),
                "type_icon":       classify.icon(dtype),
                "type_confidence": rec.get("type_confidence", 0.0),
                "no_probe":        rec.get("no_probe", False),
                "wan_exposed":     wan_by_ip.get(d.get("ip", ""), []),
                "bw_samples":      samples,  # [(ts, in, out), ...] last 30 min
                "present":         d.get("present", True),
                "last_seen":       d.get("last_seen") or rec.get("last_seen"),
            })
        # Triage queue = unknown, non-self devices, ordered newest first.
        triage = sorted(
            [d for d in enriched
             if not d["is_known"] and not d["me"] and d.get("present", True)],
            key=lambda d: -(d.get("first_seen") or 0),
        )
        return {
            "ssid":       ssid or "",
            "network":    self._net or "",
            "public_ip":  self._public_ip or "",
            "count":      len(devices),
            "last_scan":  time.strftime("%H:%M:%S", time.localtime(last)) if last else "—",
            "last_scan_epoch": last or 0,            # numeric, for staleness checks
            "last_scan_error": self._last_scan_error, # epoch of last scan failure, 0 if none
            "devices":    enriched,
            "triage":     triage,
            "known":      known_map,
            "hook":       store.hook_script,
            "alerts":     store.alerts(limit=50),
            "unack_count": store.unack_alert_count(),
            "webhooks":   store.webhooks(),
            "health":     store.latest_health() or self._compute_and_store_health(
                              [d for d in enriched if d.get("present", True)]),
            "wan_mappings": wan_all,
            "settings": self._settings_for_dashboard(),
            "sniffer":   sniffer.status(),
            "app_name":   __app_name__,
            "version":    __version__,
        }

    def _settings_for_dashboard(self) -> dict:
        """Assemble the dashboard settings block from ONE settings query plus a
        cached keep-alive read. _dash_state runs on every /api/state (per tab,
        per SSE tick, plus the poll fallback), so the old form — ~10 separate
        get_setting() round-trips and a plistlib.load of the LaunchAgent plist
        from disk every time — was pure per-request overhead. router_pass is
        deliberately never surfaced here."""
        s = store.all_settings()
        return {
            "voice_enabled":          s.get("voice_enabled", "0") == "1",
            "shortcut_on_new_device": s.get("shortcut_on_new_device", ""),
            "shortcut_on_alert":      s.get("shortcut_on_alert", ""),
            "first_run_done":         s.get("first_run_done", "0") == "1",
            "router_kind":            s.get("router_kind", "none"),
            "router_host":            s.get("router_host", ""),
            "router_user":            s.get("router_user", ""),
            "router_site":            s.get("router_site", "default"),
            "router_ssh_port":        s.get("router_ssh_port", "22"),
            "router_iface":           s.get("router_iface", "0"),
            "router_verify_tls":      s.get("router_verify_tls", "0") == "1",
            "keep_alive":             self._cached_keep_alive(),
        }

    def _cached_keep_alive(self) -> bool:
        """Keep-alive reflects the on-disk LaunchAgent plist, which only changes
        when the user toggles it. Cache the parsed value for a few seconds so
        /api/state doesn't stat + plistlib.load the plist on every request."""
        now = time.time()
        with self._lock:
            if self._keep_alive_cache is not None and (now - self._keep_alive_ts) < 10:
                return self._keep_alive_cache
        val = _read_keep_alive_status()
        with self._lock:
            self._keep_alive_cache = val
            self._keep_alive_ts    = now
        return val

    def _compute_and_store_health(self, enriched_devices: list[dict],
                                  dhcp_servers: list | None = None) -> dict:
        # Reuse the caller's rogue-DHCP snapshot when provided (the scan loop
        # computes it once per cycle) instead of recomputing the full-table
        # aggregate here as well.
        if dhcp_servers is None:
            dhcp_servers = detect.rogue_dhcp_servers(store)
        result = health.compute(
            devices       = enriched_devices,
            unack_alerts  = store.alerts(unacknowledged_only=True, limit=200),
            wan_mappings  = store.wan_mappings(),
            dhcp_servers  = dhcp_servers,
        )
        store.record_health(result["score"], result["reasons"])
        result["ts"] = time.time()
        return result

    # ── Main-thread timer ─────────────────────────────────────────────────────

    def _flush_pending(self, _):
        with self._lock:
            pending = self._pending
            self._pending = None
            title  = self._pending_title
            self._pending_title = None
            status = self._pending_status
            self._pending_status = None
        # Apply staged menu-bar mutations on the main thread. Title and status
        # are applied independently of the device-tuple rebuild so a
        # "not connected" state (no device tuple) still updates.
        if title is not None:
            self.title = title
        if status is not None:
            self._status.title, self._scan_time.title = status
        if pending:
            self._rebuild_menu(*pending)

    # ── SSID monitor ─────────────────────────────────────────────────────────

    def _monitor_loop(self):
        """Trigger rescans periodically.

        Two trigger paths:
          1. SSID changed (we connected, disconnected, or moved networks).
          2. AUTO_RESCAN seconds passed since the last scan.

        Critically, path 2 runs whether or not we successfully detected an
        SSID. macOS 14+ ties SSID reads to Location Services authorization;
        without that grant, _current_ssid() returns "" — but the scan itself
        only needs the interface IP/CIDR, which get_wifi_info() reads from
        ifconfig (no permission required). So we keep scanning even when we
        can't name the network. _run_scan handles "no WiFi interface" by
        marking the title with "!" and returning silently.
        """
        while True:
            ssid = _current_ssid()
            with self._lock:
                changed    = ssid != self._ssid
                self._ssid = ssid
                last       = self._last_scan

            if changed and not ssid:
                self._set_title(ICON)
                with self._lock:
                    self._pending_status = ("Not connected", "Last scan: —")

            if changed and ssid:
                self._trigger_scan()
            elif (time.time() - last) > AUTO_RESCAN:
                self._trigger_scan()

            time.sleep(POLL_INTERVAL)

    # ── Scan lifecycle ────────────────────────────────────────────────────────

    def _trigger_scan(self):
        with self._lock:
            if self._scanning:
                return
            self._scanning = True
        self._set_title(f"{ICON} ···")
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self):
        try:
            iface, local_ip, network = get_wifi_info()
            with self._lock:
                ssid         = self._ssid
                use_fallback = self._use_fallback
                prev_net     = self._net
                self._net    = network
                net_changed  = network != prev_net
                if net_changed:
                    # Drop the previous network's devices so none of them get
                    # carried over (with stale wrong-subnet IPs) into the new
                    # network's list during the grace window.
                    self._devices = []
            if net_changed:
                # The network identity changed (roamed, switched SSID, or the
                # subnet changed). Drop the per-IP enrichment caches so a
                # colliding IP (e.g. 192.168.1.10 on both home and office
                # /24s) can't show the previous network's hostname/latency.
                clear_scanner_caches()

            devices, use_fallback = do_scan(
                network, timeout=3, use_fallback=use_fallback, quiet=True,
                iface_ip=local_ip, iface=iface,
            )
            devices = enrich(devices, local_ip, skip_vendor=False, iface=iface)

            # Load the known-device map and the stored-device records ONCE for
            # the whole loop instead of querying is_known/known_name/get_device
            # per device (the loop runs for every device on every scan). The
            # fingerprint/ports we read from `seen0` are written by the sniffer
            # and the previous scan's background port-scan, so a snapshot taken
            # here is current for classification.
            known = store.known
            seen0 = store.all_seen

            # Persist to store; this also stamps _is_new / _vendor_changed.
            self_type, self_vendor = ("unknown", "")
            for d in devices:
                # For the local Mac we know the platform authoritatively:
                # Wi-Fi MAC randomization breaks OUI lookup, and no scanner
                # fingerprint traffic ever comes back from self, so the
                # generic classifier always falls back to "unknown" without
                # these overrides. Apply them before `touch` so the right
                # vendor lands in the device row.
                if d.get("me"):
                    if self_type == "unknown":
                        self_type, self_vendor = _local_mac_model()
                    if self_vendor and d.get("vendor", "—") in ("", "—"):
                        d["vendor"] = self_vendor
                store.touch(d, known=known)
                # Auto-name the local Mac on first sighting. Safe to mark Known —
                # it's literally the host running INS. Idempotent: only fires if
                # the user hasn't already Known-marked it (possibly with a name
                # they prefer).
                if d.get("me") and d["mac"] not in known:
                    name = _local_computer_name()
                    if name:
                        store.add_known(d["mac"], name)
                # Classify on every scan — cheap, and lets the type refine
                # as ports/fingerprints come in over subsequent rescans.
                stored = seen0.get(d["mac"], {})
                fp_hints = stored.get("fingerprint", {}) or {}
                fp_str   = best_fingerprint(fp_hints)
                d["fp_name"] = fp_str   # attach so the menu rebuild needn't re-query
                # DHCP option 55 lets us still identify devices behind a
                # randomised MAC — let it patch the empty vendor column.
                dhcp_vendor_hint = classify.dhcp_vendor(fp_hints)
                if dhcp_vendor_hint and d.get("vendor", "—") in ("", "—"):
                    d["vendor"] = dhcp_vendor_hint
                dtype, conf = classify.classify(
                    vendor=d.get("vendor", ""),
                    fingerprint=fp_str,
                    ports=stored.get("ports", []),
                    hostname=d.get("hostname", ""),
                    hints=fp_hints,
                )
                if d.get("me") and self_type != "unknown":
                    dtype, conf = self_type, 1.0
                store.update_device_type(d["mac"], dtype, conf)
                d["device_type"]     = dtype
                d["type_confidence"] = conf
                d["ports"]           = stored.get("ports", [])  # for the health score

            now = time.time()
            for d in devices:
                d["present"]   = True
                d["last_seen"] = now

            # Carry over devices that were seen very recently but missed by THIS
            # sweep. ARP/mDNS are probabilistic, and a full-tunnel VPN or a
            # sleeping phone routinely drops a response — without this, a still
            # connected device flickers out of the list every time a sweep
            # misses it. Carried devices keep their last-known data, are marked
            # not-present, and age out after PRESENCE_GRACE seconds of silence.
            with self._lock:
                prev_devices = list(self._devices)
            cur_macs = {d["mac"] for d in devices}
            carried = []
            for pd in prev_devices:
                if pd["mac"] in cur_macs:
                    continue
                if pd.get("me"):
                    # The host itself is discovered only intermittently (it never
                    # answers its own ARP sweep). Keep it shown as PRESENT, never
                    # 💤/away — it's literally this machine, always on the LAN.
                    pd = dict(pd)
                    pd["present"]   = True
                    pd["last_seen"] = now
                    carried.append(pd)
                    continue
                last = pd.get("last_seen") or seen0.get(pd["mac"], {}).get("last_seen", 0)
                if last and (now - last) <= PRESENCE_GRACE:
                    pd = dict(pd)
                    pd["present"] = False
                    carried.append(pd)
            display = devices + carried

            with self._lock:
                # All MACs we knew last scan — present AND carried-away. A device
                # "joins" only when its MAC is new to this set.
                prev_macs        = {x["mac"] for x in self._devices}
                self._devices    = display
                self._last_scan  = now
                self._use_fallback = use_fallback
                self._pending    = (display, network, ssid or "Unknown")

            # Record the stable population (present + recently-seen) so the
            # history chart and menu-bar count don't dip every time a sweep
            # misses a still-connected device.
            store.record_scan(len(display), ssid or "")

            # Compute the network-wide detectors ONCE per scan cycle and reuse
            # them for both the health score and the network-scope alerts. Each
            # is a full-table aggregate over the devices/sightings/dhcp tables;
            # the old code recomputed rogue_dhcp_servers/arp_anomalies/
            # fingerprint_groups separately in health and in alert evaluation
            # (and alert evaluation ran twice per cycle), so this collapses
            # several redundant scans into one.
            try:
                dhcp_servers  = detect.rogue_dhcp_servers(store)
                arp_anomalies = detect.arp_anomalies(store)
                fp_groups     = detect.fingerprint_groups(store)
            except Exception:
                dhcp_servers, arp_anomalies, fp_groups = [], [], []

            # Security rules + port scans run on the devices ACTUALLY seen this
            # sweep — carried-over devices carry no new information.
            self._evaluate_device_alerts(devices, new_ports_by_mac={})
            self._evaluate_network_alerts(dhcp_servers, arp_anomalies, fp_groups)

            # Recompute the health score every scan from the devices PRESENT now
            # (not carried-away ones, which would keep dragging the score down
            # after they left). Computing it here also fixes the staleness where
            # _dash_state's `latest_health() or compute` only ever computed once.
            try:
                self._compute_and_store_health(devices, dhcp_servers=dhcp_servers)
            except Exception:
                pass

            # Join detection keys off MAC, not IP: a returning away-device
            # (known MAC) isn't a join, and a genuinely new device isn't missed
            # just because DHCP reused a carried device's IP within the grace
            # window. `prev_macs` empty = first populated scan → suppress the
            # join firehose.
            joined_devs = [d for d in devices if d["mac"] not in prev_macs]
            if joined_devs and prev_macs:
                for d in sorted(joined_devs, key=lambda x: x.get("ip", "")):
                    store.run_hook(d, ssid or "")
                    events.publish(events.DEVICE_JOINED, {"device": d, "ssid": ssid})

            events.publish(events.SCAN_COMPLETED,
                           {"count": len(display), "ssid": ssid or ""})

            self._set_title(f"{ICON} {len(display)}")

            # Port scan in background — doesn't block menu update
            threading.Thread(
                target=self._bg_port_scan,
                args=(list(devices),),
                daemon=True,
            ).start()

        except NoNetworkError:
            # Wi-Fi briefly unavailable (sleep, VPN transition, roaming). Keep
            # the current list (the grace period preserves devices) and retry on
            # the next poll. _monitor_loop owns the "Not connected" state when
            # Wi-Fi is actually down, so stay quiet here — no log spam, no
            # thread death (the old sys.exit killed the scan thread).
            pass
        except Exception:
            # A recurring scan failure is otherwise invisible — just a silent
            # "!" in the menu bar. Log the traceback to /tmp/ins.err and stamp
            # the time so the dashboard can surface "scanning is broken" — but
            # rate-limit it so a persistent failure can't flood the log.
            now = time.time()
            if now - self._last_traceback_ts >= 300:
                self._last_traceback_ts = now
                import traceback
                traceback.print_exc()
            with self._lock:
                self._last_scan_error = now
            self._set_title(f"{ICON} !")
        finally:
            with self._lock:
                self._scanning = False

    def _bg_port_scan(self, devices: list[dict]):
        seen = store.all_seen
        new_ports_by_mac: dict[str, list[int]] = {}
        for d in devices:
            # Respect the user's "don't probe this device" flag — for fragile
            # IoT/printers we've previously crashed by port-scanning.
            if seen.get(d["mac"], {}).get("no_probe"):
                continue
            try:
                ports = scan_ports(d["ip"])
                newly_opened = store.update_ports(d["mac"], ports)
                if newly_opened:
                    new_ports_by_mac[d["mac"]] = newly_opened
                # Skip identification probes if we already have a fingerprint —
                # avoids mDNS/SSDP/SMB chatter on every 5 s rescan.
                if seen.get(d["mac"], {}).get("fingerprint"):
                    continue
                hints = probe_device(d["ip"], d["mac"], ports)
                if hints:
                    store.update_fingerprint(d["mac"], hints)
                    # Re-classify with the fresh fingerprint.
                    dtype, conf = classify.classify(
                        vendor=d.get("vendor", ""),
                        fingerprint=best_fingerprint(hints),
                        ports=ports,
                        hostname=d.get("hostname", ""),
                    )
                    store.update_device_type(d["mac"], dtype, conf)
                    d["device_type"]     = dtype
                    d["type_confidence"] = conf
            except Exception:
                pass

        if new_ports_by_mac:
            # Re-run security rules for devices with newly-opened ports.
            updated = []
            for d in devices:
                if d["mac"] in new_ports_by_mac:
                    fresh = store.get_device(d["mac"]) or {}
                    fresh.update({k: d.get(k) for k in ("ip", "hostname", "vendor")})
                    fresh["is_known"]   = store.is_known(d["mac"])
                    fresh["known_name"] = store.known_name(d["mac"])
                    fresh["mac"]        = d["mac"]
                    fresh["me"]         = d.get("me", False)
                    updated.append(fresh)
            # Only per-device rules here — a newly-opened port doesn't change the
            # network-scope detectors, which the main scan loop already ran.
            self._evaluate_device_alerts(updated, new_ports_by_mac)

    def _dispatch_alert(self, alert) -> None:
        """Persist one Alert with atomic same-day dedup, and publish it to the
        event bus (notifications / webhooks / SSE / voice / shortcuts) only if it
        was actually inserted — never a duplicate. The insert+dedup is one lock
        hold in the store, so two overlapping evaluator threads can't both fire
        the same alert (which would double-POST every webhook)."""
        alert_id = store.add_alert_if_new_today(
            kind=alert.kind, severity=alert.severity,
            title=alert.title, message=alert.message, mac=alert.mac,
        )
        if alert_id is None:
            return
        payload = alert.as_dict() | {"id": alert_id, "ts": time.time()}
        events.publish(events.ALERT_RAISED, payload)

    def _evaluate_device_alerts(
        self, devices: list[dict], new_ports_by_mac: dict[str, list[int]]
    ):
        """Run per-device security rules; persist + dispatch each Alert."""
        for d in devices:
            mac = d.get("mac")
            new_ports = new_ports_by_mac.get(mac, [])
            wan_for_d = store.wan_mappings_for(d.get("ip", ""))
            for alert in security.evaluate(
                d, new_ports=new_ports, wan_mappings=wan_for_d
            ):
                self._dispatch_alert(alert)

    def _evaluate_network_alerts(self, dhcp_servers, arp_anomalies, fingerprint_groups):
        """Run network-scope security rules against precomputed detector output
        (the scan loop computes each detector once per cycle and threads it
        through, instead of re-running the full-table aggregates here)."""
        try:
            net_alerts = security.evaluate_network(
                dhcp_servers       = dhcp_servers,
                arp_anomalies      = arp_anomalies,
                fingerprint_groups = fingerprint_groups,
            )
        except Exception:
            net_alerts = []
        for alert in net_alerts:
            self._dispatch_alert(alert)

    # ── Menu rebuild (main thread only) ──────────────────────────────────────

    def _rebuild_menu(self, devices: list[dict], network: str, ssid: str):
        count = len(devices)
        self._status.title    = f"🌐  {ssid}  —  {network}"
        self._scan_time.title = f"Last scan: {time.strftime('%H:%M:%S')}  ·  {count} device(s)"
        unack = store.unack_alert_count()
        self._alerts_item.title = (
            f"🚨  Security Alerts  ·  {unack} unread" if unack
            else "🛡  Security Alerts  ·  all clear"
        )

        sorted_devs = sorted(
            devices, key=lambda d: tuple(int(x) for x in d["ip"].split("."))
        )

        device_items = []
        for d in sorted_devs:
            ip      = d["ip"]
            is_known = d.get("is_known", False)
            is_me    = d.get("me", False)

            present = d.get("present", True)

            # Status emoji — is_me always wins (never show your own machine as
            # away); 💤 for a device seen recently but missing from the latest
            # sweep (kept in the list during the grace window).
            if is_me:         icon = "🔵"
            elif not present: icon = "💤"
            elif is_known:    icon = "🟢"
            else:             icon = "🔴"

            # Label — same name-resolution order as the dashboard:
            # known_name > probe fingerprint > hostname > vendor > bare IP.
            # fp_name was computed during the scan (see _run_scan), so the
            # main-thread menu rebuild doesn't re-query the store per device.
            name = d.get("known_name") or d.get("fp_name") or ""
            if not name:
                hn = d.get("hostname") or ""
                if hn and hn != "—":
                    name = hn.rstrip(".").removesuffix(".local")
            if name:
                label = f"{icon}  {ip}  —  {name}"
            else:
                vendor = d.get("vendor", "")
                label  = f"{icon}  {ip}  —  {vendor}" if vendor and vendor != "—" else f"{icon}  {ip}"

            if not present:
                label += "  ·  away"
            elif d.get("latency") is not None:
                label += f"  ({d['latency']}ms)"

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
        head = [self._update_item, None] if self._update_info else []
        self.menu.update(
            head
            + [self._status, self._scan_time, None]
            + device_items
            + [None, self._alerts_item, self._dash_item,
               None, self._rescan, None, self._quit]
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
        known = store.known   # one query, not 2 per device
        for d in devices:
            kn = known.get(d["mac"])
            d["is_known"]   = kn is not None
            d["known_name"] = kn.get("name", "") if kn else ""
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

    def _open_alerts(self, _):
        subprocess.run(["open", f"http://localhost:{DASH_PORT}/#alerts"], check=False)

    def _on_rescan(self, _):
        self._trigger_scan()

    # ── WAN port-mapping refresh ─────────────────────────────────────────────

    def _wan_refresh_loop(self):
        """Periodically ask the router (via UPnP IGD) which LAN devices are
        exposed to the WAN side, and persist the snapshot so health/security
        rules can react. Best-effort: most routers either don't speak IGD or
        have it disabled (which is the safer state)."""
        time.sleep(20)  # let the first scan settle before bothering the router
        while True:
            try:
                igd_meta = igd.discover_igd(timeout=2.0)
                if igd_meta:
                    mappings = igd.list_port_mappings(igd_meta)
                    store.record_wan_mappings(mappings)
                    # All LAN devices share one external IPv4 via NAT — surface
                    # it once in the dashboard header. UPnP-sourced so no
                    # third-party echo service is involved.
                    ip = igd.get_external_ip(igd_meta)
                    if ip:
                        with self._lock:
                            self._public_ip = ip
            except Exception:
                pass
            time.sleep(WAN_REFRESH_INTERVAL)

    # ── Sniffer bootstrap ────────────────────────────────────────────────────

    def _start_sniffer_when_ready(self):
        """Wait for the first scan so we know our interface + local MAC, then
        start the passive sniffer. Never raises — failure is recorded in
        sniffer.status() and surfaced by the dashboard."""
        for _ in range(60):  # up to 60s
            try:
                iface, local_ip, _ = get_wifi_info()
            except Exception:
                time.sleep(1)
                continue
            local_mac = self._local_mac_for(iface)
            sniffer.start(store, iface=iface, local_mac=local_mac)
            return

    def _local_mac_for(self, iface: str) -> str:
        try:
            out = subprocess.run(
                ["ifconfig", iface], capture_output=True, text=True, timeout=2,
            ).stdout
            m = re.search(r"ether ([0-9a-f:]{17})", out)
            return m.group(1).upper() if m else ""
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ""

    # ── Update check ──────────────────────────────────────────────────────────

    def _update_loop(self):
        # First check 10 s after startup so the menubar settles first.
        time.sleep(10)
        while True:
            info = check_for_update(__version__)
            with self._lock:
                changed = info != self._update_info
                self._update_info = info
                if changed:
                    self._update_dirty = True
            # Piggyback periodic device-table pruning on this slow loop so a
            # long-running install (weeks between restarts) doesn't accumulate
            # unbounded rows from Wi-Fi MAC randomization. Known devices are kept.
            try:
                store.prune_old_devices()
            except Exception:
                pass
            time.sleep(UPDATE_INTERVAL)

    def _flush_update_item(self, _):
        """Main-thread: relabel the update item and rebuild the menu when info changes."""
        with self._lock:
            if not self._update_dirty:
                return
            self._update_dirty = False
            info = self._update_info
        if info:
            self._update_item.title = f"⬆️  Update available  ·  v{info['tag']}"
        # Force a menu rebuild — either with current devices or empty state.
        with self._lock:
            devices = list(self._devices)
            network = self._net or ""
            ssid    = self._ssid or "Unknown"
            self._pending = (devices, network, ssid) if devices else None
        if not devices:
            self._build_menu()

    def _on_update_clicked(self, _=None):
        info = self._update_info
        if not info:
            return

        # Frozen .app builds can't git-pull; just open the release page.
        if IS_FROZEN:
            subprocess.run(["open", info["url"]], check=False)
            return

        ok = rumps.alert(
            title=f"Update {__app_name__}",
            message=f"Update to v{info['tag']} and restart?\n\n"
                    f"Lands exactly on the v{info['tag']} release, then restarts.\n"
                    f"Log: /tmp/ins-update.log",
            ok="Update", cancel="Cancel",
        )
        if ok != 1:
            return

        script = os.path.join(PROJ_DIR, "update.sh")
        if not os.path.isfile(script):
            rumps.alert("Update failed", f"update.sh not found at {script}")
            return

        # Clear any stale result so the watcher only reacts to THIS run.
        try:
            os.remove("/tmp/ins-update.status")
        except OSError:
            pass

        # Detach so the script survives launchctl kickstart -k killing this
        # process. Pass the release tag so it lands on exactly what we offered.
        subprocess.Popen(
            [script, info["tag"]],
            cwd=PROJ_DIR,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        # On success update.sh restarts us (this thread dies with the process);
        # on failure we survive, so watch for a "fail" status and surface it
        # instead of leaving the user clicking a dead Update item.
        threading.Thread(target=self._watch_update_result, daemon=True).start()

    def _watch_update_result(self):
        # Poll well past a cold dependency install (scapy + pyobjc can take a few
        # minutes on a cache miss) — the old ~60s budget could exit before a slow
        # failure wrote its status, so the failure notification never fired. On
        # success update.sh restarts us and this daemon thread dies anyway.
        for _ in range(360):                        # up to ~12 min
            time.sleep(2)
            try:
                with open("/tmp/ins-update.status") as f:
                    status = f.read().strip()
            except OSError:
                continue
            if status.startswith("fail"):
                # osascript runs out-of-process, so it's safe from this thread.
                subprocess.run(
                    ["osascript", "-e",
                     'display notification "Update failed — see /tmp/ins-update.log" '
                     f'with title "{__app_name__}"'],
                    check=False,
                )
                return
            if status.startswith("ok"):
                return


if __name__ == "__main__":
    InsApp().run()
