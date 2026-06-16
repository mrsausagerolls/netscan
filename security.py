"""Security analyzer — turns scan facts into plain-English alerts.

Rule philosophy: an alert is only useful if a non-technical user can act on it.
Each rule produces (severity, title, message) tuples where:

  - title is short enough for a notification banner (< 60 chars)
  - message ends with a suggested action ("If this isn't yours, …")
  - severity is 'info', 'warning', or 'critical'

Rules are pure functions of the device + scan context; the caller persists
results and dispatches notifications/webhooks. Keep them deterministic so
the same scan never alerts twice (the store dedups on (mac, kind, day)).
"""

import time
from dataclasses import dataclass

import classify


# ── Port reference data ─────────────────────────────────────────────────────

# Ports that are dangerous to expose on a home network. Each entry: severity + reason.
_RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    # port: (severity, label, why)
    23:    ("critical", "Telnet",
            "Telnet sends passwords in plain text. Almost no modern device should have this on."),
    21:    ("warning",  "FTP",
            "FTP also sends passwords in plain text. SFTP (port 22) is the safer alternative."),
    513:   ("critical", "rlogin",
            "rlogin is a legacy remote-login protocol with no encryption. Treat this as malware unless you put it there."),
    514:   ("critical", "rsh",
            "rsh runs commands with no authentication. Treat this as suspicious."),
    111:   ("warning",  "RPC portmapper",
            "RPC has a long history of remote exploits. Only safe if you specifically configured a file server."),
    2049:  ("warning",  "NFS",
            "NFS file sharing. Fine inside your LAN, but the share itself should require authentication."),
    3389:  ("warning",  "Microsoft Remote Desktop",
            "RDP is a frequent target for brute-force attacks. Disable it unless you actively use it."),
    5900:  ("warning",  "VNC",
            "VNC remote desktop. Older versions have weak or no passwords by default."),
    6667:  ("warning",  "IRC",
            "IRC server port. Sometimes a sign of botnet command-and-control on a home network."),
    1080:  ("warning",  "SOCKS proxy",
            "Open proxy — can be used by anyone in your LAN to bounce traffic through this device."),
}

# ── Data model ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Alert:
    kind:     str
    severity: str       # info / warning / critical
    title:    str
    message:  str
    mac:      str | None = None

    def as_dict(self) -> dict:
        return {
            "kind": self.kind, "severity": self.severity,
            "title": self.title, "message": self.message, "mac": self.mac,
        }


# ── Rules ───────────────────────────────────────────────────────────────────

def _device_label(device: dict) -> str:
    """Friendly label like 'iPhone-of-Sam (192.168.1.45)' or fall back to MAC."""
    name = device.get("known_name") or ""
    if not name:
        hn = device.get("hostname") or ""
        if hn and hn != "—":
            name = hn
    if not name:
        vendor = device.get("vendor") or ""
        if vendor and vendor != "—":
            name = vendor
    ip = device.get("ip") or device.get("mac") or "?"
    return f"{name} ({ip})" if name else ip


def check_new_device(device: dict) -> Alert | None:
    """Fire when a brand-new MAC appears on the network."""
    if not device.get("_is_new"):
        return None
    if device.get("is_known"):
        return None  # marked known already — possibly via another channel
    if device.get("me"):
        return None  # never alert on the host itself

    label_text = _device_label(device)
    dtype = device.get("device_type", "unknown")
    type_phrase = classify.label(dtype).lower() if dtype != "unknown" else "device"

    return Alert(
        kind="new_device",
        severity="info",
        title=f"New {type_phrase} joined: {label_text}",
        message=(
            f"A {type_phrase} you haven't seen before is now on your WiFi. "
            f"MAC {device.get('mac')}. "
            "If this is yours, you can mark it as Known from the dashboard. "
            "If you don't recognize it, change your WiFi password and remove it from the router."
        ),
        mac=device.get("mac"),
    )


def check_vendor_change(device: dict) -> Alert | None:
    """A MAC's vendor changing strongly suggests MAC-address spoofing."""
    old = device.get("_vendor_changed")
    if not old:
        return None
    new = device.get("vendor", "?")
    return Alert(
        kind="vendor_changed",
        severity="critical",
        title=f"Hardware mismatch on {_device_label(device)}",
        message=(
            f"This device's MAC address used to belong to {old}, "
            f"but now reports {new}. "
            "A device's hardware fingerprint shouldn't change. "
            "This usually means someone is pretending to be one of your devices to bypass network controls. "
            "Change your WiFi password and remove unknown devices from the router."
        ),
        mac=device.get("mac"),
    )


def check_risky_ports(device: dict, new_ports: list[int]) -> list[Alert]:
    """Flag insecure protocols on newly-opened ports (or first sighting)."""
    alerts: list[Alert] = []
    label_text = _device_label(device)
    for port in new_ports:
        if port in _RISKY_PORTS:
            sev, proto, why = _RISKY_PORTS[port]
            alerts.append(Alert(
                kind=f"risky_port_{port}",
                severity=sev,
                title=f"{proto} open on {label_text}",
                message=(
                    f"Port {port} ({proto}) is open. {why} "
                    "If you don't know why this is on, unplug the device and reset it to factory defaults."
                ),
                mac=device.get("mac"),
            ))
    return alerts


def check_default_creds(device: dict) -> Alert | None:
    """Vendor-based heuristic: known-bad default credentials in shipped firmware."""
    vendor = (device.get("vendor") or "").lower()
    dtype  = device.get("device_type", "unknown")
    ports  = set(device.get("ports", []))

    has_admin_panel = bool(ports & {80, 443, 8080})
    if not has_admin_panel:
        return None

    bad_default_vendors = {
        "hikvision":       "admin / 12345",
        "dahua":           "admin / admin",
        "xiongmai":        "admin / (blank)",
        "foscam":          "admin / (blank)",
    }
    for needle, creds in bad_default_vendors.items():
        if needle in vendor:
            return Alert(
                kind="default_creds_risk",
                severity="warning",
                title=f"Default-password risk on {_device_label(device)}",
                message=(
                    f"This {classify.label(dtype).lower()} ships with default credentials ({creds}) "
                    "and exposes a web admin page. If you've never changed the password, "
                    "anyone on the same network can take it over. "
                    "Open its IP address in a browser and set a strong password right now."
                ),
                mac=device.get("mac"),
            )
    return None


def check_admin_panel_for_camera(device: dict) -> Alert | None:
    """Camera with web admin and no HTTPS — common, worth a one-time nudge."""
    if device.get("device_type") != "camera":
        return None
    ports = set(device.get("ports", []))
    if 80 in ports and 443 not in ports:
        return Alert(
            kind="camera_no_https",
            severity="info",
            title=f"Camera admin page is HTTP-only on {_device_label(device)}",
            message=(
                "This camera's admin page is not encrypted (HTTP, not HTTPS). "
                "Anyone on your network can sniff the password when you log in. "
                "If the camera has an HTTPS option, enable it; otherwise consider replacing it."
            ),
            mac=device.get("mac"),
        )
    return None


# ── Network-wide rules ──────────────────────────────────────────────────────

def check_wan_exposed_ports(device: dict, wan_mappings: list[dict]) -> list[Alert]:
    """The router has a WAN port-forward pointing at this device.

    `wan_mappings` is the list returned by store.wan_mappings_for(ip).
    Empty list → no exposure (return []). Non-empty → one alert per mapping,
    with severity escalated to critical for cameras and unencrypted protocols.
    """
    alerts: list[Alert] = []
    if not wan_mappings:
        return alerts
    dtype = device.get("device_type", "unknown")
    label_text = _device_label(device)
    for m in wan_mappings:
        port = m.get("internal_port") or m.get("external_port") or 0
        sev = "warning"
        if dtype == "camera" or port in (23, 21, 3389, 5900, 80):
            sev = "critical"
        alerts.append(Alert(
            kind=f"wan_exposed_{port}",
            severity=sev,
            title=f"{label_text} is reachable from the internet",
            message=(
                f"Your router is forwarding external port "
                f"{m.get('external_port')}/{m.get('protocol', 'TCP')} to "
                f"{m.get('internal_ip')}:{m.get('internal_port')}. "
                "This means anyone on the public internet can try to reach this device. "
                "If you didn't deliberately set this up, open your router's admin page, "
                "find the Port Forwarding (sometimes 'NAT / Virtual Server') section, and remove it. "
                "Many routers also enable UPnP by default — turning UPnP off prevents devices "
                "from quietly poking holes in your firewall in the future."
            ),
            mac=device.get("mac"),
        ))
    return alerts


def check_rogue_dhcp(servers: list) -> list[Alert]:
    """More than one DHCP server seen recently → alert critical.

    `servers` is a list of detect.DhcpServer (or anything with .ip / .mac).
    """
    if len(servers) <= 1:
        return []
    listing = ", ".join(f"{s.ip} ({s.mac})" for s in servers)
    return [Alert(
        kind="rogue_dhcp",
        severity="critical",
        title="More than one DHCP server is answering on this network",
        message=(
            f"Two or more devices on your network are handing out IP addresses: {listing}. "
            "A home network should have exactly one — your router. "
            "Extra DHCP servers usually mean a second router was plugged in by mistake "
            "(switch its WAN port to LAN, or disable DHCP on it), or that someone is "
            "running a rogue DHCP server to redirect your traffic through their machine. "
            "Either way, find and unplug the unexpected device."
        ),
    )]


def check_arp_anomalies(anomalies: list) -> list[Alert]:
    """An IP claimed by multiple MACs in a short window is an ARP-spoof signature."""
    out: list[Alert] = []
    for a in anomalies:
        out.append(Alert(
            kind=f"arp_flap_{a.ip}",
            severity="critical",
            title=f"IP {a.ip} has been claimed by multiple devices",
            message=(
                f"In the last hour, the IP address {a.ip} answered ARP requests "
                f"with these MAC addresses: {', '.join(a.macs)}. "
                "Genuine devices keep the same MAC; rapid changes are the signature "
                "of an ARP-spoofing attack used to redirect traffic. "
                "If you didn't change a router or restart your network, treat this as serious: "
                "change your WiFi password and remove any device you don't recognize."
            ),
            mac=None,
        ))
    return out


def check_dns_threat(device: dict, observed_domains: list[str],
                     threat_list: set[str]) -> list[Alert]:
    """Any observed DNS query against a domain on the local threat list.

    `threat_list` is a set of lowercase host suffixes. INS ships a small,
    static seed list and reads more from `~/Library/Application Support/
    InglNetScan/threats.txt` if the user has dropped one in. Nothing is fetched
    from the network — keep it local.
    """
    if not threat_list or not observed_domains:
        return []
    hits: list[str] = []
    for q in observed_domains:
        q = q.lower().rstrip(".")
        if q in threat_list or any(q.endswith("." + t) for t in threat_list):
            hits.append(q)
    if not hits:
        return []
    label_text = _device_label(device)
    return [Alert(
        kind="dns_threat",
        severity="warning",
        title=f"{label_text} contacted a flagged domain",
        message=(
            f"This device looked up {', '.join(hits[:5])}"
            + (" and others" if len(hits) > 5 else "")
            + ". "
            "Those domains are on the local threat list (malware command-and-control, "
            "phishing infrastructure, or known abuse). "
            "If this is an IoT device, factory-reset it. "
            "If it's a computer or phone, run a malware scan."
        ),
        mac=device.get("mac"),
    )]


def check_randomized_mac_group(group) -> Alert | None:
    """Tell the user "AA:BB:.. is probably your phone using a new MAC" before
    we spam them with five 'new device' banners.

    `group` is detect.FingerprintGroup. We only fire if there are 2+ MAC
    members and we have a label for the canonical device.
    """
    if not group.member_macs or not group.canonical_label:
        return None
    members = ", ".join(group.member_macs[:5])
    if len(group.member_macs) > 5:
        members += f" (+{len(group.member_macs) - 5} more)"
    return Alert(
        kind=f"randomized_mac_{group.canonical_mac}",
        severity="info",
        title=f"\"{group.canonical_label}\" appears to be using a randomized MAC",
        message=(
            f"These MACs share the same hostname/identity as \"{group.canonical_label}\": "
            f"{members}. "
            "iPhones, recent iPads, and modern Android phones rotate their WiFi MAC for "
            "privacy. INS is grouping them so you aren't alerted about each one as a new device. "
            "If any of these MACs doesn't belong to that device, mark it Unknown and "
            "investigate."
        ),
        mac=group.canonical_mac,
    )


# ── Orchestrator ────────────────────────────────────────────────────────────

def evaluate(device: dict, new_ports: list[int] | None = None,
             wan_mappings: list[dict] | None = None,
             observed_domains: list[str] | None = None,
             threat_list: set[str] | None = None) -> list[Alert]:
    """Run every per-device rule. Returns 0+ Alert objects."""
    out: list[Alert] = []

    a = check_new_device(device)
    if a: out.append(a)

    a = check_vendor_change(device)
    if a: out.append(a)

    out.extend(check_risky_ports(device, new_ports or []))

    a = check_default_creds(device)
    if a: out.append(a)

    a = check_admin_panel_for_camera(device)
    if a: out.append(a)

    out.extend(check_wan_exposed_ports(device, wan_mappings or []))

    if observed_domains and threat_list:
        out.extend(check_dns_threat(device, observed_domains, threat_list))

    return out


def evaluate_network(dhcp_servers: list, arp_anomalies: list,
                     fingerprint_groups: list) -> list[Alert]:
    """Run network-scope rules. Inputs come from `detect.py`."""
    out: list[Alert] = []
    out.extend(check_rogue_dhcp(dhcp_servers))
    out.extend(check_arp_anomalies(arp_anomalies))
    for g in fingerprint_groups:
        a = check_randomized_mac_group(g)
        if a:
            out.append(a)
    return out


# ── Dedup helper ────────────────────────────────────────────────────────────

def alert_key(alert: Alert) -> str:
    """Key used to dedup repeated alerts per day per device."""
    day = time.strftime("%Y-%m-%d")
    return f"{alert.mac or '-'}::{alert.kind}::{day}"
