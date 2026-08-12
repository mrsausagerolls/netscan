"""Network Health Score — one number a non-technical user can read at a glance.

Start at 100, subtract weighted penalties for each thing that's currently
worrying about the network. Surface the top reasons alongside the number so
the user can see *why* and act on it.

Penalty weights are intentionally chunky so that one critical issue is
visible in the score (e.g. a rogue DHCP server takes 35 points off — the
score goes from 100 → 65, which reads as "Fair / take action" in the UI).

Inputs:
  - devices: list[dict] from store.all_seen.values()
  - unack_alerts: list[dict] from store.alerts(unacknowledged_only=True)
  - wan_mappings: list[dict] from store.wan_mappings()
  - dhcp_servers: list returned by detect.rogue_dhcp_servers(store)

Output:
  dict with keys:
    score: int 0–100
    band:  "excellent" | "good" | "fair" | "poor" | "at_risk"
    headline: short user-facing summary
    reasons: list[{weight: int, label: str}]
"""

import security

# Penalty table — one entry per condition, biggest first.
# Each tuple: (max penalty per occurrence, soft cap across all occurrences).
_PENALTIES = {
    "rogue_dhcp":         (35, 35),
    "arp_flap":           (25, 25),
    "vendor_changed":     (25, 25),
    "wan_exposed_camera": (25, 25),
    "wan_exposed_other":  (10, 20),
    "default_creds":      (15, 30),
    # Risky open ports, bucketed by security._RISKY_PORTS severity so the score
    # stays in lockstep with the alert severities (single source of truth).
    "risky_port_critical":(15, 30),   # Telnet, rlogin, rsh
    "risky_port_warning": (8,  24),   # FTP, RPC, NFS, RDP, VNC, IRC, SOCKS
    "unknown_device":     (4,  20),
    "camera_no_https":    (4,  8),
    "unack_critical":     (8,  16),
    "unack_warning":      (3,  9),
    "no_alerts_baseline": (0,  0),   # informational
}

# Map each risky port to (health-penalty-key, human label) from the canonical
# security._RISKY_PORTS table so this file never drifts from the alert rules.
_PORT_PENALTY = {
    port: ("risky_port_critical" if sev == "critical" else "risky_port_warning", proto)
    for port, (sev, proto, _why) in security._RISKY_PORTS.items()
}

_BAND_THRESHOLDS = [
    (90, "excellent", "All clear — your network looks healthy."),
    (75, "good",      "Looking good — minor things to keep an eye on."),
    (55, "fair",      "Take a look — a few things on your network deserve attention."),
    (35, "poor",      "Action needed — something on your network is wrong."),
    (0,  "at_risk",   "At risk — please address the items below now."),
]


def compute(devices: list[dict], unack_alerts: list[dict],
            wan_mappings: list[dict], dhcp_servers: list) -> dict:
    """Compute the live health score from current state."""
    score = 100
    reasons: list[dict] = []

    # Track per-bucket totals against the soft cap.
    bucket_totals: dict[str, int] = {}

    def penalize(key: str, label: str):
        per, cap = _PENALTIES.get(key, (0, 0))
        spent = bucket_totals.get(key, 0)
        if spent >= cap:
            return
        taken = min(per, cap - spent)
        if taken <= 0:
            return
        bucket_totals[key] = spent + taken
        reasons.append({"weight": taken, "label": label, "key": key})

    # Rogue DHCP — biggest single hit.
    if len(dhcp_servers) > 1:
        penalize("rogue_dhcp",
                 f"{len(dhcp_servers)} DHCP servers answering on the network")

    # WAN-exposed devices via IGD.
    for m in wan_mappings or []:
        ip = m.get("internal_ip", "?")
        ext = m.get("external_port")
        # Tag whether the LAN device looks like a camera.
        dev = next((d for d in devices if d.get("ip") == ip), None)
        if dev and dev.get("device_type") == "camera":
            penalize("wan_exposed_camera",
                     f"Camera at {ip} is reachable from the internet (port {ext})")
        else:
            penalize("wan_exposed_other",
                     f"{ip} is reachable from the internet (port {ext})")

    # Per-device hits.
    unknown = 0
    for d in devices:
        if not d.get("is_known") and not d.get("me"):
            unknown += 1

        ports = set(d.get("ports") or [])
        who = d.get("hostname") or d.get("vendor") or d.get("ip", "?")
        for p in ports:
            entry = _PORT_PENALTY.get(p)
            if not entry:
                continue
            key, proto = entry
            penalize(key, f"{proto} (port {p}) open on {who}")

        # Camera with admin on HTTP only.
        if d.get("device_type") == "camera" and 80 in ports and 443 not in ports:
            penalize("camera_no_https",
                     f"Camera at {d.get('ip')} has an unencrypted admin page")

        # Default-credential vendors with an admin panel.
        v = (d.get("vendor") or "").lower()
        if any(needle in v for needle in
               ("hikvision", "dahua", "foscam", "xiongmai")) and \
           (ports & {80, 443, 8080}):
            penalize("default_creds",
                     f"{d.get('vendor', '?')} device at {d.get('ip')} likely on default password")

    if unknown:
        # Scale with the count (up to the soft cap) instead of a flat single
        # hit, so 10 unknown devices read worse than 1. Done as one aggregate
        # reason rather than per-device penalize() calls to keep the dashboard
        # top-reasons list uncluttered.
        per, cap = _PENALTIES["unknown_device"]
        weight = min(per * unknown, cap)
        if weight > 0:
            bucket_totals["unknown_device"] = weight
            reasons.append({
                "weight": weight,
                "label": f"{unknown} unknown device{'s' if unknown != 1 else ''} on the network",
                "key": "unknown_device",
            })

    # Dedicated heavy penalties for the most serious spoofing/MITM alert kinds.
    # These carry their own 25-point weight instead of being flattened into the
    # generic unack_critical bucket (capped at 16 across ALL criticals), which
    # otherwise let an active ARP-spoof or vendor-spoof network read "excellent".
    def _has_kind(prefix_or_exact, *, prefix=False):
        for a in unack_alerts:
            k = a.get("kind") or ""
            if (k.startswith(prefix_or_exact) if prefix else k == prefix_or_exact):
                return True
        return False

    if _has_kind("vendor_changed"):
        penalize("vendor_changed",
                 "A device's hardware vendor changed — possible MAC spoofing")
    if _has_kind("arp_flap", prefix=True):
        penalize("arp_flap",
                 "An IP is claimed by multiple devices — possible ARP spoofing")

    # Generic unacknowledged pressure, EXCLUDING the kinds handled above so a
    # single spoofing alert isn't counted twice.
    def _counts_generic(a) -> bool:
        k = a.get("kind") or ""
        return k != "vendor_changed" and not k.startswith("arp_flap")

    crit = sum(1 for a in unack_alerts
               if a.get("severity") == "critical" and _counts_generic(a))
    warn = sum(1 for a in unack_alerts if a.get("severity") == "warning")
    if crit:
        penalize("unack_critical",
                 f"{crit} unresolved critical alert{'s' if crit != 1 else ''}")
    if warn:
        penalize("unack_warning",
                 f"{warn} unresolved warning{'s' if warn != 1 else ''}")

    # Subtract total weight from score.
    score -= sum(r["weight"] for r in reasons)
    score = max(0, min(100, score))

    band, headline = _band(score)
    # Sort reasons by weight (biggest first) so the dashboard surfaces the top fixes.
    reasons.sort(key=lambda r: r["weight"], reverse=True)

    return {
        "score":    score,
        "band":     band,
        "headline": headline,
        "reasons":  reasons,
    }


def _band(score: int) -> tuple[str, str]:
    for threshold, band, headline in _BAND_THRESHOLDS:
        if score >= threshold:
            return band, headline
    return _BAND_THRESHOLDS[-1][1], _BAND_THRESHOLDS[-1][2]
