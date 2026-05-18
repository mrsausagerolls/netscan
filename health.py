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

# Penalty table — one entry per condition, biggest first.
# Each tuple: (max penalty per occurrence, soft cap across all occurrences).
_PENALTIES = {
    "rogue_dhcp":        (35, 35),
    "arp_flap":          (25, 25),
    "vendor_changed":    (25, 25),
    "wan_exposed_camera":(25, 25),
    "wan_exposed_other": (10, 20),
    "default_creds":     (15, 30),
    "telnet_open":       (15, 15),
    "rdp_open":          (10, 20),
    "vnc_open":          (10, 20),
    "ftp_open":          (8,  16),
    "unknown_device":    (4,  20),
    "camera_no_https":   (4,  8),
    "unack_critical":    (8,  16),
    "unack_warning":     (3,  9),
    "no_alerts_baseline":(0,  0),   # informational
}

_BAND_THRESHOLDS = [
    (90, "excellent", "All clear — your network looks healthy."),
    (75, "good",      "Looking good — minor things to keep an eye on."),
    (55, "fair",      "Take a look — a few things on your network deserve attention."),
    (35, "poor",      "Action needed — something on your network is wrong."),
    (0,  "at_risk",   "At risk — please address the items below now."),
]


def _kind_of_port(port: int) -> str | None:
    if port == 23:                              return "telnet_open"
    if port == 3389:                            return "rdp_open"
    if port == 5900:                            return "vnc_open"
    if port == 21:                              return "ftp_open"
    return None


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
        for p in ports:
            kind = _kind_of_port(p)
            if not kind:
                continue
            penalize(kind,
                     f"Port {p} open on {d.get('hostname') or d.get('vendor') or d.get('ip', '?')}")

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
        penalize("unknown_device",
                 f"{unknown} unknown device{'s' if unknown != 1 else ''} on the network")

    # Unacknowledged alert pressure.
    crit = sum(1 for a in unack_alerts if a.get("severity") == "critical")
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
