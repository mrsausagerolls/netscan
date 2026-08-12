"""Network-wide passive detectors.

Where `security.py` runs rules against a single device, this module produces
findings about the *network as a whole*:

  * Rogue-DHCP — more than one host on the LAN is answering DHCP DISCOVER.
    On a home network this almost always means a misconfigured second router
    or an attacker.
  * ARP-spoof / MAC-flap — the same IP address has answered ARP with
    different MAC addresses in a short window, or the same MAC has claimed
    multiple IPs. Classic MITM signature.
  * Randomized-MAC clustering — group "new" MACs that share a fingerprint with
    a known device so we can show "this is probably the same iPhone" instead
    of spamming five join alerts.

All three operate on data the store already collects (sightings + devices);
nothing here opens new sockets or sends packets. The active DHCP probe lives
in `_active_dhcp_probe` and is opt-in (off by default) because it needs raw
sockets via scapy and not every install has them.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass

# ── Result types ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DhcpServer:
    ip:        str
    mac:       str
    first_seen: float
    last_seen:  float


@dataclass(frozen=True)
class ArpAnomaly:
    ip:    str
    macs:  tuple[str, ...]    # observed MACs for this IP, newest first


@dataclass(frozen=True)
class FingerprintGroup:
    canonical_mac: str        # the established device
    canonical_label: str
    member_macs:  tuple[str, ...]   # MACs that look like the same device


# ── Rogue DHCP ───────────────────────────────────────────────────────────────


# A rogue DHCP server is only counted when it is BOTH recent and recurring.
# The old 7-day window pinned a critical alert (and −35 health) for a full week
# after a single stray OFFER — a phone hotspot, a bridged VM, or a travel router
# briefly plugged in — long after the device was gone. A genuinely rogue server
# handing out leases is seen repeatedly and recently; a one-off blip is not.
_DHCP_RECENT_WINDOW = 24 * 3600   # last sighting must be within a day
_DHCP_MIN_SIGHTINGS = 2           # ignore a single stray OFFER


def rogue_dhcp_servers(store, recent_window: int = _DHCP_RECENT_WINDOW,
                       min_sightings: int = _DHCP_MIN_SIGHTINGS) -> list[DhcpServer]:
    """Return DHCP servers actively answering on this network.

    A home network should have exactly one DHCP server (the router); a second
    persistent one is worth a critical alert. We count a (ip, mac) only when it
    was seen within `recent_window` AND at least `min_sightings` times, so a
    transient second server doesn't linger as a false positive. The store
    records observations via `store.record_dhcp_server(ip, mac)` from the sniffer.
    """
    now = time.time()
    rows = store._q(
        "SELECT ip, mac, MIN(ts) AS first, MAX(ts) AS last "
        "FROM dhcp_servers WHERE ts >= ? GROUP BY ip, mac "
        "HAVING COUNT(*) >= ? AND MAX(ts) >= ? ORDER BY MAX(ts) DESC",
        (now - 7 * 86400, min_sightings, now - recent_window),
    )
    return [
        DhcpServer(
            ip=r["ip"], mac=r["mac"],
            first_seen=r["first"], last_seen=r["last"],
        )
        for r in rows
    ]


# ── ARP-spoof / MAC-flap ─────────────────────────────────────────────────────


def arp_anomalies(store, window_seconds: int = 3600,
                  flap_window: int = 180) -> list[ArpAnomaly]:
    """Return IPs claimed by multiple MACs that are answering *simultaneously*.

    Real ARP-spoofing = two+ MACs answering for one IP at (nearly) the same
    time. A normal DHCP lease handoff also produces two MACs for one IP within
    the window, but SEQUENTIALLY — the old lease holder stops being seen, then
    the new one starts (often minutes-to-hours apart). Flagging that as a
    "someone is spoofing — change your WiFi password" critical alert is a false
    positive. So we only flag when the second-most-recent MAC was itself sighted
    within `flap_window` seconds, i.e. both MACs are still active concurrently.
    """
    now = time.time()
    cutoff = now - window_seconds
    rows = store._q(
        "SELECT ip, mac, MAX(ts) AS last FROM sightings "
        "WHERE ts >= ? AND ip IS NOT NULL "
        "GROUP BY ip, mac ORDER BY ip, last DESC",
        (cutoff,),
    )
    by_ip: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for r in rows:
        by_ip[r["ip"]].append((r["mac"], r["last"]))

    out: list[ArpAnomaly] = []
    for ip, sightings in by_ip.items():
        if len(sightings) < 2:
            continue
        sightings.sort(key=lambda x: x[1], reverse=True)
        # The 2nd-newest MAC must still be recently active — otherwise this is a
        # sequential lease handoff, not concurrent spoofing.
        if (now - sightings[1][1]) <= flap_window:
            out.append(ArpAnomaly(
                ip=ip, macs=tuple(m for m, _ in sightings),
            ))
    return out


# ── Randomized-MAC clustering ────────────────────────────────────────────────


def _normalize_fingerprint(hints: dict) -> str:
    """Stable string fingerprint for similarity comparison.

    We pick the high-signal fields (mDNS hostname, UPnP friendlyName,
    NetBIOS name) and ignore noisy ones (HTTP Server header changes with
    every firmware push).

    NOTE: grouping keys on the EXACT concatenation of whichever of these fields
    are present, so only fields captured together on the same active scan are
    safe to include. The DHCP option-12 hostname is deliberately excluded: it's
    captured passively at a different time than mDNS/SSDP/SMB, so folding it in
    would make two rotated-MAC siblings normalize differently (one with the
    hostname, one without) and land in different buckets — fragmenting exactly
    the groups this is meant to collapse. Enabling it would require grouping on
    any-shared-signal rather than exact-string equality.
    """
    parts = []
    for key in ("mdns", "ssdp", "smb"):
        v = (hints or {}).get(key, "").strip().lower()
        if v:
            parts.append(v)
    return " ".join(parts)


def fingerprint_groups(store) -> list[FingerprintGroup]:
    """Group MACs that almost certainly belong to the same physical device.

    Used to turn "new device joined: AA:BB:.. / new device joined: CC:DD:.."
    (same iPhone, randomized MAC) into a single grouped alert.

    Only groups when:
      - The fingerprint string is non-empty (don't merge "unknown" things).
      - At least one member is already in the Known list (the canonical one).
    """
    devices = store.all_seen
    by_fp: dict[str, list[str]] = defaultdict(list)
    for mac, dev in devices.items():
        fp = _normalize_fingerprint(dev.get("fingerprint") or {})
        if fp:
            by_fp[fp].append(mac)

    out: list[FingerprintGroup] = []
    for fp, macs in by_fp.items():
        if len(macs) < 2:
            continue
        canonical = next(
            (m for m in macs if store.is_known(m)),
            None,
        )
        if not canonical:
            continue
        members = tuple(m for m in macs if m != canonical)
        out.append(FingerprintGroup(
            canonical_mac   = canonical,
            canonical_label = store.known_name(canonical) or fp,
            member_macs     = members,
        ))
    return out


# ── Active probes (optional, opt-in) ─────────────────────────────────────────


def _active_dhcp_probe(iface: str, timeout: float = 4.0) -> list[DhcpServer]:
    """Send a DHCPDISCOVER, collect every responder.

    Off by default — needs scapy + raw sockets. The passive `rogue_dhcp_servers`
    path is preferred because it works without elevated privileges.
    """
    try:
        from scapy.all import (  # type: ignore
            Ether, IP, UDP, BOOTP, DHCP, srp, conf,
        )
    except ImportError:
        return []

    conf.verb = 0
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=b"\x00" * 16)
        / DHCP(options=[("message-type", "discover"), "end"])
    )
    try:
        answered, _ = srp(pkt, iface=iface, timeout=timeout, verbose=False)
    except Exception:
        return []

    now = time.time()
    seen: dict[tuple[str, str], DhcpServer] = {}
    for _, r in answered:
        try:
            srv_ip  = r[IP].src
            srv_mac = r[Ether].src.upper()
        except (IndexError, AttributeError):
            continue
        key = (srv_ip, srv_mac)
        if key not in seen:
            seen[key] = DhcpServer(srv_ip, srv_mac, now, now)
    return list(seen.values())
