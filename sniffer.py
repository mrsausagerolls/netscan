"""Passive packet sniffer — per-device bandwidth + DNS logging.

Why this module exists: ARP/ping scans tell us WHAT is on the network. They
don't tell us how much each device is talking or to whom. For non-technical
users, "your smart TV uploaded 4 GB at 3 a.m." is actionable; "device.last_seen
was 30 seconds ago" isn't. The sniffer fills that gap with passive observation
only — no probes, no modifications, just listening.

Privileges
----------
Packet capture needs raw socket access. On macOS that means root or read
access on /dev/bpf*. INS runs under a per-user LaunchAgent by default, so
the sniffer starts in "permission-check" mode: if it can't bind, it logs a
status string the dashboard surfaces ("Bandwidth monitoring not enabled —
run tools/enable_sniffer.sh once with sudo") and silently no-ops. Other
INS features keep working normally.

What we capture
---------------
- Ethernet/IPv4 frames on the active WiFi interface.
- Frame length (for bandwidth attribution by src/dst MAC).
- DNS queries — name, type — for the dashboard's DNS history.

What we DON'T capture
---------------------
- Payload bytes from non-DNS traffic. We never see what's in your packets.
- WAN-side or VPN-encapsulated traffic. WiFi-LAN only.

Flush model
-----------
Per-MAC counters live in memory and snapshot to SQLite once a minute. DNS
queries write through synchronously (low volume, easier to query). The
1-minute flush window also drives threat-intel checks — when a DNS query
hits the threat list, an alert fires via the existing events bus.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field

import events


# ── Status reporting ────────────────────────────────────────────────────────

@dataclass
class SnifferStatus:
    enabled:    bool   = False
    running:    bool   = False
    reason:     str    = ""        # last failure reason (for the dashboard)
    packets:    int    = 0
    started_ts: float  = 0.0


_status = SnifferStatus()
_status_lock = threading.Lock()


def status() -> dict:
    with _status_lock:
        return {
            "enabled":    _status.enabled,
            "running":    _status.running,
            "reason":     _status.reason,
            "packets":    _status.packets,
            "started_ts": _status.started_ts,
        }


def _set_status(**fields):
    with _status_lock:
        for k, v in fields.items():
            setattr(_status, k, v)


# ── Per-MAC counters ────────────────────────────────────────────────────────

@dataclass
class _Counters:
    bytes_in:  int = 0
    bytes_out: int = 0


_counters: dict[str, _Counters] = defaultdict(_Counters)
_counter_lock = threading.Lock()


def _bump(mac: str, direction: str, n: int):
    if not mac:
        return
    mac = mac.upper()
    with _counter_lock:
        c = _counters[mac]
        if direction == "in":
            c.bytes_in += n
        else:
            c.bytes_out += n


def _snapshot_and_reset() -> dict[str, _Counters]:
    """Return a copy of the per-MAC counters and zero them in place."""
    with _counter_lock:
        snap = {m: _Counters(c.bytes_in, c.bytes_out) for m, c in _counters.items()}
        _counters.clear()
        return snap


# ── Packet handler ──────────────────────────────────────────────────────────

def _handle_packet(pkt, local_mac: str, threat_list, store) -> None:
    """Called once per captured packet. Must be fast — scapy queues are bounded
    and dropping packets here means bandwidth/DNS gaps."""
    try:
        from scapy.layers.l2 import Ether                # type: ignore
        from scapy.layers.inet import IP                # type: ignore
        from scapy.layers.dns import DNS, DNSQR         # type: ignore
    except ImportError:
        return

    if not pkt.haslayer(Ether):
        return
    eth = pkt[Ether]
    src_mac = eth.src.upper() if eth.src else ""
    dst_mac = eth.dst.upper() if eth.dst else ""
    n = len(pkt)

    # Direction is "out" for traffic originated by the WiFi host running INS,
    # "in" for traffic destined to it. For peer-to-peer LAN traffic we count
    # both ends so neither device looks idle.
    if src_mac == local_mac:
        _bump(dst_mac or src_mac, "out", n)
    elif dst_mac == local_mac:
        _bump(src_mac, "in", n)
    else:
        # Peer to peer or broadcast — credit the source as "out".
        _bump(src_mac, "out", n)

    # DNS extraction: response side gives us the recursive resolver, query
    # side gives us the asker. We want the asker → record under src_mac.
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        dns = pkt[DNS]
        if dns.qr == 0 and pkt.haslayer(IP):
            qname = (pkt[DNSQR].qname or b"").decode("ascii", errors="ignore").rstrip(".")
            qtype = int(pkt[DNSQR].qtype) if pkt[DNSQR].qtype is not None else 0
            store.record_dns_query(src_mac, qname, qtype)
            hit = threat_list.matches(qname) if threat_list else None
            if hit:
                _publish_threat_alert(src_mac, qname, hit, store)

    with _status_lock:
        _status.packets += 1


def _publish_threat_alert(mac: str, qname: str, matched_suffix: str, store) -> None:
    """Fire a critical alert through the standard events bus."""
    alert_id = store.add_alert(
        kind="dns_threat_match",
        severity="warning",
        title=f"Device {mac} contacted {qname}",
        message=(
            f"This device looked up {qname}, which matches the local threat "
            f"list entry {matched_suffix!r}. "
            "If this is an IoT device, factory-reset it. "
            "If it's a computer or phone, run a malware scan and review "
            "recently-installed software."
        ),
        mac=mac,
    )
    events.publish(events.ALERT_RAISED, {
        "kind": "dns_threat_match", "severity": "warning",
        "title": f"Device {mac} contacted {qname}",
        "message": f"Looked up {qname} (threat list: {matched_suffix}).",
        "mac": mac, "id": alert_id, "ts": time.time(),
    })


# ── Flush loop ──────────────────────────────────────────────────────────────

def _flush_loop(store, interval: int = 60):
    """Every `interval` seconds, snapshot counters and write to store."""
    while True:
        time.sleep(interval)
        try:
            snap = _snapshot_and_reset()
            if snap:
                store.record_bandwidth_samples(
                    [(mac, c.bytes_in, c.bytes_out) for mac, c in snap.items()],
                )
        except Exception:
            pass


# ── Entry point ─────────────────────────────────────────────────────────────

def _can_capture() -> tuple[bool, str]:
    """Return (True, "") if we can probably capture, else (False, reason)."""
    if os.name != "posix":
        return False, "Sniffer requires macOS or Linux."
    # On macOS, root or BPF read access is required. Cheap probe: try to open
    # one of the BPF device nodes for reading.
    for n in range(0, 4):
        path = f"/dev/bpf{n}"
        try:
            fd = os.open(path, os.O_RDWR)
            os.close(fd)
            return True, ""
        except FileNotFoundError:
            continue
        except PermissionError:
            return False, (
                f"Couldn't open {path} — packet capture needs elevated permissions. "
                "Run tools/enable_sniffer.sh once with sudo to grant BPF access."
            )
        except OSError as e:
            return False, f"BPF open failed: {e}"
    return False, "No /dev/bpf* devices found — packet capture unsupported."


def start(store, iface: str, local_mac: str, threats_path=None) -> dict:
    """Start the sniffer in a background thread. Idempotent. Returns the
    current status dict. Never raises — failure modes are captured in the
    status fields so the dashboard can surface them."""
    if _status.running:
        return status()

    ok, reason = _can_capture()
    if not ok:
        _set_status(enabled=False, running=False, reason=reason)
        return status()

    try:
        from scapy.all import AsyncSniffer            # type: ignore
    except ImportError:
        _set_status(enabled=False, running=False,
                    reason="scapy not importable; reinstall requirements.txt")
        return status()

    import threats as threats_mod
    threat_list = threats_mod.ThreatList(threats_path) if threats_path \
                  else threats_mod.ThreatList()

    def handler(pkt):
        _handle_packet(pkt, local_mac.upper() if local_mac else "",
                       threat_list, store)

    try:
        sniffer = AsyncSniffer(
            iface=iface,
            prn=handler,
            store=False,                  # don't keep packets in memory
            filter="ip",                  # IPv4 only — keeps it small
        )
        sniffer.start()
    except Exception as e:
        _set_status(enabled=False, running=False, reason=f"sniffer start failed: {e}")
        return status()

    _set_status(enabled=True, running=True, reason="",
                packets=0, started_ts=time.time())

    threading.Thread(target=_flush_loop, args=(store,), daemon=True).start()
    return status()
