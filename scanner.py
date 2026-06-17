#!/usr/bin/env python3
"""Inglorious Network Scanner — lists all devices on your local WiFi network."""

import argparse
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, wait
from ipaddress import IPv4Network

PROBE_PORTS = {
    22:   "SSH",
    80:   "HTTP",
    443:  "HTTPS",
    554:  "RTSP",
    8080: "HTTP-alt",
    8883: "MQTT",
    9100: "Print",
    5000: "UPnP",
    137:  "NetBIOS",
    445:  "SMB",
}

# ── Dependency check ─────────────────────────────────────────────────────────

def _check_deps():
    missing = []
    for pkg in ("scapy", "rich", "mac_vendor_lookup"):
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"Missing: {', '.join(missing)}")
        print(f"  pip install {' '.join(missing)}")
        sys.exit(1)

_check_deps()

from mac_vendor_lookup import MacLookup  # type: ignore
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text
from scapy.all import ARP, Ether, srp, conf  # type: ignore

_mac_lookup = MacLookup()
console = Console()

# ── Network detection ────────────────────────────────────────────────────────

_wifi_iface_cache: str | None = None


def _detect_wifi_iface() -> str:
    """Find the active Wi-Fi interface name (e.g. 'en0') via networksetup."""
    hw_lines = subprocess.run(
        ["networksetup", "-listallhardwareports"],
        capture_output=True, text=True
    ).stdout.splitlines()
    for i, line in enumerate(hw_lines):
        if "Wi-Fi" in line or "AirPort" in line:
            for nearby in hw_lines[i:i + 4]:
                m = re.search(r"Device:\s+(en\d+)", nearby)
                if m:
                    return m.group(1)
            break
    return "en0"


def _iface_inet(iface: str) -> tuple[str, str] | None:
    """Return (ip, netmask_hex) for `iface`, or None if it has no IPv4 address."""
    ifc = subprocess.run(["ifconfig", iface], capture_output=True, text=True).stdout
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+)", ifc)
    return (m.group(1), m.group(2)) if m else None


def get_wifi_info() -> tuple[str, str, str]:
    """Return (interface, local_ip, cidr_network) for the active WiFi.

    The Wi-Fi interface NAME is a stable hardware mapping, so it's cached after
    first detection — that saves a `networksetup -listallhardwareports`
    subprocess on every subsequent scan. We only re-detect if the cached
    interface has stopped reporting an IPv4 address (e.g. dock/undock).
    """
    global _wifi_iface_cache
    iface = _wifi_iface_cache or _detect_wifi_iface()
    inet = _iface_inet(iface)
    if inet is None and _wifi_iface_cache:
        iface = _detect_wifi_iface()      # cached iface went away — re-detect once
        inet = _iface_inet(iface)
    if inet is None:
        console.print(f"[red]No IP found on {iface} — are you connected to WiFi?[/red]")
        sys.exit(1)

    _wifi_iface_cache = iface
    ip, netmask = inet
    prefix = bin(int(netmask, 16)).count("1")
    network = str(IPv4Network(f"{ip}/{prefix}", strict=False))
    return iface, ip, network

# ── Helpers ──────────────────────────────────────────────────────────────────

def _normalize_mac(mac: str) -> str:
    return ":".join(o.zfill(2).upper() for o in mac.split(":"))


def _is_unicast(ip: str, mac: str) -> bool:
    if mac == "FF:FF:FF:FF:FF:FF":
        return False
    if int(ip.split(".")[0]) >= 224:
        return False
    return True


def _parse_arp_table(arp_output: str, only_ips: set[str] | None = None) -> dict[str, str]:
    """Parse `arp -a` / `arp -an` output into an ordered {ip: mac} dict.

    Skips incomplete entries and non-unicast addresses, normalizes MACs, and —
    when `only_ips` is given — keeps only those IPs. First sighting per IP wins,
    preserving arp-output order. Shared by fallback_scan and _arp_resolve so the
    OS-output parser lives in one place.
    """
    by_ip: dict[str, str] = {}
    for line in arp_output.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)", line)
        if not m or "incomplete" in line:
            continue
        ip, mac = m.group(1), _normalize_mac(m.group(2))
        if only_ips is not None and ip not in only_ips:
            continue
        if ip not in by_ip and _is_unicast(ip, mac):
            by_ip[ip] = mac
    return by_ip

# ── Scanning ─────────────────────────────────────────────────────────────────

def arp_scan(network: str, timeout: int = 3) -> list[dict]:
    conf.verb = 0
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(pkt, timeout=timeout, verbose=False)
    return [
        {"ip": r.psrc, "mac": _normalize_mac(r.hwsrc)}
        for _, r in answered
        if _is_unicast(r.psrc, _normalize_mac(r.hwsrc))
    ]


def _mdns_browse(iface_ip: str | None = None, timeout: float = 2.0) -> list[str]:
    """Send the canonical DNS-SD service-enumeration query (PTR
    `_services._dns-sd._udp.local`) and collect the source IPs of every
    responder.

    Catches devices that ignore ICMP / ARP probes but participate in mDNS
    (most iPhones and iPads, AirPlay receivers, Chromecasts, smart TVs,
    HomeKit accessories). We don't bother parsing the response payload —
    just the fact of a reply tells us the IP is live.

    Returns a sorted list of unique IPs. Safe to call without root; uses a
    plain UDP socket. Silent on permission errors.
    """
    import struct

    MCAST_GRP  = "224.0.0.251"
    MCAST_PORT = 5353

    # DNS wire format: PTR query for _services._dns-sd._udp.local
    qname  = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    # qtype=PTR(12), qclass=IN(1) with the "unicast response preferred" (QU)
    # high bit set per RFC 6762 §5.4 so responders may reply directly to our
    # ephemeral port even if we can't bind :5353.
    qfooter = struct.pack("!HH", 12, 1 | 0x8000)
    header  = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    query   = header + qname + qfooter

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass

    # Prefer binding to the mDNS port so we receive multicast replies too;
    # if mDNSResponder won't share, fall back to an ephemeral port and rely on
    # the QU bit. Many responders honor QU; missing the rest is acceptable.
    try:
        sock.bind(("", MCAST_PORT))
        mreq = struct.pack("4s4s", socket.inet_aton(MCAST_GRP),
                           socket.inet_aton(iface_ip or "0.0.0.0"))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError:
        try:
            sock.bind(("", 0))
        except OSError:
            sock.close()
            return []

    if iface_ip:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            socket.inet_aton(iface_ip))
        except OSError:
            pass
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    sock.settimeout(0.4)

    seen: set[str] = set()
    try:
        sock.sendto(query, (MCAST_GRP, MCAST_PORT))
        deadline = time.monotonic() + timeout
        idle_deadline: float | None = None  # set once replies start arriving
        while time.monotonic() < deadline:
            try:
                _, addr = sock.recvfrom(4096)
                seen.add(addr[0])
                # Replies are arriving — stop early after a short quiet gap
                # instead of always burning the full timeout on a busy LAN.
                idle_deadline = time.monotonic() + 0.6
            except socket.timeout:
                if idle_deadline is not None and time.monotonic() >= idle_deadline:
                    break
                continue
            except OSError:
                break
    except OSError:
        pass
    finally:
        sock.close()

    return sorted(seen)


def _arp_resolve(ips: list[str]) -> list[dict]:
    """Ping a list of IPs once to populate the kernel ARP cache, then read
    `arp -a` to extract their MACs. Returns only IPs that ARP-resolved.

    Designed for the mDNS-discovered-but-not-yet-seen path: we already know
    the IPs are alive (they answered mDNS), but we still need MACs to fit
    them into INS's device model.
    """
    if not ips:
        return []

    def ping(ip: str):
        subprocess.run(
            ["ping", "-c", "1", "-W", "500", ip],
            capture_output=True, check=False,
        )

    with ThreadPoolExecutor(max_workers=min(20, len(ips))) as ex:
        list(ex.map(ping, ips))

    arp_out = subprocess.run(["arp", "-an"], capture_output=True, text=True).stdout
    by_ip = _parse_arp_table(arp_out, only_ips=set(ips))
    return [{"ip": ip, "mac": mac} for ip, mac in by_ip.items()]


def fallback_scan(network: str, quiet: bool = False) -> list[dict]:
    if not quiet:
        console.print("[yellow]No root — falling back to ping sweep (slower)…[/yellow]\n")
    hosts = list(IPv4Network(network).hosts())

    def ping(ip):
        subprocess.run(["ping", "-c", "1", "-W", "500", str(ip)], capture_output=True)

    with ThreadPoolExecutor(max_workers=100) as ex:
        list(ex.map(ping, hosts))

    arp_out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
    by_ip = _parse_arp_table(arp_out)
    return [{"ip": ip, "mac": mac} for ip, mac in by_ip.items()]

# ── Enrichment ───────────────────────────────────────────────────────────────

# ── Enrichment caches ────────────────────────────────────────────────────────
#
# The scan loop re-runs every ~30s (and bursts on manual rescan / SSID changes).
# Vendor is STATIC per MAC, and reverse-DNS names rarely change — re-resolving
# them every scan is pure waste. These module-level caches let enrich() resolve
# each fact at most once per TTL and reuse it thereafter. Cache writes happen on
# the calling thread (never inside the worker pool), so no lock is needed.
_HOSTNAME_TTL = 300.0   # reverse-DNS rarely changes — re-check every 5 min
_LATENCY_TTL  = 20.0    # keep ~per-scan freshness but dedupe burst rescans

_vendor_cache:   dict[str, str] = {}                          # MAC -> vendor (incl. "—")
_hostname_cache: dict[str, tuple[float, str]] = {}            # IP  -> (monotonic_ts, hostname)
_latency_cache:  dict[str, tuple[float, float | None]] = {}   # IP  -> (monotonic_ts, latency)


def clear_caches() -> None:
    """Drop all enrichment caches. For tests, and callable on a network change."""
    _vendor_cache.clear()
    _hostname_cache.clear()
    _latency_cache.clear()


def _is_locally_administered(mac: str) -> bool:
    """True if the MAC is locally-administered (randomized / privacy MAC). Its
    OUI carries no manufacturer information, so an OUI lookup is meaningless."""
    try:
        return bool(int(mac[:2], 16) & 0b10)
    except (ValueError, IndexError):
        return False


def get_vendor(mac: str) -> str:
    """Resolve a MAC's manufacturer from the OUI database — memoized per MAC.

    Randomized/locally-administered MACs and the IEEE "Private" placeholder carry
    no real vendor, so they resolve to "—" without touching the OUI database.
    Any lookup failure maps to "—"; vendor naming is best-effort and must never
    break a scan.
    """
    cached = _vendor_cache.get(mac)
    if cached is not None:
        return cached
    if _is_locally_administered(mac):
        _vendor_cache[mac] = "—"
        return "—"
    try:
        v = _mac_lookup.lookup(mac)
        if not v or v.strip().lower() == "private":
            v = "—"
    except Exception:
        v = "—"
    _vendor_cache[mac] = v
    return v


def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "—"


def ping_latency(ip: str) -> float | None:
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1000", ip],
        capture_output=True, text=True,
    )
    m = re.search(r"time[<=](\d+\.?\d*)", result.stdout)
    return round(float(m.group(1)), 1) if m else None


def _port_open(ip: str, port: int, timeout: float = 0.4) -> bool:
    try:
        s = socket.socket()
        s.settimeout(timeout)
        ok = s.connect_ex((ip, port)) == 0
        s.close()
        return ok
    except Exception:
        return False


def scan_ports(ip: str) -> list[int]:
    """Return list of open port numbers from PROBE_PORTS."""
    with ThreadPoolExecutor(max_workers=len(PROBE_PORTS)) as ex:
        hits = {port: ex.submit(_port_open, ip, port) for port in PROBE_PORTS}
    return sorted(port for port, f in hits.items() if f.result())


def _mdns_lookup(ip: str) -> str | None:
    """Query mDNS for a .local hostname via reverse lookup."""
    try:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        r = subprocess.run(
            ["dns-sd", "-timeout", "1", "-Q", rev, "PTR"],
            capture_output=True, text=True, timeout=3,
        )
        m = re.search(r"(\S+\.local\.?)", r.stdout)
        if m:
            return m.group(1).rstrip(".")
    except Exception:
        pass
    return None


def _http_fingerprint(ip: str, port: int, tls: bool = False) -> tuple[str, str]:
    """Return (Server header, page title) from HTTP/HTTPS."""
    import urllib.request, ssl
    try:
        scheme = "https" if tls else "http"
        ctx = ssl.create_default_context() if tls else None
        if ctx:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            f"{scheme}://{ip}:{port}/",
            headers={"User-Agent": "InglNetScan/2.0"},
        )
        resp = urllib.request.urlopen(req, timeout=2, context=ctx)
        server = resp.headers.get("Server", "")
        body = resp.read(4096).decode("utf-8", errors="ignore")
        title_m = re.search(r"<title[^>]*>([^<]{1,80})</title>", body, re.I)
        return server.strip(), (title_m.group(1).strip() if title_m else "")
    except Exception:
        return "", ""


def _fetch_upnp_desc(url: str) -> str | None:
    """Fetch UPnP device description XML and return friendlyName or modelName."""
    import urllib.request
    try:
        body = urllib.request.urlopen(url, timeout=2).read(8192).decode("utf-8", errors="ignore")
        for tag in ("friendlyName", "modelName", "manufacturer"):
            m = re.search(rf"<{tag}>([^<]+)</{tag}>", body)
            if m and m.group(1).strip():
                return m.group(1).strip()
    except Exception:
        pass
    return None


def _ssdp_probe(ip: str, timeout: float = 1.5) -> str | None:
    """Send unicast SSDP M-SEARCH and parse the UPnP device description."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {ip}:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(msg, (ip, 1900))
        data, _ = s.recvfrom(2048)
        s.close()
        resp = data.decode("utf-8", errors="ignore")
        loc = re.search(r"(?i)LOCATION:\s*(\S+)", resp)
        if loc:
            name = _fetch_upnp_desc(loc.group(1).strip())
            if name:
                return name
        srv = re.search(r"(?i)SERVER:\s*(.+)", resp)
        return srv.group(1).strip() if srv else None
    except Exception:
        return None


def _smb_name(ip: str) -> str | None:
    """Try to grab the NetBIOS/SMB machine name."""
    try:
        r = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=3,
        )
        m = re.search(r"^\s+(\S+)\s+<00>", r.stdout, re.M)
        return m.group(1).strip() if m else None
    except Exception:
        return None


def probe_device(ip: str, mac: str, open_ports: list[int]) -> dict:
    """Run identification probes and return a dict of hints."""
    hints: dict[str, str] = {}

    # mDNS — most useful for Apple/randomized-MAC devices
    mdns = _mdns_lookup(ip)
    if mdns:
        hints["mdns"] = mdns

    # HTTP fingerprinting
    if 80 in open_ports:
        server, title = _http_fingerprint(ip, 80)
        if title:   hints["http_title"]  = title
        if server:  hints["http_server"] = server
    if 443 in open_ports:
        server, title = _http_fingerprint(ip, 443, tls=True)
        if title:   hints["https_title"]  = title
        if server:  hints["https_server"] = server
    if 8080 in open_ports:
        server, title = _http_fingerprint(ip, 8080)
        if title:   hints["http8080_title"]  = title
        if server:  hints["http8080_server"] = server

    # SSDP / UPnP
    ssdp = _ssdp_probe(ip)
    if ssdp:
        hints["ssdp"] = ssdp

    # NetBIOS / SMB
    if 137 in open_ports or 445 in open_ports:
        smb = _smb_name(ip)
        if smb:
            hints["smb"] = smb

    return hints


def best_fingerprint(hints: dict) -> str:
    """Pick the most human-readable identification string from probe hints."""
    for key in ("mdns", "ssdp", "smb", "http_title", "https_title",
                "http8080_title", "http_server", "https_server"):
        val = hints.get(key, "")
        if val and val not in ("—", ""):
            return val
    # Fall back to DHCP OS-family label when active probes had nothing —
    # better than "—" for devices that decline mDNS/SSDP entirely.
    if hints.get("dhcp_55"):
        import classify  # local import to avoid a top-level cycle
        lbl = classify.dhcp_label(hints)
        if lbl:
            return lbl
    return ""


def _resolve_stale(ips: list[str], fn, cache: dict, ttl: float,
                   timeout: float, default):
    """Resolve `fn(ip)` for the subset of `ips` whose cache entry is missing or
    older than `ttl`, in one bounded thread pool, and write the results back to
    `cache` as (now, value). A whole-batch deadline (`timeout`) caps the wall
    time; IPs that don't resolve in time keep their previous value (or default).
    No nested pools, and we never block on shutdown for a wedged resolver."""
    now = time.monotonic()
    stale = [ip for ip in ips
             if ip not in cache or (now - cache[ip][0]) >= ttl]
    if not stale:
        return
    ex = ThreadPoolExecutor(max_workers=min(20, len(stale)))
    futs = {ex.submit(fn, ip): ip for ip in stale}
    wait(list(futs), timeout=timeout)
    for fut, ip in futs.items():
        if fut.done():
            try:
                val = fut.result()
            except Exception:
                val = default
            cache[ip] = (now, val)
        # else: timed out — leave the cache untouched so we retry next scan and
        # keep displaying the last known value (if any) rather than blanking it.
    ex.shutdown(wait=False)   # don't block on a stuck resolver


def enrich(devices: list[dict], local_ip: str, skip_vendor: bool = False) -> list[dict]:
    """Attach vendor / hostname / latency / me to each device.

    Vendor is memoized per MAC; reverse-DNS and latency are resolved only when
    their per-IP cache entry is missing or stale, so a steady-state rescan does
    almost no network work — the expensive resolution happens once, then is
    reused until the TTL expires.
    """
    for d in devices:
        d["vendor"] = "—" if skip_vendor else get_vendor(d["mac"])
        d["me"] = d["ip"] == local_ip

    ips = [d["ip"] for d in devices]
    _resolve_stale(ips, get_hostname, _hostname_cache, _HOSTNAME_TTL,
                   timeout=1.5, default="—")
    _resolve_stale(ips, ping_latency, _latency_cache, _LATENCY_TTL,
                   timeout=2.0, default=None)

    for d in devices:
        h = _hostname_cache.get(d["ip"])
        d["hostname"] = h[1] if h else "—"
        l = _latency_cache.get(d["ip"])
        d["latency"] = l[1] if l else None
    return devices

# ── Display ──────────────────────────────────────────────────────────────────

def build_table(
    devices: list[dict],
    iface: str,
    network: str,
    elapsed: float,
    joined: set[str] | None = None,
    left: set[str] | None = None,
) -> Table:
    joined = joined or set()
    left = left or set()
    timestamp = time.strftime("%H:%M:%S")

    title = (
        f"[bold cyan]WiFi Devices — {network}[/bold cyan]  "
        f"[dim]({iface})  {timestamp}[/dim]"
    )
    if joined:
        title += f"  [bold green]+{len(joined)} joined[/bold green]"
    if left:
        title += f"  [bold red]-{len(left)} left[/bold red]"

    table = Table(
        title=title,
        header_style="bold magenta",
        border_style="dim",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("IP Address", min_width=16)
    table.add_column("MAC Address", style="yellow", min_width=18)
    table.add_column("Hostname", style="green", min_width=22)
    table.add_column("Vendor", style="white", min_width=22)
    table.add_column("Status", width=8)

    devices_sorted = sorted(devices, key=lambda d: tuple(int(x) for x in d["ip"].split(".")))

    for i, d in enumerate(devices_sorted, 1):
        ip = d["ip"]
        if d.get("me"):
            ip_cell = Text(f"{ip} (you)", style="bold cyan")
        elif ip in joined:
            ip_cell = Text(ip, style="bold green")
        else:
            ip_cell = Text(ip, style="cyan")

        if ip in joined:
            status = Text("● joined", style="bold green")
        else:
            status = Text("○", style="dim")

        table.add_row(
            str(i), ip_cell, d["mac"], d["hostname"], d["vendor"], status
        )

    # Ghost rows for devices that just left
    for ip in sorted(left):
        table.add_row(
            "–",
            Text(ip, style="bold red strike"),
            "—", "—", "—",
            Text("✕ left", style="bold red"),
        )

    footer = f"[dim]{len(devices)} device(s)  •  scanned in {elapsed:.1f}s  •  Ctrl-C to stop[/dim]"
    table.caption = footer
    return table


def do_scan(
    network: str, timeout: int, use_fallback: bool, quiet: bool = False,
    iface_ip: str | None = None,
) -> tuple[list[dict], bool]:
    """Run one scan cycle. Returns (devices, use_fallback).

    Layered discovery:
      1. ARP scan if we have raw-socket privileges, else ICMP ping sweep.
      2. mDNS service-enumeration sweep that catches devices ignoring ARP/ICMP
         (most modern iPhones, AirPlay receivers, Chromecasts). New IPs are
         ARP-resolved and merged into the device list. mDNS failures are
         non-fatal — the ARP/ping result still ships.
    """
    if use_fallback:
        devices, used_fb = fallback_scan(network, quiet=quiet), True
    else:
        try:
            devices, used_fb = arp_scan(network, timeout), False
        except Exception as e:
            if "permission" in str(e).lower() or "root" in str(e).lower():
                devices, used_fb = fallback_scan(network, quiet=quiet), True
            else:
                console.print(f"[red]Scan error: {e}[/red]")
                sys.exit(1)

    try:
        known_ips  = {d["ip"] for d in devices}
        mdns_ips   = [ip for ip in _mdns_browse(iface_ip=iface_ip)
                      if ip not in known_ips and _ip_in_network(ip, network)]
        if mdns_ips:
            for extra in _arp_resolve(mdns_ips):
                if extra["ip"] not in known_ips:
                    devices.append(extra)
                    known_ips.add(extra["ip"])
    except Exception:
        pass

    return devices, used_fb


def _ip_in_network(ip: str, network: str) -> bool:
    """True if `ip` falls inside the CIDR `network`. Cheap; no exception leaks."""
    try:
        from ipaddress import IPv4Address, IPv4Network
        return IPv4Address(ip) in IPv4Network(network)
    except Exception:
        return False

# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scan your WiFi network for connected devices."
    )
    parser.add_argument("--timeout", type=int, default=3,
                        help="ARP scan timeout in seconds (default: 3)")
    parser.add_argument("--no-vendor", action="store_true",
                        help="Skip MAC vendor lookup (faster, offline)")
    parser.add_argument("--watch", type=int, nargs="?", const=30, metavar="SECONDS",
                        help="Re-scan every N seconds, highlight changes (default: 30)")
    args = parser.parse_args()

    console.rule("[bold cyan]Inglorious Network Scanner[/bold cyan]")
    iface, local_ip, network = get_wifi_info()
    console.print(
        f"  Interface: [cyan]{iface}[/cyan]   "
        f"IP: [cyan]{local_ip}[/cyan]   "
        f"Network: [cyan]{network}[/cyan]\n"
    )

    use_fallback = False

    if args.watch is None:
        # ── Single scan ──────────────────────────────────────────────────────
        t0 = time.time()
        devices, use_fallback = do_scan(network, args.timeout, use_fallback)
        if not devices:
            console.print("[red]No devices found.[/red]")
            return
        with console.status(f"[bold green]Resolving {len(devices)} device(s)…[/bold green]"):
            devices = enrich(devices, local_ip, skip_vendor=args.no_vendor)
        console.print(build_table(devices, iface, network, time.time() - t0))

    else:
        # ── Watch mode ───────────────────────────────────────────────────────
        interval = args.watch
        console.print(
            f"[bold green]Watch mode[/bold green] — rescanning every "
            f"[cyan]{interval}s[/cyan]. Press [bold]Ctrl-C[/bold] to stop.\n"
        )

        known: dict[str, dict] = {}   # ip → enriched device
        joined: set[str] = set()
        left: set[str] = set()

        try:
            while True:
                t0 = time.time()
                raw, use_fallback = do_scan(network, args.timeout, use_fallback)
                enriched = enrich(raw, local_ip, skip_vendor=args.no_vendor)
                elapsed = time.time() - t0

                current_ips = {d["ip"] for d in enriched}
                known_ips = set(known.keys())

                joined = current_ips - known_ips
                left = known_ips - current_ips

                # Update known: add new, keep departing briefly for display, remove stale
                for d in enriched:
                    known[d["ip"]] = d
                for ip in left:
                    del known[ip]

                all_devices = list(known.values())

                console.clear()
                console.print(
                    build_table(all_devices, iface, network, elapsed, joined, left)
                )

                if joined:
                    console.print(
                        f"[bold green]New device(s): {', '.join(sorted(joined))}[/bold green]"
                    )
                if left:
                    console.print(
                        f"[bold red]Departed: {', '.join(sorted(left))}[/bold red]"
                    )

                time.sleep(interval)

        except KeyboardInterrupt:
            console.print("\n[dim]Stopped.[/dim]")


if __name__ == "__main__":
    main()
