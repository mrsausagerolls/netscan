#!/usr/bin/env python3
"""WiFi Scanner — lists all devices on your local WiFi network."""

import argparse
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
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

from mac_vendor_lookup import MacLookup, VendorNotFoundError  # type: ignore
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text
from scapy.all import ARP, Ether, srp, conf  # type: ignore

_mac_lookup = MacLookup()
console = Console()

# ── Network detection ────────────────────────────────────────────────────────

def get_wifi_info() -> tuple[str, str, str]:
    """Return (interface, local_ip, cidr_network) for the active WiFi."""
    hw_lines = subprocess.run(
        ["networksetup", "-listallhardwareports"],
        capture_output=True, text=True
    ).stdout.splitlines()

    iface = "en0"
    for i, line in enumerate(hw_lines):
        if "Wi-Fi" in line or "AirPort" in line:
            for nearby in hw_lines[i:i + 4]:
                m = re.search(r"Device:\s+(en\d+)", nearby)
                if m:
                    iface = m.group(1)
                    break
            break

    ifc = subprocess.run(["ifconfig", iface], capture_output=True, text=True).stdout
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+)", ifc)
    if not m:
        console.print(f"[red]No IP found on {iface} — are you connected to WiFi?[/red]")
        sys.exit(1)

    ip = m.group(1)
    prefix = bin(int(m.group(2), 16)).count("1")
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


def fallback_scan(network: str, quiet: bool = False) -> list[dict]:
    if not quiet:
        console.print("[yellow]No root — falling back to ping sweep (slower)…[/yellow]\n")
    hosts = list(IPv4Network(network).hosts())

    def ping(ip):
        subprocess.run(["ping", "-c", "1", "-W", "500", str(ip)], capture_output=True)

    with ThreadPoolExecutor(max_workers=100) as ex:
        list(ex.map(ping, hosts))

    arp_out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
    seen, devices = set(), []
    for line in arp_out.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)", line)
        if m and "incomplete" not in line:
            ip = m.group(1)
            mac = _normalize_mac(m.group(2))
            if ip not in seen and _is_unicast(ip, mac):
                seen.add(ip)
                devices.append({"ip": ip, "mac": mac})
    return devices

# ── Enrichment ───────────────────────────────────────────────────────────────

def get_vendor(mac: str) -> str:
    try:
        return _mac_lookup.lookup(mac)
    except (VendorNotFoundError, Exception):
        return "—"


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
            headers={"User-Agent": "NetScan/1.0"},
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
    return ""


def enrich(devices: list[dict], local_ip: str, skip_vendor: bool = False) -> list[dict]:
    for d in devices:
        d["vendor"] = "—" if skip_vendor else get_vendor(d["mac"])
        d["me"] = d["ip"] == local_ip

    def _resolve(d):
        # gethostbyaddr has no built-in timeout; cap it so a slow upstream
        # resolver can't stall the whole scan cycle.
        try:
            from concurrent.futures import ThreadPoolExecutor as _TPE
            with _TPE(max_workers=1) as inner:
                d["hostname"] = inner.submit(get_hostname, d["ip"]).result(timeout=1.5)
        except Exception:
            d["hostname"] = "—"
        d["latency"] = ping_latency(d["ip"])
        return d

    with ThreadPoolExecutor(max_workers=20) as ex:
        return list(ex.map(_resolve, devices))

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
    network: str, timeout: int, use_fallback: bool, quiet: bool = False
) -> tuple[list[dict], bool]:
    """Run one scan cycle. Returns (devices, use_fallback)."""
    if use_fallback:
        return fallback_scan(network, quiet=quiet), True
    try:
        return arp_scan(network, timeout), False
    except Exception as e:
        if "permission" in str(e).lower() or "root" in str(e).lower():
            return fallback_scan(network, quiet=quiet), True
        console.print(f"[red]Scan error: {e}[/red]")
        sys.exit(1)

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

    console.rule("[bold cyan]WiFi Scanner[/bold cyan]")
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
