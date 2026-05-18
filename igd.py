"""UPnP IGD (Internet Gateway Device) client.

Enumerates the WAN port mappings configured on the local router. This is how
we surface "port 8443 on this camera is reachable from the public internet"
in plain English: if the router has an active IGD mapping for that LAN
ip:port → external port, INS warns about it.

We only *read* mappings. We never call AddPortMapping / DeletePortMapping —
INS doesn't modify the router.

Public API:
  discover_igd() -> dict | None        # SSDP M-SEARCH for an IGD control URL
  list_port_mappings(igd) -> list[Mapping]

Mapping is a dataclass with: external_port, internal_client, internal_port,
protocol, description, lease_duration, enabled.

All network calls have hard timeouts; the module is safe to call from the
scanner thread but it does block, so call it on a worker.
"""

import re
import socket
import urllib.parse
import urllib.request
from dataclasses import dataclass
from xml.etree import ElementTree

_NS = {
    "s": "http://schemas.xmlsoap.org/soap/envelope/",
}

_IGD_SEARCH_TARGETS = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
]


@dataclass(frozen=True)
class Mapping:
    external_port:   int
    internal_client: str
    internal_port:   int
    protocol:        str       # TCP / UDP
    description:     str
    lease_duration:  int
    enabled:         bool

    def is_public(self) -> bool:
        """True if this mapping exposes an internal host to the WAN side."""
        return self.enabled and self.external_port > 0 and bool(self.internal_client)


# ── Discovery ────────────────────────────────────────────────────────────────


def discover_igd(timeout: float = 2.0) -> dict | None:
    """Multicast SSDP M-SEARCH for an IGD; return its control URL + service type.

    Returns None if no IGD answers (no router, IGD disabled, or blocked).
    """
    for st in _IGD_SEARCH_TARGETS:
        loc = _msearch(st, timeout=timeout)
        if not loc:
            continue
        meta = _parse_device_xml(loc)
        if meta:
            return meta
    return None


def _msearch(st: str, timeout: float) -> str | None:
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        f"ST: {st}\r\n\r\n"
    ).encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.sendto(msg, ("239.255.255.250", 1900))
        # Read first response (we don't try multiple routers).
        data, _ = s.recvfrom(2048)
        s.close()
        resp = data.decode("utf-8", errors="ignore")
        m = re.search(r"(?i)^LOCATION:\s*(\S+)", resp, re.M)
        return m.group(1).strip() if m else None
    except (OSError, socket.timeout):
        return None


def _parse_device_xml(location: str) -> dict | None:
    """Walk the device description; return {control_url, service_type, urlbase}."""
    try:
        with urllib.request.urlopen(location, timeout=2) as resp:
            body = resp.read(64 * 1024)
    except Exception:
        return None

    parsed = urllib.parse.urlparse(location)
    urlbase = f"{parsed.scheme}://{parsed.netloc}"

    # The XML uses an internal namespace; strip it for simpler iteration.
    text = re.sub(rb'\sxmlns="[^"]+"', b"", body, count=1)
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None

    for svc in root.iter("service"):
        st = (svc.findtext("serviceType") or "").strip()
        ctrl = (svc.findtext("controlURL") or "").strip()
        if "WANIPConnection" in st or "WANPPPConnection" in st:
            if not ctrl:
                continue
            if not ctrl.startswith("http"):
                ctrl = urllib.parse.urljoin(urlbase + "/", ctrl)
            return {"control_url": ctrl, "service_type": st, "urlbase": urlbase}
    return None


# ── Port-mapping enumeration ─────────────────────────────────────────────────


def list_port_mappings(igd: dict, max_entries: int = 64) -> list[Mapping]:
    """Walk GetGenericPortMappingEntry from index 0 until the router returns
    SpecifiedArrayIndexInvalid (HTTP 500 on most routers).

    Returns the list it managed to collect. Routers vary wildly in correctness;
    a partial list is better than none, so failures stop iteration but don't
    raise.
    """
    out: list[Mapping] = []
    for i in range(max_entries):
        entry = _get_mapping(igd, i)
        if entry is None:
            break
        out.append(entry)
    return out


def _get_mapping(igd: dict, index: int) -> Mapping | None:
    body = (
        '<?xml version="1.0"?>\n'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        f'<u:GetGenericPortMappingEntry xmlns:u="{igd["service_type"]}">'
        f"<NewPortMappingIndex>{index}</NewPortMappingIndex>"
        "</u:GetGenericPortMappingEntry>"
        "</s:Body></s:Envelope>"
    ).encode()
    req = urllib.request.Request(
        igd["control_url"],
        data=body,
        headers={
            "Content-Type": "text/xml; charset=\"utf-8\"",
            "SOAPAction":
                f'"{igd["service_type"]}#GetGenericPortMappingEntry"',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            xml = resp.read(8192)
    except Exception:
        return None

    return _parse_mapping(xml)


def _parse_mapping(xml: bytes) -> Mapping | None:
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return None

    def find(tag: str) -> str:
        # Tags can appear with or without a namespace prefix depending on the
        # router. Strip namespaces and search by local name.
        for el in root.iter():
            local = el.tag.rsplit("}", 1)[-1]
            if local == tag and el.text is not None:
                return el.text.strip()
        return ""

    ext = find("NewExternalPort")
    if not ext:
        return None
    try:
        return Mapping(
            external_port   = int(ext or 0),
            internal_client = find("NewInternalClient"),
            internal_port   = int(find("NewInternalPort") or 0),
            protocol        = find("NewProtocol") or "TCP",
            description     = find("NewPortMappingDescription"),
            lease_duration  = int(find("NewLeaseDuration") or 0),
            enabled         = find("NewEnabled") in ("1", "true", "True"),
        )
    except ValueError:
        return None


# ── Convenience ──────────────────────────────────────────────────────────────


def wan_exposed_for(internal_ip: str) -> list[Mapping]:
    """Best-effort: return active WAN mappings pointing at a specific LAN IP.

    Returns an empty list if no IGD is reachable (no router exposes UPnP, or
    UPnP is disabled — which is the safer state and shouldn't itself raise).
    """
    igd = discover_igd()
    if not igd:
        return []
    return [m for m in list_port_mappings(igd)
            if m.is_public() and m.internal_client == internal_ip]
