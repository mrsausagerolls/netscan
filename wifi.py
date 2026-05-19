"""Wi-Fi neighbor survey via CoreWLAN.

A single function — `scan_neighbors()` — wraps `CWInterface.scanForNetworks…`
and turns the resulting `NSSet<CWNetwork>` into a plain list of dicts the
dashboard can render. Kept tiny so it's easy to swap for a CLI fallback
(e.g. `airport -s`) later if Apple ever deprecates CoreWLAN.

The scan is synchronous and takes 3–10 seconds; callers should run it on a
worker thread. macOS 14+ also gates the SSID field behind Location Services
authorisation — we still return what CoreWLAN gives us (BSSID, channel, RSSI,
security) even when the SSID comes back as the empty string.
"""

from __future__ import annotations


# CoreWLAN's `CWSecurity` enum is exposed by pyobjc as plain ints.
_SECURITY_LABELS = {
    0:  "Open",
    1:  "WEP",
    2:  "WPA Personal",
    3:  "WPA Personal Mixed",
    4:  "WPA2 Personal",
    5:  "Dynamic WEP",
    6:  "WPA Enterprise",
    7:  "WPA Enterprise Mixed",
    8:  "WPA2 Enterprise",
    9:  "WPA3 Personal",
    10: "WPA3 Enterprise",
    11: "WPA3 Transition",
    12: "OWE",
    13: "OWE Transition",
}


def _band_for_channel(ch: int) -> str:
    """2.4/5/6 GHz inference from channel number. Good-enough for display."""
    if not ch:
        return ""
    if ch <= 14:
        return "2.4 GHz"
    if ch >= 36 and ch < 200:
        return "5 GHz"
    if ch >= 200:
        return "6 GHz"
    return ""


def scan_neighbors() -> list[dict]:
    """Run an active Wi-Fi scan and return one dict per visible network.

    Each dict: {ssid, bssid, channel, band, rssi, security, is_current}.
    Returns `[]` when CoreWLAN isn't available or the scan fails.
    """
    try:
        from CoreWLAN import CWWiFiClient  # type: ignore
    except ImportError:
        return []
    try:
        client = CWWiFiClient.sharedWiFiClient()
        iface  = client.interface()
        if iface is None:
            return []
        current_bssid = (iface.bssid() or "").upper()
        networks, error = iface.scanForNetworksWithName_error_(None, None)
        if error or networks is None:
            return []
    except Exception:
        return []

    out: list[dict] = []
    for net in networks:
        try:
            channel_obj = net.wlanChannel()
            channel = int(channel_obj.channelNumber()) if channel_obj else 0
            bssid   = (net.bssid() or "").upper()
            out.append({
                "ssid":       net.ssid() or "",
                "bssid":      bssid,
                "channel":    channel,
                "band":       _band_for_channel(channel),
                "rssi":       int(net.rssiValue() or 0),
                "security":   _SECURITY_LABELS.get(int(net.securityMode() or 0), "Unknown"),
                "is_current": bool(bssid and bssid == current_bssid),
            })
        except Exception:
            continue

    out.sort(key=lambda n: (-n["rssi"], n["ssid"].lower()))
    return out
