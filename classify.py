"""Device-type classifier.

Maps a discovered device to a human-friendly category using three signals:

  1. Vendor (OUI lookup) — strongest single signal for the long tail of IoT
  2. Open ports — printer (9100), camera (554), Windows host (445), router admin (80+443+8080)
  3. Fingerprint strings — mDNS / SSDP friendlyName / NetBIOS name keywords

Confidence is a 0.0-1.0 score combining the rule weights that fired.

Adding a new vendor or pattern: edit the constants at the top — no logic changes.
"""

import re

# Display label per type. Used everywhere in the UI.
TYPE_LABELS = {
    "router":      "Router / Gateway",
    "access_point":"Access Point",
    "printer":     "Printer",
    "camera":      "Camera",
    "tv":          "TV / Streaming Box",
    "speaker":     "Speaker",
    "phone":       "Phone",
    "tablet":      "Tablet",
    "laptop":      "Laptop",
    "desktop":     "Desktop",
    "computer":    "Computer",
    "watch":       "Wearable",
    "console":     "Game Console",
    "nas":         "NAS / Storage",
    "iot":         "Smart Home / IoT",
    "voice_assistant": "Voice Assistant",
    "server":      "Server",
    "unknown":     "Unknown",
}

TYPE_ICONS = {
    "router":      "🛰",
    "access_point":"📶",
    "printer":     "🖨",
    "camera":      "📷",
    "tv":          "📺",
    "speaker":     "🔊",
    "phone":       "📱",
    "tablet":      "📱",
    "laptop":      "💻",
    "desktop":     "🖥",
    "computer":    "💻",
    "watch":       "⌚",
    "console":     "🎮",
    "nas":         "💾",
    "iot":         "💡",
    "voice_assistant": "🗣",
    "server":      "🗄",
    "unknown":     "❔",
}

# Vendor substring (case-insensitive) → device type.
# Order doesn't matter — longest specific match wins via _match_vendor.
_VENDOR_TYPE: list[tuple[str, str]] = [
    # Network gear
    ("ubiquiti",        "access_point"),
    ("aruba",           "access_point"),
    ("ruckus",          "access_point"),
    ("eero",            "access_point"),
    ("plume",           "access_point"),
    ("netgear",         "router"),
    ("tp-link",         "router"),
    ("tp link",         "router"),
    ("d-link",          "router"),
    ("asus",            "router"),
    ("linksys",         "router"),
    ("cisco",           "router"),
    ("mikrotik",        "router"),
    ("zyxel",           "router"),
    ("fortinet",        "router"),
    ("juniper",         "router"),
    ("huawei",          "router"),
    # Printers
    ("brother",         "printer"),
    ("hewlett packard", "printer"),  # HP printers often appear as full string
    ("epson",           "printer"),
    ("canon",           "printer"),
    ("lexmark",         "printer"),
    ("kyocera",         "printer"),
    ("ricoh",           "printer"),
    ("xerox",           "printer"),
    # Cameras
    ("hikvision",       "camera"),
    ("dahua",           "camera"),
    ("axis communic",   "camera"),
    ("amcrest",         "camera"),
    ("reolink",         "camera"),
    ("foscam",          "camera"),
    ("wyze",            "camera"),
    ("nest labs",       "camera"),
    ("arlo",            "camera"),
    ("ring",            "camera"),
    ("ezviz",           "camera"),
    # TVs / streamers
    ("roku",            "tv"),
    ("vizio",           "tv"),
    ("hisense",         "tv"),
    ("tcl ",            "tv"),
    ("lg electronics",  "tv"),
    ("samsung electronics", "tv"),
    ("amazon technologies", "tv"),  # Fire TV; refined by fingerprint later
    ("chromecast",      "tv"),
    ("apple tv",        "tv"),
    # Speakers / voice
    ("sonos",           "speaker"),
    ("bose",            "speaker"),
    ("sonance",         "speaker"),
    ("harman international", "speaker"),
    # Consoles
    ("nintendo",        "console"),
    ("sony interactive", "console"),
    ("microsoft xbox",  "console"),
    # NAS
    ("synology",        "nas"),
    ("qnap",            "nas"),
    ("western digital", "nas"),
    ("seagate",         "nas"),
    ("buffalo",         "nas"),
    # Phones / tablets / wearables
    ("apple, inc",      "phone"),    # default for Apple; refined by fingerprint
    ("apple inc",       "phone"),
    ("samsung",         "phone"),    # refined by fingerprint
    ("xiaomi",          "phone"),
    ("oppo",            "phone"),
    ("oneplus",         "phone"),
    ("google, inc",     "phone"),
    ("motorola",        "phone"),
    # IoT vendors
    ("espressif",       "iot"),
    ("tuya",            "iot"),
    ("shelly",          "iot"),
    ("philips lighting","iot"),
    ("signify",         "iot"),
    ("belkin",          "iot"),
    ("tp-link technologies (shenzhen)", "iot"),
    ("lifi labs",       "iot"),
    ("ecobee",          "iot"),
    ("honeywell",       "iot"),
    ("ihome",           "iot"),
    # Computers
    ("dell",            "desktop"),
    ("lenovo",          "laptop"),
    ("intel corporate", "computer"),
    ("micro-star",      "desktop"),
    ("gigabyte",        "desktop"),
    ("asustek",         "desktop"),
    ("raspberry pi",    "computer"),
    # Voice assistants
    ("amazon, technologies", "voice_assistant"),
]

# Fingerprint keyword (case-insensitive) → device type.
_FP_KEYWORDS: list[tuple[str, str]] = [
    (r"apple tv\b",       "tv"),
    (r"iphone\b",         "phone"),
    (r"ipad\b",           "tablet"),
    (r"macbook\b",        "laptop"),
    (r"imac\b",           "desktop"),
    (r"mac mini\b",       "desktop"),
    (r"airport\b",        "access_point"),
    (r"echodot\b|echo dot|amazon echo", "voice_assistant"),
    (r"alexa\b",          "voice_assistant"),
    (r"google home\b|google nest hub", "voice_assistant"),
    (r"homepod\b",        "speaker"),
    (r"sonos\b",          "speaker"),
    (r"roku\b",           "tv"),
    (r"fire tv\b|firestick|fire stick", "tv"),
    (r"nintendo\b|switch", "console"),
    (r"playstation\b|ps5|ps4", "console"),
    (r"xbox\b",           "console"),
    (r"printer\b|laserjet|deskjet|officejet", "printer"),
    (r"camera\b|ipcam|nvr|hikvision|dahua", "camera"),
    (r"nas\b|synology|qnap|drobo", "nas"),
    (r"router\b|gateway|asuswrt", "router"),
    (r"access point\b|unifi|aruba|ubnt", "access_point"),
    (r"watch\b",          "watch"),
    (r"thermostat\b",     "iot"),
    (r"smartplug\b|smart plug|smart bulb", "iot"),
]

# Port-set heuristics — applied only if vendor + fingerprint were inconclusive.
def _port_type(ports: set[int]) -> str | None:
    if 9100 in ports:                              return "printer"        # JetDirect
    if 554 in ports and not (80 in ports and 443 in ports):
        return "camera"                                                     # RTSP
    if (137 in ports or 139 in ports) and 445 in ports:
        return "computer"                                                   # SMB host
    if 80 in ports and 443 in ports and 8080 in ports:
        return "router"                                                     # router admin
    if 22 in ports and 80 in ports and 445 not in ports:
        return "server"                                                     # Linux/server
    if 8883 in ports or 1883 in ports:             return "iot"             # MQTT
    return None


def _match_vendor(vendor: str) -> tuple[str, float] | None:
    v = (vendor or "").lower()
    if not v or v == "—":
        return None
    best: tuple[str, str] | None = None
    for needle, dtype in _VENDOR_TYPE:
        if needle in v:
            if best is None or len(needle) > len(best[0]):
                best = (needle, dtype)
    return (best[1], 0.6) if best else None


def _match_fingerprint(fp_string: str) -> tuple[str, float] | None:
    s = (fp_string or "").lower()
    if not s:
        return None
    for pat, dtype in _FP_KEYWORDS:
        if re.search(pat, s):
            return (dtype, 0.85)
    return None


def classify(
    vendor: str = "",
    fingerprint: str = "",
    ports: list[int] | None = None,
    hostname: str = "",
) -> tuple[str, float]:
    """Return (device_type_key, confidence_0_to_1).

    Priority: fingerprint keyword > vendor OUI > port heuristic > unknown.
    Hostname is folded into the fingerprint check so router .local names work.
    """
    ports_set = set(ports or [])
    combined_fp = " ".join(filter(None, [fingerprint, hostname]))

    fp_match = _match_fingerprint(combined_fp)
    if fp_match:
        return fp_match

    vendor_match = _match_vendor(vendor)
    port_match   = _port_type(ports_set)

    if vendor_match and port_match and vendor_match[0] == port_match:
        return (vendor_match[0], 0.9)        # both signals agree → high confidence
    if vendor_match:
        return vendor_match
    if port_match:
        return (port_match, 0.5)

    return ("unknown", 0.0)


def label(device_type: str) -> str:
    return TYPE_LABELS.get(device_type, "Unknown")


def icon(device_type: str) -> str:
    return TYPE_ICONS.get(device_type, "❔")
