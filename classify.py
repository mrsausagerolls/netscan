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

# DHCP option-55 (Parameter Request List) signatures. The sequence of requested
# parameters differs distinctly between operating systems even when the client
# randomises its MAC. We match by "the full sequence equals X" first, then by
# distinctive feature options as a fallback. Compiled from public DHCP traces
# (fingerbank.org, Wireshark sample captures); add more as you observe them.
#
# Format: (option_55_sequence_as_csv_string, device_type, vendor_hint, label_hint)
_DHCP_55_EXACT: list[tuple[str, str, str, str]] = [
    # Apple — iOS / iPadOS
    ("1,121,3,6,15,119,252",                          "phone",   "Apple", "iPhone / iPad"),
    ("1,3,6,15,119,252",                              "phone",   "Apple", "iPhone / iPad"),
    # Apple — macOS
    ("1,121,3,6,15,114,119,252",                      "laptop",  "Apple", "Mac"),
    ("1,3,6,15,114,119,252,95,44,46",                 "laptop",  "Apple", "Mac"),
    # Android
    ("1,3,6,15,26,28,51,58,59,43",                    "phone",   "",      "Android"),
    ("1,33,3,6,15,26,28,51,58,59,43",                 "phone",   "",      "Android"),
    # Windows 10 / 11
    ("1,3,6,15,31,33,43,44,46,47,121,249,252",        "computer","",      "Windows"),
    ("1,15,3,6,44,46,47,31,33,121,249,43,252",        "computer","",      "Windows"),
    # ChromeOS
    ("1,33,3,6,12,15,26,28,42,51,54,58,59,119,252",   "laptop",  "",      "ChromeOS"),
    # Generic Linux / dhclient
    ("1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,33,252,42", "computer","","Linux"),
]

# Distinctive feature options — if the PRL contains them, we can still infer
# coarse OS family even when the exact sequence doesn't match a known signature.
# Triggers only when no _DHCP_55_EXACT match was found.
_DHCP_55_FEATURES: list[tuple[set[int], str, str, str]] = [
    # WPAD (252) is overwhelmingly an Apple/Microsoft thing; combined with 119
    # (domain search) and 95 (LDAP) it leans Apple.
    ({252, 119, 95},                                  "laptop",  "Apple", "Mac"),
    # Window's Vista+ Classless Static Route (121) + ms-classless (249).
    ({121, 249, 252},                                 "computer","",      "Windows"),
    # Android-distinctive: 26 (Interface MTU) + 51 (Lease Time) early.
    ({26, 51, 58, 59},                                "phone",   "",      "Android"),
]


def _match_dhcp(hints: dict) -> tuple[str, str, str, float] | None:
    """Return (device_type, vendor_hint, label_hint, confidence) from DHCP
    option 55 if we can. None when no DHCP fingerprint is recorded or no
    signature matches."""
    prl = (hints or {}).get("dhcp_55", "")
    if not prl:
        return None
    for sig, dtype, vendor, label in _DHCP_55_EXACT:
        if sig == prl:
            return (dtype, vendor, label, 0.9)
    requested = {int(x) for x in prl.split(",") if x.strip().isdigit()}
    for feats, dtype, vendor, label in _DHCP_55_FEATURES:
        if feats.issubset(requested):
            return (dtype, vendor, label, 0.65)
    return None


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
    (r"nintendo\b", "console"),  # bare "switch" removed — matched network switches, "light switch", etc.
    (r"playstation\b|ps5|ps4", "console"),
    (r"xbox\b",           "console"),
    (r"printer\b|laserjet|deskjet|officejet", "printer"),
    (r"camera\b|ipcam|nvr|hikvision|dahua", "camera"),
    # \bnas\b so "Jonas-PC" isn't a NAS; the prefix allowlist still catches the
    # common concatenated names (mynas, homenas, filenas, storagenas).
    (r"\bnas\b|\b(?:my|home|file|storage)nas\b|synology|qnap|drobo", "nas"),
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
    hints: dict | None = None,
) -> tuple[str, float]:
    """Return (device_type_key, confidence_0_to_1).

    Priority: fingerprint keyword > DHCP-55 exact > vendor OUI > port
    heuristic > DHCP-55 feature-set > unknown. Hostname is folded into the
    fingerprint check so router .local names work.
    """
    ports_set = set(ports or [])
    combined_fp = " ".join(filter(None, [fingerprint, hostname]))

    fp_match = _match_fingerprint(combined_fp)
    if fp_match:
        return fp_match

    dhcp_match = _match_dhcp(hints or {})
    if dhcp_match and dhcp_match[3] >= 0.85:
        return (dhcp_match[0], dhcp_match[3])

    vendor_match = _match_vendor(vendor)
    port_match   = _port_type(ports_set)

    if vendor_match and port_match and vendor_match[0] == port_match:
        return (vendor_match[0], 0.9)        # both signals agree → high confidence
    if vendor_match:
        return vendor_match
    if dhcp_match:                           # weaker DHCP feature-set fallback
        return (dhcp_match[0], dhcp_match[3])
    if port_match:
        return (port_match, 0.5)

    return ("unknown", 0.0)


def dhcp_vendor(hints: dict | None) -> str:
    """Return the vendor hint suggested by the DHCP fingerprint, or ""."""
    m = _match_dhcp(hints or {})
    return m[1] if m else ""


def dhcp_label(hints: dict | None) -> str:
    """Return a short OS-family label suggested by the DHCP fingerprint, or "".

    Used as a fallback display name when probes don't yield an mDNS/SSDP
    friendly name. Examples: "iPhone / iPad", "Mac", "Windows", "Android".
    """
    m = _match_dhcp(hints or {})
    return m[2] if m else ""


def label(device_type: str) -> str:
    return TYPE_LABELS.get(device_type, "Unknown")


def icon(device_type: str) -> str:
    return TYPE_ICONS.get(device_type, "❔")
