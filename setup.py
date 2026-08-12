"""py2app build script — run: python setup.py py2app

NOTE: until Inglorious Labs is a registered Apple Developer, the .app produced
by this script is unsigned and unnotarized. macOS Gatekeeper will block it for
end users. The supported install path is `get.sh` (source + LaunchAgent).
This script is kept so a signed build can be cut later without code changes.
"""

from setuptools import setup
from version import __version__, __app_name__, __org__

APP     = ["app.py"]
OPTIONS = {
    "argv_emulation": False,  # Must be False for menu-bar apps
    "plist": {
        "CFBundleName":                "InglNetScan",
        "CFBundleDisplayName":         __app_name__,
        "CFBundleIdentifier":          "co.ingloriouslabs.netscan",
        "CFBundleVersion":             __version__,
        "CFBundleShortVersionString":  __version__,
        "CFBundleGetInfoString":       f"{__app_name__} {__version__} — Made by {__org__}",
        "NSHumanReadableCopyright":    f"© 2026 {__org__}",
        "LSUIElement":                 True,   # Hide from Dock
        "NSLocationWhenInUseUsageDescription":
            f"{__app_name__} reads the WiFi SSID to display your current network name.",
    },
    "packages": [
        "rumps",
        "scapy",
        "rich",
        "mac_vendor_lookup",
        "objc",
        "CoreWLAN",
        "CoreLocation",
        "SystemConfiguration",
    ],
    # Every first-party module, including the lazily-imported ones (routerctl,
    # launchd_agent, wifi, threats are `import`ed inside functions/handlers, and
    # igd/detect/health/sniffer/actions off app.py). py2app's static modulegraph
    # can miss lazy imports, so list them explicitly or a frozen build crashes
    # the first time it hits one.
    "includes": [
        "scanner", "store", "dashboard", "wol", "updater", "version",
        "classify", "security", "events", "notify", "webhooks",
        "detect", "health", "igd", "sniffer", "routerctl",
        "launchd_agent", "actions", "threats", "wifi",
    ],
    "excludes": ["tkinter", "unittest", "xmlrpc"],
    # Bundle the dashboard assets (HTML/CSS/JS + self-hosted fonts) into
    # Contents/Resources/static so a frozen build serves the real dashboard,
    # not the bare fallback page. dashboard.py resolves this from a
    # sys.frozen-aware base.
    "resources": ["static"],
}

setup(
    name    = __app_name__,
    version = __version__,
    app     = APP,
    options = {"py2app": OPTIONS},
    setup_requires = ["py2app"],
)
