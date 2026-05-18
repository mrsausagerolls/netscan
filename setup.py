"""py2app build script — run: python setup.py py2app"""

from setuptools import setup
from version import __version__

APP     = ["app.py"]
OPTIONS = {
    "argv_emulation": False,  # Must be False for menu-bar apps
    "plist": {
        "CFBundleName":                "NetScan",
        "CFBundleDisplayName":         "NetScan",
        "CFBundleIdentifier":          "com.netscan.wifiscanner",
        "CFBundleVersion":             __version__,
        "CFBundleShortVersionString":  __version__,
        "LSUIElement":                 True,   # Hide from Dock
        "NSLocationWhenInUseUsageDescription":
            "NetScan reads the WiFi SSID to display your current network name.",
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
    "includes": ["scanner", "store", "dashboard", "wol", "updater", "version"],
    "excludes": ["tkinter", "unittest", "xmlrpc"],
}

setup(
    name    = "NetScan",
    version = __version__,
    app     = APP,
    options = {"py2app": OPTIONS},
    setup_requires = ["py2app"],
)
