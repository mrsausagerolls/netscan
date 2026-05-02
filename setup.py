"""py2app build script — run: python setup.py py2app"""

from setuptools import setup

APP     = ["app.py"]
OPTIONS = {
    "argv_emulation": False,  # Must be False for menu-bar apps
    "plist": {
        "CFBundleName":                "NetScan",
        "CFBundleDisplayName":         "NetScan",
        "CFBundleIdentifier":          "com.netscan.wifiscanner",
        "CFBundleVersion":             "1.0.0",
        "CFBundleShortVersionString":  "1.0.0",
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
        "SystemConfiguration",
    ],
    "includes": ["scanner", "store", "dashboard", "wol"],
    "excludes": ["tkinter", "unittest", "email", "html", "http", "xmlrpc"],
}

setup(
    name    = "NetScan",
    version = "1.0.0",
    app     = APP,
    options = {"py2app": OPTIONS},
    setup_requires = ["py2app"],
)
