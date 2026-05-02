# NetScan

macOS menu-bar app that continuously scans your local WiFi network, shows all connected devices, and serves a live dashboard at `http://localhost:8765`.

## Features

- ARP scan (requires `sudo`) with automatic ping-sweep fallback
- Device enrichment: vendor lookup, hostname resolution, ping latency, port scan
- Known-device allowlist with custom labels (green = known, red = unknown, blue = you)
- Wake-on-LAN
- Join hook — run a shell script when a new device appears
- Live web dashboard with sortable table, history chart, and device manager
- Auto-rescans every 5 s; detects network changes

## Install from source

```bash
git clone <repo-url>
cd wifi-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run once to verify:
```bash
sudo python app.py
```

### Launch at login (LaunchAgent)

Edit `com.wifiscanner.plist` — set the `ProgramArguments` paths to match your installation — then:

```bash
cp com.wifiscanner.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.wifiscanner.plist
```

## Build DMG

```bash
pip install py2app
python setup.py py2app
hdiutil create -volname NetScan -srcfolder dist/NetScan.app -ov -format UDZO NetScan.dmg
```

## SSID display

macOS 14+ requires **Location Services** access to read the WiFi SSID.  
Grant it in: **System Settings → Privacy & Security → Location Services → Python** (or your terminal app).

## Requirements

- macOS 13+, Apple Silicon or Intel
- Python 3.11+
- `sudo` / root for ARP scanning (falls back to ping sweep otherwise)
