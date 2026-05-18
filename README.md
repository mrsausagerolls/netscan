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

```bash
./install.sh
```

`install.sh` substitutes the venv Python path and `app.py` path into `com.wifiscanner.plist.tmpl` and loads it as a user LaunchAgent.

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

## Dashboard security

The dashboard binds to `127.0.0.1` only. Mutating endpoints (`/api/known/*`, `/api/hook`, `/api/wol`) require a same-origin `Origin` or `Referer` header (`http://127.0.0.1:8765` or `http://localhost:8765`); cross-origin requests are rejected with 403. The join hook stores an arbitrary shell script, so this check is what prevents a malicious webpage from silently installing one.

## Tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

Smoke tests cover the WoL packet layout, MAC/IP filters, store roundtrip, and the dashboard origin check.
