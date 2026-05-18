# NetScan

> Made by **Inglorious Labs**

macOS menu-bar app that continuously scans your local WiFi network, shows all connected devices, and serves a live dashboard at `http://localhost:8765`.

## Features

- ARP scan (requires `sudo`) with automatic ping-sweep fallback
- Device enrichment: vendor lookup, hostname resolution, ping latency, port scan
- Identification probes: mDNS, UPnP/SSDP, NetBIOS, HTTP fingerprinting
- Known-device allowlist with custom labels (green = known, red = unknown, blue = you)
- Wake-on-LAN
- Join hook — run a shell script when a new device joins
- Live web dashboard with sortable table, history chart, and device manager
- Auto-rescans every 5 s; detects network changes
- In-app update check against GitHub Releases

## Install from source

```bash
git clone https://github.com/mrsausagerolls/netscan.git wifi-scanner
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

`install.sh` substitutes the venv Python path and `app.py` path into `com.wifiscanner.plist.tmpl` and loads it as a per-user LaunchAgent.

### Updating

NetScan checks the GitHub Releases API every 6 hours (and once 10 s after startup). When a newer release exists, an `⬆️  Update available  ·  vX.Y.Z` item appears at the top of the menubar.

- **Source install** (cloned + `install.sh`): click the item, confirm, and `update.sh` runs `git pull --ff-only` and restarts the LaunchAgent via `launchctl kickstart -k`. Logs to `/tmp/netscan-update.log`. To check manually: `./update.sh`.
- **DMG install** (`/Applications/NetScan.app`): click the item to open the release page; download and replace the .app.

To cut a release: bump [version.py](version.py), tag `vX.Y.Z`, push the tag, and publish a GitHub Release at that tag (attach the DMG so DMG users can download directly).

## Build DMG

```bash
pip install py2app
python setup.py py2app
hdiutil create -volname NetScan -srcfolder dist/NetScan.app -ov -format UDZO NetScan.dmg
```

The bundle is stamped with `CFBundleGetInfoString = "NetScan X.Y.Z — Made by Inglorious Labs"` and `NSHumanReadableCopyright = "© 2026 Inglorious Labs"`, visible in **About NetScan** and the .app's Get Info pane.

## SSID display

macOS 14+ requires **Location Services** access to read the WiFi SSID. Grant it in **System Settings → Privacy & Security → Location Services → Python** (or your terminal app, when running from source). The first launch will prompt automatically.

## Dashboard

Open from the menubar (`Open Dashboard ↗ localhost:8765`) or directly at `http://localhost:8765`.

The dashboard is a single-page UI: any path under `http://localhost:8765/*` resolves to the dashboard (SPA-style fallback), so stale bookmarks and typo'd URLs still load it. Only `/api/*` paths return JSON.

### Security model

The server binds to `127.0.0.1` only. Mutating endpoints (`/api/known/*`, `/api/hook`, `/api/wol`) require a same-origin `Origin` or `Referer` header (`http://127.0.0.1:8765` or `http://localhost:8765`); cross-origin requests are rejected with 403. The join hook stores an arbitrary shell script, so this check is what prevents a malicious webpage from silently installing one.

## Requirements

- macOS 13+, Apple Silicon or Intel
- Python 3.11+
- `sudo` / root for ARP scanning (falls back to ping sweep otherwise)

## Tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

Smoke tests cover the WoL packet layout, MAC/IP filters, store roundtrip, the dashboard origin check, and the updater's version comparison + network-failure handling.

---

NetScan — © 2026 Inglorious Labs
