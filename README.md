# Inglorious Network Scanner

> **Know everything connected to your WiFi. Get a friendly heads-up the moment something's wrong.**
>
> Made by **Inglorious Labs** — local-only, no telemetry, no cloud, no accounts.

INS is a macOS menu-bar app that watches your home network for you. It names
every device, explains what each one is in plain English, and tells you when
something deserves attention — a new device joined, a camera left its admin
page open to the internet, your network is being claimed by two DHCP servers
at once.

It's built for everyday people who want to know what's on their WiFi without
having to learn ARP, RTSP, or what an IGD is.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/mrsausagerolls/netscan/main/get.sh | bash
```

One command. Clones to `~/.ins`, sets up a Python venv, installs deps, and
registers a LaunchAgent so INS starts on every login. Look for **📡** in your
menubar when it's done.

Requires macOS 13+, Python 3.11+, and git (`xcode-select --install` if missing).

Environment overrides (must be on the **bash** side of the pipe — they're
consumed by the installer, not by curl):

```bash
curl -fsSL https://raw.githubusercontent.com/mrsausagerolls/netscan/main/get.sh \
  | INS_DIR=/custom/path INS_NO_AUTOSTART=1 bash
```

- `INS_DIR=/custom/path` — install somewhere other than `~/.ins`
- `INS_NO_AUTOSTART=1` — skip the LaunchAgent (run manually instead)

The legacy `NETSCAN_DIR` / `NETSCAN_NO_AUTOSTART` variables still work for
people upgrading from earlier installs.

To uninstall:
```bash
launchctl unload ~/Library/LaunchAgents/co.ingloriouslabs.netscan.plist
rm -rf ~/.ins
```

## What INS notices

Out of the box, INS tells you in plain English when:

- A device you've never seen before joined your WiFi.
- A MAC address suddenly reports a different manufacturer (hardware mismatch,
  often a spoofing attempt).
- A risky protocol becomes reachable on any device — Telnet, FTP, RDP, VNC,
  rlogin, rsh, NFS, RPC, IRC, open SOCKS proxy.
- A camera or DVR is on a brand that ships with default credentials, and its
  admin page is up.
- A camera's admin page is reachable over HTTP instead of HTTPS.
- **More than one DHCP server is answering on your LAN** — almost always a
  misconfigured second router or an attacker.
- **An IP address has been claimed by multiple MACs in a short window** — the
  fingerprint of an ARP-spoof / MITM attempt.
- **The router has a WAN port-forward pointing at one of your devices** — INS
  walks the router's UPnP IGD to enumerate every public-facing mapping and
  flags cameras and unencrypted protocols as critical.
- A device looked up a domain on the local threat-intel list (optional;
  ship-your-own list).
- Your phone's randomized WiFi MAC changed (collapsed into a single
  "this is probably the same iPhone" notice instead of repeated joined-alerts).

## Network Health Score

The dashboard's Overview tab shows a single **0–100 Network Health Score**
with the top reasons your score isn't 100, sorted by impact. One unencrypted
camera is a soft tap on the score; a rogue DHCP server cuts it in half. The
score gives non-technical users an at-a-glance read; the reason list tells
them where to act first.

## Naming new devices

Every unknown device queues in a strip pinned to the top of the Devices tab
so you can name or ignore them in a single sitting — first-launch, after a
party, after the router rebooted. Bulk-mark, individual rename, and an
Ignore action that also stops probing fragile IoT.

## Launchers

Three ways to open INS, all installed automatically by `get.sh` /
`install.sh`:

- **Menubar** (📡) — already running after install; the auto-start LaunchAgent
  keeps it there across logins.
- **`/Applications/Inglorious Network Scanner.app`** — a small clickable
  launcher. Double-click from Finder or pin it to the Dock; it loads the
  LaunchAgent if INS isn't running, waits for the dashboard to come up,
  and opens it in your default browser. Unsigned, so Gatekeeper warns on
  first launch — right-click → Open.
- **`ins` CLI** (symlinked into `~/.local/bin`):

  | Command | Does |
  |---|---|
  | `ins`            | Open the dashboard (starts INS if needed) |
  | `ins start`      | Load the LaunchAgent |
  | `ins stop`       | Unload the LaunchAgent |
  | `ins restart`    | Kickstart |
  | `ins status`     | Show running state + dashboard reachability |
  | `ins logs`       | Tail `/tmp/ins.log` |
  | `ins update`     | Run `update.sh` |
  | `ins version`    | Print installed version |

  Add `~/.local/bin` to your PATH if it isn't already.

## Dashboard

Open from the menubar (`Open Dashboard ↗ localhost:8765`), the Applications
launcher, the `ins` CLI, or directly at `http://localhost:8765`.

Tabs: **Overview** (the status statement, everything needing attention, and
a network summary), **Devices** (the full list, with new-device naming pinned
on top), **Activity** (alert history, devices-over-time chart, Wi-Fi survey),
and **Settings** (remote access, notifications, webhooks, router, join hook,
privacy).

Every alert has a *"What does this mean?"* button that opens an inline drawer
with a plain-English explanation and the recommended fix.

### Notifications & webhooks

Critical alerts fire as native macOS banners. Burst-coalescing collapses
floods of `new_device` alerts (everyone reconnecting after a router reboot)
into a single banner.

Send alerts off-Mac via webhooks — INS auto-detects the receiver from the URL:

| Receiver | URL shape |
|---|---|
| **Discord** | `https://discord.com/api/webhooks/...` |
| **Slack**   | `https://hooks.slack.com/services/...` |
| **Pushover**| `https://api.pushover.net/1/messages.json?token=APP&user=USR` |
| **ntfy**    | `https://ntfy.sh/your-topic` |
| Generic     | anything else → clean JSON `{source, alert}` body |

Add as many as you want; each one has a minimum severity filter (info /
warning / critical only).

### Security model

The server binds to `127.0.0.1` only, unless you explicitly enable
**Settings → Remote access** (off by default), which serves a token-gated,
read-only view on your LAN for the iOS companion — see SECURITY.md.
Mutating endpoints (`/api/known/*`,
`/api/hook`, `/api/wol`, `/api/triage/*`, `/api/devices/no_probe`) require a
same-origin `Origin` or `Referer` header; cross-origin requests are rejected
with HTTP 403. The join hook stores an arbitrary shell command, so this check
is what prevents a malicious webpage from silently installing one.

See [SECURITY.md](SECURITY.md) for the full privacy + threat-model statement.

## Privacy

Everything stays on your Mac. No cloud, no accounts, no telemetry.

The only outbound calls INS makes are:

1. **GitHub Releases API** every 6 h for update checks. Anonymous.
2. **MAC vendor lookups** against a locally cached OUI database.
3. **Optional**: webhooks *you* configure (Discord, Slack, Pushover, ntfy, …).

That's it. Full statement in [SECURITY.md](SECURITY.md).

## Updating

INS checks the GitHub Releases API every 6 hours (and once 10 s after
startup). When a newer release exists, an `⬆️ Update available · vX.Y.Z` item
appears at the top of the menubar.

- **Source install** (via `get.sh`): click the item, confirm, and `update.sh`
  hard-resets `~/.ins` onto the exact released tag you were shown — so the code
  matches what you consented to, and a stray local edit can't strand the update;
  your `.venv` and `data/` are left untouched — then restarts the LaunchAgent.
  Logs to `/tmp/ins-update.log`. Manual: `~/.ins/update.sh`.
- **Signed .app** (planned — v2.5, see ROADMAP): until then the supported path
  is `get.sh`; for the unsigned .app the menubar item just opens the release
  page so you can download and replace it manually.

## Manual install (alternative)

```bash
git clone https://github.com/mrsausagerolls/netscan.git ~/.ins
cd ~/.ins
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./install.sh
```

## Build a .app bundle

```bash
pip install py2app
python setup.py py2app
hdiutil create -volname "InglNetScan" -srcfolder dist/InglNetScan.app -ov \
  -format UDZO InglNetScan.dmg
```

Until INS is built with an Apple Developer ID, the resulting `.app` is
unsigned and Gatekeeper will block it for end users — that's why the
supported install path is `get.sh`. See [ROADMAP.md](ROADMAP.md) for the
signing-and-notarization plan.

## SSID display

macOS 14+ requires **Location Services** access to read the WiFi SSID. Grant
it in **System Settings → Privacy & Security → Location Services → Python**
(or your terminal app, when running from source). The first launch will
prompt automatically.

## Requirements

- macOS 13+, Apple Silicon or Intel
- Python 3.11+
- `sudo` / root for ARP scanning (falls back to ping sweep otherwise)

## Tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

## Reporting a security issue

Email **security@inglorious.co** — please don't open a public GitHub issue
for unpatched vulnerabilities. Full disclosure policy in [SECURITY.md](SECURITY.md).

---

Inglorious Network Scanner — © 2026 Inglorious Labs
