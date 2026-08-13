# Roadmap

The principles INS optimizes for, in order:

1. **Local-only.** No accounts, no cloud, no telemetry.
2. **Friendly for non-experts.** Plain-English alerts with one concrete action.
3. **Useful out of the box.** First scan on first launch; no setup required.
4. **Honest about uncertainty.** Confidence-aware labels — never falsely
   confident, never falsely scary.

## Shipped — v2.0

- Static-SPA dashboard (`/static/`) replacing inlined HTML.
- SQLite store with WAL — survives crashes, migrates v1 JSON automatically.
- Device classifier (`classify.py`) — vendor + port + fingerprint signals.
- Plain-English security rules (`security.py`):
  - New device joined
  - Hardware (vendor) mismatch on a MAC
  - Risky port newly opened (Telnet, FTP, RDP, VNC, etc.)
  - Default-password risk (Hikvision / Dahua / Foscam / Xiongmai)
  - Camera admin page on HTTP, not HTTPS
- Event bus (`events.py`) + native notifications (`notify.py`) +
  Discord/Slack/generic webhooks (`webhooks.py`).
- Per-day alert deduplication, severity-filtered webhook routing.
- LaunchAgent install path + in-app updater against GitHub Releases.

## Shipped — v2.1

- **Network Health Score** (0–100) with weighted reasons.
- **Triage queue** UI to batch-name or batch-block unknown devices.
- **mDNS browse discovery** so ARP-silent devices (iPhones, AirPlay, Chromecast)
  appear in the device list.
- **Auto-name local Mac** via `scutil --get ComputerName`; **fingerprint as
  headline name** for printers/cameras/TVs that advertise a friendlyName.
- **Server-Sent Events** for instant dashboard updates instead of 3 s polling
  (30 s fallback if SSE drops).
- **Per-device story drawer** — sightings, port history, alerts triggered,
  WAN exposure, identity. Click any device card to open.
- **First-launch onboarding tour** — 3-step Welcome / Health Score / Triage
  walkthrough, marked done in store so it doesn't reappear.
- **Voice alert announcements** (opt-in) via `say` for warning + critical.
- **Apple Shortcuts triggers** — run a named Shortcut on new-device or alert
  events. The shortcut receives the payload as JSON on stdin.
- **New detection rules**: rogue DHCP, ARP-spoof, WAN-exposed port via UPnP
  IGD, DNS threat-intel local match, MAC-randomization clustering.
- **Per-device probe opt-out** for fragile IoT/printers.
- **Notification burst-coalescing** (5 new joins → 1 banner).
- **Pushover** + **ntfy** webhook dispatchers alongside Discord/Slack.

## Shipped — v2.2 / v2.3 / v2.4

**v2.2** — Router quarantine. `routerctl.py` with Unifi (REST) + OpenWrt
(SSH `uci macfilter`) backends. Per-device Block button in the story
drawer. Test-connection workflow before relying on it.

**v2.3** — Passive sniffer. `sniffer.py` (scapy AsyncSniffer) with
permission gating; per-device bandwidth tracking flushed to SQLite once
a minute; DNS query logging with mtime-driven threat-intel match
(`threats.py`). Bandwidth sparkline + DNS lookups in the device story
drawer. One-time `sudo tools/enable_sniffer.sh` setup creates an
`access_bpf` group and persists `/dev/bpf*` permissions across boots.

**v2.4** — iOS companion app scaffold in `/ios`. Swift / SwiftUI source
for a read-only LAN-only viewer that discovers INS via Bonjour and
renders devices + alerts + health score. **Scaffold-only — not built or
tested by author; users open in Xcode 15+, follow ios/README.md.** No
INS-side runtime changes shipped in this version — v2.5 work below is
what's needed to make the scaffold actually connect.

## v2.5 — remote access (Phase A shipped)

- **LAN-bind dashboard option** — ✅ **shipped.** Opt-in *Settings → Remote
  access* binds the LAN interface (`0.0.0.0`), gated by a random bearer token
  (constant-time compared, regenerable) and restricted to a **read-only**
  endpoint allowlist — a valid token can't mutate state or read the
  token/webhook endpoints. Off by default; turning it off rebinds to loopback.
- **Bonjour service publish** — ✅ **shipped.** `bonjour.py` advertises
  `_ins._tcp` via `NSNetService` (bundled pyobjc, no new dep) whenever remote
  access is on, so the iOS app can discover the Mac without a typed IP.
- **iOS client (Phase B)** — pending: finish `INSClient.resolve()` and send the
  `Authorization: Bearer` token (store it in Keychain). Server contract is done.
- **Signed + notarized .app + DMG (Phase C)** — parked until there's an Apple
  Developer account. The single biggest trust win — fixes the macOS
  notification attribution (currently "Script Editor") and lets the
  curl-installer become optional.
- **Homebrew cask** — `brew install --cask inglorious-network-scanner`.
- **Eero router-block** via Cognito-auth API. Brittle (Amazon rotates
  challenge formats); deferred until v2.5 has integration tests against
  a recorded Cognito flow.
- **Schedule profiles** — "Out of town" auto-alerts on any new device;
  "Kids' bedtime" silences non-critical alerts for a window.
- **Per-network memory** — when you move between home / office / café,
  INS keeps device lists separated per SSID rather than mixing them.

## Exploration — v3.0

- **Connection map per device** — extend the v2.3 sniffer to also record
  remote IPs (not just bandwidth totals) and surface "your smart TV
  phones home to Korea" insights with country/ASN annotation via a local
  GeoIP DB.
- **Local-LLM "Name this device"** — feed vendor + ports + fingerprint to
  a small local model (Ollama if installed) and propose a friendly name.
  Strictly on-device.
- **Community fingerprint database (opt-in).** Anonymous
  `fingerprint_hash → label` submissions, no PII.
- **Linux port** — factor a headless engine + dashboard out of the macOS
  menubar wrapper so INS can run as a systemd service.
- **Home Assistant MQTT publisher** for prosumer integration.
- **Native iOS app, fully maintained** — promote the v2.4 scaffold into a
  first-class build with App Store distribution. Needs an Apple Developer
  account and ongoing iOS-side maintenance.

## Architectural debt

These are known and worth fixing before piling more features on:

- **Scanner thread model.** Today every probe runs synchronously inside the
  scan loop. Adding pcap-based traffic analysis or active threat-intel
  lookups needs a proper async worker pool with backpressure.
- **TUI / engine coupling in `scanner.py`.** The rich-console rendering is
  intermixed with the scanning engine. Splitting them is a prerequisite
  for the Linux port and for headless test fixtures.
- **Hook sandboxing.** `store.run_hook` does
  `subprocess.Popen(script, shell=True, env=env)`. Fine for trusted local
  scripts written by the user, but a tighter contract (allowlist of env
  vars, no shell expansion, optional sandbox-exec wrapper) would let us
  expose hook execution to webhook-triggered flows later.
- **No integration tests.** Smoke tests cover pure functions. A pcap-replay
  harness would let us assert on rule behavior end-to-end without a live
  network.

## Out of scope

- Any feature requiring an INS-operated cloud service.
- Centralized fleet management. INS is one user, one Mac, one LAN. If you
  want fleet visibility, you want a different tool.
- Active offensive capabilities (brute-force, deauth, exploit attempts).
  INS protects the user; it does not attack the network.
