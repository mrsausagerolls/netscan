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

## Next — v2.2 (not started)

- **Signed + notarized .app + DMG.** The single biggest trust win. Once we
  have an Apple Developer ID, the curl-installer becomes optional rather
  than the recommended path. Also fixes the macOS notification attribution
  (currently appears as "Script Editor").
- **Homebrew cask** — `brew install --cask inglorious-network-scanner`.
- **Router-API block / quarantine** — when the user clicks "Block" on a
  device, INS calls the router's API to kick it off the WiFi. Per-vendor
  modules; first targets:
  - **Unifi (UDM-Pro / Dream Machine / Cloud Key)** via the official REST
    API. Needs admin creds in Settings; tested with a real device before
    shipping.
  - **OpenWrt** via SSH + `uci set wireless.@wifi-iface[0].macfilter='deny'`.
  - **Eero** via the unofficial Cognito-auth API (carries breakage risk).
- **Schedule profiles** — "Out of town" auto-alerts on any new device; "Kids'
  bedtime" silences non-critical alerts for a window. Cron-style scheduler
  + scoped rule activation.
- **Per-network memory** — when you move between home / office / café, INS
  keeps device lists separated per SSID rather than mixing them.

## Exploration — v3.0

- **Bandwidth + connection map per device** via passive pcap on the WiFi
  interface. Needs root (current launchd registration runs as the user),
  pulls per-device byte counts + remote IPs over rolling windows, surfaces
  "your smart TV phones home to Korea" insights. Significant scanner thread
  rework.
- **DNS query logging + threat-intel correlation.** Opt-in; needs root pcap
  or a local resolver shim. Vastly more powerful than the v2.0 local-list
  match because we'd see *every* lookup, not just ones that happen to be on
  a known-bad domain. Privacy-sensitive — has to be opt-in and locally-only.
- **iOS companion app (LAN-only).** Native Swift app that discovers the
  local INS via Bonjour and surfaces alerts + triage on your phone. No
  cloud round-trip. Realistic scope: a few weekends of native iOS work
  plus Apple Developer + App Store submission.
- **Local-LLM "Name this device"** — feed vendor + ports + fingerprint to
  a small local model (Ollama if installed) and propose a friendly name.
  Strictly on-device.
- **Community fingerprint database (opt-in).** Anonymous
  `fingerprint_hash → label` submissions, no PII.
- **Linux port** — factor a headless engine + dashboard out of the macOS
  menubar wrapper so INS can run as a systemd service.
- **Home Assistant MQTT publisher** for prosumer integration.

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
