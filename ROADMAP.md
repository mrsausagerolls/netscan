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

## In progress — v2.1

- **Network Health Score** (0–100) with one-line reasons.
- **Triage queue** UI for batch-acknowledging unknown devices.
- **New detection rules**:
  - Rogue DHCP server detector
  - ARP-spoof / MAC-flap detector
  - WAN-exposed port check via UPnP IGD enumeration
  - DNS threat-intel match (local DB, no upload)
  - MAC-randomization recognition (deduplicate "same iPhone, different MAC"
    alerts via fingerprint similarity).
- **Per-device probe opt-out** — never touch devices the user has marked
  fragile (printers, legacy IoT).
- **Notification burst-coalescing** — five new devices → one banner.
- **Pushover** + **ntfy** webhook dispatchers alongside Discord/Slack.
- **SECURITY.md** and this roadmap.

## Next — v2.2 (not started)

- **Signed + notarized .app + DMG.** The single biggest trust win. Once we
  have an Apple Developer ID, the curl-installer becomes optional rather
  than the recommended path. Also fixes the macOS notification attribution
  (currently appears as "Script Editor" — see [notify.py](notify.py)).
- **Homebrew cask** — `brew install --cask inglorious-network-scanner`.
- **Onboarding tour** — first-launch walkthrough that classifies "you",
  the router, and the obvious household devices, then hands the user a
  triage queue for the rest.
- **Inline alert help drawer** — per-alert "what does this mean / what
  should I do" explainer pages, reachable from every alert.
- **Apple Shortcuts actions** — "Run shortcut when new device joins" etc.
- **iOS companion app (LAN-only)** — read-only push notifications and
  triage from the phone, talking to the local INS over Bonjour.

## Exploration — v3.0

- **Passive traffic-pattern anomalies.** Per-device byte/connection
  baselines from libpcap on the WiFi interface; flag IoT that suddenly
  uploads at 3 a.m. Requires significant rework of the scanner thread
  model — see the worker-pool note below.
- **Local-LLM "Name this device"** — feed vendor + ports + fingerprint to
  a small local model (Ollama if installed, falls back to rules) and
  propose a friendly name. Strictly on-device.
- **Community fingerprint database (opt-in).** Anonymous
  `fingerprint_hash → label` submissions, no PII. Same model as the MAC
  vendor OUI database.
- **Linux port.** scapy is cross-platform; the blocker is `rumps` (macOS
  menubar). Likely path: factor out a headless engine + dashboard, run as
  a systemd service on Linux.
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
