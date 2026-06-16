# Security & Privacy

Inglorious Network Scanner (INS) is designed to *protect* your home network,
which means it has to earn your trust before it can be useful.

## What stays on your Mac

**Everything.** INS has no cloud, no accounts, no telemetry, no crash reporting.

- All scan data lives in a local SQLite database under `~/Library/Application
  Support/InglNetScan/ins.db` (when installed as a `.app`) or in `./data/` (when
  run from source).
- The dashboard binds to `127.0.0.1` only. Nothing INS does is reachable from
  outside your machine.
- The dashboard loads **no third-party assets** — fonts and all other resources
  are bundled and served from `127.0.0.1`, so opening it makes zero outbound
  requests.
- The only outbound network calls INS itself makes are:
  - **GitHub Releases API** every 6 h, to check for a newer version. Anonymous;
    no machine identifier sent. Disable by setting `INS_NO_UPDATE_CHECK=1`.
  - **MAC vendor OUI lookups**, performed by the `mac-vendor-lookup` library
    against a locally cached database. No per-MAC request leaves your machine.
  - **Optional**: webhooks *you* configure (Discord, Slack, Pushover, ntfy, …).
    These fire only on alerts you've subscribed to. Disable any webhook from
    Settings → Webhooks.

If INS ever adds a feature that sends data off-machine by default, it will be
opt-in, documented in this file, and listed in the dashboard's Privacy panel.

## What INS does *to* your network

INS performs **active probing** of devices on your own LAN. Some of this looks
identical to reconnaissance done by attackers — because that's what scanning
*is* — and some IoT devices crash or rate-limit when probed.

- **ARP sweep** of your subnet (requires root; falls back to a ping sweep).
- **TCP connect** attempts on a small fixed list of ports (see
  [scanner.py](scanner.py) `PROBE_PORTS`).
- **mDNS / SSDP / NetBIOS / HTTP** identification probes against devices that
  expose those services.

You can suppress probing for an individual device by marking it as
*"don't probe"* in the dashboard. INS still records its presence but never
opens a port or sends an HTTP request to it.

## What INS will never do

- Crack passwords, brute-force admin panels, or send unsolicited authentication
  attempts.
- Modify devices it sees (no port-knocking, no DHCP starvation, no router
  config changes, no WiFi deauth).
- Phone home with the devices found on your network.

## The local web dashboard

The dashboard is reachable only at `http://127.0.0.1:8765` and
`http://localhost:8765`. **Every** request — GET and POST — must carry a `Host`
header matching one of those two loopback names; anything else is rejected with
HTTP 403. This defeats DNS-rebinding attacks, where a malicious page rebinds its
own domain to `127.0.0.1` to read your scan data cross-origin. On top of that,
every *mutating* endpoint also requires a same-origin `Origin`/`Referer` header,
so a webpage in another tab cannot silently install a join hook, mark a device
as known, or wake a host.

The join hook stores an arbitrary shell command. Treat that capability the way
you'd treat your shell history: anyone with access to your Mac account can edit
it. INS makes no attempt to sandbox the hook script — but the device-supplied
values it exports (`DEVICE_HOSTNAME`, `DEVICE_VENDOR`, `SSID`, …) are stripped to
a safe character set first, so a rogue device advertising a booby-trapped name
can't inject shell metacharacters into an otherwise-innocent hook.

## Reporting a vulnerability

If you find a security issue in INS itself, please email
**security@inglorious.co** with:

- A description of the issue and its impact.
- Steps or a proof-of-concept that reproduces it locally.
- Your preferred contact for follow-up.

Please do **not** open a public GitHub issue for unpatched vulnerabilities.
We will acknowledge within 72 hours and aim to ship a fix within 14 days for
high-severity issues. There is no bug bounty program at this time, but
researchers who report responsibly will be credited in the release notes
unless they prefer to remain anonymous.

## Threat model

INS is meant for **a single user on a personal home network**. It does not
attempt to defend against:

- Other users on the same Mac account (they have full local access anyway).
- An attacker who has already compromised the Mac running INS.
- Adversaries inside the LAN with the ability to ARP-spoof or run a rogue
  DHCP server can confuse INS's own detection rules. INS has rules that try
  to *flag* those conditions, but cannot rule them out from inside.

The intended adversary is the everyday risk surface: a device that shouldn't
be on the network, a default-password camera exposed to the WAN, a rogue
DHCP server from a misconfigured second router, a hardware fingerprint
suddenly changing on a known MAC.
