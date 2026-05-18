# Inglorious Network Scanner — iOS companion (scaffold)

> ⚠️ **This is an untested scaffold, not a working build.** The Swift source
> in this directory is a starting point for an iOS / iPadOS companion app
> that discovers a running INS instance over the local network (via Bonjour)
> and renders a read-only view of devices + alerts using the same backend
> APIs the dashboard uses. It has not been compiled or run by the author —
> you will need Xcode 15+ and a few minutes to wire it into a fresh project.
>
> No part of this is on the App Store. You're building and side-loading it
> yourself.

## What this app does (once built)

- Discovers running INS instances on the local WiFi via Bonjour service
  type `_ins._tcp.local`.
- Connects to the discovered instance's `/api/stream` Server-Sent Events
  feed for live updates.
- Reads `/api/state` for the device list, health score, and alerts.
- Read-only: no controls to mark Known, no triage, no settings. The
  companion is meant to be an at-a-glance phone view, not a remote.

## What this app does NOT do

- No cloud round-trip. Everything is LAN-only via Bonjour.
- No notifications outside of WiFi range. iOS background networking is
  intentionally restricted — Push Notifications would require an APNs
  server and a real Apple Developer account, which is out of scope for
  a side-loaded scaffold.
- No control surface. To mark a device Known or block one, use the Mac
  dashboard.

## One-time setup on the INS side (the Mac running INS)

The Mac's dashboard server already binds `127.0.0.1` — that's intentionally
not reachable from another device on the same WiFi. To use this companion
app, you'll need to add a LAN-bind option to `dashboard.py` so the phone
can reach it. That work is **not in this commit**; it's tracked under v2.5
in `ROADMAP.md`. The scaffold currently expects:

- `http://<ins-mac>:8765/api/state`   reachable from the phone
- `http://<ins-mac>:8765/api/stream`  reachable from the phone
- A Bonjour service published by INS as `_ins._tcp.local`

Until INS publishes that service (also v2.5), you'll need to enter the
Mac's IP manually in the app's "Manual host" field.

## Build instructions

1. Open Xcode 15 or newer. **File → New → Project → iOS → App**.
2. Product Name: `InglNetScan`. Interface: **SwiftUI**. Language: **Swift**.
3. Replace the generated `ContentView.swift` and `InglNetScanApp.swift`
   with the files in this directory.
4. Add `INSClient.swift` and `Models.swift` to the project (drag into the
   Project navigator).
5. Open the project's `Info.plist` and add the keys from
   `Info.plist.snippet.xml` in this directory. The two important ones are
   `NSLocalNetworkUsageDescription` and `NSBonjourServices`. iOS 14+
   requires explicit user consent for local-network access; without these
   keys Bonjour discovery silently returns nothing.
6. Build to a real device (the Simulator doesn't see your home WiFi). On
   first launch the system prompts for Local Network access — accept.

## Files in this scaffold

| File | What it is |
|---|---|
| `InglNetScanApp.swift` | App entry point, sets up the shared `INSClient`. |
| `ContentView.swift`    | Main UI — device list, health score, alert feed. |
| `INSClient.swift`      | Bonjour browser + REST + SSE client. |
| `Models.swift`         | Decodable structs matching `/api/state`. |
| `Info.plist.snippet.xml` | Keys to merge into Info.plist (Bonjour + privacy). |

## Caveats — author honesty

I wrote this without an iOS toolchain in the loop. The Bonjour discovery
code uses `NWBrowser` from Network.framework which is the modern path; SSE
parsing is hand-rolled (no third-party deps). It should compile. It may
need import fixes, signing-bundle tweaks, or subtle Network.framework
behavior corrections that only show up when you actually build. Treat this
as the starting point of an afternoon, not a finished app.

PRs from anyone who gets this running on their device cheerfully accepted.
