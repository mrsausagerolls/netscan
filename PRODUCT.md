# Product

## Register

product

## Users

Non-technical home users ("everyday people who want to know what's on their
WiFi without having to learn ARP, RTSP, or what an IGD is" per the README),
plus the technically-curious owner. Context: a macOS menubar app whose
dashboard lives at localhost:8765. It gets glanced at, not lived in: a tab
left open in a corner, opened when a notification fires, or checked at night
when something feels off. The job on any given screen: "is my network okay,
and if not, what exactly do I do about it?" Secondary jobs: naming/triaging
new devices, reading an alert's plain-English explanation, checking a
specific device's story.

## Product Purpose

Inglorious Network Scanner watches a home WiFi network: names every device,
explains what each one is in plain English, and raises a friendly alert the
moment something deserves attention (new device, risky protocol, rogue DHCP,
WAN exposure). Strictly local-only: no cloud, no accounts, no telemetry.
Success = a non-expert acts correctly on an alert without googling, and feels
calmer, not more paranoid, for having the tool open.

## Brand Personality

Calm guardian. Three words: composed, trustworthy, precise. The interface
projects quiet confidence, the feeling of a well-run security desk where
everything is watched and nothing is dramatized. Alarm is a scarce resource:
the design stays low-contrast and unhurried until something is genuinely
wrong, and then that one thing is unmissable.

## Anti-references

- Hacker-terminal aesthetics: neon green/red on pure black, glitch effects,
  Matrix cosplay. INS is for people who found "ARP" intimidating.
- Alarmist security-vendor dashboards that sell fear: red badges everywhere,
  pulsing warnings, "threats blocked" counters.
- Generic SaaS admin templates: identical card grids, icon+heading+text
  repetition, gradient hero metrics, sidebar-with-avatars.
- Consumer smart-home cuteness (illustrations, mascots, confetti): friendly
  is tone, not decoration.

## Design Principles

1. **Calm by default, loud only when true.** Severity color has a strict
   budget; a healthy network should render nearly monochrome. One critical
   alert should change the room.
2. **Plain English first, detail one layer down.** Every surface leads with
   the human sentence; MACs, ports, and fingerprints are one click deeper,
   never gone.
3. **Glanceable in one second.** From across the room the page must answer
   "am I okay?" through hierarchy alone, before a single word is read.
4. **Honest about uncertainty.** Confidence-aware labels: never falsely
   confident, never falsely scary. "Identifying…" is an honest state and
   deserves first-class styling.
5. **Feels self-contained.** Local-only is the product's spine; the design
   should feel like an instrument you own, not a service you visit.

## Accessibility & Inclusion

WCAG 2.1 AA. Keyboard-first support is already wired (focus traps, Escape
handling, aria-live alert announcements, aria-current nav) and must survive
the redesign. Status is never conveyed by color alone (pair with icon/text).
Respect prefers-reduced-motion. Contrast: body text ≥ 4.5:1, large/secondary
≥ 3:1, including severity colors on their tinted backgrounds.
