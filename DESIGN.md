# Design

The INS dashboard visual system, as implemented in `static/style.css` (v2.6).
Register: product. Direction: calm guardian — composed, trustworthy, precise.
Severity color is a budget, not a decoration: a healthy network renders nearly
monochrome; one critical alert changes the room.

## Theme

Dark only, by scene: a home user glances at a tab left open in a dim living
room at night, wanting reassurance, not a cockpit. Low glare, soft contrast.
`color-scheme: dark`.

## Color

All colors are OKLCH. Neutrals are near-blacks tinted toward the brand hue
(h≈225) — never pure `#000`/`#fff`. Strategy: **Restrained** (tinted neutrals
plus one accent under 10% of the surface).

| Token | Value | Role |
|---|---|---|
| `--bg` | `oklch(17.5% 0.012 225)` | page ground |
| `--bg-raised` | `oklch(20% 0.013 225)` | list/chart containers |
| `--surface` / `-2` / `-3` | 22.5% / 26% / 30% | hover, controls, chips |
| `--line` / `-2` / `-3` | alpha hairlines | separators, borders, strong borders |
| `--text` / `-2` / `-3` | 93% / 76% / 62% | primary, secondary, captions (all ≥ AA on bg) |
| `--accent` | `oklch(80% 0.085 200)` | teal: primary action, selection, "this Mac" |
| `--accent-deep` | `oklch(66% 0.09 202)` | primary-button fill |
| `--ok` | `oklch(80% 0.07 165)` | sage: the rare explicit all-clear |
| `--warn` | `oklch(82% 0.115 85)` | amber: unknown devices, warnings |
| `--crit` | `oklch(72% 0.16 30)` | red-orange: critical only |

Each severity color has `-tint` (≈8–10% alpha background) and `-line`
(≈26–30% alpha border) companions. Status is never color alone — always paired
with a glyph or text.

## Typography

Two voices, both self-hosted variable fonts (local-only rule — no CDN):

- **Geist** (`--sans`) for language: headings, labels, sentences.
- **Geist Mono** (`--mono`) for machine facts: IPs, MACs, ports, timestamps,
  counts. The two-voice texture is a signature; never set prose in mono or
  data in sans.

Fixed rem scale ×1.2: 11 / 12.5 / 13.5 (body) / 15 / 18 / 23 / 30px. The 30px
step exists for exactly one element: the Overview status statement.
Uppercase micro-labels (eyebrows, table headers) use 11px with 0.07–0.11em
tracking.

## Signature moves

1. **The status statement** (`.statement`): the Overview leads with a
   typographic verdict ("All clear." / "Your network is at risk.") — no ring
   widget, no hero-metric card. Severity tints the eyebrow, score chip, and a
   faint full-bleed wash (`.sev-warn` / `.sev-crit ::before`).
2. **Stroke icon set**: every device type and severity glyph is a drawn
   24px stroke SVG (1.6 width, round caps) defined in `app.js`
   (`DEVICE_ICONS`, `SEV_ICON`). No emoji anywhere in the UI.
3. **Comfortable rows**: the device list is a single list view — name in
   sans leads, technical columns quiet in mono. No card grid.

## Components

- Buttons: `.btn` (surface), `.btn-primary` (accent-deep fill, dark text),
  `.btn-danger` (crit outline), `.btn-ghost`. One shape everywhere,
  radius 7px.
- Containers: lists and charts sit in `--bg-raised` with a `--line` border,
  radius 14px. Sections separate with hairlines, not nested cards.
- Status dots: `s-me` (accent) / `s-known` (neutral) / `s-unknown` (amber) /
  `s-identifying` (hollow). Known is deliberately neutral, not green.
- Drawers slide from the right (`.drawer`, 430/520px), scrim + focus trap +
  `inert` background.

## Motion

150–250ms, `cubic-bezier(.16,1,.3,1)` ease-out only. Motion conveys state
(tab fade, drawer slide, severity crossfade) — never decoration. All animation
collapses under `prefers-reduced-motion`.

## Accessibility

WCAG 2.1 AA. `aria-live` region for new alerts, `aria-current` on nav,
focus traps in dialogs, `:focus-visible` accent outline, Escape closes
overlays, status never conveyed by color alone.
