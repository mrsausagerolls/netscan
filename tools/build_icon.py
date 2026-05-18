#!/usr/bin/env python3
"""Generate the launcher .app icon (.icns) using PyObjC.

Renders the INS brand mark (radar dish on a dark cyan-accented background)
at every macOS-required size, packs them into an `iconset/` directory, and
runs `iconutil` to produce the final `AppIcon.icns`.

Run once during development:

    python3 tools/build_icon.py

Commits the resulting .icns to the repo so end users don't need PyObjC
installed to get a proper launcher icon.

No external deps — uses AppKit via PyObjC, which INS already depends on
for CoreWLAN / CoreLocation.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

try:
    from AppKit import (                                                   # type: ignore
        NSImage, NSColor, NSBitmapImageRep, NSGraphicsContext,
        NSFont, NSMakeRect, NSMakePoint, NSBezierPath,
        NSFontAttributeName, NSForegroundColorAttributeName,
        NSAttributedString, NSBitmapImageFileTypePNG,
    )
    from Foundation import NSMutableDictionary                            # type: ignore
except ImportError as e:
    print(f"PyObjC not available — install requirements.txt: {e}", file=sys.stderr)
    sys.exit(1)


HERE = Path(__file__).resolve().parent
LAUNCHER = HERE.parent / "launcher" / "Inglorious Network Scanner.app"
RESOURCES = LAUNCHER / "Contents" / "Resources"
ICONSET = HERE / "build" / "AppIcon.iconset"
OUT_ICNS = RESOURCES / "AppIcon.icns"

# Standard macOS iconset sizes — (filename, edge in pixels).
SIZES = [
    ("icon_16x16.png",       16),
    ("icon_16x16@2x.png",    32),
    ("icon_32x32.png",       32),
    ("icon_32x32@2x.png",    64),
    ("icon_128x128.png",     128),
    ("icon_128x128@2x.png",  256),
    ("icon_256x256.png",     256),
    ("icon_256x256@2x.png",  512),
    ("icon_512x512.png",     512),
    ("icon_512x512@2x.png",  1024),
]


def _color(r: float, g: float, b: float, a: float = 1.0):
    return NSColor.colorWithSRGBRed_green_blue_alpha_(r, g, b, a)


def render(size: int) -> bytes:
    """Render a square icon and return its PNG bytes."""
    img = NSImage.alloc().initWithSize_((size, size))
    img.lockFocus()

    # Background: dark navy, matches the dashboard.
    _color(0.027, 0.035, 0.051).setFill()
    NSBezierPath.fillRect_(NSMakeRect(0, 0, size, size))

    # Rounded rect mask (icon-style corners).
    radius = size * 0.22
    rect = NSMakeRect(0, 0, size, size)
    mask = NSBezierPath.bezierPathWithRoundedRect_xRadius_yRadius_(rect, radius, radius)
    mask.addClip()

    # Subtle gradient overlay top → bottom.
    _color(0.047, 0.063, 0.094).setFill()
    NSBezierPath.fillRect_(NSMakeRect(0, size * 0.4, size, size * 0.6))

    # Cyan glow ring near the edge.
    inset = size * 0.06
    ring_rect = NSMakeRect(inset, inset, size - 2 * inset, size - 2 * inset)
    ring = NSBezierPath.bezierPathWithRoundedRect_xRadius_yRadius_(
        ring_rect, radius * 0.85, radius * 0.85,
    )
    ring.setLineWidth_(max(1.0, size / 280.0))
    _color(0.0, 0.85, 0.96, 0.32).setStroke()
    ring.stroke()

    # Render the radar emoji centered. At small sizes the emoji renders
    # blurry, so for ≤32 we switch to a typographic "INS" mark.
    if size <= 32:
        attrs = NSMutableDictionary.dictionary()
        font_size = size * 0.36
        attrs[NSFontAttributeName]            = NSFont.boldSystemFontOfSize_(font_size)
        attrs[NSForegroundColorAttributeName] = _color(0.0, 0.85, 0.96, 1.0)
        text = NSAttributedString.alloc().initWithString_attributes_("INS", attrs)
        bbox = text.size()
        text.drawAtPoint_(NSMakePoint(
            (size - bbox.width) / 2.0,
            (size - bbox.height) / 2.0,
        ))
    else:
        attrs = NSMutableDictionary.dictionary()
        font_size = size * 0.55
        attrs[NSFontAttributeName] = NSFont.systemFontOfSize_(font_size)
        text = NSAttributedString.alloc().initWithString_attributes_("📡", attrs)
        bbox = text.size()
        text.drawAtPoint_(NSMakePoint(
            (size - bbox.width) / 2.0,
            (size - bbox.height) / 2.0 - (size * 0.03),
        ))
        # Small "INS" caption underneath for sizes that have room.
        if size >= 256:
            cap_attrs = NSMutableDictionary.dictionary()
            cap_font_size = size * 0.085
            cap_attrs[NSFontAttributeName] = \
                NSFont.systemFontOfSize_(cap_font_size)
            cap_attrs[NSForegroundColorAttributeName] = _color(0.0, 0.85, 0.96, 0.85)
            cap = NSAttributedString.alloc().initWithString_attributes_("INS", cap_attrs)
            cap_w = cap.size().width
            cap.drawAtPoint_(NSMakePoint(
                (size - cap_w) / 2.0,
                size * 0.085,
            ))

    img.unlockFocus()

    # Resample to an exact-pixel bitmap rep so the @2x sizes match disk
    # exactly. NSImage's pointSize differs from pixelsHigh on retina.
    tiff = img.TIFFRepresentation()
    rep = NSBitmapImageRep.imageRepWithData_(tiff)
    png_data = rep.representationUsingType_properties_(NSBitmapImageFileTypePNG, None)
    return bytes(png_data)


def main():
    if ICONSET.exists():
        shutil.rmtree(ICONSET)
    ICONSET.mkdir(parents=True)

    print(f"Rendering {len(SIZES)} icon sizes into {ICONSET}…")
    for name, edge in SIZES:
        path = ICONSET / name
        path.write_bytes(render(edge))
        print(f"  {name}  ({edge}×{edge})")

    RESOURCES.mkdir(parents=True, exist_ok=True)
    print(f"Packing into {OUT_ICNS}…")
    result = subprocess.run(
        ["iconutil", "-c", "icns", str(ICONSET), "-o", str(OUT_ICNS)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print("iconutil failed:")
        print(result.stderr or result.stdout, file=sys.stderr)
        sys.exit(1)
    print(f"✓ {OUT_ICNS}")
    print(f"  ({OUT_ICNS.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
