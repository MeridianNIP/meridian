"""Render the Meridian SVG assets into the PNG sizes GitHub needs.
Pure Python via cairosvg; no external binaries.

Outputs (under brand/):
    avatar-512.png            for GitHub profile / org avatar
    social-preview-1280x640.png  for repo Settings → Social preview

Run from anywhere:
    /tmp/isobuild-venv/bin/python brand/render-pngs.py
"""
from __future__ import annotations

import os

import cairosvg

HERE = os.path.dirname(os.path.abspath(__file__))


def _embed(path: str) -> str:
    """Read an SVG file and strip its XML prolog so it can be nested
    inside another <svg> element."""
    xml = open(path).read()
    if xml.startswith("<?xml"):
        xml = xml.split("?>", 1)[1].lstrip()
    return xml


def render_avatar() -> str:
    """512×512 square. Just the MARK (not the wordmark) on a dark
    background so it stays legible when GitHub crops it to a circle."""
    mark = _embed(os.path.join(HERE, "meridian-mark-teal.svg"))
    canvas = f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     width="512" height="512" viewBox="0 0 512 512">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%"   stop-color="#0d131b"/>
      <stop offset="100%" stop-color="#0b0f14"/>
    </linearGradient>
  </defs>
  <rect width="512" height="512" fill="url(#bg)" rx="64" ry="64"/>
  <svg x="76" y="76" width="360" height="360">
    {mark}
  </svg>
</svg>
"""
    out = os.path.join(HERE, "avatar-512.png")
    cairosvg.svg2png(bytestring=canvas.encode("utf-8"),
                     output_width=512, output_height=512,
                     write_to=out)
    return out


def render_social() -> str:
    """1280×640 landscape for the repo social-preview card.

    Uses the mono-white wordmark variant — the teal one is designed
    for light backgrounds and disappears against the dark canvas."""
    wordmark = _embed(os.path.join(HERE, "meridian-wordmark-mono-white.svg"))
    WORDMARK_W, WORDMARK_H = 760, 180
    canvas = f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     width="1280" height="640" viewBox="0 0 1280 640">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%"   stop-color="#0d131b"/>
      <stop offset="100%" stop-color="#0b0f14"/>
    </linearGradient>
  </defs>
  <rect width="1280" height="640" fill="url(#bg)"/>
  <g stroke="#1f2937" stroke-width="0.5" opacity="0.45">
    {''.join(f'<line x1="{x}" y1="0" x2="{x}" y2="640"/>' for x in range(0, 1281, 40))}
    {''.join(f'<line x1="0" y1="{y}" x2="1280" y2="{y}"/>' for y in range(0, 641, 40))}
  </g>
  <rect x="0" y="0" width="6" height="640" fill="#20c896"/>
  <svg x="{(1280 - WORDMARK_W) // 2}" y="210" width="{WORDMARK_W}" height="{WORDMARK_H}">
    {wordmark}
  </svg>
  <text x="640" y="470"
        font-family="ui-monospace, 'SF Mono', Menlo, Consolas, monospace"
        font-size="22" fill="#9ca3af" text-anchor="middle">
    Self-hosted DDI &amp; network-ops portal · Apache 2.0
  </text>
  <text x="640" y="568"
        font-family="ui-monospace, 'SF Mono', Menlo, Consolas, monospace"
        font-size="16" fill="#20c896" text-anchor="middle">
    github.com/MeridianNIP/meridian
  </text>
</svg>
"""
    out = os.path.join(HERE, "social-preview-1280x640.png")
    cairosvg.svg2png(bytestring=canvas.encode("utf-8"),
                     output_width=1280, output_height=640,
                     write_to=out)
    return out


if __name__ == "__main__":
    a = render_avatar()
    s = render_social()
    print(f"wrote {a} ({os.path.getsize(a)} bytes)")
    print(f"wrote {s} ({os.path.getsize(s)} bytes)")
