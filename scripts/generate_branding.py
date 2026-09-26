"""
CyberPort Scanner - Professional Brand Identity & Asset Generator
Generates:
- static/images/cyberport-symbol.svg (Standalone vector emblem)
- static/images/cyberport-logo.svg (Horizontal brand lockup)
- static/images/favicon.svg (Optimized vector favicon)
- static/images/apple-touch-icon.png (180x180 high-res icon)
- static/images/favicon-32x32.png (32x32 favicon)
- static/images/favicon-16x16.png (16x16 favicon)
- static/images/favicon.ico (Multi-resolution 16/32/48 ICO)
- static/images/cyberport-symbol.png (512x512 master symbol)
- static/images/cyberport-logo.png (1000x250 master horizontal logo)
- static/images/cyberport-og.png (1200x630 OpenGraph social banner)
"""

import os
import math
from PIL import Image, ImageDraw, ImageFont, ImageFilter

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "images")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# -------------------------------------------------------------------------
# 1. STANDALONE SYMBOL SVG
# -------------------------------------------------------------------------
SYMBOL_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" width="100%" height="100%" fill="none">
  <defs>
    <!-- Gradients -->
    <linearGradient id="cyberCyanGreen" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00e5ff" />
      <stop offset="50%" stop-color="#00f5b8" />
      <stop offset="100%" stop-color="#00ff9d" />
    </linearGradient>
    <linearGradient id="cyberVertical" x1="50%" y1="0%" x2="50%" y2="100%">
      <stop offset="0%" stop-color="#00e5ff" />
      <stop offset="100%" stop-color="#00ff9d" />
    </linearGradient>
    <linearGradient id="shieldFill" x1="50%" y1="0%" x2="50%" y2="100%">
      <stop offset="0%" stop-color="#00e5ff" stop-opacity="0.14" />
      <stop offset="50%" stop-color="#00ff9d" stop-opacity="0.04" />
      <stop offset="100%" stop-color="#05080a" stop-opacity="0.85" />
    </linearGradient>
    <radialGradient id="radarSweepGrad" cx="60" cy="58" r="28" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#00e5ff" stop-opacity="0.5" />
      <stop offset="70%" stop-color="#00ff9d" stop-opacity="0.15" />
      <stop offset="100%" stop-color="#00ff9d" stop-opacity="0" />
    </radialGradient>
    <radialGradient id="coreGlow" cx="60" cy="58" r="16" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#ffffff" stop-opacity="0.9" />
      <stop offset="25%" stop-color="#00e5ff" stop-opacity="0.8" />
      <stop offset="70%" stop-color="#00ff9d" stop-opacity="0.3" />
      <stop offset="100%" stop-color="#00ff9d" stop-opacity="0" />
    </radialGradient>
    <!-- Glow Filters -->
    <filter id="neonGlow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="2" result="blur1" />
      <feGaussianBlur stdDeviation="5" result="blur2" />
      <feMerge>
        <feMergeNode in="blur2" />
        <feMergeNode in="blur1" />
        <feMergeNode in="SourceGraphic" />
      </feMerge>
    </filter>
  </defs>

  <!-- Ambient Shield Backing -->
  <path d="M 48 14 L 52 14 L 52 8 L 68 8 L 68 14 L 72 14 L 104 32 L 104 66 L 60 108 L 16 66 L 16 32 Z"
        fill="url(#shieldFill)" />

  <!-- Outer Cyber-Shield Frame with Top Port Connector Tab -->
  <path d="M 48 14 L 52 14 L 52 8 L 68 8 L 68 14 L 72 14 L 104 32 L 104 66 L 60 108 L 16 66 L 16 32 Z"
        stroke="url(#cyberVertical)" stroke-width="3.5" stroke-linejoin="round" stroke-linecap="round"
        filter="url(#neonGlow)" />

  <!-- Inner Circuit Perimeter -->
  <path d="M 50 20 L 70 20 L 98 36 L 98 63 L 60 100 L 22 63 L 22 36 Z"
        stroke="#00e5ff" stroke-width="1.2" stroke-opacity="0.45" stroke-dasharray="8 3 3 3" fill="none" />

  <!-- Corner Via Pins (Connected Nodes) -->
  <circle cx="22" cy="36" r="2" fill="#00ff9d" opacity="0.8" />
  <circle cx="98" cy="36" r="2" fill="#00e5ff" opacity="0.8" />
  <circle cx="22" cy="63" r="2" fill="#00ff9d" opacity="0.8" />
  <circle cx="98" cy="63" r="2" fill="#00e5ff" opacity="0.8" />

  <!-- Radar Scan Sweep Wedge -->
  <path d="M 60 58 L 84 40 A 28 28 0 0 0 60 30 Z" fill="url(#radarSweepGrad)" />

  <!-- Port Scanner Arcs (Reconnaissance Rings) -->
  <!-- Outer Scanner Arc -->
  <path d="M 60 32 A 26 26 0 1 1 36 48"
        stroke="url(#cyberCyanGreen)" stroke-width="2.4" stroke-linecap="round" fill="none" opacity="0.9" />
  <!-- Inner Scanner Arc -->
  <path d="M 47 47 A 17 17 0 1 1 60 75"
        stroke="#00e5ff" stroke-width="2" stroke-linecap="round" fill="none" opacity="0.8" />

  <!-- Network Circuit Lines Connecting to Ports -->
  <!-- North Port Connection -->
  <line x1="60" y1="50" x2="60" y2="28" stroke="#00e5ff" stroke-width="2" stroke-linecap="round" />
  <!-- East Port Connection -->
  <line x1="68" y1="58" x2="88" y2="58" stroke="#00ff9d" stroke-width="2" stroke-linecap="round" />
  <!-- South Port Connection -->
  <line x1="60" y1="66" x2="60" y2="86" stroke="#00e5ff" stroke-width="2" stroke-linecap="round" />
  <!-- West Port Connection -->
  <line x1="52" y1="58" x2="32" y2="58" stroke="#00ff9d" stroke-width="2" stroke-linecap="round" />

  <!-- Diagonal Circuit Traces -->
  <path d="M 46 44 L 38 36 L 30 36" stroke="#00e5ff" stroke-width="1.4" stroke-linecap="round" fill="none" opacity="0.6" />
  <path d="M 74 44 L 82 36 L 90 36" stroke="#00ff9d" stroke-width="1.4" stroke-linecap="round" fill="none" opacity="0.6" />
  <circle cx="30" cy="36" r="1.5" fill="#00e5ff" />
  <circle cx="90" cy="36" r="1.5" fill="#00ff9d" />

  <!-- 4 Primary Network Port Nodes -->
  <!-- North Node -->
  <circle cx="60" cy="28" r="4" fill="#05080a" stroke="#00e5ff" stroke-width="2" />
  <circle cx="60" cy="28" r="1.8" fill="#00e5ff" />
  <!-- East Node (Open Port Indicator) -->
  <circle cx="88" cy="58" r="4" fill="#05080a" stroke="#00ff9d" stroke-width="2" />
  <circle cx="88" cy="58" r="1.8" fill="#00ff9d" filter="url(#neonGlow)" />
  <!-- South Node -->
  <circle cx="60" cy="86" r="4" fill="#05080a" stroke="#00e5ff" stroke-width="2" />
  <circle cx="60" cy="86" r="1.8" fill="#00e5ff" />
  <!-- West Node -->
  <circle cx="32" cy="58" r="4" fill="#05080a" stroke="#00ff9d" stroke-width="2" />
  <circle cx="32" cy="58" r="1.8" fill="#00ff9d" />

  <!-- Active Scan Ping Dot (Radar blip) -->
  <circle cx="78" cy="42" r="2.2" fill="#ffffff" filter="url(#neonGlow)" />
  <circle cx="78" cy="42" r="1.2" fill="#00ff9d" />

  <!-- Center Port Scanner Core Target -->
  <circle cx="60" cy="58" r="9" fill="url(#coreGlow)" />
  <circle cx="60" cy="58" r="8" fill="#070f10" stroke="url(#cyberVertical)" stroke-width="2.2" />
  <circle cx="60" cy="58" r="3.6" fill="#00ff9d" />
  <circle cx="60" cy="58" r="1.5" fill="#ffffff" />

  <!-- Center Reticle Crosshair Ticks -->
  <line x1="60" y1="46" x2="60" y2="49" stroke="#00e5ff" stroke-width="1.5" stroke-linecap="round" />
  <line x1="60" y1="67" x2="60" y2="70" stroke="#00e5ff" stroke-width="1.5" stroke-linecap="round" />
  <line x1="48" y1="58" x2="51" y2="58" stroke="#00e5ff" stroke-width="1.5" stroke-linecap="round" />
  <line x1="69" y1="58" x2="72" y2="58" stroke="#00e5ff" stroke-width="1.5" stroke-linecap="round" />
</svg>
"""

# -------------------------------------------------------------------------
# 2. HORIZONTAL LOGO SVG (Symbol + "CyberPort Scanner")
# -------------------------------------------------------------------------
HORIZONTAL_LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 520 120" width="100%" height="100%" fill="none">
  <defs>
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;800;900&amp;family=Rajdhani:wght@600;700&amp;family=JetBrains+Mono:wght@500;700&amp;display=swap');
      .brand-title {
        font-family: 'Orbitron', 'Bahnschrift', 'Segoe UI', sans-serif;
        font-weight: 800;
        font-size: 40px;
        letter-spacing: 2px;
      }
      .brand-sub {
        font-family: 'JetBrains Mono', 'Rajdhani', monospace, sans-serif;
        font-weight: 700;
        font-size: 13px;
        letter-spacing: 6px;
      }
      .brand-badge {
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        font-size: 10px;
        letter-spacing: 1.5px;
      }
    </style>
    <linearGradient id="hLogoCyanGreen" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00e5ff" />
      <stop offset="60%" stop-color="#00ff9d" />
      <stop offset="100%" stop-color="#00ff9d" />
    </linearGradient>
    <linearGradient id="hShieldFill" x1="50%" y1="0%" x2="50%" y2="100%">
      <stop offset="0%" stop-color="#00e5ff" stop-opacity="0.16" />
      <stop offset="50%" stop-color="#00ff9d" stop-opacity="0.05" />
      <stop offset="100%" stop-color="#05080a" stop-opacity="0.8" />
    </linearGradient>
    <radialGradient id="hRadarSweep" cx="60" cy="58" r="28" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#00e5ff" stop-opacity="0.5" />
      <stop offset="70%" stop-color="#00ff9d" stop-opacity="0.15" />
      <stop offset="100%" stop-color="#00ff9d" stop-opacity="0" />
    </radialGradient>
    <filter id="hGlow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="2.5" result="blur" />
      <feMerge>
        <feMergeNode in="blur" />
        <feMergeNode in="SourceGraphic" />
      </feMerge>
    </filter>
  </defs>

  <!-- Left: CyberPort Symbol Emblem -->
  <g transform="translate(4, 0)">
    <!-- Ambient Shield Backing -->
    <path d="M 48 14 L 52 14 L 52 8 L 68 8 L 68 14 L 72 14 L 104 32 L 104 66 L 60 108 L 16 66 L 16 32 Z"
          fill="url(#hShieldFill)" />

    <!-- Outer Cyber-Shield Frame -->
    <path d="M 48 14 L 52 14 L 52 8 L 68 8 L 68 14 L 72 14 L 104 32 L 104 66 L 60 108 L 16 66 L 16 32 Z"
          stroke="url(#hLogoCyanGreen)" stroke-width="3.5" stroke-linejoin="round" stroke-linecap="round"
          filter="url(#hGlow)" />

    <!-- Inner Circuit Perimeter -->
    <path d="M 50 20 L 70 20 L 98 36 L 98 63 L 60 100 L 22 63 L 22 36 Z"
          stroke="#00e5ff" stroke-width="1.2" stroke-opacity="0.45" stroke-dasharray="8 3 3 3" fill="none" />

    <!-- Radar Wedge -->
    <path d="M 60 58 L 84 40 A 28 28 0 0 0 60 30 Z" fill="url(#hRadarSweep)" />

    <!-- Scanner Arcs -->
    <path d="M 60 32 A 26 26 0 1 1 36 48" stroke="url(#hLogoCyanGreen)" stroke-width="2.4" stroke-linecap="round" fill="none" opacity="0.9" />
    <path d="M 47 47 A 17 17 0 1 1 60 75" stroke="#00e5ff" stroke-width="2" stroke-linecap="round" fill="none" opacity="0.8" />

    <!-- Channel Lines -->
    <line x1="60" y1="50" x2="60" y2="28" stroke="#00e5ff" stroke-width="2" stroke-linecap="round" />
    <line x1="68" y1="58" x2="88" y2="58" stroke="#00ff9d" stroke-width="2" stroke-linecap="round" />
    <line x1="60" y1="66" x2="60" y2="86" stroke="#00e5ff" stroke-width="2" stroke-linecap="round" />
    <line x1="52" y1="58" x2="32" y2="58" stroke="#00ff9d" stroke-width="2" stroke-linecap="round" />

    <!-- 4 Port Nodes -->
    <circle cx="60" cy="28" r="4" fill="#05080a" stroke="#00e5ff" stroke-width="2" />
    <circle cx="60" cy="28" r="1.8" fill="#00e5ff" />
    <circle cx="88" cy="58" r="4" fill="#05080a" stroke="#00ff9d" stroke-width="2" />
    <circle cx="88" cy="58" r="1.8" fill="#00ff9d" filter="url(#hGlow)" />
    <circle cx="60" cy="86" r="4" fill="#05080a" stroke="#00e5ff" stroke-width="2" />
    <circle cx="60" cy="86" r="1.8" fill="#00e5ff" />
    <circle cx="32" cy="58" r="4" fill="#05080a" stroke="#00ff9d" stroke-width="2" />
    <circle cx="32" cy="58" r="1.8" fill="#00ff9d" />

    <!-- Center Core -->
    <circle cx="60" cy="58" r="8" fill="#070f10" stroke="url(#hLogoCyanGreen)" stroke-width="2.2" />
    <circle cx="60" cy="58" r="3.6" fill="#00ff9d" />
    <circle cx="60" cy="58" r="1.5" fill="#ffffff" />
  </g>

  <!-- Divider Circuit Line -->
  <line x1="130" y1="28" x2="130" y2="92" stroke="#00e5ff" stroke-width="1.5" stroke-opacity="0.3" stroke-dasharray="4 4" />
  <circle cx="130" cy="28" r="2" fill="#00e5ff" opacity="0.6" />
  <circle cx="130" cy="92" r="2" fill="#00ff9d" opacity="0.6" />

  <!-- Right: Typography -->
  <g transform="translate(150, 0)">
    <!-- Top Security Kicker Badge -->
    <g transform="translate(0, 22)">
      <rect x="0" y="0" width="138" height="18" rx="3" fill="#00e5ff" fill-opacity="0.08" stroke="#00e5ff" stroke-opacity="0.3" stroke-width="1" />
      <circle cx="8" cy="9" r="3" fill="#00ff9d" />
      <text x="16" y="12.5" fill="#00e5ff" class="brand-badge">SECURE RECON</text>
    </g>

    <!-- Main Title: CYBERPORT -->
    <text x="0" y="74" class="brand-title">
      <tspan fill="#00ff9d" filter="url(#hGlow)">CYBER</tspan><tspan fill="#e6fff5">PORT</tspan>
    </text>

    <!-- Subtitle: SCANNER with Terminal Bracket Accents -->
    <text x="2" y="98" fill="#8fb5ac" class="brand-sub">
      <tspan fill="#00e5ff">//</tspan> SCANNER <tspan fill="#00e5ff">PORT INTEL</tspan>
    </text>
  </g>
</svg>
"""

# -------------------------------------------------------------------------
# 3. OPTIMIZED FAVICON SVG
# -------------------------------------------------------------------------
FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="100%" height="100%" fill="none">
  <defs>
    <linearGradient id="favGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00e5ff" />
      <stop offset="100%" stop-color="#00ff9d" />
    </linearGradient>
  </defs>

  <!-- Dark Backdrop for clean visibility in both light and dark browser tabs -->
  <rect width="64" height="64" rx="14" fill="#05080a" />

  <!-- Outer Cyber-Shield -->
  <path d="M 26 8 L 28 8 L 28 5 L 36 5 L 36 8 L 38 8 L 54 18 L 54 36 L 32 58 L 10 36 L 10 18 Z"
        stroke="url(#favGrad)" stroke-width="2.5" stroke-linejoin="round" fill="#070f10" />

  <!-- Scanner Arc -->
  <path d="M 32 20 A 13 13 0 1 1 19 32" stroke="#00e5ff" stroke-width="2" stroke-linecap="round" fill="none" />

  <!-- Port Channels -->
  <line x1="32" y1="26" x2="32" y2="16" stroke="#00e5ff" stroke-width="1.8" stroke-linecap="round" />
  <line x1="36" y1="32" x2="46" y2="32" stroke="#00ff9d" stroke-width="1.8" stroke-linecap="round" />
  <line x1="32" y1="38" x2="32" y2="48" stroke="#00e5ff" stroke-width="1.8" stroke-linecap="round" />
  <line x1="28" y1="32" x2="18" y2="32" stroke="#00ff9d" stroke-width="1.8" stroke-linecap="round" />

  <!-- Port Nodes -->
  <circle cx="32" cy="16" r="2.5" fill="#00e5ff" />
  <circle cx="46" cy="32" r="2.5" fill="#00ff9d" />
  <circle cx="32" cy="48" r="2.5" fill="#00e5ff" />
  <circle cx="18" cy="32" r="2.5" fill="#00ff9d" />

  <!-- Center Core -->
  <circle cx="32" cy="32" r="4.5" fill="#070f10" stroke="url(#favGrad)" stroke-width="1.8" />
  <circle cx="32" cy="32" r="2" fill="#00ff9d" />
</svg>
"""

# -------------------------------------------------------------------------
# 4. RASTER GENERATOR (Pillow Rendering)
# -------------------------------------------------------------------------
def draw_cyberport_symbol(draw, size, offset_x=0, offset_y=0, scale=1.0, dark_bg=False):
    """Draws pixel-perfect anti-aliased CyberPort Scanner symbol on Pillow canvas."""
    cx = offset_x + size * 0.5
    cy = offset_y + size * 0.483

    # Colors
    c_void = (5, 8, 10, 255)
    c_panel = (7, 15, 16, 255)
    c_cyan = (0, 229, 255, 255)
    c_green = (0, 255, 157, 255)
    c_white = (255, 255, 255, 255)
    c_cyan_glow = (0, 229, 255, 80)
    c_green_glow = (0, 255, 157, 90)

    def tx(x):
        return offset_x + (x / 120.0) * size
    def ty(y):
        return offset_y + (y / 120.0) * size

    # Shield vertices
    shield_pts = [
        (tx(48), ty(14)), (tx(52), ty(14)), (tx(52), ty(8)), (tx(68), ty(8)),
        (tx(68), ty(14)), (tx(72), ty(14)), (tx(104), ty(32)), (tx(104), ty(66)),
        (tx(60), ty(108)), (tx(16), ty(66)), (tx(16), ty(32))
    ]

    # Fill shield
    draw.polygon(shield_pts, fill=c_panel)

    # Outer Shield Border
    stroke_w = max(2, int(3.5 * (size / 120.0)))
    draw.polygon(shield_pts, outline=c_cyan, width=stroke_w)

    # Scanner Arcs
    r_outer = 26 * (size / 120.0)
    draw.arc([cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer],
             start=-50, end=210, fill=c_green, width=max(2, int(2.4 * (size / 120.0))))

    r_inner = 17 * (size / 120.0)
    draw.arc([cx - r_inner, cy - r_inner, cx + r_inner, cy + r_inner],
             start=30, end=240, fill=c_cyan, width=max(1, int(2.0 * (size / 120.0))))

    # Channel Lines
    line_w = max(1, int(2.0 * (size / 120.0)))
    draw.line([(cx, cy - 8 * (size / 120.0)), (cx, ty(28))], fill=c_cyan, width=line_w)
    draw.line([(cx + 8 * (size / 120.0), cy), (tx(88), cy)], fill=c_green, width=line_w)
    draw.line([(cx, cy + 8 * (size / 120.0)), (cx, ty(86))], fill=c_cyan, width=line_w)
    draw.line([(cx - 8 * (size / 120.0), cy), (tx(32), cy)], fill=c_green, width=line_w)

    # 4 Port Nodes
    node_r = 4.0 * (size / 120.0)
    node_inner_r = 1.8 * (size / 120.0)

    for px, py, col in [
        (cx, ty(28), c_cyan),
        (tx(88), cy, c_green),
        (cx, ty(86), c_cyan),
        (tx(32), cy, c_green)
    ]:
        draw.ellipse([px - node_r, py - node_r, px + node_r, py + node_r], fill=c_void, outline=col, width=max(1, int(2.0 * (size / 120.0))))
        draw.ellipse([px - node_inner_r, py - node_inner_r, px + node_inner_r, py + node_inner_r], fill=col)

    # Center Core
    core_r = 8.0 * (size / 120.0)
    draw.ellipse([cx - core_r, cy - core_r, cx + core_r, cy + core_r], fill=c_panel, outline=c_cyan, width=max(1, int(2.2 * (size / 120.0))))
    draw.ellipse([cx - 3.6 * (size / 120.0), cy - 3.6 * (size / 120.0), cx + 3.6 * (size / 120.0), cy + 3.6 * (size / 120.0)], fill=c_green)
    draw.ellipse([cx - 1.5 * (size / 120.0), cy - 1.5 * (size / 120.0), cx + 1.5 * (size / 120.0), cy + 1.5 * (size / 120.0)], fill=c_white)


def generate_png_symbol(size=512, filepath=None, transparent=True):
    """Generates high-res symbol with 4x supersampling for ultra-smooth anti-aliasing."""
    ss = 4
    canvas_size = size * ss
    img = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    margin = int(canvas_size * 0.08)
    draw_cyberport_symbol(draw, canvas_size - 2 * margin, offset_x=margin, offset_y=margin)

    # Downsample with Lanczos filter for razor-sharp vector-like rendering
    final_img = img.resize((size, size), Image.Resampling.LANCZOS)
    if filepath:
        final_img.save(filepath, "PNG", optimize=True)
    return final_img


def generate_apple_touch_icon(size=180, filepath=None):
    """Generates iOS Apple Touch Icon with dark void backing, rounded aesthetic, and neon emblem."""
    ss = 4
    canvas_size = size * ss
    img = Image.new("RGBA", (canvas_size, canvas_size), (5, 8, 10, 255))
    draw = ImageDraw.Draw(img)

    # Subtle background cyber grid
    grid_col = (0, 229, 255, 12)
    step = int(canvas_size / 12)
    for x in range(0, canvas_size, step):
        draw.line([(x, 0), (x, canvas_size)], fill=grid_col, width=2)
    for y in range(0, canvas_size, step):
        draw.line([(0, y), (canvas_size, y)], fill=grid_col, width=2)

    margin = int(canvas_size * 0.14)
    draw_cyberport_symbol(draw, canvas_size - 2 * margin, offset_x=margin, offset_y=margin)

    final_img = img.resize((size, size), Image.Resampling.LANCZOS)
    if filepath:
        final_img.save(filepath, "PNG", optimize=True)
    return final_img


def generate_horizontal_logo_png(width=1040, height=240, filepath=None):
    """Generates master horizontal logo PNG (transparent background)."""
    ss = 2
    cw, ch = width * ss, height * ss
    img = Image.new("RGBA", (cw, ch), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Draw symbol on left
    sym_size = int(ch * 0.85)
    sym_margin_x = int(ch * 0.08)
    sym_margin_y = int((ch - sym_size) / 2)
    draw_cyberport_symbol(draw, sym_size, offset_x=sym_margin_x, offset_y=sym_margin_y)

    # Divider line
    div_x = sym_margin_x + sym_size + int(30 * ss)
    draw.line([(div_x, int(40 * ss)), (div_x, int(ch - 40 * ss))], fill=(0, 229, 255, 75), width=int(2 * ss))
    draw.ellipse([div_x - 3 * ss, 40 * ss - 3 * ss, div_x + 3 * ss, 40 * ss + 3 * ss], fill=(0, 229, 255, 180))
    draw.ellipse([div_x - 3 * ss, ch - 40 * ss - 3 * ss, div_x + 3 * ss, ch - 40 * ss + 3 * ss], fill=(0, 255, 157, 180))

    # Text positioning
    text_x = div_x + int(40 * ss)

    # Load system font
    font_paths = [
        r"C:\Windows\Fonts\bahnschrift.ttf",
        r"C:\Windows\Fonts\segoeuib.ttf",
        r"C:\Windows\Fonts\arialbd.ttf"
    ]
    font_path = next((p for p in font_paths if os.path.exists(p)), None)

    if font_path:
        font_badge = ImageFont.truetype(font_path, int(15 * ss))
        font_title = ImageFont.truetype(font_path, int(64 * ss))
        font_sub = ImageFont.truetype(font_path, int(18 * ss))
    else:
        font_badge = font_title = font_sub = ImageFont.load_default()

    # Badge: [ SECURE RECON ]
    badge_y = int(32 * ss)
    badge_w = int(180 * ss)
    badge_h = int(28 * ss)
    draw.rounded_rectangle([text_x, badge_y, text_x + badge_w, badge_y + badge_h], radius=int(4 * ss),
                          fill=(0, 229, 255, 20), outline=(0, 229, 255, 90), width=int(1.5 * ss))
    draw.ellipse([text_x + 12 * ss, badge_y + 10 * ss, text_x + 20 * ss, badge_y + 18 * ss], fill=(0, 255, 157, 255))
    draw.text((text_x + 28 * ss, badge_y + 6 * ss), "SECURE RECON", font=font_badge, fill=(0, 229, 255, 255))

    # Title: CYBERPORT
    title_y = badge_y + badge_h + int(14 * ss)
    # Draw CYBER in signal green
    draw.text((text_x, title_y), "CYBER", font=font_title, fill=(0, 255, 157, 255))

    # Calculate offset for PORT
    cyber_bbox = draw.textbbox((text_x, title_y), "CYBER", font=font_title)
    cyber_w = cyber_bbox[2] - cyber_bbox[0] + int(6 * ss)
    draw.text((text_x + cyber_w, title_y), "PORT", font=font_title, fill=(230, 255, 245, 255))

    # Subtitle: // SCANNER PORT INTEL
    sub_y = title_y + int(68 * ss)
    draw.text((text_x, sub_y), "// SCANNER  PORT INTEL  TCP/IP RECON", font=font_sub, fill=(143, 181, 172, 255))

    final_img = img.resize((width, height), Image.Resampling.LANCZOS)
    if filepath:
        final_img.save(filepath, "PNG", optimize=True)
    return final_img


def generate_opengraph_banner(width=1200, height=630, filepath=None):
    """Generates high-impact 1200x630 OpenGraph social share card."""
    img = Image.new("RGBA", (width, height), (5, 8, 10, 255))
    draw = ImageDraw.Draw(img)

    # Ambient matrix / cyber grid
    grid_col = (0, 229, 255, 14)
    step = 50
    for x in range(0, width, step):
        draw.line([(x, 0), (x, height)], fill=grid_col, width=1)
    for y in range(0, height, step):
        draw.line([(0, y), (width, y)], fill=grid_col, width=1)

    # Glowing center emblem
    sym_size = 280
    sym_x = 100
    sym_y = int((height - sym_size) / 2)
    draw_cyberport_symbol(draw, sym_size, offset_x=sym_x, offset_y=sym_y)

    # Font setup
    font_paths = [
        r"C:\Windows\Fonts\bahnschrift.ttf",
        r"C:\Windows\Fonts\segoeuib.ttf",
        r"C:\Windows\Fonts\arialbd.ttf"
    ]
    font_path = next((p for p in font_paths if os.path.exists(p)), None)

    if font_path:
        font_pill = ImageFont.truetype(font_path, 16)
        font_title = ImageFont.truetype(font_path, 62)
        font_sub = ImageFont.truetype(font_path, 22)
        font_feat = ImageFont.truetype(font_path, 17)
    else:
        font_pill = font_title = font_sub = font_feat = ImageFont.load_default()

    content_x = sym_x + sym_size + 60

    # Pill badge
    pill_y = 150
    draw.rounded_rectangle([content_x, pill_y, content_x + 320, pill_y + 36], radius=6,
                          fill=(0, 229, 255, 24), outline=(0, 229, 255, 120), width=1)
    draw.ellipse([content_x + 16, pill_y + 13, content_x + 26, pill_y + 23], fill=(0, 255, 157, 255))
    draw.text((content_x + 36, pill_y + 8), "PROFESSIONAL SECURITY RECON", font=font_pill, fill=(0, 229, 255, 255))

    # Main Title: CYBERPORT SCANNER
    title_y = pill_y + 54
    draw.text((content_x, title_y), "CYBER", font=font_title, fill=(0, 255, 157, 255))
    c_box = draw.textbbox((content_x, title_y), "CYBER", font=font_title)
    cw = c_box[2] - c_box[0] + 8
    draw.text((content_x + cw, title_y), "PORT", font=font_title, fill=(230, 255, 245, 255))

    p_box = draw.textbbox((content_x + cw, title_y), "PORT", font=font_title)
    pw = p_box[2] - p_box[0] + 18
    draw.text((content_x + cw + pw, title_y), "SCANNER", font=font_title, fill=(0, 229, 255, 255))

    # Subtitle
    sub_y = title_y + 78
    draw.text((content_x, sub_y),
              "High-performance TCP port scanner & network attack surface analyzer.",
              font=font_sub, fill=(143, 181, 172, 255))
    draw.text((content_x, sub_y + 34),
              "Designed for educational learning & authorized cybersecurity testing.",
              font=font_sub, fill=(77, 107, 100, 255))

    # Tech Chips
    chips_y = sub_y + 90
    chips = ["1000+ Port Engine", "Real-Time Telemetry", "RFC 1918 Enforced", "CSV Export"]
    chip_x = content_x
    for chip in chips:
        c_len = int(len(chip) * 10) + 24
        draw.rounded_rectangle([chip_x, chips_y, chip_x + c_len, chips_y + 30], radius=4,
                              fill=(7, 15, 16, 255), outline=(0, 255, 157, 80), width=1)
        draw.text((chip_x + 12, chips_y + 6), chip, font=font_feat, fill=(230, 255, 245, 255))
        chip_x += c_len + 14

    # Bottom border line
    draw.line([(0, height - 4), (width, height - 4)], fill=(0, 255, 157, 255), width=4)

    if filepath:
        img.save(filepath, "PNG", optimize=True)
    return img


def generate_all_assets():
    """Generates all vector SVGs and raster PNG/ICO assets."""
    print("Generating branding assets in:", OUTPUT_DIR)

    # 1. SVGs
    with open(os.path.join(OUTPUT_DIR, "cyberport-symbol.svg"), "w", encoding="utf-8") as f:
        f.write(SYMBOL_SVG.strip())
    print("[OK] cyberport-symbol.svg generated")

    with open(os.path.join(OUTPUT_DIR, "cyberport-logo.svg"), "w", encoding="utf-8") as f:
        f.write(HORIZONTAL_LOGO_SVG.strip())
    print("[OK] cyberport-logo.svg generated")

    with open(os.path.join(OUTPUT_DIR, "favicon.svg"), "w", encoding="utf-8") as f:
        f.write(FAVICON_SVG.strip())
    print("[OK] favicon.svg generated")

    # 2. Master Symbol PNG (512x512)
    sym_512 = generate_png_symbol(size=512, filepath=os.path.join(OUTPUT_DIR, "cyberport-symbol.png"))
    print("[OK] cyberport-symbol.png (512x512) generated")

    # 3. Apple Touch Icon (180x180)
    generate_apple_touch_icon(size=180, filepath=os.path.join(OUTPUT_DIR, "apple-touch-icon.png"))
    print("[OK] apple-touch-icon.png (180x180) generated")

    # 4. Standard Favicons (32x32 and 16x16 PNG)
    generate_png_symbol(size=32, filepath=os.path.join(OUTPUT_DIR, "favicon-32x32.png"))
    print("[OK] favicon-32x32.png generated")

    generate_png_symbol(size=16, filepath=os.path.join(OUTPUT_DIR, "favicon-16x16.png"))
    print("[OK] favicon-16x16.png generated")

    # 5. Multi-resolution favicon.ico (16, 32, 48)
    ico_16 = generate_png_symbol(size=16)
    ico_32 = generate_png_symbol(size=32)
    ico_48 = generate_png_symbol(size=48)
    ico_path = os.path.join(OUTPUT_DIR, "favicon.ico")
    ico_48.save(ico_path, format="ICO", sizes=[(16, 16), (32, 32), (48, 48)])
    print("[OK] favicon.ico (16, 32, 48) generated")

    # 6. Horizontal Logo PNG
    generate_horizontal_logo_png(filepath=os.path.join(OUTPUT_DIR, "cyberport-logo.png"))
    print("[OK] cyberport-logo.png generated")

    # 7. OpenGraph Banner
    generate_opengraph_banner(filepath=os.path.join(OUTPUT_DIR, "cyberport-og.png"))
    print("[OK] cyberport-og.png (1200x630) generated")

    print("\nAll brand assets successfully generated!")

if __name__ == "__main__":
    generate_all_assets()
