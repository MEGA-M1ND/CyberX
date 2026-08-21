"""Small multiples of degradation curves, emitted as standalone SVG.

Stdlib only - the repository has no charting dependency and this experiment is
not the place to add one.  Each metric gets its own panel with its own single
axis; there are no dual-axis charts here.

Colours are the validated categorical palette (five slots, checked for
colourblind separation and lightness band in both light and dark surfaces).
Because the palette's light steps sit below 3:1 against a light surface, every
series carries a direct end-label as well as a legend entry, so identity never
rests on colour alone.  A `prefers-color-scheme` block swaps to the dark steps.
"""
from __future__ import annotations

import html
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

SERIES_LIGHT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#4a3aa7"]
SERIES_DARK = ["#3987e5", "#d95926", "#199e70", "#c98500", "#9085e9"]

PANEL_W, PANEL_H = 330, 210
PAD_L, PAD_R, PAD_T, PAD_B = 46, 92, 30, 34
COLS = 2


def _style(n_series: int) -> str:
    light = "\n".join(f"    --s{i}: {SERIES_LIGHT[i]};" for i in range(n_series))
    dark = "\n".join(f"      --s{i}: {SERIES_DARK[i]};" for i in range(n_series))
    return f"""<style>
  svg {{
    --surface: #fcfcfb;
    --ink: #0b0b0b;
    --ink-muted: #6b6a66;
    --grid: #dedddA;
{light}
    font-family: ui-sans-serif, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
  }}
  @media (prefers-color-scheme: dark) {{
    svg {{
      --surface: #1a1a19;
      --ink: #ffffff;
      --ink-muted: #a8a79d;
      --grid: #33322f;
{dark}
    }}
  }}
  .bg {{ fill: var(--surface); }}
  .grid {{ stroke: var(--grid); stroke-width: 1; }}
  .axis {{ stroke: var(--ink-muted); stroke-width: 1; }}
  .tick {{ fill: var(--ink-muted); font-size: 9px; }}
  .panel-title {{ fill: var(--ink); font-size: 11.5px; font-weight: 600; }}
  .panel-sub {{ fill: var(--ink-muted); font-size: 9px; }}
  .lbl {{ font-size: 9px; }}
  .legend {{ fill: var(--ink-muted); font-size: 10px; }}
  .line {{ fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }}
  .dot {{ stroke: var(--surface); stroke-width: 2; }}
</style>"""


def _panel(x0: int, y0: int, title: str, subtitle: str, xs: Sequence[float],
           series: List[Tuple[str, List[Optional[float]]]], y_max: float) -> str:
    w = PANEL_W - PAD_L - PAD_R
    h = PANEL_H - PAD_T - PAD_B
    out: List[str] = [f'<g transform="translate({x0},{y0})">']
    out.append(f'<text class="panel-title" x="0" y="10">{html.escape(title)}</text>')
    out.append(f'<text class="panel-sub" x="0" y="22">{html.escape(subtitle)}</text>')

    def px(i: int) -> float:
        return PAD_L + (w * i / max(1, len(xs) - 1))

    def py(v: float) -> float:
        return PAD_T + h - (h * v / y_max)

    for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = py(frac * y_max)
        out.append(f'<line class="grid" x1="{PAD_L}" y1="{y:.1f}" x2="{PAD_L + w}" y2="{y:.1f}"/>')
        out.append(f'<text class="tick" x="{PAD_L - 6}" y="{y + 3:.1f}" text-anchor="end">'
                   f'{frac * y_max:.1f}</text>')
    out.append(f'<line class="axis" x1="{PAD_L}" y1="{PAD_T + h}" x2="{PAD_L + w}" y2="{PAD_T + h}"/>')
    for i, xv in enumerate(xs):
        out.append(f'<text class="tick" x="{px(i):.1f}" y="{PAD_T + h + 14}" '
                   f'text-anchor="middle">{int(xv * 100)}%</text>')
    out.append(f'<text class="tick" x="{PAD_L + w / 2:.1f}" y="{PAD_T + h + 27}" '
               f'text-anchor="middle">evidence coverage</text>')

    # Two arms can trace exactly the same curve (Arms D and E on unsafe escape
    # are identical), and the later one would simply paint over the earlier.
    # Dashing the duplicate keeps both readable without implying a difference.
    seen: Dict[Tuple, int] = {}
    label_slots: List[Tuple[float, str, str]] = []

    for idx, (name, values) in enumerate(series):
        colour = f"var(--s{idx})"
        key = tuple(values)
        duplicate = key in seen
        seen.setdefault(key, idx)
        points = [(px(i), py(v)) for i, v in enumerate(values) if v is not None]
        dash = ' stroke-dasharray="5 4"' if duplicate else ""
        if len(points) > 1:
            path = " ".join(f"{'M' if k == 0 else 'L'}{x:.1f},{y:.1f}"
                            for k, (x, y) in enumerate(points))
            out.append(f'<path class="line" d="{path}" stroke="{colour}"{dash}/>')
        for x, y in points:
            out.append(f'<circle class="dot" cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{colour}"/>')
        if points:
            label_slots.append((points[-1][1], colour, name))

    # Push end-labels apart so none collide, keeping their vertical order.
    label_slots.sort()
    min_gap = 11.0
    placed: List[float] = []
    for y, _, _ in label_slots:
        target = y if not placed else max(y, placed[-1] + min_gap)
        placed.append(target)
    overflow = placed[-1] - (PAD_T + h) if placed and placed[-1] > PAD_T + h else 0.0
    for (_y, colour, name), slot in zip(label_slots, placed):
        ly = slot - overflow
        out.append(f'<text class="lbl" x="{PAD_L + w + 7:.1f}" y="{ly + 3:.1f}" fill="{colour}">'
                   f'{html.escape(name)}</text>')
    out.append("</g>")
    return "\n".join(out)


def small_multiples(panels: List[Dict], series_names: List[str], title: str) -> str:
    rows = (len(panels) + COLS - 1) // COLS
    width = COLS * PANEL_W + 16
    height = rows * PANEL_H + 62
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
             f'viewBox="0 0 {width} {height}" role="img" '
             f'aria-label="{html.escape(title)}">',
             _style(len(series_names)),
             f'<rect class="bg" x="0" y="0" width="{width}" height="{height}"/>',
             f'<text class="panel-title" x="10" y="18" style="font-size:13px">{html.escape(title)}</text>']

    lx = 10
    for idx, name in enumerate(series_names):
        parts.append(f'<circle cx="{lx + 4}" cy="34" r="4" fill="var(--s{idx})"/>')
        parts.append(f'<text class="legend" x="{lx + 13}" y="37.5">{html.escape(name)}</text>')
        lx += 16 + 7 * len(name)

    for i, panel in enumerate(panels):
        x0 = 8 + (i % COLS) * PANEL_W
        y0 = 48 + (i // COLS) * PANEL_H
        parts.append(_panel(x0, y0, panel["title"], panel["subtitle"], panel["xs"],
                            panel["series"], panel["y_max"]))
    parts.append("</svg>")
    return "\n".join(parts)


def write_svg(path: Path, content: str) -> Path:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content + "\n")
    return Path(path)
