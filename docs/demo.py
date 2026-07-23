#!/usr/bin/env python3
"""Render the terminal demo used in the README and social posts.

This helper intentionally lives outside the package and only needs Pillow:

    python3 -m pip install Pillow
    python3 docs/demo.py

The scan summary shown here is the output of scanning the repository's safe
four-file fixture, presented with the user-facing ``~/.../my-plugin`` path.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "demo.gif"
WIDTH = 1200
HEIGHT = 675

BACKGROUND = "#070B12"
BACKGROUND_GLOW = "#0C2530"
PANEL = "#0D131D"
PANEL_TOP = "#111A26"
BORDER = "#263344"
TEXT = "#E6EDF3"
MUTED = "#8B9AAF"
CYAN = "#4FD1C5"
GREEN = "#6EE7A8"
BLUE = "#72A7FF"
YELLOW = "#F2C96D"
RED = "#FF6B6B"

FONT_PATH = "/System/Library/Fonts/Menlo.ttc"
FALLBACK_FONT_PATH = "/System/Library/Fonts/SFNSMono.ttf"
FONT_FILE = FONT_PATH if Path(FONT_PATH).exists() else FALLBACK_FONT_PATH
FONT = ImageFont.truetype(FONT_FILE, 20)
FONT_SMALL = ImageFont.truetype(FONT_FILE, 16)
FONT_TITLE = ImageFont.truetype(FONT_FILE, 27)


@dataclass(frozen=True)
class Line:
    text: str
    color: str = TEXT


frames: list[Image.Image] = []
durations: list[int] = []
lines: list[Line] = []


def rounded(
    draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], radius: int, fill: str
) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill)


def draw_frame(current: Line | None = None, *, cursor: bool = False) -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT), BACKGROUND)
    draw = ImageDraw.Draw(image)

    # Quiet depth without a noisy gradient: broad, layered rounded glows.
    rounded(draw, (-170, -180, 540, 360), 260, BACKGROUND_GLOW)
    rounded(draw, (845, 500, 1320, 790), 180, "#101A29")

    draw.text((54, 40), "HERMES PLUGIN GUARD", font=FONT_TITLE, fill=TEXT)
    draw.text((54, 80), "Static review before plugin enablement", font=FONT_SMALL, fill=MUTED)

    badge_specs = [
        ("LOCAL", 901, CYAN),
        ("NO EXECUTION", 982, GREEN),
    ]
    for label, x, color in badge_specs:
        right = x + (62 if label == "LOCAL" else 164)
        rounded(draw, (x, 44, right, 76), 8, PANEL_TOP)
        draw.rounded_rectangle((x, 44, right, 76), radius=8, outline=color, width=1)
        draw.text((x + 12, 51), label, font=FONT_SMALL, fill=color)

    # Terminal chrome and shadow.
    rounded(draw, (43, 126, 1157, 638), 18, "#03070C")
    rounded(draw, (36, 118, 1150, 630), 18, PANEL)
    draw.rounded_rectangle((36, 118, 1150, 630), radius=18, outline=BORDER, width=2)
    rounded(draw, (38, 120, 1148, 165), 16, PANEL_TOP)
    draw.rectangle((38, 144, 1148, 165), fill=PANEL_TOP)

    for x, color in ((62, RED), (88, YELLOW), (114, GREEN)):
        draw.ellipse((x, 135, x + 12, 147), fill=color)
    draw.text((470, 131), "~/hermes-plugin-guard", font=FONT_SMALL, fill=MUTED)

    x = 63
    y = 188
    line_height = 31
    visible_lines = [*lines]
    if current is not None:
        visible_lines.append(current)

    for row in visible_lines:
        draw.text((x, y), row.text, font=FONT, fill=row.color)
        y += line_height

    if cursor:
        cursor_text = visible_lines[-1].text if visible_lines else ""
        cursor_x = x + int(draw.textlength(cursor_text, font=FONT)) + 2
        draw.rectangle((cursor_x, y - line_height + 3, cursor_x + 10, y - 3), fill=CYAN)

    draw.line((63, 595, 1123, 595), fill=BORDER, width=1)
    draw.text((63, 603), "LOCAL STATIC ANALYSIS", font=FONT_SMALL, fill=CYAN)
    draw.text((886, 603), "PLUGIN CODE IS NEVER RUN", font=FONT_SMALL, fill=MUTED)
    return image


def add_frame(duration: int, current: Line | None = None, *, cursor: bool = False) -> None:
    frames.append(draw_frame(current, cursor=cursor))
    durations.append(duration)


def pause(duration: int, *, cursor: bool = False) -> None:
    add_frame(duration, cursor=cursor)


def type_line(text: str, color: str = TEXT, *, step: int = 2, delay: int = 65) -> None:
    for end in range(step, len(text) + step, step):
        add_frame(delay, Line(text[: min(end, len(text))], color), cursor=True)
    lines.append(Line(text, color))


def reveal(text: str, color: str = TEXT, *, duration: int = 520) -> None:
    lines.append(Line(text, color))
    pause(duration)


def main() -> None:
    # Intro and a real installation command for the v0.1.1 GitHub release.
    pause(900)
    pause(450, cursor=True)
    type_line("$ pipx install \\", CYAN, step=1, delay=80)
    type_line(
        '> "git+https://github.com/mauricemohr88-debug/hermes-plugin-guard.git@v0.1.1"',
        TEXT,
        step=2,
        delay=55,
    )
    pause(850, cursor=True)
    reveal("  installed package hermes-plugin-guard 0.1.1", MUTED, duration=650)
    reveal("  apps now available: hpg, hermes-plugin-guard", GREEN, duration=850)
    reveal("", duration=350)

    # The report below is the exact text format produced by the safe fixture.
    type_line("$ hpg scan ~/.hermes/plugins/my-plugin", CYAN, step=1, delay=70)
    pause(1_150, cursor=True)
    reveal("hermes-plugin-guard 0.1.1", MUTED, duration=500)
    reveal("Scanned 1 plugin(s), 4 file(s) — 0 finding(s)", TEXT, duration=600)
    reveal("Summary: no findings", MUTED, duration=600)
    reveal("Result: PASS (no finding at or above high)", GREEN, duration=950)

    # Leave enough time to read the result before the loop starts again.
    pause(7_000, cursor=True)

    palette_frames = [
        frame.convert("P", palette=Image.Palette.ADAPTIVE, colors=96, dither=Image.Dither.NONE)
        for frame in frames
    ]
    palette_frames[0].save(
        OUTPUT,
        save_all=True,
        append_images=palette_frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=1,
    )
    print(f"Wrote {OUTPUT} ({sum(durations) / 1000:.1f}s, {len(frames)} frames)")


if __name__ == "__main__":
    main()
