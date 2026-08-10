"""Generate extension icons and a README GUI screenshot."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
ICON_DIR = ROOT / "browser-extension" / "icons"
DOCS = ROOT / "docs"
ICON_DIR.mkdir(parents=True, exist_ok=True)
DOCS.mkdir(parents=True, exist_ok=True)

BG = (11, 18, 32, 255)
PANEL = (18, 26, 43, 255)
ACCENT = (0, 212, 170, 255)
FG = (230, 237, 247, 255)
MUTED = (139, 155, 180, 255)
RED = (239, 68, 68, 255)
YELLOW = (234, 179, 8, 255)
GREEN = (34, 197, 94, 255)
INPUT = (26, 36, 56, 255)


def make_font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    candidates = [
        r"C:\Windows\Fonts\segoeuib.ttf" if bold else r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\arialbd.ttf" if bold else r"C:\Windows\Fonts\arial.ttf",
    ]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


def make_icon(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    margin = max(1, size // 16)
    draw.rounded_rectangle(
        [margin, margin, size - margin - 1, size - margin - 1],
        radius=max(2, size // 5),
        fill=BG,
        outline=ACCENT,
        width=max(1, size // 16),
    )
    cx, cy = size / 2, size / 2
    width, height = size * 0.42, size * 0.48
    shield = [
        (cx, cy - height * 0.45),
        (cx + width * 0.45, cy - height * 0.25),
        (cx + width * 0.38, cy + height * 0.15),
        (cx, cy + height * 0.45),
        (cx - width * 0.38, cy + height * 0.15),
        (cx - width * 0.45, cy - height * 0.25),
    ]
    draw.polygon(shield, fill=PANEL, outline=ACCENT)
    radius = max(2, size // 14)
    draw.ellipse([cx - radius * 3, cy - radius, cx - radius, cy + radius], fill=ACCENT)
    draw.ellipse([cx + radius, cy - radius, cx + radius * 3, cy + radius], fill=ACCENT)
    draw.line(
        [(cx - radius * 1.2, cy), (cx + radius * 1.2, cy)],
        fill=ACCENT,
        width=max(1, size // 18),
    )
    return img


def make_screenshot() -> Image.Image:
    width, height = 1100, 720
    shot = Image.new("RGB", (width, height), BG[:3])
    draw = ImageDraw.Draw(shot)

    title_f = make_font(28, True)
    sub_f = make_font(14)
    label_f = make_font(13, True)
    body_f = make_font(13)
    mono_f = make_font(13)
    score_f = make_font(34, True)
    status_f = make_font(18, True)

    draw.text((40, 28), "PHISHING URL DETECTOR", fill=ACCENT[:3], font=title_f)
    draw.text(
        (40, 68),
        "Heuristic + WHOIS + HTML + Online reputation",
        fill=MUTED[:3],
        font=sub_f,
    )

    draw.rounded_rectangle([40, 110, 780, 158], radius=10, fill=INPUT[:3], outline=(36, 48, 73))
    draw.text(
        (54, 124),
        "http://secure-login.paypal-verify.xyz/update",
        fill=FG[:3],
        font=mono_f,
    )
    draw.rounded_rectangle([800, 110, 940, 158], radius=10, fill=(20, 61, 54))
    draw.text((824, 124), "Analiz Et", fill=FG[:3], font=label_f)
    draw.rounded_rectangle([955, 110, 1060, 158], radius=10, fill=PANEL[:3], outline=(36, 48, 73))
    draw.text((972, 124), "PDF", fill=FG[:3], font=label_f)

    draw.rounded_rectangle([40, 180, 1060, 290], radius=12, fill=PANEL[:3])
    draw.text((60, 198), "Risk Skoru: 100", fill=FG[:3], font=score_f)
    draw.text((60, 250), "Durum: HIGH_RISK", fill=RED[:3], font=status_f)
    draw.ellipse([980, 210, 1004, 234], fill=GREEN[:3])
    draw.ellipse([1012, 210, 1036, 234], fill=YELLOW[:3])
    draw.ellipse([1044, 210, 1068, 234], fill=RED[:3])

    draw.rounded_rectangle([40, 310, 540, 560], radius=12, fill=PANEL[:3])
    draw.rounded_rectangle([560, 310, 1060, 560], radius=12, fill=PANEL[:3])
    draw.text((60, 328), "Bulunan Problemler", fill=MUTED[:3], font=label_f)
    draw.text((580, 328), "Oneriler", fill=MUTED[:3], font=label_f)

    problems = [
        "HTTPS kullanilmiyor",
        "Supheli uzanti (.xyz)",
        "Supheli kelime: login / paypal",
        "Domain icinde '-' kullanimi",
    ]
    recs = [
        "Bu baglantiya tiklamayin",
        "Resmi kanaldan teyit edin",
        "Supheli uzantilarda islem yapmayin",
        "Sifre / kart bilgisi girmeyin",
    ]
    y = 365
    for item in problems:
        draw.text((60, y), f"X  {item}", fill=FG[:3], font=body_f)
        y += 32
    y = 365
    for item in recs:
        draw.text((580, y), f"-  {item}", fill=FG[:3], font=body_f)
        y += 32

    draw.rounded_rectangle([40, 580, 1060, 680], radius=12, fill=PANEL[:3])
    draw.text((60, 596), "Analiz Gecmisi (oturum)", fill=MUTED[:3], font=label_f)
    draw.rounded_rectangle([60, 628, 1040, 662], radius=8, fill=INPUT[:3])
    draw.text(
        (74, 636),
        "[15:42:11] HIGH_RISK (100) | http://secure-login.paypal-verify.xyz/update",
        fill=FG[:3],
        font=mono_f,
    )
    return shot


def main() -> None:
    for size in (16, 48, 128):
        path = ICON_DIR / f"icon{size}.png"
        make_icon(size).save(path)
        print("wrote", path)

    shot_path = DOCS / "screenshot.png"
    make_screenshot().save(shot_path, optimize=True)
    print("wrote", shot_path, shot_path.stat().st_size)


if __name__ == "__main__":
    main()
