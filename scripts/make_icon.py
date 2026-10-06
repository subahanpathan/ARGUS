"""Generate ARGUS app icon (.ico) programmatically — shield + eye motif."""
from pathlib import Path
from PIL import Image, ImageDraw

S = 512


def build_icon() -> Image.Image:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # Background: rounded square, deep navy
    d.rounded_rectangle([16, 16, S - 16, S - 16], radius=96, fill=(7, 12, 22, 255))

    # Shield silhouette
    cx = S // 2
    shield_top = 90
    shield_bot = S - 96
    half_w = 160
    pts = [
        (cx - half_w, shield_top),
        (cx + half_w, shield_top),
        (cx + half_w, shield_top + 150),
        (cx, shield_bot),
        (cx - half_w, shield_top + 150),
    ]
    d.polygon(pts, fill=(10, 20, 36, 255), outline=(0, 200, 255, 255), width=14)

    # Inner glow ring (cyan)
    d.ellipse(
        [cx - 105, shield_top + 70, cx + 105, shield_top + 280],
        outline=(0, 210, 255, 200),
        width=12,
    )

    # Eye / pupil (ARGUS = all-seeing)
    d.ellipse([cx - 52, shield_top + 122, cx + 52, shield_top + 226], fill=(0, 220, 255, 255))
    d.ellipse([cx - 24, shield_top + 150, cx + 24, shield_top + 198], fill=(7, 12, 22, 255))
    d.ellipse([cx - 8, shield_top + 166, cx + 8, shield_top + 182], fill=(140, 245, 255, 255))

    return img


if __name__ == "__main__":
    import sys

    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("argus.ico")
    img = build_icon()
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(out, format="ICO", sizes=sizes)
    png_path = out.with_suffix(".png")
    img.save(png_path, format="PNG")
    print(f"Wrote {out} and {png_path}")
