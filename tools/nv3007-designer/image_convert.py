"""Convert any image into a native NV3007 frame (142x428 RGB565, big-endian).

Orientation is the fiddly part. The panel is physically 142(W) x 428(H)
portrait, but the wallet UI is drawn/viewed in LANDSCAPE (428 wide x 142
tall). The firmware does a software 90-deg rotation with FLIP_X=true,
FLIP_Y=false onto the native panel coordinates (see
``secure/src/ui/lcd.rs::blit_glyph``). We reproduce that here so a designer
can work on a 428x142 landscape canvas and see it upright on the real panel.

Orientation maths (matches the firmware): a native pixel (nx, ny) displays
the logical landscape pixel

    lx = (427 - ny) if flip_y else ny        # landscape column, 0..427
    ly = (141 - nx) if flip_x else nx        # landscape row,    0..141

Defaults flip_x=True, flip_y=False reproduce the validated bench orientation.
If your test pattern shows up mirrored or upside-down, flip one boolean --
resolve it ONCE with an asymmetric glyph (an "F" or an arrow), exactly the
way the firmware orientation was pinned on the bench. Color bars can't reveal
a mirror; use the F pattern.
"""

from __future__ import annotations

import numpy as np
from PIL import Image, ImageDraw, ImageFont

from nv3007 import FRAME_WIDTH, FRAME_HEIGHT  # 142, 428

# Logical landscape canvas the designer works in.
LAND_W = FRAME_HEIGHT  # 428
LAND_H = FRAME_WIDTH   # 142


def _fit(img: Image.Image, w: int, h: int, mode: str) -> Image.Image:
    """Resize `img` to exactly (w, h). mode: stretch | contain | cover."""
    img = img.convert("RGB")
    if mode == "stretch":
        return img.resize((w, h), Image.LANCZOS)
    src_w, src_h = img.size
    scale = (min if mode == "contain" else max)(w / src_w, h / src_h)
    new = img.resize((max(1, round(src_w * scale)), max(1, round(src_h * scale))), Image.LANCZOS)
    canvas = Image.new("RGB", (w, h), (0, 0, 0))
    canvas.paste(new, ((w - new.size[0]) // 2, (h - new.size[1]) // 2))
    return canvas


def rgb_to_native_bytes(rgb: np.ndarray, flip_x: bool = True, flip_y: bool = False) -> bytes:
    """rgb: landscape HxWx3 uint8 array of shape (LAND_H=142, LAND_W=428, 3).
    Returns native 142x428 RGB565 big-endian bytes in raster order (ny, nx)."""
    if rgb.shape[:2] != (LAND_H, LAND_W):
        raise ValueError(f"expected landscape {LAND_H}x{LAND_W}, got {rgb.shape[:2]}")
    # (142,428,3) -> transpose to native (428,142,3): T[ny,nx] = L[nx,ny]
    nat = np.transpose(rgb, (1, 0, 2))          # shape (428,142,3), no flip
    if flip_x:
        nat = nat[:, ::-1, :]                     # ly = 141 - nx
    if flip_y:
        nat = nat[::-1, :, :]                     # lx = 427 - ny
    nat = np.ascontiguousarray(nat).astype(np.uint16)
    r = nat[..., 0] >> 3
    g = nat[..., 1] >> 2
    b = nat[..., 2] >> 3
    v = (r << 11) | (g << 5) | b                  # (428,142) uint16
    out = np.empty((*v.shape, 2), dtype=np.uint8)
    out[..., 0] = (v >> 8).astype(np.uint8)       # big-endian: high byte first
    out[..., 1] = (v & 0xFF).astype(np.uint8)
    return out.tobytes()


def image_to_frame(
    img: Image.Image,
    orient: str = "wallet",
    fit: str = "contain",
    flip_x: bool = True,
    flip_y: bool = False,
) -> bytes:
    """Convert a PIL image to a native NV3007 frame (bytes).

    orient="wallet": treat the image as a 428x142 landscape design (the wallet
        viewing orientation) and rotate to native.
    orient="native": treat the image as a 142x428 portrait; no rotation, just
        pack (X_OFFSET is applied at push time by set_window).
    """
    if orient == "native":
        fitted = _fit(img, FRAME_WIDTH, FRAME_HEIGHT, fit)     # 142x428
        nat = np.asarray(fitted, dtype=np.uint16)              # (428,142,3)
        r, g, b = nat[..., 0] >> 3, nat[..., 1] >> 2, nat[..., 2] >> 3
        v = (r << 11) | (g << 5) | b
        out = np.empty((*v.shape, 2), dtype=np.uint8)
        out[..., 0] = (v >> 8).astype(np.uint8)
        out[..., 1] = (v & 0xFF).astype(np.uint8)
        return out.tobytes()
    # wallet (landscape)
    fitted = _fit(img, LAND_W, LAND_H, fit)                     # 428x142
    rgb = np.asarray(fitted, dtype=np.uint8)                    # (142,428,3)
    return rgb_to_native_bytes(rgb, flip_x=flip_x, flip_y=flip_y)


# ---------------------------------------------------------------------------
# Built-in test patterns (no external assets)
# ---------------------------------------------------------------------------

def orientation_test_image() -> Image.Image:
    """A 428x142 landscape image with an unmistakable orientation: a big red
    'F' at top-left, a green arrow pointing right, corner labels. Use this to
    pin flip_x/flip_y — an 'F' reveals every mirror/rotation a color bar hides."""
    img = Image.new("RGB", (LAND_W, LAND_H), (10, 10, 20))
    d = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("DejaVuSans-Bold.ttf", 96)
        small = ImageFont.truetype("DejaVuSans.ttf", 18)
    except Exception:
        font = ImageFont.load_default()
        small = ImageFont.load_default()
    d.text((8, 8), "F", fill=(255, 40, 40), font=font)
    d.text((4, 2), "TL", fill=(120, 120, 120), font=small)
    d.text((LAND_W - 34, 2), "TR", fill=(120, 120, 120), font=small)
    d.text((4, LAND_H - 22), "BL", fill=(120, 120, 120), font=small)
    d.text((LAND_W - 34, LAND_H - 22), "BR", fill=(120, 120, 120), font=small)
    # green arrow -> right, mid-height
    y = LAND_H // 2
    d.line((150, y, 380, y), fill=(40, 255, 40), width=6)
    d.polygon((380, y - 18, 380, y + 18, 415, y), fill=(40, 255, 40))
    return img
