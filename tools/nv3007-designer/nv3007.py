"""NV3007 142x428 SPI LCD driver — host-side, bridge-agnostic.

This is a faithful Python port of the firmware bring-up in
``fsbl/src/nv3007.rs`` / ``secure/src/hw/lcd_nv3007.rs`` / ``secure/src/ui/lcd.rs``.
It exists so a designer with only a USB-to-SPI bridge (no STM32 dev board)
can push pixels to the real EastRising ER-TFTM1.65-2 panel and iterate on
UI visuals.

Nothing in this file is specific to the USB bridge. All bus access goes
through a :class:`Transport` — implement one per bridge (see ``ch347.py``).
The two panel-facing operations a backend must provide are:

    command(cmd, params)  -> one CS-low window, DC=0 for the command byte
                             then DC=1 for the parameter bytes (the NV3007
                             resets its parameter index on CS-high, so a
                             command and its params MUST share one CS window)
    pixels(data)          -> one CS-low window, DC=1, stream RGB565 bytes

Panel facts (authoritative, from docs/hardware/nv3007/*.pdf + firmware):
  * 142(W) x 428(H) native, IPS, NV3007 controller, 4-wire 8-bit SPI.
  * SPI mode 0 (CPOL=0, CPHA=0), MSB-first, 8-bit.
  * RGB565, big-endian on the wire (high byte first).
  * CASET/RASET carry a +12 X offset (RAM is wider than the visible window).
  * 3.3 V logic; VCC 3.0/3.3/3.5 V; module current <= 60 mA.
  * RES active-low: firmware ties it to 3.3 V and uses SWRESET (0x01).
  * BLK is a logic-level backlight enable (High = on): tie to 3.3 V.
"""

from __future__ import annotations

import abc
import time

# ---------------------------------------------------------------------------
# Geometry (mirrors the firmware verbatim)
# ---------------------------------------------------------------------------

FRAME_WIDTH = 142   # native X (columns)
FRAME_HEIGHT = 428  # native Y (rows)
X_OFFSET = 12       # CASET adds 12 to every X coordinate (HW-validated)
Y_OFFSET = 0

# NV3007 / MIPI-DCS commands used here
SWRESET = 0x01
SLPOUT = 0x11
DISPON = 0x29
CASET = 0x2A
RASET = 0x2B
RAMWR = 0x2C

# ---------------------------------------------------------------------------
# NV3007 init sequence — ported 1:1 from fsbl/src/nv3007.rs INIT_SEQ, which is
# in turn byte-for-byte from the dgen1 production bootloader (matches
# Arduino_GFX Arduino_NV3007.h). Do NOT alter values without re-validating on
# the panel — these are production-tuned gamma / GVDD-GVCL / GOA timing.
#
# Order matters: the 0xFF/0xA5 vendor unlock must precede the tuning writes,
# and COLMOD (0x3A = 0x05, RGB565) must be sent AFTER the 0xFF/0x00 relock or
# you get vertical striping.
# ---------------------------------------------------------------------------

INIT_SEQ: list[tuple[int, list[int]]] = [
    # --- vendor command-mode unlock + analog rails ---
    (0xFF, [0xA5]),
    (0x8F, [0x22, 0x03]),
    (0x9A, [0x78]),
    (0x9B, [0x78]),
    (0x9C, [0xA0]),
    (0x9D, [0x17]),
    (0x9E, [0xC3]),
    (0x83, [0xA6]),
    (0x84, [0xC6]),
    (0x85, [0x62]),
    # --- gamma ---
    (0x6E, [0x0F]), (0x7E, [0x0F]), (0x60, [0x04]), (0x70, [0x00]),
    (0x6D, [0x36]), (0x7D, [0x36]), (0x61, [0x05]), (0x71, [0x05]),
    (0x6C, [0x32]), (0x7C, [0x31]), (0x62, [0x0B]), (0x72, [0x0A]),
    (0x68, [0x4A]), (0x78, [0x4C]), (0x66, [0x32]), (0x76, [0x30]),
    (0x6B, [0x13]), (0x7B, [0x12]), (0x63, [0x09]), (0x73, [0x07]),
    (0x6A, [0x16]), (0x7A, [0x14]), (0x64, [0x08]), (0x74, [0x06]),
    (0x69, [0x0D]), (0x79, [0x0A]), (0x65, [0x04]), (0x75, [0x03]),
    (0x67, [0x33]), (0x77, [0x22]), (0x6F, [0x00]), (0x7F, [0x00]),
    # --- GOA timing ---
    (0x50, [0x00]), (0x52, [0xD6]), (0x53, [0x04]), (0x54, [0x04]),
    (0x55, [0x1B]), (0x56, [0x1B]),
    (0xA0, [0x2A, 0x24, 0x00]),
    (0xA1, [0x84]), (0xA2, [0x85]), (0xA8, [0x36]), (0xA9, [0x80]),
    (0xAA, [0x73]),
    (0xAB, [0x03, 0x61]), (0xAC, [0x03, 0x65]), (0xAD, [0x03, 0x60]),
    (0xAE, [0x03, 0x64]),
    (0xB9, [0x82]), (0xBA, [0x83]), (0xBB, [0x80]), (0xBC, [0x81]),
    (0xBD, [0x02]), (0xBE, [0x01]), (0xBF, [0x04]), (0xC0, [0x03]),
    (0xC4, [0x33]), (0xC5, [0x80]), (0xC6, [0x73]), (0xC7, [0x01]),
    (0xC8, [0x33, 0x33]),
    (0xC9, [0x5B]), (0xCA, [0x5A]), (0xCB, [0x5D]), (0xCC, [0x5C]),
    (0xCD, [0x33, 0x33]),
    (0xCE, [0x5F]), (0xCF, [0x5E]), (0xD0, [0x61]), (0xD1, [0x60]),
    # --- frame timing / inversion ---
    (0xB0, [0x3A, 0x3A, 0x00, 0x00]),
    (0xB6, [0x32]), (0xB7, [0x80]), (0xB8, [0x73]),
    (0xE0, [0x00]), (0xE1, [0x03, 0x0F]), (0xE2, [0x04]), (0xE3, [0x01]),
    (0xE4, [0x0E]), (0xE5, [0x01]), (0xE6, [0x19]), (0xE7, [0x10]),
    (0xE8, [0x10]), (0xE9, [0x21]), (0xEA, [0x12]), (0xEB, [0xD0]),
    (0xEC, [0x04]), (0xED, [0x07]), (0xEE, [0x07]), (0xEF, [0x09]),
    (0xF0, [0xD0]), (0xF1, [0x0E]), (0xF9, [0x56]),
    (0xF2, [0x26, 0x1B, 0x0B, 0x20]),
    (0xEC, [0x04]),
    (0x35, [0x00]),
    (0x44, [0x00, 0x10]),
    (0x46, [0x10]),
    # --- lock vendor command-mode, then COLMOD = RGB565 ---
    (0xFF, [0x00]),
    (0x3A, [0x05]),
]


class Transport(abc.ABC):
    """Bus abstraction one implements per USB-to-SPI bridge.

    A backend owns CS + DC + the SPI clock/data. RES and BLK are assumed
    tied to 3.3 V (firmware-style), so there are no methods for them; reset
    is done in software via SWRESET.
    """

    @abc.abstractmethod
    def command(self, cmd: int, params: bytes = b"") -> None:
        """Send one command byte (DC=0) then its params (DC=1) inside a
        single CS-low window."""

    @abc.abstractmethod
    def pixels(self, data: bytes) -> None:
        """Stream RGB565 pixel bytes (DC=1) inside a single CS-low window.
        `data` may be large (a full frame is 121_552 bytes); the backend is
        responsible for chunking to its USB packet limit while holding CS."""

    def close(self) -> None:  # optional
        pass


class NV3007:
    """The panel. Bring-up + address-window + pixel push, over a Transport."""

    WIDTH = FRAME_WIDTH
    HEIGHT = FRAME_HEIGHT

    def __init__(self, transport: Transport):
        self.t = transport

    # -- bring-up ----------------------------------------------------------
    def init(self) -> None:
        """SWRESET (RES is tied high) -> full dgen1 init -> SLPOUT -> DISPON.
        Mirrors the validated firmware ``Lcd::init`` timing."""
        self.t.command(SWRESET)
        time.sleep(0.15)
        for cmd, params in INIT_SEQ:
            self.t.command(cmd, bytes(params))
        self.t.command(SLPOUT)
        time.sleep(0.20)
        self.t.command(DISPON)
        time.sleep(0.15)
        self.set_window(0, 0, FRAME_WIDTH - 1, FRAME_HEIGHT - 1)
        time.sleep(0.02)

    # -- addressing --------------------------------------------------------
    def set_window(self, x0: int, y0: int, x1: int, y1: int) -> None:
        cx0, cx1 = x0 + X_OFFSET, x1 + X_OFFSET
        cy0, cy1 = y0 + Y_OFFSET, y1 + Y_OFFSET
        self.t.command(CASET, bytes([cx0 >> 8, cx0 & 0xFF, cx1 >> 8, cx1 & 0xFF]))
        self.t.command(RASET, bytes([cy0 >> 8, cy0 & 0xFF, cy1 >> 8, cy1 & 0xFF]))
        self.t.command(RAMWR)  # RAMWR opens its own CS window; pixels follow

    # -- pixel push --------------------------------------------------------
    def blit_full(self, rgb565_be: bytes) -> None:
        """Push a full native frame: FRAME_WIDTH*FRAME_HEIGHT RGB565 pixels,
        big-endian, in native raster order (row ny outer, col nx inner)."""
        expect = FRAME_WIDTH * FRAME_HEIGHT * 2
        if len(rgb565_be) != expect:
            raise ValueError(f"frame must be {expect} bytes, got {len(rgb565_be)}")
        self.set_window(0, 0, FRAME_WIDTH - 1, FRAME_HEIGHT - 1)
        self.t.pixels(rgb565_be)

    def fill(self, rgb565: int) -> None:
        """Solid-fill the panel with one RGB565 color."""
        hi, lo = (rgb565 >> 8) & 0xFF, rgb565 & 0xFF
        frame = bytes([hi, lo]) * (FRAME_WIDTH * FRAME_HEIGHT)
        self.blit_full(frame)


# Convenience RGB565 constants (for test patterns)
BLACK = 0x0000
WHITE = 0xFFFF
RED = 0xF800
GREEN = 0x07E0
BLUE = 0x001F
