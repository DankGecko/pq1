"""CH347 (Mode 1, VID:PID 1a86:55db) SPI + GPIO transport over libusb/pyusb.

Portable macOS + Linux backend for ``nv3007.Transport``. No kernel module,
no vendor DLL: it speaks the CH347's raw vendor-bulk protocol on interface 2
(bulk EP 0x06 OUT / 0x86 IN). There is no maintained pure-Python CH347 Mode-1
library, so this is a fresh implementation written from the documented WCH
protocol (opcodes + the 26-byte SPI config struct + the GPIO bit encoding are
protocol facts, cross-checked against WCH's GPL Linux driver
`ch34x_mphsi_master_linux` and the independent `aystarik/ch347-i2c-spi-gpio`).

Wiring model (matches the firmware's minimal-GPIO shape):
  panel SCK  -> CH347 SPI-block  SCK
  panel MOS  -> CH347 SPI-block  MOSI (silk may say SDO)
  panel CS   -> CH347 SPI-block  CS0   (hardware SCS0, controlled by cmd 0xC1)
  panel DC   -> CH347 UART-block CTS   (= CH347 GPIO index 6), driven by cmd 0xCC
  panel VCC  -> CH347 3.3V (level switch MUST be at 3.3V)
  panel GND  -> CH347 GND
  panel RES  -> 3.3V  (software SWRESET 0x01, like the firmware)
  panel BLK  -> 3.3V  (backlight always on)

Two things are inherently bench-verifiable on first bring-up (flagged inline):
  * the SPI-clock divisor->MHz mapping (WCH doesn't publish the base clock) —
    check SCK with a logic analyzer and adjust `freq_hz` if it's off;
  * that CH347 GPIO index 6 physically toggles the DC pin on this board — the
    `test` pattern + a scope/LA confirm it. If DC is on a different pin, pass
    `dc_gpio=`. If the hardware CS proves flaky across the command/param window,
    use `cs_gpio=` to drive CS from a GPIO instead (see README, fully firmware-
    identical software-NSS path).
"""

from __future__ import annotations

import os
import struct
import sys

import usb.core
import usb.util

import nv3007

VID = 0x1A86
PID = 0x55DB
IFACE = 2
EP_OUT = 0x06
EP_IN = 0x86

# --- CH347 vendor opcodes (verified against WCH's GPL driver) ---------------
CMD_SPI_INIT = 0xC0     # payload = 26-byte config; reply 4B, status at [3]
CMD_SPI_CONTROL = 0xC1  # CS + timing; 13B packet; NO reply
CMD_SPI_BLCK_WR = 0xC4  # write-only block; reply 4B ack, [3]==0 OK; <=507 data
CMD_INFO_RD = 0xCA      # read current config; reply 3B hdr + 26B config
CMD_GPIO = 0xCC         # 8 config bytes (GPIO0..7); write 11 read 11

CFG_LEN = 26
MAX_SPI_CHUNK = 507     # CH347 bulk max (510) minus the 3-byte command header

# CS-control byte (per WCH ch347spi_set_cs): 0x80 = enable+ASSERT (drive
# active-low low), 0xC0 = enable+DEASSERT. NOT the reverse some web posts claim.
CS_ASSERT = 0x80
CS_DEASSERT = 0xC0

# Per-GPIO config byte for cmd 0xCC:
#   0x80 modify-enable | 0x40 dir-modify | 0x20 dir(1=out) | 0x10 data-modify |
#   0x08 out-value(1=high)   => out-high 0xF8, out-low 0xF0, leave-alone 0x00
GPIO_OUT_HIGH = 0xF8
GPIO_OUT_LOW = 0xF0

# SPI clock: WCH sets baudrate_scale = iclock*8; with a ~120 MHz base the SCK is
# 120MHz / 2^(iclock+1). Verify on a scope and adjust if your unit differs.
_FREQ_TO_ICLOCK = {
    60_000_000: 0, 30_000_000: 1, 15_000_000: 2, 7_500_000: 3,
    3_750_000: 4, 1_875_000: 5,
}


def _libusb_backend():
    """Return an explicit libusb backend on macOS.

    pyusb's ctypes backend uses ``ctypes.util.find_library``, which on Apple
    Silicon does NOT search ``/opt/homebrew/lib`` — so ``usb.core.find`` throws
    ``NoBackendError`` even after ``brew install libusb``. This is the #1
    "fails at line 1 on a Mac" gotcha. Point the backend at the dylib
    explicitly. Returns None on Linux (default autodiscovery works there).
    """
    if sys.platform != "darwin":
        return None
    import usb.backend.libusb1
    for cand in (
        "/opt/homebrew/lib/libusb-1.0.dylib",   # Apple Silicon (Homebrew)
        "/usr/local/lib/libusb-1.0.dylib",      # Intel (Homebrew)
        "/opt/local/lib/libusb-1.0.dylib",      # MacPorts
    ):
        if os.path.exists(cand):
            be = usb.backend.libusb1.get_backend(find_library=lambda _x, c=cand: c)
            if be is not None:
                return be
    return None  # fall back to autodiscovery; find() will raise a clear error


class CH347Transport(nv3007.Transport):
    def __init__(self, freq_hz: float = 15e6, dc_gpio: int | None = None,
                 cs_gpio: int | None = None, mode: int = 0):
        self.dc_gpio = 6 if dc_gpio is None else dc_gpio   # CTS/GPIO6 (vendor default)
        self.cs_gpio = cs_gpio                             # None => hardware SCS0
        self.mode = mode

        try:
            dev = usb.core.find(idVendor=VID, idProduct=PID, backend=_libusb_backend())
        except usb.core.NoBackendError as e:
            raise IOError(
                "libusb not found. macOS: `brew install libusb`; Linux: install "
                "libusb-1.0. On Apple Silicon, ensure /opt/homebrew/lib/"
                "libusb-1.0.dylib exists (or set DYLD_LIBRARY_PATH=/opt/homebrew/lib)."
            ) from e
        if dev is None:
            raise IOError(
                "CH347 (1a86:55db, Mode 1) not found. Check: board plugged in, "
                "mode switch at M1, level switch at 3.3V, and (Linux) the udev "
                "rule installed / you're in the plugdev group."
            )
        self.dev = dev

        # Linux: iface 2 is vendor-class and normally unbound (cdc_acm holds 0/1),
        # but the out-of-tree WCH module would grab it — detach if present.
        if sys.platform.startswith("linux"):
            try:
                if dev.is_kernel_driver_active(IFACE):
                    dev.detach_kernel_driver(IFACE)
            except (NotImplementedError, usb.core.USBError):
                pass

        # macOS: composite device is already configured and ifaces 0/1 are CDC-
        # claimed, so set_configuration() often throws BUSY — harmless, ignore.
        try:
            dev.set_configuration()
        except usb.core.USBError:
            pass
        usb.util.claim_interface(dev, IFACE)

        self._spi_init(mode=mode, freq_hz=int(freq_hz))

        # DC line as a push-pull output (start high = data mode).
        self._gpio_out(self.dc_gpio, 1)
        if self.cs_gpio is not None:
            self._gpio_out(self.cs_gpio, 1)  # CS idle high (deasserted)

    # -- low-level USB ------------------------------------------------------
    def _xfer(self, out: bytes, in_len: int = 0, timeout: int = 2000) -> bytes:
        if out:  # never push a zero-length bulk packet — the CH347 would desync
            self.dev.write(EP_OUT, out, timeout=timeout)
        if in_len:
            return bytes(self.dev.read(EP_IN, in_len, timeout=timeout))
        return b""

    @staticmethod
    def _pkt(opcode: int, payload: bytes) -> bytes:
        n = len(payload)
        return bytes([opcode, n & 0xFF, (n >> 8) & 0xFF]) + payload

    # -- SPI setup (read-modify-write of the live config) -------------------
    def _spi_init(self, mode: int, freq_hz: int) -> None:
        # Read the chip's current 26-byte config and patch only cpol/cpha/baud/
        # firstbit — direction/mode/datasize/nss/crc keep the firmware defaults.
        self._xfer(bytes([CMD_INFO_RD, 0x01, 0x00, 0x01]))
        rsp = self._xfer(b"", 3 + CFG_LEN)
        if len(rsp) < 3 + CFG_LEN:
            raise IOError(f"CH347 INFO_RD short reply ({len(rsp)}B); check wiring/mode")
        cfg = bytearray(rsp[3:3 + CFG_LEN])

        cpol = 0x0002 if mode in (2, 3) else 0x0000
        cpha = 0x0001 if mode in (1, 3) else 0x0000
        iclock = _FREQ_TO_ICLOCK.get(freq_hz)
        if iclock is None:  # nearest known
            iclock = min(_FREQ_TO_ICLOCK.items(), key=lambda kv: abs(kv[0] - freq_hz))[1]
        struct.pack_into("<H", cfg, 6, cpol)
        struct.pack_into("<H", cfg, 8, cpha)
        struct.pack_into("<H", cfg, 12, iclock * 8)   # baudrate_scale
        struct.pack_into("<H", cfg, 14, 0x0000)       # firstbit: MSB

        self._xfer(self._pkt(CMD_SPI_INIT, bytes(cfg)))
        ack = self._xfer(b"", 4)
        if len(ack) < 4 or ack[0] != CMD_SPI_INIT or ack[3] != 0x00:
            raise IOError(f"CH347 SPI init NAK: {ack!r}")

    # -- CS / DC / SPI primitives ------------------------------------------
    def _cs(self, assert_low: bool) -> None:
        if self.cs_gpio is not None:
            self._gpio_out(self.cs_gpio, 0 if assert_low else 1)  # active-low
            return
        b = CS_ASSERT if assert_low else CS_DEASSERT
        # [0xC1, len=10, cs0, activeDelay(2), deactiveDelay(2), cs1(=0), 4x delay]
        # cs1=0x00 leaves CS1 untouched; auto-deassert bit clear so CS holds.
        self._xfer(self._pkt(CMD_SPI_CONTROL, bytes([b, 0, 0, 0, 0, 0x00, 0, 0, 0, 0])))

    def _dc(self, data: bool) -> None:
        self._gpio_out(self.dc_gpio, 1 if data else 0)

    def _gpio_out(self, pin: int, value: int) -> None:
        cfg = bytearray(8)
        cfg[pin] = GPIO_OUT_HIGH if value else GPIO_OUT_LOW
        self._xfer(self._pkt(CMD_GPIO, bytes(cfg)), 11)  # drain the 11B status

    def _spi_write(self, data: bytes) -> None:
        mv = memoryview(data)
        for off in range(0, len(mv), MAX_SPI_CHUNK):
            blk = bytes(mv[off:off + MAX_SPI_CHUNK])
            self._xfer(self._pkt(CMD_SPI_BLCK_WR, blk))
            ack = self._xfer(b"", 4)
            if len(ack) < 4 or ack[3] != 0x00:
                raise IOError("CH347 SPI block-write NAK")

    # -- nv3007.Transport interface ----------------------------------------
    def command(self, cmd: int, params: bytes = b"") -> None:
        self._cs(True)
        self._dc(False)               # command phase
        self._spi_write(bytes([cmd]))
        if params:
            self._dc(True)            # data phase (CS held low across the window)
            self._spi_write(params)
        self._cs(False)

    def pixels(self, data: bytes) -> None:
        self._cs(True)
        self._dc(True)
        self._spi_write(data)         # one CS window; chunked internally
        self._cs(False)

    def close(self) -> None:
        try:
            usb.util.release_interface(self.dev, IFACE)
            usb.util.dispose_resources(self.dev)
        except Exception:
            pass
