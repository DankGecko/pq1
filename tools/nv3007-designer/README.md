# NV3007 Designer Bring-up (CH347 USB → SPI)

Drive the wallet's **NV3007 LCD** (EastRising ER-TFTM1.65-2, 142×428) straight
from a laptop over a **Waveshare "USB TO UART/I2C/SPI/JTAG"** bridge, so a
designer can iterate on UI visuals **without the STM32 dev board**. This is
pure visual bring-up: push PNGs to the real panel, tweak, repeat. No wallet
logic is involved.

The panel init sequence, geometry, RGB565 packing and orientation here are a
faithful 1:1 port of the firmware (`fsbl/src/nv3007.rs`, `secure/src/ui/lcd.rs`),
so what shows on the bench panel matches what the device renders.

- Works on **macOS** (the designer's MacBook) and **Linux** — identical code.
- **Pure Python + libusb** (pyusb). No kernel module, no vendor DLL, no
  code-signing. The CH347's SPI/GPIO lives on a vendor USB interface that
  no OS driver claims, so we talk to it directly.

---

## 1. What the bridge actually is

Despite the "USB-to-SPI" name, this board is **not** an FTDI chip — it's a
**WCH CH347T**. It enumerates as `1a86:55db` ("QinHeng USB To UART+SPI+I2C")
when its mode DIP is at **M1**. SPI/I2C/GPIO ride a vendor-class bulk interface
(interface 2); the "UART1" you also get is a normal `/dev/ttyACM*` we ignore.

> **Two switches, both latched at power-on — set them before plugging in USB:**
> - **Mode** DIP → **M1** (gives UART1 + SPI + I2C on `55db`).
> - **Level** slide switch → **3.3 V** (sets the I/O + VCC voltage).
>
> ⚠️ **The level switch is independent of the mode switch.** M1 alone does *not*
> guarantee 3.3 V. If the level switch is on **5 V**, the header VCC **and every
> signal line** become 5 V and **will destroy the panel** (VCC max 3.5 V).
> Always meter VCC→GND ≈ 3.3 V before connecting the panel.

---

## 2. Wiring

The panel is a self-contained 3.3 V breakout: **8-pin header, silkscreen order
`GND · VCC · SCK · MOS · RES · DC · CS · BLK`**. It's write-only (no MISO), the
backlight `BLK` is a logic enable (High = on), and `RES` is active-low.

| NV3007 pin | → CH347 header pin | CH347 detail | Notes |
|---|---|---|---|
| **GND** | SPI block **GND** | — | common ground |
| **VCC** | SPI block **VCC** | switchable rail | **must read ≈3.3 V** (level switch @ 3.3 V) |
| **SCK** | SPI block **SCK** (CLK) | chip pin 6 | SPI clock |
| **MOS** | SPI block **MOSI** | chip pin 8 (silk may say **SDO**) | panel data-in |
| **RES** | **VCC / 3.3 V** | tied high | reset done in software (SWRESET 0x01), like the firmware |
| **DC** | UART block **CTS** | **GPIO6** (chip pin 2) | data/command line, driven as GPIO |
| **CS** | SPI block **CS0** | chip pin 5 (hardware SCS0) | active-low chip select |
| **BLK** | **VCC / 3.3 V** | tied high | backlight always on |

Notes:
- **DC is on the UART connector, not the SPI connector.** `DC → UART1.CTS`
  (CH347 GPIO index 6) is exactly Waveshare's own reference wiring for an SPI
  display. Everything else is on the SPI block.
- **Don't cross MOSI/MISO.** Panel `MOS` (data-in) → board **MOSI/SDO**. The
  board's MISO/SDI is left unconnected.
- Only **6 wires** to the SPI block (GND, VCC×also feeds RES+BLK, SCK, MOSI, CS)
  plus **1 wire** (DC) to the UART block. RES and BLK just jumper to the 3.3 V
  rail.
- **Optional hardware reset:** wire `RES → UART1.RTS` (GPIO7) instead of 3.3 V
  and the firmware-style SWRESET still works either way — not required.

---

## 3. One-time software setup

Install Python deps everywhere:

```bash
python3 -m pip install -r requirements.txt      # pyusb, Pillow, numpy
```

### macOS (the designer's Mac)

```bash
brew install libusb
```

That's it — no kext, no root, no code-signing. macOS claims only the CDC-UART
interfaces; the SPI vendor interface is free. The driver already points pyusb at
Homebrew's libusb (`/opt/homebrew/lib` on Apple Silicon, `/usr/local/lib` on
Intel). If you ever see `NoBackendError`, run
`export DYLD_LIBRARY_PATH=/opt/homebrew/lib` and retry.

### Linux (your box)

```bash
sudo apt install libusb-1.0-0            # Debian/Ubuntu (Fedora: dnf install libusb1)
sudo cp 99-ch347.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
# make sure you're in plugdev, then unplug/replug the board:
sudo usermod -aG plugdev "$USER"         # (re-login if you weren't already)
```

The CDC-UART interfaces bind to `cdc_acm` (harmless — that's `/dev/ttyACM0`); we
only claim the vendor interface, which stays unbound. If you ever loaded WCH's
out-of-tree kernel module it will grab the interface — `sudo modprobe -r ch347`.

---

## 4. Usage

```bash
# sanity check: RGB fills + an orientation 'F'
python3 show.py test

# solid fill (RRGGBB)
python3 show.py fill 00FF00

# push one design
python3 show.py image mock.png                 # 428x142 landscape assumed
python3 show.py image portrait.png --orient native

# LIVE loop: re-push whenever the file (or newest PNG in a folder) changes
python3 show.py watch mock.png
python3 show.py watch designs/
```

**Designer workflow:** design at **428 × 142** (landscape — the way the wallet
is viewed), export a PNG, and run `watch` on it. Every re-export repaints the
physical panel in ~0.3 s. Iterate until it looks right.

Useful flags (all subcommands): `--freq 15e6` (SPI clock), `--orient wallet|native`,
`--fit contain|cover|stretch`, `--flip-x/--no-flip-x`, `--flip-y`, `--dc-gpio N`,
`--cs-gpio N`.

---

## 5. First-bring-up checklist (do this before trusting it)

The panel electrical facts and the CH347 protocol are verified from datasheets
and WCH's own driver, but **this driver has not yet been run on your exact board**
— close these two loops on the bench first (your Kingst LA1010 covers both; see
the `la1010` skill):

1. **Switches:** Mode **M1**, Level **3.3 V**, set *before* USB. Meter VCC→GND
   ≈ 3.3 V, and CS0 idle ≈ 3.3 V (not 5 V). *(SCK idles low in mode 0 — don't
   use it to check voltage; a 0 V reading there is correct.)*
2. **`python3 show.py test`:** expect green → red → blue fills (confirms SPI +
   init + color order), then a red **F** + green arrow pointing right.
   - Nothing lights → check wiring / switches / that `init` printed.
   - Mirrored or rotated → add `--flip-x/--no-flip-x/--flip-y` (or `--orient`)
     until the **F** reads correctly, then note the working combo. An "F"
     reveals mirrors that color bars can't.
3. **Logic analyzer (optional but recommended):**
   - Probe **SCK** during a push and confirm the actual clock. WCH doesn't
     publish the divisor base clock, so `--freq` is nominal; adjust if it's off.
   - Probe **DC (GPIO6)** and confirm it toggles low (command) / high (data).
     If DC doesn't move, it's on a different pin — try another `--dc-gpio`.

---

## 6. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `NoBackendError` | libusb not found. macOS: `brew install libusb` (+ the DYLD hint above). Linux: `apt install libusb-1.0-0`. |
| `... not found (1a86:55db)` | Mode DIP not at M1, or set after power-on. Set M1, replug. Confirm with `lsusb \| grep 1a86`. |
| `USBError: Access denied` (Linux) | udev rule not installed or not in `plugdev`. Install `99-ch347.rules`, re-login, replug. |
| `USBError: Resource busy` | Another process holds the interface (or a crashed run). Replug, or `modprobe -r ch347` if the WCH kernel module is loaded. |
| Panel stays black, fills don't show | Wiring (esp. MOS↔MOSI, DC pin), or level switch not at 3.3 V. Re-run the checklist. |
| Vertical stripes | COLMOD ordering — shouldn't happen with the ported init; re-flash confirms. |
| Image sideways/mirrored | Orientation flags — see checklist step 2. |
| Tearing during a change | Cosmetic (full-frame repaint races the scan-out); static frames are clean. |

---

## 7. Files

| File | Role |
|---|---|
| `nv3007.py` | Panel driver: init sequence, geometry, `Transport` interface. **Bridge-independent.** |
| `image_convert.py` | PNG → native 142×428 RGB565 (big-endian) + orientation transform. |
| `ch347.py` | CH347 SPI+GPIO transport over pyusb/libusb (the one bridge-specific file). |
| `show.py` | CLI: `test` / `fill` / `image` / `watch`. |
| `requirements.txt` | `pyusb`, `Pillow`, `numpy`. |
| `99-ch347.rules` | Linux udev rule for non-root access. |

To support a different USB-SPI bridge later, implement one `nv3007.Transport`
(the `command()` + `pixels()` methods) — nothing else changes.
