# Build Your Own PQ1

*Snapshot 2026-07-14.*

The PQ1 isn't open-source as a gesture. The **entire wallet — post-quantum signer, dual
secure elements, trusted display, PIN gating — runs on four boards you can order today**,
no custom PCB, no NDA'd datasheet, no factory. This is not a stripped-down demo: it is the
exact bench rig the shipping firmware is developed and silicon-validated on. Roughly
**$150 in parts** and an afternoon of jumper wires gets you a working post-quantum
ERC-4337 hardware wallet that signs real SPHINCS+C10 transactions on its own screen.

Don't want to buy anything? The whole wallet also boots in QEMU:

```bash
make play        # interactive wallet in QEMU — arrow keys, PIN entry, seed wizard, signing
```

---

## Bill of materials

| # | Part | What it is in the PQ1 | Buy | ≈ Price |
|---|------|------------------------|-----|---------|
| 1 | **ST B-U585I-IOT02A** Discovery kit | The wallet itself — STM32U585 (Cortex-M33, TrustZone), hardware SHA-256/SAES/TRNG. The on-board ST-LINK/V3E is your programmer, so no extra probe needed. | [Mouser](https://www.mouser.com/ProductDetail/STMicroelectronics/B-U585I-IOT02A) | $70 |
| 2 | **Infineon OPTIGA™ Trust M Shield** (`TRUSTMV3SHIELDTOBO1`) | Secure element #1 (Trust M V3, CC EAL6+). Holds one XOR half of your seed entropy; talks encrypted I²C (Shielded Connection). | [Mouser](https://www.mouser.com/ProductDetail/Infineon-Technologies/TRUSTMV3SHIELDTOBO1) | $15 |
| 3 | **NXP OM-SE050ARD-E** dev kit | Secure element #2 (EdgeLock SE050E, CC EAL6+). Holds the other entropy half + silicon PIN counter; talks SCP03. **Must be the `-E` variant** — the firmware pins the SE050E's `AppletConfig` and will reject other variants. | [Mouser](https://www.mouser.com/ProductDetail/NXP-Semiconductors/OM-SE050ARD-E) | $40 |
| 4 | **NV3007 1.65″ IPS display module**, 142×428, 8-pin SPI header (`GND·VCC·SCK·MOS·RES·DC·CS·BLK`) | The trusted display — PIN entry, seed words, and every transaction render here, inside the secure world. Get the breakout-board version, not the bare FPC panel. | [Alibaba listing — link coming] <!-- TODO(markus): paste the Alibaba link for the NV3007 breakout --> · reference module: [EastRising ER-TFTM1.65-2](https://www.buydisplay.com/1-65-inch-142x428-ips-tft-lcd-display-module-for-arduino-raspberry-pi) | $10 |
| 5 | Solderless breadboard, 400-point (1×) | Holds the OPTIGA shield, the two buttons, and the 3V3/GND rails. | [Mouser (BB400T)](https://www.mouser.com/ProductDetail/BusBoard-Prototype-Systems/BB400T) | $7 |
| 6 | Jumper wires — one 40-pack **M–F** + one 40-pack **M–M** (~20 actually used) | Everything below is point-to-point 2.54 mm jumpers. | [Mouser (Adafruit 826, M–F)](https://www.mouser.com/ProductDetail/Adafruit/826) · [Mouser (Adafruit 758, M–M)](https://www.mouser.com/ProductDetail/Adafruit/758) | $9 |
| 7 | 2× 6 mm tactile push buttons | The entire user input: LEFT / RIGHT. Physical confirm only — no touchscreen, no input controller IC. | [Mouser (Omron B3F-1000)](https://www.mouser.com/ProductDetail/Omron-Electronics/B3F-1000) | $1 |
| 8 | Micro-USB **data** cable + USB-C cable | Micro-USB → the ST-LINK debug port for flashing; USB-C → powers the finished device and carries the companion-app HID link. You probably own both. | — | — |

**Total ≈ $150**, most of it the Discovery kit. Prices drift — trust the links, not this column.

Soldering: possibly none. The Discovery kit and the SE050 kit arrive assembled; if the
OPTIGA shield or the display breakout ship with loose pin headers, those two headers are
the only iron work in the build.

---

## How it goes together

```
   [ NV3007 LCD ]        [LEFT] [RIGHT]        ← trusted display + confirm buttons
        │ SPI (4 wires)       │ GPIO (2)          (both live on the breadboard)
   ┌────┴─────────────────────┴─────┐
   │   OM-SE050ARD-E   (SE #2)      │  ← stacks directly on the Arduino headers
   ├────────────────────────────────┤
   │   B-U585I-IOT02A  (STM32U585)  │  ← the wallet
   └───────────────┬────────────────┘
                   │ I²C1 (D14/D15) + reset
        [ OPTIGA Trust M V3 shield ]   ← SE #1, seated in the breadboard
```

About **20 jumpers** total. The SE050 shield passes the Arduino headers through, so most
signal taps land on its top header (J2: `1=D8 · 2=D9 · 3=D10 · 4=D11 · 6=D13 · 7=GND ·
9=SDA/D14 · 10=SCL/D15`). First, feed the breadboard rails: one jumper from a 3V3 socket
to the **+** rail, one from GND to the **–** rail.

**OPTIGA shield — 6 wires:**

| OPTIGA pin | Goes to |
|---|---|
| `3V3` | breadboard **+** rail |
| `GND` | breadboard **–** rail |
| `CTL` | breadboard **+** rail (power gate, always on) |
| `SCL` | `D15` (SE050 J2:10) |
| `SDA` | `D14` (SE050 J2:9) |
| `RST` | **`D6`** on the Discovery board's own CN14 socket — ⚠ read below |

> ⚠ **The one trap in this build:** put the OPTIGA reset wire on the CN14 position
> **silkscreened D6 — not D5.** The stacked SE050 shield routes D5 to the SE050's ENA
> line, so an OPTIGA reset pulse on D5 power-cycles the SE050 mid-write (we bricked a
> provisioning run learning this). And yes, on this board the CN14 silkscreen is
> off-by-one versus the user manual — the firmware drives PE0, which is the pad labeled
> D6. Full story: `docs/work-todo.md` Completion Log 2026-04-23.

**NV3007 display — 8 wires:**

| Module pin | Goes to |
|---|---|
| `GND` | breadboard **–** rail |
| `VCC` | breadboard **+** rail — power VCC **before** any logic pin |
| `SCK` | `D13` (SE050 J2:6) |
| `MOS` | `D11` (SE050 J2:4) |
| `CS`  | `D10` (SE050 J2:3) |
| `DC`  | `D4` on the Discovery's own CN14 socket (the SE050 shield doesn't break out D0–D7) |
| `RES` | breadboard **+** rail — **tie to 3V3, do NOT wire to a GPIO**; the firmware resets the panel in software |
| `BLK` | breadboard **+** rail (backlight always on) |

**Buttons — 4 wires:** LEFT button between `D8` (SE050 J2:1) and the **–** rail; RIGHT
between `D9` (J2:2) and the **–** rail. Active-low, internal pull-ups — no resistors.

Authoritative wiring references (pin-verified on real silicon, logic analyzer and all):
`docs/hardware/nv3007-wiring.md` · `docs/secure-elements/optiga-bringup-status.md`
§"Hardware wiring" · `docs/hardware/dev-board-setup.md`.

---

## Flash it

One-time setup (details in `docs/hardware/dev-board-setup.md`):

```bash
rustup target add thumbv8m.main-none-eabi
cargo install probe-rs-tools
# + STM32CubeProgrammer from st.com (writes the TrustZone option bytes; free account)
```

Then, with the Micro-USB cable on the ST-LINK port:

```bash
make flash-hw-dual-se-lcd-standalone
```

That one target builds both TrustZone worlds (dual-SE + LCD + buttons + USB), flashes
them, programs the TrustZone option bytes, and resets. Move the JP4 jumper to `5V_UCPD`,
unplug the programmer, plug in USB-C — the device now boots standalone: measured-boot
fingerprint, then the first-boot wizard walks you through PIN and a 24-word seed **on the
device's own screen**, provisions both secure elements with XOR entropy halves, and
you're signing. First signature ≤ 3 s; ~1.1 s warm. (To re-run the wizard on a used rig:
`make wipe-for-wizard`.)

---

## What you just built

- **A real post-quantum signer.** Every signature is SPHINCS+C10 — hash-based, no ECDSA
  anywhere — verified on-chain by the same Yul verifier the production wallet uses.
- **A real dual-SE seed split.** Your seed entropy is XOR-split across the OPTIGA and the
  SE050. Neither chip alone — desoldered, decapped, whatever — holds a single bit of it.
- **A real trusted display.** Transactions are decoded and rendered inside the TrustZone
  secure world; the companion app never gets to substitute a hash.
- **PIN gating in silicon, three ways.** SE050 UserID counter, OPTIGA lockout counter,
  MCU flash counter — reconciled to the strictest on every boot.
- **Verifiability.** The build is reproducible (`docs/firmware/reproducible-builds.md`,
  `make verify-repro`), and the boot fingerprint — 8 BIP-39 words on the LCD — lets you
  check the flash contents against a build you made yourself. This is the same property
  production units ship with (at RDP-0, flash verifiable over SWD before first power).

**The honest caveat:** a breadboard PQ1 is a real signer, not a hardened one. The dev
build pairs the secure elements with bench keys, leaves the OPTIGA in its unlocked
lifecycle state, keeps the debug port open, and its jumper wires are gloriously easy to
probe. Production units burn all of that down at provisioning (`docs/production-todo.md`).
The cryptography is identical; the armor is not. Don't put your savings behind a
breadboard — do use it to verify that everything we claim about the firmware is true, on
hardware you own.

Questions, bugs, or a wiring photo you're proud of → open an issue.
