# NV3007 SPI display → B-U585I-IOT02A wiring

**Module:** EastRising **ER-TFTM1.65-2** (controller **NV3007**, 142×428 RGB565, 4-wire 8-bit SPI).
8-pin header order (module §4.1): **GND · VCC · SCK · MOS(=SDA/MOSI) · RES · DC · CS · BLK**.

Resolved + adversarially verified 2026-06-08 against UM2839 (B-U585I-IOT02A user manual),
the in-tree driver (`secure/src/hw/lcd_nv3007.rs` + `secure/src/hw/spi_hw.rs`, `spi1-arduino`),
and the module + NV3007 datasheets. **MCU pins are code-certain (the firmware drives exactly
these); the physical jumper position is where the risk lives.**

---

## ⚠️ Headline: DC is on PE7; RES is tied to 3V3 (do NOT wire it to a GPIO)

The Phase-A scaffold (2026-05-19) originally chose **PE3 for DC** and **PE1 for RES**, but per
UM2839 Appendix B Table 28 neither is broken out to any user header (PE3 = on-board OCTOSPI
PSRAM `R_DQS`, no exposed pad; PE1 = camera connector CN7 pin 26 only). Both were retargeted
**2026-06-08** and the driver (`lcd_nv3007.rs`) now reflects the as-built bench reality:

- **DC → PE7** (GPIOE bit 7, Arduino **D4 / CN14**) — `DC_PIN = 7`. Driven as a push-pull
  output and **confirmed working on real silicon**. Wire DC to PE7.
- **RES → tied to 3V3 externally — NOT driven by a GPIO.** Both candidate GPIO pins proved
  **un-drivable** on this board (PD15/D2 read flat on the logic analyzer; PE14/D12 likewise).
  The firmware therefore holds the panel out of reset and issues a **software `SWRESET` (0x01)**
  instead of a hardware-reset pin pulse (`init()` / `lcd_test_loop`, `lcd_nv3007.rs:712-740`).
  The `RES_PIN = 14` constant + its GPIO config are vestigial ("now unused", `:737`).

**→ Action: wire DC to PE7 and tie RES to 3V3. Do NOT wire RES to a GPIO** — neither PE14 nor
PD15 can drive it on this board; the panel is reset in software via `SWRESET`.

---

## Confirmed wiring (seat these now)

| Module pin | Signal | MCU pin | Board position | Notes |
|---|---|---|---|---|
| 1 GND | ground | — | **CN13 pin 7** (closest GND to SPI) or CN17 pin 6/7 | |
| 2 VCC | +3.3 V | — | **CN17 pin 4 (3V3)** | 3.0–3.5 V; budget +60 mA for the backlight; bring VCC up **before** any logic pin |
| 3 SCK | SPI1_SCK (AF5) | **PE13** | **Arduino D13 = CN13 pin 6** | also drives LD2 (blue ARD LED) → flashes on SCK, harmless |
| 4 MOS | SPI1_MOSI/SDA (AF5) | **PE15** | **Arduino D11 = CN13 pin 4** | single data line; write-only build |
| 7 CS | chip-select, active-low | **PE12** | **Arduino D10 = CN13 pin 3** | software-managed GPIO (SSM), not AF |
| 8 BLK | backlight, **active-high** | — | **CN17 pin 4 (3V3)** | tie high = always-on for bring-up; a future GPIO/PWM can dim |
| 6 DC | data/command | **PE7** | **Arduino D4 = CN14** | push-pull GPIO (`DC_PIN = 7`); confirmed working on silicon |
| 5 RES | reset, active-low | **— (tie to 3V3)** | **CN17 pin 4 (3V3)** | NOT a GPIO — PE14 and PD15 both proved un-drivable; firmware resets via software `SWRESET` (0x01) |

**MISO (PE14 / D12) is unused** — the panel is write-only (single SDA line, no SDO). Leave it
unconnected. (The driver sets a *vestigial* push-pull RES output on PE14, overriding the
SPI1_MISO AF, but as-built RES is tied to 3V3 and that PE14 config drives nothing — see headline.)

The CN13 silkscreen is trustworthy here: the documented D5/D6 off-by-one (`pin_diag.rs:16-23`)
is on **CN14** and is shield-specific (PE4 → SE050 ENA on the stacked OM-SE050ARD), so it does
**not** extrapolate to CN13 — corroborated by the working PB8/PB9 OLED I2C on the same connector.

---

## Electrical (confirmed)

- **3.3 V both sides → no level shifter.** Module VIH = 0.7·VCC = 2.31 V < STM32 VOH ≈ 3.3 V;
  VIL = 0.99 V > VOL ≈ 0 V (module datasheet §4.3).
- **SPI Mode 0** (CPOL=0, CPHA=0), **MSB-first, 8-bit, 5 MHz** (÷32 from 160 MHz; `spi_hw.rs:189-204`).
  SCK latches data on the rising edge, idles low → Mode 0 (NV3007 §4.1.1).
- **Power sequencing:** enable VCC → release RES → start SPI. Driving a logic pin before VCC is up
  forward-biases the input ESD diodes (back-power / latch-up risk; module precautions p.14).
- **Reset (as-built):** RES is tied to 3V3, so `init()` does **not** pulse a reset pin — it
  issues a software `SWRESET` (0x01) then waits ≥120 ms before commands. The pin-pulse path
  `hard_reset()` (HIGH 10 ms → LOW 200 ms → HIGH 120 ms) is retained in the driver but **unused**
  on this board (it would only matter if RES were ever wired to a real GPIO).
- **Backlight:** BLK is a µA-level *logic enable* into an on-board LED driver; the ~60 mA LED
  current flows from VCC, not through BLK. Safe to drive from a 3.3 V GPIO or tie to 3V3.

## Refresh, partial updates & tearing (validated on hardware 2026-06-09)

Panel bring-up complete. SPI runs at **÷4 = 40 MHz** (`ui-lcd`-gated in `spi_hw.rs`; the
shared-bus default stays ÷32 for non-LCD builds). DWT-measured on a real B-U585I:

- **Full-frame** (142×428 RGB565 = 121,552 B): **24.3 ms ≈ 41 fps** — bus-saturated, the clean
  ceiling. 60 fps full-frame would need ~58 MHz, which violates the NV3007 10 ns data
  setup/hold (datasheet Table 8-3-2) → corruption; ÷2 (80 MHz) also starves the polled FIFO. So
  41 fps is the full-frame write limit on this polled bus. (The panel's *internal* glass refresh
  is a separate, always-on 60 Hz — independent of how fast we write GRAM.)
- **Partial** (`fill_rect`, e.g. 40×40 = 3,200 B): **0.65 ms** (~1,500 fps-equiv). Redraw only the
  changed region — this is how the trusted UI keeps PIN / tx-confirm / fingerprint screens instant.
- **Flicker:** never clear-then-redraw a region in motion; draw new content directly over the old
  and update only the changed slivers (draw-over technique). A full erase leaves a black gap.
- **Tearing — no hardware vsync on this module.** The NV3007 has a TE output (datasheet §5.4,
  cmds 0x34/0x35) but the 8-pin header (GND·VCC·SCK·MOS·RES·DC·CS·BLK) does **not** break TE out,
  so writes can't be gated on vblank without tapping the TE pad on the FPC. Continuously-moving
  content tears occasionally; **static screens — i.e. the entire wallet UI — never tear**, so this
  is irrelevant in practice. If tear-free animation is ever wanted, tap TE → a free GPIO and gate
  repaints on its vblank pulse.

## ⚠️ Damage vectors before powering on

1. **VCC-first power sequencing** (above) — the live risk: never drive a logic pin before VCC is up.

Historical (no longer applicable now that DC=PE7 and RES is 3V3-tied): the Phase-A PE3/PE1 choice
risked **PE3/PSRAM contention** (DC on PE3 fought the on-board OCTOSPI PSRAM DQS driver) and
**PE1/camera contention** (RES on PE1 = camera CN7). Both are moot — those pins are no longer used.

## Verification method

- **SPI silk labels (low-priority):** `make pin-diag-boot-hw` + logic-analyzer capture
  (`pin_diag::header_sweep`) maps each candidate MCU pin → physical CN13 pad. Optional — CN13 is corroborated.
- **DC reachability (PE7):** `header_sweep` does pulse PE7, so an LA capture confirms the
  CN14-D4 → MCU path. Or multimeter-continuity from CN14 D4 to the DC jumper point.
- **RES:** nothing to verify on a GPIO — RES is tied to 3V3 (CN17 pin 4) and reset is software
  `SWRESET`. Just confirm RES is pulled to 3V3, not left floating or wired to a GPIO.

---

## DC/RES retarget — DONE (2026-06-08)

The Phase-A PE3/PE1 pins were retargeted and bench-validated; the driver (`lcd_nv3007.rs`) is
now at the as-built state:

- **DC → PE7** (Arduino D4 / CN14) — stays on **GPIOE**, reusing the existing GPIOE config + BSRR
  helpers (`DC_PIN = 7`). **Confirmed driving on silicon.**
- **RES → tied to 3V3 (no GPIO).** PD15 (GPIOD / Arduino D2) was tried first but read **flat on the
  logic analyzer**; PE14 (the unused SPI1_MISO / D12) likewise proved **un-drivable**. RES is
  therefore held high externally and the panel is reset in software with **`SWRESET` (0x01)**. The
  `RES_PIN = 14` constant + its GPIO block remain in the driver but are vestigial.

Phase-B bring-up is done: the `lcd-test` feature + `make lcd-test-hw` cycle the screen
green→red→blue and confirmed the wiring + ported init sequence on a real B-U585I (panel alive
2026-06-09; see the Refresh section above).
