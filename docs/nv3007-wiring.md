# NV3007 SPI display → B-U585I-IOT02A wiring

**Module:** EastRising **ER-TFTM1.65-2** (controller **NV3007**, 142×428 RGB565, 4-wire 8-bit SPI).
8-pin header order (module §4.1): **GND · VCC · SCK · MOS(=SDA/MOSI) · RES · DC · CS · BLK**.

Resolved + adversarially verified 2026-06-08 against UM2839 (B-U585I-IOT02A user manual),
the in-tree driver (`secure/src/hw/lcd_nv3007.rs` + `secure/src/hw/spi_hw.rs`, `spi1-arduino`),
and the module + NV3007 datasheets. **MCU pins are code-certain (the firmware drives exactly
these); the physical jumper position is where the risk lives.**

---

## ⚠️ Headline: DC (PE3) and RES (PE1) are NOT wireable as the Phase-A driver has them

The Phase-A scaffold (2026-05-19, never bench-tested) chose **PE3 for DC** and **PE1 for RES**.
Per UM2839 Appendix B Table 28, **neither is broken out to any user header**:

- **PE3 (DC)** — main function `OCTOSPI.R_DQS`: the **on-board octo-SPI PSRAM** DQS line
  (UM2839 Table 11). **No exposed pad anywhere.** The driver configures PE3 as a *push-pull
  output* (`init_dc_res_gpios`, `lcd_nv3007.rs:189-211`); if the PSRAM is enabled, two
  push-pull drivers fight the same net → **bus contention → potential damage**. Not a wiring
  problem — a pin-choice problem.
- **PE1 (RES)** — main function `CAM.D3`: exposed only on the **camera connector CN7 pin 26**.
  Reachable but awkward, and contends with camera data if a B-CAMS-OMV is fitted.

**→ Action: retarget `DC_PIN` / `RES_PIN` to two free GPIOs on an accessible header** (one-line
driver change) before wiring DC/RES. See "Next step" below. **Do not wire DC/RES until then.**

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
| 5 RES | reset, active-low | PE1 → **retarget** | ⚠️ see headline | |
| 6 DC | data/command | PE3 → **retarget** | ⚠️ see headline | |

**MISO (PE14 / D12) is unused** — the panel is write-only (single SDA line, no SDO). Leave unconnected.

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
- **Reset timing (driver):** `hard_reset()` does HIGH 10 ms → LOW 200 ms → HIGH 120 ms
  (`lcd_nv3007.rs:303-310`) — a conservative superset of the NV3007 ≥10 µs settle / ≥120 ms-before-commands minimums.
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

1. **PE3 / PSRAM contention** — if you wire DC to PE3 (don't), **disable the on-board OCTOSPI PSRAM
   first**; otherwise the driver's push-pull output fights the PSRAM DQS driver. (Mooted by retargeting DC.)
2. **PE1 / camera** — ensure no camera board on CN7 if tapping PE1 for RES. (Mooted by retargeting RES.)
3. **VCC-first power sequencing** (above).

## Verification method

- **SPI silk labels (low-priority):** `make pin-diag-boot-hw` + logic-analyzer capture
  (`pin_diag::header_sweep`) maps each candidate MCU pin → physical CN13 pad. Optional — CN13 is corroborated.
- **DC/RES reachability — do NOT rely on `header_sweep`:** it pulses only
  PA4/PE0/PE4/PB6/PE5/PE7/PF13/PB2/PD15/PC1/PA8 — it **never touches PE1 or PE3**, so "no edge"
  there is meaningless. Use **multimeter continuity** from the chosen GPIO's header pin to the jumper point.

---

## Next step: retarget DC/RES + Phase-B bring-up

**Free GPIOs on the Arduino digital header (CN14), confirmed unused by the firmware** (appear only
in `pin_diag`): **PE7** (UM2839 D4), **PD15** (D2), **PF13** (D7). (Avoid: PA8/PC1 = buttons D9/D8,
PB2 = SAU/UART, PB6/PE5/PA4 = OPTIGA, PE0/PE4 = OPTIGA-RST / SE050-ENA.)

**Proposed retarget:**
- **DC → PE7** (Arduino D4) — stays on **GPIOE**, so the driver's existing GPIOE config + BSRR
  helpers are reused; change is just `DC_PIN: 3 → 7`.
- **RES → PD15** (Arduino D2) — on **GPIOD**, so the driver adds a small GPIOD config + a
  GPIOD-BSRR variant of `res_low`/`res_high`.

⚠️ **Verify the physical position of PE7/PD15 on YOUR board before wiring** — same silkscreen-shift
caveat (the printed D-label may not match): multimeter-continuity from the CN14 pin to the MCU, or
add PE7/PD15 to `pin_diag::header_sweep` and capture. (This is exactly the check the Phase-A driver
skipped for PE1/PE3.)

Then:
1. Update `DC_PIN`/`RES_PIN` (+ GPIOD block for RES) in `lcd_nv3007.rs`; update the module header
   comment + the 4 pin tests. (See work-todo §28 Phase B.)
2. Add a `lcd-test` feature + `make lcd-test-hw` that fills the screen green→red→blue in a loop
   (mirror `decoy-flicker-test`) to confirm bring-up.
