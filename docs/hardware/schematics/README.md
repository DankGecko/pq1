# PQ1 mainboard — schematics

Schematic sheets for the PQ1 mainboard, revision **V10**, dated 2026-07-14 15:00
(vendor build code `AL_A66_MB_V10_20260714_1500`; `A66` is the ODM's internal
project code for the PQ1 mainboard). Two sheets, A1.

| File | Sheets | Contents |
|------|--------|----------|
| `AL_A66_MB_V10_20260714_1500.pdf` | 1 | MCU, both secure elements, display + backlight, buttons, SWD (`U1xx` / `R1xx` / `C1xx`) |
| | 2 | USB-C, charging + power path, button and debug connectors, EMI (`U2xx` / `C2xx` / `D2xx`) |

Unlike the copper plots in [`../pcb/`](../pcb/), these sheets **do** carry full
reference-designator-to-net mapping, so this is the authority for *which MCU pin
carries which net*. It is not the authority for what is safe to physically
probe — [`../evt-debug-pins.md`](../evt-debug-pins.md) is.

## Why this matters right now

[`../evt-silicon-validation.md`](../evt-silicon-validation.md) says, of the
firmware pin table: *"Cross-check every row against the EVT schematic before
flashing anything"*, and flags several rows as chosen empirically on the dev
board rather than from a schematic — notably the OPTIGA RST / SE050 ENA nets,
which it calls *"almost certainly wrong on EVT"*. These sheets are the document
that check was waiting on. The cross-check itself has **not** been done; nothing
in `evt-silicon-validation.md` has been updated against this file.

## Index (read off sheet 1, for orientation only)

Confirm against the PDF before relying on any of it:

- MCU `U101` — **STM32U585CIU6TR** (48-pin; no Port D/E)
- Secure elements — **SLS32AIA010MH** (OPTIGA Trust M) and **SE050E2HQ1**
- Buses — `I2C1`, `I2C2`, `I2C4`; `SPI1` (`SPI1_CS` / `SPI1_SCK` / `SPI1_MOSI`) to the display
- Display — `LCM_DC` / `LCM_RST` / `LCM_TE` / `LCM_EN` / `LCM_LEDA` / `LCM_LEDK`
- Backlight — `AW21036QNR`, `AW99703CSR`; charging + power path on sheet 2 — `AW32901`, `AW35602`
- Rails — `VDD1_3V3`, `VDD3V3`, `VDD3V6`, `VDDA`, `VBAT`
- Buttons — `UP_KEY`, `DOWN_KEY`; debug — `SWDIO`, `SWCLK`

## Provenance

- `sha256 5ba0309d30882b1e04f4fef0eeca4cf7603ab921d85994a4290873481f4ff029`
- Byte-identical to the file received from the ODM. The delivered copy arrived
  through a browser as `…_1500-2.pdf`; the `-2` is a download-dedup suffix, not
  part of the vendor build code, and was dropped so the name matches the
  convention the layer plots in [`../pcb/`](../pcb/) use. Contents unaltered.
- This is the only schematic revision tracked here. Earlier ODM drops are
  superseded and are deliberately not kept, so there is nothing to confuse this
  file with.

## Scope

- This is the EVT-era board revision, matching the V10 layer artwork in
  [`../pcb/`](../pcb/) (layout snapshot `…_20260715_1100`, one day later).
- These are the ODM's design output — a record of what was built, not a
  design-review artifact. No signal-integrity, EMC, or tamper/side-channel
  review is implied by their presence in this repo.
- `*.pdf` is globally `.gitignore`d in this repo because vendor-copyrighted
  datasheets may not be redistributed (those live outside the repo). This
  directory is an explicit exception: our own board documentation is open
  source. The vendor datasheets for the parts *on* this board are not, and are
  still excluded.
