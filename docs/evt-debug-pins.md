# EVT/DVT Debug Pins & Test Pads — STM32U585

**Target MCU:** STM32U585xx (Cortex-M33, TrustZone)
**Scope:** Debug access only — for hardware bring-up, validation, and security audit.
**Lifecycle rule:** **Populate for EVT/DVT, DNP / remove for MP** (mass production).

---

## SWD debug header

1.27 mm Cortex 10-pin connector.

- PA13 — SWDIO
- PA14 — SWCLK
- PB3 — SWO (trace)
- NRST — Reset
- 3V3 — VTref
- GND — Ground

## Debug UART (log console)

- PA9 — USART1_TX (AF7)
- PA10 — USART1_RX (AF7)
- GND — Ground

## Boot select

- BOOT0 — Pad/jumper on EVT/DVT; hard-strap to GND on MP

## Bus test pads (logic-analyzer access)

Through-hole pads / wire loops sized for grabber clips (not bare SMD pads).

- PB8 — I2C1_SCL (SE bus: OPTIGA + SE050)
- PB9 — I2C1_SDA (SE bus)
- PE13 — SPI1_SCK (LCD)
- PE15 — SPI1_MOSI (LCD)
- PE3 — LCD DC
- CC1 — USB-C CC1 (at connector)
- CC2 — USB-C CC2 (at connector)
- VBUS — USB-C VBUS (at connector)
- GND — 2x clip points

## SCA scope trigger

- PD2 — sca-trigger (scope / ChipWhisperer sync)

---

## Notes for the hardware team

- Populate the **SWD** and **UART** as **headers** (plug-in, no soldering required); DNP the connectors for MP.
- Bring bus signals out to **labeled through-hole test points / loops** (grabber-clip friendly), not bare SMD pads.
- EVT has **no on-board ST-Link** → debugging uses an external probe (ST-Link V3 / J-Link) plus a USB-UART dongle and a logic analyzer.
- All items above are debug-only and must be **DNP / removed for MP**.
