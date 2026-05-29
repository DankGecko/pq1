# PQ1 — Screen + LED-Matrix Dev Board

Small board with the **NV3007 screen** + **AW22127 RGB LED matrix**, to hand-jumper to our **B-U585I-IOT02A** rig.

**Hard requirement: no BTB / fine-pitch / FPC connectors exposed** — terminate them on-board; we only touch 0.1″ pin headers.

## Power
- **5 V + GND** in; on-board regulators make 1.8 V, 2.8 V, the backlight rail, and the LED VLED rail (size VLED for the matrix current).

## Level shifting
- Both parts are 1.8 V logic; our MCU is 3.3 V. Level-shift SPI + I²C + control on-board (3.3 V reference) so we jumper plain 3.3 V.

## Signals on the 0.1″ header (~12 pins, labeled)
- Power: 5V, GND
- Screen (SPI): CS, SCLK, MOSI, DC, RES — backlight always on, no dimming
- LED (AW22127, I²C 0x6a): SCL, SDA, RST, INT

## Excluded
- Touch panel (CST816D)
