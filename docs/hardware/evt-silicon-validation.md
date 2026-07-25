# EVT silicon-validation checklist — everything that must be proven on real hardware

**Created 2026-07-24. Snapshot as of that date.** Compiled ahead of the first custom
**PQSigner EVT** PCBs (STM32U585 + OPTIGA Trust M V3 + SE050C2 + NV3007 LCD + 2 buttons).

## What this document is

Until now, everything in this firmware was validated on the ST **B-U585I-IOT02A**
dev kit (jumper-wired Arduino headers + OM-SE050ARD shield) or on **QEMU
mps2-an505**. Neither proves the firmware works on our own board, and a large
class of claims — the entire silicon-lockdown ceremony, per-die key derivation,
fault-injection resistance — has *never* been exercised on any hardware at all.

This is the **single index** of every such item: every assumption baked into the
code that was measured on the dev kit and could differ on our PCB, and every
security property whose proof is an unrun on-silicon test. It exists so that when
boards arrive we work from one list instead of re-deriving it from scattered docs.

**This file is an index, not the authority.** Each item points at the doc /
`file:line` / GitHub issue that owns it. Where a procedure exists, follow that
source. The load-bearing references here were produced by an automated sweep on
2026-07-24 — **spot-check a `file:line` before you act on it**, because the tree
moves.

### How to read the tables

- **Destructive?** — **DESTRUCTIVE** = irreversible on that die/part (RDP burn,
  OTP fuse, WRP/option-byte lock, OPTIGA/SE050 lifecycle ratchet, PUT KEY commit).
  Do these **only on sacrificial parts first**, never on a unit you want back.
  **NON-DEST** = read-only or reversible bench measurement, safe on any board.
  **MIXED** = a non-destructive measurement gates a later destructive burn.
- **Ref** — the owning doc / code site / GitHub issue (`#NNN` = `EthereumPhone/PQ1`).

### Do these in order

1. **§1–§2 first (all NON-DEST).** Board bring-up and pin/clock/bus verification.
   Nothing below is trustworthy until the board runs firmware at the right clock
   with the right pins. These need only an ST-LINK V3 + logic analyzer + UART.
2. **§3–§10 (mostly DESTRUCTIVE) only on sacrificial parts,** and only after §1–§2
   pass. The irreversible ceremony and the FI campaigns consume silicon.
3. **Keep ≥1 EVT unit pristine** (never RDP-locked, never OTP-burned) for
   regression debugging.

### Prerequisites already on the bench / to buy

- **Probe:** ST-LINK V3 (`probe-rs` compatible). **UART:** the EVT exposes a
  PA9/PA10 header — **the dev kit's on-board ST-LINK VCP does not exist on our
  board** (§2, `uart.rs:1-9`), so the RDP≥1 debug channel *is* that header.
- **Logic analyzer** for the I2C1 (PB8/PB9) + LCD SPI pads.
- **FI/SCA rigs already on the bench:** Ledger Donjon Scaffold (Vdd crowbar),
  Electronic Cats FaultyCat (EMFI), Rigol MHO934. **Absent, needed for on-silicon
  power/EM SCA:** ChipWhisperer-Husky / ChipSHOUTER (`docs/tooling-and-systems.md:71,95`).
- **Sacrificial-part budget** (from `docs/provisioning/first-boot-hardware-bringup.md:47-49`,
  `docs/security/red-teaming.md:52-53`): ≥5 STM32U585, ≥5 SE050C2 (OEF A201),
  ≥1 TRUSTMV3SHIELDTOBO1, plus ≥3 units beyond the one RDP-2 "production-config" unit.

### The one-line honest status

From `docs/audits/external-invariants-20-response-20260704.md`: **nothing has
shipped; the code is done, the silicon lockdown ceremony is not.** 16 of 20
external invariants pass from source review; the 4 that fail (HDP, RDP2/WRP/OEM2,
BOOT_LOCK, BOR) are all the unburned option-byte layer below. The single artifact
that would close most of §3 is *a verified option-byte / OTP readback attestation
from a fully-provisioned, RDP2-locked production unit* — which requires doing this.

---

## Sacrificial-unit plan — validate everything while destroying only 2 boards

**Goal (owner decision 2026-07-24):** spend at most **2 EVT PCBs** as sacrificial
units. Every other board stays a reusable **RDP-0** development board forever.

**The core move:** separate *chip-silicon destruction* from *on-board ceremony
proof*. The tests that physically kill a chip — Vdd crowbars, EMFI glitch
campaigns, many-shot atomicity — are about **silicon behavior, not our PCB**, so
they run on **loose parts and dev kits and consume zero EVT boards.** The 2
sacrificial EVT boards are spent only on what genuinely needs the real integrated
board: the irreversible lockdown ceremony, end to end.

### Three board tiers

1. **Dev fleet (every board except 2) — RDP-0 forever, infinitely reusable.** Runs
   the dev feature set (`dev-testkey`/`mock-se`, hardcoded master,
   `make wipe-for-wizard` to re-provision). SWD stays live → always reflashable.
   Carries all daily firmware development **and** every non-destructive validation
   item below.
2. **Loose parts / dev kit (0 EVT boards) — the destruction sink.** ≥5 loose
   STM32U585 (incl. the B-U585I dev kits), ≥5 loose SE050C2/A201, ≥1 OPTIGA
   TRUSTMV3SHIELDTOBO1 shield, + Scaffold/FaultyCat rigs. Absorbs every
   crowbar / glitch / atomicity / torn-write test.
3. **S1 + S2 (exactly 2 EVT boards) — the golden ceremony proof.** Chosen **late**,
   as the two best-behaving fleet boards after bring-up. Each runs the full
   production first-boot self-lock **once** → two independent RDP-2-locked,
   fully-provisioned units.

### Why 2 and not 1

- **DHUK uniqueness at RDP-2 (§10.7) needs n ≥ 2 locked boards** to compare per-die
  fingerprints — one locked board cannot demonstrate uniqueness.
- **A repeatable receipt beats a one-off:** two independent units both reading back
  the correct option-byte/OTP profile is materially stronger evidence for the
  invariant, and gives a clean confirmation run after any fix the first run surfaces.
- **One terminal lock, no retry:** RDP-2 is forever. If the first real on-board run
  reveals an integration surprise, S2 is the held-in-reserve confirmation.

### Phase sequence (with gates)

**Phase 0 — Prep (no EVT boards).** Obtain the loose parts. Build the
bench-ship-validation image (§7.1). Fix the OPTIGA shield handshake (§5.5) on the
dev kit. Discover the option-byte register offsets by non-dest readback +
destructive rehearsal on a loose U585. Run the ship-blocker crowbars — SE050
PUT-KEY atomicity (§6.3) and OTP torn-burn (§4.2) — on loose parts so those
verdicts exist *before* any EVT board is at risk.
*Gate: ceremony offsets/ordering/timings known; crowbar verdicts in hand; firmware frozen.*

**Phase 1 — Fleet bring-up (all EVT boards, RDP-0, non-dest).** §1 pin-map, §2
clock/bus/timing, §4.4 flash-page health, §6.1 SE050C2 fingerprint capture,
§5.5/§5.6 OPTIGA handshake + sign, §3.9/§3.11 readbacks, §10 non-dest platform checks.
*Gate: every board is a known-good RDP-0 dev board. Daily dev proceeds on all of them indefinitely.*

**Phase 2 — Rehearse + select (loose parts + dev kit).** Full dry-run on loose
STM32 + SE050C2 + OPTIGA shield: power-cut/torn-write durability matrices
(§7.3, §4.2), OPTIGA lifecycle ratchet + brick-recovery (§5), SE rotation
(§6.2/§6.6), RDP-2 downgrade campaign (§9.6). Designate the 2 best-behaving fleet
boards as S1/S2.
*Gate: the on-board run will be **confirmation, not discovery**. Do not proceed until a loose-part run completes the whole ceremony cleanly.*

**Phase 3 — S1 (first sacrificial).** RDP-1 DHUK capture over VCP (§7.4) → full
first-boot self-lock (§7) → RDP-2. Read back the option-byte/OTP profile; run the
SWD-must-fail probe (§3.10); confirm OPTIGA/SE in-situ lockdown (§5, §6.2/§6.6).
*Gate: if ANY integration bug appears, STOP — fix firmware, return to Phase 2 on loose parts. Do NOT burn S2 to debug.*

**Phase 4 — S2 (second sacrificial).** Repeat the clean ceremony. Compare S1↔S2
DHUK fingerprints → close §10.7 (n = 2 at RDP-2). Two independent readback receipts
→ discharge the option-byte/OTP invariant.
*Gate: two locked units, two matching-profile receipts, distinct DHUKs.*

**Standing rule:** the remaining boards never leave RDP-0. If S1 *and* S2 both
surface distinct on-board bugs, that means Phase-2 rehearsal was insufficient — do
**not** reflexively promote a third board; reproduce and fix on loose parts first.

### Hard dependency (the plan fails without it)

This plan holds **only if loose SE050C2/A201 samples and OPTIGA shields are
obtainable.** The ship-blocker crowbars (§6.3 PUT-KEY atomicity, §6.8 admin-delete,
§4.2 OTP torn-burn) destroy the chip and need many parts for statistical
confidence; they cannot fit inside 2 boards. If loose production-part SEs cannot be
sourced, those ship-blockers have nowhere to run except EVT boards and the
sacrificial count rises well past 2. **Resolve loose-part sourcing before committing
to the 2-board budget.**

### Item routing — which tier closes each section

| Tier | Closes |
|---|---|
| **Dev fleet (RDP-0, reusable)** | §1, §2, §3.9, §3.11, §4.4, §5.5, §5.6, §6.1, §6.7, §6.10–6.13, §8 (non-dest bench), §9.1–9.5, §10.1, §10.3, §10.6 |
| **Loose parts / dev kit (0 EVT)** | §4.2, §5 ratchet-rehearsal + brick-recovery, §6.2/§6.6 rehearsal, §6.3, §6.5, §6.8, §7.3 durability, §9.6, §11 research |
| **S1 + S2 (2 sacrificial EVT)** | §3.1–3.8, §3.10, §3.12, §4.1, §5 in-situ, §6.2/§6.6 in-situ, §7 full ceremony ×2, §10.7 |

---

## §1 — Board bring-up: pin map cross-check (NON-DEST, do first)

The drivers hardcode **bit positions**, not pin abstractions. If the EVT moves any
signal to a different GPIO bank/pin, that driver's MODER/OTYPER/OSPEEDR/PUPDR/AFR
math is wrong. **Cross-check every row against the EVT schematic before flashing
anything.** Several of these pins were chosen empirically on the dev board (LA
capture), not from a schematic, and are flagged.

| Signal | Firmware pin | Ref | EVT note |
|---|---|---|---|
| LEFT button | PC1 (Arduino D8) | `secure/src/hw/buttons.rs:81,159` | dev-kit jumper wire |
| RIGHT button | PA8 (Arduino D9) | `buttons.rs:82,165` | shares GPIOA with SWD PA13/PA14 |
| USER button (test) | PC13 | `buttons.rs:168` | **on-board only — will not exist on EVT** |
| Consumption-mask PWM | PA5, TIM2_CH1 AF1 | `secure/src/hw/consumption_mask.rs:19,268` | must sit near/across the die supply to matter (§9) |
| Debug UART TX | PA9, USART1 AF7 | `secure/src/hw/uart.rs:113` | **needs an EVT header — no on-board VCP** |
| Debug UART RX | PA10, USART1 AF7 | — | EVT spec pin |
| I2C1 SCL (both SEs) | PB8 AF4 | `secure/src/hw/i2c_hw.rs:12,105` | 400 kHz, **external pull-ups assumed** (§2) |
| I2C1 SDA (both SEs) | PB9 AF4 | `i2c_hw.rs:13` | OPTIGA @0x30 + SE050 @0x48 share this bus |
| I2C2 SCL/SDA (STSAFE probe) | PH4/PH5 AF4 | `secure/src/hw/i2c2_probe.rs:26` | probes on-board STSAFE-A110 @0x20 — **not on EVT** |
| LCD SPI (`ui-lcd`/`spi1-arduino`) | PE12 CS / PE13 SCK / PE14 MISO / PE15 MOSI, SPI1 AF5 | `secure/src/hw/spi_hw.rs:14,36` | shipping display path |
| LCD SPI (default/non-arduino) | PB12–15, SPI2 AF5 | `spi_hw.rs:5,34` | bench builds only |
| LCD DC | PE7 (Arduino D4) | `secure/src/hw/lcd_nv3007.rs:102` | retargeted 2026-06-08 off unreachable PE3/PE1 |
| LCD RES | PE14 | `lcd_nv3007.rs:107,711` | **tied to 3V3 on dev board → SWRESET used, pin never drives** |
| USB D-/D+ | PA11/PA12 OTG_FS AF10 | `secure/src/hw/usb_hw.rs:95` | direct to connector |
| USB CC1/CC2 | PA15/PB15 UCPD1 | `usb_hw.rs:98,384` | through TCPP03 (see below) |
| TCPP03 port-protect EN | PB5 (drive HIGH before USB) | `usb_hw.rs:100,189` | **on-board TCPP03-M20 (U8) — may not exist on EVT** |
| **OPTIGA RST** | **PE0 ("D6")** | `secure/src/optiga/reset_pin.rs:51,14-21` | **empirical, contradicts UM2839, silkscreen off-by-one — almost certainly wrong on EVT** |
| SE050 ENA | Arduino D5 = PE4 (implicit) | `reset_pin.rs:14-21` | why OPTIGA RST was moved off PE4 |

**Highest-risk rows (verify against schematic first):** OPTIGA RST / SE050 ENA
nets (empirical, board-specific — the PE0 choice is almost certainly wrong on the
EVT); the two button pins; TCPP03 PB5. `reset_pin.rs:29-104` also documents a
silicon-write-ordering quirk (a bare BSRR store produced no edge; full
MODER→…→BSRR + 50 ms settle was required) — re-check on EVT silicon.

---

## §2 — Clock, bus, and timing re-verification (NON-DEST, do first)

Every busy-wait, timeout, baud divisor, and I2C/SPI timing word in the firmware is
calibrated to **160 MHz SYSCLK**. If the EVT power design can't reach VOS1 the part
silently drops to 16 MHz and **all** of it is wrong at once.

| Item | Assumption | Ref | EVT risk |
|---|---|---|---|
| Clock tree | 160 MHz via PLL1, VOS1 + EPOD boost, 4 WS; **falls back to 16 MHz if VOS fails** | `secure/src/hw/rcc.rs:121-138` | LDO-vs-SMPS dependent; BOOSTRDY "may never set" on LDO-only. Drives everything below. **Verify SYSCLK on silicon before trusting any timing.** |
| I2C1 timing | `TIMING_400KHZ = 0x1090_378F` for 160 MHz PCLK1 + 3.3 kΩ external pull-ups | `secure/src/hw/i2c_hw.rs:80-119` | breaks if PCLK≠160 MHz, different pull-ups, or higher bus capacitance. No clock-stretch handling. |
| I2C `asm::delay` calibration | `delay(8000)` = 50 µs nominal but **~150 µs wall-clock (≈3× calibration)** | `secure/src/optiga/i2c.rs:26-47,300` | bench-measured constant; shifts with clock. OPTIGA GUARD_TIME + all IFX poll cadences ride on it (`ifx_i2c.rs:330`). |
| SE050 busy-waits | "wait N nop loops" for interface reset / WTX / read-retry | `secure/src/se050/t1oi2c.rs:137,307` | clock-calibrated; re-verify at EVT clock. |
| LCD SPI clock | **÷8 = 20 MHz cap** — set *because the dev board's LD2 LED on PE13=SCK* rounds 40 MHz edges | `secure/src/hw/spi_hw.rs:219-236` | comment says a board with no LED on SCK "could go back to ÷4 (40 MHz)" — **re-tune up on EVT.** |
| SysTick cadence | `TIMEOUT_TICKS`/`FORCED_FLOW_DEADLINE_MS` in ~1 ms ticks from `setup_systick()` | `secure/src/timeout.rs:26-56` | reload derived from SYSCLK; every wall-clock deadline drifts if clock differs. |
| UART BRR | `BRR=1389` for 115200 at PCLK2 160 MHz | `secure/src/hw/uart.rs:133` | recompute if PCLK2 differs. |
| HASH KAT | SHA-256("abc") self-test halts on mismatch; ALGO=bits17+18, pulse RSTR each hash | `secure/src/hw/hash.rs:122-162,258` | silicon-rev sensitive; runs automatically on every HW boot. |
| RNG | secure alias only, CONDRST bit 30, needs HSI48 | `secure/src/hw/rng.rs:8-94` | noisier EVT rail can raise SEIS/CEIS; recovery-once-then-panic path. |
| Bus decode | OPTIGA = Infineon nibble **CRC-16 KERMIT**, FCS **high-byte-first** (do NOT "fix"); SE050 = **CRC-16/CCITT** | `optiga/ifx_i2c.rs:126-153`; `se050/t1oi2c.rs:74-76` | protocol-not-board, but re-confirm if EVT carries a different SE silicon rev. |

**Bring-up smoke tests (NON-DEST):** `make test-key-speed` (DWT-timed sign, prints
`=== PASS ===`; substantially-slower-than-expected timings ⇒ HASH peripheral or
clock wrong), `make saes-self-test-hw`, `make lcd-test-hw` / `make splash-test-hw`,
`make flash-hw-optiga-shield-handshake-only`, `make pin-gate-hw-counter-e2e`.

---

## §3 — STM32U585 option-byte lockdown ceremony (all DESTRUCTIVE)

The most-repeated cluster and the reason "nothing has shipped." Enforced at build
time by the `nsc/mod.rs` `compile_error!` fences, but **never burned on a die.**
Ordering rule everywhere: **WRP1A → DA/OEM key → RDP2 last.** Register offsets
marked "not silicon-pinned" fail closed today (`shared/src/lockdown.rs`) and must be
confirmed against RM0456 + a positive bench read before the constants are flipped.

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 3.1 | **RDP Level 2 burn (`RDP=0xCC`)** — kills SWD/JTAG forever | DESTRUCTIVE | `external-invariants-20-response-20260704.md:37-48`; `main.rs:914-928`; issue **#34**; `tools/factory-provisioning-verify.sh:165` |
| 3.2 | **WRP1A on FSBL pages** — must precede RDP2; `WRP1A_MASK_PINNED=false` | DESTRUCTIVE | `shared/src/lockdown.rs:63-68,189`; issue **#35**; `first-boot-hardware-bringup.md:63` |
| 3.3 | **WRP2A on bank-2 FSBL pages** (both banks) | DESTRUCTIVE | issue **#35, #43** |
| 3.4 | **OEM2KEY / DA-key provisioning + OEM1/2LOCK bit-position pin** — default DA password must fail | MIXED (detection NON-DEST on sacrificial part; finalization DESTRUCTIVE) | `shared/src/lockdown.rs:98-120`; issues **#40, #34**; error `E080A` |
| 3.5 | **HDP1 (HDP1EN + HDP1_PEND) + mirror HDP2** over FSBL — configured nowhere today | DESTRUCTIVE | `external-invariants-20-response-20260704.md:29-35`; issues **#39, #43** |
| 3.6 | **BOOT_LOCK=1** (+ SWAP_BANK=0) — SECBOOTADD0 set but remap still NS-reachable | DESTRUCTIVE | `external-invariants-20-response-20260704.md:50-56`; issues **#38, #44** |
| 3.7 | **BOR_LEV ≥ 4 + SRAM2_RST=0 + armed PVD** — `make stm32-harden-opts` only sets BOR_LEV=3; brownout currently bypasses the SRAM wipe | DESTRUCTIVE | `external-invariants-20-response-20260704.md:205-213`; `shared/src/lockdown.rs:92`; issues **#49, #82**; `reset_cause.rs:72-77` |
| 3.8 | **SECWM1/2 watermarks + SECBOOTADD0 match EVT flash geometry** (not the bench split) | DESTRUCTIVE | `Makefile` `flash-hw*` targets `:195`; issue **#37, #43** |
| 3.9 | **RM0456 register-layout pins** — SECWM1R1@0x50 / SECWM2R1@0x60, SECBOOTADD0 alignment, OPTWERR bit position | NON-DEST (readback) | `first-boot-hardware-bringup.md:55-75`; `shared/src/lockdown.rs:70-76` |
| 3.10 | **SWD-attach-must-fail EOL probe** on every RDP2 unit | NON-DEST (precondition = 3.1 burned) | `external-invariants-20-response-20260704.md:58-67`; issue **#53** |
| 3.11 | **GPDMA blocked from secure SRAM; trusted-path GPIOs stay secure** — verify on silicon | NON-DEST | issue **#53** |
| 3.12 | Sacrificial dry-run: **BOOT_LOCK→OPTWERR lock + both-banks-WRP / identical-FSBL no-op** behavior | DESTRUCTIVE | issues **#45, #41** |

---

## §4 — STM32 OTP: device-master burn + rollback floor (DESTRUCTIVE, one-way fuse)

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 4.1 | **Device-master OTP burn viability on EVT silicon.** On the Rev W dev board every attempt hit `SECSR=0x90` (WRPERR\|PGSERR) — such a die "rejects user OTP writes; reject the part." Confirm EVT parts accept the burn. | DESTRUCTIVE | `evt-factory-bringup.md:155,295`; `secure/src/hw/otp.rs:653-741`; issue **#133** |
| 4.2 | **OTP torn half-burn / QW atomicity** (`HW-ASSUME-QW-ATOMIC`, `HW-ASSUME-OTP-ONEWAY`). 32-byte master = two QW writes; power-cut between them silently drops 256→128 bits. Torn/ECC-poisoned QW0 may read unstably → brick. | DESTRUCTIVE (Scaffold Vdd crowbar on sacrificial U585) | `hardware-assumption-boundary-2026-07-17.md:426-484`; `red-teaming.md:574-611`; issues **#93, #94** |
| 4.3 | **Legacy unary rollback tally is production-blocked** — replace before production (Draft 1.1, see §11) | DESTRUCTIVE (OTP) | `otp.rs:9-19`; issue **#31** |
| 4.4 | **Flash page 126/124 per-chip write-hostility.** Bench chip: page 126 erase-OK but QW0 program PROGERR\|PGSERR; page 124 truly untouched; page 123 in reserve. **Re-blank-check on EVT silicon.** | NON-DEST (read/erase probe) → informs DESTRUCTIVE layout | `secure/src/hw/flash.rs:751-757` |

No dedicated OTP make target; exercised via `make build-hw-factory-provisioning` +
`make factory-status-hw`.

---

## §5 — OPTIGA Trust M V3 lifecycle (DESTRUCTIVE ratchets + NON-DEST bring-up)

Ship-blocker cluster S-1/S-2/S-3. LcsO ratchets are points of no return — sacrificial
parts only. **Prerequisite bug:** the Shielded Connection handshake is still broken
on silicon (5.5), which blocks the first real on-silicon C10 sign (5.6).

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 5.1 | **S-1: F1D0 `Change=ALW` → LcsO=Operational ratchet** + sacrificial-part validation | DESTRUCTIVE | `STATUS.md:326`; `optiga/mod.rs::verify_and_lock`; issues **#24, #73** |
| 5.2 | **S-2: real type-`0x11` trust-anchor pool `{0xE0E8,0xE0E9,0xE0EF}` closure** + device-cert retype boundary (observed `0xE0E3` is a full type-`0x12` cert; retired helper is a no-op) | DESTRUCTIVE (neutralize/ratchet) | `STATUS.md:327`; `optiga-bringup-status.md:26-34`; issues **#16, #19, #21, #25, #26, #86** |
| 5.3 | **S-3: silicon-enforced PIN lockout** — E120 LUC + F1D0 `Execute=LUC`, F1E1 freeze; validate ratchet/reset/limit boundary | DESTRUCTIVE | `STATUS.md:328`; `make optiga-hw-counter-e2e` (partial PASS 2026-04-22); issue **#254** |
| 5.4 | **S-4: sentinel lifecycle F1D5↔F1E1 replacement choice** — design + bench evidence | MIXED | `STATUS.md:333`; issue **#215** |
| 5.5 | **Shielded Connection handshake broken on silicon** — SlaveFinished returns 7-byte error `0a 00 02 08 40 75 d4 00`; `shield.establish` bails `HandshakeFailed`. **Blocks 5.6 and the S-5-analog LA capture.** | NON-DEST (LA debug: capture MasterFinished, read 0xE0C5 SEC counter, cross-check TLS-PRF/CCM-8 AAD) | `optiga-bringup-status.md:64-93`; `red-teaming.md:330-345` |
| 5.6 | **First real on-silicon SPHINCS+C10 sign through the OPTIGA path** — never reached (blocked by 5.5) | NON-DEST | `optiga-bringup-status.md:95-97` |
| 5.7 | **Per-session 2-write throttle / CloseApplication no-response** — root cause unconfirmed (suspected SEC counter 0xE0C5); RST-pulse workaround in tree | NON-DEST | `optiga-bringup-status.md:53-56,99` |
| 5.8 | **OPTIGA PBS rotation (first-boot Phase B):** transport-shield handshake (#443), SetData(E140) wedge timing, E140 rewrite, re-shield-under-FINAL, page-126 program-hostility | DESTRUCTIVE (E140 rewrite = brick-risk) | `first-boot-hardware-bringup.md:122-132`; `optiga/mod.rs::rotate_pbs_to_salted`; `optiga-brick-postmortem.md` |
| 5.9 | **E140 LcsO ratchet ordering** — sacrificial part: Operational E140 authenticates with transport PBS, accepts new PBS via Conf(E140), re-establishes after a cut (ratchet stays factory-side) | DESTRUCTIVE | `first-boot-hardware-bringup.md:161-165`; issue **#73** |
| 5.10 | **OP17 residuals** — no PRL self-heal on unlock (wedge burns page-124), E120 wipe gate, boot-reconcile init, DL-frame validation, verdict-confusion in PIN verify | MIXED | issues **#119, #122, #125, #127**; `optiga-bringup-status.md:57,104` |

---

## §6 — SE050C2 (OEF 0xA201) production-part validation (MIXED)

The final part migrated E2→C2/A201 on 2026-07-20 but **has never run on silicon.**
Several SCP03 paths were fixed 2026-07-21 after being found never-executed.

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 6.1 | **`TODO(C2-silicon)`: SE050C2 AppletConfig fingerprint not captured.** Anti-substitution gate only knows the E2 bench value `0x3F9F`; capture + pin the C2 `AppletConfig` on first bring-up (a C2 run fails the gate loudly until then) | NON-DEST (unauthenticated identity read) | `secure/src/se050_stress/tests/audit.rs:429`; `docs/SE050C2HQ1_Z01SDZ/README.md`; issue **#61** |
| 6.2 | **SCP03 transport→final `PUT KEY` migration on C2 silicon** — two paths that "had never run on silicon" fixed 2026-07-21, still silicon-unvalidated | DESTRUCTIVE (in-place PUT KEY under transport DEK; torn write → dead keyset) | `first-boot-provisioning.md:249-254`; `secure/src/scp03_logic.rs:27-47,789`; issue **#55** |
| 6.3 | **`HW-ASSUME-PUTKEY-ATOMIC` — highest-leverage bench test (ship-blocker).** Scaffold crowbar across the PUT KEY commit window; probe ENC/MAC and DEK independently. A confirmed `ENC/MAC-final + DEK-transport` is a ship-blocker. | DESTRUCTIVE (sacrificial SE050s, Vdd crowbar) | `red-teaming.md:460-503`; `first-boot-hardware-bringup.md:101-120`; issue **#398** |
| 6.4 | **`HW-CONFIRM-PUTKEY-KCV-RESP`** — does the GP applet echo per-key KCVs? If yes, make the 0-length case fail-closed | NON-DEST | `first-boot-provisioning.md:272-276`; issue **#398** |
| 6.5 | **`HW-CONFIRM-PUTKEY-REPUT-IDEMPOTENT` / DEK-liveness** — torn-write safety net not shipped until re-PUT idempotency confirmed | DESTRUCTIVE | `first-boot-provisioning.md:277-292` |
| 6.6 | **SE050 admin credential re-key transport→final** — confirm `SW=0x6986` admin-lockout does NOT trip | DESTRUCTIVE (delete+recreate) | `first-boot-hardware-bringup.md:118-120`; issues **#55, #56** |
| 6.7 | **S-5: SCP03 logic-analyzer bus capture** — Rust round-trip silicon-verified 2026-05-28; the LA capture confirming no `half_E` plaintext on the wire is the only remaining leg | NON-DEST (LA) | `STATUS.md:329`; `se050-silicon-findings.md:60`; issue **#7** |
| 6.8 | **S-6: admin-delete policy on USERID_OBJ** — sacrificial-part silicon verification pending | DESTRUCTIVE | issue **#8** |
| 6.9 | **S-7 lower-severity SE050 items** — close in the S-5/S-6 hardening pass | MIXED | issue **#9** |
| 6.10 | **Boot-time SE050 attempt-counter reconcile leg silently skipped** (`ReadObjectAttributes` policy-gated `SW=0x6986`); regression test fires if a future rev honors the read | NON-DEST | `se050-silicon-findings.md:71-114`; `se050/mod.rs:485` |
| 6.11 | **Five A3-recovery sites** (`reinit`, `authenticate_and_read`, `admin_factory_reset`, duress read/verify, `user_factory_reset`) — on-silicon re-run of `se050-stress-destructive` + `pin-gate-hw-counter-e2e` pending | MIXED | `se050-silicon-findings.md:313-364` |
| 6.12 | **SE050 variant/GetVersion assertion** — expect OEF `0xA201`, fail-closed (anti-substitution) | NON-DEST | issue **#61**; `first-boot-provisioning.md` |
| 6.13 | **Case-2 read bug** — `send_apdu` mangles payload-less reads (`get_version_ext` goes on the wire with no Le) | NON-DEST | issue **#444** |
| 6.14 | **half_E: drop ALLOW_WRITE at first provisioning; user/admin UserID final ship policy** | DESTRUCTIVE | issues **#59, #56, #57** |

Targets: `make se050-stress` / `-destructive`, `make se050-reset-e2e`,
`make flash-hw-se050-rotate-scp03`, `make pin-gate-hw-counter-e2e`.

---

## §7 — First-boot self-provisioning (`rdp2-self-lock`) on-device runbook

Status: **candidate implemented, not production-approved; silicon + protocol-closure
gates pending.** Code: `secure/src/first_boot/{mod,journal,state}.rs`,
`shared/src/lockdown.rs`, `secure/src/hw/{flash,secret_keys}.rs`. **The authoritative
runbook is `docs/provisioning/first-boot-hardware-bringup.md` — follow it, not this
summary.** The full ordered silicon matrix is `first-boot-provisioning.md:208-229`.

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 7.1 | **Whole flow is un-flashable today** — needs a `bench-ship-validation` image (owner sign-off); `mode-production` blocked by `FW_ROLLBACK_PRODUCTION_BLOCKED` + needs `FSBL_VENDOR_PUBKEY`. **Hard prerequisite for every §7 bench item.** | NON-DEST (build config) | `first-boot-provisioning.md:320-338`; issue **#268** |
| 7.2 | **Phase-A confirm-gate (R2.4)** interactive pass on real LCD + 2 buttons — accept (chord→burn), decline (long-left→stays RDP-0), idle; prompt must block with SysTick/IWDG not yet started | MIXED (leadup NON-DEST, burn DESTRUCTIVE) | `first-boot-hardware-bringup.md:88-91`; issue **#34** |
| 7.3 | **Flash/OTP torn-write during first boot** (`QW-ATOMIC`+`OTP-ONEWAY`) + **Phase-B power-cut durability matrix** — journal/salt/two-phase rotation must resume at every step boundary | DESTRUCTIVE | `first-boot-hardware-bringup.md:92,141-150`; issue **#399** |
| 7.4 | **`HW-ASSUME-DHUK-RDP12` + SAES Tier-1 DHUK self-test** — one-shot RDP-1 vs RDP-2 DHUK fingerprint compare; the "per-die DHUK is final" premise Phase B rests on | MIXED (RDP-1 fingerprint NON-DEST; RDP-2 lock DESTRUCTIVE, one-shot) | `first-boot-hardware-bringup.md:135-137`; issue **#33**; `red-teaming.md:621-637` |
| 7.5 | **Factory handoff/receipt (`verify_factory_receipt()`)** — device-side stub; PQ-clean signing authority is an OPEN owner decision (ship-blocker) | NON-DEST (design/owner gate) | `first-boot-provisioning.md:294-318`; issues **#76, #268, #249** |
| 7.6 | **Two ship-profile checks fail-closed until silicon-pinned** — `E0809` (WRP1A) then `E080A` (OEM-lock); flip each const with RM0456 citation + positive bench detection | NON-DEST | `first-boot-provisioning.md:159-190`; `shared/src/lockdown.rs:113-120` |
| 7.7 | **BHK page first-write (Tier-2 Phase 2B) + WRP on page 126 + re-pair-after-BHK-loss** | DESTRUCTIVE | issues **#32, #36, #77, #204**; `dual-se-bhk-e2e` |

Flip-after-bench-passes constant table: `first-boot-hardware-bringup.md:172-186`.

---

## §8 — FSBL / FW-update boot trust chain: fault injection (NEEDS-SILICON)

`verify_signature` is sentinel-hardened; the audits flag the surrounding checks as
single-fault-skippable, with physical-glitch feasibility explicitly needs-silicon.
All are **NON-DEST bench** (a glitcher on the target) unless noted.

| # | Item | Ref |
|---|---|---|
| 8.1 | **F15: FW-update/FSBL FI-asymmetry** — `verify_digest`/`verify_rollback` bare while `verify_signature` hardened; `try_once_flag` outside signed preimage; OTP floor single unvoted read. "Physical-FI feasibility requires silicon confirmation." | `ef-swarm-scan-verification-20260626.md:53-66`; `fw_update/mod.rs:417-451`; `fsbl/src/main.rs:124-136`; issue **#376** |
| 8.2 | **FSBL `verify_images` bare `!=` ⊕ FW-COMMIT bare `if let Err`** = 2-fault firmware-replacement chain; per-boot glitch success-rate on `fsbl/src/verify.rs:41` unproven | `fault-injection-20260625-114309.md:94-172`; `fsbl/src/verify.rs:41`; `cmd_fw_commit.rs:49` |
| 8.3 | **Trusted-display consent-gate glitch (WYSIWYS break)** — how reliably does the `(Button,Press)` discriminant flip Left→Right vs crash? | `fault-injection-20260625-114309.md:176-194`; `ui/confirm.rs:74-87`; `buttons.rs:130-136`; issue **#421** |
| 8.4 | **FSBL non-signature `.ok()?` anti-rollback + BEGIN `verify_manifest` bare match** — prior MEDIUMs re-confirmed still open | `fault-injection-20260625-114309.md:198-242`; `fsbl/src/main.rs:124-128` |
| 8.5 | **`tools/sca` has no confirm-button / `fsbl_verify_images` / `fw_commit` sweep** — suite reports green for the FSBL boot path only because it never exercises it | `fault-injection-20260625-114309.md:388` |
| 8.6 | **On-silicon ERC-7730 descriptor-authority fault campaign** (ship-blocker) + physical NV3007 WYSIWYS campaign | issues **#376, #375, #374** |
| 8.7 | Related still-open physical items: **F3** torn-compaction cap rollback, **F10** BEGIN-cancel resets FI wipe budget, **F16** NSC post-verify response FI, **F8a/b** SE-tunnel desync | `ef-swarm-scan-verification-20260626.md:29-88` |

FSBL RAM constraint to respect: 16 KB, no MSPLIM; `fsbl/src/main.rs:99-107` peaked at
~24.7 KB copying manifest pages → HardFault, now borrows from flash. Any EVT SRAM
base/size change re-opens this. `fsbl/memory-stm32u585.x` is legacy bench geometry —
"do not derive WRP or irreversible ops from this linker script."

---

## §9 — SCA / FI rig campaigns (blocked-on: bench)

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 9.1 | **Full FI fault-sweep** — 14 rainbow harnesses × full width × all fault models (~40 h); harnesses built, only smoke-run | NON-DEST (compute) | `STATUS.md:312`; `tools/sca/fault_sweep_*.py`; `make -C tools/sca c10-sign` |
| 9.2 | **dudect DWT Welch t-test on real U585** (`verify()`/KDF) — no target/artifact yet | NON-DEST | `STATUS.md:366`; issue **#298** |
| 9.3 | **lascar/scared CPA — on-silicon SHA-2 PRF DPA sufficiency** (emulated half done with a software-AES stand-in; on-silicon open) | NON-DEST | `STATUS.md:367,412`; issues **#228, #236** |
| 9.4 | **Signature FI hardening — verify-before-release on the glitch rig** via `sca-trigger` GPIO (PD2), then re-confirm the gate exists in the prod binary | NON-DEST | `red-teaming.md:284-312`; issue **#139** |
| 9.5 | **RNG raw statistical capture on silicon** — U5 raw-noise limitation means NIST-EA capture needs a sacrificial RDP-0/1 unit | NON-DEST (needs low-RDP part) | `red-teaming.md:176-221`; `hardware-assumption-boundary-2026-07-17.md:337-356` |
| 9.6 | **RDP-2 offensive downgrade campaign** — "single highest-leverage unverifiable premise; a success is a ship decision." FaultyCat EMFI + Scaffold voltage. Note: Šimoník thesis shows ~76% PIN-glitch bypass on STM32U5 silicon | DESTRUCTIVE (sacrificial U585s) | `first-boot-hardware-bringup.md:82-87`; `STATUS.md:372-374`; issues **#301, #133** |

**SCA note:** the on-bench LA1010 is digital-only. On-silicon power/EM SCA (9.2/9.3)
needs a ChipWhisperer-Husky / ChipSHOUTER, which is **not yet on the bench**
(`docs/tooling-and-systems.md:95`) — see the shopping thread.

---

## §10 — Platform: TAMP, GTZC, measured-boot, DHUK, PIN lockstep

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 10.1 | **TAMP tamper response never silicon-validated.** `tamp-wipe` forced ON for shipping dual-SE images; driver was at the wrong base (`0x5600_4400`, now `0x5600_7C00`) — unnoticed because log-only. A false ITAMP9 on a noisy EVT rail would wipe the device. | DESTRUCTIVE (glitch/decap triggering) | `hardware-assumption-boundary-2026-07-17.md:357`; `red-teaming.md:550-570`; `secure/src/hw/tamp.rs:126-132`; issues **#391, #47, #75, #81** |
| 10.2 | **TAMP isolation in GTZC2 unfinished** — SECCFGR/TAMP wiring is a documented follow-up; GTZC2 (RTC-domain TAMP/BKP-SRAM) intentionally NOT locked today | NON-DEST | `secure/src/sau.rs:386-388,548`; issues **#50, #70** |
| 10.3 | **`gtzc-enforcement-hw` C3 gap:** it builds *without* `spi1-arduino`, so the SECCFGR2/SPI1-secure bit (the one keeping NS off the trusted display) is NOT covered by the 7/7 receipt | NON-DEST | `secure/src/sau.rs:389-406`; issue **#239** |
| 10.4 | **F2/F3/F4 platform-security silicon items** — IWDG secure, RCC/PWR clock security, TAMPSEC + DBP hygiene | MIXED | issues **#79, #80, #81** |
| 10.5 | **Measured-boot / FSBL fingerprint on silicon** — immutable FSBL + secure-world display verdict confirmed once resource/silicon gates close | NON-DEST | `red-teaming.md:522-525`; `secure/src/measured_boot.rs` |
| 10.6 | **Three-way PIN-attempt + directional boot cross-check** — E120 LUC + page-124 + SE050 UserID; boot reconciliation lacks a **cold-reboot silicon receipt** (only the directional page124/E120 check exists). `make pin-gate-wipe-e2e` is the QEMU analogue to redo on silicon | MIXED | `STATUS.md:336`; `red-teaming.md:347-384`; issues **#200, #119** |
| 10.7 | **DHUK per-die uniqueness at RDP-2 — n=2, unmeasured at RDP2.** Distinct fingerprints seen at RDP-1; no board has ever been at RDP-2. Capture on the self-locked part | DESTRUCTIVE (RDP-2 self-lock is one-shot) | `hardware-assumption-boundary-2026-07-17.md:330-336`; `red-teaming.md:621-637`; issue **#33** |
| 10.8 | **SWAP_BANK / bank-2 mirror** — SWAP_BANK=0, HDP2+SECWM2 over bank-2 FSBL range, stage identical FSBL in both banks' frozen range | DESTRUCTIVE | issues **#42, #43, #44** |
| 10.9 | **USB-C warm-reset topology** — TCPP03 (PB5) is an on-board dev-kit part; if the EVT omits/changes it, the CC-open/dead-battery re-enumeration choreography must be re-derived | NON-DEST | `secure/src/hw/usb_hw.rs:91-100,209-346`; `fwup-transport-hw-iwdg` |

---

## §11 — Firmware-rollback + SCP03-rotation receipts (DESTRUCTIVE, ship-blockers)

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 11.1 | **HIGH-1: SE050 SCP03 published-key rotation ceremony closure** — journaled candidate exists; production closure needs authenticated per-unit handoff/receipt, authenticate-before-rotate rule, old/new/KVN recovery proof, E140 order, **silicon validation** | DESTRUCTIVE | `STATUS.md:300,334`; `red-teaming.md:435-458`; issues **#55, #76, #204** |
| 11.2 | **FW-RB: A/B rollback + anti-rollback root — Draft 1.1 is NO-GO.** Must close its OPEN silicon gates then obtain separately-authorized Section-13 silicon/factory receipts | DESTRUCTIVE (OTP/TAMP/journal on real silicon) | `STATUS.md:325`; `a-b-firmware-rollback-architecture.md`; `fw-rollback-draft12-candidate-2026-07-21.md` |
| 11.2a | OPEN-PIN-HW-1 — attempt-neutral SE050 prep + one-attempt-cut evidence | DESTRUCTIVE | `a-b-firmware-rollback-architecture.md:444-503` |
| 11.2b | OPEN-JRN-HW-1 / -DUR-1 — physical TAMP journal backend + interrupted-marker durability | DESTRUCTIVE | `:169-172,505-546` |
| 11.2c | OPEN-FLASH-HW-1 — SRAM mutation closure, IWDG timing, cache | DESTRUCTIVE | `:698-750` |
| 11.2d | OPEN-ECC-1 — candidate/marker reads + OTP correction attribution | DESTRUCTIVE | `:605-649` |
| 11.2e | OPEN-RAM-1 — immutable FSBL RAM/stack envelope (38,912 B target / 40,960 B ceiling) | NON-DEST (measure) | `:235,746-752` |
| 11.2f | OPEN-OTP-1..3 — OTP physical record format / rollback-key storage / interrupted-cell authority (after the sacrificial master-closure test) | DESTRUCTIVE | `:1064-1370` |

Draft-manifest work is **not implementation-approved** (CLAUDE.md) — no schema is
current authority. Listed for completeness; do not action without owner stage decision.

---

## Related / duplicate aggregations (do not re-derive; keep in sync)

- **`docs/STATUS.md` §A ship-gate table** — the authoritative ship-blocker list
  (FW-RB, S-1..S-7, HIGH-1, Claim 3) with `blocked-on: bench/factory/code` columns.
- **`docs/provisioning/first-boot-hardware-bringup.md`** — the ordered on-silicon
  runbook (§7 here is a pointer to it).
- **`docs/verification/hardware-assumption-boundary-2026-07-17.md`** — the
  epistemology layer: six assumption surfaces, each with a named falsifying silicon
  test. Establishes ARMv8-M/CMSE and OPTIGA/SE050 internals as permanently
  `silicon-E2E`-or-nothing.
- **`docs/security/red-teaming.md`** — the `HW-ASSUME` ledger + rig-bound tests
  (`PUTKEY-ATOMIC`, `QW-ATOMIC`, `OTP-ONEWAY`, `RDP2`, `DHUK-RDP12`, `OEM2-ABSENT`).
- **`docs/audits/external-invariants-20-response-20260704.md`** — 16 PASS / 4 FAIL,
  all FAILs = this deferred silicon ceremony.
- **`docs/security/adversarial-review/silicon-lockdown-adversarial-review.md`** +
  `shared/src/lockdown.rs:10` — the SL1..SLn "reversible-state-mistaken-for-locked" playbook.
- **GitHub Issues** `EthereumPhone/PQ1`, labels `ship-blocker`, `surface:hardware`,
  and the search `silicon` — the live tracker; close with silicon evidence in the
  comment. This index groups those by subsystem; the issues remain the source of truth.

## Make-target quick reference

| Purpose | Target | Status |
|---|---|---|
| DWT-timed sign smoke | `make test-key-speed` | works on any HW build |
| SAES SW + DHUK domain-sep + fingerprint | `make saes-self-test-hw` | RDP-0 (shared constant) |
| Capture **real per-die DHUK** over VCP | `make saes-self-test-hw-rdp1` | burns RDP=0xBB (SWD dies; UART only) |
| Restore RDP-0 after fingerprint | `make saes-self-test-hw-rdp0-regress` | reversible from RDP1 only |
| GTZC NS-access RAZ-fault | `make gtzc-enforcement-hw` | PASSED 7/7 2026-05-20 (see 10.3 gap) |
| OPTIGA shield handshake only | `make flash-hw-optiga-shield-handshake-only` | currently fails (5.5) |
| OPTIGA E120 LUC + PIN cycles | `make optiga-hw-counter-e2e` | partial PASS 2026-04-22 |
| Three-way PIN per-attempt | `make pin-gate-hw-counter-e2e` | no reboot/reconcile coverage |
| 10-wrong-PIN wipe | `make pin-gate-wipe-e2e` | QEMU; redo on silicon (10.6) |
| SE050 stress | `make se050-stress` / `-destructive` | 16/2 PASS; A3 re-run pending |
| LCD bring-up | `make lcd-test-hw` / `make splash-test-hw` | dev board only so far |
| Brown-out + SRAM2 option bytes | `make stm32-harden-opts` | sets BOR_LEV=3 (target ≥4 — 3.7) |
| One-shot RDP-2 self-lock | first-boot only (`program_rdp_level2_and_launch`) | never run |

*End of index. Amend in place — do not fork a parallel silicon-validation doc.*
