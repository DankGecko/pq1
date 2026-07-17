# End-User Device Verification — byte-exact firmware proof at unboxing

**Status: DESIGN (2026-07-17). Nothing here is implemented; work breakdown at
the end.** Companion pieces that already exist: reproducible builds
(`docs/firmware/reproducible-builds.md`), RDP-0 shipping + first-boot RDP-2
self-lock (work-todo #36, `docs/provisioning/first-boot-provisioning.md`),
measured-boot 8-word fingerprint (`docs/security/measured-boot.md`).

## The claim this design delivers

> A user who receives a PQ1 in the mail can **fully verify, byte-for-byte,
> that the device contains exactly the published open-source firmware build**
> — before any secret exists on the device, using ~$5 of commodity hardware
> from an independent supply chain, in under two minutes, with no soldering
> or disassembly.

The core claim is **unconditional on factory honesty** for the firmware bytes:
it does not rest on attestation, certificates, or trusting anyone. It rests on
physics: at RDP-0 the SWD debug port, with the CPU halted at the reset vector,
returns the true contents of every persistent bit on the MCU, and **no
firmware executes while it is read** — so there is nothing that can lie.

## Why this is the only possible shape

Fake firmware flashed in transit has byte-identical *capabilities* to the
genuine build: same flash, same OTP (including SE transport keys), same SEs,
same DHUK once it self-locks. No challenge/response, CA, SE attestation, or
companion protocol can distinguish them **from inside**, because every answer
the genuine firmware can compute, the fake can too. Exactly two asymmetries
exist:

1. **External readout of the persistent state, with the CPU not running**
   (SWD at RDP-0, connect-under-reset). Ground truth; nothing to trust.
2. Code made immutable **before** the adversary's window (factory RDP-2 burn)
   — which moves the trust to the factory ceremony and was rejected as the
   primary mechanism (owner decision 2026-07-14: ship RDP-0, user-verifiable).

PQ1 ships RDP-0, so (1) is available to every user. This document's job is to
make (1) an actual consumer procedure instead of an expert escape hatch.

## User procedure (what the quickstart card says)

1. **Get a verifier probe — NOT from the PQ1 box.** Any CMSIS-DAP/ST-LINK
   compatible SWD probe works: a $4 Raspberry Pi Pico flashed with the
   open-source `debugprobe` UF2 (drag-and-drop, no tools), a CH347 board, an
   ST-LINK clone, or the optional open-hardware PQ1 Verify Cable. The point of
   supply-chain independence: an interdictor of the device parcel does not
   control the probe.
2. **Before powering the device from anything else**, connect the probe to the
   PQ1's USB-C port (SWD is routed on the SBU pins — see hardware section) and
   run the open-source verifier: `pq1-verify` (probe-rs CLI) or the WebUSB
   page. One click.
3. The tool halts the core at the reset vector, dumps **all persistent MCU
   state**, and diffs it against the published reproducible release. Result:
   **green + 8 BIP-39 fingerprint words**, or red with the exact differing
   region.
4. **Unplug (full power removal), then power on normally, keeping the device
   in hand.** The boot screen renders its 8-word measured-boot fingerprint.
   **Compare: screen words == tool words == words published for the release.**
5. Confirm the on-screen "lock device" prompt; the verified firmware then
   performs the RDP-2 self-lock + SE credential rotation (work-todo #36) and
   enters the seed wizard. From this point the verified code is immutable and
   is its own guardian.

A user who skips this gets the weaker companion-app SE genuine-check only
(board-level, does **not** prove firmware) and the quickstart must say so
plainly. Deterrence still generalizes: an interdictor cannot know which units
will be verified, so tampering at scale is detectable at scale.

## Ground-truth dump mechanics

- **Reset-halt without NRST:** attach SWD, set `DHCSR.C_DEBUGEN` +
  `DEMCR.VC_CORERESET`, issue `AIRCR.SYSRESETREQ` → the core halts at the
  reset vector **before executing a single instruction**. (Standard vector
  catch; probe-rs supports it. NRST wiring is therefore not required — two
  SBU pins suffice.)
- It does not matter that VBUS briefly ran whatever firmware was resident
  before the probe attached: the dump reads persistent state *after* the
  halt, and the subsequent power-cycle (step 4) discards all volatile state.
  What the dump shows is exactly what executes after the power-cycle.
- **Coverage — every persistent bit on the U585:**

  | Region | Expected value | Source of truth |
  |---|---|---|
  | Flash, both banks, all pages except 123–127 | byte-exact == published full-flash release image (unused pages erased `0xFF`) | reproducible build artifact |
  | Flash pages 123–127 (per-device state) | blank/erased at ship | ship profile (Phase A re-checks the same) |
  | Option bytes (RDP, TZEN, WRP both banks, BOOT_LOCK, SECWM, BOR, …) | exact published ship profile; **RDP must be `0xAA`** | published ship option-byte profile |
  | OTP area (per-device: OTP master → transport keys) | salted hash matches this unit's factory birth certificate | transparency log (see below) |
  | MCU 96-bit UID | matches birth certificate | transparency log |
  | System memory / engineering bytes | mask ROM, not writable | n/a |
  | Backup domain (RTC backup regs) | volatile — PQ1 has no VBAT battery; cleared by the step-4 power removal | board requirement (see hardware section) |

  There is no other writable persistent store on the MCU. A device that
  arrives **not** at RDP `0xAA`, or with any flash/option-byte/OTP deviation,
  fails loudly → do not use, return it. (This includes a device an attacker
  — or malicious resident firmware — already locked to RDP-2: the dump is
  simply impossible, which *is* the tamper signal.)
- The tool computes the 8-word fingerprint from the dumped active slot via
  the same `sphincs_tz_bip39::firmware_fingerprint_lines` derivation,
  binding the chip it probed to the screen the user reads in step 4.

## Why in-transit malware cannot survive a green result

Suppose the parcel was interdicted and malicious firmware ran on the device
before the user verified. For the attack to persist past step 5 it must live
in some persistent state. Walk the list:

- **MCU flash / option bytes / OTP** — dumped and diffed; any residue is a
  red result. "Self-cleaning" malware that restores genuine bytes before
  shipment has, by construction, left the device genuinely clean: after the
  power-cycle only the verified bytes execute. Extra burned OTP bits are
  one-way and show up as a birth-certificate hash mismatch.
- **RAM** — dead after the step-4 power removal.
- **SE050 / OPTIGA state** (pre-poisoned objects, known transport keys):
  neutralized by the existing first-boot design — Phase B rotates SCP03/admin
  to the BHK axis and OPTIGA PBS to the DHUK+TRNG-salt axis, and the seed
  wizard provisions user objects from scratch. Transport keys being known to
  a transit attacker is already in the threat model (the factory knows them
  too); they die at step 5 before any seed exists. **Design requirement on
  the wizard:** treat all pre-existing SE user-object state as hostile —
  delete/recreate with verified policies, never adopt.
- **The SEs run no attacker code** (SE050 applets are NXP-signed; OPTIGA has
  no user code), so "malware inside the SE" is not a channel.

Conclusion: a green dump + matching on-screen words + user custody from step
2 onward ⇒ the device that enters the seed wizard is running **exactly** the
published build. That is the full-verification claim.

## Required design delta: confirm-gated Phase A

Today's #36 candidate runs Phase A (RDP=0xCC programming) on first boot
unconditionally. Under this design that is wrong twice over: (a) a curious
user who powers the device before verifying would irreversibly destroy their
own ability to verify; (b) a transit attacker could power genuine devices to
lock them (DoS, and it defeats verification of genuine units). **Phase A must
be gated on an explicit trusted-UI confirmation** — boot at RDP-0 shows
"Confirm to lock device — after that verification over SWD not possible
anymore.", and only a
deliberate button sequence proceeds to the lock. An attacker pressing it in
transit yields a device that arrives locked → fails step 3 → rejected. The
gate converts that attack from compromise into a returned unit.

## Verifier tool + hardware trust

- The tool is open source, reproducibly built, and trivially re-implementable
  (its spec is "dump these ranges, diff against these published artifacts") —
  independent implementations are encouraged and expected. Rebuilding the
  firmware from source locally (`make verify-repro`,
  `docs/firmware/reproducible-builds.md` §Independent verification workflow)
  removes even the release-artifact trust.
- A compromised host PC can lie. Mitigations, layered: run from a live USB or
  a phone (WebUSB); cross-check the 8 published fingerprint words on a second
  device — the step-4 screen comparison is independent of the host that ran
  the dump.
- Probe firmware (e.g. Pico `debugprobe`) is open source and user-flashed;
  the probe never sees secrets (there are none on the device yet).

## What this explicitly does NOT prove (honest boundary)

Firmware verification ≠ device verification. Out of scope, with their
mitigating layers:

1. **Hardware implants around a genuine MCU** (e.g. a logger on the LCD SPI
   bus capturing the seed words during the wizard, or a button injector).
   The firmware is exactly genuine; the board is not. Layer: tamper-evident
   packaging/case, published board photos for visual comparison, and the SE-CA
   genuine-check; targeted per-unit hardware implants remain the residual, as
   they are for every wallet vendor.
2. **A counterfeit board with an SWD-emulating fake "MCU" + the victim unit's
   transplanted genuine SEs**, serving genuine bytes over the debug port while
   running attacker code elsewhere. Cost: custom hardware per unit plus
   destructive transplant. Layers: birth-certificate UID↔SE binding in the
   transparency log, SE-CA check, tamper evidence, case design. Accepted
   residual at this cost tier.
3. **ST silicon itself** (mask ROM, RDP enforcement). Inherited, as by every
   STM32 product.

The previous companion-only "CA in the SEs" idea proves only chip
genuineness — it is kept (it kills clone/counterfeit boards and anchors the
transparency log) but it is **not** the firmware proof; this procedure is.

## Hardware + factory requirements

- **Route SWDIO/SWCLK to USB-C SBU1/SBU2** on the production board (unused by
  USB 2.0; add ESD protection). No NRST needed (vector catch). After the
  step-5 RDP-2 lock the debug port is silicon-dead, so the routing is inert
  for the device's whole life after unboxing — zero attack surface added.
  Fallback if SBU routing fails review: an accessible pogo-pad footprint, at
  the cost of the "one cable" UX.
- **No VBAT retention** on the production board (no coin cell / supercap on
  the backup domain), so the step-4 power removal fully clears volatile state.
- **Factory birth certificate + transparency log:** per unit, factory HSM
  signs `(MCU UID, salted OTP-content hash, SE cert public keys, ship
  option-byte profile id, firmware release hash)` into an append-only public
  log. The verifier checks the per-device rows against it; the companion's
  SE-CA activation check cross-references the same entry. Note the dependency
  split: the *firmware* claim needs no log; the log covers per-device OTP,
  clone deterrence, and overbuild accounting (work-todo #22's manifest slots
  in here unchanged).

## Work breakdown

1. `pq1-verify` CLI on probe-rs: reset-halt, full dump, diff vs release
   artifact + ship option-byte profile, fingerprint-word output. (The repo
   already drives probe-rs; this is host tooling, no firmware change.)
2. WebUSB/WebHID browser variant of (1) with guided UX.
3. Confirm-gated Phase A (trusted-UI "verify or lock" screen) in
   `secure/src/first_boot/` — the one firmware change this design requires.
4. Seed-wizard SE-state hostility rule (delete/recreate, never adopt) —
   verify current wizard behavior, close any gap.
5. Production board: SBU↔SWD routing + ESD + no-VBAT requirement into the
   hardware spec.
6. Birth-certificate signing + transparency log service; fold into the #22
   factory-manifest design.
7. Quickstart card + docs: the 5-step procedure, the "skipping this = weaker
   guarantee" statement, supported probe list.
8. Optional open-hardware PQ1 Verify Cable (nice-to-have; commodity probes
   are the security story).
