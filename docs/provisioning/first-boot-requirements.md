# First-boot self-provisioning — device-side requirements

Status: normative requirements for the `rdp2-self-lock` flow (2026-07-21).
Companion to [`first-boot-provisioning.md`](first-boot-provisioning.md) (the
operator/field runbook, factory⇄device split, error codes, and silicon
runbook). This document states only **what the on-device flow must do** — it
grants no production authority; the handoff/receipt, authenticate-before-rotate,
recovery-adequacy, E140-ordering, and silicon gates tracked there remain OPEN.

Requirement keywords are RFC-2119 (**MUST / MUST NOT / SHOULD**).

---

## 0. Scope and division of labor

The device-side flow performs exactly **one MCU-irreversible action** (the
RDP-2 burn) and a set of **secret rotations** off the factory transport
keysets. Everything else — the entire option-byte profile *except RDP*
(TZEN, SECWM, SECBOOTADD0, **WRP1A over the FSBL pages**, BOR, OEM locks),
the OTP-master burn, and all SE-internal structure and irreversible locks —
is staged at the **factory** while the device is at RDP-0 and therefore
user-verifiable over SWD before first power.

Rationale (invariant #10): the user verifies *state*, not code promises. WRP
is reversible at RDP-0, so factory staging costs nothing; deferring the WRP
write into first boot would create a fault-injection / power-cut window in
which RDP-2 could burn with the FSBL unprotected — an unrecoverable forfeit
of the verify-once guarantee. The device therefore **verifies** the staged
lock and **only then** welds it shut.

## 1. Placement in the boot sequence

- **R1.1** The entire flow MUST run before the seed wizard, before the first
  PIN entry, and before any wallet secret exists on the device.
- **R1.2** Phase A MUST run at earliest secure boot, before SE traffic, USB
  bring-up, or any per-device flash write.
- **R1.3** The flow MUST be a no-op on every boot after completion: RDP
  already at Level 2 → skip Phase A; page-127 journal shows ALL_DONE → skip
  Phase B. (Idempotence is the resume mechanism, not an optimization.)

## 2. Phase A — verify the ship state, then self-lock (pre-lock, MCU point of no return)

- **R2.1 (verify, don't set).** Phase A MUST read back and verify the full
  published ship option-byte profile (`shared/src/lockdown.rs`
  `SHIP_PROFILE_U585`): TZEN=1, SECWM1/2, SECBOOTADD0, **WRP1A covering the
  FSBL pages**, OEM-locks state. The flow MUST NOT program WRP or any option
  byte other than RDP itself. A missing or wrong WRP1A is a hard fail, never
  something Phase A "fixes" — a unit that reaches the field unstaged is not a
  genuine ship unit.
- **R2.2 (blank per-device pages).** Pages 123–127 MUST be blank-checked
  before locking. A pre-planted page-127 journal would spoof "already done"
  and a pre-planted salt would make the final OPTIGA PBS predictable.
- **R2.3 (OTP master present).** The factory OTP-master burn MUST be
  confirmed present (it is the root of the transport keysets Phase B
  authenticates against). Absent → fail before the lock.
- **R2.4 (confirm gate — owner decision 2026-07-17, not yet implemented).**
  The RDP burn MUST NOT run automatically on first power. The trusted UI
  MUST display an explicit "Confirm to lock device — after that verification
  over SWD not possible anymore." prompt and wait for a deliberate on-device
  button sequence. Until confirmed the device MUST stay at RDP-0, touch no
  SE/USB/journal state, and re-enter the same prompt on every boot.
- **R2.5 (the burn).** Only after R2.1–R2.4 pass MAY the flow program
  RDP=0xCC and issue `OBL_LAUNCH` (which resets the MCU). If the launch
  fails to reset, the flow MUST park (never continue executing below RDP-2).
- **R2.6 (fail unlocked).** Every Phase-A fault MUST halt with the unit
  still at RDP-0 — returnable and reflashable. Phase A MUST NOT convert a
  bad flash, bad profile, or failed burn into an RDP-2 brick.
- **R2.7 (ordering, invariant #10).** R2.1 before R2.5 is the load-bearing
  order: WRP verified-set strictly before RDP-2. No refactor may reorder,
  weaken, or make conditional the WRP1A check on any path that can reach the
  RDP write.

## 3. Phase B — journaled secret rotation (post-lock, per-die DHUK now final)

All Phase-B steps MUST be recorded commit-LAST in the append-only page-127
journal and MUST be resumable across resets (§4). Order:

- **R3.1 BHK first-write.** Generate the BHK from the hardware TRNG, store
  DHUK-wrapped on page 126. The write MUST erase-and-reprovision
  (anti-pre-plant) and MUST be journal-gated so a torn write is retried, not
  trusted.
- **R3.2 SE050 SCP03 rotation.** Transport → final (BHK-rooted) via GP
  `PUT KEY`, key blocks wrapped under the transport DEK. Two-phase: the
  FINAL keyset MUST be confirmed live (successful re-establish) before the
  transport keyset is considered dead.
- **R3.3 SE050 admin credential re-key.** Transport → final (BHK-rooted),
  delete + recreate, same two-phase confirm discipline.
- **R3.4 OPTIGA PBS rotation.** Persist a fresh TRNG salt to the page-127
  journal **before** deriving or writing the final PBS (DHUK + salt), then
  rotate via shielded `SetData(E140)`, two-phase confirm. The salt record
  MUST be reserved in full (data QWs + completion markers) before the first
  program command; insufficient journal room fails closed with no write.
- **R3.5 Finalize.** Mark ALL_DONE, then continue into normal boot → seed
  wizard.
- **R3.6 (rotation only).** Phase B MUST NOT create SE objects/policies,
  ratchet any SE lifecycle state (LcsO, E140 metadata, F1D0), burn OTP, or
  touch any option byte. It rotates the pairing secrets it inherits —
  nothing else.

## 4. Power-loss and resume requirements

- **R4.1** Every step MUST be idempotent between completed flash quad-word
  programs; completion markers are written only after the step's effect is
  durable (commit-LAST).
- **R4.2** On a resume boot the flow MUST re-scan the journal, skip every
  completed step, and continue at the first incomplete one. Per-SE resume
  MUST probe the FINAL keyset first, then the TRANSPORT keyset; success on
  either determines where the step restarts.
- **R4.3** The recovery budget is finite (one 512-QW page). When the journal
  cannot hold a full pending record plus its completion markers, the flow
  MUST fail closed without writing.
- **R4.4** The UI MUST show "DO NOT POWER OFF" during Phase A's burn window
  and all of Phase B; a resume MUST display "RECOVERING / DO NOT POWER OFF",
  not an error.

## 5. Failure discipline

- **R5.1** Unrecoverable states fail **closed**, halting with a stable
  `EXXXX` code on the LCD (`first_boot/state.rs` `FirstBootError`; code
  table in [`first-boot-provisioning.md`](first-boot-provisioning.md)).
  Codes MUST remain stable across firmware versions.
- **R5.2** Class boundary: Phase-A faults (`0x080x`) halt **unlocked**;
  Phase-B faults (`0x081x`+) occur after the lock and route to RMA. No fault
  path may leave the device continuing into normal boot with a
  partially-rotated keyset.

## 6. Things the flow MUST NOT do (summary)

- Program or modify WRP or any option byte other than RDP (Phase A) — §2.1.
- Write anything into the FSBL flash range, ever (invariant #10).
- Burn RDP-2 before the WRP1A + blank-page + OTP-master + confirm-gate
  checks all pass — §2.7.
- Perform SE-internal irreversible provisioning (factory scope) — §3.6.
- Run under any dev/test feature: `rdp2-self-lock` is production-only,
  implies `bhk`, requires `dual-se`, and is compile-fenced against
  `debug-log` / `e2e-test` / `mock-se` (`nsc/mod.rs`; check with
  `make build-rdp2-self-lock`).
- Enter the seed wizard, accept a PIN, or expose USB before ALL_DONE.

## 7. Traceability

| Requirement | Code |
|---|---|
| R1.x boot wiring | `secure/src/main.rs` |
| R2.x Phase A | `secure/src/first_boot/mod.rs` `run_pre_lock_and_maybe_lock` |
| R2.1 profile comparators | `shared/src/lockdown.rs` |
| R2.5 RDP write path | `secure/src/hw/flash.rs` |
| R3.x state machine | `secure/src/first_boot/state.rs` |
| R4.x journal codec | `secure/src/first_boot/journal.rs` |
| R3.2–R3.4 SE rotations | `secure/src/se050/{mod,scp03}.rs`, `secure/src/optiga/mod.rs` |
| R2.4 confirm gate | **not yet implemented** — current code burns immediately after `ui::init()` |

Gaps between this document and the code are defects in one or the other;
R2.4 is the one known intentional gap as of 2026-07-21.
