# VULN — FW-COMMIT raises anti-rollback floor before the new image is committable (permanent-brick / HIGH availability)

- **Severity:** HIGH (availability / permanent unrecoverable device-DoS). MEDIUM on confidentiality/integrity.
- **Status:** **PARTIAL FIX ONLY.** The 2026-06-30 reorder closes the narrow
  pre-manifest power-loss window, but not the A/B probation failure: raising
  the floor before the new slot proves health excludes the old slot and makes
  try-once rollback nonfunctional. The underlying bitwise OTP tally is also
  invalid on STM32U585 ECC quad-words. Production is compile-blocked; see the
  unapproved Draft 1.1 research candidate in
  [`../a-b-firmware-rollback-architecture.md`](../a-b-firmware-rollback-architecture.md).
- **Component:** firmware-update commit + FSBL boot selection.
- **Root cause:** `secure/src/nsc/cmd_fw_commit.rs` — `otp::bump_to(new_version-1)` ran *before* the new manifest/boot-state were written.
- **Not:** a fund-theft / signature-forgery / auth-bypass issue. Funds are seed-recoverable; not remotely attacker-triggerable.

## Fix applied (2026-06-30)

Reordered the commit sequence so the irreversible OTP rollback-floor bump is the **last** flash
write, and gated it behind a from-flash candidacy re-verification. New order in `cmd_fw_commit.rs::run`:

1. Write the new slot's manifest (`try_once = TRIED`), per-quadword `write_quadword_verified`.
2. Write the boot-state pointer → new slot.
3. **Anti-brick gate:** re-read the just-written manifest *from flash* (`ManifestRef::new(flash_manifest)`)
   and require `verify_structural + verify_crc + verify_digest + verify_rollback(new_rollback_floor)` to
   pass, AND `boot_state::read()` to resolve to the new slot. The strict `verify_rollback(new_rollback_floor)`
   is the keystone — it proves the floor about to be written cannot reject the very slot being committed.
   Any failure aborts **without** bumping OTP (old slot stays bootable) and drops the streaming context.
4. `otp::bump_to(new_rollback_floor)` — **last** irreversible op, only after the new slot is proven a
   valid FSBL candidate. This closes the earlier torn-commit window, but the
   claim that the old slot remains available for try-once revert is false once
   the raised floor makes it ineligible.
5. Drop ctx, `sys_reset`.

**Narrow effect only:** this ordering prevents the floor from retiring the old
slot before any new candidate exists. It is not brick-safe at every torn
window. A launched OTP program can be interrupted/ambiguous, and after a
successful floor bump the old slot is ineligible before the new slot proves
health; the legacy single-candidate selector cannot provide the advertised
try-once fallback.

**Architecture correction:** a complete repair does require coordinated FSBL,
manifest/journal, health, and floor-ownership changes. The earlier
"No FSBL change required" conclusion applied only to the narrow power-loss
sibling and must not be used as the A/B rollback disposition.

**Tests:** the source-order regression test that previously *pinned the vulnerable ordering*
(`negative_commit_bumps_otp_before_writing_new_manifest`) is replaced by
`legacy_commit_bumps_otp_after_manifest_and_boot_state` (asserts manifest-write < OTP and boot-state <
OTP) plus `legacy_commit_reverifies_new_slot_from_flash_before_otp_bump` (asserts the from-flash
`verify_rollback` gate precedes the bump). Full secure host suite: 2145 passed. Secure firmware target builds
clean with `debug-log` both ON and OFF.

## Original finding summary (historical, before the 2026-06-30 reorder)

`CMD_FW_COMMIT` bumps the OTP anti-rollback floor to `new_version - 1` as **step 1**, *before* it
writes the new slot's manifest (step 2, `:175-192`) and updates the boot-state pointer (step 3, `:204`).
A power interruption in the window between the OTP bump and the completion of the manifest write leaves
the device with **no bootable slot**, and the FSBL response to "no valid slot" is `halt()`. With WRP1A-locked
FSBL and production RDP-2, this is an **unrecoverable brick**.

## Original mechanism (historical)

Commit order in `cmd_fw_commit.rs::run`:

1. `otp::bump_to(new_rollback_floor)` where `new_rollback_floor = new_version.saturating_sub(1)`  — **irreversible OTP write** (`:154`).
2. Program the new slot's manifest page (`try_once = TRIED`), 512 quadwords / 8 KB (`:175-192`).
3. Write boot-state → new slot (`:204`).
4. Drop ctx, `sys_reset`.

If power is lost **after step 1 but before step 2 completes** (an OTP program plus an 8 KB flash write —
milliseconds to tens of ms, on *every* update):

- **Old slot** (the currently-running, previously-committed firmware, version `old_version`):
  FSBL `filter_valid` → `verify_rollback(floor)` requires `fw_version > floor`
  (`fsbl/src/main.rs:149`, `fsbl/src/manifest.rs`). With `floor = new_version - 1 ≥ old_version`
  (normal upgrade), `old_version > new_version - 1` is **false → old slot rejected**.
- **New slot**: its manifest is not yet (fully) written → `verify_structural` / `verify_crc` /
  `verify_digest` fail → **new slot rejected**.
- `pick_slot(None, None)` → `None` → `halt()` (`fsbl/src/main.rs:94-96`). No DFU / recovery path;
  FSBL is immutable (WRP1A). Under RDP-2 the slots cannot be re-flashed via SWD → **permanent brick.**

The last statement in the original analysis—"power loss after step 2 is
safe"—was too broad. It only established candidate selectability, not health,
fallback preservation, or OTP-interruption durability.

## Why HIGH (availability)

- Permanent, unrecoverable device destruction, fleet-wide, **no in-field recovery**.
- Triggered by an *ordinary* event (USB unplug / brownout) during the vendor-initiated update flow —
  not an exotic attack. Updates are exactly when users disturb the cable.
- Textbook secure-OTA anti-pattern: never raise the anti-rollback floor before the replacement image is
  committed and selectable.

## Why NOT a theft/forgery HIGH

- Funds are recoverable via the BIP-39 seed on replacement hardware (no value-at-risk loss).
- Not remotely attacker-triggerable: `CMD_FW_BEGIN` requires a vendor-signed manifest (the companion
  cannot forge it) + PIN + a physical install confirm. An attacker can only induce the brick with
  physical power control during the user's own update, and gains nothing but DoS.

## Historical ordering rationale

The code comment at `:143-153` justifies bumping OTP first: "a reset between OTP and flash leaves the
rollback floor raised — the partially-staged slot fails verification on next boot but the rollback gate
still rejects older signed releases." The comment is correct that this preserves anti-downgrade, but it
**understates the consequence**: it omits that the *old* (last-known-good) slot is ALSO rejected by the
raised floor, which is the actual brick.

## Superseded narrow recommendation

The first repair proposed raising the floor only once the new slot was fully
written and selectable:

1. Write the new manifest (`try_once = TRIED`) + boot-state pointer first.
2. `otp::bump_to(new_version - 1)` last (still before `sys_reset`).

That change closed one sibling window but is not the complete fix. Draft 1.1
preserves the PENDING → ATTEMPTED → health → CONFIRMED research
candidate, with the immutable FSBL establishing the security-epoch floor
afterward. It is not implementation-approved; its durable journal/ECC/OTP,
resource, release-policy, factory, and silicon gates remain open and
production-blocking.

## Replacement regression matrix

Exercise every cut across the candidate PENDING → ATTEMPTED → health → CONFIRMED
state machine. Every pre-CONFIRMED cut must preserve and select the already
confirmed fallback; no runtime path may establish the floor. Only a subsequent
immutable-FSBL step may establish `security_epoch - 1` for a CONFIRMED slot.
Torn/ambiguous journal or floor state must decode to the frozen typed recovery
or fail-closed outcome, never silently expose an older floor. Physical
interruption claims remain blocked until the separately authorized silicon
phase.
