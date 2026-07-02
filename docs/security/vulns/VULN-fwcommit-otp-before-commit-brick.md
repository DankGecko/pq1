# VULN — FW-COMMIT raises anti-rollback floor before the new image is committable (permanent-brick / HIGH availability)

- **Severity:** HIGH (availability / permanent unrecoverable device-DoS). MEDIUM on confidentiality/integrity.
- **Status:** **FIXED 2026-06-30** (working tree). Found 2026-06-29.
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
   valid FSBL candidate. On error: drop context, surface `FwUpdateOtpExhausted`/`FwUpdateFlashError`; the
   old slot remains bootable (FSBL try-once revert) — no brick.
5. Drop ctx, `sys_reset`.

**Why this is brick-safe at every torn window:** the OTP floor is raised only after both the new manifest
and the boot-state are durable and re-verified. A power-loss *before* the bump leaves both slots valid, so
FSBL boots/falls back to the old (last-known-good) slot — at worst a lost-and-retried update, never a brick.

**Residual downgrade window (accepted):** between the boot-state write and the OTP bump the floor is still
old. This is immaterial — a torn commit reverts to the *same* old firmware (not an older signed release),
and forcing an actual downgrade would require a validly-signed older image + PIN + physical confirm + precise
power timing, a far higher bar than "cause a power blip" and strictly less bad than an unrecoverable brick.

**No FSBL change required.** The fix is contained to the secure-world COMMIT handler; the WRP1A-locked FSBL
trust root is untouched.

**Tests:** the source-order regression test that previously *pinned the vulnerable ordering*
(`negative_commit_bumps_otp_before_writing_new_manifest`) is replaced by
`negative_commit_bumps_otp_last_after_manifest_and_boot_state` (asserts manifest-write < OTP and boot-state <
OTP) plus `negative_commit_reverifies_new_slot_from_flash_before_otp_bump` (asserts the from-flash
`verify_rollback` gate precedes the bump). Full secure host suite: 2145 passed. Secure firmware target builds
clean with `debug-log` both ON and OFF.

## Summary

`CMD_FW_COMMIT` bumps the OTP anti-rollback floor to `new_version - 1` as **step 1**, *before* it
writes the new slot's manifest (step 2, `:175-192`) and updates the boot-state pointer (step 3, `:204`).
A power interruption in the window between the OTP bump and the completion of the manifest write leaves
the device with **no bootable slot**, and the FSBL response to "no valid slot" is `halt()`. With WRP1A-locked
FSBL and production RDP-2, this is an **unrecoverable brick**.

## Mechanism (traced)

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

Power loss *after* step 2 (manifest fully written) is safe: the new slot is a valid candidate and
`pick_slot` selects it on the next boot even though boot-state still points at the old slot (it picks the
highest valid `fw_version`, and the TRIED + stale-boot-state case does not trigger the revert).

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

## The current ordering is deliberate — fix needs a conscious change

The code comment at `:143-153` justifies bumping OTP first: "a reset between OTP and flash leaves the
rollback floor raised — the partially-staged slot fails verification on next boot but the rollback gate
still rejects older signed releases." The comment is correct that this preserves anti-downgrade, but it
**understates the consequence**: it omits that the *old* (last-known-good) slot is ALSO rejected by the
raised floor, which is the actual brick.

## Recommended fix

Raise the floor only once the new slot is fully written and selectable:

1. Write the new manifest (`try_once = TRIED`) + boot-state pointer first.
2. `otp::bump_to(new_version - 1)` last (still before `sys_reset`).

A momentary post-commit downgrade window on power-loss is strictly less bad than an unrecoverable brick,
and exploiting it would require physical access **plus** a validly-signed older image (a far higher bar
than "cause a power blip"). Alternatively, exempt the last-known-good committed slot from the rollback
floor (treat it as a permanent fallback) until the newly-installed slot self-confirms alive.

## Regression test idea

Simulate the torn-commit states in the FW-update e2e (QEMU): (a) OTP bumped, manifest absent → assert the
old slot still boots (post-fix), and (b) manifest written, boot-state absent → assert the new slot boots.
Pre-fix, case (a) must reproduce the both-slots-invalid → halt brick.
