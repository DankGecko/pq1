//! CMD_FW_COMMIT — finalize a staged update.
//!
//! Runs the heavyweight checks that BEGIN could only partially do:
//!
//!   1. Drain the context (or bail if there isn't one).
//!   2. Confirm `received_*_len == expected_*_len`.
//!   3. Re-hash the written images from flash and compare against the
//!      manifest's signed hashes. Any mismatch → abort.
//!   4. Display the new measurement (8 BIP-39 words) + "Confirm
//!      update?" prompt on the OLED. Wait for long-right.
//!   5. On confirm: write the target manifest page (`try_once = TRIED`),
//!      point the boot-state page at the new slot, re-verify from flash
//!      that the new slot is a valid FSBL candidate, THEN bump the OTP
//!      rollback floor LAST (irreversible — kept last so a torn commit
//!      reverts to the old slot instead of bricking), and reset.
//!   6. On cancel: drop the context; the inactive slot stays erased.

use fw_manifest::{ManifestRef, MANIFEST_SIZE, TRY_ONCE_TRIED};
use sphincs_tz_shared::NscStatus;

use super::state::{peek_state, FW_UPDATE};
use super::{GatewayArgs, HandlerGuard};
use crate::fw_update::{self, verify::ImageCheckError};
use crate::hw::{boot_state, flash, otp};
use crate::ui;

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. The body
/// touches the static-mut `FW_UPDATE` and OTP/flash programming
/// primitives; preconditions for each are documented at the call site.
pub(super) unsafe fn run(_args: &GatewayArgs) -> u32 {
    let _busy = HandlerGuard::enter();

    // PIN gate.
    if peek_state(|s| s.pin_verified.check_sentinel()) != crate::fi::OK_SENTINEL {
        return NscStatus::NotInitialized as u32;
    }

    // SAFETY: category 5 — read-only borrow of `static mut FW_UPDATE`.
    // The non-reentrant dispatcher + `HandlerGuard` above mean no
    // other code path can mutate this slot while we hold `ctx_ref`.
    let ctx_ref = unsafe { (*core::ptr::addr_of!(FW_UPDATE)).as_ref() };
    let Some(ctx) = ctx_ref else {
        return NscStatus::FwUpdateBadState as u32;
    };

    // Re-hash + compare. A successful verify_images proves the bytes
    // streamed into the inactive slot match the vendor-signed manifest
    // the user already confirmed at BEGIN.
    let manifest = ManifestRef::new(&ctx.manifest_bytes);
    if let Err(e) = fw_update::verify::verify_images(ctx, &manifest) {
        // Glitch-resistance (audit: FW-COMMIT single-fault bypass). A
        // mismatch means the slot's bytes do NOT match the confirmed
        // manifest — flash corruption (brown-out) OR an attacker trying
        // to land a fault on the (now FI-hardened) `verify_images`
        // binding. DROP the streaming context either way: previously it
        // was left intact with no failure counter, so a glitch rig could
        // re-issue CMD_FW_COMMIT indefinitely — zero user interaction per
        // attempt — until a fault landed and an unsigned image committed.
        // With the context dropped, a retry requires a fresh CMD_FW_BEGIN,
        // which re-runs the F-7 manifest-signature verify AND the
        // trusted-display install confirm (a physical button press) before
        // re-streaming every chunk. Each glitch attempt is now a full,
        // user-gated re-BEGIN + re-stream — not a tight in-place loop.
        //
        // We deliberately do NOT arm the admin-wipe here (unlike BEGIN's
        // bad-signature path): a verify_images mismatch has a *benign*
        // cause — flash corruption on a flaky USB transfer / brown-out —
        // so wiping the user's wallet on a COMMIT mismatch would brick it
        // on bad luck. The context drop is the bound; it carries no
        // destructive false-positive.
        //
        // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`
        // under the non-reentrant dispatcher + `HandlerGuard`. The dropped
        // `FwUpdateCtx` zeroizes its bookkeeping via `ZeroizeOnDrop`. The
        // `ctx`/`manifest` borrows are not used after this point — we
        // return immediately below.
        unsafe {
            *core::ptr::addr_of_mut!(FW_UPDATE) = None;
        }
        secure_log!(
            "[S][fwup] COMMIT verify_images FAIL ({:?}) — streaming context dropped",
            e
        );
        return match e {
            ImageCheckError::LengthMismatch | ImageCheckError::StreamingHashMismatch => {
                NscStatus::FwUpdateBadChunk as u32
            }
            ImageCheckError::SecureMismatch | ImageCheckError::NonsecureMismatch => {
                NscStatus::FwUpdateBadImage as u32
            }
        };
    }

    // No user prompt at COMMIT — finding A moved that to CMD_FW_BEGIN
    // (see fw_update::confirm_install). If `verify_images` above
    // succeeded, the bytes streamed into the inactive slot match the
    // manifest's signed hashes — the same hashes whose fingerprint
    // the user already confirmed at BEGIN — so we have everything we
    // need to commit. A `verify_images` failure already returned
    // FwUpdateBadImage/BadChunk above; COMMIT only reaches here on a
    // bit-perfect verified install.

    // Transport e2e gate (finding #25 / make fwup-transport-hw): the
    // over-USB transport test wants to validate the FULL state machine
    // + verify_images on real bytes-from-host, but MUST stop here —
    // the OTP rollback bump and sys_reset below are irreversible and
    // would brick a reflashable bench chip. Under `fwup-transport-e2e`
    // we drop the streaming ctx (zeroizing via ZeroizeOnDrop) and
    // return Ok WITHOUT bumping OTP / writing the manifest / writing
    // boot-state / resetting. The host test interprets Ok-without-
    // reset as PASS. Fenced out of mode-production (see nsc/mod.rs).
    #[cfg(feature = "fwup-transport-e2e")]
    {
        secure_log!("[S][fwup-transport-e2e] verify_images PASS — stopping before OTP/reset");
        // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`
        // under the non-reentrant dispatcher. The dropped value's
        // ZeroizeOnDrop wipes the manifest copy and running hashers.
        unsafe {
            *core::ptr::addr_of_mut!(FW_UPDATE) = None;
        }
        return NscStatus::Ok as u32;
    }

    // -- Commit -----------------------------------------------------

    let inactive: flash::Slot = ctx.inactive.into();
    let new_version = manifest.fw_version();

    // The OTP rollback floor must land at `new_version - 1`, NOT
    // `new_version`. `verify_rollback` (run by both FSBL at boot and
    // BEGIN) accepts a manifest only when `fw_version > floor` (strict),
    // so a floor equal to the just-installed version would make FSBL
    // reject THIS slot on the next boot (`V > V` is false) and brick the
    // device, while a floor of `V - 1` lets V boot yet still rejects
    // every release `<= V - 1` (full anti-downgrade). We derive the
    // floor from the SIGNED `fw_version`, never from the manifest's
    // unsigned `boot_counter_snap` field: trusting that field would let
    // a hostile companion lower the floor at BEGIN and re-open a
    // downgrade window. `saturating_sub` is defensive — `new_version >= 1`
    // always holds here (BEGIN's `verify_rollback` already rejected
    // `fw_version <= floor`, and `floor >= 0`).
    let new_rollback_floor = new_version.saturating_sub(1);

    // ANTI-BRICK ORDERING (docs/VULN-fwcommit-otp-before-commit-brick.md).
    // The irreversible OTP rollback-floor bump is the LAST flash write in
    // this handler, performed only AFTER the new slot's manifest + the
    // boot-state pointer are durably written and re-verified from the
    // committed state (steps 1-3 below). The previous ordering bumped OTP
    // FIRST; a power-loss between that bump and the manifest write floored
    // out the OLD (last-known-good) slot while the NEW slot was not yet a
    // valid candidate, leaving FSBL with NO bootable slot -> `halt()` ->
    // permanent brick (production RDP-2 + WRP1A-locked FSBL = no in-field
    // recovery). With the bump LAST, any power-loss before it lands leaves
    // the old slot bootable: FSBL keeps booting it (or reverts to it via
    // the try-once + boot-state path), so a torn commit is at worst a
    // lost-and-retried update, never a brick. The narrow downgrade window
    // this opens (floor stays old until the final write) is immaterial: a
    // torn commit reverts to the SAME old firmware (not an older signed
    // release), and forcing a real downgrade would need a validly-signed
    // older image + PIN + physical confirm + precise power timing — a far
    // higher bar than "cause a power blip", and strictly less bad than an
    // unrecoverable brick.

    // 1. Write the target manifest page. The try_once_flag in the
    //    signed manifest should have been COMMITTED; we re-write it
    //    as TRIED here because the slot has not yet confirmed it
    //    boots cleanly. FSBL on the next reset sees TRIED + our
    //    matching boot-state entry and can revert if the slot fails
    //    to set "committed".
    let mut manifest_copy = ctx.manifest_bytes;
    manifest_copy[fw_manifest::OFF_TRY_ONCE] = TRY_ONCE_TRIED;
    // Recompute CRC since we mutated a byte.
    let new_crc = fw_manifest::crc32_ieee(&manifest_copy[..fw_manifest::OFF_CRC32]);
    manifest_copy[fw_manifest::OFF_CRC32..].copy_from_slice(&new_crc.to_be_bytes());

    // Program the manifest as 512 consecutive QWs (8 KB / 16 B).
    let manifest_addr = flash::manifest_addr(inactive);
    for qw in 0..(MANIFEST_SIZE / 16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&manifest_copy[qw * 16..qw * 16 + 16]);
        // SAFETY: `write_quadword_verified` is `unsafe fn` (bank-2
        // flash mutation, irreversible per-page). Precondition: the
        // target page lives in the inactive slot's manifest region —
        // `manifest_addr(inactive)` derives the base from
        // `ctx.inactive`, which is the slot BEGIN erased. Each call
        // here advances `qw * 16` within that erased page span, so we
        // are programming only pre-erased flash.
        if unsafe {
            flash::write_quadword_verified((manifest_addr + (qw * 16) as u32), &buf)
        }
        .is_err()
        {
            return NscStatus::FwUpdateFlashError as u32;
        }
    }

    // 2. Point the boot-state page at the new (tried) slot. Written only
    //    after the manifest is fully programmed (above), so the on-disk
    //    pointer can never reference a half-written manifest. Still BEFORE
    //    the OTP bump (step 4): both slots stay valid through this write,
    //    so a power-loss here lets FSBL revert to the old slot.
    let new_boot_state = boot_state::BootState {
        active_slot: inactive,
        last_good_version: new_version,
    };
    // SAFETY: `boot_state::write` is `unsafe fn` because it programs
    // the boot-state flash page. The page lives outside both slot
    // regions and is owned exclusively by the boot-state driver; we
    // call it once, just after the manifest has been programmed, so
    // the on-disk pointer can never reference a half-written manifest.
    if unsafe { boot_state::write(&new_boot_state) }.is_err() {
        return NscStatus::FwUpdateFlashError as u32;
    }

    // 3. Anti-brick gate: PROVE, from the bytes physically in flash, that
    //    the new slot is now a valid FSBL candidate UNDER the floor we are
    //    about to write — BEFORE the irreversible OTP bump. The per-
    //    quadword `write_quadword_verified` above already read each QW back,
    //    so re-running the manifest's own structural / CRC / digest checks
    //    here validates the assembled whole, and the strict
    //    `verify_rollback(new_rollback_floor)` is the keystone: it confirms
    //    `fw_version > floor` still holds for the just-committed slot, so the
    //    floor we write next cannot reject the very slot we are committing.
    //    We also confirm the boot-state pointer resolves to the new slot.
    //    Any failure aborts WITHOUT bumping OTP — the old slot stays
    //    bootable, so even the abort path is brick-safe.
    {
        // SAFETY: `manifest_addr` is the 8 KB memory-mapped manifest page of
        // the inactive slot, fully programmed just above and not mutated
        // concurrently (non-reentrant dispatcher + `HandlerGuard`). The cast
        // yields a shared reference to readable flash for the verify only;
        // `ManifestRef` reads, never writes.
        let flash_manifest: &[u8; MANIFEST_SIZE] =
            unsafe { &*(manifest_addr as *const [u8; MANIFEST_SIZE]) };
        let committed = ManifestRef::new(flash_manifest);
        let manifest_ok = committed.verify_structural().is_ok()
            && committed.verify_crc().is_ok()
            && committed.verify_digest().is_ok()
            && committed.verify_rollback(new_rollback_floor).is_ok();
        let pointer_ok = matches!(
            boot_state::read(),
            Ok(bs) if bs.active_slot == inactive && bs.last_good_version == new_version
        );
        if !manifest_ok || !pointer_ok {
            // No OTP bump has happened: the old slot still boots. Drop the
            // streaming context so a retry goes through a fresh, user-gated
            // BEGIN (which re-erases + re-streams the inactive slot).
            // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`
            // under the non-reentrant dispatcher + `HandlerGuard`.
            unsafe {
                *core::ptr::addr_of_mut!(FW_UPDATE) = None;
            }
            secure_log!(
                "[S][fwup] COMMIT pre-OTP re-verify FAIL — aborting before rollback-floor bump (old slot stays bootable)"
            );
            return NscStatus::FwUpdateFlashError as u32;
        }
    }

    // 4. Raise the anti-rollback floor — the FINAL, irreversible flash op
    //    before reset (see the ANTI-BRICK ORDERING note above). Doing this
    //    LAST is what makes a torn commit recoverable rather than bricking.
    // SAFETY: `otp::bump_to` is `unsafe fn` because it programs OTP one-way
    // (irreversible). Precondition: the new slot's manifest + boot-state are
    // durably written and were just re-verified from flash as a valid FSBL
    // candidate under `new_rollback_floor`.
    if let Err(e) = unsafe { otp::bump_to(new_rollback_floor) } {
        // The new slot is fully written and boot-state points at it, but the
        // floor could not be raised. Both slots remain valid, so FSBL reverts
        // to the old slot (try-once) — no brick. Surface the error and drop
        // the context.
        // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`.
        unsafe {
            *core::ptr::addr_of_mut!(FW_UPDATE) = None;
        }
        return match e {
            otp::OtpError::OutOfBudget => NscStatus::FwUpdateOtpExhausted as u32,
            _ => NscStatus::FwUpdateFlashError as u32,
        };
    }

    // F10: the install is now fully committed (OTP bumped, manifest written,
    // boot-state points at the new slot). This is the ONLY place the
    // manifest-verify-failure wipe budget is cleared — a completed, user-
    // confirmed update earns honest users a fresh budget, while a BEGIN→cancel
    // loop (which never reaches here) can no longer reset it. Non-fatal if the
    // flash erase inside fails (worst case: a few stale failures carry over,
    // still bounded by the threshold).
    super::cmd_fw_begin::reset_verify_failure_tally();

    // 5. Drop the context (zeroize manifest bytes + running hashes).
    // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`
    // under the non-reentrant dispatcher. The dropped `FwUpdateCtx`'s
    // ZeroizeOnDrop impl wipes the manifest copy and IncrementalSha256
    // running state.
    unsafe {
        *core::ptr::addr_of_mut!(FW_UPDATE) = None;
    }

    // 6. Reboot into the new firmware with automatic USB re-enumeration.
    //    Does not return.
    //
    // The OTP rollback floor is already bumped + the new manifest is
    // written with `try_once = TRIED` + boot-state points at the new
    // slot, so a `sys_reset` boots the new firmware. `cc_open_then_reset`
    // holds the USB-C CC lines open long enough that the host's typec
    // layer registers a real detach, THEN resets — so the post-reset
    // dead-battery Rd reads as a fresh attach and the device
    // re-enumerates with NO physical replug (task #26; the bare
    // `sys_reset` left the host port stuck because VBUS stays asserted).
    // Re-enumeration latency is ~20-25 s (mostly device boot); the OLED
    // shows "reconnecting" across it. The companion app simply waits for
    // the device to come back.
    ui::show_status("Update OK", "reconnecting...");
    #[cfg(feature = "stm32u585")]
    unsafe {
        crate::hw::usb_hw::cc_open_then_reset();
    }
    // QEMU / non-hw fallback — sys_reset works cleanly there.
    #[cfg(not(feature = "stm32u585"))]
    cortex_m::peripheral::SCB::sys_reset();
}
