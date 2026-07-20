//! CMD_FW_COMMIT — legacy V1 staged-update finalizer (bench only).
//!
//! **Production-blocked:** this handler predates Draft 1.1. It advances the
//! rejected unary OTP floor before candidate health and therefore does not
//! provide the promised A/B rollback contract. The source is retained for
//! pre-production diagnosis; `stm32u585 + mode-production` and all factory
//! images fail compilation until the reviewed replacement is implemented.
//!
//! Runs the heavyweight checks that BEGIN could only partially do:
//!
//!   1. Drain the context (or bail if there isn't one).
//!   2. Confirm `received_*_len == expected_*_len`.
//!   3. Re-hash the written images from flash and compare against the
//!      manifest's signed hashes. Any mismatch → abort.
//!   4. Display the new measurement (8 BIP-39 words) + "Confirm
//!      update?" prompt on the NV3007 LCD. Wait for long-right.
//!   5. On confirm: write the target manifest page (`try_once = TRIED`),
//!      point the boot-state page at the new slot, re-verify from flash
//!      that the new slot is a legacy FSBL candidate, then attempt the
//!      unsupported unary OTP bump and reset. This ordering narrows one old
//!      pre-manifest brick window; it does not preserve a fallback through
//!      probation and is not crash-safe for interrupted OTP programming.
//!   6. On cancel: drop the context; the inactive slot stays erased.

use fw_manifest::{ManifestRef, MANIFEST_SIZE, TRY_ONCE_TRIED};
use sphincs_tz_shared::NscStatus;

use super::state::{peek_state, FW_UPDATE};
use super::{GatewayArgs, HandlerGuard};
use crate::fw_update::{self, verify::ImageCheckError};
use crate::hw::{boot_state, flash, otp};
use crate::timeout;
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

    // Reset the idle activity timer — the contract documented in
    // `cmd_fw_chunk.rs` ("CHUNK does NOT reset the idle timer — BEGIN
    // already did, and COMMIT will again"). Reaching here means a live
    // FW_UPDATE context exists, i.e. this COMMIT finalizes a real,
    // user-confirmed BEGIN — not companion keepalive spam, so the
    // no-context `FwUpdateBadState` path above deliberately does NOT
    // reset (that would reopen the X17-UI3 idle-window-extension
    // pattern). The reset matters on the failure paths below: they drop
    // the context and let the host re-BEGIN, which needs a fresh 120 s
    // window rather than whatever the BEGIN→…→COMMIT transfer left over.
    timeout::reset_activity();

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
        // trusted-display verifier authorization + detailed install confirm
        // before re-streaming every chunk. Each glitch attempt is now a full,
        // user-gated re-BEGIN + re-stream — not a tight in-place loop.
        //
        // We deliberately never arm the admin wipe from update failures.
        // A mismatch has benign causes (flash corruption, flaky transfer,
        // brown-out), and untrusted companion input must not be able to
        // destroy wallet state. The context drop is the non-destructive bound.
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

    // LEGACY ORDERING ONLY. Moving the floor write after the manifest closed
    // the older "floor advanced before any new candidate exists" window. It
    // did NOT make the transaction brick-safe: the candidate is selected as
    // the sole floor-admissible slot before health, the legacy try-once
    // fallback is nonfunctional in that state, and an interrupted OTP QW is
    // ambiguous/lost. Draft 1.1 proposes replacing this sequence with
    // PENDING -> ATTEMPTED -> health -> CONFIRMED -> FSBL-owned establishment.

    // 1. Write the target manifest page. The try_once_flag in the
    //    signed manifest should have been COMMITTED; we re-write it
    //    as TRIED here because the slot has not yet confirmed it
    //    boots cleanly. FSBL on the next reset sees TRIED + our
    //    matching boot-state entry. The current single-candidate selector does
    //    not provide a reliable revert after the floor excludes the old slot.
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
        if unsafe { flash::write_quadword_verified((manifest_addr + (qw * 16) as u32), &buf) }
            .is_err()
        {
            // Terminal failure: drop the context like the other failure
            // exits — retaining it would let every retried COMMIT pass
            // the live-context guard and re-reset the idle timer (an
            // X17-UI3-style keepalive; GPT-5.6 wave finding).
            // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`
            // under the non-reentrant dispatcher + `HandlerGuard`.
            unsafe {
                *core::ptr::addr_of_mut!(FW_UPDATE) = None;
            }
            return NscStatus::FwUpdateFlashError as u32;
        }
    }

    // 2. Point the boot-state page at the new (tried) slot. Written only
    //    after the manifest is fully programmed (above), so the on-disk
    //    pointer can never reference a half-written manifest. Still BEFORE
    //    the OTP bump (step 4). This preserves the old slot only until the
    //    later floor write; it is not the reviewed probation contract.
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
        // Same terminal-failure rule as the manifest-write path above:
        // the context must not survive this return (keepalive guard).
        // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`
        // under the non-reentrant dispatcher + `HandlerGuard`.
        unsafe {
            *core::ptr::addr_of_mut!(FW_UPDATE) = None;
        }
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
    //    Any failure aborts without launching the legacy OTP bump. This
    //    protects the pre-bump case only; it is not a global brick-safety
    //    claim for the handler.
    {
        // SAFETY: `manifest_addr` is the 8 KB memory-mapped manifest page of
        // the inactive slot, fully programmed just above and not mutated
        // concurrently (non-reentrant dispatcher + `HandlerGuard`). The cast
        // yields a shared reference to readable flash for the verify only;
        // `ManifestRef` reads, never writes.
        let flash_manifest: &[u8; MANIFEST_SIZE] =
            unsafe { &*(manifest_addr as *const [u8; MANIFEST_SIZE]) };
        let committed = ManifestRef::new(flash_manifest);
        // FI-hardening (X17-FW1 / playbook FW11): this is the LAST
        // authorization gate before the irreversible OTP floor bump, so a
        // bare `if !(a && b) { return }` reject would be one branch-flip
        // away from falling through to `otp::bump_to` — two coordinated
        // faults (tear the manifest write + skip the reject) brick the
        // device (new slot boot-invalid, old slot floor-excluded). Route
        // both verdicts through `check_true_into_sentinel` (double-
        // evaluated + Hamming-distant sentinel) with
        // `scrub_sentinel_register` between the paired callsites (stale-r0
        // defence, F-15.r1), matching `verify_images`' aggregate-gate
        // pattern. The closures RE-RUN the verifications; `black_box`
        // stops LLVM from proving a re-evaluation redundant (F-1).
        crate::fi::wait_random();
        let manifest_gate = crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(committed.verify_structural().is_ok())
                && core::hint::black_box(committed.verify_crc().is_ok())
                && core::hint::black_box(committed.verify_digest().is_ok())
                && core::hint::black_box(committed.verify_rollback(new_rollback_floor).is_ok())
        });
        crate::fi::scrub_sentinel_register();
        let pointer_gate = crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(matches!(
                boot_state::read(),
                Ok(bs) if bs.active_slot == inactive && bs.last_good_version == new_version
            ))
        });
        if manifest_gate != crate::fi::OK_SENTINEL || pointer_gate != crate::fi::OK_SENTINEL {
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

    // 4. Attempt the rejected legacy unary floor update. Production never
    //    reaches this code: STM32U585 OTP QWs are one-program-only, and a
    //    reset/power loss during a launched program is not retry-safe.
    // SAFETY: `otp::bump_to` is `unsafe fn` because it programs OTP one-way
    // (irreversible). Precondition: the new slot's manifest + boot-state are
    // durably written and were just re-verified from flash as a valid FSBL
    // candidate under `new_rollback_floor`.
    if let Err(e) = unsafe { otp::bump_to(new_rollback_floor) } {
        // The new slot is fully written and boot-state points at it, but the
        // legacy floor could not be raised. Surface the error and drop the
        // context; do not claim recoverability if a QW program may have
        // launched, because its post-reset state can be ambiguous.
        // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`.
        unsafe {
            *core::ptr::addr_of_mut!(FW_UPDATE) = None;
        }
        return match e {
            otp::OtpError::OutOfBudget => NscStatus::FwUpdateOtpExhausted as u32,
            _ => NscStatus::FwUpdateFlashError as u32,
        };
    }

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
    // Re-enumeration latency is ~20-25 s (mostly device boot); the NV3007 LCD
    // shows "reconnecting" across it. The companion app simply waits for
    // the device to come back.
    ui::show_status("Update OK", "reconnecting...");
    // Only the USB image (`stm32u585` + `usb`) has `hw::usb_hw`. A
    // display-only / semihosting / probe-rs bench image (`stm32u585`
    // without `usb`, e.g. `make e2e-hw-dual-se`) and the QEMU build both
    // take the plain `sys_reset` below — no USB host port to keep alive,
    // and the new firmware boots either way. Both arms diverge (`-> !`).
    #[cfg(all(feature = "stm32u585", feature = "usb"))]
    unsafe {
        crate::hw::usb_hw::cc_open_then_reset();
    }
    #[cfg(not(all(feature = "stm32u585", feature = "usb")))]
    cortex_m::peripheral::SCB::sys_reset();
}
