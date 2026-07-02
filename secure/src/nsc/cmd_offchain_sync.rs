//! CMD_OFFCHAIN_SYNC — bump per-slot `last_userop_count` to a
//! companion-supplied target. "Set if greater", idempotent.
//!
//! The repair path in `cmd_sign_userop::run` computes
//! `new_offchain_count = max(local_offchain, last_userop_snapshot)`
//! using firmware-flash state only. After a firmware reflash that
//! wipes the offchain-state flash region, both counters start at
//! zero — but the on-chain `offchainSigCount[ownerIndex]` may still
//! be non-zero (carried over from before the reflash). Without a way
//! to inform the firmware of the on-chain floor, the next userop emits
//! `newOffchainCount = 0` and reverts with
//! `OffchainSigCountNotMonotonic`.
//!
//! Wire layout:
//!   * Input (21 bytes):
//!       [ 0.. 1) account_index (u8)
//!       [ 1.. 9) chain_id      (u64 BE)
//!       [ 9..13) slot_index    (u32 BE)
//!       [13..21) target_count  (u64 BE)
//!   * Output: no body, SW only.
//!
//! Security note: the *value* set here is harmless — the host already drives
//! slot use (it picks `account_index` / `slot_index`, signs what it likes), and
//! the on-chain combined-cap check (`slotUses + offchainSigCount <= cap`) still
//! enforces the per-slot budget regardless of what the firmware emits.
//!
//! What the value-only reasoning missed (page-123 exhaustion → permanent-brick;
//! `docs/security/vulns/VULN-offchain-sync-page123-exhaustion-brick.md`): the durable *write*
//! mints a fresh page-123 journal entry for a companion-chosen, seed-independent
//! `slot_key`. With no consent gate a hostile companion can spray distinct
//! `(account,chain,slot)` tuples to fill the page and wedge compaction into a
//! permanent, seed-survivable signing brick. Two defences now apply:
//!   1. **Consent (here):** creating a slot the firmware has NOT seen before
//!      requires an explicit trusted-display `confirm()` — a spray would need
//!      one physical confirm per distinct tuple. Re-syncs of an already-
//!      registered slot are idempotent floor bumps and stay confirm-free. This
//!      mirrors the `cmd_sign_offchain` MEDIUM-3 "defer the durable write until
//!      after confirm" discipline.
//!   2. **Structural cap:** `offchain_state::MAX_DISTINCT_SLOTS` (enforced at the
//!      flash `write_entry` chokepoint and the host mock) refuses a new distinct
//!      slot past a budget chosen so compaction can never fail — the page is
//!      provably un-wedgeable by any caller, confirmed or not.

use sphincs_tz_shared::{NscStatus, MAX_ACCOUNT_INDEX, OFFCHAIN_SYNC_INPUT_LEN};

use super::ptr_validate::validate_ns_read_ptr;
use super::GatewayArgs;

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. NS pointer
/// derefs happen only after `validate_ns_read_ptr` has proved the
/// input range is fully NS-classified. No output buffer in this
/// command (status word only).
pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    let _busy = super::HandlerGuard::enter();

    if super::state::peek_state(|s| s.pin_verified.check_sentinel()) != crate::fi::OK_SENTINEL {
        return NscStatus::NotInitialized as u32;
    }

    let in_ptr = args.arg0 as *const u8;
    let total_len = args.arg2 as usize;

    if total_len != OFFCHAIN_SYNC_INPUT_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    // HIGH-1 (audit fault-injection 20260611): sentinel-gate the NS read
    // pointer (bare `if !validate` is single-fault FAIL-OUT). This handler
    // has no output buffer, so only the read pointer is validated.
    let read_ptr_ok = crate::fi::check_true_into_sentinel(|| {
        validate_ns_read_ptr(args.arg0, OFFCHAIN_SYNC_INPUT_LEN)
    });
    if read_ptr_ok != crate::fi::OK_SENTINEL {
        return NscStatus::InvalidPointer as u32;
    }

    let mut buf = [0u8; OFFCHAIN_SYNC_INPUT_LEN];
    for i in 0..OFFCHAIN_SYNC_INPUT_LEN {
        buf[i] = core::ptr::read_volatile(in_ptr.add(i));
    }
    let account_index = buf[0] as u32;
    let chain_id = u64::from_be_bytes([
        buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
    ]);
    let slot_index = u32::from_be_bytes([buf[9], buf[10], buf[11], buf[12]]);
    let target_count = u64::from_be_bytes([
        buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19], buf[20],
    ]);
    if account_index > MAX_ACCOUNT_INDEX {
        return NscStatus::InvalidPointer as u32;
    }

    // Value-inflation → consent-free durable slot brick defence (Layer 1;
    // `docs/security/vulns/VULN-offchain-sync-value-inflation-slot-brick.md`). `target_count` is
    // fully companion-controlled and, for an already-registered slot, is written
    // durably WITHOUT a confirm (the gate below only fires for new slots). The
    // sign paths promote it verbatim into the monotonic `offchain` counter, so an
    // un-clamped `>= MAX_SLOT_USES` would permanently trip the combined-cap gate —
    // a seed-survivable, consent-free brick of the slot. Clamp it to
    // `OFFCHAIN_COUNT_CEILING` (`MAX_SLOT_USES - 1`) at the source: a truthful
    // on-chain `offchainSigCount` (the only value a legitimate sync mirrors) is
    // always `< MAX_SLOT_USES`, so this never rejects an honest sync, while a
    // hostile inflation can no longer reach the brick state. Belt-and-braces: the
    // durable flash setters clamp again (see `crate::offchain_state`), so a single
    // skipped site cannot re-open the hole.
    let target_count = crate::offchain_state::clamp_offchain_count(target_count);

    let slot_key =
        crate::offchain_state::slot_key_compute(account_index as u8, chain_id, slot_index);

    // Consent gate — two brick classes, one confirm.
    //
    // (a) NEW-SLOT (page-123 exhaustion → permanent-brick fix; module Security
    //     note + docs/security/vulns/VULN-offchain-sync-page123-exhaustion-brick.md). A durable
    //     write for a slot the firmware has NOT seen before mints a new page-123
    //     journal entry for a companion-chosen, seed-independent slot_key; an
    //     unbounded spray of distinct tuples would wedge compaction into a
    //     permanent signing brick. One physical confirm per distinct tuple makes
    //     a spray infeasible.
    //
    // (b) VALUE-INFLATION (docs/security/vulns/VULN-offchain-sync-value-inflation-slot-brick.md).
    //     Even on an ALREADY-registered slot, a sync that RAISES `last_userop` is
    //     promoted into the monotonic off-chain counter and burns the slot's
    //     few-time budget toward exhaustion with no user interaction. The clamp
    //     above already blocks the permanent, cap-tripping brick; this confirm
    //     additionally denies the *consent-free near-exhaustion* that would
    //     otherwise let a hostile companion force the slot-rotation treadmill.
    //     A raise only ever occurs on genuine recovery (post-reflash catch-up —
    //     itself a NEW slot, case (a) — or a rare multi-device floor advance),
    //     so gating it costs an honest user at most one confirm while removing
    //     the attacker's silent lever. Fail-safe: if this read glitches the sync
    //     is over-gated (an extra confirm), never under-gated.
    //
    // An idempotent re-sync (`target <= stored`) is a no-op and stays confirm-
    // free. Bare unsafe facade calls match this file's existing convention.
    let is_new_slot = !crate::offchain_state::offchain_count_is_registered(&slot_key);
    let raises_floor = target_count > crate::offchain_state::last_userop_count_read(&slot_key);
    if is_new_slot || raises_floor {
        use crate::ui::confirm::{confirm_checked, ConfirmResult};
        let pages = crate::tx::display::build_offchain_sync_pages(
            account_index as u8,
            chain_id,
            slot_index,
        );
        let (cr, cr_verdict) = confirm_checked(pages.as_slice());
        match cr {
            ConfirmResult::Confirmed => {}
            ConfirmResult::Cancelled => {
                crate::ui::show_status("Cancelled", "");
                return NscStatus::UserRejected as u32;
            }
            ConfirmResult::IdleWipe => {
                super::zeroize_sensitive_state();
                return NscStatus::IdleWipe as u32;
            }
        }
        // FI belt (UI1 / work-todo #12c): affirmative-sentinel gate; fail closed.
        if cr_verdict != crate::fi::OK_SENTINEL {
            super::zeroize_sensitive_state();
            return NscStatus::UserRejected as u32;
        }
    }

    // `last_userop_count_set` is tolerant of `target <= current` (no-op).
    // The repair branch in `cmd_sign_userop::run` will pick up the new
    // floor via `last_userop_count_read` → `max(local, last_userop)`,
    // and `offchain_count_promote_to` will bump `local_offchain` in turn
    // so subsequent off-chain signs see a consistent base.
    if crate::offchain_state::last_userop_count_set(&slot_key, target_count).is_err() {
        return NscStatus::InternalError as u32;
    }

    NscStatus::Ok as u32
}
