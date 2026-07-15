//! CMD_FW_ABORT — discard a partial update.
//!
//! Drops the in-SRAM `FwUpdateCtx`. The inactive slot's erased +
//! partially-written pages stay in whatever state they're in —
//! harmless, because FSBL rejects a manifest-less slot as
//! `BadMagic` and falls back to the active slot. A subsequent
//! `CMD_FW_BEGIN` re-erases before re-seeding, so nothing leaks.
//!
//! Gated on `pin_verified` like every FW entry point (CLAUDE.md: CMDs
//! 20–24 require unlock). Not a wedge: a context exists only after a
//! PIN-verified BEGIN, and lock / idle-wipe already drops `FW_UPDATE`,
//! so a locked device has nothing left to abort.

use sphincs_tz_shared::NscStatus;

use super::state::{peek_state, FW_UPDATE};

/// # Safety
/// CMSE non-secure-entry handler — caller is the gateway dispatcher
/// (`nsc/mod.rs`) on either the QEMU mailbox path or the STM32U585
/// CMSE veneer. Dispatcher invariants apply: single-threaded,
/// non-reentrant, NS arguments have already been snapshotted.
pub(super) unsafe fn run() -> u32 {
    // Hold the busy guard for the whole handler (finding LCR-F2). The
    // `*FW_UPDATE = None` write below is NOT the atomic "single-statement write"
    // the previous comment claimed: `FwUpdateCtx` is `#[derive(ZeroizeOnDrop)]`,
    // so `= None` runs a non-atomic multi-field destructor. The SysTick idle-wipe
    // (`main.rs`) also does `*FW_UPDATE = None` whenever `!handler_is_busy()`, so
    // without this guard idle-wipe can preempt the handler on the CMSE path and
    // race the destructor (update-state corruption / read-during-drop). Every
    // sibling FW handler (BEGIN/CHUNK/COMMIT) already holds it; STATUS/ABORT were
    // the two that didn't. The guard drops at function exit (after the write).
    let _busy = super::HandlerGuard::enter();

    // PIN gate — matches BEGIN/CHUNK/COMMIT.
    if peek_state(|s| s.pin_verified.check_sentinel()) != crate::fi::OK_SENTINEL {
        return NscStatus::NotInitialized as u32;
    }

    // SAFETY: `FW_UPDATE` is the secure-world `static mut` that holds the
    // in-flight firmware-update context (category 5). Access is serialised by
    // the non-reentrant gateway, and the `HandlerGuard` above blocks the SysTick
    // idle-wipe from racing the drop. `addr_of_mut!` is used (rather than `&mut`)
    // to avoid materialising a reference we don't need; the write replaces the
    // slot wholesale.
    unsafe {
        *core::ptr::addr_of_mut!(FW_UPDATE) = None;
    }
    NscStatus::Ok as u32
}
