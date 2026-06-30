//! NS pointer + length bounds checks.
//!
//! Every gateway command receives raw pointers from the non-secure
//! world. Before the secure world touches a single byte of memory
//! those pointers describe, it MUST prove:
//!
//!   1. The target range lies entirely inside a known NS region
//!      (NS SRAM for writes, NS SRAM or NS flash for reads).
//!   2. The range does not alias the shared mailbox — otherwise a
//!      hostile NS could get the secure world to overwrite the very
//!      command word it's still interpreting.
//!   3. The arithmetic `ptr + len` does not overflow.
//!   4. (HIGH-1) On ARMv8-M, the SAU actually classifies every byte
//!      of the range as Non-Secure *right now*. The constant-range
//!      check above uses compile-time constants that go stale if
//!      `memory.x` / `sau.rs` change without everyone updating
//!      `shared/src/lib.rs`. The TT instruction asks the hardware
//!      directly.
//!
//! TT result bit layout (ARMv8-M, used by Zephyr/TF-M):
//!   bit 22 S     — 1 if Secure, 0 if Non-Secure
//!   bit 21 NSRW  — 1 if NS read-write
//!   bit 20 NSR   — 1 if NS readable
//!   bit 17 SRVLD — 1 if SAU region matched
//!
//! These helpers are called on every `cmd_*` entry; keeping them in a
//! single tiny file makes the memory-boundary invariants easy to audit.

use sphincs_tz_shared::ns_ptr_validate::{ns_read_window_ok, ns_write_window_ok, NsRegions};
use sphincs_tz_shared::{
    NS_FLASH_BASE, NS_FLASH_END, NS_SRAM_BASE, NS_SRAM_END, SHARED_MAILBOX_BASE, SHARED_MAILBOX_END,
};

/// The non-secure memory map this build validates against, assembled
/// from the cfg-gated `pqsigner-proto` linker constants. The pure
/// window-check arithmetic (null reject, `usize → u32` truncation
/// reject, `ptr + len` overflow reject, constant-window containment,
/// shared-mailbox disjointness) lives in
/// [`sphincs_tz_shared::ns_ptr_validate`] — host-compilable and
/// Kani-proven *sound* (`cargo kani -p sphincs-tz-shared`). This is the
/// single concrete map the firmware feeds it; the hardware `TT`/SAU
/// re-classification below is ANDed in on top.
const NS_REGIONS: NsRegions = NsRegions {
    ns_sram_base: NS_SRAM_BASE,
    ns_sram_end: NS_SRAM_END,
    ns_flash_base: NS_FLASH_BASE,
    ns_flash_end: NS_FLASH_END,
    mailbox_base: SHARED_MAILBOX_BASE,
    mailbox_end: SHARED_MAILBOX_END,
};

/// ARMv8-M `TT` (Test Target) — ask the SAU/IDAU for the security
/// attributes of `addr` in the *current* security state. Returns the
/// 32-bit TT response word as described in ARMv8-M Reference Manual.
///
/// Only present on real STM32U585 hardware — QEMU mps2-an505 has no
/// real SAU (the workaround there is the shared-mailbox dispatch).
#[cfg(feature = "stm32u585")]
#[inline(always)]
fn tt(addr: u32) -> u32 {
    let r: u32;
    // SAFETY: ARMv8-M `TT` is a pure register-to-register query that
    // reads the SAU/IDAU classification of `addr` from secure state
    // and returns the 32-bit result word. It performs no memory
    // access (`nomem`), does not touch the stack (`nostack`), and
    // leaves architectural flags unchanged (`preserves_flags`). The
    // operand register holding `addr` is read-only from the
    // instruction's perspective, so this `asm!` cannot affect
    // surrounding code. Inline asm is the only way to emit a `TT`
    // — Rust has no intrinsic for it.
    unsafe {
        core::arch::asm!(
            "tt {out}, {addr}",
            out = out(reg) r,
            addr = in(reg) addr,
            options(nomem, nostack, preserves_flags),
        );
    }
    r
}

/// Check that every byte in `[ptr, ptr+len)` is classified as
/// Non-Secure by the SAU, returning `false` otherwise. Stride the TT
/// instruction at 32-byte granularity (SAU regions are always 32-byte
/// aligned, so it's enough to test one byte per aligned block plus
/// the final byte).
#[cfg(feature = "stm32u585")]
fn tt_range_is_ns(ptr: u32, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let end_incl = match ptr.checked_add(len as u32 - 1) {
        Some(e) => e,
        None => return false,
    };

    // TT response: bit 22 = S, bit 20 = NSR. Accept if NS (S=0) and
    // NS-readable (NSR=1).
    let is_ns = |r: u32| ((r >> 22) & 1) == 0;
    let nsr = |r: u32| ((r >> 20) & 1) == 1;
    let ok = |r: u32| is_ns(r) && nsr(r);

    let r0 = tt(ptr);
    let r1 = tt(end_incl);

    if !ok(r0) || !ok(r1) {
        return false;
    }
    // Stride through the middle 32-byte blocks.
    let mut cur = (ptr + 32) & !31;
    while cur < end_incl {
        if !ok(tt(cur)) {
            return false;
        }
        cur = match cur.checked_add(32) {
            Some(v) => v,
            None => return false,
        };
    }
    true
}

#[cfg(not(feature = "stm32u585"))]
fn tt_range_is_ns(_ptr: u32, _len: usize) -> bool {
    // DELIBERATE NO-OP ON HOST/QEMU — NOT a missing check, do not "fix" it by
    // modelling SAU regions here. The `TT` instruction queries the real silicon
    // SAU; there is NO faithful host model of it (SAU Region 1, the NSC
    // carve-out, is a link-time symbol with no host value). A *discriminating*
    // host model would DIVERGE from silicon (the device's NS windows are
    // subsets of its SAU NS regions, so the hardware `TT` returns NS for every
    // window-accepted address — including the mailbox); a *non-discriminating*
    // one is exactly this `true`. Returning `true` is therefore the honest host
    // behaviour: the load-bearing range gate is the constant-window check the
    // caller already ran (`ns_{read,write}_window_ok`, host-exercised +
    // Kani-proven), and the ONLY drift a host model could catch — a window
    // escaping its SAU region — is caught at COMPILE TIME by the subset
    // assertion in `secure/src/sau.rs`. Real `TT` semantics are validated on
    // silicon (`make gtzc-enforcement-hw`), not here. (Item 4, audit 2026-06-29.)
    true
}

/// Validate that `ptr + len` falls entirely within a non-secure memory
/// region the secure world is allowed to **write** to (NS SRAM only),
/// and does not overlap the shared mailbox.
#[inline]
pub(super) fn validate_ns_write_ptr(ptr: u32, len: usize) -> bool {
    // Pure constant-window arithmetic (null / truncation / overflow /
    // containment / mailbox-disjoint) — Kani-proven sound in
    // `sphincs_tz_shared::ns_ptr_validate`.
    if !ns_write_window_ok(&NS_REGIONS, ptr, len) {
        return false;
    }
    // HIGH-1: double-check against the SAU in hardware. Evaluated only
    // when the window check already passed, preserving the original
    // short-circuit order.
    tt_range_is_ns(ptr, len)
}

/// Validate that `ptr + len` falls entirely within a non-secure memory
/// region the secure world is allowed to **read** from. Allows both NS
/// SRAM and NS flash (the latter is read-only and can hold static
/// payloads like an unsigned tx). The shared mailbox is excluded.
#[inline]
pub(super) fn validate_ns_read_ptr(ptr: u32, len: usize) -> bool {
    // Pure constant-window arithmetic (NS SRAM *or* NS flash, mailbox-
    // disjoint when in SRAM) — Kani-proven sound in
    // `sphincs_tz_shared::ns_ptr_validate`.
    if !ns_read_window_ok(&NS_REGIONS, ptr, len) {
        return false;
    }
    // HIGH-1: double-check against the SAU in hardware. Evaluated only
    // when the window check already passed, preserving the original
    // short-circuit order.
    tt_range_is_ns(ptr, len)
}
