//! OTP rollback-floor read for the FSBL.
//!
//! Legacy mirror of `secure/src/hw/otp.rs::rollback_floor`.
//!
//! This unary bit-tally is not a valid STM32U585 OTP backend: one
//! ECC-protected 128-bit quad-word cannot be reprogrammed bit by bit. Shipping
//! builds are compile-blocked. Draft 1.1 proposes a typed floor/journal
//! interface, but is not implementation-approved and leaves the physical
//! codec open. Do not extend this reader or treat `ROLLBACK_WORDS * 32` as
//! physical update capacity.

use core::ptr::read_volatile;

const OTP_BASE: usize = 0x0BFA_0000;
const ROLLBACK_WORDS: usize = 32;

/// F15 hardening: read the OTP rollback tally TWICE and take the MAX of the
/// two independent passes. The floor feeds `verify_rollback`; a single faulted
/// word-read that under-counts zero bits would LOWER the floor, admitting a
/// validly-signed *downgrade*. Sentinel-hardening `verify_rollback` alone does
/// not help — both evaluations consume the same faulted floor — so the read
/// itself must be voted. `max(a, b)` is the conservative vote for a monotonic
/// floor: a glitch that under-counts one pass is overridden by the correct one
/// (defeating the single-fault downgrade), while a glitch that over-counts only
/// rejects more (fail-closed DoS, never admits a downgrade). Two clean reads
/// agree, so honest boots are unaffected.
pub fn rollback_floor() -> u32 {
    let a = rollback_floor_once();
    let b = rollback_floor_once();
    a.max(b)
}

fn rollback_floor_once() -> u32 {
    let mut count: u32 = 0;
    let base = OTP_BASE as *const u32;
    for i in 0..ROLLBACK_WORDS {
        // SAFETY: OTP is memory-mapped; indices bounded by ROLLBACK_WORDS.
        let w = unsafe { read_volatile(base.add(i)) };
        count += w.count_zeros();
    }
    count
}
