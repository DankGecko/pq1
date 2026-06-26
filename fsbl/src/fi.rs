//! FSBL-side fault-injection hardening — thin shim over the shared
//! `pqsigner-fi` crate.
//!
//! Mirrors the pattern `secure/src/fi.rs` uses. The only meaningful
//! difference is the RNG source: secure-world has a TRNG (`crate::rng::byte`);
//! FSBL doesn't currently initialise the TRNG, so [`wait_random`] uses a
//! fixed loop length. This weakens the *attacker-retiming* defence — an
//! attacker who can produce one precisely-timed fault can produce a second
//! at the same relative offset without any new effort — but the *invariant
//! check inside the loop* still catches mid-loop glitches the same way.
//!
//! The overall bar for bypassing the FSBL gate stays at **2 coordinated
//! faults**: one on the inner verify, one on the caller's `!= OK_SENTINEL`
//! cmp+branch — same as the secure-world `verify_manifest` gate. Without
//! `wait_random` randomness, those two faults can share a single setup;
//! with TRNG (future), they need independent precise timing.
//!
//! Future: when FSBL initialises the STM32U585 TRNG peripheral, swap
//! [`rng_byte`] for a real TRNG read and the FSBL gate matches secure-world
//! exactly. Tracked: TRNG init is currently in `secure/src/hw/rng.rs` and
//! depends on RCC + the peripheral being clocked, which FSBL doesn't yet
//! do.

pub use pqsigner_fi::OK_SENTINEL;

/// FSBL has no TRNG online; return a non-zero fixed byte. The invariant
/// loop's per-iteration sanity check (`i + j == wait`) still defends
/// against mid-loop glitches; only attacker retiming is unaffected by the
/// constant.
#[inline(always)]
fn rng_byte() -> u8 {
    0x42
}

#[inline(never)]
fn wait_random() {
    pqsigner_fi::wait_random_loop(rng_byte);
}

/// Like `secure::fi::check_true_into_sentinel` — see `pqsigner-fi/src/lib.rs`
/// for the full hardening rationale and Finding F-5 in `tools/sca/README.md`
/// for the residual-fault analysis.
#[inline(never)]
pub fn check_true_into_sentinel<F: FnMut() -> bool>(cond: F) -> u32 {
    pqsigner_fi::check_true_into_sentinel(cond, wait_random)
}

/// Scrub the AAPCS return register (`r0`) to a known non-sentinel value
/// between paired `check_true_into_sentinel` callsites — mirror of
/// `secure::fi::scrub_sentinel_register` (F-15.r1). Without this, a
/// branch-skip glitch on the second `bl check_true_into_sentinel` would
/// leave the *stale* `OK_SENTINEL` from the first call in `r0`, so the
/// caller's `cmp r0, #OK_SENTINEL` passes without ever faulting the second
/// gate. After this call `r0` holds `0`, so a skip of the next `bl` makes
/// the compare fail and the gate reject.
#[inline(never)]
pub fn scrub_sentinel_register() {
    wait_random();
    #[cfg(all(target_arch = "arm", not(test)))]
    unsafe {
        // SAFETY: zero-clobber on the ARM AAPCS return register; touches
        // neither memory nor stack.
        core::arch::asm!("mov r0, #0", out("r0") _, options(nomem, nostack));
    }
}
