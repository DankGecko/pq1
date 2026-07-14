//! Multi-source strong RNG. Mirrors Trezor's
//! `core/embed/sec/rng/rng_strong.c` design: fill from the platform
//! TRNG (STM32 hardware RNG on real silicon; semihosting `/dev/urandom`
//! on QEMU), then XOR-mix per-block from each available secure-element
//! TRNG.
//!
//! **Security argument.** XOR over independent random sources preserves
//! entropy from any unbroken source. If `n-1` of the `n` contributing
//! TRNGs are compromised / biased / stuck, the remaining one carries
//! full entropy into the output. This defends:
//!
//!   - **STM32U585 RNG seed-error / clock-error** (latched SEIS/CEIS):
//!     compromised silicon RNG → SE-side bytes still random.
//!   - **OPTIGA Trust M TRNG fault** (chip-side glitch): STM32 + SE050
//!     still contribute.
//!   - **SE050 TRNG fault**: STM32 + OPTIGA still contribute.
//!   - **Single-fault FI on one source's read path**: the other two
//!     reach the XOR-fold unfaulted.
//!
//! **Failure semantics — strict, no silent fall-through.** Any source
//! that fails to deliver entropy aborts the call. Specifically: the
//! platform TRNG (STM32 RNG SEIS/CEIS, or QEMU `/dev/urandom`) AND
//! the SE-side contribution (which itself is `OPTIGA ⊕ SE050` and
//! requires *both* chips to succeed; see `DualSecureElement::random`).
//! Refusing the call is the loud failure mode — under EMFI / I2C
//! glitching, silently degrading to fewer sources would let an
//! attacker reduce entropy without anything noticing.
//!
//! Under `feature = "mock-se"` only (dev/QEMU builds), the SE-side
//! contribution is allowed to be absent because the mock backend has
//! no TRNG. CI gates production firmware on `mock-se` OFF.
//!
//! **What we do NOT defend** with the XOR alone:
//!
//!   - A single-fault that clamps the **buffer** (not the source) to
//!     all-zeros after the fold. The post-fill non-zero acceptance
//!     gate catches this: an all-zero N-byte buffer is diagnostic of
//!     a stuck-at-0 fault (legitimate randoms collide with all-zero
//!     at probability `2^-(8·N)` — for N=16, that's 2^-128).
//!   - A coordinated fault that mutates all three sources identically.
//!     Out of scope for our threat model (single-fault assumption).
//!
//! Consumed by `crate::crypto::c10_sign_verified_with_progress` to
//! draw a fresh `opt_rand` per signing call (F-13 follow-up; aligned
//! with `docs/work-todo.md` §10 "Multi-Source RNG").

use zeroize::Zeroize;

/// Fill `buf` with strong random bytes: platform TRNG XOR'd with the
/// active SE backend's `random()` (which itself XOR-mixes all
/// available SE-side sources for multi-SE backends like
/// `DualSecureElement`).
///
/// Returns `Err(())` if:
///   - the platform TRNG fails (STM32 RNG peripheral seed/clock error
///     on hardware, or semihosting `/dev/urandom` unavailable on QEMU),
///   - the SE-side TRNG fails on a production backend (for
///     `DualSecureElement` this means either OPTIGA or SE050 failed),
///   - the resulting buffer is all-zero after the fold (stuck-at-0
///     fault diagnostic — fail-closed).
///
/// Under `feature = "mock-se"` the SE call is allowed to fail (the
/// mock backend has no TRNG); under any production backend
/// (`optiga-trust-m`, `se050`, `dual-se`) a missing SE
/// contribution is fatal.
pub fn fill(buf: &mut [u8]) -> Result<(), ()> {
    if buf.is_empty() {
        return Ok(());
    }

    // ── Step 1: platform TRNG (STM32 or QEMU /dev/urandom) ──────────
    // Establishes the baseline; XOR layers below strictly improve
    // entropy. STM32 RNG SEIS/CEIS or `/dev/urandom` read failure
    // aborts the call.
    crate::rng::fill(buf)?;

    // ── Step 2: XOR-mix per-block from the SE backend ────────────────
    // For multi-SE backends the trait impl already XOR-folds the
    // per-source contributions internally and requires every chip to
    // succeed (see `DualSecureElement::random`). Block-by-block
    // matches Trezor's pattern and keeps the SE TLV body small.
    let mut block = [0u8; 32];
    let mut off = 0;
    while off < buf.len() {
        let len = (buf.len() - off).min(block.len());
        // SAFETY: the caller (sign path) has unlocked the SE, so the
        // global SE handle is initialised.
        #[cfg(all(not(test), not(feature = "mock-se")))]
        {
            unsafe { crate::se_random(&mut block[..len]) }.map_err(|_| {
                block.zeroize();
            })?;
            for i in 0..len {
                buf[off + i] ^= block[i];
            }
        }
        #[cfg(all(not(test), feature = "mock-se"))]
        if unsafe { crate::se_random(&mut block[..len]) }.is_ok() {
            for i in 0..len {
                buf[off + i] ^= block[i];
            }
        }
        off += len;
    }
    block.zeroize();

    // ── Step 3: fail-closed non-zero acceptance gate ────────────────
    // An all-zero buffer is a strong signal of a stuck-at-0 fault
    // somewhere on the fill path. For any reasonable buffer length
    // (the typical caller uses 16 B for SPHINCS+C10 OptRand) the
    // legitimate collision probability with all-zero is 2^-(8·N),
    // which is negligible. Refuse rather than silently emit a
    // predictable random.
    let mut acc: u8 = 0;
    for &b in buf.iter() {
        acc |= b;
    }
    if acc == 0 {
        return Err(());
    }

    Ok(())
}
