//! Platform-agnostic RNG facade.
//!
//! On QEMU: delegates to `host_rng` (semihosting /dev/urandom).
//! On STM32U585: delegates to `hw::rng` (hardware TRNG peripheral).

#[cfg(not(feature = "stm32u585"))]
use crate::host_rng;
#[cfg(feature = "stm32u585")]
use crate::hw::rng as hw_rng;

pub fn fill(buf: &mut [u8]) -> Result<(), ()> {
    #[cfg(not(feature = "stm32u585"))]
    { host_rng::fill(buf) }
    #[cfg(feature = "stm32u585")]
    { hw_rng::fill(buf) }
}

pub fn byte() -> u8 {
    #[cfg(not(feature = "stm32u585"))]
    { host_rng::byte() }
    #[cfg(feature = "stm32u585")]
    { hw_rng::byte() }
}

/// One TRNG byte for **NON-SECRET** uses, returning `fallback` instead of
/// panicking if the peripheral reports a transient seed/clock error or
/// times out.
///
/// `byte()` deliberately `.expect()`s on TRNG failure so a secret-consuming
/// caller (SE handshake, nonce, key material) can never silently proceed
/// on a deterministic stream — see the `negative_rng_byte_helper_panics_*`
/// pin. But the FI-delay loop length in [`crate::fi::wait_random`] is
/// explicitly non-secret (it only sets the *duration* of a timing delay and
/// leaks nothing — see `fi.rs` rationale), and it is read thousands of times
/// per signature. Routing that path through a fatal `.expect()` means a
/// single transient STM32U5 TRNG seed-error during any of those reads panics
/// the secure world mid-sign and hangs the device until a power cycle. This
/// helper degrades that non-secret path gracefully.
///
/// **Do NOT use for key/nonce/handshake material** — a `fallback` is a
/// fixed byte, so anything that needs unpredictability must use `byte()` /
/// `fill()` (which fail loudly).
pub fn byte_nonsecret(fallback: u8) -> u8 {
    let mut b = [0u8; 1];
    match fill(&mut b) {
        Ok(()) => b[0],
        Err(()) => fallback,
    }
}
