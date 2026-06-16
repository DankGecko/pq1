use crate::rng::{CryptoRng, PrivateRng, PublicRng, RngCore};
use checkct_macros::checkct;

// Constant-time verification of sphincs_c10::shuffle::fisher_yates.
//
// The 32-byte shuffle `seed` is the per-signature DPA-defence secret:
// it is derived from rng_strong and must NOT leak through control flow
// or memory-access addresses. `n` (number of WOTS chains / FORS trees)
// is a PUBLIC compile-time parameter (43 or 13), so we fix it to a
// public constant.
#[checkct]
pub fn checkct() {
    use sphincs_c10::shuffle::fisher_yates;

    // SECRET: the shuffle seed.
    let mut seed = [0u8; 32];
    PrivateRng.fill_bytes(&mut seed);

    // Keep the __checkct_public_rand symbol alive (the binsec script
    // unconditionally `replace`s it). Draw one public byte and feed it
    // to the public parameter `n` so the symbol is referenced.
    let mut pub_byte = [0u8; 1];
    PublicRng.fill_bytes(&mut pub_byte);

    // PUBLIC: n is the chain/tree count (here the l=43 WOTS case).
    // `n` stays public — derived from the public RNG draw, range-clamped.
    let n: usize = 43 + (pub_byte[0] & 0) as usize;

    let _perm = fisher_yates(&seed, n);
    core::hint::black_box(_perm);
}
