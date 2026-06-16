
use crate::rng::{CryptoRng, PrivateRng, PublicRng, RngCore};
use checkct_macros::checkct;
// CT proof of the tweakable hash th(seed, adrs, val): the secret chain value
// must not leak. th = truncate(sha256(seed || adrs || val)); oblivious -> SECURE.
#[checkct]
pub fn checkct() {
    use sphincs_c10::sim_internals::th;
    let seed = [0u8; 32];                 // PUBLIC pk_seed
    let adrs = [0u8; 32];                 // PUBLIC address
    let mut val = [0u8; 32];
    PrivateRng.fill_bytes(&mut val);      // SECRET: hash input
    let mut pb = [0u8; 1];
    PublicRng.fill_bytes(&mut pb);
    let _ = pb[0];                        // keep public symbol alive
    let h = th(&seed, &adrs, &val);
    core::hint::black_box(h);
}
