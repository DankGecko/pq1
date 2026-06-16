
use crate::rng::{CryptoRng, PrivateRng, PublicRng, RngCore};
use checkct_macros::checkct;
// CT proof of the FORS secret-key PRF: sha256(sk_seed || "fors" || indices).
// sk_seed is SECRET; the indices are PUBLIC structure.
#[checkct]
pub fn checkct() {
    use sphincs_c10::sim_internals::fors_secret;
    let mut sk = [0u8; 32];
    PrivateRng.fill_bytes(&mut sk);       // SECRET: sk_seed
    let mut pb = [0u8; 1];
    PublicRng.fill_bytes(&mut pb);
    let ht = (pb[0] & 0) as u32;          // PUBLIC indices
    let s = fors_secret(&sk, ht, 0, 0);
    core::hint::black_box(s);
}
