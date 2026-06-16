
use crate::rng::{CryptoRng, PrivateRng, PublicRng, RngCore};
use checkct_macros::checkct;
// CT proof of the SHA-256 KDF: secret keying material must not leak through
// control flow or memory-access address. SHA-256 is data-oblivious -> SECURE.
#[checkct]
pub fn checkct() {
    use pqsigner_domain::kdf;
    let mut secret = [0u8; 32];
    PrivateRng.fill_bytes(&mut secret);   // SECRET: keying material (input)
    let mut dom = [0u8; 16];
    PublicRng.fill_bytes(&mut dom);       // PUBLIC: domain label
    let k = kdf(&dom, &secret, 0);        // index 0 public
    core::hint::black_box(k);
}
