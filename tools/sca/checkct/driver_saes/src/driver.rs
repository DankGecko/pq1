use crate::rng::{PrivateRng, PublicRng, RngCore};
use checkct_macros::checkct;

// Include the PRODUCTION CMAC framing source VERBATIM (not a copy) so the CT
// proof covers exactly the code that ships in `secure/src/cmac.rs`. The
// `#[cfg(test)]` NIST-vector module there is gated out of this build
// (cargo-checkct builds a non-test release binary), so only `core` is used and
// `pub(crate)` items are visible within this driver crate.
#[path = "../../../../../secure/src/cmac.rs"]
mod cmac;

// CT proof of the SAES-CMAC(DHUK) Tier-1 KDF FRAMING.
//
// In production the AES block is the STM32U585 SAES coprocessor under
// `KeySel::Dhuk` — the DHUK key never enters the CPU, so the only secret the
// CPU framing touches is the AES *output*: L = AES(DHUK, 0^128) and each
// CBC-MAC chain state. The CPU-side framing — `double_l` (GF(2^128) doubling,
// which branches on the secret MSB: `if (input[0] & 0x80) { out[15] ^= 0x87 }`),
// the CBC XOR chain, and the final-block K1/K2 selection — must not leak those
// secret bytes through control flow or a secret-dependent memory-access address.
//
// We model the SAES coprocessor as a data-oblivious primitive returning SECRET
// bytes (its timing is key-independent in hardware). The KDF message
// (`label || counter`) is PUBLIC.
//
// SECURE  => the CMAC framing is constant-time w.r.t. the secret AES outputs.
// INSECURE => `double_l`'s secret-MSB branch (or a final-block select) compiled
//             to a data-dependent branch — a real finding to harden (mask the
//             reduction instead of branching).
#[checkct]
pub fn checkct() {
    let aes = |_block: &[u8; 16]| -> Result<[u8; 16], ()> {
        // SECRET: the SAES coprocessor's output (L and each CBC state). The
        // framing below must be constant-time w.r.t. these bytes.
        let mut out = [0u8; 16];
        PrivateRng.fill_bytes(&mut out);
        Ok(out)
    };

    // PUBLIC: the KDF input (`label || counter`). 40 bytes exercises the
    // multi-block path with a PARTIAL last block (the K2 + 0x80-pad branch),
    // and runs `double_l` twice (on secret L, then secret K1).
    let mut msg = [0u8; 40];
    PublicRng.fill_bytes(&mut msg);

    let mut tag = [0u8; 16];
    let _ = cmac::cmac_generic::<(), _>(&msg, aes, &mut tag);
    core::hint::black_box(tag);
}
