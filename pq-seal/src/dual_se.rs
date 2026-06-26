//! Dual-SE-facing convenience API over the [`crate::seal`] / [`crate::open`]
//! primitive — seals a 256-bit entropy half into the **storage split** the
//! hardware actually needs (`ct` → MCU secure flash, `aead` → the SE), with the
//! right context AAD so a blob can never be replayed as the other half or
//! another account.
//!
//! The 1616-byte sealed blob does **not** fit on OPTIGA (F1D1 is 140 B, the
//! largest Type-2 object is 1500 B, the I2C buffer is 1557 B — see
//! `docs/security/ml-kem-inner-wrap.md`). So the caller stores the 1568-byte
//! ML-KEM `ct` in MCU secure flash (not a standalone secret — IND-CCA) and only
//! the 48-byte `aead` on the SE. This is pure logic; the firmware binds `seed`
//! + `huk_secret` from two `hw::huk` labels and `encaps_msg` from the TRNG.

// `aad` (additional authenticated data) and `aead` (the sealed tail) are
// distinct standard crypto terms that clippy::similar_names flags as too alike.
#![allow(clippy::similar_names)]

use crate::{open, seal, WrapError, CT_LEN, ENCAPS_MSG_LEN, HUK_LEN, SEED_LEN, TAG_LEN};

/// Length of an XOR entropy half (256-bit share).
pub const HALF_LEN: usize = 32;
/// Length of the AEAD part stored on the SE (`gcm_ct ‖ tag` for a 32-byte half).
pub const AEAD_LEN: usize = HALF_LEN + TAG_LEN; // 48

/// Which secure element a half lives on — selects the AAD domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HalfId {
    /// `half_O`, stored on the OPTIGA Trust M.
    OptigaHalfO,
    /// `half_E`, stored on the SE050.
    Se050HalfE,
}

impl HalfId {
    const fn tag(self) -> &'static [u8] {
        match self {
            HalfId::OptigaHalfO => b"optiga:half_O",
            HalfId::Se050HalfE => b"se050:half_E",
        }
    }
}

/// Longest `tag()` (13) + `account_index` big-endian (4).
const AAD_MAX: usize = 13 + 4;

fn build_aad(buf: &mut [u8; AAD_MAX], half: HalfId, account_index: u32) -> &[u8] {
    let t = half.tag();
    buf[..t.len()].copy_from_slice(t);
    buf[t.len()..t.len() + 4].copy_from_slice(&account_index.to_be_bytes());
    &buf[..t.len() + 4]
}

/// Seal a 256-bit `half` for `(half_id, account_index)` into the storage split:
/// returns `(ct, aead)` — `ct` (1568 B) for MCU secure flash, `aead` (48 B) for
/// the SE.
///
/// # Errors
/// [`WrapError`] propagated from [`crate::seal`] (only on an internal AEAD
/// failure; the fixed-size buffer here is always large enough).
pub fn seal_half(
    seed: &[u8; SEED_LEN],
    huk_secret: &[u8; HUK_LEN],
    encaps_msg: &[u8; ENCAPS_MSG_LEN],
    half_id: HalfId,
    account_index: u32,
    half: &[u8; HALF_LEN],
) -> Result<([u8; CT_LEN], [u8; AEAD_LEN]), WrapError> {
    let mut scratch = [0u8; AAD_MAX];
    let aad = build_aad(&mut scratch, half_id, account_index);

    let mut sealed = [0u8; CT_LEN + AEAD_LEN];
    seal(seed, encaps_msg, huk_secret, aad, half, &mut sealed)?;

    let mut ct = [0u8; CT_LEN];
    ct.copy_from_slice(&sealed[..CT_LEN]);
    let mut aead = [0u8; AEAD_LEN];
    aead.copy_from_slice(&sealed[CT_LEN..]);
    Ok((ct, aead))
}

/// Recover a half from its split storage: `ct` (MCU flash) + `aead` (SE).
///
/// # Errors
/// [`WrapError`] if the GCM tag fails — tampered `ct`/`aead`, wrong `seed`,
/// wrong `huk_secret`, or a `(half_id, account_index)` mismatch (no
/// cross-half / cross-account replay).
pub fn open_half(
    seed: &[u8; SEED_LEN],
    huk_secret: &[u8; HUK_LEN],
    half_id: HalfId,
    account_index: u32,
    ct: &[u8; CT_LEN],
    aead: &[u8; AEAD_LEN],
) -> Result<[u8; HALF_LEN], WrapError> {
    let mut scratch = [0u8; AAD_MAX];
    let aad = build_aad(&mut scratch, half_id, account_index);

    let mut sealed = [0u8; CT_LEN + AEAD_LEN];
    sealed[..CT_LEN].copy_from_slice(ct);
    sealed[CT_LEN..].copy_from_slice(aead);

    let mut half = [0u8; HALF_LEN];
    open(seed, huk_secret, aad, &sealed, &mut half)?;
    Ok(half)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; SEED_LEN] = [0x42; SEED_LEN];
    const HUK: [u8; HUK_LEN] = [0xA5; HUK_LEN];
    const M: [u8; ENCAPS_MSG_LEN] = [0x17; ENCAPS_MSG_LEN];
    const HALF: [u8; HALF_LEN] = [0x5A; HALF_LEN];

    #[test]
    fn split_sizes() {
        let (ct, aead) = seal_half(&SEED, &HUK, &M, HalfId::OptigaHalfO, 0, &HALF).unwrap();
        assert_eq!(ct.len(), 1568);
        assert_eq!(aead.len(), 48);
    }

    #[test]
    fn round_trip_both_halves_and_accounts() {
        for half_id in [HalfId::OptigaHalfO, HalfId::Se050HalfE] {
            for acct in [0u32, 1, 255, 1_000] {
                let (ct, aead) = seal_half(&SEED, &HUK, &M, half_id, acct, &HALF).unwrap();
                let got = open_half(&SEED, &HUK, half_id, acct, &ct, &aead).unwrap();
                assert_eq!(got, HALF);
            }
        }
    }

    #[test]
    fn cross_half_open_fails() {
        // A blob sealed as half_O can't open as half_E (AAD domain separation).
        let (ct, aead) = seal_half(&SEED, &HUK, &M, HalfId::OptigaHalfO, 0, &HALF).unwrap();
        assert_eq!(
            open_half(&SEED, &HUK, HalfId::Se050HalfE, 0, &ct, &aead),
            Err(WrapError)
        );
    }

    #[test]
    fn cross_account_open_fails() {
        let (ct, aead) = seal_half(&SEED, &HUK, &M, HalfId::OptigaHalfO, 0, &HALF).unwrap();
        assert_eq!(
            open_half(&SEED, &HUK, HalfId::OptigaHalfO, 1, &ct, &aead),
            Err(WrapError)
        );
    }

    #[test]
    fn the_two_halves_seal_distinctly() {
        let o = seal_half(&SEED, &HUK, &M, HalfId::OptigaHalfO, 0, &HALF).unwrap();
        let e = seal_half(&SEED, &HUK, &M, HalfId::Se050HalfE, 0, &HALF).unwrap();
        assert_ne!(o.1, e.1, "same half under different ids must seal differently");
    }
}
