#![no_std]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
//! ML-KEM-1024 + AES-256-GCM **encrypt-to-self inner wrap** (invariant #3 PQ
//! confidentiality layer; SOTA §"ML-KEM-1024 inner wrap planned").
//!
//! ## Why
//!
//! The dual-SE entropy halves (`half_O` on OPTIGA, `half_E` on SE050) cross
//! I²C under the SEs' *classical* secure channels — OPTIGA Shielded Connection
//! (AES-128-CCM-8) and SE050 SCP03 (AES-CMAC/CBC). Those channels' session
//! keys are derived from classical primitives, so a **Harvest-Now-Decrypt-Later
//! (HNDL)** adversary who records the bus today and breaks the channel with a
//! future CRQC recovers the plaintext half. For a wallet holding long-term
//! funds, the attacker need not be present at decryption time — this is the
//! dominant residual threat (README §threat-model).
//!
//! This crate adds a **post-quantum inner layer**: each half is sealed with
//! ML-KEM-1024 (FIPS 203) + AES-256-GCM *before* it ever touches I²C, so the
//! classical SE channel carries only PQ-opaque ciphertext. Breaking the SE
//! channel yields an ML-KEM ciphertext; recovering the half additionally
//! requires the ML-KEM decapsulation key — which never leaves the U585 secure
//! world and is re-derived each boot from a HUK-bound 64-byte seed (so nothing
//! lattice-secret is *stored* in plaintext, on a bus, or on an SE).
//!
//! ## Construction — KEM-DEM "encrypt-to-self"
//!
//! The MCU holds ONE ML-KEM-1024 keypair, derived deterministically from a
//! device-bound 64-byte `seed` (`hw::huk`):
//!
//! ```text
//! seal(seed, m, pt):                       open(seed, ct‖aead):
//!   dk = ML-KEM.from_seed(seed)              dk = ML-KEM.from_seed(seed)
//!   ek = dk.encapsulation_key()              K  = ML-KEM.Decaps(dk, ct)
//!   (ct, K) = ML-KEM.Encaps(ek; m)           pt = AES-256-GCM.Open(K, aead)
//!   aead = AES-256-GCM.Seal(K, pt)           return pt
//!   return ct ‖ aead
//! ```
//!
//! `K` (the 32-byte ML-KEM shared secret) is the AES-256 key. Because a fresh
//! `K` is produced for **every** seal (the encapsulation message `m` is fresh
//! TRNG), the `(key, nonce)` pair is unique even with a fixed all-zero GCM
//! nonce — the textbook KEM-DEM construction. ML-KEM decapsulation uses
//! *implicit rejection* (it never errors — a bad ciphertext yields a
//! pseudo-random `K`); the GCM tag is what authenticates, so a tampered `ct`,
//! a tampered `aead`, or the wrong `seed` all fail at `open` via the tag.
//!
//! ## Scope
//!
//! Pure no_std logic — the caller (secure world) supplies the HUK-bound `seed`
//! and fresh TRNG `encaps_msg`. Wiring into the OPTIGA/SE050 store+read paths
//! (object sizing, provisioning) is the firmware-integration step, layered on
//! this primitive. ml-kem is RustCrypto-ACVP-validated; on-target NIST-vector
//! + constant-time validation of the decaps path remains a hardware follow-up
//! (README §acceptance).

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use ml_kem::kem::{Ciphertext, Decapsulate};
use ml_kem::{B32, DecapsulationKey, MlKem1024, Seed};
use zeroize::Zeroize;

/// ML-KEM-1024 ciphertext length (FIPS 203).
pub const CT_LEN: usize = 1568;
/// AES-256-GCM authentication tag length.
pub const TAG_LEN: usize = 16;
/// Device keypair seed length (`d‖z`); the deterministic "secret key".
pub const SEED_LEN: usize = 64;
/// Fresh encapsulation-message length the caller must supply per `seal`.
pub const ENCAPS_MSG_LEN: usize = 32;
/// Bytes `seal` adds on top of the plaintext: `ct ‖ tag`.
pub const OVERHEAD: usize = CT_LEN + TAG_LEN;

/// Domain-separation AAD bound into every GCM seal/open.
const AAD: &[u8] = b"pqsigner-inner-wrap-v1";
/// KEM-DEM: `K` is unique per seal, so a fixed nonce keeps `(K, nonce)` unique.
const NONCE: [u8; 12] = [0u8; 12];

/// Sealing or opening failed (buffer too small, or — for `open` — the GCM tag
/// did not authenticate: tampered ciphertext or wrong device seed). Carries no
/// detail by design (no oracle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapError;

/// Exact sealed length for a plaintext of `pt_len` bytes.
#[must_use]
pub const fn sealed_len(pt_len: usize) -> usize {
    CT_LEN + pt_len + TAG_LEN
}

fn dk_from_seed(seed: &[u8; SEED_LEN]) -> DecapsulationKey<MlKem1024> {
    DecapsulationKey::<MlKem1024>::from_seed(Seed::from(*seed))
}

/// Encrypt-to-self seal `plaintext` under the device keypair derived from
/// `seed`, using `encaps_msg` (fresh TRNG) as the ML-KEM encapsulation
/// randomness. Writes `ct ‖ aead` into `out`; returns the byte count
/// (`sealed_len(plaintext.len())`).
///
/// # Errors
/// [`WrapError`] if `out` is shorter than `sealed_len(plaintext.len())`.
pub fn seal(
    seed: &[u8; SEED_LEN],
    encaps_msg: &[u8; ENCAPS_MSG_LEN],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, WrapError> {
    let total = sealed_len(plaintext.len());
    if out.len() < total {
        return Err(WrapError);
    }
    let dk = dk_from_seed(seed);
    let (ct, mut shared) = dk
        .encapsulation_key()
        .encapsulate_deterministic(&B32::from(*encaps_msg));

    out[..CT_LEN].copy_from_slice(&ct[..]);
    let pt_end = CT_LEN + plaintext.len();
    out[CT_LEN..pt_end].copy_from_slice(plaintext);

    let result = (|| {
        let cipher = Aes256Gcm::new_from_slice(&shared[..]).map_err(|_| WrapError)?;
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&NONCE), AAD, &mut out[CT_LEN..pt_end])
            .map_err(|_| WrapError)?;
        out[pt_end..total].copy_from_slice(tag.as_slice());
        Ok(total)
    })();
    shared.zeroize();
    result
}

/// Open a `ct ‖ aead` blob produced by [`seal`] under the device keypair
/// derived from `seed`. Writes the recovered plaintext into `out`; returns its
/// length (`sealed.len() - OVERHEAD`).
///
/// # Errors
/// [`WrapError`] if `sealed` is malformed/too short, `out` is too small, or the
/// GCM tag fails to authenticate (tampered blob or wrong `seed`).
pub fn open(seed: &[u8; SEED_LEN], sealed: &[u8], out: &mut [u8]) -> Result<usize, WrapError> {
    if sealed.len() < OVERHEAD {
        return Err(WrapError);
    }
    let pt_len = sealed.len() - OVERHEAD;
    if out.len() < pt_len {
        return Err(WrapError);
    }
    let ct = Ciphertext::<MlKem1024>::try_from(&sealed[..CT_LEN]).map_err(|_| WrapError)?;
    let dk = dk_from_seed(seed);
    let mut shared = dk.decapsulate(&ct);

    let pt_end = CT_LEN + pt_len;
    out[..pt_len].copy_from_slice(&sealed[CT_LEN..pt_end]);
    let tag = Tag::from_slice(&sealed[pt_end..]);

    let result = (|| {
        let cipher = Aes256Gcm::new_from_slice(&shared[..]).map_err(|_| WrapError)?;
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(&NONCE), AAD, &mut out[..pt_len], tag)
            .map_err(|_| WrapError)?;
        Ok(pt_len)
    })();
    shared.zeroize();
    if result.is_err() {
        out[..pt_len].zeroize(); // never leave a half-decrypted plaintext on a tag failure
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; SEED_LEN] = [0x42; SEED_LEN];
    const MSG: [u8; ENCAPS_MSG_LEN] = [0x17; ENCAPS_MSG_LEN];
    const HALF: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];

    #[test]
    fn round_trip_32b_half() {
        let mut sealed = [0u8; sealed_len(32)];
        let n = seal(&SEED, &MSG, &HALF, &mut sealed).unwrap();
        assert_eq!(n, sealed.len());
        assert_eq!(n, CT_LEN + 32 + TAG_LEN);
        let mut out = [0u8; 32];
        let m = open(&SEED, &sealed, &mut out).unwrap();
        assert_eq!(m, 32);
        assert_eq!(out, HALF);
    }

    #[test]
    fn ciphertext_is_not_the_plaintext() {
        // The plaintext half must NOT appear verbatim in the sealed blob.
        let mut sealed = [0u8; sealed_len(32)];
        seal(&SEED, &MSG, &HALF, &mut sealed).unwrap();
        assert!(
            !sealed.windows(32).any(|w| w == HALF),
            "plaintext leaked into the sealed blob"
        );
    }

    #[test]
    fn deterministic_given_seed_and_msg() {
        let mut a = [0u8; sealed_len(32)];
        let mut b = [0u8; sealed_len(32)];
        seal(&SEED, &MSG, &HALF, &mut a).unwrap();
        seal(&SEED, &MSG, &HALF, &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn fresh_encaps_msg_changes_ciphertext() {
        let mut a = [0u8; sealed_len(32)];
        let mut b = [0u8; sealed_len(32)];
        seal(&SEED, &MSG, &HALF, &mut a).unwrap();
        let msg2 = [0x18; ENCAPS_MSG_LEN];
        seal(&SEED, &msg2, &HALF, &mut b).unwrap();
        assert_ne!(a, b, "different encaps randomness must yield a different ct");
        // ...but both still open to the same half.
        let (mut oa, mut ob) = ([0u8; 32], [0u8; 32]);
        open(&SEED, &a, &mut oa).unwrap();
        open(&SEED, &b, &mut ob).unwrap();
        assert_eq!(oa, HALF);
        assert_eq!(ob, HALF);
    }

    #[test]
    fn tamper_in_ct_region_fails() {
        let mut sealed = [0u8; sealed_len(32)];
        seal(&SEED, &MSG, &HALF, &mut sealed).unwrap();
        sealed[10] ^= 1; // flip a byte inside the ML-KEM ciphertext
        let mut out = [0u8; 32];
        assert_eq!(open(&SEED, &sealed, &mut out), Err(WrapError));
    }

    #[test]
    fn tamper_in_aead_region_fails() {
        let mut sealed = [0u8; sealed_len(32)];
        seal(&SEED, &MSG, &HALF, &mut sealed).unwrap();
        let i = CT_LEN + 5; // inside the AEAD ciphertext
        sealed[i] ^= 1;
        let mut out = [0u8; 32];
        assert_eq!(open(&SEED, &sealed, &mut out), Err(WrapError));
    }

    #[test]
    fn wrong_seed_fails_via_tag() {
        // ML-KEM decaps never errors (implicit rejection) → a wrong seed yields
        // a pseudo-random K → the GCM tag is what rejects.
        let mut sealed = [0u8; sealed_len(32)];
        seal(&SEED, &MSG, &HALF, &mut sealed).unwrap();
        let mut other = SEED;
        other[0] ^= 1;
        let mut out = [0u8; 32];
        assert_eq!(open(&other, &sealed, &mut out), Err(WrapError));
    }

    #[test]
    fn empty_and_buffer_bounds() {
        // empty plaintext round-trips
        let mut sealed = [0u8; sealed_len(0)];
        seal(&SEED, &MSG, &[], &mut sealed).unwrap();
        let mut out = [0u8; 0];
        assert_eq!(open(&SEED, &sealed, &mut out).unwrap(), 0);
        // too-small out for seal
        let mut tiny = [0u8; CT_LEN]; // no room for plaintext+tag
        assert_eq!(seal(&SEED, &MSG, &HALF, &mut tiny), Err(WrapError));
        // too-short sealed for open
        assert_eq!(open(&SEED, &[0u8; OVERHEAD - 1], &mut [0u8; 0]), Err(WrapError));
    }
}
