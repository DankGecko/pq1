#![no_std]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
//! **Hybrid** ML-KEM-1024 + HUK + AES-256-GCM **encrypt-to-self inner wrap**
//! (invariant #3 PQ confidentiality layer; README "ML-KEM-1024 inner wrap
//! planned").
//!
//! ## Why
//!
//! The dual-SE entropy halves (`half_O` on OPTIGA, `half_E` on SE050) cross
//! I²C under the SEs' *classical* secure channels — OPTIGA Shielded Connection
//! (AES-128-CCM-8) and SE050 SCP03 (AES-CMAC/CBC), whose session keys derive
//! from classical primitives. A **Harvest-Now-Decrypt-Later (HNDL)** adversary
//! records the bus today and decrypts once a CRQC exists. This crate seals each
//! half to PQ-opaque ciphertext *before* it touches I²C.
//!
//! ## Why HYBRID (not ML-KEM-only)
//!
//! The MCU seals AND opens — encrypt-to-self. For self-sealed data, ML-KEM-only
//! would be *strictly weaker* than AES-256-GCM under a HUK key: it adds a
//! "break ML-KEM" recovery path (ct → shared secret) that needs **no physical
//! access**, resting on the lattice assumption the project distrusts for the
//! signing key (SPHINCS+ is used precisely because hashes have a longer
//! cryptanalytic track record). So the AEAD key is derived from **both**:
//!
//! ```text
//!   K = HMAC-SHA256(key = huk_secret, msg = mlkem_shared_secret ‖ aad ‖ tag)
//! ```
//!
//! - **Break ML-KEM alone** (recover `mlkem_shared_secret` from `ct`): still
//!   needs `huk_secret` to form `K` → useless without physically extracting the
//!   specific U585 die's HUK.
//! - **Extract HUK alone**: still needs `mlkem_shared_secret`, which requires
//!   the ML-KEM `dk` (= the HUK-derived seed) — i.e. the HUK again — or breaking
//!   the lattice.
//!
//! `K` can therefore never drop below the AES-256/HUK floor, while ML-KEM keeps
//! the NIST-PQC confidentiality layer for defence-in-depth and crypto-agility.
//! (Design rationale: `docs/security/ml-kem-inner-wrap.md`.)
//!
//! ## Construction — KEM-DEM with a hybrid key
//!
//! The MCU holds ONE ML-KEM-1024 keypair derived deterministically from a
//! HUK-bound 64-byte `seed` (`from_seed`; nothing lattice-secret is stored, on
//! a bus, or on an SE). Per seal:
//!
//! ```text
//! seal(seed, m, huk, aad, pt):              open(seed, huk, aad, ct‖aead):
//!   dk = ML-KEM.from_seed(seed)               dk = ML-KEM.from_seed(seed)
//!   (ct, ss) = Encaps(dk.ek; m)               ss = Decaps(dk, ct)
//!   K = HMAC(huk, ss ‖ aad ‖ tag)             K  = HMAC(huk, ss ‖ aad ‖ tag)
//!   n = SHA256("…nonce" ‖ ct ‖ aad)[..12]     n  = SHA256("…nonce" ‖ ct ‖ aad)[..12]
//!   aead = AES-256-GCM(K, n, aad, pt)         pt = AES-256-GCM.open(K, n, aad, aead)
//!   store ct ‖ aead                           return pt
//! ```
//!
//! A fresh `ss` is produced for every seal (the encapsulation message `m` is
//! fresh TRNG), so `(K, n)` is unique. ML-KEM decapsulation uses *implicit
//! rejection* (never errors); the **GCM tag** authenticates, so a tampered
//! `ct`/`aead`, the wrong `seed`, the wrong `huk`, or the wrong `aad` all fail.
//! The caller binds `aad` = (chip-id ‖ half-id ‖ `account_index`) so a blob can
//! never be replayed as the other half or another account.
//!
//! ## Scope
//!
//! Pure `no_std` logic. The caller (secure world) supplies the HUK-bound `seed`
//! (`hw::huk`), the `huk_secret` (a second independent `hw::huk` label), fresh
//! TRNG `encaps_msg`, and the context `aad`. Firmware wiring (OPTIGA/SE050
//! store+read, object sizing) is the integration step. ml-kem is
//! RustCrypto-ACVP-validated; on-target NIST-vector + constant-time validation
//! of the decaps path is a hardware follow-up.

pub mod dual_se;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use hmac::{Hmac, Mac};
use ml_kem::kem::{Ciphertext, Decapsulate};
use ml_kem::{B32, DecapsulationKey, MlKem1024, Seed};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// ML-KEM-1024 ciphertext length (FIPS 203).
pub const CT_LEN: usize = 1568;
/// AES-256-GCM authentication tag length.
pub const TAG_LEN: usize = 16;
/// Device keypair seed length (`d‖z`); the deterministic ML-KEM "secret key".
pub const SEED_LEN: usize = 64;
/// HUK secret length (a `hw::huk::derive_device_key` output).
pub const HUK_LEN: usize = 32;
/// Fresh encapsulation-message length the caller must supply per `seal`.
pub const ENCAPS_MSG_LEN: usize = 32;
/// Bytes `seal` adds on top of the plaintext: `ct ‖ tag`.
pub const OVERHEAD: usize = CT_LEN + TAG_LEN;

/// Domain-separation tag bound into the hybrid KDF.
const KDF_TAG: &[u8] = b"pqsigner-inner-wrap-v1-kdf";
/// Domain-separation tag bound into the nonce derivation.
const NONCE_TAG: &[u8] = b"pqsigner-inner-wrap-v1-nonce";

/// Sealing or opening failed (buffer too small, or — for `open` — the GCM tag
/// did not authenticate: tampered ciphertext, wrong device seed, wrong HUK, or
/// wrong context AAD). Carries no detail by design (no oracle).
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

/// Hybrid AEAD key: HMAC-SHA256 keyed by the HUK secret over the ML-KEM shared
/// secret + context. Binds `K` to BOTH the lattice secret and the device HUK.
fn derive_key(huk_secret: &[u8; HUK_LEN], mlkem_ss: &[u8], aad: &[u8]) -> [u8; 32] {
    // HMAC accepts any key length and never errors on construction.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(huk_secret).expect("hmac key");
    mac.update(mlkem_ss);
    mac.update(aad);
    mac.update(KDF_TAG);
    let prk = mac.finalize().into_bytes();
    let mut k = [0u8; 32];
    k.copy_from_slice(&prk);
    k
}

/// Deterministic GCM nonce bound to the ciphertext + context (recomputed at
/// `open` from the stored `ct`, so it is not transmitted).
fn derive_nonce(ct: &[u8], aad: &[u8]) -> [u8; 12] {
    let mut h = Sha256::new();
    h.update(NONCE_TAG);
    h.update(ct);
    h.update(aad);
    let d = h.finalize();
    let mut n = [0u8; 12];
    n.copy_from_slice(&d[..12]);
    n
}

/// Hybrid encrypt-to-self seal of `plaintext`. Derives the ML-KEM keypair from
/// `seed`, encapsulates with `encaps_msg` (fresh TRNG), forms the hybrid AEAD
/// key from the shared secret + `huk_secret`, and seals under context `aad`
/// (e.g. chip-id ‖ half-id ‖ `account_index`). Writes `ct ‖ aead` into `out`;
/// returns `sealed_len(plaintext.len())`.
///
/// # Errors
/// [`WrapError`] if `out` is shorter than `sealed_len(plaintext.len())`.
pub fn seal(
    seed: &[u8; SEED_LEN],
    encaps_msg: &[u8; ENCAPS_MSG_LEN],
    huk_secret: &[u8; HUK_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, WrapError> {
    let total = sealed_len(plaintext.len());
    if out.len() < total {
        return Err(WrapError);
    }
    let dk = dk_from_seed(seed);
    let (ct, mut ss) = dk
        .encapsulation_key()
        .encapsulate_deterministic(&B32::from(*encaps_msg));

    let mut k = derive_key(huk_secret, &ss[..], aad);
    ss.zeroize();
    let nonce = derive_nonce(&ct[..], aad);

    out[..CT_LEN].copy_from_slice(&ct[..]);
    let pt_end = CT_LEN + plaintext.len();
    out[CT_LEN..pt_end].copy_from_slice(plaintext);

    let result = (|| {
        let cipher = Aes256Gcm::new_from_slice(&k).map_err(|_| WrapError)?;
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, &mut out[CT_LEN..pt_end])
            .map_err(|_| WrapError)?;
        out[pt_end..total].copy_from_slice(tag.as_slice());
        Ok(total)
    })();
    k.zeroize();
    result
}

/// Open a `ct ‖ aead` blob produced by [`seal`] under the same `seed`,
/// `huk_secret`, and context `aad`. Writes the recovered plaintext into `out`;
/// returns its length.
///
/// # Errors
/// [`WrapError`] if `sealed` is malformed/too short, `out` is too small, or the
/// GCM tag fails to authenticate (tampered blob, wrong `seed`, wrong
/// `huk_secret`, or wrong `aad`).
pub fn open(
    seed: &[u8; SEED_LEN],
    huk_secret: &[u8; HUK_LEN],
    aad: &[u8],
    sealed: &[u8],
    out: &mut [u8],
) -> Result<usize, WrapError> {
    if sealed.len() < OVERHEAD {
        return Err(WrapError);
    }
    let pt_len = sealed.len() - OVERHEAD;
    if out.len() < pt_len {
        return Err(WrapError);
    }
    let ct = Ciphertext::<MlKem1024>::try_from(&sealed[..CT_LEN]).map_err(|_| WrapError)?;
    let dk = dk_from_seed(seed);
    let mut ss = dk.decapsulate(&ct);

    let mut k = derive_key(huk_secret, &ss[..], aad);
    ss.zeroize();
    let nonce = derive_nonce(&sealed[..CT_LEN], aad);

    let pt_end = CT_LEN + pt_len;
    out[..pt_len].copy_from_slice(&sealed[CT_LEN..pt_end]);
    let tag = Tag::from_slice(&sealed[pt_end..]);

    let result = (|| {
        let cipher = Aes256Gcm::new_from_slice(&k).map_err(|_| WrapError)?;
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), aad, &mut out[..pt_len], tag)
            .map_err(|_| WrapError)?;
        Ok(pt_len)
    })();
    k.zeroize();
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
    const HUK: [u8; HUK_LEN] = [0xA5; HUK_LEN];
    const AAD: &[u8] = b"optiga:half_O:acct0";
    const HALF: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];

    fn seal_half(seed: &[u8; 64], msg: &[u8; 32], huk: &[u8; 32], aad: &[u8]) -> [u8; sealed_len(32)] {
        let mut sealed = [0u8; sealed_len(32)];
        seal(seed, msg, huk, aad, &HALF, &mut sealed).unwrap();
        sealed
    }

    #[test]
    fn round_trip_32b_half() {
        let sealed = seal_half(&SEED, &MSG, &HUK, AAD);
        assert_eq!(sealed.len(), CT_LEN + 32 + TAG_LEN);
        let mut out = [0u8; 32];
        assert_eq!(open(&SEED, &HUK, AAD, &sealed, &mut out).unwrap(), 32);
        assert_eq!(out, HALF);
    }

    #[test]
    fn ciphertext_is_not_the_plaintext() {
        let sealed = seal_half(&SEED, &MSG, &HUK, AAD);
        assert!(!sealed.windows(32).any(|w| w == HALF), "plaintext leaked");
    }

    #[test]
    fn deterministic_given_all_inputs() {
        assert_eq!(seal_half(&SEED, &MSG, &HUK, AAD), seal_half(&SEED, &MSG, &HUK, AAD));
    }

    #[test]
    fn fresh_encaps_msg_changes_ciphertext_but_opens_same() {
        let a = seal_half(&SEED, &MSG, &HUK, AAD);
        let b = seal_half(&SEED, &[0x18; 32], &HUK, AAD);
        assert_ne!(a, b);
        let (mut oa, mut ob) = ([0u8; 32], [0u8; 32]);
        open(&SEED, &HUK, AAD, &a, &mut oa).unwrap();
        open(&SEED, &HUK, AAD, &b, &mut ob).unwrap();
        assert_eq!(oa, HALF);
        assert_eq!(ob, HALF);
    }

    #[test]
    fn hybrid_floor_wrong_huk_fails() {
        // THE hybrid property: correct seed + ct, but a wrong HUK → wrong K →
        // tag fails. A future ML-KEM break (recovering ss) without the HUK
        // therefore cannot recover the half.
        let sealed = seal_half(&SEED, &MSG, &HUK, AAD);
        let mut other = HUK;
        other[0] ^= 1;
        let mut out = [0u8; 32];
        assert_eq!(open(&SEED, &other, AAD, &sealed, &mut out), Err(WrapError));
    }

    #[test]
    fn wrong_seed_fails() {
        let sealed = seal_half(&SEED, &MSG, &HUK, AAD);
        let mut other = SEED;
        other[0] ^= 1;
        let mut out = [0u8; 32];
        assert_eq!(open(&other, &HUK, AAD, &sealed, &mut out), Err(WrapError));
    }

    #[test]
    fn wrong_aad_fails_no_cross_context_replay() {
        // A blob sealed as half_O / acct0 cannot open as half_E / acct1.
        let sealed = seal_half(&SEED, &MSG, &HUK, AAD);
        let mut out = [0u8; 32];
        assert_eq!(open(&SEED, &HUK, b"se050:half_E:acct1", &sealed, &mut out), Err(WrapError));
    }

    #[test]
    fn tamper_ct_and_aead_fail() {
        for i in [10usize, CT_LEN + 5] {
            let mut sealed = seal_half(&SEED, &MSG, &HUK, AAD);
            sealed[i] ^= 1;
            let mut out = [0u8; 32];
            assert_eq!(open(&SEED, &HUK, AAD, &sealed, &mut out), Err(WrapError));
        }
    }

    #[test]
    fn empty_and_buffer_bounds() {
        let mut sealed = [0u8; sealed_len(0)];
        seal(&SEED, &MSG, &HUK, AAD, &[], &mut sealed).unwrap();
        assert_eq!(open(&SEED, &HUK, AAD, &sealed, &mut [0u8; 0]).unwrap(), 0);
        let mut tiny = [0u8; CT_LEN];
        assert_eq!(seal(&SEED, &MSG, &HUK, AAD, &HALF, &mut tiny), Err(WrapError));
        assert_eq!(open(&SEED, &HUK, AAD, &[0u8; OVERHEAD - 1], &mut [0u8; 0]), Err(WrapError));
    }
}
