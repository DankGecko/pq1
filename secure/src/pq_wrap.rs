//! Firmware adapter binding the pure [`pqsigner_pq_seal`] hybrid inner wrap to
//! the device-bound key derivation ([`crate::hw::secret_keys`]) and the TRNG
//! ([`crate::rng`]).
//!
//! The ML-KEM-1024 keypair seed (64 B) and the hybrid HUK secret (32 B) come
//! from two distinct `secret_keys` labels — per-die, deterministic across
//! boots, never stored in plaintext (production: `SAES-CMAC(DHUK, …)`; dev/QEMU:
//! `HKDF(OTP-master, …)`). `seal_half_hw` draws a fresh 32-byte encapsulation
//! message from the TRNG. The return is the `(ct, aead)` storage split
//! (`docs/security/ml-kem-inner-wrap.md`): `ct` (1568 B) → MCU flash, `aead`
//! (48 B) → the SE. This is the bridge layer; the provision/reconstruct
//! rewiring (piece 2b) calls these.

use pqsigner_pq_seal::dual_se::{open_half, seal_half, AEAD_LEN, HALF_LEN};
use pqsigner_pq_seal::CT_LEN;
use zeroize::Zeroize;

// Which SE a half lives on — re-exported for the dual-SE provision/reconstruct
// wiring (`crate::dual_se`).
pub use pqsigner_pq_seal::dual_se::HalfId;

/// Opaque inner-wrap failure (key derivation, TRNG, or AEAD tag). No detail by
/// design — never an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapError;

/// Derive the (64-byte ML-KEM seed, 32-byte hybrid HUK secret) from the device
/// key hierarchy (production hardware). Two independent labels, so a future
/// ML-KEM break alone can't recover a half without the HUK secret.
#[cfg(feature = "stm32u585")]
fn device_keys() -> Result<([u8; 64], [u8; 32]), WrapError> {
    use crate::hw::secret_keys;
    let seed = secret_keys::mlkem_seed().map_err(|_| WrapError)?;
    let huk_secret = secret_keys::mlkem_wrap_secret().map_err(|_| WrapError)?;
    Ok((seed, huk_secret))
}

/// QEMU/host DEV key path. The device key hierarchy (`hw::{otp,
/// secret_keys}`) is `stm32u585`-only, so off-target we derive DETERMINISTIC
/// TEST keys from a fixed dev constant — this is what lets `make e2e` exercise
/// the seal/open round-trip. NEVER a production path: `not(stm32u585)` is by
/// definition a non-shipping (QEMU / host-test) build.
#[cfg(not(feature = "stm32u585"))]
fn device_keys() -> Result<([u8; 64], [u8; 32]), WrapError> {
    Ok((
        dev_derive::<64>(b"mlkem-seed-v1"),
        dev_derive::<32>(b"mlkem-wrap-huk-v1"),
    ))
}

/// SHA-256-counter expansion of a fixed dev master into `N` deterministic
/// bytes (QEMU/host only — see [`device_keys`]).
#[cfg(not(feature = "stm32u585"))]
fn dev_derive<const N: usize>(label: &[u8]) -> [u8; N] {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; N];
    let mut offset = 0usize;
    let mut counter = 0u8;
    while offset < N {
        let mut h = Sha256::new();
        h.update(b"pqsigner-mlkem-QEMU-DEV-master-v1");
        h.update(label);
        h.update([counter]);
        let block = h.finalize();
        let take = core::cmp::min(32, N - offset);
        out[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
        counter += 1;
    }
    out
}

/// Seal a 256-bit `half` for `(half_id, account_index)` under the device
/// keypair + a fresh TRNG encapsulation message. Returns `(ct, aead)`.
///
/// # Errors
/// [`WrapError`] on HUK-derivation failure, TRNG failure, or an internal AEAD
/// failure.
pub fn seal_half_hw(
    half_id: HalfId,
    account_index: u32,
    half: &[u8; HALF_LEN],
) -> Result<([u8; CT_LEN], [u8; AEAD_LEN]), WrapError> {
    let (mut seed, mut huk_secret) = device_keys()?;
    let mut m = [0u8; 32];
    let res = (|| {
        crate::rng::fill(&mut m).map_err(|()| WrapError)?;
        seal_half(&seed, &huk_secret, &m, half_id, account_index, half).map_err(|_| WrapError)
    })();
    seed.zeroize();
    huk_secret.zeroize();
    m.zeroize();
    res
}

/// Recover a half from its `(ct, aead)` split under the device keypair.
///
/// # Errors
/// [`WrapError`] on HUK-derivation failure or a tag mismatch (tampered
/// `ct`/`aead`, wrong device, or a `(half_id, account_index)` mismatch).
pub fn open_half_hw(
    half_id: HalfId,
    account_index: u32,
    ct: &[u8; CT_LEN],
    aead: &[u8; AEAD_LEN],
) -> Result<[u8; HALF_LEN], WrapError> {
    let (mut seed, mut huk_secret) = device_keys()?;
    let res =
        open_half(&seed, &huk_secret, half_id, account_index, ct, aead).map_err(|_| WrapError);
    seed.zeroize();
    huk_secret.zeroize();
    res
}

/// SRAM-backed `(ct ‖ tag)` store for the two sealed halves, indexed by
/// [`HalfId`]. The dual-SE wiring stores the 1568-byte ML-KEM `ct` + 16-byte
/// GCM tag here while the 32-byte GCM ciphertext goes to the SE.
///
/// **This is the QEMU-validation backing.** The e2e provisions + reconstructs
/// in one boot, so SRAM suffices. The PERSISTENT store is the hardware
/// finalization (piece 2b "d"): the secure flash is FULL (firmware fills
/// pages 0-122, persistent stores fill 123-127), so a real `ct` store needs
/// either an NS-flash bank-2 region or a FLASH-shrink to free a page — and
/// that placement must be validated against the secure watermark on real
/// silicon, which QEMU can't check. See `docs/security/ml-kem-inner-wrap.md`.
#[cfg(feature = "mlkem-inner-wrap")]
pub mod ct_store {
    use super::HalfId;
    use core::ptr::addr_of_mut;
    use pqsigner_pq_seal::{CT_LEN, TAG_LEN};

    const SLOT: usize = CT_LEN + TAG_LEN; // 1584
    static mut STORE: [[u8; SLOT]; 2] = [[0u8; SLOT]; 2];
    static mut PRESENT: [bool; 2] = [false, false];

    const fn idx(half: HalfId) -> usize {
        match half {
            HalfId::OptigaHalfO => 0,
            HalfId::Se050HalfE => 1,
        }
    }

    /// Store `(ct, tag)` for `half`.
    pub fn put(half: HalfId, ct: &[u8; CT_LEN], tag: &[u8; TAG_LEN]) {
        let i = idx(half);
        // SAFETY: the secure world is single-threaded; no concurrent access to
        // STORE/PRESENT. `addr_of_mut!` avoids a `static_mut_refs` reference.
        unsafe {
            let slot = &mut (*addr_of_mut!(STORE))[i];
            slot[..CT_LEN].copy_from_slice(ct);
            slot[CT_LEN..].copy_from_slice(tag);
            (*addr_of_mut!(PRESENT))[i] = true;
        }
    }

    /// Load `(ct, tag)` for `half`, if a `put` has occurred.
    #[must_use]
    pub fn get(half: HalfId) -> Option<([u8; CT_LEN], [u8; TAG_LEN])> {
        let i = idx(half);
        // SAFETY: single-threaded; reads after `put`.
        unsafe {
            if !(*addr_of_mut!(PRESENT))[i] {
                return None;
            }
            let slot = &(*addr_of_mut!(STORE))[i];
            let mut ct = [0u8; CT_LEN];
            ct.copy_from_slice(&slot[..CT_LEN]);
            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(&slot[CT_LEN..]);
            Some((ct, tag))
        }
    }
}

/// Seal a half for SE storage under the inner wrap (provision path): stashes
/// `(ct, tag)` in the ct-store and returns the 32-byte AES-GCM ciphertext to
/// hand to the SE in place of the raw half (so the SE object size is unchanged
/// and what crosses I²C is PQ-opaque).
///
/// # Errors
/// [`WrapError`] on key-derivation / TRNG / AEAD failure.
#[cfg(feature = "mlkem-inner-wrap")]
pub fn seal_half_for_se(
    half_id: HalfId,
    account_index: u32,
    half: &[u8; HALF_LEN],
) -> Result<[u8; 32], WrapError> {
    let (ct, aead) = seal_half_hw(half_id, account_index, half)?; // aead = gcm_ct(32) ‖ tag(16)
    let mut tag = [0u8; pqsigner_pq_seal::TAG_LEN];
    tag.copy_from_slice(&aead[32..]);
    ct_store::put(half_id, &ct, &tag);
    let mut gcm_ct = [0u8; 32];
    gcm_ct.copy_from_slice(&aead[..32]);
    Ok(gcm_ct)
}

/// Recover a half under the inner wrap (reconstruct path): takes the 32-byte
/// AES-GCM ciphertext read back from the SE, fetches `(ct, tag)` from the
/// ct-store, reassembles the AEAD blob, and opens it.
///
/// # Errors
/// [`WrapError`] if the ct-store has no entry or the GCM tag fails.
#[cfg(feature = "mlkem-inner-wrap")]
pub fn open_half_from_se(
    half_id: HalfId,
    account_index: u32,
    gcm_ct: &[u8; 32],
) -> Result<[u8; HALF_LEN], WrapError> {
    let (ct, tag) = ct_store::get(half_id).ok_or(WrapError)?;
    let mut aead = [0u8; AEAD_LEN];
    aead[..32].copy_from_slice(gcm_ct);
    aead[32..].copy_from_slice(&tag);
    open_half_hw(half_id, account_index, &ct, &aead)
}

/// Boot self-test (feature `mlkem-self-test`): round-trips a dummy half through
/// the real HUK-derived keypair + the TRNG and checks cross-half rejection.
/// Returns `true` on PASS. This is the call that pulls ml-kem into the image,
/// so the flash delta is measurable by building with vs without the feature.
#[cfg(feature = "mlkem-self-test")]
pub fn self_test() -> bool {
    let half = [0x5Au8; HALF_LEN];
    let Ok((ct, aead)) = seal_half_hw(HalfId::OptigaHalfO, 0, &half) else {
        return false;
    };
    // Correct round-trip recovers the half.
    match open_half_hw(HalfId::OptigaHalfO, 0, &ct, &aead) {
        Ok(got) if got == half => {}
        _ => return false,
    }
    // Cross-half must fail (AAD domain separation).
    if open_half_hw(HalfId::Se050HalfE, 0, &ct, &aead).is_ok() {
        return false;
    }
    // When the wrap is wired, also exercise the SE-storage SPLIT exactly as the
    // dual-SE provision/reconstruct does it: seal → (gcm_ct to the SE, ct+tag to
    // the ct-store) → open_half_from_se. This validates the plumbing the
    // hardware-only `dual_se` path uses, on QEMU.
    #[cfg(feature = "mlkem-inner-wrap")]
    {
        let Ok(gcm_ct) = seal_half_for_se(HalfId::OptigaHalfO, 0, &half) else {
            return false;
        };
        match open_half_from_se(HalfId::OptigaHalfO, 0, &gcm_ct) {
            Ok(got) if got == half => {}
            _ => return false,
        }
    }
    true
}
