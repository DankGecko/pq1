//! Crypto helpers: KDF, AES-GCM wrap/unwrap, PIN state ser/de, and on-unlock
//! SLH-DSA key derivation from a stored seed.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

use crate::secure_element::SecureElement;
use slh_dsa::{Sha2_128f, SigningKey};
use sphincs_tz_shared::MAX_ATTEMPTS;
use zeroize::Zeroize;

// r-mem slot assignments
pub const RMEM_ENCRYPTED_SEED: u16 = 0;
pub const RMEM_PIN_STATE: u16 = 1;
pub const RMEM_VERIFYING_KEY: u16 = 2;

/// Length of the SLH-DSA-Sha2_128f seed material:
/// `sk_seed (16) ‖ sk_prf (16) ‖ pk_seed (16)`. The fourth field of a
/// serialized SigningKey, `pk_root` (16 B), is computed deterministically
/// from these three on every unlock — that's the whole point of "store the
/// seed, derive the key".
pub const SEED_LEN: usize = 48;

/// Total stored blob: 12-byte nonce ‖ encrypted_seed (48) ‖ AES-GCM tag (16).
pub const SEED_BLOB_LEN: usize = 12 + SEED_LEN + 16;

// ---------------------------------------------------------------------------
// KDF helpers
// ---------------------------------------------------------------------------

pub fn kdf(domain: &[u8], input: &[u8], index: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(input);
    h.update([index]);
    h.finalize().into()
}

pub fn macd_init_input(master_secret: &[u8; 32], j: u8) -> [u8; 32] {
    kdf(b"sphincs-macd-init", master_secret, j)
}

pub fn macd_pin_input(pin: &[u8; 8], j: u8) -> [u8; 32] {
    kdf(b"sphincs-macd-pin", pin, j)
}

pub fn derive_wrap_key(master_secret: &[u8; 32]) -> [u8; 32] {
    kdf(b"sphincs-wrap-key", master_secret, 0)
}

pub fn derive_seed_nonce(master_secret: &[u8; 32]) -> [u8; 12] {
    let h = kdf(b"sphincs-seed-nonce", master_secret, 0);
    let mut n = [0u8; 12];
    n.copy_from_slice(&h[..12]);
    n
}

fn nonce_for(index: u8) -> [u8; 12] {
    let h: [u8; 32] = kdf(b"sphincs-nonce", &[index], 0);
    let mut n = [0u8; 12];
    n.copy_from_slice(&h[..12]);
    n
}

// ---------------------------------------------------------------------------
// AES-GCM helpers (in-place, no_std)
// ---------------------------------------------------------------------------

pub fn aes_encrypt_inplace(
    key: &[u8; 32],
    buf: &mut [u8],
    plaintext_len: usize,
    nonce_idx: u8,
) -> usize {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = nonce_for(nonce_idx);
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut buf[..plaintext_len])
        .expect("AES-GCM encrypt failed");
    buf[plaintext_len..plaintext_len + 16].copy_from_slice(&tag);
    plaintext_len + 16
}

pub fn aes_decrypt_inplace(
    key: &[u8; 32],
    buf: &mut [u8],
    ct_len: usize,
    nonce_idx: u8,
) -> Result<usize, ()> {
    if ct_len < 16 {
        return Err(());
    }
    let plaintext_len = ct_len - 16;
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = nonce_for(nonce_idx);
    let (ct, tag_bytes) = buf[..ct_len].split_at_mut(plaintext_len);
    let tag = aes_gcm::Tag::from_slice(tag_bytes);
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(&nonce), &[], ct, tag)
        .map_err(|_| ())?;
    Ok(plaintext_len)
}

// ---------------------------------------------------------------------------
// Seed encryption/decryption with the master secret
// ---------------------------------------------------------------------------

/// Encrypt a 48-byte SLH-DSA seed under the wrap key derived from
/// `master_secret`. Output layout: `nonce(12) ‖ ciphertext(48) ‖ tag(16)`.
pub fn encrypt_seed_blob(seed: &[u8; SEED_LEN], master_secret: &[u8; 32]) -> [u8; SEED_BLOB_LEN] {
    let mut wrap = derive_wrap_key(master_secret);
    let nonce = derive_seed_nonce(master_secret);

    let mut blob = [0u8; SEED_BLOB_LEN];
    blob[..12].copy_from_slice(&nonce);
    blob[12..12 + SEED_LEN].copy_from_slice(seed);

    let cipher = Aes256Gcm::new_from_slice(&wrap).unwrap();
    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &[],
            &mut blob[12..12 + SEED_LEN],
        )
        .expect("seed encryption");
    blob[12 + SEED_LEN..].copy_from_slice(&tag);

    wrap.zeroize();
    blob
}

/// Decrypt a stored seed blob with the master secret. Returns the 48-byte
/// seed material on success.
pub fn decrypt_seed_blob(blob: &[u8], master_secret: &[u8; 32]) -> Result<[u8; SEED_LEN], ()> {
    if blob.len() != SEED_BLOB_LEN {
        return Err(());
    }
    let mut wrap = derive_wrap_key(master_secret);
    // The nonce stored at the head of the blob; we trust it because the
    // wrap_key is master-bound.
    let nonce: [u8; 12] = blob[..12].try_into().unwrap();
    let mut seed_buf = [0u8; SEED_LEN];
    seed_buf.copy_from_slice(&blob[12..12 + SEED_LEN]);
    let tag = aes_gcm::Tag::from_slice(&blob[12 + SEED_LEN..]);

    let cipher = Aes256Gcm::new_from_slice(&wrap).unwrap();
    let r = cipher
        .decrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut seed_buf, tag)
        .map_err(|_| ());

    wrap.zeroize();
    r?;
    Ok(seed_buf)
}

/// Derive a fully-formed SLH-DSA-SHA2-128f signing key from the 48-byte
/// stored seed. Calls the FIPS-205 `slh_keygen_internal` primitive — the
/// `pk_root` Merkle root is *computed* from `sk_seed`/`pk_seed`, not just
/// deserialized.
pub fn derive_signing_key(seed: &[u8; SEED_LEN]) -> SigningKey<Sha2_128f> {
    let sk_seed = &seed[0..16];
    let sk_prf = &seed[16..32];
    let pk_seed = &seed[32..48];
    SigningKey::<Sha2_128f>::slh_keygen_internal(sk_seed, sk_prf, pk_seed)
}

// ---------------------------------------------------------------------------
// PIN state serialization (unchanged)
// ---------------------------------------------------------------------------

pub const PER_SLOT_CT_LEN: usize = 32 + 16; // master_secret (32) + AES-GCM tag (16)
pub const PIN_STATE_MAX_LEN: usize = 1 + MAX_ATTEMPTS as usize * PER_SLOT_CT_LEN; // 433

pub fn serialize_pin_state(
    next_index: u8,
    encrypted_secrets: &[[u8; PER_SLOT_CT_LEN]],
    buf: &mut [u8],
) -> usize {
    buf[0] = next_index;
    let mut offset = 1;
    for c in encrypted_secrets {
        buf[offset..offset + PER_SLOT_CT_LEN].copy_from_slice(c);
        offset += PER_SLOT_CT_LEN;
    }
    offset
}

pub struct PinState {
    pub next_index: u8,
    pub num_slots: usize,
    pub encrypted_secrets: [[u8; PER_SLOT_CT_LEN]; MAX_ATTEMPTS as usize],
}

pub fn deserialize_pin_state(blob: &[u8], blob_len: usize) -> Result<PinState, ()> {
    if blob_len == 0 {
        return Err(());
    }
    let next_index = blob[0];
    let rest = &blob[1..blob_len];
    if rest.len() % PER_SLOT_CT_LEN != 0 {
        return Err(());
    }
    let num_slots = rest.len() / PER_SLOT_CT_LEN;
    let mut encrypted_secrets = [[0u8; PER_SLOT_CT_LEN]; MAX_ATTEMPTS as usize];
    for (i, chunk) in rest.chunks(PER_SLOT_CT_LEN).enumerate() {
        encrypted_secrets[i].copy_from_slice(chunk);
    }
    Ok(PinState {
        next_index,
        num_slots,
        encrypted_secrets,
    })
}

// ---------------------------------------------------------------------------
// First-boot provisioning (mock SE path)
// ---------------------------------------------------------------------------

/// One-shot provisioning for the mock secure element. Generates a fresh seed,
/// derives the SLH-DSA verifying key, sets up the MAC-and-Destroy PIN chain,
/// and stores everything in r-mem. Only called when the device is detected
/// as unprovisioned (see `main::is_provisioned`).
///
/// On the mock SE, the "TRNG" is a deterministic value because we have no
/// hardware RNG in QEMU. This is fine for testing only — `tropic01_se`
/// uses the chip TRNG and is what runs on real hardware.
#[cfg(feature = "mock-se")]
pub fn provision_mock_device(se: &mut impl SecureElement) {
    use signature::Keypair;

    // Deterministic seed for QEMU-only testing.
    let mut seed = [0u8; SEED_LEN];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = i as u8 + 0x20;
    }

    // Derive the keypair to compute the verifying key.
    let signing_key = derive_signing_key(&seed);
    let vk = signing_key.verifying_key();
    let vk_bytes = vk.to_bytes();

    // Test PIN
    let pin: [u8; 8] = *b"12345678";

    // Master secret (deterministic for the mock)
    let mut master_secret: [u8; 32] = kdf(b"test-master", &seed[..32], 0);

    // Encrypt seed
    let seed_blob = encrypt_seed_blob(&seed, &master_secret);

    // Initialize MACD slots and build per-slot encrypted master_secret blobs
    let mut encrypted_secrets = [[0u8; PER_SLOT_CT_LEN]; MAX_ATTEMPTS as usize];
    for j in 0..MAX_ATTEMPTS {
        let init_in = macd_init_input(&master_secret, j);
        let pin_in = macd_pin_input(&pin, j);

        se.mac_and_destroy(j as u16, &init_in).unwrap();
        let mut w_j = se.mac_and_destroy(j as u16, &pin_in).unwrap();
        se.mac_and_destroy(j as u16, &init_in).unwrap();

        let mut ct_buf = [0u8; PER_SLOT_CT_LEN];
        ct_buf[..32].copy_from_slice(&master_secret);
        aes_encrypt_inplace(&w_j, &mut ct_buf, 32, j);
        encrypted_secrets[j as usize] = ct_buf;
        w_j.zeroize();
    }

    // Store everything in r-mem
    se.r_mem_erase(RMEM_ENCRYPTED_SEED).ok();
    se.r_mem_write(RMEM_ENCRYPTED_SEED, &seed_blob).unwrap();

    let mut pin_state_buf = [0u8; PIN_STATE_MAX_LEN];
    let ps_len = serialize_pin_state(0, &encrypted_secrets, &mut pin_state_buf);
    se.r_mem_erase(RMEM_PIN_STATE).ok();
    se.r_mem_write(RMEM_PIN_STATE, &pin_state_buf[..ps_len])
        .unwrap();

    se.r_mem_erase(RMEM_VERIFYING_KEY).ok();
    se.r_mem_write(RMEM_VERIFYING_KEY, &vk_bytes).unwrap();

    // Wipe sensitive intermediates
    seed.zeroize();
    master_secret.zeroize();
}
