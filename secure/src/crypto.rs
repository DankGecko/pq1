/// Crypto helpers ported from desktop/src/main.rs to no_std.
///
/// All Vec<u8> replaced with fixed-size buffers.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

use crate::secure_element::SecureElement;
use sphincs_tz_shared::MAX_ATTEMPTS;
use zeroize::Zeroize;

// r-mem slot assignments (same as desktop)
pub const RMEM_ENCRYPTED_SK: u16 = 0;
pub const RMEM_PIN_STATE: u16 = 1;
pub const RMEM_VERIFYING_KEY: u16 = 2;

// ---------------------------------------------------------------------------
// KDF helpers (identical to desktop, already no_std compatible)
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

fn nonce_for(index: u8) -> [u8; 12] {
    let h: [u8; 32] = kdf(b"sphincs-nonce", &[index], 0);
    let mut n = [0u8; 12];
    n.copy_from_slice(&h[..12]);
    n
}

// ---------------------------------------------------------------------------
// AES-GCM (no_std: use fixed-size buffers with AeadInPlace)
// ---------------------------------------------------------------------------

/// AES-GCM encrypt in-place. `buf` must have room for plaintext + 16-byte tag.
/// Returns the total ciphertext length (plaintext_len + 16).
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

/// AES-GCM decrypt in-place. `buf[..ct_len]` has ciphertext + tag.
/// Returns plaintext length (ct_len - 16) on success.
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
// PIN state serialization (fixed-size buffers)
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
// Enrollment (for QEMU testing: enroll a test key with hardcoded PIN)
// ---------------------------------------------------------------------------

/// Enroll a test keypair into the mock secure element.
/// Uses a deterministic "RNG" for QEMU reproducibility.
pub fn enroll_test_key(se: &mut impl SecureElement) {
    use signature::{Keypair, Signer};
    use slh_dsa::{Sha2_128f, SigningKey};

    // Deterministic key from a fixed seed (for QEMU testing only)
    let mut seed = [0u8; 64];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = i as u8;
    }
    let signing_key = SigningKey::<Sha2_128f>::try_from(seed.as_slice())
        .expect("test key");
    let vk = signing_key.verifying_key();
    let vk_bytes = vk.to_bytes();

    // Test PIN: "12345678"
    let pin: [u8; 8] = *b"12345678";

    // Master secret (deterministic for test)
    let mut master_secret: [u8; 32] = kdf(b"test-master", &seed[..32], 0);

    // Encrypt signing key
    let mut wrap_key = derive_wrap_key(&master_secret);
    let mut sk_bytes = signing_key.to_bytes();
    let mut sk_buf = [0u8; 64 + 12 + 16]; // sk + nonce + tag
    // Prepend a fixed nonce
    let sk_nonce: [u8; 12] = kdf(b"test-sk-nonce", &master_secret, 0)[..12]
        .try_into()
        .unwrap();
    sk_buf[..12].copy_from_slice(&sk_nonce);
    sk_buf[12..12 + 64].copy_from_slice(&sk_bytes);
    // Encrypt sk_buf[12..76] in-place, tag goes to sk_buf[76..92]
    let cipher = Aes256Gcm::new_from_slice(&wrap_key).unwrap();
    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&sk_nonce),
            &[],
            &mut sk_buf[12..12 + 64],
        )
        .expect("encrypt SK");
    sk_buf[12 + 64..12 + 64 + 16].copy_from_slice(&tag);
    let sk_blob_len = 12 + 64 + 16; // 92 bytes

    // Initialize MACD slots and create encrypted secrets
    let mut encrypted_secrets = [[0u8; PER_SLOT_CT_LEN]; MAX_ATTEMPTS as usize];
    for j in 0..MAX_ATTEMPTS {
        let init_in = macd_init_input(&master_secret, j);
        let pin_in = macd_pin_input(&pin, j);

        // Initialize slot
        se.mac_and_destroy(j as u16, &init_in).unwrap();
        // Get w_j from PIN input
        let mut w_j = se.mac_and_destroy(j as u16, &pin_in).unwrap();
        // Re-initialize
        se.mac_and_destroy(j as u16, &init_in).unwrap();

        // Encrypt master_secret with w_j
        let mut ct_buf = [0u8; PER_SLOT_CT_LEN];
        ct_buf[..32].copy_from_slice(&master_secret);
        aes_encrypt_inplace(&w_j, &mut ct_buf, 32, j);
        encrypted_secrets[j as usize] = ct_buf;
        w_j.zeroize();
    }

    // Store in SE
    se.r_mem_erase(RMEM_ENCRYPTED_SK).ok();
    se.r_mem_write(RMEM_ENCRYPTED_SK, &sk_buf[..sk_blob_len])
        .unwrap();

    let mut pin_state_buf = [0u8; PIN_STATE_MAX_LEN];
    let ps_len = serialize_pin_state(0, &encrypted_secrets, &mut pin_state_buf);
    se.r_mem_erase(RMEM_PIN_STATE).ok();
    se.r_mem_write(RMEM_PIN_STATE, &pin_state_buf[..ps_len])
        .unwrap();

    se.r_mem_erase(RMEM_VERIFYING_KEY).ok();
    se.r_mem_write(RMEM_VERIFYING_KEY, &vk_bytes).unwrap();

    // Wipe all sensitive intermediates
    seed.zeroize();
    sk_bytes.zeroize();
    master_secret.zeroize();
    wrap_key.zeroize();
    sk_buf.zeroize();
}
