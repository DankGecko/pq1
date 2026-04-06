/// Secure gateway via shared memory + secure SysTick interrupt.
///
/// QEMU 8.2.2 workaround: SG veneers don't work due to MPC/INVEP bug.
/// On real STM32U585, replace with CMSE extern "cmse-nonsecure-entry".

use crate::secure_element::SecureElement;
use sphincs_tz_shared::{
    MAX_ATTEMPTS, NscStatus, SIGNATURE_LEN, VERIFYING_KEY_LEN, PIN_LEN, TX_HASH_LEN,
};

// Command IDs
const CMD_NONE: u32 = 0;
const CMD_GET_REMAINING: u32 = 1;
const CMD_ENTER_PIN: u32 = 2;
const CMD_GET_PUBKEY: u32 = 3;
const CMD_SIGN: u32 = 4;

// Shared memory layout (in NS SRAM)
const SHARED_CMD: *mut u32 = 0x2802_FF00 as *mut u32;
const SHARED_ARG0: *mut u32 = 0x2802_FF04 as *mut u32; // ptr to input data (NS addr)
const SHARED_ARG1: *mut u32 = 0x2802_FF08 as *mut u32; // ptr to output buf (NS addr)
const SHARED_ARG2: *mut u32 = 0x2802_FF0C as *mut u32; // output buf len
const SHARED_RESULT: *mut u32 = 0x2802_FF10 as *mut u32;
const SHARED_DONE: *mut u32 = 0x2802_FF14 as *mut u32;

/// Secure state
static mut REMAINING_ATTEMPTS: u8 = MAX_ATTEMPTS;
static mut PIN_VERIFIED: bool = false;
static mut MASTER_SECRET: [u8; 32] = [0u8; 32];

/// Called from secure SysTick handler.
pub fn poll_gateway() {
    unsafe {
        let cmd = core::ptr::read_volatile(SHARED_CMD);
        if cmd == CMD_NONE {
            return;
        }

        let result = dispatch(cmd);

        core::ptr::write_volatile(SHARED_RESULT, result);
        core::ptr::write_volatile(SHARED_DONE, 1);
        core::ptr::write_volatile(SHARED_CMD, CMD_NONE);
    }
}

unsafe fn dispatch(cmd: u32) -> u32 {
    match cmd {
        CMD_GET_REMAINING => cmd_get_remaining(),
        CMD_ENTER_PIN => cmd_enter_pin(),
        CMD_GET_PUBKEY => cmd_get_pubkey(),
        CMD_SIGN => cmd_sign(),
        _ => NscStatus::InternalError as u32,
    }
}

unsafe fn cmd_get_remaining() -> u32 {
    REMAINING_ATTEMPTS as u32
}

unsafe fn cmd_enter_pin() -> u32 {
    let pin_ptr = core::ptr::read_volatile(SHARED_ARG0) as *const u8;

    // Read PIN from NS memory
    let mut pin = [0u8; PIN_LEN];
    for i in 0..PIN_LEN {
        pin[i] = core::ptr::read_volatile(pin_ptr.add(i));
    }

    // Verify PIN
    let se = &mut *core::ptr::addr_of_mut!(crate::SE);
    match crate::pin::verify_pin(se, &pin) {
        Ok(master) => {
            MASTER_SECRET = master;
            PIN_VERIFIED = true;
            // Read current state to update remaining attempts
            REMAINING_ATTEMPTS = MAX_ATTEMPTS;
            NscStatus::Ok as u32
        }
        Err(NscStatus::PinIncorrect) => {
            if REMAINING_ATTEMPTS > 0 {
                REMAINING_ATTEMPTS -= 1;
            }
            NscStatus::PinIncorrect as u32
        }
        Err(status) => status as u32,
    }
}

unsafe fn cmd_get_pubkey() -> u32 {
    let out_ptr = core::ptr::read_volatile(SHARED_ARG1) as *mut u8;
    let out_len = core::ptr::read_volatile(SHARED_ARG2);

    if out_len < VERIFYING_KEY_LEN as u32 {
        return NscStatus::InvalidPointer as u32;
    }

    // Read verifying key from SE
    let se = &mut *core::ptr::addr_of_mut!(crate::SE);
    let mut vk_buf = [0u8; 64]; // verifying key is 32 bytes
    let vk_len = match se.r_mem_read(crate::crypto::RMEM_VERIFYING_KEY, &mut vk_buf) {
        Ok(len) => len,
        Err(_) => return NscStatus::NotInitialized as u32,
    };

    // Write to NS memory
    for i in 0..vk_len {
        core::ptr::write_volatile(out_ptr.add(i), vk_buf[i]);
    }

    NscStatus::Ok as u32
}

unsafe fn cmd_sign() -> u32 {
    if !PIN_VERIFIED {
        return NscStatus::NotInitialized as u32;
    }

    let hash_ptr = core::ptr::read_volatile(SHARED_ARG0) as *const u8;
    let sig_ptr = core::ptr::read_volatile(SHARED_ARG1) as *mut u8;
    let sig_buf_len = core::ptr::read_volatile(SHARED_ARG2);

    if sig_buf_len < SIGNATURE_LEN as u32 {
        return NscStatus::InvalidPointer as u32;
    }

    // Read tx hash from NS memory
    let mut tx_hash = [0u8; TX_HASH_LEN];
    for i in 0..TX_HASH_LEN {
        tx_hash[i] = core::ptr::read_volatile(hash_ptr.add(i));
    }

    // Decrypt signing key
    let se = &mut *core::ptr::addr_of_mut!(crate::SE);
    let mut sk_blob = [0u8; 128];
    let sk_blob_len = match se.r_mem_read(crate::crypto::RMEM_ENCRYPTED_SK, &mut sk_blob) {
        Ok(len) => len,
        Err(_) => return NscStatus::InternalError as u32,
    };

    let sk_nonce = &sk_blob[..12];
    let sk_ct = &sk_blob[12..sk_blob_len];

    let wrap_key = crate::crypto::derive_wrap_key(&MASTER_SECRET);
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use aes_gcm::Nonce;
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&wrap_key).unwrap();

    let ct_len = sk_ct.len();
    if ct_len < 16 {
        return NscStatus::CryptoError as u32;
    }
    let plaintext_len = ct_len - 16;
    let mut sk_dec = [0u8; 64];
    sk_dec[..plaintext_len].copy_from_slice(&sk_ct[..plaintext_len]);
    let tag = aes_gcm::Tag::from_slice(&sk_ct[plaintext_len..]);

    if cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(sk_nonce),
            &[],
            &mut sk_dec[..plaintext_len],
            tag,
        )
        .is_err()
    {
        return NscStatus::CryptoError as u32;
    }

    // Sign
    use signature::Signer;
    use slh_dsa::{Sha2_128f, SigningKey};

    let signing_key = match SigningKey::<Sha2_128f>::try_from(sk_dec[..plaintext_len].as_ref()) {
        Ok(k) => k,
        Err(_) => return NscStatus::CryptoError as u32,
    };

    let sig = match signing_key.try_sign(&tx_hash) {
        Ok(s) => s,
        Err(_) => return NscStatus::CryptoError as u32,
    };

    // Serialize and write signature to NS memory
    let sig_bytes = sig.to_bytes();
    for i in 0..SIGNATURE_LEN {
        core::ptr::write_volatile(sig_ptr.add(i), sig_bytes[i]);
    }

    // Wipe key from RAM
    sk_dec = [0u8; 64];
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    NscStatus::Ok as u32
}

pub fn init_gateway() {
    unsafe {
        core::ptr::write_volatile(SHARED_CMD, CMD_NONE);
        core::ptr::write_volatile(SHARED_RESULT, 0);
        core::ptr::write_volatile(SHARED_DONE, 0);
    }
}

// CMSE veneer kept for real hardware
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_remaining_attempts() -> u32 {
    unsafe { REMAINING_ATTEMPTS as u32 }
}
