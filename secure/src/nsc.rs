//! Secure gateway with trusted-UI sign confirmation.
//!
//! Today this runs as a SysTick-polled shared-memory mailbox (a QEMU
//! workaround for the broken SG instruction check on mps2-an505). On real
//! STM32U585 hardware the same dispatch logic will be invoked from CMSE
//! `cmse-nonsecure-entry` veneers — the only difference is who pulls the
//! trigger (poll vs direct call).
//!
//! Gateway commands:
//!
//! | ID | Name           | NS → S args                              | S behavior |
//! |----|----------------|------------------------------------------|------------|
//! | 1  | GET_REMAINING  | —                                        | reads chip; returns u32 |
//! | 2  | REQUEST_UNLOCK | —                                        | secure UI prompts for PIN |
//! | 3  | GET_PUBKEY     | out_ptr, out_len                         | reads slot 2 |
//! | 4  | SIGN           | unsigned_tx_ptr, sig_out_ptr, tx_len     | parse → confirm → sign |

use crate::secure_element::SecureElement;
use crate::timeout;
use crate::ui;
use sphincs_tz_shared::{
    NscStatus, CMD_GET_PUBKEY, CMD_GET_REMAINING, CMD_NONE, CMD_REQUEST_UNLOCK, CMD_SIGN,
    MAX_ATTEMPTS, MAX_TX_LEN, NS_FLASH_BASE, NS_FLASH_END, NS_SRAM_BASE, NS_SRAM_END,
    SHARED_MAILBOX_BASE, SHARED_MAILBOX_END, SIGNATURE_LEN, VERIFYING_KEY_LEN,
};
use zeroize::Zeroize;

// Shared memory layout (in NS SRAM)
const SHARED_CMD: *mut u32 = 0x2802_FF00 as *mut u32;
const SHARED_ARG0: *mut u32 = 0x2802_FF04 as *mut u32;
const SHARED_ARG1: *mut u32 = 0x2802_FF08 as *mut u32;
const SHARED_ARG2: *mut u32 = 0x2802_FF0C as *mut u32;
const SHARED_RESULT: *mut u32 = 0x2802_FF10 as *mut u32;
const SHARED_DONE: *mut u32 = 0x2802_FF14 as *mut u32;

// Secure state
static mut REMAINING_ATTEMPTS: u8 = MAX_ATTEMPTS;
static mut PIN_VERIFIED: bool = false;
static mut MASTER_SECRET: [u8; 32] = [0u8; 32];

/// Snapshot of shared memory arguments, read atomically in dispatch()
/// to prevent TOCTOU races where NS modifies args between validation and use.
struct GatewayArgs {
    arg0: u32,
    arg1: u32,
    arg2: u32,
}

/// Validate that a pointer + length falls entirely within a non-secure
/// memory region the secure world is allowed to **write** to (NS SRAM only),
/// and does not overlap the shared mailbox.
#[inline]
fn validate_ns_write_ptr(ptr: u32, len: usize) -> bool {
    if ptr == 0 {
        return false;
    }
    let end = match ptr.checked_add(len as u32) {
        Some(e) => e,
        None => return false,
    };
    if !(ptr >= NS_SRAM_BASE && end <= NS_SRAM_END) {
        return false;
    }
    // Reject any overlap with the shared mailbox region.
    if ptr < SHARED_MAILBOX_END && end > SHARED_MAILBOX_BASE {
        return false;
    }
    true
}

/// Validate that a pointer + length falls entirely within a non-secure
/// memory region the secure world is allowed to **read** from. Allows both
/// NS SRAM and NS flash (the latter is read-only and can hold static
/// payloads like an unsigned tx). The shared mailbox is excluded.
#[inline]
fn validate_ns_read_ptr(ptr: u32, len: usize) -> bool {
    if ptr == 0 {
        return false;
    }
    let end = match ptr.checked_add(len as u32) {
        Some(e) => e,
        None => return false,
    };
    let in_sram = ptr >= NS_SRAM_BASE && end <= NS_SRAM_END;
    let in_flash = ptr >= NS_FLASH_BASE && end <= NS_FLASH_END;
    if !(in_sram || in_flash) {
        return false;
    }
    if in_sram && ptr < SHARED_MAILBOX_END && end > SHARED_MAILBOX_BASE {
        return false;
    }
    true
}

/// Whether the device is currently unlocked (PIN_VERIFIED == true).
#[allow(static_mut_refs)]
pub fn is_unlocked() -> bool {
    unsafe { PIN_VERIFIED }
}

/// Zeroize all sensitive global state. Called from panic handler and
/// inactivity wipe.
pub fn zeroize_sensitive_state() {
    unsafe {
        let ms = &raw mut MASTER_SECRET;
        (*ms).zeroize();
        PIN_VERIFIED = false;
    }
}

pub fn init_gateway() {
    unsafe {
        core::ptr::write_volatile(SHARED_CMD, CMD_NONE);
        core::ptr::write_volatile(SHARED_RESULT, 0);
        core::ptr::write_volatile(SHARED_DONE, 0);
    }
}

pub fn poll_gateway() {
    unsafe {
        let cmd = core::ptr::read_volatile(SHARED_CMD);
        if cmd == CMD_NONE {
            return;
        }

        let args = GatewayArgs {
            arg0: core::ptr::read_volatile(SHARED_ARG0),
            arg1: core::ptr::read_volatile(SHARED_ARG1),
            arg2: core::ptr::read_volatile(SHARED_ARG2),
        };

        let result = dispatch(cmd, &args);

        core::ptr::write_volatile(SHARED_RESULT, result);
        // Order matters: write RESULT before DONE so NS can't see DONE=1
        // with stale RESULT. Then clear CMD last so NS can issue another.
        core::ptr::write_volatile(SHARED_DONE, 1);
        core::ptr::write_volatile(SHARED_CMD, CMD_NONE);
    }
}

unsafe fn dispatch(cmd: u32, args: &GatewayArgs) -> u32 {
    match cmd {
        CMD_GET_REMAINING => cmd_get_remaining(),
        CMD_REQUEST_UNLOCK => cmd_request_unlock(),
        CMD_GET_PUBKEY => cmd_get_pubkey(args),
        CMD_SIGN => cmd_sign(args),
        _ => NscStatus::InternalError as u32,
    }
}

// ---------------------------------------------------------------------------
// CMD_GET_REMAINING
// ---------------------------------------------------------------------------

unsafe fn cmd_get_remaining() -> u32 {
    #[cfg(feature = "tropic01-se")]
    {
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match se.batch_read_pin_state() {
            Ok(next_index) => {
                let remaining = if next_index >= MAX_ATTEMPTS {
                    0
                } else {
                    MAX_ATTEMPTS - next_index
                };
                REMAINING_ATTEMPTS = remaining;
                remaining as u32
            }
            Err(_) => REMAINING_ATTEMPTS as u32,
        }
    }
    #[cfg(not(feature = "tropic01-se"))]
    {
        REMAINING_ATTEMPTS as u32
    }
}

// ---------------------------------------------------------------------------
// CMD_REQUEST_UNLOCK — secure UI prompts for PIN, PIN never touches NS RAM
// ---------------------------------------------------------------------------

unsafe fn cmd_request_unlock() -> u32 {
    use crate::ui::pin_entry::{enter_pin, PinEntryResult};

    let pin = match enter_pin() {
        PinEntryResult::Pin(p) => p,
        PinEntryResult::Cancelled => {
            ui::show_status("Cancelled", "");
            return NscStatus::UserRejected as u32;
        }
        PinEntryResult::IdleWipe => {
            zeroize_sensitive_state();
            ui::show_status("Locked", "(idle wipe)");
            return NscStatus::IdleWipe as u32;
        }
    };

    ui::show_status("Verifying...", "");

    let result = verify_pin_with_chip(&pin);

    let mut pin_copy = pin;
    pin_copy.zeroize();

    result
}

unsafe fn verify_pin_with_chip(pin: &[u8; 8]) -> u32 {
    #[cfg(feature = "tropic01-se")]
    {
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match se.batch_verify_pin(pin, MAX_ATTEMPTS) {
            Ok(master) => {
                MASTER_SECRET = master;
                PIN_VERIFIED = true;
                REMAINING_ATTEMPTS = MAX_ATTEMPTS;
                timeout::reset_activity();
                ui::show_status("Unlocked", "");
                NscStatus::Ok as u32
            }
            Err(crate::secure_element::SeError::SlotExpired) => {
                REMAINING_ATTEMPTS = 0;
                ui::show_status("PIN locked", "");
                NscStatus::PinLocked as u32
            }
            Err(crate::secure_element::SeError::InvalidParameter) => {
                if REMAINING_ATTEMPTS > 0 {
                    REMAINING_ATTEMPTS -= 1;
                }
                ui::show_status("Wrong PIN", "");
                NscStatus::PinIncorrect as u32
            }
            Err(_) => NscStatus::InternalError as u32,
        }
    }
    #[cfg(not(feature = "tropic01-se"))]
    {
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match crate::pin::verify_pin(se, pin) {
            Ok(master) => {
                MASTER_SECRET = master;
                PIN_VERIFIED = true;
                REMAINING_ATTEMPTS = MAX_ATTEMPTS;
                timeout::reset_activity();
                ui::show_status("Unlocked", "");
                NscStatus::Ok as u32
            }
            Err(NscStatus::PinIncorrect) => {
                if REMAINING_ATTEMPTS > 0 {
                    REMAINING_ATTEMPTS -= 1;
                }
                ui::show_status("Wrong PIN", "");
                NscStatus::PinIncorrect as u32
            }
            Err(NscStatus::PinLocked) => {
                ui::show_status("PIN locked", "");
                NscStatus::PinLocked as u32
            }
            Err(status) => status as u32,
        }
    }
}

// ---------------------------------------------------------------------------
// CMD_GET_PUBKEY
// ---------------------------------------------------------------------------

unsafe fn cmd_get_pubkey(args: &GatewayArgs) -> u32 {
    let out_ptr = args.arg1 as *mut u8;
    let out_len = args.arg2;

    if out_len < VERIFYING_KEY_LEN as u32 {
        return NscStatus::InvalidPointer as u32;
    }

    if !validate_ns_write_ptr(args.arg1, VERIFYING_KEY_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    let mut vk_buf = [0u8; 64];
    let read_result = {
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        #[cfg(feature = "tropic01-se")]
        {
            let mut seed_blob = [0u8; 128];
            se.batch_read_seed_and_vk(&mut seed_blob, &mut vk_buf)
                .map(|(_, vk_len)| vk_len)
        }
        #[cfg(not(feature = "tropic01-se"))]
        {
            se.r_mem_read(crate::crypto::RMEM_VERIFYING_KEY, &mut vk_buf)
        }
    };

    match read_result {
        Ok(vk_len) => {
            for i in 0..vk_len {
                core::ptr::write_volatile(out_ptr.add(i), vk_buf[i]);
            }
            NscStatus::Ok as u32
        }
        Err(_) => NscStatus::NotInitialized as u32,
    }
}

// ---------------------------------------------------------------------------
// CMD_SIGN — parse EIP-1559 envelope, display, confirm, sign
// ---------------------------------------------------------------------------

unsafe fn cmd_sign(args: &GatewayArgs) -> u32 {
    use crate::tx::{display::render_pages, eip1559};
    use crate::ui::confirm::{confirm, ConfirmResult};

    if !PIN_VERIFIED {
        return NscStatus::NotInitialized as u32;
    }

    let tx_ptr = args.arg0 as *const u8;
    let sig_ptr = args.arg1 as *mut u8;
    let tx_len = args.arg2 as usize;

    // 1. Validate sizes and pointers
    if tx_len == 0 || tx_len > MAX_TX_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, tx_len) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, SIGNATURE_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // 2. Copy unsigned tx into a secure-stack buffer (TOCTOU defense)
    let mut tx_buf = [0u8; MAX_TX_LEN];
    for i in 0..tx_len {
        tx_buf[i] = core::ptr::read_volatile(tx_ptr.add(i));
    }
    let tx_bytes = &tx_buf[..tx_len];

    // 3. Parse the EIP-1559 envelope
    let parsed = match eip1559::parse(tx_bytes) {
        Ok(t) => t,
        Err(_) => {
            ui::show_status("Bad tx", "(parse fail)");
            return NscStatus::CryptoError as u32;
        }
    };

    // 4. Render pages and ask the user
    let pages = render_pages(&parsed);
    let confirm_result = confirm(pages.as_slice());
    match confirm_result {
        ConfirmResult::Confirmed => {}
        ConfirmResult::Cancelled => {
            ui::show_status("Cancelled", "");
            return NscStatus::UserRejected as u32;
        }
        ConfirmResult::IdleWipe => {
            zeroize_sensitive_state();
            ui::show_status("Locked", "(idle wipe)");
            return NscStatus::IdleWipe as u32;
        }
    }

    ui::show_status("Signing...", "");

    // 5. Read the encrypted seed blob from the SE
    let mut seed_blob = [0u8; 128];
    let seed_blob_len = {
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        #[cfg(feature = "tropic01-se")]
        {
            let mut vk_ignore = [0u8; 64];
            match se.batch_read_seed_and_vk(&mut seed_blob, &mut vk_ignore) {
                Ok((seed_len, _)) => seed_len,
                Err(_) => return NscStatus::InternalError as u32,
            }
        }
        #[cfg(not(feature = "tropic01-se"))]
        {
            match se.r_mem_read(crate::crypto::RMEM_ENCRYPTED_SEED, &mut seed_blob) {
                Ok(len) => len,
                Err(_) => return NscStatus::InternalError as u32,
            }
        }
    };

    // 6. Decrypt the seed using the master secret unwrapped from PIN entry
    let mut seed = match crate::crypto::decrypt_seed_blob(
        &seed_blob[..seed_blob_len],
        &*core::ptr::addr_of!(MASTER_SECRET),
    ) {
        Ok(s) => s,
        Err(_) => {
            seed_blob.zeroize();
            return NscStatus::CryptoError as u32;
        }
    };
    seed_blob.zeroize();

    // 7. Derive the SLH-DSA signing key (FIPS-205 KeyGen) on the stack
    let signing_key = crate::crypto::derive_signing_key(&seed);

    // 8. Hedged sign: pass the secure-element's encrypted-seed-derived
    //    randomizer as opt_rand to avoid pure-deterministic signatures.
    let mut rand_buf = [0u8; 16];
    derive_sign_randomizer(&parsed.signing_hash, &mut rand_buf);

    use slh_dsa::Sha2_128f;
    use slh_dsa::SigningKey as Sk;
    let sig = match <Sk<Sha2_128f>>::try_sign_with_context(
        &signing_key,
        &parsed.signing_hash,
        &[],
        Some(&rand_buf),
    ) {
        Ok(s) => s,
        Err(_) => {
            seed.zeroize();
            rand_buf.zeroize();
            return NscStatus::CryptoError as u32;
        }
    };

    // 9. Write 17,088-byte signature to NS memory
    let sig_bytes = sig.to_bytes();
    for i in 0..SIGNATURE_LEN {
        core::ptr::write_volatile(sig_ptr.add(i), sig_bytes[i]);
    }

    // 10. Wipe sensitive material
    seed.zeroize();
    rand_buf.zeroize();

    timeout::reset_activity();
    ui::show_status("Signed", "");
    NscStatus::Ok as u32
}

/// Derive a 16-byte randomizer for hedged SLH-DSA signing from the master
/// secret and the message hash. Mixes the chip-bound master into every
/// signature so the same message produces different signatures across
/// different unlocks.
fn derive_sign_randomizer(msg_hash: &[u8; 32], out: &mut [u8; 16]) {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"sphincs-sign-rand");
    unsafe { h.update(&*core::ptr::addr_of!(MASTER_SECRET)) };
    h.update(msg_hash);
    let r = h.finalize();
    out.copy_from_slice(&r[..16]);
}

// CMSE veneer kept for real hardware (bypasses QEMU's broken SG check)
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_remaining_attempts() -> u32 {
    unsafe { REMAINING_ATTEMPTS as u32 }
}
