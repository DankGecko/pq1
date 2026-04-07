// Shared memory gateway (must match secure/src/nsc.rs)
const SHARED_CMD: *mut u32 = 0x2802_FF00 as *mut u32;
const SHARED_ARG0: *mut u32 = 0x2802_FF04 as *mut u32;
const SHARED_ARG1: *mut u32 = 0x2802_FF08 as *mut u32;
const SHARED_ARG2: *mut u32 = 0x2802_FF0C as *mut u32;
const SHARED_RESULT: *const u32 = 0x2802_FF10 as *const u32;
const SHARED_DONE: *mut u32 = 0x2802_FF14 as *mut u32;

const CMD_GET_REMAINING: u32 = 1;
const CMD_REQUEST_UNLOCK: u32 = 2;
const CMD_GET_PUBKEY: u32 = 3;
const CMD_SIGN: u32 = 4;
const CMD_CLEAR_SIGN: u32 = 5;

unsafe fn gateway_call(cmd: u32, arg0: u32, arg1: u32, arg2: u32) -> u32 {
    core::ptr::write_volatile(SHARED_DONE, 0);
    core::ptr::write_volatile(SHARED_ARG0, arg0);
    core::ptr::write_volatile(SHARED_ARG1, arg1);
    core::ptr::write_volatile(SHARED_ARG2, arg2);
    core::ptr::write_volatile(SHARED_CMD, cmd);

    while core::ptr::read_volatile(SHARED_DONE as *const u32) == 0 {
        cortex_m::asm::nop();
    }
    core::ptr::read_volatile(SHARED_RESULT)
}

pub fn get_remaining_attempts() -> u32 {
    unsafe { gateway_call(CMD_GET_REMAINING, 0, 0, 0) }
}

/// Ask the secure world to prompt the user for their PIN on the trusted UI.
/// The PIN never crosses the gateway — NS only sees the result.
pub fn request_unlock() -> u32 {
    unsafe { gateway_call(CMD_REQUEST_UNLOCK, 0, 0, 0) }
}

pub fn get_pubkey(buf: &mut [u8; 32]) -> u32 {
    unsafe { gateway_call(CMD_GET_PUBKEY, 0, buf.as_mut_ptr() as u32, 32) }
}

/// Sign an unsigned EIP-1559 transaction envelope. Secure world parses the
/// envelope, displays it on the trusted UI, waits for physical confirmation,
/// then signs.
pub fn sign(unsigned_tx: &[u8], sig_buf: &mut [u8]) -> u32 {
    unsafe {
        gateway_call(
            CMD_SIGN,
            unsigned_tx.as_ptr() as u32,
            sig_buf.as_mut_ptr() as u32,
            unsigned_tx.len() as u32,
        )
    }
}

/// ZK clear-sign: verify a Groth16 proof that the human-readable string
/// matches the Aave calldata, display the verified string on the trusted UI,
/// and sign the EIP-1559 transaction if the user confirms.
///
/// The payload buffer must contain:
///   [0..384)           : Groth16 proof (π.A || π.B || π.C)
///   [384..548)         : calldata (164 bytes, zero-padded)
///   [548..612)         : human-readable string (64 bytes, null-padded)
///   [612..616)         : tx_len (u32 LE)
///   [616..616+tx_len)  : unsigned EIP-1559 transaction envelope
pub fn clear_sign(payload: &[u8], sig_buf: &mut [u8]) -> u32 {
    unsafe {
        gateway_call(
            CMD_CLEAR_SIGN,
            payload.as_ptr() as u32,
            sig_buf.as_mut_ptr() as u32,
            payload.len() as u32,
        )
    }
}
