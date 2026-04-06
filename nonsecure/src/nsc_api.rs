// Shared memory gateway (must match secure/src/nsc.rs)
const SHARED_CMD: *mut u32 = 0x2802_FF00 as *mut u32;
const SHARED_ARG0: *mut u32 = 0x2802_FF04 as *mut u32;
const SHARED_ARG1: *mut u32 = 0x2802_FF08 as *mut u32;
const SHARED_ARG2: *mut u32 = 0x2802_FF0C as *mut u32;
const SHARED_RESULT: *const u32 = 0x2802_FF10 as *const u32;
const SHARED_DONE: *mut u32 = 0x2802_FF14 as *mut u32;

const CMD_GET_REMAINING: u32 = 1;
const CMD_ENTER_PIN: u32 = 2;
const CMD_GET_PUBKEY: u32 = 3;
const CMD_SIGN: u32 = 4;

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

pub fn enter_pin(pin: &[u8; 8]) -> u32 {
    unsafe { gateway_call(CMD_ENTER_PIN, pin.as_ptr() as u32, 0, 0) }
}

pub fn get_pubkey(buf: &mut [u8; 32]) -> u32 {
    unsafe { gateway_call(CMD_GET_PUBKEY, 0, buf.as_mut_ptr() as u32, 32) }
}

pub fn sign(tx_hash: &[u8; 32], sig_buf: &mut [u8], sig_buf_len: u32) -> u32 {
    unsafe {
        gateway_call(
            CMD_SIGN,
            tx_hash.as_ptr() as u32,
            sig_buf.as_mut_ptr() as u32,
            sig_buf_len,
        )
    }
}
