#![no_std]
#![no_main]

use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;
use sphincs_tz_shared::{NscStatus, SIGNATURE_LEN, VERIFYING_KEY_LEN};

mod nsc_api;

// Static signature buffer (17KB is too large for stack)
static mut SIG_BUF: [u8; SIGNATURE_LEN] = [0u8; SIGNATURE_LEN];

#[cortex_m_rt::entry]
fn main() -> ! {
    hprintln!("[NS] Non-secure world started!");

    // Test 1: Get remaining attempts
    let attempts = nsc_api::get_remaining_attempts();
    hprintln!("[NS] Remaining PIN attempts: {}", attempts);
    assert_eq!(attempts, 9);

    // Test 2: Get public key
    let mut pubkey = [0u8; VERIFYING_KEY_LEN];
    let status = nsc_api::get_pubkey(&mut pubkey);
    hprintln!("[NS] Get pubkey: {:?}", NscStatus::from(status));
    assert_eq!(status, NscStatus::Ok as u32);
    hprintln!("[NS] Pubkey[0..4]: {:02x?}", &pubkey[..4]);

    // Test 3: Enter PIN (correct)
    let pin = *b"12345678";
    let status = nsc_api::enter_pin(&pin);
    hprintln!("[NS] Enter PIN: {:?}", NscStatus::from(status));
    assert_eq!(status, NscStatus::Ok as u32);

    // Test 4: Sign a test hash
    let tx_hash = [0xABu8; 32];
    let status = unsafe {
        nsc_api::sign(&tx_hash, &mut SIG_BUF, SIGNATURE_LEN as u32)
    };
    hprintln!("[NS] Sign: {:?}", NscStatus::from(status));
    assert_eq!(status, NscStatus::Ok as u32);
    hprintln!(
        "[NS] Sig[0..8]: {:02x?}",
        unsafe { &SIG_BUF[..8] }
    );
    hprintln!("[NS] Sig len: {} bytes", SIGNATURE_LEN);

    hprintln!("\n[NS] === All tests passed! ===");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}
