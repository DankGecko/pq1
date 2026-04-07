#![no_std]
#![no_main]

use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;
use sphincs_tz_shared::{NscStatus, SIGNATURE_LEN, VERIFYING_KEY_LEN};

mod nsc_api;

// Static signature buffer (17KB is too large for stack)
static mut SIG_BUF: [u8; SIGNATURE_LEN] = [0u8; SIGNATURE_LEN];

/// A complete unsigned EIP-1559 transaction envelope (50 bytes), built by hand:
///
/// ```text
/// 0x02 ‖ rlp([
///   chain_id          = 1,
///   nonce             = 0,
///   max_priority_fee  = 2 gwei,
///   max_fee           = 50 gwei,
///   gas_limit         = 21000,
///   to                = 0xabcdef123456789abcdef123456789abcdef1234,
///   value             = 1 ETH (= 10^18 wei),
///   data              = (empty),
///   access_list       = []
/// ])
/// ```
///
/// The secure world parses this, displays the fields on the trusted UI,
/// waits for the user to confirm via the buttons, then signs.
static UNSIGNED_TX: [u8; 50] = [
    0x02,                                                       // EIP-2718 type 2
    0xf0,                                                       // RLP list header (0xc0 + 48)
    0x01,                                                       // chain_id = 1
    0x80,                                                       // nonce = 0
    0x84, 0x77, 0x35, 0x94, 0x00,                               // max_priority = 2 gwei
    0x85, 0x0b, 0xa4, 0x3b, 0x74, 0x00,                         // max_fee = 50 gwei
    0x82, 0x52, 0x08,                                           // gas_limit = 21000
    0x94,                                                       // to: 20-byte string header
    0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
    0xf1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34,
    0x88, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00,       // value = 10^18 wei
    0x80,                                                       // data = empty
    0xc0,                                                       // access_list = empty
];

#[cortex_m_rt::entry]
fn main() -> ! {
    hprintln!("[NS] Non-secure world started!");

    // Test 1: Get remaining attempts
    let attempts = nsc_api::get_remaining_attempts();
    hprintln!("[NS] Remaining PIN attempts: {}", attempts);
    assert_eq!(attempts, 9);

    // Test 2: Get public key (no unlock required)
    let mut pubkey = [0u8; VERIFYING_KEY_LEN];
    let status = nsc_api::get_pubkey(&mut pubkey);
    hprintln!("[NS] Get pubkey: {:?}", NscStatus::from(status));
    assert_eq!(status, NscStatus::Ok as u32);
    hprintln!("[NS] Pubkey[0..4]: {:02x?}", &pubkey[..4]);

    // Test 3: Request unlock — secure world prompts user via display+buttons
    hprintln!("[NS] Requesting unlock (PIN entry on trusted UI)...");
    hprintln!("[NS]   Press 'l' to increment digit, 'L' to advance/submit");
    hprintln!("[NS]   Press 'h' to decrement digit, 'H' to back/cancel");
    let status = nsc_api::request_unlock();
    hprintln!("[NS] Unlock: {:?}", NscStatus::from(status));
    assert_eq!(status, NscStatus::Ok as u32);

    // Test 4: Sign an EIP-1559 transaction
    hprintln!("[NS] Sending EIP-1559 envelope ({} bytes) for signing...", UNSIGNED_TX.len());
    hprintln!("[NS]   On the trusted UI, scroll with 'l' / 'h', long-press 'L' to confirm");
    let status = unsafe { nsc_api::sign(&UNSIGNED_TX, &mut SIG_BUF) };
    hprintln!("[NS] Sign: {:?}", NscStatus::from(status));
    assert_eq!(status, NscStatus::Ok as u32);
    hprintln!("[NS] Sig[0..8]: {:02x?}", unsafe { &SIG_BUF[..8] });
    hprintln!("[NS] Sig len: {} bytes", SIGNATURE_LEN);

    hprintln!("\n[NS] === All tests passed! ===");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}
