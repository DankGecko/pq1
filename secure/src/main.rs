#![no_std]
#![no_main]
#![feature(cmse_nonsecure_entry)]

/// Conditional debug logging macro. Compiles to no-op without the `debug-log` feature,
/// ensuring no semihosting output in production builds.
#[cfg(feature = "debug-log")]
macro_rules! secure_log {
    ($($arg:tt)*) => { cortex_m_semihosting::hprintln!($($arg)*) };
}
#[cfg(not(feature = "debug-log"))]
macro_rules! secure_log {
    ($($arg:tt)*) => {};
}

mod boot_ns;
mod crypto;
mod nsc;
mod pin;
mod sau;
mod secure_element;
#[cfg(feature = "tropic01-se")]
mod semihosting_spi;
#[cfg(feature = "tropic01-se")]
mod tropic01_se;

use secure_element::MockSecureElement;

const NS_FLASH_BASE: u32 = 0x0020_0000;

const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;

// Global mock SE (used when mock-se feature is active)
#[cfg(feature = "mock-se")]
static mut SE: MockSecureElement = MockSecureElement::new();

// Global TROPIC01 SE (used when tropic01-se feature is active)
#[cfg(feature = "tropic01-se")]
static mut SE: tropic01_se::Tropic01SecureElement = tropic01_se::Tropic01SecureElement::new();

fn setup_systick() {
    unsafe {
        core::ptr::write_volatile(SYST_RVR, 1000);
        core::ptr::write_volatile(SYST_CVR, 0);
        core::ptr::write_volatile(SYST_CSR, 0x07);
    }
}

#[cortex_m_rt::entry]
fn main() -> ! {
    secure_log!("[S] Secure world starting...");

    sau::init();
    secure_log!("[S] SAU + MPC configured");

    // Enroll test keypair
    #[cfg(feature = "mock-se")]
    {
        unsafe { crypto::enroll_test_key(&mut SE) };
        secure_log!("[S] Test key enrolled (mock SE)");
    }

    #[cfg(feature = "tropic01-se")]
    {
        secure_log!("[S] Enrolling key on TROPIC01 chip...");
        tropic01_enroll();
        secure_log!("[S] Key enrolled on TROPIC01 (e2e encrypted)");
    }

    nsc::init_gateway();
    setup_systick();
    secure_log!("[S] Gateway ready");

    secure_log!("[S] Booting non-secure world...");
    unsafe { boot_ns::boot(NS_FLASH_BASE) }
}

#[cfg(feature = "tropic01-se")]
fn tropic01_enroll() {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use signature::Keypair;
    use slh_dsa::{Sha2_128f, SigningKey};
    use sphincs_tz_shared::MAX_ATTEMPTS;
    use zeroize::Zeroize;

    // Generate key seed from TROPIC01's hardware TRNG
    let mut seed = [0u8; 64];
    unsafe {
        SE.get_trng_bytes(&mut seed[..32]).expect("TRNG failed for seed[..32]");
        SE.get_trng_bytes(&mut seed[32..]).expect("TRNG failed for seed[32..]");
    }

    let signing_key = SigningKey::<Sha2_128f>::try_from(seed.as_slice()).unwrap();
    let vk = signing_key.verifying_key();
    let vk_bytes = vk.to_bytes();
    let mut sk_bytes = signing_key.to_bytes();

    let pin: [u8; 8] = *b"12345678";
    let mut master_secret: [u8; 32] = crypto::kdf(b"test-master", &seed[..32], 0);

    // Encrypt signing key
    let mut wrap_key = crypto::derive_wrap_key(&master_secret);
    let sk_nonce: [u8; 12] = crypto::kdf(b"test-sk-nonce", &master_secret, 0)[..12]
        .try_into()
        .unwrap();
    let mut sk_buf = [0u8; 92]; // 12 nonce + 64 SK + 16 tag
    sk_buf[..12].copy_from_slice(&sk_nonce);
    sk_buf[12..76].copy_from_slice(&sk_bytes);
    let cipher = Aes256Gcm::new_from_slice(&wrap_key).unwrap();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&sk_nonce), &[], &mut sk_buf[12..76])
        .unwrap();
    sk_buf[76..92].copy_from_slice(&tag);

    // Batch enroll on real TROPIC01 chip (e2e encrypted session)
    unsafe {
        SE.batch_enroll(&sk_buf[..92], &[], &vk_bytes, &master_secret, &pin, MAX_ATTEMPTS)
            .expect("TROPIC01 enrollment failed");
    }

    // Wipe all sensitive intermediates
    seed.zeroize();
    sk_bytes.zeroize();
    master_secret.zeroize();
    wrap_key.zeroize();
    sk_buf.zeroize();
}

#[cortex_m_rt::exception]
fn SysTick() {
    nsc::poll_gateway();
}

/// Custom panic handler: zeroizes all sensitive state before halting.
/// This ensures secrets don't persist in RAM after a crash.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    nsc::zeroize_sensitive_state();

    #[cfg(feature = "debug-log")]
    {
        // Best-effort debug output -- may fail if semihosting is unavailable
        cortex_m_semihosting::hprintln!("[S] PANIC: {}", _info);
    }

    loop {
        cortex_m::asm::bkpt();
    }
}
