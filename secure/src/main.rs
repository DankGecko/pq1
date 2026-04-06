#![no_std]
#![no_main]
#![feature(cmse_nonsecure_entry)]

use cortex_m_semihosting::hprintln;
use panic_semihosting as _;

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
    hprintln!("[S] Secure world starting...");

    sau::init();
    hprintln!("[S] SAU + MPC configured");

    // Enroll test keypair
    #[cfg(feature = "mock-se")]
    {
        unsafe { crypto::enroll_test_key(&mut SE) };
        hprintln!("[S] Test key enrolled (mock SE, PIN: 12345678)");
    }

    #[cfg(feature = "tropic01-se")]
    {
        hprintln!("[S] Enrolling key on TROPIC01 chip...");
        tropic01_enroll();
        hprintln!("[S] Key enrolled on TROPIC01 (e2e encrypted, PIN: 12345678)");
    }

    nsc::init_gateway();
    setup_systick();
    hprintln!("[S] Gateway ready");

    hprintln!("[S] Booting non-secure world...");
    unsafe { boot_ns::boot(NS_FLASH_BASE) }
}

#[cfg(feature = "tropic01-se")]
fn tropic01_enroll() {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use signature::Keypair;
    use slh_dsa::{Sha2_128f, SigningKey};
    use sphincs_tz_shared::MAX_ATTEMPTS;

    // Generate deterministic test key (replace with real RNG on production)
    let mut seed = [0u8; 64];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = i as u8;
    }
    let signing_key = SigningKey::<Sha2_128f>::try_from(seed.as_slice()).unwrap();
    let vk = signing_key.verifying_key();
    let vk_bytes = vk.to_bytes();
    let sk_bytes = signing_key.to_bytes();

    let pin: [u8; 8] = *b"12345678";
    let master_secret: [u8; 32] = crypto::kdf(b"test-master", &seed[..32], 0);

    // Encrypt signing key
    let wrap_key = crypto::derive_wrap_key(&master_secret);
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
}

#[cortex_m_rt::exception]
fn SysTick() {
    nsc::poll_gateway();
}
