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
mod timeout;
#[cfg(feature = "tropic01-se")]
mod tropic01_se;
mod tx;
mod ui;

use crypto::{RMEM_ENCRYPTED_SEED, RMEM_PIN_STATE, RMEM_VERIFYING_KEY};
use secure_element::{MockSecureElement, SecureElement};

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

/// SysTick reload value. mps2-an505 default is 25 MHz, so 25_000 cycles ≈ 1 ms.
/// `timeout::TIMEOUT_TICKS = 120_000` therefore corresponds to 2 minutes.
const SYSTICK_RELOAD: u32 = 25_000;

fn setup_systick() {
    unsafe {
        core::ptr::write_volatile(SYST_RVR, SYSTICK_RELOAD);
        core::ptr::write_volatile(SYST_CVR, 0);
        core::ptr::write_volatile(SYST_CSR, 0x07);
    }
}

/// Returns true if the secure element already holds an encrypted seed,
/// PIN state, and verifying key. Used to skip re-provisioning on every boot.
fn is_provisioned(se: &mut impl SecureElement) -> bool {
    let mut buf = [0u8; 128];
    se.r_mem_read(RMEM_ENCRYPTED_SEED, &mut buf).is_ok()
        && se.r_mem_read(RMEM_PIN_STATE, &mut buf).is_ok()
        && se.r_mem_read(RMEM_VERIFYING_KEY, &mut buf).is_ok()
}

#[cortex_m_rt::entry]
fn main() -> ! {
    secure_log!("[S] Secure world starting...");

    sau::init();
    secure_log!("[S] SAU + MPC configured");

    ui::init();
    secure_log!("[S] UI initialized");

    // Provision on first boot only
    #[cfg(feature = "mock-se")]
    unsafe {
        if !is_provisioned(&mut SE) {
            secure_log!("[S] Unprovisioned (mock SE) — running first-boot provisioning");
            crypto::provision_mock_device(&mut SE);
            secure_log!("[S] Provisioned");
        } else {
            secure_log!("[S] Device already provisioned");
        }
    }

    #[cfg(feature = "tropic01-se")]
    unsafe {
        if !is_provisioned(&mut SE) {
            secure_log!("[S] Unprovisioned (TROPIC01) — running first-boot provisioning");
            let pin: [u8; 8] = *b"12345678";
            SE.provision(&pin, sphincs_tz_shared::MAX_ATTEMPTS)
                .expect("TROPIC01 provisioning failed");
            secure_log!("[S] Provisioned (e2e encrypted)");
        } else {
            secure_log!("[S] Device already provisioned");
        }
    }

    nsc::init_gateway();
    setup_systick();
    secure_log!("[S] Gateway ready");

    ui::show_status("PQSigner OS", "Ready");

    secure_log!("[S] Booting non-secure world...");
    unsafe { boot_ns::boot(NS_FLASH_BASE) }
}

#[cortex_m_rt::exception]
fn SysTick() {
    timeout::tick();

    // Background idle wipe: if PIN state is unlocked and the inactivity
    // timer has fired with no command in flight, wipe.
    if timeout::is_idle() && nsc::is_unlocked() {
        nsc::zeroize_sensitive_state();
        ui::show_status("Locked", "(idle wipe)");
    }

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
