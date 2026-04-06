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

use secure_element::MockSecureElement;

const NS_FLASH_BASE: u32 = 0x0020_0000;

// SysTick registers (secure)
const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;

// Global secure element instance
static mut SE: MockSecureElement = MockSecureElement::new();

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

    // Enroll test keypair (PIN: "12345678")
    unsafe { crypto::enroll_test_key(&mut SE) };
    hprintln!("[S] Test key enrolled (PIN: 12345678)");

    nsc::init_gateway();
    setup_systick();
    hprintln!("[S] Gateway ready");

    hprintln!("[S] Booting non-secure world...");
    unsafe { boot_ns::boot(NS_FLASH_BASE) }
}

#[cortex_m_rt::exception]
fn SysTick() {
    nsc::poll_gateway();
}
