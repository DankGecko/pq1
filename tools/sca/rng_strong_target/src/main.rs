//! thumbv8m FI target for `secure/src/rng_strong.rs` — the multi-source
//! strong-RNG fold whose failure semantics were tightened to **strict /
//! fail-closed** by `bb2615f6` ("SE-TRNG failure is FATAL under production
//! backends; was a silent fall-through"). work-todo §18b RANK 2.
//!
//! The real `rng_strong::fill` is `#[path]`-included verbatim, so this sweep
//! exercises the SHIPPED control flow:
//!   1. platform TRNG  (`crate::rng::fill(buf)?`)
//!   2. SE fold        (`crate::se_random(block)?`  — OPTIGA ⊕ SE050, both
//!                      mandatory, mirroring `DualSecureElement::random`)
//!   3. fail-closed all-zero acceptance gate (`if acc == 0 { return Err }`)
//!
//! The two crate-root hooks `rng_strong` depends on (`rng::fill`,
//! `se_random`) are supplied here as **harness-controllable stubs**: a set of
//! `#[no_mangle]` control statics lets the sweep choose, per run, whether each
//! source "succeeds" and what byte it contributes — so we can stage the exact
//! failure scenarios bb2615f6 must keep fatal:
//!   * OPTIGA TRNG fails    → must refuse (no degrade to platform ⊕ SE050)
//!   * SE050 TRNG fails     → must refuse
//!   * platform TRNG fails  → must refuse
//!   * all sources stuck-at-0 → all-zero gate must refuse
//!
//! The FI question: can a single skip / stuck-at fault make `fill` return
//! `Ok` (entropy accepted) in any of those scenarios — i.e. force a
//! "SE-TRNG-OK" and let a weakened/zero fold through?
//!
//! **Scope (honest).** Emulation tests the *software* fail-closed logic +
//! all-zero gate. The SE TRNGs themselves, the I2C transport, and the STM32
//! RNG SEIS/CEIS latches are stubbed — their silicon behaviour is out of
//! scope. This is single-fault FI completeness for a new fatal-branch secret
//! path, not a known-bug fire drill.

#![no_std]
#![no_main]

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use cortex_m_rt::entry;
use panic_halt as _;

// ===========================================================================
// Harness-controlled stubs (set via mem_write before each run).
//   *_OK   == 0  → that source FAILS (returns Err)
//   *_BYTE       → the byte that source contributes (uniform fill / XOR)
// Non-`.bss` initial values so a missing harness-set still gives a sane run.
// ===========================================================================
#[no_mangle]
pub static mut RS_PLATFORM_OK: u32 = 1;
#[no_mangle]
pub static mut RS_OPTIGA_OK: u32 = 1;
#[no_mangle]
pub static mut RS_SE050_OK: u32 = 1;
#[no_mangle]
pub static mut RS_PLATFORM_BYTE: u8 = 0x33;
#[no_mangle]
pub static mut RS_OPTIGA_BYTE: u8 = 0xAA;
#[no_mangle]
pub static mut RS_SE050_BYTE: u8 = 0x55;

/// The accepted entropy (out-of-band readback). `.bss` → re-zeroed on reset.
#[no_mangle]
pub static mut SCA_RS_OUT: [u8; 16] = [0u8; 16];

/// Platform TRNG hook (`crate::rng::fill`). Fills `buf` uniformly with
/// `RS_PLATFORM_BYTE`, or fails if `RS_PLATFORM_OK == 0` (STM32 RNG
/// SEIS/CEIS / `/dev/urandom`-unavailable stand-in).
pub mod rng {
    use super::{addr_of, read_volatile, RS_PLATFORM_BYTE, RS_PLATFORM_OK};
    pub fn fill(buf: &mut [u8]) -> Result<(), ()> {
        // SAFETY: single-threaded; volatile reads of harness-set control statics.
        if unsafe { read_volatile(addr_of!(RS_PLATFORM_OK)) } == 0 {
            return Err(());
        }
        let b = unsafe { read_volatile(addr_of!(RS_PLATFORM_BYTE)) };
        for x in buf.iter_mut() {
            *x = b;
        }
        Ok(())
    }
}

/// SE fold hook (`crate::se_random`) — mirrors `DualSecureElement::random`
/// (`secure/src/dual_se.rs:500-515`): OPTIGA contribution mandatory, SE050
/// contribution mandatory, each XOR-folded into `buf`, each failure fatal.
///
/// # Safety
/// Matches the real `crate::se_random` extern signature (an `unsafe fn`); the
/// caller (`rng_strong::fill`) invokes it inside an `unsafe` block.
#[no_mangle]
pub unsafe fn se_random(buf: &mut [u8]) -> Result<(), ()> {
    // OPTIGA contribution — mandatory.
    if read_volatile(addr_of!(RS_OPTIGA_OK)) == 0 {
        return Err(());
    }
    let o = read_volatile(addr_of!(RS_OPTIGA_BYTE));
    for x in buf.iter_mut() {
        *x ^= o;
    }
    // SE050 contribution — mandatory.
    if read_volatile(addr_of!(RS_SE050_OK)) == 0 {
        return Err(());
    }
    let s = read_volatile(addr_of!(RS_SE050_BYTE));
    for x in buf.iter_mut() {
        *x ^= s;
    }
    Ok(())
}

/// The REAL strong-RNG fold (`#[path]`-included; the `not(test),
/// not(mock-se)` production branch with the fatal `?` is the one compiled).
#[path = "../../../../secure/src/rng_strong.rs"]
mod rng_strong;

/// **FI target.** Draw 16 bytes through `rng_strong::fill` (the SPHINCS+C10
/// OptRand size). Returns `1` if entropy was ACCEPTED (`Ok`), `0` if REFUSED
/// (`Err` — the fail-closed outcome). Copies the accepted bytes to
/// `SCA_RS_OUT` so the harness can confirm a bypass actually released weak
/// entropy.
#[no_mangle]
pub extern "C" fn sca_rng_strong_fill() -> u32 {
    let mut buf = [0u8; 16];
    let r = rng_strong::fill(&mut buf);
    if r.is_ok() {
        let p = addr_of_mut!(SCA_RS_OUT) as *mut u8;
        for (i, &b) in buf.iter().enumerate() {
            // SAFETY: SCA_RS_OUT is a 16-byte static; i < 16.
            unsafe { write_volatile(p.add(i), b) };
        }
        1
    } else {
        0
    }
}

// ===========================================================================
// Keep-alive roots.
// ===========================================================================
#[used]
static _KEEP_FILL: extern "C" fn() -> u32 = sca_rng_strong_fill;

#[entry]
fn main() -> ! {
    core::hint::black_box(&_KEEP_FILL);
    // Touch the control statics so they survive DCE even if the harness is
    // the only writer/reader.
    // SAFETY: single-threaded address-of for keep-alive.
    unsafe {
        core::hint::black_box(addr_of!(RS_PLATFORM_OK));
        core::hint::black_box(addr_of!(RS_OPTIGA_OK));
        core::hint::black_box(addr_of!(RS_SE050_OK));
        core::hint::black_box(addr_of!(RS_PLATFORM_BYTE));
        core::hint::black_box(addr_of!(RS_OPTIGA_BYTE));
        core::hint::black_box(addr_of!(RS_SE050_BYTE));
        core::hint::black_box(addr_of!(SCA_RS_OUT));
    }
    loop {
        cortex_m::asm::nop();
    }
}
