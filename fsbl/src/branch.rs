//! Branch into the selected slot's reset handler.
//!
//! On a Cortex-M33 reset vector layout, the first 4 bytes of the
//! image are the initial stack pointer, and the next 4 are the
//! reset-handler address (Thumb bit set). We:
//!
//! 1. Re-point VTOR to the slot's vector table.
//! 2. Set MSP to the slot's initial stack pointer.
//! 3. Scrub every general-purpose register the FSBL may have dirtied
//!    (r0, r1, r4–r12, lr) so the new image inherits no residue from
//!    SPHINCS+ verification or flash/manifest parsing — the Trezor
//!    boot-stage hygiene analog.
//! 4. Branch to the slot's reset handler.
//!
//! After the branch we never return. The slot's own `#[cortex_m_rt::entry]`
//! machinery zeroes BSS, copies .data, calls `main()`, etc.
//!
//! Register state at handoff: the only surviving registers are the two
//! architectural handoff values — the slot's initial MSP (held in r2,
//! moved into MSP *before* the scrub) and the reset-handler address
//! (held in r3, the branch target) — plus SP by construction. Both are
//! non-secret flash addresses; everything else is zeroed.

use core::arch::asm;
use core::ptr::read_volatile;

use crate::slot::{slot_secure_addr, Slot};

/// Perform the handoff to `slot`. **Does not return.**
///
/// # Safety
///
/// Caller must have verified the slot's image hash matches the
/// manifest's signed `secure_hash`. Branching to an unverified slot
/// is a full sandbox-escape for any attacker who can write flash,
/// which in our model means someone with unfuse-level physical
/// access — but we don't rely on that, we rely on the hash check.
pub unsafe fn into_slot(slot: Slot) -> ! {
    let vtor_addr = slot_secure_addr(slot) as *const u32;

    // SAFETY: `vtor_addr` is an aligned flash address within the slot.
    // The first two u32s are the initial MSP value and the reset-
    // handler address, as defined by the Cortex-M startup convention.
    let msp = unsafe { read_volatile(vtor_addr) };
    let reset = unsafe { read_volatile(vtor_addr.add(1)) };

    // Update VTOR so the CPU finds interrupt vectors at the slot's
    // base address (System Control Block offset 0x08 — SCB_VTOR).
    const SCB_VTOR: *mut u32 = 0xE000_ED08 as *mut u32;
    // SAFETY: SCB_VTOR is an MMIO register; write is atomic.
    unsafe {
        core::ptr::write_volatile(SCB_VTOR, vtor_addr as u32);
    }

    // Data + instruction sync so the CPU picks up the new vector
    // table before the next interrupt / memory access.
    cortex_m::asm::dsb();
    cortex_m::asm::isb();

    // Set MSP + scrub + jump. We're already in handler mode per the
    // cortex-m-rt entry-path contract, so we can write MSP directly.
    // After the bx, the slot's reset handler takes over — it sees an
    // initialized MSP and the Thumb bit is already in the reset value
    // (cortex-m-rt always sets it).
    //
    // The handoff values are pinned to r2/r3 by explicit constraints so
    // the scrub cannot clobber them; they necessarily stay live until
    // the branch (both are non-secret flash addresses — see the module
    // doc). MSP is installed FIRST, then every other GPR the FSBL's
    // SPHINCS+ verify / flash / manifest parsing may have dirtied is
    // zeroed, then we branch.
    unsafe {
        asm!(
            // 1. Install the slot's stack pointer before any register
            //    is cleared.
            "msr MSP, r2",
            // 2. Scrub every GPR except the r2/r3 handoff pair.
            "mov r0, #0",
            "mov r1, #0",
            "mov r4, #0",
            "mov r5, #0",
            "mov r6, #0",
            "mov r7, #0",
            "mov r8, #0",
            "mov r9, #0",
            "mov r10, #0",
            "mov r11, #0",
            "mov r12, #0",
            "mov lr, r0",
            // 3. Branch; only r2 (already in MSP), r3 (target), and SP
            //    carry state across.
            "bx r3",
            in("r2") msp,
            in("r3") reset,
            options(noreturn)
        );
    }
}
