/// Boot the non-secure world.
///
/// Sets VTOR_NS, MSP_NS, then branches to the NS reset vector via BXNS.
///
/// The MPC must be configured before calling this so that the NS flash
/// region at `ns_vector_table` is accessible.

// Non-Secure Vector Table Offset Register
const VTOR_NS: *mut u32 = 0xE002_ED08 as *mut u32;

/// # Safety
///
/// `ns_vector_table` must point to a valid non-secure vector table
/// in non-secure flash (NS alias address space, e.g. 0x00200000).
/// The MPC must already be configured to allow access.
/// This function does not return.
pub unsafe fn boot(ns_vector_table: u32) -> ! {
    let vt = ns_vector_table as *const u32;

    // 1. Set VTOR_NS
    core::ptr::write_volatile(VTOR_NS, ns_vector_table);

    // 2. Read NS initial stack pointer (vector table entry 0)
    let ns_msp = core::ptr::read_volatile(vt);

    // 3. Set MSP_NS
    core::arch::asm!(
        "msr MSP_NS, {0}",
        in(reg) ns_msp,
    );

    // 4. Read NS reset handler (vector table entry 1)
    let ns_reset = core::ptr::read_volatile(vt.add(1));

    // 5. Branch to non-secure reset handler (clear LSB for NS target)
    let ns_entry = ns_reset & !1u32;
    core::arch::asm!(
        "bxns {0}",
        in(reg) ns_entry,
        options(noreturn),
    );
}
