/// SAU and MPC configuration for mps2-an505 (Cortex-M33 TrustZone).

// SAU register addresses (ARMv8-M standard)
const SAU_CTRL: *mut u32 = 0xE000_EDD0 as *mut u32;
const SAU_RNR: *mut u32 = 0xE000_EDD8 as *mut u32;
const SAU_RBAR: *mut u32 = 0xE000_EDDC as *mut u32;
const SAU_RLAR: *mut u32 = 0xE000_EDE0 as *mut u32;

// MPC base addresses for mps2-an505 (SSE-200 IoTKit)
const MPC0_BASE: u32 = 0x5800_7000; // SSRAM-0 (code, 4MB)
const MPC1_BASE: u32 = 0x5800_8000; // SSRAM-1 (data, 2MB)

// MPC register offsets
const MPC_BLK_MAX: u32 = 0x10;
const MPC_BLK_IDX: u32 = 0x18;
const MPC_BLK_LUT: u32 = 0x1C;

extern "C" {
    static __veneer_base: u32;
    static __veneer_limit: u32;
}

unsafe fn configure_sau_region(region: u32, base: u32, limit: u32, nsc: bool) {
    core::ptr::write_volatile(SAU_RNR, region);
    core::ptr::write_volatile(SAU_RBAR, base & 0xFFFF_FFE0);
    let nsc_bit = if nsc { 1 << 1 } else { 0 };
    core::ptr::write_volatile(SAU_RLAR, (limit & 0xFFFF_FFE0) | nsc_bit | 1);
}

unsafe fn configure_mpc_partial_ns(mpc_base: u32, ns_start_lut_idx: u32) {
    let blk_max = core::ptr::read_volatile((mpc_base + MPC_BLK_MAX) as *const u32);
    let blk_idx_reg = (mpc_base + MPC_BLK_IDX) as *mut u32;
    let blk_lut_reg = (mpc_base + MPC_BLK_LUT) as *mut u32;

    for idx in 0..=blk_max {
        core::ptr::write_volatile(blk_idx_reg, idx);
        let val = if idx >= ns_start_lut_idx { 0xFFFF_FFFF } else { 0 };
        core::ptr::write_volatile(blk_lut_reg, val);
    }
}

pub fn init() {
    unsafe {
        // MPC0: SSRAM-0 — first 2MB secure (code), rest NS (NS code + NSC veneers)
        configure_mpc_partial_ns(MPC0_BASE, 64);

        // MPC1: SSRAM-1 — first 128KB secure (stack), rest NS
        configure_mpc_partial_ns(MPC1_BASE, 4);

        // Disable SAU while configuring
        core::ptr::write_volatile(SAU_CTRL, 0);

        // Region 0: NS code flash (SSRAM-0 NS alias, 0x200000+)
        configure_sau_region(0, 0x0020_0000, 0x003F_FFFF, false);

        // Region 1: NSC veneers (placed in NSC memory region by linker)
        let veneer_base = &__veneer_base as *const u32 as u32;
        let veneer_limit = &__veneer_limit as *const u32 as u32;
        let nsc_end = if veneer_limit > veneer_base {
            ((veneer_limit + 0xFF) & 0xFFFF_FF00) - 1
        } else {
            veneer_base + 0xFF
        };
        configure_sau_region(1, veneer_base, nsc_end, true);

        // Region 2: NS data SRAM (SSRAM-1 NS alias, offset 128KB)
        configure_sau_region(2, 0x2802_0000, 0x29FF_FFFF, false);

        // Region 3: NS peripherals
        configure_sau_region(3, 0x4000_0000, 0x4FFF_FFFF, false);

        // Enable SAU + barriers
        core::ptr::write_volatile(SAU_CTRL, 1);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }
}
