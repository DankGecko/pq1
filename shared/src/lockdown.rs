//! Pure silicon-lockdown option-byte decode logic (host-testable).
//!
//! The STM32U585 option-byte *reads* are MMIO and live in the `stm32u585`-gated
//! `secure/src/hw/flash.rs`, which the host test build never compiles (`mod hw`
//! is `#[cfg(not(test))]`). The decode/compare logic below is pure arithmetic
//! with no hardware dependency, so it lives here in the host-compiled `shared`
//! crate and is unit-tested — mirroring how `ns_ptr_validate` keeps the pure
//! NS-pointer window check host-testable while the MMIO deref stays in `secure`.
//!
//! Silicon-lockdown adversarial-review playbook: SL1 (reversible-state-mistaken-
//! for-locked), SL2/SL3 (boot-redirect detectability), SL7 (RDP-verify-in-boot).

/// STM32U585 readout-protection (RDP) level, decoded from `FLASH_OPTR.RDP[7:0]`
/// per RM0456: `0xAA` = Level 0, `0xCC` = Level 2, `0x55` = Level 0.5 (valid
/// only with `TZEN=1`), and **any other value** = Level 1 (the catch-all — RDP1
/// is deliberately NOT a single code). A shipping image should only ever run at
/// Level 2, where SWD/JTAG is disabled in silicon.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RdpLevel {
    L0,
    L0_5,
    L1,
    L2,
}

/// Pure decode of the `FLASH_OPTR.RDP` byte.
#[must_use]
pub const fn rdp_level_from_byte(rdp: u8) -> RdpLevel {
    match rdp {
        0xAA => RdpLevel::L0,
        0x55 => RdpLevel::L0_5,
        0xCC => RdpLevel::L2,
        _ => RdpLevel::L1,
    }
}

/// The `SECBOOTADD0R` address field is `boot_address >> 7`, stored RIGHT-ALIGNED
/// in the low bits (confirmed by `tools/ob-configurator` writing the bare
/// `0x0018_0000` = `0x0C00_0000 >> 7` for the FSBL boot address, with no shift).
/// The field occupies bits `[24:0]`; the high bits `[31:25]` hold control flags
/// (an eventual `BOOT_LOCK` / reserved).
const SECBOOTADD0_ADDR_MASK: u32 = 0x01FF_FFFF;

/// Does the `SECBOOTADD0R` register value select `expected_boot_addr` as the
/// secure boot entry? A shipping image must boot the immutable WRP1A-locked FSBL
/// (`expected_boot_addr = 0x0C00_0000`); a different address is a boot redirect
/// (SL2). The high control bits are masked out so that *setting* `BOOT_LOCK`
/// (whose exact bit position is doc-ambiguous) does not read as a wrong address.
#[must_use]
pub const fn secboot_selects(secbootadd0r: u32, expected_boot_addr: u32) -> bool {
    (secbootadd0r & SECBOOTADD0_ADDR_MASK) == (expected_boot_addr >> 7)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STM32U585 FSBL base (secure bank-1 page 0) — the shipping boot entry.
    const FSBL_BASE: u32 = 0x0C00_0000;

    #[test]
    fn rdp_decode_only_cc_is_level2() {
        assert_eq!(rdp_level_from_byte(0xAA), RdpLevel::L0);
        assert_eq!(rdp_level_from_byte(0xCC), RdpLevel::L2);
        assert_eq!(rdp_level_from_byte(0x55), RdpLevel::L0_5);
        assert_eq!(rdp_level_from_byte(0x00), RdpLevel::L1);
        assert_eq!(rdp_level_from_byte(0xFF), RdpLevel::L1);
        // SL1 (reversible-state-mistaken-for-locked): ONLY 0xCC may decode as
        // Level 2. No erased/garbage byte may read as RDP2, or the boot check
        // would pass on an unlocked part.
        for b in 0u16..=255 {
            let b = b as u8;
            assert_eq!(
                rdp_level_from_byte(b) == RdpLevel::L2,
                b == 0xCC,
                "only 0xCC may decode as RDP2 (byte {b:#04x})"
            );
        }
    }

    #[test]
    fn secboot_selects_fsbl_base_and_tolerates_control_bits() {
        // The value tools/ob-configurator programs (0x0C00_0000 >> 7 = 0x180000).
        assert_eq!(FSBL_BASE >> 7, 0x0018_0000);
        assert!(secboot_selects(0x0018_0000, FSBL_BASE), "FSBL base must pass");
        // Setting high control bits (e.g. an eventual BOOT_LOCK in [31:25]) must
        // NOT flip the address check to "wrong address".
        assert!(secboot_selects(0x0018_0000 | (1 << 31), FSBL_BASE), "BOOT_LOCK bit tolerated");
        assert!(secboot_selects(0x0018_0000 | (1 << 25), FSBL_BASE), "high control bit tolerated");
        // A redirected / erased / off-by-one boot address must FAIL (the SL2
        // boot-redirect signal).
        assert!(!secboot_selects(0x0000_0000, FSBL_BASE), "erased/zero must fail");
        assert!(!secboot_selects(0x0018_0001, FSBL_BASE), "off-by-one addr must fail");
        assert!(!secboot_selects(0x0C08_0000 >> 7, FSBL_BASE), "redirected addr must fail");
        // A control bit WITHIN the address field must still fail (it changes the
        // address) — proves the mask is [24:0], not wider.
        assert!(!secboot_selects(0x0018_0000 | (1 << 24), FSBL_BASE), "addr-field bit changes address");
    }
}
