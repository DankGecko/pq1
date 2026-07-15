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
/// secure boot entry? A target shipping image must select the approved FSBL
/// base (`expected_boot_addr = 0x0C00_0000`); a different address is a boot
/// redirect (SL2). This predicate proves only the address selection, not the
/// FSBL extent, WRP mapping, or lifecycle state. The high control bits are
/// masked out so that *setting* `BOOT_LOCK` (whose exact bit position is
/// doc-ambiguous) does not read as a wrong address.
#[must_use]
pub const fn secboot_selects(secbootadd0r: u32, expected_boot_addr: u32) -> bool {
    (secbootadd0r & SECBOOTADD0_ADDR_MASK) == (expected_boot_addr >> 7)
}

// ===========================================================================
// Ship option-byte profile (work-todo #36 — first-boot RDP-2 self-lock).
//
// Devices ship at RDP-0 with a batch-uniform image; the first field boot
// verifies the option bytes against this profile BEFORE programming RDP=0xCC.
// A mismatch means the unit did not leave the factory in the published state
// (or a transit attacker tampered with the option bytes) → the first-boot
// flow halts UNLOCKED with a numbered fault (never bricks a bad unit into
// RDP-2). The open-source RDP-0 verifier tool reuses these same const fns so
// the published profile and the on-device check can never diverge.
//
// Register layout confidence (STM32U585, RM0456 §7.11):
//   CONFIRMED (code-cross-checked): TZEN=bit31 of FLASH_OPTR; RDP=OPTR[7:0];
//     SECWM1R1 all-secure = 0x007F_0000 and SECWM2R1 all-NS = 0x0000_007F
//     (tools/ob-configurator/src/main.rs:104-114); SECBOOTADD0 via
//     `secboot_selects`.
//   BENCH-CONFIRM (exact bit positions are an RM0456 pin — see the #36
//     deferred silicon-validation runbook): BOR_LEV field, WRP1A page span,
//     and the OEM1/OEM2 key-lock status bits. These live behind the single
//     named constants below so one bench correction fixes every caller. The
//     host tests below exercise the comparator LOGIC, not the silicon truth.
// ===========================================================================

/// `FLASH_OPTR.TZEN` — TrustZone enable (bit 31). Must be set in the ship
/// profile (secure world is mandatory).
pub const OPTR_TZEN: u32 = 1 << 31;

/// Expected `FLASH_OPTR.RDP` byte in the *ship* state (RDP Level 0). The
/// first-boot flow only programs `0xCC` (Level 2) after this verifies.
pub const SHIP_RDP_BYTE: u8 = 0xAA;

/// `SECWM1R1` value that marks all of bank 1 secure (`PSTRT=0, PEND=0x7F`).
pub const SECWM1_ALL_SECURE: u32 = 0x007F_0000;
/// `SECWM2R1` value that marks all of bank 2 non-secure (`PSTRT=0x7F > PEND=0`).
pub const SECWM2_ALL_NS: u32 = 0x0000_007F;

/// BENCH-CONFIRM (RM0456): `FLASH_OPTR.BOR_LEV` field position. Best-effort
/// per RM0456; pin against silicon in the #36 runbook before this field is
/// treated as load-bearing (it is advisory today — see `ShipProfile`).
pub const BOR_LEV_SHIFT: u32 = 8;
pub const BOR_LEV_MASK: u32 = 0x7;

/// BENCH-CONFIRM (RM0456): OEM1/OEM2 key-lock status bits. A shipped unit must
/// have NO OEM key provisioned — otherwise a transit attacker could pre-plant
/// an OEM2 password enabling a later RDP-2 → RDP-1 regression. Exact register
/// (FLASH_NSSR vs FLASH_OPTSR) + bit positions are a runbook pin; the mask is
/// isolated here so the correction is one line.
pub const OEM1LOCK: u32 = 1 << 26;
pub const OEM2LOCK: u32 = 1 << 27;

/// Which option-byte field failed verification — drives the numbered
/// first-boot fault screen so a mismatch reports *what* was wrong.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ObField {
    Tzen,
    Rdp,
    Secwm1,
    Secwm2,
    SecBootAdd0,
    Wrp1a,
    OemLock,
}

/// The confirmed, load-bearing half of the ship option-byte profile. Fields
/// whose exact bit layout is still an RM0456 bench pin (BOR_LEV, WRP1A span)
/// are checked by the separate `bor_lev_ok` / `wrp1a_covers_fsbl` const fns
/// and are advisory until pinned.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ShipProfile {
    /// Expected secure boot entry (WRP1A-locked FSBL base).
    pub boot_addr: u32,
    /// Expected `FLASH_OPTR.RDP` byte at ship (Level 0).
    pub rdp_byte: u8,
}

/// The STM32U585 ship profile (RDP-0, TZEN=1, all-bank-1-secure, FSBL boot).
pub const SHIP_PROFILE_U585: ShipProfile = ShipProfile {
    boot_addr: 0x0C00_0000,
    rdp_byte: SHIP_RDP_BYTE,
};

/// Verify `FLASH_OPTR` matches the ship profile's TZEN + RDP fields.
#[must_use]
pub const fn optr_matches_ship(optr: u32, p: &ShipProfile) -> Result<(), ObField> {
    if optr & OPTR_TZEN == 0 {
        return Err(ObField::Tzen);
    }
    if (optr & 0xFF) as u8 != p.rdp_byte {
        return Err(ObField::Rdp);
    }
    Ok(())
}

/// Is `secwm1r1` the "all bank 1 secure" value?
#[must_use]
pub const fn secwm_bank1_all_secure(secwm1r1: u32) -> bool {
    secwm1r1 == SECWM1_ALL_SECURE
}

/// Is `secwm2r1` the "all bank 2 non-secure" value?
#[must_use]
pub const fn secwm_bank2_all_ns(secwm2r1: u32) -> bool {
    secwm2r1 == SECWM2_ALL_NS
}

/// Does the WRP1A option register lock (write-protect) FSBL pages 0..=3?
///
/// BENCH-CONFIRM (RM0456): the `WRP1AR` layout is `STRT` in bits `[6:0]`,
/// `END` in bits `[22:16]`, `UNLOCK` in bit `[31]` (0 = locked). We require
/// `UNLOCK==0` and the `[STRT..=END]` span to cover pages 0..=3. The exact
/// bit fields are a runbook pin; kept in one place for a one-line fix.
#[must_use]
pub const fn wrp1a_covers_fsbl(wrp1ar: u32) -> bool {
    let unlock = (wrp1ar >> 31) & 1;
    let strt = wrp1ar & 0x7F;
    let end = (wrp1ar >> 16) & 0x7F;
    unlock == 0 && strt == 0 && end >= 3
}

/// Are BOTH OEM key-lock bits clear (no OEM key provisioned at ship)?
#[must_use]
pub const fn oem_locks_absent(oem_status: u32) -> bool {
    oem_status & (OEM1LOCK | OEM2LOCK) == 0
}

/// Advisory BOR-level check (BENCH-CONFIRM position). Returns the decoded
/// 3-bit BOR level so the caller can log/compare; not yet a hard gate because
/// the shipped BOR_LEV target is still being pinned (#36).
#[must_use]
pub const fn bor_lev(optr: u32) -> u32 {
    (optr >> BOR_LEV_SHIFT) & BOR_LEV_MASK
}

/// Full ship-profile verification over the raw option-byte register reads.
/// Returns the first failing field, or `Ok(())` if every load-bearing field
/// matches. Ordered most-fundamental-first (TZEN → RDP → windows → boot addr →
/// WRP → OEM locks) so the fault screen names the most basic discrepancy.
///
/// The caller (first-boot Phase A) additionally blank-checks the per-device
/// flash pages 123..=127 — that lives in the hw layer since it reads flash,
/// not option bytes.
#[must_use]
pub const fn verify_ship_profile(
    optr: u32,
    secwm1r1: u32,
    secwm2r1: u32,
    secbootadd0r: u32,
    wrp1ar: u32,
    oem_status: u32,
    p: &ShipProfile,
) -> Result<(), ObField> {
    if let Err(f) = optr_matches_ship(optr, p) {
        return Err(f);
    }
    if !secwm_bank1_all_secure(secwm1r1) {
        return Err(ObField::Secwm1);
    }
    if !secwm_bank2_all_ns(secwm2r1) {
        return Err(ObField::Secwm2);
    }
    if !secboot_selects(secbootadd0r, p.boot_addr) {
        return Err(ObField::SecBootAdd0);
    }
    if !wrp1a_covers_fsbl(wrp1ar) {
        return Err(ObField::Wrp1a);
    }
    if !oem_locks_absent(oem_status) {
        return Err(ObField::OemLock);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Legacy bench FSBL base; the target shipping entry remains gated by the
    /// production geometry, WRP/option-byte ceremony, and silicon receipts.
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

    // --- Ship option-byte profile (work-todo #36) ---------------------------

    /// A well-formed ship-state OPTR: TZEN set, RDP=0xAA, plausible BOR field.
    const GOOD_OPTR: u32 = OPTR_TZEN | (0x3 << BOR_LEV_SHIFT) | (SHIP_RDP_BYTE as u32);
    /// WRP1A locking pages 0..=3: UNLOCK=0, STRT=0, END=3.
    const GOOD_WRP1A: u32 = (3 << 16) | 0;

    #[test]
    fn optr_ship_requires_tzen_and_rdp0() {
        assert_eq!(optr_matches_ship(GOOD_OPTR, &SHIP_PROFILE_U585), Ok(()));
        // TZEN clear → Tzen fault.
        assert_eq!(
            optr_matches_ship(GOOD_OPTR & !OPTR_TZEN, &SHIP_PROFILE_U585),
            Err(ObField::Tzen)
        );
        // RDP already 0xCC (Level 2) at "ship" → not a fresh RDP-0 unit.
        let optr_l2 = (GOOD_OPTR & !0xFF) | 0xCC;
        assert_eq!(optr_matches_ship(optr_l2, &SHIP_PROFILE_U585), Err(ObField::Rdp));
        // RDP Level 1 (garbage byte) → Rdp fault (only 0xAA passes at ship).
        let optr_l1 = (GOOD_OPTR & !0xFF) | 0x11;
        assert_eq!(optr_matches_ship(optr_l1, &SHIP_PROFILE_U585), Err(ObField::Rdp));
    }

    #[test]
    fn secwm_window_exact_match() {
        assert!(secwm_bank1_all_secure(SECWM1_ALL_SECURE));
        assert!(!secwm_bank1_all_secure(SECWM1_ALL_SECURE | 1), "any deviation fails");
        assert!(!secwm_bank1_all_secure(0), "erased fails");
        assert!(secwm_bank2_all_ns(SECWM2_ALL_NS));
        assert!(!secwm_bank2_all_ns(SECWM2_ALL_NS ^ 0x0001_0000), "partial-secure bank2 fails");
    }

    #[test]
    fn wrp1a_must_lock_and_span_fsbl() {
        assert!(wrp1a_covers_fsbl(GOOD_WRP1A), "STRT=0 END=3 UNLOCK=0 covers pages 0..=3");
        assert!(wrp1a_covers_fsbl((7 << 16) | 0), "wider span still covers 0..=3");
        // UNLOCK=1 (bit31 set) → write-protect removable → NOT covered.
        assert!(!wrp1a_covers_fsbl(GOOD_WRP1A | (1 << 31)), "UNLOCK=1 fails");
        // Span starting at page 1 leaves FSBL page 0 unprotected.
        assert!(!wrp1a_covers_fsbl((3 << 16) | 1), "STRT=1 leaves page 0 open");
        // Span ending at page 2 leaves page 3 unprotected.
        assert!(!wrp1a_covers_fsbl((2 << 16) | 0), "END=2 leaves page 3 open");
    }

    #[test]
    fn oem_locks_must_be_absent_at_ship() {
        assert!(oem_locks_absent(0), "no OEM key → ok");
        assert!(!oem_locks_absent(OEM1LOCK), "OEM1 provisioned → fail");
        assert!(!oem_locks_absent(OEM2LOCK), "OEM2 provisioned (regression-password risk) → fail");
        assert!(!oem_locks_absent(OEM1LOCK | OEM2LOCK), "both → fail");
        // Unrelated status bits do not trip the check.
        assert!(oem_locks_absent(1 << 3), "unrelated bit ignored");
    }

    #[test]
    fn verify_ship_profile_orders_and_passes_good_state() {
        assert_eq!(
            verify_ship_profile(
                GOOD_OPTR, SECWM1_ALL_SECURE, SECWM2_ALL_NS,
                FSBL_BASE >> 7, GOOD_WRP1A, 0, &SHIP_PROFILE_U585,
            ),
            Ok(())
        );
        // Each corruption surfaces its own field, in fundamental-first order.
        assert_eq!(
            verify_ship_profile(GOOD_OPTR & !OPTR_TZEN, SECWM1_ALL_SECURE, SECWM2_ALL_NS, FSBL_BASE >> 7, GOOD_WRP1A, 0, &SHIP_PROFILE_U585),
            Err(ObField::Tzen)
        );
        assert_eq!(
            verify_ship_profile(GOOD_OPTR, 0, SECWM2_ALL_NS, FSBL_BASE >> 7, GOOD_WRP1A, 0, &SHIP_PROFILE_U585),
            Err(ObField::Secwm1)
        );
        assert_eq!(
            verify_ship_profile(GOOD_OPTR, SECWM1_ALL_SECURE, 0, FSBL_BASE >> 7, GOOD_WRP1A, 0, &SHIP_PROFILE_U585),
            Err(ObField::Secwm2)
        );
        assert_eq!(
            verify_ship_profile(GOOD_OPTR, SECWM1_ALL_SECURE, SECWM2_ALL_NS, 0, GOOD_WRP1A, 0, &SHIP_PROFILE_U585),
            Err(ObField::SecBootAdd0)
        );
        assert_eq!(
            verify_ship_profile(GOOD_OPTR, SECWM1_ALL_SECURE, SECWM2_ALL_NS, FSBL_BASE >> 7, GOOD_WRP1A | (1 << 31), 0, &SHIP_PROFILE_U585),
            Err(ObField::Wrp1a)
        );
        assert_eq!(
            verify_ship_profile(GOOD_OPTR, SECWM1_ALL_SECURE, SECWM2_ALL_NS, FSBL_BASE >> 7, GOOD_WRP1A, OEM2LOCK, &SHIP_PROFILE_U585),
            Err(ObField::OemLock)
        );
    }
}
