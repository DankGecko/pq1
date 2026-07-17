//! Pure decoding of the STM32 `DBGMCU_IDCODE` word: which die is this?
//!
//! Free of MMIO so the decode is host-testable; `hw::dbgmcu` does the single
//! volatile read and hands the word here. Same split, and the same reason, as
//! [`crate::otp_state`] and [`crate::flash_policy`].
//!
//! **Why this exists (work-todo A4a / `HW-ASSUME-REV-U`).** The STM32U5 SESIP
//! certificate — SESIP-2400133-01, security target TN1545 Rev 3, SESIP3 +
//! Physical Attacker Resistance, evaluated at RDP-2 — is the strongest
//! third-party evidence behind `HW-ASSUME-RDP2`, which is in turn the single
//! highest-leverage unverifiable premise in the design. TN1545 §3.3.1 pins the
//! die it covers: **DEV_ID `0x482`, REV_ID `0x3003` = STM32U585 v3.3, "rev U"**.
//!
//! We have never checked. Every DEV_ID probe in this repo is a *plan* in a
//! document (`docs/security/production-security.md`,
//! `docs/security/threat-model.md`, work-todo §"anti-counterfeit probes"); no
//! code reads `DBGMCU_IDCODE` at all. So a certificate for rev U is currently
//! being cited on bench parts whose revision nobody has read. A rev X or rev W
//! die is not a counterfeit and not a defect — it is simply **outside the
//! certificate's scope**, and inheriting the SESIP claims onto it would be an
//! unforced overclaim.
//!
//! Scope, deliberately narrow: this **reads and reports**. It is not the
//! anti-counterfeit boot policy (CPUID r0p4 + UID plausibility + DHUK
//! fingerprint + errata fingerprinting, "halt on any anomaly"), which is a
//! separate, larger work-todo item. Reading a matching IDCODE proves nothing
//! against an attacker who can present any value on a bus they control; it
//! answers a question we are asking about our OWN bench, not an adversary's
//! part.

/// `DBGMCU_IDCODE` `DEV_ID` for the STM32U585 (RM0456 §75.12.1; ST's CMSIS
/// `DBGMCU_IDCODE_DEV_ID_Msk` is bits 0..11).
pub const DEV_ID_STM32U585: u16 = 0x482;

/// `REV_ID` for silicon revision U (v3.3) — the ONLY revision
/// SESIP-2400133-01 / TN1545 Rev 3 covers.
pub const REV_ID_REV_U: u16 = 0x3003;

/// Decoded `DBGMCU_IDCODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DieId {
    /// Bits 0..11 — the device family/part.
    pub dev_id: u16,
    /// Bits 16..31 — the silicon revision.
    pub rev_id: u16,
}

impl DieId {
    /// Decode the raw `DBGMCU_IDCODE` register word.
    #[must_use]
    pub const fn from_idcode(idcode: u32) -> Self {
        Self {
            dev_id: (idcode & 0x0000_0FFF) as u16,
            rev_id: (idcode >> 16) as u16,
        }
    }

    /// Is this the part we believe we are running on?
    #[must_use]
    pub const fn is_stm32u585(self) -> bool {
        self.dev_id == DEV_ID_STM32U585
    }

    /// Is this die inside the scope of SESIP-2400133-01 / TN1545 Rev 3?
    ///
    /// **`false` is not a defect.** It means the SESIP claims — including the
    /// Physical Attacker Resistance package that `HW-ASSUME-RDP2` leans on —
    /// were not evaluated for this die, so they must not be cited for it.
    #[must_use]
    pub const fn is_sesip_covered(self) -> bool {
        self.is_stm32u585() && self.rev_id == REV_ID_REV_U
    }

    /// ST's published revision letter for a known `REV_ID`, or `None`.
    ///
    /// Only revisions we have a source for are listed. `None` means "we have
    /// not established what this is" — NOT "invalid". Guessing a letter for an
    /// unknown code would be inventing provenance.
    #[must_use]
    pub const fn rev_letter(self) -> Option<&'static str> {
        match self.rev_id {
            // TN1545 Rev 3 §3.3.1: REV_ID 0x3003 = "STM32U585x version 3.3 (rev U)".
            0x3003 => Some("U"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact word a rev-U STM32U585 presents. Bit positions are ST's
    /// (`DBGMCU_IDCODE_DEV_ID_Pos = 0`, `REV_ID_Pos = 16`), cross-checked
    /// against the CMSIS header by `make verify-mmio-addresses`' sibling
    /// discipline — a swap here would silently accept the wrong die.
    #[test]
    fn decodes_the_sesip_covered_die() {
        let d = DieId::from_idcode(0x3003_0482);
        assert_eq!(d.dev_id, 0x482);
        assert_eq!(d.rev_id, 0x3003);
        assert!(d.is_stm32u585());
        assert!(d.is_sesip_covered());
        assert_eq!(d.rev_letter(), Some("U"));
    }

    /// A different revision of the SAME part: correct silicon, outside the
    /// certificate. This must be reported, not silently accepted — it is the
    /// whole point of the probe.
    #[test]
    fn same_part_different_revision_is_not_sesip_covered() {
        for rev in [0x1000u16, 0x2000, 0x2001, 0x3000, 0x3002, 0x3004] {
            let d = DieId::from_idcode((u32::from(rev) << 16) | 0x482);
            assert!(d.is_stm32u585(), "rev {rev:#06x} is still a U585");
            assert!(
                !d.is_sesip_covered(),
                "rev {rev:#06x} is NOT rev U — SESIP-2400133-01 does not cover it"
            );
            assert_eq!(d.rev_letter(), None, "we have no source for rev {rev:#06x}");
        }
    }

    /// The right revision number on the WRONG part must not inherit coverage.
    #[test]
    fn rev_u_id_on_a_different_part_is_not_covered() {
        let d = DieId::from_idcode(0x3003_0483);
        assert!(!d.is_stm32u585());
        assert!(!d.is_sesip_covered());
    }

    /// DEV_ID is 12 bits: the nibble above it belongs to no field we read, and
    /// must not bleed into the comparison.
    #[test]
    fn dev_id_is_masked_to_12_bits() {
        // 0x1482 & 0xFFF == 0x482 — but the part is NOT a U585.
        let d = DieId::from_idcode(0x3003_1482);
        assert_eq!(d.dev_id, 0x482, "bits 12..15 are not part of DEV_ID");
        // Documented consequence: this decoder cannot distinguish it. The
        // reserved nibble is not a field ST defines, so there is nothing to
        // check it against — recorded rather than silently assumed benign.
        assert!(d.is_stm32u585());
    }

    #[test]
    fn all_zero_and_all_ones_are_not_our_die() {
        assert!(!DieId::from_idcode(0x0000_0000).is_sesip_covered());
        assert!(!DieId::from_idcode(0xFFFF_FFFF).is_sesip_covered());
        // A dead/undriven bus reads one of these; neither may pass.
        assert!(!DieId::from_idcode(0xFFFF_FFFF).is_stm32u585());
    }

    /// Field independence: DEV_ID must come from the low bits and REV_ID from
    /// the high ones. A swapped shift passes the happy-path test above only if
    /// this one is absent.
    #[test]
    fn fields_are_not_swapped() {
        let d = DieId::from_idcode(0x0482_3003);
        assert_eq!(d.dev_id, 0x003, "low 12 bits");
        assert_eq!(d.rev_id, 0x0482, "high 16 bits");
        assert!(!d.is_sesip_covered());
    }
}
