//! DBGMCU — read the die identity (`DBGMCU_IDCODE`).
//!
//! The MMIO half of [`crate::die_id`]; the decode and every policy question
//! live there, host-tested. This file is one register read.
//!
//! See `crate::die_id` for WHY (work-todo A4a / `HW-ASSUME-REV-U`): the STM32U5
//! SESIP certificate covers REV_ID `0x3003` (rev U) and nothing else, and no
//! code in this repo has ever read the revision it is being cited on.

use super::mmio::RoReg32;

/// `DBGMCU_BASE` — ST CMSIS `stm32u585xx.h`: `#define DBGMCU_BASE (0xE0044000UL)`.
/// Accessible from the secure world; `hw::iwdg` already drives `DBGMCU_APB1FZR1`
/// at `+0x08` off this same base.
const DBGMCU_BASE: u32 = 0xE004_4000;
/// `DBGMCU_IDCODE` is at offset 0x00 (RM0456 §75.12.1).
const DBGMCU_IDCODE_ADDR: u32 = DBGMCU_BASE;

// SAFETY: a real, 4-byte-aligned, read-only debug register. Reads are pure
// loads with no side effects and no ordering requirement against anything else.
const IDCODE: RoReg32 = unsafe { RoReg32::new(DBGMCU_IDCODE_ADDR) };

/// Read and decode `DBGMCU_IDCODE`.
#[must_use]
pub fn die_id() -> crate::die_id::DieId {
    crate::die_id::DieId::from_idcode(IDCODE.read())
}

/// Log the die identity and whether it is inside the SESIP certificate's scope.
///
/// Report-only, by design. A mismatch is NOT a fault: a rev X/W part is
/// perfectly good silicon that SESIP-2400133-01 simply does not cover, and the
/// consequence is a documentation one — `HW-ASSUME-RDP2`'s certificate evidence
/// must not be cited for this die. Halting here would conflate "outside a
/// certificate's scope" with "broken", and would brick every bench board that
/// predates rev U.
///
/// The separate, larger anti-counterfeit boot policy (CPUID r0p4 + UID
/// plausibility + DHUK fingerprint, halt-on-anomaly) is where a *fault* belongs;
/// this is not that, and an IDCODE read proves nothing against an attacker who
/// controls the part anyway.
pub fn report_die_id() {
    let d = die_id();
    let _ = d;
    secure_log!(
        "[S] die: DBGMCU_IDCODE dev_id={:#05x} rev_id={:#06x} rev={} u585={} sesip_covered={}",
        d.dev_id,
        d.rev_id,
        d.rev_letter().unwrap_or("?"),
        d.is_stm32u585(),
        d.is_sesip_covered()
    );
    if !d.is_sesip_covered() {
        secure_log!(
            "[S] die: NOT the SESIP-2400133-01 die (TN1545 Rev 3 pins dev_id=0x482 \
             rev_id=0x3003 'rev U'). The certificate's Physical-Attacker-Resistance \
             evidence behind HW-ASSUME-RDP2 does NOT apply to this part. Not a defect; \
             a scope fact — record it."
        );
    }
}
