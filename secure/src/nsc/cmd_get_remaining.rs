//! `CMD_GET_REMAINING` — return how many PIN attempts are still
//! available in the current lockout window.
//!
//! User-facing value is the MIN of MCU page-124 and the runtime SE-driver
//! `remaining_attempts()` mirror. For the dual backend that mirror reflects
//! the active unlock paths and is synchronized conservatively from page 124;
//! it is not a fresh, authoritative read of all three silicon counters.
//!
//! Why MIN: never display more attempts than either locally enforced view.
//! Boot rollback detection is separate and directionally compares page 124
//! with readable OPTIGA E120; the production SE050 attempt attribute cannot be
//! peeked without weakening policy or consuming an attempt.

use super::state;

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. Body touches
/// the `static mut crate::SE` driver under the single-threaded
/// dispatcher invariant; no NS pointer derefs.
pub(super) unsafe fn run() -> u32 {
    use crate::secure_element::WalletStore;

    let se = &mut *core::ptr::addr_of_mut!(crate::SE);
    let se_remaining = se.remaining_attempts();

    #[cfg(feature = "stm32u585")]
    let mcu_remaining = {
        let used = crate::hw::flash::pin_attempts_read();
        sphincs_tz_shared::MAX_ATTEMPTS.saturating_sub(used)
    };
    #[cfg(not(feature = "stm32u585"))]
    let mcu_remaining: u8 = sphincs_tz_shared::MAX_ATTEMPTS;

    let remaining = mcu_remaining.min(se_remaining);
    state::with_state(|s| s.remaining_attempts = remaining);
    remaining as u32
}
