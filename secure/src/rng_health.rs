//! Pure acceptance checks for words returned by the STM32U5 TRNG.
//!
//! The MMIO state machine lives in [`crate::hw::rng`].  Keeping these
//! predicates hardware-free lets the host suite exercise the two software
//! health tests that sit behind the peripheral's own SP 800-90B tests:
//! reject an all-zero word and reject two consecutive identical words.

/// Whether one observed TRNG word is safe to release to a caller.
///
/// `status_clean` must describe the status sampled *after* reading RNG_DR.
/// `previous` uses zero as the "no previous word" sentinel, which is
/// unambiguous because zero is rejected independently.
#[inline]
pub(crate) fn word_is_acceptable(status_clean: bool, word: u32, previous: u32) -> bool {
    status_clean && word != 0 && word != previous
}

#[cfg(test)]
mod tests {
    use super::word_is_acceptable;

    #[test]
    fn accepts_clean_nonzero_nonrepeating_word() {
        assert!(word_is_acceptable(true, 0x1234_5678, 0x8765_4321));
        assert!(word_is_acceptable(true, 0x1234_5678, 0));
    }

    #[test]
    fn rejects_error_observation_even_for_plausible_word() {
        assert!(!word_is_acceptable(false, 0x1234_5678, 0x8765_4321));
    }

    #[test]
    fn rejects_zero_and_continuous_repeat() {
        assert!(!word_is_acceptable(true, 0, 0));
        assert!(!word_is_acceptable(true, 0xA5A5_5A5A, 0xA5A5_5A5A));
    }
}
