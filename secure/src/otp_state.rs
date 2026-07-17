//! Pure classification of the device-master-key OTP region.
//!
//! The master key occupies **two** OTP quad-words and the STM32U585 programs
//! one *complete* quad-word at a time, so a reset between the two programs
//! leaves a region that is neither blank nor complete. Getting that third
//! state wrong is not cosmetic: classifying per-*bit* ("any bit cleared ⇒
//! burned") reports an interrupted burn as burned, `read_device_master` then
//! hands back `[QW0 ‖ 0xFF×16]`, and every SE transport credential (SCP03
//! enc/mac/dek, admin PIN, OPTIGA PBS) roots in a silently halved, 128-bit
//! master — permanently, with no detection and no retry. That was the D4
//! defect, fixed 2026-07-17.
//!
//! Keeping the rule free of MMIO makes it executable on the host; the hardware
//! driver in `hw::otp` performs the volatile reads and consumes this verdict.
//! (Same split, and for the same reason, as [`crate::flash_policy`].)
//!
//! The lesson generalises: model at the granularity the silicon actually
//! commits at. The repo already learned this once — the rejected unary
//! rollback tally in `hw::otp` assumed a bit-lattice, which is *true* at the
//! bit level and still produced an invalid design, because the binding
//! constraint is quad-word-program-once, not bit monotonicity. D4 is the same
//! mistake applied to the master key.

/// Size of the device master key in bytes.
pub(crate) const MASTER_KEY_SIZE: usize = 32;
/// Number of 32-bit words in the device-master-key region (32 B = 8 words).
pub(crate) const MASTER_KEY_WORDS: usize = MASTER_KEY_SIZE / 4;
/// Bytes in one OTP quad-word — the STM32U585 program granularity.
pub(crate) const QW_BYTES: usize = 16;
/// 32-bit words in one OTP quad-word.
pub(crate) const WORDS_PER_QW: usize = QW_BYTES / 4;
/// Quad-words spanned by the device master key. **Two** — the burn is not
/// atomic; it takes two separate programs with a reset window between them.
pub(crate) const MASTER_KEY_QWS: usize = MASTER_KEY_SIZE / QW_BYTES;
/// A blank (never-programmed) OTP word. Erased OTP reads all-1s.
pub(crate) const BLANK_WORD: u32 = 0xFFFF_FFFF;

/// Which quad-words of the device-master-key region are programmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasterKeyState {
    /// Both quad-words virgin (all `0xFF`). A burn may proceed.
    Virgin,
    /// Exactly one quad-word programmed — an interrupted burn. Completable:
    /// the virgin quad-word can still take its one legal program.
    Partial,
    /// Both quad-words programmed.
    Complete,
}

/// Is quad-word `qw` programmed?
///
/// Any word `!= BLANK_WORD` inside the quad-word means at least one bit has
/// flipped, so the quad-word has taken its one legal program and is now
/// immutable. This is a *per-quad-word* predicate on purpose — the quad-word
/// is the granularity at which the silicon commits.
#[must_use]
pub(crate) const fn qw_programmed(words: &[u32; MASTER_KEY_WORDS], qw: usize) -> bool {
    let base = qw * WORDS_PER_QW;
    let mut w = 0;
    while w < WORDS_PER_QW {
        if words[base + w] != BLANK_WORD {
            return true;
        }
        w += 1;
    }
    false
}

/// Classify the master-key region from its eight raw words.
#[must_use]
pub const fn classify_master_words(words: &[u32; MASTER_KEY_WORDS]) -> MasterKeyState {
    match (qw_programmed(words, 0), qw_programmed(words, 1)) {
        (false, false) => MasterKeyState::Virgin,
        (true, true) => MasterKeyState::Complete,
        // Either order is `Partial`. `(true, false)` is the D4 tear between
        // the two programs. `(false, true)` is reachable too, because the
        // pre-fix burn ran BOTH programs before inspecting either result, so a
        // failed QW0 could still be followed by a successful QW1.
        _ => MasterKeyState::Partial,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: u32 = BLANK_WORD;

    fn words(qw0: [u32; 4], qw1: [u32; 4]) -> [u32; MASTER_KEY_WORDS] {
        let mut w = [B; MASTER_KEY_WORDS];
        w[..4].copy_from_slice(&qw0);
        w[4..].copy_from_slice(&qw1);
        w
    }

    #[test]
    fn virgin_region_is_virgin() {
        assert_eq!(
            classify_master_words(&[B; MASTER_KEY_WORDS]),
            MasterKeyState::Virgin
        );
    }

    #[test]
    fn fully_burned_region_is_complete() {
        assert_eq!(
            classify_master_words(&words([1, 2, 3, 4], [5, 6, 7, 8])),
            MasterKeyState::Complete
        );
    }

    /// **The D4 regression test.** A burn interrupted between its two
    /// quad-word programs. The pre-fix rule ("any word != blank ⇒ burned")
    /// called this `Complete`; `read_device_master` then returned
    /// `[QW0 ‖ 0xFF×16]` and every SE transport credential rooted in a
    /// 128-bit master. It must be `Partial`.
    #[test]
    fn qw0_burned_qw1_virgin_is_partial_not_complete() {
        assert_eq!(
            classify_master_words(&words([0xDEAD_BEEF, 0xCAFE_BABE, 1, 2], [B; 4])),
            MasterKeyState::Partial,
            "an interrupted burn must never classify as Complete — this is D4"
        );
    }

    /// Reachable because the pre-fix burn ran both programs before checking
    /// either result, so a failed QW0 could be followed by a successful QW1.
    #[test]
    fn qw0_virgin_qw1_burned_is_partial() {
        assert_eq!(
            classify_master_words(&words([B; 4], [0xDEAD_BEEF, 1, 2, 3])),
            MasterKeyState::Partial
        );
    }

    /// The tightest form of the bug: a SINGLE cleared bit anywhere in QW0 was
    /// enough for the old rule to declare the whole 32-byte master burned.
    #[test]
    fn one_cleared_bit_in_qw0_alone_is_partial() {
        for i in 0..WORDS_PER_QW {
            let mut qw0 = [B; 4];
            qw0[i] = B & !1; // exactly one bit programmed
            assert_eq!(
                classify_master_words(&words(qw0, [B; 4])),
                MasterKeyState::Partial,
                "one cleared bit in QW0 word {i} must not mean the master is burned"
            );
        }
    }

    /// Symmetric in QW1, and a cleared bit in EACH quad-word is `Complete`
    /// (both took their one program).
    #[test]
    fn per_quad_word_not_per_bit() {
        let one_bit = B & !1;
        assert_eq!(
            classify_master_words(&words([B; 4], [one_bit, B, B, B])),
            MasterKeyState::Partial
        );
        assert_eq!(
            classify_master_words(&words([one_bit, B, B, B], [one_bit, B, B, B])),
            MasterKeyState::Complete,
            "a programmed bit in EACH quad-word means both took their one program"
        );
    }

    /// An all-zero region (every bit programmed) is `Complete`, not `Virgin` —
    /// guards against an inverted blank sentinel.
    #[test]
    fn all_zero_region_is_complete() {
        assert_eq!(
            classify_master_words(&[0u32; MASTER_KEY_WORDS]),
            MasterKeyState::Complete
        );
    }

    /// Exhaustive over the 2^8 blank/programmed patterns: the verdict is a
    /// function of the two per-quad-word disjunctions and nothing else.
    #[test]
    fn exhaustive_over_blank_programmed_patterns() {
        for mask in 0u32..256 {
            let mut w = [B; MASTER_KEY_WORDS];
            for (i, slot) in w.iter_mut().enumerate() {
                if mask & (1 << i) != 0 {
                    *slot = 0; // programmed
                }
            }
            let qw0 = mask & 0x0F != 0;
            let qw1 = mask & 0xF0 != 0;
            let expect = match (qw0, qw1) {
                (false, false) => MasterKeyState::Virgin,
                (true, true) => MasterKeyState::Complete,
                _ => MasterKeyState::Partial,
            };
            assert_eq!(classify_master_words(&w), expect, "mask {mask:#04x}");
        }
    }
}
