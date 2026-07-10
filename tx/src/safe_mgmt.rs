//! Safe-native owner / module / guard / fallback operation decoder.
//!
//! Pure-logic counterpart to the gated renderer at
//! `secure/src/tx/display/safe_mgmt.rs`. Lives here in `pqsigner-tx`
//! (next to the other clear-sign byte-layout decoders — `safe_tx`,
//! `multisend`, `cowswap_order`, `erc20`) because the firmware display
//! tree is `#[cfg(not(test))]`-gated in `secure/` (it depends on the
//! secure-only UI layer), whereas the classifier itself is pure data
//! and host-compilable / Kani-friendly. `secure/src/tx/eip712/safe/
//! mgmt_decode.rs` re-exports everything below verbatim, so every
//! caller (`safe_display`, the `safe_mgmt` renderer, `multi_send`'s
//! per-record classifier, `extra_tests`, the render pure-tests) keeps
//! working unchanged.
//!
//! Fires when the outer Safe-tx render sees
//! `canonical.to == canonical.safe_address` and `raw_data[0..4]`
//! matches one of the eight Safe v1.3.0+ singleton selectors below.
//! The cryptographic bind between `raw_data` and the on-chain
//! `safeTxHash` is established upstream in
//! `secure/src/tx/eip712/safe/verify.rs`; by the time this module sees
//! `raw_data` it is byte-equivalent to what the on-chain Safe will
//! execute once threshold approvals collect.
//!
//! ## Hardening rules (all enforced in `classify_safe_mgmt`)
//!
//! * **Strict length match** per selector. Truncated / over-long
//!   calldata never decodes; the caller treats `None` as "unknown
//!   Safe op" and renders the loud blind-sign branch.
//! * **Address-word canonicalness**: every address parameter must
//!   come encoded as `0..12` zero bytes + 20-byte address. Solidity's
//!   ABI accepts non-canonical encodings on input but rejects them
//!   here so the on-device display can never disagree with the
//!   on-chain interpretation.
//! * **Threshold-word canonicalness**: `uint256` words for `_threshold`
//!   must fit in `u16` (`bytes[0..30]` zero). Real Safes can't have
//!   more than 65535 owners; an out-of-range threshold is surfaced
//!   as [`ThresholdValue::Overflow`] so the user sees `>2^16`
//!   rather than a silently-truncated number.
//! * **No panics on any input** — every slice access is bounds-checked.
//!
//! ## Bounded verification (Kani)
//!
//! The `#[cfg(kani)] mod verification` block at the bottom proves, over
//! ALL symbolic calldata (length ≤ 100 — the longest canonical shape,
//! `removeOwner`/`swapOwner`):
//!
//!   * panic / arithmetic-overflow / slice-OOB freedom, and
//!   * **decode-soundness** (the WYSIWYS direction): `classify_safe_mgmt`
//!     returning `Some(op)` ⟹ the calldata length is *exactly* the
//!     canonical length for `op`'s selector, the selector bytes match,
//!     and every field of `op` is the verbatim copy of its canonical
//!     byte range — reconstructed from the ORIGINAL input bytes (never
//!     the decoder's cursor), with each address word canonical
//!     (high-12 zero) and each threshold faithful (`Fits(n)` ⟺ the
//!     high-30 bytes are zero and `n` is the low-2-byte BE value,
//!     `Overflow` ⟺ a high byte is set), and
//!   * **selector-gating** (a reverse direction): any calldata whose
//!     first four bytes are not one of the eight known selectors (which
//!     includes every `< 4`-byte input) is rejected with `None`.
//!
//! Bound stated honestly: forward soundness + selector-gating are
//! *exhaustive* over the symbolic input space (a fixed-layout decoder
//! with no `N`-proportional loop). Completeness (canonical ⟹ accept)
//! is a separate, lower-severity property — a false-reject is
//! refuse-to-clear-sign (loud blind-sign fallback), not a forgery — and
//! is NOT claimed here.

use sphincs_tz_shared::{
    SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD, SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD,
    SAFE_MGMT_SELECTOR_DISABLE_MODULE, SAFE_MGMT_SELECTOR_ENABLE_MODULE,
    SAFE_MGMT_SELECTOR_REMOVE_OWNER, SAFE_MGMT_SELECTOR_SET_FALLBACK_HANDLER,
    SAFE_MGMT_SELECTOR_SET_GUARD, SAFE_MGMT_SELECTOR_SWAP_OWNER,
};

/// Decoded `_threshold` value from a Safe `uint256` parameter.
///
/// `Fits(n)` carries the threshold for display; `Overflow` means the
/// supplied uint256 had bits set beyond the low 16 — the renderer
/// surfaces this as `! >2^16` rather than truncating.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ThresholdValue {
    Fits(u16),
    Overflow,
}

/// A Safe-native owner/module/guard/fallback operation decoded out of
/// the SafeTx's inner calldata.
#[derive(Copy, Clone, Debug)]
pub enum SafeMgmtOp {
    AddOwnerWithThreshold {
        new_owner: [u8; 20],
        new_threshold: ThresholdValue,
    },
    RemoveOwner {
        prev_owner: [u8; 20],
        owner: [u8; 20],
        new_threshold: ThresholdValue,
    },
    SwapOwner {
        prev_owner: [u8; 20],
        old_owner: [u8; 20],
        new_owner: [u8; 20],
    },
    ChangeThreshold {
        new_threshold: ThresholdValue,
    },
    EnableModule {
        module: [u8; 20],
    },
    DisableModule {
        prev_module: [u8; 20],
        module: [u8; 20],
    },
    /// `guard == [0u8; 20]` means "removing guard".
    SetGuard {
        guard: [u8; 20],
    },
    /// `handler == [0u8; 20]` means "removing fallback handler".
    SetFallbackHandler {
        handler: [u8; 20],
    },
}

fn decode_addr_word(word: &[u8; 32]) -> Option<[u8; 20]> {
    if word[0..12].iter().any(|&b| b != 0) {
        return None;
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&word[12..32]);
    Some(addr)
}

fn decode_threshold_word(word: &[u8; 32]) -> ThresholdValue {
    if word[0..30].iter().any(|&b| b != 0) {
        return ThresholdValue::Overflow;
    }
    ThresholdValue::Fits(u16::from_be_bytes([word[30], word[31]]))
}

fn word_at(raw: &[u8], off: usize) -> Option<&[u8; 32]> {
    raw.get(off..off + 32)?.try_into().ok()
}

/// Classify a Safe self-call payload.
///
/// `None` means "unknown / non-canonical Safe self-call"; the caller
/// should render the loud blind-sign branch with `"Unknown Safe op"`.
pub fn classify_safe_mgmt(raw_data: &[u8]) -> Option<SafeMgmtOp> {
    if raw_data.len() < 4 {
        return None;
    }
    let selector: [u8; 4] = raw_data[0..4].try_into().ok()?;
    let body = &raw_data[4..];

    match selector {
        s if s == SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD => {
            if raw_data.len() != 68 {
                return None;
            }
            let new_owner = decode_addr_word(word_at(body, 0)?)?;
            let new_threshold = decode_threshold_word(word_at(body, 32)?);
            Some(SafeMgmtOp::AddOwnerWithThreshold {
                new_owner,
                new_threshold,
            })
        }
        s if s == SAFE_MGMT_SELECTOR_REMOVE_OWNER => {
            if raw_data.len() != 100 {
                return None;
            }
            let prev_owner = decode_addr_word(word_at(body, 0)?)?;
            let owner = decode_addr_word(word_at(body, 32)?)?;
            let new_threshold = decode_threshold_word(word_at(body, 64)?);
            Some(SafeMgmtOp::RemoveOwner {
                prev_owner,
                owner,
                new_threshold,
            })
        }
        s if s == SAFE_MGMT_SELECTOR_SWAP_OWNER => {
            if raw_data.len() != 100 {
                return None;
            }
            let prev_owner = decode_addr_word(word_at(body, 0)?)?;
            let old_owner = decode_addr_word(word_at(body, 32)?)?;
            let new_owner = decode_addr_word(word_at(body, 64)?)?;
            Some(SafeMgmtOp::SwapOwner {
                prev_owner,
                old_owner,
                new_owner,
            })
        }
        s if s == SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD => {
            if raw_data.len() != 36 {
                return None;
            }
            let new_threshold = decode_threshold_word(word_at(body, 0)?);
            Some(SafeMgmtOp::ChangeThreshold { new_threshold })
        }
        s if s == SAFE_MGMT_SELECTOR_ENABLE_MODULE => {
            if raw_data.len() != 36 {
                return None;
            }
            let module = decode_addr_word(word_at(body, 0)?)?;
            Some(SafeMgmtOp::EnableModule { module })
        }
        s if s == SAFE_MGMT_SELECTOR_DISABLE_MODULE => {
            if raw_data.len() != 68 {
                return None;
            }
            let prev_module = decode_addr_word(word_at(body, 0)?)?;
            let module = decode_addr_word(word_at(body, 32)?)?;
            Some(SafeMgmtOp::DisableModule {
                prev_module,
                module,
            })
        }
        s if s == SAFE_MGMT_SELECTOR_SET_GUARD => {
            if raw_data.len() != 36 {
                return None;
            }
            let guard = decode_addr_word(word_at(body, 0)?)?;
            Some(SafeMgmtOp::SetGuard { guard })
        }
        s if s == SAFE_MGMT_SELECTOR_SET_FALLBACK_HANDLER => {
            if raw_data.len() != 36 {
                return None;
            }
            let handler = decode_addr_word(word_at(body, 0)?)?;
            Some(SafeMgmtOp::SetFallbackHandler { handler })
        }
        _ => None,
    }
}

/// Number of confirmation pages required to render a [`SafeMgmtOp`].
/// Top end is 3 pages (removeOwner / swapOwner).
#[must_use]
pub fn page_count(op: &SafeMgmtOp) -> usize {
    match op {
        SafeMgmtOp::AddOwnerWithThreshold { .. } => 2,
        SafeMgmtOp::RemoveOwner { .. } => 3,
        SafeMgmtOp::SwapOwner { .. } => 3,
        SafeMgmtOp::ChangeThreshold { .. } => 1,
        SafeMgmtOp::EnableModule { .. } => 2,
        SafeMgmtOp::DisableModule { .. } => 2,
        SafeMgmtOp::SetGuard { .. } => 2,
        SafeMgmtOp::SetFallbackHandler { .. } => 2,
    }
}

// ---------------------------------------------------------------------------
// Unit tests (host-runnable)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::vec::Vec;

    fn hex(addr: [u8; 20]) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..32].copy_from_slice(&addr);
        w
    }

    fn u256_be(n: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..32].copy_from_slice(&n.to_be_bytes());
        w
    }

    fn build(selector: [u8; 4], words: &[[u8; 32]]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + words.len() * 32);
        v.extend_from_slice(&selector);
        for w in words {
            v.extend_from_slice(w);
        }
        v
    }

    const A: [u8; 20] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xde,
        0xad, 0xbe, 0xef, 0x12, 0x34,
    ];
    const B: [u8; 20] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x01, 0x02, 0x03, 0x04,
    ];
    const C: [u8; 20] = [
        0xfe, 0xed, 0xfa, 0xce, 0xba, 0xbe, 0xca, 0xfe, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42,
    ];

    const ZERO_ADDR: [u8; 20] = [0u8; 20];

    #[test]
    fn add_owner_with_threshold_positive() {
        let data = build(
            SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD,
            &[hex(A), u256_be(3)],
        );
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::AddOwnerWithThreshold {
                new_owner,
                new_threshold,
            } => {
                assert_eq!(new_owner, A);
                assert_eq!(new_threshold, ThresholdValue::Fits(3));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn add_owner_truncated_returns_none() {
        let mut data = build(
            SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD,
            &[hex(A), u256_be(3)],
        );
        data.pop();
        assert!(classify_safe_mgmt(&data).is_none());
    }

    #[test]
    fn add_owner_over_long_returns_none() {
        let mut data = build(
            SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD,
            &[hex(A), u256_be(3)],
        );
        data.push(0x00);
        assert!(classify_safe_mgmt(&data).is_none());
    }

    #[test]
    fn add_owner_noncanonical_address_returns_none() {
        let mut addr_word = hex(A);
        addr_word[5] = 0xff;
        let data = build(
            SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD,
            &[addr_word, u256_be(3)],
        );
        assert!(classify_safe_mgmt(&data).is_none());
    }

    #[test]
    fn add_owner_threshold_overflow_surfaces() {
        let mut t_word = u256_be(0);
        t_word[29] = 0x01;
        let data = build(SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD, &[hex(A), t_word]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::AddOwnerWithThreshold { new_threshold, .. } => {
                assert_eq!(new_threshold, ThresholdValue::Overflow);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn add_owner_threshold_max_u16_fits() {
        let data = build(
            SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD,
            &[hex(A), u256_be(65535)],
        );
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::AddOwnerWithThreshold { new_threshold, .. } => {
                assert_eq!(new_threshold, ThresholdValue::Fits(65535));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn remove_owner_positive_with_sentinel_prev() {
        let mut sentinel = [0u8; 32];
        sentinel[31] = 0x01;
        let data = build(
            SAFE_MGMT_SELECTOR_REMOVE_OWNER,
            &[sentinel, hex(A), u256_be(2)],
        );
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::RemoveOwner {
                prev_owner,
                owner,
                new_threshold,
            } => {
                let mut expected_prev = [0u8; 20];
                expected_prev[19] = 0x01;
                assert_eq!(prev_owner, expected_prev);
                assert_eq!(owner, A);
                assert_eq!(new_threshold, ThresholdValue::Fits(2));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn swap_owner_positive() {
        let data = build(SAFE_MGMT_SELECTOR_SWAP_OWNER, &[hex(A), hex(B), hex(C)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::SwapOwner {
                prev_owner,
                old_owner,
                new_owner,
            } => {
                assert_eq!(prev_owner, A);
                assert_eq!(old_owner, B);
                assert_eq!(new_owner, C);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn change_threshold_one_is_multisig_off_signal() {
        let data = build(SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD, &[u256_be(1)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::ChangeThreshold {
                new_threshold: ThresholdValue::Fits(1),
            } => {}
            _ => panic!("expected ChangeThreshold(1)"),
        }
    }

    #[test]
    fn change_threshold_zero_decodes_faithfully() {
        let data = build(SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD, &[u256_be(0)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::ChangeThreshold {
                new_threshold: ThresholdValue::Fits(0),
            } => {}
            _ => panic!("expected ChangeThreshold(0)"),
        }
    }

    #[test]
    fn enable_module_positive() {
        let data = build(SAFE_MGMT_SELECTOR_ENABLE_MODULE, &[hex(A)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::EnableModule { module } => assert_eq!(module, A),
            _ => panic!(),
        }
    }

    #[test]
    fn disable_module_positive() {
        let data = build(SAFE_MGMT_SELECTOR_DISABLE_MODULE, &[hex(B), hex(A)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::DisableModule {
                prev_module,
                module,
            } => {
                assert_eq!(prev_module, B);
                assert_eq!(module, A);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn set_guard_zero_is_removal() {
        let data = build(SAFE_MGMT_SELECTOR_SET_GUARD, &[u256_be(0)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::SetGuard { guard } => assert_eq!(guard, ZERO_ADDR),
            _ => panic!(),
        }
    }

    #[test]
    fn set_guard_nonzero_positive() {
        let data = build(SAFE_MGMT_SELECTOR_SET_GUARD, &[hex(C)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::SetGuard { guard } => assert_eq!(guard, C),
            _ => panic!(),
        }
    }

    #[test]
    fn set_fallback_handler_zero_is_removal() {
        let data = build(SAFE_MGMT_SELECTOR_SET_FALLBACK_HANDLER, &[u256_be(0)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::SetFallbackHandler { handler } => assert_eq!(handler, ZERO_ADDR),
            _ => panic!(),
        }
    }

    #[test]
    fn unknown_selector_returns_none() {
        let data = build([0xde, 0xad, 0xbe, 0xef], &[u256_be(0)]);
        assert!(classify_safe_mgmt(&data).is_none());
    }

    #[test]
    fn short_data_returns_none() {
        let data: [u8; 3] = [0x69, 0x4e, 0x80];
        assert!(classify_safe_mgmt(&data).is_none());
    }

    #[test]
    fn empty_data_returns_none() {
        assert!(classify_safe_mgmt(&[]).is_none());
    }

    #[test]
    fn page_counts_within_envelope() {
        // Caller adds SAFE_HEADER_PAGES (3) + page_count + 1 (confirm).
        // Max should land at 3 + 3 + 1 = 7, well inside MAX_PAGES=31.
        for op in [
            SafeMgmtOp::ChangeThreshold {
                new_threshold: ThresholdValue::Fits(2),
            },
            SafeMgmtOp::AddOwnerWithThreshold {
                new_owner: A,
                new_threshold: ThresholdValue::Fits(2),
            },
            SafeMgmtOp::RemoveOwner {
                prev_owner: B,
                owner: A,
                new_threshold: ThresholdValue::Fits(2),
            },
            SafeMgmtOp::SwapOwner {
                prev_owner: A,
                old_owner: B,
                new_owner: C,
            },
            SafeMgmtOp::EnableModule { module: A },
            SafeMgmtOp::DisableModule {
                prev_module: B,
                module: A,
            },
            SafeMgmtOp::SetGuard { guard: C },
            SafeMgmtOp::SetFallbackHandler { handler: ZERO_ADDR },
        ] {
            assert!(page_count(&op) <= 3);
        }
    }
}

// ---------------------------------------------------------------------------
// Bounded verification (Kani)
// ---------------------------------------------------------------------------

#[cfg(kani)]
mod verification {
    use super::*;

    /// Canonical length of each selector's calldata (selector + words).
    const LEN_ADD_OWNER: usize = 68; // selector + 2 words
    const LEN_REMOVE_OWNER: usize = 100; // selector + 3 words
    const LEN_SWAP_OWNER: usize = 100; // selector + 3 words
    const LEN_CHANGE_THRESHOLD: usize = 36; // selector + 1 word
    const LEN_ENABLE_MODULE: usize = 36;
    const LEN_DISABLE_MODULE: usize = 68;
    const LEN_SET_GUARD: usize = 36;
    const LEN_SET_FALLBACK: usize = 36;

    /// Longest canonical calldata (removeOwner / swapOwner). Sizes the
    /// symbolic input array so every shape is reachable.
    const N: usize = 100;

    /// In-Kani reachability anchor: a concrete canonical frame for EVERY
    /// one of the eight selectors is accepted by the decoder. Used by the
    /// symbolic soundness harnesses below so they cannot pass vacuously —
    /// a decoder that rejected any of these (e.g. a dead match arm) fails
    /// HERE, not by silently slipping through that variant's `Some ⟹ …`
    /// field-soundness postconditions. A zeroed body is canonical for
    /// every shape: a zero address word is `high-12 zero + [0;20]` (valid),
    /// and a zero threshold word is `Fits(0)`, so all eight accept-paths
    /// are anchored, not just one.
    fn anchor_witness() {
        for (sel, n) in [
            (SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD, LEN_ADD_OWNER),
            (SAFE_MGMT_SELECTOR_REMOVE_OWNER, LEN_REMOVE_OWNER),
            (SAFE_MGMT_SELECTOR_SWAP_OWNER, LEN_SWAP_OWNER),
            (SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD, LEN_CHANGE_THRESHOLD),
            (SAFE_MGMT_SELECTOR_ENABLE_MODULE, LEN_ENABLE_MODULE),
            (SAFE_MGMT_SELECTOR_DISABLE_MODULE, LEN_DISABLE_MODULE),
            (SAFE_MGMT_SELECTOR_SET_GUARD, LEN_SET_GUARD),
            (SAFE_MGMT_SELECTOR_SET_FALLBACK_HANDLER, LEN_SET_FALLBACK),
        ] {
            let mut canon = [0u8; N];
            canon[0..4].copy_from_slice(&sel);
            assert!(classify_safe_mgmt(&canon[..n]).is_some());
        }
    }

    /// Reconstruct + assert one address field is the verbatim canonical
    /// decode of `word` (`= data[off..off+32]`): the high 12 bytes are
    /// zero AND the returned address is `word[12..32]`. Independent of
    /// the decoder's internals — reads the ORIGINAL input word.
    fn assert_addr_word_sound(word: &[u8], got: [u8; 20]) {
        for i in 0..12 {
            assert_eq!(word[i], 0);
        }
        let mut expect = [0u8; 20];
        expect.copy_from_slice(&word[12..32]);
        assert_eq!(got, expect);
    }

    /// Reconstruct + assert one threshold field is the faithful decode of
    /// `word`: `Fits(n)` ⟺ the high 30 bytes are zero and `n` is the
    /// low-2-byte BE value; `Overflow` ⟺ some high byte is set. Reads the
    /// ORIGINAL input word, never the decoder's cursor.
    fn assert_threshold_word_sound(word: &[u8], got: ThresholdValue) {
        let high_zero = word[0..30].iter().all(|&b| b == 0);
        match got {
            ThresholdValue::Fits(n) => {
                assert!(high_zero);
                assert_eq!(n, u16::from_be_bytes([word[30], word[31]]));
            }
            ThresholdValue::Overflow => {
                assert!(!high_zero);
            }
        }
    }

    /// Panic / arithmetic-overflow / slice-OOB freedom over ALL symbolic
    /// calldata of length ≤ N. The decoder must never panic regardless of
    /// what the (untrusted) companion supplies — any length, any selector,
    /// any content. (Kani runs these default checks on every harness; a
    /// dedicated one documents the guarantee on the parse surface.)
    #[kani::proof]
    #[kani::unwind(33)]
    fn classify_safe_mgmt_panic_free() {
        let data: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let _ = classify_safe_mgmt(&data[..len]);
    }

    /// PRIMARY SOUNDNESS — the WYSIWYS direction, over ALL symbolic
    /// calldata (any selector, any length ≤ N, any bytes).
    ///
    /// `classify_safe_mgmt(s) == Some(op)` ⟹
    ///   * `s.len()` is EXACTLY the canonical length for `op`'s selector,
    ///   * `s[0..4]` is that selector, and
    ///   * every field of `op` is the verbatim canonical decode of its
    ///     fixed in-bounds byte range, reconstructed from the ORIGINAL
    ///     input (each address word canonical / high-12 zero, each
    ///     threshold faithful per `assert_threshold_word_sound`).
    ///
    /// Reconstruction reads the fixed `data` array at constant offsets
    /// (all `< canonical_len ≤ N`), which — once `len` is pinned to the
    /// canonical length — are byte-identical to what the decoder read, so
    /// this is a genuine soundness check and NOT a self-recheck of the
    /// decoder's own cursor.
    ///
    /// Bound: exhaustive over the symbolic input space (fixed-layout
    /// decoder, no `N`-proportional loop; `N = 100` is the longest
    /// canonical shape so every selector is reachable).
    #[kani::proof]
    #[kani::unwind(33)]
    fn classify_safe_mgmt_soundness() {
        anchor_witness();

        let data: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let s = &data[..len];

        if let Some(op) = classify_safe_mgmt(s) {
            match op {
                SafeMgmtOp::AddOwnerWithThreshold {
                    new_owner,
                    new_threshold,
                } => {
                    assert_eq!(len, LEN_ADD_OWNER);
                    assert_eq!(&data[0..4], &SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD);
                    assert_addr_word_sound(&data[4..36], new_owner);
                    assert_threshold_word_sound(&data[36..68], new_threshold);
                }
                SafeMgmtOp::RemoveOwner {
                    prev_owner,
                    owner,
                    new_threshold,
                } => {
                    assert_eq!(len, LEN_REMOVE_OWNER);
                    assert_eq!(&data[0..4], &SAFE_MGMT_SELECTOR_REMOVE_OWNER);
                    assert_addr_word_sound(&data[4..36], prev_owner);
                    assert_addr_word_sound(&data[36..68], owner);
                    assert_threshold_word_sound(&data[68..100], new_threshold);
                }
                SafeMgmtOp::SwapOwner {
                    prev_owner,
                    old_owner,
                    new_owner,
                } => {
                    assert_eq!(len, LEN_SWAP_OWNER);
                    assert_eq!(&data[0..4], &SAFE_MGMT_SELECTOR_SWAP_OWNER);
                    assert_addr_word_sound(&data[4..36], prev_owner);
                    assert_addr_word_sound(&data[36..68], old_owner);
                    assert_addr_word_sound(&data[68..100], new_owner);
                }
                SafeMgmtOp::ChangeThreshold { new_threshold } => {
                    assert_eq!(len, LEN_CHANGE_THRESHOLD);
                    assert_eq!(&data[0..4], &SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD);
                    assert_threshold_word_sound(&data[4..36], new_threshold);
                }
                SafeMgmtOp::EnableModule { module } => {
                    assert_eq!(len, LEN_ENABLE_MODULE);
                    assert_eq!(&data[0..4], &SAFE_MGMT_SELECTOR_ENABLE_MODULE);
                    assert_addr_word_sound(&data[4..36], module);
                }
                SafeMgmtOp::DisableModule {
                    prev_module,
                    module,
                } => {
                    assert_eq!(len, LEN_DISABLE_MODULE);
                    assert_eq!(&data[0..4], &SAFE_MGMT_SELECTOR_DISABLE_MODULE);
                    assert_addr_word_sound(&data[4..36], prev_module);
                    assert_addr_word_sound(&data[36..68], module);
                }
                SafeMgmtOp::SetGuard { guard } => {
                    assert_eq!(len, LEN_SET_GUARD);
                    assert_eq!(&data[0..4], &SAFE_MGMT_SELECTOR_SET_GUARD);
                    assert_addr_word_sound(&data[4..36], guard);
                }
                SafeMgmtOp::SetFallbackHandler { handler } => {
                    assert_eq!(len, LEN_SET_FALLBACK);
                    assert_eq!(&data[0..4], &SAFE_MGMT_SELECTOR_SET_FALLBACK_HANDLER);
                    assert_addr_word_sound(&data[4..36], handler);
                }
            }
        }
    }

    /// SELECTOR-GATING (a reverse direction), over ALL symbolic calldata:
    /// any input whose first four bytes are NOT one of the eight known
    /// selectors — which INCLUDES every `< 4`-byte input — is rejected
    /// with `None`. So an unrecognized / short calldata can never be
    /// mis-rendered as a Safe management op. Combined with the forward
    /// soundness above (which pins `len` to the exact canonical length
    /// per selector), a wrong-length input under a known selector is also
    /// rejected (the selector→variant map is exclusive).
    #[kani::proof]
    #[kani::unwind(33)]
    fn classify_safe_mgmt_rejects_unknown_selector() {
        anchor_witness();

        let data: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let s = &data[..len];

        let known = len >= 4 && {
            let sel = [data[0], data[1], data[2], data[3]];
            sel == SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD
                || sel == SAFE_MGMT_SELECTOR_REMOVE_OWNER
                || sel == SAFE_MGMT_SELECTOR_SWAP_OWNER
                || sel == SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD
                || sel == SAFE_MGMT_SELECTOR_ENABLE_MODULE
                || sel == SAFE_MGMT_SELECTOR_DISABLE_MODULE
                || sel == SAFE_MGMT_SELECTOR_SET_GUARD
                || sel == SAFE_MGMT_SELECTOR_SET_FALLBACK_HANDLER
        };
        if !known {
            assert!(classify_safe_mgmt(s).is_none());
        }
    }

    /// NON-VACUITY — positive control. A concrete canonical
    /// `addOwnerWithThreshold(owner, 3)` is ACCEPTED and decodes to
    /// exactly the expected fields (distinctive edge sentinels in the
    /// address word catch a shared-offset bug between harness and
    /// decoder). Without this, the soundness proof could pass vacuously.
    #[kani::proof]
    #[kani::unwind(33)]
    fn classify_safe_mgmt_accepts_canonical_add_owner() {
        let mut buf = [0u8; LEN_ADD_OWNER];
        buf[0..4].copy_from_slice(&SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD);
        // address word at [4..36]: high 12 zero, then 20-byte address with
        // edge sentinels at [16] (first addr byte) and [35] (last).
        buf[16] = 0xaa;
        buf[35] = 0xbb;
        // threshold word at [36..68]: low byte == 3.
        buf[67] = 3;
        match classify_safe_mgmt(&buf) {
            Some(SafeMgmtOp::AddOwnerWithThreshold {
                new_owner,
                new_threshold,
            }) => {
                assert_eq!(new_owner[0], 0xaa);
                assert_eq!(new_owner[19], 0xbb);
                assert_eq!(new_threshold, ThresholdValue::Fits(3));
            }
            _ => panic!("a canonical addOwnerWithThreshold must decode"),
        }
    }

    /// NON-VACUITY — on-point negative control: a non-canonical address
    /// word (a byte set in the high-12 padding) under an otherwise
    /// well-formed `enableModule` frame must be REFUSED. This is exactly
    /// the "on-device render disagrees with on-chain ABI" threat the
    /// address-canonicalness rule forecloses.
    #[kani::proof]
    #[kani::unwind(33)]
    fn classify_safe_mgmt_rejects_noncanonical_address() {
        let mut buf = [0u8; LEN_ENABLE_MODULE];
        buf[0..4].copy_from_slice(&SAFE_MGMT_SELECTOR_ENABLE_MODULE);
        buf[10] = 0x01; // high-12 padding byte set → non-canonical address
        buf[35] = 0xcc; // some address content
        assert!(classify_safe_mgmt(&buf).is_none());
    }

    /// NON-VACUITY — on-point negative control: a known selector
    /// (`changeThreshold`) with the WRONG length (one byte short of the
    /// canonical 36) must be REFUSED. Anchors the strict-length rule the
    /// forward soundness `assert_eq!(len, …)` encodes.
    #[kani::proof]
    #[kani::unwind(33)]
    fn classify_safe_mgmt_rejects_wrong_length() {
        let mut buf = [0u8; LEN_CHANGE_THRESHOLD - 1];
        buf[0..4].copy_from_slice(&SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD);
        assert!(classify_safe_mgmt(&buf).is_none());
    }

    /// NON-VACUITY — threshold boundary control: a `changeThreshold`
    /// whose uint256 has a bit set above the low 16 surfaces
    /// `Overflow` (rendered ">2^16"), while `u16::MAX` still `Fits`. This
    /// is the faithful-not-truncated guarantee for the threshold field.
    #[kani::proof]
    #[kani::unwind(33)]
    fn classify_safe_mgmt_threshold_boundary() {
        // Overflow: byte at [29] (the 30th high byte) set.
        let mut over = [0u8; LEN_CHANGE_THRESHOLD];
        over[0..4].copy_from_slice(&SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD);
        over[4 + 29] = 0x01;
        match classify_safe_mgmt(&over) {
            Some(SafeMgmtOp::ChangeThreshold { new_threshold }) => {
                assert_eq!(new_threshold, ThresholdValue::Overflow);
            }
            _ => panic!("threshold with a high bit set must decode as Overflow"),
        }
        // Fits: u16::MAX in the low two bytes, nothing above.
        let mut max = [0u8; LEN_CHANGE_THRESHOLD];
        max[0..4].copy_from_slice(&SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD);
        max[4 + 30] = 0xff;
        max[4 + 31] = 0xff;
        match classify_safe_mgmt(&max) {
            Some(SafeMgmtOp::ChangeThreshold { new_threshold }) => {
                assert_eq!(new_threshold, ThresholdValue::Fits(u16::MAX));
            }
            _ => panic!("u16::MAX threshold must decode as Fits"),
        }
    }
}
