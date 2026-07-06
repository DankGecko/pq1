//! Pure amount-DECISION layer for the amount-shaped formatters
//! (`amount` / `tokenAmount` / `unit`) — M4 of the formatter-∀ track.
//!
//! ## Why a separate layer
//!
//! The M3 Tier-P0 round (b04d6398) proved the division-free formatter
//! properties but had to HONESTLY DROP the token-amount gate ∀s: CBMC
//! unwinds BOTH branches of a conditional before `kani::assume` prunes,
//! so any harness whose reachable code contains the `format_decimal`
//! paint path (the documented div10 bit-blast swamp) runs out of memory
//! even on concrete inputs. The fix is architectural, not a bigger box:
//! each amount formatter's DECISION — which arm paints, with which
//! message / decimals / ticker, and whether the token-identity page is
//! emitted — is a pure selection over bytes (no division, no
//! formatting) factored out of the PAINT half. Kani closes the decision
//! ∀ here without ever seeing `format_decimal`; the paint halves stay
//! bound byte-exactly by the golden-grid host tests and covered by the
//! Lean `format_decimal` track (div10 / extract_digits ∀ already
//! kernel-proven).
//!
//! ## Behavior-identical contract
//!
//! These functions compute EXACTLY what the pre-M4 in-line ladders in
//! [`super::formatters`] computed — same arms, same precedence, same
//! defaults, same reject paths. Any change here is a display-semantics
//! change and must re-run the golden-grid gates
//! (`cargo test -p pqsigner-erc7730 --release` +
//! `cargo test -p sphincs-tz-secure --tests --release`).

use pqsigner_tx::erc20::bundle::Erc20Metadata;

use super::super::primitives::native_ticker;
use crate::display::DISPLAY_COLS;
use crate::render::params::ParamSet;

/// Default threshold wording when the descriptor supplies no (valid)
/// `message` param (spec: "message to display above threshold, defaults
/// to Unlimited" — review 3.6).
pub const DEFAULT_THRESHOLD_MESSAGE: &[u8] = b"unlimited";

/// Which row-shape `render_token_amount`'s paint half draws. Selected by
/// [`token_amount_decision`].
#[derive(Debug, PartialEq, Eq)]
pub enum TokenAmountArm<'a> {
    /// `value >= threshold` and the token is bound (native sentinel or
    /// Merkle-verified ERC-20): one loud `"<message> <ticker>"` row.
    Unlimited {
        message: &'a [u8],
        ticker: &'a [u8],
    },
    /// `value >= threshold` but the token could NOT be bound: the loud
    /// message row + `"(unverified)"` (review 4.5 — an unbound 2^256-1
    /// must not fall through to `!AMOUNT OVERFLOW`, exactly when trust
    /// is lowest; the identity page below keeps the missing token
    /// identity loud).
    UnlimitedUnverified { message: &'a [u8] },
    /// Below threshold (or no threshold), token bound: scaled amount
    /// with the VERIFIED decimals + ticker.
    Bound { decimals: u32, ticker: &'a [u8] },
    /// Below threshold (or no threshold), token NOT bound: RAW integer,
    /// no scaling, loud `! raw, dec=?` footer (audit M-4 — never present
    /// a scaled decimal with an assumed scale; a 6-decimal token would
    /// render 10^12× off while *looking* authoritative).
    UnverifiedRaw,
}

/// The complete decision for one `tokenAmount` field: the value-row arm
/// plus whether the token-identity page must ALSO be emitted.
#[derive(Debug, PartialEq, Eq)]
pub struct TokenAmountDecision<'a> {
    pub arm: TokenAmountArm<'a>,
    /// `Some(addr)` → the paint half MUST append the `"Token
    /// (UNVERIFIED)"` page showing `addr` (audit 2026-06-25 MEDIUM-1:
    /// with no Merkle-verified metadata the token *identity* is still a
    /// signed operand — a descriptor that covers the token only via a
    /// `tokenPath` has no address field of its own, so a companion that
    /// withholds the optional ERC-20 metadata trailer must not have the
    /// user approve a transfer/withdraw/swap of an UNNAMED token).
    /// `Some` exactly when the token address resolved but could not be
    /// bound (native counts as bound); `None` when bound (the ticker
    /// already names the token) or when no address resolved at all
    /// (nothing to bind — the raw arm's `! raw, dec=?` footer stays
    /// loud, and the page-budget gate fails closed on overflow).
    pub identity_page: Option<[u8; 20]>,
}

/// Decide which `tokenAmount` arm paints. Pure — no division, no
/// formatting, no `Pages`; ∀-proven by the `kani_harness` module below.
///
/// * `value` — the resolved 32-byte BE amount word (the signed operand).
/// * `token_addr` — the token contract resolved by
///   `formatters::resolve_token_address` (`params.tokenPath` wins, then
///   the `params.token` literal); `None` when no address could be
///   resolved.
/// * `erc20` — the companion-supplied, Merkle-verified metadata trailer
///   (untrusted until its `contract` matches the resolved address).
///
/// Ladder (order is load-bearing):
///
/// 1. **Native-currency sentinel** (`nativeCurrencyAddress`): a resolved
///    token equal to the descriptor's sentinel (`0xEeee…`/`0x0`) IS the
///    chain native currency → 18 decimals + `native_ticker(chain_id)`.
///    Takes precedence over the `erc20` bundle: the sentinel is not a
///    real ERC-20 contract, and this is a Merkle-pinned descriptor
///    decision (baked into the IR), so it needs no companion metadata
///    and emits no identity page.
/// 2. **ERC-20 binding**: the `erc20` bundle counts only when the
///    addresses agree. `None` = the token could NOT be bound to a
///    Merkle-verified metadata entry — its decimals are unknown.
/// 3. **Threshold / approve-all sentinel, HOISTED ABOVE the bound match**
///    (review 4.5): when the descriptor supplies a `threshold` and the
///    value is ≥ it, this is an "unlimited" approval — the single most
///    dangerous action — for BOUND and UNBOUND tokens alike. BE byte
///    arrays compare lexicographically == numeric on a full-width u256,
///    so a direct `>=` over the raw bytes is correct.
/// 4. **Message param** (review 3.6): the descriptor's `message`
///    overrides the default "unlimited" wording; validate printable
///    ASCII + row-fitting (anti-homoglyph on the trusted display) before
///    trusting it, else the fixed fallback.
pub fn token_amount_decision<'a>(
    value: &[u8; 32],
    token_addr: Option<[u8; 20]>,
    erc20: Option<&Erc20Metadata<'a>>,
    chain_id: u64,
    params: &ParamSet<'a>,
) -> TokenAmountDecision<'a> {
    let is_native = matches!(
        (token_addr, params.native_currency),
        (Some(addr), Some(native)) if &addr == native
    );

    let bound: Option<(u32, &'a [u8])> = if is_native {
        Some((18, native_ticker(chain_id)))
    } else {
        match (token_addr, erc20) {
            (Some(addr), Some(meta)) if addr == meta.contract => {
                Some((u32::from(meta.decimals), meta.symbol))
            }
            _ => None,
        }
    };

    let is_unlimited = params.threshold.is_some_and(|t| *value >= *t);

    let arm = if is_unlimited {
        let message: &'a [u8] = params
            .message
            .filter(|m| {
                !m.is_empty()
                    && m.len() <= DISPLAY_COLS
                    && m.iter().all(|&b| (0x20..0x7f).contains(&b))
            })
            .unwrap_or(DEFAULT_THRESHOLD_MESSAGE);
        match bound {
            Some((_, ticker)) => TokenAmountArm::Unlimited { message, ticker },
            None => TokenAmountArm::UnlimitedUnverified { message },
        }
    } else {
        match bound {
            Some((decimals, ticker)) => TokenAmountArm::Bound { decimals, ticker },
            None => TokenAmountArm::UnverifiedRaw,
        }
    };

    // MEDIUM-1: the identity page fires exactly when a RESOLVED token
    // could not be bound — in the unlimited AND the raw arms alike.
    let identity_page = if bound.is_none() { token_addr } else { None };

    TokenAmountDecision { arm, identity_page }
}

/// Decision half of a scalar `amount` / `unit` field: which decimals to
/// scale by and which unit string to append.
#[derive(Debug, PartialEq, Eq)]
pub struct ScalarAmountDecision<'a> {
    pub decimals: u32,
    pub unit: &'a [u8],
}

/// `amount` formatter decision: the chain's NATIVE currency — decimals
/// default 18; the ticker defaults per chain (POL/BNB/AVAX/… — review
/// 3.5) instead of always "ETH"; a descriptor-supplied `base` overrides.
pub fn amount_decision<'a>(chain_id: u64, params: &ParamSet<'a>) -> ScalarAmountDecision<'a> {
    ScalarAmountDecision {
        decimals: u32::from(params.decimals.unwrap_or(18)),
        unit: params.base.unwrap_or_else(|| native_ticker(chain_id)),
    }
}

/// `unit` formatter decision: decimals default 0 (a bare count), unit
/// string defaults empty. The 18-vs-0 default asymmetry with
/// [`amount_decision`] is load-bearing: swapping the defaults mis-scales
/// a bare-count field (or a native amount) by 10^18.
pub fn unit_decision<'a>(params: &ParamSet<'a>) -> ScalarAmountDecision<'a> {
    ScalarAmountDecision {
        decimals: u32::from(params.decimals.unwrap_or(0)),
        unit: params.base.unwrap_or(b""),
    }
}

#[cfg(test)]
mod tests {
    //! Host witnesses for the decision arms (the byte-exact PAINT
    //! behavior stays bound by the golden-grid render tests over
    //! `render_token_amount` / `render_amount` / `render_unit`).
    use super::*;

    const SENTINEL: [u8; 20] = [0xEE; 20];

    fn usdc() -> Erc20Metadata<'static> {
        Erc20Metadata {
            chain_id: 1,
            contract: [0xAA; 20],
            decimals: 6,
            name: b"USD Coin",
            symbol: b"USDC",
        }
    }

    #[test]
    fn unlimited_bound_at_threshold_boundary() {
        let mut t = [0u8; 32];
        t[31] = 42;
        let mut params = ParamSet::default();
        params.threshold = Some(&t);
        params.native_currency = Some(&SENTINEL);
        let d = token_amount_decision(&t, Some(SENTINEL), None, 1, &params);
        assert_eq!(
            d,
            TokenAmountDecision {
                arm: TokenAmountArm::Unlimited { message: b"unlimited", ticker: b"ETH" },
                identity_page: None,
            }
        );
    }

    #[test]
    fn below_threshold_native_stays_bound_amount() {
        let mut t = [0u8; 32];
        t[31] = 42;
        let mut v = [0u8; 32];
        v[31] = 41;
        let mut params = ParamSet::default();
        params.threshold = Some(&t);
        params.native_currency = Some(&SENTINEL);
        let d = token_amount_decision(&v, Some(SENTINEL), None, 1, &params);
        assert_eq!(d.arm, TokenAmountArm::Bound { decimals: 18, ticker: b"ETH" });
        assert_eq!(d.identity_page, None);
    }

    #[test]
    fn erc20_hit_binds_that_metadata() {
        let meta = usdc();
        let v = [0u8; 32];
        let params = ParamSet::default();
        let d = token_amount_decision(&v, Some([0xAA; 20]), Some(&meta), 1, &params);
        assert_eq!(d.arm, TokenAmountArm::Bound { decimals: 6, ticker: b"USDC" });
        assert_eq!(d.identity_page, None);
    }

    #[test]
    fn erc20_miss_is_raw_with_identity_page() {
        let meta = usdc();
        let v = [0u8; 32];
        let params = ParamSet::default();
        let d = token_amount_decision(&v, Some([0xBB; 20]), Some(&meta), 1, &params);
        assert_eq!(d.arm, TokenAmountArm::UnverifiedRaw);
        assert_eq!(d.identity_page, Some([0xBB; 20]));
    }

    #[test]
    fn unlimited_unverified_keeps_identity_page() {
        let t = [0u8; 32]; // any value >= 0 is unlimited
        let mut params = ParamSet::default();
        params.threshold = Some(&t);
        let d = token_amount_decision(&t, Some([0xBB; 20]), None, 1, &params);
        assert_eq!(d.arm, TokenAmountArm::UnlimitedUnverified { message: b"unlimited" });
        assert_eq!(d.identity_page, Some([0xBB; 20]));
    }

    #[test]
    fn invalid_message_falls_back_to_default() {
        let t = [0u8; 32];
        let mut params = ParamSet::default();
        params.threshold = Some(&t);
        params.message = Some(b"bad\x01msg"); // non-printable -> rejected
        let d = token_amount_decision(&t, None, None, 1, &params);
        assert_eq!(d.arm, TokenAmountArm::UnlimitedUnverified { message: b"unlimited" });
    }

    #[test]
    fn valid_message_overrides_default() {
        let t = [0u8; 32];
        let mut params = ParamSet::default();
        params.threshold = Some(&t);
        params.message = Some(b"All your USDC");
        let d = token_amount_decision(&t, None, None, 1, &params);
        assert_eq!(
            d.arm,
            TokenAmountArm::UnlimitedUnverified { message: b"All your USDC" }
        );
    }

    #[test]
    fn scalar_defaults_asymmetry() {
        let params = ParamSet::default();
        let a = amount_decision(137, &params);
        assert_eq!((a.decimals, a.unit), (18, &b"POL"[..]));
        let u = unit_decision(&params);
        assert_eq!((u.decimals, u.unit), (0, &b""[..]));
    }
}

#[cfg(kani)]
mod kani_harness {
    //! The token-amount gate ∀s M3 could not afford (formatter-∀ track
    //! M4). Everything under proof here is division-free by
    //! construction: `token_amount_decision` never formats, so CBMC
    //! never unwinds `format_decimal`. Style follows
    //! `render/resolve.rs`: independent oracles (an explicit MSB-first
    //! numeric scan, re-stated validity loops), concrete non-vacuity
    //! witnesses, and `scripts/kani_mutations.json` pins on the
    //! load-bearing behaviours.

    use super::*;

    /// Independent numeric big-endian `a >= b` oracle — an explicit
    /// most-significant-byte-first scan, NOT the code's array
    /// `PartialOrd`.
    fn be_ge(a: &[u8; 32], b: &[u8; 32]) -> bool {
        let mut i = 0usize;
        while i < 32 {
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    fn is_unlimited_arm(arm: &TokenAmountArm<'_>) -> bool {
        matches!(
            arm,
            TokenAmountArm::Unlimited { .. } | TokenAmountArm::UnlimitedUnverified { .. }
        )
    }

    /// (a) THE ∀ M3 HONESTLY DROPPED — doubly-symbolic threshold gate:
    /// ∀ value bytes, ∀ threshold bytes, ∀ token-binding shape (address
    /// present/absent, erc20 hit/miss with symbolic contract/decimals/
    /// symbol, native sentinel present/absent), ∀ chain id — an
    /// Unlimited* arm is selected ⟺ a threshold param is present AND
    /// numeric_BE(value) >= numeric_BE(threshold) per the independent
    /// oracle. Both directions of MEDIUM-severity failure are pinned: a
    /// missed gate renders the most dangerous approval as a normal
    /// amount; a spurious gate hides the real amount behind "unlimited".
    #[kani::proof]
    #[kani::unwind(34)]
    fn amt_dec_unlimited_iff_ge_threshold() {
        let value: [u8; 32] = kani::any();
        let threshold: [u8; 32] = kani::any();
        let has_threshold: bool = kani::any();
        let token: [u8; 20] = kani::any();
        let has_token: bool = kani::any();
        let native: [u8; 20] = kani::any();
        let has_native: bool = kani::any();
        let contract: [u8; 20] = kani::any();
        let decimals: u8 = kani::any();
        let sym: [u8; 4] = kani::any();
        let meta = Erc20Metadata {
            chain_id: kani::any(),
            contract,
            decimals,
            name: b"",
            symbol: &sym,
        };
        let has_meta: bool = kani::any();
        let mut params = ParamSet::default();
        if has_threshold {
            params.threshold = Some(&threshold);
        }
        if has_native {
            params.native_currency = Some(&native);
        }
        let token_addr = if has_token { Some(token) } else { None };
        let d = token_amount_decision(
            &value,
            token_addr,
            if has_meta { Some(&meta) } else { None },
            kani::any(),
            &params,
        );
        let expect_unlimited = has_threshold && be_ge(&value, &threshold);
        assert!(is_unlimited_arm(&d.arm) == expect_unlimited);
        // With no message param, the wording is pinned to the default.
        match d.arm {
            TokenAmountArm::Unlimited { message, .. }
            | TokenAmountArm::UnlimitedUnverified { message } => {
                assert!(message == DEFAULT_THRESHOLD_MESSAGE);
            }
            _ => {}
        }
    }

    /// (a2) ∀ message params (len ≤ 18 covers the > DISPLAY_COLS
    /// reject): the threshold row's wording is the descriptor `message`
    /// EXACTLY when it is non-empty, row-fitting and printable ASCII
    /// (anti-homoglyph, review 3.6) — else the pinned default. Validity
    /// re-derived by an independent loop.
    #[kani::proof]
    #[kani::unwind(34)]
    fn amt_dec_message_param_binding() {
        const MMAX: usize = 18;
        let backing: [u8; MMAX] = kani::any();
        let mlen: usize = kani::any();
        kani::assume(mlen <= MMAX);
        let value: [u8; 32] = kani::any();
        let threshold = [0u8; 32]; // any value >= 0 -> always unlimited
        let mut params = ParamSet::default();
        params.threshold = Some(&threshold);
        params.message = Some(&backing[..mlen]);
        let d = token_amount_decision(&value, None, None, 1, &params);
        // Independent validity oracle.
        let mut valid = mlen > 0 && mlen <= DISPLAY_COLS;
        let mut i = 0usize;
        while i < mlen {
            if backing[i] < 0x20 || backing[i] >= 0x7f {
                valid = false;
            }
            i += 1;
        }
        match d.arm {
            TokenAmountArm::UnlimitedUnverified { message } => {
                if valid {
                    assert!(message.len() == mlen);
                    let mut k = 0usize;
                    while k < mlen {
                        assert!(message[k] == backing[k]);
                        k += 1;
                    }
                } else {
                    assert!(message == DEFAULT_THRESHOLD_MESSAGE);
                }
            }
            _ => assert!(false),
        }
    }

    /// (b) Token-identity ∀ (the MEDIUM-1 identity-hiding + M-4
    /// assumed-scale classes closed for ALL addresses): erc20 metadata
    /// HIT (resolved addr == meta.contract) ⟺ `Bound` with THAT
    /// metadata's decimals + symbol bytes; MISS ⟹ `UnverifiedRaw` with
    /// the identity page carrying the RESOLVED address; no resolved
    /// address ⟹ `UnverifiedRaw` with no identity page.
    #[kani::proof]
    #[kani::unwind(34)]
    fn amt_dec_token_identity_binding() {
        let value: [u8; 32] = kani::any();
        let addr: [u8; 20] = kani::any();
        let has_token: bool = kani::any();
        let contract: [u8; 20] = kani::any();
        let decimals: u8 = kani::any();
        let sym: [u8; 4] = kani::any();
        let meta = Erc20Metadata {
            chain_id: 1,
            contract,
            decimals,
            name: b"",
            symbol: &sym,
        };
        let has_meta: bool = kani::any();
        let params = ParamSet::default(); // no threshold, no sentinel
        let token_addr = if has_token { Some(addr) } else { None };
        let d = token_amount_decision(
            &value,
            token_addr,
            if has_meta { Some(&meta) } else { None },
            1,
            &params,
        );
        if has_token && has_meta && addr == contract {
            match d.arm {
                TokenAmountArm::Bound { decimals: dd, ticker } => {
                    assert!(dd == u32::from(decimals));
                    assert!(ticker.len() == 4);
                    let mut k = 0usize;
                    while k < 4 {
                        assert!(ticker[k] == sym[k]);
                        k += 1;
                    }
                }
                _ => assert!(false),
            }
            assert!(d.identity_page.is_none());
        } else {
            assert!(matches!(d.arm, TokenAmountArm::UnverifiedRaw));
            if has_token {
                assert!(d.identity_page == Some(addr));
            } else {
                assert!(d.identity_page.is_none());
            }
        }
    }

    /// (c) Native-sentinel precedence ∀: a resolved token equal to the
    /// descriptor's Merkle-pinned `nativeCurrencyAddress` IS the chain
    /// native currency — `Bound(18, native_ticker(chain_id))`, no
    /// identity page — and takes precedence over the companion-supplied
    /// erc20 trailer EVEN when that trailer also matches the same
    /// address. A non-native miss still gets the identity page with the
    /// sentinel param present.
    #[kani::proof]
    #[kani::unwind(34)]
    fn amt_dec_native_sentinel_precedence() {
        let value: [u8; 32] = kani::any();
        let addr: [u8; 20] = kani::any();
        let native: [u8; 20] = kani::any();
        let contract: [u8; 20] = kani::any();
        let decimals: u8 = kani::any();
        let sym: [u8; 4] = kani::any();
        let meta = Erc20Metadata {
            chain_id: 1,
            contract,
            decimals,
            name: b"",
            symbol: &sym,
        };
        let has_meta: bool = kani::any();
        let chain_id: u64 = kani::any();
        let mut params = ParamSet::default();
        params.native_currency = Some(&native);
        let d = token_amount_decision(
            &value,
            Some(addr),
            if has_meta { Some(&meta) } else { None },
            chain_id,
            &params,
        );
        if addr == native {
            match d.arm {
                TokenAmountArm::Bound { decimals: dd, ticker } => {
                    assert!(dd == 18);
                    let expect = native_ticker(chain_id);
                    assert!(ticker.len() == expect.len());
                    let mut k = 0usize;
                    while k < ticker.len() {
                        assert!(ticker[k] == expect[k]);
                        k += 1;
                    }
                }
                _ => assert!(false),
            }
            assert!(d.identity_page.is_none());
        } else if !(has_meta && addr == contract) {
            assert!(matches!(d.arm, TokenAmountArm::UnverifiedRaw));
            assert!(d.identity_page == Some(addr));
        }
    }

    /// (d) Scalar decisions ∀: `amount` defaults decimals=18 + the
    /// per-chain native ticker (descriptor `base` overrides both
    /// formatters' unit); `unit` defaults decimals=0 + empty unit. The
    /// 18-vs-0 asymmetry is load-bearing (a swap mis-scales by 10^18).
    #[kani::proof]
    #[kani::unwind(34)]
    fn amt_dec_scalar_defaults() {
        let dec: u8 = kani::any();
        let has_dec: bool = kani::any();
        let base: [u8; 4] = kani::any();
        let has_base: bool = kani::any();
        let chain_id: u64 = kani::any();
        let mut params = ParamSet::default();
        if has_dec {
            params.decimals = Some(dec);
        }
        if has_base {
            params.base = Some(&base);
        }
        let a = amount_decision(chain_id, &params);
        let u = unit_decision(&params);
        if has_dec {
            assert!(a.decimals == u32::from(dec));
            assert!(u.decimals == u32::from(dec));
        } else {
            assert!(a.decimals == 18);
            assert!(u.decimals == 0);
        }
        if has_base {
            assert!(a.unit.len() == 4 && u.unit.len() == 4);
            let mut k = 0usize;
            while k < 4 {
                assert!(a.unit[k] == base[k] && u.unit[k] == base[k]);
                k += 1;
            }
        } else {
            let expect = native_ticker(chain_id);
            assert!(a.unit.len() == expect.len());
            let mut k = 0usize;
            while k < a.unit.len() {
                assert!(a.unit[k] == expect[k]);
                k += 1;
            }
            assert!(u.unit.is_empty());
        }
    }

    /// Non-vacuity witnesses: every arm REACHED with concrete inputs
    /// (mirrors the host `tests` module so the same points are pinned
    /// under both engines).
    #[kani::proof]
    #[kani::unwind(34)]
    fn amt_dec_arms_concrete() {
        let sentinel = [0xEEu8; 20];
        let mut t = [0u8; 32];
        t[31] = 42;
        let mut params = ParamSet::default();
        params.threshold = Some(&t);
        params.native_currency = Some(&sentinel);

        // Unlimited (bound via the native sentinel) at value == threshold.
        let d = token_amount_decision(&t, Some(sentinel), None, 1, &params);
        match d.arm {
            TokenAmountArm::Unlimited { message, ticker } => {
                assert!(message == &b"unlimited"[..]);
                assert!(ticker == &b"ETH"[..]);
            }
            _ => assert!(false),
        }
        assert!(d.identity_page.is_none());

        // One below the threshold: stays a bound amount.
        let mut small = [0u8; 32];
        small[31] = 41;
        let d2 = token_amount_decision(&small, Some(sentinel), None, 1, &params);
        match d2.arm {
            TokenAmountArm::Bound { decimals, ticker } => {
                assert!(decimals == 18);
                assert!(ticker == &b"ETH"[..]);
            }
            _ => assert!(false),
        }

        // ERC-20 hit binds THAT metadata.
        let meta = Erc20Metadata {
            chain_id: 1,
            contract: [0xAA; 20],
            decimals: 6,
            name: b"USD Coin",
            symbol: b"USDC",
        };
        let v = [0u8; 32];
        let none_params = ParamSet::default();
        let d3 = token_amount_decision(&v, Some([0xAA; 20]), Some(&meta), 1, &none_params);
        match d3.arm {
            TokenAmountArm::Bound { decimals, ticker } => {
                assert!(decimals == 6);
                assert!(ticker == &b"USDC"[..]);
            }
            _ => assert!(false),
        }
        assert!(d3.identity_page.is_none());

        // Miss: raw + identity page.
        let d4 = token_amount_decision(&v, Some([0xBB; 20]), Some(&meta), 1, &none_params);
        assert!(matches!(d4.arm, TokenAmountArm::UnverifiedRaw));
        assert!(d4.identity_page == Some([0xBB; 20]));

        // Unlimited + unbound: loud message AND the identity page.
        let d5 = token_amount_decision(&t, Some([0xBB; 20]), None, 1, &params);
        match d5.arm {
            TokenAmountArm::UnlimitedUnverified { message } => {
                assert!(message == &b"unlimited"[..]);
            }
            _ => assert!(false),
        }
        assert!(d5.identity_page == Some([0xBB; 20]));
    }
}
