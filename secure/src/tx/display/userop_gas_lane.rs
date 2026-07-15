//! EntryPoint v0.6 UserOperation gas-triple trusted-display binding (finding F10).
//!
//! The signed userOpHash commits `callGasLimit`, `verificationGasLimit`, and
//! `preVerificationGas` as three independent, ordered 256-bit words
//! (`aa::userop::compute_sphincs_digest_v06`). The generic Safe/CoW envelope
//! renderer previously showed only their saturated `u64` aggregate
//! (`tx.gas_limit`), so two UserOperations whose gas triple is a permutation
//! with the same sum — e.g. `(call=100000, verification=200000)` vs
//! `(call=200000, verification=100000)` — produced byte-identical confirmation
//! pages even though the signed digest differed. A hostile companion could thus
//! misallocate gas (inner-call OOG griefing / bundler over-pay via
//! preVerificationGas) behind an unchanged screen — a WYSIWYS-injectivity break.
//!
//! This lane renders all three exact values (plus their `Total:`, the same
//! aggregate the envelope shows) on one page, and the handler independently
//! FI-proves that page materialized. Unlike the nonce lane there is no
//! compact/skip fast path: the page is ALWAYS inserted and ALWAYS proved, so a
//! skipped inserter or proof call fails closed. Only the ERC-7730 renderer
//! already showed the components inline; on that path this gate double-shows,
//! which is redundant-but-safe (matching the nonce-lane precedent). Every other
//! UserOp dispatch branch (value transfer, ERC-20, Safe v1/exec, CoW, blind,
//! typed-call) relied on this handler-level gate for gas injectivity.

use super::Pages;
use crate::tx::eip1559::U256;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// Page budget reserved by every UserOp renderer for the gas triple (F10).
/// Unlike [`super::nonce_lane::NONZERO_NONCE_LANE_PAGES`] this is unconditional
/// — the page is always emitted, so the reservation is always one.
pub(crate) const USEROP_GAS_PAGES: usize = 1;

type GasLanePage = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];

/// Insert the exact call / verification / pre-verification gas page, after the
/// signer, target, and (conditional) nonce-lane pages.
///
/// Returns `Err(())` if the page buffer is full OR any gas value is too wide to
/// render faithfully in `DISPLAY_COLS`; every caller maps that to refusal (fail
/// closed — the finding's "render the exact three gas values … or refuse"
/// contract). The insertion index (`min(4, pages.len)`) sits at or after the
/// nonce lane's `min(3, …)`, so it never shifts an already-proven signer,
/// target, or nonce-lane page.
#[inline(never)]
pub(crate) fn enforce_userop_gas_page(
    pages: &mut Pages,
    call_gas: &[u8; 32],
    verification_gas: &[u8; 32],
    pre_verification_gas: &[u8; 32],
) -> Result<(), ()> {
    let page = build_gas_lane_page(call_gas, verification_gas, pre_verification_gas).ok_or(())?;
    let at = core::cmp::min(4, pages.len);
    let idx = super::value_page::insert_blank(pages, at)?;
    pages.buf[idx] = page;
    Ok(())
}

/// Exact all-4-row predicate for the gas page.
pub(crate) fn userop_gas_page_matches(
    pages: &Pages,
    page_index: usize,
    call_gas: &[u8; 32],
    verification_gas: &[u8; 32],
    pre_verification_gas: &[u8; 32],
) -> bool {
    let Some(expected) = build_gas_lane_page(call_gas, verification_gas, pre_verification_gas)
    else {
        return false;
    };
    let Some(actual) = pages.as_slice().get(page_index) else {
        return false;
    };
    let mut diff = 0u8;
    for row in 0..DISPLAY_ROWS {
        for col in 0..DISPLAY_COLS {
            diff |= actual[row][col] ^ expected[row][col];
        }
    }
    diff == 0
}

/// FI-hardened completion proof for [`enforce_userop_gas_page`].
///
/// The caller records `prior_len`, calls the non-inlined inserter, scrubs the
/// ABI return register, and accepts only [`crate::fi::OK_SENTINEL`] here. The
/// predicate requires exactly one new page at the deterministic insertion index
/// whose four rows match the three signed gas words (and their total). A
/// skipped inserter or proof call fails closed.
#[inline(never)]
pub(crate) fn userop_gas_page_proof(
    pages: &Pages,
    prior_len: usize,
    call_gas: &[u8; 32],
    verification_gas: &[u8; 32],
    pre_verification_gas: &[u8; 32],
) -> u32 {
    crate::fi::check_true_into_sentinel(|| {
        prior_len.checked_add(USEROP_GAS_PAGES).is_some_and(|expected_len| {
            core::hint::black_box(pages.len == expected_len)
                && userop_gas_page_matches(
                    pages,
                    core::cmp::min(4, prior_len),
                    call_gas,
                    verification_gas,
                    pre_verification_gas,
                )
        })
    })
}

/// Big-endian `[u8; 32]` → `u128`, saturating when the high 128 bits are set.
fn to_u128_saturating(v: &[u8; 32]) -> u128 {
    if v[..16].iter().any(|&b| b != 0) {
        return u128::MAX;
    }
    match v[16..].try_into() {
        Ok(a) => u128::from_be_bytes(a),
        Err(_) => u128::MAX,
    }
}

/// Saturating `u64` total — the same value as the handler's `display_gas_limit`
/// and the envelope's aggregate gas page, so `Total:` here reconciles with it.
fn gas_total_u64(call: &[u8; 32], verify: &[u8; 32], prever: &[u8; 32]) -> u64 {
    to_u128_saturating(call)
        .saturating_add(to_u128_saturating(verify))
        .saturating_add(to_u128_saturating(prever))
        .min(u64::MAX as u128) as u64
}

fn build_gas_lane_page(
    call: &[u8; 32],
    verify: &[u8; 32],
    prever: &[u8; 32],
) -> Option<GasLanePage> {
    let mut page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    write_gas_row(&mut page[0], b"Call:", &U256(*call))?;
    write_gas_row(&mut page[1], b"Verify:", &U256(*verify))?;
    write_gas_row(&mut page[2], b"PreVer:", &U256(*prever))?;
    let total = gas_total_u64(call, verify, prever);
    let mut total_bytes = [0u8; 32];
    total_bytes[24..].copy_from_slice(&total.to_be_bytes());
    write_gas_row(&mut page[3], b"Total:", &U256(total_bytes))?;
    Some(page)
}

/// Render `prefix` followed by the decimal of `value` into one row, space-padded.
///
/// `None` if `prefix.len() + digits` does not fit `DISPLAY_COLS` (a gas value too
/// large to show faithfully → the caller refuses). Mirrors the ERC-7730
/// renderer's `write_u256_decimal_with_prefix`.
fn write_gas_row(row: &mut [u8; DISPLAY_COLS], prefix: &[u8], value: &U256) -> Option<()> {
    *row = [b' '; DISPLAY_COLS];
    let mut digits = [0u8; 80];
    let n = value.format_decimal(0, 0, false, &mut digits)?;
    if prefix.len().checked_add(n)? > DISPLAY_COLS {
        return None;
    }
    row[..prefix.len()].copy_from_slice(prefix);
    row[prefix.len()..prefix.len() + n].copy_from_slice(&digits[..n]);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gas(n: u64) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[24..].copy_from_slice(&n.to_be_bytes());
        v
    }

    #[test]
    fn gas_page_inserted_and_proved() {
        let (c, v, p) = (gas(100_000), gas(200_000), gas(21_000));
        let mut pages = Pages::with_len(4);
        assert!(enforce_userop_gas_page(&mut pages, &c, &v, &p).is_ok());
        assert_eq!(pages.len, 5);
        assert_eq!(&pages.buf[4][0], b"Call:100000     ");
        assert_eq!(&pages.buf[4][1], b"Verify:200000   ");
        assert_eq!(&pages.buf[4][2], b"PreVer:21000    ");
        assert_eq!(&pages.buf[4][3], b"Total:321000    ");
        assert_eq!(
            userop_gas_page_proof(&pages, 4, &c, &v, &p),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn permuted_gas_triple_yields_distinct_pages() {
        // (call, verification) swapped, same sum: the aggregate `Total:` is
        // identical but the component rows differ, so the page is NOT the same —
        // exactly the collision the old aggregate-only display allowed.
        let a = build_gas_lane_page(&gas(100_000), &gas(200_000), &gas(21_000)).unwrap();
        let b = build_gas_lane_page(&gas(200_000), &gas(100_000), &gas(21_000)).unwrap();
        assert_eq!(a[3], b[3], "totals must match (same sum)");
        assert_ne!(a, b, "permuting the gas split must change the page");

        let mut pages = Pages::with_len(4);
        enforce_userop_gas_page(&mut pages, &gas(100_000), &gas(200_000), &gas(21_000)).unwrap();
        assert!(userop_gas_page_matches(
            &pages, 4, &gas(100_000), &gas(200_000), &gas(21_000)
        ));
        assert!(!userop_gas_page_matches(
            &pages, 4, &gas(200_000), &gas(100_000), &gas(21_000)
        ));
    }

    #[test]
    fn every_component_is_bound() {
        let (c, v, p) = (gas(111), gas(222), gas(333));
        let mut pages = Pages::with_len(1);
        enforce_userop_gas_page(&mut pages, &c, &v, &p).unwrap();
        assert!(userop_gas_page_matches(&pages, 1, &c, &v, &p));
        assert!(!userop_gas_page_matches(&pages, 1, &gas(112), &v, &p));
        assert!(!userop_gas_page_matches(&pages, 1, &c, &gas(223), &p));
        assert!(!userop_gas_page_matches(&pages, 1, &c, &v, &gas(334)));
    }

    #[test]
    fn proof_rejects_skipped_or_corrupted_page() {
        let (c, v, p) = (gas(1), gas(2), gas(3));
        let mut pages = Pages::with_len(2);
        assert_ne!(
            userop_gas_page_proof(&pages, 2, &c, &v, &p),
            crate::fi::OK_SENTINEL
        );
        enforce_userop_gas_page(&mut pages, &c, &v, &p).unwrap();
        assert_eq!(
            userop_gas_page_proof(&pages, 2, &c, &v, &p),
            crate::fi::OK_SENTINEL
        );
        pages.buf[2][0][5] ^= 1;
        assert_ne!(
            userop_gas_page_proof(&pages, 2, &c, &v, &p),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn oversized_gas_value_fails_closed() {
        // ~78-digit value cannot be shown faithfully in DISPLAY_COLS.
        let huge = [0xFFu8; 32];
        let mut pages = Pages::with_len(1);
        assert!(enforce_userop_gas_page(&mut pages, &huge, &gas(1), &gas(1)).is_err());
        assert_eq!(pages.len, 1, "no page inserted on refuse");
    }

    #[test]
    fn fails_closed_when_buffer_full() {
        let mut full = Pages::with_len(super::super::MAX_PAGES);
        assert!(enforce_userop_gas_page(&mut full, &gas(1), &gas(2), &gas(3)).is_err());
        assert_eq!(full.len, super::super::MAX_PAGES);
    }
}
