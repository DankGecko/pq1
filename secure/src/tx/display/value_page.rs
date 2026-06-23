//! Dispatcher-level native-ETH `value` invariant (audit C-1 / H-2 / M-8).
//!
//! The outer UserOp `value` is signed verbatim into
//! `executeWithOffchainCount(ownerIndex, count, target, value, data)`, but
//! several renderers historically surfaced only token / inner-tx semantics
//! and never the native ETH — so a malicious companion could display a
//! benign token transfer while signing an ETH-draining `call{value}` to an
//! attacker contract.
//!
//! Rather than trust each renderer to opt in, EVERY sign confirm funnels
//! through [`enforce_native_value_page`] (called by
//! [`super::pick_sign_pages`]): when `value != 0` it splices a dedicated,
//! loud value page in right after the renderer's banner. A future renderer
//! physically cannot forget it.
//!
//! Lives in its own file (not `mod.rs`) so the host-test scaffold
//! (`crate::display_under_test`) can `#[path]`-mount it and exercise the
//! real body — `mod.rs`'s `pick_sign_pages` dispatcher pulls in
//! firmware-only deps and is gated `#[cfg(not(test))]`.

use super::primitives;
use super::Pages;
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// Splice a loud native-ETH `value` page into an already-rendered page set
/// when `value != 0`, reporting whether the WYSIWYS invariant holds.
///
/// The page lands at index 1 (immediately after the banner) for
/// prominence. Two hardening properties (audit 2026-06-18 — native-value
/// WYSIWYS gate), because the outer UserOp `value` is signed verbatim into
/// `executeWithOffchainCount(...)` and forwarded on chain via
/// `target.call{value: value}(data)` — so hiding it is an ETH drain behind
/// a benign confirm (the same class as audit C-1 / H-2 / M-8):
///
///   * **FI-hardened skip decision.** The dangerous outcome is *skipping*
///     the value page on a non-zero value. The skip path is therefore
///     gated on a Hamming-distant sentinel proof that `value == 0`
///     (`fi::check_true_into_sentinel` double-evaluates the predicate with
///     `wait_random` between, then commits the verdict to a volatile
///     sentinel). A single fault that tries to force the skip on a
///     non-zero value cannot produce `OK_SENTINEL`, so control falls
///     through to the mandatory splice — matching the FI bar every other
///     sign-path gate already meets. A bare `if value.is_zero()` was one
///     instruction-skip away from dropping the page.
///   * **Fails CLOSED on a full page buffer.** If `value != 0` and the
///     page cannot be spliced (`pages.len == MAX_PAGES`), returns
///     `Err(())` so the caller REFUSES to sign rather than release a
///     signature over ETH the user never saw. The old code silently
///     skipped on a false assumption ("every renderer that reaches
///     `MAX_PAGES` already shows the value"), which is untrue for the
///     dynamically-grown ERC-7730 calldata renderer (`6 + N_visible`
///     pages): a future ≥18-visible-field payable descriptor would have
///     dropped the value page with no fault at all. Refusing is the
///     dispatcher-level analogue of the multiSend gate's "refuse rather
///     than truncate" rule.
///
/// Returns `Ok(())` when the invariant holds (value robustly zero, or the
/// loud page was spliced) and `Err(())` when a mandatory value page could
/// not be spliced — the caller must map that to a refuse-to-sign. The
/// `Result` is `#[must_use]` by construction, so `pick_sign_pages`'s `?`
/// can never silently drop the refusal.
pub(super) fn enforce_native_value_page(pages: &mut Pages, value: &U256) -> Result<(), ()> {
    // Skip ONLY on a sentinel-robust proof that `value == 0`. `black_box`
    // keeps the two internal evaluations of the predicate from collapsing
    // into one (F-1). Any other outcome — value non-zero, or a glitched
    // zero-check — flows to the mandatory splice below.
    let may_skip =
        crate::fi::check_true_into_sentinel(|| core::hint::black_box(value.is_zero()));
    if may_skip == crate::fi::OK_SENTINEL {
        return Ok(());
    }
    // value is non-zero (or the zero-check was faulted): a loud value page
    // is MANDATORY. Splice it; `?` fails CLOSED when the buffer is full so
    // the caller refuses to sign instead of hiding the ETH.
    let at = if pages.len >= 1 { 1 } else { 0 };
    let idx = insert_blank(pages, at)?;
    primitives::write_line(pages.row_mut(idx, 0), "! NATIVE ETH");
    let [_lbl, r1, r2, foot] = pages.page_mut(idx);
    let fit = primitives::write_eth_two_rows(r1, r2, value);
    primitives::write_line(
        foot,
        match fit {
            primitives::AmountFit::Full => "> next",
            primitives::AmountFit::Overflow => "!AMOUNT OVERFLOW",
        },
    );
    Ok(())
}

/// Splice the two standard gas/fee pages (identical to value_transfer
/// pages 3-4) immediately before the renderer's trailing page (the confirm
/// prompt on the Safe and CoW surfaces).
///
/// Called by [`super::pick_sign_pages`] for the Safe / CoW / v1-ZK
/// surfaces, which — unlike every other renderer — do not emit gas pages
/// of their own. The five EntryPoint v0.6 fee fields are committed to by
/// the UserOp signature and the wallet pays the EntryPoint prefund out of
/// its own native ETH; hiding them is a fee-bomb drain behind a benign
/// confirm (audit 2026-06-19 — the WYSIWYS sibling of the native-value
/// gate above).
///
/// Unlike [`enforce_native_value_page`] there is no skip-on-zero decision
/// (gas is shown unconditionally, matching every other renderer), so there
/// is no FI skip gate to harden here. The only failure mode is a full page
/// buffer, which FAILS CLOSED: the check is performed up-front so the
/// splice is atomic (never a single orphaned gas page) and the caller maps
/// `Err(())` to a refuse-to-sign.
pub(super) fn enforce_gas_pages(pages: &mut Pages, tx: &Eip1559Tx) -> Result<(), ()> {
    // Atomic budget check: both pages or neither.
    if pages.len + 2 > super::MAX_PAGES {
        return Err(());
    }
    // Insert just before the trailing page so the gas pages read after the
    // semantic content, matching value_transfer's "Max fee" / "Worst-case"
    // ordering. `at` clamps to 0 for the (impossible here) empty-buffer case.
    let at = pages.len.saturating_sub(1);
    // Page A: "Max fee:" + max_fee_per_gas (gwei) + priority tip.
    let a = insert_blank(pages, at)?;
    primitives::write_line(pages.row_mut(a, 0), "Max fee:");
    let _ = primitives::write_gwei(pages.row_mut(a, 1), &tx.max_fee_per_gas);
    primitives::write_tip_row(pages.row_mut(a, 2), &tx.max_priority_fee_per_gas);
    primitives::write_line(pages.row_mut(a, 3), "> next");
    // Page B: "Worst-case:" + max_fee_per_gas * gas_limit (ETH) + gas limit.
    let b = insert_blank(pages, a + 1)?;
    primitives::write_line(pages.row_mut(b, 0), "Worst-case:");
    primitives::write_fee_budget_row(pages.row_mut(b, 1), &tx.max_fee_per_gas, tx.gas_limit);
    primitives::write_gas(pages.row_mut(b, 2), tx.gas_limit);
    primitives::write_line(pages.row_mut(b, 3), "> next");
    Ok(())
}

/// Insert a blank page at index `at`, shifting the pages currently at
/// `at..len` one slot toward the back. Returns the index of the new
/// (cleared) page, or `Err(())` when the buffer is already full.
fn insert_blank(pages: &mut Pages, at: usize) -> Result<usize, ()> {
    if pages.len >= super::MAX_PAGES {
        return Err(());
    }
    let at = core::cmp::min(at, pages.len);
    // Shift back-to-front so we never clobber a page we still need to move.
    // `Page` is `Copy`, so the array assignment is a byte copy.
    let mut i = pages.len;
    while i > at {
        pages.buf[i] = pages.buf[i - 1];
        i -= 1;
    }
    pages.buf[at] = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    pages.len += 1;
    Ok(at)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_wei() -> U256 {
        let mut v = [0u8; 32];
        v[31] = 1;
        U256(v)
    }

    fn gwei(n: u64) -> U256 {
        // n * 1e9 wei, fits a u64 for any realistic gas price.
        let wei = (n as u128) * 1_000_000_000u128;
        let mut v = [0u8; 32];
        v[16..32].copy_from_slice(&wei.to_be_bytes());
        U256(v)
    }

    fn fee_tx() -> Eip1559Tx {
        Eip1559Tx {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: gwei(2),
            max_fee_per_gas: gwei(50),
            gas_limit: 21_000,
            to: Some([0x11u8; 20]),
            value: U256::zero(),
            data_len: 0,
            access_list_count: 0,
            signing_hash: [0u8; 32],
        }
    }

    /// Audit C-1 regression. The invariant is applied uniformly to the
    /// final page set regardless of which renderer (TxKind) produced it,
    /// so a single test over a synthetic banner+body+confirm set proves
    /// the per-TxKind guarantee: a non-zero `value` always yields a loud
    /// value page right after the banner.
    #[test]
    fn nonzero_value_inserts_loud_value_page_after_banner() {
        let mut pages = Pages::with_len(3);
        primitives::write_line(pages.row_mut(0, 0), "! Unknown token");
        primitives::write_line(pages.row_mut(2, 2), "L=Cancel");
        assert!(enforce_native_value_page(&mut pages, &one_wei()).is_ok());
        assert_eq!(pages.len, 4, "a value page must be inserted");
        // Banner stays first; the loud value page is now second.
        assert_eq!(&pages.buf[0][0][..15], b"! Unknown token");
        assert_eq!(&pages.buf[1][0][..12], b"! NATIVE ETH");
        // The original body shifted back by one — nothing clobbered.
        assert_eq!(&pages.buf[3][2][..8], b"L=Cancel");
    }

    /// A zero `value` must NOT add a page (no spurious "0 ETH" page), and
    /// reports `Ok` (invariant holds — nothing to show).
    #[test]
    fn zero_value_adds_no_page() {
        let mut pages = Pages::with_len(3);
        assert!(enforce_native_value_page(&mut pages, &U256::zero()).is_ok());
        assert_eq!(pages.len, 3);
    }

    /// `insert_blank` on a full buffer fails closed instead of panicking,
    /// so the invariant degrades gracefully rather than overrunning.
    #[test]
    fn insert_blank_on_full_buffer_is_err() {
        let mut pages = Pages::with_len(super::super::MAX_PAGES);
        assert!(insert_blank(&mut pages, 1).is_err());
    }

    /// Audit 2026-06-18 regression — FAIL CLOSED. A non-zero `value` that
    /// cannot be spliced because the renderer already filled the page
    /// budget must return `Err(())` (caller refuses to sign), NOT silently
    /// drop the loud ETH page. Pages are left unchanged so nothing
    /// confirmable hides the value.
    #[test]
    fn nonzero_value_full_buffer_fails_closed() {
        let mut pages = Pages::with_len(super::super::MAX_PAGES);
        let before = pages.len;
        assert!(
            enforce_native_value_page(&mut pages, &one_wei()).is_err(),
            "non-zero value on a full buffer must fail closed"
        );
        assert_eq!(pages.len, before, "no page may be spliced or dropped");
    }

    /// A non-zero value with exactly one free slot must splice the loud
    /// page (the common case for the short value-hiding renderers, which
    /// never approach the cap).
    #[test]
    fn nonzero_value_with_room_splices_and_reports_ok() {
        let mut pages = Pages::with_len(super::super::MAX_PAGES - 1);
        assert!(enforce_native_value_page(&mut pages, &one_wei()).is_ok());
        assert_eq!(pages.len, super::super::MAX_PAGES);
        assert_eq!(&pages.buf[1][0][..12], b"! NATIVE ETH");
    }

    /// Audit 2026-06-19 — gas/fee WYSIWYS splice. The two gas pages are
    /// inserted right before the renderer's trailing (confirm) page, so a
    /// Safe/CoW confirm can no longer hide the signed maxFeePerGas / gas
    /// limits. Banner stays first, confirm stays last.
    #[test]
    fn gas_pages_spliced_before_confirm() {
        let mut pages = Pages::with_len(3);
        primitives::write_line(pages.row_mut(0, 0), "Sign CowSwap?");
        primitives::write_line(pages.row_mut(2, 2), "L=Cancel");
        assert!(enforce_gas_pages(&mut pages, &fee_tx()).is_ok());
        assert_eq!(pages.len, 5, "two gas pages must be inserted");
        // Original banner first; confirm shifted to the last slot.
        assert_eq!(&pages.buf[0][0][..13], b"Sign CowSwap?");
        assert_eq!(&pages.buf[4][2][..8], b"L=Cancel");
        // Gas pages sit just before the confirm page.
        assert_eq!(&pages.buf[2][0][..8], b"Max fee:");
        assert_eq!(&pages.buf[3][0][..11], b"Worst-case:");
    }

    /// FAIL CLOSED + ATOMIC. With fewer than two free slots the gas splice
    /// must refuse (caller refuses to sign) and leave the page set
    /// untouched — never a single orphaned gas page hiding the other.
    #[test]
    fn gas_pages_insufficient_room_fails_closed_atomically() {
        // Exactly one free slot — not enough for the two-page splice.
        let mut pages = Pages::with_len(super::super::MAX_PAGES - 1);
        let before = pages.len;
        assert!(
            enforce_gas_pages(&mut pages, &fee_tx()).is_err(),
            "fewer than two free slots must fail closed"
        );
        assert_eq!(pages.len, before, "no page may be spliced (atomic)");
    }
}
