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
use crate::tx::eip1559::U256;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// Splice a loud native-ETH `value` page into an already-rendered page set
/// when `value != 0`. The page lands at index 1 (immediately after the
/// banner) for prominence; if the buffer is already full it is silently
/// skipped — every renderer that reaches `MAX_PAGES` already shows the
/// value on one of its own pages, so only the value-hiding (short)
/// renderers are affected, and those never approach the cap.
pub(super) fn enforce_native_value_page(pages: &mut Pages, value: &U256) {
    if value.is_zero() {
        return;
    }
    let at = if pages.len >= 1 { 1 } else { 0 };
    let idx = match insert_blank(pages, at) {
        Ok(i) => i,
        Err(()) => return,
    };
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
        enforce_native_value_page(&mut pages, &one_wei());
        assert_eq!(pages.len, 4, "a value page must be inserted");
        // Banner stays first; the loud value page is now second.
        assert_eq!(&pages.buf[0][0][..15], b"! Unknown token");
        assert_eq!(&pages.buf[1][0][..12], b"! NATIVE ETH");
        // The original body shifted back by one — nothing clobbered.
        assert_eq!(&pages.buf[3][2][..8], b"L=Cancel");
    }

    /// A zero `value` must NOT add a page (no spurious "0 ETH" page).
    #[test]
    fn zero_value_adds_no_page() {
        let mut pages = Pages::with_len(3);
        enforce_native_value_page(&mut pages, &U256::zero());
        assert_eq!(pages.len, 3);
    }

    /// `insert_blank` on a full buffer fails closed instead of panicking,
    /// so the invariant degrades gracefully rather than overrunning.
    #[test]
    fn insert_blank_on_full_buffer_is_err() {
        let mut pages = Pages::with_len(super::super::MAX_PAGES);
        assert!(insert_blank(&mut pages, 1).is_err());
    }
}
