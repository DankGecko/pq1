//! Test-only scaffold for the `secure-tx-display` slice.
//!
//! The production `tx::display` module is gated `#[cfg(not(test))]` (see
//! `secure/src/tx/mod.rs`) because the production `mod.rs` imports
//! `crate::ui::confirm::Page`, which lives behind a hardware-only path.
//! That gate keeps the entire per-renderer source tree out of the host
//! test build even though every individual renderer is pure logic.
//!
//! This scaffold:
//!
//!   * Re-declares `MAX_PAGES` and `Pages` byte-for-byte equivalent to
//!     the production definitions (see `tx/display/mod.rs`). If the
//!     production constants ever change, the [`pure_tests::
//!     positive_max_pages_matches_production`] regression test fires
//!     because it asserts the value verbatim against the source text.
//!
//!   * `#[path]`-mounts each per-renderer source file under this
//!     parallel tree. Each file's `super::primitives::*` /
//!     `super::Pages` paths then resolve to *this* scaffold's items,
//!     not the gated-out production ones, so the bodies compile and
//!     execute unchanged.
//!
//!   * Lives entirely under `#[cfg(test)]` in `main.rs`, so production
//!     builds are unaffected.
//!
//! Coverage caveat: `pick_sign_pages` (the dispatcher in
//! `tx/display/mod.rs`) depends on `crate::zk` / `crate::tx::eip712::
//! cowswap_display`, both of which are themselves gated to firmware
//! builds, so it is documented in the report's "Coverage gaps" section
//! and exercised by the firmware-side e2e harness instead.

use crate::ui::confirm::Page;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// Mirrors the production `tx::display::MAX_PAGES`. Pinned by the
/// `negative_max_pages_matches_production_constant` test. (22 → 24 with the
/// multiSend clear-sign feature; 24 → 27 with the Safe gas-refund
/// worst-case magnitude page + the Safe/CoW gas-fee splice; 27 → 28 with the
/// Safe `safeTxGas` page — see the production doc comment.)
pub const MAX_PAGES: usize = 28;

/// Mirrors the production `tx::display::Pages`. Fields and methods kept
/// `pub` so the included submodules can construct and mutate them via
/// `super::Pages`; the production type uses `pub(super)` because the
/// production parent scope (`crate::tx::display`) re-exports through
/// the dispatcher.
pub struct Pages {
    pub buf: [Page; MAX_PAGES],
    pub len: usize,
}

impl Pages {
    pub fn as_slice(&self) -> &[Page] {
        &self.buf[..self.len]
    }

    pub fn empty_with_len(len: usize) -> Self {
        assert!(len <= MAX_PAGES, "Pages::empty_with_len: len > MAX_PAGES");
        Pages {
            buf: [[[b' '; DISPLAY_COLS]; DISPLAY_ROWS]; MAX_PAGES],
            len,
        }
    }

    pub fn row_mut(&mut self, page: usize, row: usize) -> &mut [u8; DISPLAY_COLS] {
        assert!(page < self.len);
        assert!(row < DISPLAY_ROWS);
        &mut self.buf[page][row]
    }

    pub fn with_len(len: usize) -> Self {
        Self::empty_with_len(len)
    }

    /// Mirrors the production `Pages::push_blank` (see
    /// `tx/display/mod.rs:144`). Required for the test-mounted
    /// `erc7730/` renderer which grows its page buffer dynamically.
    pub fn push_blank(&mut self) -> Result<usize, ()> {
        if self.len >= MAX_PAGES {
            return Err(());
        }
        self.buf[self.len] = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
        let idx = self.len;
        self.len += 1;
        Ok(idx)
    }

    /// Mirrors the production `Pages::page_mut` (see
    /// `tx/display/mod.rs:127`). Required for renderers that need to
    /// access two rows of the same page simultaneously via
    /// `split_at_mut`.
    pub fn page_mut(&mut self, page: usize) -> &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS] {
        assert!(page < self.len);
        &mut self.buf[page]
    }
}

/// **te-2 (Trezor-port) — canonical golden hash over a rendered `Pages`
/// grid.**
///
/// Hashes the page count then every *used* page's full row×col ASCII grid,
/// so ANY change to layout, spacing, truncation, divider placement, row
/// position, or page count changes the digest. This is the pixel-golden
/// gate's host-runnable complement for the security-critical decode-and-
/// render screens (Safe / CoW / ERC-7730): the per-substring faithfulness
/// assertions in these modules check that *specific* fields render, but a
/// full-grid golden also catches WYSIWYS regressions *elsewhere* on the
/// page (a shifted label, a dropped divider, a truncation the substring
/// check doesn't look at). The firmware `ui/golden.rs` gate covers the
/// LCD pixel-font layer for `value_transfer`; the Safe/CoW/ERC-7730 inputs
/// need host-only dbgen fixtures, so their golden gate lives here.
///
/// Intentional layout changes require re-blessing the `GOLDEN_*` constant
/// in the calling test — that explicit step is the point of a golden gate.
pub fn golden_grid_hash(pages: &Pages) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((pages.len as u32).to_be_bytes());
    for page in pages.as_slice() {
        for row in page {
            h.update(&row[..]);
        }
    }
    h.finalize().into()
}

// `primitives` was extracted to the host crate so it can be fuzzed directly;
// re-export it here (instead of `#[path]`-mounting the shim) so every mounted
// render file's `super::primitives::*` / `super::super::primitives::*` resolves
// to the same byte-writers the device build uses.
pub use pqsigner_erc7730::display::primitives;

#[path = "../tx/display/value_transfer.rs"]
pub mod value_transfer;

#[path = "../tx/display/blind_sign.rs"]
pub mod blind_sign;

#[path = "../tx/display/eip1271.rs"]
pub mod eip1271;

#[path = "../tx/display/erc20_known.rs"]
pub mod erc20_known;

#[path = "../tx/display/erc20_unknown.rs"]
pub mod erc20_unknown;

// The dispatcher-level native-value invariant (audit C-1 / H-2 / M-8).
// Mounted so its real body + regression tests run on the host even though
// the `pick_sign_pages` dispatcher that calls it is firmware-only.
#[path = "../tx/display/value_page.rs"]
pub mod value_page;

#[path = "../tx/display/slot_rotation.rs"]
pub mod slot_rotation;

#[path = "../tx/display/batch.rs"]
pub mod batch;

#[path = "../tx/display/typed_call/mod.rs"]
pub mod typed_call;

// ERC-7730 / ERC-8213 renderers. Mounted alongside the other renderers
// so host tests in `erc7730_render_pure_tests.rs` can call the full
// `render_erc7730_pages` / `render_erc7730_eip712_pages` pipelines and
// assert the resulting OLED rows byte-for-byte against the strings a
// user would actually see on the device.
#[path = "../tx/display/erc7730/mod.rs"]
pub mod erc7730;

#[path = "../tx/display/erc8213.rs"]
pub mod erc8213;

// `safe_display` IS re-mounted (2026-06-30). Its absolute `crate::tx::display::
// {Pages,primitives}` + `crate::tx::eip712::cowswap_display::*` paths now
// resolve via the `#[cfg(test)] pub(crate) use … as display` alias in
// `tx/mod.rs` and the test mount of `cowswap_display` in `eip712/mod.rs`.
// `#[allow(dead_code)]` because under the test build the binary crate's
// production callers (`pick_sign_pages`, the handlers) are gated out, so the
// public entry points would otherwise warn as unused. Render-faithfulness
// tests in `safe_display_render_pure_tests.rs`.
#[path = "../tx/display/safe_display.rs"]
#[allow(dead_code)]
pub mod safe_display;

// `safe_mgmt` IS re-mounted: it has no unused helpers in the host-test
// configuration, and its per-op renderers are pure-display logic that
// should be host-asserted against expected page rows.
#[path = "../tx/display/safe_mgmt.rs"]
pub mod safe_mgmt;

#[cfg(test)]
mod pure_tests;

#[cfg(test)]
mod erc7730_render_pure_tests;

#[cfg(test)]
mod safe_mgmt_render_pure_tests;

#[cfg(test)]
mod cowswap_render_pure_tests;

#[cfg(test)]
mod safe_display_render_pure_tests;
