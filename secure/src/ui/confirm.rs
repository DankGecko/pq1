//! Multi-page transaction confirmation dialog.
//!
//! The pages are pre-rendered by `tx::display::render_pages` from a parsed
//! `Eip1559Tx`. This module just handles the navigation:
//!
//!   * tap right    → next page
//!   * tap left     → previous page
//!   * long right   → confirm
//!   * long left    → cancel

use super::{display, DISPLAY_COLS, DISPLAY_ROWS};
// The interactive event loop below is compiled out in `e2e-test` builds,
// so its imports are gated the same way to avoid unused-import warnings.
#[cfg(not(feature = "e2e-test"))]
use super::{input, Button, Press};
#[cfg(not(feature = "e2e-test"))]
use crate::timeout;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ConfirmResult {
    Confirmed,
    Cancelled,
    IdleWipe,
}

/// A single page of the confirm dialog: 4 lines, 16 cols each.
pub type Page = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];

pub fn confirm(pages: &[Page]) -> ConfirmResult {
    if pages.is_empty() {
        return ConfirmResult::Cancelled;
    }

    // ---- e2e-test fast-path ----
    //
    // Render every page (so the test harness can scrape the framebox
    // log lines if it wants to assert page content), then auto-confirm
    // without reading stdin. This is the only place the secure world
    // would block on user input during a sign request, so this single
    // bypass is enough to make every cmd_* path non-interactive.
    #[cfg(feature = "e2e-test")]
    {
        for page in pages.iter() {
            render_page(page);
        }
        return ConfirmResult::Confirmed;
    }

    #[cfg(not(feature = "e2e-test"))]
    {
        let mut idx: usize = 0;
        // WYSIWYS scroll-to-end gate (2026-06-26): a long-press-right only
        // CONFIRMS once the user has paged to the last page at least once;
        // before that it is demoted to "advance one page". Without this a
        // user could long-press on page 0 and authorise a signature without
        // ever seeing the security-critical pages the dispatcher splices in
        // (native-ETH value at index 1, gas/fee pages, Safe gas-refund
        // pages, the ERC-8213 fingerprint) — defeating every per-page
        // WYSIWYS mitigation in the firmware. Mirrors the identical
        // `seen_last` gate the seed-backup wizard already enforces
        // (`seed_wizard::show_mnemonic_simple`).
        let mut seen_last = false;
        // HIGH-13 fix: do NOT reset the inactivity timer on entry.
        // NS can spam SIGN_USEROP / request-unlock calls; each call
        // lands us here and the old code reset the timer before the
        // user had touched a button. That kept the unlocked window
        // open indefinitely as long as NS kept asking — the exact
        // thing CLAUDE.md forbids ("NS pings do not reset [the
        // inactivity timer]. Only real button presses on S-world
        // confirm dialogs count as activity.").

        loop {
            render_page(&pages[idx]);
            // Sticky: once the final page has been displayed, confirm is
            // unlocked from any page. Reaching the last page requires
            // short-right past every intermediate page (short-right advances
            // one page at a time and is capped at the end), so the whole set
            // has been shown before this flips true.
            if idx + 1 >= pages.len() {
                seen_last = true;
            }

            let mut idle = || timeout::is_idle();
            let event = match input().wait_button(&mut idle) {
                Some(ev) => ev,
                None => return ConfirmResult::IdleWipe,
            };

            // A button event IS real user activity — reset the timer
            // here and only here. This is the trusted-display contract.
            timeout::reset_activity();

            match event {
                (Button::Right, Press::Short) => {
                    if idx + 1 < pages.len() {
                        idx += 1;
                    }
                }
                (Button::Left, Press::Short) => {
                    if idx > 0 {
                        idx -= 1;
                    }
                }
                (Button::Right, Press::Long) => {
                    if seen_last {
                        return ConfirmResult::Confirmed;
                    }
                    // Not yet scrolled to the end — treat the long-press as
                    // "next page" so the user is guided through the remaining
                    // (possibly drain-bearing) pages before they can sign.
                    if idx + 1 < pages.len() {
                        idx += 1;
                    }
                }
                (Button::Left, Press::Long) => return ConfirmResult::Cancelled,
            }
        }
    }
}

fn render_page(page: &Page) {
    let d = display();
    d.clear();
    for (row_idx, row) in page.iter().enumerate() {
        d.draw_line(row_idx, super::ascii_str(row));
    }
    d.flush();
}

/// Render a sequence of pre-rendered pages WITHOUT waiting for input — each is
/// drawn + flushed (which, under `ui-capture`, emits a `[UI-FP]` fingerprint).
/// The render-only golden harness ([`crate::ui::golden`]) uses this to capture
/// screens directly, skipping the C10 keygen/sign that makes the e2e-based
/// ui-golden too slow on QEMU's software SHA-256.
#[cfg(feature = "ui-golden-render")]
pub fn render_capture_pages(pages: &[Page]) {
    for page in pages {
        render_page(page);
    }
}
