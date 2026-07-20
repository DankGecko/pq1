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
    confirm_checked(pages).0
}

/// FI-hardened variant of [`confirm`]: returns the [`ConfirmResult`] together
/// with a Hamming-distant sentinel that is [`crate::fi::OK_SENTINEL`] ONLY when
/// the result is an affirmative `Confirmed` produced at the accept branch
/// (long-right after the scroll-to-end gate). Every other return path — cancel,
/// idle-wipe, empty-pages — yields a value that is NOT `OK_SENTINEL`.
///
/// Sign paths MUST gate signing on `sentinel == crate::fi::OK_SENTINEL` and fail
/// closed otherwise. The verdict and the sentinel are two independent words both
/// set at the decision point, so a single instruction-skip of a reject-arm
/// `return` (which leaves the verdict non-`Confirmed`) is caught by the sentinel
/// reading `FAIL_SENTINEL`, and a single value-fault flipping the verdict to
/// `Confirmed` in transit is caught by the sentinel still reading
/// `FAIL_SENTINEL` — forging a signature past the confirm gate needs two
/// consistent faults. (Closes trusted-UI finding UI1 / work-todo #12c.)
pub fn confirm_checked(pages: &[Page]) -> (ConfirmResult, u32) {
    if pages.is_empty() {
        return (ConfirmResult::Cancelled, crate::fi::FAIL_SENTINEL);
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
        return (ConfirmResult::Confirmed, crate::fi::OK_SENTINEL);
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
        //
        // F14/SCAFI-2: the gate variable is a `FihBool` (complement-pair
        // storage + double-read), NOT a bare stack bool — a single
        // stuck-at/bit-flip on a plain `seen_last: bool` made every read
        // (the gate AND the sentinel closure) read `true`, authorising
        // signing without ever reaching the final page.
        let mut seen_last = crate::fih::FihBool::new_false();
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
                seen_last.set_true();
            }

            let mut idle = || timeout::is_idle();
            // Tell the watchdog exactly when this live handler is waiting on
            // trusted physical input. The guard is deliberately scoped to
            // `wait_button`: display rendering and all work after the event
            // retain the ordinary noninteractive busy-handler deadline. This
            // marker does NOT reset the inactivity timer, so an unattended
            // companion-triggered prompt still returns IdleWipe after 120 s.
            let event = match {
                let _trusted_ui_wait = timeout::TrustedUiWaitGuard::enter();
                input().wait_button(&mut idle)
            } {
                Some(ev) => ev,
                None => return (ConfirmResult::IdleWipe, crate::fi::FAIL_SENTINEL),
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
                    // F14/SCAFI-2: the gate compares the Hamming-distant
                    // sentinel born from the FihBool (`check_sentinel` =
                    // `check_true_into_sentinel(is_true_fi)`), never a bare
                    // bool branch. A garbage/stuck register reads ≠
                    // OK_SENTINEL and falls through to "advance one page"
                    // (fail-closed).
                    let gate = seen_last.check_sentinel();
                    if gate == crate::fi::OK_SENTINEL {
                        // Affirmative accept. Born the sentinel HERE, at the
                        // decision point, from `seen_last` (the scroll-to-end
                        // gate) — NOT recomputed from the returned enum, which a
                        // value-fault could forge. The `Confirmed` verdict and
                        // the sign-gate sentinel are two independent words set
                        // at the same instruction.
                        return (ConfirmResult::Confirmed, gate);
                    }
                    // Not yet scrolled to the end — treat the long-press as
                    // "next page" so the user is guided through the remaining
                    // (possibly drain-bearing) pages before they can sign.
                    if idx + 1 < pages.len() {
                        idx += 1;
                    }
                }
                (Button::Left, Press::Long) => {
                    return (ConfirmResult::Cancelled, crate::fi::FAIL_SENTINEL)
                }
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
