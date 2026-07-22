//! Multi-page transaction confirmation dialog.
//!
//! The pages are pre-rendered by `tx::display::render_pages` from a parsed
//! `Eip1559Tx`. This module just handles the navigation:
//!
//!   * tap right    → next page
//!   * tap left     → previous page
//!   * long right   → confirm
//!   * long left    → cancel

#[cfg(not(feature = "e2e-test"))]
use super::confirm_core::{NavigationCore, NavigationDecision, NavigationInput};
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

/// Result of the forced confirmation variant.  Deadline expiry is distinct
/// from the existing inactivity wipe: real button activity resets only the
/// latter and never extends the forced absolute deadline.
#[cfg(feature = "erc7730-forced-blind")]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum ForcedConfirmResult {
    Confirmed,
    Cancelled,
    IdleWipe,
    DeadlineExpired,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum ConfirmLoopResult {
    Confirmed,
    Cancelled,
    IdleWipe,
    DeadlineExpired,
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
    let mut deadline_never_expires = || false;
    let (result, sentinel) = confirm_checked_inner(pages, &mut deadline_never_expires);
    let ordinary = match result {
        ConfirmLoopResult::Confirmed => ConfirmResult::Confirmed,
        ConfirmLoopResult::Cancelled | ConfirmLoopResult::DeadlineExpired => {
            ConfirmResult::Cancelled
        }
        ConfirmLoopResult::IdleWipe => ConfirmResult::IdleWipe,
    };
    (ordinary, sentinel)
}

/// Forced-flow confirmation with one absolute, caller-supplied deadline.
///
/// The predicate is sampled at every navigation iteration, inside the
/// `wait_button` predicate (which the GPIO backend carries through release
/// waits), and immediately before returning an affirmative receipt input.
/// It is never reset by button activity.  The ordinary S-world inactivity
/// timer remains a separate predicate and still wipes an idle session first.
#[cfg(feature = "erc7730-forced-blind")]
pub(crate) fn confirm_forced_checked(
    pages: &[Page],
    deadline_expired: &mut dyn FnMut() -> bool,
) -> (ForcedConfirmResult, u32) {
    let (result, sentinel) = confirm_checked_inner(pages, deadline_expired);
    let forced = match result {
        ConfirmLoopResult::Confirmed => ForcedConfirmResult::Confirmed,
        ConfirmLoopResult::Cancelled => ForcedConfirmResult::Cancelled,
        ConfirmLoopResult::IdleWipe => ForcedConfirmResult::IdleWipe,
        ConfirmLoopResult::DeadlineExpired => ForcedConfirmResult::DeadlineExpired,
    };
    (forced, sentinel)
}

fn confirm_checked_inner(
    pages: &[Page],
    deadline_expired: &mut dyn FnMut() -> bool,
) -> (ConfirmLoopResult, u32) {
    if pages.is_empty() {
        return (ConfirmLoopResult::Cancelled, crate::fi::FAIL_SENTINEL);
    }
    if deadline_expired() {
        return (ConfirmLoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
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
        for (idx, page) in pages.iter().enumerate() {
            if deadline_expired() {
                return (ConfirmLoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
            }
            render_page(page, idx, pages.len());
        }
        if deadline_expired() {
            return (ConfirmLoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
        }
        return (ConfirmLoopResult::Confirmed, crate::fi::OK_SENTINEL);
    }

    #[cfg(not(feature = "e2e-test"))]
    {
        let Some(mut navigation) = NavigationCore::new(pages.len()) else {
            return (ConfirmLoopResult::Cancelled, crate::fi::FAIL_SENTINEL);
        };
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
        // `NavigationCore` owns the FI-hardened `seen_last` state. Both the
        // ordinary and forced variants therefore execute the same ordering and
        // affirmative-sentinel logic.
        // HIGH-13 fix: do NOT reset the inactivity timer on entry.
        // NS can spam SIGN_USEROP / request-unlock calls; each call
        // lands us here and the old code reset the timer before the
        // user had touched a button. That kept the unlocked window
        // open indefinitely as long as NS kept asking — the exact
        // thing CLAUDE.md forbids ("NS pings do not reset [the
        // inactivity timer]. Only real button presses on S-world
        // confirm dialogs count as activity.").

        loop {
            if deadline_expired() {
                return (ConfirmLoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
            }
            let idx = navigation.page_index();
            render_page(&pages[idx], idx, pages.len());
            // Sticky: once the final page has been displayed, confirm is
            // unlocked from any page. Reaching the last page requires
            // short-right past every intermediate page (short-right advances
            // one page at a time and is capped at the end), so the whole set
            // has been shown before this flips true.
            navigation.mark_current_page_rendered();

            if deadline_expired() {
                return (ConfirmLoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
            }

            let mut wait_abort = || timeout::is_idle() || deadline_expired();
            // Tell the watchdog exactly when this live handler is waiting on
            // trusted physical input. The guard is deliberately scoped to
            // `wait_button`: display rendering and all work after the event
            // retain the ordinary noninteractive busy-handler deadline. This
            // marker does NOT reset the inactivity timer, so an unattended
            // companion-triggered prompt still returns IdleWipe after 120 s.
            let event = match {
                let _trusted_ui_wait = timeout::TrustedUiWaitGuard::enter();
                input().wait_button(&mut wait_abort)
            } {
                Some(ev) => ev,
                None => {
                    if deadline_expired() {
                        return (ConfirmLoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
                    }
                    return (ConfirmLoopResult::IdleWipe, crate::fi::FAIL_SENTINEL);
                }
            };

            if deadline_expired() {
                return (ConfirmLoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
            }

            // A button event IS real user activity — reset the timer
            // here and only here. This is the trusted-display contract.
            timeout::reset_activity();

            let nav_input = match event {
                (Button::Left, Press::Short) => NavigationInput::LeftShort,
                (Button::Right, Press::Short) => NavigationInput::RightShort,
                (Button::Left, Press::Long) => NavigationInput::LeftLong,
                (Button::Right, Press::Long) => NavigationInput::RightLong,
            };
            match navigation.handle(nav_input) {
                NavigationDecision::Continue => {}
                NavigationDecision::Cancelled => {
                    return (ConfirmLoopResult::Cancelled, crate::fi::FAIL_SENTINEL);
                }
                NavigationDecision::Confirmed(gate) => {
                    // A final fresh deadline sample immediately precedes the
                    // affirmative result consumed by the receipt publisher.
                    if deadline_expired() {
                        return (ConfirmLoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
                    }
                    return (ConfirmLoopResult::Confirmed, gate);
                }
            }
        }
    }
}

fn render_page(page: &Page, idx: usize, total: usize) {
    let d = display();
    d.clear();
    for (row_idx, row) in page.iter().enumerate() {
        if row_idx == DISPLAY_ROWS - 1 {
            // Page-position indicator (#488 / TZP-17): overlay ` i/n` on
            // the footer row at DRAW time. The pre-rendered page buffers
            // are never mutated — work on a stack copy so the confirm
            // transcript and every FI page-content proof keep comparing
            // the renderer's exact bytes.
            let mut footer = *row;
            overlay_page_position(&mut footer, idx, total);
            d.draw_line(row_idx, super::ascii_str(&footer));
        } else {
            d.draw_line(row_idx, super::ascii_str(row));
        }
    }
    d.flush();
}

/// Right-align a ` i/n` page-position indicator (e.g. ` 3/9`) onto a
/// footer-row copy. Deterministic fit rule: let `used` be the row's
/// length trimmed of trailing spaces and `ind` the formatted indicator
/// (leading space + (idx+1) + '/' + total); the overlay is drawn only
/// when `used + ind.len() <= DISPLAY_COLS`, otherwise the row is shown
/// unchanged. Right-aligned means the indicator ends at the last column.
fn overlay_page_position(row: &mut [u8; DISPLAY_COLS], idx: usize, total: usize) {
    let mut ind = [b' '; DISPLAY_COLS];
    let Some(ind_len) = format_page_indicator(idx, total, &mut ind) else {
        return;
    };
    let used = row.iter().rposition(|&c| c != b' ').map_or(0, |p| p + 1);
    if used + ind_len > DISPLAY_COLS {
        return;
    }
    row[DISPLAY_COLS - ind_len..].copy_from_slice(&ind[..ind_len]);
}

/// Format ` i/n` (leading space, 1-based page number) into `out`,
/// returning the indicator length. Returns `None` when the digits do not
/// fit `out` — the caller then draws the footer unchanged (same fail-quiet
/// behaviour as the width rule).
fn format_page_indicator(idx: usize, total: usize, out: &mut [u8]) -> Option<usize> {
    use pqsigner_erc7730::display::primitives::format_u64;
    out[0] = b' ';
    let n1 = format_u64(idx as u64 + 1, out.get_mut(1..)?)?;
    let slash = 1 + n1;
    *out.get_mut(slash)? = b'/';
    let n2 = format_u64(total as u64, out.get_mut(slash + 1..)?)?;
    Some(slash + 1 + n2)
}

/// Render a sequence of pre-rendered pages WITHOUT waiting for input — each is
/// drawn + flushed (which, under `ui-capture`, emits a `[UI-FP]` fingerprint).
/// The render-only golden harness ([`crate::ui::golden`]) uses this to capture
/// screens directly, skipping the C10 keygen/sign that makes the e2e-based
/// ui-golden too slow on QEMU's software SHA-256.
#[cfg(feature = "ui-golden-render")]
pub fn render_capture_pages(pages: &[Page]) {
    for (idx, page) in pages.iter().enumerate() {
        render_page(page, idx, pages.len());
    }
}
