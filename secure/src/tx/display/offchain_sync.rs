//! Standalone "SYNC COUNTER?" confirm pages for `CMD_OFFCHAIN_SYNC`.
//!
//! `CMD_OFFCHAIN_SYNC` lets the (untrusted) companion set a durable floor on a
//! slot's `last_userop_count` so a firmware that was reflashed can re-learn the
//! on-chain off-chain-sig floor and stop emitting non-monotonic counts. The
//! value is security-relevant: it is folded into the firmware's combined
//! few-time-key budget on the next sign. The *durable write itself* also creates a fresh page-123
//! journal entry for a **companion-chosen, seed-independent**
//! `(account_index, chain_id, slot_index)` tuple. With no consent gate a hostile
//! companion can spray distinct tuples to fill the page and wedge compaction
//! into a permanent, seed-survivable signing brick
//! (`docs/security/vulns/VULN-offchain-sync-page123-exhaustion-brick.md`).
//!
//! This is the trusted-display affirmative-consent step the handler shows
//! before writing an entry for a slot it has **not** seen before, or before
//! raising an existing slot's floor — exactly the `cmd_sign_offchain` MEDIUM-3
//! "defer the durable write until after confirm" discipline. The final page
//! binds that consent to the exact current and requested counts; omitting those
//! values would let a hostile companion turn a plausible "sync" prompt into an
//! undisclosed near-exhaustion request.

use super::primitives::{chain_name, write_chain};
use super::Pages;
use crate::ui::DISPLAY_COLS;

/// Build the 3-page "SYNC COUNTER?" confirmation shown before a new-slot or
/// floor-raising `CMD_OFFCHAIN_SYNC` durable write.
///
/// Layout (16 cols × 4 rows):
///
/// ```text
///   page 0:               page 1:               page 2:
///     (blank)               Chain: <id>           Current: <n>
///     SYNC COUNTER?         (chain name)           L=Cancel
///     Off-chain floor       Account: <n>           Target: <n>
///     (blank)               Slot: <n>              R=Confirm
/// ```
///
/// Counts are runtime-bounded by the handler to `0..=MAX_SLOT_USES-1`, so the
/// decimal representation (at most five digits for the current C10 policy) is
/// exact and cannot be truncated by the 16-column rows.
#[must_use]
pub fn build_offchain_sync_pages(
    account_index: u8,
    chain_id: u64,
    slot_index: u32,
    current_count: u64,
    target_count: u64,
) -> Pages {
    let mut out = Pages::empty_with_len(3);

    // Page 0 — banner + intent. Rows 0/3 stay blank (pre-filled with spaces).
    write_centered(out.row_mut(0, 1), b"SYNC COUNTER?");
    write_centered(out.row_mut(0, 2), b"Off-chain floor");

    // Page 1 — the exact parameters being authorised. `write_chain` formats the
    // full u64 chain id (or "!OVF" — it never silently truncates); `chain_name`
    // labels known networks and renders "(UNVERIFIED)" otherwise.
    write_chain(out.row_mut(1, 0), chain_id);
    write_centered(out.row_mut(1, 1), chain_name(chain_id).as_bytes());
    write_label_dec(out.row_mut(1, 2), b"Account: ", u64::from(account_index));
    write_label_dec(out.row_mut(1, 3), b"Slot: ", u64::from(slot_index));

    // Page 2 — the exact state transition being authorised. The handler passes
    // the post-clamp target it will write, not the raw untrusted wire value.
    write_label_dec(out.row_mut(2, 0), b"Current: ", current_count);
    write_centered(out.row_mut(2, 1), b"L=Cancel");
    write_label_dec(out.row_mut(2, 2), b"Target: ", target_count);
    write_centered(out.row_mut(2, 3), b"R=Confirm");

    out
}

fn write_centered(row: &mut [u8; DISPLAY_COLS], text: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let len = core::cmp::min(text.len(), DISPLAY_COLS);
    let start = (DISPLAY_COLS - len) / 2;
    row[start..start + len].copy_from_slice(&text[..len]);
}

/// Left-aligned `"<label><decimal>"`. Callers runtime-bound values that carry
/// security meaning so their complete decimal form fits; the writer itself
/// remains bounds-safe for every `u64`.
fn write_label_dec(row: &mut [u8; DISPLAY_COLS], label: &[u8], value: u64) {
    *row = [b' '; DISPLAY_COLS];
    let mut p = 0usize;
    for &c in label.iter() {
        if p >= DISPLAY_COLS {
            break;
        }
        row[p] = c;
        p += 1;
    }
    write_dec(row, p, value);
}

fn write_dec(row: &mut [u8; DISPLAY_COLS], pos: usize, value: u64) -> usize {
    if value == 0 {
        if pos < DISPLAY_COLS {
            row[pos] = b'0';
            return 1;
        }
        return 0;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0;
    let mut v = value;
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let mut written = 0;
    for i in 0..n {
        let p = pos + i;
        if p >= DISPLAY_COLS {
            break;
        }
        row[p] = tmp[n - 1 - i];
        written += 1;
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row_text(row: &[u8; DISPLAY_COLS]) -> &str {
        core::str::from_utf8(row).expect("renderer emits ASCII")
    }

    #[test]
    fn sync_pages_bind_exact_current_and_target_counts() {
        let pages = build_offchain_sync_pages(7, 1, 42, 9, 65_535);
        assert_eq!(pages.len, 3);
        assert_eq!(row_text(&pages.buf[2][0]), "Current: 9      ");
        assert_eq!(row_text(&pages.buf[2][2]), "Target: 65535   ");
        assert_eq!(row_text(&pages.buf[2][1]), "    L=Cancel    ");
        assert_eq!(row_text(&pages.buf[2][3]), "   R=Confirm    ");
    }

    #[test]
    fn changing_either_count_changes_trusted_pixels() {
        let a = build_offchain_sync_pages(0, 1, 0, 10, 11);
        let b = build_offchain_sync_pages(0, 1, 0, 12, 11);
        let c = build_offchain_sync_pages(0, 1, 0, 10, 13);
        assert_ne!(a.buf[2], b.buf[2], "current count must be display-bound");
        assert_ne!(a.buf[2], c.buf[2], "target count must be display-bound");
    }
}
