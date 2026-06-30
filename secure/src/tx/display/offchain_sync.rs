//! Standalone "SYNC COUNTER?" confirm pages for `CMD_OFFCHAIN_SYNC`.
//!
//! `CMD_OFFCHAIN_SYNC` lets the (untrusted) companion set a durable floor on a
//! slot's `last_userop_count` so a firmware that was reflashed can re-learn the
//! on-chain off-chain-sig floor and stop emitting non-monotonic counts. The
//! value it sets is harmless on its own — the on-chain combined-cap check still
//! bounds the budget — but the *durable write itself* creates a fresh page-123
//! journal entry for a **companion-chosen, seed-independent**
//! `(account_index, chain_id, slot_index)` tuple. With no consent gate a hostile
//! companion can spray distinct tuples to fill the page and wedge compaction
//! into a permanent, seed-survivable signing brick
//! (`docs/VULN-offchain-sync-page123-exhaustion-brick.md`).
//!
//! This is the trusted-display affirmative-consent step the handler shows
//! before writing an entry for a slot it has **not** seen before — exactly the
//! `cmd_sign_offchain` MEDIUM-3 "defer the durable write until after confirm"
//! discipline, and the structural sibling of the `FLAG_REGISTER_SLOT`
//! [`super::build_slot_rotation_pages`] gate. Re-syncs of an already-registered
//! slot are idempotent floor bumps and stay confirm-free.

use super::primitives::{chain_name, write_chain};
use super::Pages;
use crate::ui::DISPLAY_COLS;

/// Build the 2-page "SYNC COUNTER?" confirm shown before a new-slot
/// `CMD_OFFCHAIN_SYNC` durable write.
///
/// Layout (16 cols × 4 rows):
///
/// ```text
///   page 0:                          page 1:
///     row 0:   (blank)                 row 0:  Chain: <id>
///     row 1:  SYNC COUNTER?            row 1:  (chain name)
///     row 2:  Off-chain floor          row 2:  Account: <n>
///     row 3:   (blank)                 row 3:  Slot: <n>
/// ```
///
/// Two pages so the `confirm()` scroll-to-end (`seen_last`) gate is meaningful:
/// the user must page to the parameters before a long-press can confirm.
#[must_use]
pub fn build_offchain_sync_pages(account_index: u8, chain_id: u64, slot_index: u32) -> Pages {
    let mut out = Pages::empty_with_len(2);

    // Page 0 — banner + intent. Rows 0/3 stay blank (pre-filled with spaces).
    write_centered(out.row_mut(0, 1), b"SYNC COUNTER?");
    write_centered(out.row_mut(0, 2), b"Off-chain floor");

    // Page 1 — the exact parameters being authorised. `write_chain` formats the
    // full u64 chain id (or "!OVF" — it never silently truncates); `chain_name`
    // labels known networks and renders "(UNVERIFIED)" otherwise.
    write_chain(out.row_mut(1, 0), chain_id);
    write_centered(out.row_mut(1, 1), chain_name(chain_id).as_bytes());
    write_label_dec(out.row_mut(1, 2), b"Account: ", account_index as usize);
    write_label_dec(out.row_mut(1, 3), b"Slot: ", slot_index as usize);

    out
}

fn write_centered(row: &mut [u8; DISPLAY_COLS], text: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let len = core::cmp::min(text.len(), DISPLAY_COLS);
    let start = (DISPLAY_COLS - len) / 2;
    row[start..start + len].copy_from_slice(&text[..len]);
}

/// Left-aligned `"<label><decimal>"`. `account_index` (0..=255, ≤3 digits) and
/// `slot_index` (u32, ≤10 digits) are type-bounded so a 6-char label + the
/// number always fits the 16-col row; the bounds guard in `write_dec` keeps it
/// panic-free for any input regardless.
fn write_label_dec(row: &mut [u8; DISPLAY_COLS], label: &[u8], value: usize) {
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

fn write_dec(row: &mut [u8; DISPLAY_COLS], pos: usize, value: usize) -> usize {
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
