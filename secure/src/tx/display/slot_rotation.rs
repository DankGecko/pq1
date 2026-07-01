//! Standalone "ROTATE SLOT?" confirm page for `FLAG_REGISTER_SLOT`.
//!
//! When the companion sets `FLAG_REGISTER_SLOT`, the firmware emits a
//! Type 1 (`addOwnerBytes`) UserOp alongside the user's Type 2. That
//! Type 1 silently consumes one of the wallet's `MAX_BOOTSTRAP_USES`
//! bootstrap budget items on chain — so a hostile companion that always
//! sets the flag can drain the bootstrap reserve at twice the rate the
//! user thinks they're authorising.
//!
//! Closing the gap is a UI affair, not an invariant break: every Type 1
//! is already verified by the bootstrap C10 sig and bumps `bootstrapUses`
//! through the on-chain monotonic cap. We just need the trusted display
//! to surface the rotation as its own affirmative-consent step before
//! the inner-tx render runs.

use super::Pages;
use crate::ui::DISPLAY_COLS;

/// Build the one-page "ROTATE SLOT?" confirm shown before the inner-tx
/// confirm whenever `FLAG_REGISTER_SLOT` is set.
///
/// Layout (16 cols × 4 rows):
///
/// ```text
///   row 0:                    (blank)
///   row 1:    ROTATE SLOT?
///   row 2:    New slot: N
///   row 3:    +bootstrap use
/// ```
///
/// `slot_index` is the firmware-side index supplied in the FLAG word
/// (always `>= 1` here — the handler refuses `register_slot && slot_index
/// == 0` upstream). Its on-chain `ownerIndex` is `slot_index + 1`, but
/// the firmware/UI/flash all key on the firmware-side index, so we keep
/// the displayed number aligned with that convention.
pub fn build_slot_rotation_pages(slot_index: u32) -> Pages {
    let mut out = Pages::empty_with_len(1);

    out.row_mut(0, 0).copy_from_slice(&[b' '; DISPLAY_COLS]);
    write_centered(out.row_mut(0, 1), b"ROTATE SLOT?");
    let mut buf = [b' '; DISPLAY_COLS];
    write_new_slot(&mut buf, slot_index);
    out.row_mut(0, 2).copy_from_slice(&buf);
    write_centered(out.row_mut(0, 3), b"+bootstrap use");

    out
}

fn write_centered(row: &mut [u8; DISPLAY_COLS], text: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let len = core::cmp::min(text.len(), DISPLAY_COLS);
    let start = (DISPLAY_COLS - len) / 2;
    row[start..start + len].copy_from_slice(&text[..len]);
}

fn write_new_slot(row: &mut [u8; DISPLAY_COLS], slot_index: u32) {
    // `slot_index` is the raw 22-bit FLAG-word field (0..=4_194_303); the
    // sign handlers only reject `register_slot && slot_index == 0`, so any
    // other value — including a buggy or hostile companion's 7-digit
    // garbage — reaches here. Every write below is bounded to the 16-col
    // row so no `slot_index` can index past `buf`/`row` and panic the
    // secure world mid-render (a panic here would abort the sign and hang
    // the device until a power cycle). Values that don't fit after the
    // prefix are truncated on the display only — the on-chain Type-1 sig,
    // not this advisory page, binds the real index.
    let mut buf = [b' '; DISPLAY_COLS];
    let prefix = b"New slot: ";
    let mut p = 0usize;
    for &c in prefix.iter() {
        if p >= DISPLAY_COLS {
            break;
        }
        buf[p] = c;
        p += 1;
    }
    p += write_dec(&mut buf, p, slot_index as usize);
    // `write_dec` never writes past `DISPLAY_COLS`, so `p <= DISPLAY_COLS`
    // and the centering math below cannot underflow or overrun.
    let len = core::cmp::min(p, DISPLAY_COLS);
    *row = [b' '; DISPLAY_COLS];
    let start = (DISPLAY_COLS - len) / 2;
    row[start..start + len].copy_from_slice(&buf[..len]);
}

/// Write `value` as decimal digits into `buf` starting at `pos`, stopping
/// at the row edge. Returns the number of digits actually written (which
/// may be fewer than `value` has, if it would overflow the row). Never
/// indexes past `buf.len()`.
fn write_dec(buf: &mut [u8; DISPLAY_COLS], pos: usize, value: usize) -> usize {
    if value == 0 {
        if pos < DISPLAY_COLS {
            buf[pos] = b'0';
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
    let mut written = 0usize;
    for i in 0..n {
        if pos + i >= DISPLAY_COLS {
            break;
        }
        buf[pos + i] = tmp[n - 1 - i];
        written += 1;
    }
    written
}
