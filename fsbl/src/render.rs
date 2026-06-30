//! FSBL firmware-fingerprint NV3007 LCD render.
//!
//! Composes:
//!   * The pure layout function [`sphincs_tz_bip39::firmware_fingerprint_lines`]
//!     (digest → 4 × 16 ASCII grid; host-testable in `bip39/tests/`).
//!   * The minimal NV3007 142×428 SPI LCD driver in [`crate::nv3007`].
//!
//! The hold delay lives here. The pure render-glue lives in `bip39` so the
//! secure-world `measured_boot::run` can re-use the exact same byte grid
//! (visual parity is part of the trust story: FSBL's screen and the slot's
//! advisory screen must show the same words for the same digest; any
//! divergence is a strong tamper signal).

use sphincs_tz_bip39::firmware_fingerprint_lines;

use crate::nv3007::{delay_ms, Lcd};

/// How long the FSBL fingerprint stays on the LCD before branching
/// into the slot. 3 seconds at 16 MHz core clock — long enough for a
/// human to glance + recognise the words; short enough that boot UX
/// stays under 5 s end-to-end.
pub const FINGERPRINT_HOLD_MS: u32 = 3_000;

/// Drive the LCD end-to-end: init, render, flush, delay, return.
///
/// Safe to call exactly once during FSBL boot, immediately before
/// `branch::into_slot`. The NV3007 is a write-only SPI panel, so there is no
/// presence probe — the FSBL only ever builds for real `thumbv8m` silicon
/// (no QEMU FSBL path), where the panel is always wired.
pub fn render_fingerprint(digest: &[u8; 32]) {
    let mut lcd = Lcd::new();
    lcd.init();
    lcd.clear();

    let rows = firmware_fingerprint_lines(digest);
    for (i, row) in rows.iter().enumerate() {
        lcd.draw_text(i, row);
    }
    lcd.flush();

    // Hold ~3 s so the user can read the words. No button-wait — FSBL
    // doesn't init GPIO buttons; a power-cycle is the abort path.
    delay_ms(FINGERPRINT_HOLD_MS);
}
