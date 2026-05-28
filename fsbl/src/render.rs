//! FSBL firmware-fingerprint OLED render.
//!
//! Composes:
//!   * The pure layout function [`sphincs_tz_bip39::firmware_fingerprint_lines`]
//!     (digest → 4 × 16 ASCII grid; host-testable in `bip39/tests/`).
//!   * The minimal SSD1306 + I2C1 driver in [`crate::oled`].
//!
//! The hold delay + I2C probe + no-OLED graceful fallback live here.
//! The pure render-glue lives in `bip39` so the secure-world
//! `measured_boot::run` can re-use the exact same byte grid (visual
//! parity is part of the trust story: FSBL's screen and the slot's
//! advisory screen must show the same words for the same digest;
//! any divergence is a strong tamper signal).

use sphincs_tz_bip39::firmware_fingerprint_lines;

use crate::oled::{delay_ms, Oled};

/// How long the FSBL fingerprint stays on the OLED before branching
/// into the slot. 3 seconds at 16 MHz core clock — long enough for a
/// human to glance + recognise the words; short enough that boot UX
/// stays under 5 s end-to-end.
pub const FINGERPRINT_HOLD_MS: u32 = 3_000;

/// Drive the OLED end-to-end: init, render, flush, delay, return.
///
/// Safe to call exactly once during FSBL boot, immediately before
/// `branch::into_slot`. On a board without an OLED the function still
/// returns cleanly (the I2C probe fails, `Oled::is_present` stays
/// false, rendering becomes a no-op). Regression-locked by
/// `fsbl/tests/no_oled_fallback.rs`.
pub fn render_fingerprint(digest: &[u8; 32]) {
    let mut oled = Oled::new();
    oled.init();
    oled.clear();

    let rows = firmware_fingerprint_lines(digest);
    for (i, row) in rows.iter().enumerate() {
        oled.draw_text(i, row);
    }
    oled.flush();

    // Hold ~3 s so the user can read the words. No button-wait — FSBL
    // doesn't init GPIO buttons; a power-cycle is the abort path.
    delay_ms(FINGERPRINT_HOLD_MS);
}
