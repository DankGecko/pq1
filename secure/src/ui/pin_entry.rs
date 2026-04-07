//! 2-button 8-digit PIN entry, fully driven from the secure UI so the PIN
//! never touches non-secure RAM.
//!
//! Controls:
//!   * tap right    → digit + 1
//!   * tap left     → digit - 1
//!   * long right   → next position (or submit on the last position)
//!   * long left    → previous position (or cancel on position 0)

use super::{display, input, Button, Press, DISPLAY_COLS};
use crate::timeout;
use sphincs_tz_shared::PIN_LEN;

pub enum PinEntryResult {
    Pin([u8; PIN_LEN]),
    Cancelled,
    IdleWipe,
}

pub fn enter_pin() -> PinEntryResult {
    let mut pin = [0u8; PIN_LEN];
    let mut pos: usize = 0;

    timeout::reset_activity();

    loop {
        render_pin_screen(&pin, pos);

        let mut idle = || timeout::is_idle();
        let event = match input().wait_button(&mut idle) {
            Some(ev) => ev,
            None => {
                // backend signalled idle wipe
                wipe_pin(&mut pin);
                return PinEntryResult::IdleWipe;
            }
        };

        timeout::reset_activity();

        match event {
            (Button::Right, Press::Short) => {
                pin[pos] = (pin[pos] + 1) % 10;
            }
            (Button::Left, Press::Short) => {
                pin[pos] = (pin[pos] + 9) % 10;
            }
            (Button::Right, Press::Long) => {
                if pos + 1 == PIN_LEN {
                    // Convert each digit (0-9) to its ASCII byte ('0'-'9')
                    // before returning, since the secure-element MACD chain
                    // is keyed off the ASCII representation.
                    let mut ascii = [0u8; PIN_LEN];
                    for i in 0..PIN_LEN {
                        ascii[i] = b'0' + pin[i];
                    }
                    wipe_pin(&mut pin);
                    return PinEntryResult::Pin(ascii);
                } else {
                    pos += 1;
                }
            }
            (Button::Left, Press::Long) => {
                if pos == 0 {
                    wipe_pin(&mut pin);
                    return PinEntryResult::Cancelled;
                } else {
                    pos -= 1;
                }
            }
        }
    }
}

fn render_pin_screen(pin: &[u8; PIN_LEN], pos: usize) {
    let d = display();
    d.clear();
    d.draw_line(0, "   Enter PIN");

    // Render the 8 digits, hiding past digits as '*'.
    let mut row1 = [b' '; DISPLAY_COLS];
    // Layout: 8 digits, separated by spaces, centered.
    // Total width: 8*2 - 1 = 15 chars, fits in 16 cols.
    for (i, &d) in pin.iter().enumerate() {
        let col = i * 2;
        if col >= DISPLAY_COLS {
            break;
        }
        row1[col] = if i < pos {
            b'*'
        } else if i == pos {
            // Active position: show the digit.
            b'0' + d
        } else {
            b'_'
        };
    }
    // SAFETY: only ASCII written.
    let s = unsafe { core::str::from_utf8_unchecked(&row1) };
    d.draw_line(1, s);

    // Position indicator under the active digit.
    let mut row2 = [b' '; DISPLAY_COLS];
    let col = pos * 2;
    if col < DISPLAY_COLS {
        row2[col] = b'^';
    }
    let s2 = unsafe { core::str::from_utf8_unchecked(&row2) };
    d.draw_line(2, s2);

    d.draw_line(3, "L=- R=+ LL=back");
    d.flush();
}

fn wipe_pin(pin: &mut [u8; PIN_LEN]) {
    use zeroize::Zeroize;
    pin.zeroize();
}
