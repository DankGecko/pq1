//! Real OLED + GPIO button backend for STM32U585 + SSD1306 + 2 buttons.
//!
//! This file is intentionally minimal until the hardware arrives. The
//! `Display` and `Input` types are wired up against the `ssd1306`,
//! `embedded-graphics`, and `embedded-hal` crates so the structure compiles
//! once those deps are pulled in. The actual peripheral instantiation
//! (I2C handle, GPIO input pins) is filled in by `secure/src/hw/stm32u585.rs`
//! after the board arrives, and the `Display::new()` / `Input::new()`
//! signatures will gain peripheral parameters at that point.
//!
//! Today, building with `--features ui-oled` requires linking against an
//! HAL implementation, so it will fail until the embassy-stm32 wiring is
//! in place. That is intentional: it gives a clear "not-yet-supported"
//! error rather than silently misbehaving.

#![cfg(feature = "ui-oled")]

use super::{Button, Press, DISPLAY_COLS, DISPLAY_ROWS};

// NOTE: these `pub use` lines are placeholders. Once embassy-stm32 is wired
// in, replace the unit-struct fields below with concrete `embassy_stm32::i2c::I2c`
// and `embassy_stm32::gpio::Input` types.

pub struct Display {
    rows: [[u8; DISPLAY_COLS]; DISPLAY_ROWS],
}

impl Display {
    pub const fn new() -> Self {
        Self {
            rows: [[b' '; DISPLAY_COLS]; DISPLAY_ROWS],
        }
    }

    pub fn init(&mut self) {
        // TODO(hw): initialize SSD1306 over I2C
        //   let interface = I2CDisplayInterface::new(i2c);
        //   let mut display = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate0)
        //       .into_buffered_graphics_mode();
        //   display.init().unwrap();
    }

    pub fn clear(&mut self) {
        for row in &mut self.rows {
            *row = [b' '; DISPLAY_COLS];
        }
    }

    pub fn draw_line(&mut self, row: usize, text: &str) {
        if row >= DISPLAY_ROWS {
            return;
        }
        let bytes = text.as_bytes();
        let mut col = 0;
        for &b in bytes {
            if col >= DISPLAY_COLS {
                break;
            }
            self.rows[row][col] = if (0x20..=0x7e).contains(&b) { b } else { b'?' };
            col += 1;
        }
        for c in col..DISPLAY_COLS {
            self.rows[row][c] = b' ';
        }
    }

    pub fn flush(&mut self) {
        // TODO(hw): clear framebuffer; draw each row with FONT_8X16; display.flush()
        //   for (i, row) in self.rows.iter().enumerate() {
        //       Text::with_baseline(text, Point::new(0, (i*16) as i32),
        //           MonoTextStyle::new(&FONT_8X16, BinaryColor::On), Baseline::Top)
        //           .draw(&mut display)?;
        //   }
        //   display.flush()?;
    }
}

pub struct Input;

impl Input {
    pub const fn new() -> Self {
        Self
    }

    pub fn init(&mut self) {
        // TODO(hw): configure GPIO inputs with pull-ups
    }

    /// Poll both GPIOs in a tight loop, debounce ~20 ms, measure press
    /// duration; >500 ms = Long. Calls `idle_check()` every iteration so the
    /// inactivity timer can wipe sensitive state and abort.
    pub fn wait_button(&mut self, idle_check: &mut dyn FnMut() -> bool) -> Option<(Button, Press)> {
        // TODO(hw): real GPIO poll loop
        //   loop {
        //       if idle_check() { return None; }
        //       let l = self.left.is_low(); let r = self.right.is_low();
        //       if l || r {
        //           let start = timeout::now();
        //           while self.left.is_low() == l && self.right.is_low() == r {
        //               if idle_check() { return None; }
        //               cortex_m::asm::nop();
        //           }
        //           let dur = timeout::now() - start;
        //           let press = if dur > 500 { Press::Long } else { Press::Short };
        //           let btn = if l { Button::Left } else { Button::Right };
        //           return Some((btn, press));
        //       }
        //       cortex_m::asm::wfe();
        //   }
        let _ = (idle_check, DISPLAY_ROWS, DISPLAY_COLS);
        compile_error!(
            "ui-oled backend stub: fill in secure/src/ui/oled.rs and secure/src/hw/stm32u585.rs after board arrives"
        );
    }
}
