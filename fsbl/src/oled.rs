//! Minimal SSD1306 128×32 OLED driver for the FSBL fingerprint render.
//!
//! Ports the I2C1 + SSD1306 setup from `secure/src/hw/i2c.rs` +
//! `secure/src/ui/oled.rs` but drops every dependency the FSBL doesn't
//! need: no `embedded-graphics`, no `MonoFont`, no semihosting logs, no
//! shared `hw::mmio` typed wrappers. Raw `read_volatile` / `write_volatile`
//! against the secure-alias MMIO addresses, a 512-byte framebuffer, and a
//! tiny glyph-blit text renderer that consumes the 5×8 font in
//! [`crate::glyphs`].
//!
//! Display geometry: 4 rows × 16 columns at 5×8 px per glyph (with 3 px
//! of intra-row padding to fill the 128-wide display). Matches the
//! `DISPLAY_COLS=16, DISPLAY_ROWS=4` grid in `secure/src/ui/mod.rs:51`.
//!
//! All I2C / RCC / GPIO addresses are STM32U585 secure-alias values.
//! On QEMU the driver is a no-op (no I2C peripheral) — the `init`
//! probe returns false and rendering falls through silently, which is
//! the same graceful-no-OLED degradation the FSBL would see on a board
//! without a daughterboard.

use core::ptr::{read_volatile, write_volatile};

use crate::glyphs::{glyph_col, FONT_GLYPH_W};

// ---------------------------------------------------------------------------
// MMIO addresses (STM32U585 secure aliases — TZEN=1 makes APB1 secure)
// ---------------------------------------------------------------------------

const RCC_S: usize = 0x5602_0C00;
const GPIOB_S: usize = 0x5202_0400;
const I2C1: usize = 0x5000_5400;

// RCC offsets
const RCC_AHB2ENR1: usize = RCC_S + 0x8C;
const RCC_APB1ENR1: usize = RCC_S + 0x9C;
const RCC_APB1RSTR1: usize = RCC_S + 0x74;

// GPIOB offsets
const GPIOB_MODER: usize = GPIOB_S + 0x00;
const GPIOB_OTYPER: usize = GPIOB_S + 0x04;
const GPIOB_OSPEEDR: usize = GPIOB_S + 0x08;
const GPIOB_PUPDR: usize = GPIOB_S + 0x0C;
const GPIOB_AFRH: usize = GPIOB_S + 0x24;

// I2C1 offsets
const I2C_CR1: usize = I2C1 + 0x00;
const I2C_CR2: usize = I2C1 + 0x04;
const I2C_TIMINGR: usize = I2C1 + 0x10;
const I2C_ISR: usize = I2C1 + 0x18;
const I2C_ICR: usize = I2C1 + 0x1C;
const I2C_TXDR: usize = I2C1 + 0x28;

// ISR bits
const TXIS: u32 = 1 << 1;
const NACKF: u32 = 1 << 4;
const STOPF: u32 = 1 << 5;
const TCR: u32 = 1 << 7;
const BERR: u32 = 1 << 8;
const ARLO: u32 = 1 << 9;
const BUSY: u32 = 1 << 15;

const TIMEOUT: u32 = 10_000_000;

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

#[inline(always)]
fn rd(addr: usize) -> u32 {
    // SAFETY: `addr` is one of the constants above (all valid secure-alias
    // MMIO addresses owned by RCC / GPIOB / I2C1). Reads have no side
    // effects beyond clearing read-to-clear bits on certain status
    // registers (ISR), which is the intended semantics.
    unsafe { read_volatile(addr as *const u32) }
}

#[inline(always)]
fn wr(addr: usize, v: u32) {
    // SAFETY: same as `rd`. Writes go to disjoint bit fields between this
    // driver and (nothing else, since FSBL runs single-threaded with no
    // other drivers initialised). On the shared RCC/GPIOB registers
    // we use RMW to preserve other peripherals' bits, except for I2C1
    // CR1/CR2/TIMINGR/ICR/TXDR which are exclusively ours.
    unsafe { write_volatile(addr as *mut u32, v) }
}

#[inline(always)]
fn set_bits(addr: usize, bits: u32) {
    wr(addr, rd(addr) | bits);
}

#[inline(always)]
fn clear_bits(addr: usize, bits: u32) {
    wr(addr, rd(addr) & !bits);
}

#[inline(always)]
fn modify(addr: usize, f: impl FnOnce(u32) -> u32) {
    wr(addr, f(rd(addr)));
}

// ---------------------------------------------------------------------------
// I2C1 init + write
// ---------------------------------------------------------------------------

/// Initialize I2C1 (PB8=SCL, PB9=SDA, ~100 kHz). Mirrors
/// `secure/src/hw/i2c.rs::init` minus the secure-log instrumentation.
///
/// `sysclk_mhz` is the system clock as configured at FSBL boot. FSBL
/// runs the MCU at its 16 MHz HSI reset default (no RCC bring-up before
/// branching), so we pick the `PRESC=0` timing preset that hits 100 kHz
/// at a 16 MHz APB1.
fn i2c1_init() {
    set_bits(RCC_AHB2ENR1, 1 << 1); // GPIOB clock
    cortex_m::asm::dsb();
    set_bits(RCC_APB1ENR1, 1 << 21); // I2C1 clock
    cortex_m::asm::dsb();
    set_bits(RCC_APB1RSTR1, 1 << 21);
    cortex_m::asm::dsb();
    clear_bits(RCC_APB1RSTR1, 1 << 21);
    cortex_m::asm::dsb();

    // PB8/PB9: AF mode, open-drain, very-high speed, pull-up, AF4.
    modify(GPIOB_MODER, |v| {
        (v & !(0b11 << 16) & !(0b11 << 18)) | (0b10 << 16) | (0b10 << 18)
    });
    set_bits(GPIOB_OTYPER, (1 << 8) | (1 << 9));
    set_bits(GPIOB_OSPEEDR, (0b11 << 16) | (0b11 << 18));
    modify(GPIOB_PUPDR, |v| {
        (v & !(0b11 << 16) & !(0b11 << 18)) | (0b01 << 16) | (0b01 << 18)
    });
    modify(GPIOB_AFRH, |v| (v & !0xFF) | (4 << 0) | (4 << 4));

    // Disable I2C1 to allow TIMINGR write.
    wr(I2C_CR1, 0);
    cortex_m::asm::dsb();
    // 16 MHz / 100 kHz timing preset, matching secure-world's PRESC=0 path.
    wr(I2C_TIMINGR, 0x0042_3F4F);
    wr(I2C_CR1, 1); // PE
    cortex_m::asm::dsb();
}

/// Single-shot I2C write at 7-bit address `addr`. Returns `true` on
/// success, `false` on NACK / timeout / bus error / arbitration loss.
///
/// Mirrors `secure/src/hw/i2c.rs::write` minus the secure-log output.
fn i2c1_write(addr: u8, data: &[u8]) -> bool {
    let total = data.len();
    if total == 0 {
        return true;
    }

    let mut t = TIMEOUT;
    while rd(I2C_ISR) & BUSY != 0 {
        t -= 1;
        if t == 0 {
            let cr1 = rd(I2C_CR1);
            wr(I2C_CR1, cr1 & !1);
            cortex_m::asm::dsb();
            wr(I2C_CR1, cr1 | 1);
            cortex_m::asm::dsb();
            return false;
        }
    }

    let mut offset = 0usize;
    let mut remaining = total;

    while remaining > 0 {
        let chunk = if remaining > 255 { 255 } else { remaining };
        let last_chunk = remaining <= 255;

        let mut cr2: u32 = (addr as u32) << 1;
        cr2 |= (chunk as u32) << 16;
        if offset == 0 {
            cr2 |= 1 << 13; // START
        }
        if last_chunk {
            cr2 |= 1 << 25; // AUTOEND
        } else {
            cr2 |= 1 << 24; // RELOAD
        }
        wr(I2C_CR2, cr2);

        for _ in 0..chunk {
            t = TIMEOUT;
            loop {
                let isr = rd(I2C_ISR);
                if isr & (NACKF | BERR | ARLO) != 0 {
                    wr(I2C_ICR, NACKF | BERR | ARLO | STOPF);
                    return false;
                }
                if isr & TXIS != 0 {
                    break;
                }
                t -= 1;
                if t == 0 {
                    let cr1 = rd(I2C_CR1);
                    wr(I2C_CR1, cr1 & !1);
                    cortex_m::asm::dsb();
                    wr(I2C_CR1, cr1 | 1);
                    return false;
                }
            }
            wr(I2C_TXDR, data[offset] as u32);
            offset += 1;
        }
        remaining -= chunk;
        if !last_chunk {
            t = TIMEOUT;
            while rd(I2C_ISR) & TCR == 0 {
                t -= 1;
                if t == 0 {
                    return false;
                }
            }
        }
    }

    t = TIMEOUT;
    while rd(I2C_ISR) & STOPF == 0 {
        t -= 1;
        if t == 0 {
            return false;
        }
    }
    wr(I2C_ICR, STOPF);
    true
}

// ---------------------------------------------------------------------------
// SSD1306 + 4×16 framebuffer
// ---------------------------------------------------------------------------

/// 128 × 32 / 8 bits per page = 512 bytes of SSD1306 page data.
pub const FRAMEBUF_LEN: usize = 512;
/// 4 rows × 16 columns text grid (matches `secure/src/ui/mod.rs:51`).
/// Kept exported for tests + future renderers that want to bound their
/// row buffers; the in-tree FSBL render glue gets the same constants
/// from `sphincs_tz_bip39::{FINGERPRINT_ROWS, FINGERPRINT_COLS}`.
#[allow(dead_code)]
pub const DISPLAY_COLS: usize = 16;
#[allow(dead_code)]
pub const DISPLAY_ROWS: usize = 4;

const SSD1306_ADDR_PRIMARY: u8 = 0x3C;
const SSD1306_ADDR_ALT: u8 = 0x3D;

/// SSD1306 init sequence (clock, multiplex, charge pump, segment remap,
/// COM scan, contrast, ON). Matches the byte-for-byte secure-world
/// sequence at `secure/src/ui/oled.rs:134-153` so the FSBL OLED looks
/// identical to the secure-world OLED.
const INIT_CMDS: &[u8] = &[
    0xD5, 0x80, 0xA8, 0x1F, 0xD3, 0x00, 0x40, 0x8D, 0x14, 0x20, 0x00, 0xA1, 0xC8, 0xDA, 0x02,
    0x81, 0x8F, 0xD9, 0xF1, 0xDB, 0x40, 0xA4, 0xA6, 0xAF,
];

pub struct Oled {
    addr: u8,
    fb: [u8; FRAMEBUF_LEN],
    /// `true` once `init` has probed an SSD1306 successfully. Renders
    /// are no-ops while `present == false` so a board without an OLED
    /// daughterboard still boots cleanly into the slot.
    present: bool,
}

impl Oled {
    pub const fn new() -> Self {
        Self {
            addr: SSD1306_ADDR_PRIMARY,
            fb: [0u8; FRAMEBUF_LEN],
            present: false,
        }
    }

    /// Bring up I2C1 + probe both possible SSD1306 addresses. Sets
    /// `present = true` on success. Idempotent; safe to call once at
    /// FSBL boot.
    pub fn init(&mut self) {
        i2c1_init();

        // Probe by sending `0xAE` (display OFF) over both addresses
        // and latching whichever ACKs.
        let probe_cmd = [0x00u8, 0xAE];
        let addr = if i2c1_write(SSD1306_ADDR_PRIMARY, &probe_cmd) {
            SSD1306_ADDR_PRIMARY
        } else if i2c1_write(SSD1306_ADDR_ALT, &probe_cmd) {
            SSD1306_ADDR_ALT
        } else {
            // No OLED — no-OLED-fallback per the plan: leave `present`
            // false so subsequent rendering becomes a no-op and FSBL
            // branches into the slot. UX regression, not a security
            // failure (FSBL still verified the slot signature + hash).
            self.present = false;
            return;
        };
        self.addr = addr;

        for &cmd in INIT_CMDS {
            i2c1_write(addr, &[0x00, cmd]);
        }
        // Full-screen address window.
        i2c1_write(addr, &[0x00, 0x21, 0x00, 0x7F]);
        i2c1_write(addr, &[0x00, 0x22, 0x00, 0x03]);

        self.present = true;
        self.clear();
        self.flush();
    }

    /// Zero the framebuffer (display goes black on next flush).
    pub fn clear(&mut self) {
        self.fb = [0u8; FRAMEBUF_LEN];
    }

    /// Returns true iff `init` found an SSD1306. Tests use this to
    /// assert the no-OLED-fallback path keeps FSBL alive.
    #[allow(dead_code)]
    pub fn is_present(&self) -> bool {
        self.present
    }

    /// Read-only access to the framebuffer (for tests and QEMU capture).
    #[allow(dead_code)]
    pub fn framebuffer(&self) -> &[u8; FRAMEBUF_LEN] {
        &self.fb
    }

    /// Draw a row of ASCII bytes into the framebuffer. `row ∈ 0..4`.
    /// Each character is the 5×8 glyph from [`crate::glyphs`]; we leave
    /// 3 px between adjacent glyphs (5 + 3 = 8 px stride × 16 cols =
    /// exactly 128 px). Non-printable bytes render as blanks.
    pub fn draw_text(&mut self, row: usize, text: &[u8]) {
        if row >= DISPLAY_ROWS {
            return;
        }
        // Each row is one SSD1306 page (8 px tall). Page byte at column
        // c in the framebuffer is `fb[row * 128 + c]`. Glyph column-byte
        // already has the right bit layout (bit r = pixel at row r), so
        // we just OR it into the framebuffer.
        let mut col_px: usize = 0;
        for &b in text {
            if col_px + FONT_GLYPH_W > 128 {
                break;
            }
            for c in 0..FONT_GLYPH_W {
                self.fb[row * 128 + col_px + c] = glyph_col(b, c);
            }
            // 5 px glyph + 3 px gap = 8 px per character.
            col_px += FONT_GLYPH_W + 3;
        }
        // Zero out the remainder of the row so partial overwrites
        // don't leak previous content.
        while col_px < 128 {
            self.fb[row * 128 + col_px] = 0;
            col_px += 1;
        }
    }

    /// Push the framebuffer to the SSD1306 over I2C. No-op if no OLED
    /// is present.
    pub fn flush(&self) {
        if !self.present {
            return;
        }
        // Reset window to full screen.
        i2c1_write(self.addr, &[0x00, 0x21, 0x00, 0x7F]);
        i2c1_write(self.addr, &[0x00, 0x22, 0x00, 0x03]);

        for page in 0..4 {
            let start = page * 128;
            let mut chunk = [0u8; 129];
            chunk[0] = 0x40; // Co=0, D/C#=1 → data stream
            chunk[1..].copy_from_slice(&self.fb[start..start + 128]);
            i2c1_write(self.addr, &chunk);
        }
    }
}

/// Blocking cycle-counted delay. ~ms at 16 MHz core clock (the FSBL's
/// HSI reset default). Matches the secure-world's calibration shape at
/// `secure/src/ui/oled.rs:450-456` but scaled down to 16 MHz instead of
/// 160 MHz.
pub fn delay_ms(ms: u32) {
    for _ in 0..ms {
        for _ in 0..4_000 {
            cortex_m::asm::nop();
        }
    }
}
