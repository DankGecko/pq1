//! Animated splash-screen preview for the NV3007 SPI LCD (`splash-test`).
//!
//! A bench-only harness that ports the three HTML/`<canvas>` splash revisions
//! in `assets/splash-1{6,7,8}-*.standalone.html` (hyperspace / horizon /
//! nebula) to `no_std` Rust so a bench operator can judge how each looks on the
//! real panel. `main()` short-circuits into [`run`], which cycles the three
//! revisions (~12 s each) forever. Build + flash via `make splash-test-hw`.
//!
//! ## How the port stays faithful
//!
//! The browser renders to a 428×142 (landscape) 1-bit canvas: every frame
//! clears to black then turns individual pixels ON (white) via
//! `ctx.fillRect(x, y, 1, 1)`. We mirror that exactly with a 1-bit packed
//! landscape framebuffer ([`Splash::fb`], 7 597 B) — `set` turns a pixel ON,
//! `fb_clear` blanks the frame. No animation ever draws in the background
//! colour mid-frame, so the ON-only model is complete.
//!
//! Floating-point math (the JS `Math.*`) is done in `f32` via `micromath`'s
//! fast approximations — more than enough accuracy for a dithered 1-bit splash,
//! and the crate is pure-Rust `no_std` (no soft-float libcall surface). The one
//! intentional divergence is the PRNG (see [`Lcg`]): we use an integer LCG, so
//! the exact star *coordinates* differ from the browser, but the statistical
//! character (a uniform field at the same density) — all the visual needs — is
//! identical.
//!
//! ## Orientation
//!
//! The panel is native portrait 142(X)×428(Y); the splash is landscape. We
//! reuse the SAME landscape→native transpose + flip the trusted-UI text path
//! uses (`ui::lcd`, resolved on hardware 2026-06-09 to `FLIP = (true, false)`):
//! a landscape point `(lx, ly)` maps to native `(nx, ny) = (141 - ly, lx)`.
//! [`Splash::blit`] streams the frame to the panel in native scan order.

#![cfg(feature = "splash-test")]
// Pixel coordinates round-trip through f32/i32/usize all over the per-pixel
// loops; the conversions are intentional and bounded. Quiet the pedantic cast
// + naming lints for this self-contained bench module only.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::unreadable_literal
)]

use crate::hw::lcd_nv3007 as lcd;
use micromath::F32Ext;

// ---------------------------------------------------------------------------
// Canvas geometry (landscape, matching the HTML `WIDTH`/`HEIGHT`)
// ---------------------------------------------------------------------------
const LW: usize = 428; // landscape width  (canvas WIDTH)
const LH: usize = 142; // landscape height (canvas HEIGHT)
const W: f32 = LW as f32;
const H: f32 = LH as f32;
/// 1-bit packed framebuffer size — `428*142 = 60 776` bits = exactly 7 597 B.
const FB_BYTES: usize = (LW * LH).div_ceil(8);

// Nebula coarse-noise grid. The HTML used `step = 4` (108×36); we coarsen to
// `step = 6` to ~halve the per-frame `noise()` calls (the dominant nebula
// compute cost) for a slightly softer cloud — bilinear interpolation hides the
// coarser sampling. `GW`/`GH` use `div_ceil(STEP) + 1` so the bilinear's
// `gx+1`/`gy+1` neighbours are ALWAYS in-grid for every pixel (a plain
// `LW/STEP + 1` under-sizes the grid when STEP doesn't divide LW, which would
// make the right/bottom edge read the wrong cell). Exhaustively bounds-checked
// on the host over all 60 776 pixels.
const STEP: usize = 6;
const GW: usize = LW.div_ceil(STEP) + 1; // ceil(428/6)+1 = 73
const GH: usize = LH.div_ceil(STEP) + 1; // ceil(142/6)+1 = 25

/// Nebula carve radii, squared — lets the per-pixel hot loop skip `sqrt` for
/// the two dominant regions: the carved-out centre (`d ≤ 104`, `carve = 0`) and
/// the saturated body (`d ≥ 172`, `carve = 1`). Only the 104..172 transition
/// annulus needs the real distance.
const R_IN2: f32 = 104.0 * 104.0; // 10816
const R_OUT2: f32 = 172.0 * 172.0; // (104 + 68)² = 29584

// RGB565 — white text on black, same as the trusted-UI `ui::lcd` backend.
const FG: u16 = 0xFFFF;
const BG: u16 = 0x0000;

/// How long each revision is shown before advancing, in ms.
const HOLD_MS: u32 = 12_000;

// ---------------------------------------------------------------------------
// Seeded PRNG — integer reimplementation of the HTML's LCG.
// ---------------------------------------------------------------------------
/// `s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff`.
///
/// The browser does the multiply in `f64` (which loses precision above 2^53)
/// then masks, so a bit-exact match would require emulating that rounding. We
/// instead keep the state in `u32` and wrap — a perfectly uniform LCG whose
/// output stream differs from the browser's but lays out star fields of the
/// same density and character, which is all a splash preview needs.
struct Lcg(u32);

impl Lcg {
    fn new(seed: u32) -> Self {
        Self(seed)
    }

    #[inline]
    fn next(&mut self) -> f32 {
        self.0 = self.0.wrapping_mul(1103515245).wrapping_add(12345) & 0x7fff_ffff;
        self.0 as f32 / 2147483647.0
    }
}

// ---------------------------------------------------------------------------
// Helpers shared with the HTML (`bay`, `Math.round`, clamps)
// ---------------------------------------------------------------------------

/// 4×4 ordered (Bayer) dither: ON when `v` (0..1) beats the cell threshold.
/// Identical table + threshold to the HTML's `bay`.
const BAYER: [[u8; 4]; 4] = [[0, 8, 2, 10], [12, 4, 14, 6], [3, 11, 1, 9], [15, 7, 13, 5]];

#[inline]
fn bay(x: i32, y: i32, v: f32) -> bool {
    v > (BAYER[(y & 3) as usize][(x & 3) as usize] as f32 + 0.5) / 16.0
}

/// `Math.round` — round half toward +∞ (NOT Rust's round-half-away-from-zero).
#[inline]
fn jround(x: f32) -> i32 {
    (x + 0.5).floor() as i32
}

#[inline]
fn fmin(a: f32, b: f32) -> f32 {
    if a < b {
        a
    } else {
        b
    }
}

#[inline]
fn fmax(a: f32, b: f32) -> f32 {
    if a > b {
        a
    } else {
        b
    }
}

/// `Math.min(1, Math.max(0, x))`.
#[inline]
fn clamp01(x: f32) -> f32 {
    fmax(0.0, fmin(1.0, x))
}

// ---------------------------------------------------------------------------
// The PQ1 wordmark — 41 cells wide, 18 rows tall (caps 15, descender to 18).
// Transcribed verbatim from the HTML `WORDMARK` array.
// ---------------------------------------------------------------------------
const WORDMARK: [&[u8]; 18] = [
    b".#############....##############...######",
    b"###############..################..######",
    b"###############..################..######",
    b"####.......####..####........####.....###",
    b"###.........###..###..........###.....###",
    b"###.........###..###..........###.....###",
    b"###.........###..###..........###.....###",
    b"###........####..###..........###.....###",
    b"###.###########..###..........###.....###",
    b"###.###########..###..........###.....###",
    b"###.##########...###..........###.....###",
    b"###..............####........####.....###",
    b"###..............################.....###",
    b"###..............################.....###",
    b"###...............##############......###",
    b"...........................####..........",
    b"............................####.........",
    b".............................####........",
];

/// How the logo reveal is gated this frame.
#[derive(Clone, Copy)]
enum Reveal {
    /// Settled — every logo pixel ON.
    All,
    /// Dithering in — pixel ON when `bay(px, py, p)` (p ramps 0→1).
    Dither(f32),
}

// ---------------------------------------------------------------------------
// Per-animation state
// ---------------------------------------------------------------------------
#[derive(Clone, Copy)]
struct HsStar {
    x: f32,
    y: f32,
    z: f32,
}

#[derive(Clone, Copy)]
struct HzStar {
    x: i32,
    y: i32,
    k: f32,
    born: f32,
}

#[derive(Clone, Copy)]
struct NbStar {
    x: i32,
    y: i32,
    k: f32,
}

/// All splash state + the framebuffer. Lives in a single `static mut` (BSS,
/// not the stack) — `fb` (7.6 KB) + `field` (15.5 KB) are too big to want on
/// the secure stack, mirroring how `ui::lcd::Display` keeps its scratch off it.
struct Splash {
    /// 1-bit packed framebuffer in **native panel scan order** — bit `k` is the
    /// `k`-th pixel the SPI stream wants (`k = lx*FRAME_WIDTH + (141 - ly)`), so
    /// the blit is a straight byte-wise expand with no transpose. `set` does the
    /// landscape→native map; see [`Splash::set`].
    fb: [u8; FB_BYTES],
    /// Nebula coarse-noise field, `[gy * GW + gx]`.
    field: [f32; GW * GH],
    /// `pow(n, 2.2) * 0.7` sampled at 256 levels of `n ∈ [0, 1]` — replaces a
    /// per-pixel `powf` in the nebula. Feeds a dither threshold, so 256 levels
    /// is visually lossless.
    pow_lut: [f32; 256],
    hs: [HsStar; 240],
    hz: [HzStar; 150],
    hz_n: usize,
    nb: [NbStar; 60],
    nb_n: usize,
}

static mut SPLASH: Splash = Splash::new();

impl Splash {
    const fn new() -> Self {
        Self {
            fb: [0; FB_BYTES],
            field: [0.0; GW * GH],
            pow_lut: [0.0; 256],
            hs: [HsStar {
                x: 0.0,
                y: 0.0,
                z: 0.0,
            }; 240],
            hz: [HzStar {
                x: 0,
                y: 0,
                k: 0.0,
                born: 0.0,
            }; 150],
            hz_n: 0,
            nb: [NbStar {
                x: 0,
                y: 0,
                k: 0.0,
            }; 60],
            nb_n: 0,
        }
    }

    // -- framebuffer primitives (the JS `ctx.fillRect(x, y, 1, 1)` model) -----

    #[inline]
    fn fb_clear(&mut self) {
        self.fb.fill(0);
    }

    /// Turn landscape pixel `(x=lx, y=ly)` ON. Out-of-canvas coords are silently
    /// dropped — the HTML relies on the same canvas clipping.
    ///
    /// The framebuffer is stored in **native panel scan order** (the bit order
    /// the SPI stream wants), so the landscape→native transpose lives HERE
    /// rather than in the blit: that keeps the per-frame blit a trivial
    /// byte-wise expand. The transpose is the same `FLIP=(true,false)` map the
    /// trusted-UI text path uses — native `nx = 141 - ly`, `ny = lx` — and the
    /// stream index is `k = ny*FRAME_WIDTH + nx` (CASET col inner, RASET row
    /// outer). Since `set` runs once per *lit* pixel (far fewer than the 60 776
    /// the old per-pixel blit transpose touched), this is also cheaper overall.
    #[inline]
    fn set(&mut self, x: i32, y: i32) {
        if x < 0 || x >= LW as i32 || y < 0 || y >= LH as i32 {
            return;
        }
        let nx = (lcd::FRAME_WIDTH as usize - 1) - y as usize; // 141 - ly
        let ny = x as usize; // lx
        let k = ny * lcd::FRAME_WIDTH as usize + nx; // stream index, 0..60775
        self.fb[k >> 3] |= 1 << (k & 7);
    }

    /// Filled `w`×`h` ON-rect (the horizon moon's 3×3 disc).
    fn fill_rect_on(&mut self, x: i32, y: i32, w: i32, h: i32) {
        for dy in 0..h {
            for dx in 0..w {
                self.set(x + dx, y + dy);
            }
        }
    }

    /// Paint the wordmark at `(x, y)`, each cell `s` px square — the HTML
    /// `big`/`glyph`. `reveal` gates individual device pixels for the dither-in.
    #[optimize(speed)]
    fn draw_logo(&mut self, x: i32, y: i32, s: i32, reveal: Reveal) {
        for (r, row) in WORDMARK.iter().enumerate() {
            for (c, &cell) in row.iter().enumerate() {
                if cell != b'#' {
                    continue;
                }
                for dy in 0..s {
                    for dx in 0..s {
                        let px = x + c as i32 * s + dx;
                        let py = y + r as i32 * s + dy;
                        let on = match reveal {
                            Reveal::All => true,
                            Reveal::Dither(p) => bay(px, py, p),
                        };
                        if on {
                            self.set(px, py);
                        }
                    }
                }
            }
        }
    }

    // -- init (one-time star layout, RNG-seeded exactly like the HTML) --------

    /// Precompute the nebula `pow(n, 2.2) * 0.7` lookup table (256 `powf` calls,
    /// once) so the per-pixel hot loop is a table read instead of a `powf`.
    fn init_luts(&mut self) {
        let mut i = 0;
        while i < 256 {
            self.pow_lut[i] = (i as f32 / 255.0).powf(2.2) * 0.7;
            i += 1;
        }
    }

    fn init_hyperspace(&mut self) {
        let mut r = Lcg::new(77);
        for s in &mut self.hs {
            *s = HsStar {
                x: r.next() * W,
                y: r.next() * H,
                z: 0.3 + r.next() * 0.7,
            };
        }
    }

    fn init_horizon(&mut self) {
        let mut r = Lcg::new(55);
        let mut n = 0;
        for _ in 0..150 {
            // All four draws happen BEFORE the filters — the HTML advances its
            // RNG identically whether or not the candidate is kept.
            let x = (r.next() * W) as i32;
            let y = (r.next() * H) as i32;
            let k = r.next();
            let born = r.next() * 1400.0;
            if y as f32 > limb_y(x as f32) - 4.0 {
                continue;
            }
            if x > 116 && x < 312 && y > 0 && y < 100 {
                continue;
            }
            self.hz[n] = HzStar { x, y, k, born };
            n += 1;
        }
        self.hz_n = n;
    }

    fn init_nebula(&mut self) {
        let mut r = Lcg::new(21);
        let mut n = 0;
        for _ in 0..60 {
            let x = (r.next() * W) as i32;
            let y = (r.next() * H) as i32;
            let k = r.next();
            if x > 116 && x < 312 && y > 24 && y < 116 {
                continue;
            }
            self.nb[n] = NbStar { x, y, k };
            n += 1;
        }
        self.nb_n = n;
    }

    // -- per-frame render (`now` = ms since this revision started) ------------

    #[optimize(speed)]
    fn render_hyperspace(&mut self, now: f32) {
        const CX: f32 = 214.0;
        const CY: f32 = 71.0;
        let t = now % 7000.0;
        self.fb_clear();

        if t < 1500.0 {
            // slow drift
            for i in 0..self.hs.len() {
                let s = self.hs[i];
                let x = (((s.x - t * 0.012 * s.z) % W) + W) % W;
                let xi = x as i32;
                let yi = s.y as i32;
                if s.z > 0.6 || bay(xi, yi, 0.4) {
                    self.set(xi, yi);
                }
            }
        } else if t < 2700.0 {
            // warp: radial streaks
            let k = (t - 1500.0) / 1200.0;
            let kk = k * k;
            for i in 0..self.hs.len() {
                let s = self.hs[i];
                let dx = s.x - CX;
                let dy = s.y - CY;
                let d = nonzero((dx * dx + dy * dy).sqrt());
                let ux = dx / d;
                let uy = dy / d;
                let l = kk * (16.0 + 120.0 * s.z);
                let mut q = 0.0;
                while q < l {
                    let x = jround(s.x + ux * q);
                    let y = jround(s.y + uy * q * 0.6);
                    if x < 0 || x >= LW as i32 || y < 0 || y >= LH as i32 {
                        break;
                    }
                    self.set(x, y);
                    q += 1.0;
                }
            }
        } else {
            // materialize + hold
            let p = fmin(1.0, (t - 2700.0) / 800.0);
            if p < 1.0 {
                let fade = 1.0 - p;
                for i in 0..self.hs.len() {
                    let s = self.hs[i];
                    if s.z < 0.5 {
                        continue;
                    }
                    let dx2 = s.x - CX;
                    let dy2 = s.y - CY;
                    let d2 = nonzero((dx2 * dx2 + dy2 * dy2).sqrt());
                    let l2 = fade * (16.0 + 120.0 * s.z);
                    let mut q = 0.0;
                    while q < l2 {
                        let x = jround(s.x + (dx2 / d2) * (q + (1.0 - fade) * 80.0));
                        let y = jround(s.y + (dy2 / d2) * q * 0.6);
                        if x < 0 || x >= LW as i32 || y < 0 || y >= LH as i32 {
                            break;
                        }
                        if bay(x, y, fade) {
                            self.set(x, y);
                        }
                        q += 1.0;
                    }
                }
            } else {
                // settled, twinkling
                for i in 0..self.hs.len() {
                    let s = self.hs[i];
                    let tw = (now * 0.002 + s.x * 13.7 + s.y * 7.1).sin();
                    if s.x > 116.0 && s.x < 312.0 && s.y > 24.0 && s.y < 116.0 {
                        continue;
                    }
                    let xi = s.x as i32;
                    let yi = s.y as i32;
                    if s.z > 0.55 && tw > -0.7 {
                        self.set(xi, yi);
                    } else if tw > 0.5 && bay(xi, yi, 0.4) {
                        self.set(xi, yi);
                    }
                }
            }
            self.draw_logo(
                132,
                34,
                4,
                if p >= 1.0 {
                    Reveal::All
                } else {
                    Reveal::Dither(p)
                },
            );
        }
    }

    #[optimize(speed)]
    fn render_horizon(&mut self, now: f32) {
        let t = now;
        self.fb_clear();

        for i in 0..self.hz_n {
            let s = self.hz[i];
            if t < s.born {
                continue;
            }
            let tw = (now * 0.0015 + s.x as f32 * 13.7 + s.y as f32 * 7.1).sin();
            if s.k > 0.45 {
                if tw > -0.85 {
                    self.set(s.x, s.y);
                }
            } else if tw > -0.2 && bay(s.x, s.y, 0.3) {
                self.set(s.x, s.y);
            }
        }

        let rise = (1.0 - ease(clamp01((t - 700.0) / 1900.0))) * 52.0;
        for x in 0..LW as i32 {
            let ly = limb_y(x as f32) + rise;
            let mut y = ly.ceil() as i32;
            while (y as f32) < H {
                let depth = y as f32 - ly;
                if depth < 2.5 {
                    self.set(x, y);
                    y += 1;
                    continue;
                }
                let v = fmax(0.03, 0.5 - depth * 0.0225);
                if bay(x, y, v) {
                    self.set(x, y);
                }
                y += 1;
            }
        }

        if t > 2600.0 {
            let op = fmin(1.0, (t - 2600.0) / 700.0);
            for i in 0..720 {
                let ang = (i as f32 / 720.0) * core::f32::consts::PI * 2.0;
                let x = jround(214.0 + ang.cos() * 260.0);
                let y = jround(112.0 + ang.sin() * 52.0);
                if x < 0 || x >= LW as i32 || y < 0 || y >= LH as i32 {
                    continue;
                }
                if y as f32 > limb_y(x as f32) + 1.0 && ang.sin() > 0.0 {
                    continue;
                }
                if i % 8 < 4 && bay(x, y, op) {
                    self.set(x, y);
                }
            }
            // The orbiting moon.
            let ma = core::f32::consts::PI + (t - 2600.0) * 0.00042;
            let mx = jround(214.0 + ma.cos() * 260.0);
            let my = jround(112.0 + ma.sin() * 52.0);
            if !(my as f32 > limb_y(mx as f32) + 1.0 && ma.sin() > 0.0)
                && mx > 1
                && mx < LW as i32 - 3
                && my > 1
                && my < LH as i32 - 3
            {
                self.fill_rect_on(mx - 1, my - 1, 3, 3);
            }
        }

        let p = clamp01((t - 1900.0) / 900.0);
        if p > 0.0 {
            self.draw_logo(
                132,
                12,
                4,
                if p >= 1.0 {
                    Reveal::All
                } else {
                    Reveal::Dither(p)
                },
            );
        }
    }

    #[optimize(speed)]
    fn render_nebula(&mut self, now: f32) {
        let t = now / 1000.0;
        let drift = t * 6.4;
        for gy in 0..GH {
            for gx in 0..GW {
                self.field[gy * GW + gx] =
                    noise(gx as f32 * STEP as f32 + drift, gy as f32 * STEP as f32, t);
            }
        }
        self.fb_clear();

        // Reciprocals so the per-pixel hot loop multiplies instead of dividing
        // (an f32 `vdiv` is ~14 cycles; a multiply ~1).
        const INV_STEP: f32 = 1.0 / STEP as f32;
        const INV68: f32 = 1.0 / 68.0;
        for y in 0..LH {
            let gy = y / STEP;
            // The HTML reads `field[idx+gw]`/`[idx+gw+1]`; on the bottom rows
            // (`gy+1 == GH`) those are out of the typed array → `undefined` →
            // NaN → the `v > 0.02` test is false → no pixel. We skip the same
            // rows so the look matches AND we never index past `field`.
            if gy + 1 >= GH {
                continue;
            }
            // Row-constant terms hoisted out of the x loop.
            let fy = (y - gy * STEP) as f32 * INV_STEP; // == y/STEP - gy, no div
            let omfy = 1.0 - fy;
            let ay = (y as f32 - 70.0) * 1.9;
            let ay2 = ay * ay;
            let gyb = gy * GW; // field row base
            // Track ax = x-214, gx = x/STEP, rem = x mod STEP incrementally —
            // no per-pixel integer OR float division (host-verified the
            // sequence equals x-214 / x/STEP / x%STEP for all x).
            let mut ax = -214.0f32;
            let mut gx = 0usize;
            let mut rem = 0usize;
            for x in 0..LW {
                // carve = clamp01((d - 104)/68), d = hypot(x-214, (y-70)*1.9).
                // Squared-distance branch: skip the carved-out centre and the
                // saturated body without ever calling sqrt; only the annulus
                // does. Equivalent to the original clamp (carve ≤ 0 ⟺ d ≤ 104,
                // carve = 1 ⟺ d ≥ 172).
                let d2 = ax * ax + ay2;
                if d2 > R_IN2 {
                    let carve = if d2 >= R_OUT2 {
                        1.0
                    } else {
                        (d2.sqrt() - 104.0) * INV68
                    };
                    let fx = rem as f32 * INV_STEP;
                    let omfx = 1.0 - fx;
                    let idx = gyb + gx;
                    // SAFETY: bounds-check elision in the per-pixel hot path.
                    // idx = gyb + gx with gy ≤ GH-2 (the `gy+1 >= GH` guard
                    // above) and gx ≤ (LW-1)/STEP = GW-2 (gx tracks x/STEP,
                    // x < LW), so all four accessed indices idx, idx+1, idx+GW,
                    // idx+GW+1 are ≤ (gy+2)*GW - 1 ≤ GH*GW - 1 < field.len()
                    // (GW*GH). Exhaustively host-verified over all 60 776 pixels
                    // for STEP=6 / GW=73 / GH=25 (max index 1824 < 1825).
                    let n = unsafe {
                        *self.field.get_unchecked(idx) * omfx * omfy
                            + *self.field.get_unchecked(idx + 1) * fx * omfy
                            + *self.field.get_unchecked(idx + GW) * omfx * fy
                            + *self.field.get_unchecked(idx + GW + 1) * fx * fy
                    };
                    // v = pow(n, 2.2) * 0.7 * carve, via the precomputed LUT. n
                    // is bounded to ~(0.018, 0.982) so the clamp never fires in
                    // practice; when it does it mirrors the original
                    // out-of-range behaviour — a negative/NaN n maps to index 0
                    // (pow_lut[0]=0 → no pixel), exactly as the old
                    // pow(neg,2.2)=NaN → NaN>0.02=false.
                    let li = ((n * 255.0) as i32).clamp(0, 255) as usize;
                    let v = self.pow_lut[li] * carve;
                    if v > 0.02 && bay(x as i32, y as i32, v) {
                        self.set(x as i32, y as i32);
                    }
                }
                ax += 1.0;
                rem += 1;
                if rem == STEP {
                    rem = 0;
                    gx += 1;
                }
            }
        }

        for i in 0..self.nb_n {
            let s = self.nb[i];
            let tw = (now * 0.0017 + s.x as f32 * 9.3 + s.y as f32 * 5.7).sin();
            if s.k > 0.5 {
                if tw > -0.8 {
                    self.set(s.x, s.y);
                }
            } else if tw > 0.3 {
                self.set(s.x, s.y);
            }
        }

        let p = fmin(1.0, now / 900.0);
        self.draw_logo(
            132,
            34,
            4,
            if p >= 1.0 {
                Reveal::All
            } else {
                Reveal::Dither(p)
            },
        );
    }

    // -- blit: landscape framebuffer → native panel ---------------------------

    /// Stream the framebuffer to the panel as a SINGLE continuous transaction:
    /// one `set_window` over the whole frame + one chunked RAMWR stream (via
    /// `lcd::write_pixels_with`). Because `fb` is already stored in native scan
    /// order (see [`Splash::set`]), this is a pure **byte-wise expand** — read a
    /// packed byte (8 consecutive stream pixels), emit FG/BG for each bit — with
    /// NO per-pixel transpose, multiply, or bounds check. That keeps the blit at
    /// the polled-SPI throughput floor instead of being CPU-bound on the unpack.
    /// One full repaint per frame, so no stale content survives.
    #[optimize(speed)]
    fn blit(&self) {
        const N: u32 = lcd::FRAME_WIDTH as u32 * lcd::FRAME_HEIGHT as u32; // 60776
        lcd::set_window(0, 0, lcd::FRAME_WIDTH - 1, lcd::FRAME_HEIGHT - 1);
        let mut byte_idx = 0usize;
        let mut cur = self.fb[0];
        let mut bit = 0u8;
        lcd::write_pixels_with(N, || {
            let on = (cur >> bit) & 1 != 0;
            bit += 1;
            if bit == 8 {
                bit = 0;
                byte_idx += 1;
                // N == FB_BYTES*8 exactly, so the guard only fails after the
                // final pixel (no further next() call) — never an OOB read.
                if byte_idx < FB_BYTES {
                    cur = self.fb[byte_idx];
                }
            }
            if on {
                FG
            } else {
                BG
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Free helpers used by the renderers (mirror the HTML's closures)
// ---------------------------------------------------------------------------

/// `Math.hypot(...) || 1` — substitute 1 only when exactly zero (avoid /0).
#[inline]
fn nonzero(d: f32) -> f32 {
    if d == 0.0 {
        1.0
    } else {
        d
    }
}

/// Horizon planet limb: `104 + R - sqrt(R² - (x - pcx)²)` with `R = 731`,
/// `pcx = 214`. The radicand stays positive for all `x ∈ [0, 428)`.
#[inline]
fn limb_y(x: f32) -> f32 {
    const R: f32 = 731.0;
    const PCX: f32 = 214.0;
    let dx = x - PCX;
    104.0 + R - (R * R - dx * dx).sqrt()
}

/// Horizon ease — `1 - (1 - u)³` (cubic ease-out). Integer cube, no `powf`.
#[inline]
fn ease(u: f32) -> f32 {
    let a = 1.0 - u;
    1.0 - a * a * a
}

/// Nebula fBm field — 3 octaves of the HTML's `noise(x, y, t)`.
#[optimize(speed)]
fn noise(x: f32, y: f32, t: f32) -> f32 {
    let mut v = 0.0;
    let mut a = 0.55;
    let mut f = 0.0375;
    for o in 0..3 {
        let of = o as f32;
        v += a
            * ((x * f + (y * f * 1.31 + of * 2.1 + t * 0.18).sin() * 2.3 + of * 4.7).sin()
                + (y * f * 0.83 + (x * f * 1.17 + of * 1.3 - t * 0.11).sin() * 1.9).cos())
            / 2.0;
        a *= 0.5;
        f *= 2.15;
    }
    v * 0.5 + 0.5
}

// ---------------------------------------------------------------------------
// Entry point — never returns.
// ---------------------------------------------------------------------------

/// Enable the Cortex-M33 single-precision FPU so the splash's f32 math runs on
/// hardware VFP instead of soft-float emulation (~10-50× faster; the nebula's
/// per-frame sin/cos/pow is the difference between ~1 fps and a smooth preview).
///
/// The firmware is otherwise all-integer, so the FPU is left disabled at reset.
/// The `splash-test` build alone is compiled with
/// `-C target-feature=+fp-armv8d16sp` (the M33 FPU, **soft-float ABI kept** so
/// the CMSE veneer / NS interface is unchanged — only internal codegen uses
/// VFP), which means it MUST flip `CPACR` before executing any VFP instruction
/// or the first one UsageFaults (NOCP). This runs before [`Splash::init_luts`]
/// (the first float user), and the whole boot path up to here is float-free.
#[inline(never)]
fn enable_fpu() {
    // CPACR @ 0xE000_ED88: CP10 (bits 21:20) + CP11 (bits 23:22) = 0b11 → full
    // access. SAFETY: a core debug/SCB register always reachable from secure
    // code; single-threaded; no float op appears in this function, and the
    // DSB/ISB make the enable take effect before any later VFP instruction.
    const CPACR: *mut u32 = 0xE000_ED88 as *mut u32;
    unsafe {
        let v = core::ptr::read_volatile(CPACR);
        core::ptr::write_volatile(CPACR, v | (0b11 << 20) | (0b11 << 22));
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

/// Enable + read the DWT cycle counter (160 cycles/µs @160 MHz) for the
/// per-revision compute-vs-blit timing split. Same register dance as
/// `lcd_nv3007::lcd_test_loop`.
fn dwt_init() {
    // SAFETY: core debug-block registers, always accessible to secure code.
    unsafe {
        let demcr = 0xE000_EDFC as *mut u32;
        core::ptr::write_volatile(demcr, core::ptr::read_volatile(demcr) | (1 << 24)); // TRCENA
        core::ptr::write_volatile(0xE000_1FB0 as *mut u32, 0xC5AC_CE55); // DWT_LAR unlock
        core::ptr::write_volatile(0xE000_1004 as *mut u32, 0); // CYCCNT = 0
        let ctrl = 0xE000_1000 as *mut u32;
        core::ptr::write_volatile(ctrl, core::ptr::read_volatile(ctrl) | 1); // CYCCNTENA
    }
}

#[inline]
fn dwt_cyc() -> u32 {
    // SAFETY: plain read of the free-running DWT cycle counter.
    unsafe { core::ptr::read_volatile(0xE000_1004 as *const u32) }
}

/// Short-circuit boot into the splash preview. Assumes `ui::init()` already
/// brought the LCD up (it does — `Display::init` → `lcd::init`). Cycles the
/// three revisions ~12 s each, forever. Driven by `make splash-test-hw`.
pub fn run() -> ! {
    // Hardware FPU first — every later float op depends on it.
    enable_fpu();
    dwt_init();
    // SAFETY: the secure world is single-threaded and we hold the only
    // reference to SPLASH for the rest of the program's life. Same `&raw mut`
    // static pattern as `ui::DISPLAY`.
    let sp = unsafe { &mut *(&raw mut SPLASH) };
    sp.init_luts();
    sp.init_hyperspace();
    sp.init_horizon();
    sp.init_nebula();

    lcd::fill_screen(BG);
    secure_log!("[SPLASH] preview: hyperspace(16) -> horizon(17) -> nebula(18), ~12s each, looping");

    let mut idx: u32 = 0;
    loop {
        // Braced arms: `secure_log!` expands to `#[cfg]`-gated statements, so it
        // must sit in statement (not expression) position.
        match idx % 3 {
            0 => {
                secure_log!("[SPLASH] -> hyperspace (rev 16)");
            }
            1 => {
                secure_log!("[SPLASH] -> horizon (rev 17)");
            }
            _ => {
                secure_log!("[SPLASH] -> nebula (rev 18)");
            }
        }
        let t0 = crate::timeout::now();
        let mut frames: u32 = 0;
        let mut compute_cyc: u64 = 0; // DWT cycles spent in render_*
        let mut blit_cyc: u64 = 0; // DWT cycles spent streaming to the panel
        loop {
            let now = crate::timeout::now().wrapping_sub(t0) as f32;
            let c0 = dwt_cyc();
            match idx % 3 {
                0 => sp.render_hyperspace(now),
                1 => sp.render_horizon(now),
                _ => sp.render_nebula(now),
            }
            let c1 = dwt_cyc();
            sp.blit();
            let c2 = dwt_cyc();
            compute_cyc += u64::from(c1.wrapping_sub(c0));
            blit_cyc += u64::from(c2.wrapping_sub(c1));
            frames += 1;
            let elapsed = crate::timeout::now().wrapping_sub(t0);
            if elapsed >= HOLD_MS {
                // Average FPS + the per-frame compute/blit split (µs) so a bench
                // operator can see exactly where each animation spends its time
                // (compute-bound vs the SPI blit floor) over USB/semihosting.
                let fps = frames.saturating_mul(1000) / elapsed.max(1);
                let n = u64::from(frames).max(1);
                let comp_us = compute_cyc / 160 / n; // 160 cycles/µs @160 MHz
                let blit_us = blit_cyc / 160 / n;
                secure_log!(
                    "[SPLASH] {} fr / {} ms = ~{} fps | per-frame: compute {} us, blit {} us",
                    frames,
                    elapsed,
                    fps,
                    comp_us,
                    blit_us
                );
                break;
            }
        }
        idx = idx.wrapping_add(1);
    }
}
