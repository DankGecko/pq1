//! SE050 on-silicon stress-test harness.
//!
//! Catalog-driven runner that exercises the SE050 driver against real
//! silicon and reports per-test PASS/FAIL via `secure_log!` semihosting.
//! Picked up by `make se050-stress*` recipes; gated behind the
//! `se050-stress` Cargo feature so production builds don't link any of
//! it.
//!
//! ## Adding a new test
//!
//! 1. Pick the file under `tests/` that matches your topic (or create a
//!    new one and `mod` it in `tests/mod.rs`).
//! 2. Write a function `fn my_test(ctx: &mut StressCtx) -> StressResult`.
//! 3. Register it with `stress_test!(MY_TEST, "my_test", Tier::Safe,
//!    my_test);`.
//! 4. Add `&MY_TEST` to that file's `pub static TESTS: &[&StressTest]`
//!    slice (the one place each category collects its own tests).
//!
//! That's the entire diff — no Cargo.toml, no `main.rs`, no Makefile.
//!
//! ## Selection
//!
//! - `make se050-stress` runs every Safe-tier test.
//! - `make se050-stress-destructive` adds Destructive-tier tests.
//! - `make se050-stress-only-<name>` runs a single test by name. The
//!   Makefile injects the filter as `SE050_STRESS_ONLY=<name>` via
//!   `RUSTFLAGS=--cfg stress_only=...` so the secure crate picks it up
//!   through `option_env!` at compile time. (A bare env var change is
//!   NOT in cargo's cache key — the Makefile force-rebuilds via
//!   a timestamped `--cfg stress_build=<unix>` to avoid stale binaries.)
//!
//! ## OID carve-out
//!
//! Stress tests own range `0x7B5E_*` exclusively (see `oid.rs`):
//! - `0x7B5E_00A0` — stress-admin UserID (unlimited attempts, hardware-
//!   root-derived PIN, admin-delete authority over the whole range).
//! - `0x7B5E_NN??` — test N (1..=255) owns 256 OIDs. The runner cleans
//!   this sub-range before AND after each test, so a crashed test never
//!   poisons the next run.
//!
//! Production OIDs `0x7B10_*` are NEVER touched.

#![cfg(feature = "se050-stress")]

use crate::se050::Se050;
use crate::se050::apdu::Se050Error;

pub mod ctx;
pub mod oid;
#[macro_use]
pub mod registry;
pub mod tests;

pub use ctx::StressCtx;

// ---------------------------------------------------------------------------
// Public types — extending these adds capability without breaking existing
// tests.
// ---------------------------------------------------------------------------

/// Test difficulty / safety classification.
///
/// `Safe`: idempotent, leaves no persistent SE050 state behind. Always
/// run by `make se050-stress`. Examples: SCP03 burst, TRNG quality,
/// scratch-object churn.
///
/// `Destructive`: drives UserID attempt counters or otherwise mutates
/// state in a way that can leave the chip's persistent storage in a
/// partial state if the test crashes before cleanup. The top-of-run
/// admin sweep reclaims them on the next boot, but the user opts in
/// explicitly via `make se050-stress-destructive`.
///
/// New tiers (`Adversarial`, `Soak`, …) can be added as variants
/// without touching existing tests — they keep their declared tier
/// unchanged and the catalog runner just filters on the new variant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    Safe,
    Destructive,
}

impl Tier {
    pub fn name(self) -> &'static str {
        match self {
            Tier::Safe => "safe",
            Tier::Destructive => "destructive",
        }
    }
}

/// A single stress test. Constructed by the `stress_test!` macro and
/// referenced from each test file's `TESTS` slice.
pub struct StressTest {
    pub name: &'static str,
    pub tier: Tier,
    pub run: fn(&mut StressCtx) -> StressResult,
}

pub type StressResult = Result<(), StressError>;

/// Structured failure modes. Adding a variant is a forward-compatible
/// extension — `Debug` is exhaustive so the compiler catches any new
/// reporting site.
#[derive(Debug)]
pub enum StressError {
    /// Test setup-time assertion failed with a descriptive label.
    Assertion {
        what: &'static str,
        iter: u32,
    },
    /// A byte (or first-differing byte of a buffer) didn't match the
    /// expected value. Caller passes the offset-0 difference; deeper
    /// diagnostics belong in a per-test `secure_log!`.
    Mismatch {
        what: &'static str,
        expected: u8,
        got: u8,
    },
    /// SE050 returned an unexpected SW.
    UnexpectedSw {
        what: &'static str,
        sw: u16,
    },
    /// Underlying driver error bubbled through `?`.
    Driver(Se050Error),
    /// A test timeout (e.g. WTX retry budget exhausted).
    Timeout(&'static str),
}

impl From<Se050Error> for StressError {
    fn from(e: Se050Error) -> Self {
        StressError::Driver(e)
    }
}

// ---------------------------------------------------------------------------
// Compile-time selectors (driven by RUSTFLAGS the Makefile sets)
// ---------------------------------------------------------------------------

/// Single-test filter. `None` ⇒ run every test in the catalog (subject
/// to tier filter). `Some(name)` ⇒ run only the matching test.
///
/// Wired via `option_env!("SE050_STRESS_ONLY")`. The cache-busting
/// `--cfg stress_build=<ts>` injected by the Makefile guarantees a
/// rebuild whenever the filter changes (env vars are NOT in cargo's
/// fingerprint).
pub const FILTER: Option<&str> = option_env!("SE050_STRESS_ONLY");

/// Tier to run. `None` (or unrecognised) ⇒ Safe. `Some("destructive")`
/// ⇒ Safe + Destructive.
pub const TIER_ENV: Option<&str> = option_env!("SE050_STRESS_TIER");

/// Outer loop count for soak runs. Default 1.
const REPEAT_ENV: Option<&str> = option_env!("SE050_STRESS_REPEAT");

fn tier_includes(t: Tier) -> bool {
    match TIER_ENV {
        Some("destructive") | Some("all") => true,
        _ => matches!(t, Tier::Safe),
    }
}

fn repeat_count() -> u32 {
    match REPEAT_ENV.and_then(|s| s.parse::<u32>().ok()) {
        Some(n) if n >= 1 => n,
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// Runner entry — called from `main.rs` under `#[cfg(feature = "se050-stress")]`.
// ---------------------------------------------------------------------------

/// Run the registered stress-test catalog against the supplied SE050
/// driver. Reports a per-test PASS/FAIL line plus a summary, then
/// returns (`main.rs` halts in `wfi` after this).
pub fn run_catalog(se: &mut Se050) {
    let catalog = tests::ALL_TESTS;
    let total = catalog.len();
    let repeats = repeat_count();
    let tier_label = match TIER_ENV {
        Some(s) => s,
        None => "safe",
    };
    let filter_label = match FILTER {
        Some(s) => s,
        None => "ALL",
    };

    secure_log!("[S][stress] === SE050 STRESS RUNNER ===");
    secure_log!(
        "[S][stress] catalog: {} tests, tier={}, filter={}, repeat={}",
        total, tier_label, filter_label, repeats,
    );
    crate::ui::show_status("se050-stress", "running...");

    // SE050 init — must succeed, or there's nothing to test.
    if let Err(e) = se.init() {
        secure_log!("[S][stress] FATAL: Se050::init() failed: {:?}", e);
        crate::ui::show_status("se050-stress", "init FAIL");
        return;
    }

    // Top-of-run admin sweep: clean any leftovers from a crashed prior
    // run. Best-effort: we don't fail the suite if it doesn't fully
    // succeed (the per-test cleanup will catch most contamination
    // anyway).
    let swept = oid::admin_sweep_all(se);
    secure_log!(
        "[S][stress] top-of-run admin sweep: {} cleared, {} failed",
        swept.cleared, swept.failed,
    );

    let mut pass: u32 = 0;
    let mut fail: u32 = 0;
    let mut skip: u32 = 0;

    for r in 0..repeats {
        if repeats > 1 {
            secure_log!("[S][stress] --- repeat {}/{} ---", r + 1, repeats);
        }
        for (idx, test) in catalog.iter().enumerate() {
            // Tier filter.
            if !tier_includes(test.tier) {
                secure_log!(
                    "[S][stress] SKIP  {:03}/{:03} {} (tier={})",
                    idx + 1, total, test.name, test.tier.name(),
                );
                skip += 1;
                continue;
            }
            // Single-test filter.
            if let Some(only) = FILTER {
                if !only.is_empty() && only != test.name {
                    skip += 1;
                    continue;
                }
            }

            // Force a clean SCP03 + T=1' state between tests so a
            // counter-perturbation in test N can't bleed into N+1.
            if let Err(e) = se.reinit() {
                secure_log!(
                    "[S][stress] FAIL  {:03}/{:03} {} err=reinit({:?})",
                    idx + 1, total, test.name, e,
                );
                fail += 1;
                continue;
            }

            secure_log!(
                "[S][stress] BEGIN {:03}/{:03} {}",
                idx + 1, total, test.name,
            );
            // Show running test on OLED so the operator can see progress
            // without the probe attached.
            crate::ui::show_status(test.name, "...");

            let t0 = arch_cycles_now();
            let mut ctx = StressCtx::new(se, (idx + 1) as u16);
            let result = (test.run)(&mut ctx);
            let elapsed_ms = cycles_to_ms(arch_cycles_now().wrapping_sub(t0));

            // Per-test teardown: best-effort sweep of this test's sub-
            // range, regardless of pass/fail, so the next test starts
            // clean.
            let _ = oid::admin_sweep_test_range(se, (idx + 1) as u16);

            match result {
                Ok(()) => {
                    secure_log!(
                        "[S][stress] PASS  {:03}/{:03} {} ({} ms)",
                        idx + 1, total, test.name, elapsed_ms,
                    );
                    crate::ui::show_status(test.name, "PASS");
                    pass += 1;
                }
                Err(e) => {
                    secure_log!(
                        "[S][stress] FAIL  {:03}/{:03} {} err={:?} ({} ms)",
                        idx + 1, total, test.name, e, elapsed_ms,
                    );
                    crate::ui::show_status(test.name, "FAIL");
                    fail += 1;
                }
            }
        }
    }

    secure_log!(
        "[S][stress] === SUMMARY: {} PASS / {} FAIL / {} SKIP ===",
        pass, fail, skip,
    );
    secure_log!("[S][stress] === DONE ===");

    // OLED summary frame (visible without probe-rs attached).
    let mut sum_buf = [0u8; 16];
    let label = format_summary(pass, fail, &mut sum_buf);
    crate::ui::show_status("se050-stress", label);
}

// ---------------------------------------------------------------------------
// Local time / formatting helpers (kept private to keep the runner self-
// contained; `bench_key_speed` uses the same DWT register pattern).
// ---------------------------------------------------------------------------

#[inline]
fn arch_cycles_now() -> u32 {
    crate::ARCH.dwt_cyccnt.read()
}

const HCLK_HZ: u32 = 160_000_000;
const CYCLES_PER_MS: u32 = HCLK_HZ / 1_000;

#[inline]
fn cycles_to_ms(c: u32) -> u32 {
    c / CYCLES_PER_MS
}

/// Format "P/F" into the supplied buffer and return a `&str` view.
/// Avoids `core::fmt::Write` machinery so the OLED status path stays
/// cheap and `no_std`-clean.
fn format_summary<'a>(pass: u32, fail: u32, buf: &'a mut [u8; 16]) -> &'a str {
    for b in buf.iter_mut() {
        *b = b' ';
    }
    let mut i = 0;
    i = u32_to_decimal(pass, buf, i);
    buf[i] = b'P';
    i += 1;
    buf[i] = b'/';
    i += 1;
    i = u32_to_decimal(fail, buf, i);
    buf[i] = b'F';
    i += 1;
    // SAFETY: we wrote only ASCII bytes (digits + 'P' + '/' + 'F').
    unsafe { core::str::from_utf8_unchecked(&buf[..i]) }
}

fn u32_to_decimal(mut n: u32, buf: &mut [u8; 16], mut i: usize) -> usize {
    if n == 0 {
        buf[i] = b'0';
        return i + 1;
    }
    let start = i;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    // Reverse the digits we just wrote.
    buf[start..i].reverse();
    i
}
