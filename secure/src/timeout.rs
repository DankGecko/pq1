//! Inactivity timeout / activity tracking.
//!
//! `tick()` is called once per SysTick (~1 ms). `reset_activity()` is called
//! whenever real user input occurs (button press, successful PIN entry,
//! confirmed sign). `is_idle()` returns true after [`TIMEOUT_TICKS`] ticks
//! have elapsed without activity, and is checked from any blocking dialog so
//! it can interrupt them and trigger a wipe.
//!
//! Background NS gateway commands (GET_REMAINING, GET_PUBKEY) intentionally
//! do NOT count as activity — only physical user input does, matching the
//! Ledger model.

use core::sync::atomic::{AtomicU32, Ordering};

/// 2 minutes at ~1 ms tick. The actual SysTick reload is configured in
/// `main::setup_systick()`.
pub const TIMEOUT_TICKS: u32 = 2 * 60 * 1000;

static TICKS: AtomicU32 = AtomicU32::new(0);
static LAST_ACTIVITY: AtomicU32 = AtomicU32::new(0);

#[inline]
pub fn now() -> u32 {
    TICKS.load(Ordering::Relaxed)
}

#[inline]
pub fn tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn reset_activity() {
    LAST_ACTIVITY.store(now(), Ordering::Relaxed);
}

#[inline]
pub fn idle_for() -> u32 {
    now().wrapping_sub(LAST_ACTIVITY.load(Ordering::Relaxed))
}

#[inline]
pub fn is_idle() -> bool {
    idle_for() > TIMEOUT_TICKS
}

/// Convenience: an `idle_check` callable suitable for `Input::wait_button`.
pub fn idle_check() -> bool {
    is_idle()
}
