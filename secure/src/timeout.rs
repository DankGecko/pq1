//! Inactivity timeout / activity tracking.
//!
//! `tick()` is called once per SysTick (~1 ms). `reset_activity()` is called
//! whenever real user input occurs (button press, successful PIN entry,
//! confirmed sign). `is_idle()` returns true after [`TIMEOUT_TICKS`] ticks
//! have elapsed without activity, and is checked from any blocking dialog so
//! it can interrupt them and trigger a wipe.
//!
//! Trusted confirmation dialogs also expose a scoped
//! [`TrustedUiWaitGuard`]. The secure watchdog uses that signal to distinguish
//! a healthy handler deliberately waiting for a physical button from a
//! handler wedged in crypto / parsing / flash. The signal never resets the
//! inactivity timer: once [`is_idle`] becomes true, the watchdog resumes its
//! ordinary bounded-stall policy even if a broken input backend failed to
//! return from the dialog.
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

/// Nesting depth of secure trusted-UI button waits.
///
/// Only secure UI code can acquire this guard; NS has no writer. A depth
/// counter rather than a boolean makes nested trusted dialogs fail-safe: an
/// inner guard dropping cannot accidentally clear an outer wait. This state
/// is watchdog bookkeeping only and grants no signing/update authority.
static TRUSTED_UI_WAIT_DEPTH: AtomicU32 = AtomicU32::new(0);

/// RAII marker for the narrow interval in which trusted UI is blocked waiting
/// for a physical button event.
///
/// Keep the guard around the input wait only, not rendering, parsing, crypto,
/// or flash. Those noninteractive operations remain subject to the watchdog's
/// normal busy-handler deadline.
pub struct TrustedUiWaitGuard;

impl TrustedUiWaitGuard {
    #[must_use]
    pub fn enter() -> Self {
        TRUSTED_UI_WAIT_DEPTH.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for TrustedUiWaitGuard {
    fn drop(&mut self) {
        // Saturating CAS mirrors HandlerGuard: underflow is impossible in safe
        // Rust, but must never wrap into an effectively permanent UI-wait
        // authorization if the implementation changes later.
        let mut cur = TRUSTED_UI_WAIT_DEPTH.load(Ordering::SeqCst);
        loop {
            let next = cur.saturating_sub(1);
            match TRUSTED_UI_WAIT_DEPTH.compare_exchange_weak(
                cur,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
    }
}

/// Whether secure code is currently blocked on a trusted physical input.
///
/// The watchdog additionally requires `!is_idle()` before treating this as
/// progress, so a leaked/wedged wait is still bounded.
#[inline]
pub fn trusted_ui_is_waiting() -> bool {
    TRUSTED_UI_WAIT_DEPTH.load(Ordering::SeqCst) > 0
}

/// Clear any outstanding trusted-UI marker during lock / panic / tamper
/// zeroization.
///
/// Firmware uses panic=abort, so RAII destructors do not run on those paths.
/// Clearing explicitly prevents a panic inside `wait_button` from extending
/// watchdog feeding until the inactivity deadline. Later guard drops use a
/// saturating decrement and therefore remain safe after this emergency clear.
#[inline]
pub fn clear_trusted_ui_wait() {
    TRUSTED_UI_WAIT_DEPTH.store(0, Ordering::SeqCst);
}

#[inline]
pub fn now() -> u32 {
    TICKS.load(Ordering::Relaxed)
}

/// Raw pointer to the underlying `TICKS` word. Used by callers that
/// want to apply `fi::read_volatile_voted` against the same word —
/// triple-read with fences to defend a single-fault glitch on the
/// `ldr` instruction that would otherwise return an attacker-clamped
/// value. The `AtomicU32` API doesn't expose the underlying address
/// directly, so we surface it explicitly here.
#[inline]
pub fn ticks_ptr() -> *const u32 {
    TICKS.as_ptr() as *const u32
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
