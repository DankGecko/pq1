//! Independent watchdog (IWDG) — USB-path hang detection.
//!
//! The USB stack runs in the **non-secure** world as a poll loop
//! (`nonsecure/src/main.rs`). A malicious or buggy host could wedge
//! that loop (e.g. an input that drives the APDU parser into an
//! infinite loop), leaving the device unresponsive with no way to
//! recover short of a power-cycle. The IWDG is the backstop: if the
//! system stops making forward progress, the watchdog resets the chip,
//! and the boot-time `reset_cause` path classifies the IWDG reset as
//! abnormal and zeroizes SRAM before re-running unlock.
//!
//! # Liveness model (why it doesn't false-fire on legit long ops)
//!
//! The IWDG is **owned + kicked by the secure world** — `init` runs in
//! secure boot, and the secure SysTick handler (1 ms cadence) calls
//! [`systick_watch_and_kick`] every tick. It keeps the watchdog fed
//! while any of three progress signals holds:
//!
//!   1. **NS heartbeat advanced** — NS bumps a counter (a `static mut`
//!      in NS SRAM, registered with us once at boot via
//!      [`register_ns_heartbeat`]) on every poll-loop iteration. A
//!      live NS loop keeps this advancing even when idle-polling.
//!   2. **A gateway handler is busy** — `nsc::handler_is_busy()` is
//!      true whenever a CMSE veneer is mid-flight. This covers the
//!      multi-second secure operations (first-sign ~3 s, batch sign,
//!      ~2 s FW-slot erase) during which NS is blocked in the veneer
//!      and therefore NOT bumping its heartbeat. Without this signal
//!      a long legit sign would look like a hang.
//!   3. **Trusted UI is waiting for a physical button** — the narrow
//!      `timeout::TrustedUiWaitGuard` is live and the 120 s inactivity
//!      timer has not expired. This prevents the 30 s compute deadline
//!      from resetting the device in the middle of a legitimate confirm
//!      dialog. The timeout condition is load-bearing: a wedged input
//!      backend stops receiving this exception once idle, then falls back
//!      to the ordinary bounded watchdog path.
//!
//! Only when all progress signals are absent for `NS_STALL_LIMIT_TICKS`
//! consecutive ticks does SysTick stop kicking, after which the IWDG
//! hardware timeout (~2 s) resets the chip. Total NS-loop-hang
//! detection ≈ `NS_STALL_LIMIT_TICKS` (4 s) + IWDG (~2 s) ≈ 6 s.
//!
//! A secure-world deadlock with interrupts disabled stops SysTick
//! entirely → no kicks → IWDG fires directly (~2 s), independent of
//! the heartbeat logic. A secure handler that spins with interrupts enabled
//! is capped by `MAX_BUSY_TICKS`. Trusted UI temporarily suspends that compute
//! deadline only while it is actually waiting for secure physical input and
//! the independent inactivity timer remains live.
//!
//! # Register access alias
//!
//! IWDG is reached via its **NS alias** (`0x4000_3000`). It defaults
//! to non-secure in the GTZC TZSC, and secure code can write NS
//! peripherals. The IWDG's hardware "cannot be stopped once started"
//! property makes NS-accessibility harmless: NS can at most *kick* it
//! (which only delays a reset), never disable it. Marking it
//! GTZC-secure is an optional follow-up (it touches the invariant-#4
//! TZSC allowlist in `sau.rs`, so it's deliberately out of scope here).
//!
//! # Feature gating
//!
//! Behind `iwdg`. **OFF for `mode-bringup` / `mode-e2e`**: a live IWDG
//! would reset the device during probe-rs breakpoints / semihosting
//! pauses. When the feature is off every entry point compiles to a
//! no-op, so call sites are safe without the flag — and crucially
//! `init` never starts the watchdog, so test builds can't self-reset.

#![allow(dead_code)]

#[cfg(feature = "iwdg")]
use crate::hw::mmio::Reg32;

// IWDG NS alias — see module doc on the alias choice.
#[cfg(feature = "iwdg")]
const IWDG: u32 = 0x4000_3000;

#[cfg(feature = "iwdg")]
struct IwdgRegs {
    kr: Reg32,  // key register   @ 0x00 (write 0xCCCC start / 0x5555 access / 0xAAAA reload)
    pr: Reg32,  // prescaler       @ 0x04
    rlr: Reg32, // reload          @ 0x08
    sr: Reg32,  // status (PVU/RVU/WVU) @ 0x0C
}

// SAFETY: each address is a real, 4-byte-aligned IWDG MMIO register,
// touched single-threaded from secure boot (`init`) and the secure
// SysTick handler (`kick` / `systick_watch_and_kick`). SysTick never
// re-enters itself, so there is no aliasing between the two writers.
#[cfg(feature = "iwdg")]
const REG: IwdgRegs = unsafe {
    IwdgRegs {
        kr: Reg32::new(IWDG + 0x00),
        pr: Reg32::new(IWDG + 0x04),
        rlr: Reg32::new(IWDG + 0x08),
        sr: Reg32::new(IWDG + 0x0C),
    }
};

#[cfg(feature = "iwdg")]
const KEY_RELOAD: u32 = 0xAAAA; // refresh the down-counter ("kick")
#[cfg(feature = "iwdg")]
const KEY_START: u32 = 0xCCCC; // start IWDG (and auto-start LSI)
#[cfg(feature = "iwdg")]
const KEY_ACCESS: u32 = 0x5555; // unlock PR/RLR for writing

// Prescaler /256 (PR=6) + reload 250 → ~2 s at the nominal 32 kHz LSI.
// LSI is ±~50% so the real timeout is ~1–3 s; that imprecision is
// irrelevant because normal operation kicks every 1 ms (SysTick) —
// orders of magnitude under even the 1 s low end. The PRECISE
// false-fire threshold is the SysTick-counted `NS_STALL_LIMIT_TICKS`,
// not this coarse hardware timeout.
#[cfg(feature = "iwdg")]
const PR_DIV_256: u32 = 6;
#[cfg(feature = "iwdg")]
const RLR_2S: u32 = 250;

// 4 s of 1 ms SysTick ticks of *no progress* (neither NS heartbeat
// advancing nor a handler busy) before we stop feeding the watchdog.
// Comfortably above any NS-side loop-body stall — every loop op
// (poll / try_receive / queue_response / poll_tx) is sub-millisecond,
// and the multi-second secure crypto is covered by `handler_is_busy()`
// — so only a genuine hang reaches this.
#[cfg(feature = "iwdg")]
const NS_STALL_LIMIT_TICKS: u32 = 4000;

// rr-2 (Trezor-port): max consecutive ticks a *busy handler* alone may feed
// the watchdog. `handler_busy` legitimately holds across a bounded window (a
// full CMD_SIGN_USEROP_BATCH: per-UserOp keygen + two FI-double-compute signs
// each) — but a handler that spins forever with its `HandlerGuard` held would
// otherwise feed the IWDG forever (the hole flagged in the module doc above)
// AND suppress the 120 s idle-wipe (which shares the `handler_busy` gate). Set
// generously (~30 s at 1 kHz SysTick) above the worst legit continuous-busy
// window so a real batch never trips it, but a wedged handler does.
#[cfg(feature = "iwdg")]
const MAX_BUSY_TICKS: u32 = 30_000;

// Heartbeat-watch state. Sole writer is the secure SysTick handler
// (single-threaded, non-reentrant) plus the one-time boot registration.
#[cfg(feature = "iwdg")]
static mut NS_HEARTBEAT_ADDR: u32 = 0; // 0 = NS hasn't registered yet
#[cfg(feature = "iwdg")]
static mut LAST_HEARTBEAT: u32 = 0;
#[cfg(feature = "iwdg")]
static mut STALL_TICKS: u32 = 0;
// rr-2: consecutive ticks fed on `handler_busy` alone (no NS heartbeat
// advance). Reset on real NS progress or when the handler goes idle.
#[cfg(feature = "iwdg")]
static mut BUSY_TICKS: u32 = 0;

/// Start the IWDG with a ~2 s timeout. Once started it CANNOT be
/// stopped (hardware property) — that's the point. Call from secure
/// boot after `setup_systick()` so SysTick is already feeding it.
#[cfg(feature = "iwdg")]
pub fn init() {
    // Freeze the IWDG counter while a debugger has the core halted
    // (DBGMCU_APB1FZR1.DBG_IWDG_STOP, bit 12). Without this, every
    // probe-rs / OpenOCD halt — breakpoint, semihosting roundtrip,
    // RTT poll, single-step — lets the LSI-clocked IWDG keep counting
    // and bite mid-debug. The bit has NO effect when no debugger is
    // attached (production), so it's safe to always set. Standard
    // practice for any IWDG-enabled firmware that's ever debugged.
    // SAFETY: single 32-bit RMW of a debug-component register
    // (DBGMCU @ 0xE0044000, APB1FZR1 @ +0x08), accessible from secure.
    unsafe {
        const DBGMCU_APB1FZR1: *mut u32 = (0xE004_4000u32 + 0x08) as *mut u32;
        const DBG_IWDG_STOP: u32 = 1 << 12;
        let v = core::ptr::read_volatile(DBGMCU_APB1FZR1);
        core::ptr::write_volatile(DBGMCU_APB1FZR1, v | DBG_IWDG_STOP);
    }

    // Start first (also auto-starts the LSI clock), then unlock +
    // program prescaler/reload, wait for the LSI-domain update to
    // settle, and take the first explicit reload. The default 0.5 s
    // timeout (PR=/4, RLR=0xFFF) gives ample margin to finish this
    // config before the first bite.
    REG.kr.write(KEY_START);
    REG.kr.write(KEY_ACCESS);
    REG.pr.write(PR_DIV_256);
    REG.rlr.write(RLR_2S);
    // Wait for PVU | RVU | WVU (SR bits 2:0) to clear — the new
    // prescaler/reload have propagated to the LSI clock domain.
    while REG.sr.read() & 0b111 != 0 {
        core::hint::spin_loop();
    }
    REG.kr.write(KEY_RELOAD);
}

/// Refresh the watchdog counter. Safe to call any time after [`init`].
#[cfg(feature = "iwdg")]
#[inline]
pub fn kick() {
    REG.kr.write(KEY_RELOAD);
}

/// Register the NS heartbeat counter address (called once, via a CMSE
/// veneer, from NS boot). Returns `true` if the address validated as a
/// 4-byte-aligned location inside NS SRAM and was stored.
#[cfg(feature = "iwdg")]
pub fn register_ns_heartbeat(addr: u32) -> bool {
    use sphincs_tz_shared::{NS_SRAM_BASE, NS_SRAM_END};
    if addr & 0x3 != 0 || addr < NS_SRAM_BASE || addr.saturating_add(4) > NS_SRAM_END {
        return false;
    }
    // SAFETY: single-threaded boot-time registration; SysTick (the only
    // other accessor) reads this with a volatile load.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(NS_HEARTBEAT_ADDR), addr);
    }
    true
}

/// Called from the secure SysTick handler every ~1 ms. Feeds the IWDG
/// while the system is making progress; stops feeding after
/// `NS_STALL_LIMIT_TICKS` ticks of no progress so the watchdog resets a
/// hung device. The secure-state booleans are passed in rather than reaching
/// across modules from inside the ISR. `trusted_ui_waiting` is accepted as
/// progress only while `idle_timed_out == false`; it therefore cannot turn a
/// leaked UI guard into an unbounded watchdog feed.
#[cfg(feature = "iwdg")]
pub fn systick_watch_and_kick(handler_busy: bool, trusted_ui_waiting: bool, idle_timed_out: bool) {
    // SAFETY: SysTick is the sole runtime writer of these statics and
    // does not re-enter itself; the boot registration of
    // `NS_HEARTBEAT_ADDR` has completed by the time NS is running.
    unsafe {
        let addr = core::ptr::read_volatile(core::ptr::addr_of!(NS_HEARTBEAT_ADDR));
        if addr == 0 {
            // Boot grace: NS hasn't registered its heartbeat yet. Keep
            // the watchdog fed so the boot window doesn't trip it.
            kick();
            return;
        }
        // Read the NS heartbeat (secure reading an NS SRAM address —
        // permitted; the address was range-validated at registration).
        let hb = core::ptr::read_volatile(addr as *const u32);
        let last = core::ptr::read_volatile(core::ptr::addr_of!(LAST_HEARTBEAT));

        if hb != last {
            // Genuine NS forward progress (NS looped) — reset both timers.
            core::ptr::write_volatile(core::ptr::addr_of_mut!(LAST_HEARTBEAT), hb);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(STALL_TICKS), 0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(BUSY_TICKS), 0);
            kick();
        } else if trusted_ui_waiting && !idle_timed_out {
            // A secure confirmation dialog is making intentional progress by
            // waiting for a human. Reset both machine-stall counters so the
            // 30 s compute deadline cannot false-fire during the documented
            // 120 s UI window. Only real secure UI code can hold the guard,
            // and it does not reset LAST_ACTIVITY; once the inactivity timer
            // expires this branch becomes unreachable and a wedged input
            // backend is reset by the normal handler/NS bound below.
            core::ptr::write_volatile(core::ptr::addr_of_mut!(STALL_TICKS), 0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(BUSY_TICKS), 0);
            kick();
        } else if handler_busy {
            // A secure veneer is mid-flight — NS is blocked in the gateway so
            // its heartbeat can't advance. Legitimate for a BOUNDED window,
            // but rr-2: cap it, or a wedged handler holding its `HandlerGuard`
            // feeds the watchdog forever. `handler_busy` is NOT an NS stall,
            // so reset STALL_TICKS; count busy ticks separately.
            core::ptr::write_volatile(core::ptr::addr_of_mut!(STALL_TICKS), 0);
            let b = core::ptr::read_volatile(core::ptr::addr_of!(BUSY_TICKS))
                .saturating_add(1);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(BUSY_TICKS), b);
            if b < MAX_BUSY_TICKS {
                kick();
            } else if b == MAX_BUSY_TICKS {
                secure_log!(
                    "[S][iwdg] BUSY LIMIT hit (b={}) — handler wedged busy, stopping kicks, IWDG will fire",
                    b
                );
            }
            // else: busy past the cap → stop feeding → IWDG fires.
        } else {
            // No NS progress and no busy handler → NS-loop stall.
            core::ptr::write_volatile(core::ptr::addr_of_mut!(BUSY_TICKS), 0);
            let s = core::ptr::read_volatile(core::ptr::addr_of!(STALL_TICKS))
                .saturating_add(1);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(STALL_TICKS), s);
            if s < NS_STALL_LIMIT_TICKS {
                // Still within the grace window — keep feeding.
                kick();
            } else if s == NS_STALL_LIMIT_TICKS {
                // DIAGNOSTIC: about to stop feeding — IWDG will reset
                // in ~2 s. Logged once at the threshold crossing so we
                // can tell a real stall from flaky USB. hb/last captured
                // for the post-mortem.
                secure_log!(
                    "[S][iwdg] STALL LIMIT hit (s={}) hb=0x{:08x} last=0x{:08x} — stopping kicks, IWDG will fire",
                    s, hb, last
                );
            }
            // else: stalled past the limit → stop feeding → IWDG fires.
        }
    }
}

// ---------------------------------------------------------------------------
// No-op stubs when the feature is off. `init` deliberately does NOT
// start the watchdog, so a non-`iwdg` build (every test build) can
// never self-reset.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "iwdg"))]
pub fn init() {}
#[cfg(not(feature = "iwdg"))]
#[inline]
pub fn kick() {}
#[cfg(not(feature = "iwdg"))]
pub fn register_ns_heartbeat(_addr: u32) -> bool {
    false
}
#[cfg(not(feature = "iwdg"))]
pub fn systick_watch_and_kick(
    _handler_busy: bool,
    _trusted_ui_waiting: bool,
    _idle_timed_out: bool,
) {
}
