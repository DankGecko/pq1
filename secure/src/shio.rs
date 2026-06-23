//! Resilient semihosting host-stdout writer (QEMU / dev builds only).
//!
//! Drop-in replacement for the output half of
//! `cortex_m_semihosting::hprintln!` that does **not** busy-spin when
//! QEMU's chardev-backed `SYS_WRITE` reports "0 bytes written".
//!
//! **The bug this fixes.** `cortex_m_semihosting::hio::write_all` loops
//! ```ignore
//!   n if n <= buffer.len() => { let off = buffer.len() - n; buffer = &buffer[off..]; }
//! ```
//! When the semihosting `SYS_WRITE` returns `n == buffer.len()` (i.e.
//! the host accepted **zero** bytes), `off == 0`, `buffer` is unchanged,
//! and the loop spins forever at 100 % CPU. QEMU returns exactly that
//! when its `-chardev` write side is wedged — which `make e2e` triggers
//! by running `qemu … </dev/null`: the stdio chardev gets an immediate
//! stdin EOF, and once QEMU's I/O thread services the HUP the chardev
//! stops accepting output. The first high-volume burst after that point
//! (the `show_progress("C10 sign", …)` frames during signing) then
//! wedges the guest — the "make e2e hangs forever during C10 sign"
//! report. The signing math is fine; only the log output spins.
//!
//! **The fix.** Detect the no-forward-progress case, retry a bounded
//! number of times to absorb a transient stall, then **drop** the rest
//! of the line. Dropping a few diagnostic bytes is correct here: this is
//! QEMU/dev-only output and a wedged chardev will never drain, so the
//! only alternatives are "drop" or "hang".

#![allow(dead_code)] // some helpers unused depending on UI/feature config

use core::fmt;
use core::sync::atomic::{AtomicIsize, Ordering};
use cortex_m::interrupt;
use cortex_m_semihosting::{nr, syscall};

/// Sentinel for "host stdout fd not opened yet". Real fds are >= 0; a
/// failed `SYS_OPEN` returns -1, which we store and then short-circuit on.
const FD_UNOPENED: isize = -2;

/// Cached host-stdout (`:tt`) fd. Opened once, lazily.
static HOST_FD: AtomicIsize = AtomicIsize::new(FD_UNOPENED);

/// Return the cached host-stdout fd, opening `:tt` on first use.
///
/// A benign double-open under (non-existent, single-core S-world)
/// concurrency would just leak one fd; not worth a lock.
fn fd() -> isize {
    let cur = HOST_FD.load(Ordering::Relaxed);
    if cur != FD_UNOPENED {
        return cur;
    }
    let name = b":tt\0";
    // SAFETY: ARM semihosting SYS_OPEN with a static, NUL-terminated name
    // and a valid mode; returns the fd (>=0) or -1 on failure.
    let opened =
        unsafe { syscall!(OPEN, name.as_ptr(), nr::open::W_TRUNC, name.len() - 1) } as isize;
    HOST_FD.store(opened, Ordering::Relaxed);
    opened
}

/// Resilient `SYS_WRITE` loop: like `hio::write_all` but bails on
/// no-progress instead of spinning forever.
fn write_bytes(fd: isize, mut buf: &[u8]) {
    if fd < 0 {
        return; // SYS_OPEN failed earlier — nowhere to write.
    }
    let fd = fd as usize;
    let mut stalls: u32 = 0;
    while !buf.is_empty() {
        // SYS_WRITE returns the number of bytes that were NOT written
        // (0 == fully written).
        // SAFETY: `buf` is a valid slice for the duration of the call.
        let not_written = unsafe { syscall!(WRITE, fd, buf.as_ptr(), buf.len()) };
        if not_written == 0 {
            return; // all bytes accepted
        }
        if not_written > buf.len() {
            // Error sentinel (e.g. JLink returns -1..-15 as a huge
            // usize). Nothing actionable — drop the rest.
            return;
        }
        if not_written == buf.len() {
            // Zero forward progress: the chardev is wedged. Absorb a
            // brief transient stall, then DROP instead of spinning — the
            // whole point of this module.
            stalls += 1;
            if stalls >= 4 {
                return;
            }
            continue;
        }
        // Partial write: advance past the accepted prefix and continue.
        stalls = 0;
        let written = buf.len() - not_written;
        buf = &buf[written..];
    }
}

/// Sink adapter so `core::fmt` can format directly into the resilient
/// writer without an intermediate heap/stack buffer.
struct Sink {
    fd: isize,
}

impl fmt::Write for Sink {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_bytes(self.fd, s.as_bytes());
        Ok(())
    }
}

/// Write `s` verbatim (no trailing newline).
pub fn print_str(s: &str) {
    interrupt::free(|_| write_bytes(fd(), s.as_bytes()));
}

/// `hprintln!`-equivalent: write the formatted arguments followed by a
/// newline. Resilient to a wedged QEMU chardev (drops rather than hangs).
pub fn println(args: fmt::Arguments) {
    interrupt::free(|_| {
        let mut sink = Sink { fd: fd() };
        let _ = fmt::Write::write_fmt(&mut sink, args);
        write_bytes(sink.fd, b"\n");
    });
}
