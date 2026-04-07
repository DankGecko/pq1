#!/usr/bin/env python3
"""
Two-button hardware-wallet emulator front-end.

The QEMU mock UI exposes a 16x4 OLED + two physical buttons. This wrapper
maps your laptop's arrow keys to those buttons so the demo feels like a
real hardware wallet:

    ←  alone         Left button, short tap   (back / prev / scroll)
    →  alone         Right button, short tap  (next / scroll)
    ← + →  together  CONFIRM                  (long-press right; advance / OK)
    Esc              CANCEL                   (long-press left; back out)
    Ctrl-C           Quit

"Both arrows together" is detected as two arrow keypresses arriving within
~150 ms of each other, since terminals can't actually report simultaneous
keys. Tap them at the same time and it feels right.

Under the hood this script just translates the keystrokes to the existing
single-char protocol the semihosting backend already understands
(`h`/`l`/`L`/`H`), spawns QEMU as a subprocess, and forwards QEMU's
framebox output back to the terminal with CRLF translation (because the
terminal is in raw mode while you're playing).
"""

import os
import select
import subprocess
import sys
import termios
import threading
import time
import tty
from pathlib import Path

# How long to wait after the first arrow key to see if the OTHER arrow
# arrives — defines what "press both at once" means in practice. 150 ms is
# comfortably above human inter-finger jitter and well below the perception
# threshold for "this feels laggy".
CHORD_WINDOW = 0.15  # seconds

REPO_ROOT = Path(__file__).resolve().parent.parent
SECURE_ELF = (
    REPO_ROOT / "target" / "secure" / "thumbv8m.main-none-eabi" / "release" / "sphincs-tz-secure"
)
NONSECURE_ELF = (
    REPO_ROOT / "target" / "nonsecure" / "thumbv8m.main-none-eabi" / "release" / "sphincs-tz-nonsecure"
)

BANNER = """\
================================================================
  SPHINCS+ Wallet — two-button hardware emulation
================================================================
   <-           Left button  (back / prev / scroll down)
   ->           Right button (next / scroll up)
   <- + ->      CONFIRM      (press both arrows together)
   Esc          CANCEL       (back out one step)
   Ctrl-C       Quit

  Booting QEMU... terminal is in raw mode until QEMU exits.
================================================================
"""


def must_have_binaries():
    if not SECURE_ELF.exists() or not NONSECURE_ELF.exists():
        sys.stderr.write(
            "wallet_run: build artifacts not found.\n"
            "  Run `make all` first, then try again.\n"
        )
        sys.exit(1)


def spawn_qemu():
    return subprocess.Popen(
        [
            "qemu-system-arm",
            "-M", "mps2-an505",
            "-monitor", "null",
            "-serial", "null",
            "-chardev", "stdio,id=hostio",
            "-semihosting-config", "enable=on,target=native,chardev=hostio",
            "-kernel", str(SECURE_ELF),
            "-device", f"loader,file={NONSECURE_ELF}",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        # Put QEMU in its own process group so a Ctrl-C delivered to the
        # terminal (which we trap in raw mode anyway) cannot kill QEMU
        # before we have a chance to clean up.
        preexec_fn=os.setsid,
    )


def forward_qemu_output(qemu_stdout, stop_event):
    """Read QEMU's framebox bytes, translate \\n -> \\r\\n for raw-mode
    terminal display, write to our stdout."""
    out = sys.stdout.buffer
    while not stop_event.is_set():
        try:
            b = qemu_stdout.read(1)
        except (ValueError, OSError):
            break
        if not b:
            break
        if b == b"\n":
            out.write(b"\r\n")
        else:
            out.write(b)
        try:
            out.flush()
        except BrokenPipeError:
            break


def read_one_event(fd, timeout):
    """Read at most one logical key event with the given timeout (seconds).

    Returns one of:
        ('left',)        — left arrow
        ('right',)       — right arrow
        ('cancel',)      — Esc
        ('quit',)        — Ctrl-C / EOF
        None             — timeout
    """
    rlist, _, _ = select.select([fd], [], [], timeout)
    if not rlist:
        return None
    try:
        b = os.read(fd, 1)
    except OSError:
        return ('quit',)
    if not b:
        return ('quit',)
    c = b[0]
    if c == 0x03:  # Ctrl-C
        return ('quit',)
    if c == 0x1b:  # ESC — possibly start of an arrow escape sequence
        # Wait briefly for the rest of the sequence. If nothing comes, treat
        # it as a standalone Esc (= cancel).
        rlist, _, _ = select.select([fd], [], [], 0.08)
        if not rlist:
            return ('cancel',)
        try:
            b2 = os.read(fd, 1)
        except OSError:
            return ('cancel',)
        if b2 not in (b"[", b"O"):  # CSI or SS3 (application-keypad mode)
            return ('cancel',)
        rlist, _, _ = select.select([fd], [], [], 0.08)
        if not rlist:
            return ('cancel',)
        try:
            b3 = os.read(fd, 1)
        except OSError:
            return ('cancel',)
        if b3 == b"D":
            return ('left',)
        if b3 == b"C":
            return ('right',)
        # Other arrow / function key — drop silently.
        return None
    # Any other byte: drop. We deliberately do NOT pass through h/l/L/H so
    # this script is the only input source while running.
    return None


def main():
    must_have_binaries()

    fd = sys.stdin.fileno()
    if not os.isatty(fd):
        sys.stderr.write("wallet_run: stdin must be a TTY (run from a real terminal)\n")
        sys.exit(1)

    sys.stdout.write(BANNER)
    sys.stdout.flush()
    time.sleep(0.4)

    old_termios = termios.tcgetattr(fd)
    qemu = None
    stop_event = threading.Event()
    forwarder = None

    try:
        tty.setcbreak(fd)
        qemu = spawn_qemu()
        forwarder = threading.Thread(
            target=forward_qemu_output,
            args=(qemu.stdout, stop_event),
            daemon=True,
        )
        forwarder.start()

        def emit(byte: str):
            try:
                qemu.stdin.write(byte.encode())
                qemu.stdin.flush()
            except (BrokenPipeError, ValueError, OSError):
                pass

        # Chord state: we hold a single arrow press for up to CHORD_WINDOW
        # seconds to see if the other one is about to arrive.
        pending = None  # 'left' or 'right'
        pending_until = 0.0

        while True:
            if qemu.poll() is not None:
                break
            if pending is None:
                timeout = 0.2  # poll qemu liveness occasionally
            else:
                remaining = pending_until - time.monotonic()
                timeout = max(0.0, remaining)

            ev = read_one_event(fd, timeout)

            if ev is None:
                # Timeout. If a pending arrow has aged out, flush it as a
                # plain short tap.
                if pending is not None and time.monotonic() >= pending_until:
                    emit('h' if pending == 'left' else 'l')
                    pending = None
                continue

            kind = ev[0]
            if kind == 'quit':
                break
            if kind == 'cancel':
                if pending is not None:
                    emit('h' if pending == 'left' else 'l')
                    pending = None
                emit('H')  # Long-press Left = cancel / back
                continue
            if kind in ('left', 'right'):
                if pending is None:
                    pending = kind
                    pending_until = time.monotonic() + CHORD_WINDOW
                elif pending != kind:
                    # Both arrows within the window → CHORD = confirm
                    emit('L')  # Long-press Right = confirm
                    pending = None
                else:
                    # Same arrow twice — flush the first as a single tap and
                    # start a new pending window for the second. Lets the
                    # user mash one arrow without paying CHORD_WINDOW per
                    # press for everything except the very last tap.
                    emit('h' if pending == 'left' else 'l')
                    pending = kind
                    pending_until = time.monotonic() + CHORD_WINDOW
    finally:
        stop_event.set()
        # Drain any final QEMU output before restoring the terminal so the
        # final "Wallet ready" / framebox makes it to the screen.
        if qemu is not None:
            try:
                qemu.stdin.close()
            except Exception:
                pass
            try:
                qemu.wait(timeout=2)
            except subprocess.TimeoutExpired:
                qemu.terminate()
                try:
                    qemu.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    qemu.kill()
        if forwarder is not None:
            forwarder.join(timeout=1)
        termios.tcsetattr(fd, termios.TCSADRAIN, old_termios)
        sys.stdout.write("\r\n")
        sys.stdout.flush()


if __name__ == '__main__':
    main()
