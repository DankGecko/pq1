#!/usr/bin/env python3
"""Ground-truth measurement of the FIXED c10_sign_target: new baseline
signature + instruction count, to re-pin the full-sweep harness post-fix.

fcee705a (FORS-forest ht_idx binding) changes signature bytes and adds a few
instructions per sign. Old baseline sig was 3ff0ef84…; old TOTAL_EST was
6,622,918,000 — both against the VULNERABLE pre-fix binary.

  - bisect instr count  → the new TOTAL_EST for c10_sign_full_sweep.py.

Caveat: sig[:16] is R (the grind_r randomizer), invariant under the FORS fix, so
it CANNOT confirm "fixed code is linked" — confirm that via build provenance
(source has ht_idx in fors_secret AND ELF newer than source). This prints the
FORS region (byte 16+) for reference only.

No per-instruction hook (that'd be ~40 min on 6.6 B instr). Baseline is a
single native run (~54 s); the count is a fresh-emulator bisect (~8 min, each
step independent so no fault-state residue concern).

Run:  donjon-sca run tools/sca/c10_sign_measure.py
"""
import os
import sys
import time

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

from rainbow.generics import rainbow_cortexm
from unicorn import UcError

HERE = os.path.dirname(os.path.abspath(__file__))
ELF = os.path.join(HERE, "c10_sign_target", "target", "thumbv8m.main-none-eabi",
                   "release", "sca-c10-sign-target")
RET = 0xAAAA_AAAA
STACK_TOP = 0x9000_0000
_STACK_LEN = 0x10_000
MSG_ADDR = 0x6000_0000
SIG_ADDR = 0x6000_1000
SIG_LEN = 4008
BUDGET = 10_000_000_000
TEST_MSG = bytes(range(32))
FN = "sca_c10_sign_verified"

OLD_TOTAL_EST = 6_622_918_000


def fresh():
    e = rainbow_cortexm()
    e.load(ELF)
    e.map_space(STACK_TOP - _STACK_LEN, STACK_TOP + 0x20)
    return e


def setup(e):
    e.reset()
    e[STACK_TOP - _STACK_LEN] = b"\x00" * _STACK_LEN
    e["sp"] = STACK_TOP
    e[MSG_ADDR] = TEST_MSG
    e[SIG_ADDR] = b"\x00" * SIG_LEN
    e["r0"] = MSG_ADDR
    e["r1"] = SIG_ADDR
    e["lr"] = RET


def reaches_ret(count):
    """True iff the function returns within `count` instructions."""
    e = fresh()
    setup(e)
    begin = e.functions[FN][0]
    try:
        e.start(begin, RET, count=count)
    except (RuntimeError, UcError):
        return False  # crashed before RET within this budget
    return e["pc"] == RET


def main():
    if not os.path.exists(ELF):
        sys.exit(f"ELF missing: {ELF}")
    print("=== c10_sign FIXED-binary ground-truth measurement ===")
    print(f"ELF: {ELF}\n")

    # 1) Full baseline → sig + return value.
    e = fresh()
    setup(e)
    t0 = time.time()
    e.start(e.functions[FN][0], RET, count=BUDGET)
    wall = time.time() - t0
    reached = e["pc"] == RET
    r0 = e["r0"] & 0xFFFF_FFFF
    sig = bytes(e[SIG_ADDR:SIG_ADDR + SIG_LEN])
    print(f"baseline: reached RET={reached}  r0={r0} ({'Ok' if r0 == 1 else 'NOT Ok!'})  ({wall:.1f} s)")
    # NOTE: sig[0..16] is R (the grind_r randomizer), which the FORS ht_idx fix does
    # NOT change — so sig[:16] CANNOT distinguish the fixed binary from the vulnerable
    # one. The fix only changes the FORS region (byte 16+). Confirm "fixed code is
    # linked" via build provenance instead: source has the ht_idx arg in fors_secret
    # AND the ELF is newer than that source (see the pre-resume integrity check).
    print(f"  sig[:16] (= R, invariant under the FORS fix): {sig[:16].hex()}")
    print(f"  sig[16:32] (= start of FORS region, DOES change with the fix): {sig[16:32].hex()}")
    print()

    # 2) Bisect the exact instruction count (fresh emulator each step).
    print("Bisecting instruction count (fresh emulator per step)…")
    lo, hi = 1, BUDGET
    # Tighten hi quickly: if old estimate +5% still reaches RET, start there.
    probe = int(OLD_TOTAL_EST * 1.05)
    if reaches_ret(probe):
        hi = probe
        print(f"  upper bound {hi:,} reaches RET ✓")
    steps = 0
    while hi - lo > 2000:           # ±2k precision is plenty for a 500k-stride sweep
        mid = (lo + hi) // 2
        if reaches_ret(mid):
            hi = mid
        else:
            lo = mid
        steps += 1
        if steps % 4 == 0:
            print(f"    step {steps}: [{lo:,}, {hi:,}]  (window {hi-lo:,})")
    total = hi
    print(f"  instruction count ≈ {total:,}  ({steps} bisect steps)")
    print()

    delta = total - OLD_TOTAL_EST
    print(f"OLD TOTAL_EST: {OLD_TOTAL_EST:,}")
    print(f"NEW count:     {total:,}   Δ={delta:+,} ({delta/OLD_TOTAL_EST*100:+.3f}%)")
    print()
    # Conservative TOTAL_EST: round up with a small margin so the sweep covers
    # the whole function (positions past the true end return 'short', harmless).
    new_est = ((total + 99_999) // 100_000) * 100_000
    print(f">>> set TOTAL_EST = {new_est}  (rounded up from {total:,} for full coverage)")
    print(f">>> full NEW baseline sig:")
    print(sig.hex())
    return 0 if (reached and r0 == 1) else 1


if __name__ == "__main__":
    sys.exit(main())
