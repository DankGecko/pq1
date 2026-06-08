#!/usr/bin/env python3
"""C10-sign FI baseline probe — measure the REAL per-emulation cost on this
box before committing to a full sweep, and reveal whether `start_and_fault`
runs at native unicorn speed or adds per-instruction Python overhead.

The answer decides the full-sweep architecture:
  - faulted run ≈ baseline, ~flat across fault position  → native `count=`;
    each fault costs ~one full emulation regardless of where it lands → a
    NAIVE parallel sweep (each worker runs start→RET, no snapshot) is fine.
  - faulted run >> baseline (and/or scales with fault index)  → a Python
    per-instruction hook dominates → naive is infeasible; need snapshot/
    restore so the bulk of the run is native and only a short tail is faulted.

Run:  donjon-sca run tools/sca/c10_sign_baseline_probe.py
"""
import os
import sys
import time

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

from rainbow.generics import rainbow_cortexm
from rainbow.fault_models import fault_skip
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
COUNT_BUDGET = 10_000_000_000
TEST_MSG = bytes(range(32))
# Hardcoded in fault_sweep_c10_sign.py (measured 2026-05-18 via bisect):
TOTAL_EST = 6_622_918_000


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


def main():
    if not os.path.exists(ELF):
        sys.exit(f"ELF missing: {ELF}\n  build it: make -C {HERE} build-c10-sign")
    fn = "sca_c10_sign_verified"

    print("=== C10-sign FI baseline probe ===")
    print(f"ELF: {ELF}\n")

    # 1) Baseline: one full unfaulted emulation (no hooks → native unicorn).
    e = fresh()
    setup(e)
    begin = e.functions[fn][0]
    t0 = time.time()
    e.start(begin, RET, count=COUNT_BUDGET)
    base_t = time.time() - t0
    ret = e["pc"] == RET
    sig = bytes(e[SIG_ADDR:SIG_ADDR + SIG_LEN])
    print(f"[baseline] full sign+verify+gate: {base_t:6.1f} s   "
          f"(reached RET: {ret}, r0={e['r0'] & 0xFFFFFFFF}, sig[:8]={sig[:8].hex()})")
    print(f"           native rate ≈ {TOTAL_EST / base_t / 1e6:,.0f} M instr/s "
          f"(over the {TOTAL_EST:,}-instr estimate)\n")

    # 2) Faulted emulations at early / mid / late positions.
    #    If start_and_fault is native, all three ≈ base_t (run start→RET regardless).
    #    If a per-instruction Python hook dominates, these are >> base_t.
    print("[faulted] fault_skip at three positions (cost vs baseline reveals the mechanism):")
    rows = []
    for label, frac in [("1%", 0.01), ("50%", 0.50), ("99%", 0.99)]:
        idx = int(TOTAL_EST * frac)
        e = fresh()
        setup(e)
        t0 = time.time()
        try:
            e.start_and_fault(fault_skip, idx, begin, RET, count=COUNT_BUDGET)
            outcome = f"ret r0={e['r0'] & 0xFFFFFFFF}, RET:{e['pc'] == RET}"
        except (RuntimeError, UcError):
            outcome = f"crash@{e['pc']:#x}"
        except IndexError:
            outcome = "short (idx past end)"
        ft = time.time() - t0
        rows.append(ft)
        print(f"          idx {idx:>13,} ({label:>3}): {ft:6.1f} s  "
              f"({ft / base_t:4.1f}× baseline)  [{outcome}]")

    avg_fault = sum(rows) / len(rows)
    print()
    print("=== verdict ===")
    if avg_fault <= base_t * 1.5:
        print(f"NATIVE: faulted runs ≈ baseline ({avg_fault:.1f}s vs {base_t:.1f}s). "
              f"start_and_fault uses native count=; no per-instr Python hook.")
        print(f"  → NAIVE parallel sweep is fine: each fault ≈ {base_t:.0f}s, fully independent.")
        print(f"  → est. wall for N positions × 3 models on W workers: "
              f"N×3×{base_t:.0f}/W s.  e.g. N=10k, W=30 → "
              f"{10000 * 3 * base_t / 30 / 3600:.1f} h.")
    else:
        print(f"HOOKED: faulted runs >> baseline ({avg_fault:.1f}s vs {base_t:.1f}s, "
              f"{avg_fault / base_t:.0f}×). A per-instruction Python hook dominates.")
        print(f"  → naive is infeasible; the full sweep needs snapshot/restore so only a")
        print(f"    short tail past each snapshot is faulted (existing harness machinery).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
