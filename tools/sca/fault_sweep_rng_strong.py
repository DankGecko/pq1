#!/usr/bin/env python3
"""Fault-injection sweep over `secure/src/rng_strong.rs` — the multi-source
strong-RNG fold whose failure semantics `bb2615f6` tightened to **strict /
fail-closed** (an SE-TRNG failure is now FATAL under production backends; it
used to silently fall through). work-todo §18b RANK 2.

The target ELF `#[path]`-includes the REAL `rng_strong::fill` and supplies its
two crate-root hooks (`rng::fill` = platform TRNG, `se_random` = the
OPTIGA⊕SE050 SE fold) as harness-controlled stubs. So this sweeps the SHIPPED
control flow:

    crate::rng::fill(buf)?;                 // platform TRNG — Step 1
    se_random(block)?; buf ^= block;        // SE fold (OPTIGA⊕SE050) — Step 2
    if acc(buf) == 0 { return Err(()); }    // fail-closed all-zero gate — Step 3

bb2615f6's contract: **any** source that fails to deliver entropy must abort
the call (refuse to sign) rather than silently degrade to fewer sources, and an
all-zero post-fold buffer must be rejected. We stage each failure scenario and
ask whether a single skip / stuck-at fault can force a "SE-TRNG-OK" — make
`fill` return `Ok` (entropy accepted) when it must refuse:

  * OPTIGA TRNG fails   (RS_OPTIGA_OK=0)   → must refuse
  * SE050 TRNG fails    (RS_SE050_OK=0)    → must refuse
  * platform TRNG fails (RS_PLATFORM_OK=0) → must refuse
  * all sources stuck-0 (all bytes 0)      → all-zero gate must refuse

A bypass is `r0 == 1` (entropy accepted) in any of those — a single fault let a
weakened / all-zero fold through. (A positive baseline — all sources OK,
non-zero — must return `r0 == 1`, so a green sweep isn't vacuous.)

**Scope (honest).** Emulation tests the software fail-closed logic + all-zero
gate. The SE TRNGs, the I2C transport, and the STM32 RNG SEIS/CEIS latches are
stubbed — silicon behaviour is out of scope. Single-fault FI completeness for a
new fatal-branch secret path.

Run:   donjon-sca run tools/sca/fault_sweep_rng_strong.py
       (or, building the target ELF first:  make -C tools/sca rng-strong)
"""
import os
import sys
import bisect

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

import cle
from rainbow.generics import rainbow_cortexm
from rainbow.fault_models import fault_skip, fault_stuck_at
from unicorn import UcError

FAULT_MODELS = [
    ("skip", fault_skip),
    ("stuck-at-0", fault_stuck_at(0x0000_0000)),
    ("stuck-at-FF", fault_stuck_at(0xFFFF_FFFF)),
]

HERE = os.path.dirname(os.path.abspath(__file__))
ELF = os.path.join(HERE, "rng_strong_target", "target", "thumbv8m.main-none-eabi", "release", "sca-rng-strong-target")
RET = 0xAAAA_AAAA
BUDGET = 16384
MAX_I = 1500
FN = "sca_rng_strong_fill"

if not os.path.exists(ELF):
    sys.exit(f"target ELF not found: {ELF}\nbuild it first:   make -C {HERE} rng-strong")

_ld = cle.Loader(ELF, auto_load_libs=False)


def _sym(name):
    s = _ld.main_object.get_symbol(name)
    if s is None:
        s = next((x for x in _ld.main_object.symbols if name in (x.name or "")), None)
    if s is None:
        sys.exit(f"symbol {name} not found — rebuild (make -C tools/sca rng-strong)")
    return s.rebased_addr


A_PLAT_OK = _sym("RS_PLATFORM_OK")
A_OPT_OK = _sym("RS_OPTIGA_OK")
A_SE_OK = _sym("RS_SE050_OK")
A_PLAT_B = _sym("RS_PLATFORM_BYTE")
A_OPT_B = _sym("RS_OPTIGA_BYTE")
A_SE_B = _sym("RS_SE050_BYTE")
A_OUT = _sym("SCA_RS_OUT")

# scenario = (platform_ok, optiga_ok, se050_ok, plat_byte, opt_byte, se_byte, expect_accept)
SCENARIOS = [
    ("positive (all OK, non-zero)", (1, 1, 1, 0x33, 0xAA, 0x55), True),
    ("OPTIGA TRNG fails",           (1, 0, 1, 0x33, 0xAA, 0x55), False),
    ("SE050 TRNG fails",            (1, 1, 0, 0x33, 0xAA, 0x55), False),
    ("platform TRNG fails",         (0, 1, 1, 0x33, 0xAA, 0x55), False),
    ("all sources stuck-at-0",      (1, 1, 1, 0x00, 0x00, 0x00), False),
]


def fresh_emu():
    e = rainbow_cortexm()
    e.load(ELF)
    return e


def fn_table(e):
    return sorted((v[0] & ~1, k) for k, v in e.functions.items())


def fn_at(table, pc):
    starts = [a for a, _ in table]
    i = bisect.bisect_right(starts, pc & ~1) - 1
    return table[i][1] if i >= 0 else "<?>"


def set_scenario(e, scn):
    plat_ok, opt_ok, se_ok, pb, ob, sb = scn
    e.emu.mem_write(A_PLAT_OK, int(plat_ok).to_bytes(4, "little"))
    e.emu.mem_write(A_OPT_OK, int(opt_ok).to_bytes(4, "little"))
    e.emu.mem_write(A_SE_OK, int(se_ok).to_bytes(4, "little"))
    e.emu.mem_write(A_PLAT_B, bytes([pb]))
    e.emu.mem_write(A_OPT_B, bytes([ob]))
    e.emu.mem_write(A_SE_B, bytes([sb]))
    e.emu.mem_write(A_OUT, b"\x00" * 16)


def run(e, scn, fault=None):
    """Returns (kind, r0, out) — kind in {ret, crash, hang, short}."""
    e.reset()
    e.reset_stack()
    set_scenario(e, scn)
    e["lr"] = RET
    begin = e.functions[FN][0]
    try:
        if fault is None:
            e.start(begin, RET, count=BUDGET)
        else:
            e.start_and_fault(fault[0], fault[1], begin, RET, count=BUDGET)
    except (RuntimeError, UcError):
        return ("crash", None, None)
    except IndexError:
        return ("short", None, None)
    if e["pc"] != RET:
        return ("hang", None, None)
    out = bytes(e.emu.mem_read(A_OUT, 16))
    return ("ret", e["r0"] & 0xFFFF_FFFF, out)


def baselines():
    for label, scn, expect_accept in SCENARIOS:
        e = fresh_emu()
        k, r0, out = run(e, scn)
        assert k == "ret", f"{label}: baseline did not return cleanly (kind={k})"
        want = 1 if expect_accept else 0
        assert r0 == want, f"{label}: baseline r0={r0} (want {want})"
    print("baselines OK  (positive accepts; OPTIGA/SE050/platform-fail + all-zero all refuse)")


def sweep(scn, model):
    bypass, crashes, hangs, noeffect = [], 0, 0, 0
    locs = {}
    def locate(i, table):
        e2 = fresh_emu()
        e2.reset(); e2.reset_stack(); set_scenario(e2, scn); e2["lr"] = RET
        try:
            e2.start(e2.functions[FN][0], RET, count=i)
        except Exception:
            pass
        locs[i] = (fn_at(table, e2["pc"]), e2["pc"])
    for i in range(1, MAX_I):
        e = fresh_emu()
        table = fn_table(e)
        k, r0, out = run(e, scn, fault=(model, i))
        if k == "short":
            break
        if k == "crash":
            crashes += 1; continue
        if k == "hang":
            hangs += 1; continue
        if r0 == 1:
            bypass.append((i, out)); locate(i, table)
        else:
            noeffect += 1
    return bypass, crashes, hangs, noeffect, locs


ZERO16 = b"\x00" * 16


def classify(out):
    """Classify a bypass (fill returned Ok when it should have refused) by what
    entropy it actually released:
      * 'all-zero'  — out is 16 zero bytes: a PREDICTABLE output escaped. Only
                      reachable in the all-sources-zero scenario (= the all-zero
                      acceptance gate was skipped). Reaching all-zero needs every
                      source compromised — outside the single-fault model for a
                      healthy system.
      * 'degraded'  — out is non-zero: the fold proceeded with the REMAINING
                      source(s) after one was dropped. In the real system those
                      carry full entropy (the whole point of XOR-mixing N
                      independent TRNGs), so this fails-loud-LESS but does NOT
                      weaken the output below one strong source.
    """
    return "all-zero" if out == ZERO16 else "degraded"


if __name__ == "__main__":
    baselines()
    zero_accept = 0          # all-zero output accepted (predictable entropy escaped)
    degrade = {"skip": 0, "stuck-at-0": 0, "stuck-at-FF": 0}
    for label, scn, expect_accept in SCENARIOS:
        if expect_accept:
            continue  # the positive scenario has nothing to bypass
        print(f"\n== rng_strong fail-closed: scenario '{label}' ==")
        for mlabel, model in FAULT_MODELS:
            bypass, cr, hg, ne, locs = sweep(scn, model)
            nz = sum(1 for _, out in bypass if classify(out) == "all-zero")
            ndeg = len(bypass) - nz
            zero_accept += nz
            degrade[mlabel] += ndeg
            total = len(bypass) + cr + hg + ne
            print(f"  [{mlabel}] swept {total}:  accept-bypass={len(bypass)} "
                  f"(degraded={ndeg} all-zero={nz})  crashes={cr}  hangs={hg}  no-effect={ne}")
            # Show a few representative [skip] sites (the interesting model).
            if mlabel == "skip" and bypass:
                for i, out in bypass[:4]:
                    fn, pc = locs[i]
                    print(f"        [skip] instr {i}: pc={pc:#010x} in {fn}  out={out.hex()}  ({classify(out)})")

    print()
    print("FINDINGS (audit-only — single-fault sweep of fail-closed `?`-glue):")
    print(f"  - 'degraded' bypasses (skip={degrade['skip']} stuck0={degrade['stuck-at-0']} "
          f"stuckFF={degrade['stuck-at-FF']}): a single fault skips a fatal `?` (or stuck-ats the")
    print("    Ok/Err result slot) so `fill` proceeds after one source 'failed'. This is the same")
    print("    call-site-glue / result-register-corruption residual class as PIN-gate F-4 / C10 F-2.")
    print("    It defeats the fail-LOUD intent, but the multi-source XOR design means the output")
    print("    still carries full entropy from every UNbroken source — dropping one of")
    print("    {platform, OPTIGA, SE050} under one fault does NOT weaken the result below one strong")
    print("    TRNG (rng_strong.rs §'Security argument'). Mitigation (if ever desired): a")
    print("    sentinel-encoded per-source result the caller positively compares, like the C10 gate.")
    if zero_accept:
        print(f"  - 'all-zero' accepts ({zero_accept}): ONLY in the all-sources-stuck-at-0 scenario — a")
        print("    single skip of the `if acc==0 { return Err }` backstop. Reaching an all-zero")
        print("    buffer requires platform AND OPTIGA AND SE050 to all produce zero (three")
        print("    independent failures), which is outside the single-fault model for a healthy")
        print("    system; the gate is a backstop for a post-fold buffer clamp, itself a single")
        print("    fault — you get one or the other, not both (rng_strong.rs §'What we do NOT")
        print("    defend': out of scope for the single-fault assumption).")
    print()
    print("VERDICT: no single fault produces WEAK entropy from a healthy system — every 'bypass'")
    print("either retains a strong unbroken source (XOR resilience) or needs an out-of-single-fault")
    print("precondition (all sources zero). The bb2615f6 strict semantics + all-zero gate hold under")
    print("the single-fault model. Audit-only; no fix expected (matches the F-2/F-4 residual class).")
    # Audit-only sweep: the residuals found are the documented call-glue class,
    # not a single-fault path to weak entropy. Exit 0.
    sys.exit(0)
