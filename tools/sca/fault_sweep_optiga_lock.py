#!/usr/bin/env python3
"""Fault-injection sweep over the OPTIGA **LcsO-ratchet read-back gate** —
`verify_and_lock` (`secure/src/optiga/mod.rs:731-768`), the verify-before-lock
gate the S-1/S-2/S-3 provisioning hardening relies on. work-todo §18b RANK 3.

`verify_and_lock` is the single chokepoint before every **irreversible**
`LcsO=Operational` ratchet. The OPTIGA silently accepts SetMetadata APDUs
carrying access-condition constructs it won't honour, so the firmware reads the
metadata back and confirms the exact AC bytes landed before freezing them:

    n = get_metadata(oid, &mut stored)?;
    if is_metadata_operational(stored, n) { return Ok }   // idempotent skip
    if !metadata_matches_expected(stored, n, expected) {   // THE GATE
        return Err(Status(0xEB));                          // fail closed, no lock
    }
    lock_oid(oid)                                          // irreversible ratchet

The target ELF copies the pure metadata parser/comparator VERBATIM from
`apdu.rs` and stubs the I2C round-trips (`get_metadata` returns a
harness-selected stored buffer; `lock_oid` sets `OPTIGA_LOCK_FIRED`).

Scenario MISMATCH (the chip silently kept `Change=ALW` instead of the intended
`Change=Auto(F1D0)`): the gate MUST refuse to lock (`return 0`, `LOCK_FIRED=0`).
The FI question: can a single fault make the irreversible ratchet fire anyway —
`OPTIGA_LOCK_FIRED == 1` — freezing a chip whose AC didn't land (bricking it
with the wrong, possibly all-deny, permissions)?

Verdict signals per fault (MISMATCH scenario):
  * OPTIGA_LOCK_FIRED == 1  → THE IRREVERSIBLE RATCHET FIRED on an unverified
                              chip = the genuine bad outcome.
  * return == 1, LOCK_FIRED == 0 → result-register-corruption only (the stubbed
                              lock never ran) — the benign F-2 class.

**Scope (honest).** Emulation tests the software readback-verify-then-lock
logic. The OPTIGA's own LcsO sequencing, the I2C transport, and the SetMetadata
silent-accept quirk are stubbed — silicon behaviour is out of scope.

Run:   donjon-sca run tools/sca/fault_sweep_optiga_lock.py
       (or, building the target ELF first:  make -C tools/sca optiga-lock)
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
ELF = os.path.join(HERE, "optiga_lock_target", "target", "thumbv8m.main-none-eabi", "release", "sca-optiga-lock-target")
RET = 0xAAAA_AAAA
BUDGET = 8192
MAX_I = 1200
FN = "sca_optiga_verify_and_lock"

if not os.path.exists(ELF):
    sys.exit(f"target ELF not found: {ELF}\nbuild it first:   make -C {HERE} optiga-lock")

_ld = cle.Loader(ELF, auto_load_libs=False)


def _sym(name):
    s = _ld.main_object.get_symbol(name)
    if s is None:
        s = next((x for x in _ld.main_object.symbols if name in (x.name or "")), None)
    if s is None:
        sys.exit(f"symbol {name} not found — rebuild (make -C tools/sca optiga-lock)")
    return s.rebased_addr


A_SEL = _sym("OPTIGA_STORED_SEL")
A_LOCK = _sym("OPTIGA_LOCK_FIRED")

# (label, sel, expect_return, expect_lock)
SCENARIOS = [
    ("MISMATCH (AC silently didn't land)", 0, 0, 0),
    ("MATCH (AC verified)",                1, 1, 1),
    ("already OPERATIONAL (idempotent)",   2, 2, 0),
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


def lock_fired(e):
    return int.from_bytes(e.emu.mem_read(A_LOCK, 4), "little")


def run(e, sel, fault=None):
    """Returns (kind, ret, locked) — kind in {ret, crash, hang, short}."""
    e.reset()
    e.reset_stack()
    e.emu.mem_write(A_SEL, int(sel).to_bytes(4, "little"))
    e.emu.mem_write(A_LOCK, b"\x00\x00\x00\x00")
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
        return ("hang", None, lock_fired(e))
    return ("ret", e["r0"] & 0xFFFF_FFFF, lock_fired(e))


def baselines():
    for label, sel, exp_ret, exp_lock in SCENARIOS:
        e = fresh_emu()
        k, ret, locked = run(e, sel)
        assert k == "ret", f"{label}: baseline kind={k}"
        assert ret == exp_ret and locked == exp_lock, \
            f"{label}: baseline ret={ret} lock={locked} (want {exp_ret},{exp_lock})"
    print("baselines OK  (mismatch→refuse,no-lock ; match→lock ; operational→skip,no-lock)")


def sweep(sel, model):
    real_lock, corrupt_ret, crashes, hangs, noeffect = [], [], 0, 0, 0
    locs = {}
    def locate(i, table):
        e2 = fresh_emu()
        e2.reset(); e2.reset_stack()
        e2.emu.mem_write(A_SEL, int(sel).to_bytes(4, "little"))
        e2.emu.mem_write(A_LOCK, b"\x00\x00\x00\x00")
        e2["lr"] = RET
        try:
            e2.start(e2.functions[FN][0], RET, count=i)
        except Exception:
            pass
        locs[i] = (fn_at(table, e2["pc"]), e2["pc"])
    for i in range(1, MAX_I):
        e = fresh_emu()
        table = fn_table(e)
        k, ret, locked = run(e, sel, fault=(model, i))
        if k == "short":
            break
        if k == "crash":
            crashes += 1; continue
        if k == "hang":
            hangs += 1; continue
        if locked == 1:
            real_lock.append(i); locate(i, table)       # irreversible ratchet fired — bad
        elif ret == 1:
            corrupt_ret.append(i); locate(i, table)      # r0 corruption only — benign
        else:
            noeffect += 1
    return real_lock, corrupt_ret, crashes, hangs, noeffect, locs


if __name__ == "__main__":
    baselines()
    fired = {"skip": 0, "stuck-at-0": 0, "stuck-at-FF": 0}
    # Only the MISMATCH scenario has something to bypass (lock a chip whose AC
    # was not confirmed). MATCH/OPERATIONAL are positive-direction baselines.
    sel = 0
    label = SCENARIOS[0][0]
    print(f"\n== OPTIGA verify_and_lock: scenario '{label}' ==")
    for mlabel, model in FAULT_MODELS:
        real_lock, corrupt_ret, cr, hg, ne, locs = sweep(sel, model)
        fired[mlabel] = len(real_lock)
        total = len(real_lock) + len(corrupt_ret) + cr + hg + ne
        print(f"  [{mlabel}] swept {total}:  RATCHET-FIRED={len(real_lock)}  "
              f"r0-corrupt-only={len(corrupt_ret)}  crashes={cr}  hangs={hg}  no-effect={ne}")
        # Show a few representative [skip] sites (the model that matters).
        if mlabel == "skip" and real_lock:
            for i in real_lock[:5]:
                fn, pc = locs[i]
                print(f"        [skip] instr {i}: pc={pc:#010x} in {fn} — LcsO ratchet fired on unverified AC")

    print()
    print("FINDING (audit-only): the readback-verify-then-lock gate is single-fault-defeatable —")
    print(f"  {fired['skip']} [skip] / {fired['stuck-at-0']} [stuck0] / {fired['stuck-at-FF']} [stuckFF] "
          "single faults make verify_and_lock fire the irreversible")
    print("  LcsO ratchet on a chip whose AC readback did NOT match the intent. The gate is a plain")
    print("  branch with no FI redundancy (sentinel / double-evaluate), so this is expected.")
    print()
    print("RISK CONTEXT (why this is low-priority, exit 0):")
    print("  - verify_and_lock runs at PROVISIONING time, ONCE per OID, in the trusted PQ1 factory")
    print("    (PQ1-factory-HSM-controlled) — NOT on any per-signature / field-attacker hot path.")
    print("  - Its purpose is to catch the OPTIGA's SILENT-AC-REJECT *quirk* (a correctness issue),")
    print("    not to resist an adversary: an attacker who can glitch the bench during provisioning")
    print("    already controls the provisioning process. So a fault here is a YIELD/reliability event")
    print("    (a glitched bench bricks a part with the wrong AC, caught by post-provisioning QA), not")
    print("    a field-exploitable security bypass.")
    print("  - Hardening (route the readback-verify through fi::check_true_into_sentinel +")
    print("    double-evaluate before lock_oid, like the C10 gate) is available if a hostile-")
    print("    provisioning threat model is ever in scope; not warranted under the current one.")
    # Audit-only, provisioning-time, trusted-factory path: report but do not fail.
    sys.exit(0)
