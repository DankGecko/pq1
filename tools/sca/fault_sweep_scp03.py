#!/usr/bin/env python3
"""Fault-injection sweep over the SE050 SCP03 response-unwrap **R-MAC verify
gate** — work-todo §18b RANK 1.

`sca_scp03_unwrap_gate` in the target ELF feeds the firmware's real
`unwrap_response` (a kept-in-sync copy of `secure/src/se050/scp03.rs`, calling
the BYTE-FOR-BYTE `aes128_cbc_decrypt` / `cmac_aes128` from
`secure/src/scp03_logic.rs`) a **forged** response:

    ciphertext( R-ENC of an attacker-chosen half_E )  ||  WRONG R-MAC (zeros)  ||  9000

An attacker who can drive the I2C bus can produce the ciphertext (it's just
AES-CBC under a key they're trying to recover) but CANNOT produce the 8-byte
R-MAC without `S-RMAC`. The lone thing standing between that forged response
and the host accepting an attacker-chosen `half_E` (invariant #1: one XOR half
of the BIP-39 seed) is the constant-time gate

    let mac_full = cmac_aes128(&session.s_rmac, &[&session.mcv, body, sw]);
    if !ct_eq_8(&mac_full[..8], rmac_recv) { return Err(RMacMismatch); }   // scp03.rs

This sweep asks: **can a single instruction-skip / dest-reg-stuck-at fault make
that gate accept the forged response** — so `unwrap_response` returns `Ok`,
R-ENC-decrypts the body, and releases the attacker's `half_E`?

Verdict signals (per fault):
  * r0 == 1            → unwrap returned Ok on a WRONG-R-MAC response = GATE BYPASS
  * SCA_SCP03_OUT[..15] == b"FORGED::half_E!"  → the attacker's half_E was
                          actually released (strong confirmation of plaintext leak)
An un-faulted baseline returns r0 == 0 (rejected) and leaves the out buffer zero.

**Scope (honest).** This audits the *software* unwrap logic + the MAC-verify
gate under single-fault models — NOT the SE050 silicon, the I2C bus physics, or
the R-MAC's cryptographic strength (forging the MAC without a fault is ~2^-64).
It is defense-in-depth completeness: a new gate-shaped secret path shouldn't
ship un-swept when C10-sign / KDF / PIN-gate / FW-verify all have harnesses.

Env knobs:
  SCP03_MAXI    upper bound on instruction positions (default 200000; the sweep
                auto-stops earlier when start_and_fault runs out of instructions)
  SCP03_STRIDE  sweep every Nth instruction (default 1 = exhaustive; raise for a
                quick smoke run)

Run:   donjon-sca run tools/sca/fault_sweep_scp03.py
       (or, building the target ELF first:  make -C tools/sca scp03-fi)
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
ELF = os.path.join(HERE, "scp03_target", "target", "thumbv8m.main-none-eabi", "release", "sca-scp03-target")
RET = 0xAAAA_AAAA
STACK_TOP = 0x9000_0000     # soft (bitsliced) AES + the 1 KB `plain` buffer need a
STACK_LEN = 0x2_0000        # real stack (128 KB); rainbow's default reset_stack is tiny
BUDGET = 2_000_000          # AES soft (bitsliced) unwrap is large; give it headroom
MAX_I = int(os.environ.get("SCP03_MAXI", "200000"))
STRIDE = max(1, int(os.environ.get("SCP03_STRIDE", "1")))
GATE_FN = "sca_scp03_unwrap_gate"
SELFTEST_FN = "sca_scp03_unwrap_valid_selftest"
ATTACKER = b"FORGED::half_E!"   # == ATTACKER_HALF_E in the target

if not os.path.exists(ELF):
    sys.exit(f"target ELF not found: {ELF}\nbuild it first:   make -C {HERE} scp03-fi")

_ld = cle.Loader(ELF, auto_load_libs=False)


def _sym_addr(name):
    s = _ld.main_object.get_symbol(name)
    if s is None:
        s = next((x for x in _ld.main_object.symbols if name in (x.name or "")), None)
    if s is None:
        sys.exit(f"could not find symbol {name} in the ELF — rebuild (make -C tools/sca scp03-fi)")
    return s.rebased_addr


OUT_ADDR = _sym_addr("SCA_SCP03_OUT")


def fresh_emu():
    e = rainbow_cortexm()
    e.load(ELF)
    e.map_space(STACK_TOP - STACK_LEN, STACK_TOP + 0x20)
    return e


def fn_table(e):
    return sorted((v[0] & ~1, k) for k, v in e.functions.items())


def fn_at(table, pc):
    starts = [a for a, _ in table]
    i = bisect.bisect_right(starts, pc & ~1) - 1
    return table[i][1] if i >= 0 else "<?>"


def released_half_e(e):
    return bytes(e.emu.mem_read(OUT_ADDR, 15))


def run_gate(e, fault=None):
    """Returns (kind, status, leaked) — kind in {ret, crash, hang, short}."""
    e.reset()
    e["sp"] = STACK_TOP
    e["r0"] = OUT_ADDR & 0xFFFF_FFFF
    e["lr"] = RET
    begin = e.functions[GATE_FN][0]
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
    return ("ret", e["r0"] & 0xFFFF_FFFF, released_half_e(e))


def selftest():
    """The target must ACCEPT a correctly-MAC'd response of the same shape and
    release the expected plaintext — otherwise the gate sweep is vacuous."""
    e = fresh_emu()
    e.reset()
    e["sp"] = STACK_TOP
    e["lr"] = RET
    try:
        e.start(e.functions[SELFTEST_FN][0], RET, count=BUDGET)
    except (RuntimeError, UcError, IndexError):
        sys.exit("selftest crashed — target is broken")
    st = e["r0"] & 0xFFFF_FFFF
    assert st == 1, f"selftest returned {st} (want 1: valid response accepted, plaintext == ATTACKER_HALF_E)"

    # And the forged (wrong-R-MAC) response MUST be rejected with no fault.
    e = fresh_emu()
    k, st, leaked = run_gate(e)
    assert k == "ret" and st == 0, f"forged-response baseline: kind={k} status={st} (want ret,0 = rejected)"
    assert leaked == b"\x00" * 15, f"forged-response baseline leaked plaintext without a fault: {leaked!r}"
    print("baselines OK  (valid R-MAC -> accepted+correct plaintext ; forged R-MAC -> rejected, no leak)")


def sweep(label, model):
    bypass, crashes, hangs, noeffect = [], 0, 0, 0
    locs = {}
    def locate(i, table):
        e2 = fresh_emu()
        e2.reset(); e2["sp"] = STACK_TOP; e2["r0"] = OUT_ADDR; e2["lr"] = RET
        try:
            e2.start(e2.functions[GATE_FN][0], RET, count=i)
        except Exception:
            pass
        locs[i] = (fn_at(table, e2["pc"]), e2["pc"])
    for i in range(1, MAX_I, STRIDE):
        e = fresh_emu()
        table = fn_table(e)
        k, st, leaked = run_gate(e, fault=(model, i))
        if k == "short":
            break
        if k == "crash":
            crashes += 1; continue
        if k == "hang":
            hangs += 1; continue
        if st == 1:
            # Gate bypassed — unwrap accepted a wrong-R-MAC response.
            leak = leaked == ATTACKER
            bypass.append((i, leak)); locate(i, table)
        else:
            noeffect += 1
    return bypass, crashes, hangs, noeffect, locs


if __name__ == "__main__":
    selftest()
    if STRIDE > 1:
        print(f"(stride={STRIDE} — smoke run, NOT exhaustive; the vulnerable instructions sit at")
        print(" specific positions a coarse stride steps over — use stride=1 for a real verdict)")

    # Classify each bypass by where the fault landed:
    #   * GENUINE   — inside `unwrap_response` (the real firmware R-MAC gate) AND
    #                 it released the attacker's half_E. This is the finding.
    #   * register  — returned Ok but no plaintext leak: result-register
    #                 corruption (the inherent F-2 class, not a gate defeat).
    #   * scaffold  — inside `build_forged_wrapped`: the harness faulting its OWN
    #                 response builder (flips it to emit a VALID-MAC response).
    #                 NOT a real attack — the attacker supplies the response on
    #                 the I2C bus; they cannot fault the firmware's builder.
    SCAFFOLD = ("build_forged_wrapped",)
    GATE = "unwrap_response"
    genuine = {"skip": [], "stuck-at-0": [], "stuck-at-FF": []}
    register = {"skip": 0, "stuck-at-0": 0, "stuck-at-FF": 0}
    scaffold = {"skip": 0, "stuck-at-0": 0, "stuck-at-FF": 0}
    for label, model in FAULT_MODELS:
        print(f"\n== SCP03 R-MAC gate: single-fault [{label}] sweep (forged response) ==")
        bypass, cr, hg, ne, locs = sweep(label, model)
        total = len(bypass) + cr + hg + ne
        for i, leak in bypass:
            fn = locs[i][0]
            if any(s in fn for s in SCAFFOLD):
                scaffold[label] += 1
            elif GATE in fn and leak:
                genuine[label].append((i, locs[i][1]))
            else:
                register[label] += 1
        print(f"  swept {total} positions:  GENUINE-gate-bypass(half_E released)={len(genuine[label])}  "
              f"register-corruption={register[label]}  harness-scaffold={scaffold[label]}  "
              f"crashes={cr}  hangs={hg}  no-effect={ne}")
        for i, pc in genuine[label]:
            print(f"        !!! [{label}] instr {i}: pc={pc:#010x} in unwrap_response — forged response ACCEPTED, half_E RELEASED")

    skip_genuine = len(genuine["skip"])
    print()
    if any(genuine[m] for m in genuine):
        print("FINDING — the SCP03 R-MAC verify gate IS single-fault-defeatable:")
        print(f"  {skip_genuine} [skip] / {len(genuine['stuck-at-0'])} [stuck0] / {len(genuine['stuck-at-FF'])} [stuckFF] "
              "single faults INSIDE unwrap_response make a forged (wrong-R-MAC)")
        print("  SE050 response get ACCEPTED and release the attacker's half_E. Unlike the C10")
        print("  verify-before-release gate (FI-hardened after F-1) and the PIN gate, the firmware's")
        print("  `unwrap_response` checks the R-MAC with a PLAIN `if !ct_eq_8(..) { return Err }` — no")
        print("  sentinel, no double-evaluate — so one instruction-skip past that branch (or a stuck-at")
        print("  that zeroes the computed MAC to match the forged all-zero R-MAC) releases the plaintext.")
        print("  Threat: bench attacker driving the I2C bus + a single glitch → host accepts a chosen")
        print("  half_E (one XOR half of the seed). Recommended fix: route the R-MAC verdict through")
        print("  fi::check_true_into_sentinel + double-evaluate, exactly like crypto.rs's C10 gate.")
        print("  (register-corruption + harness-scaffold hits above are NOT this finding — see legend.)")
    else:
        print("OK — across all 3 single-fault models, no fault inside unwrap_response makes it accept a")
        print("forged (wrong-R-MAC) SE050 response or release half_E.")
    # Exit non-zero on a GENUINE [skip] gate bypass inside unwrap_response (a real,
    # field-relevant weakness on the SE050 secret channel). Scaffold/register hits
    # do not count.
    sys.exit(1 if skip_genuine else 0)
