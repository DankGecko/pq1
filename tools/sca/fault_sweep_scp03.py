#!/usr/bin/env python3
"""Fault-injection sweep over the SE050 SCP03 response-unwrap **R-MAC verify
gate** — work-todo §18b RANK 1.

`sca_scp03_unwrap_gate` in the target ELF feeds the firmware's real
`unwrap_response` (a kept-in-sync copy of `secure/src/se050/scp03.rs`, calling
the BYTE-FOR-BYTE `aes128_cbc_decrypt` / `cmac_aes128` /
`verify_rmac_into` from `secure/src/scp03_logic.rs`) a **forged** response:

    ciphertext( R-ENC of the COMPLEMENT of an attacker-chosen half_E )
        ||  WRONG R-MAC (zeros)  ||  9000

An attacker who can drive the I2C bus can produce the ciphertext (it's just
AES-CBC under a key they're trying to recover) but CANNOT produce the 8-byte
R-MAC without `S-RMAC`. The lone thing standing between that forged response
and the host accepting an attacker-chosen `half_E` (invariant #1: one XOR half
of the BIP-39 seed) is the R-MAC authentication-receipt gate

    verify_rmac_into(.. two independent full R-MAC recomputations ..) → receipt
    if read_volatile(receipt) != OK_SENTINEL { return Err }   // twice, scp03.rs

The forged frame carries the **complement** of the desired payload because the
LEGACY F-28 gate (pre-2026-08-03) folded an R-MAC mismatch into the released
bytes as XOR-0xFF — a public bijection that turned exactly this frame into the
attacker's chosen plaintext after a single fault skipped the early rejection
(the wave-17 GPT-5.6 blocker). The reworked gate publishes a fail-initialized
receipt instead and never complements the output, so ANY acceptance that
releases `half_E` is a genuine bypass.

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
# Optional subset for parallel runs: SCP03_MODELS="skip" / "stuck-at-0,stuck-at-FF".
if os.environ.get("SCP03_MODELS"):
    _want = set(os.environ["SCP03_MODELS"].split(","))
    FAULT_MODELS = [(l, m) for (l, m) in FAULT_MODELS if l in _want]

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
VALID3_FN = "sca_scp03_unwrap_valid3_gate"
WIT3_FN = "sca_scp03_valid3_witness"
ATTACKER = b"FORGED::half_E!"   # == ATTACKER_HALF_E in the target
# The valid3 frame's expected release (TLV 0x41 0x1e || 30 bytes) + SW — must
# match valid3_expected() in the target. A single fault that makes the valid3
# gate return Ok with anything else is a corrupted release (the wave-18
# decrypt-writeback class the R-ENC relation receipt must now reject).
VALID3_EXPECTED = bytes([0x41, 0x1E] + [0xA0 + i for i in range(30)]) + b"\x90\x00"

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


def run_valid3(e, fault=None):
    """Like run_gate but for the VALID frame: returns (kind, status, out[0:34]).
    A corrupted release is (ret, 1) with out != VALID3_EXPECTED."""
    e.reset()
    e["sp"] = STACK_TOP
    e["r0"] = OUT_ADDR & 0xFFFF_FFFF
    e["lr"] = RET
    begin = e.functions[VALID3_FN][0]
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
    return ("ret", e["r0"] & 0xFFFF_FFFF, bytes(e.emu.mem_read(OUT_ADDR, 34)))


def valid3_baseline():
    """The valid 3-block frame must unwrap to the expected plaintext+SW, and the
    witness must agree with the script's hardcoded expectation."""
    e = fresh_emu()
    k, st, out = run_valid3(e)
    assert (k, st) == ("ret", 1), f"valid3 baseline rejected: {k} {st} (gate must accept)"
    assert out == VALID3_EXPECTED, f"valid3 baseline wrong release: {out.hex()} != {VALID3_EXPECTED.hex()}"
    # Witness cross-check (expected plaintext at [0..32], ciphertext at [32..80]).
    e = fresh_emu()
    e.reset(); e["sp"] = STACK_TOP; e["r0"] = OUT_ADDR; e["lr"] = RET
    try:
        e.start(e.functions[WIT3_FN][0], RET, count=BUDGET)
    except (RuntimeError, UcError, IndexError):
        sys.exit("valid3 witness crashed — target is broken")
    wit = bytes(e.emu.mem_read(OUT_ADDR, 80))
    assert wit[:32] == VALID3_EXPECTED[:32], f"witness/expectation mismatch: {wit[:32].hex()}"
    print("valid3 baseline OK  (valid frame -> Ok + expected plaintext + 9000)")


def valid3_phase_bounds():
    """Execution-index bounds splitting the valid3 gate into harness phases.
    The shared AES/CMAC code runs in ALL phases, so fn-name classification
    cannot separate them; index bounds can:
      [0, unwrap_start)          — build_valid3_wrapped (harness frame builder)
      [unwrap_start, unwrap_end) — unwrap_response (the real firmware path)
      [unwrap_end, ...)          — the harness's own out readback
    Returns (unwrap_start_idx, unwrap_end_idx)."""
    from unicorn import UC_HOOK_CODE
    import re as _re
    import subprocess
    unwrap_start = _sym_addr("unwrap_response") & ~1  # cle carries the Thumb bit; PCs are even
    # Return address = the instruction after `bl unwrap_response` in the gate.
    objdump = subprocess.run(
        ["arm-none-eabi-objdump", "-d", ELF], capture_output=True, text=True, check=True
    ).stdout
    ret_addr = None
    in_gate = False
    for line in objdump.splitlines():
        if f"<{VALID3_FN}>:" in line:
            in_gate = True
            continue
        if in_gate and line.strip().endswith(">:"):
            in_gate = False
        m = _re.match(r"\s*([0-9a-f]+):.*\bbl\s+([0-9a-f]+)\s+<[^>]*unwrap_response>", line)
        if in_gate and m:
            ret_addr = int(m.group(1), 16) + 4
            break
    assert ret_addr is not None, "could not find bl unwrap_response in the valid3 gate"
    state = {"count": 0, "start_idx": None, "end_idx": None}

    def hook(uc, address, size, _e):
        state["count"] += 1
        if address == unwrap_start and state["start_idx"] is None:
            state["start_idx"] = state["count"]
        if address == ret_addr and state["start_idx"] is not None and state["end_idx"] is None:
            state["end_idx"] = state["count"]

    e = fresh_emu()
    e.reset(); e["sp"] = STACK_TOP; e["r0"] = OUT_ADDR; e["lr"] = RET
    e.emu.hook_add(UC_HOOK_CODE, hook, user_data=e)
    try:
        e.start(e.functions[VALID3_FN][0], RET, count=BUDGET)
    except (RuntimeError, UcError, IndexError):
        sys.exit("phase-bounds run crashed — target is broken")
    assert state["start_idx"] is not None and state["end_idx"] is not None, \
        f"could not bound unwrap phase: {state}"
    return state["start_idx"], state["end_idx"]


def sweep_valid3(label, model):
    """Sweep the VALID frame: a release is recorded whenever unwrap returns Ok
    with bytes != VALID3_EXPECTED. The CALLER-SIDE classification then splits:
      * genuine      — downstream-ACCEPTED corruption: SW still 0x9000, TLV
                       header intact, but the random bytes differ (the only
                       shape that substitutes unauthenticated entropy).
      * availability — Ok with a corrupted return length (downstream slice
                       underflow → panic) or corrupted SW (!= 0x9000 →
                       send_apdu returns Err). Both fail CLOSED (halt/Err),
                       never a substituted release — the inherent F-2
                       result-register class, not a gate defeat."""
    corrupted, crashes, hangs, clean = [], 0, 0, 0
    locs = {}
    def locate(i, table):
        e2 = fresh_emu()
        e2.reset(); e2["sp"] = STACK_TOP; e2["r0"] = OUT_ADDR; e2["lr"] = RET
        try:
            e2.start(e2.functions[VALID3_FN][0], RET, count=i)
        except Exception:
            pass
        locs[i] = (fn_at(table, e2["pc"]), e2["pc"])
    start = int(os.environ.get("SCP03_V3_START", "1"))
    max_i = int(os.environ.get("SCP03_V3_MAXI", str(MAX_I)))
    for i in range(max(1, start), max_i, STRIDE):
        e = fresh_emu()
        table = fn_table(e)
        k, st, out = run_valid3(e, fault=(model, i))
        if k == "short":
            break
        if k == "crash":
            crashes += 1; continue
        if k == "hang":
            hangs += 1; continue
        if st == 1:
            if out != VALID3_EXPECTED:
                corrupted.append((i, out)); locate(i, table)
            else:
                clean += 1
        else:
            clean += 1  # rejected (r0 == 0) — correct fail-closed behavior
    return corrupted, crashes, hangs, clean, locs


if __name__ == "__main__":
    selftest()
    valid3_baseline()
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

    # ---- Phase 2: VALID frame — no single fault may corrupt the release ----
    # A corrupted release is Ok with out != expected. Classification by
    # execution-phase index bounds (shared AES code runs in every phase, so
    # fn names cannot separate them):
    #   * scaffold — fault inside build_valid3_wrapped (the harness's OWN
    #     frame builder) or the harness's own out readback: an attacker
    #     cannot fault either.
    #   * genuine — fault inside unwrap_response (the real firmware path):
    #     the firmware released bytes it did not authenticate.
    v3_start, v3_end = valid3_phase_bounds()
    print(f"(valid3 phase bounds: unwrap executes at indices {v3_start}..{v3_end})")
    v3_genuine = {"skip": [], "stuck-at-0": [], "stuck-at-FF": []}
    v3_scaffold = {"skip": 0, "stuck-at-0": 0, "stuck-at-FF": 0}
    v3_avail = {"skip": 0, "stuck-at-0": 0, "stuck-at-FF": 0}
    for label, model in FAULT_MODELS:
        print(f"\n== SCP03 release fidelity: single-fault [{label}] sweep (valid response) ==")
        corrupted, cr, hg, cl, locs = sweep_valid3(label, model)
        total = len(corrupted) + cr + hg + cl
        for i, out in corrupted:
            # Downstream-accepted corruption: valid SW + intact TLV header +
            # wrong random bytes. Anything else (bad SW, corrupted length)
            # fails closed at send_apdu (Err) or the secure-world panic.
            downstream_accepted = (
                out[32:34] == b"\x90\x00" and out[0] == 0x41 and out[1] == 0x1E
                and out[2:32] != VALID3_EXPECTED[2:32]
            )
            if not downstream_accepted:
                v3_avail[label] += 1
            elif i < v3_start or i >= v3_end:
                v3_scaffold[label] += 1
            else:
                v3_genuine[label].append((i, locs[i][0], locs[i][1], out))
        print(f"  swept {total} positions:  GENUINE-corrupted-release={len(v3_genuine[label])}  "
              f"availability-fail-closed={v3_avail[label]}  harness-scaffold={v3_scaffold[label]}  "
              f"crashes={cr}  hangs={hg}  clean-or-rejected={cl}")
        for i, fn, pc, out in v3_genuine[label][:8]:
            print(f"        !!! [{label}] instr {i}: pc={pc:#010x} in {fn} — Ok with out={out.hex()}")

    skip_genuine = len(genuine["skip"])
    v3_skip_genuine = len(v3_genuine["skip"])
    print()
    if any(genuine[m] for m in genuine):
        print("FINDING — the SCP03 R-MAC authentication-receipt gate IS single-fault-defeatable:")
        print(f"  {skip_genuine} [skip] / {len(genuine['stuck-at-0'])} [stuck0] / {len(genuine['stuck-at-FF'])} [stuckFF] "
              "single faults INSIDE unwrap_response make a forged (wrong-R-MAC)")
        print("  SE050 response get ACCEPTED and release the attacker's half_E. The F-28-rework gate")
        print("  (fail-initialized receipt from two independent full R-MAC recomputations in")
        print("  verify_rmac_into, re-checked by two volatile reads before any copy/counter/Ok)")
        print("  must reject this frame: one fault should defeat at most one recomputation or one")
        print("  check, never both. A genuine hit means the duplication was collapsed (LTO) or a")
        print("  check/publication is missing — re-inspect the optimized disassembly of")
        print("  pqsigner_se050_scp03_rmac_verify_into and the caller gate in unwrap_response.")
        print("  Threat: bench attacker driving the I2C bus + a single glitch → host accepts a chosen")
        print("  half_E (one XOR half of the seed). (register-corruption + harness-scaffold hits above")
        print("  are NOT this finding — see legend.)")
    else:
        print("OK — across all 3 single-fault models, no fault inside unwrap_response makes it accept a")
        print("forged (wrong-R-MAC) SE050 response or release half_E.")
    if any(v3_genuine[m] for m in v3_genuine):
        print("FINDING — the SCP03 release path IS single-fault-corruptible on a VALID frame:")
        print(f"  {v3_skip_genuine} [skip] / {len(v3_genuine['stuck-at-0'])} [stuck0] / {len(v3_genuine['stuck-at-FF'])} [stuckFF] "
              "single faults make unwrap_response return Ok with bytes that are NOT the")
        print("  authenticated plaintext while the downstream SW/TLV checks still accept (e.g.")
        print("  bus-visible ciphertext in place of TRNG output). The R-ENC relation receipt")
        print("  (pqsigner_se050_scp03_renc_verify_into) and the receipt-bound rng_exact::copy_exact")
        print("  release must fail closed here. Threat: one glitch during a GetRandom unwrap")
        print("  substitutes attacker-known bytes for the SE050 entropy contribution.")
    else:
        print("OK — across all 3 single-fault models, no fault makes a VALID frame release bytes that")
        print("the downstream SW/TLV checks accept while differing from the authenticated plaintext.")
        print(f"(availability-class Ok-corruptions that fail closed downstream — corrupted return length")
        print(f"or SW: {sum(v3_avail.values())} total; these are the inherent F-2 result-register class.)")
    # Exit non-zero on a GENUINE [skip] gate bypass or a GENUINE [skip] corrupted
    # release (real, field-relevant weaknesses on the SE050 secret channel).
    # Scaffold/register hits do not count.
    sys.exit(1 if (skip_genuine or v3_skip_genuine) else 0)
