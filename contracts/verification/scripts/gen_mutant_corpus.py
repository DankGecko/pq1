#!/usr/bin/env python3
"""Generate the shared adversarial mutant corpus for the A3.1 functional
layer (GAP-1 hardening: mutant-level Lean <-> bytecode parity).

Mirrors the mutation classes of the on-bytecode wrong-accept screen
(`SPHINCsC10AsmAdversarial.t.sol`) and adds targeted classes for the two
historic GAP-1 defect sites (the WOTS chain-pos ADRS field is exercised
by every functional mutant; the calldataload straddling-read tail
[3992, 4008) gets a dense stride-1 sweep; both per-layer count fields get
exhaustive byte flips).

Expected results are computed with the Yul-replica oracle from
`gap1_differential.py` (validated 10/10 = the bytecode function on the
KAT corpus) and then INDEPENDENTLY asserted against the deployed
bytecode by `test/SPHINCsC10AsmMutantCorpus.t.sol` (forge) — so the
committed corpus carries true bytecode ground truth. The Lean executable
`lake exe verify-mutant-corpus` replays the same corpus through
`Spec.Signature.verify` as a HARD CHECK.

Output: contracts/smart-wallet/test/c10_mutant_corpus.json
JSON keys inside each entry are emitted in ALPHABETICAL order because
forge's `vm.parseJson` -> `abi.decode(.., (Entry[]))` coerces object
fields in alphabetical key order.

Deterministic: no randomness; re-running reproduces the file byte-for-byte.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from gap1_differential import yul_verify, hx  # noqa: E402

VECTORS_JSON = os.path.normpath(os.path.join(
    HERE, "../../smart-wallet/test/c10_test_vectors.json"))
OUT = os.path.normpath(os.path.join(
    HERE, "../../smart-wallet/test/c10_mutant_corpus.json"))

SIG_LEN = 4008


def stride(pos: int, n: int) -> int:
    """The adversarial test's mutation schedule (stride 4 over the binding
    head [0,128) and the top-Merkle tail [n-64, n), stride 64 elsewhere)."""
    if pos < 128 or pos >= n - 64:
        return 4
    return 64


def schedule(n: int):
    pos = 0
    while pos < n:
        yield pos
        pos += stride(pos, n)


def main():
    data = json.load(open(VECTORS_JSON))
    base = data["vectors"][0]
    assert base["label"] == "valid-1" and base["expectValid"]
    pk_seed = hx(base["pkSeed"])
    pk_root = hx(base["pkRoot"])
    message = hx(base["message"])
    sig = bytearray(hx(base["signature"]))
    assert len(sig) == SIG_LEN

    entries = []

    def add(label, s=pk_seed, r=pk_root, m=message, sg=None):
        sg = bytes(sg if sg is not None else sig)
        res = yul_verify(s, r, m, sg)
        entries.append({
            "expectValid": res is True,
            "label": label,
            "message": "0x" + m.hex(),
            "pkRoot": "0x" + r.hex(),
            "pkSeed": "0x" + s.hex(),
            "signature": "0x" + sg.hex(),
        })

    # Positive controls: all four valid vectors, unmutated. A corpus pass
    # cannot be vacuous (reject-everything would fail these).
    for v in data["vectors"]:
        if v["expectValid"]:
            add(f"positive-control-{v['label']}",
                hx(v["pkSeed"]), hx(v["pkRoot"]), hx(v["message"]),
                hx(v["signature"]))

    # Class 1: single-byte flips (xor 0xFF) on the adversarial schedule.
    for pos in schedule(SIG_LEN):
        mut = bytearray(sig)
        mut[pos] ^= 0xFF
        add(f"byteflip-{pos}", sg=mut)

    # Class 2: single-bit flips (xor 0x01) on the same schedule.
    for pos in schedule(SIG_LEN):
        mut = bytearray(sig)
        mut[pos] ^= 0x01
        add(f"bitflip-{pos}", sg=mut)

    # Class 3: whole-region zeroing (same 8 windows as the bytecode screen).
    offs = [0, 32, 800, 1600, 2400, 3000, 3600, 3976]
    lens = [32, 256, 256, 256, 256, 256, 256, 32]
    for off, ln in zip(offs, lens):
        mut = bytearray(sig)
        for i in range(ln):
            if off + i < SIG_LEN:
                mut[off + i] = 0
        add(f"zeroregion-{off}", sg=mut)

    # Class 4: degenerate signatures.
    add("degenerate-allzero", sg=bytes(SIG_LEN))
    add("degenerate-allff", sg=b"\xff" * SIG_LEN)
    tail = bytearray(sig)
    for i in range(SIG_LEN - 1024, SIG_LEN):
        tail[i] = 0
    add("degenerate-tailzero", sg=tail)

    # Class 5: key / message perturbation (top-byte flips stay inside the
    # N-mask so rejection comes from the functional layer, not the input
    # gate — the mask gate itself is owned by the Halmos input-gate rules
    # and is NOT modelled at the Spec.Signature.verify level, so
    # mask-violating keys are deliberately excluded from this corpus).
    add("perturb-pkSeed-top",
        s=bytes([pk_seed[0] ^ 0x01]) + pk_seed[1:])
    add("perturb-pkRoot-top",
        r=bytes([pk_root[0] ^ 0x01]) + pk_root[1:])
    add("perturb-message-lastbyte",
        m=message[:31] + bytes([message[31] ^ 0x01]))

    # Class 6 (GAP-1 defect-site regression): dense stride-1 byte flips
    # across the calldataload straddling-read tail [3992, 4008) — the
    # layer-1 final Merkle sibling that loadWord32 used to zero out.
    for pos in range(3992, 4008):
        mut = bytearray(sig)
        mut[pos] ^= 0xFF
        add(f"strad-tail-byteflip-{pos}", sg=mut)

    # Class 7: exhaustive byte flips of both per-layer WOTS+C count fields
    # (layer 0 at 2336+688, layer 1 at 3172+688) — drives the digit-sum
    # gate / revert path on the bytecode and the `none` path in Lean.
    for layer, base_off in ((0, 2336 + 688), (1, 3172 + 688)):
        for i in range(4):
            mut = bytearray(sig)
            mut[base_off + i] ^= 0xFF
            add(f"countflip-L{layer}-byte{i}", sg=mut)

    # Sanity: every non-positive entry must be a reject (wrong-accepts in
    # the ORACLE would silently weaken the corpus).
    n_pos = sum(1 for e in entries if e["expectValid"])
    assert n_pos == 4, f"expected exactly the 4 positive controls, got {n_pos}"

    with open(OUT, "w") as f:
        json.dump({"entries": entries}, f, indent=0, sort_keys=True)
        f.write("\n")
    print(f"wrote {OUT}: {len(entries)} entries "
          f"({n_pos} positive controls, {len(entries) - n_pos} rejects)")


if __name__ == "__main__":
    main()
