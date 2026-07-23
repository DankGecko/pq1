#!/usr/bin/env python3
"""verify-sphincs-digest-field-order — SOURCE-level Rust<->Solidity<->Lean
field-order pin for the digest the firmware actually signs (FV surface
`actual-signed-digest-correspondence`, roadmap P1.7; the F2 fix; the Lean leg
was added 2026-07-19 for FV deep review F6).

WHY. The firmware signs `aa::userop::compute_sphincs_digest_v06` — a single
SHA-256 over a 360-byte preimage of 12 fields. The on-chain
`PQSmartWallet.sol::sphincsDigest` recomputes the SAME digest with SHA-256 over
`abi.encodePacked(...)` of the SAME 12 fields, and the Lean model the
`theft_free` family quantifies over hand-mirrors them in
`ValidateUserOp.lean::sphincsDigestPreimage`. Their agreement on a Rust-
generated vector is checked in Forge (`PQSmartWalletRealSig.t.sol`), and the
on-chain digest's sensitivity to every field is checked in
`SphincsDigestFieldBinding.t.sol`. But a vector KAT cannot see a *source*
divergence that a fresh vector regeneration would also carry (e.g. someone swaps
two gas fields in the Rust `chain_update` chain AND regenerates the vectors) —
the sources would then disagree structurally while every committed
vector still matched. This gate pins the three field ORDERS against each other
at the source, so a one-sided reorder/insert/delete in ANY of the three fails
CI before any vector. The Lean leg exists because nothing else machine-pinned
the model's preimage: an equal-width swap in `sphincsDigestPreimage` used to
pass `lake build`, the ledger gate, the closure pins, and this lint.

Same tier as the repo's other transcription gates (`check_c10_transcription.py`):
a regression pin, not a proof. Pure source parse, no toolchain.

SCOPE (F9). This pins the field SEQUENCE and the field->preimage mapping across
the Rust, Solidity, and Lean sources; it does NOT prove
`chain_update`/`abi.encodePacked`/the Lean `ByteVec` concatenation produce
byte-identical preimages (that rests on the sha2 streaming==concat +
abi.encodePacked packing rules + the Lean ByteVec defs, named assumptions — the
Forge differential vector is the byte-level cross-check). And it is NOT the
(stronger, blocked) Aeneas ∀-over-layout extraction of the digest.

Exit 0 = the three field orders match; 1 = drift; 2 = parse/usage error.
`--self-test` reorders a copy of each side and asserts the check fires.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]
RUST = REPO_ROOT / "aa" / "src" / "userop.rs"
SOL = REPO_ROOT / "contracts" / "smart-wallet" / "src" / "PQSmartWallet.sol"
LEAN = (REPO_ROOT / "contracts" / "verification" / "lean" /
        "SphincsCVerify" / "Wallet" / "ValidateUserOp.lean")

# The canonical 12-field preimage order (firmware compute_sphincs_digest_v06).
CANON_ORDER = [
    "sender", "nonce", "init_code_digest", "call_data_digest",
    "call_gas_limit", "verification_gas_limit", "pre_verification_gas",
    "max_fee_per_gas", "max_priority_fee_per_gas", "paymaster_and_data_digest",
    "entry_point", "chain_id",
]


def canon(token: str) -> str | None:
    """Map a Rust `chain_update(arg)` or Solidity `abi.encodePacked` element to a
    canonical field name. Ordered most-specific-first so overlapping substrings
    (pre_verification vs verification, max_priority vs max_fee, call_data vs
    call_gas) resolve correctly."""
    t = re.sub(r"[^a-z0-9]", "", token.lower())
    t = (t.replace("userop", "").replace("params", "").replace("sha256", "")
          .replace("address", "").replace("block", "").replace("u64towordbe", ""))
    checks = [
        ("sender", "sender"),
        ("nonce", "nonce"),
        ("initcode", "init_code_digest"),
        ("calldata", "call_data_digest"),
        ("callgas", "call_gas_limit"),
        ("preverification", "pre_verification_gas"),
        ("verificationgas", "verification_gas_limit"),
        ("maxpriority", "max_priority_fee_per_gas"),
        ("maxfee", "max_fee_per_gas"),
        ("paymaster", "paymaster_and_data_digest"),
        ("entrypoint", "entry_point"),
        ("chainid", "chain_id"),
    ]
    for needle, name in checks:
        if needle in t:
            return name
    return None


def _balanced_args(s: str, open_at: int) -> tuple[list[str], int]:
    """Given `s` and the index of an opening '(', return (top-level comma-split
    args, index-after-close). Respects nested parens."""
    assert s[open_at] == "("
    depth = 0
    args: list[str] = []
    cur = []
    i = open_at
    while i < len(s):
        c = s[i]
        if c == "(":
            depth += 1
            if depth > 1:
                cur.append(c)
        elif c == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(cur).strip())
                return [a for a in args if a], i + 1
            cur.append(c)
        elif c == "," and depth == 1:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    raise ValueError("unbalanced parens")


def extract_rust_order(src: str) -> list[str]:
    m = re.search(r"pub fn compute_sphincs_digest_v06\b", src)
    if not m:
        raise ValueError("compute_sphincs_digest_v06 not found in Rust source")
    body = src[m.start():m.start() + 2000]
    fields = []
    for cu in re.finditer(r"\.chain_update\(", body):
        args, _ = _balanced_args(body, cu.end() - 1)
        fields.append(args[0])
        if len(fields) >= 12:
            break
    return [canon(f) for f in fields]


def extract_sol_order(src: str) -> list[str]:
    m = re.search(r"function sphincsDigest\b", src)
    if not m:
        raise ValueError("sphincsDigest not found in Solidity source")
    body = src[m.start():m.start() + 1500]
    ep = body.find("abi.encodePacked(")
    if ep < 0:
        raise ValueError("abi.encodePacked not found in sphincsDigest")
    args, _ = _balanced_args(body, ep + len("abi.encodePacked"))
    return [canon(a) for a in args]


def extract_lean_order(src: str) -> list[str]:
    """Parse `sphincsDigestPreimage`'s `++`-concatenated operand sequence into
    canonical field names. The body starts after the `ByteVec.cast (by decide)
    <|` prefix and each operand is one of: `op.sender`, `ByteVec.natToB32 op.x`,
    `sha256OfArr op.x`, `entryPoint`, `ByteVec.natToB32 chainId` — after
    stripping the wrappers, `canon` resolves the same names as the other legs."""
    m = re.search(r"def sphincsDigestPreimage\b", src)
    if not m:
        raise ValueError("sphincsDigestPreimage not found in Lean source")
    nxt = src.find("\n/--", m.end())
    body = src[m.end(): nxt if nxt > 0 else m.end() + 2000]
    cast = body.find("<|")
    if cast < 0:
        raise ValueError("sphincsDigestPreimage body not found (`<|` prefix missing)")
    fields = []
    for part in body[cast + 2:].split("++"):
        operand = (part.replace("ByteVec.natToB32", "")
                       .replace("sha256OfArr", "")
                       .replace("op.", "").strip())
        if operand:
            fields.append(operand)
    return [canon(f) for f in fields]


def compare(rust: list[str], sol: list[str], lean: list[str]) -> list[str]:
    fails = []
    for label, side in (("Rust", rust), ("Solidity", sol), ("Lean", lean)):
        if None in side:
            fails.append(f"{label}: an unrecognised field (mapped to None): {side}")
        if side != CANON_ORDER:
            fails.append(f"{label} field order != canonical.\n  {label.lower():8s} = {side}\n"
                         f"  canon    = {CANON_ORDER}")
    if rust != sol or rust != lean:
        fails.append(f"Rust vs Solidity vs Lean field order DRIFT.\n  rust = {rust}\n"
                     f"  sol  = {sol}\n  lean = {lean}")
    return fails


def self_test() -> int:
    print("=== check_sphincs_digest_field_order --self-test (negative control) ===")
    rust = extract_rust_order(RUST.read_text())
    sol = extract_sol_order(SOL.read_text())
    lean = extract_lean_order(LEAN.read_text())
    ok = True
    # control: the real sources must match
    if compare(rust, sol, lean):
        print("  FAIL: clean sources do NOT match — the pin is stale, reconcile first"); ok = False
    else:
        print("  ok: clean Rust/Solidity/Lean field orders match the canonical 12-field sequence")
    # negative: swap two adjacent gas fields on the Solidity side -> must fire
    sol_swapped = sol[:]
    i = CANON_ORDER.index("max_fee_per_gas"); j = CANON_ORDER.index("max_priority_fee_per_gas")
    sol_swapped[i], sol_swapped[j] = sol_swapped[j], sol_swapped[i]
    if compare(rust, sol_swapped, lean):
        print("  ok: a max_fee/max_priority swap on the Solidity side is CAUGHT")
    else:
        print("  FAIL: a field-order swap was NOT caught — the pin is vacuous!"); ok = False
    # negative: drop a field on the Rust side -> must fire
    if compare(rust[:-1], sol, lean):
        print("  ok: a dropped field (length mismatch) is CAUGHT")
    else:
        print("  FAIL: a dropped field was NOT caught!"); ok = False
    # negative: swap two gas fields on the Lean side -> must fire (the F6 gap)
    lean_swapped = lean[:]
    i = CANON_ORDER.index("call_gas_limit"); j = CANON_ORDER.index("verification_gas_limit")
    lean_swapped[i], lean_swapped[j] = lean_swapped[j], lean_swapped[i]
    if compare(rust, sol, lean_swapped):
        print("  ok: a call_gas/verification_gas swap on the Lean side is CAUGHT")
    else:
        print("  FAIL: a Lean field-order swap was NOT caught — the F6 gap persists!"); ok = False
    print("=== self-test PASS ===" if ok else "=== self-test FAILED ===")
    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    try:
        rust = extract_rust_order(RUST.read_text(encoding="utf-8"))
        sol = extract_sol_order(SOL.read_text(encoding="utf-8"))
        lean = extract_lean_order(LEAN.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    fails = compare(rust, sol, lean)
    print("=== verify-sphincs-digest-field-order (Rust compute_sphincs_digest_v06 <-> "
          "Solidity sphincsDigest <-> Lean sphincsDigestPreimage) ===")
    print(f"  Rust order:     {rust}")
    print(f"  Solidity order: {sol}")
    print(f"  Lean order:     {lean}")
    if fails:
        print(f"\nFAIL: {len(fails)} field-order divergence(s):", file=sys.stderr)
        for f in fails:
            print(f"  - {f}", file=sys.stderr)
        print("\nThe digest the firmware signs, the digest the wallet recomputes on-chain, "
              "and the digest the Lean model quantifies over no longer list the same fields "
              "in the same order. A regenerated vector would hide this. Reconcile "
              "aa/src/userop.rs, PQSmartWallet.sol::sphincsDigest, and "
              "ValidateUserOp.lean::sphincsDigestPreimage.", file=sys.stderr)
        return 1
    print("\nOK: the firmware-signed, on-chain-recomputed, and Lean-model digests share "
          "the exact 12-field preimage order (source-level pin).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
