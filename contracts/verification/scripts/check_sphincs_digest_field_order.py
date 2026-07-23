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
vector still matched. This gate pins the three field ORDERS and exact source
expressions against each other, so a one-sided reorder/insert/delete or an
expression that merely contains a familiar field name fails CI before any
vector. The parsers require one exact function signature and the complete
Rust/Solidity body to equal the canonical returned digest expression; alternate
update APIs, wrappers, overload decoys, early returns, and after-12 truncation
therefore fail. The Lean leg exists because nothing else
machine-pinned the model's preimage: an equal-width swap in
`sphincsDigestPreimage` used to pass `lake build`, the ledger gate, the closure
pins, and this lint.

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
`--self-test` exercises reorder/drop controls plus parser-level 13th-field,
compound-expression, decoy/overload, alternate-update, and early-return controls.
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


def _normalise_expr(token: str) -> str:
    """Ignore formatting whitespace only; semantic punctuation stays pinned."""
    return re.sub(r"\s+", "", token)


RUST_FIELDS = {
    _normalise_expr(expr): field
    for expr, field in zip((
        "params.sender",
        "params.nonce.0",
        "params.init_code_digest",
        "call_data_digest",
        "params.call_gas_limit.0",
        "params.verification_gas_limit.0",
        "params.pre_verification_gas.0",
        "params.max_fee_per_gas.0",
        "params.max_priority_fee_per_gas.0",
        "params.paymaster_and_data_digest",
        "params.entry_point",
        "u64_to_word_be(params.chain_id)",
    ), CANON_ORDER)
}
SOL_FIELDS = {
    _normalise_expr(expr): field
    for expr, field in zip((
        "userOp.sender",
        "userOp.nonce",
        "sha256(userOp.initCode)",
        "sha256(userOp.callData)",
        "userOp.callGasLimit",
        "userOp.verificationGasLimit",
        "userOp.preVerificationGas",
        "userOp.maxFeePerGas",
        "userOp.maxPriorityFeePerGas",
        "sha256(userOp.paymasterAndData)",
        "address(_entryPoint)",
        "block.chainid",
    ), CANON_ORDER)
}
LEAN_FIELDS = {
    _normalise_expr(expr): field
    for expr, field in zip((
        "op.sender",
        "ByteVec.natToB32 op.nonce",
        "sha256OfArr op.initCode",
        "sha256OfArr op.callData",
        "ByteVec.natToB32 op.callGasLimit",
        "ByteVec.natToB32 op.verificationGasLimit",
        "ByteVec.natToB32 op.preVerificationGas",
        "ByteVec.natToB32 op.maxFeePerGas",
        "ByteVec.natToB32 op.maxPriorityFeePerGas",
        "sha256OfArr op.paymasterAndData",
        "entryPoint",
        "ByteVec.natToB32 chainId",
    ), CANON_ORDER)
}


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


def _balanced_body(s: str, open_at: int) -> str:
    """Return the complete function body inside the brace at open_at."""
    if open_at < 0 or open_at >= len(s) or s[open_at] != "{":
        raise ValueError("function opening brace not found")
    depth = 0
    for i in range(open_at, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return s[open_at + 1:i]
    raise ValueError("unbalanced function braces")


def extract_rust_order(src: str) -> list[str]:
    named = list(re.finditer(r"\bpub\s+fn\s+compute_sphincs_digest_v06\b", src))
    exact = list(re.finditer(
        r"\bpub\s+fn\s+compute_sphincs_digest_v06\s*"
        r"\(\s*params\s*:\s*&AaUserOpParamsV06Sha256\s*,\s*"
        r"call_data_digest\s*:\s*&\[u8\s*;\s*32\]\s*,?\s*\)\s*"
        r"->\s*\[u8\s*;\s*32\]\s*\{",
        src,
    ))
    if len(named) != 1 or len(exact) != 1 or named[0].start() != exact[0].start():
        raise ValueError(
            "expected exactly one canonical Rust digest declaration/signature; "
            f"found {len(named)} named and {len(exact)} exact"
        )
    body = _balanced_body(src, exact[0].end() - 1)
    if re.search(r"\breturn\b", body):
        raise ValueError(
            "compute_sphincs_digest_v06 must use its single implicit tail return; "
            "an explicit/early return can bypass the pinned digest chain"
        )
    starts = list(re.finditer(r"\bSha256::new\(\)", body))
    if len(starts) != 1:
        raise ValueError(
            "compute_sphincs_digest_v06 must contain exactly one Sha256::new() "
            f"return chain, found {len(starts)}"
        )
    tail = re.search(r"\.finalize\(\)\s*\.into\(\)\s*$", body)
    if tail is None or tail.start() <= starts[0].end():
        raise ValueError(
            "Rust digest must be the unique Sha256::new() chain ending the function"
        )
    chain = body[starts[0].end():tail.start()]
    fields = []
    for cu in re.finditer(r"\.chain_update\(", chain):
        args, _ = _balanced_args(chain, cu.end() - 1)
        if len(args) != 1:
            raise ValueError(f"Rust chain_update expected one argument, got {args}")
        fields.append(RUST_FIELDS.get(_normalise_expr(args[0])))
    body_without_line_comments = re.sub(r"//[^\n]*", "", body)
    expected_expr = (
        "Sha256::new()"
        + "".join(f".chain_update({expr})" for expr in RUST_FIELDS)
        + ".finalize().into()"
    )
    if _normalise_expr(body_without_line_comments) != _normalise_expr(expected_expr):
        raise ValueError(
            "Rust digest body contains an unparsed statement/update/wrapper or "
            "does not exactly equal the canonical returned hash chain"
        )
    return fields


def extract_sol_order(src: str) -> list[str]:
    named = list(re.finditer(r"\bfunction\s+sphincsDigest\b", src))
    exact = list(re.finditer(
        r"\bfunction\s+sphincsDigest\s*"
        r"\(\s*UserOperation06\s+calldata\s+userOp\s*\)\s*"
        r"public\s+view\s+returns\s*\(\s*bytes32\s*\)\s*\{",
        src,
    ))
    if len(named) != 1 or len(exact) != 1 or named[0].start() != exact[0].start():
        raise ValueError(
            "expected exactly one canonical Solidity digest declaration/signature; "
            f"found {len(named)} named and {len(exact)} exact"
        )
    body = _balanced_body(src, exact[0].end() - 1)
    all_returns = list(re.finditer(r"\breturn\b", body))
    returns = list(re.finditer(r"\breturn\s+sha256\s*\(", body))
    if len(all_returns) != 1 or len(returns) != 1 or all_returns[0].start() != returns[0].start():
        raise ValueError(
            "sphincsDigest must contain exactly one return statement and it must "
            f"be `return sha256(...)`; found {len(all_returns)} total return(s), "
            f"{len(returns)} matching digest return(s)"
        )
    sha_args, _ = _balanced_args(body, returns[0].end() - 1)
    if len(sha_args) != 1:
        raise ValueError(f"returned sha256 expected one argument, got {sha_args}")
    packed = sha_args[0].strip()
    ep_match = re.match(r"abi\.encodePacked\s*\(", packed)
    if ep_match is None:
        raise ValueError("returned sha256 argument is not abi.encodePacked(...)")
    args, packed_end = _balanced_args(packed, ep_match.end() - 1)
    if packed[packed_end:].strip():
        raise ValueError("unexpected expression around returned abi.encodePacked(...)")
    expected_body = (
        "return sha256(abi.encodePacked("
        + ",".join(SOL_FIELDS)
        + "));"
    )
    if _normalise_expr(body) != _normalise_expr(expected_body):
        raise ValueError(
            "Solidity digest body contains an unparsed statement/expression or "
            "does not exactly equal the canonical returned sha256(abi.encodePacked(...))"
        )
    return [SOL_FIELDS.get(_normalise_expr(a)) for a in args]


def extract_lean_order(src: str) -> list[str]:
    """Parse `sphincsDigestPreimage`'s `++`-concatenated operand sequence into
    canonical field names. The body starts after the `ByteVec.cast (by decide)
    <|` prefix. Each whitespace-normalised operand must exactly match the
    checker-owned expression for that field."""
    m = re.search(r"def sphincsDigestPreimage\b", src)
    if not m:
        raise ValueError("sphincsDigestPreimage not found in Lean source")
    nxt = src.find("\n/--", m.end())
    body = src[m.end(): nxt if nxt > 0 else m.end() + 2000]
    cast = body.find("<|")
    if cast < 0:
        raise ValueError("sphincsDigestPreimage body not found (`<|` prefix missing)")
    operands = [part for part in body[cast + 2:].split("++") if part.strip()]
    return [LEAN_FIELDS.get(_normalise_expr(part)) for part in operands]


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
    print("=== check_sphincs_digest_field_order --self-test "
          "(order + parser negative controls) ===")
    rust_src = RUST.read_text()
    sol_src = SOL.read_text()
    lean_src = LEAN.read_text()
    rust = extract_rust_order(rust_src)
    sol = extract_sol_order(sol_src)
    lean = extract_lean_order(lean_src)
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
    # parser negative: a 13th chain_update in the complete Rust function body
    # must be observed, not hidden by an after-12 truncation.
    tail = ("        .chain_update(u64_to_word_be(params.chain_id))\n"
            "        .finalize()")
    if rust_src.count(tail) != 1:
        print("  FAIL: could not uniquely locate the Rust digest tail for 13th-field control")
        ok = False
    else:
        rust_extra_src = rust_src.replace(
            tail,
            "        .chain_update(u64_to_word_be(params.chain_id))\n"
            "        .chain_update(params.sender)\n"
            "        .finalize()",
            1,
        )
        try:
            rust_extra = extract_rust_order(rust_extra_src)
        except ValueError:
            print("  ok: a 13th Rust chain_update is CAUGHT (parser does not truncate)")
        else:
            if len(rust_extra) == 13 and compare(rust_extra, sol, lean):
                print("  ok: a 13th Rust chain_update is CAUGHT (parser does not truncate)")
            else:
                print("  FAIL: a 13th Rust chain_update escaped the complete-body parser!")
                ok = False
    # parser negative: an expression containing a recognised field is not the
    # exact field expression and must map to None rather than substring-alias.
    exact = ".chain_update(params.call_gas_limit.0)"
    compound = ".chain_update(params.call_gas_limit.0 + params.nonce.0)"
    if rust_src.count(exact) != 1:
        print("  FAIL: could not uniquely locate call_gas_limit for expression control")
        ok = False
    else:
        try:
            rust_compound = extract_rust_order(rust_src.replace(exact, compound, 1))
        except ValueError:
            print("  ok: a compound Rust expression is CAUGHT "
                  "(exact mapping, no substring alias)")
        else:
            if None in rust_compound and compare(rust_compound, sol, lean):
                print("  ok: a compound Rust expression is CAUGHT "
                      "(exact mapping, no substring alias)")
            else:
                print("  FAIL: a compound Rust expression aliased to a canonical field!")
                ok = False
    # parser negatives: alternate early returns must not bypass the canonical
    # tail expression on either implementation side.
    rust_fn = re.search(r"pub fn compute_sphincs_digest_v06\b", rust_src)
    sol_fn = re.search(r"function sphincsDigest\b", sol_src)
    assert rust_fn is not None and sol_fn is not None
    rust_open = rust_src.find("{", rust_fn.end())
    sol_open = sol_src.find("{", sol_fn.end())
    rust_early = (
        rust_src[:rust_open + 1]
        + "\n    if params.chain_id == 0 { return [0u8; 32]; }\n"
        + rust_src[rust_open + 1:]
    )
    sol_early = (
        sol_src[:sol_open + 1]
        + "\n        if (userOp.nonce == 0) return bytes32(0);\n"
        + sol_src[sol_open + 1:]
    )
    try:
        extract_rust_order(rust_early)
    except ValueError:
        print("  ok: alternate Rust early return is CAUGHT")
    else:
        print("  FAIL: alternate Rust early return bypassed the digest pin!")
        ok = False
    try:
        extract_sol_order(sol_early)
    except ValueError:
        print("  ok: alternate Solidity early return is CAUGHT")
    else:
        print("  FAIL: alternate Solidity early return bypassed the digest pin!")
        ok = False
    # parser negative: a canonical Solidity decoy must not hide drift in the
    # abi.encodePacked that actually feeds the returned sha256.
    sol_body = _balanced_body(sol_src, sol_open)
    sol_return = re.search(r"\breturn\s+sha256\s*\(", sol_body)
    assert sol_return is not None
    sha_args, _ = _balanced_args(sol_body, sol_return.end() - 1)
    return_abs = sol_open + 1 + sol_return.start()
    sol_decoy = (
        sol_src[:return_abs]
        + f"bytes memory decoy = {sha_args[0]};\n        "
        + sol_src[return_abs:]
    )
    actual_return = sol_decoy.find("return sha256", return_abs)
    actual_field = sol_decoy.find("userOp.callGasLimit", actual_return)
    if actual_field < 0:
        print("  FAIL: could not locate returned Solidity callGasLimit for decoy control")
        ok = False
    else:
        sol_decoy = (
            sol_decoy[:actual_field]
            + "userOp.callGasLimit + userOp.nonce"
            + sol_decoy[actual_field + len("userOp.callGasLimit"):]
        )
        try:
            sol_actual = extract_sol_order(sol_decoy)
        except ValueError:
            print("  ok: canonical unused Solidity decoy cannot hide drift in returned digest")
        else:
            if None in sol_actual and compare(rust, sol_actual, lean):
                print("  ok: canonical unused Solidity decoy cannot hide drift in returned digest")
            else:
                print("  FAIL: a canonical Solidity decoy hid drift in the returned digest!")
                ok = False
    # parser negative: likewise, a canonical Rust decoy hash chain plus a
    # drifted tail expression must be rejected rather than parsed as the return.
    actual_start = rust_src.find("Sha256::new()", rust_open)
    actual_end = rust_src.find(".into()", actual_start) + len(".into()")
    if actual_start < 0 or actual_end < len(".into()"):
        print("  FAIL: could not locate Rust return chain for decoy control")
        ok = False
    else:
        decoy_expr = rust_src[actual_start:actual_end]
        rust_decoy = (
            rust_src[:actual_start]
            + f"let _decoy: [u8; 32] = {decoy_expr};\n    "
            + rust_src[actual_start:]
        )
        actual_start_2 = rust_decoy.find("Sha256::new()", actual_start + len(decoy_expr))
        actual_field_2 = rust_decoy.find(exact, actual_start_2)
        rust_decoy = (
            rust_decoy[:actual_field_2]
            + compound
            + rust_decoy[actual_field_2 + len(exact):]
        )
        try:
            extract_rust_order(rust_decoy)
        except ValueError:
            print("  ok: canonical Rust decoy chain cannot masquerade as returned digest")
        else:
            print("  FAIL: a canonical Rust decoy chain was accepted as the returned digest!")
            ok = False
    # Review reproducer: wrapping the returned builder can mutate that same
    # hasher through a different Digest API before the visible chain_updates.
    hidden_wrapper = (
        "({ let mut h = Sha256::new(); "
        "sha2::Digest::update(&mut h, params.sender); h })"
    )
    hidden_update = (
        rust_src[:actual_start]
        + hidden_wrapper
        + rust_src[actual_start + len("Sha256::new()"):]
    )
    try:
        extract_rust_order(hidden_update)
    except ValueError:
        print("  ok: hidden Digest::update wrapper on returned Rust hasher is CAUGHT")
    else:
        print("  FAIL: hidden Digest::update changed the returned digest but passed!")
        ok = False

    # Review reproducer: a canonical same-name overloaded Solidity decoy before
    # a drifted one-argument implementation must not be selected by name alone.
    sol_body = _balanced_body(sol_src, sol_open)
    sol_close = sol_open + 1 + len(sol_body)
    original_decl = sol_src[sol_fn.start():sol_close + 1]
    overloaded_decoy = original_decl.replace(
        "UserOperation06 calldata userOp)",
        "UserOperation06 calldata userOp, bool ignored)",
        1,
    )
    drifted_actual = sol_src.replace(
        "userOp.callGasLimit,",
        "userOp.callGasLimit + userOp.nonce,",
        1,
    )
    overload_mutant = (
        drifted_actual[:sol_fn.start()]
        + overloaded_decoy
        + "\n    "
        + drifted_actual[sol_fn.start():]
    )
    try:
        extract_sol_order(overload_mutant)
    except ValueError:
        print("  ok: canonical same-name Solidity overload decoy is CAUGHT")
    else:
        print("  FAIL: same-name Solidity overload hid drift in called implementation!")
        ok = False
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
