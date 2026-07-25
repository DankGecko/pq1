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
therefore fail. The gate also pins the load-bearing Solidity and Lean consumers:
`_validateSignature` must pass that digest to C10, and both the executable Lean
model and its success predicate must pass that digest to `verify_fn`. This keeps
the canonical digest definitions from becoming unused decoys. The Lean leg
exists because nothing else
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

Exit 0 = the three field orders and their verifier consumers match; 1 = drift;
2 = parse/usage error.
`--self-test` exercises reorder/drop controls plus parser-level 13th-field,
compound-expression, decoy/overload, alternate-update, and early-return controls.
"""
from __future__ import annotations

import re
import sys
from collections.abc import Callable
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


def _brace_depth_at(s: str, pos: int) -> int:
    """Brace nesting immediately before pos in comment/string-stripped text."""
    depth = 0
    for c in s[:pos]:
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth < 0:
                raise ValueError("unexpected closing brace")
    return depth


def _strip_c_comments(src: str) -> str:
    """Blank Solidity comments and string literals before source matching."""
    out: list[str] = []
    i = 0

    def blank(c: str) -> str:
        return "\n" if c == "\n" else " "

    while i < len(src):
        if src.startswith("//", i):
            while i < len(src) and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if src.startswith("/*", i):
            out.extend((" ", " "))
            i += 2
            while i < len(src) and not src.startswith("*/", i):
                out.append(blank(src[i]))
                i += 1
            if i < len(src):
                out.extend((" ", " "))
                i += 2
            continue
        if src[i] in {'"', "'"}:
            quote = src[i]
            out.append(" ")
            i += 1
            while i < len(src):
                c = src[i]
                out.append(blank(c))
                i += 1
                if c == "\\" and i < len(src):
                    out.append(blank(src[i]))
                    i += 1
                elif c == quote:
                    break
            continue
        out.append(src[i])
        i += 1
    return "".join(out)


def _strip_lean_noncode(src: str) -> str:
    """Blank Lean line/nested-block comments and strings."""
    out: list[str] = []
    i = 0

    def blank(c: str) -> str:
        return "\n" if c == "\n" else " "

    while i < len(src):
        if src.startswith("--", i):
            while i < len(src) and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if src.startswith("/-", i):
            depth = 1
            out.extend((" ", " "))
            i += 2
            while i < len(src) and depth:
                if src.startswith("/-", i):
                    depth += 1
                    out.extend((" ", " "))
                    i += 2
                elif src.startswith("-/", i):
                    depth -= 1
                    out.extend((" ", " "))
                    i += 2
                else:
                    out.append(blank(src[i]))
                    i += 1
            continue
        if src[i] == '"':
            out.append(" ")
            i += 1
            while i < len(src):
                c = src[i]
                out.append(blank(c))
                i += 1
                if c == "\\" and i < len(src):
                    out.append(blank(src[i]))
                    i += 1
                elif c == '"':
                    break
            continue
        out.append(src[i])
        i += 1
    return "".join(out)


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
    canonical field names. Require one exact declaration/signature, its entire
    normalized body, and the one exact `sphincsDigest` caller. This mirrors the
    Rust/Solidity anti-decoy checks: a same-name namespace decoy, alternate
    caller, or hidden statement must fail rather than select the first match."""
    named = list(re.finditer(
        r"(?m)^[ \t]*def[ \t]+sphincsDigestPreimage\b", src
    ))
    exact = list(re.finditer(
        r"(?m)^[ \t]*def[ \t]+sphincsDigestPreimage[ \t\r\n]*"
        r"\([ \t]*op[ \t]*:[ \t]*UserOperation[ \t]*\)"
        r"[ \t\r\n]*\([ \t]*entryPoint[ \t]*:[ \t]*ByteVec[ \t]+20[ \t]*\)"
        r"[ \t\r\n]*\([ \t]*chainId[ \t]*:[ \t]*Nat[ \t]*\)"
        r"[ \t]*:[ \t\r\n]*ByteVec[ \t]+360[ \t]*:=[ \t\r\n]*"
        r"ByteVec\.cast[ \t]*\([ \t]*by[ \t]+decide[ \t]*\)[ \t]*<\|",
        src,
    ))
    if len(named) != 1 or len(exact) != 1 or named[0].start() != exact[0].start():
        raise ValueError(
            "expected exactly one canonical Lean sphincsDigestPreimage "
            f"declaration/signature; found {len(named)} named and {len(exact)} exact"
        )
    body_end = src.find("\n/--", exact[0].end())
    if body_end < 0:
        raise ValueError(
            "sphincsDigestPreimage declaration has no closing documentation boundary"
        )
    body = src[exact[0].end():body_end]
    expected_body = "++".join(LEAN_FIELDS)
    if _normalise_expr(body) != _normalise_expr(expected_body):
        raise ValueError(
            "Lean sphincsDigestPreimage body contains an unparsed "
            "statement/expression or is not the exact canonical concatenation"
        )

    caller_named = list(re.finditer(
        r"(?m)^[ \t]*def[ \t]+sphincsDigest\b", src
    ))
    caller_exact = list(re.finditer(
        r"(?m)^[ \t]*def[ \t]+sphincsDigest[ \t\r\n]*"
        r"\([ \t]*op[ \t]*:[ \t]*UserOperation[ \t]*\)"
        r"[ \t\r\n]*\([ \t]*entryPoint[ \t]*:[ \t]*ByteVec[ \t]+20[ \t]*\)"
        r"[ \t\r\n]*\([ \t]*chainId[ \t]*:[ \t]*Nat[ \t]*\)"
        r"[ \t]*:[ \t\r\n]*ByteVec[ \t]+32[ \t]*:=",
        src,
    ))
    if (
        len(caller_named) != 1
        or len(caller_exact) != 1
        or caller_named[0].start() != caller_exact[0].start()
    ):
        raise ValueError(
            "expected exactly one canonical Lean sphincsDigest "
            f"declaration/signature; found {len(caller_named)} named and "
            f"{len(caller_exact)} exact"
        )
    caller_end = src.find("\n/--", caller_exact[0].end())
    if caller_end < 0:
        raise ValueError("sphincsDigest declaration has no closing documentation boundary")
    caller_body = src[caller_exact[0].end():caller_end]
    expected_caller = "sha256_concat (sphincsDigestPreimage op entryPoint chainId)"
    if _normalise_expr(caller_body) != _normalise_expr(expected_caller):
        raise ValueError(
            "Lean sphincsDigest body must exactly hash sphincsDigestPreimage"
        )

    operands = [part for part in body.split("++") if part.strip()]
    return [LEAN_FIELDS.get(_normalise_expr(part)) for part in operands]


def check_sol_consumer(src: str) -> None:
    """Pin `_validateSignature`'s canonical digest-to-C10 dataflow."""
    clean = _strip_c_comments(src)
    named = list(re.finditer(r"\bfunction\s+_validateSignature\b", clean))
    exact = list(re.finditer(
        r"\bfunction\s+_validateSignature\s*\(\s*"
        r"UserOperation06\s+calldata\s+userOp\s*,\s*bytes32\s*\)\s*"
        r"internal\s+returns\s*\(\s*uint256\s*\)\s*\{",
        clean,
    ))
    if len(named) != 1 or len(exact) != 1 or named[0].start() != exact[0].start():
        raise ValueError(
            "expected exactly one canonical Solidity _validateSignature "
            f"declaration/signature; found {len(named)} named and {len(exact)} exact"
        )
    body = _balanced_body(clean, exact[0].end() - 1)

    digest_binding = re.compile(
        r"\bbytes32\s+digest\s*=\s*sphincsDigest\s*\(\s*userOp\s*\)\s*;"
    )
    digest_bindings = list(digest_binding.finditer(body))
    if len(digest_bindings) != 1:
        raise ValueError(
            "_validateSignature must bind exactly one "
            "`bytes32 digest = sphincsDigest(userOp);`"
        )
    if _brace_depth_at(body, digest_bindings[0].start()) != 0:
        raise ValueError(
            "_validateSignature canonical digest binding must execute at "
            "top-level, not inside conditional/dead control flow"
        )
    if len(re.findall(r"\bsphincsDigest\s*\(", body)) != 1:
        raise ValueError(
            "_validateSignature must contain exactly one sphincsDigest call"
        )
    if len(re.findall(r"\b(?:bytes32\s+)?digest\s*=", body)) != 1:
        raise ValueError(
            "_validateSignature must assign the verifier digest exactly once"
        )

    verify_calls = list(re.finditer(
        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*verify\s*\(", body
    ))
    if len(verify_calls) != 1:
        raise ValueError(
            "_validateSignature must contain exactly one verifier `.verify` call"
        )
    if verify_calls[0].group(1) != "c10Verifier":
        raise ValueError(
            "_validateSignature's sole verifier call must use c10Verifier directly"
        )
    if _brace_depth_at(body, verify_calls[0].start()) != 0:
        raise ValueError(
            "_validateSignature canonical verifier call must execute at "
            "top-level, not inside conditional/dead control flow"
        )
    try_prefix = re.search(r"\btry\s*$", body[:verify_calls[0].start()])
    if (
        try_prefix is None
        or _brace_depth_at(body, try_prefix.start()) != 0
    ):
        raise ValueError(
            "_validateSignature must execute the canonical verifier call "
            "directly as a top-level try expression"
        )
    args, verify_end = _balanced_args(body, verify_calls[0].end() - 1)
    expected = ["pkSeed", "pkRoot", "digest", "innerSig"]
    if [_normalise_expr(arg) for arg in args] != expected:
        raise ValueError(
            "_validateSignature must call "
            "c10Verifier.verify(pkSeed, pkRoot, digest, innerSig)"
        )
    for return_stmt in re.finditer(
        r"\breturn\b\s*([^;]*);", body[:verify_calls[0].start()]
    ):
        if _normalise_expr(return_stmt.group(1)) != "SIG_VALIDATION_FAILED":
            raise ValueError(
                "_validateSignature must not return success before the "
                "canonical C10 verifier call"
            )
    canonical_result_flow = re.compile(
        r"\s*returns\s*\(\s*bool\s+ok\s*\)\s*\{\s*"
        r"if\s*\(\s*!\s*ok\s*\)\s*return\s+SIG_VALIDATION_FAILED\s*;\s*"
        r"\}\s*catch\s*\{\s*return\s+SIG_VALIDATION_FAILED\s*;\s*\}"
    )
    if canonical_result_flow.match(body, verify_end) is None:
        raise ValueError(
            "_validateSignature canonical C10 call must retain the reviewed "
            "top-level try/false-return/catch-return control flow"
        )
    if len(re.findall(r"\bc10Verifier\b", body)) != 1:
        raise ValueError(
            "_validateSignature must not alias or otherwise reuse c10Verifier"
        )
    if len(re.findall(r"\bdigest\b", body)) != 2:
        raise ValueError(
            "_validateSignature digest binding must feed only the canonical C10 call"
        )


def _lean_consumer_body(src: str, name: str, signature: str) -> str:
    named = list(re.finditer(
        rf"(?m)^[ \t]*def[ \t]+{re.escape(name)}\b", src
    ))
    exact = list(re.finditer(signature, src))
    if len(named) != 1 or len(exact) != 1 or named[0].start() != exact[0].start():
        raise ValueError(
            f"expected exactly one canonical Lean {name} declaration/signature; "
            f"found {len(named)} named and {len(exact)} exact"
        )
    body_end = src.find("\n/--", exact[0].end())
    if body_end < 0:
        raise ValueError(f"{name} declaration has no closing documentation boundary")
    return src[exact[0].end():body_end]


def check_lean_consumers(src: str) -> None:
    """Pin the executable/model digest arguments passed to `verify_fn`."""
    ok_body = _strip_lean_noncode(
        _lean_consumer_body(
            src,
            "validateSignatureOk",
            r"(?m)^[ \t]*def[ \t]+validateSignatureOk[ \t\r\n]*"
            r"\([ \t]*s[ \t]*:[ \t]*Storage[ \t]*\)[ \t\r\n]*"
            r"\([ \t]*op[ \t]*:[ \t]*UserOperation[ \t]*\)[ \t\r\n]*"
            r"\([ \t]*entryPoint[ \t]*:[ \t]*ByteVec[ \t]+20[ \t]*\)[ \t\r\n]*"
            r"\([ \t]*chainId[ \t]*:[ \t]*Nat[ \t]*\)[ \t\r\n]*"
            r"\([ \t]*verify_fn[ \t]*:[ \t]*ByteVec[ \t]+32[ \t]*→[ \t]*"
            r"ByteVec[ \t]+32[ \t]*→[ \t]*ByteVec[ \t]+32[ \t]*→[ \t]*"
            r"ByteVec[ \t]+SignatureLen[ \t]*→[ \t]*Bool[ \t]*\)[ \t\r\n]*"
            r"\([ \t]*d[ \t]*:[ \t]*DecodedSig[ \t]*\)[ \t]*"
            r"\([ \t]*owner[ \t]*:[ \t]*OwnerBytes[ \t]*\)[ \t]*"
            r":[ \t]*Prop[ \t]*:=",
        )
    )
    expected_ok = (
        "verify_fn (owner.raw.take 32 (by decide)) "
        "(owner.raw.drop 32 (by decide)) "
        "(sphincsDigest op entryPoint chainId) d.innerSig = true"
    )
    if _normalise_expr(expected_ok) not in _normalise_expr(ok_body):
        raise ValueError(
            "validateSignatureOk must pass sphincsDigest directly to verify_fn"
        )
    if len(re.findall(r"\bsphincsDigest\b", ok_body)) != 1:
        raise ValueError(
            "validateSignatureOk must contain exactly one sphincsDigest use"
        )
    if len(re.findall(r"\bverify_fn\b", ok_body)) != 1:
        raise ValueError(
            "validateSignatureOk must contain exactly one verify_fn use"
        )

    executable_body = _strip_lean_noncode(
        _lean_consumer_body(
            src,
            "validateSignature",
            r"(?m)^[ \t]*def[ \t]+validateSignature[ \t\r\n]*"
            r"\([ \t]*s[ \t]*:[ \t]*Storage[ \t]*\)[ \t\r\n]*"
            r"\([ \t]*op[ \t]*:[ \t]*UserOperation[ \t]*\)[ \t\r\n]*"
            r"\([ \t]*entryPoint[ \t]*:[ \t]*ByteVec[ \t]+20[ \t]*\)[ \t\r\n]*"
            r"\([ \t]*chainId[ \t]*:[ \t]*Nat[ \t]*\)[ \t\r\n]*"
            r"\([ \t]*verify_fn[ \t]*:[ \t]*ByteVec[ \t]+32[ \t]*→[ \t]*"
            r"ByteVec[ \t]+32[ \t]*→[ \t]*ByteVec[ \t]+32[ \t]*→[ \t]*"
            r"ByteVec[ \t]+SignatureLen[ \t]*→[ \t]*Bool[ \t]*\)[ \t]*"
            r":[ \t\r\n]*Result[ \t]*×[ \t]*Storage[ \t]*:=",
        )
    )
    expected_flow = re.compile(
        r"\blet\s+digest\s*:=\s*sphincsDigest\s+op\s+entryPoint\s+chainId\s*"
        r"\bif\s+verify_fn\s+pkSeed\s+pkRoot\s+digest\s+innerSig\s*=\s*false\s+then"
    )
    if expected_flow.search(executable_body) is None:
        raise ValueError(
            "validateSignature must bind sphincsDigest and immediately pass it "
            "to verify_fn(pkSeed, pkRoot, digest, innerSig)"
        )
    if len(re.findall(r"\bsphincsDigest\b", executable_body)) != 1:
        raise ValueError(
            "validateSignature must contain exactly one sphincsDigest use"
        )
    if len(re.findall(r"\bverify_fn\b", executable_body)) != 1:
        raise ValueError(
            "validateSignature must contain exactly one verify_fn use"
        )
    if len(re.findall(r"\blet\s+digest\s*:=", executable_body)) != 1:
        raise ValueError(
            "validateSignature must bind the verifier digest exactly once"
        )
    if len(re.findall(r"\bdigest\b", executable_body)) != 2:
        raise ValueError(
            "validateSignature digest binding must feed only the canonical verifier call"
        )


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

    def expect_consumer_rejection(
        label: str, checker: Callable[[str], None], mutant: str
    ) -> None:
        nonlocal ok
        try:
            checker(mutant)
        except ValueError:
            print(f"  ok: {label} is CAUGHT")
        else:
            print(f"  FAIL: {label} escaped the consumer binding pin!")
            ok = False

    try:
        check_sol_consumer(sol_src)
        check_lean_consumers(lean_src)
    except ValueError as e:
        print(f"  FAIL: clean verifier-consumer binding is stale: {e}")
        ok = False
    else:
        print("  ok: clean Solidity/Lean verifier consumers use the pinned digest")

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

    # Review reproducer: a canonical same-name Lean definition in a namespace
    # must not hide equal-width drift in the real model definition.
    lean_preimage = re.search(
        r"(?m)^[ \t]*def[ \t]+sphincsDigestPreimage\b", lean_src
    )
    assert lean_preimage is not None
    lean_preimage_end = lean_src.find("\n/--", lean_preimage.end())
    canonical_decl = lean_src[lean_preimage.start():lean_preimage_end]
    actual_operand = "++ ByteVec.natToB32 op.callGasLimit"
    drifted_operand = "++ ByteVec.natToB32 op.nonce"
    if lean_src.count(actual_operand) != 1:
        print("  FAIL: could not uniquely locate Lean callGasLimit operand for decoy control")
        ok = False
    else:
        drifted_lean = lean_src.replace(actual_operand, drifted_operand, 1)
        decoy_lean = (
            drifted_lean[:lean_preimage.start()]
            + "namespace DigestPinDecoy\n"
            + canonical_decl
            + "\nend DigestPinDecoy\n\n"
            + drifted_lean[lean_preimage.start():]
        )
        try:
            extract_lean_order(decoy_lean)
        except ValueError:
            print("  ok: canonical namespaced Lean decoy cannot hide real preimage drift")
        else:
            print("  FAIL: namespaced Lean decoy hid drift in the real preimage!")
            ok = False

    # The field-order declaration is not sufficient unless the modeled digest
    # actually hashes it.
    canonical_caller = "sha256_concat (sphincsDigestPreimage op entryPoint chainId)"
    if lean_src.count(canonical_caller) != 1:
        print("  FAIL: could not uniquely locate canonical Lean digest caller")
        ok = False
    else:
        caller_mutant = lean_src.replace(
            canonical_caller, "sha256_concat (ByteVec.zero 360)", 1
        )
        try:
            extract_lean_order(caller_mutant)
        except ValueError:
            print("  ok: drifted Lean sphincsDigest caller is CAUGHT")
        else:
            print("  FAIL: Lean sphincsDigest stopped hashing the pinned preimage!")
            ok = False

    # Load-bearing consumer controls: canonical digest definitions or calls may
    # not survive as unused decoys while the actual verifier receives zero.
    sol_binding = "bytes32 digest = sphincsDigest(userOp);"
    sol_verify = "c10Verifier.verify(pkSeed, pkRoot, digest, innerSig)"
    if sol_src.count(sol_binding) != 1 or sol_src.count(sol_verify) != 1:
        print("  FAIL: could not uniquely locate canonical Solidity consumer flow")
        ok = False
    else:
        expect_consumer_rejection(
            "a zeroed Solidity digest binding",
            check_sol_consumer,
            sol_src.replace(sol_binding, "bytes32 digest = bytes32(0);", 1),
        )
        expect_consumer_rejection(
            "an unused canonical Solidity digest decoy",
            check_sol_consumer,
            sol_src.replace(
                sol_binding,
                "bytes32 digestDecoy = sphincsDigest(userOp);\n"
                "        bytes32 digest = bytes32(0);",
                1,
            ),
        )
        expect_consumer_rejection(
            "a redirected Solidity verifier argument",
            check_sol_consumer,
            sol_src.replace(
                sol_verify,
                "c10Verifier.verify(pkSeed, pkRoot, bytes32(0), innerSig)",
                1,
            ),
        )
        expect_consumer_rejection(
            "a Solidity success return before the canonical verifier",
            check_sol_consumer,
            sol_src.replace(
                sol_binding,
                "return SIG_VALIDATION_SUCCESS;\n"
                "        bytes32 digest = sphincsDigest(userOp);",
                1,
            ),
        )
        canonical_flow = (
            "        bytes32 digest = sphincsDigest(userOp);\n"
            "        try c10Verifier.verify(pkSeed, pkRoot, digest, innerSig) "
            "returns (bool ok) {\n"
            "            if (!ok) return SIG_VALIDATION_FAILED;\n"
            "        } catch {\n"
            "            return SIG_VALIDATION_FAILED;\n"
            "        }\n"
        )
        if sol_src.count(canonical_flow) != 1:
            print("  FAIL: could not uniquely locate canonical Solidity try/catch flow")
            ok = False
        else:
            dead_only = (
                "        if (false) {\n"
                "            bytes32 digest = sphincsDigest(userOp);\n"
                "            try c10Verifier.verify(pkSeed, pkRoot, digest, innerSig) "
                "returns (bool ok) {\n"
                "                if (!ok) return SIG_VALIDATION_FAILED;\n"
                "            } catch {\n"
                "                return SIG_VALIDATION_FAILED;\n"
                "            }\n"
                "        }\n"
            )
            expect_consumer_rejection(
                "a canonical Solidity verifier flow hidden under if(false)",
                check_sol_consumer,
                sol_src.replace(canonical_flow, dead_only, 1),
            )
            dead_with_live_alias = (
                dead_only
                + "        ISPHINCSVerifier liveVerifier = c10Verifier;\n"
                + "        try liveVerifier.verify("
                "pkSeed, pkRoot, bytes32(0), innerSig"
                ") returns (bool liveOk) {\n"
                + "            if (!liveOk) return SIG_VALIDATION_FAILED;\n"
                + "        } catch {\n"
                + "            return SIG_VALIDATION_FAILED;\n"
                + "        }\n"
            )
            expect_consumer_rejection(
                "a dead canonical Solidity decoy plus live zero-digest alias",
                check_sol_consumer,
                sol_src.replace(canonical_flow, dead_with_live_alias, 1),
            )
        sol_comment_decoy = sol_src.replace(
            sol_verify,
            "verifier.verify(pkSeed, pkRoot, verifierInput, innerSig)",
            1,
        ).replace(
            sol_binding,
            "/* bytes32 digest = sphincsDigest(userOp);\n"
            "        c10Verifier.verify(pkSeed, pkRoot, digest, innerSig); */\n"
            "        ISPHINCSVerifier verifier = c10Verifier;\n"
            "        bytes32 verifierInput = bytes32(0);",
            1,
        )
        expect_consumer_rejection(
            "a canonical Solidity consumer hidden in a comment",
            check_sol_consumer,
            sol_comment_decoy,
        )

    lean_binding = "let digest := sphincsDigest op entryPoint chainId"
    lean_verify = "if verify_fn pkSeed pkRoot digest innerSig = false then"
    if lean_src.count(lean_binding) != 1 or lean_src.count(lean_verify) != 1:
        print("  FAIL: could not uniquely locate canonical Lean consumer flow")
        ok = False
    else:
        expect_consumer_rejection(
            "a zeroed Lean executable digest binding",
            check_lean_consumers,
            lean_src.replace(
                lean_binding, "let digest := ByteVec.zero 32", 1
            ),
        )
        expect_consumer_rejection(
            "a coherent Lean model/spec digest redirection",
            check_lean_consumers,
            lean_src.replace(
                "sphincsDigest op entryPoint chainId", "ByteVec.zero 32"
            ),
        )
        expect_consumer_rejection(
            "an unused canonical Lean digest decoy",
            check_lean_consumers,
            lean_src.replace(
                lean_verify,
                "if verify_fn pkSeed pkRoot (ByteVec.zero 32) innerSig = false then",
                1,
            ),
        )
        lean_flow = f"{lean_binding}\n        {lean_verify}"
        expect_consumer_rejection(
            "a canonical Lean consumer hidden in a comment",
            check_lean_consumers,
            lean_src.replace(
                lean_flow,
                f"/-\n        {lean_flow}\n        -/\n        if false then",
                1,
            ),
        )
    print("=== self-test PASS ===" if ok else "=== self-test FAILED ===")
    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    try:
        rust_src = RUST.read_text(encoding="utf-8")
        sol_src = SOL.read_text(encoding="utf-8")
        lean_src = LEAN.read_text(encoding="utf-8")
        rust = extract_rust_order(rust_src)
        sol = extract_sol_order(sol_src)
        lean = extract_lean_order(lean_src)
        check_sol_consumer(sol_src)
        check_lean_consumers(lean_src)
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
          "the exact 12-field preimage order, and the Solidity/Lean verifiers "
          "consume that pinned digest (source-level pin).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
