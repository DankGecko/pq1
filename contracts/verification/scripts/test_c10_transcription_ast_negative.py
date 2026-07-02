#!/usr/bin/env python3
"""
test_c10_transcription_ast_negative.py — negative controls proving the STRUCTURAL
check (check_c10_transcription_ast.py) closes the STATISTICAL lint's documented hole.

The statistical lint (check_c10_transcription.py) states its own blind spot: an edit
INSIDE one fragment that preserves the constant-SET, the statement-kind HISTOGRAM, and
the N-mask gate variables PASSES it — a same-kind statement REORDER, a non-gate
`var "X" -> var "Y"` swap, or a non-commutative operand-order swap. This harness applies
exactly those three mutation classes to a COPY of C10Program.lean and asserts, for each:

    statistical lint -> PASS (0)   [the hole: it cannot see the mutation]
    structural check -> FAIL (1)   [closed: the AST tree flips]

Each mutant is behaviour-changing (writes the wrong word, swaps a subtraction that flips
WOTS chain length, reorders memory writes) yet constant-set/kind/gate-preserving. If any
mutant does NOT flip statistical=PASS / structural=FAIL, the structural check has NOT
closed the hole and this test fails.

Run: python3 contracts/verification/scripts/test_c10_transcription_ast_negative.py
Exit 0 = all controls behaved as required; non-zero = a control regressed.
"""
from __future__ import annotations

import importlib.util
import io
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


STAT = load_module("c10_stat", "check_c10_transcription.py")
STRUCT = load_module("c10_struct", "check_c10_transcription_ast.py")

BASE_LEAN = (STRUCT.LEAN).read_text()

# (label, description, old_substring, new_substring). Each edit is a single, exact,
# behaviour-CHANGING but constant-set/kind/gate-preserving intra-fragment mutation.
MUTATIONS = [
    (
        "M1-reorder",
        "H_msg: swap two same-kind mstores (0x20<-root, 0x40<-R) — reorders memory writes",
        '  , .mstore (lit 0x20) (var "root")\n  , .mstore (lit 0x40) (var "R")\n',
        '  , .mstore (lit 0x40) (var "R")\n  , .mstore (lit 0x20) (var "root")\n',
    ),
    (
        "M2-varswap",
        'H_msg: mstore(0x40) writes `root` instead of `R` — non-gate var swap',
        '  , .mstore (lit 0x40) (var "R")\n',
        '  , .mstore (lit 0x40) (var "root")\n',
    ),
    (
        "M3-operand",
        'WOTS: `steps := eSub (var "digit") (lit 7)` instead of `7 - digit` — operand swap',
        '.letv "steps" (eSub (lit 7) (var "digit"))',
        '.letv "steps" (eSub (var "digit") (lit 7))',
    ),
]


def run_checker(mod, lean_text: str) -> int:
    """Point a checker's module-global LEAN at a temp mutated copy, run main(),
    return its exit code. stdout/stderr suppressed."""
    tmp = HERE / f".neg_ctrl_tmp_{mod.__name__}.lean"
    tmp.write_text(lean_text)
    saved = mod.LEAN
    mod.LEAN = tmp
    try:
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(buf):
            try:
                rc = mod.main()
            except SystemExit as e:  # FATAL path (shouldn't hit for these mutants)
                rc = e.code if isinstance(e.code, int) else 2
        return rc
    finally:
        mod.LEAN = saved
        tmp.unlink(missing_ok=True)


def main() -> int:
    print("=== A3.1 structural-check NEGATIVE CONTROLS ===")
    print("    (each mutant must PASS the statistical lint yet FAIL the structural check)\n")

    # Sanity: the clean tree must PASS BOTH (else the harness paths are wrong).
    clean_stat = run_checker(STAT, BASE_LEAN)
    clean_struct = run_checker(STRUCT, BASE_LEAN)
    print(f"    baseline (clean tree)      statistical={clean_stat}  structural={clean_struct}"
          f"  {'ok' if clean_stat == 0 and clean_struct == 0 else 'BROKEN HARNESS'}")
    if clean_stat != 0 or clean_struct != 0:
        print("    FATAL: clean tree does not PASS both checkers — harness misconfigured.", file=sys.stderr)
        return 2
    print()

    failures = 0
    for label, desc, old, new in MUTATIONS:
        if old not in BASE_LEAN:
            print(f"    [{label}] FATAL — anchor text not found in C10Program.lean "
                  f"(the file drifted; update this mutation).", file=sys.stderr)
            failures += 1
            continue
        if BASE_LEAN.count(old) != 1:
            print(f"    [{label}] FATAL — anchor text is not unique "
                  f"({BASE_LEAN.count(old)}×); refine it.", file=sys.stderr)
            failures += 1
            continue
        mutated = BASE_LEAN.replace(old, new, 1)
        stat_rc = run_checker(STAT, mutated)
        struct_rc = run_checker(STRUCT, mutated)
        # REQUIRED: statistical blind (PASS=0), structural catches (FAIL=1).
        ok = (stat_rc == 0 and struct_rc == 1)
        mark = "ok  " if ok else "FAIL"
        print(f"    [{mark}] {label:12s} statistical={stat_rc}(want 0)  structural={struct_rc}(want 1)")
        print(f"           {desc}")
        if not ok:
            failures += 1
            if struct_rc != 1:
                print(f"           ^^ HOLE NOT CLOSED: structural check did NOT catch this "
                      f"(rc={struct_rc}).", file=sys.stderr)
            if stat_rc != 0:
                print(f"           ^^ note: statistical lint ALSO caught it (rc={stat_rc}) — "
                      f"then it isn't a demonstration of the hole.", file=sys.stderr)
    print()
    if failures:
        print(f"RESULT: FAIL — {failures} negative control(s) did not behave as required.", file=sys.stderr)
        return 1
    print("RESULT: PASS — all 3 intra-fragment mutation classes (reorder / var-swap /")
    print("        operand-swap) are INVISIBLE to the statistical lint and CAUGHT by the")
    print("        structural check. The documented hole is closed for these classes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
