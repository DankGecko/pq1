#!/usr/bin/env python3
"""Semantic axiom extractor for the EasyCrypt +C port (F5, 2026-07-16).

`ec_sweep.py` COUNTS axioms (`len(re.findall(...))`) and discards the name and
statement — so the old `EXPECTED_TOTAL_AXIOMS=8` count pin cannot tell that a
load-bearing axiom was deleted and a benign one added (count preserved), nor
that e.g. `dmkey_ll` was silently weakened from `is_lossless dmkey` to `false`.
This emits, per axiom, `name<TAB>normalized-full-statement`, sorted, so
check_easycrypt.sh can pin the EXACT (name -> statement) set toolchain-free.

Reuses `ec_sweep.strip()` (nesting-aware comment removal) so it never trips on
the word "axiom" inside a `(* ... *)` comment or prose. Handles the multi-line
axioms (eqiks_g / neqisvs_g / rng_g) by scanning to the statement-terminating
`.` — the `.` followed by whitespace/EOF; a projection dot `x.`1` is followed by
a backtick, never whitespace, so it is not mistaken for a terminator.
"""
import re
import sys

from ec_sweep import strip


def extract(code: str) -> list[tuple[str, str]]:
    """[(name, normalized `axiom name : stmt.`)] from ALREADY-STRIPPED code."""
    out = []
    n = len(code)
    for m in re.finditer(r"(?m)^[ \t]*axiom\s+(\w+)", code):
        name = m.group(1)
        j = m.end()
        while j < n:
            if code[j] == "." and (j + 1 >= n or code[j + 1].isspace()):
                break
            j += 1
        stmt = re.sub(r"\s+", " ", code[m.start():j + 1]).strip()
        out.append((name, stmt))
    return out


def extract_files(paths: list[str]) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for p in paths:
        code = strip(open(p, encoding="utf-8", errors="replace").read())
        rows += extract(code)
    return sorted(rows)


if __name__ == "__main__":
    for name, stmt in extract_files(sys.argv[1:]):
        print(f"{name}\t{stmt}")
