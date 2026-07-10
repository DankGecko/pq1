#!/usr/bin/env python3
r"""Nesting-aware EasyCrypt comment stripper + admit/axiom counter.

EasyCrypt comments NEST: `(* a (* b *) c *)`. A non-greedy regex
`\(\*.*?\*\)` closes at the FIRST `*)`, leaking the tail into the "code",
which makes prose like "zero-admit" look like a tactic. Conversely, a
line-anchored `^\s*admit\.` MISSES an inline `proof. admit. qed.` -- which is
exactly the form the (now deleted) WOTS_C_Encoding.ec used.

So: strip properly, then match on word boundaries.
"""
import re, sys

def strip(src: str) -> str:
    out, i, depth, n = [], 0, 0, len(src)
    while i < n:
        if src.startswith("(*", i):
            depth += 1; i += 2
        elif src.startswith("*)", i) and depth:
            depth -= 1; i += 2
        else:
            if not depth:
                out.append(src[i])
            i += 1
    return "".join(out)

def counts(path: str):
    code = strip(open(path, encoding="utf-8", errors="replace").read())
    admits = len(re.findall(r"\badmit\b", code))
    axioms = len(re.findall(r"^\s*axiom\b", code, re.M))
    return admits, axioms

if __name__ == "__main__":
    for p in sys.argv[1:]:
        a, x = counts(p)
        print(f"{p}\t{a}\t{x}")
