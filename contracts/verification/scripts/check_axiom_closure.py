#!/usr/bin/env python3
"""P8 CI gate helper: assert each `#print axioms` closure in a dump file
contains ONLY an allowed set of axioms (and never `sorryAx`).

`#print axioms` pretty-prints long axiom lists across multiple wrapped lines,
so a per-line grep is unreliable. This flattens the output, parses each
`'name' depends on axioms: [a, b, c]` record, and checks the bracket contents
against the allowed set passed on the command line.

Usage:
    check_axiom_closure.py <dump-file> <allowed-axiom> [<allowed-axiom> ...]

The kernel triple {propext, Classical.choice, Quot.sound} is always allowed.
Exit 0 = every closure is within the allowed set and no sorryAx.
Exit 1 = a violation (printed to stderr).
"""
import re
import sys

KERNEL = {"propext", "Classical.choice", "Quot.sound"}


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: check_axiom_closure.py <dump-file> [allowed-axiom ...]", file=sys.stderr)
        return 2
    dump_path = sys.argv[1]
    allowed = KERNEL | set(sys.argv[2:])
    with open(dump_path, "r", encoding="utf-8") as fh:
        text = fh.read()

    if "sorryAx" in text:
        print("FAIL: sorryAx present in an axiom closure — a proof is incomplete.", file=sys.stderr)
        return 1

    # Flatten wrapped lines so each `'name' depends on axioms: [ ... ]` is one string.
    flat = re.sub(r"\s+", " ", text)

    violations = []
    # `does not depend on any axioms` records carry no bracket and are fine.
    for m in re.finditer(r"'([^']+)' depends on axioms: \[([^\]]*)\]", flat):
        name, axs = m.group(1), m.group(2)
        axset = {a.strip() for a in axs.split(",") if a.strip()}
        extra = axset - allowed
        if extra:
            violations.append((name, sorted(extra)))

    if violations:
        print("FAIL: axiom closure(s) contain disallowed axioms:", file=sys.stderr)
        for name, extra in violations:
            print(f"  {name}: {', '.join(extra)}", file=sys.stderr)
        print(f"  (allowed set: {', '.join(sorted(allowed))})", file=sys.stderr)
        return 1

    print(f"OK: all closures within allowed axiom set ({len(allowed)} allowed, no sorryAx).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
