#!/usr/bin/env python3
"""P8 CI gate helper: assert each `#print axioms` closure in a dump file
contains ONLY an allowed set of axioms (and never `sorryAx`).

`#print axioms` pretty-prints long axiom lists across multiple wrapped lines,
so a per-line grep is unreliable. This flattens the output, parses each
`'name' depends on axioms: [a, b, c]` record, and checks the bracket contents
against the allowed set passed on the command line.

Usage:
    check_axiom_closure.py <dump-file> [--expect-records N] <allowed-axiom> [<allowed-axiom> ...]
    check_axiom_closure.py --manifest <manifest-file> <dump-file>

The kernel triple {propext, Classical.choice, Quot.sound} is always allowed.

`--manifest <file>` (F3 per-headline mode, 2026-07-16): instead of one flat
allowed-set for every theorem, read an EXACT per-headline allowlist (one line
`FullyQualified.Name [extra axiom ...]`; kernel triple implicit; `#`/blank lines
ignored). This is BIDIRECTIONAL and fails closed:
  * every dump record's name MUST appear in the manifest (an UNLISTED headline —
    e.g. a theorem that consumed a rogue `axiom Evil : False`, or a new theorem
    someone added without disclosing its closure — fails); AND
  * every manifest entry MUST appear in the dump (a DROPPED headline, or a dump
    truncated by an elaboration error, fails); AND
  * each headline's live closure ⊆ {kernel} ∪ its listed extras.
This gives the permanent `Evil:False` negative control its teeth: the canary
headline is not in the manifest, so the gate is RED for a reason the old
`grep sorryAx` could never see.

`--expect-records N` (F3 declaration inventory, 2026-07-16): assert the dump
contains EXACTLY N `#print axioms` records (each theorem prints either
`'X' depends on axioms: [...]` or `'X' does not depend on any axioms`). A gate
that only greps for `sorryAx`/disallowed axioms cannot tell that a theorem was
silently DROPPED from the audit file, or that an elaboration error truncated the
dump so the headline closure is no longer covered — either way the count falls.
Requiring the exact record count makes dropping or short-circuiting a headline
theorem a hard failure. Adding a theorem to the gate must consciously bump N.

Exit 0 = every closure is within the allowed set, no sorryAx, and (if given) the
         record count matches exactly.
Exit 1 = a violation (printed to stderr).
Exit 2 = usage error.
"""
import re
import sys

KERNEL = {"propext", "Classical.choice", "Quot.sound"}


def parse_dump_records(text: str) -> dict[str, set[str]]:
    """{headline name: axiom set} from a `#print axioms` dump (both the
    `depends on axioms: [...]` and `does not depend on any axioms` forms)."""
    flat = re.sub(r"\s+", " ", text)
    out: dict[str, set[str]] = {}
    for m in re.finditer(r"'([^']+)' depends on axioms: \[([^\]]*)\]", flat):
        out[m.group(1)] = {a.strip() for a in m.group(2).split(",") if a.strip()}
    for m in re.finditer(r"'([^']+)' does not depend on any axioms", flat):
        out.setdefault(m.group(1), set())
    return out


def parse_manifest(text: str) -> dict[str, set[str]]:
    """{headline name: extra-axiom set} from the per-headline allowlist file."""
    out: dict[str, set[str]] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        toks = line.split()
        out[toks[0]] = set(toks[1:])
    return out


def run_manifest_mode(manifest_path: str, dump_path: str) -> int:
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = parse_manifest(fh.read())
    with open(dump_path, "r", encoding="utf-8") as fh:
        dump_text = fh.read()
    if "sorryAx" in dump_text:
        print("FAIL: sorryAx present in an axiom closure — a proof is incomplete.", file=sys.stderr)
        return 1
    live = parse_dump_records(dump_text)

    fails: list[str] = []
    for name, axset in live.items():
        if name not in manifest:
            fails.append(f"UNLISTED headline `{name}` in the dump (closure {sorted(axset - KERNEL)}) "
                         f"— not in the per-headline manifest. A new/rogue theorem (e.g. one "
                         f"consuming `axiom Evil : False`) must be disclosed there.")
            continue
        allowed = KERNEL | manifest[name]
        extra = axset - allowed
        if extra:
            fails.append(f"headline `{name}` closure carries disallowed axiom(s) {sorted(extra)} "
                         f"(manifest allows only {sorted(manifest[name])} beyond the kernel triple).")
    for name in manifest:
        if name not in live:
            fails.append(f"MISSING headline `{name}` — listed in the manifest but absent from the "
                         f"dump (dropped from the audit file, or an elaboration error truncated it).")

    if fails:
        print(f"FAIL: per-headline axiom closure violations ({len(fails)}):", file=sys.stderr)
        for f in fails:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(f"OK: all {len(live)} headline closures match the per-headline manifest "
          f"(no unlisted/missing headline, no undisclosed axiom, no sorryAx).")
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print("usage: check_axiom_closure.py <dump-file> [--expect-records N] [allowed-axiom ...]\n"
              "   or: check_axiom_closure.py --manifest <manifest-file> <dump-file>",
              file=sys.stderr)
        return 2
    if argv[0] == "--manifest":
        if len(argv) != 3:
            print("usage: check_axiom_closure.py --manifest <manifest-file> <dump-file>", file=sys.stderr)
            return 2
        return run_manifest_mode(argv[1], argv[2])
    dump_path = argv[0]
    rest = argv[1:]
    expect_records = None
    if "--expect-records" in rest:
        i = rest.index("--expect-records")
        try:
            expect_records = int(rest[i + 1])
        except (IndexError, ValueError):
            print("ERROR: --expect-records needs an integer argument", file=sys.stderr)
            return 2
        rest = rest[:i] + rest[i + 2:]
    allowed = KERNEL | set(rest)
    with open(dump_path, "r", encoding="utf-8") as fh:
        text = fh.read()

    if "sorryAx" in text:
        print("FAIL: sorryAx present in an axiom closure — a proof is incomplete.", file=sys.stderr)
        return 1

    # Flatten wrapped lines so each `'name' depends on axioms: [ ... ]` is one string.
    flat = re.sub(r"\s+", " ", text)

    # A record is EITHER `'X' depends on axioms: [...]` OR `'X' does not depend
    # on any axioms`. Count both for the declaration inventory.
    dep_records = list(re.finditer(r"'([^']+)' depends on axioms: \[([^\]]*)\]", flat))
    nodep_records = list(re.finditer(r"'([^']+)' does not depend on any axioms", flat))
    n_records = len(dep_records) + len(nodep_records)

    violations = []
    for m in dep_records:
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

    if expect_records is not None and n_records != expect_records:
        print(f"FAIL: declaration inventory — dump has {n_records} `#print axioms` "
              f"record(s) but {expect_records} expected. A headline theorem was DROPPED "
              f"from the audit file, or an elaboration error truncated the dump (the "
              f"headline closure is no longer covered). If a theorem was intentionally "
              f"added/removed, update --expect-records.", file=sys.stderr)
        return 1

    inv = f", {n_records}/{expect_records} records" if expect_records is not None else f", {n_records} records"
    print(f"OK: all closures within allowed axiom set ({len(allowed)} allowed, no sorryAx{inv}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
