#!/usr/bin/env python3
"""Dedup an Aeneas-generated Funs.lean against already-committed extractions.

Aeneas extracts every transitive dependency into each --start-from module, so
two extractions sharing a Rust item (e.g. sphincs_c10::params::H appears in
both the FORS and the merkle extraction) produce DUPLICATE Lean declarations,
which clash when both modules are imported (AxiomCheck imports everything).

This filter drops the declaration chunks named on the kill list and prepends
imports of their canonical homes. It is part of the deterministic extraction
pipeline (run by the Makefile drift-guard on BOTH the fresh extraction and at
commit time), so the committed file always equals filter(fresh extraction).

Usage: dedup_extraction.py <in.lean> <out.lean> --kill 'sphincs_c10::params::H' \
           --kill 'sphincs_c10::address::make_adrs' --add-import Extracted.Adrs
"""
import argparse
import re
import sys


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("infile")
    ap.add_argument("outfile")
    ap.add_argument("--kill", action="append", default=[],
                    help="Rust path of a decl chunk to drop (matches the doc-comment header)")
    ap.add_argument("--add-import", action="append", default=[],
                    help="Lean module to import (the canonical home of dropped decls)")
    ap.add_argument("--sed-import", action="append", default=[],
                    help="OLD=NEW import-prefix rewrite (e.g. 'Merkle.=Extracted.Merkle.')")
    args = ap.parse_args()

    text = open(args.infile).read()

    # 1. import-prefix rewrites
    for rule in args.sed_import:
        old, new = rule.split("=", 1)
        text = text.replace(f"import {old}", f"import {new}")

    # 2. split into chunks at each generated doc comment `/-- [rust::path]...`
    #    chunk 0 is the file header (imports/options/namespace open).
    parts = re.split(r"(?m)^(?=/-- \[)", text)
    kept = [parts[0]]
    for chunk in parts[1:]:
        header = chunk.split("\n", 1)[0]
        m = re.match(r"/-- \[([^\]]+)\]", header)
        path = m.group(1) if m else ""
        if any(path == k or path.startswith(k + "::") for k in args.kill):
            continue
        kept.append(chunk)
    text = "".join(kept)

    # 3. add canonical-home imports after the last existing import
    if args.add_import:
        lines = text.split("\n")
        last_import = max(i for i, l in enumerate(lines) if l.startswith("import "))
        add = [f"import {m}" for m in args.add_import if f"import {m}" not in text]
        lines[last_import + 1:last_import + 1] = add
        text = "\n".join(lines)

    open(args.outfile, "w").write(text)


if __name__ == "__main__":
    sys.exit(main())
