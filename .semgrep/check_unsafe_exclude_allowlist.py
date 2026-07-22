#!/usr/bin/env python3
"""F13 guard (full-project sweep 2026-07-14).

The `no-unsafe-in-pure-logic-crates` ERROR rule enforces CLAUDE.md's unsafe
taxonomy: the host-runnable pure-logic crates must stay 100% safe Rust. Three
files are `exclude:`d because they hold structurally-required unsafe that was
DELIBERATELY relocated into a host crate so it could be formally verified there
(Kani window-check proof + Miri tree-borrows for the NS-pointer primitives; the
FI stack-canary and transcript-poison volatiles that rode in with the ERC-7730
render dispatch). See
the rule's header comment in pqsigner-invariants.yml for the proof pointers.

Each excluded file is a hole in the unsafe ban. This guard asserts the exclude
list stays EXACTLY those three documented files, so a future over-broad exclude
cannot silently silence a genuine `unsafe` in a pure-logic crate. Run by
`make invariant-gates`.
"""
import pathlib
import sys

import yaml

RULE_ID = "no-unsafe-in-pure-logic-crates"
EXPECTED = {
    "shared/src/ns_ptr_validate.rs",
    "pqsigner-erc7730/src/display/render/mod.rs",
    "pqsigner-erc7730/src/display/mod.rs",
}


def main() -> int:
    cfg = pathlib.Path(__file__).with_name("pqsigner-invariants.yml")
    doc = yaml.safe_load(cfg.read_text())
    rules = {r.get("id"): r for r in doc.get("rules", [])}
    rule = rules.get(RULE_ID)
    if rule is None:
        print(f"FAIL: rule {RULE_ID!r} not found in {cfg}", file=sys.stderr)
        return 1
    found = set(rule.get("paths", {}).get("exclude", []))
    if found != EXPECTED:
        print(f"FAIL: {RULE_ID} exclude list drifted from the documented allowlist.",
              file=sys.stderr)
        print(f"  expected: {sorted(EXPECTED)}", file=sys.stderr)
        print(f"  found:    {sorted(found)}", file=sys.stderr)
        print("  Every excluded file is a hole in the pure-logic unsafe ban. Keep the",
              file=sys.stderr)
        print("  list minimal and documented (see the rule header comment + its proofs).",
              file=sys.stderr)
        return 1
    print(f"    OK: {RULE_ID} exclude list == the 3 documented host-verified files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
