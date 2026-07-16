#!/usr/bin/env python3
"""verify-extraction-freshness — the TOOLCHAIN-FREE half of the F1 fix (2026-07-16).

THE GAP (FV review finding F1). The 15 `extract-*` Make targets regenerate the
Aeneas extraction and `diff` it against the committed `Extracted/<Mod>/Funs.lean`
— a real freshness gate, but it needs the §33 charon/aeneas toolchain in
`~/.local/share/pqsigner-lean`, so it is NOT runnable on a stock CI runner.
Without it, current Rust can drift from the committed Lean while `verify-build`
and `verify-extracted` stay green (the committed `.lean` still type-checks
against its own stale self). Empirically, 4 of 15 extractions were already stale
when this gate was written (tx-merkle semantically; bip39/u256-mul/fwmanifest
cosmetically — since refreshed) and NO green gate caught it.

THIS GATE is the CI-runnable tripwire: it pins `sha256(committed generated Lean)`
(robust primary — the literal charon→aeneas output, so it moves on any semantic
drift including transitively-inlined callees) plus `sha256(mirrored Rust file)`
(coarse secondary — whole-file, over-fires on unrelated shared-file edits, never
under-fires). If EITHER drifts for a `fresh` entry, this FAILS: someone changed
the Rust (or the Lean) without re-running the named `extract-*` target, so the
committed extraction is no longer known-fresh. HONEST SCOPE: this is a
"Rust-unchanged-since-last-extraction" tripwire, NOT a correspondence proof; the
toolchain-gated `make verify-extraction-regen` (which actually re-runs charon→
aeneas and diffs) is the real regen check.

WAIVED-STALE entries (`fresh: false`) are reported LOUDLY with their waiver and
do NOT count as a clean pass — but they do not fail the build either (a
pre-existing, tracked drift, e.g. tx-merkle which Aeneas can no longer translate).
This is the honest middle ground F1 asks for: the drift is VISIBLE and TRACKED,
never silently green.

Usage:
  check_extraction_freshness.py                 verify pins (CI; exit 1 on drift)
  check_extraction_freshness.py --self-test     wired-in negative control (FW tag flip)
  check_extraction_freshness.py --update        re-pin ALL hashes (maintainer; run
                                                ONLY after `make verify-extraction-regen`
                                                confirms the extractions are fresh)
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

VERIF_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
REGISTRY = VERIF_DIR / "extraction_registry.json"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_registry() -> dict:
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


def check() -> int:
    reg = load_registry()
    fails: list[str] = []
    waived: list[str] = []
    fresh_ok = 0
    for e in reg["entries"]:
        tgt = e["target"]
        drift = []
        for rel, pin in zip(e["rust_files"], e["rust_files_sha256"]):
            p = REPO_ROOT / rel
            if not p.exists():
                drift.append(f"rust file {rel} MISSING")
            elif sha256_file(p) != pin:
                drift.append(f"rust file {rel} CHANGED (sha256 drift)")
        for rel, pin in zip(e["generated_lean"], e["generated_lean_sha256"]):
            p = REPO_ROOT / rel
            if not p.exists():
                drift.append(f"generated Lean {rel} MISSING")
            elif sha256_file(p) != pin:
                drift.append(f"generated Lean {rel} CHANGED (sha256 drift)")
        if not e.get("fresh", True):
            waived.append(f"{tgt}: WAIVED-STALE — {e.get('waiver', '(no reason given)')}"
                          + (f"  [+ live drift since pin: {'; '.join(drift)}]" if drift else ""))
            continue
        if drift:
            fails.append(f"{tgt}: {'; '.join(drift)} — the committed extraction is NO LONGER "
                         f"known-fresh. Re-run `make -C {e['make_dir']} {tgt}` (needs the "
                         f"charon/aeneas toolchain), re-prove/re-build, then "
                         f"`check_extraction_freshness.py --update` to re-pin.")
        else:
            fresh_ok += 1

    print(f"=== verify-extraction-freshness ({len(reg['entries'])} extractions) ===")
    print("    sha256 tripwire: committed generated Lean + mirrored Rust file. Toolchain-free.")
    print(f"    fresh & pinned-OK: {fresh_ok} | waived-stale: {len(waived)} | drifted: {len(fails)}")
    for w in waived:
        print(f"  [waived] {w}")
    if fails:
        print(f"\nFAIL: {len(fails)} extraction(s) drifted from their pin:", file=sys.stderr)
        for f in fails:
            print(f"  - {f}", file=sys.stderr)
        print("\nA green verify-build/verify-extracted on a stale committed .lean is exactly the "
              "F1 defect. Re-extract before trusting the extracted proofs.", file=sys.stderr)
        return 1
    print("\nOK: every fresh extraction matches its pin (Rust unchanged since last extraction). "
          "NB this is a freshness tripwire, not a correspondence proof — see `make verify-extraction-regen`.")
    return 0


def update() -> int:
    """Re-pin every hash from the current tree. MAINTAINER ONLY — run this only
    after `make verify-extraction-regen` has confirmed the committed extractions
    actually match a fresh charon→aeneas run; otherwise you would pin drift."""
    reg = load_registry()
    for e in reg["entries"]:
        e["rust_files_sha256"] = [sha256_file(REPO_ROOT / r) for r in e["rust_files"]]
        e["generated_lean_sha256"] = [sha256_file(REPO_ROOT / g) for g in e["generated_lean"]]
    REGISTRY.write_text(json.dumps(reg, indent=2) + "\n", encoding="utf-8")
    print(f"re-pinned {len(reg['entries'])} extractions in {REGISTRY}. "
          f"REMINDER: only valid if `make verify-extraction-regen` was green first.")
    return 0


def self_test() -> int:
    """WIRED-IN NEGATIVE CONTROL (F1): the FW-manifest domain-tag `PQFW_V1`->`PQFW_V2`
    single-byte flip must move BOTH tripwire halves. `verify-build`/`verify-extracted`
    would stay GREEN on the stale committed Lean; the freshness tripwire must go RED."""
    print("=== check_extraction_freshness --self-test (FW-tag flip negative control) ===")
    reg = load_registry()
    fw = next(e for e in reg["entries"] if e["target"] == "extract-fwmanifest-preimage")
    ok = True

    # Clean control: the real files must MATCH their pins (fresh entry).
    rust = REPO_ROOT / fw["rust_files"][0]
    lean = REPO_ROOT / fw["generated_lean"][0]
    clean_rust = sha256_file(rust) == fw["rust_files_sha256"][0]
    clean_lean = sha256_file(lean) == fw["generated_lean_sha256"][0]
    if clean_rust and clean_lean:
        print("  ok: clean fw-manifest files MATCH their pins (not always-firing)")
    else:
        print(f"  FAIL: clean fw-manifest files do NOT match pins (rust_ok={clean_rust} lean_ok={clean_lean})")
        ok = False

    # PoC (Rust half): flip PQFW_V1 -> PQFW_V2 in the source bytes.
    rb = rust.read_bytes()
    if b"PQFW_V1" not in rb:
        print("  FAIL: could not find b\"PQFW_V1\" in the fw-manifest source (tag moved?)")
        ok = False
    else:
        mutated = rb.replace(b"PQFW_V1", b"PQFW_V2", 1)
        if sha256_bytes(mutated) != fw["rust_files_sha256"][0]:
            print("  ok: PQFW_V1->PQFW_V2 source flip DIVERGES from the rust pin (tripwire fires)")
        else:
            print("  FAIL: source tag flip did NOT change the rust hash — tripwire vacuous!")
            ok = False

    # PoC (Lean half): the literal 49#u8 ('1') -> 50#u8 ('2') in the generated Lean.
    lb = lean.read_bytes()
    if b"49#u8" not in lb:
        print("  FAIL: could not find the tag byte 49#u8 in the generated Lean")
        ok = False
    else:
        mutated = lb.replace(b"49#u8", b"50#u8", 1)
        if sha256_bytes(mutated) != fw["generated_lean_sha256"][0]:
            print("  ok: 49#u8->50#u8 generated-Lean flip DIVERGES from the lean pin (tripwire fires)")
        else:
            print("  FAIL: generated-Lean tag flip did NOT change the hash — tripwire vacuous!")
            ok = False

    print("=== self-test PASS ===" if ok else "=== self-test FAILED ===")
    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    if "--update" in sys.argv[1:]:
        return update()
    return check()


if __name__ == "__main__":
    sys.exit(main())
