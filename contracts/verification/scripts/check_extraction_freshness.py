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

DELETION-TOLERANCE FLOORS (F3/F13, 2026-07-19). A registry that only ever gets
CHECKED is a registry that can be EDITED to green: deleting the drifted entry,
emptying a pin list, or shrinking the registry to zero entries all used to PASS
(zip() silently truncates; an empty registry has nothing to fail). This gate now
hard-fails on: (a) LIST-LENGTH MISMATCH between a files list and its pins list
("registry MALFORMED — possible dropped pin"); (b) an EMPTY registry or one
missing any target named in its top-level "required_targets" list ("registry
shrank — deletion-tolerance guard"); (c) any on-disk
extracted/Extracted/*/Funs.lean module NOT registered in any entry ("unpinned
extracted module" — the completeness floor; also what enrolls new extractions).
A pin referencing a file that does not exist still fails via the ordinary drift
path. HONEST SCOPE, updated: the floors police REGISTRY integrity (malformation,
shrinkage, unenrolled modules); they say nothing about whether a pinned
extraction is semantically correct — that remains `make verify-extraction-regen`.

Usage:
  check_extraction_freshness.py                 verify pins + floors (CI; exit 1 on
                                                drift or a floor violation)
  check_extraction_freshness.py --self-test     wired-in negative controls (FW tag flip
                                                + registry deletion/dropped-pin/unpinned-
                                                module floors)
  check_extraction_freshness.py --update <target> [--waived-ok]
                                                re-pin ONE entry's hashes (maintainer; run
                                                ONLY after `make verify-extraction-regen`
                                                confirms that extraction is fresh). Bare
                                                --update refuses (exit 2). Re-pinning a
                                                WAIVED-STALE (fresh:false) entry with live
                                                drift also refuses unless --waived-ok.
"""
from __future__ import annotations

import copy
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


def entry_drift(e: dict) -> list[str]:
    """Live drift of one entry's files vs their pins. A pin referencing a file that
    does not exist fails HERE (the ordinary drift path), not in a floor."""
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
    return drift


def evaluate(reg: dict) -> tuple[list[str], list[str], list[str], int, int]:
    """The check core, against an in-memory registry dict (self_test passes mutated
    copies here — the real extraction_registry.json is never touched).
    Returns (drift_fails, floor_fails, waived, fresh_ok, n_disk_modules)."""
    drift_fails: list[str] = []
    floor_fails: list[str] = []
    waived: list[str] = []
    fresh_ok = 0
    for e in reg["entries"]:
        tgt = e["target"]
        # FLOOR (a): length-match — zip() silently truncates a dropped pin.
        if (len(e["rust_files"]) != len(e["rust_files_sha256"])
                or len(e["generated_lean"]) != len(e["generated_lean_sha256"])):
            floor_fails.append(f"entry {tgt}: registry MALFORMED (list length mismatch — "
                               f"possible dropped pin)")
            continue
        drift = entry_drift(e)
        if not e.get("fresh", True):
            waived.append(f"{tgt}: WAIVED-STALE — {e.get('waiver', '(no reason given)')}"
                          + (f"  [+ live drift since pin: {'; '.join(drift)}]" if drift else ""))
            continue
        if drift:
            drift_fails.append(f"{tgt}: {'; '.join(drift)} — the committed extraction is NO LONGER "
                               f"known-fresh. Re-run `make -C {e['make_dir']} {tgt}` (needs the "
                               f"charon/aeneas toolchain), re-prove/re-build, then "
                               f"`check_extraction_freshness.py --update {tgt}` to re-pin.")
        else:
            fresh_ok += 1

    # FLOOR (b): required-ID / deletion-tolerance guard — the registry must not SHRINK.
    if not reg["entries"]:
        floor_fails.append("registry shrank — deletion-tolerance guard: ZERO entries "
                           "(an empty registry used to pass vacuously)")
    present = {e["target"] for e in reg["entries"]}
    for tgt in reg.get("required_targets", []):
        if tgt not in present:
            floor_fails.append(f"registry shrank — deletion-tolerance guard: required target "
                               f"{tgt} is ABSENT from the registry")

    # FLOOR (c): completeness — every on-disk extracted module MUST be pinned somewhere.
    registered = {g for e in reg["entries"] for g in e["generated_lean"]}
    disk_modules = sorted((VERIF_DIR / "extracted" / "Extracted").glob("*/Funs.lean"))
    for f in disk_modules:
        rel = f.relative_to(REPO_ROOT).as_posix()
        if rel not in registered:
            floor_fails.append(f"unpinned extracted module {rel} — add it to extraction_registry.json")
    return drift_fails, floor_fails, waived, fresh_ok, len(disk_modules)


def check() -> int:
    reg = load_registry()
    drift_fails, floor_fails, waived, fresh_ok, n_modules = evaluate(reg)
    fails = drift_fails + floor_fails

    print(f"=== verify-extraction-freshness ({len(reg['entries'])} extractions) ===")
    print("    sha256 tripwire: committed generated Lean + mirrored Rust file. Toolchain-free.")
    floor_note = (f"registry floors OK ({n_modules} on-disk extracted module(s) all pinned, "
                  f"required-targets present, pin lists length-matched)" if not floor_fails else
                  f"registry floors VIOLATED ({len(floor_fails)} — see FAIL below)")
    print(f"    fresh & pinned-OK: {fresh_ok} | waived-stale: {len(waived)} | "
          f"drifted: {len(drift_fails)} | {floor_note}")
    for w in waived:
        print(f"  [waived] {w}")
    if fails:
        print(f"\nFAIL: {len(fails)} freshness/registry failure(s) "
              f"({len(drift_fails)} drifted pin(s), {len(floor_fails)} floor violation(s)):", file=sys.stderr)
        for f in fails:
            print(f"  - {f}", file=sys.stderr)
        print("\nA green verify-build/verify-extracted on a stale committed .lean is exactly the "
              "F1 defect. Re-extract before trusting the extracted proofs.", file=sys.stderr)
        return 1
    print("\nOK: every fresh extraction matches its pin (Rust unchanged since last extraction) and "
          "the registry floors hold. NB this is a freshness tripwire, not a correspondence proof — "
          "see `make verify-extraction-regen`.")
    return 0


def update(args: list[str]) -> int:
    """Re-pin ONE entry's hashes from the current tree. MAINTAINER ONLY — run this only
    after `make verify-extraction-regen` has confirmed that entry's committed extraction
    actually matches a fresh charon→aeneas run; otherwise you would pin drift. Bare
    `--update` (no target) refuses: re-pinning EVERYTHING from a possibly-drifted tree is
    the self-referential F3(c) defect. Re-pinning a WAIVED-STALE (fresh:false) entry whose
    files currently drift from the pins also refuses unless --waived-ok is passed —
    re-basing a waiver onto the drifted tree must be a deliberate act."""
    unknown = [a for a in args if a.startswith("--") and a != "--waived-ok"]
    targets = [a for a in args if not a.startswith("--")]
    if unknown or len(targets) != 1:
        print("usage: check_extraction_freshness.py --update <target> [--waived-ok]\n"
              "  Re-pin ONE registry entry from the current tree (bare --update refuses: re-pinning\n"
              "  EVERYTHING from a possibly-drifted tree is the self-referential F3(c) defect).\n"
              "  Run ONLY after `make verify-extraction-regen` confirms that extraction is fresh.\n"
              "  A WAIVED-STALE (fresh:false) entry with live drift also needs --waived-ok.",
              file=sys.stderr)
        return 2
    waived_ok = "--waived-ok" in args
    target = targets[0]
    reg = load_registry()
    entry = next((e for e in reg["entries"] if e["target"] == target), None)
    if entry is None:
        known = ", ".join(e["target"] for e in reg["entries"])
        print(f"ERROR: no registry entry with target {target!r}. Known targets: {known}",
              file=sys.stderr)
        return 2
    drift = entry_drift(entry)
    if drift and not entry.get("fresh", True) and not waived_ok:
        print(f"REFUSED: {target} is WAIVED-STALE (fresh:false) and its files drift from the pins:\n"
              + "\n".join(f"  - {d}" for d in drift)
              + "\nRe-pinning would silently re-base the waiver onto the drifted tree. Pass "
                "--waived-ok to acknowledge, or fix the extraction first "
                "(`make verify-extraction-regen`).",
              file=sys.stderr)
        return 2
    entry["rust_files_sha256"] = [sha256_file(REPO_ROOT / r) for r in entry["rust_files"]]
    entry["generated_lean_sha256"] = [sha256_file(REPO_ROOT / g) for g in entry["generated_lean"]]
    REGISTRY.write_text(json.dumps(reg, indent=2) + "\n", encoding="utf-8")
    print(f"re-pinned {target} in {REGISTRY}. "
          f"REMINDER: only valid if `make verify-extraction-regen` was green first.")
    return 0


def self_test() -> int:
    """WIRED-IN NEGATIVE CONTROLS.
    (F1) the FW-manifest domain-tag `PQFW_V1`->`PQFW_V2` single-byte flip must move BOTH
    tripwire halves. `verify-build`/`verify-extracted` would stay GREEN on the stale
    committed Lean; the freshness tripwire must go RED.
    (F3/F13) the three registry floors must each fire on an IN-MEMORY mutated copy of
    the registry (the real extraction_registry.json is never touched): (a) one entry
    DELETED -> required-ID floor; (b) one pin DROPPED from an entry -> length-match
    floor (the old zip() silently truncated this to a pass); (c) one real on-disk
    module removed from the registry (and from required_targets, isolating the floor)
    -> completeness floor."""
    print("=== check_extraction_freshness --self-test (FW-tag flip + registry-floor negative controls) ===")
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

    # FLOOR NEGATIVES (F3/F13): run the checker core against IN-MEMORY mutated copies
    # of the registry — the real extraction_registry.json is never touched.
    # (a) required-ID floor: a copy with one entry DELETED must fail the deletion guard.
    shrunk = copy.deepcopy(reg)
    dropped = shrunk["entries"].pop()
    fa = evaluate(shrunk)[1]
    if any("deletion-tolerance guard" in m and dropped["target"] in m for m in fa):
        print(f"  ok: in-memory copy with entry '{dropped['target']}' DELETED fails "
              f"(required-ID floor fires)")
    else:
        print(f"  FAIL: deleting entry '{dropped['target']}' did NOT fire the required-ID floor!")
        ok = False

    # (b) length-match floor: a copy with one pin DROPPED from an entry must fail MALFORMED
    #     (the old zip() silently truncated exactly this to a pass).
    mal = copy.deepcopy(reg)
    victim = mal["entries"][0]
    victim["rust_files_sha256"] = victim["rust_files_sha256"][:-1]
    fb = evaluate(mal)[1]
    if any("MALFORMED" in m and victim["target"] in m for m in fb):
        print(f"  ok: in-memory copy with a dropped pin in '{victim['target']}' fails "
              f"(length-match floor fires)")
    else:
        print(f"  FAIL: a dropped pin in '{victim['target']}' did NOT fire the length-match floor!")
        ok = False

    # (c) completeness floor: a copy missing one REAL on-disk module must fail unpinned.
    #     The entry is removed from required_targets too, so ONLY the completeness floor
    #     can catch it (isolation).
    comp = copy.deepcopy(reg)
    victim = next(e for e in comp["entries"]
                  if any(g.endswith("/Funs.lean") for g in e["generated_lean"]))
    comp["entries"] = [e for e in comp["entries"] if e["target"] != victim["target"]]
    comp["required_targets"] = [t for t in comp.get("required_targets", []) if t != victim["target"]]
    fc = evaluate(comp)[1]
    if any("unpinned extracted module" in m for m in fc):
        print(f"  ok: in-memory copy missing the on-disk module of '{victim['target']}' fails "
              f"(completeness floor fires)")
    else:
        print(f"  FAIL: removing '{victim['target']}' (module still on disk) did NOT fire the "
              f"completeness floor!")
        ok = False

    print("=== self-test PASS ===" if ok else "=== self-test FAILED ===")
    return 0 if ok else 1


def main() -> int:
    args = sys.argv[1:]
    if "--self-test" in args:
        return self_test()
    if "--update" in args:
        return update([a for a in args if a != "--update"])
    return check()


if __name__ == "__main__":
    sys.exit(main())
