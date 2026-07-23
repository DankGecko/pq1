#!/usr/bin/env python3
"""verify-extraction-freshness — the TOOLCHAIN-FREE half of the F1 fix (2026-07-16).

THE GAP (FV review finding F1). The 17 `extract-*` Make targets regenerate the
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

DELETION-TOLERANCE FLOORS (F3/F13, 2026-07-19; fail-closed 2026-07-23). A
registry that only ever gets CHECKED is a registry that can be EDITED to green:
deleting a drifted entry, emptying a paired file+pin list, marking an entry
`fresh:false`, or rewriting the registry's own required-target list all used to
evade the tripwire. The gate therefore owns the exact target identities and the
only permitted waived-stale identity in code. A checker-owned digest also binds
the entire registry, including every pin and the waiver reason. It hard-fails
on: (a) target identity/order drift, per-target Rust/generated-Lean path drift,
duplicates, mutable `required_targets`, or any registry-binding drift; (b)
EMPTY, malformed/all-zero, or length-mismatched pins; (c) any waiver other than
the checker-owned `extract-tx-merkle` record, or any change from that waiver's
expected live-drift state; (d) any recursively discovered `**/Funs.lean` or
Aeneas-marker generated module not registered in an entry. A pin referencing a
file that does not exist still fails via the ordinary drift path. HONEST SCOPE,
updated: the floors police REGISTRY integrity (malformation, shrinkage, waiver
identity, unenrolled modules); they say nothing about whether a pinned
extraction is semantically correct — that remains
`make verify-extraction-regen`.

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
                                                Any accepted re-pin also requires a reviewed
                                                REGISTRY_BINDING_SHA256 update.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from pathlib import Path

VERIF_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
REGISTRY = VERIF_DIR / "extraction_registry.json"

# Checker-owned deletion/waiver floor. Keeping target and target→file identities
# outside the mutable registry makes deleting/replacing an entry or one of its
# paired paths, rewriting required_targets, or flipping fresh:false a gate
# failure rather than a way to redefine what the gate is meant to cover.
REQUIRED_ENTRY_PATHS = {
    "extract-sphincs-adrs": (
        ("sphincs-c10/src/address.rs",),
        ("contracts/verification/extracted/Extracted/Adrs.lean",),
    ),
    "extract-aa-userop": (
        ("aa/src/userop.rs",),
        ("contracts/verification/extracted/Extracted/UserOp/Funs.lean",
         "contracts/verification/extracted/Extracted/UserOp/Types.lean",
         "contracts/verification/extracted/Extracted/UserOp/FunsExternal.lean"),
    ),
    "extract-fors-index": (
        ("sphincs-c10/src/fors.rs",),
        ("contracts/verification/extracted/Extracted/Fors/Funs.lean",
         "contracts/verification/extracted/Extracted/Fors/Types.lean"),
    ),
    "extract-tx-merkle": (
        ("tx/src/erc20/merkle.rs",),
        ("contracts/verification/extracted/Extracted/TxMerkle/Funs.lean",
         "contracts/verification/extracted/Extracted/TxMerkle/Types.lean",
         "contracts/verification/extracted/Extracted/TxMerkle/FunsExternal.lean"),
    ),
    "extract-merkle-verify": (
        ("sphincs-c10/src/merkle.rs",),
        ("contracts/verification/extracted/Extracted/Merkle/Funs.lean",
         "contracts/verification/extracted/Extracted/Merkle/Types.lean",
         "contracts/verification/extracted/Extracted/Merkle/FunsExternal.lean"),
    ),
    "extract-wots-pkfromsig": (
        ("sphincs-c10/src/wots.rs",),
        ("contracts/verification/extracted/Extracted/PkFromSig/Funs.lean",
         "contracts/verification/extracted/Extracted/PkFromSig/Types.lean",
         "contracts/verification/extracted/Extracted/PkFromSig/FunsExternal.lean"),
    ),
    "extract-hash-fns": (
        ("sphincs-c10/src/hash.rs",),
        ("contracts/verification/extracted/Extracted/Hash/Funs.lean",
         "contracts/verification/extracted/Extracted/Hash/Types.lean",
         "contracts/verification/extracted/Extracted/Hash/FunsExternal.lean"),
    ),
    "extract-bip39-roundtrip": (
        ("bip39/src/lib.rs",),
        ("contracts/verification/extracted/Extracted/Bip39/Funs.lean",
         "contracts/verification/extracted/Extracted/Bip39/Types.lean"),
    ),
    "extract-decode-item": (
        ("tx-core/src/rlp.rs",),
        ("contracts/verification/extracted/Extracted/Decode/Funs.lean",
         "contracts/verification/extracted/Extracted/Decode/Types.lean",
         "contracts/verification/extracted/Extracted/Decode/FunsExternal.lean"),
    ),
    "extract-u256-mul": (
        ("tx-core/src/eip1559.rs",),
        ("contracts/verification/extracted/Extracted/U256Mul/Funs.lean",
         "contracts/verification/extracted/Extracted/U256Mul/Types.lean"),
    ),
    "extract-format-decimal": (
        ("tx-core/src/eip1559.rs",),
        ("contracts/verification/extracted/Extracted/FormatDecimal/Funs.lean",),
    ),
    "extract-fwmanifest-preimage": (
        ("fw-manifest/src/lib.rs",),
        ("contracts/verification/extracted/Extracted/FwManifest/Funs.lean",
         "contracts/verification/extracted/Extracted/FwManifest/Types.lean"),
    ),
    "extract-wots-digits": (
        ("sphincs-c10/src/wots.rs",),
        ("contracts/verification/extracted/Extracted/Wots/Funs.lean",
         "contracts/verification/extracted/Extracted/Wots/Types.lean"),
    ),
    "extract-aa-eip1271": (
        ("aa/src/eip1271.rs",),
        ("contracts/verification/extracted/Extracted/Eip1271/Funs.lean",
         "contracts/verification/extracted/Extracted/Eip1271/Types.lean",
         "contracts/verification/extracted/Extracted/Eip1271/FunsExternal.lean"),
    ),
    "extract-txcore-rlp": (
        ("tx-core/src/rlp.rs",),
        ("contracts/verification/extracted/Extracted/Rlp/Funs.lean",
         "contracts/verification/extracted/Extracted/Rlp/Types.lean",
         "contracts/verification/extracted/Extracted/Rlp/FunsExternal.lean"),
    ),
    "extract-pinstate": (
        ("domain/src/lib.rs", "proto/src/lib.rs"),
        ("contracts/verification/extracted/Extracted/PinState/Funs.lean",
         "contracts/verification/extracted/Extracted/PinState/Types.lean",
         "contracts/verification/extracted/Extracted/PinState/TypesExternal.lean",
         "contracts/verification/extracted/Extracted/PinState/FunsExternal.lean"),
    ),
    "extract-slotkdf": (
        ("domain/src/lib.rs",),
        ("contracts/verification/extracted/Extracted/SlotKdf/Funs.lean",
         "contracts/verification/extracted/Extracted/SlotKdf/Types.lean",
         "contracts/verification/extracted/Extracted/SlotKdf/FunsExternal.lean"),
    ),
}
REQUIRED_TARGETS = tuple(REQUIRED_ENTRY_PATHS)
ALLOWED_WAIVED_TARGETS = frozenset({"extract-tx-merkle"})
REGISTRY_BINDING_SHA256 = "8baf893c83b074cf5fd2959841c11abd2b2f41e1c35b864539f7e614e23fb312"
EXPECTED_WAIVED_DRIFT = {"extract-tx-merkle": ()}
SHA256_RE = re.compile(r"[0-9a-f]{64}")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_registry() -> dict:
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


def registry_binding(reg: dict) -> str:
    """Stable integrity binding for all mutable registry metadata and pins."""
    canonical = json.dumps(
        reg, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def discover_generated_modules() -> list[Path]:
    """Recursively find committed Aeneas output.

    Split extractions use Funs.lean; single-file output (for example Adrs.lean)
    and generated Types.lean carry Aeneas's first-line marker. The union catches
    both shapes while excluding the many hand-written proof/spec modules.
    """
    root = VERIF_DIR / "extracted" / "Extracted"
    found = set(root.rglob("Funs.lean"))
    for path in root.rglob("*.lean"):
        try:
            with path.open(encoding="utf-8", errors="replace") as source:
                first_line = source.readline()
        except OSError:
            continue
        if "THIS FILE WAS AUTOMATICALLY GENERATED BY AENEAS" in first_line:
            found.add(path)
    return sorted(found)


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

    live_binding = registry_binding(reg)
    if live_binding != REGISTRY_BINDING_SHA256:
        floor_fails.append(
            "registry integrity binding mismatch — pins/waivers/metadata changed; "
            f"expected {REGISTRY_BINDING_SHA256}, got {live_binding}"
        )

    entries = reg.get("entries")
    if not isinstance(entries, list):
        return [], ["registry MALFORMED: entries must be a list"], [], 0, 0

    targets = [e.get("target") if isinstance(e, dict) else None for e in entries]
    if targets != list(REQUIRED_TARGETS):
        floor_fails.append(
            "checker-owned target identity/order mismatch — expected "
            f"{list(REQUIRED_TARGETS)}, got {targets}"
        )
    duplicates = sorted({t for t in targets if t is not None and targets.count(t) > 1})
    if duplicates:
        floor_fails.append(f"duplicate registry target(s): {duplicates}")
    if reg.get("required_targets") != list(REQUIRED_TARGETS):
        floor_fails.append(
            "mutable required_targets metadata does not exactly mirror the "
            "checker-owned target identity list"
        )

    for e in entries:
        if not isinstance(e, dict) or not isinstance(e.get("target"), str):
            floor_fails.append("registry MALFORMED: every entry needs a string target")
            continue
        tgt = e["target"]
        list_keys = (
            "rust_files",
            "rust_files_sha256",
            "generated_lean",
            "generated_lean_sha256",
        )
        if any(not isinstance(e.get(k), list) for k in list_keys):
            floor_fails.append(
                f"entry {tgt}: registry MALFORMED (file and pin fields must be lists)"
            )
            continue
        if any(len(e[k]) == 0 for k in list_keys):
            floor_fails.append(
                f"entry {tgt}: registry MALFORMED (empty file/pin list — paired-empty "
                "lists used to pass vacuously)"
            )
            continue
        # Length matching prevents zip() from silently truncating a dropped pin.
        if (len(e["rust_files"]) != len(e["rust_files_sha256"])
                or len(e["generated_lean"]) != len(e["generated_lean_sha256"])):
            floor_fails.append(f"entry {tgt}: registry MALFORMED (list length mismatch — "
                               f"possible dropped pin)")
            continue
        pins = e["rust_files_sha256"] + e["generated_lean_sha256"]
        if any(not isinstance(pin, str) or SHA256_RE.fullmatch(pin) is None
               or pin == "0" * 64 for pin in pins):
            floor_fails.append(
                f"entry {tgt}: registry MALFORMED (every pin must be a nonzero "
                "lowercase 64-hex sha256)"
            )
            continue
        expected_paths = REQUIRED_ENTRY_PATHS.get(tgt)
        if expected_paths is None:
            floor_fails.append(f"entry {tgt}: unexpected target has no checker-owned path identity")
            continue
        if (tuple(e["rust_files"]) != expected_paths[0]
                or tuple(e["generated_lean"]) != expected_paths[1]):
            floor_fails.append(
                f"entry {tgt}: checker-owned file identity mismatch — expected "
                f"rust={list(expected_paths[0])}, lean={list(expected_paths[1])}; got "
                f"rust={e['rust_files']}, lean={e['generated_lean']}"
            )
            continue
        if not isinstance(e.get("fresh"), bool):
            floor_fails.append(f"entry {tgt}: registry MALFORMED (fresh must be explicit bool)")
            continue

        is_waived = not e["fresh"]
        if is_waived and tgt not in ALLOWED_WAIVED_TARGETS:
            floor_fails.append(
                f"entry {tgt}: unauthorised waived-stale target — fresh:false cannot "
                "redefine checker coverage"
            )
            continue
        if not is_waived and tgt in ALLOWED_WAIVED_TARGETS:
            floor_fails.append(
                f"entry {tgt}: checker-owned waiver identity changed without updating "
                "the gate"
            )
            continue

        drift = entry_drift(e)
        if is_waived:
            if not isinstance(e.get("waiver"), str) or not e["waiver"].strip():
                floor_fails.append(
                    f"entry {tgt}: checker-owned waiver requires a nonempty reason"
                )
            expected_drift = EXPECTED_WAIVED_DRIFT[tgt]
            if tuple(drift) != expected_drift:
                floor_fails.append(
                    f"entry {tgt}: waived live drift changed — expected "
                    f"{list(expected_drift)}, got {drift}; re-review the waiver"
                )
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

    # Completeness is recursive: nested generated modules must not evade enrollment.
    registered = {
        g
        for e in entries
        if isinstance(e, dict) and isinstance(e.get("generated_lean"), list)
        for g in e["generated_lean"]
    }
    disk_modules = discover_generated_modules()
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
                  f"registry digest + target/file/waiver identities exact, pins well-formed)" if not floor_fails else
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
          f"REMINDER: only valid if `make verify-extraction-regen` was green first; "
          f"review and update REGISTRY_BINDING_SHA256 before the gate can pass.")
    return 0


def self_test() -> int:
    """WIRED-IN NEGATIVE CONTROLS.
    (F1) the FW-manifest domain-tag `PQFW_V1`->`PQFW_V2` single-byte flip must move BOTH
    tripwire halves. `verify-build`/`verify-extracted` would stay GREEN on the stale
    committed Lean; the freshness tripwire must go RED.
    (F3/F13) the fail-closed registry floors must each fire on an IN-MEMORY
    mutated copy of the registry (the real extraction_registry.json is never
    touched): deleted entry, dropped pin, paired-empty file+pin lists, paired
    path+pin deletion/replacement, blank/all-zero pins, waiver reason/drift
    tampering, rewritten required_targets metadata, unauthorised fresh:false,
    and an unregistered on-disk generated module."""
    print("=== check_extraction_freshness --self-test "
          "(FW-tag flip + fail-closed registry negative controls) ===")
    reg = load_registry()
    fw = next(e for e in reg["entries"] if e["target"] == "extract-fwmanifest-preimage")
    ok = True

    if registry_binding(reg) == REGISTRY_BINDING_SHA256:
        print("  ok: clean registry matches its checker-owned integrity binding")
    else:
        print("  FAIL: clean registry does not match REGISTRY_BINDING_SHA256")
        ok = False
    adrs = REPO_ROOT / "contracts/verification/extracted/Extracted/Adrs.lean"
    if adrs in discover_generated_modules():
        print("  ok: recursive generated-module census includes single-file Adrs.lean")
    else:
        print("  FAIL: generated-module census missed single-file Aeneas output Adrs.lean")
        ok = False

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
    # (a) checker-owned identity floor: a copy with one entry DELETED must fail.
    shrunk = copy.deepcopy(reg)
    dropped = shrunk["entries"].pop()
    fa = evaluate(shrunk)[1]
    if any("checker-owned target identity/order mismatch" in m for m in fa):
        print(f"  ok: in-memory copy with entry '{dropped['target']}' DELETED fails "
              f"(checker-owned identity floor fires)")
    else:
        print(f"  FAIL: deleting entry '{dropped['target']}' did NOT fire the "
              f"checker-owned identity floor!")
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

    # (c) paired-empty floor: deleting BOTH a file and its matching pin must not
    #     turn zip() into a vacuous pass.
    empty = copy.deepcopy(reg)
    victim = empty["entries"][0]
    victim["rust_files"] = []
    victim["rust_files_sha256"] = []
    fc = evaluate(empty)[1]
    if any("empty file/pin list" in m and victim["target"] in m for m in fc):
        print(f"  ok: paired-empty file+pin lists in '{victim['target']}' fail "
              f"(non-empty floor fires)")
    else:
        print(f"  FAIL: paired-empty file+pin lists in '{victim['target']}' passed vacuously!")
        ok = False

    # (d) deleting a non-Funs generated path AND its matching pin used to evade
    #     both the length and Funs-only completeness floors.
    paired_drop = copy.deepcopy(reg)
    victim = next(e for e in paired_drop["entries"] if len(e["generated_lean"]) > 1)
    victim["generated_lean"].pop()
    victim["generated_lean_sha256"].pop()
    fd = evaluate(paired_drop)[1]
    if any("checker-owned file identity mismatch" in m and victim["target"] in m for m in fd):
        print(f"  ok: paired generated-path+pin deletion in '{victim['target']}' fails "
              f"(checker-owned file identity fires)")
    else:
        print(f"  FAIL: paired generated-path+pin deletion in '{victim['target']}' escaped!")
        ok = False

    # (e) replacing a mirrored Rust path and its pin with another real pair must
    #     not silently retarget the tripwire.
    retarget = copy.deepcopy(reg)
    victim = next(e for e in retarget["entries"]
                  if e["target"] == "extract-fwmanifest-preimage")
    donor = next(e for e in retarget["entries"] if e["target"] == "extract-aa-userop")
    victim["rust_files"] = donor["rust_files"][:]
    victim["rust_files_sha256"] = donor["rust_files_sha256"][:]
    fe = evaluate(retarget)[1]
    if any("checker-owned file identity mismatch" in m and victim["target"] in m for m in fe):
        print(f"  ok: paired Rust-path+pin replacement in '{victim['target']}' fails "
              f"(checker-owned file identity fires)")
    else:
        print(f"  FAIL: paired Rust-path+pin replacement in '{victim['target']}' retargeted "
              f"the tripwire!")
        ok = False

    # (f) mutable metadata cannot redefine the checker-owned target floor.
    metadata = copy.deepcopy(reg)
    metadata["required_targets"] = []
    ff = evaluate(metadata)[1]
    if any("mutable required_targets metadata" in m for m in ff):
        print("  ok: rewriting required_targets to [] fails (checker owns target identities)")
    else:
        print("  FAIL: rewriting required_targets to [] redefined the coverage floor!")
        ok = False

    # (g) an ordinary fresh entry cannot be waived by flipping fresh:false.
    waiver = copy.deepcopy(reg)
    victim = next(e for e in waiver["entries"]
                  if e["target"] not in ALLOWED_WAIVED_TARGETS)
    victim["fresh"] = False
    fg = evaluate(waiver)[1]
    if any("unauthorised waived-stale target" in m and victim["target"] in m for m in fg):
        print(f"  ok: fresh:false on '{victim['target']}' fails "
              f"(checker-owned waiver identity fires)")
    else:
        print(f"  FAIL: fresh:false on '{victim['target']}' bypassed drift checking!")
        ok = False

    # (h) blank/all-zero pins and a missing waiver reason on the sole authorized
    #     stale entry must fail before waiver handling can hide them.
    for label, replacement in (("blank", ""), ("all-zero", "0" * 64)):
        bad_pin = copy.deepcopy(reg)
        victim = next(e for e in bad_pin["entries"]
                      if e["target"] == "extract-tx-merkle")
        victim["rust_files_sha256"][0] = replacement
        fh = evaluate(bad_pin)[1]
        if any("nonzero lowercase 64-hex sha256" in m and victim["target"] in m for m in fh):
            print(f"  ok: {label} pin on authorized waiver fails (pin-shape floor fires)")
        else:
            print(f"  FAIL: {label} pin on authorized waiver passed!")
            ok = False

    no_reason = copy.deepcopy(reg)
    victim = next(e for e in no_reason["entries"]
                  if e["target"] == "extract-tx-merkle")
    victim.pop("waiver")
    fi = evaluate(no_reason)[1]
    if any("requires a nonempty reason" in m and victim["target"] in m for m in fi):
        print("  ok: missing authorized-waiver reason fails")
    else:
        print("  FAIL: missing authorized-waiver reason passed!")
        ok = False

    # (i) the waiver is bound to its current zero-live-drift state. Replacing
    #     its valid pin with another valid sha256 must force re-review.
    drifted_waiver = copy.deepcopy(reg)
    victim = next(e for e in drifted_waiver["entries"]
                  if e["target"] == "extract-tx-merkle")
    donor = next(e for e in drifted_waiver["entries"]
                 if e["target"] == "extract-aa-userop")
    victim["rust_files_sha256"][0] = donor["rust_files_sha256"][0]
    fj = evaluate(drifted_waiver)[1]
    if any("waived live drift changed" in m and victim["target"] in m for m in fj):
        print("  ok: changed live drift on authorized waiver fails")
    else:
        print("  FAIL: changed live drift on authorized waiver passed!")
        ok = False

    # (j) recursive completeness floor: a copy missing one REAL on-disk module
    #     must still report the unpinned module even though the mutable
    #     required_targets metadata is edited in tandem.
    comp = copy.deepcopy(reg)
    victim = next(e for e in comp["entries"]
                  if any(g.endswith("/Funs.lean") for g in e["generated_lean"]))
    comp["entries"] = [e for e in comp["entries"] if e["target"] != victim["target"]]
    comp["required_targets"] = [t for t in comp.get("required_targets", []) if t != victim["target"]]
    fk = evaluate(comp)[1]
    if any("unpinned extracted module" in m for m in fk):
        print(f"  ok: in-memory copy missing the on-disk module of '{victim['target']}' fails "
              f"(recursive completeness floor fires)")
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
