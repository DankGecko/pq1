#!/usr/bin/env python3
"""verify-kani-mutation — the Kani-side analogue of the Lean `verify-proof-mutation`
gate (contracts/verification/scripts/check_proof_mutations.py). It answers the
same anti-vacuity gut-check mechanically, but for the firmware bounded-verification
harnesses instead of the Lean proofs:

    "If I broke this decoder / gate, would a Kani harness actually turn red?"

For each entry in scripts/kani_mutations.json it mutates a production
decoder/gate function in a way whose outcome is KNOWN (a load-bearing break that
a specific harness is supposed to catch -> expect that harness to flip to
`VERIFICATION:- FAILED`), runs ONLY that harness, and asserts the result matches
`expect`. A green-when-it-should-be-red is a vacuous / under-constrained harness
(the exact failure the per-slice manual mutation checks caught by hand — this
makes them a standing gate). Institutionalises work-todo §34/§35.

ROBUSTNESS (mirrors the Lean gate — non-negotiable):
  * Every mutation must MATERIALLY change the file (find present EXACTLY once,
    replace != find). A mutation that fails to apply is a HARD FAIL (exit 2),
    never a silent skip — else the catcher reproduces the vacuity it exists to
    catch.
  * A CANARY mutation (id == "canary", always run) must be caught. If it is not,
    the harness machinery is broken (kani not running / output not parsed) and
    ALL results are void (exit 2).
  * The mutated file is ALWAYS reverted (finally + atexit + SIGINT/SIGTERM) and
    the revert is VERIFIED (re-read == original); a failed revert is a hard error
    with a `git checkout` recovery hint.

SCOPE: closes the "vacuous Kani harness" class for the covered harnesses. It does
NOT prove the harnesses are complete (a mutation not in the manifest may still
survive) — it pins the specific load-bearing behaviours. Add an entry whenever a
new load-bearing harness lands.

Usage:
    check_kani_mutations.py [--tier quick|default|full] [--list]
Environment: MUTATIONS=quick|default|full overrides the tier (default: default).

Exit: 0 = every mutation was caught as expected; 1 = a survivor (vacuous harness)
      found; 2 = harness/manifest error (mutation didn't apply, canary survived,
      revert failed, kani missing / did not run).
"""
from __future__ import annotations

import atexit
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
MANIFEST = SCRIPT_DIR / "kani_mutations.json"

TIER_ORDER = {"quick": 0, "default": 1, "full": 2}

# Global so the signal/atexit handler can restore a half-applied mutation.
_ACTIVE: tuple[Path, str] | None = None


def _restore_active() -> None:
    global _ACTIVE
    if _ACTIVE is None:
        return
    path, orig = _ACTIVE
    try:
        path.write_text(orig, encoding="utf-8")
    except OSError:
        sys.stderr.write(f"\n!!! COULD NOT REVERT {path} — run `git checkout -- {path}` !!!\n")
    _ACTIVE = None


def _signal_handler(signum, frame):
    sys.stderr.write(f"\n[caught signal {signum}] reverting active mutation…\n")
    _restore_active()
    sys.exit(2)


atexit.register(_restore_active)
signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


class HarnessError(Exception):
    pass


def run_kani(crate: str, harness: str, z_flags: list[str]) -> tuple[str, str]:
    """Run one Kani harness. Returns (outcome, tail) where outcome is
    "kani_fails" (harness reported VERIFICATION:- FAILED), "kani_passes"
    (VERIFICATION:- SUCCESSFUL), or raises HarnessError if kani did not produce
    a verdict (compile error / crash / missing tool)."""
    cmd = ["cargo", "kani", "-p", crate, *z_flags, "--harness", harness]
    try:
        cp = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=1800)
    except FileNotFoundError:
        raise HarnessError("`cargo kani` not runnable — install kani-verifier + `cargo kani setup`.")
    except subprocess.TimeoutExpired:
        raise HarnessError(f"kani timed out on {crate}::{harness} (>1800s).")
    out = cp.stdout + cp.stderr
    tail = out[-800:].strip()
    if "VERIFICATION:- FAILED" in out:
        return "kani_fails", tail
    if "VERIFICATION:- SUCCESSFUL" in out:
        return "kani_passes", tail
    # No verdict line: compile error, wrong harness name, or crash.
    raise HarnessError(
        f"{crate}::{harness}: kani produced no VERIFICATION verdict "
        f"(compile error / unknown harness?). tail: …{tail[-400:]}"
    )


def apply_and_test(mut: dict) -> tuple[bool, str]:
    """Apply one mutation, run its harness, evaluate vs `expect`, ALWAYS revert.
    Returns (matched_expectation, detail). Raises HarnessError on a
    didn't-apply / failed-revert / no-verdict condition (exit 2)."""
    global _ACTIVE
    path = REPO_ROOT / mut["file"]
    if not path.exists():
        raise HarnessError(f"{mut['id']}: target file {path} does not exist")
    orig = path.read_text(encoding="utf-8")
    find, replace = mut["find"], mut["replace"]

    # --- materiality guards (anti-vacuity in the catcher itself) ---
    n = orig.count(find)
    if n == 0:
        raise HarnessError(
            f"{mut['id']}: find-string ABSENT in {mut['file']} — mutation did not "
            f"apply (file drifted?). Reconcile scripts/kani_mutations.json."
        )
    if n != 1:
        raise HarnessError(
            f"{mut['id']}: find-string occurs {n}x in {mut['file']} (not unique) — "
            f"ambiguous mutation. Tighten the find-string."
        )
    if replace == find:
        raise HarnessError(f"{mut['id']}: replace == find (no-op mutation).")
    mutated = orig.replace(find, replace)
    if mutated == orig:
        raise HarnessError(f"{mut['id']}: applying the mutation changed nothing.")

    try:
        _ACTIVE = (path, orig)
        path.write_text(mutated, encoding="utf-8")
        if path.read_text(encoding="utf-8") == orig:
            raise HarnessError(f"{mut['id']}: write did not take effect.")

        outcome, tail = run_kani(mut["crate"], mut["harness"], mut.get("z_flags", []))
        matched = outcome == mut["expect"]
        detail = f"outcome={outcome} expect={mut['expect']}"
        if not matched:
            detail += f" [tail: …{tail[-300:]}]"
        return matched, detail
    finally:
        path.write_text(orig, encoding="utf-8")
        if path.read_text(encoding="utf-8") != orig:
            _ACTIVE = (path, orig)
            raise HarnessError(f"{mut['id']}: REVERT FAILED for {path} — run `git checkout -- {path}`")
        _ACTIVE = None


def main() -> int:
    args = sys.argv[1:]
    tier = os.environ.get("MUTATIONS", "default")
    if "--tier" in args:
        tier = args[args.index("--tier") + 1]
    if tier not in TIER_ORDER:
        print(f"ERROR: unknown tier {tier!r} (quick|default|full)", file=sys.stderr)
        return 2

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    muts = manifest["mutations"]
    sel = [m for m in muts if TIER_ORDER[m.get("tier", "default")] <= TIER_ORDER[tier]]
    # Canary is ALWAYS included regardless of tier.
    if not any(m["id"] == "canary" for m in sel):
        sel = [m for m in muts if m["id"] == "canary"] + sel

    if "--list" in args:
        for m in sel:
            print(f"  [{m.get('tier','default'):7s}] {m['id']:28s} "
                  f"{m['crate']}::{m['harness']}  ({m['file']})")
        return 0

    print(f"=== verify-kani-mutation (tier={tier}, {len(sel)} mutations) ===")
    print("    Kani-side anti-vacuity: break a decoder/gate, expect a harness to turn red.")
    print("    Each mutation recompiles the crate + runs one harness (~1-4 min), then reverts.\n")

    # Verify tooling up front (fail fast with a clear message, not mid-run).
    try:
        subprocess.run(["cargo", "kani", "--version"], cwd=str(REPO_ROOT),
                       capture_output=True, timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("ERROR: `cargo kani` not runnable "
              "(install: cargo install --locked kani-verifier && cargo kani setup).",
              file=sys.stderr)
        return 2

    results = []
    canary_ok = None
    for m in sel:
        t0 = time.time()
        print(f"--> {m['id']:28s} {m['crate']}::{m['harness']}  expect={m['expect']}")
        try:
            matched, detail = apply_and_test(m)
        except HarnessError as e:
            print(f"    HARNESS ERROR: {e}", file=sys.stderr)
            return 2
        dt = time.time() - t0
        mark = "ok  " if matched else "SURV"
        print(f"    [{mark}] {detail}  ({dt:.0f}s)")
        results.append((m, matched, detail))
        if m["id"] == "canary":
            canary_ok = matched

    if canary_ok is False:
        print("\n=== HARNESS BROKEN: the canary mutation was NOT caught. The mutation "
              "harness cannot detect a fault — ALL results are void. ===", file=sys.stderr)
        return 2

    survivors = [(m, d) for (m, ok, d) in results if not ok]
    print()
    if survivors:
        print(f"FAIL: {len(survivors)} mutation(s) SURVIVED (the harness did not catch the break):",
              file=sys.stderr)
        for m, d in survivors:
            print(f"  - {m['id']} ({m['crate']}::{m['harness']}): {d}", file=sys.stderr)
            print(f"      note: {m.get('note','')}", file=sys.stderr)
        print("\nA survived mutation = the Kani harness is VACUOUS / under-constrained for that "
              "behaviour (it would pass even with the decoder broken). Strengthen the harness "
              "(add the missing assertion) or reconcile the manifest.", file=sys.stderr)
        return 1
    print(f"OK: all {len(results)} mutations were caught — every load-bearing break turns a "
          f"Kani harness red (no vacuous proofs in the covered set).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
