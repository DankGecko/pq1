#!/usr/bin/env python3
"""verify-proof-mutation — the proof-side analogue of cargo-mutants, defending
failure-class V4 ("dead conjunct / vacuous lemma") from the FV adversarial-review
playbook. It answers the gut-check mechanically:

    "If I deleted this axiom / weakened this lemma — would something turn red?"

For each entry in lean/scripts/proof_mutations.json it mutates the Lean source
in a way whose outcome is KNOWN (delete-by-rename a load-bearing axiom -> expect
BUILD FAIL; comment out a non-consumed marker -> expect BUILD PASS + an exact
closure drop; rename a zero-consumer axiom -> expect BUILD PASS), rebuilds the
whole library, and asserts the result matches `expect`. A green-when-it-should-
be-red is a vacuity, reported as a failure. Most mutations EXECUTE a specific
falsifiability claim AXIOM_STATUS.json makes only in prose.

ROBUSTNESS (non-negotiable, per the playbook):
  * Every mutation must MATERIALLY change the file (find present, EXACTLY once,
    replace != find). A mutation that fails to apply is a HARD FAIL of the
    manifest (exit 2), NEVER a silent skip — otherwise the catcher reproduces
    the exact vacuity it exists to catch.
  * A permanent CANARY mutation (a guaranteed build-break in theft_free) must
    trip. If it does not, the harness is broken and ALL results are void.
  * The mutated file is ALWAYS reverted (finally + atexit + SIGINT/SIGTERM),
    and the revert is VERIFIED (re-read == original); a failed revert is a hard
    error with a `git checkout` recovery hint.
  * The full library is rebuilt (lake build SphincsCVerify rebuilds the changed
    module + all reverse-dependencies; mathlib stays cached) so a `build_fails`
    mutation can't pass spuriously on a stale incremental artifact.

SCOPE: closes V4 + the load-bearingness claims. Does NOT close V7 (a latent-FALSE
axiom still type-checks -> invisible to mutation while lean/ is mathlib-free) or
V11 (wrong spec). See docs/verification/fv-adversarial-review-playbook.md §A.

Usage:
    check_proof_mutations.py [--tier quick|default|full] [--list]
Environment: MUTATIONS=quick|default|full overrides the tier (default: default).

Exit: 0 = every mutation behaved as expected; 1 = a vacuity/broken-claim found;
      2 = harness/manifest error (mutation didn't apply, canary didn't trip,
          revert failed, build tooling missing).
"""
from __future__ import annotations

import atexit
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
VERIF_DIR = SCRIPT_DIR.parent
LEAN_DIR = VERIF_DIR / "lean"
MANIFEST = LEAN_DIR / "scripts" / "proof_mutations.json"
DUMP_SCRIPT = "scripts/dump_axioms.lean"
KERNEL = {"propext", "Classical.choice", "Quot.sound"}

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


def parse_dump(text: str) -> dict[str, set[str]]:
    flat = re.sub(r"\s+", " ", text)
    out: dict[str, set[str]] = {}
    for m in re.finditer(r"'([^']+)' depends on axioms: \[([^\]]*)\]", flat):
        out[m.group(1)] = {a.strip() for a in m.group(2).split(",") if a.strip()}
    for m in re.finditer(r"'([^']+)' does not depend on any axioms", flat):
        out.setdefault(m.group(1), set())
    return out


def run_build() -> tuple[bool, str]:
    """lake build SphincsCVerify — full transitive rebuild. (ok, tail-output)."""
    cp = subprocess.run(["lake", "build", "SphincsCVerify"], cwd=str(LEAN_DIR),
                        capture_output=True, text=True, timeout=1800)
    out = (cp.stdout + cp.stderr)
    return cp.returncode == 0, out[-1500:]


def run_dump() -> dict[str, set[str]]:
    cp = subprocess.run(["lake", "env", "lean", DUMP_SCRIPT], cwd=str(LEAN_DIR),
                        capture_output=True, text=True, timeout=900)
    return parse_dump(cp.stdout + cp.stderr)


class HarnessError(Exception):
    pass


def apply_and_test(mut: dict) -> tuple[bool, str]:
    """Apply one mutation, rebuild, evaluate vs `expect`, ALWAYS revert.
    Returns (matched_expectation, detail). Raises HarnessError on a
    didn't-apply / failed-revert condition (manifest/harness fault, exit 2)."""
    global _ACTIVE
    path = LEAN_DIR / mut["file"]
    if not path.exists():
        raise HarnessError(f"{mut['id']}: target file {path} does not exist")
    orig = path.read_text(encoding="utf-8")
    find, replace = mut["find"], mut["replace"]

    # --- materiality guards (the anti-vacuity-in-the-catcher checks) ---
    n = orig.count(find)
    if n == 0:
        raise HarnessError(f"{mut['id']}: find-string ABSENT in {mut['file']} — "
                           f"mutation did not apply (file drifted?). Reconcile the manifest.")
    if n != 1:
        raise HarnessError(f"{mut['id']}: find-string occurs {n}x in {mut['file']} (not unique) — "
                           f"ambiguous mutation. Tighten the find-string.")
    if replace == find:
        raise HarnessError(f"{mut['id']}: replace == find (no-op mutation).")
    mutated = orig.replace(find, replace)
    if mutated == orig:
        raise HarnessError(f"{mut['id']}: applying the mutation changed nothing.")

    detail = ""
    try:
        _ACTIVE = (path, orig)
        path.write_text(mutated, encoding="utf-8")
        if path.read_text(encoding="utf-8") == orig:
            raise HarnessError(f"{mut['id']}: write did not take effect.")

        build_ok, build_tail = run_build()
        outcome = "build_passes" if build_ok else "build_fails"

        closure_ok = True
        if mut["expect"] == "build_passes" and build_ok and "closure_check" in mut:
            cc = mut["closure_check"]
            live = run_dump()
            got = live.get(cc["theorem"])
            exp = set(cc["expect_axioms"])
            if got is None:
                closure_ok = False
                detail += f" [closure: theorem {cc['theorem']} absent from dump]"
            elif got != exp:
                closure_ok = False
                detail += (f" [closure drift: MISSING {sorted(exp - got)} "
                           f"EXTRA {sorted(got - exp)}]")
            else:
                detail += f" [closure dropped to exactly {len(exp)} as advertised]"

        matched = (outcome == mut["expect"]) and closure_ok
        if not matched and outcome == "build_fails" and mut["expect"] == "build_passes":
            detail += f" [build tail: …{build_tail[-300:].strip()}]"
        detail = f"outcome={outcome} expect={mut['expect']}" + detail
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
            print(f"  [{m.get('tier','default'):7s}] {m['id']:28s} expect={m['expect']:13s} {m['file']}")
        return 0

    print(f"=== verify-proof-mutation (tier={tier}, {len(sel)} mutations) ===")
    print("    proof-side cargo-mutants: delete/weaken a claim, expect the build to react.")
    print("    Each mutation rebuilds the full library (~1-5 min) then reverts.\n")

    # Verify shell tooling up front.
    try:
        subprocess.run(["lake", "--version"], cwd=str(LEAN_DIR), capture_output=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("ERROR: `lake` not runnable (need elan-installed Lean 4).", file=sys.stderr)
        return 2

    results = []
    canary_ok = None
    for m in sel:
        t0 = time.time()
        print(f"--> {m['id']:28s} ({m['file']})  expect={m['expect']}")
        try:
            matched, detail = apply_and_test(m)
        except HarnessError as e:
            print(f"    HARNESS ERROR: {e}", file=sys.stderr)
            return 2
        dt = time.time() - t0
        mark = "ok " if matched else "FAIL"
        print(f"    [{mark}] {detail}  ({dt:.0f}s)")
        results.append((m, matched, detail))
        if m["id"] == "canary":
            canary_ok = matched

    # Canary gate: if the canary did not behave (build_fails), the harness is void.
    if canary_ok is False:
        print("\n=== HARNESS BROKEN: the canary mutation did NOT break the build. "
              "The mutation harness cannot detect a fault — ALL results are void. ===", file=sys.stderr)
        return 2

    failures = [(m, d) for (m, ok, d) in results if not ok]
    print()
    if failures:
        print(f"FAIL: {len(failures)} mutation(s) did not behave as the ledger claims:", file=sys.stderr)
        for m, d in failures:
            print(f"  - {m['id']}: {d}", file=sys.stderr)
            print(f"      ledger claim: {m.get('ledger_claim','')}", file=sys.stderr)
        print("\nA build_fails-expected mutation that PASSED = a dead/vacuous dependency "
              "(V4). A build_passes-expected mutation that FAILED = a 'not load-bearing' "
              "or closure claim in AXIOM_STATUS.json is FALSE. Reconcile.", file=sys.stderr)
        return 1
    print(f"OK: all {len(results)} mutations behaved as advertised "
          f"(load-bearing claims break on deletion; markers/zero-consumers stay green "
          f"with the exact closure drop).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
