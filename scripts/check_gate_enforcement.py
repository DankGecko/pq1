#!/usr/bin/env python3
"""verify-gate-enforcement — closes catalog class G1 (gate-enforcement vacuity)
from docs/verification/fv-adversarial-review-playbook.md Part A2.

The other anti-vacuity gates (verify-proof-mutation, verify-ledger-consistency,
verify-kani-mutation, verify-protocol-models) each ask "is a PROOF hollow?" This
one asks the level-up question the 2026-07-01 adversarial round found the tree
was blind to: **does the gate that polices hollowness actually RUN on the diff it
polices?** A gate that is green-when-run but never fires — wrong `paths:` filter,
`continue-on-error`, `workflow_dispatch`-only, or simply not invoked by any job —
is exactly as dangerous as a hollow proof (F1: `verify-ledger-consistency` never
ran on `AXIOM_STATUS.json`-only edits until an adversarial pass found it by hand).

For each gate in scripts/gate_enforcement.json it parses the live CI workflows and
asserts the wiring matches the declared enforcement:
  * per_pr_blocking — the declared `runs_in` workflow invokes `make <target>`, has a
    push/pull_request trigger, the invoking job is NOT `continue-on-error`, and the
    trigger `paths:` COVER every `polices_paths` entry (or there is no paths filter).
    A polices path NOT covered by the filter = the F1 class = FAIL.
  * nightly — the `runs_in` workflow invokes it AND has a `schedule` trigger.
  * local_documented — deliberately not CI-gated; a NOTE, never a FAIL (must carry a
    `why`). Surfaced so the non-enforcement is VISIBLE, not silent.

Robustness (mirrors the sibling gates): a gate whose target no workflow invokes is a
HARD FAIL (unwired); ships a `--self-test` negative control (inject a broken
expectation, expect RED). Read-only — never mutates.

Exit: 0 = every gate enforced as declared; 1 = an enforcement gap (unwired /
path-uncovered / non-blocking); 2 = harness/manifest error (missing file, YAML parse).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required (pip install pyyaml).", file=sys.stderr)
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = Path(__file__).resolve().parent / "gate_enforcement.json"


def _norm_prefix(glob: str) -> str:
    """A path glob -> its literal directory prefix (strip trailing /**, /*, *)."""
    g = glob.rstrip("/")
    for suf in ("/**", "/*"):
        if g.endswith(suf):
            g = g[: -len(suf)]
    return g.rstrip("/*").rstrip("/")


def _covers(filter_globs: list[str], policed: str) -> bool:
    """Does the workflow's `paths:` filter cover the policed path? True if some
    filter glob is `policed` or an ancestor of it (prefix match on directories)."""
    p = _norm_prefix(policed)
    for f in filter_globs:
        fp = _norm_prefix(f)
        if fp == "" or p == fp or p.startswith(fp + "/") or p.startswith(fp):
            # ancestor or equal (fp=="" means a bare '**' catch-all)
            if fp == "" or p == fp or p.startswith(fp + "/"):
                return True
    return False


def _get_on(wf: dict) -> dict:
    """`on:` — PyYAML (YAML 1.1) parses the bare key `on` as boolean True."""
    return wf.get("on") or wf.get(True) or {}


def load_workflow(wf_path: Path) -> dict | None:
    if not wf_path.exists():
        return None
    try:
        return yaml.safe_load(wf_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise SystemExit(f"HARNESS ERROR: {wf_path} is not valid YAML: {e}")


def invokes_target(wf: dict, target: str) -> tuple[bool, bool, bool]:
    """Scan every job's steps for a `make [-C dir] <target>` invocation. Returns
    (invoked, in_continue_on_error_job, job_is_event_gated)."""
    pat = re.compile(r"\bmake\b[^\n]*\b" + re.escape(target) + r"\b")
    for job in (wf.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        run_text = "\n".join(str(s.get("run", "")) for s in steps if isinstance(s, dict))
        if pat.search(run_text):
            coe = bool(job.get("continue-on-error"))
            # a job gated to only run on workflow_dispatch (never push/PR/schedule)
            job_if = str(job.get("if", ""))
            dispatch_only = "workflow_dispatch" in job_if and "schedule" not in job_if
            return True, coe, dispatch_only
    return False, False, False


def triggers(wf: dict) -> dict:
    on = _get_on(wf)
    out = {"push": None, "pull_request": None, "schedule": False, "workflow_dispatch": False}
    if isinstance(on, list):
        for k in on:
            if k in out:
                out[k] = True
        return out
    for k in ("push", "pull_request"):
        if k in on:
            node = on[k] or {}
            out[k] = (node.get("paths") if isinstance(node, dict) else None) or []  # [] = trigger, no path filter
    out["schedule"] = "schedule" in on
    out["workflow_dispatch"] = "workflow_dispatch" in on
    return out


def check_gate(g: dict) -> list[str]:
    fails = []
    target = g["id"]
    enforcement = g["enforcement"]
    runs_in = g.get("runs_in")
    wf_path = REPO_ROOT / ".github" / "workflows" / runs_in if runs_in else None
    wf = load_workflow(wf_path) if wf_path else None

    if enforcement == "local_documented":
        if not g.get("why"):
            fails.append(f"{target}: enforcement=local_documented but no `why` — undisclosed non-gate.")
        print(f"    [note] {target:26s} local-only (not CI-gated): {g.get('why','')[:80]}")
        return fails

    if wf is None:
        fails.append(f"{target}: declared runs_in={runs_in} but that workflow file is absent.")
        return fails

    invoked, coe, dispatch_only = invokes_target(wf, target)
    if not invoked:
        # maybe another workflow invokes it — scan all, then report the mismatch
        other = [p.name for p in (REPO_ROOT / ".github/workflows").glob("*.yml")
                 if invokes_target(load_workflow(p) or {}, target)[0]]
        where = f" (found in {other} instead)" if other else " (found in NO workflow — UNWIRED)"
        fails.append(f"{target}: not invoked by its declared runs_in={runs_in}{where}.")
        return fails

    tg = triggers(wf)
    if enforcement == "per_pr_blocking":
        if tg["push"] is None and tg["pull_request"] is None:
            fails.append(f"{target}: per_pr_blocking but {runs_in} has no push/pull_request trigger.")
        if coe:
            fails.append(f"{target}: per_pr_blocking but its job is `continue-on-error: true` (non-blocking).")
        if dispatch_only:
            fails.append(f"{target}: per_pr_blocking but its job is workflow_dispatch-gated (never fires on PRs).")
        # F1 check: the trigger paths must COVER every policed path
        for trig in ("push", "pull_request"):
            filt = tg[trig]
            if filt is None:
                continue  # this trigger absent
            if filt == []:
                continue  # trigger present with NO paths filter => covers everything
            for policed in g.get("polices_paths", []):
                if not _covers(filt, policed):
                    fails.append(f"{target}: {runs_in} `{trig}.paths` does NOT cover policed `{policed}` "
                                 f"(the F1 class — gate can't fire on edits to that surface).")
    elif enforcement == "nightly":
        if not tg["schedule"]:
            fails.append(f"{target}: enforcement=nightly but {runs_in} has no `schedule` trigger.")

    if not fails:
        cov = "no-path-filter" if any(tg[t] == [] for t in ("push", "pull_request")) else "paths cover policed surface"
        lvl = "per-PR blocking" if enforcement == "per_pr_blocking" else "nightly"
        print(f"    [ok]   {target:26s} {lvl}, {cov}")
    return fails


def main() -> int:
    self_test = "--self-test" in sys.argv[1:]
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"HARNESS ERROR: cannot read {MANIFEST}: {e}", file=sys.stderr)
        return 2
    gates = manifest["gates"]

    if self_test:
        # Negative control: a gate that claims per_pr_blocking but polices a path no
        # real workflow filter covers MUST be caught. If it is not, the harness is void.
        print("=== --self-test (negative control) ===")
        broken = {"id": "verify-ledger-consistency", "make": "x", "enforcement": "per_pr_blocking",
                  "runs_in": "lean-fv.yml", "polices_paths": ["totally/unpoliced/surface/**"]}
        f = check_gate(broken)
        if not f:
            print("  SELF-TEST FAILED: the broken gate (polices an uncovered path) was NOT caught — "
                  "harness is void.", file=sys.stderr)
            return 2
        print(f"  self-test OK: broken gate caught ({len(f)} violation(s)).")
        return 0

    print(f"=== verify-gate-enforcement ({len(gates)} gates) ===")
    print("    G1: does each soundness gate actually RUN on the diff it polices?\n")
    all_fails = []
    for g in gates:
        all_fails += check_gate(g)

    print()
    if all_fails:
        print(f"FAIL: {len(all_fails)} gate-enforcement gap(s) — a gate that is green-when-run but does "
              f"not fire on its policed surface:", file=sys.stderr)
        for m in all_fails:
            print(f"  - {m}", file=sys.stderr)
        print("\nThis is catalog class G1 (false assurance). Wire the gate / widen its `paths:` / make it "
              "blocking, or (if intentionally local) set enforcement=local_documented with a `why`.", file=sys.stderr)
        return 1
    print(f"OK: all {len(gates)} gates fire on the surface they police (or are documented local-only).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
