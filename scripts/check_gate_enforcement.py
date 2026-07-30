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
    push/pull_request trigger, the invoking job/step is NOT `continue-on-error`, and the
    trigger `paths:` COVER every `polices_paths` entry (or there is no paths filter).
    A polices path NOT covered by an allowlist `paths:` filter — OR one EXCLUDED by a
    `paths-ignore:` filter — = the F1 class = FAIL.
    A gate with `required_run` must additionally match that complete step `run:` block
    byte-for-byte; merely retaining the target text cannot downgrade a load-bearing
    launcher to a diagnostic direct invocation.
  * nightly — the `runs_in` workflow invokes it AND has a `schedule` trigger.
  * local_documented — deliberately not CI-gated; a NOTE, never a FAIL (must carry a
    `why`). Surfaced so the non-enforcement is VISIBLE, not silent.

Robustness (mirrors the sibling gates): a gate whose target no workflow invokes is a
HARD FAIL (unwired); the invocation check inspects STEP-level `if:`/`continue-on-error`
(not just job-level), so a workflow_dispatch-gated or non-blocking STEP is caught; a
final COMPLETENESS pass asserts that every soundness `make verify-*` target invoked by
any workflow is enrolled in this manifest (so a CI-wired gate cannot silently escape
the manifest — the G1META-1 class). Reverse checks derive the full `make kani`
crate surface and every source file in `kani_mutations.json`, so their declared
path inventories cannot silently lag the executable gates. Ships `--self-test`
negative controls for each reverse check. Read-only — never mutates.
KNOWN OUT-OF-SCOPE evasions (fail-closed / documented, not modelled): a gate invoked via
`uses:` a reusable workflow (no inline `run` text) reads as UNWIRED (a false FAIL, safe
direction); matrix-`exclude` on the invoking job is not modelled.

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
KANI_MUTATIONS = Path(__file__).resolve().parent / "kani_mutations.json"
EXTRACTION_REGISTRY = (
    REPO_ROOT / "contracts" / "verification" / "extraction_registry.json"
)


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
        # ancestor or equal (fp=="" means a bare '**' catch-all)
        if fp == "" or p == fp or p.startswith(fp + "/"):
            return True
    return False


def _ignored(paths_ignore: list[str], policed: str) -> bool:
    """Does a `paths-ignore:` filter EXCLUDE the policed surface? A push/PR that
    edits ONLY files under the policed prefix is skipped when a directory-prefix
    ignore glob is the policed path or an ancestor of it — the gate then never fires
    on that surface (the F1 class, via denylist). Extension-only ignore globs
    (`**/*.md`) do not normalise to a directory ancestor, so they don't false-flag a
    directory-policed path — reused from `_covers`'s ancestor logic."""
    return _covers(paths_ignore, policed)


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


def _dispatch_only(cond: str) -> bool:
    """An `if:` that pins execution to workflow_dispatch (never push/PR/schedule)."""
    return "workflow_dispatch" in cond and "schedule" not in cond


def invokes_target(
    wf: dict, target: str, required_run: str | None = None
) -> tuple[bool, bool, bool]:
    """Scan every job's steps for a `make [-C dir] <target>` invocation. If
    `required_run` is supplied, only an exact complete run-block match counts. Returns
    (invoked, non_blocking, dispatch_only) where the two flags OR together the JOB-
    level and the matching STEP-level `continue-on-error` / `if:` (a non-blocking or
    workflow_dispatch-gated STEP defeats a per-PR gate just as a job-level one does)."""
    pat = re.compile(r"\bmake\b[^\n]*\b" + re.escape(target) + r"\b")
    for job in (wf.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        job_coe = bool(job.get("continue-on-error"))
        job_dispatch_only = _dispatch_only(str(job.get("if", "")))
        for s in job.get("steps") or []:
            if not isinstance(s, dict):
                continue
            run = str(s.get("run", ""))
            if pat.search(run) and (required_run is None or run == required_run):
                coe = job_coe or bool(s.get("continue-on-error"))
                dispatch_only = job_dispatch_only or _dispatch_only(str(s.get("if", "")))
                return True, coe, dispatch_only
    return False, False, False


def triggers(wf: dict) -> dict:
    """Per-trigger shape. push/pull_request map to None (trigger absent) or a dict
    {"paths": <allowlist|None>, "paths_ignore": <denylist|None>}; a present trigger
    with neither filter has both None (= covers everything)."""
    on = _get_on(wf)
    out = {"push": None, "pull_request": None, "schedule": False, "workflow_dispatch": False}
    if isinstance(on, list):
        for k in on:
            if k in ("push", "pull_request"):
                out[k] = {"paths": None, "paths_ignore": None}
            elif k in ("schedule", "workflow_dispatch"):
                out[k] = True
        return out
    for k in ("push", "pull_request"):
        if k in on:
            node = on[k] if isinstance(on[k], dict) else {}
            out[k] = {"paths": node.get("paths"), "paths_ignore": node.get("paths-ignore")}
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

    required_run = g.get("required_run")
    if required_run is not None and (
        not isinstance(required_run, str) or not required_run
    ):
        fails.append(f"{target}: `required_run` must be a non-empty string.")
        return fails

    invoked, coe, dispatch_only = invokes_target(wf, target, required_run)
    if not invoked:
        if required_run is not None and invokes_target(wf, target)[0]:
            fails.append(
                f"{target}: {runs_in} retains the target text but its complete `run:` "
                "block does not exactly match `required_run` — the authoritative "
                "launcher boundary was changed or removed."
            )
            return fails
        # maybe another workflow invokes it — scan all, then report the mismatch
        other = [p.name for p in (REPO_ROOT / ".github/workflows").glob("*.yml")
                 if invokes_target(load_workflow(p) or {}, target)[0]]
        where = f" (found in {other} instead)" if other else " (found in NO workflow — UNWIRED)"
        fails.append(f"{target}: not invoked by its declared runs_in={runs_in}{where}.")
        return fails

    tg = triggers(wf)
    has_ignore_filter = False
    if enforcement == "per_pr_blocking":
        if tg["push"] is None and tg["pull_request"] is None:
            fails.append(f"{target}: per_pr_blocking but {runs_in} has no push/pull_request trigger.")
        if coe:
            fails.append(f"{target}: per_pr_blocking but its job/step is `continue-on-error: true` (non-blocking).")
        if dispatch_only:
            fails.append(f"{target}: per_pr_blocking but its job/step is workflow_dispatch-gated (never fires on PRs).")
        # F1 check: an allowlist `paths:` must COVER every policed path, and a
        # `paths-ignore:` denylist must NOT EXCLUDE any policed path.
        for trig in ("push", "pull_request"):
            node = tg[trig]
            if node is None:
                continue  # this trigger absent
            allow, deny = node["paths"], node["paths_ignore"]
            for policed in g.get("polices_paths", []):
                if allow is not None and not _covers(allow, policed):
                    fails.append(f"{target}: {runs_in} `{trig}.paths` does NOT cover policed `{policed}` "
                                 f"(the F1 class — gate can't fire on edits to that surface).")
                if deny and _ignored(deny, policed):
                    has_ignore_filter = True
                    fails.append(f"{target}: {runs_in} `{trig}.paths-ignore` EXCLUDES policed `{policed}` "
                                 f"(the F1 class — a push touching only that surface is skipped).")
            if deny:
                has_ignore_filter = True
    elif enforcement == "nightly":
        if not tg["schedule"]:
            fails.append(f"{target}: enforcement=nightly but {runs_in} has no `schedule` trigger.")

    if not fails:
        def _present_no_filter(t):
            return isinstance(tg[t], dict) and tg[t]["paths"] is None and tg[t]["paths_ignore"] is None
        if any(_present_no_filter(t) for t in ("push", "pull_request")):
            cov = "no-path-filter"
        elif has_ignore_filter:
            cov = "paths-ignore filter (policed surface not excluded)"
        else:
            cov = "paths cover policed surface"
        lvl = "per-PR blocking" if enforcement == "per_pr_blocking" else "nightly"
        print(f"    [ok]   {target:26s} {lvl}, {cov}")
    return fails


SOUNDNESS_TARGET = re.compile(r"\bmake\b[^\n]*?\b(verify-[a-z0-9-]+|kani|miri)\b")


def invoked_soundness_targets() -> dict:
    """target -> set(workflow filenames) for every soundness `make` target actually
    invoked in a `run:` step (comments/`env` outside run blocks are NOT matched)."""
    found: dict = {}
    for p in sorted((REPO_ROOT / ".github/workflows").glob("*.yml")):
        wf = load_workflow(p) or {}
        for job in (wf.get("jobs") or {}).values():
            if not isinstance(job, dict):
                continue
            for s in job.get("steps") or []:
                if not isinstance(s, dict):
                    continue
                for m in SOUNDNESS_TARGET.finditer(str(s.get("run", ""))):
                    found.setdefault(m.group(1), set()).add(p.name)
    return found


def completeness(manifest: dict) -> list[str]:
    """G1META-1: every soundness `make verify-*`/`kani`/`miri` target a workflow
    actually runs must be a manifest gate id (or explicitly `_completeness_waived`
    with a reason) — else a CI-wired gate silently escapes the manifest, exactly the
    self-limiting-manifest gap the 2026-07-02 round found."""
    fails = []
    ids = {g["id"] for g in manifest["gates"]}
    waived = manifest.get("_completeness_waived", {})  # {target: reason}
    for target, wfs in sorted(invoked_soundness_targets().items()):
        if target in ids or target in waived:
            continue
        fails.append(f"COMPLETENESS: `{target}` is invoked in {sorted(wfs)} but is NOT a manifest gate "
                     f"(nor in _completeness_waived) — a CI-wired soundness gate escaping the manifest (G1META-1).")
    return fails


def _workspace_crate_dirs() -> dict:
    """package-name -> repo-relative source dir (parsed from each crate's Cargo.toml)."""
    out: dict = {}
    for cargo in REPO_ROOT.glob("*/Cargo.toml"):
        try:
            m = re.search(r'^\s*name\s*=\s*"([^"]+)"', cargo.read_text(encoding="utf-8"), re.M)
        except OSError:
            continue
        if m:
            out[m.group(1)] = cargo.parent.name
    return out


def _makefile_kani_crates() -> list[str]:
    """Crates `make kani` runs `cargo kani -p` on, parsed from the `kani:` target block."""
    try:
        lines = (REPO_ROOT / "Makefile").read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    crates, in_kani = [], False
    for ln in lines:
        if re.match(r"^kani:", ln):
            in_kani = True
            continue
        if in_kani and re.match(r"^[A-Za-z0-9_.-]+:", ln):  # next top-level target
            break
        if in_kani:
            m = re.search(r"cargo kani -p (\S+)", ln)
            if m:
                crates.append(m.group(1))
    return crates


def kani_makefile_coverage(policed: list[str], kani_crates: list[str], crate_dirs: dict) -> list[str]:
    """REVERSE-CHECK (finding §2 #6): every crate `make kani` actually runs
    `cargo kani -p` on must have its `<dir>/src/` covered by the kani gate's
    `polices_paths`. The forward `check_gate` only asserts the trigger `paths:` cover
    the DECLARED polices_paths; nothing asserts the declared surface matches what the
    target RUNS — so a new `cargo kani -p <crate>` added to the Makefile without
    updating polices_paths would silently escape a (future per-PR) kani path filter.
    This is exactly the domain/src + tx-core/src omission the 2026-07-01 kani review
    found (gate-enforcement-kani-polices-omits-domain-txcore)."""
    fails = []
    norm = [_norm_prefix(p) for p in policed]
    for c in sorted(set(kani_crates)):
        d = crate_dirs.get(c)
        if d is None:
            fails.append(f"kani-reverse: Makefile `cargo kani -p {c}` maps to no workspace crate dir.")
            continue
        want = f"{d}/src/"
        if not any(want.startswith(n) for n in norm):
            fails.append(f"kani-reverse: `make kani` runs `cargo kani -p {c}` but `{d}/src/**` is NOT covered "
                         f"by the kani gate's polices_paths (a future per-PR kani would drop that crate's "
                         f"harnesses — finding §2 #6).")
    return fails


def kani_mutation_manifest_coverage(policed: list[str], mutation_files: list[str]) -> list[str]:
    """Reverse-check every source file named by the Kani mutation manifest.

    The gate manifest's forward workflow check cannot prove that its declared
    `polices_paths` still covers a growing mutation manifest. Deriving this
    inventory closes the same false-green class for verify-kani-mutation.
    """
    fails = []
    required = set(mutation_files)
    required.add("scripts/kani_mutations.json")
    for source in sorted(required):
        if not _covers(policed, source):
            fails.append(
                "kani-mutation-reverse: scripts/kani_mutations.json mutates "
                f"`{source}` but verify-kani-mutation polices_paths does not cover it"
            )
    return fails


def _kani_mutation_files() -> list[str]:
    try:
        manifest = json.loads(KANI_MUTATIONS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise SystemExit(f"HARNESS ERROR: cannot read {KANI_MUTATIONS}: {e}")
    mutations = manifest.get("mutations")
    if not isinstance(mutations, list) or any(
        not isinstance(m, dict) or not isinstance(m.get("file"), str)
        for m in mutations
    ):
        raise SystemExit("HARNESS ERROR: kani_mutations.json needs a mutations[] file string per entry")
    return [m["file"] for m in mutations]


def extraction_freshness_coverage(
    policed: list[str], rust_files: list[str]
) -> list[str]:
    """Reverse-check the registry-derived extraction source/control surface.

    `check_gate` proves workflow paths cover declared `polices_paths`; this
    proves the declaration itself covers every live registry source plus the
    files that define/update the fail-closed gate.
    """
    required = set(rust_files)
    required.update(
        {
            "contracts/verification/extraction_registry.json",
            "contracts/verification/Makefile",
            "contracts/verification/scripts/check_extraction_freshness.py",
            "contracts/verification/scripts/check_extraction_regen_output.py",
        }
    )
    return [
        "extraction-freshness-reverse: registry/control path "
        f"`{path}` is not covered by verify-extraction-freshness polices_paths"
        for path in sorted(required)
        if not _covers(policed, path)
    ]


def _extraction_rust_files() -> list[str]:
    try:
        registry = json.loads(EXTRACTION_REGISTRY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise SystemExit(f"HARNESS ERROR: cannot read {EXTRACTION_REGISTRY}: {e}")
    entries = registry.get("entries")
    if not isinstance(entries, list):
        raise SystemExit("HARNESS ERROR: extraction registry needs entries[]")
    rust_files: list[str] = []
    for entry in entries:
        files = entry.get("rust_files") if isinstance(entry, dict) else None
        if not isinstance(files, list) or any(not isinstance(f, str) for f in files):
            raise SystemExit(
                "HARNESS ERROR: extraction registry entries need rust_files[] strings"
            )
        rust_files.extend(files)
    return rust_files


def main() -> int:
    self_test = "--self-test" in sys.argv[1:]
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"HARNESS ERROR: cannot read {MANIFEST}: {e}", file=sys.stderr)
        return 2
    gates = manifest["gates"]

    if self_test:
        # Negative controls; every one MUST be caught or the harness is void.
        print("=== --self-test (negative controls) ===")
        broken_allow = {"id": "verify-ledger-consistency", "make": "x", "enforcement": "per_pr_blocking",
                        "runs_in": "lean-fv.yml", "polices_paths": ["totally/unpoliced/surface/**"]}
        fa = check_gate(broken_allow)
        if not fa:
            print("  SELF-TEST FAILED: uncovered-allowlist gate NOT caught — harness void.", file=sys.stderr)
            return 2
        ledger_gate = next(
            (g for g in gates if g["id"] == "verify-ledger-consistency"), None
        )
        if ledger_gate is None or not isinstance(ledger_gate.get("required_run"), str):
            print(
                "  SELF-TEST FAILED: verify-ledger-consistency has no exact "
                "`required_run` contract.",
                file=sys.stderr,
            )
            return 2
        live_ledger_wf = load_workflow(
            REPO_ROOT / ".github" / "workflows" / ledger_gate["runs_in"]
        )
        if live_ledger_wf is None or not invokes_target(
            live_ledger_wf,
            ledger_gate["id"],
            ledger_gate["required_run"],
        )[0]:
            print(
                "  SELF-TEST FAILED: the live authoritative ledger invocation does "
                "not match its exact `required_run` contract.",
                file=sys.stderr,
            )
            return 2
        prefix_deleted = {
            "jobs": {
                "ledger": {
                    "steps": [{"run": ledger_gate["make"] + "\n"}],
                }
            }
        }
        if not invokes_target(prefix_deleted, ledger_gate["id"])[0] or invokes_target(
            prefix_deleted,
            ledger_gate["id"],
            ledger_gate["required_run"],
        )[0]:
            print(
                "  SELF-TEST FAILED: deleting the authoritative launcher prefix was "
                "not distinguished from a valid ledger invocation.",
                file=sys.stderr,
            )
            return 2
        # The paths-ignore (denylist F1) branch is tested DIRECTLY against `_ignored`
        # rather than through a real workflow's `paths-ignore:` filter. CI trigger
        # configs are refactored over time — ci.yml intentionally DROPPED all
        # paths-ignore filters (2026-07), which silently voided the old
        # workflow-coupled control here. A self-test that stops exercising a branch
        # when an unrelated workflow changes is itself the vacuity this gate exists
        # to prevent (incidental fix during the 2026-07-15 FV review sweep).
        if not _ignored(["contracts/verification/**"], "contracts/verification/lean/Foo.lean"):
            print("  SELF-TEST FAILED: a directory-prefix paths-ignore glob did NOT exclude a policed "
                  "sub-path — the denylist F1 check is void.", file=sys.stderr)
            return 2
        if _ignored(["docs/**"], "contracts/verification/lean/Foo.lean"):
            print("  SELF-TEST FAILED: an unrelated paths-ignore glob WRONGLY excluded a policed path "
                  "(_ignored over-fires).", file=sys.stderr)
            return 2
        # 3rd control: an uncovered crate `make kani` runs must be caught by the reverse-check.
        rc = kani_makefile_coverage(["tx/src/**"], ["pqsigner-domain"], {"pqsigner-domain": "domain"})
        if not rc:
            print("  SELF-TEST FAILED: uncovered kani-Makefile crate NOT caught — harness void.", file=sys.stderr)
            return 2
        rm = kani_mutation_manifest_coverage(
            ["tx/src/multisend.rs"],
            ["tx/src/multisend.rs", "aa/src/userop.rs"],
        )
        if not rm:
            print("  SELF-TEST FAILED: uncovered Kani mutation file NOT caught — harness void.",
                  file=sys.stderr)
            return 2
        rext = extraction_freshness_coverage(
            [
                "domain/src/**",
                "contracts/verification/extraction_registry.json",
                "contracts/verification/Makefile",
                "contracts/verification/scripts/check_extraction_freshness.py",
                "contracts/verification/scripts/check_extraction_regen_output.py",
            ],
            ["domain/src/lib.rs", "proto/src/lib.rs"],
        )
        if not rext:
            print(
                "  SELF-TEST FAILED: uncovered extraction-registry source NOT caught "
                "— harness void.",
                file=sys.stderr,
            )
            return 2
        print(f"  self-test OK: allowlist gap caught ({len(fa)}), exact authoritative "
              "ledger invocation/prefix-deletion control verified, "
              "paths-ignore denylist logic verified "
              f"(directly), kani-reverse gap caught ({len(rc)}), "
              f"kani-mutation-reverse gap caught ({len(rm)}), "
              f"extraction-reverse gap caught ({len(rext)}).")
        return 0

    print(f"=== verify-gate-enforcement ({len(gates)} gates) ===")
    print("    G1: does each soundness gate actually RUN on the diff it polices?\n")
    all_fails = []
    for g in gates:
        all_fails += check_gate(g)
    all_fails += completeness(manifest)
    kani_gate = next((g for g in gates if g["id"] == "kani"), None)
    if kani_gate:
        all_fails += kani_makefile_coverage(kani_gate.get("polices_paths", []),
                                            _makefile_kani_crates(), _workspace_crate_dirs())
    kani_mutation_gate = next(
        (g for g in gates if g["id"] == "verify-kani-mutation"), None
    )
    if kani_mutation_gate:
        all_fails += kani_mutation_manifest_coverage(
            kani_mutation_gate.get("polices_paths", []),
            _kani_mutation_files(),
        )
    extraction_gate = next(
        (g for g in gates if g["id"] == "verify-extraction-freshness"), None
    )
    if extraction_gate:
        all_fails += extraction_freshness_coverage(
            extraction_gate.get("polices_paths", []),
            _extraction_rust_files(),
        )

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
