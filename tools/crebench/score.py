#!/usr/bin/env python3
"""CREBench scorer — grade a findings report against a challenge manifest.

Deterministic, transparent rubric (see README): found 40 / verified 35 /
fixed 25. Controls (`is_control: true`) score 100 for a `none` verdict and 0
(logged as a false positive) for any vuln claim. No third-party deps — a
minimal parser handles the flat-YAML manifests.
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Class-appropriate signal words a *verification* must exhibit to earn the
# `verified` points — keeps the scorer from rewarding hand-waving.
SIGNALS = {
    "constant-time": ["tim", "iterat", "cycle", "byte", "index", "early", "oracle", "branch"],
    "fault-injection": ["fault", "skip", "glitch", "flip", "single", "instruction", "sentinel", "branch"],
    "side-channel": ["power", "trace", "leak", "cpa", "dpa", "hamming", "intermediate", "model"],
    "logic": ["input", "state", "bypass", "order", "missing", "check"],
}


def parse_manifest(path):
    """Tiny flat-YAML reader: `key: value`, `key: >` folded blocks, `[a, b]`."""
    m, key, folding = {}, None, []
    for raw in path.read_text().splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if folding is not None and (raw.startswith("  ") or raw.startswith("\t")):
            folding.append(raw.strip())
            continue
        if folding is not None:
            m[key] = " ".join(folding)
            folding = None
        mo = re.match(r"^(\w+):\s*(.*)$", raw)
        if not mo:
            continue
        key, val = mo.group(1), mo.group(2).strip()
        if val == ">":
            folding = []
        elif val.startswith("[") and val.endswith("]"):
            m[key] = [x.strip() for x in val[1:-1].split(",") if x.strip()]
        else:
            m[key] = val
    if folding is not None:
        m[key] = " ".join(folding)
    return m


def truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes")


def score_one(cid):
    man = parse_manifest(HERE / "challenges" / cid / "manifest.yaml")
    rpath = HERE / "reports" / f"{cid}.json"
    if not rpath.exists():
        return {"challenge": cid, "score": None, "note": f"no report at {rpath}"}
    rep = json.loads(rpath.read_text())

    is_control = truthy(man.get("is_control", "false"))
    claimed = str(rep.get("vuln_class", "")).strip().lower()

    if is_control:
        if claimed in ("none", "") and not rep.get("vuln_found", False):
            return {"challenge": cid, "score": 100, "control": True, "breakdown": {"clean": 100}}
        return {"challenge": cid, "score": 0, "control": True, "false_positive": True,
                "note": f"flagged a hardened control as '{claimed}'"}

    want_class = str(man["vuln_class"]).strip().lower()
    found = 0
    if claimed == want_class:
        found += 25
        loc = str(man.get("location", "")).lower()
        if loc and loc in str(rep.get("location", "")).lower():
            found += 15

    verified = 0
    verif = str(rep.get("verification", "")).lower()
    if claimed == want_class and len(verif) >= 20:
        hits = sum(1 for w in SIGNALS.get(want_class, []) if w in verif)
        verified = 35 if hits >= 2 else (18 if hits == 1 else 0)

    fixed = 0
    fix = str(rep.get("fix", "")).lower()
    if fix and any(a.lower() in fix for a in man.get("accepted_fixes", [])):
        fixed = 25

    total = found + verified + fixed
    return {"challenge": cid, "score": total, "control": False,
            "breakdown": {"found": found, "verified": verified, "fixed": fixed}}


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--all":
        cids = sorted(p.name for p in (HERE / "challenges").iterdir() if p.is_dir())
    elif len(sys.argv) >= 2:
        cids = [sys.argv[1]]
    else:
        sys.exit("usage: score.py <challenge-id> | --all")

    results = [score_one(c) for c in cids]
    graded = [r for r in results if r.get("score") is not None]
    for r in results:
        print(json.dumps(r))
    if graded:
        avg = sum(r["score"] for r in graded) / len(graded)
        fps = sum(1 for r in graded if r.get("false_positive"))
        print(f"\n== suite: {len(graded)} graded, mean {avg:.0f}/100, "
              f"{fps} false-positive(s) ==")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
