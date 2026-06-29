#!/usr/bin/env python3
"""run_review.py — backend-AGNOSTIC orchestrator for the PQSigner FV adversarial
review. Drives any CLI/agent that reads a prompt and emits JSON (Claude Code,
Codex, a raw LLM, a future system). The portable primitive is:

    (PROMPT.md persona)  +  (protocol.json angles/schema)  +  (pipe to $CMD)

It is intentionally THIN — the linchpin is the strict findings schema in
PROMPT.md/protocol.json, not this orchestrator. For each review angle it
assembles the prompt (persona + angle instructions + resolved target paths),
runs N independent reviewer passes through the chosen backend, parses the JSON
answers, cross-votes (a finding ≥ quorum reviewers raise is 'confirmed'), and
writes report.md + findings.json.

Usage:
    run_review.py --backend claude                       # all angles, defaults
    run_review.py --backend codex --angle lean-vacuity   # one angle
    run_review.py --backend generic --cmd 'codex exec - < {prompt_file}'
    run_review.py --backend claude --reviewers 3 --quorum 2   # majority cross-vote
    run_review.py --dry-run --angle ledger-honesty       # print the prompt, no call
    run_review.py --backend generic --cmd 'cat tests/canned_findings.json' --self-test-ok
        # SELF-TEST: proves orchestration end-to-end without burning an LLM call

Exit: 0 = ran (findings may be non-empty — this tool REPORTS, it does not gate);
      2 = orchestration/setup error.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

KIT_DIR = Path(__file__).resolve().parent
PROTOCOL = KIT_DIR / "protocol.json"
PROMPT_MD = KIT_DIR / "PROMPT.md"


def load_protocol() -> dict:
    return json.loads(PROTOCOL.read_text(encoding="utf-8"))


def resolve_targets(root: Path, globs: list[str]) -> list[Path]:
    out: list[Path] = []
    for g in globs:
        for p in sorted(root.glob(g)):
            if p.is_file():
                out.append(p)
    return out


def assemble_prompt(proto: dict, angle: dict, root: Path, inline: bool, max_bytes: int) -> str:
    persona = PROMPT_MD.read_text(encoding="utf-8")
    files = resolve_targets(root, angle["targets"])
    lines = [persona, "\n\n---\n\n## THIS REVIEW",
             f"ROOT (absolute): {root}",
             f"ANGLE: {angle['id']} — {angle['title']}",
             "",
             angle["instructions"],
             "",
             "### Targets to review (read these in full if you have file tools):"]
    for f in files:
        lines.append(f"- {f}")
    if not files:
        lines.append("- (no files matched this angle's globs under ROOT — report that as honest_residual)")
    if inline:
        lines.append("\n### INLINED-FILES (your runtime may lack file tools):")
        for f in files:
            try:
                data = f.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                lines.append(f"\n----- {f} (unreadable: {e}) -----")
                continue
            truncated = data[:max_bytes]
            tag = "" if len(data) <= max_bytes else f" [TRUNCATED to {max_bytes} bytes of {len(data)}]"
            lines.append(f"\n----- {f}{tag} -----\n{truncated}")
    lines.append("\n\nNow emit the STRICT JSON object (findings + honest_residual) for THIS angle only.")
    return "\n".join(lines)


# JSON extraction: pull the last balanced top-level {...} from possibly-noisy output.
def extract_json(text: str) -> dict | None:
    # strip ```json fences if present
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidates = list(fenced)
    # also brace-scan for top-level objects
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    candidates.append(text[start:i + 1])
    for cand in reversed(candidates):
        try:
            obj = json.loads(cand)
            if isinstance(obj, dict) and "findings" in obj:
                return obj
        except json.JSONDecodeError:
            continue
    return None


def run_backend(template: str, prompt: str, timeout: int) -> tuple[str, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".prompt.md", delete=False) as tf:
        tf.write(prompt)
        prompt_path = tf.name
    cmd = template.replace("{prompt_file}", prompt_path)
    try:
        cp = subprocess.run(cmd, shell=True, cwd=str(KIT_DIR),
                            capture_output=True, text=True, timeout=timeout)
        return cp.stdout, cp.stderr
    finally:
        try:
            Path(prompt_path).unlink()
        except OSError:
            pass


def aggregate(per_reviewer: list[dict | None], quorum: int) -> dict:
    """Group findings across reviewer passes; mark confirmed if ≥ quorum distinct
    reviewers raised a matching (target-basename, v_class, title-stem) finding."""
    groups: dict[tuple, dict] = {}
    residuals: list[str] = []
    for ridx, ans in enumerate(per_reviewer):
        if ans is None:
            residuals.append(f"[reviewer {ridx}] produced no parseable JSON.")
            continue
        residuals.append(f"[reviewer {ridx}] {ans.get('honest_residual', '(no honest_residual!)')}")
        for f in ans.get("findings", []):
            tgt = str(f.get("target", "")).split("/")[-1].split(":")[0]
            stem = "-".join(re.findall(r"[a-z0-9]+", str(f.get("title", "")).lower())[:5])
            key = (tgt, f.get("v_class", "?"), stem)
            g = groups.setdefault(key, {"voters": set(), "items": []})
            g["voters"].add(ridx)
            g["items"].append(f)
    confirmed, unconfirmed = [], []
    for key, g in groups.items():
        rep = max(g["items"], key=lambda x: x.get("confidence", 0))
        rep = dict(rep)
        rep["_votes"] = len(g["voters"])
        (confirmed if len(g["voters"]) >= quorum else unconfirmed).append(rep)
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    keyf = lambda x: (sev_rank.get(x.get("severity", "info"), 9), -x.get("confidence", 0))
    confirmed.sort(key=keyf)
    unconfirmed.sort(key=keyf)
    return {"confirmed": confirmed, "unconfirmed": unconfirmed, "residuals": residuals}


def render_report(proto: dict, results: dict[str, dict], reviewers: int, quorum: int) -> str:
    out = ["# FV adversarial-review report", "",
           f"protocol: {proto['name']} v{proto['version']} | "
           f"reviewers={reviewers} quorum={quorum}", ""]
    total_conf = sum(len(r["confirmed"]) for r in results.values())
    total_unconf = sum(len(r["unconfirmed"]) for r in results.values())
    out += [f"**{total_conf} confirmed** (≥{quorum} reviewers) | "
            f"{total_unconf} single-/sub-quorum | across {len(results)} angle(s)", ""]
    for angle_id, r in results.items():
        out += [f"## angle: {angle_id}", ""]
        if r["confirmed"]:
            out.append("### confirmed findings")
            for f in r["confirmed"]:
                out += _fmt_finding(f)
        if r["unconfirmed"]:
            out.append("### sub-quorum findings (single reviewer — triage, do not trust blindly)")
            for f in r["unconfirmed"]:
                out += _fmt_finding(f)
        if not r["confirmed"] and not r["unconfirmed"]:
            out.append("_no findings parsed for this angle._")
        out.append("")
        out.append("#### honest residuals (the tracked defeaters — read these)")
        for res in r["residuals"]:
            out.append(f"- {res}")
        out.append("")
    out += ["---",
            "_This review surfaces candidates; it does not gate. It closes nothing on its "
            "own — V7 (latent-false axiom) and V11 (wrong spec) survive any single pass. "
            "Treat the honest residuals as the live to-verify list, not as reassurance._"]
    return "\n".join(out)


def _fmt_finding(f: dict) -> list[str]:
    return [
        f"- **[{f.get('severity','?')}/{f.get('v_class','?')}] {f.get('title','')}** "
        f"(votes={f.get('_votes',1)}, conf={f.get('confidence','?')})",
        f"  - target: `{f.get('target','')}`",
        f"  - claim: {f.get('claim','')}",
        f"  - defect: {f.get('defect','')}",
        f"  - poc: {f.get('poc','')}",
        f"  - fix: {f.get('suggested_fix','')}",
    ]


def main() -> int:
    proto = load_protocol()
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="claude", help="key in protocol.backends, or 'generic' with --cmd")
    ap.add_argument("--cmd", default=None, help="command template for --backend generic (may use {prompt_file})")
    ap.add_argument("--angle", action="append", help="angle id (repeatable); default = all")
    ap.add_argument("--reviewers", type=int, default=proto["defaults"]["reviewers"])
    ap.add_argument("--quorum", type=int, default=proto["defaults"]["quorum"])
    ap.add_argument("--jobs", type=int, default=proto["defaults"]["jobs"])
    ap.add_argument("--out", default=str(KIT_DIR / "out"))
    ap.add_argument("--inline-files", action="store_true", help="embed file contents (tool-less backends)")
    ap.add_argument("--max-file-bytes", type=int, default=60000)
    ap.add_argument("--timeout", type=int, default=1200)
    ap.add_argument("--dry-run", action="store_true", help="print one assembled prompt and exit")
    ap.add_argument("--self-test-ok", action="store_true", help="assert >=1 finding parsed (for CI self-test)")
    args = ap.parse_args()

    root = (KIT_DIR / proto["root"]).resolve()
    if not root.is_dir():
        print(f"ERROR: root {root} not a directory", file=sys.stderr)
        return 2

    if args.backend == "generic":
        if not args.cmd:
            print("ERROR: --backend generic requires --cmd", file=sys.stderr)
            return 2
        template = args.cmd
    else:
        template = proto["backends"].get(args.backend)
        if not template:
            print(f"ERROR: unknown backend {args.backend!r}; known: {list(proto['backends'])}", file=sys.stderr)
            return 2

    angles = proto["angles"]
    if args.angle:
        want = set(args.angle)
        angles = [a for a in angles if a["id"] in want]
        if not angles:
            print(f"ERROR: no angle matched {args.angle}", file=sys.stderr)
            return 2

    if args.dry_run:
        print(assemble_prompt(proto, angles[0], root, args.inline_files, args.max_file_bytes))
        return 0

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, dict] = {}
    raw_dump: dict[str, list] = {}

    for angle in angles:
        prompt = assemble_prompt(proto, angle, root, args.inline_files, args.max_file_bytes)
        print(f"==> angle {angle['id']}: {args.reviewers} reviewer pass(es) via `{args.backend}`…",
              file=sys.stderr)

        def one_pass(_i):
            out, err = run_backend(template, prompt, args.timeout)
            obj = extract_json(out)
            if obj is None and err.strip():
                print(f"    reviewer {_i} stderr: {err.strip()[:200]}", file=sys.stderr)
            return obj

        if args.jobs > 1:
            with ThreadPoolExecutor(max_workers=args.jobs) as ex:
                per = list(ex.map(one_pass, range(args.reviewers)))
        else:
            per = [one_pass(i) for i in range(args.reviewers)]

        results[angle["id"]] = aggregate(per, args.quorum)
        raw_dump[angle["id"]] = [p for p in per]

    report = render_report(proto, results, args.reviewers, args.quorum)
    (out_dir / "report.md").write_text(report, encoding="utf-8")
    (out_dir / "findings.json").write_text(json.dumps(results, indent=2, default=list), encoding="utf-8")
    (out_dir / "raw.json").write_text(json.dumps(raw_dump, indent=2), encoding="utf-8")
    print(report)
    print(f"\n[written to {out_dir}/report.md, findings.json, raw.json]", file=sys.stderr)

    if args.self_test_ok:
        n = sum(len(r["confirmed"]) + len(r["unconfirmed"]) for r in results.values())
        if n == 0:
            print("SELF-TEST FAIL: orchestration produced 0 parsed findings.", file=sys.stderr)
            return 2
        print(f"SELF-TEST OK: orchestration parsed/aggregated {n} finding(s) end-to-end.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
