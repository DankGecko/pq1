#!/usr/bin/env python3
"""
Print a human-readable axiom-status table sourced from
`contracts/verification/docs/AXIOM_STATUS.json`.

Used by the `verify-theft-free` make target to produce HONEST output —
each axiom in the dependency closure of `theft_free` is listed with
its current discharge state (placeholder | misleading | cited-tcb |
discharged-bytecode | kernel-tcb).

Output format is plain text, ~80 columns wide.

Exit code:
  0  the ledger uses the closed status vocabulary and was formatted.
  2  malformed or unknown status data (never render an overclaim).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR", "") == ""

def c(code: str) -> str:
    return code if COLOR else ""

RED = c("\033[31m")
YELLOW = c("\033[33m")
GREEN = c("\033[32m")
BLUE = c("\033[34m")
GRAY = c("\033[90m")
BOLD = c("\033[1m")
DIM = c("\033[2m")
RESET = c("\033[0m")


STATUS_LABEL_PLAIN = {
    "placeholder": "PLACEHOLDER",
    "misleading":  "MISLEADING",
    "cited-tcb":   "CITED-TCB",
    "discharged-bytecode": "DISCHARGED",
    "kernel-tcb":  "KERNEL-TCB",
}
STATUS_COLOR = {
    "placeholder": RED,
    "misleading":  YELLOW,
    "cited-tcb":   BLUE,
    "discharged-bytecode": GREEN,
    "kernel-tcb":  GRAY,
}


def status_label(status: str, width: int) -> str:
    if status not in STATUS_LABEL_PLAIN:
        raise ValueError(
            f"unknown axiom status {status!r}; "
            f"allowed={sorted(STATUS_LABEL_PLAIN)}"
        )
    plain = STATUS_LABEL_PLAIN[status]
    pad = max(width - len(plain), 0)
    return f"{STATUS_COLOR.get(status, '')}{plain}{RESET}" + " " * pad


def find_status_file() -> Path:
    here = Path(__file__).resolve()
    candidate = here.parents[1] / "docs" / "AXIOM_STATUS.json"
    if not candidate.exists():
        sys.stderr.write(f"ERROR: AXIOM_STATUS.json not found at {candidate}\n")
        sys.exit(2)
    return candidate


def _reject_duplicate_keys(pairs: list) -> dict:
    """`object_pairs_hook` rejecting duplicate JSON object keys.  Plain
    `json.loads` is silently last-wins: the human-facing table must reflect
    the SAME record the consistency gate enforces, not a hidden first one."""
    obj = {}
    for key, value in pairs:
        if key in obj:
            sys.stderr.write(
                f"ERROR: duplicate key {key!r} in AXIOM_STATUS.json — refusing to "
                f"format a last-wins overwrite (reconcile the ledger)\n")
            sys.exit(2)
        obj[key] = value
    return obj


def main() -> int:
    data = json.loads(find_status_file().read_text(encoding="utf-8"),
                      object_pairs_hook=_reject_duplicate_keys)
    unknown = sorted({
        ax.get("status")
        for ax in data.get("axioms", [])
        if ax.get("status") not in STATUS_LABEL_PLAIN
    }, key=repr)
    if unknown:
        sys.stderr.write(
            f"ERROR: unknown axioms[].status value(s) {unknown}; refusing to "
            "format an unvalidated assurance label\n"
        )
        return 2

    bar = "=" * 76
    print(bar)
    print(f"  {BOLD}theft_free: KERNEL-CHECKED{RESET}")
    print()
    print(f"  Lean 4 elaborated and type-checked the theorem")
    print(f"  `{data['headline_theorem']}`.")
    print()
    print(f"  The table below classifies every axiom in its dependency closure.")
    print(f"  Categories:")
    print(f"    - {RED}PLACEHOLDER{RESET}: type reduces to `True`. No semantic content;")
    print(f"      the axiom name appears in `#print axioms` for documentation")
    print(f"      but the kernel is not constrained by it.")
    print(f"    - {YELLOW}MISLEADING{RESET}: has propositional content but states a")
    print(f"      property of a Lean model that is not the deployed contract.")
    print(f"    - {BLUE}CITED-TCB{RESET}: has content; discharge is a citation to a")
    print(f"      peer-reviewed proof or universally-trusted Ethereum infrastructure.")
    print(f"    - {GREEN}DISCHARGED{RESET}: has content; a machine-checkable artifact")
    print(f"      (Kontrol session, Certora rule-set, Lean theorem) discharges it.")
    print(f"    - {GRAY}KERNEL-TCB{RESET}: Lean 4 kernel built-in, trusted as part of")
    print(f"      the kernel's soundness.")
    print(bar)

    print()
    print(f"  {BOLD}{'#':<12}{'Status':<14}{'Axiom':<48}{RESET}")
    print(f"  {'-' * 12}{'-' * 14}{'-' * 48}")
    for ax in data["axioms"]:
        status = ax["status"]
        ax_id = ax["id"]
        name = ax["name"]
        short = name.split(".")[-1]
        print(f"  {ax_id:<12}{status_label(status, 14)}{short}")

    print()
    print(bar)
    print(f"  {BOLD}Discharge plan per axiom{RESET}")
    print(bar)
    for ax in data["axioms"]:
        if ax["status"] == "kernel-tcb":
            continue
        print()
        print(f"  {BOLD}{ax['id']}: {ax['name']}{RESET}")
        print(f"      Status: {status_label(ax['status'], 0)}")
        # Wrap description at ~70 cols.
        desc = ax.get("description", "")
        for line in wrap(desc, 68):
            print(f"      {DIM}{line}{RESET}")
        # Status detail (concise)
        if ax.get("status_detail"):
            for line in wrap(ax["status_detail"], 68):
                print(f"      {DIM}> {line}{RESET}")
        # Planned discharge
        for step in ax.get("planned_discharge", []):
            for j, line in enumerate(wrap(step, 64)):
                prefix = "      -> " if j == 0 else "         "
                print(f"      {prefix}{line}")
        if ax.get("citation"):
            for line in wrap(f"cite: {ax['citation']}", 64):
                print(f"      {DIM}      {line}{RESET}")

    print()
    print(bar)
    summary = data["summary"]
    total = summary["total_axioms_in_closure"]
    placeholder = summary["placeholder_true_typed"]
    misleading = summary["misleading"]
    cited = summary["cited_tcb"]
    discharged = summary["discharged_bytecode"]
    kernel = summary["kernel_tcb"]
    print(f"  Summary: {total} axiom(s) in closure;",
          f"{RED}{placeholder} placeholder{RESET},",
          f"{YELLOW}{misleading} misleading{RESET},",
          f"{BLUE}{cited} cited-TCB{RESET},",
          f"{GREEN}{discharged} discharged{RESET},",
          f"{GRAY}{kernel} kernel-TCB{RESET}.")
    print()
    print(f"  Honest one-line: {data['headline_one_line']}")
    print()
    print(f"  Source of truth: contracts/verification/docs/AXIOM_STATUS.json")
    print(f"  Discharge plan:  contracts/verification/docs/DISCHARGE_PLAN.md")
    print(bar)
    return 0


def wrap(text: str, width: int) -> list[str]:
    """Greedy word-wrap to roughly `width` columns."""
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        if not cur:
            cur = w
        elif len(cur) + 1 + len(w) <= width:
            cur = cur + " " + w
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


if __name__ == "__main__":
    sys.exit(main())
