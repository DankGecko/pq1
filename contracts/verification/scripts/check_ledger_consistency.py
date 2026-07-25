#!/usr/bin/env python3
"""verify-ledger-consistency — anti-vacuity gate defending failure-class V5
("undischarged-but-advertised") from docs/verification/fv-adversarial-review-playbook.md.

The EF swarm's recurring proof finding (P1 / I-5) was *the ledger said one
thing and the kernel said another*: `theft_free_bytecode` carried a raw `hInv`
hypothesis while AXIOM_STATUS.json advertised the cap "discharged". This gate
makes the human-facing ledger (docs/AXIOM_STATUS.json) FALSIFIABLE against the
machine truth: it cross-checks the advertised closures, axiom inventory, status
counts, and headline-theorem statement shapes against the LIVE Lean dump and
the Lean source — and fails on any divergence.

Eight independent checks (all run; every failure is reported):

  C1  CLOSURE EXACT-SET — every theorem in the ledger's `closures` block has a
      `#print axioms` closure EXACTLY equal to the advertised set (no missing,
      no extra). Generalises lint_fv (c) from {theft_free, offchain} to every
      advertised theorem, and derives the expectation FROM the ledger (so
      editing the ledger to lie is caught against the live dump).
  C2  LINT_FV CROSS-CHECK — `closures[theft_free]` equals the hard-coded
      THEFT_EXPECTED+THEFT_KERNEL pin in lint_fv_invariants.sh, and the
      offchain entry equals that lint's OFF_ALLOWED. Binds this block to the
      existing pin so a 5th drift surface is never born.
  C3  NO UNDOCUMENTED AXIOM — every non-kernel axiom that actually appears in a
      tracked theorem's LIVE closure is documented as an `axioms[].name` entry
      in the ledger (silent trust-expansion guard).
  C4  NO PHANTOM LEDGER AXIOM — every non-kernel `axioms[].name` resolves to a
      real `axiom <ident>` declaration in the Lean source (can't pad the ledger
      with credibility-only entries).
  C5  COUNT CONSISTENCY — the `summary` per-status counts equal the actual tally
      of the `axioms` array by status (format_axiom_status.py READS these counts,
      it does not regenerate them, so drift is real).
  C6  STATUS HYGIENE — no `placeholder`/`misleading` status remains; every
      `discharged-bytecode` axiom carries a real discharge artifact (pinned
      codehash / halmos / kontrol / certora session); every `cited-tcb` axiom
      carries a citation or artifact. No bald "discharged"/"cited" claim.
  C7  SIGNATURE PINS — each headline theorem's normalised statement text hashes
      to its pinned sha256, and satisfies its must_contain/must_not_contain
      substrings. Catches a re-introduced RAW HYPOTHESIS (e.g. reverting the P1
      fix to a bald-`hInv` conditional) that the axiom-closure checks cannot see.
  C8  NO sorryAx — belt-and-braces (verify-audit is the authoritative sorry gate).

================================  SCOPE / CAVEAT  =============================
The LIVE-closure source is `#print axioms` (dump_axioms.lean). In Lean v4.22.0
(this tree) `collectAxioms` was believed to be in the pre-#8842 UNDER-REPORT
window (the #8842 fix merged 2025-07; whether this pin carries it is
unverified — check before relying on either reading). `make verify-lean4checker`
is an INDEPENDENT kernel/environment REPLAY: it catches declarations that fail
to kernel-check, but it does NOT recompute the axiom closure and cannot reveal
a `collectAxioms` omission (its Replay re-adds referenced `.axiomInfo`
declarations as legal axioms; the #8840 shape survives it — FV deep review F5,
2026-07-19). THIS gate checks advertised-vs-#print-axioms CONSISTENCY and the
ledger's internal coherence; it deliberately does NOT try to close the
under-report gap — the allowlist backstop for that class (an external checker
with a `permitted_axioms` list, e.g. nanoda_lib) is tracked as a follow-up.
(NB: --dump expects `#print axioms` format, i.e. dump_axioms.lean output; it
does NOT parse lean4checker's report format. Use a pre-captured dump_axioms
output for offline/CI runs.)

This gate closes V5 (advertised != actual) and V4-adjacent surfaces. It does
NOT catch V7 (latent-FALSE axiom — non-detonatable while lean/ is mathlib-free)
or V11 (wrong spec). See the playbook §A. Do not let "we have a ledger gate
now" become the next overconfidence.
==============================================================================

Usage:
    check_ledger_consistency.py [--dump <file>] [--self-test]

  --dump FILE   use a pre-captured `dump_axioms.lean` output (the `#print axioms`
                format) instead of running lake. (NOT a lean4checker report —
                that has a different format; verify-lean4checker is its own gate.)
  --self-test   run the WIRED-IN NEGATIVE CONTROL: feed each check a corrupted
                input and assert it fires. Proves the gate is not vacuous.
                (Exits 0 iff every corruption was caught.)

Exit: 0 = consistent; 1 = at least one divergence; 2 = internal error.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

KERNEL = {"propext", "Classical.choice", "Quot.sound"}

# --------------------------------------------------------------------------- #
# MANDATORY REGISTRY (F8, 2026-07-16, closes the deletion-tolerance vacuity).
#
# Every other check in this gate iterates a DECLARED collection, so deleting a
# whole collection (e.g. all of `closures`, or the entire `axioms` array with a
# zeroed `summary`) makes the per-entry loops run zero times and PASS silently.
# These IDs are hard-coded HERE — deliberately NOT derived from the ledger, so an
# edit that deletes a ledger entry cannot also delete its floor in one stroke —
# and asserted present, so a deletion is a hard failure. Mirrors the hard-coded
# KERNEL set + the THEFT_EXPECTED pin cross-check (C2).
HEADLINE_THEOREM = "SphincsCVerify.Spec.Theorems.theft_free"
MANDATORY_CLOSURES = {
    "SphincsCVerify.Spec.Theorems.theft_free",                       # flagship
    "SphincsCVerify.Spec.Theorems.theft_free_bytecode",
    "SphincsCVerify.Spec.Theorems.theft_free_bytecode_reachable",
    "SphincsCVerify.Spec.Theorems.theft_free_with_calldata_binding",
    "SphincsCVerify.Spec.Theorems.factory_squat_defence_bytecode",
    "SphincsCVerify.Wallet.Invariants.reachable_implies_combinedCap",
    "SphincsCVerify.Wallet.OffchainBinding.offchain_nested_disjoint_from_userop_digest",
}
MANDATORY_SIGNATURE_PINS = {
    "SphincsCVerify.Spec.Theorems.theft_free",
    "SphincsCVerify.Spec.Theorems.theft_free_bytecode",
    "SphincsCVerify.Spec.Theorems.theft_free_bytecode_reachable",
    "SphincsCVerify.Spec.Theorems.factory_squat_defence_bytecode",
    "SphincsCVerify.Wallet.Invariants.reachable_implies_combinedCap",
}
MANDATORY_WITNESSES = {
    "SphincsCVerify.Wallet.Invariants.combinedCapInvariant_empty",
    "SphincsCVerify.Wallet.Invariants.combinedCapInvariant_initialised",
    "SphincsCVerify.Interpreter.C10.H_adrs_dischargeable",
    "SphincsCVerify.Interpreter.C10.H_sib_dischargeable",
    "SphincsCVerify.Wallet.CreditLedger.execute_step_satisfiable",
}
MANDATORY_COROLLARIES = {
    "SphincsCVerify.Spec.Theorems.theft_free_with_calldata_binding",
    "SphincsCVerify.Spec.Theorems.executeBatch_faithful",
    "SphincsCVerify.Wallet.Invariants.initialize_called_exactly_once",
    "SphincsCVerify.Wallet.Invariants.owner_set_nonempty_after_init",
    "SphincsCVerify.Wallet.Invariants.cannot_remove_bootstrap",
    "SphincsCVerify.Wallet.Invariants.create2_address_chain_independent",
    "SphincsCVerify.Wallet.Invariants.factory_requires_bootstrap_sig",
    "SphincsCVerify.Wallet.Invariants.eip1271_forbids_bootstrap",
}
# C11 — EXACT `closures` identity pin (2026-07-25, closure-review residual):
# the mandatory floors above require only that the load-bearing subset be
# present, and C1 iterates only ledger-declared entries — so a ledger edit that
# DELETED a non-mandatory tracked identity (shrinking the pinned receipt from
# 18 theorems to 17) sailed through C0/C1/C5 with zero failures (reproduced:
# dropping `SphincsCVerify.Crypto.honest_sig_not_forgery`).  Pin the exact key
# set: adding, renaming, or deleting a tracked closure identity must
# consciously update this second authoritative copy — the same discipline as
# the proof-mutation corpus digest.  (The reverse direction — live dump records
# beyond these keys — is deliberately NOT pinned: dump_axioms.lean prints ~79
# further audit-context theorems on purpose.)
EXPECTED_CLOSURES_KEYS = {
    "SphincsCVerify.Crypto.honest_sig_not_forgery",
    "SphincsCVerify.Crypto.keyHistory_empty_signs_nothing",
    "SphincsCVerify.Spec.Theorems.deployed_executeBatch_requires_prior_token",
    "SphincsCVerify.Spec.Theorems.deployed_execute_requires_prior_token",
    "SphincsCVerify.Spec.Theorems.executeBatch_faithful",
    "SphincsCVerify.Spec.Theorems.factory_squat_defence_bytecode",
    "SphincsCVerify.Spec.Theorems.theft_free",
    "SphincsCVerify.Spec.Theorems.theft_free_bytecode",
    "SphincsCVerify.Spec.Theorems.theft_free_bytecode_reachable",
    "SphincsCVerify.Spec.Theorems.theft_free_with_calldata_binding",
    "SphincsCVerify.Wallet.Invariants.cannot_remove_bootstrap",
    "SphincsCVerify.Wallet.Invariants.create2_address_chain_independent",
    "SphincsCVerify.Wallet.Invariants.eip1271_forbids_bootstrap",
    "SphincsCVerify.Wallet.Invariants.factory_requires_bootstrap_sig",
    "SphincsCVerify.Wallet.Invariants.initialize_called_exactly_once",
    "SphincsCVerify.Wallet.Invariants.owner_set_nonempty_after_init",
    "SphincsCVerify.Wallet.Invariants.reachable_implies_combinedCap",
    "SphincsCVerify.Wallet.OffchainBinding.offchain_nested_disjoint_from_userop_digest",
}
# The flagship `theft_free` trust base (A1..A5, non-kernel). Deleting any of
# these from `axioms[]` silently shrinks the advertised assumption set.
MANDATORY_AXIOM_NAMES = {
    "SphincsCVerify.Bridge.EntryPoint.entrypoint_honest",              # A2
    "SphincsCVerify.Bridge.solidityVerifier_compiles_correctly",       # A3.1
    "SphincsCVerify.Bridge.precompile_0x02_is_FIPS_180_4",             # A1
    "SphincsCVerify.Bridge.evm_bytecode_executes_correctly",           # A4
    "SphincsCVerify.Crypto.EUF_CMA_SPHINCSplusC",                      # A5
    "SphincsCVerify.Crypto.ITSR_F",                                    # A5
    "SphincsCVerify.Crypto.SM_DT_TCR_F",                               # A5
    "SphincsCVerify.Crypto.hMsg_random_oracle",                        # A5
}
MANDATORY_COLLECTIONS = ["closures", "signature_pins", "witness_coverage", "axioms", "claim_corollaries"]

SCRIPT_DIR = Path(__file__).resolve().parent
VERIF_DIR = SCRIPT_DIR.parent
LEAN_DIR = VERIF_DIR / "lean"
LEDGER_PATH = VERIF_DIR / "docs" / "AXIOM_STATUS.json"
LINT_FV_PATH = SCRIPT_DIR / "lint_fv_invariants.sh"
DUMP_SCRIPT = "scripts/dump_axioms.lean"


# --------------------------------------------------------------------------- #
# parsing helpers
# --------------------------------------------------------------------------- #
def parse_dump(text: str) -> dict[str, set[str]]:
    """Parse `#print axioms` output into {theorem_fqn: {axiom_fqn, ...}}.

    `#print axioms` wraps long lists across lines; flatten first.
    """
    flat = re.sub(r"\s+", " ", text)
    closures: dict[str, set[str]] = {}
    for m in re.finditer(r"'([^']+)' depends on axioms: \[([^\]]*)\]", flat):
        name = m.group(1)
        axset = {a.strip() for a in m.group(2).split(",") if a.strip()}
        closures[name] = axset
    for m in re.finditer(r"'([^']+)' does not depend on any axioms", flat):
        closures.setdefault(m.group(1), set())
    return closures


def parse_bash_array(text: str, var: str) -> list[str]:
    """Extract the quoted string entries of a bash `VAR=( ... )` array."""
    m = re.search(re.escape(var) + r"=\(\s*(.*?)\)", text, re.DOTALL)
    if not m:
        return []
    return re.findall(r'"([^"]+)"', m.group(1))


def axiom_ident(name: str) -> str:
    """Last dotted component of an axiom `name`, tolerating a compound display
    name like `...solidityWalletExecute_compiles_correctly (+ ...Batch...)`."""
    head = name.strip().split()[0] if name.strip() else name
    return head.split(".")[-1]


def extract_statement(text: str, short: str) -> str | None:
    """`theorem <short> ...` up to and including the first `:= by` delimiter,
    whitespace-normalised. Mirrors the seeding in scripts at gate-authoring time.
    """
    m = re.search(r"(\btheorem\s+" + re.escape(short) + r"\b.*?:=\s+by)", text, re.DOTALL)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()


def sha256_hex(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def run_live_dump() -> str:
    """Run dump_axioms.lean and return combined output. Non-fatal exit (the
    script ends on a missing `main`); we gate on emitted content, like lint_fv."""
    try:
        cp = subprocess.run(
            ["lake", "env", "lean", DUMP_SCRIPT],
            cwd=str(LEAN_DIR), capture_output=True, text=True, timeout=900,
        )
    except FileNotFoundError:
        raise SystemExit("ERROR: `lake` not found on PATH (need elan-installed Lean 4).")
    except subprocess.TimeoutExpired:
        raise SystemExit("ERROR: dump_axioms.lean timed out (>900s).")
    return cp.stdout + cp.stderr


# --------------------------------------------------------------------------- #
# pure checks: each takes parsed data, returns list[str] of failures
# --------------------------------------------------------------------------- #
def check_closures(ledger: dict, live: dict[str, set[str]]) -> list[str]:
    fails = []
    for thm, expected in ledger.get("closures", {}).items():
        exp = set(expected)
        if thm not in live:
            fails.append(f"C1 {thm}: advertised in `closures` but ABSENT from the live dump "
                         f"(rename? dropped from dump_axioms.lean? proof error?)")
            continue
        got = live[thm]
        missing = exp - got
        extra = got - exp
        if missing or extra:
            parts = []
            if missing:
                parts.append("MISSING " + ", ".join(sorted(missing)))
            if extra:
                parts.append("EXTRA " + ", ".join(sorted(extra)))
            fails.append(f"C1 {thm}: advertised closure != live closure — " + "; ".join(parts))
    return fails


def check_lint_fv_crosscheck(ledger: dict, lint_text: str) -> list[str]:
    fails = []
    expected = set(parse_bash_array(lint_text, "THEFT_EXPECTED"))
    kernel = set(parse_bash_array(lint_text, "THEFT_KERNEL"))
    if not expected or not kernel:
        fails.append("C2 could not parse THEFT_EXPECTED/THEFT_KERNEL from lint_fv_invariants.sh "
                     "(format changed? — reconcile by hand before trusting this gate)")
        return fails
    lint_set = expected | kernel
    tf = "SphincsCVerify.Spec.Theorems.theft_free"
    ledger_set = set(ledger.get("closures", {}).get(tf, []))
    if ledger_set != lint_set:
        fails.append(f"C2 closures[theft_free] != lint_fv THEFT_EXPECTED+THEFT_KERNEL pin — "
                     f"ledger-only={sorted(ledger_set - lint_set)} lint-only={sorted(lint_set - ledger_set)}")
    # offchain entry vs OFF_ALLOWED. NB: OFF_ALLOWED is a permitted ALLOWLIST in
    # lint_fv (it lists the full kernel triple even though the actual offchain
    # closure uses only {propext, Quot.sound}), so the binding here is SUBSET
    # (ledger closure within the allowlist) + keccak present. Exactness of the
    # offchain closure itself is enforced by C1 against the live dump.
    off_allowed = set(parse_bash_array(lint_text, "OFF_ALLOWED"))
    off_thm = "SphincsCVerify.Wallet.OffchainBinding.offchain_nested_disjoint_from_userop_digest"
    off_ledger = set(ledger.get("closures", {}).get(off_thm, []))
    if off_allowed and off_ledger:
        outside = off_ledger - off_allowed
        if outside:
            fails.append(f"C2 closures[offchain] has axiom(s) OUTSIDE lint_fv OFF_ALLOWED: "
                         f"{sorted(outside)}")
        keccak = "SphincsCVerify.Wallet.OffchainBinding.keccak_sha256_cross_separation"
        if keccak not in off_ledger:
            fails.append("C2 closures[offchain] is missing keccak_sha256_cross_separation "
                         "(the Gap-3 RAW32-oracle defense would be vacuous).")
    return fails


def _documented_axioms(ledger: dict) -> tuple[set[str], set[str]]:
    """(short-idents, full-names) of every axiom the ledger documents, including
    the `covers` list of a compound entry (so a row that bundles e.g. the single
    + Batch execute axioms must ENUMERATE both full FQNs, not hide one in prose)."""
    short = set(KERNEL)
    full = set(KERNEL)
    for a in ledger.get("axioms", []):
        short.add(axiom_ident(a["name"]))
        full.add(a["name"].strip().split()[0])
        for c in a.get("covers", []):
            short.add(axiom_ident(c))
            full.add(c.strip().split()[0])
    return short, full


def check_no_undocumented_axiom(ledger: dict, live: dict[str, set[str]]) -> list[str]:
    fails = []
    documented, documented_full = _documented_axioms(ledger)
    tracked = set(ledger.get("closures", {}))
    seen: dict[str, str] = {}
    for thm in tracked:
        for ax in live.get(thm, set()):
            seen.setdefault(ax, thm)
    for ax, where in sorted(seen.items()):
        if ax in KERNEL:
            continue
        if ax in documented_full or axiom_ident(ax) in documented:
            continue
        fails.append(f"C3 axiom `{ax}` appears in the live closure of {where} but is NOT "
                     f"documented as an `axioms[].name` entry in the ledger (silent trust expansion).")
    return fails


def check_no_phantom_axiom(ledger: dict, source_idents: set[str]) -> list[str]:
    fails = []
    for a in ledger.get("axioms", []):
        if a.get("status") == "kernel-tcb":
            continue
        for nm in [a["name"]] + a.get("covers", []):
            ident = axiom_ident(nm)
            if ident not in source_idents:
                fails.append(f"C4 ledger axiom {a['id']} (`{nm}`) has no `axiom {ident}` "
                             f"declaration in the Lean source — phantom/credibility-only entry?")
    return fails


def check_counts(ledger: dict) -> list[str]:
    fails = []
    axioms = ledger.get("axioms", [])
    summary = ledger.get("summary", {})
    tally: dict[str, int] = {}
    for a in axioms:
        tally[a.get("status", "?")] = tally.get(a.get("status", "?"), 0) + 1
    checks = [
        ("cited_tcb", tally.get("cited-tcb", 0)),
        ("discharged_bytecode", tally.get("discharged-bytecode", 0)),
        ("kernel_tcb", tally.get("kernel-tcb", 0)),
        ("placeholder_true_typed", tally.get("placeholder", 0)),
        ("misleading", tally.get("misleading", 0)),
        ("total_axioms_in_closure", len(axioms)),
    ]
    for key, actual in checks:
        if key not in summary:
            continue
        if summary[key] != actual:
            fails.append(f"C5 summary.{key} = {summary[key]} but actual tally = {actual} "
                         f"(the hand-maintained count drifted from the axioms array)")
    return fails


def check_status_hygiene(ledger: dict) -> list[str]:
    fails = []
    for a in ledger.get("axioms", []):
        st = a.get("status")
        if st in ("placeholder", "misleading"):
            fails.append(f"C6 axiom {a['id']} (`{a['name']}`) has status `{st}` — the ledger "
                         f"advertises 0 placeholder/misleading; reintroducing one must be conscious.")
        if st == "discharged-bytecode":
            arts = a.get("discharge_artifacts", [])
            ok = any(("pinned_codehash" in art) or
                     (art.get("type") in ("halmos-session", "kontrol-kevm-session", "certora-rule-set",
                                           "lean-refinement", "executable-lean-differential"))
                     for art in arts)
            if not ok:
                fails.append(f"C6 axiom {a['id']} marked `discharged-bytecode` but carries no "
                             f"discharge artifact (pinned codehash / halmos / kontrol / certora / lean).")
        if st == "cited-tcb":
            if not a.get("citation") and not a.get("discharge_artifacts"):
                fails.append(f"C6 axiom {a['id']} marked `cited-tcb` but carries neither a citation "
                             f"nor a discharge artifact.")
    return fails


def check_signature_pins(ledger: dict, file_reader) -> list[str]:
    fails = []
    for thm, pin in ledger.get("signature_pins", {}).items():
        short = thm.split(".")[-1]
        rel = pin["file"]
        text = file_reader(rel)
        if text is None:
            fails.append(f"C7 {thm}: pinned file {rel} not readable")
            continue
        stmt = extract_statement(text, short)
        if stmt is None:
            fails.append(f"C7 {thm}: could not extract `theorem {short} ... := by` "
                         f"(body delimiter changed? refactor?) — reconcile the pin by hand.")
            continue
        got = sha256_hex(stmt)
        if got != pin["sha256"]:
            fails.append(f"C7 {thm}: statement-hash DRIFT — pinned {pin['sha256'][:16]}… "
                         f"got {got[:16]}…. The theorem STATEMENT changed (a hypothesis added/removed, "
                         f"a conjunct dropped). If intended, update the pin; else it is a regression.")
            continue
        for sub in pin.get("must_contain", []):
            if sub not in stmt:
                fails.append(f"C7 {thm}: statement must contain `{sub}` but does not.")
        for sub in pin.get("must_not_contain", []):
            if sub in stmt:
                fails.append(f"C7 {thm}: statement must NOT contain `{sub}` but does "
                             f"(a forbidden raw hypothesis crept back in).")
    return fails


def check_no_sorry(live_text: str) -> list[str]:
    return ["C8 sorryAx present in a tracked closure — a proof is incomplete."] if "sorryAx" in live_text else []


def check_witness_coverage(ledger: dict, live: dict[str, set[str]]) -> list[str]:
    """C9 — ENFORCED non-vacuity-witness coverage. Each `witness_coverage` entry
    names a hand-written witness lemma proving a headline hypothesis is satisfiable
    (so the K conditional that conditions on it is not vacuous). The witness must
    (a) be PRESENT in the live dump (tracked by dump_axioms.lean + compiled) and
    (b) be KERNEL-ONLY — a non-vacuity witness that itself leans on a project axiom
    could be circular (the axiom might be the very thing being witnessed)."""
    fails = []
    for entry in ledger.get("witness_coverage", []):
        w = entry["witness"]
        construct = entry.get("construct", "?")
        if w not in live:
            fails.append(f"C9 witness `{w}` (for {construct}) is NOT in the live dump — the "
                         f"hypothesis would be UNWITNESSED (possibly vacuous). Restore the lemma "
                         f"or add `#print axioms {w}` to dump_axioms.lean.")
            continue
        rogue = live[w] - KERNEL
        if rogue:
            fails.append(f"C9 witness `{w}` closure carries non-kernel axiom(s) {sorted(rogue)} — a "
                         f"non-vacuity witness must be kernel-only, else it may be circular (resting "
                         f"on the very assumption it claims to witness).")
    return fails


# --------------------------------------------------------------------------- #
# C0 — MANDATORY REGISTRY (F8): deletion-tolerance guard.
# --------------------------------------------------------------------------- #
def check_mandatory_registry(ledger: dict) -> list[str]:
    """C0 — every mandatory collection is non-empty AND every hard-coded floor ID
    (flagship + bytecode/reachability chain closures, signature pins, non-vacuity
    witnesses, claim corollaries, and the flagship A1..A5 axiom names) is present.
    Closes the deletion-tolerance vacuity: deleting a whole `closures`/`axioms`/…
    collection (which makes every per-entry loop pass zero times) now fails here,
    as does silently pruning a single load-bearing ID."""
    fails = []
    for key in MANDATORY_COLLECTIONS:
        col = ledger.get(key)
        if not col:
            fails.append(f"C0 mandatory collection `{key}` is EMPTY or ABSENT — a whole evidence "
                         f"collection was deleted; the per-entry checks would pass vacuously.")
    if ledger.get("headline_theorem") != HEADLINE_THEOREM:
        fails.append(f"C0 headline_theorem = {ledger.get('headline_theorem')!r}, expected "
                     f"{HEADLINE_THEOREM!r} (the flagship was renamed or removed).")
    closures = ledger.get("closures", {})
    for t in sorted(MANDATORY_CLOSURES):
        if t not in closures:
            fails.append(f"C0 mandatory closure `{t}` absent from `closures` (deleted?).")
    pins = ledger.get("signature_pins", {})
    for t in sorted(MANDATORY_SIGNATURE_PINS):
        if t not in pins:
            fails.append(f"C0 mandatory signature_pin `{t}` absent from `signature_pins` (deleted?).")
    witnesses = {e.get("witness") for e in ledger.get("witness_coverage", [])}
    for w in sorted(MANDATORY_WITNESSES):
        if w not in witnesses:
            fails.append(f"C0 mandatory non-vacuity witness `{w}` absent from `witness_coverage` (deleted?).")
    coros = set(ledger.get("claim_corollaries", []))
    for c in sorted(MANDATORY_COROLLARIES):
        if c not in coros:
            fails.append(f"C0 mandatory claim corollary `{c}` absent from `claim_corollaries` (deleted?).")
        if c not in closures:
            fails.append(f"C0 claim corollary `{c}` is not a `closures` key (its closure is unpinned).")
    _, documented_full = _documented_axioms(ledger)
    for a in sorted(MANDATORY_AXIOM_NAMES):
        if a not in documented_full and axiom_ident(a) not in _documented_axioms(ledger)[0]:
            fails.append(f"C0 mandatory flagship axiom `{a}` not documented in `axioms[]` — the "
                         f"theft_free trust base (A1..A5) was silently pruned.")
    return fails


def check_closures_identity_pin(ledger: dict) -> list[str]:
    """C11 — the exact `closures` key set MUST equal EXPECTED_CLOSURES_KEYS.
    C0's floors only police a mandatory subset and C1 only iterates declared
    entries, so without this pin a quiet deletion of any other tracked identity
    shrinks the pinned evidence receipt while the gate stays green."""
    keys = set(ledger.get("closures", {}))
    if keys == EXPECTED_CLOSURES_KEYS:
        return []
    missing = sorted(EXPECTED_CLOSURES_KEYS - keys)
    extra = sorted(keys - EXPECTED_CLOSURES_KEYS)
    parts = []
    if missing:
        parts.append("DELETED " + ", ".join(missing))
    if extra:
        parts.append("UNPINNED-NEW " + ", ".join(extra))
    return [f"C11 closures identity drift ({len(keys)} keys, expected "
            f"{len(EXPECTED_CLOSURES_KEYS)}) — {'; '.join(parts)}. Adding, renaming, or "
            f"deleting a tracked closure identity must consciously update EXPECTED_CLOSURES_KEYS."]


# --------------------------------------------------------------------------- #
# source-ident harvest (for C4)
# --------------------------------------------------------------------------- #
def harvest_source_axiom_idents() -> set[str]:
    idents: set[str] = set()
    spec = LEAN_DIR / "SphincsCVerify"
    if not spec.is_dir():
        return idents
    pat = re.compile(r"^\s*axiom\s+([A-Za-z_][A-Za-z0-9_']*)")
    for f in spec.rglob("*.lean"):
        try:
            for line in f.read_text(encoding="utf-8").splitlines():
                m = pat.match(line)
                if m:
                    idents.add(m.group(1))
        except OSError:
            continue
    return idents


# --------------------------------------------------------------------------- #
# negative control
# --------------------------------------------------------------------------- #
def self_test() -> int:
    """WIRED-IN NEGATIVE CONTROL. Feed each check a corrupted input; assert it
    fires. If any corruption is NOT caught, the gate is vacuous → fail loudly."""
    print("=== check_ledger_consistency --self-test (negative control) ===")
    tf = "SphincsCVerify.Spec.Theorems.theft_free"
    base_closure = ["propext", "Classical.choice", "Quot.sound",
                    "SphincsCVerify.Bridge.solidityVerifier_compiles_correctly"]
    ledger = {
        "closures": {tf: list(base_closure)},
        "axioms": [
            {"id": "A3.1", "name": "SphincsCVerify.Bridge.solidityVerifier_compiles_correctly",
             "status": "discharged-bytecode",
             "discharge_artifacts": [{"type": "halmos-session", "pinned_codehash": "0xabc"}]},
            {"id": "K", "name": "propext", "status": "kernel-tcb"},
        ],
        "summary": {"cited_tcb": 0, "discharged_bytecode": 1, "kernel_tcb": 1,
                    "placeholder_true_typed": 0, "misleading": 0, "total_axioms_in_closure": 2},
        "signature_pins": {},
    }
    live_ok = {tf: set(base_closure)}
    cases = []

    # C1: live closure drops an advertised axiom -> must fire
    cases.append(("C1 missing", check_closures(ledger, {tf: set(base_closure[:-1])})))
    # C1: live closure gains an undocumented axiom -> must fire
    cases.append(("C1 extra", check_closures(ledger, {tf: set(base_closure + ["Foo.sneaky"])})))
    # C3: undocumented axiom in live closure -> must fire
    cases.append(("C3", check_no_undocumented_axiom(ledger, {tf: set(base_closure + ["Foo.undocumented"])})))
    # C4: phantom ledger axiom (not in source) -> must fire
    cases.append(("C4", check_no_phantom_axiom(ledger, set())))
    # C5: count drift -> must fire
    bad_counts = dict(ledger); bad_counts["summary"] = dict(ledger["summary"]); bad_counts["summary"]["discharged_bytecode"] = 99
    cases.append(("C5", check_counts(bad_counts)))
    # C6: discharged-bytecode with no artifact -> must fire
    bad_hygiene = {"axioms": [{"id": "X", "name": "SphincsCVerify.Bridge.x", "status": "discharged-bytecode",
                               "discharge_artifacts": []}]}
    cases.append(("C6 no-artifact", check_status_hygiene(bad_hygiene)))
    # C6: a placeholder reappears -> must fire
    cases.append(("C6 placeholder", check_status_hygiene({"axioms": [{"id": "P", "name": "n", "status": "placeholder"}]})))
    # C7: signature drift -> must fire
    pin_ledger = {"signature_pins": {tf: {"file": "x.lean", "sha256": "deadbeef" * 8}}}
    cases.append(("C7 hash", check_signature_pins(
        pin_ledger, lambda r: "theorem theft_free (a : Nat) : True := by trivial")))
    # C7: must_not_contain violated -> must fire
    pin_ledger2 = {"signature_pins": {tf: {"file": "x.lean",
                   "sha256": sha256_hex("theorem theft_free (hInv : X) : True := by"),
                   "must_not_contain": ["hInv"]}}}
    cases.append(("C7 forbidden", check_signature_pins(
        pin_ledger2, lambda r: "theorem theft_free (hInv : X) : True := by trivial")))
    # C8: sorryAx -> must fire
    cases.append(("C8", check_no_sorry("'x' depends on axioms: [sorryAx]")))
    # C10: A3.1 bridge axiom RHS reverted to verifyYulModel -> must fire
    def _reverted_reader(rel):
        if "Refinement.lean" in rel:
            return "axiom solidityVerifier_compiles_correctly :\n  ∀ x, foo x = verifyYulModel x\n\n/-- next -/"
        return "def deployedVerifier (x : T) : Bool :=\n  verifyYulModel x\n\n/-! next -/"
    cases.append(("C10 verifyYulModel-revert", check_bridge_axiom_rhs(_reverted_reader)))
    # C9: witness missing from the dump -> must fire
    wc_ledger = {"witness_coverage": [{"construct": "cap", "witness": "Foo.cap_witness"}]}
    cases.append(("C9 missing", check_witness_coverage(wc_ledger, {})))
    # C9: witness present but rests on a non-kernel axiom -> must fire
    cases.append(("C9 rogue", check_witness_coverage(
        wc_ledger, {"Foo.cap_witness": {"propext", "Some.project_axiom"}})))

    # C0 (F8) DELETION NEGATIVES — the vacuity the per-entry loops could not see.
    # A ledger that satisfies every mandatory floor (the clean control for C0):
    mand = {
        "headline_theorem": HEADLINE_THEOREM,
        "closures": {t: [] for t in (MANDATORY_CLOSURES | MANDATORY_COROLLARIES)},
        "signature_pins": {t: {} for t in MANDATORY_SIGNATURE_PINS},
        "witness_coverage": [{"witness": w} for w in MANDATORY_WITNESSES],
        "claim_corollaries": sorted(MANDATORY_COROLLARIES),
        "axioms": [{"name": a} for a in MANDATORY_AXIOM_NAMES] + [{"name": "propext"}],
    }
    # (a) whole `closures` collection wiped -> must fire
    cases.append(("C0 closures deleted", check_mandatory_registry({**mand, "closures": {}})))
    # (b) only the flagship theft_free closure dropped -> must fire
    cl_no_flag = {k: v for k, v in mand["closures"].items() if k != HEADLINE_THEOREM}
    cases.append(("C0 flagship closure dropped", check_mandatory_registry({**mand, "closures": cl_no_flag})))
    # (c) whole `signature_pins` collection wiped -> must fire
    cases.append(("C0 signature_pins deleted", check_mandatory_registry({**mand, "signature_pins": {}})))
    # (d) whole `witness_coverage` collection wiped -> must fire
    cases.append(("C0 witness_coverage deleted", check_mandatory_registry({**mand, "witness_coverage": []})))
    # (e) whole `axioms` array wiped (the case check_counts alone misses) -> must fire
    cases.append(("C0 axioms deleted", check_mandatory_registry({**mand, "axioms": []})))
    # (f) `claim_corollaries` wiped -> must fire
    cases.append(("C0 claim_corollaries deleted", check_mandatory_registry({**mand, "claim_corollaries": []})))
    # (g) flagship theorem renamed -> must fire
    cases.append(("C0 headline_theorem mutated", check_mandatory_registry({**mand, "headline_theorem": "X.evil"})))
    # (h) a single flagship axiom (A5 EUF-CMA) pruned from axioms[] -> must fire
    ax_no_a5 = [a for a in mand["axioms"] if a["name"] != "SphincsCVerify.Crypto.EUF_CMA_SPHINCSplusC"]
    cases.append(("C0 flagship axiom pruned", check_mandatory_registry({**mand, "axioms": ax_no_a5})))

    # C11 EXACT-IDENTITY NEGATIVES — deleting a NON-mandatory tracked closure
    # (the reproduced 18->17 shrink) or adding an unpinned one must both fire.
    full_closures = {k: [] for k in EXPECTED_CLOSURES_KEYS}
    shrunk_closures = {k: v for k, v in full_closures.items()
                       if k != "SphincsCVerify.Crypto.honest_sig_not_forgery"}
    cases.append(("C11 non-mandatory closure deleted", check_closures_identity_pin({"closures": shrunk_closures})))
    cases.append(("C11 unpinned closure added", check_closures_identity_pin({"closures": {**full_closures, "X.evil": []}})))

    # control: a CLEAN input must NOT fire (guards against always-fire vacuity)
    clean = check_closures(ledger, live_ok) + check_mandatory_registry(mand) \
        + check_closures_identity_pin({"closures": full_closures})

    ok = True
    for label, result in cases:
        if not result:
            print(f"  FAIL: corruption `{label}` was NOT caught — gate is vacuous for this check!")
            ok = False
        else:
            print(f"  ok: `{label}` caught ({result[0][:70]}…)")
    if clean:
        print(f"  FAIL: a CLEAN closure produced a failure (gate always-fires): {clean}")
        ok = False
    else:
        print("  ok: clean closure produced no failure (not always-firing)")
    print("=== self-test PASS ===" if ok else "=== self-test FAILED ===")
    return 0 if ok else 1


def check_bridge_axiom_rhs(file_reader) -> list[str]:
    """C10 (2026-07-02, finding a31/A3.1-RHS-unpinned): the A3.1 bridge axiom RHS and
    the `deployedVerifier` def body MUST be `execC10Asm`, never the truncating
    `verifyYulModel` (FALSE as a ∀ off N-masked keys — the bytecode's two
    `and(key,N_MASK)==key` guards). A silent revert to `= verifyYulModel` keeps every
    closure axiom NAME identical, so C1 (name-diff) cannot see it — this pins the RHS
    SHAPE. The docstrings above both decls DISCUSS verifyYulModel, so we extract only the
    declaration BODY (past the `:` / `:=`, up to the next blank line / decl)."""
    fails = []
    checks = [
        ("lean/SphincsCVerify/Bridge/Refinement.lean",
         r"\baxiom\s+solidityVerifier_compiles_correctly\b\s*:(.*?)(?=\n\n|\n/-|\n\s*axiom\b|\n\s*def\b|\n\s*theorem\b)",
         "A3.1 axiom solidityVerifier_compiles_correctly RHS"),
        ("lean/SphincsCVerify/Bridge/EntryPoint.lean",
         r"\bdef\s+deployedVerifier\b.*?:=(.*?)(?=\n\n|\n/-|\n\s*def\b|\n\s*theorem\b)",
         "deployedVerifier def body"),
    ]
    for rel, pat, label in checks:
        text = file_reader(rel)
        if text is None:
            fails.append(f"C10 {label}: source file {rel} unreadable.")
            continue
        m = re.search(pat, text, re.DOTALL)
        if not m:
            fails.append(f"C10 {label}: declaration not found in {rel} (renamed/moved? reconcile the pin).")
            continue
        body = m.group(1)
        if "execC10Asm" not in body:
            fails.append(f"C10 {label}: must be `execC10Asm` but it is ABSENT "
                         f"(reverted to the FALSE-as-∀ verifyYulModel form?).")
        if "verifyYulModel" in body:
            fails.append(f"C10 {label}: contains `verifyYulModel` — the truncating form is FALSE "
                         f"as a ∀ off N-masked keys; the RHS must be `execC10Asm`.")
    return fails


# --------------------------------------------------------------------------- #
def main() -> int:
    args = sys.argv[1:]
    if "--self-test" in args:
        return self_test()
    dump_file = None
    if "--dump" in args:
        i = args.index("--dump")
        try:
            dump_file = args[i + 1]
        except IndexError:
            print("ERROR: --dump needs a file argument", file=sys.stderr)
            return 2

    try:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot load ledger {LEDGER_PATH}: {exc}", file=sys.stderr)
        return 2

    live_text = Path(dump_file).read_text(encoding="utf-8") if dump_file else run_live_dump()
    live = parse_dump(live_text)
    if not live:
        print("ERROR: no axiom closures parsed from the dump — is the Lean project built? "
              "(cd lean && lake build SphincsCVerify)", file=sys.stderr)
        return 2

    lint_text = LINT_FV_PATH.read_text(encoding="utf-8") if LINT_FV_PATH.exists() else ""
    source_idents = harvest_source_axiom_idents()

    def reader(rel: str) -> str | None:
        p = VERIF_DIR / rel
        try:
            return p.read_text(encoding="utf-8")
        except OSError:
            return None

    fails: list[str] = []
    fails += check_mandatory_registry(ledger)
    fails += check_closures_identity_pin(ledger)
    fails += check_closures(ledger, live)
    fails += check_lint_fv_crosscheck(ledger, lint_text) if lint_text else \
        ["C2 lint_fv_invariants.sh not found — cannot cross-check the closure pin."]
    fails += check_no_undocumented_axiom(ledger, live)
    fails += check_no_phantom_axiom(ledger, source_idents)
    fails += check_counts(ledger)
    fails += check_status_hygiene(ledger)
    fails += check_signature_pins(ledger, reader)
    fails += check_bridge_axiom_rhs(reader)
    fails += check_no_sorry(live_text)
    fails += check_witness_coverage(ledger, live)

    print("=== verify-ledger-consistency (advertised AXIOM_STATUS.json vs live Lean truth) ===")
    print(f"  closures tracked: {len(ledger.get('closures', {}))} | "
          f"axioms documented: {len(ledger.get('axioms', []))} | "
          f"signature pins: {len(ledger.get('signature_pins', {}))} | "
          f"witnesses: {len(ledger.get('witness_coverage', []))}")
    print("  NOTE: live source is `#print axioms` (under-reports in lean v4.22.0); "
          "verify-lean4checker is the completeness backstop.")
    if fails:
        print(f"\nFAIL: {len(fails)} ledger/kernel divergence(s):", file=sys.stderr)
        for f in fails:
            print(f"  - {f}", file=sys.stderr)
        print("\nThe human-facing ledger no longer matches the machine truth. "
              "Reconcile docs/AXIOM_STATUS.json with the Lean source/dump.", file=sys.stderr)
        return 1
    print("\nOK: every advertised closure, count, status, and headline-statement pin "
          "matches the live Lean truth.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
