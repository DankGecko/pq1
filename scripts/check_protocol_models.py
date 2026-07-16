#!/usr/bin/env python3
"""verify-protocol-models — a regression GATE for the design-layer protocol
proofs (ProVerif / Tamarin / CryptoVerif). It is the third sibling of the repo's
anti-vacuity gates (`verify-proof-mutation` for Lean, `verify-kani-mutation` for
the firmware harnesses).

WHY a gate and not just `make proverif`/`tamarin`/`cryptoverif`: those targets
RUN the tools but exit 0 whether a query is true or false — and these models
carry DESIGNED `is false` residuals (positive controls + documented leak-
residuals). So a bare run is NOT a gate: a security query silently flipping
true->false, or a lemma falsifying, would go unnoticed between manual re-runs.
This asserts each model's verdict pattern against a committed per-file baseline;
any drift (a true->false flip, a falsified lemma, a lost proof, or a tool/parse
failure that zeroes the counts) exits non-zero.

SCOPE (upgraded 2026-07-16, FV review finding F7 — reopens PM-2). This is now a
verdict-IDENTITY gate, not just a verdict-COUNT tripwire:

  1. NONZERO PROVER EXIT IS A FAILURE, checked BEFORE any output parsing.
     proverif 2.05 and tamarin 1.12 both exit 0 on success EVEN with designed
     `is false` residuals (verified on every in-tree model 2026-07-16), so a
     nonzero code cleanly means the tool crashed / could not parse — it must not
     be read as "0 queries, all fine". The pre-fix driver discarded the child
     return code entirely, so a prover that died mid-run (or a synthetic process
     that printed the expected banner and exited 42) passed. It no longer does.

  2. PER-QUERY / PER-LEMMA IDENTITY, not just counts. Each ProVerif RESULT line
     is parsed to (normalized query text -> verdict) and each Tamarin lemma to
     (lemma name -> verdict), then compared as an EXACT DICT against the
     committed baseline. A same-count semantic substitution (e.g. changing the
     authenticity query `Install(m) ==> Sign(m)` to the tautology
     `Install(m) ==> Install(m)`) keeps the true/false COUNTS identical but
     changes the query TEXT, so it now fails. Counts + `cannot be proved`==0 are
     retained as belt-and-braces.

ProVerif fresh-variable suffixes (`c_2`, `p_6`, `m_1`, ...) are numbered
per-run, so the query text is normalized `_[0-9]+ -> _N` before comparison; the
predicate/structure — the security-relevant part — is exact.

Families (select with the PROTOCOL_MODELS env var, comma-separated; default all):
  * proverif    — 5 .pv (dual-SE unlock, SCP03 handshake+replay, OPTIGA shield,
                  FW-update authenticity)
  * tamarin     — 3 .spthy (PIN-lockstep, SCP03 replay, seed-split XOR)
  * cryptoverif — 1 .cv (seed-split secrecy, computational)
CI runs `PROTOCOL_MODELS=proverif,tamarin` — an EXPLICIT 2-family subset (the 8
symbolic models). CryptoVerif is local-only on purpose: its ONE property
(seed-split secrecy) is already symbolically gated by tamarin/seed_split_xor.spthy
— the .cv is the computational belt-and-braces. This is a stated subset, not a
silent skip.

Baselines were produced by ProVerif 2.05 / Tamarin 1.12.0 / Maude 3.5.1 — the CI
job pins those exact versions, else the counts can shift for reasons unrelated to
any real regression. Update the baselines below (and note it) when a model
legitimately changes.

Exit: 0 = every in-scope model matches its baseline; 1 = a regression (drifted
count/identity / falsified / lost proof); 2 = harness error (tool missing, file
absent, nonzero prover exit).

Self-test: `check_protocol_models.py --self-test` runs the WIRED-IN NEGATIVE
CONTROL (no tools needed): it feeds each pure checker a corrupted input
(the `Install=>Install` substitution, a verified->falsified flip, a nonzero
exit, a missing lemma) and asserts each fires, plus a clean input that must NOT
fire. Proves the gate is not vacuous. CI runs it alongside the live gate.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PV_DIR = REPO_ROOT / "contracts" / "verification" / "proverif"
TAM_DIR = REPO_ROOT / "contracts" / "verification" / "tamarin"

# --------------------------------------------------------------------------- #
# COMMITTED BASELINES — captured from ProVerif 2.05 / Tamarin 1.12.0, 2026-07-16.
# Update (and note) when a model legitimately changes.
# --------------------------------------------------------------------------- #
# ProVerif: {file: {normalized_query: verdict_bool}} — verdict True = "is true".
PROVERIF_IDENTITY: dict[str, dict[str, bool]] = {
    "dual_se_unlock.pv": {
        "not attacker(reconstruct(hoB[],heB[]))": True,
        "not attacker(reconstruct(ho1[],he1[]))": True,
        "not attacker(reconstruct(ho2[],he2[]))": True,
        "not attacker(reconstruct(hoP[],heP[]))": False,
        "event(ReleasedHalfO(h,p_N)) ==> event(PresentedPinO(p_N))": True,
        "event(ReleasedHalfE(h,p_N)) ==> event(PresentedPinE(p_N))": True,
        "not event(ReleasedHalfO(h,p_N))": False,
        "not event(ReleasedHalfE(h,p_N))": False,
    },
    "scp03_handshake.pv": {
        "not attacker(pinB[])": True,
        "event(HostAccepted(h,c_N)) ==> event(CardSent(h,c_N))": True,
        "event(CardAccepted(h,c_N)) ==> event(HostSent(h,c_N))": True,
        "not event(CardSent(h,c_N))": False,
        "not event(HostAccepted(h,c_N))": False,
        "not event(HostSent(h,c_N))": False,
        "not event(CardAccepted(h,c_N))": False,
        "not attacker(pinR[])": False,
    },
    "optiga_shield_handshake.pv": {
        "not attacker(halfOB[])": True,
        "event(HostAccepted(h,c)) ==> event(OptSent(h,c))": True,
        "event(OptAccepted(h,c)) ==> event(HostSent(h,c))": True,
        "not event(HostAccepted(h,c))": False,
        "not event(OptAccepted(h,c))": False,
        "not attacker(halfOR[])": False,
    },
    "scp03_replay.pv": {
        "event(Accept(ctr_N,cmd_N)) ==> event(Send(ctr_N,cmd_N))": True,
        "not event(Accept(ctr_N,cmd_N))": False,
    },
    "fw_update_authenticity.pv": {
        "event(Install(m_N)) ==> event(Sign(m_N))": True,
        "not event(Install(m_N))": False,
    },
}
# Tamarin: {file: {lemma_name: "verified"|"falsified"}}.
TAMARIN_IDENTITY: dict[str, dict[str, str]] = {
    "pin_lockstep.spthy": {
        "honest_boot_possible": "verified",
        "fresh_synced_means_no_reset": "verified",
        "zero_synced_means_all_reset": "verified",
        "full_reset_bypass": "verified",
    },
    "scp03_replay.spthy": {
        "can_accept": "verified",
        "no_replay": "verified",
    },
    "seed_split_xor.spthy": {
        "seed_secret_under_single_compromise": "verified",
        "both_compromised_leaks_seed": "verified",
    },
}


class HarnessError(Exception):
    pass


# --------------------------------------------------------------------------- #
# pure parsers + comparison (unit-testable without the tools)
# --------------------------------------------------------------------------- #
def _norm_query(q: str) -> str:
    """Normalize ProVerif fresh-variable suffixes `_<digits>` -> `_N` so the
    baseline is stable across runs. The predicate structure is preserved."""
    return re.sub(r"_\d+", "_N", q.strip())


def parse_proverif(output: str) -> tuple[dict[str, bool], int]:
    """(normalized query -> verdict_bool, cannot_be_proved_count) from a run.
    A duplicated query text (same normalized key, conflicting verdict) is a
    parse ambiguity and raises, so a model cannot hide a flip behind a twin."""
    identity: dict[str, bool] = {}
    for m in re.finditer(r"^RESULT (.+?) is (true|false)\.?\s*$", output, re.MULTILINE):
        key = _norm_query(m.group(1))
        verdict = m.group(2) == "true"
        if key in identity and identity[key] != verdict:
            raise HarnessError(f"conflicting verdicts for normalized query {key!r} "
                               f"— fresh-var normalization is too aggressive for this model")
        identity[key] = verdict
    cannot = output.count("cannot be proved")
    return identity, cannot


def parse_tamarin(output: str) -> dict[str, str]:
    """{lemma_name: verdict} from a `tamarin-prover --prove` run."""
    identity: dict[str, str] = {}
    for m in re.finditer(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\):\s*(verified|falsified)\b",
                         output, re.MULTILINE):
        identity[m.group(1)] = m.group(2)
    return identity


def diff_identity(fname: str, expected: dict, got: dict) -> list[str]:
    """Exact-dict comparison. Reports missing keys, unexpected extra keys, and
    verdict mismatches — each is a regression."""
    fails = []
    for key, ev in expected.items():
        if key not in got:
            fails.append(f"{fname}: expected result `{key}` is MISSING "
                         f"(lost/renamed proof, or the tool did not emit it)")
        elif got[key] != ev:
            fails.append(f"{fname}: result `{key}` verdict DRIFTED — "
                         f"expected {ev!r}, got {got[key]!r} (a security property flipped)")
    for key, gv in got.items():
        if key not in expected:
            fails.append(f"{fname}: UNEXPECTED result `{key}` = {gv!r} "
                         f"(new/substituted query — if intentional, update the baseline)")
    return fails


# --------------------------------------------------------------------------- #
# live runners
# --------------------------------------------------------------------------- #
def _run(cmd: list[str], cwd: Path, timeout: int) -> tuple[str, int]:
    try:
        cp = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise HarnessError(f"tool not runnable: {cmd[0]!r} not on PATH")
    except subprocess.TimeoutExpired:
        raise HarnessError(f"{' '.join(cmd)} timed out (>{timeout}s)")
    return cp.stdout + cp.stderr, cp.returncode


def check_proverif() -> list[str]:
    fails = []
    for fname, ident in PROVERIF_IDENTITY.items():
        path = PV_DIR / fname
        if not path.exists():
            raise HarnessError(f"proverif model missing: {path}")
        out, rc = _run(["proverif", fname], PV_DIR, 600)
        if rc != 0:
            # proverif exits 0 even on `is false` residuals; nonzero == tool error.
            raise HarnessError(f"proverif exited {rc} on {fname} (crash/parse error, NOT a verdict)")
        got, cannot = parse_proverif(out)
        et = sum(1 for v in ident.values() if v)
        ef = sum(1 for v in ident.values() if not v)
        t = sum(1 for v in got.values() if v)
        f = sum(1 for v in got.values() if not v)
        id_fails = diff_identity(fname, ident, got)
        if cannot != 0:
            id_fails.append(f"{fname}: {cannot} query(ies) `cannot be proved` (expected 0)")
        mark = "ok  " if not id_fails else "FAIL"
        print(f"    [{mark}] {fname:28s} true={t}/{et} false={f}/{ef} cannot={cannot}/0 "
              f"(identity: {len(ident)} queries pinned)")
        fails += id_fails
    return fails


def check_tamarin() -> list[str]:
    fails = []
    for fname, ident in TAMARIN_IDENTITY.items():
        path = TAM_DIR / fname
        if not path.exists():
            raise HarnessError(f"tamarin model missing: {path}")
        out, rc = _run(["tamarin-prover", "--prove", fname], TAM_DIR, 900)
        if rc != 0:
            raise HarnessError(f"tamarin exited {rc} on {fname} (crash/parse error, NOT a verdict)")
        got = parse_tamarin(out)
        ev = sum(1 for v in ident.values() if v == "verified")
        v = sum(1 for x in got.values() if x == "verified")
        fl = sum(1 for x in got.values() if x == "falsified")
        id_fails = diff_identity(fname, ident, got)
        mark = "ok  " if not id_fails else "FAIL"
        print(f"    [{mark}] {fname:24s} verified={v}/{ev} falsified={fl}/0 "
              f"(identity: {len(ident)} lemmas pinned)")
        fails += id_fails
    return fails


def check_cryptoverif() -> list[str]:
    # Reuse `make cryptoverif` — it owns the -lib/layout probe (F7: it now tries
    # both `libexec/default` and `bin/default`, the two documented install
    # layouts, so this works on nix AND opam switches).
    out, rc = _run(["make", "cryptoverif"], REPO_ROOT, 600)
    if rc != 0:
        raise HarnessError(f"`make cryptoverif` exited {rc} (tool missing / lib-path / crash):\n"
                           + "\n".join(out.strip().splitlines()[-5:]))
    ok = "All queries proved" in out
    mark = "ok  " if ok else "FAIL"
    print(f"    [{mark}] seed_split_secrecy.cv  'All queries proved'={'yes' if ok else 'NO'}")
    return [] if ok else ["cryptoverif seed_split_secrecy.cv: 'All queries proved' not in output"]


FAMILIES = {"proverif": check_proverif, "tamarin": check_tamarin, "cryptoverif": check_cryptoverif}


# --------------------------------------------------------------------------- #
# WIRED-IN NEGATIVE CONTROL (no tools needed)
# --------------------------------------------------------------------------- #
def self_test() -> int:
    print("=== check_protocol_models --self-test (negative control) ===")
    ok = True

    def expect_fire(label: str, fails: list[str]) -> None:
        nonlocal ok
        if fails:
            print(f"  ok: `{label}` caught ({fails[0][:72]}…)")
        else:
            print(f"  FAIL: corruption `{label}` was NOT caught — gate is vacuous here!")
            ok = False

    def expect_clean(label: str, fails: list[str]) -> None:
        nonlocal ok
        if fails:
            print(f"  FAIL: clean input `{label}` produced a failure (always-fires): {fails}")
            ok = False
        else:
            print(f"  ok: clean `{label}` produced no failure (not always-firing)")

    fw = "fw_update_authenticity.pv"
    base = PROVERIF_IDENTITY[fw]

    # Clean control: the real committed output must NOT fire.
    clean_out = ("RESULT event(Install(m_1)) ==> event(Sign(m_1)) is true.\n"
                 "RESULT not event(Install(m_1)) is false.\n")
    got, _ = parse_proverif(clean_out)
    expect_clean("fw baseline", diff_identity(fw, base, got))

    # PoC 1: Install=>Sign substituted by the tautology Install=>Install (SAME
    # true/false counts) — the count-only gate missed this; identity catches it.
    tauto_out = ("RESULT event(Install(m_1)) ==> event(Install(m_1)) is true.\n"
                 "RESULT not event(Install(m_1)) is false.\n")
    got, _ = parse_proverif(tauto_out)
    expect_fire("Install=>Install tautology (same count)", diff_identity(fw, base, got))

    # PoC 2: a security query flips true -> false.
    flip_out = ("RESULT event(Install(m_1)) ==> event(Sign(m_1)) is false.\n"
                "RESULT not event(Install(m_1)) is false.\n")
    got, _ = parse_proverif(flip_out)
    expect_fire("authenticity query flipped true->false", diff_identity(fw, base, got))

    # PoC 3: `cannot be proved` residual must fire.
    got, cannot = parse_proverif(clean_out + "Query ... cannot be proved.\n")
    fails = diff_identity(fw, base, got) + (
        [f"{fw}: {cannot} cannot"] if cannot else [])
    expect_fire("cannot-be-proved residual", fails)

    # PoC 4: nonzero prover exit with expected banner text (the exit-42 PoC).
    # The live checker raises HarnessError on rc!=0 BEFORE parsing; simulate that
    # contract directly.
    def rc_gate(rc: int) -> list[str]:
        if rc != 0:
            return [f"proverif exited {rc} (crash/parse error, NOT a verdict)"]
        return []
    expect_fire("nonzero exit 42 with expected banner", rc_gate(42))
    expect_clean("zero exit", rc_gate(0))

    # PoC 5 (tamarin): a verified lemma reported falsified.
    tl = "pin_lockstep.spthy"
    tbase = TAMARIN_IDENTITY[tl]
    tclean = "\n".join(f"  {k} (all-traces): {v} (3 steps)" for k, v in tbase.items())
    expect_clean("tamarin baseline", diff_identity(tl, tbase, parse_tamarin(tclean)))
    tflip = tclean.replace("honest_boot_possible (all-traces): verified",
                           "honest_boot_possible (all-traces): falsified")
    expect_fire("tamarin lemma falsified", diff_identity(tl, tbase, parse_tamarin(tflip)))
    # PoC 6 (tamarin): a lemma silently dropped.
    tdrop = "\n".join(l for l in tclean.splitlines() if "full_reset_bypass" not in l)
    expect_fire("tamarin lemma dropped", diff_identity(tl, tbase, parse_tamarin(tdrop)))

    print("=== self-test PASS ===" if ok else "=== self-test FAILED ===")
    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()

    sel = os.environ.get("PROTOCOL_MODELS", "proverif,tamarin,cryptoverif")
    families = [f.strip() for f in sel.split(",") if f.strip()]
    unknown = [f for f in families if f not in FAMILIES]
    if unknown:
        print(f"ERROR: unknown family/families {unknown} (valid: {list(FAMILIES)})", file=sys.stderr)
        return 2

    print(f"=== verify-protocol-models (families: {', '.join(families)}) ===")
    print("    Assert each design-layer model's per-query/per-lemma verdict IDENTITY vs the")
    print("    committed baseline; nonzero prover exit is a failure (F7, 2026-07-16).\n")

    all_fails = []
    for fam in families:
        print(f"--> {fam}")
        try:
            all_fails += FAMILIES[fam]()
        except HarnessError as e:
            print(f"    HARNESS ERROR: {e}", file=sys.stderr)
            return 2

    print()
    if all_fails:
        print(f"FAIL: {len(all_fails)} protocol-model regression(s):", file=sys.stderr)
        for m in all_fails:
            print(f"  - {m}", file=sys.stderr)
        print("\nA drifted verdict/identity = a model's proof changed. If INTENTIONAL "
              "(you edited a model), update the baseline in scripts/check_protocol_models.py "
              "and note it. Otherwise a security property regressed — investigate.", file=sys.stderr)
        return 1
    print(f"OK: all in-scope protocol models match their per-query/per-lemma identity baseline "
          f"(for the families run).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
