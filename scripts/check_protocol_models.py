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

SCOPE (honest): this is a verdict-COUNT gate per file — a nightly regression
tripwire, NOT a verdict-IDENTITY check. A true->false flip only hides if an
exactly-cancelling false->true happens in the SAME file; for these models (each
residual is a distinct predicate) that does not occur. For identity you would
normalize ProVerif's fresh-var suffixes (`_[0-9]+` -> `_N`) and golden-diff the
RESULT lines; not built — counts suffice as a tripwire, and the model-level
predicate names are the stable part anyway.

Families (select with the PROTOCOL_MODELS env var, comma-separated; default all):
  * proverif    — 5 .pv (dual-SE unlock, SCP03 handshake+replay, OPTIGA shield,
                  FW-update authenticity)
  * tamarin     — 3 .spthy (PIN-lockstep, SCP03 replay, seed-split XOR)
  * cryptoverif — 1 .cv (seed-split secrecy, computational)
CI runs `PROTOCOL_MODELS=proverif,tamarin` — an EXPLICIT 2-family subset (the 8
symbolic models). CryptoVerif is local-only on purpose: it installs cleanly only
via nix (its `-lib` path is nix-layout-specific) and its ONE property (seed-split
secrecy) is already symbolically gated by tamarin/seed_split_xor.spthy — the .cv
is the computational belt-and-braces. This is a stated subset, not a silent skip.

Baselines were produced by ProVerif 2.05 / Tamarin 1.12.0 / Maude 3.5.1 — the CI
job pins those exact versions, else the counts can shift for reasons unrelated to
any real regression. Update the baselines below (and note it) when a model
legitimately changes.

Exit: 0 = every in-scope model matches its baseline; 1 = a regression (drifted
count / falsified / lost proof); 2 = harness error (tool missing, file absent).
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

# (file, expect_true, expect_false) — per .pv. `cannot be proved` must be 0.
PROVERIF = [
    ("dual_se_unlock.pv", 5, 3),  # +2 false = the ReleasedHalfO/E reachability witnesses (PM-2, 2026-07-02): a reachable event query reports `is false`; both MUST stay false (reachable) or the honest legs went dead + the secrecy verdicts turned vacuous.
    ("scp03_handshake.pv", 3, 5),  # +4 false = the CardSent/HostAccepted/HostSent/CardAccepted reachability witnesses (F2, 2026-07-02): the baseline card/host legs must stay reachable or pinB + both mutual-auth correspondences turn vacuous while pinR stays false.
    ("optiga_shield_handshake.pv", 3, 3),  # +2 false = the HostAccepted/OptAccepted reachability witnesses (F1, 2026-07-02): the baseline optiga/host legs must stay reachable or both mutual-auth correspondences + half_O secrecy turn vacuous (mutation-demonstrated).
    ("scp03_replay.pv", 1, 1),  # +1 false = the Accept reachability witness (F2, 2026-07-02): the card must be able to accept a genuine command or event(Accept)==>event(Send) holds vacuously.
    ("fw_update_authenticity.pv", 1, 1),
]
# (file, expect_verified) — per .spthy. `falsified` must be 0.
TAMARIN = [
    ("pin_lockstep.spthy", 4),
    ("scp03_replay.spthy", 2),
    ("seed_split_xor.spthy", 2),
]


class HarnessError(Exception):
    pass


def _run(cmd: list[str], cwd: Path, timeout: int) -> str:
    try:
        cp = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise HarnessError(f"tool not runnable: {cmd[0]!r} not on PATH")
    except subprocess.TimeoutExpired:
        raise HarnessError(f"{' '.join(cmd)} timed out (>{timeout}s)")
    return cp.stdout + cp.stderr


def check_proverif() -> list[str]:
    fails = []
    for fname, et, ef in PROVERIF:
        path = PV_DIR / fname
        if not path.exists():
            raise HarnessError(f"proverif model missing: {path}")
        out = _run(["proverif", fname], PV_DIR, 600)
        t = len(re.findall(r"RESULT.*is true", out))
        f = len(re.findall(r"RESULT.*is false", out))
        c = out.count("cannot be proved")
        ok = (t == et and f == ef and c == 0)
        mark = "ok  " if ok else "FAIL"
        print(f"    [{mark}] {fname:28s} true={t}/{et} false={f}/{ef} cannot={c}/0")
        if not ok:
            fails.append(f"proverif {fname}: got true={t} false={f} cannot={c}, "
                         f"expected true={et} false={ef} cannot=0")
    return fails


def check_tamarin() -> list[str]:
    fails = []
    for fname, ev in TAMARIN:
        path = TAM_DIR / fname
        if not path.exists():
            raise HarnessError(f"tamarin model missing: {path}")
        out = _run(["tamarin-prover", "--prove", fname], TAM_DIR, 900)
        v = out.count("verified")
        fl = out.count("falsified")
        ok = (v == ev and fl == 0)
        mark = "ok  " if ok else "FAIL"
        print(f"    [{mark}] {fname:24s} verified={v}/{ev} falsified={fl}/0")
        if not ok:
            fails.append(f"tamarin {fname}: got verified={v} falsified={fl}, "
                         f"expected verified={ev} falsified=0")
    return fails


def check_cryptoverif() -> list[str]:
    # Reuse `make cryptoverif` — it owns the -lib/nix invocation logic.
    out = _run(["make", "cryptoverif"], REPO_ROOT, 600)
    ok = "All queries proved" in out
    mark = "ok  " if ok else "FAIL"
    print(f"    [{mark}] seed_split_secrecy.cv  'All queries proved'={'yes' if ok else 'NO'}")
    return [] if ok else ["cryptoverif seed_split_secrecy.cv: 'All queries proved' not in output"]


FAMILIES = {"proverif": check_proverif, "tamarin": check_tamarin, "cryptoverif": check_cryptoverif}


def main() -> int:
    sel = os.environ.get("PROTOCOL_MODELS", "proverif,tamarin,cryptoverif")
    families = [f.strip() for f in sel.split(",") if f.strip()]
    unknown = [f for f in families if f not in FAMILIES]
    if unknown:
        print(f"ERROR: unknown family/families {unknown} (valid: {list(FAMILIES)})", file=sys.stderr)
        return 2

    print(f"=== verify-protocol-models (families: {', '.join(families)}) ===")
    print("    Assert each design-layer model's verdict pattern vs the committed baseline.")
    print("    (verdict-COUNT tripwire per file — not identity; see the module docstring.)\n")

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
        print("\nA drifted verdict count = a model's proof changed. If INTENTIONAL "
              "(you edited a model), update the baseline in scripts/check_protocol_models.py "
              "and note it. Otherwise a security property regressed — investigate.", file=sys.stderr)
        return 1
    print(f"OK: all in-scope protocol models match baseline "
          f"(proverif 13 true / 4 false, tamarin 8 verified / 0 falsified, "
          f"cryptoverif proved — for the families run).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
