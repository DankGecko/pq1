# PREDICTION — gate run, 2026-08-13 (written BEFORE the run)

All of today's work lives in `experiments/wots-badenc/`. The certified trees
(`base-c10-split/`, `cdrafts-split/`), `cert_gate_split.sh`, `cert-identity.tsv`
and `closure-c10-split.txt` are **untouched** — `git status --short` on them is
empty, verified immediately before launching.

Per the recon, `INPUTS_SHA256` hashes the `cert_cone.py` require-cone of the
closure roots plus named manifests/tools. **`experiments/` is outside that set.**

## Therefore I predict, exactly:

1. `### RESULT: GREEN`, 0 FAIL.
2. `INPUTS_SHA256 = eb589cafe306046da0a5d7ba0820c7e9` — **byte-identical** to the
   last run. Today's 13 commits must move it by zero.
3. `CLOSURE_COMPILED=32 EXPECTED=32`.
4. `statements pinned=111 expected=111`.
5. `cone: added=0 removed=0`.
6. `ledger=242`.
7. Toolchain r2026.02, 25 provers.

## What each falsifier would mean

* **INPUTS_SHA256 changed** ⇒ something I believed was outside the hashed set is
  inside it. That would mean the experiment is not as isolated as I have been
  claiming all day, and every "the certified artifact is untouched" statement in
  today's commits would need retracting.
* **Any FAIL** ⇒ the experiment leaked into the certified trees despite a clean
  `git status` (e.g. via a stray `.eco` or an include-path shadow).
* **cone added>0** ⇒ a new closure root or dependency crept in.

I expect a boring, byte-identical reproduction. The point of running it is that
"my work is isolated" is currently an *argument*, and this turns it into a
*measurement*.
