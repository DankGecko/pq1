# C10 (SPHINCS+C) EUF-CMA — certified EasyCrypt artifact

Snapshot of the `c10-eufcma-port` research workspace, **re-taken 2026-08-12 at
its commit `0c825ed`**, at which the SPLIT gate is **GREEN — 208 OK, 0 FAIL**
(`INPUTS_SHA256 eb589caf...`, toolchain r2026.02, 25 prover configurations,
receipt in `scratch/gate_run.out`).

> **Previous snapshot line, kept for history:** taken at `16fe480`
> (2026-08-05, "run 26"), at which both certification gates were GREEN.
> **Scope note on this re-snapshot:** the receipt above is for the **split**
> gate, which is the certified closure (32 files). The **fork** tree is synced
> for completeness but its gate was NOT re-run for this snapshot — do not read
> "GREEN" as covering it.

This directory supersedes the older `../drafts/*.ec` snapshot, which is an
earlier stage of the same work and is retained only as history.

## What is actually proved, and what is not

Read this section before quoting anything from this directory.

The headline theorem is `EUFCMA_SPHINCS_PLUS_C10_GROUNDED`
(`cdrafts-split/SphincsC10CapstoneWired.ec`). It is a real, machine-checked
theorem, and it is **not a numerically meaningful bound**:

* It carries `Q = Pr[EUF_CMA_Gproc_I(R_fors_p(F)) : res /\ !covered]` as an
  UNREDUCED bad-event probability. Nothing in this tree bounds `Q` below 1, so
  the bound is currently compatible with 1. What `Q` buys over the earlier
  free-real formulation is that it is a *named game probability an instantiator
  cannot choose*, where a free real could be set to 1 at will.
* `Pr[M.F.ITSRC10 ...]` is likewise carried unreduced — that is the FORS+C10
  assumption and the honest headline term.
* Each cone contains **two admits**, every one pinned by statement digest:
  * split — `nhchwcoll_hchwpre_msg` (`base-c10-split/WOTS_TW_ES.ec`), inherited
    from MM45; and `extract_op` (`cdrafts-split/FORS_C_TreePort.ec`), the
    OpenPRE branch of the FORS bad-event cascade. `extract_op`'s own comment
    names four un-discharged parts (R-KEY, R-SIM, R-INDEX, R-OPEN) and records
    that closing it needs **exposed randomized leaf keygen** — an upstream
    interface change, not more proof effort.
  * fork — `nhchwcoll_hchwpre_msg` and `EUFNAGCMA_FLSLXMSSMTTWESNPRF`, both
    inherited.
* `GprocVI.ec` is the **V→VI hop**, added in run 26 and **admit-free**: MM45
  proves its TRH and TRCO branches over a restructured game `_VI`, not `_V`
  (`FORS_ES.ec:4828-4832`), so without this the T3 reduction has no alignable
  left-hand side. Nine theorems, zero new assumptions — the split ledger stayed
  at 239 across the promotion. It is a **prerequisite**, not a bound.
* `FORS_C_TreePort.ec` (1733 lines) is the prior attempt at bounding `Q`. It was
  admitted to the split closure in run 23 *specifically so its real status is
  gate-enforced rather than asserted in its own prose*; certifying it raised the
  split census by 100 rows. Note what it does and does not bound:
  `fors_c_tree_port` bounds `EUF_CMA_FORSC_I`, **not** `EUF_CMA_Gproc_I`.
  Different game. It does not bound `Q`.
* Deployed-parameter and encoder claims are narrower than their names suggest;
  see `cdrafts-fork/C10DeployedGeometry.ec` sections 35-41.

`cdrafts-fork/C10DeployedGeometry.ec` is a ~2900-line dated log of every claim
this artifact has made and every one it has had to withdraw. It is the honest
record and is more useful than any summary, including this one.

## Reproducing the GREEN

Requires EasyCrypt **r2026.02** (the pinned toolchain; r2026.06 fails four
closure files). A container recipe is in `../docker/`.

```sh
export LC_ALL=C          # REQUIRED: identity hashing is collation-sensitive
bash cert_gate_split.sh  # 24 targets, 87 pins, 1159 census rows
bash cert_gate_fork.sh   # 19 targets,  9 pins, 1089 census rows
```

Both must end `RESULT: GREEN` / `CERT_FAILURES=0`. Expected identities are
committed in `cert-identity.tsv`; each gate recomputes and compares, and
recomputes again at the end to catch drift mid-run.

The gates check, in order: input identity, include-path ambiguity, a
concurrency guard, a verified recursive `.eco` purge, compilation of every
closure file **as an explicit target**, that every closure file is
**requirable** (EasyCrypt returns rc=0 for a file that ends mid-proof — this
phase is what catches that), that named results are `lemma` and not `axiom`,
statement digests, a require-cone census compared as a multiset against a
committed baseline with additions *and* removals fatal, two census-regression
canaries, and controls checked for polarity **and declared failure reason**.

## Layout

| path | what |
|---|---|
| `base-c10-split/`, `base-c10-fork/` | MM45 base, locally modified — see LICENSE.MM45 |
| `cdrafts-split/`, `cdrafts-fork/` | the C10 development (two certified trees) |
| `cert_gate_{split,fork}.sh` | the certification gates |
| `cert-*.tsv`, `closure-c10-*.txt` | manifests: baseline census, statement pins, controls, identity |
| `tools/` | `cert_cone.py` (census), `stmt_digest.py` (statement digests) |
| `scratch/` | control and canary fixtures **referenced by the gates only** |
| `experiments/tcollres-leg/` | on the fork gate's include path; carries three FINDING notes |

Two trees exist because route (D) splits the C10 width across two projection
members; `-split` and `-fork` are separately certified and are not
interchangeable.

## Provenance and licence

`base-c10-*` derives from [MM45/FV-SPHINCSPLUS-EC](https://github.com/MM45/FV-SPHINCSPLUS-EC)
(ASIACRYPT 2024), **MIT licensed** — see `LICENSE.MM45`, which is reproduced
here as that licence requires. Those files are **modified**: relative to
upstream, `SPHINCS_PLUS.ec` differs by ~3729 lines and `WOTS_TW_ES.ec` by ~469;
`FORS_ES.ec` is byte-identical to upstream. Everything under `cdrafts-*` is
this project's own work.

The upstream MM45 clone and the source papers are deliberately **not**
redistributed here; `PROVENANCE.md` records how to obtain them.


---

## UPDATE 2026-08-12 — what changed since the `16fe480` snapshot

Additive note, per this repo's docs convention. The sections above still describe
the artifact; these are the deltas a reader must know before quoting it.

**New certified results.**
* `cdrafts-split/GprocChargedQWired.ec` (closure member #32) —
  `EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED`, the first statement here that is
  **N2-free AND Q-wired at once**: the universal grind premise
  `exists c, predC (ThC ps ad m c)` is replaced by an explicit charged summand,
  and the unreduced tree term by three named SM-DT hardness advantages. It
  entered the closure at **zero assumption cost** (census `added=0 removed=0`,
  ledger unchanged at 242).
* `cdrafts-split/DarkSide.ec` + `DarkSideC10.ec` — the FORS+C coverage
  combinatorics, promoted and cloned at C10's `t`.
* `cdrafts-split/GprocQBound.ec` / `GprocQWired.ec` — `Q = T1+T2+T3` bounded and
  wired into the deployed quotation surface.

**A result that CLOSES a question by refutation.**
`scratch/_countermodel.ec` proves, over a **legal** clone of the abstract theory,
`Pr[ITSRC10(...)] = 1`. Therefore **no parameter-independent bound on ITSRC10 is
provable for that game as axiomatized.** This says NOTHING about the deployed
instance (which fixes `mco` at a concrete op); it is not an attack. Negative
control alongside it.

**A finding that should stop a plausible-looking research direction.**
`experiments/tcollres-leg/FINDING-def11-is-unsound-at-c10.md` — the CiC
Definition-11 (T-COLL-RES) hop is **UNSOUND at deployed C10**: Def 11 samples
`rho` uniformly per attempt, C10 deterministically enumerates a minimal counter
over a public map, so effective `|R| = 1` and the assumption is FALSE (~2^72.3
birthday, below the project's own 96-bit floor). **The deployed wallet is not
affected** — C10's WOTS layer never encodes an adversary-chosen value. This is a
proof-technique limitation, not a vulnerability. `experiments/` is included in
this snapshot specifically so this finding travels with the artifact.

**Still open, stated plainly.**
* Two `admit`s in the cone, both pinned in `cert-baseline-split.tsv` and both
  verified **non-load-bearing** for the headline: `FORS_C_TreePort.ec:1511`
  (a leaf nothing requires) and `base-c10-split/WOTS_TW_ES.ec:1513` (feeds a
  theorem the capstone never applies).
* `Pr[M.F.ITSRC10 ..]` and `Pr[M_EUF_GCMA_WOTSTWESNPRF ..]` are carried
  unreduced. Reducing the latter must NOT be done by applying the existing WOTS
  theorem — that consumes the `:1513` admit and would make it load-bearing.
* Residual Q2b (pinning `encode_msgWOTS` to the deployed digit map) is open;
  see `scratch/scope_q2b_VERDICT.md`. It is fidelity, not a security term.

**Scoping verdicts** worth reading before picking up this work:
`scratch/scope_fextractop_VERDICT.md`, `scratch/scope_q2b_VERDICT.md`,
`scratch/wots_leg_state_2026_08_12.md`, `scratch/review_2026_08_11_VERDICT.md`.

---

## UPDATE 2026-08-13 — the WOTS admit is REFUTABLE, and a charged replacement exists

Everything in this section lives in `experiments/wots-badenc/` and
`scratch/wots_admit_is_injectivity.ec`. **None of it is certified.** The gate was
re-run after this work with `INPUTS_SHA256` **byte-identical**
(`eb589cafe306046da0a5d7ba0820c7e9`, 208 OK / 0 FAIL, receipt in
`scratch/RECEIPT-gate-2026-08-13.md`), which is the measurement that this work
sits entirely outside the certified surface. Treat it as a **proposal**.

**The `:1513` admit is not merely unproven — its statement is FALSE at deployed
geometry.** `scratch/wots_admit_is_injectivity.ec` (0 admits, 0 axioms, gated
under both drivers with four graded negative controls) proves the open goal is
*equivalent* to injectivity of `encode_msgWOTS` on the constant-sum surface, and
that at C10's parameters `2^(8*n_m) = w^len * 2^127` — the encoder is
`2^127`-to-one. A single surface collision refutes **the whole five-hypothesis
lemma**, not just its subgoal, because `is_chwcoll` (`:763`) and `is_chwpre`
(`:808`) share the conjunct `BaseW.val em'.[i] < BaseW.val em.[i]`, which under a
collision is `x < x`.

**Consequence that reverses an assumed ordering: Q2b cannot be wired before the
admit is removed.** Pinning `encode_msgWOTS` to the deployed digit map would make
the base file *inconsistent-if-completed*. Checked that this is not already live:
`GprocQWired`'s `hencb` is the encode **bridge**, not the identification, so the
current artifact is consistent.

**The replacement, and it costs nothing.** `admit_free_caller_split` derives
`encode m = encode m' \/ has_chwpre ...` from the already-complete
`nhchwcoll_hchwpre` (`:1476`). The left disjunct is the `BadEnc` event. In
`experiments/wots-badenc/base/` the admit is gone and the WOTS-TW bound carries
an explicit charge instead; `experiments/wots-badenc/cd/` threads it through the
closure (**all 32 closure files build**), and
`cd/GprocQWiredWotsCharged.ec` reduces the previously-raw
`Pr[M_EUF_GCMA_WOTSTWESNPRF ..]` summand — **soundly, for the first time** —
with an anti-vacuity witness whose must-fail control is `runctlw.sh`.

**This supersedes the bullet above** that says reducing that summand "must NOT be
done by applying the existing WOTS theorem". That warning was correct while the
admit stood. The correct statement now: it must not be done by applying the
**pre-charge** theorem; the charged one is admit-free.

**Still open, and it is research rather than plumbing:** bounding
`Pr[Game4_WOTSTWES_BadEnc(..) : res /\ BadEncFlag.badenc]`. This is where +C
seed-withholding finally applies (one layer up the messages are `ThC ps ad x c`,
so `encode o ThC ps ad .` is seed-keyed) — and where a **type-level** collision
must not be mistaken for a **reachable** `ThC`/SHA-256 one. Two losslessness
obligations are also carried as premises rather than discharged.

**Retracted here:** the previous session's recommendation to spend a day on an
isolated "seed-withholding" step. There is no such step — the admitted goal is a
universal statement about a free op with no `ps` in it, so no probabilistic
argument at any layer can prove it. See
`scratch/FINDING-seed-withholding-has-no-isolated-step.md`.

### CORRECTION 2026-08-13 (same day) — the charge is a STRUCTURE, not a small number

The `UPDATE` above is accurate on every point except its implied quantity, and
the omission matters enough to fix in place rather than leave to be discovered.

**The BadEnc term is 1 at the WOTS-TW layer.**
`experiments/wots-badenc/base/BadEncCountermodel.ec` (compiles, 0 admits,
0 axioms) proves the load-bearing half: `verify_encode_transfer` shows
verification reads the message ONLY through its codeword
(`pkWOTS_from_sigWOTS` computes `em <- encode_msgWOTS m` at `:2341` and its loop
touches `em` alone), so under an encoding collision a signature for `cm` *is
already* a signature for `cm'`. The explicit adversary `A_coll` — one query,
forge by REPLAY, never touch `OC` — therefore satisfies every win conjunct.

**So the charged theorem, while TRUE, is quantitatively VACUOUS at a generic
`Adv_MEUFGCMA_WOTSTWESNPRF`: its right-hand side is >= 1.**
`cd/GprocQWiredWotsCharged.ec` inherits this. Nothing above is retracted — the
admit really is gone, the closure really does build, the reduction really is
sound — but it buys an **honest structure**, not a smaller bound.

That is the exact formal content of "MM45's WOTS-TW theorem is false at deployed
C10 geometry". The bound has to live one layer **up**, at +C, where the WOTS
message is `ThC ps ad x c` and the adversary cannot choose it freely — and it
will require a **named hardness assumption on `encode o ThC`**, not a proof. The
countermodel is what makes that assumption unavoidable rather than lazy.

**Still not an attack, and unchanged:** C10's WOTS layer never encodes an
adversary-chosen value (`sphincs-c10/src/fors.rs:265-268`). `A_coll` is a
model-level object the deployment gives nobody the ability to build.

Not yet mechanised: the `Pr[..] = 1%r` packaging (oracle losslessness plus WOTS
correctness for the honest query). Each win conjunct was checked at source
individually; what is missing is assembly, not argument.

### UPDATE 2026-08-13 (later) — `Pr[BadEnc] = 1` is now MECHANISED

The correction above said the `Pr[..] = 1%r` packaging was "not yet mechanised".
**It now is**, admit-free, in `experiments/wots-badenc/base/BadEncCountermodel.ec`:

```
lemma badenc_is_one &m :
     P cm => cm <> cm' => encode_msgWOTS cm = encode_msgWOTS cm'
  => Pr[Game4_WOTSTWES_BadEnc(A_coll).main() @ &m
         : res /\ BadEncFlag.badenc] = 1%r.
```

Compiles `RC=0`, ledger class 0. Backed by **four must-fail controls**
(`controls/Ctl{A,B,C,D}.ec`, driven by `runctl.sh`), each failing at a distinct
site: A/B/C each replace ONE hypothesis by `true` — intro arity unchanged, so the
control deletes information rather than breaking syntax — and D mutates the
conclusion to `= 0%r`.

**What made it tractable:** rather than a cross-procedure loop invariant relating
the oracle's accumulator to `verify`'s, both loops are pinned to one functional
characterisation `pkfs_fun`, so WOTS correctness for the honest query becomes
syntactic. `altx_query_computes_fun` is the oracle half; `verify_replay_valid` is
stated parameter-free so the game-level call needs no `exists*`.

**Three limits, stated because they bound what this result means:**

1. **It is CONDITIONAL and that is not closed.** `cm`, `cm'` remain free ops and
   the colliding pair is a HYPOTHESIS. The content is *"if an encoding collision
   on the constant-sum surface exists, the term is 1"* — not an unconditional 1.
   Exhibiting a **deployed-geometry** pair is still residual **Q2b**.
   Satisfiability was checked so the statement is not vacuous: `encode_msgWOTS`
   is free (`:624`), no top-level axiom of the fork constrains it, and a constant
   encoder models all three hypotheses.
2. **"Axiom-free" means none were ADDED.** The proof is relative to the ambient
   declared parameters (`ge2_len`, `ge1_c`, lossless `dpseed`/`ddgstblock`). It
   never unfolds `cf`, so it does not use `ch0`/`chS`, and it sits outside
   `section Proof_M_EUF_GCMA_WOTS_TW_ES_NPRF`, so the section-local
   `declare axiom`s are out of scope — `A_coll`'s losslessness is **proved**.
3. Only **concrete-oracle** losslessness of `A_coll` is proved. Instantiating the
   full exported charged inequality at `A_coll` would additionally want general
   `A_coll(O,OC)` losslessness. Not needed here; not done.

So the position is now mechanised end to end: **there is no bound on the BadEnc
term at the WOTS-TW layer, because it is 1.** The bound must live at +C, and will
require a named hardness assumption on `encode o ThC`. This countermodel is what
makes that assumption unavoidable rather than lazy.

**Unchanged:** not an attack. C10's WOTS layer never encodes an adversary-chosen
value (`sphincs-c10/src/fors.rs:265-268`); `A_coll` is a model-level object the
deployment gives nobody the ability to build.
