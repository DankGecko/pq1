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

### CORRECTION 2026-08-13 (third) — "seed-withholding is the lever" is REFUTED

Every `UPDATE`/`CORRECTION` above says the BadEnc bound "must live one layer up,
at +C, where seed-withholding finally applies". **The seed-withholding part is
wrong**, and it is wrong in a way that would have produced an unsound assumption.
Both external reviewers found it independently and I verified it at source:

* `WOTS_TW_ES.ec:2526` — `proc choose() : unit { O.query, OC.query }`: the
  adversary **may query the collection oracle during `choose`**.
* `O_THFC_Default.init(ps)` runs **before** `A.choose()` — `OC` is keyed with the
  real `ps` throughout.

So withholding the *value* of `ps` blocks only oracle-free **offline** computation,
which is irrelevant to a collision the adversary can obtain by querying. GPT-5.6:
*"a useful target-selection timing condition, not a hardness proof."*

**Why it matters beyond wording:** writing the +C assumption while believing
withholding is the protection yields a game whose `choose` has no `OC` — which
**under-models the real adversary**. That is a silent soundness gap, not a typo.
The real levers are per-index freshness, `dist_wgpidxs`, and `ThC`-mediation.

### Two further corrections to statements above

1. **"Only the specific deployed adversary."** Wrong. `R_int_WOTSTW` is defined
   for *every* `Adv_MEUFGCMA_WOTSC` (`WOTS_C_Interactive.ec:1753`), so a +C
   theorem can be **uniform over all admissible +C adversaries**, not merely at
   `R_top_C(F)` — a stronger statement than the one claimed above.
2. **"Quantitatively vacuous."** Overstated. `Pr[G] <= terms + Pr[bad]` is the
   Bellare–Rogaway shape and is never `< 1` for all `A`; the defect is the absence
   of a bad-event bound **at the quotation site**, not in the theorem. Likewise the
   countermodel proves probability 1 *conditional on a gated pair it does not
   construct* — the precise claim is that **the generic theory cannot supply a
   nontrivial bound**.

### The number, and what it means for expectations

`|C_T| = [x^205]((1-x^8)/(1-x))^43 = 2^114.0941`; surface fraction `2^-14.906`;
model-level birthday cost `~2^71.95` ThC evaluations. This **reproduces this
repo's own** `experiments/tcollres-leg/FINDING-def11-is-unsound-at-c10.md:50`
(`2^114.094`, `~2^72.3`) — convergent confirmation from an independent model, not
a new defect. Consequence: at `(len=43, w=8, target_sum=205)` this term is
**~2^-72-class wherever it is placed and however it is named**. Moving it does not
make it small.

**Deployed classification unchanged, and this is not an attack:** C10's WOTS layer
never encodes an adversary-chosen value (`sphincs-c10/src/fors.rs:265-268`). The
model grants a freely chosen message; the deployment does not.

### Agreed next unit

Move the paid term to the +C layer as `T-COLL-RES-ENUM(encode o ThC)` — whose
discriminator is `d <> d'` (the repo's own **B2** branch,
`experiments/tcollres-leg/Extraction.ec:66-76`), which must **not** require
`c' = grindC` (verify recomputes from the *supplied* counter) and must **keep
`OC` live during `pick`** — *and* carry the `2^71.95` figure to the headline
rather than seeking a placement that hides it.

### UPDATE 2026-08-14 — the charge is MOVED to +C. It is still not bounded.

The WOTS leg is now complete **as a structure**. In order:

1. MM45's `WOTS_TW_ES.ec:1513` admit is **false** at deployed geometry — refuted,
   not merely unproven (`scratch/wots_admit_is_injectivity.ec`).
2. Replaced by an admit-free BadEnc charge; closure rethreaded, **32/32** building.
3. That charge is **provably 1 where it sat**
   (`experiments/wots-badenc/base/BadEncCountermodel.ec`, `badenc_is_one`,
   admit-free, four must-fail controls).
4. So it was **moved**. `experiments/wots-badenc/red/BadEncStep4.ec`:

```
c <= p_tgts =>
Pr[Game4_WOTSTWES_BadEnc(R_int_WOTSTW(A)).main() @ &m : res /\ BadEncFlag.badenc]
  <= Pr[T_COLL_RES_ENUM(R_TCOLL(A), O_TCollEnum_Default, FC.O_THFC_Default).main() @ &m : res]
```

uniform over **every** `A : Adv_MEUFGCMA_WOTSC` — not one instantiation — because
`R_int_WOTSTW` is generic (`WOTS_C_Interactive.ec:1753`).

**The simulation is perfect, and the one real divergence is provably invisible
rather than argued away:** the `FC.O_THFC_Default.tws` transcript differs, but
`get_tweaks` is not in `Adv_MEUFGCMA_WOTSC.choose`'s allowed set
(`WOTS_C_Scheme.ec:142`) and `OC.query` never reads `tws`. It is deliberately
absent from every invariant and deliberately **not** given a control — a control
on an invisible divergence compiles green and means nothing.

**Fifteen must-fail controls** across the three files, all `RC=1`, none producing
a `.eco`. One (`S4CtlG`) is a *necessity control on a proof step*, flagged as such:
the other step-4 controls all fail **inside** `s4_transfer`, so if the closing
`smt()` could discharge the residual without that lemma, they would say nothing
about the bound. It cannot.

**A structural correction found during the build:** the two-term shape
(B1 → S-TCR(+C), B2 → T_COLL) is **wrong at this boundary**. Under
`R_int_WOTSTW`, `forge` returns a `ThC` value (`:1813`), so Game 4's
`is_fresh <- m' <> m` already *is* `dg <> dg'` — the B2 condition. A B1 run makes
`res` false, so charging B1 would add a term that cannot occur, i.e. a weakening.
B1 is charged one layer up, where `WOTS_C_Interactive` already does
`Pr[mu_split (G0_INT.coll)] -> S_TCR_C_Int`. *(Not to be conflated with
`B2_is_empty`, the encoder-bridge question, which is wide open — it is the reason
`T_COLL_RES_ENUM` exists at all.)*

### WHAT IS STILL NOT TRUE

* **Nothing bounds `Pr[T_COLL_RES_ENUM]`.** The term went from provably-1 at the
  wrong layer to an **unbounded assumption at the right layer**. That is the
  entire delta. It is a structure, not a number.
* `T_COLL_RES_ENUM` carries **no disjointness conjunct**, so its win set is larger
  than the S-TCR(+C) template's and the assumption is correspondingly **stronger**.
* At `(len=43, w=8, target_sum=205)` the expectation remains **~2^-72-class**
  (`|C_T| = 2^114.0941`, birthday `~2^71.95`) — a **parameter** property that no
  placement or naming changes.
* `c <= p_tgts` is a premise, not free — though not a new demand:
  `WOTS_C_Interactive.ec:1350` already states it and `interactive_hop1` carries it.

**Still not an attack, unchanged:** C10's WOTS layer never encodes an
adversary-chosen value (`sphincs-c10/src/fors.rs:265-268`).

**Still outside the certified surface.** The gate has now run **three times
byte-identical** (`INPUTS_SHA256 eb589cafe306046da0a5d7ba0820c7e9`, receipts in
`scratch/RECEIPT-gate-2026-08-1{3,3b,4}.md`). This whole development is a
**proposal**; promoting it would be a deliberate decision to move that hash.

### CONCLUSION 2026-08-14 — `Pr[T_COLL_RES_ENUM]` cannot be usefully bounded

The obvious next question after moving the charge is "how big is the new term?".
**There is no bound to find**, and the reason is a **parameter fact**, not a proof
gap. Full argument in `scratch/FINDING-tcollres-cannot-be-bounded.md`.

`T_COLL_RES_ENUM` is a hardness **assumption**. Reducing it to a standard THF
assumption is closed off: the **B2** branch — distinct digests, equal codewords —
is exactly what S-TCR(+C) does not cover, which is why the game exists at all, so
a reduction would be circular. The only quantitative statement available is the
cost of the best generic attack:

```
|C_T| = [x^205]((1-x^8)/(1-x))^43 = 2^114.0941
surface fraction = 2^-14.9059
birthday        ~ 2^71.95 ThC evaluations   (memoryless, van Oorschot–Wiener)
```

**No proof can bound an advantage below its best generic attack**, so this term is
~2^-72-class at deployed parameters and no placement, naming, or extra hypothesis
changes it. Reproduced independently twice — by an external model from source
alone, and by this repo's own
`experiments/tcollres-leg/FINDING-def11-is-unsound-at-c10.md:50`.

**Stated carefully.** `tools/forsc_grinding_margin.py:143` sets
`WORK_FLOOR_BITS = 96`, so this leg sits ~24 bits below it. That is a statement
about **the WOTS leg's proof term** — not a claim that the product has 72-bit
security. This repo's own finding warns that two different "96"s exist here
(`:128-129`); do not conflate them.

**Not an attack, and not a false assumption.** C10's WOTS layer never encodes an
adversary-chosen value (`sphincs-c10/src/fors.rs:265-268`): the birthday adversary
needs a freely chosen message, which the **model** grants and the **deployment**
does not. And the assumption is not false — it simply cannot be assumed above its
generic attack.

**What the WOTS track therefore bought:** the obstruction is now *located*. The
`:1513` admit is gone; its replacement charge is provably 1 at the WOTS-TW layer,
so it could never have been bounded there; it is moved uniformly over all +C
adversaries to a named assumption at the keyed-digest layer; and that
assumption's generic attack is computed exactly. **The obstruction is
`(len=43, w=8, target_sum=205)` — a parameter choice, not a missing lemma.**

**The only honest next units:** machine-check the count (nothing in EasyCrypt
states `2^114.0941` today — feasibility unmeasured); carry the figure to the
headline in the `forsc_grinding_margin.py` genre; and a **parameter conversation,
which is an owner decision** — changing `(len, w, target_sum)` changes
`sig = 4008`, the on-chain verifier, and every KAT. Do not spend further effort
trying to prove a bound on this term.

### UPDATE 2026-08-14 (later) — the surface count is now a THEOREM

The `CONCLUSION` above rests on `|C_T| = 2^114.0941`, which until now existed only
as Python plus prose. It is now machine-checked, admit-free, in
`experiments/wots-badenc/count/`:

```
lemma c10_surface_count :
  count_ds 43 8 205 = 22169393903687611906220091621190388.
```

plus the security-relevant integer corollaries `2^114 < count < 2^115` and
`count * 2^14 < 8^43 < count * 2^15` (i.e. `2^-15 < p < 2^-14`, stated over
integers, no reals).

**Feasibility was the open question and the answer is yes** — EasyCrypt evaluates
the 43-step reduction in **41 s**. `iota_`/`iteri` are axiomatised so `simplify`
cannot touch them, and `smt()` on `2^114 = <literal>` fails after 27 s; but
*structural* list recursion over int literals does reduce, so `VecDP.ec` restates
the DP in an accumulator-free sliding-window orientation and `CountDS.ec` proves
the bridge. Measured scaling: 10 steps 0.58 s, 20 → 3.3 s, 30 → 11.9 s, 43 → 41.1 s.

**`count_ds` is a genuine recursion**, `iter n (cstep b) (fun t => b2i (t = 0)) s`
— the constant appears only in lemma statements, never in a definition. Eight
controls; the two perturbations (`205 → 204`, `43 → 42`) each fail **at their own
`ctl_*` lemma rather than at the kernel lemma above it**, so the perturbed
reduction genuinely ran and only the unperturbed constant was rejected. The
constant is independently cross-checked four ways (DP, inclusion–exclusion, direct
polynomial multiplication, and the complement symmetry
`count(43,8,205) = count(43,8,96)` — the last also checked inside EasyCrypt).

**Reusable trap, recorded:** the reduction is asymmetric. A true 43-step equation
reduces in 41 s; a false one at the same scale exhausts the stack (435 s under
unlimited stack). Any `trivial`-invoking tactic (`by`, `//`, `smt`) on a goal
still holding the unreduced term re-runs the whole 41 s reduction, and `apply`
did not terminate in 120 s. **`c10_surface_count` is rewrite-only.**

### THE BOUNDARY — this counts DIGIT VECTORS, not codewords

Stated because the distinction is exactly the one that has bitten this repo
before. The theorem is over `int` lists with entries in `[0,8)`; connecting it to
`emsgWOTS` is **not done**, and five specific blockers stand in the way:

1. `WOTS_TW_ES.ec:74` `const len : {int | 2 <= len}` is not linked to `c10_len = 43`;
2. `val_w : 4 <= w` is not linked to `c10_w = 8`, and `BaseW.val` is not shown to
   range bijectively over `[0,8)`;
3. `WOTS_TW_ES.ec:647` **defines** `target_sum = digitsum (encode_msgWOTS tgt_witness)`,
   not 205 — and `C10DeployedGeometry.ec:101-104` explicitly declines the claim
   that the deployed encoder reaches 205;
4. there is no `emsgWOTS <-> int list` bijection (needs FinType/`Alphabet.enum`
   plumbing plus `digitsum = sumz`);
5. surface ≠ fibre: `|C_T|` counts codewords, while `T_COLL_RES_ENUM`'s B2 branch
   is about *messages* colliding through `encode_msgWOTS`.

**The number is now a theorem; its identification with the codeword surface is
still prose.** Likewise `~2^71.95` remains unmechanised — it needs `sqrt` over
reals; what is mechanised are the two integer facts it is computed from.

---

## CORRECTION 2026-08-14 (final) — BOTH claims above were wrong, in opposite directions

Two external reviewers, asked independently with C10's parameters frozen,
**converged on refuting a premise this README has repeated all along** and
**diverged on the number** — and the divergence is where the information was.
Everything below verified at source. Full write-up:
`scratch/FINDING-both-my-claims-were-wrong.md`.

### (1) "The deployment never lets the adversary choose the WOTS message" is FALSE

This sentence carries the *"not an attack"* classification above, and it is
inherited from `experiments/tcollres-leg/FINDING-def11-is-unsound-at-c10.md`,
which reasoned that `compute_fors_pk` takes no message argument.

`compute_fors_pk` takes no *message* argument — but **its `roots` argument is
attacker-supplied at verification.** In `sphincs-c10/src/hypertree.rs`:

```
fors_secrets ← read from the signature        (attacker-supplied)
auth_paths   ← read from the signature        (attacker-supplied)
fors_roots   ← reconstruct_fors_root(...)
fors_pk      ← compute_fors_pk(seed, ht_idx, fors_roots)
current_node ← fors_pk                        ← THE WOTS MESSAGE
wots_pk      ← pk_from_sig(..., &current_node, &wots_sigma, count)
```

Nothing validates those secrets before `fors_pk` is formed, and `count` is also
read from the signature. The honest-*signer* statement is true
(`fors.rs:265-268`) and **does not transfer to the verifier** — and the forgery
game is about the verifier. So "WOTS messages are key-determined" is not merely
unproven, it is **provably false at source**.

### (2) But "cannot be usefully bounded, ~2^-72" is ALSO wrong — too PESSIMISTIC

`2^71.95 = 2^57.05 × 2^14.906`, and the second factor is the cost of landing one
sample on the constant-sum surface — which **the oracle pays**
(`ctr <- grindC ps ad m`), not the adversary. So it is **2^57 oracle queries**,
not 2^72 of adversary work.

And a free offline birthday **does not win**: the win condition reads
`(ad,m,ctr,dg,e) <@ O.get(i)` with `0 <= i < nrts`, so **one side of the collision
must be a RECORDED entry**. Colliding two of your own samples wins nothing. It is
a *target search*.

| side | cost |
|---|---|
| query | advantage `q_s² · 2^-114.09`; at the deployed cap `q_s = 2^16` → **2^-82** |
| offline | `2^114.09 / n_ad`; multi-target amplification **dies on address-keying** |

`R` is derived from `sk_seed` (`fors.rs:94-131`), so honest signings cannot be
steered onto one address; even adversary-favourable `n_ad = 2^16` gives **2^98**.

**So the leg's honest ceiling is ~2^98–2^114 work, or 2^-82 at the deployed query
cap — at or ABOVE the 96-bit work floor, not 24 bits below it.** The
`CONCLUSION` section's *"there is no bound to find; do not spend further effort"*
is **RETRACTED**: it priced an attack the query budget forbids.

### The leg is fine — but for the OPPOSITE reason to the one given above

The constraint is not on the *message* side (that freedom is real). It is on the
**target** side: the collision must involve an honestly-signed, address-bound
entry, and those are capped and scattered.

### THE ACTION ITEM — `p_tgts` is unpinned

The entire `2^-82` rests on instantiating `p_tgts` at the deployed usage cap.
**VERIFIED:** `cdrafts-split/WOTS_C_Real.ec:340` —
`const p_tgts : { int | 0 <= p_tgts } as ge0_ptgts` — it is abstract, exactly like
`target_sum`. **Quoting 2^-82 without pinning it would be unfounded.** Target shape,
parameters frozen:

```
for q_s <= 2^16 signing queries and q_h hash queries,
  Adv_T-COLL-RES-ENUM  <=  (q_s^2 + q_h * n_ad_max) * 2^-114.09
```

with `2^-114.09` already machine-checked (`experiments/wots-badenc/count/`).

### Limits — this is NOT a clean bill of health

The `q_s²` and `2^114.09 / n_ad` figures are **generic-model arithmetic, not
theorems** — the same epistemic class as the ITSR margin table. `n_ad_max` is
established nowhere; "honest signings scatter" is an argument about `grind_r`, not
a proved bound. The `ThC`-width question (128 vs 129) sits underneath this term and
shifts the constant. The honest summary is that **the leg's ceiling is set by the
target budget, and that budget has never been pinned.**

### UPDATE 2026-08-15 — `p_tgts` pinned; and the `2^-82` figure is STILL not quotable

`experiments/ptgts-pin/`. The correction above named pinning `p_tgts` as the action
item that would make `2^-82` quotable. **That was wrong**, and the pinning work is
what shows why.

**`c = 262656 = 2^18 + 2^9`, unconditionally.** The hypertree geometry is already
axiomatised in `base-c10-split/SPHINCS_PLUS.ec` (`hp_val : h' = 9`, `d_val : d = 2`),
so no hypothesis is needed. Confirmed against `sphincs-c10/src/params.rs`
(H=18, D=2, SUBTREE_H=9) and `hypertree.rs:23`. `p_tgts` is pinned at `262656`, the
**least** admissible value, and `c <= p_tgts` is discharged in a capstone whose
statement is machine-diffed against `cdrafts-split/C10DeployedCapstone.ec:280-394`
by a self-tested script. Twelve controls; off-by-one **brackets the pin from both
sides** (`262657` passes, `262655` fails).

**Why `2^-82` is still not quotable:**

* it needs `q_s = 2^16` **signing** queries — that is `MAX_SLOT_USES`, an on-chain
  **deployment policy** bound, and **nothing in the model expresses it**;
* `p_tgts` caps S-TCR **targets**; the model's query cap is `c`, which is larger.
  Substituting gives **`c² · 2^-114.09 = 2^-78.09`**, not `2^-82`;
* pinning `p_tgts := 2^16` is wrong twice — `65536 < 262656` fails the premise
  (proved: `c10_usage_cap_is_not_admissible_as_p_tgts`), and it would cap the
  reduction's targets *below what it places*, making the S-TCR win condition FALSE.

Also corrected: the two caps are **~2 bits apart, not ~4**
(`c/q_s = 4.0078 → 2.0028` bits). The `4.006` figure is the **squared** gap —
right for a `q_s²`-shaped term, wrong as a statement about the caps themselves.

**The premise is TRADED, not eliminated:** `c <= p_tgts` becomes
`p_tgts = c10_p_tgts`. Making it unconditional requires
`op p_tgts : int = 262656` in `cdrafts-split/WOTS_C_Real.ec`, which moves
`INPUTS_SHA256` and needs a `cert-identity.tsv` re-baseline — deliberately out of
scope here.

### A separate finding surfaced by the pin: `WOTS_C_Multi` is outside the certified perimeter

**VERIFIED:** `WOTS_C_Multi` appears in **neither** `closure-c10-split.txt` **nor**
any of the four `cert-*.tsv`. No certified run compiles it. The bridging step
"one target per committed query" — which is what gives `c <= p_tgts` its *shape* —
lives at `WOTS_C_Multi.ec:490-494`. So that premise's **justification** sits on a
file the gate never builds, even though its **satisfaction** is now pinned. Same
defect class as the stale `experiments/` files, but inside the premise structure of
the deployed statement.

**What `2^-82` would still need:** an argument that the term counts *signing
queries* rather than hypertree instances, and the `2^16` policy bound imported into
the model. Neither exists.

### CONCLUSION 2026-08-18 — do NOT import the deployment cap, and withdraw the numbers

Asked both external reviewers whether importing `MAX_SLOT_USES` into the model is
right. **Both said no.** Full write-up:
`scratch/FINDING-do-not-import-the-policy-cap.md`.

**The objection that invalidates the whole numeric thread:** *a surface cardinality
does not prove that `Pr[T_COLL_RES_ENUM]` is bounded by a birthday expression.*
`q²/|C_T|` is **not** obtained by counting `|C_T|`. Turning a surface size into an
advantage needs an explicit assumption about how `ThC` images behave against an
adversary holding the keyed oracle and choosing its own counter — and
`TCollResEnum.ec` says outright that nothing bounds it.

**So `2^-82` and `2^-78.09` are WITHDRAWN.** They were heuristic estimates on a
model that was never derived. `"clears the 96 floor"` is withdrawn too: that floor
is a **query-work** floor, `2^-82` is an **advantage**, and
`tools/forsc_grinding_margin.py` carries an F3 correction that exists *because a
previous version made exactly this conflation*.

**And the term is not in the certified statement at all.** VERIFIED: `grep -rn
T_COLL_RES_ENUM cdrafts-split/ base-c10-split/` returns nothing; the certified
capstone RHS (`SphincsC10CapstoneWired.ec:595-604`) carries four other terms.

**The query count fails independently.** VERIFIED on the live closure member
(`XmssmtCC_All.ec:752`): `R_MEUFGCMAWOTSC_EUFNAGCMA_C.choose` computes and stores
**all** WOTS+C public keys — it is **eager**, so `nrts = c = 262656` regardless of
how many signatures the deployment makes. `q_s = 2^16` is wrong and `2·q_s` equally
unsupported; a `q_s`-shaped bound needs an **on-demand reduction**, a rebuild.

*(One reviewer cited a `_wip` file for this, absent from the closure and all four
`cert-*.tsv` — the same non-certified-draft trap `Extraction.ec` sets. The live file
was checked instead. Note the live `R_int_WOTSTW.choose` is by contrast **lazy**:
the eagerness is at the hypertree layer, not the WOTS one.)*

**A reviewer corrected itself, and I had over-recorded it.** A partial (killed) run
called `MAX_SLOT_USES` a "mutable governance parameter"; its completed run withdrew
that. VERIFIED: `PQSmartWallet.sol:71` is a compile-time `constant` with no setter,
consistent with invariant #7 and Rust↔Solidity drift-gated. What survives is weaker
— an imported cap would still rest on the on-chain check and the firmware gate,
both outside EasyCrypt's TCB.

### The honest position on this leg

`Pr[T_COLL_RES_ENUM]` is an **unbounded assumption**; the surface count is a
**theorem**; **no derivation connects them**. What the work bought is precision
about where the ignorance sits — not security.

**Still open, and it is a design-intent question rather than a proof task:** whether
the overall EUF-CMA statement is meant to cover **bootstrap-signed Type-1
authorisations**. If it is, the target-side argument does not apply to the bootstrap
key, which has no device-side cap.

### UPDATE 2026-08-18 (later) — a file ENTERS the certified closure; and the next link in its chain is RED

> **:warning: READ THE CORRECTION AT THE END OF THIS FILE BEFORE §1 BELOW.** The
> *rationale* given in §1 — that gating `WOTS_C_Multi` brought a certified premise's
> justification inside the gate — is **retracted**: the certified capstone does not
> consume D.1 at all. The **mechanics** in §1 (RED -> GREEN, ledger unchanged at
> 242, census additions zero) stand, as do §2-§4.

Two things happened, and the second is the more important one.

#### 1. `WOTS_C_Multi.ec` is now GATED — deliberate re-baseline, ledger UNCHANGED

`c <= p_tgts` is a premise carried by **11 of the closure members, in 48 places**.
The lemma that justifies its *shape* — `D1_reduce` ("the reduction places one
S-TCR(+C) target per committed query", `cdrafts-split/WOTS_C_Multi.ec:523`) — lived
in a file that was in **neither** `closure-c10-split.txt` **nor** any `cert-*.tsv`.
**The gate had never built it.** Write-up:
`scratch/FINDING-c-le-ptgts-justification-is-ungated.md`.

It compiles clean and is zero-admit, so gating it is a strict improvement. Done:
closure `32 -> 33`, `CONE_FILES 43 -> 44`,
`INPUTS_SHA256 eb589caf... -> 45b788a6...`, with the mandatory `cert-identity.tsv`
RE-BASELINE LOG entry.

**Both runs are vendored, and the RED one is the point.** The gate was run *before*
updating the baseline, and it correctly refused the change:

```
scratch/gate_run1_wcm.log   RED (2 failures)
  FAIL INPUTS_SHA256 DRIFT: committed eb589caf..., computed 2af7b788...
  cone: keys now=1113 baseline=1099 | ROWS now=1193 baseline=1179 | added=14
  FAIL cone census GREW -- 14 new rows, ALL from cdrafts-split/WOTS_C_Multi.ec

scratch/gate_run2_wcm.log   GREEN at 45b788a6...
  cone: keys now=1113 baseline=1113 | ROWS now=1193 baseline=1193 | added=0
  ledger=242 (UNCHANGED)   statements pinned=111/111
```

**All 14 added rows are `module` / `module-type` class. The ledger — admits,
axioms, clone-discharges — stayed at 242.** Adding a proof file added zero
assumptions. That is what "ADDITIONS ARE FATAL" is for: it made a deliberate,
reviewable change impossible to make silently.

#### 2. RETRACTION — "`D1_bridge_WOTSTW` does not exist" was FALSE

The finding above originally reported that `WOTS_C_Multi.ec`'s header describes two
bridge artefacts the tree does not contain, and marked it **VERIFIED**. It is wrong.
`D1_bridge_WOTSTW` is at `cdrafts-split/WOTS_C_Bridge.ec:433` — **the same
directory**. The name was searched for *inside `WOTS_C_Multi.ec`* and its absence
**there** reported as absence from the repo: `absence-from-the-wrong-scope`, an error
class this file's own log already records twice.

The chain does exist: `D1_bridge_WOTSTW` (`:433`) -> `D1_MEUFNACMA_WOTSC_MM45`
(`:719`) -> `..._embthfc` (`WOTS_C_EmbDischarge.ec:174`) -> consumed at
`SPHINCS_C.ec:252`.

*(Process note worth keeping: a delegated agent was briefed to write the "does not
exist" sentence into a cone file and **refused**, having checked. Had it complied, a
new false claim would have been installed in the tree.)*

#### 3. THE FINDING THAT REPLACES IT — `WOTS_C_Bridge.ec` does not compile, and says it does

**Measured at r2026.02, in-container.** The terminal
`by rewrite hoq; do ! split; smt().` of the `disj_wgpidxs` bookkeeping step — inside
`D1_bridge_WOTSTW`'s own proof — fails `cannot prove goal (strict)`, `__RC=1`, no
`.eco`. Its header claimed, since 2026-07-08:

> `PROOF STATUS (2026-07-08): PROVED IN FULL — ZERO admits.`

**It is not a prover-budget artefact.** Re-run with `-timeout 120 -max-provers 8` it
fails at the same tactic with the same error after **2592 s**. Receipts:
`experiments/wots-badenc/bridge.out`, `bridge_timeout.out`.

**Indicated cause, not demonstrated:** `fe2b22f` (2026-08-01) retyped the
non-certified side-files for route (D) the same day `msgWOTS` widened to
`mdgstblock` (`ea1087f`). The retype restored **type**-correctness; nothing
re-checked **provability**, because the gate never builds this file.
`WOTS_C_Multi.ec` went through the same retype in the same commit and **does**
compile. No pre-split checkout was reconstructed. Full diagnosis:
`scratch/FINDING-wots-c-bridge-is-genuinely-broken.md`.

**What is NOT claimed:** that the goal is false (`smt` failing is not a refutation),
or that anything certified is affected. `WOTS_C_Bridge`, `WOTS_C_EmbDischarge` and
`SPHINCS_C` are all outside the closure; the gate is GREEN at `45b788a6...` without
them. **"ZERO admits" also remains true** — there is no `admit`/`sorry`/`axiom` in
the file. It does not *admit* the goal, it *fails to close* it. What was false is
"PROVED IN FULL".

The header is now corrected in place with a dated additive note (comments only —
proven, not asserted: a comment-stripper was first shown to **detect** a mutated
`smt()` call, then shown the before/after stripped text is byte-identical).
**The file is deliberately NOT gated**: adding a red file to the closure turns the
gate red by construction.

#### 4. And the two receipts disagree on the line number — on purpose

`bridge_timeout.out` prints `:659`, `bridge.out` prints `:693`. They are runs on
**different versions of the file**: the 39-line correction note sits above the
failing tactic and shifted it. Same tactic, same error, same step. Both the note and
the finding now carry the file state per receipt.

**And it happened again at vendoring time.** Every `file:line` in this section was
re-measured against the snapshot before publishing, and **four of them were stale** —
`D1_reduce` (`:488` -> `:523`), `D1_bridge_WOTSTW` (`:391` -> `:433`),
`D1_MEUFNACMA_WOTSC_MM45` (`:677` -> `:719`), and the `WOTS_C_Reduction` span. The
correction note's own 39 lines had moved two of them. A fifth citation was nearly
dropped as fabricated because a `grep` for its exact phrase found nothing — the
phrase wraps across two lines in the source; opening the file showed the quote is
genuine (`WOTS_C_Reduction.ec:341-344`). All line numbers here are anchored to **this
frozen snapshot**, which is the only reason they can be trusted at all.

This is the **third** time in this one correction that a line reference went stale
under its own edit — the first two being the note citing `:659` after itself moving
it to `:693`, and the note's closing line still saying "until `:659` is repaired".
Everything is now anchored on tactic text. It is a small thing that keeps recurring,
which is the reason it is written down rather than quietly fixed.

#### What this does and does not do for `c <= p_tgts`

**Does:** the lemma giving the premise its shape is now inside the gate, so it cannot
silently rot the way `WOTS_C_Bridge` did.

**Does not:** `D1_reduce` is stated over `STCRC_WC.Col`, while the certified chain
runs over `FC`. `WOTS_C_Reduction.ec:341-344` calls unifying them "the remaining
structural reconciliation", and the bridge that would connect them is the file that
does not currently compile. The premise remains **carried, not discharged** — which
is what the certified statements already say, and they are right to.

**Known gap in the new gating, stated plainly:** the gate proves `D1_reduce`
**compiles**; it does not yet pin its **statement**, so it does not prove the lemma
still *says* `c <= p_tgts`. Closing that means `EXPECT_PINS 111 -> 113` in
`cert_gate_split.sh`. Deliberately not done in this change — a pin on the first link
of a chain whose second link is red would read as more assurance than it is.

### CORRECTION 2026-08-18 (same day) — the certified capstone does NOT consume D.1

Raised by GPT-5.6 in the review round on the section immediately above, and
**re-verified independently at source before being accepted**, because it
contradicts a claim published minutes earlier. Full write-up:
`scratch/FINDING-d1-is-not-the-certified-route.md`.

**What was published:** *"the lemma that justifies [`c <= p_tgts`]'s shape —
`D1_reduce` — lived in a file the gate had never built."* The factual half is
right; the **inference is wrong**, and it is the part that made the change sound
load-bearing.

**VERIFIED.** The capstone discharges the hypertree term by applying the +C
component theorem *directly* —
`SphincsC10CapstoneWired.ec:624`,
`have hHT := EUFNAGCMA_FLSLXMSSMTTWCESNPRF (R_top_C(F)) ...`. The token `D1_`
occurs in that file **exactly once**, in a comment (`:548`), and that comment names
the route actually taken: *"Carried from **`interactive_D1_MA`** up through
`XmssmtCC_All` to here."*

**`interactive_D1_MA` is `WOTS_C_Interactive.ec:3193`, and that file has been IN the
closure all along.** It carries `c <= p_tgts` itself (`:3197`), and the "one target
per query" rationale is stated in the same gated file (`:1350`). Every one of the 11
premise-carrying files is on that interactive route.

**The two developments are parallel, not sequential:**

```
CERTIFIED:  interactive_D1_MA (WOTS_C_Interactive, GATED)
              -> XmssmtCC_All -> SphincsC10CapstoneWired          [GREEN]

PAPER D.1:  D1_reduce -> D1_MEUFNACMA_WOTSC (WOTS_C_Multi, now gated)
              -> D1_bridge_WOTSTW (WOTS_C_Bridge)                 [RED]
              -> WOTS_C_EmbDischarge -> SPHINCS_C                 [ungated]
```

The D.1 chain is a **second, independent assembly of the same leg** (paper 2022/778
App. D). The capstone depends on none of it — which is the real reason the red bridge
costs the certified artifact nothing. That conclusion was stated correctly above; the
*reason* given for it was wrong.

**What the re-baseline actually bought — narrower, but real:** a compiling,
zero-admit file is now inside the gate and cannot rot silently the way
`WOTS_C_Bridge` did. It did **not** bring the certified premise's justification
inside the gate; that was never outside it.

**And a sharper point survives both versions:** *neither* route discharges
`c <= p_tgts`. Both carry it as a hypothesis. "The lemma that justifies its shape"
was the wrong phrase for `D1_reduce` to begin with — `D1_reduce` **uses** the
premise, it does not establish it.

**The framing error, named:** a premise was found in 11 certified files, a lemma
elsewhere was found mentioning the same premise, and the second was concluded to
justify the first — **without checking whether the certified chain reaches it**. A
name-level match read as a dependency. One `grep` of the capstone for `D1_` settles
it. Same family as `absence-from-the-wrong-scope`, inverted: **presence in the wrong
scope, read as relevance.**

**Effect on the deferred `EXPECT_PINS 111 -> 113`:** weaker still. The chain those
pins would protect is not the certified one, so they are drift-hardening on a
**supplemental** development and must be labelled as such if ever added.

### UPDATE 2026-08-18 — the certified statement is ROLE-AGNOSTIC, and no key is named in it

> **:white_check_mark: PARTLY RESOLVED 2026-08-19 — see the final section of this
> file.** The finding below that *"the scope restriction is written down nowhere in
> the EasyCrypt"* was true when written; those facts are now **gated** as
> `cdrafts-split/C10DeployedScope.ec` with six statement pins. Still open, and
> still yours to decide: the instantiation contract naming which key a quoted
> figure applies to.

The open question flagged at the end of the 2026-08-15 update — *does the overall
EUF-CMA statement cover bootstrap-signed Type-1 authorisations?* — is answered.
Full write-up: `scratch/FINDING-bootstrap-scope-is-unwritten.md`.

**It covers them, and that is the problem.** VERIFIED:

```
cdrafts-split/FxChain.ec:255
  module EUFCMA_C10 (F : Adv_EUFCMA_C) =
    DSSC.Stateless.EUF_CMA(SPHINCS_PLUS_C10, F, DSSC.Stateless.O_CMA_Default).
```

The textbook **single-key stateless EUF-CMA game** — one keypair, one adversary, one
signing oracle, and no chain, owner index, wallet, role, or per-key counter anywhere
in it. So the theorem is not slot-only: it applies verbatim to the bootstrap key, and
an adversary collecting `C · 2^16` Type-1 signatures across `C` chains is just *an
adversary in the same game*. **No carried term becomes unsound.**

**And `c` / `p_tgts` were never the signature count** — an error corrected here.
`WOTS_C_Real.ec:41` defines `c` as the **structural** WOTS-TW instance count of the
hypertree (`bigi predT (fun d' => nr_nodes_ht d' 0) 0 d`), which is why it pins
unconditionally at `262656`. `c <= p_tgts` is a reduction-side **target** cap, not a
bound on how many messages a wallet key may sign.

**What actually degrades is the NUMBER.** The generic multi-target contribution is
`(q + q²)·2⁻¹²⁸`, so at `q = C·2^16` the floor is `96 − 2·log₂ C` bits — below 96 as
soon as `C > 1`. The project's own Lean already tabulates this
(`Quantitative.lean:193-210`) and notes there is **no on-chain cap on the number of
chains**.

**THE FINDING — the scope restriction is written down nowhere in the EasyCrypt.**
Checked as an absence claim by searching the *mechanism*: all 33 closure members for
`bootstrap|chain_id|chainid|slot_index|65536|MAX_SLOT|per-chain|wallet`. **Exactly two
hits, both comments, neither a statement** — and the second
(`FORS_C10.ec:87`) is the one place in the certified closure where the deployment cap
appears in a quantitative argument, using the **per-chain `2^16`**: the exact number
that does not apply to the bootstrap key. It is prose justifying a rejected route, so
it moves no theorem — but it is a certified file reasoning from a per-chain cap.

**This is a documentation/scope question, not a proof task.** A second EUF-CMA
theorem "for the bootstrap key" would be the same theorem. What is missing is an
explicit instantiation contract: slot keys instantiate `q` with their capped per-key
count; the bootstrap key instantiates `q` with the **aggregate across every chain
sharing it**; and every quoted bit-figure names which of the two it used. Proving
that mapping is a real project — the Lean file records that even the single-chain
`Reachable -> q <= C` theorem is not assembled (`Quantitative.lean:87-95`).

**Owner decision required:** state the instantiation contract, or restrict the quoted
figures to slot keys explicitly. Realistic bootstrap usage is tens of signatures
(slot rotations only), so practical exposure is far below any of this — but practical
exposure is not what a security claim states, and the claim currently names no key.

### UPDATE 2026-08-18 (round 2) — the two reviewers DIVERGE, and the sharper answer wins

Both models were asked the bootstrap-scope question independently. They **converge**
on the verdict and **diverge on the mechanism**, which is the whole reason for running
two. Full write-up: `scratch/FINDING-round2-divergence-none-of-the-terms.md`;
transcript `scratch/review_kimi_bootstrap_scope_2026_08_18.md`.

| | claim |
|---|---|
| GPT-5.6 | "the directly affected generic multi-target term is `S_TCR_C_Int_MA`; its quadratic component degrades to `96 − 2⌈log₂ C⌉`" |
| Kimi K3 | "**none** of the four terms degrades, by nothing — the model has no signing-query parameter at all" |

**Kimi is right.** VERIFIED: the four carried terms appear in the capstone RHS
(`:595-604`) with **coefficient 1 and no query factor** — bare `Pr[...]` summands;
same in the component theorem (`XmssmtCC_All.ec:8583-8592`). Query counts enter only
as win-condition caps keyed to **hypertree geometry**, not adversary behaviour. GPT
mapped the EasyCrypt term onto Lean's `(q + q²)·2⁻¹²⁸` arithmetic for the *same
assumption* — two different objects. **Nothing in the certified artifact prices `q`.**

So the correct statement is not "the certificate is silently weaker for the bootstrap
key" but **"the certificate is silent, full stop"** — all cross-chain degradation
lives outside it. (The section above already said the number degrades rather than a
term; this sharpens *why*.)

**Three facts the round produced that were not in hand, all verified here:**

1. **A hard structural ceiling that `C · 65536` crosses at C = 4.**
   `FL_SL_XMSS_MT_ES.ec:73` `const l : int = 2 ^ h` with `h = h'·d = 18`
   (`SPHINCS_PLUS.ec:124`), so `l = 2^18 = 262144` messages — the capacity of the
   hypertree game itself. Not a probability claim; the model's geometry. Practically
   irrelevant (real bootstrap use is tens of signatures) but a crisp boundary where
   the discussion previously had only soft arithmetic.

2. **`c <= p_tgts` is ALREADY PINNED where it is load-bearing.** The capstone
   statement is pinned (`cert-statements-split.tsv:3`) and
   `tools/stmt_digest.py:108-113` digests from `^lemma <name>` to `^\s*proof\b` —
   **premises included**. This deflates the deferred `EXPECT_PINS 111 -> 113` a third
   time: not merely on the wrong (supplemental) chain, it **duplicates existing
   protection**. Kimi also caught that the digest's negative lookahead
   `(?![A-Za-z0-9_'])` means a pin on `D1_MEUFNACMA_WOTSC` would not match
   `D1_MEUFNACMA_WOTSC_MM45`; correct targets are `WOTS_C_Multi.ec:523` and `:951`.

3. **The unbounded-query evidence was outside the repo, and I had searched the repo.**
   `DigitalSignatures.eca` is an EasyCrypt **stdlib** theory in the opam switch —
   `~/.opam/checkct/lib/easycrypt/theories/crypto/DigitalSignatures.eca:1335`: *"access
   to a signing oracle that it can query an **unlimited** number of times"*, with
   `O_CMA_Default` keeping a query list as a counter, not a cap. Q1(a) now rests on
   source rather than inference. **That is `absence-from-the-wrong-scope` for the
   fourth time in one day** — this time searching the project tree for a file that
   lives in the toolchain's library path.

**THE BETTER NEXT UNIT (Kimi's, and better than anything on my list): pin the
NEGATIVE scope facts.** `experiments/ptgts-pin/PTgtsPin.ec` already proves them and
already compiles (Kimi compile-tested: RC=0, ~2 s) — `c = 262656`, `! (c <= 65536)`,
`l = 2^18` — and its own prose already says *"nothing in this model expresses the
on-chain 2^16 cap"*. Promoting a cleaned version into the closure with statement pins
turns the finding *"the scope restriction is written nowhere"* from a README paragraph
into a **machine-checked, gated artifact**. It is the only candidate that changes what
can be claimed, and the work largely exists.

Revised ranking: **(1) pin the negative scope facts** · (2) bridge repair, with eyes
open that the certificate does not need it · (3) the statement pins — busywork.

### UPDATE 2026-08-19 — the negative scope facts are now GATED (closure 33 → 34, gate GREEN)

Kimi K3's ranked-#1 unit from the review round, and it was better than anything on
my own list. The finding above was that the **scope** of the certified statement —
what stops a reader quoting it *"at 2^16 uses"* — is written down nowhere in the
EasyCrypt. Those facts existed, but in an **ungated experiment**. They are now
compiled on every gate run and pinned by digest.

**Promoted by MOVING, not copying.** `experiments/ptgts-pin/PTgtsPin.ec` was
`git mv`d to `cdrafts-split/C10DeployedScope.ec` and all ten dependents repointed,
so exactly **one** definition of these facts exists in the tree. A copy would have
been a fresh drift surface — the defect class this whole arc keeps finding.

```
GATE: GREEN (RC=0), in-container r2026.02, 25 prover configurations
  CLOSURE_COMPILED = 34/34        (was 33)
  statements pinned = 117/117     (was 111 — six new pins)
  cone: added=0 removed=0         ledger=242 UNCHANGED
  OK inputs unchanged across the run (bcb2f295...)
```

Both runs are vendored: `scratch/gate_run1_scope.log` is RED **on the drift line
only** — the gate correctly refusing an unbaselined change — and
`scratch/gate_run2_scope.log` is GREEN.

**Zero census rows of any class**, so `cert-baseline-split.tsv` needed **no edit at
all**: the file contains only definitions (`op x : int = <value>`) and proved
lemmas, and a definition is not an assumption. Only the identity row moved.

**And `added=0` was not taken on trust.** It is ambiguous between "nothing new
entered" and "the census never looked at this file" — the
absence-from-the-wrong-search shape recorded four times this week. Settled by
measurement (`experiments/ptgts-pin/census_coverage_probe.sh`): injecting an axiom
into the new file moves `ledger` 242 → 243; removing it restores 242.

**What is pinned:** `c10_c_closed`, `c10_p_tgts_is_least`, `c10_c_le_p_tgts_at_pin`,
`c10_usage_cap_is_not_admissible_as_p_tgts`, `c10_ht_capacity`,
`c10_ht_capacity_vs_usage_cap`.

**What it does NOT buy, stated in the file header:** it does not make the capstone
say anything about query counts — the capstone has no query parameter at all. The
gain is that the facts *bounding that silence* are machine-checked artifacts rather
than prose. A reader asking why "at 2^16 uses" is not a reading of this development
now gets a gated theorem instead of a paragraph.

**The policy cap is NOT imported.** `c10_q_s` (= 65536 = `MAX_SLOT_USES`) occurs
only in the **conclusions** of the section-5 lemmas, never as a hypothesis, and
nothing in `base-c10-split/` or `cdrafts-split/` requires this file. Both reviewers
rejected importing the deployment cap on 2026-08-15; naming it in a *negative*
statement about what it cannot be is the opposite move, and the fence is in the
header so the distinction is not left to the reader.

**Controls.** `pin_discrimination.sh`: deleting each pinned lemma's conclusion
(replacing it with `true`) moves its digest, 6/6 — plus a no-op leg, because if
whitespace also moved a digest then "it moved" would carry no signal. An
axiom-downgrade leg checks that `lemma` → `axiom` yields `NOT-FOUND`, which the
gate hard-fails. `runall.sh`: 11 targets at declared polarity after the move,
statement-identity 0 broken, 0 admits/axioms in code.

**My first version of the axiom-downgrade control passed for the wrong reason** and
is worth recording. The mutation helper threw (it anchored `qed.` at line start;
this file's proofs are one-liners), leaving an **empty** file — and an empty file
also digests to `NOT-FOUND`, the exact verdict under test. Caught by reading the
traceback rather than the verdict. It is now guarded by a size check, and **the
guard is self-tested**: a deliberately truncating helper makes it report
`truncated, not downgraded`.

**Two defects fixed in the file before promotion**, both found by re-measuring
rather than trusting: it cited `WOTS_C_Multi.ec:490-494` (stale — the phrase is at
`:233`, `D1_reduce` at `:523`) and asserted *"`WOTS_C_Multi` is NOT in
`closure-c10-split.txt`"*, which **became false on 2026-08-18** when that file was
gated. The section's conclusion is unchanged, for the reason found the same day:
the capstone does not consume D.1 at all.

**Method note.** I tried to predict the new `INPUTS_SHA256` locally instead of
re-running the gate, got a mismatch, and nearly read it as tree drift. A
**known-answer test** settled it: my script produced `d124120a` for a clean `HEAD`
worktree whose committed identity is `45b788a6`, so the script was wrong — it
omitted the four `base-c10-split` roots the gate adds — not the tree. The gate then
printed `OK INPUTS_SHA256 matches`. A mismatch against a tool written five minutes
ago is evidence about the tool first.

### UPDATE 2026-08-19/20 — the policy-cap fence is now ENFORCED (PHASE 1g), and my first design was wrong

The claim *"we did not import the deployment cap into the model"* held by **inspection
and a header comment**. A future closure member could `require` `C10DeployedScope` and
nothing would notice. It is now a gate check.

**The main result is that my first design was killed before implementation.** It was
three token-greps: no inbound require · the identifier `c10_q_s` is confined to one
file · lemmas naming it carry no `=>`. A 54-agent adversarial review confirmed **33
bypasses**. The decisive three, each re-verified at source:

1. **Re-declare the value under another name** — `op c10_max_slot_uses : int = 65536.`
   in whatever file wants it, plus a premise. No require edge, no occurrence of the
   token. This is the **house idiom**, not a contrived attack:
   `C10DeployedGeometry.ec:66` and `C10DeployedInstance.ec:44` both define
   `c10_n = 16` and **neither requires the other**.
2. **Spell it in model symbols.** This very file proves `l = 4 * c10_q_s`, so `l %/ 4`
   denotes 65536 using only model constants — defeating a token grep, a literal grep,
   **and human review**, since it reads as a structural fraction of hypertree capacity.
3. **`declare axiom` inside a section** carries no `=>`, so an arrow test is blind.

The root error: **a grep keys on a NAME; the object of concern is a NUMBER IN A PREMISE
POSITION.** No enumeration of forbidden syntax closes that. (The review also caught
that `PHASE 1f` was already taken — `cert_gate_split.sh:295`, WATCHED FILES.)

**So the fence is an INVENTORY**, in this gate's own additions-are-fatal idiom, making
the quarantine file immutable-by-default: its committed declaration set (24) and
require set (3) live in `cert-quarantine-split.tsv`, enforced by
`tools/policy_cap_fence.py`. Five checks — isolation-in, isolation-out, sealed-leaf
construct allowlist, declaration inventory, magnitude tripwire.

**And the file is now fully pinned.** It was **6 of 18 lemmas and 0 of 6 ops** — so a
value swap `op c10_p_tgts : int = 262656 -> 65536` moved **no pin**, inside the very
file that quarantines the cap. All 24 declarations are pinned; `EXPECT_PINS 117 -> 135`.

**The fence's own files are hashed**, in *both* the start and end-of-run computations.
An assertion caught that the hash line occurs **twice**; updating only one would have
made them disagree and spuriously tripped "inputs CHANGED DURING THE RUN".

```
GATE run 2: GREEN (RC=0)   identity bcb2f295 -> 2fcbf2ef
  CLOSURE_COMPILED = 34/34      statements pinned = 135/135
  cone: added=0 removed=0       ledger=242
  OK quarantine intact: 24 declarations, 3 require lines, sealed leaf,
     no inbound requires, no magnitude leakage
```

**Controls:** five must-fail controls (`fence_controls.sh`), each asserted to fail *for
the declared reason*, against a green baseline first — a fence that never passes proves
nothing.

**What it does NOT close**, stated in the tool, the manifest, the gate phase and here:
a **new** policy number introduced **elsewhere** under another name — routes 1 and 2
above. Those touch other files, which this fence does not inventory. Closing that class
needs exhaustive statement pinning over all 34 closure members (~623 statements).
Separate project.

#### Run 1 was RED with a second, unexpected failure — published, not buried

`FAIL GprocT1Opre (cli): 473 diagnostic(s)` on a file with **zero source changes**,
which passed in the two runs before and the run after. An `smt` failure under the cli
driver — the load-flake signature this repo already documents for `EncoderBridge.pow8`.
**Cause not established:** I ran probes in the same container during run 1 and none
during run 2, which is suggestive but one trial per arm, not a controlled measurement.
Both receipts are vendored (`scratch/gate_run1_fence.log` RED,
`scratch/gate_run2_fence.log` GREEN). Write-up:
`scratch/FINDING-gate-cli-phase-is-load-flaky.md`.

The tempting response was to re-run and keep the green one. That converts the gate into
a slot machine, and it is the reason both logs are here.

**Method note.** I twice tried to reimplement the gate's `INPUTS_SHA256` locally to
save a 50-minute run. A known-answer test caught **both** attempts wrong — each
reproduced the wrong hash for a clean `HEAD` worktree whose identity is committed. I
stopped after two and used the gate as the authority.

#### CORRECTION 2026-08-20 — the fence above PASSED VACUOUSLY, and my own controls could not have found it

Raised by review of the pushed fence; **confirmed by measurement**. Against a
`cert-quarantine-split.tsv` gutted to comments only, the fence printed
`OK quarantine intact` with `rc=0` — `want_decls` and `want_reqs` both came back
empty, so **Q2 and Q4 silently skipped** and the check reported green while checking
nothing.

That is the exact vacuous-pass shape this tree's controls exist to catch, reproduced
inside a control I had written the previous day — in the same session where I fixed
the same defect in `pin_discrimination.sh`. Twice, same shape.

**Why my own controls could not have found it:** all five **add** something (an
inbound require, a require line, a section, a declaration, a magnitude). Vacuity comes
from **removal**. New control `C0` removes the manifest's rows and asserts the failure
names `Q0`. The suite is now 6/6 for the declared reason, against a green baseline.

**Fix:** a `Q0` anti-vacuity check with `EXPECT_DECLS = 24` / `EXPECT_REQS = 3` as
committed constants **in the tool — deliberately not in the manifest they guard**,
which the same edit could otherwise zero along with the data.

Also: `Q5` is now documented as a **tripwire, not a rule** — `2 ^ 16` will eventually
match legitimate arithmetic in some future certified file, and there is deliberately no
allowlist yet. A `Q5` hit is not proof of a policy import.

```
GATE run 3: GREEN (RC=0)   identity 2fcbf2ef -> 84ebde0d
  34/34 compiled · 135/135 pins · cone added=0 · ledger=242
  OK quarantine intact · OK inputs unchanged across the run
```

**And the flake lead came back negative, which is worth as much as a positive.** The
`ECO_PURGED=37` vs `38` difference in the flaking run is real, is explained (a cleanup
deleted one `.eco` between runs), and **cannot be causal**: all five runs report
`ECO_REMAINING=0`, so every run began from an identical zero-`.eco` state. Run 3 adds a
fourth distinct purge count (`0`) with the same post-purge state and a passing `cli`
leg. `GprocT1Opre (cli)` now stands at **1 failure in 5 runs**; the finding records the
ruled-out hypothesis rather than leaving it open.
