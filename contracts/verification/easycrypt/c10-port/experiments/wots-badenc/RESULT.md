# RESULT — `wots-badenc`

Grade against `PREDICTION.md`, which was written and committed (`4d1ebcb`)
**before** the compile ran and is deliberately **not** edited afterwards.

> **THE PREDICTION UNDER-PROMISED — read this result, not that closing section.**
> `PREDICTION.md` ends by saying the experiment "does not charge the event" and
> yields "the exact goal state that half has to discharge". True when written.
> The probe delivered something strictly stronger: not a goal state, but **proof
> that the charge is the ONLY remaining obligation** — with the collision branch
> stubbed and nothing else altered, the entire 6629-line development compiles
> clean. See "THE HEADLINE" below.

> ### ⚠ `probe/WOTS_TW_ES.ec` CONTAINS A LIVE `admit`. NEVER PROMOTE OR VENDOR IT.
> It is a measurement instrument. The branch it stubs is genuinely unproved and,
> at deployed geometry, genuinely **unprovable** (see
> `scratch/FINDING-seed-withholding-has-no-isolated-step.md`). Nothing mechanical
> stops a mistake here: `cert_gate_split.sh`'s cone census **does not cover
> `experiments/`**, so this admit is invisible to the certification gate. It must
> stay in this directory, and it must never be copied into `base-c10-split/`,
> `cdrafts-split/`, or the PQSigner_OS vendored snapshot.

## Prediction 2 — CONFIRMED before the run

Fork has **0 bare `admit` tactics** (`grep -cE '^[[:space:]]*admit[[:space:]]*\.'`);
the original `base-c10-split/WOTS_TW_ES.ec` has 1. The three remaining textual
hits for "admit" in the fork are comment prose (`:640`, `:1495`, `:2631`).
No new `axiom` / `declare axiom`.

Line arithmetic for grading prediction 1: the edit is +6 lines, so the sole live
caller moves from `:6542` to **`:6548`** (verified by grep, not assumed). Fork is
6629 lines vs 6623.

## Prediction 1 — structurally CONFIRMED, line WRONG, and the reason matters

```
[critical] [.../base/WOTS_TW_ES.ec: line 6554 (0-45)] cannot apply view
__RC=1
```

**Exactly one diagnostic.** So "the development breaks at exactly one site" is
confirmed — the admitted lemma is consumed in exactly one place, as the grep said.

**But I predicted `:6548` and the break is `:6554`.** Six lines later, inside the
same tactic block. The reason is worth recording because it is not obvious:

```
6548: move/(nhchwcoll_hchwpre_msg ps{2} q.`1 _ _ q.`4 sig'{2} hPq2 hPmp2) ...  <- SUCCEEDS
6549: move=> hchwpre; ...                            <- binds hchwpre to the DISJUNCTION
6554: - by move/hchwpre_neq0_findchwpre: hchwpre.    <- FAILS, "cannot apply view"
```

Applying a view whose conclusion became a disjunction **still succeeds** — it just
delivers a disjunction as the new hypothesis. The failure is deferred to the first
*consumer* of that hypothesis. So the site is the caller's proof block, as
predicted; the precise line is where the value is *used*, not where it is
*produced*.

## Prediction 4 — CONFIRMED, and it was the one I was least sure of

I flagged the risk that the disjunct would be "silently absorbed by an `smt()`
further down", and said explicitly that absorption would **not** be a success.
**It was not absorbed.** It surfaces as a hypothesis of the wrong shape at the
first place it is used, which is exactly the clean outcome: the BadEnc branch has
no proof available and cannot be faked by the surrounding automation.

## STEPS 1–3 COMPLETE — the charge is EXPORTED and the file is ADMIT-FREE

`base/` now compiles `__RC=0`, **zero admits**, `.eco` emitted, and exports:

```
Pr[M_EUF_GCMA_WOTSTWESNPRF(A, O_MEUFGCMA_WOTSTWESNPRF, O_THFC_Default) : res]
  <= (w-2)%r * `|UD(false) - UD(true)|
   + Pr[SM_DT_TCR_C(R_SMDTTCRC_Game34WOTSTWES(A), ...) : res]
   + ( Pr[SM_DT_PRE_C(R_SMDTPREC_Game4WOTSTWES(A), ...) : res]
     + Pr[Game4_WOTSTWES_BadEnc(A) : res /\ BadEncFlag.badenc] )
```

MM45's admitted encoder injectivity is replaced by an explicit, named
probability. **Nothing is admitted anywhere in the file.**

| step | what | how |
|---|---|---|
| 1 | instrument the flag | `BadEncFlag.badenc <- em = em'` beside the existing `em`/`em'` locals |
| 2 | split + charge | `Pr[mu_split BadEncFlag.badenc]`; `!badenc` half bounded exactly as MM45 does; postcondition strengthened to `res{1} /\ !badenc{1} => res{2}` |
| 3 | export | pre-section `O_Game34_WOTSTWES_AltX` + `Game4_WOTSTWES_BadEnc(A)`, related to the local game by `Alt_BadEnc_eq` / `EqPr_BadEnc` |

**The BadEnc branch is discharged, not admitted.** `!badenc`, carried down from
the strengthened postcondition, says the two encodings differ — which
contradicts the left disjunct of the replacement lemma outright.

### Step 3 took two rounds, and round 1's failure was legitimate

* **Round 1** put the flag on the section-local game and made the exportable game
  return the event as a **conjunct of its result**. The two tails then differed
  and `sim` refused: *"cannot infer the set of equalities"*. That is not a tactic
  problem — the bodies really were not the same program.
* **Round 2** puts the flag in its own pre-section module `BadEncFlag`, so both
  games write the **same global** and are statement-identical. `sim` then relates
  them via the `Game4_WOTSTWES_Orig_Alt` pattern (`A` is abstract, so `inline *`
  cannot reach it and the adversary calls need `call` + an oracle equivalence).

### The export obstacle, and the house answer

`Game4_WOTSTWES_Alt` and `O_Game34_WOTSTWES_Alt` are section-**local**, so no
exported statement can name them. This file already solves exactly that problem
for `R_SMDTPREC_Game4WOTSTWES` (`:3073`), which inlines its own oracle copy for
the same reason. Followed verbatim. Neither new module depends on anything
section-local: the oracle's only module reference is `O_MEUFGCMA_WOTSTWESNPRF`,
which is already global because the exported game uses it.

### Soundness point, checked rather than assumed

`A` is declared **after** `BadEncFlag`, so it may write that variable. Harmless:
the flag is assigned **after** `A` has finished, so the assignment overwrites
anything `A` did. **No restriction was added to `A`** — adding `-BadEncFlag`
would change the exported theorem's memory-separation obligations for every
downstream caller, which is a real cost paid for nothing.

## THE MECHANICAL PART — DONE: the charge is threaded into the closure

`cd/XmssmtCC_All.ec` compiles `__RC=0`, zero diagnostics, `.eco` emitted, against
the charged base. `EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Unfolded` (`:8811`) now carries
the encoding-collision summand on its RHS at the **same** adversary instantiation
as the UD/TCR/PRE terms, and applies `MEUFGCMA_WOTSTWESNPRF_Charged`.

### The scope was narrower than I first reported

* **Only ONE closure file applies the WOTS theorem.** My first scan said eleven —
  that pattern matched inside `O_MEUFGCMA_WOTSTWESNPRF` and
  `Adv_MEUFGCMA_WOTSTWESNPRF`. With **both** word boundaries and comments
  stripped it is `XmssmtCC_All.ec:8902` alone. Checked with a control confirming
  the tightened pattern still finds the known applier rather than silently
  matching nothing — over-counting from a loose token is the mirror of this
  repo's recurring absence-from-the-wrong-token defect.
* **`FL_SL_XMSS_MT_ES` needs nothing.** It clones `WOTS_TW_ES` (`:547`) but never
  applies the theorem — which is why the three downstream files already built.
* **`_assembly_unfold_wip.ec` is a superseded historical draft**, outside the
  closure and disowned by its own sibling header (`XmssmtCC_All.ec:58-60`). The
  application I first found there is **not** the live one, and the two files'
  premises genuinely differ: the gated file has **ten**, because an `emb_tw`
  injectivity premise was removed in the 2026-07-25 vacuity repair for being
  jointly contradictory with the disjointness premise — it had made the lemma
  *vacuous*. Editing the draft would have been wasted work against a dead file.
* **`EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Unfolded` is NOT pinned** in
  `cert-statements-split.tsv` (only the three capstones are). Convenient here —
  but it also means **the gate would not have caught a bad edit to it**.

### Correction to my own earlier scoping

I described the mechanical part as *"thread through `FL_SL_XMSS_MT_ES` to
`GprocQWired.ec:457`"*. **That was wrong.** `GprocQWired` leaves the WOTS term
**unreduced** — it never applies the theorem, so there is nothing there to
thread. Making that summand *reducible* is a **new result**, now sound for the
first time because the admit is gone, but it is not plumbing and is not claimed
under this heading.

### No new separation obligation

The charged theorem's statement mentions `BadEncFlag`, but no `-BadEncFlag`
restriction was added to the section's declared adversary — so callers inherit
no new memory-separation requirement. `A_ht`'s existing restriction block
sufficed, which this compile confirms rather than assumes.

### What remains — and one half of it is research, not cleanup

1. Thread the summand onward through `FL_SL_XMSS_MT_ES` to `GprocQWired.ec:457`.
   Mechanical; the downstream files already build (below), they simply do not
   carry the new term yet.
2. **Bound `Pr[Game4_WOTSTWES_BadEnc(A) : res /\ BadEncFlag.badenc]`.** This is
   where +C seed-withholding is finally the right argument, because one layer up
   the messages are `ThC ps ad x c` and `encode o ThC ps ad .` *is* seed-keyed.
   It is also where GPT-5.6's standing objection bites: a **type-level** collision
   is not a **reachable** `ThC`/SHA-256 collision. Do not confuse the two.

## Prediction 3 — NOW CLOSED, and confirmed

Run against the charged `base/` (`rundown.sh`):

```
FL_SL_XMSS_MT_ES __RC=0
FORS_ES          __RC=0
SPHINCS_PLUS     __RC=0
```

All three build clean, so "every other file in the base compiles unchanged"
holds — now measured rather than asserted. `FL_SL_XMSS_MT_ES` clones
`WOTS_TW_ES` (`:547`) but never applies the WOTS theorem, so renaming it to
`MEUFGCMA_WOTSTWESNPRF_Charged` and adding a summand breaks nothing downstream.

### Original wording, kept for the record

## Prediction 3 — UNTESTED, not confirmed

I predicted "every other file in the base compiles unchanged". **I did not test
this.** Only `WOTS_TW_ES.ec` was compiled as a target. Its dependencies
(`HashAddresses`, `TweakableHashFunctions`, `KeyedHashFunctions`,
`OpenPRE_From_TCR_DSPR_THF`, `BinaryTrees`, `MerkleTrees`, `PRE_From_SPR_DSPR`)
were compiled transitively and produced no diagnostics, but
`FL_SL_XMSS_MT_ES.ec`, `FORS_ES.ec` and `SPHINCS_PLUS.ec` were never built.
Recording this as untested rather than letting a green-looking run stand in for
a claim I did not check.

**To close it in one run** (next session — do not re-derive why it is open):

```bash
bash experiments/wots-badenc/setup.sh          # restore the verbatim copies
docker exec -w /work ec-grind bash -lc 'eval $(opam env); \
  for f in FL_SL_XMSS_MT_ES FORS_ES SPHINCS_PLUS; do \
    easycrypt compile -I experiments/wots-badenc/probe \
      experiments/wots-badenc/probe/$f.ec 2>&1 | tr "\r" "\n" \
      | grep -E "^\[critical\]|^\[error\]" ; echo "$f rc=$?" ; done'
```

Run it against `probe/` (the stubbed tree, which builds) — against `base/` the
three will fail for the *inherited* `WOTS_TW_ES` break and tell you nothing new.
Expected: three clean builds. If any of them fails for a *different* reason, the
"one break site" conclusion is wrong and the headline below needs revisiting.

## THE HEADLINE — the BadEnc charge is the SOLE remaining obligation

Two-sided measurement, both legs run, neither inferred:

| tree | edit | result | `.eco` |
|---|---|---|---|
| `base/` | admit replaced by the disjunction, **nothing else** | `__RC=1`, 1 diagnostic at `:6554` | **none** (real failure) |
| `probe/` | same, **plus** `first admit` on the BadEnc branch only | `__RC=0`, **0 diagnostics** | 5934 B, fresh (real build) |

Anti-fail-open checks, because "RC=0" on a 6629-line file is exactly the shape a
mistake hides in:

* probe contains **exactly one** admit (`grep -c` = 1), and it is the stub at
  `:6555` — not a second one that crept in;
* the probe emitted a `.eco`, so the build genuinely completed rather than
  short-circuiting;
* the un-stubbed fork emitted **no** `.eco`, so its `RC=1` is a real failure and
  the two legs are genuinely different.

**Conclusion.** Replacing the admitted injectivity lemma with the BadEnc
disjunction breaks the development in exactly one place, and stubbing *only* the
collision branch restores a full clean build. So **nothing else in MM45's 6600-line
WOTS-TW development depended on the admitted injectivity.** The entire residual is
the one probability term.

This is the same shape as `experiments/wots-tw-incenc/RESULT.md`'s bridged-gap
probe, and it converts the charge from "somewhere in a 2–4 week campaign" into a
single, located obligation:

> `Step_Game4_WOTSTWES_SMDTPREC` (`:6338`) must become
> `Pr[Game4_WOTSTWES.main() @ &m : res] <= Pr[SM_DT_PRE_C(...).main() @ &m : res]
>  + Pr[Game4_WOTSTWES.main() @ &m : BadEnc]`,
> its `byequiv` postcondition going from `res{1} => res{2}` to
> `res{1} /\ !badenc{1} => res{2}`.

## WHAT THIS DOES NOT DO — the boundary, stated plainly

The probe's `admit` is a **measurement instrument, not a deliverable**. It is not
committed as progress and must never be promoted: it stubs a branch that is
*genuinely unproved*, and at deployed geometry genuinely *unprovable*.

The remaining work is real and is **not** done here:

1. **Instrument the bad flag.** `badenc` must be a global of a `Game4` variant so
   it is expressible in a `Pr[...]`. The file already uses this pattern
   extensively (`Game4_WOTSTWES_Alt`, `Game2_WOTSTWES`, `..._Inlined`), so the
   shape is house-standard — but it is still a new module plus an
   equality-of-probability hop.
2. **Split the probability** and re-prove the equiv under the strengthened
   precondition.
3. **Thread the new summand** through `MEUFGCMA_WOTSTWESNPRF` (`:6578`) and out
   to the deployed quotation surface at `GprocQWired.ec:457`.
4. **Bound `Pr[BadEnc]`** — which is where +C seed-withholding finally becomes the
   right argument, because one layer up the messages are `ThC ps ad x c` and
   `encode o ThC ps ad .` *is* seed-keyed. This step is a genuine cryptographic
   assumption, not a proof cleanup, and it is where GPT-5.6's remaining objection
   bites: a *type-level* collision is not a *reachable* `ThC`/SHA-256 collision.

Steps 1–3 are mechanical-but-substantial; step 4 is the research. Nothing in this
experiment licenses skipping any of them.

## PROCESS LESSON — four failed launches before one real run

Recording this because it is the *second* time in this session that process
management, not proof work, ate the clock (the first was four aborted
`cert_gate_split.sh` runs). All four failures were **silent or misread**:

1. **`docker exec -d` with nested quoting** — launched nothing. Detected only by
   `ps aux | grep -c [e]asycrypt` returning 0 and no output file appearing.
   *Fix: put the command in a script file; never nest three levels of quoting.*
2. **Permission denied** writing `run.out` — the container user cannot create
   files in a fresh subdirectory. `experiments/` itself is `drwxrwxrwx`, which is
   why every prior experiment worked and this one did not.
   *Fix: `chmod -R 777` the new experiment dir, matching house convention.*
3. **Missing `.eca` files** — I copied `base-c10-split/*.ec` and not `*.eca`, so
   `HashAddresses` could not be located. The base tree is not `.ec`-only.
4. **`&&` chain aborted** — `chmod` failed on the now-root-owned `run.out`
   (`Operation not permitted`), which killed the chain **before** the `docker
   exec`, so the compile never ran and I read a **stale** `run.out` as if it were
   the new result. *This is the dangerous one*: it produced a plausible,
   completely wrong reading.

And one misread that belongs to a named error class:

5. I reported "zero diagnostics" from
   `grep -aE '^\[critical\]' run.out` — which **cannot match**, because
   EasyCrypt's progress spinner uses `\r`, so the entire output is one line until
   it is passed through `tr '\r' '\n'`. Absence concluded from a search that
   could not find the thing. Same class as `feedback_absence_from_wrong_token`,
   and the second instance today.

**Rule going forward for this repo:** a run has not happened until you have
positively observed *either* the process (`ps`) *or* a freshly-timestamped output
file. `rm -f` the output before every run so a stale file cannot masquerade as a
result, and always pipe EasyCrypt output through `tr '\r' '\n'` before grepping.
