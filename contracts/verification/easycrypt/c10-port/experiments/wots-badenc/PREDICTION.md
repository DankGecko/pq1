# Experiment `wots-badenc` — lift the BadEnc disjunction to the Game4 caller

**Written BEFORE running the compile.** Falsifiable prediction, not a post-hoc
reading of whatever the tool printed. Same discipline as
`experiments/wots-tw-incenc/PREDICTION.md`, which this experiment directly
continues.

## Why

`base-c10-split/WOTS_TW_ES.ec:1505` `nhchwcoll_hchwpre_msg` closes with a bare
`admit`. Its open goal is `m <> m' => encode_msgWOTS m <> encode_msgWOTS m'`.
This session proved (gated GREEN, `scratch/wots_admit_is_injectivity.ec`) that:

* the goal is **equivalent to injectivity of `encode_msgWOTS` on the constant-sum
  surface**, and
* at deployed C10 geometry the encoder is `2^127`-to-one, so **a collision refutes
  the entire five-hypothesis lemma**, not merely its admitted subgoal —
  `is_chwcoll` (`:763`) and `is_chwpre` (`:808`) share the conjunct
  `BaseW.val em'.[i] < BaseW.val em.[i]`, which under `em = em'` is `x < x`.

So the admit cannot be discharged. It must be **replaced**. The replacement is
already proved admit-free (`admit_free_caller_split`), from the complete
`nhchwcoll_hchwpre` (`:1476`):

```
P m => P m' => !has_chwcoll ... =>
  encode_msgWOTS m = encode_msgWOTS m'  \/  has_chwpre ...
```

The left disjunct is the **`BadEnc`** event — the thing a +C seed-withholding
argument can eventually bound, because one layer up the messages are
`ThC ps ad x c` and `encode o ThC ps ad .` **is** seed-keyed.

## THE EDIT (exactly one, and it REMOVES an admit)

In the forked base, `nhchwcoll_hchwpre_msg` keeps its **name and hypotheses** and
its conclusion becomes the disjunction. Its proof becomes admit-free:

```
move=> hPm hPmp hne hnc.
case (encode_msgWOTS m = encode_msgWOTS m') => [heq | hbad]; first by left.
by right; apply (nhchwcoll_hchwpre ps ad m m' sig sig').
```

Nothing else in the tree is touched. The name is preserved deliberately so the
break lands on **use of the conclusion**, not on name resolution — a
`unknown symbol` failure would tell me nothing.

## PREDICTION

1. **The forked `WOTS_TW_ES.ec` breaks at EXACTLY ONE site: `:6542`**, the sole
   live caller. It consumes the conclusion directly as `has_chwpre`
   (`move=> hchwpre;`), which is now a disjunction.
2. **The admit count of the forked file drops from 1 to 0**, and no new
   `axiom`/`declare axiom` appears.
3. Every other file in the base compiles unchanged, because the lemma is used
   nowhere else (verified: the only non-copy hit is `:6542`).
4. The residual goal at the break will require the caller to handle the
   `encode_msgWOTS q.\`2 = encode_msgWOTS m'` branch, for which **there is no
   proof available at that point** — that is exactly the term that must become a
   charged probability in `MEUFGCMA_WOTSTWESNPRF`'s statement.

**What would falsify this:** breaks at more than one site (⇒ the lemma is used
somewhere my grep missed — my recurring error class, see
`feedback_absence_from_wrong_token`); or a break in a *different* file (⇒ the
lemma escapes `WOTS_TW_ES.ec`); or the file compiling unchanged (⇒ the caller
never actually consumed the conclusion, and my reading of `:6542` is wrong).

**Prediction 4 is the one I am least sure of** — the caller's goal after the
`move/` is a large `equiv` context and the disjunction may be absorbed by an
`smt()` further down rather than surfacing cleanly. If it is absorbed, that is
NOT a success: it would mean the bad branch is being discharged by something I
have not identified, and I must find out what.

## What this experiment does NOT do

It does not charge the event. Charging requires adding a `Pr[BadEnc]` summand to
`MEUFGCMA_WOTSTWESNPRF`'s statement and threading it through Game4 — the
expensive half. This experiment produces the **exact goal state** that half has
to discharge, which is the information needed to price it honestly rather than
from a guess.
