# RESULT — extraction lemma: the existing S-TCR(+C) game is NOT reusable as-is

Companion to `PREDICTION-extraction.md` (written before compiling).

## Verdict on the question the experiment was run to decide

> "Determine whether the existing S-TCR(+C) game can be reused as-is or needs a
> codeword-valued refinement." (GPT-5.6)

**Answer: it needs a refinement — or, equivalently, the deployed-encoder
bridge.** This is now machine-checked rather than argued.

## Receipts

`experiments/tcollres-leg/Extraction.ec`, compiled as an explicit target against
the port's real `WOTS_C_Scheme`:

* compile `rc=0`, `.eco` written
* **0 admits, 0 axioms**
* **negative control passes**: injecting `lemma NEGCTL : false. proof. trivial. qed.`
  makes it FAIL (`rc=1`); restoring returns `rc=0`. So the proofs are genuinely
  checked — this is not a `require`-not-re-verifying pass (trap T1, which bit
  this project twice this week).
* vendored MM45 tree untouched.

## The structural finding

The +C encoding FACTORS as `level3 = encode_msgWOTS o level2`, i.e.
`encode_msgWOTS_C ps ad m c = encode_msgWOTS (ThC ps ad m c)` (bridge recorded at
`XmssmtCC_All.ec:1178`). So the obligation left open at
`shadow/WOTS_TW_ES.ec:1359` — which lives at LEVEL 3 — decomposes into **two
disjoint causes, not one** (`coll_splits_by_level`, proven):

| cause | event | charge |
|---|---|---|
| **B1** | the `ThC` digests already collide | S-TCR(+C) target collision — existing machinery applies |
| **B2** | digests DIFFER but their codewords agree | **NO HOME** |

**B2 is precisely MM45's injectivity failure, and Definition 9 does NOT rescue
it**: Def 9 constrains distinct CODEWORDS, and in B2 the codewords are equal.
This is exactly the codeword-valued refinement GPT-5.6 predicted would be
needed; it is now a machine-checked structural fact rather than a prediction.

`extraction_good_branch` (also proven) confirms the other half: in the `!COLL`
branch the hypothesis the WOTS chain argument consumes — codeword inequality —
is literally available with no side condition. That half is near-trivial BY
DESIGN and is marked as such in-file; it is the check that the good branch hands
over the right thing, not a result.

## How B2 closes — and why it cannot close here

`coll_collapses_under_bridge` (proven) shows B2 becomes empty, and B1 becomes the
sole cause, GIVEN the hypothesis `B2_is_empty`. That hypothesis is stated as an
explicit premise and deliberately **NOT axiomatised**.

Discharging it requires the deployed-encoder bridge: `encode_msgWOTS_C` is the
base-8 digit extraction of the **low 129 bits** of SHA-256, which IS injective on
those bits — so distinct digests agreeing on all 43 digits is impossible unless
they agree on those 129 bits, collapsing B2 into B1. That is **step 4 of the
five-step route** and cannot be done at the current abstraction level: `ThC`,
`predC` and `encode_msgWOTS_C` are ABSTRACT ops (`WOTS_C_Real.ec:180,220,223`),
not yet connected to the deployed SHA-256 encoder.

**Until that bridge exists, B2 is a genuine, uncharged event.**

## What this does and does not license

LICENSES: the decomposition is legitimate; the good branch yields the needed
hypothesis; and the S-TCR(+C) route needs either a codeword-valued refinement or
the encoder bridge. It converts a design question into a settled one and tells us
the next step is the ENCODER BRIDGE, not more game-shaping.

DOES NOT LICENSE: anything about C10's security level. `Pr[G /\ COLL]` remains
entirely uncharged — charging it needs the address-bound, post-transcript S-TCR(+C)
reduction (step 2), which was NOT attempted. The leg is not closed and C10 is not
proven at deployed parameters.

## Prediction accuracy

Predicted: (D) low risk; (E) compiles only if COLL is stated at CODEWORD
granularity; the `!COLL` branch does not by itself close the leg. All three held.
The one thing the prediction did NOT anticipate is the B1/B2 split — that emerged
from writing the lemma, and it is the actual finding.

Note on (D): the probabilistic decomposition over the real game module was NOT
mechanized here — the game's `m`, `m'` are local variables, so splitting on a
predicate over them needs an instrumented game plus a `byequiv`. That is real
work and is the honest residual of this experiment; the structural half (E, and
the B1/B2 split) is what compiled.
