# Extraction-lemma experiment — prediction, written BEFORE compiling

## What is being tested

GPT-5.6's recommended cheapest decision-relevant experiment: a small EasyCrypt
extraction lemma at the FORS -> hypertree -> WOTS boundary that, from an accepted
forgery, produces **either the exact equal-codeword target event or a lower-layer
break** — deciding whether the existing S-TCR(+C) machinery is reusable as-is or
needs a codeword-valued refinement.

## The trichotomy being mechanized

| forged reconstructed node | codeword relation | charge |
|---|---|---|
| A. same canonical node | — | lower-layer FORS/tree reuse-or-collision |
| B. different node | SAME codeword | address-bound target 2nd-preimage / S-TCR(+C) |
| C. different node | different codeword | Def 9 incomparability -> existing chain argument |

## Why a bare trichotomy would be VACUOUS (and how this avoids it)

`P \/ !P` is a tautology. Stating the case split alone proves nothing, and the
deep-research finding of 2026-07-25 is explicit that **case-split-only is
UNSOUND** — the collision must be removed by a GAME HOP before the split, not
reasoned about inside it.

So the non-vacuous content here is exactly two claims, and both must compile
with **no admits**:

* **(D) Decomposition.** `Pr[G] <= Pr[G /\ COLL] + Pr[G /\ !COLL]` over the REAL
  `M_EUF_GCMA_WOTSC_NPRF`, not a toy. This is the probabilistic step that makes
  the split legitimate; it is where a case-split-only attempt fails.
* **(E) Extraction.** In the `!COLL` branch, the hypothesis the existing WOTS
  chain argument consumes — `encode m' <> encode m` — actually HOLDS. This is
  what decides reusability: if `!COLL` does not literally give that hypothesis,
  the existing S-TCR(+C) game needs a codeword-valued refinement.

## PREDICTION

1. **(D) compiles.** It is a `mu_split`/`Pr` union step; EasyCrypt supports it
   directly. Low risk.
2. **(E) compiles ONLY IF the collision event is stated at the right granularity
   — over CODEWORDS (`encode_msgWOTS_C ps ad m c`), not over messages.** If I
   state `COLL` as message-equality, (E) will fail, and that failure IS the
   finding (it would mean the existing game is message-valued where a
   codeword-valued refinement is required).
3. **The `!COLL` branch does NOT by itself close the leg.** Even with (D)+(E)
   green, `Pr[G /\ COLL]` remains uncharged; charging it needs the S-TCR(+C)
   reduction with the address-bound, post-transcript target event, which is
   step 2 of the 5-step route and is NOT attempted here.

## Falsifiers, stated up front

* If (D) or (E) needs an `admit`, the experiment has FAILED and the shape is
  wrong — report that, do not paper over it.
* If everything compiles **instantly** (< ~2 s with dependencies already built),
  suspect `require`-not-re-verifying (trap T1, which bit this project twice this
  week) and re-check by compiling as an EXPLICIT target and by a negative control
  that injects `lemma : false`.
* A green result licenses ONLY: "the decomposition is legitimate and the
  existing chain hypothesis is recoverable in the good branch". It does NOT
  license any statement about C10's security level.

## Method

Leaf file under `experiments/tcollres-leg/`, requiring the port's real
`WOTS_C_Scheme`. The vendored MM45 tree is NOT touched
(`git status FV-SPHINCSPLUS-EC/` must stay empty). Compile as an explicit target
with a negative control.
