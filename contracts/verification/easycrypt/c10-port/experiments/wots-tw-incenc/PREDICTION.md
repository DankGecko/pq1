# Experiment: localize MM45's injectivity dependency (Track B milestone 2a)

**Written BEFORE running the compile.** This is a falsifiable prediction, not a
post-hoc reading of whatever the tool printed.

## Why

The capstone chain is CERTIFIED-0-ADMIT but instantiable only at MM45-admissible
`w in {4,16,256}`. C10 ships `w = 8` (`log2_w = 3`, `len = 43`). The blocker is
`WOTS_TW_ES.ec:572`:

```
axiom two_encodings (m m' : msgWOTS) :
     m <> m'
  => exists i, 0 <= i < len /\ val (encode m).[i] < val (encode m').[i].
```

Applied in BOTH argument orders to `m <> m'`, this forces `encode` to be
INJECTIVE with an ANTICHAIN image. Exact DP: the largest antichain of
`{0..7}^43` is `2^123.76 < 2^128`, so the axiom is UNSATISFIABLE at deployed
geometry by ANY encoding. C10's real encoding is deliberately MANY-TO-ONE (a
counter grind finds a preimage with digit-sum `= target_sum`).

Published fix (Drake-Khovratovich-Kudinov-Wagner, IACR CiC 2/1/13 = ePrint
2025/055): Def 9 quantifies the antichain over **CODEWORDS**, not messages, and
explicitly permits many-to-one. `drafts/IncEnc.ec` already proves (CERTIFIED-
0-ADMIT) that Construction 6 / target-sum is incomparable for ARBITRARY
`(v,w,T)`, and that C10's `(43,3,205)` geometry is admissible AND non-vacuous.

## Measured repair surface (verified at source, this session)

The ENTIRE injectivity dependency of MM45's WOTS-TW development is 5 lines, all
in `WOTS_TW_ES.ec`:

| line | role |
|------|------|
| 572  | the `two_encodings` axiom |
| 582  | consumer 1 — inside `exenc_neq0` |
| 1305 | consumer 2 — inside `nhchwcoll_hchwpre` |
| 1492 | the single downstream use of `exenc_neq0` |
| 6233 | the single downstream use of `nhchwcoll_hchwpre` |

## The three edits

1. **Weaken the axiom** `m <> m'` -> `encode_msgWOTS m <> encode_msgWOTS m'`
   (this IS Def 9 incomparability over codewords; satisfied by target-sum at any
   geometry per `IncEnc.ec::tsw_incomparable`).
2. **`exenc_neq0`** can no longer be derived (its proof feeds `two_encodings` a
   constructed message `pm` with `pm <> m`, which under a many-to-one encoding
   does NOT give `encode pm <> encode m`). Introduce it as an EXPLICIT axiom
   `enc_nonzero`. This is an honest NARROWING: the repaired development is no
   longer parametric in the encoding, it now requires a positive-target-sum
   code. It must appear in the axiom census, not be slipped in as a lemma that
   "still holds".
3. **Weaken `nhchwcoll_hchwpre`'s hypothesis** to `encode m <> encode m'`. Its
   conclusion ALREADY mentions only encodings, so nothing downstream of its
   conclusion changes.

## PREDICTION (falsifiable)

> **Edits 1-3 succeed. Exactly ONE site fails: `:6233`, for want of
> `encode_msgWOTS q.`2 <> encode_msgWOTS m'` where the game supplies only the
> message inequality `neqq2_mp : q.`2 <> m'`. NOTHING ELSE fails.**

Rationale: `:6233` is the forgery site. The M-EUF-GCMA game guarantees the
forged message differs from the queried one; it says nothing about their
codewords. That gap is EXACTLY the T-COLL-RES event (Def 11), and the published
framework requires it be discharged in a game hop BEFORE the case split
(case-split-only is UNSOUND — deep-research finding 2026-07-25).

## How to read the outcome

- **Exactly one failure at `:6233`** -> prediction confirmed. This mechanically
  proves the injectivity requirement is an ARTIFACT localized to a single proof
  step, and that the step is precisely where T-COLL-RES must enter. It also
  yields the first real cost estimate for the computational leg.
- **ZERO failures** -> **RED FLAG, not a win.** A weaker axiom is MORE
  satisfiable, so the danger here is proving less than it appears. Zero failures
  would mean the codeword hypothesis got discharged without T-COLL-RES; hunt for
  why before believing anything.
- **A FOURTH site appears** -> that is the real news. It changes the
  tractability estimate and must be reported as such, not absorbed.

## Method discipline (traps this project has already been bitten by)

- **T2** — EasyCrypt does NOT invalidate a dependent's `.eco`. Delete every
  `.eco` in the closure and compile each file as an EXPLICIT target.
- **T1/T3** — `require` does not re-verify, and a 0-admit theorem can be
  VACUOUS. A green compile is not the gate; the admit sweep + axiom census is.
- **Read-only invariant** — the vendored `FV-SPHINCSPLUS-EC/` tree is NOT
  edited. The experiment compiles a COPY on an include path that shadows it;
  `git status FV-SPHINCSPLUS-EC/` must stay empty. The diff IS the artifact.

## Scope guard

Edits 1-3 plus the compile are the whole deliverable. The T-COLL-RES game hop
(step 4) is the computational leg two independent reviewers recommended
stopping; a green result here does NOT license starting it in the same pass.
The value is LOCALIZING the gap and proving the localization mechanically.

---

# UNIT 2 — the chain (added 2026-07-26, before running)

`chain/WOTS_TW_ES.ec` = the 3 edits + a bridge exposing the ORIGINAL
message-inequality interface, whose single missing obligation is left OPEN as
**exactly one `admit`** and **no injectivity axiom** — so a downstream site that
needs injectivity must FAIL rather than borrow it.

## Textual pre-evidence (grep is NOT proof — this is why we compile)

`two_encodings`, `exenc_neq0`, `nhchwcoll_hchwpre`: **0 uses** in
`FL_SL_XMSS_MT_ES.ec` and `SPHINCS_PLUS.ec`. They use `encode_msgWOTS` only as an
OPERATOR in program code (`em <- encode_msgWOTS root`). Nothing anywhere
`realize`s `two_encodings` — clones carry it, and a carried axiom that gets
WEAKER is strictly safe. The capstone drafts mention it only in comments.

## THE SHADOWING TRAP (must be closed first)

If `-I chain` does NOT actually shadow `-I FV-SPHINCSPLUS-EC/proofs`, then
`FL_SL_XMSS_MT_ES.ec` would compile against the PRISTINE `WOTS_TW_ES` and pass
trivially — **a false pass that looks exactly like success.**

Canary: `nhchwcoll_hchwpre_msg` exists ONLY in the chain copy. A one-line file
that `require import WOTS_TW_ES` and mentions it compiles **iff** shadowing
works. Run this BEFORE trusting any chain result.

## PREDICTION

1. `chain/WOTS_TW_ES.ec` -> `RC=0`, exactly 1 admit.
2. Shadow canary -> compiles (shadowing effective).
3. `FL_SL_XMSS_MT_ES.ec` -> compiles clean against the weakened axiom.
4. `SPHINCS_PLUS.ec` -> compiles clean.
5. No downstream site needs injectivity; the localization extends to the chain.

A failure at 3/4/5 is the REAL news and would mean injectivity is load-bearing
further up than the WOTS layer — report it as such, do not absorb it.
