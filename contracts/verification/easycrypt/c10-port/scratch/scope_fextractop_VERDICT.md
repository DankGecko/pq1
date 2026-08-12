# F-EXTRACT-OP SCOPING — VERDICT, 2026-08-12

Two independent reviewers (GPT-5.6 via codex, Kimi K3 via CLI), both read source,
neither modified any file. Every citation below re-verified by me.

## ANSWER: do not close F-EXTRACT-OP. Do not attempt encoder injectivity.

Both reviewers converged on every disqualifier. Convergence this complete is
strong evidence; the one divergence is resolved below, against Kimi.

---

## CONVERGENT FINDINGS (both, independently, and I verified each)

**1. Neither admit reaches the headline. My retraction was right.**
- **A** (`FORS_C_TreePort.ec:1511` `extract_op`): used only by `fors_c_tree_port`
  in the same file. No `.ec` requires/imports/clones `FORS_C_TreePort`. It is a
  certification root only.
- **B** (`WOTS_TW_ES.ec:1513` `nhchwcoll_hchwpre_msg`): feeds
  `MEUFGCMA_WOTSTWESNPRF` (`:6578`), applied only by
  `EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Unfolded` (`XmssmtCC_All.ec:8811`, applying at
  `:8902`) — which **no capstone consumes** (verified: only comment references in
  `SPHINCS_C.ec:98` / `SPHINCS_C_c10.ec:98`). The canonical deployed result
  carries the raw WOTS game at `GprocQWired.ec:457`.
- So `C10DeployedGeometry.ec:1755` ("load-bearing for the top result") is FALSE
  and its own retraction is correct. Both reviewers reproduced the dependency
  independently rather than trusting either paragraph.

**2. A is a SUPERSEDED DEAD END — closing it would move no term, even if wired.**
Sharper than either reviewer put it, and I verified this myself:
`FORS_C_TreePort.ec:186` defines its **own local mirror** `module SM_DT_OpenPRE`
(the header at `:25` calls it a "faithful mirror" of
`TweakableHashFunctions.eca`'s). The headline carries the **real**
`FTWES.F_OpenPRE.SM_DT_OpenPRE` (`GprocQWired.ec:123`), which the **fully proven**
Gproc route already reaches (`GprocT1Opre.ec:2168`, proof ending `:3819`) and
which `GprocQBound.ec:62` aggregates. So `extract_op` targets a *different game
object* than the theorem's term.
GPT adds: even closed, the theorem would still assume unconditional Merkle
path-fold injectivity, which `FORS_C_TreePort.ec:1063` admits is stronger than
real Merkle structure. "Admit-free" would not mean "instantiated for the scheme".
**Disposition: retire/archive. Never wire it — wiring would REPLACE a proven
OpenPRE leg with an unproven one, a strict regression.**

**3. My (d) was WRONG, and impossible — not merely hard.**
The admitted step is exactly `m <> m' => encode_msgWOTS m <> encode_msgWOTS m'`.
It cannot hold at deployed geometry: input 256 bits, output 43 base-8 digits =
129 bits, and the deployed extraction reads only 129 of the 256 input bits
(`C10DeployedInstance.ec:367`). `WOTS_TW_ES.ec:711-725` already states the
unrelativised form is **UNSATISFIABLE** (largest antichain of {0..7}^43 =
2^123.76 < 2^128) because C10's encoding is deliberately MANY-TO-ONE by counter
grind.
`c10_embg_inj` is irrelevant: it is about `c10_embg : dgstblock * cntr -> dgst`
(`C10DeployedInstance.ec:313/336`), NOT `encode_msgWOTS : mdgstblock -> emsgWOTS`.
The "PINNED_ENCODER" headline pins `emb_in = c10_embg`; it does **not** pin the
WOTS digit encoder. **Similar names concealing a complete type mismatch — that is
what I fell for.**

**4. The `fkeygen` blast radius I quoted was inflated.** "20 occurrences in 4
files" counts comments. Formal uses are confined to `FORS_C.ec` and
`FORS_C_TreePort.ec`; there is no re-clone cascade. But the *semantic* cost is
unchanged: sound closure is option (iii), an effective re-port of MM45's sampling
structure (exposed sampled leaves, challenge-derived public keys, signatures
carrying `O.open` results, exact target ordering, history-aware unopened-leaf
selection). GPT: **8-15 focused engineer-days, ~2-3 elapsed weeks, for zero
headline movement.** PHASE-2 baseline re-cut is ~0.5-1 day — administrative, not
the cost.

**5. ITSRC10 is the real numerical blocker but is not a viable target** — my own
countermodel (`scratch/_countermodel.ec`) proves a legal instance wins with
probability exactly 1, so no parameter-independent bound exists. Terminated.
Of *executable* work, WOTS is the target.

---

## THE DIVERGENCE — resolved AGAINST Kimi

**Kimi** framed the residual as "the T-COLL-RES obligation (Def 11)" and pointed
at `drafts/IncEnc.ec` + `experiments/wots-tw-incenc` as scaffolding.

**GPT-5.6 explicitly warned: do NOT label the residual "Def-11 T-COLL-RES" yet.**

**I verified. GPT is right, and `IncEnc.ec` forbids Kimi's framing in its own
words:**
- *"NAME THE LEDGER ENTRY **'Def 11 VARIANT M1' AND NOT 'Def 11'**"*
- Def 11 "is transcribed as a GAME... It type-checks; **nothing is claimed about
  its advantage**."
- "The transcription is also **missing every side condition** of Def 11 (naturals,
  epoch domain [L], uniform parameter sampling, losslessness) and the
  adversary-memory restriction".
- "The game's own **NON-VACUITY** -- that the win event is reachable for some
  adversary and some IncEnc -- **is NOT established**."
- Lemma 7: "**ONLY THE INCOMPARABILITY HALF IS PROVEN HERE.** The error/delta half
  (Def 10) is where eps-uniformity of Th_msg and the grind budget enter."
- GPT further: IncEnc's randomized-retry oracle does not match C10's
  **deterministic first-good-counter grind**. A faithful quantitative collision
  reduction is a separate **4-8+ week** project.

**Lesson: Kimi imported a paper's definition name onto a repo object that the repo
itself says is only a variant of it.** That is precisely the claim-drift class this
development exists to prevent, and adopting it would have put a false name in the
ledger.

---

## RECOMMENDED NEXT UNIT (GPT-5.6's, adopted — better costed and better named)

**Charge the WOTS encoded-message collision explicitly, then propagate to a
parallel deployed QWIRED theorem.**

1. Define the event `ENC_COLL_WOTS := m <> m' /\ encode_msgWOTS m = encode_msgWOTS m'`.
2. Split Game4 on it **before** the call at `WOTS_TW_ES.ec:6542`.
3. Use the already-proven codeword-level `nhchwcoll_hchwpre` ONLY in the
   unequal-codeword branch.
4. Export a **B-free** bound:
   `Pr[WOTS] <= Pr[ENC_COLL_WOTS] + (w-2)*|Pr[UD0]-Pr[UD1]| + Pr[TCR] + Pr[PRE]`.
5. Thread it through the existing `_Unfolded` scaffold and produce a parallel
   deployed QWIRED theorem replacing the raw WOTS summand
   (`GprocQWired.ec:457`) — the QBound/QWired parallel-and-promote pattern, one
   level down.

**Cost: 12-18 focused engineer-days, ~3-4 elapsed weeks**, including controls, a
deliberate census/baseline re-cut, and an in-container gate run.

**Name the residual `ENC_COLL_WOTS`, NOT "Def 11 / T-COLL-RES".**

**Why it beats the alternatives:**
- A: costs nearly as much, moves nothing.
- Encoder injectivity: mathematically impossible.
- Merely wiring `_Unfolded` (4-7 days): **promotes B into the headline** — it would
  make a live admit load-bearing. A regression, not progress.
- ITSRC10: requires redesigning the model; theorem-terminated as stated.
- S-TCR: improves naming, not the number.

**Honest limit, stated by GPT and worth keeping:** this improves the assumption
surface and proof honesty. It does **not** make the bound numerically meaningful —
both `ENC_COLL_WOTS` and `ITSRC10` remain explicit blockers.

---

## MY SCORECARD ON THIS TOPIC TODAY

I revised my read on these two admits **four times**, and the last revision was
the dangerous one: I proposed proving a statement the repo had already proved
**unsatisfiable**, in the very file I was citing. Root cause both times was the
same as the `dbin` and `INPUTS_SHA256` misses: **similar names read as the same
object** (`c10_embg_inj` vs `encode_msgWOTS`; "encoder-pinned" headline vs the
WOTS digit encoder), and a conclusion asserted from a search that could not have
established it. See `[[feedback_absence_from_wrong_token]]`.
