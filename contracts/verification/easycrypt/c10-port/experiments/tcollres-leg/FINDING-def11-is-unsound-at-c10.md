# STOP: the planned CiC Def-11 hop is UNSOUND at deployed C10

**Date 2026-07-27. Written before any mechanization, which is the point.**

The task was "do the computational leg to prove C10 at deployed parameters".
The plan was: discharge the one remaining obligation (`m <> m'` does not give
`encode m <> encode m'`) by hopping to CiC Definition 11 (T-COLL-RES), as the
published framework prescribes. **Do not do this.** It would produce a ~2^72
EUF-CMA statement — 23 bits BELOW the project's own 96-bit floor — and call it
a proof.

## Two corrections, in order of importance

### 1. My framing premise was WRONG (self-correction)

I opened by treating `|C_T| = 2^114.09` (the constant-sum layer at T=205) as a
security ceiling bounding what the leg could conclude. It is not.

A codeword is **43 digits x 3 bits = 129 bits**. Hitting a SPECIFIC codeword is
matching 129 bits => `2^-129` per hash, INDEPENDENT of how many codewords are
valid. `sum = 205` is a publicly checkable *validity gate*, not the security
gate; the layer size cancels out of the per-query success probability.

Falsifiable test (run, confirms): change `TARGET_SUM` 205 -> 150. The layer
grows `2^114.09 -> 2^123.76` and grind cost drops `2^14.91 -> 2^5.24`, while the
target-hit cost stays `2^129`. **A quantity that moves liveness but no adversary
success event is not a security ceiling.**

Correct figures: encoding second-preimage `2^129` classical, `~2^64.15` Grover;
multi-target over ~2^17 reachable WOTS instances `2^112`. All above the 96-bit
floor, none binding. Caught by Kimi K3; re-derived independently before adopting.

### 2. CiC Definition 11 does NOT hold at C10's deployed encoder

Converged across several independent adversarial reviewers, each reproducing the
arithmetic from source:

* Def 11's oracle **samples rho uniformly from R on every attempt**
  (paper-cic-2-1-13.txt:876-878; mirrored in `drafts/IncEnc.ec` as `r <$ drand`).
* C10 **deterministically enumerates the minimal counter** over a wholly public
  map (`sphincs-c10/src/wots.rs:59-70`, `for count in 0..10_000_000u32`). No key,
  no sampling, and the minimal count is transmitted and publicly re-checkable.
  **Effective `|R| = 1`.**
* Def 11 also hands the adversary `P` BEFORE it chooses `m`
  (paper:868-873; `IncEnc.ec:1040`).

So restate Def 11 faithfully at the deployed encoder and the assumption is
**FALSE**, not merely unproven: precompute canonical encodings for ~2^57
honest-side and ~2^57 forgery-side candidates at `2^14.906` hashes each and
birthday-collide inside `|C_T| = 2^114.094` — **~2^72.3-72.95 hashes**,
memoryless via van Oorschot-Wiener. Table 1's `q'pK/|R|` term is `>= 1`, so the
paper's own bound yields nothing.

`eq (14)` is the load-bearing leg of Parameter Requirement 2, not `eq (13)`:
`log|R| >= ~170.58` required vs `23.25` actual (and `23.25 = log2(10^7)` is the
ITERATION CAP, not entropy — the counter has ~0 bits). The `eq (13)` 2.32-bit
shortfall (vw=129 vs 131.32) is union-bound slack that SLH-DSA-128s misses by
more; it was correctly triaged NO-ACTION. **The `log|R|` half was not, and it is
what makes the raw Def-11 route unusable.**

## THE DEPLOYED WALLET IS NOT AFFECTED

State this plainly: **there is no attack.** The 2^72 break is on the *named
game*, not the product. It does not transfer because C10's WOTS layer never
encodes an adversary-chosen value — it encodes key-determined internal nodes
(per-position FORS roots, fixed subtree roots): `fors.rs:265-268` (`compute_fors_pk`
takes no message argument), `fors.rs:136-141`, `hypertree.rs:262/274/290-291`.
The adversary cannot inject a chosen `m` into the grinder, so the birthday has
nothing to collide against. Deployed cost stays `2^129` classical / `~2^64.15`
Grover, dominated by the pre-existing `2^128` second-preimage on `fors_pk` that
SLH-DSA-SHA2-128s carries identically.

Classification: **proof-technique limitation**, not a vulnerability.

## THE CORRECT REPAIR — and it is already in the port

Do NOT import message-independence into a Def-11 hop. Discharge the obligation
inside the +C GCMA game, where a STRONGER and already-mechanized restriction is
available: **the public seed is withheld until after the messages are chosen.**

Verified verbatim at `drafts/WOTS_C_Scheme.ec`:

```
:142  proc choose() : unit { O.query, OC.query }      <- NO input, so no ps
:143  proc forge(ps : pseed) : int * msgWOTS * (sigWOTS * cntr) {}
:200  A.choose();                                     <- messages committed first
:201  (i, m', sigc') <@ A.forge(ps);                  <- ps only now
:207  is_fresh <- m' <> m;                            <- EXACTLY our obligation
:213  dist_wgpidxs <@ O.dist_addresses();             <- one message per address
```

Since `wots_digest` absorbs `pk_seed` first (`sphincs-c10/src/hash.rs:350-365`),
**no encoding is computable at choose-time**, which kills the precomputation
birthday at that site without any assumption about message-independence. And
`dist_wgpidxs` forbids two honest targets sharing a tweak.

Honest caveat to carry: `pk_seed` IS public in the deployed system
(`params.rs:85`), so seed-withholding is a MODELLING restriction. The real-world
safety on this axis rests on message-independence (R1); seed-withholding (R2) is
what makes the EasyCrypt proof go through. Both must be recorded — R2 discharges
the proof obligation, R1 is the deployment justification.

## Revised plan for the computational leg

1. Discharge the `:1359` obligation inside `M_EUF_GCMA_WOTSC_NPRF` using
   seed-withholding + `dist_wgpidxs`, NOT a Def-11 hop.
2. Record the Def-11 falsification as a finding against the framework's
   instantiation at C10, not against C10.
3. Separately record that R1 (message-independence) is the deployment-side
   justification and is asserted, not proven -- already tracked at
   `docs/STATUS.md:415`.
4. Do not quote `2^114` as a security level anywhere; quote `2^129` single-target
   / `2^112` multi-target.

---

# ADDENDUM (17-agent adversarial workflow) — two corrections to the above, and a sharper finding

## Corrections to MY numbers

1. **"multi-target 2^112" was WRONG.** The encoding term is **p-INDEPENDENT**.
   `wots_digest = SHA-256(pk_seed || ADRS || msg || 0^28 || count)`
   (`hash.rs:350-365`, ADRS at `wots.rs:61`), so one hash trial commits to exactly
   one (key, instance) and tests exactly one target: Q trials => Q * 2^-129
   regardless of how many targets exist. Table 1's classical first term carries no
   `p`, consistently. All four independent analyses agree. **Quote 2^129, never
   2^112.**
2. **The two "96"s are different objects.** `forsc_grinding_margin.py:143`
   `WORK_FLOOR_BITS = 96` is a **WORK floor** (its own :130-143 note);
   `Quantitative.lean`'s 96 is a separate **advantage exponent**. Do not merge.

## THE SHARPER FINDING: Def 11 verbatim is VACUOUS, not merely unusable

Lemma 8 (`paper:1610`) reduces T-COLL-RES to SM-rTCR of Th_msg; Table 1's
classical SM-rTCR row (`paper:652`) is `(q'+1)/|H| + q'*pK/|R|`. At C10:
`p = 2*qs = 2^17` (d=2, two WOTS instances per signature, `hypertree.rs:268`),
and `|R| <= 2^32` (the count is a u32). The second term at EVERY reachable corner:

```
K=1        pK=2^17.00  |R|=2^32     q=2^16 -> 2^2.58    VACUOUS  (most charitable)
K=E[grind] pK=2^31.91  |R|=2^32     q=2^96 -> 2^95.91   VACUOUS
K=10^7     pK=2^40.25  |R|=2^23.25  q=2^96 -> 2^113.00  VACUOUS
```

Non-vacuity at `q = 2^96` needs `|R| > 2^126.91`. **So eq (14) is not decorative
accounting — its violation is exactly what makes the published bound yield
nothing.** This CORRECTS the project's earlier NO-ACTION triage of the eq-13/14
item: eq (13)'s 2.32-bit slack was correctly triaged, but the `log|R|` half was
not, and that is the load-bearing leg.

## CALIBRATION — C10 is BETTER than the NIST standard on this axis

No published route proves ANY SPHINCS+-family WOTS layer at deployed parameters.
Parameter Requirement 1 (`paper:1729-1737`) imposes the identical RHS on plain
checksum Winternitz, and **NIST's own SLH-DSA-SHA2-128s misses it by 3.32 / 9.64
— MORE than C10's 2.32 / 8.64.** Do not report this as "our scheme is weak".

## THREE-WAY CLASSIFICATION (final)

| item | class |
|---|---|
| eq (13), vw=129 vs 131.32/137.64 | **sufficient-condition failure** — union-bound slack; NIST misses by more; no attack |
| eq (14), log\|R\| <= 32 vs >= 147.32 | **proof-technique failure WITH TEETH** — makes the published bound vacuous, and makes the NAMED ASSUMPTION false at ~2^72.3. An attack on a candidate assumption shape, NOT on the product |
| `two_encodings` | **FALSE AXIOM** at C10 geometry — 2^128 messages into 2^114.09 codewords = 2^13.9 preimages each. Injectivity would need v >= 45; C10 has v = 43. This is the actual defect in the current proof state |

**There is no attack on deployed C10 on this axis at any work factor below
2^128.** The 2^72.3 preconditions — adversary-chosen encoded message, P public at
choice time, two messages at one ADRS — are ALL violated by the deployed signer.
Never quote 2^72.3 as a C10 security level.

## THE RIGHT ASSUMPTION IS NOT CiC Def 11 — it is SPHINCS+C's own Def C.1

Use **S-TCR(+C)** (`paper-nist-pqc2022.txt:1981-2000`): A1 gets oracle access but
**not P**; the counter is a deterministic search index with **no randomness space
at all** (which is what C10 actually does); `DIST({T_i})`; and the win condition
is **M != M_i**. Direction matters: Def 11's `(m,rho) != (m*,rho*)` is EASIER to
win, so "Adv small" under Def 11 is the STRONGER assumption; Def C.1's
message-inequality is EXACTLY the obligation at
`is_fresh <- m' <> m` (`WOTS_C_Scheme.ec:207`).

## WHAT MECHANIZING BUYS — stated with what it does NOT buy

BUYS: converts a **false axiom** into **one named computational assumption**
whose generic hardness at deployed geometry is `2^129` / `2^64.15` and which is
not the binding term. Today the WOTS+C leg has NO instantiation at deployed C10
and none CAN exist while `two_encodings` is there (`docs/STATUS.md:422`).

DOES NOT BUY: it does not prove C10's EUF-CMA. Still cited afterwards: `ITSRC10`
(FORS+C — no theorem exists in the literature), the composition, MM45's trusted
base, and the new assumption itself. **The leg moves one obligation from
"provably false" to "plausible and named".** That is the honest headline.

## NEXT EXPERIMENT (cheapest, decision-relevant, hours not sessions)

Discharge `is_fresh <- m' <> m` in the EXISTING `M_EUF_GCMA_WOTSC_NPRF`
(`WOTS_C_Scheme.ec:183-217`) from a seed-hiding target-collision assumption,
WITHOUT touching MM45's base. It either type-checks — leg is small, Def 11
dropped — or it immediately surfaces the missing premise. Watch whether it also
needs the `disj_wgpidxs` collection-oracle separation (`:215`). That single
answer decides one-week vs two-month.

Runner-up (firmware, ~30 lines): an ADRS->node invariance harness — sign N
messages, assert each (layer,tree,kp) ever sees exactly ONE WOTS input value.
Turns the deployment-side premise from a code-read into a CI-gated fact. Note it
tests only the REACHABILITY half; the mechanism half needs a scaled-down
instance. Two tests, not one.

---

# ADDENDUM 2 (GPT-5.6) — it CORRECTS the other two reviews, and corrects me

Divergence carried the information. Kimi and the 17-agent workflow both leaned on
"C10's WOTS only encodes key-determined internal nodes, so a chosen value can
never enter the grinder". GPT-5.6 shows that is true of the honest SIGNER but
**verification does not enforce that provenance** — all verified at source:

* `R` is read from the signature and NEVER recomputed. Verbatim in our own
  source comment (`sphincs-c10/src/fors.rs:92-97`): *"The verifier never
  recomputes R (it reads R from the signature)"*.
* The layer-0 WOTS input is RECONSTRUCTED from supplied FORS secrets + paths
  (`hypertree.rs:378`); the next WOTS input from the supplied WOTS signature,
  count and auth path (`hypertree.rs:418`).
* The forged count is unconstrained except that its codeword sums to 205
  (`wots.rs:139`).
* **Our own forgery test already does this**: `fors_forgery_resistance.rs` —
  *"Forge phase: grind R (a freely chosen 16-byte field) until the digest selects
  an ht_idx + leaves the harvest fully covers."*

So the adversary cannot preselect an honest WOTS position, but **after collecting
signatures it can target a HARVESTED position by grinding public (message, R)
pairs.** The obligation therefore does NOT disappear — it becomes an
**address-bound, post-transcript target second-preimage** obligation, and
establishing it needs the **FORS -> hypertree -> WOTS composition**, not WOTS
inspection alone. Seed-withholding in `WOTS_C_Scheme.ec` is a real modelling
device but it does not by itself settle the deployed question.

## The correct case split (GPT-5.6)

| forged reconstructed node | codeword relation | required charge |
|---|---|---|
| same canonical node | — | lower-layer FORS/tree reuse-or-collision argument |
| different node | SAME codeword | address-bound target second-preimage / S-TCR(+C) |
| different node | different codeword | Def 9 incomparability -> the existing WOTS chain argument |

## CORRECTION TO MY OWN UNIT-2 HEADLINE

I wrote that the chain's dependence on injectivity is confined to ONE obligation.
That is true **as stated** and I stand by it. But I let it read as "one
obligation away from a deployed C10 theorem". **It is not.** Verified at source
in the very shadow tree I gated:

* `shadow/WOTS_TW_ES.ec:31` — `log2_w : { int | log2_w = 2 \/ log2_w = 4 \/ log2_w = 8 }`.
  **C10 needs `log2_w = 3`. It is not in that set.** (This is the long-known F1
  blocker; my experiment did not touch it.)
* `shadow/WOTS_TW_ES.ec:37-43` — still the CHECKSUM geometry
  `len1`, `len2` (checksum length), `len = len1 + len2`. **C10 has no checksum;
  its `len = 43` is flat.**
* `shadow/WOTS_TW_ES.ec:603` — `enc_nonzero` is introduced but UNLINKED (C10
  should discharge it easily from `TARGET_SUM = 205 > 0`, but that is not done).

So the honest claim boundary is: **the injectivity dependence is one obligation;
a deployed-C10 theorem is at least four** (that obligation + the `log2_w`
admissibility + the checksum geometry + linking `enc_nonzero`). `docs/STATUS.md`
and `contracts/verification/docs/THE_CLAIM.md:17` already say no deployed-C10
instantiation exists; my write-up should not have implied otherwise.

## Multi-target, settled

Aggregate-work formulation: `Pr[any target hit] <= Q / 2^129` where `Q` is TOTAL
raw hash work — **no extra `2^17` factor**. The `2^112` figure is a per-target
budget / parallel-rounds view; total expected work stays `2^129`. A reduction
that guesses one target may lose a factor `T`, but that is reduction TIGHTNESS,
not raw-hash probability. So: quote `2^129` aggregate; if a per-target budget is
ever quoted, label it as such.

## GPT-5.6's prioritized route to a deployed theorem (5 steps)

1. Define the faithful event: same public seed + WOTS address, canonical honest
   node/count vs a DIFFERENT forged node and arbitrary forged count, equal low-129
   codeword.
2. Prove the composition/extraction lemma: every accepted full forgery yields
   either a lower-layer FORS/tree break, an address-bound codeword target
   collision, or the distinct-codeword case Def 9 already handles. Must include
   attacker-controlled `R` and address grinding.
3. Prove ONE canonical honest target per address (gives `r_a = 1` for the
   multi-target bound). Needs FORS + hypertree correctness.
4. Bridge the exact deployed encoder: SHA-256 serialization, full address, 16-byte
   node padding, u32 count, first-success policy, 10M cap, low-129-bit projection,
   target sum 205.
5. ONLY THEN replace the admit, discharge `enc_nonzero`, remove the MM45
   `log2_w`/checksum restrictions, and re-run all explicit targets.

**Immediate experiment (GPT-5.6's, more faithful than the workflow's):** a small
EasyCrypt EXTRACTION LEMMA at the FORS->hypertree->WOTS boundary, without further
changing MM45, that produces either the exact equal-codeword target event or a
lower-layer break. That decides whether the existing S-TCR(+C) game is reusable
as-is or needs a codeword-valued refinement. Note `WOTS_C_Real.ec:175,220`:
`ThC` and the codeword encoding are still ABSTRACT — not yet connected to the
deployed full-SHA-256 / low-129-bit encoder.

---

# CORRECTION 2026-07-27 — "Def 11 verbatim is VACUOUS" is OVERSTATED

Everything above is kept verbatim. This block corrects it. Raised by GPT-5.6 in
adversarial review; **verified against the paper myself before writing this**,
per the standing rule that a reviewer's load-bearing citation is a lead, not a
fact.

## The claim that does not survive

The section heading *"Def 11 verbatim is VACUOUS, not merely unusable"* is wrong,
and it is wrong in a way that matters for what we build next.

**C10's encoder does not instantiate Definition 11's oracle at all.** Def 11
step 2(b)i (`paper-cic-2-1-13.txt:875-880`) reads:

```
(b) Set ctr := 0 and x := ⊥. While ctr < K and x = ⊥:
     i. Sample ρ ←$ R.
    ii. Set x := IncEnc(P, m, ρ, ep).
   iii. Set ctr := ctr + 1.
```

The oracle **samples ρ uniformly from R**, up to K times. C10's grinder does
**deterministic enumeration**: `for count in 0..10_000_000u32 { … if sum ==
TARGET_SUM { return } }` (`sphincs-c10/src/wots.rs:139-146`) — it starts at
`count = 0`, walks upward, and returns the **first** success. That is not
uniform sampling with retries; it is a deterministic search whose output is a
*function* of `(seed, adrs, msg_hash)`.

So the right statement is **"C10's encoder is not a Def-11 encoder"**, not
"Def 11 is vacuous". A definition is not vacuous; what I actually computed was
that *one particular bound* — the one obtained by routing through Lemma 8
(`paper:1610`) into Table 1's SM-rTCR row (`paper:652`) — goes non-informative
when evaluated at C10's `(p, |R|, q)`. **A bound going non-informative is not the
same as the notion being vacuous**, and evaluating a bound whose hypotheses C10
does not satisfy is answering a question that never arose.

This is a *stronger* reason not to build on Def 11 than the one I gave, so the
conclusion is unchanged and better supported.

## What DOES survive, unchanged

* **The recommendation.** Do not build the C10 hop on CiC Def 11 / Lemma 8 /
  Table 1. Use SPHINCS+C's own **Def C.1 S-TCR(+C)** (`paper-nist-pqc2022.txt:1981-2000`).
  This was the section's operative conclusion and it stands — now for the cleaner
  reason that the deployed encoder is outside Def 11's shape entirely.
* **The `two_encodings` finding.** Independent of Def 11 and unaffected. It is the
  real defect, and unit 1 acted on it.
* **The arithmetic** in the vacuity table, *read as what it is*: the value of that
  published bound at C10's numbers. It is correct arithmetic about an
  inapplicable bound.
* **"No attack on deployed C10 on this axis at any work factor below 2^128."**

## Also downgraded: the 2^72.3 figure

`~2^72.3` is a **hand-computed, pre-mechanization heuristic**, not a machine-checked
result and not a security level. The three-way table already says *"Never quote
2^72.3 as a C10 security level"*; that warning is now strengthened to: do not quote
it as a *result* either. It is an order-of-magnitude sketch of a candidate
assumption shape under preconditions the deployed signer violates.

## Calibration on my own reporting

I had been treating this document as the session's most valuable output. It is
not: the durable parts are the `two_encodings` finding and the recommendation to
use Def C.1. The vacuity framing was a category error — bound versus notion — and
it survived because I checked the arithmetic carefully and the *applicability*
not at all.
