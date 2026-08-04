# N2 IS NOT REACHABLE — it is INDEPENDENT, and discharging it collapses the gate

Answer to "check if N2 is reachable at all". N2 is the premise

```
exists (c : cntr), predC (ThC ps ad m c)
```

of `wotsc_grind_targets_predC` (`cdrafts/WOTS_C_Real.ec:314-316`), the last thing
gating the WOTS+C honest leg.

Produced by a 9-agent adversarial workflow; every load-bearing claim below
re-verified at source by me. Where the workflow and I computed the same number
independently, both are shown.

---

## 1. VERDICT: independent — not provable, not refutable

`thfc` (`base-c10/SPHINCS_PLUS.ec:442`) and `encode_msgWOTS`
(`base-c10/WOTS_TW_ES.ec:562`) are both free. Two models of the *entire* closure:

**N2 holds:** `thfc := fun _ _ _ _ => tgt_witness`. Then `ThC ps ad m c =
tgt_witness` everywhere, and `predC tgt_witness` holds by definition, since
`target_sum = cw_sum (encode_msgWOTS tgt_witness)`.

**N2 fails:** the deciding symbol is the **encoder**, not `thfc`. Take an image
`{(0,3,1,…,1), (3,0,1,…,1), (1,1,1,…,1)}` — an antichain (so `two_encodings`
holds), every codeword has a nonzero digit (so `enc_nonzero` holds), and the sums
are **not** constant. Set `tgt_witness` to a sum-3 preimage and `thfc` to a
constant sum-2 digest: `predC (ThC …) = false` everywhere.

So `wotsc_grind_targets_predC` can never drop its hypothesis. **No amount of work
over abstract `ThC` closes N2.**

## 2. THE FINDING — N2 and the gate-vacuity residual are ONE residual, not two

I had been tracking these as separate open items. They are the same item.

`predC d = (cw_sum (encode_msgWOTS d) = target_sum)`, and `target_sum` is
*defined* as `cw_sum (encode_msgWOTS tgt_witness)`. So if the encoder is
**constant-sum** — which is what "+C" means, and which is exactly the intended
instantiation (`cdrafts/IncEnc.ec:693-709`, `c10_code = tsw_code 43 3 205`,
proved incomparable) — then `cw_sum ∘ encode_msgWOTS` is constant, hence

> **`predC ≡ true`, so N2 is a trivial theorem AND the +C gate carries no content.**

You cannot obtain "N2 discharged" and "the gate has content" from the same
encoder without an assumption on `thfc`. That is the honest answer to the
question, and it is why the residual kept relocating: unconstrained `predC` →
property of the encoder → property of `target_sum` → N2 → back to the gate.

Biting the other way: the **deployed** encoder (the plain base-8 decomposition of
`wots_digest`) is **not a model of `two_encodings` at all** — independently
confirmed here with the witness pair `(0,…,0,1)` vs `(0,…,0,2)`, matching
`Identification.ec`'s `(1, 0)`. The axiom is faithful only *restricted to
`predC`-satisfying digests*, which remains the right long-run repair and is still
not made in `base-c10`.

## 3. CORRECT TREATMENT

| option | verdict |
|---|---|
| **(a) carry N2 as a premise in the artifact** | **RIGHT**, and permanently — it is independent. But label it honestly: required for the theorem to have *content*, not for it to be *valid*. |
| **(b) charge `Pr[grind_fails]` in a COMPLETENESS statement** | **RIGHT** for the deployed claim. `Pr[honest sig verifies] >= 1 - p_nu`. |
| (c) charge it in the security bound | **WRONG**, and not "conservative". The +C gate only *narrows* the accept set (`WOTS_C_Scheme.ec:101,103`, the `/\ okC` conjunct), so grind failure removes honest signatures and never admits a forgery. `grind` is total, so no reduction aborts and there is no seam for an additive term. A `p_nu` summand would mislabel an availability event as a security loss — a false statement about the artifact, not a safety margin. |
| (d) dissolve via the paper's `r = λ` | **WRONG as stated.** Deployed `r` is not λ: the firmware searches `0..10_000_000` (`wots.rs:62`) — 2^23.25 tries, not 2^128, a **2^104.7** shortfall. What does transfer is the paper's Appendix-C *bounded-k* computation, which collapses into (b) with a number attached. |

## 4. THE DEPLOYED NUMBER — computed twice, independently, agreeing

```
codewords summing to 205      = 2^114.0941
space 8^43                    = 2^129           (exact)
per-counter success p         = 2^-14.9059      ~ 1/30,698
expected tries per signature  = 30,698
Pr[fail in 10^7 tries]        = (1-p)^1e7 = e^-325.8 = 2^-470
```

| index set | bound |
|---|---|
| one WOTS+C grind | 2^-470 |
| honest lifetime (2 grinds/sig × 65,536 sigs, invariant #7 cap) | 2^-453 |
| adversary steering `(ps,ad,m)` with 2^128 hash queries | **2^-342** |
| FORS+C leg (`p = 2^-11`, same 10^7 cap) | 2^-7046 |

**Negligible** — ~342 bits of slack at Cat-1. Three caveats that must travel with
the number: (i) it is an RO heuristic over `wots_digest`, not a theorem; (ii) the
counter axis is keyed by a device-held seed, so the 2^128 multiplier is very
conservative — it is not attacker-steerable; (iii) it is a **deployment** number
and does not transport into the EC model unqualified, because model `ThC` has
codomain `dgstblock = 8n = 128` bits while the deployed digit map consumes 129
(`FINDING-thc-width-is-unfixed.md`, still BLOCKING).

Aside worth keeping: `E[tries] = 30,698` at `T=205` versus `37.8` at the optimal
`T=150`. The choice is deliberate — it buys 96 rather than 151 verifier chain
steps (`SPHINCsC10Asm.sol:176`). Grind cost was traded for on-chain gas.

## 5. SECURITY OR AVAILABILITY?

**Availability in the deployment; vacuity-assurance in the proof. Not in the
security-advantage ledger.**

Deployed: grind failure → `panic!` (`wots.rs:74`) → the handler zeroizes
secure-world state, paints `! FATAL ERROR / Secrets wiped / Power-cycle to retry`,
and parks in WFI. **Fail-closed**: no partial signature, no forgery path, no
counter bump. Cost is a lost signing session plus a power-cycle and PIN re-entry;
`gated_unlock` resets page 124 on a correct PIN, so no attempt is permanently
consumed. At 2^-470 this branch is a broken-SHA256 indicator, not an attack
surface, and halting is the right response.

**Do not generalize this to "p_nu is always availability".** The FORS-side twin
`good_pos` (`cdrafts/FORS_C10.ec:208`, consumed by `query_ll` at `:345-346`) is a
**live axiom inside the certified closure**, needed for signing-oracle
losslessness — a genuine precondition of the security statement. WOTS+C gets a
premise and FORS+C10 gets an axiom because WOTS+C's grind is a total op while
FORS+C10 uses rejection sampling.

## 6. THE STRUCTURAL FINDING — the certified closure asserts no non-vacuity at all

**`cdrafts/SphincsC10Content.ec` is absent from `closure-c10.txt` (0 matches) and
has no `.eco`** — verified. It has never been compiled as a target. Every
anti-vacuity result in the development lives in that one uncompiled file
(CONCLUSIONS 2-6, `MODEL_N1_N2_nondegenerate`, `gate_passes_on_ground_counter`).

So the receipts this session has been accumulating certify a chain that contains
**no statement that the capstone is non-vacuous**. That is a bigger gap than N2.

## 7. THREE FALSE CLAIMS IN THE REPO, ONE OF THEM MINE

* **`cdrafts/FORS_C.ec:84-88`** — *"In WOTS+C, a 'wrong' counter still yields a
  WOTS-TW-verifiable signature … grind-failure is a pure no-op"* is **FALSE**,
  four ways: the port's own model (`WOTS_C_Scheme.ec:101,103`, `/\ okC`); the
  firmware verifier (`wots.rs:160`, zero-pk sentinel → Merkle mismatch); the
  on-chain verifier (`SPHINCsC10Asm.sol:165-170`, hard `revert`); and the signer
  (`wots.rs:74` `panic!` — on failure *no signature exists at all*, strictly worse
  than a no-op). Its *conclusion* survives, but for a different reason: the gate
  is monotone-restrictive, not that the defect cancels.
* **`cdrafts/Grind.ec:22-27`** — *"`grind_fails` is CARRIED as an additive term
  rather than assumed away"*, and **`cdrafts/STCR_C.ec:77`** — *"carried term
  `Grind.grind_fails`"*. Both **FALSE**: comment-stripped search shows
  `grind_fails` appears in **zero** statements, games or proofs outside
  `Grind.ec` — 7 occurrences, all comments. It is stated and dropped.
* **Mine:** `WOTS_C_Real.ec:268` cited the lemma at `:260-262`; my own edits this
  session pushed it to `:314-316`. Fixed, with the drift noted in place.

`Grind.ec` and `STCR_C.ec` are **not** edited here: they are closure files still
byte-identical to the concurrent session's `drafts/`, and diverging two more of
them to correct comments is not worth the audit cost. The false claims are
recorded here instead.

## 8. NEXT

For the **deployed** claim: **nothing further is needed.** The number is computed,
negligible, fail-closed, and not attacker-steerable.

For the artifact, in priority order:

1. **Compile `SphincsC10Content.ec` and put it in the closure** — §6. Note it has
   a suspected internal defect: its N1 premise is stated in `digitsum` at a
   *shadowing* lemma binder `target_sum`, while `predC` is now defined in
   `cw_sum` at the global `target_sum`, and **no `cw_sum` ↔ `digitsum` bridge
   lemma exists** anywhere.
2. Record N2 as independent with both witness models — this document.
3. Fix the stale/false artifacts in §7.

**Do not**: try to prove N2; add a `p_nu` term to the EUF-CMA bound; or
axiomatize counter-fibre surjectivity of `thfc` (it needs `|cntr| >= |dgstblock|`
— 2^32 vs 2^128, false).

`Pr[G /\ COLL]` remains uncharged. `WOTS_TW_ES.ec:1353` remains ADMITTED.
**C10 is not proven at deployed parameters.**

---

## UPDATE 2026-07-31 — the verdict above STANDS, but the proof no longer needs N2

Nothing in sections 1–3 is retracted. N2 is still independent over the closure:
not provable, not refutable, and no work over abstract `ThC` closes it. What
changed is that the WOTS-TW leg no longer has to **assume** it — it can **pay**
for it instead.

`cdrafts-fork/GFailCharged.ec` + `cdrafts-fork/XmssmtCCCharged.ec` carry a chain
in which the N2 premise is replaced by an additive summand:

```
Pr[GAME1_INT(A, O_Default, OC_Default).main() @ &m :
     res /\ gfail_of O_Default.ps O_Default.qs]
```

running from `interactive_hop2_charged` up to
`EUFNAGCMA_FLSLXMSSMTTWCESNPRF_charged` — the lemma
`SphincsC10CapstoneWired.ec:624` applies — with **no N2 premise anywhere in it**.

**Why this was possible without reproving anything.** `Grind.ec:104`'s
`grindP_iff`, read at the `STCRC_WC` clone (`f <- ThC`, `prop <- predC`), makes

```
grind_fails ps ad m  \/  predC (ThC ps ad m (grindC ps ad m))
```

a *tautology*. The gate invariant carried through the oracle coupling was
weakened by that disjunct, which is free; N2 then had to be consumed at exactly
one place rather than maintained at every oracle step. `interactive_hop2`'s
statement is unchanged as a result, so the existing N2-carrying chain and all its
consumers are untouched and the two chains coexist.

**This is a relocation, not a resolution — and THIS document is half of why.**
Because N2 is independent, the charged summand is likewise not provably zero;
`scratch/synth_charged_canary6.ec` is a registered MUST-FAIL control asserting
`Pr[res /\ gfail] = 0` *without* N2, and it is verified to fail on `cannot prove
goal (strict)`. Section 1 is the reason it must.

**CORRECTION 2026-07-31 (adversarial review).** An earlier version of this update
went further and said that in section 1's own "N2 fails" model the summand
"equals the whole success mass". That does not follow, and the error is worth
recording because it is easy to repeat. In that model `predC (ThC ..)` is false
*everywhere*; but `WOTS_C_ES.verify` returns `pk-match /\ okC` with
`okC = predC (ThC ps ad m counter)` (`cdrafts-fork/WOTS_C_Scheme.ec:101-103`),
and `GAME1_INT`'s `res` conjoins `is_valid`
(`cdrafts-fork/WOTS_C_Interactive.ec:940-942`). So there `res` is false, the
charge is **0**, and the claim reads 0 = 0 — it establishes nothing.

Correctly stated: N2 being false is **necessary** for a nonzero charge but not
**sufficient**. A positive charge requires a *mixed* model in which the grind
fails on some **queried** tuple while the run still succeeds; no such model, and
no lower bound of any kind, exists in this repository. And a MUST-FAIL control
shows only that the solver cannot *derive* a bound — never that a probability is
positive. Conflating those two was the defect. The honest position is that the
term is neither known-positive nor known-zero: it is simply unbounded here.

The converse direction is proved too: `gfail_zero_under_N2` shows the summand is
0 under N2, and `interactive_D1_MA_from_charged` /
`leaf_reduction_MEUFGCMAWOTSC_bound_from_charged` re-derive the original
N2-carrying statements verbatim from the charged ones. So the charged chain
**subsumes** the N2 chain rather than sitting beside it.

Bounding the term numerically still needs the concrete hash and remains out of
scope, exactly as `Grind.ec:22-27` says of the paper's p_nu.

STILL N2-CARRYING (not converted): the capstone lemmas
`SphincsC10CapstoneWired.ec:484` and `:841`, and `XmssmtCC_All.ec:8816`
(`_Unfolded`).
