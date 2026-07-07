# Mechanizing C10 EUF-CMA in EasyCrypt — a sourced feasibility verdict (2026-07)

**Bottom line:** turning the cited `Crypto.EUF_CMA_SPHINCSplusC` axiom
(`contracts/verification/lean/SphincsCVerify/Crypto/EUFCMA.lean`) into a
machine-checked theorem is **NOT a multi-person-year effort**. The expensive
part — a tight, sorry-free EasyCrypt EUF-CMA proof of *standard* SPHINCS+ — is
**already public, maintained, and modular**. The real cost is the delta to our
two `+C` deviations (WOTS+C, FORS+C), for which paper-level security reductions
already exist. Honest single-person estimate: **~6–18 person-months**, with the
regime set by a small number of named, checkable facts. This corrects the
"~50k lines, multi-person-year" framing previously carried in `EUFCMA.lean`.

Scope note: this is the effort to mechanize the **qualitative reduction** that
bounds the residual adversary advantage `ε(A)` (the `BreaksHash` token today).
The **quantitative / usage-cap** layer is *already* Lean-kernel-checked
(`Crypto/Quantitative.lean`: the `Q·2⁻¹²⁸` query term and the generic
`(q+q²)·2⁻ⁿ` multi-target term — the terms a usage cap controls). This port
would replace the cited `ε(A)` with a proved bound; it does not change
`theft_free`'s safety guarantee, which is EUF-CMA-free by construction.

Evidence base: a 2026-07 adversarial deep-research pass (15 claims confirmed at
3-vote, 2 refuted, sources §"References"). Where a load-bearing fact is
**not** triple-confirmed it is flagged INLINE as UNVERIFIED.

---

## 1. What C10 actually is (the delta that must be mechanized)

C10 = SPHINCS+ with **two** structural deviations from FIPS 205, both from the
"SPHINCS+C" line (Hülsing et al., ePrint 2022/778 / PQC-2022; family origin
also ePrint 2025/2203). See `docs/verification/c10-fips205-delta-audit.md` for
the byte-level map.

- **WOTS+C** — no checksum chains (`l=43`, all message digits). The signer
  grinds a 32-bit `count` until the base-8 digit sum of a count-tweaked digest
  equals `target_sum=205`; the verifier re-hashes with `count` and reverts if
  `Σdigit≠205`. The constant-sum constraint does the checksum's job.
- **FORS+C** — grinds the message randomizer `R` until the last (`k−1=12`th)
  FORS index is forced to zero, dropping one auth path.

Both are **count/rejection-grinding** constructions (2022/778): sign by
searching for a counter that lands the digest in a compressible subset.

## 2. Part (A) — replaying standard SPHINCS+ is ZERO cost (confirmed)

`github.com/MM45/FV-SPHINCSPLUS-EC` is a **complete, public, machine-checked**
EasyCrypt artifact. Its top-level `lemma EUFCMA_SPHINCS_PLUS` in
`proofs/SPHINCS_PLUS.ec` bounds `Pr[EUF_CMA(SPHINCS_PLUS, A, O_CMA_Default)]`,
it re-checks under EasyCrypt release **2026.02** (Z3 4.13.4 / Alt-Ergo) via
`make check`, and it is **actively maintained** (193 commits, last push
2026-05-31, MIT). [conf 3-0]

This is the artifact behind Barbosa–Dupressoir–Hülsing–Meijers–Strub, "A Tight
Security Proof for SPHINCS+, Formally Verified," ASIACRYPT 2024 (ePrint
2024/910). The prior "we would replay ~50k lines" cost is therefore **not
incurred** — the replay is done and reusable.

## 3. Part (B) — the WOTS+C / FORS+C delta is a MODULAR swap, not a ripple

Three independently-confirmed facts line up at the *same* interface:

1. **The EasyCrypt dev is modular by construction.** `SPHINCS_PLUS.ec` composes
   its components through *parameterized theory clones* — `clone import FORS_ES
   as FTWES with …` (≈ line 455) and `clone import FL_SL_XMSS_MT_ES as
   FSSLXMTWES with …` (≈ line 546). FORS and the WOTS/XMSS-hypertree enter the
   top-level theorem at **declared interfaces**; the README states it verifies a
   *modular* restructuring of the Hülsing–Kudinov ASIACRYPT-2022 tightness
   proof. [conf 3-0] So a variant is a component-level swap, not a monolith
   rewrite.

2. **The WOTS layer is already isolated** as a standalone `WOTS-TW` scheme with
   its own (multi-instance) d-EU-naCMA proof — the clean interface a WOTS+C
   proof must satisfy or replace (ePrint 2022/346, Hülsing–Kudinov "Recovering
   the tight security proof of SPHINCS+"). [conf 3-0]

3. **WOTS+C was *designed* to hit exactly that interface.** The SPHINCS+C paper
   (2022/778) states it directly: *"By obtaining a d-EU-naCMA security proof for
   WOTS+C one can just substitute WOTS-TW in SPHINCS+. This results in adding an
   S-TCR(+C) term to the security of SPHINCS+"* (Theorem 5.2 gives the full
   bound alongside the standard PRF / PRF_msg / ITSR / SM-UD / SM-TCR / SM-PRE /
   SM-DSPR terms). [conf 3-0]

So the paper-level modularity and the EasyCrypt modularity **meet at the same
seam** (`WOTS-TW`). The overall bound changes by **exactly one added term**.

### Do the +C reductions exist? Yes — one full, one sketch.

- **WOTS+C has a *full* tight EU-CMA reduction** in 2022/778 Appendix B,
  relating it to WOTS+ security plus an m-eTCR-style message-hash property, with
  the crucial structural finding that constant-sum *"constrains the adversary
  rather than easing its task."* [conf 3-0] (Two competing claims that the paper
  merely *asserts* equivalence / offers only a heuristic analysis were
  **REFUTED** 0-3 — it is a real reduction.)
- **CAVEAT — the load-bearing gap:** the **d-EU-naCMA** proof (the model
  actually needed to substitute into SPHINCS+) is only a **sketch in Appendix
  D**. [conf 3-0] Mechanization must *fill that sketch to full rigor* — bounded
  work (complete an expert author's sketch), but it is the single largest chunk
  and the main source of schedule risk.

### The one genuinely-new modeling object (count-grinding)

Grinding forces a new hash notion the standard SPHINCS+ stack lacks:
**S-TCR(Prop)** — "special target collision resistance," parameterized by a
boolean predicate, proved via a dedicated **grinding oracle** `O^{+C}(P,·,·)`
that outputs `Th(P,T,M‖i)` for a counter `i` meeting the constant-sum
condition. [conf 3-0] Any EasyCrypt mechanization must formalize this
rejection-sampling game object — but it is *one* new game, already defined and
proof-sketched in the paper (2022/778).

### FORS+C

FORS+C's R-grind of the forced-zero index modifies the **`MCO_ITSR.ITSR`** term
(interleaved target-subset resilience — the FORS message-to-indices property) in
the top-level bound, and drops one auth path (a structural simplification).
[conf 2-0, from the FV-SPHINCSPLUS-EC final-bound term list] The R-grind is a
second rejection-sampling model of the same shape as WOTS+C's.

## 4. The security *debit* is orthogonal (dissolves the main worry)

The "sec_18 = 118.3 bits" curve (upstream `sweep_d2_fluhrer_dang.py`, recorded
in the delta-audit) is **not** a WOTS+C weakness and **not** a +C-specific
reduction:

- **Fluhrer & Dang (2024/018) explicitly EXCLUDE SPHINCS+C** — their tables
  cover only standard parameter-set variation (`n,h,d,a,k,w`), and their
  analysis is a **concrete attack-success-probability** Poisson leaf-collision
  computation, **not** a reduction (no SM-DT-TCR / ITSR games appear). [conf
  3-0, two claims] The curve is that few-time-signature formula *applied to*
  C10's `d=2` params.
- That debit is the ordinary many-signatures leaf-collision term — exactly the
  `Q·2⁻¹²⁸` query term **already** kernel-checked in `Quantitative.lean` and
  bounded by the 2¹⁶ usage cap (invariant #7/#9). It is orthogonal to the
  WOTS+C reduction, which stays a clean add-one-term swap.

Combined with "constant-sum constrains the adversary" and the CRYPTO-2023
finding that constant-sum WOTS+ has **no known forgery/security concern** (the
only reported "flaw" was in a competing DAG design, not in constant-sum WOTS;
ePrint 2023/850) [conf 3-0, two claims], there is no evidence the +C change
damages the delicate tightness argument.

## 5. The residual risk, named

- The **2020 tightness flaw** (Kudinov–Kiktenko–Fedorov) was located
  *specifically in the WOTS layer* — the exact layer WOTS+C modifies. [conf 3-0]
  This is why WOTS-TW is isolated at all; it makes the swap *tractable* rather
  than terrifying, but the swap does land on historically-delicate machinery.
- The HK22 repair rests on a nontrivial hash-property stack (quantum query
  lower bounds, undetectability, PRF), which a WOTS+C proof inherits. [conf 3-0]
- **UNVERIFIED but decisive** (verification votes were truncated by a session
  limit, not refuted): a claim that in the dev, *"WOTS-TW security is parametric
  over an abstract message encoding, and the checksum encoding is a separate
  instantiation module."* If TRUE, WOTS+C is nearly a drop-in (swap the encoding
  instantiation) and pushes hard toward the best case. **This is the single
  highest-value fact to confirm** — a ~30-minute direct read of `WOTS_TW.ec` in
  the repo settles it.

## 6. Part (C) — calibrated estimate

| Component | Cost | Why |
|---|---|---|
| Replay standard SPHINCS+ | **0 pm** | done, public, maintained, sorry-free (§2) |
| WOTS+C mechanization | ~3–6 pm (dev-fluent) · 6–12 pm (newcomer) | formalize S-TCR(Prop)+`O^{+C}`; **fill the Appendix-D d-EU-naCMA sketch**; swap the WOTS-TW clone; add one term |
| FORS+C mechanization | ~2–6 pm | R-grind model + the `MCO_ITSR.ITSR` modification + drop one auth path |

**Honest figure: ~6–18 person-months, one qualified EasyCrypt+SPHINCS+ person.**

- Plural **"person-years" is NOT defensible** on this evidence.
- Best case (~6 mo): an MM45 author reusing their own S-TCR(+C) material, and
  WOTS-TW turns out parametric over the encoding (§5 UNVERIFIED).
- Worst case (~18 mo ≈ a person-year): a newcomer ramping on a 193-commit dev,
  the Appendix-D sketch has real gaps, and the FORS+C ITSR modification is
  fiddly. Even the worst case is *single*-person-year, not multi.

**What sets the regime:** (1) completeness of the Appendix-D d-EU-naCMA sketch;
(2) whether WOTS-TW is parametric over the encoding (§5); (3) whether the
grinding oracle / S-TCR(Prop) fits EasyCrypt's existing `SM_DT_*` machinery or
needs new pRHL rejection-sampling scaffolding.

## 7. Part (D) — the smallest decisive first increment

**Formalize `S-TCR(Prop)` + the `O^{+C}` grinding oracle in EasyCrypt and prove
WOTS+C in the d-EU-naCMA model against the same `WOTS-TW` interface
`SPHINCS_PLUS.ec` already instantiates** — i.e., fill Appendix D and check that
substituting it changes the top-level bound by *exactly* the one `S-TCR(+C)`
term Theorem 5.2 predicts.

- If the grinding oracle + S-TCR(Prop) formalize cleanly and the d-EU-naCMA
  proof reuses the WOTS-TW scaffolding in a few weeks → **"months" regime
  confirmed**; commit to the full port.
- If formalizing the grinding oracle exposes pRHL subtleties that don't fit the
  existing `SM_DT_*` machinery → the longer end; re-plan.

Cheap pre-step (hours, no EasyCrypt): read `WOTS_TW.ec` to settle §5-UNVERIFIED,
and read Appendix D of 2022/778 to gauge the sketch's completeness.

## 8. Recommendation

This is a **credible, de-riskable** track, not a research moonshot — a genuine
"cited → proved" upgrade for the last unproven leg (A5). It is **not** required
for any current claim (`theft_free` safety is EUF-CMA-free; the quantitative
cap layer is already proved). Sequence: do §7's cheap pre-step + first
increment *before* committing budget; the ideal executor is someone from the
MM45/Barbosa orbit. Until then, `EUFCMA.lean` correctly records A5 as a *cited*
assumption — now with an honest, sourced cost for closing it.

## References

- FV-SPHINCSPLUS-EC — `github.com/MM45/FV-SPHINCSPLUS-EC` (EasyCrypt, MIT, 2026.02).
- Barbosa, Dupressoir, Hülsing, Meijers, Strub — "A Tight Security Proof for
  SPHINCS+, Formally Verified," ASIACRYPT 2024, IACR ePrint **2024/910**.
- Hülsing et al. — "SPHINCS+C: Compressing SPHINCS+ With (Almost) No Cost,"
  PQC-2022, IACR ePrint **2022/778** (Thm 5.2; App. B WOTS+C reduction; App. D
  d-EU-naCMA sketch; S-TCR(Prop) + `O^{+C}`).
- Hülsing, Kudinov — "Recovering the Tight Security Proof of SPHINCS+,"
  ASIACRYPT 2022, IACR ePrint **2022/346** (WOTS-TW; the 2020 WOTS-layer flaw).
- Fluhrer & Dang — IACR ePrint **2024/018** (concrete few-time curve; excludes +C).
- Constant-sum WOTS+ size-optimality / no-security-concern — IACR ePrint
  **2023/850** (CRYPTO 2023).
- +C family origin also cited as IACR ePrint **2025/2203** (upstream corpus).

*In-repo: `contracts/verification/lean/SphincsCVerify/Crypto/{EUFCMA,Quantitative}.lean`,
`docs/verification/c10-fips205-delta-audit.md`,
`contracts/verification/docs/EUF_CMA_INCONSISTENCY.md`.*
