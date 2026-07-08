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

## UPDATE 2026-07-07 — the port is UNDERWAY, and WOTS+C single-instance is MACHINE-CHECKED

This stopped being hypothetical. A live EasyCrypt port exists at `~/repos/c10-eufcma-port`
(local, no remote; MM45 `FV-SPHINCSPLUS-EC` + `FV-XMSS-EC` cloned in-tree; checked under
the `ec-r2026` opam switch with Alt-Ergo 2.6.0). Milestone reached:

- **Single-instance WOTS+C EU-naCMA (`EUFNACMA_WOTSC_C2`) is FULLY machine-checked, ZERO admit**
  (independently re-verified: clean rebuild EXIT 0, zero admit tactics in `Grind.ec` +
  `WOTS_C_Reduction.ec`). The proven bound is EXACTLY the paper's Thm 5.2 shape —
  `Pr[EUF_NACMA_WOTSC(A)] <= Pr[S_TCR_C(R_STCRC_WOTSC(A))] + Pr[EUF_NACMA_WOTSTW(R_WOTSTW_WOTSC(A))]`
  — under three explicit, paper-faithful hypotheses: `1 <= p_tgts`, address-separation
  (A never queries the collection oracle at the challenge tweak), and `encode_bridge`
  (`encode_msgWOTS_C p a x c = encode_msgWOTS (ThC p a x c)` — the DEFINITION of the +C encoding).
- Built from: the Algorithm-9 reduction `R_STCRC_WOTSC` (hop1, S-TCR(+C)) + the Algorithm-10
  reduction `R_WOTSTW_WOTSC` (hop2, WOTS-TW) + the new `S-TCR(Prop)` game + grinding oracle on
  the REAL `TweakableHashFunctions.eca` types, composed via `EUFNACMA_WOTSC_C2`. `Grind.ec` is
  zero-admit (the operational grind-search `= grind` op is proven).
- **The `p_ν` (grind-failure) worry was RESOLVED as a reduction ARTIFACT, not inherent.** The
  first-pass reduction sent a sentinel `d = witness` on grind-failure, which diverged from the
  honest signer and appeared to force a `+Pr[grind_fails]` term. Because `grind` is TOTAL and the
  sign-correspondence holds for ANY counter, embedding the digest UNIFORMLY as `ThC(m, grind(m))`
  removes the divergence entirely — so WOTS+C EU-naCMA carries **no** p_ν term (consistent with
  p_ν living, if anywhere, at the top-level SPHINCS+ bound / the FORS+C R-grind, not the WOTS+C hop).

**Calibration against §6:** the WOTS+C leg — the load-bearing "+C novelty" — went from a cited
axiom to a machine-checked reduction in a handful of focused sessions, matching the paper's
modular prediction and the S-TCR(+C) single-added-term structure. This is empirical support that
the estimate's **best case is the right regime for the WOTS+C leg**, not the worst. It does NOT
retire the estimate: the remaining legs (D.1 multi-instance WOTS+C → FORS+C → composition into
`EUFCMA_SPHINCS_PLUS`) are the bulk, and FORS+C's R-grind is where a genuine top-level abort/p_ν
term may actually live. Progress log + the exact reduction structure: `~/repos/c10-eufcma-port/PROVENANCE.md`.

---

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
- **RESOLVED 2026-07-07 by direct repo recon — and it INVERTS the best case
  below.** The parametricity claim is TRUE: `WOTS_TW_ES.ec:569`
  `op encode_msgWOTS : msgWOTS -> emsgWOTS` is a fully abstract operator (never
  defined; its only structural assumption is `axiom two_encodings`,
  `WOTS_TW_ES.ec:572`), and the base repo's `FV-XMSS-EC/proofs/WOTS_TW_Checksum.ec`
  is exactly a separate `clone import WOTS_TW with op encode_msgWOTS <- …` that
  `realize`s `two_encodings` — the clean encoding-swap the checksum uses. **BUT
  WOTS+C CANNOT use that seam** (two structural reasons, both grep-checkable):
  (1) `encode_msgWOTS` is a pure, deterministic, *post-hash* function of the
  message alone, whereas WOTS+C's compression is `base_w(Th+C(P,T,m,count))` —
  it needs the public seed `P`, the address `T`, and the grinded `count`, which
  live *upstream* of the encode seam and are inexpressible as an `encode_msgWOTS`
  instantiation; (2) `two_encodings` is an unconditional `axiom`, and the
  constant-sum-via-hash map breaks it whenever two messages collide under
  `Th+C` — that gap *is* `S-TCR(+C)`, a computational property, which cannot
  discharge an axiom. So parametricity buys **black-box reuse of the 6314-line
  WOTS-TW theorem** (never reopened; its stated bound `MEUFGCMA_WOTSTWESNPRF`,
  `WOTS_TW_ES.ec:6269`, is what Thm 5.2's added term sits beside) — but NOT an
  encoding drop-in. WOTS+C needs a **new scheme fragment + a new game
  (`S-TCR_C`) + the App-D reduction**. (Evidence: the recon workspace
  `~/repos/c10-eufcma-port/` — `PLAN.md` + typechecking drafts `STCR_C.ec`,
  `WOTS_C_Encoding.ec`.)

## 6. Part (C) — calibrated estimate

| Component | Cost | Why |
|---|---|---|
| Replay standard SPHINCS+ | **0 pm** | done, public, maintained, sorry-free (§2) |
| WOTS+C mechanization | ~3–6 pm (dev-fluent) · 6–12 pm (newcomer) | formalize S-TCR(Prop)+`O^{+C}`; **fill the Appendix-D d-EU-naCMA sketch**; swap the WOTS-TW clone; add one term |
| FORS+C mechanization | ~2–6 pm | R-grind model + the `MCO_ITSR.ITSR` modification + drop one auth path |

**Honest figure: ~6–18 person-months, one qualified EasyCrypt+SPHINCS+ person.**

- Plural **"person-years" is NOT defensible** on this evidence.
- **CORRECTED 2026-07-07 (repo recon):** the ~6-month best case is NOT
  supported — it rested on the "encoding drop-in," now shown structurally
  impossible (§5 RESOLVED). WOTS+C requires a *new scheme* + a *new game*
  (`STCR_C.ec`) + the App-D reduction, not a `clone … with op encode_msgWOTS`.
  **Land the honest figure MID-BAND of the 6–18-month band**, with the App-D
  pRHL obligations (grinding-oracle losslessness; the Algorithm-10 case-split)
  as the named schedule risk, and FORS+C the smaller second increment on the
  same rejection-sampling scaffolding.
- (superseded) Best case (~6 mo): an MM45 author reusing their own S-TCR(+C)
  material, and WOTS-TW turns out parametric over the encoding (§5 UNVERIFIED).
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

## 9. Progress — 2026-07-07 (recon + toolchain + first typechecking drafts)

EasyCrypt was installed on the dev box (git-`dev` + Alt-Ergo 2.6.0, opam
`checkct` switch) and the §7 first increment was STARTED. Work product lives in
a separate repo `~/repos/c10-eufcma-port/` (not pushed; PQSigner untouched):

- **Module-structure map (`PLAN.md`).** `EUFCMA_SPHINCS_PLUS`
  (`SPHINCS_PLUS.ec:4338-4370`) has 12 summands mapping term-for-term onto Thm
  5.2. `S-TCR(+C)` slots in as a sibling of the WOTS-layer terms
  `(w-2)·SM_DT_UD_C` / `SM_DT_TCR_C` / `SM_DT_PRE_C` (`:4360/4364/4366`);
  FORS+C changes term #3 `MCO_ITSR.ITSR` (`:4347`); the substitution seam is
  `clone import FL_SL_XMSS_MT_ES` (`:546`). Game templates:
  `TweakableHashFunctions.eca` `SMDTTCRC` (`:542-581`, closest sibling).
- **Typechecking drafts.** `STCR_C.ec` (the `S-TCR(Prop)` game + `O^{+C}`
  grinding oracle, paper Def C.1) elaborates standalone; `WOTS_C_Encoding.ec`
  (the WOTS+C scheme fragment + `Th+C` + the D.1 reduction skeleton, cloning
  `STCRC`) elaborates and its `realize` was mutation-tested (non-vacuous). Both
  under EC-dev + Alt-Ergo, exit 0. Rest on 3 explicit assumptions; **`grindCP`
  (grinding-oracle losslessness) = App-D gap #1, parked as an axiom — its
  discharge is the concrete first rigor step.**
- **App-D assessment.** Thm D.1 + a ~15-line sketch; names the hardest step
  (deferred public seed, which maps onto the dev's existing `Oracle_THFC`).
  Three under-justified pieces mechanization must fill: grinding losslessness
  (the pRHL obligation above), the Algorithm-10 case-split, multi-target
  counting to `q6`. First two are the schedule risk; none conceptually novel.
- **Toolchain caveat.** EC-`dev` surface syntax is compatible (all scheme
  *declarations* elaborate) but the repo's proof SCRIPTS carry r2026.02→dev
  tactic drift (a probe failed inside a proof at `WOTS_TW_ES.ec:1433`). Run the
  full port under the repo's pinned r2026.02, or budget proof-script upkeep;
  add Z3 4.13.4 for proof discharge (Alt-Ergo suffices for the definition layer).

Net: the "months, not years" verdict is REINFORCED by the real repo (modular
clone seams; a stated reusable WOTS-TW bound; a genuinely singular added term),
while the ~6-month best case is RETRACTED (§5/§6). The mechanization has a
concrete, typechecking starting point and a named first rigor obligation.

### UPDATE 2026-07-07b — gap #1 DISCHARGED, S-TCR(+C) instantiated on REAL types

The named first rigor obligation (App-D gap #1) is now discharged, the game is
reconciled to the real repo, the r2026.02 toolchain is stood up, and the added
term is instantiated on the real SPHINCS+ types. Artifacts in
`~/repos/c10-eufcma-port/drafts/` (commits `1f3c9ce`, `3be8dd6`, `f7184bb`).

**Honest ledger (proved / assumed / admitted / remaining):**

- **PROVED (real EasyCrypt, `qed`, no `admit`):**
  - `Grind.ec` — gap #1 discharge. The unconditional `axiom grindP` is GONE,
    replaced by: `grind` a TOTAL deterministic search over the finite counter
    type; `grind_correct` (∃ good counter ⇒ prop holds) PROVED; `grind_fails_iff`
    (the p_ν failure event) PROVED; **`GrindSearch_search_ll` — losslessness /
    termination of the bounded search PROVED** (the obligation App D elides);
    `grind_fails` exposed as a first-class carried event.
  - `STCR_C.ec` — the `S-TCR(Prop)` game reconciled to the REAL
    `TweakableHashFunctions.eca` (instantiated `in_t := msg×cntr`, `f := Th+C`),
    so its collection oracle IS the repo's `Th_lambda`; grinding via the proved
    total op (no `grindP`); `query_targets_predC` + `O_STCRC_query_good` PROVED.
  - `WOTS_C_Real.ec` — **`InSec^{S-TCR(+C)}(Th+C; q6)` instantiated on the REAL
    WOTS types** (`pseed`/`adrs`/`dgstblock`/`msgWOTS`), reusing the real
    `dpseed`; the added Thm-5.2 term is now a concrete game, and grinding is
    proved over the real types. Compiles under the real `WOTS_TW_ES.eco`.
- **DEFINED (real modules, zero admits) — `WOTS_C_Scheme.ec`:** the WOTS+C
  scheme `WOTS_C_ES` (keygen reused; `sign` grinds the counter + encodes via
  `Th+C` + chain-walks with `cf`/`set_chidx` verbatim, returns `sigWOTS*cntr`;
  `verify` recomputes the encoding from `(m,counter)`, rebuilds the pk, and gates
  on BOTH pk-match AND `predC` on the recomputed digest) + the d-EU-naCMA game
  `M_EUF_GCMA_WOTSC_NPRF` (mirrors `M_EUF_GCMA_WOTSTWESNPRF`; collection oracle =
  real `FC.Oracle_THFC`). **Consequence: every term of Thm D.1 is now a concrete,
  nameable game** — LHS `M_EUF_GCMA_WOTSC_NPRF`, the added `STCRC_WC.S_TCR_C`, the
  reused `M_EUF_GCMA_WOTSTWESNPRF`.
  - **PROVED prerequisite properties of the scheme (zero admits):**
    `sign_counter_predC` — every honest WOTS+C signature carries a `+C`-valid
    counter (threads the discharged grinding through `sign`); and the full
    losslessness chain `pkfs_ll` / `keygenR_ll` / `WOTS_C_ES_keygen_ll` /
    `WOTS_C_ES_sign_ll` / `O_MEUFGCMA_WOTSC_query_ll` (the scheme procs +
    signing oracle terminate) — exactly the facts the Alg-9/Alg-10 reduction
    proofs consume. **21 `qed`-closed lemmas total across the five drafts (incl. Thm C.2 proved), 3
    labelled admit (the orthogonal Grind bridge).**
- **ASSUMED (modelling axioms, NOT cryptographic gaps):** counter type finite
  (`CntrFT.enum_spec` — the C10 counter is a 32-bit word); `Th+C`/`predC`
  abstract ops (the C10-specific hash/predicate). `dpseed` losslessness and
  `p ≥ 0` are discharged (real lemma / trivial).
- **ADMITTED (labelled, orthogonal):** `GrindSearch_run_computes_grind` — the
  operational-loop↔pure-op bridge. NOT a security axiom and NOT part of the gap-#1
  discharge (every game/reduction uses the proved op directly); provable, left
  admitted after the EC `wp`/`while` goal-shape resisted a one-session close.
- **Thm C.2 (single-instance WOTS+C EU-naCMA) — PROVED modulo 2 game-hops
  (`WOTS_C_Reduction.ec`, commit `bb…` / 2026-07-07b).** Both reduction BODIES are
  now real, zero-admit modules faithful to the paper pseudocode: `R_STCRC_WOTSC`
  (Alg 9) and `R_WOTSTW_WOTSC` (Alg 10 — grinds the +C seed via `Th_lambda` in
  `choose()` and defers signing to the revealed `pp`; the naCMA structure
  dissolves the "public-seed availability" worry). Single-instance games
  `EUF_NACMA_WOTSC` / `EUF_NACMA_WOTSTW` / `GAME1_WOTSC` are defined;
  `EUFNACMA_WOTSC_C2` (Thm C.2) is **PROVED** by composing the two game-hops
  (`smt` over the `Pr` terms — genuinely chains them, not vacuous). The only open
  obligations are the two hop lemmas `WOTSC_C2_hop1` / `WOTSC_C2_hop2` — the
  paper's two reduction-correctness pRHL arguments — admitted and clearly
  labelled. **3 admits total across the port** (this pair + the orthogonal Grind
  bridge); **21 `qed`-closed lemmas.**
- **REMAINING:** discharge the two Thm-C.2 hop admits (the pRHL fill); the
  collection unification (`STCRC_WC.Col` ≡ the repo `FC`, one `Th_lambda`) + the
  len-vs-len1 encoding truncation; then the multi-instance lift (Thm D.1 / Alg-10
  deferred-seed + `d*≠d` case split + `q6` counting), FORS+C, and composition into
  `EUFCMA_SPHINCS_PLUS`.

**Toolchain resolved.** The r2026.02 drift caveat above is closed: EasyCrypt
r2026.02 is installed in opam switch `ec-r2026`; the whole repo (incl.
`WOTS_TW_ES.ec`) builds clean, and all three drafts compile under it. Run recipe:
`bash ~/repos/c10-eufcma-port/ec-r2026.sh compile -I FV-SPHINCSPLUS-EC/proofs -I drafts <f.ec>`.

## UPDATE 2026-07-08 — Thm D.1 (multi-instance WOTS+C) FULLY MACHINE-CHECKED; FORS+C ITSR(+C) hop PROVED; a soundness bug CAUGHT+FIXED

Overnight run in `~/repos/c10-eufcma-port` (local, no remote — commits by explicit path). Every "proved" below was independently re-verified by the coordinator: clean-from-scratch compile (`.eco` deleted) EXIT 0, admit/`sorry`/`axiom` sweep, and closure grep.

**Thm C.2 (single-instance WOTS+C EU-naCMA) — the two hop admits are GONE.** Both `WOTSC_C2_hop1` and `WOTSC_C2_hop2` were closed earlier; C.2 is fully zero-admit. The apparent `p_ν` (grind-failure) term in hop2 was diagnosed as a **reduction artifact** (a sentinel `d = witness` divergence), not a real term: embedding the digest uniformly as `ThC(m, grind(m))` — well-defined because `grind` is total — removes the divergence, giving a *cleaner* theorem with no abort term.

**Thm D.1 (multi-instance WOTS+C d-EU-naCMA) — FULLY PROVEN (0 admit, benign closure).** `D1_MEUFNACMA_WOTSC` composes two now-real hops: `D1_hop1` (S-TCR(+C) side, the d-query lift of C.2's `WOTSC_C2_reduce`) and `D1_hop2` (WOTS-TW side, the lift of C.2's `WOTSC_C2_hop2` — the hard grind-scan-inside-commit nested `while{2}` coupling). `drafts/WOTS_C_Multi.ec`: **admit=0, sorry=0, axiom=0**, clean rebuild EXIT 0. Closure rests only on a benign `is_lossless dpp` (seed-distribution) axiom + the standard abstract-hash/FinType modeling idiom; the unconditional `grindP` "a good counter always exists" is NOT in the chain (replaced by the *proven conditional* `grind_correct`). **Scope caveat (honest):** D.1 is proven as the two-term reduction between the *local* games (`M_EUF_NACMA_WOTSC_L`, `M_EUF_NACMA_WOTSTW_L` over `STCRC_WC.Col`); connecting the WOTS-TW term to MM45's black-box `MEUFGCMA_WOTSTWESNPRF` is the still-deferred FC↔STCRC bridge (comment-level `D1_bridge_WOTSTW`, not a hidden admit — an agent is scaffolding it now).

**A real soundness bug was caught and fixed en route (the honesty regime working).** An agent flagged that `D1_hop2` was *false as stated*: the multi-instance WOTS-TW game `M_EUF_NACMA_WOTSTW_L` had mis-copied a `disj_wgpidxs adlO adlOC` conjunct from the LHS game, but the Alg-10 reduction *must* grind via the collection oracle `OC` at the instance addresses (public seed is naCMA-hidden), so `adlO ⊆ adlOC` → the conjunct is identically false → the RHS game was vacuously 0 → the composed headline was **unsound-as-stated** (silently collapsing to `Pr[LHS] ≤ Pr[S-TCR]`, dropping the WOTS-TW term). The claim was **code-verified and advisor-confirmed**, then fixed at the root: drop that one conjunct (evidence: C.2's single-instance `EUF_NACMA_WOTSTW` is disjointness-free, `return m'<>m /\ is_valid`), making the RHS the genuine WOTS-TW advantage and hop2 the true lift — which was then *proved* to `qed`. A **bridge-debt warning** is recorded in-file: because the game is now disjointness-free it has the *larger* winning set, so the future MM45 bridge must be stated for the composed adversary `R_multi_WOTSTW(A0)` (carrying the source game's disjointness), never as a standalone arbitrary-adversary `local ≤ MM45` (false in the same direction). **Pattern noted:** this is the *second* subtle soundness bug bred by the "local game over `STCRC_WC.Col`, defer the MM45 unification" modeling (after the non-adaptive-shape fork) — the deferred bridge is where they hide; it should be discharged properly rather than deferred further.

**FORS+C leg STARTED — the +C-specific security content is PROVED.** `drafts/FORS_C.ec`: `EUFCMA_FORSC` faithfully states the FORS-TW four-term bound with the single substitution `ITSR(mco) → ITSR(+C)(mco_C)` (the three tree terms — OpenPRE/TRH/TRCO — unchanged, since +C rewrites only the message→index map). The **ITSR(+C) game-hop `ITSRC_hop` is a real zero-admit `qed`** (verified non-vacuous: the instrumented `covered` flag is FORS_ES's `valid_ITSR` event, genuinely reachable on both branches). The sole remaining admit is the tree-terms bound (`htree`, three abstract non-negative reals — an honest parametric placeholder, since this file's tree layer is abstract; the agent correctly *declined* to fake a numeric tie). An earlier unsound `in_t=msg` deterministic-fold (which would have missed a forger using a non-canonical counter against the paper's permissive verifier) was caught and replaced by a bespoke free-counter ITSR(+C) game. **p_ν on the FORS side, adjudicated:** the R-grind is *total* in the model (same `head witness (good_ctrs)` idiom); grind-existence is carried as an explicit *hypothesis* (`good_counter_exists`, not an axiom), exactly as the paper's `r := λ` choice makes `Pr[grind_fails] = (1−p)^{2^r}` doubly-exponentially negligible. No genuine additive p_ν term in the FORS+C security reduction — same structural situation as WOTS+C.

**WOTS+C MM45 bridge — STATED SOUNDLY (`drafts/WOTS_C_Bridge.ec`, 1 admit).** `D1_bridge_WOTSTW` bounds D.1's local WOTS-TW term by MM45's *actual* `M_EUF_GCMA_WOTSTWESNPRF` for the composed adversary `R_bridge_WOTSTW(A)` (which routes grinding → the collection oracle at type-separated message-compression addresses, signing → MM45's signing oracle at the instance addresses — MM45's O/OC separation realized). It rests on two flagged, satisfiable embedding hypotheses (Th+C is FC's `thfc` at an embedded address; SPHINCS+ address-type separation) — real modeling facts discharged by reading the concrete address encoding, not axioms. The composition `D1_MEUFNACMA_WOTSC_MM45` chains proven-D.1 + the bridge into the final MM45-connected two-term bound. The sole admit (`BRIDGE-ADMIT-1`) is the per-oracle game-equivalence + disjointness discharge — the multi-week FC↔STCRC reconciliation, honestly labelled. (The agent self-caught and fixed a vacuity bug in the disjointness hypothesis and proved a zero-admit witness lemma for it — non-vacuity verified.)

**FORS+C tree leg — precisely characterized (`drafts/FORS_C_Tree.ec`, comment-only gap doc).** Unlike the WOTS bridge, the FORS tree reductions are **not** black-box reusable for +C: FORS_ES reads the FORS leaf *and instance* indices off the **counter-free** digest `mco mk m`, whereas a +C forgery's digest is counter-dependent (`mco mk' m' c'`), selecting a different instance and different leaves — so the concrete FORS_ES OpenPRE/TRH/TRCO reduction modules would mis-simulate a +C forger. The honest scope: the tree leg is a **multi-week +C-*variant* reduction port** (re-derive the three tree hops over the counter-carrying message hash + a single→multi embedding), but it contains **no remaining +C-specific mathematics** — the genuinely +C-novel work (the message-hash `ITSR(+C)` hop) is already the proven zero-admit hop in `FORS_C.ec`.

**Net position:** every +C-*specific* piece of new cryptographic content is now mechanized (C.2 full, D.1 full, the WOTS+C MM45 bridge stated soundly, the FORS+C `ITSR(+C)` hop proven). All remaining work — `BRIDGE-ADMIT-1`, the two WOTS embedding hypotheses, the FORS tree port, FORS+C multi-instance, and the final SPHINCS+C composition — is multi-week **MM45-machinery structural porting/reconciliation with no new +C mathematics to discover.** The "months not years" verdict holds, and the intellectually load-bearing part (finding and proving the two +C deltas) is done. These remaining legs are the "MM45 unification"-flavoured ones that proved bug-prone tonight (two soundness bugs caught) — they warrant design care, not speed.

**Separately (Lean side):** the `FormatDecimalSpec` CI-OOM was resolved as an infra carve-out (see the firmware-bounded-verification track) — the ~42 GB single-declaration kernel-typecheck is irreducible (a per-bind peel was measured ineffective a 4th time), so the proof is carved to a ≥48 GB heavy CI lib that still axiom-gates all three M7 theorems, keeping the default 16 GB job green; the proof itself is unchanged (real `qed`, kernel-triple closure).
