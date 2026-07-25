# Mechanizing C10 EUF-CMA in EasyCrypt — a sourced feasibility verdict (2026-07)

> **UPDATE — 2026-07-17 (supersedes the "10/21, skip 11" CAPSTONE status below).**
> The C10-CONCRETE capstone is now machine-verified in MM45's confirmed toolchain,
> container-gated. `easycrypt/drafts/SPHINCS_C_c10.ec` — `EUFCMA_SPHINCS_PLUS_C` with its
> FORS leg routed through the **concrete** `FORS_C10_Multi.MFORSC10` (not the abstract
> `FORS_C_Multi`) — compiles **as a target over its full 21-file closure** (MM45 base + `+C`
> drafts + the C10 model) in `fv-sphincsplus-ec:r2026.02` (EC git-hash r2026.02, Z3 4.13.4 +
> Alt-Ergo 2.6.0). MM45's own base is 11/11 green there. Reproduce:
> `make -C contracts/verification verify-easycrypt-docker` (needs the out-of-tree MM45 checkout
> + docker); receipt: `easycrypt/docker/GATE-RECEIPT-2026-07-17.log`.
>
> **Why the picture below flipped:** the "10/21 compiled, 11 skipped, abstract capstone" status
> was a LOCAL-toolchain limitation (the box couldn't build `SPHINCS_PLUS.eco`) — **not** a proof
> defect. Root cause: the port's `easycrypt.project` had dropped `Z3@4.13.4` (the README requires
> Z3 4.13.4 **and** Alt-Ergo 2.6.0); Alt-Ergo alone failed the SMT goals and cascaded into
> misleading type-mismatches. Restoring Z3 makes MM45's base + the C10 closure verify. The
> C10-representability stop/go the correction demanded is answered concretely: the C10-faithful
> `FORS_C10` model compiles and is load-bearing — a weakened-axiom control (`<` → `<=`) shows
> `good_pos`'s **strict** positivity is required for `query_ll`'s oracle-losslessness.
>
> **HONEST SCOPE — do not over-read.** This is NOT an end-to-end EUF-CMA proof. It stays a
> **conditional composition**: `hfx` (FX skeleton), `hbridge` (XMSS-MT), `htree` (FORS tree
> cluster) are carried labelled hypotheses, NOT discharged (controls C1/C2 confirm they are
> load-bearing). The C10 wire upgrades ONLY the FORS leg abstract→concrete. The capstone's LIVE
> assumption set **grew**: `good_pos` (=p_ν) + `FORS_C10`'s g-structure axioms are now in its
> closure (traded for the dropped `good_counter_exists` premise). The ITSRC10 assumption and the
> MM45-base axioms remain assumed. The ~6–18 person-month estimate for a full self-contained
> proof stands.

> **Controlling correction — 2026-07-15.** The historical progress log below
> remains useful, but its optimistic “concrete C10” and near-capstone language
> is superseded. The full wrapper currently exits successfully after compiling
> 10/21 files and skipping 11 MM45-dependent files; axiom pins are count-only.
> More fundamentally, imported MM45 WOTS fixes `log2_w∈{2,4,8}` and standard
> checksum WOTS, while shipped C10 uses `log2_w=3`, 43 checksum-free target-sum
> chains. Continue only as staged research after a fail-closed build and a C10
> representability stop/go gate; do not resume the abstract capstone first.
> See the [full review](../security/adversarial-review/findings/fv-full-stack-2026-07-15-coordinator.md)
> and [research roadmap](formal-verification-assurance-expansion-2026-07-15.md).

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

**WOTS+C MM45 bridge — FULLY PROVEN (`drafts/WOTS_C_Bridge.ec`, 0 admit).** `D1_bridge_WOTSTW` bounds D.1's local WOTS-TW term by MM45's *actual* `M_EUF_GCMA_WOTSTWESNPRF` for the composed adversary `R_bridge_WOTSTW(A)` (which routes grinding → the collection oracle at type-separated message-compression addresses, signing → MM45's signing oracle at the instance addresses — MM45's O/OC separation realized). Originally budgeted as a multi-week reconciliation and left as one labelled admit (`BRIDGE-ADMIT-1`), it was then **fully discharged**: a five-block `byequiv` ladder (ps + oracle inits; the emb-map oracle coupling via a `qeq` lemma that makes the two collection oracles return the *same* digest through the embedding and grows `FC.tws = map emb_tw Col.tws`; the signing coupling; the forge relay; the success-bit entailment discharging MM45's `disj_wgpidxs` conjunct live). Independently verified: clean rebuild EXIT 0, 0 admit / 0 sorry / 0 axiom, 5 qed; the lemma statement and both hypothesis bodies are byte-identical to the pre-proof version (nothing weakened); both hypotheses are load-bearing and jointly satisfiable (non-vacuous). During the proof the agent self-caught a soundness bug — a false invariant `R_multi.qs = qs` that compiled only while the hard block was admitted, and which the kernel rejected once that block was honestly proven (affirmative anti-vacuity evidence). It rests on two flagged, satisfiable embedding hypotheses (Th+C is FC's `thfc` at an embedded address; SPHINCS+ address-type separation) — real modeling facts discharged by reading the concrete address encoding, not axioms. **Consequently the composition `D1_MEUFNACMA_WOTSC_MM45` is now fully proven (0 admit):** WOTS+C multi-instance EU-naCMA ≤ S-TCR(+C) + MM45's *real* WOTS-TW GCMA advantage, a conditional theorem on the two embedding hypotheses. **The WOTS+C side is therefore essentially complete** — the only residual is discharging those two embedding hypotheses against the concrete SPHINCS+ address encoding (a concrete, non-cryptographic modeling task, not a reduction).

**FORS+C tree leg — precisely characterized (`drafts/FORS_C_Tree.ec`, comment-only gap doc).** Unlike the WOTS bridge, the FORS tree reductions are **not** black-box reusable for +C: FORS_ES reads the FORS leaf *and instance* indices off the **counter-free** digest `mco mk m`, whereas a +C forgery's digest is counter-dependent (`mco mk' m' c'`), selecting a different instance and different leaves — so the concrete FORS_ES OpenPRE/TRH/TRCO reduction modules would mis-simulate a +C forger. The honest scope: the tree leg is a **multi-week +C-*variant* reduction port** (re-derive the three tree hops over the counter-carrying message hash + a single→multi embedding), but it contains **no remaining +C-specific mathematics** — the genuinely +C-novel work (the message-hash `ITSR(+C)` hop) is already the proven zero-admit hop in `FORS_C.ec`.

**Net position:** the WOTS+C side is essentially complete — C.2 (single) full, D.1 (multi) full, and the MM45 bridge fully proven (0 admit), so WOTS+C multi-instance EU-naCMA is machine-checked against MM45's real WOTS-TW theorem modulo only the two concrete address-encoding hypotheses. On the FORS side the +C-specific novelty (the `ITSR(+C)` hop) is proven, and the +C-*invariant* tree layer is scaffolded (`drafts/FORS_C_TreePort.ec`: the three-way OpenPRE/TRH/TRCO union bound proven modulo three labelled `F-EXTRACT` admits, each a +C-variant re-derivation of one FORS_ES tree hop). Remaining work: discharge the two WOTS embedding hypotheses (concrete address encoding); the three FORS `F-EXTRACT` tree-hop ports; FORS+C multi-instance; and the final SPHINCS+C composition. This is **MM45-machinery structural porting with no new +C mathematics to discover** — the intellectually load-bearing part (finding and proving the +C deltas) is done. Multiple soundness/vacuity bugs were caught and fixed along the way (D.1-hop2's false conjunct; the bridge's false invariant, self-caught mid-proof; the FORS split's classifier robustness limit, disclosed) — these "MM45 unification"-flavoured legs are bug-prone and warrant design care, not speed. The "months not years" verdict holds and has, if anything, tightened.

### UPDATE 2026-07-08 (later) — three follow-on legs advanced

- **WOTS+C down to a single hypothesis.** `emb_thfc_ThC` (FLAG-1) was discharged by *defining* `ThC := thfc(embedded)` — the faithful SPHINCS+ realization (Thm 5.2), verified sound (the whole WOTS chain rebuilds 0-admit; `predC`/`thfc` stay abstract so the S-TCR(+C) term stays genuine). It is a definitional specialization, so all embedding content now sits in the remaining `emb_disj_wgpidxs` (FLAG-2, the address-type separation), whose discharge is a bounded-but-larger *stack-rebase* (the concrete address-type scheme lives in `SPHINCS_PLUS.ec`, off the WOTS+C stack's base). WOTS+C multi-instance EU-naCMA is thus 0-admit conditional on that one flagged hypothesis.
- **FORS tree-port footgun closed.** The classifiers `brk_op/brk_trh` are now pinned *structurally* (`brk_structural`, backed by the proven `brk_genuine_partition`) — non-circular (says nothing about game state, so `break ⟹ win` still needs the real pRHL) and satisfiable, with the residual narrowed to structural-recompute fidelity grounded in the trusted recompute.
- **FORS tree hops — real partial discharge.** For the two key-knowing hops (`extract_trh`, `extract_trco`), the *simulation invariants* are now machine-checked byequivs, and the *mathematical heart* of the trco hop is a standalone qed (`trco_collision_core`: a valid forgery with divergent roots forces a genuine trco collision) — verified non-circular (no `extract_*`/reduction references) and non-vacuous. The three admits stay open honestly: what remains is precisely extractor *index-fidelity* (naming the registered target index of the proven collision), which is `extract_*`-op-dependent — closable only via the concrete op definitions (multi-week) or the forbidden circular assumption. So the +C-variant collision arguments go through *structurally*; the remainder is concrete op-level machinery.

Throughout, the discipline held: an agent's overstated label was caught and corrected via adversarial review, no admit was closed falsely, and every "proved" survived an independent recompile + admit/axiom sweep + non-circularity/non-vacuity check.

### UPDATE 2026-07-08 (capstone) — the full SPHINCS+C EUF-CMA reduction is assembled top-to-bottom

Four more legs landed, all independently verified:

- **FLAG-2 scheme fact proven in the real SPHINCS+ scheme.** `emb_disj_concrete` (0-admit) discharges the address-type separation over the concrete `FSSLXMTWES.WTWES` instance (`nth3_valid` anchored to the real `valid_widxvalsgp`; `dist_adrstypes` gives `chtype ≠ pkcotype`). This upgrades FLAG-2 from a satisfiable hypothesis to *proven-true in the real scheme* — but, honestly, it does **not** yet make WOTS+C unconditional: the corollary's hypothesis is over the *abstract* `WOTS_TW_ES` instance (different namespace), and threading the concrete proof in needs a stack rebase that crosses the proven D.1 file. Precisely characterized, not forced.
- **FORS+C multi-instance** (`EUFCMA_MFORSC`) stated faithfully (MM45's `EUF_CMA_MFORSTWESNPRF` with `ITSR→ITSR(+C)`), the multi-instance `ITSR(+C)` hop proven, tree terms abstract-admitted. The D.1-hop2 disjointness trap was *consciously avoided* — no disjointness conjunct, with a documented reason (FORS routes one pooled instance per message).
- **FORS `extract_trco` fully closed** (admit 3→2). The agent caught that the original `R_trco` reduction was broken (per-sign duplicate target registration → the S-TCR set's distinctness conjunct was false → RHS identically 0, the same spurious-0 pattern as D.1-hop2), fixed it faithfully (register the single committed-root target once), and closed the hop via the proven collision lemma — verified non-vacuous (empirical load-bearing test) and non-circular. `extract_trh`/`extract_op` honestly left admitted (heavier).
- **The capstone `EUFCMA_SPHINCS_PLUS_C`** (`drafts/SPHINCS_C.ec`, 0-admit) mirrors MM45's top-level `EUFCMA_SPHINCS_PLUS_FX` with exactly the two +C substitutions, the PRF/hypertree/Merkle terms carried unchanged, and the two proven +C leg theorems load-bearing. It is an **honest conditional composition, not an outright security proof**: every leg hypothesis is an explicit premise, and the +C-*invariant* MM45 skeleton (the PRF/composition/XMSS-MT machinery) is carried as two assumed hypotheses (`hfx`, `hbridge`) rather than re-proven — because that skeleton is unchanged by +C and its port is mechanical. The axiom closure is clean (only the standard `dpp_ll` losslessness; the unconditional grind axioms are out of the chain).

**Net:** the entire SPHINCS+C EUF-CMA reduction now exists top-to-bottom in EasyCrypt with **every +C-specific piece machine-checked** — the two leaf reductions (WOTS+C, FORS+C) single- and multi-instance, the WOTS+C→MM45 bridge, one FORS tree hop fully closed, and the FLAG-2 scheme fact — composed into the top-level theorem. What remains is entirely **MM45-machinery porting with no new +C mathematics**: porting the +C-invariant skeleton (`hfx`/`hbridge`) and building the concrete `SPHINCS_PLUS_C` scheme module, the FLAG-2 stack rebase, the two heavier tree hops (`extract_trh`/`extract_op`), and the abstract tree terms. The intellectual core — finding and proving the +C deltas — is done end-to-end; the "months not years" verdict is now strongly, empirically supported.

### UPDATE 2026-07-08 (MM45-machinery pass) — two structural findings + a second tree hop closed

A pass at the "MM45-machinery" remainder both advanced it and, importantly, **corrected the earlier framing that it was mere plumbing** — it is genuinely multi-month and structurally non-trivial:

- **The top-level skeleton (`hfx`) is a re-derivation, not a clone.** MM45's `EUFCMA_SPHINCS_PLUS_FX` is a section-*local* lemma that hardcodes the counter-free message hash `mco mk m` throughout its six game-hops, so porting to +C means redefining four intermediate games and both reductions and re-proving all six byequivs. The one simplification proven: the composition *arithmetic* is `+C`-invariant, isolating the entire difficulty into those six byequivs.
- **A real batch-vs-interactive composition gap (the important finding).** D.1 was proven over the *batch* (non-adaptive) WOTS+C game — a deliberate choice that makes its S-TCR reduction clean. But SPHINCS+'s hypertree reduction structurally requires the *interactive* WOTS game (it queries upper-layer instances on messages derived from lower-layer public keys returned by earlier queries — impossible for a batch adversary that must commit all queries up front). So **D.1-over-batch does not directly compose into SPHINCS+**; a faithful composition needs D.1 re-proven over the interactive game `M_EUF_GCMA_WOTSC_NPRF` (which is what the paper's Thm D.1 actually is). This is a *faithfulness* gap, not a soundness break (the capstone is explicitly conditional), but it is genuine deferred work the batch shortcut created — surfaced and precisely characterized rather than left latent.
- **A second FORS tree hop closed.** `extract_trh` is now fully proven (`admit`-count in the tree-port file 2→1; only the leaf-hash `extract_op` remains), via the same register-once reduction discipline that closed `extract_trco`, plus a proven interior-node pigeonhole. Non-circular (structural hypotheses constrain only trusted recompute ops), non-vacuous (empirical load-bearing test), verified.

**Revised honest bottom line:** every `+C`-*specific* piece of cryptography remains machine-checked, and two of the three FORS tree hops are now fully closed. But the *assembly* into an unconditional top-level theorem is more than plumbing — it needs the interactive D.1, the `+C` XMSS-MT re-derivation, and the six-byequiv skeleton re-derivation, all multi-month MM45 work with no new `+C` mathematics. The person-months estimate holds; the honest accounting is that the composition tail is real work, not a formality.

### UPDATE 2026-07-08 (composition obstruction) — a genuine open design question, and a narrative correction

A further probe (attempting the interactive-D.1 the composition needs) surfaced a third and more consequential structural fact, and prompts an honest correction to the framing above.

**The finding.** Re-proving D.1 over the interactive WOTS+C game splits into a constructible WOTS-TW half and a **genuinely blocked S-TCR(+C) half**. The `S-TCR(+C)` challenge game hands the reduction its oracles only during the query phase (no public seed `pp`) and `pp` only afterward (no oracles). But the interactive forger demands honest WOTS+C signatures *synchronously during its queries*, and honest signing needs `pp` (the chains evaluate under it). There is no point at which the reduction holds both — and the `+C` S-TCR oracle serves only message-encoding (`Th+C`) digests, never the chain-hash values needed to sign. So the S-TCR(+C) reduction cannot be built against the interactive game.

**Why it is not a quick fix.** The tempting resolution — reveal `pp` to the adversary earlier — is *unsound*: the defining feature of *target*-collision-resistance is that the target is committed *before* the key is available, so revealing `pp` early silently moves to a strictly stronger assumption (toward collision-resistance) while still calling it S-TCR(+C). That is a soundness bug hiding in a definition. The sound route is to rework the S-TCR(+C) *oracle* to also serve signing material (as MM45's SM-DT oracle does for the WOTS chain layer) **and prove the reworked game is still the same S-TCR(+C) assumption** — a genuine, `+C`-specific open problem, not mechanical porting.

**Narrative correction.** Each of the three composition-tail probes (the skeleton re-derivation, the batch-vs-interactive gap, and this S-TCR signing block) falsified the "remaining work is just multi-month plumbing with no new `+C` mathematics" framing. That recurring pattern is itself the result: **the composition tail is where the real difficulty of putting `+C` into SPHINCS+ lives**, and it contains at least one open design question. The honest headline is therefore:

> The `+C` leaf reductions (WOTS+C and FORS+C, single- and multi-instance) and two of the three FORS tree hops are machine-checked *in isolation*. Whether they compose into a faithful SPHINCS+C EUF-CMA theorem is **open**, with one identified structural obstruction (interactive S-TCR(+C) signing) that may require a reworked — and separately re-justified — assumption.

This remains a strong, real result — the hard `+C`-specific reductions exist and are verified — but it is **not** a complete SPHINCS+C security proof, and the remaining path is not merely labor. The batch-game theorems (C.2, D.1, the bridge) stand as valid results about the batch game regardless.

### UPDATE 2026-07-09 (obstruction resolved *faithfully*, in design) — it was not a strengthened assumption

Following up "resolve it faithfully," a ground-truth read of MM45's actual reduction (plus advisor adjudication) shows the S-TCR(+C) signing block is **not** a fundamental obstruction and needs **no** strengthened assumption. MM45's WOTS-TW security reduction *also* holds no public seed while signing — it signs by **stitching oracle outputs**: the attacked chain hash `f` comes from the SM-DT challenge oracle, and the *honest* hashing comes from the **collection oracle** serving the full size-indexed `thfc` family. The apparent block was an artifact of the draft's simplified S-TCR collection (serving only the message hash `Th+C`, not the chain hash). The faithful fix — which the port's own plan already lists as open — is to reconcile that collection oracle to the real family (it serves *both* `Th+C` and chain-`f`, since `Th+C` is a `thfc` instance), let the reduction stitch chain values from it, and route only the *challenge* through the SM-DT oracle. This is standard SM-DT-TCR-over-a-collection, the exact shape MM45 uses; the target still commits before the key, so target-collision-resistance is intact and the assumption is *not* strengthened.

The one soundness-critical obligation of the reconciliation — that the message-hash target address is disjoint from the chain-walk addresses (`disj_lists`) — is discharged by the **FLAG-2 address-type-separation lemma already proven earlier this session**, through a bridge lemma already in the repo. So the make-or-break check passes on already-proven ground.

Honest status: the *design* is resolved and its critical check passes; it becomes a *machine-checked* result only once the reconciled game + stitching reduction + re-proved hop compile clean (mechanization underway, with a mandatory non-vacuity gate). The upshot is the good one: the composition tail's central obstruction dissolves into faithful engineering (a planned collection reconciliation) rather than a reworked assumption — the outcome the "resolve it faithfully" instruction was aiming at.

**Separately (Lean side):** the `FormatDecimalSpec` CI-OOM was resolved as an infra carve-out (see the firmware-bounded-verification track) — the ~42 GB single-declaration kernel-typecheck is irreducible (a per-bind peel was measured ineffective a 4th time), so the proof is carved to a ≥48 GB heavy CI lib that still axiom-gates all three M7 theorems, keeping the default 16 GB job green; the proof itself is unchanged (real `qed`, kernel-triple closure).

---

## UPDATE 2026-07-09 — ADVERSARIAL REVIEW: three corrections, one of them a soundness bug

A 105-agent adversarial review (32 findings, 30 surviving 3-vote refutation) plus
mechanical proof-of-concepts and a re-read of the **published** paper corrected three
things in this document. Two of them invalidate claims made above; the third reverses a
framing. **Everything the review cleared is listed at the end — the WOTS+C leg holds up.**

### Correction 1 (methodology) — "COMPILES EXIT=0" certifies far less than assumed

**EasyCrypt's `require` does not re-verify a dependency's proofs.** It imports the lemma
*statements* and trusts them. Reproduced mechanically:

```
# Broken2.ec -> compiles standalone EXIT=1 (correctly rejected)
lemma brk2 : forall (b : bool), b.  proof. trivial. qed.
# Uses2.ec   -> compiles EXIT=0, deriving `false`
require import Broken2.
lemma e2 : false. proof. by have := brk2 false. qed.
```

Also: **`admit` compiles EXIT 0 with zero output** (no warning). And a cold-cache compile
of the capstone `SPHINCS_C.ec` takes 1.3 s writing only its own `.eco`, while
`WOTS_TW_ES.ec` alone needs 81 s as a target — the chain was never re-verified.

Therefore every *"clean-from-scratch rebuild EXIT 0"* / *"independently re-verified"* claim
above is **scoped to the single file named on the command line**. The `-check-all` flag does
force real checking (it correctly rejects `Uses2.ec`) but currently dies re-checking the
stdlib. The sound gate is: **compile every file as a target + a comment-stripped admit/axiom
sweep of each** (naive `grep '^\s*admit'` counts prose). This does not, by itself, mean any
particular lemma above is wrong — it means the *evidence offered for them* was weaker than
stated, and had to be re-established file-by-file. It has been.

### Correction 2 (soundness) — the FORS tree admits were FALSE, not deferred

`tree_*` (`FORS_C.ec`) and `mtree_*` (`FORS_C_Multi.ec`) were free abstract ops
`{real | 0%r <= _}` inside the **abstract** theories `FORSC` / `MFORSC`, with the tree bound
closed by `admit`. A legal clone may instantiate all three to `0%r` (sole realization
obligation `0 <= 0`), under which the admitted step reads `Pr[… /\ !covered] <= 0%r` —
**false**. Cloning `MFORSC` with `mtree_* <- 0%r` compiles EXIT 0 and yields
`Pr[FORS+C multi EUF-CMA] <= Pr[ITSR(+C)]` with **no tree terms at all**. Dually,
`<- 1%r` makes the bound trivially true, so the theorem constrained nothing.

This is the same bug class as the already-caught `D1_hop2` (false conjunct → RHS ≡ 0) and
`R_trco` (spurious 0). Crucially, **a constant cannot bound a `forall A` probability**, so
"finish the tree-layer port" would *never* have discharged these admits — the statement had
to change. This corrects the claim above that the tree terms were an "honest parametric
placeholder" on a smooth path to the port.

**Fixed** (`c10-eufcma-port` commit `7ba51d4`): the six reals are now universally-quantified
lemma parameters and the tree bound is an **explicit premise** of `EUFCMA_FORSC` /
`EUFCMA_MFORSC`, threaded through `SPHINCS_C.ec`. The theorems are true conditionals, the
admits are gone, and the obligation is visible in the statement. Verified per-file:
`FORS_C.ec`, `FORS_C_Multi.ec`, `SPHINCS_C.ec` each EXIT 0 with **0 admits**; both
false-instantiation PoCs now fail; deleting the premise makes the capstone fail (load-bearing).

**This corrects the formalization of the tree terms, not FORS+C cryptography.**

### Correction 3 (fidelity) — the paper never proves FORS+C

Checked against the **final IEEE S&P 2023 version** (DOI 10.1109/SP46215.2023.10179381).
The paper contains exactly **two** theorems:

- **Thm C.2** — WOTS+C single-instance EU-naCMA. Our `EUFNACMA_WOTSC_C2` matches it exactly.
- **Thm 5.2** — the SPHINCS+C bound. Its preamble: *"By obtaining a d−EU-naCMA security proof
  for **WOTS+C** one can just substitute WOTS-TW with our modification. This results in adding
  a S-TCR(+C) term."* Its message-hash term is the **plain** `InSec^itsr(Hmsg)`.

FORS+C's security is a one-paragraph informal argument: §IV *"The security analysis is the same
as the security analysis of FORS… we can use the previous ITSR analysis to bound the security
of FORS+C"*; §V *"The usage of FORS+C is straightforward."* It is a combinatorial
`DarkSide_γ` bound — **no reduction, no theorem.**

⇒ Our bespoke `ITSR(+C)` game is **original work filling an informal gap in a published paper**,
not a port. That is real credit *and* real risk: no paper to check it against, and nothing
reduces `ITSRC` to plain `itsr`. **The repeated claim above that the residual is
"MM45-machinery structural porting with no new +C mathematics to discover" is wrong for the
FORS side.** (It remains right for the WOTS side.)

### What `EUFCMA_SPHINCS_PLUS_C` actually establishes

`p_sphincs_c` is an **abstract free real**, never equated to any `Pr[EUF_CMA_…]`; no SPHINCS+C
scheme module and no SPHINCS+C EUF-CMA game exist in the repo. The proof body is
`move=> …; have hF; have hW; smt()` — a linear-arithmetic transitivity. `hfx` (which *is*
MM45's proven `EUFCMA_SPHINCS_PLUS_FX`, ported) and `hbridge` are **assumed premises**; deleting
`hfx` makes the file fail, i.e. they carry the composition. Of the paper's ~12 `InSec` terms,
exactly **three** are real games (`ITSR(+C)`, `S-TCR(+C)`, MM45's WOTS-TW GCMA); the rest —
`skg_adv`, `mkg_adv`, `mtree_*`, `xmssmt_trees` — are unconstrained slack.

The fair statement is therefore: **"IF the assumed composition holds, the SPHINCS+C advantage is
bounded by the three +C game advantages plus unconstrained slack."** It is *partially*, not
wholly, vacuous — the three game terms are genuine. Contrast MM45's real top lemma
(`SPHINCS_PLUS.ec:4338`), whose LHS is `Pr[EUF_CMA(SPHINCS_PLUS, A, O_CMA_Default).main() @ &m : res]`
over a concrete scheme, with every RHS term a game probability.

### Corrected ledger

- **Real admits across `drafts/*.ec`: 3** (was 5), **all in files nothing requires**:
  `FORS_C_TreePort.ec`, `FORS_C_TreePort_skel.ec` (untracked scratch), `WOTS_C_Interactive.ec`.
  The capstone's chain is admit-free.
- **Real axiom declarations: 1** — `axiom dpp_ll : is_lossless dpp`. (`WOTS_C_Encoding.ec`,
  which held the unconditional `axiom grindCP` and did not even compile, was deleted.)
- **Orphaned** (contribute zero to the capstone today): `FORS_C_TreePort` — and note it targets
  `FORS_C`'s single-instance obligation while the capstone routes through `FORS_C_Multi`'s
  independent one; `FORS_C_Tree`; `WOTS_C_Interactive`; `SPHINCS_C_Skeleton`'s proven
  `FX_skeleton_C`; and `WOTS_C_Flag2Discharge` (its FLAG-2 proof is over a *defined* `emb_tw` in
  namespace `FSSLXMTWES.WTWES`, whereas the capstone premise is over the *abstract* `emb_tw`).
- **MM45 reference:** 0 admit tactics anywhere. `WOTS_TW_ES.ec` (what our WOTS+C leg depends on)
  verifies as a target, 81 s, EXIT 0. `SPHINCS_PLUS.ec` fails an `smt()` at `:1932` *on our box
  only* — our switch lacks the `Z3@4.13.4` that `FV-XMSS-EC/easycrypt.project` declares. Not a
  timeout, and **not evidence against MM45**.

### Cleared by the review (these hold up)

- **The p_ν adjudication is correct and faithful to the paper**, which states outright: *"we
  assume that it is always possible to find a good counter and the adversary can not depend its
  behavior on the existence of a fitting counter."* No additive p_ν term in Thm 5.2 either.
- **The WOTS+C leg is the genuine deliverable.** `D1_MEUFNACMA_WOTSC_MM45_embthfc` bounds a
  **real game** by **real games** (`S_TCR_C` + MM45's actual `M_EUF_GCMA_WOTSTWESNPRF`) with no
  free reals and zero admits, and Thm C.2 matches the paper's Thm C.2 exactly.
- **`disj_lists` is the paper's own restriction** on the Thλ collection oracle — *"queries to Thλ
  should use different tweaks from the ones that are used for challenge queries"* — justified
  only by an informal random-function argument. That informal justification, not the restriction,
  is the real residual. (It lives in `WOTS_C_Interactive.ec`, which is orphaned; the capstone
  routes through the batch D.1.)
- **No prior formal verification of SPHINCS+C exists** in EasyCrypt or any other prover, so the
  +C legs are novel work. MM45 = ePrint 2024/910, ASIACRYPT 2024.

---

## UPDATE 2026-07-09b — the FORS+C leg: model mismatch, and a black-box dead end

Continuing after the review, two results that **change the plan** for the FORS+C leg.

### 1. Our EasyCrypt FORS+C models the PAPER's scheme, not the one we ship

| | key `R` / `mk` | counter | in the signature |
|---|---|---|---|
| **`drafts/FORS_C.ec`** (paper) | sampled uniformly (`mk <$ dmkey`) | **ground** (`c <- gc mk m`) | the counter |
| **C10** (`sphincs-c10/`) | **ground** (`fors.rs::grind_r`) | none | `R` only |

`params.rs`: `SIG_FORS_TOTAL = SIG_R + SIG_FORS_SECRETS + SIG_FORS_AUTH` — there is **no
counter field** in the FORS section (the 4-byte count in `SIG_HT_LAYER` is the *WOTS+C*
counter). So `ITSRC`, `mco : mkey -> msg -> cntr -> out`, `good_counter_exists` and the
whole free-counter apparatus describe the paper's FORS+C. **Results proven there do not
transfer to C10 without a re-base.** This is the fourth model-vs-implementation mismatch
found today, and it is the same class as the rest.

### 2. A black-box reduction to plain ITSR exists for C10 — and is quantitatively useless

The paper's hand-wave (*"we can use the previous ITSR analysis"*) is the claim that
`ITSR(+C)` reduces to plain `ITSR`. We checked both models:

- **C10's model (grind the key).** The reduction **exists and is sound**: simulate the +C
  oracle, whose `R` is *conditioned* on `predC`, by **rejection sampling** on plain ITSR's
  uniform-key oracle. *Coverage* transfers (the reduction's target list is a superset, and
  coverage is monotone in it); *freshness* transfers (every rejected target carries
  `¬predC`, the forgery carries `predC`, so they can never collide).
- **The paper's model (grind the counter).** The reduction **does not exist**: folding
  `(m,c)` into the ITSR input is circular, because `c = gc(mk,m)` depends on the key the
  oracle has not yet returned. This is the "key-before-grind circularity" `FORS_C.ec`'s own
  comments cite as the reason for a bespoke free-counter game.

  *(Irony worth stating: the scheme we ship is easier to justify than the one in the paper,
  and the model our port has been building is the one that cannot be reduced.)*

**But the C10 reduction loses 88 bits.** Rejection sampling registers `~t = 2^11` targets
per real query, so at the `2^16` per-chain cap the reduction's game has `2^27` targets over
`2^18` FORS instances — a max per-instance load of `~625` rather than `~5`:

| | max load γ | ITSR term |
|---|---|---|
| direct (paper's DarkSide) argument | ≈ 4.9 | **≈ 113 bits** |
| generic black-box reduction | ≈ 625 | **≈ 25 bits** |

⇒ **`A5-ITSR` cannot be discharged by a black-box reduction to Barbosa et al.'s plain ITSR.**
Closing it requires mechanizing the **direct, tight, non-black-box DarkSide argument**
against a **C10-faithful** model. We did *not* mechanize the reduction: it would have been a
week of EasyCrypt (unbounded-`while` sampler, losslessness, conditioned-distribution
coupling) to obtain a valid theorem too weak to cite. Recomputed by
`contracts/verification/scripts/forsc_grinding_margin.py::itsr_report`, so it cannot rot.

### 3. New guardrail — the usage cap is load-bearing for FORS security

The ITSR term is ≈113 bits **only because** of `MAX_SLOT_USES = 2^16` (which keeps the max
per-instance FORS load at γ≈5). `make -C contracts/verification verify-forsc-margin`
guardrail 4 now **fails** if the cap is raised enough to push the ITSR term below the
96-bit floor (`--self-test` trips it at `qs = 2^26`). Nobody had written this dependency down.

### 4. Systemic residual — the signing-side model↔implementation bridge is unverified

Four mismatches in one day all share a root: **nothing checks that the EasyCrypt/Lean
*scheme model* equals the Rust/Solidity *implementation* on the signing side.** A3.1 covers
the on-chain verifier; the signer's grind/encode path has no such bridge. Until it does,
"the port proves something about C10" is an assumption, not a fact. Tracked here rather than
chased now.

---

## UPDATE 2026-07-09c — FLAG-2 discharged: the WOTS+C leg is now UNCONDITIONAL

The last real hypothesis on the WOTS+C leg is gone. `emb_disj_wgpidxs` (FLAG-2) was
undischargeable for a *namespace* reason, not a mathematical one: the proof
(`emb_disj_concrete`) lived in `WOTS_C_Flag2Discharge.ec` over the **concrete**
`FSSLXMTWES.WTWES` instance, while the premise was stated over the **abstract**
`WOTS_TW_ES` — two different `adrs` types.

**Fix (c10-eufcma-port `c5fa41a`): re-base the WOTS+C stack onto the concrete instance
and *define* `emb_tw`.** It turned out to be a header swap plus one re-exposed constant:

- `require import SPHINCS_PLUS.` + `import FSSLXMTWES.WTWES.` in place of the abstract theory.
- `emb_tw ad = insubd (put (put (put (val ad) 0 0) 1 0) 3 pkcotype)` — the pkcotype flip.
- The clone substitutes `op c <- bigi predT (fun d' => nr_nodes_ht d' 0) 0 d` **away**, so `c`
  is re-exposed with the identical definition (statements stay byte-identical). Of the
  substituted names only `n`/`w`/`len`/`c` were referenced.
- The FLAG-2 proof chain moves into `WOTS_C_Real.ec`; `WOTS_C_Bridge.ec` proves
  `emb_disj_wgpidxs_holds : emb_disj_wgpidxs`.

**Result**

| lemma | premises before | after | conclusion |
|---|---|---|---|
| `D1_MEUFNACMA_WOTSC_MM45_embthfc` | 3 | **2** | byte-identical (md5-checked) |
| `EUFCMA_SPHINCS_PLUS_C` | 7 | **6** | byte-identical (md5-checked) |

So **WOTS+C multi-instance EU-naCMA is bounded by `S-TCR(+C)` + MM45's *real* WOTS-TW GCMA
game with no embedding hypothesis** — unconditional apart from the parameter side-condition
`c <= p_tgts` and the definitional encode-compat identity. Removing a hypothesis strengthens;
nothing was weakened.

**Anti-vacuity (a rebase is exactly where games go degenerate — so this was checked, not assumed):**
- Replacing the corollary's RHS with `0%r` **fails to compile** ⇒ the LHS is not identically 0.
- `nonvac_guard` — a valid WOTS signing address exists, so the guard premise is live.
- `emb_off_range` — no `emb_tw` image is itself a valid WOTS chain address, so FLAG-2 is not
  vacuously true via an `a := emb_tw b` self-collision.
- `thfc`, `emb_in`, `predC` stay **abstract** ⇒ the S-TCR(+C) term is still the genuine
  SM-DT-TCR-C assumption, not trivialised by moving to the concrete instance.

Verified clean-from-scratch with **every file compiled as a target** (`require` does not
re-verify): 18/18 EXIT 0, **3 real admits — all in orphaned files**, **1 real axiom** (`dpp_ll`).

**What this does NOT change.** `A5-EUFCMA` stays `cited-tcb`. The capstone LHS `p_sphincs_c`
is still an abstract real (no SPHINCS+C scheme module exists), and `hfx`, `hbridge`, the FORS
tree layer and the FORS+C leg are still open. This closes one of seven premises — the one that
was bounded, already proven, and blocking a clean citable claim about WOTS+C.

---

## UPDATE 2026-07-10 — the margin script's METHOD was wrong (external review); corrected figures

A second frontier model (`gpt-5.6-sol`, run via `codex exec` read-only) was asked to
adversarially review `drafts/FORS_C10.ec` and propose an EasyCrypt strategy. It found
real defects, all since verified against the code. The most consequential is a
**correction to our own arithmetic**, and it supersedes the numbers in *UPDATE 2026-07-09b*
above.

### The error

`forsc_grinding_margin.py` evaluated `DS` at a **high-probability maximum per-instance load**
("typical max ≈ 5") and reported **≈113 bits**. That is **not a cryptographic bound**:

- the tail event that *some* one of the `2^18` bins is heavier is not negligible; and
- a maximum is the wrong object anyway — **the adversary cannot choose which FORS instance
  its candidate lands in**, because the digest decides it.

### The correct object

A *fresh* candidate's instance load is `G ~ Bin(qs, 1/N)`, and the adversary's `q_h` hash
queries contribute a union-bound factor:

```
Pr[win]  ≤  (q_h + 1) · (1/t_last) · E_G[ DS_G^(k−1) ],    G ~ Bin(qs, 1/N)
```

### Corrected figures (at `qs = 2^16`, `N = 2^18`, `t = t_last = 2^11`, `k = 13`)

| quantity | old (max-load, **wrong method**) | corrected (binomial mixture) |
|---|---|---|
| FORS+C ITSR term | ≈113 bits | **130.6 bits** |
| plain FORS, same method | — | **128.5 bits** |
| generic black-box reduction | ≈25 bits | **28.1 bits** |
| **bits lost going black-box** | ≈88 | **≈102** |
| 96-bit floor first crossed at | `qs = 2^26` | **`qs = 2^22`** |

Two things change substantively. **FORS+C is not merely "never weaker" than plain FORS — it
is the *stronger* of the two by 2.1 bits** at our parameters. And the usage-cap guardrail is
**tighter than advertised**: the 96-bit floor is crossed at `2^22`, not `2^26`, so the
headroom above `MAX_SLOT_USES = 2^16` is 6 doublings, not 10.

The old method under-stated security by ~15 bits, so the *direction* was safe — but the
method was wrong, and the number was published in `AXIOM_STATUS.json` and enforced by a CI
gate. `scripts/forsc_grinding_margin.py` now computes the mixture directly (with `lgamma`
so the `2^27`-target case is tractable), and its `--self-test` trips at `qs = 2^22`.

### Other findings from the same review (verified, being addressed)

- **`FORS_C10.ec`'s header claims a hypothesis the file never states** (`0%r < mu dmkey (good m)`).
  Claim-vs-code drift, ours.
- **`g` is unconstrained**, so a legal clone can set `g y = []`, making coverage vacuously true.
  MM45 constrains its `g` with three axioms (`size_g`, `eqiks_g`, `neqisvs_g`). This is the same
  abstract-theory-instantiation attack we used to kill the FORS tree admits.
- **No memoization**: MM45's FORS signing oracle carries `mmap : (msg, mkey) fmap`; ours resamples
  `R` per query, so it models neither C10 (`opt_rand = None` ⇒ deterministic per message) nor MM45.
- **Freshness**: our game uses *pair* freshness, which admits `(R', m)` for an already-signed `m` —
  not an EUF-CMA forgery. This is **not unsound** (message-fresh ⇒ pair-fresh, so ours is a larger
  event and a valid upper bound), and MM45's generic ITSR is pair-fresh too. But the game is
  non-EUF and must be named accordingly.
- The `q_h`-unboundedness it flags applies **equally to MM45's plain ITSR** (`mco` is a pure op
  there too). That is precisely why ITSR is *assumed* rather than bounded — see below.

### The reframing that makes this tractable

Independently established while the review ran: **MM45 never bounds ITSR — it assumes it.**
`EUFCMA_SPHINCS_PLUS`'s RHS carries `Pr[MCO_ITSR.ITSR(...)]` as an *unreduced term*, and no
lemma anywhere in MM45 bounds it. Nor does EasyCrypt's stdlib have any concentration
inequality (no Chernoff/Hoeffding/Chebyshev/Markov; only `mu_le`/`mu_mem`/`mu_split`/`mu_sub`).

So the honest closure of the FORS+C gap is **not a reduction**. `ITSRC10` is a *new,
nonstandard hardness assumption* — standard ITSR plus the conditioning of the message key.
State it at exactly the level MM45 states plain ITSR; justify its concrete security on paper
(this script); and cite the ~102-bit black-box loss as evidence that the nonstandard assumption
is **necessary, not lazy**.

---

## UPDATE 2026-07-10 (later) — FORS-side C10 rebase + k-fold product landed; a toolchain-reproducibility finding

A four-way parallel push on the remaining FORS-side items. **Every "landed" below survived the
coordinator's OWN negative controls re-run against the canonical tree — not the sub-agent's
self-report** (this campaign's whole bug history is EXIT-0-but-unsound, so a verify-agent is the
same epistemic object as the bug it checks; the gate has to be a control you run and read the exit
code of).

**LANDED (compile-as-target EXIT 0 + comment-stripped admit/axiom sweep + negative controls that FIRE):**

- **`DarkSide.ec` k-fold product (`cover_all_pr`).** The joint all-covered probability over `nt`
  INDEPENDENT trees `mu (dlist (dlist dleaf gam) nt) [all-covered] = DS gam ^ nt` — the genuine
  independence product (EQUALITY, not a bound; `dlistE` factors the joint `mu` into the per-tree
  product, each factor `= cover_pr = DS gam`). This is the first "NOT proven here" milestone from
  the file's own header, past the per-tree `forsc_le_fors`. Controls (coordinator-run): RHS→`0%r`
  fails, RHS→`1%r` fails, deleting the `0<=c<t` range hypothesis fails; all three dependent FORS
  files still compile. It still does NOT close the tight bound — the binomial **mixture** over
  instance load + the `(q_h+1)` union bound need a concentration inequality EasyCrypt's stdlib
  lacks (unchanged wall).

- **`FORS_C10_Multi.ec` (NEW) — the multi-instance C10-FAITHFUL FORS+C leg.** The "(c) C10 rebase"
  that `XMSSMT_C_Scheme.ec`'s note said must precede a scheme module. `EUFCMA_MFORSC10` mirrors the
  paper model's `EUFCMA_MFORSC` over the C10 CONDITIONED, NON-memoized oracle
  (`mk <$ dcond dmkey (good m)` per signature, pool-routed by `idx_of`):
  `Pr[EUF_CMA_MFORSC10(A,O)] <= Pr[ITSRC10(R_ITSRC10_MFORSC10(A), O_ITSRC10_Default)] + mtree_*`.
  The `ITSRC10` term is carried as the UNREDUCED named assumption (never bounded — the ~102-bit
  black-box dead end and the missing concentration inequality both still apply); the three tree
  terms are an EXPLICIT premise. The REAL content — the multi→single reduction
  `R_ITSRC10_MFORSC10` + its hop `ITSRC10_hop_M` (the C10 analogue of `ITSRC_hop_M`) + the
  covered/!covered `mu_split` — is PROVEN, 0 admit. Controls (coordinator-run): deleting the tree
  premise fails; zeroing the ITSRC10 term in the *main* theorem (hop occurrence preserved) fails.
  Introduces two benign sugar-assumptions (`op [lossless] dpseed` → `dpseed_ll`; `const d {1<=d} as
  ge1_d`) that mirror `FORS_C.ec` exactly and that `ec_sweep` does not count as `axiom`-keyword —
  the ledger stays 8. Existence of a good key is carried by the inherited **load-bearing** axiom
  `good_pos` (= p_ν), a ledger-visible modeling choice rather than the paper's per-theorem
  `good_counter_exists` premise.

- **Model↔implementation signing bridge** (`sphincs-c10/tests/fors_model_bridge.rs` +
  `docs/verification/fors-model-impl-bridge-2026-07.md`). Grounds the EC model's `predC_fors`
  against the SHIPPED Rust: the +C predicate reads bit-offset **`(K-1)·A = 132`, width 11**, and
  real `grind_r` outputs have that window zero on every sampled digest; localized to *exactly* 132
  (adjacent bit 131 is not universally zero). Cross-checked against `SPHINCsC10Asm.sol` (`shr(132)`
  / `shr(143)` htIdx). Control (coordinator-run): `C10_BRIDGE_PREDC_OFFSET=131` makes the grounding
  assertion FAIL. **Honestly scoped:** this grounds the index/predicate LAYER and its bit layout —
  the five structural axioms are true-by-construction (empirical discriminating power nil), and the
  random-oracle idealisation of `H(sk‖…)`, `dmkey_ll`/`good_pos`, non-memoization, and the tight
  `ITSRC10` bound are explicitly NOT grounded. This is the first artifact converting "the port is
  about C10" from assumption toward fact on the signing side (A3.1 covers only the on-chain verifier).

**WALL — characterized, not forced (no false close):**

- **`extract_op`** (the last of the three FORS tree admits; `FORS_C_TreePort.ec`) does NOT close.
  The narrowed residual R-KEY needs `pk = fkeygen(ps,adz).\`1 = pk_of_leaves ps adz ys` for the
  SAMPLED `ys` of the challenge oracle — unprovable because `fkeygen` is an OPAQUE DETERMINISTIC op
  (`FORS_C.ec:324`), so the internal leaf-secret sampling that FORS_ES's real OpenPRE reduction
  couples to `O.pick` is SEALED and cannot be re-sampled. (The "key-free ⇒ simpler" framing was
  wrong: key-free is exactly why `R_op` cannot sidestep R-KEY the way the key-KNOWING `trh`/`trco`
  hops did.) Closing it requires refining `fkeygen` from an op into a sampling procedure — a
  `FORS_C.ec` modeling refactor (the "multi-week +C-variant tree port" §UPDATE 2026-07-08
  predicted), not a one-session close. Stays admitted (orphaned; the capstone routes through
  `FORS_C_Multi`'s independent obligation).

**TOOLCHAIN-REPRODUCIBILITY FINDING (new, and load-bearing for the gate's honesty).** The
`verify-easycrypt` full-compile gate is **not reproducible on a box without z3 4.13.x**.
`SPHINCS_PLUS.ec:1932` needs z3 4.13.4 (both Alt-Ergo 2.6.0 and z3 4.16.0 fail it with
`cannot prove goal (strict)`), and z3 4.13.x is not installable here without a root/system package.
Because `require` does NOT re-verify, the past "20/20 compiled" run silently relied on a **stale
`SPHINCS_PLUS.eco`** that no longer exists on this box. Consequence:
- The **stdlib-only FORS+C chain** (`DarkSide`, `FORS_C`, `FORS_C_Multi`, `FORS_C10`,
  `FORS_C10_Multi`, `Grind`, `STCR_C`) IS freshly compile-gateable with Alt-Ergo alone — that is
  where all three landed units live, so their gate is fully reproducible.
- The **MM45-chain drafts** (`WOTS_C_*`, `SPHINCS_C`, `XMSSMT_C_*`) require the prebuilt
  `SPHINCS_PLUS.eco` / z3 4.13.4. So the MM45-chain-dependent items — the concrete SPHINCS+C
  **scheme module (1a)**, the **capstone rewire (2b-wire)** onto this new C10 FORS leg, and the
  **interactive D.1 (1c)** — could not be compile-gated this session and were therefore **NOT**
  attempted-into-the-tree (promoting an ungated proof would violate the whole discipline). 1c is
  independently a "person-weeks" operational byequiv; `hfx` (the capstone skeleton) is independently
  multi-month. `verify-easycrypt`'s header now states the z3 4.13.4 dependency.

**Net FORS-side position.** The FORS leg now has, all machine-checked and stdlib-reproducible: the
C10-faithful single-instance model (`FORS_C10.ec`), its multi-instance d-EU-CMA leg
(`FORS_C10_Multi.ec`), the k-fold combinatorial core (`DarkSide.ec`), and an empirical model↔impl
bridge for the index layer. The honest closure of the FORS+C security gap remains the named
`ITSRC10` assumption. The remaining path to a *concrete* SPHINCS+C theorem is gated only by the z3
4.13.4 toolchain (for 1a/2b-wire) and the multi-month `hfx` skeleton port — **no new +C mathematics**.

### UPDATE 2026-07-10 (later, cont.) — two more DarkSide milestones; the mixture is a NUMERIC wall

Continuing the DarkSide combinatorial argument (all coordinator-gated, additive, 0 admit/axiom,
each with a firing negative control; port + vendored in sync):

- **`cover_some_le` — the `(q_h+1)` union bound.** `Pr[some of |cands| candidate leaf-vectors is
  covered in all nt trees] <= |cands| * DS gam ^ nt`, by finite subadditivity over the proven
  `cover_all_pr`. Controls: RHS→`0%r` fails; dropping the `|cands|` factor fails. (Port `e2bb4f4`.)
- **`ds_le_linear` — the Bernoulli linearisation `DS gam <= gam/t`.** The rigorous one-sided form
  of the paper's `DS_gamma ~ gamma/t`, by induction. Control: RHS→`0%r` fails. (Port `2d892c6`.)

So **2 of the 3 remaining DarkSide milestones are now mechanized** (union bound + linearisation);
only the **binomial mixture** `E_{G~dbin(1/N,qs)}[DS(G)^(k-1)]` remains. EasyCrypt DOES have `dbin`
(`Distr.ec:2795`), so it is not blocked on a missing distribution — but a *symbolic* bound on that
high binomial moment has **no clean closed form**, which is exactly why the margin script
(`forsc_grinding_margin.py`) evaluates it NUMERICALLY (`lgamma`). Mechanizing it symbolically is the
"concentration inequality" territory; the honest position is to keep the concrete-security number in
the (kernel-independent but auditable) numeric script rather than force a loose symbolic bound.
**Caveat unchanged:** even a fully-mechanized DarkSide bound stays PURE PROBABILITY — connecting it
to `Pr[ITSRC10(A,O)]` for an arbitrary adversary + ROM is the assumption-level gap that neither MM45
nor the paper closes (it is *why* ITSR is assumed), so these lemmas advance the paper-level
justification of `ITSRC10`, they do not turn it into a game-level theorem.

### UPDATE 2026-07-10 (later, cont. 2) — z3 4.13.4 obtained, but `SPHINCS_PLUS.ec:1932` is an IRREDUCIBLE platform wall here; 2b-wire PREPARED but UNGATEABLE

Attempted to unblock the MM45-chain items (the scheme module 1a, and the capstone rewire 2b-wire
onto the new C10 FORS leg) by getting z3 4.13.4 — the version `FV-XMSS-EC/easycrypt.project`
declares. Findings, exhaustive:

- **z3 4.13.x will NOT build from source here** (gcc 15 rejects z3 4.13.0's `m_low_bound` template).
  Got the **official prebuilt z3 4.13.4 Linux binary** instead (`~/.local/opt/z3-4.13.4/z3`, runs on
  glibc 2.39), registered in `why3-ec-r2026.conf` via `why3 config detect` (recognized version, OK,
  correct driver). EC-r2026 lists `Z3@4.13.4` in its known provers.
- **`SPHINCS_PLUS.ec:1932` STILL fails** `cannot prove goal (strict)` — the goal is
  `sp 2 2; conseq (: _ ==> ={pkFORS}) => />; 1: smt().` Tried, all failing: bare `compile`
  (default), z3 4.16, **z3 4.13.4**, MM45's EXACT `runtest` project config (Alt-Ergo@2.6.0,
  `timeout=3`; note SPHINCSPLUS's project uses Alt-Ergo ONLY — `:1932` is an Alt-Ergo goal), and
  Alt-Ergo at **`-timeout 60`** (so it is NOT a timeout). MM45's CI passes this goal, so it is a
  **platform/prover-BUILD difference, not a proof defect** — the Alt-Ergo 2.6.0 in the `ec-r2026`
  opam switch behaves differently on this goal than MM45's CI Alt-Ergo. No `docker` on this box to
  run MM45's exact-toolchain image (`make docker-check`).
- ⇒ **`SPHINCS_PLUS.eco` cannot be freshly built on this box by any means available**, so the whole
  MM45-chain (WOTS_C_*, SPHINCS_C, XMSSMT_C_*) is un-compile-gateable here. This is a HARDER wall
  than "need z3 4.13.4": we HAVE z3 4.13.4 and it still fails. Needs MM45's exact CI toolchain (their
  Docker image or an equivalently-built Alt-Ergo), not just the right prover version.

**2b-wire is PREPARED, correct-by-construction, and NOT promoted.** The rewired capstone (FORS leg
routed through `FORS_C10_Multi.MFORSC10`: the FORS clone, module renames, and — critically —
**dropping the `good_counter_exists` premise** since C10 has no counter, the good-key existence being
the inherited `good_pos` axiom) is saved at `~/repos/c10-eufcma-port/pending-2b-wire/`
(`SPHINCS_C.c10-fors.ec.UNGATED` + a README with the 8-edit recipe and the honesty controls to run).
Because it cannot be compiled here, it is **NOT verified and NOT committed** — the discipline is
absolute (never promote a proof you cannot gate). A future session on a working MM45 toolchain
applies the recipe, gates it (delete tree premise → fail; zero ITSRC10 term → fail), then vendors.
The `FORS_C10_Multi` leg it routes through IS verified (stdlib-gateable, landed this session); only
the capstone *composition* over it is blocked, and purely by the `SPHINCS_PLUS.eco` toolchain wall.

## UPDATE 2026-07-18 — XMSS-MT+C core-lemma attack: scheme-level +C-invariance CONFIRMED (a bankable finding)

Re-estimate evidence, independent of how far the capstone gets this cycle:

**MM45's entire XMSS-MT tree machinery is reused byte-for-byte by the +C scheme.** `XMSSMT_C_Scheme.ec`
imports `pkco`, `cons_ap_trh`, `val_bt_trh`, `val_ap_trh` directly from MM45's `FSSLXMTWES` instance;
`leaves_from_sspsad` / `gen_root` / `keygen` are annotated "byte-for-byte MM45" (line 33) and verified
so (pkco at :84/:191, val_bt_trh/cons_ap_trh at :96/:128/:129). The **only** +C delta in the whole
hypertree is `okC <- predC (ThC ps ad m counter)` at :158 — the message-compression grinding gate,
which lives strictly **inside the WOTS leaf** (`WOTS_C_ES`), never in the tree hashing.

**Consequence for the core reduction lemma** (`EUFNAGCMA_FLSLXMSSMTTWESNPRF_MEUFGCMAWOTSTWES`,
FL_SL_XMSS_MT_ES.ec:4075): its two tree-collision reductions (`R_SMDTTCRCPKCO_EUFNAGCMA` :2130,
`R_SMDTTCRCTRH_EUFNAGCMA` :2415) and its three instrumented-game equivs (`EqPr_..._Orig_V` :3005,
`Eqv_..._Orig_C` :3511, `Eqv_..._C_V` :3962) operate over the tree structure that is +C-identical.
The instrumented games (`EUF_NAGCMA_..._C` :3054, `_V` :3285) inline the WOTS encoding **inside the
game body** — so both sides of every equiv share it, and the equivs align execution *traces* (never
invoke an encoding *property* — the checksum/constant-sum security argument is the LEAF theorem's job,
delegated out via the leaf reduction). ⇒ the tree reductions + tree game-hops are expected to port by
**scheme-substitution** (`encode_msgWOTS`→`encode_msgWOTS_C`, add the `grindC` counter-loop alignment
on BOTH sides), with the entire +C delta absorbed in the already-closed leaf term (interactive-D.1).

**This is direct evidence against the 6-18-person-month figure**: the hard, novel +C work is the WOTS+C
leaf (interactive-D.1 — CLOSED, gold-standard-verified this program); the ~2000-line hypertree
collision-extraction machinery above it is a mechanical port, not fresh cryptographic proof. Pending
the empirical spike (port `Eqv_..._Orig_C` and compile) to convert "expected mechanical" → "shown
mechanical". Caveat retained: the leaf-term premise `A_wf` is CARRIED at the component level (the
faithful +C analog of MM45's shipped `H_pkco`) and remains **open** until the capstone reduction-image
discharge — do not read "component theorem done" as "A_wf discharged".

### UPDATE 2026-07-18 (same day, tightened) — read-level +C-invariance CONFIRMED for the WHOLE core lemma

Extended the checksum-reasoning audit from the suspect equiv to the entire core-lemma region
(FL_SL_XMSS_MT_ES.ec:3005-4290). Result: **ALL FOUR proof components are checksum/constant-sum-free**
— `Eqv_..._Orig_C` (:3511, the pk-reconstruction/collision-extraction alignment, the hardest one,
uses only generic base-w facts `cf`/`ch_comp`/`BaseW.valP`/`val_w`), `EqPr_..._Orig_V` (:3005),
`Eqv_..._C_V` (:3962), and the assembly `..._MEUFGCMAWOTSTWES` (:4075, a pure `Pr[mu_split ...
valid_WOTSTWES]` + `ler_add` splitting the instrumented V-game win into the three collision buckets,
each routed to its reduction). No component invokes an encoding *property* — the WOTS security
argument is delegated wholesale to the leaf theorem via `R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA`.

⇒ The +C port of the ~2000-line hypertree collision-extraction machinery is **mechanical**:
scheme-substitution (`encode_msgWOTS`→`encode_msgWOTS_C ps ad m counter`, tree ops verbatim) plus
counter-threading friction (the `sigFLSLXMSSMTTWC` element bundles `((sigWOTS,counter),ap)`, so every
sig destructure + the forgery reconstruction `pkWOTS_from_sigWOTS_C` carry the counter). The three
collision flags (:3268-3273) are +C-identical (the counter never enters a collision comparison).
**100% of the +C cryptographic novelty sits in the WOTS+C leaf (interactive-D.1 — CLOSED).** Remaining
to convert "shown by reading" → "shown by compiler": the empirical port-and-compile of the C/V game
modules + the equivs (in progress). This is the sharpest evidence yet against 6-18-pmo: the layer
everyone assumes is expensive (hypertree security) is a substitution port off MM45.

### CORRECTION 2026-07-18 (same day) — "mechanical" is PROVISIONAL: the forge-soundness SEAM is untested

The two updates above are correct that NO component of the core lemma has a checksum/constant-sum-
*property* dependency (a necessary condition, confirmed by reading). But that must NOT round up to "the
whole ~2000-line hypertree layer is a mechanical port." A negative checksum-grep is structurally blind
to one thing: the **tree↔leaf SEAM** at `EqPr_..._Orig_V` (FL_SL_XMSS_MT_ES.ec:3005) — the hop the
assembly uses (`rewrite EqPr_..._Orig_V`) to map the instrumented V-game's `valid_WOTSTWES` bucket down
to `Pr[M_EUF_GCMA_WOTS(R_leaf)]` (it drops to the WOTS-level `FC.O_THFC_Default` — that IS the seam, not
bookkeeping). In OUR port the leaf term is `Pr[M_EUF_GCMA_WOTSC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht))]`, and
**milestone 2's `R_leaf_C.forge` is SHAPE-ONLY** — the reduction-soundness leg ("a hypertree forgery
yields a WOTS+C forgery, forge-selection correctness") is explicitly DEFERRED (XMSSMT_C_Reduction.ec
scope note, "D1-COMPOSITION LEG ONLY"). The seam hop asks an *interface-shape* question a checksum-grep
cannot detect: does `R_leaf_C`'s shape-only `forge` extract the **counter-carrying** WOTS+C forgery in
precisely the form `EqPr_..._Orig_V`'s alignment consumes? If not, porting this hop forces a **rework of
the already-"0-admit" milestone 2**, not a mechanical substitution.

⇒ HONEST STATUS: checksum-freedom across all components = confirmed, bankable, real evidence vs 6-18-pmo
(the WOTS-security *argument* does not re-enter the tree layer). "Mechanical" is **provisional** and
scoped: the pure-tree components (`Eqv_Orig_C`, `Eqv_C_V`, the 2 tree reductions, assembly bookkeeping)
are mechanical; the **seam `EqPr_Orig_V ⟷ R_leaf_C` is the untested go/no-go**. The next empirical spike
must aim at THAT compile (build C+V games only as scaffold to reach it) — `Eqv_Orig_C` (pure tree) would
compile clean and prove nothing about the seam. Until the seam hop compiles, do not call the layer done.

### REFINEMENT 2026-07-18 (same day) — the seam's rework risk is LOWER than "shape-only" implied

Read the actual milestone-2 `R_MEUFGCMAWOTSC_EUFNAGCMA_C.forge` body (XMSSMT_C_Reduction.ec:645-656)
against MM45's `R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.forge` (FL_SL_XMSS_MT_ES.ec:225-238). Our forge is a
**complete, counter-carrying extraction — NOT a stub**: identical `find` predicate (`pkWOTSs' i =
pkWOTSs i /\ (m'::rootss') i <> (ml::rootss) i`), identical `fidx = bigi nr_trees 0 cidx * l' + tidx*l'
+ kpidx`, and it extracts `sigc' = (sigWOTS, counter)` (the +C-carrying forgery) and returns
`(fidx, root', sigc')`. It reconstructs pks via the counter-threaded `pkWOTS_from_sigWOTS_C`. The
`valid_WOTSTWES` event MM45 defines (:3268) is EXACTLY this `find` predicate and is **counter-independent**
(pk-match + root-mismatch; the counter never enters it). ⇒ the `EqPr_Orig_V ⟷ R_leaf_C` connection is
expected to port.

So "milestone-2's forge is shape-only" (my own note's wording) means the extraction CODE is complete and
MM45-faithful; what is DEFERRED is the soundness PROOF — that a valid hypertree forgery on a fresh message
forces `valid_WOTSTWES` (the level-wise telescoping: a re-rooting on a different message must, at some
layer, hit a matching pk with a different signed root = a WOTS forgery, else a pkco/trh collision). That
telescoping is tree-level and counter-independent. NET: the seam is still the untested go/no-go and its
compile is the fact-converter (advisor discipline holds), but the risk it forces a milestone-2 *rework* is
LOWER than "shape-only stub" implied — the forge already has the right counter-carrying shape. Next
session: port C+V games (scaffold), then compile the seam soundness (`EqPr_Orig_V` + the `V ∧ valid_WOTSTWES
⟺ M_EUF_GCMA_WOTSC(R_leaf_C)` connection). That compile is the go/no-go, not `Eqv_Orig_C`.

### UPDATE 2026-07-19 — adversarial verification of the seam (8-agent workflow): rework risk LOW, one genuine +C edit pinned

Ran an 8-agent workflow (map + 4 independent adversarial skeptics + 2 drafters + rework critic, ~1.18M
tokens) to convert the seam go/no-go from my reading to an adversarially-checked verdict. Result:

**MILESTONE-2 REWORK RISK = LOW** (scoped to `R_MEUFGCMAWOTSC_EUFNAGCMA_C.forge` + `leaf_reduction_
MEUFGCMAWOTSC_bound`). Each of 4 refutation axes was refuted on independently-confirmed source:
 - *fidx/query-accounting*: `grindC = STCRC_WC.G.grind` is a PURE TOTAL OP (WOTS_C_Real.ec:223), ZERO
   oracle queries; `Default.query` appends exactly one qs entry ⇒ fidx→qs one-for-one identical to MM45.
 - *cidx-selection*: `okC` never enters `find`/`fidx`/return; our forge predicate (:646-651) is
   byte-identical to MM45 (:2112-2119); reconstruction is total over pure ops.
 - *valid_WOTSTWES counter-independence*: the predicate (:3268) is byte-for-byte counter-free.
 - *telescoping bypass*: `okC` is a STRICTLY-ADDED conjunct — it can only SHRINK the valid-forgery set;
   pkco/val_ap_trh byte-identical ⇒ no new bypass.
The +C interface ALREADY COMPILES (R_leaf_C.forge returns `int*msgWOTS*(sigWOTS*cntr)` = the exact
`Adv_MEUFGCMA_WOTSC.forge` type; the bound is proved against `O_MEUFGCMA_WOTSC_Default`). So the
interface-shape worry is discharged in milestone-2; the residual is a WIN-CONDITION obligation.

**CORRECTION to "mechanical": the seam is NOT mechanical — exactly ONE genuine +C divergence.**
`WOTS_C_ES.verify` folds `okC = predC(ThC ps ad m' counter')` into `is_valid{2}` (WOTS_C_Scheme.ec:101,
206), which MM45's `valid_WOTSTWES` and `find` both OMIT. So the +C seam byequiv must diverge from MM45
at exactly one spot: (1) the C/V-game reconstruction whiles ACCUMULATE `allOkC` from `pkWOTS_from_sigWOTS_C`'s
okC bit, so `allOkC{1}` sits in the `mu_split` bucket; (2) the conseq (:4537 analog) must RETAIN
`is_valid{1}` (MM45 DROPS it); (3) discharge `okC{2}` from `allOkC{1}` at the final skip (:4645 analog),
reusing the address+msg+counter alignment that already proves pk-equality — via the already-0-admit
milestone-1 helpers `root_from_sigC_okl_eq` (:416), `all_idfun_nth` (:350), `pkfromsigC_verify_eq` (:321).
This does NOT push work back onto R_leaf_C (at most a cosmetic okC side-accumulator in its while).

**NEXT COMPILE TARGET (the go/no-go converter):** the +C FIRST `ler_add` branch byequiv (analog of
:4107-4696): define `EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V` (is_valid inline gains `/\ allOkC`), then prove
`Pr[V.main : (is_valid /\ is_fresh) /\ valid_WOTSTWES] <= Pr[M_EUF_GCMA_WOTSC_NPRF(R_leaf_C,
O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default) : res]`. State against `O_MEUFGCMA_WOTSC_Default` FIRST — do
NOT pre-build O_V/EqPr_Orig_V_C (whether the V-oracle is needed is compile-revealed; okC is oracle-
independent). Crux ≈ 5 lines (retain is_valid{1} + okC-from-allOkC discharge). EVERYTHING IS UNBUILT
(grep confirms no +C hypertree V-game exists) — "low rework, no mechanical surprise" is a reading-grounded,
adversarially-checked PROJECTION, not compiled fact. The byequiv compile is what makes it fact.

### UPDATE 2026-07-19 — seam byequiv: statement SETTLED + opening PROVEN; a reusable pRHL introspection unblock

Two agent workflows on the seam byequiv (the go/no-go: `V ∧ valid_WOTSTWES ≤ M_EUF_GCMA_WOTSC(R_leaf_C)`):

**Landed (compiles EXIT 0, in WIP `drafts/_seam_byequiv_wip.ec`):**
 - The byequiv **STATEMENT is settled**, resolving the oracle-plumbing question that blocked me earlier:
   the V-game's abstract collection oracle is instantiated with **`FC.O_THFC_Default`** — the SAME module
   `M_EUF_GCMA_WOTSC_NPRF` hands `A_ht` on the RHS (`R_leaf_C` passes OC straight to `A(OC)`), and
   `FC.Oracle_THFC` is structurally accepted where the V-game expects `FSSLXMTWES.TRHC.Oracle_THFC` (same
   init/get_tweaks/query signature). RHS is literally the `leaf_reduction_MEUFGCMAWOTSC_bound` term ⇒ the
   second `ler_add` step chains cleanly.
 - The **opening choose-alignment is PROVEN**, exposing a +C *simplification*: both sides hand `A_ht` the
   collection oracle directly (no MM45 `O_THFC` wrapper), so choose couples by collection-oracle glob
   equality alone — no `typeidx<>chtype` bookkeeping invariant needed.
 - **Milestone-2 rework: NONE** (re-confirmed a 4th time, code-traced): the okC discharge uses only the
   already-0-admit helpers `pkfromsigC_verify_eq`/`all_idfun_nth`/`root_from_sigC_okl_eq`.

**The residual + a genuine TOOLING unblock:** the remaining ~370-line cube-build bulk (MM45
`FL_SL_XMSS_MT_ES.ec:4143-4531` analog) is mechanical transcription but needs pRHL goal introspection to
tune the nested-`while` invariants. The batch gate (`easycrypt compile`, errors-only, ~4-8s/iter) does NOT
print pRHL goal states — which is why the first grind stalled. **Fix: `easycrypt cli` (the proof-general
REPL) DOES stream full relational goal states** (both program sides + `post`). Wrapped as
`ec-goal.sh <file> <line>` (feed the file prefix into `cli`, dump the pending goal at the frontier). This
is the EasyCrypt analog of `lean-lsp` for agent-driven proof development and unblocks the bulk (and all
future pRHL work in this port). Validated on the actual stuck goal — the dumped `post` confirms the +C
divergence is correctly wired: `(is_valid{1} /\ is_fresh{1}) /\ valid_WOTSTWES{1} => ... is_valid{2} ...`
(is_valid{1}, carrying allOkC, retained; is_valid{2}, carrying okC, in the consequent). A max-effort grind
with this tool is in progress. Real file `drafts/XMSSMT_C_Reduction.ec` stays 0-admit clean throughout;
only the WIP carries the single bulk admit.

### UPDATE 2026-07-19 (cont.) — seam byequiv reduced to 3 admits; structural tail PROVEN; O_V hop discovered

Max-effort introspection grind (ec-goal.sh) on the bulk. Result: seam_branch1_WOTSC in the WIP
(drafts/_seam_byequiv_wip.ec) compiles EXIT 0 with exactly **3 labeled admits**, structural tail PROVEN:

**Proven admit-free this session:** part-0 choose-alignment; part-2 signing-loop coupling (counter threaded
through the ((sigWOTS,cntr),ap) cube; needed adding ps{1}=ps{2} to the cube post); part-3 verify-inline +
the conseq **RETAINING is_valid{1}** (the +C divergence-a; needed adding -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C to
the A_ht restriction for the module-write frame — sound, A_ht's only interface is OC); and the verify
DISCHARGE (given Q supplies the okC gate, is_valid{2}=pk-match∧okC consumes it, is_valid{1} threads through).

**3 residual admits, discriminating content isolated:**
 - #A conseq bookkeeping — trivial, counter-free (size qs=c, uniq/disj from P; MM45 :4542-4546 verbatim).
 - #1 cube-build (MM45 :4143-4531) — mechanical + a **newly-discovered prerequisite**: a WOTS+C
   `O_orig→O_V` element-sampling oracle hop (analog of MM45 EqPr_Orig_V + the _V oracle at WOTS_TW_ES.ec
   :2915-3277); no WOTS+C analog exists yet — additive game infra, +C delta trivial (grindC/encode
   deterministic, commute with the reindex), does NOT change the lemma's conclusion (still Pr[…
   O_MEUFGCMA_WOTSC_Default …]).
 - #B reconstruction (MM45 :4554-4681) + **the okC-GHOST = the one discriminating +C step** — proving
   allOkC{1} propagates to the extracted layer cidx's okC=predC(ThC…). This is a **proof-plumbing assembly
   of the already-0-admit milestone-1 helpers** (all_idfun_nth/pkfromsigC_verify_eq/root_from_sigC_okl_eq):
   the novel +C cryptographic content is already proven; #B assembles it.

**Honest calibration:** the seam is NOT yet a compiled fact, but NO structural +C no-go was found; both
intermediate posts P and Q are satisfiable (honest deferrals, not false posts the tail exploits);
milestone-2 rework NONE (R_leaf_C + leaf bound untouched). Residual = mechanical MM45 transcription (#1,#A,
#B-coupling) + proof-plumbing over proven helpers (#B-okC) + one additive oracle-hop infra (O_V). No novel
cryptographic difficulty remains. A focused grind proving the okC-ghost first is in progress.

### UPDATE 2026-07-19 (cont.) — the discriminating +C content (okC-ghost) PROVEN 0-admit + audited genuine

The crux — the one place a +C no-go could hide — is now a compiled, adversarially-audited fact.
`okC_ghost` (drafts/_okc_ghost_dev.ec standalone + ported into _seam_byequiv_wip.ec, both CERTIFIED-0-ADMIT):
running the WOTS+C hypertree reconstruction and obtaining a satisfied aggregate +C gate (allOkC=true) FORCES
the per-layer constant-sum gate `predC(ThC p addr_cidx root_cidx counter_cidx)` at the extracted layer, on
the ACTUAL reconstruction triple. Proven as: an ExtTri instrumented twin records per-layer (addr,root,counter);
L3b (`root_from_sigC_okl_tri_char`) pins each okC-list entry = predC(ThC…) by while-invariant (via
pkfsc_okC_post — THIS is the +C content, proven by construction not hypothesized); L3a ties the real
`root_from_sigC` allOkC to `all idfun okl`; `okC_select` (via all_idfun_nth) selects the in-range layer.
**Adversarial audit PASS** (independent recompile + proof-chain grep): genuine, non-vacuous, 0-admit/0-axiom
— cidx range used only for the size bound (not trivializing), allOkC a hypothesis (not assumed), no smt in
the chain, passes the discriminator test (arbitrary predC/ThC/reconstruction breaks it). NB the prover's
FIRST attempt was a generic list tautology that hypothesized the +C content away; the auditor caught it and
forced the correct construction — the audit stage earned its cost.

**Honest residual (seam still 3 admits — NOT a compiled fact yet):** #A conseq bookkeeping (non-trivial
{1}/{2} reconciliation, not the "trivial" first thought); #1 cube-build (MM45 :4143-4531 + the O_V oracle-hop
infra); #B reconstruction — and the ghost does NOT `call`-plug into #B because the V-game INLINES its
reconstruction, so consuming the ghost means RE-ESTABLISHING L3b's per-layer invariant inside the inlined
V-loop (or a V-loop~tri-twin equiv): **real work, not mechanical consumption**. **Milestone-2 no-rework:
downgraded to UNVERIFIED for the actual #B coupling** (the ghost needed no R_leaf_C change, consistent with
no-rework, but #B's ghost-consumption was not exercised).

**Gate-hygiene finding (important):** EasyCrypt treats `admit` as a WARNING, so `easycrypt compile` returns
EXIT 0 even with admits — a compile-clean gate does NOT certify admit-freedom. TRUE 0-admit certification
must ALSO grep the source for admit/assume tactics (+ axiom decls). Added `ec-certify.sh` (compile EXIT 0 AND
admit/assume/axiom-free). All prior "0-admit" claims in this port were separately grep-verified, so they hold;
but the gate script alone was insufficient. (Kin to the earlier lessons: `require` does not re-verify; a
broken theory compiles EXIT 0.)

### CORRECTION 2026-07-19 — scope + estimate calibration (supersedes any "novel +C work is done" phrasing)

Advisor-flagged over-rounding + two verification gaps closed. The precise, honest state:

**Hardened (good):** the okC-ghost's WHOLE +C dependency chain is CERTIFIED-0-ADMIT (comment-stripped admit
+ axiom sweep, ec-certify.sh fixed): WOTS_C_Real/Scheme/Interactive.ec, XMSSMT_C_Scheme/Reduction.ec,
_okc_ghost_dev.ec — all 0 admit / 0 axiom (over the MM45 cited-TCB base). So the okC-ghost 0-admit is real
through its dependency chain, not just a target-file grep.

**What is actually PROVEN + audited (this whole program, +C-novel content):** exactly TWO +C swaps — the
WOTS+C leaf bound (interactive-D.1) and the okC-propagation (okC-ghost, a sub-lemma of the FIRST ler_add
branch of the core lemma). No structural +C wall surfaced in either.

**What is NOT done (do NOT read "the novel +C work is done"):**
 - the first-branch seam byequiv itself — 3 admits (#1 cube-build + the O_V oracle-hop that does not exist
   yet, #A conseq, #B reconstruction / ghost-consumption = "real work not mechanical");
 - the SECOND ler_add branch (pkco/trh tree reductions R_pkco_C/R_trh_C) — NOT BUILT;
 - the XMSS-MT component-theorem assembly + its type-premise discharge;
 - **FORS+C — OPEN**, a separate +C novelty (counter in H_msg / ITSR-with-counter): FORS_C10.ec carries 7
   axiom-decls + an admit, and FORS_C/FORS_C_Tree/FORS_C_TreePort carry admits (FORS_C10_Multi is 0-admit).
   Not "folded into leaf+ghost";
 - the capstone SPHINCS+C composition and the A_wf discharge at the capstone (a deferred projection).
 Generously, this is ~a third through ONE of several capstone pieces.

**Estimate verdict — TEMPERED (this is NOT a disproof of 6-18 person-months):** a full session of max-effort
multi-agent grinding (~2.8M subagent tokens) closed a sub-sub-lemma + its structural tail and STILL left the
first branch open with a newly-discovered oracle-hop. "Mechanical" under-counted three times this session
(the okC edit, the O_V hop, the #B ghost-bridge). The honest, narrower claim the evidence supports: *the +C
swaps examined are tractable and no novel cryptographic wall has been found; AI-assisted, the remainder LOOKS
like proof-engineering rather than research — IF the mechanical characterization holds, and it has repeatedly
expanded.* Not "weeks not months" as a settled fact; "no wall found so far."

### UPDATE 2026-07-19 (cont.) — seam byequiv down to 1 admit (#A+#B CLOSED); 2nd-branch tree reductions typecheck

Parallel workflow (3 agents, ~863k tokens). Results, auditor-verified:
 - **#A (conseq) and #B (reconstruction + okC integration) CLOSED 0-admit** in _seam_byequiv_wip.ec — WIP now
   has exactly ONE real admit (#1 cube-build). #B genuinely consumes the okC-ghost: a V-loop invariant clause
   (C15) re-establishes the per-layer characterization `nth okl j = predC(ThC ps ad_j root_j counter_j)`
   INSIDE the inlined reconstruction loop (maintained via all_idfun_rcons + pkWOTS_from_sigWOTS_C's definitional
   okC), then extracts it via all_idfun_nth at the forgery layer cidx. **Audit: non-vacuous** (flipping Q's
   predC conjunct to false breaks the compile), not smt-cheated, not hypothesized.
 - **CONDITIONAL**: #A/#B are proven AGAINST the still-admitted cube-build post P (#1) — a specific MM45
   qs-characterization (not vacuous), so meaningful, but the seam is NOT admit-free yet.
 - **Load-bearing +C adaptation (not "mechanical"):** the +C `allOkC <- true` statement shifts MM45's
   wp/seq boundary by one, so the folded conseq/Q antecedents bound STALE values ⇒ #A/#B unprovable as first
   framed. Fixed by reframing the conseq/Q/tail antecedents to the real unfolded antecedent (seam-internal;
   R_leaf_C + leaf-bound UNTOUCHED — milestone-2 no-rework holds).
 - **Open integrity item:** the byequiv's A_ht restriction gained `-EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C` (for the
   is_valid{1} module-write frame); argued sound but its discharge at the downstream ler_add consumer is
   unverified.
 - **2nd-branch tree reductions** R_SMDTTCRCPKCO_C / R_SMDTTCRCTRH_C built + typecheck (CERTIFIED-0-ADMIT,
   drafts/_seam_tree_reductions_wip.ec). Caveat (real +C wrinkle): the SM-DT-TCR-C game reveals `pp` only at
   find, but the +C encode site is SEED-dependent (grindC ps / encode_msgWOTS_C ps) whereas MM45's is not —
   pick grinds against a witness-valued module-var seed; its equality with the game seed is deferred to the
   downstream byequiv. Typecheck ≠ soundness (module defs only).

Remaining on the first branch: #1 cube-build (MM45 :4167-4531 nested invariant) + its prerequisite O_V
element-sampling oracle-hop (no WOTS+C analog exists yet). Consistent theme: each "mechanical" layer has
needed real adaptation (okC edit, O_V hop, antecedent reframe) — no cryptographic wall, but real engineering.

### UPDATE 2026-07-19 (cont.) — O_V hop DONE + audited; a premise-structure REFINEMENT (corrects the A_wf framing)

The #1 grind delivered the O_V oracle-hop and surfaced a genuine statement-level finding.

**O_V oracle-hop: COMPLETE, gated 0-admit, audited GENUINE.** Built in _seam_byequiv_wip.ec:
`O_MEUFGCMA_WOTSC_V` (element-sampling), `Eqv_O_MEUFGCMA_WOTSC_query_Orig_V` (whole-key ~ element-sampling
query equiv via a DList Sample_LoopSnoc leg + ch_comp pk/sig fusion, MM45 WOTS_TW_ES.ec:2928-3002 analog),
and the Pr-hop `EqPr_MEUFGCMAWOTSC_Orig_V` (MM45 :3005-3032). Audit: a real whole-key-keygen+sign ~
per-element-sampling equality, not vacuous; dependencies CERTIFIED-0-ADMIT. The byequiv now does
`rewrite (EqPr_MEUFGCMAWOTSC_Orig_V A_ht)` before byequiv; statement RHS unchanged (still O_..._Default).

**The cube-build (#1) is BLOCKED on a premise gap, not transcription — and it corrects the A_wf reconciliation.**
The cube-build post P needs `all (get_typeidx <> chtype) FC.O_THFC_Default.tws{2}`. The collection oracle
records queried addresses UNCONDITIONALLY, A_ht is abstract, and our leaf bound carries ONLY the member-based
`A_wf` (`p.1 <> dfC`) — which says NOTHING about chtype (in the deployed design Th+C sits at pkcotype/dfC,
NOT chtype). MM45's core lemma (:4096) carries a TYPE-based `allnchads = hoare[A.choose : ==> all
(get_typeidx <> chtype) ads]` for exactly this. So P is unprovable (indeed false for a chtype-querying A_ht)
without adding `allnchads`.

⇒ **Refinement of the 2026-07-18 reconciliation (which over-simplified):** the member-based `A_wf` is NOT a
blanket +C analog of MM45's three type premises `allnchads/allnpkcoads/allntrhads`. It is the analog of the
**pkcotype-axis** premise ONLY (where +C's Th+C target sits, at member dfC). The **chtype axis (WOTS chains)
still needs the TYPE-based `allnchads`**, verbatim MM45; likewise the trhxtype axis. So the +C component
theorem must carry BOTH kinds: the type-based address premises (chtype/pkco/trh, MM45-faithful, for the
tree/WOTS machinery) AND the member-based `A_wf` (the +C-specific Th+C protection). Both are component-level
premises, both discharged at the capstone (the reduction-image adversary avoids chtype AND member dfC — the
FORS/message OC queries sit at FORS types ≠ chtype and members ≠ dfC). This is a premise-STRUCTURE correction,
NOT a soundness break and NOT an R_leaf_C/leaf-bound rework (both untouched). FIX (authorized, MM45-faithful):
add `allnchads` to seam_branch1_WOTSC + strengthen the part-0 seq post to carry the dropped ps/ad/pp
equalities, then close the cube-build transcription. Carrying it needs a downstream re-check at the eventual
component-assembly consumer (same as MM45 carries+discharges its type premises).

### MILESTONE 2026-07-19 — the first ler_add branch byequiv is a COMPILED 0-admit FACT (seam go/no-go resolved YES)

`seam_branch1_WOTSC` (drafts/_seam_byequiv_wip.ec) is CERTIFIED-0-ADMIT — independently re-verified (ec-certify:
compile OK / 0 admit-tactics / 0 axiom; nested-strip tactic-position admits = 0; whole file EXIT0; committed
HEAD 1bdd7ce) and adversarially AUDITED (statement intact, premises faithful, cube-build genuine not smt-forced).
It proves: `Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A_ht,FC.O_THFC_Default).main : res /\ valid_WOTSTWES] <=
Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht), O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default) : res]`.
This is the SEAM — the one place a +C hard-rework could have hidden — now a compiled fact, integrating: the
proven okC-ghost (discriminating +C content), the O_V element-sampling oracle-hop, the #A conseq, and the full
nested cube-build. Milestone-2 (R_leaf_C / leaf bound) UNTOUCHED throughout.

PREMISE LIST (9, both address-discipline kinds carried, per the refined understanding): c<=p_tgts; hembdisj;
hembinj; hencb; dfC<>8n; dfC<>8n*len; dfC<>8n*2; **A_wf_ht (member-based, pkcotype/dfC/Th+C axis)**;
**allnchads (type-based, get_typeidx<>chtype, WOTS-chain axis)**. Plus module-separation restrictions.

FOUR genuine +C reworks in the cube-build (found by ec-goal introspection, beyond rename): (1) side-2 sig
names sigclp/sigcnt; (2) a NEW sig-counter maintenance conjunct grindC(addr,root){1}={2} (the ground counter,
absent in MM45); (3) qualified WAddress.insubdK/DBLL.insubdK/DigestBlock.valP; (4) tree-hash size-leaf via
smt(DigestBlock.valP) (MM45's bare /# lacked the digest-size fact). Consistent theme: no cryptographic wall,
but EVERY "mechanical" layer needed real adaptation.

NON-BLOCKING residuals (out of scope, honestly flagged): (a) the carried allnchads + the
-EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C restriction must be dischargeable at the downstream ler_add/composition
consumer (MM45 discharges its type premises at :4338; not re-checked here) — do NOT read this lemma's 0-admit
as EUF-CMA closure; (b) stale in-proof comments (documentation lag, no soundness impact); (c) cited-TCB: the
vendored MM45 `require import SPHINCS_PLUS` base carries its own axioms (local +C drafts verified 0-admit/0-axiom).

STILL OPEN toward the SPHINCS+C capstone: the SECOND ler_add branch byequiv (uses the built tree reductions
R_SMDTTCRCPKCO_C/R_SMDTTCRCTRH_C, with the deferred-seed +C wrinkle); the component-theorem assembly (chain
branch-1 + branch-2 + leaf bound, discharge the carried premises); FORS+C (separate +C novelty, OPEN); the
capstone composition + premise discharge.

### SCOPING 2026-07-19 — the SECOND branch is the first NO-TEMPLATE point: tree reductions must grind (novel modeling)

Before grinding the second ler_add branch, a paper-scoping of the deferred-seed wrinkle (advisor-prompted).
Findings:

1. **The tree reductions genuinely must grind — MM45 gives NO template here.** `R_leaf_C` sidestepped grinding
   by reducing to the WOTS+C *game* (grinded sigs come from the WOTS oracle). But `R_SMDTTCRCPKCO_C`/
   `R_SMDTTCRCTRH_C` reduce to the pkco/trh *TCR games*, which provide no WOTS signing — so their `pick` must
   build the pks itself, including the grind. Standard SPHINCS+ never grinds, so MM45's tree reductions don't;
   a pre-committed reduction that needs seed-dependent grinding is a problem the base proof never faced. This
   is the FIRST genuine +C novel-modeling point (not transcription-with-adaptation).

2. **The module-var seed is DEAD, not deferred.** The typecheck-green `_seam_tree_reductions_wip.ec` grinds
   with a module-var `ps` (line 100) that is witness-valued at `pick` and cannot provably equal the freshly
   sampled game `pp` — unsound-as-written. Those modules are SCAFFOLDING, not partial soundness; do not count
   them toward the second branch.

3. **The sound path is grind-via-OC, and it fits on count but needs member-aware disjointness.** `grindC`/`ThC`
   are pure ops (`ThC = thfc(...) ps ...`) that need the seed; the sound fix is to grind by iterating
   `OC.query` for `ThC` (OC holds `pp`) until `predC`, a variable-length loop at pkcotype/member-`dfC`.
   Termination rests on the finite counter type `CntrFT` + a good-counter-exists premise (WOTS_C_Real.ec:209).
   MM45's `disj_relcqsadtcr` (WOTS_TW_ES.ec:1963) needs only DISJOINTNESS, not a fixed collection-query count,
   so the variable prefix is tolerated on count. BUT the grinding queries (member `dfC`) are disjoint from the
   pkco/trh targets (member `8n·len` / `8n·2`) by MEMBER, not by MM45's group-index — so the disjointness
   argument needs the MEMBER-AWARE transcript machinery (the shape built for the leaf via interactive-D.1),
   EXTENDED to the tree reductions. Not a wall; genuine +C design work reusing the leaf's member-separation.

⇒ CHARACTER CHANGE (honest estimate update): the second branch is not byequiv transcription — it is
soundness-design (restructure the tree reductions to grind-via-OC + build a member-aware disjointness for
them + then the byequiv). No wall in sight, but this confirms the pattern sharpening: genuine design work
recurs at each +C seam, and the tree layer is where MM45's template runs out. "Weeks of transcription" is the
wrong model; "recurring novel modeling at each +C seam, AI-assisted" is the honest one.

### ADVERSARIAL REVIEW 2026-07-19 (GPT-5.6 + Kimi K3) — grind-via-OC is DEAD; do grind-in-find; and a FOUNDATIONS flag

Two independent external reviews (codex/GPT-5.6 and Kimi K3, each reading the sources) of the proposed
grind-via-OC design. They CONVERGE on both the disqualifier and the fix, and Kimi adds a foundations finding.

**DISQUALIFIER (both, verified by me in source): grind-via-OC cannot win the stock pkco game.**
`SM_DT_TCR_C`'s win requires `disj_lists twsO twsOC` on RAW TWEAKS (TweakableHashFunctions.eca ~:745), and
the collection oracle records only the raw tweak (:586). `emb_tw ad = insubd(put(put(put (val ad) 0 0) 1 0) 3
pkcotype)` (WOTS_C_Real.ec:80) — and `valid_idxvalspkco` forces indices 0,1 = 0, so EVERY valid pkcotype
address at (kp,t,l) is THE SAME address as the pkco target. The reduction would query its own challenge
tweak ⇒ the run is deterministically rejected. Member separation (dfC vs 8n·len) is real and provable but
INVISIBLE to the stock win condition. (trh is asymmetric: targets at trhxtype vs grind at pkcotype ⇒ disjoint
by type, stock game fine. Only pkco collides.)

**MY CORE PREMISE WAS FALSE (both):** "the grind determines the chain heights" — no. In `pick` each WOTS chain
is walked FULLY to `w-1`; `em` only selects which intermediates are REVEALED as `sigWOTS`. So pkWOTS tops,
leaves, nodes, roots and ALL target inputs are grind-INDEPENDENT. `pick` never needed the seed.

**THE FIX (both, converged): GRIND-IN-FIND.** `pick` becomes byte-verbatim MM45 (delete the grindC/
encode_msgWOTS_C lines + the em-pluck; chains+nodes via OC, targets via O) ⇒ transcript identical to MM45 ⇒
`dist_tweaks`/`disj_lists`/`fidx` arithmetic carry over unchanged. `find(pp)` — which DOES receive the seed —
builds `counterstd` (grindC pp), `em` (via `hencb`), and `sigWOTStd` by pure chain walks, then runs the
existing assembly incl. `A.forge`. `find` makes ZERO oracle calls ⇒ zero transcript pollution ⇒ STOCK games
for both branches, NO new cryptographic assumption. PRECEDENT ALREADY IN-REPO AND 0-ADMIT: `R_multi_STCRC`
"defers keypair/signature construction to find(pp)" (WOTS_C_Multi.ec:186-196); same architecture as the leaf
batch reduction (WOTS_C_Reduction.ec:66-90). MM45 does provide a grinding-reduction template — in `find`,
not `pick`. Smallest diff: move ~15 lines from each `pick` into each `find`. Both reviewers explicitly say
DO NOT build a member-aware pkco game (new game + full branch proof + a second non-MM45 capstone assumption).

**FOUNDATIONS FLAG (Kimi, unique — a calibration on the branch-1 milestone):** the `A_wf_ht` premise carried
by branch 1 ("A_ht never opens member dfC") FORBIDS the adversary from evaluating ThC — i.e. it excludes
GRINDING forgers, which is the very attack class +C exists to withstand. So `seam_branch1_WOTSC` is genuinely
0-admit, but its **+C content is thin**: the theorem closes over a forger class that cannot grind. It also
means the member-aware pkco variant would buy nothing (it would tolerate queries our own `A_wf_ht` already
forbids — the real inconsistency in my plan). If grinding forgers are ever to be in scope: trh survives on
the stock game (type separation), pkco needs a member-aware variant, and the S-TCR(+C) term needs INPUT-level
freshness (the forger's grind hits the same member AND tweak as the targets, so even member-aware disj fails —
only "don't query the exact target input, which the adversary doesn't know" works). **That is a foundations
redesign, not a branch-2 decision.** Decide it BEFORE investing further in member-aware machinery.

### CORRECTION 2026-07-19 — the "thin +C content" flag was WRONG (GPT-5.6, verified in source)

The FOUNDATIONS FLAG recorded above (Kimi: "`A_wf_ht` forbids evaluating ThC ⇒ excludes GRINDING forgers ⇒
branch-1's +C content is thin") is **INCORRECT**. GPT-5.6 refuted it and I verified every load-bearing claim:

- `ThC` / `grindC` are **pure operators**, not oracle procedures (WOTS_C_Real.ec:175, :223). The ONLY thing
  that appends to the member-aware transcript is an explicit `O_THFC_MA.query` call
  (`tws_ma <- rcons tws_ma (df,tw)`, WOTS_C_Interactive.ec:2081).
- The **phase split is deliberate and documented in our own file** (WOTS_C_Interactive.ec:75-76):
  `pick`/`choose` = "has oracles, NO pp"; `find(pp)`/`forge` = "has pp, NO oracles". The adversary types
  literally carry empty oracle lists: `proc forge(...) : ... {}` (XMSSMT_C_Reduction.ec:204),
  `proc find(pp) : ... {}` (STCR_C.ec:175, WOTS_C_Interactive.ec:304).
- ⇒ a +C forger grinds **after** the seed is revealed, in a phase with **no oracle access**, as pure
  unrecorded computation. `A_wf_ht` constrains ONLY explicit member-`dfC` collection calls during the
  pre-seed `choose` phase. **It does NOT restrict the forger's grinding.**
- This is paper-faithful: the SPHINCS+C paper (in-repo `paper-nist-pqc2022.txt`) Definition C.1 splits the
  S-TCR(Prop) adversary into A1 (registers p targets via the oracle, pre-seed) and A2 (gets P, computes
  freely — grinding explicitly allowed); Appendix D uses Th only while P is hidden — exactly the role of our
  collection oracle. Kimi's proposed "input-level freshness" is NOT standard S-TCR and is actually FALSE as a
  premise: Def C.1 returns the counter j_i to the adversary, so the target input is public after registration
  and candidate grinding at the same member AND tweak must be allowed.
⇒ `A_wf_ht` should be described as a **pre-seed choose-phase auxiliary-collection separation premise**, not a
non-grinding-forger restriction. Branch-1's +C content is NOT thin on these grounds.

**What DOES survive as real, actionable (GPT-5.6):**
1. The discharge is **prospective, not implemented** — the capstone still carries abstract `hfx`/`hbridge`
   and there is no concrete shared top reduction (SPHINCS_C.ec:22, :189).
2. **`8*n*k` gap**: MM45's top-reduction `choose` makes FORS collection calls at lengths `8n`, `8n*2`, and
   `8n*k` (SPHINCS_PLUS.ec:1544/1568/1581). Our seam carries separation from the first two but not visibly
   from `8n*k` — a concrete discharge needs that fact (or a pair-level invariant).
3. **`A_wf_ht` is over-strong**: it bans EVERY member-`dfC` query (WOTS_C_Interactive.ec:2547) while the game
   needs only the target tagged pair `(dfC, emb_tw T_i)` (:2126). Weakening it removes needless obligations.
4. **The game-level bridge is DEFERRED** (WOTS_C_Interactive.ec:484): we prove a pointwise collision-predicate
   bridge but not the full game-level reduction to standard `SM_DT_TCR_C`. Since abstract members `thfc df`
   may be CORRELATED, TCR of `thfc dfC` alone does not automatically cover access to other members at the same
   address. **Until that bridge exists the RHS must be labelled a custom collection-aware S-TCR(+C) advantage**,
   or backed by an explicit domain-separation/independence assumption. (This is the honest-labelling issue.)

**RECOMMENDATION (GPT-5.6, option iii — adopted):** keep `A_wf_ht` but document it accurately; prove its
discharge for the concrete top-reduction image when that exists (auditing `8n*k` and +C-specific FORS calls —
moderate Hoare work, far cheaper than reopening interactive-D.1); clean up the assumption boundary (prove the
tagged-tweak game-level bridge OR state the collection-aware assumption honestly); optionally weaken `A_wf_ht`
to the game-exact target-pair condition. Do **NOT** redo the leaf chain for input-level freshness. A clean
formulation offered: treat `(member,address)` as an **extended tweak**, making the member-aware transcript
ordinary tagged-tweak separation while post-seed candidate grinding stays allowed.
Citation fix: MM45 component premises are FL_SL_XMSS_MT_ES.ec:4075; the top theorem + discharge are
SPHINCS_PLUS.ec:4338 / :4375 (my earlier "FL_SL:4338" was inside the component proof).

### FOUNDATIONS RESOLVED 2026-07-19 — both models converge; the fix is a real choice (delete-conjunct vs discharge)

Kimi K3's foundations pass SELF-CORRECTS its earlier alarm and converges with GPT-5.6 on the substance:

**CONVERGED (both, verified):**
- `A_wf_ht` does NOT exclude grinding forgers. Kimi's own correction: "it excludes *logging* member-`dfC`
  queries; **grinding is transcript-invisible for an oracle-free forger**." The thinness worry is real ONLY
  if the capstone hands the forger the collection oracle, or the discharge is never built.
- **Input-level freshness is wrong and Kimi retracts it**: "targets are adversary-chosen/known in EUF-CMA;
  TCR needs freshness of the COLLISION (x ≠ x'), not of the query history. No level of history-freshness
  belongs in this assumption."
- **Def C.1 (S-TCR(Prop)) IS the clean assumption and already admits grinding forgers** — don't invent a new
  one. Our pick-before-`pp` staging is paper-faithful (paper App D:2198-2199 ≡ STCR_C.ec:173-176); the
  counter-returning `O_Prop` is intrinsic to +C; the good-counter assumption is carried honestly as
  `Grind.grind_fails`. **The avoidable part is the disj/member machinery layered on top.**
- **The theorem worth stating** (both): *for all ORACLE-FREE EUF-CMA forgers F,
  `Pr[EUF-CMA(F)] <= ... + InSec^{S-TCR(+C)}(Th+C; p_tgts) + ...`* with that term verbatim Def C.1.
  **(i)-discharged and (ii) both deliver it; (i)-CARRIED does not.** So carry-and-document is NOT shippable.

**DIVERGENCE — the actual decision:**
- **GPT-5.6 → option (iii)**: keep `A_wf_ht`, document it accurately (pre-seed choose-phase separation), prove
  its discharge against the concrete top-reduction image later, clean the assumption boundary.
- **Kimi → option (ii), tightly scoped**: DELETE the `disj_lists` conjunct from our bespoke `S_TCR_C_Int_MA`
  (:2126-2131); then `A_wf_ht`, `member_sep_disj` (:1999, applied :2218) and the whole `O_THFC_MA`
  member-tagged transcript become dead code. Leaf success-transfer gets strictly SIMPLER (deletions, not new
  obligations); branch-1 loses a premise; **nothing needs discharging above the leaf ever again**. Cost: days
  + re-certification churn on two 0-admit files; edits are monotone weakenings.
  Kimi's justification: the conjunct is *power-neutral* — the collection oracle merely logs while computing
  the real `fc`, so an adversary can be re-wrapped to route forbidden queries inline with identical
  behaviour ⇒ restricted and unrestricted classes have equal max success ⇒ artifact, not assumption.

**MY ADJUDICATION FLAG (to settle before acting):** Kimi's power-neutrality rests on re-wrapping the
adversary to compute the hash inline instead of querying — but during `pick` the adversary has **no `pp`**
(that is the entire point of the hidden-seed phase), so it cannot compute inline there. If the re-wrap fails
pre-seed, dropping the conjunct is a genuine (if mild) STRENGTHENING of the assumption, not a neutral
cleanup — still sound for our upper bound, but it should be labelled as such rather than sold as free.

**NOTE both models independently corrected my citation**: MM45 carries the premises at
FL_SL_XMSS_MT_ES.ec:4075-4087 / :6306-6318 and discharges them in **SPHINCS_PLUS.ec:4375-4560**; Kimi adds
that the discharge MECHANISM is "**the top adversary is oracle-free**" — stronger than "the reduction answers
those queries itself". Our infrastructure for exactly that already exists (`member_aware_disj_discharged`,
WOTS_C_Interactive.ec:2045-2054). Also flagged: the negative control `A_ht_dfC_breaks_wf` shows the premise is
load-bearing *for the current win bool* — it is NOT evidence the restriction is semantically necessary.

### ROUND-2 RULING 2026-07-19 — objection UPHELD; do NOT delete the conjunct; build the oracle-free top discharge

GPT-5.6 round-2 (cross-examination) ruled on the delete-vs-discharge divergence. **My objection is CORRECT**;
it withdrew any delete leaning. Verified by me against the paper text.

**(1) Power-neutrality FAILS pre-seed.** `pick` has oracles but no `pp`; `find(pp)` has `pp` but no oracles
(WOTS_C_Interactive.ec:302/319); `O_THFC_MA.query` computes with its PRIVATE stored seed and logs (:2071);
the oracle interface never exposes `pp` (TweakableHashFunctions.eca:569). A re-wrapper therefore has exactly
three options and all fail: call OC (creates the forbidden log entry), compute `thfc..pp..` inline
(impossible — no `pp` in pick), or defer to `find` (not an equivalent simulation; the value may control later
pre-seed target registrations, and `O.query` is gone by then). Formally, with C = the other five win
conditions and D = the disjointness conjunct: `Pr[conjunct-free win] = Pr[C] = Pr[C/\D] + Pr[C/\¬D]`, so
deletion adds exactly the collisions whose target coordinate was opened through the hidden-seed oracle;
`sup Pr[C/\D] <= sup Pr[C]` with **no generic equality and no bound on the added term**. Deletion is a genuine
STRENGTHENING, not a free cleanup.

**(2) DECISIVE — the PAPER ITSELF imposes the separation.** paper-nist-pqc2022.txt:817-818: *"The main purpose
of this oracle is to prepare for a challenge query. So the natural restriction we make is that queries to Thλ
should use different tweaks from the ones that are used for challenge queries."* And Thλ exists precisely for
our pre-seed problem (:812-816: no access to the public parameter at challenge-placement time ⇒ introduce Thλ,
which *shares the public parameter with the challenger*). Literal Def C.1 gives A1 ONLY its p `O_Prop` queries
(:1981-1992); App E's "oracle access to Th for A1" (:2293) is over a freshly generated Th, not an oracle
initialised with the hidden challenge P. ⇒ **our collection oracle + separation IS the paper's Thλ device with
the paper's own restriction. "Delete = return to the paper's assumption" is FALSE — deleting would DEPART from
the paper.** Our modelling is more paper-faithful than the delete-position credited.

**(3) The oracle-free top discharge is the recommended path — and needs no edits to certified files.**
`A_wf_ht` can be discharged externally in a NEW integration file by instantiating the existing leaf lemma
(XMSSMT_C_Reduction.ec:739) with the concrete top-reduction image, mirroring MM45 (component carries premises
:6306; top discharges structurally SPHINCS_PLUS.ec:4430; the external forger first appears in `forge` :1615).
Required additions: a `size(flatten roots) = 8*n*k` lemma, a fourth fact `dfC <> 8*n*k`, a nested-loop Hoare
invariant that all top-owned entries have member <> dfC, then apply `R_leaf_C_A_wf_MA`. NOTE
`member_aware_disj_discharged` (WOTS_C_Interactive.ec:2045) is NOT sufficient verbatim — it covers only
{8n, 8n*len, 8n*2}, missing the top reduction's `8*n*k` calls (SPHINCS_PLUS.ec:1581). Medium proof-engineering
cost, LOW semantic risk, **zero changes to WOTS_C_Interactive.ec / XMSSMT_C_Reduction.ec**.

**(4) Residual honesty item (unchanged):** the discharge removes `A_wf_ht` but does NOT by itself bound the
bespoke `Pr[S_TCR_C_Int_MA]` by standalone Def C.1 — hidden-seed non-target-member collection calls remain.
Either prove that bridge, or state the paper-facing assumption in its collection-lifted form
**`S-TCR(+C)(Th+C ∈ Thλ)`**, which is exactly how the paper states its own final bound (:833-837, Thm 5.2).

DECISION ADOPTED: build the oracle-free top-image discharge in a new integration file; do NOT delete the
conjunct; label the assumption as the Thλ-lifted S-TCR(+C) unless/until the standalone bridge is proved.

### ROUND-2 CONVERGENCE 2026-07-19 — Kimi REVERSES; both models + the paper now agree. Path settled.

Kimi K3 round-2 explicitly reverses its delete recommendation: *"If my earlier position was 'delete', I now
reverse it"* — for three reasons it re-derived independently: `pick` has no `pp` (:302-305); Def C.1's A1 has
no Th access (paper:1984-1998) so deletion is a STRENGTHENING not a return; and the member-aware discharge
already exists in-file, so deletion's entire motivation (avoiding discharge work) is moot.

**The conjunct is LOAD-BEARING, not an artifact** (Kimi's reversal finding): it is *"the fence that makes the
OC-augmented game coincide with Def C.1's winning power"*, and it is **the same idiom in which every
`SM_DT_*_C` term of the already-certified SPHINCS+ bound is stated** (SPHINCS_PLUS.ec:4356-4370). So our
formulation is not a bespoke weakness — it is MM45's standard assumption idiom.

**IMPORTANT CORRECTION to Position B as I had framed it:** discharging a TWEAK-ONLY `A_wf` is **impossible,
not merely costly** — the premise is FALSE for the hypertree adversary, because the file's own analysis proves
the pkco tweak of `ad` *is* `emb_tw ad` (WOTS_C_Interactive.ec:1950-1964), making tweak-only disjointness
unsatisfiable. **You cannot discharge a false premise.** Position B survives ONLY in its member-aware form —
which is exactly the third path. This retro-justifies the member-aware machinery: it is what makes the premise
true at all.

**THE ADOPTED PATH (both models, converged) — concrete-adversary member-audit discharge:**
The top EUF-CMA forger F is oracle-free (its only oracle is the CMA signing oracle, SPHINCS_PLUS.ec:4339); it
computes hashes inline from the pk. Hence in the composed adversary `R_int_STCRC(R_leaf(F))` **every**
`OC.query` site is syntactically reduction-owned, so `A_wf_MA` becomes a concrete provable Hoare goal:
 - `R_int_STCRC`'s chain-walk queries (member `8n`) — **ALREADY PROVEN**: `owrap_chainwalk_member8n` (:2764-2782).
 - `R_leaf`'s own queries — pkco `8n*len`, trh `8n*2`, f `8n` — need while-invariants over its concrete choose
   loops (MM45's own pattern: premises FL_SL:6307-6318 discharged by concrete while-proofs SPHINCS_PLUS.ec
   :4375-4560, query shapes :1544-1587).
 - Then `member_aware_disj_discharged` (:2045-2054) + the FLAG facts (`dfC = 8n+32 ∉ {8n, 8n*len, 8n*2}`, plus
   **`8n*k` once FORS layers are in scope**) closes it at the existing application point (:2218).
**Cost (Kimi): a few hundred lines of EC** — while-invariants tracking `size x ∈ {8n, 8n*len, 16n}` via
`DigestBlock.valP`/`size_cat`/`size_flatten`, precedented twice over. **No new axioms, no game edits, no
re-certification, no edits to any certified 0-admit file** (`A_wf_MA` is a premise instantiated by the
CONSUMING file).

**ASSUMPTION LABEL (settled):** ship it as `InSec` of `S_TCR_C_Int_MA` over `Adv_ISTCRC` = **Def C.1 stated in
the MM45 SM-DT-C collection idiom with member-aware freshness** — identical in kind to every other assumption
term in the shipped bound — plus the one-sentence note: *restricted to adversaries making no collection
queries it is verbatim Def C.1; collection queries at challenged coordinates are losing.* Demanding a
syntactically-verbatim standalone Def C.1 term would require either the batch certified theorem (wrong game
for the interactive composition) or a ROM equivalence hop (out of scope) — so the idiom form IS the correct
ship target. (GPT-5.6's equivalent framing: the Thλ-lifted `S-TCR(+C)(Th+C ∈ Thλ)`, which is how the paper
states its own Thm 5.2 bound.)

⇒ FOUNDATIONS QUESTION CLOSED. Two independent frontier models + the paper text converge. Next build items,
both unblocked and independent: (1) grind-in-find for branch 2; (2) the member-audit discharge above.

### 2026-07-19 — BOTH BUILD TRACKS LANDED (audited); plus a CRITICAL GATE DEFECT found + fixed

Parallel workflow, independently adversarially audited (auditor did not rely on either self-report).
**Both tracks PASS. Neither touched any certified file** (verified by git diff).

**GATE DEFECT (found independently by BOTH agents; my bug, now fixed).** `scratch-ecc.sh` piped EasyCrypt
through `tr|grep|grep|tail`, so `$?` was *tail's* and always 0 ⇒ `ec-certify.sh` always set `comp=OK` and
reported CERTIFIED-0-ADMIT **even on files EasyCrypt REJECTED** (demo: a lemma proving `false` ⇒
"cannot save an incomplete proof", still green). FIXED: the script now captures EasyCrypt's own rc via a
sentinel and exits with it; the negative control correctly FAILS. **RE-VERIFIED with the fixed gate:
XMSSMT_C_Reduction.ec, _seam_byequiv_wip.ec, _okc_ghost_dev.ec, _seam_tree_reductions_wip.ec and
_member_audit_wip.ec are ALL genuinely CERTIFIED-0-ADMIT** — the defect only misfired when compilation
actually failed, so no prior green claim was a false positive. The auditor additionally swept the transitive
trust base (WOTS_C_Real/Scheme, XMSSMT_C_Scheme, WOTS_C_Interactive, upstream SPHINCS_PLUS.ec): all 0-admit.

**TRACK A — grind-in-find: DONE (drafts/_seam_tree_reductions_wip.ec, 3 commits, CERTIFIED-0-ADMIT).**
Both tree reductions restructured. Audited independently: brace-matched extraction of both `pick` bodies gives
**ZERO `grindC` and ZERO `encode_msgWOTS_C`** (each now occurs exactly once, in `find`); **no `ps`/pseed module
variable exists** in either reduction (the only seed touched is `find`'s parameter = the game's own `pp`;
`O_THFC.init` ignores its arg and is called `init(witness)`, MM45-identical); and **both `find` bodies contain
0 `O.query` and 0 `OC.query`**, rebuilding the cube with the pure `cf` chain function over the seeds `pick`
sampled. `pick` is MM45-verbatim in the deletions-only sense — mechanically checked by normalising both bodies
(undoing clone renames) and diffing against MM45, with the comparison harness itself negative-controlled
(perturbing an oracle address arg / a loop bound / deleting an oracle call are each CAUGHT). The unsound
design is now structurally unreachable: re-injecting `grindC ps` fails with "unknown variable or constant: ps".
⇒ stock games for both branches, no new assumption.

**TRACK B — member-audit: DONE (drafts/_member_audit_wip.ec, CERTIFIED-0-ADMIT).** Built more than scoped:
`size_trco_input` (the FORS-layer trco input sits at member `8*n*k` — the only new size fact a top audit
needs); the four-member set `mem4/in_thfc4 = {8n, 8n*len, 8n*2, 8n*k}` with `mem4_neq_dfC`,
`all_in_thfc4_neq_dfC`, and `member_aware_disj_discharged_4` (built on the IMPORTED `member_sep_disj`, so no
edit to the concurrently-owned file); `othfcma_query_mem4` / `owrap_query_mem4`; **`R_leaf_C_members4` — the
concrete Hoare while-invariant audit over R_leaf's nested cube-build loops**, proving every reduction-owned
`OC.query` records a member IN the set; `R_leaf_C_A_wf_MA_members4`; and the payoff
**`leaf_reduction_MEUFGCMAWOTSC_bound_members4`** — the leaf bound with `A_wf_ht` replaced by a mechanically
producible 4-set audit. KEY INSIGHT: the POSITIVE-set form is required — the existing `=8*n` twin
`owrap_chainwalk_member8n` is UNUSABLE once pkco/trh entries exist (`all(=8n)` becomes false while
`all in_thfc4` survives); the positive set is composable, strictly stronger than the terminal `<>dfC` form.
Controls: `A_ht_dfC_breaks_members4` (negative — premise load-bearing) and `A_ht_trco` (**positive — a FORS
trco query SATISFIES the 4-member premise but VIOLATES the 3-member one, proving the fourth member is
NECESSARY once FORS is in the composed adversary**, not decorative).

**HONEST RESIDUALS (Track B self-documented, auditor concurred):** (a) the concrete SPHINCS+C TOP reduction
`R_top` DOES NOT EXIST — the end-to-end discharge is NOT closed, and the agent *deliberately declined* to build
a free-floating stand-in "because it would be indistinguishable from faking the discharge"; (b) the four
`dfC <> {8n, 8n*len, 8n*2, 8n*k}` facts remain THREADED HYPOTHESES (dfC is an abstract op, so the parameter
arithmetic cannot be discharged in EC here); (c) R_leaf's forge-selection SOUNDNESS is still deferred
(untouched by this track — the bound remains the D1-composition leg only); (d) the premise on A_ht is
RESHAPED (into a mechanically-producible member-set audit), not eliminated.

### 2026-07-19 — RESIDUAL PICKUP: R_top BUILT (A_wf DISCHARGED), forge-soundness residual proven STALE, branch-2 started

Three parallel residual tracks, independently audited: **all three PASS**. (The auditor's `no_cert_file_edits:
false` is a FALSE ATTRIBUTION — the only dirty do-not-modify file is drafts/FORS_C_TreePort.ec, mtime
2026-07-17, diff byte-identical to what the PREVIOUS audit reported before these tracks existed, and no commit
of any track touches it. It is the concurrent session's work.)

**T1 — R_top BUILT + AUDITED + PAYOFF (drafts/_rtop_wip.ec, CERTIFIED-0-ADMIT, 8 commits).** This closes the
`A_wf` discharge that has been open since the start of this program.
 - **R_top defined**: the +C analog of MM45's R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA (SPHINCS_PLUS.ec:1490-1595),
   FORS cube-build mirroring :1544-1587 (6 nested loops, 3 OC.query sites), simulated CMA oracle, forge that
   installs the hypertree pk/sig list, runs F, and re-derives the forged FORS pk as the hypertree message.
 - **The load-bearing condition is ENFORCED BY TYPING, not inspection** (stronger than I specified): a new
   interface `Adv_EUFCMA_C (O : SOracle_CMA_C)` is a functor of the SIGNING oracle ALONE, so F structurally
   CANNOT receive OC; auditor independently confirmed `A(O_CMA).forge` appears only in `forge` and `choose`
   never mentions A. Consequently the audit is **PREMISE-FREE** (unlike R_leaf_C_members4, which needs
   `call A_wf_ht`).
 - **`R_top_members4` PROVED** — a real 6-nested-while Hoare proof, `othfcma_query_mem4` at each site
   (FORS leaf 8n via DigestBlock.valP; node 8n*2 via size_trh_input; root 8n*k via size_trco_input); smt only
   on size side-conditions; MM45's valid_tbfidx/insubdK/dist_adrstypes arithmetic NOT needed (type axis vs our
   length axis), exactly as predicted. Proved first try.
 - **PAYOFF `leaf_reduction_MEUFGCMAWOTSC_bound_Rtop`**: the leaf bound at `A_ht := R_top(F)` with the
   member-set premise discharged — **NO adversary well-formedness hypothesis of any kind on F**. Remaining
   hypotheses are the inherited WOTS+C side-conditions + the four abstract dfC facts; none constrain F.
 - Controls incl. the compiled **`R_top_OC_leak_breaks_members4`**: building R_top_OC + F_leak with the
   forbidden OC pass-through PROVES the postcondition fails ⇒ the no-leak condition is load-bearing.

**T2 — the forge-soundness residual is STALE (drafts/_compose_wip.ec, CERTIFIED-0-ADMIT).** SPLIT VERDICT:
 - **(b) "R_leaf_C's forge-selection correctness is unproven" is NOW FALSE.** `seam_branch1_WOTSC` IS that
   direction: its LHS event is "A_ht produced a VALID (real +C verify: size-d, root-match, allOkC) and FRESH
   forgery in the WOTS bucket", its RHS is "R_leaf_C(A_ht) WINS the WOTS+C game", and the conseq at :2559
   discharges exactly that implication with nothing else assumed. A residual I had carried since milestone 2
   was already closed by branch-1.
 - **(a) stays TRUE of the leaf bound taken alone** (it bounds the WOTS+C game, not the hypertree game).
 - **PRECISION**: what is discharged is the CONDITIONAL (bucket-win ⇒ R_leaf_C-win). Bucket REACHABILITY (the
   flag disjunction) is a SEPARATE obligation — so the bound is not vacuous-by-emptiness. Anti-vacuity controls
   run: dropping the S_TCR summand fails; flipping the find-predicate to the pkco-bucket disequality fails.
 - **NEW RESIDUAL R1 (previously untracked, genuine):** the game-level **real → C → V hops are ABSENT** from
   the port. branch-1's LHS is the _V_ game; both instrumented games are DEFINED but NEITHER hop lemma exists
   (verified by a declaration-level grep over all of drafts/). This must be built before branch-1 says anything
   about the REAL game.

**T3 — branch-2 byequiv started (drafts/_seam_branch2_wip.ec, 3 labelled admits, 7 commits).** Closed: the
statement + full combining scaffold (both mu_splits + ler_add chaining, over the SAME V-game instantiation and
flag carrier branch-1 fixed, so the branches chain); the **ZERO CASE fully**, via a new 0-admit
`ht_telescope_contra`; **PKCO PART 0 (choose alignment) fully**, including the inline/swap reindex and the
cross-clone FC{1}~PKCOC{2} oracle hop (both verified to be Collection clones with identical instantiation).
Two consequences of Track A's grind-in-find land here as concrete deltas from MM45: `swap 16 11` (not MM45's
`swap 16 10` — +C inserts `allOkC <- true`) and `seq 7 7` (not `seq 7 8` — R.pick no longer has a `sigWOTStd`
init). New operators ht_chad/ht_root/ht_cnt/ht_sigc characterize the honest +C sig-cube element and were
checked TWO-SIDED (against both the V-game element line and find's grind-in-find rebuild).

**REMAINING (precise):** R_top's and R_leaf's REDUCTION SOUNDNESS (the composed bound is still the
D1-composition leg); FORS+C signer not wired into R_top's simulated CMA game (the load-bearing fact that
survives: the +C delta does not touch `choose`, which is why the audit and payoff are unaffected); the four
dfC-separation facts remain threaded hypotheses; R1 (real→C→V hops); R2 (the other two buckets = T3's work);
capstone premise discharge for `allnchads`.

### 2026-07-20 — game hops: C~V CLOSED 0-admit; REAL~C substantially ported; branch-2 no-template step CLOSED

Two parallel tracks, independently audited: **BOTH PASS** (`no_forbidden_edits: true` — the attribution
guidance worked, no repeat false violation).

**H — GAME HOPS (drafts/_gamehops_wip.ec, 4 admits, 8 commits).**
 - **HOP C~V CLOSED 0-ADMIT** (standalone certificate at commit 4f99e8f). Auditor-verified GENUINE: post is
   `={res}` with NO weakening; the coupling is an explicit 4-level elementwise cube invariant + wp/skip
   transcription, not an smt-forced shell.
 - **The one genuinely +C obligation IS PROVED, not assumed:** V's accumulated `allOkC` is carried as
   `allOkC0{1} = allOkC{2}` against C's INLINED `FL_SL_XMSS_MT_C_ES.verify -> root_from_sigC`, so the +C
   constant-sum gate is literally the same object on both sides. Anti-vacuity: replacing V's gate with
   `(allOkC \/ true)` breaks the proof.
 - **A port artifact MM45 does NOT have:** our C game carries a SEPARATE `counterstd` cube while V carries a
   FUSED `(sigWOTS,cntr)` cube, so MM45's `seq 12 12 ... by sim` does not apply. Closed with the explicit cube
   invariant + the `rng_tidxdiv`/`rng_tidxmod` index ranges — which are LOAD-BEARING, not decoration: an
   out-of-range `nth witness` on the fused side is `witness<:sigWOTS*cntr>`, which is NOT provably
   `(witness<:sigWOTS>, witness<:cntr>)`. Tactic drift was real and as warned (swap 17 14 vs MM45 16; seq 13 12
   vs 12 12; inline{1} 5 vs 3) — all resolved with ec-goal.sh, never guessed.
 - **HOP REAL~C: substantially ported, 4 labelled admits** (LPTAIL/NTTAIL/TDTAIL/H1-B), each with its MM45
   template range and pending goal. CLOSED: the tail drain, the leaves drain, the full 4-level cube
   characterisation STATEMENT with both +C additions (counter cubes via `grindC` at the chtype keypair address;
   sigWOTS via `encode_msgWOTS_C ... (grindC ...)` in place of MM45's `encode_msgWOTS`), and the ENTIRE
   innermost (len) level incl. the `ch_comp` two-step->one-step composition. Remaining = 3 outer nested-while
   maintenance steps (MM45:3743-3822) + the signing alignment (:3823-3961): mechanical-to-medium transcription,
   NO new crypto content.
 - **LIFT banked but CONDITIONAL:** `EqPr_..._Orig_V` + `seam_branch1_lifted_to_REAL` exist and the auditor
   confirms the composition soundly licenses the lift — but it depends on the admitted REAL~C hop, so
   **branch-1 does NOT yet lift to the REAL game.** Correctly not claimed. Nice correctness detail: the lift
   REFUSES to mu_split on the REAL game (which never writes C.valid_WOTSTWES) and splits on the V side, which
   legitimately writes that flag.

**B2 — BRANCH-2 (drafts/_seam_branch2_wip.ec, 3 admits — count UNCHANGED, content materially reduced).**
 - **ADMIT-1b(i) FULLY CLOSED 0-admit — the grind-in-find find-prologue `seq 0 4`, explicitly the ONE step
   with NO MM45 template** (it exists only because of our grind-in-find refactor). Proved as a 4-deep
   one-sided `while{2}` (d / nr_trees / l' / len).
 - **ADMIT-1a reduced** from "the whole cube-build (MM45:4766-5100)" to "the inner-tree body only
   (:4854-5093)": both the outer (per-layer) and middle (per-inner-tree) two-sided `while` invariants are now
   STATED and BOTH adequacy gates CLOSED 0-admit (established-at-entry, and implying the next level).
 - **8 new 0-admit pure lemmas/operators**, reduction-agnostic so they also serve the untouched TRH admit.
   4 anti-vacuity controls run, all failing as required.
 - **Honesty catch:** the prior STATUS block predicted `hencb` would be consumed in the find-prologue; it is
   NOT (both sides encode with `encode_msgWOTS_C`). The block self-contradicted and its NOT-CLAIMED half was
   the correct one. Also recorded 4 new port deltas (e.g. after the inlines `find` claims the unsuffixed local
   names, so side-2 locals inside `pick` are `rootsntp0`/`root0`/... — writing `={rootsntp}` would be wrong).
 - Explicitly stated: ZERO of the three originally-named admits is FULLY discharged; the count is unchanged.

**NET:** the +C-specific content in both tracks is now proved (allOkC coupling; the no-template find-prologue);
what remains in both is MM45 transcription with known template ranges.

### 2026-07-20 — REAL~C CLOSED: the game-hop chain now starts from the REAL game (still conditional on branch-2)

Two parallel continuations, independently audited: **BOTH PASS**, including `h2_lift_claim_honest: true`.

**H2 — ALL FOUR REAL~C ADMITS CLOSED; drafts/_gamehops_wip.ec is CERTIFIED-0-ADMIT** (5 commits).
`Eqv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Orig_C` is now 0-admit, so with the already-closed C~V hop the chain
REAL ~ C ~ V is complete. Auditor verification that the statement was not weakened to make it provable: the
hop statement is **byte-identical across all seven commits** from pre-closure to post
(`={glob A, glob OC} ==> ={res}`), and the region contains only two conseq steps (`==> ={sigl}`,
`==> ={sapl}`) — **no `==> true`, no `(true)` intermediate post**; no `declare axiom`/`hypothesis` hiding a
closure. The transitive dependency sweep (the check ec-certify CANNOT give, since `require` loads .eco without
re-verifying) comes back CLEAN, so the 0-admit claim bottoms out in real proofs.
 - **THE LIFT IS HONEST AND STILL CONDITIONAL.** `seam_branch1_lifted_to_REAL`'s LHS is the genuine REAL game,
   and the complement summand `Pr[V : res /\ !valid_WOTSTWES]` is EXPLICIT IN THE STATEMENT rather than buried;
   the in-file note reads "HONEST STATUS OF THE LIFT — STILL NOT UNCONDITIONAL". So: the hop chain genuinely
   STARTS from the REAL game, but the branch-1 bound is not yet an unconditional REAL-game bound — the
   complement bucket is exactly branch-2's two tree reductions.
 - Seven port deltas MM45's script does not tell you were recorded, incl. one NOT in the prior residual note
   and load-bearing: MM45 removes `O_THFC_Default.init(ps)` via `inline *`, which we cannot (our OC is
   abstract), and the invariant form `call (: ={glob OC})` is REJECTED on a direct OC call. Fix: swap the
   independent `ad <- adz` past the sampling/init so wp can consume it, then discharge the identical prefix
   with a FORWARD `seq 2 2 : (={glob A, glob OC, ps}); 1: by sim` — the seq post must stay purely relational
   (sim rejects `ad{2} = adz`).
 - AXIOM SCOPE (honest): the ONLY two axiom declarations in the entire transitive require-closure are
   `dpp_ll` (STCR_C.ec:53, a clone-parameter losslessness side condition) and MM45's own `dist_adrstypes`
   (SPHINCS_PLUS.ec:111, address-type distinctness). Neither is a smuggled cryptographic assumption.

**B3 — branch-2: 3 admits (count unchanged), but 1a shrank to a leaf.** ADMIT-1a-INNERTREE went from the whole
inner-tree body (MM45:4854-5170) to a single entry/exit leaf (:5163-5177). CLOSED 0-admit: part (a) the
side-2-only tree-hash nodes loop (:4854-4943) and part (b) the ENTIRE two-sided l' loop (:4944-5162) —
invariant, per-keypair body (len loop + one-sided chain-walk), per-keypair leaf, full ts/uniq/leaves
bookkeeping. **Grind-in-find made this SIMPLER than MM45**: side 2's `pick` has no `em` and builds no
signature, so the chain-walk is a plain 0..w-1 walk and MM45's `if (i0 = em_ele)` sig-reveal branches were
DELETED; at the l' level MM45's `={sigWOTSlp}` is replaced by the one-sided `ht_sigc_at` characterisation.
Remaining: the 1a leaf (small), 1b-rest (root reordering + signing simulation + extraction), and ADMIT-3 TRH
(untouched, the larger branch, MM45:5338-6298).

**TOOLING FIX (my bug, found by the REAL~C track):** `ec-goal.sh` had a hardcoded `timeout 90`; on these large
files cli was killed mid-transcript and the script then printed **the last goal it had seen — from a DIFFERENT
lemma — with no warning**. A silent wrong answer handed to an agent. FIXED: default 600s (EC_GOAL_TIMEOUT
override) and a timeout now exits 124 with a DO-NOT-TRUST banner. Also recorded the fast-loop technique that
made this session feasible: a gutted copy with every OTHER proof body replaced by `admit.` and all statements
untouched — goal states inside the target proof stay byte-identical, and it compiles in ~18s vs ~2min.
(Coordination note: a concurrent session overwrote an agent's probe script in the shared scratchpad; agents
should namespace scratch files under a private subdir.)

### 2026-07-20 (cont.) — branch-2 PKCO nearly done (3->2 admits); TRH developed in parallel; two more METHOD hazards

Audited: **both tracks PASS** (p_genuine, t_selfcontained, no_forbidden_edits all true).

**P — PKCO finish (drafts/_seam_branch2_wip.ec, 3 -> 2 admits, 3 commits).**
 - **ADMIT-1a-INNERTREE-LEAF CLOSED** ⇒ **PART 1a (cube-build establishment) is now 0-admit at ALL THREE
   levels** (outer/middle/inner-tree), so the `seq 7 7` post is DERIVED from the programs rather than merely
   proved adequate — that was explicitly under NOT-CLAIMED in the incoming block.
 - **ADMIT-1b-rest (i) root reordering + (ii) THE WHOLE SIGNING-LOOP SIMULATION closed 0-admit.** The +C
   content here is real: MM45 discharges this entire step with `seq 2 2 ...; by conseq />; sim` because ITS two
   signature cubes are equal AS LISTS. **`sim` is unavailable to us** — side 1 reads a (sigWOTS,cntr) PAIR from
   the honest cube while side 2 BUILDS the pair from R.sigWOTStd and R.counterstd (grind-in-find defers the
   cube to find). They agree only by TRANSITIVITY through ht_sigc, which required producing the edivz index
   bounds first. Auditor read `ht_sigcube_transitivity` in full: genuine, non-vacuous.
 - Auditor's strong check: **smt() appears only on bounded index/telescope side goals with explicit hints and
   is NEVER the top-level closer**; the seq 2 2 post carries the full ~19-conjunct cube invariant (no weakening).
 - **CORRECTION to an inherited claim:** the previous block asserted 1b part (iii) "carries over from MM45
   UNCHANGED". FALSE — its post carries two conjuncts MM45 lacks: `dist{2}` and
   `STCRC_WC.Col.disj_lists twsO{2} twsOC{2}` (the member-aware disjointness obligation). Now corrected in-file.

**T — TRH branch (drafts/_branch2_trh_wip.ec).** The agent DIED on an API stream-idle timeout, but the
incremental-commit discipline preserved **5 commits** of real work: PART 1a skeleton (outer+middle two-sided
while invariants), the PART 1a ADEQUACY GATE (0-admit), the PART 1a LAYER-RCONS (0-admit), the INNERTREE
sub-skeleton, and the l' KEYPAIR body incl. the chain walk (0-admit). Its block carries 4 honest, finer-grained
admits (TRH-1a-NODESBODY / -KEYPAIRLEAF / -INNERTREE-LEAF / TRH-1b-rest).

**TRANSPLANT MECHANICS (flagged by the auditor):** T forked from P BEFORE P's two closures, so T's shared
prefix still contains the OLD 1a/1b admits. Only T's APPENDED TRH block may be moved onto P's current file,
then recompiled. Note the count arithmetic: transplanting replaces P's single ADMIT-3 with T's 4 — the raw
number goes UP while the granularity gets strictly FINER.

**TWO MORE METHOD HAZARDS (both cost real time; now recorded):**
 1. **EasyCrypt's `trivial` NEVER FAILS** — it closes the goal if it can and is a SILENT NO-OP otherwise. In a
    gutted fast-loop copy whose tail is a row of `admit.`s, a non-closing `trivial` is absorbed by the next
    admit and the batch compile still exits 0: a **FALSE GREEN that scratch-ecc.sh cannot detect**. The
    reliable closure gate for a gutted copy is the EXACT TRAILING-ADMIT-COUNT LADDER (k-1 must fail downstream,
    k clean, k+1 reports "all goals are closed"). The real file's `qed` with N admits remains the strongest gate,
    since EasyCrypt refuses to save an incomplete proof.
 2. **`ec-goal.sh` can print a STALE PRE-`split` GOAL** after a `split` that in fact succeeded — a second
    reliability failure in that script (the first was the silent timeout truncation, fixed earlier today).
    Treat its output as a hint, not ground truth, and cross-check with the admit ladder.

**STATE:** branch-2 PKCO has 1 admit left (1b-rest-(iii): the A.forge call, reconstruction loop, pkco collision
extraction + fidx arithmetic, PLUS the two +C post conjuncts above); TRH has 4 finer admits pending transplant.

### 2026-07-20 — branch-2 PKCO half 0-ADMIT; TRH one sub-part left; THIRD gate defect fixed + ALL claims re-verified

**P2 — the LAST PKCO admit is CLOSED.** `ADMIT-1b-rest-(iii)` (A_ht.forge call + d-step reconstruction loop +
pkco collision extraction + fidx arithmetic; MM45 :5150-5325 plus two +C post components) is proved, so **the
ENTIRE PKCO half of `seam_branch2` is 0-admit**: the chain `seq 5 10 -> seq 7 7 -> seq 0 4 -> seq 2 2 -> (iii)`
is derived end-to-end from the two programs, and the first `ler_add` summand carries no admit.
 - **NO new premises forced.** `seam_branch2`'s statement is BYTE-IDENTICAL (sha256 ef4885d989143120) across
   all six commits — auditor-verified, no premise sneak-in. Stronger: part (iii) consumes NONE of the three
   hypotheses (RUN control: prefixing its tactic block with `clear hencb allnpkcoads allntrhads.` still
   compiles clean on the exact admit ladder). Structural reason: `Adv_...forge` has an EMPTY oracle annotation,
   so the adversary cannot append to the THFC tws during forge and the type conjunct survives the call free.
 - **CORRECTION to my earlier framing:** the disjointness discharged in (iii) is the GENERIC TYPE-INDEX form
   (`! has (mem tws) (unzip1 ts)`, via hasPn/mapP/allP), NOT a member-aware notion — it imports none of
   branch-1's `member_sep_disj`/`dfC` machinery. Branch-1's member-aware obligation is a DIFFERENT obligation
   living in `seam_branch1_WOTSC`. I had conflated them.

**T2 — TRH is one sub-part from done.** `ADMIT-TRH-1a-NODESBODY` (the ~326-line inner node tree-hash level with
target-set bookkeeping, MM45 :5625-5950 — the largest block of the branch), `-KEYPAIRLEAF` (incl. the
collection-input LENGTH bridge) and `-INNERTREE-LEAF` are all CLOSED 0-admit ⇒ **TRH PART 1a is 0-admit at all
three levels**. `ADMIT-TRH-1b-rest` (i) root reordering + (ii) the whole signing-loop simulation are closed;
only (iii) remains. NO new premises forced (the TRH branch is type-disjoint from the WOTS-chain axis, so none
of branch-1's extra premises are needed). Its file shows 4 admits, but 3 are the STALE COPY of `seam_branch2`
it forked from — the real TRH residual is ONE.

**THIRD GATE DEFECT (mine), found by the auditor: STALE .eco CACHE HITS.** EasyCrypt skips recompilation when
the target's own `.eco` is newer than its `.ec`, so `ec-certify` could return an INSTANT `compile=OK` **without
ever reading the current file**. The auditor caught it with full pristine compiles + a `DELIBERATE_BREAK`
canary (3m21s / 5m36s, sole error at the canary line). FIXED: the gate now deletes the target's own `.eco`
first (never dependencies). Honest cost: 3-6 min per real compile. Negative control correctly FAILS.
(Running tally of gate defects, all caught by agents, none by me: (1) exit status was `tail`'s, always 0;
(2) `ec-goal.sh` 90s timeout silently printed a goal from a DIFFERENT lemma; (3) stale-.eco green.)

**RE-VERIFICATION UNDER THE FIXED GATE (forced real recompiles, no cache) — ALL CLAIMS HOLD:**
```
_gamehops_wip.ec        compile=OK  admit-tactics=0  axiom-decls=0   CERTIFIED-0-ADMIT
_rtop_wip.ec            compile=OK  admit-tactics=0  axiom-decls=0   CERTIFIED-0-ADMIT
_seam_branch2_wip.ec    compile=OK  admit-tactics=1  axiom-decls=0   (ADMIT-3 / TRH — expected)
_branch2_trh_wip.ec     compile=OK  admit-tactics=4  axiom-decls=0   (3 stale-copy + 1 real TRH residual)
XMSSMT_C_Reduction.ec   compile=OK  admit-tactics=0  axiom-decls=0   CERTIFIED-0-ADMIT
```
So the REAL~C + C~V game hops, R_top with its A_wf discharge, and the base reduction file are all genuinely
admit-free under real compilation — no stale-cache false green anywhere.

### MILESTONE 2026-07-20 — BRANCH-2 COMPLETE: seam_branch2 is CERTIFIED-0-ADMIT (independently canary-verified)

The TRH branch's last admit closed and the transplant landed, so **both `ler_add` summands of the XMSS-MT+C
component bound are now proved**.

**`seam_branch2` — CERTIFIED-0-ADMIT** (compile=OK, admit-tactics=0, axiom-decls=0), on the exact committed
bytes, via a REAL ~8-minute compile (the gate deletes the target's own .eco). Independent census on the
comment-stripped source: 0 admits, 0 axiom/hypothesis/sorry/admitted. ADMIT-3 is gone, replaced by
`by apply (seam_branch2_trh A_ht &m hencb allntrhads).` (line 5046).

**AUDITOR'S INDEPENDENT VERIFICATION — the decisive evidence.** Rather than trusting either track, the auditor
compiled a pristine copy (byte-identical for its first 5402 lines) with a tail canary
`lemma AUDIT_CANARY_FALSE : false`: 8m09s, EXACTLY ONE error — `cannot save an incomplete proof` at the
canary's own qed. EasyCrypt stops at the first error, so **no error before that line proves the entire body
typechecked — both `seam_branch2_trh`'s qed and `seam_branch2`'s qed were accepted.** It explicitly defended
against BOTH known gate failure modes: it pre-verified the container could write .eco into the scratch dir
(killing the FALSE-RED artifact, see below), and the 8-minute duration rules out a stale-cache instant green.
 - **STATEMENT INTACT:** seam_branch2's header through `proof.` extracted from the pre-integration commit and
   from the current file — 1600 bytes each, **diff EMPTY**. The integration commit's ONLY deleted line is the
   ADMIT-3 admit.
 - **NO HIDDEN PREMISE:** `seam_branch2_trh` takes only `hencb` + `allntrhads` — a strict SUBSET of
   seam_branch2's three premises, both already in scope. Nothing new enters its obligations.
 - **GENUINE:** smt is NOT the top-level closer anywhere on the critical path; seam_branch2_trh ends in
   structural rewriting (`by rewrite ... bs2intK. qed.`).
 - Anti-vacuity RUN: deleting ONLY the apply line yields `cannot save an incomplete proof` ⇒ load-bearing.

**THREE REAL TRH PORT DELTAS (not renames):** the conseq post loses MM45's `dist` conjunct by itself (it is
literally `uqunz1ts`, closed by assumption during `/>`); `0 <= fidx` cannot use MM45's bare `?addr_ge0
?mulr_ge0` cascade because we do not import IntOrder — the bare names are SILENT NO-OPS inside `?...` and
MM45's focus indices are invalid (the port's one real compile failure); and MM45's `0 * (2 ^ h - 1)` padding is
a hard error because bare `h` is AMBIGUOUS (FSSLXMTWES.h vs SPHINCS_PLUS.h).

**FOURTH TOOLING HAZARD — a FALSE *RED* (mirror of the false greens):** the ec-grind container runs as uid
1001 and cannot write into a host-created scratch subdir, so EasyCrypt typechecks the whole file successfully,
fails ONLY on the .eco write, and **exits 1 with NO diagnostic**. That nearly produced a wrong "the premise IS
consumed" conclusion. **Discriminator: rc=1 WITHOUT a `[critical]` line means it actually compiled.** (Its
second-order trap — `bash scratch-ecc.sh F | tail -n` makes `$?` tail's, always 0 — is the same pipe bug fixed
earlier, resurfacing in agent usage; capture rc with a redirect, not a pipe.)

**HONESTY NOTE from the TRH agent:** it committed a causal claim ("fails so the rewrite can unify"), its own
control CONTRADICTED it (the real cause is name ambiguity), and it RETRACTED the claim at the site and in a
follow-up commit. The tactic was never wrong — only the stated reason.

**STATE OF THE CHAIN NOW (all forced-recompile verified):** `seam_branch1_WOTSC` 0-admit; `seam_branch2`
0-admit; the REAL~C and C~V game hops 0-admit; R_top + its A_wf discharge 0-admit; `XMSSMT_C_Reduction.ec`
0-admit. Remaining toward an unconditional statement: assembling the two branches with the hops into a single
REAL-game bound, discharging the three carried type premises (allnchads/allnpkcoads/allntrhads) at the
capstone, R_top's reduction SOUNDNESS, and the FORS+C wiring.

## MILESTONE 2026-07-20 — THE XMSS-MT+C COMPONENT THEOREM IS PROVED (real game, 0-admit, canary-verified)

`lemma EUFNAGCMA_FLSLXMSSMTTWCESNPRF` (drafts/_assembly_wip.ec:8439) proves, for the **REAL** EUF-NAGCMA game:

```
Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A_ht, FC.O_THFC_Default).main() @ &m : res]
  <=  Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_leaf_C(A_ht)), ...)]        (WOTS-TW)
    + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_leaf_C(A_ht)), ...)]                  (the +C S-TCR term)
    + Pr[PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(A_ht), ...)]                (pkco)
    + Pr[TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(A_ht), ...)]                  (trh)
```
proved by chaining `seam_branch1_lifted_to_REAL` and `seam_branch2`. This is the +C analog of MM45's
component theorem, and it is the culmination of the whole chain: game hops (REAL~C~V), branch-1 (WOTS bucket),
branch-2 (pkco+trh buckets), the okC-ghost, the O_V oracle hop, grind-in-find, and R_top's A_wf discharge.

**INDEPENDENT AUDIT — the auditor ran its OWN gates, not the tracks':**
 - CANARY forced real compile: pristine 8588-line body + a canary lemma proving false ⇒ the ONLY error is at
   the canary's own qed (line 8592). EasyCrypt halts at the first error, so **the entire body typechecks and
   all 47 proofs close**. Its own comment-stripped sweep: 0 admit tactics, 0 axiom decls.
 - **LHS INTEGRITY — it really is the REAL game**, not the V game: the module is defined exactly once (:278),
   distinct from `_C` (:1177) and `_V` (:1419), uses real keygen/sign and the +C verify (size gate + root
   match + allOkC). ZERO occurrences of any `valid_*` flag in the statement.
 - **NO DROPPED SUMMAND**, verified by breaking a DIFFERENT one than the track did: deleting the trh summand
   (whole-file diff = only those lines) gives `cannot prove goal (strict)` at the smt() line, WITH a
   `[critical]` line (so it is not the uid-1001 false-red). Load-bearing on the real, un-gutted artifact.
 - Premises: ELEVEN, the exact union of the two ingredients, `move=>` intro list matching 1:1. The four hoare
   premises sit over FOUR DIFFERENT oracle instances and are carried SEPARATELY — no cross-instance
   identification is assumed. Carrying them is MM45-faithful (its component theorem carries three and
   discharges them only at the capstone). Non-vacuity of the member premise is separately PROVEN by
   `A_ht_dfC_breaks_wf`, which exhibits a concrete violating adversary.

**THE ONE REAL FINDING — a premise-DISCLOSURE gap (audit flipped `premises_fully_disclosed` to false):**
the header advertises eleven premises and claims to be "exactly the union", but a **clone-inherited axiom
rides in undisclosed**: `drafts/Grind.ec:47` clones `FinType as CntrFT` and its `enum_spec` obligation is never
realized (the file's own comment even asserts "No new axiom is introduced" — that is wrong as stated; it is
carried as a modelling fact that the counter type is finite/enumerable). Not a soundness break — the real
counter type IS finite — but the premise list is incomplete AS ADVERTISED and must be disclosed. The auditor
BOUNDED the leak: `TweakableHashFunctions.eca` has exactly one axiom (`in_collection`) and STCR_C realizes it,
and the `dpp` losslessness obligation is realized ⇒ **`enum_spec` is the SOLE port-introduced undischarged
clone axiom, not the first of many.** (Plus `dpp_ll` in STCR_C.ec and MM45's own base axioms as cited TCB.)

**SCOPE CAVEATS — these must travel with any quotation of the theorem:**
 1. **OC is FIXED to `FC.O_THFC_Default`**, not universally quantified. A version quantified over OC is NOT proved.
 2. **This is the NPRF game** (WOTS keys sampled uniformly from a cube), not the full PRF-keyed scheme. The
    key-generation PRF hop is a separate deliverable. Faithful to MM45's component level, but this is NOT the
    complete scheme.
 3. **The WOTS-TW summand is left as the M-EUF-GCMA game term, NOT unfolded** into UD/TCR/PRE. MM45's analog
    unfolds to five summands. So this is a component theorem relative to a GAME, not relative to base hash
    assumptions.
 4. The four adversary-restriction premises are CARRIED, discharged only at the capstone (R_top discharges the
    member-based one for the concrete reduction image; the three type premises remain).

**HONEST HEADLINE:** the XMSS-MT+C hypertree component bound is machine-checked end-to-end over the real game,
0-admit, modulo eleven disclosed premises + one undisclosed clone axiom (now disclosed here) + the four scope
caveats above. It is NOT yet a SPHINCS+C EUF-CMA theorem: that needs the capstone composition, the premise
discharges, R_top's reduction soundness, FORS+C, and the PRF hop.

### 2026-07-20 (cont.) — WOTS-TW summand UNFOLDED to base-hash terms; all four R_top restriction premises DISCHARGED

Two parallel tracks on the certified component theorem, independently audited: **both FAITHFUL AND HONEST**
(u_honest / t_honest / no_hidden_premise all true; verdict: no overstatement, dropped summand, or papered
oracle mismatch). Grind.ec's self-contradictory disclosure comment was corrected first (enum_spec IS a
clone-inherited undischarged obligation, now disclosed).

**U — the WOTS-TW GAME summand is now BASE-HASH TERMS** (drafts/_assembly_unfold_wip.ec:8708,
`EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Unfolded`, CERTIFIED-0-ADMIT via a real ~12-min compile with the .eco written).
Instantiated MM45's premise-free `MEUFGCMA_WOTSTWESNPRF` (WOTS_TW_ES.ec:6269) at
A := R_int_WOTSTW(R_leaf_C(A_ht)) to replace summand 1 with `(w-2)*|UD(false)-UD(true)| + TCR + PRE`. The bound
is now SIX summands: **1-3 UD/TCR/PRE [base hash], 5-6 pkco/trh SM-DT-TCR-C [base hash]** — and **4 =
S_TCR_C_Int_MA, the bespoke +C grinding-counter interactive S-TCR game [NOT a base hash assumption], carried
unchanged, still awaiting its own reduction (MM45 has no counterpart).** So the audit's goal is met FOR THE
WOTS-TW SUMMAND (5 of 6 are now base-hash), not yet for the whole bound.
 - **TWO new premises CARRIED, disclosed in the header (11 -> 13):** the losslessness facts
   `A_ht_choose_ll` / `A_ht_forge_ll` — the exact analogue of MM45's own section declare-axioms
   (FL_SL_XMSS_MT_ES.ec:2742/2750), UNAVOIDABLE because A_ht is abstract. The composed-reduction losslessness
   obligations were genuinely PROVED (while-variant scripts) down to these abstract-adversary facts. Both
   RUN-verified load-bearing (premise:=true breaks the apply).
 - **Oracle instances line up with NO bridge:** WOTS_TW_ES.ec:450 does `clone import Collection as FC`, so its
   bare `O_THFC_Default` IS `FC.O_THFC_Default` — machine-verified via `print`; the composition is a plain
   smt() with no cross-clone hop.

**T — ALL FOUR adversary-restriction premises DISCHARGED for R_top** (drafts/_rtop_typeaudit_wip.ec,
admit=0/axiom=0, auditor's own canary compile GREEN): `R_top_allnchads` (chtype), `R_top_allnpkcoads`
(pkcotype), `R_top_allntrhads` (trhxtype), plus bonus `R_top_A_wf_ht` (the member axis in exact
capstone-collapsed form). **The failure mode I flagged was AVOIDED:** the pkco/trh lemmas are stated over
`R_SMDTTCRCPKCO_C(R_top(F),..).O_THFC` / `R_SMDTTCRCTRH_C(R_top(F),..).O_THFC` — the EXACT instances the
component theorem names — NOT over R_top's own instance. Premise-free in F (oracle-freeness enforced by
typing). Each statement is character-identical to the component premise under A_ht := R_top(F).
 - **Disclosed side-conditions (not hidden):** `R_top_A_wf_ht` needs a FOURTH `dfC <> 8*n*k` fact (explicit in
   its signature); and the T file is a SEPARATE compilation unit that reproduces R_SMDTTCRCPKCO_C/
   R_SMDTTCRCTRH_C locally, so cross-file MODULE IDENTITY is a carried assumption (bodies diffed identical).
 - Out of scope, labelled: R_top reduction SOUNDNESS (R3) and the FORS+C signer wiring (R4) — R_top still
   simulates SPHINCS+ with a +C hypertree.

**WHERE THE CAPSTONE STANDS NOW:** all four restriction premises HAVE a discharge for the concrete top-image
(T), and the WOTS-TW summand rests on base hashes (U). What remains for a SPHINCS+C EUF-CMA theorem: reduce
summand 4 (the +C S-TCR term) to a standard assumption OR state it as the paper's Thl-lifted S-TCR(+C); prove
R_top's reduction SOUNDNESS; wire FORS+C; add the PRF (NPRF->PRF) hop; and assemble T's discharges + U's
unfold + the losslessness facts into one capstone lemma (currently these live in separate compilation units).

### 2026-07-20 — U-file (unfold) 0-admit INDEPENDENTLY re-confirmed by my own forced canary compile

The workflow auditor had confirmed the T file with its own canary compile but the U-file compile had not
returned at its report time. I reproduced it myself: pristine copy of `drafts/_assembly_unfold_wip.ec` (8882
lines) + an appended `lemma _U_AUDIT_CANARY : false`, real forced compile (target .eco deleted, chmod-777
scratch). Result: `rc=1`, and the SOLE `[critical]` line is `cannot save an incomplete proof` at line 8886 —
the canary's own qed. EasyCrypt halts at the first error, so nothing before 8886 errored ⇒ the entire body
(including `EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Unfolded`) typechecks and every proof closes. So `CERTIFIED-0-ADMIT`
on the unfold file is now verified at THREE independent levels (build track → workflow auditor → this session),
matching the earlier component-theorem verification standard.

### 2026-07-21 — Wave 1: item 1 (S-TCR summand) RESOLVED at the honest level; item 4 (PRF hop) STRUCTURE + composition, 2 legs open

First items on the new fast require-base (XmssmtCC_All; ~2s compiles). Both audited HONEST, neither overstates.

**ITEM 1 — S-TCR summand: DONE at the honest level (drafts/stcr_reduction_wip.ec, CERTIFIED-0-ADMIT,
canary-verified).** Resolves the "summand 4 is not a standard assumption" caveat correctly:
 - `summand4_le_std` (in exact component-theorem syntax): bounds summand 4 by the standard single-member
   SM-DT-TCR(+C) 2nd-preimage advantage on member `thfc dfC`, consuming the PROVEN predicate bridge
   `S_TCR_C_Int_MA_win_implies_2ndpreimage`. So the +C summand now rests on **the paper's named collection-aware
   S-TCR(+C) / InSec notion (Def C.1, Thm 5.2)**, and its winning event is a genuine standard TCR collision.
   `disj_lists_nil` documents the twsMA=[] collapse to verbatim Def C.1. 0 axioms; two modelling hyps
   (emb_in_len/emb_in_inj) THREADED (not axioms), both negative-control-verified load-bearing.
 - **HONEST NAMING CAVEAT (audit-flagged):** the RHS is still the paper's Def C.1 INTERACTIVE notion (counter/
   grind oracle), NOT a plain non-interactive SM-DT-TCR; the `std`/`asStd` naming could momentarily mislead.
 - **PART 2 — reduction to PLAIN SM-DT-TCR: BLOCKED, and the block is a MACHINE-CHECKED FINDING.** Two
   obstruction lemmas (`grind_via_OC_breaks_disj`, `readd_tweak_breaks_dist`) prove: the +C challenge oracle
   grinds a pp-dependent counter and RETURNS it; a reduction can't reproduce that in the standard oracle
   interface (pp hidden until find) without recording the target tweak into twsO or twsOC, falsifying
   dist/disj_lists on exactly the winning runs. ⇒ **the +C message-compression layer genuinely needs the
   counter-oracle S-TCR(+C) assumption, not plain SM-DT-TCR** — a rigorous reason (matching the paper's ROM
   argument), not a hand-wave. This is the correct, final resolution: summand 4 IS the paper's assumption, and
   here is why it can be nothing weaker.

**ITEM 4 — PRF hop: STRUCTURE + composition proved, 2 byequiv legs OPEN (drafts/prf_hop_wip.ec, 2 admits).**
 - Defined `FL_SL_XMSS_MT_C_ES_PRF` (PRF-keyed +C-hypertree keygen), `EUF_NAGCMA_FLSLXMSSMTTWCESPRF` (PRF game),
   and `R_SKGPRF_FLSLXMSSMTC` (genuine R_SKGPRF-style reduction to the SKG PRF property) — all TYPECHECK.
 - `SKGPRF_hop` (Pr[PRF-game] <= Pr[NPRF-game] + |SKG-PRF term|) and `SKGPRF_hop_composed` (folds into the
   component theorem) are ADMIT-FREE proofs — but they CONSUME two admitted byequiv legs, so the composed
   bound is CONTINGENT.
 - **The 2 open legs (precise):** `EqPr_PRF_false` (setup seq: `sim` cannot carry the keygen-LOCAL{1} =
   O_PRF-GLOBAL{2} key equality + the RHS-only `!b{2}` predicate across A.choose + the abstract OC.init) and
   `EqPr_NPRF_true` (not attempted). A known EC pattern — closeable with an explicit invariant instead of sim.
 - **Scope honesty (disclosed):** stated at the HYPERTREE level; MKG is N/A here (only SKG applies); does NOT
   compose to a full-scheme PRF hop (FORS+C keys + MKG term deferred with the FORS+C item).

Net: item 1 resolved honestly (with a bonus impossibility result); item 4 is structurally there with 2 focused
byequiv legs to close. Remaining: item 3 (FORS+C wiring), item 2 (R_top soundness), item 5 (capstone).

### 2026-07-21 — Wave 2: item 4 (PRF hop) CLOSED; item 3 (FORS+C wiring) milestone met (R_top_C typechecks)

Both tracks audited PASS, no overstatement (independent forced-recompile + canary + negative controls).

**ITEM 4 — PRF hop: CLOSED (drafts/prf_hop_wip.ec, CERTIFIED-0-ADMIT).** The two open byequiv legs are now
machine-checked admit-free:
 - `EqPr_PRF_false` (b=false) and `EqPr_NPRF_true` (b=true) closed via the standard early-vs-late sampling swap:
   swap the RHS O_PRF init block DOWN past the abstract prefix (ad<-adz; ps<$; OC.init; A.choose) so NO one-sided
   fact crosses the direct abstract OC.init (which rejects `call (: ={glob OC})` — the exact XmssmtCC_All.ec:4683
   branch-1 precedent), carrying the one-sided b/ad via a 3-arg conseq side-2 hoare (the Reprogramming.ec:312
   idiom). False leg couples ss{1}=k{2} at the cube (rcondf b=false); true leg ports MM45's lazy/eager
   map-domain invariant WOTS-only with per-query freshness via HA.eq_adrs_idxsq address-injectivity.
 - `SKGPRF_hop` + `SKGPRF_hop_composed` are now UNCONDITIONAL (previously consumed the 2 admits). smt() appears
   only in the top-level hop arithmetic (a<=b+|a-b|), never forcing a byequiv (audit-confirmed). Statements
   byte-identical to the admit-era versions. 0 admits / 0 axioms / 0 new premises (one stdlib `FMap` import).
   Two negative controls (flip a freshness index; off-by-one domain range) both FAIL → injectivity + invariant
   load-bearing. Scope unchanged: hypertree-level SKG hop; full-scheme MKG term still deferred with FORS+C.

**ITEM 3 — FORS+C wiring: milestone met (drafts/rtop_forsc_wip.ec, R_top_C typechecks CERTIFIED-0-ADMIT).**
`R_top_C : Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF` is the C10 FORS+C variant of the base R_top (XmssmtCC_All.ec:9443).
 - MODEL CHOICE (decisive, not a shortcut): target the DEPLOYED C10 FORS model, not the paper model. The base's
   top sig type `sigSPHINCSPLUSTWC = mkey * FTWES.sigFORSTW * sigFLSLXMSSMTTWC` (XmssmtCC_All.ec:9419) is ALREADY
   the C10 shape (mkey*sigFORSTW, no counter). So my 5-delta plan's "3-arg grinding mco" + "mkeygen swap" are
   PAPER-model deltas that are legitimately N/A here (FTWES.mco is 2-arg; the FORS cube is built via OC.query,
   no keygen call) — honestly explained, audit-confirmed not faked.
 - THE ONE REAL +C DELTA, wired concretely: O_CMA.sign replaces R_top's memoized uniform draw
   (`mk <$ dmkey; mmap`) with the C10 fresh CONDITIONED draw `mk <$ dcond dmkey (good_fors m)` (mmap dropped),
   where `good_fors m mk = (nth witness (FTWES.g (FTWES.mco mk m)) (k-1)).`3 = 0` is `predC_fors` UNFOLDED onto
   FTWES's concrete g/mco — so the simulated oracle's grinding-conditioning is tied to the SAME digest the
   reduction evaluates (faithful; not an abstract stand-in). choose / FTWES.mco / FL_FORS_ES_NPRF.sign /
   pkFORS_from_sigFORSTW are byte-identical to R_top (all +C-invariant).
 - HONEST RESIDUAL (deferred to the soundness track, NOT a typecheck barrier): `good_pos` / `p_nu` — the
   positive-good-mass assumption (for some mk, good_fors holds); `dcond` is well-typed for any predicate (zero
   good-mass degrades to dnull, a dead signer, rather than failing to compile). good_pos is a NAMED assumption
   already carried in FORS_C10.ec, needed only for the LOSS term — the FORS-side analogue of Grind.ec's
   grind_fails/p_nu WOTS carry. Reduction SOUNDNESS (item 2) explicitly deferred, not claimed.

STATUS OF THE 5 ITEMS: item 1 RESOLVED (honest relabel + impossibility finding); item 4 CLOSED; item 3
milestone (R_top_C typechecks). REMAINING: item 2 (R_top_C soundness — the crux) then item 5 (capstone).

### 2026-07-21 — SCOPING item 2 (R_top_C soundness) + THE ASSUMPTION LEDGER (read this before any capstone claim)

A read-only source scope of the top reduction (cite-checked) plus an advisor pass reset the plan. Two load-bearing
facts, recorded here so they gate every downstream claim:

**FACT A — item 2's LHS object does not exist yet.** The base (XmssmtCC_All.ec) defines and well-formedness-AUDITS
R_top but proves NO soundness probability bound; it says so itself twice (C.7 at :9889-9895, R3 at :10622-10624).
There is no `SPHINCS_PLUS_C` scheme module, no top +C EUF-CMA game, no `NPRFNPRF_V` validity-inlined +C game, no
`valid_MFORSC10 = (pkFORS' = pkFORS)` split predicate, and no top FORS reduction. The "payoff" lemma
`leaf_reduction_MEUFGCMAWOTSC_bound_Rtop` (:9695) is the WOTS+C LEAF bound instantiated at A_ht:=R_top(F), NOT top
soundness. So R_top_C inherits a blank soundness slate. Item 2 therefore DECOMPOSES — it is not a one-shot push.
The MM45 template is `SPHINCS_PLUS.ec` section `Proof_SPHINCS_PLUS_EUFCMA` (:1631-4609), whose six game-hops
(Orig->PRFPRF; SKG-PRF; MKG-PRF; NPRFNPRF->V + mu_split on valid; VT->FORS-EUF; VF->NAGCMA via RV) item 2 mirrors.
Plan (advisor-endorsed): take **hop-6 (VF: R_top_C soundness) as the next milestone** — the RHS NAGCMA game already
exists (base :278; R_top_C is already typed to it) and the coupling is a single coupled `rnd` on a shared `dcond`
with NO mmap-memoization invariant (genuinely simpler than MM45). The clone `good == good_fors` (FORSC10-onto-FTWES)
is expected to bite ONLY the VT branch (hop-5), because hop-6/the V-game use concrete `good_fors` throughout and the
split predicate never mentions abstract `good` — to be confirmed by grep before building.

**FACT B — THE CAPSTONE IS A REDUCTION TO AN EXPLICIT LEDGER, NOT AN UNCONDITIONAL THEOREM. "Capstone assembled"
must NEVER be read as "SPHINCS+C EUF-CMA proven."** The genuinely hard PQ crypto is NOT in the scaffolding items —
it is the *carried, unreduced* leaf assumption below. When the capstone lands, its statement is
`Pr[EUF_CMA(SPHINCS+C10) : forger wins] <= (sum of the ledger terms)`, and the ledger is:

  1. **ITSRC10 — the load-bearing UNREDUCED assumption (the ~102-bit gap).** `EUFCMA_MFORSC10`
     (FORS_C10_Multi.ec:472-491) proves, under the H-TREE-MULTI premise,
       Pr[EUF_CMA_MFORSC10(A, O_CMA_MFORSC10)] <= Pr[ITSRC10(R_ITSRC10_MFORSC10(A), O_ITSRC10_Default)]
                                                   + mtree_openpre + mtree_trh + mtree_trco.
     The multi->single legs ARE proved (byequiv). But the leaf `Pr[ITSRC10(...)]` — the FORS+C
     interleaved-target-subset-resilience tight bound (single-instance game FORS_C10.ec:276) — is a NAMED,
     NONSTANDARD, UNREDUCED assumption, carried and never numerically bounded (black-box route loses ~102 bits,
     FORS_C10.ec:86-91; the direct route needs a concentration inequality EC does not have; FORS_C10_Multi.ec:53-62).
     THIS is where the +C security ultimately rests. Every capstone claim MUST foreground it.
  2. `mtree_openpre` / `mtree_trh` / `mtree_trco` — FORS Merkle-tree premises (explicit).
  3. **S-TCR(+C) counter-oracle** — summand 4 (Def C.1 / Thm 5.2), the paper's interactive grind-oracle notion
     (proven irreducible to plain SM-DT-TCR, this doc's 2026-07-21 Wave-1 entry).
  4. **SKG-PRF** (proven-admit-free hop, Wave 2) and **MKG-PRF** — but see the OPEN QUESTION below on whether the +C
     conditioned draw structurally absorbs MM45's MKG-PRF hop-3 (item-4 note: "MKG N/A at hypertree level"); resolve
     at full-scheme scope before assuming a hop-3 term exists.
  5. `good_pos` (FORS_C10.ec:208) — FORS mkey positive-mass / well-definedness (consumed via losslessness upstream,
     NOT an additive loss term for hop-6; a two-sided identical `dcond` couples under `rnd` regardless).
  6. `CntrFT.enum_spec` (Grind.ec) — WOTS+C counter-type finiteness (a faithful MODELLING axiom; the deployed
     counter is a bounded machine int) — and `Grind.grind_fails`/p_nu, the WOTS+C counter-grind FAILURE event,
     carried ADDITIVELY as adversary loss on the hypertree/WOTS side.
  7. `emb_in_len` / `emb_in_inj` — the S-TCR member modelling hypotheses (Wave-1, load-bearing, negative-control-checked).
  8. MM45's OWN inherited base axioms (e.g. `dist_adrstypes`) — outside our port's TCB but part of the total trust base.

So: the port's DELIVERABLE is a machine-checked reduction chain assembling the above into a single EUF-CMA bound
with an explicit, auditable assumption ledger — NOT a from-nothing unconditional proof. That is the honest claim,
and it is a strong one; overstating it as "SPHINCS+C is proven EUF-CMA" would retroactively undercut the whole
honest-track record. (good_pos gates the 0-NEW-axiom story of the good==good_fors clone, not whether the reduction
exists: worst case re-types FORS_C10's already-carried g-axioms at the concrete FTWES types — an existing ledger
entry re-typed, not a new assumption.)

### 2026-07-21 — Wave 3: the good==good_fors clone lands 0-NEW-AXIOM; hop-6 (VF) stated + 2/3 legs proven

Both tracks audited PASS, no overstatement (independent forced-recompile + canary + non-vacuity controls).

**CLONE PROBE — good == good_fors: 0 NEW AXIOMS (drafts/good_clone_probe.ec, CERTIFIED-0-ADMIT).** The scout's
"single biggest risk" resolves on the cleanest ledger line. `clone FORS_C10.FORSC10 with mco<-FTWES.mco, g<-FTWES.g,
...` succeeds and:
 - ALL FIVE g-axioms (size_g/eqiks_g/neqisvs_g/rng_g/uniq_g, FORS_C10.ec:166-192) DISCHARGE as PROVED LEMMAS from
   FTWES's concrete `g = mkseq(...)` (rng_g the only one needing the BLKAL `size(val m)=k*a` invariant). `print
   C.size_g` etc. report `lemma`, not axiom. This is STRICTLY BETTER than the advisor's worst case (re-typed
   carried axioms): they become theorems.
 - `good_eq_good_fors` PROVED (C.good = good_fors, pure delta-unfold) — the two are the same op both provably and
   definitionally-by-clone.
 - SOLE residual: `good_pos` (= the paper's p_nu positive-good-mass, FORS_C10.ec:208) re-typed at the concrete
   FTWES.mco/dmkey/g instance — `print C.good_pos` reports `axiom`. It is the SAME assumption FORS_C10 already
   carries, NOT new, and genuinely un-dischargeable (a legal base model can force good-mass to 0).
 - HONEST METRIC CAVEAT: ec-certify's `axiom-decls=0` is a file-TEXT metric (good_pos is INHERITED, not textually
   declared) — it does NOT mean "0 assumptions." The ledger line is: 0 NEW axioms, sole entry = re-typed-carried good_pos.

**VF SOUNDNESS (hop-6) — stated with exact MM45 shape, 2/3 legs proven (drafts/rtop_c_soundness_wip.ec, 1 admit).**
 - STEP-0 CONFIRMED (structural, both external reviewers): hop-6 is CLONE-FREE. `good_fors` enters only (i) the
   oracle mk-draw `mk <$ dcond dmkey (good_fors m)` — byte-identical on V_C and R_top_C sides, so it couples by a
   single `rnd` on the shared dcond EXPRESSION (couples even if dcond degrades to dnull => NO good_pos needed here),
   and (ii) the carried-then-dropped forced-zero is_valid gate. The abstract-`good` clone is isolated to the VT
   branch (hop-5, out of scope). So hop-6 lands independent of the clone — a clean "VF clone-free / VT gated on the
   (now-0-new-axiom) clone" story.
 - Built V_C (`EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V`, mirror MM45 :2186-2239: fresh conditioned mk-draw, FORS-sign via
   FTWES, valid_MFORSC10 <- pkFORS'=pkFORS) and RV_C (the RV intermediate, mirror :2602) — both typecheck.
 - PROVEN: `Eqv_Orig_RV_C` (NAGCMA(R_top_C(F)) ~ RV_C(F) via sim, non-vacuity canary-verified) + inside hop-6 the
   RHS-rewrite leg and the opening ad/ps coupling. hop-6 `LeqPr_VF_C` statement byte-matches MM45 :3468-3471.
 - ADMITTED (1, load-bearing): the core V_C~RV_C coupling, with a precise 3-leg residual — R6a (FORS-cube <->
   committed-pkFORS invariant, the BULK, +C-invariant, MM45 :3482-3564 establish / :4176-4277 consume; "genuinely
   large ~800-line near-verbatim port"); R6b (oracle-call equiv via the single coupled rnd + sigl-table invariant);
   R6c (validity/freshness event mapping, :3935). Its TRUTH is argued (hand + GPT-5.6 + Kimi, ~10 falsifiers tried,
   none held) but NOT yet machine-checked.
 - FIDELITY FIX (GPT-5.6, source-verified): V_C's is_valid was missing the C10 forced-zero gate `good_fors m' mk'`
   (a subtly-wrong hybrid); added it (byequiv stays true — the conjunct only shrinks res{1}).

**LEDGER UPDATE — MKG-PRF RESOLVED (does NOT vanish).** The Wave-2 "MKG N/A at hypertree level" note is now precise:
the +C fresh conditioned draw makes MM45's hop-3 (memoized-uniform -> random-function) VACUOUS at the V-game/hop-6
level (no memoization to bite), but an MKG-PRF term PERSISTS at the +C FULL-SCHEME level (mkg_adv) — the fresh draw
is the OUTPUT of that idealisation (uniform dmkey) plus +C conditioning, not a replacement. So the ledger's MKG-PRF
entry STAYS; the fresh-vs-memoized deterministic-PRF faithfulness gap is the deferred full-scheme-wave question.

ITEM 2 STATE: hop-6 (VF) stated + 2/3 legs proven (1 coupling admit = ~800-line MM45-verbatim port); the clone it
would need on the VT side is de-risked to 0-new-axiom. REMAINING for item 2: close the hop-6 coupling admit; then
hop-5 (VT into EUF_CMA_MFORSC10, using the now-proven clone). Then item 5 (top scheme + PRF hops + composition).

### 2026-07-21 — Wave 4: hop-6 (VF) R6a-establish CLOSED; R6b/R6c residual (1 admit) — empirical scope read

Audit PASS, honest, no overclaim (forced recompile + canary-flip; statements byte-identical to pre-wave 0fcb7cd).
 - CLOSED: the R6a-ESTABLISH leg of the V_C~RV_C coupling inside `LeqPr_VF_C` — the FORS-cube <-> committed-pkFORS
   invariant (MM45 :3482-3564), now a PROVEN `seq 5 4` block (drafts/rtop_c_soundness_wip.ec:709), near-verbatim +C
   port (WOTS/HT keygen coupled via new keygenC_eq/keygenC_pkin helpers; full :3482-3503 conjunct set ported
   verbatim, not trimmed). Non-vacuity: falsifying the invariant's trco relation is REJECTED.
 - RESIDUAL (1 admit, :966, precisely documented with an in-file ACTIONABLE HANDOFF): R6a-CONSUME (:4176-4277 the
   nth_flatten/edivz arithmetic); R6b (the +C sigl-table as a ONE-SIDED `while{2}` — the genuinely-hard two-source
   merge; needs a phoare recast of the deterministic HT.sign closed form, reusable from _assembly_unfold_wip.ec:4816
   but currently TWO-sided); R6c (:3935-4278 the oracle-call coupling of the single mk `rnd` + the +C is_valid/
   is_fresh event map). hop-6 stays PARTIAL (2/3 legs + R6a-establish; 1 admit).

EMPIRICAL SCOPE READ: closing hop-6 fully is >1 wave (R6b is the hard leg). The remaining item-2/item-5 work is all
large +C-INVARIANT MM45 transcription — hop-6 R6b/R6c (~1-2 waves), then hop-5 VT (~1-2 waves), then the top scheme
module + Orig->V game chain + PRF-hop wiring + mu_split + composition (~2-4 waves). No new +C security content; the
ledger (ITSRC10 + the 7 others) is fixed. The +C-SPECIFIC intellectual work is COMPLETE; what remains is mechanizing
the reduction assembly that is already argued.

### 2026-07-21 — MILESTONE: the SPHINCS+C10 EUF-CMA CAPSTONE STATEMENT compiles (assembled reduction to the ledger)

The headline deliverable is now a single machine-checkable EasyCrypt theorem. `drafts/sphincs_c10_capstone_wip.ec`
(compiles rc=0; ec-certify = compile=OK, admit-tactics=6, axiom-decls=0). Audited PASS — "HONEST CONDITIONAL
REDUCTION, no soundness hole found; nothing silently dropped" (forced recompile + two RUN anti-vacuity controls:
deleting the `+ mkg_adv` summand breaks the final smt; false-canary rejected).

**`lemma EUFCMA_SPHINCS_PLUS_C10 &m`** states MM45's EUFCMA_SPHINCS_PLUS_FX 4-term bound, +C-substituted and
EXPANDED to leaf assumptions:
  p_sphincs_c <= skg_adv + mkg_adv
               + (Pr[ITSRC10] + mtree_openpre + mtree_trh + mtree_trco)      (FORS+C10 term)
               + (WOTS-TW+C multi + S-TCR(+C) + pkco-TCR + trh-TCR)           (hypertree term)

 - **2 of 6 RHS legs GENUINELY PROVEN**, wired to base theorems that are themselves 0-admit/0-axiom (source-verified
   term-for-term by the auditor, member-axis discharged via the proven R_top_members4 + the in-file-proven
   good_eq_good_fors): the FORS+C10 term via `M.EUFCMA_MFORSC10` (FORS_C10_Multi.ec:472) and the hypertree term via
   the component theorem `EUFNAGCMA_FLSLXMSSMTTWCESNPRF` (XmssmtCC_All.ec:8439) at A_ht:=R_top(F).
 - **6 explicit per-hop admits = the FX composition skeleton** (hop1..hop6), each with its MM45 line-ref +
   genuinely-open-vs-transcription-deferred status + missing invariant: Orig->PRFPRF (open), SKG-PRF (partial:
   proven 0-admit at hypertree level, scheme-level needs FORS+C keys), MKG-PRF (open), NPRFNPRF->V + mu_split
   (open; V_C game exists), VT/hop-5 (open; needs Adv_EUFCMA_C -> Adv_EUFCMA_MFORSC10 reduction + the now-proven
   clone + ITSR-C10 coupling), VF/hop-6 (partial: LeqPr_VF_C proven modulo the R6b/R6c admit).
 - **LHS is an HONESTLY-FLAGGED ABSTRACT real** `p_sphincs_c` over `F <: Adv_EUFCMA_C` — no concrete
   `module SPHINCS_PLUS_C10 : Scheme` exists (the +C scheme lives only as simulated CMA oracles inside reductions);
   building it = MM45's `module SPHINCS_PLUS` + the 2 Thm-5.2 substitutions, and MM45's FX is section-local with no
   clone shortcut, so it is the multi-month scheme-module remainder, stated as the CONCRETE-LHS residual.
 - **THE LEDGER is documented in-file and audit-verified COMPLETE**: the admit-census + the carried axioms (a
   comment-stripped live-axiom sweep over the 13-file transitive closure) cover ITSRC10 (foregrounded, the
   ~102-bit-gap carried PROBABILITY term, unreduced on the RHS — not an axiom), mtree_* (carried H-TREE-MULTI
   premise, false-at-zero so a hypothesis not an admit), S-TCR(+C) (STCR_C.dpp_ll + the S_TCR_C_Int_MA RHS term),
   SKG/MKG-PRF (skg_adv/mkg_adv reals), good_pos (live axiom via clone C), CntrFT.enum_spec, and MM45's base axioms
   (dist_adrstypes, ch0/chS/two_encodings, ...). Nothing silently dropped.

HONEST HEADLINE: **SPHINCS+C10 EUF-CMA REDUCES to {ITSRC10 + the 8-entry ledger + the 6 documented FX-skeleton
hops}, machine-checked exactly as stated — 2 of 6 hops proven against 0-admit base theorems, the other 4 explicit
admits over the (unbuilt) +C intermediate games, and the LHS an abstract real pending the concrete +C scheme
module.** This is NOT an unconditional proof of SPHINCS+C security; it is the assembled reduction whose admit list
IS the exact remaining +C-invariant MM45-transcription work. REMAINING: discharge the 6 hops (VF R6b/R6c and VT are
the crypto-adjacent ones; the rest are +C-invariant transcription) + build the concrete scheme-module LHS.

### 2026-07-21 — Wave 6: concrete SPHINCS_PLUS_C10 scheme module + EUF_CMA game built; capstone LHS grounded

Audit PASS. The abstract LHS is now backed by a real scheme game.
 - `drafts/sphincs_c10_scheme_wip.ec` (CERTIFIED-0-ADMIT, 0 new axiom): `module SPHINCS_PLUS_C10 :
   DSSC.Stateless.Scheme` — a faithful port of MM45 SPHINCS_PLUS.ec:957 keygen/sign/verify at the SAME seed sk, with
   the 2 Thm-5.2 substitutions: (i) FORS message key `mk <$ dcond dmkey (good_fors m)` + seed-based FTWES FORS,
   (ii) +C hypertree FL_SL_XMSS_MT_C_ES (seed-based). Output = sigSPHINCSPLUSTWC; verify gates on
   `good_fors m mk /\ size sigHT = d /\ root'=root /\ allOkC` (mirrors V_C is_valid). `EUFCMA_C10(F) =
   DSSC.Stateless.EUF_CMA(SPHINCS_PLUS_C10, F, O_CMA_Default)` for F<:Adv_EUFCMA_C TYPECHECKS (the #1 risk — the
   hand-written +C forger type structurally-subtyping into the DSSC-clone Adv_EUFCMA — empirically resolved).
   DSSC is a fresh clone of the already-in-closure axiom-free stdlib DigitalSignatures ⇒ 0 new axioms.
 - `drafts/sphincs_c10_capstone_concrete_wip.ec` (compiles, 6 admits unchanged, 0 axioms): a COPY of the capstone
   (the committed abstract one is INTACT) with the LHS re-grounded from the abstract real `p_sphincs_c` to
   `Pr[EUFCMA_C10(F).main() @ &m : res]`. hop1 just re-typed; admit count rose by 0.

HONEST CAVEATS (disclosed, both external reviewers + advisor converged):
 - IDEALISED-mk LEVEL: the built scheme draws `mk <$ dcond dmkey (good_fors m)` (the repo's standing fresh-draw C10
   model, rtop_c_soundness_wip.ec:100-125 / FORS_C10_Multi.ec:163-167 "matching production") rather than a
   deterministic `mkg ms m`. Consequence: `ms` is dead, the MKG-PRF hop is VACUOUS at THIS LHS, and signing is
   RANDOMISED (same m -> different sig, unlike MM45's deterministic scheme). So `Pr[EUFCMA_C10(F)]` is the advantage
   of the randomised-mk / real-skg-key IDEALISATION — defensible as the port's +C model, but NOT a byte-identical
   pre-MKG "Orig" of a deterministic deployed scheme; a deterministic-mkg Orig (making the MKG hop non-vacuous) is
   the faithfulness refinement if the capstone must be about the byte-identical deployed scheme.
 - COMPILES != CORRECT: scheme sign/verify CORRECTNESS (an honestly-generated signature verifies) is a separate
   equiv/phoare obligation, plausible by construction but NOT proven here.
 - This is the LHS OBJECT ONLY: the 6 MM45 FX byequiv/game hops (the multi-month remainder — build the +C
   intermediate game chain PRFPRF/NPRFPRF/NPRFNPRF/V + the reductions + the 6 byequivs) remain admits, none proven.

SESSION NET (2026-07-21, Waves 1-6, all adversarially audited): the +C-SPECIFIC intellectual content is COMPLETE
(item1 impossibility+relabel, item3 conditioned draw, item4 PRF hop CLOSED, the good==good_fors clone 0-NEW-AXIOM,
hop-6 VF R6a-establish); the SPHINCS+C10 EUF-CMA CAPSTONE STATEMENT compiles (2/6 hops proven vs 0-admit base thms,
ledger audit-verified complete, ITSRC10 foregrounded); and the concrete SPHINCS_PLUS_C10 scheme+game grounds the
LHS. REMAINING = the multi-month FX game-chain construction (the 6 hops) + scheme correctness + the
deterministic-Orig refinement — all +C-INVARIANT transcription, no new +C security content, ledger fixed.

### 2026-07-21 — Wave 7: scheme-correctness fragment + a FALSE-IN-PRINCIPLE finding; hop-6 R6b CLOSED (residual = R6c only)

Both tracks audited HONEST (forced recompile + canary-flips; statements byte-identical; no new axiom).

**TRACK A — scheme correctness: maximal unconditional FRAGMENT proved + a genuine modelling FINDING
(drafts/sphincs_c10_scheme_wip.ec, CERTIFIED-0-ADMIT).**
 - PROVED `sign_gates` (phoare = 1%r): the 2 of 4 verify-conjuncts DETERMINED BY sign's own output always hold on
   an honest signature at probability 1 — `good_fors m0 res.1` (via `dcond_supp` on the +C draw
   `mk <$ dcond dmkey (good_fors m)`) and `size res.3 = d`. Non-vacuity machine-checked (phoare=1%r not hoare;
   2 negative-control canaries rejected). good_pos exposed as a visible premise (= the carried axiom via
   good_eq_good_fors), NOT re-cloned, NO new axiom.
 - **KEY FINDING (source-verified, converged with GPT-5.6 + advisor): full `verify(honest sig) = 1%r` is FALSE IN
   PRINCIPLE for the abstract +C model.** verify gates on `allOkC`; the total +C grinder returns a FALLBACK counter
   when no good one exists (Grind.ec:79); and there is NO unconditional counter-existence axiom (predC is bare,
   `grindP` is DEAD/replaced by the conditional `grind_correct`). So an honest signature can REJECT — correctness
   holds only under a per-layer `exists c, predC (ThC ps ad m c)` hypothesis, i.e. exactly the p_nu / good-counter-
   existence event the security already carries (FORS_C.ec:95's "Pr[honest verifies] >= 1 - p_nu"). This is a
   MODELLING artefact, not a C10 flaw: the scheme's correctness is CONDITIONAL on the SAME good-counter-existence
   assumption as its security. Residual splits: R1 (`root'=root`, a multi-day proof-ASSEMBLY from existing
   components eq_valbt_valap/ch_comp/list2tree — not novel) + R2 (`allOkC`, the genuine +C completeness gap =
   the good-counter-existence hypothesis).

**TRACK B — hop-6 (VF): R6b (the HARD leg) CLOSED; residual narrowed to R6c ONLY (drafts/rtop_c_soundness_wip.ec,
1 admit).** A prior full wave (Wave 4) reached only R6a-establish; this wave added R6b + a new reusable phoare.
 - New asset `nprf_sign_cf` (CERTIFIED-0-ADMIT phoare = 1%r): characterizes the REAL `FL_SL_XMSS_MT_C_ES_NPRF.sign`
   as a pure d-layer closed form (built bottom-up from 3 inner-proc closed forms + closed-form ops; deterministic
   signer ⇒ unconditional; +C ground counter via encode_msgWOTS_C). Advisor-confirmed soundness anchor: it pins
   sig_cf_elem/ap_cf_elem to the actual signer, so R6c cannot satisfy them vacuously.
 - R6b (the +C sigl-table, the flagged hard leg) closed one-sidedly via `seq 1 2 + while{2} + call nprf_sign_cf`.
   hop-6 `LeqPr_VF_C` residual is now **R6c ONLY** (MM45 :3935-4278): the oracle mk-rnd coupling on the shared
   `dcond` (no mmap) + R6a-CONSUME (:4176-4277 nth_flatten/edivz arithmetic) + the validity/freshness map. The
   missing invariant to build = the mmap-free oracle relational invariant carrying the R6b table + the seq-5-4
   pkFORSnt-trco commitment through A.forge. Statements byte-identical (proof body only); non-vacuity confirmed
   (phoare-index + table-index perturbations + false-canary all rejected).

ITEM 2 (VF branch) is now one leg from complete: hop-6 = R6c only. Scheme correctness is a proved 2/4-conjunct
fragment + the precise (R1 assembly, R2 = p_nu-conditional) residual. Both landed with source-verified findings.

### 2026-07-21 — Wave 8: hop-6 (VF soundness) reaches 0-ADMIT; scheme-correctness root cores proved

Both audited PASS (forced recompile; 3 canary-flips each; statements byte-identical; no new axiom).

**TRACK C — hop-6 (VF) is now 0-ADMIT (drafts/rtop_c_soundness_wip.ec, CERTIFIED-0-ADMIT).** R6c closed →
`LeqPr_VF_C` (Pr[V_C : res /\ !valid_MFORSC10] <= Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(R_top_C(F), FC.O_THFC_Default)])
is a fully-proven theorem. The V_C~RV_C coupling is a REAL byequiv (proc/seq/call/sim reusing nprf_sign_cf /
genpkfors_flatten / keygenC_eq2), NOT smt-forced (the sole smt is the documented sound-weakening conseq entailment).
7 new proven helpers, headlined by `genpkfors_flatten` (the R6a-CONSUME identity gen_pkFORS(skFORSnt at idx) =
nth (flatten pkFORSnt) (val idx) via getsettrhf_kpidx + the seq-5-4 trco commitment). Non-vacuity: 3 canaries the
auditor re-ran, all REJECTED (Eqv ={res}->res<>res; LeqPr is_valid{2}->!is_valid{2}; seq-body sigFORSTW eq->neq).
The two +C simplifications vs MM45 (no mmap; MM45's HT-sign while collapses to the proven nprf_sign_cf closed form)
are what made the ~800-line port tractable across Waves 4/7/8. GPT-5.6 supplied exact lemma names + caught the
size sigl=l gap. **⇒ ONE of the two top-reduction branches (VF: forgery-is-a-hypertree-forgery) is fully
machine-checked; the sibling VT branch (forgery-is-a-FORS-forgery, via ITSR-C10) remains open.**

**TRACK R — scheme correctness: 2 root-round-trip cores proved (drafts/sphincs_c10_scheme_wip.ec, CERTIFIED-0-
ADMIT, PARTIAL).** Proved (each canary-verified, assembled from pre-existing components, no new axiom):
`val_ap_cons_ap_trh_rt` (the hypertree Merkle layer round-trip, from eq_valbt_valap + size/nth_consap + list2tree
facts, mirroring SPHINCS_PLUS.ec:1965-1983 lifted to a standalone verify-side op-lemma) and `cf_roundtrip` (the
WOTS+C chain leaf round-trip via ch_comp). HONEST SCOPE (auditor-corrected): this is NOT a proven root_eq theorem
nor "3 of 4 conjuncts" — conjuncts [1]good_fors + [2]size=d are proved (Wave-7 sign_gates), [3]root_eq = these 2
cores + an open d-layer procedure-assembly (R1a/R1b/R1c: lift cf_roundtrip through the len-loop; the d-layer index-
alignment induction; the verify-side FORS pkFORS round-trip — real relational EC work, multi-day, not novel), and
[4]allOkC stays the R2 hypothesis (unconditionally FALSE per Wave 7; also transported via R1b/R1c). The conditional-
correctness lemma is STATED (comment-only; its per-layer good-counter premise is a stated hypothesis, not an axiom).

STATE: VF branch DONE (hop-6 0-admit). Remaining item-2/item-5: hop-5 (VT, the ITSR-C10 branch); the FX chain
(hops 1-4, Orig->V); the root-round-trip assembly; and the uppercase-refactor to wire the proven hops into the
capstone (discharge its admits). All +C-invariant transcription except VT (crypto-adjacent) + the carried ITSRC10.

### 2026-07-21 — Wave 9: hop-5 (VT) FINDING — abstract MFORSC10 is an unprovable/vacuous reduction target; R1c (FORS round-trip) proved

Both audited HONEST. Track T produced a MACHINE-CHECKED FINDING that refines the capstone's FORS leg.

**TRACK T — hop-5 (VT): the reduction + bridge built (0-admit), but LeqPr_VT_C is UNPROVABLE-OR-VACUOUS against
the ABSTRACT FORS+C game (drafts/rtop_c_vt_wip.ec, 1 admit by design).** Proved 0-admit: the M-clone of
FORS_C10_Multi.MFORSC10 onto concrete FTWES; `good_eq_good_fors_M` (the +C bridge, M.F.good = good_fors) +
`dcond_good_eq` (the mk-rnd coupling — the proven "+C bite" that hop-6 was free of); and `R_fors :
M.Adv_EUFCMA_MFORSC10`, a genuine MM45-shape reduction (delegates the FORS mk-draw to M.O_CMA_MFORSC10, HT-signs
locally, extracts the reconstructed-pkFORS forgery — turns the capstone's "no reduction exists" into a typed one).
 - **THE FINDING (advisor x2 + GPT-5.6 converge, MACHINE-CHECKED): `LeqPr_VT_C : Pr[V_C:res /\ valid_MFORSC10] <=
   Pr[M.EUF_CMA_MFORSC10(R_fors(F))]` is unprovable-or-vacuous as stated.** FORS_C10_Multi.MFORSC10 is an ABSTRACT
   theory whose `fverify` (and fsign/mkeygen) are UNCONSTRAINED ops; `fverify := false` is a LEGAL instantiation ⇒
   Pr[RHS]=0 keygen-independently (proved: `rhs_zero_fverify_false` via a legal Mz clone, CERTIFIED-0-ADMIT). Pr[LHS]
   never mentions fverify, so the bound holds only if Pr[LHS]=0 in every model — unprovable (VT is reachable, as in
   MM45) or vacuous. **IMPLICATION for the capstone:** its FORS term, wired via the abstract M.EUFCMA_MFORSC10, is
   potentially VACUOUS (that theorem's bound is true but says nothing under fverify:=false), and hop-5 cannot connect
   p_vt to it. The abstract op-level FORS+C game is NOT a sound reduction target.
 - THE FIX (named residual): a CONCRETE PROCEDURAL FORS+C multi-game — fverify defined as reconstructed-key equality
   + predC_fors, mkeygen/fsign concrete — then port MM45's keygen+signing coupling (SPHINCS_PLUS.ec:3143-3174/
   3307-3327; concrete FORS_ES pieces verified in-source). CONSTRAINT (D2): V_C samples the FORS cube
   `skFORS_ele <$ ddgstblock` INDEPENDENTLY of ps, so the concrete game's mkeygen must sample the cube the same way
   for the coupling to hold. OPEN SUB-QUESTION: is Pr[LHS]>0 establishable (VT reachable)? If not, it dents the
   Pr[V_C]=VT+VF decomposition accounting. Non-vacuity: 3 flip/canary gates rejected; good_eq_good_fors_M +
   dcond_good_eq are genuine (canary-negated -> rejected), used SOUNDLY, not smuggling a false equality.

**TRACK R — root round-trip: R1c (FORS pkFORS round-trip) PROVED; R1b (HT d-layer) OPEN (sphincs_c10_scheme_wip.ec,
CERTIFIED-0-ADMIT).** Proved `fors_pkFORS_from_sig_gen` (consumer) + `fors_sign_trace` (producer, discharges the
honest-coupling premise in-file so it is grounded not assumed) + R1a `pkWOTS_sigC_eq_skWOTS`. root_eq NOT closed —
R1b (the hypertree d-layer round-trip) is the sole blocker, decomposed into 4 genuine sub-lemmas (HT signer trace;
seed-based leaf bridge; foldedivz index alignment; d-layer running-root induction closing by R1a + the Wave-8
hypertree core). Multi-day, procedure-level relational, not novel. No new axiom.

IMPACT: the VF branch is proven (hop-6); the VT branch needs the concrete FORS+C game refinement (a soundness-
relevant faithfulness fix to the capstone's FORS leg, not a false theorem). Scheme correctness is components + the
open R1b assembly. The finding is exactly the kind of vacuity the honest track exists to catch.

### 2026-07-21 — Wave 10: FORS-leg finding DIAGNOSED (reassuring) — EUFCMA_MFORSC10 is MEANINGFUL; the gap is the hop-5 seam

Discriminating investigation (advisor-prescribed) + adversarial adjudication. VERDICT: verdict_sound=True,
accept_all_probe_valid=True, fix_path_sound=True. The Wave-9 finding does NOT undermine the proven pieces.

**EUFCMA_MFORSC10 IS A GENUINE MEANINGFUL BOUND (the reassuring result).** The informative test (fverify:=ACCEPT-ALL,
not false) + a negative control settle it: accept-all is a LEGAL instantiation (no MFORSC10 axiom rejects it — the
theory declares ZERO axioms on fverify/mkeygen/fsign), EUFCMA_MFORSC10 holds at accept-all, and the bound is a
GENUINE CONDITIONAL whose content is exactly (ITSRC10 assumption) + the LOAD-BEARING H-TREE-MULTI mtree premise —
dropping the mtree premise makes the bound unprovable ("cannot close goals"), proving the RHS scales via that
premise, NOT via any hidden fverify-soundness hypothesis. So the vacuity is NOT in EUFCMA_MFORSC10; the FORS bound
is real. The earlier "potentially vacuous FORS leg" caveat is corrected in both capstone files (commit 3544003).

**THE VF/HYPERTREE LEG IS CONFIRMED CONCRETE** (XmssmtCC_All.ec:257 verify is a real proc, :8439 discharged via
concrete WOTS-C + TCR reductions) — hop-6 does NOT share the asterisk. No asterisk on both proven legs.

**THE GAP IS PURELY THE hop-5 SEAM, and it is STRUCTURAL (not cheap-inherit).** LeqPr_VT_C cannot connect p_vt to
the ABSTRACT game for two independent reasons: (i) fverify unconstrained ⇒ fverify:=false zeroes Pr[RHS]
(rhs_zero_fverify_false); (ii) D2 — M.mkeygen is a PURE OP deriving the FORS cube from ps (FORS_C10_Multi.ec:129/210)
while V_C samples skFORS_ele <$ ddgstblock ps-INDEPENDENTLY (rtop_c_soundness_wip.ec:402), so no equality-supported
coupling. inherit-concrete-fverify ALONE is insufficient (kills only (i); D2 still blocks).

**THE PINNED FIX (structural, > the "1-2 sessions" the investigator estimated — adjudicator flagged over-optimistic):**
build a CONCRETE PROCEDURAL M-FORS+C game replacing all three abstract ops — (1) procedural sampling keygen a la
MM45 M_FORS_ES_NPRF.keygen (FORS_ES.ec:1933, skFORS_ele <$ ddgstblock :1829 ps-independently = the IDENTICAL draw
to V_C:402, reconciling D2 by construction); (2) concrete routed sign (FL_FORS_ES_NPRF.sign, :2055); (3) verify by
pkFORS_from_sigFORSTW reconstructed-key-equality + predC_fors (:1759). EUFCMA_MFORSC10 INSTANTIATES at it
automatically (proven with abstract ops ⇒ holds for every legal instantiation). Then port MM45's pool coupling
(SPHINCS_PLUS.ec:3143-3174 keygen/pubkey + :3307-3327 sign carry-through) to prove LeqPr_VT_C. The +C bite
(good_eq_good_fors_M / dcond_good_eq) is already proven and orthogonal. NOTE (adjudicator): reachability Pr[VT]>0 is
a meaningfulness question — mu_split makes Pr[V_C]=Pr[VT]+Pr[VF] exact regardless, and the concrete-game reduction
makes hop-5 provable either way (Pr[VT] <= FORS_term whether Pr[VT] is 0 or positive).

NET: the finding refined, not fatal. Proven pieces (EUFCMA_MFORSC10 real, VF/hop-6 concrete 0-admit) stand. Next =
build the concrete procedural FORS+C game + hop-5 over it (the pinned structural fix).

### 2026-07-21 — Wave 11: hop-5 concrete-game attempt — D2 resolved, but op-clone is a dead-end; procedural FORS+C game needed

Audited HONEST (concrete_game_legal=FALSE, eufcma_transfers=FALSE, hop5_genuine=FALSE — all correctly self-labelled;
no new axiom; no overclaim). Real but PARTIAL progress + an architectural finding.
 - GENUINE WIN (D2 make-or-break resolved): the "op mkeygen cannot sample" obstruction is NOT absolute. A clone
   controls the pseed TYPE + dpseed DISTRIBUTION, so a seed-wrapped clone Mc (drafts/RTopCVtMcWrapSeed.ec, 0-admit)
   makes the game's own `ps <$ dpseed` sample the FORS secret cube ps-INDEPENDENTLY with a distribution matching
   V_C:~402 DRAW-FOR-DRAW (dskFORS = dmap (dlist (dlist ddgstblock t) k) insubd == V_C's cube). D2 genuinely
   reconciled (keygen_couples=TRUE, auditor-confirmed not fudged).
 - BUT NOT A CONCRETE GAME + a SOUNDNESS LANDMINE: Mc binds mkeygen ONLY (pkFORS pool = `witness` placeholder;
   fsign/fverify LEFT ABSTRACT), so verify is NOT reconstructed-key-eq+predC_fors and the bound sits under the SAME
   `fverify:=false` vacuity horn (D1 UNTOUCHED — hop-5 not one step closer to provable). Worse, the seed-wrap puts
   the SECRET cube INSIDE ps (pseed := pseed * skFORS-cube), so Mc.EUFCMA_MFORSC10's forall-A conclusion is
   MEANINGLESS for a key-reading A — sound ONLY at a tape-projecting reduction (TAPE-IN-PS LANDMINE, documented).
   LeqPr_VT_C_concrete is a STATED+admit typed shell.
 - ARCHITECTURAL FINDING: the port's FORS+C multi-game FORS_C10_Multi.MFORSC10 is ABSTRACT-OP-based (mkeygen/fsign/
   fverify are ops), which structurally cannot serve as the hop-5 reduction target for the SAMPLING-based V_C game
   without either the tape-in-ps hack (unsound-unless-projected) or a PROCEDURAL re-formulation. CONVERGED SOUND
   PATH (advisor + Kimi): PROC-IFY keygen/sign/verify (mirror MM45 M_FORS_ES_NPRF + the +C conditioning) — kills D2
   AND the tape-in-ps landmine in one move, leaving the FORS correctness lemma + the byequiv. This is a real
   multi-session construction (a procedural FORS+C multi-game + re-deriving its EUF-CMA bound to ITSRC10 + hop-5).

STATE: hop-5 (VT) is BLOCKED on a procedural FORS+C game (multi-session). All proven pieces stand (hop-6/VF 0-admit;
EUFCMA_MFORSC10 meaningful; capstone statement; concrete scheme LHS; scheme-correctness fragment). The VT branch is
the deepest remaining item; the FX chain (hops 1-4) + root assembly (R1b) also remain.

### 2026-07-22 — FX-chain Wave 1: hop-1 (Orig→PRFPRF materialization) PROVEN 0-admit, audited HONEST

First hop of the FX-chain discharge program (user directive: FX chain first, then the VT rabbit hole).
`drafts/fx_chain_wip.ec` (2224 lines, CERTIFIED-0-ADMIT, committed 5fbb820 in c10-eufcma-port).

**BUILT (the shared +C FX-chain game surface, MM45 :1726-2186 ported +C-substituted):** `SPHINCS_PLUS_C10_FS.
{keygen_prf_c (skg-derived FORS cube at trhftype/set_thtbidx u*t+v + skg WOTS cube at chtype, port :1727),
keygen_nprf_c (uniform ddgstblock cubes, port :1800; differs from prf ONLY by skg→sample)}`, `O_CMA_SPHINCSPLUSTWC_FS`
(: SOracle_CMA_C with init/fresh/nr_queries; fresh `mk <$ dcond dmkey (good_fors m)` per query — the +C idealisation,
NO mkg/mmap — cube FORS-sign via FL_FORS_ES_NPRF, cube HT-sign via FL_SL_XMSS_MT_C_ES_NPRF), and the two monolithic
games `EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF` / `_NPRFPRF` with the faithful +C verify (good_fors ∧ size-d ∧ root ∧ allOkC).
SPHINCS_PLUS_C10 + EUFCMA_C10 inlined VERBATIM from sphincs_c10_scheme_wip.ec (diffed; established lowercase-inline
pattern).

**hop-1 PROVEN 0-admit:** `Eqv_EUFCMA_C10_FSPRFPRFC` + `Pr_EUFCMA_C10_FSPRFPRFC` —
  Pr[EUFCMA_C10(F) : res] = Pr[FS_PRFPRF(F) : res]
(port of MM45 Eqv_..._Orig_FSPRFPRF :2243-2571). The heavy lifting: a +C seed↔cube closed-form infrastructure
(fors_sign_seed_cf / fors_sign_cube_cf / htsign_seed_cf / nprf_sign_cf / leaves_*_cf, all phoare-1%r with concrete
mkseq/cf functional postconditions), the sign-body equiv Eqv_C10_sign_FSbody, and the game-level keygen cube-coupling
nested-whiles. Delta 1 (fresh dcond mk on BOTH sides) makes hop-1 a pure materialization fold — no mkg/RF leg exists.

**AUDIT (adversarial, PASS/HONEST):** 3 canaries REJECTED by the gate (postcondition res-flip; Pr `=`→`<`;
htsign_seed_cf size d→d+1); statements diffed verbatim vs MM45 modulo the documented +C deltas; adversary
restrictions confirmed minimal (MM45's local-module locality ↔ explicit `-` here); no new axioms. keygen_nprf_c's
(root, WOTS cube) shape verified to coincide with FL_SL_XMSS_MT_C_ES_NPRF.keygen — the hop-4 landing pad on V_C is
structurally aligned; the FS oracle sign body is line-identical to V_C.O_CMA_C.sign.

**hop-2/hop-3 setup (auditor-confirmed):** the PRF surface is CONFINED TO KEYGEN (the FS oracle never reads ss/ms —
only cubes + ps), so hop-2's SKG reduction invariant is plain cube equality over exactly two skg address families
(FORS trhftype u*t+v + WOTS chtype), and MM45's MKG hop has NO +C analog at all (delta 1 eliminated it) — hop-3 will
be an honest vacuous discharge (same game both sides, 0 ≤ mkg_adv), disclosed as a conservative over-count.

STATE: FX chain 1/4 hops machine-checked. Remaining: hop-2 (SKG scheme-level), hop-3 (vacuous, honest), hop-4
(NPRFPRF→V_C + mu_split), then capstone wiring; hop-5/VT (procedural FORS+C game) afterwards per the directive.

### 2026-07-24 — FX chain handoff (Kimi -> Claude): hop-1 + hop-2 both CERTIFIED-0-ADMIT

During a Claude usage cap, Kimi K3 took over and built the FX chain (the Orig->V game hops that discharge the
capstone's hop1-hop4 admits) in drafts/fx_chain_wip.ec. On resume, hop-1 was committed 0-admit and hop-2 was mid-
proof (compile=FAIL). Handoff continued by Claude.
 - **hop-1 (Orig->PRFPRF materialization byequiv): CERTIFIED-0-ADMIT (Kimi, git 5fbb820).** The +C analog of MM45
   Eqv_EUF_CMA_SPHINCSPLUSTW_Orig_FSPRFPRF (SPHINCS_PLUS.ec:2243-2571): the function-secret games
   (SPHINCS_PLUS_C10_FS, O_CMA_SPHINCSPLUSTWC_FS, EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF/_NPRFPRF) + Eqv_EUFCMA_C10_FSPRFPRFC
   + the Pr corollary. Shorter than MM45 because every signer is factored into closed-form support equivs
   (Eqv_C10_sign_FSbody, the +C analog of Eqv_SPHINCS_PLUS_S_sign). Audit PASS.
 - **hop-2 (scheme-level SKG-PRF, PRFPRF->NPRFPRF, INCLUDING FORS+C keys): CERTIFIED-0-ADMIT (Claude, git e5fcfe1).**
   EqPr_SKGPRF_C_false / EqPr_SKGPRF_C_true / SKGPRF_C_hop, the scheme-level port of prf_hop_wip.ec's hypertree SKG
   hop, extended to the FORS cube. The compile break was NOT the FORS-cube freshness (Kimi had closed it via
   HA.eq_adrs_idxsq + valid_tbfidx/nr_nodesf address-injectivity) but a poisoned `/\ #post` on the skFORSnt
   while-invariant (it asserted "ALL nr_trees complete" -- false mid-loop). Fixed by matching MM45's minimal-FORS-
   invariant (SPHINCS_PLUS.ec:2901-3040): drop #post, bare L1-reestablish, MM45 entry+exit boundary. Statements
   byte-verbatim, no new axiom, SKGPRF_C_hop triangle unconditional; audit PASS (false-canary rejected; 2
   freshness/index perturbations break -> injectivity load-bearing on both coordinates).
 - HONEST SCOPE (agent-stated): CERTIFIED-0-ADMIT is the SINGLE-FILE gate -- it loads the MM45 base
   (SPHINCS_PLUS.ec / XmssmtCC_All) as trusted un-re-verified .eco, so it is "0-admit ON the MM45 base," not
   "verified down to the axioms." hop-1+hop-2 are 2 of the 4 FX hops; NOT SPHINCS+C proven -- the capstone still
   rests on ITSRC10 + hops 3/4 + hop-5 (VT, the procedural-FORS-game construction) + the other admits.

REMAINING FX: hop-3 (NPRFPRF->NPRFNPRF + MKG-PRF), hop-4 (NPRFNPRF->V_C + mu_split into VT/VF), then wire hops 1-4
into the capstone (replace the hop1-hop4 admits, re-certify). VT/hop-5 remains the procedural-FORS-game construction.

### 2026-07-24 — FX hop-3 (MKG-PRF): FINDING = the in-chain hop is the IDENTITY at +C (not a paid hop)

Audit PASS (finding is SOUND + HONEST, not evasive; 3-review-converged: agent + GPT-5.6 + Kimi + advisor). Committed
as a sourced 0-admit FINDING comment block (fx_chain_wip.ec 4531211); fx_chain_wip.ec stays CERTIFIED-0-ADMIT.
 - RESOLUTION: the MM45-shaped MKG-PRF hop (NPRFPRF->NPRFNPRF, SPHINCS_PLUS.ec:3055) does NOT port to +C as a paid
   hop -- it is the IDENTITY. C10 models the message key as a fresh, non-memoized, +C-conditioned draw
   `mk <$ dcond dmkey (good_fors m)` on EVERY game of the chain (real scheme :193, the FS CMA oracle shared by
   PRFPRF and NPRFPRF :460, downstream V_C :347); `mkg` is NEVER applied in-chain (grep-verified: only in "NOT mkg"
   comments). So a faithful NPRFNPRF is DEFINITIONALLY NPRFPRF (p_nprfprf = p_nprfnprf by sim); there is no keyed
   mkg to reduce, hence no R_MKGPRF / EqPr legs / paid |MKG-PRF| triangle. Correctly declined to fabricate
   reflexivity-theatre (advisor + GPT-5.6). conditioning_sound=TRUE (good_fors threaded through ONE shared oracle
   -> structurally cannot double-count or drop).
 - The genuine MKG idealisation is REAL but lives at a SEPARATE pre-hop-1 boundary: the deployed scheme keys the
   grind on sk_seed (sphincs-c10 fors.rs nonce loop); idealising that keyed salted-grinder to the dcond model is an
   RO step needing a primitive with salt+nonce in_t and multi-query-per-signature -- which MM45's message-only
   MKG_PRF clone (in_t=msg, 1 query/msg) cannot express. A separate, larger item, not this seam.
 - H1 ACCOUNTING FIX APPLIED (git 1dc746c): both capstone files' hop3 relabelled. Since the in-chain hop is the
   identity, `mkg_adv` is a PHANTOM in-chain summand (SOUND but silently-zeroable over-estimate). The capstone bounds
   the IDEALISED-mk model; mkg_adv now correctly reads as the pre-hop-1 boundary term (deployed keyed-grind ->
   idealised model, a documented open refinement), NOT a discharged in-chain hop. Bound left structurally unchanged
   (mkg_adv >= 0 is a valid over-estimate); tightening option (hop3 := identity, drop mkg_adv) documented in-file.

FX STATUS: hop-1 (0-admit), hop-2 (0-admit), hop-3 (IDENTITY finding, no paid hop). REMAINING: hop-4 (NPRFNPRF->V_C
+ mu_split into VT/VF), then wire hops 1-4 into the capstone. VT/hop-5 = the procedural-FORS-game construction.

### 2026-07-24 — FX hop-4 (NPRFPRF->V_C + mu_split) CERTIFIED-0-ADMIT: the ENTIRE FX CHAIN is machine-checked

Audit PASS. drafts/fx_chain_wip.ec (now 3162 lines) is CERTIFIED-0-ADMIT with all four FX hops.
 - Inlined V_C (EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V) BYTE-IDENTICAL to rtop_c_soundness_wip.ec:326-456 (empty diff,
   verified twice; good_fors dep byte-identical fx:124==rtop:135; V_C references 0 other fx defs -> no silent shadow).
 - Eqv_NPRFPRF_V_C : Pr[FS_NPRFPRF(A)] = Pr[V_C(A)] by byequiv (full two-sided ==> ={res}); V_C only inlines the +C
   verify + records the spectator valid_MFORSC10 flag (absent from res). Genuine inlining (6 proven proc;sim
   structural helpers; the FORS module-var/local mismatch defeated whole-program sim -> explicit rnd-aligned nested
   whiles), NOT smt-forced. hop4_musplit : Pr[FS_NPRFPRF] = Pr[V_C:res/\valid_MFORSC10] + Pr[V_C:res/\!valid_MFORSC10]
   = p_vt + p_vf, EXACT via Pr[mu_split] (not an inequality; RHS order (valid,!valid) matches hop-5/hop-6).
 - No new axiom; false-canary + a drop-VT non-vacuity canary both rejected.
 - HONEST SEAM (to be closed by the wiring step): "fx's V_C == rtop's V_C == the game hop-5/hop-6 bind" is a
   byte-identity + identical-import-base argument, NOT a machine-checked cross-file fact (lowercase files cannot
   require each other). The wiring refactor (uppercase + require, not inline) turns this into a machine-checked link.

**FX CHAIN COMPLETE:** the whole Orig -> PRFPRF -> NPRFPRF -> V_C -> (VT + VF) reduction is machine-checked 0-admit
on the MM45 base. Combined with hop-6 (VF, LeqPr_VF_C 0-admit), the ONLY open reduction step in the Orig->leaf chain
is hop-5 (VT, the procedural-FORS-game construction). REMAINING: wire hops 1-4 (+ hop-6) into the capstone (rename
WIP files uppercase + require, discharge the hop1/hop2/hop4/hop6 admits, re-certify) -> the capstone drops from 6
admits toward {hop-5 VT + the carried ITSRC10 + the pre-hop-1 mkg boundary}. Then hop-5's procedural FORS game.

### 2026-07-24 — CAPSTONE WIRED: 6 admits -> 2 (FX chain machine-linked into the top bound)

Audit PASS (files compile, seams closed, discharges genuine, bound unchanged/tighter, no new axiom, concurrent
untouched). The FX chain is now machine-wired into the capstone.
 - RENAMES (git mv): rtop_c_soundness_wip.ec -> RtopCSoundness.ec, fx_chain_wip.ec -> FxChain.ec (uppercase =
   require-able). New wired capstone drafts/SphincsC10CapstoneWired.ec (the old 6-admit capstones kept intact).
 - SEAMS CLOSED (machine-checked, not byte-copy): FxChain now `require import RtopCSoundness` and DELETES its inline
   good_fors + 131-line V_C copies, so hop4 (FxChain) and hop6a (RtopCSoundness) name the SAME V_C module -- the
   hop-4 byte-identity seam is now a MACHINE-CHECKED require link (module identity, compile-enforced; distinct
   modules would fail the final smt, as two canaries confirmed). (7 further helper-name collisions shadow harmlessly
   -- proof-internal.)
 - HOPS DISCHARGED (admit 6->2, over REAL game probabilities, from CERTIFIED-0-ADMIT lemmas, not smt-forced):
   hop1 = Pr_EUFCMA_C10_FSPRFPRFC (EUFCMA_C10 = FS_PRFPRF, byequiv -- materialization is inside this 0-admit
   byequiv); hop2 = SKGPRF_C_hop (skg_adv GROUNDED to the concrete |Pr[SKG_PRF false]-Pr[SKG_PRF true]| -- a
   STRENGTHENING of the bound); hop4 = hop4_musplit (FS_NPRFPRF = V_C:VT + V_C:VF); hop6a = LeqPr_VF_C
   (V_C:VF <= NAGCMA(R_top_C(F), TRHC.O)). hop3 = the +C in-chain identity, machine-true via a `0 <= mkg_adv`
   premise (mkg_adv stays the nonneg phantom MKG boundary summand). hF = M.EUFCMA_MFORSC10 (proven); ITSRC10 stays
   a carried UNREDUCED probability term on the RHS (foregrounded headline hardness).
 - THE 2 REMAINING ADMITS (precise): (1) hop5 [VT] -- the procedural-FORS+C game reduction Adv_EUFCMA_C -> M + the
   ITSR-C10 coupling (A_fors a FREE forger; the multi-session construction; good_eq_good_fors sub-fact proven).
   (2) hop6b -- `Pr[NAGCMA(R_top_C(F), TRHC.O)] <= Pr[NAGCMA(R_top(F), FC.O)]`, bundling (a) the R_top_C[conditioned
   mk] -> R_top[uniform memoized mk] reduction and (b) the FC.O<->TRHC.O cross-clone oracle hop (XmssmtCC_All:5340
   has the in-proof coupling). hop6b is TRACTABLE: applying the component theorem directly at A_ht:=R_top_C(F)
   dissolves gap (a), leaving R_top_C_members4 (a near-verbatim port of the proven R_top_members4 -- choose is
   identical between R_top and R_top_C) + the oracle-clone sim (b). ~1 wave -> capstone to 1 admit (hop5) + ITSRC10.

This is the strongest honest form yet: a machine-checked SPHINCS+C10 EUF-CMA reduction whose Orig->leaf chain
(hops 1,2,4,6a + the hop-3 identity) is discharged over real games, with only the FORS-forgery branch (hop5, a
known construction) + the hop6b reduction-reconciliation + the carried ITSRC10 assumption open. Cosmetic doc-drift
to clean: FxChain.ec:2851 stale "INLINED VERBATIM" comment (superseded by the :2876 delete-note).

### 2026-07-24 — hop6b CLOSED: the wired SPHINCS+C10 EUF-CMA capstone is at 1 ADMIT (hop5/VT) + carried ITSRC10

Audit PASS, NO DEFECTS FOUND. capstone admit 2->1 confirmed on forced recompile (compile reached qed, admit-tactics=1).
 - R_top_C_members4 + R_top_C_allnchads/_allnpkcoads/_allntrhads + R_top_C_A_wf_ht: PROVEN verbatim ports
   (RtopCSoundness.ec:1681-1997). Sound because R_top_C.choose (:174-247) and R_top.choose (XmssmtCC_All:9495-9574)
   are BYTE-IDENTICAL (normalized diff = 0); the O_CMA.sign delta (conditioned dcond mk vs memoized mmap) is never
   touched by the choose audit. Non-vacuity RUN: the validated XmssmtCC_All Control A (trco mem4 site perturbation)
   FAILS on the port. CERTIFIED-0-ADMIT.
 - oracle_clone_hop_C (FC.O <-> TRHC.O): PROVEN reconciliation. FC (WOTS_TW_ES:450) and FSSLXMTWES.TRHC
   (FL_SL_XMSS_MT_ES:445) are DISTINCT Collection clones both binding op fc<-thfc, chain-verified (GPT-5.6-confirmed)
   to the SAME SPHINCS_PLUS.thfc, so O_THFC_Default.query is operationally identical. A genuine byequiv coupling the
   two DISTINCT-glob oracle states (NOT sim, NOT trivial). Non-vacuous (drop-pp fails; qeq is a witness not a
   dependency, RUN-confirmed).
 - hop6b DISCHARGED via the CLEAN closure: the +C component theorem EUFNAGCMA_FLSLXMSSMTTWCESNPRF (forall A_ht) is
   applied DIRECTLY at A_ht := R_top_C(F) -> gap (a) [R_top_C->R_top mk-distribution] DISSOLVES; only gap (b) [oracle
   clone] remained, closed by oracle_clone_hop_C. Net -3 premises: the 3 carried member hypotheses were REMOVED from
   the capstone statement and discharged in-proof (a strengthening). No new axiom; RtopCSoundness + FxChain
   re-certified 0-admit/0-axiom; false-canary rejected.
 - HONEST FRAMING (GPT-5.6, folded into the ledger): the RHS is now the R_top_C(F)-INSTANTIATED bound -- a genuine
   NEW proven upper bound on the UNCHANGED LHS Pr[EUFCMA_C10(F)], NOT claimed numerically equal to a hypothetical
   R_top(F) RHS (which was itself never proven). R_top_C samples the conditioned mk from the ideal dcond = the
   pre-existing mk modelling boundary, not a new gap.

**STATE: the wired capstone SphincsC10CapstoneWired.ec has exactly ONE admit -- hop5 (the VT / FORS-forgery leg).**
The bound: Pr[EUFCMA_C10(F)] <= skg_adv + mkg_adv + hF(FORS+C10 term = M.EUFCMA_MFORSC10 -> ITSRC10 + mtree_*) +
(component theorem at R_top_C(F) = WOTS-TW+C + S-TCR(+C) + pkco-TCR + trh-TCR). Everything EXCEPT hop5 (V_C:VT <=
the FORS term) is machine-checked over real games on the MM45 base:
  hop1 EUFCMA_C10=PRFPRF (proven) . hop2 SKG-PRF (proven, skg_adv grounded) . hop3 =NPRFNPRF (+C identity) .
  hop4 =V_C:VT+V_C:VF (proven) . hop6 V_C:VF<=hypertree (PROVEN: hop6a LeqPr_VF_C + hop6b + member ports) .
  hop5 V_C:VT<=FORS term (ADMITTED -- the procedural-FORS+C game reduction, the Wave-9/10/11 multi-session item).
So SPHINCS+C10 EUF-CMA now REDUCES, machine-checked, to {ITSRC10 (carried ~102-bit-gap hardness) + hop5 (the FORS-
forgery-branch reduction, a known procedural-game construction)}. This is the strongest honest form of the port to
date. hop5 remains the sole open reduction step; ITSRC10 the sole carried cryptographic hardness assumption.

### 2026-07-24 — hop5 Wave 12: the SOUND procedural FORS+C game Gproc is BUILT + its EUF-CMA bound to ITSRC10 is CERTIFIED-0-ADMIT

The pinned fix from Waves 9-11 (a CONCRETE PROCEDURAL FORS+C multi-game replacing the abstract MFORSC10 that D1/D2
make an unsound hop5 target) is now built and machine-checked for its first two steps. New file
`drafts/GprocFORSC10.ec` (CERTIFIED: compile=OK, admit-tactics=1 [hop5 only], axiom-decls=0; false-canary REJECTED).

**STEP 1 — Gproc BUILT + typechecks (closes D1 + D2 by construction).** `GprocKg.keygen` is a PROC that SAMPLES the
nested FORS cube `skFORS_ele <$ ddgstblock` ps-INDEPENDENTLY, byte-mirroring `V_C.main` (RtopCSoundness :394-410) —
reconciles D2 by construction — then precomputes the pkFORS pool via `gen_pkFORS`. `O_CMA_Gproc.sign` draws the fresh
CONDITIONED `mk <$ dcond dmkey (good_fors m)` NON-memoized, edivz-routed `FL_FORS_ES_NPRF.sign` (byte-identical to
`V_C.O_CMA_C.sign` minus the HT-sign). `EUF_CMA_Gproc`'s verify is CONCRETE: `predC_fors (mco mk' m') /\
pkFORS_from_sigFORSTW = pool entry` — the EXACT `V_C.valid_MFORSC10` gate, NOT a zeroable abstract op (closes D1;
contrast `rhs_zero_fverify_false`).

**STEP 2 — the bridge is REJECTED; the EUF-CMA bound is RE-DERIVED, CERTIFIED-0-ADMIT.** The bridge (prove
`Pr[Gproc EUF] = Pr[MFORSC10 EUF at concrete ops]` then instantiate the abstract `EUFCMA_MFORSC10`) is self-defeating:
the abstract keygen `(pks,sks) <- mkeygen ps ad` is a DETERMINISTIC op of `ps`, Gproc SAMPLES the cube; no concrete op
reproduces a sampling distribution under the honest `dpseed` (the only escape — cube-in-ps — is the tape-in-ps landmine
Gproc kills). So we RE-DERIVE the three FORS_C10_Multi lemmas over Gproc: `eufcma_gproc_I_eq` (instrumented ghost-`ts`
game, res-preserving), `R_ITSRC10_Gproc` (multi->single reduction, procedural nested cube), `ITSRC10_hop_Gproc`
(covered-part <= `Pr[M.F.ITSRC10(R_ITSRC10_Gproc)]`), and `EUFCMA_Gproc`: `Pr[Gproc EUF] <= Pr[M.F.ITSRC10(...)] +
mtree_*` — the SAME carried ITSRC10 assumption + mtree premise, now over the SOUND concrete game. Each byequiv is the
FORS_C10_Multi proof + a `sim`/`call` keygen prefix (`keygen_eq`, `forsnprf_sign_eq`, `pkfromsig_eq`) — the concrete
procs replace the abstract op-folds.

**STEP 3 — hop5 STATED over the concrete Gproc; the coupling is the honest residual (NO 4th obstruction).**
`R_fors_p` (the VT reduction, nested-routing analogue of `rtop_c_vt_wip.R_fors` retyped to Gproc's concrete oracle) is
constructible; `LeqPr_VT_C_proc : Pr[V_C : res /\ valid_MFORSC10] <= Pr[EUF_CMA_Gproc(R_fors_p(F))]` is stated in its
exact required form and ADMITTED with a PRECISE in-file residual. This admit is a TRANSCRIPTION residual (the MM45
:3129-3467 VT-coupling ported to +C: keygen/pool coupling + HT keygen via `keygenC_eq` + oracle coupling via
`trcoINV`/`genpkfors_flatten` + forge extraction via `good_eq_good_fors_M`/`dcond_good_eq`), NOT a modelling seam — all
three diagnosed obstructions (D1/D2/tape-in-ps) are RESOLVED by Gproc. The keygen/pool-derivation sub-lemma
(`GprocKg_pool_inv`: the pool = `gen_pkFORS` closed form = `cfPk`, simpler than R_top_C's inlined tree-hash because
Gproc CALLS `gen_pkFORS`) was constructed and compiled in isolation, but its list-bookkeeping closers are
SMT-nondeterministic (identical code passed then failed across runs), so it is kept OUT of the certified file pending a
deterministic hardening — a reproducibility issue, not a soundness one.

NET: the 3-wave diagnosis's CORE blocker is resolved — the SOUND procedural reduction target now EXISTS and its
EUF-CMA bound to ITSRC10 is machine-checked 0-admit. hop5 is now a PURELY-TRANSCRIPTION coupling (advisor + this
session concur: grind, not a wall). The capstone's hop5 admit is UNCHANGED (still against the abstract M); Step 4
(rewire the capstone FORS leg from abstract-M to concrete-Gproc) awaits the hop5 coupling. No new axiom; `good_pos`
carried as before; ITSRC10 stays the sole carried hardness.

### 2026-07-24 — hop5 STEPS 1+2 DONE: procedural FORS+C game Gproc + its ITSRC10 bound (0-admit); the 3 obstructions DISSOLVED

Audit PASS on the structural work (build agent committed 4 commits then died to an API stall; audit ran on the
committed state). drafts/GprocFORSC10.ec (672 lines, 1 admit = only LeqPr_VT_C_proc, 0 axioms).
 - STEP 1 -- Gproc GENUINELY PROCEDURAL + CONCRETE (the pinned fix, now built): GprocKg.keygen (:186) is a PROC that
   samples the FORS cube skFORS_ele <$ ddgstblock ps-INDEPENDENTLY in nested whiles, BYTE-IDENTICAL to V_C
   (RtopCSoundness:394-410) -> D2 (keygen mismatch) DISSOLVED by construction. EUF_CMA_Gproc (:280) verify is a
   HARDCODED concrete conjunction: reconstructed-pkFORS-eq (pkFORS_from_sigFORSTW = pool entry) AND predC_fors ->
   D1 DISSOLVED: fverify:=false is NOT a legal instantiation (the Wave-9 vacuity horn is genuinely closed; non-
   trivially satisfiable). No tape-in-ps. So all 3 diagnosed obstructions (D1/D2/tape-in-ps) are resolved; NO new
   (4th) obstruction appeared.
 - STEP 2 -- EUF-CMA(Gproc) <= ITSRC10: the BRIDGE to MFORSC10-at-concrete-ops was correctly REJECTED (op-keygen
   deterministic-in-ps cannot couple to Gproc's proc-sampling), so RE-DERIVED over Gproc: eufcma_gproc_I_eq (:444)
   + ITSRC10_hop_Gproc (:514) + EUFCMA_Gproc (:549), all CERTIFIED-0-ADMIT. Adversarial canary (flip covered->!covered
   in ITSRC10_hop_Gproc) FAILS -> the coverage coupling is load-bearing, not smt-forced. RHS = the carried M.F.ITSRC10
   assumption + the carried false-at-zero mtree premise. No new axiom.
 - STEP 3 -- LeqPr_VT_C_proc (:635, Pr[V_C:VT] <= Pr[Gproc EUF via R_fors_p]) is STATED + ADMITTED. Its residual is
   a PRECISE TRANSCRIPTION (the MM45 VT-coupling :3129-3467 to +C), 4 legs all reusing PROVEN assets: (i) keygen+pool
   coupling (cube byte-identical sim/while; pool one-sided establishing trcoINV via genpkfors_cf -- SIMPLER than
   R_top_C's inlined tree-hash); (ii) HT keygen via keygenC_eq (proven); (iii) oracle coupling (gen_pkFORS on-the-fly
   = pool entry via trcoINV + genpkfors_flatten, proven); (iv) forge/event map (good_fors = predC_fors via
   good_eq_good_fors_M; valid_MFORSC10 => pool-eq via trcoINV; freshness coincides; mk-rnd via dcond_good_eq). It is a
   TRANSCRIPTION residual, NOT a modelling seam (contrast the abstract-M rtop_c_vt_wip.LeqPr_VT_C which is
   unprovable-or-vacuous). STEP 4 (capstone discharge) not done; wired capstone still at 1 admit.

hop5 DE-RISKED from a multi-session rabbit hole to a BOUNDED transcription: the sound FORS+C EUF game exists,
ITSRC10-bounded 0-admit; only the VT-coupling byequiv remains (reuses proven assets, no new obstruction). NEXT:
mechanize LeqPr_VT_C_proc + discharge the capstone hop5 -> capstone to 0 admit (modulo carried ITSRC10 + trusted base).

### 2026-07-24 — hop5 CLOSED: the wired SPHINCS+C10 EUF-CMA capstone is CERTIFIED-0-ADMIT (reduces to ITSRC10 + the MM45 base)

Audit PASS + INDEPENDENTLY re-verified (I re-ran ec-certify on forced recompile of both files). This is the
culmination of the port.
 - LeqPr_VT_C_proc (GprocFORSC10.ec:693-948) MECHANIZED CERTIFIED-0-ADMIT: the VT coupling byequiv
   V_C(F) ~ EUF_CMA_Gproc(R_fors_p(F)) : (res /\ valid_MFORSC10){1} => res{2}. PURE transcription (no hidden
   invariant mismatch, no finding, nothing smt-forced): (i) keygen cube byte-identical nested-while + pool one-sided
   while{2} building the trcoINV invariant via call{2} genpkfors_cf; (ii) HT keygen keygenC_eq2; (iii) oracle couple
   (forsnprf_sign_eq + htsign_eq + genpkfors_cf, R delegates FORS-sign to O.sign); (iv) event map (good_fors =
   predC_fors via good_eq_good_fors_M; valid_MFORSC10 => pool-eq via genpkfors_cf; +C mk-rnd via dcond_good_eq).
   FOUR non-vacuity canaries all REJECTED (auditor RAN them): the VT-EVENT FLIP (negate valid_MFORSC10 -> cannot
   prove goal, so NOT vacuous -- the Wave-9 failure mode does not recur), the predC_fors ACCEPT-ALL probe (cannot
   prove -> the +C forced-zero gate is genuinely non-degenerate, CLOSING the Wave-9/10 accept-all vacuity mode for
   the CONCRETE Gproc M clone), trailing-false, and capstone hF-removal (hop5 load-bearing).
 - CAPSTONE DISCHARGED 1 -> 0 (SphincsC10CapstoneWired.ec, CERTIFIED-0-ADMIT, independently re-verified). Rewired
   the FORS leg from the abstract M.EUFCMA_MFORSC10 onto the CONCRETE Gproc: FORS leg =
   Pr[V_C:VT] <=(LeqPr_VT_C_proc) Pr[Gproc EUF] <=(EUFCMA_Gproc) ITSRC10 + mtree_*. The free A_fors forger was
   REMOVED (F-derived via R_fors_p(F)); the local abstract clone M deleted. **The abstract-M vacuity caveat is
   ELIMINATED** -- GprocFORSC10.M clones FORS_C10_Multi.MFORSC10 with concrete FTWES types and REALIZES all 8
   structural/distribution axioms (g-axioms + good_pos etc.), so the transitive axiom closure SHRANK (no new axiom;
   fewer). The mtree premise was RESTATED over the concrete F-derived Gproc game (a strengthening: scoped to
   R_fors_p(F), the actual adversary, not all A_fors).

**THE RESULT (precise + honest): the entire +C-specific EUF-CMA reduction for SPHINCS+C10 is now MACHINE-CHECKED
with ZERO admits.** SphincsC10CapstoneWired.ec proves
  Pr[EUFCMA_C10(F)] <= (SKG-PRF advantage) + (nonneg mkg phantom) + (ITSRC10 + mtree_* via the concrete Gproc FORS
                        game) + (WOTS-TW+C + S-TCR(+C) + pkco-TCR + trh-TCR via the component theorem at R_top_C)
with all six FX hops + the FORS + hypertree legs discharged by applying single-sourced 0-admit lemmas. The chain:
hop1 materialization (proven) . hop2 SKG-PRF (proven, skg grounded) . hop3 +C identity . hop4 mu_split (proven) .
hop5 VT->concrete-Gproc->ITSRC10 (PROVEN, this entry) . hop6 VF->hypertree (proven). CONDITIONALITY (the honest
ledger, all foregrounded in the capstone header): (1) the carried ITSR(+C)/C10 hardness assumption -- the ~102-bit
FORS+C interleaved-target-subset-resilience, UNREDUCED on the RHS (the paper carries it too); (2) the three
false-at-zero mtree_* FORS-Merkle premises; (3) the TRUSTED MM45 base .eco (XmssmtCC_All / FxChain / RtopCSoundness
+ FV-SPHINCSPLUS-EC and their SPHINCS+ base axioms) loaded require-only, NOT re-verified in this compile (the
single-file gate) -- each base file is itself independently CERTIFIED-0-ADMIT, so a full-chain from-scratch
recompile would upgrade "trusted" to "verified" (the definitive next verification).

This realizes the feasibility thesis exactly: NOT a from-scratch proof of SPHINCS+C10, but a machine-checked
REDUCTION of C10 EUF-CMA to {the MM45 standard-SPHINCS+ base + the +C hardness assumption (ITSRC10 / S-TCR(+C))} --
the +C DELTA is fully mechanized, 0-admit, with the abstract-game vacuity risks all closed by construction. "Months
not years" is now empirically settled: the port is machine-checked end-to-end modulo the named carried assumptions.

### 2026-07-25 — FULL-CHAIN VERIFIED: trusted base -> VERIFIED base, and the definitive TCB

The known trap of this project is that EasyCrypt `require` does NOT re-verify (a required theory full of `admit`
loads with EXIT 0), so every prior CERTIFIED-0-ADMIT was "0-admit ON a trusted base". That is now CLOSED.

**THE GATE (run: scratchpad/fullchain.sh, ~35 min wall).** Computed the capstone's transitive require closure over
PROJECT files = **24 files** (10 MM45 base + 14 ours, ~2.4 MB), **DELETED all 22 existing .eco**, then compiled
**every file AS A TARGET** in topological order, then admit-swept and axiom-censused the WHOLE chain.
  RESULT: **24/24 compiled from source, 0 compile failures, 0 ADMIT TACTICS CHAIN-WIDE.**
  (Timings incl. FORS_ES 336s, FL_SL_XMSS_MT_ES 441s, SPHINCS_PLUS 144s, XmssmtCC_All 864s, FxChain 81s.)
So the whole reduction -- MM45 base + the +C stack + the capstone -- is machine-checked from source, admit-free.

**THE DEFINITIVE TCB (the axiom census, refined).** The raw sweep found 18 textual `axiom` declarations, but a
textual sweep is BOTH over- and under-inclusive. Refined by checking every `realize` site:
 - **REALIZED (13) -- these are PROVED, not assumptions:** ours -- dmkey_ll, size_g, eqiks_g, neqisvs_g, rng_g,
   uniq_g (all realized at the capstone clone, GprocFORSC10.ec:139-146), dpp_ll (WOTS_C_Real.ec:199),
   in_collection (STCR_C.ec:101); MM45's -- dist_adrstypes (x3), valid_fidxvals_idxvals, valid_widxvals_idxvals,
   valid_xidxvals_idxvals (realized at their instantiation sites in SPHINCS_PLUS.ec / FL_SL_XMSS_MT_ES.ec).
 - **CARRIED (5) = THE TRUE AXIOM-TCB:**
     MM45 base (3, inherited from the third-party standard-SPHINCS+ proof):
       * `ch0`, `chS` (WOTS_TW_ES) -- the defining equations of the WOTS chaining function (definitional).
       * `two_encodings` (WOTS_TW_ES:572) -- the standard-encoding property.
     Our port (2, both modelling facts, both previously disclosed):
       * `good_pos` (FORS_C10.ec:208) -- p_nu positive good-counter mass; genuinely undischargeable from abstract
         mco/dmkey (a legal model can zero the good-mass), hence correctly an axiom.
       * `CntrFT.enum_spec` (Grind.ec:62, clone-inherited from FinType) -- the +C counter type is FINITE (true of
         the deployed 32-bit counter). **This one is INVISIBLE to a textual axiom sweep** -- it is a clone-inherited
         obligation with no `axiom` keyword. Recorded so no future census misses it.
 - **SOUNDNESS CHECK ON `two_encodings` (verified, not assumed -- it matters):** the constant-sum +C map is known to
   BREAK two_encodings, so if our chain had instantiated MM45's WOTS_TW_ES at the +C encoding, that axiom would be
   FALSE in the intended model and the whole chain unsound. VERIFIED IT DOES NOT: the +C encoding is a SEPARATE op
   `encode_msgWOTS_C : pseed -> adrs -> msgWOTS -> cntr -> emsgWOTS` (WOTS_C_Real.ec:220, different arity);
   `encode_msgWOTS` is NEVER substituted (`<-`) anywhere in drafts/; and WOTS_TW_ES is never cloned with a replaced
   encoding. So two_encodings constrains only MM45's own standard encoding -- exactly the intended black-box use of
   the WOTS-TW term (paper Thm 5.2 shape: WOTS+C <= S-TCR(+C) + WOTS-TW-at-the-standard-encoding).

**METHODOLOGICAL LESSON (for the gate discipline).** `ec-certify.sh` counts textual `axiom` declarations in ONE
file. That is not the TCB: it OVERCOUNTS axioms realized at clone sites (13 of our 18) and UNDERCOUNTS
clone-inherited obligations that carry no `axiom` keyword (CntrFT.enum_spec). The sound TCB procedure is the one
run here: full-closure compile-as-target + admit sweep + axiom census + a per-axiom `realize`-site check.

**THE CLAIM WE ARE NOW ENTITLED TO MAKE** (unchanged in kind, strictly stronger in evidence):
  SPHINCS+C10 EUF-CMA is reduced, by a machine-checked admit-free EasyCrypt proof compiled from source end-to-end,
  to: {the carried ITSR(+C)/C10 hardness assumption (unreduced, the ~102-bit-gap headline) + the mtree_* FORS-Merkle
  premises + the S-TCR(+C)/WOTS/TCR/PRF advantage terms + 5 carried axioms (3 MM45 base + good_pos + counter
  finiteness)}. It is NOT a from-scratch unconditional proof of SPHINCS+C10, and the modelled scheme sits at the
  idealised-mk level (the deployed firmware keys the grind on sk_seed -- the disclosed pre-hop-1 boundary).

### 2026-07-25 — ⚠ RETRACTION: THE CAPSTONE AS STATED IS **VACUOUS** (contradictory premises). What survives, precisely.

**THIS SUPERSEDES THE "CLAIM WE ARE NOW ENTITLED TO MAKE" IN THE PRECEDING ENTRY. That sentence is WITHDRAWN.**
An adversarial statement-level audit found, and I independently re-derived and machine-verified, that two premises of
`EUFCMA_SPHINCS_PLUS_C10` are JOINTLY CONTRADICTORY. A theorem with an unsatisfiable hypothesis set is vacuously
true and establishes NOTHING about its conclusion.

**THE DEFECT (verify it yourself in four lines).** The two premises (SphincsC10CapstoneWired.ec:447-449, textually
identical to the component theorem's at XmssmtCC_All.ec:8451-8453):
  hembdisj : forall a b, valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)
  hembinj  : forall a b, get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b) => get_wgpidxs a = get_wgpidxs b
`emb_tw ad = insubd (put (put (put (val ad) 0 0) 1 0) 3 pkcotype)` (WOTS_C_Real.ec:80) writes only val-indices 0,1
-- which `get_wgpidxs = drop 2 (val ad)` (WOTS_TW_ES.ec:389) DISCARDS -- and index 3, to the CONSTANT pkcotype.
So emb_tw is IDEMPOTENT on the get_wgpidxs projection. Instantiating hembinj at (a, emb_tw a) therefore yields
`get_wgpidxs a = get_wgpidxs (emb_tw a)`, which hembdisj forbids for any valid_wadrs a -- and such an a exists by
the PROVEN `nonvac_guard` (WOTS_C_Real.ec:140). Contradiction.
MACHINE EVIDENCE (re-verified by me): `scratch/synth_exact_prefix_vacuity.ec` -- compiled under the capstone's
VERBATIM import prefix so every symbol resolves identically -- proves `CAPSTONE_PREMISES_CONTRADICTORY : hembdisj =>
hembinj => false`, CERTIFIED-0-ADMIT; its negative control `scratch/synth_negctl.ec` correctly FAILS.

**A FALSE DISCLOSURE MADE THIS SURVIVE.** SphincsC10CapstoneWired.ec:190-194 affirmatively states these premises are
"base-provable via emb_disj_wgpidxs_holds, WOTS_C_Bridge.ec:200". That lemma proves ONLY the disjointness half (its
body is `exact: emb_disj_concrete`); NO injectivity counterpart (`emb_gp_inj_holds`) exists anywhere in drafts/.
Claiming base-provability for a REFUTABLE premise is worse than leaving it undisclosed, and it is why this survived
multiple audits.

**EXACT BLAST RADIUS -- what is and is NOT affected (do not over- or under-state):**
 - NOT AFFECTED: the 2026-07-25 FULL-CHAIN VERIFICATION (24/24 compiled from source, 0 admits chain-wide, the TCB
   census). That result is about compilation and admit-freeness, which are orthogonal to premise satisfiability --
   and this defect is precisely the class such a gate CANNOT see.
 - NOT AFFECTED: the individual hop lemmas. hop1 (Orig->PRFPRF), hop2 (SKG-PRF), hop4 (mu_split), hop5
   (LeqPr_VT_C_proc + EUFCMA_Gproc), hop6a (LeqPr_VF_C) are proven WITHOUT these premises -- demonstrated by the
   salvage below, which chains them unconditionally.
 - AFFECTED: (a) the capstone's top-level statement, and (b) the XMSS-MT+C COMPONENT THEOREM
   (EUFNAGCMA_FLSLXMSSMTTWCESNPRF, XmssmtCC_All.ec:8439) itself, since it carries the same premise pair -- so the
   EXPANSION of the hypertree term into {WOTS-TW+C multi + S-TCR(+C) + pkco-TCR + trh-TCR} is vacuous. The route TO
   the hypertree game is fine; only its leaf expansion is lost.

**WHAT ACTUALLY SURVIVES -- an UNCONDITIONAL, admit-free bound (re-verified CERTIFIED-0-ADMIT by me):**
`scratch/synth_recoverable_unconditional.ec`, lemma RECOVERABLE_UNCONDITIONAL, with **NO premises and NO free
reals** (strictly more honest than the retracted statement, which had four free reals):
    Pr[EUFCMA_C10(F) : res]  <=  |SKG-PRF adv of R_SKGPRF_EUFCMA_C(F)|
                               + Pr[ITSRC10(R_ITSRC10_Gproc(R_fors_p F))]
                               + Pr[EUF_CMA_Gproc_I(R_fors_p F) : res /\ !covered]
                               + Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(R_top_C F, FC.O_THFC_Default) : res]
Every adversary on the RHS is F-DERIVED; every term is a real game probability. This IS a genuine theorem about the
modelled scheme. Its remaining honest caveats: the hypertree term is UNEXPANDED (see blast radius); `predC`
(WOTS_C_Real.ec:180) is an unconstrained op, so a legal instantiation `predC := fun _ => false` makes verify always
reject and zeroes the LHS -- LHS non-vacuity is NOT established (this is MM45's abstract-primitive methodology, but
it is owed a disclosure); the model is the paper's idealised-mk, VIRTUAL k-full-tree FORS+C, whereas the deployed
crate drops the last FORS auth path (sphincs-c10/src/params.rs:66-73) -- the virtual->wire bridge is cited paper
prose (2022/778 §4.1.1), unmechanized, and was missing from every ledger.

**THE REPAIR (real, but not one line).** The guarded fact IS a theorem (`scratch/refuter_repair.ec`,
`hembinj_repaired : valid_wadrs a => valid_wadrs b => ...` compiles), so the mathematics is sound and the premise is
repairable by adding validity guards. But the premise is eliminated inside `emb_dist` (WOTS_C_Interactive.ec:703-720)
over an ARBITRARY `adrs list` under only `uniq_wgpidxs`, whose live consumer is `interactive_success_transfer_MA`
(:2194-2219) -- so the guards must be threaded through those, not merely added at the capstone.

**LESSON (the important one).** Compile-cleanliness, admit-freeness, and a full-chain from-source rebuild are all
necessary and NONE of them detects an unsatisfiable premise set. A 0-admit theorem can say nothing at all. Premise
JOINT-SATISFIABILITY must be a standing gate item, with a witness obligation: for every carried premise set, either
exhibit a model satisfying all of them simultaneously, or state that non-vacuity is unestablished.

### 2026-07-25 — VACUITY REPAIRED: the contradictory premise is ELIMINATED (not guarded); capstone premise-free on the emb_tw axis

Follow-up to the retraction above. The repair took the STRONGER of the two routes: the refutable premise is **deleted
outright**, not replaced by a guarded version that would owe its own satisfiability argument.

**WHY ELIMINATION WORKS (design, adversarially reviewed by GPT-5.6 + Kimi K3, then source-verified):**
 - `get_wgpidxs (emb_tw a) = put (get_wgpidxs a) 1 pkcotype` (`wgp_embv`), and `nth3_valid` (WOTS_C_Real.ec:132)
   gives every VALID WOTS address `chtype` at that very position. So writing a CONSTANT there cannot merge two
   distinct group prefixes: for valid a,b the injectivity conclusion follows with NO injectivity premise. Proven as
   `emb_dist_valid (l) : all valid_wadrs l => uniq_wgpidxs l => uniq (map emb_tw l)` (CERTIFIED-0-ADMIT).
   Its negative control (same script, guard removed) correctly FAILS -- the guard is load-bearing, not decoration.
 - THE INVARIANT IS TRUE BY **INTERFACE TYPING**, not a runtime check: the signing oracle's type is
   `proc query(wad : wadrs, m)` (WOTS_C_Scheme.ec:132) with `wadrs = WAddress.sT`, a Subtype at `P <- valid_wadrs`
   (WOTS_TW_ES.ec:867). The adversary CANNOT EXPRESS an invalid address on that interface; `WAddress.valP` gives
   validity by construction. `O_STCRC_Default.ts` has exactly two writers, both internal (STCR_C.ec:124/134), and
   the reduction's only `O.query` call goes through that typed wrapper (WOTS_C_Interactive.ec:559-570).
   Machine evidence: `R_ts_allvalid` is a proven hoare invariant, not a premise.
 - CORRECTLY **NOT** CLAIMED: `all valid_wadrs tws_ma` is FALSE (the collection oracle `O_THFC_MA.query` takes a RAW
   adrs, so the adversary CAN inject there) -- and the member-aware design never needs it (`member_sep_disj` needs
   only `p.1 <> dfC`). LATENT TRAP RECORDED: `R_STCRC_WOTSC.pick` (WOTS_C_Reduction.ec:77) calls `O.query(witness,..)`
   with an arbitrary address -- the all-valid invariant must NEVER be stated for that instance.

**RESULT (I independently verified the premise binder myself):** the capstone `EUFCMA_SPHINCS_PLUS_C10` now carries
NEITHER half -- `hembinj` deleted chain-wide, `hembdisj` DISCHARGED in-proof by the already-proven `emb_disj_concrete`.
Its full premise list is now exactly: `c <= p_tgts`, `0 <= mkg_adv`, encode-compat, four `dfC <> ...` width facts,
and the H-TREE-MULTI Pr bound. Four files re-certified 0-admit/0-axiom (WOTS_C_Interactive, XMSSMT_C_Reduction,
XmssmtCC_All, SphincsC10CapstoneWired). The conclusion is UNWEAKENED (RHS unchanged); no new axiom; the repair is a
net STRENGTHENING (11 component-theorem premises -> 10, and the capstone loses both).

**THE SATISFIABILITY GATE (the new standing requirement) -- PASSED WITH A MODEL, not with "no contradiction found".**
`scratch/audit_model_receipt.ec` (CERTIFIED-0-ADMIT, capstone-verbatim prefix) exhibits an actual satisfying
interpretation: `emb_in := fun x => val x.1 ++ [false]` (well-typed, image size 8n+1), `p_tgts := max 0 c`,
`encode_msgWOTS_C := encode_msgWOTS o ThC`, `mkg_adv := 0`, `(mtree_*) := (1,0,0)`. The elegant part:
**8n+1 is ODD while all four forbidden widths (8n, 8n*len, 8n*2, 8n*k) are EVEN**, so the four `dfC <> ...` premises
hold simultaneously for every admissible n,k,len. The old attack re-run against the repaired premises is REJECTED;
the control with the deleted premise restored is GREEN.

**⚠ NEW METHODOLOGICAL TRAP FOUND (same class as the `require` trap, worth as much as the repair).** EasyCrypt does
NOT invalidate a DEPENDENT's `.eco` when a required `.ec` changes. After XmssmtCC_All.ec was rebuilt, the downstream
files kept their OLD `.eco` and the capstone "compiled" in 3.6 SECONDS against a STALE environment -- a green that
means nothing. `scratch/vacuity_repair_gate.sh` therefore recompiles the ENTIRE chain as EXPLICIT TARGETS and checks
.eco mtimes actually moved. **Any future edit to a mid-chain file MUST be gated this way, not by a single-file
certify.** (My own third-party re-run of that gate was in flight at time of writing.)

**HONEST RESIDUAL VACUITY VECTORS (this repair fixed ONE of them; these remain, and the theorem is not yet
"meaningful" in the strongest sense):**
 - **V1 `predC` is completely unconstrained** (WOTS_C_Real.ec:180; no axiom in the closure mentions it). Under the
   admissible interpretation `predC := fun _ => false` the capstone's LHS is IDENTICALLY ZERO -- the bound is true
   but content-free. This is the biggest live vector.
 - **V2 `emb_in` is unconstrained** and the capstone carries neither `emb_in_len` nor `emb_in_inj`, so a CONSTANT
   `emb_in` is admissible, under which the S-TCR(+C) RHS term is ~1 and the bound is content-free from the other
   side. **NOTE HONESTLY: the satisfying model exhibited above is itself of this degenerate family** -- so what is
   established is "the premise set is SATISFIABLE", NOT "satisfiable by a model in which the theorem has content".
   Those are different claims and only the first is proven.
 - V3 `p_tgts` is abstract with only `0 <= p_tgts`, so `c <= p_tgts` is a genuine side condition (refuted by
   `p_tgts := 0`). V4 inherited axioms (CntrFT.enum_spec, good_pos, MM45 base). V5 FLAGGED-NOT-INVESTIGATED: whether
   `EUF_CMA_Gproc_I.covered` can be identically true (would hollow the FORS leg's content, not the capstone's truth).
 - Minor defects the audit raised: a stale claim-vs-code comment in the new non-vacuity justification
   (WOTS_C_Interactive.ec:2195-2199) and two committed canaries weaker than their billing (bare `smt` with few
   lemmas). Both cosmetic/hygiene, neither affects the result.

**NET.** The specific defect that made the capstone vacuous is genuinely and structurally fixed, by deletion rather
than patching, with a machine-checked satisfying model and an unweakened conclusion. What is NOT yet established is
that the abstract primitives (`predC`, `emb_in`) admit only interpretations under which the statement has content --
that is the next honest frontier, and it is MM45's own abstract-primitive methodology, not a defect introduced here.

**POST-REPAIR FULL-CHAIN RE-VERIFICATION (independent, run by me — CONFIRMED).** After the repair edits to four
mid-chain files, I re-ran the full-closure gate from scratch (delete every closure .eco; compile all 24 files as
explicit targets; admit sweep; axiom census):
  **24/24 compiled from source, 0 compile failures, 0 ADMIT TACTICS CHAIN-WIDE, 18 axiom declarations —
  the census is UNCHANGED from pre-repair, confirming the repair introduced no new axiom.**
Provenance note (honest): two instances of the runner ended up executing concurrently (an earlier nohup'd run
survived a harness stop and overlapped my relaunch), so the report contains two interleaved verdict blocks. This
does NOT weaken the result — the timings prove both did REAL work rather than cache-hitting: XmssmtCC_All 840s/841s,
FL_SL_XMSS_MT_ES 425s/429s, FORS_ES 313s/320s, SPHINCS_PLUS 141s/142s, WOTS_TW_ES 119s/120s, FxChain 80s/82s. Every
file has at least one genuine from-source compile, including all four REPAIRED files. So the repair holds up under
the strongest gate available — one that is structurally immune to BOTH known traps (it deletes every .eco, so
neither `require`-does-not-re-verify nor stale-dependent-.eco can produce a false green).

## UPDATE 2026-07-25b — TRACK V: the capstone made PROVABLY CONTENTFUL (V1/V2 attacked), and a NEW faithfulness finding that outranks both

The previous update closed the *satisfiability* gap and honestly left two **content** vectors open (V1 unconstrained
`predC`, V2 unconstrained `emb_in`). This wave attacked them. Deliverable: **`drafts/SphincsC10Content.ec`,
CERTIFIED-0-ADMIT, 0 axiom declarations**, plus `scratch/trackV_gate.sh` (**TRACK-V GATE PASS**: 6 canaries all
REJECTED, positive control GREEN, 1 disclosed non-canary). The **whole-chain gate was re-run and PASSES**; note that
**no mid-chain file was edited** — the new file is a leaf that `require`s the capstone, so the T2 stale-`.eco` hazard
does not arise for the chain.

**RUNG REACHED: (b), and only in a qualified form.** Not (c). Full (c) — "define `predC`/`emb_in` at their C10
meanings and discharge non-degeneracy as THEOREMS" — is **not derivable from this closure**: non-degeneracy bottoms
out in the unconstrained image of `encode_msgWOTS`, a free target constant, and `thfc`. Defining `predC` in place
would **relocate** the dependency, not remove it (and would put bigop arithmetic under every `smt()` in 24 files);
that is why the in-place edit was deliberately **not** made.

**What landed, all 0-admit.**
- **The mathematical heart of WOTS+C, PROVED** (`constsum_antichain`, `constsum_encoding_is_two_encodings`): a
  **constant-sum digit encoding satisfies MM45's `two_encodings` antichain condition WITHOUT a checksum**. This is
  exactly what the +C gate buys, and here it is a theorem quantified over an *arbitrary* encoding.
- **The V1 mechanism refuted at its own procedure** (`gate_passes_on_ground_counter`): the same
  `pkWOTS_from_sigWOTS_C` at which the V1 audit proved the gate *always rejects* is proved to *accept* on the
  honestly-ground counter.
- **`EUFCMA_SPHINCS_PLUS_C10_CONTENTFUL`**: the capstone bound **re-derived verbatim by `exact`-applying the
  unchanged capstone** (so the RHS provably did not drift and nothing is weakened), conjoined with 6 content
  conclusions. The capstone itself is left **byte-identical**.
- **PART G — the joint model on the ACTUAL globals.** Pins `emb_in`, `predC`, `encode_msgWOTS_C`, and `thfc`
  *at the single index `dfC`* by definitional equations, and proves all four added premises **plus the capstone's own
  bridge premise** hold at those globals, non-degenerately. **The insight that makes this coherent:** `f = thfc(8n)`,
  `trh = thfc(8n·2)`, `pkco = thfc(8n·len)`, `trco = thfc(8n·k)` are the *same* `thfc` (SPHINCS_PLUS.ec:440-449), so
  pinning `thfc` everywhere would collapse the whole scheme — pinning it at `dfC` alone is sound **precisely because
  the capstone's four `dfC <> …` separation premises make `dfC` distinct from all four**. That is what those premises
  are for; `f`/`trh`/`pkco`/`trco` stay completely free.

**Non-degeneracy — ACHIEVED vs PROVABLY NOT ACHIEVABLE (the honest core).**
- ACHIEVED: `predC` **not identically false**; `emb_in` **not constant** (injective, constant-width, faithful
  `M‖counter`); `ThC` **not constant**; the exact hypothesis under which the LHS was proven identically zero is
  **refuted**.
- **NOT achievable by any model-theoretic premise**, and now understood as to *why*: "the S-TCR(+C) RHS term is not
  ≈1". **Pigeonhole:** `msgWOTS` *is* `dgstblock`, and premise N2 makes `m ↦ ThC ps tw m (grindC ps tw m)` map the
  whole message space into the gate set (PART F conclusion 4). If the gate ever *rejects*, that map cannot be
  injective, so a **gate-passing same-tweak collision always exists — at the oracle's own recorded counters**
  (`STCR_C.ec:127-137`), i.e. a winning S-TCR pair always exists. S-TCR is a **hardness-of-finding** assumption; only
  the degeneracy that is *ours* — a collapsing serialisation — is excludable, and N3/N4 exclude it. (Stated, not
  mechanized.)

**⚠ NEW FINDING, arguably bigger than V1/V2 — the port cannot be instantiated at C10's deployed WOTS parameters.**
Three *independent* grounds, each verified at source by me and by both external reviewers:
1. **`w` is out of range.** `const log2_w : { int | log2_w = 2 \/ log2_w = 4 \/ log2_w = 8 } as val_log2w`
   (WOTS_TW_ES.ec:31) ⇒ `w ∈ {4,16,256}`. C10 uses **W=8** (`sphincs-c10/src/params.rs:43`), i.e. `log2_w = 3`.
   Not substitutable — `len1`/`len2`/`len` are carried unchanged through both clone levels
   (FL_SL_XMSS_MT_ES.ec:544-545, SPHINCS_PLUS.ec:551-552).
2. **The checksum chains are still there.** `len = len1 + len2` with `1 <= len2` (WOTS_TW_ES.ec:43,133), and the +C
   sign/verify loops run to `len`. WOTS+C's entire purpose is to *eliminate* the `len2` checksum chains
   (`sphincs-c10/src/wots.rs:3-5`; C10 has `L = 43 = len1` only).
3. **`two_encodings` is FALSE at C10's actual encoding**, for two reasons: (a) with pure base-w and no checksum, the
   all-zero digest's encoding is pointwise dominated by every other, so no index `i` with `enc(m)[i] < enc(0)[i]`
   exists; (b) **`extract_digits` consumes only bits 0..128 of a 256-bit `wots_digest`** (`sphincs-c10/src/wots.rs:27-45`,
   `src/hash.rs:350-365` — verified independently), discarding 127 bits, so the deployed encoding is massively
   non-injective and distinct messages share an encoding.
   A further structural mismatch: formal `ThC` outputs `8n` bits (128 at n=16) while C10's WOTS message digest is
   **256** bits with **128**-bit chain elements — the formal model ties both widths to the single parameter `n`.

   **Consequence, stated plainly:** what is mechanized is *an abstract WOTS+C-style construction over MM45-supported
   WOTS parameters*, **not** deployed C10's WOTS layer. This is a faithfulness gap in the *interpretation* of the
   result, not a logical defect in it, and it is inherited from the MM45 base rather than introduced by the port.
   The constructive half: `constsum_encoding_is_two_encodings` shows the *right* repair — replace MM45's
   unconditional `two_encodings` axiom with the **predC-restricted** version, which a checksum-free constant-sum
   encoding provably satisfies.

**External adversarial review (both used, both acted on).** GPT-5.6 found the decisive hole — PARTS D/E witness with
*fresh existential* functions, so they could hold while the *actual* `predC` is false and `emb_in` constant. That is
what PART G was built to close. Kimi K3 found two further precise gaps: the joint model initially left the capstone's
own `encode_msgWOTS_C` bridge premise dangling (fixed: hypothesis (iv) — verified `encode_msgWOTS_C` is a free op,
WOTS_C_Real.ec:220), and the pigeonhole argument used an arbitrary Skolem counter that does not reach the game's win
condition (fixed: tightened to `grindC`, which is exactly what the challenge oracle records). Both reviewers
independently confirmed the axiom census (`predC`/`emb_in`/`thfc` carry **no** axiom anywhere in the closure, also
checking `declare axiom`, refined `const … as`, `op [lossless full uniform]`-generated facts, and clone
side-conditions) and confirmed findings 1-3 above. Neither modified any file.

**Self-found honesty item.** Conclusion 6 of the contentful theorem is **not** premise-dependent — the control
`scratch/trackV_probe_C6_without_N1.ec` **COMPILES**, because MM45's unconditional `two_encodings` already gives it.
Recorded at the conclusion itself and run in the gate as a *disclosed non-canary*. The informative statement is the
PART B version, quantified over an arbitrary encoding.

**Disclosure.** The positive-mass conclusion (`0 < mu ddgstblock predC`, the FORS `good_pos` shape) uses
`FTWES.ddgstblock_fu` — an **inherited, unrealized** MM45 clone axiom (SPHINCS_PLUS.ec clones FORS_ES without
realizing it). Pre-existing base TCB, not introduced here; the existential form is free of it. **No new axiom is
declared anywhere in this wave**; the four added premises are explicit, inspectable hypotheses of a *new* theorem,
and the capstone's own premise list is unchanged.
