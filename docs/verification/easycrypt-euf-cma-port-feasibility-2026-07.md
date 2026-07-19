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
