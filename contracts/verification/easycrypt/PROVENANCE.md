# c10-eufcma-port — provenance

Research workspace for the first increment of mechanizing C10 (SPHINCS+C)
EUF-CMA in EasyCrypt. Kept entirely outside the PQSigner repo.

## Inputs (gitignored, reproducible)
- `FV-SPHINCSPLUS-EC/` — git clone --depth 1 https://github.com/MM45/FV-SPHINCSPLUS-EC
  (the ASIACRYPT-2024 tight-proof artifact; local tweak: dropped the Z3 pin from
  `easycrypt.project` so Alt-Ergo alone typechecks definitions).
- `FV-XMSS-EC/` — git clone --depth 1 https://github.com/MM45/FV-XMSS-EC
  (reused base; has `TweakableHashFunctions.eca`, `WOTS_TW_Checksum.ec`).
- `paper-nist-pqc2022.pdf` (+ `.txt`) — SPHINCS+C, 39-page NIST PQC-2022 version
  (csrc.nist.gov), the fuller one WITH the security appendices (Thm 5.2, Def C.1
  S-TCR(Prop), Thm C.2, App-D sketch, Algorithms 9/10). IACR ePrint 2022/778 itself
  is Cloudflare-gated; this NIST version carries the same App B/C/D content.
- `paper-sphincsc-sp2023.pdf` — the FINAL published version (IEEE S&P 2023,
  DOI 10.1109/SP46215.2023.10179381), fetched via OpenAlex → `pure.tue.nl`
  (eprint.iacr.org returns HTTP 403 to non-browser clients). 10 pages, no appendices.
- ⚠ `paper-2022-778.pdf` and `paper2.pdf` are **NOT PDFs** — they are 5.5 KB
  Cloudflare "Just a moment…" HTML stubs from a failed `curl`. Do not cite them.
  (`paper-eyalro.pdf` is the author's *slide deck*, not the paper.) None are tracked.

## Deliverables (tracked)
- `drafts/STCR_C.ec`         — S-TCR(Prop) game + O^{+C} grinding oracle. TYPECHECKS.
- `drafts/PLAN.md`           — recon map, decisive finding, target lemmas,
                               file-by-file plan, App-D assessment, regime call.
- `drafts/FORS_C.ec`         — FORS+C security leg (second few-time primitive).
                               Faithful `EUFCMA_FORSC` theorem + bespoke ITSR(+C)
                               free-counter game + grind-abort analysis.
                               COMPILES EXIT=0, **zero admit** (since 2026-07-09).
- `drafts/WOTS_C_Encoding.ec` — **DELETED 2026-07-09.** Superseded scratch (broken
                               `op f`, EXIT=1), required by nothing, and it carried
                               an unconditional `axiom grindCP` that a naive
                               `grep axiom drafts/*.ec` surfaced as if it were live.

## EasyCrypt
EC `dev` (git-main) via opam switch `checkct`, Alt-Ergo 2.6.0 (no z3/cvc5).
```
export PATH="/usr/bin:/bin:$HOME/.nix-profile/bin:$PATH"
eval $($HOME/.nix-profile/bin/opam env --switch=checkct)
easycrypt compile -p Alt-Ergo@2.6.0 drafts/STCR_C.ec
```
⚠ **See "UPDATE 2026-07-09 — what `compile` actually certifies" at the bottom before
reading any "COMPILES EXIT=0" claim in this file.**

### UPDATE 2026-07-07 — CORRECTED check recipe (reduction chain)
The `checkct` recipe above does NOT build the WOTS+C reduction chain: `checkct`
(EC-dev) cannot compile the FV `WOTS_TW_ES.ec` ("for tag lossless, load Distr
first" bug in `DigitalSignatures.eca`), and the stale checkct `.eco` yields
"cannot locate theory WOTS_TW_ES". The working toolchain is the PINNED release
**`ec-r2026`** (r2026.02, matching FV-SPHINCSPLUS-EC's `easycrypt.project`), with
BOTH FV proof dirs on the include path — **XMSS FIRST, SPHINCSPLUS SECOND** (the
last `-I` wins for the duplicated `TweakableHashFunctions.eca`; only the
SPHINCSPLUS one carries `Collection.diff_t`, and `WOTS_TW_ES`/`STCR_C` need it):
```
bash ec-r2026.sh compile \
  -I FV-XMSS-EC/proofs -I FV-SPHINCSPLUS-EC/proofs -I drafts \
  drafts/WOTS_C_Reduction.ec
```
Dependency order for a clean rebuild (delete `drafts/*.eco` first):
`Grind → STCR_C → WOTS_C_Real → WOTS_C_Scheme → WOTS_C_Reduction`
(and rebuild `FV-SPHINCSPLUS-EC/proofs/WOTS_TW_ES.eco` under the same order if
missing). `WOTS_C_Encoding.ec` is a superseded scratch file (broken op `f`), not
in the reduction chain — ignore it.

### STATUS 2026-07-07e — MILESTONE: Thm C.2 FULLY ZERO-ADMIT (hop2 tail landed)
The single remaining forge/verify/post tail admit in `WOTSC_C2_hop2` is
**DISCHARGED**. `drafts/WOTS_C_Reduction.ec` and `drafts/Grind.ec` now contain
**ZERO `admit` tactics**; the whole reduction chain rebuilds **EXIT 0** under
`ec-r2026` (recipe above). Single-instance WOTS+C EU-naCMA (`EUFNACMA_WOTSC_C2`,
"Thm C.2") is machine-checked under exactly the three explicit hypotheses
`1 <= p_tgts`, address-separation (`sep`), and the encode bridge (`encb`).
- **The tail plumbing (the only gap, never a math gap):** after the sign `seq`,
  carry `m{2} = ThC psv witness mm (grindC …)` in the invariant (needed for the
  freshness post). Then: `call (verifyC_TW2 encb)` transfers WOTS+C validity to
  WOTS-TW validity on the +C digest; `wp; sp` absorbs the inlined `R.forge`'s
  trailing digest-return AND leading parameter-bindings (`sp` is the key — the
  param bindings sit *before* the `A.forge` call, so `wp` alone can't reach them
  and the two `A.forge` args won't align); `call (: true)` couples the oracle-free
  `A(OC).forge` on both sides (same `(glob A, arg)` ⇒ same `res`); `skip => /> *;
  smt()` discharges the post — GAME.1's non-collision
  `ThC ps witness mm grindC <> ThC ps witness m' c'` **is** the WOTS-TW freshness
  `digest' <> d` once the forge result aligns. No p_nu term, no weakened statement.
- Confirms the 07-07d prediction exactly: "once the tail lands, zero-admit under
  the 3 explicit hypotheses." It landed.

### STATUS 2026-07-07d — p_nu was an ARTIFACT; hop2 signing coupling CLOSES
Definitive answer to "does hop2 need p_nu?": **NO — it was an artifact of the
reduction, not inherent.** The earlier p_nu obstacle came from `R.choose` sending
the *sentinel* `d = witness` on grind-fail. Fix: `R.choose` now commits the digest
**uniformly** as `ThC ps witness mm (grindC ps witness mm)` (a final `Th_lambda`
query at the grind seed; `grind` is TOTAL so this is well-defined even on fail,
NOT the sentinel). Since `signC_TW` is an identity for ANY counter (incl.
`witness`), the honest signer's digest and `R.choose`'s digest coincide on EVERY
path — the coupling does NOT diverge, and hop2 needs NO extra term.
- **Proven (zero admit):** `GrindSearch_run_computes_grind` (Grind.ec);
  `Rchoose_grind` (R.choose returns the uniform digest, `sd = grindC`, on every
  path); `keygenC_TW`/`keygenC_TW_s`/`signC_TW`/`verifyC_TW`/`grindC_filter`.
- **hop2 byequiv (machine-checked so far):** seed sample + `OC.init` + `AA.choose`
  coupling + grind block (`sd = grindC`, uniform digest) + keygen + sign — all
  CLOSE. A is fed byte-identical `(sig, grindC)` on both sides.
- **Single remaining admit:** the mechanical forge/verify/post tail (relate A's
  no-oracle forge, the `R.forge` digest binding, `verifyC_TW`, and the post where
  GAME.1's non-collision IS the WOTS-TW freshness). Blocked only on EC
  inlined-variable plumbing (`R.forge`'s result var), NO math gap, NO p_nu.
- Thm C.2: once the tail lands, zero-admit under the 3 explicit hypotheses
  (`1<=p_tgts`, address-separation, `encode_bridge`). The p_nu term is NOT needed.

### STATUS 2026-07-07c — Grind operational admit DISCHARGED + hop2 p_nu finding (SUPERSEDED by 07-07d: p_nu was an artifact)
- **`GrindSearch_run_computes_grind` PROVED (Grind.ec, zero admit).** The bounded
  finite counter scan computes the pure op `grind`: loop invariant "while not
  found, `r = witness` AND `head (filter (predC∘ThC) cs) = grind`", with the
  one-step fact `head_filter_ne`. This removes Grind.ec's last labelled admit — a
  standing admit gone from the whole stack. Whole chain rebuilds EXIT 0.
- **hop2 is STILL admitted, and the operational grind is NOT its only blocker.**
  Building the coupling on top of the (now available) operational grind surfaced a
  second, genuine obstacle — the **grind-FAILURE (p_nu) case**: when no counter
  satisfies `predC` for `mm` (`grind_fails`, positive probability), `R.choose`
  sends `d = witness`, and `signC_TW`'s precondition demands
  `witness = ThC ps witness mm witness` (false; `two_encodings` makes
  `encode_msgWOTS` injective). The honest signer then feeds A a *different*
  signature, breaking the "A driven identically" coupling; GAME.1 can still win
  there. So `Pr[GAME.1] <= Pr[WOTS-TW]` (no extra term) is NOT provable by this
  reduction — the faithful bound carries `+ Pr[grind_fails]` (the paper's p_nu,
  which Grind.ec (e) already flags as a CARRIED additive term). Threading
  `!grind_fails` as a hypothesis is REJECTED (it drops a positive-probability
  event → silently weakens the theorem). The fix restructures the hop2 / Thm C.2
  statement with the p_nu term, grounded in the paper's App-C statement — a scoped
  follow-up. **Thm C.2 is NOT zero-admit.**

### STATUS 2026-07-07b — Thm C.2 hop2 groundwork (Algorithm-10 / WOTS-TW)
`WOTSC_C2_hop2` remains ONE labelled admit, but the reduction is now correct and
its modeling core is machine-checked:
- **`R_WOTSTW_WOTSC.forge` FIXED** — returns the +C **digest**
  `ThC pk.`2 witness m' counter'` (not A's raw message) as the WOTS-TW forgery
  message, the faithful Algorithm-10 shape (WOTS-TW verifies via `encode_msgWOTS`;
  WOTS+C chain-walks `encode_msgWOTS_C` = `encode_msgWOTS` of that digest).
- **Modeling triple PROVED (qed):** `keygenC_TW` (WOTS+C/WOTS-TW keygen identical),
  `signC_TW` (under the encode bridge, WOTS+C-signing `m` == WOTS-TW-signing the +C
  digest, emitting the grind counter), `verifyC_TW` (a valid WOTS+C forgery gives a
  valid WOTS-TW forgery on the digest; the extra `predC` gate only strengthens).
- **`encode_bridge` threaded** as an explicit, faithful hypothesis on `hop2` and
  `EUFNACMA_WOTSC_C2` (`encode_msgWOTS_C p a x c = encode_msgWOTS (ThC p a x c)` —
  the definition of the +C encoding).
- **Sole residual:** the operational grind-search correctness —
  `R_WOTSTW_WOTSC.choose`'s finite `Th_lambda` scan computes `grindC` (so `sd =`
  the digest seed). This is the SAME content as Grind.ec's existing labelled admit
  `GrindSearch_run_computes_grind` (a `head (filter predC∘ThC enum)` loop-scan
  invariant), orthogonal to the security argument.
Thm C.2 (`EUFNACMA_WOTSC_C2`) therefore holds under three explicit hypotheses
(`1<=p_tgts`, address separation, `encode_bridge`) with a single remaining
operational-grind admit; it is NOT yet fully zero-admit.

### STATUS 2026-07-07 — Thm C.2 hop1 PROVED (zero admit)
`drafts/WOTS_C_Reduction.ec`: `WOTSC_C2_reduce` (Algorithm-9 reduction-correctness
byequiv) and `WOTSC_C2_hop1` (GAME.0 ≤ GAME.1 + InSec^{S-TCR(+C)}) are now real
`qed`s, **under two explicit, paper-faithful hypotheses**: `1 <= p_tgts`
(target-count) and address separation (A never queries `Th_lambda`/OC at the
challenge tweak `witness`). Both thread through `EUFNACMA_WOTSC_C2`. The SOLE
remaining `admit` in the file is `WOTSC_C2_hop2` (the Algorithm-10 / WOTS-TW hop).
No new `axiom` is introduced; `print axioms` is unavailable in r2026, but the hop1
proof script invokes only `sim`/`inline`/`conseq`/`auto`/`smt(grindC_E)` over the
scheme procs plus the two hypotheses — it does not reach the FV MEUFGCMA lemmas
nor Grind's operational `GrindSearch_run_computes_grind` admit (`grindC` is used
as the total op `G.grind`, unfolded definitionally by `grindC_E`).

### STATUS 2026-07-07e — Thm D.1 hop1 core `D1_reduce` PROVED (zero admit); D.1 admits 2 → 1
`drafts/WOTS_C_Multi.ec` rebuilds **EXIT 0** clean-from-scratch (`ec-r2026`, XMSS
-I before SPHINCSPLUS -I); admit sweep = **exactly 1 labelled admit** (`D1_hop2`,
line ~647). `D1_reduce` now ends in **`qed`** — no admit, no sorry, no new axiom.

- **`D1_reduce` (Algorithm-9 multi-instance byequiv) — PROVED.** The d-query lift
  of the single-query `WOTSC_C2_reduce`. `byequiv G0_MULTI ~ S_TCR_C(R_multi_STCRC(A))`
  coupling `(res{1} /\ coll{1}) => res{2}`, built as:
  (1) choose sync (`ch_eq` by `sim`); (2) a **one-sided `while{2}`** over
  `R_multi_STCRC.pick`'s target-registration loop establishing
  `O.ts = map (fun q => (WAddress.val q.1, q.2, grindC pp (WAddress.val q.1) q.2)) qs`;
  (3) a **two-sided `while`** coupling G0_MULTI's and `R.find`'s keygen+sign loops
  with a per-index invariant carrying `={ks}`, `adlO = map (val∘fst) (take k qs)`,
  and the counter fact `∀ idx<k, (nth ks idx).2.2 = grindC pp (val (nth qs idx).1) (nth qs idx).2`
  (via side-1 `exists*` + `keygen_eqs`/`sign_eqs2`, grind deterministic);
  (4) tail: the collision at forged index `i` maps to S_TCR_C success on target `i`
  through the counter fact + `nth_map`, with `nrts = size qs ≤ c ≤ p_tgts` and the
  two predicate bridges.
- **New helper lemmas (all `qed`, zero admit):** `uniq_wgpidxs_uniq`,
  `disj_wgpidxs_disj_lists` (moved ABOVE `D1_reduce` so it can consume them), and
  `map_fst_targets` (`map fst (map g qs) = map (val∘fst) qs`, by `-map_comp`).
- `WOTS_C_Multi.ec` now `require import WOTS_C_Reduction` to reuse its zero-admit
  `keygen_eq`/`sign_eq`/`keygen_eqs`/`sign_eqs2`/`verify_ll`/`grindC_E` (that file
  is itself admit- and axiom-free).
- **Remaining D.1 admit: `D1_hop2`** (Algorithm-10 multi byequiv) only — the
  nested grind-scan while-loop coupling. `D1_hop1` (which threads `D1_reduce`) and
  the headline `D1_MEUFNACMA_WOTSC` were already `qed`.

### STATUS 2026-07-07c — Thm D.1 (MULTI-instance WOTS+C d-EU-naCMA) — PARTIAL, STATED + composed, 2 labelled admits
New file `drafts/WOTS_C_Multi.ec` (compiles clean, `ec-r2026`, XMSS -I before
SPHINCSPLUS -I). Also reconciled the stale Thm-C.2 admit-COMMENT in
`WOTS_C_Encoding.ec` (that file is superseded scratch, NOT in the build chain; the
real C.2 lives in `WOTS_C_Reduction.ec` as `EUFNACMA_WOTSC_C2`).

**Modeling decision (verified, not assumed):** `FC` in WOTS_TW_ES.ec:450 is the
CHAIN-HASH collection (`in_t <- dgst`, `f <- f`), it does NOT compute Th+C. So the
multi-instance reductions are built over the S-TCR(+C) collection `STCRC_WC.Col`
(which computes Th+C), EXACTLY as C.2's hop2 already modeled WOTS-TW over
`STCRC_WC.Col`. The connection of the WOTS-TW term to the repo's FC-based
`M_EUF_GCMA_WOTSTWESNPRF` (hence MM45's `MEUFGCMA_WOTSTWESNPRF` black box) is the
SAME FC<->STCRC_WC.Col unification C.2 deferred (WOTS_C_Reduction.ec ~line 342). We
model d-EU-naCMA in its literal NON-adaptive shape (adversary commits its d queries
in `choose`, receives keypairs+sigs in `forge`), which lets BOTH reductions be REAL
zero-admit modules that defer sig-construction to where `pp` is available — the
exact idiom C.2's single-query reductions use, lifted to d queries. (An adaptive
M_EUF_GCMA oracle would force the S-TCR reduction to apply the chain hash `f` at the
hidden `pp` during `choose`, which `STCRC_WC.Col` can't do — precisely the deferred
unification; non-adaptive commitment sidesteps it, and d-EU-naCMA is the notion
Thm D.1 states.)

**REAL, zero-admit (compile-checked):**
- `M_EUF_NACMA_WOTSC_L` / `M_EUF_NACMA_WOTSTW_L` — the multi-instance d-EU-naCMA
  games for WOTS+C and (local) WOTS-TW, over `STCRC_WC.Col`.
- `GAME1_MULTI` / `G0_MULTI` — instrumented games (collision-event split).
- `R_multi_STCRC` (Algorithm 9, d-query lift of `R_STCRC_WOTSC`) — registers one
  S-TCR(+C) target per committed query in `pick`, defers keypair/sig to `find(pp)`,
  relays A's forgery on instance i as the collision on target i.
- `R_multi_WOTSTW` (Algorithm 10, d-query lift of `R_WOTSTW_WOTSC`) — per query
  grinds a +C counter via the collection oracle and commits the +C digest
  `ThC(pp,wad,m,grind)` (= msgWOTS, since `msgWOTS = dgstblock`) as the WOTS-TW
  message; in `forge` reconstructs each WOTS+C sig and relays A's forgery on the
  digest.

**PROVEN (qed):**
- `D1_MEUFNACMA_WOTSC` — the headline Thm D.1 two-term bound
  `Pr[M_EUF_NACMA_WOTSC_L(A)] <= Pr[S_TCR_C(R_multi_STCRC(A))] + Pr[M_EUF_NACMA_WOTSTW_L(R_multi_WOTSTW(A))]`,
  composed from the two hops (linear real arithmetic), under two explicit
  hypotheses: `c <= p_tgts` (target-count) and the `encode_bridge`.
- `D1_hop1` — GAME.0 <= GAME.1 + S-TCR(+C), with the instrumentation byequivs
  `e0` (`Pr[GAME.0]=Pr[G0_MULTI]`) and `e1` (`Pr[G0_MULTI: res /\ !coll]=Pr[GAME1_MULTI]`)
  PROVEN (real `seq 15 15`/`sim` byequivs); the collision part supplied by `D1_reduce`.

**LABELLED ADMITS (exactly 2, each documenting its exact obligation):**
- `D1_reduce` (D.1 hop1 core, Algorithm-9 multi byequiv): the d-query lift of the
  single-query `WOTSC_C2_reduce` coupling — per-index target-registration invariant
  relating `O.ts` to `qs` + the deterministic grind, plus the `uniq_wgpidxs =>
  uniq`(tweaks) and `disj_wgpidxs => disj_lists` predicate bridges. Multi-round.
- `D1_hop2` (D.1 hop2 core, Algorithm-10 multi byequiv): the d-query lift of
  `WOTSC_C2_hop2` — per-index `signC_TW`/`verifyC_TW2` + the nested grind-scan
  while-loop coupling (as in C.2's hop2 grind block). Multi-round.

Not yet done: discharging the two admits (per-index loop invariants), the
FC<->STCRC_WC.Col unification bridges connecting the WOTS-TW term to the repo
`MEUFGCMA_WOTSTWESNPRF`, and the LHS bridge to Scheme.ec's `M_EUF_GCMA_WOTSC_NPRF`.
Next legs after D.1: FORS+C multi-instance, then the SPHINCS+C composition.

### STATUS 2026-07-07f — FORS+C security leg STARTED (drafts/FORS_C.ec)
Second few-time primitive for the SPHINCS+C composition. COMPILES EXIT=0 clean
from scratch under the ec-r2026 recipe (XMSS -I then SPHINCSPLUS -I).

- **Template found:** `FV-SPHINCSPLUS-EC/proofs/FORS_ES.ec` — top game
  `EUF_CMA_MFORSTWESNPRF` (~2007), top theorem `EUFCMA_MFORSTWESNPRF_OPRE`
  (~3829) reducing FORS-TW EUF-CMA to FOUR terms:
  `MCO_ITSR.ITSR` + `F_OpenPRE` + `TRHC_TCR` + `TRCOC_TCR` (interleaved-target
  subset resilience of the message hash `mco`; OpenPRE of the leaf hash; S-TCR
  of the tree hash `trh` and root-compression `trco`).
- **FORS+C theorem stated FAITHFULLY** (`EUFCMA_FORSC`): the FORS-TW four-term
  bound with the SINGLE substitution `ITSR(mco) -> ITSR(+C)(mco_C)`, the three
  tree terms unchanged (the +C R-grind rewrites only the message->index map,
  never the Merkle/root layer). Mirrors WOTS+C Thm C.2/D.1 adding exactly one
  +C term. Cross-checked vs SPHINCS+C Thm 5.2 (its only +C term is the WOTS+C
  `S-TCR(+C)(Th+C)`; FORS+C is folded into a tighter `itsr(Hmsg)` DarkSide
  bound — consistent with ITSR->ITSR(+C)).
- **Proven (2 lemmas, zero admit each):** `mco_C_predC` (discharged p_nu form:
  `(exists good counter) => predC_fors(mco_C mk m)`, via Grind.grind_correct)
  and `O_ITSRC_query_good` (game-level: every ITSR(+C) target the oracle records
  is +C-valid). Plus the Grind-clone re-exports.
- **1 labelled admit:** `EUFCMA_FORSC` composition (the ITSR(+C) hop pRHL +
  the three +C-invariant tree hops, a multi-session port of the FORS_ES proof).
  Analogous to D.1's labelled byequiv admits.
- **CRITICAL grind-abort verdict (flagged for parent review; big comment block
  atop FORS_C.ec):** the FORS+C R-grind is TOTAL in the model (same
  `head witness (good_ctrs)` idiom as WOTS+C); there is NO additive p_nu term in
  the FORS+C SECURITY bound — Thm 5.2 carries none, dissolved by the r=lambda
  counter-space choice (paper ~line 739, App C). The one FORS-specific nuance:
  the verifier requires the last tree to open leaf 0, so grind-failure breaks
  COMPLETENESS (invalid honest sig) rather than being a WOTS+C-style no-op — but
  that is a correctness concern present identically in the real game and the
  reduction, so it does NOT enter the EUF-CMA advantage. `good_counter_exists`
  is carried as an EXPLICIT lemma HYPOTHESIS (the discharged p_nu), not an axiom.
- **Advisor-caught soundness fix (recorded as modeling note M2):** an initial
  in_t=msg deterministic-grind fold was UNSOUND against the paper's PERMISSIVE
  verifier (accepts any predC_fors-counter). Fixed by making ITSR(+C) a BESPOKE
  free-counter game (like STCR_C's counter-returning oracle): the forgery carries
  a free c', coverage lands on the forger's real digest — no extra collision
  term, sidesteps key-before-grind circularity.
- **Caveat (honest):** the three tree terms are currently carried as abstract
  non-negative reals `tree_openpre/trh/trco` (scaffold placeholders documented
  as the FORS_ES reduction advantages); the four-term bound is faithful in SHAPE
  but not yet a meaningful numeric bound until those are tied to the concrete
  `Pr[FORS_ES reduction]` expressions. Next: instantiate them + discharge the
  ITSR(+C) hop, then FORS+C multi-instance, then SPHINCS+C composition.

### UPDATE 2026-07-08 — ITSR(+C) game-hop PROVED (standalone zero-admit `qed`)

The +C-specific game-hop is now a real theorem and the composition consumes it.

- **New instrumented game `EUF_CMA_FORSC_I`** — identical to `EUF_CMA_FORSC` but
  records a GHOST target list `ts` of `(mk, m, gc mk m)` (one entry per UNIQUE
  queried message, matching `O_ITSRC_Default.query`) plus a coverage boolean
  `covered` (FORS_ES's `valid_ITSR` event, expressed with `List.all` so it is
  `wp`-absorbable). `covered` is COVERAGE-ONLY; freshness is carried separately.
- **`eufcma_forsc_I_eq` (qed, zero admit):** `Pr[EUF_CMA_FORSC : res] =
  Pr[EUF_CMA_FORSC_I : res]` — the ghost never touches `res`.
- **`ITSRC_hop` (qed, zero admit) — the primary deliverable:**
  `Pr[EUF_CMA_FORSC_I : res /\ covered] <= Pr[ITSRC(R_ITSRC_FORSC(A), O_ITSRC_Default) : res]`.
  One linear byequiv (WOTSC_C2_reduce shape): couple the signing oracles
  (sign-invariant threads `ts{1}=O_ITSRC.ts{2}` and `map(.\`2)ts ⊆ qs`), then the
  final entailment gives: `is_valid ⇒ predC_fors` (condition i, from `verifyC`),
  `covered ⇒` coverage (condition ii, via `allP` and `ts{1}=ts{2}`), and
  message-freshness `!m'∈qs` ⇒ triple-freshness `!(mk',m',c')∈ts` (condition iii,
  via `mapP` on the `msgs(ts)⊆qs` invariant). Mirrors FORS_ES splitting
  `valid_ITSR` into coverage (line 3341) + the `!(k,x)∈kxl` freshness thread
  (line 3900). The hop uses NEITHER `good_counter_exists` NOR `O_ITSRC_query_good`
  (`move=> _` on the composition confirms the hypothesis is composition-side only:
  `ITSRC.main` checks `predC_fors` only on the forgery digest, never on recorded
  targets) — no machinery threaded to manufacture a use.
- **Composition `EUFCMA_FORSC` rewired:** instrument (`eufcma_forsc_I_eq`),
  `Pr[mu_split covered]`, bound the covered part by `ITSRC_hop`, and `smt()` the
  linear-real combination.

**Admit count: 1 → 1 (UNCHANGED, honestly reported).** What changed is the
NATURE: the ITSR(+C) hop is now a standalone zero-admit `qed`; the sole remaining
`admit.` narrowed in scope from "the WHOLE composition (ITSR hop + 3 tree hops)"
to the TREE-TERMS bound (`htree`) ONLY — `Pr[res /\ !covered] <= tree_openpre +
tree_trh + tree_trco`. That bound CANNOT reach zero admit in this file: the tree
layer is fully abstract (`fkeygen`/`fsign`/`fverify` opaque, no Merkle structure
in scope), so there is no concrete OpenPRE/TRH/TRCO game to tie the three
abstract reals to. The stretch goal (tie `tree_openpre` to `Pr[F_OpenPRE...]`)
was DECLINED on faithfulness grounds — a "tie" would require building the tree
layer or faking a numeric equality. NO axiom, NO sorry, NO weakened statement.

`FORS_C.ec`: 5 `qed` (was 3), exactly 1 tactic `admit.`.

Check recipe (clean from scratch):
```
rm -f drafts/FORS_C.eco          # ONLY your own object (shared tree — never global -delete)
bash ec-r2026.sh compile -I FV-XMSS-EC/proofs -I FV-SPHINCSPLUS-EC/proofs \
  -I drafts drafts/FORS_C.ec   # EXIT=0
```

---

### UPDATE 2026-07-09 — what `compile` actually certifies (READ THIS FIRST)

An adversarial review (105-agent swarm + mechanical PoCs) established two facts that
**invalidate the evidence shape used throughout this file above**:

**1. `require` does NOT re-verify.** EasyCrypt loads a required theory's lemma
*statements* and trusts them. Reproduce:
```
# Broken2.ec -> compiles standalone EXIT=1 (correctly rejected)
lemma brk2 : forall (b : bool), b.  proof. trivial. qed.
# Uses2.ec   -> compiles EXIT=0, deriving `false`
require import Broken2.
lemma e2 : false. proof. by have := brk2 false. qed.
```
Consequently **"file X compiles EXIT 0" certifies ONLY X's own proof scripts.**
Compiling the capstone `SPHINCS_C.ec` from a cold cache takes 1.3 s and writes only
`SPHINCS_C.eco`; `WOTS_TW_ES.ec` alone as a target takes 81 s. **The chain was never
re-verified by a capstone compile.** Every "clean-from-scratch rebuild EXIT 0" claim
above should be read as scoped to the single file named on the command line.

The `-check-all` flag *does* force checking required theories (it correctly rejects
`Uses2.ec`), but it also re-checks the stdlib and currently dies inside
`theories/datatypes/Real.ec`. **The practical sound gate is: compile EVERY file as a
target, plus a comment-stripped admit/axiom sweep of each.**

**2. `admit` compiles EXIT 0 with ZERO output.** No warning. Exit code says nothing
about admits. And `grep '^\s*admit'` **without stripping `(* … *)` comments** massively
over-counts (prose containing the word "admit"). Use:
```
perl -0777 -pe 's/\(\*.*?\*\)//gs' F.ec | grep -nE '^\s*(\+\s*)?admit\s*\.'
```
Also: `.eco` caches *verification results* and is content-hashed, so `touch f.ec`
"recompiles" in ~0.1 s verifying nothing.

### UPDATE 2026-07-09 — H-TREE / H-TREE-MULTI were FALSE, not deferred

`tree_*` (FORS_C.ec) and `mtree_*` (FORS_C_Multi.ec) were free abstract ops
`{real | 0%r <= _}` inside the **abstract** theories `FORSC` / `MFORSC`, with the tree
bound closed by `admit`. A legal clone may instantiate all three to `0%r` (sole
realization obligation `0 <= 0`), under which the admitted step reads
`Pr[… /\ !covered] <= 0%r` — **false**. Demonstrated mechanically: cloning `MFORSC`
with `mtree_* <- 0%r` compiled EXIT 0 and yielded `Pr[FORS+C multi EUF-CMA] <=
Pr[ITSR(+C)]` with **no tree terms** — strictly stronger than the paper. Dually,
`<- 1%r` made the whole bound trivially true. Same bug class as the already-fixed
`D1_hop2` (false conjunct → RHS ≡ 0) and `R_trco` (spurious 0).

Because a constant cannot bound a `forall A` probability, **completing the tree-layer
port would never have discharged these admits** — the statements had to change.

**Fixed (commit `7ba51d4`):** the six reals became universally-quantified *lemma
parameters* and the tree bound became an **explicit premise** of `EUFCMA_FORSC` /
`EUFCMA_MFORSC`; `SPHINCS_C.ec` threads it through. The theorems are now true
conditionals, the admits are gone, and the obligation is visible in the statement.
Discharge = port the FORS_ES tree layer and instantiate the premise.

Verified per-file (each compiled AS A TARGET): `FORS_C.ec` EXIT 0 / 0 admit,
`FORS_C_Multi.ec` EXIT 0 / 0 admit, `SPHINCS_C.ec` EXIT 0 / 0 admit.
Regression: both false-instantiation PoCs now fail (`unknown operator mtree_openpre`).
Non-vacuity: deleting the `htree` premise makes `SPHINCS_C.ec` fail (strict).

### UPDATE 2026-07-09 — corrected ledger

- **Real admits across `drafts/*.ec`: 3** (was 5), and **all three are in files that
  NOTHING requires**: `FORS_C_TreePort.ec` (extract_op), `FORS_C_TreePort_skel.ec`
  (untracked 13-line scratch probe whose `admit` closes a *trivially true* statement —
  delete or gitignore it), `WOTS_C_Interactive.ec`. The capstone's chain is admit-free.
- **Real axiom declarations across `drafts/*.ec`: 1** — `axiom dpp_ll : is_lossless dpp`
  (STCR_C.ec), benign. The unconditional `grindCP` left with `WOTS_C_Encoding.ec`.
- **Orphaned (required by nothing, contribute zero to the capstone today):**
  `FORS_C_TreePort` (and note it targets `FORS_C`'s single-instance obligation, while
  the capstone routes through `FORS_C_Multi`'s independent one), `FORS_C_Tree`,
  `WOTS_C_Interactive`, `SPHINCS_C_Skeleton`'s proven `FX_skeleton_C`, and
  `WOTS_C_Flag2Discharge` (its FLAG-2 proof is over a *defined* `emb_tw` in namespace
  `FSSLXMTWES.WTWES`; the capstone premise is over the *abstract* `emb_tw`).
- **MM45 reference:** **0 admit tactics** in all of `FV-SPHINCSPLUS-EC` + `FV-XMSS-EC`.
  `WOTS_TW_ES.ec` (the file our WOTS+C leg depends on) verifies as a target: 81 s,
  EXIT 0. `SPHINCS_PLUS.ec` fails an `smt()` at `:1932` **on this box only** — the
  switch has Alt-Ergo but not the `Z3@4.13.4` that `FV-XMSS-EC/easycrypt.project`
  declares. Not a timeout (persists at `-timeout 30`), and **not evidence against MM45**.

### UPDATE 2026-07-09 — literature: the paper never proves FORS+C

Checked against the **final IEEE S&P 2023 version** (`paper-sphincsc-sp2023.pdf`).
The paper has exactly **two** theorems: Thm 5.2 (SPHINCS+C bound) and Thm C.2 (WOTS+C
EU-naCMA — which our `EUFNACMA_WOTSC_C2` matches exactly).

- Thm 5.2's preamble: *"By obtaining a d−EU-naCMA security proof for **WOTS+C** one can
  just substitute WOTS-TW with our modification. This results in adding a S-TCR(+C)
  term."* Its message-hash term is the **plain** `InSec^itsr(Hmsg)`.
- §IV *1) Security*: *"The security analysis is the same as the security analysis of
  FORS… **we can use the previous ITSR analysis to bound the security of FORS+C**."*
  §V: *"The usage of FORS+C is **straightforward**."*
- So FORS+C's security is a one-paragraph informal `DarkSide_γ` combinatorial argument.
  There is **no FORS+C reduction and no FORS+C theorem** in the paper.

⇒ Our bespoke `ITSR(+C)` game is **original work filling an informal gap**, not a port.
This is credit *and* risk: nothing reduces `ITSRC` to the paper's plain `itsr`, and the
standing claim "MM45-machinery structural porting with **no new +C mathematics to
discover**" is **wrong for the FORS side**.

**Also confirmed sound (the review had teeth):** the p_ν adjudication is *faithful to
the paper*, which states outright: *"we assume that it is always possible to find a good
counter and the adversary can not depend its behavior on the existence of a fitting
counter."* No additive p_ν term in Thm 5.2. And `disj_lists` is the paper's **own**
restriction on the Thλ collection oracle (*"queries to Thλ should use different tweaks
from the ones that are used for challenge queries"*), justified only informally — that
informal justification, not the restriction, is the real residual.
