kimi version 0.34.0
• This is a read-only verification task on an EasyCrypt codebase. I need to read the actual sources and check each leg. Let me read the key files.

  Let me start by reading the relevant locations:
  - `base-c10-split/WOTS_TW_ES.ec:1476-1516` (both lemmas), `:6530-6560` (caller)
  - `cdrafts-split/WOTS_C_Real.ec:214`, `cdrafts-split/WOTS_C_Scheme.ec:100-230`
  - `cdrafts-split/GprocQWired.ec:440-470`
  - `scratch/wots_admit_is_injectivity.ec`
  - `sphincs-c10/src/wots.rs:26-45` (may not exist in this repo; check)
  - `WOTS_TW_ES.ec:270`, `:46`

  This is substantial reading across multiple files. I could delegate to explore agents, but I need precise line-level verification for a verdict. The task is focused enough — maybe 6 file regions. I can do it myself, or delegate to parallel explore agents. Given precision matters (a verdict on refutation), I'll read key files myself. Actually the volume is moderate: let me read directly.

  Let me start reading.

• I'll read the actual sources for each leg before rendering any verdict. Starting with the admit site and its caller.

• Leg 1 verified at source: admit at 1505-1514, open goal `P m => P m' => m <> m' => encode_msgWOTS m <> encode_msgWOTS m'` (the admitted subgoal after `apply nhchwcoll_hchwpre`). Caller at 6542: applies `nhchwcoll_hchwpre_msg ps{2} q.1 _ _ q.4 sig'{2} hPq2 hPmp2` with `neqq2_mp` being m' <> q.2 presumably. q is nth of O_MEUFGCMA_WOTSTWESNPRF.qs — an oracle query. m' adversary-chosen. So Leg 1 confirmed at these sites: ps is passed as the pseed parameter to the lemma but the goal doesn't involve ps. Note the lemma DOES take `ps` — but the admitted goal (encode m <> encode m') is ps-free. Also the statement's conclusion/hypotheses about has_chwcoll/has_chwpre involve ps, but the admit is only on the encoding inequality. So seed-withholding has nothing to bite on — the admit itself is unkeyed.

  Wait — but is it true that "seed withholding has nothing to bite on"? The claim: the encoding-collision event at that layer has probability 1? Hmm — "the encoding-collision event at that layer has probability 1" — actually the user says the adversary can choose m' = some m'' with same encoding as a query m, with probability 1. That's about the game. Need to check whether the game at that layer constrains m' to differ... m' <> m checked (neqq2_mp), but encode can collide. So if encode is many-to-one, adversary wins trivially by picking a collision. Yes.

  Now check: is the caller at 6542 the "sole live caller"? Search for nhchwcoll_hchwpre_msg usages across repo. Also check whether the lemma at 6542 is used within MEUFGCMA_WOTSTWESNPRF proof. Let me grep.

  Also need: `cdrafts-split/WOTS_C_Real.ec:214`, `WOTS_C_Scheme.ec:100-230`, `GprocQWired.ec:440-470`, `scratch/wots_admit_is_injectivity.ec`, `WOTS_TW_ES.ec:46` and `:270`, and `sphincs-c10/src/wots.rs` (may not be in repo — check).

• Admit and caller confirmed at source. Now checking the caller's uniqueness and the +C layer files.

• Legs 1, 2 partially confirmed. Now I need:

  - Confirm the caller `:6542` is the sole live caller within base-c10-split (grep shows only line 6542 in base-c10-split; other files are copies/mutations). ✓
  - The M_EUF_GCMA_WOTSTWESNPRF game: check the adversary type — does `forge` receive ps at the TW layer too? In WOTS_TW_ES, the NPRF game: adversary's forge gets ps? Actually "NPRF" means the ps is given to the adversary in forge? Let me check M_EUF_GCMA_WOTSTWESNPRF game definition around line 2323 in WOTS_TW_ES.ec. The user's claim Leg 1: m' adversary-chosen msgWOTS, m one of its own queries, no pseed interposed — i.e., encode_msgWOTS doesn't depend on ps at all (encoder unkeyed). That's plainly true: encode_msgWOTS is a function of m only. Whether ps is withheld at that layer is irrelevant to the encoder. The "seed-withholding" in the +C layer is about ThC being ps-keyed.

  Wait — actually check: in M_EUF_GCMA_WOTSTWESNPRF, is ps given to the adversary at forge time? For WOTS_TW the adversary type... the user's claim in Leg 2 says M_EUF_GCMA_WOTSC_NPRF's adversary "withholds ps from choose" — verified: `choose() : unit { O.query, OC.query }` and `forge(ps : pseed)` — so ps IS given at forge, withheld during choose. ✓

  - Leg 2: the summand at GprocQWired.ec:457 — verified: `Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))), ...)]`. So the +C layer reaches the TW game via reduction R_int_WOTSTW. The question: is this summand "UNREDUCED"? Need to check whether there's a theorem applying MEUFGCMA_WOTSTWESNPRF (the lemma at :6578) to bound this term. The base theorem `MEUFGCMA_WOTSTWESNPRF &m` bounds `Pr[M_EUF_GCMA_WOTSTWESNPRF(A, ...)]` for all A presumably by TCR/OpenPRE terms. If that theorem (which contains the admit in its proof) is applied to reduce this summand, then the +C bound consumes the admit. Is the summand left unreduced in GprocQWired (i.e., the deployed theorem keeps it as a raw probability term)? Line 457 shows it as a raw Pr[...] term on the RHS of the bound — so yes, it remains unreduced at the deployed level. Whether it's reduced anywhere else — search for applications of MEUFGCMA_WOTSTWESNPRF lemma.

  - Also need to check: is there any other route from +C to the admit — e.g., a WOTSC-level reduction to WOTS-TW that proves `Pr[M_EUF_GCMA_WOTSC_NPRF...] <= Pr[M_EUF_GCMA_WOTSTWESNPRF...]` plus other terms, which exists at R_int_WOTSTW. That's exactly the route in 457. To bound further you'd apply the base theorem → consumes admit. Leg 2's "circular" claim: reducing the summand consumes the admit, so you can't use the +C seed-withholding to discharge the admit without circularity... wait, actually the user's claim is subtler: seed-withholding at +C can't discharge the admit because to route the +C adversary's advantage down to the TW game you need the base theorem which needs the admit. Hmm, actually the logic: to discharge the admit via a seed-withholding argument, you'd bound the collision event by something at the +C layer; but the +C layer's bound on TW forgery is via the base theorem, which itself needs the admit — circular. That seems right if the only +C→TW route is the theorem.

  But is there an alternative route? Question 2 asks: a different M_EUF_GCMA_WOTSC_NPRF-level reduction that never needs nhchwcoll_hchwpre_msg. E.g., is there a lemma bounding Pr[M_EUF_GCMA_WOTSC_NPRF] directly in terms of THFC properties (SM_DT_TCR_C etc.) without going through M_EUF_GCMA_WOTSTWESNPRF? Let me search cdrafts-split for lemmas about M_EUF_GCMA_WOTSC_NPRF bounds.

  - Leg 3: EasyCrypt idiom question — can you charge a term inside a qed-ed proof without editing? Answer: no. Once a lemma is qed, its proof is opaque; you can only use its statement. There's no idiom to get "credit" for a case split inside a proof. Section/clone re-instantiation works at theory/lemma statement level, not proof internals. `local` declarations restrict export. So Leg 3 stands as far as EasyCrypt semantics. I can verify by knowledge; the repo itself says this (cert_cone.py: "EasyCrypt has no..."). Let me read cert_cone.py around line 8 for the repo's own statement.

  - Q2b tension: need to check msgWOTS definition at WOTS_TW_ES.ec:270, n_m at :46, encode_msgWOTS, P predicate, and deployed C10 parameters (n_m = 2*n? and domain 2^256 vs w^len). And sphincs-c10/src/wots.rs — check if that path exists in this repo (probably not; it's an external repo reference). Check.

  - Also read scratch/wots_admit_is_injectivity.ec to check the equivalence proof claim, and the gate script.

  Let me do these reads in parallel. Also check `encode_msgWOTS` definition and `P`.

• Legs 1 and 2's key sites verified. Now the remaining pieces: the encoder definitions, the game at the TW layer, the scratch proof, and repo docs.

• Now I need to check:

  1. The `encode_msgWOTS` op at :624 — free op (no definition, no axioms?). Check :620-660. Also check whether any axiom constrains it (two_encodings at :716-732 is an axiom? check). two_encodings: let me read 620-740.

  2. The M_EUF_GCMA_WOTSTWESNPRF game and adversary type at the TW layer — whether forge receives ps, and whether m'/m are as described. Also, is the encoder dependent on ps anywhere? No — `encode_msgWOTS : msgWOTS -> emsgWOTS` is unkeyed. Leg 1's essential claim verified: the admitted subgoal mentions only m, m', encode_msgWOTS, P — no ps.

  But wait: one subtlety in Leg 1 — "the encoding-collision event at that layer has probability 1". Hmm, at the TW layer the adversary's m' is a msgWOTS, and m is a query's message. Since encode is unkeyed and abstract, the adversary doesn't actually know encode_msgWOTS (it's a free op — not computable by the adversary... actually in EasyCrypt, free ops are still deterministic functions the adversary could in principle compute? A free op with no definition is an arbitrary function; the adversary is a probabilistic program that can call any operator? In EasyCrypt, adversary code can use any operator in scope — even abstract ones, since ops are just uninterpreted functions; the adversary can compute them). Actually for the claim "probability 1", the adversary would need to find a collision — it can if encode is many-to-one and it can compute encode. But whether the model guarantees collisions exist depends on geometry — which is exactly Q2b. Abstractly, there are models where encode is injective, so the collision event isn't probability 1 in all models. The user's phrasing "probability 1" is loose but directionally: seed-withholding has nothing to bite on — correct.

  3. Leg 2: need to check whether the summand at :457 is truly unreduced, and whether MEUFGCMA_WOTSTWESNPRF lemma (:6578) is ever applied anywhere in cdrafts-split (or the deployed theorem) to reduce that term. Grep for `MEUFGCMA_WOTSTWESNPRF` applications in cdrafts-split. Also check whether there's a separate WOTSC-level bound that avoids the base theorem: search for lemmas concluding `Pr[M_EUF_GCMA_WOTSC_NPRF...` in cdrafts-split.

  4. Leg 3: EasyCrypt semantics — I know: qed makes proof opaque; no idiom charges internal proof terms. Repo corroborates (cert_cone.py). I can verify cert_cone.py text.

  5. Q2b: check sphincs-c10 exists in repo? The tree doesn't show sphincs-c10 at top level. The claim cites `sphincs-c10/src/wots.rs:26-45` — likely external. Check with Glob. Also check mdgstblock definition :179-193 (subtype of bool list size 8*n_m), which I partially saw: line 193 `op P x <- size x = 8 * n_m` — need context (the subtype mdgstblock). Let me read :175-200.

  Also check `two_encodings` at :716-732 — is it an axiom? It appeared in proof at 1485 as a lemma used. Read 700-740.

  Also the gate script scratch/spike_wots_admit_gate.sh — check quickly to verify "gated GREEN" claim? The user says it's gated; I can read the script and maybe the latest output file. Since read-only and running easycrypt compile on a scratch file is allowed (it's not cert_gate_split.sh)... but compiling requires easycrypt available. The user says READ-ONLY meaning don't modify files; running a compile is not modifying. But the gate script might write output files. Safer: just read the script and existing output. Actually running `easycrypt compile scratch/wots_admit_is_injectivity.ec` would produce .eco — that modifies the tree. Avoid. Read the gate log if present.

  Let me also verify the claim about `tgt_witness` and `target_sum` at :640-660, and check whether the deployed-geometry constraint `n = 16, w = 8, len = 43` is actually wired anywhere (i.e., Q2b status: is encode_msgWOTS pinned to base-8 digit map anywhere?). Check c10_deployed_encoder_gives_width referenced in GprocQWired:469. And check whether any file defines encode_msgWOTS := extract_digits-like. Grep for `encode_msgWOTS <-` or `encode_msgWOTS :=`... Actually clone with `op encode_msgWOTS <- ...` possible. Search.

  Also for Q4: "does msgWOTS = mdgstblock really make the encoder's domain 2^256 at deployed parameters, or is there a constraint elsewhere that restricts the reachable domain to ≤ 2^129?" At the TW layer, in M_EUF_GCMA_WOTSTWESNPRF the messages are arbitrary msgWOTS (adversary-chosen from full type? the game samples? check the game: adversary queries O.query with m : msgWOTS of its choice — the type is the full 256-bit digest). But at the +C layer, messages reaching WOTS-TW are ThC ps ad m c — outputs of thfc, i.e., elements of... ThC returns msgWOTS via join_dgst of two thfc outputs. The reachable set under +C is at most |dgstblock × cntr| mapped through ThC... but ThC's image could still be all of msgWOTS in principle. Hmm, but the relevant point for Q4: does any constraint restrict reachable domain? P restricts to constant-sum surface of size... number of m with digitsum = target_sum ≤ w^len = 2^129. So the admit only cares about the surface {m | P m}, which has size ≤ 2^129 < 2^256. The collision question is injectivity ON the surface. So the domain argument 2^256 vs 2^129 doesn't by itself refute injectivity on the surface! The surface has at most 2^129 elements and codomain has 2^129 elements, so pigeonhole does NOT forbid an injection on the surface. Wait but L3: the refutation comes from the deployed encoder ignoring top 127 bits: messages agreeing on low 129 bits but differing above map to same codeword. But do such messages lie on the surface? If encode m = encode tgt_witness then digitsum equal, so P m holds — yes! P is a function of the codeword (P_encode_congr). So any m differing from tgt_witness only in the ignored top bits has the same encoding, hence P m, and m <> tgt_witness → refutes. Good, that's the real argument and it's sound GIVEN the deployed encoder really ignores top bits.

  But subtlety: tgt_witness is abstract; the deployed witness needs a concrete m0 agreeing on low 129 bits. Fine.

  Another subtlety for L4/Q4: the claim "2^(8*n_m) = w^len * 2^127" — arithmetic verified in the file (proved). But cardinality of mdgstblock subtype = 2^(8*n_m)? The subtype of bool lists of size 8*n_m — cardinality 2^256 if... yes, number of bool lists of length 256 is 2^256. The file itself admits card instances are not built; the arithmetic is proved, the cardinalities asserted in comments. So the "domain is 2^256" claim is trusted on standard math, verified arithmetic.

  Now, is there a constraint restricting reachable domain? At the TW layer game, m' is adversary-chosen arbitrary msgWOTS — no restriction. At +C layer, messages are ThC outputs — thfc outputs joined; image potentially all of mdgstblock. So no ≤2^129 restriction on the domain; but the P-surface is ≤ 2^129... hmm wait, actually is the surface size ≤ 2^129? P m ⟺ digitsum(encode m) = target_sum. Multiple m map to same codeword; surface = preimage of the set of codewords with that digitsum. Preimage can be huge (up to 2^256) if encoder is many-to-one! So surface size is NOT bounded by 2^129 unless encoder injective. Right — so injectivity on the surface is genuinely the question, and with the deployed 129-bit-reading encoder, surface = 2^127 × (number of length-43 base-8 strings with sum = target_sum) which is ≫ 2^129... anyway collisions exist galore. The argument stands conditionally.

  Now let me check remaining items:
  - read WOTS_TW_ES.ec:620-740 (encode op, tgt_witness, P, two_encodings — axiom or lemma?)
  - read :175-200 (mdgstblock subtype)
  - M_EUF_GCMA_WOTSTWESNPRF game + adv type (~:2280-2420?)
  - grep for applications of MEUFGCMA_WOTSTWESNPRF lemma in cdrafts-split
  - grep for `Pr[M_EUF_GCMA_WOTSC_NPRF` bounds in cdrafts-split
  - check c10_deployed_encoder_gives_width
  - check sphincs-c10 presence
  - read tools/cert_cone.py head
  - read scratch/spike_wots_admit_gate.sh and its latest output

  Let me batch.

• Now the encoder definitions, the TW-layer game/adversary type, and whether the summand is ever reduced elsewhere.

• Big picture emerging. Key items left:

  1. Leg 2's "unreduced summand" claim: the deployed theorem (GprocQWired:457) keeps `Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(...))]` as a raw term. But is there anywhere a reduction `interactive_D1`-style lemma (WOTS_C_Interactive.ec:2325, :3219) that bounds `Pr[M_EUF_GCMA_WOTSC_NPRF] <= Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(A))] + Pr[S_TCR...]`? Yes — lines 2325-2327 show exactly that shape. That's the D1 theorem. And crucially: does anything APPLY `MEUFGCMA_WOTSTWESNPRF` (the base theorem at :6578) to reduce the summand further? The user's Leg 2 says the summand is UNREDUCED in the final bound — verified at GprocQWired:457, it appears as a raw Pr term on the RHS. So the deployed bound still contains the TW forgery probability as an opaque term. Hmm wait — actually that means the deployed theorem's RHS includes an unbounded TW-forgery term; the bound isn't fully reduced to hardness assumptions. That's the user's point: to reduce it you'd apply the base theorem whose proof contains the admit.

  But for Leg 2's circularity claim: "Reducing that summand means applying the base WOTS theorem, which consumes the admit. Circular." The circularity is: you can't use seed-withholding (a +C-layer argument) to discharge the base-layer admit, because the only channel by which the +C layer talks about WOTS-TW forgery is the base theorem itself. Hmm, is that actually circular? To discharge the admit via seed-withholding, you'd need to prove: in the TW game at :6542, the case where encode m = encode m' can't be reached (or handled). The +C observation is that at the +C layer, m = ThC ps ad m0 c is ps-dependent and the adversary doesn't know ps at choose time, so it can't TARGET a collision. But :6542 is inside the base theorem's proof about an ARBITRARY adversary A — including ones that know ps (forge gets ps at :2521!). Wait — at the TW layer, `forge(ps : pseed)` — ps is GIVEN to the adversary at forge time. So at the TW layer there's no seed withholding at all in forge; withholding only applies to choose. And m' is produced by forge, which HAS ps. So even the seed-withholding idea fails structurally at the TW layer: forge receives ps. Actually wait — does that matter? The collision-freedom needed is between encode m' and encode m where m is a choose-time query. The adversary picks queries at choose (without ps) and m' at forge (with ps). Since encode is unkeyed, ps-knowledge is irrelevant to finding encoding collisions anyway. So Leg 1's conclusion stands: at the :6542 site, no ps-dependence between adversary and encode_msgWOTS. VERIFIED: adversary type at :2519-2521 shows forge gets ps; encode_msgWOTS (:624) is a free op of msgWOTS only — VERIFIED no ps parameter.

  2. Question 2: is there a route from +C to the admit NOT through the base theorem? WOTS_C_Bridge.ec is interesting: it builds `R_bridge_WOTSTW` turning an `Adv_MnaCMA_WOTSC` into an `Adv_MEUFGCMA_WOTSTWESNPRF` — a different bridge to the TW game. But any route that lands on `Pr[M_EUF_GCMA_WOTSTWESNPRF(...)]` and then bounds it via the base theorem consumes the admit. A route that avoids the admit entirely would have to bound the +C game without the base TW theorem — e.g., XMSSMT_C_Bridge routes through M_EUF_GCMA_WOTSC_NPRF too. Does any lemma bound M_EUF_GCMA_WOTSC_NPRF directly in terms of THFC/TCR properties without the TW game? The D1 theorem (WOTS_C_Interactive:2325) bounds it by TW-game + S_TCR terms. WOTS_C_Bridge offers an alternative: bound by M_EUF_NACMA_WOTSTW_L (batch naCMA). Line 69: `Pr[M_EUF_NACMA_WOTSTW_L(B)] >= Pr[MEUFGCMA_WOTSTWESNPRF(B-analog)]` — comment. Hmm, WOTS_C_Bridge might reduce to a naCMA notion that still needs... Let me look at WOTS_C_Bridge.ec briefly to see whether it's a completed alternative route that avoids nhchwcoll_hchwpre_msg. Its header at :9-11 says "the black box discharged by MEUFGCMA_WOTSTWESNPRF at WOTS_TW_ES.ec:6269" — so it still treats the base theorem as the black box. So no admit-free route; the bridge is about a different reduction into the same TW game.

  3. Leg 3: EasyCrypt — from knowledge: no idiom to reach inside a qed proof. Section/clone re-instantiation can re-prove lemmas with different op instantiations but that's re-proving, not charging inside. `local` affects name export. Abstract theory refactor requires editing. VERIFIED by EasyCrypt semantics (I can't run easycrypt to demonstrate, but this is definitional: qed seals the proof term; only the statement is exported). The repo itself states this in cert_cone.py:8 — let me read that to quote.

  4. Q2b tension: check whether encode_msgWOTS is pinned anywhere to the deployed digit map. Grep for clone/where encode_msgWOTS instantiated, e.g. `encode_msgWOTS <-` in cdrafts-split/cdrafts-fork. Also check `c10_deployed_encoder_gives_width` in GprocQWired — what does it pin? Let me grep. Also check whether sphincs-c10 directory exists.

  Also check FINDING doc and gate script quickly? The deliverable asks verdicts; the gate GREEN claim — I can check the gate script exists and a recent output log. Let me look at scratch/spike_wots_admit_gate.sh and any output.

  Also Q4: "is there a constraint elsewhere that restricts the reachable domain to ≤ 2^129?" At the TW game, the adversary's m' ranges over all msgWOTS — check M_EUF_GCMA_WOTSTWESNPRF.main (:2527+) and the oracle query: does query accept arbitrary m : msgWOTS? Look at :2527-2600. Also `O_MEUFGCMA_WOTSTWESNPRF.query`. Let me read that region. Also note: in the deployed-geometry capstone (C10DeployedCapstone / GprocQWired), is there a premise like `hencb` constraining the encoder? GprocQWired:468 mentions `henc` hypotheses: `hn hlen hk hcard hemb hc hencb hN2` — `hencb` might be an encoder-related premise! Let me check GprocQWired's lemma statement around :380-430 for what hencb is. If hencb pins encode_msgWOTS to the deployed base-8 digit map, then Q2b might already be wired (partially). Check.

• Two more checks: what the deployed-geometry hypotheses (`hemb`, `hencb`) actually pin, and whether the TW-layer game lets `m'` range over the full wide digest.

• Interesting: there's `scratch/scope_q2b_VERDICT.md` and `scratch/q2b_clonability_measurement.md` — prior work on Q2b. Also `C10DeployedInstance.ec` has a deployed encoder over `bool list` (`c10_digit_at` standalone, NOT wired into `encode_msgWOTS`). And `c10_deployed_encoder_meets_model` — let me read C10DeployedInstance.ec around 380-520 to see what's actually pinned. The PINNED_ENCODER lemma hypothesis at GprocQWired:424-425 is `encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)` — an equality premise carried as hypothesis, not a wiring of encode_msgWOTS to the digit map.

  Key question for the Q2b tension: is `encode_msgWOTS` (the base op) identified with the deployed base-8 digit map anywhere? The grep shows `MODEL_encb_shape : encode_msgWOTS := encode_msgWOTS o ThC` in an audit receipt (a "shape" note), and C10DeployedInstance defines `c10_digit_at` standalone with lemmas about it, but q2b_clonability_measurement.md says the clone with concrete encode is "clonable" but presumably NOT DONE. Let me read that measurement doc and the C10DeployedInstance region.

  Also should check scratch/FINDING-seed-withholding-has-no-isolated-step.md to compare with the claim (it's the user's own finding doc). And tools/cert_cone.py header for Leg 3 corroboration. And check whether sphincs-c10 exists locally: Glob. Also check the wots.rs reference — likely an external checkout not in this repo; if absent, the "reads 129 bits" claim is taken on trust from the repo's own comments (WOTS_TW_ES.ec:34 says "L*LOG_W = 129 bits consumed by extract_digits (wots.rs:16,27-44)").

  Let me read those.

• The prior Q2b measurement docs exist — reading them plus the deployed-instance file and the finding doc.base-c10
base-c10-fork
base-c10-split
cdrafts
cdrafts-fork
cdrafts-split
cert-baseline-split.tsv
cert-baseline.tsv
cert-controls-split.tsv
cert-controls.tsv
cert_gate_fork.sh
cert_gate_run.log
cert_gate_split.sh
cert-identity.tsv
cert-margin-split.tsv
cert-statements-fork.tsv
cert-statements-split.tsv
cert-watched-split.tsv
closure-c10-fork.txt
closure-c10-split.txt
closure-c10.txt
drafts
ec-c10.sh
ec-certify.sh
ec-container-up.sh
ec-goal-fork.sh
ec-goal.sh
ec-r2026.sh
ec.sh
experiments
FV-SPHINCSPLUS-EC
FV-XMSS-EC
_gate10b.raw
_gate10c.raw
_gate10d.raw
_gate10.raw
_gate11.raw
_gate12.raw
_gate13.raw
_gate14.raw
_gate15.raw
_gate16.raw
_gate17.raw
_gate18.raw
_gate19.raw
_gate20.raw
_gate21.raw
_gate22.raw
_gate23.raw
_gate24.raw
_gate25.raw
_gate26.raw
_gate27.raw
_gatef10b.raw
_gatef10c.raw
_gatef10d.raw
_gatef10.raw
_gatef11.raw
_gatef12.raw
_gatef15.raw
_gatef17.raw
_gatef18.raw
_gatef19.raw
_gatef20.raw
_gatef21.raw
_gatef22.raw
_gatef23.raw
_gatef24.raw
_gatef25.raw
_gatef26.raw
_gatef27.raw
_gatef.raw
_gate.raw
_mut2_cdrafts
_mut3_base
_mut3.raw
_mut_base
_mut_cdrafts
_mutkill_closure.raw
_mutkill.raw
_mut.raw
paper-2022-778.pdf
paper2.pdf
paper-cic-2-1-13.pdf
paper-cic-2-1-13.txt
paper-eyalro.pdf
paper-eyalro.txt
paper-nist-pqc2022.pdf
paper-nist-pqc2022.txt
paper-sphincsc-sp2023.pdf
pending-2b-wire
probe2.eco
PROVENANCE.md
scratch
scratch-archive
scratch-ecc.sh
sp2023.txt
tools
wire_test_fork.sh
wire_test.sh
---
ls: cannot access '/home/nicola/repos/c10-eufcma-port/sphincs-c10': No such file or directory
---
ls: cannot access '/home/nicola/repos/sphincs-c10/src': No such file or directory


• sphincs-c10 is not in the repo — the wots.rs claims are taken on trust (from repo comments referencing an external repo). But C10DeployedInstance.ec:370-373 documents the digit extraction reading 129 bits (digit i at bit offset 3i, last digit i=42 reaches bit 128), and `c10_digit_at` is defined over `bool list` with `nth false bs j` for j ≥ size bs returning false — i.e., bits above 256 are read as 0, and bits 129..255 are never read. That is VERIFIED at source in the port (c10_digit_at :382-385, window lemmas :404-411). So "the deployed encoder reads 129 bits and ignores the top 127" is verified in the port's own model of the deployed map; the fidelity of that model to wots.rs is taken on trust (external file not present here), though the repo consistently documents it.

  Important nuance for the Q2b tension / headline claim: the user says "closing residual Q2b would REFUTE the admit's statement." Check: if encode_msgWOTS is pinned to the deployed digit map (reads low 129 bits), then take m0 = tgt_witness with top bit flipped. Then encode m0 = encode tgt_witness, P m0 (since P depends only on encoding), m0 <> tgt_witness → AdmitGoal false. Yes — provided tgt_witness... wait, tgt_witness is a `const tgt_witness : msgWOTS` — abstract constant. Under the clone with the pinned encoder, tgt_witness is still an abstract constant of type mdgstblock (it would remain unsubstantiated unless also instantiated). m0 must differ from tgt_witness only in top bits — m0 exists (flip bit 200 of val tgt_witness, insub back — size preserved). encode m0 = encode tgt_witness since digit map reads only low 129 bits. So yes, under pinning, AdmitGoal is refutable. The scratch file proves the conditional refutation (L3) and the arithmetic (L4). VERIFIED at scratch/wots_admit_is_injectivity.ec:123-142.

  But one caveat the user themselves noted: the scratch file's L4 proves only the arithmetic inequality; cardinality facts (2^256 domain etc.) are standard math, not formalized. Also the "refutation" requires the encoder to be exactly the 129-bit-reading map; Q2b is NOT closed (the missing span per q2b_clonability_measurement.md). So the headline "closing Q2b would refute the admit" is: TRUE as a conditional, and verified in its formal part.

  Now, one potential attack on Leg 1 I should check: is there ps-dependence via `P`? P m = digitsum(encode m) = target_sum — no ps. The caller at :6542 passes ps{2} to the lemma, but the admitted subgoal is ps-free. Also: could the adversary's m' be constrained by freshness m' <> m only? Yes — :2576 is_fresh <- m' <> m, no codeword constraint. So a collision (encode m' = encode m, m' <> m) passes freshness and, if the adversary can produce a valid sig' (e.g. reuse sig of m if encodings equal — indeed if encode m' = encode m, the SAME signature verifies for m'! verify uses encode_msgWOTS m' — check :2568 verify with m'. If encode m' = encode m, then verification of sig' := sig under m' succeeds identically). So at the TW layer, an encoding collision is a TRIVIAL forgery: query m, get sig, forge (m', sig) with same encoding. Probability of winning = probability adversary can find such m' — which, if encode is many-to-one AND the adversary can compute encode... encode is a free op; in EasyCrypt the adversary is arbitrary code parameterized by all operators, so it can compute encode. If encode is many-to-one, adversary wins with probability 1. But the theorem quantifies over all models of the free ops; in models where encode is injective on the surface, no collision exists and the admit is provable. So the admit is exactly "encode injective on surface" — a model assumption. The claim "probability 1" holds in models where collisions exist; abstractly the statement is undischarged. Fine — Leg 1 STANDS as "unkeyed layer; seed-withholding can't bite". VERIFIED: game :2530-2576, adv type :2519-2521, encode op :624, P :654.

  Also note: at the TW layer forge GETS ps (:2560), so even seed-withholding-as-secrecy is absent at forge time. Strengthens the user's claim actually.

  Leg 2: check the exact statement at WOTS_C_Interactive.ec:2325-2327 (the D1 bound) — bounds Pr[M_EUF_GCMA_WOTSC_NPRF] <= Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(A))] + Pr[S_TCR_C_Int...]. And GprocQWired:457 shows the summand remaining on the RHS of the deployed theorem — unreduced. Is the base theorem (MEUFGCMA_WOTSTWESNPRF, :6578) applied ANYWHERE in the certified closure (cdrafts-split)? Grep for applications: search for `MEUFGCMA_WOTSTWESNPRF ` as lemma application, e.g. `apply MEUFGCMA_WOTSTWESNPRF` or `exact (MEUFGCMA_WOTSTWESNPRF` in cdrafts-split. From the grep above, no occurrence of `MEUFGCMA_WOTSTWESNPRF(` without the M_ prefix as a lemma application appeared — all hits are the module M_EUF_GCMA_WOTSTWESNPRF. Let me grep specifically for the lemma name without M_EUF prefix.

  Also verify the claim "sole live caller :6542" — grep showed in base-c10-split only :6542. ✓ (also the fork/base copies, irrelevant).

  Leg 3: I know EasyCrypt has no such idiom. Corroborate with tools/cert_cone.py and scope_fextractop_VERDICT.md perhaps. Read cert_cone.py header.

  Also should I check the FINDING doc to see if the user's claim matches what they wrote? Not strictly needed.

  One more attack angle on Leg 2 (question 2): WOTS_C_Bridge.ec offers a route to M_EUF_GCMA_WOTSTWESNPRF probability from a DIFFERENT adversary notion (Adv_MnaCMA_WOTSC). But it still lands on the TW game prob, which is only boundable via the base theorem. Also its header (:9-11) says it treats the base theorem as the black box. Let me quickly read WOTS_C_Bridge.ec:1-80 to confirm it's not an admit-free alternative bound.

  Also check XMSSMT_C_Bridge (:140, :179-184): bounds batch naCMA by interactive M_EUF_GCMA_WOTSC_NPRF — again routes through the same game.

  Let me do final greps/reads:
  - grep for lemma application of MEUFGCMA_WOTSTWESNPRF in cdrafts-split (word boundary, excluding M_EUF_GCMA).
  - read WOTS_C_Interactive.ec:2300-2340 and 3210-3230 to see the D1 statement shape.
  - read WOTS_C_Bridge.ec:1-80.
  - read tools/cert_cone.py head.
  - check spike gate script existence + recent log.

• Nearly there. Final checks: whether the base theorem is ever applied downstream, the D1 bound's shape, the Bridge alternative, and the repo's own statement on Leg 3.

• Important finding: cert_cone.py says `cdrafts-fork/XmssmtCC_All.ec:8907` APPLIES `MEUFGCMA_WOTSTWESNPRF` — but that's cdrafts-FORK. My grep for applications in the whole repo found none (the grep pattern `apply MEUFGCMA_WOTSTWESNPRF` found no .ec hits!). Hmm — the grep searched the whole repo and found only a .md hit. So maybe XmssmtCC_All.ec applies it differently (e.g. `exact (MEUFGCMA_WOTSTWESNPRF ...)` — my pattern `exact.*MEUFGCMA_WOTSTWESNPRF` should catch that... unless it's applied via `have ... := MEUFGCMA_WOTSTWESNPRF ...` — my `have.*:=` pattern should catch that too. Wait, my grep output shows only one result. Let me check cdrafts-fork/XmssmtCC_All.ec:8907 directly to see how it's applied. This matters for Leg 2's "circular" claim: if the FORK tree already applies the base theorem to reduce the summand, then in the fork the admit IS consumed (as inherited assumption), but the user's claim is about the SPLIT tree and about routing seed-withholding TO the admit. Actually the grep I ran covered the whole repo (no path), pattern with `apply|exact|have|move/`. Zero .ec hits is surprising. Let me verify directly.

  Also for the split tree: is there any application of the lemma `MEUFGCMA_WOTSTWESNPRF` (the final theorem at :6578) anywhere? If the summand at GprocQWired:457 is never reduced by the base theorem in the split tree, then the deployed split theorem carries the unreduced TW term — consistent with the user's "UNREDUCED summand" claim.

  But wait — there's a subtlety for Leg 2's circularity: the claim is "Reducing that summand means applying the base WOTS theorem, which consumes the admit. Circular." The circularity is about using seed-withholding to discharge the admit: to transfer the +C seed-withholding to the :6542 site, you'd need the +C adversary's win probability to be bounded via the reduction R_int_WOTSTW into the TW game, and then analyze the collision case inside the TW proof — which is the admitted spot. That's not literally circular reasoning; it's "the only channel is the base theorem whose proof contains the admit, and you can't inject an argument into it from outside" (which is Leg 3). Fine.

  Let me check XmssmtCC_All.ec:8907 in cdrafts-fork and also whether cdrafts-split has any analogous application. Also check GprocChargedQWired / C10DeployedCapstone to see if the summand remains raw there too (grep showed the Pr[M_EUF_GCMA_WOTSTWESNPRF...] terms as statement text — those are in lemma statements, not applications of the base theorem).

  Also I should double check the claim in the FINDING doc: "Adv_MEUFGCMA_WOTSTWESNPRF has ..." — seed given at forge exactly as +C mirror. Consistent with what I read at :2521.

  One more thing for Q4: the user asks whether any constraint restricts the reachable domain of encode to ≤2^129. At the TW game, m' is arbitrary msgWOTS (full 2^256 type) — verified :2536, :2560; query m : msgWOTS arbitrary (adversary-chosen through O.query — check the oracle query signature quickly: Oracle_MEUFGCMA_WOTSTWESNPRF query takes m : msgWOTS — I haven't verified but it's standard; the caller poses q := nth qs i0 with q.`2 : msgWOTS). No domain restriction. However — the P gate: the fork's game succeeds only if P m /\ P m' (per interactive_D1 comment :2311-2312: "the fork's M_EUF_GCMA_WOTSTWESNPRF succeeds only if P m /\ P m'"). So the game is gated on P. P restricts to the constant-sum surface. Does the surface have size ≤ 2^129? NO — as I noted, the surface is the PREIMAGE under encode of the sum-target_sum codewords; if encode is many-to-one the surface can be much larger (up to 2^256). So no hidden ≤2^129 restriction. The domain stays 2^256; Q4 answer: no such constraint; the user's reading is right. VERIFIED by P's definition (:654) being a function of the codeword only.

  Now check XmssmtCC_All in both trees for the application.

• One loose end: `cert_cone.py` claims `XmssmtCC_All.ec:8907` applies the base theorem — but my application-grep found nothing. Checking both trees directly.

• cdrafts-fork/XmssmtCC_All.ec:8907: `move: (MEUFGCMA_WOTSTWESNPRF (R_int_WOTSTW(...)) _ _ &m)` — the FORK tree DOES apply the base theorem to reduce the summand (consuming the admit as inherited). My earlier grep pattern missed it because it used `move: (` not `move/`. Let me check the split tree for the analogous application.So in the split tree, `XmssmtCC_All.ec:8902` DOES apply the base theorem `MEUFGCMA_WOTSTWESNPRF` to `R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht))` — i.e., there IS a reduced version of the summand in the tree (consuming the admit as inherited assumption). But the DEPLOYED QWIRED theorem at GprocQWired:457 keeps the summand unreduced. So Leg 2's factual claim ("reaches WOTS-TW only via the UNREDUCED summand at GprocQWired:457") is accurate for the deployed/canonical statement; the tree also contains a reduced variant (XmssmtCC_All) that consumes the admit — which supports, not refutes, the claim that reducing consumes the admit.

  Now for Leg 2's deeper question (Q2): is there a route from the +C layer to the admit that does NOT go through the base theorem? The routes to a BOUND on the +C game all pass through either the TW game prob (then base theorem) — or WOTS_C_Bridge's naCMA route which still treats the base theorem as the black box (header :9-11). Also there's an alternative adversary-type refactor sketched in C10DeployedGeometry.ec:944-1006 (COST: the +C reduction stops being an Adv_MEUFGCMA_WOTSTWESNPRF...) — a sketch of a modified reduction, not a completed admit-free route.

  But hold on — the deeper question is whether the +C layer's seed-withholding can discharge the ADMIT (encode injectivity on the surface) at all. The admit is a pure math statement about a free op encode_msgWOTS. Seed-withholding is a probabilistic statement about a game. These are different categories: you cannot prove `forall m m', P m => P m' => m<>m' => encode m <> encode m'` from ANY game-based argument, because it's a universal statement about the encoder function itself. Wait — actually, could you? If you could show "if a collision existed, the adversary would win with probability 1, contradicting the proven bound"... but the bound at the TW layer is exactly what the admit is needed for — circular indeed. And more fundamentally: the TW theorem is proved for ARBITRARY free-op models; in a model where encode has a collision on the surface, the adversary wins with probability ~1 (replay sig), so no security bound can hold in that model — the admit is genuinely a necessary model assumption, not dischargeable by any probabilistic argument at any layer. Seed-withholding at +C changes the distribution of m, m' but the admitted lemma at :6542 is applied INSIDE the base proof to arbitrary A — the reduction R_int_WOTSTW(A) is one specific A, but the base proof's case split must handle the collision case for THAT A too, and the lemma statement is model-level universal. Hmm, but the admit could in principle be discharged by a game hop in the base proof bounding the probability of reaching the collision case — for arbitrary A. For arbitrary A that knows encode (free op, computable), the collision case is reachable with whatever probability A chooses — can't bound it without assuming injectivity or something about encode. So no — the admit is irreducible without a model assumption on encode. That's the real reason there is no isolated unit: it's not (only) a routing problem; it's that the goal is a universal arithmetic statement about a free op, false in some models, true in others, and no game hop can decide it. This strengthens the user's claim rather than refuting it.

  Wait — but is that exactly right? The user's claim is about "seed-withholding" specifically: "there is no isolated one-day seed-withholding unit that discharges the admit; the seed-withholding observation cannot be routed to that admit at all." My analysis: correct, and for an even stronger reason (category mismatch + forge gets ps anyway).

  Now Leg 3: can EasyCrypt charge a term inside a qed-ed proof without editing the file? Answer: No. Section/clone re-instantiation re-proves statements under substitution (a NEW development — as the q2b measurement doc itself found: "a clone yields a second development"). `local` only affects name visibility. There is no reflection into proof scripts. VERIFIED by EasyCrypt semantics knowledge; corroborated by repo's own docs (q2b_clonability_measurement.md:94-99: "It does not make the *existing* closure's encode_msgWOTS be the digit map"). I should be honest: I did not re-verify EasyCrypt semantics by running the tool; this is language-semantics knowledge plus the repo's own measured statement.

  However — one attack on Leg 3: "without editing the base file" — you CAN fork the base file (the repo already does: base-c10-fork, _mut3_base etc. are copies). Leg 3 says "requires editing or forking the base file" — the user concedes forking. So Leg 3 as stated stands.

  Q2b tension verdict: REAL, with one sharpening. Verified components:
  - encode_msgWOTS is a free op (:624) — VERIFIED.
  - P is a definition on codeword (:654) — VERIFIED; hence any same-codeword pair satisfies P both ways (P_encode_congr proved in scratch :68-70).
  - msgWOTS = mdgstblock, subtype of bool lists of size 8*n_m, n_m = 2n (:270, :46, :191-197) — VERIFIED.
  - Deployed digit map reads 129 bits: c10_digit_at (:382-385) reads bits 3i..3i+2 for i<43 → max bit 128; c10_window_bits = 129 proved (:404). Bits 129-255 ignored. VERIFIED in the port's model of the deployed map. The correspondence to actual sphincs-c10/src/wots.rs is taken ON TRUST — that file is not in this repo (verified absent by ls).
  - Q2b not yet wired: encode_msgWOTS remains free; the PINNED_ENCODER capstone carries the identification only as a premise about encode_msgWOTS_C vs encode_msgWOTS∘ThC (GprocQWired:424-425), and c10_digit_at is standalone (q2b measurement doc, C10DeployedInstance comments) — VERIFIED.
  - The refutation conditional: proved in scratch file (L3) — VERIFIED the file content; did NOT re-run the gate (read-only instruction; also can't verify "gated GREEN" myself — I could check the gate script's last output if one exists. Minor; the user's gating claim is plausible but I take it on trust. Actually, let me quickly check whether there's a recent gate output for the spike. The user said scratch/spike_wots_admit_gate.sh. Let me check it exists and if there's an output log. Quick glob.

  One caveat on the headline: "closing Q2b would REFUTE the admit's statement" — precisely: it would refute AdmitGoal PROVIDED the pinned encoder is exactly the 129-bit-reading map AND tgt_witness's codeword has another preimage (which it does: flip any of the top 127 bits — but careful: tgt_witness is an abstract const; its val is some bool list of size 256; flipping bit 129 gives a different list, insub gives different mdgstblock — need val injectivity, standard). Also the flipped message has the same encoding hence P holds. So yes refutable. BUT also note the subtlety: refuting AdmitGoal makes nhchwcoll_hchwpre_msg's STATEMENT... wait, would the base file become "inconsistent-if-completed"? nhchwcoll_hchwpre_msg's full statement: P m => P m' => m<>m' => !has_chwcoll ... => has_chwpre .... If AdmitGoal is false, is the full lemma statement still true? NO — because nhchwcoll_hchwpre (the proved one) plus the false injectivity give it; but the full statement itself: take m, m' a collision pair with sig=sig' honest signature... Actually is the full statement refuted too? has_chwpre ps ad (encode m) (encode m') sig sig' with encode m = encode m' — is that derivable/false? has_chwpre e e' sig sig' means exists i, is_chwpre... If e = e', is_chwpre requires... probably e.[i] digit <> 0 and sig' chain from sig reaches... with sig = sig' and e = e', chain positions coincide — likely has_chwpre false for some choices. The repo's own comment at :1468-1474 says the gap IS the T-COLL-RES event and must be discharged by a game hop; and FINDING doc :135 says "the identification REFUTES nhchwcoll_hchwpre_msg's statement". Hmm — whether the full 5-hypothesis statement is false under pinning requires exhibiting sig sig' with !has_chwcoll and not has_chwpre. Plausible (take sig=sig'=honest sig of m; has_chwcoll? chains identical → no collision positions where digits differ... !has_chwcoll likely holds since is_chwcoll requires digit inequality... with e=e', is_chwcoll i requires val e.[i] < val e'.[i] or something — false everywhere, so !has_chwcoll holds; has_chwpre requires exists i with is_chwpre, which likely requires digit m.[i] <> 0 and sig' chain-preimage at a position determined by digits — with equal digits, the preimage index condition is_chwpre might still hold?? is_chwpre at :1450ish. Not worth fully verifying; the scratch file only claims !AdmitGoal, which is the admitted subgoal — that's the verified part. The "base file becomes inconsistent-if-completed" phrasing: if the encoder is pinned via clone, the clone's nhchwcoll_hchwpre_msg re-proof would... the admit would need discharging; AdmitGoal false means the LEMMA (as stated, the _msg variant) — hmm, the lemma nhchwcoll_hchwpre_msg is derivable from AdmitGoal + nhchwcoll_hchwpre; if AdmitGoal is false, the lemma may still be true or false independently. Being careful: the user's headline says "closing Q2b would refute the admit's statement" — the admit's open goal is exactly AdmitGoal; the scratch file proves collision ⟹ !AdmitGoal. VERIFIED. The stronger "base file inconsistent-if-completed" — depends on the full statement being false; the repo asserts it (FINDING:135) but I haven't verified is_chwcoll/is_chwpre semantics. Actually if the full statement were still true despite !AdmitGoal, the proof would just need a different route. But actually: nhchwcoll_hchwpre_msg statement with sig := sig', ps, ad arbitrary... Let me quickly check is_chwpre/is_chwcoll definitions to settle "refutes the lemma statement" vs "refutes only the open goal". Read :1440-1468.

  Also check FINDING doc briefly? Not necessary.

  Let me read the has_chwcoll/is_chwpre definitions, and check the spike gate script + latest output.

• Two final verifications: the `is_chwcoll`/`is_chwpre` semantics (does pinning refute the full lemma or only the open goal?) and the spike gate's existence/last receipt.-rw-rw-r-- 1 nicola nicola 5498 Aug 12 17:37 scratch/spike_wots_admit_gate.sh
wots_admit_is_injectivity.eco
spike_wots_admit_gate.sh
wots_admit_is_injectivity.ec
_spike_load2.ec
_spike_load.ec
---
scratch/wots_admit_is_injectivity.ec
scratch/wots_admit_is_injectivity.eco


• I have enough. Let me check is_chwcoll/is_chwpre definitions to settle whether the full lemma statement is refuted under pinning, not just the open goal. is_chwcoll appeared at :1439: `is_chwcoll` involves `lt em_emp` (digit inequality) and neq of sig elements. With encode m = encode m', digits equal everywhere → is_chwcoll false everywhere → !has_chwcoll holds for any sig sig'. is_chwpre: need its definition. Let me grep quickly.

  Also there's a .eco file — evidence the spike compiled at some point. Good enough as weak corroboration; the gate script exists.

  Let me grep is_chwpre definition quickly.Both `is_chwcoll` and `is_chwpre` have `BaseW.val em'.[i] < BaseW.val em.[i]` as a conjunct. If encode m = encode m' (em = em'), this is false at every i, so `has_chwcoll` is false and `has_chwpre` is false. Therefore, under an encoding collision, the full statement of `nhchwcoll_hchwpre_msg` — `P m => P m' => m<>m' => !has_chwcoll ... => has_chwpre ...` — is REFUTED by any collision pair (take any sig sig', e.g. sig=sig'; hypotheses hold: P both (same codeword), m<>m', !has_chwcoll (digit-inequality conjunct fails); conclusion has_chwpre false (same conjunct fails)). VERIFIED at :763-817. So under Q2b pinning, the full lemma statement — not just the open goal — becomes false. The "inconsistent-if-completed" headline is correct (with the standard caveat that completing = discharging the admit as stated; the false statement can't be proved in a consistent theory).

  I now have everything. Write the verdict.

  Verdicts:

  LEG 1 — STANDS. Verified:
  - admit at :1513, open goal exactly as claimed (:1505-1514 read).
  - sole live caller in base-c10-split: :6542 (grep whole repo; only copies elsewhere).
  - The caller passes q.`2 (a stored oracle query's message) and m'{2} (forge output) — game at :2530-2576: m' from A.forge (:2560), m from O.get(i) (:2563), freshness only m'<>m (:2576).
  - encode_msgWOTS is a free op on msgWOTS only (:624) — no ps parameter anywhere; P (:654) is digitsum of codeword, no ps. So no ps-dependence at the site. 
  - Sharpening in the user's favor: at the TW layer forge RECEIVES ps (:2521, :2560), so there's no seed-secrecy at all at that layer at forge time; and encode is unkeyed regardless, so ps-knowledge is irrelevant to collision-finding.
  - One imprecision in the user's leg: "the encoding-collision event at that layer has probability 1" is model-dependent — in models of the free op where encode IS injective on the surface, no collision exists. The correct statement is: the admit is exactly the injectivity assumption; where it fails, the win is trivial (replay the queried sig — verify :2568 uses encode m', and equal encodings make sig verify for m'). Doesn't change the verdict.

  LEG 2 — STANDS. Verified:
  - ThC is ps-keyed (:214-216 WOTS_C_Real.ec, thfc applied with ps).
  - Adv_MEUFGCMA_WOTSC withholds ps at choose, grants at forge (WOTS_C_Scheme.ec:141-144); game :183-217.
  - The +C→TW channel is D1: interactive_D1 (WOTS_C_Interactive.ec:2325-2329) bounds the +C game by Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(A))] + S-TCR term.
  - The deployed QWIRED theorem keeps the summand raw at GprocQWired.ec:457-458 — UNREDUCED. Verified.
  - The only reduction of that summand anywhere is applying the base theorem: XmssmtCC_All.ec:8902 (split) does `move: (MEUFGCMA_WOTSTWESNPRF (R_int_WOTSTW(...)) _ _ &m)`. So "reducing consumes the admit" is verified — and the base theorem's proof contains the admit at :6542→:1513.
  - Alternative route check: WOTS_C_Bridge.ec routes a different (naCMA) notion but its header (:9-11) explicitly treats MEUFGCMA_WOTSTWESNPRF as the black box being consumed. XMSSMT_C_Bridge bounds batch notions by M_EUF_GCMA_WOTSC_NPRF — i.e. INTO the same game, not around it. No admit-free route exists in the tree.
  - Stronger reason the claim holds (beyond routing): the admitted goal is a universal statement about a free op; no probabilistic/game argument at any layer can prove it, and in any model where it fails the TW game's bound fails with it (replay forgery). So the admit isn't merely unroutable-to — it's a model assumption that must be discharged by encoder identification (Q2b) or assumed.

  Hmm wait — careful: under Q2b the admit is FALSE. So "discharged by encoder identification" is wrong — under the deployed encoder the admit's statement is refuted, so the real fix is the game hop before the case split (as the file's own comment :1473-1474 says), restructuring the proof so the collision case is bounded probabilistically (T-COLL-RES event). That's where seed-withholding-like arguments COULD live — but inside the base proof, requiring editing (Leg 3). Hmm, actually could the collision case be bounded at all for arbitrary A? For arbitrary A that computes encode, A can deliberately produce collisions with probability 1 — UNLESS in models where collisions don't exist. Wait, but then the theorem would be false in collision-models... unless the theorem is only claimed under Q2b pinning where... collisions DO exist at deployed geometry! So under the deployed encoder, the TW theorem itself — with the current case split — would be unsalvageable? No wait: the game is gated on P m /\ P m' (per the fork's gating; check: does M_EUF_GCMA_WOTSTWESNPRF.main include P conjuncts? I read :2603 partially — "return 0 <= nrqs <= c /\ ..." — the comment at interactive_D1 :2311-2312 says the fork's game succeeds only if P m /\ P m'. So the return includes P m /\ P m'.) Under the deployed encoder with collisions on the surface, the adversary CAN win: query m (grind... wait at the TW layer the adversary supplies m directly — it can pick m on the surface? It needs P m for the win conjunct; it can compute encode and digitsum, so it can find surface messages by grinding its own choices — no ps needed since encode is unkeyed). Then find m' ≠ m with same encoding (exists since encoder ignores top 127 bits — flip a top bit; same digitsum → on surface), replay sig. Win with probability 1. So under Q2b pinning, the WHOLE theorem MEUFGCMA_WOTSTWESNPRF becomes false?! Unless the bound's RHS terms also blow up... The RHS has TCR/OpenPRE terms; a probability-1 win can't be bounded by negligible terms unless those terms are also 1 in that model. Hmm — actually wait: is the replayed forgery detected by has_chwcoll case? In the base proof the case split is on has_chwcoll; with em = em', no chain collision and no chain preimage (digit strict inequality fails), so neither extraction works — the proof NEEDS encode m ≠ encode m'. And the win is real. So under deployed pinning, the base theorem's bound can only hold if one of the RHS probability terms is large — e.g. does the replay forgery yield an OpenPRE/TCR win for the reduction? The reduction extracts... nothing (no chain collision/preimage). So the theorem is genuinely FALSE under deployed pinning? That would mean the whole WOTS-TW bound dies at deployed geometry, not just the admit. But hold on — is that right cryptographically? In real WOTS+C, signing reveals the chain values for m; an m' with the same codeword verifies with the same signature — trivially. Real C10 avoids this how? Because in the deployed scheme, the message signed at the TW layer is ThC(ps, ad, m, c) — ps-keyed and counter-ground; the adversary can't choose the TW-layer message directly; to get a codeword collision it must find (m,c), (m',c') with ThC outputs differing only in top 127 bits — a near-collision attack on ThC costing 2^127-ish. THAT's where seed-withholding bites: the +C layer's TCR/secrecy properties are exactly what prevents codeword collisions. So the REAL discharge of the collision case is: encode-collision on ThC outputs ⟹ structural property of ThC (e.g. a TCR/SPR-style break), which IS a keyed, seed-dependent argument. So seed-withholding IS the right kind of argument — but it must be applied to the reduction R_int_WOTSTW's specific adversary inside a proof, i.e., at the +C layer where messages are ThC outputs, NOT at the generic TW layer where the theorem quantifies over all A and all models and is simply false-in-some-models without the injectivity assumption.

  Hmm — so does this refute Leg 2's "that layer cannot reach down"? The user's leg says the +C layer reaches WOTS-TW only via the unreduced summand, and reducing consumes the admit — circular. My analysis: the correct repair is to prove a STRENGTHENED TW theorem for the specific reduction adversary (or under an assumption about ThC outputs) — i.e., you don't route seed-withholding to the admit; you replace the generic theorem with one whose collision case is bounded by a +C-level hardness term. That's exactly "editing or forking the base file" (Leg 3) plus a new reduction argument. So no isolated one-day unit — the claim STANDS, but the honest next unit is visible: a "WOTS-TW-under-ThC-messages" variant theorem.

  Also this reveals the sharpest objection to the user's overall framing — the claim "seed-withholding cannot be routed to that admit at all" is right, but the deeper finding (which the user half-has) is that the admit is not an isolable gap at all: it's the exact spot where the generic MM45 theorem is UNPROVABLE at deployed geometry, and discharging it requires changing the theorem's statement/setting (gating to ThC-image messages or adding a TCR term), i.e. a base-file edit — consistent with their conclusion.

  Wait, I should double-check the claim that the game return includes P m /\ P m'. Let me verify :2603-2610.

  Also Q4 answer: no constraint restricts the reachable domain to ≤2^129. The P-surface is a PREIMAGE under encode, size unbounded by 2^129 when encode is many-to-one (under deployed map, surface has ~2^127 × #(sum-204 codewords)... whatever, ≫). And the game lets m' range over all msgWOTS (:2536, :2560). So domain genuinely 2^256. VERIFIED.

  Leg 3 — STANDS. EasyCrypt: qed seals proof; only statement exported. No idiom (section/clone/local) reaches inside a proof script. Clone re-instantiation creates a second development (repo's own measurement: q2b_clonability_measurement.md:94-99). I did not re-run EasyCrypt; this is language-semantics knowledge corroborated by the repo's measured docs. One softening: "editing or forking" — forking is cheap and the repo already maintains forks (base-c10-fork, _mut3_base); so Leg 3's practical bite is small: the base file is vendored anyway, and the parallel-and-promote pattern could carry a patched copy. The user's leg says "requires editing or forking the base file" — accurate; but note the repo ALREADY forks routinely, so Leg 3 is the weakest leg: it states a real EasyCrypt fact but its cost implication ("cannot insert from outside a finished qed") is routinely worked around in this very repo by patched copies (experiments/wots-tw-incenc/chain/WOTS_TW_ES.ec is exactly such a patched copy!). So Leg 3 as a statement about EasyCrypt: STANDS. As a claim that the repair is impractical: weaker than presented.

  Q2b tension — REAL, verified in all formal parts:
  - encode free op :624; P def :654; msgWOTS=mdgstblock :270/:191-197; n_m=2n :46.
  - Deployed map reads 129 bits: c10_digit_at C10DeployedInstance.ec:382-385, c10_window_bits :404 (43*3=129). Bits 129..255 unread. VERIFIED in port's model; fidelity to actual wots.rs taken ON TRUST (sphincs-c10 not in this repo — checked, absent).
  - Full lemma statement refuted under collision: is_chwcoll and is_chwpre both conjunct `val em'.[i] < val em.[i]` (:765, :810) — with em=em' both false everywhere, so !has_chwcoll true and has_chwpre false; P m' holds by same codeword. So any collision pair refutes the full 5-hypothesis statement, not just the open goal. VERIFIED at :763-817. This strengthens the user's headline ("inconsistent-if-completed") from plausible to verified-modulo-pinning.
  - Q2b currently unwired: encode_msgWOTS free; PINNED_ENCODER capstone carries only encode_msgWOTS_C = encode_msgWOTS∘ThC as premise (GprocQWired:424-425); c10_digit_at standalone. VERIFIED.
  - The scratch file proves what the user says (L1, L1s, L2, L3, L4-arithmetic) — I read all 190 lines; proofs are short and look correct; I did NOT re-run the gate (read-only instruction; .eco artifact exists, dated). The gate GREEN claim: taken on trust, weakly corroborated by the presence of wots_admit_is_injectivity.eco.
  - One over-read to flag in the user's headline: L4's cardinality framing (domain 2^256 vs codomain 2^129) is NOT what refutes injectivity-on-the-surface (the surface could a priori be small); the refutation needs the specific 129-bit-read structure (L3's witness), which the user does say. Fine. Also the scratch file itself honestly records that card instances aren't built (:150-155).

  Strongest single objection: Leg 3 is load-bearing for the "no isolated unit" conclusion but is the weakest leg — EasyCrypt opacity of qed is real, yet this repo routinely maintains patched copies of the base file (experiments/wots-tw-incenc/chain/, base-c10-fork, _mut3_base), and cert_gate_split already pins statements across such copies. So "cannot insert a game hop from outside a finished qed" is true of the mechanism but does NOT imply "no one-day unit": the unit "fork base file, add the T-COLL-RES game hop before the case split, re-gate" is exactly the kind of unit this repo has executed repeatedly (the wots-tw-incenc experiment did precisely the statement-weakening variant). What makes the unit hard is not Leg 3's opacity — it's that the hop's content (bounding the collision event) is FALSE for the generic adversary at the TW layer (Leg 1) and only becomes true relative to ThC-image messages at the +C layer (Leg 2) — i.e. the repair requires changing what's proved (a ThC-image-restricted TW theorem or an added TCR(+C) term), not merely finding a tactic slot. The user should reframe: the admit is not a gap IN a proof; it's a point where the theorem-as-stated is false at deployed geometry (given Q2b), so the cheapest genuinely useful next unit is the one their FINDING doc already implies: prove, in the parallel track, the refutation conditional end-to-end — i.e. close Q2b in a CLONE (the measured 12-obligation route), and inside that clone derive !AdmitGoal from an exhibited top-bit-flip witness. That converts "the admit must be removed before wiring" from a derived headline into a gated receipt, and it forces the real design decision (replace the generic TW theorem with a ThC-image-gated one) into the open.

  Hmm wait — is "refute in a clone" actually achievable in one day-ish? The clone with concrete encoder requires re-proving obligations; two_encodings re-proves (it's a lemma now). AdmitGoal's negation: exhibit m0 = flip-top-bit(tgt_witness)... but tgt_witness is an abstract const in the theory; in the clone it remains abstract unless realized. encode_msgWOTS m0 = encode tgt_witness requires knowing digits computed from low 129 bits — true for ANY tgt_witness since the map ignores top bits. m0 <> tgt_witness needs val_inj on the subtype and bit 129 flip changing the list — provable. P m0 via P_encode_congr analog. So yes, a clean conditional refutation in the clone. That's a genuinely useful, cheap-ish next unit.

  Also should I double check the P-conjunct claim in the game return? The interactive_D1 comment says the fork's game succeeds only if P m /\ P m'. Let me verify quickly at :2603-2615 to not state it unverified... Actually it's a minor supporting detail. I'll cite it as: game return includes P conjuncts — from interactive_D1 comment (trusted) — or verify. It's one read; do it. Actually I've done a lot of tool calls; one more quick read is fine and cheap. But my reply doesn't strictly need it: for Leg 1 the relevant facts are verified. The P-gating matters for the "replay forgery wins with prob 1" argument — the adversary must make m, m' both on surface. It can (unkeyed encode computable). I'll state it as verified-via-comment? No — better verify. Quick read of :2603-2615.

• One last check — whether the TW game's win condition actually includes the `P m /\ P m'` conjuncts.

• All verified. Write the final answer. Be blunt, give verdicts per leg with sources, verdict on Q2b, strongest objection, and cheapest useful next unit. Mark VERIFIED vs trusted for each load-bearing statement.

• # VERDICT

  ## LEG 1 — STANDS

  Every load-bearing fact VERIFIED at source:

  - The admit is at `base-c10-split/WOTS_TW_ES.ec:1513`; the open goal after `apply nhchwcoll_hchwpre` is exactly `encode_msgWOTS m <> encode_msgWOTS m'` under `P m`, `P m'`, `m <> m'` (`:1505-1514`).
  - Sole live caller in the split tree: `:6542` (repo-wide grep; every other hit is a fork/copy/experiment). It passes `q.`2` (a stored oracle query, posed at `:6541` from `O_MEUFGCMA_WOTSTWESNPRF.qs{2}`) and `m'{2}` (the forgery).
  - The game (`:2530-2605`): `m'` comes from `A.forge` (`:2560`), `m` from `O.get(i)` (`:2563`), freshness is only `m' <> m` (`:2576`) — no codeword constraint.
  - `encode_msgWOTS` is a **free op on `msgWOTS` alone** (`:624`) — no `ps` parameter exists for it to depend on. `P` (`:654`) is `digitsum (encode_msgWOTS m) = target_sum` — also `ps`-free.

  So there is no `ps`-dependence between adversary and encoder at `:6542`. None is *possible* — the encoder's type forbids it. Two sharpenings in your favor, both VERIFIED: at the TW layer `forge` **receives** `ps` (`:2521`, `:2560`), so there is no seed secrecy at forge time at all; and if `encode m' = encode m`, the queried signature replays verbatim (`verify` at `:2568` keys only on `encode_msgWOTS m'`), so the collision case is a trivial win, not a hard one.

  One imprecision, not fatal: "collision event has probability 1" is model-dependent. `encode_msgWOTS` is a free op; injective-on-surface models exist (your own scratch file says this, `:27-34`). Correct statement: the admit *is* the injectivity assumption; where it fails, the win is trivial.

  ## LEG 2 — STANDS

  VERIFIED:

  - `ThC ps tw m c` applies `thfc ... ps ...` twice — `ps`-keyed (`WOTS_C_Real.ec:214-216`).
  - `Adv_MEUFGCMA_WOTSC` withholds `ps` from `choose`, grants it at `forge` (`WOTS_C_Scheme.ec:141-144`); game at `:183-217`.
  - The only +C→TW channel is D1: `interactive_D1` (`WOTS_C_Interactive.ec:2325-2329`) bounds the +C game by `Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(A))] + S-TCR term`, and the deployed QWIRED theorem carries that summand **raw** at `GprocQWired.ec:457-458`. UNREDUCED — VERIFIED.
  - The only reduction of that summand anywhere in the tree is applying the base theorem: `XmssmtCC_All.ec:8902` does `move: (MEUFGCMA_WOTSTWESNPRF (R_int_WOTSTW(...)) _ _ &m)` — whose proof contains the admit. "Reducing consumes the admit" is VERIFIED, and your "circular" framing is accurate.
  - Alternative-route check (your Q2): `WOTS_C_Bridge.ec` routes a *different* (naCMA) notion but its own header (`:9-11`) names `MEUFGCMA_WOTSTWESNPRF` as "the black box discharged" — same dependency. `XMSSMT_C_Bridge.ec` bounds batch notions *by* `M_EUF_GCMA_WOTSC_NPRF` — into the same game, not around it. No admit-free route exists in the tree.

  Stronger than your leg, and this is the part your framing keeps circling: the admitted goal is a **universal statement about a free op**. No game argument at any layer can prove it, and in any model where it fails the TW bound fails with it (replay forgery, above — and the win condition does include `P m /\ P m'`, VERIFIED `:2603-2605`, which the adversary satisfies unaided since `encode` is unkeyed and computable by it). Seed-withholding is the *right kind* of argument cryptographically — but it applies to `ThC`-image messages, i.e. to a *strengthened* TW theorem for the reduction's specific adversary, not to the generic one. That is a statement-level change, which is exactly why no routing exists.

  ## LEG 3 — STANDS (but it's your weakest leg)

  EasyCrypt semantics: `qed` seals the proof term; only the statement is exported. No section/clone/`local` mechanism reaches inside a proof script. Clone-with-realization yields a *second development* — your own measurement doc says this verbatim (`scratch/q2b_clonability_measurement.md:94-99`). This is language knowledge I did not re-verify by running the tool; corroborated by the repo's measured docs (VERIFIED as repo statements, TRUSTED as tool behavior).

  Why it's weak: your conclusion is "requires editing or forking the base file" — and this repo forks the base file *routinely* (`base-c10-fork`, `_mut3_base`, `experiments/wots-tw-incenc/chain/WOTS_TW_ES.ec` — the last being exactly a patched-statement copy with a shadow canary). The gate already pins statements across such copies. So Leg 3's mechanism-fact is true, but it does not by itself make the unit hard. What makes the unit hard is Legs 1+2: the hop's *content* is false for the generic TW adversary. Don't lean on Leg 3 in the write-up; it reads as an excuse, and a reviewer will swat it with the incenc experiment.

  ## Q2b tension — REAL, and stronger than you stated

  VERIFIED at source: `n_m = 2*n` (`:46`); `msgWOTS = mdgstblock`, subtype of `bool list` of size `8*n_m` (`:270`, `:191-197`); the deployed digit map `c10_digit_at` reads bits `3i..3i+2` for `i < 43`, i.e. exactly the low 129 bits, `c10_window_bits` proves `43*3 = 129` (`C10DeployedInstance.ec:382-405`); `encode_msgWOTS` is still free and Q2b unwired — the PINNED_ENCODER capstone carries only `encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)` as a *premise* (`GprocQWired.ec:424-425`), and `c10_digit_at` is standalone.

  Your Q4 answer: **no constraint restricts the reachable domain to ≤ 2^129.** `m'` ranges over the full `msgWOTS` type (`:2536`, `:2560`), and the `P`-surface is a *preimage* under `encode` — under a many-to-one encoder it is *larger* than the codeword count, not smaller. VERIFIED from the definitions.

  The strengthening you missed: pinning refutes not just the open goal but the **full five-hypothesis lemma statement**. Both `is_chwcoll` and `is_chwpre` carry the conjunct `BaseW.val em'.[i] < BaseW.val em.[i]` (`:765`, `:810`). Under a collision (`em = em'`) that conjunct fails at every index, so `!has_chwcoll` holds and `has_chwpre` fails — any collision pair, any `sig sig'`, refutes the whole statement. VERIFIED at `:763-817`. So "the base file becomes inconsistent-if-completed under the identification" is not over-read; it is verified modulo the pinning itself.

  Taken ON TRUST: fidelity to `sphincs-c10/src/wots.rs` — that repo is **not present** here (checked); the port's model of it is verified, the correspondence is not. Also the gate-GREEN status of your spike: the `.eco` artifact exists and I read all 190 lines (proofs are short and correct-looking), but per your read-only instruction I did not re-run the gate.

  ## Strongest objection

  Your framing — "the admit cannot be discharged by an isolated unit" — is right for the wrong stated reason, and one clause is just wrong: "the seed-withholding observation cannot be routed to that admit **at all**." It can, but only as a *theorem replacement*, not a proof patch: gate the TW statement to `ThC`-image messages (or add a TCR(+C) collision term), where withholding `ps` from `choose` genuinely bounds the codeword-collision event. That is precisely the real C10 mechanism — the deployed encoder's collisions are unreachable only because the adversary can't target `ThC` outputs without `ps`. So the admit isn't an unlucky gap in a finished proof; it's the exact point where the *generic* MM45 theorem is false at deployed geometry. Say that instead — it's a stronger, more quotable finding than "no one-day unit exists."

  ## Cheapest genuinely useful next unit

  Close the refutation conditionally, end-to-end, in a clone — the route your own measurement already priced (12 obligations, geometry half proved at `C10DeployedInstance.ec:62-67`):

  1. `clone WOTS_TW_ES as PINNED with op encode_msgWOTS <- <129-bit digit map> proof *`, realize the obligations.
  2. Inside the clone: `m0 :=` top-bit-flip of `val tgt_witness`, prove `m0 <> tgt_witness` (subtype `val_inj`), `encode m0 = encode tgt_witness` (map ignores bits ≥ 129), hence `!AdmitGoal` via your `admit_refuted_by_witness`, and the full-statement refutation via the `:765/:810` conjunct.

  That converts "the admit must be removed BEFORE the identification is wired" from a derived headline into a gated receipt, and it forces the actual design decision — the `ThC`-image-gated replacement theorem — into the open, where it belongs.

To resume this session: kimi -r session_90146463-e025-4a30-97d1-f2397165e5ec
