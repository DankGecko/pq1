kimi version 0.36.0
• This is a research/audit task. Read-only. I need to investigate:

  1. Whether the certified EUF-CMA statement covers bootstrap key (single keypair vs multi-key/multi-chain).
  2. Whether adding statement pins for D1_reduce is false comfort while WOTS_C_Bridge is RED.
  3. Rank next units.
  4. Strongest objection.

  This is a big investigation. I should delegate parallel explore agents, but I also need to verify specific claims myself. Let me plan:

  - Q1a: Search cdrafts-split/ and base-c10-split/ for how queries are counted (c, p_tgts), whether the model is single-key, whether anything quantifies over multiple keypairs/chains. Also check the PQSigner_OS repo: domain/src/lib.rs:411, contracts/smart-wallet/src/PQSmartWallet.sol:449-453, Lean Quantitative.lean:172-185.
  - Q1b: identify which of the four terms degrades under multi-target reuse. Terms: M_EUF_GCMA_WOTSTWESNPRF, S_TCR_C_Int_MA, PKCOC_TCR.SM_DT_TCR_C, TRHC_TCR.SM_DT_TCR_C. SM_DT_TCR = "single/multi-target"? Need to look at definitions.
  - Q1c: search for scope restriction documentation.
  - Q2: read cert_gate_split.sh:33, the pins mechanism, WOTS_C_Bridge status.
  - Q3: look at the candidates.

  Also compile-test anything cited from experiments/ — I may not need to cite from experiments/ at all, but the disj_wgpidxs step in WOTS_C_Bridge is in cdrafts-split. The user said do not run cert_gate_split.sh (container-only). Can I compile individual .ec files with easycrypt? Check if easycrypt is available on host. The user says WOTS_C_Bridge measured at r2026.02 does not compile — I can take that as given; maybe I can re-run a quick compile to verify if easycrypt is available locally. r2026.02 is a container version though. Let me check.

  Strategy: launch several parallel explore agents:

  1. Agent A: Q1a/Q1c — does the c10-split formalization model a single keypair; where is adversary query counting (c, p_tgts); search for any multi-key/bootstrap/multi-chain notion; check the capstone statement SphincsC10CapstoneWired.ec:595-604 and the EUF-CMA game definitions.
  2. Agent B: Q1b — the four terms' definitions: what M_EUF_GCMA_WOTSTWESNPRF is, S_TCR_C_Int_MA, SM_DT_TCR_C for PKCOC and TRHC; single-target vs multi-target; how the c <= p_tgts premise threads; whether multi-chain reuse of one key hits which term (likely the multi-target TCR terms SM_DT_TCR_C — "SM_DT" = single-message? multi-target? Need facts).
  3. Agent C: PQSigner_OS repo — verify lib.rs:411, PQSmartWallet.sol:449-453, Quantitative.lean P14; how bootstrap key is used for Type-1; cross-chain budget.
  4. Agent D: gate mechanics — cert_gate_split.sh:33, EXPECT_PINS, how pins work, closure-c10-split.txt, whether D1_reduce is gated, WOTS_C_Bridge status, what the gate receipt would say.

  Then I synthesize. Also I should verify some key lines myself for VERIFIED citations (file:line). Explore agents can report file:line citations; I can spot-check the load-bearing ones.

  Q1b requires understanding: the four terms. "SM_DT_TCR_C" — in SPHINCS+ formalization by the original authors (FV-SPHINCSPLUS-EC), there are SM_DT_TCR (single-message, distinct-target tweakable TCR?) Actually in the original SPHINCS+ EC proof: SM-DT-TCR = "single-message distinct-target target collision resistance". The security reductions: EUF-CMA of SPHINCS+ reduces to EUF-CMA of WOTS+TW (or EUF-NACMA?), SM_DT_TCR of PKCOC and TRHC hash functions, TCR of underlying, ITSR, etc.

  The multi-chain question: bootstrap key used across chains — each chain has its own... what? The hash addresses? If the same SPHINCS+ key signs Type-1 authorizations on multiple chains, the queries increase per chain, so total q = C * per-chain. If the model counts c (adversary queries) against p_tgts, and the reduction bounds things in terms of c, then using the same key across chains just multiplies the number of queries — which is captured by c (query count) as long as the adversary's queries are all to the same keypair. Actually the model is single-key with q queries; multi-chain doesn't create multiple keys, it's the SAME key with more queries. So the statement covers it as long as c counts total queries across all chains. But the per-chain cap enforcement means the cap on-chain is per-chain, so total uses can be C * MaxBootstrapUses — which the Lean P14 already notes. The certified bound is per-query-count; the degradation is that the effective security bound's query count is larger by factor C. Which term degrades? The terms linear in query count... The WOTS EUF term M_EUF_GCMA... with q queries, WOTS+ security has factor related to q. The SM_DT_TCR terms with p_tgts distinct targets — p_tgts = number of targets = number of queries. So all terms degrade linearly-ish. But the real question: is the slot/bootstrap distinction absent from the model? Almost surely yes — the model has one keypair, one adversary, q queries. Bootstrap is just more queries to the same key, so the statement DOES cover it mathematically (same keypair!), but the *budget claim* "capped at 65536 uses" is false for bootstrap across chains — the model's c would need to count cross-chain total, and the on-chain cap only caps per-chain. So it's a scope/documentation question: the model covers any number of queries to one key; the artifact that fails is the *cap* (an external assumption about c's bound), not the reduction.

  Q1d: likely documentation/scope. The model quantifies over c; the system assumes c < 65536 enforced on-chain; for bootstrap that's wrong by factor C. That's not a proof gap — the probability bound is still valid for the actual c — but the claimed concrete security level degrades because c is actually C*larger. Honest answer: the statement covers the bootstrap key as a mathematical object (same keypair, queries counted by c), but the *bound's instantiation* with per-chain cap is unsound; the fix is documentation + setting the cap/budget correctly. Which term degrades: all terms monotone in q/p_tgts, but specifically the ones with factor q. Need facts from the files.

  Let me dispatch agents. I'll do 4 explore agents in parallel with thorough level. Actually AgentSwarm or individual Agent calls — individual calls fine, in one block.

  Also I might verify compile-ability: check if easycrypt is available on host: `which easycrypt`. The user says container-only r2026.02 for the gate script; compiling individual files may still work if easycrypt is installed. Let me check quickly.

  Let me also personally read the capstone statement lines and a couple of key files to ground citations.

  Plan:
  1. Quick host checks (which easycrypt; ls key files).
  2. Launch 4 explore agents in parallel.
  3. Spot-verify load-bearing citations myself.
  4. Write the verdict.

  Let me start with the parallel agents plus a couple of my own reads.

• I'll investigate this across both repos. Let me start with a quick environment check and then dispatch parallel exploration agents on the four sub-questions./home/nicola/.opam/checkct/bin/easycrypt
Error: easycrypt: unknown option '-version'.

Usage: easycrypt [command] [options...] [args...]
2026-07-21-183319-this-session-is-being-continued-from-a-previous-c.txt
2026-07-21-230737-this-session-is-being-continued-from-a-previous-c.txt
aa
AGENTS.md
assets
bip39
Cargo.lock
Cargo.toml
CLAUDE.md
config
contracts
dbgen
deny.toml
DIY.md
docs
domain
FIRMWARE_AUDIT_INTAKE.md
flake.lock
flake.nix
fsbl


• The task is read-only, so no changes needed, but I should read PQSigner_OS/AGENTS.md before working there. Let me read it, and dispatch the parallel explore agents.

• Reading the PQSigner_OS AGENTS.md, then dispatching parallel exploration agents.

• Read-only task; I'll be careful not to modify anything in PQSigner_OS. Now dispatch parallel explore agents. I'll launch 4 agents:

  1. **Agent A (Q1a/Q1c, EC side)**: In c10-eufcma-port `cdrafts-split/` and `base-c10-split/`: does anything quantify over multiple keypairs / chains / "bootstrap"? How are adversary queries counted (`c`, `p_tgts`)? Is the EUF-CMA game single-keypair? Where is the signing query cap (65536) mentioned, if anywhere? Is any scope restriction written down (header comments of capstone, EUFCMA_C10 module definition)? Deliver file:line citations.

  2. **Agent B (Q1b, terms)**: Define the four carried terms precisely: find definitions of `M_EUF_GCMA_WOTSTWESNPRF`, `S_TCR_C_Int_MA`, `SM_DT_TCR_C` (PKCOC and TRHC), the query-count parameters (`c`, `p_tgts`), and the `D1_reduce` theorem in `cdrafts-split/WOTS_C_Multi.ec:488` with its `c <= p_tgts` premise. How does q (number of signing queries) enter each bound — which terms scale with q? What does SM_DT_TCR mean (multi-target TCR?). Deliver file:line citations.

  3. **Agent C (PQSigner_OS side)**: Verify `domain/src/lib.rs:411`, `contracts/smart-wallet/src/PQSmartWallet.sol:449-453`, `contracts/verification/lean/SphincsCVerify/Crypto/Quantitative.lean:172-185` (P14). How bootstrap key is used for Type-1 slot-registration; whether the same SPHINCS+ keypair is reused across chains; what slotUses cap does; whether hash-address/domain separation differs per chain. Deliver file:line citations. Read-only.

  4. **Agent D (gate mechanics, Q2)**: Read `cert_gate_split.sh` (find it — probably in repo root or tools/), `closure-c10-split.txt`, how EXPECT_PINS and statement pins work, whether D1_reduce/WOTS_C_Multi are gated, status of WOTS_C_Bridge in the closure (is it in closure-c10-split.txt or not?), what the gate receipt reports. Also check `WOTS_C_Reduction.ec:338-345` "remaining structural reconciliation" FC<->STCRC_WC.Col. Deliver file:line citations.

  Also maybe agent for Q3 disj_wgpidxs in WOTS_C_Bridge — what the failing step is. Could fold into D or B. I'll fold the disj_wgpidxs question into Agent B or a 5th agent. Let me fold it into Agent D's scope? Better: agent B handles WOTS_C_Multi + WOTS_C_Bridge chain since it reads those files anyway.

  I'll launch all four in one block with subagent_type=explore, thorough.

• Read-only understood; I'll only read in PQSigner_OS. Now dispatching four parallel exploration agents.

• Excellent, comprehensive results. Now let me spot-verify a few load-bearing citations myself, especially:

  1. The PQSigner_OS facts (lib.rs:407-411, PQSmartWallet.sol:447-455, Quantitative.lean:172-187, 219-226).
  2. The key EC facts: WOTS_C_Multi.ec:523 (D1_reduce), closure-c10-split.txt lines 7 and 17, cert_gate_split.sh:33 EXPECT_PINS, WOTS_C_Multi.ec:949 D1_MEUFNACMA_WOTSC (so the pin can target the closure member), PTgtsPin.ec:287-327 (but that's in experiments/ — the user said compile-test anything cited from experiments/. Hmm — I cite it as evidence that the model lacks the cap. Do I need to compile-test it? The instruction: "Compile-test anything you cite from experiments/: several files there are stale, and Extraction.ec does not compile." If I cite PTgtsPin.ec claims (e.g., that it proves !(c <= 65536)), I should compile-test it. Alternatively, I can avoid leaning on it — treat it as corroborating note, marked as an experiments/ file that I either compile-test or downgrade. Let me try compiling it quickly. Easycrypt is available on host at ~/.opam/checkct/bin/easycrypt. Compile-test would need the right include paths (easycrypt.project). Let me check how long it takes; the file might take a while. Try with timeout.

  Actually the load-bearing claims for Q1 are:
  - Single-keypair game: EUFCMA_C10 = DSSC.Stateless.EUF_CMA(...) at FxChain.ec:255-256; stdlib game calls keygen once. Let me verify FxChain.ec:255-256 and scratch/lensA/DigitalSignatures.eca:1484-1525 (or better the actual stdlib path). The scratch copy is fine to cite as a byte-copy, but better to cite the actual stdlib. Let me check the real stdlib file: ~/.opam/checkct/lib/easycrypt/theories/crypto/DigitalSignatures.eca or similar.
  - No bootstrap/multi-chain notion: grep zero hits — I can re-run the grep myself quickly.
  - c and p_tgts definitions: base-c10-split/WOTS_TW_ES.ec:78-79, cdrafts-split/WOTS_C_Real.ec:339-340.
  - Capstone premise c <= p_tgts at SphincsC10CapstoneWired.ec:526/865.
  - Four terms coefficient 1 at XmssmtCC_All.ec:8583-8592.
  - The hypertree game signs exactly l = 2^h messages (XmssmtCC_All.ec:350-356, FL_SL_XMSS_MT_ES.ec:73). This is important for Q1b: exceeding 2^h queries is outside game expressiveness. Wait — for C10, is h such that 2^h = 65536? Probably the deployed geometry C10DeployedGeometry sets things. Not crucial.
  - Uncapped O_CMA.sign in R_top at XmssmtCC_All.ec:9592-9621.

  For Q2:
  - cert_gate_split.sh:33 EXPECT_PINS=111; pins via stmt_digest.py textual; pin of D1_reduce can target WOTS_C_Multi.ec:523 (in closure, compiles); the pin doesn't require compiling WOTS_C_Bridge. And "D1_MEUFNACMA_WOTSC" exists in WOTS_C_Multi.ec:949 (closure member) — so both pins can be on the gated, compiling file. That changes the Q2 analysis: the planned pins do NOT pin anything in the red file. But wait — user said "statement pins for D1_reduce and D1_MEUFNACMA_WOTSC". Both exist in WOTS_C_Multi.ec. So the pins are honest about the file they're in. The false-comfort question: does pinning D1_reduce's statement (with c <= p_tgts premise) buy a green check on a chain whose second link doesn't compile? The gate receipt doesn't claim the D.1 chain is complete; but would a reader conclude more? The bridge is not in the closure, so the gate says nothing about it. The pin verifies the statement text of a compiling, gated theorem. That's honest as long as the receipt/notes don't claim the bridge. Actually there's a subtlety: is D1_reduce even *used* by the certified capstone chain? Agent B said the wired capstone uses the interactive component theorem (WOTS_C_Interactive + XmssmtCC_All), not the bridge. And D1_reduce — is it used by anything in the closure? WOTS_C_Multi.ec:949 D1_MEUFNACMA_WOTSC — used by WOTS_C_Bridge (not in closure) and... does anything in the closure use D1_reduce? If D1_reduce and D1_MEUFNACMA_WOTSC are dead code within the gated closure (only consumed by the red bridge), then pinning them guards statements on a chain whose only consumer is red — mild false comfort, but the pins themselves are accurate. Need to check usage. Let me grep.

  Also Q3: rank candidates. The FC<->STCRC_WC.Col reconciliation is exactly what WOTS_C_Bridge attempts (agent B §5) — so (i) and (ii) are the same work essentially: repairing the bridge IS the reconciliation. Interesting.

  Let me now spot-verify key citations myself with parallel reads/greps. Priority list:

  1. FxChain.ec:250-260 (EUFCMA_C10 def).
  2. Real stdlib DigitalSignatures.eca EUF_CMA game body — find it under opam.
  3. base-c10-split/WOTS_TW_ES.ec:76-82 (c const).
  4. cdrafts-split/WOTS_C_Real.ec:336-356 (p_tgts, p_stcr wiring).
  5. cdrafts-split/WOTS_C_Multi.ec:519-533 (D1_reduce) and :940-960 (D1_MEUFNACMA_WOTSC, and header note about bridge).
  6. closure-c10-split.txt full read (33 lines — quick).
  7. cert_gate_split.sh:30-40 (EXPECT_PINS).
  8. grep bootstrap/multi-chain/65536 in cdrafts-split base-c10-split.
  9. XmssmtCC_All.ec:8529-8600 (component theorem conclusion) — at least :8583-8592.
  10. PQSigner_OS: domain/src/lib.rs:400-415 and :520-530; PQSmartWallet.sol:447-455; Quantitative.lean:170-190, 219-226.
  11. Grep usage of D1_reduce / D1_MEUFNACMA_WOTSC in closure files.
  12. experiments/ptgts-pin/PTgtsPin.ec:287-327 — read; decide whether to cite. If cited, compile-test.

  That's a lot; batch them. Let me do reads in parallel.cdrafts-split/FORS_C10.ec:87:   at C10's 2^16 per-chain cap the reduction's game has 2^27 registered targets.
---
trap 'rm -rf "$TMPD"' EXIT
# Expected inventory sizes, COMMITTED. A guard that recomputes its expectation
# from the file it is checking cannot detect truncation of that file.
EXPECT_PINS=111
# COMMITTED WATCHED-ROW COUNT (2026-08-10).  This replaced a `-ge 3` floor when
# T1/T2/T3 were PROMOTED into closure-c10-split.txt: a floor cannot express
# "there are deliberately none left", so retiring the last watched row would
Verified: FxChain.ec:255-256, D1_reduce at WOTS_C_Multi.ec:523 (user said 488 — stale), D1_MEUFNACMA_WOTSC at :951 (in the closure member, not the bridge), closure list (WOTS_C_Multi line 7, capstone 17, bridge absent), EXPECT_PINS=111 at line 33, grep: only one "per-chain" hit in FORS_C10.ec:87 (comment), zero bootstrap/65536/multi-chain.

  Important new fact from the header at WOTS_C_Multi.ec:942-949: the file itself already documents that the bridge is absent from closure and doesn't compile, and that nothing in WOTS_C_Multi discharges the FC<->STCRC_WC.Col unification — "the bound below is over the LOCAL WOTS-TW game only." That's highly relevant for Q2: the local file is already honest. So pinning D1_reduce and D1_MEUFNACMA_WOTSC pins statements in a compiling closure member that itself carries a written caveat about the red downstream file.

  But wait — is D1_MEUFNACMA_WOTSC (or D1_reduce) used anywhere in the gated closure? The capstone goes through WOTS_C_Interactive/XmssmtCC_All per agent B. Let me grep usage.

  Also verify:
  - c const at base-c10-split/WOTS_TW_ES.ec:78-79
  - p_tgts at WOTS_C_Real.ec:339-340
  - capstone premise c <= p_tgts at :526/:865
  - XmssmtCC_All.ec:8583-8592 component theorem conclusion
  - PQSigner_OS three citations
  - PTgtsPin.ec — decide on citing; if cite, compile-test.

  Also need to check the stdlib DigitalSignatures.eca EUF_CMA game. Find actual path: probably /home/nicola/.opam/checkct/lib/easycrypt/theories/crypto/DigitalSignatures.eca.

  Let me batch.cdrafts-split/SPHINCS_C_c10.ec:13:         XMSS-MT EUF-NAGCMA term)             (D1_MEUFNACMA_WOTSC_MM45_embthfc,
cdrafts-split/SPHINCS_C_c10.ec:253:  have hW := D1_MEUFNACMA_WOTSC_MM45_embthfc A_wots &m hc encb.
cdrafts-split/SPHINCS_C.ec:13:         XMSS-MT EUF-NAGCMA term)             (D1_MEUFNACMA_WOTSC_MM45_embthfc,
cdrafts-split/SPHINCS_C.ec:252:  have hW := D1_MEUFNACMA_WOTSC_MM45_embthfc A_wots &m hc encb.
cdrafts-split/WOTS_C_Flag2Discharge.ec:6:   `D1_MEUFNACMA_WOTSC_MM45` as a CONDITIONAL theorem on two flagged embedding
cdrafts-split/WOTS_C_Flag2Discharge.ec:38:   It does NOT make the corollary `D1_MEUFNACMA_WOTSC_MM45_embthfc`
cdrafts-split/WOTS_C_Interactive.ec:989:   batch `D1_reduce` tail `smt(uniq_wgpidxs_uniq disj_wgpidxs_disj_lists)`
cdrafts-split/XMSSMT_C_Bridge.ec:168:   it is NOT the repo's proven D.1.  The proven `D1_MEUFNACMA_WOTSC_MM45_embthfc`
cdrafts-split/XMSSMT_C_Bridge.ec:183:       the repo's batch D1_MEUFNACMA_WOTSC_MM45_embthfc). *)
--- usage in closure members:
cdrafts-split/WOTS_C_Multi.ec
cdrafts-split/WOTS_C_Interactive.ec
Key finding: `D1_reduce` / `D1_MEUFNACMA_WOTSC` within closure members are only referenced in WOTS_C_Multi (definition) and WOTS_C_Interactive (:989 — a comment about the batch tactic). The real consumers are SPHINCS_C.ec / SPHINCS_C_c10.ec / WOTS_C_EmbDischarge / XMSSMT_C_Bridge — none of which are in the closure list. So within the gated closure, the D.1 chain lemmas are effectively dead-end: they compile, they're pinned (if added), but nothing gated consumes them. That's important for Q2.

  Wait — WOTS_C_Interactive.ec:989 mentions `D1_reduce` — just a comment reference to the tactic. So no gated consumer.

  Now verify the remaining citations:
  - Stdlib DigitalSignatures.eca EUF_CMA game (find in opam).
  - Capstone premise c <= p_tgts at :526 / :865.
  - PQSigner_OS three spots.
  - PTgtsPin.ec: read and compile-test if I cite it.
  - XmssmtCC_All.ec:350-356 (l messages) and FL_SL_XMSS_MT_ES.ec:73 (l = 2^h), and R_top uncapped sign at :9592-9621. These support Q1b claim that multi-chain queries don't degrade terms. Maybe verify the l = 2^h line and the while loop quickly.

  Let me batch these./home/nicola/.opam/checkct/lib/easycrypt/theories/crypto/DigitalSignatures.eca
1484:  module EUF_CMA(S : Scheme, A : Adv_EUFCMA, O : Oracle_CMA) = {
3117:  module EUF_CMA(S : Scheme, A : Adv_EUFCMA, O : Oracle_CMA) = {
---
     construction and carried as the `0 <= mkg_adv` premise below. *)
  (mkg_adv : real)
  (* FORS +C-invariant tree reals (forall-bound; FALSE-AT-ZERO -- see header). *)
  (mtree_openpre mtree_trh mtree_trco : real)
  &m :
    (* ---- component-theorem parameter side-conditions (carried) ---- *)
    c <= p_tgts =>
    (* mkg_adv is the nonneg phantom MKG boundary term (hop-3); an advantage is
       >= 0 by construction, so this is a definitional side-condition, not a new
       assumption -- it makes the hop-3 identity `Pr[NPRFPRF] <= Pr[NPRFPRF]+mkg_adv`
       machine-true instead of an admit that is false for mkg_adv < 0. *)
                the concrete Gproc game; F must be disjoint from the Gproc game/reduction
                states (LeqPr_VT_C_proc + EUFCMA_Gproc(R_fors_p(F)) well-formedness). *)
             -R_fors_p, -O_CMA_Gproc, -O_CMA_Gproc_I, -R_ITSRC10_Gproc,
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default })
  &m :
    c <= p_tgts =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    (forall (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock),
       exists (cc : cntr), predC (ThC ps0 ad0 m0 cc)) =>
    dfC0 <> 8 * n =>
    dfC0 <> 8 * n * len =>
    dfC0 <> 8 * n * 2 =>
    dfC0 <> 8 * n * k =>
    Pr[EUFCMA_C10(F).main() @ &m : res]
      (* +C SKG-PRF advantage: GROUNDED (was the free real skg_adv) to the exact
         concrete R_SKGPRF_EUFCMA_C PRF-distinguishing term that hop-2 (SKGPRF_C_hop)
    (* Generate keypair for FL-SL-XMSS-MT-TW+C-ES-NPRF *)
    (pk, sk) <@ FL_SL_XMSS_MT_C_ES_NPRF.keygen(ps, ad);

    (* Sign (up to l) messages from the list provided by the adversary *)
    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);

      sig <@ FL_SL_XMSS_MT_C_ES_NPRF.sign(sk, m, Index.insubd (size sigl));

      sigl <- rcons sigl sig;
    }

    (* Ask adversary to forge (given public key and list of signatures) *)
    (m', sig', idx') <@ A(OC).forge(pk, sigl);

--- l def:
374:    op l <- adrs_len,
--- R_top sign oracle:
  module O_CMA : SOracle_CMA_C = {
    proc sign(m : msg) : sigSPHINCSPLUSTWC = {
      var mk : mkey;
      var sigFORSTW : FTWES.sigFORSTW;
      var cm : FTWES.msgFORSTW;
      var idx : index;
      var tidx, kpidx : int;
      var skFORS : FTWES.skFORS;
      var sigHT : sigFLSLXMSSMTTWC;

      if (m \notin mmap) {
        mk <$ dmkey;
        mmap.[m] <- mk;
      }
      mk <- oget mmap.[m];

      (cm, idx) <- FTWES.mco mk m;

      (tidx, kpidx) <- edivz (Index.val idx) l';

      skFORS <- nth witness (nth witness skFORSnt tidx) kpidx;

      sigFORSTW <@ FTWES.FL_FORS_ES_NPRF.sign((skFORS, ps,
                     set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);

      sigHT <- nth witness sigFLSLXMSSMTTWCl (Index.val idx);

      return (mk, sigFORSTW, sigHT);
    }
  }

The EUF_CMA module grep didn't print the body. Let me get the body from the stdlib. Also the `op l` grep found line 374 with `op l <- adrs_len` — that's a clone binding, not the definition. Agent B claimed `const l : int = 2 ^ h` at FL_SL_XMSS_MT_ES.ec:73. Let me check line 73.

  Also confirm R_top's O_CMA.sign is uncapped — the body I see has no counter/cap check, it memoizes per message. But wait: `sigHT <- nth witness sigFLSLXMSSMTTWCl (Index.val idx)` — it indexes a precomputed signature list by idx derived from the message. So repeated queries with distinct messages map to indices... idx comes from FTWES.mco mk m — deterministic per message. Interesting: so the simulated oracle can answer unbounded distinct messages, reusing hypertree indices — i.e., the model's oracle doesn't cap at 2^h queries, but the underlying NAGCMA game gives exactly l signatures. Actually this is about the reduction R_top simulating the CMA oracle from the NAGCMA game: the NAGCMA game provides l = 2^h signatures of adversary-committed messages... wait, in NAGCMA the adversary commits the message list ml beforehand (non-adaptive). The R_top simulation maps arbitrary adaptive queries to indices via mco. Whatever — the key structural point: the EUF-CMA game (stdlib) has one keypair, unlimited queries, counted but uncapped.

  Let me now verify the stdlib EUF_CMA body and line 73 of FL_SL_XMSS_MT_ES.ec, and then the PQSigner_OS citations.    proc forge(pk : pk_t) : msg_t * sig_t
  }.

  (* EUF-CMA game *)
  module EUF_CMA(S : Scheme, A : Adv_EUFCMA, O : Oracle_CMA) = {
    proc main() : bool = {
      var pk : pk_t;
      var sk : sk_t;
      var m : msg_t;
      var sig : sig_t;
      var is_valid, is_fresh : bool;
            
      (* Generate a key pair using the considered signature scheme *)
      (pk, sk) <@ S.keygen();
      
      (* Initialize the signing oracle with the generated secret key *)
      O(S).init(sk);

      (*
        Ask the adversary to forge a signature for any message (and provide both the
        message and the signature) given the public key pk and access to a signing oracle 
        that it can query an unlimited number of times
      *)
      (m, sig) <@ A(O(S)).forge(pk);

      (* 
        Verify (w.r.t. message m) the signature sig provided by the adversary 
        using the verification algorithm of the considered signature scheme 
      *)
      is_valid <@ S.verify(pk, m, sig);
      
      (* 
        Check whether message for which the adversary forged a signature is fresh 
        (i.e., check whether message is not included in the list of messages for which 
        the adversary received signatures through an oracle query)
      *)
      is_fresh <@ O(S).fresh(m);
     
      (* 
        Success iff
        (1) "is_valid": the forged signature provided by the adversary is valid, and
        (2) "is_fresh": the message for which the adversary forged a signature is fresh.
      *)
      return is_valid /\ is_fresh; 
    }
  }.

  
  (*
    - 
    Strong Existential UnForgeability under Chosen-Message Attack (SEUF-CMA).
=== O_CMA_Default:
1269:  module (O_CMA_Default : Oracle_CMA) (S : Scheme) = {
2902:  module (O_CMA_Default : Oracle_CMA) (S : Scheme) = {
  Number of leaves of "flattened" hypertree
  (i.e., total number of leaves of all inner trees on bottom layer)
*)
const l : int = 2 ^ h.


(* -- Address types -- *)
// Domain-separated KDF over the BIP-39 seed that produces an independent
// SPHINCS+C10 bootstrap keypair. The on-chain identity uses the
// `derive_c10_master_*` chain below; this surface only feeds the cached
// `RMEM_BOOTSTRAP_VK` slot consumed by `store_macd_encrypted`.

/// Derive the bootstrap signer's SPHINCS+C10 seed (48 bytes) from the
/// BIP-39 seed. The bootstrap signer is global (not per-chain), stateless,
/// and never rotates.
#[must_use]
pub fn bootstrap_seed_from_bip39(bip39_seed: &[u8; 64]) -> [u8; SEED_LEN] {
    let mut out = [0u8; SEED_LEN];
=== sol 447-455:
        // ── Role split ──────────────────────────────────────────────
        bytes4 selector = _selectorOf(userOp.callData);
        if (ownerIndex == 0) {
            if (selector != this.addOwnerBytes.selector) {
                return SIG_VALIDATION_FAILED;
            }
            if (_getStorage().bootstrapUses >= MAX_BOOTSTRAP_USES) {
                return SIG_VALIDATION_FAILED;
            }
=== lean 170-190:
   genericTerm_le_of_le hq generic_term_at_slot_cap⟩

/-- Same headline anchored at the bootstrap cap (Type-1 registration key).

    **P14 (cross-chain caveat).** `MaxBootstrapUses` is enforced PER CHAIN, but
    the bootstrap key is chain-INDEPENDENT (invariant #6 requires it for
    cross-chain address stability — the same key registers slot 0 on every
    chain). So a single bootstrap key's true EUF-CMA query budget across `C`
    chains is `C · MaxBootstrapUses`, not `MaxBootstrapUses`. This per-chain
    theorem therefore bounds only the single-chain term; the cross-chain bound
    is `advantage_floor_within_bootstrap_cap_crosschain` below, which shows the
    floor degrades by `⌈log₂ C⌉` bits yet stays ≥ 96 bits for any realistic
    deployment (it would take `C > 2^16` chains to erode below the operative
    slot-generic floor). Mirrors the per-chain-vs-lifetime caveat the slot
    aggregate already carries. -/
theorem advantage_floor_within_bootstrap_cap {q : Nat} (hq : q ≤ MaxBootstrapUses) :
    q * 2 ^ 112 ≤ 2 ^ SecurityBits :=
  queryTerm_le_of_le hq eufcma_term_at_bootstrap_cap

/-- **Cross-chain bootstrap-key floor (P14).** A bootstrap key signing across
    `C` chains has total query budget `q ≤ C · MaxBootstrapUses`. For any
=== lean 219-226:
theorem advantage_floor_within_bootstrap_cap_crosschain
    {q C : Nat} (hq : q ≤ C * MaxBootstrapUses) (hC : C ≤ 2 ^ 16) :
    q * 2 ^ 96 ≤ 2 ^ SecurityBits :=
  Nat.le_trans (Nat.mul_le_mul hq (Nat.le_refl (2 ^ 96)))
    (Nat.le_trans
      (Nat.mul_le_mul (Nat.mul_le_mul hC (Nat.le_refl MaxBootstrapUses))
        (Nat.le_refl (2 ^ 96)))
      (by decide))
All PQSigner_OS citations verified. Now the last piece: the `experiments/ptgts-pin/PTgtsPin.ec` claims — if I cite them, I should compile-test. The claim I'd lean on: the model has no 65536 cap and even proves `!(c <= 65536)`. That's a nice-to-have corroboration but not strictly load-bearing — the load-bearing claim is the *absence* of any cap in the gated closure, which I've verified by grep + reading the constants. I could cite PTgtsPin as INFERRED/untested or compile-test it. The user explicitly said compile-test anything cited from experiments/. Let me try to compile it — need to know the easycrypt.project include setup. Check for easycrypt.project at repo root.

  Actually, let me try compiling PTgtsPin.ec with the right -I flags. Look at how the gate invokes easycrypt: PHASE 1 compiles `$D/$n.ec`. Let me check the compile command in cert_gate_split.sh to replicate flags (without running the gate).

• All PQSigner_OS citations verify. Last item: the `experiments/ptgts-pin/PTgtsPin.ec` claims — per instructions, I must compile-test before citing. Checking how the gate invokes easycrypt so I can replicate the flags.27:B=base-c10-split; D=cdrafts-split; INC="-I $B -I $D"
177:  if easycrypt compile -I $B $B/$n.ec >/dev/null 2>&1; then echo "OK   base/$n"; else echo "FAIL base/$n"; fail=$((fail+1)); fi
183:  if easycrypt compile $INC $D/$n.ec >/dev/null 2>&1; then echo "OK   $n"; else echo "FAIL $n"; fail=$((fail+1)); fi
206:if easycrypt compile $INC "$TMPD/require_all.ec" >/dev/null 2>&1; then
210:  easycrypt compile $INC "$TMPD/require_all.ec" 2>&1 | tr '\r' '\n' | grep -a '^\[critical\]' | head -2 | sed 's/^/       /'
219:# `easycrypt compile` iterates the smt call by default; `easycrypt cli` does
274:  cli_one "base/$n" -I $B < $B/$n.ec
322:  if ! easycrypt compile $INC -I scratch "$wf" >/dev/null 2>&1; then
330:  cli_one "watched $wf" $INC -I scratch < "$wf"
379:  if easycrypt compile $INC -I scratch -I "$TMPD" "$TMPD/require_watched.ec" >/dev/null 2>&1; then
---
   which one a given sentence meant.

   WHAT THIS PIN DOES **NOT** SUPPLY -- the point of stating P4 at all.
   scratch/FINDING-both-my-claims-were-wrong.md quotes a WOTS-leg figure

       advantage  <=  q_s^2 * 2^-114.09,   at q_s = 2^16  ->  2^-82

   That `q_s` is the SIGNING-QUERY count, not `c` and not `p_tgts`.  Pinning
   `p_tgts` does not pin `q_s`: nothing in this model expresses the on-chain
   2^16 cap, and the model's own query cap is `c`, which is LARGER.  Two
   consequences, both to be stated rather than papered over:

     (i)  Using the model's cap where the figure uses q_s costs 4.006 bits:
          c^2 * 2^-114.09 = 2^36.006 * 2^-114.094 = 2^-78.09, not 2^-82.
          The 2^-82 figure is therefore NOT licensed by anything pinned here;
          it needs a separate argument that signing queries -- not hypertree
          instances -- are what the term counts, plus the 2^16 policy bound
          imported into the model.  Neither exists.
     (ii) Pinning `p_tgts := 2^16` to make the arithmetic line up would be
          WRONG twice over: it would not discharge the premise (65536 < 262656,
          proved below), and it would cap the reduction's targets below the
          number it actually places, which turns the S-TCR win condition FALSE
          and breaks the reduction rather than tightening it.

   The `2^-114.09` constant itself is machine-checked
   (experiments/wots-badenc/count/C10SurfaceKernel.ec).  The `q_s^2 * ...`
   shape around it is generic-model arithmetic and is not a theorem here.
   -------------------------------------------------------------------------- *)
op c10_q_s : int = 65536.       (* MAX_SLOT_USES -- deployment, not model *)

lemma c10_usage_cap_below_c : c10_q_s < c.
proof. by rewrite c10_c_closed /c10_c /c10_q_s. qed.

(* Even counting every hypertree layer a signature touches, the deployed cap
   stays under the model's structural count. *)
lemma c10_layers_times_usage_cap_below_c : c10_d * c10_q_s < c.
proof. by rewrite c10_c_closed /c10_c /c10_d /c10_q_s. qed.

(* The TIGHTER separation: distinct WOTS instances reachable under the usage
   cap <= q_s (one bottom-layer instance per signature) + l' (every top-tree
   instance there is).  l' = 2 ^ h' = 512. *)
lemma c10_distinct_instances_under_usage_cap : c10_q_s + l' < c.
proof. by rewrite /l' hp_val c10_pow2_9 c10_c_closed /c10_c /c10_q_s. qed.

(* THE MUST-NOT-DO, AS A THEOREM: the usage cap is NOT an admissible pin for
   p_tgts.  This is the statement that forbids the convenient substitution. *)
lemma c10_usage_cap_is_not_admissible_as_p_tgts : ! (c <= c10_q_s).
proof. by rewrite c10_c_closed /c10_c /c10_q_s. qed.

(* The hypertree's message capacity, for the record: l = 2^18 = 4 * q_s. *)
lemma c10_ht_capacity : l = 262144.


• Now compile-test PTgtsPin.ec. It presumably requires things from base-c10-split/cdrafts-split. Let me check its header for `require` lines and then compile with -I flags.

• Compile-testing the experiments file before citing it:32:require import AllCore List IntDiv Ring StdBigop StdOrder.
33:require import SPHINCS_PLUS.
34:require import WOTS_C_Real.
35:import FSSLXMTWES.
36:import Bigint BIA.
37:import IntOrder.
---
348 experiments/ptgts-pin/PTgtsPin.ec


[-] [0033] 10.3% (-1.0B / [frag -1.0B])
[\] [0034] 10.4% (-1.0B / [frag -1.0B])
[|] [0035] 10.6% (-1.0B / [frag -1.0B])
[/] [0036] 10.7% (-1.0B / [frag -1.0B])
[-] [0037] 10.8% (-1.0B / [frag -1.0B])
[\] [0038] 10.9% (-1.0B / [frag -1.0B])
[|] [0049] 13.9% (-1.0B / [frag -1.0B])
[/] [0050] 13.9% (-1.0B / [frag -1.0B])
[-] [0058] 15.8% (-1.0B / [frag -1.0B])
[\] [0059] 15.8% (-1.0B / [frag -1.0B])
[|] [0061] 16.0% (-1.0B / [frag -1.0B])
[/] [0061] 16.0% (-1.0B / [frag -1.0B])
[-] [0061] 16.4% (-1.0B / [frag -1.0B])
[\] [0062] 16.4% (-1.0B / [frag -1.0B])
[|] [0084] 23.1% (-1.0B / [frag -1.0B])
[/] [0085] 23.5% (-1.0B / [frag -1.0B])
[-] [0086] 24.0% (-1.0B / [frag -1.0B])
[\] [0095] 26.4% (-1.0B / [frag -1.0B])
[|] [0095] 26.5% (-1.0B / [frag -1.0B])
[/] [0095] 26.8% (-1.0B / [frag -1.0B])
[-] [0096] 26.8% (-1.0B / [frag -1.0B])
[\] [0118] 32.6% (-1.0B / [frag -1.0B])
[|] [0120] 32.7% (-1.0B / [frag -1.0B])
[/] [0121] 32.8% (-1.0B / [frag -1.0B])
[-] [0122] 32.9% (-1.0B / [frag -1.0B])
[\] [0123] 33.1% (-1.0B / [frag -1.0B])
[|] [0124] 33.3% (-1.0B / [frag -1.0B])
[/] [0125] 33.5% (-1.0B / [frag -1.0B])
[-] [0126] 33.8% (-1.0B / [frag -1.0B])
[\] [0127] 33.9% (-1.0B / [frag -1.0B])
[|] [0128] 34.0% (-1.0B / [frag -1.0B])
[/] [0132] 35.0% (-1.0B / [frag -1.0B])
[-] [0132] 35.0% (-1.0B / [frag -1.0B])
[\] [0132] 35.3% (-1.0B / [frag -1.0B])
[|] [0133] 35.3% (-1.0B / [frag -1.0B])
[/] [0136] 36.0% (-1.0B / [frag -1.0B])
[-] [0137] 36.1% (-1.0B / [frag -1.0B])
[\] [0138] 36.4% (-1.0B / [frag -1.0B])
[|] [0139] 36.6% (-1.0B / [frag -1.0B])
[/] [0140] 36.6% (-1.0B / [frag -1.0B])
[-] [0193] 53.9% (-1.0B / [frag -1.0B])
[\] [0197] 54.9% (-1.0B / [frag -1.0B])
[|] [0197] 54.9% (-1.0B / [frag -1.0B])
[/] [0197] 55.0% (-1.0B / [frag -1.0B])
[-] [0198] 55.1% (-1.0B / [frag -1.0B])
[\] [0202] 55.9% (-1.0B / [frag -1.0B])
[|] [0202] 56.0% (-1.0B / [frag -1.0B])
[/] [0202] 56.2% (-1.0B / [frag -1.0B])
[-] [0203] 56.2% (-1.0B / [frag -1.0B])
[\] [0215] 60.4% (-1.0B / [frag -1.0B])
[|] [0215] 60.5% (-1.0B / [frag -1.0B])
[/] [0215] 60.7% (-1.0B / [frag -1.0B])
[-] [0216] 60.7% (-1.0B / [frag -1.0B])
[\] [0218] 61.0% (-1.0B / [frag -1.0B])
[|] [0218] 61.0% (-1.0B / [frag -1.0B])
[/] [0218] 61.3% (-1.0B / [frag -1.0B])
[-] [0219] 61.3% (-1.0B / [frag -1.0B])
[\] [0240] 68.4% (-1.0B / [frag -1.0B])
[|] [0240] 68.4% (-1.0B / [frag -1.0B])
[/] [0240] 68.7% (-1.0B / [frag -1.0B])
[-] [0241] 68.7% (-1.0B / [frag -1.0B])
[\] [0245] 69.7% (-1.0B / [frag -1.0B])
[|] [0245] 69.7% (-1.0B / [frag -1.0B])
[/] [0245] 70.0% (-1.0B / [frag -1.0B])
[-] [0246] 70.0% (-1.0B / [frag -1.0B])
[\] [0308] 88.8% (-1.0B / [frag -1.0B])
[|] [0311] 89.3% (-1.0B / [frag -1.0B])
[/] [0311] 89.3% (-1.0B / [frag -1.0B])
[-] [0311] 89.5% (-1.0B / [frag -1.0B])
[\] [0312] 89.5% (-1.0B / [frag -1.0B])
[|] [0316] 90.5% (-1.0B / [frag -1.0B])
[/] [0316] 90.6% (-1.0B / [frag -1.0B])
[-] [0316] 90.8% (-1.0B / [frag -1.0B])
[\] [0317] 90.9% (-1.0B / [frag -1.0B])
[|] [0322] 92.3% (-1.0B / [frag -1.0B])
[/] [0322] 92.3% (-1.0B / [frag -1.0B])
[-] [0322] 92.6% (-1.0B / [frag -1.0B])
[\] [0323] 92.7% (-1.0B / [frag -1.0B])
[|] [0327] 93.9% (-1.0B / [frag -1.0B])
[/] [0327] 93.9% (-1.0B / [frag -1.0B])
[-] [0327] 94.1% (-1.0B / [frag -1.0B])
[\] [0328] 94.2% (-1.0B / [frag -1.0B])
[|] [0331] 94.7% (-1.0B / [frag -1.0B])
[/] [0331] 94.8% (-1.0B / [frag -1.0B])
[-] [0331] 95.1% (-1.0B / [frag -1.0B])
[\] [0332] 95.1% (-1.0B / [frag -1.0B])
[|] [0334] 95.4% (-1.0B / [frag -1.0B])
[/] [0334] 95.5% (-1.0B / [frag -1.0B])
[-] [0334] 95.7% (-1.0B / [frag -1.0B])
[\] [0335] 95.7% (-1.0B / [frag -1.0B])
[|] [0349] 100.0% (-1.0B / [frag -1.0B])
                                                   

RC=0

real	0m1.982s
user	0m1.638s
sys	0m0.085s
• PTgtsPin.ec compiles clean (RC=0, ~2s). Good — I can cite it as compile-tested.

  I have everything I need. Remaining minor verifications? The claim about `disj_wgpidxs` at WOTS_TW_ES.ec:465-466 and the failing block at WOTS_C_Bridge.ec:693-701 — agent B verified; the user themselves confirmed the failure; I don't need to re-run a 2592s compile. I could quickly confirm the bridge fails to compile but that takes long; the user's measurement stands and the file header documents it. I'll mark that as VERIFIED by user's measurement + file header, not re-run.

  One more check for Q2: does WOTS_C_Interactive (closure member) use D1_reduce? The grep showed WOTS_C_Interactive.ec:989 mentions `D1_reduce` — in a comment ("batch D1_reduce tail smt(...)"). Let me quickly confirm it's a comment. Actually the grep output: `cdrafts-split/WOTS_C_Interactive.ec:989:   batch `D1_reduce` tail `smt(uniq_wgpidxs_uniq disj_wgpidxs_disj_lists)`` — looks like comment text (indented, backticks). Good enough; mark INFERRED that it's a comment. Actually let me be careful about one Q2 sub-point: "pinning D1_reduce's statement... motive: gate proves it compiles, not that it still says c <= p_tgts". The pin would indeed catch statement drift. The question is whether it's false comfort given the red bridge. Facts:

  - Both target lemmas live in WOTS_C_Multi.ec (compiling closure member). D1_reduce at :523, D1_MEUFNACMA_WOTSC at :951. (User's stated locations — D1_reduce :488, D1_MEUFNACMA_WOTSC in bridge :677 — are both stale/wrong. If the user pins "D1_MEUFNACMA_WOTSC in WOTS_C_Bridge.ec", the pin FAILS as NOT-FOUND because the bridge's lemma is named D1_MEUFNACMA_WOTSC_MM45 and the digest regex has a negative lookahead.)
  - WOTS_C_Multi.ec itself already carries the honest caveat at :942-949: nothing in this file discharges the FC<->STCRC_WC.Col unification; the bound is over the LOCAL game only.
  - No closure member consumes D1_reduce/D1_MEUFNACMA_WOTSC (only comment mention). The real consumer chain (SPHINCS_C.ec etc.) is outside the closure, and the wired capstone doesn't use the bridge at all (uses the interactive component theorem at SphincsC10CapstoneWired.ec:624).

  So: is pinning false comfort? My verdict: it is honest *as a pin* but low value, and the false-comfort risk is real but mitigated by the in-file caveat. The deeper point: pinning D1_reduce's `c <= p_tgts` guards a statement that no gated theorem consumes — it protects a dead-end chain link. The capstone already carries `c <= p_tgts` as its own premise (SphincsC10CapstoneWired.ec:526 and :865), and the component theorem carries it (XmssmtCC_All.ec:8539 per agent B; I saw `hc` at :8594). So the premise the user cares about (threaded through 11 certified files) is already pinned where it matters — check whether the capstone pin exists: cert-statements-split.tsv:3 pins EUFCMA_SPHINCS_PLUS_C10_GROUNDED — yes, agent D verified. So the capstone's own statement, including `c <= p_tgts`, is already pinned. The additional pins guard only the D.1 file's restatement.

  Is the c <= p_tgts premise "threaded through 11 certified files, 48 occurrences"? Not verified by me; mark INFERRED/user claim.

  Now Q1 synthesis:

  (a) The model is single-keypair, single adversary, unlimited queries. VERIFIED: FxChain.ec:255-256 (EUFCMA_C10 = stdlib Stateless.EUF_CMA); stdlib DigitalSignatures.eca:1484-1524 (one keygen, one oracle init, "unlimited number of times" comment); O_CMA_Default at :1269 (counter, no cap). No bootstrap/slot/chain/65536 anywhere in cdrafts-split/base-c10-split (grep: zero hits except FORS_C10.ec:87 comment mention of "2^16 per-chain cap" in a heuristic remark, and internal "slot" datastructure senses). The slot/bootstrap distinction is ABSENT from the model.

  So (a) answer: the certified statement ranges over a single keypair; the distinction is absent. BUT — and this is the subtle point — the bootstrap key IS a single SPHINCS+C10 keypair. Cross-chain reuse of one keypair is still one keypair with more queries. The EUF-CMA game allows unlimited queries. So the statement *does* formally cover the bootstrap key as "one keypair, adversary makes q queries"; what it does NOT express is any numeric cap on q. The failure is not that the statement doesn't apply — it's that the *deployment's claimed bound on q* (65536) is false for the bootstrap key (true bound C*65536), and the model has no query-cap parameter at all in which to even state that. Hmm, but wait: does the EC statement's validity depend on q at all? The bound's RHS terms are game probabilities whose internal caps are keyed to hypertree geometry, not to q (agent B §3: all four terms coefficient 1; caps c, t_smdttcr are structural). The EUF-CMA game admits unlimited queries. So increasing q from 65536 to C*65536 does not change the certified bound at all — the bound is uniform in the adversary (any F, any number of queries). Wait, is that right? The bound quantifies over all F <: Adv_EUFCMA_C with module disjointness — no efficiency/query bound (lens-A confirmed "NO losslessness / query-bound / efficiency hypothesis on F"). So the bound holds for an adversary making arbitrarily many queries. Interesting!

  But hold on — is that actually true of the *underlying* reductions? In a standard SPHINCS+ security proof, the bound degrades with q_s (e.g., the q_s^2 factor in WOTS bad-encoding, per PTgtsPin's quoted figure `q_s^2 * 2^-114.09`). How can the EC bound be uniform in q? Because the NAGCMA game structure: the adversary commits its message list upfront (non-adaptive), the game signs exactly l = 2^h messages, and the reduction's TCR target counts are capped by geometry. The R_top simulation answers adaptive queries by mapping them to indices. Actually for an adversary making more than l queries... the bound still holds as a probability statement; the ITSRC10/TCR terms' caps are saturated. The point is the EC bound is a worst-case bound independent of q — it doesn't get *worse* with more queries because the terms' caps are already at the geometry maximum. That's the nature of the carried "SM_DT_TCR" multi-target terms with caps = total instances.

  So the honest answer to (b): reading the statement as covering bootstrap Type-1: NONE of the four carried terms becomes unsound, and none degrades — the bound is uniform in the adversary's query count (no q factor anywhere; VERIFIED coefficient-1 at XmssmtCC_All.ec:8583-8592 and capstone :595-604; caps keyed to geometry: c = total leaves instantiated in FL_SL_XMSS_MT_ES... agent B said PKCOC_TCR t_smdttcr <- same as c at :425-426, TRHC at :463-464). The thing that breaks is NOT inside the EC statement: it's the *external* security-level arithmetic that instantiates "advantage at the cap" — PQSigner_OS's own Lean P14 already says the floor degrades with C (96 - 2·log2 C bits for the generic multi-target term). Wait, but if the EC bound is uniform in q, why does the Lean floor degrade with C? Because the Lean quantitative floor uses a *different* (tighter, generic-model) accounting that scales with q — q * 2^96 ≤ 2^SecurityBits etc. Those Lean bounds are heuristics about what the terms evaluate to, not the EC theorem. Hmm, actually the Lean theorems are arithmetic: they say "if q ≤ cap then q * 2^112 ≤ 2^SecurityBits" — they're computing the concrete bit-security given a presumed per-query advantage term. The cross-chain companion accounts for C.

  So the degradation story: the EC-certified bound covers the bootstrap key (same keypair, arbitrary queries) WITHOUT degradation of its own terms; what degrades cross-chain is the *deployment-level bit-security estimate* (the Lean floor), because the adversary's budget is C× larger and the presumed per-query/quantitative terms scale. And there's a second, sharper gap: the EUF-CMA game covers at most l = 2^h = 262144 distinct-message signatures? No wait — the EUF-CMA game is unlimited queries. Hmm, but the underlying hardness: can a SPHINCS+ key sign more than 2^h messages? The hypertree has 2^h leaf slots; signing more than 2^h distinct messages reuses WOTS instances — the model's NAGCMA game caps at l committed messages, and the EUF-CMA bound... The R_top oracle memoizes per message and maps each new message to an index via mco (random oracle-ish map). The model allows unlimited queries; whether the bound stays meaningful when q > 2^h is a question about term magnitudes (SM_DT_TCR with all targets registered is presumably near-1 useless). But formally the statement still holds. With C=2^16 chains × 65536 uses = 2^32 total uses vs hypertree capacity l = 2^18 (PTgtsPin: c10_ht_capacity: l = 262144 = 2^18, compile-tested). So the *realistic* bootstrap deployment can exceed the hypertree's message capacity — at which point no security bound means anything (WOTS instances massively reused). But the EC statement itself is still a true theorem; it's just vacuous-ish at that regime because the RHS terms saturate.

  Hmm wait, is it really true the EUF-CMA game permits q > l? The stdlib game: yes, unlimited. And the reduction R_top's oracle: memoized per message, indices from mco — can answer arbitrarily many. The NAGCMA game inside: adversary commits ml, game signs exactly l messages from the list. The leaf reduction queries the WOTS oracle once per leaf of the entire hypertree regardless of how many messages committed. OK.

  So (b) answer refined: If the statement is read as covering bootstrap Type-1 authorizations — it DOES cover them (same keypair, CMA queries unlimited, bound uniform in q), and NONE of the four terms degrades within the formalism. The degradation is entirely outside the EC statement: (i) the concrete security-level arithmetic (Lean P14: floor degrades by ~2·log2 C bits, VERIFIED Quantitative.lean:189-226); (ii) at C·65536 > l = 2^18 the deployment exceeds the structure the bound was sanity-checked against (PTgtsPin c10_ht_capacity, compile-tested by me), though the theorem remains formally true. And the capstone's own premise c <= p_tgts is about hypertree-instance counts (c = 262656 per PTgtsPin compile-tested lemma c10_usage_cap_below_c... wait c10_q_s < c means 65536 < c = 262656), not about signing queries — so the premise is unaffected by bootstrap reuse.

  Hmm, one more subtlety for (b): the user asks "which of the four carried terms becomes unsound or degraded, and by how much". The disciplined answer: none of the four — because the model has no parameter that counts the adversary's signing queries, there is no term in which multi-chain reuse could register. That's the finding: the question "which term degrades" presupposes the model prices query count, and it doesn't. The multi-target reuse "hits" nothing in the EC statement; it hits the external quantitative reading (Lean floor) and eventually the structural capacity.

  Actually wait — I should double check one thing: is the EUF-CMA statement's bound really meaningful/vacuous-independent-of-q? The RHS terms are advantages of derived adversaries against primitives. The derived adversary R_top_C(F) runs F; if F makes 2^32 queries, the derived SM_DT_TCR adversary registers targets capped at t_smdttcr (it just can't register more; extra queries map to already-registered targets or are answered from memoization). The bound Pr[EUF-CMA] ≤ sum of Pr[...] holds for ALL F regardless. So yes: uniform. The soundness of the *statement* is unaffected. What changes with q is the *interpretation*: for the bound to give 96-bit security you need the RHS terms small, and for hash-based schemes the relevant terms' smallness is an assumption about the hash function against adversaries with bounded resources — but the EC statement treats them as free variables. OK.

  (c) Scope restriction written down? Agent A: not found anywhere — no written statement restricting to single keypair or disclaiming cross-chain reuse. The restriction is structural (stdlib EUF_CMA game) but undocumented. However — I should be careful: the FAITHFULNESS NOTE (single-adversary) at SphincsC10CapstoneWired.ec:342-347 is about adversaries, not keys. Let me quickly verify there is really nothing. Agent A grepped; I'll do one more targeted grep for "keypair" / "single" in the capstone header to be safe. Actually agent A checked headers :1-470 of the capstone and found nothing. I'll mark: VERIFIED (by full-header read + grep) that no scope restriction is written; the only related note is the single-adversary faithfulness note which is not about keypairs. Maybe quickly read :342-347 to quote it.

  (d) Proof question or documentation question? Given (b)'s answer — no term degrades; the statement is uniform in q — this is a documentation/scope question, PLUS a genuine deployment-arithmetic issue already owned by Lean P14. So: documentation/scope. The one caveat: nothing in the EC model can express the 2^16 cap at all (PTgtsPin proves c=262656 > 65536, compile-tested), so "the capstone certifies the deployment's 2^16-capped usage" is unsupportable as a claim — that's a documentation fix, not new proof work. Unless the user wants to certify the cross-chain composition (hybrid over C... no, same key — no hybrid needed; it's the same single-key game) — the only proof work would be if they wanted a machine-checked connection between q and concrete bit-security, which is a quantitative-layer question the Lean side already handles informally-ish.

  Q2 verdict: Pinning D1_reduce + D1_MEUFNACMA_WOTSC (both in WOTS_C_Multi.ec, closure member, compiles) is *honest but nearly worthless*, and as the user described it it's broken in detail: "D1_MEUFNACMA_WOTSC" is not in WOTS_C_Bridge.ec (:677 is a tactic line; the bridge lemma is D1_MEUFNACMA_WOTSC_MM45 at :719) — if pinned against the bridge path, the gate FAILS NOT-FOUND. Pinned against WOTS_C_Multi.ec, both resolve. Is it false comfort? The in-file header (WOTS_C_Multi.ec:942-949) already discloses the red bridge, and the gate receipt doesn't claim chain completeness. But the motive is partially misguided: the `c <= p_tgts` premise the user wants protected is already pinned where it's load-bearing — the capstone statement itself is pinned (cert-statements-split.tsv:3) and carries c <= p_tgts at :526/:865. D1_reduce is consumed by nothing in the gated closure (only a comment mention in WOTS_C_Interactive.ec:989); its real consumers (SPHINCS_C.ec:252, via bridge+embdischarge) are ungated, and the bridge is red. So pinning guards a leaf statement on a branch that (i) ends nowhere in the certified artifact and (ii) is currently broken one link downstream. A gate reader would see "D1_reduce pinned ✓" and could reasonably but wrongly conclude the D.1 chain is certified end-to-end. Verdict: mild false comfort / low value; not dishonest if the receipt notes scope. Honest alternative: pin it AND add the caveat to whatever doc accompanies the receipt — or better, spend the effort on the bridge. Actually my ranking: the pins are cheap and the protection is real (statement drift detection); the dishonesty risk is in *prose around the gate*, not the pin. I'd say: pin it, but only together with a receipt-side note that D.1's downstream (bridge → embdischarge → SPHINCS_C) is ungated and red; otherwise defer.

  Hmm, user said "Do not hedge to a middle position." I need a crisp verdict. My verdict on Q2: as specified (pin `D1_MEUFNACMA_WOTSC` in WOTS_C_Bridge.ec:677) it is *broken*, not merely comfort — the pin won't resolve. Corrected to target WOTS_C_Multi.ec, it is honest-but-low-value, and I'll call it: NOT false comfort as a pin (the file is self-disclosing), but it buys almost nothing because the premise is already pinned at the capstone and the lemmas are dead ends in the closure. Rank it last.

  Wait — one correction: is the capstone pin actually covering the premise text? The pin digests the statement from `lemma EUFCMA_SPHINCS_PLUS_C10_GROUNDED` to `proof.` — that includes the `c <= p_tgts =>` premise at :526. Yes.

  Q3 ranking:
  1. (iv) resolve Q1 as scope/documentation — cheap, and it corrects a live misunderstanding that affects how the certificate is presented externally. Highest value-per-effort and it's the one that changes decisions.
  2. (i) repair disj_wgpidxs in WOTS_C_Bridge + gate the D.1 chain — real proof work; note (ii) is the SAME work: the FC<->STCRC_WC.Col reconciliation is exactly what the bridge attempts (WOTS_C_Reduction.ec:338-345 ↔ bridge header :19-62). So (i) and (ii) merge into one unit. Its value: it would connect the local D.1 bound to MM45's real game. But — bluntly — the wired capstone doesn't need it (uses the interactive component theorem directly, SphincsC10CapstoneWired.ec:624). So the D.1 chain is an alternative/legacy path (SPHINCS_C.ec is the "older pre-wired assembly"). Repairing it has archival/robustness value, not capstone value. Hmm — that downgrades (i)/(ii) substantially. Is the D.1/bridge chain actually needed by anything gated? No: SPHINCS_C.ec not in closure; bridge not in closure; capstone independent. So repairing the bridge is busywork *for the certificate* — unless the user wants the D.1 chain as an independent corroboration or as the basis for future work. Being blunt: candidate (i)+(ii) is proof work on a chain the certified capstone does not consume. The question is whether the chain has standalone value (the D.1 multi-instance S-TCR bound is arguably the cleaner theorem). But if no gated artifact consumes it, it's optional.
  3. (iii) the pins — cheap, honest if scoped, near-zero marginal protection (premise already pinned at capstone; lemmas dead-end in closure).

  Fifth candidate the user is not seeing: the real gap for PQSigner_OS is the missing machine-checked link between the EC statement and the deployment's quantitative claim — i.e., the fact that NOTHING in the gated closure bounds signing queries at all (no q_s parameter exists), so any "96-bit at 2^16 uses" claim rests on the ungated PTgtsPin-style reasoning plus Lean arithmetic. A useful unit: promote a small, compiling "deployment scope" theory into the closure that states precisely what the capstone does and does not say about query counts and cross-chain reuse (basically formalize PTgtsPin's negative results: c > 65536, l = 2^18 capacity, c <= p_tgts is not the usage cap) so the gate *pins the scope limits themselves*. That turns the Q1(c) finding (restriction written nowhere) into a pinned artifact. That's better than pinning D1_reduce. Actually PTgtsPin.ec compiles (I tested, RC=0) — it's in experiments/, ungated; promoting a cleaned version into the closure is concrete and feasible.

  Hmm, but careful: PTgtsPin requires WOTS_C_Real etc. — fine, those are in the closure. Promoting it = adding to closure list + re-baseline. That's a real candidate fifth unit: "pin the negative scope facts."

  Q4: strongest objection. The user's framing in Q1(b) presupposes that multi-chain reuse "hits" one of the four terms — i.e., that the certified bound is query-count-sensitive the way the paper/Lean arithmetic is. That's wrong: the EC statement has no query-count parameter; the bound is uniform in the adversary; so "which term degrades" has answer "none, and that's precisely why the certificate neither confirms nor denies the cross-chain claim — the degradation lives entirely in the unmechanized quantitative layer (Lean P14) and in the capacity ceiling l = 2^18." The strongest single objection, though, to the *next gate step*: the pins as specified target a lemma name/location that doesn't exist (D1_MEUFNACMA_WOTSC is not in WOTS_C_Bridge.ec; :677 is a tactic line), and the premise the user wants to protect is already pinned at the capstone — so the planned unit both fails mechanically and duplicates existing protection. That's the strongest objection.

  Actually, strongest objection overall should probably target the biggest wrong framing: "the same shape of false comfort I just corrected in that file's header" — the analogy is flawed: the bridge header was false because it claimed "PROVED IN FULL" for a file that doesn't compile. Pinning D1_reduce in a *compiling, gated* file claims only "this statement text is unchanged and this file compiles" — which is true. The false comfort would be in the *reader's inference*, and the file itself already carries the corrective disclosure (:942-949). So the analogy overstates. But the mechanical fact (pin target doesn't exist) is decisive.

  Let me also double check the claim "D1_reduce" line the user gave (:488) is stale — yes, verified at :523.

  One more verification: capstone pin exists in cert-statements-split.tsv:3 — agent D verified; trust it but it's load-bearing for my Q2 argument. Quick grep to confirm. Also confirm WOTS_C_Interactive.ec:989 is a comment. And check the FAITHFULNESS note :342-347 for Q1c. Let me do these three quickly.

• PTgtsPin.ec compiles clean (RC=0, 2 s) — citable. Three final spot-checks:3:cdrafts-split/SphincsC10CapstoneWired.ec::EUFCMA_SPHINCS_PLUS_C10_GROUNDED	4649eba5761382549d106f45db91e372
91:# EUFCMA_SPHINCS_PLUS_C10_GROUNDED) EQUALS three named terms over the
---
   have distinct WOTS group-prefixes, the S_TCR_C_Int winning conjuncts ALL hold —
   crucially `uniq (map emb_tw twsOraw)` (via `emb_dist_valid`) and
   `FC.disj_lists (map emb_tw twsOraw) twsOC` (via `disj_lists_discharged`, i.e.
   FLAG-2 on the chains + well-formed A).  This is the interactive analogue of the
   batch `D1_reduce` tail `smt(uniq_wgpidxs_uniq disj_wgpidxs_disj_lists)`
   (WOTS_C_Multi.ec:592), now carrying the chain-walk tweaks FLAG-2 covers.
   -------------------------------------------------------------------------- *)
lemma interactive_success_transfer
---
       decls (the component theorem certifies 0-axiom, XmssmtCC_All.ec:8503).

   ------ (4) FAITHFULNESS NOTE  (single-adversary -- NOW CLOSED both sides) ----
   MM45 has ONE shared forger A giving every RHS `R_x(A)`.  BOTH sides are now
   F-derived: the HYPERTREE side is A_ht := R_top_C(F) (RtopCSoundness.ec:138), and
   (Step 4) the FORS side is A_fors := R_fors_p(F) (GprocFORSC10, the VT reduction) --
   the former FREE `M.Adv_EUFCMA_MFORSC10` is GONE.  The single-adversary caveat that
   SPHINCS_C_c10.ec:93-100 flagged for the FORS leg is CLOSED here.
   ========================================================================== *)


• All confirmed:
  - Capstone pin exists at cert-statements-split.tsv:3 (statement pin includes premises → c <= p_tgts already pinned at the capstone).
  - WOTS_C_Interactive.ec:989 mention of D1_reduce is inside a comment (context confirms — it's in a comment block above lemma interactive_success_transfer).
  - FAITHFULNESS note is about the single *adversary*, not keypairs.

  I have everything. Now write the final answer. Structure per the deliverable: (1) verdict Q1(a)-(d) with VERIFIED/INFERRED citations; (2) pins honest or false comfort; (3) ranked next unit; (4) strongest objection. Be blunt, no hedging to middle.

  Keep it tight but complete. Mark VERIFIED (file:line) vs INFERRED. Note compile-test status of PTgtsPin.

• All checks done. Here is the full deliverable.

  ---

  ## (1) Q1 — Does the certified statement cover bootstrap-signed Type-1?

  ### (a) The slot/bootstrap distinction is absent from the model — but that is not the whole answer

  **VERIFIED:**

  - The certified game is one keypair, one oracle, one adversary. `EUFCMA_C10(F)` is literally the EasyCrypt stdlib game: `cdrafts-split/FxChain.ec:255-256` (`= DSSC.Stateless.EUF_CMA(SPHINCS_PLUS_C10, F, DSSC.Stateless.O_CMA_Default)`). The stdlib game (`~/.opam/checkct/lib/easycrypt/theories/crypto/DigitalSignatures.eca:1484-1524`) calls `keygen()` exactly once, installs that one `sk` in the oracle, calls the adversary once, and its own comment says the oracle "can query an **unlimited** number of times". `O_CMA_Default` (same file, :1269) keeps a query list as a **counter, not a cap** (`nr_queries` returns `size qs`).
  - The adversary is quantified with **no query bound**: `F <: Adv_EUFCMA_C{...}` carries module-disjointness restrictions only (`SphincsC10CapstoneWired.ec:841-863`); the premises (:865-873) are `c <= p_tgts`, an encode-compat equation, N2, and four width facts — nothing bounding F's queries.
  - Neither `c` nor `p_tgts` counts deployment signatures. `c` = "Number of WOTS-TW instances to consider for M-EUF-GCMA" (`base-c10-split/WOTS_TW_ES.ec:78-79`), concretely the total hypertree leaf/instance count; `p_tgts` = "Number of S-TCR(+C) targets the SPHINCS+ reduction places" (`cdrafts-split/WOTS_C_Real.ec:339-340`). Both have only lower bounds.
  - Grep over `cdrafts-split/` + `base-c10-split/`: **zero** hits for `bootstrap`, `multi-chain`, `cross-chain`, `multi-key`, `65536`. The single `per-chain` hit is a heuristic comment (`FORS_C10.ec:87`) that the file itself disclaims as carrying no EasyCrypt result. "Chain"/"slot" hits are all WOTS hash-chains and data-structure slots.
  - Corroboration from `experiments/ptgts-pin/PTgtsPin.ec` — **I compile-tested it: `easycrypt compile -I base-c10-split -I cdrafts-split` exits RC=0 in ~2 s on this host**. It proves `! (c <= 65536)` (`c10_usage_cap_is_not_admissible_as_p_tgts`, PTgtsPin.ec:326-327) with `c = 262656`, and states in prose (:287-289): "nothing in this model expresses the on-chain 2^16 cap".

  **So (a): yes, the distinction is absent.** But the sharper statement is: the model doesn't *need* the distinction, because the bootstrap key **is** a single SPHINCS+C10 keypair — cross-chain reuse is the same keypair answering more queries, and the game already allows unlimited queries. The statement *applies* to the bootstrap key. What it cannot do is say anything about how many queries is too many.

  For the PQSigner_OS facts, all three of your citations verify (line numbers slightly off): `domain/src/lib.rs:407-411` (comment + fn; note this is the *legacy* derivation — the on-chain identity is `derive_c10_master_*` at :546, which takes **no chain_id**, so it is literally the same keypair on every chain); `PQSmartWallet.sol:447-455` (cap is a **scalar per-deployment** counter `bootstrapUses`, per-chain only because each chain hosts its own deployment — not a `mapping(chainId)`); `Quantitative.lean:172-187` (P14 verbatim as you quoted) plus the cross-chain companion at :219-226 with the `96 − 2·log₂C` degradation correction.

  ### (b) None of the four terms degrades — and that *is* the finding

  **VERIFIED:** All four carried terms appear with **coefficient 1** and no query-count factor, both in the component theorem `EUFNAGCMA_FLSLXMSSMTTWCESNPRF` (`cdrafts-split/XmssmtCC_All.ec:8583-8592`, read directly) and in the capstone (`SphincsC10CapstoneWired.ec:595-604`, read directly). Query counts enter only as win-condition caps keyed to **hypertree geometry**, not to adversary behaviour: `t_smdttcr = c` (total hypertree instances) for PKCOC (`FL_SL_XMSS_MT_ES.ec:425-426`), `t_smdttcr = Σ nr_trees × (2^h' − 1)` for TRHC (:463-464), and the hypertree game signs exactly `l = 2^h` committed messages (`XmssmtCC_All.ec:348-356`; `const l : int = 2 ^ h` at `FL_SL_XMSS_MT_ES.ec:73`). The reduction's simulated CMA oracle is uncapped (memoizes per message, `XmssmtCC_All.ec:9592-9621`).

  So the honest answer to "which term does multi-chain reuse hit" is: **none of them, by nothing.** Your question presupposes the bound is query-count-sensitive, like the paper's/Lean's `q_s`-arithmetic. The EasyCrypt statement has no parameter in which cross-chain reuse could register — it is a bound uniform over all adversaries, already worst-case. The degradation from bootstrap reuse is real but lives **entirely outside the certified artifact**: in the quantitative layer (your own Lean P14: floor degrades to `96 − 2·log₂C` bits — INFERRED to be generic-model arithmetic, not derived from the EC terms) and in the structural ceiling `l = 2^18 = 262144` signatures per keypair (PTgtsPin.ec:330-332, compile-tested), which `C × 65536` crosses at C ≥ 4.

  ### (c) The scope restriction is written **nowhere**

  **VERIFIED** (full-header read + grep): the capstone header (:1-470) discusses admits, single-sourcing, idealisations, and a "FAITHFULNESS NOTE (single-adversary)" (:342-347) — which is about all RHS reductions being derived from the one forger F, **not** about keypairs. No file in the gated closure states "one keypair", "no cross-chain reuse", or any usage-cap disclaimer. The restriction is real but purely structural (it falls out of the stdlib game). That absence is the finding.

  ### (d) This is a documentation/scope question, not a proof question

  Because of (b): no term breaks, no lemma goes false, no new reduction is needed — the theorem is true for the bootstrap key as-is. What is missing is (i) a written scope statement on the certificate, and (ii) honesty that the "2^16-capped usage" deployment claim is not expressible in, let alone certified by, this model (PTgtsPin proves the model's structural count *exceeds* the cap). Manufacturing proof work here would be busywork.

  ---

  ## (2) Q2 — The 111 → 113 pin step: broken as specified, low-value as fixable

  **VERIFIED mechanics** (`cert_gate_split.sh:33` `EXPECT_PINS=111`; pins are rows of `cert-statements-split.tsv`, digested **purely textually** by `tools/stmt_digest.py` — no EasyCrypt run touches the pinned file):

  - **As you specified it, the step fails.** There is no lemma `D1_MEUFNACMA_WOTSC` in `WOTS_C_Bridge.ec` — :677 is a tactic line inside `D1_bridge_WOTSTW`; the bridge's lemma is `D1_MEUFNACMA_WOTSC_MM45` (:719), and the digest regex has a negative lookahead that makes the short name NOT-FOUND → hard gate FAIL. Also your `D1_reduce :488` anchor is stale; it's at `WOTS_C_Multi.ec:523`.
  - **Retargeted to `WOTS_C_Multi.ec`, both pins resolve**: `D1_reduce` (:523) and `D1_MEUFNACMA_WOTSC` (:951) both live in that compiling, gated closure member (line 7 of `closure-c10-split.txt`; capstone at line 17; bridge and EmbDischarge absent).

  Is it false comfort? **No — but it's near-zero value, and your motive is already satisfied elsewhere.** Three facts:

  1. The premise you want protected, `c <= p_tgts`, is **already pinned where it is load-bearing**: the capstone statement itself is pinned (`cert-statements-split.tsv:3`), and the pin digests the full statement text including the `c <= p_tgts =>` premise at `SphincsC10CapstoneWired.ec:526`. Any drift in that premise at the certified boundary already turns the gate red.
  2. Within the gated closure, `D1_reduce`/`D1_MEUFNACMA_WOTSC` are **dead ends**: no closure member consumes them (the only other hit, `WOTS_C_Interactive.ec:989`, is a comment). Their real consumer chain (`WOTS_C_Bridge.ec` → `WOTS_C_EmbDischarge.ec:174` → `SPHINCS_C.ec:252`) is entirely outside the closure, and the **wired capstone does not use the bridge at all** — it applies the interactive component theorem directly (:624). So you'd be pinning the statements of a chain whose only downstream is red *and* disconnected from the certified artifact.
  3. The false-comfort analogy to the bridge header doesn't hold: the header *lied* ("PROVED IN FULL" on a non-compiling file); a pin on a compiling, gated file claims only "this text is unchanged and this file compiles" — true. And `WOTS_C_Multi.ec:942-949` already carries, in-file, exactly the disclosure you'd want ("absent from closure-c10-split.txt… does not compile at r2026.02… nothing in THIS file discharges the unification").

  Verdict: **not dishonest, but busywork** — it duplicates existing protection on a dead-end chain. A gate-reader could over-read it, but the receipt plus the in-file caveat say enough. Do it only if it costs you ten minutes; do not spend a unit on it.

  ---

  ## (3) Q3 — Ranked next units

  1. **Resolve Q1 as scope/documentation, and pin the *negative* facts (the fifth candidate you're missing).** The gap in Q1(c) — restriction written nowhere — is fixable concretely: `experiments/ptgts-pin/PTgtsPin.ec` **already compiles** (I tested) and already proves the scope-limiting theorems (`c > 65536`, `l = 2^18`, `p_tgts` is not the usage cap). Promote a cleaned version into the closure with statement pins, so the gate itself certifies what the certificate does *not* say about query counts and cross-chain reuse. This converts your Q1 finding from prose into a pinned artifact and directly serves the PQSigner_OS integration claim. Highest value, modest cost.
  2. **Bridge repair (i) — with eyes open that it is optional for the certificate.** Note (ii) **is the same work**: `WOTS_C_Reduction.ec:338-345`'s "remaining structural reconciliation" (FC ↔ STCRC_WC.Col) is exactly what the bridge attempts (bridge header :19-62) and exactly where `disj_wgpidxs` fails (:693-701). But the wired capstone doesn't consume this chain — `SPHINCS_C.ec` is the older pre-wired assembly. Repair it only if the D.1 path has standalone value to you (it is the cleaner multi-instance S-TCR statement), not because the certificate needs it.
  3. **The statement pins (iii).** Cheap, honest, nearly redundant — see Q2.

  Busywork call: (iii) is busywork; (i)=(ii) is real proof work but on a chain the certificate doesn't use; (1) is the only candidate that changes what you can *claim*.

  ---

  ## (4) Strongest objection

  **Your Q1(b) framing assumes the certified bound prices query count; it doesn't, and that inverts your conclusion.** There is no term that "becomes unsound or degraded" by bootstrap reuse, because the model contains no signing-query parameter at all — the bound is uniform over unlimited-query adversaries, with all four caps keyed to hypertree geometry. So the certificate is not *silently weaker* for the bootstrap key; it is *silent, full stop* — the cross-chain degradation (Lean P14's `96 − 2·log₂C`, and the hard wall at `l = 2^18` vs `C·65536`) lives entirely in an unmechanized quantitative layer that the gate never touches. The practical consequence cuts against your planned work: the danger is not a false sense of proof completeness, it's that *any* concrete bit-security figure attached to the bootstrap key rests on arithmetic outside the certified closure — which is why the scope-pinning unit (Q3 #1) outranks everything on your list. And a smaller but decisive correction: your planned pin target `D1_MEUFNACMA_WOTSC` in `WOTS_C_Bridge.ec` does not exist — the step as specified turns the gate RED, not green.

To resume this session: kimi -r session_7fe9cc6e-09d7-4c18-98ce-8058d01d1465
