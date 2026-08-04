(* ==========================================================================
   SphincsC10CapstoneWired.ec -- SPHINCS+C10 EUF-CMA CAPSTONE, WIRED variant of
   sphincs_c10_capstone_concrete_wip.ec (the 6-admit concrete-LHS capstone).

   WHAT CHANGED (2026-07-24 wiring pass) vs the 6-admit concrete capstone:
     (a) SINGLE-SOURCING.  The scheme (SPHINCS_PLUS_C10 / DSSC / EUFCMA_C10),
         good_fors, and V_C are no longer INLINED byte-copies -- they are now
         `require import`ed from FxChain (scheme + hop lemmas) and RtopCSoundness
         (good_fors + V_C + R_top_C + LeqPr_VF_C).  FxChain itself requires
         RtopCSoundness, so V_C is ONE module across both -- the hop-4/hop-6 p_vf
         seam is machine-checked by module identity, not byte-equality.
     (b) DISCHARGE.  Four of the six FX hops are no longer admits: they are proven
         by APPLYING the single-sourced 0-admit lemmas over the REAL game
         probabilities (the five free intermediate reals p_* are GONE, each became
         the concrete game Pr-expression it named; the SKG advantage is grounded to
         the concrete R_SKGPRF_EUFCMA_C PRF term in the RHS):
            hop1 = Pr_EUFCMA_C10_FSPRFPRFC (EUFCMA_C10 = FS_PRFPRF)          [FxChain]
            hop2 = SKGPRF_C_hop            (FS_PRFPRF <= FS_NPRFPRF + |SKG|) [FxChain]
            hop3 = IDENTITY               (mkg_adv nonneg phantom, 0<=mkg_adv premise)
            hop4 = hop4_musplit           (FS_NPRFPRF = V_C:VT + V_C:VF)     [FxChain]
            hop6a = LeqPr_VF_C            (V_C:VF <= NAGCMA(R_top_C(F),TRHC.O)) [Rtop]
     ADMIT COUNT: 6 -> 2 -> 1 -> 0 (Step 4, hop5 concretisation).  hop5 (the VT leg) is
     now DISCHARGED: GprocFORSC10.LeqPr_VT_C_proc (PROVEN CERTIFIED-0-ADMIT) is a real
     byequiv V_C(F) ~ EUF_CMA_Gproc(R_fors_p(F)) coupling into the CONCRETE procedural
     FORS+C10 game Gproc, chained with EUFCMA_Gproc (Gproc EUF-CMA <= ITSR(+C)/C10).  The
     free FORS forger A_fors is GONE -- the FORS leg is F-derived (R_fors_p(F)) and the
     abstract-M vacuity caveat is ELIMINATED (the abstract clone's fverify:=false zeroing
     no longer applies -- Gproc's verify is the concrete reconstructed-pkFORS equality).
     This file's `qed` now carries NO admit; only the ITSR(+C)/C10 hardness assumption
     (M.F.ITSRC10) and the trusted un-re-verified MM45 base .eco remain (do NOT read this
     as a from-scratch proof of SPHINCS+C10).  hop6b was DISCHARGED earlier by the CLEAN
     closure: the component theorem
     (`forall A_ht, ...`) is applied DIRECTLY at A_ht := R_top_C(F) -- so hHT and hop6a
     BOTH speak of R_top_C(F), which DISSOLVES the old gap (a) [R_top_C -> R_top
     reduction] entirely; the sole residual gap (b) [FC.O<->TRHC.O oracle clone] is
     PROVEN by RtopCSoundness.oracle_clone_hop_C (a byequiv over two distinct
     identical-code `Collection` clones, both op fc<-thfc).  The four member-audit
     premises at R_top_C(F) (R_top_C_members4 / _allnchads / _allnpkcoads / _allntrhads)
     are VERBATIM R_top->R_top_C ports (choose byte-identical), CERTIFIED-0-ADMIT in
     RtopCSoundness.  HONEST FRAMING (GPT-5.6 review 2026-07-24): the LHS -- the real
     SPHINCS+C10 advantage Pr[EUFCMA_C10(F)] -- is UNCHANGED, and the RHS is now a
     PROVEN upper bound on it whose four hypertree leaf terms are the standard +C
     4-term shape at A_ht := R_top_C(F).  This is a DIFFERENT concrete RHS from a
     hypothetical R_top(F) one and is NOT claimed numerically equal to it: the
     pre-closure capstone's R_top(F) RHS was itself never established (it sat behind
     the admitted hop6b), so there is no proven predecessor bound to compare against
     -- a genuine NEW proven bound, not a re-proof of an old one.  (Three carried
     member premises were also REMOVED -- a strengthening of the hypotheses.)  R_top_C
     draws the conditioned mk from the IDEAL `dcond` (the acknowledged mk modelling
     boundary, header (0)), so like the whole chain this is a game/probability bound;
     R_top_C's PPT-implementability is the SAME open modelling question as elsewhere,
     NOT a new gap introduced by hop6b.  The OLD 6-admit capstones
     (sphincs_c10_capstone_concrete_wip.ec, sphincs_c10_capstone_wip.ec) are kept
     intact.  hop5 is now DISCHARGED (LeqPr_VT_C_proc + EUFCMA_Gproc, 2026-07-24) -- the
     wired capstone is 0-admit.  Do NOT read the `qed` as a from-scratch proof of
     SPHINCS+C10: the carried ITSR(+C)/C10 hardness (M.F.ITSRC10, unreduced on the RHS),
     the three false-at-zero mtree_* premises, and the TRUSTED un-re-verified MM45 base
     .eco (XmssmtCC_All / FxChain / RtopCSoundness + the SPHINCS+ base axioms, loaded
     require-only) all remain.  This is a machine-checked REDUCTION to that ledger.

   ROLE = BUILD / ASSEMBLE.  States the top-level SPHINCS+C10 EUF-CMA bound in
   MM45's `EUFCMA_SPHINCS_PLUS_FX` 4-term shape (SPHINCS_PLUS.ec:4287), with the
   two paper-2022/778 Thm-5.2 +C substitutions, wired term-by-term to the PROVEN
   base-A leg theorems where one exists and ADMITTED (with a precise in-file
   residual) on each +C-transcription leg that is not yet built.

       MM45 FX term                         +C substitution (this file)
       -----------------------------------  -----------------------------------
       |SKG-PRF adv|                        |SKG-PRF adv|  (GROUNDED to the concrete
                                             R_SKGPRF_EUFCMA_C PRF term; hop2 DISCHARGED)
       |MKG-PRF adv|                        mkg_adv  (PHANTOM in-chain summand; hop3 is
                                             the identity, 0<=mkg_adv premise, NOT a hop)
       Pr[EUF_CMA_MFORSTWESNPRF ...]   -->   FORS+C10 multi bound  (M.EUFCMA_MFORSC10,
                                             FORS_C10_Multi.ec:472) EXPANDED to
                                             Pr[ITSRC10 ...] + mtree_{openpre,trh,trco}
       Pr[EUF_NAGCMA_FLSLXMSSMTTWESNPRF...] -> the +C COMPONENT THEOREM
                                             (EUFNAGCMA_FLSLXMSSMTTWCESNPRF,
                                             XmssmtCC_All.ec:8439) EXPANDED to
                                             WOTS-TW+C multi + S-TCR(+C) + pkco-TCR
                                             + trh-TCR, applied at A_ht := R_top_C(F)
                                             (2026-07-24: was R_top(F); see hop6b).

   ==========================================================================
   THE LEDGER  --  READ THIS BEFORE READING THE COMPILING THEOREM.

   This file COMPILES (typechecks) WITH ADMITS.  It is NOT an unconditional
   proof of SPHINCS+C10 EUF-CMA security.  The correct claim is:

     "SPHINCS+C10 EUF-CMA REDUCES to {the ledger below}, machine-checked modulo
      the explicitly-admitted +C-invariant MM45-transcription legs."

   Do NOT read the `qed` as "SPHINCS+C is proven".

   ------ (0) LHS NATURE  (CONCRETE in this variant) --------------------------
   RESOLVED in this file: the concrete `module SPHINCS_PLUS_C10 :
   DSSC.Stateless.Scheme` and its generic game `EUFCMA_C10(F) =
   DSSC.Stateless.EUF_CMA(SPHINCS_PLUS_C10, F, DSSC.Stateless.O_CMA_Default)` are
   INHERITED from FxChain (via require import; the pre-wiring capstone inlined
   them from sphincs_c10_scheme_wip.ec).  The capstone LHS is now
   the CONCRETE advantage `Pr[EUFCMA_C10(F).main() @ &m : res]`, NOT the abstract
   real `p_sphincs_c`.  The +C forger TYPE `Adv_EUFCMA_C` (XmssmtCC_All.ec:9428)
   is the game adversary (structural-subtypes the DSSC clone's Adv_EUFCMA).  The
   scheme is MM45 `module SPHINCS_PLUS` (SPHINCS_PLUS.ec:957) at the SAME seed sk,
   with the two Thm-5.2 substitutions ((i) FORS message key
   `mk <$ dcond dmkey (good_fors m)`, seed-based FTWES FORS; (ii) +C hypertree
   FL_SL_XMSS_MT_C_ES).  HONEST CAVEAT: `dcond` idealises the real keyed mk (mkg),
   so this LHS sits at the real-key / IDEALISED-mk level, not a genuine pre-MKG
   Orig (`ms` dead, MKG hop vacuous, signing randomised) -- see the scheme file's
   LEDGER.  What REMAINS the residual is MM45's FX PROOF over this scheme (the 6
   hops below, section-local, multi-month) -- NOT the scheme OBJECT, which now
   exists.

   ------ (1) ADMIT CENSUS  (WIRED: 6 -> 2 -> 1 -> 0) ------------------------------
   ZERO `admit` remains in this file (hop5 DISCHARGED in Step 4 via LeqPr_VT_C_proc +
   EUFCMA_Gproc).  All SIX FX hops are DISCHARGED by applying single-sourced 0-admit
   lemmas; the five free intermediate reals p_prfprf/p_nprfprf/p_nprfnprf/p_vt/p_vf are
   GONE (each became the concrete game Pr-expression it named).  Each hop, MM45 line, status:

     [DISCHARGED hop1]  EUFCMA_C10 = FS_PRFPRF (MM45 Eqv_..._Orig_FSPRFPRF
        SPHINCS_PLUS.ec:2243).  By FxChain.Pr_EUFCMA_C10_FSPRFPRFC (a byequiv
        EQUALITY, CERTIFIED-0-ADMIT).  The on-demand/materialization cube step is
        INSIDE that proven byequiv; the capstone LHS binds FxChain.EUFCMA_C10 so
        the application is exact.

     [DISCHARGED hop2]  FS_PRFPRF <= FS_NPRFPRF + |SKG-PRF| (MM45
        EqAdv_..._PRFPRF_NPRFPRF_SKGPRF SPHINCS_PLUS.ec:2668).  By
        FxChain.SKGPRF_C_hop (CERTIFIED-0-ADMIT), a SCHEME-level +C hop (covers the
        FORS+C and WOTS+C skg keys).  The SKG advantage is GROUNDED to the concrete
        R_SKGPRF_EUFCMA_C PRF-distinguishing term in the RHS.

     [hop3 IDENTITY / PHANTOM -- not an admit, not a lemma-discharge]  MM45's paid
        MKG-PRF triangle (EqAdv_..._NPRFPRF_NPRFNPRF_MKGPRF SPHINCS_PLUS.ec:3055)
        does NOT port: C10 draws mk fresh & non-memoized `<$ dcond dmkey (good_fors
        m)` on every game, so NPRFNPRF is DEFINITIONALLY NPRFPRF (p_nprfprf =
        p_nprfnprf = Pr[FS_NPRFPRF(F)]).  mkg_adv is a nonneg PHANTOM boundary
        summand kept in the bound (0<=mkg_adv premise makes the hop3 identity
        `Pr[NPRFPRF] <= Pr[NPRFPRF] + mkg_adv` machine-true).  The GENUINE MKG
        idealisation is a SEPARATE pre-hop-1 boundary term (deployed keyed-grind on
        sk_seed -> this dcond model) -- an OPEN modelling refinement, NOT this hop.
        (rtop_c_soundness_wip.ec:114-120; SPHINCS_C_c10.ec:195/210.)

     [DISCHARGED hop4]  FS_NPRFPRF = V_C:VT + V_C:VF (MM45 Eqv_..._NPRFNPRF_V
        SPHINCS_PLUS.ec:2572 + mu_split).  By FxChain.hop4_musplit (Eqv_NPRFPRF_V_C
        byequiv then Pr[mu_split] on valid_MFORSC10, CERTIFIED-0-ADMIT).  V_C is the
        SINGLE-SOURCED RtopCSoundness module -- the SAME one hop6a consumes.

     [DISCHARGED hop5 -- Step 4, VT leg]  MM45 LeqPr_..._VT_MFORSTWESNPRF
        (SPHINCS_PLUS.ec:3129).  By GprocFORSC10.LeqPr_VT_C_proc (PROVEN, byequiv
        V_C(F) ~ EUF_CMA_Gproc(R_fors_p(F))) then EUFCMA_Gproc (Gproc EUF-CMA <=
        ITSR(+C)/C10), both CERTIFIED-0-ADMIT.  The former residual (a reduction
        Adv_EUFCMA_C -> M.Adv_EUFCMA_MFORSC10 over a CONCRETE procedural FORS+C game,
        vs the abstract clone whose mkeygen/fverify were unconstrained --
        rtop_c_vt_wip.ec Wave-9/10) is now BUILT: the reduction is R_fors_p (F-derived),
        the concrete game is Gproc, and the ITSR-C10 coupling is EUFCMA_Gproc.

     [DISCHARGED hop6a]  V_C:VF <= NAGCMA(R_top_C(F), TRHC.O).  By
        RtopCSoundness.LeqPr_VF_C -- now CERTIFIED-0-ADMIT (the whole VF leg,
        Eqv_Orig_RV_C + R6a/R6b/R6c consume, is PROVEN; MM45 LeqPr_..._VF :3468).
        [NB: earlier capstone drafts noted LeqPr_VF_C "modulo ONE admit :966" -- that
        is STALE; RtopCSoundness re-certifies 0-admit under `ec-certify`.]

     [DISCHARGED hop6b -- 2026-07-24, the CLEAN closure]  Was THE SUBSTANTIVE
        RESIDUAL.  LeqPr_VF_C (hop6a) lands on `Pr[NAGCMA(R_top_C(F), TRHC.O)]`.  The
        OLD hop6b bridged that to `Pr[NAGCMA(R_top(F), FC.O)]`, bundling (a) the
        R_top_C -> R_top reduction [distinct mk-distributions] AND (b) the FC.O<->TRHC.O
        oracle clone.  CLEAN closure: apply the component theorem (`forall A_ht`)
        DIRECTLY at A_ht := R_top_C(F), so hHT consumes `Pr[NAGCMA(R_top_C(F), FC.O)]`
        and gap (a) DISSOLVES entirely (never reduce R_top_C to R_top).  The sole
        residual gap (b) is PROVEN by RtopCSoundness.oracle_clone_hop_C
        `Pr[NAGCMA(R_top_C(F),TRHC.O)] <= Pr[NAGCMA(R_top_C(F),FC.O)]`: FC and
        FSSLXMTWES.TRHC are DISTINCT `Collection` clones BOTH binding op fc<-thfc /
        get_diff<-size, so O_THFC_Default.query coincides -- an honest byequiv
        reconciliation (NOT sim; glob differs), non-vacuous (pp coupling load-bearing).
        The four member-audit premises at R_top_C(F) are VERBATIM R_top->R_top_C ports
        (choose byte-identical), CERTIFIED-0-ADMIT in RtopCSoundness.  [The pre-closure
        note that this restatement "is strictly worse / needs a nonexistent R_top_C
        variant of R_top_members4" is SUPERSEDED: that port now exists and is proven.]

   NOTE ec-certify: admit-tactics=0, axiom-decls=0 (Step 4).  Hops 1/2/4/5/6a/6b are
   ALL machine-discharged by applying proven lemmas (hop5 = LeqPr_VT_C_proc + EUFCMA_Gproc,
   both CERTIFIED-0-ADMIT); hop3 is the machine-true identity + nonneg phantom.  The
   ledger records ZERO admit -- only the carried ITSR(+C)/C10 term + mtree premises remain
   (see (2)/(3)), which are hypotheses/assumptions, NOT admits.

   ------ (2) CARRIED PREMISES (this lemma's hypotheses -- NOT admits) ---------
   These are genuine assumptions, threaded to the proven legs, kept as premises
   (NEVER admits) because they are load-bearing and, for mtree_*, FALSE-AT-ZERO:
     * c <= p_tgts                              (WOTS+C target-count side-cond)
     * encode-compat  encode_msgWOTS_C = encode_msgWOTS o ThC   (definitional)
     * emb_tw disjointness + injectivity        -- **NO LONGER CARRIED** (2026-07-25).
       ===== THE VACUITY DEFECT AND ITS REPAIR (read this before citing) =====
       HISTORY.  This capstone used to carry BOTH
         hembdisj : forall a b, valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)
         hembinj  : forall a b, get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b)
                             => get_wgpidxs a = get_wgpidxs b
       and that pair is **JOINTLY CONTRADICTORY**: emb_tw (WOTS_C_Real.ec:80) writes
       only val-indices 0,1 -- which get_wgpidxs = drop 2 (WOTS_TW_ES.ec:389)
       DISCARDS -- and index 3 to the CONSTANT pkcotype, so emb_tw is IDEMPOTENT on
       the get_wgpidxs projection.  Instantiating hembinj at (a, emb_tw a) gives
       get_wgpidxs a = get_wgpidxs (emb_tw a), which hembdisj forbids for valid a
       (and such an a exists: PROVEN nonvac_guard, WOTS_C_Real.ec:140).  Machine
       witness: scratch/synth_exact_prefix_vacuity.ec, CERTIFIED-0-ADMIT (negative
       control scratch/synth_negctl.ec correctly FAILS).  The capstone as then
       stated was therefore **VACUOUSLY TRUE** and established nothing.
       REPAIR (2026-07-25) -- an ELIMINATION, not a guard:
         * hembinj is DELETED everywhere (WOTS_C_Interactive.ec, XMSSMT_C_Reduction.ec,
           XmssmtCC_All.ec, here).  The obligation it served (`uniq (map emb_tw
           twsOraw)`) is now discharged by the THEOREM `emb_dist_valid`, fed the
           PROVEN GAME INVARIANT `R_ts_allvalid`: every S-TCR(+C) target the
           reduction registers sits at a VALID WOTS address, because the signing
           oracle's interface type is `wadrs = WAddress.sT` (a Subtype clone at
           P <- valid_wadrs), so the adversary cannot express an invalid one.
           On valid addresses the injectivity is itself a THEOREM
           (`hembinj_repaired`) -- nth3_valid puts `chtype` at val-index 3, so
           emb_tw genuinely changes it and the idempotence disappears.
         * hembdisj is DISCHARGED here by the PROVEN theorem `emb_disj_concrete`
           (WOTS_C_Real.ec:153); the component theorem still carries it (it is
           genuinely consumed inside interactive_hop2 via disj_wgpidxs_transfer)
           but it is a theorem, hence satisfiable, hence non-vacuity-safe.
       RESULT: the emb_tw axis is PREMISE-FREE at this capstone -- STRICTLY FEWER
       hypotheses than the vacuous version, same conclusion, and the remaining
       premise set is SATISFIABLE (see the SATISFIABILITY RECEIPT block below).
       THE RECEIPT THAT THE DEFECT IS GONE is not the green compile: it is that
       scratch/synth_exact_prefix_vacuity.ec can no longer be stated against this
       file's premises, because the premises it contradicts no longer exist.
       (scratch/synth_recoverable_unconditional.ec, RECOVERABLE_UNCONDITIONAL --
       the premise-free fallback bound cited during the vacuous period -- remains
       valid and compiling; it is now a weaker sibling, not the thing to cite.)

       ===== SATISFIABILITY RECEIPT (the gate a green compile does NOT give) =====
       This whole repair exists because a CERTIFIED-0-ADMIT theorem turned out
       VACUOUS, so "it compiles" is NOT evidence.  The receipts, all machine-run:
         [R1] scratch/synth_repaired_nonvacuity.ec, CANARY1 + CANARY2: take THIS
              lemma's post-repair premise list VERBATIM and re-run the exact attack
              that killed the old statement (derive `false`; derive
              `Pr[EUFCMA_C10(F)] <= -1%r`).  BOTH MUST BE **REJECTED** by the gate.
              A green compile of that file is a REGRESSION, not a success.
         [R2] same file, P1/P2/P3: the emb_tw axis is now carried by THEOREMS
              (emb_disj_concrete; hembinj_repaired), and they COEXIST at a
              witnessed valid address -- the direct contrast with the old pair,
              which had no model at all.
         [R3] same file, P4/P5: the replacement premise `all valid_wadrs l` is
              LIVE AT SIZE 2, i.e. at a two-element list with genuinely DISTINCT
              group prefixes -- NOT merely at a singleton, where the lemma it
              feeds (emb_dist_valid) would be vacuously true.
         [R4] in-file below: `capstone_emb_axis_premise_free` and
              `capstone_real_premises_satisfiable` -- the emb_tw obligation the
              component theorem still names is discharged by a theorem, and the
              two REAL-valued premises (0<=mkg_adv, the H-TREE-MULTI bound) are
              JOINTLY satisfiable at concrete values.
       HONEST RESIDUAL: the remaining six premises (c<=p_tgts, encode-compat, the
       four dfC0 width facts) are conditions on ABSTRACT MODEL CONSTANTS (p_tgts is
       declared with only `0 <= p_tgts`; dfC0 = size (emb_in witness) over the
       abstract op emb_in), not on universally-quantified variables of this lemma,
       so they cannot be instantiated from inside the theory and their joint
       satisfiability is argued, not machine-proved.  They are UNCHANGED inherited
       premises -- they predate and are orthogonal to the vacuity defect -- and
       [R1] shows they do not (obviously) entail false.  This is a weaker claim
       than the emb_tw axis, and is stated as such deliberately.
       TWO FURTHER HONESTY POINTS (raised in the 2026-07-25 external review and
       verified):
         (i) SATISFIABLE is not TRUE-FOR-EVERY-INTERPRETATION.  `p_tgts` is
             declared `const p_tgts : { int | 0 <= p_tgts }` (WOTS_C_Real.ec:183),
             so `p_tgts = 0` is a PERMITTED interpretation and would FALSIFY
             `c <= p_tgts` (c >= 1 via FL_SL_XMSS_MT_ES ge1_c).  The premise is
             therefore a genuine side condition that a concrete C10
             instantiation must discharge -- it is not free.  A consistent
             interpretation exists (take p_tgts := c), which is what
             satisfiability means here.
        (ii) A REJECTED canary shows only that the SELECTED TACTICS do not derive
             a contradiction; it is not a consistency proof.  The repository
             contains no machine-checked model simultaneously interpreting all
             the remaining abstract constants.  Treat [R1] as strong evidence,
             not as a proof of consistency.

     * dfC0 <> {8n, 8n*len, 8n*2, 8n*k}          (C10 serialisation-width facts; the
                                                 8n*k fact bridges all four member axes
                                                 at R_top_C(F))
     * allnchads / allnpkcoads / allntrhads     (NO LONGER carried -- as of 2026-07-24
                                                 all FOUR choose-audit member axes at
                                                 A_ht := R_top_C(F) are DISCHARGED
                                                 in-proof via the PROVEN ports
                                                 RtopCSoundness.R_top_C_allnchads /
                                                 _allnpkcoads / _allntrhads / _A_wf_ht.
                                                 Removing these three hypotheses is a
                                                 STRENGTHENING.)
     * H-TREE-MULTI (mtree_openpre+mtree_trh+mtree_trco premise) -- FALSE-AT-ZERO:
       EUFCMA_MFORSC10's header shows a bare bound collapses under a mtree_*<-0
       clone, so this MUST be a hypothesis, never an admit (FORS_C10_Multi.ec:469).

   ------ (3) CARRIED ASSUMPTIONS  (the inherited ledger; EMPIRICALLY PROBED) ---
   EasyCrypt has no `Print Assumptions`; the closure = `grep '^axiom'` over the
   transitive require set (13 .ec/.eca files: SPHINCS_PLUS + XmssmtCC_All +
   WOTS_C_{Real,Scheme,Interactive,Reduction} + XMSSMT_C_Scheme + FORS_C10{,_Multi}
   + STCR_C + Grind + the MM45 base FORS_ES / FL_SL_XMSS_MT_ES / WOTS_TW_ES /
   KeyedHashFunctions / TweakableHashFunctions).  Split by kind:

   [carried PROBABILITY TERM -- not an axiom]
     * ITSRC10  -- THE HEADLINE, the ~102-bit-gap FORS+C10 interleaved-target
       subset-resilience hardness.  `Pr[M.F.ITSRC10 ...]` appears UNREDUCED on
       the RHS (honest conditional; FORS_C10_Multi.ec:455).  FOREGROUND THIS.
     * SKG/MKG-PRF -- the two PRF advantages (skg_adv/mkg_adv abstract reals).

   [carried PREMISES of this lemma -- not axioms; see (2)]
     * mtree_* (H-TREE-MULTI, false-at-zero), c<=p_tgts, encode-compat, 0<=mkg_adv,
       dfC0 facts (now incl. 8n*k).  (The 3 member hoare premises are NO LONGER
       carried -- discharged at R_top_C(F) via the proven ports.  The emb_tw
       disj/inj PAIR is NO LONGER carried either -- see (2): inj ELIMINATED as
       contradictory, disj DISCHARGED via emb_disj_concrete.)
     * CORRECTION 2026-07-25 (claim-vs-code drift, found in adversarial review):
       this ledger previously listed `emb_in_len` / `emb_in_inj`
       (WOTS_C_Interactive.ec:369-375) as carried premises of THIS lemma.  THEY ARE
       NOT.  Neither appears in this capstone's signature nor in the component
       theorem's; they are premises of the WOTS+C FAITHFULNESS lemmas only, and the
       capstone chain never applies those lemmas.  Removed from the ledger.

   [LIVE easycrypt `axiom` decls in the closure]
     * good_pos (= p_nu, FORS_C10.ec:208) -- positive good-counter mass; carried
       by clone M, load-bearing for FORS+C10 oracle losslessness.  (2nd headline.)
     * FORS+C10 structural g-axioms size_g/eqiks_g/neqisvs_g/rng_g/uniq_g +
       dmkey_ll (FORS_C10.ec:149-208) -- FORS+C10 model surface carried by clone M
       (all DISCHARGEABLE at the concrete FTWES instance -- good_clone_probe.ec
       realises them by exact -- but ABSTRACT here since M has no `with`).
     * STCR_C.dpp_ll (STCR_C.ec:53) -- lossless S-TCR(+C) public-parameter draw.
     * MM45 BASE security-model axioms (the accepted SPHINCS+ foundation,
       inherited, not re-litigated): SPHINCS_PLUS.dist_adrstypes (:111);
       WOTS_TW_ES.{ch0,chS} (:504/511, the WOTS chaining fn), .two_encodings
       (:572), .valid_widxvals_idxvals (:339); FORS_ES/FL_SL_XMSS_MT_ES
       .dist_adrstypes + .valid_{f,x}idxvals_idxvals; TweakableHashFunctions
       .in_collection (:567).  (KeyedHashFunctions.eca contributes 0 live axioms
       in the current closure -- earlier drafts over-listed a g-extractor axiom.)
     * CntrFT.enum_spec = FinType.enum_spec (Grind.ec:35, STCR_C.ec:61) -- the
       STANDARD EasyCrypt finite-type enumeration-completeness fact for the C10
       32-bit counter; a library modelling fact, not a bespoke assumption.

   [checked ABSENT as live axioms]
     * grindP (Grind.ec) -- was App-D gap#1; REPLACED by a total finite-search
       operational model (Grind.ec header) -- 0 live axioms there.  Absent.
     * XmssmtCC_All / WOTS_C_Real "axiom ..." grep hits are COMMENT prose, not
       decls (the component theorem certifies 0-axiom, XmssmtCC_All.ec:8503).

   ------ (4) FAITHFULNESS NOTE  (single-adversary -- NOW CLOSED both sides) ----
   MM45 has ONE shared forger A giving every RHS `R_x(A)`.  BOTH sides are now
   F-derived: the HYPERTREE side is A_ht := R_top_C(F) (RtopCSoundness.ec:138), and
   (Step 4) the FORS side is A_fors := R_fors_p(F) (GprocFORSC10, the VT reduction) --
   the former FREE `M.Adv_EUFCMA_MFORSC10` is GONE.  The single-adversary caveat that
   SPHINCS_C_c10.ec:93-100 flagged for the FORS leg is CLOSED here.
   ========================================================================== *)

require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.
(* WIRED SEAM (2026-07-24): require the two +C layers so the LHS scheme-game, the
   V_C seam, and the discharged hops are SINGLE-SOURCED (no longer re-inlined):
     RtopCSoundness -> good_fors, V_C (EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V),
                       R_top_C, and hop-6 lemma LeqPr_VF_C.
     FxChain        -> DSSC, SPHINCS_PLUS_C10, EUFCMA_C10 (the capstone LHS),
                       the FS_PRFPRF/FS_NPRFPRF games, and hops
                       Pr_EUFCMA_C10_FSPRFPRFC / SKGPRF_C_hop / hop4_musplit.
   FxChain itself requires RtopCSoundness, so V_C is ONE module across both files
   -- the p_vf term produced by hop4 (FxChain) and consumed by hop6a (RtopCSoundness)
   is now bridged by module identity, machine-checked, not byte-equality. *)
require import RtopCSoundness.
require import FxChain.
(* WIRED (Step 4, hop5 concretisation): the procedural FORS+C10 game Gproc, its
   EUF-CMA<=ITSRC10 bound (EUFCMA_Gproc), the VT coupling (LeqPr_VT_C_proc, PROVEN
   CERTIFIED-0-ADMIT), and the F-derived reductions R_fors_p / R_ITSRC10_Gproc.  Its
   clone `M` (= FORS_C10_Multi.MFORSC10 onto the CONCRETE FTWES instance) REPLACES the
   capstone's former abstract `clone ... as M` -- this is what eliminates the abstract-M
   vacuity caveat: the FORS leg's ITSRC10 term is now over the concrete Gproc game with an
   F-derived adversary R_fors_p(F), not a free A_fors against an abstract game. *)
require import GprocFORSC10.
require FORS_C10 FORS_C10_Multi.
require DigitalSignatures.
require import BitEncoding. import BS2Int BitChunking.
(* Mirror XmssmtCC_All's own import preamble so the reduction/oracle names the
   component theorem and R_top mention (R_int_STCRC, R_int_WOTSTW, O_THFC_MA, dfC0,
   M_EUF_GCMA_WOTSTWESNPRF, STCRC_WC, encode_msgWOTS_C, ThC, emb_tw, ...) resolve. *)
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.

(* FORS+C10 multi leg.  `M` is now GprocFORSC10.M (required above) -- the CONCRETE
   FORS_C10_Multi.MFORSC10 clone onto FTWES, carrying the ITSR(+C)/C10 assumption game
   `M.F.ITSRC10`.  The former local abstract `clone FORS_C10_Multi.MFORSC10 as M` (no
   `with`) was DELETED (Step 4): the abstract clone is exactly what let `fverify:=false`
   zero the FORS bound (the vacuity caveat); the concrete Gproc chain removes it. *)

(* ==========================================================================
   VT-SIDE `good` BRIDGE  (the good_clone wiring the GOAL names).

   The abstract FORS+C predicate machinery (FORS_C10.FORSC10's `good`/predC_fors)
   instantiated onto the base's CONCRETE FORS clone FTWES, so the abstract clone
   `good` and the concrete `good_fors` (= predC_fors unfolded on FTWES.g/FTWES.mco,
   the C10 forced-last-leaf-0 gate the V_C forgery check uses) become the SAME op.
   INLINED VERBATIM from good_clone_probe.ec (lowercase -> un-requireable); the
   five g-axioms DISCHARGE from FTWES's structured `g`, so clone C adds NO new
   assumption beyond C.good_pos (= the SAME p_nu as good_pos, re-typed at the
   concrete FTWES.mco/g/dmkey).  good_eq_good_fors is the proven sub-fact the VT
   hop (hop5) relies on; the remaining VT reduction is hop5's residual.
   ========================================================================== *)
(* good_fors -- SINGLE-SOURCED, inherited from RtopCSoundness (via FxChain); the
   inline byte-copy was deleted 2026-07-24 (diff-confirmed identical).  clone C
   below realizes C.good = predC_fors, and good_eq_good_fors relates it to THIS
   inherited good_fors -- the hop-5 good-bridge sub-fact. *)

lemma ftw_size_g (y : FTWES.msgFORSTW * index) : size (FTWES.g y) = k.
proof. by rewrite /FTWES.g /= size_mkseq; smt(ge1_k). qed.
lemma ftw_eqiks_g (x x' : int * int * int) (y : FTWES.msgFORSTW * index) :
  x \in FTWES.g y => x' \in FTWES.g y => x.`1 = x'.`1.
proof. by rewrite /FTWES.g /= => /mkseqP [i [_ ->]] /mkseqP [j [_ ->]] /=. qed.
lemma ftw_neqisvs_g (x x' : int * int * int) (y : FTWES.msgFORSTW * index) :
  x \in FTWES.g y => x' \in FTWES.g y => x <> x' => x.`2 <> x'.`2.
proof. by rewrite /FTWES.g /= => /mkseqP [i [_ ->]] /mkseqP [j [_ ->]] /=; smt(). qed.
lemma ftw_rng_g (y : FTWES.msgFORSTW * index) (x : int * int * int) :
  x \in FTWES.g y => 0 <= x.`3 < t.
proof.
rewrite /FTWES.g /= => /mkseqP [i [rng_i ->]] /=.
split; 1: exact bs2int_ge0.
move => _.
have ha : 0 < a by smt(ge1_a).
have szc : size (nth witness (chunk a (FTWES.BLKAL.val y.`1)) i) = a.
- apply: (in_chunk_size a (FTWES.BLKAL.val y.`1)
                     (nth witness (chunk a (FTWES.BLKAL.val y.`1)) i) ha).
  apply/mem_nth.
  rewrite (size_chunk a _ ha) FTWES.BLKAL.valP.
  smt(ge1_a).
have -> : t = 2 ^ a by rewrite /t.
have hlt := bs2int_le2Xs (rev (nth witness (chunk a (FTWES.BLKAL.val y.`1)) i)).
rewrite size_rev szc in hlt.
exact hlt.
qed.
lemma ftw_uniq_g (y : FTWES.msgFORSTW * index) :
  uniq (map (fun (x : int * int * int) => x.`2) (FTWES.g y)).
proof.
rewrite /FTWES.g /= map_mkseq /mkseq map_inj_in_uniq 2:iota_uniq.
move => u v _ _ /=. smt().
qed.

(* clone with the five g-axioms + ge1_k/ge1_a/dmkey_ll DISCHARGED; good_pos
   carried un-realized -> C.good_pos (concrete-instance p_nu). *)
clone FORS_C10.FORSC10 as C with
  type mkey <- mkey, type msg <- msg, type out_t <- FTWES.msgFORSTW * index,
  op k <- k, op a <- a, op dmkey <- dmkey, op mco <- FTWES.mco, op g <- FTWES.g
  proof ge1_k, ge1_a, dmkey_ll, size_g, eqiks_g, neqisvs_g, rng_g, uniq_g.
  realize ge1_k     by exact: ge1_k.
  realize ge1_a     by exact: ge1_a.
  realize dmkey_ll  by exact: dmkey_ll.
  realize size_g    by exact: ftw_size_g.
  realize eqiks_g   by exact: ftw_eqiks_g.
  realize neqisvs_g by exact: ftw_neqisvs_g.
  realize rng_g     by exact: ftw_rng_g.
  realize uniq_g    by exact: ftw_uniq_g.

(* THE PAYOFF: the abstract clone `good` IS the concrete C10 forgery-gate
   `good_fors` -- provable and definitional-by-clone (good_clone_probe.ec:140). *)
lemma good_eq_good_fors (m : msg) (mk : mkey) : C.good m mk = good_fors m mk.
proof. by rewrite /C.good /C.predC_fors /good_fors. qed.

(* ==========================================================================
   CONCRETE-LHS  --  SINGLE-SOURCED, inherited from FxChain (via require import).
   The scheme object `SPHINCS_PLUS_C10 : DSSC.Stateless.Scheme`, the fresh
   `DigitalSignatures as DSSC` clone at the +C signature type, and the generic
   game `EUFCMA_C10(F) = DSSC.Stateless.EUF_CMA(SPHINCS_PLUS_C10, F, O_CMA_Default)`
   were inline byte-copies here in the pre-wiring capstone; deleted 2026-07-24
   (scheme diff-confirmed code-identical modulo comments, DSSC byte-identical).
   The capstone LHS `Pr[EUFCMA_C10(F).main() @ &m : res]` now binds FxChain's
   EUFCMA_C10 -- EXACTLY the game hop-1 (Pr_EUFCMA_C10_FSPRFPRFC) is stated about,
   so hop-1 discharges by APPLICATION, not by re-proof.  Honesty caveats (real skg
   keys + IDEALISED-mk via dcond; `ms` dead, MKG hop vacuous, signing randomised;
   good_fors gate in verify; NO new axiom) are unchanged -- see FxChain's scheme
   header + THE LEDGER (0) above.
   ========================================================================== *)

(* ==========================================================================
   THE CAPSTONE THEOREM  (CONCRETE-LHS variant).
   ========================================================================== *)
lemma EUFCMA_SPHINCS_PLUS_C10
  (* The top SPHINCS+C10 EUF-CMA forger.  The bound is stated per-forger F;
     the hypertree term below is F-derived (R_top_C(F); 2026-07-24, was R_top(F)). *)
  (F <: Adv_EUFCMA_C{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V, -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default,
             -R_top,
             (* WIRED (2026-07-24): additional separations required by the APPLIED hop
                lemmas (Pr_EUFCMA_C10_FSPRFPRFC / SKGPRF_C_hop / hop4_musplit /
                LeqPr_VF_C).  Standard reduction well-formedness -- F is a proof-external
                forger disjoint from the internal game/reduction states; NOT a weakening
                of the bound (the current 6-admit capstone omitted them only because it
                never applied the hops). *)
             -DSSC.Stateless.O_CMA_Default, -O_CMA_SPHINCSPLUSTWC_FS,
             -SKG_PRF.O_PRF_Default, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V,
             -R_top_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV,
             (* WIRED (Step 4): the FORS/VT leg is now F-DERIVED via R_fors_p(F) into
                the concrete Gproc game; F must be disjoint from the Gproc game/reduction
                states (LeqPr_VT_C_proc + EUFCMA_Gproc(R_fors_p(F)) well-formedness). *)
             -R_fors_p, -O_CMA_Gproc, -O_CMA_Gproc_I, -R_ITSRC10_Gproc,
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default })
  (* WIRED (Step 4): the free FORS forger `A_fors` is REMOVED -- the FORS leg is now
     F-derived (R_fors_p(F)) against the CONCRETE Gproc game, so the bound is per-F only.
     This is the concretisation that eliminates the abstract-M vacuity caveat. *)
  (* WIRED (2026-07-24): the SKG-PRF advantage and the FIVE +C intermediate game
     probabilities (p_prfprf/p_nprfprf/p_nprfnprf/p_vt/p_vf) are NO LONGER free
     reals.  Hops 1/2/4 and the hop-6 leg (6a) are discharged by APPLYING the proven
     single-sourced lemmas, so each intermediate became the concrete game Pr-expression
     it names (FS_PRFPRF, FS_NPRFPRF, V_C:VT, V_C:VF) and the SKG term became the
     concrete R_SKGPRF_EUFCMA_C PRF-distinguishing advantage in the RHS.  This is a
     GROUNDING (same magnitude, now named), not a weakening.  mkg_adv STAYS a free
     real: it is the phantom in-chain MKG boundary term (hop-3, header (1)), nonneg by
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
    0%r <= mkg_adv =>
    (* ---- 2026-07-25 VACUITY REPAIR: BOTH emb_tw premises are GONE from this
       statement.  The injectivity half was CONTRADICTORY with the disjointness
       half (see the header note), making the whole capstone VACUOUS; it is now
       ELIMINATED upstream -- the component theorem no longer has it, and the
       `dist` obligation is discharged from the PROVEN game invariant
       R_ts_allvalid.  The disjointness half is DISCHARGED here by the PROVEN
       theorem `emb_disj_concrete` (WOTS_C_Real.ec:153), not carried.  Net: the
       emb_tw axis is PREMISE-FREE at this capstone -- strictly fewer hypotheses
       than before, and (unlike before) a SATISFIABLE premise set. ---- *)
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    (* N2 = "the +C grind always finds a good counter" -- App-D gap #1, historically
       named `grindCP`.  IT REACHES THE CAPSTONE, and that is not an accident: the
       P-relativized fork retired MM45's two encoding axioms by GATING the WOTS-TW
       game on `P m /\ P m'`, which makes grind-success load-bearing (the queried
       message on the reduction side is `ThC ps ad m (grindC ps ad m)`).  Carried
       from interactive_D1_MA up through XmssmtCC_All to here.
       NOT discharged by `P_inhabited` / `targetSumReachable` -- those are the weak
       `exists d, predC d` shape.  See base-c10-fork/WOTS_TW_ES.ec. *)
    (forall (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock),
       exists (cc : cntr), predC (ThC ps0 ad0 m0 cc)) =>
    dfC0 <> 8 * n =>
    dfC0 <> 8 * n * len =>
    dfC0 <> 8 * n * 2 =>
    dfC0 <> 8 * n * k =>   (* 4th C10 width fact: bridges all FOUR member axes at R_top_C(F) *)
    (* ---- NOTE (2026-07-24 hop6b closure): the three choose-audit member premises
            (chtype / pkco / trh axes) at R_top_C(F) that the component theorem needs
            are NO LONGER carried here -- they are DISCHARGED in-proof via the PROVEN
            ports RtopCSoundness.R_top_C_allnchads / _allnpkcoads / _allntrhads (and the
            O_THFC_MA member axis via R_top_C_A_wf_ht / R_top_C_members4).  Removing
            three hypotheses is a STRENGTHENING of the theorem, not a weakening. ---- *)
    (* ---- FORS+C10 H-TREE-MULTI premise (FALSE-AT-ZERO -- must be a premise).
            NOW over the CONCRETE Gproc instrumented game with the F-derived reduction
            R_fors_p(F) (was M.EUF_CMA_MFORSC10_I(A_fors) against the abstract game). ---- *)
    (   Pr[EUF_CMA_Gproc_I(R_fors_p(F)).main() @ &m
             : res /\ !EUF_CMA_Gproc_I.covered]
     <= mtree_openpre + mtree_trh + mtree_trco) =>

    (* ---- CONCLUSION: the MM45 FX 4-term bound, +C-substituted and EXPANDED.
            LHS RE-GROUNDED: the CONCRETE scheme-game advantage (was p_sphincs_c). ---- *)
    Pr[EUFCMA_C10(F).main() @ &m : res]
      (* +C SKG-PRF advantage: GROUNDED (was the free real skg_adv) to the exact
         concrete R_SKGPRF_EUFCMA_C PRF-distinguishing term that hop-2 (SKGPRF_C_hop)
         delivers. *)
      <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
           - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
       + mkg_adv
       (* +C subst #1: FORS+C10 CONCRETE expansion.  The ITSR(+C)/C10 term is now over
          the F-DERIVED reduction R_ITSRC10_Gproc(R_fors_p(F)) (was the free
          M.R_ITSRC10_MFORSC10(A_fors)) -- delivered by LeqPr_VT_C_proc (PROVEN) then
          EUFCMA_Gproc.  Same carried M.F.ITSRC10 hardness assumption; now concrete. *)
       + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(F)),
                          M.F.O_ITSRC10_Default).main() @ &m : res]
           + mtree_openpre + mtree_trh + mtree_trco )
       (* +C subst #2: hypertree COMPONENT THEOREM expansion at A_ht := R_top_C(F)
          (2026-07-24 hop6b CLEAN closure: applied DIRECTLY at R_top_C(F), so gap
          (a) R_top_C -> R_top is DISSOLVED; the four leaf terms keep the STANDARD +C
          shape -- WOTS-TW+C multi / S-TCR(+C) / pkco-TCR / trh-TCR -- now at
          R_top_C(F).  This is a PROVEN upper bound on the UNCHANGED LHS; the four
          terms are a DIFFERENT concrete RHS from a hypothetical R_top(F) one, not
          claimed numerically equal (see header (1)).  LeqPr_VF_C already lands on
          R_top_C(F), so the sole reconciliation is the FC.O<->TRHC.O oracle-clone
          hop, discharged by RtopCSoundness.oracle_clone_hop_C. ITSRC10 stays fg). *)
       + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                      O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(F)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(F)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res] ).
proof.
  move=> hc hmkg hencb hN2 hdf8n hdflen hdf2 hdfnk htree.
  (* ---- member axes at A_ht := R_top_C(F): ALL FOUR DISCHARGED via the PROVEN
     ports (RtopCSoundness, 2026-07-24 hop6b closure).  A_wf_ht (member/dfC0 axis) via
     R_top_C_A_wf_ht (= R_top_C_members4 collapsed by all_in_thfc4_neq_dfC); the
     chtype/pkco/trh axes via R_top_C_allnchads/_allnpkcoads/_allntrhads.  Each is a
     VERBATIM R_top->R_top_C port (choose is byte-identical).  These replace the three
     hypotheses the pre-closure capstone carried -- now proven, so removed from the
     statement (a STRENGTHENING). *)
  have A_wf_ht     := R_top_C_A_wf_ht     F hdf8n hdflen hdf2 hdfnk.
  have allnchads   := R_top_C_allnchads   F.
  have allnpkcoads := R_top_C_allnpkcoads F.
  have allntrhads  := R_top_C_allntrhads  F.
  (* ---- hypertree term: PROVEN via the +C COMPONENT THEOREM applied DIRECTLY at
     A_ht := R_top_C(F) -- the CLEAN hop6b closure that DISSOLVES gap (a). ---- *)
  (* the component theorem still CARRIES the disjointness premise (it is genuinely
     consumed inside interactive_hop2 via disj_wgpidxs_transfer); it is DISCHARGED
     here by the PROVEN theorem emb_disj_concrete, so the capstone carries neither
     half of the former emb_tw pair. *)
  have hHT := EUFNAGCMA_FLSLXMSSMTTWCESNPRF (R_top_C(F)) &m hc emb_disj_concrete hencb hN2
                hdf8n hdflen hdf2 A_wf_ht allnchads allnpkcoads allntrhads.
  (* ---- FORS+C10 term: bounded via M.EUFCMA_MFORSC10 (conditional on htree) ---- *)
  (* !! WAVE-9/10 CAVEAT (2026-07-21, machine-checked drafts/rtop_c_vt_wip.ec + Wave-10
     probes): hF ITSELF is a GENUINE MEANINGFUL bound (accept-all probe + negative
     control: no hidden fverify-hypothesis; content = ITSRC10 + load-bearing mtree
     premise). The GAP is the hop5 SEAM: M's fverify/mkeygen are UNCONSTRAINED
     (fverify:=false zeroes Pr[RHS]; M.mkeygen cannot couple to V_C's ps-independent
     cube, D2), so LeqPr_VT_C cannot connect p_vt to the ABSTRACT game. FIX = a CONCRETE
     PROCEDURAL M-FORS+C game (procedural keygen matching V_C + concrete sign + verify by
     reconstructed-pkFORS eq + predC_fors) + hop5 over it. FORS leg CONDITIONAL on that.
     (Hypertree leg unaffected -- concrete NAGCMA win.) *)
  have hF := EUFCMA_Gproc (R_fors_p(F)) mtree_openpre mtree_trh mtree_trco &m htree.

  (* ======================================================================
     FX SKELETON (WIRED 2026-07-24) -- the MM45 game hops.  Hops 1/2/4 and the
     hop-6 leg (6a) are now DISCHARGED by APPLYING the proven, single-sourced
     lemmas (Pr_EUFCMA_C10_FSPRFPRFC / SKGPRF_C_hop / hop4_musplit / LeqPr_VF_C);
     the five intermediate p_* reals are gone, each replaced by the concrete game
     Pr-expression it named.  hop6b is now ALSO DISCHARGED (2026-07-24): applying the
     component theorem at R_top_C(F) dissolved gap (a), and gap (b) is the proven
     oracle-clone hop (RtopCSoundness.oracle_clone_hop_C).  hop5 (VT leg) is now ALSO
     DISCHARGED (Step 4): LeqPr_VT_C_proc + EUFCMA_Gproc.  hop3 (identity/phantom) is the
     only non-lemma step -- a machine-true identity + nonneg phantom, NOT an admit.  ZERO
     admit remains.
     ====================================================================== *)

  (* hop1  DISCHARGED  EUFCMA_C10 = FS_PRFPRF.
     FxChain.Pr_EUFCMA_C10_FSPRFPRFC -- a byequiv EQUALITY (the +C analog of MM45
     Eqv_..._Orig_FSPRFPRF, SPHINCS_PLUS.ec:2243); the on-demand/materialization
     cube step is INSIDE that proven byequiv.  LHS = the capstone's concrete LHS. *)
  have hop1 := Pr_EUFCMA_C10_FSPRFPRFC F &m.

  (* hop2  DISCHARGED  FS_PRFPRF <= FS_NPRFPRF + |SKG-PRF|.
     FxChain.SKGPRF_C_hop (CERTIFIED-0-ADMIT), the +C analog of MM45
     EqAdv_..._PRFPRF_NPRFPRF_SKGPRF (SPHINCS_PLUS.ec:2668).  The SKG term is the
     concrete R_SKGPRF_EUFCMA_C PRF-distinguishing advantage now in the RHS. *)
  have hop2 := SKGPRF_C_hop F &m.

  (* hop3  IDENTITY / PHANTOM  (NOT a lemma-discharge; NOT in the {1,2,4,6a} set).
     +C FINDING (3-review-converged, FxChain header): the in-chain MKG-PRF hop is the
     IDENTITY -- C10 draws mk <$ dcond dmkey (good_fors m) fresh & non-memoized on
     every game, so NPRFNPRF is DEFINITIONALLY NPRFPRF and MM45's paid |MKG-PRF|
     triangle (SPHINCS_PLUS.ec:3055) does not port.  p_nprfprf = p_nprfnprf = the SAME
     term Pr[FS_NPRFPRF(F)]; mkg_adv is a nonneg PHANTOM boundary summand (the separate
     pre-hop-1 deployed-grind -> idealised-dcond term), kept in the bound but NOT a
     discharged reduction.  Proven from the `0 <= mkg_adv` premise (hmkg) -- pure
     arithmetic, NOT an smt-forced discharge of a real hop. *)
  have hop3 : Pr[EUF_CMA_SPHINCSPLUSTWC_FS_NPRFPRF(F).main() @ &m : res]
              <= Pr[EUF_CMA_SPHINCSPLUSTWC_FS_NPRFPRF(F).main() @ &m : res] + mkg_adv
    by smt().

  (* hop4  DISCHARGED  FS_NPRFPRF = V_C:VT + V_C:VF.
     FxChain.hop4_musplit -- an EQUALITY (Eqv_NPRFPRF_V_C byequiv, then Pr[mu_split]
     on valid_MFORSC10); the +C analog of MM45 Eqv_..._NPRFNPRF_V (:2572) + mu_split.
     V_C (EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V) is the SINGLE-SOURCED RtopCSoundness
     module -- the SAME one hop6a consumes.  THIS is the machine-checked p_vf seam. *)
  have hop4 := hop4_musplit F &m.

  (* hop5  DISCHARGED (Step 4 -- was the SOLE remaining admit).  GprocFORSC10.LeqPr_VT_C_proc
     (PROVEN CERTIFIED-0-ADMIT): the VT branch bounds V_C:VT against the CONCRETE procedural
     FORS+C10 game Gproc via the F-DERIVED reduction R_fors_p(F) (a real byequiv coupling,
     the sound replacement for the abstract-M seam -- the three obstructions D1 fverify /
     D2 keygen / tape-in-ps are dissolved by Gproc's construction).  Chained with hF
     (EUFCMA_Gproc) this lands the FORS leg on the concrete M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(F)))
     term in the RHS -- no free A_fors, no abstract game. *)
  have hop5 := LeqPr_VT_C_proc F &m.

  (* hop6a  DISCHARGED  V_C:VF <= NAGCMA(R_top_C(F), TRHC.O).
     RtopCSoundness.LeqPr_VF_C (CERTIFIED-0-ADMIT: the whole VF leg -- Eqv_Orig_RV_C
     plus the R6a/R6b/R6c consume -- is PROVEN there; the +C analog of MM45
     LeqPr_..._VF, SPHINCS_PLUS.ec:3468).  Its V_C:VF LHS is the SAME single-sourced
     module term hop4 produced (the seam bridges by module identity). *)
  have hop6a := LeqPr_VF_C F &m.

  (* hop6b  DISCHARGED (2026-07-24, the CLEAN closure).  LeqPr_VF_C (hop6a) lands on
     `Pr[NAGCMA(R_top_C(F), TRHC.O_THFC_Default)]`; hHT (component theorem, applied at
     R_top_C(F)) consumes `Pr[NAGCMA(R_top_C(F), FC.O_THFC_Default)]`.  Gap (a) [the
     old R_top_C -> R_top reduction, conditioned vs memoized mk] is DISSOLVED -- the
     component theorem is `forall A_ht`, so it is applied DIRECTLY at R_top_C(F), never
     at R_top(F).  The sole residual gap (b) [FC.O <-> TRHC.O cross-clone oracle] is
     PROVEN by RtopCSoundness.oracle_clone_hop_C: FC (WOTS_TW_ES:450) and FSSLXMTWES.TRHC
     (FL_SL_XMSS_MT_ES:445) are DISTINCT `Collection` clones BOTH binding op fc<-thfc /
     get_diff<-size, so their O_THFC_Default.query bodies coincide -- an honest byequiv
     reconciliation (NOT a sim: glob differs), non-vacuous (the pp coupling is
     load-bearing).  (The pre-closure note that Option A "is strictly worse / needs a
     nonexistent R_top_C variant of R_top_members4" is SUPERSEDED: that port now exists
     and is proven, CERTIFIED-0-ADMIT, in RtopCSoundness.) *)
  have hop6b := oracle_clone_hop_C F &m.

  (* ---- sound-direction linear transitivity: hop1..hop5 + hop6a + hop6b(=oracle
          hop) + hF + hHT.  Every shared atom is syntactically identical across the
          facts (FS_PRFPRF, FS_NPRFPRF, the single-sourced V_C:VT / V_C:VF, the
          Gproc-game term EUF_CMA_Gproc(R_fors_p(F)) [hop5->hF], and the two NAGCMA terms
          -- BOTH now at R_top_C(F): NAGCMA(R_top_C(F),TRHC.O) bridges hop6a->hop6b,
          NAGCMA(R_top_C(F),FC.O) bridges hop6b->hHT), and mkg_adv >= 0 (hmkg): pure
          real-arithmetic chaining, NOT an smt-forced discharge of any hop.  ZERO admit
          remains -- hop5 is the proven LeqPr_VT_C_proc + EUFCMA_Gproc chain. ---- *)
  smt().
qed.

(* ==========================================================================
   [R4] IN-FILE SATISFIABILITY RECEIPTS (2026-07-25).  A green compile is NOT
   evidence of non-vacuity -- this whole repair exists because a CERTIFIED-0-ADMIT
   theorem turned out VACUOUS.  These two lemmas are the in-file half of the
   receipt set; the canary half lives in scratch/synth_repaired_canary{1,2,3}.ec
   and MUST BE REJECTED by the gate (canary3 instantiates THIS theorem and fails
   to derive `Pr[EUFCMA_C10(F)] <= -1%r`, which the pre-repair statement DID
   derive -- see scratch/synth_exact_prefix_vacuity.ec:CAPSTONE_IS_VACUOUS).
   ========================================================================== *)

(* (R4a) The emb_tw obligation the COMPONENT THEOREM still names is a THEOREM, not
   an assumption -- this is the term passed at the `hHT` application above.  So the
   emb_tw axis contributes NO hypothesis to this capstone, and in particular cannot
   contribute a contradiction (which is exactly what the deleted injectivity
   premise did). *)
lemma capstone_emb_axis_premise_free :
  forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b).
proof. exact emb_disj_concrete. qed.

(* (R4b) The two REAL-valued premises of the theorem above are JOINTLY SATISFIABLE
   at concrete values, so neither hides a `false`.  (The H-TREE-MULTI premise is
   FALSE-AT-ZERO by design -- that is why it is a premise and not an admit -- but
   satisfiable it certainly is.)

   *** CORRECTED 2026-07-30 (claim-vs-code drift, found in adversarial review). ***
   This paragraph used to read: "scratch/synth_repaired_canary3.ec discharges both
   OUTRIGHT while instantiating the theorem, so the capstone is genuinely
   APPLICABLE, not merely well-typed."  THAT CITATION INVERTED THE ARTIFACT.
   canary3 is a MUST-FAIL vacuity canary; its own header reads "MUST BE
   **REJECTED** BY THE GATE ... A GREEN COMPILE HERE IS A REGRESSION."  It exists
   to show the ABSURD bound `Pr[EUFCMA_C10(F)] <= -1%r` is NOT derivable.  Citing
   a control whose whole purpose is to be rejected as evidence that the theorem
   is usable reads the artifact backwards.

   WHAT canary3 ACTUALLY ESTABLISHES (and it is worth having): it discharges both
   real-valued premises at concrete values AND STILL fails to reach the absurd
   bound.  That is an ANTI-VACUITY result, not an applicability result.  It is
   enforced mechanically by cert_gate_fork.sh phase 3, which requires it to fail
   *for its declared reason* (`cannot prove goal (strict)`) -- because when the N2
   premise was added, canary3 silently began failing on an ARITY mismatch instead
   and was testing nothing while still "failing".

   HOW APPLICABLE IS THE THEOREM, HONESTLY?  The only witness in this repo is the
   lemma directly below, and it is TRIVIAL: it takes mtree_openpre = 1, at which
   point the tree bracket of the conclusion alone contributes >= 1 and the bound
   is satisfied by `Pr[mu_le1]` regardless of anything else.  So the correct
   statement is: the premises are satisfiable and the theorem is instantiable, at
   a point where the bound says nothing numerically.  A NON-trivial
   instantiation -- concrete named advantages in place of mkg_adv and the three
   mtree_* reals -- does not exist yet and is the outstanding work. *)
lemma capstone_real_premises_satisfiable
  (F <: Adv_EUFCMA_C{ -R_fors_p, -O_CMA_Gproc, -O_CMA_Gproc_I, -R_ITSRC10_Gproc,
                      -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default }) &m :
  exists (mkg_adv mtree_openpre mtree_trh mtree_trco : real),
       0%r <= mkg_adv
    /\ Pr[EUF_CMA_Gproc_I(R_fors_p(F)).main() @ &m
            : res /\ !EUF_CMA_Gproc_I.covered]
       <= mtree_openpre + mtree_trh + mtree_trco.
proof.
exists 0%r 1%r 0%r 0%r => /=.
by rewrite Pr[mu_le1].
qed.

(* ==========================================================================
   GROUNDED CAPSTONE — the free reals ELIMINATED.

   WHY.  Adversarial review 2026-07-30 (GPT-5.6) rated the capstone's headline
   defect as: its only in-repo witness for the four free reals is
   `capstone_real_premises_satisfiable`, which takes mtree_openpre = 1, at which
   point the conclusion's tree bracket alone contributes >= 1 and the bound holds
   by `Pr[mu_le1]` regardless of anything else.  A theorem whose only
   instantiation says nothing numerically is a ledger, not a bound.

   WHAT THIS IS.  The same theorem with every free real DISCHARGED, so there is
   nothing left to set to 1:

     * `mkg_adv` is GONE, not renamed.  Hop-3 is the IDENTITY (C10 draws mk fresh
       and non-memoized, so NPRFNPRF is definitionally NPRFPRF), and the summand's
       only use was the tautology `x <= x + mkg_adv` under `0 <= mkg_adv`.  A free
       nonneg summand that can be taken to 0 represents NOTHING, so instantiating
       it at 0 loses no content and removes a term that read as if the MKG
       advantage were accounted for.  IT IS NOT: the genuine MKG idealisation
       remains a separate OPEN modelling boundary (header (1)).  Deleting the
       summand makes that visible instead of papering it.

     * `mtree_openpre + mtree_trh + mtree_trco` are GONE, replaced by the very
       probability their premise bounded.  The premise
         Pr[EUF_CMA_Gproc_I(R_fors_p(F)) : res /\ !covered] <= sum
       is instantiated at sum := that Pr, so it becomes reflexivity and the
       hypothesis DISAPPEARS.

   NET, CORRECTED 2026-07-30 after adversarial review (both points CONFIRMED
   against source; the first draft of this paragraph overstated on both):

     * hypotheses: strictly fewer (9 -> 7).  That part stands.
     * right-hand side: WEAKLY smaller, NOT strictly.  Equality holds at exactly
       this instantiation (mkg_adv = 0 and tree total = Q).  My first draft also
       justified it by "every dropped summand was non-negative" -- FALSE: there
       is no `0 <= mtree_*` premise anywhere, only a lower bound on their SUM
       (see the parent's tree hypothesis).  Individual tree reals may be
       negative; what licenses the substitution is `Q <= mtree_openpre +
       mtree_trh + mtree_trco`, not summand sign.

   AND THE HONEST LIMIT OF THE "GROUNDING".  `Q` is an UNREDUCED bad-event
   probability, not discharged cryptographic content: nothing here bounds it
   below 1, and if Q = 1 this bound is as uninformative as the free-real version
   was.  What changed is that Q is a NAMED game probability that cannot be CHOSEN
   by an instantiator, where the free real could be set to 1 at will.  That is a
   real improvement in what the statement pins down, and it is NOT the same thing
   as a numerically meaningful bound.

   WHAT IT DOES NOT FIX.  `Pr[M.F.ITSRC10 ...]` is still carried UNREDUCED --
   that is the ~102-bit-gap FORS+C10 assumption and is the honest headline term.
   N2 still reaches here undischarged.  Nothing about the encoder / target 205 is
   pinned (see C10DeployedGeometry.ec for why that is blocked, not pending).
   ========================================================================== *)
lemma EUFCMA_SPHINCS_PLUS_C10_GROUNDED
  (F <: Adv_EUFCMA_C{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V, -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default,
             -R_top,
             (* WIRED (2026-07-24): additional separations required by the APPLIED hop
                lemmas (Pr_EUFCMA_C10_FSPRFPRFC / SKGPRF_C_hop / hop4_musplit /
                LeqPr_VF_C).  Standard reduction well-formedness -- F is a proof-external
                forger disjoint from the internal game/reduction states; NOT a weakening
                of the bound (the current 6-admit capstone omitted them only because it
                never applied the hops). *)
             -DSSC.Stateless.O_CMA_Default, -O_CMA_SPHINCSPLUSTWC_FS,
             -SKG_PRF.O_PRF_Default, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V,
             -R_top_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV,
             (* WIRED (Step 4): the FORS/VT leg is now F-DERIVED via R_fors_p(F) into
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
         delivers. *)
      <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
           - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
       (* +C subst #1: FORS+C10 CONCRETE expansion.  The ITSR(+C)/C10 term is now over
          the F-DERIVED reduction R_ITSRC10_Gproc(R_fors_p(F)) (was the free
          M.R_ITSRC10_MFORSC10(A_fors)) -- delivered by LeqPr_VT_C_proc (PROVEN) then
          EUFCMA_Gproc.  Same carried M.F.ITSRC10 hardness assumption; now concrete. *)
       + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(F)),
                          M.F.O_ITSRC10_Default).main() @ &m : res]
           + Pr[EUF_CMA_Gproc_I(R_fors_p(F)).main() @ &m
                : res /\ !EUF_CMA_Gproc_I.covered] )
       (* +C subst #2: hypertree COMPONENT THEOREM expansion at A_ht := R_top_C(F)
          (2026-07-24 hop6b CLEAN closure: applied DIRECTLY at R_top_C(F), so gap
          (a) R_top_C -> R_top is DISSOLVED; the four leaf terms keep the STANDARD +C
          shape -- WOTS-TW+C multi / S-TCR(+C) / pkco-TCR / trh-TCR -- now at
          R_top_C(F).  This is a PROVEN upper bound on the UNCHANGED LHS; the four
          terms are a DIFFERENT concrete RHS from a hypothetical R_top(F) one, not
          claimed numerically equal (see header (1)).  LeqPr_VF_C already lands on
          R_top_C(F), so the sole reconciliation is the FC.O<->TRHC.O oracle-clone
          hop, discharged by RtopCSoundness.oracle_clone_hop_C. ITSRC10 stays fg). *)
       + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                      O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(F)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(F)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res] ).
proof.
move=> hc hencb hN2 hdf8n hdflen hdf2 hdfnk.
have h := EUFCMA_SPHINCS_PLUS_C10 F 0%r
            Pr[EUF_CMA_Gproc_I(R_fors_p(F)).main() @ &m
                 : res /\ !EUF_CMA_Gproc_I.covered] 0%r 0%r
            &m hc _ hencb hN2 hdf8n hdflen hdf2 hdfnk _.
+ by [].
+ by smt().
by smt().
qed.
