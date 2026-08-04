(* ==========================================================================
   SphincsC10CapstoneCharged.ec — the capstone WITHOUT the N2 premise.

   `EUFCMA_SPHINCS_PLUS_C10_CHARGED` is `EUFCMA_SPHINCS_PLUS_C10`
   (SphincsC10CapstoneWired.ec) with the N2 hypothesis deleted and a fifth
   summand added to the hypertree group.  Proof is verbatim apart from two
   lines: the intro drops `hN2`, and `hHT` comes from
   `EUFNAGCMA_FLSLXMSSMTTWCESNPRF_charged` (XmssmtCCCharged.ec) rather than its
   N2-carrying twin.  Everything else -- the FX hop skeleton, hop6b, hF, the
   final real-arithmetic chaining -- is untouched.

   ADDITIVE: SphincsC10CapstoneWired.ec is not modified, so the original capstone
   and its satisfiability receipts / canaries stand exactly as they are.

   WHAT THIS IS NOT.  N2 is not discharged.  Nothing here bounds the new summand.

   BE CAREFUL WITH THE VACUITY CLAIM (CORRECTED 2026-07-31, adversarial review).
   An earlier version of this note said the charge "equals the whole success mass
   in exactly the models where N2 is false".  That is WRONG AS AN ARGUMENT.  In
   the witness model of FINDING-n2-is-independent.md section 1, `predC (ThC ..)`
   is false EVERYWHERE -- but `WOTS_C_ES.verify` returns `pk-match /\ okC` with
   `okC = predC (ThC ps ad m counter)` (WOTS_C_Scheme.ec:101-103), and
   GAME1_INT's `res` conjoins `is_valid` (WOTS_C_Interactive.ec:940-942).  So in
   that model `res` is FALSE, the charge is 0, and "equals the whole success
   mass" reads 0 = 0.  It establishes nothing.

   THE ACCURATE STATEMENT.  N2 being false is NECESSARY for the charge to be
   nonzero, but NOT SUFFICIENT: a positive charge needs a MIXED model in which
   the grind fails on some QUERIED tuple while the run still succeeds.  No such
   model -- and no lower bound of any kind -- exists in this repository.  Nor do
   canary6/canary7 supply one: a MUST-FAIL control shows the solver cannot
   DERIVE a bound, not that the probability is positive.  That conflation is
   exactly what the review caught.

   So the term is neither known-positive nor known-zero; it is simply UNBOUNDED
   here.  What the charged capstone buys is narrow and real: the statement no
   longer ASSUMES an unprovable proposition, it prices one.
   ========================================================================== 
   [ADDED 2026-08-02, run 13, found INDEPENDENTLY BY TWO LEGS.  THIS THEOREM HAS
   CONTENT-FREE DIRECTIONS OF ITS OWN, and the project's disclosure list named
   only three, all belonging to the GROUNDED/DEPLOYED chain.
     * The four charged reals (mkg_adv, mtree_openpre, mtree_trh, mtree_trco) are
       UNIVERSALLY QUANTIFIED.  At (0,1,0,0) the premise
         Pr[EUF_CMA_Gproc_I(R_fors_p(F)) : res /\ !covered] <= mtree_openpre
                                                            + mtree_trh + mtree_trco
       holds by Pr[mu_le1] while the conclusion's RHS already exceeds 1, so that
       instantiation asserts nothing numerically -- verbatim the defect the
       GROUNDED header condemns ("a theorem whose only instantiation says nothing
       numerically is a ledger, not a bound").  This does NOT make the theorem
       false or content-free at every instantiation; it means the theorem does not
       by itself exclude the useless ones, and its only consumer re-quantifies the
       same reals rather than instantiating them.
     * The `gfail` summand is likewise bounded by nothing here.
   This theorem derives from the UNGROUNDED capstone and inherits its receipts,
   which is exactly why it kept a shape the grounding pass removed elsewhere.] *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.
require import RtopCSoundness.
require import FxChain.
require import GprocFORSC10.
require FORS_C10 FORS_C10_Multi.
require DigitalSignatures.
require import BitEncoding. import BS2Int BitChunking.
require import SphincsC10CapstoneWired.
require import GFailCharged.
require import XmssmtCCCharged.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.

lemma EUFCMA_SPHINCS_PLUS_C10_CHARGED
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
    (* N2 IS GONE FROM THIS CAPSTONE (2026-07-31).  It used to sit here, carried
       from interactive_D1_MA up through XmssmtCC_All, because the P-relativized
       fork retired MM45's two encoding axioms by GATING the WOTS-TW game on
       `P m /\ P m'`, which made grind-success load-bearing.  It is now a SUMMAND
       instead of a hypothesis -- see the last term of the conclusion.  That is a
       relocation, NOT a discharge: nothing in this repository bounds that term.
       It cannot be proved zero (N2 is independent -- see
       experiments/tcollres-leg/FINDING-n2-is-independent.md), but neither is it
       known to be POSITIVE; the obvious "grind fails everywhere" model does not
       witness a positive charge, because verify's okC conjunct makes res false
       there.  See this file's header. *)
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
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res]
           (* +C subst #3 (NEW): the grind-failure charge that replaces N2. *)
           + Pr[GAME1_INT(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)),
                          O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
                  res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps
                                  O_MEUFGCMA_WOTSC_Default.qs] ).
proof.
  move=> hc hmkg hencb hdf8n hdflen hdf2 hdfnk htree.
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
  have hHT := EUFNAGCMA_FLSLXMSSMTTWCESNPRF_charged (R_top_C(F)) &m hc emb_disj_concrete hencb
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
   TOP-LEVEL SUBSUMPTION.  Re-derives `EUFCMA_SPHINCS_PLUS_C10`'s statement --
   N2 premise, original four-term hypertree group, no extra summand -- from the
   charged capstone above, via `gfail_zero_under_N2` at the very adversary the
   capstone instantiates.

   So the charged capstone does not merely sit beside the original: it implies
   it.  Statement text below is taken VERBATIM from
   SphincsC10CapstoneWired.ec:484 (generated, not retyped), so the two cannot
   drift; only the proof differs.
   ========================================================================== *)
lemma EUFCMA_SPHINCS_PLUS_C10_from_charged
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
have hch := EUFCMA_SPHINCS_PLUS_C10_CHARGED F mkg_adv mtree_openpre mtree_trh mtree_trco &m
              hc hmkg hencb hdf8n hdflen hdf2 hdfnk htree.
have hz  := gfail_zero_under_N2 (R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))) &m hN2.
smt().
qed.
