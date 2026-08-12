(* ===========================================================================
   THE Q LEG, WIRED INTO THE CAPSTONE.

   WHAT THIS CHANGES, in one line: the headline bound's FORS-tree term stops
   being an UNREDUCED bad-event probability and becomes three NAMED hardness
   advantages.

   SphincsC10CapstoneWired.ec's EUFCMA_SPHINCS_PLUS_C10_GROUNDED eliminated the
   free reals mtree_openpre/mtree_trh/mtree_trco by instantiating their sum at
   Q = Pr[EUF_CMA_Gproc_I(R_fors_p(F)) : res /\ !covered] itself, so the
   H-TREE-MULTI premise became reflexivity and disappeared.  That file states its
   own honest limit, and it is the exact gap this file closes:

     "Q is an UNREDUCED bad-event probability, not discharged cryptographic
      content: nothing here bounds it below 1, and if Q = 1 this bound is as
      uninformative as the free-real version was."

   gproc_Q_bound (GprocQBound.ec) bounds Q by the three branch reductions, so
   instantiating the SAME parametric capstone at

     mtree_openpre := Pr[SM_DT_OpenPRE(R_OPRE_Gproc(R_fors_p(F)))]
     mtree_trh     := Pr[SM_DT_TCR_C(R_TRH_Gproc(R_fors_p(F)))]
     mtree_trco    := Pr[SM_DT_TCR_C(R_TRCO_Gproc(R_fors_p(F)))]

   discharges the premise by a REDUCTION rather than by reflexivity, and the RHS
   now carries terms an instantiator cannot set to 1 at will and which are
   standard SM-DT hardness assumptions.

   WHAT IT DOES NOT DO -- and these matter, because "wired into the capstone" is
   easy to over-read:
     * It does NOT make the bound numerically meaningful.  Pr[M.F.ITSRC10 ..] is
       still carried UNREDUCED and is the honest headline term (the ~102-bit
       FORS+C10 gap); N2 still reaches here undischarged; nothing about the
       encoder / target 205 is pinned.  Those are unchanged by this file.
     * It does NOT reduce the assumption COUNT.  Three hardness advantages
       replace one bad-event probability.  What improves is that they are named,
       reduction-backed, and not instantiator-chosen.
     * It IS formally a NARROWING: F now carries nine more separations, so the
       theorem applies to strictly fewer forgers.  That is the same move the
       capstone already made twice ("WIRED (2026-07-24)", "WIRED (Step 4)") and
       is standard reduction well-formedness -- but it is a narrowing, and the
       GROUNDED lemma it derives from is left UNTOUCHED so both are available.

   ADDITIVE BY CONSTRUCTION.  Nothing in SphincsC10CapstoneWired.ec is edited:
   this derives from the parametric EUFCMA_SPHINCS_PLUS_C10, so every existing
   pinned statement digest there is unmoved.
   =========================================================================== *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS XmssmtCC_All RtopCSoundness FxChain GprocFORSC10 GprocVI.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme WOTS_C_Interactive.
require FORS_C10 FORS_C10_Multi DigitalSignatures.
require import BitEncoding. import BS2Int BitChunking.
require import SphincsC10CapstoneWired.
require import GprocT1Opre GprocT2Trh GprocT3Trco GprocQBound.
require import C10DeployedInstance C10DeployedCapstone.
(* Same import surface the capstone itself opens (SphincsC10CapstoneWired.ec
   :381-387): the lemma statement below is that file's, so it needs that file's
   unqualified names (R_int_STCRC, FSSLXMTWES.*, EmsgWOTS, ...). *)
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.

lemma EUFCMA_SPHINCS_PLUS_C10_QWIRED
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
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default,
             (* WIRED (2026-08-10, Q leg): the nine separations gproc_Q_bound needs.
                Same class as the "WIRED (Step 4)" block above -- F is a
                proof-external forger and these are the Gproc branch game, the
                three branch reductions and their four challengers.  This is
                formally a NARROWING of the hypothesis (it applies to fewer F);
                it is taken deliberately, and it is the price of replacing an
                unreduced Q with three named hardness advantages. *)
             -EUF_CMA_Gproc_V, -R_OPRE_Gproc, -R_TRH_Gproc, -R_TRCO_Gproc,
             -FTWES.F_OpenPRE.O_SMDTOpenPRE_Default,
             -FTWES.TRHC_TCR.O_SMDTTCR_Default, -FTWES.TRHC.O_THFC_Default,
             -FTWES.TRCOC_TCR.O_SMDTTCR_Default, -FTWES.TRCOC.O_THFC_Default })
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
           + ( Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(R_fors_p(F)),
                     FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res]
             + Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(R_fors_p(F)),
                     FTWES.TRHC_TCR.O_SMDTTCR_Default,
                     FTWES.TRHC.O_THFC_Default).main() @ &m : res]
             + Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(R_fors_p(F)),
                     FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                     FTWES.TRCOC.O_THFC_Default).main() @ &m : res] ) )
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
            Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(R_fors_p(F)),
                 FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res]
            Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(R_fors_p(F)),
                 FTWES.TRHC_TCR.O_SMDTTCR_Default,
                 FTWES.TRHC.O_THFC_Default).main() @ &m : res]
            Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(R_fors_p(F)),
                 FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                 FTWES.TRCOC.O_THFC_Default).main() @ &m : res]
            &m hc _ hencb hN2 hdf8n hdflen hdf2 hdfnk _.
+ by [].
+ by apply (gproc_Q_bound (R_fors_p(F)) &m).
by smt().
qed.


(* ===========================================================================
   ANTI-VACUITY: THE RESTRICTED ADVERSARY CLASS IS INHABITED.

   WHY THIS EXISTS.  QWIRED above adds NINE module separations to the forger F.
   Every separation NARROWS the theorem, and a restriction set that no module can
   satisfy would make it vacuous -- proved, gated, GREEN, and about nothing.  The
   reductions are built FROM F, which is exactly where such a circularity could
   hide.  Two independent adversarial reviews (2026-08-10) agreed the set is
   inhabited and that there is no F <-> R(F) cycle -- EasyCrypt restrictions are
   negative, one-directional accessibility constraints -- but both also said an
   UNCOMMITTED argument has no certification value.  So it is committed here.

   WHAT THE WITNESS IS.  A forger with its OWN global state that actually calls
   its signing oracle.  Statefulness is the point: a stateless module satisfies
   any {-X} vacuously, so it would witness almost nothing.  This one has the
   shape the restrictions are actually about.

   WHAT THIS DOES AND DOES NOT SHOW.  It shows the constraint set is not
   self-contradictory, so QWIRED is not vacuous in the module-restriction sense.
   It does NOT show the bound is numerically meaningful -- it is not; see the
   header above: Pr[M.F.ITSRC10 ..] is still carried UNREDUCED.  And note the
   OTHER vacuity class does not apply here at all: QWIRED has no free reals left
   (that is what capstone_real_premises_satisfiable exists to witness for the
   parametric capstone), because gproc_Q_bound discharged the H-TREE-MULTI
   premise by a theorem rather than by an instantiator's choice.

   The companion evidence is the MUST-FAIL direction, recorded rather than
   committed as a second copy: deleting even one of the nine separations makes
   the QWIRED proof fail with "the module R_fors_p(F) is not allowed to use the
   module(s) F".  Enforced AND satisfiable is the two-sided result. *)
module (WitnessF : Adv_EUFCMA_C) (O : SOracle_CMA_C) = {
  var queried : msg list

  proc forge(pk : pkSPHINCSPLUSTW) : msg * sigSPHINCSPLUSTWC = {
    var s : sigSPHINCSPLUSTWC;
    queried <- [];
    s <@ O.sign(witness);
    queried <- witness :: queried;
    return (witness, s);
  }
}.

(* The instantiated bound.  Stated as the REAL conclusion at the witness rather
   than as `true`, so the pinned digest protects something: if the nine
   separations ever became unsatisfiable, or the conclusion drifted, this stops
   compiling. *)
lemma qwired_at_witness &m :
    c <= p_tgts =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    (forall (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock),
       exists (cc : cntr), predC (ThC ps0 ad0 m0 cc)) =>
    dfC0 <> 8 * n =>
    dfC0 <> 8 * n * len =>
    dfC0 <> 8 * n * 2 =>
    dfC0 <> 8 * n * k =>
    Pr[EUFCMA_C10(WitnessF).main() @ &m : res]
      (* +C SKG-PRF advantage: GROUNDED (was the free real skg_adv) to the exact
         concrete R_SKGPRF_EUFCMA_C PRF-distinguishing term that hop-2 (SKGPRF_C_hop)
         delivers. *)
      <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(WitnessF), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
           - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(WitnessF), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
       (* +C subst #1: FORS+C10 CONCRETE expansion.  The ITSR(+C)/C10 term is now over
          the F-DERIVED reduction R_ITSRC10_Gproc(R_fors_p(WitnessF)) (was the free
          M.R_ITSRC10_MFORSC10(A_fors)) -- delivered by LeqPr_VT_C_proc (PROVEN) then
          EUFCMA_Gproc.  Same carried M.F.ITSRC10 hardness assumption; now concrete. *)
       + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(WitnessF)),
                          M.F.O_ITSRC10_Default).main() @ &m : res]
           + ( Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(R_fors_p(WitnessF)),
                     FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res]
             + Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(R_fors_p(WitnessF)),
                     FTWES.TRHC_TCR.O_SMDTTCR_Default,
                     FTWES.TRHC.O_THFC_Default).main() @ &m : res]
             + Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(R_fors_p(WitnessF)),
                     FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                     FTWES.TRCOC.O_THFC_Default).main() @ &m : res] ) )
       (* +C subst #2: hypertree COMPONENT THEOREM expansion at A_ht := R_top_C(WitnessF)
          (2026-07-24 hop6b CLEAN closure: applied DIRECTLY at R_top_C(WitnessF), so gap
          (a) R_top_C -> R_top is DISSOLVED; the four leaf terms keep the STANDARD +C
          shape -- WOTS-TW+C multi / S-TCR(+C) / pkco-TCR / trh-TCR -- now at
          R_top_C(WitnessF).  This is a PROVEN upper bound on the UNCHANGED LHS; the four
          terms are a DIFFERENT concrete RHS from a hypothetical R_top(WitnessF) one, not
          claimed numerically equal (see header (1)).  LeqPr_VF_C already lands on
          R_top_C(WitnessF), so the sole reconciliation is the FC.O<->TRHC.O oracle-clone
          hop, discharged by RtopCSoundness.oracle_clone_hop_C. ITSRC10 stays fg). *)
       + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF))),
                                      O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(WitnessF)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(WitnessF)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res] ).
proof. by apply (EUFCMA_SPHINCS_PLUS_C10_QWIRED WitnessF &m). qed.


(* ===========================================================================
   THE DEPLOYED LEVEL -- PARALLEL AND PROMOTE.

   WHY THESE EXIST.  QWIRED above had NO CONSUMER.  The deployed chain
   (C10DeployedCapstone.ec:62 -> :132) applies EUFCMA_SPHINCS_PLUS_C10_GROUNDED,
   so the SHIPPED headline still carried the unreduced Q that gproc_Q_bound
   exists to replace.  Adversarial review 2026-08-11 put it plainly: calling the
   deployed result "Q-wired" would have been false.

   WHY NOT EDIT THE DEPLOYED LEMMAS IN PLACE.  The two reviewers split on this
   and the disagreement is the useful part.  In-place is safe by consumer
   analysis (nothing outside C10DeployedCapstone.ec uses them).  But QWIRED is
   NOT a same-domain strengthening: it NARROWS F by nine separations AND
   replaces an exact term Q with an upper bound that may be larger.  Mutating a
   published theorem name would hide BOTH changes behind an unchanged name.  The
   repo's own precedent is parallel-supersede -- "The older lemma stays -- it is
   not repaired, it is superseded for quotation" (cert_gate_split.sh:425-426) --
   so that is what is done here.  The GROUNDED-derived lemmas keep their exact
   statements and digests; these are the ones to quote.

   PLACEMENT is deliberate: they live HERE, not in C10DeployedCapstone.ec, so the
   dependency runs FORWARD along closure order (C10DeployedInstance #22,
   C10DeployedCapstone #23 -> GprocQWired #29).  Editing the deployed file to
   import this one would have created a backward edge and forced a closure
   reorder.

   WHAT IS AND IS NOT BOUGHT.  The tree term becomes three NAMED SM-DT hardness
   advantages instead of an unreduced bad-event probability an instantiator
   cannot be held to.  Nothing numeric improves: Pr[M.F.ITSRC10 ..] is still
   carried unreduced and remains the honest headline term, and the pinned
   cert-margin-split.tsv row adv_log2_qh128 = -2.6 is what that means at a large
   query budget.
   =========================================================================== *)
lemma EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS_QWIRED
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
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default,
             (* WIRED (2026-08-11, Q leg at the DEPLOYED level): the same nine
                separations EUFCMA_SPHINCS_PLUS_C10_QWIRED carries.  A NARROWING,
                taken deliberately -- see this file's header. *)
             -EUF_CMA_Gproc_V, -R_OPRE_Gproc, -R_TRH_Gproc, -R_TRCO_Gproc,
             -FTWES.F_OpenPRE.O_SMDTOpenPRE_Default,
             -FTWES.TRHC_TCR.O_SMDTTCR_Default, -FTWES.TRHC.O_THFC_Default,
             -FTWES.TRCOC_TCR.O_SMDTTCR_Default, -FTWES.TRCOC.O_THFC_Default })
  &m :
    (* ==== THE DEPLOYED PARAMETERS (sphincs-c10/src/params.rs) ==== *)
    n       = c10_n     =>   (* 16, params.rs:19 *)
    len     = c10_len   =>   (* 43, params.rs:49 *)
    k       = c10_k     =>   (* 13, params.rs:34 *)
    size (emb_in witness) = 8 * n + c10_r =>   (* NODE || u32 counter *)
    c <= p_tgts =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    (forall (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock),
       exists (cc : cntr), predC (ThC ps0 ad0 m0 cc)) =>
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
           + ( Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(R_fors_p(F)),
                     FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res]
             + Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(R_fors_p(F)),
                     FTWES.TRHC_TCR.O_SMDTTCR_Default,
                     FTWES.TRHC.O_THFC_Default).main() @ &m : res]
             + Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(R_fors_p(F)),
                     FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                     FTWES.TRCOC.O_THFC_Default).main() @ &m : res] ) )
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
move=> hn hlen hk hsz hc hencb hN2.
have [# h0 h1 h2 h3 g0 g1 g2 g3 hnem] := c10_dfC_separations_deployed hn hlen hk hsz.
exact (EUFCMA_SPHINCS_PLUS_C10_QWIRED F &m hc hencb hN2 h0 h1 h2 h3).
qed.

(* The encoder-pinned variant -- THE CANONICAL ONE TO QUOTE.  Same relationship
   to the lemma above as _PINNED_ENCODER has to AT_DEPLOYED_PARAMS. *)
lemma EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS_PINNED_ENCODER_QWIRED
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
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default,
             (* WIRED (2026-08-11, Q leg at the DEPLOYED level): the same nine
                separations EUFCMA_SPHINCS_PLUS_C10_QWIRED carries.  A NARROWING,
                taken deliberately -- see this file's header. *)
             -EUF_CMA_Gproc_V, -R_OPRE_Gproc, -R_TRH_Gproc, -R_TRCO_Gproc,
             -FTWES.F_OpenPRE.O_SMDTOpenPRE_Default,
             -FTWES.TRHC_TCR.O_SMDTTCR_Default, -FTWES.TRHC.O_THFC_Default,
             -FTWES.TRCOC_TCR.O_SMDTTCR_Default, -FTWES.TRCOC.O_THFC_Default })
  &m :
    n       = c10_n     =>
    len     = c10_len   =>
    k       = c10_k     =>
    STCRC_WC.G.CntrFT.card <= 2 ^ c10_r =>
    emb_in = c10_embg =>
    c <= p_tgts =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    (forall (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock),
       exists (cc : cntr), predC (ThC ps0 ad0 m0 cc)) =>
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
           + ( Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(R_fors_p(F)),
                     FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res]
             + Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(R_fors_p(F)),
                     FTWES.TRHC_TCR.O_SMDTTCR_Default,
                     FTWES.TRHC.O_THFC_Default).main() @ &m : res]
             + Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(R_fors_p(F)),
                     FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                     FTWES.TRCOC.O_THFC_Default).main() @ &m : res] ) )
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
move=> hn hlen hk hcard hemb hc hencb hN2.
have hsz := c10_deployed_encoder_gives_width hemb.
exact (EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS_QWIRED F &m hn hlen hk hsz hc hencb hN2).
qed.

(* ANTI-VACUITY AT THE LEVEL PEOPLE ACTUALLY QUOTE.  qwired_at_witness already
   witnesses the same restriction set one layer down, so this is arguably
   redundant -- but the deployed lemma is the quotation surface, and this repo's
   doctrine is that a receipt belongs where the claim is made.  Cheap, and it
   means the canonical deployed statement cannot become vacuous without a gate
   failure. *)
lemma deployed_qwired_at_witness &m :
    n       = c10_n     =>
    len     = c10_len   =>
    k       = c10_k     =>
    STCRC_WC.G.CntrFT.card <= 2 ^ c10_r =>
    emb_in = c10_embg =>
    c <= p_tgts =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    (forall (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock),
       exists (cc : cntr), predC (ThC ps0 ad0 m0 cc)) =>
    Pr[EUFCMA_C10(WitnessF).main() @ &m : res]
      (* +C SKG-PRF advantage: GROUNDED (was the free real skg_adv) to the exact
         concrete R_SKGPRF_EUFCMA_C PRF-distinguishing term that hop-2 (SKGPRF_C_hop)
         delivers. *)
      <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(WitnessF), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
           - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(WitnessF), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
       (* +C subst #1: FORS+C10 CONCRETE expansion.  The ITSR(+C)/C10 term is now over
          the F-DERIVED reduction R_ITSRC10_Gproc(R_fors_p(WitnessF)) (was the free
          M.R_ITSRC10_MFORSC10(A_fors)) -- delivered by LeqPr_VT_C_proc (PROVEN) then
          EUFCMA_Gproc.  Same carried M.F.ITSRC10 hardness assumption; now concrete. *)
       + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(WitnessF)),
                          M.F.O_ITSRC10_Default).main() @ &m : res]
           + ( Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(R_fors_p(WitnessF)),
                     FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res]
             + Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(R_fors_p(WitnessF)),
                     FTWES.TRHC_TCR.O_SMDTTCR_Default,
                     FTWES.TRHC.O_THFC_Default).main() @ &m : res]
             + Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(R_fors_p(WitnessF)),
                     FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                     FTWES.TRCOC.O_THFC_Default).main() @ &m : res] ) )
       (* +C subst #2: hypertree COMPONENT THEOREM expansion at A_ht := R_top_C(WitnessF)
          (2026-07-24 hop6b CLEAN closure: applied DIRECTLY at R_top_C(WitnessF), so gap
          (a) R_top_C -> R_top is DISSOLVED; the four leaf terms keep the STANDARD +C
          shape -- WOTS-TW+C multi / S-TCR(+C) / pkco-TCR / trh-TCR -- now at
          R_top_C(WitnessF).  This is a PROVEN upper bound on the UNCHANGED LHS; the four
          terms are a DIFFERENT concrete RHS from a hypothetical R_top(WitnessF) one, not
          claimed numerically equal (see header (1)).  LeqPr_VF_C already lands on
          R_top_C(WitnessF), so the sole reconciliation is the FC.O<->TRHC.O oracle-clone
          hop, discharged by RtopCSoundness.oracle_clone_hop_C. ITSRC10 stays fg). *)
       + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF))),
                                      O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(WitnessF)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(WitnessF)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res] ).
proof.
by apply (EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS_PINNED_ENCODER_QWIRED WitnessF &m).
qed.
