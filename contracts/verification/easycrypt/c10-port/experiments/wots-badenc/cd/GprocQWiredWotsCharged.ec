(* ==========================================================================
   THE WOTS SUMMAND, REDUCED -- experiment wots-badenc.

   GprocQWired.ec:457 carries the WOTS-TW advantage as a RAW, UNREDUCED game
   probability.  It was left raw for a reason: reducing it meant applying MM45's
   `MEUFGCMA_WOTSTWESNPRF`, whose proof consumed an `admit` for encoder
   injectivity -- a statement this experiment showed is FALSE at deployed C10
   geometry.  Reducing it would have imported a false lemma into the headline.

   THAT OBSTACLE IS GONE.  The admit is replaced by an explicit encoding-collision
   charge, so the summand can now be reduced SOUNDLY, for the first time.

   Parallel-and-promote: GprocQWired.ec is NOT modified.  The older theorem stays
   valid -- it is superseded for quotation, not repaired.
   ========================================================================== *)
(* Header taken VERBATIM from GprocQWired.ec:48-65.  Note line 60:
   `import FSSLXMTWES.WTWES.` -- the WOTS_TW_ES namespace arrives through a
   CLONE, not directly, so the charged theorem and the BadEnc game/flag are the
   cloned copies.  Getting this wrong was the 4th failed compile of this file. *)
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
require import GprocQWired.

lemma EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS_PINNED_ENCODER_QWIRED_WOTSCHARGED
  (F <: Adv_EUFCMA_C{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V, -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default,
             -R_top,
             (* ADDED: the six WOTS-TW-internal modules MM45's WOTS theorem
                requires its adversary to be disjoint from.  A SUPERSET
                restriction is a STRONGER hypothesis on F, so everything the
                original QWIRED theorem discharged is still discharged. *)
             -FC_UD.O_SMDTUD_Default, -FC_TCR.O_SMDTTCR_Default,
             -FC_PRE.O_SMDTPRE_Default, -R_SMDTUDC_Game23WOTSTWES,
             -R_SMDTTCRC_Game34WOTSTWES, -R_SMDTPREC_Game4WOTSTWES,
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
    (* The two losslessness obligations of the charged WOTS theorem, carried as
       PREMISES rather than discharged here.  Their shape mirrors MM45's section
       declare-axioms A_choose_ll / A_forge_ll (WOTS_TW_ES.ec:3350, :3354)
       instantiated at this adversary.  XmssmtCC_All.ec:8905-8969 discharges
       exactly these inline for a generic hypertree adversary; exporting that
       work is a separate unit. *)
    (forall (O <: Oracle_MEUFGCMA_WOTSTWESNPRF{-R_int_WOTSTW, -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -R_top_C, -F}) (OC <: FC.Oracle_THFC{-R_int_WOTSTW, -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -R_top_C, -F}),
       islossless O.query => islossless OC.query =>
       islossless R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)), O, OC).choose) =>
    (forall (O <: Oracle_MEUFGCMA_WOTSTWESNPRF{-R_int_WOTSTW, -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -R_top_C, -F}) (OC <: FC.Oracle_THFC{-R_int_WOTSTW, -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -R_top_C, -F}),
       islossless R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)), O, OC).forge) =>
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
       + ( (   (w - 2)%r
               * `|Pr[FC_UD.SM_DT_UD_C(R_SMDTUDC_Game23WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
                       FC_UD.O_SMDTUD_Default, FC.O_THFC_Default).main(false) @ &m : res]
                   - Pr[FC_UD.SM_DT_UD_C(R_SMDTUDC_Game23WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
                       FC_UD.O_SMDTUD_Default, FC.O_THFC_Default).main(true) @ &m : res]|
             + Pr[FC_TCR.SM_DT_TCR_C(R_SMDTTCRC_Game34WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
                     FC_TCR.O_SMDTTCR_Default, FC.O_THFC_Default).main() @ &m : res]
             + ( Pr[FC_PRE.SM_DT_PRE_C(R_SMDTPREC_Game4WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
                       FC_PRE.O_SMDTPRE_Default, FC.O_THFC_Default).main() @ &m : res]
               + Pr[Game4_WOTSTWES_BadEnc(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))).main() @ &m
                       : res /\ BadEncFlag.badenc] ) )
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(F)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(F)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res] ).
proof.
move=> hn hlen hk hcard hemb hc hencb hN2 hll_choose hll_forge.
have hbase := EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS_PINNED_ENCODER_QWIRED
                F &m hn hlen hk hcard hemb hc hencb hN2.
have hwots := MEUFGCMA_WOTSTWESNPRF_Charged (R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))) hll_choose hll_forge &m.
(* Every other summand on the two right-hand sides is syntactically identical,
   so this is monotonicity of + over the single replaced term. *)
smt().
qed.


(* ==========================================================================
   ANTI-VACUITY.  This repo's doctrine (GprocQWired.ec:473-478) is that a
   receipt belongs where the claim is made, and the theorem above is a NEW
   quotation surface, so it needs its own.

   IT IS NOT CEREMONIAL HERE.  The theorem above WIDENS `F`'s restriction set by
   six WOTS-TW-internal modules.  Over-constraining `F` is exactly how a
   statement like this becomes vacuous, and nothing else in this file would
   detect it.  This lemma instantiates at `WitnessF` (GprocQWired.ec:198) --
   deliberately STATEFUL and CALLING ITS ORACLE
   (GprocChargedQWired.ec:147-153), not a trivial do-nothing adversary -- so if
   the widened set were unsatisfiable, THIS APPLY WOULD FAIL.

   WHAT IT DOES *NOT* CLOSE, stated so the receipt is not over-read: the two
   losslessness premises remain PREMISES here.  This witnesses that the MODULE
   RESTRICTION SET is satisfiable; it does not witness that those two
   propositions hold.  They are known satisfiable -- XmssmtCC_All.ec:8905-8969
   discharges exactly the analogous obligations for a generic hypertree
   adversary -- but "known satisfiable elsewhere" is not "proved here", and
   exporting that work is the remaining unit.
   ========================================================================== *)
lemma deployed_qwired_wotscharged_at_witness &m :
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
    (* The two losslessness obligations of the charged WOTS theorem, carried as
       PREMISES rather than discharged here.  Their shape mirrors MM45's section
       declare-axioms A_choose_ll / A_forge_ll (WOTS_TW_ES.ec:3350, :3354)
       instantiated at this adversary.  XmssmtCC_All.ec:8905-8969 discharges
       exactly these inline for a generic hypertree adversary; exporting that
       work is a separate unit. *)
    (forall (O <: Oracle_MEUFGCMA_WOTSTWESNPRF{-R_int_WOTSTW, -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -R_top_C, -WitnessF}) (OC <: FC.Oracle_THFC{-R_int_WOTSTW, -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -R_top_C, -WitnessF}),
       islossless O.query => islossless OC.query =>
       islossless R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF)), O, OC).choose) =>
    (forall (O <: Oracle_MEUFGCMA_WOTSTWESNPRF{-R_int_WOTSTW, -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -R_top_C, -WitnessF}) (OC <: FC.Oracle_THFC{-R_int_WOTSTW, -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -R_top_C, -WitnessF}),
       islossless R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF)), O, OC).forge) =>
    Pr[EUFCMA_C10(WitnessF).main() @ &m : res]
      (* +C SKG-PRF advantage: GROUNDED (was the free real skg_adv) to the exact
         concrete R_SKGPRF_EUFCMA_C PRF-distinguishing term that hop-2 (SKGPRF_C_hop)
         delivers. *)
      <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(WitnessF), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
           - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(WitnessF), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
       (* +C subst #1: FORS+C10 CONCRETE expansion.  The ITSR(+C)/C10 term is now over
          the WitnessF-DERIVED reduction R_ITSRC10_Gproc(R_fors_p(WitnessF)) (was the free
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
       + ( (   (w - 2)%r
               * `|Pr[FC_UD.SM_DT_UD_C(R_SMDTUDC_Game23WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF)))),
                       FC_UD.O_SMDTUD_Default, FC.O_THFC_Default).main(false) @ &m : res]
                   - Pr[FC_UD.SM_DT_UD_C(R_SMDTUDC_Game23WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF)))),
                       FC_UD.O_SMDTUD_Default, FC.O_THFC_Default).main(true) @ &m : res]|
             + Pr[FC_TCR.SM_DT_TCR_C(R_SMDTTCRC_Game34WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF)))),
                     FC_TCR.O_SMDTTCR_Default, FC.O_THFC_Default).main() @ &m : res]
             + ( Pr[FC_PRE.SM_DT_PRE_C(R_SMDTPREC_Game4WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF)))),
                       FC_PRE.O_SMDTPRE_Default, FC.O_THFC_Default).main() @ &m : res]
               + Pr[Game4_WOTSTWES_BadEnc(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF)))).main() @ &m
                       : res /\ BadEncFlag.badenc] ) )
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(WitnessF)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(WitnessF)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res] ).
proof.
by apply (EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS_PINNED_ENCODER_QWIRED_WOTSCHARGED WitnessF &m).
qed.
