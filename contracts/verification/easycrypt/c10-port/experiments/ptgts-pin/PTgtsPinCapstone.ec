(* ==========================================================================
   PTgtsPinCapstone.ec -- THE DEPLOYED CAPSTONE WITH `c <= p_tgts` DISCHARGED.

   This is TARGET P3's deliverable: the thing that changes.  The statement below
   is C10DeployedCapstone.ec's `EUFCMA_SPHINCS_PLUS_C10_CONTENTFUL_AT_DEPLOYED_ENCODER`
   with ONE premise replaced --

       c <= p_tgts          (a condition on an ABSTRACT constant, FALSE under the
                             permitted interpretation p_tgts = 0)
       p_tgts = c10_p_tgts  (the deployed PIN, = 262656 = c, proved least
                             admissible in PTgtsPin.ec section 3)

   -- and everything else, premises and conclusion alike, identical.  The
   statement was extracted MECHANICALLY from lines 280-394 of the certified file
   (a python slice + one string replacement), not retyped.

   AND THAT IDENTITY IS CHECKED, not merely asserted: `check_stmt_identity.sh`
   re-derives the slice from cdrafts-split/C10DeployedCapstone.ec, applies the
   single replacement, and diffs it against this file (and against the three
   capstone controls).  It is wired into runall.sh.  Self-tested: perturbing one
   token deep in the premise list (`8 * n * k` -> `8 * n * a`) makes it report
   BROKEN with the offending line.  The generator's own `assert` only checked
   that the OLD premise was PRESENT, which would not have caught drift anywhere
   else in the 115 lines.

   HONEST READING.  This does not make the capstone unconditional; it converts
   an unpinned side condition into an instantiation choice with a computed
   value.  That is the same move C10DeployedInstance.ec makes for `emb_in`
   (`emb_in = c10_embg`), and it is weaker than a theorem, deliberately: nothing
   inside an elaborated EasyCrypt theory can prove what a declared `const` is.

   CERTIFIED TREES UNTOUCHED: this file lives in experiments/ and only
   `require import`s cdrafts-split/ and base-c10-split/.
   ========================================================================== *)
require import AllCore List Distr StdBigop StdOrder IntDiv RealExp.
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
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.
require import SphincsC10CapstoneWired.
require import SphincsC10Content.
require import C10DeployedInstance.
require import C10DeployedCapstone.
require import C10DeployedScope.

lemma EUFCMA_SPHINCS_PLUS_C10_AT_PINNED_PTGTS
  (F <: Adv_EUFCMA_C{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V, -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default,
             -R_top,
             -DSSC.Stateless.O_CMA_Default, -O_CMA_SPHINCSPLUSTWC_FS,
             -SKG_PRF.O_PRF_Default, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V,
             -R_top_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV,
             -R_fors_p, -O_CMA_Gproc, -O_CMA_Gproc_I, -R_ITSRC10_Gproc,
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default })
  (mkg_adv : real)
  (mtree_openpre mtree_trh mtree_trco : real)
  &m :
    (* THE ENCODER IS THE DEPLOYED ONE -- these two replace the free LEN/INJ
       hypotheses the original carries, and DISCHARGE them. *)
    STCRC_WC.G.CntrFT.card <= 2 ^ c10_r =>
    emb_in = c10_embg =>
    (* ---- THE ONLY DELTA vs the deployed capstone: `c <= p_tgts` is REPLACED
           by the PIN that implies it (PTgtsPin.c10_c_le_p_tgts_at_pin).  Every
           other premise, and the entire conclusion, is byte-identical to
           C10DeployedCapstone.ec:280-394 -- extracted mechanically, not
           retyped. ---- *)
    p_tgts = c10_p_tgts =>
    0%r <= mkg_adv =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC0 <> 8 * n =>
    dfC0 <> 8 * n * len =>
    dfC0 <> 8 * n * 2 =>
    dfC0 <> 8 * n * k =>
    (   Pr[EUF_CMA_Gproc_I(R_fors_p(F)).main() @ &m
             : res /\ !EUF_CMA_Gproc_I.covered]
     <= mtree_openpre + mtree_trh + mtree_trco) =>
    (* ---- N1 IS NO LONGER A PREMISE: discharged by `N1_holds` above, which
           needs the predC tie (WOTS_C_Real) AND the cw_sum/digitsum bridge.
           The `(target_sum : int)` binder was ALSO removed: it SHADOWED the
           global `target_sum`, which is why N1 could not be discharged in
           place even after both were available. ---- *)
    (* ---- N2: p_nu -- a good counter always exists (witness: MODEL_N1_N2) ---- *)
    (forall (ps : pseed) (ad : adrs) (mm : dgstblock), exists (cc : cntr), predC (ThC ps ad mm cc)) =>
    (* ---- N3/N4: emb_in constant-width + injective (witness: MODEL_emb_in) ---- *)
       (* ==== CONCLUSION 1: THE CAPSTONE BOUND, UNCHANGED AND UNWEAKENED ==== *)
       (Pr[EUFCMA_C10(F).main() @ &m : res]
          <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
               - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
           + mkg_adv
           + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(F)),
                              M.F.O_ITSRC10_Default).main() @ &m : res]
               + mtree_openpre + mtree_trh + mtree_trco )
           + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                          O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
               + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                   STCRC_WC.O_STCRC_Default).main() @ &m : res]
               + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(F)),
                      FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                      FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
               + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(F)),
                      FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                      FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res] ))
       (* ==== CONCLUSION 2 (the V1 MECHANISM excluded): the EXACT hypothesis of
               predC_false_zeroes_capstone_LHS is REFUTED.
               PRECISION (do not overstate): refuting an implication's hypothesis does
               NOT falsify its conclusion.  What is established is that the KNOWN
               MECHANISM by which the LHS was shown identically zero is excluded -- NOT
               that the LHS is nonzero.  Proving `Pr[EUFCMA_C10(F0)] > 0` for some F0
               needs honest-signature verification through the d-layer address/root
               bookkeeping of `root_from_sigC`, i.e. SCHEME CORRECTNESS, which MM45
               never proves for any scheme and which is the genuine next rung. ==== *)
    /\ (! (forall (x : msgWOTS), ! predC x))
       (* ==== CONCLUSION 3: the FORS `good_pos` SHAPE, DERIVED (uses the
               inherited FTWES.ddgstblock_fu; see the header disclosure). ==== *)
    /\ 0%r < mu dmsgWOTS predC
       (* ==== CONCLUSION 4: EVERY honestly-ground counter passes the +C gate,
               at EVERY (ps,ad,m).  This is the mechanism the V1 audit zeroed. ==== *)
    /\ (forall (ps : pseed) (ad : adrs) (mm : dgstblock), predC (ThC ps ad mm (grindC ps ad mm)))
       (* ==== CONCLUSION 5 (the V2 MECHANISM excluded): the S-TCR(+C) win condition is a GENUINE
               second preimage on a SINGLE collection member at a SINGLE tweak --
               not a trivial coincidence forced by a collapsing serialisation. ==== *)
    (* ROUTE (D) [REWRITTEN 2026-08-01 after adversarial review].  The previous
       route-(D) restatement was DEFECTIVE: it had NO collision antecedent and
       NO projected equality -- its last two conjuncts were just ThC's
       DEFINITION (ThC_same_member), which holds unconditionally and asserts
       nothing about a second preimage, while the header above kept promising
       one.  ThC_coll_projects was never used.  That is the same
       still-compiles-but-no-longer-means-it defect this file keeps catching,
       introduced by me and caught by external review.

       This is now the REAL statement: FROM a ThC collision, at the fixed
       challenged member dfC0, on DISTINCT inputs -- i.e. exactly
       SMDTTCRC's winning condition. *)
    /\ (forall (ps : pseed) (tw : adrs) (mm mm' : dgstblock) (j cc : cntr),
          mm' <> mm =>
          ThC ps tw mm j = ThC ps tw mm' cc =>
             emb_in0 (mm, j) <> emb_in0 (mm', cc)
          /\ thfc dfC0 ps (emb_tw tw) (emb_in0 (mm , j ))
           = thfc dfC0 ps (emb_tw tw) (emb_in0 (mm', cc)))
       (* ==== CONCLUSION 6: on the gate-restricted set, MM45's `two_encodings`
               antichain condition holds.

               HONESTY NOTE (2026-07-25, established by running the control
               scratch/trackV_probe_C6_without_N1.ec, which COMPILED): unlike
               conclusions 2-5, THIS conclusion is NOT premise-dependent.  It is
               already derivable from MM45's own unconditional `two_encodings`
               AXIOM (WOTS_TW_ES.ec:571), because `encode_msgWOTS d <>
               encode_msgWOTS d'` forces `d <> d'`.  It is retained only to
               display the relationship; it adds NO content here.
               The INFORMATIVE version is PART B above
               (`constsum_encoding_is_two_encodings`), which is quantified over an
               ARBITRARY encoding E and therefore genuinely shows that a
               CHECKSUM-FREE constant-sum encoding satisfies the antichain
               condition -- a fact the ambient axiom cannot supply. ==== *)
    /\ (forall (d d' : msgWOTS),
          predC d => predC d' => encode_msgWOTS d <> encode_msgWOTS d' =>
          exists (i : int), 0 <= i < len
                 /\ BaseW.val (encode_msgWOTS d).[i] < BaseW.val (encode_msgWOTS d').[i]).
proof.
move=> hcard hemb hpin hmkg hencb hdf8n hdflen hdf2 hdfnk htree hN2.
exact (EUFCMA_SPHINCS_PLUS_C10_CONTENTFUL_AT_DEPLOYED_ENCODER
         F mkg_adv mtree_openpre mtree_trh mtree_trco &m
         hcard hemb (c10_c_le_p_tgts_at_pin hpin)
         hmkg hencb hdf8n hdflen hdf2 hdfnk htree hN2).
qed.
