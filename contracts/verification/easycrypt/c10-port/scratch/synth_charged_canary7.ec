(* ==========================================================================
   MUST-FAIL CONTROL #7 — "IS THE CAPSTONE'S CHARGE LOAD-BEARING?"

   THIS FILE MUST BE **REJECTED** BY EASYCRYPT.
   A GREEN COMPILE HERE IS A REGRESSION, NOT A RESULT.

   It asserts `EUFCMA_SPHINCS_PLUS_C10_CHARGED` with the grind-failure summand
   DROPPED from the hypertree group.  If that compiled, the charged capstone
   would be numerically identical to a capstone that assumes nothing about the
   grind -- i.e. the whole N2-to-charged-term chain would be decorative at the
   top level, which is the only level a reader cares about.

   EXPECTED FAILURE REASON: "cannot prove goal (strict)" at the final smt().
   ========================================================================== *)
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
require import SphincsC10CapstoneCharged.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.

lemma canary7_capstone_charge_is_inert
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
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    (* N2 IS GONE FROM THIS CAPSTONE (2026-07-31).  It used to sit here, carried
       from interactive_D1_MA up through XmssmtCC_All, because the P-relativized
       fork retired MM45's two encoding axioms by GATING the WOTS-TW game on
       `P m /\ P m'`, which made grind-success load-bearing.  It is now a SUMMAND
       instead of a hypothesis -- see the last term of the conclusion.  That is a
       relocation, NOT a discharge: nothing in this repository bounds that term,
       and by experiments/tcollres-leg/FINDING-n2-is-independent.md it cannot be
       proved zero (there is a model of the closure where the grind fails
       everywhere and the term equals the whole success mass). *)
    dfC <> 8 * n =>
    dfC <> 8 * n * len =>
    dfC <> 8 * n * 2 =>
    dfC <> 8 * n * k =>   (* 4th C10 width fact: bridges all FOUR member axes at R_top_C(F) *)
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
move=> hc hmkg hencb hdf8n hdflen hdf2 hdfnk htree.
have h := EUFCMA_SPHINCS_PLUS_C10_CHARGED F mkg_adv mtree_openpre mtree_trh mtree_trco &m
              hc hmkg hencb hdf8n hdflen hdf2 hdfnk htree.
smt().
qed.
