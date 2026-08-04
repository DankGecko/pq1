(* ==========================================================================
   XmssmtCCCharged.ec — propagating the CHARGED (N2-free) WOTS-TW leg upward.

   `GFailCharged.ec` replaced hop2's universal N2 premise with a visible summand
   and produced `interactive_D1_MA_charged`.  This file carries that upward
   through the hypertree chain that the capstone actually traverses.

   WHY A SEPARATE FILE.  Purely additive: XmssmtCC_All.ec is not touched, so the
   existing N2-carrying chain and every consumer of it stay exactly as they are,
   and the two chains coexist.  That also keeps the 727s XmssmtCC_All rebuild out
   of the edit loop.

   WHICH CHAIN.  `interactive_D1_MA`, not plain `interactive_D1` --
   XmssmtCC_All.ec:1205 is what the capstone chain applies, because plain D1 is
   not composable for the hypertree adversary (the member-aware repair note in
   WOTS_C_Interactive.ec explains why).  An adversarial review caught this
   before the wrong lemma got built.

   THE PATTERN, once per lemma:
     - DELETE the N2 premise,
     - ADD the charged summand for the SAME adversary the original instantiates,
     - keep the proof, swapping the N2 lemma for its charged counterpart.
   Restriction sets are carried over VERBATIM.  That is only possible because
   the charged chain has no instrumented module to restrict against -- see the
   revision note at the top of GFailCharged.ec for why that mattered.

   NOT A DISCHARGE OF N2.  The summand is unbounded in this repository.
   ========================================================================== *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import DList DMap.
require import BinaryTrees MerkleTrees.
require import BitEncoding.
import BS2Int.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.
require import GFailCharged.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.

(* --------------------------------------------------------------------------
   UNIT 1 — the leaf reduction's WOTS+C bound, charged.

   Mirrors `leaf_reduction_MEUFGCMAWOTSC_bound` (XmssmtCC_All.ec:1165) with the
   N2 premise removed and the grind-failure summand added.  The side condition
   is discharged by exactly the same `R_leaf_C_A_wf_MA` step.
   -------------------------------------------------------------------------- *)
lemma leaf_reduction_MEUFGCMAWOTSC_bound_charged
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C }) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC0 <> 8 * n =>
    dfC0 <> 8 * n * len =>
    dfC0 <> 8 * n * 2 =>
    hoare[ A_ht(O_THFC_MA).choose :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC0) O_THFC_MA.tws_ma ] =>
    Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
                             O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                         STCRC_WC.O_STCRC_Default).main() @ &m : res]
     + Pr[GAME1_INT(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
                    O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
            res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
move=> hc hembdisj hencb hdf8n hdflen hdf2 A_wf_ht.
apply (interactive_D1_MA_charged (R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)) &m hc hembdisj hencb).
by apply (R_leaf_C_A_wf_MA A_ht hdf8n hdflen hdf2 A_wf_ht).
qed.

(* --------------------------------------------------------------------------
   SUBSUMPTION AT THIS LEVEL TOO.  Re-derives the ORIGINAL
   `leaf_reduction_MEUFGCMAWOTSC_bound` (N2 premise, two summands) from the
   charged form, so the charged chain implies the existing one here as well and
   not merely at the D.1 level.  Restriction set is verbatim the original's.
   -------------------------------------------------------------------------- *)
lemma leaf_reduction_MEUFGCMAWOTSC_bound_from_charged
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C }) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    (forall (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock),
       exists (cc : cntr), predC (ThC ps0 ad0 m0 cc)) =>
    dfC0 <> 8 * n =>
    dfC0 <> 8 * n * len =>
    dfC0 <> 8 * n * 2 =>
    hoare[ A_ht(O_THFC_MA).choose :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC0) O_THFC_MA.tws_ma ] =>
    Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
                             O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                         STCRC_WC.O_STCRC_Default).main() @ &m : res].
proof.
move=> hc hembdisj hencb hN2 hdf8n hdflen hdf2 A_wf_ht.
have hch := leaf_reduction_MEUFGCMAWOTSC_bound_charged A_ht &m hc hembdisj hencb
              hdf8n hdflen hdf2 A_wf_ht.
have hz := gfail_zero_under_N2 (R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)) &m hN2.
smt().
qed.

(* --------------------------------------------------------------------------
   UNIT 2 — the branch-1 seam composed with the leaf bound, charged.
   Mirrors `seam_branch1_leaf_composed` (XmssmtCC_All.ec:3743).  `seam_branch1_
   WOTSC` is already N2-free, so only the leaf half changes.
   -------------------------------------------------------------------------- *)
lemma seam_branch1_leaf_composed_charged
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V }) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC0 <> 8 * n =>
    dfC0 <> 8 * n * len =>
    dfC0 <> 8 * n * 2 =>
    hoare[ A_ht(O_THFC_MA).choose :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC0) O_THFC_MA.tws_ma ] =>
    hoare[ A_ht(FC.O_THFC_Default).choose :
             FC.O_THFC_Default.tws = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws ] =>
    Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A_ht, FC.O_THFC_Default).main() @ &m :
         res /\ EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                         STCRC_WC.O_STCRC_Default).main() @ &m : res]
     + Pr[GAME1_INT(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
                    O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
            res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
move=> hc hembdisj hencb hdf8n hdflen hdf2 A_wf_ht allnchads.
have hseam := seam_branch1_WOTSC A_ht &m hc hembdisj hencb
                hdf8n hdflen hdf2 A_wf_ht allnchads.
have hleaf := leaf_reduction_MEUFGCMAWOTSC_bound_charged A_ht &m hc hembdisj hencb
                hdf8n hdflen hdf2 A_wf_ht.
smt().
qed.

(* --------------------------------------------------------------------------
   UNIT 3 — lifted to the REAL EUF-NAGCMA game, charged.
   Mirrors `seam_branch1_lifted_to_REAL` (XmssmtCC_All.ec:5007); same
   EqPr + mu_split on `valid_WOTSTWES`, one extra summand carried through.
   -------------------------------------------------------------------------- *)
lemma seam_branch1_lifted_to_REAL_charged
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V }) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC0 <> 8 * n =>
    dfC0 <> 8 * n * len =>
    dfC0 <> 8 * n * 2 =>
    hoare[ A_ht(O_THFC_MA).choose :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC0) O_THFC_MA.tws_ma ] =>
    hoare[ A_ht(FC.O_THFC_Default).choose :
             FC.O_THFC_Default.tws = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws ] =>
    Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A_ht, FC.O_THFC_Default).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                         STCRC_WC.O_STCRC_Default).main() @ &m : res]
     + Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A_ht, FC.O_THFC_Default).main() @ &m :
            res /\ !EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES]
     + Pr[GAME1_INT(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
                    O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
            res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
move=> hc hembdisj hencb hdf8n hdflen hdf2 A_wf_ht allnchads.
have hcomp := seam_branch1_leaf_composed_charged A_ht &m hc hembdisj hencb
                hdf8n hdflen hdf2 A_wf_ht allnchads.
rewrite (EqPr_EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Orig_V A_ht FC.O_THFC_Default &m).
rewrite Pr[mu_split EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES].
smt().
qed.

(* --------------------------------------------------------------------------
   UNIT 4 — the hypertree headline, charged.  THIS is the lemma the capstone
   calls (SphincsC10CapstoneWired.ec:624).

   Mirrors `EUFNAGCMA_FLSLXMSSMTTWCESNPRF` (XmssmtCC_All.ec:8532).  Branch 2
   (`seam_branch2`) is already N2-free, so only the branch-1 half changes; the
   `!valid_WOTSTWES` residue of unit 3 is what branch 2 absorbs.
   -------------------------------------------------------------------------- *)
lemma EUFNAGCMA_FLSLXMSSMTTWCESNPRF_charged
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V,
             -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default }) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC0 <> 8 * n =>
    dfC0 <> 8 * n * len =>
    dfC0 <> 8 * n * 2 =>
    hoare[ A_ht(O_THFC_MA).choose :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC0) O_THFC_MA.tws_ma ] =>
    hoare[ A_ht(FC.O_THFC_Default).choose :
             FC.O_THFC_Default.tws = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws ] =>
    hoare[ A_ht(R_SMDTTCRCPKCO_C(A_ht, FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                                 FSSLXMTWES.PKCOC.O_THFC_Default).O_THFC).choose :
             R_SMDTTCRCPKCO_C.O_THFC.ads = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads ] =>
    hoare[ A_ht(R_SMDTTCRCTRH_C(A_ht, FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                                FSSLXMTWES.TRHC.O_THFC_Default).O_THFC).choose :
             R_SMDTTCRCTRH_C.O_THFC.ads = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads ] =>
    Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A_ht, FC.O_THFC_Default).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                         STCRC_WC.O_STCRC_Default).main() @ &m : res]
     + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(A_ht),
            FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
            FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
     + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(A_ht),
            FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
            FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res]
     + Pr[GAME1_INT(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
                    O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
            res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
move=> hc hembdisj hencb hdf8n hdflen hdf2 A_wf_ht allnchads
       allnpkcoads allntrhads.
have h1 := seam_branch1_lifted_to_REAL_charged A_ht &m hc hembdisj hencb
             hdf8n hdflen hdf2 A_wf_ht allnchads.
have h2 := seam_branch2 A_ht &m hencb allnpkcoads allntrhads.
smt().
qed.

(* --------------------------------------------------------------------------
   UNIT 6 — the members-4 variant, charged.
   Mirrors `leaf_reduction_MEUFGCMAWOTSC_bound_members4` (XmssmtCC_All.ec:9273):
   same lemma as unit 1 but with the member axis stated via `in_thfc4`, collapsed
   by `all_in_thfc4_neq_dfC`.  Off the capstone's direct path, but it is what
   `_Rtop` (unit 7) builds on.
   -------------------------------------------------------------------------- *)
lemma leaf_reduction_MEUFGCMAWOTSC_bound_members4_charged
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C }) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC0 <> 8 * n => dfC0 <> 8 * n * len => dfC0 <> 8 * n * 2 => dfC0 <> 8 * n * k =>
    hoare[ A_ht(O_THFC_MA).choose :
             O_THFC_MA.tws_ma = [] ==> all in_thfc4 O_THFC_MA.tws_ma ] =>
    Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
                             O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                         STCRC_WC.O_STCRC_Default).main() @ &m : res]
     + Pr[GAME1_INT(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
                    O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
            res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
move=> hc hembdisj hencb h1 h2 h3 h4 hA.
apply (leaf_reduction_MEUFGCMAWOTSC_bound_charged A_ht &m hc hembdisj hencb h1 h2 h3).
conseq hA => //.
by move=> &hr _ tws_ma; apply (all_in_thfc4_neq_dfC tws_ma h1 h2 h3 h4).
qed.

(* --------------------------------------------------------------------------
   UNIT 7 — the same at A_ht := R_top(F), charged.
   Mirrors `leaf_reduction_MEUFGCMAWOTSC_bound_Rtop` (XmssmtCC_All.ec:9835); the
   member axis is discharged by the proven port `R_top_members4`.
   -------------------------------------------------------------------------- *)
lemma leaf_reduction_MEUFGCMAWOTSC_bound_Rtop_charged
  (F <: Adv_EUFCMA_C{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -R_top }) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC0 <> 8 * n => dfC0 <> 8 * n * len => dfC0 <> 8 * n * 2 => dfC0 <> 8 * n * k =>
    Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top(F)),
                             O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top(F))),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top(F))),
                         STCRC_WC.O_STCRC_Default).main() @ &m : res]
     + Pr[GAME1_INT(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top(F)),
                    O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
            res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
move=> hc hembdisj hencb h1 h2 h3 h4.
apply (leaf_reduction_MEUFGCMAWOTSC_bound_members4_charged (R_top(F)) &m hc hembdisj hencb
         h1 h2 h3 h4).
apply (R_top_members4 F).
qed.
