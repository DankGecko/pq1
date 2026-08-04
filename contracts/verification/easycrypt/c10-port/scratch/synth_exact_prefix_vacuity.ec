(* ==========================================================================
   STATUS 2026-07-25 -- READ BEFORE INTERPRETING THIS FILE.

   This file is the HISTORICAL DEFECT WITNESS.  It proves that the two
   PROPOSITIONS hembdisj / hembinj are JOINTLY CONTRADICTORY, and that anything
   carrying BOTH is vacuous.  IT STILL COMPILES AFTER THE REPAIR, AND IT SHOULD:
   the two propositions are still contradictory -- that is a fact about the
   propositions, not about any lemma.

   WHAT CHANGED: SphincsC10CapstoneWired.EUFCMA_SPHINCS_PLUS_C10 and
   XmssmtCC_All.EUFNAGCMA_FLSLXMSSMTTWCESNPRF NO LONGER CARRY THEM.  `hembinj` was
   ELIMINATED (its obligation is now discharged from the PROVEN game invariant
   R_ts_allvalid via the THEOREM emb_dist_valid); `hembdisj` is discharged at the
   capstone by the PROVEN theorem emb_disj_concrete.  So `CAPSTONE_IS_VACUOUS`
   below no longer applies to the capstone -- its hypotheses are not the
   capstone's hypotheses any more.

   THE POST-REPAIR RECEIPTS (run these, not this file):
     scratch/synth_repaired_nonvacuity.ec   -> MUST BE GREEN (0-admit)
     scratch/synth_repaired_canary1.ec      -> MUST BE REJECTED
     scratch/synth_repaired_canary2.ec      -> MUST BE REJECTED
     scratch/synth_repaired_canary3.ec      -> MUST BE REJECTED
                                               (instantiates the REPAIRED capstone
                                                and fails to derive Pr <= -1%r)
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
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.
import HA.Adrs.

(* EXACT-PREFIX VACUITY PROBE: identical require/import prefix to
   SphincsC10CapstoneWired.ec, so `emb_tw`/`get_wgpidxs`/`valid_wadrs`/`adrs`
   resolve to EXACTLY the symbols the capstone premises mention. *)
lemma wgp_embv (s : int list) (p : int) :
  drop 2 (put (put (put s 0 0) 1 0) 3 p) = put (drop 2 s) 1 p.
proof. by rewrite drop_put 1://= !drop_put_out //=. qed.

lemma emb_gp_idem (a : adrs) :
  get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw (emb_tw a)).
proof.
have hsz : size (val a) = adrs_len.
+ by move: (valP a); rewrite /valid_adrsidxs => -[-> _].
rewrite /get_wgpidxs !emb_tw_val !wgp_embv.
apply (eq_from_nth witness); 1: by rewrite !size_put.
move=> i hi; rewrite !nth_put; 1,2,3: smt(size_put).
by case (1 = i).
qed.

(* the capstone's hembdisj (:447) and hembinj (:448-449), copied VERBATIM *)
lemma CAPSTONE_PREMISES_CONTRADICTORY :
     (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b))
  => (forall (a b : adrs),
        get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b) => get_wgpidxs a = get_wgpidxs b)
  => false.
proof.
move=> hembdisj hembinj.
have [a va] := nonvac_guard.
have heq := hembinj a (emb_tw a) (emb_gp_idem a).
by move: (hembdisj a a va).
qed.

(* THE CONSEQUENCE, stated directly: under the capstone's own premise pair the LHS
   probability is bounded by ANYTHING, e.g. by -1 -- the signature of vacuity. *)
lemma CAPSTONE_IS_VACUOUS (F <: Adv_EUFCMA_C{-DSSC.Stateless.O_CMA_Default}) &m :
     (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b))
  => (forall (a b : adrs),
        get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b) => get_wgpidxs a = get_wgpidxs b)
  => Pr[EUFCMA_C10(F).main() @ &m : res] <= -1%r.
proof.
move=> h1 h2; have := CAPSTONE_PREMISES_CONTRADICTORY h1 h2; smt().
qed.
