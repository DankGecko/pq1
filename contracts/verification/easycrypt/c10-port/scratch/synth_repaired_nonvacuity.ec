(* ==========================================================================
   THE REPAIR RECEIPT (2026-07-25).  Companion to scratch/synth_exact_prefix_vacuity.ec.

   READ THIS FIRST.  `synth_exact_prefix_vacuity.ec` proves that the two
   PROPOSITIONS

     hembdisj : forall a b, valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)
     hembinj  : forall a b, get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b)
                         => get_wgpidxs a = get_wgpidxs b

   are JOINTLY CONTRADICTORY.  That file still compiles after the repair, and it
   SHOULD: the two propositions are still contradictory: that is a fact about the
   propositions, not about any lemma.  What changed is that
   `SphincsC10CapstoneWired` and `XmssmtCC_All.EUFNAGCMA_FLSLXMSSMTTWCESNPRF` NO
   LONGER CARRY THEM -- `hembinj` was ELIMINATED (the obligation it served is now
   discharged from the PROVEN game invariant `R_ts_allvalid`), and `hembdisj` is
   discharged at the capstone by the PROVEN theorem `emb_disj_concrete`.

   So the receipt that the defect is gone CANNOT be "the old witness now fails".
   It is this THREE-FILE set:

     scratch/synth_repaired_nonvacuity.ec  (THIS FILE)   -> MUST BE **GREEN**, 0-admit
        the POSITIVE half: the emb_tw axis is now carried by THEOREMS, they
        COEXIST at a witnessed valid address, and the replacement premise is LIVE
        AT SIZE 2 (not merely at a singleton, where the lemma it feeds would be
        vacuously true).
     scratch/synth_repaired_canary1.ec                   -> MUST BE **REJECTED**
        take the REPAIRED capstone's premise list VERBATIM, try to derive `false`.
     scratch/synth_repaired_canary2.ec                   -> MUST BE **REJECTED**
        same premise list, try to derive `Pr[EUFCMA_C10(F)] <= -1%r` -- the exact
        vacuity signature scratch/synth_exact_prefix_vacuity.ec exhibited for the
        OLD premise list.

   A green compile of either canary file is a REGRESSION, not a success.
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

(* --------------------------------------------------------------------------
   POSITIVE HALF (these ARE theorems; they are what replaced the premise).
   -------------------------------------------------------------------------- *)

(* (P1) The surviving disjointness half is a THEOREM -- so carrying it anywhere
   cannot introduce a contradiction. *)
lemma P1_hembdisj_is_a_theorem :
  forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b).
proof. exact emb_disj_concrete. qed.

(* (P2) The GUARDED injectivity -- the shape the repair actually uses -- is a
   THEOREM too, so the repaired chain assumes nothing on this axis. *)
lemma P2_guarded_injectivity_is_a_theorem :
  forall (a b : adrs),
       valid_wadrs a => valid_wadrs b
    => get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b)
    => get_wgpidxs a = get_wgpidxs b.
proof. exact hembinj_repaired. qed.

(* (P3) The two facts COEXIST -- jointly, at a WITNESSED valid address.  This is
   the direct contrast with the old pair: the old (disj, UNGUARDED inj) pair had
   no model; the new (disj, GUARDED inj) pair is realised by actual theorems. *)
lemma P3_new_emb_axis_is_consistent :
  exists (a : adrs),
       valid_wadrs a
    /\ (forall (b : adrs), get_wgpidxs a <> get_wgpidxs (emb_tw b))
    /\ (forall (b : adrs), valid_wadrs b =>
          get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b) => get_wgpidxs a = get_wgpidxs b).
proof.
have [a va] := nonvac_guard.
exists a.
split; first exact va.
split.
+ by move=> b; exact (emb_disj_concrete a b va).
by move=> b vb; exact (hembinj_repaired a b va vb).
qed.

(* (P4) SATISFIABILITY AT SIZE 2 -- the mandatory gate.  `emb_dist_valid` is
   vacuously true at |l| <= 1, so a singleton witness would prove nothing.  Here
   the new premise set is LIVE at a TWO-element list with genuinely DISTINCT
   group prefixes, i.e. at the size where the lemma does real work. *)
lemma P4_two_distinct_valid_groups :
  exists (a b : adrs),
    valid_wadrs a /\ valid_wadrs b /\ get_wgpidxs a <> get_wgpidxs b.
proof.
have vl0 : valid_lidx 0 by rewrite /valid_lidx; smt(ge1_d).
have vt0 : valid_tidx 0 0 by rewrite /valid_tidx /nr_trees; smt(IntOrder.expr_gt0).
have vk0 : valid_kpidx 0 by rewrite /valid_kpidx; smt(ge2_lp).
have vk1 : valid_kpidx 1 by rewrite /valid_kpidx; smt(ge2_lp).
exists (set_kpidx (set_typeidx (set_ltidx adz 0 0) chtype) 0)
       (set_kpidx (set_typeidx (set_ltidx adz 0 0) chtype) 1).
split; first by apply (validxadrs_validwadrs_setallboch 0 0 0 adz); rewrite ?valx_adz.
split; first by apply (validxadrs_validwadrs_setallboch 0 0 1 adz); rewrite ?valx_adz.
rewrite /get_wgpidxs.
apply (neq_from_nth witness _ _ 0).
rewrite !nth_drop //=.
by apply (neqkpidx_setkptypelt 0 0 0 0 chtype 0 1 adz); rewrite ?valx_adz //=.
qed.

lemma P5_new_premise_live_at_size2 :
  exists (l : adrs list),
    size l = 2 /\ all valid_wadrs l /\ uniq_wgpidxs l /\ uniq (map emb_tw l).
proof.
have [a b [va [vb hne]]] := P4_two_distinct_valid_groups.
have hall : all valid_wadrs [a; b] by rewrite /= va vb.
have huq  : uniq_wgpidxs [a; b] by rewrite /uniq_wgpidxs /= hne.
exists [a; b].
split; first by [].
split; first exact hall.
split; first exact huq.
exact (emb_dist_valid [a; b] hall huq).
qed.

(* (P6) The two REAL-valued premises of the repaired capstone are JOINTLY
   SATISFIABLE at concrete values -- so neither is a hidden `false`.  (The
   H-TREE-MULTI premise is FALSE-AT-ZERO by design, hence stated as a premise;
   satisfiable it certainly is.) *)
lemma P6_real_premises_satisfiable
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
