require import AllCore List Distr.
require import XmssmtCC_All.

require import SPHINCS_PLUS.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
require WOTS_C_Real WOTS_C_Scheme WOTS_C_Interactive.
import WOTS_C_Real.
import WOTS_C_Scheme.
import WOTS_C_Interactive.

(* ==========================================================================
   stcr_reduction_wip.ec  --  the +C S-TCR summand of the XMSS-MT component
                              theorem, made honest at the assumption level.

   TARGET.  The component theorem `EUFNAGCMA_FLSLXMSSMTTWCESNPRF`
   (XmssmtCC_All.ec:8439) has, as its bespoke +C summand,

     Pr[ S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                        STCRC_WC.O_STCRC_Default).main() @ &m : res ]        (*S*)

   (`R_MEUFGCMAWOTSC_EUFNAGCMA_C` = the paper's leaf reduction R_leaf_C).  (*S*)
   is the advantage of the reduction adversary in the *interactive,
   collection-/member-aware S-TCR(+C)* game `S_TCR_C_Int_MA`.  Until now this
   was flagged "not a standard hardness assumption".  This file closes that
   caveat in the two priority levels the task sets.

   --------------------------------------------------------------------------
   (1) THE HONEST RELABEL  (this file, CERTIFIED-0-ADMIT).
   --------------------------------------------------------------------------
   `S_TCR_C_Int_MA` IS, by definition, the collection-aware S-TCR(+C) game.
   Its win predicate is
        0<=i<nrts /\ 0<=nrts<=p_tgts /\ uniq (map emb_tw twsOraw)
        /\ m'<>m /\ ThC pp tw m j = ThC pp tw m' ctr
        /\ FC.disj_lists (map (fun t => (dfC, emb_tw t)) twsOraw) twsMA.
   The already-proven predicate bridge `S_TCR_C_Int_MA_win_implies_2ndpreimage`
   (WOTS_C_Interactive.ec:2145) shows that this win predicate implies the
   STANDARD single-member SM-DT-TCR(+C) 2nd-preimage predicate for the fixed
   collection member `thfc dfC` at tweak `emb_tw tw`:
        0<=i<nrts /\ 0<=nrts<=t /\ uniq (map emb_tw twsOraw)
        /\ emb_in (m,j) <> emb_in (m',ctr)
        /\ thfc dfC pp (emb_tw tw) (emb_in (m,j))
         = thfc dfC pp (emb_tw tw) (emb_in (m',ctr))
        /\ FC.disj_lists (map (fun t => (dfC, emb_tw t)) twsOraw) twsMA
   (member/tweak/inputs = the value dictionary at WOTS_C_Interactive.ec:471-476;
   `SMDTTCRC.SM_DT_TCR_C` shape, TweakableHashFunctions.eca:745).

   PART 1 below packages (S) as the InSec notion of the paper's Thm 5.2: it
   defines `S_TCR_C_Int_MA_asStd`, the SAME game with its win RELABELLED to that
   standard single-member 2nd-preimage predicate, and proves
        (S)  <=  Pr[ S_TCR_C_Int_MA_asStd(...) : res ].
   So the +C summand is bounded by the advantage of finding a genuine standard
   single-member target-collision on the tweakable hash member `thfc dfC` — the
   `InSec^{S-TCR(+C)}(Th; .)` quantity of the paper (Def C.1 / App C).  This is
   the "Thla-lifted" collection-aware form Thm 5.2 uses; restricted to
   no-collection-query adversaries (`twsMA = []`, so `disj_lists .. []` is
   vacuously true) it is verbatim Def C.1 (S-TCR(Prop)) with Prop = predC.

   The two modelling premises `emb_in_len` / `emb_in_inj` are the concrete
   `M || counter` serialisation facts (fixed-width => same length => one member;
   field-injective => real 2nd-preimage) threaded as HYPOTHESES exactly as the
   file threads embdisj/embinj/encb — never axioms (the sweep stays 0-axiom).
   See WOTS_C_Interactive.ec:369-395 for their faithfulness/non-vacuity.

   --------------------------------------------------------------------------
   (2) THE GAME-LEVEL REDUCTION TO A *PLAIN* SM-DT-TCR  --  BLOCKED (finding).
   --------------------------------------------------------------------------
   PART 2 (prose, below the certified lemmas) attempts the further step: a
   module R' : Adv_SMDTTCRC with (S) <= Pr[SM_DT_TCR_C(R'(...))] over the plain
   (non-grinding) TCR game.  It BLOCKS.  The exact blocking step is reported
   there; the short version is that the +C challenge oracle GRINDS a pp-dependent
   counter and returns it, which the plain SM-DT-TCR oracle does not model, and
   reproducing the grind pollutes the very target coordinate the TCR win must
   keep fresh.  Hence (1) is not merely a fallback: the collection-aware
   S-TCR(+C) with a counter oracle is the assumption the +C message-compression
   layer genuinely needs (as in the paper, which argues the counter mechanism in
   the ROM, not via a standard-model TCR reduction).
   ========================================================================== *)

(* ==========================================================================
   PART 1.  THE HONEST RELABEL.
   ========================================================================== *)

(* The standard single-member SM-DT-TCR(+C) collision game for member `thfc dfC`.
   BYTE-IDENTICAL to `S_TCR_C_Int_MA` (WOTS_C_Interactive.ec:2100) except the
   final `return`, which is the bridge's STANDARD 2nd-preimage predicate (with
   the target cap taken at t := p_tgts, so `0 <= nrts <= p_tgts` is unchanged). *)
module S_TCR_C_Int_MA_asStd(A : Adv_ISTCRC, O : STCRC_WC.Oracle_STCRC) = {
  module A = A(O, O_THFC_MA)

  proc main() : bool = {
    var pp : pseed;
    var tw : adrs;
    var m, m' : msgWOTS;
    var j, ctr : cntr;
    var i : int;
    var nrts : int;
    var twsOraw : adrs list;
    var twsMA : (int * adrs) list;

    pp <$ dpseed;
    O_THFC_MA.init(pp);
    O.init(pp);

    A.pick();
    (i, m', ctr) <@ A.find(pp);

    (tw, m, j) <@ O.get(i);

    nrts    <@ O.nr_targets();
    twsOraw <@ O.get_tweaks();
    twsMA   <- O_THFC_MA.tws_ma;

    return    0 <= i < nrts
           /\ 0 <= nrts <= p_tgts
           /\ uniq (map emb_tw twsOraw)
           /\ emb_in (m, j) <> emb_in (m', ctr)
           /\ thfc dfC pp (emb_tw tw) (emb_in (m, j))
            = thfc dfC pp (emb_tw tw) (emb_in (m', ctr))
           /\ FC.disj_lists (map (fun (t : adrs) => (dfC, emb_tw t)) twsOraw) twsMA;
  }
}.

(* GENERIC RELABEL BOUND.  For ANY interactive S-TCR(+C) adversary A, the
   collection-aware S-TCR(+C) advantage is bounded by the standard single-member
   SM-DT-TCR(+C) collision advantage (member `thfc dfC`).  Consumes the predicate
   bridge; the games differ ONLY in the win, coupled by `sim`, so the bound is a
   pointwise weakening `win => standard` lifted to probabilities. *)
lemma stcrc_ma_le_std
  (A <: Adv_ISTCRC{-STCRC_WC.O_STCRC_Default, -O_THFC_MA}) &m :
  (forall (x y : msgWOTS * cntr), size (emb_in x) = size (emb_in y)) =>
  (forall (x y : msgWOTS * cntr), emb_in x = emb_in y => x = y) =>
  Pr[S_TCR_C_Int_MA(A, STCRC_WC.O_STCRC_Default).main() @ &m : res]
  <= Pr[S_TCR_C_Int_MA_asStd(A, STCRC_WC.O_STCRC_Default).main() @ &m : res].
proof.
  move=> emb_in_len emb_in_inj.
  byequiv (_ : ={glob A} ==> res{1} => res{2}) => //; proc.
  seq 9 9 : (   ={pp, tw, m, m', j, ctr, i, nrts, twsOraw, twsMA}
             /\ ={glob O_THFC_MA, glob STCRC_WC.O_STCRC_Default}).
  + sim.
  wp; skip => &1 &2 [#] 10!-> _ _ _ _ Hwin.
  apply (S_TCR_C_Int_MA_win_implies_2ndpreimage p_tgts pp{2} i{2} nrts{2}
           twsOraw{2} twsMA{2} tw{2} m{2} m'{2} j{2} ctr{2}
           emb_in_len emb_in_inj _ Hwin).
  smt(ge0_ptgts).
qed.

(* SUMMAND-4 COROLLARY.  The exact +C summand of the component theorem
   `EUFNAGCMA_FLSLXMSSMTTWCESNPRF` (XmssmtCC_All.ec:8481), bounded by the standard
   single-member SM-DT-TCR(+C) collision advantage.  Instantiates the generic
   relabel at the composed reduction adversary; the component theorem's own A_ht
   module restriction discharges the `Adv_ISTCRC{-..}` side condition. *)
lemma summand4_le_std
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C }) &m :
  (forall (x y : msgWOTS * cntr), size (emb_in x) = size (emb_in y)) =>
  (forall (x y : msgWOTS * cntr), emb_in x = emb_in y => x = y) =>
  Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                    STCRC_WC.O_STCRC_Default).main() @ &m : res]
  <= Pr[S_TCR_C_Int_MA_asStd(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                    STCRC_WC.O_STCRC_Default).main() @ &m : res].
proof.
  move=> emb_in_len emb_in_inj.
  exact (stcrc_ma_le_std (R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)))
           &m emb_in_len emb_in_inj).
qed.

(* DEF C.1 NOTE (no-collection-query specialisation).  When the adversary makes
   NO collection query — `twsMA = []` — the standard win's collection-freshness
   conjunct `FC.disj_lists (map .. twsOraw) []` is VACUOUSLY true, so the win
   collapses to the bare S-TCR(Prop) collision predicate of the paper's Def C.1
   (App C): a target collision on `thfc dfC` with the +C predicate.  Hence the
   InSec notion bounding summand 4 is verbatim Def C.1 restricted to
   no-collection-query adversaries, and its `disj_lists` conjunct is the
   `Thla`-lifted collection-aware generalisation Thm 5.2 uses. *)
lemma disj_lists_nil (s : (int * adrs) list) : FC.disj_lists s [] = true.
proof. by rewrite /disj_lists has_pred0. qed.

(* ==========================================================================
   PART 2.  THE GAME-LEVEL REDUCTION TO A *PLAIN* SM-DT-TCR  --  BLOCKED.

   GOAL of (2): a module R' : FC'.SMDTTCRC.Adv_SMDTTCRC over a `thfc dfC`-membered
   clone `FC'` of the standard collection TCR game, with

       (S)  <=  Pr[ FC'.SMDTTCRC.SM_DT_TCR_C(R'(A),
                      FC'.SMDTTCRC.O_SMDTTCR_Default, FC.O_THFC_Default).main() ]

   so that summand 4 would rest on the STANDARD SM-DT-TCR assumption (the plain,
   NON-grinding target-collision game, TweakableHashFunctions.eca:717).  The
   predicate bridge already gives the winning-EVENT half; (2) asks for the module
   + the game-level bound.  IT BLOCKS.  The exact blocking step, grounded in the
   two oracle interfaces:

   -------------------------------------------------------------------------
   THE ONE STRUCTURAL DIFFERENCE: the +C challenge oracle GRINDS and returns the
   counter; the plain SM-DT-TCR oracle does neither.
   -------------------------------------------------------------------------
   Source game oracle  `STCRC_WC.O_STCRC_Default.query(tw,m)` (STCR_C.ec:127-137):
        i <- grind pp tw m;         (* pp-DEPENDENT counter search *)
        y <- ThC pp tw m i;
        ts <- rcons ts (tw, m, i);
        return (y, i);              (* RETURNS the counter *)
   Plain target game oracle `O_SMDTTCR_Default.query(tw,x)` (TweakableHashFunctions
   .eca:284-294):
        y <- f pp tw x;  ts <- rcons ts (tw,x);  return y;   (* no grind, no ctr *)

   A wrapper R'(A) must answer A's synchronous signing query O_A.query(tw,m) —
   issued INSIDE A.pick() — with the pair (ThC pp tw m i, i) for i = grind pp tw m.
   pp is NOT revealed until A.find(pp) (SM_DT_TCR_C.main: pick() has no pp; pp only
   reaches A.find, TweakableHashFunctions.eca:734-735).  So during pick() R' must
   reproduce the grind WITHOUT pp.  The counter i is the least counter with
   `predC (ThC pp tw m i)`, and `ThC pp tw m i = thfc dfC pp (emb_tw tw) (emb_in
   (m,i))` (WOTS_C_Real.ec:175).  The ONLY pp-holding surfaces R' can call in
   pick() are:
       O   = Oracle_SMDTTCR : query(tw',x) => f pp tw' x, and RECORDS (tw',x) in twsO;
       OC  = Oracle_THFC    : query(tw',x) => fc (size x) pp tw' x, RECORDS tw' in twsOC.
   Both evaluate `thfc dfC pp (emb_tw tw) (emb_in(m,i'))` (O directly as the member,
   OC as `fc (size (emb_in(m,i'))) = thfc dfC` since size (emb_in _) = dfC under
   emb_in_len) — so R' CAN grind.  But each grind candidate is RECORDED, and the
   target R' must register for A's forgery sits at tweak `emb_tw tw` (its 2nd-
   preimage `emb_in (m',ctr)` collides there).  Hence:

     * grind through OC  => `emb_tw tw \in twsOC`, while the registered target has
       `emb_tw tw \in twsO`  => the win-conjunct `disj_lists twsO twsOC` is FALSE
       (grind_via_OC_breaks_disj below);
     * grind through O    => `emb_tw tw` recorded once per candidate in twsO
       => the win-conjunct `dist = uniq (unzip1 twsO)` is FALSE
       (readd_tweak_breaks_dist below).

   Either way the reduction's OWN grind falsifies a required freshness/distinctness
   conjunct on EXACTLY the runs where A wins, so the natural bound
   `Pr[S_TCR_C_Int_MA(A)] <= Pr[SM_DT_TCR_C(R'(A))]` does NOT hold: the RHS event
   is destroyed wherever the LHS event holds.  The two lemmas below machine-check
   the incompatibility core.

   WHY THE MEMBER-AWARE SOURCE GAME DOESN'T HAVE THIS PROBLEM: in `S_TCR_C_Int_MA`
   the grind is done by the BESPOKE challenge oracle (which holds pp and does NOT
   count against the collection list) — grinding is "free".  The member-aware
   disjointness `disj_lists (map (fun t => (dfC,emb_tw t)) twsOraw) tws_ma` then
   holds because the reduction's collection accesses (chain-walk / pkco / trh) sit
   at members <> dfC (dfC <> {8n, 8n*len, 8n*2}).  A PLAIN SM-DT-TCR game has no
   free grind, so the grind cost lands on precisely the lists the win needs clean.

   SECONDARY (constructibility) gap: the in-scope standard collection-TCR game
   `FSSLXMTWES.WTWES.FC_TCR` (WOTS_TW_ES.ec:471) challenges the member `f =
   thfc (8*n)` (the WOTS chain hash), NOT `thfc dfC` (dfC = 8n+r, the message-
   compression member).  Targeting a plain SM-DT-TCR at `thfc dfC` needs a FRESH
   `TweakableHashFunctions with f <- thfc dfC` clone + its `.SMDTTCRC`.  This is
   constructible (a clone), but it is a different game than any currently in scope,
   and it does not remove the grind block above.

   CONCLUSION (the finding).  The +C message-compression summand does NOT reduce
   to a plain SM-DT-TCR assumption by a tight black-box reduction: the obstruction
   is the counter-search (grinding) oracle, which the standard TCR game does not
   model and which a reduction cannot simulate within the standard oracle interface
   without polluting the target coordinate.  The assumption the +C layer genuinely
   needs is therefore the collection-aware S-TCR(+C) with a counter-returning grind
   oracle — the paper's Def C.1 / the InSec notion of Thm 5.2 (which argues the
   counter mechanism in the ROM, `Th ~ random function`, not via a standard-model
   TCR reduction).  PART 1's relabel is thus the CORRECT endpoint, and this is the
   precise reason.
   ========================================================================== *)

(* OBSTRUCTION LEMMA 1 (grind-through-collection horn).  If the registered target
   tweak `emb_tw tw` also appears among the collection-query tweaks (as it must
   when R' grinds ThC = thfc dfC via OC at that tweak), the standard TCR win's
   collection-freshness conjunct `disj_lists twsO twsOC` is falsified. *)
lemma grind_via_OC_breaks_disj (twsO twsOC : adrs list) (tw : adrs) :
  emb_tw tw \in twsO => emb_tw tw \in twsOC => ! FC.disj_lists twsO twsOC.
proof.
  move=> h1 h2; rewrite /disj_lists negbK.
  by apply/hasP; exists (emb_tw tw).
qed.

(* OBSTRUCTION LEMMA 2 (grind-through-challenge horn).  If R' instead grinds via
   the challenge oracle O, each candidate re-records the target tweak `emb_tw tw`,
   so it recurs in the target-tweak list and the win's distinctness conjunct
   `dist = uniq twsO` is falsified. *)
lemma readd_tweak_breaks_dist (twsO : adrs list) (tw : adrs) :
  emb_tw tw \in twsO => ! uniq (rcons twsO (emb_tw tw)).
proof. by move=> h; rewrite rcons_uniq h. qed.

