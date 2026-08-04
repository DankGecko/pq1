(* ==========================================================================
   GFailCharged.ec — the N2-to-charged-term rewrite of the WOTS-TW leg.

   GOAL OF THE WHOLE REWRITE: replace hop2's universal N2 premise ("the +C grind
   never fails, anywhere") with a CHARGED TERM, so the assumption becomes a
   visible probability instead of a hypothesis:

     Pr[GAME1_INT(A)]  <=  Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(A))]
                         + Pr[GAME1_INT(A) : res /\ gfail_of ps qs]

   THIS IS NOT A DISCHARGE.  `Pr[... : gfail]` is bounded by NOTHING in this
   repo -- it is as unreduced as Pr[ITSRC10].  The gain is that an assumed
   impossibility becomes a term you can see.  Bounding it needs the concrete
   hash and is out of scope here (Grind.ec:22-26 says the same).

   CONTENTS: the grind-failure predicate, hop2 with the gate sourced from
   `!gfail` instead of from N2, the mu_split reassembly, the N2-free
   member-aware D.1, and a proof that the charged chain SUBSUMES the N2 chain.

   SHAPE FOLLOWS REPO PRECEDENT: GprocFORSC10.ec splits on `covered` with
   `Pr[mu_split ...]` in the same way.  It differs in one respect that matters --
   `covered` is a GAME-MODULE VARIABLE, whereas `gfail_of` is a pure predicate
   over the honest oracle's own globals.  That distinction is not cosmetic; see
   the revision note below for why it is what keeps the subsumption exact.  In
   neither case does the shared oracle change.
   ========================================================================== *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme WOTS_C_Reduction XMSSMT_C_Scheme.
require import WOTS_C_Interactive.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import WOTS_C_Reduction.
import HA.Adrs.

(* ==========================================================================
   THE GRIND-FAILURE EVENT, AS A PURE PREDICATE ON THE HONEST ORACLE'S OWN
   RECORDED STATE.

   REVISION 2026-07-31 (two mutually blind adversarial reviews).  The first
   version of this file introduced an INSTRUMENTED GAME `GAME1_INT_I` carrying a
   `var gfail`, following GprocFORSC10.ec's `covered` precedent.  That worked,
   but it forced every charged lemma to add `-GAME1_INT_I` to its adversary
   restriction set -- so `interactive_D1_MA_from_charged` quantified over a
   STRICTLY SMALLER adversary class than `interactive_D1_MA`, and the claim that
   it re-derived the latter's exact statement was FALSE.  Module restrictions
   are part of a theorem.

   The fix is not to document the gap but to remove it: `gfail` is computable
   from the honest oracle's OWN globals (`ps`, `qs`), both of which are
   referenceable inside a `Pr[...]` event.  So no instrumented game is needed,
   no new module exists to restrict against, and every lemma below carries
   EXACTLY the restriction set of the lemma it generalizes.

   Bonus: the coupling invariant already speaks in terms of
   `O_MEUFGCMA_WOTSC_Default.ps`, so the ps-bridging the instrumented version
   needed disappears too.
   ========================================================================== *)
(* ROUTE (D): O_MEUFGCMA_WOTSC_Default.qs is the +C game's list, so its
   message component is a NODE (dgstblock) -- grind_fails takes ThC's INPUT. *)
op gfail_of (ps : pseed)
            (qs : (adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) list) : bool =
  has (fun (q : adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) =>
         STCRC_WC.G.grind_fails ps q.`1 q.`2) qs.

(* ==========================================================================
   STEP 2b -- hop2 WITH THE GATE SOURCED FROM `!gfail` INSTEAD OF FROM N2.

   Identical to `interactive_hop2` (WOTS_C_Interactive.ec) except:
     - the N2 premise is GONE,
     - the success event is narrowed to `res /\ !gfail`.
   The coupling it calls (`choose_tw`) is the SAME lemma `interactive_hop2`
   calls -- since STEP 2a that coupling is N2-free, which is exactly what makes
   this reuse possible without duplicating 330 lines of pRHL.

   HONEST READING.  This does NOT discharge N2.  It converts "assume the grind
   never fails anywhere" into "pay Pr[the grind failed on some queried message]".
   Nothing in this repository bounds that probability; it is as unreduced as
   Pr[ITSRC10] or Q.  The gain is that an assumption became a visible term.
   ========================================================================== *)
lemma interactive_hop2_charged
  (A <: Adv_MEUFGCMA_WOTSC{-R_int_WOTSTW, -O_MEUFGCMA_WOTSC_Default,
                          -O_MEUFGCMA_WOTSTWESNPRF, -FC.O_THFC_Default}) &m :
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    Pr[GAME1_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
         res /\ ! gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs]
  <= Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(A),
                               O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res].
proof.
  move=> embdisj encb.
  byequiv (_ : ={glob A} ==>
                 res{1}
              /\ ! gfail_of O_MEUFGCMA_WOTSC_Default.ps{1} O_MEUFGCMA_WOTSC_Default.qs{1}
              => res{2}) => //.
  proc.
  seq 1 1 : (={glob A, ps}); first by rnd; skip => />.
  seq 2 2 : (   ={glob A, ps}
             /\ O_MEUFGCMA_WOTSC_Default.ps{1} = ps{1}
             /\ O_MEUFGCMA_WOTSC_Default.qs{1} = []
             /\ O_MEUFGCMA_WOTSTWESNPRF.ps{2} = ps{2}
             /\ O_MEUFGCMA_WOTSTWESNPRF.qs{2} = []
             /\ FC.O_THFC_Default.pp{1} = ps{1} /\ FC.O_THFC_Default.tws{1} = []
             /\ FC.O_THFC_Default.pp{2} = ps{2} /\ FC.O_THFC_Default.tws{2} = []).
  + inline*; auto => />.
  (* Phase 1: A.choose{1} ~ R.choose{2} (O_wrap.init resets wads; then choose_tw). *)
  have choose0 :
    equiv[ A(O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).choose
         ~ R_int_WOTSTW(A, O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).choose :
             ={glob A}
             /\ O_MEUFGCMA_WOTSC_Default.ps{1} = O_MEUFGCMA_WOTSTWESNPRF.ps{2}
             /\ O_MEUFGCMA_WOTSC_Default.ps{1} = FC.O_THFC_Default.pp{1}
             /\ O_MEUFGCMA_WOTSC_Default.ps{1} = FC.O_THFC_Default.pp{2}
             /\ O_MEUFGCMA_WOTSC_Default.qs{1} = []
             /\ O_MEUFGCMA_WOTSTWESNPRF.qs{2} = []
             /\ FC.O_THFC_Default.tws{1} = [] /\ FC.O_THFC_Default.tws{2} = []
             ==>
             ={glob A}
             /\ O_MEUFGCMA_WOTSC_Default.ps{1} = O_MEUFGCMA_WOTSTWESNPRF.ps{2}
             /\ O_MEUFGCMA_WOTSC_Default.ps{1} = FC.O_THFC_Default.pp{1}
             /\ O_MEUFGCMA_WOTSC_Default.ps{1} = FC.O_THFC_Default.pp{2}
             /\ O_MEUFGCMA_WOTSTWESNPRF.qs{2}
                  = map (fun (q : adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) =>
                           (q.`1, ThC O_MEUFGCMA_WOTSC_Default.ps{1} q.`1 q.`2 q.`4.`2, q.`3, q.`4.`1))
                        O_MEUFGCMA_WOTSC_Default.qs{1}
             /\ map WAddress.val R_int_WOTSTW.O_wrap.wads{2}
                  = map (fun (q : adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) => q.`1)
                        O_MEUFGCMA_WOTSC_Default.qs{1}
             /\ all (fun (t : adrs) => t \in FC.O_THFC_Default.tws{1} \/ exists b, t = emb_tw b)
                    FC.O_THFC_Default.tws{2}
             (* Carried, NOT dropped.  The gated game's success condition ends
                `/\ P m /\ P m'`: `P m'` (FORGED) comes free from verifyC_TW's
                strengthened post, but `P m` (QUERIED, the message `O.get(i)`
                reads back) has no other source -- it exists only because
                `choose_tw` maintains it across every signing query.  Weakening
                it away here left the final `smt` with no gate hypothesis in
                context at all. *)
             /\ all (fun (q : adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) =>
                       STCRC_WC.G.grind_fails O_MEUFGCMA_WOTSC_Default.ps{1} q.`1 q.`2 \/ predC (ThC O_MEUFGCMA_WOTSC_Default.ps{1} q.`1 q.`2 q.`4.`2))
                    O_MEUFGCMA_WOTSC_Default.qs{1} ].
  + proc*.
    inline{2} R_int_WOTSTW(A, O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).choose.
    call (choose_tw A encb).
    inline{2} R_int_WOTSTW(A, O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).O_wrap.init.
    auto => />.
  seq 1 1 : (   ={glob A, ps}
             /\ O_MEUFGCMA_WOTSC_Default.ps{1} = ps{1}
             /\ O_MEUFGCMA_WOTSC_Default.ps{1} = O_MEUFGCMA_WOTSTWESNPRF.ps{2}
             /\ O_MEUFGCMA_WOTSC_Default.ps{1} = FC.O_THFC_Default.pp{1}
             /\ O_MEUFGCMA_WOTSC_Default.ps{1} = FC.O_THFC_Default.pp{2}
             /\ O_MEUFGCMA_WOTSTWESNPRF.qs{2}
                  = map (fun (q : adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) =>
                           (q.`1, ThC O_MEUFGCMA_WOTSC_Default.ps{1} q.`1 q.`2 q.`4.`2, q.`3, q.`4.`1))
                        O_MEUFGCMA_WOTSC_Default.qs{1}
             /\ map WAddress.val R_int_WOTSTW.O_wrap.wads{2}
                  = map (fun (q : adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) => q.`1)
                        O_MEUFGCMA_WOTSC_Default.qs{1}
             /\ all (fun (t : adrs) => t \in FC.O_THFC_Default.tws{1} \/ exists b, t = emb_tw b)
                    FC.O_THFC_Default.tws{2}
             /\ all (fun (q : adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) =>
                       STCRC_WC.G.grind_fails O_MEUFGCMA_WOTSC_Default.ps{1} q.`1 q.`2 \/ predC (ThC O_MEUFGCMA_WOTSC_Default.ps{1} q.`1 q.`2 q.`4.`2))
                    O_MEUFGCMA_WOTSC_Default.qs{1}).
  + call choose0; skip => /> /#.
  (* Phase 2: couple A.forge{1} / R.forge{2}; R emits the +C-digest WOTS-TW forgery. *)
  inline{2} R_int_WOTSTW(A, O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).forge.
  sp 0 1.
  seq 1 1 : (#pre /\ i{1} = i0{2} /\ m'{1} = m'0{2} /\ sigc'{1} = sigc'{2}).
  + by call (forge_eq_tw A); skip => />.
  wp.   (* RHS return-assign: m'{2} = ThC ps (val wads[i0]) m'0 sigc'.`2 ; sig'{2} = sigc'.`1 *)
  (* Phase 3: read-backs + verify (in-range verifyC_TW; out-of-range res{1} false). *)
  inline{1} O_MEUFGCMA_WOTSC_Default.get O_MEUFGCMA_WOTSC_Default.nr_queries
            O_MEUFGCMA_WOTSC_Default.dist_addresses O_MEUFGCMA_WOTSC_Default.get_addresses
            FC.O_THFC_Default.get_tweaks.
  inline{2} O_MEUFGCMA_WOTSTWESNPRF.get O_MEUFGCMA_WOTSTWESNPRF.nr_queries
            O_MEUFGCMA_WOTSTWESNPRF.dist_addresses O_MEUFGCMA_WOTSTWESNPRF.get_addresses
            FC.O_THFC_Default.get_tweaks.
  case (0 <= i{1} < size O_MEUFGCMA_WOTSC_Default.qs{1}).
  + exists* ps{1}, (nth witness O_MEUFGCMA_WOTSC_Default.qs{1} i{1}).`1, m'{1}, (sigc'{1}.`2);
      elim* => psv adv mAv cAv.
    wp; call (verifyC_TW psv adv mAv cAv encb).
    wp; skip => &1 &2 [snap [big rng]] /=.
    move: big => [[hps0 [[hglob hps12] [hops1 [hops2 [hopp1 [hopp2 [hqs2E [hmapinv [htwsrel hgateall]]]]]]]]] [hieq [hmeq hsigceq]]].
    have hszw : size R_int_WOTSTW.O_wrap.wads{2} = size O_MEUFGCMA_WOTSC_Default.qs{1}
      by rewrite -(size_map WAddress.val) hmapinv size_map.
    have hvw : forall j, 0 <= j < size O_MEUFGCMA_WOTSC_Default.qs{1} =>
      WAddress.val (nth witness R_int_WOTSTW.O_wrap.wads{2} j) = (nth witness O_MEUFGCMA_WOTSC_Default.qs{1} j).`1.
    + move=> j hj; rewrite -(nth_map witness witness WAddress.val) 1:hszw // hmapinv (nth_map witness witness) //.
    have hvalid : all valid_wadrs (map (fun (q : adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) => q.`1) O_MEUFGCMA_WOTSC_Default.qs{1})
      by rewrite -hmapinv allP => x /mapP [w [_ ->]] /=; exact: WAddress.valP.
    split.
    + rewrite -hieq hqs2E !(nth_map witness witness) //= (hvw i{1} rng); smt().
    move=> _ result_L result_R vimpl
      [[[h0sz hszc] [[h0i hisz] [hrL [hmne [huniqL [hdisjL hncoll]]]]]] hnofail].
    have cE : c = StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => FSSLXMTWES.nr_nodes_ht d' 0) 0 d by rewrite /c.
    have hdisj2 : disj_wgpidxs (map (fun (q : adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) => q.`1) O_MEUFGCMA_WOTSC_Default.qs{1}) FC.O_THFC_Default.tws{2}
      by apply (disj_wgpidxs_transfer _ FC.O_THFC_Default.tws{1} _ embdisj hvalid hdisjL htwsrel).
    (* FORGED-side gate conjunct: verifyC_TW's post now CARRIES okC (it used to
       discard it), so result_L yields predC of the forged digest directly. *)
    have [_ hPforged] := vimpl hrL.
    move: hPforged; rewrite /predC => hPforged.   (* predC IS P since the tie *)
    (* QUERIED-side gate conjunct: instantiate the maintained `all` at the very
       index the adversary points at.  `rng` is exactly the in-range side
       condition `mem_nth` wants, which is why this branch -- and only this
       branch -- can produce it; the out-of-range branch has res{1} = false.

       2026-07-31: the maintained `all` is the WEAKER disjunctive form
       (`grind_fails \/ gate`), because that is the form the coupling can carry
       WITHOUT N2.  N2 is consumed HERE, and only here, to kill the left
       disjunct -- this lemma's statement is therefore unchanged, and everything
       above it (interactive_D1, interactive_D1_MA, XmssmtCC_All's seven, the
       capstone) is untouched.  `interactive_hop2_charged` in GFailCharged.ec
       kills the SAME disjunct with `!gfail` instead, which is the entire
       content of the N2-to-charged-term rewrite. *)
    have hd : STCRC_WC.G.grind_fails O_MEUFGCMA_WOTSC_Default.ps{1}
                (nth witness O_MEUFGCMA_WOTSC_Default.qs{1} i{1}).`1
                (nth witness O_MEUFGCMA_WOTSC_Default.qs{1} i{1}).`2
              \/ predC (ThC O_MEUFGCMA_WOTSC_Default.ps{1}
                          (nth witness O_MEUFGCMA_WOTSC_Default.qs{1} i{1}).`1
                          (nth witness O_MEUFGCMA_WOTSC_Default.qs{1} i{1}).`2
                          (nth witness O_MEUFGCMA_WOTSC_Default.qs{1} i{1}).`4.`2).
    + by move/allP: hgateall => h; apply h; apply/mem_nth; exact rng.
    have hPqueried : predC (ThC O_MEUFGCMA_WOTSC_Default.ps{1}
                             (nth witness O_MEUFGCMA_WOTSC_Default.qs{1} i{1}).`1
                             (nth witness O_MEUFGCMA_WOTSC_Default.qs{1} i{1}).`2
                             (nth witness O_MEUFGCMA_WOTSC_Default.qs{1} i{1}).`4.`2).
    + case: hd => [hfail|//].
      (* ==== THE ENTIRE CONTENT OF THE REWRITE, IN SIX LINES ====
         hop2 kills this disjunct with N2 (a hypothesis).  Here it dies by
         `!gfail` instead.  `gfail` is `has grind_fails qs` evaluated on the
         FINAL qs, so `!gfail` yields `!grind_fails` at EVERY recorded query,
         hence at index i.  Note this needs the invariant's
         `O_MEUFGCMA_WOTSC_Default.ps{1} = ps{1}`: `gfail` is written in terms
         of the game's local `ps`, the coupling in terms of the oracle's. *)
      have hmem : (nth witness O_MEUFGCMA_WOTSC_Default.qs{1} i{1})
                    \in O_MEUFGCMA_WOTSC_Default.qs{1}
        by apply/mem_nth; exact rng.
      move: hnofail; rewrite /gfail_of hasPn => hno.
      have hni : ! STCRC_WC.G.grind_fails O_MEUFGCMA_WOTSC_Default.ps{1}
                     (nth witness O_MEUFGCMA_WOTSC_Default.qs{1} i{1}).`1
                     (nth witness O_MEUFGCMA_WOTSC_Default.qs{1} i{1}).`2
        by have := hno _ hmem.
      by smt().
    move: hPqueried; rewrite /predC => hPqueried.
    rewrite -hieq hqs2E -!map_comp /(\o) /= !size_map (nth_map witness witness) //= (hvw i{1} rng).
    smt(size_ge0).
  (* out of range: res{1} = false (0 <= i < nrqs fails). *)
  wp; call{1} verify_ll; call{2} verifytw_ll.
  wp; skip => /> *.
qed.

(* ==========================================================================
   STEP 3 -- REASSEMBLY.  Split
   the ORIGINAL game's success on `gfail` and bound the good half by STEP 2b.

   Idiom follows this repo's own precedent (GprocFORSC10.ec:568-571, the
   `covered` split): rewrite by the equality, `Pr[mu_split flag]`, apply the hop.

   The residue is written as `Pr[.. : res /\ gfail]` rather than
   `Pr[.. : gfail]` only because that form needs no sub-bound.  DO NOT read that
   as tightness in any useful sense: it is tight SYNTAX for an UNBOUNDED
   quantity.  Nothing here rules OUT `Pr[res /\ gfail]` being as large as
   `Pr[res]`, in which case the inequality says nothing beyond the trivial bound.
   Corrected 2026-07-31: that is an ABSENCE OF A BOUND, not a demonstrated worst
   case -- no model exhibiting a positive charge is known either (see the vacuity
   note in SphincsC10CapstoneCharged.ec).  Contrast the precedent cited above:
   GprocFORSC10's bad half IS bounded by concrete hypotheses; nothing in this
   repository bounds this one.
   ========================================================================== *)
lemma interactive_hop2_charged_pr
  (A <: Adv_MEUFGCMA_WOTSC{-R_int_WOTSTW, -O_MEUFGCMA_WOTSC_Default,
                          -O_MEUFGCMA_WOTSTWESNPRF, -FC.O_THFC_Default}) &m :
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    Pr[GAME1_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(A),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[GAME1_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
         res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
move=> embdisj encb.
rewrite Pr[mu_split (gfail_of O_MEUFGCMA_WOTSC_Default.ps
                              O_MEUFGCMA_WOTSC_Default.qs)].
have hop := interactive_hop2_charged A &m embdisj encb.
smt().
qed.

(* ==========================================================================
   STEP 4 -- THE N2-FREE INTERACTIVE D.1 (member-aware).

   `interactive_D1_MA` is the one the capstone chain actually reaches
   (XmssmtCC_All.ec:1205 applies it; plain `interactive_D1` is NOT composable
   for the hypertree adversary -- see the member-aware repair note in
   WOTS_C_Interactive.ec).  So this, not a charged `interactive_D1`, is the
   lemma worth having.

   Note what is absent from the premise list: N2.  It has become the third
   summand.  Everything else is verbatim `interactive_D1_MA`.
   ========================================================================== *)
lemma interactive_D1_MA_charged
  (A <: Adv_MEUFGCMA_WOTSC{-R_int_STCRC, -R_int_WOTSTW, -O_MEUFGCMA_WOTSC_Default,
                          -O_MEUFGCMA_WOTSTWESNPRF, -STCRC_WC.O_STCRC_Default,
                          -FC.O_THFC_Default, -O_THFC_MA, -G0_INT}) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    hoare[ R_int_STCRC(A, STCRC_WC.O_STCRC_Default, O_THFC_MA).pick :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC0) O_THFC_MA.tws_ma ] =>
    Pr[M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(A),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(A),
                         STCRC_WC.O_STCRC_Default).main() @ &m : res]
     + Pr[GAME1_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
         res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
move=> le_c_ptgts embdisj encb A_wf_MA.
have h1 := interactive_hop1_MA A &m le_c_ptgts encb A_wf_MA.
have h2 := interactive_hop2_charged_pr A &m embdisj encb.
smt().
qed.

(* ==========================================================================
   THE SUBSUMPTION RECEIPT (adversarial-review item, 2026-07-31).

   Without this, "the charged lemma generalizes the N2 lemma" would be a claim
   about two statements with NO formal link -- a reviewer could fairly ask
   whether the charged chain proves something merely adjacent.  With it, the old
   bound is a mechanical corollary of the new one: under N2 the charged summand
   is exactly 0.

   `no_gfail_under_N2` is the pure half: N2 says a good counter exists at every
   (ps, ad, m), and `grind_fails_iff` says failure is precisely its
   non-existence -- so the `has` is false over ANY query list.
   ========================================================================== *)
lemma no_gfail_under_N2
  (ps : pseed) (qs : (adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) list) :
  (forall (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock),
     exists (cc : cntr), predC (ThC ps0 ad0 m0 cc)) =>
  ! gfail_of ps qs.
proof.
move=> hN2; rewrite /gfail_of; apply/hasPn => q _ /=.
by rewrite STCRC_WC.G.grind_fails_iff negbK; exact (hN2 _ _ _).
qed.

(* The game-level half: under N2 the charged summand is exactly 0. *)
lemma gfail_zero_under_N2
  (A <: Adv_MEUFGCMA_WOTSC{-O_MEUFGCMA_WOTSC_Default, -FC.O_THFC_Default}) &m :
  (forall (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock),
     exists (cc : cntr), predC (ThC ps0 ad0 m0 cc)) =>
  Pr[GAME1_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
         res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs] = 0%r.
proof.
move=> hN2.
byphoare => //.
hoare.
proc.
wp.
conseq (_ : _ ==> true) => //.
(* Binder order note: the ORACLE's seed `ps0` comes first and is what
   `gfail_of` is applied to; the game's local seed is `ps1`.  Discarding
   `ps0` here is what the earlier instrumented version could get away with
   and this one cannot. *)
move=> &hr _ ps0 qs ad0 adlO0 adlOC0 dwg i0 ifr ivl m0 m'0 nrqs0 ps1 sc0 sc'0 _.
rewrite negb_and; right.
exact (no_gfail_under_N2 ps0 qs hN2).
qed.

(* ==========================================================================
   SUBSUMPTION, AS A THEOREM RATHER THAN A CLAIM.

   This re-derives `interactive_D1_MA`'s EXACT statement -- N2 premise and all,
   no extra summand -- from `interactive_D1_MA_charged`.  So the charged chain
   does not merely sit alongside the N2 chain: it implies it.  Anything the N2
   version proves, the charged version proves, and the charged version also
   applies when N2 is unavailable (paying Pr[res /\ gfail] instead).

   Without this lemma, "the charged bound generalizes the N2 bound" would be a
   statement about two formally unrelated theorems.  It was added because an
   adversarial review asked for exactly that link.
   ========================================================================== *)
lemma interactive_D1_MA_from_charged
  (A <: Adv_MEUFGCMA_WOTSC{-R_int_STCRC, -R_int_WOTSTW, -O_MEUFGCMA_WOTSC_Default,
                          -O_MEUFGCMA_WOTSTWESNPRF, -STCRC_WC.O_STCRC_Default,
                          -FC.O_THFC_Default, -O_THFC_MA, -G0_INT}) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    (forall (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock),
       exists (cc : cntr), predC (ThC ps0 ad0 m0 cc)) =>
    hoare[ R_int_STCRC(A, STCRC_WC.O_STCRC_Default, O_THFC_MA).pick :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC0) O_THFC_MA.tws_ma ] =>
    Pr[M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(A),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(A),
                         STCRC_WC.O_STCRC_Default).main() @ &m : res].
proof.
move=> le_c_ptgts embdisj encb hN2 A_wf_MA.
have hch := interactive_D1_MA_charged A &m le_c_ptgts embdisj encb A_wf_MA.
have hz  := gfail_zero_under_N2 A &m hN2.
smt().
qed.
