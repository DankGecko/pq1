(* ==========================================================================
   Grind.ec  --  Genuine discharge of Appendix-D gap #1 (grinding-oracle
                 termination / losslessness) for the C10 (SPHINCS+C) port.

   WHAT THIS FILE CLOSES.  The first-increment drafts modelled the +C counter
   search as an abstract op `grind` plus an UNCONDITIONAL

       axiom grindP pp tw m : prop (f pp tw m (grind pp tw m)).

   That axiom is exactly Appendix-D gap #1 (paper's p_nu "a good counter is
   always found") parked as an assumption.  Here it is replaced by:

     (b) grind is a TOTAL deterministic search over the FINITE counter type
         (C10's counter is a 32-bit word — the search space genuinely IS
         finite, so the bounded search is the *faithful* model, not merely the
         convenient one);
     (c) the unconditional axiom becomes a PROVED conditional lemma
         `grind_correct : (exists good counter) => prop (f .. (grind ..))`;
     (d) the counter search is given an OPERATIONAL bounded-while oracle whose
         losslessness (termination) is PROVED — the obligation Appendix D
         elides — and which is PROVED to compute the pure op `grind`;
     (e) the grind-FAILURE event `grind_fails` (no good counter exists) is
         exposed as a first-class predicate so the S-TCR(+C) game / reduction
         can COUNT it as adversary loss.  Its probability is the paper's p_nu;
         it is CARRIED as an additive term rather than assumed away.  (Bounding
         Pr[grind_fails] numerically needs the concrete hash and is out of
         scope of the reduction — the paper carries it too.)

   ASSUMPTION DISCLOSURE (corrected 2026-07-20 -- the previous wording said
   "No new axiom is introduced" AND "`FinType.enum_spec` is the sole
   assumption", which is self-contradictory, and an audit of the component
   theorem correctly flagged the first half as FALSE AS STATED):

     This file DOES carry one clone-inherited, UNDISCHARGED obligation --
     `CntrFT.enum_spec` from `clone import FinType as CntrFT` below (the
     counter type is finite / enumerable).  It is never realized by a proof.

   It is a *modelling* fact, not a cryptographic one (the deployed counter type
   really is a bounded machine integer), so it does not weaken the security
   content -- but it IS an assumption the downstream theorems depend on and it
   must be disclosed alongside their explicit premise lists rather than hidden
   here.  An audit bounded the leak: this is the SOLE port-introduced
   undischarged clone axiom (TweakableHashFunctions.eca's only axiom,
   `in_collection`, is realized by STCR_C, as is the `dpp` losslessness
   obligation).  Separately inherited, and outside our TCB, are MM45's own base
   axioms (e.g. `dist_adrstypes`).
   ========================================================================== *)

require import AllCore List.
require import FinType.

abstract theory Grind.
  (* ---- parameters shared with the tweakable hash under attack ---- *)
  type pp_t.                 (* public parameter (SPHINCS+: pseed)      *)
  type tw_t.                 (* tweak            (SPHINCS+: adrs)        *)
  type msg_t.                (* message part     (WOTS+C: n-bit root)   *)
  type out_t.                (* hash output      (SPHINCS+: dgstblock)  *)

  (* The counter type is FINITE.  This is the whole point: a bounded search
     over `enum` terminates, so the grinding oracle is genuinely lossless. *)
  type cntr.
  clone import FinType as CntrFT with
    type t <- cntr.

  (* Th+C keyed on (pp,tw), taking a message AND a counter (paper Thm 5.2). *)
  op f : pp_t -> tw_t -> msg_t -> cntr -> out_t.

  (* The +C predicate on a digest (constant-sum / leading-zeros; abstract). *)
  op prop : out_t -> bool.

  (* ---- (b) TOTAL deterministic grind ---------------------------------- *)

  (* Counters that satisfy the +C predicate, in enumeration order. *)
  op good_ctrs (pp : pp_t) (tw : tw_t) (m : msg_t) : cntr list =
    filter (fun c => prop (f pp tw m c)) enum.

  (* First good counter, or `witness` if none exists.  TOTAL by construction:
     no divergent search, hence losslessness is real (proved in (d)). *)
  op grind (pp : pp_t) (tw : tw_t) (m : msg_t) : cntr =
    head witness (good_ctrs pp tw m).

  (* ---- (e) grind FAILURE as a first-class, carried event -------------- *)
  op grind_fails (pp : pp_t) (tw : tw_t) (m : msg_t) : bool =
    good_ctrs pp tw m = [].

  (* Small list helper: the head of a non-empty list is a member. *)
  lemma head_mem ['a] (s : 'a list) :
    s <> [] => head witness s \in s.
  proof. by case: s => [|x xs] //=; exact: mem_head. qed.

  (* grind FAILS iff no counter at all satisfies the +C predicate.  This is
     the exact characterization of the paper's p_nu event. *)
  lemma grind_fails_iff (pp : pp_t) (tw : tw_t) (m : msg_t) :
    grind_fails pp tw m <=> ! (exists c, prop (f pp tw m c)).
  proof.
    rewrite /grind_fails /good_ctrs -size_eq0 size_filter.
    have hc : count (fun c => prop (f pp tw m c)) enum = 0
              <=> ! has (fun c => prop (f pp tw m c)) enum
      by smt(has_count count_ge0).
    by rewrite hc hasP /=; smt(enumP).
  qed.

  (* grind succeeds exactly when it does not fail. *)
  lemma grindP_iff (pp : pp_t) (tw : tw_t) (m : msg_t) :
    prop (f pp tw m (grind pp tw m)) <=> ! grind_fails pp tw m.
  proof.
    rewrite /grind_fails; split.
    - (* prop(grind) => good_ctrs <> [] : if empty, NO counter satisfies prop
         (grind_fails_iff), contradicting prop(grind). *)
      move=> pg; apply/negP => hnil.
      have hall : ! (exists c, prop (f pp tw m c))
        by rewrite -grind_fails_iff /grind_fails hnil.
      have he : exists c, prop (f pp tw m c).
        by exists (grind pp tw m).
      by apply: hall.
    - (* good_ctrs <> [] => grind \in good_ctrs => prop holds *)
      move=> nn.
      have hin : grind pp tw m \in good_ctrs pp tw m
        by rewrite /grind; exact: (head_mem _ nn).
      move: hin; rewrite /good_ctrs mem_filter; smt().
  qed.

  (* ---- (c) THE PROVED CONDITIONAL LEMMA (was `axiom grindP`) ---------- *)
  (* Whenever a good counter exists, grind returns one.  This is the paper's
     grindP with its (previously silent) existence hypothesis made explicit
     and the conclusion PROVED — no axiom. *)
  lemma grind_correct (pp : pp_t) (tw : tw_t) (m : msg_t) :
    (exists c, prop (f pp tw m c)) => prop (f pp tw m (grind pp tw m)).
  proof.
    move=> ex; rewrite grindP_iff grind_fails_iff negbK; exact ex.
  qed.

  (* ---- (d) OPERATIONAL bounded-search oracle + losslessness ----------- *)
  (* The faithful counter search: scan the finite `enum`, stop at the first
     +C-satisfying counter.  Bounded by |enum|, hence terminating/lossless. *)
  module GrindSearch = {
    proc run(pp : pp_t, tw : tw_t, m : msg_t) : cntr = {
      var cs : cntr list;
      var r  : cntr;
      var found : bool;

      cs    <- enum;
      r     <- witness;
      found <- false;

      while (!found /\ cs <> []) {
        if (prop (f pp tw m (head witness cs))) {
          r     <- head witness cs;
          found <- true;
        }
        cs <- behead cs;
      }
      return r;
    }
  }.

  (* Termination / losslessness — the obligation App D elides.  Variant is
     `size cs`, strictly decreasing (behead) on every non-empty iteration. *)
  lemma GrindSearch_search_ll : islossless GrindSearch.run.
  proof.
    by islossless; while true (size cs); auto; smt(size_behead size_eq0 size_ge0).
  qed.

  (* ---- correctness: the operational search computes the pure op grind --- *)
  (* Loop invariant: `enum = scanned ++ cs`; while nothing found, no scanned
     counter is good; once found, `r` is the first good counter of `enum`
     (= grind).  At exit the guard is false, so either found (r = grind) or
     cs = [] with no good scanned (grind = witness = r). *)
  (* ADMITTED — operational↔op bridge.  NOT part of the gap-#1 discharge and
     NOT a security axiom: every downstream game/reduction uses the pure total
     op `grind` directly (see O_STCRC_Default in STCR_C.ec), whose correctness
     (grind_correct) and failure characterization (grind_fails_iff) are FULLY
     PROVED above, as is the termination/losslessness of the operational search
     (GrindSearch_search_ll).  This lemma additionally ties the operational
     loop to the op; the on-paper proof (invariant: enum = scanned ++ cs; the
     scanned prefix holds no good counter until `found`; then r = first good
     counter = grind) is straightforward but the EC wp/while goal-shape wiring
     resisted a one-session close.  NOW PROVED (2026-07-07): the invariant
     "while not found, the first good counter of the remaining `cs` is `grind`"
     (plus "while not found, `r` is still `witness`") threads through the scan;
     `head_filter_ne` is the one-step filter/head fact.  Zero admit. *)

  (* The first good counter of a non-empty list is either its head (if good) or
     the first good counter of the tail — the one step the scan takes. *)
  lemma head_filter_ne (P : cntr -> bool) (cs : cntr list) :
    cs <> [] =>
      head witness (filter P cs)
    = (if P (head witness cs)
       then head witness cs
       else head witness (filter P (behead cs))).
  proof.
    move=> hne; rewrite -{1}(head_behead cs witness hne) /=.
    by case (P (head witness cs)).
  qed.

  lemma GrindSearch_run_computes_grind (pp0 : pp_t) (tw0 : tw_t) (m0 : msg_t) :
    hoare[GrindSearch.run :
            pp = pp0 /\ tw = tw0 /\ m = m0 ==> res = grind pp0 tw0 m0].
  proof.
    proc.
    while (   pp = pp0 /\ tw = tw0 /\ m = m0
           /\ (found => r = grind pp0 tw0 m0)
           /\ (!found => r = witness)
           /\ (!found =>
                 head witness (filter (fun c => prop (f pp0 tw0 m0 c)) cs)
                 = grind pp0 tw0 m0)).
    + auto => /> *; smt(head_filter_ne).
    auto => />; smt().
  qed.
end Grind.
