(* ===========================================================================
   ITSRC10 PROBABILITY-ONE COUNTERMODEL -- SPIKE, 2026-08-11.

   TARGET STATEMENT, PRE-STATED BEFORE THE PROOF so the header cannot drift
   into a stronger reading:

     There exists a LEGAL instantiation of the abstract theory FORSC10's
     parameters under which Pr[ITSRC10 win] = 1.  Hence NO PARAMETER-INDEPENDENT
     BOUND is provable for this game as axiomatized.

   IT DOES NOT SAY the deployed instance is insecure.  It does NOT say "the game
   is unbounded".  The deployed chain fixes `mco` at a concrete op; Pr at THAT
   instance is a fixed number about which this file says exactly nothing.

   WHY IT EXISTS.  Three promoted headers (FORS_C10.ec, DarkSide.ec,
   DarkSideC10.ec) assert "there is a legal model in which it is won with
   probability 1" as PROSE.  That claim is the entire load-bearing reason for
   not pursuing a tight ITSRC10 bound.  In a repo whose founding line is "a
   result nothing enforces is not a receipt", the stopping argument was itself
   unenforced.  Both external reviewers (GPT-5.6, Kimi K3) independently named
   mechanising it as the single cheapest decisive step.

   THE MODEL.  k = a = 1 (so t = 2), mkey = unit, msg = bool, out_t = unit,
   dmkey = dunit, mco constant, g the single tuple (0,0,0).
   NOTE k = 1 is what makes this cheap, and neither reviewer checked it:
   `uniq_g` -- the axiom both flagged as the obstacle needing "an explicit
   construction" -- is VACUOUS at k = 1, because a one-element list is trivially
   uniq.  `uniq_g` bites at C10's k = 13; it does not bite here.  The refinements
   permit k = 1 (`const k : { int | 1 <= k }`, FORS_C10.ec:138).
   =========================================================================== *)
require import AllCore List Distr.
require FORS_C10.

clone import FORS_C10.FORSC10 as CM with
  op   k     <- 1,
  op   a     <- 1,
  type mkey  <- unit,
  type msg   <- bool,
  type out_t <- unit,
  op   dmkey <- dunit tt,
  op   mco   <- fun (_ : unit) (_ : bool) => tt,
  op   g     <- fun (_ : unit) => [(0, 0, 0)]
  proof *.
realize ge1_k    by trivial.
realize ge1_a    by trivial.
realize dmkey_ll by apply dunit_ll.
realize size_g   by trivial.
realize eqiks_g  by smt().
realize neqisvs_g by smt().
realize rng_g    by smt(expr1).
realize uniq_g   by trivial.
realize good_pos.
(* NOT by smt: `by smt(dunit1E)` is accepted by the `compile` driver and
   REJECTED by `cli` -- the exact both-drivers discrepancy PHASE 1e exists to
   catch.  Proved explicitly so it holds under both. *)
by move=> m; rewrite dunitE /good /predC_fors /=.
qed.

(* The adversary: one signing query, then forge on the OTHER message.
   Note it does NOT grind the hash -- it never evaluates `mco` itself.  This is
   the correction both my own diagnosis and the review brief needed: the win
   comes from the missing OUTPUT LAW on abstract `mco`, not from free hash
   evaluation.                                                                *)
module Amod (O : Oracle_ITSRC10) = {
  proc find() : unit * bool = {
    var mk : unit;
    mk <@ O.query(false);
    return (mk, true);
  }
}.

lemma countermodel_pr1 &m :
  Pr[ITSRC10(Amod, O_ITSRC10_Default).main() @ &m : res] = 1%r.
proof.
byphoare => //.
proc; inline *.
wp; rnd; wp; skip => /=.
(* After wp the freshness conjunct is already discharged: (tt,true) is not in
   [(tt,false)] because true <> false.  What remains is that the coverage
   conjunct holds for EVERY sampled key -- it does, because g is constant, so
   cover_f = cover_q = [(0,0,0)] -- leaving pure losslessness of the conditioned
   oracle, which is exactly good_pos (= the paper's p_nu). *)
rewrite (mu_eq _ _ predT).
- by move=> x /=; rewrite /predT /predC_fors /hC /= /#.
by apply (dcond_ll _ _ (good_pos false)).
qed.

(* ===========================================================================
   WHAT THIS ESTABLISHES, AND WHAT IT DOES NOT.

   ESTABLISHED (machine-checked, both drivers, zero admits):
     * The instantiation above is a LEGAL model of the abstract theory FORSC10 --
       all nine obligations realize (ge1_k, ge1_a, dmkey_ll, size_g, eqiks_g,
       neqisvs_g, rng_g, uniq_g, good_pos).
     * Under it, the ITSRC10 game is won with probability EXACTLY 1.
   Therefore NO PARAMETER-INDEPENDENT BOUND on ITSRC10 is provable for this game
   as axiomatized.  Any future lemma claiming one is refuted by this file.

   NOT ESTABLISHED, and must not be read in:
     * NOTHING about the deployed instance.  The deployed chain fixes `mco` at a
       concrete op; Pr at THAT instance is some fixed number this file says
       nothing about.  This is not a break, not an attack, and not a statement
       about C10's security.
     * Not "the game is unbounded".  A bound that QUANTIFIES OVER a query budget
       and a random-oracle `mco` is not excluded by this -- it is exactly what
       this file shows would be REQUIRED.

   WHY THE ADVERSARY IS INTERESTING.  It makes ONE signing query and NEVER
   evaluates `mco`.  So the win does not come from "grinding the hash for free"
   (the diagnosis in the review brief, and mine).  It comes from the absence of
   any OUTPUT LAW on the abstract `mco` -- a constant `mco` is legal, and then a
   single recorded target covers every future forgery.  A q_h bound alone would
   not fix this; the missing q_s bound and the missing output law are equally
   load-bearing.  (GPT-5.6 adversarial review, 2026-08-11.)

   WHY IT IS CHEAP, which neither reviewer predicted.  Both flagged `uniq_g`
   (strictly stronger than MM45's set, added 2026-07-10b) as the obstacle
   requiring "an explicit construction".  At k = 1 it is VACUOUS: a one-element
   list is trivially uniq.  `uniq_g` bites at C10's k = 13; it does not bite
   here, and `const k : { int | 1 <= k }` permits k = 1.

   DRIVER NOTE.  `realize good_pos by smt(dunit1E)` is accepted by the `compile`
   driver and REJECTED by `cli` -- the exact both-drivers discrepancy PHASE 1e
   exists to catch.  It is proved explicitly above so it holds under both.
   =========================================================================== *)
