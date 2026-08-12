(* NEGATIVE CONTROL for scratch/_countermodel.ec.  MUST FAIL to realize.

   WHAT IT TESTS.  The countermodel's whole force is that it is a LEGAL model --
   i.e. that the nine axioms really were discharged rather than trivially
   satisfiable by anything.  If the axiom set were vacuous, "there exists a legal
   model with Pr = 1" would be worthless.

   THIS FILE IS THE COUNTERMODEL WITH ONE CHANGE: k = 2 and `g` returning the
   SAME tuple twice.  `size_g` still holds (size = 2 = k).  `eqiks_g`, `rng_g`
   still hold.  `neqisvs_g` is VACUOUS here (its premise x <> x' is unsatisfiable
   on a list of two copies) -- which is precisely the weakness that motivated
   adding `uniq_g` on 2026-07-10b (FORS_C10.ec:188-192, citing MM45's own axioms
   having the same hole).

   EXPECTED: `realize uniq_g` FAILS -- uniq (map (fun x => x.`2) [(0,0,0);(0,0,0)])
   = uniq [0;0] = false.

   DECLARED REASON: "cannot prove goal (strict)" at the `realize uniq_g` line.
   A failure anywhere else -- or a PASS -- invalidates the control.

   This also settles a point BOTH external reviewers raised and neither checked:
   they flagged `uniq_g` as the obstacle needing an explicit construction. It is
   -- at k >= 2.  At k = 1 it is vacuous, which is why the countermodel is cheap. *)
require import AllCore List Distr.
require FORS_C10.

clone import FORS_C10.FORSC10 as CM_NEG with
  op   k     <- 2,
  op   a     <- 1,
  type mkey  <- unit,
  type msg   <- bool,
  type out_t <- unit,
  op   dmkey <- dunit tt,
  op   mco   <- fun (_ : unit) (_ : bool) => tt,
  op   g     <- fun (_ : unit) => [(0, 0, 0); (0, 0, 0)]
  proof *.
realize ge1_k    by trivial.
realize ge1_a    by trivial.
realize dmkey_ll by apply dunit_ll.
realize size_g   by trivial.
realize eqiks_g  by smt().
realize neqisvs_g by smt().
realize rng_g    by smt(expr1).
realize uniq_g   by trivial.          (* <-- MUST FAIL HERE *)
realize good_pos.
by move=> m; rewrite dunitE /good /predC_fors /=.
qed.
