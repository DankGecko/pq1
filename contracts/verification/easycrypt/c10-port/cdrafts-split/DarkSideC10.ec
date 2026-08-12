(* ===========================================================================
   DarkSide AT C10'S PARAMETERS.

   WHY THIS FILE EXISTS.  DarkSide.ec is an ABSTRACT theory: its leaf count `t`
   is a refined constant `{ int | 1 <= t }`, and until now NOTHING CLONED IT.
   Every lemma in it therefore held "for all t >= 1" and was connected to the
   C10 development by nothing at all -- a set of true statements floating beside
   the scheme rather than about it.  Promoting the file (2026-08-11) gated its
   proofs; this file is what makes them SAY something here.

   WHAT IS SUBSTITUTED.  `t <- SPHINCS_PLUS.t`, which is the SAME `t` the whole
   C10 development uses -- `const t : int = 2 ^ a` (SPHINCS_PLUS.ec:65), so at
   C10's a = 11 it is 2048.  Deliberately NOT the literal 2048: cloning at the
   numeral would produce arithmetic about a number, while cloning at the scheme's
   own `t` produces facts about the scheme.  The refinement obligation `ge1_t`
   discharges from the already-proven `ge2_t` (SPHINCS_PLUS.ec:180).

   WHAT THIS DOES AND DOES NOT BUY.  It buys the connection: the coverage
   identity, the monotone/lower-bound facts, the k-fold product and the union
   bound now hold ABOUT C10's FORS trees.  It buys NOTHING quantitative on its
   own, and in particular it does NOT touch ITSRC10.  Three pieces still stand
   between this and a tight FORS+C bound: the binomial mixture over a fresh
   candidate's instance load, the numeric evaluation at the deployed usage cap,
   and the ROM / query-budget game plus a coupling theorem.  The last is the hard
   one -- the ITSRC10 game as currently axiomatized has an abstract `mco` and no
   query bound, so there is a legal model in which it is won with probability 1.
   =========================================================================== *)
require import AllCore List Distr StdBigop StdOrder RealExp.
require import SPHINCS_PLUS.
require DarkSide.

clone import DarkSide.DarkSide as DS_C10 with
  op t <- SPHINCS_PLUS.t
  proof *.
realize ge1_t by smt(ge2_t).

(* The engine, now at C10's leaf count: a covered-leaf probability is at least
   1/t.  This is what drives "FORS+C is never weaker than plain FORS". *)
lemma c10_ds_ge_1t (gam : int) :
  1 <= gam => 1%r / SPHINCS_PLUS.t%r <= DS_C10.DS gam.
proof. by apply DS_C10.ds_ge_1t. qed.

(* The comparison itself, at C10's leaf count and for C10's k. *)
lemma c10_forsc_le_fors (kk gam : int) :
  1 <= kk => 1 <= gam =>
  DS_C10.DS gam ^ (kk - 1) * (1%r / SPHINCS_PLUS.t%r) <= DS_C10.DS gam ^ kk.
proof. by apply DS_C10.forsc_le_fors. qed.
