require import AllCore IntDiv.
require import SPHINCS_PLUS.

(* MUST-PASS #1: the hypertree height and the WIDTH INEQUALITY that forced the
   split (8*n = 128 < 129 = len*log2_w).  Both are FALSE for generic parameters
   -- the second is the exact obstruction C10DeployedInstance names.  If these
   are provable, the deployed values are genuinely in force in the theory. *)
lemma deployed_really_in_force : h = 18 /\ 8 * n < len * log2_w.
proof. by rewrite /h hp_val d_val n_val len_val log2_w_val. qed.

(* MUST-PASS #2: the base-w width. *)
lemma deployed_w : w = 8.
proof.
  (* smt(@Int) here was FLAKY: it dumps the whole Int theory at the prover, and
     under machine load the call timed out -- turning the whole split gate RED on
     a tree that had not changed (run 2026-08-04).  The gate's verdict must be a
     function of the TREE, not of prover timing, so the hint set is now the two
     power lemmas this goal actually needs. *)
  by rewrite /w log2_w_val; smt(expr0 exprS).
qed.
