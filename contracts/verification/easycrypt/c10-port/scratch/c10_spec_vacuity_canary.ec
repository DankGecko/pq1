require import AllCore IntDiv.
require import SPHINCS_PLUS.
(* MUST-FAIL: if the specialised axiom set were inconsistent, `false` would be
   provable and every theorem above would be vacuous. This MUST NOT compile. *)
lemma canary_false : false.
proof. smt(n_val k_val a_val log2_w_val len_val hp_val d_val dist_adrstypes). qed.
