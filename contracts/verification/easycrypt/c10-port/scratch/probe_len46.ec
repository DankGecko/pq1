require import AllCore List Distr IntDiv StdBigop StdOrder RealExp.
require import SPHINCS_PLUS.
require import SphincsC10CapstoneWired.
require import C10DeployedInstance.
(* MUST FAIL: provable only if the specialised theory is inconsistent. *)
lemma probe_len46 : len = 46.
proof. smt(n_val k_val a_val log2_w_val len_val hp_val d_val). qed.
