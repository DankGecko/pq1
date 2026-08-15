(* MUST FAIL.  P1's computed value, moved DOWN BY ONE.  If this compiles, the
   evaluation of `bigi predT (fun d' => nr_nodes_ht d' 0) 0 d` at the base's
   pinned h'=9 / d=2 is not actually determining an integer.
   Expected: failure on ctl_c_value. *)
require import AllCore IntDiv Ring StdBigop StdOrder.
require import SPHINCS_PLUS.
require import WOTS_C_Real.
import FSSLXMTWES.
import Bigint BIA.
import IntOrder.
require import PTgtsPin.

lemma ctl_c_value : c = 262655.
proof.
rewrite /c d_val.
rewrite (BIA.big_ltn 0 2) 1:// /=.
rewrite (BIA.big_ltn 1 2) 1:// /=.
rewrite (BIA.big_geq 2 2) 1:// /=.
rewrite /nr_nodes_ht /nr_trees /nr_nodesx hp_val d_val /=.
by rewrite expr0 c10_pow2_9.
qed.
