(* MUST FAIL.  The TIGHTNESS claim, moved UP BY ONE: 262657 is NOT the least
   admissible p_tgts, because 262656 is admissible.  If this compiles, the
   leastness receipt (PTgtsPin.ec:c10_p_tgts_is_least) proves nothing about
   WHICH integer is least.  Expected: failure on ctl_least. *)
require import AllCore IntDiv Ring StdBigop StdOrder.
require import SPHINCS_PLUS.
require import WOTS_C_Real.
require import C10DeployedScope.

op ctl_p_tgts_up : int = 262657.     (* c10_p_tgts + 1 *)

lemma ctl_least (p : int) : c <= p => ctl_p_tgts_up <= p.
proof. by rewrite c10_c_closed /c10_c /ctl_p_tgts_up /#. qed.
