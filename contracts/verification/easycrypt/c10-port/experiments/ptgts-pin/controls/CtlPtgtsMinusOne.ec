(* MUST FAIL.  The pin, moved DOWN BY ONE.  If this compiles, `c` was never
   actually computed and the discharge in PTgtsPin.ec:c10_c_le_p_tgts_at_pin
   pinned nothing.  Expected: "cannot prove goal (strict)" on ctl_discharge. *)
require import AllCore IntDiv Ring StdBigop StdOrder.
require import SPHINCS_PLUS.
require import WOTS_C_Real.
require import PTgtsPin.

op ctl_p_tgts : int = 262655.        (* c10_p_tgts - 1 *)

lemma ctl_discharge : p_tgts = ctl_p_tgts => c <= p_tgts.
proof. by move=> ->; rewrite c10_c_closed /c10_c /ctl_p_tgts. qed.
