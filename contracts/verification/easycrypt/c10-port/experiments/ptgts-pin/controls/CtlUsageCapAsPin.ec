(* MUST FAIL.  The CONVENIENT pin: p_tgts := the 2^16 deployment usage cap
   (MAX_SLOT_USES).  This is the substitution P4 exists to forbid.  If it
   compiled, the two caps would be interchangeable and the whole distinction
   this task is built around would be empty.  Expected: failure on ctl_usage. *)
require import AllCore IntDiv Ring StdBigop StdOrder.
require import SPHINCS_PLUS.
require import WOTS_C_Real.
require import PTgtsPin.

lemma ctl_usage : p_tgts = c10_q_s => c <= p_tgts.
proof. by move=> ->; rewrite c10_c_closed /c10_c /c10_q_s. qed.
