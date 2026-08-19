(* MUST PASS (positive control).  The pin is LIVE: it fixes the constant to a
   value that simultaneously (a) satisfies the declaration's own axiom, (b)
   discharges the carried premise, and (c) EXCLUDES the off-by-one below it.
   If (c) were unprovable the pin would not be pinning anything. *)
require import AllCore IntDiv Ring StdBigop StdOrder.
require import SPHINCS_PLUS.
require import WOTS_C_Real.
require import C10DeployedScope.

lemma ctl_pin_live :
  p_tgts = c10_p_tgts => 0 <= p_tgts /\ c <= p_tgts /\ ! (p_tgts <= 262655).
proof.
move=> hpin; rewrite (c10_pin_respects_ge0_ptgts hpin) (c10_c_le_p_tgts_at_pin hpin) /=.
by rewrite hpin /c10_p_tgts.
qed.
