(* MUST FAIL (anti-vacuity canary, the [R1] shape this repo uses).  Take the
   NEW premise verbatim and try to derive `false` from it with the same tactic
   battery the discharge uses.  A green compile here would mean the pin makes
   the theory inconsistent and every statement conditioned on it vacuous.
   Expected: failure on ctl_false. *)
require import AllCore IntDiv Ring StdBigop StdOrder.
require import SPHINCS_PLUS.
require import WOTS_C_Real.
require import PTgtsPin.

lemma ctl_false : p_tgts = c10_p_tgts => false.
proof. by move=> hpin; smt(c10_c_closed ge0_ptgts c10_p_tgts_dominates_c). qed.
