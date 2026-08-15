(* MUST FAIL.  Substantiates the measurement asserted in PTgtsPin.ec section 0:
   `smt()` cannot evaluate `2 ^ 9` on int, so the nine-deep `exprS` ladder is
   necessary rather than decorative.  Expected: "cannot prove goal (strict)".
   (If a future prover CAN close this, the ladder becomes optional -- which is
   information, not a regression.) *)
require import AllCore StdOrder.
import IntOrder.

lemma ctl_smt_pow : 2 ^ 9 = 512.
proof. smt(). qed.
