(* ==========================================================================
   MUST-FAIL CONTROL #8 — "IS THE WIDTH HYPOTHESIS LOAD-BEARING?"

   THIS FILE MUST BE **REJECTED** BY EASYCRYPT.
   A GREEN COMPILE HERE IS A REGRESSION, NOT A RESULT.

   `c10_dfC_separations` (C10DeployedGeometry.ec) discharges the capstone's four
   dfC separations at the deployed n / len / k, GIVEN
   `size (emb_in witness) = 8*n + r`.  This file asserts the same conclusion with
   that hypothesis DELETED.

   If it compiled, the separations would follow from the parameter ties alone --
   i.e. the lemma would say nothing about `emb_in` and would be discharging the
   premises vacuously.  `emb_in` is an ABSTRACT op (WOTS_C_Real.ec:164) with no
   size axiom anywhere in the closure, so `dfC` is unconstrained without the
   hypothesis and this must fail.

   EXPECTED FAILURE REASON: "cannot prove goal (strict)" at the final smt().
   ========================================================================== *)
require import AllCore List IntDiv Ring StdOrder.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme.
require import WOTS_C_Interactive.
require import C10DeployedGeometry.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import EmsgWOTS.
import WOTS_C_Real.
import WOTS_C_Interactive.
import IntOrder.

lemma canary8_width_hypothesis_is_inert (r : int) :
     n   = c10_n
  => len = c10_len
  => k   = c10_k
  => r <> 0
  => r <> 8 * c10_n * 2       - 8 * c10_n
  => r <> 8 * c10_n * c10_k   - 8 * c10_n
  => r <> 8 * c10_n * c10_len - 8 * c10_n
  =>    dfC <> 8 * n
     /\ dfC <> 8 * n * len
     /\ dfC <> 8 * n * 2
     /\ dfC <> 8 * n * k.
proof.
move=> hn hlen hk h0 h1 h2 h3.
move: h1 h2 h3; rewrite /c10_n /c10_len /c10_k /= => h1 h2 h3.
rewrite hn hlen hk /c10_n /c10_len /c10_k /=.
smt().
qed.
