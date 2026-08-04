(* ==========================================================================
   MUST-FAIL CONTROL #6 — "IS THE CHARGED TERM UNCONDITIONALLY ZERO?"

   THIS FILE MUST BE **REJECTED** BY EASYCRYPT.
   A GREEN COMPILE HERE IS A REGRESSION, NOT A RESULT.

   WHAT IT TESTS.  `gfail_zero_under_N2` proves the charged summand vanishes
   UNDER N2.  This file asserts the same thing with the N2 premise DELETED.  If
   it compiled, `Pr[res /\ gfail]` would be provably 0 outright -- the charged
   bound would be identical to the N2 bound, and STEP 2b/3/4 would have moved
   nothing.  It must fail.

   This is the sharper of the two inertness controls: canary5 tests whether the
   term can be dropped from the INEQUALITY; this tests whether the term is zero
   as a QUANTITY.

   EXPECTED FAILURE REASON: "cannot prove goal (strict)".
   ========================================================================== *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme WOTS_C_Reduction XMSSMT_C_Scheme.
require import WOTS_C_Interactive.
require import GFailCharged.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import WOTS_C_Reduction.

lemma canary6_gfail_is_unconditionally_zero
  (A <: Adv_MEUFGCMA_WOTSC{-O_MEUFGCMA_WOTSC_Default, -FC.O_THFC_Default}) &m :
  Pr[GAME1_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
       res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps
                       O_MEUFGCMA_WOTSC_Default.qs] = 0%r.
proof.
byphoare => //.
hoare.
proc.
wp.
conseq (_ : _ ==> true) => //.
move=> &hr _ ps0 qs ad0 adlO0 adlOC0 dwg i0 ifr ivl m0 m'0 nrqs0 ps1 sc0 sc'0 _.
rewrite negb_and; right.
smt().
qed.
