(* ==========================================================================
   MUST-FAIL CONTROL #5 — "IS THE CHARGED TERM LOAD-BEARING?"

   THIS FILE MUST BE **REJECTED** BY EASYCRYPT.
   A GREEN COMPILE HERE IS A REGRESSION, NOT A RESULT.

   WHAT IT TESTS.  `interactive_hop2_charged_pr` (GFailCharged.ec) claims

       Pr[GAME1_INT]  <=  Pr[M_EUF_GCMA_WOTSTWESNPRF]  +  Pr[res /\ gfail]

   If the third summand could simply be DROPPED, the entire N2-to-charged-term
   rewrite would be decorative: it would mean the WOTS-TW leg was already
   unconditionally bounded and the grind-failure event costs nothing.  This file
   asserts exactly that dropped form.  It must fail.

   EXPECTED FAILURE REASON: "cannot prove goal (strict)" at the final `smt()`
   -- NOT an arity/scoping/typing error.  A control that fails for the wrong
   reason tests nothing while reading red; the gate matches the reason string.
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

lemma canary5_charged_term_is_inert
  (A <: Adv_MEUFGCMA_WOTSC{-R_int_WOTSTW, -O_MEUFGCMA_WOTSC_Default,
                          -O_MEUFGCMA_WOTSTWESNPRF, -FC.O_THFC_Default}) &m :
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    Pr[GAME1_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
  <= Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(A),
                               O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res].
proof.
move=> embdisj encb.
have h := interactive_hop2_charged_pr A &m embdisj encb.
smt().
qed.
