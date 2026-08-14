require import AllCore List Distr.
require import SPHINCS_PLUS.
require WOTS_C_Real.
require WOTS_C_Interactive.
import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import WOTS_C_Interactive.

(* does the composed game even typecheck? *)
module SmokeGame (A : WOTS_C_Scheme.Adv_MEUFGCMA_WOTSC) =
  Game4_WOTSTWES_BadEnc(R_int_WOTSTW(A)).
