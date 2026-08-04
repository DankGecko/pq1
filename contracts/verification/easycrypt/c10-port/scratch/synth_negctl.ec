(* NEGATIVE CONTROL for synth_vacuity_check.ec: the ambient theory must NOT be
   already inconsistent, i.e. `false` must NOT be derivable without the premises. *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import WOTS_C_Scheme.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.

(* MUST FAIL *)
lemma ambient_is_inconsistent : false.
proof. smt(emb_disj_concrete nonvac_guard emb_tw_val dist_adrstypes emb_off_range). qed.
