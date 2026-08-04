(* CANARY -- MUST BE **REJECTED** BY THE GATE.  See scratch/synth_repaired_nonvacuity.ec
   for the full receipt set.  This file takes the REPAIRED capstone's premise list
   (SphincsC10CapstoneWired.ec post-2026-07-25: c<=p_tgts, 0<=mkg_adv, encode-compat,
   the four dfC width facts -- note the emb_tw pair is ABSENT, which is the point)
   and re-runs the attack that killed the old statement.  A GREEN COMPILE HERE IS A
   REGRESSION.  Expected: rc<>0 with `cannot prove goal (strict)`. *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.
require import RtopCSoundness.
require import FxChain.
require import GprocFORSC10.
require FORS_C10 FORS_C10_Multi.
require DigitalSignatures.
require import BitEncoding. import BS2Int BitChunking.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.
import HA.Adrs.

(* CANARY 1: can the repaired premise list derive `false`? *)
lemma CANARY1_repaired_premises_contradictory
  (mkg_adv : real) :
     c <= p_tgts
  => 0%r <= mkg_adv
  => (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
        encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc))
  => dfC <> 8 * n
  => dfC <> 8 * n * len
  => dfC <> 8 * n * 2
  => dfC <> 8 * n * k
  => false.
proof.
move=> hc hmkg hencb hdf8n hdflen hdf2 hdfnk.
smt(emb_disj_concrete hembinj_repaired nonvac_guard ge0_ptgts).
qed.
