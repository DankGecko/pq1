(* CANARY 3 -- MUST BE **REJECTED** BY THE GATE.  The END-TO-END vacuity test:
   INSTANTIATE the REPAIRED capstone theorem itself (EUFCMA_SPHINCS_PLUS_C10) at
   concrete reals, supply its post-repair premise list, and try to conclude the
   absurd bound `Pr[EUFCMA_C10(F)] <= -1%r` -- exactly what
   scratch/synth_exact_prefix_vacuity.ec's CAPSTONE_IS_VACUOUS DID conclude from
   the OLD premise pair.  A GREEN COMPILE HERE IS A REGRESSION.
   Expected: rc<>0 with `cannot prove goal (strict)`. *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.
require import RtopCSoundness.
require import FxChain.
require import GprocFORSC10.
require import SphincsC10CapstoneWired.
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

lemma CANARY3_repaired_capstone_still_vacuous
(F <: Adv_EUFCMA_C{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V, -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default,
             -R_top,
             -DSSC.Stateless.O_CMA_Default, -O_CMA_SPHINCSPLUSTWC_FS,
             -SKG_PRF.O_PRF_Default, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V,
             -R_top_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV,
             -R_fors_p, -O_CMA_Gproc, -O_CMA_Gproc_I, -R_ITSRC10_Gproc,
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default })
  &m :
     c <= p_tgts
  => (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
        encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc))
     (* N2 -- ADDED 2026-07-30.  The capstone gained this premise when the fork
        gated the WOTS-TW game; without it this canary fails on ARITY at the
        `have hcap :=` below, i.e. it would still be "rejected" while testing
        NOTHING.  Caught by cert_gate_fork.sh phase 3, which requires a must-fail
        control to fail for its DECLARED reason (`cannot prove goal (strict)`),
        not merely to fail. *)
  => (forall (ps0 : pseed) (ad0 : adrs) (m0 : msgWOTS),
        exists (cc : cntr), predC (ThC ps0 ad0 m0 cc))
  => dfC <> 8 * n
  => dfC <> 8 * n * len
  => dfC <> 8 * n * 2
  => dfC <> 8 * n * k
  => Pr[EUFCMA_C10(F).main() @ &m : res] <= -1%r.
proof.
move=> hc hencb hN2 hdf8n hdflen hdf2 hdfnk.
have hcap := EUFCMA_SPHINCS_PLUS_C10 F 0%r 1%r 0%r 0%r &m hc _ hencb hN2 hdf8n hdflen hdf2 hdfnk _.
+ by [].
+ have hle1 : Pr[EUF_CMA_Gproc_I(R_fors_p(F)).main() @ &m
                   : res /\ !EUF_CMA_Gproc_I.covered] <= 1%r by rewrite Pr[mu_le1].
  smt().
smt().
qed.
