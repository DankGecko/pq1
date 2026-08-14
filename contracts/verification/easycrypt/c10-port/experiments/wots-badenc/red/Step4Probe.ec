(* ##########################################################################
   SUPERSEDED 2026-08-14 -- STEP 4 NOW CLOSES.  See `BadEncStep4.ec`
   (`badenc_le_tcoll`), admit-free, with five must-fail controls.  This file is
   RETAINED as the recorded blocking goal of the run that did not close it
   (`Step4Probe.goal` / `Step4Probe.out`); it still fails to compile by design
   and must never be read as current status.
   ########################################################################## *)
(* ==========================================================================
   Step4Probe.ec  --  MEASUREMENT INSTRUMENT.  THIS FILE IS EXPECTED TO FAIL
   TO COMPILE.  IT IS NOT A RESULT AND MUST NEVER BE CITED AS ONE.

   ###################  WHAT IT IS FOR  ####################################
   STEP 4 -- the probability inequality
       Pr[Game4_WOTSTWES_BadEnc(R_int_WOTSTW(A)) : res /\ BadEncFlag.badenc]
         <= Pr[T_COLL_RES_ENUM(R_TCOLL(A), O_TCollEnum_Default, FC.O_THFC_Default) : res]
   did NOT close in this session.  Rather than assert an estimate of what
   remains, this file drives the proof to the FIRST BLOCKING GOAL and the
   receipt `Step4Probe.out` / `Step4Probe.dump` records it verbatim.

   It contains NO `admit`, NO `axiom`, and NO `declare axiom` -- it simply
   fails.  That is deliberate: a failing file cannot masquerade as a proof,
   whereas a stubbed one can (see ../RESULT.md's standing warning about
   `probe/WOTS_TW_ES.ec`).
   ##########################################################################

   EXTRA HYPOTHESIS, DECLARED RATHER THAN SMUGGLED.  `le_c_ptgts : c <= p_tgts`
   is REQUIRED and is not currently in scope for this pair of games: the
   left-hand game bounds the query count by `c` (`0 <= nrqs <= c`) while
   T_COLL_RES_ENUM bounds the target count by `p_tgts` (`nrts <= p_tgts`).
   The development already carries this premise in exactly this role
   (`../cd/WOTS_C_Interactive.ec`'s `interactive_hop1*`), so it is a premise of
   the statement below, not an axiom.
   ========================================================================== *)
require import AllCore List Distr.
require import SPHINCS_PLUS.
require WOTS_C_Real.
require import WOTS_C_Scheme.
require import TCollResEnum.
require import BadEncSplit.
require import BadEncToTColl.
require import WOTS_C_Interactive.
import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import EmsgWOTS.

section Step4.

declare module A <: Adv_MEUFGCMA_WOTSC{-O_MEUFGCMA_WOTSTWESNPRF,
                                       -O_MEUFGCMA_WOTSC_Default,
                                       -R_int_WOTSTW, -R_TCOLL,
                                       -FC.O_THFC_Default,
                                       -O_TCollEnum_Default}.

lemma badenc_le_tcoll &m :
     c <= p_tgts
  => Pr[Game4_WOTSTWES_BadEnc(R_int_WOTSTW(A)).main() @ &m
          : res /\ BadEncFlag.badenc]
     <= Pr[T_COLL_RES_ENUM(R_TCOLL(A), O_TCollEnum_Default,
                           FC.O_THFC_Default).main() @ &m : res].
proof.
move=> le_c_ptgts.
byequiv (_ : ={glob A} ==> (res{1} /\ BadEncFlag.badenc{1}) => res{2}) => //.
proc.
qed.

end section Step4.
