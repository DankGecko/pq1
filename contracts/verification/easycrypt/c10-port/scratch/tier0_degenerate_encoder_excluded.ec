require import AllCore List.
require import SPHINCS_PLUS.
require import WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme WOTS_C_Interactive.
require import XmssmtCC_All RtopCSoundness FxChain GprocFORSC10.
require import C10DeployedInstance.
(* MUST-FAIL CONTROL (Tier 0, 2026-08-02).  RETAINED BUT KNOWN NON-DISCRIMINATING
   -- READ THIS BEFORE COUNTING IT (header corrected 2026-08-04, run 22).

   THE ORIGINAL HEADER CLAIMED, WRONGLY: "MUST FAIL: a CONSTANT encoder cannot
   satisfy the identification, because c10_embg is injective under the
   cardinality bound.  If this compiles, the Tier-0 lemma does not exclude the
   degenerate model after all."  The run-14 review killed that (commit 8faf5c8,
   finding 4; GPT-5.6 and Opus 5 independently).  This control FAILS WHETHER OR
   NOT the injectivity result exists: failure to PROVE constancy is not proof of
   NON-constancy, and degeneracy is a SATISFIABILITY property that no compile
   failure can witness.  So a RED here is not evidence, and the gate line
   "controls executed (unique)=5" counts four discriminating controls and this.

   WHAT ACTUALLY DISCRIMINATES for this claim is POSITIVE and lives in-cone:
   c10_embg_not_constant and c10_deployed_encoder_not_constant in
   cdrafts-split/C10DeployedCapstone.ec, both pinned in PHASE 1c.  They break if
   DigestBlock.val_inj or the two-distinct-blocks fact is ever weakened.

   KEPT ANYWAY: deleting a control is a worse habit than carrying a labelled
   weak one, and its polarity still catches an outright inversion of
   c10_deployed_encoder_meets_model.  See C10DeployedGeometry.ec section 41. *)
lemma TIER0_NEGATIVE_CONTROL :
     STCRC_WC.G.CntrFT.card <= 2 ^ c10_r
  => emb_in = c10_embg
  => (forall (x y : dgstblock * cntr), emb_in x = emb_in y).
proof.
  move=> hcard heq x y.
  by have [_ hinj] := c10_deployed_encoder_meets_model hcard heq; smt().
qed.
