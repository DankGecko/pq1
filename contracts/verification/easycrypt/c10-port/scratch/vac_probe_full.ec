(* HARD VACUITY PROBE: pull in the WHOLE closure so every axiom the development
   carries is in scope, then try to derive `false`.  This MUST FAIL. *)
require import AllCore List Distr IntDiv StdBigop StdOrder RealExp.
require import SPHINCS_PLUS.
require import XmssmtCC_All.
require import RtopCSoundness.
require import FxChain.
require import GprocFORSC10.
require import SphincsC10CapstoneWired.
require import SphincsC10Content.
require import GFailCharged.
require import XmssmtCCCharged.
require import SphincsC10CapstoneCharged.
require import C10DeployedInstance.
require import C10DeployedCapstone.

lemma VACUITY_CANARY_full_closure : false.
proof.
smt(n_val k_val a_val log2_w_val len_val hp_val d_val dist_adrstypes
    ge1_n ge1_k ge1_a val_log2w ge2_len ge1_hp ge1_d).
qed.
