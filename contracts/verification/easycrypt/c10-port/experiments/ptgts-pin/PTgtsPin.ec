(* ==========================================================================
   PTgtsPin.ec -- PIN `p_tgts` AT THE DEPLOYED VALUE, AND DISCHARGE `c <= p_tgts`.

   WHY THIS FILE EXISTS.  Every deployed statement in this development carries
   the premise `c <= p_tgts`.  SphincsC10CapstoneWired.ec:251-252 calls it an
   "HONEST RESIDUAL: conditions on ABSTRACT MODEL CONSTANTS", and
   cdrafts-split/WOTS_C_Real.ec:340 is

       const p_tgts : { int | 0 <= p_tgts } as ge0_ptgts.

   -- abstract, so `p_tgts = 0` is a permitted interpretation and the premise is
   then FALSE.  This file computes `c` exactly at the deployed geometry, pins
   `p_tgts` at the least value that satisfies the carried premise, and turns
   `c <= p_tgts` from a side condition on an unpinned constant into a
   consequence of that pin.  (Section 3(B) is explicit that the REDUCTION-LEVEL
   story for why the premise has this shape lives in an UNCERTIFIED file and is
   not relied on here.)

   READ-ONLY DISCIPLINE.  base-c10-split/ and cdrafts-split/ are the CERTIFIED
   trees and are NOT touched.  `p_tgts` is therefore pinned the way
   cdrafts-split/C10DeployedInstance.ec pins `emb_in` -- by a deployed-instance
   `c10_*` definition plus HYPOTHETICAL tie lemmas on the model's own constant --
   not by editing the abstract declaration (which would move the gate hash).

   WHAT IS AND IS NOT CLAIMED.  Sections 2 and 3 below are UNCONDITIONAL
   theorems: `c` is determinate in this tree (see section 1), so `c = 262656`
   and `c <= c10_p_tgts` carry no hypotheses at all.  Section 4's transfer to
   the model constant is hypothetical on `p_tgts = c10_p_tgts` -- that is an
   INSTANTIATION CHOICE, exactly like `emb_in = c10_embg`, not a theorem, and
   section 5 states what it does and does not buy.
   ========================================================================== *)
require import AllCore List IntDiv Ring StdBigop StdOrder.
require import SPHINCS_PLUS.
require import WOTS_C_Real.
import FSSLXMTWES.
import Bigint BIA.
import IntOrder.

(* --------------------------------------------------------------------------
   0.  POWER-OF-TWO EVALUATION.

   `^` on `int` does NOT reduce (`iterop`-backed), and `smt()` fails on
   `2 ^ 9 = 512` -- MEASURED here, rc=1 "cannot prove goal (strict)", the same
   obstruction experiments/wots-badenc/count/README.md records for `2 ^ 114`.
   The `exprS` ladder from C10DeployedInstance.ec:`c10_pow8` does reduce; this
   is that ladder, nine deep.
   -------------------------------------------------------------------------- *)
lemma c10_pow2_9 : 2 ^ 9 = 512.
proof.
by rewrite (_ : 9 = 8 + 1) 1:// exprS 1://
           (_ : 8 = 7 + 1) 1:// exprS 1://
           (_ : 7 = 6 + 1) 1:// exprS 1://
           (_ : 6 = 5 + 1) 1:// exprS 1://
           (_ : 5 = 4 + 1) 1:// exprS 1://
           (_ : 4 = 3 + 1) 1:// exprS 1://
           (_ : 3 = 2 + 1) 1:// exprS 1://
           (_ : 2 = 1 + 1) 1:// exprS 1:// expr1.
qed.

lemma c10_pow2_18 : 2 ^ 18 = 262144.
proof. by rewrite (_ : 18 = 9 + 9) 1:// exprD_nneg 1,2:// c10_pow2_9. qed.

(* --------------------------------------------------------------------------
   1.  THE DEPLOYED GEOMETRY IS ALREADY AXIOMATISED IN THE SPLIT BASE.

   This is the fact that makes section 2 an unconditional theorem rather than a
   hypothetical, and it was NOT obvious: base-c10-split/SPHINCS_PLUS.ec pins the
   whole parameter set as axioms, not as declarations --

       n_val      : n      = 16     (:44)     a_val    : a  = 11   (:60)
       k_val      : k      = 13     (:53)     len_val  : len = 43  (:97)
       log2_w_val : log2_w = 3      (:73)
       hp_val     : h'     = 9      (:106)    d_val    : d   = 2   (:116)

   and `h = h' * d` (:124), `l = 2 ^ h` (:131), `l' = 2 ^ h'` (:111) are
   `const` DEFINITIONS on top of those.  Cross-checked against the deployment:
   sphincs-c10/src/params.rs has N=16 (:19), H=18 (:22), D=2 (:25),
   SUBTREE_H = H/D = 9 (:28), K=13 (:34), A=11 (:37), W=8 (:43), LOG_W=3 (:46),
   L=43 (:49), TARGET_SUM=205 (:52), with `assert!(SUBTREE_H * D == H)` (:88).

   Restated as receipts so this file's arithmetic is auditable against ONE
   place, and so a change to the base's pins breaks HERE rather than silently.
   -------------------------------------------------------------------------- *)
op c10_hp : int = 9.        (* h'  -- inner (XMSS) tree height, params.rs:28 *)
op c10_d  : int = 2.        (* d   -- hypertree layers,          params.rs:25 *)
op c10_h  : int = 18.       (* h   -- total hypertree height,    params.rs:22 *)

(* NOTE: `h` is ambiguous under `import FSSLXMTWES` -- the clone at
   SPHINCS_PLUS.ec:600 substitutes h'/d/l/l' but NOT the derived `h`, so
   `FSSLXMTWES.h` and `SPHINCS_PLUS.h` are two operators with the same body.
   Qualify throughout; they are equal, and the qualified one is the one `l`
   is built on. *)
lemma c10_geometry_pinned_in_base :
  h' = c10_hp /\ d = c10_d /\ SPHINCS_PLUS.h = c10_h.
proof. by rewrite /c10_hp /c10_d /c10_h /SPHINCS_PLUS.h hp_val d_val. qed.

(* --------------------------------------------------------------------------
   2.  TARGET P1 -- `c` EXACTLY, AT THE DEPLOYED PARAMETERS.

   `c` is the WOTS-TW instance count of the whole hypertree.  It is NOT the
   WTWES constant (the concrete clone at FL_SL_XMSS_MT_ES.ec:554 substitutes
   that away); WOTS_C_Real.ec:41 re-exposes it under the same name as an
   ordinary DEFINITION

       op c : int = bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 d

   which, with the base's pins, is a closed integer.  Layer d' contributes
   `nr_trees d' * nr_nodes 0 = 2 ^ (h' * (d - d' - 1)) * 2 ^ h'`, so

       c = 2^(9*1) * 2^9  +  2^(9*0) * 2^9  =  2^18 + 2^9  =  262656.

   Structurally: 2^9 = 512 inner trees at the bottom layer x 512 leaves each
   = 2^18 bottom-layer WOTS instances, plus the single top tree's 2^9 = 512.
   That matches the implementation exactly -- sphincs-c10/src/hypertree.rs:23
   "Builds all 2^SUBTREE_H = 512 WOTS keys at layer 1, tree 0".
   -------------------------------------------------------------------------- *)
op c10_c : int = 262656.

lemma c10_c_closed : c = c10_c.
proof.
rewrite /c /c10_c d_val.
rewrite (BIA.big_ltn 0 2) 1:// /=.
rewrite (BIA.big_ltn 1 2) 1:// /=.
rewrite (BIA.big_geq 2 2) 1:// /=.
rewrite /nr_nodes_ht /nr_trees /nr_nodesx hp_val d_val /=.
by rewrite expr0 c10_pow2_9.
qed.

(* c is 2^18 + 2^9, i.e. NOT a power of two -- worth having explicitly, because
   every "~2^18" shorthand in the prose rounds it DOWN. *)
lemma c10_c_is_two_powers : c = 2 ^ 18 + 2 ^ 9.
proof. by rewrite c10_c_closed /c10_c c10_pow2_18 c10_pow2_9. qed.

(* And the structural reading: bottom-layer leaves (l) plus top-tree leaves (l'). *)
lemma c10_c_is_leaves_plus_toptree : c = l + l'.
proof.
rewrite /l /l' /SPHINCS_PLUS.h hp_val d_val /= c10_pow2_18 c10_pow2_9.
by rewrite c10_c_closed /c10_c.
qed.

(* --------------------------------------------------------------------------
   3.  TARGET P2 -- PIN `p_tgts`, AND WHY AT THIS VALUE.

   WHAT `p_tgts` IS.  Read at source, and SPLIT BY CERTIFICATION STATUS -- this
   repo's recurring defect is citing an uncompiled draft as if it were checked,
   so the two halves are kept apart deliberately.

   (A) IN CERTIFIED FILES (members of closure-c10-split.txt, hence recompiled by
       every gate run):
     * WOTS_C_Real.ec:354 passes it into the S-TCR(+C) theory as
       `op p_stcr <- p_tgts`.
     * In STCR_C.ec, `p_stcr` occurs in exactly TWO places -- its declaration
       (:56, `const p_stcr : { int | 0 <= p_stcr } as ge0_pstcr`) and ONE use:
       the win condition of `S_TCR_C.main` (:216) contains the conjunct
       `0 <= nrts <= p_stcr`, where
       `nrts` is the number of targets the challenge oracle actually handed out.
       So `p_tgts` is a CAP ON THE TARGET COUNT, and it sits on the ADVERSARY'S
       side of the win condition: if the reduction places more targets than the
       cap, the S-TCR game returns FALSE and the reduction transfers nothing.
     * WOTS_C_Scheme.ec:214: the WOTS+C multi-instance game's own win condition
       caps the committed queries, `0 <= nrqs <= c`.
     * The premise `c <= p_tgts` is carried verbatim by five closure members
       (SphincsC10CapstoneWired :526/:865 -- labelled there simply "(WOTS+C
       target-count side-cond)", GprocQWired :102 and four more, GFailCharged,
       GprocChargedQWired, C10DeployedCapstone).

   (B) NOT CERTIFIED -- stated as design intent, NOT as a verified fact:
     * The bridging step "the reduction places ONE target PER COMMITTED QUERY"
       appears in WOTS_C_Multi.ec:490-494 (`D1_reduce`).  **WOTS_C_Multi is NOT
       in closure-c10-split.txt**: it is not a gate target, no certified run
       compiles it, and `D1_reduce` carries a header labelling the Algorithm-9
       multi-instance byequiv as its core obligation.  So the "one target per
       WOTS instance" reading is the reduction's INTENT; it is not checked here
       and this file does not rest on it.

   WHY 262656 IS NEVERTHELESS THE RIGHT PIN, and why (B) does not weaken it:
   the object to satisfy is the premise the CERTIFIED statements already carry,
   `c <= p_tgts`, whatever argument motivated its shape.  At the deployed
   geometry `c` is the closed integer of section 2, so the least value that
   satisfies the premise is exactly 262656: anything smaller fails it, anything
   larger is pure slack.  Were (B) wrong, the premise would still be the thing
   to satisfy and 262656 would still be the least value satisfying it.  It is
   pinned to the CLOSED INTEGER rather than to the symbol `c` so that it cannot
   silently track a later geometry change.

   NOT CHOSEN TO MAKE A NUMBER COME OUT WELL -- and that is checkable:
   `c10_p_tgts_is_least` below, and the two-sided bracket in controls/
   (`CtlCapstonePinOffByOne` must fail at 262655, `CtlCapstonePinPlusOne` must
   pass at 262657).  Section 5 records what this pin does NOT buy, including the
   number it is closest to being mistaken for.
   -------------------------------------------------------------------------- *)
op c10_p_tgts : int = 262656.

(* (a) the pin is a PERMITTED interpretation of the declaration
       `const p_tgts : { int | 0 <= p_tgts } as ge0_ptgts`. *)
lemma c10_p_tgts_admissible : 0 <= c10_p_tgts.
proof. by rewrite /c10_p_tgts. qed.

(* (b) the pin dominates c -- UNCONDITIONALLY, no hypothesis at all, because
       section 2 made c determinate. *)
lemma c10_p_tgts_dominates_c : c <= c10_p_tgts.
proof. by rewrite c10_c_closed /c10_c /c10_p_tgts. qed.

(* (c) TIGHTNESS: it is the LEAST value satisfying the premise.  READ THIS
       HONESTLY -- since `c10_p_tgts = c` (below), after rewriting this lemma is
       literally `c <= p => c <= p`, so its whole content is
       `c10_p_tgts_is_exactly_c`; it is stated separately only because "least"
       is the property one wants to read off.  A `0 <= p` hypothesis was dropped
       from it after review: it did NO work (the goal never uses it), and an
       unused named hypothesis in a receipt lemma is exactly the no-op-control
       shape this project has been burned by.  Dropping it also STRENGTHENS the
       statement -- leastness now ranges over all integers, not just the ones
       the declaration admits. *)
lemma c10_p_tgts_is_least (p : int) : c <= p => c10_p_tgts <= p.
proof. by rewrite c10_c_closed /c10_c /c10_p_tgts /#. qed.

lemma c10_p_tgts_is_exactly_c : c10_p_tgts = c.
proof. by rewrite c10_c_closed /c10_c /c10_p_tgts. qed.

(* --------------------------------------------------------------------------
   4.  TARGET P3 -- DISCHARGE `c <= p_tgts` AT THE PIN.

   The model constant cannot be eliminated from an already-elaborated theory
   (EasyCrypt cannot re-interpret a declared const from inside it -- the same
   obstruction C10DeployedGeometry.ec records as residual (Q1)).  So the
   discharge takes the shape C10DeployedInstance.ec uses for `emb_in`: the
   premise is replaced by the PIN, and the pin implies it.

   The epistemic move, stated plainly: `c <= p_tgts` was a CONDITION ON AN
   UNPINNED CONSTANT which a permitted interpretation (`p_tgts = 0`) falsifies.
   After this it is a CONSEQUENCE OF AN INSTANTIATION CHOICE, and the choice is
   the least value the carried premise admits.  That is strictly stronger than the
   satisfiability argument SphincsC10CapstoneWired.ec:262-268 currently records
   ("a consistent interpretation exists, take p_tgts := c"), because the value
   is now a closed integer computed from the deployed geometry rather than a
   symbol, and because tightness is proved.  It is NOT a proof that `p_tgts`
   equals 262656 -- nothing inside the theory could be.
   -------------------------------------------------------------------------- *)
lemma c10_c_le_p_tgts_at_pin : p_tgts = c10_p_tgts => c <= p_tgts.
proof. by move=> ->; exact c10_p_tgts_dominates_c. qed.

(* The pin is also consistent with the declaration's axiom, so instantiating at
   it cannot contradict `ge0_ptgts`. *)
lemma c10_pin_respects_ge0_ptgts : p_tgts = c10_p_tgts => 0 <= p_tgts.
proof. by move=> ->; exact c10_p_tgts_admissible. qed.

(* --------------------------------------------------------------------------
   5.  TARGET P4 -- HOW `c` RELATES TO THE 2^16 DEPLOYMENT USAGE CAP.
       (State it plainly, because collapsing the two is the whole risk here.)

   THEY ARE DIFFERENT QUANTITIES.

     c   = 262656 = 2^18 + 2^9.  A STRUCTURAL count: how many WOTS-TW instances
           the hypertree contains.  It is the model's cap on committed queries
           (`nrqs <= c`, WOTS_C_Scheme.ec:214) and therefore the thing `p_tgts`
           must dominate.  It has nothing to do with any deployment policy.

     q_s = 65536 = 2^16.  A DEPLOYMENT policy bound: MAX_SLOT_USES, the on-chain
           per-key signature cap (PQSigner_OS invariant #7).  It is enforced by
           the wallet contract, not by the hypertree.

   ARITHMETIC (all proved below).  Crudely, counting every layer a signature
   touches: d * q_s = 131072 < c.  Tighter, and the honest number: a signature
   touches ONE bottom-layer WOTS instance and one top-tree instance, and only
   l' = 512 top-tree instances EXIST, so the DISTINCT instances a fully
   exhausted key can touch is at most q_s + l' = 66048 -- about a QUARTER of c,
   not a half.  The hypertree's own message capacity (l = 2^18) is four times
   the usage cap.  Both bounds are recorded; the tighter one strengthens the
   separation rather than weakening it.

   THE GAP, EXACTLY, because the prose has been loose about it:

       c / q_s          = 4.0078125       ->  log2 c - log2 q_s = 2.0028 bits
       (c / q_s)^2      = 16.0626         ->  4.0056 bits

   So the two caps are ~2 bits apart, NOT ~4.  The "~4 bits" figure that has
   been repeated is the SQUARED gap -- correct for a q_s^2-shaped advantage
   term (see below), wrong as a statement about the caps themselves.  Both
   numbers are recorded here so the next reader does not have to re-derive
   which one a given sentence meant.

   WHAT THIS PIN DOES **NOT** SUPPLY -- the point of stating P4 at all.
   scratch/FINDING-both-my-claims-were-wrong.md quotes a WOTS-leg figure

       advantage  <=  q_s^2 * 2^-114.09,   at q_s = 2^16  ->  2^-82

   That `q_s` is the SIGNING-QUERY count, not `c` and not `p_tgts`.  Pinning
   `p_tgts` does not pin `q_s`: nothing in this model expresses the on-chain
   2^16 cap, and the model's own query cap is `c`, which is LARGER.  Two
   consequences, both to be stated rather than papered over:

     (i)  Using the model's cap where the figure uses q_s costs 4.006 bits:
          c^2 * 2^-114.09 = 2^36.006 * 2^-114.094 = 2^-78.09, not 2^-82.
          The 2^-82 figure is therefore NOT licensed by anything pinned here;
          it needs a separate argument that signing queries -- not hypertree
          instances -- are what the term counts, plus the 2^16 policy bound
          imported into the model.  Neither exists.
     (ii) Pinning `p_tgts := 2^16` to make the arithmetic line up would be
          WRONG twice over: it would not discharge the premise (65536 < 262656,
          proved below), and it would cap the reduction's targets below the
          number it actually places, which turns the S-TCR win condition FALSE
          and breaks the reduction rather than tightening it.

   The `2^-114.09` constant itself is machine-checked
   (experiments/wots-badenc/count/C10SurfaceKernel.ec).  The `q_s^2 * ...`
   shape around it is generic-model arithmetic and is not a theorem here.
   -------------------------------------------------------------------------- *)
op c10_q_s : int = 65536.       (* MAX_SLOT_USES -- deployment, not model *)

lemma c10_usage_cap_below_c : c10_q_s < c.
proof. by rewrite c10_c_closed /c10_c /c10_q_s. qed.

(* Even counting every hypertree layer a signature touches, the deployed cap
   stays under the model's structural count. *)
lemma c10_layers_times_usage_cap_below_c : c10_d * c10_q_s < c.
proof. by rewrite c10_c_closed /c10_c /c10_d /c10_q_s. qed.

(* The TIGHTER separation: distinct WOTS instances reachable under the usage
   cap <= q_s (one bottom-layer instance per signature) + l' (every top-tree
   instance there is).  l' = 2 ^ h' = 512. *)
lemma c10_distinct_instances_under_usage_cap : c10_q_s + l' < c.
proof. by rewrite /l' hp_val c10_pow2_9 c10_c_closed /c10_c /c10_q_s. qed.

(* THE MUST-NOT-DO, AS A THEOREM: the usage cap is NOT an admissible pin for
   p_tgts.  This is the statement that forbids the convenient substitution. *)
lemma c10_usage_cap_is_not_admissible_as_p_tgts : ! (c <= c10_q_s).
proof. by rewrite c10_c_closed /c10_c /c10_q_s. qed.

(* The hypertree's message capacity, for the record: l = 2^18 = 4 * q_s. *)
lemma c10_ht_capacity : l = 262144.
proof. by rewrite /l /SPHINCS_PLUS.h hp_val d_val /= c10_pow2_18. qed.

lemma c10_ht_capacity_vs_usage_cap : l = 4 * c10_q_s.
proof. by rewrite c10_ht_capacity /c10_q_s. qed.

(* ==========================================================================
   SUMMARY OF WHAT LANDED, for anyone reading only the bottom of the file.

     P1  c = 262656 = 2^18 + 2^9                      c10_c_closed  (no premises)
     P2  p_tgts pinned at 262656, least admissible    c10_p_tgts_is_least
     P3  c <= p_tgts at the pin                       c10_c_le_p_tgts_at_pin
     P4  c vs the 2^16 usage cap                      section 5 + its five lemmas

   STILL OPEN, and not addressed by any of the above: the pin is an
   instantiation choice, not a theorem; the S-TCR(+C) term's game-level
   reduction is still deferred; `q_s` is still not expressed in this model, so
   the 2^-82 figure remains unfounded here.
   ========================================================================== *)
