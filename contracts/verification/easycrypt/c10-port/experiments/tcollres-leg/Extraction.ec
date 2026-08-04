(* ==========================================================================
   EXTRACTION EXPERIMENT — the FORS -> hypertree -> WOTS boundary.

   Purpose (GPT-5.6's recommended cheapest decision-relevant test): from the
   +C GCMA forgery event, extract EITHER the exact equal-codeword target event
   OR a lower-layer break, and thereby decide whether the port's existing
   S-TCR(+C) machinery is reusable AS-IS or needs a codeword-valued refinement.

   See PREDICTION-extraction.md, written before this compiled.

   NON-VACUITY DISCIPLINE.  `P \/ !P` is a tautology; stating the trichotomy
   alone proves nothing, and the 2026-07-25 deep-research finding is explicit
   that CASE-SPLIT-ONLY IS UNSOUND (the collision must be removed by a game hop
   BEFORE the split).  So the content here is exactly:

     (D) DECOMPOSITION over the REAL game, not a toy.
     (E) EXTRACTION: in the good branch, the hypothesis the WOTS chain argument
         actually consumes is recoverable.

   Anything that reduces to `P \/ !P` is marked VACUOUS in place and does not
   count as a result.
   ========================================================================== *)
require import AllCore List Distr.
require import SPHINCS_PLUS.
require WOTS_C_Real.
require import WOTS_C_Scheme.

import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import EmsgWOTS.

(* --------------------------------------------------------------------------
   THE THREE LEVELS.  This is the structural fact the experiment turns on, and
   it is why a single "encoding collision" event is the WRONG granularity:

     level 1   messages          m, m' : msgWOTS
     level 2   ThC digests       ThC ps ad m c
     level 3   codewords         encode_msgWOTS_C ps ad m c

   The +C encoding FACTORS as level3 = encode_msgWOTS o level2 (the bridge
   recorded at XmssmtCC_All.ec:1178).  The obligation left open at
   shadow/WOTS_TW_ES.ec:1359 lives at LEVEL 3.
   -------------------------------------------------------------------------- *)

(* The codeword-collision event, stated at level 3 — the granularity the
   PREDICTION says is required.  If this had been stated at level 1 (message
   equality) the extraction below would not go through, and that failure would
   itself have been the finding. *)
op COLL (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr) : bool =
  encode_msgWOTS_C ps ad m' c' = encode_msgWOTS_C ps ad m c.

(* --------------------------------------------------------------------------
   (E) EXTRACTION — the part that decides reusability.

   The WOTS chain argument (my weakened `nhchwcoll_hchwpre`) consumes exactly
   CODEWORD inequality.  This says: in the !COLL branch that hypothesis is
   literally available, with NO further side condition.  It is stated over the
   real +C encoding, so it is not a toy.
   -------------------------------------------------------------------------- *)
lemma extraction_good_branch (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr) :
     ! COLL ps ad m m' c c'
  => encode_msgWOTS_C ps ad m' c' <> encode_msgWOTS_C ps ad m c.
proof. by rewrite /COLL. qed.

(* --------------------------------------------------------------------------
   THE REFINEMENT THE EXPERIMENT IS ACTUALLY TESTING FOR.

   Because level3 = encode_msgWOTS o level2, a level-3 collision has TWO
   disjoint causes, and they must be charged to DIFFERENT assumptions:

     (B1) the ThC digests already collide          -> S-TCR(+C) target collision
     (B2) the digests DIFFER but their codewords agree
                                                   -> an encode_msgWOTS collision
                                                      on DISTINCT digests

   (B2) is precisely MM45's injectivity failure, and Def 9 incomparability does
   NOT rescue it: Def 9 constrains distinct CODEWORDS, and in (B2) the codewords
   are equal.  So a single "charge the collision to S-TCR" step is NOT enough —
   this is the codeword-valued refinement GPT-5.6 predicted would be needed.
   -------------------------------------------------------------------------- *)
lemma coll_splits_by_level (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr) :
     COLL ps ad m m' c c'
  =>    (ThC ps ad m' c' =  ThC ps ad m c)   (* B1: level-2 collision *)
     \/ (ThC ps ad m' c' <> ThC ps ad m c    (* B2: level-3 only       *)
         /\ encode_msgWOTS_C ps ad m' c' = encode_msgWOTS_C ps ad m c).
proof.
rewrite /COLL => hcoll.
case: (ThC ps ad m' c' = ThC ps ad m c) => hthc.
- by left.
- by right.
qed.

(* --------------------------------------------------------------------------
   HONEST MARKER — what is NOT proved here, so nothing downstream over-reads it.

   The (B2) branch cannot be closed at this abstraction level: `ThC` and
   `encode_msgWOTS_C` are ABSTRACT ops in this development
   (WOTS_C_Real.ec:180,220,223).  Closing (B2) requires the deployed-encoder
   bridge — concretely that `encode_msgWOTS_C` is the base-8 digit extraction of
   the LOW 129 BITS of SHA-256, which is injective on those bits, so that
   (B2) becomes empty and (B1) is the only cause.  That is step 4 of the
   five-step route and is NOT attempted here.

   Until that bridge exists, (B2) is a genuine, uncharged event.
   -------------------------------------------------------------------------- *)
op B2_is_empty : bool =
  forall (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr),
    encode_msgWOTS_C ps ad m' c' = encode_msgWOTS_C ps ad m c =>
    ThC ps ad m' c' = ThC ps ad m c.

(* Conditional closure: IF the deployed-encoder bridge is supplied, the level-3
   collision collapses to the single S-TCR(+C) charge.  Stated as an implication
   with the bridge as an explicit hypothesis — deliberately NOT axiomatised. *)
lemma coll_collapses_under_bridge (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr) :
     B2_is_empty
  => COLL ps ad m m' c c'
  => ThC ps ad m' c' = ThC ps ad m c.
proof. by move=> hb; rewrite /COLL => hc; apply hb. qed.
