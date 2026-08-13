(* ==========================================================================
   SPIKE, 2026-08-12 -- WHAT THE WOTS ADMIT ACTUALLY DEMANDS.

   Companion to scratch/FINDING-seed-withholding-has-no-isolated-step.md.
   READ THAT FIRST: it retracts the previous session's "seed-withholding spike"
   recommendation on the grounds that the admit sits at the WOTS-TW layer, where
   nothing is keyed, so there is no isolated step to discharge.

   THE TARGET.  base-c10-split/WOTS_TW_ES.ec:1505 `nhchwcoll_hchwpre_msg` closes
   with a bare `admit`, whose open goal is

       P m => P m' => m <> m' => encode_msgWOTS m <> encode_msgWOTS m'

   This file does NOT discharge it (it cannot -- see below).  It establishes
   exactly WHAT it is, so the residual can be stated honestly and gated:

     L1  the goal is EQUIVALENT to injectivity of `encode_msgWOTS` on the
         constant-sum surface `{m | P m}`;
     L1s ...and the second `P` hypothesis is REDUNDANT, so it is really
         "no message off the surface collides with one on it" either;
     L2  it forces `tgt_witness` -- the one message the theory KNOWS is on the
         surface -- to be the UNIQUE preimage of its own codeword;
     L3  hence ANY single collision witness on the surface refutes it;
     L3s ...and refutes not merely the admitted subgoal but the FULL five-
         hypothesis lemma statement, for any sig/sig' (Kimi K3, verified);
     L4  at deployed C10 parameters the encoder's domain is 2^127 times larger
         than its entire codomain.

   WHY THE GOAL IS NOT REFUTABLE HERE, and this is the load-bearing caveat:
   `encode_msgWOTS` is a FREE op (WOTS_TW_ES.ec:624) and `n`, `w`, `len` are
   abstract.  A model with a small domain and a large codeword space makes the
   goal TRUE.  So it is satisfiable abstractly, and the refutation must be
   conditional on the deployed geometry -- which is precisely residual Q2b.
   L3 + L4 are the two halves of that conditional refutation; L3 is proved here,
   L4's arithmetic is proved here, and the WITNESS L3 consumes is what Q2b would
   supply.  That coupling is the finding.

   ZERO admits, ZERO axioms declared in this file.  Nothing in the base tree is
   modified: this is the parallel-and-promote pattern that built GprocQBound /
   GprocQWired / GprocChargedQWired.
   ========================================================================== *)
require import AllCore List IntDiv Ring StdOrder StdBigop.
require import WOTS_TW_ES.
import IntOrder.

(* --------------------------------------------------------------------------
   The admit's open goal, named so it can be quoted and gated.
   Stated VERBATIM in the shape WOTS_TW_ES.ec:1505 leaves open.
   -------------------------------------------------------------------------- *)
op AdmitGoal : bool =
  forall (m m' : msgWOTS),
    P m => P m' => m <> m' => encode_msgWOTS m <> encode_msgWOTS m'.

(* Injectivity of the encoder restricted to the constant-sum surface. *)
op EncInjOnP : bool =
  forall (m m' : msgWOTS),
    P m => P m' => encode_msgWOTS m = encode_msgWOTS m' => m = m'.

(* The same with the second surface hypothesis dropped. *)
op EncInjOnP1 : bool =
  forall (m m' : msgWOTS),
    P m => encode_msgWOTS m = encode_msgWOTS m' => m = m'.

(* --------------------------------------------------------------------------
   L0.  `P` is a property of the CODEWORD, not of the message: equal encodings
   force equal membership of the surface.  This is what makes L1s possible, and
   it is a consequence of `P` having been turned into a DEFINITION (2026-07-29).
   Under the old abstract `P` this lemma was NOT available.
   -------------------------------------------------------------------------- *)
lemma P_encode_congr (m m' : msgWOTS) :
  encode_msgWOTS m = encode_msgWOTS m' => (P m <=> P m').
proof. by rewrite /P => ->. qed.

(* --------------------------------------------------------------------------
   L1.  THE ADMIT IS AN INJECTIVITY DEMAND.  Not "a technicality about distinct
   messages" -- the two statements are interderivable.
   -------------------------------------------------------------------------- *)
lemma admitgoal_iff_encinjonP : AdmitGoal <=> EncInjOnP.
proof.
rewrite /AdmitGoal /EncInjOnP; split => h m m' hP hP'.
+ by move=> heq; case (m = m') => // hne; move: (h m m' hP hP' hne).
by move=> hne; apply/negP => heq; apply hne; apply (h m m').
qed.

(* L1s.  The second hypothesis buys nothing: by L0 it is implied. *)
lemma encinjonP_iff_encinjonP1 : EncInjOnP <=> EncInjOnP1.
proof.
rewrite /EncInjOnP /EncInjOnP1; split => h m m' hP.
+ by move=> heq; apply (h m m') => //; move: hP; rewrite (P_encode_congr m m').
by move=> _ heq; apply (h m m').
qed.

lemma admitgoal_iff_encinjonP1 : AdmitGoal <=> EncInjOnP1.
proof. by rewrite admitgoal_iff_encinjonP encinjonP_iff_encinjonP1. qed.

(* --------------------------------------------------------------------------
   L2.  THE ANCHOR.  `tgt_witness` is the ONE message the theory knows lies on
   the surface -- `target_sum` is DEFINED as its digit sum (WOTS_TW_ES.ec:645),
   so `P tgt_witness` costs nothing.  The admit therefore forces it to be the
   unique preimage of its own codeword.

   This is the sharpest UNCONDITIONAL consequence available: it converts an
   abstract injectivity demand into a statement about one named constant.
   -------------------------------------------------------------------------- *)
lemma P_tgt_witness : P tgt_witness.
proof. by rewrite /P /target_sum. qed.

lemma admit_forces_tgt_witness_unique :
  AdmitGoal =>
  forall (m : msgWOTS), encode_msgWOTS m = encode_msgWOTS tgt_witness => m = tgt_witness.
proof.
move=> h m heq.
have h1 : EncInjOnP1 by move: h; rewrite admitgoal_iff_encinjonP1.
apply (h1 m tgt_witness) => //.
by move: P_tgt_witness; rewrite -(P_encode_congr m tgt_witness heq).
qed.

(* --------------------------------------------------------------------------
   L3.  CONDITIONAL REFUTATION.  One collision witness against `tgt_witness` is
   enough.  Under the deployed identification (residual Q2b) such a witness is
   immediate -- the C10 digit map reads 129 bits of a 256-bit digest and IGNORES
   the top 127 (sphincs-c10/src/wots.rs:26-45), so every message agreeing with
   `tgt_witness` on the low 129 bits and differing above is one.
   -------------------------------------------------------------------------- *)
lemma admit_refuted_by_witness (m0 : msgWOTS) :
     m0 <> tgt_witness
  => encode_msgWOTS m0 = encode_msgWOTS tgt_witness
  => ! AdmitGoal.
proof.
move=> hne heq; apply/negP => h.
by apply hne; apply (admit_forces_tgt_witness_unique h).
qed.

(* The general form: any collision on the surface, not just against tgt_witness. *)
lemma admit_refuted_by_surface_collision (m m' : msgWOTS) :
     P m
  => m <> m'
  => encode_msgWOTS m = encode_msgWOTS m'
  => ! AdmitGoal.
proof.
move=> hP hne heq; apply/negP => h.
have h1 : EncInjOnP1 by move: h; rewrite admitgoal_iff_encinjonP1.
by apply hne; apply (h1 m m').
qed.

(* --------------------------------------------------------------------------
   L3s.  THE SHARPENING (Kimi K3, 2026-08-12, verified at source before adopting).

   A surface collision does not merely refute the OPEN GOAL of the admit -- it
   refutes the ENTIRE five-hypothesis statement of `nhchwcoll_hchwpre_msg`, for
   ANY `sig`/`sig'`.  The reason is that both chain predicates carry the SAME
   first conjunct:

     is_chwcoll ... i  =  BaseW.val em'.[i] < BaseW.val em.[i] /\ ...   (:763-768)
     is_chwpre  ... i  =  BaseW.val em'.[i] < BaseW.val em.[i] /\ ...   (:807-812)

   Under a collision `em = em'` that conjunct is `x < x` -- false at EVERY index.
   So `has_chwcoll` is false (hence its negation, a HYPOTHESIS, holds) while
   `has_chwpre` is also false (the CONCLUSION fails).  Every hypothesis is
   satisfied and the conclusion is not.

   This is why section 4 of the FINDING was UNDER-stated: it is not "the admitted
   subgoal becomes unprovable", it is "the lemma becomes false".
   -------------------------------------------------------------------------- *)
lemma collision_kills_both_chain_predicates
      (ps : pseed) (ad : adrs) (m m' : msgWOTS) (sig sig' : sigWOTS) :
     encode_msgWOTS m = encode_msgWOTS m'
  =>  ! has_chwcoll ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'
   /\ ! has_chwpre  ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'.
proof.
move=> heq; rewrite /has_chwcoll /has_chwpre; split; rewrite hasPn => i _.
+ by rewrite /is_chwcoll /= heq /=; smt().
by rewrite /is_chwpre /= heq /=; smt().
qed.

lemma full_statement_refuted_by_surface_collision
      (ps : pseed) (ad : adrs) (m m' : msgWOTS) (sig sig' : sigWOTS) :
     P m
  => m <> m'
  => encode_msgWOTS m = encode_msgWOTS m'
  => ! (   P m
        => P m'
        => m <> m'
        => ! has_chwcoll ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'
        => has_chwpre ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig').
proof.
move=> hP hne heq; apply/negP => h.
have [hnc hnp] :=
  collision_kills_both_chain_predicates ps ad m m' sig sig' heq.
have hP' : P m' by move: hP; rewrite (P_encode_congr m m').
by move: (h hP hP' hne hnc).
qed.

(* --------------------------------------------------------------------------
   L5.  THE ADMIT-FREE REPLACEMENT (GPT-5.6's recommended unit, 2026-08-12).

   THIS IS THE CONSTRUCTIVE PAYOFF OF THE WHOLE SPIKE.  The admitted lemma
   `nhchwcoll_hchwpre_msg` tries to conclude `has_chwpre` outright.  That is
   false under a collision (L3s).  The CALLER-SHAPED SPLIT below concludes the
   DISJUNCTION instead, and is proved with ZERO admits from the already-proved
   `nhchwcoll_hchwpre` (the non-`_msg` version, WOTS_TW_ES.ec:1476, whose proof
   is complete):

     encode m = encode m'   \/   has_chwpre ...

   The left disjunct IS the `BadEnc` event -- exactly the thing a +C
   seed-withholding argument can bound, because at that layer the messages are
   `ThC ps ad x c` and the composite `encode o ThC ps ad .` IS seed-keyed.

   So the repair is not "discharge the admit" (impossible -- the statement is
   false at deployed geometry).  It is: replace it with this disjunction, lift
   the disjunction at the Game4 caller, and charge the left branch.  This lemma
   is the first half, and it costs nothing.

   NOTE it needs NO `m <> m'` hypothesis -- strictly weaker premises than the
   admitted lemma, and it still gives the caller everything except the charge.
   -------------------------------------------------------------------------- *)
lemma admit_free_caller_split
      (ps : pseed) (ad : adrs) (m m' : msgWOTS) (sig sig' : sigWOTS) :
     P m
  => P m'
  => ! has_chwcoll ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'
  =>  encode_msgWOTS m = encode_msgWOTS m'
   \/ has_chwpre ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'.
proof.
move=> hP hP' hnc; case (encode_msgWOTS m = encode_msgWOTS m') => [heq | hne].
+ by left.
by right; apply (nhchwcoll_hchwpre ps ad m m' sig sig').
qed.

(* And the reconciliation: excluding the BadEnc branch recovers EXACTLY the
   admitted lemma's conclusion.  So the split loses nothing -- it makes the
   missing side condition VISIBLE instead of admitted. *)
lemma caller_split_recovers_admit_under_badenc
      (ps : pseed) (ad : adrs) (m m' : msgWOTS) (sig sig' : sigWOTS) :
     P m
  => P m'
  => encode_msgWOTS m <> encode_msgWOTS m'
  => ! has_chwcoll ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'
  => has_chwpre ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'.
proof.
move=> hP hP' hbad hnc.
by case (admit_free_caller_split ps ad m m' sig sig' hP hP' hnc).
qed.

(* --------------------------------------------------------------------------
   L4.  THE DEPLOYED CARDINALITY GAP.  At C10's parameters the encoder's domain
   `msgWOTS = mdgstblock` has 2^(8*n_m) = 2^256 elements (it is the subtype of
   `bool list` of length 8*n_m -- WOTS_TW_ES.ec:179,191-193,270) and its
   codomain has w^len = 8^43 = 2^129.  So the codomain is 2^127 times SMALLER.

   Recorded honestly: this is the ARITHMETIC of the gap.  Turning it into "no
   injection exists" additionally needs `card` instances for the two subtype /
   Word clones, which this development does not build (FinType/Finite are
   available -- PRE_From_SPR_DSPR.ec:2,24 -- but not instantiated here).  What is
   proved below is the inequality itself, which is the part that was never
   written down anywhere in the tree.
   -------------------------------------------------------------------------- *)
(* Deterministic, no SMT -- copied from the shared discharge in
   experiments/tcollres-leg/EncoderBridge.ec:120, whose header records that the
   SMT version was flaky under full-chain load and therefore made every receipt
   containing it a measurement of machine load rather than of the proof. *)
lemma c10_pow8 : 8 = 2 ^ 3.
proof.
by rewrite (_ : 3 = 2 + 1) 1:// exprS 1:// (_ : 2 = 1 + 1) 1:// exprS 1:// expr1.
qed.

lemma c10_pow43_eq : 8 ^ 43 = 2 ^ 129.
proof. by rewrite c10_pow8 -exprM. qed.

lemma pow2_256_split : 2 ^ 256 = 2 ^ 129 * 2 ^ 127.
proof. by rewrite -exprD_nneg //=. qed.

(* The gap, stated as the multiplier -- this is the number that matters. *)
lemma c10_codomain_shortfall :
  n = 16 => w = 8 => len = 43 => 2 ^ (8 * n_m) = w ^ len * 2 ^ 127.
proof.
move=> hn hw hlen.
rewrite hw hlen c10_pow43_eq /n_m hn (_ : 8 * (2 * 16) = 256) 1://.
by apply pow2_256_split.
qed.

lemma c10_domain_exceeds_codomain :
  n = 16 => w = 8 => len = 43 => w ^ len < 2 ^ (8 * n_m).
proof.
move=> hn hw hlen.
rewrite (c10_codomain_shortfall hn hw hlen) hw hlen c10_pow43_eq.
have hpos126 : 0 < 2 ^ 126 by apply expr_gt0.
have hgt1 : 1 < 2 ^ 127 by rewrite (_ : 127 = 126 + 1) 1:// exprS 1://; smt().
have hpos : 0 < 2 ^ 129 by apply expr_gt0.
smt().
qed.
