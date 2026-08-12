(* Q2a SPIKE -- is 205 ATTAINED by `digitsum` on a real codeword at C10 geometry?
   NOT a deliverable yet.  See scratch/wots_leg_state_2026_08_12.md.

   WHY.  cdrafts-split/SphincsC10Content.ec:70 records residual Q2: target_sum is
   witnessed EXISTENTIALLY (`target_sum := digitsum (encode_msgWOTS d0)`), NOT at
   C10's deployed 205, and "whether 205 lies in the image of digitsum o
   encode_msgWOTS is undecided by this closure".
   C10DeployedInstance.ec:135 only gets `0 <= 205 <= len*(w-1)` and says so
   explicitly: "a necessary condition, not a sufficient one".

   Q2 SPLITS IN TWO, and only the second half needs the encoder pinned:
     (Q2a) is 205 attained by `digitsum` on SOME codeword?   <- UNCONDITIONAL
     (Q2b) is that codeword in the IMAGE of encode_msgWOTS?  <- needs pinning
   This file attacks Q2a.  It upgrades "not excluded by the geometry" to
   "realised by an exhibited codeword", which is strictly stronger and is a
   prerequisite for Q2b being a sensible question at all.

   WITNESS: 29 digits of 7, one digit of 2, 13 digits of 0 -> 29*7 + 2 = 205,
   over len = 43 digits, each < w = 8.                                        *)
require import AllCore List IntDiv StdBigop StdOrder.
require import WOTS_TW_ES.
import StdBigop.Bigint BIA.
import EmsgWOTS BaseW.

(* the digit pattern *)
op q2a_dig (i : int) : int = if i < 29 then 7 else if i = 29 then 2 else 0.

lemma q2a_dig_rng (i : int) : 2 <= w => 8 <= w => 0 <= q2a_dig i < w.
proof. by move=> _ hw; rewrite /q2a_dig; smt(). qed.

(* the exhibited codeword *)
op q2a_cw : emsgWOTS = EmsgWOTS.offun (fun i => BaseW.insubd (q2a_dig i)).

lemma q2a_val (i : int) :
  8 <= w => 0 <= i < len => BaseW.val q2a_cw.[i] = q2a_dig i.
proof.
move=> hw rgi; rewrite /q2a_cw EmsgWOTS.offunE //=.
by rewrite BaseW.insubdK //; smt(q2a_dig_rng).
qed.

(* THE TARGET: 205 is attained. *)
lemma q2a_digitsum_205 : len = 43 => 8 <= w => digitsum q2a_cw = 205.
proof.
move=> hlen hw; rewrite /digitsum hlen.
rewrite (BIA.eq_big_int 0 43 _ q2a_dig).
+ by move=> i rgi /=; apply q2a_val => //; rewrite hlen.
rewrite (BIA.big_cat_int 29 0 43) 1,2://.
rewrite (BIA.big_cat_int 30 29 43) 1,2://.
rewrite BIA.big_int1 /q2a_dig /=.
rewrite (BIA.eq_big_int 0 29 _ (fun _ => 7)) 1:/#.
rewrite (BIA.eq_big_int 30 43 _ (fun _ => 0)) 1:/#.
rewrite !BIA.sumri_const 1,2://=.
by rewrite !intmulz.
qed.

lemma q2a_205_attained :
  len = 43 => 8 <= w => exists (e : emsgWOTS), digitsum e = 205.
proof. by move=> hlen hw; exists q2a_cw; apply q2a_digitsum_205. qed.

(* ---------------------------------------------------------------------------
   Q4's arithmetic half.  SphincsC10Content.ec:78 records residual Q4: what is
   established is `predC` SOMEWHERE-TRUE, not a PROPER subset -- "in the
   exhibited model `predC d1` may also hold, i.e. the gate may never reject."
   At the deployed target the gate DOES reject: exhibit a codeword whose digit
   sum is not 205.                                                            *)
op q2a_cw0 : emsgWOTS = EmsgWOTS.offun (fun _ => BaseW.insubd 0).

lemma q2a_val0 (i : int) :
  8 <= w => 0 <= i < len => BaseW.val q2a_cw0.[i] = 0.
proof.
move=> hw rgi; rewrite /q2a_cw0 EmsgWOTS.offunE //=.
by rewrite BaseW.insubdK //; smt().
qed.

lemma q2a_digitsum_0 : len = 43 => 8 <= w => digitsum q2a_cw0 = 0.
proof.
move=> hlen hw; rewrite /digitsum hlen.
rewrite (BIA.eq_big_int 0 43 _ (fun _ => 0)).
+ by move=> i rgi /=; apply q2a_val0 => //; rewrite hlen.
by rewrite BIA.sumri_const //= intmulz.
qed.

(* BOTH halves at once: at C10's geometry the digit-sum gate at 205 is
   inhabited AND proper -- it accepts something and rejects something. *)
lemma q2a_gate_at_205_is_inhabited_and_proper :
     len = 43 => 8 <= w =>
  exists (e e' : emsgWOTS), digitsum e = 205 /\ digitsum e' <> 205.
proof.
move=> hlen hw; exists q2a_cw q2a_cw0.
by rewrite q2a_digitsum_205 // q2a_digitsum_0.
qed.
