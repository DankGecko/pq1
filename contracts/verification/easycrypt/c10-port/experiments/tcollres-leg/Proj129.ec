(* ==========================================================================
   THE 129/128 PROJECTION LEMMA — repairing a defect in EncoderBridge.ec.

   WHAT WAS WRONG.  `EncoderBridge.c10_enc_inj` proves injectivity of the base-8
   digit map on inputs in `[0, 2^128)`, and `RESULT-encoder-bridge.md` narrated
   that as "129 >= 128, so there is ONE BIT to spare".  The deployed encoder does
   not have a spare bit.  `sphincs-c10/src/wots.rs:35-46` extracts

       digit[i] = (digest >> (i * 3)) & 7   for i in 0..42

   so it consumes bits 0..128 — **129 bits, not 128**.  Digit 42 is bits
   126,127,128, and bit 128 is that digit's MSB, weight 4.  A statement about
   `[0, 2^128)` therefore does not cover the deployed input range.
   (Defect found by GPT-5.6, 2026-07-27 adversarial review.)

   WHAT THIS FILE PROVES.  Two things, and the second is the interesting one.

   1. The repair is not merely available, it is EXACT: `8^43 = 2^129`, so the
      digit map is injective on the FULL deployed range `[0, 2^129)` with no
      budget slack at all.  `c10_enc_inj_129` replaces the 128-bit statement.

   2. On the CONSTANT-SUM SURFACE the 129th bit is redundant: if two values in
      `[0, 2^129)` both have digit sum 205 and agree on their low 128 bits, they
      are EQUAL.  Flipping bit 128 moves digit 42 by exactly 4, so it moves the
      sum by 4, so it cannot preserve `sum = 205`.

   WHY (2) MATTERS.  The port models a digest as a 128-bit `dgstblock`, while the
   deployment feeds 129 bits to the digit map.  (2) says that mismatch costs
   nothing ON THE SET THE VERIFIER ACCEPTS — `pk_from_sig` returns all-zero
   unless the digit sum is exactly `TARGET_SUM` (`wots.rs:155-160`), so only the
   constant-sum surface is ever live.  This is the arithmetic half of the
   faithfulness obligation recorded as gap 2 in `RESULT-encoder-bridge.md`.

   IT IS ONLY THE ARITHMETIC HALF.  This file does NOT prove that the model's
   abstract `ThC`-produced `dgstblock` IS the low 128 bits of the deployed
   `wots_digest`.  That identification is still unwired (`ThC` is abstract at
   `WOTS_C_Real.ec:175`).  Read (2) as: *given* that identification, the 128-bit
   index loses nothing.  The identification itself remains owed.

   DIGIT ORDER.  `int2dig` is MOST-significant-first (index 0 = bits 126..128);
   the firmware is least-significant-first (index 42 = bits 126..128).  Digit SUM
   and INJECTIVITY are both order-invariant, so these two results transfer as
   stated.  The CHAIN ASSIGNMENT (which digit drives which WOTS chain) is NOT
   order-invariant and is NOT addressed here.
   ========================================================================== *)
require import AllCore List IntDiv Ring StdOrder.
require import EncoderBridge.
import IntOrder.

(* -- digit sum, in the same recursive style as `dig2int` -------------------- *)
op dsum (ds : int list) : int =
  with ds = []      => 0
  with ds = d :: ds => d + dsum ds.

lemma dsum_rcons (ds : int list) (d : int) : dsum (rcons ds d) = dsum ds + d.
proof. elim: ds => //= x ds ih; rewrite ih; ring. qed.

(* peel the LEAST significant digit, matching `int2digS` *)
lemma dsum_int2digS (l n : int) :
  0 <= l => 0 <= n =>
  dsum (int2dig (l + 1) n) = dsum (int2dig l (n %/ wd)) + n %% wd.
proof. by move=> ge0_l ge0_n; rewrite int2digS // dsum_rcons. qed.

(* ==========================================================================
   THE KEY ARITHMETIC.  Prepending a top digit `c` adds exactly `c` to the sum.
   This is what makes "flip bit 128 => sum moves by 4" a theorem rather than a
   picture.
   ========================================================================== *)
lemma dsum_hi (l n c : int) :
     0 <= l
  => 0 <= n < wd ^ l
  => 0 <= c < wd
  => dsum (int2dig (l + 1) (n + c * wd ^ l)) = dsum (int2dig l n) + c.
proof.
move=> ge0_l; move: l ge0_l n c; apply: intind.
+ move=> n c [ge0_n ltn] [ge0_c ltc].
  have -> : n = 0 by move: ltn; rewrite expr0 /#.
  by rewrite expr0 /= int2dig0 /= /int2dig mkseq1 /= expr0 divz1 modz_small /#.
move=> l ge0_l ih n c [ge0_n ltn] [ge0_c ltc].
have gt0w : 0 < wd by exact gt0_wd.
have ge0_pow : 0 <= wd ^ l by smt(expr_ge0 gt0_wd).
(* rewrite the argument so the division/modulo lemmas apply verbatim *)
have harg : n + c * wd ^ (l + 1) = (c * wd ^ l) * wd + n.
+ by rewrite exprS //; ring.
have ge0_arg : 0 <= n + c * wd ^ (l + 1) by smt(expr_ge0 gt0_wd).
rewrite dsum_int2digS 1:/# //.
rewrite harg divzMDl 1:/# modzMDl.
have -> : c * wd ^ l + n %/ wd = n %/ wd + c * wd ^ l by ring.
(* This was `first 2 by smt(ltz_divLR gt0_wd exprS divz_ge0)` until 2026-07-28.
   It asks SMT to reason about wd^l vs wd^(l+1) with a SYMBOLIC exponent, which
   is far harder than the `8 = 2^3` goal that first exposed the problem -- and it
   is the site that actually fails: 5/5 under CPU saturation, 0/5 idle
   (stress_leaves.sh).  Discharged by hand instead; the two obligations are
   `0 <= n %/ wd < wd^l` (from n < wd^(l+1) via ltz_divLR + exprS) and
   `0 <= c < wd` (already in context). *)
rewrite ih.
+ split; first by apply divz_ge0; [exact gt0w | exact ge0_n].
  move=> _; rewrite ltz_divLR 1:gt0w mulzC -exprS 1:ge0_l.
  exact ltn.
+ by split.
by rewrite dsum_int2digS //; ring.
qed.

(* ==========================================================================
   ANTI-VACUITY.  Every digit sum in the achievable band is REACHED.

   Without this, `c10_low128_determines` could be a true theorem about the EMPTY
   SET -- if no integer in range had digit sum 205, everything below would hold
   vacuously (trap T3: a 0-admit theorem can still be vacuous).  The proof reuses
   `dsum_hi`, so it is also an independent exercise of that lemma.
   ========================================================================== *)
lemma dsum_surj (l s : int) :
     0 <= l
  => 0 <= s <= l * (wd - 1)
  => exists n, 0 <= n < wd ^ l /\ dsum (int2dig l n) = s.
proof.
move=> ge0_l; move: l ge0_l s; apply: intind.
+ move=> s [ge0_s les]; exists 0.
  by rewrite expr0 int2dig0 /=; smt().
move=> l ge0_l ih s [ge0_s les].
have gt1w : 1 < wd by exact gt1_wd.
have ge0_pow : 0 <= wd ^ l by smt(expr_ge0 gt0_wd).
pose c := if s <= wd - 1 then s else wd - 1.
have hc : 0 <= c < wd by smt().
have [n [hn hdn]] : exists n, (0 <= n < wd ^ l) /\ dsum (int2dig l n) = s - c.
+ by apply ih; smt().
(* the range obligation is NONLINEAR (c * wd^l), so feed smt the two products
   it cannot discover on its own *)
have hub : c * wd ^ l <= (wd - 1) * wd ^ l by smt(ler_wpmul2r).
have hlo : 0 <= c * wd ^ l by smt(mulr_ge0).
have hexp : (wd - 1) * wd ^ l + wd ^ l = wd ^ (l + 1) by rewrite exprS //; ring.
exists (n + c * wd ^ l); split; 1: smt().
by rewrite (dsum_hi l n c ge0_l hn hc) hdn; ring.
qed.

(* ==========================================================================
   C10 NUMBERS.  8^42 = 2^126 and 8^43 = 2^129, so 2^128 = 4 * 8^42: adding
   2^128 bumps the TOP digit by 4 and nothing else.
   ========================================================================== *)
(* both now use EncoderBridge.pow8 -- deterministic, no SMT.  See the note there:
   the old `by smt()` timed out under full-chain load while passing cold. *)
lemma c10_pow42 : 8 ^ 42 = 2 ^ 126.
proof. by rewrite pow8 -exprM. qed.

lemma c10_pow43 : 8 ^ 43 = 2 ^ 129.
proof. by rewrite pow8 -exprM. qed.

(* --------------------------------------------------------------------------
   THE STEP: bit 128 is worth EXACTLY 4 in the digit sum.
   -------------------------------------------------------------------------- *)
lemma c10_step (x : int) :
     wd = 8
  => 0 <= x < 2 ^ 128
  => dsum (int2dig 43 (x + 2 ^ 128)) = dsum (int2dig 43 x) + 4.
proof.
move=> hwd [ge0_x ltx].
have h126 : 0 < 2 ^ 126 by smt(expr_gt0).
have h128v : 2 ^ 128 = 4 * 2 ^ 126 by smt(exprS expr_gt0).
have hpow : wd ^ 42 = 2 ^ 126 by rewrite hwd c10_pow42.
(* decompose x = r + t * 2^126 with r < 2^126 and t < 4.  `r` and `t` are
   introduced OPAQUELY (not by `pose`) so the rewrites below cannot loop back
   through their definitions. *)
have [r t] [hr [ht hx]] :
  exists r t, (0 <= r < 2 ^ 126) /\ ((0 <= t < 4) /\ x = r + t * 2 ^ 126).
+ exists (x %% 2 ^ 126) (x %/ 2 ^ 126).
  smt(modz_ge0 ltz_pmod divz_ge0 ltz_divLR divz_eq).
have e1 : dsum (int2dig 43 x) = dsum (int2dig 42 r) + t.
+ rewrite hx.
  have -> : 43 = 42 + 1 by done.
  have -> : r + t * 2 ^ 126 = r + t * wd ^ 42 by rewrite hpow.
  by apply dsum_hi; smt().
have e2 : dsum (int2dig 43 (x + 2 ^ 128)) = dsum (int2dig 42 r) + (t + 4).
+ have -> : x + 2 ^ 128 = r + (t + 4) * wd ^ 42 by rewrite hpow hx; ring.
  have -> : 43 = 42 + 1 by done.
  by apply dsum_hi; smt().
by rewrite e1 e2; ring.
qed.

(* ==========================================================================
   RESULT 1 — the repaired bridge, at the range the deployment ACTUALLY uses.
   Note there is no slack: 8^43 = 2^129 exactly.
   ========================================================================== *)
lemma c10_enc_inj_129 (x y : int) :
     wd = 8
  => 0 <= x < 2 ^ 129
  => 0 <= y < 2 ^ 129
  => int2dig 43 x = int2dig 43 y
  => x = y.
proof.
move=> hwd rgx rgy heq.
apply (int2dig_inj 43) => //; rewrite hwd c10_pow43 //.
qed.

(* ==========================================================================
   RESULT 2 — ON THE CONSTANT-SUM SURFACE THE 129th BIT IS DETERMINED.
   This is the statement that makes a 128-bit model index honest.
   ========================================================================== *)
lemma c10_low128_determines (x y : int) :
     wd = 8
  => 0 <= x < 2 ^ 129
  => 0 <= y < 2 ^ 129
  => dsum (int2dig 43 x) = 205
  => dsum (int2dig 43 y) = 205
  => x %% 2 ^ 128 = y %% 2 ^ 128
  => x = y.
proof.
move=> hwd rgx rgy hsx hsy hmod.
have h128 : 0 < 2 ^ 128 by smt(expr_gt0).
have h129 : 2 ^ 129 = 2 * 2 ^ 128 by smt(exprS expr_gt0).
(* equal low 128 bits + both < 2*2^128  ==>  x - y is 0 or +-2^128 *)
have hdx := divz_eq x (2 ^ 128).
have hdy := divz_eq y (2 ^ 128).
have hqx : 0 <= x %/ 2 ^ 128 < 2 by smt(divz_ge0 ltz_divLR).
have hqy : 0 <= y %/ 2 ^ 128 < 2 by smt(divz_ge0 ltz_divLR).
have hcase : x = y \/ y = x + 2 ^ 128 \/ x = y + 2 ^ 128.
+ smt().
case: hcase => [// | [hy | hx]].
+ have hxlt : 0 <= x < 2 ^ 128 by smt().
  have := c10_step x hwd hxlt.
  by rewrite -hy hsx hsy /#.
+ have hylt : 0 <= y < 2 ^ 128 by smt().
  have := c10_step y hwd hylt.
  by rewrite -hx hsx hsy /#.
qed.

(* The faithfulness form actually consumed downstream: the low-128 projection is
   injective ON CODEWORDS of the constant-sum surface. *)
lemma c10_low128_faithful (x y : int) :
     wd = 8
  => 0 <= x < 2 ^ 129
  => 0 <= y < 2 ^ 129
  => dsum (int2dig 43 x) = 205
  => dsum (int2dig 43 y) = 205
  => x %% 2 ^ 128 = y %% 2 ^ 128
  => int2dig 43 x = int2dig 43 y.
proof. by move=> hwd rgx rgy hsx hsy hmod; congr; apply (c10_low128_determines). qed.

(* ==========================================================================
   NEGATIVE CONTROL, MECHANIZED — the constant-sum hypothesis is LOAD-BEARING.

   Without `sum = 205`, agreeing on the low 128 bits does NOT determine the
   codeword: 0 and 2^128 agree on all 128 low bits and have DIFFERENT digit
   vectors.  So RESULT 2 is not a repackaging of RESULT 1, and the "spare bit"
   narrative in RESULT-encoder-bridge.md was genuinely wrong: the 129th bit is
   free in general and pinned only on the constant-sum surface.
   ========================================================================== *)
lemma negctl_129th_bit_is_NOT_free : wd = 8 => int2dig 43 0 <> int2dig 43 (2 ^ 128).
proof.
move=> hwd; apply/negP => heq.
have hlt : 2 ^ 128 < 2 ^ 129 by smt(exprS expr_gt0).
have hz : 0 = 2 ^ 128.
+ by apply (c10_enc_inj_129 0 (2 ^ 128)); smt(expr_gt0).
smt(expr_gt0).
qed.

(* --------------------------------------------------------------------------
   ANTI-VACUITY AT C10: the sum-205 surface is NONEMPTY, so `c10_low128_determines`
   is not a theorem about the empty set.  205 <= 43 * 7 = 301, so it is reachable.
   -------------------------------------------------------------------------- *)
lemma c10_target_sum_reachable :
  wd = 8 => exists n, 0 <= n < 2 ^ 129 /\ dsum (int2dig 43 n) = 205.
proof.
move=> hwd.
have [n [hn hdn]] : exists n, (0 <= n < wd ^ 43) /\ dsum (int2dig 43 n) = 205.
+ by apply dsum_surj; smt().
by exists n; rewrite hdn /=; move: hn; rewrite hwd c10_pow43.
qed.

(* and the MECHANISM, concretely: the two witnesses differ in sum by exactly 4 *)
lemma negctl_witness_sums_differ_by_4 :
  wd = 8 => dsum (int2dig 43 (2 ^ 128)) = dsum (int2dig 43 0) + 4.
proof. by move=> hwd; have := c10_step 0 hwd _; [smt(expr_gt0) | smt()]. qed.
