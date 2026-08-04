(* ==========================================================================
   ENCODER BRIDGE — discharging `B2_is_empty` from the bit budget.

   Extraction.ec left exactly one uncharged event:

     B2 : the ThC digests DIFFER but their codewords AGREE.

   Def 9 cannot rescue B2 (it constrains DISTINCT codewords; in B2 they are
   equal).  B2 empties iff the digit map is INJECTIVE on digests.  This file
   proves that, from the bit budget alone, and instantiates it at C10.

   WHY THIS FILE IS PARAMETRIC, not a clone of the MM45 namespace.
   The vendored WOTS_TW_ES still carries `val_log2w : log2_w = 2 \/ = 4 \/ = 8`
   (shadow/WOTS_TW_ES.ec:31) and the CHECKSUM geometry len = len1 + len2 (:43).
   C10 needs log2_w = 3 and a flat len = 43, so the instantiation is REJECTED
   there -- the long-known F1 blocker, untouched by this experiment.  So the
   arithmetic is proved parametrically here and instantiated at C10's numbers,
   exactly as drafts/IncEnc.ec does for Def 9.

   PROVENANCE: `int2lbw` / `bw2int` / `int2lbwK` are transcribed from the
   research base at FV-XMSS-EC/proofs/WOTS_TW_Checksum.ec:22,40,85 and restated
   over plain ints (no BaseW subtype) so this stays a leaf.  Nothing in either
   vendored tree is modified.
   ========================================================================== *)
require import AllCore List IntDiv Ring StdOrder.
import IntOrder.

(* -- base, parametric.  `wd` is the RADIX (C10: 8), not the bit width. ----- *)
op wd : int.
axiom gt1_wd : 1 < wd.

lemma gt0_wd : 0 < wd. proof. smt(gt1_wd). qed.

(* digit map: n |-> its `l` base-wd digits, most significant first *)
op int2dig (l n : int) : int list =
  mkseq (fun (i : int) => (n %/ wd ^ (l - 1 - i)) %% wd) l.

(* left inverse *)
op dig2int (ds : int list) : int =
  with ds = []      => 0
  with ds = d :: ds => d * wd ^ (size ds) + dig2int ds.

lemma int2dig0 (n : int) : int2dig 0 n = [].
proof. by rewrite /int2dig mkseq0. qed.

lemma size_int2dig (l n : int) : 0 <= l => size (int2dig l n) = l.
proof. by move=> ge0_l; rewrite /int2dig size_mkseq /#. qed.

lemma int2digS (l n : int) :
  0 <= l => 0 <= n => int2dig (l + 1) n = rcons (int2dig l (n %/ wd)) (n %% wd).
proof.
move=> ge0_l ge0_n; rewrite /int2dig mkseqS //= expr0 divz1.
congr; apply eq_in_mkseq => i rng_i /=.
have -> : l + 1 - 1 - i = (l - 1 - i) + 1 by ring.
rewrite exprS 1:/# divzMr 1:#smt:(gt0_wd) 1:#smt:(gt0_wd expr_ge0).
by congr.
qed.

lemma dig2int_rcons (ds : int list) (d : int) :
  dig2int (rcons ds d) = dig2int ds * wd + d.
proof.
elim: ds => /= [| x ds ih]; 1: by rewrite expr0 /#.
by rewrite ih size_rcons exprS 1:size_ge0 /#.
qed.

(* THE INVERSE.  Transcribed from WOTS_TW_Checksum.ec:85. *)
lemma int2digK (l n : int) :
  0 <= l => 0 <= n < wd ^ l => dig2int (int2dig l n) = n.
proof.
move=> ge0_l; elim: l ge0_l n.
+ by move=> n; rewrite int2dig0 expr0 /#.
move=> l ge0_l ih n [] ge0_n lt_n.
rewrite int2digS // dig2int_rcons ih; 2: smt(gt0_wd).
split; 1: smt(gt0_wd).
by move=> _; rewrite ltz_divLR 1:gt0_wd mulzC -exprS.
qed.

(* ==========================================================================
   THE BRIDGE.  Injectivity of the digit map on the range the digests occupy.
   This is the whole mathematical content of `B2_is_empty`.
   ========================================================================== *)
lemma int2dig_inj (l x y : int) :
     0 <= l
  => 0 <= x < wd ^ l
  => 0 <= y < wd ^ l
  => int2dig l x = int2dig l y
  => x = y.
proof.
move=> ge0_l rgx rgy heq.
by rewrite -(int2digK l x) // -(int2digK l y) // heq.
qed.

(* The bit-budget form actually used: digests are 8*n bits, so they live in
   [0, 2^(8n)).  Injectivity needs 2^(8n) <= wd^len.  NOTE the direction --
   this is where C10's 129 >= 128 does the work, and it is the ONLY thing the
   bridge needs.  It is INDEPENDENT of the constant-sum constraint. *)
lemma enc_inj_from_budget (nb l x y : int) :
     0 <= l
  => 2 ^ nb <= wd ^ l
  => 0 <= x < 2 ^ nb
  => 0 <= y < 2 ^ nb
  => int2dig l x = int2dig l y
  => x = y.
proof. by move=> ge0_l hbud rgx rgy; apply (int2dig_inj l) => /#. qed.

(* ==========================================================================
   C10 INSTANTIATION — does the bit budget actually hold at deployed numbers?

   C10: n = 16 bytes => digests are 8*16 = 128 bits; wd = 8; len = 43.
   Budget needed: 2^128 <= 8^43.  And 8^43 = 2^129.  So it holds, with ONE BIT
   to spare.  That single bit is the entire reason B2 can be emptied at C10.
   ========================================================================== *)
(* `8 = 2^3` was proved by `smt()` until 2026-07-28.  It is a TRIVIAL goal, but
   handing it to SMT made the proof NONDETERMINISTIC: under the load of a
   full-chain run it TIMED OUT (`FAIL leaf/Proj129 rc=1`) while passing 5/5 cold
   on an idle machine.  A flaky proof makes every receipt that contains it
   untrustworthy -- the run is then measuring machine load, not the proof.  It is
   now discharged deterministically, with NO SMT call, and shared so the three
   sites that needed it cannot drift apart. *)
lemma pow8 : 8 = 2 ^ 3.
proof. by rewrite (_ : 3 = 2 + 1) 1:// exprS 1:// (_ : 2 = 1 + 1) 1:// exprS 1:// expr1. qed.

lemma c10_pow : 8 ^ 43 = 2 ^ 129.
proof. by rewrite pow8 -exprM. qed.

lemma c10_budget : 2 ^ 128 <= 8 ^ 43.
proof. by rewrite c10_pow; apply ler_weexpn2l. qed.

(* The bridge AT C10, with the budget discharged rather than assumed.

   *** SUPERSEDED 2026-07-27 -- USE `Proj129.c10_enc_inj_129` INSTEAD. ***
   This lemma is TRUE but its range is WRONG for the deployment.  It quantifies
   over [0, 2^128); the deployed encoder consumes 129 bits, not 128
   (`sphincs-c10/src/wots.rs:35-46` extracts digit i from bits 3i..3i+2 for
   i in 0..42, so bits 0..128).  The "one bit to spare" narrative attached to
   this lemma was wrong: on the FULL deployed range [0, 2^129) the budget is
   exactly tight (8^43 = 2^129) and there is no slack at all.  Defect found in
   the 2026-07-27 adversarial review; the repair and the constant-sum
   determinacy result are in Proj129.ec. *)
lemma c10_enc_inj (x y : int) :
     wd = 8
  => 0 <= x < 2 ^ 128
  => 0 <= y < 2 ^ 128
  => int2dig 43 x = int2dig 43 y
  => x = y.
proof.
move=> hwd rgx rgy heq.
apply (enc_inj_from_budget 128 43) => //.
by rewrite hwd; exact c10_budget.
qed.
