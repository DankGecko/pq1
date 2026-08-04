(* ==========================================================================
   NEGATIVE CONTROL: is cdrafts-fork/LeafWiring.ec's repaired poisoning lemma
   VACUOUS?

   Claim under test (raised 2026-07-29): the premises I added to
   `naive_transcription_is_poisoned` --

       P m0 => P m1 => toint m0 = 0 => toint m1 = 1 => NaiveTranscription toint

   -- are JOINTLY CONTRADICTORY, so the lemma proves `false` from an empty
   hypothesis set and certifies nothing.  It would still compile green with
   0 admits (trap T3).

   THE DISCRIMINATOR.  If the premises really are contradictory by digit-sum
   arithmetic alone, then `false` is derivable WITHOUT `two_encodings` -- and the
   whole antichain apparatus in the current proof is dead weight.  That is what
   this file proves.  `two_encodings` is deliberately NEVER mentioned below.

   This file is a CONTROL, not a closure member.  It lives in scratch/ and is
   not on any wire path.
   ========================================================================== *)
require import AllCore List IntDiv Ring StdOrder StdBigop.
require import SPHINCS_PLUS.
require import EncoderBridge.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import EmsgWOTS.
import IntOrder.
import StdBigop.Bigint BIA.

(* -- verbatim from LeafWiring.ec (inlined so this control cannot race the wire
      test on LeafWiring.eco) -- *)
op cwlist (e : emsgWOTS) : int list = map BaseW.val (EmsgWOTS.val e).

lemma cwlist_nth (e : emsgWOTS) (i : int) :
  0 <= i < len => nth 0 (cwlist e) i = BaseW.val e.[i].
proof.
move=> rgi; rewrite /cwlist (nth_map witness).
+ by rewrite EmsgWOTS.valP.
by rewrite EmsgWOTS.getE rgi.
qed.

op NaiveTranscription (toint : msgWOTS -> int) : bool =
  forall (m : msgWOTS), cwlist (encode_msgWOTS m) = int2dig len (toint m).

(* ==========================================================================
   STEP 1.  Under the transcription, `toint m = 0` forces EVERY digit to 0,
   hence digitsum = 0.
   ========================================================================== *)
lemma digitsum_zero (toint : msgWOTS -> int) (m0 : msgWOTS) :
     toint m0 = 0
  => NaiveTranscription toint
  => digitsum (encode_msgWOTS m0) = 0.
proof.
move=> h0; rewrite /NaiveTranscription => htr.
rewrite /digitsum big1_seq // => i [_ /mem_range rgi] /=.
by rewrite -cwlist_nth 1:rgi htr h0 /int2dig nth_mkseq //= div0z mod0z.
qed.

(* ==========================================================================
   STEP 2.  Under the transcription, `toint m = 1` puts a 1 in the LAST digit
   (most-significant-first, so index len-1 carries wd^0).
   ========================================================================== *)
lemma last_digit_one (toint : msgWOTS -> int) (m1 : msgWOTS) :
     toint m1 = 1
  => NaiveTranscription toint
  => BaseW.val (encode_msgWOTS m1).[len - 1] = 1.
proof.
move=> h1; rewrite /NaiveTranscription => htr.
have gt1w : 1 < wd by exact gt1_wd.
have ge2len : 2 <= len by exact ge2_len.
have rgi : 0 <= len - 1 < len by smt().
rewrite -cwlist_nth 1:rgi htr h1 /int2dig nth_mkseq //=.
(* `//=` above already reduced `len - 1 - (len - 1)` to 0; goal is
   `1 %/ wd ^ 0 %% wd = 1`. *)
by rewrite expr0 divz1; smt(gt1_wd).
qed.

(* ==========================================================================
   STEP 3.  THE CONTRADICTION -- and note `two_encodings` is NOT used.

   digitsum is a sum of non-negative terms.  If it is 0, every term is 0, in
   particular the last one -- which step 2 says is 1.
   ========================================================================== *)
lemma leafwiring_premises_are_contradictory
  (toint : msgWOTS -> int) (m0 m1 : msgWOTS) :
     P m0
  => P m1
  => toint m0 = 0
  => toint m1 = 1
  => NaiveTranscription toint
  => false.
proof.
move=> hP0 hP1 h0 h1 htr.
have ge2len : 2 <= len by exact ge2_len.
(* both sit on the gate, so their digit sums agree *)
have hEq : digitsum (encode_msgWOTS m1) = digitsum (encode_msgWOTS m0).
+ by move: hP0 hP1; rewrite /P => -> ->.
have hz : digitsum (encode_msgWOTS m1) = 0.
+ by rewrite hEq (digitsum_zero toint m0).
(* peel the last term out of the sum *)
have hmem : len - 1 \in range 0 len by rewrite mem_range; smt().
have hsplit := big_rem predT (fun (i : int) => BaseW.val (encode_msgWOTS m1).[i])
                 (range 0 len) (len - 1) hmem.
have hge0 : 0 <= big predT (fun (i : int) => BaseW.val (encode_msgWOTS m1).[i])
                    (rem (len - 1) (range 0 len)).
+ by apply sumr_ge0 => i _ /=; smt(BaseW.valP).
move: hz; rewrite /digitsum hsplit /= (last_digit_one toint m1) //.
smt().
qed.
