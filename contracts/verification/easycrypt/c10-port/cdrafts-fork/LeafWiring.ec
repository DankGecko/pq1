(* ==========================================================================
   LeafWiring.ec — WIRING THE LEAVES IN, THE ONLY WAY THAT IS SOUND.

   THE REQUEST was "wire the leaves into the closure".  The seven files in
   experiments/tcollres-leg/ compile in `wire_test.sh` but NOTHING in
   `closure-c10.txt` requires them.  The obvious fix — a bridge file that assumes
   the chain's abstract `encode_msgWOTS` transcribes to the leaves' base-wd digit
   map, and then imports their conclusions — IS POISONED, and this file proves it
   rather than asserting it.

   WHY POISONED.  base-c10 carries `axiom two_encodings` (WOTS_TW_ES.ec:579) as a
   GLOBAL axiom: distinct codewords must be pointwise INCOMPARABLE.  The base-wd
   digit map is not: `int2dig len 0` is the all-zero codeword and is dominated by
   every other.  So "encode_msgWOTS = the digit map" CONTRADICTS an axiom already
   in the closure.  A bridge file assuming it would prove everything ex falso —
   its "derived" chain-typed results would be worthless AND would look exactly
   like success.

   WHAT THIS FILE IS.  A closure member that genuinely REQUIRES a leaf
   (`EncoderBridge`, for `int2dig` and `int2dig_inj`) and CONSUMES it — to prove
   that the naive wiring is impossible.  That is real wiring: the leaf is a
   dependency of a chain file and its lemmas do work here.  It is also the honest
   maximum: the transcription cannot be assumed, so the only thing that can be
   derived from it is a contradiction.

   WHAT IT IS NOT.  It does NOT make the capstone consume any leaf conclusion.
   It cannot — see above.  Wiring in the strong sense ("the bound depends on a
   leaf result") requires relativizing `two_encodings` to predC-satisfying
   digests, which needs a FORK of MM45: `FL_SL_XMSS_MT_ES.ec:6342` consumes
   `MEUFGCMA_WOTSTWESNPRF` through a reduction that queries the WOTS-TW oracle on
   SUBTREE ROOTS, which satisfy no predC, so a gated game cannot serve that
   consumer.

   AXIOM COST, stated because wiring a leaf in has one.  `require import
   EncoderBridge` brings `axiom gt1_wd : 1 < wd` into the closure's census.  It
   is about EncoderBridge's OWN fresh abstract `wd`, and is satisfiable
   (interpret `wd := 8`), so it CANNOT introduce inconsistency — but it does now
   appear in the census and must be reported there.

   ---------------------------------------------------------------------------
   UPDATE 2026-07-29 — THE FORK EXISTS, AND THIS FILE IS **OUT OF THE FORK
   CLOSURE**.  (base-c10 track unchanged: there the result is real.)

   Everything above was written against base-c10, where `two_encodings` is a
   GLOBAL axiom.  In base-c10-fork it is a LEMMA gated on the constant-sum
   surface (`P m => P m' => ...`), so the axiom this file warns about is GONE and
   the warning has NO ADDRESSEE here.

   MY FIRST ATTEMPT AT A REPAIR WAS VACUOUS, AND THIS IS THE RECORD OF IT.
   I added `P m0` / `P m1` premises and claimed the result "relativizes rather
   than disappearing".  FALSE.  Those premises are JOINTLY CONTRADICTORY, by
   digit-sum arithmetic that never touches the antichain:

       NaiveTranscription + toint m0 = 0  ->  all digits of enc m0 are 0
                                          ->  digitsum = 0  ->  target_sum = 0
       NaiveTranscription + toint m1 = 1  ->  last digit of enc m1 is 1
                                          ->  digitsum = 1  ->  target_sum = 1

   So the "repaired" lemma proved `false` from an empty hypothesis set: 0 admits,
   compiles green, certifies nothing.  Trap T3.  The discriminating control is
   scratch/LWVacuity.ec (rc=0), which derives the contradiction WITHOUT
   `two_encodings` -- so the antichain apparatus was dead weight.

   The banner I first wrote also asked the WRONG question ("does a second
   P-satisfying message exist", pointing at the ~2^123.759 surface).  Irrelevant:
   these two specific witnesses are excluded by arithmetic at any surface size.

   WHAT REMAINS BELOW is the honest residue: the contradiction stated as what it
   actually is -- a fact about the gate's arithmetic, not a warning about an
   encoder axiom -- plus `GatedTranscription`, still unproven and unassumed.
      ========================================================================== *)
require import AllCore List IntDiv Ring StdOrder StdBigop.
require import SPHINCS_PLUS.
require import EncoderBridge.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import EmsgWOTS.
import IntOrder.
import StdBigop.Bigint BIA.

(* The canonical codeword -> int list projection.  This part IS provable: it is
   just `BaseW.val` pushed through the Word's underlying list. *)
op cwlist (e : emsgWOTS) : int list = map BaseW.val (EmsgWOTS.val e).

lemma cwlist_nth (e : emsgWOTS) (i : int) :
  0 <= i < len => nth 0 (cwlist e) i = BaseW.val e.[i].
proof.
move=> rgi; rewrite /cwlist (nth_map witness).
+ by rewrite EmsgWOTS.valP.
by rewrite EmsgWOTS.getE rgi.
qed.

lemma cwlist_inj (e e' : emsgWOTS) : e = e' => cwlist e = cwlist e'.
proof. by move=> ->. qed.

(* ==========================================================================
   THE NAIVE TRANSCRIPTION — the hypothesis a bridge file would want.
   `toint` is any indexing of digests by integers (bs2int, say); the content is
   that the chain's encoder computes the base-wd digits of that index.
   ========================================================================== *)
op NaiveTranscription (toint : msgWOTS -> int) : bool =
  forall (m : msgWOTS), cwlist (encode_msgWOTS m) = int2dig len (toint m).

(* ==========================================================================
   RESULT, HONESTLY ATTRIBUTED.  On the fork's gated surface the naive
   transcription is contradictory -- but for a reason that has NOTHING to do with
   the antichain / `two_encodings`, which is why this file no longer belongs in
   the fork closure.

   The reason is pure digit-sum arithmetic: `toint m0 = 0` forces every digit of
   `enc m0` to 0, so `P m0` pins `target_sum = 0`; `toint m1 = 1` puts a 1 in the
   last digit, so `P m1` pins `target_sum = 1`.

   READ THE DIRECTION CAREFULLY.  This says those PREMISES cannot all hold.  It
   does NOT say anything about the chain's encoder, and it must NOT be cited as
   a refutation of a gated bridge -- see `GatedTranscription` below, which is
   still open.  `two_encodings` is deliberately not used in the proof.
   ========================================================================== *)
lemma naive_transcription_is_contradictory_on_the_gate
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
have gt1w : 1 < wd by exact gt1_wd.
(* both sit on the gate, so their digit sums agree *)
have hEq : digitsum (encode_msgWOTS m1) = digitsum (encode_msgWOTS m0).
+ by move: hP0 hP1; rewrite /P => -> ->.
(* toint m0 = 0 makes every digit of enc m0 zero *)
have hzero : digitsum (encode_msgWOTS m0) = 0.
+ rewrite /digitsum big1_seq // => i [_ /mem_range rgi] /=.
  by rewrite -cwlist_nth 1:rgi htr h0 /int2dig nth_mkseq //= div0z mod0z.
(* toint m1 = 1 puts a 1 in the last digit (most-significant-first) *)
have hone : BaseW.val (encode_msgWOTS m1).[len - 1] = 1.
+ have rgi : 0 <= len - 1 < len by smt().
  rewrite -cwlist_nth 1:rgi htr h1 /int2dig nth_mkseq //=.
  by rewrite expr0 divz1; smt(gt1_wd).
(* a sum of non-negative terms that is 0 cannot contain a 1 *)
have hmem : len - 1 \in range 0 len by rewrite mem_range; smt().
have hsplit := big_rem predT (fun (i : int) => BaseW.val (encode_msgWOTS m1).[i])
                 (range 0 len) (len - 1) hmem.
have hge0 : 0 <= big predT (fun (i : int) => BaseW.val (encode_msgWOTS m1).[i])
                    (rem (len - 1) (range 0 len)).
+ by apply sumr_ge0 => i _ /=; smt(BaseW.valP).
have : digitsum (encode_msgWOTS m1) = 0 by rewrite hEq hzero.
by rewrite /digitsum hsplit /= hone; smt().
qed.

(* ==========================================================================
   THE SOUND SHAPE, recorded but NOT assumed: relativize to the gate.

   `Identification.ec` established that the digit map's obstruction disappears on
   the constant-sum surface — there its image is an antichain (IncEnc's
   `tsw_incomparable`) and it is injective (`Proj129`).  So the transcription
   that is NOT poisoned is the predC-relativized one below.

   It is deliberately left as an `op`, unproven and unassumed: consuming it needs
   `two_encodings` itself relativized, which is the MM45 fork described in the
   header.  Stating it here makes the remaining gap a named object in a compiled
   closure file rather than a paragraph in a comment.
   ========================================================================== *)
op GatedTranscription (toint : msgWOTS -> int) (P : msgWOTS -> bool) : bool =
  forall (m : msgWOTS), P m => cwlist (encode_msgWOTS m) = int2dig len (toint m).
