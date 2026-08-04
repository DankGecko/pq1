(* ==========================================================================
   *** STATUS, FIRST LINE: this is the SEVENTH gated-not-wired leaf.  Nothing in
   *** `closure-c10.txt` requires it.  Six leaves with zero chain consumers is
   *** the pattern two reviews have now named.  Read everything below as
   *** arithmetic that LICENSES a modelling decision, not as chain progress.

   THE DIRECTIVE AND WHY ITS LITERAL FORM IS BLOCKED.

   Asked: "fix ThC to the 129-bit truncation".  The substance is right — the
   security-relevant object is the 129-bit window, since deployed signing
   DISCARDS the digest entirely (`sphincs-c10/src/wots.rs:119`:
   `let (count, _digest, digits) = find_count(...)`) and only the digits are
   used.  But the literal form is not expressible in MM45's type structure:

     * `dgstblock` is `bool list` constrained by `size x = 8 * n`
       (`FL_SL_XMSS_MT_ES.ec:130-137`).  Widths are multiples of 8.
     * `msgWOTS = dgstblock` (`WOTS_TW_ES.ec:213`) and
       `encode_msgWOTS : msgWOTS -> emsgWOTS` (`:563`) is applied to `ThC`'s
       output by the encode bridge.  So `ThC`'s output type MUST be `msgWOTS`.
     * 129 is not a multiple of 8 — mechanized below as `width_129_not_8n`.

   Retyping anyway means forking MM45 (531 `ThC` mentions across 35 cdrafts
   files, plus the `STCRC_WC` clone binding `out_t <- dgstblock`).

   WHAT ACTUALLY BLOCKS THE DECISION — and it is NOT the type system.

   There were two readings on the table:
     (A) `ThC = wots_digest` (256-bit)   -> digit map 2^127-to-1, the premise
         `EncMsgInjOnThCImage` is FALSE, `Composition.orphan_empty` unsound,
         composition four-way with an uncharged branch.  Model OPTIMISTIC.
     (B) `ThC = ` the low-128 projection -> orphan empty ON THE CONSTANT-SUM
         SURFACE via `Proj129.c10_low128_determines`.  Model faithful, and
         conservative on the S-TCR term (assuming TCR of a 128-bit-output
         function is STRONGER than needing a 129-bit match).

   (B) is the reading that preserves my own earlier work, so it deserves the
   hostile check, and it FAILS it:

     **(B) depends entirely on the surface restriction, i.e. on `predC`.  And
     `predC` carries NO AXIOM ANYWHERE IN THE CLOSURE** — the repo says so
     itself (`SphincsC10Content.ec:492`), and `target_sum` appears ZERO times in
     `WOTS_C_Scheme.ec`.  So `predC := fun _ => false` is a model, under which
     every surface statement is vacuous and (B) is unlicensed.

   Therefore: as the development stands, NEITHER reading is licensed, and the
   width question cannot be settled by choosing one.  The missing ingredient is
   the same in both cases — a `predC` actually tied to the digit sum.

   WHAT THIS FILE SUPPLIES: that tie, as a concrete candidate, with the
   degeneracy killed in BOTH directions.  It does not install the tie in the
   chain (that is a cdrafts/base-c10 edit and is not taken here).
   ========================================================================== *)
require import AllCore List IntDiv Ring StdOrder.
require import EncoderBridge Proj129.
import IntOrder.

(* ==========================================================================
   1.  WHY THE LITERAL DIRECTIVE IS BLOCKED, as a checked fact rather than prose.
   MM45 digest widths are 8*n.  129 is not one.
   ========================================================================== *)
lemma width_129_not_8n : ! (exists (k : int), 8 * k = 129).
proof. by apply/negP => -[k] h; smt(). qed.

(* The two admissible widths bracketing 129 are n = 16 -> 128 and n = 17 -> 136. *)
lemma bracketing_widths : 8 * 16 = 128 /\ 8 * 17 = 136.
proof. by []. qed.

(* NOT MECHANIZED, and flagged as such: widening to n = 17 does not rescue
   injectivity either, because 2^136 > 8^43 = 2^129 leaves 2^7 preimages per
   codeword.  `c10_pow43` (8^43 = 2^129) IS mechanized in Proj129; the step from
   there to `2^129 < 2^136` defeated `smt()` on concrete exponentiation and is
   not worth a hand-rolled `exprS` chain for a remark.  Treat this sentence as
   arithmetic commentary, not as a receipt. *)

(* ==========================================================================
   2.  THE MISSING TIE.  A CONCRETE predC candidate: the deployed gate.

   Deployed WOTS accepts on the digit sum ALONE -- `wots.rs:160`
   (`if sum != TARGET_SUM { return [0u8; N]; }`) and `SPHINCsC10Asm.sol:170`.
   There is no leading-zeros conjunct in WOTS (that is FORS+C's `predC_fors`).
   ========================================================================== *)
op predC_sum (d : int) : bool = dsum (int2dig 43 d) = 205.

(* ==========================================================================
   3.  NON-DEGENERACY, BOTH DIRECTIONS.

   The vacuity hazard is that `predC` is unconstrained, so BOTH `fun _ => false`
   (which zeroes the LHS of the bound and makes every surface claim vacuous) and
   `fun _ => true` (which erases the gate entirely) are models.  A candidate tie
   is only worth anything if it excludes BOTH.  Each is killed by an explicit
   witness.
   ========================================================================== *)

(* kills `fun _ => false` : the gate is SATISFIABLE *)
lemma predC_sum_inhabited :
  wd = 8 => exists (d : int), 0 <= d < 2 ^ 129 /\ predC_sum d.
proof.
move=> hwd; have [n [rgn hn]] := c10_target_sum_reachable hwd.
by exists n; rewrite /predC_sum.
qed.

(* kills `fun _ => true` : the gate actually REJECTS something.

   Rather than computing a digit sum, reuse the 4-jump that drives this whole
   experiment: `c10_step` says `dsum(2^128) = dsum(0) + 4`, so 0 and 2^128
   CANNOT BOTH pass a fixed-sum gate.  Whichever one fails is the witness. *)
lemma predC_sum_rejects :
  wd = 8 => exists (d : int), 0 <= d < 2 ^ 129 /\ ! predC_sum d.
proof.
move=> hwd.
have h128 : 0 < 2 ^ 128 by smt(expr_gt0).
have h129 : 2 ^ 129 = 2 * 2 ^ 128 by smt(exprS expr_gt0).
have hstep : dsum (int2dig 43 (2 ^ 128)) = dsum (int2dig 43 0) + 4.
+ by have := c10_step 0 hwd _; smt().
case: (predC_sum 0) => h0.
+ by exists (2 ^ 128); rewrite /predC_sum; move: h0; rewrite /predC_sum; smt().
by exists 0; rewrite /predC_sum; smt().
qed.

(* ==========================================================================
   4.  UNDER THE TIE, THE MODEL'S 128-BIT WIDTH IS FAITHFUL TO THE 129-BIT
   WINDOW.  This is `Proj129.c10_low128_determines` RE-SITED, not re-proved:
   its role is to license the model's digest width, which is what the width
   question was actually about.
   ========================================================================== *)
lemma low128_faithful_under_predC_sum (d d' : int) :
     wd = 8
  => 0 <= d  < 2 ^ 129
  => 0 <= d' < 2 ^ 129
  => predC_sum d
  => predC_sum d'
  => d %% 2 ^ 128 = d' %% 2 ^ 128
  => d = d'.
proof. by move=> hwd rg rg' h1 h2; apply c10_low128_determines. qed.

(* The orphan-emptiness ingredient, stated over the tie: on the gated set,
   equal codewords force equal 129-bit windows.  (Exact, not budgeted:
   8^43 = 2^129.) *)
lemma orphan_empty_ingredient_under_tie (d d' : int) :
     wd = 8
  => 0 <= d  < 2 ^ 129
  => 0 <= d' < 2 ^ 129
  => predC_sum d
  => predC_sum d'
  => int2dig 43 d = int2dig 43 d'
  => d = d'.
proof. by move=> hwd rg rg' _ _; apply c10_enc_inj_129. qed.

(* ==========================================================================
   THE LEDGER, precisely, because "SHA-256" is no longer accurate either way.

   * The function the S-TCR(+C) assumption must be about is
     `trunc_129 . wots_digest` -- NOT 256-bit SHA-256.  An adversary only ever
     needs to match the 129 bits the digit map consumes; the other 127 are
     discarded by the signer (`wots.rs:119`).  Assuming target-collision
     resistance of a narrower-output function is a STRICTLY STRONGER assumption
     than assuming it of SHA-256, and the ledger currently names the weaker one.
   * If instead the model's 128-bit `dgstblock` is kept as the index (reading B),
     that is CONSERVATIVE on this term -- a 128-bit match is easier than a
     129-bit match, so assuming the 128-bit function is TCR demands more.  But it
     is only licensed once `predC` is tied, per §3.

   WHAT IS NOT DONE.
   * The tie is NOT installed in the chain.  `predC` remains abstract and
     axiom-free in `WOTS_C_Real.ec:180`; nothing here changes that.  Installing
     it means either an axiom (`axiom predC_is_sum : predC = ...`) or defining
     `predC` concretely, and both are cdrafts edits with their own review.
   * No probability is bounded.  `Pr[G /\ COLL]` is untouched.
   * `WOTS_TW_ES.ec:1353` remains ADMITTED and propagates into
     `FL_SL_XMSS_MT_ES.ec:6342`.
   * C10 is NOT proven at deployed parameters.
   ========================================================================== *)
