(* ==========================================================================
   C10DeployedGeometry.ec — THE DEPLOYED-GEOMETRY RECEIPT.

   WHAT WAS ASKED FOR, AND WHAT THIS IS.
   The adversarial review of 2026-07-30 recommended a "deployed-instantiation
   corollary" pinning the real encoder, target 205, parameters, the 32-bit
   counter and serialization, replacing universal N2 with a grind-failure
   probability, and replacing `mkg_adv` / `mtree_*` with named advantages.

   THIS FILE DELIVERS A STRICT SUBSET, and says so up front:

     DONE   (1) ADMISSIBILITY of the deployed C10 parameter values against every
                constraint the model declares for them.
     DONE   (2) The WIDTH OBSTRUCTION that blocks pinning the encoder, stated as
                a CHECKED FACT against the model's own types instead of prose in
                an unwired leaf.
     NOT DONE  the encoder / target 205 / counter / serialization pinning, the
                N2 -> grind-failure-probability replacement, and the free-real
                replacement.

   (2) IS THE REASON (1) IS AS FAR AS IT GOES.  NARROWED 2026-07-30 (second
   review wave; the first narrowing missed this paragraph and the one at the
   `c10_codomain_exceeds_domain_model` lemma).  What is MECHANIZED here is a
   CARDINALITY GAP: at deployed geometry the codeword space (w^len = 2^129) is
   strictly larger than the message space (2^(8n) = 2^128).  The step from that
   to "the encoder cannot be pinned" is PROSE -- it needs the finite-type
   cardinality argument carried to `msgWOTS`/`emsgWOTS`, which is NOT done in
   this file, plus the faithfulness argument about the deployed 129-bit digit
   window.  Do not cite this file as a mechanized impossibility theorem.

   WHY THIS FILE REQUIRES THE MODEL, AND WHERE THE SURROGATE LINE FALLS.
   `experiments/tcollres-leg/Identification.ec` records the trap: everything there
   is proved about a type-DISCONNECTED surrogate (its own `wd`, its own `int list`
   codewords), so "EasyCrypt has verified NOTHING there about `encode_msgWOTS`",
   and the correspondences were hand transcriptions.

   SO BE PRECISE ABOUT THIS FILE (corrected during review of my own first draft,
   whose header claimed more than it delivered):
     * Section 1's `c10_admissible_*` and section 2's `c10_*_space` lemmas are
       PURE INTEGER ARITHMETIC about the `c10_*` ops defined below.  They are
       exactly the side conditions a clone at deployed values would have to
       discharge -- useful, but on their own they say nothing about the model.
     * The `*_model` lemmas at the end are the ONES THAT TIE: they are stated
       over the MODEL's own `n`, `w`, `len` under hypotheses fixing them to the
       deployed values, so EasyCrypt checks the connection rather than a reader.
   Cite the `_model` forms when the claim is about the model.
   ========================================================================== *)
require import AllCore List IntDiv Ring StdOrder.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme.
require import WOTS_C_Interactive.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
(* for the `emsgWOTS` codeword type + `digitsum`, used in section 5 *)
import EmsgWOTS.
import WOTS_C_Real.
import WOTS_C_Interactive.
import IntOrder.

(* ==========================================================================
   0.  THE DEPLOYED C10 GEOMETRY (docs/CLAUDE.md: h=18, d=2, a=11, k=13, w=8,
       n=16, len=43, target_sum=205, sig=4008 B).
   These are PLAIN INTEGERS.  They are not wired into the model -- they are the
   values the hypotheses below fix the model's parameters to.
   ========================================================================== *)
op c10_n        : int = 16.
op c10_log2_w   : int = 3.
op c10_w        : int = 8.
op c10_len      : int = 43.
op c10_target_sum : int = 205.

(* ==========================================================================
   1.  ADMISSIBILITY.  Every constraint the model DECLARES on these parameters
       is satisfied by the deployed values.

       This is the honest core of "pins the deployed parameters": it is an
       ADMISSIBILITY receipt, NOT an instantiation.  It does not clone the theory
       at these values; it checks that doing so could not fail on the parameter
       side.  Read the name literally.

       It has teeth: had C10's geometry violated any declared bound, the
       corresponding lemma below would be unprovable.  `val_log2w` is the one
       that historically DID bite -- MM45's original three-literal restriction
       made log2_w = 3 inexpressible, which is why WOTS_TW_ES.ec:31 records a
       deliberate relaxation to `2 <= log2_w`.
   ========================================================================== *)
lemma c10_admissible_n        : 1 <= c10_n.       proof. by rewrite /c10_n. qed.
lemma c10_admissible_log2w    : 2 <= c10_log2_w.  proof. by rewrite /c10_log2_w. qed.
lemma c10_admissible_len      : 2 <= c10_len.     proof. by rewrite /c10_len. qed.

(* `w` is DERIVED in the model (`const w = 2 ^ log2_w`), so the deployed pair
   must be mutually consistent -- an independent check, not a restatement. *)
(* `8 = 2 ^ 3`, proof shape reused verbatim from
   experiments/tcollres-leg/EncoderBridge.ec:120 (where it is already checked). *)
lemma c10_pow8 : 8 = 2 ^ 3.
proof. by rewrite (_ : 3 = 2 + 1) 1:// exprS 1:// (_ : 2 = 1 + 1) 1:// exprS 1:// expr1. qed.

lemma c10_w_consistent : c10_w = 2 ^ c10_log2_w.
proof. by rewrite /c10_w /c10_log2_w c10_pow8. qed.

(* The gate value is attainable as a digit sum at this geometry: 43 digits, each
   in [0,7], sum at most 301; 205 <= 301, and 205 >= 0.  So `target_sum = 205` is
   not out of range for the deployed codeword space.  (Attainability of exactly
   205 by the deployed encoder is a different claim and is NOT made here.) *)
lemma c10_target_sum_in_range :
  0 <= c10_target_sum <= c10_len * (c10_w - 1).
proof. by rewrite /c10_target_sum /c10_len /c10_w. qed.

(* ==========================================================================
   2.  THE WIDTH OBSTRUCTION — why the encoder cannot be pinned here.

   The model fixes, by construction:
     * `msgWOTS = dgstblock` and `dgstblock` is `bool list` with `size = 8 * n`
       (WOTS_TW_ES.ec:163, :213).  The encoder's DOMAIN has 2^(8*n) elements.
     * `emsgWOTS` is `Word` over `baseW = {0..w-1}` of length `len`
       (WOTS_TW_ES.ec:219).  The encoder's CODOMAIN has w^len elements.

   At the deployed geometry that is 2^128 vs 8^43 = 2^129: the codomain is
   STRICTLY LARGER than the domain, by exactly one bit.

   WHAT THIS DOES AND DOES NOT ESTABLISH (narrowed 2026-07-30 after review).
   The cardinality gap excludes COVERING the deployed codeword space from the
   model's message type; it does NOT by itself exclude defining `encode_msgWOTS`
   as some non-surjective map.  The stronger "cannot be pinned" reading rests on
   the FAITHFULNESS argument below, which is prose, not mechanized:

   Deployed C10 signing discards the digest and
   uses only the digits (`sphincs-c10/src/wots.rs:119`), so the security-relevant
   object is the 43-digit / 129-bit window.  A `dgstblock` cannot carry it: digest
   widths in this model are multiples of 8, and 129 is not one.  Widening does not
   help either -- n = 17 gives 136 bits, and 2^136 > 8^43 leaves 2^7 preimages per
   codeword.  (That last step is NOT mechanized here; it is flagged as unmechanized
   in experiments/tcollres-leg/ThCWidth.ec too, and nothing below leans on it.)

   Retyping anyway is a fork of MM45: ~531 `ThC` mentions across 35 files plus the
   `STCRC_WC` clone binding `out_t <- dgstblock`.

   [RETRACTED 2026-07-31.  The "RESOLVED ... it is the intermediate WIDTH"
    answer recorded here on 2026-07-30 was WRONG, and so was the banked
    reviewer's cardinality diagnosis it replaced.  Both are artifacts of the
    same thing.  See section 7 at the end of this file for the reconciled
    position, established by a two-model review wave (2026-07-31) whose
    load-bearing citations were re-verified at source.  Kept for the record.]
   OPEN QUESTION, BANKED 2026-07-30 (second review wave, NOT resolved here).
   One reviewer argues the cardinality gap is the WRONG diagnosis: since
   `encode_msgWOTS` is axiom-free and the deployed digit map is itself a
   NON-surjective map of exactly this type shape, a type-correct pinning exists
   set-theoretically, and "the genuine blocker is the `two_encodings`/antichain
   structure, not cardinality."  That is plausible and would relocate this file's
   central framing -- note the fork RELATIVIZED `two_encodings` to the
   constant-sum surface precisely so the digit map could live there, which cuts
   against cardinality being the obstruction at all.
   It is recorded rather than acted on because settling it means re-deriving what
   blocks the pinning, which is its own investigation.  Nothing ABOVE depends on
   the resolution: the mechanized content of this file is the cardinality gap and
   the admissibility receipt, both of which stand either way.

   STALE VERDICT CORRECTED.  ThCWidth.ec concluded that NEITHER width reading was
   licensed because "`predC` carries NO AXIOM ANYWHERE IN THE CLOSURE, so
   `predC := fun _ => false` is a model".  That disqualifier NO LONGER HOLDS:
   `cdrafts-fork/WOTS_C_Real.ec:239` now DEFINES `predC = P`, and `P_inhabited`
   rules out the all-false model.  The ingredient that file named as missing has
   since been supplied.  The width obstruction below is independent of it and
   survives regardless.
   ========================================================================== *)

(* 8^43 = 2^129, mechanized rather than asserted. *)
lemma c10_codeword_space : c10_w ^ c10_len = 2 ^ 129.
proof.
rewrite /c10_w /c10_len c10_pow8 -exprM.
by congr.
qed.

(* The digest space at the deployed width. *)
lemma c10_message_space : 2 ^ (8 * c10_n) = 2 ^ 128.
proof. by rewrite /c10_n. qed.

(* THE OBSTRUCTION, in one line: the codomain is strictly bigger. *)
lemma c10_codomain_exceeds_domain :
  2 ^ (8 * c10_n) < c10_w ^ c10_len.
proof.
rewrite c10_codeword_space c10_message_space.
have -> : 129 = 128 + 1 by ring.
rewrite exprS 1://.
smt(expr_gt0).
qed.

(* RENAMED AND RE-SCOPED 2026-07-30 (adversarial review, CONFIRMED against source).
   This lemma was called `c10_encoder_cannot_be_surjective`.  THAT NAME WAS A LIE
   ABOUT ITS OWN STATEMENT: the statement is a bare integer inequality -- it
   mentions neither `encode_msgWOTS`, nor surjectivity, nor the message/codeword
   types -- and its proof is `exact c10_codomain_exceeds_domain`, i.e. it was an
   alias.  A reader grepping for the name would have taken a cardinality fact for
   a theorem about the encoder.

   WHAT THE ARITHMETIC DOES EXCLUDE: any SURJECTION from the 2^128 messages onto
   all 2^129 codewords, since the codomain is strictly larger (and hence any
   bijection, a bijection being in particular a surjection).
   [Phrasing corrected 2026-07-30, second review wave: this read "any BIJECTION
   (equivalently, any surjection)".  Both classes are empty HERE, so the
   conclusion was unaffected, but surjection and bijection are NOT equivalent in
   general and the parenthetical asserted that they are.  In a file whose whole
   purpose is claim hygiene, loose phrasing is the defect.]
   WHAT IT DOES *NOT* EXCLUDE: defining `encode_msgWOTS` as some particular
   NON-surjective map -- including a restriction of the deployed digit map.  So
   it does not by itself prove "the encoder cannot be pinned"; it proves the
   deployed 43-digit codeword space cannot be covered from a 128-bit message
   type.  Making the impossibility claim precise would need the cardinality
   argument carried to the model's finite types, which is NOT done here. *)
lemma c10_codeword_space_not_covered :
  2 ^ (8 * c10_n) < c10_w ^ c10_len.
proof. exact c10_codomain_exceeds_domain. qed.

(* And the width fact that kills the retype-to-fit escape: 129 is not 8*k. *)
lemma c10_width_129_not_8n : ! (exists (k : int), 8 * k = 129).
proof. by apply/negP => -[k] h; smt(). qed.

(* ==========================================================================
   3.  THE TIE.  Everything above is arithmetic about `c10_*`; these are the
       statements over the MODEL's OWN parameters, so the correspondence is
       machine-checked instead of hand-transcribed.
   ========================================================================== *)

(* Deployed digest width, at the model's `n`. *)
lemma c10_digest_width_model : n = c10_n => 8 * n = 128.
proof. by move=> ->; rewrite /c10_n. qed.

(* Deployed codeword-space size, at the model's `w` and `len`. *)
lemma c10_codeword_space_model : w = c10_w => len = c10_len => w ^ len = 2 ^ 129.
proof. by move=> -> ->; exact c10_codeword_space. qed.

(* THE CARDINALITY GAP, over the model's own parameters: at deployed geometry the
   codeword space is strictly larger than the message space.

   WHAT FOLLOWS, AND ITS STATUS.  "`encode_msgWOTS` is therefore not surjective"
   is TRUE -- no map from a 2^128 set onto a 2^129 set is -- but it is NOT
   MECHANIZED HERE.  The lemma below is an inequality between two INTEGERS; it
   does not mention `encode_msgWOTS`, and nothing in this file establishes that
   `msgWOTS` and `emsgWOTS` have those cardinalities.  Bridging that needs the
   finite-type argument (DigestBlockFT / the EmsgWOTS Word clone), which is left
   undone.  Treat the non-surjectivity sentence as a PROSE CONSEQUENCE with a
   named gap, not as something the adjacent lemma proves. *)
lemma c10_codomain_exceeds_domain_model :
  n = c10_n => w = c10_w => len = c10_len => 2 ^ (8 * n) < w ^ len.
proof.
move=> hn hw hl; rewrite (c10_digest_width_model hn) (c10_codeword_space_model hw hl).
have -> : 129 = 128 + 1 by ring.
rewrite exprS 1://.
smt(expr_gt0).
qed.

(* ==========================================================================
   4.  TIE CHECK — proof that section 3 really is about the MODEL's parameters.

   A `_model` lemma that silently resolved `n` / `w` / `len` to something other
   than the model's constants would still COMPILE and would mean nothing.  That
   is the exact failure mode this file exists to avoid, so it is tested rather
   than asserted: each lemma below discharges a deployed bound BY APPLYING THE
   MODEL'S OWN DECLARED CONSTRAINT to the model's constant.  If `n` here were a
   local op, `ge1_n` would not apply to it and these would not typecheck.
   ========================================================================== *)
lemma c10_tie_n   : n = c10_n => 1 <= c10_n.
proof. by move=> <-; exact ge1_n. qed.

lemma c10_tie_len : len = c10_len => 2 <= c10_len.
proof. by move=> <-; exact ge2_len. qed.

(* `w` is DEFINED as `2 ^ log2_w` (WOTS_TW_ES.ec:37), so the model constrains it
   via the derived bound `val_w : 4 <= w` rather than an axiom.  Applying that to
   the model's `w` is the tie; 4 <= 8 holds at deployed geometry. *)
lemma c10_tie_w   : w = c10_w => 4 <= c10_w.
proof. by move=> <-; exact val_w. qed.

(* And the definitional consistency, over the model's own two constants. *)
lemma c10_tie_w_def : log2_w = c10_log2_w => w = c10_w.
proof. by move=> h; rewrite /w h /c10_log2_w /c10_w c10_pow8. qed.

(* ==========================================================================
   5.  SETTLING "ANTICHAIN vs CARDINALITY" (raised in review wave 2, banked
       above as an open question; RESOLVED here).

   THE CLAIM UNDER TEST: "the genuine blocker [to pinning `encode_msgWOTS` to
   the deployed digit map] is the `two_encodings`/antichain structure, not
   cardinality."

   ANSWER: IT DEPENDS ON THE TREE, and for THIS tree the claim is FALSE.

     base-c10          `axiom two_encodings` (WOTS_TW_ES.ec:579), UNRELATIVIZED
                       and quantified over all message pairs.  It constrains the
                       encoder directly, and identifying `encode_msgWOTS` with
                       the base-wd digit map CONTRADICTS it -- which is exactly
                       what cdrafts/LeafWiring.ec proves.  There, the antichain
                       IS the blocker.

     base-c10-fork     `lemma two_encodings` (WOTS_TW_ES.ec:665), whose entire
                       proof is `rewrite /P; apply constsum_antichain`.
                       `constsum_antichain` is a statement about arbitrary
                       CODEWORDS of equal digit sum -- it never mentions
                       `encode_msgWOTS`.  So in the fork the antichain constrains
                       the encoder NOT AT ALL, and cannot be what blocks pinning.

   Mechanized below rather than argued: the antichain property holds for an
   ARBITRARY encoder `E` on any constant-sum surface.  Since it holds for every
   E, no choice of E can violate it, so it rules out no candidate encoder.

   SO WHAT IS THE BLOCKER IN THE FORK?  Neither of the two candidates:
     * NOT the antichain -- see the lemma below.
     * NOT cardinality -- the gap forbids SURJECTIONS onto the 2^129 codeword
       space (section 2); it does not forbid DEFINING a non-surjective encoder,
       and the deployed digit map is exactly such a map.
   It is FAITHFULNESS of the composite.  Deployed signing derives the 43 digits
   from a 129-bit window (`wots.rs:119` discards the digest and keeps the
   digits), whereas the model's pipeline is `ThC : ... -> dgstblock` followed by
   `encode_msgWOTS`, and `dgstblock` carries 8*n bits.  By `c10_width_129_not_8n`
   no `n` makes 8*n = 129, so the model's composite cannot BE the deployed
   derivation for any encoder choice.  The obstruction is the intermediate WIDTH,
   not the encoder's structure and not the codomain's size.

   CONSEQUENCE FOR THIS FILE: section 2's framing was aimed one step off target.
   The cardinality gap is true and mechanized, but it is not the reason pinning
   fails; the width fact `c10_width_129_not_8n` is.  Both are stated; only the
   latter is load-bearing for the impossibility reading.
   ========================================================================== *)
lemma antichain_holds_for_any_encoder
  (E : msgWOTS -> emsgWOTS) (T : int) (m m' : msgWOTS) :
     digitsum (E m)  = T
  => digitsum (E m') = T
  => E m <> E m'
  => exists (i : int),
          0 <= i < len
       /\ BaseW.val (E m).[i] < BaseW.val (E m').[i].
proof. by move=> h1 h2 hne; apply constsum_antichain; [rewrite h1 h2 | exact hne]. qed.

(* ==========================================================================
   SECTION 6 -- THE FOUR dfC SEPARATIONS, AT THE DEPLOYED PARAMETER SET.

   WHAT THIS CLOSES.  SphincsC10Content.ec's residual (Q3) says PART G's model
   pins `thfc` at index `8*n + r`, so it is PARAMETER-CONDITIONAL: scheme-
   preserving only while `8*n + r` misses the four member indices, and that
   "is guaranteed by the capstone's separation premises, NOT by the model
   itself".  `MODEL_dfC_8np32_unsafe_at_n4` (8*4+32 = 8*4*2) shows the guard is
   genuinely not automatic.

   At C10's deployed n / len / k the guard becomes a THEOREM.  That is worth
   having precisely because the separations are the ONE family of capstone
   premises that does not touch `w` or the encoder -- so they are dischargeable
   at the deployed parameters even though, per the FAITHFULNESS FINDING at
   SphincsC10Content.ec:96-100, the WOTS LAYER is NOT instantiable there
   (n=16, log2_w=3, len=43).  Two premise families, two different verdicts; do
   not read this as instantiating C10.

   WHY IT IS STATED THIS WAY.  `MODEL_dfC_separations_at_port_params`
   (SphincsC10Content.ec:464) is BARE INTEGER ARITHMETIC -- `8*16+32 <> 8*16*35`
   -- which cannot discharge anything, the surrogate-disconnection failure
   recorded in experiments/tcollres-leg/Identification.ec.  The lemma below is
   instead HYPOTHETICAL ON THE MODEL'S OWN SYMBOLS (`n`, `len`, `k`,
   `emb_in`) and concludes about the REAL `dfC` (= `size (emb_in witness)`,
   WOTS_C_Interactive.ec:405), so it composes with the capstone.

   The width hypothesis is `size (emb_in witness) = 8*n + r`, which is exactly
   what the faithful serialisation delivers (`embg_size`,
   SphincsC10Content.ec:404).  `r` stays a parameter of the lemma: it is not a
   theory constant, and the counter width enters ONLY through this equation.
   ========================================================================== *)

(* Deployed FORS parameter, from sphincs-c10/src/params.rs:34 (K = 13).
   `k` itself is an abstract const (SPHINCS_PLUS.ec:30, only 1 <= k), so this is
   a DEFINITION and the tie below is a HYPOTHESIS -- same discipline as
   c10_tie_n / c10_tie_len / c10_tie_w above. *)
op c10_k : int = 13.

lemma c10_dfC_separations (r : int) :
     n   = c10_n
  => len = c10_len
  => k   = c10_k
  => size (emb_in witness) = 8 * n + r
     (* the four widths `8*n + r` must avoid, written as the gaps themselves so
        the side conditions are self-documenting rather than magic numbers *)
  => r <> 0
  => r <> 8 * c10_n * 2       - 8 * c10_n
  => r <> 8 * c10_n * c10_k   - 8 * c10_n
  => r <> 8 * c10_n * c10_len - 8 * c10_n
  =>    dfC <> 8 * n
     /\ dfC <> 8 * n * len
     /\ dfC <> 8 * n * 2
     /\ dfC <> 8 * n * k.
proof.
move=> hn hlen hk hsz h0 h1 h2 h3.
move: h1 h2 h3; rewrite /c10_n /c10_len /c10_k /= => h1 h2 h3.
rewrite /dfC hsz hn hlen hk /c10_n /c10_len /c10_k /=.
smt().
qed.

(* The deployed instance: the C10 grind counter is a u32
   (sphincs-c10/src/wots.rs:54-60, `find_count -> (u32, ...)`), so r = 32 and
   dfC = 8*16 + 32 = 160, which avoids {128, 5504, 256, 1664}. *)
lemma c10_dfC_separations_r32 :
     n   = c10_n
  => len = c10_len
  => k   = c10_k
  => size (emb_in witness) = 8 * n + 32
  =>    dfC <> 8 * n
     /\ dfC <> 8 * n * len
     /\ dfC <> 8 * n * 2
     /\ dfC <> 8 * n * k.
proof.
move=> hn hlen hk hsz.
by apply (c10_dfC_separations 32 hn hlen hk hsz);
   rewrite /c10_n /c10_len /c10_k.
qed.

(* ROBUSTNESS TO THE MODELLING CHOICE.  The implementation hashes the counter
   inside a 32-BYTE slot (`wots_digest`, sphincs-c10/src/hash.rs:357-363: a
   128-byte preimage whose last 32 bytes carry the u32 big-endian), so a reader
   could model the counter field as 256 bits rather than 32.  The separations
   hold either way -- 384 also avoids {128, 5504, 256, 1664} -- so the result
   does not depend on resolving that modelling question. *)
lemma c10_dfC_separations_r256 :
     n   = c10_n
  => len = c10_len
  => k   = c10_k
  => size (emb_in witness) = 8 * n + 256
  =>    dfC <> 8 * n
     /\ dfC <> 8 * n * len
     /\ dfC <> 8 * n * 2
     /\ dfC <> 8 * n * k.
proof.
move=> hn hlen hk hsz.
by apply (c10_dfC_separations 256 hn hlen hk hsz);
   rewrite /c10_n /c10_len /c10_k.
qed.

(* --------------------------------------------------------------------------
   THE OTHER CAPSTONE PREMISES — WHY THEY GET NO RECEIPT HERE.

   An adversarial review (2026-07-31) banked the residual that `hc`, `hencb` and
   the four `dfC <>` facts carry no satisfiability receipt in either capstone
   file (R4b covers only the two real-valued premises).  Per-family verdict:

   * THE FOUR dfC SEPARATIONS — DISCHARGED above at the deployed n / len / k,
     given the serialisation width.  This is the family that does not touch `w`
     or the encoder, which is exactly why it survives the WOTS-layer
     non-instantiability.

   * `hencb`  (encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc))
     — NOT RECEIPTABLE HERE, and deliberately not faked.  `encode_msgWOTS_C` is
     an abstract op (WOTS_C_Real.ec:337).  The available existential receipt,
     `exists E, forall .., E .. = encode_msgWOTS (ThC ..)`, is trivially true
     (take the composition) and says NOTHING about the actual op -- it is
     precisely the "weak witness" SphincsC10Content.ec's PART G header already
     criticises in PARTS D/E, and residual (Q1) records why a machine-checked
     `clone ... realize` is impossible at this seam: EasyCrypt cannot
     re-interpret an already-declared op from inside the theory.  Writing such a
     lemma would manufacture the appearance of a receipt without the substance.

   * `hc` (c <= p_tgts) — NOT A THEOREM AND NOT MEANT TO BE.  `p_tgts` is an
     abstract constant carrying only `0 <= p_tgts` (WOTS_C_Real.ec:300); `c` is
     the hypertree's WOTS-instance count (WOTS_C_Real.ec:41).  `c <= p_tgts` is a
     PARAMETER CHOICE -- the SM-DT-TCR game must be given at least as many
     targets as there are instances -- satisfiable by construction and not
     derivable from the closure.  Recording it as a premise is correct.

   So the residual is now: one family discharged, two families explained rather
   than receipted.  That is the honest resolution, not a full one.
   -------------------------------------------------------------------------- *)

(* ==========================================================================
   SECTION 7 -- RECONCILED POSITION ON "WHAT BLOCKS DEPLOYED C10" (2026-07-31).

   Established by a bounded two-model review wave (GPT-5.6, Kimi K3; mutually
   blind, read-only, frozen tree cdf64f10) after a discrepancy was noticed
   between this file's model and the Rust implementation.  Both legs returned
   OBSTRUCTION UNSOUND independently.  Every citation below was re-verified at
   source before being recorded.

   1.  THE IMPLEMENTATION HAS TWO WIDTHS; THIS MODEL HAS ONE.
       - chain elements are 16 bytes: `chain_hash(val: &[u8; N]) -> [u8; N]`,
         sphincs-c10/src/hash.rs:322-328, N = 16 (params.rs:19);
       - the WOTS MESSAGE DIGEST is 32 bytes: `wots_digest(..) -> [u8; 32]`,
         hash.rs:350-355, and `extract_digits(digest: &[u8; 32])` (wots.rs:16)
         consumes bit offsets 0..128 -- 129 bits -- since the last digit is at
         offset 42*3 = 126 (wots.rs:27-44).
       In this model `dgstblock` is ONE type of width 8*n (WOTS_TW_ES.ec:161-168)
       serving BOTH roles: chain elements (`f = thfc (8*n)`, :428) and, via
       `msgWOTS = dgstblock` (:213), ThC's output and `encode_msgWOTS`'s domain
       (WOTS_C_Real.ec:175; WOTS_TW_ES.ec:563).  n = 16 is faithful to the chains
       and unfaithful to the digest; n = 32 is the reverse.  NO SINGLE n WORKS.

   2.  BOTH PREVIOUSLY-RECORDED BLOCKERS ARE ARTIFACTS OF THAT TIE.
       (a) The cardinality gap `c10_codomain_exceeds_domain` (2^128 < 2^129,
           :163-181) is TRUE ARITHMETIC but is NOT an obstruction: it compares
           the codeword space against a 128-bit domain that the deployment does
           not use.  Under the faithful correspondence the encoder's domain is
           the 256-bit digest (2^256 > 2^129), or -- restricted to the window
           `extract_digits` actually reads -- exactly 2^129, where the deployed
           digit map is base-8 expansion, a BIJECTION onto the codeword space.
           Neither reading yields domain < codomain.
       (b) The relocation to `c10_width_129_not_8n` (:211-212), recorded here on
           2026-07-30 as "the intermediate WIDTH is the blocker", is WRONG for
           the same reason: 129 is not the deployed intermediate width.  256 is,
           and 256 = 8 * 32 IS a multiple of 8 -- see c10_width_256_is_8n_and_fits
           below.  The retype-to-fit escape that lemma claims to kill is open.

   3.  THE CONCLUSION SURVIVES, VIA A DIFFERENT DEFECT.  "Deployed C10 is not
       faithfully instantiable in this development AS TYPED" still holds -- but
       because of (1), the one-n-two-widths tie, not because of any counting
       argument.  Do not cite (2a) or (2b) as the reason.

   4.  WHAT A REPAIR WOULD BE, AND WHY IT IS NOT ATTEMPTED HERE.  Split the
       width: keep a chain-block type at 8*n (n = 16) and introduce a separate
       message-digest type at 8*n_m (n_m = 32), retyping ThC's output and
       `encode_msgWOTS`'s domain to the latter.  Known breakage: the `STCRC_WC`
       clone binding `out_t <- dgstblock` (already flagged at :135-136) and every
       site composing ThC's output into a `dgstblock` context (~531 `ThC`
       mentions across 35 files, :135).  Reviewers spot-checked consumers only;
       the blast radius is UNVERIFIED.  This is a fork of MM45's type structure,
       not an edit.

   5.  STALENESS FOUND IN A NEIGHBOURING FINDING.  SphincsC10Content.ec:96-100
       states this theory "CANNOT be instantiated at C10's deployed WOTS
       parameters".  That finding's stated mechanisms are NOT the width argument
       and two of them no longer hold in this fork: its F1 cites MM45's
       three-literal `log2_w` restriction, but both trees now read
       `2 <= log2_w` (WOTS_TW_ES.ec:34); its F2 cites `len2 > 0` forcing
       len > len1, but the fork DROPPED len1/len2 and made `len` primitive with
       `2 <= len` for C10's 43 (WOTS_TW_ES.ec:41-53).  Its F3 (the
       two_encodings/antichain count) is independent of the width question and
       stands or falls separately; the fork relativized `two_encodings`.
       Treat :96-100 as historical until re-derived.
   ========================================================================== *)

(* The mechanized half of 2(b): a width that IS a multiple of 8 and accommodates
   the 129 bits `extract_digits` reads.  This is the escape `c10_width_129_not_8n`
   claims to kill, and it is open -- which is why 129-not-8k cannot be the
   blocker.  (The deployed digest is exactly this width: 32 bytes.) *)
lemma c10_width_256_is_8n_and_fits :
  8 * 32 = 256 /\ 129 <= 256.
proof. by []. qed.

(* ==========================================================================
   SECTION 8 -- WHERE THE WIDTH SPLIT ACTUALLY FAILS (measured, 2026-07-31).

   Section 7 named the obstruction (one `n`, two widths) and estimated the
   repair as "retype ThC's output and encode_msgWOTS's domain; ~531 ThC mentions
   across 35 files; blast radius unverified".  That estimate was replaced by a
   MEASUREMENT, and the answer is sharper and worse than a count of sites.

   METHOD.  A throwaway probe: `base-c10-fork/*.ec` copied to a scratch tree with
   every proof body gutted to `admit.` via base-c10-fork/gut.py (compile drops
   from 574s to 2s, so only TYPE errors surface and iteration is cheap; module
   procedure bodies are NOT gutted, so scheme-level type mixing still shows).
   Then `type msgWOTS = dgstblock` was replaced by a fresh `mdgstblock` subtype
   at width `8*n_m`, `n_m` independent of `n`.  Reproduce with:
     for f in base-c10-fork/*.ec; do python3 base-c10-fork/gut.py "$f" DST/$(basename $f) 0 0; done
     cp base-c10-fork/*.eca DST/ && chmod 777 DST      # container writes .eco there
     <apply the split> && easycrypt compile -I DST DST/WOTS_TW_ES.ec

   RESULT 1 -- THE WOTS LAYER SURVIVES.  With the widths split,
   WOTS_TW_ES.ec typechecks (rc=0): declarations, clones and module bodies all
   accept a message type distinct from the chain-element type.  So the WOTS
   layer is NOT where the tie is enforced.

   RESULT 2 -- THE HYPERTREE MAKES IT STRUCTURALLY IMPOSSIBLE, not merely
   expensive.  FL_SL_XMSS_MT_ES.ec fails at the signing loop:

       var root : dgstblock;
       root <- m;                                   <-- msgFLSLXMSSMTTW vs dgstblock
       while (size sapl < d) {
         sigWOTS <@ WOTS_TW_ES.sign((.., root));
         root <- val_bt_trh ps .. (list2tree leaves);
       }

   Layer k's WOTS MESSAGE IS layer k-1's ROOT.  The message type must equal the
   node type because roots are recursively signed -- so `msgWOTS = dgstblock` is
   STRUCTURAL, not an abbreviation, and no amount of retyping widens `msgWOTS`
   while keeping this loop.  (`root_from_sigFLSLXMSSMTTW` has the same shape.)

   RESULT 3 -- SO THE MISMATCH IS NOT WHERE SECTION 7 PUT IT.  The deployment
   agrees with the model here: every hypertree layer signs a 16-byte node.  What
   differs is the ENCODER'S input -- ThC(node, count) at 32 bytes, not the node.
   And `encode_msgWOTS_C : pseed -> adrs -> msgWOTS -> cntr -> emsgWOTS`
   (WOTS_C_Real.ec:337) ALREADY has the faithful shape: node in, digits out, no
   128-bit intermediate mentioned.

   THE CONFLATION IS EXACTLY ONE PREMISE.  `hencb`,
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc),
   forces ThC's output to be a `msgWOTS` -- hence `dgstblock`, hence 8*n.  That
   single equation is the whole of the unfaithfulness.

   AND IT IS LOAD-BEARING, WHICH IS WHY THIS IS HARD.  `hencb` is precisely what
   lets the +C reduction hand ThC's output to the HONEST WOTS-TW oracle as a
   message (R_int_WOTSTW, WOTS_C_Interactive.ec).  Dropping it does not just lose
   a premise -- the reduction to MM45's WOTS-TW stops existing.  Faithfully, the
   deployment's WOTS+C reduces to a WOTS-TW instance whose MESSAGES are 256 bits
   while its CHAINS are 128; MM45's WOTS-TW cannot express that instance, because
   `f = thfc (8*n)` and `msgWOTS = dgstblock` fix both to the same `n`.

   STATUS: the repair is NOT a retype of ThC's output.  It is a WOTS-TW variant
   with independent message and chain widths, plus a +C-aware hypertree whose
   loop carries `ThC(root, c)` rather than `root`.  That is a new development,
   not an edit to this one.  NOT ATTEMPTED.  Nothing above section 8 depends on
   this; it records where the wall is so the next attempt starts at the wall.
   ========================================================================== *)

(* ==========================================================================
   SECTION 9 -- SCOPING THE WOTS-TW VARIANT (measured, 2026-07-31).

   Section 8 located the wall.  This measures what a repair would actually cost,
   and the headline is that ONE of the two feared costs is ZERO.

   RESULT A -- THE WOTS-TW LAYER IS FREE.  `base-c10-fork/WOTS_TW_ES.ec` copied
   verbatim (NO gutting, both original admits intact), with `type msgWOTS =
   dgstblock` replaced by a fresh `mdgstblock` subtype at width `8*n_m`, `n_m`
   INDEPENDENT of `n`:

       easycrypt compile -I <probe> <probe>/WOTS_TW_ES.ec    ->  rc=0, 137s

   The whole `Proof_M_EUF_GCMA_WOTS_TW_ES_NPRF` section, the gated
   `MEUFGCMA_WOTSTWESNPRF` theorem and every supporting lemma go through
   UNCHANGED with the message width decoupled from the chain width.  MM45's
   chain argument does not care that messages are wider, and neither does the
   encoding surface -- `encode_msgWOTS : msgWOTS -> emsgWOTS` simply takes a
   wider domain.  ZERO proof repair in the WOTS layer.

   (Prior expectation, recorded so the miss is visible: "does the chain argument
   care? probably not; does the encoding/two_encodings surface? probably yes."
   The second half was wrong.)

   RESULT B -- CORRECTION TO SECTION 8's PESSIMISM.  Section 8 concluded the
   repair is "a new development, not an edit", on the grounds that `hencb` is the
   conflation and is load-bearing.  That is too strong, and the reason is a
   TYPE-ROLE SWAP it did not consider.

   Today `ThC : pseed -> adrs -> msgWOTS -> cntr -> dgstblock` -- input and
   output BOTH 8*n.  Faithfully the input is a hypertree NODE (16 B) and the
   output is the WOTS digest (32 B), i.e.

       ThC : pseed -> adrs -> dgstblock -> cntr -> msgWOTS

   with `msgWOTS` the WIDE type.  Under that retyping `hencb`,
   `encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)`, REMAINS
   WELL-TYPED -- `ThC`'s output is exactly what `encode_msgWOTS` now consumes --
   and the +C reduction still hands `ThC`'s output to the honest WOTS-TW oracle,
   which by RESULT A now accepts wide messages.  So `hencb` need not be dropped
   and the reduction need not be rebuilt.  Section 8's "removes the reduction"
   holds only for DELETING hencb, not for retyping around it.

   The +C hypertree already has the faithful shape: `XMSSMT_C_Scheme.ec:117-129`
   passes `root : dgstblock` to `WOTS_C_ES.sign`, which grinds internally.  It is
   MM45's UNGATED hypertree (`FL_SL_XMSS_MT_ES.ec:1078`) that signs roots with
   WOTS-TW directly and therefore breaks.

   THE REMAINING OPEN QUESTION, now sharp enough to be worth one experiment:
   does the +C chain need the ungated FL_SL hypertree's SCHEME, or only its TREE
   MACHINERY (leaves_from_sspsad, cons_ap_trh, val_bt_trh, the trh/pkco
   surfaces)?  If the latter, the split is a bounded edit after all.  If the
   former, section 8's verdict stands.  NOT MEASURED -- and note this file has
   twice now recorded a confident answer to "what blocks C10" that a measurement
   overturned, so it is left open rather than guessed a third time.
   ========================================================================== *)

(* ==========================================================================
   SECTION 10 -- THE OPEN QUESTION OF SECTION 9, SETTLED (measured 2026-07-31).

   Q: does the +C chain need MM45's UNGATED FL_SL hypertree SCHEME, or only its
      TREE MACHINERY?
   A: TREE MACHINERY.  The split is a BOUNDED EDIT, not a new development.
      Section 8's verdict is withdrawn.

   EVIDENCE 1 -- THE CLOSURE NEVER USES THE UNGATED SCHEME.  Comment-stripped
   scan of all 19 closure files for code (not prose) references:

       FL_SL_XMSS_MT_ES (module)          0        cons_ap_trh          18
       FL_SL_XMSS_MT_ES_NPRF              0        val_bt_trh           49
       EUF_NAGCMA_FLSLXMSSMTTWESNPRF      0        val_ap_trh           10
       root_from_sigFLSLXMSSMTTW          0        leaves_from_sspsad    7
       skFLSLXMSSMTTW                     0        nr_nodes_ht          32
                                                   pkco                 47
       pkFLSLXMSSMTTW                    14        list2tree           101
         (a TYPE, FL_SL_XMSS_MT_ES.ec:611, not a scheme procedure)

   The +C chain runs on its own scheme (`FL_SL_XMSS_MT_C_ES`, 104 uses) and on
   the shared tree machinery.  It touches the ungated scheme zero times.

   EVIDENCE 2 -- ONLY THE UNGATED SIDE BREAKS, AND ITS PROOFS ARE NOT NEEDED.
   With the split applied, an iterative excise-and-recompile over the gutted
   FL_SL removed exactly six modules before it compiled, every one ungated-side:
   FL_SL_XMSS_MT_ES, FL_SL_XMSS_MT_ES_NPRF, EUF_NAGCMA_FLSLXMSSMTTWESNPRF,
   R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA, R_SMDTTCRCPKCO_EUFNAGCMA,
   R_SMDTTCRCTRH_EUFNAGCMA.  No tree-machinery item ever appeared.

   EVIDENCE 3 -- AND IT HOLDS AT THE PROOF LEVEL, NOT ONLY TYPES.  The weakness
   of Evidence 2 is that gutted probes only answer "do the statements typecheck".
   So the experiment was repeated with PROOFS INTACT:
       full FL_SL_XMSS_MT_ES.ec + width split + ungated side (6 modules and
       section Proof_EUF_NAGCMA_FL_SL_XMSS_MT_ES_NPRF) excised
       -> rc=0, 58s, 0 admits remaining
   Every tree-machinery lemma still proves with the message width decoupled.
   Combined with SECTION 9's result (full WOTS_TW_ES.ec, proofs intact, rc=0,
   137s), BOTH base layers are split-compatible at the proof level.

   NOTABLE SIDE-EFFECT.  The ungated side is where the fork's admitted
   `EUFNAGCMA_FLSLXMSSMTTWESNPRF` lives -- one of the closure's TWO cone admits
   (cert-baseline.tsv).  Excising it removes that admit, and with it the taint it
   propagates.  A split fork would have a strictly smaller assumption base here.
   It would also require a cert-baseline update, so it is a deliberate decision,
   not a free win.

   WHAT REMAINS UNMEASURED, and it is the next thing to do:
     (i)  the cdrafts chain under the split.  The designed retyping is
          `ThC : pseed -> adrs -> dgstblock -> cntr -> msgWOTS` (node in, wide
          digest out -- the role swap of section 9 (B)), with `WOTS_C_ES.sign`
          taking a node.  NOT compiled.
     (ii) whether to excise MM45's ungated side from the fork's base at all, or
          instead clone WOTS_TW_ES twice (narrow-message for the ungated twin,
          wide for +C).  Excision is simpler and is what was measured; cloning
          preserves MM45 content the fork inherited.
   Neither is blocked; both are ordinary work now that the wall turned out not
   to be one.
   ========================================================================== *)

(* ==========================================================================
   SECTION 11 -- CORRECTION TO SECTION 10, AND THE CDRAFTS-LAYER FINDING.

   (A) SECTION 10 OVERSTATED ITS SCAN.  It reported "the closure never uses the
   ungated scheme", measured over the 19 CDRAFTS closure files, and generalised
   that to "the closure".  The BASE cone was not scanned, and it does use it:

       base-c10-fork/SPHINCS_PLUS.ec -- 19 code refs, including
         FL_SL_XMSS_MT_ES.gen_root (:927)      FL_SL_XMSS_MT_ES.sign (:968)
         FL_SL_XMSS_MT_ES.root_from_sigFLSLXMSSMTTW (:1002)
         FL_SL_XMSS_MT_ES_NPRF.{sign,keygen,verify,leaves_from_sklpsad}
       base-c10-fork/FORS_ES.ec -- 0.

   Found by compiling, not by re-reading: excising the ungated hypertree made
   SPHINCS_PLUS.ec fail on `unknown procedure: FL_SL_XMSS_MT_ES.gen_root`.
   Section 10's PROOF-LEVEL results (WOTS_TW_ES rc=0; FL_SL rc=0 with the
   ungated side excised) STAND -- they were measured on those files.  What does
   not stand is the scope of the "never used" claim.

   The excision plausibly just extends one level: the ungated SPHINCS+ scheme
   module `SPHINCS_PLUS_S` has 0 code refs in the +C closure.  NOT asserted as
   settled -- that is the same partial-scan inference that produced this
   correction, and it has now misfired twice.

   (B) THE CDRAFTS LAYER HAS ITS OWN ONE-WIDTH TIE, one level down from the
   msgWOTS one, and it is the more interesting of the two:

       op thfc : int -> pseed -> adrs -> dgst -> dgstblock     (ONE codomain)
       op f    : ... = thfc (8 * n)                            (chains, 16 B)
       op ThC ps tw m c = thfc (size (emb_in (m,c))) ..        (so ThC : .. -> dgstblock)

   `ThC`'s output is `dgstblock` STRUCTURALLY, because the whole development
   shares ONE tweakable-hash collection with ONE codomain.  The deployment does
   not: `chain_hash -> [u8; N]` (16 B, hash.rs:322-328) and
   `wots_digest -> [u8; 32]` (32 B, hash.rs:350-355) are different functions with
   different output widths.  So the faithful model needs a SECOND hash family,
   e.g. `op thfc_m : int -> pseed -> adrs -> dgst -> mdgstblock`, with

       emb_in : dgstblock * cntr -> dgst
       ThC    : pseed -> adrs -> dgstblock -> cntr -> msgWOTS
       STCRC_WC binding  msg_t <- dgstblock,  out_t <- msgWOTS

   (C) AND THAT IS WHERE THE NEXT REAL QUESTION IS.  Moving ThC to its own hash
   family changes WHICH family the S-TCR(+C) assumption is about -- which is
   faithful (wots_digest really is not chain_hash) but interacts with the
   MEMBER-AWARE argument: `dfC` identifies ThC as the member of the SHARED
   `thfc` collection at input-length index `size (emb_in witness)`, and
   `member_sep_disj` / `member_aware_disj_discharged`
   (WOTS_C_Interactive.ec) turn that into the disjointness the +C reduction
   needs.  If ThC lives in a different collection, that argument must be
   restated over two collections.  UNVERIFIED -- and it is the first thing to
   measure next, because it decides whether the cdrafts layer is as free as the
   base layers turned out to be.

   STATUS: the cdrafts chain does NOT yet compile under the split.  The probe got
   as far as (A) before the base excision had to widen.  No claim is made here
   about the cdrafts layer's cost.
   ========================================================================== *)

(* ==========================================================================
   SECTION 12 -- TWO-COLLECTION PROBE: HOW FAR IT GOT (measured 2026-07-31).

   Question asked: does the MEMBER-AWARE argument survive when ThC moves to its
   own hash collection?  ANSWER: NOT REACHED.  What follows is what was
   established on the way, and exactly what stands between.

   PROBE.  base-c10-fork + cdrafts-fork copied verbatim (PROOFS INTACT
   throughout) to a private include path, with:
     - msgWOTS  := mdgstblock  (width 8*n_m, n_m independent of n)
     - a SECOND collection  op thfc_m : int -> pseed -> adrs -> dgst -> mdgstblock
     - emb_in   : dgstblock * cntr -> dgst          (node in)
     - ThC      : .. -> dgstblock -> cntr -> msgWOTS (wide digest out)
     - predC    : msgWOTS -> bool                    (the gate is on the DIGEST)
     - STCRC_WC binding  msg_t <- dgstblock,  out_t <- msgWOTS
     - msgFLXMSSMTTW := dgstblock                    (the hypertree signs NODES)
     - the ungated side excised where it blocks (see below)

   COMPILES, PROOFS INTACT:
       WOTS_TW_ES        rc=0        FL_SL_XMSS_MT_ES  rc=0 (ungated excised)
       SPHINCS_PLUS      rc=0 (ungated excised)
       Grind             rc=0        STCR_C            rc=0
       WOTS_C_Real       rc=0   <-- ThC, predC, STCRC_WC clone,
                                    wotsc_grind_targets_predC
       WOTS_C_Scheme     rc=0   <-- the +C scheme (12 sites: it signs NODES)
       XMSSMT_C_Scheme   rc=0   <-- the +C hypertree

   BASE EXCISIONS NEEDED: 13, EVERY ONE UNGATED-SIDE.  FL_SL's 6 modules + its
   ungated proof section; SPHINCS_PLUS's `SPHINCS_PLUS`, R_SKGPRF_EUFCMA,
   R_MKGPRF_EUFCMA, R_MFORSTWESNPRFEUFCMA_EUFCMA,
   R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA + its ungated proof section.  (This is
   the widened excision section 11 predicted but declined to assert; it is now
   measured, at the proof level.)

   NOT ONE PROOF FAILED.  Every error encountered across the whole probe was a
   TYPE ANNOTATION -- a msgWOTS that should be dgstblock or vice versa.  No
   tactic broke, no lemma became unprovable.  That is the substantive signal so
   far, and it is why the remaining question is worth finishing rather than
   abandoning.

   WHERE IT STOPPED, AND WHY THAT IS THE INTERESTING PLACE.
   `WOTS_C_Reduction.ec` is the +C <-> WOTS-TW BRIDGE: 28 `msgWOTS` sites, and it
   references WOTS_TW_ES directly.  Unlike the +C-only files it legitimately
   carries BOTH widths -- the +C side signs nodes, the WOTS-TW side signs ThC's
   wide output -- so a blanket rename is WRONG there and each site needs its
   role decided.  That file sits between the probe and `WOTS_C_Interactive.ec`,
   where member_sep_disj / members_in_thfc_set_neq_dfC /
   member_aware_disj_discharged live.

   SO THE MEMBER-AWARE QUESTION IS STILL OPEN.  The prior worth stating (and
   distrusting): with ThC in its own collection, a `thfc` query cannot collide
   with a `thfc_m` challenge, so the disjointness the repair was built to rescue
   might become FREE and the member-aware machinery redundant.  That is a
   comfortable story of exactly the kind this file has recorded and retracted
   five times.  It is NOT asserted.  The measurement is: decide the 28 bridge
   sites, then compile WOTS_C_Interactive and read what happens to those three
   lemmas.
   ========================================================================== *)

(* ==========================================================================
   SECTION 13 -- THE MEMBER-AWARE ARGUMENT UNDER TWO COLLECTIONS: ANSWERED.

   ANSWER: the member-aware machinery is not BROKEN by two collections -- it is
   made MOOT, at the price of RE-FOUNDING the S-TCR(+C) assumption over the
   second collection.  That price is where the work is; the machinery itself is
   collateral.

   HOW FAR THE PROBE GOT (all with PROOFS INTACT):
     WOTS_C_Reduction  rc=0  -- the +C <-> WOTS-TW bridge, 28 sites decided:
                               24 to `dgstblock` (A's +C messages are NODES) and
                               4 blocks to `msgWOTS` (the WOTS-TW-side game, the
                               bridge's `choose` return, its `y`/`d` collection
                               results, and its `forge` return -- all ThC OUTPUTS).
                               The split makes that dual role EXPLICIT IN THE
                               TYPES, where the single-`n` model hid it.
     WOTS_C_Interactive      -- 107 sites renamed; `ThC_member` and
                               `ThC_same_member` restated over `thfc_m` (both
                               typecheck: ThC IS thfc_m by definition).  Then the
                               FIRST genuine proof failure of the entire probe.

   THE FAILURE, AND IT IS THE ANSWER.  `S_TCR_C_Int_win_2ndpreimage` concludes

       thfc dfC pp (emb_tw tw) (emb_in (m, j))
     = thfc dfC pp (emb_tw tw) (emb_in (m', ctr))

   -- a collision IN THE `thfc` COLLECTION at member `dfC`, which is exactly what
   makes the S_TCR_C_Int term "EXACTLY SMDTTCRC.SM_DT_TCR_C's winning collision
   for the member f := thfc dfC" (the file says so at :443-447).  With ThC in
   `thfc_m`, the collision lives in the OTHER collection and
   `rewrite -(ThC_same_member ..)` reports `nothing to rewrite`.

   SO THE COST IS NOT THE MEMBER-AWARE LEMMAS.  It is that the S-TCR(+C)
   assumption -- its collection clone, its `SM_DT_TCR_C` instance, its oracle,
   and `dfC` itself -- is founded on `thfc`.  Moving ThC to `thfc_m` means
   re-founding all of it over the second collection.  `member_sep_disj`,
   `members_in_thfc_set_neq_dfC` and `member_aware_disj_discharged` are
   downstream of that, not the obstacle.

   THE PRIOR, ADJUDICATED.  Section 12 recorded: "with ThC in its own collection
   a thfc query cannot collide with a thfc_m challenge, so the disjointness the
   member-aware repair rescues might be FREE and the machinery redundant."
   DIRECTIONALLY RIGHT, INCOMPLETE.  Free disjointness is plausible -- pkco/trh
   queries live in `thfc` and simply cannot meet a `thfc_m` challenge, which is
   the very coincidence the repair was built for -- but that payoff sits BEHIND
   the re-founding, not instead of it.  NOT verified: no probe has yet
   constructed the second clone, so "the machinery becomes redundant" remains
   unproven.  It is recorded as the next measurement, not as a result.

   SCORECARD FOR THE WHOLE SPLIT, proof-level, probe with proofs intact:
     base   WOTS_TW_ES, FL_SL_XMSS_MT_ES, SPHINCS_PLUS        rc=0
            (13 excisions, every one ungated-side)
     +C     Grind, STCR_C, WOTS_C_Real, WOTS_C_Scheme,
            XMSSMT_C_Scheme, WOTS_C_Reduction                 rc=0
     stop   WOTS_C_Interactive -- at the S-TCR(+C) collection foundation.
   Across ~150 edits the ONLY non-type-annotation failure is that one, and it is
   a genuine design question rather than a defect.
   ========================================================================== *)

(* ==========================================================================
   SECTION 14 -- SECOND COLLECTION BUILT; THE DISJOINTNESS QUESTION ANSWERED,
   AND THE ANSWER IS NOT THE COMFORTABLE ONE.

   BUILT AND COMPILING (probe, proofs intact):
     op f_m : pseed -> adrs -> dgst -> mdgstblock = thfc_m (8 * n_m).
     clone TweakableHashFunctions as F_M   (out_t <- mdgstblock, f <- f_m)
     clone F_M.Collection        as FC_M   (get_diff <- size, fc <- thfc_m,
                                            in_collection by exists (8*n_m))
   WOTS_TW_ES rc=0 with both collections side by side.  Not `import`ed, so FC's
   names stay unambiguous.

   FREE, AS PREDICTED: `STCRC_WC.Col` needed NO change.  `STCRC` clones its own
   collection from its `out_t` (STCR_C.ec:96), and `out_t` is already `msgWOTS`
   under the split -- so the S-TCR(+C) game's collection oracle self-adjusts to
   the wide family.  Restating `ThC_member`, `ThC_same_member`,
   `S_TCR_C_Int_win_2ndpreimage` and `S_TCR_C_Int_win_implies_SMDTTCRC` over
   `thfc_m` is mechanical and compiles.

   THE WALL, AT WOTS_C_Interactive.ec:1744.  `R_int_WOTSTW` -- the +C -> WOTS-TW
   reduction -- has signature

       module (R_int_WOTSTW (A : Adv_MEUFGCMA_WOTSC) : Adv_MEUFGCMA_WOTSTWESNPRF)
              (O : Oracle_MEUFGCMA_WOTSTWESNPRF, OC : FC.Oracle_THFC)

   and it COMPUTES ThC THROUGH `OC` -- the grind loop `y <@ OC.query(emb_tw ad,
   emb_in (m, seed)); if (predC y) ...` then `d <@ OC.query(emb_tw ad,
   emb_in (m, c))` (:1739-1747).  `OC` is the NARROW collection oracle, because
   that is what MM45's `Adv_MEUFGCMA_WOTSTWESNPRF` supplies.  With ThC in
   `thfc_m`, those queries must go to an `FC_M.Oracle_THFC` THAT THE WOTS-TW GAME
   DOES NOT PROVIDE.

   SO THE TRADE IS NOT "machinery for nothing".  It is:
     GAIN  the member-aware repair becomes unnecessary -- a `thfc` query cannot
           collide with a `thfc_m` challenge, so the pkco-at-`emb_tw ad`
           coincidence that forced the repair cannot arise.  Disjointness IS
           free, exactly as section 12 guessed.
     COST  the +C reduction stops being an `Adv_MEUFGCMA_WOTSTWESNPRF`.  It would
           need `(O, OC : FC.Oracle_THFC, OC_M : FC_M.Oracle_THFC)`, i.e. an
           ADVERSARY-INTERFACE CHANGE to MM45's WOTS-TW game.

   AND THAT EXPLAINS THE CONFLATION.  Sharing one collection is what lets the +C
   reduction be an honest WOTS-TW adversary using ONLY the oracles that game
   offers.  The single-`n` tie is not sloppiness; it is load-bearing for the
   reduction's TYPE.  The member-aware repair is the price MM45's interface
   charges for keeping ThC inside the shared collection.

   HONEST SCOPE: the GAIN half is an argument from the two families being
   distinct, not a compiled proof -- no probe has yet built the two-oracle
   reduction and re-derived disjointness inside it.  The COST half IS compiled:
   the signature at :1715-1716 and the failure at :1744 are mechanical facts.
   Anyone continuing should treat "disjointness free" as very likely and
   "interface change required" as established.
   ========================================================================== *)

(* ==========================================================================
   SECTION 15 -- THE TWO-ORACLE REDUCTION, BUILT; DISJOINTNESS VERIFIED.

   BUILT AND COMPILING (probe, proofs intact, WOTS_TW_ES rc=0):

     module type Adv_MEUFGCMA_WOTSTWESNPRF_2(O, OC : Oracle_THFC,
                                             OC_M : FC_M.Oracle_THFC)
     module M_EUF_GCMA_WOTSTWESNPRF_2(A, O, OC, OC_M)

   The game body is COPIED VERBATIM from M_EUF_GCMA_WOTSTWESNPRF with two
   changes: `OC_M.init(ps)` alongside `OC.init(ps)`, and `A(O, OC, OC_M)`.  The
   WIN CONDITION IS UNCHANGED -- `adlOC` still comes from `OC` alone, so the wide
   oracle is a pure evaluation facility contributing no tweaks to the
   disjointness check.

   And the reduction, `R_int_WOTSTW` retyped to
     (O : Oracle_MEUFGCMA_WOTSTWESNPRF, OC : FC.Oracle_THFC,
      OC_M : FC_M.Oracle_THFC) : Adv_MEUFGCMA_WOTSTWESNPRF_2
   with ThC's grind loop and digest query moved from `OC` to `OC_M`.

   DISJOINTNESS -- VERIFIED, AND IT IS FREE.  Enumerating every collection-oracle
   call inside the reduction:

       OC_M  <-  emb_tw ad, emb_in (m, seed)      (the grind loop)
       OC_M  <-  emb_tw ad, emb_in (m, c)         (the digest)
       OC    <-  (none)

     emb_tw reaches the NARROW oracle : FALSE
     emb_tw reaches the WIDE oracle   : TRUE

   So `emb_tw ad` CANNOT ENTER the narrow transcript `adlOC`.  The member-aware
   repair exists precisely because a pkco query at `emb_tw ad` coincides with
   ThC's target tweak (WOTS_C_Interactive.ec's member-aware note); with two
   collections that coincidence is STRUCTURALLY UNREACHABLE, not merely
   improbable.  Section 12's prediction is confirmed.

   SCOPE OF "VERIFIED": this is a structural fact about the reduction module --
   the narrow oracle is never called with an `emb_tw` tweak -- established by
   enumerating its calls, not by a compiled pRHL proof of the disjointness
   invariant.  It is the strongest available statement short of the full
   downstream cascade, and it makes the invariant's PREMISE unreachable rather
   than merely discharging it.

   THE COST, NOW COUNTED.  Changing the adversary type propagates: 7
   instantiations of `R_int_WOTSTW(A, O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default)`
   in WOTS_C_Interactive alone need the third oracle, and every downstream
   consumer (interactive_hop2, interactive_D1, interactive_D1_MA, XmssmtCC_All's
   seven, the capstones) follows.  ALSO OUTSTANDING and larger: relating
   `M_EUF_GCMA_WOTSTWESNPRF_2` back to MM45's one-oracle game -- an adversary
   with an oracle for an INDEPENDENT hash family at the hidden `pp` is not
   obviously no stronger, and that is a cryptographic step, not a retyping.
   NEITHER attempted.

   NET: the member-aware machinery can be retired, and the price is an interface
   change plus that one game-relation obligation.  Whether that trade is worth
   making is a design decision, not a measurement.
   ========================================================================== *)

(* ==========================================================================
   SECTION 16 -- CORRECTION TO SECTION 15, FOUND BY ATTACKING MY OWN CLAIM.

   Section 15 said: "emb_tw ad CANNOT ENTER the narrow transcript adlOC ... the
   coincidence is STRUCTURALLY UNREACHABLE".  THAT IS FALSE, and the refutation
   is one line of the reduction:

       module AA = A(O_wrap, OC)          (WOTS_C_Interactive.ec, R_int_WOTSTW)

   The wrapped adversary `A` is handed the NARROW collection oracle DIRECTLY.
   `A` is adversarial.  Nothing prevents it from calling `OC.query(emb_tw ad, ..)`
   itself.  So `emb_tw ad` CAN appear in `adlOC`; what the two-collection split
   removes is only that the REDUCTION ITSELF is forced to put it there on every
   signing query.

   WHAT SURVIVES, STATED PRECISELY:
     BEFORE  the reduction NECESSARILY recorded `emb_tw ad` in the narrow
             transcript on every query, so the coincidence was GUARANTEED and
             the member-aware repair was MANDATORY.
     AFTER   the reduction records nothing there; the coincidence becomes
             ADVERSARY-CHOSEN rather than structural.
   That is a real weakening of the obligation but NOT its elimination.

   AND THE OPEN PART, which section 15 skated: `FC.disj_lists` compares TWEAKS
   (adrs), not (family, tweak) pairs.  So an adversarial `A` querying the narrow
   oracle at `emb_tw ad` still collides with the tweak-only condition as written,
   even though its query is in a DIFFERENT hash family from the challenge.
   Making the two-collection setting actually pay off therefore needs the
   condition to become FAMILY-AWARE -- which is the same shape of repair as the
   member-aware one, one level up.  Whether that is cheaper than what it
   replaces is NOT established here.

   SO SECTION 15's CONCLUSION ("the member-aware machinery can be retired") IS
   WITHDRAWN pending that question.  Its other content stands: the two-oracle
   game and reduction are built and compile, the win condition is unchanged, and
   the interface cost (7 instantiations + downstream + the game-relation
   obligation) is counted.

   METHOD NOTE, because it is the point: this was found by asking "could emb_tw
   reach OC by ANOTHER route?" and enumerating what `A` is instantiated with --
   the same question put to the reviewers as check 2.  Enumerating the
   REDUCTION's own calls (section 15's evidence) was necessary and not
   sufficient: it answered "does the reduction do it" and I read it as "can it
   happen".
   ========================================================================== *)

(* ==========================================================================
   SECTION 17 -- REVIEW WAVE ON THE TWO-ORACLE WORK: VERDICT FLAWED.
   Section 15's payoff is WITHDRAWN, and section 16's correction was itself
   too gentle.

   GPT-5.6 leg (read-only, frozen 5cce118/4e02cf2, probe manifested) returned
   FLAWED.  Every load-bearing citation below re-verified at source.

   F1 (CRITICAL) -- and it is stronger than section 16 admitted.  Section 16
   said the coincidence becomes "ADVERSARY-CHOSEN rather than structural".  In
   fact THE CONCRETE CALLER DOES IT UNCONDITIONALLY.  The hypertree leaf
   reduction signs through the +C oracle and then compresses the returned public
   key with a pkco query through the NARROW collection oracle at the SAME
   address (XMSSMT_C_Reduction.ec:524-530).  `emb_tw` sets index-3 to `pkcotype`
   while preserving kp/tree/layer, so that pkco tweak IS `emb_tw ad` -- and this
   repository already says so:

       "the leaf reduction's pkco tweak coincides with a ThC target tweak, but
        sits at a DIFFERENT member, so the member-tagged transcript stays
        dfC-free."                        (XMSSMT_C_Reduction.ec:680-684)

   So what rescues the situation is MEMBER SEPARATION -- exactly the machinery
   section 15 proposed to retire.  Under two collections that becomes FAMILY
   separation: the same argument, renamed.  THE PAYOFF LARGELY EVAPORATES.

   F2 (HIGH) -- "one game-relation obligation" is WRONG; there are at least two.
     (a) Relating the two-oracle game to MM45's needs an ASSUMPTION, not a
         proof: `thfc` and `thfc_m` are separate UNINTERPRETED ops
         (WOTS_TW_ES.ec:435-438), i.e. distinct SYMBOLS -- not probabilistically
         independent.  `thfc_m(pp,..)` may correlate with the hidden `pp`.
         Closing it needs either an auxiliary-oracle WOTS assumption or a joint
         domain-separation / independent-RF simulation.
     (b) `R_int_STCRC` still needs the NARROW `FC` for chain evaluation
         (WOTS_C_Interactive.ec:553-603) while S-TCR now uses the WIDE
         collection -- a second auxiliary-oracle obligation, and its bridge is
         already explicitly deferred (:487-494).

   F3 (MEDIUM) -- "cost counted" was 7 TEXTUAL OCCURRENCES of one instantiation
   pattern plus an unattempted downstream list.  That is not a dependency
   census, and section 15 presented it as one.  "Verified", "free", "confirmed",
   "structurally unreachable" all outran their evidence; the scope disclaimer at
   the end of section 15 does not cure a bad enumeration, because the
   enumeration itself was the wrong question (the reduction's calls, not the
   reachable calls).

   WHAT SURVIVED REVIEW (INFO-level, confirmed):
     - the two-oracle game is faithful: only the third parameter, the `choose`
       effect, `A(O,OC,OC_M)` and `OC_M.init(ps)` differ; win condition
       unchanged and `adlOC` still from `OC` alone;
     - `F_M`/`FC_M` are well-formed, `in_collection` witnessed at `8*n_m`,
       no import ambiguity -- but this establishes DISTINCT SYMBOLS, not
       cryptographic independence;
     - the retyping's role flow is semantically right (node in / digest out,
       predC on the digest, +C and hypertree sign nodes, bridge returns digests);
     - the 13 excisions are genuinely ungated-side with no +C dependency found,
       though the admitted theorem is DELETED, not discharged.

   NET POSITION ON THE WIDTH SPLIT, honestly: the base layers are free
   (section 9/10, proof-level), the +C retyping is mechanical (section 12), and
   the two-oracle construction is buildable -- but it does NOT retire the
   member-aware machinery, and it ADDS two auxiliary-oracle assumptions.  On
   present evidence the split's cost/benefit is WORSE than section 15 claimed
   and the honest recommendation is: do not adopt it to remove member-awareness,
   because it does not.
   ========================================================================== *)

(* ==========================================================================
   SECTION 18 -- RECONCILIATION OF THE TWO LEGS.  SECTION 17 OVER-CORRECTED.

   Both legs returned FLAWED and CONVERGED on the defect (section 15's
   enumeration missed `module AA = A(O_wrap, OC)`).  They DIVERGED on the
   consequence, and that divergence is where the information was.  Reproduced at
   source rather than voted on:

     GPT-5.6: the concrete leaf reduction puts `emb_tw ad` into the narrow
              transcript, member separation rescues it, so the payoff evaporates.
     Kimi K3: that narrow-transcript traffic was ALWAYS there and is HARMLESS;
              the repair's actual problem was the S-TCR side, which IS clean.

   KIMI IS RIGHT, AND SECTION 17 IS WITHDRAWN.  Two facts settle it:

     (i)  `R_int_STCRC (A) (O : STCRC_WC.Oracle_STCRC, OC : FC.Oracle_THFC)`
          with `module AA = A(O_wrap, OC)` (WOTS_C_Interactive.ec:553-554,615)
          -- A is handed the +C signing wrapper and the NARROW oracle ONLY.
          A NEVER HOLDS A WIDE-COLLECTION ORACLE.
     (ii) `STCRC_WC.Col` is cloned with
          `op fc <- fun _ pp tw x => ThC pp tw x.`1 x.`2` (STCR_C.ec:96-103),
          so the S-TCR transcript is over ThC -- the WIDE family under the split.

   Hence the wide transcript contains ONLY the reduction's own ThC queries, and
   the S-TCR disjointness -- which is what the member-aware repair exists to
   rescue -- is clean BY CONSTRUCTION.

   AND THE NARROW TRAFFIC IS A DIFFERENT CONDITION ENTIRELY.  `emb_tw ad` in
   `adlOC` bears on the WOTS-TW game's `disj_wgpidxs adlO adlOC`, which is
   discharged by the `embdisj` premise -- `get_wgpidxs` retains index 3 and
   `pkcotype <> chtype` -- and which the capstone discharges with the PROVEN
   `emb_disj_concrete`, before and after the split alike.  It was never the
   member-aware repair's problem.  Section 17 conflated the two disjointness
   conditions.

   SO THE CORRECT STATEMENT OF THE PAYOFF IS:
     NOT  "emb_tw cannot enter adlOC"                        (section 15 -- FALSE)
     NOT  "the payoff evaporates"                            (section 17 -- FALSE)
     BUT  "A holds no wide oracle, and the reduction's own ThC calls left the
          narrow transcript" -- so the member-aware repair IS moot, for a reason
          section 15 did not give.

   OTHER FINDINGS ACCEPTED:
     * "BUILT AND COMPILING" overstates the reduction: WOTS_C_Interactive.ec
       does NOT compile end-to-end -- stale two-oracle instantiations remain.
       Honest wording: "typechecks up to the first stale instantiation".
     * "7 instantiations" was a bad count: ~4 game-lemma sites plus ~8 equiv
       applications in that file, and ~25 `R_int_WOTSTW` mentions in
       XmssmtCC_All.ec.  Section 15's "cost counted" is retracted as a census.
     * THE OUTSTANDING ASSUMPTION IS NAMEABLE, and this is the most useful thing
       either leg produced: `forge(ps)` REVEALS `ps`, and `thfc_m` is a pure op
       any adversary can then evaluate itself -- so `OC_M`'s only real content is
       PRE-`ps` access to `thfc_m` under the hidden seed.  The obligation is
       therefore a PRF-AT-HIDDEN-KEY assumption on the second family (or a
       direct re-founding of WOTS-TW EUF-GCMA on the two-oracle game), not a
       vague "independence" hand-wave.
     * Comment rot at the seam (WOTS_C_Real.ec:78-79,167;
       WOTS_C_Interactive.ec:182,1700-1706 still say ThC = thfc / "grinds via
       OC").  Minor, but stale sentences are this subsystem's documented failure
       mode.
     * Probe `.eco` staleness: WOTS_TW_ES.ec was edited after the other objects
       were built, so sections 13-14's rc=0 were against an earlier WOTS_TW_ES.
       Diff is additive plus one changed line, so low risk -- but the receipts
       are not perfectly aligned and should not be quoted as if they were.

   NET, FINALLY: the width split's base layers are free, the +C retyping is
   mechanical, the two-oracle construction is buildable, and it DOES retire the
   member-aware machinery -- at the price of a PRF-at-hidden-key assumption on
   `thfc_m` plus the R_int_STCRC narrow-oracle bridge.  Whether that trade is
   worth making is a design decision.  It is NOT the "do not adopt" of
   section 17.
   ========================================================================== *)

(* ==========================================================================
   SECTION 19 -- THE TWO-ORACLE DESIGN QUESTION, ANSWERED (review wave, and a
   premise I checked that the reviewer could not).

   Kimi K3 leg on frozen 96b158f/2aedf6e returned AVOIDABLE, proposing to keep
   ONE collection and build the wide digest from TWO domain-separated members:

     ThC ps ad m c = wide( thfc _ ps (emb_tw ad) (emb_in0 (m,c)),
                           thfc _ ps (emb_tw ad) (emb_in1 (m,c)) ),  n_m := 2*n

   Under that route R_int_WOTSTW reverts to ONE oracle, the two-oracle game is
   deleted, and MEUFGCMA_WOTSTWESNPRF applies VERBATIM with MM45's own RHS --
   because MM45's THF games already grant OC access to ALL members under the
   shared ps, so both halves fall under the EXISTING SM-DT-UD/TCR/PRE
   assumptions with no restatement.  Structurally that is a better idea than
   the second collection.

   BUT IT RESTS ON A PREMISE THE REVIEWER COULD NOT CHECK, and pre-committed on:
     "Whether deployment's chain and digest hashes share one primitive -- the
      check-1 route assumes it (SHAKE-style); IF THEY ARE GENUINELY INDEPENDENT
      PRIMITIVES, THE XOF ROUTE IS AN IDEALIZATION AND (A) IS THE HONEST SHAPE."
   `sphincs-c10/` is absent from the review worktree, so it could not look.

   I LOOKED.  `wots_digest` (sphincs-c10/src/hash.rs:350-365) is a SINGLE
   `sha256_bytes(&buf)` over a 128-byte preimage, returning 32 bytes.  There is
   no XOF and no two-block structure; `chain_hash` (:322-328) is a separate call
   returning 16.  Modelling the 32-byte digest as a concatenation of two
   domain-separated 16-byte tweakable hashes is therefore an IDEALIZATION of a
   different function -- and, as the reviewer itself notes, S-TCR of a
   concatenation does not follow from S-TCR of the halves.

   SO, BY THE REVIEWER'S OWN CRITERION: (A) IS THE HONEST SHAPE.  Give the three
   MM45 RHS reductions two-oracle forms and state the two-oracle analogue with
   the same RHS.

   AND MY CHARACTERISATION OF THE ASSUMPTION WAS WRONG TWICE (reviewer, HIGH):
     * it is NOT "PRF-at-hidden-key on thfc_m".  What route (A) actually needs is
       "SM-DT-UD / SM-DT-TCR / SM-DT-PRE of `thfc` UNDER JOINT `thfc_m`-ORACLE
       ACCESS" -- nothing about thfc_m's own pseudorandomness;
     * and a PRF hop could not work anyway: `forge(ps)` REVEALS ps
       (WOTS_TW_ES.ec:2615) and `R_int.forge` evaluates `ThC ps` directly
       (WOTS_C_Interactive.ec:1770), so any OC_M simulator is distinguishable
       post-reveal with advantage ~1.  Option (B) is UNSOUND, not merely
       expensive.  Sections 15 and 18 name PRF-at-hidden-key; that naming is
       WITHDRAWN here.

   ALSO WITHDRAWN, per the same review: section 18's "the member-aware machinery
   can be retired".  Under (A) the machinery is KEPT.  And "disjointness free"
   (commit 5cce118) was free only because the two-oracle game stopped TRACKING
   the grind -- the obligation did not vanish, it moved into the wall.

   ONE REVIEWER FINDING ALREADY ADDRESSED: "nothing constrains len*log2_w <=
   8*n_m, so the deployed-geometry claim has no model-level witness" was true at
   96b158f and is now closed -- cdrafts-split/C10DeployedInstance.ec proves
   c10_window_bits (= 129), c10_window_fits_digest (129 <= 8*n_m) and
   c10_window_exceeds_chain_width (8*n < 129).
   ========================================================================== *)

(* ==========================================================================
   SECTION 20 -- BOTH LEGS RECONCILED.  ROUTE (D), AND A STRUCTURAL CLAIM OF
   MINE IS REFUTED.

   Both legs returned AVOIDABLE.  They proposed the SAME shape and DIFFERED on
   the one detail that decides whether it is faithful -- and section 19, written
   from the Kimi leg alone, picked the wrong branch.

     Kimi K3 : two DOMAIN-SEPARATED members of `thfc`, concatenated.
     GPT-5.6 : two PROJECTIONS of the SAME evaluation --
                 Hlo = low128(wots_digest ..), Hhi = high128(wots_digest ..),
                 ThC = join(Hlo, Hhi)
               with the explicit warning that the two serialisers "must be
               decoded away before evaluating the same deployed wots_digest;
               HASHING TWO DIFFERENT TAGS WOULD BE UNFAITHFUL."

   That warning is exactly the defect I found in the Kimi route by reading
   sphincs-c10/src/hash.rs:350-365 (one `sha256_bytes`, not an XOF).  So the
   projection form SURVIVES the check that killed the domain-separation form,
   and route (D) -- not (A) -- is the answer.  SECTION 19's conclusion is
   SUPERSEDED; its correction of the ASSUMPTION NAMING stands (see below).

   MY STRUCTURAL CLAIM IS REFUTED (GPT-5.6, on section 11(B) at :940-944).  I
   wrote that a Collection has ONE `out_t`, so one collection "provably cannot
   hold both a 16-byte chain hash and a 32-byte message digest", and treated the
   second family as FORCED.  The projection construction refutes it: model
   `msgWOTS` as a PAIR of `dgstblock`s and keep the collection's `out_t` at
   `dgstblock` -- the WIDE value is built OUTSIDE the collection by `join`, from
   two members the collection dispatches by input size.  One collection, one
   output width, two members, a wide digest.  I had the abstraction right and
   the consequence wrong.

   BOTH LEGS, INDEPENDENTLY, ON THE ASSUMPTION (CRITICAL):
   "PRF-at-hidden-key on thfc_m" is WRONG.  `ps` is a DELAYED PUBLIC SEED, not a
   secret key: an adversary saves one pre-`ps` answer, receives `ps` at forge,
   recomputes the pure op, and distinguishes any simulator with advantage ~1.
   Sections 15 and 18 name it; that naming is withdrawn (already recorded in
   section 19, and confirmed here by the second leg).

   WHAT ROUTE (D) COSTS -- it is not free, and both legs say so:
     * MM45's theorem becomes type-applicable, but its RHS then means
       UD/TCR/PRE security for an ENLARGED, CORRELATED collection containing
       BOTH digest projections.  "Not the old assumption for free" (GPT-5.6).
     * the S-TCR repair is NOT mechanical: present faithfulness rests on ThC
       being ONE fixed member (WOTS_C_Interactive.ec:419); a composite ThC needs
       a PROJECTION-COLLISION reduction plus member-aware handling of the other
       projection.  The member-aware machinery stays ACTIVE -- which independently
       re-confirms section 18's withdrawal.
     * ~2x hash-oracle queries during the grind; join/split and serialiser
       lemmas; distinct member indices (dfC -> {dfC0, dfC1}).
     * n_m = 2*n is REQUIRED for this instantiation (both legs).

   ALSO: (A) IS NOT THE CHEAP OPTION I TOOK IT FOR.  GPT-5.6: "A is essentially
   the same work as C" -- its three `_2` reductions are the concrete
   manifestation of re-running Games 2-4, and their RHS games would be
   auxiliary-oracle versions, NOT MM45's original terms.  Section 19 called (A)
   "the honest shape" partly because I believed it was bounded.  It is honest
   AND expensive; (D) is honest and cheaper.

   NET: the width split stays (129 > 128 at n=16 is real).  The SECOND FAMILY
   goes.  Both legs converge on that sentence: "split widths, yes; separate
   family, no."
   ========================================================================== *)

(* ==========================================================================
   SECTION 21 (2026-08-01) — ROUTE (D) IMPLEMENTED.  STATUS, HONESTLY.

   Section 20 chose route (D) (one collection, two projection members) over the
   second-family design of sections 13-18.  It is now BUILT, not merely chosen.

   WHAT IS GREEN (base-c10-split 4/4, cdrafts-split 12):
     WOTS_TW_ES, FL_SL_XMSS_MT_ES, FORS_ES, SPHINCS_PLUS (base);
     WOTS_C_Real, WOTS_C_Scheme, WOTS_C_Multi, WOTS_C_INTERACTIVE,
     WOTS_C_Reduction, WOTS_C_Flag2Discharge, STCR_C, XMSSMT_C_Scheme,
     XMSSMT_C_Bridge, C10DeployedInstance, FORS_C10, FORS_C10_Multi.

   The choke point of section 19-20 -- XmssmtCC_All:8901 applying MM45's
   one-oracle MEUFGCMA_WOTSTWESNPRF to a two-oracle reduction -- IS GONE at its
   source: R_int_WOTSTW is back on MM45's ORIGINAL interface.  No two-oracle
   game, no two-oracle analogue, no two-oracle forms of MM45's three
   sub-reductions.  That entire branch of obligations was dissolved, which is
   exactly what a YES on rw7's check 1 was supposed to buy.

   WHAT IS STILL BLOCKED (9): WOTS_C_Bridge, WOTS_C_EmbDischarge,
   XMSSMT_C_Reduction, XmssmtCC_All, GprocFORSC10, RtopCSoundness, FxChain,
   and both capstones.  Every type error through the bridge layer is resolved;
   what remains at each site is PROOF obligations of two mechanical kinds:
     (a) the doubled transcript (two projection queries per ThC evaluation, so
         `rcons` becomes `rcons (rcons ..)`), and
     (b) SMT hint refreshes, because splitting qC's message type from qTW's
         changes the term shapes the old hints were tuned to.
   XMSSMT_C_Reduction additionally has ONE genuine incomplete proof (:817) that
   must be closed on its merits, not by hint-tuning.

   COSTS PAID, as both review legs predicted:
     * ~2x collection queries in every grind loop;
     * the rcons/emb_tw transcript reasoning is BACK and doubled -- two comments
       in WOTS_C_Interactive claiming it was "gone" were TRUE ONLY of the
       abandoned second-family design and have been corrected in place;
     * dfC -> {dfC0, dfC1} throughout the member-separation machinery;
     * a projection-collision reduction (ThC_coll_projects) replaces the old
       "ThC IS one member by definition" argument, which route (D) does not have.
       It is cheap because join_dgst is injective: a wide collision is a
       collision in EACH half, so one is read off at the fixed member dfC0.

   THE HYPOTHESIS THIS BUYS IS STRONGER THAN MM45'S, AND THAT IS NOT FREE.
   Under the deployed instantiation the two members are PROJECTIONS of a single
   sha256 evaluation, hence CORRELATED.  MM45's RHS therefore now means
   UD/TCR/PRE for an enlarged, correlated collection.  Modelling them as two
   domain-separated hashes instead would be UNFAITHFUL -- wots_digest
   (sphincs-c10/src/hash.rs:350-365) is ONE sha256_bytes call -- so the
   correlation is forced by the deployment, not chosen for convenience.

   COVERAGE CLAIM, PRECISELY.  The formalization does NOT yet cover the deployed
   parameters.  C10DeployedInstance proves the deployed geometry is ADMISSIBLE
   under the split (c10_split_removes_the_width_obstruction: 8^43 <= 2^256,
   against c10_unsplit_fell_short: 2^128 < 8^43) and that both deployed members
   separate; the width obstruction that made n=16/len=43/log2_w=3 impossible in
   the unsplit model is gone.  But the +C chain above WOTS_C_Interactive is not
   yet re-proved under route (D), so no end-to-end statement holds at our
   parameters today.  Q1 (meta-level identification of encode_msgWOTS with the
   deployed digit map) and the FORS hop5 seam remain open independently.
   ========================================================================== *)

(* ==========================================================================
   SECTION 22 (2026-08-01) — ROUTE (D) CLOSED.  THE SPLIT FORK IS GREEN.

   CLEAN REBUILD (all .eco deleted, base and cdrafts from scratch):
       base-c10-split    4/4    OK
       cdrafts-split    19/19   OK   (closure-c10-fork.txt)
       + C10DeployedInstance    OK   (39 lemmas; new in the split)
       TOTAL 23/23, ZERO failures.

   SOUNDNESS CHECK — the result is not bought with assumptions:
     * ZERO new `admit`s.  Line-level parity against the certified fork: the
       only difference in ANY admit-bearing line across the whole closure is a
       comment (`dfC` -> `dfC0` in prose).  Counts match file-for-file (Grind 1,
       WOTS_C_Interactive 3, XmssmtCC_All 11, FORS_C10 1, CapstoneWired 3,
       Content 1, Geometry 1, CapstoneCharged 2).
     * ZERO new axioms, in cdrafts AND base (line-level diff, both empty).
     * ONE assumption REMOVED: the split previously declared
       `const n_m : {int | 1 <= n_m} as ge1_nm`.  Route (D) makes n_m = 2*n a
       DEFINITION and PROVES ge1_nm.

   WHAT THIS ESTABLISHES.  The +C EUF-CMA chain now compiles at a model whose
   widths match the deployment: n = 16 chain blocks, n_m = 32 message digest,
   len = 43, log2_w = 3, target_sum = 205.  The width obstruction is genuinely
   gone, not assumed away -- C10DeployedInstance proves BOTH
       c10_unsplit_fell_short              : 2^(8*16) < 8^43     (the old wall)
       c10_split_removes_the_width_obstruction : 8^43 <= 2^(8*32)
   and both deployed projection members (161, 162) clear all four separations
   and differ from each other.

   WHAT THIS DOES NOT ESTABLISH — read this before quoting the line above.
   (1) The chain is PARAMETRIC; it is not instantiated AT n=16/len=43.  The
       deployed values discharge its side conditions; they do not replace its
       parameters.  Q1 is the reason: EasyCrypt cannot re-interpret an already
       declared op from inside the theory, which is why
       MODEL_JOINT_on_actual_globals states (i)-(iv) as HYPOTHESES rather than
       as a clone-realization.  Their simultaneous satisfiability rests on the
       axiom census (predC/emb_in/thfc carry no axiom) plus non-circularity.
   (2) The FORS hop5 seam is open independently of this work.
   (3) THE ASSUMPTION IS STRICTLY STRONGER THAN MM45'S.  Under the deployed
       instantiation the two members are PROJECTIONS OF ONE sha256 evaluation
       (wots_digest, sphincs-c10/src/hash.rs:350-365 is a single sha256_bytes
       call), hence CORRELATED.  MM45's UD/TCR/PRE therefore range over an
       enlarged, correlated collection.  This is forced by the deployment, not
       chosen: two domain-separated hashes would be UNFAITHFUL.  It is not the
       old assumption for free.

   THE DEFECT CLASS THIS PORT KEPT PRODUCING — for whoever reviews it next.
   FIVE statements would have compiled green while no longer asserting what they
   were written to assert, because the split separates two roles that shared one
   type.  All five were repaired on their merits:
     * A_ht_dfC and F_leak (negative controls) queried `emb_in witness`, which
       after route (D) no longer records the CHALLENGED member -- they would
       have passed while witnessing nothing.
     * c10_dfC_separations and its r=256 robustness corollary would have
       certified separation for a width NO member has, and for one member while
       saying nothing about the other.
     * CONCLUSION 5 of SphincsC10Content asserted a SINGLE-member second
       preimage; ThC is now a join, so the equation is simply false.  Restated
       as the join + ThC_coll_projects.
   A green compile does not detect this class.  Counts and greps piped through
   `head` do not either -- that truncation is exactly how the F_leak instance
   was missed on the first sweep.
   ========================================================================== *)

(* ==========================================================================
   SECTION 23 (2026-08-01) — THE DEVELOPMENT IS NOW SPECIALISED TO C10.

   n = 16, k = 13, a = 11, log2_w = 3 (w = 8), len = 43, h' = 9 (h = 18), d = 2.

   HOW, AND WHY IT WAS SMALL.  The architecture is ALREADY clone-based:
   SPHINCS_PLUS declares the parameters and clones FL_SL_XMSS_MT_ES (which in
   turn clones WOTS_TW_ES) with them, and the +C chain imports
   FSSLXMTWES.WTWES -- the CLONE, not the top-level theory.  So SEVEN constants
   in ONE file specialise the whole chain.  The "restructure everything into
   abstract theories" refactor was not needed; that estimate was wrong.

   OPAQUE, NOT TRANSPARENT — a deliberate design choice.  Writing `op n = 16`
   makes the value delta-reducible, so size side-conditions auto-discharge; that
   silently shifts goal counts and breaks index-based proof scripts throughout
   MM45's heavily-tuned proofs (hit twice, cascading, before backing out).
   Declaration + value axiom gives the IDENTICAL specialisation with ZERO
   perturbation.  Anything needing the number rewrites `n_val`.

   ASSUMPTION COUNT UNCHANGED — 8 before, 8 after, in the only file changed:
       fork  : 1 axiom + 7 `const x : {int | P x} as ax`  = 8
       split : 8 axioms + 0                               = 8
   Every `const .. as ax` WAS an axiom; it is now a VALUE axiom with the old
   bound DERIVED as a lemma.  One traded for one, per parameter.
   (A whole-directory grep reports 36 vs 37; that is an ARTEFACT of dedupe
   across files that redeclare the same constants, plus a trailing space on the
   fork's `h'` line defeating a `\.$` regex.  Count per changed file, not per
   tree.)

   CLEAN REBUILD 25/25, zero failures, zero proof breakage.

   NON-VACUITY, TWO-SIDED — this is the check that matters, because an
   inconsistent specialisation compiles green and proves everything:
     * MUST-PASS (C10SpecControls.ec): h = 18, w = 8, and
       `8 * n < len * log2_w` (128 < 129) -- the EXACT obstruction that forced
       the width split, and FALSE for generic parameters.  Provable => the
       deployed values are genuinely in force.
     * MUST-FAIL (registered canary): `false` is NOT provable from the
       specialised axiom set.
   The risk was real, not hypothetical: standard WOTS at these sizes demands
   len = len1 + len2 = 46, and C10 uses 43.  It is consistent only because +C
   drops the checksum -- the fork says so explicitly ("len is an independent
   parameter").  Had that split survived anywhere, len_val would have made the
   theory inconsistent and every theorem above vacuous.
   ========================================================================== *)

(* ==========================================================================
   SECTION 24 (2026-08-01) — CORRECTION TO SECTION 22'S ADMIT EVIDENCE.

   SECTION 22 REPORTED ADMIT COUNTS THAT WERE MEASURED WRONG.  It said
   "Counts match file-for-file (Grind 1, WOTS_C_Interactive 3, XmssmtCC_All 11,
   FORS_C10 1, CapstoneWired 3, Content 1, Geometry 1, CapstoneCharged 2)".
   Those numbers came from `grep -c "admit"`, which in this repo overwhelmingly
   matches PROSE IN COMMENTS -- "Zero admits", "NO admit", "admit-tactics=0",
   "is admitted.  THAT IS NO LONGER TRUE".  They were not counting tactics.

   MEASURED PROPERLY (EasyCrypt comments stripped, then the `admit` token at a
   tactic position):

       base-c10-split/WOTS_TW_ES.ec          1   (fork: 1  -- IDENTICAL)
       base-c10-split/FL_SL_XMSS_MT_ES.ec    0   (fork: 1  -- excised ungated side)
       base-c10-split/FORS_ES.ec             0   (fork: 0)
       base-c10-split/SPHINCS_PLUS.ec        0   (fork: 0)
       cdrafts-split/  ALL closure files     0   (identical to fork, file for file)

   SO THE CONCLUSION OF SECTION 22 STANDS AND IS IN FACT STRONGER THAN STATED:
   the +C closure carries ZERO admit tactics, and route (D) + the specialisation
   introduced none.  But it was asserted on evidence that did not support it,
   which is the same defect class this file keeps recording -- a CLAIM measured
   badly, not a PROOF that failed.

   THE ONE REAL ADMIT, NAMED HONESTLY.  It is
       base-c10-split/WOTS_TW_ES.ec  lemma nhchwcoll_hchwpre_msg
       `admit.  (* <-- THE PRE-EXISTING GAP: encode m <> encode m' *)`
   present IDENTICALLY in the certified fork (fork:1452 / split:1513, same lemma,
   same comment).  It is INHERITED from MM45's WOTS-TW development, not
   introduced here.  It sits in the base WOTS-TW theory.
   [SUPERSEDED BY SECTION 29 -- this sentence previously read "so the deployed
   capstone DOES rest on it", which is FALSE and contradicted section 29 for two
   days.  MEUFGCMA_WOTSTWESNPRF is never APPLIED by either capstone; the WOTS-TW
   probability is CARRIED as an unreduced RHS summand.  The admit is inherited
   and IDLE.  It would become load-bearing only if that summand were later
   discharged via MEUFGCMA_WOTSTWESNPRF.  Read section 29, not this paragraph.]

   METHOD NOTE, so this is not repeated: never count `admit` (or any tactic) with
   a raw grep in this repo.  Strip `(* ... *)` first.  The helper used at the time lived in a
   session scratch directory and was NEVER COMMITTED, so that citation pointed at
   nothing -- an unreproducible receipt, corrected 2026-08-02.  The maintained
   equivalent is tools/cert_cone.py, which strips comments before matching and is
   what both gates now run.  The same hazard applies to counting `axiom`.
   ========================================================================== *)

(* ==========================================================================
   SECTION 25 (2026-08-01) — ADVERSARIAL REVIEW RESULT (Kimi K3 + GPT-5.6,
   mutually blind, frozen at 5e3f6e7 / tree 6fd4a82).

   VERDICTS DIVERGED: GPT-5.6 said BROKEN, Kimi K3 said SOUND-AS-CLAIMED (core).
   Reconciled by REPRODUCTION at source, not by vote.  Result: the CORE SURVIVES;
   the FRAMING DID NOT.  Both legs converged on the substance.

   WHAT SURVIVED (both legs, independently)
     * NO INCONSISTENCY -- the thing I most feared is absent.  Kimi's decisive
       details: no `len*log2_w <= 8*n` constraint survives anywhere; FORS_ES's
       `d = s*l` discharges EXACTLY (2^18 = 2^9 * 2^9); the len1/len2 surface is
       gone from proof BODIES (comments only).  My own probes agree: with the
       WHOLE closure in scope `false` is unprovable, and so is `len = 46`.
       [CORRECTED 2026-08-01: I also listed `n = 17`, `log2_w = 4` and
       `8*n = len*log2_w` as probed.  They were run, but their files were DELETED
       and never committed, so that evidence is UNREPRODUCIBLE.  Only
       scratch/vac_probe_full.ec and scratch/probe_len46.ec are tracked and gated.
       An uncommitted probe is an anecdote.]  Still evidence, not proof.
     * ROUTE (D) IS SOUND AS MECHANIZED: join_dgst_inj fully proved, and
       ThC_coll_projects genuinely projects a join collision onto member dfC0.
     * ADMIT PARITY IS REAL: 0 = 0 across all closure files.

   DEFECTS FOUND AND FIXED IN CODE
     1. CONCLUSION 5 of SphincsC10Content was DEFECTIVE -- and it was MY route-(D)
        restatement.  It had NO collision antecedent and NO projected equality;
        its last two conjuncts were ThC's DEFINITION, which holds unconditionally,
        while the header kept promising "a GENUINE second preimage on a SINGLE
        collection member".  ThC_coll_projects was never used.  Found by GPT-5.6.
        NOW REWRITTEN with the real content and proved via
        S_TCR_C_Int_win_2ndpreimage.  This is the SIXTH instance of the
        still-compiles-but-no-longer-means-it class, and the first I introduced
        myself while claiming (in section 22) to have repaired exactly it.
     2. c10_embg INJECTIVITY WAS PROSE ONLY.  The file claimed the deployed
        serialisation "is injective" but proved only its WIDTH.  That gap is
        load-bearing: the deployed capstone's premise constrains
        `size (emb_in witness)`, and a CONSTANT emb_in satisfies it while
        collapsing every ThC input and making the S-TCR term trivially winnable
        (GPT-5.6's kill-shot scenario).  NOW PROVED: c10_embg_inj, plus
        c10_embg_meets_LEN_and_INJ.
     3. The pigeonhole note REUSED |dgstblock| = |msgWOTS| a few lines after
        retracting it.  Under route (D) the digest space is the SQUARE of the
        node space, so the counting step does NOT go through.  Corrected in place.
     4. The vacuity canaries were NOT REGISTERED in cert-controls.tsv (both legs).
        Now registered, MUST-FAIL, alongside C10SpecControls as MUST-PASS.
     5. `ge2_len (used 160x chain-wide)` -- no counting convention yields 160.
        Corrected.

   CLAIMS IN SECTIONS 20-24 THAT WERE WRONG, CORRECTED HERE
     A. "ASSUMPTION COUNT UNCHANGED -- 8 before, 8 after" (section 23) is FALSE
        for the file as a whole.  base-c10-fork/SPHINCS_PLUS.ec has NINE
        assumption-producing declarations (7 `const..as` + dist_adrstypes +
        `declare axiom A_forge_ll`).  It is 9 -> 8 BY DELETION: the split excised
        the file's entire security tail.  MEASURED: SPHINCS_PLUS.ec 4613 -> 1019
        lines, FL_SL_XMSS_MT_ES.ec 6452 -> 1543 lines, and MM45's OWN capstone
        `EUFCMA_SPHINCS_PLUS` is PRESENT in the fork and ABSENT in the split.
        Correct statement: "8 retained, 1 deleted with the tail."  Nothing
        dangles (the +C chain builds its own capstone), but the split BASE now
        states no EUF-CMA theorem at all, and "fewer admits because excised" is
        literally true and strictly less meaningful than it sounds.
     B. "TOTAL 23/23" (section 22) and "25/25" (section 23) reconcile with
        NOTHING.  closure-c10-split.txt lists 22 files; with 4 base files the
        target count is 26.  Section 22 also cited the FORK's closure list for a
        SPLIT claim.  Receipts must name the list they were measured against.
     C. "target_sum = 205" listed among the deployed parameters IN FORCE
        (sections 22, 23) is FALSE.  `target_sum` remains
        `digitsum (encode_msgWOTS tgt_witness)` (WOTS_TW_ES.ec:647); NO axiom
        pins it.  That is the Q1 encoder gap, which I listed as closed.  The
        specialisation pins n, k, a, log2_w, len, h', d -- SEVEN values, not the
        encoder target.
     D. "forced by the deployment ... domain-separating them would be UNFAITHFUL"
        (sections 20, 21) is OVERCLAIMED, and both legs said so independently.
        The two members are distinguished by INPUT-LENGTH TAGS (161 vs 162 bits)
        that have NO counterpart in the deployment, which is one sha256_bytes
        over one 128-byte preimage with no tag bits.  Kimi's phrasing is the
        accurate one: route (D) is FAITHFUL AS A CONSERVATIVE STRENGTHENING, NOT
        FORCED; domain separation would be DIFFERENT, not unfaithful.  The
        instantiation bridge from two tagged members to one sha256 call is
        PROSE, NOT PROOF -- it is the honest residual, and the accurate version
        already sits in the code at WOTS_C_Real.ec (the correlated-collection note).
     E. The deployed capstone is a REDUCTION, NOT A NUMERIC GUARANTEE: `c <= p_tgts`
        is assumed with `p_tgts` a free abstract constant (the +C target count is
        NOT specialised), N2 and the emb_in-width premise stay assumptions, and
        the RHS still carries an unreduced ITSRC10 term and an unbounded bad event.

   ALSO NOTED: cdrafts-fork/C10DeployedGeometry.ec (this file) still narrates the
   ABANDONED two-collection design as current in sections 6-18.  Fine as dated
   history, but the fork and split copies now tell different stories and only the
   split tree compiles.  Read sections 20+ as authoritative.
   ========================================================================== *)

(* ==========================================================================
   SECTION 26 (2026-08-01) — SECOND ADVERSARIAL REVIEW (run 2), frozen at
   b858721 / tree d72849a.  Run 2 deliberately targeted DIFFERENT surface: the
   RHS's meaningfulness, the FORS/Gproc leg, and the run-1 REMEDIATION ITSELF
   (the freshest, least-reviewed code).  It found THREE defects in that
   remediation.  Recording them because they are mine.

   1. `c10_embg_inj` IS AN ORPHAN, AND SECTION 25's "NOW PROVED" OVERCLAIMED.
      I proved LEN+INJ for `c10_embg` in response to run 1's constant-`emb_in`
      scenario, and wrote that this closed it.  IT DOES NOT.  `c10_embg` occurs
      NOWHERE outside C10DeployedInstance.ec, and the capstone's `emb_in` is a
      different, abstract op that is never tied to it.  Worse, LEN/INJ are NOT
      premises of the capstone at all -- this repo's own wiring ledger says so
      (SphincsC10CapstoneWired.ec:310-315: "THEY ARE NOT ... the capstone chain
      never applies those lemmas").
      HONEST STATEMENT: c10_embg_inj shows the model's LEN/INJ requirements are
      SATISFIABLE BY A DEPLOYED-SHAPED SERIALISATION.  It does NOT constrain the
      capstone's `emb_in`, and run 1's constant-`emb_in` observation therefore
      STANDS as a statement about what the S-TCR term MEANS.  Proving a lemma
      about a candidate is not the same as wiring it in; I conflated them.

   2. TWO REGISTERED CONTROLS POINTED AT UNTRACKED FILES.  `scratch/vac_probe_full.ec`
      and `scratch/probe_len46.ec` were registered MUST-FAIL in cert-controls.tsv
      while being untracked, so from a clean checkout the gate would see missing
      files.  A control that cannot be found is not a control.  Now tracked.

   3. "A WINNING PAIR ALWAYS EXISTS" SURVIVED THE RETRACTION IT DEPENDED ON.
      Section 25 corrected the pigeonhole counting (|msgWOTS| is the SQUARE of
      |dgstblock| under the split, so nothing is forced by counting) but left the
      conclusion that counting supported.  An incomplete fix is its own defect.
      Retracted in place; the CONSEQUENCE below it is unaffected because it never
      depended on existence.

   AND THE RUN-2 KILL SHOT, WHICH IS REAL AND IS THE KNOWN SEAM.
   The bound carries `Q = Pr[EUF_CMA_Gproc_I(R_fors_p(F)) : res /\ !covered]`
   with NOTHING bounding it below 1.  Mechanically: the capstone proof
   instantiates the parent's `mtree_openpre` with Q ITSELF and 0%r for the other
   two tree reals (SphincsC10CapstoneWired.ec:909-916), so the tree premise
   becomes `Q <= Q` and closes by smt().  That summand is CARRIED, NOT REDUCED.
   The file says this in its own words already (":828-837": "if Q = 1 this bound
   is as uninformative as the free-real version was").
   QUALIFIER THE REVIEWER MISSED: `cdrafts-split/FORS_C_TreePort.ec` DOES prove
   `Pr[res /\ !covered] <= OP + TRH + TRCO` -- it is simply NOT IN
   closure-c10-split.txt.  So this is the KNOWN-OPEN FORS hop5 seam, not a new
   break.  It is nonetheless the correct emphasis: until that port is in the
   closure, the deployed bound is NOT numerically meaningful.

   ALSO CONFIRMED (both runs): `p_tgts` is free (`WOTS_C_Real.ec:340`, only
   `0 <= p_tgts`), and since `1 <= c`, the instantiation `p_tgts = 0` makes the
   premise `c <= p_tgts` UNSATISFIABLE -- i.e. there are instantiations at which
   both capstones are vacuously true.  Nothing pins a deployed target count.

   NET AFTER TWO RUNS.  The theory is consistent (hunted by four independent
   agents across two runs, nothing found).  The mechanised mathematics of route
   (D) holds.  What is NOT true is that the deployed bound is a security
   guarantee: its headline term `Pr[M.F.ITSRC10 ...]` is an unreduced bespoke
   assumption (the black-box route to MM45's ITSR loses ~102 bits --
   FORS_C10_Multi.ec:57), `Q` is unbounded in-closure, and `p_tgts`, the counter
   cardinality, `emb_in`, N2 and `target_sum` all remain free or assumed.
   ========================================================================== *)

(* ==========================================================================
   SECTION 27 (2026-08-01) — MY FIX OF MY FIX WAS ALSO PARTIAL.

   Section 26 item 3 reported the pigeonhole conclusion "Corrected in place".
   The run-2 internal swarm produced a SURVIVING finding proving that receipt
   wrong, with the diff as evidence: commit 249f30e touches
   SphincsC10Content.ec in THREE hunks [CORRECTED 2026-08-01: I wrote "exactly
   TWO"; `git show` reports three -- the numerology lesson of this very section,
   violated by the section stating it], and the file's HEADER lies in
   neither.  So while one paragraph carried the retraction, the header still
   asserted the withdrawn step as established:
     :47-48  "It also records, with a pigeonhole argument, what NO model can achieve."
     :85-88  "PROVABLY unreachable by any model-theoretic premise: pigeonhole
              forces gate-passing same-tweak collisions to EXIST ..."
     :675    "... and existence is forced."
   Plus a domain slip at :649 ("maps msgWOTS INTO the gate set" -- ThC's input is
   a NODE, dgstblock).

   ALL FOUR NOW CORRECTED, and the sweep was done by grepping the WHOLE FILE for
   every pigeonhole-dependent phrase rather than patching the site under review.

   AND THE CLAIM WAS WORSE THAN UNSUPPORTED.  The refuting agent sharpened it:
   `predC`, `emb_in` and `thfc` carry NO axiom anywhere in the closure (this
   file's own census), so an interpretation making ThC INJECTIVE on (m,c) is
   admissible -- and in that model the S-TCR(+C) term is 0.  So "PROVABLY
   unreachable by any model-theoretic premise" is not merely unsupported, it is
   plausibly FALSE.  The honest word is NOT ACHIEVED, never IMPOSSIBLE.  What
   survives as the real ground for the faithfulness point is a HEURISTIC about
   the DEPLOYED function (the constant-sum set is a ~2^-15 fraction of the digest
   space, so gate-passing collisions are abundant), now labelled as such.

   THE LESSON, THIRD-ORDER.  Instance six of the
   still-compiles-but-no-longer-means-it class was introduced by the commit
   claiming to fix instance five; instance seven was introduced by the commit
   claiming to fix instance six.  A partial fix is not a smaller version of a
   fix -- it is a NEW defect, because it also produces a receipt saying the
   problem is closed.  RULE ADOPTED: when retracting a claim, grep the WHOLE
   FILE for every phrase that depended on it -- headers and summaries first,
   since those are what a reader quotes -- and never accept a fix whose evidence
   is confined to the hunk under review.
   ========================================================================== *)

(* ==========================================================================
   SECTION 28 (2026-08-01) — RUN-2 SECOND LEG (Kimi K3).  BOTH LEGS CONVERGED
   ON THE SAME KILL SHOT, AND KIMI CAUGHT MY OVER-CORRECTION.

   CONVERGENT KILL SHOT (independent, both legs): the run-1 injectivity fix is an
   ORPHAN.  `c10_embg_inj` is correctly proved but applied NOWHERE; the deployed
   capstone's only `emb_in` premise is a WIDTH AT ONE POINT, which a CONSTANT
   `emb_in` satisfies.  Injectivity of the model's `emb_in` (N4) appears only in
   EUFCMA_SPHINCS_PLUS_C10_CONTENTFUL, and THAT lemma is applied nowhere either --
   so CONCLUSION 5, even now that it is genuine, never reaches the deployed
   capstone.  The V2 collapse is NOT excluded at the deployed level.  Section 25's
   "NOW PROVED" is true of lemmas that connect to nothing.  Capstone header fixed
   to name the width premise as the fourth and DECISIVE remaining assumption.

   KIMI CAUGHT MY OVER-CORRECTION TO RUN 1 — the classic second-leg payoff.
   Section 25.A said "the split BASE now states no EUF-CMA theorem at all".
   FALSE.  Run 1 told me SPHINCS_PLUS.ec's own tail was excised; I generalised
   that to the whole base.  The split base RETAINS
       base-c10-split/FORS_ES.ec:6531      lemma EUFCMA_MFORSTWESNPRF
       base-c10-split/WOTS_TW_ES.ec:6578   lemma MEUFGCMA_WOTSTWESNPRF
   and the latter is exactly the capstone's first hypertree summand.  Correct
   statement: SPHINCS_PLUS.ec's OWN top-level capstone was excised; the base's
   component EUF-CMA theorems remain.

   SECTION 24's SCOPE WAS TOO BROAD.  "the +C closure carries ZERO admit tactics"
   holds for the 22 GATED files only; non-gated cdrafts-split files carry admits.
   And the inherited admit is NOT merely inherited-and-idle: `nhchwcoll_hchwpre_msg`
   feeds `MEUFGCMA_WOTSTWESNPRF` (WOTS_TW_ES.ec:6578), which IS the capstone's
   first hypertree summand.  It is load-bearing for the top result.
   [SUPERSEDED — see SECTION 29 FINDING 2, which retracts this sentence verbatim:
   `MEUFGCMA_WOTSTWESNPRF` is NEVER APPLIED in SphincsC10CapstoneWired.ec; the
   capstone CARRIES the WOTS-TW game probability as an unreduced summand.  The
   retraction existed but this paragraph was left unmarked, so a reader arriving
   at section 28 first read a retracted claim as current.  Marker added
   2026-08-02 (run 11, Kimi K3); section 31's own SUPERSEDED-marker rule had not
   been applied to its own predecessor.]

   NO GATE WATCHED THE SPLIT AT ALL.  cert_gate_fork.sh references only the fork,
   so every "26/26" was an ad-hoc run with nothing enforcing it.  A result nothing
   enforces is not a receipt.  ADDED cert_gate_split.sh: targets from
   closure-c10-split.txt, a COMMENT-STRIPPED admit census (expected 0), and the
   four registered controls.

   ALSO FROM KIMI, NOT YET ACTIONED (recorded so they are not lost):
     * `good_pos` (FORS_C10.ec:208) is NOT realized in the M clone
       (GprocFORSC10.ec:137-148) -- a quantitative AXIOM baked into the deployed
       FORS game, not a premise.
     * SphincsC10Content.ec:90-198 argues against the FORK base and is stale in
       three specific ways (a log2_w constraint that no longer exists;
       |msgWOTS| = 2^128 contradicting the same file; "no deployed instantiation
       of ANY part" against C10SpecControls.ec).
     * GprocFORSC10.ec:700-728 narrates "this admit" inside a finished proof.
     * Section 23's line count is off by one (1020, not 1019).

   BOTH LEGS AGREE ON WHAT IS SOUND: all six rewritten/added lemmas are correctly
   stated and proved; ThC_members_distinct is genuinely unconditional;
   CONCLUSION 5's proof is exact; the pigeonhole retraction is honest; no
   smt()-from-contradiction anywhere; zero admit tactics in the gated closure.
   [CORRECTED 2026-08-01: this sentence also said "the specialisation is
   consistent with exactly 8 axioms".  That is true of SPHINCS_PLUS.ec ALONE and
   FALSE of the closure -- see sections 30 and 31; the real ledger is 71 entries.
   Re-endorsing it here, under the banner "BOTH LEGS AGREE ON WHAT IS SOUND",
   left the log contradicting itself in two places at once.]  Kimi's summary is
   the fair one: THE PROOFS ARE HONEST; THE NEWEST CLAIMS WERE NOT.
   ========================================================================== *)

(* ==========================================================================
   SECTION 29 (2026-08-01) — RUN 3.  THE GATE I BUILT WAS THE WEAK POINT, AND
   SECTION 28 ASSERTED A DEPENDENCY I NEVER REPRODUCED.

   FINDING 1 (mine, KILL-SHOT against my own infrastructure).  cert_gate_split.sh
   PHASE 2 was a flat `admit` regex over `cdrafts-split/<name>.ec` for the 22
   closure names.  It therefore COULD NOT SEE the live admit in
   base-c10-split/WOTS_TW_ES.ec:1513 -- a file the SAME script compiles one phase
   earlier -- while printing an unqualified "gated-closure admit tactics = 0
   (expected 0)" and GREEN.  It also counted NO `axiom` and NO `declare axiom`,
   and had NO baseline, so the assumption set could GROW SILENTLY.
   WORSE: the correct mechanism ALREADY EXISTED next to it.  cert_gate_fork.sh
   PHASE 2 is a transitive require-cone census of admit/axiom/declare-axiom
   diffed against cert-baseline.tsv with ADDITIONS FATAL, and its header names
   "DEPENDENCY-CONE TAINT" as defect #1 with this exact instance.  I wrote a
   weaker gate beside a correct one and reported its GREEN for a day.
   FIXED: tools/cert_cone.py's include dirs are now overridable
   (CERT_CONE_DIRS); PHASE 2 runs the SAME cone census over both split trees and
   diffs it against the new cert-baseline-split.tsv, additions fatal.
   THE LEDGER IT NOW EXPOSES (27 entries, previously invisible):
       1  admit          base-c10-split/WOTS_TW_ES.ec  nhchwcoll_hchwpre_msg
      23  axiom
       3  declare-axiom

   FINDING 2 (a claim of mine that was FALSE, and I took it from a reviewer
   without reproducing it).  Section 28 said the inherited admit "is NOT merely
   inherited-and-idle: nhchwcoll_hchwpre_msg feeds MEUFGCMA_WOTSTWESNPRF
   (WOTS_TW_ES.ec:6578), which IS the capstone's first hypertree summand.  It is
   load-bearing for the top result."  THAT IS WRONG.
   `MEUFGCMA_WOTSTWESNPRF` is NEVER APPLIED in SphincsC10CapstoneWired.ec.  It
   occurs there only as (a) module-restriction names (`-O_MEUFGCMA_WOTSTWESNPRF`)
   and (b) a `Pr[M_EUF_GCMA_WOTSTWESNPRF(...)] ` TERM inside the RHS (:596, :898).
   The capstone CARRIES the WOTS-TW game probability as an UNREDUCED SUMMAND; it
   does not discharge it via the theorem that rests on the admit.  `require
   import` does not create a dependency on every lemma in a required theory.
   CORRECT STATEMENT: the admit is inherited and is NOT load-bearing for either
   capstone.  It would become load-bearing only if the WOTS-TW summand were later
   discharged via MEUFGCMA_WOTSTWESNPRF.
   HOW I GOT IT WRONG: I accepted a run-2 reviewer assertion because it was
   specific and cited line numbers, without opening those lines.  That is the
   failure mode this whole file catalogues, committed by the coordinator rather
   than by a reviewer.  REPRODUCE BEFORE RECORDING -- including when the claim
   makes the work look WORSE, since a false pessimism is still a false claim.
   ========================================================================== *)

(* --- NEGATIVE CONTROLS ON THE GATE ITSELF (2026-08-01) ---------------------
   A gate is only worth its receipt if it has been ATTACKED.  Both phases have
   now been shown to REJECT a deliberately planted defect:

     PHASE 2 (cone census): an `axiom SMUGGLED_ASSUMPTION : 1 = 2.` appended to a
       closure file is DETECTED as `added=1` and named with file/line.  The
       previous flat-regex version would not have looked at axioms at all.

     PHASE 3 (controls): a deliberately unparseable file registered MUST-FAIL
       with reason "cannot prove goal (strict)" is REJECTED as "failed for the
       WRONG reason: parse error".  The previous polarity-only version accepted it.

   Both plants were reverted; the tree is clean.  Record this because a green
   gate that has never been attacked is indistinguishable from a gate that
   cannot fail. ------------------------------------------------------------- *)

(* ==========================================================================
   SECTION 30 (2026-08-01) — RUN 3, SECOND LEG.  THREE MORE OF MY CLAIMS WERE
   WRONG, INCLUDING TWO WHERE I OVER-CORRECTED A REVIEWER.

   1. I BROKE THE SIBLING GATE.  The run-2 remediation appended four split rows
      to cert-controls.tsv.  cert_gate_fork.sh reads that file WHOLESALE with
      FORK includes, so those rows fail there with "cannot locate theory
      C10DeployedInstance" -- a reason mismatch that turns the fork gate RED.
      The commit that FIXED "polarity without reason" left the neighbouring gate
      failing for exactly that reason class.  FIXED: split controls moved to
      cert-controls-split.tsv; cert-controls.tsv restored to fork-only; the
      split gate's silent whitelist removed (it would have hidden future rows).

   2. FABRICATED NUMEROLOGY, RECORDED BY ME.  Section 25 cited, as a decisive
      consistency detail, "FORS_ES's `d = s*l` discharges EXACTLY
      (2^18 = 2^9 * 2^9)".  NO SUCH COMPUTATION EXISTS.  base-c10-split/FORS_ES.ec
      :45-57 declares `s` and `l` with only `1 <= s`, `1 <= l`, and `d = s * l`;
      nothing pins them to 2^9.  I took the detail from a run-1 reviewer report
      because it was specific, and recorded it WITHOUT REPRODUCING IT.  RETRACTED.

   3. SECTION 26's "QUALIFIER THE REVIEWER MISSED" WAS ITSELF WRONG.  I wrote
      that FORS_C_TreePort.ec "DOES prove" the !covered bound and is "simply NOT
      IN" the closure -- i.e. a listing problem.  It is not.  That file bounds
      `EUF_CMA_FORSC_I` (:5), whereas the capstone's Q is over `EUF_CMA_Gproc_I`
      (SphincsC10CapstoneWired.ec:567) -- A DIFFERENT GAME -- and it carries its
      own labelled admit (:76).  So GPT-5.6's run-2 kill shot was MORE right than
      my correction allowed, and bringing the bound in needs a discharged admit
      plus single->multi and abstract->concrete bridges, not an entry in a list.

   4. "consistent with exactly 8 axioms" (section 23) is true of ONE FILE
      (SPHINCS_PLUS.ec) and false of the closure.  The cone census now reports the
      real ledger: 27 entries (1 admit, 23 axiom, 3 declare-axiom), including 7
      in cdrafts-split/FORS_C10.ec alone.

   REFUTED BY REPRODUCTION -- a run-3 finding I do NOT accept.  Kimi reported that
   the retracted pigeonhole "survives in a fork-gated file" (cdrafts-fork/
   SphincsC10Content.ec) and that my sweep "covered one file of five".  The
   retraction is WIDTH-SPECIFIC: base-c10-fork/WOTS_TW_ES.ec:213 has
   `type msgWOTS = dgstblock` (EQUAL cardinality), where the pigeonhole is VALID;
   base-c10-split/WOTS_TW_ES.ec:270 has `type msgWOTS = mdgstblock` (twice as
   wide), where it is not.  The fork copies are CORRECT AS WRITTEN.  Section 27's
   "ALL FOUR" is scoped to the split file, which is the only tree the retraction
   applies to.  (cdrafts/ and drafts/ copies are ungated history.)

   ACKNOWLEDGED LIMIT ON MY OWN VACUITY EVIDENCE.  The three MUST-FAIL canaries
   hand `smt()` only the integer value axioms, and EasyCrypt's smt uses no
   unlisted global axioms -- so they certify that SEVEN INTEGER ASSIGNMENTS ARE
   MUTUALLY CONSISTENT, not that the closure is consistent.  An inconsistency
   outside the arithmetic fragment (clone-carried axioms, `good_pos` against an
   empty `dmkey`, ch0/chS) would leave them green.  Stated here so the controls
   are not read as more than they are.

   GATE STRENGTHENED AGAIN: PHASE 1b now asserts the three named top results
   exist as `lemma`/`theorem` and NOT as `axiom` -- closing the other half of the
   "the gate certifies filenames" observation.
   ========================================================================== *)

(* ==========================================================================
   SECTION 31 (2026-08-01) — RUN 4.  THE LEDGER I PUBLISHED WAS WRONG BY 2.6x,
   AND THE REPO HAD WARNED ME A WEEK EARLIER.

   KILL SHOT (GPT-5.6, reproduced).  tools/cert_cone.py -- the walker I adopted
   in run 3 to replace my own flat regex -- resolved only `theory + '.ec'`.
   Every LOCAL ABSTRACT THEORY (.eca) therefore TERMINATED the cone silently:
   TweakableHashFunctions.eca, OpenPRE_From_TCR_DSPR_THF.eca, HashAddresses.eca,
   KeyedHashFunctions.eca.  Their assumptions were invisible, including
   `axiom in_collection` (TweakableHashFunctions.eca:567) and two `declare axiom`s
   (OpenPRE_From_TCR_DSPR_THF.eca:284,287).  The walker also counted only three
   textual forms, ignoring refined constants `const x : { .. } as name` -- which
   DECLARE an axiom apiece.

   THE TRUE LEDGER (32 cone files, was reported as 28):
       41  refined-const   (previously counted as ZERO)
       24  axiom           (reported 23)
        5  declare-axiom   (reported 3)
        1  admit
       ---
       71  TOTAL           (SECTION 29 AND 30 SAID 27)
   Section 29's "THE LEDGER IT NOW EXPOSES" and section 30's repetition of "27
   entries" are RETRACTED.  cert-baseline-split.tsv regenerated at 71.

   AND THE REPO ALREADY KNEW.  scratch/audit_axcensus_broad.sh, dated 2026-07-25,
   states the omissions verbatim: "It misses `declare axiom`, `hypothesis`,
   refined-type `const x : { .. } as name`, `op [lossless full uniform] d` ...
   and UNREALIZED clone side-conditions".  I adopted the narrower walker without
   reading the file next to it.  THIS IS THE THIRD TIME: the `admitted.` canary
   (2026-07-26), cert_gate_fork.sh's cone census, and now this.  The pattern is
   not carelessness about proofs -- it is REBUILDING INFRASTRUCTURE THIS REPO
   ALREADY HAS, WORSE, BECAUSE I DID NOT READ IT FIRST.

   SECTION 24 CONTRADICTED SECTION 29 FOR TWO DAYS.  Section 24 said the deployed
   capstone "DOES rest on" the inherited admit; section 29 established it does
   not.  Section 24 is now marked SUPERSEDED in place.  A claims log that
   contradicts itself is worse than one that is merely wrong, because a reader
   can quote whichever half they reach first.

   GATE HARDENED AGAIN (all four holes were real):
     * `set -o pipefail` -- a CRASHED census piped into `wc` previously read as
       "added=0", i.e. GREEN.  My own broken edit demonstrated this live.
     * PHASE 1b now strips comments before grepping (a declaration inside
       `(* .. *)` passed) and binds the name exactly (`NAME'` no longer
       satisfies a check for `NAME`).
     * PHASE 2b now requires a census ROW OF KIND `admit`, not any output line
       containing the substring -- the canary's own FILENAME contains
       "admitted", so the old check was self-satisfying.
     * PHASE 3 now counts UNIQUE EXECUTED controls (not file rows, so duplicates
       cannot pad the guard), validates the polarity enum, and REFUSES a
       MUST-FAIL whose declared reason is bare `-` (which accepted any failure).

   GOOD_POS, SETTLED (this was the one live finding recorded twice and never
   acted on).  It is NOT realized: the M clone's proof list
   (GprocFORSC10.ec:119-148) names eight obligations and F.good_pos is not among
   them.  But it is NOT REACHABLE from either capstone proof either: its only
   consumers are the helpers `query_ll` / `good_exists` (FORS_C10.ec:345-352),
   which the capstone chain does not use -- the Gproc hop inlines the query
   instead.  So it is AMBIENT NAMESPACE BAGGAGE supporting the lossless-
   rejection-sampler story, not a proof dependency.  Realizable only with
   concrete `mkey`/`dmkey`/`mco`, which remain abstract.  Whether it is TRUE at
   the deployed parameters is UNRESOLVED: under an ideal uniform window the mass
   would be ~2^-11, but nothing pins that distribution.
   Note the repo's own comments call it "LOAD-BEARING" (FORS_C10_Multi.ec:46,85,
   450); that is true of FORS_C10's internal story and FALSE of the capstone.
   ========================================================================== *)

(* --- SECTION 31 ADDENDUM: THE FORK'S OWN LEDGER WAS UNDERSTATED BY 51 -------
   Fixing tools/cert_cone.py had a consequence I nearly shipped without checking,
   and it is the SAME mistake as run 2 (where adding split rows to
   cert-controls.tsv turned the sibling fork gate RED).  cert_cone.py serves BOTH
   gates.  With .eca resolution and refined-const counting, the FORK census goes
   24 -> 75.  Comparing like-for-like (3 columns; the 4th is a line reference,
   which is why cert_gate_fork.sh projects before diffing and my split gate now
   does too), the fork baseline was MISSING 51 ENTRIES: 48 refined-const,
   2 declare-axiom, 1 axiom.
   So the "certified" fork's assumption ledger was understated too.  That is NOT
   a regression I introduced -- it is a pre-existing blindness my fix exposes.
   cert-baseline.tsv EXPANDED to 75: the 24 curated rows keep their notes
   VERBATIM, the 51 newly-visible are appended and marked.  Both gates now
   reconcile exactly (fork 75=75, split 71=71, added=0, removed=0).
   ALSO FIXED: my split gate compared FULL lines including `# line N`, so any
   edit shifting a line read as add+remove.  It now projects to 3 columns, as the
   fork gate always did.  Accepted limitation, stated: a changed STATEMENT at the
   same file/kind/name is invisible to a textual census.  EasyCrypt has no
   `#print axioms`; this is a require-graph census, not a kernel check. --------- *)

(* ==========================================================================
   SECTION 32 (2026-08-01) — RUN 5.  THE STATEMENT PIN DID NOT PIN MEANING, AND
   I HAVE NOW PUBLISHED FOUR DIFFERENT WRONG LEDGER TOTALS.

   KILL SHOT (Kimi K3, reproduced).  Statement digests fix TEXT, not DENOTATION.
   One line:
       -op emb_in : dgstblock * cntr -> dgst.
       +op emb_in (x : dgstblock * cntr) : dgst = witness.
   makes ThC CONSTANT in (m,c), so the +C gate stops binding the signed message
   and the RHS term Pr[S_TCR_C_Int_MA(..)] becomes the S-TCR game of a constant
   function -- trivially winnable.  EVERY GATE PHASE STAYS GREEN: no proof
   unfolds emb_in (VERIFIED: zero `/emb_in` rewrites in the closure -- its
   injectivity and width are carried as HYPOTHESES, never derived), the pinned
   statements mention it only as a token, abstract and defined ops are both
   non-census categories, and no control names it.
   FIXED: tools/stmt_digest.py gains an `op:` mode pinning DECLARATIONS.
   Negative control: the kill-shot edit moves emb_in's digest
   7fe3541382ed3df97047978e2f7d3943 -> 71d6c4d14d137b4977b38b554c3a8c86.
   Now pinned: emb_in, emb_in0, emb_in1, ThC, predC, join_dgst, c10_n/len/k.

   MY "FORK-GATE PARITY" COMMIT MESSAGE (9f3466a) WAS FALSE.  I ported the
   empty-census guard and the scratch purge and called it parity; the fork gate
   had NEITHER PHASE 1b NOR 1c, so its capstones could be weakened to
   `true. trivial.` and stay GREEN.  Actually ported now, with
   cert-statements-fork.tsv.

   THE LEDGER TOTAL HAS BEEN WRONG FOUR TIMES: 8 -> 27 -> 71 -> 136.
   Run 5 found that `op [lossless|full|uniform]` GENERATES an axiom apiece and
   was never counted -- 61 of them in the split cone alone.  Each previous total
   was published as authoritative.  The pattern is not that I keep miscounting;
   it is that a TEXTUAL census has no completeness argument, and I kept quoting
   its output as if it did.  The baselines now say so in their own headers, and
   name the categories STILL uncounted (nested-clone obligations, section
   `declare module` hypotheses, subtype non-emptiness, control-file cones).

   ALSO FIXED THIS ROUND:
     * REMOVALS ARE NOW FATAL.  They were NOTE-only.  Converting a refined const
       to a definition (e.g. `p_tgts := 0`) made its census row vanish quietly
       while making the premise `c <= p_tgts` false -- a vacuous theorem, scored
       as a "tightening".
     * PHASE 1c had no row-count guard (delete a row, unpin that lemma) and its
       read loop dropped an unterminated last line (delete the trailing newline,
       unpin the last lemma).  Both closed.
     * stmt_digest's comment stripper SPLICED tokens: `f(* *)x` and `fx` -- a
       different parse -- digested identically.  cert_cone.py already emitted a
       space; stmt_digest now does too.

   WHAT RUN 5 CONFIRMED SOUND, read line-by-line: join_dgst_inj,
   ThC_coll_projects, R_int_WOTSTW's grind/qs simulation, all six FX hop
   statements, the capstone hop arithmetic (including GROUNDED's Q <= Q
   instantiation), equiv postcondition strengths, and the adversary class.
   No broken proof step was found in five rounds.  THE MATHEMATICS HAS HELD
   THROUGHOUT; every defect has been in the claims about it or the machinery
   around it.
   ========================================================================== *)

(* ==========================================================================
   SECTION 33 (2026-08-01) — RUN 6.  THE GATE ENFORCED 98 OF ITS 136 BASELINE
   ROWS, AND I HAD NO IDEA.

   FINDING (internal swarm; TWO EXECUTED EXPLOITS, not an argument).  Both gates
   projected the live census AND the baseline through
       awk '{print $1"\t"$2"\t"$3}' | sort -u
   discarding the line number.  `sort -u` also discards MULTIPLICITY, so the
   split baseline's 136 data rows enforced only 98 KEYS (fork: 140 -> 102).  Any
   assumption whose (file, kind, name) triple already occurred was invisible IN
   BOTH DIRECTIONS.  Same-file name reuse is the NORMAL SHAPE of this tree:
   KeyedHashFunctions.eca alone carries `op [lossless] din` 16 times in 16
   distinct nested scopes, `dkey` 19 times, `dout` 4 times.

   DEMONSTRATED, on a copy:
     REMOVAL  -- drop `[lossless]` from 15 of the 16 `din` declarations: the
                 census falls 136 -> 121 rows and the gate prints `removed=0`.
                 That is run 5's "REMOVALS ARE FATAL TOO" failing to fire on a
                 15-row disappearance.
     ADDITION -- append `theory SneakyScope. axiom valid_fidxvals_idxvals :
                 false. end SneakyScope.` to FORS_ES.ec, a file that ALREADY owns
                 that name: the census gains a row and the gate prints `added=0`.
                 "ADDITIONS FATAL" defeated by an `axiom false`.

   FIXED: both gates now compare MULTISETS (`sort | uniq -c`), which keeps the
   line-number independence the projection was introduced for while restoring
   multiplicity.  Verified against BOTH exploits: the removal now reports
   `-16 ... op-annotation:lossless din`, the addition `+2 ... axiom
   valid_fidxvals_idxvals`.  All 136 / 140 rows are now enforced.

   AND MY RUN-5 "REMOVALS ARE FATAL" WAS SPLIT-ONLY.  cert_gate_fork.sh still
   printed a bare NOTE with no `fail=$((fail+1))`.  Third occurrence of
   fix-one-gate-leave-the-sibling.  Now fatal on both.

   THE LEDGER NUMBER WAS WRONG A FIFTH TIME -- in a new way.  Previous rounds
   found the CENSUS undercounting (8 -> 27 -> 71 -> 136).  This round found the
   GATE enforcing less than the census reports: 98 of 136.  So "136" was true of
   the baseline FILE and false of what was actually checked.  I have now been
   wrong about this quantity five times, in four distinct ways, and each time I
   published the figure as settled.  The number is not the problem; treating any
   output of a textual, unproven-complete procedure as settled is.

   PROVIDER REFUSAL, RECORDED HONESTLY.  Run 6's GPT-5.6 leg was blocked by the
   provider's safety filter (flagged as possible cybersecurity risk).  It was NOT
   rephrased to evade the block.  Run 6 therefore ran with ONE external leg plus
   the internal swarm, and run 5 likewise had one.  Cross-leg divergence has been
   the most informative signal in every round; two rounds without it is a real
   weakening of the method, not a footnote.
   ========================================================================== *)

(* ==========================================================================
   SECTION 34 (2026-08-02) — RUN 7.  ONE NEWLINE DEFEATED THE ENTIRE CENSUS.

   KILL SHOT (Kimi K3, reproduced here).  tools/cert_cone.py matched every
   pattern PER LINE.  EasyCrypt's grammar is newline-insensitive, so

       proof. admit
       .

   COMPILES and the census reported NOTHING.  Same for `admitted` + newline + `.`,
   `axiom` + newline + name, and refined constants split before `as`.  SIX ROUNDS
   hardened this census -- `admit.` then `admitted.` then mid-line admits -- and
   every one of those fixes stayed WITHIN A LINE.  Nobody probed the terminator on
   the NEXT line.  VERIFIED both halves here: EasyCrypt accepts the construct, and
   the census emitted zero rows for it.
   FIXED: census now runs whitespace-normalised over comment-stripped text, with
   line numbers from match offsets.  Re-run over both trees: 136 / 140 rows,
   added=0 removed=0 -- so the hole was REAL AND EXPLOITABLE BUT UNEXPLOITED.

   SECOND KILL SHOT (GPT-5.6, reproduced).  `axiom k_val : k = 12.` makes the
   deployed theorem VACUOUS -- its premise `k = c10_k` (c10_k = 13) becomes
   unsatisfiable -- while every digest, census row and control is unchanged.  The
   census records the NAME of a value axiom, never its STATEMENT.  FIXED: all
   seven value axioms are now digest-pinned (k=13 -> f7d8e6da..., k=12 ->
   b08a9d3f...).

   THIRD: `join_dgst` WAS NEVER PINNED, though section 32 claimed it was.
   stmt_digest terminated the declaration at the first `.`, which lands INSIDE
   `MDigestBlock.insubd`, so the digest covered `... = MDigestBlock.` and the
   whole body -- on which join_dgst_inj and the S-TCR projection rest -- was free.
   Kimi reproduced it: body replaced by `insubd []`, digest unchanged.  FIXED.

   OPERATIONAL FINDINGS THAT INVALIDATE RECEIPTS, NOT PROOFS:
     * NO GATE PINNED THE TOOLCHAIN.  This container runs r2026.02; the reviewer's
       ambient build is r2026.06, under which FOUR closure files fail as TARGETS
       (WOTS_TW_ES:1637, XmssmtCC_All:984, RtopCSoundness:687, FxChain:615).
       Both gates now print the tree SHA and the EasyCrypt GIT hash, so a receipt
       states what produced it.  A green receipt without those is not reproducible.
     * cert_gate_fork.sh did `cd /work` with no failure check and no tree
       identity, so on a host without /work it certified whatever CWD it landed
       in -- demonstrated over a garbage tree containing `axiom backdoor : false.`
       with exit 0.  Now guarded.
     * Both gates wrote FIXED world-writable /tmp paths with no write check; a
       pre-squatted read-only file reproduced GREEN over a new `false` axiom.  Now
       mktemp -d with a trap.
     * An EMPTY declared reason matched any failure (the split only rejected the
       literal "-").  [CORRECTED 2026-08-02: "Now both" was FALSE -- the edit
       landed on the ACCEPT side of the split's condition, so an empty reason was
       explicitly accepted, and the fork had no check at all.  Both now reject it
       up front.]

   AND A SIXTH LEDGER MISCOUNT, INSIDE THE SECTION TALLYING THE PREVIOUS FIVE.
   Section 32 said `op [lossless|full|uniform]` contributed 61; it is 65 (61
   lossless + 2 full + 2 uniform).  71 + 65 = 136 checks out; 71 + 61 = 132 does
   not.  Corrected in place.
   ASSUMPTION COUNT: the two legs now diverge -- Kimi 147 (136 + 11 clone-carried
   instances, obtained by compiling an admitted-harness and reading EasyCrypt's
   `print` per clone), GPT-5.6 168 (32 further generated obligations).  I am NOT
   adopting either figure without reproducing its method.  What both agree on,
   and what I now state instead of a number: THE TEXTUAL CENSUS UNDERCOUNTS, AND
   CLONE-CARRIED OBLIGATIONS ARE INVISIBLE TO IT BY CONSTRUCTION.

   WHAT HELD, AGAIN.  Kimi read the FORS/Gproc leg and the capstone arithmetic
   line-by-line: faithful oracle simulation, a complete covered/not-covered split,
   no dropped or double-counted term, module restrictions a subset at every apply
   site, no admits in that leg.  Seven rounds, zero broken proof steps.
   ========================================================================== *)

(* --- SECTION 34 ADDENDUM: CLONE DISCHARGE IS NOW A CENSUS CATEGORY ---------
   The run-7 swarm found a THIRD kill shot, and its refuter VERIFIED it by
   mutating the real tree: deleting a name from a clone's `proof` clause -- or
   deleting `proof *.` together with its `realize` block -- converts a PROVED
   obligation into an ASSUMED axiom with ZERO delta in every gate phase.
   At base-c10-split/SPHINCS_PLUS.ec:392, `print HA.Adrs.inhabited` flipped from
   `lemma` to `axiom [prove]` with a byte-identical statement, the file still
   compiled rc=0, and PHASE 2 reported added=0 removed=0 while 1b/1c/2b were
   byte-identical.  That defeats the ENTIRE RATIONALE for making removals fatal
   in run 5.
   POPULATION: 77 clone sites in the 32-file cone [CORRECTED 2026-08-02:
   the "80" was a raw grep including COMMENTS -- the same prose-counting error
   section 24 records.  77 sites, 77 census rows after the indented-clone fix] -- 57 `proof *`, 12 partial
   named lists, 11 with no proof clause at all; 9 propagate stdlib-declared
   obligations (Subtype.inhabited / FinType.enum_spec) that could never acquire a
   census row under the old scope note.  Live carried axioms confirmed by
   `print`: CntrFT.enum_spec (counter finiteness -- the basis of Grind's
   totality), HA.Adrs.inhabited, WAddress.inhabited.  None is FALSE; the defect
   is that the ledger cannot see them, cannot see them change, and cannot see a
   proof become an assumption.
   FIXED: `clone-discharge:<mode>|realize:<names>` is now a census kind.  The
   verified mutation moves its row from
     clone-discharge:star|realize:Adrs.inhabited.,ge1_l
   to
     clone-discharge:list:ge1_l|realize:ge1_l
   Baselines regenerated: split 136 -> 207 rows (71 clone-discharge), fork
   140 -> 210 (70).
   [CORRECTED 2026-08-02, run 10, found independently by BOTH reviewers: those
   two figures are STALE.  The regenerated baselines of that commit were 213 and
   216, not 207 and 210 -- I quoted an intermediate count from before the
   indented-clone fix landed.  A seventh wrong total, in the very section that
   records the sixth.  Current run-10 figures: ledger 213 split / 216 fork,
   meaning 324 / 357, totals 537 / 573.]
   [ALSO CORRECTED: the breakdown "57 `proof *`, 12 partial named lists, 11 with
   no proof clause" sums to 80, not 77, and survived the sentence that corrected
   80 to 77.  Measured now: 54 star, 12 list, 9 none, 2 empty = 77.]  LIMIT, stated: the proof-list extraction is textual, so
   `by`/`smt` tokens from `proof X by smt(..)` land in the key.  Noisy, but sound
   for CHANGE DETECTION, which is what the row is for.
   AND A FALSE SOUNDNESS PRINCIPLE IN PROVENANCE.md, corrected: it asserted "No
   EasyCrypt clone can weaken an inherited axiom".  That holds only for axioms
   NAMED in the `proof` clause; an omitted one is installed verbatim with no
   obligation, even when false (`clone TT as T1 with op c <- -5.` yields
   `axiom ge0c: 0 <= -5`, from which `false` follows).  It was load-bearing prose
   in a DO-NOT list. ------------------------------------------------------- *)

(* ===========================================================================
   SECTION 35 (2026-08-02) — RUN 9 RECEIPTS ARE GREEN, AND THE IDENTITY LINE
   THEY CARRY WAS AN IDENTITY OF (TREE, LOCALE) RATHER THAN OF THE TREE.

   Both gates at 6d6b64f:
     split  22 targets OK | pins 49=49 | cone keys 171=171 rows 213=213
            added=0 removed=0 | canary caught | controls 4 | RESULT GREEN EXIT=0
     fork   19 closure OK | pins  7=7  | cone keys 174=174 rows 216=216
            controls 12=12 | CERT_FAILURES=0 EXIT=0

   Then I tried to confirm the split receipt belonged to THIS tree by
   recomputing its INPUTS_SHA256 on the host, and got a DIFFERENT value:
       container (gate) 45c4a166621aadf4a100aae46bb8263f
       host             fa7a6e6f2d39217aff2e7ea3a780d2ef
   on a tree `git status` reported clean in both cone directories.  On the
   evidence available at that moment the correct reading was "the GREEN receipt
   is stale", and I was one step from recording that.

   CAUSE.  The hash is over `sha256sum` lines emitted in `sort -u` ORDER.  The
   file SET was identical (32 = 32); only the ORDER differed, in exactly the
   three names where glibc's en_US.UTF-8 collation disagrees with POSIX about
   `_` and case:  STCR_C, XmssmtCC_All, XmssmtCCCharged.  The container runs
   LC_ALL unset -> POSIX; the host runs en_US.UTF-8.

   WHY IT MATTERS beyond the scare.  The line exists so a third party can bind a
   receipt to a tree without a VCS.  A value that changes with the reader's
   locale cannot do that: it produces false DRIFT alarms (what happened here)
   and, worse, invites the reflex of "recompute until it matches", which is how
   a real drift gets waved through.  It is not a soundness hole -- for a FIXED
   locale the map from content to hash is still injective -- but it is a
   reproducibility hole in the one artifact whose whole job is reproducibility.
   Secondary: `sort -u` de-duplicates by COLLATION equality, and UTF-8 locales
   treat some punctuation as ignorable, so the control inventory count at
   :207/:198 could silently merge two distinct control paths.  That direction
   fails closed (count drops below the committed expectation), but it would fail
   for a reason unrelated to the thing being tested.

   FIXED: `export LC_ALL=C` at the top of both gates.  Verified BOTH ways, on
   the host, with the scripts' own construction:
     split  LC_ALL=C -> 45c4a166...  (= the container receipt)
     fork   LC_ALL=C -> 1cfc5a69...  (= the container receipt)
            fork default locale -> cfb14d3f...  (the divergence, reproduced)
   So both run-9 receipts DO belong to tree a71c701d, and from now on the host
   and the container agree by construction.

   CAVEAT I am not going to paper over: this was found by accident, while doing
   something else, at round 9.  Nine adversarial rounds had read these scripts.
   Environment-dependence of the receipt was not on anyone's checklist -- mine
   or the reviewers'.  The category "what else does this receipt silently depend
   on (locale, PATH, python version, filesystem order, TZ)?" is now an explicit
   review question, and it is open: only locale has been audited.
   ======================================================================= *)

(* ===========================================================================
   SECTION 36 (2026-08-02) — RUN 10.  TWO INDEPENDENT REVIEWERS, TWO DIFFERENT
   KILL SHOTS, BOTH REAL, AND BOTH IN THE SAME CLASS: THE CENSUS KEYED ON NAMES
   WHERE THE ASSUMPTION LIVES IN THE TEXT.

   Target: commit 3a9ed6a3, tree cabe932a.  Kimi K3 and GPT-5.6 got byte-
   identical prompts, separate detached worktrees, no sight of each other.
   Both returned BROKEN.  They did not agree on the finding -- which is the
   useful case (section 30's lesson) -- but the two findings are the same defect
   seen from two sides.

   KILL SHOT 1 (Kimi K3), CONFIRMED BY EXECUTION.  The one thing this whole
   development narrates -- "ONE real admit, exactly MM45's encode-injectivity
   gap" -- had its STATEMENT pinned by nothing.
     base-c10-split/WOTS_TW_ES.ec:1505  lemma nhchwcoll_hchwpre_msg
   Replace premise 4
     !has_chwcoll ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'
   with `true`, adapt the proof to a single `admit.`, and:
     * PHASE 1  -- COMPILES, rc=0 (measured, not argued).  THE ARTIFACT IS NOT IN
       THE TREE: `_mut_base/` is a gitignored scratch copy, so this receipt was
       un-reproducible from a clean checkout -- the same defect section 25
       condemns, committed in the sentence claiming "measured, not argued".
       Reproduce with `bash tools/repro_killshot1.sh` (committed 2026-08-02),
       which applies the two-line diff to a temp copy and compiles it.
     * PHASE 1b -- checks three capstone NAMES; unaffected
     * PHASE 1c -- all 12 pins for that file are `op:` declarations; not one
                   lemma statement in WOTS_TW_ES.ec was pinned
     * PHASE 2  -- row was (file, 'admit', nhchwcoll_hchwpre_msg): BYTE-IDENTICAL
     * PHASE 2b/3 -- unrelated.  GREEN.
   [UPGRADED 2026-08-02, after the full run: kill shot 1 compiles the ENTIRE
   CLOSURE, not just its own file.  Against the mutated base, all 22 certified
   files compile OK -- XmssmtCC_All 850s, RtopCSoundness, FxChain, all three
   capstones, C10DeployedInstance, C10DeployedCapstone, C10SpecControls.  The
   mutated tree differs from the certified one in exactly TWO LINES of ONE file:
     WOTS_TW_ES.ec:1509  `!has_chwcoll ...`  ->  `true`
     WOTS_TW_ES.ec:1512  proof adapted to a single `admit.`
   [The `admit.` itself is at :1513; :1512 is the `move=>` line -- run 12 caught
    the off-by-one.  The two-line diff is unchanged.]
   So this was not "a file compiles"; it was a complete, working, invisible
   weakening of the one assumption the whole receipt narrates.  PHASE 1 green,
   census row byte-identical, 49 pins byte-identical.]
   The assumption silently becomes "a chain preimage exists whenever
   P m /\ P m' /\ m <> m'" -- no collision-freeness side condition, almost
   certainly FALSE for the real scheme -- while every receipt keeps describing
   it as MM45's encode-injectivity obligation.  Nine rounds fixed
   "names-not-statements" for the capstones and stopped one lemma short of the
   only assumption whose content matters.

   KILL SHOT 2 (GPT-5.6), CONFIRMED CENSUS-BLIND, **NOT COMPILE-VERIFIED**.
   [CORRECTED 2026-08-02, run 11, GPT-5.6's own follow-up leg: this section later
   called items 1 and 2 "working exploits".  Only item 1 earned that.  As written
   the item-2 edit does NOT compile: `realize ge0_pstcr by exact: ge0_ptgts`
   (WOTS_C_Real.ec:357) consumes ge0_ptgts as NONNEGATIVITY, and the edit changes
   it to an equality, so `exact:` fails; it needs a co-edit to `by smt(ge0_ptgts)`
   which I never ran.  What IS measured is the census blindness.]  A refinement predicate
   is an axiom, and EasyCrypt demands no inhabitation proof for it.
     cdrafts-split/WOTS_C_Real.ec:340   const p_tgts : { int | 0 <= p_tgts } as ge0_ptgts.
   Strengthen to `{ int | p_tgts = 0 }`.  The deployed capstone's premise
   `c <= p_tgts` (C10DeployedCapstone.ec:80) then contradicts `1 <= c`
   (base-c10-split/WOTS_TW_ES.ec:79): the theorem is VACUOUSLY TRUE.  Old census
   row, both ways: `refined-const  ge0_ptgts`.  All 41 refined-const predicates
   were unpinned, and PHASE 1c cannot address them anyway -- the manifest key is
   file::name and the const is named `n`/`p_tgts`, not `ge1_n`/`ge0_ptgts`.
   The general form is worse than the instance: scratch/refine_contra_probe.ec
   compiles rc=0 and derives `false` from `{ int | 1 <= bad /\ bad <= 0 }`, so a
   contradictory refinement makes the ENTIRE closure vacuous with no census delta.

   MY OWN FINDING, AND ITS HONEST LIMIT.  Module bodies and module types had zero
   coverage in every phase.  Narrowing the capstone forger's restriction
   (XmssmtCC_All.ec:9563, Adv_EUFCMA_C: `{ O.sign }` -> `{ }`) left all 49 pinned
   digests and all 213 rows byte-identical.  BUT IT DOES NOT COMPILE: XmssmtCC_All
   fails with `invalid module application` at :10018 (a concrete module ascribed
   to that type), and 9 dependents fall with it.  So this is a demonstrated
   TOOL-BLINDNESS, not a demonstrated working exploit -- unlike kill shots 1 and 2,
   which are.
   [CORRECTED with the line above: kill shot 1 is a working exploit (closure-wide
   compile measured); kill shot 2 is census-blindness measured and compilation
   NOT measured.  Do not read "both" into this paragraph.]  I am recording it at that strength and no higher.

   FIXED (tools/cert_cone.py): three content digests, each closing a demonstrated
   bypass rather than a hypothesised one --
     admit:<statement-digest>        01a2cfed95f4 -> 8f1e32428803 on kill shot 1
     refined-const:<predicate-digest> 720f257d2456 -> 30c4f3dc03fe on kill shot 2
     module:/module-type:<body-digest>  paired remove/add on the restriction edit
   plus two blind spots the reviewers found in passing: `clone include X` recorded
   the KEYWORD as the name (5 sites, TweakableHashFunctions.eca:611/658/710/758/837
   -- swapping the included theory was invisible), and `declare module A <: T {..}`
   (3 sites) matched no pattern at all.  Statement pins added for the admitted
   lemmas themselves: split 49 -> 50, fork 7 -> 9.
   Ledger 213 split / 216 fork UNCHANGED -- these are meaning-carriers and content
   digests, not new assumptions.  Totals 537 / 573.

   GATE ROBUSTNESS, from GPT-5.6's environment sweep:
     * `$TMPD` was unquoted -- a TMPDIR containing whitespace could suppress
       PHASE 2 entirely.  Quoted.
     * the .eco purge was `rm -f ... || true`: a purge that FAILS is exactly the
       stale-cache green it exists to prevent.  Now verified (ECO_REMAINING must
       be 0) and extended over the data-driven control inventory, which the
       hardcoded three-glob list could not see.
     * cert_gate_split.sh had no `cd` and trusted the caller's directory.  Now
       asserts its inputs are present before running a phase.
     * PHASE 2b's canary matched `$2=="admit"` exactly, which the new
       `admit:<digest>` kind would have broken -- caught before committing, by
       reading the pattern rather than the exit status.
     * NEW PHASE 2c: a digest that stops DISCRIMINATING is invisible to
       removal-fatality (both rows still there, both still one row).  Two
       fixtures differing in one token now assert the module-type digest
       separates them.

   MEASURED WHILE DOING THIS, worth keeping: EasyCrypt fails SILENTLY on a stale
   .eco -- rc=1 with ZERO diagnostic lines (not one `[critical]`).  I lost twenty
   minutes reading that as "the mutation breaks the closure" before purging the
   copied .eco and getting rc=0.  Every FAIL from a copied tree must be re-tested
   after a purge before it is believed.

   A NEAR-MISS I ALMOST BANKED.  My first test of the admit-statement digest
   printed DISCRIMINATES: False, and I nearly recorded the fix as ineffective.
   The test was wrong, not the fix: I mutated the first TEXTUAL occurrence of the
   premise, which belongs to `nhchwcoll_hchwpre` -- a different lemma earlier in
   the file.  Re-run against the correct span: 01a2cfed95f4 -> 8f1e32428803.

   STILL OPEN, stated plainly, both reviewers converging:
     * The S-TCR(+C) term in both capstones is a BESPOKE game, not a standard
       assumption.  XmssmtCC_All.ec:8710-8719 says so in the tree: "still awaits
       reduction to a standard assumption".  The game-level reduction is
       explicitly deferred (WOTS_C_Interactive.ec:520-527), and the stock game's
       tweak-only freshness is replaced by (member,tweak) freshness.  GPT-5.6
       calls this the kill shot; I record it as a KNOWN, DISCLOSED gap that the
       tree already documents, but my review prompt's phrase "the S-TCR repair is
       ThC_coll_projects" was too confident: ThC_coll_projects discharges the
       COLLISION ALGEBRA, not the probability reduction.
     * C10DeployedCapstone.ec:32-40 already concedes that a CONSTANT `emb_in`
       satisfies every premise while collapsing ThC and making the S-TCR term
       trivially winnable.  Injectivity of the deployed `emb_in` is not assumed
       and not discharged.  `c10_embg_inj` (C10DeployedInstance.ec:336) is still
       applied nowhere.
     * INPUTS_SHA256 is printed and NEVER COMPARED.  No expected value is
       committed anywhere, so no run can fail on identity drift.  Committing one
       requires a file OUTSIDE the hashed set (the log is inside it -- see the
       self-reference in section 35).  NOT DONE THIS ROUND.
     * Nested-clone obligations (18 Subtype + 6 FinType sites), clone
       `with`-clause operands, and abstract-carrier declarations remain
       uncounted.  One census row per clone site regardless of how many
       obligations the mode leaves installed.
     * cdrafts-split/C10DeployedGeometry.ec is a DIFFERENT file from this one:
       same 29 declarations, but the split copy carries the route-(D) lemma
       statements (dfC0/dfC1) while this fork copy still has the pre-split single
       `dfC` versions, and this narrative (sections 20-36) exists only here.  A
       reader pointed at "sections 20-36" is reading the file with the SUPERSEDED
       lemmas.  Not reconciled this round.
   ======================================================================= *)

(* ===========================================================================
   SECTION 37 (2026-08-02) — RUN 10, POST-FIX.  THE HARDENING ITSELF HAD THREE
   DEFECTS, ALL FOUND BY RUNNING IT, TWO OF THEM IN GUARDS ADDED HOURS EARLIER.

   1. The PROVERS receipt hashed the EMPTY STRING (`e3b0c44298fc1c14 0
      configurations`): `easycrypt config` prints `known provers:` on STDERR and
      I wrote 2>/dev/null.  Run 8 found exactly this empty-input defect in the
      identity hash.  I reproduced it, in a line whose purpose was to make the
      receipt more honest, two hours later.  Corrected value: 25 configurations,
      0a5b3d54dcce300e.

   2. The .eco purge guard fired on its first outing — correctly, and on me.
      `ECO_REMAINING=34` after a purge that reported 0 deletions.  TaskStop on
      the host had killed the `docker exec` client but NOT the in-container
      script, whose orphaned compile kept writing into the tree the next run was
      purging.  Added a concurrency guard so a racy receipt cannot be produced.

   3. THE SAME GUARD THEN FAILED AGAIN FOR A DIFFERENT REASON: its purge was a
      GLOB (`scratch/*.eco`) and its check a recursive FIND, so 33 objects in
      scratch SUBDIRECTORIES (advprobe, audit0725, dsn, f1probe, f1probe/base3,
      incenc) failed a gate that had never tried to delete them.  A guard whose
      two halves disagree about scope reports a defect that does not exist,
      which is how guards get disabled.  Both halves are recursive now.

   AND A LATENT HOLE IN THE RUN-10 DIGESTS, found by testing the new code against
   a synthetic file rather than re-reading it: `_stmt_digest` degraded to the
   CONSTANT `nostmt` for an `admit.` inside a `theorem` (the inherited DECL regex
   lists lemma|equiv|hoare|axiom|module|op|pred and NOT theorem) and for an
   `admit.` inside a `realize <axiom>` block (the enclosing name is an axiom, not
   lemma-shaped).  Either way the row LOOKS pinned and is not — the exact failure
   PHASE 2c exists to catch, in the one place 2c was not looking.  Neither cone
   has a live instance (0 `theorem`s), which is why nothing surfaced it.
   FIXED: DECL extended (theorem|phoare|const|abbrev|type), `_stmt_digest` falls
   back to the enclosing declaration span, PHASE 2c now canaries the ADMIT digest
   with two fixtures differing only in a premise (the kill shot in miniature),
   and a live `admit:nostmt` row is a hard failure.  Verified this moves NO live
   row: 537 = 537, zero delta against the baseline.

   IDENTITY IS NOW ENFORCED, AND COVERS THE MACHINERY.  INPUTS_SHA256 was printed
   and compared to nothing — a receipt no run can fail on is decoration.  The
   expected values live in cert-identity.tsv, deliberately OUTSIDE the hashed set
   (storing them inside reproduces the self-reference section 35 records).  The
   hashed set now also covers tools/cert_cone.py, tools/stmt_digest.py, the
   control inventory and the gate script itself:
   [CORRECTED 2026-08-02, run 12: "the control inventory" was true of the SPLIT
   gate only.  cert-controls-fork.tsv DOES NOT EXIST -- the fork gate's controls
   are inline --
   [CORRECTION OF THE CORRECTION, run 13: THAT IS FALSE.  cert-controls.tsv (no
   -fork suffix) EXISTS and the fork gate reads it at PHASE 3.  I searched for
   the wrong filename, found nothing, and turned its absence into a claim about
   the gate's design -- then wrote that claim into this log.  The fork identity
   hashed neither the manifest nor any control source, so all twelve fork
   controls' declared reasons were editable with zero identity delta.  Both are
   hashed now.] so the fork identity hashed no control inventory and the run-10
   "data-driven purge coverage" was dead code behind `2>/dev/null`.  Worse, the
   fork identity resolved TWO include dirs while the gate COMPILED with three:
   see section 39.] blinding the census tool is a
   strictly easier attack than editing a proof, and PHASE 2b/2c only canary two
   specific behaviours of it.

   WHY THIS MATTERS MORE THAN THE PER-DECLARATION DIGESTS.  The split cone holds
   567 `op` declarations, 226 `type`, 12 `theory`, 3 `abbrev`; PHASE 1c pins 50.
   Enumeration will never close that surface.  The identity comparison closes it
   structurally — no text change in a cone file or in the machinery can be silent
   — and the per-declaration digests keep the job they are actually good at:
   saying WHAT changed rather than only THAT something did.

   RECEIPT, split tree, tree 1c90d0e7 (before this section was written):
     22 targets OK | pins 50=50 | cone 496 keys / 537 rows | added=0 removed=0
     ledger 213 | meaning 324 | 2b caught | 2c discriminates | 4 controls
     RESULT GREEN, EXIT=0
   The fork gate of that same run FAILED on defect 3 above and on nothing else.
   ======================================================================= *)

(* ===========================================================================
   SECTION 38 (2026-08-02) — RUN 11.  TWO LEGS, TWO KILL SHOTS, AND ONE OF THEM
   WAS ALREADY LIVE IN THE MANIFEST.

   Target: commit f564e8db, tree 1c90d0e7.  Byte-identical prompts, separate
   detached worktrees, mutually blind.  Both returned BROKEN, again with
   DIFFERENT findings, and again the two findings are one defect seen twice:
   THE GATE PINNED CLAIMS WITHOUT PINNING THEIR SUBJECTS.

   KILL SHOT 1 (Kimi K3) — INCONSISTENCY VIA AN ABSTRACT CONSTANT.
     base-c10-split/SPHINCS_PLUS.ec:142   const pkcotype : int.
                                     ->   const pkcotype : int = chtype.
   makes the PINNED axiom at :165
     axiom dist_adrstypes : uniq [chtype; pkcotype; trhxtype; trhftype; trcotype]
   FALSE (duplicate list head).  `false` is then derivable in every file that
   requires SPHINCS_PLUS, so all three capstones become theorems of an
   inconsistent theory — the single failure mode that destroys everything at
   once.  Measured: `chtype` and `pkcotype` appear in ZERO rows of
   cert-statements-split.tsv and ZERO rows of cert-baseline-split.tsv.  An
   abstract `const` is not a refined constant (`{..} as`), not an op-annotation,
   not a module, and not one of the 46 hand-picked pinned ops: it fell between
   every category ten rounds had built.  The gate pinned the SENTENCE and left
   its NOUNS free.

   MEASURED, INCLUDING THE PART THE REVIEWER GOT WRONG.
     * It COMPILES: all four base files build against the mutated SPHINCS_PLUS.
     * The theory IS inconsistent: a probe requiring only SPHINCS_PLUS proves
       `false` by `smt(dist_adrstypes ...)` on the mutated base and FAILS to on
       the pristine one.
     * A FINGERPRINT worth remembering: compile time COLLAPSES, because once
       `false` is derivable every smt goal closes instantly --
       FL_SL_XMSS_MT_ES 555s -> 55s, SPHINCS_PLUS 169s -> 8s.
     * BUT THE CLAIM "every phase stays silent" IS FALSE.  Kimi argued PHASE 3
       would stay quiet because "the prover sees two uninterpreted constants".
       It does not: with a BODY, smt uses it.  `scratch/vac_probe_full.ec` is a
       MUST-FAIL control asserting `false` is unprovable from the whole closure;
       on the mutated tree that control COMPILES, and a MUST-FAIL control that
       compiles is reported as `FAIL control ...: MUST-FAIL but COMPILED`.
       THE GATE GOES RED — via the two-sided vacuity control, not via the census.
       That control was added precisely because a green compile is not evidence
       of content, and this is the first time it has caught a real attack.
   So the honest scoring is: census blindness CONFIRMED and now fixed; theory
   inconsistency CONFIRMED; "gate stays GREEN" REFUTED BY MEASUREMENT.

   KILL SHOT 2 (GPT-5.6) — SCOPE DECOY, AND A PIN THAT WAS ALREADY MIS-AIMED.
   tools/stmt_digest.py resolved a pinned name with `re.search` — the FIRST
   textual match, any indentation, no scope or kind discipline.  Its constructed
   attack puts `abstract theory D. op c10_k : int = 13. end D.` above a real
   `op c10_k : int = 12.`; the pin reproduces, the capstone goes vacuous.
   CHECKING THAT MECHANISM AGAINST THE ACTUAL MANIFEST FOUND THE CLASS ALREADY
   REALISED, and on the worst possible symbol:
     pin `op:base-c10-split/WOTS_TW_ES.ec::P` digested
        op P x <- 0 <= x < w            (BaseW Subtype clone operand, :162)
     while the +C GATE PREDICATE
        op P (m : msgWOTS) : bool = digitsum (encode_msgWOTS m) = target_sum.
     at :654 — the predicate deciding which messages pass the counter gate, the
     `P` in the admitted lemma's premises, and the `P` in `predC = P` — was
     pinned by NOTHING.  A `<-` operand binding is never the declaration a pin
     means.  Exactly ONE of the 50 pins moves under the fix:
     a61d325021beb509... -> fe55dd1ef00e83fb...  The other 49 and all 9 fork
     pins are unchanged, which is what makes it a correction and not a
     re-baseline.

   BOTH LEGS, INDEPENDENTLY, ON THE CLONE PARSER.  The tail ran to the next
   COLUMN-0 keyword, so inside an INDENTED `abstract theory` it overran into a
   later declaration's `proof.` and the recorded discharge mode became a function
   of unrelated following text.  Two live instances — Grind.ec:62 (`clone import
   FinType as CntrFT with type t <- cntr.`, NO proof clause at all) and
   STCR_C.ec:65 — were recorded as `empty` when they are `none`: EVERY inherited
   obligation installed as an axiom, the most assumption-heavy mode, labelled as
   the emptiest.  And `\bproof\b(.*?)\.` stopped at the first dot, so
   `proof Alphabet.enum_spec, ge0_n` recorded `list:Alphabet` and any retarget to
   another `Alphabet.*` left the row byte-identical.  Both fixed by taking the
   clone STATEMENT span (depth-0 terminating dot) and stopping the proof list at
   `rename`, which follows `proof` in the grammar.  Measured delta: exactly five
   rows, all corrections; mode distribution 54 star / 12 list / 11 none / 0 empty.

   FIXED, AND WHAT EACH FIX ACTUALLY DOES:
     * abstract-const/op/type rows with declaration digests — 106 new rows (13
       const, 47 op, 46 type).  The pkcotype edit is caught as a FATAL REMOVAL
       rather than a changed digest: a parameter that acquires a body stops being
       a parameter, so its row disappears, and removals have been fatal since
       run 5.  Verified both ways on a mutated copy.
     * pin resolution skips `<-` operand bindings and reports genuine ambiguity
       as AMBIGUOUS-n-DECLARATIONS instead of silently taking the first.
     * clone statement span + qualified proof names (above).

   AND A RECEIPT THAT COULD NOT BE REPRODUCED FROM THE TREE (Kimi).  Section 36
   said kill shot 1 was "measured, not argued" and cited `_mut_base/WOTS_TW_ES.ec`
   — a GITIGNORED scratch copy.  That is the defect section 25 condemns,
   committed inside the sentence claiming measurement.  `tools/repro_killshot1.sh`
   now applies the two-line diff to a temp copy and prints the census rows; run
   from a clean checkout it reproduces the recorded digests exactly
   (01a2cfed95f4 -> 8f1e32428803).  Kimi independently measured the same
   post-fix digest from the description alone.

   ALSO CORRECTED THIS ROUND:
     * Section 36 said "items 1 and 2 are working exploits".  Only item 1 is:
       the item-2 predicate edit does NOT compile as written, because
       `realize ge0_pstcr by exact: ge0_ptgts` consumes ge0_ptgts as
       nonnegativity and the edit makes it an equality.  Census blindness is
       measured; compilation is not.  (GPT-5.6 caught my overstatement.)
     * Section 28's "It is load-bearing for the top result" now carries a
       SUPERSEDED marker pointing at section 29, which retracted it verbatim.
       Section 31 wrote the marker rule and it had never been applied to its own
       predecessor, so a reader arriving in order read a retracted claim as
       current.

   NOT CLOSED, and now on the record:
     * The concurrency guard is TOCTOU — one `ps` snapshot, then a long unlocked
       compile.  It catches the case that actually happened (an orphan already
       running) and not a compile started after the snapshot.
     * Module digests start at the NAME, so the `local` / `declare` modifier is
       outside the digest: a scope change is invisible.
     * Kimi's ledger recount: 143 real assumptions (136 fact rows + 7 nested-clone
       installs the mode rows hide) + 102 parameter carriers + 324 meaning rows.
       GPT's: >= 165/169 by a different decomposition.  They disagree, as the
       previous pair did, and the baseline header keeps saying LOWER BOUND.
     * One review leg was refused by its provider on cyber-risk grounds.  Recorded
       as an unavailable leg; the prompt was not reworded to get around it.
   ======================================================================= *)

(* ===========================================================================
   SECTION 39 (2026-08-02) — RUN 12.  ONE LEG; THE HOLE WAS IN THE FORK GATE'S
   GEOMETRY.
   [HEADLINE CORRECTED, run 13, by two legs independently.  It read "THE FIRST
   ROUND THAT COULD NOT BREAK THE SPLIT GATE", which overstates this section's
   own body ("one leg, one round, and not a proof") -- and this file's own rule
   is that HEADLINES are what readers quote.  Worse, the criterion is close to
   vacuous: once the identity hashes every cone byte, NO in-cone edit can keep
   both identity and census green, so "could not break it" mostly restates the
   identity.  In that same round, `local clone` matching nothing at three
   IN-CONE SPLIT sites was itself a census break in the split tree.  The
   supportable claim is: one leg, in the include-geometry class, did not break
   the split gate in one round.  Run 13 then broke it outside the cone -- the
   control sources were never hashed at all.]

   Target: commit d52ac65, tree 2ac4ec22.  ONE leg only: the second reviewer's
   provider refused the prompt on cyber-risk grounds.  That is recorded as an
   unavailable leg; the prompt was NOT reworded to get around the refusal, so
   this round has half the usual coverage and should be read that way.

   THE SPLIT RESULT, STATED PLAINLY BECAUSE IT IS THE FIRST TIME: the leg
   reproduced both identities under LC_ALL=C, probed cwd / -I ordering /
   extension shadowing, and reported that it could find no edit keeping BOTH the
   identity and the census green on the split tree.  That is one leg, one round,
   and not a proof; it is still the first round where the split machinery held.

   KILL SHOT (fork gate) — THE HASHED SET AND THE COMPILED SET WERE DIFFERENT.
     cert_gate_fork.sh:49   INC="-I $B -I $D -I $L"          <- THREE dirs
     cert_gate_fork.sh:81   CERT_CONE_DIRS="base-c10-fork,cdrafts-fork"  <- TWO
     PHASE 2 (:195)         cert_cone.py's default            <- THREE
   EasyCrypt resolves a LATER -I ahead of an earlier one — ahead even of the
   target file's own directory (the leg compiled probes for this).  So a file
   planted in experiments/tcollres-leg/ silently overrides a same-named fork-cone
   theory in every PHASE 1 and PHASE 3 compile, while the identity — which never
   resolves there — hashes the pristine copy and still matches cert-identity.tsv.
   PHASE 2 keys rows by path and would normally see the flip; it does not for the
   SEVEN fork-cone files that carry zero census rows (BinaryTrees, MerkleTrees,
   C10DeployedGeometry, GFailCharged, SphincsC10CapstoneCharged, SphincsC10Content,
   XmssmtCCCharged) — and two of those are required directly by the charged
   capstone (SphincsC10CapstoneCharged.ec:51-52).  The split gate never had this
   hole because its compiled set and its hashed set are the same two directories;
   the fork port kept the historical three-dir INC and nobody intersected the two
   sets per file.  The end-to-end payload was NOT compiled — mechanism proven,
   specific edit not — and it is recorded at that strength.
   FIXED: the fork identity now resolves the same three directories it compiles.

   ALSO REAL, ALSO FIXED:
     * `local clone` matched NOTHING.  Three in-cone sites —
       OpenPRE_From_TCR_DSPR_THF.eca:720, FORS_ES.ec:2826, WOTS_TW_ES.ec:3176 —
       had no row of any kind, so deleting a `proof *.` there installs stdlib
       obligations as axioms with zero census delta.  Measured after the fix:
       exactly three new rows, no removals (643 -> 646).
     * `_stmt_digest` in cert_cone.py still resolved duplicate names BY POSITION.
       Run 11 fixed exactly this in tools/stmt_digest.py and left the twin in the
       other tool.  Latent today (zero duplicate names in either cone) and now
       reported as `ambig<n>` instead of silently digesting the first.
     * cert-controls-fork.tsv DOES NOT EXIST, so the run-10 "data-driven purge
       coverage" in the fork gate was dead code behind `2>/dev/null`.
     * The subtotal line reported `ledger=213 meaning=324` against a 643-row
       census: the 106 parameter rows added in run 11 were in the baseline and in
       NO subtotal.  A receipt whose parts do not add up to its total invites the
       reader to trust the total.  Now prints ledger / parameters / meaning / total.

   A CLAIM IN THE HEADLINE THEOREM'S HEADER WAS INCOMPLETE.  C10DeployedCapstone's
   residual list named the query bound, the encode bridge, N2 and the width
   premise, and never mentioned the unreduced bad event
      Q = Pr[EUF_CMA_Gproc_I(R_fors_p(F)).main() @ &m : res /\ !covered]
   which nothing bounds below 1.  SphincsC10CapstoneWired.ec:828-834 says it
   plainly ("if Q = 1 this bound is as uninformative as the free-real version
   was"); the deployed capstone — the one a reader is most likely to quote —
   did not repeat it.  Added.

   TWO MORE OF MY OWN CLAIMS CORRECTED:
     * Section 37 said the hashed set covers "the control inventory and the gate
       script itself".  True for the split gate, false for the fork gate.
     * Section 36 cited the admit at :1512; it is at :1513.

   POSITIVE RESULT ON THE MATHEMATICS, from the leg that went looking: the hop
   chain traced clean — no dropped or double-counted term, no wrong-direction
   inequality, no equiv postcondition weaker than its consumer, and no k-fold
   FORS amplification to attack (the routing relays into one ITSRC10 game).  The
   content-free directions remain the three already disclosed: the S-TCR term,
   the constant-emb_in collapse, and Q.

   STILL OPEN after this round: 349 clone `with`-operands undigested (including
   SPHINCS_PLUS.ec:633 `op valid_xidxvalsgp <- predT`, a validity predicate
   instantiated to constant-true through an operand nothing pins); obligations
   generated inside nested clones (18 Subtype + 6 FinType sites [run 13: SEVEN was wrong, and it
   reverted a correct 6 recorded in section 36], one row per site
   regardless of how many the mode leaves installed); `rename` clauses undigested.
   The leg's own next-total estimates were 239 (or 293 counting raw axiom
   instances) against my ledger (216 after this same section's own fix -- "213" was stale
   the moment it was written) — the eighth mutually inconsistent count, and
   the baseline header still says LOWER BOUND for exactly this reason.
   ======================================================================= *)

(* ===========================================================================
   SECTION 40 (2026-08-02) — RUN 13.  THREE LEGS.  THE CONTROL THAT CAUGHT THE
   WORST ATTACK WAS ITSELF UNPINNED, AND A DIGEST I HAD ALREADY SEEN WAS A
   CONSTANT.

   Target: commit 5ef9ddd, tree 52c56e61.  Legs: Kimi K3, GPT-5.6, and — after
   round 12 lost a leg to a provider refusal — an Opus 5 agent, on the owner's
   instruction to substitute rather than run at half coverage.  Same prompt,
   separate worktrees, mutually blind.  Opus 5 is the same model family as the
   coordinator, so convergence between IT and me is weaker evidence than
   convergence with a non-Claude leg; weighted accordingly.

   FINDING 1 (Kimi K3) — THE FALLBACK DIGEST WAS THE CONSTANT sha256(".").
   tools/cert_cone.py `_stmt_digest`: the search pattern begins `(?:^|\.)`, which
   matches the PRECEDING declaration's terminating dot, and the code passed
   `m2.start()` — that dot — to `_decl_span`, whose terminator rule is "a dot
   followed by whitespace at depth 0".  It therefore returned "." immediately.
   Every declaration resolving through the fallback digested to
   sha256(".")[:12] = cdb4ee2aea69: content-independent, and dressed as hex so
   the gate's only degraded-digest check (a grep for `nostmt`) sailed past it.
   The main path escaped by luck — `cut` is normally found — but a lemma closed
   by `by smt()` with no `proof` keyword hits the same constant.
   I SAW THIS VALUE AND DISMISSED IT.  When I built the run-11 fallback I ran a
   synthetic test, printed `admit:cdb4ee2aea69`, thought "is that sha256 of
   something constant?", decided not to check, and shipped it.  Five seconds of
   `printf '.' | sha256sum` would have closed it two rounds earlier.  That is the
   exact failure this log exists to record: not missing the anomaly, SEEING it
   and declining to spend the cheapest possible check on it.
   FIXED by capturing the keyword position (`m.start(1)`), and `ambig<n>` is now
   as fatal as `nostmt` — it was equally content-independent and equally ungated.
   One row moves: admit 01a2cfed95f4 -> aac0bca56296 (the digest no longer
   carries a leading "."), so sections 36/38 quote the pre-run-13 value.

   FINDING 2 (Opus 5 and Kimi K3, independently) — THE CONTROL SOURCES WERE
   NEVER HASHED.  The identity covered cert-controls-split.tsv (paths, polarity,
   declared reasons) and NOT the control .ec files, nor the six PHASE 2b/2c
   fixtures.  So scratch/vac_probe_full.ec — the two-sided vacuity control that
   is the ONLY mechanism in this system to have caught a real end-to-end attack
   (run 11's `pkcotype` inconsistency) — could be rewritten to still fail for its
   declared reason while probing almost nothing: zero census delta, zero identity
   delta, gate GREEN.  Compounding it, cert_gate_fork.sh:306 compiles PHASE-3
   controls with `-I scratch`, a FOURTH include dir outside the hashed set: run
   12 fixed the compiled-set/hashed-set mismatch for PHASE 1/2 and stopped one
   phase short, in the phase section 38 credits as the only one that has ever
   caught anything.  FIXED: both identities now hash the control manifest, every
   control source, and all five canary fixtures.

   FINDING 3 (my own claim, false) — "the fork gate's controls are inline".
   cert-controls.tsv EXISTS and PHASE 3 reads it.  I searched for
   cert-controls-FORK.tsv, found nothing, and converted its absence into a claim
   about the gate's design, then wrote that into section 37 and into the fork
   gate's own comments.  Twelve fork controls' declared reasons were editable
   with no identity delta.

   FINDING 4 (Opus 5) — A FOURTH AND FIFTH CONTENT-FREE DIRECTION, IN A
   CERTIFIED TOP RESULT.  SphincsC10CapstoneCharged universally quantifies four
   reals; at (0,1,0,0) the premise holds by Pr[mu_le1] while the conclusion's RHS
   exceeds 1.  Kimi found the same file's `gfail` summand bounded by nothing.
   Section 39's "the content-free directions remain the three already disclosed"
   was therefore FALSE, and the CHARGED header — corrected on 2026-07-31 by an
   adversarial review ABOUT VACUITY — never mentioned either.  Now disclosed in
   that header.

   FINDING 5 (Kimi K3) — run 12's `local clone` fix was HALF DONE: the
   `(?:local\s+)?` went into the match pattern and not into the tail terminator,
   so a column-0 `local clone` following another clone is swallowed by its
   predecessor's tail — the very hole that commit claimed to close.  Dormant
   because all three live sites follow a non-clone declaration.  Fixed.

   THE MODE TALLY INSIDE THE IDENTITY CONTRADICTED ITS OWN FILE.  Both baselines
   said "54 star, 12 list, 11 none, 0 empty" (= 77) against 80 clone rows; the
   tree is 57/12/11.  I regenerated the rows in run 12 and hand-edited the prose
   beside them.  The tally is now COMPUTED FROM THE ROWS.

   ON THE LEDGER, THE HONEST POSITION HAS CHANGED.  I have called 216 a LOWER
   BOUND.  Opus 5 showed it is not a bound in either direction: rows are counted
   at the DECLARATION site regardless of discharge at the unique instantiation —
   `FL_SL_XMSS_MT_ES.ec:342 valid_xidxvals_idxvals` is fully realized at
   SPHINCS_PLUS.ec:671-675 and still occupies a LEDGER row — while 80 clone
   markers stand for 0-or-more installed obligations apiece.  Kimi independently
   recounted 216 with its own walker and settled the operand count at exactly 349
   (321 `<-` + 28 `<=`; the baseline header's "321" was the undercount).  The
   three figures 216 / 239 / 293 are row-populations of three different
   syntactic scans in different units; the question "which is right" is
   ILL-POSED, and no textual census can be made sound in either direction without
   EasyCrypt's own cloning semantics.  The header should stop saying LOWER BOUND
   and say that.

   POSITIVE, AND FROM TWO LEGS NOW: the hop chain was independently reconstructed
   and traced clean — every atom exactly once, no dropped or double-counted term,
   no wrong-direction inequality, both non-`={res}` postconditions sound-direction,
   `res /\ !covered` only ever a premise.  CHECK 1 also settled: SPHINCS_PLUS.ec:633
   `op valid_xidxvalsgp <- predT` is BENIGN — adrs_len = 6 forces the only
   reachable input to `[]`, so `predT []` is the only sensible binding.
   ======================================================================= *)

(* --- SECTION 40 ADDENDUM: THE THIRD LEG (GPT-5.6) --------------------------
   Converged with the other two on the unhashed control sources -- three
   independent legs, same top finding -- and added three the fix set missed:

   * ANNOTATED OPS WERE NOT PARAMETERS.  The abstract pattern required the name
     to follow `op` IMMEDIATELY, so every `op [lossless] d : t.` carried its
     op-annotation row (name + tag) and NO declaration digest: its TYPE was
     unpinned.  PARAMETERS 106 -> 169 split, 99 -> 162 fork.  Its predicted
     figure was ">= 167"; measured 169.
   * DECL omitted `realize`, so an `admit.` inside a realize block resolved its
     enclosing name to whatever declaration preceded it.
   * THE IDENTITY WAS COMPUTED ONCE AND NEVER RECHECKED, before a compile phase
     that runs the better part of an hour.  An edit after the hash and a revert
     before the census compiles altered sources under a green receipt.  Both
     gates now recompute the identity at the END and fail on any drift.  This
     does not close a determined race; it does catch any edit that persists.

   AND IT INDEPENDENTLY CONFIRMED A FIX MID-FLIGHT.  It reported the fork census
   swallowing DLP into DMS at FL_SL_XMSS_MT_ES.ec:2764/2768 -- true of the tree
   it reviewed, already closed by this round's tail-terminator fix, and the
   reason the fork ledger moved 220 -> 221.  Its own independent recount of the
   fork ledger was 221.  Two counts from different methods agreeing on a number
   this artifact has got wrong eight times is worth recording.

   ITS LEDGER FIGURE: 268 for split, with a method the others did not have --
   replace the 24 Subtype/FinType proxy rows with the 76 axioms those sites
   actually install (18 Subtype x 4 + 2 inhabited + 6 FinType enum_spec), giving
   216 - 24 + 76.  It also corrects 293 to 292 and states 239/293 have no
   committed harness.  It agrees a definitive total needs an EasyCrypt
   AST/environment dump after recursive clone expansion, not a regex.
   THREE LEGS NOW AGREE that `valid_xidxvalsgp <- predT` is benign, and that
   _CHARGED carries a content-free direction the disclosure list omitted.
   -------------------------------------------------------------------------- *)

(* --- SECTION 41 (2026-08-04) — RUN 22.  THREE COUNTS THAT DO NOT MEAN WHAT
   THEIR NAMES SAY.  Both gates GREEN at commit 225a005 / tree 2b452fa6 (split
   22 targets / 66 pins / 1055 rows; fork 19 / 9 / 1089), certifying Tier-1
   brick 2b.  No finding overturned that result.  What follows is three places
   where a NUMBER the receipt prints is weaker than the number a reader will
   take it for.  None is a soundness defect; all three are receipt defects, and
   this artifact's whole failure history is receipts that assert less than they
   appear to.

   (1) "controls executed (unique)=5" IS NOT FIVE DISCRIMINATING CONTROLS.
   One of the five, scratch/tier0_degenerate_encoder_excluded.ec, TESTS NOTHING.
   The run-14 review established it (commit 8faf5c8, finding 4; GPT-5.6 and
   Opus 5 independently): it is a MUST-FAIL control that fails whether or not
   INJ exists, because failure to PROVE constancy is not proof of NON-constancy,
   and degeneracy is a satisfiability property that no compile failure can
   witness.  THAT FINDING HAD NEVER REACHED THIS LOG.  Sections 35-40 stop at
   run 13; run 14's findings went into a commit message and two lemma headers,
   so the log's own record of what the controls are worth was a round stale.
   Worse, the control's OWN header still asserted the disproven framing -- "MUST
   FAIL: a CONSTANT encoder cannot satisfy the identification ... If this
   compiles, the Tier-0 lemma does not exclude the degenerate model after all"
   -- which is precisely the claim run 14 killed.  Corrected in this commit.  I
   found this only because I wrote "Section 40's round established it" here and
   then checked the citation instead of asserting it; the grep returned nothing
   but my own sentence.  It is retained -- deleting a control is a worse habit
   than keeping a weak one -- but the honest count of controls that could catch
   a Tier-0 regression is FOUR, and the discriminating statements for that
   particular claim are the POSITIVE lemmas c10_embg_not_constant and
   c10_deployed_encoder_not_constant, both pinned in PHASE 1c.  If "5 controls"
   is ever quoted as five independent checks, this section is the correction.

   (2) THE CENSUS IS SILENT ON pkfors_of, AND SILENCE IS NOT ENDORSEMENT.
   Brick 2b landed with census delta ZERO (added=0 removed=0), and that fact is
   worth exactly what it says: the proof introduced no admit, axiom, abstract
   parameter, clone obligation or module body.  It says NOTHING about whether
   pkfors_of computes what MM45's gen_pkFORS computes, because a DEFINED op
   creates no census row at all.  A zero-delta census over a wrong definition
   is a green receipt for a wrong proof.  Two other guards carry that weight:
   PHASE 1c pins the definition body (op:...::pkfors_of = 6bbaa54458976927...),
   and MM45_keygen_pk_from_sk is a hoare triple over FTWES.M_FORS_ES_NPRF.keygen
   ITSELF -- MM45's real module -- concluding that MM45's returned pk pool is
   pkfors_of applied to MM45's OWN returned sk pool.  Faithfulness is therefore
   PROVED, not assumed; but it is proved by that lemma, not by the census, and
   quoting the zero delta as if it covered the definition would be the error.

   (3) ECO_REMAINING=0 DID NOT DISTINGUISH "NOTHING WAS STALE" FROM "180 STALE
   OBJECTS WERE REMOVED", and run 22 was the second case.  A previous fork-gate
   run had survived its task kill and was still spawning compiles against a tree
   that had moved under it.  The split gate purged them correctly -- purge scope
   and check scope have been identical since section 37 -- but printed only the
   survivor count, so its receipt could not show a reader that a purge had done
   any work.  I had to establish it after the fact from .eco mtimes: every
   object under the split include path was written between 15:45:55 and
   16:08:27, and cdrafts-split/GprocFORSC10.eco (16:07:59) postdates its source
   (15:25:31) by 42 minutes, so PHASE 1 really did rebuild.  cert_gate_split.sh
   now prints ECO_PURGED, as the fork gate already did.  NOTE THE POLARITY: the
   count is a RECEIPT, not a check.  A nonzero ECO_PURGED is normal.

   AND A CORRECTION IN THE OTHER DIRECTION, WHICH IS RARER HERE.  Section 40's
   round withdrew the claim that the Gproc/MM45 keygen addresses "coincide --
   CHECKED, not assumed", on the ground that GprocKg_sk_eq cannot witness it
   (keygen is address-independent and both pk computations were one-sided).
   That withdrawal was right about THAT lemma and is now SUPERSEDED for the
   pair proved in brick 2b: MM45_keygen_pk_from_sk and Gproc_keygen_pk_from_sk
   each derive the SAME address expression, set_kpidx (set_tidx (set_typeidx
   adi trhftype) i) j, from their own module's code.  The set_thtbidx/set_kpidx
   argument order that run 21 asked about and I answered "did not verify" is
   consequently derived on both sides.  Recorded because the reflex in this log
   is to withdraw and leave withdrawn; a withdrawal can also be overtaken.
   -------------------------------------------------------------------------- *)
