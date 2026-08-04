(* ==========================================================================
   THE IDENTIFICATION STEP — and why the NAIVE form is IMPOSSIBLE.

   GOAL AS PREVIOUSLY STATED (by me, at the end of the Proj129 unit):
     "identify `encode_msgWOTS` with the base-8 digit map, so Proj129's proven
      injectivity discharges `PremiseReduction.EncMsgInjOnThCImage`."

   THAT GOAL IS UNACHIEVABLE AS STATED.

   *** SCOPE CORRECTION 2026-07-27 — READ THIS BEFORE THE CLAIMS BELOW. ***
   Everything in this file is proved about `enc_c10 : int -> codeword`, where
   `codeword = int list` (IncEnc.ec:564).  This file requires ONLY AllCore/List/
   IntDiv/Ring/StdOrder, EncoderBridge, Proj129, IncEnc.  It NEVER requires
   `WOTS_TW_ES` or `SPHINCS_PLUS`, and `EncoderBridge.ec:29-30` declares its OWN
   `op wd` + `axiom gt1_wd`, unconnected to base-c10's `w`/`log2_w`.

   So EasyCrypt has verified NOTHING here about `encode_msgWOTS`.  The
   correspondences

       nth 0 x i  <->  BaseW.val x.[i]      43  <->  len
       int list   <->  emsgWOTS             int <->  msgWOTS = dgstblock

   are HAND TRANSCRIPTIONS, checked by no tool.  The original commit message for
   this file said "the NAIVE form is PROVED IMPOSSIBLE"; that over-claims by
   exactly this gap.  The honest reading is: **this is a proof about a
   type-disconnected surrogate of the model's encoder**, and it is only as good
   as the transcription.  Found by adversarial review, not by me.

   A SECOND correction, same source: base-c10 does NOT pin C10's geometry.
   Verbatim: `WOTS_TW_ES.ec:28  const n : { int | 1 <= n } as ge1_n.`,
   `:34 const log2_w : { int | 2 <= log2_w } as val_log2w.`,
   `:53 const len : { int | 2 <= len } as ge2_len.`  Making the geometry
   EXPRESSIBLE (commit ff80b4e) is not INSTANTIATING it.  Therefore the counting
   obstruction below is a true statement about an instantiation **that does not
   exist in this development**, and no contradiction is EasyCrypt-derivable
   inside base-c10 as written (take `len` large and the axiom is satisfiable
   alongside injectivity).  DO NOT describe base-c10 as inconsistent.

   The obstruction:

     * base-c10's weakened `two_encodings` (WOTS_TW_ES.ec:579), applied to the
       ordered pair (m,m') AND to (m',m), forces any two DISTINCT codewords in
       the image to be INCOMPARABLE.  So image(encode_msgWOTS) is an ANTICHAIN.
     * The plain base-8 digit map does NOT have antichain image: `int2dig 43 0`
       is dominated by every codeword.  Mechanized below as
       `digit_map_violates_global_two_encodings`, with the explicit witness pair
       (1, 0) — no counting argument needed.
     * Independently (counting, NOT mechanized here — see the honesty note):
       the largest antichain of {0..7}^43 is 2^123.759, while
       `msgWOTS = dgstblock` has 2^128 elements (WOTS_TW_ES.ec:213, n = 16).
       So NO encoder satisfying the global axiom can be injective at C10, and
       `PremiseReduction.EncMsgInj` is jointly UNSATISFIABLE with `two_encodings`.

   WHAT IS ACHIEVABLE — and is proved here (about the surrogate; see above).
   Restrict to the CONSTANT-SUM SURFACE (digit sum = target_sum = 205), which is
   the only set the C10 verifier accepts — `sphincs-c10/src/wots.rs:160`
   (`if sum != TARGET_SUM { return [0u8; N]; }`) and
   `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol:170`.  The gate is
   **SUM ONLY**.  (`WOTS_C_Real.ec:178-179` describes predC as "sums to
   target_sum, and the first z digits are zero"; the leading-zeros half is
   **FORS+C's** `predC_fors`, NOT deployed WOTS.  Verified at the two sites
   above.  A predC carrying a leading-zeros conjunct would be UNFAITHFUL, not
   more complete.)  On that surface the digit map is SIMULTANEOUSLY

     (a) incomparable-imaged   -> satisfies what `two_encodings` needs
     (b) nonzero-digited       -> satisfies what `enc_nonzero` needs
     (c) INJECTIVE             -> what `EncMsgInjOnThCImage` needs

   and (a)+(c) are compatible there precisely because restricting the codomain
   also restricts the DOMAIN: the sum-205 digests are ~2^114, not 2^128.  The
   pigeonhole that kills the global statement does not apply.

   So the identification is not "encode_msgWOTS = digit map".  It is
   "encode_msgWOTS = digit map ON THE predC SURFACE", and the price is that
   `two_encodings` must be RELATIVIZED to that surface in base-c10.

   *** WHAT THIS FILE DOES NOT ESTABLISH — read before quoting. ***

   (1) BLOCKING: `ThC`'s OUTPUT WIDTH IS UNFIXED, AND THE ANSWER FLIPS ON IT.
       Model: `ThC ... : dgstblock` (`WOTS_C_Real.ec:175`) = 8*n bits = 128 at n=16.
       Deployed: `wots_digest` returns `[u8; 32]` — **256 bits, untruncated**
       (`sphincs-c10/src/hash.rs:344-364`, whose own doc-comment says "Returns the
       full 32-byte digest for base-w digit extraction").  The digit map consumes
       **129 of those 256 bits** (digit 42 = bit_offset 126, spans into byte 15,
       reading bit 128).  Three readings, three different answers:

         ThC = trunc_129(wots_digest)  -> digit map injective (8^43 = 2^129,
                                          exactly tight); premise TRUE of deployment
         ThC = wots_digest (256 bits)  -> digit map is 2^127-to-1; premise FALSE,
                                          `Composition.orphan_empty` UNSOUND at
                                          deployed parameters, composition really
                                          four-way with an UNCHARGED branch
         ThC = dgstblock at n=16       -> true in the model, but the model is then
                                          not C10

       `Proj129.c10_low128_determines` bridges 129 -> 128 on the surface.  NOTHING
       bridges 256 -> 129.  So the model's 128-bit choice ELIMINATES an
       encoding-collision event the deployment genuinely HAS: it is OPTIMISTIC,
       not conservative.  This is NOT an attack — exploiting it needs a 129-bit
       TARGET partial preimage (~2^129), not a birthday collision — but the
       direction of the unfaithfulness is the wrong one.  Note also that adopting
       the truncation reading makes the downstream S-TCR(+C) assumption one about
       a 129-BIT-OUTPUT function, strictly stronger than the SHA-256 statement the
       ledger names.

   (2) `predC` CARRIES NO AXIOM ANYWHERE IN THE CLOSURE — the repo says so itself
       (`SphincsC10Content.ec:492`).  `predC := fun _ => false` satisfies every
       predC statement in the development and zeroes the LHS of the bound.  Any
       predC-relativized claim inherits that vacuity hazard until predC is tied
       to the digit sum, which `WOTS_C_Scheme.ec` does NOT do (`target_sum`
       appears zero times there).

   (3) RELATIVIZING `two_encodings` IN PLACE IS NOT AN OPTION.
       `FL_SL_XMSS_MT_ES.ec:6342` consumes `MEUFGCMA_WOTSTWESNPRF` via a reduction
       that queries the WOTS-TW oracle on SUBTREE ROOTS, which satisfy no predC.
       A predC-gated WOTS-TW game cannot serve that consumer, so base-c10 would
       stop compiling — taking all of `cdrafts` with it.  The only sound route is
       a FORK: a predicate-parameterised copy of `WOTS_TW_ES` used only by the +C
       track (~3450 lines to re-prove), which forfeits the "MM45 invoked as a
       black box, its proof never reopened" property that `WOTS_C_Real.ec:248-249`
       names as the reason the port is credible.  `enc_nonzero` (`:597`) is ALSO
       false of the digit map and would need the same treatment, at a harder site
       (`relcqsadpre_rng`, `:1528`, a pure counting lemma with no game context).

   Nothing in base-c10 is modified here.  The relativized axiom is a PROPOSAL and
   an expensive one, not a licensed edit.

   PROVENANCE: the antichain half is NOT re-proved here.  `IncEnc.tsw_incomparable`
   (cdrafts/IncEnc.ec:627) already proves the target-sum code is incomparable for
   arbitrary (v,w,T); this file instantiates it at C10 and connects it to the
   digit map.  The injectivity half comes from `Proj129`.
   ========================================================================== *)
require import AllCore List IntDiv Ring StdOrder.
require import EncoderBridge Proj129.
require import IncEnc.
import IntOrder.

(* The DEPLOYED encoder, as an int-list codeword: 43 base-8 digits.
   `sphincs-c10/src/wots.rs:35-46`, modulo digit ORDER (see the note at the foot
   of Proj129.ec: sum and injectivity are order-invariant, chain assignment is
   not and is not addressed). *)
op enc_c10 (d : int) : codeword = int2dig 43 d.

(* ==========================================================================
   0.  BRIDGE THE TWO SUM OPERATORS.  Proj129 uses `dsum`, IncEnc uses `sumz`.
   ========================================================================== *)
lemma dsum_sumz (ds : int list) : dsum ds = sumz ds.
proof. by elim: ds => /= [| a ds ih]; [exact sumz_nil | rewrite ih sumz_cons]. qed.

(* ==========================================================================
   1.  THE DIGIT MAP LANDS IN C10's TARGET-SUM CODE (on the surface).
   ========================================================================== *)
lemma enc_c10_digits_bounded (d : int) :
  wd = 8 => all (fun (x : int) => 0 <= x < 2 ^ 3) (enc_c10 d).
proof.
move=> hwd; rewrite /enc_c10 /int2dig; apply/allP => x /mkseqP [i] [rgi ->] /=.
have gt0w : 0 < wd by exact gt0_wd.
(* was `by smt()` until 2026-07-28 -- the SAME concrete-exponentiation class that
   timed out under load in Proj129. Now deterministic, via EncoderBridge.pow8. *)
have h8 : 2 ^ 3 = 8 by rewrite -pow8.
smt(modz_ge0 ltz_pmod).
qed.

lemma enc_c10_size (d : int) : size (enc_c10 d) = 43.
proof. by rewrite /enc_c10 size_int2dig. qed.

lemma enc_c10_into_code (d : int) :
  wd = 8 => dsum (enc_c10 d) = 205 => c10_code (enc_c10 d).
proof.
move=> hwd hsum; rewrite /c10_code /tsw_code /c10_v /c10_w /c10_T.
rewrite enc_c10_size /=; split; 1: by apply enc_c10_digits_bounded.
by rewrite -dsum_sumz.
qed.

(* ==========================================================================
   2.  (a) INCOMPARABLE on the surface — what `two_encodings` needs.
       Inherited from IncEnc.tsw_incomparable; NOT re-proved.
   ========================================================================== *)
lemma enc_c10_incomparable_on_surface (d d' : int) :
     wd = 8
  => dsum (enc_c10 d)  = 205
  => dsum (enc_c10 d') = 205
  => enc_c10 d <> enc_c10 d'
  =>  (exists (i : int), 0 <= i < 43 /\ nth 0 (enc_c10 d)  i < nth 0 (enc_c10 d') i)
   /\ (exists (i : int), 0 <= i < 43 /\ nth 0 (enc_c10 d') i < nth 0 (enc_c10 d)  i).
proof.
move=> hwd h1 h2 hne.
have hc  : c10_code (enc_c10 d)  by apply enc_c10_into_code.
have hc' : c10_code (enc_c10 d') by apply enc_c10_into_code.
by have := c10_incomparable (enc_c10 d) (enc_c10 d') hc hc' hne; rewrite /c10_v.
qed.

(* ==========================================================================
   3.  (b) NONZERO DIGIT on the surface — what `enc_nonzero` needs.
       205 > 0, so a codeword summing to 205 cannot be all zeros.
   ========================================================================== *)
lemma enc_c10_nonzero_on_surface (d : int) :
     dsum (enc_c10 d) = 205
  => exists (i : int), 0 <= i < 43 /\ nth 0 (enc_c10 d) i <> 0.
proof.
move=> hsum; case: (exists (i : int), 0 <= i < 43 /\ nth 0 (enc_c10 d) i <> 0) => // hno.
have hall : forall (i : int), 0 <= i < 43 => nth 0 (enc_c10 d) i = 0 by smt().
have heq : enc_c10 d = nseq 43 0.
+ apply (eq_from_nth 0); 1: by rewrite enc_c10_size size_nseq.
  move=> i; rewrite enc_c10_size => rgi.
  by rewrite nth_nseq 1:// hall.
move: hsum; rewrite heq dsum_sumz sumz_nseq //.
qed.

(* ==========================================================================
   4.  (c) INJECTIVE on the surface — what `EncMsgInjOnThCImage` needs.
       From Proj129.  Note the range is the FULL deployed [0, 2^129), where the
       digit map is exactly tight (8^43 = 2^129).
   ========================================================================== *)
lemma enc_c10_injective_on_surface (d d' : int) :
     wd = 8
  => 0 <= d  < 2 ^ 129
  => 0 <= d' < 2 ^ 129
  => enc_c10 d = enc_c10 d'
  => d = d'.
proof. by move=> hwd rg rg'; apply c10_enc_inj_129. qed.

(* The 128-bit form, which is what the MODEL indexes by: on the surface the low
   128 bits determine the codeword (Proj129.c10_low128_determines). *)
lemma enc_c10_low128_faithful (d d' : int) :
     wd = 8
  => 0 <= d  < 2 ^ 129
  => 0 <= d' < 2 ^ 129
  => dsum (enc_c10 d)  = 205
  => dsum (enc_c10 d') = 205
  => d %% 2 ^ 128 = d' %% 2 ^ 128
  => enc_c10 d = enc_c10 d'.
proof. by move=> hwd rg rg' h1 h2 hm; apply c10_low128_faithful. qed.

(* ==========================================================================
   5.  THE HEADLINE, POSITIVE: (a), (b) and (c) hold TOGETHER on the surface.
   So base-c10's requirements and the injectivity PremiseReduction needs are
   JOINTLY SATISFIABLE at C10 — provided everything is read on the constant-sum
   surface.  This is the identification, in the only form that can be true.
   ========================================================================== *)
lemma c10_surface_satisfies_all_three (d d' : int) :
     wd = 8
  => 0 <= d  < 2 ^ 129
  => 0 <= d' < 2 ^ 129
  => dsum (enc_c10 d)  = 205
  => dsum (enc_c10 d') = 205
  =>  (* (a) incomparable when distinct *)
      (enc_c10 d <> enc_c10 d' =>
         (exists (i : int), 0 <= i < 43 /\ nth 0 (enc_c10 d)  i < nth 0 (enc_c10 d') i)
      /\ (exists (i : int), 0 <= i < 43 /\ nth 0 (enc_c10 d') i < nth 0 (enc_c10 d)  i))
      (* (b) every codeword has a nonzero digit *)
   /\ (exists (i : int), 0 <= i < 43 /\ nth 0 (enc_c10 d) i <> 0)
      (* (c) injective *)
   /\ (enc_c10 d = enc_c10 d' => d = d').
proof.
move=> hwd rg rg' h1 h2; split; [| split].
+ by move=> hne; apply enc_c10_incomparable_on_surface.
+ by apply enc_c10_nonzero_on_surface.
by apply enc_c10_injective_on_surface.
qed.

(* ==========================================================================
   6.  THE HEADLINE, NEGATIVE: the GLOBAL identification is IMPOSSIBLE.

   The plain digit map violates the weakened `two_encodings` at the explicit
   witness pair (1, 0).  `int2dig 43 0` is the all-zero codeword, every digit is
   >= 0, so NO index has digit(1) < digit(0) — while the codewords differ.

   This needs no counting argument, and it is why "identify encode_msgWOTS with
   the digit map" cannot be done without relativization.
   ========================================================================== *)
lemma digit_map_violates_global_two_encodings :
  wd = 8 =>
     enc_c10 1 <> enc_c10 0
  /\ ! (exists (i : int), 0 <= i < 43 /\ nth 0 (enc_c10 1) i < nth 0 (enc_c10 0) i).
proof.
move=> hwd.
have h128 : 0 < 2 ^ 128 by smt(expr_gt0).
have h129 : 2 ^ 129 = 2 * 2 ^ 128 by smt(exprS expr_gt0).
have gt0w : 0 < wd by exact gt0_wd.
split.
+ apply/negP => heq.
  have h10 : 1 = 0 by apply (enc_c10_injective_on_surface 1 0) => //; smt().
  by move: h10.
apply/negP => -[i] [rgi hlt].
have hz : nth 0 (enc_c10 0) i = 0.
+ by rewrite /enc_c10 /int2dig nth_mkseq //= div0z mod0z.
have hge : 0 <= nth 0 (enc_c10 1) i.
+ by rewrite /enc_c10 /int2dig nth_mkseq //=; smt(modz_ge0).
smt().
qed.

(* ==========================================================================
   7.  ANTI-VACUITY: the surface is NONEMPTY, so §5 is not about the empty set.
   Two routes, deliberately independent:
     * `Proj129.c10_target_sum_reachable` — every achievable sum is reached.
     * `IncEnc.c10_code_nonempty` — explicit witnesses in the code.
   ========================================================================== *)
lemma surface_nonempty : wd = 8 => exists (d : int), 0 <= d < 2 ^ 129 /\ dsum (enc_c10 d) = 205.
proof.
move=> hwd; have [n [rgn hn]] := c10_target_sum_reachable hwd.
by exists n; rewrite /enc_c10.
qed.

(* ==========================================================================
   THE LEDGER, after this file.

     enc_c10 = digit map, GLOBALLY, is NOT antichain-imaged  -- PROVED (§6)
     enc_c10 on the surface satisfies (a),(b),(c) together   -- PROVED (§5)
     ...both about the SURROGATE.  Transferring either to `encode_msgWOTS`
     is hand transcription, NOT machine-checked.  See the scope correction.

     PremiseReduction.EncMsgInj (global)      -- unsatisfiable at C10 GEOMETRY,
                                                 which base-c10 does not pin
     PremiseReduction.EncMsgInjOnThCImage     -- as WRITTEN it quantifies over ALL
                                                 (c,c'), including counters that
                                                 fail the gate and never occur.
                                                 It is STRONGER than the
                                                 composition needs.

   THE REMAINING OBLIGATION IS NOT WHAT I PREVIOUSLY WROTE.  I said it was "show
   the chain only ever encodes predC-satisfying digests", and split that into an
   easy honest leg and a hard forgery leg.  Both halves of that were wrong:

     * FORGERY leg is the UNCONDITIONAL one (`WOTS_C_Scheme.ec:101,103` gates on
       `okC <- predC (ThC ps ad m counter)` and conjoins it to acceptance).
     * HONEST leg is the CONDITIONAL one: `wotsc_grind_targets_predC`
       (`WOTS_C_Real.ec:208-210`) requires `exists c, predC (ThC ps ad m c)` as a
       PREMISE.  That is capstone premise N2, not an axiom, and it carries an
       uncharged probability term — the firmware bounds the search at
       `for count in 0..10_000_000u32` and PANICS on failure (`wots.rs:62-74`),
       a strictly smaller search space than the model's never-failing `grind`
       (`Grind.ec:79-80`).

   And it is all downstream of (1) above: until `ThC`'s output width is fixed, the
   premise being discharged is not yet a statement about deployed C10.

   `Pr[G /\ COLL]` remains entirely uncharged.  `WOTS_TW_ES.ec:1353` remains
   ADMITTED and propagates past its section into `FL_SL_XMSS_MT_ES.ec:6342`.
   C10 is still NOT proven at deployed parameters.

   `Pr[G /\ COLL]` remains entirely uncharged.  C10 is still NOT proven at
   deployed parameters.
   ========================================================================== *)
