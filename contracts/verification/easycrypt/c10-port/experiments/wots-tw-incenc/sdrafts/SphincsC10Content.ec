(* ==========================================================================
   SphincsC10Content.ec -- TRACK V: MAKE THE SPHINCS+C10 CAPSTONE PROVABLY HAVE
   CONTENT.  (2026-07-25.)

   WHY THIS FILE EXISTS.  drafts/SphincsC10CapstoneWired.ec is CERTIFIED-0-ADMIT
   and its premise set is SATISFIABLE (repaired 2026-07-25).  But a TRUE, 0-admit,
   satisfiably-premised theorem can still be CONTENT-FREE, and two such vectors
   survived that repair:

     (V1) `op predC : dgstblock -> bool` (WOTS_C_Real.ec:180) is COMPLETELY
          UNCONSTRAINED -- an axiom census over the entire closure finds NO axiom
          mentioning it.  Under the ADMISSIBLE reading `predC := fun _ => false`
          every layer's +C gate rejects, so `Pr[EUFCMA_C10(F).main() : res]` is
          IDENTICALLY ZERO and the bound says nothing
          (machine-checked: scratch/audit_residual_predC_zeroes_lhs.ec).

     (V2) `op emb_in : msgWOTS * cntr -> dgst` (WOTS_C_Real.ec:164) is likewise
          unconstrained and the capstone carries NEITHER `emb_in_len` NOR
          `emb_in_inj`.  Under a CONSTANT `emb_in`, `ThC` collapses in (m,c) and
          the S-TCR(+C) RHS term is trivially ~1: content-free from the RHS side.

   WHAT THIS FILE DOES.  It leaves the capstone BYTE-IDENTICAL (nothing is
   weakened, no premise is added to it, no chain file is edited) and adds:

     * PART A/B -- the mathematical heart of WOTS+C, PROVED: a CONSTANT-SUM
       digit encoding satisfies MM45's antichain condition (`two_encodings`,
       WOTS_TW_ES.ec:571) WITHOUT a checksum.  This is exactly what the +C gate
       buys, and here it is a THEOREM, not an assumption.

     * PART C -- the +C gate PASSES on an honestly-ground counter, at the very
       procedure at which the V1 audit proved it always FAILS.

     * PART D/E -- a NON-DEGENERATE satisfiability MODEL CORE for every premise
       added below: an interpretation in which predC is NOT identically false and
       ThC is NOT constant, plus a FAITHFUL `M || counter` serialisation witness
       for emb_in that is constant-width and INJECTIVE (hence not constant).

     * PART F -- `EUFCMA_SPHINCS_PLUS_C10_CONTENTFUL`: the capstone bound,
       RE-DERIVED VERBATIM by APPLYING the unchanged capstone, CONJOINED with the
       content facts that the two degeneracies are excluded.

     * PART G -- the JOINT MODEL, ON THE ACTUAL GLOBALS.  PARTS D/E witness with
       FRESH existential functions, which is a weak witness (external review,
       2026-07-25: those lemmas can hold while the ACTUAL predC is false and the
       ACTUAL emb_in constant).  PART G pins `emb_in`, `predC` and `thfc`-at-index-
       dfC by definitional equations and PROVES all four added premises AND the
       non-degeneracy AT THOSE GLOBALS.  It also records, with a pigeonhole
       argument, what NO model can achieve.

   HONEST LIMIT (stated up front, again at PART D, and sharpened at PART G).
   This lands ladder rung (b), NOT (c) -- and (b) only in the qualified form
   spelled out at PART G.  Full (c) -- "discharge non-degeneracy as THEOREMS" --
   is NOT derivable from this closure: it bottoms out in the unconstrained image
   of `encode_msgWOTS`, in the free target constant, and in `thfc`.  Defining
   predC in place would RELOCATE that dependency, not remove it.  PART G's
   hypotheses (i)-(iii) are EQUATIONS ON THE ACTUAL OPS, not a clone-realization;
   the step "these equations are simultaneously satisfiable as interpretations" is
   a meta-level step licensed by the axiom census (predC / emb_in / thfc carry no
   axiom anywhere in the closure) plus their non-circularity.

   RESIDUAL QUALIFICATIONS ON PART G's WITNESS (external review, Kimi K3, 2026-07-25;
   all four upheld and recorded rather than argued away):
     (Q1) Satisfiability of PART G's (i)-(iv) is a META-argument -- axiom census plus
          non-circularity -- NOT a machine-checked `clone ... realize`.  It cannot be
          one: EasyCrypt cannot re-interpret an already-declared op from inside the
          theory.  "Witness" here means "consistent by inspection", and that is the
          strongest form available at this seam.
     (Q2) N1 is witnessed at `target_sum := digitsum (encode_msgWOTS d0)`, i.e.
          EXISTENTIALLY over the target.  It is NOT witnessed at C10's deployed
          TARGET_SUM = 205: whether 205 lies in the image of `digitsum o
          encode_msgWOTS` is undecided by this closure (see MODEL_predC_strict_iff).
     (Q3) Hypothesis (iii) pins `thfc` at index `8*n + r` for ALL inputs, so the model
          is PARAMETER-CONDITIONAL: it is only scheme-preserving while `8*n + r` misses
          the four member indices.  That is guaranteed by the capstone's separation
          premises, NOT by the model itself -- and MODEL_dfC_8np32_unsafe_at_n4 shows
          the guard is not automatic.
     (Q4) What is established is `predC` SOMEWHERE-TRUE, not `predC` a PROPER subset.
          In the exhibited model `predC d1` may also hold, i.e. the gate may never
          reject.  Excluding THAT would require constraining `encode_msgWOTS`'s image,
          which the closure does not do.

   NON-DEGENERACY ACHIEVED vs NOT ACHIEVED (see the note after PART G):
     ACHIEVED     -- predC not identically false; emb_in not constant (injective);
                     ThC not constant; the LHS-zeroing interpretation refuted.
     NOT ACHIEVED -- "the S-TCR(+C) RHS term is not ~1".  PROVABLY unreachable by
                     any model-theoretic premise: pigeonhole forces gate-passing
                     same-tweak collisions to EXIST whenever the gate ever
                     rejects.  S-TCR is a hardness-of-FINDING assumption.

   ****  FAITHFULNESS FINDING -- READ BEFORE QUOTING ANY OF THIS AS "C10".  ****
   AMENDED 2026-07-25 after a three-lens adjudication (F1/F2/F3 each re-probed at
   source with machine-checked receipts, plus two external reviewers).  The headline
   conclusion is UNCHANGED; two of the three stated MECHANISMS were wrong and are
   corrected here, and the "three INDEPENDENT grounds" framing is RETRACTED.

   This theory CANNOT be instantiated at C10's deployed WOTS parameters
   (n = 16, W = 8 i.e. log2_w = 3, L = 43, TARGET_SUM = 205 --
   sphincs-c10/src/params.rs:19,43,46,49,52).  The obstruction is LOCALIZED TO THE
   WOTS LAYER: FORS_ES's constraints (ge1_n / ge1_k / ge1_a at FORS_ES.ec:22,25,28)
   and SPHINCS_PLUS's tree constraints (ge1_hp / ge1_d at SPHINCS_PLUS.ec:58,64) do
   NOT exclude deployed n=16 / k=13 / a=11 / h'=9 / d=2; only log2_w is restricted.
   That localizes where any future repair would live.  It does NOT mean any leg is
   currently proven AT deployed C10: val_log2w is ambient in every theory that
   requires SPHINCS_PLUS (including GprocFORSC10.ec:53), so there is no deployed
   instantiation of ANY part of this development.

     (F1) BLOCKING, as stated.  `const log2_w : { int | log2_w = 2 \/ log2_w = 4
          \/ log2_w = 8 } as val_log2w` (WOTS_TW_ES.ec:31) => w in {4,16,256};
          deployed log2_w = 3.  Single-sourced through both clone levels
          (FL_SL_XMSS_MT_ES.ec:542,578 and SPHINCS_PLUS.ec:549,614), so the +C stack
          runs at the SAME w -- the "it is only the black-box standard-WOTS leg"
          defence is unavailable.  NEW: F1 alone is CHEAPLY REPAIRABLE.  Relaxing to
          `1 <= log2_w` and deleting the two enumeration lemmas val_w
          (WOTS_TW_ES.ec:61) and val_len1 (:96) compiles all three vendored levels at
          0 admits, and then len1 = 43 EXACTLY at deployed n=16, log2_w=3.  See the
          DO-NOT below: that repair ALONE buys no claimable ground.

     (F2) BLOCKING as to representability -- MECHANISM WORDING CORRECTED.
          The previous text said the "CHECKSUM CHAINS WOTS+C EXISTS TO REMOVE are
          still present".  That misattributes the mechanism: FV-SPHINCSPLUS-EC
          contains NO concrete checksum at all.  `encode_msgWOTS` is an ABSTRACT op
          (WOTS_TW_ES.ec:569) whose only constraint is the `two_encodings` axiom
          (:572); "checksum" appears solely as a comment on the len2 FORMULA (:39).
          The concrete checksum lives in the sibling FV-XMSS-EC
          (WOTS_TW_Checksum.ec:140), which this repo never requires -- MM45 REPLACED
          it with the abstract antichain axiom.  What `1 <= len2` forces is therefore
          WIDTH, not checksum semantics: len = len1 + len2 > len1 always, whereas
          deployed C10 signs exactly L = 43 = len1 chains.  Note len2 is a DEFINITION
          (:40), not a declared constant, so ge1_len2 (:133) is DERIVABLE and cannot
          be admitted away.

     (F3) BLOCKING, and the STRONGEST of the three -- but RESTATED.  The previous
          text said the axiom is FALSE at C10's actual encoding.  The truth is
          stronger: at C10's deployed WOTS GEOMETRY the axiom is UNSATISFIABLE --
          NO function whatsoever satisfies it.  Applied in both argument orders,
          `two_encodings` forces `encode_msgWOTS` to be INJECTIVE with an ANTICHAIN
          image in the pointwise order, so |msgWOTS| = 2^128 must fit inside the
          maximum antichain of the len-fold product of {0..w-1}.  Exact big-integer
          DP over that product's coefficients, with de Bruijn-Tengbergen-Kruyswijk
          CITED-NOT-FORMALISED for "max antichain = max rank layer":
              w=8  len=43  DEPLOYED    2^123.76  <   2^128    NO MODEL
              w=8  len=45              2^129.73  >=  2^128    ok
              w=8  len=46  MM45 shape  2^132.71  >=  2^128    ok
              w=16 len=35  SPHINCS+    2^133.90  >=  2^128    ok
          The two mechanisms previously given are subsumed or reclassified: the
          all-zero-domination case is a special case of the antichain bound, and the
          "127 discarded bits" point is a real model-vs-implementation width
          mismatch but not the defect F3 alleged.

   RETRACTION.  "Three INDEPENDENT grounds" is WRONG.  F3 SUPERSEDES F1 and F2: it
   is the claim that relaxing them is INSUFFICIENT.  No encoding exists at 43 base-8
   chains, so no relaxation of val_log2w or of len makes the deployed shape
   representable under the UNCONDITIONAL axiom.  These are ONE coupled obstruction,
   not three additive ones.

   TWO ANTI-MISREADS, BOTH LOAD-BEARING.
     1. This is NOT a defect in C10.  C10's encoding is DELIBERATELY non-injective:
        same-encoding pairs are meant to EXIST and merely to be hard to FIND, which
        is exactly what an S-TCR-on-Th+C term pays for.  The unsatisfiability is a
        fact about MM45's BUNDLED axiom at that geometry, not about the signer.
     2. The shipped development is NOT vacuous.  `two_encodings` is satisfiable at
        every admissible instantiation -- FV-XMSS-EC realizes it for the concrete
        checksum encoding (WOTS_TW_Checksum.ec:312) -- and w=8 is unsubstitutable,
        so the unsatisfiable regime is unreachable from here.  Every theorem in this
        development remains a valid theorem about SPHINCS+C at MM45-admissible WOTS
        parameters.

   PART B DOES NOT SUPPLY THE REPAIR IT CLAIMED TO.  The header previously said the
   right repair is the predC-RESTRICTED `two_encodings`, "which a checksum-free
   constant-sum encoding satisfies", citing constsum_encoding_is_two_encodings
   (:192).  That lemma's hypotheses are GLOBAL over all of msgWOTS -- `injective E`
   AND `forall m, digitsum (E m) = T` -- and at deployed geometry they are JOINTLY
   UNSATISFIABLE: the TARGET_SUM=205 layer holds only 2^114.09 points and even the
   largest layer holds 2^123.76, both below 2^128.  PART B is therefore VACUOUS at
   deployed parameters.  It remains a correct and useful result about the antichain
   half; it is NOT a deployed-parameter repair.

   THE ACTUAL SHAPE OF ANY FUTURE REPAIR.  MM45's `two_encodings` BUNDLES two
   properties: ANTICHAIN IMAGE and GLOBAL INJECTIVITY.  WOTS+C supplies the first via
   the constant-sum gate and PROVABLY CANNOT supply the second at 43 base-8 chains --
   an injective antichain encoding of 2^128 messages needs len >= 45 at w = 8, so
   deployed L = 43 is two chains short by counting alone.  Any sound
   deployed-parameter development must therefore DROP the injectivity half and charge
   same-encoding pairs to a computational term -- precisely the S-TCR-on-Th+C summand
   the paper's Thm 5.2 introduces.  That is a scoped separate project (a parametric
   WOTS+C layer with free (n, w, len) and a gate-restricted antichain hypothesis),
   NOT a patch to this development.

   DO NOT DO THE F1-ONLY REPAIR.  It is proven cheap, behaviour-preserving and
   0-admit across all three vendored levels -- and it buys ZERO claimable ground
   (len1 = 43 but len = 46 <> 43).  F1+F2 without F3 is strictly WORSE than the
   status quo: it yields a compiling but VACUOUS artifact.  Every route to a
   deployed-parameter claim edits or forks the vendored MM45 proof and forfeits the
   independently-published-artifact property, which is a large part of why this port
   is credible.

   CONSEQUENCE, UNCHANGED: what is mechanized here is the SPHINCS+C MECHANISM at
   MM45-admissible WOTS parameters, NOT deployed C10's WOTS layer.

   ASSUMPTION DISCLOSURE.  PART F's positive-mass corollary (C2) uses
   `FTWES.ddgstblock_fu` -- an INHERITED, UNREALIZED MM45 clone axiom
   (SPHINCS_PLUS.ec:455-517 clones FORS_ES without realizing `ddgstblock_fu`).
   It is pre-existing base TCB, not introduced here; the existential form (C1)
   is free of it.  NO new axiom is declared in this file.
   ========================================================================== *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.
require import RtopCSoundness.
require import FxChain.
require import GprocFORSC10.
require FORS_C10 FORS_C10_Multi.
require DigitalSignatures.
require import BitEncoding. import BS2Int BitChunking.
require import SphincsC10CapstoneWired.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.
import HA.Adrs.
import Bigint BIA.

(* ==========================================================================
   PART A -- the digit sum, and CONSTANT-SUM => ANTICHAIN.
   ========================================================================== *)

(* The constant-sum functional, over the PORT's `len` digits.
   NOT byte-identical to C10's: the port's `len = len1 + len2` INCLUDES checksum
   digits (WOTS_TW_ES.ec:43 with `ge1_len2`), whereas C10 sums over `L = 43 = len1`
   only and at `w = 8`, which this theory does not admit.  See the FAITHFULNESS note
   in the header.  The deployed analogue is sphincs-c10/src/wots.rs:64-67 (signer)
   and :156-161 (verifier's indexed re-computation).                          *)
op digitsum (e : emsgWOTS) : int = bigi predT (fun i => BaseW.val e.[i]) 0 len.

(* Equal digit sums + pointwise domination => equality. *)
lemma constsum_dominance (e e' : emsgWOTS) :
  digitsum e = digitsum e' =>
  (forall (i : int), 0 <= i < len => BaseW.val e'.[i] <= BaseW.val e.[i]) =>
  e = e'.
proof.
move=> hsum hdom.
apply EmsgWOTS.emsgWOTSP => i rgi.
apply BaseW.val_inj.
have hd : bigi predT (fun j => BaseW.val e.[j] - BaseW.val e'.[j]) 0 len = 0.
+ by rewrite -sumrB -/(digitsum e) -/(digitsum e') hsum.
have hin : i \in range 0 len by rewrite mem_range.
have hu : uniq (range 0 len) by exact: range_uniq.
have heq := bigD1 (fun j => BaseW.val e.[j] - BaseW.val e'.[j]) (range 0 len) i hin hu.
have hrest :
  0 <= big (predC1 i) (fun j => BaseW.val e.[j] - BaseW.val e'.[j]) (range 0 len).
+ by apply sumr_ge0_seq => j hj _ /=; smt(mem_range).
have hi := hdom i rgi.
move: heq; rewrite hd /=; smt().
qed.

(* THE ANTICHAIN PROPERTY.  Two DISTINCT encodings with the SAME digit sum always
   have an index at which the first is STRICTLY smaller.  This is EXACTLY the
   shape of MM45's `two_encodings` AXIOM (WOTS_TW_ES.ec:571-577) -- here PROVED,
   on the constant-sum-restricted set. *)
lemma constsum_antichain (e e' : emsgWOTS) :
  digitsum e = digitsum e' => e <> e' =>
  exists (i : int), 0 <= i < len /\ BaseW.val e.[i] < BaseW.val e'.[i].
proof.
move=> hsum hne.
have h : ! (forall (i : int), 0 <= i < len => BaseW.val e'.[i] <= BaseW.val e.[i]).
+ by apply/negP => hdom; apply hne; exact: (constsum_dominance e e' hsum hdom).
smt().
qed.

(* ==========================================================================
   PART B -- WHAT THE +C GATE BUYS: a constant-sum encoding satisfies MM45's
   `two_encodings` WITHOUT a checksum.  This is the formal content of the
   sphincs-c10 header comment ("Instead of a checksum (WOTS+ len2 chains),
   WOTS+C grinds a count value until the base-w digit sum equals TARGET_SUM.
   This eliminates checksum chains", src/wots.rs:3-5).
   ========================================================================== *)
lemma constsum_encoding_is_two_encodings (E : msgWOTS -> emsgWOTS) (T : int) :
  injective E =>
  (forall (m : msgWOTS), digitsum (E m) = T) =>
  forall (m m' : msgWOTS), m <> m' =>
    exists (i : int), 0 <= i < len /\ BaseW.val (E m).[i] < BaseW.val (E m').[i].
proof.
move=> hinj hcs m m' hne.
by apply constsum_antichain; [rewrite 2!hcs | apply/negP => h; apply hne; exact: hinj].
qed.

(* ==========================================================================
   PART C -- THE V1 MECHANISM, REFUTED AT ITS OWN PROCEDURE.
   scratch/audit_residual_predC_zeroes_lhs.ec STEP 1 proves
     (forall x, ! predC x) => hoare[ .. pkWOTS_from_sigWOTS_C : true ==> ! res.`2 ]
   i.e. the per-layer +C gate ALWAYS rejects.  Below is the two-sided companion:
   given the paper's p_nu ("it is always possible to find a good counter"), the
   SAME procedure ACCEPTS on the honestly-ground counter.
   ========================================================================== *)
lemma gate_passes_on_ground_counter (ps0 : pseed) (ad0 : adrs) (m0 : msgWOTS) :
  (exists (c : cntr), predC (ThC ps0 ad0 m0 c)) =>
  hoare[ FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C :
           ps = ps0 /\ ad = ad0 /\ m = m0 /\ counter = grindC ps0 ad0 m0
           ==> res.`2 ].
proof.
move=> hex; proc.
wp; while (ps = ps0 /\ ad = ad0 /\ m = m0 /\ counter = grindC ps0 ad0 m0).
+ by auto.
auto => />; rewrite /grindC => *.
exact: (wotsc_grind_targets_predC ps0 ad0 m0 hex).
qed.

(* ==========================================================================
   PART D -- THE NON-DEGENERATE SATISFIABILITY MODEL CORE.

   THE DELIVERABLE IS NOT "the premises are satisfiable" (already known).  It is
   "satisfiable by a model in which the theorem has CONTENT": predC NOT
   identically false AND emb_in NOT constant.  Both are established below.
   ========================================================================== *)

(* dgstblock has at least two elements (n >= 1). *)
lemma two_dgstblocks : exists (d0 d1 : dgstblock), d0 <> d1.
proof.
exists (DigestBlock.insubd (nseq (8 * n) false))
       (DigestBlock.insubd (true :: nseq (8 * n - 1) false)).
apply/negP => heq.
have h0 : DigestBlock.val (DigestBlock.insubd (nseq (8 * n) false)) = nseq (8 * n) false.
+ by rewrite DigestBlock.insubdK 1:size_nseq //; smt(ge1_n).
have h1 : DigestBlock.val (DigestBlock.insubd (true :: nseq (8 * n - 1) false))
          = true :: nseq (8 * n - 1) false.
+ by rewrite DigestBlock.insubdK //= size_nseq; smt(ge1_n).
have hc : nseq (8 * n) false = true :: nseq (8 * n - 1) false by rewrite -h0 -h1 heq.
have := congr1 (fun (s : bool list) => nth witness s 0) _ _ hc.
by rewrite /= nth_nseq; smt(ge1_n).
qed.

(* MODEL CORE for premises N1 (predC pinned to the C10 constant-sum gate) and
   N2 (the paper's p_nu).  `encode_msgWOTS` is the AMBIENT one, so MM45's
   `two_encodings` holds of it by hypothesis -- NOTHING about the base has to be
   re-established, which is what makes this a model of the WHOLE theory and not
   only of the two new premises.

   NON-DEGENERACY, both axes the task names:
     * P (the interpretation of predC) is NOT identically false;
     * H (the interpretation of ThC)   is NOT constant.
   The counter-distinctness hypothesis `c0 <> c1` is what the C10 32-bit counter
   space supplies (2^32 counters); it cannot be PROVED here because `type cntr`
   is abstract (only finiteness is carried, via STCRC_WC.G.CntrFT). *)
lemma MODEL_N1_N2_nondegenerate (c0 c1 : cntr) :
  c0 <> c1 =>
  exists (H : pseed -> adrs -> msgWOTS -> cntr -> dgstblock)
         (T : int) (P : dgstblock -> bool),
       (* N1 : P IS the C10 constant-sum gate at target T *)
       (forall (dgt : dgstblock), P dgt <=> digitsum (encode_msgWOTS dgt) = T)
       (* N2 : for EVERY (ps,ad,m) a good counter exists *)
    /\ (forall (ps : pseed) (ad : adrs) (m : msgWOTS), exists (cc : cntr), P (H ps ad m cc))
       (* NON-DEGENERACY 1 : P is NOT identically false *)
    /\ (! (forall (dgt : dgstblock), ! P dgt))
       (* NON-DEGENERACY 2 : H is NOT constant *)
    /\ (exists (ps ps' : pseed) (ad ad' : adrs) (m m' : msgWOTS) (cc cc' : cntr),
          H ps ad m cc <> H ps' ad' m' cc').
proof.
move=> hne01.
have [d0 d1 hd] := two_dgstblocks.
exists (fun (_ : pseed) (_ : adrs) (_ : msgWOTS) (cc : cntr) => if cc = c0 then d0 else d1)
       (digitsum (encode_msgWOTS d0))
       (fun (dgt : dgstblock) => digitsum (encode_msgWOTS dgt) = digitsum (encode_msgWOTS d0)).
split; first by move=> dgt /=.
split; first by move=> ps ad m; exists c0 => /=.
split; first by apply/negP => h; move: (h d0) => /=.
by exists witness witness witness witness witness witness c0 c1 => /=; smt().
qed.

(* HONEST CHARACTERISATION.  Whether the gate is a STRICT subset (i.e. whether it
   ever REJECTS) is EXACTLY non-constancy of the ambient digit-sum map, and that
   is decided by neither direction of the closure: `encode_msgWOTS` carries only
   `two_encodings`, which forces incomparability but NOT distinct digit sums.  At
   C10's deployed encoding (base_w of a 128-bit digest) the map is manifestly
   non-constant, so the gate is a strict non-empty subset -- a META-level remark
   about the intended instantiation, NOT a theory fact. *)
lemma MODEL_predC_strict_iff (T : int) :
  (exists (dgt : dgstblock), digitsum (encode_msgWOTS dgt) <> T)
  <=> ! (forall (dgt : dgstblock), digitsum (encode_msgWOTS dgt) = T).
proof. smt(). qed.

(* ==========================================================================
   PART E -- THE emb_in WITNESS.  A FAITHFUL `M || counter` serialisation that
   is CONSTANT-WIDTH and INJECTIVE -- hence, in particular, NOT CONSTANT, which
   is the exact V2 degeneracy.  It uses ONLY the counter finiteness the chain
   already carries (STCRC_WC.G.CntrFT); nothing new is assumed.
   ========================================================================== *)
(* The faithful `M || counter` serialisation, as a named op so that PART G can
   pin the ACTUAL `emb_in` to it. *)
op embg (r : int) (x : msgWOTS * cntr) : dgst =
  DigestBlock.val x.`1 ++ int2bs r (index x.`2 STCRC_WC.G.CntrFT.enum).

lemma embg_size (r : int) (x : msgWOTS * cntr) :
  0 <= r => size (embg r x) = 8 * n + r.
proof. by move=> ge0_r; rewrite /embg size_cat DigestBlock.valP size_int2bs; smt(). qed.

lemma embg_len (r : int) (x y : msgWOTS * cntr) :
  0 <= r => size (embg r x) = size (embg r y).
proof. by move=> ge0_r; rewrite (embg_size r x ge0_r) (embg_size r y ge0_r). qed.

lemma embg_inj (r : int) (x y : msgWOTS * cntr) :
  0 <= r => STCRC_WC.G.CntrFT.card <= 2 ^ r => embg r x = embg r y => x = y.
proof.
move=> ge0_r hcard.
have hidx_rng : forall (cc : cntr), 0 <= index cc STCRC_WC.G.CntrFT.enum < 2 ^ r.
+ move=> cc; split; 1: by exact index_ge0.
  move=> _.
  have h1 : index cc STCRC_WC.G.CntrFT.enum < size STCRC_WC.G.CntrFT.enum.
  + by rewrite index_mem; exact STCRC_WC.G.CntrFT.enumP.
  have h2 : size STCRC_WC.G.CntrFT.enum = STCRC_WC.G.CntrFT.card
    by rewrite /STCRC_WC.G.CntrFT.card.
  smt().
move: x y => [m cc] [m' cc'] /=; rewrite /embg /= => heq.
have hs : size (DigestBlock.val m) = size (DigestBlock.val m') by rewrite 2!DigestBlock.valP.
have hsplit : DigestBlock.val m = DigestBlock.val m'
              /\ int2bs r (index cc  STCRC_WC.G.CntrFT.enum)
                 = int2bs r (index cc' STCRC_WC.G.CntrFT.enum).
+ by rewrite -(eqseq_cat _ _ _ _ hs); apply heq.
case: hsplit => hm hc.
have hmm : m = m' by apply DigestBlock.val_inj.
have hii : index cc STCRC_WC.G.CntrFT.enum = index cc' STCRC_WC.G.CntrFT.enum.
+ have e1 := int2bsK r (index cc  STCRC_WC.G.CntrFT.enum) ge0_r (hidx_rng cc ).
  have e2 := int2bsK r (index cc' STCRC_WC.G.CntrFT.enum) ge0_r (hidx_rng cc').
  by rewrite -e1 -e2 hc.
have hcc : cc = cc'.
+ have n1 := nth_index witness cc  STCRC_WC.G.CntrFT.enum (STCRC_WC.G.CntrFT.enumP cc ).
  have n2 := nth_index witness cc' STCRC_WC.G.CntrFT.enum (STCRC_WC.G.CntrFT.enumP cc').
  by rewrite -n1 -n2 hii.
by rewrite hmm hcc.
qed.

lemma MODEL_emb_in_witness (r : int) :
  0 <= r =>
  STCRC_WC.G.CntrFT.card <= 2 ^ r =>
  exists (g : msgWOTS * cntr -> dgst),
       (* emb_in_len *)
       (forall (x y : msgWOTS * cntr), size (g x) = size (g y))
       (* emb_in_inj -- in particular g is NOT constant *)
    /\ (forall (x y : msgWOTS * cntr), g x = g y => x = y)
       (* the induced dfC = size (emb_in witness) *)
    /\ (forall (x : msgWOTS * cntr), size (g x) = 8 * n + r).
proof.
move=> ge0_r hcard; exists (embg r).
split; 1: by move=> x y; exact: (embg_len r x y ge0_r).
split; 2: by move=> x; exact: (embg_size r x ge0_r).
by move=> x y; exact: (embg_inj r x y ge0_r hcard).
qed.

(* The FOUR dfC separations the capstone carries, at the emb_in witness with the
   C10 counter width r = 32 and the port's own admissible parameters (n = 16,
   log2_w = 4 => len1 = 2n = 32, len2 = 3, len = 35; k = 13).  dfC = 8n + 32 = 160
   avoids all four.  NB `8*n + 32` is NOT universally safe -- at n = 4 it equals
   8*n*2 -- which is exactly why the four separations are premises, not lemmas. *)
lemma MODEL_dfC_separations_at_port_params :
     8 * 16 + 32 <> 8 * 16
  /\ 8 * 16 + 32 <> 8 * 16 * 35
  /\ 8 * 16 + 32 <> 8 * 16 * 2
  /\ 8 * 16 + 32 <> 8 * 16 * 13.
proof. smt(). qed.

lemma MODEL_dfC_8np32_unsafe_at_n4 : 8 * 4 + 32 = 8 * 4 * 2.
proof. smt(). qed.

(* ==========================================================================
   PART G -- THE JOINT MODEL, ON THE **ACTUAL GLOBALS**.

   PARTS D/E witness the premises with FRESH existentially-quantified functions.
   That is a legitimate but weak form of witness: those lemmas can be true while
   the ACTUAL `predC` is identically false and the ACTUAL `emb_in` is constant
   (external adversarial review, 2026-07-25, GPT-5.6 hole #1 -- correct).  PART G
   closes that gap: it pins the THREE ACTUAL GLOBALS by definitional equations and
   PROVES that all four added premises then hold AT THOSE GLOBALS, non-degenerately.

   WHY PINNING `thfc` AT ONE INDEX IS SOUND, AND NOT SCHEME-DESTROYING.
   `f = thfc (8*n)`, `trh = thfc (8*n*2)`, `pkco = thfc (8*n*len)` and
   `trco = thfc (8*n*k)` (SPHINCS_PLUS.ec:440-449) are the SAME `thfc` at fixed
   indices.  Constraining `thfc` at EVERY index would make all four constant and
   collapse the whole scheme.  Hypothesis (iii) below therefore constrains `thfc`
   at the SINGLE index `8*n + r` = `dfC`, which the capstone's own four separation
   premises (`dfC <> 8*n`, `<> 8*n*len`, `<> 8*n*2`, `<> 8*n*k`) guarantee is
   DISTINCT from all four.  So `f`/`trh`/`pkco`/`trco` remain entirely free in this
   model -- they may be as good a hash family as one likes.  That is precisely the
   job those four separation premises do.

   THE REMAINING META-STEP (the honest residual).  EasyCrypt cannot re-interpret an
   already-declared op from inside the theory, so (i)-(iii) are HYPOTHESES here
   rather than a clone-realization.  Their simultaneous satisfiability rests on:
   (a) `predC`, `emb_in` and `thfc` carry NO axiom anywhere in the closure (axiom
   census, independently confirmed by two external reviewers); and (b) the three
   equations are NON-CIRCULAR -- `emb_in` is fixed from primitives, `predC` from
   `encode_msgWOTS`, and `thfc` at one index from `emb_in`.
   ========================================================================== *)
lemma MODEL_JOINT_on_actual_globals (r : int) (c0 c1 : cntr) (d0 d1 : dgstblock) :
  0 <= r =>
  STCRC_WC.G.CntrFT.card <= 2 ^ r =>
  c0 <> c1 =>
  d0 <> d1 =>
  (* (i) the ACTUAL emb_in IS the faithful `M || counter` serialisation *)
  emb_in = embg r =>
  (* (ii) the ACTUAL predC IS the C10 constant-sum gate, at a REACHABLE target *)
  predC = (fun (dgt : dgstblock) =>
             digitsum (encode_msgWOTS dgt) = digitsum (encode_msgWOTS d0)) =>
  (* (iii) the ACTUAL thfc, AT THE SINGLE INDEX dfC ONLY (see the note above) *)
  (forall (ps : pseed) (tw : adrs) (x : dgst),
     thfc (8 * n + r) ps tw x
     = if (exists (mm : msgWOTS), x = emb_in (mm, c0)) then d0 else d1) =>
  (* (iv) the ACTUAL encode_msgWOTS_C -- a FREE op (WOTS_C_Real.ec:220, no axiom
         anywhere), so the capstone's OWN bridge premise is discharged by this same
         model rather than left dangling (external review, Kimi K3, 2026-07-25). *)
  encode_msgWOTS_C = (fun (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr) =>
                        encode_msgWOTS (ThC p a x cc)) =>
    (* ==== the induced dfC ==== *)
       dfC = 8 * n + r
    (* ==== the CAPSTONE'S OWN bridge premise, at the actual globals ==== *)
    /\ (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
          encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc))
    (* ==== ALL FOUR ADDED PREMISES, AT THE ACTUAL GLOBALS ==== *)
    /\ (forall (dgt : dgstblock),
          predC dgt <=> digitsum (encode_msgWOTS dgt) = digitsum (encode_msgWOTS d0))
    /\ (forall (ps : pseed) (ad : adrs) (mm : msgWOTS), exists (cc : cntr), predC (ThC ps ad mm cc))
    /\ (forall (x y : msgWOTS * cntr), size (emb_in x) = size (emb_in y))
    /\ (forall (x y : msgWOTS * cntr), emb_in x = emb_in y => x = y)
    (* ==== NON-DEGENERACY, AT THE ACTUAL GLOBALS ==== *)
    /\ (! (forall (dgt : dgstblock), ! predC dgt))                (* predC NOT identically false *)
    /\ (exists (x y : msgWOTS * cntr), emb_in x <> emb_in y)      (* emb_in NOT constant *)
    /\ (exists (ps : pseed) (tw : adrs) (mm : msgWOTS) (j j' : cntr),
          ThC ps tw mm j <> ThC ps tw mm j').                     (* ThC NOT constant, at ONE (ps,tw,mm) *)
proof.
move=> ge0_r hcard hc01 hd01 hemb hpre hthf hencC.
have hdf : dfC = 8 * n + r by rewrite /dfC hemb (embg_size r witness ge0_r).
have hThC0 : forall (ps : pseed) (tw : adrs) (mm : msgWOTS), ThC ps tw mm c0 = d0.
+ move=> ps tw mm.
  have hs : size (emb_in (mm, c0)) = 8 * n + r by rewrite hemb (embg_size r (mm, c0) ge0_r).
  rewrite /ThC hs hthf.
  have hex : exists (mm' : msgWOTS), emb_in (mm, c0) = emb_in (mm', c0) by exists mm.
  by rewrite hex.
have hThC1 : forall (ps : pseed) (tw : adrs) (mm : msgWOTS), ThC ps tw mm c1 = d1.
+ move=> ps tw mm.
  have hs : size (emb_in (mm, c1)) = 8 * n + r by rewrite hemb (embg_size r (mm, c1) ge0_r).
  rewrite /ThC hs hthf.
  have hnex : ! (exists (mm' : msgWOTS), emb_in (mm, c1) = emb_in (mm', c0)).
  + apply/negP => [[mm' heq]].
    have : (mm, c1) = (mm', c0).
    + by apply (embg_inj r (mm, c1) (mm', c0) ge0_r hcard); move: heq; rewrite hemb.
    smt().
  by rewrite hnex.
split; 1: by exact hdf.
split; 1: by move=> p a x cc; rewrite hencC.
split; 1: by move=> dgt; rewrite hpre.
split; 1: by move=> ps ad mm; exists c0; rewrite hThC0 hpre.
split; 1: by move=> x y; rewrite hemb; exact: (embg_len r x y ge0_r).
split; 1: by move=> x y; rewrite hemb; exact: (embg_inj r x y ge0_r hcard).
split; 1: by apply/negP => h; move: (h d0); rewrite hpre.
split.
+ exists (d0, c0) (d1, c0); rewrite hemb; apply/negP => heq.
  by have := embg_inj r (d0, c0) (d1, c0) ge0_r hcard heq; smt().
by exists witness witness witness c0 c1; rewrite hThC0 hThC1.
qed.

(* ---- WHAT PART G DOES **NOT** ACHIEVE (external review, 2026-07-25) --------
   The witness above makes `ThC` non-constant, but at any FIXED counter it still
   maps every message to the same digest, so the S-TCR(+C) win condition
   `ThC pp tw m j = ThC pp tw m' ctr /\ m' <> m` (STCR_C.ec:215-220) is satisfiable
   in it.  That is NOT a defect of this particular witness: it is UNAVOIDABLE.

   PIGEONHOLE ARGUMENT (stated, NOT mechanized -- honest limit).  `msgWOTS` IS
   `dgstblock` (WOTS_TW_ES.ec:219), so the two have equal, finite cardinality.
   Take the Skolem counter to be the SIGNER'S OWN one, `c_m := grindC ps tw m`:
   CONCLUSION 4 of PART F proves `predC (ThC ps tw m (grindC ps tw m))` for EVERY m
   under N2.  (Using `grindC` rather than an arbitrary Skolem witness is what makes
   the argument land on the S-TCR game's ACTUAL recorded targets -- the challenge
   oracle records exactly `j = grind pp tw m`, STCR_C.ec:127-137.  External review,
   Kimi K3, 2026-07-25, correctly flagged the arbitrary-Skolem version as not
   reaching the game's win condition.)
   So m |-> ThC ps tw m (grindC ps tw m) maps msgWOTS INTO the gate set.  If the gate
   ever REJECTS -- i.e. `predC` is a STRICT subset -- then |predC| < |dgstblock| =
   |msgWOTS|, so that map cannot be injective: some m <> m' have
   `ThC ps tw m (grindC ps tw m) = ThC ps tw m' (grindC ps tw m')`.  That is exactly
   the S-TCR win condition at the recorded target for m with forgery
   `(m', grindC ps tw m')`.  A winning pair ALWAYS EXISTS.

   CONSEQUENCE, stated plainly: the RHS-side non-degeneracy "the S-TCR(+C) term is
   not ~1" is NOT achievable by ANY model-theoretic premise, because S-TCR security
   is about the HARDNESS OF FINDING such a collision, not its non-existence -- and
   existence is forced.  This is FAITHFUL to the real scheme (at C10's parameters
   the constant-sum set is a ~2^-15 fraction of the digest space, so gate-passing
   collisions are abundant; security rests entirely on `thfc` being hard to invert).
   What N3/N4 DO exclude is the degeneracy that is OURS rather than the hash's: a
   collapsing SERIALISATION, which would trivialise S-TCR independently of how good
   `thfc` is.  That is the honest scope of the V2 repair.
   ------------------------------------------------------------------------- *)

(* ==========================================================================
   PART F -- THE CONTENTFUL CAPSTONE.

   The capstone bound, RE-DERIVED VERBATIM by APPLYING the UNCHANGED
   `EUFCMA_SPHINCS_PLUS_C10` (so nothing is weakened and the RHS cannot have
   drifted -- `exact` would fail), CONJOINED with the facts that exclude V1/V2.

   The FOUR added premises N1-N4 are NON-DEGENERACY premises: they are NOT used
   to prove the bound (the bound is the capstone's, unchanged); they narrow the
   models to those in which the statement has content.  Each has its witness in
   PART D/E above.  N2 is the WOTS-side analogue of the FORS-side `good_pos`,
   which the chain carries as an AXIOM (FORS_C10.ec:208) -- so N2 is strictly
   better: an inspectable premise instead of an axiom, and in its EXISTENTIAL
   (weaker) form rather than the probability form.
   ========================================================================== *)
lemma EUFCMA_SPHINCS_PLUS_C10_CONTENTFUL
  (F <: Adv_EUFCMA_C{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V, -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default,
             -R_top,
             -DSSC.Stateless.O_CMA_Default, -O_CMA_SPHINCSPLUSTWC_FS,
             -SKG_PRF.O_PRF_Default, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V,
             -R_top_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV,
             -R_fors_p, -O_CMA_Gproc, -O_CMA_Gproc_I, -R_ITSRC10_Gproc,
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default })
  (mkg_adv : real)
  (mtree_openpre mtree_trh mtree_trco : real)
  (target_sum : int)
  &m :
    (* ---- the capstone's OWN premises, verbatim ---- *)
    c <= p_tgts =>
    0%r <= mkg_adv =>
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC <> 8 * n =>
    dfC <> 8 * n * len =>
    dfC <> 8 * n * 2 =>
    dfC <> 8 * n * k =>
    (   Pr[EUF_CMA_Gproc_I(R_fors_p(F)).main() @ &m
             : res /\ !EUF_CMA_Gproc_I.covered]
     <= mtree_openpre + mtree_trh + mtree_trco) =>
    (* ---- N1: predC IS the C10 constant-sum gate (witness: MODEL_N1_N2) ---- *)
    (forall (dgt : dgstblock), predC dgt <=> digitsum (encode_msgWOTS dgt) = target_sum) =>
    (* ---- N2: p_nu -- a good counter always exists (witness: MODEL_N1_N2) ---- *)
    (forall (ps : pseed) (ad : adrs) (mm : msgWOTS), exists (cc : cntr), predC (ThC ps ad mm cc)) =>
    (* ---- N3/N4: emb_in constant-width + injective (witness: MODEL_emb_in) ---- *)
    (forall (x y : msgWOTS * cntr), size (emb_in x) = size (emb_in y)) =>
    (forall (x y : msgWOTS * cntr), emb_in x = emb_in y => x = y) =>
       (* ==== CONCLUSION 1: THE CAPSTONE BOUND, UNCHANGED AND UNWEAKENED ==== *)
       (Pr[EUFCMA_C10(F).main() @ &m : res]
          <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
               - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
           + mkg_adv
           + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(F)),
                              M.F.O_ITSRC10_Default).main() @ &m : res]
               + mtree_openpre + mtree_trh + mtree_trco )
           + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                          O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
               + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                   STCRC_WC.O_STCRC_Default).main() @ &m : res]
               + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(F)),
                      FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                      FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
               + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(F)),
                      FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                      FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res] ))
       (* ==== CONCLUSION 2 (the V1 MECHANISM excluded): the EXACT hypothesis of
               predC_false_zeroes_capstone_LHS is REFUTED.
               PRECISION (do not overstate): refuting an implication's hypothesis does
               NOT falsify its conclusion.  What is established is that the KNOWN
               MECHANISM by which the LHS was shown identically zero is excluded -- NOT
               that the LHS is nonzero.  Proving `Pr[EUFCMA_C10(F0)] > 0` for some F0
               needs honest-signature verification through the d-layer address/root
               bookkeeping of `root_from_sigC`, i.e. SCHEME CORRECTNESS, which MM45
               never proves for any scheme and which is the genuine next rung. ==== *)
    /\ (! (forall (x : dgstblock), ! predC x))
       (* ==== CONCLUSION 3: the FORS `good_pos` SHAPE, DERIVED (uses the
               inherited FTWES.ddgstblock_fu; see the header disclosure). ==== *)
    /\ 0%r < mu ddgstblock predC
       (* ==== CONCLUSION 4: EVERY honestly-ground counter passes the +C gate,
               at EVERY (ps,ad,m).  This is the mechanism the V1 audit zeroed. ==== *)
    /\ (forall (ps : pseed) (ad : adrs) (mm : msgWOTS), predC (ThC ps ad mm (grindC ps ad mm)))
       (* ==== CONCLUSION 5 (the V2 MECHANISM excluded): the S-TCR(+C) win condition is a GENUINE
               second preimage on a SINGLE collection member at a SINGLE tweak --
               not a trivial coincidence forced by a collapsing serialisation. ==== *)
    /\ (forall (ps : pseed) (tw : adrs) (mm mm' : msgWOTS) (j cc : cntr),
          mm' <> mm =>
             emb_in (mm, j) <> emb_in (mm', cc)
          /\ ThC ps tw mm  j  = thfc dfC ps (emb_tw tw) (emb_in (mm , j ))
          /\ ThC ps tw mm' cc = thfc dfC ps (emb_tw tw) (emb_in (mm', cc)))
       (* ==== CONCLUSION 6: on the gate-restricted set, MM45's `two_encodings`
               antichain condition holds.

               HONESTY NOTE (2026-07-25, established by running the control
               scratch/trackV_probe_C6_without_N1.ec, which COMPILED): unlike
               conclusions 2-5, THIS conclusion is NOT premise-dependent.  It is
               already derivable from MM45's own unconditional `two_encodings`
               AXIOM (WOTS_TW_ES.ec:571), because `encode_msgWOTS d <>
               encode_msgWOTS d'` forces `d <> d'`.  It is retained only to
               display the relationship; it adds NO content here.
               The INFORMATIVE version is PART B above
               (`constsum_encoding_is_two_encodings`), which is quantified over an
               ARBITRARY encoding E and therefore genuinely shows that a
               CHECKSUM-FREE constant-sum encoding satisfies the antichain
               condition -- a fact the ambient axiom cannot supply. ==== *)
    /\ (forall (d d' : dgstblock),
          predC d => predC d' => encode_msgWOTS d <> encode_msgWOTS d' =>
          exists (i : int), 0 <= i < len
                 /\ BaseW.val (encode_msgWOTS d).[i] < BaseW.val (encode_msgWOTS d').[i]).
proof.
move=> hc hmkg hencb hdf8n hdflen hdf2 hdfnk htree hN1 hN2 hN3 hN4.
(* --- CONCLUSION 1: APPLY the unchanged capstone. --- *)
have hcap := EUFCMA_SPHINCS_PLUS_C10 F mkg_adv mtree_openpre mtree_trh mtree_trco &m
               hc hmkg hencb hdf8n hdflen hdf2 hdfnk htree.
split; 1: by exact hcap.
(* --- CONCLUSION 2: predC is not identically false. --- *)
have [cc0 hcc0] := hN2 witness witness witness.
split; 1: by apply/negP => h; move: (h (ThC witness witness witness cc0)).
(* --- CONCLUSION 3: positive mass. --- *)
split.
+ have h1 : 0%r < mu1 ddgstblock (ThC witness witness witness cc0).
  + have := FTWES.ddgstblock_fu (ThC witness witness witness cc0); smt(@Distr).
  have h2 : mu1 ddgstblock (ThC witness witness witness cc0) <= mu ddgstblock predC
    by apply mu_sub => y /=; smt().
  smt().
(* --- CONCLUSION 4: the ground counter always passes the gate. --- *)
split.
+ move=> ps ad mm; rewrite /grindC.
  exact: (wotsc_grind_targets_predC ps ad mm (hN2 ps ad mm)).
(* --- CONCLUSION 5: genuine second preimage on a single member. --- *)
split.
+ move=> ps tw mm mm' j cc hne.
  split; 1: by exact: (ThC_genuine_2ndpreimage mm mm' j cc hN4 hne).
  by split; apply ThC_same_member.
(* --- CONCLUSION 6: the gate restores the antichain condition. --- *)
move=> d d' hd hd' hnee.
by apply constsum_antichain => //; rewrite (hN1 d) in hd; rewrite (hN1 d') in hd'; smt().
qed.
