(* ==========================================================================
   COMPOSITION / EXTRACTION LEMMA — step 2 of the five-step route.

   GOAL (GPT-5.6's formulation): for each accepted forgery, extract EITHER a
   lower-layer FORS/tree break, OR an address-bound codeword target collision,
   OR the distinct-codeword case Definition 9 already handles.

   NON-VACUITY — read this before reading the lemmas.
   A bare trichotomy `A \/ (¬A /\ B) \/ (¬A /\ ¬B)` is a TAUTOLOGY and proves
   nothing.  The content here is that the composition is **THREE-WAY AND NOT
   FOUR-WAY**: there is a fourth combination which no assumption in the ledger
   charges, and it is eliminated by the encoder bridge (EncoderBridge.ec) rather
   than assumed away.  Delete the bridge and this file's main lemma becomes
   FALSE, not merely unprovable — that is what makes it a real statement.
   ========================================================================== *)
require import AllCore List Distr.
require import SPHINCS_PLUS.
require WOTS_C_Real.
require import WOTS_C_Scheme.

import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import EmsgWOTS.

(* --------------------------------------------------------------------------
   THE THREE CHARGES.  Each names the assumption that pays for it.
   `m`  = the CANONICAL node the honest signer signed at address `ad`
   `m'` = the node the forged signature reconstructs to at that same address
   -------------------------------------------------------------------------- *)

(* A — the forgery reconstructs the SAME node.  The WOTS layer is then not
   broken at all: the signature on that node is the honest one.  The break must
   be LOWER-LAYER (FORS few-time coverage, or a tree second-preimage).  Charged
   to the FORS/ITSRC10 side of the ledger, NOT to anything WOTS-level. *)
op ChargeA (m m' : msgWOTS) : bool = m' = m.

(* B — different node, but the TWEAKABLE HASH collides.  This is an
   address-bound target collision: charged to S-TCR(+C) (SPHINCS+C Def C.1),
   whose game the port already reduces to (WOTS_C_Reduction.ec). *)
op ChargeB (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr) : bool =
  m' <> m /\ ThC ps ad m' c' = ThC ps ad m c.

(* C — different node, different CODEWORD.  This is precisely the hypothesis the
   weakened `nhchwcoll_hchwpre` consumes (unit 1), so the existing WOTS chain
   argument runs unchanged under Def 9 incomparability. *)
op ChargeC (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr) : bool =
  m' <> m /\ encode_msgWOTS_C ps ad m' c' <> encode_msgWOTS_C ps ad m c.

(* --------------------------------------------------------------------------
   THE FOURTH CASE — the one nothing in the ledger charges.

   Different node, tweakable hash DIFFERS, yet the codewords AGREE.  Def 9 does
   not reach it (Def 9 constrains DISTINCT codewords; here they are equal) and
   S-TCR(+C) does not reach it either (the ThC values differ, so there is no
   target collision to hand the reduction).  If this case were inhabited the
   composition would be FOUR-way with an uncharged branch, and the leg would be
   unclosable without a new assumption.
   -------------------------------------------------------------------------- *)
op Orphan (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr) : bool =
     m' <> m
  /\ ThC ps ad m' c' <> ThC ps ad m c
  /\ encode_msgWOTS_C ps ad m' c' = encode_msgWOTS_C ps ad m c.

(* The encoder bridge, as an explicit hypothesis (NOT axiomatised here).
   EncoderBridge.ec proves its mathematical core at C10 geometry: the base-8
   digit map is injective on 128-bit digests because 43*3 = 129 >= 128. *)
op EncInj : bool =
  forall (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr),
    encode_msgWOTS_C ps ad m' c' = encode_msgWOTS_C ps ad m c =>
    ThC ps ad m' c' = ThC ps ad m c.

(* The CONVERSE direction, and a genuinely SEPARATE hypothesis: equal ThC values
   give equal codewords, i.e. the encoding FACTORS through ThC
   (`encode_msgWOTS_C p a x c = encode_msgWOTS (ThC p a x c)`, the bridge recorded
   at XmssmtCC_All.ec:1178).  This is NOT derivable here -- `encode_msgWOTS_C` is
   an ABSTRACT op (WOTS_C_Real.ec:220) -- and it is needed for DISJOINTNESS, not
   for exhaustiveness.  Discovered by the compiler refusing the disjointness
   proof, which is exactly what an honest formalisation should do. *)
op ThCDeterminesCodeword : bool =
  forall (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr),
    ThC ps ad m' c' = ThC ps ad m c =>
    encode_msgWOTS_C ps ad m' c' = encode_msgWOTS_C ps ad m c.

(* ==========================================================================
   RESULT 1 — the orphan case is EMPTY under the bridge.
   This is the load-bearing step: it is what turns a 4-way split into a 3-way
   one, and it is exactly where EncoderBridge.ec is consumed.
   ========================================================================== *)
lemma orphan_empty (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr) :
  EncInj => ! Orphan ps ad m m' c c'.
proof.
rewrite /EncInj /Orphan => hinj; apply/negP => -[hne [hthc henc]].
by apply hthc; apply hinj.
qed.

(* ==========================================================================
   RESULT 2 — THE COMPOSITION LEMMA.

   Every forgery at a given address falls into exactly one of the three CHARGED
   cases.  Note the hypothesis: without `EncInj` this is FALSE (the orphan case
   escapes all three), so the statement is not a tautology.
   ========================================================================== *)
lemma composition_is_threeway (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr) :
     EncInj
  =>    ChargeA m m'
     \/ ChargeB ps ad m m' c c'
     \/ ChargeC ps ad m m' c c'.
proof.
rewrite /ChargeA /ChargeB /ChargeC /EncInj => hinj.
case: (m' = m) => [-> | hneq]; 1: by left.
case: (ThC ps ad m' c' = ThC ps ad m c) => hthc; 1: by right; left.
right; right; split; 1: by [].
apply/negP => heq.
by apply hthc; apply hinj.
qed.

(* ==========================================================================
   RESULT 3 — the charges are MUTUALLY EXCLUSIVE, so "extract" is well-defined:
   a forgery cannot be double-counted across two assumptions.
   ========================================================================== *)
lemma charges_disjoint_AB (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr) :
  ChargeA m m' => ! ChargeB ps ad m m' c c'.
proof. by rewrite /ChargeA /ChargeB => ->; apply/negP => -[]. qed.

lemma charges_disjoint_AC (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr) :
  ChargeA m m' => ! ChargeC ps ad m m' c c'.
proof. by rewrite /ChargeA /ChargeC => ->; apply/negP => -[]. qed.

lemma charges_disjoint_BC (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr) :
     ThCDeterminesCodeword
  => ChargeB ps ad m m' c c' => ! ChargeC ps ad m m' c c'.
proof.
rewrite /ThCDeterminesCodeword /ChargeB /ChargeC => hfac -[hne heq].
by apply/negP => -[_ hnenc]; apply hnenc; apply hfac.
qed.

(* ==========================================================================
   RESULT 4 — case C hands the WOTS chain argument EXACTLY its hypothesis.
   (Companion to Extraction.ec's `extraction_good_branch`, restated over the
   charge so the composition is self-contained.)
   ========================================================================== *)
lemma chargeC_feeds_chain (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr) :
     ChargeC ps ad m m' c c'
  => encode_msgWOTS_C ps ad m' c' <> encode_msgWOTS_C ps ad m c.
proof. by rewrite /ChargeC => -[_ ?]. qed.

(* ==========================================================================
   HONEST MARKER — what this file does NOT do.

   * It does NOT connect to the SPHINCS+ VERIFY procedure.  `m'` is taken as
     "the node the forgery reconstructs to"; PROVING that an accepted signature
     yields such an `m'` at a specific address is the FORS->hypertree half of
     step 2, and needs attacker-controlled `R` and address grinding
     (hypertree.rs:378,418 reconstruct the node from adversary-supplied
     material).  NOT attempted here.
   * It does NOT charge ChargeA.  That is the lower-layer FORS/tree obligation
     and lands on ITSRC10, which has no theorem in the literature.
   * It does NOT bound any probability.  `Pr[G /\ COLL]` is untouched; this is
     the EVENT DECOMPOSITION only, which is what step 2 asks for and no more.
   ========================================================================== *)
