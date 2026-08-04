(* ==========================================================================
   PREMISE REDUCTION — Composition.ec's two hypotheses are NOT new assumptions.

   `Composition.ec` states two premises and deliberately does not axiomatise
   them:

     EncInj                 equal codewords => equal ThC     (exhaustiveness)
     ThCDeterminesCodeword  equal ThC => equal codewords      (disjointness)

   I introduced both as if they were fresh.  They are not.  The chain ALREADY
   carries, as an explicit premise threaded through every interactive hop, the
   ENCODE BRIDGE

       forall p a x cc, encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)

   -- `WOTS_C_Interactive.ec:1006,1277,1346,1561,1794,1916,1991`, `SPHINCS_C.ec:176`,
   and the capstone WIPs.  This file shows what that premise buys:

     * `ThCDeterminesCodeword` follows from the bridge ALONE.  Zero new assumptions.
     * `EncInj` follows from the bridge PLUS injectivity of `encode_msgWOTS`,
       and under the bridge it is EQUIVALENT to injectivity of `encode_msgWOTS`
       ON THE IMAGE OF ThC -- not globally.

   WHY THE "ON THE IMAGE" PART MATTERS.  It is the exact amount of injectivity
   the composition needs, and it is strictly less than what MM45's original
   `two_encodings` demanded.  Keep the two failure modes distinct:

     * INJECTIVITY at C10 is FINE: the digit map sends 128-bit digests into a
       129-bit codeword space (`Proj129.c10_enc_inj_129`, exactly tight).
     * The ANTICHAIN half of the original `two_encodings` is what is
       unsatisfiable at C10 (largest antichain of {0..7}^43 is 2^123.76 < 2^128).

   Unit 1 removed the antichain demand.  It did NOT remove injectivity, and
   injectivity is not the thing that was ever in trouble.

   STATUS: STANDALONE LEAF, GATED NOT WIRED.  Proving these two implications
   does not by itself discharge anything in the chain -- the chain's hops take
   the bridge as a premise and still do.  What this buys is bookkeeping honesty:
   the composition's assumption count drops from two bespoke premises to one
   already-carried premise plus one crisp classical property.
   ========================================================================== *)
require import AllCore List Distr.
require import SPHINCS_PLUS.
require WOTS_C_Real.
require import WOTS_C_Scheme.
require import Composition.

import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import EmsgWOTS.

(* The chain's own premise, named.  Transcribed VERBATIM from the binder at
   WOTS_C_Interactive.ec:1561 -- if this drifts from the chain, the reduction
   below stops meaning what it claims, so it is written out rather than cited. *)
op EncodeBridge : bool =
  forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
    encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc).

(* Injectivity of the MM45 encoder, stated explicitly rather than via `injective`
   so the statement is readable next to the ops it constrains. *)
op EncMsgInj : bool =
  forall (u v : msgWOTS), encode_msgWOTS u = encode_msgWOTS v => u = v.

(* The WEAKER, exact requirement: injectivity only where ThC actually lands, and
   only AT A FIXED (ps, ad).  The address binding is not incidental -- `EncInj`
   itself is stated at a common (ps, ad) (`Composition.ec:68-71`), because the
   whole composition is address-bound (that is what S-TCR(+C) buys).  An earlier
   draft of this file quantified over two INDEPENDENT addresses; that version is
   strictly stronger than `EncInj` and the equivalence below would have been
   FALSE.  Caught before compiling, recorded so the shape is not "simplified"
   back later. *)
op EncMsgInjOnThCImage : bool =
  forall (ps : pseed) (ad : adrs) (m m' : msgWOTS) (c c' : cntr),
    encode_msgWOTS (ThC ps ad m c) = encode_msgWOTS (ThC ps ad m' c') =>
    ThC ps ad m c = ThC ps ad m' c'.

(* ==========================================================================
   RESULT 1 — disjointness is FREE.  `ThCDeterminesCodeword` needs the bridge
   and nothing else.
   ========================================================================== *)
lemma thc_determines_from_bridge : EncodeBridge => ThCDeterminesCodeword.
proof.
rewrite /EncodeBridge /ThCDeterminesCodeword => hb ps ad m m' c c' heq.
by rewrite !hb heq.
qed.

(* ==========================================================================
   RESULT 2 — exhaustiveness costs exactly ONE classical property.
   ========================================================================== *)
lemma encinj_from_bridge_and_inj : EncodeBridge => EncMsgInj => EncInj.
proof.
rewrite /EncodeBridge /EncMsgInj /EncInj => hb hinj ps ad m m' c c' heq.
by apply hinj; move: heq; rewrite !hb.
qed.

(* The sharper form: only injectivity ON ThC's IMAGE is needed. *)
lemma encinj_from_bridge_and_image_inj :
  EncodeBridge => EncMsgInjOnThCImage => EncInj.
proof.
rewrite /EncodeBridge /EncMsgInjOnThCImage /EncInj => hb hinj ps ad m m' c c' heq.
by apply (hinj ps ad m' m c' c); move: heq; rewrite !hb.
qed.

(* ...and it is not merely sufficient, it is EQUIVALENT under the bridge, so
   this is the EXACT amount of injectivity the composition consumes -- no more. *)
lemma image_inj_from_encinj : EncodeBridge => EncInj => EncMsgInjOnThCImage.
proof.
rewrite /EncodeBridge /EncInj /EncMsgInjOnThCImage => hb he ps ad m m' c c' heq.
by apply (he ps ad m' m c' c); rewrite !hb.
qed.

(* Global injectivity trivially implies the image form. *)
lemma global_inj_implies_image_inj : EncMsgInj => EncMsgInjOnThCImage.
proof. by rewrite /EncMsgInj /EncMsgInjOnThCImage => h ps ad m m' c c'; apply h. qed.

(* ==========================================================================
   THE LEDGER, after this file.

   Composition.ec's premises now stand as:

     ThCDeterminesCodeword  <=  EncodeBridge                       [chain premise]
     EncInj                 <=  EncodeBridge + EncMsgInjOnThCImage [chain premise
                                                                    + injectivity]

   and `EncMsgInjOnThCImage` is the ONLY thing not already carried by the chain.

   WHAT IS STILL OWED — do not read this file as closing the gap.
   `encode_msgWOTS` is ABSTRACT in base-c10 (`WOTS_TW_ES.ec:563`), constrained
   only by the weakened `two_encodings` (:579) and `enc_nonzero` (:597).
   NEITHER gives injectivity, deliberately.  So `EncMsgInjOnThCImage` is not
   derivable here.  `Proj129.c10_enc_inj_129` gives the arithmetic REASON it
   holds at C10 -- the base-8 digit map is injective on [0, 2^129) -- but
   converting that into this premise requires IDENTIFYING `encode_msgWOTS` with
   the digit map and `ThC`'s output with the deployed 129-bit projection.  That
   identification is unwired and remains the single outstanding obligation on
   this path.
   ========================================================================== *)
