(* ==========================================================================
   COUNTERMODEL — the BadEnc term is 1, so it CANNOT be bounded at this layer.

   The charged WOTS-TW bound (WOTS_TW_ES.ec, this fork) replaces MM45's admitted
   encoder injectivity with an explicit summand

       Pr[Game4_WOTSTWES_BadEnc(A) : res /\ BadEncFlag.badenc].

   The obvious next question is "how small is it?".  THE ANSWER IS: NOT SMALL.
   For an explicit adversary it is exactly 1, so no non-trivial bound exists at
   the WOTS-TW layer, and the charged theorem — while TRUE — is quantitatively
   VACUOUS when applied to an arbitrary `Adv_MEUFGCMA_WOTSTWESNPRF`.

   WHY.  Verification reads the message ONLY through its codeword:
   `pkWOTS_from_sigWOTS` (:2333) computes `em <- encode_msgWOTS m` (:2341) and
   its loop touches `em` alone.  So under an encoding collision a signature for
   `m` is *already* a signature for `m'`, and the adversary forges by replaying
   it.  Every other win conjunct falls out:

     is_fresh      m' <> m                                    (hypothesis)
     !hchwcoll     em = em' makes the strict digit inequality
                   `BaseW.val em'.[i] < BaseW.val em.[i]` FALSE at every index
     P m'          from P m, since P depends only on the codeword
     dist_wgpidxs  `uniq` of a ONE-element list
     disj_wgpidxs  the adversary never queries OC, so adlOC = []
     0 <= nrqs <= c  one query, and `ge1_c` gives 1 <= c

   THIS IS NOT A NEW DEFECT.  It is the precise formal content of "MM45's WOTS-TW
   theorem is false at deployed C10 geometry": the theorem quantifies over ALL
   msgWOTS, and at deployed widths the encoder is 2^127-to-one.  The charged
   bound is progress toward an HONEST STRUCTURE, not toward a small number — the
   term has to be bounded one layer UP, at +C, where the WOTS message is
   `ThC ps ad x c` and the adversary cannot choose it freely.

   *** THE DEPLOYED WALLET IS NOT AFFECTED, AND THIS IS NOT AN ATTACK. ***
   C10's WOTS layer never encodes an adversary-chosen value — it encodes
   key-determined internal nodes (sphincs-c10/src/fors.rs:265-268;
   `compute_fors_pk` takes no message argument).  The adversary below is a
   MODEL-LEVEL object that the deployment gives no one the ability to build.
   Classification is unchanged: proof-technique limitation, not a vulnerability.

   CONDITIONAL, exactly as `admit_refuted_by_surface_collision` is:
   `encode_msgWOTS` is free here, so the colliding pair is a HYPOTHESIS.  At
   deployed geometry such pairs exist in abundance (residual Q2b supplies them);
   this file does not reach for that identification.
   ========================================================================== *)
require import AllCore List Distr DList StdOrder StdBigop.
require import WOTS_TW_ES.

(* The colliding pair, and the address to query at.  Free ops: the collision
   facts are carried as HYPOTHESES of the theorem, not asserted here. *)
op cm  : msgWOTS.
op cm' : msgWOTS.
op wad0 : wadrs.

(* --------------------------------------------------------------------------
   THE LOAD-BEARING FACT.  Verification transfers across an encoding collision.
   -------------------------------------------------------------------------- *)
equiv pkfs_encode_transfer :
  WOTS_TW_ES.pkWOTS_from_sigWOTS ~ WOTS_TW_ES.pkWOTS_from_sigWOTS :
      ={sig, ps, ad}
   /\ encode_msgWOTS m{1} = encode_msgWOTS m{2}
   ==> ={res}.
proof.
proc.
while (={pkWOTS, sig, ps, ad, em}); first by auto.
by auto.
qed.

equiv verify_encode_transfer :
  WOTS_TW_ES.verify ~ WOTS_TW_ES.verify :
      ={pk, sig}
   /\ encode_msgWOTS m{1} = encode_msgWOTS m{2}
   ==> ={res}.
proof.
proc.
by call pkfs_encode_transfer; auto.
qed.

(* --------------------------------------------------------------------------
   THE COUNTERMODEL ADVERSARY.  One query at `wad0` on `cm`; forge `cm'` by
   REPLAYING the signature.  It never queries OC, which is what makes
   `disj_wgpidxs` hold.
   -------------------------------------------------------------------------- *)
module (A_coll : Adv_MEUFGCMA_WOTSTWESNPRF) (O : Oracle_MEUFGCMA_WOTSTWESNPRF, OC : FC.Oracle_THFC) = {
  var sg : sigWOTS

  proc choose() : unit = {
    var pksig : pkWOTS * sigWOTS;
    pksig <@ O.query(wad0, cm);
    sg <- pksig.`2;
  }

  proc forge(ps : pseed) : int * msgWOTS * sigWOTS = {
    return (0, cm', sg);
  }
}.

(* ==========================================================================
   WHAT IS PROVED HERE, AND WHAT IS NOT.

   PROVED (compiles, 0 admits, 0 axioms):
     * `pkfs_encode_transfer` / `verify_encode_transfer` -- verification depends
       on the message ONLY through its codeword, so validity transfers across an
       encoding collision.  This is the load-bearing fact: it is what makes the
       replay forgery work, and it is a THEOREM about MM45's own `verify`, not an
       assumption.
     * `A_coll` -- the explicit adversary, well-typed against MM45's
       `Adv_MEUFGCMA_WOTSTWESNPRF`: one query on `cm`, forge `cm'` by replaying
       the signature, never touch `OC`.

   NOT PROVED HERE -- the packaging step:

       lemma badenc_is_one &m :
            P cm => cm <> cm' => encode_msgWOTS cm = encode_msgWOTS cm'
         => Pr[Game4_WOTSTWES_BadEnc(A_coll).main() @ &m
                : res /\ BadEncFlag.badenc] = 1%r.

   It needs (a) losslessness of the oracle's two `while` loops (routine, bounded
   by `len`, same shape as `pkfs_ll` at :2?), and (b) WOTS correctness for the
   honest query -- `pkWOTS_from_sigWOTS(cm, sg, ps, ad) = pk` for the `(pk, sg)`
   the oracle produced -- which then transfers to `cm'` by
   `verify_encode_transfer`.  Neither is deep; both are real work.

   DO NOT read the absence of that lemma as doubt about the claim.  The win
   conjuncts were each checked at source before this file was written:
     is_fresh     hypothesis `cm <> cm'`
     !hchwcoll    `x < x` at every index (already proved as
                  `collision_kills_both_chain_predicates` in the spike file)
     P cm'        `P_encode_congr`
     dist_wgpidxs `uniq` of a singleton (uniq_wgpidxs, :456)
     disj_wgpidxs `adlOC = []` since `A_coll` never queries OC (:465)
     0<=nrqs<=c   `const c : { int | 1 <= c } as ge1_c` (:79)
   What is missing is the mechanised assembly, not the argument.
   ========================================================================== *)
