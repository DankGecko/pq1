(* ==========================================================================
   RTopCVtMcSampDistr.ec  --  EMPIRICAL OBSTRUCTION WITNESS for hop-5 STEP 1.

   STEP 1 of the pinned hop-5 fix asks for a clone `Mc` of
   FORS_C10_Multi.MFORSC10 whose `mkeygen` is a CONCRETE PROCEDURAL keygen that
   SAMPLES  skFORS_ele <$ ddgstblock  ps-INDEPENDENTLY (matching V_C and MM45's
   M_FORS_ES_NPRF.keygen).

   OBSTRUCTION WITNESS (documents-only; the offending clone is COMMENTED OUT below
   so this file COMPILES rc=0 -- see the captured error there).  When the clone is
   ACTIVE it FAILS: `mkeygen` (FORS_C10_Multi.ec:129) is a deterministic OPERATOR
   whose codomain is a VALUE `FTWES.pkFORS list * FTWES.skFORS list`, NOT a
   distribution.  A clone can only substitute the op's DEFINITION with a pure term;
   a sample (`<$ ddgstblock : dgstblock distr`) is not a value of that type and is
   not even a legal term-former in an op body.  The type error EC emits is the
   machine-checked proof of the NAIVE obstruction (circumvented in the sibling).

   (The sibling file RTopCVtMcDetOK.ec binds the SAME clone with a DETERMINISTIC
   mkeygen and COMPILES -- isolating the failure to the sampling, not the clone.)
   ========================================================================== *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import DList DMap FMap.
require import BinaryTrees MerkleTrees.
require import BitEncoding.
import BS2Int BitChunking.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.
require FORS_C10 FORS_C10_Multi.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.
import FTWES.DBLLKTL.
import DigestBlock.
import IntOrder.

(* The five concrete g-facts (verbatim from rtop_c_vt_wip.ec:161-196). *)
lemma ftw_size_g (y : FTWES.msgFORSTW * index) : size (FTWES.g y) = k.
proof. by rewrite /FTWES.g /= size_mkseq; smt(ge1_k). qed.

lemma ftw_eqiks_g (x x' : int * int * int) (y : FTWES.msgFORSTW * index) :
  x \in FTWES.g y => x' \in FTWES.g y => x.`1 = x'.`1.
proof. by rewrite /FTWES.g /= => /mkseqP [i [_ ->]] /mkseqP [j [_ ->]] /=. qed.

lemma ftw_neqisvs_g (x x' : int * int * int) (y : FTWES.msgFORSTW * index) :
  x \in FTWES.g y => x' \in FTWES.g y => x <> x' => x.`2 <> x'.`2.
proof. by rewrite /FTWES.g /= => /mkseqP [i [_ ->]] /mkseqP [j [_ ->]] /=; smt(). qed.

lemma ftw_rng_g (y : FTWES.msgFORSTW * index) (x : int * int * int) :
  x \in FTWES.g y => 0 <= x.`3 < t.
proof.
rewrite /FTWES.g /= => /mkseqP [i [rng_i ->]] /=.
split; 1: exact bs2int_ge0.
move => _.
have ha : 0 < a by smt(ge1_a).
have szc : size (nth witness (chunk a (FTWES.BLKAL.val y.`1)) i) = a.
- apply: (in_chunk_size a (FTWES.BLKAL.val y.`1)
                     (nth witness (chunk a (FTWES.BLKAL.val y.`1)) i) ha).
  apply/mem_nth.
  rewrite (size_chunk a _ ha) FTWES.BLKAL.valP.
  smt(ge1_a).
have -> : t = 2 ^ a by rewrite /t.
have hlt := bs2int_le2Xs (rev (nth witness (chunk a (FTWES.BLKAL.val y.`1)) i)).
rewrite size_rev szc in hlt.
exact hlt.
qed.

lemma ftw_uniq_g (y : FTWES.msgFORSTW * index) :
  uniq (map (fun (x : int * int * int) => x.`2) (FTWES.g y)).
proof.
rewrite /FTWES.g /= map_mkseq /mkseq map_inj_in_uniq 2:iota_uniq.
move => u v _ _ /=. smt().
qed.

(* ==========================================================================
   THE OBSTRUCTION.  Attempt to clone MFORSC10 binding `mkeygen` to a keygen that
   SAMPLES the FORS secret cube (the STEP 1 recipe).  A sample has type
   `dgstblock distr`; the op slot demands a value `FTWES.skFORS list`.  EC rejects.

   NB: the literal task recipe  `skFORS_ele <$ ddgstblock; ...`  is not even a
   legal term (`<$` is a pWhile statement, not a term constructor), so it cannot
   appear in an op body at all.  The binding below is the closest WELL-FORMED
   attempt to put distribution content into the value slot -- and it still fails,
   on the codomain type: `dgstblock distr` vs `FTWES.skFORS list`.
   ========================================================================== *)
(* CAPTURED EasyCrypt REJECTION  (bash scratch-ecc.sh drafts/RTopCVtMcSampDistr.ec,
   with the clone below ACTIVE):

     [drafts/RTopCVtMcSampDistr.ec:113] operator `mkeygen' body has type
       pseed -> adrs -> #a * dgstblock Distr.distr
     instead of
       pseed -> adrs -> FTWES.pkFORS list * FTWES.skFORS list

   The op codomain's second component is a VALUE `FTWES.skFORS list`; the
   distribution `ddgstblock : dgstblock Distr.distr` cannot inhabit it.  This is
   the machine-checked proof that a keygen OP cannot sample -- the naive STEP-1
   recipe is a type error.  (The literal recipe `skFORS_ele <$ ddgstblock` is
   even worse: `<$` is not a term-former, so it cannot appear in an op body.)

   The offending clone is COMMENTED OUT so this file COMPILES (rc=0) and does not
   poison a compile-every-file soundness sweep; the rejection above is the durable
   artifact.  The CIRCUMVENTION that DOES compile is RTopCVtMcWrapSeed.ec
   (pseed-wrapping: the game samples the FORS cube at its own `ps <$ dpseed`). *)
(*
clone FORS_C10_Multi.MFORSC10 as McSamp with
  type F.mkey    <- mkey,
  type F.msg     <- msg,
  type F.out_t   <- FTWES.msgFORSTW * index,
  op   F.k       <- k,
  op   F.a       <- a,
  op   F.dmkey   <- dmkey,
  op   F.mco     <- FTWES.mco,
  op   F.g       <- FTWES.g,
  type pseed     <- pseed,
  type adrs      <- adrs,
  type pkFORS    <- FTWES.pkFORS,
  type skFORS    <- FTWES.skFORS,
  type sigFORSTW <- FTWES.sigFORSTW,
  op   dpseed    <- dpseed,
  op   adz       <- adz,
  op   d         <- l,
  (* <<< THE OBSTRUCTION: a distribution where a value list is required. >>> *)
  op   mkeygen   <- fun (ps : pseed) (ad : adrs) =>
                      (witness, ddgstblock)

  proof F.ge1_k, F.ge1_a, F.dmkey_ll, F.size_g, F.eqiks_g, F.neqisvs_g,
        F.rng_g, F.uniq_g, ge1_d, dpseed_ll.
  realize F.ge1_k     by exact: ge1_k.
  realize F.ge1_a     by exact: ge1_a.
  realize F.dmkey_ll  by exact: dmkey_ll.
  realize F.size_g    by exact: ftw_size_g.
  realize F.eqiks_g   by exact: ftw_eqiks_g.
  realize F.neqisvs_g by exact: ftw_neqisvs_g.
  realize F.rng_g     by exact: ftw_rng_g.
  realize F.uniq_g    by exact: ftw_uniq_g.
  realize ge1_d       by smt(ge2_l).
  realize dpseed_ll   by exact: dpseed_ll.
*)
