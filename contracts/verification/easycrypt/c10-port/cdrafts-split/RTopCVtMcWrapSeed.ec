(* ==========================================================================
   RTopCVtMcWrapSeed.ec  --  EMPIRICAL TEST of the pseed-WRAPPING circumvention
   of the hop-5 STEP 1 "op mkeygen cannot sample" obstruction.

   GPT-5.6 (2026-07-21) refuted the ABSOLUTE form of the obstruction: because a
   clone CONTROLS the `pseed` TYPE (FORS_C10_Multi.ec:98) and the `dpseed`
   DISTRIBUTION (line 108), one can WRAP the seed to carry an eagerly-sampled,
   ps-INDEPENDENT FORS-secret "tape".  The game's OWN `ps <$ dpseed`
   (FORS_C10_Multi.ec:209) then samples the tape; a PURE deterministic `mkeygen`
   merely PROJECTS it.  So the cube is sampled ps-independently WITHOUT the op
   ever sampling and WITHOUT rewriting the game body's `<-`.

   THIS FILE MUST COMPILE.  It builds exactly that wrapped clone (skeleton:
   faithful sampling tape distribution `dtape` matching V_C's nesting; pure
   projecting `mkeygen`; pkFORS-derivation left as a placeholder `[]` -- that is
   STEP-2 substance, not needed to test the sampling MECHANISM).  If it compiles,
   the naive "op can't sample" obstruction is NOT absolute and STEP 1 is
   achievable as a clone via seed-wrapping.

   CAVEAT (for the deliverable, NOT a compile blocker): the wrapped
   EUF_CMA_MFORSC10.main HANDS the adversary the full `(pks, ps, ad)` where `ps`
   now contains the secret tape (FORS_C10_Multi.ec:213).  The bound is sound &
   non-vacuous ONLY for a wrapper reduction that PROJECTS the tape away before
   invoking the SPHINCS forger F; it is vacuous for a tape-reading adversary.
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
   THE SAMPLING TAPE.  A genuine, ps-INDEPENDENT distribution over the FORS
   secret cube, nested EXACTLY as V_C samples it (rtop_c_vt_wip.ec:466-482):
   outer nr_trees 0, inner l', each a k x t cube of ddgstblock, insubd'd.
   ========================================================================== *)
op dskFORS : FTWES.skFORS distr =
  dmap (dlist (dlist ddgstblock t) k) FTWES.DBLLKTL.insubd.

op dtapeI : FTWES.skFORS list distr = dlist dskFORS l'.
op dtape  : FTWES.skFORS list list distr = dlist dtapeI (nr_trees 0).

(* The WRAPPED public-seed distribution: base seed PRODUCT (independent) tape. *)
op dpseedW : (pseed * FTWES.skFORS list list) distr =
  dlet dpseed (fun (ps : pseed) => dmap dtape (fun tp => (ps, tp))).

lemma dskFORS_ll : is_lossless dskFORS.
proof. by rewrite /dskFORS dmap_ll dlist_ll dlist_ll ddgstblock_ll. qed.

lemma dtapeI_ll : is_lossless dtapeI.
proof. by rewrite /dtapeI dlist_ll dskFORS_ll. qed.

lemma dtape_ll : is_lossless dtape.
proof. by rewrite /dtape dlist_ll dtapeI_ll. qed.

lemma dpseedW_ll : is_lossless dpseedW.
proof.
rewrite /dpseedW; apply dlet_ll; 1: exact dpseed_ll.
by move => ps _; rewrite dmap_ll dtape_ll.
qed.

(* ==========================================================================
   THE WRAPPED CLONE.  pseed := pseed * tape ; dpseed := dpseedW (samples tape
   eagerly, ps-independently) ; mkeygen := PURE projector of the pre-sampled
   tape into the secret pool.  (pks derivation is a STEP-2 placeholder `[]`.)

   If this compiles, the sampling of the FORS cube happens at the game's
   `ps <$ dpseed` and `mkeygen` stays a legal deterministic op -- circumventing
   the "op cannot sample" obstruction WITHOUT touching the game body.

   !!! LOAD-BEARING INVARIANT for any consumer of McW !!!  The wrapped public key
   (pks, ps, ad) has the SECRET FORS cube inside `ps` (FORS_C10_Multi.ec:213).  So
   McW.EUFCMA_MFORSC10's forall-A conclusion is MEANINGLESS for a key-reading A;
   McW is sound & non-vacuous ONLY when instantiated at a reduction that PROJECTS
   the tape (`ps.`1`) away before handing anything to the SPHINCS forger F.  Do NOT
   clone/apply McW without honouring this.  (The clean alternative that removes the
   landmine is to proc-ify FORS_C10_Multi.ec's keygen/sign/verify.)
   ========================================================================== *)
clone FORS_C10_Multi.MFORSC10 as McW with
  type F.mkey    <- mkey,
  type F.msg     <- msg,
  type F.out_t   <- FTWES.msgFORSTW * index,
  op   F.k       <- k,
  op   F.a       <- a,
  op   F.dmkey   <- dmkey,
  op   F.mco     <- FTWES.mco,
  op   F.g       <- FTWES.g,
  type pseed     <- pseed * (FTWES.skFORS list list),
  type adrs      <- adrs,
  type pkFORS    <- FTWES.pkFORS,
  type skFORS    <- FTWES.skFORS,
  type sigFORSTW <- FTWES.sigFORSTW,
  op   dpseed    <- dpseedW,
  op   adz       <- adz,
  op   d         <- l,
  op   mkeygen   <- fun (pst : pseed * (FTWES.skFORS list list)) (ad : adrs) =>
                      (witness, flatten pst.`2)

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
  realize dpseed_ll   by exact: dpseedW_ll.

(* If we reach here, the wrapped clone is legal: the sampling obstruction is
   circumvented.  Confirm EUFCMA_MFORSC10 instantiates at the wrapped clone. *)
lemma eufcma_instantiates_wrapped
  (A <: McW.Adv_EUFCMA_MFORSC10{-McW.R_ITSRC10_MFORSC10, -McW.O_CMA_MFORSC10,
        -McW.O_CMA_MFORSC10_I, -McW.F.O_ITSRC10_Default, -McW.EUF_CMA_MFORSC10_I})
  (mo mt mc : real) &m :
    (   Pr[McW.EUF_CMA_MFORSC10_I(A).main() @ &m : res /\ !McW.EUF_CMA_MFORSC10_I.covered]
     <= mo + mt + mc) =>
    Pr[McW.EUF_CMA_MFORSC10(A, McW.O_CMA_MFORSC10).main() @ &m : res]
  <=   Pr[McW.F.ITSRC10(McW.R_ITSRC10_MFORSC10(A), McW.F.O_ITSRC10_Default).main() @ &m : res]
     + mo + mt + mc.
proof. exact (McW.EUFCMA_MFORSC10 A mo mt mc &m). qed.
