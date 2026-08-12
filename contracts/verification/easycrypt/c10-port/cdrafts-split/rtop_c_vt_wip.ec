(* ==========================================================================
   rtop_c_vt_wip.ec  --  ROLE = T / HOP-5 (VT branch).

   The FORS-FORGERY branch of the SPHINCS+C10 top decomposition.  Mirror of
   MM45 `LeqPr_EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_VT_MFORSTWESNPRF`
   (SPHINCS_PLUS.ec:3129-3467).  Target:

     lemma LeqPr_VT_C :
       Pr[V_C(F) : res /\ valid_MFORSC10]
       <= Pr[M.EUF_CMA_MFORSC10(R_fors(F), M.O_CMA_MFORSC10) : res]

   where V_C = EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V (the shared +C V-game, inlined
   verbatim from rtop_c_soundness_wip.ec), valid_MFORSC10 = (reconstructed pkFORS
   = honest pkFORS) is the FORS+C EUF break, and M = the clone of
   FORS_C10_Multi.MFORSC10 onto the concrete FTWES types.

   --------------------------------------------------------------------------
   WHAT IS PROVEN HERE (0-admit, empirically):
     * M : the concrete clone of FORS_C10_Multi.MFORSC10 onto the base FTWES
       instance (F-level mkey/msg/out_t/k/a/dmkey/mco/g bound to the base; scheme
       TYPES pseed/adrs/pkFORS/skFORS/sigFORSTW bound to FTWES.*; d <- l).  The
       five g-axioms DISCHARGE from FTWES's structured `g` (ftw_*_g, verbatim from
       good_clone_probe.ec); ge1_d / dpseed_ll discharge; `good_pos` (= p_nu) is
       CARRIED (M.F.good_pos, the sole ledger residual of the clone -- identical
       to good_clone_probe.ec's verdict).  mkeygen / fsign / fverify are LEFT
       ABSTRACT (R_fors never calls them; only the M-game oracle/verify do).
     * good_eq_good_fors_M : M.F.good m mk = good_fors m mk -- the +C bridge, pure
       delta-unfold (mirror good_clone_probe.ec:140 for the MFORSC10 clone).
     * dcond_good_eq : dcond dmkey (M.F.good m) = dcond dmkey (good_fors m) -- the
       EXACT `mk`-rnd coupling fact the byequiv would use.  This is the "+C bite"
       the VT hop turns on (hop-6 was clone-free; here good == good_fors is what
       makes M.O_CMA_MFORSC10.sign's draw and V_C.O_CMA_C.sign's draw couplable).
     * R_fors : M.Adv_EUFCMA_MFORSC10 -- the reduction, in the correct MM45 shape
       (pre-gen WOTS/HT via the +C keygen, DELEGATE the FORS mk-draw + tree-sign
       to M.O_CMA_MFORSC10.sign, extract the reconstructed-pkFORS forgery).  This
       turns the capstone's hand-waved "no reduction from Adv_EUFCMA_C to
       M.Adv_EUFCMA_MFORSC10 exists" (sphincs_c10_capstone_concrete_wip.ec:187)
       into a TYPED reduction.
     * rhs_zero_fverify_false : Pr[Mz.EUF_CMA_MFORSC10(A, .).main : res] = 0%r --
       the MACHINE-CHECKED (0-admit) witness of the admitted lemma's defect (see
       below): `Mz` is the M-clone with the LEGAL binding fverify:=false, under
       which the RHS is identically 0 for ANY adversary/keygen.

   --------------------------------------------------------------------------
   *** UPDATE 2026-07-21b -- THE "UNPROVABLE-OR-VACUOUS" DICHOTOMY BELOW IS
       SUPERSEDED FOR A CONCRETE CLONE.  The D2 leg is NOT an absolute obstruction. ***
   [empirical W1/W2 + GPT-5.6 + Kimi-K3 + advisor reconcile, all 2026-07-21.]

   The dichotomy in the paragraph after this one presumed the *abstract* clone M
   (mkeygen/fsign/fverify left abstract).  Two machine-checked probes correct it:

     (W1) drafts/RTopCVtMcSampDistr.ec -- the NAIVE STEP-1 recipe (bind the op
          `mkeygen` to a sample) is a TYPE ERROR (op codomain is a VALUE
          `FTWES.skFORS list`; a `dgstblock distr` cannot inhabit it).  So D2 is a
          real obstruction *for the naive binding*.
     (W2) drafts/RTopCVtMcWrapSeed.ec -- but it is CIRCUMVENTED.  A clone CONTROLS
          the `pseed` TYPE and the `dpseed` DISTRIBUTION, so wrapping
          `pseed := pseed * (FTWES.skFORS list list)` and `dpseed := dpseedW`
          (a product distr that samples the FORS cube ps-INDEPENDENTLY) makes the
          game's OWN `ps <$ dpseed` sample the cube, and a PURE projecting
          `mkeygen` extracts it.  This clone COMPILES (rc=0) and `EUFCMA_MFORSC10`
          INSTANTIATES at it (`exact McW.EUFCMA_MFORSC10 ...` compiles).  Hence the
          keygen "op cannot sample" wall is not absolute; the STEP-1 mechanism is
          achievable as a clone.

   BUT WRAPPING IS NOT "HOP-5 FIXED" -- it is STEP 1 of 3, and after it this
   `LeqPr_VT_C` is exactly as admitted as before:
     * `fverify` is STILL abstract in M (the D1 horn / rhs_zero_fverify_false below
       stands for M).  A meaningful concrete clone must ALSO bind `fverify`
       concretely (reconstructed-key equality) and `mkeygen`'s pks pool (W2's
       `pks = witness` is a placeholder) -- those are pure ops mirroring the
       deterministic procs `gen_pkFORS`/`pkFORS_from_sigFORSTW` (FORS_ES.ec:1839/
       1629), whose bodies are ops-only (`f`/`trco`/`val_bt_trh` are ops,
       FORS_ES.ec:455/623/695) so the mirror ops are legal -- but each needs an
       op=proc REFINEMENT lemma.  That bridge (a "second grind"), not the sampling,
       is the real cost; and
     * the MM45-shaped byequiv (SPHINCS_PLUS.ec:3143-3174/3307-3327) is unbuilt.

   SEMANTIC HAZARD of the wrapping (first-class -- do NOT bury): the wrapped
   `EUF_CMA_MFORSC10.main` HANDS the adversary the full `(pks, ps, ad)` where `ps`
   now CONTAINS THE SECRET CUBE.  So `Mc.EUFCMA_MFORSC10`'s forall-A conclusion is
   MEANINGLESS for a key-reading A (LHS ~ 1, the H-TREE-MULTI premise forced ~ 1),
   and the carried ITSRC10 assumption is nominally stated over a hand-the-key game.
   It is sound & NON-VACUOUS only for a wrapper reduction R_fors_c that PROJECTS the
   tape away before running F (then every probability equals the unwrapped value).
   Any file that clones the wrapped Mc MUST record the "tape-projecting adversaries
   only" invariant first.

   CONVERGED SOUND PATH (advisor + Kimi, owner's call): PROC-IFY the scheme surface
   of FORS_C10_Multi.ec -- make `keygen` a sampling PROC (calling gen_skFORS/
   gen_pkFORS a la FORS_ES.ec:1933-1960), `fsign`/`fverify`/`mverifyC` PROCs -- and
   re-port the three abstract proofs (no internal keygen dependence) + re-point the
   consumer clones.  That kills the D2 obstruction AND the tape-leak landmine in one
   move, leaving only genuine content (the FORS correctness lemma + the byequiv).
   Wrapping is the fallback if the shared-file blast radius is unacceptable.

   WHAT THIS UPDATE DOES *NOT* SUPERSEDE: only the "D2 keygen leg is an absolute
   obstruction" claim is retracted.  STILL LIVE: (1) the D1 horn (abstract fverify)
   -- concrete fverify is REQUIRED and unbuilt; (2) the OPEN sub-question below --
   is `Pr[LHS] > 0` (V_C's `res /\ valid_MFORSC10` reachable) even establishable?
   That is ORTHOGONAL to D2 and remains open; if it fails, the capstone's
   Pr[V_C]=VT+VF accounting is also dented.  Neither is resolved here.

   --------------------------------------------------------------------------
   [HISTORICAL, PARTLY SUPERSEDED (only the D2 "absolute obstruction" claim):]
   WHAT IS ADMITTED, AND WHY IT IS UNPROVABLE-OR-VACUOUS (not merely hard).
   [advisor 2026-07-21 (x2) AND GPT-5.6 read-the-source review 2026-07-21 CONVERGE;
    corroborated by the capstone's own open-leg note.]

   `LeqPr_VT_C` is stated in its exact required form and ADMITTED.  The admit is
   NOT a "hard byequiv I ran out of time on".  The robust statement of the defect
   is a STRUCTURAL DICHOTOMY that needs no countermodel search and no unproven
   "Pr[LHS] > 0" premise:

     * MACHINE-VERIFIED FACT (axiom grep over FORS_C10_Multi.MFORSC10): `fverify`
       is an UNCONSTRAINED op -- NO axiom mentions it (nor `fsign`/`mkeygen`).
       The clone here binds only types + digest ops, so `fverify` stays abstract.
     * Hence `M.fverify := (fun _ _ _ _ _ => false)` is a LEGAL instantiation.
       Under it `mverifyC` is definitionally false (FORS_C10_Multi.ec:139-143), so
       `is_valid` is false and Pr[RHS] = 0 (FORS_C10_Multi.ec:215-218) -- and this
       is fverify-ONLY, INDEPENDENT of keygen.  This step is MACHINE-CHECKED here
       (0-admit) by `mverifyC_false` + `rhs_zero_fverify_false` on the clone `Mz`.
     * Pr[LHS] does not mention `fverify` at all.
     * THEREFORE `Pr[LHS] <= Pr[RHS]` is derivable ONLY IF `Pr[LHS] = 0` in every
       model.  So `LeqPr_VT_C` is either
           (i)  UNPROVABLE           -- if the FORS-forgery event
                                        `res /\ valid_MFORSC10` is reachable in
                                        some legal model (the EXPECTED case: it is
                                        a genuine forgery event); OR
           (ii) VACUOUSLY TRUE       -- if that event is unreachable (Pr[LHS] = 0
                                        for all instantiations).
       Either way it carries NO security content tied to the concrete FORS+C game;
       no sound tactic proves horn (i), and horn (ii) would be content-free.

   [RETRACTION of the earlier "false-as-stated / RHS strictly smaller" phrasing:
    that presumed `Pr[LHS] > 0` is reachable WHILE the base axioms hold, which is
    NOT established here.  The dichotomy above is the defensible claim.]

   OPEN SUB-QUESTION (flagged, NOT resolved this session): is `Pr[LHS] > 0` even
   establishable for V_C's `res /\ valid_MFORSC10`?  If it is NOT, that is a
   SEPARATE defect that also undermines the capstone's decomposition accounting
   `Pr[V_C] = Pr[VT] + Pr[VF]` (sphincs_c10_capstone_concrete_wip.ec) -- which
   silently assumes each branch carries content.  Down-stream owners must not
   treat either branch's non-vacuity as given.

   TWO WAYS THE ABSTRACTION BITES (illustration; both legal instantiations):
     (D1, abstract verify -- the dichotomy's horn (i) witness)  fverify := false
       => Pr[RHS] = 0, keygen-independent (as above).
     (D2, keygen faithfulness)  Even with a sane `fverify`, RHS `mverifyC` tests
       reconstruct against MKEYGEN's pool (FORS_C10_Multi.ec:139-143) while LHS
       `valid_MFORSC10` tests V_C's HONEST gen_pkFORS of the cube sampled
       skFORS_ele <$ ddgstblock INDEPENDENTLY of `ps` (rtop_c_soundness_wip.ec:
       390-409; ddgstblock full/uniform, FORS_ES.ec:315).  `ps` is handed to the
       arbitrary forger on both sides (not re-indexable), so conditional on equal
       `ps` the left cube carries fresh entropy the right pool lacks -- no
       equality-supported coupling without an ADDED refinement relation.  [NB the
       obstacle is the cube's ps-INDEPENDENT entropy + abstract verify/sign, NOT
       the over-general "a point-mass op can never equal a distribution" (`mkeygen
       ps ad` IS nondegenerate in the freshly-sampled `ps`).]

   MM45's analogous VT lemma (SPHINCS_PLUS.ec:3129-3467) goes through because its
   target M-FORS game has ALL THREE concrete pieces (verified in-source this
   session): procedural random keygen (FORS_ES.ec:1932, called :2022), concrete
   routed signing (:2055), and concrete verify ending in reconstructed-key
   equality (:1759 -> FL_FORS_ES.verify); its proof couples the secret pools +
   derived pubkeys (SPHINCS_PLUS.ec:3143-3174) and carries that concrete relation
   through signing (:3307-3327).  Sampling keygen is NECESSARY BUT NOT SUFFICIENT
   -- the whole concrete refinement is.  FORS_C10_Multi.MFORSC10's op-level
   abstraction exposes none of it; this is the MODELLING SEAM the capstone left as
   a FREE adversary (sphincs_c10_capstone_concrete_wip.ec:184-189).

   BLOCKED LEG (residual, precise):  FULL concrete-scheme refinement of the FORS+C
   multi-game -- fverify (abstract op vs reconstructed-key equality; the horn-(i)
   blocker), mkeygen (op vs V_C's ps-independent NPRF cube), fsign (op vs
   FL_FORS_ES_NPRF.sign).  To close, one of: (i) introduce a CONCRETE PROCEDURAL
   M-FORS+C game that SAMPLES the cube, derives every pubkey, signs with the
   concrete routed address, and verifies by reconstructed-key equality +
   predC_fors; then port MM45 :3143-3174 / :3307-3327; or (ii) connect the
   abstract MFORSC10 to that concrete scheme via a full keygen/sign/verify
   REFINEMENT interface (a bare `mkeygen ps adz = sampled_pool` equation is NOT
   adequate -- the sign/verify refinement is also load-bearing).  Neither is done
   here.  The +C bite (good_eq_good_fors_M / dcond_good_eq) is orthogonal to this
   blocker and IS proven.

   CONTAINMENT.  Lowercase filename => NOT require-importable; nothing consumes
   `LeqPr_VT_C`.  The file is NOT-CERTIFIED-BY-DESIGN (admit present) and the
   admitted proposition MUST NOT be treated as proven.
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

(* --------------------------------------------------------------------------
   The C10 FORS+C conditioning predicate, CONCRETE at the base FTWES digest
   (predC_fors of FORS_C10.ec:197 unfolded on FTWES.g / FTWES.mco).  INLINED
   verbatim from rtop_c_soundness_wip.ec:135.
   -------------------------------------------------------------------------- *)
op good_fors (m : msg) (mk : mkey) : bool =
  (nth witness (FTWES.g (FTWES.mco mk m)) (k - 1)).`3 = 0.

(* ==========================================================================
   The FIVE concrete g-facts (FORSC10's five g-axioms at the FTWES types).
   INLINED verbatim from good_clone_probe.ec:66-107.
   ========================================================================== *)
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
   THE M CLONE.  FORS_C10_Multi.MFORSC10 onto the concrete FTWES instance.
   F-level bound (for the good-bridge + good_pos); scheme TYPES bound (so R_fors
   is constructible and the RHS Pr typechecks); mkeygen/fsign/fverify LEFT
   ABSTRACT; good_pos CARRIED (M.F.good_pos).  d <- l (total HT-leaf FORS pool).
   ========================================================================== *)
clone FORS_C10_Multi.MFORSC10 as M with
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
  op   d         <- l

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

(* THE +C BRIDGE.  M.F.good IS the concrete C10 forgery-gate good_fors -- pure
   delta-unfold (definitional-by-clone; mirror good_clone_probe.ec:140). *)
lemma good_eq_good_fors_M (m : msg) (mk : mkey) : M.F.good m mk = good_fors m mk.
proof. by rewrite /M.F.good /M.F.predC_fors /good_fors. qed.

(* THE mk-RND COUPLING FACT.  The two conditioned draws are the SAME distribution
   (M.O_CMA_MFORSC10.sign draws  dcond dmkey (good m);  V_C.O_CMA_C.sign draws
   dcond dmkey (good_fors m)) -- this is the leg the VT byequiv's `rnd` uses.
   The "+C bite": hop-6 was clone-free, here good == good_fors is load-bearing. *)
lemma dcond_good_eq (m : msg) :
  dcond dmkey (M.F.good m) = dcond dmkey (good_fors m).
proof. by congr; apply fun_ext => mk; exact good_eq_good_fors_M. qed.

(* ==========================================================================
   INLINED VERBATIM from rtop_c_soundness_wip.ec:138-277 -- R_top_C (the VF-
   branch reduction; carried for context / self-containedness, per the hop-5
   task's inline list -- NOT consumed by LeqPr_VT_C).
   ========================================================================== *)
module (R_top_C (A : Adv_EUFCMA_C) : Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF)
       (OC : FSSLXMTWES.TRHC.Oracle_THFC) = {
  var skFORSnt : FTWES.skFORS list list
  var pkFORSnt : FTWES.pkFORS list list
  var root : dgstblock
  var ps : pseed
  var ad : adrs
  var sigFLSLXMSSMTTWCl : sigFLSLXMSSMTTWC list

  module O_CMA : SOracle_CMA_C = {
    proc sign(m : msg) : sigSPHINCSPLUSTWC = {
      var mk : mkey;
      var sigFORSTW : FTWES.sigFORSTW;
      var cm : FTWES.msgFORSTW;
      var idx : index;
      var tidx, kpidx : int;
      var skFORS : FTWES.skFORS;
      var sigHT : sigFLSLXMSSMTTWC;

      mk <$ dcond dmkey (good_fors m);              (* C10: fresh, conditioned *)

      (cm, idx) <- FTWES.mco mk m;

      (tidx, kpidx) <- edivz (Index.val idx) l';

      skFORS <- nth witness (nth witness skFORSnt tidx) kpidx;

      sigFORSTW <@ FTWES.FL_FORS_ES_NPRF.sign((skFORS, ps,
                     set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);

      sigHT <- nth witness sigFLSLXMSSMTTWCl (Index.val idx);

      return (mk, sigFORSTW, sigHT);
    }
  }

  proc choose() : msgFLSLXMSSMTTW list = {
    var skFORS_ele : dgstblock;
    var skFORSet : dgstblock list;
    var skFORScube : dgstblock list list;
    var skFORSlp : FTWES.skFORS list;
    var pkFORS : FTWES.pkFORS;
    var pkFORSlp : FTWES.pkFORS list;
    var leaves : dgstblock list;
    var roots : dgstblock list;
    var leaf : dgstblock;
    var nodes : dgstblock list list;
    var nodespl, nodescl : dgstblock list;
    var lnode, rnode, node : dgstblock;

    ad <- adz;

    skFORSnt <- [];
    pkFORSnt <- [];
    while (size skFORSnt < nr_trees 0) {
      skFORSlp <- [];
      pkFORSlp <- [];
      while (size skFORSlp < l') {
        skFORScube <- [];
        roots <- [];
        while (size skFORScube < k) {
          skFORSet <- [];
          leaves <- [];
          while (size skFORSet < t) {
            skFORS_ele <$ ddgstblock;
            leaf <@ OC.query(set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype)
                                                              (size skFORSnt)) (size skFORSlp))
                                         0 (size skFORScube * t + size skFORSet),
                             DigestBlock.val skFORS_ele);
            skFORSet <- rcons skFORSet skFORS_ele;
            leaves <- rcons leaves leaf;
          }

          nodes <- [];
          while (size nodes < a) {
            nodespl <- last leaves nodes;

            nodescl <- [];
            while (size nodescl < nr_nodesf (size nodes + 1)) {
              lnode <- nth witness nodespl (2 * size nodescl);
              rnode <- nth witness nodespl (2 * size nodescl + 1);

              node <@ OC.query(set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype)
                                                                (size skFORSnt)) (size skFORSlp))
                                           (size nodes + 1)
                                           (size skFORScube * nr_nodesf (size nodes + 1) + size nodescl),
                               DigestBlock.val lnode ++ DigestBlock.val rnode);

              nodescl <- rcons nodescl node;
            }
            nodes <- rcons nodes nodescl;
          }
          skFORScube <- rcons skFORScube skFORSet;
          roots <- rcons roots (nth witness (nth witness nodes (a - 1)) 0);
        }

        pkFORS <@ OC.query(set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx ad trhftype)
                                                                       (size skFORSnt)) (size skFORSlp))
                                                  trcotype) (size skFORSlp),
                           flatten (map DigestBlock.val roots));

        skFORSlp <- rcons skFORSlp (FTWES.DBLLKTL.insubd skFORScube);
        pkFORSlp <- rcons pkFORSlp pkFORS;
      }
      skFORSnt <- rcons skFORSnt skFORSlp;
      pkFORSnt <- rcons pkFORSnt pkFORSlp;
    }

    return flatten pkFORSnt;
  }

  proc forge(pk : pkFLSLXMSSMTTW, sigl : sigFLSLXMSSMTTWC list)
       : msgFLSLXMSSMTTW * sigFLSLXMSSMTTWC * index = {
    var m' : msg;
    var sig' : sigSPHINCSPLUSTWC;
    var mk' : mkey;
    var sigFORSTW' : FTWES.sigFORSTW;
    var sigHT' : sigFLSLXMSSMTTWC;
    var cm' : FTWES.msgFORSTW;
    var idx' : index;
    var tidx', kpidx' : int;
    var pkFORS' : FTWES.pkFORS;

    (root, ps, ad) <- pk;
    sigFLSLXMSSMTTWCl <- sigl;

    (m', sig') <@ A(O_CMA).forge((root, ps));

    (mk', sigFORSTW', sigHT') <- sig';

    (cm', idx') <- FTWES.mco mk' m';

    (tidx', kpidx') <- edivz (Index.val idx') l';

    pkFORS' <@ FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW(sigFORSTW', cm', ps,
                 set_kpidx (set_tidx (set_typeidx ad trhftype) tidx') kpidx');

    return (pkFORS', sigHT', idx');
  }
}.

(* ==========================================================================
   INLINED VERBATIM from rtop_c_soundness_wip.ec:326-456 -- the shared +C V-game
   EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V (V_C).  This is the LHS of LeqPr_VT_C; it is
   the SAME V_C the sibling hop-6 (LeqPr_VF_C) consumes, so the two branches
   recombine  Pr[V_C:res] = Pr[V_C:res/\valid] + Pr[V_C:res/\!valid].
   ========================================================================== *)
module EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V (A : Adv_EUFCMA_C) = {
  var valid_MFORSC10 : bool
  var qs : msg list
  var skFORSnt : FTWES.skFORS list list
  var skWOTStd : skWOTS list list list
  var root : dgstblock
  var ps : pseed
  var ad : adrs

  module O_CMA_C : SOracle_CMA_C = {
    proc sign(m : msg) : sigSPHINCSPLUSTWC = {
      var mk : mkey;
      var sigFORSTW : FTWES.sigFORSTW;
      var pkFORS : FTWES.pkFORS;
      var cm : FTWES.msgFORSTW;
      var idx : index;
      var tidx, kpidx : int;
      var skFORS : FTWES.skFORS;
      var sigHT : sigFLSLXMSSMTTWC;

      mk <$ dcond dmkey (good_fors m);

      (cm, idx) <- FTWES.mco mk m;

      (tidx, kpidx) <- edivz (Index.val idx) l';

      skFORS <- nth witness (nth witness skFORSnt tidx) kpidx;

      sigFORSTW <@ FTWES.FL_FORS_ES_NPRF.sign((skFORS, ps,
                     set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);

      pkFORS <@ FTWES.FL_FORS_ES_NPRF.gen_pkFORS(skFORS, ps,
                     set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

      sigHT <@ FL_SL_XMSS_MT_C_ES_NPRF.sign((skWOTStd, ps, ad), pkFORS, idx);

      qs <- rcons qs m;

      return (mk, sigFORSTW, sigHT);
    }
  }

  proc main() : bool = {
    var pkHT : pkFLSLXMSSMTTW;
    var skHT : skWOTS list list list * pseed * adrs;
    var skFORS_ele : dgstblock;
    var skFORSet : dgstblock list;
    var skFORScube : dgstblock list list;
    var skFORSlp : FTWES.skFORS list;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTWC;
    var mk' : mkey;
    var sigFORSTW' : FTWES.sigFORSTW;
    var sigHT' : sigFLSLXMSSMTTWC;
    var cm : FTWES.msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var pkFORS, pkFORS' : FTWES.pkFORS;
    var skFORS : FTWES.skFORS;
    var root' : dgstblock;
    var allOkC : bool;
    var is_valid, is_fresh : bool;

    ad <- adz;
    ps <$ dpseed;

    skFORSnt <- [];
    while (size skFORSnt < nr_trees 0) {
      skFORSlp <- [];
      while (size skFORSlp < l') {
        skFORScube <- [];
        while (size skFORScube < k) {
          skFORSet <- [];
          while (size skFORSet < t) {
            skFORS_ele <$ ddgstblock;
            skFORSet <- rcons skFORSet skFORS_ele;
          }
          skFORScube <- rcons skFORScube skFORSet;
        }
        skFORSlp <- rcons skFORSlp (FTWES.DBLLKTL.insubd skFORScube);
      }
      skFORSnt <- rcons skFORSnt skFORSlp;
    }

    (pkHT, skHT) <@ FL_SL_XMSS_MT_C_ES_NPRF.keygen(ps, ad);
    skWOTStd <- skHT.`1;
    root <- pkHT.`1;

    qs <- [];

    (m', sig') <@ A(O_CMA_C).forge((root, ps));

    (mk', sigFORSTW', sigHT') <- sig';

    (cm, idx) <- FTWES.mco mk' m';

    (tidx, kpidx) <- edivz (Index.val idx) l';

    skFORS <- nth witness (nth witness skFORSnt tidx) kpidx;

    pkFORS <@ FTWES.FL_FORS_ES_NPRF.gen_pkFORS(skFORS, ps,
                set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

    pkFORS' <@ FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW(sigFORSTW', cm, ps,
                 set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

    valid_MFORSC10 <- pkFORS' = pkFORS;

    (root', allOkC) <@ FL_SL_XMSS_MT_C_ES.root_from_sigC(pkFORS', sigHT', idx, ps, ad);

    is_valid <- good_fors m' mk' /\ size sigHT' = d /\ root' = root /\ allOkC;
    is_fresh <- ! (m' \in qs);

    return is_valid /\ is_fresh;
  }
}.

(* ==========================================================================
   R_fors : M.Adv_EUFCMA_MFORSC10 -- the VT-branch (FORS-forgery) reduction.
   MM45 shape (R_MFORSTWESNPRFEUFCMA_EUFCMA, SPHINCS_PLUS.ec:1363): pre-generate
   the WOTS/HT keys via the +C keygen (root handed to F), DELEGATE the FORS
   mk-draw + tree-sign to the FORS+C game oracle M.O_CMA_MFORSC10.sign (which
   draws  mk <$ dcond dmkey (good m)  and returns (mk, sigFORSTW)), do the HT-sign
   locally over the GAME-PROVIDED pkFORS pool, and on F's forgery extract the
   FORS+C forgery pair (mk', sigFORSTW').
   ========================================================================== *)
module (R_fors (A : Adv_EUFCMA_C) : M.Adv_EUFCMA_MFORSC10)
       (O : M.SOracle_CMA_MFORSC10) = {
  var pks : FTWES.pkFORS list
  var ps  : pseed
  var ad  : adrs
  var skWOTStd : skWOTS list list list

  module O_CMA : SOracle_CMA_C = {
    proc sign(m : msg) : sigSPHINCSPLUSTWC = {
      var mk : mkey;
      var sigFORSTW : FTWES.sigFORSTW;
      var cm : FTWES.msgFORSTW;
      var idx : index;
      var pkFORS : FTWES.pkFORS;
      var sigHT : sigFLSLXMSSMTTWC;

      (mk, sigFORSTW) <@ O.sign(m);          (* FORS+C game oracle: mk-draw + FORS-sign *)

      (cm, idx) <- FTWES.mco mk m;

      pkFORS <- nth witness pks (Index.val idx);   (* game-provided FORS pubkey pool *)

      sigHT <@ FL_SL_XMSS_MT_C_ES_NPRF.sign((skWOTStd, ps, ad), pkFORS, idx);

      return (mk, sigFORSTW, sigHT);
    }
  }

  proc forge(pk : FTWES.pkFORS list * pseed * adrs) : msg * M.sigFORSC10 = {
    var pkHT : pkFLSLXMSSMTTW;
    var skHT : skWOTS list list list * pseed * adrs;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTWC;
    var mk' : mkey;
    var sigFORSTW' : FTWES.sigFORSTW;
    var sigHT' : sigFLSLXMSSMTTWC;
    var root : dgstblock;

    (pks, ps, ad) <- pk;

    (pkHT, skHT) <@ FL_SL_XMSS_MT_C_ES_NPRF.keygen(ps, ad);
    skWOTStd <- skHT.`1;
    root <- pkHT.`1;

    (m', sig') <@ A(O_CMA).forge((root, ps));

    (mk', sigFORSTW', sigHT') <- sig';

    return (m', (mk', sigFORSTW'));
  }
}.

(* ==========================================================================
   LeqPr_VT_C -- the VT (FORS-forgery) branch bound, against the ABSTRACT clone M.
   STATED in its exact required form; ADMITTED.

   *** Its admit is NOT "unprovable-or-vacuous absolute" (see the header UPDATE
   2026-07-21b). ***  It is admitted because THIS statement targets the ABSTRACT M
   (mkeygen/fsign/fverify left abstract): `fverify` is UNCONSTRAINED, so
   `fverify:=false` is legal => Pr[RHS]=0 (MACHINE-CHECKED below by
   rhs_zero_fverify_false on clone Mz) -- the D1 horn, which stands FOR M.  A
   CONCRETE clone escapes it: bind `fverify` to reconstructed-key equality (closes
   D1) and sample the keygen cube via pseed-wrapping (closes D2, EMPIRICALLY
   VERIFIED: drafts/RTopCVtMcWrapSeed.ec compiles and EUFCMA_MFORSC10 instantiates
   there).  The RESIDUAL for that concrete route is: concrete `fverify`/pks pool as
   pure ops + their op=proc refinement lemmas, the MM45 byequiv
   (:3143-3174/:3307-3327), and the tape-in-ps SEMANTIC HAZARD (sound only for a
   tape-projecting reduction) -- OR, cleaner, proc-ify FORS_C10_Multi.ec.  R_fors is
   the STRUCTURALLY CORRECT MM45-shape reduction; the +C bite good_eq_good_fors_M/
   dcond_good_eq is PROVEN and orthogonal.  NOT-CERTIFIED-BY-DESIGN.
   ========================================================================== *)
lemma LeqPr_VT_C (F <: Adv_EUFCMA_C{-R_fors, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V,
                                    -M.O_CMA_MFORSC10}) &m :
  Pr[EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V(F).main() @ &m :
       res /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.valid_MFORSC10]
  <=
  Pr[M.EUF_CMA_MFORSC10(R_fors(F), M.O_CMA_MFORSC10).main() @ &m : res].
proof.
(* ADMITTED against the ABSTRACT clone M (fverify abstract => rhs_zero_fverify_false
   below; the D1 horn stands for M).  This is a MODELLING SEAM, not a stalled
   byequiv, and MUST NOT be treated as proven.  It is NOT an absolute obstruction:
   a concrete clone escapes D1 (concrete fverify) and D2 (pseed-wrapped sampling
   keygen -- EMPIRICALLY VERIFIED in drafts/RTopCVtMcWrapSeed.ec, where
   EUFCMA_MFORSC10 instantiates).  See the header UPDATE 2026-07-21b for the
   residual + the recommended proc-ification path. *)
admit.
qed.

(* ==========================================================================
   MACHINE-CHECKED WITNESS of the dichotomy's horn (i)  --  CERTIFIED-0-ADMIT.

   `fverify` is unconstrained in FORS_C10_Multi.MFORSC10 (no axiom mentions it),
   so `fverify := (fun _ => false)` is a LEGAL instantiation.  `Mz` is exactly the
   M-clone with that binding (all else identical).  Under it the multi-verify is
   identically false, hence the FORS+C multi-game RHS is 0 for ANY adversary and
   ANY keygen -- so `Pr[RHS]` cannot upper-bound a positive `Pr[LHS]`.  This is
   the concrete, checked half of "UNPROVABLE-OR-VACUOUS": no countermodel search,
   no `Pr[LHS] > 0` premise needed to see that the bound carries no content.
   ========================================================================== *)
clone FORS_C10_Multi.MFORSC10 as Mz with
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
  op   fverify   <- fun (_ : FTWES.pkFORS) (_ : pseed) (_ : adrs)
                        (_ : FTWES.msgFORSTW * index) (_ : FTWES.sigFORSTW) => false

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

(* Under fverify:=false the multi-verify is definitionally false. *)
lemma mverifyC_false (pks : FTWES.pkFORS list) (ps : pseed) (ad : adrs)
                     (m : msg) (s : Mz.sigFORSC10) :
  Mz.mverifyC pks ps ad m s = false.
proof. by case s => mk sf; rewrite /Mz.mverifyC /=. qed.

(* HORN (i) WITNESS: under the legal fverify:=false instantiation the FORS+C
   multi-game RHS is identically 0 -- INDEPENDENT of keygen and of ANY adversary.
   Hence `Pr[LHS] <= Pr[RHS]` forces `Pr[LHS] = 0` (dichotomy). *)
lemma rhs_zero_fverify_false (A <: Mz.Adv_EUFCMA_MFORSC10) &m :
  Pr[Mz.EUF_CMA_MFORSC10(A, Mz.O_CMA_MFORSC10).main() @ &m : res] = 0%r.
proof.
byphoare (_: true ==> res) => //.
hoare.
proc.
inline Mz.O_CMA_MFORSC10.init Mz.O_CMA_MFORSC10.fresh.
seq 10 : (forall (m0 : msg) (s0 : Mz.sigFORSC10), ! Mz.mverifyC pks ps ad m0 s0).
+ auto => /> *; smt(mverifyC_false).
wp.
call (_: true) => //.
skip => &hr hINV result qs.
by smt(mverifyC_false).
qed.

(* ==========================================================================
   CONCRETE (pseed-WRAPPED) route -- STEP-1 mechanism banked in-file.
   [supersedes the abstract-M dichotomy for the D2 leg; see header UPDATE 2026-07-21b]

   `Mc` is the pseed-WRAPPED clone (verbatim mechanism of drafts/RTopCVtMcWrapSeed.ec,
   which independently CERTIFIES it compiles + EUFCMA_MFORSC10 instantiates):
     pseed  := pseed * (FTWES.skFORS list list)   (base seed carries a FORS-cube tape)
     dpseed := dpseedW  (product distr; the game's `ps <$ dpseed` SAMPLES the cube
                         ps-INDEPENDENTLY, matching V_C's cube sampling by construction)
     mkeygen:= PURE projector of the pre-sampled tape.
   So the D2 "op cannot sample" wall is circumvented -- the sampling is at the game's
   own `<$ dpseed`, not in the op.

   !!! Mc INHERITS THE TAPE-IN-PS LANDMINE: Mc.EUFCMA_MFORSC10 is meaningful ONLY at a
   reduction that PROJECTS the tape.  R_fors_c below DOES project (`ps <- wps.`1`). !!!

   WHAT IS BANKED: the wrapped clone Mc (compiles), R_fors_c TYPED against Mc's
   concrete game (the reduction is constructible at the concrete FORS+C game), and
   LeqPr_VT_C_concrete STATED in its exact required form.
   WHAT IS ADMITTED (LeqPr_VT_C_concrete): the byequiv is NOT built, and this Mc still
   uses PLACEHOLDER concrete ops (mkeygen's pks pool = `witness`; fsign/fverify left
   abstract).  A meaningful (non-shell) concrete bound needs, additionally: (a) mkeygen
   deriving the real pkFORS pool as a pure op mirroring gen_pkFORS (FORS_ES.ec:1839,
   ops-only body) + its op=proc refinement; (b) fverify := reconstructed-key equality
   (pkFORS_from_sigFORSTW, FORS_ES.ec:1629) + refinement, closing D1; (c) the MM45
   byequiv coupling (SPHINCS_PLUS.ec:3143-3174 keygen pool now soundly couplable +
   :3307-3327 sign carry-through) using good_eq_good_fors_M/dcond_good_eq for the +C
   mk-rnd leg; (d) freshness map.  The CONVERGED cleaner alternative (removes the
   landmine) is to proc-ify FORS_C10_Multi.ec's keygen/sign/verify.
   ========================================================================== *)
op dskFORS : FTWES.skFORS distr =
  dmap (dlist (dlist ddgstblock t) k) FTWES.DBLLKTL.insubd.
op dtapeI : FTWES.skFORS list distr = dlist dskFORS l'.
op dtape  : FTWES.skFORS list list distr = dlist dtapeI (nr_trees 0).
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

clone FORS_C10_Multi.MFORSC10 as Mc with
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

(* R_fors_c : R_fors retargeted at the WRAPPED concrete game Mc.  Structurally the
   MM45-shape reduction; the ONLY change vs R_fors is that the game hands a WRAPPED
   seed, so forge PROJECTS `ps <- wps.`1` (discarding the secret tape wps.`2) before
   running F -- honouring the tape-projecting invariant. *)
module (R_fors_c (A : Adv_EUFCMA_C) : Mc.Adv_EUFCMA_MFORSC10)
       (O : Mc.SOracle_CMA_MFORSC10) = {
  var pks : FTWES.pkFORS list
  var ps  : pseed
  var ad  : adrs
  var skWOTStd : skWOTS list list list

  module O_CMA : SOracle_CMA_C = {
    proc sign(m : msg) : sigSPHINCSPLUSTWC = {
      var mk : mkey;
      var sigFORSTW : FTWES.sigFORSTW;
      var cm : FTWES.msgFORSTW;
      var idx : index;
      var pkFORS : FTWES.pkFORS;
      var sigHT : sigFLSLXMSSMTTWC;

      (mk, sigFORSTW) <@ O.sign(m);
      (cm, idx) <- FTWES.mco mk m;
      pkFORS <- nth witness pks (Index.val idx);
      sigHT <@ FL_SL_XMSS_MT_C_ES_NPRF.sign((skWOTStd, ps, ad), pkFORS, idx);
      return (mk, sigFORSTW, sigHT);
    }
  }

  proc forge(pk : FTWES.pkFORS list * (pseed * (FTWES.skFORS list list)) * adrs)
       : msg * Mc.sigFORSC10 = {
    var pkHT : pkFLSLXMSSMTTW;
    var skHT : skWOTS list list list * pseed * adrs;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTWC;
    var mk' : mkey;
    var sigFORSTW' : FTWES.sigFORSTW;
    var sigHT' : sigFLSLXMSSMTTWC;
    var root : dgstblock;
    var wps : pseed * (FTWES.skFORS list list);

    (pks, wps, ad) <- pk;
    ps <- wps.`1;                    (* PROJECT away the secret tape wps.`2 *)

    (pkHT, skHT) <@ FL_SL_XMSS_MT_C_ES_NPRF.keygen(ps, ad);
    skWOTStd <- skHT.`1;
    root <- pkHT.`1;

    (m', sig') <@ A(O_CMA).forge((root, ps));
    (mk', sigFORSTW', sigHT') <- sig';
    return (m', (mk', sigFORSTW'));
  }
}.

(* LeqPr_VT_C_concrete -- the VT branch bound against the CONCRETE WRAPPED game Mc.
   STATED in the exact required form; ADMITTED.  The RHS game's keygen SAMPLES the
   cube, so ONLY THE D2 LEG is circumvented.  It is NOT one step closer to provable:
   Mc binds `mkeygen` alone -- `fverify`/`fsign` are STILL ABSTRACT and the pks pool
   is a placeholder -- so the D1 horn stands VERBATIM for Mc (rhs_zero_fverify_false
   below applies to Mc's `fverify:=false` sub-instantiation too, forcing Pr[RHS]=0).
   This lemma therefore sits under the SAME fverify:=false dichotomy as LeqPr_VT_C
   until `fverify` is concretized.  The ONLY thing newly banked is that a
   SAMPLING-KEYGEN clone is CONSTRUCTIBLE (the naive-op type error is circumvented) +
   the typed projecting reduction R_fors_c.  TYPED SHELL, NOT a near-complete proof;
   MUST NOT be treated as proven. *)
lemma LeqPr_VT_C_concrete
  (F <: Adv_EUFCMA_C{-R_fors_c, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V, -Mc.O_CMA_MFORSC10}) &m :
  Pr[EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V(F).main() @ &m :
       res /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.valid_MFORSC10]
  <=
  Pr[Mc.EUF_CMA_MFORSC10(R_fors_c(F), Mc.O_CMA_MFORSC10).main() @ &m : res].
proof.
(* Residual = MM45 byequiv (:3143-3174 keygen-pool coupling -- now SOUND because Mc
   and V_C both sample the cube ps-independently -- + :3307-3327 sign carry-through +
   +C mk-rnd via good_eq_good_fors_M/dcond_good_eq + freshness) PLUS concrete
   mkeygen-pks / fverify (Mc placeholders).  NOT built this session. *)
admit.
qed.
