(* ==========================================================================
   rtop_forsc_wip.ec  --  R_top_C : the FORS+C (C10-model) variant of R_top.

   ROLE = F / FORS+C WIRING.  Milestone: R_top_C DEFINED + TYPECHECKING with the
   FORS side carried in the C10 +C shape.  Reduction SOUNDNESS is a SEPARATE,
   LATER step and is DEFERRED here (see "SOUNDNESS DEFERRED" below).

   Thin require-file over the certified base XmssmtCC_All (which owns R_top, the
   top SPHINCS+C interfaces, and the concrete FORS clone FTWES = FORS_ES).

   --------------------------------------------------------------------------
   WHICH +C MODEL.  The C10 model (FORS_C10.ec / FORS_C10_Multi.ec), NOT the
   paper model (FORS_C.ec).  Decisive: the base's top signature type is ALREADY
   the C10 shape

       sigSPHINCSPLUSTWC = mkey * FTWES.sigFORSTW * sigFLSLXMSSMTTWC
                           ^^^^^^^^^^^^^^^^^^^^^^^                     (:9419)

   i.e. `mkey * FTWES.sigFORSTW` = the C10 FORS signature `sigFORSC10 =
   mkey * sigFORSTW` (FORS_C10_Multi.ec:126) with NO counter.  Targeting the
   paper model would REQUIRE adding a `cntr` to that middle component
   (FORS_C.ec's `sigFORSC = mkey * cntr * sigFORSTW`, :322), contradicting the
   existing type.  So C10 is the minimal-change, face-value target.

   --------------------------------------------------------------------------
   THE ONE REAL DELTA vs R_top (message-hash layer only).  In the C10 model the
   FORS message key `mk` (= the randomiser R = SIG_R) is drawn FRESH per
   signature and CONDITIONED on the +C predicate, and is NOT memoized:

       mk <$ dcond dmkey (good m)            (FORS_C10_Multi.O_CMA_MFORSC10.sign:185)

   whereas MM45's R_top draws `mk <$ dmkey` UNIFORM and MEMOIZES it in `mmap`.
   R_top_C therefore (i) drops the `mmap` memoization block in `O_CMA.sign`,
   (ii) draws `mk <$ dcond dmkey (good_fors m)`, and (iii) drops `mmap` state /
   `mmap <- empty` in `forge`.  EVERYTHING ELSE IS BYTE-IDENTICAL to R_top:

     * `choose`  -- the FORS key cube built through the collection oracle
       `OC.query` is +C-INVARIANT (the +C change enters only the message->index
       map, never the key material / Merkle-tree / root-compression layer).  So
       there is NO keygen swap here: R_top's cube is `OC.query`-built, it has no
       `mkeygen` call to replace.
     * `FTWES.mco mk m` (2-arg) -- the message commit arity is the SAME in both
       the MM45 and C10 models (C10 is 2-arg + conditioned key; only the PAPER
       model is 3-arg `mco mk m cntr`).  Unchanged.
     * `FTWES.FL_FORS_ES_NPRF.sign` -- tree-layer FORS signer, +C-invariant.
     * `FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW` -- the forged-FORS-pk
       reconstruction that becomes the hypertree forgery message.  The tree
       layer is +C-invariant, so the MM45 reconstruction IS the +C one; it stays
       FTWES.  (Neither allowed committed module even exposes a
       `pkFORS_from_sigFORSTW` operator.)

   --------------------------------------------------------------------------
   `good_fors` : CONCRETE +C CONDITIONING, AND THE HONEST RESIDUAL.

   `good_fors` (defined below) is the C10 FORS+C conditioning predicate wired
   CONCRETELY: it is FORS_C10.ec:201's `good m mk = predC_fors (mco mk m)` with
   `predC_fors` (FORS_C10.ec:197) UNFOLDED to its definition
   `(nth witness (g y) (k-1)).`3 = 0` -- the +C "last FORS tree forced to leaf 0"
   condition (fors.rs:126) -- over FTWES's concrete `g` / `mco`.  It typechecks
   0-admit as-is; it is NOT an opaque abstract stand-in.

   This CORRECTS an earlier-drafted pessimistic claim (that stating the concrete
   conditioning needs a FORS_ES<->FORS_C10 bridge clone reconciling a
   `(cm,idx)`-pair vs single-`out_t` shape and discharging FORSC10's g-axioms).
   That claim is WRONG -- confirmed by running EasyCrypt.  `predC_fors` is a
   plain concrete formula, and FTWES's `g : msgFORSTW * index -> ...` consumes
   EXACTLY the `msgFORSTW * index` product that FTWES.mco returns (FORS_ES.ec:421
   / :412), so there is no pair-vs-single wall and NO bridge clone is needed to
   STATE the conditioning on the real digest.  (An external EC-running review
   (GPT-5.6) further INDICATES a full FORSC10-onto-FTWES clone is achievable with
   its `size_g`/`eqiks_g`/`neqisvs_g`/`rng_g`/`uniq_g` obligations PROVABLE from
   FORS_ES's concrete `g` rather than new axioms -- NOT independently reproduced
   here, and a SOUNDNESS-track tool not needed for this conditioning wiring.
   Only the concrete-predicate wiring above is reproduced/certified in this file.)

   THE HONEST RESIDUAL is not a typechecking barrier but a POSITIVE-MASS
   assumption: `good_pos` / p_nu (FORS_C10.ec:203+, "for some mk, good m mk").
   `dcond dmkey (good_fors m)` is well-typed for ANY predicate; with zero good-
   mass it degrades to `dnull` (a dead signer) rather than failing to compile.
   So good_pos is what makes the rejection-sampling signer LOSSLESS / faithful,
   and it is NOT derivable from FTWES's abstract `mco` / `dmkey` (a legal model
   can force the good event to mass 0).  It is a NAMED assumption already carried
   in FORS_C10.ec, on the SOUNDNESS track, and is deferred here (it is not needed
   to define or typecheck R_top_C).

   `good_fors` is an OP, not an `axiom` and not an `admit`: `ec-certify` reports
   CERTIFIED-0-ADMIT.  That certifies the module + the concrete conditioning
   typecheck; it does NOT discharge `good_pos` or the reduction's soundness.

   --------------------------------------------------------------------------
   SOUNDNESS DEFERRED.  This file provides ONLY the typechecking module R_top_C.
   Its reduction soundness (that R_top_C faithfully simulates the C10 SPHINCS+C
   CMA game, and the 4-set `choose` audit `R_top_C_members4` -- which ports
   verbatim from `R_top_members4` since `choose` is +C-invariant) is NOT
   attempted here.
   ========================================================================== *)

require import AllCore List Distr StdBigop StdOrder IntDiv.
require import DList DMap.
require import BinaryTrees MerkleTrees.
require import BitEncoding.
import BS2Int.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.

(* The C10 FORS+C conditioning predicate on the message key, wired CONCRETELY at
   the base's concrete `msg` / `mkey` / FTWES digest.  This is FORS_C10.ec:201's
   `good m mk = predC_fors (mco mk m)` with `predC_fors` (FORS_C10.ec:197)
   unfolded to `(nth witness (g y) (k-1)).`3 = 0` over FTWES's concrete `g`/`mco`
   -- the +C "last FORS tree forced to leaf 0" condition.  `good_fors m` is the
   event `dcond` conditions the fresh randomiser draw on, exactly as `good m` is
   used in `dcond dmkey (good m)` at FORS_C10_Multi.ec:185.  (Residual: positive
   good-mass `good_pos` is a named soundness-track assumption, deferred -- see the
   header; it is not needed to typecheck this definition.) *)
op good_fors (m : msg) (mk : mkey) : bool =
  (nth witness (FTWES.g (FTWES.mco mk m)) (k - 1)).`3 = 0.

(* --------------------------------------------------------------------------
   R_top_C -- R_top with the FORS side in the C10 +C shape.  Same module type
   `Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF`, same `choose`/`forge` signatures; the
   only edits are the conditioned fresh draw + removal of `mmap` (see header).
   -------------------------------------------------------------------------- *)
module (R_top_C (A : Adv_EUFCMA_C) : Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF)
       (OC : FSSLXMTWES.TRHC.Oracle_THFC) = {
  var skFORSnt : FTWES.skFORS list list
  var pkFORSnt : FTWES.pkFORS list list
  var root : dgstblock
  var ps : pseed
  var ad : adrs
  var sigFLSLXMSSMTTWCl : sigFLSLXMSSMTTWC list

  (* Simulated CMA oracle, C10 FORS+C: the FORS randomiser is drawn FRESH and
     CONDITIONED per signature (non-memoized), the hypertree signatures come
     from the NAGCMA game.  Mirror of R_top.O_CMA with the MM45 memoized
     `mk <$ dmkey` replaced by the C10 `mk <$ dcond dmkey (good_fors m)`. *)
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

  (* FORS key cube.  BYTE-IDENTICAL to R_top.choose: the cube is +C-invariant
     (the +C change enters only the message->index map, never the key material).
     The three reduction-owned `OC.query` sites and their members are unchanged. *)
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

  (* Mirror of R_top.forge with the +C hypertree signature type; `mmap <- empty`
     removed (no memoization in the C10 model).  The forged-FORS-pk
     reconstruction stays `FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW` (+C-invariant
     tree layer). *)
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
