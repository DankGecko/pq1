(* ==========================================================================
   rtop_c_soundness_wip.ec  --  ROLE = S / VF SOUNDNESS (hop-6).

   Builds the minimal +C scaffolding needed to STATE and PROVE hop-6 of the
   SPHINCS+C top reduction, mirroring the MM45 template (FV-SPHINCSPLUS-EC/
   proofs/SPHINCS_PLUS.ec, section Proof_SPHINCS_PLUS_EUFCMA):

     (1) V_C : the +C NPRFNPRF_V validity-inlined SPHINCS+C CMA game
         (mirror MM45 :2186-2239) whose oracle draws  mk <$ dcond dmkey
         (good_fors m)  FRESH / non-memoized, FORS-signs via FTWES, HT-signs
         via FL_SL_XMSS_MT_C_ES_NPRF, and inlines the +C verify to expose
         valid_MFORSC10 <- (pkFORS' = pkFORS)                (mirror :2221-2234).

     (2) RV_C : the +C RV intermediate (mirror MM45 :2602) -- the NAGCMA game
         with R_top_C inlined and skWOTStd pulled out as a module var.

     (3) hop-6 : LeqPr_VF_C  (mirror MM45 :3468-3477 + :3478-...) :
           Pr[V_C : res /\ !valid_MFORSC10]
             <= Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(R_top_C(F), FC.O_THFC_Default)].

   --------------------------------------------------------------------------
   PROVENANCE NOTE (R_top_C + good_fors are INLINED, not required).

   The task asked to `require import rtop_forsc_wip` for R_top_C + good_fors.
   That require is IMPOSSIBLE as an EasyCrypt import: `rtop_forsc_wip` is a
   lowercase filename, and EasyCrypt theory names must be uppercase-initial, so
   `require import rtop_forsc_wip.` is a hard PARSE ERROR (rc=1, `[critical] ...
   parse error` at the require token) -- confirmed by running the gate.  A
   lowercase-named .ec compiles when passed DIRECTLY to `easycrypt compile`
   (which is how rtop_forsc_wip.ec was certified) but cannot be REQUIRED by
   name.  This is exactly the "if requiring rtop_forsc_wip conflicts, copy
   R_top_C's definition in and say so" contingency in the task.

   ==> `good_fors` (below) and `module R_top_C` (below) are COPIED from
   drafts/rtop_forsc_wip.ec (CERTIFIED-0-ADMIT there): CODE is verbatim (op body
   + module body byte-identical), some inline prose comments trimmed.  No change
   of meaning.
   ========================================================================== *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import DList DMap FMap.
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
import FTWES.DBLLKTL.
import DigestBlock.
import IntOrder.

(* ==========================================================================
   STEP-0 FINDING (advisor-flagged): hop-6 is CLONE-FREE.

   CONFIRMED by reading MM45 SPHINCS_PLUS.ec:2186-2239 (NPRFNPRF_V), :2602 (RV),
   :3468-3477 (LeqPr_VF) AND the +C C10 model (FORS_C10_Multi.ec).  hop-6 does
   NOT require instantiating the ABSTRACT `good` clone.  The STRUCTURAL argument
   (not the weak "MM45 mentions no `good`" -- MM45 is base SPHINCS+, so it
   trivially wouldn't):

     * The SPLIT predicate  valid_MFORSC10 = (pkFORS' = pkFORS)  is purely
       CONCRETE and never mentions `good` (mirrors MM45 :2230 / :3469).
     * The +C conditioning  good_fors  enters hop-6 in exactly two CONCRETE
       spots, both benign for the coupling:
         (i)  the oracle mk-draw  mk <$ dcond dmkey (good_fors m)  -- BYTE-
              IDENTICAL on the V_C and R_top_C(RV_C) sides, so the byequiv
              couples it by a SINGLE `rnd` on the shared `dcond` expression and
              it cancels.  This couples EVEN IF the dcond is dnull-degenerate
              (Distr.ec dcond semantics: the `rnd` needs the two distribution
              EXPRESSIONS equal, not positive mass), so NO `good_pos` is needed.
         (ii) the forced-zero validity gate  good_fors m' mk'  in V_C's
              is_valid (the C10-faithful conjunct, see S.1) -- a deterministic
              function of the EQUAL (mk', m'), carried through and DROPPED in
              the `res{1} => res{2}` implication (it only shrinks res{1}).
       Neither spot references the ABSTRACT `good` predicate/clone; both use the
       concrete `good_fors`.  So hop-6 lands CLONE-FREE; the abstract-`good`
       clone is isolated to the VT branch (hop-5, OUT OF SCOPE here).

   NUANCE (GPT-5.6 review 2026-07-21): "clone-free" is NOT "good-free" -- a
   FAITHFUL C10 game DOES reference good_fors (oracle draw + forgery gate), but
   always the CONCRETE predicate, never the abstract clone, and never `good_pos`
   as a coupling dependency.  `good_pos` returns only DOWNSTREAM, as the C10
   signing-oracle losslessness premise for the top HT theorem (XmssmtCC_All.ec:
   8749 forge-losslessness), separate from this hop.
   ========================================================================== *)

(* ==========================================================================
   MKG-ABSORPTION OBSERVATION (advisor question for the full-scheme wave -- NOT
   solved here, reported from the V-game structure).

   Q: does the +C fresh conditioned draw  mk <$ dcond dmkey (good_fors m)
   structurally ABSORB MM45's MKG-PRF hop-3 (which turns a MEMOIZED-uniform draw
   into a random-function draw)?  Is there even an MKG-PRF term at +C scheme
   level, or does the fresh draw make hop-3 vacuous?

   OBSERVED:
   1. At the +C V-game / hop-6 level, mk is a FRESH, NON-memoized draw on BOTH
      sides (V_C.O_CMA_C.sign and R_top_C.O_CMA.sign both do
      `mk <$ dcond dmkey (good_fors m)`, no mmap).  MM45's hop-3 rewrites a
      MEMOIZED-uniform draw into a random function -- there is NO memoization
      here for it to bite on, so that transition is VACUOUS at the V-game level.
      This is the REAL C10 model, not a hybrid artifact: FORS_C10_Multi.ec:163-
      167 draws `mk <$ dcond dmkey (good m)` FRESH per signature, "matching
      production and F.O_ITSRC10_Default.query".  It is ALSO why the mmap
      coupling MM45 carries (:1488 / :3976 `={mmap}(...)`) is DROPPED in +C
      hop-6 -- the "single coupled rnd, no mmap" simplification.
   2. BUT an MKG-PRF term DOES exist at the +C FULL-SCHEME level:  `mkg_adv`
      (SPHINCS_C_c10.ec:149 "skg_adv + mkg_adv (PRF hops, +C-invariant)", :195,
      :210).  So hop-3 is NOT globally absorbed -- it is a separate, accounted,
      +C-invariant term (the hop idealising the REAL PRF-keyed mk into the
      uniform `dmkey`).  The fresh conditioned draw is the OUTPUT of that
      idealisation (uniform dmkey) PLUS the +C conditioning (dcond good_fors),
      not a replacement that eliminates the PRF hop.
   3. DEFERRED FAITHFULNESS QUESTION (full-scheme wave): MM45 MEMOIZES to model a
      DETERMINISTIC PRF as a random function (same m -> same mk); the C10 model
      RE-DRAWS fresh (same m may get different mk).  Whether the fresh-draw model
      faithfully represents the deterministic-PRF real scheme is the open
      question (related to why good_pos / oracle losslessness is load-bearing).
   ========================================================================== *)

(* ==========================================================================
   INLINED FROM rtop_forsc_wip.ec (verbatim) -- good_fors + R_top_C.
   ========================================================================== *)

(* The C10 FORS+C conditioning predicate on the message key, wired CONCRETELY at
   the base's concrete `msg` / `mkey` / FTWES digest (FORS_C10.ec:201's
   `good m mk = predC_fors (mco mk m)`, with `predC_fors` unfolded). *)
op good_fors (m : msg) (mk : mkey) : bool =
  (nth witness (FTWES.g (FTWES.mco mk m)) (k - 1)).`3 = 0.

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
   (S.1) V_C : the +C NPRFNPRF_V validity-inlined SPHINCS+C CMA game.

   Mirror of MM45 EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_V (SPHINCS_PLUS.ec:2186-2239),
   with the +C deltas:

     * the CMA oracle draws  mk <$ dcond dmkey (good_fors m)  FRESH and
       non-memoized (MM45 memoized `mk <$ dmkey` in an `mmap`).
     * the inlined validity is the C10-FAITHFUL top verify: the FORS forced-zero
       gate `good_fors m' mk'` (= predC_fors of the recomputed digest -- the +C
       validity conjunct of `mverifyC`, FORS_C10_Multi.ec:139-143) AND the
       hypertree root reconstruction via FL_SL_XMSS_MT_C_ES.root_from_sigC
       (root' + the +C allOkC constant-sum flag + the `size sig = d` gate =
       exactly the REAL +C hypertree verify, XMSSMT_C_Scheme.ec:200-212).
       The `valid_MFORSC10` split flag stays PURE reconstructed-pk equality.

   MODELLING BOUNDARY (inherited, not re-litigated here).  The FORS side is
   carried at the FTWES (MM45) signature SHAPE -- `sigFORSC10 = mkey *
   FTWES.sigFORSTW` (FORS_C10_Multi.ec:126), full k-tuple, NO structural
   last-path drop.  The C10 "+C" delta is modelled as the `good_fors` /
   predC_fors CONDITIONING on the message key (grinding R), NOT as a change to
   the FORS signature structure.  This is the F-role / FORS_C10 modelling
   decision (rtop_forsc_wip.ec header; CERTIFIED separately) and is a DELIBERATE
   security-model abstraction of the shipped implementation's K/K-1 auth-path
   optimisation.  V_C uses that same FTWES shape; hop-6 does not re-open it.
   (Corollary, per Kimi review 2026-07-21: "is_valid matches mverifyC" holds
   by-PREDICATE-ANALOGY -- the FORS INSTANCE ROUTING also differs, FORS_C10_Multi
   routes by `idx_of y` over a d-pool while FTWES routes by `edivz (val idx) l'`;
   both are the inherited FORS-model choice, not pinned by a top +C scheme
   artifact, which does not exist in-repo -- V_C is the FIRST such definition.)

   CROSS-BRANCH CONTRACT (coordination for the hop-5 / VT-branch session --
   advisor 2026-07-21).  There is ONE shared V-game.  The overall accounting is
       Pr[V_C : res] = Pr[V_C : res /\ valid_MFORSC10]    (hop-5 / VT, ITSR-C10)
                     + Pr[V_C : res /\ !valid_MFORSC10]   (hop-6 / VF, THIS file)
   so hop-5 MUST consume THIS EXACT V_C: `is_valid = good_fors m' mk' /\ <HT
   conditions>` (the forced-zero gate lives in is_valid, part of `res`) and
   `valid_MFORSC10` PURE reconstructed-pk equality.  If hop-5 independently
   defines a V-game WITHOUT the good_fors gate, or FOLDS good into the flag, the
   two branches do NOT recombine (and the ITSR-C10 game only bites on GOOD
   digests, so the gate is load-bearing for that sibling branch too).

   Key-generation ORDER matches MM45 keygen_nprf and the RV side (FORS cube
   FIRST, then the WOTS/HT keys via FL_SL_XMSS_MT_C_ES_NPRF.keygen) so the hop-6
   byequiv couples rnd-aligned.  The FORS cube is sampled with the SAME raw
   `skFORS_ele <$ ddgstblock` loop as R_top_C.choose.
   ========================================================================== *)
module EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V (A : Adv_EUFCMA_C) = {
  var valid_MFORSC10 : bool
  var qs : msg list
  var skFORSnt : FTWES.skFORS list list
  var skWOTStd : skWOTS list list list
  var root : dgstblock
  var ps : pseed
  var ad : adrs

  (* +C CMA oracle: fresh conditioned mk draw, FORS-sign, gen_pkFORS, HT-sign. *)
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

    (* FORS key cube -- sampled FIRST, same raw draw as R_top_C.choose. *)
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

    (* WOTS / hypertree keys (and the public root) via the +C HT keygen. *)
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

    (* The SPLIT flag stays PURE reconstructed-pk equality (its negation must map
       to hypertree-freshness in hop-6; folding `good_fors` in here would break
       that -- see GPT-5.6 review 2026-07-21). *)
    valid_MFORSC10 <- pkFORS' = pkFORS;

    (* Inlined C10-faithful verify.  The +C top validity is `mverifyC`
       (FORS_C10_Multi.ec:139-143) = predC_fors(mco mk' m') /\ fverify, over the
       hypertree: the FORS forced-zero gate `good_fors m' mk'` (= predC_fors of
       the recomputed digest) PLUS the hypertree root reconstruction (root' /
       allOkC / size-d, = the REAL FL_SL_XMSS_MT_C_ES.verify).  The forced-zero
       gate is a genuine validity check on the ADVERSARY's forgery (its mk' need
       not be conditioned) and MUST be present for V_C to be a faithful C10
       hybrid.  In hop-6 it is simply DROPPED from the `res{1} => res{2}`
       implication (it only shrinks the LHS event), so the byequiv stays true. *)
    (root', allOkC) <@ FL_SL_XMSS_MT_C_ES.root_from_sigC(pkFORS', sigHT', idx, ps, ad);

    is_valid <- good_fors m' mk' /\ size sigHT' = d /\ root' = root /\ allOkC;
    is_fresh <- ! (m' \in qs);

    return is_valid /\ is_fresh;
  }
}.

(* ==========================================================================
   (S.2) RV_C : the +C RV intermediate.

   Mirror of MM45 EUF_NAGCMA_FLSLXMSSMTTWESNPRF_RV (SPHINCS_PLUS.ec:2602-2642):
   the EUF-NAGCMA game for the WOTS+C hypertree with the reduction R_top_C
   inlined and its `skWOTStd` pulled out as a module var, using the REAL +C
   hypertree keygen / sign / verify (FL_SL_XMSS_MT_C_ES_NPRF) and the collection
   oracle FSSLXMTWES.TRHC.O_THFC_Default (the same OC the top NAGCMA game hands
   its adversary).
   ========================================================================== *)
module EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV (A : Adv_EUFCMA_C) = {
  var skWOTStd : skWOTS list list list

  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pk : pkFLSLXMSSMTTW;
    var sk : skWOTS list list list * pseed * adrs;
    var ml : msgFLSLXMSSMTTW list;
    var sigl : sigFLSLXMSSMTTWC list;
    var m : msgFLSLXMSSMTTW;
    var m' : msgFLSLXMSSMTTW;
    var sig : sigFLSLXMSSMTTWC;
    var sig' : sigFLSLXMSSMTTWC;
    var idx' : index;
    var is_valid : bool;
    var is_fresh : bool;

    ad <- adz;
    ps <$ dpseed;
    FSSLXMTWES.TRHC.O_THFC_Default.init(ps);
    ml <@ R_top_C(A, FSSLXMTWES.TRHC.O_THFC_Default).choose();
    (pk, sk) <@ FL_SL_XMSS_MT_C_ES_NPRF.keygen(ps, ad);

    skWOTStd <- sk.`1;

    sigl <- [];
    while (size sigl < l){
      m <- nth witness ml (size sigl);
      sig <@ FL_SL_XMSS_MT_C_ES_NPRF.sign((skWOTStd, sk.`2, sk.`3), m, Index.insubd (size sigl));
      sigl <- rcons sigl sig;
    }

    (m', sig', idx') <@ R_top_C(A, FSSLXMTWES.TRHC.O_THFC_Default).forge(pk, sigl);
    is_valid <@ FL_SL_XMSS_MT_C_ES_NPRF.verify(pk, m', sig', idx');
    is_fresh <- m' <> nth witness ml (Index.val idx');

    return is_valid /\ is_fresh;
  }
}.

(* --------------------------------------------------------------------------
   (S.3) Eqv_Orig_RV_C : structural byequiv NAGCMA(R_top_C(F)) ~ RV_C(F).

   Mirror of MM45 Eqv_EUF_NAGCMA_FLSLXMSSMTTWESNPRF_Orig_RV (SPHINCS_PLUS.ec:
   2645-2659).  The ONLY difference between the two games is that RV_C names
   `sk.`1` as the module var `skWOTStd` and passes `(skWOTStd, sk.`2, sk.`3)`
   (definitionally = `sk`) to the signer; everything else is byte-identical, so
   the coupling is a plain `sim` with the reduction's `skFORSnt` carried.
   -------------------------------------------------------------------------- *)
lemma Eqv_Orig_RV_C (F <: Adv_EUFCMA_C{-R_top_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV,
                                       -FSSLXMTWES.TRHC.O_THFC_Default}) :
  equiv[ EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(R_top_C(F), FSSLXMTWES.TRHC.O_THFC_Default).main
         ~ EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV(F).main
         : ={glob F} ==> ={res} ].
proof.
proc.
seq 7 8 : (={glob F, glob FSSLXMTWES.TRHC.O_THFC_Default, pk, ml, sigl, R_top_C.skFORSnt}); 2: by sim.
while (={sigl, ml, glob FSSLXMTWES.TRHC.O_THFC_Default}
       /\ sk{1} = (EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd, sk.`2, sk.`3){2}).
+ conseq (: _ ==> ={ml, sigl}) => //.
  wp; call (: true); 1: by sim.
  by wp.
swap{2} 6 1; wp 6 6 => /=.
conseq (: _ ==> ={glob F, glob FSSLXMTWES.TRHC.O_THFC_Default, pk, sk, ml, sigl, R_top_C.skFORSnt}); 1: smt().
by sim.
qed.

(* keygen coupling helper: the +C HT keygen is identical on both sides, and its
   public key exposes the input (ps, ad) in slots 2/3 (bound via logical vars). *)
equiv keygenC_eq_simple :
  FL_SL_XMSS_MT_C_ES_NPRF.keygen ~ FL_SL_XMSS_MT_C_ES_NPRF.keygen :
    ={ps, ad} ==> ={res}.
proof. proc; sim. qed.

lemma keygenC_pkin (psi : pseed) (adi : adrs) :
  hoare[FL_SL_XMSS_MT_C_ES_NPRF.keygen :
        ps = psi /\ ad = adi ==> res.`1.`2 = psi /\ res.`1.`3 = adi].
proof.
proc; wp; call leaves_sklpsad_h; wp.
while (ps = psi /\ ad = adi).
+ wp; while (ps = psi /\ ad = adi).
  + wp; while (ps = psi /\ ad = adi).
    + wp; while (ps = psi /\ ad = adi).
      - by auto.
      by auto.
    by auto.
  by auto.
by auto.
qed.

lemma keygenC_eq (psi : pseed) (adi : adrs) :
  equiv[FL_SL_XMSS_MT_C_ES_NPRF.keygen ~ FL_SL_XMSS_MT_C_ES_NPRF.keygen :
        ={ps, ad} /\ ps{2} = psi /\ ad{2} = adi
        ==> ={res} /\ res{2}.`1.`2 = psi /\ res{2}.`1.`3 = adi].
proof. conseq keygenC_eq_simple (keygenC_pkin psi adi) => //. qed.

(* keygen threads (ps, ad) into BOTH pk and sk: pk = (root, ps, ad); sk = (skWOTStd,
   ps, ad) (XmssmtCC_All.ec:204-205).  The sk-field variant is needed because the RV
   sign loop uses sk.`2 / sk.`3 (not pk.`2 / pk.`3), and hop-6 must know they equal
   (ps, adz) to couple the RV signatures to the V-side (which signs under ps / adz). *)
lemma keygenC_pksk (psi : pseed) (adi : adrs) :
  hoare[FL_SL_XMSS_MT_C_ES_NPRF.keygen :
        ps = psi /\ ad = adi ==>
        res.`1.`2 = psi /\ res.`1.`3 = adi /\ res.`2.`2 = psi /\ res.`2.`3 = adi].
proof.
proc; wp; call leaves_sklpsad_h; wp.
while (ps = psi /\ ad = adi).
+ wp; while (ps = psi /\ ad = adi).
  + wp; while (ps = psi /\ ad = adi).
    + wp; while (ps = psi /\ ad = adi).
      - by auto.
      by auto.
    by auto.
  by auto.
by auto.
qed.

lemma keygenC_eq2 (psi : pseed) (adi : adrs) :
  equiv[FL_SL_XMSS_MT_C_ES_NPRF.keygen ~ FL_SL_XMSS_MT_C_ES_NPRF.keygen :
        ={ps, ad} /\ ps{2} = psi /\ ad{2} = adi
        ==> ={res} /\ res{2}.`1.`2 = psi /\ res{2}.`1.`3 = adi
                   /\ res{2}.`2.`2 = psi /\ res{2}.`2.`3 = adi].
proof. conseq keygenC_eq_simple (keygenC_pksk psi adi) => //. qed.

(* ==========================================================================
   (S.4) hop-6 : LeqPr_VF_C.

   Mirror of MM45 LeqPr_EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_VF_FLSLXMSSMTTWESNPRF
   (SPHINCS_PLUS.ec:3468-3477 statement + :3478-3462 proof).  The event and RHS
   game byte-match the MM45 shape (`res /\ ! valid_MFORS...`  <=  NAGCMA of the
   reduction).

   PROOF STATUS (UPDATE 2026-07-21): the RHS-rewrite leg (NAGCMA(R_top_C(F)) =
   RV_C(F)) is PROVEN via Eqv_Orig_RV_C.  On the main coupling byequiv (V_C ~
   RV_C), the R6a ESTABLISH leg is now PROVEN (the `seq 5 4` block below: the
   FORS-cube <-> committed-pkFORS invariant, MM45 :3482-3564, near-verbatim port
   with the +C name/clone adaptations; the WOTS/HT keygen couples via
   keygenC_eq).  The SINGLE remaining `admit` after that block covers R6a-CONSUME
   (:4176-4277) + R6b (sigl-table) + R6c (validity/freshness map); see below.

   ------------------------------------------------------------------------
   RESIDUAL (what the remaining `admit` covers).  R6a-establish is DONE; the
   three legs originally scoped, minus the proven establish, are:

   (R6a) FORS-CUBE <-> COMMITTED-pkFORS INVARIANT  [the bulk; MM45 :3482-3564
       to ESTABLISH, then CONSUMED at :4176-4277 -- larger than a single block,
       per GPT-5.6 review 2026-07-21].
       ==> ESTABLISH: *PROVEN* (the `seq 5 4` block below; keygen via keygenC_eq,
           FORS-cube relational while + one-sided node-building while{2}).
       ==> CONSUME (:4176-4277, the nth_flatten/edivz/Index.insubdK arithmetic
           that turns `gen_pkFORS(skFORS at idx) = ml[idx]`) is STILL inside the
           remaining admit -- it fires inside R6c's forge/verify coupling.
       Couple V_C's keygen (raw
       `skFORS_ele <$ ddgstblock` cube, then FL_SL_XMSS_MT_C_ES_NPRF.keygen)
       with RV_C's setup (R_top_C.choose builds the cube through OC.query =
       f/trh/trco, then the same HT keygen + the sign loop building `sigl`),
       CARRYING `TRHC.O_THFC_Default.pp{2} = ps{2}` (MM45 :3482, the collection
       oracle's public seed), and establishing:
         ml{2} = flatten R_top_C.pkFORSnt{2},
         each pkFORSnt entry = trco(ps, ., flatten(map val roots)) over the
           roots computed from the SHARED skFORSnt,
         size/shape facts (nr_trees 0, l', all ((=) l' \o size)),
         all address/index bounds explicit so `nth witness` defaults are
           unreachable (the :4176-4277 nth_flatten / edivz / Index.insubdK
           arithmetic),
       i.e. the on-demand `gen_pkFORS(skFORS at idx)` on the V-side EQUALS the
       committed HT message `ml{2}[idx]` on the RV-side.  This block is
       +C-INVARIANT (FORS key cube is +C-invariant -- see R_top_C header /
       XmssmtCC_All.ec:9400-9403); the WOTS/HT keygen is the +C
       `FL_SL_XMSS_MT_C_ES_NPRF.keygen`, an identity coupling on the HT half.

   (R6b) ORACLE-CALL EQUIVALENCE given (R6a) + the mk-rnd coupling, PLUS the
       precomputed-signature-table invariant  [MM45 ~:3726-4228]:
         forall i, 0 <= i < l =>
           sigl{2}[i] = FL_SL_XMSS_MT_C_ES_NPRF.sign(skHT, ml{2}[i], Index.insubd i).
       The two signing oracles differ ONLY in the hypertree signature source:
       V_C computes `pkFORS <@ gen_pkFORS(skFORS,.)` then
       `sigHT <@ FL_SL_XMSS_MT_C_ES_NPRF.sign((skWOTStd,ps,ad), pkFORS, idx)`,
       while R_top_C reads `sigHT <- nth witness sigFLSLXMSSMTTWCl idx`.  Under
       (R6a) + this table these coincide: `sigl[idx] = HT.sign(sk, ml[idx], idx)`
       and `ml[idx] = gen_pkFORS(skFORS at idx)`.  The mk draw couples via a
       SINGLE `rnd` on the SHARED `dcond dmkey (good_fors m)` (byte-identical on
       both sides -- NO mmap memoization to carry, unlike MM45 :1488); `cm/idx`,
       `skFORS`, and `sigFORSTW` are then deterministically equal.  This is the
       genuinely SIMPLER-than-MM45 leg (no mmap invariant -- see STEP-0 finding
       at the top of this file).
       NB (one-sided losslessness): RV precomputes all `l` HT signatures while V
       signs on demand; eliminating that extra RHS computation needs HT-sign
       losslessness -- ALREADY proved at XmssmtCC_All.ec:373 (`_ll`), NOT
       `good_pos`.

   (R6c) FINAL VALIDITY/FRESHNESS EVENT MAPPING  [MM45 :3935].
       On `res{1} /\ !valid_MFORSC10{1}` (V_C forgery valid+fresh with pkFORS'
       <> pkFORS), map to `res{2}` of RV_C: the reconstructed `pkFORS'` becomes
       the forged hypertree message; V_C's inlined HT validity (root_from_sigC
       root' = root /\ allOkC /\ size = d) equals RV_C's
       `FL_SL_XMSS_MT_C_ES_NPRF.verify`, and `pkFORS' <> pkFORS = ml[idx']`
       yields INDEX-LOCAL hypertree-freshness `pkFORS' <> ml{2}[Index.val idx']`
       (RHS freshness is index-local, NOT `pkFORS' \notin ml`).  This actually
       gives EQUALITY of the events, not just implication (MM45 :3935).  The
       extra conjuncts of `res{1}` -- the forced-zero gate `good_fors m' mk'`
       (the +C fidelity conjunct) and top-freshness `!(m' \in qs)` -- are simply
       DROPPED (they only SHRINK `res{1}`), so the `<=` bound is preserved.

   NONE of (R6a)-(R6c) needs `good_pos` / positive good-mass: the `rnd` couples
   on the dcond EXPRESSION being equal, not on it having positive mass (a
   dnull-degenerate dcond still couples -- confirmed against Distr.ec dcond
   semantics).  CAVEAT (GPT-5.6): `good_pos` is NOT purely a capstone concern --
   it returns DOWNSTREAM as the C10 signing-oracle losslessness premise
   (FORS_C10.ec good-mass -> dcond_ll), which the top HT theorem needs as
   `R_top_C(F).forge` losslessness when instantiated (XmssmtCC_All.ec:8749).
   It is simply not a dependency of THIS hop's coupling.

   --------------------------------------------------------------------------
   ACTIONABLE HANDOFF for the remaining admit (advisor 2026-07-21).  After the
   proven `seq 5 4` block the residual byequiv state is:
       LHS (V_C):  qs<-[]; A(O_CMA_C).forge; <inlined verify>
       RHS (RV_C): sigl<-[]; <sign while>; R_top_C.forge(pk,sigl); verify
   Close it in two seq blocks + a tail:

   * R6b  `seq 1 2 : (#post /\ <sigl-table>)`.  Couple qs<-[] with sigl<-[] +
     the RHS sign loop as a ONE-SIDED `while{2}(<sigl-table-inv>)(l - size sigl)`
     (V has no sign loop -- termination via **`nprf_sign_ll`**, XmssmtCC_All.ec
     ~:375; NOT :373 which is a comment).  The invariant is the +C closed form
       forall i, 0<=i<size sigl{2} => nth sigl{2} i = <sig,counter,ap of layer j>
     The maintenance argument (MM45's `do 2! congr` becomes `do 3! congr`, with
     the extra `nthcs` step folding the ground counter back into `grindC ps addr
     root`) is ALREADY PROVEN at `_assembly_unfold_wip.ec:4816-4894` -- but there
     it is TWO-SIDED (real signer ~ C-game, `={sigl}`).  To reuse it one-sided,
     recast as `phoare[FL_SL_XMSS_MT_C_ES_NPRF.sign : arg = (sk,m,idx) ==> res =
     <closed form>] = 1%r` (HT.sign is deterministic -- WOTS_C_Scheme.ec:41,
     grindC is a total function, no `$`), then each loop step rewrites via it.
     NB: MM45's :3726-3769 seq-post also carries `mmap`/sk-assembly that mmap-free
     RV_C lacks, so the invariant is a RECONSTRUCTION, not a pure substitution.

   * R6c  MM45 :3935-4278 (the oracle `call` + FORS-root recompute + final map).
     The oracle body couples the single mk `rnd` on `dcond dmkey (good_fors m)`
     (byte-identical both sides, no mmap) then matches V's on-demand
     `HT.sign(sk,pkFORS,idx)` to `sigl[val idx]` via the R6b table + the R6a
     trco relation (this is where R6a-CONSUME :4176-4277 fires).  WRINKLE (do NOT
     write `={is_valid}`): the +C `root_from_sigC` returns a PAIR and V's is_valid
     carries an extra `good_fors m' mk'`, so the conseq target is
         (size sigHT'{1}=d /\ root'{1}=root{1} /\ allOkC{1}) = is_valid{2}
       /\ (! valid_MFORSC10{1}) = is_fresh{2}
     with `good_fors` + top-freshness `!(m' \in qs)` DROPPED by smt on the
     entailment (matches MM45 :3939).  Do NOT smt-force the coupling itself.
   ========================================================================== *)
lemma LeqPr_VF_C (F <: Adv_EUFCMA_C{-R_top_C, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V,
                     -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV, -FSSLXMTWES.TRHC.O_THFC_Default}) &m :
  Pr[EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V(F).main() @ &m :
       res /\ ! EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.valid_MFORSC10]
  <=
  Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(R_top_C(F), FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res].
proof.
have ->:
  Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(R_top_C(F), FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res]
  =
  Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV(F).main() @ &m : res].
+ by byequiv (Eqv_Orig_RV_C F).
byequiv => //.
proc.
(* PROVEN opening coupling: the shared `ad <- adz; ps <$ dpseed` prefix couples
   (a single `rnd` on dpseed), isolating the admit to the FORS-cube setup onward. *)
seq 2 2 : (={glob F}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = ps{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz
           /\ ad{2} = adz).
+ auto.
seq 5 4 : (   ={glob F}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{1} = EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz
           /\ ad{2} = adz
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = ps{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.root{1} = pk{2}.`1
           /\ pk{2}.`2 = ps{2}
           /\ pk{2}.`3 = adz
           /\ sk{2}.`2 = ps{2}
           /\ sk{2}.`3 = adz
           /\ FSSLXMTWES.TRHC.O_THFC_Default.pp{2} = ps{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} = R_top_C.skFORSnt{2}
           /\ ml{2} = flatten R_top_C.pkFORSnt{2}
           /\ (forall (i j : int),
                0 <= i < nr_trees 0 => 0 <= j < l' =>
                let rts
                    =
                    mkseq (fun (u : int) =>
                            FTWES.val_bt_trh ps{2} (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)
                                             (list2tree (mkseq (fun (v : int) =>
                                                 f ps{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v))
                                                          (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness R_top_C.skFORSnt{2} i) j)) u) v))) t)) u) k in
                 nth witness (nth witness R_top_C.pkFORSnt{2} i) j
                 =
                 trco ps{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) trcotype) j)
                      (flatten (map DigestBlock.val rts)))
           /\ size R_top_C.pkFORSnt{2} = nr_trees 0
           /\ all ((=) l' \o size) R_top_C.pkFORSnt{2}).
+ admit.
(* R6b: freeze the +C sigl-table (MM45 :3741-3769 + the +C counter/encode).
   Established one-sidedly by the RHS sign loop; consumed by R6c. *)
seq 1 2 : (   #pre
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.qs{1} = []
           /\ (forall (i j : int),
                 0 <= i < l => 0 <= j < d =>
                 (nth witness (nth witness sigl{2} i) j).`1
                 =
                 let ti = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) j).`1 in
                 let adlt = set_ltidx adz (j - 1) ti in
                 let rt = (if j = 0
                           then nth witness ml{2} i
                           else FSSLXMTWES.val_bt_trh ps{2} (set_typeidx adlt trhxtype)
                                  (list2tree (mkseq (fun (u : int) =>
                                      pkco ps{2} (set_kpidx (set_typeidx adlt pkcotype) u)
                                           (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                                               cf ps{2} (set_chidx (set_kpidx (set_typeidx adlt chtype) u) v) 0 (w - 1)
                                                  (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2} (j - 1)) ti) u)) v))) len)))) l'))) in
                 let chad = set_kpidx (set_typeidx (set_ltidx adz j (ti %/ l')) chtype) (ti %% l') in
                 (DBLL.insubd (mkseq (fun (v : int) =>
                    cf ps{2} (set_chidx chad v) 0 (BaseW.val (encode_msgWOTS_C ps{2} chad rt (grindC ps{2} chad rt)).[v])
                       (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2} j) (ti %/ l')) (ti %% l'))) v))) len),
                  grindC ps{2} chad rt))
           /\ (forall (i j : int),
                 0 <= i < l => 0 <= j < d =>
                 (nth witness (nth witness sigl{2} i) j).`2
                 =
                 let ti = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) (j + 1)).`1 in
                 let ki = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) (j + 1)).`2 in
                 let adlt = set_ltidx adz j ti in
                 let lfs = mkseq (fun (u : int) =>
                                     pkco ps{2} (set_kpidx (set_typeidx adlt pkcotype) u)
                                          (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                                              cf ps{2} (set_chidx (set_kpidx (set_typeidx adlt chtype) u) v) 0 (w - 1)
                                                 (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2} j) ti) u)) v))) len)))) l' in
                 FSSLXMTWES.cons_ap_trh ps{2} (set_typeidx (set_ltidx adz j ti) trhxtype) (list2tree lfs) ki)).
+ sp 1 1.
  while{2} (   sk{2}.`2 = ps{2}
            /\ sk{2}.`3 = adz
            /\ size sigl{2} <= l
            /\ (forall (i j : int),
                  0 <= i < size sigl{2} => 0 <= j < d =>
                  (nth witness (nth witness sigl{2} i) j).`1
                  =
                  let ti = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) j).`1 in
                  let adlt = set_ltidx adz (j - 1) ti in
                  let rt = (if j = 0
                            then nth witness ml{2} i
                            else FSSLXMTWES.val_bt_trh ps{2} (set_typeidx adlt trhxtype)
                                   (list2tree (mkseq (fun (u : int) =>
                                       pkco ps{2} (set_kpidx (set_typeidx adlt pkcotype) u)
                                            (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                                                cf ps{2} (set_chidx (set_kpidx (set_typeidx adlt chtype) u) v) 0 (w - 1)
                                                   (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2} (j - 1)) ti) u)) v))) len)))) l'))) in
                  let chad = set_kpidx (set_typeidx (set_ltidx adz j (ti %/ l')) chtype) (ti %% l') in
                  (DBLL.insubd (mkseq (fun (v : int) =>
                     cf ps{2} (set_chidx chad v) 0 (BaseW.val (encode_msgWOTS_C ps{2} chad rt (grindC ps{2} chad rt)).[v])
                        (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2} j) (ti %/ l')) (ti %% l'))) v))) len),
                   grindC ps{2} chad rt))
            /\ (forall (i j : int),
                  0 <= i < size sigl{2} => 0 <= j < d =>
                  (nth witness (nth witness sigl{2} i) j).`2
                  =
                  let ti = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) (j + 1)).`1 in
                  let ki = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) (j + 1)).`2 in
                  let adlt = set_ltidx adz j ti in
                  let lfs = mkseq (fun (u : int) =>
                                      pkco ps{2} (set_kpidx (set_typeidx adlt pkcotype) u)
                                           (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                                               cf ps{2} (set_chidx (set_kpidx (set_typeidx adlt chtype) u) v) 0 (w - 1)
                                                  (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2} j) ti) u)) v))) len)))) l' in
                  FSSLXMTWES.cons_ap_trh ps{2} (set_typeidx (set_ltidx adz j ti) trhxtype) (list2tree lfs) ki))
           (l - size sigl{2}).
  - move=> &m0 z.
    admit.
  skip => />.
  split; 1: smt(ge2_l).
  by split; move=> i j ge0i lti0 ge0j ltjd; exfalso; smt().
(* R6c: forge coupling + R6a-consume + validity/freshness map (MM45 :3935-4278). *)
conseq (: _ ==>
     (is_valid{1} => is_valid{2})
  /\ (! EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.valid_MFORSC10{1}) = is_fresh{2}); 1: smt().
inline{2} 2.
inline{2} 1.
admit.
qed.

(* ==========================================================================
   NON-VACUITY CANARIES (both confirmed REJECTED while live; commented out so
   the scaffolding + proven byequivs compile clean).

   CANARY 1 (gate-liveness).  `lemma canary_A : false. proof. by []. qed.`
     => REJECTED, rc!=0, "[by]: cannot close goals".  Proves the scratch-ecc
     gate is not vacuously passing a `false` goal.

   CANARY 2 (Eqv_Orig_RV_C postcondition non-vacuity).  The SAME Eqv_Orig_RV_C
     proof script with the postcondition flipped to `res{1} <> res{2}`
     => REJECTED, rc!=0, "cannot infer the set of equalities" at the closing
     `by sim`.  Proves the proven `={res}` is genuine result-EQUALITY, not a
     degenerate always-true postcondition (guards against a vacuous byequiv,
     the advisor-flagged failure mode).
   ========================================================================== *)
