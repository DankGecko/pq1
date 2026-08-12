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
   (S.3b) CLOSED-FORM CHARACTERISATION of the +C hypertree signer
   FL_SL_XMSS_MT_C_ES_NPRF.sign  (nprf_sign_cf, phoare = 1%r).

   Reusable asset for R6b (the one-sided sigl-table) and R6c (the V-side on-
   demand HT sign).  The signer is deterministic (grindC total, no sampling --
   WOTS_C_Scheme.ec:41), so `res = <closed form>` holds unconditionally on the
   inputs (total `nth witness` throughout -- confirmed GPT-5.6 + Kimi K3 review
   2026-07-21).  The d-layer closed form is the +C analogue of MM45's
   SPHINCS_PLUS.ec:3741-3769 sigl-table body: `.1` = (sigWOTS, ground counter)
   with encode_msgWOTS_C, `.2` = ap; both resolve to the post-edivz tree/kp
   index (fold asymmetry is representational).  CERTIFIED-0-ADMIT; non-vacuity
   checked by perturbing the layer index j->j+1 (proof then REJECTED).
   ========================================================================== *)
(* Helper 1: pkWOTS_from_skWOTS closed form (len chain-walk loop). *)
lemma pkwots_cf_h (skW : skWOTS) (ps0 : pseed) (ad0 : adrs) :
  hoare[WOTS_TW_ES_NPRF.pkWOTS_from_skWOTS :
        skWOTS = skW /\ ps = ps0 /\ ad = ad0
        ==> DBLL.val res = mkseq (fun (v : int) =>
              cf ps0 (set_chidx ad0 v) 0 (w - 1) (DigestBlock.val (nth witness (DBLL.val skW) v))) len].
proof.
proc.
while (ps = ps0 /\ ad = ad0 /\ skWOTS = skW
       /\ pkWOTS = mkseq (fun (v : int) =>
            cf ps0 (set_chidx ad0 v) 0 (w - 1) (DigestBlock.val (nth witness (DBLL.val skW) v))) (size pkWOTS)
       /\ 0 <= size pkWOTS <= len).
+ wp; skip => /> &hr eqpk ge0 _ ltlen.
  rewrite size_rcons {1}eqpk mkseqS 1:size_ge0 /=.
  smt(size_rcons size_ge0).
wp; skip => /> *.
split; 1: by rewrite mkseq0 /=; smt(ge2_len).
move => pkw *.
have pkwE : pkw = mkseq (fun (v : int) =>
     cf ps0 (set_chidx ad0 v) 0 (w - 1) (DigestBlock.val (nth witness (DBLL.val skW) v))) len by smt().
rewrite pkwE; apply DBLL.insubdK; rewrite size_mkseq; smt(ge2_len).
qed.

(* Helper 3: WOTS_C_ES.sign closed form (sig chain-walk loop) + counter. *)
lemma wotsc_sign_cf_h (skW : skWOTS) (ps0 : pseed) (ad0 : adrs) (mm : msgWOTS) :
  hoare[WOTS_C_ES.sign :
        sk = (skW, ps0, ad0) /\ m = mm
        ==> res.`2 = grindC ps0 ad0 mm
         /\ DBLL.val res.`1 = mkseq (fun (v : int) =>
              cf ps0 (set_chidx ad0 v) 0
                (BaseW.val (encode_msgWOTS_C ps0 ad0 mm (grindC ps0 ad0 mm)).[v])
                (DigestBlock.val (nth witness (DBLL.val skW) v))) len].
proof.
proc.
while (ps = ps0 /\ ad = ad0 /\ skWOTS = skW /\ counter = grindC ps0 ad0 mm
       /\ em = encode_msgWOTS_C ps0 ad0 mm (grindC ps0 ad0 mm)
       /\ sig = mkseq (fun (v : int) =>
            cf ps0 (set_chidx ad0 v) 0 (BaseW.val (encode_msgWOTS_C ps0 ad0 mm (grindC ps0 ad0 mm)).[v])
              (DigestBlock.val (nth witness (DBLL.val skW) v))) (size sig)
       /\ 0 <= size sig <= len).
+ wp; skip => /> &hr eqsig ge0 _ ltlen.
  rewrite size_rcons {1}eqsig mkseqS 1:size_ge0 /=.
  smt(size_rcons size_ge0).
wp; skip => /> *.
split; 1: by rewrite mkseq0 /=; smt(ge2_len).
move => sig *.
have sigE : sig = mkseq (fun (v : int) =>
     cf ps0 (set_chidx ad0 v) 0 (BaseW.val (encode_msgWOTS_C ps0 ad0 mm (grindC ps0 ad0 mm)).[v])
       (DigestBlock.val (nth witness (DBLL.val skW) v))) len by smt().
rewrite sigE; apply DBLL.insubdK; rewrite size_mkseq; smt(ge2_len).
qed.

(* Helper 2: leaves_from_sklpsad closed form (l'-loop, calls helper 1). *)
lemma leaves_cf_h (skWl : skWOTS list) (ps0 : pseed) (ad0 : adrs) :
  hoare[FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad :
        skWOTSl = skWl /\ ps = ps0 /\ ad = ad0
        ==> res = mkseq (fun (u : int) =>
              pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
                   (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                       cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                          (DigestBlock.val (nth witness (DBLL.val (nth witness skWl u)) v))) len)))) l'].
proof.
proc.
while (ps = ps0 /\ ad = ad0 /\ skWOTSl = skWl
       /\ leaves = mkseq (fun (u : int) =>
              pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
                   (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                       cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                          (DigestBlock.val (nth witness (DBLL.val (nth witness skWl u)) v))) len)))) (size leaves)
       /\ 0 <= size leaves <= l').
+ wp.
  exists* leaves; elim* => lvs.
  call (pkwots_cf_h (nth witness skWl (size lvs)) ps0 (set_kpidx (set_typeidx ad0 chtype) (size lvs))).
  wp; skip => /> eqlvs ge0 lelp guard result valpk.
  rewrite size_rcons {1}eqlvs mkseqS 1:size_ge0 /=.
  split; last by smt().
  by congr; rewrite valpk.
wp; skip => /> *.
split; 1: by rewrite mkseq0 /=; smt(ge2_lp).
move => lvs *.
have lvsE : lvs = mkseq (fun (u : int) =>
     pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
          (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
              cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                 (DigestBlock.val (nth witness (DBLL.val (nth witness skWl u)) v))) len)))) l' by smt().
by rewrite lvsE.
qed.

(* ---- closed-form ops for the +C hypertree signer ---- *)
op fidx (idx0 : index) (j : int) : int * int =
  fold (fun (ijs : int * int) => edivz ijs.`1 l') (Index.val idx0, 0) j.

op tree_leaves (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (lyr tr : int) : dgstblock list =
  mkseq (fun (u : int) =>
    pkco ps0 (set_kpidx (set_typeidx (set_ltidx ad0 lyr tr) pkcotype) u)
         (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
             cf ps0 (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 lyr tr) chtype) u) v) 0 (w - 1)
                (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd0 lyr) tr) u)) v))) len)))) l'.

op tree_root (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (lyr tr : int) : dgstblock =
  val_bt_trh ps0 (set_typeidx (set_ltidx ad0 lyr tr) trhxtype) (list2tree (tree_leaves skWOTStd0 ps0 ad0 lyr tr)).

op rt_cf (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (m0 : msgFLSLXMSSMTTW) (idx0 : index) (j : int) : msgFLSLXMSSMTTW =
  if j = 0 then m0 else tree_root skWOTStd0 ps0 ad0 (j - 1) (fidx idx0 j).`1.

op sig_cf_elem (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (m0 : msgFLSLXMSSMTTW) (idx0 : index) (j : int) : sigWOTS * cntr =
  let ti = (fidx idx0 j).`1 in
  let rt = rt_cf skWOTStd0 ps0 ad0 m0 idx0 j in
  let chad = set_kpidx (set_typeidx (set_ltidx ad0 j (ti %/ l')) chtype) (ti %% l') in
  (DBLL.insubd (mkseq (fun (v : int) =>
      cf ps0 (set_chidx chad v) 0 (BaseW.val (encode_msgWOTS_C ps0 chad rt (grindC ps0 chad rt)).[v])
         (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd0 j) (ti %/ l')) (ti %% l'))) v))) len),
   grindC ps0 chad rt).

op ap_cf_elem (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (idx0 : index) (j : int) : apFLXMSSTW =
  let ti = (fidx idx0 (j + 1)).`1 in
  let ki = (fidx idx0 (j + 1)).`2 in
  cons_ap_trh ps0 (set_typeidx (set_ltidx ad0 j ti) trhxtype) (list2tree (tree_leaves skWOTStd0 ps0 ad0 j ti)) ki.

lemma nprf_sign_cf_h (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs)
                     (m0 : msgFLSLXMSSMTTW) (idx0 : index) :
  hoare[FL_SL_XMSS_MT_C_ES_NPRF.sign :
        sk = (skWOTStd0, ps0, ad0) /\ m = m0 /\ idx = idx0
        ==> size res = d
         /\ (forall (j : int), 0 <= j < d =>
              nth witness res j
              = (sig_cf_elem skWOTStd0 ps0 ad0 m0 idx0 j, ap_cf_elem skWOTStd0 ps0 ad0 idx0 j))].
proof.
proc.
sp.
while (   ps = ps0 /\ ad = ad0 /\ skWOTStd = skWOTStd0
       /\ 0 <= size sapl <= d
       /\ (size sapl < d => tidx = (fidx idx0 (size sapl)).`1)
       /\ root = rt_cf skWOTStd0 ps0 ad0 m0 idx0 (size sapl)
       /\ (forall (j : int), 0 <= j < size sapl =>
            nth witness sapl j
            = (sig_cf_elem skWOTStd0 ps0 ad0 m0 idx0 j, ap_cf_elem skWOTStd0 ps0 ad0 idx0 j))).
+ sp 3.
  wp.
  exists* skWOTSlp, skWOTS, sapl, tidx, kpidx, root.
  elim* => slp0 skw0 sapl0 ti0 ki0 rt0.
  move => tidxlh.
  call (leaves_cf_h slp0 ps0 (set_ltidx ad0 (size sapl0) ti0)).
  call (wotsc_sign_cf_h skw0 ps0 (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0) rt0).
  skip => /> edivzE ge0 led fidxlh saplINV guard result r2E r1E.
  have tidxlhE : tidxlh = (fidx idx0 (size sapl0)).`1 by apply fidxlh.
  have [tdivE tmodE] : ti0 = tidxlh %/ l' /\ ki0 = tidxlh %% l'.
  + by move: edivzE; rewrite /edivz; smt(ge2_lp).
  have fidxS1 : fidx idx0 (size sapl0 + 1) = (ti0, ki0).
  + rewrite (: fidx idx0 (size sapl0 + 1) = edivz (fidx idx0 (size sapl0)).`1 l').
    - by rewrite /fidx foldS 1:size_ge0 /=.
    by rewrite -tidxlhE -edivzE.
  have r1E' : result.`1 = DBLL.insubd (mkseq (fun (v : int) =>
       cf ps0 (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0) v) 0
         (BaseW.val (encode_msgWOTS_C ps0 (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0)
                       (rt_cf skWOTStd0 ps0 ad0 m0 idx0 (size sapl0))
                       (grindC ps0 (set_kpidx (set_typeidx (set_ltidx ad0 (size sapl0) ti0) chtype) ki0)
                          (rt_cf skWOTStd0 ps0 ad0 m0 idx0 (size sapl0)))).[v])
         (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd0 (size sapl0)) ti0) ki0)) v))) len).
  + by rewrite -r1E DBLL.valKd.
  rewrite size_rcons.
  split; 1: smt(size_ge0).
  split; 1: by rewrite fidxS1.
  split.
  + have szne : (size sapl0 + 1 = 0) = false by smt(size_ge0).
    by rewrite /rt_cf szne /= fidxS1 /= /tree_root /tree_leaves.
  move => j ge0j ltj1.
  rewrite nth_rcons; case (j < size sapl0) => [ltj | /lezNgt gej].
  + by rewrite (saplINV j _) 1:/#.
  rewrite (: j = size sapl0) 1:/# /=.
  split.
  + rewrite r1E' r2E /sig_cf_elem /= -tidxlhE -tdivE -tmodE //.
  by rewrite /ap_cf_elem fidxS1 /= /tree_leaves.
skip => />.
split.
+ rewrite /fidx fold0 /=; smt(ge1_d).
move => sapl0 nlt ge0 led saplINV.
split; 1: smt().
move => j ge0j ltjd.
by rewrite saplINV 1:/#.
qed.

lemma nprf_sign_cf (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs)
                   (m0 : msgFLSLXMSSMTTW) (idx0 : index) :
  phoare[FL_SL_XMSS_MT_C_ES_NPRF.sign :
        sk = (skWOTStd0, ps0, ad0) /\ m = m0 /\ idx = idx0
        ==> size res = d
         /\ (forall (j : int), 0 <= j < d =>
              nth witness res j
              = (sig_cf_elem skWOTStd0 ps0 ad0 m0 idx0 j, ap_cf_elem skWOTStd0 ps0 ad0 idx0 j))] = 1%r.
proof.
conseq nprf_sign_ll (nprf_sign_cf_h skWOTStd0 ps0 ad0 m0 idx0) => //.
qed.

(* ==========================================================================
   (S.3c) R6a-CONSUME ARITHMETIC helper (pkfnt_flatten_val).

   The `nth_flatten` / `sumz` / `take` / edivz identity that turns a
   per-(tree,leaf) pkFORSnt entry into the flat `ml`-index lookup.  Ported from
   MM45 SPHINCS_PLUS.ec:4190-4216 / :4235-4257 (identical arithmetic, fired
   TWICE in R6c: the oracle sigHT-equate and the main-tail freshness map).  Pure
   list/int arithmetic; no module state.
   ========================================================================== *)
lemma pkfnt_flatten_val (pkfnt : FTWES.pkFORS list list) (ix : index) :
  size pkfnt = nr_trees 0 =>
  all ((=) l' \o size) pkfnt =>
  nth witness (nth witness pkfnt (Index.val ix %/ l')) (Index.val ix %% l')
  = nth witness (flatten pkfnt) (Index.val ix).
proof.
move => eqsz allsz.
have hge : 0 <= Index.val ix %/ l' by rewrite divz_ge0; smt(ge2_lp Index.valP).
have hlt : Index.val ix %/ l' < size pkfnt.
+ rewrite eqsz /l' /nr_trees ltz_divLR; 1: smt(ge2_lp).
  by rewrite -exprD_nneg /= 1:mulr_ge0; smt(ge1_hp ge1_d Index.valP).
have hszrow : size (nth witness pkfnt (Index.val ix %/ l')) = l'.
+ have := all_nthP ((=) l' \o size) pkfnt witness.
  rewrite allsz /= => /(_ (Index.val ix %/ l') _); 1: smt().
  by rewrite /(\o) => <-.
rewrite eq_sym.
have {1}->:
  Index.val ix = sumz (map size (take (Index.val ix %/ l') pkfnt)) + Index.val ix %% l'.
+ rewrite StdBigop.Bigint.sumzE StdBigop.Bigint.BIA.big_mapT /(\o).
  rewrite (StdBigop.Bigint.BIA.eq_big_seq _ (fun _ => l')) => [pkflp /mem_take pkfin /=|].
  - by move/allP: allsz => /(_ pkflp pkfin) @/(\o) -> //.
  rewrite StdBigop.Bigint.big_constz count_predT /= size_take.
  - by rewrite divz_ge0; smt(ge2_lp Index.valP).
  by rewrite hlt /= mulrC -divz_eq.
rewrite (nth_flatten witness); 1: smt().
+ by rewrite hszrow modz_ge0 /= 2:ltz_pmod; smt(ge2_lp).
done.
qed.

(* ==========================================================================
   (S.3d) CLOSED-FORM of the +C FORS public-key recompute (genpkfors_cf_h).

   Characterises FL_FORS_ES_NPRF.gen_pkFORS (deterministic -- pure f/val_bt_trh/
   trco walk) as the SAME trco-of-roots closed form the seq-5-4 oinv commits for
   `R_top_C.pkFORSnt`.  Used ONE-SIDED (call{1}) at BOTH R6c consume sites (the
   oracle sigHT-equate and the main-tail freshness map): once the address is the
   per-(tidx,kpidx) FORS address, this closed form + the oinv trco relation give
   `gen_pkFORS(skFORSnt[tidx][kpidx]) = pkFORSnt[tidx][kpidx]`.  Mirrors
   leaves_cf_h / nprf_sign_cf_h structure.
   ========================================================================== *)
lemma genleaves_cf_h (idxt0 : int) (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) :
  hoare[FTWES.FL_FORS_ES_NPRF.gen_leaves_single_tree :
        idxt = idxt0 /\ skFORS = skF /\ ps = ps0 /\ ad = ad0
        ==> res = mkseq (fun (i : int) =>
                    f ps0 (set_thtbidx ad0 0 (idxt0 * t + i))
                      (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skF) idxt0) i))) t].
proof.
proc.
while (   idxt = idxt0 /\ skFORS = skF /\ ps = ps0 /\ ad = ad0
       /\ leaves = mkseq (fun (i : int) =>
             f ps0 (set_thtbidx ad0 0 (idxt0 * t + i))
               (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skF) idxt0) i))) (size leaves)
       /\ 0 <= size leaves <= t).
+ wp; skip => /> &hr eqlvs ge0 _ ltt.
  rewrite size_rcons {1}eqlvs mkseqS 1:size_ge0 /=.
  by rewrite -/t; smt(size_rcons size_ge0).
wp; skip => /> *.
split; 1: by rewrite mkseq0 /=; smt(ge2_t).
move => lvs *.
have lvsE : lvs = mkseq (fun (i : int) =>
     f ps0 (set_thtbidx ad0 0 (idxt0 * t + i))
       (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skF) idxt0) i))) t by smt().
by rewrite lvsE.
qed.

lemma genpkfors_cf_h (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) :
  hoare[FTWES.FL_FORS_ES_NPRF.gen_pkFORS :
        skFORS = skF /\ ps = ps0 /\ ad = ad0
        ==> res = trco ps0 (set_kpidx (set_typeidx ad0 trcotype) (FTWES.get_kpidx ad0))
                    (flatten (map DigestBlock.val
                       (mkseq (fun (u : int) =>
                          FTWES.val_bt_trh ps0 ad0
                            (list2tree (mkseq (fun (v : int) =>
                               f ps0 (set_thtbidx ad0 0 (u * t + v))
                                 (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skF) u) v))) t)) u) k)))].
proof.
proc.
wp.
while (   skFORS = skF /\ ps = ps0 /\ ad = ad0
       /\ roots = mkseq (fun (u : int) =>
             FTWES.val_bt_trh ps0 ad0
               (list2tree (mkseq (fun (v : int) =>
                  f ps0 (set_thtbidx ad0 0 (u * t + v))
                    (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skF) u) v))) t)) u) (size roots)
       /\ 0 <= size roots <= k).
+ wp.
  exists* roots; elim* => rts0.
  call (genleaves_cf_h (size rts0) skF ps0 ad0).
  wp; skip => /> eqrts ge0 lek guard.
  rewrite size_rcons mkseqS 1:size_ge0 /=.
  rewrite -eqrts /=.
  smt().
wp; skip => /> *.
split; 1: by rewrite mkseq0 /=; smt(ge1_k).
move => rts hnlt hrts hge hle.
have szk : size rts = k by smt().
by rewrite {1}hrts szk.
qed.

(* Losslessness of the (deterministic) NPRF FORS pk recompute -- so genpkfors_cf_h
   can be lifted to a phoare = 1%r usable as a one-sided `call{1}`. *)
lemma genleaves_ll : islossless FTWES.FL_FORS_ES_NPRF.gen_leaves_single_tree.
proof.
proc; while (true) (t - size leaves).
+ move => z; auto; smt(size_rcons).
by auto; smt().
qed.

lemma genpkfors_ll : islossless FTWES.FL_FORS_ES_NPRF.gen_pkFORS.
proof.
proc; wp; while (true) (k - size roots).
+ move => z; wp; call genleaves_ll; auto; smt(size_rcons).
by auto; smt().
qed.

lemma genpkfors_cf (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) :
  phoare[FTWES.FL_FORS_ES_NPRF.gen_pkFORS :
        skFORS = skF /\ ps = ps0 /\ ad = ad0
        ==> res = trco ps0 (set_kpidx (set_typeidx ad0 trcotype) (FTWES.get_kpidx ad0))
                    (flatten (map DigestBlock.val
                       (mkseq (fun (u : int) =>
                          FTWES.val_bt_trh ps0 ad0
                            (list2tree (mkseq (fun (v : int) =>
                               f ps0 (set_thtbidx ad0 0 (u * t + v))
                                 (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skF) u) v))) t)) u) k)))] = 1%r.
proof. conseq genpkfors_ll (genpkfors_cf_h skF ps0 ad0) => //. qed.

(* ==========================================================================
   (S.3f) R6a-CONSUME (genpkfors_flatten).

   The shared core fired at BOTH R6c consume sites: the genpkfors_cf output form
   (at the per-idx FORS address, over the committed skFORSnt entry) EQUALS the flat
   `ml`-index lookup `nth (flatten pkFORSnt) (val idx)`.  Three steps: (a) the FORS
   trco address collapses `get_kpidx (set_kpidx ..) = kpidx` via `getsettrhf_kpidx`
   (MM45 :4218-4270 discharge, adz-instantiated); (b) match the seq-5-4 pkFORSnt<->
   trco commitment at (val idx %/ l', val idx %% l'); (c) `pkfnt_flatten_val`.
   ========================================================================== *)
lemma genpkfors_flatten (skfnt : FTWES.skFORS list list) (pkfnt : FTWES.pkFORS list list)
                        (psv : pseed) (ix : index) :
  size pkfnt = nr_trees 0 =>
  all ((=) l' \o size) pkfnt =>
  (forall (i j : int),
     0 <= i < nr_trees 0 => 0 <= j < l' =>
     nth witness (nth witness pkfnt i) j
     =
     trco psv (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) trcotype) j)
          (flatten (map DigestBlock.val
             (mkseq (fun (u : int) =>
                     FTWES.val_bt_trh psv (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)
                                      (list2tree (mkseq (fun (v : int) =>
                                          f psv (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v))
                                                   (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness skfnt i) j)) u) v))) t)) u) k)))) =>
  trco psv (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (Index.val ix %/ l')) (Index.val ix %% l')) trcotype)
            (FTWES.get_kpidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (Index.val ix %/ l')) (Index.val ix %% l'))))
       (flatten (map DigestBlock.val
          (mkseq (fun (u : int) =>
                  FTWES.val_bt_trh psv (set_kpidx (set_tidx (set_typeidx adz trhftype) (Index.val ix %/ l')) (Index.val ix %% l'))
                                   (list2tree (mkseq (fun (v : int) =>
                                       f psv (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (Index.val ix %/ l')) (Index.val ix %% l')) 0 (u * t + v))
                                                (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness skfnt (Index.val ix %/ l')) (Index.val ix %% l'))) u) v))) t)) u) k)))
  = nth witness (flatten pkfnt) (Index.val ix).
proof.
move => szpk allpk trcoINV.
have hj : 0 <= Index.val ix %% l' < l' by smt(ge2_lp Index.valP).
have hi : 0 <= Index.val ix %/ l' < nr_trees 0.
+ split; 1: by rewrite divz_ge0; smt(ge2_lp Index.valP).
  rewrite /nr_trees /l' ltz_divLR; 1: smt(ge2_lp).
  by rewrite -exprD_nneg /= 1:mulr_ge0; smt(ge1_hp ge1_d Index.valP).
have hgk :
  FTWES.get_kpidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (Index.val ix %/ l')) (Index.val ix %% l'))
  = Index.val ix %% l'.
+ apply getsettrhf_kpidx.
  - by rewrite /valid_tidx valadz /=; smt(ge1_hp ge1_d IntOrder.expr_gt0).
  - by rewrite valadz.
  - by move: hi; rewrite /valid_tidx.
  by move: hj; rewrite /valid_kpidx.
rewrite hgk -(trcoINV (Index.val ix %/ l') (Index.val ix %% l') hi hj).
exact (pkfnt_flatten_val pkfnt ix szpk allpk).
qed.

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
   keygenC_eq).

   UPDATE 2026-07-21 (wave 2): R6b (the +C sigl-table) is now PROVEN.  The `seq
   1 2` below freezes the table one-sidedly via the RHS sign loop (a `while{2}`
   whose body is discharged by the proven `nprf_sign_cf` phoare = 1%r -- the
   `= 1%r` bundles the RHS-loop losslessness MM45 gets from HT-sign_ll).

   UPDATE 2026-07-21 (wave 3 -- CLOSE): R6c is now PROVEN; **LeqPr_VF_C is
   0-ADMIT** (CERTIFIED: compile=OK admit-tactics=0 axiom-decls=0; forced
   recompile; both non-vacuity canaries REJECTED -- the trailing `false` and the
   flipped freshness conjunct `valid_MFORSC10{1}=is_fresh{2}` both fail).  The
   R6c close uses two genuine +C simplifications over MM45 :3935-4278 (no `mmap`;
   the HT-sign while-loop MM45 :4038-4145 collapses to the proven `nprf_sign_cf`
   closed form) plus these NEW in-file proven assets (all `qed`, no axioms):
     * pkfnt_flatten_val    -- the nth_flatten/sumz/take edivz identity (MM45 :4190-4216);
     * genleaves_cf_h / genpkfors_cf_h / genpkfors_cf -- gen_pkFORS closed form (+ _ll);
     * genpkfors_flatten    -- R6a-CONSUME: genpkfors_cf output at idx = nth(flatten pkFORSnt)(val idx),
                               via getsettrhf_kpidx (get_kpidx(set_kpidx..)=kpidx, adz) + pkfnt_flatten_val.
   The oracle coupling (`seq 5 4` forge/prefix split + `seq 5 5` in the oracle
   body) carries the mmap-free relational invariant and matches V's on-demand
   sign to the precomputed RV sigl via genpkfors_flatten + `Index.valKd`.  The
   `seq 5 4`/`seq 1 2` numbering below reflects the older wave; the live proof
   is the `seq 0 4` + `seq 5 4` forge-split + backward tail.  Structural provenance
   note preserved below for history; no `admit` remains.

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
+ inline{2} 2.
  inline{2} 1.
  wp.
  exists* ps{2}, ad{2}; elim* => psv adv.
  call (keygenC_eq2 psv adv).
  wp => /=.
  while (   EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} = R_top_C.skFORSnt{2}
         /\ R_top_C.ad{2} = adz
         /\ TRHC.O_THFC_Default.pp{2} = ps{2}
         /\ (forall (i j : int),
              0 <= i < size R_top_C.pkFORSnt{2} => 0 <= j < l' =>
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
         /\ size R_top_C.pkFORSnt{2} <= nr_trees 0
         /\ all ((=) l' \o size) R_top_C.pkFORSnt{2}
         /\ size R_top_C.pkFORSnt{2} = size R_top_C.skFORSnt{2}).
  - wp => /=.
    while (   ={skFORSlp}
           /\ R_top_C.ad{2} = adz
           /\ TRHC.O_THFC_Default.pp{2} = ps{2}
           /\ (forall (j : int),
              0 <= j < size pkFORSlp{2} =>
              let rts 
                  = 
                  mkseq (fun (u : int) => 
                          FTWES.val_bt_trh ps{2} ((set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_top_C.pkFORSnt{2})) j))
                                           (list2tree (mkseq (fun (v : int) => 
                                                         f ps{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_top_C.pkFORSnt{2})) j) 0 (u * t + v)) 
                                                                  (val (nth witness (nth witness (val (nth witness skFORSlp{2} j)) u) v))) t)) u) k in
                nth witness pkFORSlp{2} j
                =
                trco ps{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_top_C.pkFORSnt{2})) j) trcotype) j) 
                     (flatten (map DigestBlock.val rts)))
           /\ size R_top_C.pkFORSnt{2} < nr_trees 0
           /\ size pkFORSlp{2} <= l'
           /\ size R_top_C.pkFORSnt{2} = size R_top_C.skFORSnt{2}
           /\ size pkFORSlp{2} = size skFORSlp{2}).
    * inline{2} 4.
      wp => /=.
      while (   skFORScube{1} = skFORScube{2}
             /\ R_top_C.ad{2} = adz
             /\ TRHC.O_THFC_Default.pp{2} = ps{2}
             /\ roots{2}
                = 
                mkseq (fun (u : int) => 
                        FTWES.val_bt_trh ps{2} ((set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_top_C.pkFORSnt{2})) (size pkFORSlp{2})))
                                         (list2tree (mkseq (fun (v : int) => 
                                                       f ps{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_top_C.pkFORSnt{2})) (size pkFORSlp{2})) 0 (u * t + v)) 
                                                                (val (nth witness (nth witness skFORScube{2} u) v))) t)) u) (size roots{2})
             /\ all (fun (ls : dgstblock list) => size ls = t) skFORScube{2}
             /\ size R_top_C.pkFORSnt{2} < nr_trees 0
             /\ size pkFORSlp{2} < l'
             /\ size roots{2} <= k
             /\ size R_top_C.pkFORSnt{2} = size R_top_C.skFORSnt{2}
             /\ size pkFORSlp{2} = size skFORSlp{2}
             /\ size roots{2} = size skFORScube{2}).
      + wp => /=.
        while{2} (   R_top_C.ad{2} = adz
                  /\ TRHC.O_THFC_Default.pp{2} = ps{2}
                  /\ (forall (i j : int), 0 <= i < size nodes{2} => 0 <= j < nr_nodesf (i + 1) =>
                        nth witness (nth witness nodes{2} i) j
                        =
                        let leavesp = take (2 ^ (i + 1)) (drop (j * (2 ^ (i + 1))) leaves{2}) in
                          FTWES.val_bt_trh_gen ps{2} (set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_top_C.pkFORSnt{2})) (size pkFORSlp{2})) 
                                               (list2tree leavesp) (i + 1) (size skFORScube{2} * nr_nodesf (i + 1) + j))
                  /\ size leaves{2} = t 
                  /\ size nodes{2} <= a
                  /\ size R_top_C.pkFORSnt{2} = size R_top_C.skFORSnt{2}
                  /\ size pkFORSlp{2} = size skFORSlp{2})
                 (a - size nodes{2}).
        - move=> ? z.
          wp => /=.
          while (   R_top_C.ad = adz
                 /\ TRHC.O_THFC_Default.pp = ps
                 /\ nodespl = last leaves nodes
                 /\ (forall (i j : int), 0 <= i < size nodes => 0 <= j < nr_nodesf (i + 1) =>
                        nth witness (nth witness nodes i) j
                        =
                        let leavesp = take (2 ^ (i + 1)) (drop (j * (2 ^ (i + 1))) leaves) in
                          FTWES.val_bt_trh_gen ps (set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_top_C.pkFORSnt)) (size pkFORSlp)) (list2tree leavesp) (i + 1) (size skFORScube * nr_nodesf (i + 1) + j))
                 /\ (forall (j : int), 0 <= j < size nodescl =>
                       nth witness nodescl j
                       =
                       let leavesp = take (2 ^ (size nodes + 1)) (drop (j * (2 ^ (size nodes + 1))) leaves) in 
                          FTWES.val_bt_trh_gen ps (set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_top_C.pkFORSnt)) (size pkFORSlp)) (list2tree leavesp) (size nodes + 1) (size skFORScube * nr_nodesf (size nodes + 1) + j))                  
                 /\ size leaves = t
                 /\ size nodes < a
                 /\ size R_top_C.pkFORSnt = size R_top_C.skFORSnt
                 /\ size pkFORSlp = size skFORSlp)
                (nr_nodesf (size nodes + 1) - size nodescl).
          * move=> z'.
            inline 3.
            wp; skip => /> &2 nthnds nthndscl eqt_szlfs lta_sznds eqszpksknt eqszpksklp ltnrn_szndscl.
            split => [j|]; 2: by smt(size_rcons).
            rewrite ?nth_rcons ?size_rcons => ge0_j ltsznds1_j.
            case (j < size nodescl{2}) => [?| /lezNgt geszj]; 1: by rewrite nthndscl.
            have eqszj : j = size nodescl{2} by smt(size_rcons).
            rewrite eqszj /= size_cat ?valP /= (: 2 ^ (size nodes{2} + 1) = 2 ^ (size nodes{2}) + 2 ^ (size nodes{2})).
            + by rewrite exprD_nneg 1:size_ge0 //= expr1 /#.
            rewrite take_take_drop_cat 1,2:IntOrder.expr_ge0 //=.
            rewrite drop_drop 1:IntOrder.expr_ge0 //= 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:IntOrder.expr_ge0 //=.
            have ge1_2aszn2szncl : 1 <= 2 ^ (a - size nodes{2}) - 2 * size nodescl{2} - 1.
            + rewrite 2!IntOrder.ler_subr_addr /=.
              rewrite &(IntOrder.ler_trans (2 + 2 * (nr_nodesf (size nodes{2} + 1) - 1))) 1:/#.
              by rewrite /nr_nodesf mulzDr /= -{1}(expr1 2) -exprD_nneg // /#.
            rewrite -nth_last (list2treeS (size nodes{2})) 1:size_ge0.
            + rewrite size_take 1:IntOrder.expr_ge0 1:// size_drop 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:IntOrder.expr_ge0 //.
              rewrite eqt_szlfs /t (: 2 ^ a = 2 ^ (a - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
              pose szn2 := 2 ^ (size nodes{2}). 
              rewrite (: 2 ^ (a - size nodes{2}) * szn2 - size nodescl{2} * (szn2 + szn2) = (2 ^ (a - size nodes{2}) - 2 * size nodescl{2}) * szn2) 1:/#.
              pose mx := max _ _; rewrite (: 2 ^ (size nodes{2}) < mx) // /mx.
              pose sb := ((_ - _ * _) * _)%Int; rewrite &(IntOrder.ltr_le_trans sb) /sb 2:maxrr.
              by rewrite ltr_pmull 1:IntOrder.expr_gt0 // /#.
            + rewrite size_take 1:IntOrder.expr_ge0 1:// size_drop 1:addr_ge0 1:IntOrder.expr_ge0 // 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:IntOrder.expr_ge0 //.
              rewrite eqt_szlfs /t (: 2 ^ a = 2 ^ (a - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
              pose szn2 := 2 ^ (size nodes{2}). 
              rewrite (: 2 ^ (a - size nodes{2}) * szn2 - (szn2 + size nodescl{2} * (szn2 + szn2)) = (2 ^ (a - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) 1:/#.
              pose sb := ((_ - _ - _) * _)%Int.
              move: ge1_2aszn2szncl; rewrite lez_eqVlt => -[eq1_2as | gt1_2as].
              - by rewrite /sb -eq1_2as /= lez_maxr 1:IntOrder.expr_ge0.
              rewrite lez_maxr /sb 1:mulr_ge0 2:IntOrder.expr_ge0 //= 1:subr_ge0 1:ler_subr_addr.
              - rewrite &(IntOrder.ler_trans (1 + 2 * (nr_nodesf (size nodes{2} + 1) - 1))) 1:/#.
                by rewrite /nr_nodesf mulzDr -{1}(expr1 2) -exprD_nneg // /#.
              rewrite (: szn2 < (2 ^ (a - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) //.    
              by rewrite ltr_pmull 1:IntOrder.expr_gt0.
            rewrite /= /val_bt_trh_gen /trhi /trh /updhbidx /=; congr => [/# | /# |].
            case (size nodes{2} = 0) => [eq0_sz | neq0_sz].
            + rewrite eq0_sz ?expr0 /= (nth_out leaves{2}); 1: smt(size_ge0). 
              rewrite {4 8}(: 1 = 0 + 1) 1:// ?(take_nth witness) 1,2:size_drop //; 1..4:smt(size_ge0).
              by rewrite ?take0 /= ?list2tree1 /= ?nth_drop //; smt(size_ge0).
            rewrite (nth_change_dfl witness leaves{2}); 1: smt(size_ge0).
            rewrite ?nthnds /=; 1,3: smt(size_ge0).
            + split => [| _ @/nr_nodesf]; 1: smt(size_ge0).
              rewrite &(IntOrder.ltr_le_trans (nr_nodesf (size nodes{2}))) /nr_nodesf //.
              rewrite (: 2 ^ (a - size nodes{2}) = 2 * 2 ^ (a - (size nodes{2} + 1))) 2:/#.
              by rewrite -{2}(expr1 2) -exprD_nneg // /#.
            + split => [| _ @/nr_nodesf]; 1: smt(size_ge0).
              rewrite &(IntOrder.ltr_le_trans (nr_nodesf (size nodes{2}))) /nr_nodesf //.
              rewrite (: 2 ^ (a - size nodes{2}) = 2 * 2 ^ (a - (size nodes{2} + 1))) 2:/#.
              by rewrite -{2}(expr1 2) -exprD_nneg // /#.  
            rewrite /= /val_bt_trh_gen /trhi /trh /updhbidx /=; do 3! congr; 1,3: smt().
            + congr; rewrite mulzDr; congr; rewrite eq_sym {1}(mulrC (size skFORScube{2})) -mulzA.
              by rewrite /nr_nodesf -{1}(expr1 2) -exprD_nneg // /#.
            congr; rewrite mulzDr eq_sym -addzA; congr; rewrite {1}(mulrC (size skFORScube{2})) -mulzA.
            by rewrite /nr_nodesf -{1}(expr1 2) -exprD_nneg // /#.
          wp; skip => /> &2 nthnds eqt_szlfs _ eqszpksknt eqszpksklp lta_sznds.
          split => [/# | ndscl].
          split => [/# | /lezNgt gent1_szndscl nthndscl].
          rewrite -andbA; split => [i j |]; 2: smt(size_rcons).
          rewrite ?nth_rcons ?size_rcons => ge0_i ltsz1_i ge0_j ltnt1_j.
          case (i < size nodes{2}) => ?; 1: by rewrite nthnds.
          have eqiszn : i = size nodes{2} by smt(size_rcons).
          by rewrite eqiszn /= nthndscl /#.
        wp => /=.
        while (   ={skFORSet}
               /\ R_top_C.ad{2} = adz
               /\ TRHC.O_THFC_Default.pp{2} = ps{2}
               /\ leaves{2} 
                  =
                  mkseq (fun (i : int) =>
                           f ps{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_top_C.skFORSnt{2})) (size skFORSlp{2})) 0 (size skFORScube{2} * t + i)) (val (nth witness skFORSet{2} i))) (size leaves{2}) 
               /\ size leaves{2} = size skFORSet{2}
               /\ size R_top_C.skFORSnt{2} < nr_trees 0
               /\ size skFORSlp{2} < l'
               /\ size skFORScube{2} < k
               /\ size skFORSet{2} <= t).
        - inline{2} 2.
          wp; rnd; skip => /> &2 lfsdef eqszlfssk ltnt0_szsk ltlp_szsklp ltk_szsk _ ltt_szsket skele skelein.
          split; 2: smt(size_rcons).
          rewrite size_rcons valP /f mkseqS /=; 1: smt(size_ge0).
          congr; 2: by rewrite nth_rcons /#. 
          rewrite {1}lfsdef &(eq_in_mkseq) => u rng_u /=. 
          by rewrite /f; congr; rewrite nth_rcons /#.      
        wp; skip => /> &2 rtsdef allskfszt ltnt0szpkf ltlpszpkflp _ eqszpksknt eqszpksklp eqszrtsskf ltk_szsk. 
        split => [| lfs sfket /lezNgt getszsket _ lfsdef eqszsklfs _ _ let_szskfet]; 1: by rewrite mkseq0 /=; smt(ge2_t).
        split => [| nds]; 1: smt(ge1_a).
        split => [/#| /lezNgt gea_sznds nthnds eqt_szlfs lea_sznds].
        split; 2: smt(size_rcons cats1 all_cat allP ge1_a).
        rewrite size_rcons mkseqS /=; 1: smt(size_ge0).
        rewrite nthnds /=; 1,2: smt(ge1_a IntOrder.expr_gt0).
        rewrite drop0 -/t -eqt_szlfs take_size //=.
        congr; 1: rewrite {1}rtsdef.
        - rewrite &(eq_in_mkseq) => u rng_u /=.
          do 3! congr => [|/#]; rewrite fun_ext => v.
          rewrite nth_rcons (: u < size skFORScube{2}) 1:/# //=.
          by rewrite eqt_szlfs.
        rewrite /val_bt_trh; congr => [| @/nr_nodesf /=]; 2: by rewrite expr0 /#.
        congr; rewrite {1}lfsdef; congr; rewrite fun_ext => u.
        by rewrite nth_rcons (: ! size roots{2} < size skFORScube{2}) 1:/# eqszrtsskf eqt_szlfs //= /#.
      wp; skip => /> &2 nthpkflp ltnt_szpkfnt _ eqszpksknt eqszpksklp ltlp_szskflp.
      split => [| rts skf /lezNgt gek_szskf _ rtsdef allszt_skf _ lek_szrts eqszrtsskf]; 1: by rewrite mkseq0 /=; smt(ge1_k).
      split => [j |]; 2: smt(size_rcons).
      rewrite ?nth_rcons ?size_rcons -eqszpksklp => *.
      case (j < size pkFORSlp{2}) => [ltszj | nltszj]; 1: by rewrite nthpkflp.
      rewrite (: j = size pkFORSlp{2}) 1:/# /= /trco.
      congr => [| /# |].
      + rewrite size_flatten StdBigop.Bigint.sumzE StdBigop.Bigint.BIA.big_mapT.
        rewrite (StdBigop.Bigint.BIA.eq_big_seq _ (fun _ => 8 * n)).
        - by move=> bs /mapP [x [xin ->]] @/(\o) /=; rewrite valP.
        by rewrite StdBigop.Bigint.big_constz count_predT size_map /#.
      rewrite rtsdef (: size rts = k) 1:/#.
      do 3! congr; rewrite fun_ext => u. 
      do 3! congr; rewrite fun_ext => v. 
      by rewrite insubdK // /#.
    wp; skip => /> &2 nthpkfnt _ allszlp eqszpksknt ltnt_szsknt.
    split => [| pkf skf /lezNgt gelp_szskf _ nthpkflp _ lelp_szpkf eqszpksklp]; 1: smt(ge2_lp).
    split => [i j|]; 2: smt(cats1 all_cat allP size_rcons).
    rewrite ?size_rcons ?nth_rcons -eqszpksknt => *.
    case (i < size R_top_C.pkFORSnt{2}) => [ltszi | nltszi]; 1: by rewrite nthpkfnt.
    rewrite (: i = size R_top_C.pkFORSnt{2}) 1:/# /=.
    by rewrite nthpkflp // /#.
  wp; skip => />.
  split; 1: by smt(IntOrder.expr_ge0 ge1_hp ge1_d).
  move => pkfr skfr geg _ nthpkf lesz allsz eqsz resr eqps eqad _ _.
  have szeq : size pkfr = nr_trees 0 by smt().
  split; last by rewrite szeq.
  move => i j ge0i lti ge0j ltj.
  by rewrite eqps (nthpkf i j) 1:szeq // /#.
(* ---- R6b: freeze the +C sigl-table via the RHS sign loop (one-sided while{2});
   each entry is the proven nprf_sign_cf closed form. ---- *)
seq 1 2 : (#pre
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.qs{1} = []
           /\ size sigl{2} = l
           /\ (forall (i : int), 0 <= i < size sigl{2} =>
                size (nth witness sigl{2} i) = d
                /\ (forall (j : int), 0 <= j < d =>
                     nth witness (nth witness sigl{2} i) j
                     = (sig_cf_elem EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2} ps{2} adz
                          (nth witness ml{2} i) (Index.insubd i) j,
                        ap_cf_elem EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2} ps{2} adz
                          (Index.insubd i) j)))).
+ sp 1 1.
  while{2} (   sk{2}.`2 = ps{2} /\ sk{2}.`3 = adz
            /\ 0 <= size sigl{2} <= l
            /\ (forall (i : int), 0 <= i < size sigl{2} =>
                 size (nth witness sigl{2} i) = d
                 /\ (forall (j : int), 0 <= j < d =>
                      nth witness (nth witness sigl{2} i) j
                      = (sig_cf_elem EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2} ps{2} adz
                           (nth witness ml{2} i) (Index.insubd i) j,
                         ap_cf_elem EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2} ps{2} adz
                           (Index.insubd i) j))))
           (l - size sigl{2}).
  - move=> &m0 z.
    wp.
    exists* sigl, EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd, sk, ml.
    elim* => siglv sktd skv mlv.
    call (nprf_sign_cf sktd skv.`2 skv.`3 (nth witness mlv (size siglv)) (Index.insubd (size siglv))).
    wp; skip => /> sk3E ge0 lel saplINV guard result szres resINV.
    rewrite size_rcons.
    split; last by smt(size_ge0).
    split; 1: smt(size_ge0).
    move => i ge0i lti1.
    rewrite !nth_rcons; case (i < size siglv) => [lti | /lezNgt gei].
    + by move: (saplINV i _); smt().
    have iE : i = size siglv by smt().
    rewrite iE /=; split; 1: exact szres.
    move => j ge0j ltjd.
    by rewrite (resINV j _) 1:/# sk3E.
  skip => /> *.
  split; 1: smt(ge2_l).
  move => *; smt().
(* ==========================================================================
   R6c -- CLOSED (was the last admit; PROVEN 2026-07-21 wave 3).  The `conseq`
   below is the SOUND weakening `is_valid{1} => is_valid{2}` /\
   `(!valid_MFORSC10{1}) = is_fresh{2}` (dropping the +C `good_fors m' mk'` gate
   and top-freshness `!(m'\in qs)`, which only SHRINK res{1}, so the `<=` bound
   is preserved; entailment by `1: smt()`).  Coupling shape:

     LHS (V_C):  (m',sig') <@ A(O_CMA_C).forge; <gen_pkFORS; pkFORS_from_sig;
                 root_from_sigC; is_valid/is_fresh inlined>
     RHS (RV_C): (m',sig',idx') <@ R_top_C.forge(pk,sigl); verify; is_fresh

   The three sub-legs, all now DISCHARGED (map to the proof below):
   (i)  oracle `call (: oinv)` [inside the `seq 5 4` forge/prefix split]:
        V_C.O_CMA_C.sign ~ R_top_C.O_CMA.sign -- single coupled mk `rnd` on the
        SHARED `dcond dmkey (good_fors m)` (NO mmap), then `seq 5 5` couples the
        deterministic prefix + FORS sign, and V's on-demand HT sign (nprf_sign_cf
        closed form) matches `nth sigl (val idx)` (oinv sigl-table) via
        `eq_from_nth` + `Index.valKd` (idx = insubd(val idx)).
   (ii) R6a-CONSUME: `genpkfors_flatten` proves gen_pkFORS(skFORSnt at idx) =
        nth (flatten R_top_C.pkFORSnt) (val idx) via getsettrhf_kpidx + the
        seq-5-4 trco commitment + pkfnt_flatten_val (fires in BOTH the oracle
        sigHT-equate and the final freshness map).
   (iii) final validity/freshness map: `/>` closes is_valid via V.root{1}=pk.`1;
        `(!valid_MFORSC10{1}) = is_fresh{2}` reduces to genpkfors_flatten.
   ========================================================================== *)
conseq (: _ ==>
     (is_valid{1} => is_valid{2})
  /\ (! EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.valid_MFORSC10{1}) = is_fresh{2}); 1: smt().
inline{2} 2.
inline{2} 1.
(* R6c: consume the RHS forge-setup prefix (pk1<-pk; sigl0<-sigl;
   (R_top_C.root,ps,ad)<-pk1; sigFLSLXMSSMTTWCl<-sigl0), re-stating the sigl-table
   over the MODULE vars R_top_C.{sigFLSLXMSSMTTWCl,pkFORSnt,ps} so it can ride the
   oracle `call (: oinv)` invariant.  `ml{2}=flatten pkFORSnt{2}` stays a framed
   local fact for the final freshness map. *)
seq 0 4 : (   ={glob F}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{1} = EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz
           /\ R_top_C.ad{2} = adz
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = R_top_C.ps{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.root{1} = R_top_C.root{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.root{1} = pk{2}.`1
           /\ R_top_C.ps{2} = pk{2}.`2
           /\ pk{2}.`3 = adz
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} = R_top_C.skFORSnt{2}
           /\ ml{2} = flatten R_top_C.pkFORSnt{2}
           /\ (forall (i j : int),
                0 <= i < nr_trees 0 => 0 <= j < l' =>
                let rts
                    =
                    mkseq (fun (u : int) =>
                            FTWES.val_bt_trh R_top_C.ps{2} (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)
                                             (list2tree (mkseq (fun (v : int) =>
                                                 f R_top_C.ps{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v))
                                                          (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness R_top_C.skFORSnt{2} i) j)) u) v))) t)) u) k in
                 nth witness (nth witness R_top_C.pkFORSnt{2} i) j
                 =
                 trco R_top_C.ps{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) trcotype) j)
                      (flatten (map DigestBlock.val rts)))
           /\ size R_top_C.pkFORSnt{2} = nr_trees 0
           /\ all ((=) l' \o size) R_top_C.pkFORSnt{2}
           /\ size R_top_C.sigFLSLXMSSMTTWCl{2} = l
           /\ (forall (i : int), 0 <= i < size R_top_C.sigFLSLXMSSMTTWCl{2} =>
                size (nth witness R_top_C.sigFLSLXMSSMTTWCl{2} i) = d
                /\ (forall (j : int), 0 <= j < d =>
                     nth witness (nth witness R_top_C.sigFLSLXMSSMTTWCl{2} i) j
                     = (sig_cf_elem EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2} R_top_C.ps{2} adz
                          (nth witness (flatten R_top_C.pkFORSnt{2}) i) (Index.insubd i) j,
                        ap_cf_elem EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2} R_top_C.ps{2} adz
                          (Index.insubd i) j)))).
+ auto.
(* --- R6c: forward-couple the forge + deterministic prefix (L1-L5 / R1-R4) so the
   one-sided V gen_pkFORS captures its post-L5 args; then backward-couple the tail.
   The forge `call (: oinv)` carries the mmap-free oracle relational invariant
   (module vars only): sk/ad/ps equalities + the seq-5-4 pkFORSnt<->trco commitment
   + the R6b +C sigl-table over `flatten pkFORSnt`.  --- *)
seq 5 4 : (   EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{1} = EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz
           /\ R_top_C.ad{2} = adz
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = R_top_C.ps{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.root{1} = R_top_C.root{2}
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.root{1} = pk{2}.`1
           /\ R_top_C.ps{2} = pk{2}.`2
           /\ pk{2}.`3 = adz
           /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} = R_top_C.skFORSnt{2}
           /\ ml{2} = flatten R_top_C.pkFORSnt{2}
           /\ (forall (i j : int),
                0 <= i < nr_trees 0 => 0 <= j < l' =>
                let rts
                    =
                    mkseq (fun (u : int) =>
                            FTWES.val_bt_trh R_top_C.ps{2} (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)
                                             (list2tree (mkseq (fun (v : int) =>
                                                 f R_top_C.ps{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v))
                                                          (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness R_top_C.skFORSnt{2} i) j)) u) v))) t)) u) k in
                 nth witness (nth witness R_top_C.pkFORSnt{2} i) j
                 =
                 trco R_top_C.ps{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) trcotype) j)
                      (flatten (map DigestBlock.val rts)))
           /\ size R_top_C.pkFORSnt{2} = nr_trees 0
           /\ all ((=) l' \o size) R_top_C.pkFORSnt{2}
           /\ sigFORSTW'{1} = sigFORSTW'{2}
           /\ sigHT'{1} = sigHT'{2}
           /\ cm{1} = cm'{2}
           /\ idx{1} = idx'0{2}
           /\ tidx{1} = tidx'{2}
           /\ kpidx{1} = kpidx'{2}
           /\ skFORS{1} = nth witness (nth witness R_top_C.skFORSnt{2} tidx{1}) kpidx{1}
           /\ tidx{1} = Index.val idx{1} %/ l'
           /\ kpidx{1} = Index.val idx{1} %% l').
+ wp.
  call (:    EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{1} = EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2}
          /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1} = adz
          /\ R_top_C.ad{2} = adz
          /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1} = R_top_C.ps{2}
          /\ EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skFORSnt{1} = R_top_C.skFORSnt{2}
          /\ (forall (i j : int),
               0 <= i < nr_trees 0 => 0 <= j < l' =>
               let rts
                   =
                   mkseq (fun (u : int) =>
                           FTWES.val_bt_trh R_top_C.ps{2} (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j)
                                            (list2tree (mkseq (fun (v : int) =>
                                                f R_top_C.ps{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v))
                                                         (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness R_top_C.skFORSnt{2} i) j)) u) v))) t)) u) k in
                nth witness (nth witness R_top_C.pkFORSnt{2} i) j
                =
                trco R_top_C.ps{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) trcotype) j)
                     (flatten (map DigestBlock.val rts)))
          /\ size R_top_C.pkFORSnt{2} = nr_trees 0
          /\ all ((=) l' \o size) R_top_C.pkFORSnt{2}
          /\ size R_top_C.sigFLSLXMSSMTTWCl{2} = l
          /\ (forall (i : int), 0 <= i < size R_top_C.sigFLSLXMSSMTTWCl{2} =>
               size (nth witness R_top_C.sigFLSLXMSSMTTWCl{2} i) = d
               /\ (forall (j : int), 0 <= j < d =>
                    nth witness (nth witness R_top_C.sigFLSLXMSSMTTWCl{2} i) j
                    = (sig_cf_elem EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2} R_top_C.ps{2} adz
                         (nth witness (flatten R_top_C.pkFORSnt{2}) i) (Index.insubd i) j,
                       ap_cf_elem EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV.skWOTStd{2} R_top_C.ps{2} adz
                         (Index.insubd i) j)))).
  + proc.
    (* couple mk (single coupled rnd on the shared dcond) + the deterministic
       prefix + the identical FORS sign (lines 1-5 both sides). *)
    seq 5 5 : (   #pre
               /\ ={mk, cm, idx, tidx, kpidx, skFORS, sigFORSTW}
               /\ skFORS{1} = nth witness (nth witness R_top_C.skFORSnt{2} tidx{1}) kpidx{1}
               /\ 0 <= Index.val idx{1} < l
               /\ tidx{1} = Index.val idx{1} %/ l'
               /\ kpidx{1} = Index.val idx{1} %% l').
    + call (: true); 1: by sim.
      wp; rnd; skip => />; smt(Index.valP).
    (* one-side V's gen_pkFORS: pkFORS{1} = committed flat FORS pk (R6a-CONSUME). *)
    seq 1 0 : (#pre /\ pkFORS{1} = nth witness (flatten R_top_C.pkFORSnt{2}) (Index.val idx{1})).
    + exists* skFORS{1}, EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1},
              EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1}, tidx{1}, kpidx{1}.
      elim* => skFv psv adv tiv kiv.
      call{1} (genpkfors_cf skFv psv (set_kpidx (set_tidx (set_typeidx adv trhftype) tiv) kiv)).
      skip => /> &2 trcoINV szpk allpk _ _ _ _.
      exact (genpkfors_flatten R_top_C.skFORSnt{2} R_top_C.pkFORSnt{2} psv idx{2} szpk allpk trcoINV).
    (* V's HT sign (closed form) = R's precomputed sigl[val idx] (sigl-table). *)
    wp.
    exists* EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.skWOTStd{1}, EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1},
            EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1}, pkFORS{1}, idx{1}.
    elim* => skwv psv adv pkfv idxv.
    call{1} (nprf_sign_cf skwv psv adv pkfv idxv).
    skip => /> &2 trcoINV szpk allpk szsigl sigltab ge0 ltl result szres resINV.
    have hlt : 0 <= Index.val idxv < size R_top_C.sigFLSLXMSSMTTWCl{2} by smt().
    have [szsl slINV] := sigltab (Index.val idxv) hlt.
    apply (eq_from_nth witness); first by rewrite szres szsl.
    move => j; rewrite szres => rng_j.
    by rewrite (resINV j rng_j) (slINV j rng_j) Index.valKd.
  skip => />.
(* backward tail: L6..L11 / R5..R14 *)
wp.
call (: true); 1: by sim.                       (* root_from_sigC : L9 ~ R12 *)
wp.
call (: true); 1: by sim.                       (* pkFORS_from_sigFORSTW : L7 ~ R5 *)
exists* skFORS{1}, EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ps{1},
        EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V.ad{1}, tidx{1}, kpidx{1}.
elim* => skFv psv adv tiv kiv.
call{1} (genpkfors_cf skFv psv (set_kpidx (set_tidx (set_typeidx adv trhftype) tiv) kiv)).
(* Final validity/freshness map.  `/>` closes the is_valid leg via V.root{1}=pk.`1;
   the freshness equality reduces to the R6a-CONSUME identity genpkfors_flatten. *)
skip => />.
move => &2 pkad trcoINV szpk allpk result_R.
split; first by rewrite pkad.
move => _.
by rewrite (genpkfors_flatten R_top_C.skFORSnt{2} R_top_C.pkFORSnt{2} pk{2}.`2 idx'0{2} szpk allpk trcoINV).
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

(* ==========================================================================
   (S.5) hop6b CLOSURE MATERIAL  (2026-07-24) -- the member-audit ports at
   A_ht := R_top_C(F) + the FC.O <-> TRHC.O oracle-clone reconciliation.

   PURPOSE.  The capstone's hop6b bridged LeqPr_VF_C's landing
   `Pr[NAGCMA(R_top_C(F), TRHC.O_THFC_Default)]` to the component theorem's
   consumption `Pr[NAGCMA(R_top(F), FC.O_THFC_Default)]`, bundling TWO gaps:
     (a) R_top_C -> R_top  (conditioned vs memoized mk);
     (b) FC.O <-> TRHC.O   (cross-clone oracle).
   The CLEAN closure DISSOLVES (a): the component theorem
   `EUFNAGCMA_FLSLXMSSMTTWCESNPRF` (XmssmtCC_All:8439) is `forall A_ht, ...`, so
   it applies DIRECTLY at A_ht := R_top_C(F).  That needs the four member-audit
   premises at R_top_C(F) -- proven below as VERBATIM PORTS of the R_top versions
   (XmssmtCC_All:9629/10079/10226/10329/10423): R_top_C and R_top have
   BYTE-IDENTICAL `choose` bodies (the `O_CMA.sign` delta -- conditioned-mk vs
   memoized-mk -- is never touched by the choose audit), so each proof ports under
   the single module rename R_top -> R_top_C with NO other change.  Only gap (b)
   then remains, closed by `oracle_clone_hop_C` below.
   ========================================================================== *)

lemma R_top_C_members4 (F <: Adv_EUFCMA_C{-O_THFC_MA, -R_top_C}) :
  hoare[ R_top_C(F, O_THFC_MA).choose :
           O_THFC_MA.tws_ma = [] ==> all in_thfc4 O_THFC_MA.tws_ma ].
proof.
proc.
(* W1: inner trees of the hypertree bottom layer *)
while (all in_thfc4 O_THFC_MA.tws_ma).
+ wp.
  (* W2: FORS-TW instances (leaves of this inner tree) *)
  while (all in_thfc4 O_THFC_MA.tws_ma).
  + wp.
    (* the trco site: compress the k FORS roots into the FORS public key *)
    call (othfcma_query_mem4 (8 * n * k) mem4_trco).
    (* W3: FORS-TW trees of this instance *)
    while (   all in_thfc4 O_THFC_MA.tws_ma
           /\ size roots = size skFORScube
           /\ size skFORScube <= k).
    + wp.
      (* W5: layers of this FORS-TW tree *)
      while (   all in_thfc4 O_THFC_MA.tws_ma
             /\ size roots = size skFORScube
             /\ size skFORScube < k).
      + wp.
        (* W6: nodes of this layer -- the trh site *)
        while (   all in_thfc4 O_THFC_MA.tws_ma
               /\ size roots = size skFORScube
               /\ size skFORScube < k).
        + wp.
          call (othfcma_query_mem4 (8 * n * 2) mem4_trh).
          wp; skip => />; smt(size_trh_input).
        wp; skip => />.
      wp.
      (* W4: leaves of this FORS-TW tree -- the f site *)
      while (   all in_thfc4 O_THFC_MA.tws_ma
             /\ size roots = size skFORScube
             /\ size skFORScube < k).
      + wp.
        call (othfcma_query_mem4 (8 * n) mem4_f).
        wp; rnd; skip => />; smt(DigestBlock.valP).
      wp; skip => />; smt(size_rcons).
    wp; skip => />; smt(ge1_k size_rcons size_trco_input).
  wp; skip => />.
auto => />.
qed.
lemma R_top_C_allnchads (F <: Adv_EUFCMA_C{-FC.O_THFC_Default, -R_top_C}) :
  hoare[ R_top_C(F, FC.O_THFC_Default).choose :
           FC.O_THFC_Default.tws = [] ==>
           all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws ].
proof.
proc.
(* W1: inner trees of the hypertree bottom layer *)
while (   all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws
       /\ R_top_C.ad = adz).
+ wp.
  (* W2: FORS-TW instances (leaves of this inner tree) *)
  while (   all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws
         /\ R_top_C.ad = adz
         /\ 0 <= size R_top_C.skFORSnt < nr_trees 0).
  + wp.
    (* the trco site *)
    call (othfc_fc_query_ntype chtype).
    (* W3: FORS-TW trees of this instance *)
    while (   all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws
           /\ R_top_C.ad = adz
           /\ 0 <= size R_top_C.skFORSnt < nr_trees 0
           /\ 0 <= size skFORSlp < l').
    + wp.
      (* W5: layers of this FORS-TW tree *)
      while (   all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws
             /\ R_top_C.ad = adz
             /\ 0 <= size R_top_C.skFORSnt < nr_trees 0
             /\ 0 <= size skFORSlp < l'
             /\ 0 <= size skFORScube < k).
      + wp.
        (* W6: nodes of this layer -- the trh site *)
        while (   all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws
               /\ R_top_C.ad = adz
               /\ 0 <= size R_top_C.skFORSnt < nr_trees 0
               /\ 0 <= size skFORSlp < l'
               /\ 0 <= size skFORScube < k
               /\ 0 <= size nodes < a).
        + wp.
          call (othfc_fc_query_ntype chtype).
          wp; skip => &hr [#] hall ha hnt0 hnt1 hlp0 hlp1 hcb0 hcb1 hnd0 hnd1 hncl.
          split; last by move=> _ tws htws; rewrite ha /=; smt().
          split; last exact hall.
          rewrite /= ha gettype_site_fors.
          + by rewrite /valid_tidx.
          + by rewrite /valid_kpidx.
          + by rewrite /valid_thfidx; smt(ge1_a).
          + by apply valid_tbfidx_cube; smt(size_ge0).
          by smt(fors_adrstypes_ne).
        wp; skip => />; smt(size_ge0).
      wp.
      (* W4: leaves of this FORS-TW tree -- the f site *)
      while (   all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws
             /\ R_top_C.ad = adz
             /\ 0 <= size R_top_C.skFORSnt < nr_trees 0
             /\ 0 <= size skFORSlp < l'
             /\ 0 <= size skFORScube < k).
      + wp.
        call (othfc_fc_query_ntype chtype).
        wp; rnd; skip => &hr [#] hall ha hnt0 hnt1 hlp0 hlp1 hcb0 hcb1 hset x hx.
        split; last by move=> _ tws htws; rewrite ha /=; smt().
        split; last exact hall.
        rewrite /= ha -nr_nodesf0 gettype_site_fors.
        + by rewrite /valid_tidx.
        + by rewrite /valid_kpidx.
        + by rewrite /valid_thfidx; smt(ge1_a).
        + by apply valid_tbfidx_cube; smt(size_ge0 nr_nodesf0).
        by smt(fors_adrstypes_ne).
      wp; skip => />; smt(size_ge0).
    wp; skip => &hr [#] hall ha hnt0 hnt1 hlp.
    split; first by smt(size_ge0).
    move=> tws roots0 skFORScube0 hgek [#] hall2 ha2 hnt02 hnt12 hlp02 hlp12.
    split; last by move=> _ tws0 htws0; rewrite ha /=; smt().
    split; last exact hall2.
    rewrite /= ha gettype_site_trco.
    + by rewrite /valid_tidx.
    + by rewrite /valid_kpidx.
    + by rewrite /valid_kpidx.
    by smt(fors_adrstypes_ne).
  wp; skip => />; smt(size_ge0 size_rcons).
auto => />.
qed.
lemma R_top_C_allnpkcoads (F <: Adv_EUFCMA_C{-R_SMDTTCRCPKCO_C, -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                       -FSSLXMTWES.PKCOC.O_THFC_Default, -R_top_C}) :
  hoare[ R_top_C(F, R_SMDTTCRCPKCO_C(R_top_C(F), FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                                   FSSLXMTWES.PKCOC.O_THFC_Default).O_THFC).choose :
           R_SMDTTCRCPKCO_C.O_THFC.ads = [] ==>
           all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads ].
proof.
proc.
(* W1: inner trees of the hypertree bottom layer *)
while (   all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads
       /\ R_top_C.ad = adz).
+ wp.
  (* W2: FORS-TW instances (leaves of this inner tree) *)
  while (   all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads
         /\ R_top_C.ad = adz
         /\ 0 <= size R_top_C.skFORSnt < nr_trees 0).
  + wp.
    (* the trco site *)
    call (opkcowrap_query_ntype (R_top_C(F)) pkcotype).
    (* W3: FORS-TW trees of this instance *)
    while (   all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads
           /\ R_top_C.ad = adz
           /\ 0 <= size R_top_C.skFORSnt < nr_trees 0
           /\ 0 <= size skFORSlp < l').
    + wp.
      (* W5: layers of this FORS-TW tree *)
      while (   all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads
             /\ R_top_C.ad = adz
             /\ 0 <= size R_top_C.skFORSnt < nr_trees 0
             /\ 0 <= size skFORSlp < l'
             /\ 0 <= size skFORScube < k).
      + wp.
        (* W6: nodes of this layer -- the trh site *)
        while (   all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads
               /\ R_top_C.ad = adz
               /\ 0 <= size R_top_C.skFORSnt < nr_trees 0
               /\ 0 <= size skFORSlp < l'
               /\ 0 <= size skFORScube < k
               /\ 0 <= size nodes < a).
        + wp.
          call (opkcowrap_query_ntype (R_top_C(F)) pkcotype).
          wp; skip => &hr [#] hall ha hnt0 hnt1 hlp0 hlp1 hcb0 hcb1 hnd0 hnd1 hncl.
          split; last by move=> _ tws htws; rewrite ha /=; smt().
          split; last exact hall.
          rewrite /= ha gettype_site_fors.
          + by rewrite /valid_tidx.
          + by rewrite /valid_kpidx.
          + by rewrite /valid_thfidx; smt(ge1_a).
          + by apply valid_tbfidx_cube; smt(size_ge0).
          by smt(fors_adrstypes_ne).
        wp; skip => />; smt(size_ge0).
      wp.
      (* W4: leaves of this FORS-TW tree -- the f site *)
      while (   all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads
             /\ R_top_C.ad = adz
             /\ 0 <= size R_top_C.skFORSnt < nr_trees 0
             /\ 0 <= size skFORSlp < l'
             /\ 0 <= size skFORScube < k).
      + wp.
        call (opkcowrap_query_ntype (R_top_C(F)) pkcotype).
        wp; rnd; skip => &hr [#] hall ha hnt0 hnt1 hlp0 hlp1 hcb0 hcb1 hset x hx.
        split; last by move=> _ tws htws; rewrite ha /=; smt().
        split; last exact hall.
        rewrite /= ha -nr_nodesf0 gettype_site_fors.
        + by rewrite /valid_tidx.
        + by rewrite /valid_kpidx.
        + by rewrite /valid_thfidx; smt(ge1_a).
        + by apply valid_tbfidx_cube; smt(size_ge0 nr_nodesf0).
        by smt(fors_adrstypes_ne).
      wp; skip => />; smt(size_ge0).
    wp; skip => &hr [#] hall ha hnt0 hnt1 hlp.
    split; first by smt(size_ge0).
    move=> tws roots0 skFORScube0 hgek [#] hall2 ha2 hnt02 hnt12 hlp02 hlp12.
    split; last by move=> _ tws0 htws0; rewrite ha /=; smt().
    split; last exact hall2.
    rewrite /= ha gettype_site_trco.
    + by rewrite /valid_tidx.
    + by rewrite /valid_kpidx.
    + by rewrite /valid_kpidx.
    by smt(fors_adrstypes_ne).
  wp; skip => />; smt(size_ge0 size_rcons).
auto => />.
qed.
lemma R_top_C_allntrhads (F <: Adv_EUFCMA_C{-R_SMDTTCRCTRH_C, -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                       -FSSLXMTWES.TRHC.O_THFC_Default, -R_top_C}) :
  hoare[ R_top_C(F, R_SMDTTCRCTRH_C(R_top_C(F), FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                                  FSSLXMTWES.TRHC.O_THFC_Default).O_THFC).choose :
           R_SMDTTCRCTRH_C.O_THFC.ads = [] ==>
           all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads ].
proof.
proc.
(* W1: inner trees of the hypertree bottom layer *)
while (   all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads
       /\ R_top_C.ad = adz).
+ wp.
  (* W2: FORS-TW instances (leaves of this inner tree) *)
  while (   all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads
         /\ R_top_C.ad = adz
         /\ 0 <= size R_top_C.skFORSnt < nr_trees 0).
  + wp.
    (* the trco site *)
    call (otrhwrap_query_ntype (R_top_C(F)) trhxtype).
    (* W3: FORS-TW trees of this instance *)
    while (   all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads
           /\ R_top_C.ad = adz
           /\ 0 <= size R_top_C.skFORSnt < nr_trees 0
           /\ 0 <= size skFORSlp < l').
    + wp.
      (* W5: layers of this FORS-TW tree *)
      while (   all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads
             /\ R_top_C.ad = adz
             /\ 0 <= size R_top_C.skFORSnt < nr_trees 0
             /\ 0 <= size skFORSlp < l'
             /\ 0 <= size skFORScube < k).
      + wp.
        (* W6: nodes of this layer -- the trh site *)
        while (   all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads
               /\ R_top_C.ad = adz
               /\ 0 <= size R_top_C.skFORSnt < nr_trees 0
               /\ 0 <= size skFORSlp < l'
               /\ 0 <= size skFORScube < k
               /\ 0 <= size nodes < a).
        + wp.
          call (otrhwrap_query_ntype (R_top_C(F)) trhxtype).
          wp; skip => &hr [#] hall ha hnt0 hnt1 hlp0 hlp1 hcb0 hcb1 hnd0 hnd1 hncl.
          split; last by move=> _ tws htws; rewrite ha /=; smt().
          split; last exact hall.
          rewrite /= ha gettype_site_fors.
          + by rewrite /valid_tidx.
          + by rewrite /valid_kpidx.
          + by rewrite /valid_thfidx; smt(ge1_a).
          + by apply valid_tbfidx_cube; smt(size_ge0).
          by smt(fors_adrstypes_ne).
        wp; skip => />; smt(size_ge0).
      wp.
      (* W4: leaves of this FORS-TW tree -- the f site *)
      while (   all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads
             /\ R_top_C.ad = adz
             /\ 0 <= size R_top_C.skFORSnt < nr_trees 0
             /\ 0 <= size skFORSlp < l'
             /\ 0 <= size skFORScube < k).
      + wp.
        call (otrhwrap_query_ntype (R_top_C(F)) trhxtype).
        wp; rnd; skip => &hr [#] hall ha hnt0 hnt1 hlp0 hlp1 hcb0 hcb1 hset x hx.
        split; last by move=> _ tws htws; rewrite ha /=; smt().
        split; last exact hall.
        rewrite /= ha -nr_nodesf0 gettype_site_fors.
        + by rewrite /valid_tidx.
        + by rewrite /valid_kpidx.
        + by rewrite /valid_thfidx; smt(ge1_a).
        + by apply valid_tbfidx_cube; smt(size_ge0 nr_nodesf0).
        by smt(fors_adrstypes_ne).
      wp; skip => />; smt(size_ge0).
    wp; skip => &hr [#] hall ha hnt0 hnt1 hlp.
    split; first by smt(size_ge0).
    move=> tws roots0 skFORScube0 hgek [#] hall2 ha2 hnt02 hnt12 hlp02 hlp12.
    split; last by move=> _ tws0 htws0; rewrite ha /=; smt().
    split; last exact hall2.
    rewrite /= ha gettype_site_trco.
    + by rewrite /valid_tidx.
    + by rewrite /valid_kpidx.
    + by rewrite /valid_kpidx.
    by smt(fors_adrstypes_ne).
  wp; skip => />; smt(size_ge0 size_rcons).
auto => />.
qed.
lemma R_top_C_A_wf_ht (F <: Adv_EUFCMA_C{-O_THFC_MA, -R_top_C}) :
  dfC <> 8 * n => dfC <> 8 * n * len => dfC <> 8 * n * 2 => dfC <> 8 * n * k =>
  hoare[ R_top_C(F, O_THFC_MA).choose :
           O_THFC_MA.tws_ma = [] ==>
           all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma ].
proof.
move=> h1 h2 h3 h4.
conseq (R_top_C_members4 F).
move=> &hr _ tws_ma hall.
by apply (all_in_thfc4_neq_dfC _ h1 h2 h3 h4 hall).
qed.

(* ==========================================================================
   (S.6) THE FC.O <-> TRHC.O ORACLE-CLONE HOP  (gap (b), the sole residual of
   the old hop6b once (a) is dissolved).

   FC (WOTS_TW_ES.ec:450 `clone import Collection as FC`) and FSSLXMTWES.TRHC
   (FL_SL_XMSS_MT_ES.ec:445 `clone import TRH.Collection as TRHC`) are DISTINCT
   clones of the SAME `Collection` theory, BOTH instantiated `op get_diff <- size`
   and `op fc <- thfc` -- the SAME collection function.  Their `O_THFC_Default`
   modules therefore have OPERATIONALLY IDENTICAL code (query =
   `df<-size x; y<-thfc df pp tw x; tws<-rcons tws tw; return y`), differing ONLY
   in module identity (distinct pp/tws globals; the `in_collection` witness
   differs but that is an axiom, not query code).  Hence NOT a `sim` (glob
   differs), NOT the same clone: an HONEST byequiv reconciliation coupling the two
   states.  The same coupling is discharged in-proof at seam_branch2_trh PART 0
   (XmssmtCC_All:5340-5372).

   SOUNDNESS GATE + NON-VACUITY (all RUN 2026-07-24): the in-file `qeq` (query
   coupling) below compiles by `proc; auto` IFF FC.fc = TRHC.fc = thfc in scope.
   `qeq` is a STANDALONE WITNESS that the two query bodies coincide under the pp/tws
   coupling -- it is NOT a proof-term dependency of `choose_eq_C`: deleting `qeq` and
   recompiling, `choose_eq_C`'s `proc; sim` STILL closes (RUN, rc=0), because `sim`
   re-derives the identical-code oracle coincidence structurally.  NON-VACUITY: the
   drop-`pp` control (pp coupling removed) makes BOTH `qeq` and `choose_eq_C` FAIL to
   compile (thfc output depends on pp) -- so the coupling is genuinely load-bearing,
   not a vacuous byequiv.  Control transcripts archived under scratch/hop6b/. *)

equiv qeq :
  FSSLXMTWES.TRHC.O_THFC_Default.query ~ FC.O_THFC_Default.query :
     ={arg} /\ FSSLXMTWES.TRHC.O_THFC_Default.pp{1}  = FC.O_THFC_Default.pp{2}
          /\ FSSLXMTWES.TRHC.O_THFC_Default.tws{1} = FC.O_THFC_Default.tws{2}
  ==> ={res} /\ FSSLXMTWES.TRHC.O_THFC_Default.pp{1}  = FC.O_THFC_Default.pp{2}
          /\ FSSLXMTWES.TRHC.O_THFC_Default.tws{1} = FC.O_THFC_Default.tws{2}.
proof. proc; auto. qed.

(* choose is F-independent concrete code; its only external calls are OC.query,
   discharged pairwise by the identical-code match (qeq's content). *)
equiv choose_eq_C (F <: Adv_EUFCMA_C{-R_top_C, -FC.O_THFC_Default, -FSSLXMTWES.TRHC.O_THFC_Default}) :
  R_top_C(F, FSSLXMTWES.TRHC.O_THFC_Default).choose ~ R_top_C(F, FC.O_THFC_Default).choose :
    ={glob F, glob R_top_C}
    /\ FSSLXMTWES.TRHC.O_THFC_Default.pp{1}  = FC.O_THFC_Default.pp{2}
    /\ FSSLXMTWES.TRHC.O_THFC_Default.tws{1} = FC.O_THFC_Default.tws{2}
  ==> ={res, glob F, glob R_top_C}
    /\ FSSLXMTWES.TRHC.O_THFC_Default.pp{1}  = FC.O_THFC_Default.pp{2}
    /\ FSSLXMTWES.TRHC.O_THFC_Default.tws{1} = FC.O_THFC_Default.tws{2}.
proof. proc; sim. qed.

(* THE HOP.  OC is touched only in `OC.init` + `A(OC).choose` (the NAGCMA game's
   forge/keygen/sign/verify and R_top_C.forge/O_CMA.sign are all OC-free), so the
   coupling is established at init, carried through choose (choose_eq_C), and the
   OC-free tail is `sim`.  An EQUALITY; stated `<=` to drop straight into hop6b. *)
lemma oracle_clone_hop_C (F <: Adv_EUFCMA_C{-R_top_C, -FC.O_THFC_Default,
                             -FSSLXMTWES.TRHC.O_THFC_Default}) &m :
  Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(R_top_C(F),
        FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res]
  <= Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(R_top_C(F),
        FC.O_THFC_Default).main() @ &m : res].
proof.
byequiv (: ={glob F, glob R_top_C} ==> ={res}) => //.
proc.
seq 4 4 : (={ml, ps, ad, glob F, glob R_top_C}).
+ call (choose_eq_C F).
  inline{1} FSSLXMTWES.TRHC.O_THFC_Default.init.
  inline{2} FC.O_THFC_Default.init.
  auto.
sim.
qed.
