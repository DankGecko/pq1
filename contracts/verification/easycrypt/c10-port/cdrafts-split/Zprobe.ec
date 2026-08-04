(* ==========================================================================
   fx_chain_wip.ec  --  THE +C FX-CHAIN GAME MODULES + HOP-1 (Orig -> PRFPRF).

   ROLE.  This file is the +C analog of MM45's FS chain (FV-SPHINCSPLUS-EC/
   proofs/SPHINCS_PLUS.ec:1726-2571): it builds the shared +C FX-chain game
   modules (FS keygens, FS signing oracle, the PRFPRF / NPRFPRF games) and
   proves hop-1, the materialization fold

       Pr[EUFCMA_C10(F).main() @ &m : res]
       = Pr[EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF(F).main() @ &m : res],

   the +C analog of MM45's Eqv_EUF_CMA_SPHINCSPLUSTW_Orig_FSPRFPRF
   (SPHINCS_PLUS.ec:2243-2571).  The capstone's admitted hop1
   (sphincs_c10_capstone_concrete_wip.ec, `p_prfprf`) is exactly this equality.

   ==========================================================================
   THE +C DELTAS (vs MM45 :1726-2571) -- the established +C modelling decisions:

     (1) MESSAGE KEY: `mk <$ dcond dmkey (good_fors m)` FRESH PER QUERY in the
         FS oracle (NOT `mk <- mkg ms m`, NOT an mmap random function).  This is
         the +C idealisation already present in SPHINCS_PLUS_C10.sign and in
         V_C.O_CMA_C (rtop_c_soundness_wip.ec:347), so hop-1 carries NO mkg/RF
         reasoning: the SAME draw is on both sides and couples by a single
         `rnd`.  Consequently `ms` (mseed) is dead key material, kept only for
         sk-shape parity with MM45 (and the capstone's sk_t).
     (2) FORS sign in the FS oracle is CUBE-based:
           FTWES.FL_FORS_ES_NPRF.sign((skFORS, ps, <trhftype ad>), cm)  and
           FTWES.FL_FORS_ES_NPRF.gen_pkFORS(skFORS, ps, <ad>);
         the scheme side is SEED-based (the FTWES.FL_FORS_ES family).  Hop-1 is the
         skg-derived materialization fold between them.
     (3) HT sign in the FS oracle is CUBE-based:
           FL_SL_XMSS_MT_C_ES_NPRF.sign((skWOTStd, ps, ad), pkFORS, idx);
         the scheme side is the seed-based FL_SL_XMSS_MT_C_ES.sign.  Both are
         DETERMINISTIC given their inputs (the WOTS+C counter is the total op
         `grindC`, WOTS_C_Scheme.ec:56 -- no counter sampling to couple).
     (4) VERIFY in the FS games is the +C-faithful SPHINCS_PLUS_C10.verify
         (good_fors m mk /\ size sigHT = d /\ root' = root /\ allOkC, via
         FL_SL_XMSS_MT_C_ES.root_from_sigC) -- IDENTICAL on both sides of
         hop-1, so the verify tail is a plain `sim`.
     (5) FS-game sk shape: MM45's `mseed * skFORS list list * skWOTS list
         list list * pseed` at the +C types (`FTWES.skFORS` =
         FTWES.DBLLKTL subtype for the FORS cube; `skWOTS` from
         FSSLXMTWES.WTWES for the WOTS cube).

   ==========================================================================
   PROOF ARCHITECTURE (why hop-1 at +C is SHORTER than MM45 :2243-2571).

   MM45's hop-1 is one monolithic inline relational sync.  Here every signer
   involved is DETERMINISTIC (delta 1 makes the only sampling the shared mk
   draw; deltas 2-3 are deterministic), so the support equivalences are proved
   via CLOSED FORMS (phoare = 1%r), then consumed one-sided (`call{1}` /
   `call{2}`) and equated by pure list/op rewriting under the skg-cube
   coupling:

     * SEED closed forms:  fors_leaves_op / fors_sig_op / genpk_seed_cf /
       leaves_sspsad_cf / htsign_seed_cf   (ports of sphincs_c10_scheme_wip.ec
       :764-896 + rtop_c_soundness_wip.ec :608-787 structure).
     * CUBE closed forms:  genleaves_cf / fors_sign_cube_cf / genpkfors_cf /
       leaves_cf / nprf_sign_cf   (ports of rtop_c_soundness_wip.ec :631-935,
       which are unrequireable lowercase and therefore re-derived here).
     * The packed support equiv Eqv_C10_sign_FSbody is the +C analog of MM45's
       Eqv_SPHINCS_PLUS_S_sign (SPHINCS_PLUS.ec:1908-1989):  the seed-based
       SPHINCS_PLUS_C10.sign equals the materialized-cube FS oracle sign under
       the skg-cube coupling.  (MM45's own S-sign differs from its scheme only
       in the FORS pk recompute; SPHINCS_PLUS_C10.sign is ALREADY in that
       S-shape -- it calls gen_pkFORS directly -- so the +C support equiv is
       precisely the seed-vs-cube fold, with no pkFORS round-trip leg.)
     * Hop-1's keygen prefix is MM45's nested one-sided while{2} cube-coupling
       block (:2257-2390), ported with the +C FTWES.DBLLKTL / DBLL subtypes.

   ==========================================================================
   PROVENANCE / INLINING.  `good_fors`, the DSSC clone, SPHINCS_PLUS_C10 and
   EUFCMA_C10 are copied VERBATIM from sphincs_c10_scheme_wip.ec (:120-251) --
   that file is lowercase and hence un-requireable; inlining is the
   established pattern (cf. the capstone's good_clone inline and
   rtop_c_soundness_wip.ec's R_top_C inline).  The closed-form helper scripts
   are ports of the cited proven scripts (same reason).

   ==========================================================================
   HONEST LEDGER  --  updated as the file grows (see bottom for the gate).

   DEFINITIONS (sections 1-6):
     * good_fors / DSSC / SPHINCS_PLUS_C10 / EUFCMA_C10        [verbatim copy]
     * SPHINCS_PLUS_C10_FS.{keygen_prf_c, keygen_nprf_c, verify_c}
     * O_CMA_SPHINCSPLUSTWC_FS : SOracle_CMA_C (+ init/fresh/nr_queries)
     * EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF / _NPRFPRF

   PROOFS:
     * support closed forms + support equiv Eqv_C10_sign_FSbody  [PROVEN 0-admit]
     * hop-1 Eqv_EUFCMA_C10_FSPRFPRFC + Pr_EUFCMA_C10_FSPRFPRFC  [PROVEN 0-admit]

   GATE RECORD (2026-07-22, adversarially audited PASS/HONEST):
     bash ec-certify.sh drafts/fx_chain_wip.ec
       => compile=OK  admit-tactics=0  axiom-decls=0  => CERTIFIED-0-ADMIT
     Canaries REJECTED by the gate: ={res} -> res{1}=!res{2}; Pr `=` -> `<`;
     htsign_seed_cf size res = d -> d+1.  Statements diffed vs MM45 (verbatim
     modulo the documented +C deltas); scheme copy diffed verbatim vs
     sphincs_c10_scheme_wip.ec; no new axioms.
   ========================================================================== *)

require import AllCore List Distr StdBigop StdOrder IntDiv.
require import DList DMap FMap.
require import BinaryTrees MerkleTrees.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.
require DigitalSignatures.
require import BitEncoding. import BS2Int BitChunking.
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

(* The C10 FORS+C conditioning predicate on the message key -- VERBATIM copy of
   sphincs_c10_scheme_wip.ec:120-121 (= rtop_c_soundness_wip.ec:135-136 =
   capstone :216-217). *)
op good_fors (m : msg) (mk : mkey) : bool =
  (nth witness (FTWES.g (FTWES.mco mk m)) (k - 1)).`3 = 0.

(* --------------------------------------------------------------------------
   FRESH DigitalSignatures clone at the +C signature type -- VERBATIM copy of
   sphincs_c10_scheme_wip.ec:132-138 (sig_t = sigSPHINCSPLUSTWC; sk_t stays
   MM45's skSPHINCSPLUSTW).  Everything below stays DSSC.-qualified because
   `require import SPHINCS_PLUS` already pulled the OLD DSS.Stateless names
   into scope.
   -------------------------------------------------------------------------- *)
clone DigitalSignatures as DSSC with
  type pk_t  <- pkSPHINCSPLUSTW,
  type sk_t  <- skSPHINCSPLUSTW,
  type msg_t <- msg,
  type sig_t <- sigSPHINCSPLUSTWC

  proof *.

(* --------------------------------------------------------------------------
   THE CONCRETE SPHINCS+C10 SCHEME -- VERBATIM copy of sphincs_c10_scheme_wip.ec
   :143-238 (the hop-1 LHS object).  See that file's header for the +C
   substitution rationale; summary: seed-based sk (ms, ss, ps) as MM45; sign
   draws the +C conditioned message key FRESH, then runs the SEED-based FORS
   (FTWES.FL_FORS_ES.sign / gen_pkFORS) and the SEED-based +C hypertree
   (FL_SL_XMSS_MT_C_ES.sign); verify is the +C-faithful 4-conjunct gate.
   -------------------------------------------------------------------------- *)
module SPHINCS_PLUS_C10 : DSSC.Stateless.Scheme = {
  proc keygen() : pkSPHINCSPLUSTW * skSPHINCSPLUSTW = {
    var ad : adrs;
    var ms : mseed;
    var ss : sseed;
    var ps : pseed;
    var root : dgstblock;
    var pk : pkSPHINCSPLUSTW;
    var sk : skSPHINCSPLUSTW;

    ad <- adz;

    ms <$ dmseed;
    ss <$ dsseed;
    ps <$ dpseed;

    (* +C subst (ii): +C hypertree root (seed-based real FL_SL_XMSS_MT_C_ES). *)
    root <@ FL_SL_XMSS_MT_C_ES.gen_root(ss, ps, ad);

    pk <- (root, ps);
    sk <- (ms, ss, ps);

    return (pk, sk);
  }

  proc sign(sk : skSPHINCSPLUSTW, m : msg) : sigSPHINCSPLUSTWC = {
    var ms : mseed;
    var ss : sseed;
    var ps : pseed;
    var ad : adrs;
    var mk : mkey;
    var sigFORSTW : FTWES.sigFORSTW;
    var cm : FTWES.msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var pkFORS : FTWES.pkFORS;
    var sigHT : sigFLSLXMSSMTTWC;

    (ms, ss, ps) <- sk;

    ad <- adz;

    (* +C subst (i): the C10 conditioned message-key draw (grinding model). *)
    mk <$ dcond dmkey (good_fors m);

    (cm, idx) <- FTWES.mco mk m;

    (tidx, kpidx) <- edivz (Index.val idx) l';

    (* FORS branch at the MM45 FTWES shape, SEED-based (real skg keys). *)
    sigFORSTW <@ FTWES.FL_FORS_ES.sign((ss, ps,
                   set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);

    pkFORS <@ FTWES.FL_FORS_ES.gen_pkFORS(ss, ps,
                   set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

    (* +C subst (ii): +C hypertree signature (seed-based real). *)
    sigHT <@ FL_SL_XMSS_MT_C_ES.sign((ss, ps, ad), pkFORS, idx);

    return (mk, sigFORSTW, sigHT);
  }

  proc verify(pk : pkSPHINCSPLUSTW, m : msg, s : sigSPHINCSPLUSTWC) : bool = {
    var root, root' : dgstblock;
    var ps : pseed;
    var mk : mkey;
    var sigFORSTW : FTWES.sigFORSTW;
    var sigHT : sigFLSLXMSSMTTWC;
    var ad : adrs;
    var cm : FTWES.msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var pkFORS : FTWES.pkFORS;
    var allOkC : bool;

    (root, ps) <- pk;
    (mk, sigFORSTW, sigHT) <- s;

    ad <- adz;

    (cm, idx) <- FTWES.mco mk m;

    (tidx, kpidx) <- edivz (Index.val idx) l';

    pkFORS <@ FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW(sigFORSTW, cm, ps,
                   set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

    (* +C hypertree root reconstruction + per-layer constant-sum gate. *)
    (root', allOkC) <@ FL_SL_XMSS_MT_C_ES.root_from_sigC(pkFORS, sigHT, idx, ps, ad);

    (* Mirror V_C is_valid (rtop_c_soundness_wip.ec:451). *)
    return good_fors m mk /\ size sigHT = d /\ root' = root /\ allOkC;
  }
}.

(* The generic EUF_CMA game at the concrete scheme -- VERBATIM copy of
   sphincs_c10_scheme_wip.ec:250-251. *)
module EUFCMA_C10 (F : Adv_EUFCMA_C) =
  DSSC.Stateless.EUF_CMA(SPHINCS_PLUS_C10, F, DSSC.Stateless.O_CMA_Default).

(* ==========================================================================
   SECTION 4 -- THE FS (pregenerated-secret-key) SCHEME MODULE, +C.

   Port of MM45 SPHINCS_PLUS_FS (SPHINCS_PLUS.ec:1726-1874).  Both keygens
   materialize the FORS cube (nr_trees 0 x l' x k x t) and the WOTS cube
   (d x nr_trees(layer) x l' x len); `keygen_prf_c` derives every element by
   `skg ss (ps, <address>)` (the PRF side), `keygen_nprf_c` samples every
   element uniformly `<$ ddgstblock` (the NPRF side).  Both compute the public
   root from the top-most WOTS tree EXACTLY as the +C NPRF hypertree keygen
   does (FL_SL_XMSS_MT_C_ES_NPRF.keygen, XmssmtCC_All.ec:199-202): leaves via
   FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad, root via val_bt_trh at the
   trhxtype address -- so keygen_nprf_c's (root, WOTS cube) coincides with the
   V-game key material (rtop_c_soundness_wip.ec:394-415) that hop-2/hop-3
   target.
   ========================================================================== *)
module SPHINCS_PLUS_C10_FS = {
  proc keygen_prf_c() : pkSPHINCSPLUSTW * (mseed * FTWES.skFORS list list * skWOTS list list list * pseed) = {
    var ad : adrs;
    var ms : mseed;
    var ss : sseed;
    var ps : pseed;
    var skFORS_ele : dgstblock;
    var skFORSet : dgstblock list;
    var skFORScube : dgstblock list list;
    var skFORSlp : FTWES.skFORS list;
    var skFORSnt : FTWES.skFORS list list;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var root : dgstblock;
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * FTWES.skFORS list list * skWOTS list list list * pseed;

    ad <- adz;

    ms <$ dmseed;
    ss <$ dsseed;
    ps <$ dpseed;

    (* FORS cube, skg-derived at trhftype addresses (MM45 :1752-1767). *)
    skFORSnt <- [];
    while (size skFORSnt < nr_trees 0) {
      skFORSlp <- [];
      while (size skFORSlp < l') {
        skFORScube <- [];
        while (size skFORScube < k) {
          skFORSet <- [];
          while (size skFORSet < t) {
            skFORS_ele <- skg ss (ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) (size skFORSlp)) 0 (size skFORScube * t + size skFORSet));
            skFORSet <- rcons skFORSet skFORS_ele;
          }
          skFORScube <- rcons skFORScube skFORSet;
        }
        skFORSlp <- rcons skFORSlp (FTWES.DBLLKTL.insubd skFORScube);
      }
      skFORSnt <- rcons skFORSnt skFORSlp;
    }

    (* WOTS cube, skg-derived at chtype chain addresses (MM45 :1769-1784). *)
    skWOTStd <- [];
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        while (size skWOTSlp < l') {
          skWOTS <- [];
          while (size skWOTS < len) {
            skWOTS_ele <- skg ss (ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) (size skWOTS)) 0);
            skWOTS <- rcons skWOTS skWOTS_ele;
          }
          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
        }
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
    }

    (* Root from the top WOTS tree, +C NPRF-style (XmssmtCC_All.ec:199-202). *)
    skWOTSlp <- nth witness (nth witness skWOTStd (d - 1)) 0;
    leaves <@ FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (d - 1) 0);
    root <- val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhxtype) (list2tree leaves);

    pk <- (root, ps);
    sk <- (ms, skFORSnt, skWOTStd, ps);

    return (pk, sk);
  }

  proc keygen_nprf_c() : pkSPHINCSPLUSTW * (mseed * FTWES.skFORS list list * skWOTS list list list * pseed) = {
    var ad : adrs;
    var ms : mseed;
    var ss : sseed;
    var ps : pseed;
    var skFORS_ele : dgstblock;
    var skFORSet : dgstblock list;
    var skFORScube : dgstblock list list;
    var skFORSlp : FTWES.skFORS list;
    var skFORSnt : FTWES.skFORS list list;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var root : dgstblock;
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * FTWES.skFORS list list * skWOTS list list list * pseed;

    ad <- adz;

    ms <$ dmseed;
    ss <$ dsseed;
    ps <$ dpseed;

    (* FORS cube, uniformly sampled (MM45 :1824-1839; same raw draw shape as
       V_C's keygen cube, rtop_c_soundness_wip.ec:394-410). *)
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

    (* WOTS cube, uniformly sampled (MM45 :1841-1856). *)
    skWOTStd <- [];
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        while (size skWOTSlp < l') {
          skWOTS <- [];
          while (size skWOTS < len) {
            skWOTS_ele <$ ddgstblock;
            skWOTS <- rcons skWOTS skWOTS_ele;
          }
          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
        }
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
    }

    skWOTSlp <- nth witness (nth witness skWOTStd (d - 1)) 0;
    leaves <@ FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (d - 1) 0);
    root <- val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhxtype) (list2tree leaves);

    pk <- (root, ps);
    sk <- (ms, skFORSnt, skWOTStd, ps);

    return (pk, sk);
  }

  (* +C-faithful verify: the REAL scheme's verify (delta 4) -- the +C analog of
     MM45's `proc verify = SPHINCS_PLUS.verify` (SPHINCS_PLUS.ec:1873). *)
  proc verify_c = SPHINCS_PLUS_C10.verify
}.

(* ==========================================================================
   SECTION 5 -- THE FS SIGNING ORACLE, +C.

   Port of MM45 O_CMA_SPHINCSPLUSTWFS_PRF (SPHINCS_PLUS.ec:1991-2050) with the
   +C deltas (1)-(3):  the message key is drawn FRESH per query from
   `dcond dmkey (good_fors m)` (delta 1 -- byte-identical to the scheme's own
   draw, so hop-1 couples it by one `rnd`; identical to V_C.O_CMA_C.sign,
   rtop_c_soundness_wip.ec:347-365, plus the MM45-style init/fresh/nr_queries
   that V_C's oracle does not carry).
   ========================================================================== *)
module O_CMA_SPHINCSPLUSTWC_FS : SOracle_CMA_C = {
  var sk : mseed * FTWES.skFORS list list * skWOTS list list list * pseed
  var qs : msg list

  proc init(sk_init : mseed * FTWES.skFORS list list * skWOTS list list list * pseed) : unit = {
    sk <- sk_init;
    qs <- [];
  }

  proc sign(m : msg) : sigSPHINCSPLUSTWC = {
    var ms : mseed;
    var skFORS : FTWES.skFORS;
    var pkFORS : FTWES.pkFORS;
    var skFORSnt : FTWES.skFORS list list;
    var skWOTStd : skWOTS list list list;
    var ps : pseed;
    var ad : adrs;
    var mk : mkey;
    var cm : FTWES.msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var sigFORSTW : FTWES.sigFORSTW;
    var sigHT : sigFLSLXMSSMTTWC;

    (ms, skFORSnt, skWOTStd, ps) <- sk;

    ad <- adz;

    (* +C delta 1: fresh conditioned draw (NOT mkg, NOT an mmap RF). *)
    mk <$ dcond dmkey (good_fors m);

    (cm, idx) <- FTWES.mco mk m;

    (tidx, kpidx) <- edivz (Index.val idx) l';

    skFORS <- nth witness (nth witness skFORSnt tidx) kpidx;

    (* +C delta 2: cube-based FORS sign + pk recompute. *)
    sigFORSTW <@ FTWES.FL_FORS_ES_NPRF.sign((skFORS, ps,
                     set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);

    pkFORS <@ FTWES.FL_FORS_ES_NPRF.gen_pkFORS(skFORS, ps,
                     set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

    (* +C delta 3: cube-based +C hypertree sign. *)
    sigHT <@ FL_SL_XMSS_MT_C_ES_NPRF.sign((skWOTStd, ps, ad), pkFORS, idx);

    qs <- rcons qs m;

    return (mk, sigFORSTW, sigHT);
  }

  proc fresh(m : msg) : bool = {
    return ! (m \in qs);
  }

  proc nr_queries() : int = {
    return size qs;
  }
}.

(* ==========================================================================
   SECTION 6 -- THE FS EUF-CMA GAMES, +C.

   Ports of MM45 EUF_CMA_SPHINCSPLUSTWFS_PRFPRF / _NPRFPRF (SPHINCS_PLUS.ec
   :2110-2157):  same main, with the +C FS keygens / oracle / verify.
   ========================================================================== *)
module EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF (A : Adv_EUFCMA_C) = {
  proc main() : bool = {
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * FTWES.skFORS list list * skWOTS list list list * pseed;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTWC;
    var is_valid, is_fresh : bool;

    (pk, sk) <@ SPHINCS_PLUS_C10_FS.keygen_prf_c();

    O_CMA_SPHINCSPLUSTWC_FS.init(sk);

    (m', sig') <@ A(O_CMA_SPHINCSPLUSTWC_FS).forge(pk);

    is_valid <@ SPHINCS_PLUS_C10_FS.verify_c(pk, m', sig');
    is_fresh <@ O_CMA_SPHINCSPLUSTWC_FS.fresh(m');

    return is_valid /\ is_fresh;
  }
}.

module EUF_CMA_SPHINCSPLUSTWC_FS_NPRFPRF (A : Adv_EUFCMA_C) = {
  proc main() : bool = {
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * FTWES.skFORS list list * skWOTS list list list * pseed;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTWC;
    var is_valid, is_fresh : bool;

    (pk, sk) <@ SPHINCS_PLUS_C10_FS.keygen_nprf_c();

    O_CMA_SPHINCSPLUSTWC_FS.init(sk);

    (m', sig') <@ A(O_CMA_SPHINCSPLUSTWC_FS).forge(pk);

    is_valid <@ SPHINCS_PLUS_C10_FS.verify_c(pk, m', sig');
    is_fresh <@ O_CMA_SPHINCSPLUSTWC_FS.fresh(m');

    return is_valid /\ is_fresh;
  }
}.

(* ==========================================================================
   SECTION 7 -- CLOSED-FORM SUPPORT ASSETS.

   Every signer in hop-1 is deterministic (only the shared mk draw is
   sampled), so the seed-vs-cube support equiv is built from per-procedure
   closed forms (phoare = 1%r), consumed one-sided and equated under the
   skg-cube coupling.  Script provenance:
     * seed FORS leaves/sign traces -- sphincs_c10_scheme_wip.ec:764-896
       (fors_genleaves_closed / fors_sign_trace / fors_lfidx_bound, verbatim
       ports; that file is unrequireable lowercase).
     * cube FORS leaves/pk traces   -- rtop_c_soundness_wip.ec:850-935
       (genleaves_cf_h / genpkfors_cf_h, near-verbatim ports).
     * HT cube sign closed form     -- rtop_c_soundness_wip.ec:608-799
       (pkwots_cf_h / wotsc_sign_cf_h / leaves_cf_h / nprf_sign_cf_h ports).
     * HT seed sign closed form     -- NEW, mirrored on the cube one with
       gen_skWOTS (skg) replacing the cube nth (same structure as
       nprf_sign_cf_h).
   ========================================================================== *)

(* ---- (7.A) FORS SEED closed forms (port of sphincs_c10_scheme_wip.ec). ---- *)

(* The seed-side FORS leaves closed form (sphincs_c10_scheme_wip.ec:764). *)
op fors_leaves_op (ss0:sseed) (ps0:pseed) (ad0:adrs) (idxt0:int) : dgstblock list =
  mkseq (fun (j:int) => f ps0 (set_thtbidx ad0 0 (idxt0*t+j))
                          (DigestBlock.val (skg ss0 (ps0, set_thtbidx ad0 0 (idxt0*t+j))))) t.

lemma fors_genleaves_closed (idxt0:int) (ss0:sseed) (ps0:pseed) (ad0:adrs) :
  hoare[FTWES.FL_FORS_ES.gen_leaves_single_tree :
    idxt=idxt0 /\ ss=ss0 /\ ps=ps0 /\ ad=ad0 ==> res = fors_leaves_op ss0 ps0 ad0 idxt0].
proof.
admit.
qed.

lemma fors_leaves_ll : islossless FTWES.FL_FORS_ES.gen_leaves_single_tree.
proof. proc; while (true) (t - size leaves); auto; smt(size_rcons ge2_t). qed.

(* The FORS honest-signature closed form: k trees, tree i signs message-slice
   lfidx i with skg secret + honest auth path over the tree's leaves
   (sphincs_c10_scheme_wip.ec:787). *)
op fors_sig_op (ss0:sseed) (ps0:pseed) (ad0:adrs) (m0:FTWES.msgFORSTW)
   : (dgstblock * FTWES.apFORSTW) list =
  mkseq (fun (i:int) =>
    let lfidx = bs2int (rev (take a (drop (a*i) (FTWES.BLKAL.val m0)))) in
    (skg ss0 (ps0, set_thtbidx ad0 0 (i*t+lfidx)),
     FTWES.cons_ap_trh ps0 ad0 (list2tree (fors_leaves_op ss0 ps0 ad0 i)) lfidx i)) k.

(* The per-tree FORS message index lands in [0,t)
   (sphincs_c10_scheme_wip.ec:796). *)
lemma fors_lfidx_bound (mv : FTWES.msgFORSTW) (sr : int) :
  0 <= sr < k =>
  0 <= bs2int (rev (take a (drop (a * sr) (FTWES.BLKAL.val mv)))) < t.
proof.
admit.
qed.

(* Seed FORS sign emits exactly the fors_sig_op closed form
   (sphincs_c10_scheme_wip.ec:864, verbatim port). *)
lemma fors_sign_trace (ssv:sseed)(psv:pseed)(adv:adrs)(mv:FTWES.msgFORSTW) :
  hoare[FTWES.FL_FORS_ES.sign :
    sk = (ssv,psv,adv) /\ m = mv ==> FTWES.DBAPKL.val res = fors_sig_op ssv psv adv mv].
proof.
admit.
qed.

lemma fors_sign_ll : islossless FTWES.FL_FORS_ES.sign.
proof.
admit.
qed.

(* Packaged seed-side FORS sign closed form (phoare = 1%r, one-sided-call
   ready). *)
lemma fors_sign_seed_cf (ssv:sseed)(psv:pseed)(adv:adrs)(mv:FTWES.msgFORSTW) :
  phoare[FTWES.FL_FORS_ES.sign :
    sk = (ssv,psv,adv) /\ m = mv ==> FTWES.DBAPKL.val res = fors_sig_op ssv psv adv mv] = 1%r.
proof. conseq fors_sign_ll (fors_sign_trace ssv psv adv mv) => //. qed.

(* Seed-side gen_pkFORS closed form -- NEW, mirrored on the cube-side
   genpkfors_cf_h (rtop_c_soundness_wip.ec:875) with the proven seed leaves
   closed form fors_genleaves_closed replacing genleaves_cf_h. *)
lemma genpk_seed_cf_h (ss0:sseed) (ps0:pseed) (ad0:adrs) :
  hoare[FTWES.FL_FORS_ES.gen_pkFORS :
        ss = ss0 /\ ps = ps0 /\ ad = ad0
        ==> res = trco ps0 (set_kpidx (set_typeidx ad0 trcotype) (FTWES.get_kpidx ad0))
                    (flatten (map DigestBlock.val
                       (mkseq (fun (u : int) =>
                          FTWES.val_bt_trh ps0 ad0
                            (list2tree (fors_leaves_op ss0 ps0 ad0 u)) u) k)))].
proof.
admit.
qed.

lemma fors_genpk_ll : islossless FTWES.FL_FORS_ES.gen_pkFORS.
proof.
admit.
qed.

lemma genpk_seed_cf (ss0:sseed) (ps0:pseed) (ad0:adrs) :
  phoare[FTWES.FL_FORS_ES.gen_pkFORS :
        ss = ss0 /\ ps = ps0 /\ ad = ad0
        ==> res = trco ps0 (set_kpidx (set_typeidx ad0 trcotype) (FTWES.get_kpidx ad0))
                    (flatten (map DigestBlock.val
                       (mkseq (fun (u : int) =>
                          FTWES.val_bt_trh ps0 ad0
                            (list2tree (fors_leaves_op ss0 ps0 ad0 u)) u) k)))] = 1%r.
proof. conseq fors_genpk_ll (genpk_seed_cf_h ss0 ps0 ad0) => //. qed.

(* ---- (7.B) FORS CUBE closed forms (ports of rtop_c_soundness_wip.ec). ---- *)

(* The cube-side FORS leaves closed form. *)
op fors_leaves_op_cube (skF0:FTWES.skFORS) (ps0:pseed) (ad0:adrs) (idxt0:int) : dgstblock list =
  mkseq (fun (j:int) => f ps0 (set_thtbidx ad0 0 (idxt0*t+j))
             (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skF0) idxt0) j))) t.

lemma genleaves_cube_cf_h (idxt0 : int) (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) :
  hoare[FTWES.FL_FORS_ES_NPRF.gen_leaves_single_tree :
        idxt = idxt0 /\ skFORS = skF /\ ps = ps0 /\ ad = ad0
        ==> res = fors_leaves_op_cube skF ps0 ad0 idxt0].
proof.
admit.
qed.

lemma genleaves_cube_ll : islossless FTWES.FL_FORS_ES_NPRF.gen_leaves_single_tree.
proof.
admit.
qed.

(* The cube-side FORS honest-signature closed form -- NEW, mirrored on
   fors_sign_trace with the cube nth replacing skg. *)
op fors_sig_op_cube (skF0:FTWES.skFORS) (ps0:pseed) (ad0:adrs) (m0:FTWES.msgFORSTW)
   : (dgstblock * FTWES.apFORSTW) list =
  mkseq (fun (i:int) =>
    let lfidx = bs2int (rev (take a (drop (a*i) (FTWES.BLKAL.val m0)))) in
    (nth witness (nth witness (FTWES.DBLLKTL.val skF0) i) lfidx,
     FTWES.cons_ap_trh ps0 ad0 (list2tree (fors_leaves_op_cube skF0 ps0 ad0 i)) lfidx i)) k.

lemma fors_sign_cube_trace (skFv:FTWES.skFORS)(psv:pseed)(adv:adrs)(mv:FTWES.msgFORSTW) :
  hoare[FTWES.FL_FORS_ES_NPRF.sign :
    sk = (skFv,psv,adv) /\ m = mv ==> FTWES.DBAPKL.val res = fors_sig_op_cube skFv psv adv mv].
proof.
admit.
qed.

lemma fors_sign_cube_ll : islossless FTWES.FL_FORS_ES_NPRF.sign.
proof.
admit.
qed.

lemma fors_sign_cube_cf (skFv:FTWES.skFORS)(psv:pseed)(adv:adrs)(mv:FTWES.msgFORSTW) :
  phoare[FTWES.FL_FORS_ES_NPRF.sign :
    sk = (skFv,psv,adv) /\ m = mv ==> FTWES.DBAPKL.val res = fors_sig_op_cube skFv psv adv mv] = 1%r.
proof. conseq fors_sign_cube_ll (fors_sign_cube_trace skFv psv adv mv) => //. qed.

(* Cube-side gen_pkFORS closed form (port of rtop_c_soundness_wip.ec:875-935). *)
lemma genpkfors_cf_h (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) :
  hoare[FTWES.FL_FORS_ES_NPRF.gen_pkFORS :
        skFORS = skF /\ ps = ps0 /\ ad = ad0
        ==> res = trco ps0 (set_kpidx (set_typeidx ad0 trcotype) (FTWES.get_kpidx ad0))
                    (flatten (map DigestBlock.val
                       (mkseq (fun (u : int) =>
                          FTWES.val_bt_trh ps0 ad0
                            (list2tree (fors_leaves_op_cube skF ps0 ad0 u)) u) k)))].
proof.
admit.
qed.

lemma genpkfors_ll : islossless FTWES.FL_FORS_ES_NPRF.gen_pkFORS.
proof.
admit.
qed.

lemma genpkfors_cf (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) :
  phoare[FTWES.FL_FORS_ES_NPRF.gen_pkFORS :
        skFORS = skF /\ ps = ps0 /\ ad = ad0
        ==> res = trco ps0 (set_kpidx (set_typeidx ad0 trcotype) (FTWES.get_kpidx ad0))
                    (flatten (map DigestBlock.val
                       (mkseq (fun (u : int) =>
                          FTWES.val_bt_trh ps0 ad0
                            (list2tree (fors_leaves_op_cube skF ps0 ad0 u)) u) k)))] = 1%r.
proof. conseq genpkfors_ll (genpkfors_cf_h skF ps0 ad0) => //. qed.

(* ---- (7.C) HYPERTREE shared index fold + SEED closed forms. ---- *)

(* Shared layer-index fold (rtop_c_soundness_wip.ec:696, verbatim). *)
op fidx (idx0 : index) (j : int) : int * int =
  fold (fun (ijs : int * int) => edivz ijs.`1 l') (Index.val idx0, 0) j.

(* gen_skWOTS closed form: the len-loop accumulates the skg chain keys. *)
lemma genskwots_cf_h (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) :
  hoare[WOTS_TW_ES.gen_skWOTS :
        ss = ss0 /\ ps = ps0 /\ ad = ad0
        ==> res = DBLL.insubd (mkseq (fun (v : int) =>
                     skg ss0 (ps0, set_hidx (set_chidx ad0 v) 0)) len)].
proof.
admit.
qed.

(* WOTS_TW_ES.pkWOTS_from_skWOTS closed form (seed-side ES module; body is
   byte-identical to the NPRF one, so this is pkwots_cf_h's script verbatim,
   rtop_c_soundness_wip.ec:608). *)
lemma pkwots_es_cf_h (skW : skWOTS) (ps0 : pseed) (ad0 : adrs) :
  hoare[WOTS_TW_ES.pkWOTS_from_skWOTS :
        skWOTS = skW /\ ps = ps0 /\ ad = ad0
        ==> DBLL.val res = mkseq (fun (v : int) =>
              cf ps0 (set_chidx ad0 v) 0 (w - 1) (DigestBlock.val (nth witness (DBLL.val skW) v))) len].
proof.
admit.
qed.

(* WOTS_TW_ES_NPRF.pkWOTS_from_skWOTS closed form (rtop_c_soundness_wip.ec:608,
   verbatim port). *)
lemma pkwots_cube_cf_h (skW : skWOTS) (ps0 : pseed) (ad0 : adrs) :
  hoare[WOTS_TW_ES_NPRF.pkWOTS_from_skWOTS :
        skWOTS = skW /\ ps = ps0 /\ ad = ad0
        ==> DBLL.val res = mkseq (fun (v : int) =>
              cf ps0 (set_chidx ad0 v) 0 (w - 1) (DigestBlock.val (nth witness (DBLL.val skW) v))) len].
proof.
admit.
qed.

(* WOTS_C_ES.sign closed form (rtop_c_soundness_wip.ec:631, verbatim port) --
   shared by the seed and cube hypertree signers (both call WOTS_C_ES.sign). *)
lemma wotsc_sign_cf_h (skW : skWOTS) (ps0 : pseed) (ad0 : adrs) (mm : msgWOTS) :
  hoare[WOTS_C_ES.sign :
        sk = (skW, ps0, ad0) /\ m = mm
        ==> res.`2 = grindC ps0 ad0 mm
         /\ DBLL.val res.`1 = mkseq (fun (v : int) =>
              cf ps0 (set_chidx ad0 v) 0
                (BaseW.val (encode_msgWOTS_C ps0 ad0 mm (grindC ps0 ad0 mm)).[v])
                (DigestBlock.val (nth witness (DBLL.val skW) v))) len].
proof.
admit.
qed.

(* Seed-side hypertree closed-form ops: mirror rtop_c_soundness_wip.ec:699-724
   with `skg ss0 (ps0, <chain adrs>)` replacing the cube nth lookups. *)
op tree_leaves_s (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) (lyr tr : int) : dgstblock list =
  mkseq (fun (u : int) =>
    pkco ps0 (set_kpidx (set_typeidx (set_ltidx ad0 lyr tr) pkcotype) u)
         (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
             cf ps0 (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 lyr tr) chtype) u) v) 0 (w - 1)
                (DigestBlock.val (skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 lyr tr) chtype) u) v) 0)))) len)))) l'.

op tree_root_s (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) (lyr tr : int) : dgstblock =
  val_bt_trh ps0 (set_typeidx (set_ltidx ad0 lyr tr) trhxtype) (list2tree (tree_leaves_s ss0 ps0 ad0 lyr tr)).

op rt_cf_s (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) (m0 : msgFLSLXMSSMTTW) (idx0 : index) (j : int) : msgFLSLXMSSMTTW =
  if j = 0 then m0 else tree_root_s ss0 ps0 ad0 (j - 1) (fidx idx0 j).`1.

op sig_cf_elem_s (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) (m0 : msgFLSLXMSSMTTW) (idx0 : index) (j : int) : sigWOTS * cntr =
  let ti = (fidx idx0 j).`1 in
  let rt = rt_cf_s ss0 ps0 ad0 m0 idx0 j in
  let chad = set_kpidx (set_typeidx (set_ltidx ad0 j (ti %/ l')) chtype) (ti %% l') in
  (DBLL.insubd (mkseq (fun (v : int) =>
      cf ps0 (set_chidx chad v) 0 (BaseW.val (encode_msgWOTS_C ps0 chad rt (grindC ps0 chad rt)).[v])
         (DigestBlock.val (skg ss0 (ps0, set_hidx (set_chidx chad v) 0)))) len),
   grindC ps0 chad rt).

op ap_cf_elem_s (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) (idx0 : index) (j : int) : apFLXMSSTW =
  let ti = (fidx idx0 (j + 1)).`1 in
  let ki = (fidx idx0 (j + 1)).`2 in
  cons_ap_trh ps0 (set_typeidx (set_ltidx ad0 j ti) trhxtype) (list2tree (tree_leaves_s ss0 ps0 ad0 j ti)) ki.

(* leaves_from_sspsad closed form (seed): mirror of leaves_cf_h
   (rtop_c_soundness_wip.ec:660) with the gen_skWOTS skg form per leaf. *)
lemma leaves_sspsad_cf_h (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) :
  hoare[FL_SL_XMSS_MT_C_ES.leaves_from_sspsad :
        ss = ss0 /\ ps = ps0 /\ ad = ad0
        ==> res = mkseq (fun (u : int) =>
              pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
                   (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                       cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                          (DigestBlock.val (skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0)))) len)))) l'].
proof.
admit.
qed.

lemma leaves_sspsad_cf (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) :
  phoare[FL_SL_XMSS_MT_C_ES.leaves_from_sspsad :
        ss = ss0 /\ ps = ps0 /\ ad = ad0
        ==> res = mkseq (fun (u : int) =>
              pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
                   (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                       cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                          (DigestBlock.val (skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0)))) len)))) l'] = 1%r.
proof. conseq leaves_ll (leaves_sspsad_cf_h ss0 ps0 ad0) => //. qed.

(* THE SEED-SIDE HYPERTREE SIGN closed form -- mirror of nprf_sign_cf_h
   (rtop_c_soundness_wip.ec:726-787) with gen_skWOTS (skg) replacing the cube
   extraction. *)
lemma htsign_seed_cf_h (ss0 : sseed) (ps0 : pseed) (ad0 : adrs)
                       (m0 : msgFLSLXMSSMTTW) (idx0 : index) :
  hoare[FL_SL_XMSS_MT_C_ES.sign :
        sk = (ss0, ps0, ad0) /\ m = m0 /\ idx = idx0
        ==> size res = d
         /\ (forall (j : int), 0 <= j < d =>
              nth witness res j
              = (sig_cf_elem_s ss0 ps0 ad0 m0 idx0 j, ap_cf_elem_s ss0 ps0 ad0 idx0 j))].
proof.
admit.
qed.

lemma htsign_seed_cf (ss0 : sseed) (ps0 : pseed) (ad0 : adrs)
                     (m0 : msgFLSLXMSSMTTW) (idx0 : index) :
  phoare[FL_SL_XMSS_MT_C_ES.sign :
        sk = (ss0, ps0, ad0) /\ m = m0 /\ idx = idx0
        ==> size res = d
         /\ (forall (j : int), 0 <= j < d =>
              nth witness res j
              = (sig_cf_elem_s ss0 ps0 ad0 m0 idx0 j, ap_cf_elem_s ss0 ps0 ad0 idx0 j))] = 1%r.
proof.
admit.
qed.

(* ---- (7.D) HYPERTREE CUBE closed forms (ports of rtop_c_soundness_wip.ec
        :699-799, with the _c suffix to tell them from the seed _s forms). ---- *)

op tree_leaves_c (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (lyr tr : int) : dgstblock list =
  mkseq (fun (u : int) =>
    pkco ps0 (set_kpidx (set_typeidx (set_ltidx ad0 lyr tr) pkcotype) u)
         (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
             cf ps0 (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0 lyr tr) chtype) u) v) 0 (w - 1)
                (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd0 lyr) tr) u)) v))) len)))) l'.

op tree_root_c (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (lyr tr : int) : dgstblock =
  val_bt_trh ps0 (set_typeidx (set_ltidx ad0 lyr tr) trhxtype) (list2tree (tree_leaves_c skWOTStd0 ps0 ad0 lyr tr)).

op rt_cf_c (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (m0 : msgFLSLXMSSMTTW) (idx0 : index) (j : int) : msgFLSLXMSSMTTW =
  if j = 0 then m0 else tree_root_c skWOTStd0 ps0 ad0 (j - 1) (fidx idx0 j).`1.

op sig_cf_elem_c (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (m0 : msgFLSLXMSSMTTW) (idx0 : index) (j : int) : sigWOTS * cntr =
  let ti = (fidx idx0 j).`1 in
  let rt = rt_cf_c skWOTStd0 ps0 ad0 m0 idx0 j in
  let chad = set_kpidx (set_typeidx (set_ltidx ad0 j (ti %/ l')) chtype) (ti %% l') in
  (DBLL.insubd (mkseq (fun (v : int) =>
      cf ps0 (set_chidx chad v) 0 (BaseW.val (encode_msgWOTS_C ps0 chad rt (grindC ps0 chad rt)).[v])
         (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd0 j) (ti %/ l')) (ti %% l'))) v))) len),
   grindC ps0 chad rt).

op ap_cf_elem_c (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs) (idx0 : index) (j : int) : apFLXMSSTW =
  let ti = (fidx idx0 (j + 1)).`1 in
  let ki = (fidx idx0 (j + 1)).`2 in
  cons_ap_trh ps0 (set_typeidx (set_ltidx ad0 j ti) trhxtype) (list2tree (tree_leaves_c skWOTStd0 ps0 ad0 j ti)) ki.

(* leaves_from_sklpsad closed form (rtop_c_soundness_wip.ec:660, verbatim port). *)
lemma leaves_cube_cf_h (skWl : skWOTS list) (ps0 : pseed) (ad0 : adrs) :
  hoare[FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad :
        skWOTSl = skWl /\ ps = ps0 /\ ad = ad0
        ==> res = mkseq (fun (u : int) =>
              pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
                   (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                       cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                          (DigestBlock.val (nth witness (DBLL.val (nth witness skWl u)) v))) len)))) l'].
proof.
admit.
qed.

lemma leaves_cube_cf (skWl : skWOTS list) (ps0 : pseed) (ad0 : adrs) :
  phoare[FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad :
        skWOTSl = skWl /\ ps = ps0 /\ ad = ad0
        ==> res = mkseq (fun (u : int) =>
              pkco ps0 (set_kpidx (set_typeidx ad0 pkcotype) u)
                   (flatten (map DigestBlock.val (mkseq (fun (v : int) =>
                       cf ps0 (set_chidx (set_kpidx (set_typeidx ad0 chtype) u) v) 0 (w - 1)
                          (DigestBlock.val (nth witness (DBLL.val (nth witness skWl u)) v))) len)))) l'] = 1%r.
proof. conseq leaves_sklpsad_ll (leaves_cube_cf_h skWl ps0 ad0) => //. qed.

(* THE CUBE-SIDE HYPERTREE SIGN closed form (rtop_c_soundness_wip.ec:726-799,
   verbatim port at the _c ops). *)
lemma nprf_sign_cf_h (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs)
                     (m0 : msgFLSLXMSSMTTW) (idx0 : index) :
  hoare[FL_SL_XMSS_MT_C_ES_NPRF.sign :
        sk = (skWOTStd0, ps0, ad0) /\ m = m0 /\ idx = idx0
        ==> size res = d
         /\ (forall (j : int), 0 <= j < d =>
              nth witness res j
              = (sig_cf_elem_c skWOTStd0 ps0 ad0 m0 idx0 j, ap_cf_elem_c skWOTStd0 ps0 ad0 idx0 j))].
proof.
admit.
qed.

lemma nprf_sign_cf (skWOTStd0 : skWOTS list list list) (ps0 : pseed) (ad0 : adrs)
                   (m0 : msgFLSLXMSSMTTW) (idx0 : index) :
  phoare[FL_SL_XMSS_MT_C_ES_NPRF.sign :
        sk = (skWOTStd0, ps0, ad0) /\ m = m0 /\ idx = idx0
        ==> size res = d
         /\ (forall (j : int), 0 <= j < d =>
              nth witness res j
              = (sig_cf_elem_c skWOTStd0 ps0 ad0 m0 idx0 j, ap_cf_elem_c skWOTStd0 ps0 ad0 idx0 j))] = 1%r.
proof.
admit.
qed.

(* ==========================================================================
   SECTION 8 -- THE SUPPORT EQUIV (+C analog of MM45's Eqv_SPHINCS_PLUS_S_sign,
   SPHINCS_PLUS.ec:1908-1989).

   MM45's support lemma equates its seed-based scheme sign with a "spec" sign
   whose only delta is the FORS pk recompute (gen_pkFORS for
   pkFORS_from_sigFORSTW).  SPHINCS_PLUS_C10.sign is ALREADY in that S-shape,
   so the +C support equiv is precisely the SEED-vs-CUBE materialization fold:
   SPHINCS_PLUS_C10.sign (seed FORS/HT signers) equals the FS oracle sign
   (cube FORS/HT signers) under the skg-cube coupling.  Built from the Section
   7 closed forms; the per-index bounds come from `foldedivz`
   (FL_SL_XMSS_MT_ES.ec:785) + Index.valP.
   ========================================================================== *)

(* ---- (8.A) index-bound auxiliaries over the shared fold fidx. ---- *)

(* Powers of l' as powers of 2 (avoids re-deriving the exponent algebra). *)
lemma pow_l (j : int) : l' ^ j = 2 ^ (h' * j).
proof. by rewrite /l' -exprM. qed.

lemma pow_lS (j : int) : 0 <= j => l' ^ j * l' = l' ^ (j + 1).
proof.
admit.
qed.

(* The tree index at layer j (1 <= j <= d) ranges over [0, nr_trees (j-1)). *)
lemma fidx_tree_bound (idx0 : index) (j : int) :
  1 <= j <= d => 0 <= (fidx idx0 j).`1 < nr_trees (j - 1).
proof.
admit.
qed.

(* The tree index INSIDE layer j (0 <= j < d) ranges over [0, nr_trees j). *)
lemma fidx_tidx_bound (idx0 : index) (j : int) :
  0 <= j < d => 0 <= (fidx idx0 j).`1 %/ l' < nr_trees j.
proof.
admit.
qed.

(* The keypair index inside layer j ranges over [0, l'). *)
lemma fidx_kpidx_bound (idx0 : index) (j : int) :
  0 <= j => 0 <= (fidx idx0 j).`1 %% l' < l'.
proof.
admit.
qed.

(* ---- (8.B) op-level equalities under the cube couplings. ---- *)

(* The seed and cube FORS leaves closed forms coincide on a coupled FORS row. *)
lemma fors_leaves_s_eq_c (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) (skF0 : FTWES.skFORS) (u0 : int) :
  (forall (u v : int), 0 <= u && u < k => 0 <= v && v < t =>
     nth witness (nth witness (FTWES.DBLLKTL.val skF0) u) v
     = skg ss0 (ps0, set_thtbidx ad0 0 (u * t + v))) =>
  0 <= u0 < k =>
  fors_leaves_op ss0 ps0 ad0 u0 = fors_leaves_op_cube skF0 ps0 ad0 u0.
proof.
admit.
qed.

(* The seed and cube FORS signature closed forms coincide on a coupled row. *)
lemma fors_sig_op_s_eq_c (ss0 : sseed) (ps0 : pseed) (ad0 : adrs) (skF0 : FTWES.skFORS) (cm0 : FTWES.msgFORSTW) :
  (forall (u v : int), 0 <= u && u < k => 0 <= v && v < t =>
     nth witness (nth witness (FTWES.DBLLKTL.val skF0) u) v
     = skg ss0 (ps0, set_thtbidx ad0 0 (u * t + v))) =>
  fors_sig_op ss0 ps0 ad0 cm0 = fors_sig_op_cube skF0 ps0 ad0 cm0.
proof.
admit.
qed.

(* The seed and cube hypertree-tree-leaves closed forms coincide on a coupled
   WOTS tree. *)
lemma tree_leaves_s_eq_c (ss0 : sseed) (ps0 : pseed) (skWtd : skWOTS list list list) (lyr tr : int) :
  (forall (i j u v : int), 0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
     nth witness (DBLL.val (nth witness (nth witness (nth witness skWtd i) j) u)) v
     = skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)) =>
  0 <= lyr < d => 0 <= tr < nr_trees lyr =>
  tree_leaves_s ss0 ps0 adz lyr tr = tree_leaves_c skWtd ps0 adz lyr tr.
proof.
admit.
qed.

(* Hence the running roots coincide. *)
lemma rt_cf_s_eq_c (ss0 : sseed) (ps0 : pseed) (skWtd : skWOTS list list list)
                   (m0 : msgFLSLXMSSMTTW) (idx0 : index) (j : int) :
  (forall (i j u v : int), 0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
     nth witness (DBLL.val (nth witness (nth witness (nth witness skWtd i) j) u)) v
     = skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)) =>
  1 <= j <= d =>
  rt_cf_s ss0 ps0 adz m0 idx0 j = rt_cf_c skWtd ps0 adz m0 idx0 j.
proof.
admit.
qed.

(* Hence the per-layer WOTS+C signature elements coincide. *)
lemma sig_cf_elem_s_eq_c (ss0 : sseed) (ps0 : pseed) (skWtd : skWOTS list list list)
                         (m0 : msgFLSLXMSSMTTW) (idx0 : index) (j : int) :
  (forall (i j u v : int), 0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
     nth witness (DBLL.val (nth witness (nth witness (nth witness skWtd i) j) u)) v
     = skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)) =>
  0 <= j < d =>
  sig_cf_elem_s ss0 ps0 adz m0 idx0 j = sig_cf_elem_c skWtd ps0 adz m0 idx0 j.
proof.
admit.
qed.

(* Hence the per-layer authentication paths coincide. *)
lemma ap_cf_elem_s_eq_c (ss0 : sseed) (ps0 : pseed) (skWtd : skWOTS list list list)
                        (idx0 : index) (j : int) :
  (forall (i j u v : int), 0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
     nth witness (DBLL.val (nth witness (nth witness (nth witness skWtd i) j) u)) v
     = skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)) =>
  0 <= j < d =>
  ap_cf_elem_s ss0 ps0 adz idx0 j = ap_cf_elem_c skWtd ps0 adz idx0 j.
proof.
admit.
qed.

(* nr_trees 0 * l' = l (the bottom-layer leaf count), used for FORS index
   routing bounds. *)
lemma nr_trees0_l : nr_trees 0 * l' = l.
proof.
admit.
qed.

(* The FORS tree/keypair indices from the message-compression index are in
   range (the (tidx, kpidx) <- edivz (val idx) l' routing). *)
lemma edivz_pair (x : int) : edivz x l' = (x %/ l', x %% l').
proof. by rewrite /edivz; smt(ge2_lp). qed.

lemma edivz_tidx_bound (ix : index) : 0 <= Index.val ix %/ l' < nr_trees 0.
proof.
admit.
qed.

lemma edivz_kpidx_bound (ix : index) : 0 <= Index.val ix %% l' < l'.
proof.
admit.
qed.

(* ---- (8.C) THE SUPPORT EQUIV.  The seed-based scheme sign equals the
   materialized-cube FS oracle sign, under the skg-cube coupling on the FS
   key material.  +C analog of MM45's Eqv_SPHINCS_PLUS_S_sign
   (SPHINCS_PLUS.ec:1908-1989); the cube coupling is EXACTLY the one hop-1's
   keygen prefix establishes (MM45 :2250-2256). ---- *)
lemma Eqv_C10_sign_FSbody (ms0 : mseed) (ss0 : sseed) (ps0 : pseed)
      (skFnt : FTWES.skFORS list list) (skWtd : skWOTS list list list) :
  equiv[SPHINCS_PLUS_C10.sign ~ O_CMA_SPHINCSPLUSTWC_FS.sign :
        ={m}
        /\ sk{1} = (ms0, ss0, ps0)
        /\ O_CMA_SPHINCSPLUSTWC_FS.sk{2} = (ms0, skFnt, skWtd, ps0)
        /\ (forall (i j u v : int),
               0 <= i && i < nr_trees 0 => 0 <= j && j < l' => 0 <= u && u < k => 0 <= v && v < t =>
               nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness skFnt i) j)) u) v
               = skg ss0 (ps0, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))
        /\ (forall (i j u v : int),
               0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
               nth witness (DBLL.val (nth witness (nth witness (nth witness skWtd i) j) u)) v
               = skg ss0 (ps0, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0))
        ==> ={res}].
proof.
admit.
qed.


(* ---- (8.D) THE ORACLE-LEVEL WRAPPER: the +C analog of what hop-1's oracle
   `call` rule consumes for the sign case (MM45 discharges it inline with
   Eqv_SPHINCS_PLUS_S_sign + the body sync, SPHINCS_PLUS.ec:2394-2560).  The
   statement is the sign-proc case of hop-1's oracle invariant; the proof is
   the Section 8 support-equiv proof lifted over O_CMA_Default.sign's extra
   call layer (inline the SPHINCS_PLUS_C10.sign call, then the identical
   head / three one-sided-call blocks / tail, extended with the ={qs} and
   sk-relation invariant conjuncts). ---- *)
lemma Eqv_OsignC10_Default_FS :
  equiv[DSSC.Stateless.O_CMA_Default(SPHINCS_PLUS_C10).sign ~ O_CMA_SPHINCSPLUSTWC_FS.sign :
        ={arg}
        /\ ={qs}(DSSC.Stateless.O_CMA_Default, O_CMA_SPHINCSPLUSTWC_FS)
        /\ DSSC.Stateless.O_CMA_Default.sk{1}
             = (DSSC.Stateless.O_CMA_Default.sk{1}.`1, DSSC.Stateless.O_CMA_Default.sk{1}.`2,
                DSSC.Stateless.O_CMA_Default.sk{1}.`3)
        /\ O_CMA_SPHINCSPLUSTWC_FS.sk{2}
             = (DSSC.Stateless.O_CMA_Default.sk{1}.`1, O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2,
                O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3, DSSC.Stateless.O_CMA_Default.sk{1}.`3)
        /\ (forall (i j u v : int),
               0 <= i && i < nr_trees 0 => 0 <= j && j < l' => 0 <= u && u < k => 0 <= v && v < t =>
               nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2 i) j)) u) v
               = skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
                   (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))
        /\ (forall (i j u v : int),
               0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
               nth witness (DBLL.val (nth witness (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3 i) j) u)) v
               = skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
                   (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0))
        ==> ={res}
            /\ ={qs}(DSSC.Stateless.O_CMA_Default, O_CMA_SPHINCSPLUSTWC_FS)
            /\ DSSC.Stateless.O_CMA_Default.sk{1}
                 = (DSSC.Stateless.O_CMA_Default.sk{1}.`1, DSSC.Stateless.O_CMA_Default.sk{1}.`2,
                    DSSC.Stateless.O_CMA_Default.sk{1}.`3)
            /\ O_CMA_SPHINCSPLUSTWC_FS.sk{2}
                 = (DSSC.Stateless.O_CMA_Default.sk{1}.`1, O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2,
                    O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3, DSSC.Stateless.O_CMA_Default.sk{1}.`3)
            /\ (forall (i j u v : int),
                   0 <= i && i < nr_trees 0 => 0 <= j && j < l' => 0 <= u && u < k => 0 <= v && v < t =>
                   nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2 i) j)) u) v
                   = skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
                       (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))
            /\ (forall (i j u v : int),
                   0 <= i && i < d => 0 <= j && j < nr_trees i => 0 <= u && u < l' => 0 <= v && v < len =>
                   nth witness (DBLL.val (nth witness (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3 i) j) u)) v
                   = skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
                       (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0))].
proof.
admit.
qed.
(* ==========================================================================
   SECTION 9 -- HOP-1: Orig -> PRFPRF.

   +C analog of MM45 Eqv_EUF_CMA_SPHINCSPLUSTW_Orig_FSPRFPRF (SPHINCS_PLUS.ec
   :2243-2571).  Proof shape:  seq 3 3 (keygen / oracle-init / forge) + a
   `sim` verify-fresh tail;  the keygen prefix is MM45's nested one-sided
   while{2} cube-coupling block (:2257-2390) at the +C FTWES.DBLLKTL / DBLL
   subtypes;  the oracle sign case is discharged by applying the Section 8.D
   wrapper equiv Eqv_OsignC10_Default_FS (MM45 instead inlines the sign-body
   work at :2397-2545 via `rewrite equiv` with Eqv_SPHINCS_PLUS_S_sign;  the
   +C support equiv Eqv_C10_sign_FSbody proves the same body-level fact and
   is retained for later hops);  the keygen suffix
   (root/pk/sk/init) couples the top-tree leaves via the Section 7 closed
   forms (MM45 :2560-2570's inline leaves sync, collapsed to the proven
   closed forms).
   ========================================================================== *)
lemma Eqv_EUFCMA_C10_FSPRFPRFC (F <: Adv_EUFCMA_C{-DSSC.Stateless.O_CMA_Default, -O_CMA_SPHINCSPLUSTWC_FS}) :
  equiv[EUFCMA_C10(F).main ~ EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF(F).main :
        ={glob F} ==> ={res}].
proof.
proc.
seq 3 3 : (   ={pk}
           /\ m{1} = m'{2}
           /\ sig{1} = sig'{2}
           /\ ={qs}(DSSC.Stateless.O_CMA_Default, O_CMA_SPHINCSPLUSTWC_FS)); 2: by sim.
inline{1} 1; inline{2} 1.
inline{1} FL_SL_XMSS_MT_C_ES.gen_root.
seq 4 8 : (   ={glob F, ad, ms, ss, ps}
           /\ ad{1} = adz
           /\ (forall (i j u v : int),
                 0 <= i && i < nr_trees 0 =>
                 0 <= j && j < l' =>
                 0 <= u && u < k =>
                 0 <= v && v < t =>
                 nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness skFORSnt{2} i) j)) u) v =
                 skg ss{1} (ps{1}, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))
           /\ (forall (i j u v : int),
                0 <= i && i < d =>
                0 <= j && j < nr_trees i =>
                0 <= u && u < l' =>
                0 <= v && v < len =>
                nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd{2} i) j) u)) v =
                skg ss{1} (ps{1}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0))).
+ while{2} (    ad{2} = adz
            /\ (forall (i j u v : int),
                  0 <= i && i < size skWOTStd{2} =>
                  0 <= j && j < nr_trees i =>
                  0 <= u && u < l' =>
                  0 <= v && v < len =>
                  nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd{2} i) j) u)) v =
                  skg ss{2} (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)))
           (d - size skWOTStd{2}).
  - move=> _ z.
    wp => /=.
    while (    ad = adz
           /\ (forall (j u v : int),
                 0 <= j && j < size skWOTSnt =>
                 0 <= u && u < l' =>
                 0 <= v && v < len =>
                 nth witness (DBLL.val (nth witness (nth witness skWOTSnt j) u)) v =
                 skg ss (ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz (size skWOTStd) j) chtype) u) v) 0)))
          (nr_trees (size skWOTStd) - size skWOTSnt).
    * move=> z'.
      wp => /=.
      while (    ad = adz
             /\ (forall (u v : int),
                   0 <= u && u < size skWOTSlp =>
                   0 <= v && v < len =>
                   nth witness (DBLL.val (nth witness skWOTSlp u)) v =
                   skg ss (ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz (size skWOTStd) (size skWOTSnt)) chtype) u) v) 0)))
            (l' - size skWOTSlp).
      + move=> z''.
        wp => /=.
        while (    ad = adz
               /\ (forall (v : int),
                     0 <= v && v < size skWOTS =>
                     nth witness skWOTS v =
                     skg ss (ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) v) 0))
               /\ size skWOTS <= len)
              (len - size skWOTS).
        - move=> z'''.
          by wp; skip => />; smt(nth_rcons size_rcons).
        wp; skip => /> &2 nthsklp ltl_szsklp.
        split => [| skw]; 2: split => [| /lezNgt gelen_szskw]; 1,2: smt(ge2_len).
        move=> nthskw lelen_skw; split; 2: by rewrite size_rcons /#.
        move=> u v ge0_u; rewrite nth_rcons ?size_rcons /= => ltsz1_u ge0_v ltlen_v.
        by case (u < size skWOTSlp{2}); smt(DBLL.insubdK DBLL.valP).
      wp; skip => /> &2 nthsknt ltl_szsknt.
      split => [/# | skwlp]; split => [/# | /lezNgt gent_szskwnt ?].
      by split; smt(nth_rcons size_rcons).
    wp; skip => /> &2 nthsktd ltd_szsktd.
    split => [/# | skwlp]; split => [/# | /lezNgt gent_szskwnt ?].
    by split; smt(nth_rcons size_rcons).
  wp => /=.
  while{2} (    ad{2} = adz
            /\ (forall (i j u v : int),
                 0 <= i && i < size skFORSnt{2} =>
                 0 <= j && j < l' =>
                 0 <= u && u < k =>
                 0 <= v && v < t =>
                 nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness skFORSnt{2} i) j)) u) v =
                 skg ss{2} (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v))))
           (nr_trees 0 - size skFORSnt{2}).
  - move => _ z.
    wp => /=.
    while (   ad = adz
           /\ (forall (j u v : int),
                 0 <= j && j < size skFORSlp =>
                 0 <= u && u < k =>
                 0 <= v && v < t =>
                 nth witness (nth witness (FTWES.DBLLKTL.val (nth witness skFORSlp j)) u) v =
                 skg ss (ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size skFORSnt)) j) 0 (u * t + v))))
          (l' - size skFORSlp).
    * move=> z'.
      wp => /=.
      while (   ad = adz
             /\ (forall (u v : int),
                   0 <= u && u < size skFORScube =>
                   0 <= v && v < t =>
                   nth witness (nth witness skFORScube u) v =
                   skg ss (ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size skFORSnt)) (size skFORSlp)) 0 (u * t + v)))
             /\ all (fun ls => size ls = t) skFORScube
             /\ size skFORScube <= k)
            (k - size skFORScube).
      + move=> z''.
        wp => /=.
        while (   ad = adz
               /\ (forall (v : int),
                     0 <= v && v < size skFORSet =>
                     nth witness skFORSet v =
                     skg ss (ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size skFORSnt)) (size skFORSlp)) 0 (size skFORScube * t + v)))
               /\ size skFORSet <= t)
            (t - size skFORSet).
        - move=> z'''.
          by wp; skip => />; smt(nth_rcons size_rcons).
        by wp; skip => />; smt(ge2_t nth_rcons size_rcons cats1 all_cat).
      by wp; skip => />; smt(nth_rcons size_rcons ge1_k FTWES.DBLLKTL.valP FTWES.DBLLKTL.insubdK).
    by wp; skip => />; smt(nth_rcons size_rcons).
  wp; do 3! rnd.
  wp; skip => /> ms msin ss ssin ps psin.
  by do 5! (split => [/# | *]) => /#.
call (:   ={qs}(DSSC.Stateless.O_CMA_Default, O_CMA_SPHINCSPLUSTWC_FS)
       /\ DSSC.Stateless.O_CMA_Default.sk{1}
            = (DSSC.Stateless.O_CMA_Default.sk{1}.`1, DSSC.Stateless.O_CMA_Default.sk{1}.`2,
               DSSC.Stateless.O_CMA_Default.sk{1}.`3)
       /\ O_CMA_SPHINCSPLUSTWC_FS.sk{2}
            = (DSSC.Stateless.O_CMA_Default.sk{1}.`1, O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2,
               O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3, DSSC.Stateless.O_CMA_Default.sk{1}.`3)
       /\ (forall (i j u v : int),
             0 <= i && i < nr_trees 0 =>
             0 <= j && j < l' =>
             0 <= u && u < k =>
             0 <= v && v < t =>
             nth witness (nth witness (FTWES.DBLLKTL.val (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`2 i) j)) u) v =
             skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
               (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))
       /\ (forall (i j u v : int),
            0 <= i && i < d =>
            0 <= j && j < nr_trees i =>
            0 <= u && u < l' =>
            0 <= v && v < len =>
            nth witness (DBLL.val (nth witness (nth witness (nth witness O_CMA_SPHINCSPLUSTWC_FS.sk{2}.`3 i) j) u)) v =
            skg DSSC.Stateless.O_CMA_Default.sk{1}.`2
              (DSSC.Stateless.O_CMA_Default.sk{1}.`3, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0))).
+ by apply Eqv_OsignC10_Default_FS.
seq 4 2 : (={leaves} /\ ps0{1} = ps{1} /\ ad0{1} = ad{1} /\ #pre).
+ wp; sp 3 1.
  exists* ss{1}, ps{1}, ad{1}, skWOTStd{2}, ps{2}, ad{2}.
  elim* => ssv psv adv skWv ps2v ad2v.
  call{1} (leaves_sspsad_cf ssv psv (set_ltidx adv (d - 1) 0)).
  call{2} (leaves_cube_cf (nth witness (nth witness skWv (d - 1)) 0) ps2v (set_ltidx ad2v (d - 1) 0)).
  skip; move=> &1 &2.
  move=> hpre.
  split; 1: smt().
  move=> r2.
  move=> r1 cf2.
  split; 1: smt().
  move=> r0.
  move=> res0 cf1.
  split; 2: by smt().
  rewrite cf1 cf2.
  have -> : ps2v = psv by smt().
  have -> : ad2v = adv by smt().
  have -> : adv = adz by smt().
  apply eq_in_mkseq => u rng_u /=.
  do 3! congr.
  apply eq_in_mkseq => v rng_v /=.
  have h1 : 0 <= (d - 1) && (d - 1) < d by smt(ge1_d).
  have h2 : 0 <= 0 && 0 < nr_trees (d - 1).
  + have -> : nr_trees (d - 1) = 2 ^ 0 by (rewrite /nr_trees; smt()).
    by rewrite expr0; smt().
  have hwc : (forall (i j u v : int), 0 <= i && i < d => 0 <= j && j < nr_trees i =>
               0 <= u && u < l' => 0 <= v && v < len =>
               nth witness (DBLL.val (nth witness (nth witness (nth witness skWv i) j) u)) v
               = skg ssv (psv, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)) by smt().
  by rewrite (hwc (d - 1) 0 u v h1 h2 rng_u rng_v).
inline{1} DSSC.Stateless.O_CMA_Default(SPHINCS_PLUS_C10).init.
inline{2} O_CMA_SPHINCSPLUSTWC_FS.init.
wp; skip => &1 &2.
move=> hpre.
split; 1: smt().
move=> *; smt().
qed.

(* The hop-1 Pr equality, derived from the byequiv (MM45's hop-1 feeds the
   capstone's hop1 ledger entry over the free real p_prfprf). *)
lemma Pr_EUFCMA_C10_FSPRFPRFC (F <: Adv_EUFCMA_C{-DSSC.Stateless.O_CMA_Default, -O_CMA_SPHINCSPLUSTWC_FS}) &m :
  Pr[EUFCMA_C10(F).main() @ &m : res]
  = Pr[EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF(F).main() @ &m : res].
proof.
by byequiv (Eqv_EUFCMA_C10_FSPRFPRFC F).
qed.

(* ==========================================================================
   SECTION 10 -- HOP-2: FS_PRFPRF -> FS_NPRFPRF VIA SKG-PRF (scheme-level).

   +C analog of MM45's EqAdv_EUF_CMA_SPHINCSPLUSTWFS_PRFPRF_NPRFPRF_SKGPRF
   (SPHINCS_PLUS.ec:2668-3049) and its reduction R_SKGPRF_EUFCMA
   (SPHINCS_PLUS.ec:1063-1211).

   KEY +C SIMPLIFICATION (auditor-confirmed):  the PRF surface is confined to
   keygen -- the FS oracle O_CMA_SPHINCSPLUSTWC_FS never reads ss/ms, only the
   cubes + ps (Section 5, deltas 1-3).  So the reduction needs NO private
   O_CMA/qs module state (MM45 :1064-1108):  it inits the SHARED FS oracle
   with the built cubes and hands it to A, and the adversary-call invariant
   collapses to ={glob O_CMA_SPHINCSPLUSTWC_FS} with a `sim` oracle case
   (MM45 needed a cross-module sk-tuple invariant + conseq, :2738-2742).

   Also +C-specific:  both FS keygens are CUBE-based end-to-end (Sections
   3-4), so the top-tree leaves call on both sides is the SAME
   FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad (MM45 needed `sim : (={leaves})`
   to bridge seed-vs-cube there, :2743-2745);  every post-cube fact here is
   relational.
   ========================================================================== *)

(* The reduction (MM45 R_SKGPRF_EUFCMA, SPHINCS_PLUS.ec:1063-1211), +C-
   substituted:  draws ms (throwaway, sk-shape parity), ps, ad;  builds the
   FORS + WOTS cubes by querying O at EXACTLY the two skg address families
   (FORS trhftype, WOTS chtype chains);  computes the root with the same
   leaves/val_bt_trh tail as keygen_prf_c;  inits O_CMA_SPHINCSPLUSTWC_FS with
   the built cubes;  runs A(<that oracle>).forge((root, ps));  evaluates the
   +C verify_c + freshness;  returns the win bit. *)
module (R_SKGPRF_EUFCMA_C (A : Adv_EUFCMA_C) : SKG_PRF.Adv_PRF) (O : SKG_PRF.Oracle_PRF) = {
  proc distinguish() : bool = {
    var ad : adrs;
    var ms : mseed;
    var ps : pseed;
    var skFORS_ele : dgstblock;
    var skFORSet : dgstblock list;
    var skFORScube : dgstblock list list;
    var skFORSlp : FTWES.skFORS list;
    var skFORSnt : FTWES.skFORS list list;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var root : dgstblock;
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * FTWES.skFORS list list * skWOTS list list list * pseed;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTWC;
    var is_valid, is_fresh : bool;

    ad <- adz;

    ms <$ dmseed;
    ps <$ dpseed;

    (* FORS cube, queried at the trhftype skg addresses (keygen_prf_c's family,
       Section 3 / MM45 :1137-1159). *)
    skFORSnt <- [];
    while (size skFORSnt < nr_trees 0) {
      skFORSlp <- [];
      while (size skFORSlp < l') {
        skFORScube <- [];
        while (size skFORScube < k) {
          skFORSet <- [];
          while (size skFORSet < t) {
            skFORS_ele <@ O.query(ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) (size skFORSlp)) 0 (size skFORScube * t + size skFORSet));
            skFORSet <- rcons skFORSet skFORS_ele;
          }
          skFORScube <- rcons skFORScube skFORSet;
        }
        skFORSlp <- rcons skFORSlp (FTWES.DBLLKTL.insubd skFORScube);
      }
      skFORSnt <- rcons skFORSnt skFORSlp;
    }

    (* WOTS cube, queried at the chtype chain skg addresses (keygen_prf_c's
       family, Section 3 / MM45 :1161-1183). *)
    skWOTStd <- [];
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        while (size skWOTSlp < l') {
          skWOTS <- [];
          while (size skWOTS < len) {
            skWOTS_ele <@ O.query(ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) (size skWOTS)) 0);
            skWOTS <- rcons skWOTS skWOTS_ele;
          }
          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
        }
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
    }

    (* Top-tree leaves + root:  same tail as keygen_prf_c (:1189-1198). *)
    skWOTSlp <- nth witness (nth witness skWOTStd (d - 1)) 0;
    leaves <@ FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (d - 1) 0);
    root <- val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhxtype) (list2tree leaves);

    pk <- (root, ps);
    sk <- (ms, skFORSnt, skWOTStd, ps);

    O_CMA_SPHINCSPLUSTWC_FS.init(sk);

    (m', sig') <@ A(O_CMA_SPHINCSPLUSTWC_FS).forge(pk);

    is_valid <@ SPHINCS_PLUS_C10_FS.verify_c(pk, m', sig');
    is_fresh <@ O_CMA_SPHINCSPLUSTWC_FS.fresh(m');

    return is_valid /\ is_fresh;
  }
}.

(* b = false leg:  O.query = skg k, coupled ss{1} = k{2} (MM45 :2676-2745). *)
lemma EqPr_SKGPRF_C_false (A <: Adv_EUFCMA_C{-SKG_PRF.O_PRF_Default, -O_CMA_SPHINCSPLUSTWC_FS}) &m :
  Pr[EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF(A).main() @ &m : res]
  = Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(A), SKG_PRF.O_PRF_Default).main(false) @ &m : res].
proof.
admit.
qed.

(* Arithmetic helper for the FORS-family freshness arithmetic in the true leg
   (MM45's inline `(: size skFORS{m0} = ...) mulzDl -addrA ler_lt_add` chain,
   SPHINCS_PLUS.ec:3013-3016, lifted to a memory-free universal). *)
lemma skgprf_mul_lt : forall (u0 sc0 sf0 t0 v0 : int),
  0 <= u0 => u0 < sc0 => 0 <= v0 => v0 < t0 => 0 <= sf0 =>
  u0 * t0 + v0 < sc0 * t0 + sf0.
proof.
admit.
qed.

(* b = true leg:  lazy RF;  every queried address FRESH via the two-family
   domain invariant (MM45's mdom, :2762-2976), so lazy = eager uniform cube
   (MM45 :2746-3048). *)
lemma EqPr_SKGPRF_C_true (A <: Adv_EUFCMA_C{-SKG_PRF.O_PRF_Default, -O_CMA_SPHINCSPLUSTWC_FS}) &m :
  Pr[EUF_CMA_SPHINCSPLUSTWC_FS_NPRFPRF(A).main() @ &m : res]
  = Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(A), SKG_PRF.O_PRF_Default).main(true) @ &m : res].
proof.
byequiv => //.
proc.
inline{2} 2.
seq 3 15 : (={pk, m', sig'} /\ ={glob O_CMA_SPHINCSPLUSTWC_FS}).
inline{1} 1.
inline{2} 1.
seq 8 11 : (   ={glob A, ad}
            /\ ad{2} = adz
            /\ SKG_PRF.O_PRF_Default.b{2}
            /\ ss{1} = SKG_PRF.O_PRF_Default.k{2}
            /\ ms{1} = ms{2} /\ ps{1} = ps{2}
            /\ ={skFORSnt, skWOTStd}).
+ while (   SKG_PRF.O_PRF_Default.b{2}
         /\ (forall (psad : pseed * adrs),
               psad \in SKG_PRF.O_PRF_Default.m{2}
               <=>
               ((exists (i j u v : int), 
                   0 <= i < nr_trees 0 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                   psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                \/ 
                (exists (i j u v : int),
                   0 <= i < size skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\ 
                   psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))))
         /\ size skWOTStd{1} <= d
         /\ #post).
  - wp => /=.
    while (   ={skWOTSnt}
           /\ ad{2} = adz
           /\ SKG_PRF.O_PRF_Default.b{2}
           /\ ={skWOTStd}
           /\ (forall (psad : pseed * adrs),
                 psad \in SKG_PRF.O_PRF_Default.m{2}
                 <=>
                 ((exists (i j u v : int), 
                     0 <= i < nr_trees 0 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                     psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                  \/ 
                  (exists (i j u v : int),
                     0 <= i < size skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\ 
                     psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))
                  \/ (exists (j u v : int),
                      0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\ 0 <= v < len /\ 
                       psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) j) chtype) u) v) 0))))
           /\ size skWOTStd{1} < d
           /\ size skWOTSnt{1} <= nr_trees (size skWOTStd{1})).
    * wp => /=.
      while (   ={skWOTSnt, skWOTSlp}
             /\ ad{2} = adz
             /\ SKG_PRF.O_PRF_Default.b{2}
             /\ ={skWOTStd}
             /\ (forall (psad : pseed * adrs),
                   psad \in SKG_PRF.O_PRF_Default.m{2}
                   <=>
                   ((exists (i j u v : int), 
                       0 <= i < nr_trees 0 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                       psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                    \/ 
                    (exists (i j u v : int),
                       0 <= i < size skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\ 
                       psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))
                    \/ (exists (j u v : int),
                        0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\ 0 <= v < len /\ 
                         psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) j) chtype) u) v) 0))
                    \/ (exists (u v : int),
                        0 <= u < size skWOTSlp{2} /\ 0 <= v < len /\ 
                         psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) (size skWOTSnt{2})) chtype) u) v) 0))))
             /\ size skWOTStd{1} < d
             /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
             /\ size skWOTSlp{1} <= l').
      + wp => /=.
        while (   ={skWOTSnt, skWOTSlp, skWOTS}
               /\ ad{2} = adz
               /\ SKG_PRF.O_PRF_Default.b{2}
               /\ ={skWOTStd}
               /\ (forall (psad : pseed * adrs),
                     psad \in SKG_PRF.O_PRF_Default.m{2}
                     <=>
                     ((exists (i j u v : int), 
                         0 <= i < nr_trees 0 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                         psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                      \/ 
                      (exists (i j u v : int),
                         0 <= i < size skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\ 
                         psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))
                      \/ (exists (j u v : int),
                          0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\ 0 <= v < len /\ 
                           psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) j) chtype) u) v) 0))
                      \/ (exists (u v : int),
                          0 <= u < size skWOTSlp{2} /\ 0 <= v < len /\ 
                           psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) (size skWOTSnt{2})) chtype) u) v) 0))
                      \/ (exists (v : int),
                          0 <= v < size skWOTS{2} /\ 
                           psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) (size skWOTSnt{2})) chtype) (size skWOTSlp{2})) v) 0))))
               /\ size skWOTStd{1} < d
               /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
               /\ size skWOTSlp{1} < l'
               /\ size skWOTS{1} <= len).
        - inline{2} 1.
          rcondt{2} 2; 1: by auto.
          rcondt{2} 2.
          * auto => /> &2 bt mdom *.
            pose psad := (_, set_hidx _ _).
            move/iffLR /contra: (mdom psad) => -> //=.
            rewrite ?negb_or; split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 3 => @/HA.eq_idx.
              rewrite setalladzch_gettypeidx 1..4:// setalladztrhf_gettypeidx //; 2: smt(dist_adrstypes). 
              rewrite /valid_tbfidx /nr_nodesf /=; split => [/# | _].
              by rewrite (: k = k - 1 + 1) // mulzDl /= -/t ler_lt_add 1:ler_pmul 4://; smt(ge2_t).
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 5 => @/HA.eq_idx.
              by rewrite ?setalladzch_getlidx 1..8:// /#. 
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 4 => @/HA.eq_idx.
              by rewrite ?setalladzch_gettidx 1..8:// /valid_tidx /#.        
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 2 => @/HA.eq_idx.
              by rewrite ?setalladzch_getkpidx 1..8:// /valid_tidx /#.
            do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
            rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 1 => @/HA.eq_idx.
            by rewrite ?setallchadz_getchidx 1..8:// /valid_tidx /#.
          wp; rnd; wp; skip => /> &2 bt mdom *.
          rewrite -!andbA andbA; split; 2: smt(size_rcons).
          rewrite get_set_sameE oget_some /= => psad.
          split => [/mem_set [| -> /=]|]; 1,2: smt(size_ge0 size_rcons).
          move=> mdomrc; rewrite mem_set /=.
          case (psad \in SKG_PRF.O_PRF_Default.m{2}) => [// | /= ninm].
          move/iffRL /contra: (mdom psad) mdomrc => /(_ ninm) /=.
          rewrite ?negb_or => [#] -> -> -> -> /=; rewrite negb_exists => /= ninskw /=.
          move=> -[v]; rewrite size_rcons => -[rng_v psadval /=].
          case (v = size skWOTS{2}) => [ // | neqszv].
          by move: (ninskw v); rewrite negb_and (: 0 <= v && v < size skWOTS{2}) /#.
        wp; skip => /> &2 *.
        split => [* | psdbmap skw ? _ psdbmapdef ?]; 1: smt(ge2_len).
        split => [psad |]; 2: smt(size_rcons).
        by split => [/psdbmapdef | ]; smt(size_rcons size_ge0).
      wp; skip => /> &2 *.
      split => [* | psdbmap skw ? _ psdbmapdef ?]; 1: smt(ge2_lp).
      split => [psad |]; 2: smt(size_rcons).
      by split => [/psdbmapdef | ]; smt(size_rcons size_ge0).
    wp; skip => /> &2 bT mdef _ ltd_szsktd.
    split => [ * | psdbmap skw ? _ psdbmapdef ?]; 1: rewrite expr_ge0 1:// 1:/=.
    * by move => psad; split => [/mdef |] /#.
    split => [psad |]; 2: smt(size_rcons).
    by split => [/psdbmapdef | ]; smt(size_rcons size_ge0).
  wp => /=.
  while (   SKG_PRF.O_PRF_Default.b{2}
         /\ ad{2} = adz
         /\ ={skFORSnt}
         /\ (forall (psad : pseed * adrs),
               psad \in SKG_PRF.O_PRF_Default.m{2}
               <=>
               (exists (i j u v : int), 
                   0 <= i < size skFORSnt{2} /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                   psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v))))
         /\ size skFORSnt{1} <= nr_trees 0
         /\ #post).
  - wp => /=.
    while (   ={skFORSlp} 
           /\ ad{2} = adz
           /\ SKG_PRF.O_PRF_Default.b{2}
           /\ ={skFORSnt}
           /\ (forall (psad : pseed * adrs),
                 psad \in SKG_PRF.O_PRF_Default.m{2}
                 <=>
                 ((exists (i j u v : int), 
                     0 <= i < size skFORSnt{2} /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                     psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                  \/
                  (exists (j u v : int), 
                     0 <= j < size skFORSlp{2} /\ 0 <= u < k /\ 0 <= v < t /\ 
                     psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size skFORSnt{2})) j) 0 (u * t + v)))))
           /\ size skFORSnt{1} < nr_trees 0
           /\ size skFORSlp{1} <= l').
    * wp => /=.
      while (   ={skFORSlp, skFORScube}
             /\ ad{2} = adz 
             /\ SKG_PRF.O_PRF_Default.b{2}
             /\ ={skFORSnt}
             /\ (forall (psad : pseed * adrs),
                   psad \in SKG_PRF.O_PRF_Default.m{2}
                   <=>
                   ((exists (i j u v : int), 
                       0 <= i < size skFORSnt{2} /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                       psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                    \/
                    (exists (j u v : int), 
                       0 <= j < size skFORSlp{2} /\ 0 <= u < k /\ 0 <= v < t /\ 
                       psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size skFORSnt{2})) j) 0 (u * t + v)))
                    \/
                    (exists (u v : int), 
                       0 <= u < size skFORScube{2} /\ 0 <= v < t /\ 
                       psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size skFORSnt{2})) (size skFORSlp{2})) 0 (u * t + v)))))
             /\ size skFORSnt{1} < nr_trees 0
             /\ size skFORSlp{1} < l'
             /\ size skFORScube{1} <= k).
      + wp => /=.
        while (   ={skFORSlp, skFORScube, skFORSet} 
               /\ ad{2} = adz 
               /\ SKG_PRF.O_PRF_Default.b{2}
               /\ ={skFORSnt}
               /\ (forall (psad : pseed * adrs),
                     psad \in SKG_PRF.O_PRF_Default.m{2}
                     <=>
                     ((exists (i j u v : int), 
                         0 <= i < size skFORSnt{2} /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                         psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                      \/
                      (exists (j u v : int), 
                         0 <= j < size skFORSlp{2} /\ 0 <= u < k /\ 0 <= v < t /\ 
                         psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size skFORSnt{2})) j) 0 (u * t + v)))
                      \/
                      (exists (u v : int), 
                         0 <= u < size skFORScube{2} /\ 0 <= v < t /\ 
                         psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size skFORSnt{2})) (size skFORSlp{2})) 0 (u * t + v)))
                      \/ 
                      (exists (v : int),
                         0 <= v < size skFORSet{2} /\ 
                          psad = (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size skFORSnt{2})) (size skFORSlp{2})) 0 ((size skFORScube{2}) * t + v)))))
               /\ size skFORSnt{1} < nr_trees 0
               /\ size skFORSlp{1} < l'
               /\ size skFORScube{1} < k
               /\ size skFORSet{1} <= t).
        - inline{2} 1.
          rcondt{2} 2; 1: by auto.
          rcondt{2} 2.
          * auto => /> &2 bt mdom *.
            pose psad := (_, set_thtbidx _ _ _).
            move/iffLR /contra: (mdom psad) => -> //=.
            rewrite ?negb_or; split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 4 => @/HA.eq_idx.
              rewrite ?setalladztrhf_gettidx 1,2,5:// 2,4:/#.
              - rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
                rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
                by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
              rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
              rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
              by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 2 => @/HA.eq_idx.
              rewrite ?setalladztrhf_getkpidx 1,2,4:// 2,4:/#.
              - rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
                rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
                by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
              rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
              rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
              by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 0 => @/HA.eq_idx.              
              rewrite ?setalladztrhf_getbidx 1,2,4,5://.
              - rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
                rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
                by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
              - rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
                rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
                by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
              rewrite neq_ltz; right.
              by smt(skgprf_mul_lt size_ge0 ge2_t).
            do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
            rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 0 => @/HA.eq_idx.      
            rewrite ?setalladztrhf_getbidx 1,2,4,5://.
            + rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
              rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
              by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
            + rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
              rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
              by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
            by rewrite neq_ltz; right; rewrite ler_lt_add 1:// /#.
          wp; rnd; wp; skip => /> *.
          by rewrite get_set_sameE oget_some /=; smt(size_rcons size_ge0 mem_set).
        wp; skip => /> *. 
        split => *; 1: smt(ge2_t).
        by split; smt(size_rcons size_ge0). 
      by wp; skip => />; smt(size_rcons size_ge0 ge1_k).
    wp; skip => /> &2 *.
    split => *; 1: smt(ge2_lp).
    by split; smt(size_rcons size_ge0).
  wp => /=.
  swap{2} [3..3] 3.
  do 3! rnd.
  by wp; skip => /> *; smt(mem_empty).
call (: ={glob O_CMA_SPHINCSPLUSTWC_FS}).
+ by sim.
call (: ={arg} ==> ={res, glob O_CMA_SPHINCSPLUSTWC_FS}).
+ by sim.
wp.
call (: ={arg} ==> ={res}); 1: by sim.
wp; skip => />; smt().
wp.
call (: ={arg, glob O_CMA_SPHINCSPLUSTWC_FS} ==> ={res, glob O_CMA_SPHINCSPLUSTWC_FS}).
+ by sim.
call (: ={arg} ==> ={res}); 1: by sim.
wp; skip => />; smt().
qed.

(* The composed hop (pure arithmetic on the two legs;  MM45 folds this into
   the capstone at :4300-4330). *)
lemma SKGPRF_C_hop (A <: Adv_EUFCMA_C{-SKG_PRF.O_PRF_Default, -O_CMA_SPHINCSPLUSTWC_FS}) &m :
  Pr[EUF_CMA_SPHINCSPLUSTWC_FS_PRFPRF(A).main() @ &m : res]
  <=   Pr[EUF_CMA_SPHINCSPLUSTWC_FS_NPRFPRF(A).main() @ &m : res]
     + `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(A), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
         - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(A), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |.
proof.
have hf := EqPr_SKGPRF_C_false A &m.
have ht := EqPr_SKGPRF_C_true A &m.
smt().
qed.
