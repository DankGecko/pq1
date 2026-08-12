(* ==========================================================================
   sphincs_c10_capstone_concrete_wip.ec -- SPHINCS+C10 EUF-CMA CAPSTONE, the
   CONCRETE-LHS variant of sphincs_c10_capstone_wip.ec.

   THE ONLY DIFFERENCE from the committed capstone: the LHS is no longer the
   abstract real `p_sphincs_c`.  This file INLINES the concrete scheme +
   game (module SPHINCS_PLUS_C10 : DSSC.Stateless.Scheme + EUFCMA_C10, verbatim
   from sphincs_c10_scheme_wip.ec, since a lowercase WIP cannot be `require`d) and
   re-grounds the bound as `Pr[EUFCMA_C10(F).main() @ &m : res] <= <same RHS>`.
   The 6 FX hops remain EXACTLY the same admits (hop1 is merely re-typed so its
   LHS is the concrete game); admit count unchanged (6).  Everything else --
   the two proven legs (hF, hHT), the carried premises, the ledger below -- is
   identical to the committed capstone.  Do NOT read the `qed` as a proof.

   ROLE = BUILD / ASSEMBLE.  States the top-level SPHINCS+C10 EUF-CMA bound in
   MM45's `EUFCMA_SPHINCS_PLUS_FX` 4-term shape (SPHINCS_PLUS.ec:4287), with the
   two paper-2022/778 Thm-5.2 +C substitutions, wired term-by-term to the PROVEN
   base-A leg theorems where one exists and ADMITTED (with a precise in-file
   residual) on each +C-transcription leg that is not yet built.

       MM45 FX term                         +C substitution (this file)
       -----------------------------------  -----------------------------------
       |SKG-PRF adv|                        |SKG-PRF adv|  (+C-invariant, carried)
       |MKG-PRF adv|                        |MKG-PRF adv|  (+C-invariant, carried)
       Pr[EUF_CMA_MFORSTWESNPRF ...]   -->   FORS+C10 multi bound  (M.EUFCMA_MFORSC10,
                                             FORS_C10_Multi.ec:472) EXPANDED to
                                             Pr[ITSRC10 ...] + mtree_{openpre,trh,trco}
       Pr[EUF_NAGCMA_FLSLXMSSMTTWESNPRF...] -> the +C COMPONENT THEOREM
                                             (EUFNAGCMA_FLSLXMSSMTTWCESNPRF,
                                             XmssmtCC_All.ec:8439) EXPANDED to
                                             WOTS-TW+C multi + S-TCR(+C) + pkco-TCR
                                             + trh-TCR, applied at A_ht := R_top(F).

   ==========================================================================
   THE LEDGER  --  READ THIS BEFORE READING THE COMPILING THEOREM.

   This file COMPILES (typechecks) WITH ADMITS.  It is NOT an unconditional
   proof of SPHINCS+C10 EUF-CMA security.  The correct claim is:

     "SPHINCS+C10 EUF-CMA REDUCES to {the ledger below}, machine-checked modulo
      the explicitly-admitted +C-invariant MM45-transcription legs."

   Do NOT read the `qed` as "SPHINCS+C is proven".

   ------ (0) LHS NATURE  (CONCRETE in this variant) --------------------------
   RESOLVED in this file: the concrete `module SPHINCS_PLUS_C10 :
   DSSC.Stateless.Scheme` and its generic game `EUFCMA_C10(F) =
   DSSC.Stateless.EUF_CMA(SPHINCS_PLUS_C10, F, DSSC.Stateless.O_CMA_Default)` ARE
   built below (inlined from sphincs_c10_scheme_wip.ec).  The capstone LHS is now
   the CONCRETE advantage `Pr[EUFCMA_C10(F).main() @ &m : res]`, NOT the abstract
   real `p_sphincs_c`.  The +C forger TYPE `Adv_EUFCMA_C` (XmssmtCC_All.ec:9428)
   is the game adversary (structural-subtypes the DSSC clone's Adv_EUFCMA).  The
   scheme is MM45 `module SPHINCS_PLUS` (SPHINCS_PLUS.ec:957) at the SAME seed sk,
   with the two Thm-5.2 substitutions ((i) FORS message key
   `mk <$ dcond dmkey (good_fors m)`, seed-based FTWES FORS; (ii) +C hypertree
   FL_SL_XMSS_MT_C_ES).  HONEST CAVEAT: `dcond` idealises the real keyed mk (mkg),
   so this LHS sits at the real-key / IDEALISED-mk level, not a genuine pre-MKG
   Orig (`ms` dead, MKG hop vacuous, signing randomised) -- see the scheme file's
   LEDGER.  What REMAINS the residual is MM45's FX PROOF over this scheme (the 6
   hops below, section-local, multi-month) -- NOT the scheme OBJECT, which now
   exists.

   ------ (1) ADMIT CENSUS  (the open + transcription legs) --------------------
   SIX `admit`s in this file (`hop1`..`hop6`), one per MM45 FX game hop that
   connects the abstract SPHINCS+C10 forgery probability, through the (unbuilt)
   +C intermediate game probabilities p_prfprf/p_nprfprf/p_nprfnprf/p_vt/p_vf, to
   the two RHS game-terms that the proven legs then expand.  The intermediate
   reals are FREE (their +C games are not built), so each hop-inequality is an
   admit -- that is precisely the honest statement "this MM45 hop's +C analog is
   not machine-checked here".  Each hop, its MM45 line, its +C status, its
   residual invariant:

     [genuinely-open]  Orig -> PRFPRF (MM45 byequiv Eqv_..._Orig_FSPRFPRF
        SPHINCS_PLUS.ec:2243, consumed :4304).  +C analog = the on-demand ->
        materialized bridge `Eqv_ondemand_materialized`, NAMED-but-unproved
        (prf_hop_wip.ec:614-625).  Missing: the deterministic-recomputation
        equivalence for the +C cube.

     [PARTIAL/transcription]  SKG-PRF hop (MM45 EqAdv_..._PRFPRF_NPRFPRF_SKGPRF
        SPHINCS_PLUS.ec:2668, consumed :4312).  +C `SKGPRF_hop` /
        `SKGPRF_hop_composed` PROVEN (0-admit) at the HYPERTREE level
        (prf_hop_wip.ec:542/558, CERTIFIED-0-ADMIT).  Missing at scheme level:
        the SKG term additionally covers the FORS+C secret keys
        (prf_hop_wip.ec:655-656).

     [genuinely-open]  MKG-PRF hop (MM45 EqAdv_..._NPRFPRF_NPRFNPRF_MKGPRF
        SPHINCS_PLUS.ec:3055, consumed :4320).  NO +C module; the +C-invariant
        scheme-level term `mkg_adv` is a separate accounted term
        (SPHINCS_C_c10.ec:195/210, rtop_c_soundness_wip.ec:114-120).

     [genuinely-open]  NPRFNPRF -> V + mu_split (MM45 byequiv Eqv_..._NPRFNPRF_V
        SPHINCS_PLUS.ec:2572 + Pr[mu_split] :4327, consumed :4326-4327).  The
        +C V_C game exists (EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V,
        rtop_c_soundness_wip.ec:326) but the Orig->V byequiv + mu_split are not
        built here.

     [genuinely-open]  VT / hop-5 (MM45 LeqPr_..._VT_MFORSTWESNPRF
        SPHINCS_PLUS.ec:3129, consumed :4328).  This is the branch that lands on
        M.EUFCMA_MFORSC10.  Missing: a reduction from `Adv_EUFCMA_C` to
        `M.Adv_EUFCMA_MFORSC10` (NONE exists -- so `A_fors` below is FREE, not
        F-derived), the abstract-good clone instantiation (good_clone_probe.ec,
        good_eq_good_fors PROVEN there), and the ITSR-C10 coupling.

     [PARTIAL/transcription]  VF / hop-6 (MM45 LeqPr_..._VF_FLSLXMSSMTTWESNPRF
        SPHINCS_PLUS.ec:3468, consumed :4329).  +C `LeqPr_VF_C`
        (rtop_c_soundness_wip.ec:688) PROVEN modulo ONE admit (:966 = R6a-CONSUME
        MM45:4176-4277 + R6b sigl-table + R6c validity/freshness map MM45:3935),
        with Eqv_Orig_RV_C:518 and R6a-establish already proven.  Lands on the
        SAME hypertree term this file discharges via the component theorem at
        A_ht := R_top(F).

   NOTE these are SIX separate `admit`s (hop1..hop6), one per MM45 FX game hop
   (ec-certify: admit-tactics=6).  The genuinely-open vs transcription-deferred
   split is recorded per-hop so the ledger is not corrupted in either direction.

   ------ (2) CARRIED PREMISES (this lemma's hypotheses -- NOT admits) ---------
   These are genuine assumptions, threaded to the proven legs, kept as premises
   (NEVER admits) because they are load-bearing and, for mtree_*, FALSE-AT-ZERO:
     * c <= p_tgts                              (WOTS+C target-count side-cond)
     * encode-compat  encode_msgWOTS_C = encode_msgWOTS o ThC   (definitional)
     * emb_tw disjointness + injectivity        (WOTS+C embedding; base-provable
                                                 via emb_disj_wgpidxs_holds,
                                                 WOTS_C_Bridge.ec:200 -- carried
                                                 here verbatim as the component
                                                 theorem states them)
     * dfC <> {8n, 8n*len, 8n*2}                (C10 serialisation-width facts)
     * allnchads / allnpkcoads / allntrhads     (the R_top(F) choose-audit member
                                                 premises on the chtype/pkco/trh
                                                 axes -- the DEFERRED member-audit
                                                 of rtop_forsc_wip.ec:91-93; the
                                                 O_THFC_MA member axis IS
                                                 discharged below via the PROVEN
                                                 R_top_members4)
     * H-TREE-MULTI (mtree_openpre+mtree_trh+mtree_trco premise) -- FALSE-AT-ZERO:
       EUFCMA_MFORSC10's header shows a bare bound collapses under a mtree_*<-0
       clone, so this MUST be a hypothesis, never an admit (FORS_C10_Multi.ec:469).

   ------ (3) CARRIED ASSUMPTIONS  (the inherited ledger; EMPIRICALLY PROBED) ---
   EasyCrypt has no `Print Assumptions`; the closure = `grep '^axiom'` over the
   transitive require set (13 .ec/.eca files: SPHINCS_PLUS + XmssmtCC_All +
   WOTS_C_{Real,Scheme,Interactive,Reduction} + XMSSMT_C_Scheme + FORS_C10{,_Multi}
   + STCR_C + Grind + the MM45 base FORS_ES / FL_SL_XMSS_MT_ES / WOTS_TW_ES /
   KeyedHashFunctions / TweakableHashFunctions).  Split by kind:

   [carried PROBABILITY TERM -- not an axiom]
     * ITSRC10  -- THE HEADLINE, the ~102-bit-gap FORS+C10 interleaved-target
       subset-resilience hardness.  `Pr[M.F.ITSRC10 ...]` appears UNREDUCED on
       the RHS (honest conditional; FORS_C10_Multi.ec:455).  FOREGROUND THIS.
     * SKG/MKG-PRF -- the two PRF advantages (skg_adv/mkg_adv abstract reals).

   [carried PREMISES of this lemma -- not axioms; see (2)]
     * mtree_* (H-TREE-MULTI, false-at-zero), c<=p_tgts, encode-compat,
       emb_tw disj/inj, dfC facts, the 3 R_top(F) member hoare premises.
     * emb_in_len / emb_in_inj (WOTS_C_Interactive.ec:369-375) -- the WOTS+C
       `M||counter` embedding length/injectivity MODELLING PREMISES.  The file is
       explicit these are HYPOTHESES, NOT `axiom`s ("the sweep stays 0-axiom");
       threaded through the base A reductions, realisability recorded there.

   [LIVE easycrypt `axiom` decls in the closure]
     * good_pos (= p_nu, FORS_C10.ec:208) -- positive good-counter mass; carried
       by clone M, load-bearing for FORS+C10 oracle losslessness.  (2nd headline.)
     * FORS+C10 structural g-axioms size_g/eqiks_g/neqisvs_g/rng_g/uniq_g +
       dmkey_ll (FORS_C10.ec:149-208) -- FORS+C10 model surface carried by clone M
       (all DISCHARGEABLE at the concrete FTWES instance -- good_clone_probe.ec
       realises them by exact -- but ABSTRACT here since M has no `with`).
     * STCR_C.dpp_ll (STCR_C.ec:53) -- lossless S-TCR(+C) public-parameter draw.
     * MM45 BASE security-model axioms (the accepted SPHINCS+ foundation,
       inherited, not re-litigated): SPHINCS_PLUS.dist_adrstypes (:111);
       WOTS_TW_ES.{ch0,chS} (:504/511, the WOTS chaining fn), .two_encodings
       (:572), .valid_widxvals_idxvals (:339); FORS_ES/FL_SL_XMSS_MT_ES
       .dist_adrstypes + .valid_{f,x}idxvals_idxvals; TweakableHashFunctions
       .in_collection (:567).  (KeyedHashFunctions.eca contributes 0 live axioms
       in the current closure -- earlier drafts over-listed a g-extractor axiom.)
     * CntrFT.enum_spec = FinType.enum_spec (Grind.ec:35, STCR_C.ec:61) -- the
       STANDARD EasyCrypt finite-type enumeration-completeness fact for the C10
       32-bit counter; a library modelling fact, not a bespoke assumption.

   [checked ABSENT as live axioms]
     * grindP (Grind.ec) -- was App-D gap#1; REPLACED by a total finite-search
       operational model (Grind.ec header) -- 0 live axioms there.  Absent.
     * XmssmtCC_All / WOTS_C_Real "axiom ..." grep hits are COMMENT prose, not
       decls (the component theorem certifies 0-axiom, XmssmtCC_All.ec:8503).

   ------ (4) FAITHFULNESS NOTE  (single-adversary caveat) --------------------
   MM45 has ONE shared forger A giving every RHS `R_x(A)`.  Here the HYPERTREE
   side IS F-derived (A_ht := R_top(F), R_top XmssmtCC_All.ec:9443), but the FORS
   side `A_fors` is a FREE `M.Adv_EUFCMA_MFORSC10` (no reduction from Adv_EUFCMA_C
   exists -- exactly the VT/hop-5 open leg).  Constructing A_fors from F is inside
   the carried FX skeleton.  Flagged exactly as SPHINCS_C_c10.ec:93-100.
   ========================================================================== *)

require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.
require FORS_C10 FORS_C10_Multi.
require DigitalSignatures.
require import BitEncoding. import BS2Int BitChunking.
(* Mirror XmssmtCC_All's own import preamble so the reduction/oracle names the
   component theorem and R_top mention (R_int_STCRC, R_int_WOTSTW, O_THFC_MA, dfC,
   M_EUF_GCMA_WOTSTWESNPRF, STCRC_WC, encode_msgWOTS_C, ThC, emb_tw, ...) resolve. *)
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.

(* FORS+C10 multi leg.  MFORSC10 is an ABSTRACT theory (cannot be imported);
   clone it to a concrete handle M with NO `with` -- keeps every op abstract and
   carries EUFCMA_MFORSC10's proof verbatim into M.  (Concrete binding to the
   base FTWES instance -- cf. good_clone_probe.ec's clone C -- is a faithfulness
   refinement; abstract here matches SPHINCS_C_c10.ec.) *)
clone FORS_C10_Multi.MFORSC10 as M.

(* ==========================================================================
   VT-SIDE `good` BRIDGE  (the good_clone wiring the GOAL names).

   The abstract FORS+C predicate machinery (FORS_C10.FORSC10's `good`/predC_fors)
   instantiated onto the base's CONCRETE FORS clone FTWES, so the abstract clone
   `good` and the concrete `good_fors` (= predC_fors unfolded on FTWES.g/FTWES.mco,
   the C10 forced-last-leaf-0 gate the V_C forgery check uses) become the SAME op.
   INLINED VERBATIM from good_clone_probe.ec (lowercase -> un-requireable); the
   five g-axioms DISCHARGE from FTWES's structured `g`, so clone C adds NO new
   assumption beyond C.good_pos (= the SAME p_nu as good_pos, re-typed at the
   concrete FTWES.mco/g/dmkey).  good_eq_good_fors is the proven sub-fact the VT
   hop (hop5) relies on; the remaining VT reduction is hop5's residual.
   ========================================================================== *)
op good_fors (m : msg) (mk : mkey) : bool =
  (nth witness (FTWES.g (FTWES.mco mk m)) (k - 1)).`3 = 0.

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

(* clone with the five g-axioms + ge1_k/ge1_a/dmkey_ll DISCHARGED; good_pos
   carried un-realized -> C.good_pos (concrete-instance p_nu). *)
clone FORS_C10.FORSC10 as C with
  type mkey <- mkey, type msg <- msg, type out_t <- FTWES.msgFORSTW * index,
  op k <- k, op a <- a, op dmkey <- dmkey, op mco <- FTWES.mco, op g <- FTWES.g
  proof ge1_k, ge1_a, dmkey_ll, size_g, eqiks_g, neqisvs_g, rng_g, uniq_g.
  realize ge1_k     by exact: ge1_k.
  realize ge1_a     by exact: ge1_a.
  realize dmkey_ll  by exact: dmkey_ll.
  realize size_g    by exact: ftw_size_g.
  realize eqiks_g   by exact: ftw_eqiks_g.
  realize neqisvs_g by exact: ftw_neqisvs_g.
  realize rng_g     by exact: ftw_rng_g.
  realize uniq_g    by exact: ftw_uniq_g.

(* THE PAYOFF: the abstract clone `good` IS the concrete C10 forgery-gate
   `good_fors` -- provable and definitional-by-clone (good_clone_probe.ec:140). *)
lemma good_eq_good_fors (m : msg) (mk : mkey) : C.good m mk = good_fors m mk.
proof. by rewrite /C.good /C.predC_fors /good_fors. qed.

(* ==========================================================================
   CONCRETE-LHS RE-GROUNDING  --  the SPHINCS+C10 scheme object + its generic
   EUF_CMA game, inlined from sphincs_c10_scheme_wip.ec (a lowercase WIP file
   cannot be `require`d; the op `good_fors` is REUSED from :216 above, so it is
   NOT redefined here).  This is what turns the capstone LHS from the ABSTRACT
   real `p_sphincs_c` into the CONCRETE scheme-game advantage
   `Pr[EUFCMA_C10(F).main() @ &m : res]`.  See sphincs_c10_scheme_wip.ec's LEDGER
   for the honesty caveats (real skg keys + IDEALISED-mk via dcond: `ms` dead,
   MKG hop vacuous, signing randomised; the good_fors gate in verify; NO new
   axiom).  Fresh DSSC clone -- MM45's DSS binds sigSPHINCSPLUSTW, not the +C one.
   ========================================================================== *)
clone DigitalSignatures as DSSC with
  type pk_t  <- pkSPHINCSPLUSTW,
  type sk_t  <- skSPHINCSPLUSTW,
  type msg_t <- msg,
  type sig_t <- sigSPHINCSPLUSTWC

  proof *.

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
    mk <$ dcond dmkey (good_fors m);                (* +C subst (i) *)
    (cm, idx) <- FTWES.mco mk m;
    (tidx, kpidx) <- edivz (Index.val idx) l';
    sigFORSTW <@ FTWES.FL_FORS_ES.sign((ss, ps,
                   set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);
    pkFORS <@ FTWES.FL_FORS_ES.gen_pkFORS(ss, ps,
                   set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);
    sigHT <@ FL_SL_XMSS_MT_C_ES.sign((ss, ps, ad), pkFORS, idx);  (* +C subst (ii) *)
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
    (root', allOkC) <@ FL_SL_XMSS_MT_C_ES.root_from_sigC(pkFORS, sigHT, idx, ps, ad);
    return good_fors m mk /\ size sigHT = d /\ root' = root /\ allOkC;  (* mirror V_C:451 *)
  }
}.

(* The generic EUF_CMA game at the concrete scheme -- the LHS object. *)
module EUFCMA_C10 (F : Adv_EUFCMA_C) =
  DSSC.Stateless.EUF_CMA(SPHINCS_PLUS_C10, F, DSSC.Stateless.O_CMA_Default).

(* ==========================================================================
   THE CAPSTONE THEOREM  (CONCRETE-LHS variant).
   ========================================================================== *)
lemma EUFCMA_SPHINCS_PLUS_C10
  (* The top SPHINCS+C10 EUF-CMA forger.  The bound is stated per-forger F;
     the hypertree term below is F-derived (R_top(F)). *)
  (F <: Adv_EUFCMA_C{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V, -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default,
             -R_top })
  (* FORS+C10 leg forger -- FREE (not F-derived); the VT/hop-5 open leg. *)
  (A_fors <: M.Adv_EUFCMA_MFORSC10{ -M.R_ITSRC10_MFORSC10, -M.O_CMA_MFORSC10,
             -M.O_CMA_MFORSC10_I, -M.F.O_ITSRC10_Default, -M.EUF_CMA_MFORSC10_I })
  (* Abstract reals: the two PRF advantages.  The LHS is NO LONGER an abstract
     real -- it is now the CONCRETE game Pr[EUFCMA_C10(F).main() @ &m : res]. *)
  (skg_adv mkg_adv : real)
  (* The (unbuilt) +C intermediate game probabilities the FX hops route through:
     PRFPRF, NPRFPRF, NPRFNPRF, and the VT/VF split of V_C.  FREE reals -- their
     +C game modules are not built here (see THE LEDGER (1)). *)
  (p_prfprf p_nprfprf p_nprfnprf p_vt p_vf : real)
  (* FORS +C-invariant tree reals (forall-bound; FALSE-AT-ZERO -- see header). *)
  (mtree_openpre mtree_trh mtree_trco : real)
  &m :
    (* ---- component-theorem parameter side-conditions (carried) ---- *)
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (a b : adrs),
       get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b) => get_wgpidxs a = get_wgpidxs b) =>
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC <> 8 * n =>
    dfC <> 8 * n * len =>
    dfC <> 8 * n * 2 =>
    dfC <> 8 * n * k =>   (* 4th C10 width fact: only for the R_top_members4 member-axis bridge *)
    (* ---- R_top(F) choose-audit member premises (chtype / pkco / trh axes) --
            the DEFERRED member-audit; the O_THFC_MA member axis is discharged
            below via the PROVEN R_top_members4. ---- *)
    hoare[ R_top(F, FC.O_THFC_Default).choose :
             FC.O_THFC_Default.tws = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws ] =>
    hoare[ R_top(F, R_SMDTTCRCPKCO_C(R_top(F), FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                                 FSSLXMTWES.PKCOC.O_THFC_Default).O_THFC).choose :
             R_SMDTTCRCPKCO_C.O_THFC.ads = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads ] =>
    hoare[ R_top(F, R_SMDTTCRCTRH_C(R_top(F), FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                                FSSLXMTWES.TRHC.O_THFC_Default).O_THFC).choose :
             R_SMDTTCRCTRH_C.O_THFC.ads = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads ] =>
    (* ---- FORS+C10 H-TREE-MULTI premise (FALSE-AT-ZERO -- must be a premise) ---- *)
    (   Pr[M.EUF_CMA_MFORSC10_I(A_fors).main() @ &m
             : res /\ !M.EUF_CMA_MFORSC10_I.covered]
     <= mtree_openpre + mtree_trh + mtree_trco) =>

    (* ---- CONCLUSION: the MM45 FX 4-term bound, +C-substituted and EXPANDED.
            LHS RE-GROUNDED: the CONCRETE scheme-game advantage (was p_sphincs_c). ---- *)
    Pr[EUFCMA_C10(F).main() @ &m : res]
      <= skg_adv
       + mkg_adv
       (* +C subst #1: FORS+C10 multi expansion (M.EUFCMA_MFORSC10) *)
       + ( Pr[M.F.ITSRC10(M.R_ITSRC10_MFORSC10(A_fors),
                          M.F.O_ITSRC10_Default).main() @ &m : res]
           + mtree_openpre + mtree_trh + mtree_trco )
       (* +C subst #2: hypertree COMPONENT THEOREM expansion at A_ht := R_top(F) *)
       + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top(F))),
                                      O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top(F))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top(F)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top(F)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res] ).
proof.
  move=> hc hembdisj hembinj hencb hdf8n hdflen hdf2 hdfnk allnchads allnpkcoads allntrhads htree.
  (* ---- member axis: DISCHARGE via the PROVEN R_top_members4 (requireable) ----
     R_top_members4 gives `all in_thfc4`; all_in_thfc4_neq_dfC bridges to <>dfC. *)
  have A_wf_ht :
    hoare[ R_top(F, O_THFC_MA).choose :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma ].
  + conseq (R_top_members4 F) => //.
    by move=> &hr _ tws_ma; apply (all_in_thfc4_neq_dfC tws_ma hdf8n hdflen hdf2 hdfnk).
  (* ---- hypertree term: PROVEN via the +C COMPONENT THEOREM at R_top(F) ---- *)
  have hHT := EUFNAGCMA_FLSLXMSSMTTWCESNPRF (R_top(F)) &m hc hembdisj hembinj hencb
                hdf8n hdflen hdf2 A_wf_ht allnchads allnpkcoads allntrhads.
  (* ---- FORS+C10 term: bounded via M.EUFCMA_MFORSC10 (conditional on htree) ---- *)
  (* !! WAVE-9/10 CAVEAT (2026-07-21, machine-checked drafts/rtop_c_vt_wip.ec + Wave-10
     probes): hF ITSELF is a GENUINE MEANINGFUL bound (accept-all probe + negative
     control: no hidden fverify-hypothesis; content = ITSRC10 + load-bearing mtree
     premise). The GAP is the hop5 SEAM: M's fverify/mkeygen are UNCONSTRAINED
     (fverify:=false zeroes Pr[RHS]; M.mkeygen cannot couple to V_C's ps-independent
     cube, D2), so LeqPr_VT_C cannot connect p_vt to the ABSTRACT game. FIX = a CONCRETE
     PROCEDURAL M-FORS+C game (procedural keygen matching V_C + concrete sign + verify by
     reconstructed-pkFORS eq + predC_fors) + hop5 over it. FORS leg CONDITIONAL on that.
     (Hypertree leg unaffected -- concrete NAGCMA win.) *)
  have hF := M.EUFCMA_MFORSC10 A_fors mtree_openpre mtree_trh mtree_trco &m htree.

  (* ======================================================================
     FX SKELETON -- the six MM45 game hops, each an EXPLICIT admit (see THE
     LEDGER (1)).  They route p_sphincs_c through the (unbuilt) +C intermediate
     game probabilities to the FORS-game and HT-game the proven legs expand.
     ====================================================================== *)

  (* hop1  [genuinely-open]  Orig -> PRFPRF (materialization).
     MM45 byequiv Eqv_EUF_CMA_SPHINCSPLUSTW_Orig_FSPRFPRF (SPHINCS_PLUS.ec:2243),
     consumed :4304.  +C analog = Eqv_ondemand_materialized, NAMED-but-unproved
     (prf_hop_wip.ec:614-625).  MISSING: the deterministic-recomputation
     equivalence for the +C on-demand -> materialized cube.  RE-GROUNDED: the LHS
     is now the CONCRETE game Pr[EUFCMA_C10(F)...] (was the abstract p_sphincs_c),
     so this hop's LHS is a real scheme advantage.  Honesty: that scheme's mk is
     ALREADY idealised (dcond), so hop1 here folds the key-materialization step
     and the MKG-idealisation is baked into the LHS -- still an admit (this file
     does NOT prove the +C materialization byequiv). *)
  have hop1 : Pr[EUFCMA_C10(F).main() @ &m : res] <= p_prfprf.
  + admit.

  (* hop2  [PARTIAL / transcription-deferred]  PRFPRF <= NPRFPRF + |SKG-PRF|.
     MM45 EqAdv_..._PRFPRF_NPRFPRF_SKGPRF (SPHINCS_PLUS.ec:2668), consumed :4312.
     +C SKGPRF_hop / SKGPRF_hop_composed are PROVEN 0-admit at the HYPERTREE
     level (prf_hop_wip.ec:542/558, CERTIFIED-0-ADMIT) but not require-able
     (lowercase file).  MISSING at scheme level: the SKG term must also cover the
     FORS+C secret keys (prf_hop_wip.ec:655-656). *)
  have hop2 : p_prfprf <= p_nprfprf + skg_adv.
  + admit.

  (* hop3  NPRFPRF <= NPRFNPRF + mkg_adv.
     !! 2026-07-24 FINDING (fx_chain_wip.ec commit 4531211, 3-review-converged +
     audit PASS): the IN-CHAIN MKG-PRF hop is the IDENTITY at +C, NOT a paid hop.
     C10 models the message key as a fresh, non-memoized `mk <$ dcond dmkey
     (good_fors m)` on EVERY game of the chain (already the OUTPUT of the message-
     key idealisation + the +C conditioning; `mkg` never applied in-chain, grep-
     verified).  So NPRFNPRF is DEFINITIONALLY NPRFPRF (`p_nprfprf = p_nprfnprf` by
     sim) and MM45's paid |MKG-PRF| triangle does not port.  `mkg_adv` here is a
     PHANTOM in-chain summand (SOUND but silently-zeroable over-estimate).  The
     genuine MKG idealisation is a SEPARATE pre-hop-1 boundary term (deployed
     keyed-grind on sk_seed -> this idealised dcond model), a documented open
     refinement.  This capstone bounds the IDEALISED-mk model; mkg_adv reads as
     that boundary term, NOT a discharged in-chain hop.  Tightening option (not
     applied): make hop3 the identity and drop mkg_adv from the sum. *)
  have hop3 : p_nprfprf <= p_nprfnprf + mkg_adv.
  + admit.

  (* hop4  [genuinely-open]  NPRFNPRF -> V, then mu_split into VT + VF.
     MM45 byequiv Eqv_..._NPRFNPRF_V (SPHINCS_PLUS.ec:2572) + Pr[mu_split] :4327,
     consumed :4326-4327.  The +C V_C game exists
     (EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V, rtop_c_soundness_wip.ec:326) but the
     Orig->V byequiv and the mu_split over valid_MFORSC10 are not built here. *)
  have hop4 : p_nprfnprf <= p_vt + p_vf.
  + admit.

  (* hop5  [genuinely-open]  VT-part <= FORS+C10 multi game.
     MM45 LeqPr_..._VT_MFORSTWESNPRF (SPHINCS_PLUS.ec:3129), consumed :4328.
     WIRED SUB-FACT: the abstract-good == concrete-C10-gate bridge is PROVEN
     IN-FILE above as `good_eq_good_fors` (C.good = good_fors), the good_clone
     leg the GOAL names.  STILL MISSING (hop5's residual): a reduction from
     Adv_EUFCMA_C to M.Adv_EUFCMA_MFORSC10 (NONE exists -- so A_fors above is
     FREE, not F-derived) and the ITSR-C10 coupling onto that reduction. *)
  have hop5 : p_vt <= Pr[M.EUF_CMA_MFORSC10(A_fors, M.O_CMA_MFORSC10).main() @ &m : res].
  + admit.

  (* hop6  [PARTIAL / transcription-deferred]  VF-part <= hypertree game.
     MM45 LeqPr_..._VF_FLSLXMSSMTTWESNPRF (SPHINCS_PLUS.ec:3468), consumed :4329.
     +C LeqPr_VF_C (rtop_c_soundness_wip.ec:688) PROVEN modulo ONE admit (:966 =
     R6a-CONSUME MM45:4176-4277 + R6b sigl-table + R6c validity/freshness map
     MM45:3935); Eqv_Orig_RV_C:518 and R6a-establish already proven.  RESIDUAL
     also carries the R_top_C (conditioned mk) vs R_top (uniform mk) reduction
     reconciliation -- LeqPr_VF_C targets R_top_C(F). *)
  have hop6 : p_vf <= Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(R_top(F), FC.O_THFC_Default).main() @ &m : res].
  + admit.

  (* ---- sound-direction linear transitivity: hop1..hop6 + hF + hHT ---- *)
  smt().
qed.
