(* ==========================================================================
   sphincs_c10_scheme_wip.ec  --  THE CONCRETE SPHINCS+C10 SCHEME OBJECT + GAME.

   ROLE = BUILD the LHS OBJECT the capstone (sphincs_c10_capstone_wip.ec) is
   missing.  That capstone's LEDGER (0) flags: "There is NO concrete
   `module SPHINCS_PLUS_C10 : Scheme` and NO concrete
   `EUF_CMA(SPHINCS_PLUS_C10, F, O_CMA_Default)` game in this port. ... the
   SPHINCS+C10 forgery probability itself is the ABSTRACT real `p_sphincs_c`."
   THIS FILE builds that concrete scheme module + its generic EUF_CMA game so a
   follow-up capstone can re-ground `p_sphincs_c` as a real scheme advantage.

   This is the LHS OBJECT ONLY.  It is NOT MM45's FX proof over the scheme (the 6
   byequiv/game hops are the multi-month remainder); NOTHING here proves any hop.

   ==========================================================================
   WHAT THIS IS  --  a faithful port of MM45's `module SPHINCS_PLUS : Scheme`
   (FV-SPHINCSPLUS-EC/proofs/SPHINCS_PLUS.ec:957) with the two paper-2022/778
   Thm-5.2 +C substitutions, at the SAME seed-based sk MM45 uses.

       MM45 SPHINCS_PLUS (Orig)               SPHINCS_PLUS_C10 (this file)
       -------------------------------------  -----------------------------------
       sk = mseed * sseed * pseed             sk = mseed * sseed * pseed  (SAME)
       keygen: FL_SL_XMSS_MT_ES.gen_root      keygen: FL_SL_XMSS_MT_C_ES.gen_root  (subst ii)
       sign FORS: M_FORS_ES.sign              sign FORS: mk <$ dcond dmkey (good_fors m);  (subst i)
         (internally mk <- mkg ms m)            FTWES.FL_FORS_ES.sign((ss,ps,ad),cm)
       sign HT: FL_SL_XMSS_MT_ES.sign         sign HT: FL_SL_XMSS_MT_C_ES.sign     (subst ii)
       verify: root' = root                   verify: good_fors m mk /\ size=d /\ root'=root /\ allOkC
       sig = mkey*sigFORSTW*sigFLSLXMSSMTTW    sig = sigSPHINCSPLUSTWC
                                                    = mkey * FTWES.sigFORSTW * sigFLSLXMSSMTTWC  (:9419)

   WHY seed-based ("Orig"), NOT the NPRF materialized game:  MM45 pins "Orig" as
   literally `EUF_CMA(SPHINCS_PLUS, A, O_CMA_Default)` over the seed-based scheme
   (the LHS of the first byequiv Eqv_..._Orig_FSPRFPRF, SPHINCS_PLUS.ec:2243-2244).
   The concrete LHS a capstone re-grounds MUST be that seed-based object, or the
   `skg_adv`/`mkg_adv` PRF terms in the FX bound have nothing to act on.  The
   materialized game EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V (rtop_c_soundness_wip.ec:
   326) is the FAR SIDE of hops 2-3, not Orig.

   RESOLVING THE TASK-TEXT "FL_SL_XMSS_MT_C_ES_NPRF" MENTION (adversarial review
   GPT-5.6 + Kimi K3, 2026-07-21, both converge): FL_SL_XMSS_MT_C_ES_NPRF.sign
   takes a MATERIALIZED WOTS cube (XmssmtCC_All.ec:214/:228), which is type-
   incompatible with a seed-based sk.  So the NPRF phrase cannot be taken
   literally alongside "MM45's sk_t".  It is read as the ALGEBRAIC-FLOW reference:
   sign's statement shape (dcond draw -> mco -> edivz -> FORS sign -> pkFORS -> HT
   sign -> triple) matches the NPRF game's O_CMA oracle (V_C.O_CMA_C / R_top_C.
   O_CMA), which is what the eventual hop byequivs need.  We use the REAL seed-
   based +C hypertree FL_SL_XMSS_MT_C_ES (XMSSMT_C_Scheme.ec:71), which EXISTS.

   ==========================================================================
   HONEST LEDGER  --  where this concrete LHS actually sits.

   (A) IDEALISED-mk / REAL-KEY level (NOT a genuine pre-MKG Orig).
       The task-specified `mk <$ dcond dmkey (good_fors m)` is the +C conditioned
       message-key draw (the deployed C10 grinding model; FORS_C10_Multi.ec:163-
       167 "matching production").  It IDEALISES the real keyed generation
       `mk <- mkg ms m` (FORS_ES.ec:1745) into a fresh good-conditioned uniform
       draw.  Consequences, all disclosed:
         - `ms` (the mseed in sk) is DEAD key material here; kept only so sk_t is
           byte-identical to MM45's skSPHINCSPLUSTW.
         - the MKG-PRF hop is VACUOUS at this LHS (hop diff 0 <= mkg_adv, conserv.).
         - signing is RANDOMISED (same m -> different sig), a real semantic
           departure from MM45's deterministic mkg; consistent with the repo's
           standing fresh-draw decision (rtop_c_soundness_wip.ec:100-125,121-125
           "DEFERRED FAITHFULNESS QUESTION").
       So: real (skg-PRF-derived) FORS/WOTS keys + IDEALISED (uniform-conditioned)
       message key.  A pre-MKG scheme would need a keyed grinding generator taken
       to dcond by a proof -- no such full-scheme generator exists yet.

   (B) The FORS/HT KEYS are REAL (seed-derived): FTWES.FL_FORS_ES.sign and
       FL_SL_XMSS_MT_C_ES.sign derive their secret material from `ss` via skg.  So
       the SKG-PRF hop (hop2, PRFPRF->NPRFPRF) is genuinely available on this LHS.

   (C) verify CHECKS good_fors  (required + real, NOT a hop artifact).  Mirrors
       V_C's is_valid (rtop_c_soundness_wip.ec:449-451) verbatim:
         good_fors m mk /\ size sigHT = d /\ root' = root /\ allOkC.
       Rationale: honest conditioning does NOT restrict an ADVERSARY's forgery --
       the real +C verifier must reject a non-good digest, else a forgery with a
       bad digest verifies here but is rejected by V_C, and the future hop-1
       byequiv EUF_CMA(SPHINCS_PLUS_C10) ~ ... ~ V_C is false.  `good_fors` is
       public/computable from (m,mk) (:135-136).  `size sigHT = d` is load-bearing:
       root_from_sigC loops `nth witness sig i` for i<d and would consume a short
       forged sig with witness garbage without it.

   (D) "the scheme and its simulations agree" holds at the FLOW-SHAPE level, NOT
       as object identity: R_top_C.O_CMA TABLE-SELECTS a challenger HT signature
       (rtop_c_soundness_wip.ec:168) rather than running HT sign, so agreement is
       only after the NAGCMA table invariant / hops -- not claimed here.

   (E) INHERITED (no NEW axiom introduced by this file -- verified):
         - sign losslessness rests on dcond_ll + `good_pos` (positive good mass,
           FORS_C10.ec:208); good_pos is ALREADY in the capstone ledger (:147),
           this file only enters its transitive closure.
       new-axiom census for this file: NONE.

   (F) MODELLING abstractions inherited from the +C track (unchanged here): the
       full FTWES.sigFORSTW shape + `edivz (val idx) l'` instance routing are the
       acknowledged security-model abstractions of the shipped K/K-1 optimisation
       (rtop_c_soundness_wip.ec:295-308).
   ========================================================================== *)

require import AllCore List Distr StdBigop StdOrder IntDiv.
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

(* The C10 FORS+C conditioning predicate on the message key, wired CONCRETELY at
   the base's concrete msg / mkey / FTWES digest -- IDENTICAL to the op in
   rtop_c_soundness_wip.ec:135-136 and sphincs_c10_capstone_wip.ec:216-217. *)
op good_fors (m : msg) (mk : mkey) : bool =
  (nth witness (FTWES.g (FTWES.mco mk m)) (k - 1)).`3 = 0.

(* ==========================================================================
   FRESH DigitalSignatures clone at the +C signature type.

   We CANNOT reuse MM45's DSS clone (SPHINCS_PLUS.ec:673): its sig_t is the
   non-+C `sigSPHINCSPLUSTW`.  Mirror that clone line verbatim, change ONLY
   sig_t -> sigSPHINCSPLUSTWC (sk_t stays skSPHINCSPLUSTW).  We do NOT
   `import DSSC.Stateless`: `require import SPHINCS_PLUS` already pulled the OLD
   DSS.Stateless names into scope, so everything below stays DSSC.-qualified.
   ========================================================================== *)
clone DigitalSignatures as DSSC with
  type pk_t  <- pkSPHINCSPLUSTW,
  type sk_t  <- skSPHINCSPLUSTW,
  type msg_t <- msg,
  type sig_t <- sigSPHINCSPLUSTWC

  proof *.

(* ==========================================================================
   THE CONCRETE SPHINCS+C10 SCHEME.
   ========================================================================== *)
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

    (* Mirror V_C is_valid (rtop_c_soundness_wip.ec:451): the +C forced-zero gate
       is a REAL validity check on the forgery (the adversary's mk need not be
       conditioned), plus size + root + the constant-sum gate. *)
    return good_fors m mk /\ size sigHT = d /\ root' = root /\ allOkC;
  }
}.

(* ==========================================================================
   THE GENERIC EUF_CMA GAME, INSTANTIATED AT THE CONCRETE SCHEME.

   Defining it as a module functor forces the WHOLE instantiation to elaborate
   admit-free: SPHINCS_PLUS_C10 <: DSSC.Stateless.Scheme, F <: the clone's
   Adv_EUFCMA (structurally = the hand-written Adv_EUFCMA_C, XmssmtCC_All.ec:9428),
   O_CMA_Default <: Oracle_CMA.  This IS the subtyping test; the named game is
   handed to a follow-up capstone as the concrete LHS
   `Pr[EUFCMA_C10(F).main() @ &m : res]`.
   ========================================================================== *)
module EUFCMA_C10 (F : Adv_EUFCMA_C) =
  DSSC.Stateless.EUF_CMA(SPHINCS_PLUS_C10, F, DSSC.Stateless.O_CMA_Default).

(* ==========================================================================
   SCHEME CORRECTNESS -- the "compiles != correct" caveat, closed as far as it
   HONESTLY closes and no further.  READ THE RESIDUAL LEDGER at the bottom: the
   full `verify(pk,m,sign(sk,m)) = 1%r` is NOT merely unproven here, it is FALSE
   IN PRINCIPLE for the abstract +C model (a modelling artefact, not a C10 flaw).

   Trivial sub-procedure specs (the intermediate FORS calls carry no info the
   correctness gates need, but a hoare/phoare traversal must still discharge each
   concrete call).  Mirror the XMSSMT_C_Scheme.ec:231-284 style.
   ========================================================================== *)
lemma fors_leaves_h : hoare[FTWES.FL_FORS_ES.gen_leaves_single_tree : true ==> true].
proof. proc; while (true); auto. qed.

lemma fors_sign_h : hoare[FTWES.FL_FORS_ES.sign : true ==> true].
proof. proc; while (true); [by wp; call fors_leaves_h; auto | by auto]. qed.

lemma fors_genpk_h : hoare[FTWES.FL_FORS_ES.gen_pkFORS : true ==> true].
proof. proc; wp; while (true); [by wp; call fors_leaves_h; auto | by auto]. qed.

lemma fors_leaves_ll : islossless FTWES.FL_FORS_ES.gen_leaves_single_tree.
proof. proc; while (true) (t - size leaves); auto; smt(size_rcons ge2_t). qed.

lemma fors_sign_ll : islossless FTWES.FL_FORS_ES.sign.
proof.
proc; while (true) (k - size sig).
+ by move=> z; wp; call fors_leaves_ll; auto; smt(size_rcons).
by auto; smt(ge1_k).
qed.

lemma fors_genpk_ll : islossless FTWES.FL_FORS_ES.gen_pkFORS.
proof.
proc; wp; while (true) (k - size roots).
+ by move=> z; wp; call fors_leaves_ll; auto; smt(size_rcons).
by auto; smt(ge1_k).
qed.

(* GATE A -- the two verify-conjuncts that sign's OWN OUTPUT determines always
   hold on an honest signature (partial correctness; upgraded to =1%r below). *)
lemma sign_gates_hoare (m0 : msg) :
  hoare[SPHINCS_PLUS_C10.sign : m = m0
        ==> good_fors m0 res.`1 /\ size res.`3 = d].
proof.
proc.
sp; wp; call sign_size_d; call fors_genpk_h; call fors_sign_h.
wp; rnd; skip => /> mk0 /dcond_supp [_ hg] result hsz; exact hg.
qed.

(* GATE B -- sign is LOSSLESS under positive good-counter mass.  This is where
   `good_pos` (the CARRIED axiom, FORS_C10.ec:208, positive good-mass) is
   consumed: it is exactly the `0%r < mu dmkey (good_fors m0)` premise, which
   discharges to `good_pos` modulo the definitional `good_eq_good_fors`
   (sphincs_c10_capstone_wip.ec:269, `by rewrite /C.good /C.predC_fors
   /good_fors`).  Exposed as an explicit dischargeable premise rather than
   re-cloning FORSC10 here: no NEW axiom, and the dependency is visible. *)
lemma sign_ll_c10 (m0 : msg) :
  0%r < mu dmkey (good_fors m0) =>
  phoare[SPHINCS_PLUS_C10.sign : m = m0 ==> true] = 1%r.
proof.
move=> hpos; proc.
sp; wp; call sign_ll; call fors_genpk_ll; call fors_sign_ll.
wp; rnd; skip => />; apply: dcond_ll; exact hpos.
qed.

(* THE NON-VACUOUS CORRECTNESS FRAGMENT.  `= 1%r` (NOT plain hoare) is essential:
   a hoare post over a possibly-null `dcond` is vacuously satisfiable, so the
   `= 1%r` -- which forces losslessness, hence positive good-mass -- is what makes
   this a REAL statement.  Both gates are genuinely probability-1: good_fors is the
   FORS message-key conditioning (dcond_supp), size is the deterministic d-layer
   loop (sign_size_d); neither touches WOTS+C grinding. *)
lemma sign_gates (m0 : msg) :
  0%r < mu dmkey (good_fors m0) =>
  phoare[SPHINCS_PLUS_C10.sign : m = m0
         ==> good_fors m0 res.`1 /\ size res.`3 = d] = 1%r.
proof.
move=> hpos; conseq (sign_ll_c10 m0 hpos) (sign_gates_hoare m0) => //.
qed.

(* ==========================================================================
   R1 COMPONENT -- THE HYPERTREE-LAYER MERKLE ROOT ROUND-TRIP (PROVEN).

   This is the tree half of the third verify-conjunct `root' = root` (R1): for
   ONE inner (XMSS) tree of the +C hypertree, reconstructing the root from the
   HONEST authentication path (`cons_ap_trh`, what `FL_SL_XMSS_MT_C_ES.sign`
   stores at each layer) and the honest leaf equals the tree root `val_bt_trh`
   (what `gen_root` / the running `sign` root compute).  It is EXACTLY the shape
   `FL_SL_XMSS_MT_C_ES.root_from_sigC` consumes (`val_ap_trh`) against what
   `sign`/`gen_root` produce (`val_bt_trh`), so it drops into the per-layer step
   of the d-layer root reconstruction; it is also shared verbatim with the FORS
   inner-tree round-trip.

   Assembled from the source-verified components named in the R1 residual below:
   `eq_valbt_valap` (MerkleTrees.ec:71), `size_consap`/`nth_consap`
   (MerkleTrees.ec:38/51) and the `list2tree` height/balance/leaf facts
   (BinaryTrees.ec:188/199/209).  It mirrors the ONE base application of
   `eq_valbt_valap` (SPHINCS_PLUS.ec:1965-1983, there for the FORS layer inside a
   sign~sign equiv), lifted here to a standalone, reusable, verify-side op-lemma
   at the hypertree height `h'` / arity `l' = 2 ^ h'`.

   NON-VACUITY (machine-checked negative controls, scratch/, both REJECTED by the
   gate): dropping the `0 <= idx < l'` hypothesis (leaf membership no longer
   discharges) and corrupting the reconstructed leaf `idx -> 0` in the RHS (the
   `eq_valbt_valap` leaf no longer unifies) each break the proof -- so both the
   index bound and the exact leaf equality are load-bearing.
   ========================================================================== *)
lemma val_ap_cons_ap_trh_rt (ps : pseed) (ad : adrs) (leaves : dgstblock list) (idx : int) :
     size leaves = l'
  => 0 <= idx < l'
  => val_ap_trh ps ad (cons_ap_trh ps ad (list2tree leaves) idx) idx (nth witness leaves idx)
     = val_bt_trh ps ad (list2tree leaves).
proof.
move=> szlvs [ge0_idx ltlp_idx].
have ge0_hp : 0 <= h' by smt(ge1_hp).
have szlvs2 : size leaves = 2 ^ h' by rewrite szlvs.
have hidx : 0 <= idx < size leaves by rewrite szlvs; smt().
have fblvs : fully_balanced (list2tree leaves) by apply (list2tree_fullybalanced leaves h').
have hlvs : height (list2tree leaves) = h' by apply (list2tree_height leaves h').
have szrvbs : size (rev (int2bs h' idx)) = h' by rewrite size_rev size_int2bs /#.
have hbs : height (list2tree leaves) = size (rev (int2bs h' idx)) by rewrite hlvs szrvbs.
rewrite /val_ap_trh /val_ap_trh_gen /val_bt_trh /val_bt_trh_gen.
apply eq_sym.
apply (eq_valbt_valap (trhi ps ad) updhbidx (list2tree leaves)
                      (DBHPL.val (cons_ap_trh ps ad (list2tree leaves) idx))
                      (rev (int2bs h' idx))
                      (nth witness leaves idx)
                      (h', 0)).
+ exact fblvs.
+ by rewrite DBHPL.valP hlvs.
+ by rewrite DBHPL.valP szrvbs.
+ by rewrite (list2tree_lvb leaves idx h' ge0_hp szlvs2 hidx) (onth_nth witness leaves idx hidx).
+ move=> i; rewrite DBHPL.valP => rngi.
  have szc : size (cons_ap_trh_gen ps ad (list2tree leaves) (rev (int2bs h' idx)) h' 0) = h'.
  - rewrite /cons_ap_trh_gen (size_consap (trhi ps ad) updhbidx (list2tree leaves) (rev (int2bs h' idx)) (h',0)).
    * exact fblvs.
    * exact hbs.
    exact szrvbs.
  rewrite /cons_ap_trh.
  rewrite (DBHPL.insubdK (cons_ap_trh_gen ps ad (list2tree leaves) (rev (int2bs h' idx)) h' 0) szc).
  rewrite /cons_ap_trh_gen.
  rewrite (nth_consap (trhi ps ad) updhbidx (list2tree leaves) (rev (int2bs h' idx)) (h',0) i).
  * exact fblvs.
  * exact hbs.
  * by rewrite szrvbs; exact rngi.
  done.
qed.

(* ==========================================================================
   R1 COMPONENT -- THE WOTS+C CHAIN LEAF ROUND-TRIP (PROVEN).

   This is the WOTS half of a hypertree layer's leaf: on an HONEST WOTS+C
   signature element `sig_ele = cf ps ad_i 0 em_ele (val sk_ele)` (what
   `WOTS_C_ES.sign` chains, XMSSMT_C_Scheme.WOTS_C_Scheme:63), completing the
   chain the way `pkWOTS_from_sigWOTS_C` does -- `cf ps ad_i em_ele (w-1-em_ele)
   (val sig_ele)` (XMSSMT_C_Scheme.ec:154) -- lands exactly on the sk-derived pk
   element `cf ps ad_i 0 (w-1) (val sk_ele)` that `pkWOTS_from_skWOTS`
   (WOTS_TW_ES.ec:2178) computes for the tree leaf.  So the verify-recomputed
   WOTS public key equals the honest tree leaf's, element-wise -- the fact the
   leaf equality (hence the Merkle leaf fed to lemma `val_ap_cons_ap_trh_rt`)
   rests on.

   `em_ele = BaseW.val em.[i]` is IRRELEVANT to WHICH counter/encoding is used:
   verify and sign share the same `counter` (carried in the sig) and message, so
   the same `em` -- this lemma only needs the SPLIT `0..em_ele` then
   `em_ele..w-1` to compose (via `ch_comp`, WOTS_TW_ES.ec:533) to the full
   `0..w-1` chain, for ANY split point in range.  This mirrors the single base
   in-line use at WOTS_TW_ES.ec:4727-4731, lifted to a standalone op-lemma.

   NON-VACUITY (machine-checked, scratch/): corrupting the full-chain length
   `w-1 -> w-2` on the RHS is REJECTED by the gate -- the chain endpoints really
   must coincide.
   ========================================================================== *)
lemma cf_roundtrip (ps : pseed) (ad : adrs) (em_ele : int) (x : dgst) :
     valid_wadrs ad
  => size x = 8 * n
  => 0 <= em_ele <= w - 1
  => cf ps ad em_ele (w - 1 - em_ele) (DigestBlock.val (cf ps ad 0 em_ele x))
     = cf ps ad 0 (w - 1) x.
proof.
move=> adval szx rng_em.
have ->: w - 1 = em_ele + (w - 1 - em_ele) by smt().
rewrite /cf (ch_comp f ps ad 0 em_ele (w - 1 - em_ele) x) //=; smt().
qed.

(* ==========================================================================
   R1a (PROVEN) -- THE WOTS+C len-LOOP LIFT OF cf_roundtrip.

   Lifts the element-wise chain round-trip `cf_roundtrip` through the `len`-loop
   of `pkWOTS_from_sigWOTS_C` (verify side, XMSSMT_C_Scheme.ec:139) vs
   `pkWOTS_from_skWOTS` (sk side, WOTS_TW_ES.ec:2053) to a PROCEDURE-LEVEL
   relational equality: on an HONEST WOTS+C signature -- one whose j-th element is
   the half-chain `cf ps (set_chidx ad j) 0 em_ele (val sk_ele)` that
   `WOTS_C_ES.sign` (WOTS_C_Scheme.ec:63) chains, with `em = encode_msgWOTS_C ps
   ad m counter` and the SAME counter carried in the sig -- the verify-recomputed
   WOTS public key equals the sk-derived one, element for element.  Hence the two
   procedures return the SAME `pkWOTS`, so the `pkco` leaves fed to the Merkle
   layer (`val_ap_cons_ap_trh_rt`) coincide.  This is the WOTS half of one
   hypertree layer's leaf equality -- the per-layer input R1b's d-layer induction
   consumes.

   Relational core: a single synchronised `while` with invariant `pkWOTS_l{1} =
   pkWOTS{2}`; each step's appended elements are equated by ONE application of
   `cf_roundtrip` after rewriting the honest-sig coupling `hcpl`.  The `em`
   encoding is IRRELEVANT to the identity: both sides split the same chain at the
   same `em_ele`, and `cf_roundtrip` composes `0..em_ele` then `em_ele..w-1` for
   ANY split point in range.  Address validity discharges via
   `validwadrs_setchidx` (WOTS_TW_ES.ec:1052) from `valid_wadrs ad`.

   NON-VACUITY (machine-checked, scratch/, both REJECTED by the gate): dropping
   the `valid_wadrs ad0` premise (`validwadrs_setchidx` no longer discharges the
   chain-address validity) and corrupting the honest-coupling chain-START index
   `0 -> 1` (`cf_roundtrip`'s inner `cf .. 0 em_ele ..` no longer unifies) each
   break the proof -- so both the WOTS-address validity and the exact honest
   half-chain structure are load-bearing.
   ========================================================================== *)
lemma pkWOTS_sigC_eq_skWOTS (ps0 : pseed) (ad0 : adrs) (m0 : msgWOTS) (c0 : cntr)
                            (skW sig0 : dgstblocklenlist) :
     valid_wadrs ad0
  => (forall (j : int), 0 <= j < len =>
        nth witness (DBLL.val sig0) j
        = cf ps0 (set_chidx ad0 j) 0
             (BaseW.val (encode_msgWOTS_C ps0 ad0 m0 c0).[j])
             (DigestBlock.val (nth witness (DBLL.val skW) j)))
  => equiv[FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C ~ WOTS_TW_ES.pkWOTS_from_skWOTS
           :    m{1} = m0 /\ sigWOTS{1} = sig0 /\ counter{1} = c0 /\ ps{1} = ps0 /\ ad{1} = ad0
             /\ skWOTS{2} = skW /\ ps{2} = ps0 /\ ad{2} = ad0
           ==> res{1}.`1 = res{2}].
proof.
move=> adval hcpl.
proc.
sp; wp.
while (   ps{1} = ps0 /\ ad{1} = ad0 /\ sigWOTS{1} = sig0
       /\ em{1} = encode_msgWOTS_C ps0 ad0 m0 c0
       /\ skWOTS{2} = skW /\ ps{2} = ps0 /\ ad{2} = ad0
       /\ pkWOTS_l{1} = pkWOTS{2}
       /\ 0 <= size pkWOTS{2} <= len).
+ wp; skip => &1 &2 |> ge0sz lensz ltsz.
  have rng : 0 <= size pkWOTS{2} < len by smt().
  have vwad : valid_wadrs (set_chidx ad{1} (size pkWOTS{2})).
  - apply validwadrs_setchidx; [exact adval | smt()].
  have elem_eq :
      cf ps{1} (set_chidx ad{1} (size pkWOTS{2}))
         (BaseW.val (encode_msgWOTS_C ps{1} ad{1} m0 c0).[size pkWOTS{2}])
         (w - 1 - BaseW.val (encode_msgWOTS_C ps{1} ad{1} m0 c0).[size pkWOTS{2}])
         (DigestBlock.val (nth witness (DBLL.val sigWOTS{1}) (size pkWOTS{2})))
      = cf ps{1} (set_chidx ad{1} (size pkWOTS{2})) 0 (w - 1)
         (DigestBlock.val (nth witness (DBLL.val skWOTS{2}) (size pkWOTS{2}))).
  - rewrite (hcpl (size pkWOTS{2}) rng).
    apply cf_roundtrip; [exact vwad | exact DigestBlock.valP | smt(BaseW.valP)].
  rewrite elem_eq; smt(size_rcons).
skip => &1 &2 |>; smt(size_ge0 ge2_len).
qed.

(* ==========================================================================
   R1c COMPONENT (PROVEN) -- THE FORS INNER-TREE MERKLE ROOT ROUND-TRIP.

   The FORS analogue of `val_ap_cons_ap_trh_rt`, at the FORS Merkle instance
   (`FTWES.*`): height `a`, arity `t = 2 ^ a`, breadth index `bidx` (the FORS tree
   index in [0,k-1]), auth-path subtype `FTWES.DBAL`.  Reconstructing an inner
   FORS tree's root from the HONEST auth path (`FTWES.cons_ap_trh`, what
   `FTWES.FL_FORS_ES.sign` stores per tree) and the honest leaf equals the tree
   root `FTWES.val_bt_trh` (what `gen_pkFORS` computes per tree).  It drops into
   the per-tree step of the k-tree `pkFORS_from_sigFORSTW o sign = gen_pkFORS`
   round-trip (R1c).

   HONESTY CORRECTION (2026-07-21): the earlier ledger claim that
   `val_ap_cons_ap_trh_rt` "REUSES VERBATIM at the FORS height/arity" was TOO
   OPTIMISTIC.  FORS's `val_ap_trh`/`cons_ap_trh`/`val_bt_trh` (FORS_ES.ec:695-721)
   are SYNTACTICALLY DISTINCT ops from the hypertree family (FL_SL_XMSS_MT_ES.ec:
   685-706): 6-vs-5 args (the extra `bidx`), height `a` not `h'`, subtype
   `FTWES.DBAL` (size `a`) not `DBHPL` (size `h'`).  An EC lemma about one op
   family does NOT apply to the other even though both factor through the generic
   `eq_valbt_valap` (MerkleTrees.ec:71).  So only the PROOF SCRIPT transfers; this
   is a genuinely separate lemma, re-derived here (h'->a, l'->t, 0->bidx,
   DBHPL->FTWES.DBAL, unqualified FSSLXMTWES ops -> FTWES.-qualified FORS ops).

   NON-VACUITY (machine-checked, scratch/, both REJECTED by the gate): dropping
   `0 <= idx < t` (leaf membership `list2tree_lvb` no longer discharges) and
   corrupting the reconstructed leaf `nth .. idx -> nth .. 0` in the
   `eq_valbt_valap` application (leaf no longer unifies) each break the proof.
   ========================================================================== *)
lemma val_ap_cons_ap_trh_rt_fors (ps : pseed) (ad : adrs) (leaves : dgstblock list) (idx bidx : int) :
     size leaves = t
  => 0 <= idx < t
  => FTWES.val_ap_trh ps ad (FTWES.cons_ap_trh ps ad (list2tree leaves) idx bidx) idx
                      (nth witness leaves idx) bidx
     = FTWES.val_bt_trh ps ad (list2tree leaves) bidx.
proof.
move=> szlvs [ge0_idx ltt_idx].
have ge0_a : 0 <= a by smt(ge1_a).
have szlvs2 : size leaves = 2 ^ a by rewrite szlvs.
have hidx : 0 <= idx < size leaves by rewrite szlvs; smt().
have fblvs : fully_balanced (list2tree leaves) by apply (list2tree_fullybalanced leaves a).
have hlvs : height (list2tree leaves) = a by apply (list2tree_height leaves a).
have szrvbs : size (rev (int2bs a idx)) = a by rewrite size_rev size_int2bs /#.
have hbs : height (list2tree leaves) = size (rev (int2bs a idx)) by rewrite hlvs szrvbs.
rewrite /FTWES.val_ap_trh /FTWES.val_ap_trh_gen /FTWES.val_bt_trh /FTWES.val_bt_trh_gen.
apply eq_sym.
apply (eq_valbt_valap (FTWES.trhi ps ad) FTWES.updhbidx (list2tree leaves)
                      (FTWES.DBAL.val (FTWES.cons_ap_trh ps ad (list2tree leaves) idx bidx))
                      (rev (int2bs a idx))
                      (nth witness leaves idx)
                      (a, bidx)).
+ exact fblvs.
+ by rewrite FTWES.DBAL.valP hlvs.
+ by rewrite FTWES.DBAL.valP szrvbs.
+ by rewrite (list2tree_lvb leaves idx a ge0_a szlvs2 hidx) (onth_nth witness leaves idx hidx).
+ move=> i; rewrite FTWES.DBAL.valP => rngi.
  have szc : size (FTWES.cons_ap_trh_gen ps ad (list2tree leaves) (rev (int2bs a idx)) a bidx) = a.
  - rewrite /FTWES.cons_ap_trh_gen (size_consap (FTWES.trhi ps ad) FTWES.updhbidx (list2tree leaves) (rev (int2bs a idx)) (a, bidx)).
    * exact fblvs.
    * exact hbs.
    exact szrvbs.
  rewrite /FTWES.cons_ap_trh.
  rewrite (FTWES.DBAL.insubdK (FTWES.cons_ap_trh_gen ps ad (list2tree leaves) (rev (int2bs a idx)) a bidx) szc).
  rewrite /FTWES.cons_ap_trh_gen.
  rewrite (nth_consap (FTWES.trhi ps ad) FTWES.updhbidx (list2tree leaves) (rev (int2bs a idx)) (a, bidx) i).
  * exact fblvs.
  * exact hbs.
  * by rewrite szrvbs; exact rngi.
  done.
qed.

(* ==========================================================================
   RESIDUAL LEDGER -- "compiles != correct" closed exactly as far as it CAN be.

   HEADLINE INVERSION (the finding, not just a gap).  The full scheme-correctness
   statement `phoare[DSSC.Stateless.Correctness(SPHINCS_PLUS_C10).main
   : true ==> res] = 1%r` (an honest signature always verifies) is NOT merely
   unproven in this port -- it is FALSE IN PRINCIPLE for the abstract +C model.
   This is a MODELLING artefact, not a C10 defect: real C10 has negligible
   grind-failure mass, but the abstract model does not carry the probabilistic
   fact needed to drive completeness to 1.  See R2.

   `verify` (line 235) returns a 4-way conjunction
       good_fors m mk  /\  size sigHT = d  /\  root' = root  /\  allOkC.
   PROVEN here (`sign_gates`, =1%r, non-vacuous -- canaries below):
     [1] good_fors m mk   -- the drawn mk is good by construction of the +C draw
                             `mk <$ dcond dmkey (good_fors m)` (Distr.dcond_supp:
                             supp(dcond d p) => p).  Non-vacuity rests on the
                             carried positive good-mass premise (= `good_pos`,
                             FORS_C10.ec:208, modulo the DEFINITIONAL identity
                             good_eq_good_fors, capstone:269); exposed as an
                             explicit dischargeable hypothesis, NO new axiom.
     [2] size sigHT = d   -- from the PROVEN `sign_size_d` (XMSSMT_C_Scheme.ec:249).
   These two are exactly the verify-conjuncts DETERMINED BY sign's own output
   (independent of pk).  The other two require pk<->sig round-trips and are the
   residual.  They are TWO DIFFERENT KINDS of gap -- do not conflate:

   R1 (`root' = root`)  --  a proof-ASSEMBLY residual, NOW MOSTLY DISCHARGED (the
      two per-layer cores + R1a + the ENTIRE R1c FORS round-trip are PROVEN above;
      only the R1b hypertree d-layer assembly remains).  root_eq is UNCONDITIONAL on
      the +C counter -- `okC` never feeds `root` in `root_from_sigC`
      (XMSSMT_C_Scheme.ec:187-192, the `root <- val_ap_trh ...` line ignores
      `allOkC`) -- so R1 is a genuine theorem INDEPENDENT of R2; do not thread the
      counter premise through it.  MM45 is security-only (no *packaged* end-to-end
      +C correctness theorem; the XMSSMT_C_Scheme.ec:223 "no correctness lemma
      anywhere" line is about the packaging, not the COMPONENTS), but the
      components exist and the two per-layer cores are now closed IN THIS FILE
      (each with a rejected canary):
        - [PROVEN: `val_ap_cons_ap_trh_rt`]  the Merkle inner-tree layer round-
          trip -- honest auth-path (`cons_ap_trh`) + honest leaf reconstruct the
          tree root (`val_bt_trh`).  From `eq_valbt_valap` (MerkleTrees.ec:71) +
          `size_consap`/`nth_consap` (MerkleTrees.ec:38/51) + `list2tree`
          height/balance/leaf facts (BinaryTrees.ec:188/199/209).
        - [PROVEN: `cf_roundtrip`]  the WOTS+C chain leaf round-trip -- verify's
          chain-completion (`cf .. em (w-1-em)`) of an honest WOTS+C sig element
          equals the sk-derived pk element (`cf .. 0 (w-1)`).  From `ch_comp`
          (WOTS_TW_ES.ec:533).  So the verify-recomputed WOTS pk equals the honest
          tree leaf's, element-wise -- which is the Merkle leaf `val_ap_cons_ap_
          trh_rt` consumes.
      ASSEMBLY STATUS (2 of 3 sub-legs now PROVEN in-file; R1b remains):
        (R1a) [PROVEN: `pkWOTS_sigC_eq_skWOTS`, :466]  lifts `cf_roundtrip`
              through the `len`-loop of `pkWOTS_from_sigWOTS_C` vs
              `pkWOTS_from_skWOTS` to a PROCEDURE-LEVEL relational pk equality on an
              honest WOTS+C sig (premise `hcpl`).  Hence equal `pkco` leaf.
        (R1c) [PROVEN: consumer `fors_pkFORS_from_sig_gen` (:776) + producer
              `fors_sign_trace` (:823)]  the verify-side FORS pkFORS round-trip
              `pkFORS_from_sigFORSTW o sign = gen_pkFORS`.  Consumer is an equiv
              `pkFORS_from_sigFORSTW ~ gen_pkFORS` under the honest element-wise
              coupling `val sig = fors_sig_op ss ps ad m` (:746), closing each of
              the k trees by the proven FORS Merkle core `val_ap_cons_ap_trh_rt_fors`
              (:532) + the per-tree index bound `fors_lfidx_bound` (:755); producer
              is a `hoare[FL_FORS_ES.sign : ... ==> val res = fors_sig_op ...]`
              that GROUNDS the coupling (via `fors_genleaves_closed`, :727).
              Mirrors MM45 `Eqv_SPHINCS_PLUS_S_sign` (SPHINCS_PLUS.ec:1885-1990),
              which carries the same producer trace + consumer reconstruction; FORS
              is byte-identical under +C (the +C delta is only in WOTS/HT).
        (R1b) [OPEN -- the remaining sub-leg]  the d-layer HYPERTREE root round-trip
              `root_from_sigC(m, sign(...), idx, ps, ad).1 = gen_root(ss, ps, ad)`.
              It is NOT a naive synchronised while: `root_from_sigC` loops d layers,
              `gen_root` builds ONE tree (the top, `set_ltidx ad (d-1) 0`).  The
              honest decomposition (adversarial review GPT-5.6, 2026-07-21) is FOUR
              genuine sub-lemmas, not bookkeeping:
                (i)   an HT signer trace `hoare[FL_SL_XMSS_MT_C_ES.sign : ... ==>
                      <closed form of sapl>]` -- sign RETURNS `sapl` only, not its
                      running root, so the running root must be reconstructed from
                      the trace (analogue of `fors_sign_trace`, but with the WOTS+C
                      counter `grindC` + `cons_ap_trh` per layer).
                (ii)  seed-based closed forms for `gen_skWOTS`/`leaves_from_sspsad`
                      + the SELECTED-LEAF bridge: the separately-generated signing
                      `skWOTS` (XMSSMT_C_Scheme.ec:124) is the SAME deterministic key
                      that `leaves_from_sspsad` (:81) regenerates at leaf `kpidx`,
                      and its `pkco` is exactly `nth leaves kpidx` -- the leaf R1a's
                      pk-equality + `val_ap_cons_ap_trh_rt` consume.  (R1a alone gives
                      pk equality for a GIVEN skW; this bridges skW to the tree leaf.)
                (iii) the index alignment via `foldedivz` (FL_SL_XMSS_MT_ES.ec:785):
                      at the TOP layer i=d-1, tidx = Index.val idx %/ l'^d = 0 (uses
                      idx < l'^d, which is `Index.valP` since l = 2^h = l'^d), so the
                      top layer's address matches `gen_root`'s `set_ltidx ad (d-1) 0`.
                      kpidx stays nonzero (selects the leaf in the unique top tree).
                (iv)  the d-layer running-root induction relating (i)'s trace to
                      `root_from_sigC`, each layer closing by R1a + (ii) +
                      `val_ap_cons_ap_trh_rt`, exit identifying the last root with
                      `gen_root` via (iii).
              Substantial (multi-day) and genuinely procedure-level relational, NOT
              one line.  Closest MM45 templates (both `local`, not callable):
              `Eqv_EUFNAGCMA_FLSLXMSSMTTWESNPRF_Orig_C` (FL_SL_XMSS_MT_ES.ec:3511,
              signer/index/running-root trace ~3846-3958) and `..._C_V` (:3962,
              reconstruction + final top-index).  There is NO packaged HT
              `root_from_sig ~ gen_root` correctness lemma to reuse.

   R2 (`allOkC`)  --  a genuine +C COMPLETENESS gap, NOT a round-trip, and the
      reason exact `=1%r` is unattainable in principle:
        - `predC` is an UNCONSTRAINED abstract op (WOTS_C_Real.ec:180): a model
          with predC == false everywhere is legal.
        - the total grinder returns `head witness (good_ctrs ...)`, i.e. a
          FALLBACK counter when NO good counter exists (Grind.ec:79; the failure
          event `grind_fails` and `grindP_iff`: predC(ground) <=> !grind_fails).
        - `sign_counter_predC` (WOTS_C_Scheme.ec:113) emits a good counter ONLY
          under an explicit per-layer EXISTENCE premise; `sign_ll` proves
          termination, NOT existence.
      Hence an honest signature whose layer has no acceptable counter carries the
      fallback, `pkWOTS_from_sigWOTS_C` recomputes `okC = predC(...) = false`, and
      honest `verify` REJECTS.  Correct residual shape: honest correctness holds
      UNDER a per-layer good-counter-existence hypothesis -- exactly
      `exists c, predC (ThC ps ad m c)` per WOTS+C layer, the premise of
      `sign_counter_predC` (WOTS_C_Scheme.ec:113) and `wotsc_grind_targets_predC`
      (WOTS_C_Real.ec:208).  ABSENCE of that fact is source-verified: there is NO
      unconditional axiom forcing a good counter (the old `axiom grindP` was
      REPLACED by the CONDITIONAL `grind_correct`, Grind.ec:127; `predC` stays a
      bare op).  Without the hypothesis the failure is qualitative -- "some
      WOTS+C layer's counter enumeration (`grind`) contains no predC-satisfying
      counter (`grind_fails`)".  NO numeric bound is proven here (do NOT conflate
      the FORS tree-count `k` with the WOTS counter search); unconditional `=1%r`
      is false.  Corroborated by FORS_C.ec:95's own completeness framing
      (Pr[honest sig verifies] >= 1 - p_nu).

   ==========================================================================
   THE CONDITIONAL CORRECTNESS LEMMA -- THE TARGET (STATED; proof pends R1b only).

   Guarding the (unconditionally-false) full-correctness headline by R2 makes it
   a true, honest statement: under the counter-existence hypothesis (R2) and the
   same positive good-mass premise that already drives `sign_gates`, the honest
   signature always verifies.  Precise EC statement (machine-checked to TYPECHECK
   in scratch/, admit-backed; NOT admitted into this CERTIFIED-0-ADMIT file):

       lemma sphincs_c10_correctness_conditional (m0 : msg) :
            0%r < mu dmkey (good_fors m0)                   (* good-mass = good_pos *)
         => (forall (ps : pseed) (ad : adrs) (mw : msgWOTS),
               exists (c : cntr), predC (ThC ps ad mw c))   (* R2: FALSE uncond. *)
         => phoare[DSSC.Stateless.Correctness(SPHINCS_PLUS_C10).main
                     : arg = m0 ==> res] = 1%r.

   The R2 premise shown is the BLANKET "grinding never fails at any WOTS+C
   address" assumption: SUFFICIENT (it forces `allOkC` at every visited layer via
   `sign_counter_predC`, WOTS_C_Scheme.ec:113) and clearly FALSE in the abstract
   model (`predC` may be identically false, WOTS_C_Real.ec:180) -- so this is a
   GENUINE conditional, NOT vacuous (its premise is satisfiable, e.g. predC==true,
   and unprovable, so neither branch is degenerate).  A MINIMAL premise would
   quantify only over the d layer inputs the honest signer actually visits; the
   blanket form is used because pinning those inputs needs the R1b sign trace.

   ITS PROOF (once R1b lands):  inline `keygen; sign; verify`; the verify
   conjunction [1] `good_fors m mk` and [2] `size sigHT = d` discharge by
   `sign_gates` (proven above); the FORS-message equality `pkFORS^v = pkFORS^s`
   (verify's `pkFORS_from_sigFORSTW` = sign's `gen_pkFORS`) discharges by R1c
   (`fors_pkFORS_from_sig_gen` + `fors_sign_trace`, PROVEN above), so verify's
   hypertree message equals sign's; [3] `root' = root` then reduces to R1b (the HT
   d-layer round-trip, cores `val_ap_cons_ap_trh_rt` + `cf_roundtrip` + R1a proven,
   the (i)-(iv) HT assembly open); [4] `allOkC` is NOT R2 alone -- R2 gives only
   EXISTENCE of a good counter, and `sign_counter_predC` (WOTS_C_Scheme.ec:113)
   makes each honest sig counter good AT ITS SIGN-LAYER `(ad_i^s, m_i^s)`, whereas
   verify tests `predC (ThC ps ad_i^v m_i^v counter_i)` at the VERIFY-LAYER; closing
   [4] therefore ALSO needs R1b's index/address alignment (`ad^v = ad^s`) and its
   per-layer running-root equality (`m^v = m^s`) to transport THAT good counter
   across.  So [4] depends on R1b too, not R2 in isolation.  Stated -- not admitted
   -- because R1b is not yet assembled and this file must stay CERTIFIED-0-ADMIT.
   (R1c's producer+consumer are the same PATTERN R1b sub-lemma (i) needs -- a signer
   trace -- but re-derived for the WOTS+C hypertree with its `grindC` counter, NOT a
   reusable instance; and R1b closes each layer with the ALREADY-PROVEN HYPERTREE
   Merkle core `val_ap_cons_ap_trh_rt` (Wave 8), which is SYNTACTICALLY DISTINCT from
   the FORS core `val_ap_cons_ap_trh_rt_fors` R1c uses -- per the honesty correction
   at :516-525, only the proof SCRIPT transfers between the two, never the lemma.
   So R1b is the LAST assembly leg, but a genuinely new one, not a re-instantiation.)

   ==========================================================================
   NEGATIVE CONTROLS (machine-checked, kept in scratch/, all REJECTED by the
   gate -- proof each proven fragment is non-vacuous and genuinely checked):
     - canary_size : replacing gate [2] with `size res = d + 1` -> conseq
       side-goal cannot close -> REJECTED (the size gate really pins d).
     - canary_novac: `sign_gates`'s `=1%r` with the positive-mass premise DROPPED
       -> losslessness unprovable -> REJECTED (the `=1%r` really needs good-mass;
       a null dcond would give prob 0, not 1 -- so this is not vacuous).
     - canaryA1 (`val_ap_cons_ap_trh_rt`): DROP the `0 <= idx < l'` hypothesis
       -> leaf membership (`list2tree_lvb`) no longer discharges -> REJECTED.
     - canaryA2 (`val_ap_cons_ap_trh_rt`): corrupt the reconstructed leaf
       `nth .. idx -> nth .. 0` in the RHS -> `eq_valbt_valap` leaf no longer
       unifies -> REJECTED (the exact honest leaf is load-bearing).
     - canary_cf (`cf_roundtrip`): corrupt the full-chain length `w-1 -> w-2`
       -> chain endpoints no longer coincide -> REJECTED.
   ========================================================================== *)

op fors_leaves_op (ss0:sseed) (ps0:pseed) (ad0:adrs) (idxt0:int) : dgstblock list =
  mkseq (fun (j:int) => f ps0 (set_thtbidx ad0 0 (idxt0*t+j))
                          (DigestBlock.val (skg ss0 (ps0, set_thtbidx ad0 0 (idxt0*t+j))))) t.

lemma fors_genleaves_closed (idxt0:int) (ss0:sseed) (ps0:pseed) (ad0:adrs) :
  hoare[FTWES.FL_FORS_ES.gen_leaves_single_tree :
    idxt=idxt0 /\ ss=ss0 /\ ps=ps0 /\ ad=ad0 ==> res = fors_leaves_op ss0 ps0 ad0 idxt0].
proof.
proc.
while (idxt=idxt0 /\ ss=ss0 /\ ps=ps0 /\ ad=ad0 /\ size leaves <= t
       /\ leaves = mkseq (fun (j:int) => f ps0 (set_thtbidx ad0 0 (idxt0*t+j))
                            (DigestBlock.val (skg ss0 (ps0, set_thtbidx ad0 0 (idxt0*t+j))))) (size leaves)).
+ wp; skip => /> &hr szle lvsdef ltt.
  rewrite size_rcons; split; 1: smt().
  by rewrite {1}lvsdef mkseqS 1:size_ge0.
wp; skip => />; split; 1: by rewrite mkseq0 /=; smt(ge2_t).
move=> leaves negg szle lvsdef.
have szt : size leaves = t by smt(ge2_t).
by rewrite /fors_leaves_op {1}lvsdef szt.
qed.

(* The FORS honest-signature closed form: k trees, tree i signs message-slice
   lfidx i with skg secret + honest auth path over the tree's leaves. *)
op fors_sig_op (ss0:sseed) (ps0:pseed) (ad0:adrs) (m0:FTWES.msgFORSTW)
   : (dgstblock * FTWES.apFORSTW) list =
  mkseq (fun (i:int) =>
    let lfidx = bs2int (rev (take a (drop (a*i) (FTWES.BLKAL.val m0)))) in
    (skg ss0 (ps0, set_thtbidx ad0 0 (i*t+lfidx)),
     FTWES.cons_ap_trh ps0 ad0 (list2tree (fors_leaves_op ss0 ps0 ad0 i)) lfidx i)) k.

(* The per-tree FORS message index lands in [0,t): each tree consumes a distinct
   a-bit slice of the (k*a)-bit FORS digest. *)
lemma fors_lfidx_bound (mv : FTWES.msgFORSTW) (sr : int) :
  0 <= sr < k =>
  0 <= bs2int (rev (take a (drop (a * sr) (FTWES.BLKAL.val mv)))) < t.
proof.
move=> [ge0_sr ltk_sr].
split; first exact bs2int_ge0.
move=> _.
have szr : size (rev (take a (drop (a * sr) (FTWES.BLKAL.val mv)))) = a.
- rewrite size_rev size_take 2:size_drop 3:FTWES.BLKAL.valP; 1,2: smt(ge1_a size_ge0).
  have hb : a <= a * (k - sr) by rewrite -{1}(mulr1 a) IntOrder.ler_wpmul2l; smt().
  have hr : a * (k - sr) = k * a - a * sr by ring.
  smt().
have hle := bs2int_le2Xs (rev (take a (drop (a * sr) (FTWES.BLKAL.val mv)))).
have ht : t = 2 ^ a by rewrite /t.
rewrite ht; rewrite szr in hle; exact hle.
qed.

(* R1c CONSUMER: pkFORS_from_sigFORSTW on an HONEST FORS signature reconstructs
   exactly gen_pkFORS.  Mirrors MM45 SPHINCS_PLUS.ec:1932-1990 (the pkFORS
   reconstruction block of Eqv_SPHINCS_PLUS_S_sign), reusing the proven FORS
   Merkle inner-tree core val_ap_cons_ap_trh_rt_fors. *)
lemma fors_pkFORS_from_sig_gen (ssv:sseed) (psv:pseed) (adv:adrs)
                               (mv:FTWES.msgFORSTW) (sigv:FTWES.sigFORSTW) :
     FTWES.DBAPKL.val sigv = fors_sig_op ssv psv adv mv
  => equiv[FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW ~ FTWES.FL_FORS_ES.gen_pkFORS :
        sig{1}=sigv /\ m{1}=mv /\ ps{1}=psv /\ ad{1}=adv
     /\ ss{2}=ssv /\ ps{2}=psv /\ ad{2}=adv
        ==> res{1}=res{2}].
proof.
move=> hcpl.
proc.
wp.
while (   ={roots} /\ ps{1}=psv /\ ad{1}=adv /\ m{1}=mv /\ sig{1}=sigv
       /\ ss{2}=ssv /\ ps{2}=psv /\ ad{2}=adv /\ 0 <= size roots{1} <= k).
+ inline{2} 1.
  wp.
  while{2} (leaves0{2}
            = mkseq (fun (j:int) => f ps0{2} (set_thtbidx ad0{2} 0 (idxt{2}*t+j))
                       (DigestBlock.val (skg ss0{2} (ps0{2}, set_thtbidx ad0{2} 0 (idxt{2}*t+j))))) (size leaves0{2})
            /\ size leaves0{2} <= t)
           (t - size leaves0{2}).
  - move=> ? z.
    by wp; skip => />; smt(size_rcons size_ge0 mkseqS).
  wp; skip => /> &1 &2 hlek hltk.
  split => [| leaves0_R]; 1: by rewrite mkseq0; smt(ge2_t).
  split => [/#| hnlt lvsdef hlet].
  have szlvst : size leaves0_R = t by smt().
  have lvsval : leaves0_R = fors_leaves_op ssv psv adv (size roots{1}).
  - by rewrite /fors_leaves_op {1}lvsdef szlvst.
  pose lfidx := bs2int (rev (take a (drop (a * size roots{1}) (FTWES.BLKAL.val mv)))).
  have szbslt : 0 <= lfidx < t by rewrite /lfidx; apply fors_lfidx_bound; smt().
  have hnth : nth witness (FTWES.DBAPKL.val sigv) (size roots{1})
              = (skg ssv (psv, set_thtbidx adv 0 (size roots{1}*t+lfidx)),
                 FTWES.cons_ap_trh psv adv (list2tree (fors_leaves_op ssv psv adv (size roots{1}))) lfidx (size roots{1})).
  - by rewrite hcpl /fors_sig_op nth_mkseq /=; smt().
  have leafval : f psv (set_thtbidx adv 0 (size roots{1}*t+lfidx))
                   (DigestBlock.val (skg ssv (psv, set_thtbidx adv 0 (size roots{1}*t+lfidx))))
                 = nth witness (fors_leaves_op ssv psv adv (size roots{1})) lfidx.
  - by rewrite /fors_leaves_op nth_mkseq //=.
  rewrite hnth /= leafval.
  rewrite (val_ap_cons_ap_trh_rt_fors psv adv (fors_leaves_op ssv psv adv (size roots{1})) lfidx (size roots{1})).
  + by rewrite /fors_leaves_op size_mkseq; smt(ge2_t).
  + exact szbslt.
  rewrite lvsval; smt(size_rcons ge1_k).
wp; skip => />; smt(ge1_k size_ge0).
qed.

(* R1c PRODUCER: FL_FORS_ES.sign emits exactly the fors_sig_op closed form. *)
lemma fors_sign_trace (ssv:sseed)(psv:pseed)(adv:adrs)(mv:FTWES.msgFORSTW) :
  hoare[FTWES.FL_FORS_ES.sign :
    sk = (ssv,psv,adv) /\ m = mv ==> FTWES.DBAPKL.val res = fors_sig_op ssv psv adv mv].
proof.
proc.
sp.
while (ss = ssv /\ ps = psv /\ ad = adv /\ m = mv /\ 0 <= size sig <= k
       /\ sig = mkseq (fun (i:int) =>
            let lfidx = bs2int (rev (take a (drop (a*i) (FTWES.BLKAL.val mv)))) in
            (skg ssv (psv, set_thtbidx adv 0 (i*t+lfidx)),
             FTWES.cons_ap_trh psv adv (list2tree (fors_leaves_op ssv psv adv i)) lfidx i)) (size sig)).
+ wp; exlim (size sig) => szs.
  call (fors_genleaves_closed szs ssv psv adv); wp; skip.
  move=> &hr [hszs [[hss [hps [had [hm [hb sigdef]]]]] guard]] /=.
  split; first smt().
  move=> junk lv heq.
  have key : rcons sig{hr}
       (skg ss{hr} (ps{hr}, set_thtbidx ad{hr} 0 (size sig{hr} * t + bs2int (rev (take a (drop (a * size sig{hr}) (FTWES.BLKAL.val m{hr})))))),
        FTWES.cons_ap_trh ps{hr} ad{hr} (list2tree lv) (bs2int (rev (take a (drop (a * size sig{hr}) (FTWES.BLKAL.val m{hr}))))) (size sig{hr}))
     = mkseq (fun (i:int) => let lfidx = bs2int (rev (take a (drop (a*i) (FTWES.BLKAL.val mv)))) in
              (skg ssv (psv, set_thtbidx adv 0 (i*t+lfidx)),
               FTWES.cons_ap_trh psv adv (list2tree (fors_leaves_op ssv psv adv i)) lfidx i)) (size sig{hr} + 1).
  - by rewrite mkseqS 1:size_ge0 /= -sigdef heq hszs hss hps had hm.
  smt(size_rcons).
skip => &m hpre; split; last first.
+ move=> sig0 hnlt hinv.
  have szk : size sig0 = k by smt().
  have hs0 : sig0 = fors_sig_op ssv psv adv mv by rewrite hinv /fors_sig_op szk.
  have hsz : size (fors_sig_op ssv psv adv mv) = k by rewrite /fors_sig_op size_mkseq; smt(ge1_k).
  by rewrite hs0 FTWES.DBAPKL.insubdK.
+ have hsig : sig{m} = [] by smt().
  rewrite hsig mkseq0 /=; smt(ge1_k).
qed.
