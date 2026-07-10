(* ==========================================================================
   WOTS_C_Real.ec  --  The WOTS+C additions instantiated on the REAL
                       FV-SPHINCSPLUS-EC WOTS-TW infrastructure.

   THIRD-INCREMENT ARTIFACT for the C10 (SPHINCS+C) EUF-CMA mechanization.

   This file `require import`s the real `WOTS_TW_ES` (which builds clean under
   the pinned EasyCrypt r2026.02 toolchain — switch `ec-r2026`) and instantiates
   the S-TCR(+C) theory (STCR_C.STCRC) with the REAL SPHINCS+ WOTS types
   (pseed / adrs / dgstblock / msgWOTS).  The upshot:

     * `InSec^{S-TCR(+C)}(Th+C; q6)` — the ONE security term SPHINCS+C adds to
       the SPHINCS+ bound (paper Thm 5.2) — is now a CONCRETE game over the real
       digest / address / public-seed types and the REAL Th_lambda collection
       oracle (FC.Oracle_THFC's sibling), not an abstract placeholder.
     * The +C grinding is the PROVED total op (Grind.grind via STCRC_WC), so
       `wotsc_grind_targets_predC` (grinding always yields a Prop-satisfying
       target when one exists) holds over the real types with NO grindP axiom.

   WHAT REMAINS (honestly): the WOTS+C SCHEME (keygen/sign/verify with the
   chain walk + counter), the d-EU-naCMA game `M_EUF_GCMA_WOTSC_NPRF`, and the
   two reductions (Alg 9 / Alg 10) that discharge Thm C.2 / Thm D.1.  Their
   full statement is written below as a precise composition roadmap keyed to the
   real games/lemmas; the reduction PROOFS are the App-D pRHL fill (the
   person-months core) and are not attempted here.  See PLAN.md §3/§4.
   ========================================================================== *)

require import AllCore List Distr StdBigop StdOrder.
require import SPHINCS_PLUS.
require STCR_C.

import FSSLXMTWES.         (* n, w, len, d, nr_nodes_ht, pseed, dgst (FLAG-2 rebase) *)
import FSSLXMTWES.WTWES.   (* CONCRETE WOTS-TW instance *)
import HA.Adrs.            (* val / insubd / put on the adrs subtype *)

(* `c` (the WOTS-TW instance count) is SUBSTITUTED AWAY by the concrete clone
   (FL_SL_XMSS_MT_ES.ec:547 `op c <- bigi predT (fun d' => nr_nodes_ht d' 0) 0 d`),
   so the name no longer exists in WTWES. Re-expose it under the SAME name and
   the SAME definition, so every WOTS+C statement stays byte-identical. *)
import Bigint BIA.
op c : int = bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 d.

(* --------------------------------------------------------------------------
   1.  WOTS+C-specific parameters over the REAL WOTS types.
   -------------------------------------------------------------------------- *)
(* r-bit grinding counter (C10: 32-bit word) — finite (carried as the modelling
   axiom STCRC_WC.G.CntrFT.enum_spec once instantiated). *)
type cntr.

(* --------------------------------------------------------------------------
   The SPHINCS+ message-compression embedding (moved here from WOTS_C_Bridge.ec
   so that Th+C can be DEFINED as the SPHINCS+ tweakable hash at the embedded
   message-compression address, discharging the bridge's FLAG-1 `emb_thfc_ThC`
   hypothesis DEFINITIONALLY — see WOTS_C_EmbDischarge.ec).

     emb_tw : maps a WOTS instance address to its (distinct-type) SPHINCS+
              message-compression address.
     emb_in : serialises a (message, counter) pair to the `dgst` that the
              tweakable hash compresses.

   Both stay ABSTRACT ops (the concrete address encoding / serialisation is a
   downstream SPHINCS+ instantiation detail); Th+C being `thfc` at the embedded
   address on the embedded input is the faithful, non-degenerate modelling fact
   (paper Thm 5.2: Th+C is a member of the SPHINCS+ tweakable-hash family). *)
op emb_tw (ad : adrs) : adrs =
  insubd (put (put (put (val ad) 0 0) 1 0) 3 pkcotype).

(* ==========================================================================
   FLAG-2, DISCHARGED IN-PLACE (rebase 2026-07-09).  Previously `emb_tw` was an
   ABSTRACT op over the ABSTRACT `WOTS_TW_ES`, so `emb_disj_wgpidxs` had to be
   carried as a hypothesis all the way to the capstone, while its proof sat in
   `WOTS_C_Flag2Discharge.ec` over the CONCRETE `FSSLXMTWES.WTWES` -- a different
   namespace, hence unusable.  Re-basing this file onto the concrete instance and
   DEFINING `emb_tw` lets the proof live where the premise was.  Ported verbatim
   from WOTS_C_Flag2Discharge.ec (which stays as the standalone record).
   `thfc` / `emb_in` / `predC` STAY ABSTRACT, so the S-TCR(+C) term remains the
   genuine SM-DT-TCR-C assumption -- nothing is trivialised.
   ========================================================================== *)
(* Instance properties: any valid SPHINCS+ address supplies the kpidx/tidx/lidx
   the pkco validity predicate demands (needed by emb_tw_valid). *)
lemma valwadrs_inst (b : adrs) :
     valid_kpidx (nth witness (val b) 2)
  /\ valid_tidx (nth witness (val b) 5) (nth witness (val b) 4)
  /\ valid_lidx (nth witness (val b) 5).
proof.
have vb := valP b.
move: vb; rewrite /valid_adrsidxs => -[_].
rewrite /valid_idxvals /valid_idxvalsch /valid_idxvalspkco /valid_idxvalstrhx.
rewrite /valid_idxvalstrhf /valid_idxvalstrco /valid_kpidx /valid_lidx /l'.
move=> H.
smt(ge1_d IntOrder.expr_gt0).
qed.

lemma emb_tw_valid (b : adrs) :
  valid_adrsidxs (put (put (put (val b) 0 0) 1 0) 3 pkcotype).
proof.
have szb : size (val b) = adrs_len by move: (valP b); rewrite /valid_adrsidxs.
have [hk [ht hl]] := valwadrs_inst b.
rewrite /valid_adrsidxs !size_put szb /=.
rewrite /valid_idxvals; right; left.
rewrite /valid_idxvalspkco.
rewrite !nth_put ?size_put ?szb //= /adrs_len //=.
qed.

lemma emb_tw_val (b : adrs) :
  val (emb_tw b) = put (put (put (val b) 0 0) 1 0) 3 pkcotype.
proof. by rewrite /emb_tw insubdK 1:emb_tw_valid. qed.

lemma nth3_emb_tw (b : adrs) : nth witness (val (emb_tw b)) 3 = pkcotype.
proof.
have sz : size (put (put (val b) 0 0) 1 0) = adrs_len.
+ rewrite !size_put; move: (valP b); rewrite /valid_adrsidxs => -[-> _] //.
rewrite emb_tw_val nth_put; 1: by rewrite sz /adrs_len.
done.
qed.

lemma nth3_valid (a : adrs) : valid_wadrs a => nth witness (val a) 3 = chtype.
proof.
rewrite /valid_wadrs /valid_wadrsidxs /valid_widxvals /valid_widxvalsgp => -[_ [+ _]].
rewrite drop_drop //= => -[_ [+ _]].
by rewrite nth_drop.
qed.

(* NON-VACUITY: the guard premise is live (a valid WOTS signing address exists). *)
lemma nonvac_guard : exists (a : adrs), valid_wadrs a.
proof. exists (WAddress.val witness); exact: WAddress.valP. qed.

(* NON-DEGENERACY: no emb_tw image is itself a valid WOTS chain address, so
   FLAG-2 is not vacuously true via an `a := emb_tw b` self-collision. *)
lemma emb_off_range (b : adrs) : ! valid_wadrs (emb_tw b).
proof.
apply/negP => v.
have := nth3_valid (emb_tw b) v; rewrite nth3_emb_tw.
smt(dist_adrstypes).
qed.

(* THE FLAG-2 FACT ITSELF -- now a THEOREM on the stack, not a hypothesis. *)
lemma emb_disj_concrete (a b : adrs) :
  valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b).
proof.
move=> va; apply/negP => heq.
have e1 : nth witness (get_wgpidxs a) 1 = chtype.
+ by rewrite /get_wgpidxs nth_drop //= (nth3_valid a va).
have e2 : nth witness (get_wgpidxs (emb_tw b)) 1 = pkcotype.
+ by rewrite /get_wgpidxs nth_drop //= nth3_emb_tw.
have : chtype = pkcotype by rewrite -e1 -e2 heq.
smt(dist_adrstypes).
qed.
op emb_in : msgWOTS * cntr -> dgst.

(* Th+C : the count-tweaked message-compression hash
   (paper Thm 5.2:  Th+C : P x T x {0,1}^n x {0,1}^r -> {0,1}^n).
   DEFINED as the SPHINCS+ tweakable hash `thfc` at the embedded message-
   compression address `emb_tw tw` on the serialised input `emb_in (m,c)`,
   with the thfc input-length index `size (emb_in (m,c))`.  This makes the
   bridge's `emb_thfc_ThC` hold by construction (it is the DEFINITION of how
   SPHINCS+ realises Th+C), WITHOUT trivialising the S-TCR(+C) term: `thfc`,
   `emb_tw`, `emb_in`, `predC` all stay abstract, so `InSec^{S-TCR(+C)}(Th+C)`
   remains the genuine SM-DT-TCR-C assumption over the abstract tweakable hash. *)
op ThC (ps : pseed) (tw : adrs) (m : msgWOTS) (c : cntr) : dgstblock =
  thfc (size (emb_in (m, c))) ps (emb_tw tw) (emb_in (m, c)).

(* The +C predicate on a digest (WOTS+C: base_w sums to target_sum, and the
   first z digits are zero).  Abstract here; tied to base_w in the scheme file. *)
op predC : dgstblock -> bool.

(* Number of S-TCR(+C) targets the SPHINCS+ reduction places (paper: q6). *)
const p_tgts : { int | 0 <= p_tgts } as ge0_ptgts.

(* --------------------------------------------------------------------------
   2.  THE ADDED TERM, REAL: instantiate S-TCR(+C) on the real types.
   -------------------------------------------------------------------------- *)
clone import STCR_C.STCRC as STCRC_WC with
  type pp_t   <- pseed,
  type tw_t   <- adrs,
  type msg_t  <- msgWOTS,
  type cntr   <- cntr,
  type out_t  <- dgstblock,
  op   ThC    <- ThC,
  op   predC  <- predC,
  op   dpp    <- dpseed,
  op   p_stcr <- p_tgts
  proof dpp_ll, ge0_pstcr.
realize dpp_ll   by exact: dpseed_ll.
realize ge0_pstcr by exact: ge0_ptgts.

(* The concrete real S-TCR(+C) game is now `STCRC_WC.S_TCR_C`, its challenge
   oracle `STCRC_WC.O_STCRC_Default`, and its collection (Th_lambda) oracle
   `STCRC_WC.Col.O_THFC_Default` — all over pseed / adrs / dgstblock. *)

(* Grinding over the REAL types, PROVED (re-export of the discharged gap #1):
   when a Prop-satisfying counter exists, the total grind returns one. *)
lemma wotsc_grind_targets_predC (ps : pseed) (ad : adrs) (m : msgWOTS) :
  (exists c, predC (ThC ps ad m c)) => predC (ThC ps ad m (STCRC_WC.G.grind ps ad m)).
proof. exact: STCRC_WC.query_targets_predC. qed.

(* --------------------------------------------------------------------------
   3.  WOTS+C encoding (the count-dependent replacement for encode_msgWOTS).
       CONTRAST the abstract WOTS-TW hook `encode_msgWOTS : msgWOTS -> emsgWOTS`
       (WOTS_TW_ES.ec:569) — a pure function of the message alone.  WOTS+C's
       encoding additionally depends on (pseed, adrs, counter), which is exactly
       why WOTS+C is a REDUCTION, not an `encode_msgWOTS` instantiation
       (see WOTS_C_Encoding.ec / PLAN.md §1).
   -------------------------------------------------------------------------- *)
op encode_msgWOTS_C : pseed -> adrs -> msgWOTS -> cntr -> EmsgWOTS.emsgWOTS.

(* The signer's counter search is the proved total grind. *)
op grindC (ps : pseed) (ad : adrs) (m : msgWOTS) : cntr = STCRC_WC.G.grind ps ad m.

(* --------------------------------------------------------------------------
   4.  Thm C.2 / Thm D.1 — COMPOSITION ROADMAP (statements below are the goal;
       the WOTS+C scheme + reduction bodies + proofs are the remaining core).

   Thm D.1 (paper App D), the multi-instance form SPHINCS+ needs, in the shape
   of the real `MEUFGCMA_WOTSTWESNPRF` bound (WOTS_TW_ES.ec:6269) with ONE added
   S-TCR(+C) summand — every term on the RHS now nameable and REAL:

     Pr[ M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() ]  (* REAL now — WOTS_C_Scheme.ec *)
       <=  Pr[ STCRC_WC.S_TCR_C(R_STCRC_WOTSC(A),                        (* REAL, this file *)
                                STCRC_WC.O_STCRC_Default,
                                STCRC_WC.Col.O_THFC_Default).main() ]
         + Pr[ M_EUF_GCMA_WOTSTWESNPRF(R_WOTSTW_WOTSC(A),                 (* REAL, WOTS_TW_ES.ec:2323 *)
                                       O_MEUFGCMA_WOTSTWESNPRF,
                                       FC.O_THFC_Default).main() ].

   Composed with the reused black box `MEUFGCMA_WOTSTWESNPRF` (WOTS_TW_ES.ec:6269),
   the second summand unfolds to (w-2)*SM_DT_UD_C + SM_DT_TCR_C + SM_DT_PRE_C —
   giving the WOTS-layer terms of SPHINCS+C's Thm 5.2 unchanged, plus the single
   new S-TCR(+C) term instantiated in §2.

   The reductions R_STCRC_WOTSC (Alg 9) and R_WOTSTW_WOTSC (Alg 10) live inside a
   `section` with `declare module A <: Adv_MEUFGCMA_WOTSC` mirroring the repo's
   `declare module A` at WOTS_TW_ES.ec:2894; the WOTS-TW theorem is invoked as a
   black box (its 6314-line proof never reopened).  Not built here.
   -------------------------------------------------------------------------- *)

(* Losslessness of the S-TCR(+C) challenge oracle and the Th_lambda collection
   oracle over the real types (zero admits) — deterministic procs; genuine
   prerequisites the Alg-9/Alg-10 reductions consume. *)
lemma O_STCRC_query_ll : islossless STCRC_WC.O_STCRC_Default.query.
proof. by proc; auto. qed.

lemma O_THFC_query_ll : islossless STCRC_WC.Col.O_THFC_Default.query.
proof. by proc; auto. qed.
