(* ==========================================================================
   good_clone_probe.ec  --  ROLE = C / CLONE PROBE (bounded, self-contained).

   QUESTION.  Can the ABSTRACT FORS+C predicate machinery of FORS_C10.ec
   (`abstract theory FORSC10`, the `good`/`predC_fors`/`g`-axiom surface) be
   INSTANTIATED onto the base's concrete FORS clone

       FTWES = clone import FORS_ES  (SPHINCS_PLUS.ec:455, re-exported by XmssmtCC_All)

   with  mco <- FTWES.mco,  g <- FTWES.g,  ... so that the abstract `good`
   (FORS_C10.ec:201) and the concrete `good_fors` (rtop_forsc_wip.ec:124,
   = predC_fors unfolded on FTWES.mco / FTWES.g) become the SAME op -- and if so
   at what COST to the assumption ledger?

   METHOD.  We
     (1) prove FIVE standalone facts about the concrete `FTWES.g` -- the exact
         shapes of FORSC10's five g-axioms size_g / eqiks_g / neqisvs_g / rng_g /
         uniq_g (FORS_C10.ec:166-192);
     (2) `clone FORS_C10.FORSC10 as C` with  mkey/msg/out_t/k/a/dmkey/mco/g  bound
         to the concrete base objects, DISCHARGING (via `realize ... by exact ...`)
         the five g-axioms from (1) plus ge1_k / ge1_a / dmkey_ll from the base's
         own already-carried facts, and CARRYING good_pos (= p_nu) un-realized;
     (3) prove the equality lemma  `C.good m mk = good_fors m mk`.

   The concrete `g` (FORS_ES.ec:421), after the FTWES substitution, is
       g (mi : msgFORSTW * index) =
         let cmsg = chunk a (val mi.`1) in
         let idx  = val mi.`2 in
           mkseq (fun i => (idx, i, bs2int (rev (nth witness cmsg i)))) k
   and  msgFORSTW = BLKAL.sT  carries  size (val m) = k * a  (FORS_ES.ec:162-169).
   Those two facts are what make all five g-axioms PROVABLE rather than assumed.

   VERDICT (see the per-axiom table + ledger line at the bottom of this file).
   ========================================================================== *)

require import AllCore List Distr StdBigop StdOrder IntDiv.
require import DList DMap.
require import BinaryTrees MerkleTrees.
require import BitEncoding.
import BS2Int BitChunking.
require import SPHINCS_PLUS.
require FORS_C10.
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

(* --------------------------------------------------------------------------
   The concrete +C conditioning predicate, EXACTLY as in rtop_forsc_wip.ec:124.
   (predC_fors of FORS_C10.ec:197 unfolded on FTWES.g / FTWES.mco.)             *)
op good_fors (m : msg) (mk : mkey) : bool =
  (nth witness (FTWES.g (FTWES.mco mk m)) (k - 1)).`3 = 0.

(* ==========================================================================
   (1) FIVE standalone facts about the CONCRETE FTWES.g.
   These are the five g-axioms of FORSC10, stated at the concrete types.
   ========================================================================== *)

(* size_g : the digest names exactly k trees. *)
lemma ftw_size_g (y : FTWES.msgFORSTW * index) : size (FTWES.g y) = k.
proof. by rewrite /FTWES.g /= size_mkseq; smt(ge1_k). qed.

(* eqiks_g : every tuple names the SAME FORS instance (its `.`1 = val y.`2). *)
lemma ftw_eqiks_g (x x' : int * int * int) (y : FTWES.msgFORSTW * index) :
  x \in FTWES.g y => x' \in FTWES.g y => x.`1 = x'.`1.
proof. by rewrite /FTWES.g /= => /mkseqP [i [_ ->]] /mkseqP [j [_ ->]] /=. qed.

(* neqisvs_g : distinct tuples name distinct trees (their `.`2 differ). *)
lemma ftw_neqisvs_g (x x' : int * int * int) (y : FTWES.msgFORSTW * index) :
  x \in FTWES.g y => x' \in FTWES.g y => x <> x' => x.`2 <> x'.`2.
proof. by rewrite /FTWES.g /= => /mkseqP [i [_ ->]] /mkseqP [j [_ ->]] /=; smt(). qed.

(* rng_g : every leaf index is in range [0, t).  This is the ONE fact that needs
   the BLKAL length invariant  size (val y.`1) = k * a  so each chunk has size a. *)
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

(* uniq_g : the k trees named are pairwise distinct (F1 fix; strictly > neqisvs). *)
lemma ftw_uniq_g (y : FTWES.msgFORSTW * index) :
  uniq (map (fun (x : int * int * int) => x.`2) (FTWES.g y)).
proof.
rewrite /FTWES.g /= map_mkseq /mkseq map_inj_in_uniq 2:iota_uniq.
move => u v _ _ /=.
smt().
qed.

(* ==========================================================================
   (2) THE CLONE.  mco <- FTWES.mco, g <- FTWES.g, k/a/dmkey/types bound to the
   base concrete objects.  Realize the five g-axioms from (1) + ge1_k/ge1_a/
   dmkey_ll from the base.  CARRY good_pos (= p_nu) un-realized.
   ========================================================================== *)
clone FORS_C10.FORSC10 as C with
  type mkey  <- mkey,
  type msg   <- msg,
  type out_t <- FTWES.msgFORSTW * index,
  op   k     <- k,
  op   a     <- a,
  op   dmkey <- dmkey,
  op   mco   <- FTWES.mco,
  op   g     <- FTWES.g

  proof ge1_k, ge1_a, dmkey_ll, size_g, eqiks_g, neqisvs_g, rng_g, uniq_g.
  realize ge1_k     by exact: ge1_k.
  realize ge1_a     by exact: ge1_a.
  realize dmkey_ll  by exact: dmkey_ll.
  realize size_g    by exact: ftw_size_g.
  realize eqiks_g   by exact: ftw_eqiks_g.
  realize neqisvs_g by exact: ftw_neqisvs_g.
  realize rng_g     by exact: ftw_rng_g.
  realize uniq_g    by exact: ftw_uniq_g.
  (* good_pos : NOT named in the `proof` clause => carried as the axiom
     `C.good_pos (m : msg) : 0%r < mu dmkey (C.good m)` -- p_nu, re-typed at the
     concrete FTWES.mco / dmkey / g.  This is the SOLE ledger residual. *)

(* ==========================================================================
   (3) THE PAYOFF.  C.good IS good_fors -- provable, and definitional-by-clone.
   ========================================================================== *)
lemma good_eq_good_fors (m : msg) (mk : mkey) :
  C.good m mk = good_fors m mk.
proof. by rewrite /C.good /C.predC_fors /good_fors. qed.

(* Sanity: good_pos survives at the concrete instance as a NAMED axiom, and the
   oracle-losslessness gate that consumes it transfers unchanged. *)
lemma good_pos_is_carried (m : msg) : 0%r < mu dmkey (C.good m).
proof. exact: C.good_pos. qed.

(* ==========================================================================
   DELIVERABLE  --  PER-AXIOM VERDICT + LEDGER-LINE VERDICT
   (every row EMPIRICALLY confirmed by EasyCrypt: this file is CERTIFIED-0-ADMIT,
    the clone's `proof` clause named all 8 discharged axioms and each `realize`
    closed `by exact:` a real proven lemma; `print C.size_g` reports `lemma`,
    `print C.good_pos` reports `axiom`.)

   Q: do the abstract FORSC10 machinery and the concrete good_fors become the
      SAME op via  clone FORSC10 with mco <- FTWES.mco, g <- FTWES.g, ... ?
   A: YES.  good_eq_good_fors above proves  C.good m mk = good_fors m mk,
      and the proof is pure delta-unfolding (definitional-by-clone): after the
      substitution, C.predC_fors's body IS good_fors's body.  So the equality is
      BOTH provable-as-a-lemma AND definitional -- there is no ill-definedness
      cliff and no bridge clone is needed.

   ------------------------------------------------------------------------
   THE FIVE g-AXIOMS  (FORS_C10.ec:166-192).  All discharge; 0 new axioms.

     FORSC10 axiom     discharged?   realized by (concrete g fact used)
     ---------------   -----------   ------------------------------------------
     size_g   :166     YES           ftw_size_g   : size_mkseq + ge1_k
     eqiks_g  :168     YES           ftw_eqiks_g  : mkseqP -- each tuple's .1 =
                                                     val y.2 (the shared FORS idx)
     neqisvs_g:171     YES           ftw_neqisvs_g: mkseqP -- tuple i is a
                                                     function of i, so i<>j
     rng_g    :174     YES           ftw_rng_g    : in_chunk_size + BLKAL.valP
                                                     (size(val)=k*a) + bs2int_le2Xs
     uniq_g   :192     YES           ftw_uniq_g   : map_mkseq + map_inj_in_uniq
                                                     + iota_uniq

   Why they discharge and are not re-carried: the concrete FTWES.g is
   `mkseq (fun i => (val y.2, i, bs2int (rev (nth witness (chunk a (val y.1)) i)))) k`
   (FORS_ES.ec:421), a fully STRUCTURED op, and msgFORSTW = BLKAL.sT carries the
   length invariant `size (val m) = k*a` (FORS_ES.ec:162-169).  That structure is
   exactly what the five abstract axioms assert -- so at the concrete instance
   they are THEOREMS, proved from EasyCrypt-library + subtype facts only.  rng_g
   is the sole one needing the BLKAL length invariant (so each of the k chunks has
   size a and its leaf index is < 2^a = t); the other four are pure `mkseq` shape.

   Non-g realizations (also 0 new axioms):
     ge1_k, ge1_a, dmkey_ll  --  `by exact:` the BASE's own already-carried facts
     (SPHINCS_PLUS-level ge1_k / ge1_a / dmkey_ll).  Reduce to existing ledger
     entries; add nothing.

   ------------------------------------------------------------------------
   CARRIED RESIDUAL  (the ONE ledger line the clone lands on):

     good_pos  (FORS_C10.ec:208, = the paper's p_nu positive-good-mass axiom).
     EC print:  axiom good_pos: forall (m : msg), 0%r < mu dmkey (C.good m).

     It is CARRIED (not named in the clone's `proof` clause), now RE-TYPED at the
     concrete FTWES.mco / dmkey / g -- i.e. `C.good = good_fors`, so this is
     literally `0%r < mu dmkey (fun mk => good_fors m mk)`.  It is NOT a new
     assumption: it is the SAME p_nu that FORS_C10.ec already carries and that
     rtop_forsc_wip.ec:76-84 already names as the honest soundness-track residual.
     good_pos is genuinely un-dischargeable from FTWES's abstract mco/dmkey (a
     legal base model can force the good event to mass 0), which is exactly why it
     stays an axiom -- it is load-bearing for oracle losslessness (C.query_ll).

   ------------------------------------------------------------------------
   LEDGER-LINE VERDICT (bottom line).

     * The clone adds ZERO new axioms.
     * All 5 g-axioms DISCHARGE from FTWES's concrete g -- STRICTLY BETTER than the
       advisor's stated worst case (that they would re-instantiate as re-typed
       existing entries).  They do not even re-type; they become proved lemmas.
     * The clone lands on EXACTLY ONE existing ledger line: FORS_C10.ec's
       good_pos / p_nu, re-typed at the concrete instance.  No other assumption is
       introduced or moved.
   ========================================================================== *)
