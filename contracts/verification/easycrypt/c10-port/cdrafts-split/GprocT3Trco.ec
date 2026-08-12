(* T3 -- the TRCO reduction for Gproc.  SCRATCH: nothing integrates into the
   certified tree until a complete unit compiles.

   Port of R_TRCOSMDTTCRC_EUFCMA (base-c10-split/FORS_ES.ec:2643-2805) from
   MM45's multi-instance FORS game to C10's Gproc.  Substitutions:
     Adv_EUFCMA_MFORSTWESNPRF   -> Adv_EUFCMA_Gproc
     O_CMA_MFORSTWESNPRF_AV     -> O_CMA_Gproc_I
     trhtype                    -> trhftype        (the FTWES clone binds it)
     s, l                       -> nr_trees 0, l'  (likewise)
     g (mco mk' m')             -> M.F.hC mk' m'   (definitionally equal:
                                    FORS_C10.ec:211 is `hC mk m = g (mco mk m)`)
   The sk cube is sampled INLINE, mirroring GprocKg.keygen rather than MM45's
   gen_skFORS() call, so the two sides' loops align syntactically in the byequiv;
   GprocKg_sk_eq is the lemma that would otherwise have to bridge them. *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import DList DMap FMap.
require import BinaryTrees MerkleTrees.
require import BitEncoding.
import BS2Int BitChunking.
import StdOrder.IntOrder.
require import SPHINCS_PLUS.
require import XmssmtCC_All.
require import RtopCSoundness.
require import FxChain.
require import GprocFORSC10.
require import GprocVI.

module (R_TRCO_Gproc (A : Adv_EUFCMA_Gproc) : FTWES.TRCOC_TCR.Adv_SMDTTCRC)
       (O : FTWES.TRCOC_TCR.Oracle_SMDTTCR, OC : FTWES.TRCOC.Oracle_THFC) = {
  var ad : adrs
  var skFORSs : FTWES.skFORS list list
  var pkFORSs : FTWES.pkFORS list list

  proc pick() : unit = {
    var skFORS : FTWES.skFORS;
    var pkFORS : FTWES.pkFORS;
    var skFORSl : FTWES.skFORS list;
    var pkFORSl : FTWES.pkFORS list;
    var skFORS_ele, leaf, lnode, rnode, node : dgstblock;
    var skFORSet, leavest, nodespl, nodescl, rootsk : dgstblock list;
    var skFORScube, nodest : dgstblock list list;

    ad <- adz;
    skFORSs <- [];
    pkFORSs <- [];

    while (size skFORSs < nr_trees 0) {
      skFORSl <- [];
      pkFORSl <- [];

      while (size skFORSl < l') {
        (* --- sk cube for this instance, mirroring GprocKg.keygen ---------- *)
        skFORScube <- [];
        while (size skFORScube < k) {
          skFORSet <- [];
          while (size skFORSet < t) {
            skFORS_ele <$ ddgstblock;
            skFORSet <- rcons skFORSet skFORS_ele;
          }
          skFORScube <- rcons skFORScube skFORSet;
        }
        skFORS <- FTWES.DBLLKTL.insubd skFORScube;

        (* --- leaves and interior nodes, ALL through the collection oracle -- *)
        rootsk <- [];
        while (size rootsk < k) {
          leavest <- [];
          while (size leavest < t) {
            leaf <@ OC.query(set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSs)) (size skFORSl))
                                         0 (size rootsk * t + size leavest),
                             DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skFORS) (size rootsk)) (size leavest)));
            leavest <- rcons leavest leaf;
          }

          nodest <- [];
          while (size nodest < a) {
            nodespl <- last leavest nodest;
            nodescl <- [];
            while (size nodescl < nr_nodesf (size nodest + 1)) {
              lnode <- nth witness nodespl (2 * size nodescl);
              rnode <- nth witness nodespl (2 * size nodescl + 1);
              node <@ OC.query(set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSs)) (size skFORSl))
                                           (size nodest + 1) (size rootsk * nr_nodesf (size nodest + 1) + size nodescl),
                               DigestBlock.val lnode ++ DigestBlock.val rnode);
              nodescl <- rcons nodescl node;
            }
            nodest <- rcons nodest nodescl;
          }
          rootsk <- rcons rootsk (nth witness (nth witness nodest (a - 1)) 0);
        }

        (* --- register the root concatenation as a CHALLENGE TARGET -------- *)
        pkFORS <@ O.query(set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSs)) (size skFORSl)) trcotype)
                                    (FTWES.get_kpidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSs)) (size skFORSl))),
                          flatten (map DigestBlock.val rootsk));

        skFORSl <- rcons skFORSl skFORS;
        pkFORSl <- rcons pkFORSl pkFORS;
      }
      skFORSs <- rcons skFORSs skFORSl;
      pkFORSs <- rcons pkFORSs pkFORSl;
    }
  }

  proc find(ps : pseed) : int * dgst = {
    var root', leaf' : dgstblock;
    var roots' : dgstblock list;
    var m' : msg;
    var mk' : mkey;
    var sig' : sigGproc;
    var sigFORSTW' : FTWES.sigFORSTW;
    var tidx, kpidx, lfidx, cidx : int;
    var lidxs' : (int * int * int) list;
    var cm' : FTWES.msgFORSTW;
    var idx' : index;
    var skFORS_ele' : dgstblock;
    var ap' : FTWES.apFORSTW;
    var c : dgst;

    O_CMA_Gproc_I.init(skFORSs, ps, ad);

    (m', sig') <@ A(O_CMA_Gproc_I).forge((pkFORSs, ps, ad));

    (mk', sigFORSTW') <- sig';
    (cm', idx') <- FTWES.mco mk' m';
    (tidx, kpidx) <- edivz (Index.val idx') l';
    lidxs' <- M.F.hC mk' m';

    roots' <- [];
    while (size roots' < k) {
      lfidx <- (nth witness lidxs' (size roots')).`3;
      (skFORS_ele', ap') <- nth witness (FTWES.DBAPKL.val sigFORSTW') (size roots');
      leaf' <- f ps (set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx) 0 (size roots' * t + lfidx))
                 (DigestBlock.val skFORS_ele');
      root' <- FTWES.val_ap_trh ps (set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx) ap' lfidx leaf' (size roots');
      roots' <- rcons roots' root';
    }

    c <- flatten (map DigestBlock.val roots');
    cidx <- Index.val idx';

    return (cidx, c);
  }
}.


(* ISOLATED: the typeidx reduction the leaf-loop body needs.
   FTWES.gettype_setthtbkptypetrh has SIX side conditions, not five --
   valid_fidxvalsgp, valid_tidx (nth .. 4), valid_tidx i, valid_kpidx j,
   valid_thidx u, valid_tbidx u v.  MM45's `1..5:` leaves the sixth
   undischarged, so the tactic that follows silently attacks THAT instead of the
   main goal: the invocation "applies" and the goal survives.  Isolating it makes
   which condition actually fails visible. *)
(* adz is CONCRETE -- it is SPHINCS_PLUS's chain zero-address, NOT a FORS one.
   Proved by the recipe at SPHINCS_PLUS.ec:794-800 (setalladzch_gettypeidx). *)
lemma adz_val : HA.Adrs.val adz = [0; 0; 0; chtype; 0; 0].
proof.
rewrite /adz HA.Adrs.insubdK //.
rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
left => @/valid_idxvalsch /=.
(* Deterministic, one condition at a time.  The blanket
     `smt(ge2_len ge2_lp expr_ge0 expr_gt0)`
   copied from SPHINCS_PLUS.ec:752 was TIMEOUT-MARGINAL: it passed on a quiet
   machine and turned this file RED under host CPU contention, with the failure
   reported at a line 800 lines above anything I had edited.  It also omitted
   `val_w` -- the `0 < w - 1` conjunct was being found by search, not by hint,
   which is exactly why it was fragile.  `val_w` lives in WOTS_TW_ES and is
   NOT in scope unqualified here (it is inside SPHINCS_PLUS.ec, where that
   idiom was copied from). *)
rewrite /valid_hidx /valid_chidx /valid_kpidx /valid_tidx /valid_lidx /nr_trees /=.
do ! split.
+ smt(WOTS_TW_ES.val_w).
+ smt(ge2_len).
+ smt(ge2_lp).
+ by rewrite expr_gt0.
smt(ge1_d).
qed.

(* THE FORS ZERO ADDRESS, and the bridge from ours to it.

   The k-loop exit needs three of MM45's address lemmas -- vkpidx_setkpttype,
   neqtidx_setkp2type2trhtrco, neqkpidx_setkp2type2trhtrco -- and all three
   require `valid_fadrs ad`.  OUR adz does NOT satisfy it: adz is
   SPHINCS_PLUS's CHAIN zero address, type index chtype, and valid_fidxvals
   demands trhtype or trcotype.  (gettype_setkp2type2trhtrco, used in the same
   block, is stated over `val ad` instead and so applies directly -- MM45 has
   both styles.)

   But every address in the goal enters as `set_typeidx adz trhftype`, and
   set_typeidx (SPHINCS_PLUS.ec:427) zeroes indices 0,1,2 and writes index 3.
   So that expression is the CONCRETE list [0;0;0;trhftype;0;0], which IS a
   valid FORS address.  Proving that once makes all three lemmas citable at
   ad := adzf, instead of replaying their insubdK proofs with valid_fadrs
   weakened -- the same isolate-then-cite move that unblocked
   GprocTreeVI_root_h, gettype_leafaddr and root_from_nodest.

   The index-3 claim is READ FROM THE OP, not inferred from adz_val's shape: if
   set_typeidx wrote elsewhere, adzf's list would be off by one, this lemma
   would still TYPE-CHECK, and every downstream rewrite would silently fail to
   match -- this port's standing failure mode. *)
op adzf : adrs = HA.Adrs.insubd [0; 0; 0; trhftype; 0; 0].

lemma valid_fidxvals_adzf : FTWES.valid_fidxvals [0; 0; 0; trhftype; 0; 0].
proof.
rewrite /valid_fidxvals /=.
(* `/=` already discharges valid_fidxvalsgp (drop 5 _): the clone binds it to
   `nth witness adidxs 0 = 0` (SPHINCS_PLUS.ec:537) and drop 5 _ = [0]. *)
left => @/valid_fidxvalslptrh /=.
rewrite /valid_tbfidx /valid_thfidx /valid_kpidx /valid_tidx /nr_nodesf /nr_trees /=.
smt(ge1_a ge1_k ge2_lp expr_gt0).
qed.

lemma valid_adrsidxs_adzf : valid_adrsidxs [0; 0; 0; trhftype; 0; 0].
proof.
rewrite /valid_adrsidxs /adrs_len /=.
by apply FTWES.valid_fidxvals_idxvals; exact valid_fidxvals_adzf.
qed.

lemma adzf_val : HA.Adrs.val adzf = [0; 0; 0; trhftype; 0; 0].
proof. by rewrite /adzf HA.Adrs.insubdK 1:valid_adrsidxs_adzf. qed.

lemma valid_fadrs_adzf : FTWES.valid_fadrs adzf.
proof.
by rewrite /valid_fadrs /valid_fadrsidxs adzf_val /adrs_len /= valid_fidxvals_adzf.
qed.

lemma settype_adz_adzf : set_typeidx adz trhftype = adzf.
proof. by rewrite /set_typeidx adz_val /adzf. qed.

lemma settype_adzf : set_typeidx adzf trhftype = adzf.
proof. by rewrite /set_typeidx adzf_val /adzf. qed.

(* The form actually used at the rewrite site.  MM45's lemmas are phrased over
   `set_typeidx ad trhtype`, so the goal has to be moved into that shape at
   ad := adzf -- not merely collapsed to adzf, which would no longer match. *)
lemma settype_adz_eq : set_typeidx adz trhftype = set_typeidx adzf trhftype.
proof. by rewrite settype_adz_adzf settype_adzf. qed.

(* The k-loop step's mathematical core, ISOLATED: a fully-built nodest whose
   entries are the val_bt_trh_gen values determines the root at layer a-1,
   position 0.  This is exactly the final step of GprocTreeVI_root_h, lifted out
   of that hoare so the TRCO branch can CITE it instead of re-deriving it inside
   a 19-hypothesis equiv goal -- which is where every in-place attempt stalled. *)
lemma root_from_nodest (psi : pseed) (adTi : adrs) (lfs : dgstblock list)
                       (ui : int) (ndst : dgstblock list list) :
     size ndst = a
  => (forall (u v : int), 0 <= u < size ndst => 0 <= v < nr_nodesf (u + 1) =>
        nth witness (nth witness ndst u) v
        = FTWES.val_bt_trh_gen psi adTi
            (oget (sub_bt (list2tree lfs) (rev (int2bs (a - u - 1) v)))) (u + 1)
            (ui * nr_nodesf (u + 1) + v))
  => nth witness (nth witness ndst (a - 1)) 0
     = FTWES.val_bt_trh psi adTi (list2tree lfs) ui.
proof.
move=> hsz hinv.
have h := hinv (a - 1) 0 _ _.
+ smt(ge1_a).
+ rewrite /nr_nodesf (: a - (a - 1 + 1) = 0) 1:/# expr0; smt().
move: h.
rewrite (: a - 1 + 1 = a) 1:/# (: a - (a - 1) - 1 = 0) 1:/#.
rewrite /nr_nodesf (: a - a = 0) 1:/# expr0 /=.
rewrite /int2bs mkseq0 rev_nil subbt_empty oget_some.
by rewrite /FTWES.val_bt_trh.
qed.

(* THE PER-LEVEL MERKLE STEP, LIFTED.

   This is the inner-while body of GprocTreeVI_root_h (GprocVI.ec:135-183)
   restated as a pure equation.  Nothing about it is specific to that hoare
   judgement: it says that combining the two children at position nc of the
   previous level's row yields the val_bt_trh_gen value at (level+1, nc).

   Lifting it is what lets T3's node-loop body CITE the argument instead of
   replaying ~30 lines of take/drop/list2treeS surgery inside a two-memory
   equiv carrying ~19 hypotheses -- which is where every in-place attempt in
   this port has stalled.  root_from_nodest is the same lemma's FINAL step
   lifted the same way. *)
lemma node_level_step (psi : pseed) (adTi : adrs) (lfs : dgstblock list)
                      (ui : int) (ndst : dgstblock list list) (nc : int) :
     size lfs = t
  => 0 <= size ndst < a
  => (forall (u v : int), 0 <= u < size ndst => 0 <= v < nr_nodesf (u + 1) =>
        nth witness (nth witness ndst u) v
        = FTWES.val_bt_trh_gen psi adTi
            (oget (sub_bt (list2tree lfs) (rev (int2bs (a - u - 1) v)))) (u + 1)
            (ui * nr_nodesf (u + 1) + v))
  => 0 <= nc < nr_nodesf (size ndst + 1)
  => trh psi (set_thtbidx adTi (size ndst + 1) (ui * nr_nodesf (size ndst + 1) + nc))
         (DigestBlock.val (nth witness (last lfs ndst) (2 * nc))
          ++ DigestBlock.val (nth witness (last lfs ndst) (2 * nc + 1)))
     = FTWES.val_bt_trh_gen psi adTi
         (oget (sub_bt (list2tree lfs) (rev (int2bs (a - size ndst - 1) nc))))
         (size ndst + 1) (ui * nr_nodesf (size ndst + 1) + nc).
proof.
move=> eqt_szlfs [ge0_szndst lta_szndst] nthndst [ge0_nc ltnn1_nc].
rewrite /FTWES.val_bt_trh_gen (: a - size ndst - 1 = a - (size ndst + 1)) 1:/# /=.
rewrite subbt_list2tree_takedrop 4:oget_some; 1..3: smt(ge1_a size_ge0).
have ltnn_2nc1 : 2 * nc + 1 < nr_nodesf (size ndst).
- rewrite &(ltr_le_trans (2 + 2 * (nr_nodesf (size ndst + 1) - 1))) 1:/#.
  by rewrite /nr_nodesf mulzDr /= -{1}(expr1 2) -exprD_nneg // /#.
have ge1_2aszn2nc : 1 <= 2 ^ (a - size ndst) - 2 * nc - 1 by smt().
rewrite (last_nth witness); case (size ndst = 0) => [szn0 | nszn0].
- rewrite szn0 /= expr1 {3}(: 2 = 1 + 1) 1:// (take_nth witness) 1:size_drop 2:/=; 1,2: smt(size_ge0).
  rewrite (FTWES.take1_head witness) 1:size_drop 3:nth_drop 2:/= 4://; 1..3: smt(size_ge0).
  rewrite -cats1 (list2treeS 0) ?expr0 1..3:// /trhi /=.
  by rewrite ?list2tree1 /= -nth0_head nth_drop; smt(size_ge0).
rewrite nszn0 /= (: 2 ^ (size ndst + 1) = 2 ^ (size ndst) + 2 ^ (size ndst)).
+ by rewrite exprD_nneg 1:size_ge0 //= expr1 /#.
rewrite take_take_drop_cat 1,2:expr_ge0 1,2://.
rewrite drop_drop 1:expr_ge0 1://; 1: smt(expr_ge0).
rewrite (list2treeS (size ndst)) 1:size_ge0 1,2:size_take 1,3:expr_ge0 1,3:// 1,2:size_drop; 1,3: smt(size_ge0 expr_ge0).
+ rewrite eqt_szlfs /t (: 2 ^ a = 2 ^ (a - size ndst) * 2 ^ (size ndst)) 1:-exprD_nneg 2:size_ge0 1,2:/#.
  pose szn2 := 2 ^ (size ndst).
  rewrite (: 2 ^ (a - size ndst) * szn2 - nc * (szn2 + szn2) = (2 ^ (a - size ndst) - 2 * nc) * szn2) 1:/#.
  pose mx := max _ _; rewrite (: 2 ^ (size ndst) < mx) // /mx.
  pose sb := ((_ - _ * _) * _)%Int; rewrite &(ltr_le_trans sb) /sb 2:maxrr.
  by rewrite ltr_pmull 1:expr_gt0 // /#.
+ rewrite eqt_szlfs /t (: 2 ^ a = 2 ^ (a - size ndst) * 2 ^ (size ndst)) 1:-exprD_nneg 2:size_ge0 1,2:/#.
  pose szn2 := 2 ^ (size ndst).
  rewrite (: 2 ^ (a - size ndst) * szn2 - (szn2 + nc * (szn2 + szn2)) = (2 ^ (a - size ndst) - 2 * nc - 1) * szn2) 1:/#.
  pose sb := ((_ - _ - _) * _)%Int.
  move: ge1_2aszn2nc; rewrite lez_eqVlt => -[eq1_2as | gt1_2as].
  - by rewrite /sb -eq1_2as /= lez_maxr 1:expr_ge0.
  rewrite lez_maxr /sb 1:mulr_ge0 2:expr_ge0 //= 1:subr_ge0 1:ler_subr_addr.
  - rewrite &(ler_trans (1 + 2 * (nr_nodesf (size ndst + 1) - 1))) 1:/#.
    by rewrite /nr_nodesf mulzDr -{1}(expr1 2) -exprD_nneg // /#.
  rewrite (: szn2 < (2 ^ (a - size ndst) - 2 * nc - 1) * szn2) //.
  by rewrite ltr_pmull 1:expr_gt0.
rewrite 2?nthndst /=; 1..4: smt(size_ge0).
rewrite (: a - (size ndst - 1) - 1 = a - size ndst) 1:/#.
rewrite 2?subbt_list2tree_takedrop 3,6://; 1..4: smt(size_ge0).
rewrite oget_some /FTWES.val_bt_trh_gen /trhi /updhbidx /=; do 4! congr => [/# | /= | /# | /=].
+ rewrite /nr_nodesf mulrDr mulrA; congr.
  by rewrite eq_sym mulrAC -{1}(expr1 2) -exprD_nneg 1:// /#.
rewrite /nr_nodesf mulrDr -addrA; congr.
by rewrite eq_sym mulrCA; congr; rewrite -{1}(expr1 2) -exprD_nneg 1:// /#.
qed.

(* THE LEAF-INDEX BRIDGE for the suffix's roots loops.  The LEFT loop (MM45's
   pkFORS_from_sigFORSTW) indexes by the concrete chunk take/drop; the RIGHT one
   reads (nth witness (M.F.hC mk m) i).`3.  Stated directly in the take/drop
   form the loop body has, so no chunk-unfolding is needed at the use site.

   Definitional: M binds F.g <- FTWES.g (GprocFORSC10.ec:130) and FTWES.g is
   MM45's concrete extractor. *)
lemma hC_chunk (mk : mkey) (m : msg) (i : int) :
  0 <= i < k =>
  (nth witness (M.F.hC mk m) i).`3
  = bs2int (rev (take a (drop (a * i) (FTWES.BLKAL.val (FTWES.mco mk m).`1)))).
proof.
move=> rng_i.
rewrite /M.F.hC /FTWES.g /= nth_mkseq 1:// /= /chunk nth_mkseq //.
by rewrite FTWES.BLKAL.valP mulzK; smt(ge1_a).
qed.

(* The other two components, same definitional unfold.  Stated up front because
   MM45's collision argument uses .`2 (their eqfit_gcm2) and reads nthts at
   (val idx %/ l', val idx %% l'), which is .`1 -- discovering those mid-goal
   costs a probe each. *)
lemma hC_pos (mk : mkey) (m : msg) (i : int) :
  0 <= i < k => (nth witness (M.F.hC mk m) i).`2 = i.
proof. by move=> rng_i; rewrite /M.F.hC /FTWES.g /= nth_mkseq. qed.

lemma hC_inst (mk : mkey) (m : msg) (i : int) :
  0 <= i < k =>
  (nth witness (M.F.hC mk m) i).`1 = Index.val (FTWES.mco mk m).`2.
proof. by move=> rng_i; rewrite /M.F.hC /FTWES.g /= nth_mkseq. qed.

(* nr_trees 0 * l' = l.  The suffix's conseq has to discharge `size ts <= l`
   (SM_DT_TCR_C's t_smdttcr bound) from the invariant's `size ts = nr_trees 0 * l'`.
   MM45 cite `dval` for the analogous step; we have no such lemma, so it is
   proved from the parameter definitions:
     nr_trees 0 = 2^(h'*(d-1)),  l' = 2^h',  l = 2^h,  h = h'*d. *)
lemma nrtrees_lp_l : nr_trees 0 * l' = l.
proof.
rewrite /nr_trees /l' /l /h -exprD_nneg.
+ smt(ge1_hp ge1_d).
+ smt(ge1_hp).
by congr; ring.
qed.

(* The general-height form.  gettype_leafaddr below is its u = 0 instance; the
   node loop needs u = size nodest + 1, so the height index cannot stay fixed. *)
lemma gettype_nodeaddr (i j u v : int) :
     valid_tidx 0 i
  => valid_kpidx j
  => valid_thfidx u
  => valid_tbfidx u v
  => get_typeidx (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) u v)
     = trhftype.
proof.
move=> vi vj vu vv.
apply (FTWES.gettype_setthtbkptypetrh i j u v adz) => //.
+ by rewrite adz_val.
by rewrite adz_val /=; smt().
qed.

lemma gettype_leafaddr (i j v : int) :
     valid_tidx 0 i
  => valid_kpidx j
  => valid_thfidx 0
  => valid_tbfidx 0 v
  => get_typeidx (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 v)
     = trhftype.
proof.
move=> vi vj vu vv.
apply (FTWES.gettype_setthtbkptypetrh i j 0 v adz) => //.
+ by rewrite adz_val.
by rewrite adz_val /=; smt().
qed.

(* ===========================================================================
   THE T3 BOUND, RESTATED OVER Gproc_VI.

   Run 25 found that the earlier statement (over EUF_CMA_Gproc_V) was the wrong
   shape: MM45 proves its TRH and TRCO branches over the RESTRUCTURED game _VI,
   not _V (FORS_ES.ec:4828-4832), because _VI's expanded leaf/node loops are what
   the reduction byequiv aligns against.  cdrafts-split/GprocVI.ec now supplies
   the Gproc analogue and the probability-preserving hop gproc_V_VI_eq, both
   certified (run 26, admit-free, gate-enforced).

   So the bound is stated over Gproc_VI, and the Gproc_V form -- which is what
   gproc_Q_decomposition's third term actually is -- follows by rewriting with
   gproc_V_VI_eq.  The flags are named EUF_CMA_Gproc_V.* on BOTH because _VI does
   `import var EUF_CMA_Gproc_V`: same globals, not copies.
   =========================================================================== *)
lemma t3_trco_bound_VI
  (A <: Adv_EUFCMA_Gproc{-O_CMA_Gproc_I, -EUF_CMA_Gproc_I, -EUF_CMA_Gproc_V,
                         -R_TRCO_Gproc,
                         -FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                         -FTWES.TRCOC.O_THFC_Default}) &m :
    Pr[EUF_CMA_Gproc_VI(A).main() @ &m :
         ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
         /\ ! EUF_CMA_Gproc_V.valid_TRHTCR]
  <= Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(A),
           FTWES.TRCOC_TCR.O_SMDTTCR_Default, FTWES.TRCOC.O_THFC_Default).main() @ &m : res].
proof.
(* THE PORT of MM45's TRCO branch, FORS_ES.ec:5944-6423, retargeted.

   SPLIT POINT.  MM45 uses `seq 9 12`; that does NOT transfer.  Their _VI has
   keygen INLINE (9 statements to the oracle init); ours calls GprocKgVI.keygen
   as ONE statement, so the left split is 4 (ad, ps, keygen, init).  On the right,
   3 (pp, OC.init, O.init) + 4 from the inlined pick (ad, skFORSs, pkFORSs, while)
   + the inlined find's init = 8.  Hence `seq 4 8`.

   THE INVARIANT is MM45's, with s -> nr_trees 0, l -> l', trhtype -> trhftype,
   R_TRCOSMDTTCRC_EUFCMA -> R_TRCO_Gproc, and their spelled-out leaf/root nests
   replaced by fors_leaves_op_cube / the pkfors_of body -- the same ops the
   certified GprocVI chain is phrased in, so the two can meet. *)
byequiv => //.
proc.
inline{2} 5; inline{2} 4.
seq 4 9 : (   ={glob A, glob O_CMA_Gproc_I}
           /\ ps{1} = pp{2}
           (* R_TRCO_Gproc's OWN local ps, set by right statement 8 (`ps <- pp`)
              -- inside the prefix, so it has to be recorded here or the suffix
              cannot relate it to pp.  Third instance in this port of a
              correspondence that the invariant simply did not carry. *)
           /\ ps{2} = pp{2}
           /\ ad{1} = adz
           /\ ad{1} = R_TRCO_Gproc.ad{2}
           /\ skFORSnt{1} = R_TRCO_Gproc.skFORSs{2}
           /\ pkFORSnt{1} = R_TRCO_Gproc.pkFORSs{2}
           /\ (forall (i j : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
                 nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2} (i * l' + j)
                 = (let adt = set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype) i) j in
                     (set_kpidx (set_typeidx adt trcotype) (FTWES.get_kpidx adt),
                      flatten (map DigestBlock.val
                        (mkseq (fun (u : int) =>
                           FTWES.val_bt_trh pp{2} adt
                             (list2tree (fors_leaves_op_cube
                                (nth witness (nth witness R_TRCO_Gproc.skFORSs{2} i) j)
                                pp{2} adt u)) u) k)))))
           /\ (forall (i j : int), 0 <= i < nr_trees 0 => 0 <= j < l' =>
                 nth witness (nth witness R_TRCO_Gproc.pkFORSs{2} i) j
                 = (let nijts = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2} (i * l' + j) in
                      trco pp{2} nijts.`1 nijts.`2))
           /\ uniq (unzip1 FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2})
           /\ all (fun (ad : adrs) => get_typeidx ad = trcotype)
                  (unzip1 FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2})
           /\ all (fun (ad : adrs) => get_typeidx ad <> trcotype)
                  FTWES.TRCOC.O_THFC_Default.tws{2}
           /\ size FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2} = nr_trees 0 * l').
+ (* PREFIX.  Two inlines are needed where MM45 needs none: our keygen is a CALL
     (GprocKgVI.keygen), and it in turn calls GprocTreeVI.root.  Both must be
     opened to expose the loops that align with pick()'s OC.query layers.
     The outer invariant is MM45's (FORS_ES.ec:5987-6028) MINUS the two `nodess`
     conjuncts -- their reduction tracks leavess/nodess/rootss, ours keeps only
     skFORSs/pkFORSs -- and with the spelled-out leaf/root nest replaced by
     fors_leaves_op_cube, so it can meet the certified GprocVI chain. *)
  inline{1} 3.
  inline{1} GprocTreeVI.root.
  inline{1} O_CMA_Gproc_I.init.
  inline{2} O_CMA_Gproc_I.init.
  wp => /=.
  while (   ps0{1} = pp{2}
         /\ ps0{1} = FTWES.TRCOC_TCR.O_SMDTTCR_Default.pp{2}
         /\ ps0{1} = FTWES.TRCOC.O_THFC_Default.pp{2}
         /\ ad0{1} = adz
         /\ ad0{1} = R_TRCO_Gproc.ad{2}
         /\ skFORSnt0{1} = R_TRCO_Gproc.skFORSs{2}
         /\ pkFORSnt0{1} = R_TRCO_Gproc.pkFORSs{2}
         (* MEMBERSHIP, not just the nth characterisation below.  This conjunct
            was MISSING from the first transcription of this invariant: the
            header said "MM45's invariant minus the two nodess conjuncts", but
            MM45's `otsdef` (FORS_ES.ec:5994-5998) is NOT a nodes conjunct and
            it is load-bearing -- the l'-loop step has to show the appended trco
            address is FRESH, i.e. `uniq (unzip1 (rcons ts x))`, and the nth
            characterisation alone does not say that everything IN ts arose from
            some (i,j).  Found by dumping the k-loop entry+exit goal. *)
         /\ (forall (adx : adrs * dgst),
               adx \in FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
               <=>
               (exists (i j : int),
                  0 <= i < size R_TRCO_Gproc.skFORSs{2} /\ 0 <= j < l' /\
                  adx = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                          (i * l' + j)))
         /\ (forall (i j : int),
               0 <= i < size R_TRCO_Gproc.skFORSs{2} => 0 <= j < l' =>
               nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2} (i * l' + j)
               = (let adt = set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype) i) j in
                   (set_kpidx (set_typeidx adt trcotype) (FTWES.get_kpidx adt),
                    flatten (map DigestBlock.val
                      (mkseq (fun (u : int) =>
                         FTWES.val_bt_trh pp{2} adt
                           (list2tree (fors_leaves_op_cube
                              (nth witness (nth witness R_TRCO_Gproc.skFORSs{2} i) j)
                              pp{2} adt u)) u) k)))))
         /\ (forall (i j : int),
               0 <= i < size R_TRCO_Gproc.skFORSs{2} => 0 <= j < l' =>
               nth witness (nth witness R_TRCO_Gproc.pkFORSs{2} i) j
               = (let nijts = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2} (i * l' + j) in
                    trco pp{2} nijts.`1 nijts.`2))
         /\ uniq (unzip1 FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2})
         /\ all (fun (ad : adrs) => get_typeidx ad = trcotype)
                (unzip1 FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2})
         /\ all (fun (ad : adrs) => get_typeidx ad <> trcotype)
                FTWES.TRCOC.O_THFC_Default.tws{2}
         /\ size FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
            = size R_TRCO_Gproc.skFORSs{2} * l'
         /\ size R_TRCO_Gproc.skFORSs{2} = size R_TRCO_Gproc.pkFORSs{2}
         /\ size R_TRCO_Gproc.skFORSs{2} <= nr_trees 0).
  - (* OUTER BODY.  INV-D is the outer invariant plus PARTIAL-ROW clauses for the
       in-progress skFORSl: the ts entries at index (size skFORSs * l' + j) and
       their pkFORSl images.  MM45 FORS_ES.ec:6030-6103, minus its nodesl
       conjuncts. *)
    wp => /=.
    while (   ={skFORSl, pkFORSl}
           /\ ps0{1} = pp{2}
           /\ ps0{1} = FTWES.TRCOC_TCR.O_SMDTTCR_Default.pp{2}
           /\ ps0{1} = FTWES.TRCOC.O_THFC_Default.pp{2}
           /\ ad0{1} = adz
           /\ ad0{1} = R_TRCO_Gproc.ad{2}
           /\ skFORSnt0{1} = R_TRCO_Gproc.skFORSs{2}
           /\ pkFORSnt0{1} = R_TRCO_Gproc.pkFORSs{2}
           (* otsdef, INV-D form -- see the note on the outer invariant.  Here
              the partial row contributes a second disjunct. *)
           /\ (forall (adx : adrs * dgst),
                 adx \in FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 <=>
                 (exists (i j : int),
                    0 <= i < size R_TRCO_Gproc.skFORSs{2} /\ 0 <= j < l' /\
                    adx = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                            (i * l' + j))
                 \/
                 (exists (j : int),
                    0 <= j < size skFORSl{2} /\
                    adx = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                            (size R_TRCO_Gproc.skFORSs{2} * l' + j)))
           /\ (forall (i j : int),
                 0 <= i < size R_TRCO_Gproc.skFORSs{2} => 0 <= j < l' =>
                 nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2} (i * l' + j)
                 = (let adt = set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype) i) j in
                   (set_kpidx (set_typeidx adt trcotype) (FTWES.get_kpidx adt),
                    flatten (map DigestBlock.val
                      (mkseq (fun (u : int) =>
                         FTWES.val_bt_trh pp{2} adt
                           (list2tree (fors_leaves_op_cube
                              (nth witness (nth witness R_TRCO_Gproc.skFORSs{2} i) j)
                              pp{2} adt u)) u) k)))))
           /\ (forall (j : int), 0 <= j < size skFORSl{2} =>
                 nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                   (size R_TRCO_Gproc.skFORSs{2} * l' + j)
                 = (let adt = set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                                 (size R_TRCO_Gproc.skFORSs{2})) j in
                   (set_kpidx (set_typeidx adt trcotype) (FTWES.get_kpidx adt),
                    flatten (map DigestBlock.val
                      (mkseq (fun (u : int) =>
                         FTWES.val_bt_trh pp{2} adt
                           (list2tree (fors_leaves_op_cube
                              (nth witness skFORSl{2} j) pp{2} adt u)) u) k)))))
           /\ (forall (i j : int),
                 0 <= i < size R_TRCO_Gproc.skFORSs{2} => 0 <= j < l' =>
                 nth witness (nth witness R_TRCO_Gproc.pkFORSs{2} i) j
                 = (let nijts = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2} (i * l' + j) in
                      trco pp{2} nijts.`1 nijts.`2))
           /\ (forall (j : int), 0 <= j < size skFORSl{2} =>
                 nth witness pkFORSl{2} j
                 = (let nijts = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                                  (size R_TRCO_Gproc.skFORSs{2} * l' + j) in
                      trco pp{2} nijts.`1 nijts.`2))
           /\ uniq (unzip1 FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2})
           /\ all (fun (ad : adrs) => get_typeidx ad = trcotype)
                  (unzip1 FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2})
           /\ all (fun (ad : adrs) => get_typeidx ad <> trcotype)
                  FTWES.TRCOC.O_THFC_Default.tws{2}
           /\ size FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
              = size R_TRCO_Gproc.skFORSs{2} * l' + size skFORSl{2}
           /\ size R_TRCO_Gproc.skFORSs{2} = size R_TRCO_Gproc.pkFORSs{2}
           /\ size R_TRCO_Gproc.skFORSs{2} < nr_trees 0
           /\ size skFORSl{2} = size pkFORSl{2}
           /\ size skFORSl{2} <= l').
    * (* l'-LOOP BODY.  INV-E is the tree (k) loop: rootsk is the mkseq of roots
         built so far.  MM45 FORS_ES.ec:6106-6135, minus its leavesk/nodesk
         conjuncts -- their reduction accumulates those lists, ours does not. *)
      inline{2} 6.
      wp => /=.
      while (   ={skFORS, rootsk, skFORSl, pkFORSl}
             /\ ps0{1} = pp{2}
             /\ ps0{1} = FTWES.TRCOC.O_THFC_Default.pp{2}
             /\ ad0{1} = adz
             /\ ad0{1} = R_TRCO_Gproc.ad{2}
             /\ skFORSnt0{1} = R_TRCO_Gproc.skFORSs{2}
             /\ pkFORSnt0{1} = R_TRCO_Gproc.pkFORSs{2}
             /\ rootsk{2}
                = (let adt = set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                                         (size R_TRCO_Gproc.skFORSs{2})) (size skFORSl{2}) in
                     mkseq (fun (u : int) =>
                       FTWES.val_bt_trh pp{2} adt
                         (list2tree (fors_leaves_op_cube skFORS{2} pp{2} adt u)) u)
                       (size rootsk{2}))
             /\ all (fun (ad : adrs) => get_typeidx ad <> trcotype)
                    FTWES.TRCOC.O_THFC_Default.tws{2}
             /\ size R_TRCO_Gproc.skFORSs{2} = size R_TRCO_Gproc.pkFORSs{2}
             /\ size R_TRCO_Gproc.skFORSs{2} < nr_trees 0
             /\ size skFORSl{2} = size pkFORSl{2}
             /\ size skFORSl{2} < l'
             /\ size rootsk{2} <= k).
      + (* k-LOOP BODY.  INV-F is the layer (a) loop.  Its characterisation is the
           SAME one already proved for GprocTreeVI_root_h -- but that lemma is not
           citable here because GprocTreeVI.root was inlined to expose these very
           layers, so it is re-derived, which is MM45's own path
           (FORS_ES.ec:6137-6154).  Their nodess/nodesl/nodesk indices become
           size skFORSs / size skFORSl / size rootsk. *)
        wp => /=.
        while (   ={nodest, leavest, rootsk, skFORSl}
               /\ ps0{1} = pp{2}
               /\ ps0{1} = FTWES.TRCOC.O_THFC_Default.pp{2}
               /\ ad0{1} = adz
               /\ ad0{1} = R_TRCO_Gproc.ad{2}
                              (* THE INLINED ROOT'S PARAMETERS.  `inline{1} GprocTreeVI.root`
                  introduces ps1 / adT0 / leavest0 / idxt on the LEFT, and NOTHING
                  in the first transcription of these invariants related them to
                  the right -- so the node-loop body, whose left-hand value is
                  `trh ps1 (set_thtbidx adT0 ..) ..`, was not provable at all.
                  Same defect class as the missing otsdef: invisible while the
                  goal that needs it is admitted.  The bindings are read off the
                  call site, GprocVI.ec's GprocKgVI:
                    root <@ GprocTreeVI.root(ps, set_kpidx (set_tidx (set_typeidx
                              ad trhftype) (size skFORSnt)) (size skFORSl),
                              leavest, size rootsk) *)
               /\ ps1{1} = pp{2}
               /\ adT0{1} = set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                              (size R_TRCO_Gproc.skFORSs{2})) (size skFORSl{2})
               /\ leavest0{1} = leavest{2}
               /\ idxt{1} = size rootsk{2}
               /\ (forall (v w : int),
                     0 <= v < size nodest{2} => 0 <= w < nr_nodesf (v + 1) =>
                     nth witness (nth witness nodest{2} v) w
                     = FTWES.val_bt_trh_gen pp{2}
                         (set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                            (size R_TRCO_Gproc.skFORSs{2})) (size skFORSl{2}))
                         (oget (sub_bt (list2tree leavest{2}) (rev (int2bs (a - v - 1) w))))
                         (v + 1) (size rootsk{2} * nr_nodesf (v + 1) + w))
               /\ all (fun (ad : adrs) => get_typeidx ad <> trcotype)
                      FTWES.TRCOC.O_THFC_Default.tws{2}
               /\ size leavest{2} = t
               /\ size R_TRCO_Gproc.skFORSs{2} < nr_trees 0
               /\ size skFORSl{2} < l'
               /\ size rootsk{2} < k
               /\ size nodest{2} <= a).
        - (* a-LOOP BODY.  INV-G is the node (nr_nodesf) loop: INV-F plus the
             partial nodescl row.  MM45 FORS_ES.ec:6156-6181. *)
          wp => /=.
          while (   ={nodescl, nodespl, nodest, leavest, rootsk, skFORSl}
                 /\ ps0{1} = pp{2}
                 /\ ps0{1} = FTWES.TRCOC.O_THFC_Default.pp{2}
                 /\ ad0{1} = adz
                 /\ ad0{1} = R_TRCO_Gproc.ad{2}
                 /\ ps1{1} = pp{2}
                 /\ adT0{1} = set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                                (size R_TRCO_Gproc.skFORSs{2})) (size skFORSl{2})
                 /\ leavest0{1} = leavest{2}
                 /\ idxt{1} = size rootsk{2}
                 /\ nodespl{2} = last leavest{2} nodest{2}
                 /\ (forall (v w : int),
                       0 <= v < size nodest{2} => 0 <= w < nr_nodesf (v + 1) =>
                       nth witness (nth witness nodest{2} v) w
                       = FTWES.val_bt_trh_gen pp{2} (set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                            (size R_TRCO_Gproc.skFORSs{2})) (size skFORSl{2}))
                           (oget (sub_bt (list2tree leavest{2}) (rev (int2bs (a - v - 1) w))))
                           (v + 1) (size rootsk{2} * nr_nodesf (v + 1) + w))
                 /\ (forall (w : int), 0 <= w < size nodescl{2} =>
                       nth witness nodescl{2} w
                       = FTWES.val_bt_trh_gen pp{2} (set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                            (size R_TRCO_Gproc.skFORSs{2})) (size skFORSl{2}))
                           (oget (sub_bt (list2tree leavest{2})
                              (rev (int2bs (a - size nodest{2} - 1) w))))
                           (size nodest{2} + 1)
                           (size rootsk{2} * nr_nodesf (size nodest{2} + 1) + w))
                 /\ all (fun (ad : adrs) => get_typeidx ad <> trcotype)
                        FTWES.TRCOC.O_THFC_Default.tws{2}
                 /\ size leavest{2} = t
                 /\ size R_TRCO_Gproc.skFORSs{2} < nr_trees 0
                 /\ size skFORSl{2} < l'
                 /\ size rootsk{2} < k
                 /\ size nodest{2} < a
                 /\ size nodescl{2} <= nr_nodesf (size nodest{2} + 1)).
          (* NODE-LOOP BODY.  MM45 FORS_ES.ec:6182-6234 -- but their 43 lines
             of take/drop/list2treeS surgery are replaced by ONE citation of
             node_level_step, which is that argument lifted out of the certified
             GprocTreeVI_root_h.  Fifth application of isolate-then-cite here.

             This block is also what exposed the missing ps1/adT0/leavest0/idxt
             conjuncts in INV-F and INV-G: its left-hand value is literally
             `trh ps1 (set_thtbidx adT0 ..) ..`, and nothing tied those to the
             right.  With them added, `/>` substitutes far more and the intro
             shape changes (a bare `forall &2` to introduce, then 10 names). *)
          * inline{2} 3.
            wp; skip => />.
            move=> &2 nthndst nthndscl allotws eqt_szlfst lts_szndss ltl_szndsl
                   ltk_szndsk lta_szndst _ ltnn1_szndscl.
            rewrite ?size_rcons !andbA -2!andbA; split => [| /#].
            rewrite -?cats1 all_cat allotws /=.
            rewrite /trh size_cat 2!DigestBlock.valP (: 8 * n * 2 = 8 * n + 8 * n) 1:/# /=.
            split; last first.
            + have ht := gettype_nodeaddr (size R_TRCO_Gproc.skFORSs{2}) (size skFORSl{2})
                           (size nodest{2} + 1)
                           (size rootsk{2} * nr_nodesf (size nodest{2} + 1)
                            + size nodescl{2}) _ _ _ _.
              + by rewrite /valid_tidx; smt(size_ge0).
              + by rewrite /valid_kpidx; smt(size_ge0).
              + by rewrite /valid_thfidx; smt(size_ge0).
              + rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0 expr_ge0).
                by rewrite (: k = k - 1 + 1) 1:// mulrDl /= ler_lt_add
                           1:ler_pmul2r 3:// 1:expr_gt0 1:// /#.
              smt(dist_adrstypes).
            move=> w ge0_w ltsz1_w; rewrite nth_cat /=.
            case (w < size nodescl{2}) => [/# | ?].
            have eqsz_w : w = size nodescl{2} by smt().
            rewrite eqsz_w.
            (* node_level_step is stated over `trh`; the goal carries `thfc` with
               the size already normalised by the /trh rewrite above, so the
               citation is unfolded to meet it rather than the goal re-folded. *)
            have hs := node_level_step FTWES.TRCOC.O_THFC_Default.pp{2}
                         (set_kpidx (set_tidx (set_typeidx adz trhftype)
                            (size R_TRCO_Gproc.skFORSs{2})) (size skFORSl{2}))
                         leavest{2} (size rootsk{2}) nodest{2} (size nodescl{2})
                         _ _ _ _.
            + exact eqt_szlfst.
            + smt(size_ge0).
            + exact nthndst.
            + smt(size_ge0).
            by move: hs; rewrite /trh (: 8 * n * 2 = 8 * n + 8 * n) 1:/#.
          (* NODE-LOOP ENTRY+EXIT.  MM45 FORS_ES.ec:6235-6238, verbatim up to
             the intro arity. *)
          wp; skip => />.
          move=> &2 nthndst allotws eqt_szlfst lts_szndss ltl_szndsl ltk_szndsk
                 _ lta_szndst.
          split => [| tws ndscl /lezNgt genn1_szndscl _ nthndscl alltws
                      lenn1_szndscl]; 1: by rewrite expr_ge0 /#.
          split => [v w ge0_v |]; 2: by rewrite size_rcons /#.
          by rewrite size_rcons nth_rcons /#.
        (* a-loop ENTRY, then the leaf (t) loop.  INV-H: leavest is the mkseq
           prefix of the cube's row.  MM45 FORS_ES.ec:6240-6260. *)
        wp => /=.
        while (   ={leavest, skFORS, rootsk, skFORSl}
               /\ ps0{1} = pp{2}
               /\ ps0{1} = FTWES.TRCOC.O_THFC_Default.pp{2}
               /\ ad0{1} = adz
               /\ ad0{1} = R_TRCO_Gproc.ad{2}
               /\ skFORSnt0{1} = R_TRCO_Gproc.skFORSs{2}
               /\ leavest{2}
                  = mkseq (fun (v : int) =>
                      f pp{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                            (size R_TRCO_Gproc.skFORSs{2})) (size skFORSl{2})) 0 (size rootsk{2} * t + v))
                        (DigestBlock.val (nth witness
                           (nth witness (FTWES.DBLLKTL.val skFORS{2}) (size rootsk{2})) v)))
                      (size leavest{2})
               /\ all (fun (ad : adrs) => get_typeidx ad <> trcotype)
                      FTWES.TRCOC.O_THFC_Default.tws{2}
               /\ size R_TRCO_Gproc.skFORSs{2} < nr_trees 0
               /\ size skFORSl{2} < l'
               /\ size rootsk{2} < k
               /\ size leavest{2} <= t).
        - (* leaf-loop body.  Five things had to be right, none of them visible
             to the compiler:
               * NO `/>` -- it substitutes away lfstdef, which the mkseq
                 extension needs.
               * `/=` before `/f` -- the goal is wrapped in `let`s.
               * normalise ps via `-h6 h5` but ad FORWARD via `h8`, to match the
                 form lfstdef is written in.
               * lfstdef itself must be normalised to thfc form.
               * the trailing `//` after mkseqS is load-bearing: without it
                 `do ! split` does not decompose the goal at all.
             The typeidx side then needs gettype_leafaddr, which needs adz to be
             the CONCRETE chain address -- see adz_val. *)
          inline{2} 1.
          wp; skip => &1 &2 [#] h1 h2 h3 h4 h5 h6 h7 h8 h9 lfstdef allotws
                             h12 h13 h14 h15 g1 g2.
          move: lfstdef; rewrite /f ?DigestBlock.valP => lfstdef.
          rewrite /= /f DigestBlock.valP ?size_rcons ?h1 ?h2 ?h3 ?h4 -?h6 ?h5 ?h8 ?h9.
          rewrite mkseqS 1:size_ge0 -lfstdef //.
          do ! split.
          smt(dist_adrstypes ge1_a size_ge0).
          have hadz : R_TRCO_Gproc.ad{2} = adz by smt().
          rewrite hadz -cats1 all_cat /=.
          (* the four validity premises, unfolded rather than smt-guessed:
               valid_tidx 0 i   = 0 <= i < nr_trees 0        (from h12)
               valid_kpidx j    = 0 <= j < l'                (from h13)
               valid_thfidx 0   = 0 <= 0 <= a                (ge1_a)
               valid_tbfidx 0 v = 0 <= v < k * nr_nodesf 0,
                 and nr_nodesf 0 = 2^a = t, so with size rootsk < k (h14) and
                 size leavest < t -- which comes from the LOOP GUARD g1/g2, NOT
                 from the invariant's `<= t` -- we get
                 v <= (k-1)*t + t-1 = k*t - 1 < k*t. *)
          have ht := gettype_leafaddr (size R_TRCO_Gproc.skFORSs{2}) (size skFORSl{2})
                       (size rootsk{2} * t + size leavest{2}) _ _ _ _.
          + by rewrite /valid_tidx; smt(size_ge0).
          + by rewrite /valid_kpidx; smt(size_ge0).
          + by rewrite /valid_thfidx; smt(ge1_a).
          + rewrite /valid_tbfidx /nr_nodesf /=.
            split => [| _]; 1: smt(size_ge0 expr_ge0).
            (* MM45's own arithmetic for this bound, FORS_ES.ec:6266 *)
            by rewrite (: k = k - 1 + 1) 1:// mulrDl /= ler_lt_add 1:/t
                       1:ler_pmul2r 3:// 1:expr_gt0 1:// /#.
          smt(dist_adrstypes).
          smt(size_ge0 ge1_a ge2_t ge1_k).
          smt(size_ge0 ge1_a ge2_t ge1_k).
          smt(size_ge0 ge1_a ge2_t ge1_k).
          smt(size_ge0 ge1_a ge2_t ge1_k).
        (* LEAF-LOOP ENTRY+EXIT.  MM45 FORS_ES.ec:6269-6276.
           `while` folds the exit into the remaining goal's post, so this ONE
           goal carries THREE obligations, nested exactly two deep -- the leaf
           loop's entry, then (under the leaf-exit hypotheses) the a-loop's
           entry, then (under the a-exit hypotheses) the k-loop's step.

           An earlier attempt recorded "the nesting is one level deeper than the
           MM45 skeleton suggests".  THAT WAS WRONG, and the way it was wrong is
           the recurring failure mode of this port: the intro pattern used 19
           names where the leaf-exit hypotheses number 15, so every name after
           the fourth was off by four and the goal LOOKED like a repeated leaf
           loop.  The arities below are MEASURED from a goal dump, not counted
           off the invariant text: pre 19, leaf-exit 15, a-exit 15. *)
        wp; skip => &1 &2 [#] q1 q2 q3 q4 q5 q6 q7 q8 q9 q10 q11 q12 q13 q14
                              q15 q16 q17 q18 q19.
        (* (i) leaf entry: leavest starts [], and mkseq _ 0 = []. *)
        split; 1: by rewrite mkseq0; smt(ge2_t size_ge0).
        move=> lfL twsR lfR hL hR [#] r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12
                                      r13 r14 r15.
        (* (ii) a-loop entry: nodest starts [], so INV-F's row characterisation
               is vacuous (0 <= v < 0); size lfR = t comes from the leaf guard
               hR together with r15. *)
        split; 1: smt(ge1_a size_ge0).
        (* 19, not 15: INV-F gained the four inlined-root correspondences
           (ps1 / adT0 / leavest0 / idxt), so `size lfR = t` moved s11 -> s15
           and the row characterisation s9 -> s13.  Re-measured from a dump. *)
        move=> ndL twsR2 ndR gL gR [#] s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12
                                      s13 s14 s15 s16 s17 s18 s19.
        (* (iii) k-loop step.  Normalise r10 to `t` FIRST: rewriting s11
               backwards (t -> size lfR) would also hit the `size rootsk * t`
               inside the lambda and destroy the match. *)
        move: r10; rewrite s15 => r10.
        have hlfR : lfR = fors_leaves_op_cube skFORS{2} pp{2}
                      (set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                         (size R_TRCO_Gproc.skFORSs{2})) (size skFORSl{2})) (size rootsk{2}).
        + by rewrite cube_is_mkseq r10.
        have hroot := root_from_nodest pp{2}
                        (set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                           (size R_TRCO_Gproc.skFORSs{2})) (size skFORSl{2}))
                        lfR (size rootsk{2}) ndR _ _.
        + smt().                (* size ndR = a, from the a-guard gR and s15 *)
        + exact s13.            (* INV-F's row characterisation IS the premise *)
        (* s1/s3 collapse the {1} side onto the {2} side (which also discharges
           the rcons equality and the guard equivalence); then the extended
           rootsk row is mkseqS applied to q11, with hroot/hlfR supplying its
           last element. *)
        rewrite s1 s3 hroot hlfR ?size_rcons mkseqS 1:size_ge0 -q11 /=.
        smt().
      (* K-LOOP ENTRY+EXIT.  Port of MM45 FORS_ES.ec:6277-6326.  Two blocks:
         the skFORS keygen dispatch (ours is INLINE sampling loops where MM45
         has a `call`, so their `call (: true); 1: by sim` does not transfer),
         then their ts-append bookkeeping.

         Three deltas from MM45's text, each found by a goal dump:
           * `-2!andbA` where MM45 has `-3!andbA`.  The count was read off a
             dump of the SECOND goal (`-3` puts the `all (= trcotype)` conjunct
             in it, `-4` adds `uniq` too, `-2` leaves exactly the three
             arithmetic conjuncts `/#` wants).  NOT load-bearing, though: a
             negative control with `-3!andbA` restored still compiles rc=0, so
             the later tactics tolerate the coarser grouping.  Recorded because
             the isolated `-3` probe DID fail at `/#`, and it would be easy to
             mis-remember that as brittleness of the count itself.
           * `eq_adrs_idxs` is `HA.eq_adrs_idxs` here.
           * nthots/nthots1/rskdef are phrased over adz, so every application of
             them RE-INTRODUCES adz into a goal already normalised to adzf --
             hence the settype_adz_eq after each.  Without it the next rewrite
             reports `nothing to rewrite`, which reads like a missing lemma and
             is not. *)
      (* The skFORS keygen block is code-identical on both sides and touches
         nothing INV-D mentions, so the frame just rides through the two
         sampling loops.  `sim : (..)` will NOT do this: it takes its argument
         as the WHOLE relational invariant, so the pre survives only through
         what that invariant implies -- pass `={skFORScube}` alone and the
         leftover has no `size skFORSl{2} < l'` to draw on. *)
      seq 2 2 : (   ={skFORScube}
                 /\ ={skFORSl, pkFORSl}
                 /\ ps0{1} = pp{2}
                 /\ ps0{1} = FTWES.TRCOC_TCR.O_SMDTTCR_Default.pp{2}
                 /\ ps0{1} = FTWES.TRCOC.O_THFC_Default.pp{2}
                 /\ ad0{1} = adz
                 /\ ad0{1} = R_TRCO_Gproc.ad{2}
                 /\ skFORSnt0{1} = R_TRCO_Gproc.skFORSs{2}
                 /\ pkFORSnt0{1} = R_TRCO_Gproc.pkFORSs{2}
                 /\ (forall (adx : adrs * dgst),
                 adx \in FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 <=>
                 (exists (i j : int),
                 0 <= i < size R_TRCO_Gproc.skFORSs{2} /\ 0 <= j < l' /\
                 adx = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 (i * l' + j))
                 \/
                 (exists (j : int),
                 0 <= j < size skFORSl{2} /\
                 adx = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRCO_Gproc.skFORSs{2} * l' + j)))
                 /\ (forall (i j : int),
                 0 <= i < size R_TRCO_Gproc.skFORSs{2} => 0 <= j < l' =>
                 nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2} (i * l' + j)
                 = (let adt = set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype) i) j in
                 (set_kpidx (set_typeidx adt trcotype) (FTWES.get_kpidx adt),
                 flatten (map DigestBlock.val
                 (mkseq (fun (u : int) =>
                 FTWES.val_bt_trh pp{2} adt
                 (list2tree (fors_leaves_op_cube
                 (nth witness (nth witness R_TRCO_Gproc.skFORSs{2} i) j)
                 pp{2} adt u)) u) k)))))
                 /\ (forall (j : int), 0 <= j < size skFORSl{2} =>
                 nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRCO_Gproc.skFORSs{2} * l' + j)
                 = (let adt = set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                 (size R_TRCO_Gproc.skFORSs{2})) j in
                 (set_kpidx (set_typeidx adt trcotype) (FTWES.get_kpidx adt),
                 flatten (map DigestBlock.val
                 (mkseq (fun (u : int) =>
                 FTWES.val_bt_trh pp{2} adt
                 (list2tree (fors_leaves_op_cube
                 (nth witness skFORSl{2} j) pp{2} adt u)) u) k)))))
                 /\ (forall (i j : int),
                 0 <= i < size R_TRCO_Gproc.skFORSs{2} => 0 <= j < l' =>
                 nth witness (nth witness R_TRCO_Gproc.pkFORSs{2} i) j
                 = (let nijts = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2} (i * l' + j) in
                 trco pp{2} nijts.`1 nijts.`2))
                 /\ (forall (j : int), 0 <= j < size skFORSl{2} =>
                 nth witness pkFORSl{2} j
                 = (let nijts = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRCO_Gproc.skFORSs{2} * l' + j) in
                 trco pp{2} nijts.`1 nijts.`2))
                 /\ uniq (unzip1 FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2})
                 /\ all (fun (ad : adrs) => get_typeidx ad = trcotype)
                 (unzip1 FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2})
                 /\ all (fun (ad : adrs) => get_typeidx ad <> trcotype)
                 FTWES.TRCOC.O_THFC_Default.tws{2}
                 /\ size FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 = size R_TRCO_Gproc.skFORSs{2} * l' + size skFORSl{2}
                 /\ size R_TRCO_Gproc.skFORSs{2} = size R_TRCO_Gproc.pkFORSs{2}
                 /\ size R_TRCO_Gproc.skFORSs{2} < nr_trees 0
                 /\ size skFORSl{2} = size pkFORSl{2}
                 /\ size skFORSl{2} <= l'
                 /\ size skFORSl{1} < l'
                 /\ size skFORSl{2} < l').
      + while (   ={skFORScube}
                 /\ ={skFORSl, pkFORSl}
                 /\ ps0{1} = pp{2}
                 /\ ps0{1} = FTWES.TRCOC_TCR.O_SMDTTCR_Default.pp{2}
                 /\ ps0{1} = FTWES.TRCOC.O_THFC_Default.pp{2}
                 /\ ad0{1} = adz
                 /\ ad0{1} = R_TRCO_Gproc.ad{2}
                 /\ skFORSnt0{1} = R_TRCO_Gproc.skFORSs{2}
                 /\ pkFORSnt0{1} = R_TRCO_Gproc.pkFORSs{2}
                 /\ (forall (adx : adrs * dgst),
                 adx \in FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 <=>
                 (exists (i j : int),
                 0 <= i < size R_TRCO_Gproc.skFORSs{2} /\ 0 <= j < l' /\
                 adx = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 (i * l' + j))
                 \/
                 (exists (j : int),
                 0 <= j < size skFORSl{2} /\
                 adx = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRCO_Gproc.skFORSs{2} * l' + j)))
                 /\ (forall (i j : int),
                 0 <= i < size R_TRCO_Gproc.skFORSs{2} => 0 <= j < l' =>
                 nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2} (i * l' + j)
                 = (let adt = set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype) i) j in
                 (set_kpidx (set_typeidx adt trcotype) (FTWES.get_kpidx adt),
                 flatten (map DigestBlock.val
                 (mkseq (fun (u : int) =>
                 FTWES.val_bt_trh pp{2} adt
                 (list2tree (fors_leaves_op_cube
                 (nth witness (nth witness R_TRCO_Gproc.skFORSs{2} i) j)
                 pp{2} adt u)) u) k)))))
                 /\ (forall (j : int), 0 <= j < size skFORSl{2} =>
                 nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRCO_Gproc.skFORSs{2} * l' + j)
                 = (let adt = set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                 (size R_TRCO_Gproc.skFORSs{2})) j in
                 (set_kpidx (set_typeidx adt trcotype) (FTWES.get_kpidx adt),
                 flatten (map DigestBlock.val
                 (mkseq (fun (u : int) =>
                 FTWES.val_bt_trh pp{2} adt
                 (list2tree (fors_leaves_op_cube
                 (nth witness skFORSl{2} j) pp{2} adt u)) u) k)))))
                 /\ (forall (i j : int),
                 0 <= i < size R_TRCO_Gproc.skFORSs{2} => 0 <= j < l' =>
                 nth witness (nth witness R_TRCO_Gproc.pkFORSs{2} i) j
                 = (let nijts = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2} (i * l' + j) in
                 trco pp{2} nijts.`1 nijts.`2))
                 /\ (forall (j : int), 0 <= j < size skFORSl{2} =>
                 nth witness pkFORSl{2} j
                 = (let nijts = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRCO_Gproc.skFORSs{2} * l' + j) in
                 trco pp{2} nijts.`1 nijts.`2))
                 /\ uniq (unzip1 FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2})
                 /\ all (fun (ad : adrs) => get_typeidx ad = trcotype)
                 (unzip1 FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2})
                 /\ all (fun (ad : adrs) => get_typeidx ad <> trcotype)
                 FTWES.TRCOC.O_THFC_Default.tws{2}
                 /\ size FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 = size R_TRCO_Gproc.skFORSs{2} * l' + size skFORSl{2}
                 /\ size R_TRCO_Gproc.skFORSs{2} = size R_TRCO_Gproc.pkFORSs{2}
                 /\ size R_TRCO_Gproc.skFORSs{2} < nr_trees 0
                 /\ size skFORSl{2} = size pkFORSl{2}
                 /\ size skFORSl{2} <= l'
                 /\ size skFORSl{1} < l'
                 /\ size skFORSl{2} < l').
        - wp; while (   ={skFORScube, skFORSet}
                 /\ ={skFORSl, pkFORSl}
                 /\ ps0{1} = pp{2}
                 /\ ps0{1} = FTWES.TRCOC_TCR.O_SMDTTCR_Default.pp{2}
                 /\ ps0{1} = FTWES.TRCOC.O_THFC_Default.pp{2}
                 /\ ad0{1} = adz
                 /\ ad0{1} = R_TRCO_Gproc.ad{2}
                 /\ skFORSnt0{1} = R_TRCO_Gproc.skFORSs{2}
                 /\ pkFORSnt0{1} = R_TRCO_Gproc.pkFORSs{2}
                 /\ (forall (adx : adrs * dgst),
                 adx \in FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 <=>
                 (exists (i j : int),
                 0 <= i < size R_TRCO_Gproc.skFORSs{2} /\ 0 <= j < l' /\
                 adx = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 (i * l' + j))
                 \/
                 (exists (j : int),
                 0 <= j < size skFORSl{2} /\
                 adx = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRCO_Gproc.skFORSs{2} * l' + j)))
                 /\ (forall (i j : int),
                 0 <= i < size R_TRCO_Gproc.skFORSs{2} => 0 <= j < l' =>
                 nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2} (i * l' + j)
                 = (let adt = set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype) i) j in
                 (set_kpidx (set_typeidx adt trcotype) (FTWES.get_kpidx adt),
                 flatten (map DigestBlock.val
                 (mkseq (fun (u : int) =>
                 FTWES.val_bt_trh pp{2} adt
                 (list2tree (fors_leaves_op_cube
                 (nth witness (nth witness R_TRCO_Gproc.skFORSs{2} i) j)
                 pp{2} adt u)) u) k)))))
                 /\ (forall (j : int), 0 <= j < size skFORSl{2} =>
                 nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRCO_Gproc.skFORSs{2} * l' + j)
                 = (let adt = set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                 (size R_TRCO_Gproc.skFORSs{2})) j in
                 (set_kpidx (set_typeidx adt trcotype) (FTWES.get_kpidx adt),
                 flatten (map DigestBlock.val
                 (mkseq (fun (u : int) =>
                 FTWES.val_bt_trh pp{2} adt
                 (list2tree (fors_leaves_op_cube
                 (nth witness skFORSl{2} j) pp{2} adt u)) u) k)))))
                 /\ (forall (i j : int),
                 0 <= i < size R_TRCO_Gproc.skFORSs{2} => 0 <= j < l' =>
                 nth witness (nth witness R_TRCO_Gproc.pkFORSs{2} i) j
                 = (let nijts = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2} (i * l' + j) in
                 trco pp{2} nijts.`1 nijts.`2))
                 /\ (forall (j : int), 0 <= j < size skFORSl{2} =>
                 nth witness pkFORSl{2} j
                 = (let nijts = nth witness FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 (size R_TRCO_Gproc.skFORSs{2} * l' + j) in
                 trco pp{2} nijts.`1 nijts.`2))
                 /\ uniq (unzip1 FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2})
                 /\ all (fun (ad : adrs) => get_typeidx ad = trcotype)
                 (unzip1 FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2})
                 /\ all (fun (ad : adrs) => get_typeidx ad <> trcotype)
                 FTWES.TRCOC.O_THFC_Default.tws{2}
                 /\ size FTWES.TRCOC_TCR.O_SMDTTCR_Default.ts{2}
                 = size R_TRCO_Gproc.skFORSs{2} * l' + size skFORSl{2}
                 /\ size R_TRCO_Gproc.skFORSs{2} = size R_TRCO_Gproc.pkFORSs{2}
                 /\ size R_TRCO_Gproc.skFORSs{2} < nr_trees 0
                 /\ size skFORSl{2} = size pkFORSl{2}
                 /\ size skFORSl{2} <= l'
                 /\ size skFORSl{1} < l'
                 /\ size skFORSl{2} < l').
          * by auto.
          by auto.
        by auto.
      wp; skip => /> &2 otsdef nthots nthots1 nthopkfs nthopkfl uqunz1ots allots
                       allotws szots eqszskpkfs lts_szskfs eqszskpkfl _ ltl_szskfl.
      split => [| tws rsk /lezNgt gek_szrsk _ rskdef alltws lek_szrsk];
        1: by rewrite mkseq0; smt(ge1_k).
      rewrite ?size_rcons !andbA -2!andbA; split => [| /#].
      rewrite settype_adz_eq map_rcons rcons_uniq /= -?cats1 all_cat /=.
      rewrite uqunz1ots allots /=.
      rewrite FTWES.gettype_setkp2type2trhtrco /=.
      + by rewrite adzf_val.
      + by rewrite adzf_val /= /valid_tidx /nr_trees; smt(expr_gt0).
      + by rewrite /valid_tidx; smt(size_ge0).
      + by rewrite /valid_kpidx; smt(size_ge0).
      + by rewrite FTWES.vkpidx_setkpttype 1:valid_fadrs_adzf //; smt(size_ge0).
      split; last first.
      + rewrite mapP negb_exists /= => adx; rewrite negb_and -implybE.
        move/otsdef => -[[i j] [rng_i [rng_j ->]] | [j] [rng_j ->]].
        - rewrite (nthots _ _ rng_i rng_j) /= settype_adz_eq.
          rewrite -HA.eq_adrs_idxs (neq_from_nth witness _ _ 4) 2://.
          by rewrite FTWES.neqtidx_setkp2type2trhtrco 1:valid_fadrs_adzf 4,6://;
             smt(size_ge0).
        rewrite (nthots1 _ rng_j) /= settype_adz_eq.
        rewrite -HA.eq_adrs_idxs (neq_from_nth witness _ _ 2) 2://.
        by rewrite FTWES.neqkpidx_setkp2type2trhtrco 1:valid_fadrs_adzf 2,6://;
           smt(size_ge0).
      rewrite -!andbA; split => [adx |].
      + rewrite mem_cat /=.
        split.
        - case => [/otsdef | ->].
          * case => [[i j] [rng_i] | [j]] [rng_j adxval].
            + by left; exists i j;
                 rewrite rng_i rng_j nth_cat /= szots FTWES.ltlltr 2,5://;
                 smt(ge2_lp).
            by right; exists j; rewrite nth_cat /#.
          by right; exists (size skFORSl{2}); rewrite nth_cat szots /=; smt(size_ge0).
        case => [[i j] [rng_i] | [j]] [rng_j].
        - by rewrite nth_cat szots /= FTWES.ltlltr 2://; smt(ge2_lp).
        move=> ->; rewrite nth_cat szots /=.
        case (j < size skFORSl{2}) => [/# | ?].
        by rewrite (: j = size skFORSl{2}) 1:/#.
      split => [i j ge0_i ltsz_i ge0_j ltl_j |].
      + rewrite nth_cat szots /=.
        have -> /=: i * l' + j < size R_TRCO_Gproc.skFORSs{2} * l' + size skFORSl{2}.
        - by rewrite FTWES.ltlltr //; smt(ge2_lp size_ge0).
        by rewrite nthots // settype_adz_eq.
      split => [j ge0_j ltsz1_j |].
      + rewrite nth_cat szots /= nth_cat.
        case (j < size skFORSl{2}) => [ltsz_j | gesz_j].
        - rewrite (: size R_TRCO_Gproc.skFORSs{2} * l' + j
                     < size R_TRCO_Gproc.skFORSs{2} * l' + size skFORSl{2}) 1:/# /=.
          by rewrite nthots1 // settype_adz_eq.
        rewrite (: j = size skFORSl{2}) 1:/# /=.
        have hk : size rsk = k by smt().
        by move: rskdef; rewrite hk settype_adz_eq => ->.
      split => [i j ge0_i ltsz_i ge0_j ltl_j |].
      + rewrite nth_cat szots /=.
        have -> /=: i * l' + j < size R_TRCO_Gproc.skFORSs{2} * l' + size skFORSl{2}.
        - by rewrite FTWES.ltlltr //; smt(ge2_lp size_ge0).
        by rewrite nthopkfs.
      move=> j ge0_j ltsz1_j.
      rewrite ?nth_cat szots -eqszskpkfl /=.
      case (j < size skFORSl{2}) => [ltsz_j | gesz_j].
      + by rewrite (: size R_TRCO_Gproc.skFORSs{2} * l' + j
                      < size R_TRCO_Gproc.skFORSs{2} * l' + size skFORSl{2}) 1:/# /=
                   nthopkfl.
      by rewrite (: j = size skFORSl{2}) 1:/# /=.
    (* L'-LOOP ENTRY+EXIT.  Port of MM45 FORS_ES.ec:6327-6337, which transfers
       almost verbatim -- the only edits are their nodes names dropped, Top.l ->
       l', and the peel count.  Peel: `-2!andbA`, read off a dump of the second
       goal (`-3`, MM45's number, leaves the nthopkfs conjunct in it, which `/#`
       cannot close).  UNLIKE the k-loop block, the count IS load-bearing here:
       a control with `-3!andbA` restored fails at exactly this line, where the
       k-loop's equivalent control still compiles.  Both were checked; do not
       generalise either way from one of them. *)
    wp; skip => /> &2 otsdef nthots nthopkfs uqunz1ots allots allotws szots
                     eqszskpkfs _ lts_szskfs.
    split.
    + split => [adx |]; 2: smt(ge2_lp).
      by rewrite ?otsdef /#.
    move=> tws ts pkfl skfl /lezNgt gel_szskfl _ tsdef nthts nthts1 nthpkfs
           nthpkfl uqunz1ts allts alltws szts eqszskpkfl lel_szskfl.
    rewrite ?size_rcons /= !andbA -2!andbA; split => [| /#].
    rewrite -!andbA; split => [adx |]; 1: smt(size_ge0).
    split => i j ge0_i ltsz1i_ ge0_j ltl_j; rewrite ?nth_rcons.
    + case (i < size R_TRCO_Gproc.skFORSs{2}) => ?; 1: by rewrite nthts.
      by rewrite (: i = size R_TRCO_Gproc.skFORSs{2}) 1:/# /= nthts1 2:// /#.
    case (i < size R_TRCO_Gproc.pkFORSs{2}) => ?; 1: by rewrite nthpkfs 2:// /#.
    by rewrite (: i = size R_TRCO_Gproc.pkFORSs{2}) 1:/# /= nthpkfl 2:// /#.
  (* OUTER ENTRY+EXIT.  Port of MM45 FORS_ES.ec:6338-6343.

     THIS BLOCK IS WHY THE SPLIT POINT IS `seq 4 9` AND NOT `seq 4 8`.  With 8,
     the exit obligation carried an extra first conjunct -- the
     `={glob O_CMA_Gproc_I}` half of the seq post, left substituted, RIGHT still
     symbolic -- and it was not establishable, because on the right the oracle
     is initialised at statement 9.  The original accounting ("3 + 4 from the
     inlined pick + the inlined find's init = 8") missed the `ps <- pp`
     assignment that find's inlining emits BEFORE the init.  A knock-on: at 8,
     the prefix's `inline{2} O_CMA_Gproc_I.init` had no target on the right and
     was a SILENT NO-OP -- inline on an absent name is not an error.
     At 9 the conjunct disappears from this goal entirely.

     `wp; rnd; wp; skip`, not MM45's `wp; skip`: both sides sample, so the two
     `<$ dpseed` have to be paired by `rnd`.  `skip` alone reports "left
     instruction list is not empty", which reads like a wrong inline count. *)
  inline{2} 3; inline{2} 2.
  wp; rnd; wp; skip => />.
  move=> psL _.
  split => [| pkfs skfs tws ts /lezNgt ges_szskfs _ tsdef nthts nthpkfs
              uqunz1ts allts alltws szts eqszskpkfs les_szskfs];
    1: smt(expr_gt0).
  split => [i j * |]; 1: by rewrite nthts /#.
  split => [i j * |]; 1: by rewrite nthpkfs /#.
  smt().
(* SUFFIX -- forgery -> TRCO collision.  MM45 FORS_ES.ec:6344-6423.
   PARTIALLY PORTED: the reduction to the collision statement is done and
   verified; the collision argument itself is not.

   The `conseq` MUST come after the `wp`, not before: applied first, `nrts`,
   `dist`, `twsO`, `twsOC` are still universally quantified with nothing tying
   them to ts/tws, and the subgoal is unprovable.  `wp 21 11` substitutes the
   right's statements 12..15 while leaving the LEFT's flag assignments live,
   which is what the conseq's premise names.

   nrtrees_lp_l discharges `size ts <= l` (SM_DT_TCR_C's t_smdttcr bound) from
   the invariant's `size ts = nr_trees 0 * l'`; MM45 cite `dval` for this and we
   have no such lemma. *)
inline{2} 15; inline{2} 14; inline{2} 13; inline{2} 12.
wp 21 11 => /=.
conseq (: _
          ==>
             is_valid{1}
          /\ is_fresh{1}
          /\ ! EUF_CMA_Gproc_V.covered{1}
          /\ ! EUF_CMA_Gproc_V.valid_OpenPRE{1}
          /\ ! EUF_CMA_Gproc_V.valid_TRHTCR{1}
          =>
             0 <= i{2} < nr_trees 0 * l'
          /\ x{2} <> x'{2}
          /\ trco pp{2} tw{2} x{2} = trco pp{2} tw{2} x'{2}) => //.
- move=> /> &2 nthts nthpkfs uqunz1ts allts alltws szts cov vOPRE vTCR isf isv
               i tw x x' + isvT isfT covF vOPREF vTCRF.
  rewrite isvT isfT covF vOPREF vTCRF size_ge0 szts nrtrees_lp_l /=
       => -[[-> ->] [-> ->]] /=.
  rewrite hasPn => ad adints; rewrite -negP => adintws.
  move/allP: allts => /(_ ad adints) /=.
  by move/allP: alltws => /(_ ad adintws).

(* SUFFIX, MAIN EQUIV.  The two roots loops are aligned and their body is
   CLOSED: after inlining pkFORS_from_sigFORSTW and O_CMA_Gproc_I.fresh on the
   left and the O.get on the right, the bodies are identical except for the leaf
   index, and hC_chunk bridges that definitionally.

   (An earlier note here claimed this needed a new axiom on `g`.  That was
   wrong and is retracted -- see hC_chunk's header.) *)
inline{1} FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW.
inline{1} O_CMA_Gproc_I.fresh.
inline{2} 11.
wp => /=.
while (   roots{1} = roots'{2}
       /\ ps0{1} = ps{2}
       /\ ad0{1} = set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                     tidx{2}) kpidx{2}
       /\ sig{1} = sigFORSTW'{2}
       /\ m{1} = (FTWES.mco mk'{2} m'{2}).`1
       /\ lidxs'{2} = M.F.hC mk'{2} m'{2}
       (* MM45's `rsdef` (FORS_ES.ec:6367-6377), merged with their leaves'
          conjunct since our loop computes the leaf inline.  WITHOUT IT `rs` is
          universally quantified with only its size known, and the suffix's
          final distinctness goal -- the forged roots differ from the honest
          ones -- has nothing to work with.  Fourth correspondence in this port
          that the invariant simply did not carry. *)
       /\ roots'{2}
          = mkseq (fun (i : int) =>
              FTWES.val_ap_trh ps{2}
                (set_kpidx (set_tidx (set_typeidx R_TRCO_Gproc.ad{2} trhftype)
                   tidx{2}) kpidx{2})
                (nth witness (FTWES.DBAPKL.val sigFORSTW'{2}) i).`2
                (nth witness lidxs'{2} i).`3
                (f ps{2}
                   (set_thtbidx (set_kpidx (set_tidx
                      (set_typeidx R_TRCO_Gproc.ad{2} trhftype) tidx{2})
                      kpidx{2}) 0 (i * t + (nth witness lidxs'{2} i).`3))
                   (DigestBlock.val
                      (nth witness (FTWES.DBAPKL.val sigFORSTW'{2}) i).`1))
                i) (size roots'{2})
       /\ 0 <= size roots{1} <= k).
+ wp; skip => /> &2 hrs hge0 hle hguard.
  by rewrite ?size_rcons mkseqS 1:size_ge0 /= -hrs hC_chunk 1:/# /#.

(* The pre-loop code and the adversary call, VERIFIED (0 errors):
     wp => /=.
     call (: ={glob O_CMA_Gproc_I}); 1: by sim.
     skip => />.
   `sim` discharges the oracle equivalence; O_CMA_Gproc_I is the only shared
   glob, so the adversary call needs no more than that. *)
wp => /=.
call (: ={glob O_CMA_Gproc_I}); 1: by sim.
skip => />.

(* REMAINING: MM45 FORS_ES.ec:6386-6423, the forgery -> collision argument.
   ONE goal, 369 lines.  Its conclusion is
     0 <= Index.val (mco mk m).`2 < nr_trees 0 * l'
     /\ (nth ts (Index.val ..)).`2 <> flatten (map val roots')
     /\ trco ps (nth ts ..).`1 (nth ts ..).`2
        = trco ps (nth ts ..).`1 (flatten (map val roots'))
   i.e. exactly a TRCO collision at the forged instance.

   MM45's shape: pose the compressed index and `fit := find (not-queried) lidxs`;
   from the forgery's freshness derive `has (not-in lidxs)`, hence 0 <= fit < k;
   read off nthts/nthpkfs at (val idx %/ l', val idx %% l'); then
   eq_from_flatten_nth + neq_from_nth + DigestBlock.val_inj turn the two root
   lists into the collision.

   DELTAS from MM45, both real:
     * Top.l -> l', s -> nr_trees 0, g -> M.F.hC (definitional, see hC_chunk).
     * EUF_CMA_Gproc_VI's is_valid carries M.F.predC_fors (FTWES.mco mk' m'),
       which MM45's does not.  RESOLVED, and it is NOT a risk here: a dump shows
       it lands as a HYPOTHESIS in the antecedent, so it can only make this goal
       easier, and MM45's argument does not need it.  Not using it is sound.
       Where predC_fors is actually load-bearing is coverage (cover_pr /
       forsc_le_fors), not the TRCO suffix. *)
(* COLLISION ARGUMENT.  MM45 FORS_ES.ec:6386-6423.  ALL THREE conjuncts are
   closed and this file has NO admits.

   (Corrected 2026-08-07.  This comment previously said "the distinctness
   conjunct is the single remaining admit in this file", which was true when
   written and false once the conjunct was closed -- the qed below is
   unconditional.  Found by adversarial review (Kimi K3) while using this file
   as the reference for the T2 port, which is exactly the way a stale status
   line does damage: everything downstream treats it as current.)

   `fit` is the first index the adversary did not cover.  Two hypotheses are
   load-bearing and it is worth naming which does what, because a second
   opinion got this half-right: `ncov` makes fit well-defined and in range,
   and `ntcr` -- the negated TRHTCR flag -- is what says the forged root
   DIFFERS from the honest one at that index.  Kimi K3 correctly spotted that
   our game already materialises MM45's `find` as ghost state
   (GprocVI.ec:343-344), so we read fit off ncov instead of deriving it from
   freshness as MM45 do; but it also said ntcr was not needed, which is wrong.

   The three rsdef knock-ons, each re-measured from a dump, not guessed:
     * loop ENTRY is now `[] = mkseq _ 0`, not just `0 <= k`  -> needs mkseq0;
     * loop EXIT gained a hypothesis  -> intro arity +1 (hrsx);
     * hrsx is the characterisation of the forged roots the final step needs. *)
move=> &2 nthts nthpkfs uqunz1ts allts alltws szts.
move=> fsig qs ts.
split; 1: by rewrite mkseq0 /=; smt(ge1_k).
move=> rs /lezNgt gek_szrs _ hrs hge0 hle hpredC.
move=> eq_out ninqs ncov nopre ntcr.

pose vidx := Index.val (FTWES.mco fsig.`2.`1 fsig.`1).`2.
have rngi : 0 <= vidx %/ l' < nr_trees 0.
+ by rewrite divz_ge0 2:ltz_divLR; smt(ge2_lp nrtrees_lp_l Index.valP).
have rngj : 0 <= vidx %% l' < l'.
+ by rewrite modz_ge0 2:ltz_pmod; 1,2: smt(ge2_lp).

split; 1: smt(Index.valP nrtrees_lp_l).
move: (nthts _ _ rngi rngj) (nthpkfs _ _ rngi rngj).
have -> : vidx %/ l' * l' + vidx %% l' = vidx by smt(divz_eq).
move=> hts hpk.
split; last first.
+ by rewrite -hpk -eq_out hts.

have szrs : size rs = k by smt().
pose fit := List.find
  (fun (idxs : int * int * int) =>
     ! (idxs \in
        flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2) ts)))
  (M.F.hC fsig.`2.`1 fsig.`1).

have hasnin :
  has
    (fun (idxs : int * int * int) =>
       ! (idxs \in
          flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2) ts)))
    (M.F.hC fsig.`2.`1 fsig.`1).
+ by move: ncov; rewrite -has_predC.

have szhc : size (M.F.hC fsig.`2.`1 fsig.`1) = k.
+ by rewrite /M.F.hC M.F.size_g.

have rng_fit : 0 <= fit < k.
+ rewrite /fit find_ge0 /= -szhc.
  by rewrite -has_find hasnin.

have eqfit1 : (nth witness (M.F.hC fsig.`2.`1 fsig.`1) fit).`1 = vidx.
+ rewrite /vidx.
  exact (hC_inst fsig.`2.`1 fsig.`1 fit rng_fit).

have eqfit2 : (nth witness (M.F.hC fsig.`2.`1 fsig.`1) fit).`2 = fit.
+ exact (hC_pos fsig.`2.`1 fsig.`1 fit rng_fit).

rewrite hts /=.
pose rs' := mkseq _ _.
move: (FTWES.eq_from_flatten_nth
         (map DigestBlock.val rs') (map DigestBlock.val rs) _ _).
+ by rewrite ?size_map size_iota /#.
+ move=> i; rewrite size_map => rng_i.
  rewrite ?(nth_map witness) 1:// 1:size_iota; 1,2: smt(size_mkseq).
  by rewrite 2!DigestBlock.valP.
move/contra => /(_ _) //.
rewrite (neq_from_nth witness _ _ fit) 2://
        ?(nth_map witness) 1:size_mkseq 2:size_iota 1..3:/# /=.
rewrite nth_iota 1:// /= eq_sym.
rewrite hrs szrs nth_mkseq 1:rng_fit /= -/vidx.
move: ntcr.
by rewrite -/fit eqfit1 eqfit2 -/vidx &(contra) &(DigestBlock.val_inj).
qed.

(* And the Gproc_V form -- the shape gproc_Q_decomposition's T3 term has -- now
   follows from the certified hop, with NO further proof obligation. *)
lemma t3_trco_bound
  (A <: Adv_EUFCMA_Gproc{-O_CMA_Gproc_I, -EUF_CMA_Gproc_I, -EUF_CMA_Gproc_V,
                         -R_TRCO_Gproc,
                         -FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                         -FTWES.TRCOC.O_THFC_Default}) &m :
    Pr[EUF_CMA_Gproc_V(A).main() @ &m :
         ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
         /\ ! EUF_CMA_Gproc_V.valid_TRHTCR]
  <= Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(A),
           FTWES.TRCOC_TCR.O_SMDTTCR_Default, FTWES.TRCOC.O_THFC_Default).main() @ &m : res].
proof. by rewrite (gproc_V_VI_eq A &m); apply (t3_trco_bound_VI A &m). qed.

(* ===========================================================================
   RETRACTION, 2026-08-06: "T1 is blocked upstream" WAS WRONG.

   Throughout this session I repeatedly said Q could not be bounded because its
   first term T1 is blocked on an upstream interface change (exposed randomized
   leaf keygen).  That conflated two different things:

     * `extract_op` (cdrafts-split/FORS_C_TreePort.ec) IS blocked that way --
       its own comment names R-KEY / R-SIM / R-INDEX / R-OPEN.  But it bounds
       `G_Tree` / `EUF_CMA_FORSC_I`.
     * T1 of gproc_Q_decomposition is
         Pr[EUF_CMA_Gproc_V(A).main() : (res /\ !covered) /\ valid_OpenPRE]
       over `EUF_CMA_Gproc_V` -- a DIFFERENT GAME.  The c10-port README says so
       in as many words ("Different game. It does not bound `Q`.").

   So T1 is NOT blocked; it is UNSTARTED, and structurally it is the same shape
   as T3: build an SM_DT_OpenPRE adversary R_OP_Gproc and prove the byequiv, the
   way R_TRCO_Gproc was just built for the TRCO branch.  Likewise T2 (the TRH
   branch, valid_TRHTCR).

   Both are ordinary proof work on the same pattern, with the infrastructure
   this session produced already in place (adzf, node_level_step,
   root_from_nodest, hC_chunk/hC_pos/hC_inst, nrtrees_lp_l, the invariant
   lessons, the probe tooling).  Bounding Q is reachable; it is roughly two more
   reductions, not an upstream blocker.

   Recorded here because an inherited "blocked" claim I never checked is exactly
   the defect class this port keeps producing, and I repeated it to the user
   several times before checking.
   =========================================================================== *)
