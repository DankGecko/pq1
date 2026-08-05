(* GprocVI -- the V->VI hop for Gproc: the instrumented game restructured so its

   Port of EUF_CMA_MFORSTWESNPRF_VI (base-c10-split/FORS_ES.ec:3381-3592).
   `_VI` is the honest game with keygen EXPANDED into the same five nested loops
   as the reduction's pick(), hashing directly (f / trh / trco) where pick()
   calls OC.query / O.query.  MM45 leaves the OC.query lines commented out beside
   the f/trh calls, which is the clearest statement of intent available: _VI
   exists so the reduction byequiv's `while`s align one-to-one.
   It does `import var` on _V so the three flags are the SAME globals -- which is
   why MM45's probabilities keep naming _V.valid_* after the hop. *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import DList DMap FMap.
require import BinaryTrees MerkleTrees.
require import BitEncoding.
import BS2Int.
import StdOrder.IntOrder.
require import SPHINCS_PLUS.
require import XmssmtCC_All.
require import RtopCSoundness.
require import FxChain.
require import GprocFORSC10.

(* Two one-line facts about fors_leaves_op_cube.  smt cannot unfold a DEFINED op,
   so the leaf-loop exit -- which must hand the Merkle lemma its precondition
   `leavest = fors_leaves_op_cube ..` and `size .. = t` -- needs them as hints. *)
lemma cube_is_mkseq (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) (u : int) :
  fors_leaves_op_cube skF ps0 ad0 u
  = mkseq (fun (j : int) => f ps0 (set_thtbidx ad0 0 (u * t + j))
             (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skF) u) j))) t.
proof. by rewrite /fors_leaves_op_cube. qed.

lemma size_cube (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs) (u : int) :
  size (fors_leaves_op_cube skF ps0 ad0 u) = t.
proof. by rewrite cube_is_mkseq size_mkseq; smt(ge2_t). qed.

(* The trco step, isolated: a root list that agrees pointwise with the mkseq
   pkfors_of is built from IS that mkseq, so hashing it gives pkfors_of.  Kept
   out of the hoare so the loop proof does not have to do eq_from_nth inline. *)
lemma pkfors_of_from_roots (skF : FTWES.skFORS) (ps0 : pseed) (ad0 : adrs)
                           (rts : dgstblock list) :
     size rts = k
  => (forall u, 0 <= u < k =>
        nth witness rts u
        = FTWES.val_bt_trh ps0 ad0 (list2tree (fors_leaves_op_cube skF ps0 ad0 u)) u)
  => trco ps0 (set_kpidx (set_typeidx ad0 trcotype) (FTWES.get_kpidx ad0))
          (flatten (map DigestBlock.val rts))
     = pkfors_of skF ps0 ad0.
proof.
move=> hsz hnth.
have -> : rts = mkseq (fun (u : int) =>
    FTWES.val_bt_trh ps0 ad0 (list2tree (fors_leaves_op_cube skF ps0 ad0 u)) u) k.
+ apply (eq_from_nth witness); 1: by rewrite size_mkseq hsz; smt(ge1_k).
  move=> i; rewrite hsz => hi.
  by rewrite hnth 1:// nth_mkseq //=.
by rewrite /pkfors_of.
qed.

(* === THE MERKLE EQUIVALENCE, ISOLATED ======================================
   This is the real content of GprocKgVI_pk_from_sk and the reason _VI cannot
   simply call gen_pkFORS: gen_pkFORS computes each root RECURSIVELY as
   `val_bt_trh ps ad (list2tree leaves) u` (FORS_ES.ec, proc gen_pkFORS), while
   _VI must compute it INCREMENTALLY, layer by layer, so its loops align with
   R_TRCO_Gproc.pick()'s OC.query layers.  Proving those equal is the Merkle
   incremental-vs-recursive equivalence.

   Pulled out as its own procedure so the argument is independently provable and
   GprocKgVI_pk_from_sk becomes bookkeeping around it.

   MM45'S RECIPE, located (its V-VI proof, FORS_ES.ec:3668-3819, the inner
   `while{2}` at ~3716-3755).  The inner-loop invariant characterises the node at
   layer u, position v as

     val_bt_trh_gen ps adT (oget (sub_bt (list2tree leavest)
                                         (rev (int2bs (a - u - 1) v)))) (u+1)
                    (idxt * nr_nodes (u+1) + v)

   i.e. every computed node is the recursive value of the SUBTREE of
   `list2tree leavest` at that position.  The workhorse rewrites are
   `subbt_list2tree_takedrop` (BinaryTrees.ec), then `list2treeS` / `list2tree1`
   for the base layer, with `take`/`drop`/`last_nth` manipulation.  All are
   present and reachable in this tree (checked).
   ========================================================================== *)
module GprocTreeVI = {
  proc root(ps : pseed, adT : adrs, leavest : dgstblock list, idxt : int) : dgstblock = {
    var nodest : dgstblock list list;
    var nodespl, nodescl : dgstblock list;
    var lnode, rnode, node : dgstblock;

    nodest <- [];
    while (size nodest < a) {
      nodespl <- last leavest nodest;
      nodescl <- [];
      while (size nodescl < nr_nodesf (size nodest + 1)) {
        lnode <- nth witness nodespl (2 * size nodescl);
        rnode <- nth witness nodespl (2 * size nodescl + 1);
        node <- trh ps (set_thtbidx adT (size nodest + 1)
                          (idxt * nr_nodesf (size nodest + 1) + size nodescl))
                    (DigestBlock.val lnode ++ DigestBlock.val rnode);
        nodescl <- rcons nodescl node;
      }
      nodest <- rcons nodest nodescl;
    }
    return nth witness (nth witness nodest (a - 1)) 0;
  }
}.

lemma GprocTreeVI_root_h (psi : pseed) (adTi : adrs) (lfs : dgstblock list) (ui : int) :
  hoare[GprocTreeVI.root :
        ps = psi /\ adT = adTi /\ leavest = lfs /\ idxt = ui /\ size lfs = t
        ==> res = FTWES.val_bt_trh psi adTi (list2tree lfs) ui].
proof.
proc.
while (   ps = psi /\ adT = adTi /\ leavest = lfs /\ idxt = ui /\ size lfs = t
       /\ 0 <= size nodest <= a
       /\ (forall (u v : int), 0 <= u < size nodest => 0 <= v < nr_nodesf (u + 1) =>
                nth witness (nth witness nodest u) v
                = FTWES.val_bt_trh_gen psi adTi
                    (oget (sub_bt (list2tree lfs) (rev (int2bs (a - u - 1) v)))) (u + 1)
                    (ui * nr_nodesf (u + 1) + v))).
+ wp.
  while (   ps = psi /\ adT = adTi /\ leavest = lfs /\ idxt = ui /\ size lfs = t
         /\ 0 <= size nodest < a
         /\ (forall (u v : int), 0 <= u < size nodest => 0 <= v < nr_nodesf (u + 1) =>
                nth witness (nth witness nodest u) v
                = FTWES.val_bt_trh_gen psi adTi
                    (oget (sub_bt (list2tree lfs) (rev (int2bs (a - u - 1) v)))) (u + 1)
                    (ui * nr_nodesf (u + 1) + v))
         /\ nodespl = last leavest nodest
         /\ 0 <= size nodescl <= nr_nodesf (size nodest + 1)
         /\ (forall (v : int), 0 <= v < size nodescl =>
               nth witness nodescl v
               = FTWES.val_bt_trh_gen psi adTi
                   (oget (sub_bt (list2tree lfs) (rev (int2bs (a - size nodest - 1) v))))
                   (size nodest + 1) (ui * nr_nodesf (size nodest + 1) + v))).
  - wp; skip => /> &hr eqt_szlfs ge0_szndst lta_szndst nthndst ge0_szndscl
                     lenn1_szndscl nthndscl.
    rewrite ?size_rcons.
    move=> ltnn1_szndscl.
    split; 1: smt().
    move=> v ge0_v ltsz1_v.
    rewrite nth_rcons; case (v < size nodescl{hr}) => [/# | ?].
    have eqsz_v : v = size nodescl{hr} by smt().
    rewrite eqsz_v /FTWES.val_bt_trh_gen (: a - size nodest{hr} - 1 = a - (size nodest{hr} + 1)) 1:/# /=.
    rewrite subbt_list2tree_takedrop 4:oget_some; 1..3: smt(ge1_a size_ge0).
    have ltnn_2szndscl1 : 2 * size nodescl{hr} + 1 < nr_nodesf (size nodest{hr}).
    - rewrite &(ltr_le_trans (2 + 2 * (nr_nodesf (size nodest{hr} + 1) - 1))) 1:/#.
      by rewrite /nr_nodesf mulzDr /= -{1}(expr1 2) -exprD_nneg // /#.
    have ge1_2aszn2szncl : 1 <= 2 ^ (a - size nodest{hr}) - 2 * size nodescl{hr} - 1 by smt().
    rewrite (last_nth witness); case (size nodest{hr} = 0) => [szn0 | nszn0].
    - rewrite szn0 /= expr1 {3}(: 2 = 1 + 1) 1:// (take_nth witness) 1:size_drop 2:/=; 1,2: smt(size_ge0).
      rewrite (FTWES.take1_head witness) 1:size_drop 3:nth_drop 2:/= 4://; 1..3: smt(size_ge0).
      rewrite -cats1 (list2treeS 0) ?expr0 1..3:// /trhi /=.
      by rewrite ?list2tree1 /= -nth0_head nth_drop; smt(size_ge0).
    rewrite nszn0 /= (: 2 ^ (size nodest{hr} + 1) = 2 ^ (size nodest{hr}) + 2 ^ (size nodest{hr})).
    + by rewrite exprD_nneg 1:size_ge0 //= expr1 /#.
    rewrite take_take_drop_cat 1,2:expr_ge0 1,2://.
    rewrite drop_drop 1:expr_ge0 1://; 1: smt(expr_ge0).
    rewrite (list2treeS (size nodest{hr})) 1:size_ge0 1,2:size_take 1,3:expr_ge0 1,3:// 1,2:size_drop; 1,3: smt(size_ge0 expr_ge0).
    + rewrite eqt_szlfs /t (: 2 ^ a = 2 ^ (a - size nodest{hr}) * 2 ^ (size nodest{hr})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
      pose szn2 := 2 ^ (size nodest{hr}).
      rewrite (: 2 ^ (a - size nodest{hr}) * szn2 - size nodescl{hr} * (szn2 + szn2) = (2 ^ (a - size nodest{hr}) - 2 * size nodescl{hr}) * szn2) 1:/#.
      pose mx := max _ _; rewrite (: 2 ^ (size nodest{hr}) < mx) // /mx.
      pose sb := ((_ - _ * _) * _)%Int; rewrite &(ltr_le_trans sb) /sb 2:maxrr.
      by rewrite ltr_pmull 1:expr_gt0 // /#.
    + rewrite eqt_szlfs /t (: 2 ^ a = 2 ^ (a - size nodest{hr}) * 2 ^ (size nodest{hr})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
      pose szn2 := 2 ^ (size nodest{hr}).
      rewrite (: 2 ^ (a - size nodest{hr}) * szn2 - (szn2 + size nodescl{hr} * (szn2 + szn2)) = (2 ^ (a - size nodest{hr}) - 2 * size nodescl{hr} - 1) * szn2) 1:/#.
      pose sb := ((_ - _ - _) * _)%Int.
      move: ge1_2aszn2szncl; rewrite lez_eqVlt => -[eq1_2as | gt1_2as].
      - by rewrite /sb -eq1_2as /= lez_maxr 1:expr_ge0.
      rewrite lez_maxr /sb 1:mulr_ge0 2:expr_ge0 //= 1:subr_ge0 1:ler_subr_addr.
      - rewrite &(ler_trans (1 + 2 * (nr_nodesf (size nodest{hr} + 1) - 1))) 1:/#.
        by rewrite /nr_nodesf mulzDr -{1}(expr1 2) -exprD_nneg // /#.
      rewrite (: szn2 < (2 ^ (a - size nodest{hr}) - 2 * size nodescl{hr} - 1) * szn2) //.
      by rewrite ltr_pmull 1:expr_gt0.
    rewrite 2?nthndst /=; 1..4: smt(size_ge0).
    rewrite (: a - (size nodest{hr} - 1) - 1 = a - size nodest{hr}) 1:/#.
    rewrite 2?subbt_list2tree_takedrop 3,6://; 1..4: smt(size_ge0).
    rewrite oget_some /FTWES.val_bt_trh_gen /trhi /updhbidx /=; do 4! congr => [/# | /= | /# | /=].
    + rewrite /nr_nodesf mulrDr mulrA; congr.
      by rewrite eq_sym mulrAC -{1}(expr1 2) -exprD_nneg 1:// /#.
    rewrite /nr_nodesf mulrDr -addrA; congr.
    by rewrite eq_sym mulrCA; congr; rewrite -{1}(expr1 2) -exprD_nneg 1:// /#.
  by wp; skip => &hr /=; smt(size_rcons nth_rcons size_ge0 ge1_a expr_ge0).
auto => />.
(* Setup (nodest <- []) is vacuous; the content is the post-loop instantiation of
   the invariant at u = a-1, v = 0.  At that point the path `int2bs (a-(a-1)-1) 0`
   is `int2bs 0 0 = []`, so sub_bt returns the WHOLE tree (subbt_empty), the layer
   index is a, and nr_nodesf a = 2^(a-a) = 1 -- which is exactly
   val_bt_trh ps ad bt bidx = val_bt_trh_gen ps ad bt a bidx (FORS_ES.ec:695-696). *)
move=> hszlfs.
split; 1: smt(ge1_a).
move=> nodest0 hnlt hge0 hle hinv.
have h := hinv (a - 1) 0 _ _.
+ smt(ge1_a).
+ rewrite /nr_nodesf (: a - (a - 1 + 1) = 0) 1:/# expr0; smt().
move: h.
rewrite (: a - 1 + 1 = a) 1:/# (: a - (a - 1) - 1 = 0) 1:/#.
rewrite /nr_nodesf (: a - a = 0) 1:/# expr0 /=.
rewrite /int2bs mkseq0 rev_nil subbt_empty oget_some.
by rewrite /val_bt_trh.
qed.

(* Losslessness of the isolated tree procedure: needed because GprocKgVI's
   deterministic tail (tree loop + trco) is ONE-SIDED in the sk-cube equiv. *)
lemma GprocTreeVI_root_ll : islossless GprocTreeVI.root.
proof.
proc.
while (0 <= size nodest <= a) (a - size nodest).
+ move=> z; wp.
  while (0 <= size nodescl <= nr_nodesf (size nodest + 1))
        (nr_nodesf (size nodest + 1) - size nodescl).
  - by move=> z'; auto; smt(size_rcons).
  by auto; smt(size_rcons expr_ge0 ge1_a size_ge0).
by auto; smt(size_ge0 ge1_a).
qed.

(* The expanded keygen, ISOLATED.  MM45 leaves this inline in _VI; pulling it out
   makes the V-VI obligation a KEYGEN equiv rather than a whole-game byequiv,
   and the T3 proof can still `inline` it to expose the loops it must align with
   R_TRCO_Gproc.pick(). *)
module GprocKgVI = {
  proc keygen(ps : pseed, ad : adrs)
       : FTWES.pkFORS list list * FTWES.skFORS list list = {
    var skFORSnt : FTWES.skFORS list list;
    var pkFORSnt : FTWES.pkFORS list list;
    var skFORS : FTWES.skFORS;
    var pkFORS : FTWES.pkFORS;
    var skFORSl : FTWES.skFORS list;
    var pkFORSl : FTWES.pkFORS list;
    var skFORS_ele, leaf, root : dgstblock;
    var skFORSet, leavest, rootsk : dgstblock list;
    var skFORScube : dgstblock list list;

    skFORSnt <- [];
    pkFORSnt <- [];
    while (size skFORSnt < nr_trees 0) {
      skFORSl <- [];
      pkFORSl <- [];
      while (size skFORSl < l') {
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

        rootsk <- [];
        while (size rootsk < k) {
          leavest <- [];
          while (size leavest < t) {
            leaf <- f ps (set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) (size skFORSl))
                                      0 (size rootsk * t + size leavest))
                      (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skFORS) (size rootsk)) (size leavest)));
            leavest <- rcons leavest leaf;
          }
          (* the tree layer, via the isolated procedure so the Merkle lemma
             (GprocTreeVI_root_h) can be CITED rather than re-proved.  T3 can
             still `inline` this to expose the layers it must align with
             R_TRCO_Gproc.pick()'s OC.query loops. *)
          root <@ GprocTreeVI.root(ps,
                    set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) (size skFORSl),
                    leavest, size rootsk);
          rootsk <- rcons rootsk root;
        }

        pkFORS <- trco ps (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) (size skFORSl)) trcotype)
                                     (FTWES.get_kpidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) (size skFORSl))))
                      (flatten (map DigestBlock.val rootsk));

        skFORSl <- rcons skFORSl skFORS;
        pkFORSl <- rcons pkFORSl pkFORS;
      }
      skFORSnt <- rcons skFORSnt skFORSl;
      pkFORSnt <- rcons pkFORSnt pkFORSl;
    }


    return (pkFORSnt, skFORSnt);
  }
}.

module EUF_CMA_Gproc_VI (A : Adv_EUFCMA_Gproc) = {
  import var EUF_CMA_Gproc_V

  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pkFORSnt : FTWES.pkFORS list list;
    var skFORSnt : FTWES.skFORS list list;
    var m' : msg;
    var sig' : sigGproc;
    var mk' : mkey;
    var sigFORSTW' : FTWES.sigFORSTW;
    var cm : FTWES.msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var pkFORS' : FTWES.pkFORS;
    var is_valid, is_fresh : bool;
    (* expanded keygen *)
    (* ghost *)
    var lidxs', cov : (int * int * int) list;
    var dfidx, dftidx, dflfidx : int;
    var tidx2, kpidx2 : int;
    var x' : dgstblock;
    var ap' : FTWES.apFORSTW;
    var skF : FTWES.skFORS;
    var adT : adrs;
    var leaf', leafh, root', root : dgstblock;

    ad <- adz;
    ps <$ dpseed;

    (pkFORSnt, skFORSnt) <@ GprocKgVI.keygen(ps, ad);

    (* ---- from here identical to EUF_CMA_Gproc_V ------------------------- *)
    O_CMA_Gproc_I.init(skFORSnt, ps, ad);
    (m', sig') <@ A(O_CMA_Gproc_I).forge((pkFORSnt, ps, ad));

    (mk', sigFORSTW') <- sig';
    (cm, idx) <- FTWES.mco mk' m';
    (tidx, kpidx) <- edivz (Index.val idx) l';

    pkFORS' <@ FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW(sigFORSTW', cm, ps,
                 set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

    is_valid <- M.F.predC_fors (FTWES.mco mk' m')
                /\ pkFORS' = nth witness (nth witness pkFORSnt tidx) kpidx;
    is_fresh <@ O_CMA_Gproc_I.fresh(m');

    covered <-
      all (fun x => x \in flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2)
                                       O_CMA_Gproc_I.ts))
          (M.F.hC sig'.`1 m');

    lidxs' <- M.F.hC mk' m';
    cov    <- flatten (map (fun (km : mkey * msg) => M.F.hC km.`1 km.`2)
                           O_CMA_Gproc_I.ts);
    (dfidx, dftidx, dflfidx) <-
      nth witness lidxs' (find (fun i => ! (i \in cov)) lidxs');
    (x', ap') <- nth witness (FTWES.DBAPKL.val sigFORSTW') dftidx;
    (tidx2, kpidx2) <- edivz dfidx l';
    skF <- nth witness (nth witness skFORSnt tidx2) kpidx2;
    adT <- set_kpidx (set_tidx (set_typeidx ad trhftype) tidx2) kpidx2;
    leaf' <- f ps (set_thtbidx adT 0 (dftidx * t + dflfidx)) (DigestBlock.val x');
    leafh <- nth witness (fors_leaves_op_cube skF ps adT dftidx) dflfidx;
    valid_OpenPRE <- leaf' = leafh;
    root' <- FTWES.val_ap_trh ps adT ap' dflfidx leaf' dftidx;
    root  <- FTWES.val_bt_trh ps adT
               (list2tree (fors_leaves_op_cube skF ps adT dftidx)) dftidx;
    valid_TRHTCR <- root' = root;

    return is_valid /\ is_fresh;
  }
}.


(* --- SUB-OBLIGATION 1: the SK cubes agree.  Both sample nr_trees 0 x l' x k x t
   values in the SAME nesting order; GprocKg does it in its first double loop,
   GprocKgVI in the sk half of its fused loop.  GprocKg's SECOND loop (the pk
   pass) does not touch skFORSnt, so it is handled one-sidedly. *)
equiv gprockg_vi_sk_eq :
  GprocKg.keygen ~ GprocKgVI.keygen : ={ps, ad} ==> res{1}.`2 = res{2}.`2.
proof.
(* Both sides sample nr_trees 0 x l' x k x t in the SAME nesting order, so the
   sampling nests align one-to-one.  Everything else is deterministic and
   one-sided: GprocKg's SECOND (pk) pass on {1}, and GprocKgVI's tree/trco tail
   on {2}.  Both need losslessness -- genpkfors_ll and GprocTreeVI_root_ll. *)
proc.
while{1} (0 <= size pkFORSnt{1} <= nr_trees 0) (nr_trees 0 - size pkFORSnt{1}).
+ move=> &m z; wp.
  while (0 <= size pkFORSlp <= l') (l' - size pkFORSlp).
  - by move=> z'; wp; call genpkfors_ll; auto; smt(size_rcons).
  by auto; smt(size_rcons ge2_lp size_ge0).
wp.
while (={ps, ad, skFORSnt}).
+ wp.
  while (={ps, ad, skFORSnt} /\ skFORSlp{1} = skFORSl{2}).
  - wp.
    while{2} (0 <= size rootsk{2} <= k) (k - size rootsk{2}).
    * move=> &m z; wp; call GprocTreeVI_root_ll; wp.
      while (0 <= size leavest <= t) (t - size leavest).
      + by move=> z'; auto; smt(size_rcons).
      by auto; smt(size_rcons ge2_t size_ge0).
    wp.
    while (={ps, ad, skFORSnt, skFORScube} /\ skFORSlp{1} = skFORSl{2}).
    * wp.
      while (={ps, ad, skFORSnt, skFORScube, skFORSet} /\ skFORSlp{1} = skFORSl{2}).
      + by auto.
      by auto.
    by auto; smt(ge1_k size_ge0).
  by auto.
by auto; smt(expr_ge0 size_ge0).
qed.

(* --- SUB-OBLIGATION 2: GprocKgVI's pk pool is pkfors_of of its own sk pool.
   ONE-SIDED, so no alignment.  Mirrors Gproc_keygen_pk_from_sk verbatim; the
   content is that the expanded leaf loop computes fors_leaves_op_cube and the
   expanded node loops compute val_bt_trh. *)
lemma GprocKgVI_pk_from_sk (psi : pseed) (adi : adrs) :
  hoare[GprocKgVI.keygen :
        ps = psi /\ ad = adi
        ==> size res.`1 = nr_trees 0
         /\ (forall i, 0 <= i < nr_trees 0 =>
               size (nth witness res.`1 i) = l'
            /\ (forall j, 0 <= j < l' =>
                  nth witness (nth witness res.`1 i) j
                  = pkfors_of (nth witness (nth witness res.`2 i) j) psi
                      (set_kpidx (set_tidx (set_typeidx adi trhftype) i) j)))].
proof.
(* ONE-SIDED: no alignment.  The tree layer now CITES GprocTreeVI_root_h, so
   what is left is bookkeeping: the leaf loop builds fors_leaves_op_cube
   pointwise, the tree loop collects the roots, and the final trco is exactly
   pkfors_of. *)
proc.
while (   ps = psi /\ ad = adi
       /\ 0 <= size skFORSnt <= nr_trees 0
       /\ size pkFORSnt = size skFORSnt
       /\ (forall i, 0 <= i < size pkFORSnt =>
             size (nth witness pkFORSnt i) = l'
          /\ (forall j, 0 <= j < l' =>
                nth witness (nth witness pkFORSnt i) j
                = pkfors_of (nth witness (nth witness skFORSnt i) j) psi
                    (set_kpidx (set_tidx (set_typeidx adi trhftype) i) j)))).
+ wp.
  while (   ps = psi /\ ad = adi
         /\ 0 <= size skFORSl <= l'
         /\ size pkFORSl = size skFORSl
         /\ 0 <= size skFORSnt < nr_trees 0
         /\ size pkFORSnt = size skFORSnt
         /\ (forall j, 0 <= j < size pkFORSl =>
               nth witness pkFORSl j
               = pkfors_of (nth witness skFORSl j) psi
                   (set_kpidx (set_tidx (set_typeidx adi trhftype) (size skFORSnt)) j))
         /\ (forall i, 0 <= i < size pkFORSnt =>
               size (nth witness pkFORSnt i) = l'
            /\ (forall j, 0 <= j < l' =>
                  nth witness (nth witness pkFORSnt i) j
                  = pkfors_of (nth witness (nth witness skFORSnt i) j) psi
                      (set_kpidx (set_tidx (set_typeidx adi trhftype) i) j)))).
  - wp.
    while (   ps = psi /\ ad = adi
           /\ 0 <= size rootsk <= k
           /\ 0 <= size skFORSl < l'
           /\ 0 <= size skFORSnt < nr_trees 0
           /\ (forall u, 0 <= u < size rootsk =>
                 nth witness rootsk u
                 = FTWES.val_bt_trh psi
                     (set_kpidx (set_tidx (set_typeidx adi trhftype) (size skFORSnt)) (size skFORSl))
                     (list2tree (fors_leaves_op_cube skFORS psi
                        (set_kpidx (set_tidx (set_typeidx adi trhftype) (size skFORSnt)) (size skFORSl)) u)) u)).
    * (* exists* BEFORE the wp, mirroring the in-tree precedent at
         GprocFORSC10.ec's Gproc_keygen_pk_from_sk (`exists* ..; elim* ..;
         wp; call ..`).  Putting wp first leaves the call's argument tuple
         un-abstracted, and the lifted address then has no equation tying it to
         the program expression -- which is exactly why the exit would not close. *)
      exists* skFORS, (size rootsk),
              (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) (size skFORSl));
      elim* => skF0 u0 adT0.
      wp; call (GprocTreeVI_root_h psi adT0 (fors_leaves_op_cube skF0 psi adT0 u0) u0).
      wp.
      while (   ps = psi /\ ad = adi
             (* CARRY the exists* equations through the loop: they live in the
                PRE, and without them in the invariant they are lost inside the
                loop and the exit cannot discharge the Merkle precondition. *)
             /\ skF0 = skFORS /\ u0 = size rootsk
             /\ adT0 = set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) (size skFORSl)
             /\ 0 <= size leavest <= t
             /\ 0 <= size rootsk < k
             /\ 0 <= size skFORSl < l'
             /\ 0 <= size skFORSnt < nr_trees 0
             (* phrase the mkseq over adT0/u0/skF0 -- the SAME terms cube_is_mkseq
                produces -- so the exit is a syntactic match.  Phrasing it over
                adi/size rootsk/skFORS instead forces smt to prove two mkseqs
                equal under a lambda, i.e. extensionality, which it will not do. *)
             /\ leavest = mkseq (fun (j : int) =>
                    f psi (set_thtbidx adT0 0 (u0 * t + j))
                      (DigestBlock.val (nth witness (nth witness (FTWES.DBLLKTL.val skF0)
                                          u0) j))) (size leavest)).
      + auto => />; smt(size_rcons size_mkseq mkseqS ge2_t size_ge0).
      (* ENTRY and EXIT split BY HAND.  A single smt over the combined
         conjunction failed six times; the dump shows why they want different
         tools -- entry is just mkseq0 at size [], exit is the Merkle
         precondition via cube_is_mkseq/size_cube once size leavest0 = t. *)
      auto.
      move=> &hr [#] eqskF equ eqadT eqps eqad ge0rk lekrk ge0skfl ltlskfl
                     ge0skfnt ltsskfnt nthrk ltkrk.
      split; 1: smt(mkseq0 ge2_t).
      move=> leavest0 hgeT hinv.
      move: hinv => [#] h1 h2 h3 h4 h5 h6 h7 h8 h9 h10 h11 h12 h13 eqmk.
      have szt : size leavest0 = t by smt().
      have hcube : leavest0 = fors_leaves_op_cube skF0 psi adT0 u0.
      (* occurrence-selected: a bare `-szt` also rewrites the `t` inside
         `u0 * t + j`, which breaks the match with eqmk.  Only the mkseq SIZE
         argument -- the second occurrence -- may be turned back. *)
      + rewrite cube_is_mkseq -{2}szt; exact eqmk.
      smt(size_cube nth_rcons size_rcons ge2_t size_ge0).
    (* the sk-cube sampling nest touches nothing in the invariant; the exit
       is where pkfors_of_from_roots converts the pointwise root
       characterisation into pkfors_of. *)
    wp.
    while (   ps = psi /\ ad = adi
             /\ 0 <= size skFORSl < l' /\ size pkFORSl = size skFORSl
             /\ 0 <= size skFORSnt < nr_trees 0 /\ size pkFORSnt = size skFORSnt
             /\ (forall j, 0 <= j < size pkFORSl =>
                   nth witness pkFORSl j
                   = pkfors_of (nth witness skFORSl j) psi
                       (set_kpidx (set_tidx (set_typeidx adi trhftype) (size skFORSnt)) j))
             /\ (forall i, 0 <= i < size pkFORSnt =>
                   size (nth witness pkFORSnt i) = l'
                /\ (forall j, 0 <= j < l' =>
                      nth witness (nth witness pkFORSnt i) j
                      = pkfors_of (nth witness (nth witness skFORSnt i) j) psi
                          (set_kpidx (set_tidx (set_typeidx adi trhftype) i) j)))).
    + wp.
      while (   ps = psi /\ ad = adi
             /\ 0 <= size skFORSl < l' /\ size pkFORSl = size skFORSl
             /\ 0 <= size skFORSnt < nr_trees 0 /\ size pkFORSnt = size skFORSnt
             /\ (forall j, 0 <= j < size pkFORSl =>
                   nth witness pkFORSl j
                   = pkfors_of (nth witness skFORSl j) psi
                       (set_kpidx (set_tidx (set_typeidx adi trhftype) (size skFORSnt)) j))
             /\ (forall i, 0 <= i < size pkFORSnt =>
                   size (nth witness pkFORSnt i) = l'
                /\ (forall j, 0 <= j < l' =>
                      nth witness (nth witness pkFORSnt i) j
                      = pkfors_of (nth witness (nth witness skFORSnt i) j) psi
                          (set_kpidx (set_tidx (set_typeidx adi trhftype) i) j)))).
      - by auto.
      by auto.
    auto => />; smt(pkfors_of_from_roots size_rcons nth_rcons ge1_k size_ge0).
  auto => />; smt(size_rcons nth_rcons size_ge0 ge2_lp).
auto => />; smt(size_rcons nth_rcons size_ge0 ge2_lp expr_ge0 expr_gt0).
qed.

(* THE ISOLATED OBLIGATION.  This is the whole content of the V-VI hop: a LOOP
   FUSION.  GprocKg.keygen samples the entire sk cube in one double loop and then
   builds the entire pk pool in a SECOND double loop; GprocKgVI fuses them into a
   single pass and expands gen_pkFORS into explicit leaf/node/root loops.  The
   sampling SEQUENCE is identical in both (nr_trees 0 x l' x k x t, same nesting
   order) -- only the deterministic pk work moves. *)
equiv gprockg_vi_eq :
  GprocKg.keygen ~ GprocKgVI.keygen : ={ps, ad} ==> ={res}.
proof.
(* DECOMPOSED, not attacked head-on.  A direct fusion would align a ONE-pass loop
   against a TWO-pass one.  Instead reuse the shape that closed brick 2b: relate
   only the SK cubes probabilistically, and characterise each side's PK pool
   ONE-SIDEDLY as the same pure `pkfors_of` of its own SK pool.  Sound because the
   pk work is DETERMINISTIC -- the fusion moves its position, not its value.
   `exists*` is required: ps/ad are PROGRAM variables here, not logical ones.
   The conseq leaves exactly TWO goals, both pure equality implications between
   the pre and the three instantiated preconditions -- dumped with `easycrypt
   cli` rather than guessed. *)
exists* ps{1}, ad{1}; elim* => psi adi.
conseq gprockg_vi_sk_eq
       (Gproc_keygen_pk_from_sk psi adi)
       (GprocKgVI_pk_from_sk psi adi).
+ smt().
(* The remaining goal is the POST: both pk pools are `pkfors_of` of their OWN sk
   pool, and the sk pools agree -- so the pk pools agree and the pairs are equal.
   That is exactly what pk_pools_eq (brick 2b) was built for.  Rewriting the
   right-hand characterisation through hsk is what makes both sides speak about
   the SAME sk pool, which is pk_pools_eq's precondition. *)
move=> &1 &2 _ rL rR [hsk [[hszL hL] [hszR hR]]].
have h1 : rL.`1 = rR.`1.
+ apply (pk_pools_eq rL.`1 rR.`1 rL.`2 psi adi) => //.
  move=> i hi; have [hs hj] := hR i hi.
  by rewrite hsk; split.
smt().
qed.

(* ---------------------------------------------------------------------------
   THE V-VI EQUALITY.  PROVED (2026-08-05), together with every lemma it rests
   on -- this file is now ADMIT-FREE.  Still in scratch/, so in neither closure,
   neither identity set and neither census; nothing here is gate-enforced yet.

   Both sides name EUF_CMA_Gproc_V.covered / .valid_* because _VI does
   `import var EUF_CMA_Gproc_V`: the flags are the SAME globals, not copies.
   That is what makes the hop invisible in MM45's probabilities and is the
   reason I missed it on the first pass.

   MM45's counterpart is Eqv_EUF_CMA_MFORSTWESNPRF_V_VI, FORS_ES.ec:3668-3819 --
   ~150 lines.  The content is a LOOP FUSION plus an inlining: GprocKg.keygen
   builds the whole sk cube in one double loop and then the whole pk pool in a
   SECOND double loop, while _VI fuses them into one pass and expands
   gen_pkFORS into explicit leaf/node/root loops.
   --------------------------------------------------------------------------- *)
lemma gproc_V_VI_eq
  (A <: Adv_EUFCMA_Gproc{-O_CMA_Gproc_I, -EUF_CMA_Gproc_I, -EUF_CMA_Gproc_V}) &m :
    Pr[EUF_CMA_Gproc_V(A).main() @ &m :
         ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
         /\ ! EUF_CMA_Gproc_V.valid_TRHTCR]
  = Pr[EUF_CMA_Gproc_VI(A).main() @ &m :
         ((res /\ ! EUF_CMA_Gproc_V.covered) /\ ! EUF_CMA_Gproc_V.valid_OpenPRE)
         /\ ! EUF_CMA_Gproc_V.valid_TRHTCR].
proof.
byequiv (_ : ={glob A} ==>
             ={res}
          /\ EUF_CMA_Gproc_V.covered{1}       = EUF_CMA_Gproc_V.covered{2}
          /\ EUF_CMA_Gproc_V.valid_OpenPRE{1} = EUF_CMA_Gproc_V.valid_OpenPRE{2}
          /\ EUF_CMA_Gproc_V.valid_TRHTCR{1}  = EUF_CMA_Gproc_V.valid_TRHTCR{2}) => //.
proc.
(* Split right after keygen: that is the ONLY place the two games differ.
   Everything after it is byte-identical, so `sim` drives the whole tail. *)
seq 3 3 : (={glob A, ps, ad, pkFORSnt, skFORSnt}).
+ by call gprockg_vi_eq; auto.
sim.
qed.
