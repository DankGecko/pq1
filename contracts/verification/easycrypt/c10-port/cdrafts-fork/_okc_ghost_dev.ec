(* DEV scratch for the okC-GHOST (discriminating +C okC-propagation).
   Same preamble as _seam_byequiv_wip.ec so the twin references resolve. *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import BinaryTrees MerkleTrees.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.

import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.

(* --- pure list helpers (copied verbatim from the WIP, they are 2-liners) --- *)
lemma all_idfun_nth (bs : bool list) (k : int) :
  all idfun bs => 0 <= k < size bs => nth witness bs k.
proof.
move=> /allP hall rng.
by have /# := hall (nth witness bs k) (mem_nth witness bs k rng).
qed.

lemma all_idfun_rcons (s : bool list) (x : bool) :
  all idfun (rcons s x) = (all idfun s /\ x).
proof. by rewrite -cats1 all_cat /= /idfun. qed.

(* self-equiv of the per-layer reconstruction (copied from WIP :408). *)
equiv pkfsc_self_eq :
  FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C ~ FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C :
    ={m, sigWOTS, counter, ps, ad} ==> ={res}.
proof. proc; sim. qed.

(* ==========================================================================
   L1: per-layer okC is DEFINITIONALLY the +C constant-sum gate predC(ThC ...)
   on the actual (ps, ad, m, counter) inputs -- reads pkWOTS_from_sigWOTS_C's
   `okC <- predC (ThC ps ad m counter)` line. *)
hoare pkfsc_okC_post (p : pseed) (a : adrs) (mm : msgWOTS) (cc : cntr) :
  FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C :
    ps = p /\ ad = a /\ m = mm /\ counter = cc
    ==> res.`2 = predC (ThC p a mm cc).
proof.
proc; wp.
while (ps = p /\ ad = a /\ m = mm /\ counter = cc).
- by auto.
by auto.
qed.

(* ==========================================================================
   L2: augmented instrumented twin of `root_from_sigC` -- identical control flow
   and root chain (per-layer call arg EXACTLY the same inline chtype address),
   but ALSO records, per layer, the +C-gate INPUT triple (chtype address,
   root-at-call, counter) into `tri`, alongside the per-layer okC into `okl`.
   This exposes the actual reconstruction values each per-layer okC gates on. *)
module FL_SL_XMSS_MT_C_ES_ExtTri = {
  proc root_from_sigC_okl_tri(m : msgFLSLXMSSMTTW, sig : sigFLSLXMSSMTTWC, idx : index,
                              ps : pseed, ad : adrs)
       : dgstblock * bool list * (adrs * dgstblock * cntr) list = {
    var root : dgstblock;
    var tidx, kpidx : int;
    var i : int;
    var sigWOTS : sigWOTS;
    var counter : cntr;
    var sc : sigWOTS * cntr;
    var ap : apFLXMSSTW;
    var pkWOTS : pkWOTS;
    var leaf : dgstblock;
    var okC : bool;
    var okl : bool list;
    var addr : adrs;
    var tri : (adrs * dgstblock * cntr) list;

    i <- 0;
    root <- m;
    okl <- [];
    tri <- [];
    (tidx, kpidx) <- (Index.val idx, 0);
    while (i < d) {
      (tidx, kpidx) <- edivz tidx l';

      (sc, ap) <- nth witness sig i;
      sigWOTS <- sc.`1;
      counter <- sc.`2;

      addr <- set_kpidx (set_typeidx (set_ltidx ad i tidx) chtype) kpidx;
      (pkWOTS, okC) <@ FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C(root, sigWOTS, counter, ps, addr);
      okl <- rcons okl okC;
      tri <- rcons tri (addr, root, counter);

      leaf <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad i tidx) pkcotype) kpidx) (flatten (map DigestBlock.val (DBLL.val pkWOTS)));
      root <- val_ap_trh ps (set_typeidx (set_ltidx ad i tidx) trhxtype) ap kpidx leaf;

      i <- i + 1;
    }

    return (root, okl, tri);
  }
}.

(* ==========================================================================
   L3a (equiv half): the REAL `root_from_sigC`'s scalar `allOkC` = `all idfun
   okl` for the twin's per-layer okC list (the fold-to-list bridge that makes
   allOkC indexable), the roots agree, and both lists have size d.  Faithful
   EQUIV -- identical root chain + per-layer calls.  Template: the existing
   `root_from_sigC_okl_eq`. *)
equiv root_from_sigC_tri_eq :
  FL_SL_XMSS_MT_C_ES.root_from_sigC ~ FL_SL_XMSS_MT_C_ES_ExtTri.root_from_sigC_okl_tri :
    ={m, sig, idx, ps, ad}
    ==>    res{1}.`1 = res{2}.`1
        /\ res{1}.`2 = all idfun res{2}.`2
        /\ size res{2}.`2 = d
        /\ size res{2}.`3 = d.
proof.
proc.
while (   ={i, root, tidx, kpidx, sig, m, ps, ad}
       /\ allOkC{1} = all idfun okl{2}
       /\ size okl{2} = i{2} /\ size tri{2} = i{2} /\ 0 <= i{2} <= d).
+ wp; call pkfsc_self_eq; auto => />.
  smt(all_idfun_rcons size_rcons).
auto; smt(ge1_d).
qed.

(* ==========================================================================
   L3b (hoare half, THE DISCRIMINATING +C CONTENT): every entry of the twin's
   per-layer okC list is EXACTLY the +C constant-sum gate predC(ThC p addr_j
   root_j counter_j) on the actual layer-j reconstruction triple it recorded.
   This is where the +C gate is PINNED to the reconstruction: it names predC /
   ThC on the real per-layer (address, root, counter), not an arbitrary boolean.
   Its 0-admit compile is the confirmation the recipe asks for. *)
hoare root_from_sigC_okl_tri_char (p : pseed) :
  FL_SL_XMSS_MT_C_ES_ExtTri.root_from_sigC_okl_tri :
    ps = p
    ==>    size res.`2 = d
        /\ size res.`3 = d
        /\ (forall (j : int), 0 <= j < size res.`2 =>
              nth witness res.`2 j
              = predC (ThC p (nth witness res.`3 j).`1
                             (nth witness res.`3 j).`2
                             (nth witness res.`3 j).`3)).
proof.
proc.
while (   ps = p /\ size okl = i /\ size tri = i /\ 0 <= i <= d
       /\ (forall (j : int), 0 <= j < i =>
             nth witness okl j
             = predC (ThC p (nth witness tri j).`1
                            (nth witness tri j).`2
                            (nth witness tri j).`3))).
+ sp; wp.
  exists* ps, addr, root, counter; elim* => psv addrv rootv counterv.
  move=> tpre.
  call (pkfsc_okC_post psv addrv rootv counterv).
  skip => /> &hr hedivz hscap hsztri ge0okl iled hchar hokld result hres.
  rewrite !size_rcons hsztri /=.
  split; first by smt(size_ge0).
  move=> j ge0j jlt.
  rewrite !nth_rcons hsztri.
  smt().
auto => />; smt(size_ge0 ge1_d).
qed.

(* ==========================================================================
   L4 (pure selection): from `all idfun okl` (= the real reconstruction's
   `allOkC = true`) and the per-layer +C-gate characterization, the gate holds
   at ANY in-range layer -- the arithmetic content of "recover the planted
   WOTS+C layer's +C gate from the aggregate hypertree gate". *)
lemma okC_select (p : pseed) (okl : bool list) (tri : (adrs * dgstblock * cntr) list) (cidx : int) :
     all idfun okl
  => size okl = size tri
  => (forall (j : int), 0 <= j < size okl =>
        nth witness okl j
        = predC (ThC p (nth witness tri j).`1 (nth witness tri j).`2 (nth witness tri j).`3))
  => 0 <= cidx < size tri
  => predC (ThC p (nth witness tri cidx).`1 (nth witness tri cidx).`2 (nth witness tri cidx).`3).
proof.
move=> hall hsz hchar hrng.
have hrngokl : 0 <= cidx < size okl by rewrite hsz.
rewrite -(hchar cidx hrngokl).
exact (all_idfun_nth okl cidx hall hrngokl).
qed.

(* ==========================================================================
   CAPSTONE (THE okC-GHOST, single headline fact): running the real WOTS+C
   hypertree reconstruction and obtaining a satisfied aggregate +C gate
   (`all idfun okl`, i.e. the real `root_from_sigC`'s `allOkC = true` via L3a)
   FORCES the +C constant-sum gate `predC(ThC p addr_cidx root_cidx counter_cidx)`
   at EVERY layer cidx, on the ACTUAL layer-cidx reconstruction triple.  This is
   the discriminating +C okC-propagation: the extracted WOTS+C layer's gate is
   recovered from the folded hypertree gate.  Composes L3b + okC_select, 0-admit. *)
lemma okC_ghost (p : pseed) (cidx : int) :
  0 <= cidx < d =>
  hoare[ FL_SL_XMSS_MT_C_ES_ExtTri.root_from_sigC_okl_tri :
           ps = p
           ==> all idfun res.`2 =>
               predC (ThC p (nth witness res.`3 cidx).`1
                            (nth witness res.`3 cidx).`2
                            (nth witness res.`3 cidx).`3) ].
proof.
move=> hcidx.
conseq (root_from_sigC_okl_tri_char p).
move=> &hr hpsp result [hsz2 [hsz3 hchar]] hall.
apply (okC_select p result.`2 result.`3 cidx hall _ hchar _).
- by rewrite hsz2 hsz3.
- by rewrite hsz3.
qed.
