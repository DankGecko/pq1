(* ==========================================================================
   XMSSMT_C_Reduction.ec -- FOUNDATIONAL game infrastructure for the WOTS+C
   hypertree (XMSS-MT+C) EUF-NAGCMA reduction.

   This is milestone 1 (steps 1-3) of the XMSS-MT+C hypertree security port,
   the last major piece of the SPHINCS+C EUF-CMA formalization.  It mirrors
   MM45's `FL_SL_XMSS_MT_ES.ec` NPRF machinery
   (FV-SPHINCSPLUS-EC/proofs/FL_SL_XMSS_MT_ES.ec:1672-1883), specialised to the
   REAL WOTS+C hypertree `FL_SL_XMSS_MT_C_ES` (drafts/XMSSMT_C_Scheme.ec).

   WHAT IS BUILT HERE
   ------------------
     1. NPRF hypertree module `FL_SL_XMSS_MT_C_ES_NPRF`: samples the full
        WOTS-key cube INDEPENDENTLY (not via `gen_skWOTS`/`skg`), signs with
        WOTS+C (per-layer counter, exactly as `XMSSMT_C_Scheme.ec:102-134`), and
        ALIASES its `verify` to the REAL `FL_SL_XMSS_MT_C_ES.verify`
        (mirroring MM45's NPRF verifier alias at FL_SL_XMSS_MT_ES.ec:1816).
     2. Adversary interface + EUF-NAGCMA game
        (`Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF` / `EUF_NAGCMA_FLSLXMSSMTTWCESNPRF`):
        nonadaptive (exactly `l` signature queries committed up front), preserving
        freshness and the REAL WOTS+C verification.  Template:
        FL_SL_XMSS_MT_ES.ec:1824-1883.
     3. Helper specs (0-admit): NPRF signing size + losslessness; the equivalence
        of the hypertree's `pkWOTS_from_sigWOTS_C` reconstruction with WOTS+C
        `verify`; extraction of a selected layer's `okC` from the global `allOkC`.

   FAITHFULNESS DECISION (signature type)
   --------------------------------------
   MM45 wraps its size-`d` hypertree signature in the `SAPDL.sT` subtype
   (FL_SL_XMSS_MT_ES.ec:627).  Our REAL scheme `FL_SL_XMSS_MT_C_ES` deliberately
   keeps a PLAIN list `sigFLSLXMSSMTTWC` and lets `verify` enforce `size sig = d`
   (XMSSMT_C_Scheme.ec:63-69).  Because the NPRF module ALIASES that same
   `verify`, the NPRF signature output MUST be the plain `sigFLSLXMSSMTTWC` list
   (no subtype), so the game / interface / freshness all carry the plain list.
   This is the faithful choice: a subtype would mis-type the aliased verifier.

   STATUS: module + game definitions + PROVEN helper specs.  NO admit, NO axiom.
   ========================================================================== *)

require import AllCore List Distr StdBigop StdOrder IntDiv.
require import DList DMap.
require import BinaryTrees MerkleTrees.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.

(*---*) import StdOrder.IntOrder StdBigop.Bigint StdBigop.Bigint.BIA.

import FSSLXMTWES.           (* d, l, l', nr_trees, pkco, cons_ap_trh, val_bt_trh,
                                val_ap_trh, list2tree, set_ltidx, set_kpidx,
                                set_typeidx, chtype, pkcotype, trhxtype, adz,
                                Index, index, ddgstblock, dpseed, Oracle_THFC,
                                pkFLSLXMSSMTTW, msgFLSLXMSSMTTW, apFLXMSSTW, ... *)
import FSSLXMTWES.WTWES.     (* the CONCRETE WOTS-TW instance: skWOTS, sigWOTS,
                                pkWOTS, WOTS_TW_ES_NPRF, cf, set_chidx, ... *)
import WOTS_C_Real.          (* cntr, ThC, predC *)
import WOTS_C_Scheme.        (* WOTS_C_ES, grindC, encode_msgWOTS_C, WOTS_C_ES_sign_ll *)
import EmsgWOTS.             (* emsgWOTS `.[]` word-indexing *)
import XMSSMT_C_Scheme.      (* FL_SL_XMSS_MT_C_ES, sigFLSLXMSSMTTWC, wotsc_sign_h *)
import WOTS_C_Interactive.   (* R_int_STCRC, O_THFC_MA, dfC, member_sep_disj,
                                owrap_chainwalk_member8n, S_TCR_C_Int_MA,
                                interactive_D1_MA, STCRC_WC, Oracle_MEUFGCMA_WOTSC,
                                O_MEUFGCMA_WOTSC_Default, Adv_MEUFGCMA_WOTSC *)

(* --------------------------------------------------------------------------
   STEP 1: the NPRF hypertree over WOTS+C.

   Mirror of MM45's `FL_SL_XMSS_MT_ES_NPRF` (FL_SL_XMSS_MT_ES.ec:1672) with the
   two +C deltas of `FL_SL_XMSS_MT_C_ES` folded in:
     * `sign` routes each layer through `WOTS_C_ES.sign` (which grinds and
       appends the per-layer counter), reading the WOTS secret key from the
       INDEPENDENTLY-sampled cube rather than deriving it via `gen_skWOTS`;
     * `verify` is ALIASED to the real `FL_SL_XMSS_MT_C_ES.verify`, so both the
       size gate and the +C constant-sum gate are the REAL ones.
   Leaves / keygen root are +C-independent (WOTS keygen is unchanged by +C), so
   they are byte-for-byte the MM45 NPRF (modulo the FSSLXMTWES `trhtype -> trhxtype`
   rename baked into the clone).
   -------------------------------------------------------------------------- *)
module FL_SL_XMSS_MT_C_ES_NPRF = {
  (* Compute (inner tree) leaves from a WOTS-TW secret-key list, public seed, and
     address.  Mirror of FL_SL_XMSS_MT_ES.ec:1674. *)
  proc leaves_from_sklpsad(skWOTSl : skWOTS list, ps : pseed, ad : adrs) : dgstblock list = {
    var skWOTS : skWOTS;
    var pkWOTS : pkWOTS;
    var leaf : dgstblock;
    var leaves : dgstblock list;

    leaves <- [];
    while (size leaves < l') {
      skWOTS <- nth witness skWOTSl (size leaves);
      pkWOTS <@ WOTS_TW_ES_NPRF.pkWOTS_from_skWOTS(skWOTS, ps, set_kpidx (set_typeidx ad chtype) (size leaves));
      leaf <- pkco ps (set_kpidx (set_typeidx ad pkcotype) (size leaves)) (flatten (map DigestBlock.val (DBLL.val pkWOTS)));
      leaves <- rcons leaves leaf;
    }

    return leaves;
  }

  (* Key generation: sample the ENTIRE WOTS-key cube (d layers * nr_trees(layer)
     inner trees * l' leaves * len chains) independently from `ddgstblock`, then
     compute the hypertree root from the top-most inner tree.
     Mirror of FL_SL_XMSS_MT_ES.ec:1698. *)
  proc keygen(ps : pseed, ad : adrs) : pkFLSLXMSSMTTW * (skWOTS list list list * pseed * adrs) = {
    var root : dgstblock;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var pk : pkFLSLXMSSMTTW;
    var sk : skWOTS list list list * pseed * adrs;

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
    leaves <@ leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (d - 1) 0);

    root <- val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhxtype) (list2tree leaves);

    pk <- (root, ps, ad);
    sk <- (skWOTStd, ps, ad);

    return (pk, sk);
  }

  (* Signing: mirror of the REAL `FL_SL_XMSS_MT_C_ES.sign` (XMSSMT_C_Scheme.ec:102)
     but the WOTS secret key is EXTRACTED from the sampled cube instead of derived
     via `gen_skWOTS`.  Each layer routes through `WOTS_C_ES.sign`, carrying the
     ground counter (the +C delta).  Returns the plain `sigFLSLXMSSMTTWC` list. *)
  proc sign(sk : skWOTS list list list * pseed * adrs, m : msgFLSLXMSSMTTW, idx : index) : sigFLSLXMSSMTTWC = {
    var ps : pseed;
    var ad : adrs;
    var tidx, kpidx : int;
    var skWOTS : skWOTS;
    var sigWOTS : sigWOTS;
    var counter : cntr;
    var skWOTSlp : skWOTS list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var ap : apFLXMSSTW;
    var sapl : sigFLSLXMSSMTTWC;
    var root : dgstblock;

    (skWOTStd, ps, ad) <- sk;

    root <- m;
    sapl <- [];
    (tidx, kpidx) <- (Index.val idx, 0);
    while (size sapl < d) {
      (tidx, kpidx) <- edivz tidx l';

      (* Extract the WOTS+C secret key from the cube: layer (size sapl), inner
         tree (tidx), key pair (kpidx). *)
      skWOTSlp <- nth witness (nth witness skWOTStd (size sapl)) tidx;
      skWOTS <- nth witness skWOTSlp kpidx;

      (* WOTS+C sign WITH the ground counter (same call the real scheme makes). *)
      (sigWOTS, counter) <@ WOTS_C_ES.sign((skWOTS, ps, set_kpidx (set_typeidx (set_ltidx ad (size sapl) tidx) chtype) kpidx), root);

      leaves <@ leaves_from_sklpsad(skWOTSlp, ps, (set_ltidx ad (size sapl) tidx));
      ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhxtype) (list2tree leaves) kpidx;
      root <- val_bt_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhxtype) (list2tree leaves);

      sapl <- rcons sapl ((sigWOTS, counter), ap);
    }

    return sapl;
  }

  (* +C-faithful verification: the REAL scheme's verify (size gate + root match +
     the d per-layer constant-sum gates).  Mirror of MM45's NPRF alias at
     FL_SL_XMSS_MT_ES.ec:1816. *)
  proc verify = FL_SL_XMSS_MT_C_ES.verify
}.

(* --------------------------------------------------------------------------
   STEP 2: adversary interface + EUF-NAGCMA game for the WOTS+C hypertree.

   Mirror of MM45's `Adv_EUFNAGCMA_FLSLXMSSMTTWESNPRF` /
   `EUF_NAGCMA_FLSLXMSSMTTWESNPRF` (FL_SL_XMSS_MT_ES.ec:1824-1883).  Nonadaptive:
   the adversary commits its `l` message queries up front (`choose`), the game
   signs them under the NPRF key, and the adversary must then produce a fresh
   forgery.  The +C deltas are (a) the plain `sigFLSLXMSSMTTWC` signatures and
   (b) the REAL WOTS+C verification via the aliased `verify`.
   -------------------------------------------------------------------------- *)

(* Adversaries against EUF-NAGCMA for FL-SL-XMSS-MT-TW+C-ES-NPRF. *)
module type Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF (OC : FSSLXMTWES.TRHC.Oracle_THFC) = {
  proc choose() : msgFLSLXMSSMTTW list { OC.query }
  proc forge(pk : pkFLSLXMSSMTTW, sigl : sigFLSLXMSSMTTWC list) : msgFLSLXMSSMTTW * sigFLSLXMSSMTTWC * index {}
}.

(* EUF-NAGCMA for FL-SL-XMSS-MT-TW+C-ES-NPRF. *)
module EUF_NAGCMA_FLSLXMSSMTTWCESNPRF (A : Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF, OC : FSSLXMTWES.TRHC.Oracle_THFC) = {
  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pk : pkFLSLXMSSMTTW;
    var sk : skWOTS list list list * pseed * adrs;
    var ml : msgFLSLXMSSMTTW list;
    var sigl : sigFLSLXMSSMTTWC list;
    var m, m' : msgFLSLXMSSMTTW;
    var sig, sig' : sigFLSLXMSSMTTWC;
    var idx' : index;
    var is_valid, is_fresh : bool;

    (* Initialize address and public seed *)
    ad <- adz;
    ps <$ dpseed;

    (* Initialize collection oracle *)
    OC.init(ps);

    (* Ask adversary to choose a list of messages for which to receive signatures *)
    ml <@ A(OC).choose();

    (* Generate keypair for FL-SL-XMSS-MT-TW+C-ES-NPRF *)
    (pk, sk) <@ FL_SL_XMSS_MT_C_ES_NPRF.keygen(ps, ad);

    (* Sign (up to l) messages from the list provided by the adversary *)
    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);

      sig <@ FL_SL_XMSS_MT_C_ES_NPRF.sign(sk, m, Index.insubd (size sigl));

      sigl <- rcons sigl sig;
    }

    (* Ask adversary to forge (given public key and list of signatures) *)
    (m', sig', idx') <@ A(OC).forge(pk, sigl);

    (* Check validity of the forgery (REAL WOTS+C verification) *)
    is_valid <@ FL_SL_XMSS_MT_C_ES_NPRF.verify(pk, m', sig', idx');

    (* Freshness: the forged message differs from the one signed at the forgery's index *)
    is_fresh <- m' <> nth witness ml (Index.val idx');

    return is_valid /\ is_fresh;
  }
}.

(* --------------------------------------------------------------------------
   STEP 3: helper specs (0-admit).

   These are the correctness gates the reduction consumes.  The NPRF signer must
   emit exactly `d` layers (so a signature can verify at all) and must terminate;
   the hypertree's per-layer reconstruction must coincide with WOTS+C `verify`
   (so a layer of a hypertree forgery is a WOTS+C forgery); and a valid hypertree
   signature's global `allOkC` gate must yield each selected layer's `okC`.
   -------------------------------------------------------------------------- *)

(* ---- (A) + (B): the NPRF signer emits `d` layers and terminates. ----
   Mirrors the REAL scheme's `sign_size_d` / `sign_ll` (XMSSMT_C_Scheme.ec:249,278)
   with the `gen_skWOTS` call replaced by cube extraction (a pure assignment). *)

(* leaves of the call chain (hoare + losslessness), for the NPRF leaf proc. *)
lemma pkWOTS_from_skWOTS_nprf_h : hoare[WOTS_TW_ES_NPRF.pkWOTS_from_skWOTS : true ==> true].
proof. proc; while (true); auto. qed.

lemma pkWOTS_from_skWOTS_nprf_ll : islossless WOTS_TW_ES_NPRF.pkWOTS_from_skWOTS.
proof. proc; while (true) (len - size pkWOTS); auto; smt(size_rcons). qed.

lemma leaves_sklpsad_h : hoare[FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad : true ==> true].
proof.
proc; while (true).
+ by wp; call pkWOTS_from_skWOTS_nprf_h; auto.
by auto.
qed.

lemma leaves_sklpsad_ll : islossless FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad.
proof.
proc; while (true) (l' - size leaves).
+ move=> z; wp; call pkWOTS_from_skWOTS_nprf_ll; auto; smt(size_rcons).
by auto; smt().
qed.

(* (A) THE SIZE GATE: NPRF `sign` emits exactly `d` layers. *)
lemma nprf_sign_size_d :
  hoare[FL_SL_XMSS_MT_C_ES_NPRF.sign : true ==> size res = d].
proof.
proc.
while (0 <= size sapl /\ size sapl <= d).
+ wp; call leaves_sklpsad_h; call wotsc_sign_h; auto.
  smt(size_rcons).
auto; smt(ge1_d size_ge0).
qed.

(* (B) LOSSLESSNESS: NPRF `sign` terminates with probability 1 (threads the
   WOTS+C counter grind `WOTS_C_ES_sign_ll` through the d-layer loop). *)
lemma nprf_sign_ll : islossless FL_SL_XMSS_MT_C_ES_NPRF.sign.
proof.
proc; while (true) (d - size sapl).
+ move=> z; wp; call leaves_sklpsad_ll; call WOTS_C_ES_sign_ll; auto; smt(size_rcons).
by auto; smt().
qed.

(* ---- (C) THE VERIFY BRIDGE. ----
   The hypertree's internal per-layer reconstruction `pkWOTS_from_sigWOTS_C`
   (XMSSMT_C_Scheme.ec:139) coincides with standalone WOTS+C `verify`
   (WOTS_C_Scheme.ec:72): both recompute `em = encode_msgWOTS_C ps ad m counter`,
   chain-walk to a candidate pk, and evaluate the SAME `okC = predC (ThC ...)`.
   Hence a single hypertree layer's reconstruction+gate is exactly a WOTS+C
   verification.  This is the load-bearing faithfulness artifact of the milestone:
   it lets the later reduction treat a layer of a hypertree forgery as a WOTS+C
   forgery, gate included. *)
equiv pkfromsigC_verify_eq (pkv : pkWOTS) :
  FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C ~ WOTS_C_ES.verify :
    m{1} = m{2} /\ sigWOTS{1} = (sigc{2}).`1 /\ counter{1} = (sigc{2}).`2 /\
    ps{1} = (pk{2}).`2 /\ ad{1} = (pk{2}).`3 /\ (pk{2}).`1 = pkv
    ==> res{2} = (res{1}.`1 = pkv /\ res{1}.`2).
proof.
proc.
wp; while (={m, counter, ps, ad, em, pkWOTS_l} /\ sigWOTS{1} = sig{2} /\ pkWOTS{2} = pkv).
+ auto.
auto.
qed.

(* ---- (D) LAYER-okC EXTRACTION FROM THE GLOBAL allOkC. ----
   The real `root_from_sigC` (XMSSMT_C_Scheme.ec:163) folds the d per-layer +C
   gates into a single `allOkC` via `allOkC <- allOkC /\ okC`.  A valid hypertree
   signature has `allOkC = true`, and the reduction must recover the +C gate of
   the SPECIFIC layer where it plants a WOTS+C forgery.

   Because each per-layer `okC` depends on the reconstructed intermediate root
   (only produced inside the loop), no closed postcondition on `root_from_sigC`
   alone can name the k-th gate.  We therefore (1) instrument an
   `allOkC`-as-a-list twin (`root_from_sigC_okl`), (2) prove it agrees with the
   real proc on the root and satisfies `allOkC = all idfun okl` with `size okl = d`
   (an EQUIV to the real reconstruction -- faithful, not a re-definition), and
   (3) apply the pure fact that a conjunction-list true at every position yields
   any selected position. *)

(* (D.1) The pure extraction fact: an all-true boolean list is true at every
   in-range index -- the arithmetic content of "select layer k's gate". *)
lemma all_idfun_nth (bs : bool list) (k : int) :
  all idfun bs => 0 <= k < size bs => nth witness bs k.
proof.
move=> /allP hall rng.
by have /# := hall (nth witness bs k) (mem_nth witness bs k rng).
qed.

(* `all idfun` distributes over `rcons`: the fold-step used by the twin's
   invariant (`allOkC <- allOkC /\ okC` mirrors `okl <- rcons okl okC`). *)
lemma all_idfun_rcons (s : bool list) (x : bool) :
  all idfun (rcons s x) = (all idfun s /\ x).
proof. by rewrite -cats1 all_cat /= /idfun. qed.

(* (D.2) Instrumented twin of the real `root_from_sigC`: identical control flow
   and per-layer gate computation, but accumulates the per-layer `okC` into a
   list `okl` instead of AND-folding into `allOkC`. *)
module FL_SL_XMSS_MT_C_ES_Ext = {
  proc root_from_sigC_okl(m : msgFLSLXMSSMTTW, sig : sigFLSLXMSSMTTWC, idx : index,
                          ps : pseed, ad : adrs) : dgstblock * bool list = {
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

    i <- 0;
    root <- m;
    okl <- [];
    (tidx, kpidx) <- (Index.val idx, 0);
    while (i < d) {
      (tidx, kpidx) <- edivz tidx l';

      (sc, ap) <- nth witness sig i;
      sigWOTS <- sc.`1;
      counter <- sc.`2;

      (pkWOTS, okC) <@ FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C(root, sigWOTS, counter, ps,
                          set_kpidx (set_typeidx (set_ltidx ad i tidx) chtype) kpidx);
      okl <- rcons okl okC;

      leaf <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad i tidx) pkcotype) kpidx) (flatten (map DigestBlock.val (DBLL.val pkWOTS)));
      root <- val_ap_trh ps (set_typeidx (set_ltidx ad i tidx) trhxtype) ap kpidx leaf;

      i <- i + 1;
    }

    return (root, okl);
  }
}.

(* Self-equivalence of the per-layer reconstruction (identical procedure, no
   global state) -- lets the twin's per-layer call track the real one's. *)
equiv pkfsc_self_eq :
  FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C ~ FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C :
    ={m, sigWOTS, counter, ps, ad} ==> ={res}.
proof. proc; sim. qed.

(* (D.3) The instrumented twin agrees with the real reconstruction on the root,
   and its list `okl` folds (via `all idfun`) to exactly the real `allOkC`, with
   `size okl = d`.  This is a faithful EQUIV to the real `root_from_sigC`. *)
equiv root_from_sigC_okl_eq :
  FL_SL_XMSS_MT_C_ES.root_from_sigC ~ FL_SL_XMSS_MT_C_ES_Ext.root_from_sigC_okl :
    ={m, sig, idx, ps, ad}
    ==> res{1}.`1 = res{2}.`1 /\ res{1}.`2 = all idfun res{2}.`2 /\ size res{2}.`2 = d.
proof.
proc.
while (={i, root, tidx, kpidx, sig, m, ps, ad} /\
       allOkC{1} = all idfun okl{2} /\ size okl{2} = i{2} /\ 0 <= i{2} <= d).
+ wp; call pkfsc_self_eq; auto => />.
  smt(all_idfun_rcons size_rcons).
auto; smt(ge1_d).
qed.


(* ==========================================================================
   STEP 3.5 (this session): THE +C okC-GHOST -- discriminating +C okC-propagation.
   Isolated, 0-admit.  Ported from the gated dev scratch.  See okC_ghost (capstone).
   ========================================================================== *)
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

(* ==========================================================================
   STEP 4: the +C-SPECIFIC LEAF REDUCTION `R_MEUFGCMAWOTSC_EUFNAGCMA_C`.

   Template: MM45's `R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA`
   (FV-SPHINCSPLUS-EC/proofs/FL_SL_XMSS_MT_ES.ec:1888-2127), specialised to the
   INTERACTIVE WOTS+C signing oracle (`Oracle_MEUFGCMA_WOTSC`, WOTS_C_Scheme.ec:
   132) and the plain `sigFLSLXMSSMTTWC` hypertree signature.

   `R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)` is a WOTS+C adversary `Adv_MEUFGCMA_WOTSC`
   that runs the hypertree adversary `A_ht` internally and SIMULATES
   `EUF_NAGCMA_FLSLXMSSMTTWCESNPRF` to it:

     * `choose`: relay A_ht's committed `l` leaf messages, then build the ENTIRE
       hypertree cube by querying the INTERACTIVE WOTS+C signing oracle `O.query`
       per leaf (each upper-layer message is a subtree ROOT computed from
       oracle-returned pkWOTS — adaptive, exactly the MM45 nesting), storing the
       returned `(sigWOTS, counter)` per leaf (the +C counter thread,
       XMSSMT_C_Scheme.ec:102-134), compressing each pkWOTS to a leaf via `pkco`
       (member 8n*len) and hashing Merkle nodes via `trh` (member 8n*2) with the
       COLLECTION oracle `OC`.
     * `forge`: assemble honest hypertree signatures for A_ht's `l` messages, get
       A_ht's forgery, reconstruct each layer's WOTS pk via
       `pkWOTS_from_sigWOTS_C` (+C: re-derives the pk AND evaluates the constant-
       sum gate), find the layer that is a WOTS+C forgery, and return the selected
       WOTS+C forgery `(fidx, root', (sigWOTS', counter'))`.

   The ONLY +C deltas vs MM45: the signing oracle returns `(sigWOTS, cntr)` (so
   the cube stores counters and the forgery carries one), the hypertree signature
   is the plain `sigFLSLXMSSMTTWC` list (no size-d subtype), and the reconstruction
   is the +C `pkWOTS_from_sigWOTS_C`.  Everything else is byte-for-byte MM45 modulo
   the `trhtype -> trhxtype` clone rename.
   -------------------------------------------------------------------------- *)
module (R_MEUFGCMAWOTSC_EUFNAGCMA_C (A : Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF) : Adv_MEUFGCMA_WOTSC)
       (O : Oracle_MEUFGCMA_WOTSC, OC : FC.Oracle_THFC) = {
  var ad : adrs
  var ml : msgFLSLXMSSMTTW list
  var pkWOTStd : pkWOTS list list list
  var sigWOTStd : (sigWOTS * cntr) list list list
  var leavestd : dgstblock list list list
  var rootstd : dgstblock list list

  (* NOTE (A_wf_MA-faithful oracle wiring).  MM45 (FL_SL_XMSS_MT_ES.ec:1901) wraps
     `OC` in a local `O_THFC` purely to SEPARATE the inner adversary's collection
     queries from the reduction's own (used by its per-family tweak-disjointness
     bookkeeping).  Our interactive S-TCR discharge is MEMBER-based
     (`member_sep_disj` over ALL of `O_THFC_MA.tws_ma`), so no such separation
     bookkeeping is needed: we hand `A_ht` the collection oracle `OC` DIRECTLY.
     `FC.Oracle_THFC` is structurally accepted where `A_ht` expects
     `FSSLXMTWES.TRHC.Oracle_THFC` (same {init,get_tweaks,query} signature over the
     same underlying `thfc`), so this is a byte-identical simulation of A_ht's view
     with a clean threadable well-formedness hypothesis on `A_ht(OC).choose`. *)

  proc choose() : unit = {
    var pkWOTS : pkWOTS;
    var pkWOTSlp : pkWOTS list;
    var pkWOTSnt : pkWOTS list list;
    var sigc : sigWOTS * cntr;
    var sigclp : (sigWOTS * cntr) list;
    var sigcnt : (sigWOTS * cntr) list list;
    var leaf : dgstblock;
    var leaveslp : dgstblock list;
    var leavesnt : dgstblock list list;
    var root : dgstblock;
    var rootsnt, rootsntp : dgstblock list;
    var lnode, rnode, node : dgstblock;
    var nodespl, nodescl : dgstblock list;
    var nodes : dgstblock list list;

    (* Ask adversary to provide list of messages to sign (A_ht queries OC directly) *)
    ml <@ A(OC).choose();

    (* Initialize address *)
    ad <- adz;

    (* Using the provided oracles, compute and store all the WOTS+C public keys,
       WOTS+C (signature, counter) pairs, (inner tree) leaves, and (inner tree)
       roots. *)
    pkWOTStd <- [];
    sigWOTStd <- [];
    leavestd <- [];
    rootstd <- [];
    while (size pkWOTStd < d) {
      pkWOTSnt <- [];
      sigcnt <- [];
      leavesnt <- [];
      rootsnt <- [];
      rootsntp <- last ml rootstd;
      while (size pkWOTSnt < nr_trees (size pkWOTStd)) {
        pkWOTSlp <- [];
        sigclp <- [];
        leaveslp <- [];
        while (size pkWOTSlp < l') {
          (* Compute the to-be-signed message/root *)
          root <- nth witness rootsntp (size pkWOTSnt * l' + size pkWOTSlp);

          (* Query the interactive WOTS+C signing oracle to obtain the pk + (sig, counter) *)
          (pkWOTS, sigc) <@ O.query(WAddress.insubd (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTStd) (size pkWOTSnt)) chtype) (size pkWOTSlp)),
                                    root);

          (* Compress the obtained WOTS+C public key to the corresponding leaf (pkco, member 8n*len) *)
          leaf <@ OC.query(set_kpidx (set_typeidx (set_ltidx ad (size pkWOTStd) (size pkWOTSnt)) pkcotype) (size pkWOTSlp),
                           flatten (map DigestBlock.val (DBLL.val pkWOTS)));

          pkWOTSlp <- rcons pkWOTSlp pkWOTS;
          sigclp <- rcons sigclp sigc;
          leaveslp <- rcons leaveslp leaf;
        }

        nodes <- [];
        while (size nodes < h') {
          nodespl <- last leaveslp nodes;

          nodescl <- [];
          while (size nodescl < nr_nodesx (size nodes + 1)) {
            lnode <- nth witness nodespl (2 * size nodescl);
            rnode <- nth witness nodespl (2 * size nodescl + 1);

            (* Merkle node via trh (member 8n*2) *)
            node <@ OC.query(set_thtbidx (set_typeidx (set_ltidx ad (size pkWOTStd) (size pkWOTSnt)) trhxtype)
                                         (size nodes + 1) (size nodescl),
                             DigestBlock.val lnode ++ DigestBlock.val rnode);

            nodescl <- rcons nodescl node;
          }
          nodes <- rcons nodes nodescl;
        }
        pkWOTSnt <- rcons pkWOTSnt pkWOTSlp;
        sigcnt <- rcons sigcnt sigclp;
        leavesnt <- rcons leavesnt leaveslp;
        rootsnt <- rcons rootsnt (nth witness (nth witness nodes (h' - 1)) 0);
      }
      pkWOTStd <- rcons pkWOTStd pkWOTSnt;
      sigWOTStd <- rcons sigWOTStd sigcnt;
      leavestd <- rcons leavestd leavesnt;
      rootstd <- rcons rootstd rootsnt;
    }
  }

  proc forge(ps : pseed) : int * msgWOTS * (sigWOTS * cntr) = {
    var m : msgFLSLXMSSMTTW;
    var sigc, sigc' : sigWOTS * cntr;
    var pkWOTS, pkWOTS' : pkWOTS;
    var ap, ap' : apFLXMSSTW;
    var sapl : sigFLSLXMSSMTTWC;
    var sig : sigFLSLXMSSMTTWC;
    var sigl : sigFLSLXMSSMTTWC list;
    var m' : msgFLSLXMSSMTTW;
    var sig' : sigFLSLXMSSMTTWC;
    var idx' : index;
    var root, root' : dgstblock;
    var tidx, kpidx : int;
    var tkpidxs : (int * int) list;
    var leaf' : dgstblock;
    var leaves : dgstblock list;
    var cidx, fidx : int;
    var pkWOTSs, pkWOTSs' : pkWOTS list;
    var rootss, rootss' : dgstblock list;
    var okC : bool;

    (* Sign adversary-chosen messages using computed leaves/(signatures,counters) *)
    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);

      sapl <- [];
      (tidx, kpidx) <- (size sigl, 0);
      while (size sapl < d) {
        (tidx, kpidx) <- edivz tidx l';

        sigc <- nth witness (nth witness (nth witness sigWOTStd (size sapl)) tidx) kpidx;

        leaves <- nth witness (nth witness leavestd (size sapl)) tidx;

        ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhxtype) (list2tree leaves) kpidx;

        sapl <- rcons sapl (sigc, ap);
      }

      sig <- sapl;
      sigl <- rcons sigl sig;
    }

    root <- nth witness (nth witness rootstd (d - 1)) 0;

    (* Ask adversary to provide a forgery (given public key and list of signatures) *)
    (m', sig', idx') <@ A(OC).forge((root, ps, ad), sigl);

    (tidx, kpidx) <- (Index.val idx', 0);
    root' <- m';
    tkpidxs <- [];
    pkWOTSs <- [];
    rootss <- [];
    pkWOTSs' <- [];
    rootss' <- [];
    while (size pkWOTSs' < d) {
      (tidx, kpidx) <- edivz tidx l';

      (sigc', ap') <- nth witness sig' (size pkWOTSs');

      (pkWOTS', okC) <@ FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C(root', sigc'.`1, sigc'.`2, ps,
                          (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) chtype) kpidx));
      pkWOTS <- nth witness (nth witness (nth witness pkWOTStd (size pkWOTSs')) tidx) kpidx;

      leaf' <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) pkcotype) kpidx)
                    (flatten (map DigestBlock.val (DBLL.val pkWOTS')));

      root' <- val_ap_trh ps (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) trhxtype) ap' kpidx leaf';
      root <- nth witness (nth witness rootstd (size pkWOTSs')) tidx;

      tkpidxs <- rcons tkpidxs (tidx, kpidx);
      pkWOTSs <- rcons pkWOTSs pkWOTS;
      rootss <- rcons rootss root;
      pkWOTSs' <- rcons pkWOTSs' pkWOTS';
      rootss' <- rcons rootss' root';
    }

    (* Find (first) index where the elements constitute a WOTS+C forgery *)
    cidx <- find (fun (x : ((_ *  _) * _) * _) => x.`1.`1.`1 = x.`1.`1.`2 /\ x.`1.`2 <> x.`2)
                 (zip (zip (zip pkWOTSs' pkWOTSs) (m' :: rootss')) (nth witness ml (Index.val idx') :: rootss));

    (tidx, kpidx) <- nth witness tkpidxs cidx;

    fidx <- StdBigop.Bigint.BIA.bigi predT (fun i => nr_trees i) 0 cidx * l' + tidx * l' + kpidx;

    root' <- nth witness (m' :: rootss') cidx;
    sigc' <- (nth witness sig' cidx).`1;

    return (fidx, root', sigc');
  }
}.

(* ==========================================================================
   STEP 5: A_wf_MA DISCHARGE FOR THE LEAF REDUCTION (the integration payoff).

   `interactive_D1_MA` (WOTS_C_Interactive.ec:2727) carries the member-aware
   S-TCR premise
     A_wf_MA :  hoare[ R_int_STCRC(A,..,O_THFC_MA).pick :
                         O_THFC_MA.tws_ma = [] ==>
                         all (fun p => p.`1 <> dfC) O_THFC_MA.tws_ma ]
   Here we discharge it for A := R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht).  Every entry
   the run records in `O_THFC_MA.tws_ma` comes from one of three sources, and each
   sits at a member `<> dfC`:

     (i)   the S-TCR reduction's OWN chain walk in `R_int_STCRC.O_wrap.query`
           (member 8n; `owrap_query_neq_dfC` below, cf. `owrap_chainwalk_member8n`);
     (ii)  the leaf reduction's OWN `pkco` / `trh` collection queries (members
           8n*len and 8n*2; `size_pkco_input` / `size_trh_input` + `othfcma_query_neq`);
     (iii) A_ht's OWN direct collection queries (threaded well-formedness hypothesis
           `A_wf_ht` — A_ht never opens the challenged member `dfC`; NECESSARY, see
           the negative control `A_ht_dfC_breaks_wf` at the end).

   The three member-separation FLAG facts (`dfC <> 8n`, `dfC <> 8n*len`,
   `dfC <> 8n*2`; WOTS_C_Interactive.ec:2013-2020) close (i)+(ii); the hypothesis
   closes (iii).  This is precisely the member-aware payoff: the leaf reduction's
   pkco tweak coincides with a ThC target tweak, but sits at a DIFFERENT member, so
   the member-tagged transcript stays `dfC`-free.
   -------------------------------------------------------------------------- *)

(* ---- (ii.a) the pkco collection input has member 8n*len. ---- *)
lemma size_pkco_input (pk : pkWOTS) :
  size (flatten (map DigestBlock.val (DBLL.val pk))) = 8 * n * len.
proof.
rewrite size_flatten -map_comp StdBigop.Bigint.sumzE /= StdBigop.Bigint.BIA.big_map /(\o) /predT /= -/predT.
rewrite (StdBigop.Bigint.BIA.eq_bigr _ _ (fun (_ : DigestBlock.sT) => 8 * n)) 1:/=.
+ by move=> ? _; rewrite DigestBlock.valP.
by rewrite StdBigop.Bigint.big_constz count_predT; smt(DBLL.valP).
qed.

(* ---- (ii.b) the trh collection input has member 8n*2. ---- *)
lemma size_trh_input (a b : dgstblock) :
  size (DigestBlock.val a ++ DigestBlock.val b) = 8 * n * 2.
proof. by rewrite size_cat !DigestBlock.valP /#. qed.

(* ---- The member-aware collection oracle preserves the `<> dfC` invariant on any
        query whose input length is a fixed member `df0 <> dfC`. ---- *)
lemma othfcma_query_neq (df0 : int) :
  dfC <> df0 =>
  hoare[ O_THFC_MA.query :
           size x = df0 /\ all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma
           ==> all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma ].
proof.
move=> hdf; proc; auto => />; smt(mem_rcons allP).
qed.

(* ---- (i) the S-TCR reduction's chain walk records only member 8n. ----
   `<> dfC` twin of `owrap_chainwalk_member8n` (WOTS_C_Interactive.ec:2764):
   every entry `O_wrap.query` adds sits at member `size (DigestBlock.val _) = 8n`,
   and `dfC <> 8n` makes it `<> dfC`. *)
lemma owrap_query_neq_dfC
  (A <: Adv_MEUFGCMA_WOTSC{-R_int_STCRC, -O_MEUFGCMA_WOTSC_Default,
                           -STCRC_WC.O_STCRC_Default, -O_THFC_MA}) :
  dfC <> 8 * n =>
  hoare[ R_int_STCRC(A, STCRC_WC.O_STCRC_Default, O_THFC_MA).O_wrap.query :
           all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma
           ==> all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma ].
proof.
move=> hdf; proc.
inline O_THFC_MA.query STCRC_WC.O_STCRC_Default.query.
wp.
while (all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma).
+ wp.
  while (all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma).
  + wp; skip => />; smt(allP mem_rcons DigestBlock.valP).
  wp.
  while (all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma).
  + wp; skip => />; smt(allP mem_rcons DigestBlock.valP).
  wp; skip => />.
auto => />.
qed.

lemma R_leaf_C_A_wf_MA
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{-R_int_STCRC, -O_MEUFGCMA_WOTSC_Default,
                          -STCRC_WC.O_STCRC_Default, -O_THFC_MA, -R_MEUFGCMAWOTSC_EUFNAGCMA_C}) :
  dfC <> 8 * n =>
  dfC <> 8 * n * len =>
  dfC <> 8 * n * 2 =>
  hoare[ A_ht(O_THFC_MA).choose :
           O_THFC_MA.tws_ma = [] ==>
           all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma ] =>
  hoare[ R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht), STCRC_WC.O_STCRC_Default, O_THFC_MA).pick :
           O_THFC_MA.tws_ma = [] ==>
           all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma ].
proof.
move=> hdf8n hdflen hdf2 A_wf_ht.
proc.
seq 1 : (O_THFC_MA.tws_ma = []).
+ inline R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht), STCRC_WC.O_STCRC_Default, O_THFC_MA).O_wrap.init; auto.
inline R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht, R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht), STCRC_WC.O_STCRC_Default, O_THFC_MA).O_wrap, O_THFC_MA).choose.
seq 1 : (all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma).
+ call A_wf_ht; skip => />.
(* Cube-building preserves the `<> dfC` invariant: signing queries record member
   8n (O_wrap chain walk), pkco queries member 8n*len, trh queries member 8n*2. *)
while (all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma).            (* L1: layers *)
+ wp.
  while (all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma).          (* L2: inner trees *)
  + wp.
    while (all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma).        (* L4: tree layers *)
    + wp.
      while (all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma).      (* L5: nodes -> trh *)
      + wp.
        call (othfcma_query_neq (8 * n * 2) hdf2).
        wp; skip => />; smt(size_trh_input).
      wp; skip => />.
    wp.
    while (all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma).        (* L3: leaves -> sign + pkco *)
    + seq 2 : (all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma).
      + call (owrap_query_neq_dfC (R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)) hdf8n); auto.
      wp; call (othfcma_query_neq (8 * n * len) hdflen); skip => />; smt(size_pkco_input).
    wp; skip => />.
  wp; skip => />.
auto => />.
qed.

(* --------------------------------------------------------------------------
   NON-VACUITY OF THE A_ht WELL-FORMEDNESS HYPOTHESIS (negative control).

   The threaded hypothesis `A_wf_ht` in `R_leaf_C_A_wf_MA` is a GENUINE constraint
   on A_ht, not a tautology.  An A_ht that issues a single collection query on a
   `dfC`-sized input (`emb_in witness`, whose length is `dfC` BY DEFINITION,
   WOTS_C_Interactive.ec:402) DETERMINISTICALLY records member `dfC`, so the
   well-formedness postcondition `all (p.`1 <> dfC) tws_ma` is FALSE for it.  Thus
   `R_leaf_C_A_wf_MA` is not vacuously satisfiable: the hypothesis carries exactly
   the member-separation content the member-aware S-TCR bound rests on, and an
   ill-formed A_ht (one that opens the challenged member) is genuinely excluded.
   -------------------------------------------------------------------------- *)
module A_ht_dfC (OC : FSSLXMTWES.TRHC.Oracle_THFC) = {
  proc choose() : msgFLSLXMSSMTTW list = {
    var y : dgstblock;
    y <@ OC.query(witness, emb_in witness);   (* size (emb_in witness) = dfC *)
    return [];
  }

  proc forge(pk : pkFLSLXMSSMTTW, sigl : sigFLSLXMSSMTTWC list)
       : msgFLSLXMSSMTTW * sigFLSLXMSSMTTWC * index = {
    return witness;
  }
}.

(* The bad adversary DETERMINISTICALLY violates the well-formedness postcondition:
   after its single dfC-membered query, `tws_ma` is not `dfC`-free.  This witnesses
   that the `A_wf_ht` premise is unsatisfiable for `A_ht_dfC`, i.e. `R_leaf_C_A_wf_MA`
   would not apply to it -- the hypothesis is load-bearing, not vacuous. *)
lemma A_ht_dfC_breaks_wf :
  hoare[ A_ht_dfC(O_THFC_MA).choose :
           O_THFC_MA.tws_ma = [] ==>
           ! all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma ].
proof.
proc; inline O_THFC_MA.query; auto => />; rewrite /dfC //.
qed.

(* ==========================================================================
   THE INTEGRATION POINT: the leaf reduction plugs into `interactive_D1_MA`.

   Instantiating the composable member-aware interactive Thm D.1
   (WOTS_C_Interactive.ec:2727) with A := R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht) and
   DISCHARGING its `A_wf_MA` premise via `R_leaf_C_A_wf_MA` above yields: the WOTS+C
   d-EU-GCMA game for the leaf reduction is bounded by the REAL MM45 WOTS-TW
   M-EUF-GCMA game plus the member-aware interactive S-TCR(+C) term.  This is the
   critical integration -- the +C-specific leaf reduction composing with the
   already-done WOTS+C interactive theorem, with the member-separation side-
   condition (the whole reason the member-aware foundation exists) discharged
   cleanly by pkco/trh/f-vs-dfC separation.  0-admit.

   SCOPE / OPEN GAPS (honesty -- this bound is CONDITIONAL, and not the full
   leaf-reduction soundness):

     * PREMISE SET.  The bound rests on ALL of:
         { c <= p_tgts, embdisj, embinj, encb,
           dfC <> 8n, dfC <> 8n*len, dfC <> 8n*2, A_wf_ht }.
       The first four + three FLAG facts are the same threaded hypotheses the
       interactive foundation already carries.  What is PROVEN new here is the
       member characterization of R_leaf_C's OWN transcript (chain-walk 8n / pkco
       8n*len / trh 8n*2, all <> dfC) and the composition; the hypotheses are NOT
       discharged.

     * `A_wf_ht` IS A CARRIED PREMISE ON A_ht — and this is FAITHFUL TO MM45, not a
       defect (verified against MM45 source, 2026-07-18).  It is the +C ANALOG of
       MM45's OWN shipped premise: MM45's XMSS-MT COMPONENT theorem
       `EUFNAGCMA_FLSLXMSSMTTWESNPRF` (FL_SL_XMSS_MT_ES.ec:6306) LITERALLY carries
       three `hoare[A.choose : ads=[] ==> all(ad => get_typeidx ad <> {chtype|
       pkcotype|trhtype}) ads]` premises — i.e. "the hypertree adversary never opens
       the target address TYPE."  MM45's isolated WOTS-TW theorem (:6269) is
       premise-free only because `disj_wgpidxs` is baked into its game WIN condition;
       MM45 does NOT reroute A's OC queries.  MM45 DISCHARGES the three premises only
       at the TOP SPHINCS+ theorem (SPHINCS_PLUS.ec:4338, no such premises), where the
       hypertree adversary is the CONTROLLED reduction image
       `R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A)` whose OC queries structurally avoid
       the target types.  Our `A_wf_ht` is the SAME KIND of premise on a DIFFERENT
       separation AXIS: input-LENGTH (`member <> dfC`) rather than TYPE (`<> pkcotype`),
       because Th+C sits at `pkcotype` per the DEPLOYED FIRMWARE's input-structure
       domain-separation (sphincs-c10 hash.rs:wots_digest) — NOT a distinct type.  So
       "A_wf not dischargeable for ARBITRARY A_ht" is a NON-ISSUE: arbitrary A_ht never
       arises in composition, exactly as MM45's arbitrary hypertree adversary never
       arises.  DEFERRED (future capstone-interactive integration, replicating MM45's
       :4338 discharge; should go through since the reduction-image adv's OC queries
       structurally avoid member dfC, Th+C being routed via the challenge O): the
       discharge of `A_wf_ht` for the reduction-image adversary.  The negative control
       `A_ht_dfC_breaks_wf` confirms the premise is load-bearing (like MM45's H_pkco).

     * D1-COMPOSITION LEG ONLY.  This bounds `M_EUF_GCMA_WOTSC_NPRF(R_leaf_C(A_ht))`,
       NOT `EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A_ht)`.  The reduction-SOUNDNESS direction
       (a hypertree forgery yields a WOTS+C forgery, i.e. `forge` selection
       correctness) is DEFERRED: `forge` here is type-correct + MM45-faithful in
       structure but its selection correctness is unproven.  So the leaf reduction
       is NOT yet sound end-to-end. *)
lemma leaf_reduction_MEUFGCMAWOTSC_bound
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C }) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (a b : adrs),
       get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b) => get_wgpidxs a = get_wgpidxs b) =>
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC <> 8 * n =>
    dfC <> 8 * n * len =>
    dfC <> 8 * n * 2 =>
    hoare[ A_ht(O_THFC_MA).choose :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma ] =>
    Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
                             O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                         STCRC_WC.O_STCRC_Default).main() @ &m : res].
proof.
move=> hc hembdisj hembinj hencb hdf8n hdflen hdf2 A_wf_ht.
apply (interactive_D1_MA (R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)) &m hc hembdisj hembinj hencb).
by apply (R_leaf_C_A_wf_MA A_ht hdf8n hdflen hdf2 A_wf_ht).
qed.


(* ==========================================================================
   The +C instrumented collision game  EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.

   Port of MM45's local `EUF_NAGCMA_FLSLXMSSMTTWESNPRF_C`
   (FV-SPHINCSPLUS-EC/proofs/FL_SL_XMSS_MT_ES.ec:3054-3277): EUF-NAGCMA of the
   WOTS+C hypertree with INLINED keygen + validity check, PLUS the three
   instrumentation flags (WOTS+C M-EUF-GCMA forgery / pkco SM-DT-TCR-C collision
   / trh SM-DT-TCR-C collision). Parameterized over (A, OC) in the ABSTRACT-OC
   style of XMSSMT_C_Reduction.ec:208 (NOT MM45's concrete O_THFC_Default).

   +C deltas vs MM45 (else byte-for-byte, modulo the trhtype -> trhxtype clone):
     * sig type sigFLSLXMSSMTTW -> sigFLSLXMSSMTTWC (plain list; size-d enforced
       by the aliased +C verify);
     * encode site (MM45:3146): the per-leaf counter is GROUND-GRINDED (grindC)
       and encoded via encode_msgWOTS_C, both at the WOTS keypair chtype address;
     * counters carried in a PARALLEL counterstd cube (layer/tree/leaf), bundled
       into each hypertree sig element as ((sigWOTS, counter), ap);
     * forgery per-layer reconstruction via +C pkWOTS_from_sigWOTS_C (re-derives
       pk from (root, sigWOTS, counter) AND evaluates okC -- okC is discarded by
       the flags, which is exactly the counter-independence the seam relies on);
     * the 3 collision flags are VERBATIM MM45 (:3268-3273) -- they name only
       pkWOTSs'/pkWOTSs, m'/rootss'/rootss, leavess'/leavess: counter-INDEPENDENT.
   Compiles 0-error against XMSSMT_C_Reduction.ec's context; the MM45 _V pattern
   `import var EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C(A, OC)` also compiles (flags
   reachable unqualified), so the functor-global flag carrier is seam-ready.
   ========================================================================== *)
module EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C
  (A : Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF, OC : FSSLXMTWES.TRHC.Oracle_THFC) = {
  var valid_WOTSTWES, valid_TCRPKCO, valid_TCRTRH : bool

  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pk : pkFLSLXMSSMTTW;
    var ml : msgFLSLXMSSMTTW list;
    var sigl : sigFLSLXMSSMTTWC list;
    var m, m' : msgFLSLXMSSMTTW;
    var sig, sig' : sigFLSLXMSSMTTWC;
    var idx' : index;
    var is_valid, is_fresh : bool;
    var em : EmsgWOTS.emsgWOTS;
    var em_ele : int;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var pkWOTS_ele : dgstblock;
    var pkWOTS : dgstblock list;
    var pkWOTSlp : pkWOTS list;
    var pkWOTSnt : pkWOTS list list;
    var pkWOTStd : pkWOTS list list list;
    var sigWOTS_ele : dgstblock;
    var sigWOTS : dgstblock list;
    var sigWOTSlp : sigWOTS list;
    var sigWOTSnt : sigWOTS list list;
    var sigWOTStd : sigWOTS list list list;
    var counter : cntr;
    var counterlp : cntr list;
    var counternt : cntr list list;
    var counterstd : cntr list list list;
    var counterins : cntr;
    var leaf, leaf' : dgstblock;
    var leaves, leaveslp : dgstblock list;
    var leavesnt : dgstblock list list;
    var leavestd : dgstblock list list list;
    var root, root' : dgstblock;
    var rootsnt, rootsntp : dgstblock list;
    var rootstd : dgstblock list list;
    var sapl : sigFLSLXMSSMTTWC;
    var ap, ap' : apFLXMSSTW;
    var sigc' : sigWOTS * cntr;
    var sigWOTSins : sigWOTS;
    var pkWOTS', pkWOTSins : pkWOTS;
    var okC : bool;
    var tidx, kpidx : int;
    var tkpidxs : (int * int) list;
    var pkWOTSs, pkWOTSs' : pkWOTS list;
    var leavess, leavess' : dgstblock list;
    var rootss, rootss' : dgstblock list;

    (* Initialize address and public seed *)
    ad <- adz;
    ps <$ dpseed;

    (* Initialize collection oracle (abstract OC) *)
    OC.init(ps);

    (* Ask adversary for the list of messages to sign (A queries OC directly) *)
    ml <@ A(OC).choose();

    (* Inlined keygen: compute/store the full WOTS+C cube (public keys,
       signatures, per-leaf +C counters), (inner tree) leaves, and roots. *)
    skWOTStd <- [];
    pkWOTStd <- [];
    sigWOTStd <- [];
    counterstd <- [];
    leavestd <- [];
    rootstd <- [];
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      pkWOTSnt <- [];
      sigWOTSnt <- [];
      counternt <- [];
      leavesnt <- [];
      rootsnt <- [];
      rootsntp <- last ml rootstd;
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        pkWOTSlp <- [];
        sigWOTSlp <- [];
        counterlp <- [];
        leaveslp <- [];
        while (size skWOTSlp < l') {
          (* Get the to-be-signed root, GRIND the +C counter at the WOTS keypair
             (chtype) address, and encode via Th+C. *)
          root <- nth witness rootsntp (size skWOTSnt * l' + size skWOTSlp);
          counter <- grindC ps (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) root;
          em <- encode_msgWOTS_C ps (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) root counter;

          skWOTS <- [];
          pkWOTS <- [];
          sigWOTS <- [];
          (* For each element of the WOTS+C artifacts... *)
          while (size skWOTS < len) {
            em_ele <- BaseW.val em.[size skWOTS];

            (* Sample a skWOTS element *)
            skWOTS_ele <$ ddgstblock;

            sigWOTS_ele <- cf ps (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) (size skWOTS))
                              0 em_ele (DigestBlock.val skWOTS_ele);

            pkWOTS_ele <- cf ps (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) (size skWOTS))
                             em_ele (w - 1 - em_ele) (DigestBlock.val sigWOTS_ele);

            skWOTS <- rcons skWOTS skWOTS_ele;
            pkWOTS <- rcons pkWOTS pkWOTS_ele;
            sigWOTS <- rcons sigWOTS sigWOTS_ele;
          }

          leaf <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) pkcotype) (size skWOTSlp)) (flatten (map DigestBlock.val pkWOTS));

          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
          pkWOTSlp <- rcons pkWOTSlp (DBLL.insubd pkWOTS);
          sigWOTSlp <- rcons sigWOTSlp (DBLL.insubd sigWOTS);
          counterlp <- rcons counterlp counter;
          leaveslp <- rcons leaveslp leaf;
        }

        root <- val_bt_trh ps (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) trhxtype)
                           (list2tree leaveslp);

        skWOTSnt <- rcons skWOTSnt skWOTSlp;
        pkWOTSnt <- rcons pkWOTSnt pkWOTSlp;
        sigWOTSnt <- rcons sigWOTSnt sigWOTSlp;
        counternt <- rcons counternt counterlp;
        leavesnt <- rcons leavesnt leaveslp;
        rootsnt <- rcons rootsnt root;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
      pkWOTStd <- rcons pkWOTStd pkWOTSnt;
      sigWOTStd <- rcons sigWOTStd sigWOTSnt;
      counterstd <- rcons counterstd counternt;
      leavestd <- rcons leavestd leavesnt;
      rootstd <- rcons rootstd rootsnt;
    }

    root <- nth witness (nth witness rootstd (d - 1)) 0; (* Root of hypertree is the last computed root *)

    pk <- (root, ps, ad);

    (* Sign (up to l) messages: assemble hypertree signatures from the cube,
       bundling ((sigWOTS, counter), ap) per layer. *)
    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);

      sapl <- [];
      (tidx, kpidx) <- (size sigl, 0);
      while (size sapl < d) {
        (tidx, kpidx) <- edivz tidx l';

        sigWOTSins <- nth witness (nth witness (nth witness sigWOTStd (size sapl)) tidx) kpidx;
        counterins <- nth witness (nth witness (nth witness counterstd (size sapl)) tidx) kpidx;

        leaves <- nth witness (nth witness leavestd (size sapl)) tidx;

        ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhxtype) (list2tree leaves) kpidx;

        sapl <- rcons sapl ((sigWOTSins, counterins), ap);
      }

      sig <- sapl;
      sigl <- rcons sigl sig;
    }

    (* Ask adversary to provide a forgery (given public key and list of signatures) *)
    (m', sig', idx') <@ A(OC).forge(pk, sigl);

    is_valid <@ FL_SL_XMSS_MT_C_ES_NPRF.verify(pk, m', sig', idx');

    is_fresh <- m' <> nth witness ml (Index.val idx');

    (tidx, kpidx) <- (Index.val idx', 0);
    root' <- m';
    tkpidxs <- [];
    pkWOTSs <- [];
    leavess <- [];
    rootss <- [];
    pkWOTSs' <- [];
    leavess' <- [];
    rootss' <- [];
    (*
      For each WOTS+C signature/authentication path pair in the forgery, reconstruct
      the WOTS+C public key from the previous root (first one being the forgery's
      message) AND the carried counter, compress it to a leaf, and derive the next
      root from the authentication path. Track intermediate pks, leaves, roots, idxs.
    *)
    while (size pkWOTSs' < d) {
      (tidx, kpidx) <- edivz tidx l';

      (sigc', ap') <- nth witness sig' (size pkWOTSs');

      (pkWOTS', okC) <@ FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C(root', sigc'.`1, sigc'.`2, ps,
                          (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) chtype) kpidx));
      pkWOTSins <- nth witness (nth witness (nth witness pkWOTStd (size pkWOTSs')) tidx) kpidx;

      leaf' <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) pkcotype) kpidx)
                    (flatten (map DigestBlock.val (DBLL.val pkWOTS')));
      leaf <- nth witness (nth witness (nth witness leavestd (size pkWOTSs')) tidx) kpidx;

      root' <- val_ap_trh ps (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) trhxtype) ap' kpidx leaf';
      root <- nth witness (nth witness rootstd (size pkWOTSs')) tidx;

      tkpidxs <- rcons tkpidxs (tidx, kpidx);
      pkWOTSs <- rcons pkWOTSs pkWOTSins;
      rootss <- rcons rootss root;
      leavess <- rcons leavess leaf;
      pkWOTSs' <- rcons pkWOTSs' pkWOTS';
      rootss' <- rcons rootss' root';
      leavess' <- rcons leavess' leaf';
    }

    valid_WOTSTWES <- exists (i : int), 0 <= i < d /\ nth witness pkWOTSs' i = nth witness pkWOTSs i
                                                   /\ nth witness (m' :: rootss') i <> nth witness (nth witness ml (Index.val idx') :: rootss) i;
    valid_TCRPKCO <- exists (i : int), 0 <= i < d /\ nth witness leavess' i = nth witness leavess i
                                                  /\ nth witness pkWOTSs' i <> nth witness pkWOTSs i;
    valid_TCRTRH <- exists (i : int), 0 <= i < d /\ nth witness (m' :: rootss') (i + 1) = nth witness (nth witness ml (Index.val idx') :: rootss) (i + 1)
                                                 /\ nth witness leavess' i <> nth witness leavess i;

    return is_valid /\ is_fresh;
  }
}.

(* EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V : the +C "V" game -- validity-check INLINED,
   instrumented with the 3 collision flags. +C port of MM45's
   EUF_NAGCMA_FLSLXMSSMTTWESNPRF_V (FL_SL_XMSS_MT_ES.ec:3285-3507), in the
   section-free abstract-(A,OC) functor style of this file (:208).
   REQUIRES in scope: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF (:202) and the peer C game
   EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C (A)(OC) declaring the 3 flag module-vars
   `valid_WOTSTWES, valid_TCRPKCO, valid_TCRTRH : bool`.
   V reuses C's state = ONLY those 3 globals, via `import var`. Sole C->V delta:
   is_valid is inlined (not FL_SL_XMSS_MT_C_ES_NPRF.verify) and, being the +C verify
   body (XMSSMT_C_Scheme.ec:211) `size sig' = d /\ root-match /\ allOkC`, V additionally
   accumulates `allOkC <- allOkC /\ okC` in the reconstruction loop (C discards okC).
   Body type-checks EXIT=0 (EC r2026.02) vs the real drafts with a flag-only C stub;
   compile does NOT prove Eqv_C_V (prover role, via helpers :416 + :408). *)
module EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V (A : Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF) (OC : FSSLXMTWES.TRHC.Oracle_THFC) = {
  import var EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C

  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pk : pkFLSLXMSSMTTW;
    var ml : msgFLSLXMSSMTTW list;
    var sigl : sigFLSLXMSSMTTWC list;
    var m, m' : msgFLSLXMSSMTTW;
    var sig, sig' : sigFLSLXMSSMTTWC;
    var idx' : index;
    var is_valid, is_fresh : bool;
    var em : emsgWOTS;
    var em_ele : int;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var pkWOTS_ele : dgstblock;
    var pkWOTS : dgstblock list;
    var pkWOTSlp : pkWOTS list;
    var pkWOTSnt : pkWOTS list list;
    var pkWOTStd : pkWOTS list list list;
    var sigWOTS_ele : dgstblock;
    var sigWOTS : dgstblock list;
    var counter : cntr;
    var sigWOTSlp : (sigWOTS * cntr) list;
    var sigWOTSnt : (sigWOTS * cntr) list list;
    var sigWOTStd : (sigWOTS * cntr) list list list;
    var sigcins, sigc' : sigWOTS * cntr;
    var leaf, leaf' : dgstblock;
    var leaves, leaveslp : dgstblock list;
    var leavesnt : dgstblock list list;
    var leavestd : dgstblock list list list;
    var root, root' : dgstblock;
    var rootsnt, rootsntp : dgstblock list;
    var rootstd : dgstblock list list;
    var sapl : sigFLSLXMSSMTTWC;
    var ap, ap' : apFLXMSSTW;
    var pkWOTS', pkWOTSins : pkWOTS;
    var tidx, kpidx : int;
    var tkpidxs : (int * int) list;
    var pkWOTSs, pkWOTSs' : pkWOTS list;
    var leavess, leavess' : dgstblock list;
    var rootss, rootss' : dgstblock list;
    var okC, allOkC : bool;

    (* Initialize address and public seed *)
    ad <- adz;
    ps <$ dpseed;

    (* Initialize collection oracle *)
    OC.init(ps);

    (* Ask adversary for list of messages to sign *)
    ml <@ A(OC).choose();

    (* ---- INLINED NPRF keygen + honest (sig,counter) cube.  +C delta: per-leaf
            grind + Th+C encoding; the cube stores (sigWOTS, counter) pairs.
            (Byte-for-byte MM45 C/V keygen (:3123-3192) modulo trhtype->trhxtype
            and the three +C lines flagged below.) ---- *)
    skWOTStd <- [];
    pkWOTStd <- [];
    sigWOTStd <- [];
    leavestd <- [];
    rootstd <- [];
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      pkWOTSnt <- [];
      sigWOTSnt <- [];
      leavesnt <- [];
      rootsnt <- [];
      rootsntp <- last ml rootstd;
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        pkWOTSlp <- [];
        sigWOTSlp <- [];
        leaveslp <- [];
        while (size skWOTSlp < l') {
          (* to-be-signed root at this leaf *)
          root <- nth witness rootsntp (size skWOTSnt * l' + size skWOTSlp);

          (* +C (1): grind the counter and (2) encode via Th+C, at the WOTS
             keypair (chtype) address -- exactly WOTS_C_ES.sign (WOTS_C_Scheme.ec:56-57). *)
          counter <- grindC ps (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) root;
          em <- encode_msgWOTS_C ps (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) root counter;

          skWOTS <- [];
          pkWOTS <- [];
          sigWOTS <- [];
          while (size skWOTS < len) {
            em_ele <- BaseW.val em.[size skWOTS];

            skWOTS_ele <$ ddgstblock;

            sigWOTS_ele <- cf ps (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype)
                                                       (size skWOTSlp)) (size skWOTS))
                              0 em_ele (DigestBlock.val skWOTS_ele);

            pkWOTS_ele <- cf ps (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) (size skWOTS))
                             em_ele (w - 1 - em_ele) (DigestBlock.val sigWOTS_ele);

            skWOTS <- rcons skWOTS skWOTS_ele;
            pkWOTS <- rcons pkWOTS pkWOTS_ele;
            sigWOTS <- rcons sigWOTS sigWOTS_ele;
          }

          leaf <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) pkcotype) (size skWOTSlp)) (flatten (map DigestBlock.val pkWOTS));

          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
          pkWOTSlp <- rcons pkWOTSlp (DBLL.insubd pkWOTS);
          (* +C (3): the cube element carries the ground counter. *)
          sigWOTSlp <- rcons sigWOTSlp (DBLL.insubd sigWOTS, counter);
          leaveslp <- rcons leaveslp leaf;
        }

        root <- val_bt_trh ps (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) trhxtype)
                           (list2tree leaveslp);

        skWOTSnt <- rcons skWOTSnt skWOTSlp;
        pkWOTSnt <- rcons pkWOTSnt pkWOTSlp;
        sigWOTSnt <- rcons sigWOTSnt sigWOTSlp;
        leavesnt <- rcons leavesnt leaveslp;
        rootsnt <- rcons rootsnt root;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
      pkWOTStd <- rcons pkWOTStd pkWOTSnt;
      sigWOTStd <- rcons sigWOTStd sigWOTSnt;
      leavestd <- rcons leavestd leavesnt;
      rootstd <- rcons rootstd rootsnt;
    }

    root <- nth witness (nth witness rootstd (d - 1)) 0;
    pk <- (root, ps, ad);

    (* ---- INLINED honest signing: assemble the plain sigFLSLXMSSMTTWC list from
            the precomputed (sig,counter) cube + fresh auth paths.  +C: plain list
            (no size-d subtype), signature element (sigcins, ap). ---- *)
    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);

      sapl <- [];
      (tidx, kpidx) <- (size sigl, 0);
      while (size sapl < d) {
        (tidx, kpidx) <- edivz tidx l';

        sigcins <- nth witness (nth witness (nth witness sigWOTStd (size sapl)) tidx) kpidx;

        leaves <- nth witness (nth witness leavestd (size sapl)) tidx;

        ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhxtype) (list2tree leaves) kpidx;

        sapl <- rcons sapl (sigcins, ap);
      }

      sig <- sapl;
      sigl <- rcons sigl sig;
    }

    (* Ask adversary to provide a forgery (given public key and list of signatures) *)
    (m', sig', idx') <@ A(OC).forge(pk, sigl);

    is_fresh <- m' <> nth witness ml (Index.val idx');

    (* ---- INLINED validity reconstruction + the 3 collision-flag instrumentation.
            +C: pkWOTS_from_sigWOTS_C returns (pkWOTS', okC); V ACCUMULATES allOkC
            (this is the C->V delta beyond MM45's byte-identical loops). ---- *)
    (tidx, kpidx) <- (Index.val idx', 0);
    root' <- m';
    allOkC <- true;
    tkpidxs <- [];
    pkWOTSs <- [];
    leavess <- [];
    rootss <- [];
    pkWOTSs' <- [];
    leavess' <- [];
    rootss' <- [];
    while (size pkWOTSs' < d) {
      (tidx, kpidx) <- edivz tidx l';

      (sigc', ap') <- nth witness sig' (size pkWOTSs');

      (pkWOTS', okC) <@ FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C(root', sigc'.`1, sigc'.`2, ps,
                          (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) chtype) kpidx));
      allOkC <- allOkC /\ okC;
      pkWOTSins <- nth witness (nth witness (nth witness pkWOTStd (size pkWOTSs')) tidx) kpidx;

      leaf' <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) pkcotype) kpidx)
                    (flatten (map DigestBlock.val (DBLL.val pkWOTS')));
      leaf <- nth witness (nth witness (nth witness leavestd (size pkWOTSs')) tidx) kpidx;

      root' <- val_ap_trh ps (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) trhxtype) ap' kpidx leaf';
      root <- nth witness (nth witness rootstd (size pkWOTSs')) tidx;

      tkpidxs <- rcons tkpidxs (tidx, kpidx);
      pkWOTSs <- rcons pkWOTSs pkWOTSins;
      rootss <- rcons rootss root;
      leavess <- rcons leavess leaf;
      pkWOTSs' <- rcons pkWOTSs' pkWOTS';
      rootss' <- rcons rootss' root';
      leavess' <- rcons leavess' leaf';
    }

    (* The 3 collision flags -- BYTE-FOR-BYTE MM45's V (:3496-3501) modulo
       val -> Index.val.  Counter-INDEPENDENT: they name only pkWOTS/root/leaf
       equalities, never a counter.  (Shared with C via import var.) *)
    valid_WOTSTWES <- exists (i : int), 0 <= i < d /\ nth witness pkWOTSs' i = nth witness pkWOTSs i
                                                   /\ nth witness (m' :: rootss') i <> nth witness (nth witness ml (Index.val idx') :: rootss) i;
    valid_TCRPKCO <- exists (i : int), 0 <= i < d /\ nth witness leavess' i = nth witness leavess i
                                                  /\ nth witness pkWOTSs' i <> nth witness pkWOTSs i;
    valid_TCRTRH <- exists (i : int), 0 <= i < d /\ nth witness (m' :: rootss') (i + 1) = nth witness (nth witness ml (Index.val idx') :: rootss) (i + 1)
                                                 /\ nth witness leavess' i <> nth witness leavess i;

    (* +C is_valid = the REAL FL_SL_XMSS_MT_C_ES.verify predicate (XMSSMT_C_Scheme.ec:211),
       inlined: size gate (replaces MM45's size-d subtype) + reconstructed-root match
       (MM45's sole check) + the accumulated d-layer +C constant-sum gate (NEW under +C). *)
    is_valid <-    size sig' = d
                /\ nth witness (m' :: rootss') d = nth witness (nth witness ml (Index.val idx') :: rootss) d
                /\ allOkC;

    return is_valid /\ is_fresh;
  }
}.

(* ==========================================================================
   O_V ORACLE-HOP (WOTS+C analog of MM45 EqPr_MEUFGCMAWOTSTWESNPRF_Orig_V,
   FL_SL_XMSS_MT_ES.ec:2840-3032 + the WOTS_TW_ES.ec:2915-3277 element-sampling
   intermediates).  The interactive whole-key signing oracle
   O_MEUFGCMA_WOTSC_Default (keygen: sample skWOTS<$dskWOTS then chain pk; sign:
   grind + encode + chain sig) is swapped for an ELEMENT-SAMPLING fused-loop oracle
   O_MEUFGCMA_WOTSC_V so the RHS per-element sampling aligns with the V-game's
   fused len-loop (V :1443-1458).  +C delta over MM45's O_V: grindC/encode_msgWOTS_C
   are DETERMINISTIC (zero oracle queries), computed pre-loop, so they commute with
   the element reindex; the sig element carries the ground counter.
   ========================================================================== *)
clone import DList.Program as DListSampleC with
  type t <- dgstblock,
    op d <- ddgstblock
    proof *.

module O_MEUFGCMA_WOTSC_V : Oracle_MEUFGCMA_WOTSC = {
  include var O_MEUFGCMA_WOTSC_Default [-query]

  proc query(wad : wadrs, m : msgWOTS) : pkWOTS * (sigWOTS * cntr) = {
    var skWOTS_ele : dgstblock;
    var pkWOTS : dgstblock list;
    var pkWOTS_ele : dgstblock;
    var sigWOTS : dgstblock list;
    var sigWOTS_ele : dgstblock;
    var em : emsgWOTS;
    var em_ele : int;
    var counter : cntr;

    counter <- grindC ps (WAddress.val wad) m;
    em <- encode_msgWOTS_C ps (WAddress.val wad) m counter;

    pkWOTS <- [];
    sigWOTS <- [];
    while (size pkWOTS < len) {
      em_ele <- BaseW.val em.[size pkWOTS];

      skWOTS_ele <$ ddgstblock;

      sigWOTS_ele <- cf ps (set_chidx (WAddress.val wad) (size pkWOTS)) 0 em_ele (DigestBlock.val skWOTS_ele);
      pkWOTS_ele <- cf ps (set_chidx (WAddress.val wad) (size pkWOTS)) em_ele (w - 1 - em_ele) (DigestBlock.val sigWOTS_ele);

      pkWOTS <- rcons pkWOTS pkWOTS_ele;
      sigWOTS <- rcons sigWOTS sigWOTS_ele;
    }

    qs <- rcons qs (WAddress.val wad, m, DBLL.insubd pkWOTS, (DBLL.insubd sigWOTS, counter));

    return (DBLL.insubd pkWOTS, (DBLL.insubd sigWOTS, counter));
  }
}.

(* Intermediate oracle (MM45 O_MEUFGCMA_WOTSTWESNPRF_DMSDLP.query_dlp analog,
   FL_SL_XMSS_MT_ES.ec:2803): samples the whole key as a DList.Program `Sample.sample`
   list (enables Sample_LoopSnoc_eq), then two SEPARATE loops (pk via cf 0 (w-1), sig
   via cf 0 em_ele) exactly as the inlined O_Default (keygen pk-loop + sign sig-loop).
   +C: grindC/encode_msgWOTS_C prefix the sig-loop; the tuple carries the counter. *)
module O_MEUFGCMA_WOTSC_DLP = {
  import var O_MEUFGCMA_WOTSC_Default

  proc query_dlp(wad : wadrs, m : msgWOTS) : pkWOTS * (sigWOTS * cntr) = {
    var skWOTS : dgstblock list;
    var skWOTS_ele : dgstblock;
    var pkWOTS : dgstblock list;
    var pkWOTS_ele : dgstblock;
    var sigWOTS : dgstblock list;
    var sigWOTS_ele : dgstblock;
    var em : emsgWOTS;
    var em_ele : int;
    var counter : cntr;

    skWOTS <@ DListSampleC.Sample.sample(len);

    pkWOTS <- [];
    while (size pkWOTS < len) {
      skWOTS_ele <- nth witness skWOTS (size pkWOTS);
      pkWOTS_ele <- cf ps (set_chidx (WAddress.val wad) (size pkWOTS)) 0 (w - 1) (DigestBlock.val skWOTS_ele);
      pkWOTS <- rcons pkWOTS pkWOTS_ele;
    }

    counter <- grindC ps (WAddress.val wad) m;
    em <- encode_msgWOTS_C ps (WAddress.val wad) m counter;
    sigWOTS <- [];
    while (size sigWOTS < len) {
      skWOTS_ele <- nth witness skWOTS (size sigWOTS);
      em_ele <- BaseW.val em.[size sigWOTS];
      sigWOTS_ele <- cf ps (set_chidx (WAddress.val wad) (size sigWOTS)) 0 em_ele (DigestBlock.val skWOTS_ele);
      sigWOTS <- rcons sigWOTS sigWOTS_ele;
    }

    qs <- rcons qs (WAddress.val wad, m, DBLL.insubd pkWOTS, (DBLL.insubd sigWOTS, counter));

    return (DBLL.insubd pkWOTS, (DBLL.insubd sigWOTS, counter));
  }
}.

(* The query-level oracle-hop: whole-key keygen+sign ~ element-sampling fused loop.
   Two legs (MM45 splits into 3 via a DMap.Sample intermediate; we fold leg1+leg2 by
   the query_eq-style explicit `rnd DBLL.val DBLL.insubd` reindex,
   WOTS_C_Interactive.ec:891-907).  Leg A: O_Default ~ query_dlp (reindex dskWOTS ->
   ddgstblockl list).  Leg B: query_dlp ~ O_V (Sample_LoopSnoc + fuse pk/sig via ch_comp,
   MM45 :2928-3002). *)
equiv Eqv_O_MEUFGCMA_WOTSC_query_Orig_V :
  O_MEUFGCMA_WOTSC_Default.query ~ O_MEUFGCMA_WOTSC_V.query :
    ={O_MEUFGCMA_WOTSC_Default.ps, O_MEUFGCMA_WOTSC_Default.qs, arg}
    ==>
    ={O_MEUFGCMA_WOTSC_Default.ps, O_MEUFGCMA_WOTSC_Default.qs, res}.
proof.
transitivity O_MEUFGCMA_WOTSC_DLP.query_dlp
  (={O_MEUFGCMA_WOTSC_Default.ps, O_MEUFGCMA_WOTSC_Default.qs, arg}
   ==> ={O_MEUFGCMA_WOTSC_Default.ps, O_MEUFGCMA_WOTSC_Default.qs, res})
  (={O_MEUFGCMA_WOTSC_Default.ps, O_MEUFGCMA_WOTSC_Default.qs, arg}
   ==> ={O_MEUFGCMA_WOTSC_Default.ps, O_MEUFGCMA_WOTSC_Default.qs, res}) => [/# | // | |].
+ (* ---- Leg A: O_Default.query ~ query_dlp (reindex dskWOTS -> ddgstblockl list) ---- *)
  proc.
  inline{1} WOTS_C_ES.keygen WOTS_C_ES.sign WOTS_TW_ES_NPRF.keygen WOTS_TW_ES_NPRF.pkWOTS_from_skWOTS.
  inline{2} DListSampleC.Sample.sample.
  sp.
  (* couple the sample: dskWOTS = dmap ddgstblockl DBLL.insubd ~ dlist ddgstblock len *)
  seq 4 2 : (   ={O_MEUFGCMA_WOTSC_Default.ps, O_MEUFGCMA_WOTSC_Default.qs}
             /\ wad{1} = wad{2} /\ m{1} = m{2}
             /\ ps1{1} = O_MEUFGCMA_WOTSC_Default.ps{1}
             /\ ad1{1} = WAddress.val wad{1}
             /\ ps2{1} = O_MEUFGCMA_WOTSC_Default.ps{1}
             /\ ad2{1} = WAddress.val wad{1}
             /\ skWOTS1{1} = skWOTS0{1}
             /\ DBLL.val skWOTS0{1} = skWOTS{2}).
  + wp.
    rnd (fun (s : skWOTS) => DBLL.val s) (fun (l : dgstblock list) => DBLL.insubd l).
    skip => />.
    split=> [xlR xlRin | _].
    + by rewrite DBLL.insubdK //; smt(supp_dlist_size ge2_len).
    split=> [xlR xlRin | _].
    + rewrite /dskWOTS (dmap1E_can ddgstblockl DBLL.insubd DBLL.val (DBLL.insubd xlR)).
      * exact DBLL.valKd.
      * by move=> a ain; rewrite DBLL.insubdK //; smt(supp_dlist_size ge2_len).
      by rewrite DBLL.insubdK //; smt(supp_dlist_size ge2_len).
    move=> skv skvin.
    have skvsupp : DBLL.val skv \in ddgstblockl.
    + move: skvin; rewrite /dskWOTS supp_dmap => -[a [ain ->]].
      by rewrite DBLL.insubdK //; smt(supp_dlist_size ge2_len).
    split; first exact skvsupp.
    by move=> _; rewrite DBLL.valKd.
  (* pk-loop *)
  seq 2 2 : (   ={O_MEUFGCMA_WOTSC_Default.ps, O_MEUFGCMA_WOTSC_Default.qs}
             /\ wad{1} = wad{2} /\ m{1} = m{2}
             /\ ps1{1} = O_MEUFGCMA_WOTSC_Default.ps{1}
             /\ ad1{1} = WAddress.val wad{1}
             /\ skWOTS1{1} = skWOTS0{1}
             /\ DBLL.val skWOTS0{1} = skWOTS{2}
             /\ pkWOTS0{1} = pkWOTS{2}).
  + while (   ={O_MEUFGCMA_WOTSC_Default.ps}
           /\ wad{1} = wad{2}
           /\ ps2{1} = O_MEUFGCMA_WOTSC_Default.ps{1}
           /\ ad2{1} = WAddress.val wad{1}
           /\ DBLL.val skWOTS1{1} = skWOTS{2}
           /\ pkWOTS0{1} = pkWOTS{2}).
    - by wp; skip => />.
    by wp; skip => />.
  (* middle glue: {1}(7-14) deterministic, {2} nothing *)
  sp 8 0.
  (* grind + encode + sig<-[] *)
  seq 3 3 : (   ={O_MEUFGCMA_WOTSC_Default.ps, O_MEUFGCMA_WOTSC_Default.qs}
             /\ wad{1} = wad{2} /\ m{1} = m{2}
             /\ pkWOTS0{1} = pkWOTS{2}
             /\ ad0{1} = WAddress.val wad{1}
             /\ ps0{1} = O_MEUFGCMA_WOTSC_Default.ps{1}
             /\ DBLL.val skWOTS{1} = skWOTS{2}
             /\ em{1} = em{2}
             /\ counter{1} = counter{2}
             /\ sig{1} = sigWOTS{2}
             /\ pk{1}.`1 = DBLL.insubd pkWOTS{2}).
  + by wp; skip => />.
  (* sig-loop + qs + return *)
  wp.
  while (   ={O_MEUFGCMA_WOTSC_Default.ps}
         /\ wad{1} = wad{2}
         /\ ad0{1} = WAddress.val wad{1}
         /\ ps0{1} = O_MEUFGCMA_WOTSC_Default.ps{1}
         /\ em{1} = em{2}
         /\ DBLL.val skWOTS{1} = skWOTS{2}
         /\ sig{1} = sigWOTS{2}).
  + by wp; skip => />.
  by skip => /> /#.
(* ---- Leg B: query_dlp ~ O_V.query (Sample_LoopSnoc + fuse pk/sig via ch_comp,
   MM45 :2928-3002; +C: counter+encode_C prefix on {2}, seq 5 4 -> 5 5, counter in tuple) ---- *)
proc.
rewrite equiv[{1} 1 DListSampleC.Sample_LoopSnoc_eq].
inline{1} 1.
seq 5 5 : (   ={O_MEUFGCMA_WOTSC_Default.ps, O_MEUFGCMA_WOTSC_Default.qs}
           /\ wad{1} = wad{2} /\ m{1} = m{2}
           /\ counter{2} = grindC O_MEUFGCMA_WOTSC_Default.ps{2} (WAddress.val wad{2}) m{2}
           /\ em{2} = encode_msgWOTS_C O_MEUFGCMA_WOTSC_Default.ps{2} (WAddress.val wad{2}) m{2} counter{2}
           /\ pkWOTS{2}
              =
              mkseq (fun (i : int) =>
                      cf O_MEUFGCMA_WOTSC_Default.ps{2} (set_chidx (WAddress.val wad{2}) i) 0 (w - 1) (DigestBlock.val (nth witness skWOTS{1} i))) len
           /\ sigWOTS{2}
              =
              mkseq (fun (i : int) =>
                      cf O_MEUFGCMA_WOTSC_Default.ps{2} (set_chidx (WAddress.val wad{2}) i) 0 (BaseW.val em{2}.[i]) (DigestBlock.val (nth witness skWOTS{1} i))) len
           /\ size skWOTS{1} = len).
+ wp => /=.
  while (   i{1} = size pkWOTS{2}
         /\ pkWOTS{2}
            =
            mkseq (fun (i : int) =>
                    cf O_MEUFGCMA_WOTSC_Default.ps{2} (set_chidx (WAddress.val wad{2}) i) 0 (w - 1) (DigestBlock.val (nth witness l{1} i))) (size pkWOTS{2})
         /\ sigWOTS{2}
            =
            mkseq (fun (i : int) =>
                    cf O_MEUFGCMA_WOTSC_Default.ps{2} (set_chidx (WAddress.val wad{2}) i) 0 (BaseW.val em{2}.[i]) (DigestBlock.val (nth witness l{1} i))) (size sigWOTS{2})
         /\ size pkWOTS{2} <= len
         /\ size pkWOTS{2} = size sigWOTS{2}
         /\ size l{1} = size sigWOTS{2}
         /\ n{1} = len).
  - wp; rnd; wp; skip => /> &1 &2 pkwdef sigwdef _ eqszpksig eqszlsig ltlen_szpk sk_ele skelein.
    rewrite ?size_rcons /= ?mkseqS /=; 1,2: smt(size_ge0).
    rewrite andbA; split; 2: smt(size_cat).
    split; congr.
    * rewrite {1}pkwdef &(eq_in_mkseq) => j rng_j /=.
      by rewrite nth_cat (: j < size l{1}) 1:/#.
    * have vwad : valid_wadrs (set_chidx (WAddress.val wad{2}) (size pkWOTS{2})).
      + by rewrite validwadrs_setchidx 1:WAddress.valP //= /valid_chidx /#.
      rewrite nth_cat eqszlsig -eqszpksig /= {-1}(: w - 1 = BaseW.val em{2}.[size pkWOTS{2}] + (w - 1 - BaseW.val em{2}.[size pkWOTS{2}])) 1:/#.
      rewrite eq_sym /cf ch_comp 1:vwad //=; smt(BaseW.valP DigestBlock.valP).
    * rewrite {1}sigwdef &(eq_in_mkseq) => j rng_j /=.
      by rewrite nth_cat (: j < size l{1}) 1:/#.
    by rewrite nth_cat eqszlsig -eqszpksig.
  wp; skip => /> &2.
  by rewrite 2!mkseq0 /=; smt(ge2_len).
wp => /=.
while{1} (sigWOTS{1}
          =
          mkseq (fun (i : int) =>
                  cf O_MEUFGCMA_WOTSC_Default.ps{1} (set_chidx (WAddress.val wad{1}) i) 0 (BaseW.val em{1}.[i]) (DigestBlock.val (nth witness skWOTS{1} i))) (size sigWOTS{1})
          /\ size sigWOTS{1} <= len)
         (len - size sigWOTS{1}).
+ move=> _ z.
  wp; skip => /> &1 sigwdef _ ltlen_szsigw.
  by rewrite ?size_rcons mkseqS 2:{1}sigwdef /=; smt(size_ge0).
wp => /=.
while{1} (pkWOTS{1}
          =
          mkseq (fun (i : int) =>
                  cf O_MEUFGCMA_WOTSC_Default.ps{1} (set_chidx (WAddress.val wad{1}) i) 0 (w - 1) (DigestBlock.val (nth witness skWOTS{1} i))) (size pkWOTS{1})
          /\ size pkWOTS{1} <= len)
         (len - size pkWOTS{1}).
+ move=> _ z.
  wp; skip => /> &1 pkwdef _ ltlen_szpkw.
  by rewrite ?size_rcons mkseqS 2:{1}pkwdef /=; smt(size_ge0).
by wp; skip => /> &1 &2 eqlen_szsk; smt(mkseq0 ge2_len).
qed.

(* Piece 1 (O_V oracle-hop): the whole-key challenge oracle O_MEUFGCMA_WOTSC_Default
   is swapped for the element-sampling O_MEUFGCMA_WOTSC_V.  Mirror of MM45
   EqPr_MEUFGCMAWOTSTWESNPRF_Orig_V (FL_SL_XMSS_MT_ES.ec:3005-3032): re-run
   R_leaf_C.choose's nested cube-build on both sides, coupling each O.query via the
   query-level hop Eqv_O_MEUFGCMA_WOTSC_query_Orig_V and each OC.query / tree-hash
   loop by sim.  +C-transparent: the counter rides inside the (sigWOTS,cntr) cube,
   qs is shared via `include var`, so the accounting is byte-identical. *)
lemma EqPr_MEUFGCMAWOTSC_Orig_V
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -O_MEUFGCMA_WOTSC_Default,
             -O_MEUFGCMA_WOTSC_V, -FC.O_THFC_Default,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C }) &m :
    Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
         O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
    =
    Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
         O_MEUFGCMA_WOTSC_V, FC.O_THFC_Default).main() @ &m : res].
proof.
byequiv => //.
proc.
seq 4 4 : (   ={glob A_ht, glob R_MEUFGCMAWOTSC_EUFNAGCMA_C, ps}
           /\ ={O_MEUFGCMA_WOTSC_Default.qs, FC.O_THFC_Default.tws}); 2: by sim.
inline{1} 4; inline{2} 4.
while (#post /\ ={O_MEUFGCMA_WOTSC_Default.ps, FC.O_THFC_Default.pp}).
+ wp => /=.
  while (={R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad, R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd, O_MEUFGCMA_WOTSC_Default.ps, O_MEUFGCMA_WOTSC_Default.qs, FC.O_THFC_Default.pp, FC.O_THFC_Default.tws, rootsnt, rootsntp, leavesnt, sigcnt, pkWOTSnt}).
  - wp => /=.
    while (={R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad, R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd, FC.O_THFC_Default.pp, FC.O_THFC_Default.tws, nodes, pkWOTSnt, pkWOTSlp, leaveslp}).
    * by sim.
    wp => /=.
    while (={R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad, R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd, O_MEUFGCMA_WOTSC_Default.ps, O_MEUFGCMA_WOTSC_Default.qs, FC.O_THFC_Default.pp, FC.O_THFC_Default.tws, pkWOTSnt, rootsntp, leaveslp, sigclp, pkWOTSlp}).
    * wp => /=.
      call (: ={glob FC.O_THFC_Default}); 1: by sim.
      call Eqv_O_MEUFGCMA_WOTSC_query_Orig_V.
      by wp; skip.
    by wp; skip.
  by wp; skip.
wp => />.
call (: ={glob FC.O_THFC_Default}); 1: by sim.
inline *.
by wp; rnd; skip.
qed.

(* ==========================================================================
   SEAM: first ler_add branch byequiv (WOTS-forgery bucket).
   +C port of MM45 FL_SL_XMSS_MT_ES.ec:4107-4696 first branch.

   STATEMENT SETTLED + TYPECHECKS (EXIT 0):
     * Oracle plumbing resolved: the V-game's abstract OC is instantiated with
       FC.O_THFC_Default -- the SAME module M_EUF_GCMA_WOTSC_NPRF hands A_ht on the
       RHS (via R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht), which per :498/:614 passes OC
       directly to A(OC)).  FC.Oracle_THFC is structurally accepted where the V-game
       expects FSSLXMTWES.TRHC.Oracle_THFC (same {init,get_tweaks,query} signature).
     * LHS win event = res /\ EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES
       (valid_WOTSTWES is C's module var, shared with V via `import var`).
     * RHS is LITERALLY the leaf-bound RHS term so the SECOND ler_add step chains.
   ========================================================================== *)
lemma seam_branch1_WOTSC
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V }) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (a b : adrs),
       get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b) => get_wgpidxs a = get_wgpidxs b) =>
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC <> 8 * n =>
    dfC <> 8 * n * len =>
    dfC <> 8 * n * 2 =>
    hoare[ A_ht(O_THFC_MA).choose :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma ] =>
    (* STEP 1 (MM45-faithful, +C analog of allnchads, FL_SL_XMSS_MT_ES.ec:4079/4096):
       a TYPE-based well-formedness premise on A_ht run over the SAME collection oracle
       it is handed in this byequiv (FC.O_THFC_Default -- both the V-game LHS and
       R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht) RHS pass OC := FC.O_THFC_Default directly to
       A_ht(OC).choose).  This is what establishes P's conjunct
       `all (get_typeidx <> chtype) FC.O_THFC_Default.tws{2}` at the part-0 choose step
       (via `conseq (<sim equiv>) _ (<this hoare>)`), which then rides through the
       cube-build's pkco/trhx OC.query calls (all non-chtype).  Carried here, NOT
       discharged (a downstream consumer discharges it exactly as MM45 discharges
       allnchads at FL_SL:4338).  BOTH this and the member-based A_wf_ht are needed:
       allnchads for the chtype WOTS-chain axis; A_wf_ht for the +C pkcotype/dfC axis. *)
    hoare[ A_ht(FC.O_THFC_Default).choose :
             FC.O_THFC_Default.tws = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws ] =>
    Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A_ht, FC.O_THFC_Default).main() @ &m :
         res /\ EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES]
    <= Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
             O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res].
proof.
(* ==========================================================================
   STATEMENT NOTE (this session): the A_ht restriction gained
   `-EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C` (needed so the conseq's is_valid{1}/
   valid_WOTSTWES{1} references pass the module-write frame check; MM45 gets this
   for free because its _C/_V games are `local`).  SOUND (A_ht's only interface is
   OC, it cannot touch that module), but NOT YET re-checked to still discharge at
   the downstream `ler_add` consumer that chains this bound.

   STATUS (2026-07-19, UPDATED): seam_branch1_WOTSC is CERTIFIED-0-ADMIT
   (ec-certify => compile=OK, admit-tactics=0, axiom-decls=0).  The #1 cube-build
   establishment is now CLOSED -- the last admit is gone.  #A (conseq bookkeeping),
   #B (reconstruction + DISCRIMINATING +C okC-propagation), part-0 choose-alignment,
   part-2 signing sim, part-3 verify-inline + conseq RETAINING is_valid{1}, part-4/5
   reconstruction + okC discharge, the full O_V ORACLE-HOP (module
   O_MEUFGCMA_WOTSC_V + Eqv_O_MEUFGCMA_WOTSC_query_Orig_V + EqPr_MEUFGCMAWOTSC_Orig_V),
   AND the cube-build itself are all admit-free.  No R_leaf_C / leaf-bound change.

   The two obstacles flagged in the earlier draft (i: part-0 post dropping ps/ad/pp;
   ii: the tws-non-chtype conjunct) were BOTH resolved by STEP1/STEP2 of the recovered
   run: part-0 `seq 4 5` now carries ps/ad/pp + the tws-non-chtype conjunct (injected
   via `conseq (<sim>) _ allnchads`, the STEP-1 TYPE-based premise added at :1918-1920
   alongside the member-based A_wf_ht).

   CUBE-BUILD PROOF (this session): transcribed from MM45 FL_SL_XMSS_MT_ES.ec:4167-4531
   (nested d x nr_trees x l' x {element, tree-hash} while) with the +C deltas folded in.
   Mechanical parts ported by rename (nr_nodes->nr_nodesx, trhtype->trhxtype,
   O_MEUFGCMA_WOTSTWESNPRF->O_MEUFGCMA_WOTSC_Default, R_...->R_MEUFGCMAWOTSC_EUFNAGCMA_C).
   The FOUR genuine +C reworks (beyond rename):
     * SIDE-2 SIG NAMES: R.choose uses sigclp/sigcnt (not sigWOTSlp/sigWOTSnt), so the
       invariant `={..}` groups were expanded with `sigWOTSlp{1}=sigclp{2}` in place
       (order-preserved, so the closings' andbA counts still match).
     * SIG-COUNTER MAINTENANCE CONJUNCT: the sig element carries the ground counter, so
       the l'-body maintenance gains a NEW first conjunct (MM45 has the leaf there) --
       grindC address/root align via the size eqs + WAddress.insubdK (valid_tidx from
       the loop bounds); the leaf then peels as MM45's second conjunct.
     * QUALIFIED LEMMAS: bare `insubdK`/`valP` are ambiguous in this namespace ->
       WAddress.insubdK / DBLL.insubdK / DigestBlock.valP.
     * TREE-HASH size-leaf: the node input-size subgoal (size(val)+size(val)=8*n*2)
       needs smt(DigestBlock.valP); MM45's bare `/#` lacked the digest-size fact.
   ==========================================================================
   PORT RECIPE + okC-DISCHARGE CRUX ANALYSIS (single admit at the end).

   VALIDATED SO FAR (each compiled EXIT 0 in the docker gate):
     move=> hc hembdisj hembinj hencb hdf8n hdflen hdf2 A_wf_ht.
     byequiv => //.       (* auto-frames pre ={glob A_ht}, post (res/\vw){1} => res{2} *)
     proc.
     inline{2} 5; inline{2} 4.   (* RHS: inline A.forge (stmt 5) then A.choose (stmt 4);
                                    M_EUF_GCMA_WOTSC_NPRF.main stmts:
                                    1 ps<$dpseed 2 O.init 3 OC.init 4 A.choose
                                    5 A.forge 6 O.get 7 WOTS_C_ES.verify ... *)

   STRUCTURE (MM45 :4107-4696, first branch), with the +C simplification and the
   one +C divergence flagged:

   (0) CHOOSE alignment  [+C SIMPLER THAN MM45].
       MM45 wraps OC in R's local O_THFC (:1901) to separate inner/own queries, so
       its choose seq (:4120-4142) carries a wrapper-relation invariant.  OUR
       R_MEUFGCMAWOTSC_EUFNAGCMA_C hands OC DIRECTLY to A_ht (:498), and the V-game
       likewise (:1229).  With OC := FC.O_THFC_Default on BOTH sides, A_ht.choose is
       the identical call over the identical oracle.  Expect:
         seq <k1> <k2> : (={glob A_ht, ml} /\ ps aligned /\ FC.O_THFC_Default state eq
                          /\ ad{1}=adz=R_...ad{2}).
         - by call (: ={glob FC.O_THFC_Default}); (sample ps; O.init/OC.init).
       No `all typeidx <> chtype` invariant is needed here (that was MM45's
       per-family bookkeeping; ours is member-based and already discharged inside
       leaf_reduction_MEUFGCMAWOTSC_bound).  A_wf_ht is NOT consumed by THIS
       byequiv -- it is consumed by leaf_reduction_bound downstream.  (Double-check
       whether byequiv still needs any choose postcondition; likely only glob+ml eq.)

   (1) CUBE-BUILD seq  [MECHANICAL BULK -- admit as the single pre-goal].
       MM45 :4143-4531.  LHS builds the (pk,sig,leaves,roots) cube via the pkco/
       val_bt_trh OPERATORS directly (V :1235-1304); RHS builds it via O.query
       (WOTS+C interactive signing oracle) + OC.query (pkco member 8n*len, trh
       member 8n*2) inside R_leaf_C.choose (:510-564).  The seq post is the qs
       CHARACTERIZATION (adapt MM45 :4143-4166 with the +C sig element = (sigWOTS,cntr)):
         O_MEUFGCMA_WOTSC_Default.qs{2} indexed by (i,j,u) = bigi nr_trees 0 i*l'+j*l'+u
         with entry (set_kpidx(set_typeidx(set_ltidx adz i j)chtype)u,
                     to-be-signed-root, pkWOTStd[i][j][u], sigWOTStd[i][j][u]) ;
         all get_typeidx=chtype ; uniq_wgpidxs ; size qs = bigi nr_nodes_ht 0 d ;
         and cube equalities pkWOTStd{1}=R_...pkWOTStd{2} etc.
       *** This is the ~370 lines of drift-prone nested-while invariant.  The tail
           below is provable FROM this post; ADMIT the establishment. ***

   (2) SIGNING seq  [medium; sim].  MM45 :4532-4534: swap{1} [1..2] 2; sp 0 1;
       seq 2 2 : (#pre /\ ={sigl}); by conseq />; sim.  (+C: sig element carries
       the counter; both sides assemble sigl identically from the cube -> sim.)

   (3) VERIFY inline + wp + CONSEQ  [+C DIVERGENCE (a) -- RETAIN is_valid{1}].
       MM45 :4535-4536 inline the RHS verify pk-loop; :4537 conseq DROPS is_valid{1}:
           is_fresh{1} /\ valid_WOTSTWES{1} => is_valid{2} /\ m'<>m /\ idx-range.
       +C MUST KEEP is_valid{1} (it carries allOkC{1}, the sole source of okC{2}):
           is_valid{1} /\ is_fresh{1} /\ valid_WOTSTWES{1}
             => is_valid_WOTSC{2} /\ m'{2}<>m{2} /\ 0 <= i{2} < size qs{2}
       where is_valid{1} = (size sig'=d /\ root-match /\ allOkC){1}  [V :1391-1393]
       and   is_valid_WOTSC{2} = (DBLL.insubd pkWOTS_l = pkWOTS /\ okC){2}
             [WOTS_C_ES.verify, WOTS_C_Scheme.ec:103].
       The RHS `res` also needs 0<=i<nrqs, nrqs<=c (from hc + qs size), dist_wgpidxs,
       disj_wgpidxs (MM45 :4539-4546, ports verbatim -- counter-independent).

   (4) RECONSTRUCTION seq  [MM45 :4547-4681; ports with counter threaded].
       Relate V's inlined reconstruction loop (V :1352-1376) to R_leaf_C.forge's
       (:623-643).  Invariant = MM45 :4555-4595 with the sig element
       ((sigWOTS,cntr),ap) and pkWOTS_from_sigWOTS_C returning (pkWOTS',okC).
       Both sides run the SAME reconstruction => ={pkWOTSs,rootss,pkWOTSs',rootss',
       tkpidxs,tidx,kpidx,root'}.  pkWOTSs'{i} characterized as the mkseq cf-chain
       over encode_msgWOTS(nth (m'::rootss') i) -- MM45 :4576-4584, but with
       encode_msgWOTS_C ... = encode_msgWOTS (ThC ...) rewritten via `hencb`.

       +C DIVERGENCE (b) -- allOkC{1} must be carried indexably.  V accumulates the
       SCALAR allOkC{1} = /\_{layers} okC.  Add ONE invariant clause exposing it as
       an all-true list so it can be split at cidx:
           allOkC{1} = all idfun okl   (ghost, = per-layer okC of pkWOTS_from_sigWOTS_C)
       Cleanest realization: the loop's okC at layer i equals
           predC (ThC ps{1} (set_kpidx(set_typeidx(set_ltidx ad i (nth tkpidxs i).`1)chtype)
                             (nth tkpidxs i).`2) (nth (m'::rootss'){1} i) ((nth sig'{1} i).`1.`2))
       (same address+root+counter alignment that proves pk-equality -- REUSE it, do
       not invent a new one).  Since V has no okl program var, carry the clause as
           allOkC{1} = all idfun (mkseq (fun i => that predC) (size pkWOTSs'{1}))
       maintained by all_idfun_rcons at each step.  [Helpers: all_idfun_rcons :359.]

   (5) EXTRACTION  [MM45 :4643-4681; +C adds the okC discharge].
       find cidx over zip (zip (zip pkWOTSs' pkWOTSs)(m'::rootss'))(ml[idx]::rootss)
       with predicate x.`1.`1.`1=x.`1.`1.`2 /\ x.`1.`2<>x.`2 (V's valid_WOTSTWES gives
       has => 0<=cidx<d).  fidx = bigi nr_trees 0 cidx*l'+tidx*l'+kpidx (range via
       qs size, MM45 :4673-4681).  pk-match: MM45 :4672 -pkwrel/-eqpk/pkwpdef.
       +C okC DISCHARGE (the crux):  is_valid_WOTSC{2} = pk-match{2} /\ okC{2}.
         okC{2} = predC (ThC ps ad_fidx m'_cidx counter'_cidx) is recomputed by the
         RHS WOTS_C_ES.verify on O.get(fidx)'s stored pk/addr and R_leaf_C.forge's
         returned (root'=nth(m'::rootss')cidx [:653], sigc'=(nth sig' cidx).`1 [:654]).
         The stored addr = set_kpidx(set_typeidx(set_ltidx adz cidx tidx)chtype)kpidx
         (O.query at choose, characterized in (1)'s qs post) = EXACTLY the address the
         invariant-(b) clause names for layer cidx.  So okC{2} = the cidx-th conjunct
         of allOkC{1}.  Discharge:
           all_idfun_nth (:350) applied to the invariant-(b) list at k=cidx
           (0<=cidx<d=size), using allOkC{1} (from is_valid{1}, retained by the
           conseq in (3)).
         [pkfromsigC_verify_eq :321 bridges the per-layer reconstruction okC to the
          WOTS_C_ES.verify okC; all_idfun_nth :350 selects layer cidx;
          root_from_sigC_okl_eq :416 / all_idfun_rcons :359 back the list shape.]
       is_fresh{2} m'<>m: MM45 :4540-4546 disj_wgpidxs argument, verbatim.

   MILESTONE-2 (does closing okC need R_leaf_C or leaf-bound rework?):  NONE.
     * R_leaf_C.forge already returns exactly (root'_cidx, sigc'_cidx) at the
       matching chtype address (:628-656); okC aligns BY CONSTRUCTION with V's
       reconstruction (same reconstruction code, same address formula, same root'
       and counter').
     * The two load-bearing helpers (pkfromsigC_verify_eq :321, all_idfun_nth :350,
       plus root_from_sigC_okl_eq :416 / all_idfun_rcons :359) ALREADY EXIST and are
       0-admit.  The okC discharge is a local proof-engineering assembly of these;
       no change to R_leaf_C or leaf_reduction_MEUFGCMAWOTSC_bound is required.

   REMAINING WORK = pure MM45-mechanical assembly of (0)-(5).  The bulk (1) is the
   ~370-line nested cube-build invariant (drift-prone; needs interactive goal
   introspection, which the batch docker gate does not afford efficiently).  The
   tail (3)-(5) including BOTH +C divergences is fully specified above and closes
   against (1)'s admitted post using the existing 0-admit helpers.
   ========================================================================== *)
move=> hc hembdisj hembinj hencb hdf8n hdflen hdf2 A_wf_ht allnchads.
(* O_V oracle-hop: swap the whole-key challenge oracle O_MEUFGCMA_WOTSC_Default for
   the element-sampling O_MEUFGCMA_WOTSC_V (both share qs via `include var`, so P's
   qs references below stay valid), aligning the RHS with the V-game's fused loop. *)
rewrite (EqPr_MEUFGCMAWOTSC_Orig_V A_ht).
byequiv => //.
proc.
inline{2} 5; inline{2} 4.
(* ---- part (0): CHOOSE-ALIGNMENT -- PROVEN (compiles EXIT 0). ----
   +C simplification confirmed: with OC := FC.O_THFC_Default on BOTH sides and
   R_MEUFGCMAWOTSC_EUFNAGCMA_C handing OC directly to A_ht (no MM45 wrapper), the
   A_ht.choose calls couple by the collection-oracle glob equality alone; the
   sampling/inits close by `inline *; auto`.  No `typeidx<>chtype` invariant. *)
seq 4 5 : (
     ={glob A_ht}
  /\ ml{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.ml{2}
  /\ ps{1} = ps{2}
  /\ ps{1} = O_MEUFGCMA_WOTSC_Default.ps{2}
  /\ FC.O_THFC_Default.pp{1} = O_MEUFGCMA_WOTSC_Default.ps{2}
  /\ FC.O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
  /\ ad{1} = adz
  /\ ad{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad{2}
  /\ O_MEUFGCMA_WOTSC_Default.qs{2} = []
  /\ all (fun (ad0 : adrs) => get_typeidx ad0 <> chtype) FC.O_THFC_Default.tws{2}).
(* STEP 2 (MM45-faithful, choose seq FL_SL:4113-4119): part-0 now CARRIES the
   ps/ad/pp coupled equalities + the tws-non-chtype conjunct that P needs, instead
   of dropping them.  The choose call couples via the collection-oracle+A_ht glob
   equality (`by sim`) for the equalities/result, and injects the one-sided tws type
   property on side 2 via `conseq (<sim equiv>) _ (allnchads)` -- with tws{2}=[] in
   scope (established by OC.init just before choose).  The ps/ad/pp equalities are
   coupled-equal in the prefix (ps sampled equal, O.init/OC.init bind ps, ad<-adz)
   and framed through the abstract choose (A_ht cannot write ps/O.ps/R.ad). *)
+ wp.
  call (:    ={glob A_ht, glob FC.O_THFC_Default} /\ FC.O_THFC_Default.tws{2} = []
          ==> ={glob A_ht, glob FC.O_THFC_Default, res}
           /\ all (fun (ad0 : adrs) => get_typeidx ad0 <> chtype) FC.O_THFC_Default.tws{2}).
  - conseq (:    ={glob A_ht, glob FC.O_THFC_Default}
              ==> ={glob A_ht, glob FC.O_THFC_Default, res})
           _
           allnchads => //.
    by sim.
  inline *; auto.
(* ---- part (1): CUBE-BUILD seq.  Establish the qs characterization post P
   (MM45 4143-4166 + part-0 alignments, with the +C sig-pair type).  The
   ESTABLISHMENT is the mechanical bulk (needs the O_orig->O_V element-sampling
   hop, MM45 WOTS_TW_ES.ec:2915-3277 + FL_SL_XMSS_MT_ES.ec:2840-3032, then the
   MM45 4167-4531 nested cube-build).  Admit it here (labeled); the tail (2)-(5)
   below is proven AGAINST P and is the go/no-go for the seam. ---- *)
seq 6 5 : (
     ={glob A_ht}
  /\ ml{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.ml{2}
  /\ ps{1} = ps{2}
  /\ ps{1} = O_MEUFGCMA_WOTSC_Default.ps{2}
  /\ FC.O_THFC_Default.pp{1} = O_MEUFGCMA_WOTSC_Default.ps{2}
  /\ FC.O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
  /\ ad{1} = adz
  /\ ad{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad{2}
  /\ pkWOTStd{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}
  /\ sigWOTStd{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.sigWOTStd{2}
  /\ leavestd{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.leavestd{2}
  /\ rootstd{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.rootstd{2}
  /\ (forall (admpksig : adrs * msgWOTS * pkWOTS * (sigWOTS * cntr)),
        admpksig \in O_MEUFGCMA_WOTSC_Default.qs{2}
        <=>
        (exists (i j u : int), 0 <= i < d /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
          admpksig = (nth witness O_MEUFGCMA_WOTSC_Default.qs{2} (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u))))
  /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
        nth witness O_MEUFGCMA_WOTSC_Default.qs{2} (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
        =
        (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u,
         (if i = 0
          then nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.ml{2} (j * l' + u)
          else nth witness (nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.rootstd{2} (i - 1)) (j * l' + u)),
         nth witness (nth witness (nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} i) j) u,
         nth witness (nth witness (nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.sigWOTStd{2} i) j) u))
  /\ all (fun (admpksig : _ * _ * _ * _) => get_typeidx admpksig.`1 = chtype) O_MEUFGCMA_WOTSC_Default.qs{2}
  /\ uniq_wgpidxs (map (fun (admpksig : adrs * msgWOTS * pkWOTS * (sigWOTS * cntr)) => admpksig.`1) O_MEUFGCMA_WOTSC_Default.qs{2})
  /\ size O_MEUFGCMA_WOTSC_Default.qs{2} = StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 d
  /\ all (fun (ad0 : adrs) => get_typeidx ad0 <> chtype) FC.O_THFC_Default.tws{2}).
(* STEP 3: cube-build establishment.  Transcribed from MM45 FL_SL_XMSS_MT_ES.ec:4167-4531
   (nested d x nr_trees x l' x {len element-loop, tree-hash while{2}}).  +C deltas:
   sig element (sigWOTS,cntr); encode_msgWOTS_C via `hencb`; trhtype->trhxtype;
   nr_nodes->nr_nodesx; counter rides in sigWOTStd; both sides use FC.O_THFC_Default
   as OC (no MM45 O_THFC_Default{1}/FC.O_THFC_Default{2} split).  qs accounting is
   counter-free -> qs-index / all-chtype / uniq / size port verbatim; the tws
   non-chtype conjunct rides from the STEP-1 allnchads premise (carried in part-0). *)
(* ---- OUTER d-loop (MM45 4167-4210).  glob A_ht / (nothing it references) is
   framed by the while (the cube-build calls no adversary), so -- like MM45 -- it is
   NOT restated in the invariant; ml/ad/ps/pp ARE (the qs-nth characterization names
   them). ---- *)
while (
     ={ps}
  /\ ps{1} = O_MEUFGCMA_WOTSC_Default.ps{2}
  /\ FC.O_THFC_Default.pp{1} = O_MEUFGCMA_WOTSC_Default.ps{2}
  /\ FC.O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
  /\ ad{1} = adz
  /\ ad{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad{2}
  /\ ml{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.ml{2}
  /\ pkWOTStd{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}
  /\ sigWOTStd{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.sigWOTStd{2}
  /\ leavestd{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.leavestd{2}
  /\ rootstd{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.rootstd{2}
  /\ (forall (admpksig : adrs * msgWOTS * pkWOTS * (sigWOTS * cntr)),
        admpksig \in O_MEUFGCMA_WOTSC_Default.qs{2}
        <=>
        (exists (i j u : int), 0 <= i < size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
          admpksig = (nth witness O_MEUFGCMA_WOTSC_Default.qs{2} (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u))))
  /\ (forall (i j u : int), 0 <= i < size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
        nth witness O_MEUFGCMA_WOTSC_Default.qs{2} (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
        =
        (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u,
         (if i = 0
          then nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.ml{2} (j * l' + u)
          else nth witness (nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.rootstd{2} (i - 1)) (j * l' + u)),
         nth witness (nth witness (nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} i) j) u,
         nth witness (nth witness (nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.sigWOTStd{2} i) j) u))
  /\ all (fun (ad0 : adrs) => get_typeidx ad0 <> chtype) FC.O_THFC_Default.tws{2}
  /\ all (fun (admpksig : _ * _ * _ * _) => get_typeidx admpksig.`1 = chtype) O_MEUFGCMA_WOTSC_Default.qs{2}
  /\ uniq_wgpidxs (map (fun (admpksig : adrs * msgWOTS * pkWOTS * (sigWOTS * cntr)) => admpksig.`1) O_MEUFGCMA_WOTSC_Default.qs{2})
  /\ size O_MEUFGCMA_WOTSC_Default.qs{2} = StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2})
  /\ size skWOTStd{1} = size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}
  /\ size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} = size R_MEUFGCMAWOTSC_EUFNAGCMA_C.leavestd{2}
  /\ size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} = size R_MEUFGCMAWOTSC_EUFNAGCMA_C.sigWOTStd{2}
  /\ size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} = size R_MEUFGCMAWOTSC_EUFNAGCMA_C.rootstd{2}
  /\ size skWOTStd{1} <= d).
+ wp => /=.
      while (   ps{1} = ps{2} /\ pkWOTSnt{1} = pkWOTSnt{2} /\ sigWOTSnt{1} = sigcnt{2} /\ leavesnt{1} = leavesnt{2} /\ rootsnt{1} = rootsnt{2} /\ rootsntp{1} = rootsntp{2}
             /\ ps{1} = O_MEUFGCMA_WOTSC_Default.ps{2}
             /\ FC.O_THFC_Default.pp{1} = O_MEUFGCMA_WOTSC_Default.ps{2}
             /\ FC.O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
             /\ ad{1} = adz
             /\ ad{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad{2}
             /\ (forall (admpksig : adrs * msgWOTS * pkWOTS * (sigWOTS * cntr)),
                   admpksig \in O_MEUFGCMA_WOTSC_Default.qs{2}
                   <=>
                   (exists (i j u : int), 0 <= i < size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
                     admpksig = (nth witness O_MEUFGCMA_WOTSC_Default.qs{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)))
                   \/
                   (exists (j u : int), 0 <= j < size pkWOTSnt{2} /\ 0 <= u < l' /\
                     admpksig = (nth witness O_MEUFGCMA_WOTSC_Default.qs{2}
                                     (bigi predT (fun (m : int) => nr_trees m) 0 (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}) * l' + j * l' + u))))
             /\ (forall (i j u : int), 0 <= i < size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness O_MEUFGCMA_WOTSC_Default.qs{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
                   =
                   (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u,
                    (if i = 0
                     then nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.ml{2} (j * l' + u)
                     else nth witness (nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.rootstd{2} (i - 1)) (j * l' + u)),
                    nth witness (nth witness (nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} i) j) u,
                    nth witness (nth witness (nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.sigWOTStd{2} i) j) u))
             /\ (forall (j u : int), 0 <= j < size pkWOTSnt{2} => 0 <= u < l' =>
                   nth witness O_MEUFGCMA_WOTSC_Default.qs{2}
                       (bigi predT (fun (m : int) => nr_trees m) 0 (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}) * l' + j * l' + u)
                   =
                   (set_kpidx (set_typeidx (set_ltidx adz (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}) j) chtype) u,
                    nth witness rootsntp{2} (j * l' + u),
                    nth witness (nth witness pkWOTSnt{2} j) u,
                    nth witness (nth witness sigcnt{2} j) u))
             /\ all (fun (ad0 : adrs) => get_typeidx ad0 <> chtype) FC.O_THFC_Default.tws{2}
             /\ all (fun (admpksig : _ * _ * _ * _) => get_typeidx admpksig.`1 = chtype) O_MEUFGCMA_WOTSC_Default.qs{2}
             /\ uniq_wgpidxs (map (fun (admpksig : adrs * msgWOTS * pkWOTS * (sigWOTS * cntr)) => admpksig.`1) O_MEUFGCMA_WOTSC_Default.qs{2})
             /\ size O_MEUFGCMA_WOTSC_Default.qs{2}
                =
                bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2})
                +
                size pkWOTSnt{2} * l'
             /\ size skWOTSnt{1} = size pkWOTSnt{2}
             /\ size pkWOTSnt{2} = size leavesnt{2}
             /\ size pkWOTSnt{2} = size sigcnt{2}
             /\ size pkWOTSnt{2} = size rootsnt{2}
             /\ size skWOTStd{1} = size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}
             /\ size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} = size R_MEUFGCMAWOTSC_EUFNAGCMA_C.leavestd{2}
             /\ size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} = size R_MEUFGCMAWOTSC_EUFNAGCMA_C.sigWOTStd{2}
             /\ size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} = size R_MEUFGCMAWOTSC_EUFNAGCMA_C.rootstd{2}
             /\ size skWOTSnt{1} <= nr_trees (size skWOTStd{1})
             /\ size skWOTStd{1} < d).
  - wp => /=.
        while{2} (   R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad{2} = adz
                  /\ all (fun (ad0 : adrs) => get_typeidx ad0 <> chtype) FC.O_THFC_Default.tws{2}
                  /\ (forall (i j : int), 0 <= i < size nodes{2} => 0 <= j < nr_nodesx (i + 1) =>
                        nth witness (nth witness nodes{2} i) j
                        =
                        let leaveslpp = take (2 ^ (i + 1)) (drop (j * (2 ^ (i + 1))) leaveslp{2}) in
                          val_bt_trh_gen FC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad{2} (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}) (size pkWOTSnt{2})) trhxtype)
                                         (list2tree leaveslpp) (i + 1) j)
                  /\ size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} < d
                  /\ size pkWOTSnt{2} < nr_trees (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2})
                  /\ size leaveslp{2} = l'
                  /\ size nodes{2} <= h')
                 (h' - size nodes{2}).
        * move => _ z.
          wp => /=.
          while (   R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad = adz
                 /\ all (fun (ad0 : adrs) => get_typeidx ad0 <> chtype) FC.O_THFC_Default.tws
                 /\ nodespl = last leaveslp nodes
                 /\ (forall (i j : int), 0 <= i < size nodes => 0 <= j < nr_nodesx (i + 1) =>
                        nth witness (nth witness nodes i) j
                        =
                        let leaveslpp = take (2 ^ (i + 1)) (drop (j * (2 ^ (i + 1))) leaveslp) in
                          val_bt_trh_gen FC.O_THFC_Default.pp (set_typeidx (set_ltidx R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd) (size pkWOTSnt)) trhxtype)
                                         (list2tree leaveslpp) (i + 1) j)
                 /\ (forall (j : int), 0 <= j < size nodescl =>
                        nth witness nodescl j
                        =
                        let leaveslpp = take (2 ^ (size nodes + 1)) (drop (j * (2 ^ (size nodes + 1))) leaveslp) in
                          val_bt_trh_gen FC.O_THFC_Default.pp (set_typeidx (set_ltidx R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd) (size pkWOTSnt)) trhxtype)
                                         (list2tree leaveslpp) (size nodes + 1) j)
                 /\ size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd < d
                 /\ size pkWOTSnt < nr_trees (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd)
                 /\ size leaveslp = l'
                 /\ size nodescl <= nr_nodesx (size nodes + 1)
                 /\ size nodes < h')
                (nr_nodesx (size nodes + 1) - size nodescl).
          - move=> z'.
            inline 3.
            wp; skip => /> &2 allnchtws nthnds ntndscl ltd_szpktd ltnt_szpknt eqt_szlfslp _ lthp_sznds ltnn_szndscl.
            rewrite size_rcons -cats1 all_cat allnchtws /= -!andbA andbA; split => [| /#].
            rewrite gettype_setalltrh 1:valx_adz; 1..4: smt(size_ge0).
            split => [| j ge0_j ltszndscl1_j]; 1: smt(dist_adrstypes).
            rewrite nth_rcons; case (j < size nodescl{2}) => [/# | neqszj].
            have eqszj : j = size nodescl{2} by smt(size_rcons).
            rewrite eqszj /= size_cat ?valP /= (: 2 ^ (size nodes{2} + 1) = 2 ^ (size nodes{2}) + 2 ^ (size nodes{2})).
            + by rewrite exprD_nneg 1:size_ge0 //= expr1 /#.
            rewrite take_take_drop_cat 1,2:expr_ge0 //=.
            rewrite drop_drop 1:expr_ge0 //= 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 //=.
            have ge1_2aszn2szncl : 1 <= 2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1.
            + rewrite 2!IntOrder.ler_subr_addr /=.
              rewrite &(IntOrder.ler_trans (2 + 2 * (nr_nodesx (size nodes{2} + 1) - 1))) 1:/#.
              by rewrite /nr_nodesf mulzDr /= -{1}(expr1 2) -exprD_nneg // /#.
            rewrite -nth_last (list2treeS (size nodes{2})) 1:size_ge0.
            + rewrite size_take 1:expr_ge0 1:// size_drop 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 //.
              rewrite eqt_szlfslp /l' (: 2 ^ h' = 2 ^ (h' - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
              pose szn2 := 2 ^ (size nodes{2}).
              rewrite (: 2 ^ (h' - size nodes{2}) * szn2 - size nodescl{2} * (szn2 + szn2) = (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2}) * szn2) 1:/#.
              pose mx := max _ _; rewrite (: 2 ^ (size nodes{2}) < mx) // /mx.
              pose sb := ((_ - _ * _) * _)%Int; rewrite &(IntOrder.ltr_le_trans sb) /sb 2:maxrr.
              by rewrite ltr_pmull 1:expr_gt0 // /#.
            + rewrite size_take 1:expr_ge0 1:// size_drop 1:addr_ge0 1:expr_ge0 // 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 //.
              rewrite eqt_szlfslp /l' (: 2 ^ h' = 2 ^ (h' - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
              pose szn2 := 2 ^ (size nodes{2}).
              rewrite (: 2 ^ (h' - size nodes{2}) * szn2 - (szn2 + size nodescl{2} * (szn2 + szn2)) = (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) 1:/#.
              pose sb := ((_ - _ - _) * _)%Int.
              move: ge1_2aszn2szncl; rewrite lez_eqVlt => -[eq1_2as | gt1_2as].
              * by rewrite /sb -eq1_2as /= lez_maxr 1:expr_ge0.
              rewrite lez_maxr /sb 1:mulr_ge0 2:expr_ge0 //= 1:subr_ge0 1:ler_subr_addr.
              * rewrite &(IntOrder.ler_trans (1 + 2 * (nr_nodesx (size nodes{2} + 1) - 1))) 1:/#.
                by rewrite /nr_nodesx mulzDr -{1}(expr1 2) -exprD_nneg // /#.
              rewrite (: szn2 < (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) //.
              by rewrite ltr_pmull 1:expr_gt0.
            rewrite /= /val_bt_trh_gen /trhi /trh /updhbidx /=; congr; 1: by smt(DigestBlock.valP).
            case (size nodes{2} = 0) => [eq0_sz | neq0_sz].
            + rewrite eq0_sz ?expr0 /= (nth_out leaveslp{2}); 1: smt(size_ge0).
              rewrite {4 7}(: 1 = 0 + 1) 1:// ?(take_nth witness) 1,2:size_drop //; 1..4:smt(size_ge0).
              by rewrite ?take0 /= ?list2tree1 /= ?nth_drop //; smt(size_ge0).
            rewrite (nth_change_dfl witness leaveslp{2}); 1: smt(size_ge0).
            rewrite ?nthnds /=; 1,3: smt(size_ge0).
            + split => [| _ @/nr_nodesx]; 1: smt(size_ge0).
              rewrite &(IntOrder.ltr_le_trans (nr_nodesx (size nodes{2}))) /nr_nodesx //.
              rewrite (: 2 ^ (h' - size nodes{2}) = 2 * 2 ^ (h' - (size nodes{2} + 1))) 2:/#.
              by rewrite -{2}(expr1 2) -exprD_nneg // /#.
            + split => [| _ @/nr_nodesx]; 1: smt(size_ge0).
              rewrite &(IntOrder.ltr_le_trans (nr_nodesx (size nodes{2}))) /nr_nodesx //.
              rewrite (: 2 ^ (h' - size nodes{2}) = 2 * 2 ^ (h' - (size nodes{2} + 1))) 2:/#.
              by rewrite -{2}(expr1 2) -exprD_nneg // /#.
            rewrite /= /val_bt_trh_gen /trhi /trh /updhbidx /=; do 3! congr; 1: smt().
            by do 3! congr; ring.
          by wp; skip => /> &2; smt(expr_ge0 nth_rcons size_rcons).
    wp => /=.
        while (   ps{1} = ps{2} /\ pkWOTSlp{1} = pkWOTSlp{2} /\ sigWOTSlp{1} = sigclp{2} /\ leaveslp{1} = leaveslp{2} /\ rootsntp{1} = rootsntp{2}
               /\ ps{1} = O_MEUFGCMA_WOTSC_Default.ps{2}
               /\ FC.O_THFC_Default.pp{1} = O_MEUFGCMA_WOTSC_Default.ps{2}
               /\ FC.O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
               /\ ad{1} = adz
               /\ ad{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad{2}
               /\ (forall (admpksig : adrs * msgWOTS * pkWOTS * (sigWOTS * cntr)),
                     admpksig \in O_MEUFGCMA_WOTSC_Default.qs{2}
                     <=>
                     (exists (i j u : int), 0 <= i < size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
                       admpksig = (nth witness O_MEUFGCMA_WOTSC_Default.qs{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)))
                     \/
                     (exists (j u : int), 0 <= j < size pkWOTSnt{2} /\ 0 <= u < l' /\
                       admpksig = (nth witness O_MEUFGCMA_WOTSC_Default.qs{2}
                                       (bigi predT (fun (m : int) => nr_trees m) 0 (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}) * l' + j * l' + u)))
                     \/
                     (exists (j u : int), 0 <= u < size pkWOTSlp{2} /\
                       admpksig = (nth witness O_MEUFGCMA_WOTSC_Default.qs{2}
                                       (bigi predT (fun (m : int) => nr_trees m) 0 (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}) * l' + size pkWOTSnt{2} * l' + u))))
               /\ (forall (i j u : int), 0 <= i < size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                     nth witness O_MEUFGCMA_WOTSC_Default.qs{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
                     =
                     (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u,
                      (if i = 0
                       then nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.ml{2} (j * l' + u)
                       else nth witness (nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.rootstd{2} (i - 1)) (j * l' + u)),
                      nth witness (nth witness (nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} i) j) u,
                      nth witness (nth witness (nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.sigWOTStd{2} i) j) u))
               /\ (forall (j u : int), 0 <= j < size pkWOTSnt{2} => 0 <= u < l' =>
                     nth witness O_MEUFGCMA_WOTSC_Default.qs{2}
                         (bigi predT (fun (m : int) => nr_trees m) 0 (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}) * l' + j * l' + u)
                     =
                     (set_kpidx (set_typeidx (set_ltidx adz (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}) j) chtype) u,
                      nth witness rootsntp{2} (j * l' + u),
                      nth witness (nth witness pkWOTSnt{2} j) u,
                      nth witness (nth witness sigcnt{2} j) u))
               /\ (forall (u : int), 0 <= u < size pkWOTSlp{2} =>
                     nth witness O_MEUFGCMA_WOTSC_Default.qs{2}
                         (bigi predT (fun (m : int) => nr_trees m) 0 (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}) * l' + size pkWOTSnt{2} * l' + u)
                     =
                     (set_kpidx (set_typeidx (set_ltidx adz (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}) (size pkWOTSnt{2})) chtype) u,
                      nth witness rootsntp{2} (size pkWOTSnt{2} * l' + u),
                      nth witness pkWOTSlp{2} u,
                      nth witness sigclp{2} u))
               /\ all (fun (ad0 : adrs) => get_typeidx ad0 <> chtype) FC.O_THFC_Default.tws{2}
               /\ all (fun (admpksig : _ * _ * _ * _) => get_typeidx admpksig.`1 = chtype) O_MEUFGCMA_WOTSC_Default.qs{2}
               /\ uniq_wgpidxs (map (fun (admpksig : adrs * msgWOTS * pkWOTS * (sigWOTS * cntr)) => admpksig.`1) O_MEUFGCMA_WOTSC_Default.qs{2})
               /\ size O_MEUFGCMA_WOTSC_Default.qs{2}
                  =
                  bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2})
                  +
                  size pkWOTSnt{2} * l'
                  +
                  size pkWOTSlp{2}
               /\ size skWOTSlp{1} = size pkWOTSlp{2}
               /\ size pkWOTSlp{2} = size leaveslp{2}
               /\ size pkWOTSlp{2} = size sigclp{2}
               /\ size skWOTSnt{1} = size pkWOTSnt{2}
               /\ size pkWOTSnt{2} = size leavesnt{2}
               /\ size pkWOTSnt{2} = size sigcnt{2}
               /\ size pkWOTSnt{2} = size rootsnt{2}
               /\ size skWOTStd{1} = size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}
               /\ size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} = size R_MEUFGCMAWOTSC_EUFNAGCMA_C.leavestd{2}
               /\ size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} = size R_MEUFGCMAWOTSC_EUFNAGCMA_C.sigWOTStd{2}
               /\ size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} = size R_MEUFGCMAWOTSC_EUFNAGCMA_C.rootstd{2}
               /\ size skWOTSlp{1} <= l'
               /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
               /\ size skWOTStd{1} < d).
    * inline{2} 3; inline{2} 2.
      wp => /=.
      while (   ={em}
             /\ ps{1} = O_MEUFGCMA_WOTSC_Default.ps{2}
             /\ ad{1} = adz
             /\ ad{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad{2}
             /\ WAddress.val wad{2}
                =
                set_kpidx (set_typeidx (set_ltidx R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad{2} (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}) (size pkWOTSnt{2})) chtype) (size pkWOTSlp{2})
             /\ sigWOTS{1} = sigWOTS{2}
             /\ pkWOTS{1} = pkWOTS2{2}
             /\ size skWOTS{1} = size pkWOTS2{2}
             /\ size pkWOTS2{2} = size sigWOTS{2}
             /\ size skWOTStd{1} = size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}
             /\ size skWOTSnt{1} = size pkWOTSnt{2}
             /\ size skWOTSlp{1} = size pkWOTSlp{2}
             /\ size skWOTS{1} <= len).
      - by wp; rnd; wp; skip => />; smt(size_rcons).
          wp; skip => /> &1 &2 qsdef qsnth qsnth1 qsnth2 allnchtws allchqs uqswgpqs szqs eqszpksklp eqszpklfslp eqszpksiglp
                               eqszpksknt eqszpklfsnt eqszpksignt eqszpkrtsnt eqszpksktd eqszpklfstd eqszpksigtd eqszpkrtstd
                               _ ltnt_szsknt ltd_szsktd ltlp_szsklp ltlp_szpklp.
          split => [| skw pkw sigw /lezNgt gelen_szskw /lezNgt gelen_szpkw eq_em eqadw_ad eqszskpkw eqszpksigw lelen_szskw].
          - by rewrite eqszpksknt eqszpksklp /= WAddress.insubdK 1:validxadrs_validwadrs_setallboch 1:valx_adz 4:/=; smt(size_ge0 ge2_len).
          (* +C: the sig element carries the ground counter, so the sig-list
             maintenance conjunct (absent in MM45's counter-free V-game) is EXTRA.
             Peel it first (grindC address/root align via the size eqs + insubdK),
             then MM45's -6!andbA maintenance proof applies verbatim to the rest. *)
          rewrite !andbA -6!andbA; split; 2: by rewrite ?size_rcons /#.
          rewrite -!andbA; split.
          - (* +C: the sig element carries the ground counter, so this is the NEW
               first maintenance conjunct (MM45 has the leaf here).  grindC address
               and root align via the size eqs + insubdK (valid_tidx via loop bnds). *)
            by rewrite eqszpksktd eqszpksknt eqszpksklp WAddress.insubdK 1:validxadrs_validwadrs_setallboch 1:valx_adz; smt(size_ge0).
          split.
          - rewrite size_flatten -map_comp sumzE /= big_map /(\o) /predT /= -/predT.
            rewrite (eq_bigr _ _ (fun (_ : DigestBlock.sT) => 8 * n)) 1:/=.
            * by move=> ? _; rewrite DigestBlock.valP.
            by rewrite DBLL.insubdK 1:/# big_constz count_predT /#.
          rewrite /nr_nodes_ht /nr_nodesx /= -/l' -mulr_suml in szqs.
          split => [admpksig |]; 1: rewrite mem_rcons size_rcons /=; 1: split.
          - elim => [-> | /qsdef].
            * right; right; exists (size pkWOTSlp{2}).
              by split; [smt(size_ge0) | rewrite nth_rcons /#].
            elim => [[i j u [ir] [jr] [ur adval]]|].
            * by left; exists i j u; rewrite ir jr ur /= nth_rcons szqs ltbignrt_i.
            elim => [[j u [jr] [ur adval]]|].
            * right; left; exists j u; rewrite jr ur /= nth_rcons szqs.
              pose igl := _ + j * l' + _; pose igr := _ + size pkWOTSnt{2} * l' + _.
              rewrite (: igl < igr) /igl /igr 2://.
              rewrite -2!addrA ler_lt_add 1://.
              suff /#: j * l' + u < size pkWOTSnt{2} * l' /\ 0 <= size pkWOTSlp{2}.
              by rewrite size_ge0 /= (: size pkWOTSnt{2} = size pkWOTSnt{2} - 1 + 1) 1:// mulrDl ler_lt_add 2:// /#.
            elim => [u [ur adval]].
            * right; right; exists u; split; 1: smt(size_ge0).
              by rewrite nth_rcons szqs /#.
          - rewrite eqadw_ad; case; 2: case.
            * elim=> i j u [rng_i [rng_j [rng_u]]].
              by rewrite nth_rcons szqs ltbignrt_i 1..5:// /= qsdef /#.
            * elim=> j u [rng_j [rng_u]].
              rewrite nth_rcons szqs.
              pose igl := _ + j * l' + _; pose igr := _ + size pkWOTSnt{2} * l' + _.
              rewrite (: igl < igr) /igl /igr 2:/= 2:qsnth1 //.
              + rewrite -2!addrA ler_lt_add 1://.
                suff /#: j * l' + u < size pkWOTSnt{2} * l' /\ 0 <= size pkWOTSlp{2}.
                by rewrite size_ge0 /= (: size pkWOTSnt{2} = size pkWOTSnt{2} - 1 + 1) 1:// mulrDl ler_lt_add 2:// /#.
              by rewrite qsdef /#.
            by elim=> u [rng_u]; rewrite nth_rcons szqs /#.
          split => [* | ]; 1: by rewrite nth_rcons szqs ltbignrt_i // /= qsnth.
          split => [j u * | ]; 1: rewrite nth_rcons szqs.
          - pose igl := _ + j * l' + _; pose igr := _ + size pkWOTSnt{2} * l' + _.
            rewrite (: igl < igr) /igl /igr 2:/= 2:qsnth1 //.
            rewrite -2!addrA ler_lt_add 1://.
            suff /#: j * l' + u < size pkWOTSnt{2} * l' /\ 0 <= size pkWOTSlp{2}.
            by rewrite size_ge0 /= (: size pkWOTSnt{2} = size pkWOTSnt{2} - 1 + 1) 1:// mulrDl ler_lt_add 2:// /#.
          split => [u | ]; 1: rewrite size_rcons ?nth_rcons szqs => ge0_u ltsz1_u.
          - rewrite -eqszpksiglp; case (u < size pkWOTSlp{2}) => [ltszpk_u | nltszpk_u].
            + by rewrite qsnth2 // /#.
            by rewrite (: u = size pkWOTSlp{2}) 1:/# /= eqadw_ad.
          rewrite andbA; split; 1: rewrite -2!cats1 2!all_cat allnchtws allchqs /=.
          - rewrite eqadw_ad gettype_setkptypeltchpkco 1:valx_adz 3,4://; 1,2:smt(size_ge0).
            by rewrite gettype_setkptypeltchpkco 1:valx_adz 3,4://; smt(size_ge0 dist_adrstypes).
          rewrite /uniq_wgpidxs -map_comp map_rcons rcons_uniq /(\o) /=.
          split; 2: by move: uqswgpqs => @/uniq_wgpidxs; rewrite map_comp.
          rewrite mapP negb_exists => admpksig /=.
          rewrite negb_and -implybE qsdef eqadw_ad.
          rewrite /get_wgpidxs; case; 2: case.
          - elim=> i j u [rng_i [rng_j [rng_u]]].
            rewrite qsnth 1..3:// => -> /=.
            rewrite (neq_from_nth witness _ _ 3) 2?nth_drop 1..4:// 2:// /=.
            by rewrite neqlidx_setkptypelt 1:valx_adz 4..7,9://; smt(size_ge0).
          - elim=> j u [rng_j [rng_u]].
            rewrite qsnth1 1..2:// => -> /=.
            rewrite (neq_from_nth witness _ _ 2) 2?nth_drop 1..4:// 2:// /=.
            by rewrite neqtidx_setkptypelt 1:valx_adz 4..7,9://; smt(size_ge0).
          elim=> u [rng_u].
          rewrite qsnth2 1:// => -> /=.
          rewrite (neq_from_nth witness _ _ 0) 2?nth_drop 1..4:// 2:// /=.
          by rewrite neqkpidx_setkptypelt 1:valx_adz 4..7,9://; smt(size_ge0).
        wp; skip => /> &1 &2 qsdef qsnth qsnth1 allnchtws allchqs uqswgpqs szqs
                             eqszpksknt eqszpklfsnt eqszpksignt eqszpkrtsnt eqszpksktd
                             eqszpklfstd eqszpksigtd eqszpkrtstd _ ltd_szsktd ltnt_szsknt ltnt_szpknt.
        split=> [| skwlp qs tws lfslp pkwlp sigwlp /lezNgt gelp_szskwlp /lezNgt gelp_szpkwlp]; 1: smt(ge2_lp).
        move=> qspdef qspnth qspnth2 qspnth3 allnchtwsp allchqsp uqwgpqsp szqsp eqszpkskwlp eqszpkwlfslp eqszpksigwlp lelp_szskwlp.
        split=> [| tws' nds]; 1: smt(ge1_hp).
        split=> [/# | /lezNgt gehp_sznds allnchtwspp ndsnth ltd_szpkwtd eqlp_szlfslp lehp_sznds].
        rewrite !andbA -7!andbA; split; 2: by rewrite ?size_rcons /#.
        rewrite -!andbA; split.
        + congr; rewrite ndsnth 2:expr_gt0 2,3:// 2:/=; 1: smt(ge1_hp).
          by rewrite drop0 -/l' -eqlp_szlfslp take_size /#.
        by split; smt(size_ge0 nth_rcons size_rcons).
      wp; skip => /> &1 &2 qsdef qsnth allnchtws allchqs uqswgpqs szqs
                           eqszpksktd eqszpklfstd eqszpksigtd eqszpkrtstd
                           _ ltd_szskwtd ltd_szpkwtd.
      split=> [| skwnt qs tws lfsnt pkwnt rsnt sigwnt /lezNgt gent_szskwnt /lezNgt gent_szpkwnt]; 1: smt(expr_gt0).
      move=> qspdef qspnth qspnth1 allnchtwsp allchqsp uqwgpqsp szqsp eqszpkskwnt eqszpkwlfsnt eqszpksigwnt eqszpkwrsnt lent_szskwnt.
      rewrite !andbA -6!andbA; split; 2: by rewrite ?size_rcons /#.
      split; last first.
      + by rewrite szqsp size_rcons big_int_recr 1:size_ge0 //= /#.
      split => [admpksig | i j u]; last first.
      + rewrite size_rcons ?nth_rcons -eqszpksigtd -eqszpkrtstd => *.
        case (i < size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}) => [/#| ?].
        rewrite (: i = size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}) 1:/#.
        rewrite qspnth1 1:/# 1:// -nth_last -eqszpkrtstd .
        case (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} = 0) => szpkwtd /=; 2: smt(nth_change_dfl).
        by rewrite szpkwtd /= (nth_out _ _ (-1)) 1:/#.
      by split => [/qspdef | i j u]; smt(size_ge0 nth_rcons size_rcons).
wp; skip => /> &2 allnchtws.
+ split; first by rewrite big_geq //=; smt(ge1_d size_ge0).
  smt(ge1_d ltbignrt_i size_ge0).
(* ---- TAIL (parts 2-5) proven against P. ---- *)
(* part (2): signing-loop alignment (MM45 4532-4534).  +C: sig element (sigc,ap)
   carries the counter; both sides read the SAME sig cube -> sim. *)
swap{1} [1..2] 2.
sp 0 1.
seq 2 2 : (#pre /\ ={sigl}).
+ by conseq />; sim.
(* part (3): verify inline + conseq (MM45 4535-4546); +C divergence (a): RETAIN
   is_valid{1} (allOkC source). *)
inline{2} 23; inline{2} 22; inline{2} 21; inline{2} 20; inline{2} 17.
wp 15 19 => /=.
conseq (:
  (((size sig'{1} = d /\
     ((if d = 0 then m'{1} else nth witness rootss'{1} (d - 1)) =
      if d = 0 then nth witness ml{1} (Index.val idx'{1})
      else nth witness rootss{1} (d - 1)) /\
     allOkC{1}) /\
    is_fresh{1}) /\
   exists (i1 : int),
     0 <= i1 < d /\
     nth witness pkWOTSs'{1} i1 = nth witness pkWOTSs{1} i1 /\
     (if i1 = 0 then m'{1} else nth witness rootss'{1} (i1 - 1)) <>
     if i1 = 0 then nth witness ml{1} (Index.val idx'{1})
     else nth witness rootss{1} (i1 - 1))
  => is_valid{2} /\ m'{2} <> m{2} /\ 0 <= i{2} < size O_MEUFGCMA_WOTSC_Default.qs{2}).
- (* #A conseq bookkeeping (MM45 4539-4546), ANTECEDENT REFRAMED 2026-07-19 to
     POST_good's REAL unfolded antecedent (the +C `allOkC<-true` shifted
     valid_WOTSTWES/is_valid past `wp 15 19` so the folded refs were stale). *)
  move=> &1 &2 [#] eqps0 eqglob eqml eqps1 eqps2 eqpp1 eqpp2 eqad1 eqad2 eqpkwtd eqsigwtd eqlvtd eqrtd qsmem qsnth allchqs uqwgpqs szqs allnchtws eqsigl.
  move=> allOkC_L idx'_L is_fresh_L m'_L pkWOTSs_L pkWOTSs'_L rootss_L rootss'_L sig'_L i_R is_valid_R m_R m'_R HNEW HOLD.
  have [isv [neqm irng]] := HNEW HOLD.
  have cE : c = StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 d by rewrite /c.
  split; first by smt(size_ge0).
  split; first exact irng.
  split; first exact isv.
  split; first exact neqm.
  split; first exact uqwgpqs.
  rewrite /disj_wgpidxs -map_comp /get_wgpidxs /(\o) /disj_lists hasPn => ls.
  rewrite 2!mapP => -[admpksig] [admpksigin /= lsval].
  rewrite negb_exists => adx /=; rewrite negb_and -implybE => adin.
  rewrite lsval /= &(neq_from_nth witness _ _ 1).
  by rewrite ?nth_drop //=; smt(allP).
(* part (4): RECONSTRUCTION seq (MM45 4547-4681) + (5) EXTRACTION/okC (4682-4696).
   Q = the pk-reconstruction (for the final verify pk-match) AND the +C okC gate
   predC(ThC ...) at the forgery layer.  Both hold for a valid forgery under
   is_valid{1} (allOkC{1} => the cidx gate is true, MM45-shaped divergence (b)).
   HONEST SCOPE: the verify DISCHARGE below proves the STRUCTURAL half -- that,
   GIVEN Q delivers the okC-gate, the verify consumes it and is_valid{1} threads
   through (no structural no-go: is_valid{1} retention + verify okC composition
   both work).  The DISCRIMINATING +C step -- that allOkC{1}=true actually
   PROPAGATES to the extracted layer via the address-aligned all_idfun_nth /
   pkfromsigC_verify_eq / root_from_sigC_okl_eq argument (divergence (b)) -- lives
   ENTIRELY in the admitted establishment #B below and is NOT yet proven.  Q is
   true-in-principle (address alignment is sound + counter-independent), so #B is
   an honest deferral, not a vacuous/false post the discharge exploits. *)
seq 15 18 : (
  (((size sig'{1} = d /\
     ((if d = 0 then m'{1} else nth witness rootss'{1} (d - 1)) =
      if d = 0 then nth witness ml{1} (Index.val idx'{1})
      else nth witness rootss{1} (d - 1)) /\
     allOkC{1}) /\
    is_fresh{1}) /\
   exists (i1 : int),
     0 <= i1 < d /\
     nth witness pkWOTSs'{1} i1 = nth witness pkWOTSs{1} i1 /\
     (if i1 = 0 then m'{1} else nth witness rootss'{1} (i1 - 1)) <>
     if i1 = 0 then nth witness ml{1} (Index.val idx'{1})
     else nth witness rootss{1} (i1 - 1))
  =>
    m'{2} <> m{2}
    /\ 0 <= i{2} < size O_MEUFGCMA_WOTSC_Default.qs{2}
    /\ pkWOTS{2} = DBLL.insubd (mkseq (fun (k : int) =>
         cf ps{2} (set_chidx ad{2} k)
           (BaseW.val (encode_msgWOTS_C ps{2} ad{2} m'{2} (sigc'{2}).`2).[k])
           (w - 1 - BaseW.val (encode_msgWOTS_C ps{2} ad{2} m'{2} (sigc'{2}).`2).[k])
           (DigestBlock.val (nth witness (DBLL.val (sigc'{2}).`1) k))) len)
    /\ predC (ThC ps{2} ad{2} m'{2} (sigc'{2}).`2)).
+ wp => /=.
  while (   ={pkWOTSs, rootss, pkWOTSs', rootss', tkpidxs, tidx, kpidx, root'}
         /\ ps{1} = ps0{2}
         /\ ad{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad{2}
         /\ pkWOTStd{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2}
         /\ rootstd{1} = R_MEUFGCMAWOTSC_EUFNAGCMA_C.rootstd{2}
         /\ sig'{1} = sig'{2}
         /\ m'{1} = m'0{2}
         /\ root'{2} = nth witness (m'0{2} :: rootss'{2}) (size rootss'{2})
         /\ 0 <= tidx{2}
         /\ (size pkWOTSs'{2} < d =>
               tidx{2} < nr_trees (size pkWOTSs'{2}) * l')
         /\ (size pkWOTSs'{2} < d =>
                tidx{2} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (Index.val idx'{2}, 0) (size pkWOTSs'{2})).`1 /\
                kpidx{2} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (Index.val idx'{2}, 0) (size pkWOTSs'{2})).`2)
         /\ (forall (i : int), 0 <= i < size pkWOTSs{2} =>
               nth witness pkWOTSs{2} i
               =
               nth witness (nth witness (nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd{2} i) (nth witness tkpidxs{2} i).`1) (nth witness tkpidxs{2} i).`2)
         /\ (forall (i : int), 0 <= i < size rootss{2} =>
               nth witness rootss{2} i
               =
               nth witness (nth witness R_MEUFGCMAWOTSC_EUFNAGCMA_C.rootstd{2} i) (nth witness tkpidxs{2} i).`1)
         /\ (forall (i : int), 0 <= i < size pkWOTSs'{2} =>
               nth witness pkWOTSs'{2} i
               =
               DBLL.insubd (mkseq (fun (j : int) =>
                    cf ps0{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad{2} i (nth witness tkpidxs{2} i).`1)
                                                                chtype) (nth witness tkpidxs{2} i).`2) j)
                             (BaseW.val (encode_msgWOTS_C ps0{2} (set_kpidx (set_typeidx (set_ltidx R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad{2} i (nth witness tkpidxs{2} i).`1) chtype) (nth witness tkpidxs{2} i).`2) (nth witness (m'0{2} :: rootss'{2}) i) ((nth witness sig'{2} i).`1.`2)).[j])
                             (w - 1 - BaseW.val (encode_msgWOTS_C ps0{2} (set_kpidx (set_typeidx (set_ltidx R_MEUFGCMAWOTSC_EUFNAGCMA_C.ad{2} i (nth witness tkpidxs{2} i).`1) chtype) (nth witness tkpidxs{2} i).`2) (nth witness (m'0{2} :: rootss'{2}) i) ((nth witness sig'{2} i).`1.`2)).[j])
                             (DigestBlock.val (nth witness (DBLL.val (nth witness sig'{2} i).`1.`1) j))) len))
         /\ (forall (i : int), 0 <= i < size tkpidxs{2} =>
               (nth witness tkpidxs{2} i).`1 = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (Index.val idx'{2}, 0) (i + 1)).`1 /\
               (nth witness tkpidxs{2} i).`2 = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (Index.val idx'{2}, 0) (i + 1)).`2)
         /\ (forall (i : int), 0 <= i < size tkpidxs{2} =>
               0 <= (nth witness tkpidxs{2} i).`1 < nr_trees i /\
               0 <= (nth witness tkpidxs{2} i).`2 < l')
         /\ size pkWOTSs'{2} = size pkWOTSs{2}
         /\ size pkWOTSs'{2} = size rootss{2}
         /\ size pkWOTSs'{2} = size rootss'{2}
         /\ size pkWOTSs'{2} = size tkpidxs{2}
         /\ size pkWOTSs'{2} <= d
         /\ allOkC{1} = all idfun (mkseq (fun (i : int) =>
               predC (ThC ps{1} (set_kpidx (set_typeidx (set_ltidx ad{1} i (nth witness tkpidxs{1} i).`1) chtype) (nth witness tkpidxs{1} i).`2)
                                (nth witness (m'{1} :: rootss'{1}) i) ((nth witness sig'{1} i).`1.`2))) (size pkWOTSs'{1}))).
  * inline{1} 3; inline{2} 3.
    wp => /=.
    while (   ={ad0, pkWOTS_l}
           /\ ps0{1} = ps1{2}
           /\ sigWOTS0{1} = sigWOTS{2}
           /\ em0{1} = em{2}
           /\ pkWOTS_l{2} = mkseq (fun (i : int) =>
                  cf ps1{2} (set_chidx ad0{2} i) (BaseW.val em{2}.[i]) (w - 1 - BaseW.val em{2}.[i])
                     (DigestBlock.val (nth witness (DBLL.val sigWOTS{2}) i))) (size pkWOTS_l{2})
           /\ size pkWOTS_l{2} <= len).
    + wp; skip => /> &2 pkwdef _ ltlen_szpkw.
      by rewrite size_rcons mkseqS 1:size_ge0 /= {1}pkwdef; smt(size_rcons).
    wp; skip => /> &1 &2 tidxbnd tidxfld pkwrel rsrel pkwpdef tkpidef tkpirng eqszpkwp eqszpkwprs eqszpkwprsp eqszpkwptkpi ledszpkwp ltd_szpkwp.
    split => [| pkwlR _ /lezNgt gelen_szpkwlR pkwlRdef lelen_szpkwlR]; first by rewrite mkseq0 /=; smt(ge2_len).
    (* C1 root'{2} *)
    split; first by rewrite nth_rcons size_rcons; smt(size_ge0).
    (* C2 0 <= tidx %/ l' *)
    split; first by rewrite divz_ge0; smt(ge2_lp).
    (* C3 tidx %/ l' < nr_trees (size+1) *)
    split.
    + move=> ltd1; rewrite ltz_divLR; 1: smt(ge2_lp).
      have szlt : size pkWOTSs'{1} < d by smt(size_rcons).
      apply (IntOrder.ltr_le_trans (nr_trees (size pkWOTSs'{1}) * l')); 1: exact (tidxbnd szlt).
      rewrite size_rcons /nr_nodes_ht /nr_trees /nr_nodes /l' /=.
      have h0 : 0 <= h' by smt(ge1_hp).
      have hA : 0 <= h' * (d - size pkWOTSs'{1} - 1) by smt(ge1_hp size_rcons).
      have hB : 0 <= h' * (d - (size pkWOTSs'{1} + 1) - 1) by smt(ge1_hp size_rcons).
      have hC : 0 <= h' * (d - (size pkWOTSs'{1} + 1) - 1) + h' by smt().
      rewrite -!exprD_nneg //.
      by rewrite lez_eqVlt; left; congr; smt().
    (* C4 tidx fold *)
    split; first by move=> ltd1; rewrite size_rcons foldS 1:size_ge0 /= /#.
    (* C5 pkWOTSs char *)
    split.
    + move=> i1 ge0i1 lti1; move: lti1; rewrite size_rcons => lti1.
      rewrite !nth_rcons -eqszpkwp -eqszpkwptkpi.
      by case (i1 < size pkWOTSs'{1}) => /#.
    (* C6 rootss char *)
    split.
    + move=> i1 ge0i1 lti1; move: lti1; rewrite size_rcons => lti1.
      rewrite !nth_rcons -eqszpkwprs -eqszpkwptkpi.
      by case (i1 < size pkWOTSs'{1}) => /#.
    (* C7 pkWOTSs' char *)
    split.
    + move=> i1 ge0i1 lti1; move: lti1; rewrite size_rcons => lti1.
      rewrite !nth_rcons -eqszpkwptkpi.
      case (i1 < size pkWOTSs'{1}) => [ltszpki1 /= | nltszpki1].
      - rewrite pkwpdef 1://; do 2! congr; rewrite fun_ext => k.
        by case (i1 = 0) => [// | /#].
      rewrite (: i1 = size pkWOTSs'{1}) 1:/# pkwlRdef -eqszpkwprsp /=.
      do 2! congr => [| /#].
      rewrite fun_ext => k.
      by case (size pkWOTSs'{1} = 0) => [// | /#].
    (* C8 tkpidxs fold *)
    split.
    + move=> i1 ge0i1 lti1; move: lti1; rewrite size_rcons => lti1.
      rewrite !nth_rcons -eqszpkwptkpi.
      case (i1 < size pkWOTSs'{1}) => [/# | nltszpki1].
      by rewrite (: i1 = size pkWOTSs'{1}) 1:/# /= foldS 1:size_ge0 /= /#.
    (* C9 tkpidxs range *)
    split.
    + move=> i1 ge0i1 lti1; move: lti1; rewrite size_rcons => lti1.
      rewrite !nth_rcons -eqszpkwptkpi.
      case (i1 < size pkWOTSs'{1}) => [/# | nltszpki1].
      rewrite (: i1 = size pkWOTSs'{1}) 1:/# /= divz_ge0 2:modz_ge0 3:ltz_pmod 4:/=; 1..3: smt(ge2_lp).
      by rewrite ltz_divLR; smt(ge2_lp).
    (* C10-C14 sizes *)
    split; first by rewrite !size_rcons /#.
    split; first by rewrite !size_rcons /#.
    split; first by rewrite !size_rcons /#.
    split; first by rewrite !size_rcons /#.
    split; first by rewrite !size_rcons /#.
    (* C15 allOkC = all idfun (mkseq predCexpr (size+1)) *)
    rewrite size_rcons mkseqS 1:size_ge0 all_idfun_rcons; congr.
    + congr; rewrite &(eq_in_mkseq) => i [ge0i lti] /=.
      rewrite !nth_rcons -eqszpkwptkpi -eqszpkwprsp.
      by rewrite (: i < size pkWOTSs'{1}) 1:// (: i - 1 < size pkWOTSs'{1}) 1:/# /=.
    + rewrite /= !nth_rcons -eqszpkwptkpi -eqszpkwprsp /=; smt(size_ge0).
  wp => /=.
  call (: true).
  wp; skip => /> &1 &2 qsnth allchqs uqwgpqs szqs allnchtws msigidx.
  split; last first.
  move=> pkw pkw' rs rs' ti tkpi ged1 ged2 ge0ti pkwrel rsrel pkwpdef tkpidef tkpirng eqszpkwp eqszpkwrs eqszpkwrsp eqszpkwtkpi ledszpkw allokdef.
  move=> rmatch allok isfr i ge0_i ltd_i eqipkw neqimrs.
  pose zs := zip _ _; pose cidx := find _ _.
  have hascidx :
    has (fun (x : ((pkWOTS * pkWOTS) * msgFLSLXMSSMTTW) * msgFLSLXMSSMTTW) =>
              x.`1.`1.`1 = x.`1.`1.`2 /\ x.`1.`2 <> x.`2) zs.
  + rewrite -(has_nthP _ _ (((witness, witness), witness), witness)) /=.
    exists i; rewrite -(: d = size zs) 1:/zs 1:?size_zip /= 1:/#.
    split => [/#|].
    rewrite /zs ?nth_zip_cond ?size_zip ?lez_minl 1..7:/#.
    by rewrite (: i < size pkw') 1:/# //.
  have ge0_cidx : 0 <= cidx by rewrite find_ge0.
  have ltd_cidx : cidx < d.
  + by rewrite /cidx (: d = size zs) 1:/zs 1:?size_zip /= 1:/# -has_find.
  move /(nth_find (((witness, witness), witness), witness)): (hascidx) => /= @-/cidx.
  rewrite /zs ?nth_zip_cond ?size_zip ?lez_minl 1..7:/#.
  rewrite (: cidx < size pkw') 1:/# /= => -[eqpk neqrs].
  rewrite qsnth 1:// 1,2:tkpirng 1,2:/# /=.
  split; 1: rewrite ?tkpidef 1,2:/# 1:// foldS 1:// /= -divz_eq.
  + case (cidx = 0) => [-> /= | neq0_cidx]; 1: by rewrite fold0.
    move: neqrs; rewrite neq0_cidx /=.
    by rewrite -(tkpidef (cidx - 1) _) 1:/# 1:// /= rsrel 1:/#.
  split.
  + rewrite szqs; split => [| _].
    * have szt : 0 <= cidx < size tkpi by smt().
      have := tkpirng cidx szt.
      have hb : 0 <= Bigint.BIA.bigi predT nr_trees 0 cidx.
      + by rewrite Bigint.sumr_ge0 => j _; rewrite /nr_trees StdOrder.IntOrder.expr_ge0.
      smt(ge2_lp).
    rewrite mulr_suml /nr_nodes_ht /nr_nodes /= -/l'.
    rewrite (big_cat_int cidx 0 d) 1:// 1:/#.
    rewrite -addrA ltr_add2l (IntOrder.ltr_le_trans (nr_trees cidx * l')).
    * rewrite (: nr_trees cidx * l' = (nr_trees cidx - 1) * l' + l') 1:/#.
      by rewrite ler_lt_add 1:ler_wpmul2r; smt(ge2_lp).
    rewrite (big_cat_int (cidx + 1)) 1,2:/# big_int1 /= ler_addl sumr_ge0 => j _ /=.
    by rewrite mulr_ge0 expr_ge0.
  split.
  + by rewrite -pkwrel 1:/# -eqpk pkwpdef 1:/#.
  (* +C okC DISCHARGE: the extracted layer cidx's +C constant-sum gate holds,
     recovered from the aggregate hypertree gate allOkC = true (= allok, the
     per-layer okC list all-true) via all_idfun_nth at cidx. *)
  have hcidxr : 0 <= cidx < size pkw' by smt().
  have hnth := all_idfun_nth _ cidx allok _; first by rewrite size_mkseq; smt().
  by move: hnth; rewrite nth_mkseq 1:/# /=.
  + have hidxb : Index.val msigidx.`3 < nr_trees 0 * l'.
    + have [_ hb] := Index.valP msigidx.`3.
      have hl : nr_trees 0 * l' = 2 ^ (h' * d).
      + rewrite /nr_trees /nr_nodes_ht /nr_nodes /l' /=.
        have hd : 0 <= h' * (d - 1) by smt(ge1_hp ge1_d).
        have h0 : 0 <= h' by smt(ge1_hp).
        rewrite -exprD_nneg //.
        by rewrite (: h' * (d - 1) + h' = h' * d) 1:/#.
      by rewrite hl; move: hb; rewrite /l /h; smt().
    rewrite !fold0 mkseq0 /=.
    do! split; smt(Index.valP).
inline{2} 1.
wp.
while{2} (   pkWOTS_l{2} = mkseq (fun (k : int) => cf ps1{2} (set_chidx ad0{2} k)
                (BaseW.val em{2}.[k]) (w - 1 - BaseW.val em{2}.[k])
                (DigestBlock.val (nth witness (DBLL.val sig0{2}) k))) (size pkWOTS_l{2})
          /\ size pkWOTS_l{2} <= len)
         (len - size pkWOTS_l{2}).
- move=> &m0 z. by wp; skip => />; smt(size_rcons size_ge0 mkseqS).
wp; skip => /> &1 &2 Qimpl.
split; 1: by rewrite mkseq0 /=; smt(ge2_len).
move=> pkwlR; split; first by smt().
move=> gelen eqpkwlR szle szsig rm allok isf iw ge0iw ltiwd nthpkw rmm.
have hA :
  (((size sig'{1} = d /\
     ((if d = 0 then m'{1} else nth witness rootss'{1} (d - 1)) =
      if d = 0 then nth witness ml{1} (Index.val idx'{1})
      else nth witness rootss{1} (d - 1)) /\
     allOkC{1}) /\
    is_fresh{1}) /\
   exists (i1 : int),
     0 <= i1 < d /\
     nth witness pkWOTSs'{1} i1 = nth witness pkWOTSs{1} i1 /\
     (if i1 = 0 then m'{1} else nth witness rootss'{1} (i1 - 1)) <>
     if i1 = 0 then nth witness ml{1} (Index.val idx'{1})
     else nth witness rootss{1} (i1 - 1)) by smt().
have [#] neqm ge0i ltiqs pkrec okc := Qimpl hA.
have szeq : size pkwlR = len by smt().
have insubdeq : DBLL.insubd pkwlR = pkWOTS{2}.
+ by rewrite pkrec; congr; rewrite {1}eqpkwlR szeq.
by rewrite insubdeq okc neqm ge0i ltiqs /=.
qed.


(* ==========================================================================
   ==========================================================================
   T2 / COMPOSE:  CHAINING BRANCH-1 WITH THE LEAF BOUND,
                  AND THE RULING ON THE FORGE-SOUNDNESS RESIDUAL.
   ==========================================================================
   ==========================================================================

   PART I -- TERM-ALIGNMENT AUDIT (done BEFORE attempting the chain, as required:
   if anything had mismatched, the mismatch -- not a forced proof -- is the
   deliverable).  Both statements are in THIS file; quoting them verbatim:

     seam_branch1_WOTSC (:1889) concludes
       Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A_ht, FC.O_THFC_Default).main() @ &m :
            res /\ EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES]
       <= Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
                O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]

     leaf_reduction_MEUFGCMAWOTSC_bound (:1054) concludes
          Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
                O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
       <= Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
        + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                STCRC_WC.O_STCRC_Default).main() @ &m : res]

   (1) PIVOT TERM.  seam's RHS and leaf's LHS are the SAME Pr-expression, not
       merely "the same up to renaming": same game functor M_EUF_GCMA_WOTSC_NPRF,
       same adversary expression R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht) applied to the
       same A_ht, same TWO oracle arguments in the same order
       (O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default), same memory &m, same event
       `res`.  NO oracle-instantiation mismatch.  (In particular the seam does NOT
       leave the O_MEUFGCMA_WOTSC_V hop dangling: EqPr_MEUFGCMAWOTSC_Orig_V (:1840)
       is applied INSIDE seam_branch1_WOTSC's proof, so its STATEMENT is back on the
       _Default oracle -- exactly the leaf bound's LHS.)

   (2) PREMISES.  leaf's list is a PREFIX of seam's:
         seam : hc, hembdisj, hembinj, hencb, hdf8n, hdflen, hdf2, A_wf_ht, allnchads
         leaf : hc, hembdisj, hembinj, hencb, hdf8n, hdflen, hdf2, A_wf_ht
       The shared 8 are syntactically identical (A_wf_ht is the same member-based
       hoare judgement on A_ht(O_THFC_MA).choose in both).  seam additionally needs
       the TYPE-based `allnchads` on A_ht(FC.O_THFC_Default).choose.  So the
       composition's premise set = seam's 9; nothing is dropped, nothing is
       silently strengthened.

   (3) MODULE RESTRICTIONS.  leaf's restriction set is a SUBSET of seam's:
         leaf : {R_int_STCRC, R_int_WOTSTW, O_MEUFGCMA_WOTSC_Default,
                 O_MEUFGCMA_WOTSTWESNPRF, STCRC_WC.O_STCRC_Default,
                 FC.O_THFC_Default, O_THFC_MA, G0_INT,
                 R_MEUFGCMAWOTSC_EUFNAGCMA_C}
         seam : leaf's set + {EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C, O_MEUFGCMA_WOTSC_V}
       Declaring the composed A_ht with SEAM's (strictly larger) restriction set
       therefore satisfies leaf's requirement as well -- more disjointness is a
       stronger hypothesis on A_ht.  This also RETIRES the open worry recorded in
       seam_branch1_WOTSC's own STATEMENT NOTE (":1930": the added
       `-EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C` restriction was "NOT YET re-checked to
       still discharge at the downstream ler_add consumer"): it discharges, and the
       lemma below is the machine-check of that.

   CONCLUSION OF THE AUDIT: no mismatch. The chain is a bare transitivity step.
   ========================================================================== *)

lemma seam_branch1_leaf_composed
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V }) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (a b : adrs),
       get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b) => get_wgpidxs a = get_wgpidxs b) =>
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC <> 8 * n =>
    dfC <> 8 * n * len =>
    dfC <> 8 * n * 2 =>
    hoare[ A_ht(O_THFC_MA).choose :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma ] =>
    hoare[ A_ht(FC.O_THFC_Default).choose :
             FC.O_THFC_Default.tws = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws ] =>
    Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A_ht, FC.O_THFC_Default).main() @ &m :
         res /\ EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                         STCRC_WC.O_STCRC_Default).main() @ &m : res].
proof.
move=> hc hembdisj hembinj hencb hdf8n hdflen hdf2 A_wf_ht allnchads.
have hseam := seam_branch1_WOTSC A_ht &m hc hembdisj hembinj hencb
                hdf8n hdflen hdf2 A_wf_ht allnchads.
have hleaf := leaf_reduction_MEUFGCMAWOTSC_bound A_ht &m hc hembdisj hembinj hencb
                hdf8n hdflen hdf2 A_wf_ht.
smt().
qed.


(* ==========================================================================
   PART II -- THE FORGE-SOUNDNESS CORRESPONDENCE, MACHINE-CHECKED.

   The verdict in PART III turns on one factual claim that is easy to assert and
   easy to get wrong, so it is PROVEN here rather than asserted:

     R_MEUFGCMAWOTSC_EUFNAGCMA_C.forge's layer selector (:826)
        cidx <- find (fun x => x.`1.`1.`1 = x.`1.`1.`2 /\ x.`1.`2 <> x.`2)
                     (zip (zip (zip pkWOTSs' pkWOTSs) (m' :: rootss'))
                          (nth witness ml (Index.val idx') :: rootss))
     SUCCEEDS -- i.e. lands in range 0 <= cidx < d -- on EXACTLY the runs where the
     V-game's bucket flag (:1561)
        valid_WOTSTWES <- exists i, 0 <= i < d
                            /\ nth witness pkWOTSs' i = nth witness pkWOTSs i
                            /\ nth witness (m' :: rootss') i
                               <> nth witness (nth witness ml (Index.val idx') :: rootss) i
     is TRUE.

   Consequence used in PART III: the bucket restriction on seam_branch1_WOTSC's LHS
   event is NOT a weakening of R_leaf_C's forge obligation -- it is precisely that
   obligation's domain.  Off the bucket, R_leaf_C.forge has, BY CONSTRUCTION, no
   layer to select and is not supposed to win; the pkco / trh buckets are the two
   tree reductions' job.

   Stated over plain lists at the sizes the games guarantee (pk cubes of size d,
   the two root-chains of size d+1 because of the `m' ::` / `ml[idx'] ::` cons);
   instantiate mr' := m' :: rootss', mr := nth witness ml (Index.val idx') :: rootss.
   ========================================================================== *)
lemma find_inrange_iff_validWOTSTWES
  (pkWOTSs' pkWOTSs : pkWOTS list) (mr' mr : dgstblock list) :
  size pkWOTSs' = d => size pkWOTSs = d =>
  size mr' = d + 1 => size mr = d + 1 =>
  (   find (fun (x : ((pkWOTS * pkWOTS) * dgstblock) * dgstblock) =>
              x.`1.`1.`1 = x.`1.`1.`2 /\ x.`1.`2 <> x.`2)
           (zip (zip (zip pkWOTSs' pkWOTSs) mr') mr)
      < d
   <=>
      exists (i : int), 0 <= i < d
        /\ nth witness pkWOTSs' i = nth witness pkWOTSs i
        /\ nth witness mr' i <> nth witness mr i).
proof.
move=> hs1 hs2 hs3 hs4.
have hz1 : size (zip pkWOTSs' pkWOTSs) = d by rewrite size_zip hs1 hs2 /#.
have hz2 : size (zip (zip pkWOTSs' pkWOTSs) mr') = d by rewrite size_zip hz1 hs3 /#.
have hz3 : size (zip (zip (zip pkWOTSs' pkWOTSs) mr') mr) = d by rewrite size_zip hz2 hs4 /#.
have key : forall (i : int), 0 <= i < d =>
  nth witness (zip (zip (zip pkWOTSs' pkWOTSs) mr') mr) i
  = (((nth witness pkWOTSs' i, nth witness pkWOTSs i), nth witness mr' i),
     nth witness mr i).
+ move=> i rngi.
  have ltid : i < d by smt().
  rewrite nth_zip_cond hz3 ltid /= nth_zip_cond hz2 ltid /=.
  rewrite nth_zip_cond hz1 ltid /=.
  by smt(nth_change_dfl).
rewrite -hz3 -has_find -(has_nthP _ _ witness) hz3.
split.
+ move=> [i] [rngi hp]; exists i; split; first exact rngi.
  by move: hp; rewrite (key i rngi) /=.
move=> [i] [rngi hp]; exists i; split; first exact rngi.
by move: hp; rewrite (key i rngi) /=.
qed.


(* ==========================================================================
   PART III -- RULING ON THE FORGE-SOUNDNESS RESIDUAL.

   THE CLAIM UNDER TEST.  The SCOPE note attached to leaf_reduction_MEUFGCMAWOTSC_
   bound (:1048-1053) reads, verbatim:

     "D1-COMPOSITION LEG ONLY.  This bounds `M_EUF_GCMA_WOTSC_NPRF(R_leaf_C(A_ht))`,
      NOT `EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A_ht)`.  The reduction-SOUNDNESS direction
      (a hypertree forgery yields a WOTS+C forgery, i.e. `forge` selection
      correctness) is DEFERRED: `forge` here is type-correct + MM45-faithful in
      structure but its selection correctness is unproven.  So the leaf reduction
      is NOT yet sound end-to-end."

   That paragraph bundles THREE claims.  They no longer share a truth value, so the
   ruling is a SPLIT VERDICT, claim by claim.

   ------------------------------------------------------------------------------
   (a) "bounds the WOTS+C game, NOT the hypertree game"  --  STILL TRUE, unchanged.
   ------------------------------------------------------------------------------
   True of leaf_reduction_MEUFGCMAWOTSC_bound TAKEN ALONE, and it stays true: that
   lemma's LHS is a M_EUF_GCMA_WOTSC_NPRF probability.  What changes is that it is no
   longer taken alone -- seam_branch1_leaf_composed above supplies the missing left
   leg, so the CHAIN starts from a hypertree-game probability.

   ------------------------------------------------------------------------------
   (b) "`forge` selection correctness is unproven"  --  NOW FALSE.  STALE NOTE.
   ------------------------------------------------------------------------------
   seam_branch1_WOTSC (:1889) proves precisely this direction.  Evidence, in the
   order it should be checked:

     E1.  THE STATEMENT.  Its conclusion is
            Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A_ht, FC.O_THFC_Default).main() @ &m :
                 res /\ EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES]
            <= Pr[M_EUF_GCMA_WOTSC_NPRF(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht),
                    O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
          LHS event: the hypertree adversary produced a VALID (`is_valid`, the real
          +C verify: size-d gate, root-match, and the constant-sum gate `allOkC`) and
          FRESH forgery, AND that forgery lies in the WOTS bucket.  RHS event: the
          reduction R_leaf_C(A_ht) WINS the WOTS+C M-EUF-GCMA game.  A probability
          bound in that direction IS the reduction-soundness direction; there is no
          other content to "forge selection correctness".
          PRECISION.  What is discharged is the CONDITIONAL "bucket win implies
          R_leaf_C win".  The REACHABILITY of the bucket -- that a real forgery must
          land in one of the three buckets at all, i.e. the flag disjunction
          res => valid_WOTSTWES \/ valid_TCRPKCO \/ valid_TCRTRH that MM45 gets from
          its two `Pr[mu_split]`s -- is a SEPARATE obligation and lives in R2 below.
          So this bound must not be read as vacuously satisfiable-by-emptiness: it is
          a conditional whose completeness partner is tracked, not assumed.

     E2.  THE LOAD-BEARING PROOF STEP.  The `conseq` at :2559 discharges exactly the
          implication (transcribed, with the unfolded +C `is_valid{1}` on the left):
            ((size sig'{1} = d  /\  <root-match>  /\  allOkC{1}) /\ is_fresh{1})
            /\ (exists i1, 0 <= i1 < d
                  /\ nth pkWOTSs'{1} i1 = nth pkWOTSs{1} i1
                  /\ <the i1-th roots differ>)
            =>  is_valid{2} /\ m'{2} <> m{2}
                /\ 0 <= i{2} < size O_MEUFGCMA_WOTSC_Default.qs{2}
          Antecedent = V's win event conjoined with the bucket-flag BODY; consequent
          = the WOTS+C game's win event (challenge-index verify, WOTS-message
          freshness, index in range).  Nothing else is assumed.

     E3.  THE +C-SPECIFIC HALF IS INSIDE THE PROVEN PART.  The `seq 15 18` post at
          :2603 carries, besides `m'{2} <> m{2}` and the index range, BOTH
            * the pk-reconstruction equation
                pkWOTS{2} = DBLL.insubd (mkseq (fun k => cf ps{2} (set_chidx ad{2} k)
                              ... (DigestBlock.val (nth witness (DBLL.val sigc'{2}.`1) k))) len)
              -- the WOTS pk-match at the extracted layer, and
            * `predC (ThC ps{2} ad{2} m'{2} (sigc'{2}).`2)`
              -- the +C CONSTANT-SUM gate `okC` at the extracted layer.
          So the +C-discriminating step (propagating V's GLOBAL `allOkC{1}` to the
          SELECTED layer's `okC{2}` through the address/root/counter alignment) is
          part of what is proven, not something the discharge assumes.

     E4.  0-ADMIT CERTIFICATE.  `bash ec-certify.sh drafts/_compose_wip.ec` returns
          compile=OK / admit-tactics=0 / axiom-decls=0 on this file, which is a COPY
          of the seam file plus PARTS I-III.  The compile is a FULL FRESH elaboration
          (this filename had no cached .eco), so seam_branch1_WOTSC's entire proof --
          including the `#B` reconstruction/okC-propagation establishment -- is
          admit-free and axiom-free.

     E5.  A STALE INLINE COMMENT, FLAGGED.  The prose at :2596-2602 still says the
          discriminating okC step "lives ENTIRELY in the admitted establishment #B
          below and is NOT yet proven".  E4 CONTRADICTS it: there is no admit left in
          the file.  That comment is a survival from the draft in which #B was still
          admitted, and seam_branch1_WOTSC's own STATUS block (:1934, "2026-07-19,
          UPDATED") already records the closure.  The comment -- not the proof -- is
          what is out of date.  (Corollary: any downstream reader who trusted :2596
          over :1934 would UNDER-claim.  This appendix is the tie-breaker, decided by
          certificate rather than by prose.)

     E6.  THE BUCKET RESTRICTION IS NOT A LOOPHOLE -- and this is where the note's
          wording, not just its status, needs correcting.  The note glosses the
          obligation as "a hypertree forgery yields a WOTS+C forgery".  UNRESTRICTED,
          that gloss is FALSE -- and false BY DESIGN, not by a gap: a hypertree
          forgery that collides `pkco` or `trh` yields no WOTS+C forgery at all, and
          R_leaf_C is not the reduction meant to catch it.  The correct obligation on
          R_leaf_C is the BUCKET-RESTRICTED one, and find_inrange_iff_validWOTSTWES
          (PART II) proves that the restriction is exactly R_leaf_C.forge's own
          selection domain: its `find` (:826) lands in range 0 <= cidx < d on exactly
          the runs where `valid_WOTSTWES` (:1561) holds.  Hence branch-1's
          bucket-restricted statement is not a weakened version of the obligation --
          it is the whole of it.  No larger forge-soundness claim about R_leaf_C
          remains unproven.

   ------------------------------------------------------------------------------
   (c) "the leaf reduction is NOT yet sound end-to-end"  --  READING-DEPENDENT.
   ------------------------------------------------------------------------------
   This is the sentence most likely to be mis-cited in either direction, so both
   readings are stated explicitly:

     READING 1 -- "R_leaf_C.forge selects correctly; a WOTS-bucket hypertree forgery
     yields a WOTS+C forgery."   ==>  the sentence is now FALSE.  Proven: E1-E6.

     READING 2 -- "the leaf reduction, on its own, bounds the REAL hypertree
     EUF-NAGCMA game."           ==>  the sentence remains TRUE.  But the obstruction
     is NOT forge-selection; it is R1 + R2 below.

   ------------------------------------------------------------------------------
   WHAT GENUINELY REMAINS.  None of it is forge-soundness.
   ------------------------------------------------------------------------------
   R1.  THE REAL -> C -> V GAME HOPS ARE ABSENT FROM THE PORT.  seam_branch1_WOTSC's
        LHS is the _V_ game.  Both instrumented games are DEFINED here
        (EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C :1110, ..._V :1352) but neither hop lemma
        exists.  VERIFIED SCOPE (not asserted): a recursive grep over ALL of drafts/
        for `Orig_C` / `_C_V` / `Eqv_EUFNAGCMA` / `Eqv_.*Orig` returns no DECLARATION
        at all -- the declaration-level grep
          grep -rnE "^\s*(local\s+)?(lemma|equiv)\s+\w*(Orig_C|_C_V|EUFNAGCMA_.*Orig)" drafts/
        is EMPTY.  Every textual hit is either the V-game header's own admission,
        "compile does NOT prove Eqv_C_V" (:1351, replicated verbatim in each
        reduction-family draft), or -- and this is the one that must NOT be
        miscounted as the missing hop -- the ORACLE-level challenge swap
        `Eqv_O_MEUFGCMA_WOTSC_query_Orig_V` (:1681) / `EqPr_MEUFGCMAWOTSC_Orig_V`
        (:1840).  Those hop between the two WOTS+C CHALLENGE ORACLES
        (O_MEUFGCMA_WOTSC_Default vs _V) INSIDE the RHS game, and are already
        consumed inside seam_branch1_WOTSC.  They are a DIFFERENT hop from the
        GAME-level real -> C -> V equivalences, which remain unported.  MM45 has both (FL_SL_XMSS_MT_ES.ec:3512 real~C, :3963 C~V) and
        uses them at :4102 to rewrite Pr[real] into Pr[V].  Until they are ported,
        NOTHING in this file bounds
          Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A_ht, FC.O_THFC_Default).main() @ &m : res].

   R2.  THE OTHER TWO BUCKETS.  MM45 splits Pr[V : res] with two `Pr[mu_split]`s
        (:4105 on valid_WOTSTWES, :4697 on valid_TCRPKCO, :5326 on valid_TCRTRH).
        Branch 1 is what composes above; the complement
          Pr[V : res /\ !valid_WOTSTWES]  <=  pkco-S-TCR + trh-S-TCR
        needs the two tree reductions.  Concurrently owned
        (drafts/_seam_tree_reductions_wip.ec) and OPEN.

   R3.  PREMISE DISCHARGE.  Both `A_wf_ht` (member axis, `<> dfC`) and `allnchads`
        (type axis, `<> chtype`) are CARRIED by the composition, not discharged --
        faithfully to MM45, whose XMSS-MT component theorem (:6306) likewise carries
        three such premises and discharges them only at the SPHINCS+ capstone
        (SPHINCS_PLUS.ec:4338), where the hypertree adversary is a controlled
        reduction image rather than an arbitrary A_ht.

   R4.  TCB / SCOPE OF THE CERTIFICATE.  `ec-certify` is FILE-LOCAL, and EasyCrypt's
        `require` does NOT re-verify a required theory.  Independently swept with the
        same nested-comment-stripped test, the transitively required drafts are each
        admit=0 / axiom=0: WOTS_C_Interactive, WOTS_C_Real, WOTS_C_Scheme,
        XMSSMT_C_Scheme.  The vendored MM45 development (FV-SPHINCSPLUS-EC) remains
        the cited, un-re-checked base TCB.

   ------------------------------------------------------------------------------
   BOTTOM LINE.  Branch-1 DOES discharge R_leaf_C's forge-selection soundness, and
   the composition therefore closes that residual: claim (b) of the :1048 note is
   stale and should be retired, and its "hypertree forgery yields a WOTS+C forgery"
   gloss should be restated in bucket-restricted form.  What survives is a DIFFERENT
   set of obligations -- the two missing game hops (R1) and the two other buckets
   (R2), plus the capstone premise discharge (R3).  "Not sound end-to-end" is still
   an accurate description of the leaf reduction's standalone reach, but it must no
   longer be attributed to `forge` selection correctness.
   ========================================================================== *)


(* ==========================================================================
   PART IV -- ANTI-VACUITY CONTROLS ACTUALLY RUN (both DECISIVE, both removed
   after running; reproduce by re-appending the perturbation and recompiling).

   CONTROL A (targets seam_branch1_leaf_composed's `smt()`).  Same lemma, same
   proof script, but the RHS S_TCR_C_Int_MA summand DROPPED:
     ... <= Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_leaf_C(A_ht)), ...) : res]
   RESULT: `[critical] cannot prove goal (strict)` at the `smt()`.
   WHAT IT RULES OUT: an inconsistent premise context (9 hypotheses + 2 `have`s --
   if those were jointly contradictory, `smt()` would close ANY conclusion, and the
   composed bound would be worthless).  It also shows the S-TCR summand is genuinely
   load-bearing rather than carried along decoratively, i.e. the chain really passes
   THROUGH the leaf bound instead of the seam bound alone implying the result.

   CONTROL B (targets find_inrange_iff_validWOTSTWES).  Same statement, same proof
   script, but the RHS existential's pk conjunct flipped from the WOTS bucket's
   EQUALITY to the pkco bucket's DISEQUALITY
     (nth pkWOTSs' i <> nth pkWOTSs i  in place of  nth pkWOTSs' i = nth pkWOTSs i).
   RESULT: `[critical] [by]: cannot close goals` at the closing step.
   WHAT IT RULES OUT: that the correspondence is a size/index artifact that would
   hold for ANY per-index predicate.  It is specifically the WOTS-bucket predicate
   that matches R_leaf_C.forge's selector -- which is exactly the claim PART III E6
   rests on.
   ========================================================================== *)


(* ===== HOP 2 : C ~ V ===== *)
equiv Eqv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF_C_V
  (A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{-EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C})
  (OC <: FSSLXMTWES.TRHC.Oracle_THFC{-EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C, -A}) :
  EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C(A, OC).main ~ EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A, OC).main :
    ={glob A, glob OC} ==> ={res}.
proof.
proc.
swap{1} 17 14.
conseq (: _ ==> ={is_valid, is_fresh}) => //.
swap{1} [12..13] 2; swap{2} [11..12] 2.
seq 13 12 : (={glob A, glob OC, ps, ad, ml, sigl, rootstd}).
+ seq 4 4 : (={glob A, glob OC, ad, ps, ml}); 1: by sim.
  seq 7 6 : (   ={glob A, glob OC, ad, ps, ml, leavestd, rootstd}
             /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness (nth witness (nth witness sigWOTStd{2} i) j) u
                   =
                   (nth witness (nth witness (nth witness sigWOTStd{1} i) j) u,
                    nth witness (nth witness (nth witness counterstd{1} i) j) u))).
  - while (   ={glob A, glob OC, ad, ps, ml, skWOTStd, pkWOTStd, leavestd, rootstd}
           /\ size sigWOTStd{1} = size skWOTStd{1}
           /\ size counterstd{1} = size skWOTStd{1}
           /\ size sigWOTStd{2} = size skWOTStd{1}
           /\ 0 <= size skWOTStd{1} <= d
           /\ (forall (i j u : int), 0 <= i < size skWOTStd{1} => 0 <= j < nr_trees i => 0 <= u < l' =>
                 nth witness (nth witness (nth witness sigWOTStd{2} i) j) u
                 =
                 (nth witness (nth witness (nth witness sigWOTStd{1} i) j) u,
                  nth witness (nth witness (nth witness counterstd{1} i) j) u))).
    + wp => /=.
      while (   ={glob A, glob OC, ad, ps, ml, skWOTStd, pkWOTStd, leavestd, rootstd,
                  skWOTSnt, pkWOTSnt, leavesnt, rootsnt, rootsntp}
             /\ size sigWOTStd{1} = size skWOTStd{1}
               /\ size counterstd{1} = size skWOTStd{1}
               /\ size sigWOTStd{2} = size skWOTStd{1}
               /\ 0 <= size skWOTStd{1} <= d
               /\ (forall (i j u : int), 0 <= i < size skWOTStd{1} => 0 <= j < nr_trees i => 0 <= u < l' =>
                     nth witness (nth witness (nth witness sigWOTStd{2} i) j) u
                     =
                     (nth witness (nth witness (nth witness sigWOTStd{1} i) j) u,
                      nth witness (nth witness (nth witness counterstd{1} i) j) u))
             /\ size sigWOTSnt{1} = size skWOTSnt{1}
               /\ size counternt{1} = size skWOTSnt{1}
               /\ size sigWOTSnt{2} = size skWOTSnt{1}
               /\ 0 <= size skWOTSnt{1} <= nr_trees (size skWOTStd{1})
               /\ 0 <= size skWOTStd{1} < d
               /\ (forall (j u : int), 0 <= j < size skWOTSnt{1} => 0 <= u < l' =>
                     nth witness (nth witness sigWOTSnt{2} j) u
                     =
                     (nth witness (nth witness sigWOTSnt{1} j) u,
                      nth witness (nth witness counternt{1} j) u))).
      - wp => /=.
        while (   ={glob A, glob OC, ad, ps, ml, skWOTStd, pkWOTStd, leavestd, rootstd,
                    skWOTSnt, pkWOTSnt, leavesnt, rootsnt, rootsntp,
                    skWOTSlp, pkWOTSlp, leaveslp}
               /\ size sigWOTStd{1} = size skWOTStd{1}
                 /\ size counterstd{1} = size skWOTStd{1}
                 /\ size sigWOTStd{2} = size skWOTStd{1}
                 /\ 0 <= size skWOTStd{1} <= d
                 /\ (forall (i j u : int), 0 <= i < size skWOTStd{1} => 0 <= j < nr_trees i => 0 <= u < l' =>
                       nth witness (nth witness (nth witness sigWOTStd{2} i) j) u
                       =
                       (nth witness (nth witness (nth witness sigWOTStd{1} i) j) u,
                        nth witness (nth witness (nth witness counterstd{1} i) j) u))
               /\ size sigWOTSnt{1} = size skWOTSnt{1}
                 /\ size counternt{1} = size skWOTSnt{1}
                 /\ size sigWOTSnt{2} = size skWOTSnt{1}
                 /\ 0 <= size skWOTSnt{1} <= nr_trees (size skWOTStd{1})
                 /\ 0 <= size skWOTStd{1} < d
                 /\ (forall (j u : int), 0 <= j < size skWOTSnt{1} => 0 <= u < l' =>
                       nth witness (nth witness sigWOTSnt{2} j) u
                       =
                       (nth witness (nth witness sigWOTSnt{1} j) u,
                        nth witness (nth witness counternt{1} j) u))
               /\ size sigWOTSlp{1} = size skWOTSlp{1}
                 /\ size counterlp{1} = size skWOTSlp{1}
                 /\ size sigWOTSlp{2} = size skWOTSlp{1}
                 /\ 0 <= size skWOTSlp{1} <= l'
                 /\ 0 <= size skWOTSnt{1} < nr_trees (size skWOTStd{1})
                 /\ (forall (u : int), 0 <= u < size skWOTSlp{1} =>
                       nth witness sigWOTSlp{2} u
                       =
                       (nth witness sigWOTSlp{1} u, nth witness counterlp{1} u))).
        * wp => /=.
          while (   ={glob A, glob OC, ad, ps, ml, skWOTStd, pkWOTStd, leavestd, rootstd,
                      skWOTSnt, pkWOTSnt, leavesnt, rootsnt, rootsntp,
                      skWOTSlp, pkWOTSlp, leaveslp, skWOTS, pkWOTS, sigWOTS, em, counter, root}
                 /\ size sigWOTStd{1} = size skWOTStd{1}
                   /\ size counterstd{1} = size skWOTStd{1}
                   /\ size sigWOTStd{2} = size skWOTStd{1}
                   /\ 0 <= size skWOTStd{1} <= d
                   /\ (forall (i j u : int), 0 <= i < size skWOTStd{1} => 0 <= j < nr_trees i => 0 <= u < l' =>
                         nth witness (nth witness (nth witness sigWOTStd{2} i) j) u
                         =
                         (nth witness (nth witness (nth witness sigWOTStd{1} i) j) u,
                          nth witness (nth witness (nth witness counterstd{1} i) j) u))
                 /\ size sigWOTSnt{1} = size skWOTSnt{1}
                   /\ size counternt{1} = size skWOTSnt{1}
                   /\ size sigWOTSnt{2} = size skWOTSnt{1}
                   /\ 0 <= size skWOTSnt{1} <= nr_trees (size skWOTStd{1})
                   /\ 0 <= size skWOTStd{1} < d
                   /\ (forall (j u : int), 0 <= j < size skWOTSnt{1} => 0 <= u < l' =>
                         nth witness (nth witness sigWOTSnt{2} j) u
                         =
                         (nth witness (nth witness sigWOTSnt{1} j) u,
                          nth witness (nth witness counternt{1} j) u))
                 /\ size sigWOTSlp{1} = size skWOTSlp{1}
                   /\ size counterlp{1} = size skWOTSlp{1}
                   /\ size sigWOTSlp{2} = size skWOTSlp{1}
                   /\ 0 <= size skWOTSlp{1} <= l'
                   /\ 0 <= size skWOTSnt{1} < nr_trees (size skWOTStd{1})
                   /\ (forall (u : int), 0 <= u < size skWOTSlp{1} =>
                         nth witness sigWOTSlp{2} u
                         =
                         (nth witness sigWOTSlp{1} u, nth witness counterlp{1} u))).
          + by auto.
          by auto; smt(size_rcons nth_rcons).
        by wp; skip => />; smt(ge2_lp size_rcons nth_rcons).
      wp; skip => />; smt(size_rcons nth_rcons expr_ge0 size_ge0).
    by wp; skip => />; smt(ge1_d size_ge0).
  while (   ={glob A, glob OC, ad, ps, ml, leavestd, rootstd, sigl}
         /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness (nth witness (nth witness sigWOTStd{2} i) j) u
                   =
                   (nth witness (nth witness (nth witness sigWOTStd{1} i) j) u,
                    nth witness (nth witness (nth witness counterstd{1} i) j) u))
         /\ 0 <= size sigl{1} <= l).
  + wp => /=.
    while (   ={glob A, glob OC, ad, ps, ml, leavestd, rootstd, sigl, sapl, tidx, kpidx}
           /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness (nth witness (nth witness sigWOTStd{2} i) j) u
                   =
                   (nth witness (nth witness (nth witness sigWOTStd{1} i) j) u,
                    nth witness (nth witness (nth witness counterstd{1} i) j) u))
           /\ 0 <= size sigl{1} < l
           /\ 0 <= tidx{1}
           /\ (size sapl{1} = 0 => tidx{1} = size sigl{1})
           /\ (0 < size sapl{1} => tidx{1} < nr_trees (size sapl{1} - 1))
           /\ 0 <= size sapl{1} <= d).
    - wp; skip => /> &1 &2 hcube ge0_szsigl ltl_szsigl ge0_ti htz hpos ge0_szsapl lesz ltd_szsapl.
      have hlp : 0 < l' by smt(ge2_lp).
      have ge0_tdvl : 0 <= tidx{2} %/ l' by smt(divz_ge0).
      have rng_tdvl : tidx{2} %/ l' < nr_trees (size sapl{2}).
      + rewrite (ltz_divLR tidx{2} (nr_trees (size sapl{2})) l' hlp).
        case (size sapl{2} = 0) => [eq0 | neq0].
        - rewrite (: nr_trees (size sapl{2}) * l' = l).
          * rewrite eq0 /nr_trees /l' /l /h -exprD_nneg 1:mulr_ge0; 1..3: smt(ge1_hp ge1_d).
            by congr; ring.
          by rewrite (htz eq0); exact ltl_szsigl.
        rewrite (: nr_trees (size sapl{2}) * l' = nr_trees (size sapl{2} - 1)).
        - rewrite /nr_trees /l' -exprD_nneg 1:mulr_ge0; 1..3: smt(ge1_hp ge1_d).
          by congr; ring.
        by apply hpos; smt().
      have rng_tmod : 0 <= tidx{2} %% l' < l' by smt(modz_ge0 ltz_pmod).
      have h1 : 0 <= size sapl{2} < d by smt().
      have h2 : 0 <= tidx{2} %/ l' < nr_trees (size sapl{2}) by smt().
      have h3 : 0 <= tidx{2} %% l' < l' by smt().
      rewrite (hcube (size sapl{2}) (tidx{2} %/ l') (tidx{2} %% l') h1 h2 h3) /=.
      smt(size_rcons).
    by wp; skip => />; smt(ge1_d size_rcons).
  by wp; skip => />; smt(ge2_l size_ge0).
seq 14 4 : (   ={is_fresh, ps, ad, m', sig', idx'}
            /\ pk{1} = (nth witness (nth witness rootstd (d - 1)) 0, ps, ad){2}).
+ while{1} (true) (d - size pkWOTSs'{1}).
  - move=> ? z.
    inline 3.
    wp => /=.
    while (true) (len - size pkWOTS_l).
    * move=> z'.
      by wp; skip => />; smt(size_rcons).
    by wp; skip => />; smt(size_rcons).
  wp; call (: true).
  by wp; skip => /> /#.
sp 3 0.
inline{1} 1; inline{1} 6 => />.
wp.
while (   i{1} = size pkWOTSs'{2}
       /\ ps1{1} = ps{2}
       /\ ad1{1} = ad{2}
       /\ tidx0{1} = tidx{2}
       /\ kpidx0{1} = kpidx{2}
       /\ sig1{1} = sig'{2}
       /\ root1{1} = root'{2}
       /\ allOkC0{1} = allOkC{2}
       /\ root'{2} = nth witness (m'{2} :: rootss'{2}) (size pkWOTSs'{2})
       /\ 0 <= tidx{2}
       /\ (size pkWOTSs'{2} < d => tidx{2} < nr_nodes_ht (size pkWOTSs'{2}) 0)
       /\ (size pkWOTSs'{2} < d =>
             tidx{2} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (Index.val idx'{2}, 0) (size pkWOTSs'{2})).`1)
       /\ (0 < size pkWOTSs'{2} < d =>
              tidx{2} = (nth witness tkpidxs{2} (size pkWOTSs'{2} - 1)).`1)
       /\ (0 < size pkWOTSs'{2} =>
            root{2} = nth witness (nth witness rootstd{2} (size pkWOTSs'{2} - 1)) (nth witness tkpidxs{2} (size pkWOTSs'{2} - 1)).`1)
       /\ (0 < size pkWOTSs'{2} =>
            nth witness rootss{2} (size pkWOTSs'{2} - 1)
            =
            nth witness (nth witness rootstd{2} (size pkWOTSs'{2} - 1)) (nth witness tkpidxs{2} (size pkWOTSs'{2} - 1)).`1)
       /\ (0 < size pkWOTSs'{2} < d =>
              0 <= (nth witness tkpidxs{2} (size pkWOTSs'{2} - 1)).`1 < nr_nodes_ht (size pkWOTSs'{2} - 1) 0)
       /\ (forall (i : int), 0 <= i < size pkWOTSs'{2} =>
             0 <= (nth witness tkpidxs{2} i).`1 < nr_nodes_ht i 0 %/ l')
       /\ (0 < size pkWOTSs'{2} => (nth witness tkpidxs{2} 0).`1 = Index.val idx'{2} %/ l')
       /\ (forall (i : int), 1 <= i < size pkWOTSs'{2} =>
             (nth witness tkpidxs{2} i).`1 = (nth witness tkpidxs{2} (i - 1)).`1 %/ l')
       /\ size rootss{2} = size pkWOTSs'{2}
       /\ size rootss'{2} = size pkWOTSs'{2}
       /\ size tkpidxs{2} = size pkWOTSs'{2}
       /\ size pkWOTSs'{2} <= d).
+ inline{1} 5; inline{2} 3.
  wp => /=.
  while (   ={em0}
         /\ ps2{1} = ps0{2}
         /\ ad2{1} = ad0{2}
         /\ pkWOTS_l{1} = pkWOTS_l{2}
         /\ sigWOTS1{1} = sigWOTS0{2}).
  - by wp; skip.
  wp; skip => /> &2 ge0_ti ubti tidef tirel rtrel rtlrel rngtkp rngtkpdv
                    fitkp sqtkp eqszpkrs eqszpkrsp eqsztkppk _ ltdszpk pk _ /lezNgt geszpk_len.
  rewrite ?nth_rcons ?size_rcons eqsztkppk eqszpkrs eqszpkrsp /=.
  have ge0_tdvl : 0 <= tidx{2} %/ l' by rewrite divz_ge0; 1: smt(ge2_lp).
  rewrite ge0_tdvl (: size pkWOTSs'{2} + 1 <> 0) 2:/=; 1:smt(size_ge0).
  rewrite foldS 1:size_ge0 /=; split => [ltd_pk1 |].
  - rewrite ltz_divLR; 1: smt(ge2_lp).
    move: (ubti _); 1: smt().
    rewrite /nr_nodes_ht /nr_trees /nr_nodesx /l'.
    by rewrite /= -?exprD_nneg ?addr_ge0 ?mulr_ge0 ?ge1_hp; smt(ge1_hp size_rcons).
  split => [/#|]; split.
  + move=> gt0_p1 ltd_p1.
    rewrite (StdOrder.IntOrder.ler_lt_trans tidx{2} _ _ _ (ubti _)) => [|/#].
    by rewrite leq_div; smt(ge2_lp).
  split => [i ge0_i ltszpk1_i |].
  - rewrite ?nth_rcons; case (i < size tkpidxs{2}) => [/# | ?].
    rewrite (: i = size tkpidxs{2}) 1:/# ge0_tdvl /=.
    rewrite ltz_divLR 2:divzK; 1,3: smt(ge2_lp).
    by rewrite /nr_nodes_ht /nr_nodesx dvdz_mull dvdzz.
  split => [?|]; 1: case (0 < size pkWOTSs'{2}) => [//|?].
  - rewrite (tidef _); 1: smt(ge1_d).
    by rewrite -(: 0 = size pkWOTSs'{2}) 1:/# /= fold0.
  split=> [i ge1_i ltsz1_i /= | /#].
  by rewrite ?nth_rcons; case (i < size tkpidxs{2}) => /#.
wp; skip => /> &2.
split => [| allOkC0 pk r rs ts' tidx tkpi /lezNgt ged_szpk _ ge0_ti rtrel rtsrel
             rngtkpi fitkpi sqtkpi eqszpkrs eqszpkrsp eqszpktkpi led_szpk].
+ rewrite /nr_nodes_ht /nr_trees /nr_nodesx /= -exprD_nneg 1:mulr_ge0; 1..3: smt(ge1_hp ge1_d).
  by rewrite mulrDr /= mulrN1 addrAC -addrA subrr /= -/l fold0 /=; smt(ge1_d Index.valP).
have eqd_szpk : size pk = d by smt().
have hne0 : d <> 0 by smt(ge1_d).
have hd0 : 0 < size pk by smt(ge1_d).
have h0 : (nth witness tkpi (d - 1)).`1 = 0.
+ case (d = 1) => [eq1d | neq1d].
  - by rewrite eq1d /= (fitkpi _) 1:/# pdiv_small 2://; smt(Index.valP).
  suff /#: 0 <= (nth witness tkpi (d - 1)).`1 < 1.
  move: (rngtkpi (d - 1) _); 1: smt(ge1_d).
  move=> -[-> /=]; rewrite (: nr_nodes_ht (d - 1) 0 %/ l' = 1) 2://.
  rewrite eq_sym -{1}(expr0 2) /nr_nodes_ht /nr_trees /nr_nodesx /=.
  rewrite -exprD_nneg 1:mulr_ge0; 1..3: smt(ge1_hp ge1_d).
  by rewrite /l' expz_div 2://; smt(ge1_hp).
move: (rtsrel hd0); rewrite eqd_szpk h0 => rtsE.
by rewrite hne0 /= rtsE.
qed.


(* ==========================================================================
   HOP 1 : the REAL EUF-NAGCMA game ~ the instrumented C game.

   +C port of MM45 Eqv_EUFNAGCMA_FLSLXMSSMTTWESNPRF_Orig_C
   (FV-SPHINCSPLUS-EC/proofs/FL_SL_XMSS_MT_ES.ec:3511-3961).

   The REAL game calls FL_SL_XMSS_MT_C_ES_NPRF.keygen / .sign (which route each
   layer through WOTS_C_ES.sign: grindC + encode_msgWOTS_C + chain walk); the C
   game inlines the whole cube and precomputes (pkWOTS, sigWOTS, counter, leaf,
   root) per (layer, tree, leaf).  MM45's proof establishes the cube
   characterisations `nth ... = cf ps (set_chidx ...) 0 (w-1) (val sk...)` etc.
   and then aligns the signing loops.

   +C deltas vs MM45 in THIS hop:
     * the sigWOTS characterisation's encoding is
         encode_msgWOTS_C ps <chtype kp adrs> <root> (grindC ps <same adrs> <root>)
       instead of MM45's `encode_msgWOTS <root>` -- both sides compute the SAME
       deterministic grind at the SAME address, so the characterisation is
       counter-carrying but checksum-free;
     * the hypertree signature element is ((sigWOTS, counter), ap);
     * trhtype -> trhxtype, nr_nodes -> nr_nodesx under our clone.
   ========================================================================== *)
equiv Eqv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Orig_C
  (A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{-EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C})
  (OC <: FSSLXMTWES.TRHC.Oracle_THFC{-EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C, -A}) :
  EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A, OC).main ~ EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C(A, OC).main :
    ={glob A, glob OC} ==> ={res}.
proof.
proc.
seq 7 15 : (={glob A, glob OC, sigl, pk, ml}); last first.
+ wp.
  while{2} (true) (d - size pkWOTSs'{2}).
  - move=> ? z.
    inline 3.
    wp.
    while (true) (len - size pkWOTS_l).
    * move=> z'.
      by wp; skip => />; smt(size_rcons).
    by wp; skip => />; smt(size_rcons).
  wp.
  call (: true) => /=; 1: by sim.
  call (: true).
  by skip => />; smt(ge1_d).
inline{1} 5.
seq 14 13 : (   ={glob A, glob OC, ad, ps, ml, root, skWOTStd, pk}
             /\ pk{1} = (root, ps, ad){1}
             /\ sk{1} = (skWOTStd, ps, ad){1}
             /\ (forall (i j u v : int),
                   0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' => 0 <= v < len =>
                     nth witness (DBLL.val (nth witness (nth witness (nth witness pkWOTStd{2} i) j) u)) v
                     =
                     cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0 (w - 1)
                     (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd{2} i) j) u)) v)))
             /\ (forall (i j u : int),
                   0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                     nth witness (nth witness (nth witness leavestd{2} i) j) u
                     =
                     pkco ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} i j) pkcotype) u)
                     (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness pkWOTStd{2} i) j) u)))))
             /\ (forall (i j : int),
                   0 <= i < d => 0 <= j < nr_trees i =>
                     nth witness (nth witness rootstd{2} i) j
                     =
                     val_bt_trh ps{2} (set_typeidx (set_ltidx ad{2} i j) trhxtype)
                                (list2tree (nth witness (nth witness leavestd{2} i) j)))
             /\ (forall (i j u : int),
                   0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                     nth witness (nth witness (nth witness counterstd{2} i) j) u
                     =
                     grindC ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u)
                       (if i = 0
                        then nth witness ml{2} (j * l' + u)
                        else nth witness (nth witness rootstd{2} (i - 1)) (j * l' + u)))
             /\ (forall (i j u v : int),
                   0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' => 0 <= v < len =>
                     nth witness (DBLL.val (nth witness (nth witness (nth witness sigWOTStd{2} i) j) u)) v
                     =
                     cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0
                     (BaseW.val (encode_msgWOTS_C ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u)
                                   (if i = 0
                                    then nth witness ml{2} (j * l' + u)
                                    else nth witness (nth witness rootstd{2} (i - 1)) (j * l' + u))
                                   (nth witness (nth witness (nth witness counterstd{2} i) j) u)).[v])
                     (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd{2} i) j) u)) v)))
             /\ (forall (i j : int),
                   0 <= i < d => 0 <= j < nr_trees i =>
                     size (nth witness (nth witness leavestd{2} i) j) = l')).
+ inline{1} 10.
  wp => /=.
  while{1} (leaves0{1}
            =
            mkseq (fun (i : int) =>
              pkco ps1{1} (set_kpidx (set_typeidx ad1{1} pkcotype) i)
                   (flatten (map DigestBlock.val (mkseq (fun (j : int) =>
                      cf ps1{1} (set_chidx (set_kpidx (set_typeidx ad1{1} chtype) i) j)
                         0 (w - 1) (DigestBlock.val (nth witness (DBLL.val (nth witness skWOTSl{1} i)) j))) len)))) (size leaves0{1})
            /\ 0 <= size leaves0{1} <= l')
           (l' - size leaves0{1}).
  - move=> _ z.
    inline *.
    wp => /=.
    while (pkWOTS0
           =
           mkseq (fun (j : int) =>
             cf ps2 (set_chidx ad2 j) 0 (w - 1) (DigestBlock.val (nth witness (DBLL.val skWOTS1) j))) (size pkWOTS0)
           /\ 0 <= size pkWOTS0 <= len)
          (len - size pkWOTS0).
    * move=> z'.
      by wp; skip => />; smt(size_rcons mkseqS).
    wp; skip => /> *.
    split => [| pkWOTS]; 1: by rewrite mkseq0 /=; smt(ge2_len).
    split => [/# | /lezNgt gelen_szpk *].
    rewrite DBLL.insubdK 1:/# size_rcons ?mkseqS 1://.
    rewrite -andbA; split; 2: smt(ge2_len).
    by congr => /=; smt(mkseqS).
  wp => /=.
  while (   ={skWOTStd}
         /\ valid_xadrs ad{2}
         /\ (forall (i j u v : int),
               0 <= i < size pkWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' => 0 <= v < len =>
                 nth witness (DBLL.val (nth witness (nth witness (nth witness pkWOTStd{2} i) j) u)) v
                 =
                 cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0 (w - 1)
                 (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd{2} i) j) u)) v)))
         /\ (forall (i j u : int),
               0 <= i < size leavestd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                 nth witness (nth witness (nth witness leavestd{2} i) j) u
                 =
                 pkco ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} i j) pkcotype) u)
                 (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness pkWOTStd{2} i) j) u)))))
         /\ (forall (i j : int),
               0 <= i < size rootstd{2} => 0 <= j < nr_trees i =>
                 nth witness (nth witness rootstd{2} i) j
                 =
                 val_bt_trh ps{2} (set_typeidx (set_ltidx ad{2} i j) trhxtype)
                            (list2tree (nth witness (nth witness leavestd{2} i) j)))
         /\ (forall (i j u : int),
               0 <= i < size counterstd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                 nth witness (nth witness (nth witness counterstd{2} i) j) u
                 =
                 grindC ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u)
                   (if i = 0
                    then nth witness ml{2} (j * l' + u)
                    else nth witness (nth witness rootstd{2} (i - 1)) (j * l' + u)))
         /\ (forall (i j u v : int),
               0 <= i < size sigWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' => 0 <= v < len =>
                 nth witness (DBLL.val (nth witness (nth witness (nth witness sigWOTStd{2} i) j) u)) v
                 =
                 cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0
                 (BaseW.val (encode_msgWOTS_C ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u)
                               (if i = 0
                                then nth witness ml{2} (j * l' + u)
                                else nth witness (nth witness rootstd{2} (i - 1)) (j * l' + u))
                               (grindC ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u)
                                  (if i = 0
                                   then nth witness ml{2} (j * l' + u)
                                   else nth witness (nth witness rootstd{2} (i - 1)) (j * l' + u)))).[v])
                 (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd{2} i) j) u)) v)))
         /\ (forall (i j : int),
               0 <= i < size leavestd{2} => 0 <= j < nr_trees i =>
                 size (nth witness (nth witness leavestd{2} i) j) = l')
         /\ 0 <= size skWOTStd{2} <= d
         /\ size skWOTStd{2} = size pkWOTStd{2}
         /\ size skWOTStd{2} = size sigWOTStd{2}
         /\ size skWOTStd{2} = size counterstd{2}
         /\ size skWOTStd{2} = size leavestd{2}
         /\ size skWOTStd{2} = size rootstd{2}).
  - wp.
    while (   ={skWOTStd, skWOTSnt}
           /\ valid_xadrs ad{2}
           /\ rootsntp{2} = last ml{2} rootstd{2}
           /\ (forall (j u v : int),
                 0 <= j < size pkWOTSnt{2} => 0 <= u < l' => 0 <= v < len =>
                   nth witness (DBLL.val (nth witness (nth witness pkWOTSnt{2} j) u)) v
                   =
                   cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size pkWOTStd{2}) j) chtype) u) v) 0 (w - 1)
                   (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness skWOTSnt{2} j) u)) v)))
           /\ (forall (j u : int),
                 0 <= j < size leavesnt{2} => 0 <= u < l' =>
                   nth witness (nth witness leavesnt{2} j) u
                   =
                   pkco ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} (size leavestd{2}) j) pkcotype) u)
                   (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness pkWOTSnt{2} j) u)))))
           /\ (forall (j : int),
                 0 <= j < size rootsnt{2} =>
                   nth witness rootsnt{2} j
                   =
                   val_bt_trh ps{2} (set_typeidx (set_ltidx ad{2} (size rootstd{2}) j) trhxtype)
                              (list2tree (nth witness leavesnt{2} j)))
           /\ (forall (j u : int),
                 0 <= j < size counternt{2} => 0 <= u < l' =>
                   nth witness (nth witness counternt{2} j) u
                   =
                   grindC ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} (size counterstd{2}) j) chtype) u)
                     (if size counterstd{2} = 0
                      then nth witness ml{2} (j * l' + u)
                      else nth witness (nth witness rootstd{2} (size counterstd{2} - 1)) (j * l' + u)))
           /\ (forall (j u v : int),
                 0 <= j < size sigWOTSnt{2} => 0 <= u < l' => 0 <= v < len =>
                   nth witness (DBLL.val (nth witness (nth witness sigWOTSnt{2} j) u)) v
                   =
                   cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size sigWOTStd{2}) j) chtype) u) v) 0
                   (BaseW.val (encode_msgWOTS_C ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} (size sigWOTStd{2}) j) chtype) u)
                                 (if size sigWOTStd{2} = 0
                                  then nth witness ml{2} (j * l' + u)
                                  else nth witness (nth witness rootstd{2} (size sigWOTStd{2} - 1)) (j * l' + u))
                                 (grindC ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} (size sigWOTStd{2}) j) chtype) u)
                                    (if size sigWOTStd{2} = 0
                                     then nth witness ml{2} (j * l' + u)
                                     else nth witness (nth witness rootstd{2} (size sigWOTStd{2} - 1)) (j * l' + u)))).[v])
                   (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness skWOTSnt{2} j) u)) v)))
           /\ (forall (j : int),
                 0 <= j < size leavesnt{2} =>
                   size (nth witness leavesnt{2} j) = l')
           /\ 0 <= size skWOTSnt{2} <= nr_trees (size skWOTStd{2})
           /\ size skWOTSnt{2} = size pkWOTSnt{2}
           /\ size skWOTSnt{2} = size sigWOTSnt{2}
           /\ size skWOTSnt{2} = size counternt{2}
           /\ size skWOTSnt{2} = size leavesnt{2}
           /\ size skWOTSnt{2} = size rootsnt{2}
           /\ 0 <= size skWOTStd{2} < d
           /\ size skWOTStd{2} = size pkWOTStd{2}
           /\ size skWOTStd{2} = size sigWOTStd{2}
           /\ size skWOTStd{2} = size counterstd{2}
           /\ size skWOTStd{2} = size leavestd{2}
           /\ size skWOTStd{2} = size rootstd{2}).
    * wp.
      while (   ={skWOTStd, skWOTSnt, skWOTSlp}
             /\ valid_xadrs ad{2}
             /\ rootsntp{2} = last ml{2} rootstd{2}
             /\ (forall (u v : int),
                   0 <= u < size pkWOTSlp{2} => 0 <= v < len =>
                     nth witness (DBLL.val (nth witness pkWOTSlp{2} u)) v
                     =
                     cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size pkWOTStd{2}) (size pkWOTSnt{2})) chtype) u) v) 0 (w - 1)
                     (DigestBlock.val (nth witness (DBLL.val (nth witness skWOTSlp{2} u)) v)))
             /\ (forall (u : int),
                   0 <= u < size leaveslp{2} =>
                     nth witness leaveslp{2} u
                     =
                     pkco ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} (size leavestd{2}) (size leavesnt{2})) pkcotype) u)
                     (flatten (map DigestBlock.val (DBLL.val (nth witness pkWOTSlp{2} u)))))
             /\ (forall (u : int),
                   0 <= u < size counterlp{2} =>
                     nth witness counterlp{2} u
                     =
                     grindC ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} (size counterstd{2}) (size counternt{2})) chtype) u)
                       (if size counterstd{2} = 0
                        then nth witness ml{2} (size counternt{2} * l' + u)
                        else nth witness (nth witness rootstd{2} (size counterstd{2} - 1)) (size counternt{2} * l' + u)))
             /\ (forall (u v : int),
                   0 <= u < size sigWOTSlp{2} => 0 <= v < len =>
                     nth witness (DBLL.val (nth witness sigWOTSlp{2} u)) v
                     =
                     cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size sigWOTStd{2}) (size sigWOTSnt{2})) chtype) u) v) 0
                     (BaseW.val (encode_msgWOTS_C ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} (size sigWOTStd{2}) (size sigWOTSnt{2})) chtype) u)
                                   (if size sigWOTStd{2} = 0
                                    then nth witness ml{2} (size sigWOTSnt{2} * l' + u)
                                    else nth witness (nth witness rootstd{2} (size sigWOTStd{2} - 1)) (size sigWOTSnt{2} * l' + u))
                                   (grindC ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} (size sigWOTStd{2}) (size sigWOTSnt{2})) chtype) u)
                                      (if size sigWOTStd{2} = 0
                                       then nth witness ml{2} (size sigWOTSnt{2} * l' + u)
                                       else nth witness (nth witness rootstd{2} (size sigWOTStd{2} - 1)) (size sigWOTSnt{2} * l' + u)))).[v])
                     (DigestBlock.val (nth witness (DBLL.val (nth witness skWOTSlp{2} u)) v)))
             /\ 0 <= size skWOTSlp{2} <= l'
             /\ size skWOTSlp{2} = size pkWOTSlp{2}
             /\ size skWOTSlp{2} = size sigWOTSlp{2}
             /\ size skWOTSlp{2} = size counterlp{2}
             /\ size skWOTSlp{2} = size leaveslp{2}
             /\ 0 <= size skWOTSnt{2} < nr_trees (size skWOTStd{2})
             /\ size skWOTSnt{2} = size pkWOTSnt{2}
             /\ size skWOTSnt{2} = size sigWOTSnt{2}
             /\ size skWOTSnt{2} = size counternt{2}
             /\ size skWOTSnt{2} = size leavesnt{2}
             /\ size skWOTSnt{2} = size rootsnt{2}
             /\ 0 <= size skWOTStd{2} < d
             /\ size skWOTStd{2} = size pkWOTStd{2}
             /\ size skWOTStd{2} = size sigWOTStd{2}
             /\ size skWOTStd{2} = size counterstd{2}
             /\ size skWOTStd{2} = size leavestd{2}
             /\ size skWOTStd{2} = size rootstd{2}).
      + wp.
        while (   ={skWOTStd, skWOTSnt, skWOTSlp, skWOTS}
               /\ valid_xadrs ad{2}
               /\ root{2} = nth witness (last ml{2} rootstd{2}) (size skWOTSnt{2} * l' + size skWOTSlp{2})
               /\ counter{2}
                  =
                  grindC ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) (size skWOTSnt{2})) chtype) (size skWOTSlp{2})) root{2}
               /\ em{2}
                  =
                  encode_msgWOTS_C ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) (size skWOTSnt{2})) chtype) (size skWOTSlp{2})) root{2} counter{2}
               /\ (forall (v : int),
                     0 <= v < size pkWOTS{2} =>
                       nth witness pkWOTS{2} v
                       =
                       cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size pkWOTStd{2}) (size pkWOTSnt{2})) chtype) (size pkWOTSlp{2})) v) 0 (w - 1)
                       (DigestBlock.val (nth witness skWOTS{2} v)))
               /\ (forall (v : int),
                     0 <= v < size sigWOTS{2} =>
                       nth witness sigWOTS{2} v
                       =
                       cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size sigWOTStd{2}) (size sigWOTSnt{2})) chtype) (size sigWOTSlp{2})) v) 0
                       (BaseW.val em{2}.[v])
                       (DigestBlock.val (nth witness skWOTS{2} v)))
               /\ 0 <= size skWOTS{2} <= len
               /\ size skWOTS{2} = size pkWOTS{2}
               /\ size skWOTS{2} = size sigWOTS{2}
               /\ 0 <= size skWOTSlp{2} < l'
               /\ size skWOTSlp{2} = size pkWOTSlp{2}
               /\ size skWOTSlp{2} = size sigWOTSlp{2}
               /\ size skWOTSlp{2} = size counterlp{2}
               /\ size skWOTSlp{2} = size leaveslp{2}
               /\ 0 <= size skWOTSnt{2} < nr_trees (size skWOTStd{2})
               /\ size skWOTSnt{2} = size pkWOTSnt{2}
               /\ size skWOTSnt{2} = size sigWOTSnt{2}
               /\ size skWOTSnt{2} = size counternt{2}
               /\ size skWOTSnt{2} = size leavesnt{2}
               /\ size skWOTSnt{2} = size rootsnt{2}
               /\ 0 <= size skWOTStd{2} < d
               /\ size skWOTStd{2} = size pkWOTStd{2}
               /\ size skWOTStd{2} = size sigWOTStd{2}
               /\ size skWOTStd{2} = size counterstd{2}
               /\ size skWOTStd{2} = size leavestd{2}
               /\ size skWOTStd{2} = size rootstd{2}).
        - wp; rnd; wp; skip => /> &2 szad prd vxi nthpk nthsig ge0_szsk lelen_szsk
                                     eqszsp eqszss ge0_szsklp ltlp_szsklp eqszlpsp eqszlpss
                                     eqszlpsc eqszlpsl ge0_szsknt ltnt_szsknt eqszntsp eqszntss
                                     eqszntsc eqszntsl eqszntsr ge0_szsktd ltd_szsktd
                                     eqsztdsp eqsztdss eqsztdsc eqsztdsl eqsztdsr ltlen_szsk
                                     skele skelein.
          have valad : valid_xadrs ad{2}.
          + by rewrite /valid_xadrs /valid_xadrsidxs szad /= /valid_xidxvals prd vxi.
          rewrite ?size_rcons; split => [v ge0_v ltszpk1_v|].
          * rewrite 2!nth_rcons; case (v = size pkWOTS{2}) => [eqsz | /#].
            rewrite eqsz eqszsp /= eq_sym.
            pose emt := encode_msgWOTS_C _ _ _ _.
            rewrite (: w - 1 = BaseW.val emt.[size pkWOTS{2}] + (w - 1 - BaseW.val emt.[size pkWOTS{2}])) 1:/# /cf.
            rewrite ch_comp 2:DigestBlock.valP //=; 2..4: smt(BaseW.valP val_w).
            - by apply validxadrs_validwadrs_setallch => // /#.
            by rewrite eqsztdsp eqszntsp eqszlpsp; congr; ring.
          split => [v ge0_v ltszsig1_v | /#].
          rewrite 2!nth_rcons eqszss; case (v = size sigWOTS{2}) => [eqsz | /#].
          by rewrite eqsz /= eqsztdss eqszntss eqszlpss.
        wp; skip => /> &2 szad prd vxi nthpks nthlfs nthcs nthsigs ge0_szsklp ltlp_szsklp
                          eqszlpsp eqszlpss eqszlpsc eqszlpsl ge0_szsknt ltnt_szsknt
                          eqszntsp eqszntss eqszntsc eqszntsl eqszntsr ge0_szsktd ltd_szsktd
                          eqsztdsp eqsztdss eqsztdsc eqsztdsl eqsztdsr ltl_szsklp.
        split => [| pk sig sk /lezNgt gelen_szsk _]; 1: smt(ge2_len).
        move=> nthpkp nthsigp ge0_szsk lelen_szsk eqszspp eqszssp.
        have rtE : nth witness (last ml{2} rootstd{2}) (size skWOTSnt{2} * l' + size skWOTSlp{2})
                   =
                   (if size skWOTStd{2} = 0
                    then nth witness ml{2} (size skWOTSnt{2} * l' + size skWOTSlp{2})
                    else nth witness (nth witness rootstd{2} (size skWOTStd{2} - 1))
                           (size skWOTSnt{2} * l' + size skWOTSlp{2})).
        + by rewrite (last_nth witness) /= -eqsztdsr /#.
        split => [u v |].
        - rewrite size_rcons => ge0_u ltszpk1_u ge0_v ltlen_v.
          rewrite 2!nth_rcons eqszlpsp; case (u = size pkWOTSlp{2}) => [eqsz | /#].
          by rewrite eqsz /= ?DBLL.insubdK // /#.
        split => [u |].
        - rewrite size_rcons => ge0_u ltszlp1_u.
          rewrite 2!nth_rcons -eqszlpsp eqszlpsl; case (u = size leaveslp{2}) => [eqsz | /#].
          by rewrite eqsz /= DBLL.insubdK // /#.
        split => [u |].
        - rewrite size_rcons -eqszlpsc => ge0_u ltszc1_u.
          rewrite nth_rcons; case (u = size skWOTSlp{2}) => [eqsz | /#].
          by rewrite eqsz /= -eqszlpsc /= -eqsztdsc -eqszntsc rtE.
        split => [u v |]; 2: smt(size_rcons).
        rewrite size_rcons -eqszlpss => ge0_u ltszsig1_u ge0_v ltlen_v.
        rewrite 2!nth_rcons; case (u = size skWOTSlp{2}) => [eqsz | /#].
        rewrite eqsz /= -eqszlpss /=.
        have -> : DBLL.val (DBLL.insubd sig) = sig by rewrite DBLL.insubdK; smt().
        have -> : DBLL.val (DBLL.insubd sk) = sk by rewrite DBLL.insubdK; smt().
        rewrite (nthsigp v _); 1: smt().
        by rewrite -eqsztdss -eqszntss -eqszlpss rtE.
      (* l'-loop init + exit -> re-establish the nt-level characterisations after
         one inner-tree COLUMN is appended.  Port of MM45 FL_SL_XMSS_MT_ES.ec:3790-3803.
         +C delta: one extra maintenance case (counternt, between roots and sig),
         and the intro pattern is shifted by the counter conjunct + its size eq
         (nthcs / eqszntsc / eqsztdsc on the way in, nthcp / eqszscp on the way out).
         `|>` (not `/>`) keeps `valid_xadrs ad{2}` folded as `valad`, matching MM45. *)
      wp; skip => |> &2 valad nthpks nthlfs nthrs nthcs nthsigs nthszlfs ge0_szsknt lent_szsknt
                        eqszntsp eqszntss eqszntsc eqszntsl eqszntsr ge0_szsktd ltd_szsktd
                        eqsztdsp eqsztdss eqsztdsc eqsztdsl eqsztdsr ltnrt_szskts.
      split => [| cs lfs pks sigs sks /lezNgt gelp_szsks _]; 1: by smt(ge2_lp).
      move=> nthpkp nthlfp nthcp nthsigp ge0_szsks lelp_szsks eqszspp eqszssp eqszscp eqszslp.
      split => [j u v |]; 1: smt(nth_rcons size_rcons).
      split => [j u ge0_j |]; 1: rewrite ?size_rcons ?nth_rcons.
      * by move=> *; rewrite -eqszntsp -eqszntsl /#.
      split => [j ge0_j |]; 1: rewrite ?size_rcons ?nth_rcons.
      * by move=> *; rewrite -eqszntsr -eqszntsl /#.
      split => [j u ge0_j |]; 1: rewrite ?size_rcons ?nth_rcons.
      * by move=> *; rewrite -eqszntsc /#.
      split => [j u v ge0_j |]; 1: rewrite ?size_rcons ?nth_rcons.
      * by move=> *; rewrite -eqszntss /#.
      split => [j ge0_j |]; 2: by rewrite ?size_rcons /#.
      rewrite nth_rcons size_rcons => ?; case (j < size leavesnt{2}) => [/# | ?].
      by rewrite (: j = size leavesnt{2}) 1:/# /= -eqszslp /#.
    (* nr_trees-loop init + exit -> re-establish the td-level characterisations
       after one LAYER is appended.  Port of MM45 FL_SL_XMSS_MT_ES.ec:3804-3822,
       including its `/nr_trees expr_ge0` init bookkeeping.
       +C delta: the counterstd maintenance case (between roots and sig).  Unlike
       the sig case it needs NO explicit `case (i = size counterstd{2})` split --
       `nth_rcons` + `/#` discharges it, because the counter characterisation's
       only cross-list read is `nth rootstd (i-1)`, whose rcons-boundary follows
       from `size skWOTStd = size counterstd = size rootstd` already in context. *)
    wp; skip => |> &2 valad nthpk nthlf nthrt nthc nthsig sznthlf ge0_szsk _ eqszpk eqszsig eqszc eqszlf eqszrt ltd_szsk.
    split => [| cs lfs pks rts sigs sks /lezNgt genrt_szsk _].
    - by rewrite /nr_trees expr_ge0 /#.
    move=> nthpkp nthlfp nthrtp nthcp nthsigp sznthlfp ge0_szskp lenrt_szsk
           eqszpkp eqszsigp eqszcp eqszlfp eqszrtp.
    have eqnrt_szsk : size sks = nr_trees (size skWOTStd{2}) by smt().
    rewrite ?size_rcons -andbA; split => [i j u v *|].
    - by rewrite 2!nth_rcons /#.
    split => [i j u *|].
    - by rewrite 2!nth_rcons /#.
    split => [i j *|].
    - by rewrite 2!nth_rcons /#.
    split => [i j u *|].
    - by rewrite 2!nth_rcons /#.
    split => [i j u v *|].
    - rewrite 3!nth_rcons.
      case (i = size sigWOTStd{2}) => [eqsz | neqsz]; 1: by rewrite eqsz eqszsig /= nthsigp // /#.
      rewrite (: i < size sigWOTStd{2}) 1:/# /=.
      by rewrite nthsig // /#.
    split => [i j *| /#].
    by rewrite nth_rcons /#.
  (* d-loop init + exit TOGETHER with the game prefix
       ad <- adz; ps <$ dpseed; OC.init(ps); ml <@ A(OC).choose()
     and the leftover of the one-sided `leaves_from_sklpsad` mkseq drain.
     Port of MM45 FL_SL_XMSS_MT_ES.ec:3823-3840.

     THREE port deltas (the third was NOT in the residual note and is the real
     one -- the first two were):
     (a) our OC is an ABSTRACT module parameter, so MM45's
         `call (: ={O_THFC_Default.pp})` becomes `call (: ={glob OC})`, still
         discharged `by sim` (the A(OC).choose adversary call);
     (b) `valid_xadrs ad{2}` is produced from `ad <- adz` via `valx_adz`;
     (c) MM45 kills the `O_THFC_Default.init(ps)` call with `inline *`.  We
         CANNOT: OC is abstract, so there is nothing to inline, and the
         invariant form `call (: ={glob OC})` is REJECTED on a direct OC call
         ("the module OC can write OC") -- that form is only sound for the
         adversary call, where it becomes a per-oracle sim obligation.  Fix:
         `swap` the (independent) `ad <- adz` past the sampling and the init
         call so `wp` can consume it -- which is also what puts the literal
         `adz` into the post for valx_adz -- then discharge the remaining
         identical `ps <$ dpseed; OC.init(ps)` prefix with a FORWARD
         `seq 2 2 : (={glob A, glob OC, ps}); 1: by sim`, the same shape HOP 2
         uses at its `seq 4 4`.  A purely relational seq post is required here:
         `sim` rejects a post carrying the non-relational `ad{2} = adz`
         ("cannot infer the set of equalities"), which is exactly why the
         swap-then-wp route is taken instead of carrying adz through the seq. *)
  wp.
  call (: ={glob OC}); 1: by sim.
  swap{1} 1 2; swap{2} 1 2.
  wp.
  seq 2 2 : (={glob A, glob OC, ps}); 1: by sim.
  skip => |> &1 ml; rewrite valx_adz /=.
  split => [| cs lfs pks rs sigs sks /lezNgt ged_szsks _]; 1: smt(ge1_d).
  move => nthpks nthlfs nthrs nthcs nthsigs nthszlfs ge0_szsknt lent_szsknt
          eqszntsp eqszntss eqszntsc eqszntsl eqszntsr.
  split => [| lfslp]; 1: smt(ge2_lp mkseq0).
  split => [/#| /lezNgt gelp_szlfslp lfslpval ge0_szlfslp lelp_szlfslp].
  split; first rewrite -andaE; split => //.
  - rewrite nthrs; 1,2: smt(ge1_d expr_gt0).
    do 2! congr; rewrite &(eq_from_nth witness); 1: smt(ge1_d expr_gt0).
    move=> i rng_i; rewrite nthlfs; 1,2,3: smt(ge1_d expr_gt0).
    rewrite lfslpval nth_mkseq //=.
    do 3! congr; rewrite &(eq_from_nth witness) 1:size_mkseq 1:DBLL.valP; 1: smt(ge2_len).
    move=> j; rewrite size_mkseq => rng_j; rewrite nth_mkseq 1:/# /=.
    by rewrite nthpks //; smt(ge1_d expr_gt0).
  by do ? (split; 1: smt()); smt().

(* SIGNING-LOOP ALIGNMENT: the REAL signer (which inlines WOTS_C_ES.sign =
   grindC + encode_msgWOTS_C + chain walk, and recomputes each layer's leaves
   from the sk cube) against the C game's cube reads, ending at ={sigl}.
   Port of MM45 FL_SL_XMSS_MT_ES.ec:3823-3959.

   What transferred VERBATIM (checked, not assumed): the `sp 5 1` counts, the
   fold-based inner invariant, both one-sided drains, the rng_tidxdiv /
   rng_tidxmod derivations, and the Index round-trip (REAL signs at
   `Index.insubd (size sigl)` while C uses `size sigl`) -- the latter needs NO
   separate bridge lemma, it falls out of the closing
   `smt(... fold0 Index.valP Index.insubdK)`.

   +C DELTAS:
   (i)  the coupled element is ((sigWOTS, counter), ap), not (sigWOTS, ap), so
        MM45's `do 2! congr` becomes `do 3! congr` and there is one EXTRA
        maintenance goal (the ground counter);
   (ii) inside the sigWOTS goal, the C cube stores the counter SEPARATELY, so
        the two encodings agree only after `nthcs` rewrites counterstd[..]
        back into the same `grindC ps addr root` the REAL signer computed;
        MM45 has no such step (its encode_msgWOTS takes no counter);
   (iii) the counter goal itself carries NO new crypto content -- it is the
        same root correspondence as the sig goal, so it reuses MM45's
        `case (size sapl = 0)` / fold0 / -divz_eq / nthrs argument unchanged.
   Port nit: MM45's `smt(Top.ge2_l)` is `smt(ge2_l size_ge0)` in our namespace,
   and one `1:/#` side goal needs the explicit `smt(ge2_len)` MM45 itself uses
   at the sibling site. *)
conseq (: _ ==> ={sigl}) => //=.
inline *.
while (#pre /\ ={sigl} /\ 0 <= size sigl{1} <= l).
+ wp; sp 5 1 => />.
  conseq (: _ ==> ={sapl}) => />; 1: by smt(size_rcons).
  while (   #pre
         /\ ={sapl, tidx, kpidx}
         /\ root0{1}
            =
            (if size sapl{1} = 0
             then m0{1}
             else val_bt_trh ps1{1} (set_typeidx (set_ltidx ad1{1} (size sapl{1} - 1) tidx{1}) trhxtype)
                    (list2tree (mkseq (fun (i : int) =>
                      pkco ps1{1} (set_kpidx (set_typeidx (set_ltidx ad1{1} (size sapl{1} - 1) tidx{1}) pkcotype) i)
                           (flatten (map DigestBlock.val (mkseq (fun (j : int) =>
                             cf ps1{1} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad1{1} (size sapl{1} - 1) tidx{1}) chtype) i) j) 0 (w - 1)
                                (DigestBlock.val (nth witness (DBLL.val (nth witness (nth witness (nth witness skWOTStd0{1} (size sapl{1} - 1)) tidx{1}) i)) j))) len)))) l')))
         /\ (size sapl{1} < d =>
                   tidx{1} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (size sigl{1}, 0) (size sapl{1})).`1
                /\ kpidx{1} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (size sigl{1}, 0) (size sapl{1})).`2)
         /\ (0 < size sapl{1} => tidx{1} < nr_trees (size sapl{1} - 1))
         /\ 0 <= tidx{1}
         /\ 0 <= kpidx{1} < l'
         /\ 0 <= size sapl{1} <= d).
  - wp => /=.
    while{1} ((forall (i : int), 0 <= i < size leaves1{1} =>
                nth witness leaves1{1} i
                =
                pkco ps3{1} (set_kpidx (set_typeidx ad3{1} pkcotype) i)
                     (flatten (map DigestBlock.val (mkseq (fun (j : int) =>
                       cf ps3{1} (set_chidx (set_kpidx (set_typeidx ad3{1} chtype) i) j) 0 (w - 1)
                          (DigestBlock.val (nth witness (DBLL.val (nth witness skWOTSl{1} i)) j))) len))))
              /\ 0 <= size leaves1{1} <= l')
             (l' - size leaves1{1}).
    * move=> &1 z.
      wp => /=.
      while ((forall (i : int), 0 <= i < size pkWOTS0 =>
                nth witness pkWOTS0 i
                =
                cf ps4 (set_chidx ad4 i) 0 (w - 1) (DigestBlock.val (nth witness (DBLL.val skWOTS3) i)))
             /\ 0 <= size pkWOTS0 <= len)
            (len - size pkWOTS0).
      + move=> z'.
        wp; skip => /> &2 nthval ? ? ?.
        rewrite -!andbA; split; 2: by smt(size_rcons).
        move=> i ge0_i; rewrite size_rcons => ltsz1_i.
        rewrite nth_rcons; case (i = size pkWOTS0{2}) => [-> //| neqsz_i].
        by rewrite (: i < size pkWOTS0{2}) 1:/# /= nthval 1:/#.
      wp; skip => /> &2 nthlf ? ? ?.
      split => [| pkWOTS]; 1: smt(ge2_len).
      split => [/# | /lezNgt gelen_szpk nthpk ? ?].
      rewrite -!andbA; split; 2: by smt(size_rcons).
      move=> i ge0_i; rewrite size_rcons => ltsz1_i.
      rewrite nth_rcons; case (i = size leaves1{2}) => [-> //=| neqsz_i].
      + do 3! congr.
        rewrite DBLL.insubdK 1:/# &(eq_from_nth witness) => [|j rng_j].
        - by rewrite size_mkseq; smt(ge2_len).
        rewrite (nth_map witness) 1:size_iota /=; 1: smt(ge2_len).
        by rewrite nthpk 1:rng_j nth_iota 1:/# //.
      by rewrite (: i < size leaves1{2}) 1:/# /= nthlf 1:/#.
    wp => /=.
    while{1} ((forall (i : int), 0 <= i < size sig0{1} =>
                nth witness sig0{1} i
                =
                cf ps2{1} (set_chidx ad2{1} i) 0 (BaseW.val em{1}.[i])
                   (DigestBlock.val (nth witness (DBLL.val skWOTS1{1}) i)))
              /\ 0 <= size sig0{1} <= len)
             (len - size sig0{1}).
    * move=> ? z.
      wp; skip => /> &1 nthsig ? ? ?.
      rewrite -!andbA; split => [i ge0_i|]; 2: smt(size_rcons).
      rewrite size_rcons => ltsz1_i; rewrite nth_rcons.
      case (i = size sig0{1}) => [-> // | neqszs_i].
      by rewrite (: i < size sig0{1}) 1:/# /= nthsig 1:/#.
    wp; skip => /> &2 nthpks nthlfs nthrs nthcs nthsigs nthszlfs ge0_szsigl _ ltl_szsigl
                      tkpidxsv ltnt_tidx ge0_tidx ge0_kpidx ltlp_kpidx ge0_szsapl
                      _ ltd_szsapl.
    split => [| siglp]; 1: smt(ge2_len).
    split => [/# | /lezNgt gelen_szsiglp nthsiglp _ lelen_szsiglp].
    split => [| lfsp]; 1: smt(ge2_lp).
    split => [/#| /lezNgt gelp_lfsp nthlfsp _ lelp_lfsp].
    have rng_tidxdiv : 0 <= tidx{2} %/ l' && tidx{2} %/ l' < nr_trees (size sapl{2}).
    * case (size sapl{2} = 0) => [eq0 | neq0] /=.
      + move: (tkpidxsv _); 1: smt().
        rewrite eq0 fold0 /= => -[-> _].
        rewrite divz_ge0 2:ge0_szsigl /= 2:ltz_divLR; 1,2: smt(ge2_lp).
        by rewrite (ltr_le_trans l) // /nr_trees /l' -exprD_nneg 1:mulr_ge0; smt(ge1_hp ge1_d).
      rewrite divz_ge0 2:ltz_divLR; 1,2: smt(ge2_lp).
      rewrite (: nr_trees (size sapl{2}) * l' = nr_trees (size sapl{2} - 1)).
      + rewrite /nr_trees /l' -exprD_nneg 1:mulr_ge0; 1..3: smt(ge1_hp ge1_d).
        by congr; ring.
      by rewrite ge0_tidx /= ltnt_tidx 1:/#.
    have rng_tidxmod : 0 <= tidx{2} %% l' && tidx{2} %% l' < l' by smt(ge2_lp modz_ge0 ltz_pmod).
    rewrite ?size_rcons -!andbA; split.
    (* ---- the coupled element ((sigWOTS, counter), ap).  MM45 needs `do 2!
       congr` here (its element is (sigWOTS, ap)); the +C ground counter adds a
       third component, hence `do 3! congr` and one extra maintenance goal. ---- *)
    * do 3! congr.
      (* (1) sigWOTS component *)
      rewrite &(DBLL.val_inj) &(eq_from_nth witness) 1:?DBLL.valP //.
      move=> i; rewrite DBLL.valP => rng_i; rewrite DBLL.insubdK 1:/#.
      rewrite nthsiglp 1:/# nthsigs 1:/# //.
      (* +C: the C-side cube stores the ground counter separately, so the two
         encodings agree only after `nthcs` turns counterstd[..] back into the
         SAME `grindC ps addr root` the REAL signer computed.  MM45 has no such
         step -- its encode_msgWOTS takes no counter. *)
      rewrite nthcs 1..3:/#.
      case (size sapl{2} = 0) => [eq0 | neq0] /=; do ? congr.
      by move: (tkpidxsv ltd_szsapl); rewrite eq0 fold0 /= -divz_eq => -[-> _].
      by move: (tkpidxsv ltd_szsapl); rewrite eq0 fold0 /= -divz_eq => -[-> _].
      rewrite nthrs 1:/# -?divz_eq; 2: do ? congr.
      - by split => [/#|_]; rewrite ltnt_tidx /#.
      rewrite &(eq_from_nth witness) 1:size_mkseq 1:nthszlfs 1..3:/#.
      move=> j; rewrite size_mkseq => rng_j.
      rewrite nth_mkseq 1:/# /= nthlfs 1..3:/# /=; do ? congr.
      rewrite &(eq_from_nth witness) 1:size_mkseq 1:DBLL.valP; 1: smt(ge2_len).
      move=> m; rewrite size_mkseq => rng_m.
      by rewrite nth_mkseq 1:/# /= nthpks // /#.
      rewrite nthrs 1:/# -?divz_eq; 2: do ? congr.
      - by split => [/#|_]; rewrite ltnt_tidx /#.
      rewrite &(eq_from_nth witness) 1:size_mkseq 1:nthszlfs 1..3:/#.
      move=> j; rewrite size_mkseq => rng_j.
      rewrite nth_mkseq 1:/# /= nthlfs 1..3:/# /=; do ? congr.
      rewrite &(eq_from_nth witness) 1:size_mkseq 1:DBLL.valP; 1: smt(ge2_len).
      move=> m; rewrite size_mkseq => rng_m.
      by rewrite nth_mkseq 1:/# /= nthpks // /#.
      (* (2) the +C ground counter component -- the goal MM45 does not have.
         It is the SAME root correspondence as the sig case (the counter is
         `grindC ps addr root`), so after `nthcs` it reduces to root0{1} = the
         cube's root, with no new crypto content. *)
      rewrite nthcs 1..3:/#.
      case (size sapl{2} = 0) => [eq0 | neq0] /=; do ? congr.
      by move: (tkpidxsv ltd_szsapl); rewrite eq0 fold0 /= -divz_eq => -[-> _].
      rewrite nthrs 1:/# -?divz_eq; 2: do ? congr.
      - by split => [/#|_]; rewrite ltnt_tidx /#.
      rewrite &(eq_from_nth witness) 1:size_mkseq 1:nthszlfs 1..3:/#.
      move=> j; rewrite size_mkseq => rng_j.
      rewrite nth_mkseq 1:/# /= nthlfs 1..3:/# /=; do ? congr.
      rewrite &(eq_from_nth witness) 1:size_mkseq 1:DBLL.valP; 1: smt(ge2_len).
      move=> m; rewrite size_mkseq => rng_m.
      by rewrite nth_mkseq 1:/# /= nthpks // /#.
      (* (3) the authentication-path component (MM45's second congr goal) *)
      do ? congr; rewrite &(eq_from_nth witness) 1:nthszlfs 1,3:/# //.
      move=> i rng_i; rewrite nthlfsp 2:nthlfs // 1:/#.
      do ? congr; rewrite &(eq_from_nth witness) 1:size_mkseq 1:DBLL.valP; 1: smt(ge2_len).
      move=> m; rewrite size_mkseq => rng_m.
      by rewrite nth_mkseq 1:/# /= nthpks // /#.
    rewrite andbA; split; 2: smt(size_rcons).
    split; 1: rewrite (: size sapl{2} + 1 <> 0) 1:/# /=.
    * do ? congr; rewrite &(eq_from_nth witness) 1:size_mkseq 1:/#.
      by move=> i rng_i; rewrite nthlfsp 2:nth_mkseq // /#.
    by move=> ltd_szsapl1; rewrite 2?foldS /#.
  by wp; skip => />; smt(ge2_lp ge1_d fold0 Index.valP Index.insubdK).
by wp; skip => />; smt(ge2_l size_ge0).

qed.

(* ==========================================================================
   COMPOSITION : Pr[REAL game : res] = Pr[V game : res].
   MM45 analog: the `have ->:` transitivity at FL_SL_XMSS_MT_ES.ec:4098-4102.
   ========================================================================== *)
lemma EqPr_EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Orig_V
  (A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{-EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C})
  (OC <: FSSLXMTWES.TRHC.Oracle_THFC{-EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C, -A}) &m :
  Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A, OC).main() @ &m : res]
  =
  Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A, OC).main() @ &m : res].
proof.
byequiv (: ={glob A, glob OC} ==> ={res}) => //.
transitivity EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C(A, OC).main
  (={glob A, glob OC} ==> ={res}) (={glob A, glob OC} ==> ={res}) => [/# | // | |].
+ by apply (Eqv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Orig_C A OC).
by apply (Eqv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF_C_V A OC).
qed.

(* ==========================================================================
   THE LIFT.  Branch-1 (seam_branch1_leaf_composed) bounds the V-game probability
   RESTRICTED TO THE WOTS BUCKET.  `valid_WOTSTWES` is a module-global of the C
   functor that the REAL game NEVER writes, so `Pr[REAL : res /\ valid_WOTSTWES]`
   would read leftover state and is NOT the lift.  The sound lift is:
   the probability equality above, then a `Pr[mu_split]` ON THE V SIDE -- exactly
   MM45's skeleton at FL_SL_XMSS_MT_ES.ec:4098-4105.

   Consequence (stated honestly): what branch-1 + these hops give is a REAL-game
   bound MODULO the complement bucket `Pr[V : res /\ !valid_WOTSTWES]`, which is
   the two tree reductions' obligation (R2, concurrently owned in
   drafts/_seam_tree_reductions_wip.ec).  It is NOT an unconditional REAL bound.
   ========================================================================== *)
lemma seam_branch1_lifted_to_REAL
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V }) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (a b : adrs),
       get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b) => get_wgpidxs a = get_wgpidxs b) =>
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC <> 8 * n =>
    dfC <> 8 * n * len =>
    dfC <> 8 * n * 2 =>
    hoare[ A_ht(O_THFC_MA).choose :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC) O_THFC_MA.tws_ma ] =>
    hoare[ A_ht(FC.O_THFC_Default).choose :
             FC.O_THFC_Default.tws = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws ] =>
    Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A_ht, FC.O_THFC_Default).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                         STCRC_WC.O_STCRC_Default).main() @ &m : res]
     + Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A_ht, FC.O_THFC_Default).main() @ &m :
            res /\ !EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES].
proof.
move=> hc hembdisj hembinj hencb hdf8n hdflen hdf2 A_wf_ht allnchads.
have hcomp := seam_branch1_leaf_composed A_ht &m hc hembdisj hembinj hencb
                hdf8n hdflen hdf2 A_wf_ht allnchads.
rewrite (EqPr_EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Orig_V A_ht FC.O_THFC_Default &m).
rewrite Pr[mu_split EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES].
smt().
qed.


(* ==========================================================================
   RESIDUAL NOTE -- UPDATED 2026-07-20.  ALL FOUR REAL~C ADMITS ARE CLOSED.
   (ec-certify on this file: compile=OK  admit-tactics=0  axiom-decls=0
    => CERTIFIED-0-ADMIT.)

   WHAT IS CLOSED, 0-ADMIT
   -----------------------
   * Eqv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF_C_V (HOP 2, C ~ V) -- fully proven.
     Includes the two genuinely +C obligations:
       (i)  the V-side accumulated `allOkC` is coupled (as allOkC0{1}=allOkC{2})
            to the C-side INLINED FL_SL_XMSS_MT_C_ES.verify -> root_from_sigC,
            so the +C constant-sum gate is literally the same object on both
            sides -- it is PROVEN equal, not assumed;
       (ii) the cube-layout mismatch that MM45 does NOT have (C carries a
            SEPARATE counterstd cube, V carries a FUSED (sigWOTS,cntr) cube;
            MM45 closes its whole prefix `by sim`).  Closed by an explicit
            4-level elementwise cube invariant, plus -- in the signing loop --
            the MM45 rng_tidxdiv/rng_tidxmod index-range facts.  Those ranges
            are LOAD-BEARING, not decoration: an out-of-range `nth witness` on
            the fused side is `witness<:sigWOTS*cntr>`, which is NOT provably
            `(witness<:sigWOTS>, witness<:cntr>)`, so the two layouts agree
            only where the read indices are in range.
   * Eqv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Orig_C (HOP 1, REAL ~ C) -- NOW FULLY
     PROVEN.  The four formerly-labelled admits closed 2026-07-20:
       - A-LPTAIL  (l'-loop init/exit -> nt-level maintenance).  MM45:3790-3803.
       - A-NTTAIL  (nr_trees-loop init/exit -> td-level maintenance). MM45:3804-3822.
       - A-TDTAIL  (d-loop init/exit + the ad/ps/OC.init/A.choose prefix + the
                    one-sided mkseq-drain leftover).  MM45:3823-3840.
       - B         (signing-loop alignment, REAL WOTS_C_ES.sign vs C cube read,
                    ending at ={sigl}).  MM45:3823-3959.
   * EqPr_EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Orig_V and seam_branch1_lifted_to_REAL
     -- both proven, and they no longer inherit any admit from Orig_C.

   PORT DELTAS WORTH KEEPING (things MM45's script does NOT tell you)
   ------------------------------------------------------------------
   1. ABSTRACT-OC PREFIX (A-TDTAIL).  MM45 kills `O_THFC_Default.init(ps)` with
      `inline *`.  We cannot: OC is an abstract module parameter, so there is
      nothing to inline, AND the INVARIANT form `call (: ={glob OC})` is
      REJECTED on a direct OC call ("the module OC can write OC").  That form is
      sound only for the ADVERSARY call `A(OC).choose`, where it becomes a
      per-oracle `sim` obligation.  Fix actually used: `swap` the independent
      `ad <- adz` past both the sampling and the init call so `wp` can consume
      it (which is also what puts the literal `adz` into the post for
      `valx_adz`), then discharge the remaining identical `ps <$ dpseed;
      OC.init(ps)` with a FORWARD `seq 2 2 : (={glob A, glob OC, ps}); 1: by
      sim` -- the same shape HOP 2 uses at its `seq 4 4`.  The seq post must
      stay PURELY RELATIONAL: `sim` rejects a post carrying `ad{2} = adz`
      ("cannot infer the set of equalities").
   2. `|>` vs `/>` IN THE TAILS.  `|>` keeps `valid_xadrs ad{2}` FOLDED (one
      name, as in MM45); `/>` unfolds it into three components (szad/prd/vxi)
      and then it has to be rebuilt by hand.  The tails use `|>`; the len-level
      body (already closed earlier) uses `/>` and does the rebuild.
   3. COUNTER MAINTENANCE IS CHEAPER THAN THE SIG CASE.  At NTTAIL the counter
      conjunct needs NO explicit `case (i = size counterstd{2})` split (unlike
      MM45's sig case): `nth_rcons` + `/#` suffices, because the counter
      characterisation's only cross-list read is `nth rootstd (i-1)`, whose
      rcons boundary follows from the size chain already in context.
   4. THE +C COUNTER RIDES ON MM45's ROOT CORRESPONDENCE (H1-B).  No new
      invariant conjunct was needed.  The C side reads
      counterstd[size sapl][tidx%/l'][tidx%%l'], which by the cube's counter
      characterisation IS `grindC ps addr root`; the REAL side computes
      `grindC ps addr root0`.  So the counter match reduces to exactly MM45's
      existing `root0{1} = if size sapl = 0 then m0 else val_bt_trh ...`
      conjunct, and its proof reuses MM45's case/fold0/-divz_eq/nthrs argument
      verbatim.  The coupled element becoming ((sigWOTS,counter),ap) only turns
      MM45's `do 2! congr` into `do 3! congr` plus one extra goal.
   5. INSIDE THE SIG GOAL, `nthcs` IS REQUIRED (H1-B).  The C cube stores the
      counter SEPARATELY from the signature, so the two encodings agree only
      after `nthcs` rewrites counterstd[..] back into the same
      `grindC ps addr root` the REAL signer computed.  MM45 has no analogue
      (its encode_msgWOTS takes no counter).
   6. THE Index ROUND-TRIP NEEDS NO BRIDGE LEMMA.  REAL signs at
      `Index.insubd (size sigl)` and reads `Index.val` of it, while C uses
      `size sigl` directly.  This is discharged entirely by MM45's closing
      `smt(... fold0 Index.valP Index.insubdK)` -- do NOT drop those hints
      (see CONTROL B).
   7. NAMESPACE NITS: MM45's `smt(Top.ge2_l)` is `smt(ge2_l size_ge0)` here;
      `valP`/`insubdK` are `DBLL.valP`/`DBLL.insubdK`; MM45's `trhtype` is our
      `trhxtype`.

   HONEST STATUS OF THE LIFT -- STILL NOT UNCONDITIONAL
   ----------------------------------------------------
   With Orig_C now admit-free, `seam_branch1_lifted_to_REAL` no longer rides on
   any admit IN THIS FILE, and branch 1's bound genuinely STARTS from the REAL
   game rather than from V.  It is nevertheless NOT an unconditional REAL-game
   bound, for one remaining reason:
     * the bound retains the summand
         Pr[V : res /\ !EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES]
       -- the complement bucket, which is the two TREE REDUCTIONS' obligation
       (R2), concurrently owned in drafts/_seam_tree_reductions_wip.ec and NOT
       discharged here.
   So: "branch 1 lifts to the REAL game" is now true of the game-hop chain, but
   the overall branch-1 statement remains contingent on R2.  Do not report this
   file as an unconditional REAL-game bound.

   ANTI-VACUITY CONTROLS RUN 2026-07-20 (all reverted after running)
   -----------------------------------------------------------------
   CONTROL A (targets the +C-specific step in H1-B's sigWOTS goal).  Deleted the
     `rewrite nthcs 1..3:/#` INSIDE the sigWOTS goal, everything else identical.
     RESULT: `[critical] nothing to rewrite`.  RULES OUT: that the sigWOTS
     alignment closes without ever reconciling the C cube's separately-stored
     counter against the REAL signer's grindC.  (Structural failure, so this is
     the weaker of the three.)
   CONTROL B (targets the REAL-vs-C index seam -- the one thing that genuinely
     differs between the REAL game and C at the signing loop).  Same proof, but
     the inner loop's closing `smt(ge2_lp ge1_d fold0 Index.valP Index.insubdK)`
     weakened to `smt(ge2_lp ge1_d fold0)`.  RESULT: `[critical] cannot prove
     goal (strict)`.  RULES OUT: that the Index.insubd/Index.val round-trip is
     being bypassed or closed vacuously -- it is really consumed.  This is the
     DECISIVE control for the REAL~C direction.
   CONTROL C (targets the counter component itself).  Deleted the `rewrite
     nthcs 1..3:/#` inside the COUNTER goal.  RESULT: `[critical] nothing to
     rewrite`.  RULES OUT: that the ground-counter component of the coupled
     element closes without the cube's counter characterisation.
   Reproduce any of them by making the single stated edit and recompiling.
   ========================================================================== *)
