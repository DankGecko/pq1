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


(* ===== HOP 1 : REAL ~ C ===== *)
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
      admit. (* ADMIT-H1-A-LPTAIL : l'-loop -> nt-level maintenance *)
    admit. (* ADMIT-H1-A-NTTAIL : nt-loop -> td-level maintenance *)
  admit. (* ADMIT-H1-A-TDTAIL : td-loop init/exit + the A.choose/rnd prefix *)

admit. (* ADMIT-H1-B : signing-loop alignment (REAL WOTS_C_ES.sign vs C cube read) *)

qed.

(* ===== COMPOSITION : REAL = V ===== *)
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
