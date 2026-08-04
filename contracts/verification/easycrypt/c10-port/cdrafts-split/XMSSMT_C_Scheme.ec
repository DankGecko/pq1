(* ==========================================================================
   XMSSMT_C_Scheme.ec -- the FIXED-LENGTH STATELESS XMSS-MT HYPERTREE,
   INSTANTIATED WITH WOTS+C  (`FL_SL_XMSS_MT_C_ES`).

   WHY THIS FILE EXISTS
   --------------------
   The capstone `EUFCMA_SPHINCS_PLUS_C` still bounds an ABSTRACT REAL
   `p_sphincs_c`: there is no SPHINCS+C *scheme module*, so the theorem does not
   quantify over a scheme.  Building one needs, bottom-up:

       (a) WOTS+C                       -- DONE (`WOTS_C_Scheme.WOTS_C_ES`)
       (b) the hypertree over WOTS+C    -- THIS FILE
       (c) FORS+C                       -- BLOCKED, see the C10 note below
       (d) SPHINCS+C = (b) + (c)        -- then `p_sphincs_c := Pr[EUF_CMA(...)]`

   This file is (b): a faithful mirror of MM45's `FL_SL_XMSS_MT_ES`
   (FV-SPHINCSPLUS-EC/proofs/FL_SL_XMSS_MT_ES.ec:1510) with WOTS-TW replaced by
   WOTS+C.  It is also the substrate of the capstone's `hbridge` hypothesis.

   THE ONLY +C DELTAS (everything else is copied verbatim)
   ------------------------------------------------------
     1. `sign` calls `WOTS_C_ES.sign`, which returns `(sigWOTS, cntr)`.  Each
        hypertree layer therefore carries a counter.  This MATCHES the shipped
        C10 signature layout: `SIG_HT_LAYER = L * N + 4 + SUBTREE_H * N`
        (sphincs-c10/src/params.rs:76) -- the `+ 4` is exactly that per-layer
        4-byte WOTS+C counter.
     2. `pkWOTS_from_sigWOTS_C` re-derives the WOTS public key from
        `(root, sigWOTS, counter)` via `encode_msgWOTS_C`, and additionally
        evaluates the +C constant-sum gate `predC (ThC ps ad m counter)`.
        `verify` requires ALL d gates to pass.

   WOTS keygen is UNCHANGED by +C (the +C change is only in the encoding), so
   `leaves_from_sspsad` / `gen_root` / `keygen` are byte-for-byte MM45.

   C10-FAITHFULNESS NOTE (read before extending this to (c)/(d))
   -------------------------------------------------------------
   This file is C10-faithful: C10's WOTS+C *does* carry a per-layer counter in
   the signature.  Its FORS+C does NOT -- C10 grinds the randomiser `R` and has
   no FORS counter field (`SIG_FORS_TOTAL = SIG_R + SIG_FORS_SECRETS +
   SIG_FORS_AUTH`, params.rs:73).  Our FORS+C development (`FORS_C.ec`) models
   the PAPER's FORS+C (uniform key, ground counter, counter in the signature),
   so composing (d) on top of it would model a scheme we do NOT ship.  Do (c) as
   a C10 re-base FIRST.  See docs/verification/easycrypt-euf-cma-port-feasibility-2026-07.md
   §UPDATE 2026-07-09b.

   STATUS: module definitions + TWO PROVEN correctness gates (`sign_size_d`,
   `sign_ll`).  NO admit, NO axiom.  The security proof over this module
   (`hbridge`) is NOT here.
   ========================================================================== *)

require import AllCore List Distr StdBigop StdOrder IntDiv.
require import BinaryTrees MerkleTrees.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme.

import FSSLXMTWES.           (* d, l', pkco, cons_ap_trh, val_bt_trh, val_ap_trh,
                                list2tree, set_ltidx, index, apFLXMSSTW, ... *)
import FSSLXMTWES.WTWES.     (* the CONCRETE WOTS-TW instance *)
import WOTS_C_Real.          (* cntr, ThC, predC *)
import WOTS_C_Scheme.        (* WOTS_C_ES, grindC, encode_msgWOTS_C *)
import EmsgWOTS.             (* emsgWOTS `.[]` word-indexing *)

(* --------------------------------------------------------------------------
   The +C hypertree signature: d layers of (WOTS+C signature, counter) paired
   with an authentication path.  MM45 wraps its analogue in a size-d subtype;
   we keep a plain list and let `verify` enforce `size sig = d`, so no new
   subtype clone is introduced.
   -------------------------------------------------------------------------- *)
type sigFLSLXMSSMTTWC = ((sigWOTS * cntr) * apFLXMSSTW) list.

module FL_SL_XMSS_MT_C_ES = {
  (* ---- UNCHANGED by +C: WOTS keygen is identical, so leaves/root/keygen are
          verbatim MM45 (FL_SL_XMSS_MT_ES.ec:1512-1568). ---- *)
  proc leaves_from_sspsad(ss : sseed, ps : pseed, ad : adrs) : dgstblock list = {
    var skWOTS : skWOTS;
    var pkWOTS : pkWOTS;
    var leaf : dgstblock;
    var leaves : dgstblock list;

    leaves <- [];
    while (size leaves < l') {
      skWOTS <@ WOTS_TW_ES.gen_skWOTS(ss, ps, set_kpidx (set_typeidx ad chtype) (size leaves));
      pkWOTS <@ WOTS_TW_ES.pkWOTS_from_skWOTS(skWOTS, ps, set_kpidx (set_typeidx ad chtype) (size leaves));
      leaf <- pkco ps (set_kpidx (set_typeidx ad pkcotype) (size leaves)) (flatten (map DigestBlock.val (DBLL.val pkWOTS)));
      leaves <- rcons leaves leaf;
    }

    return leaves;
  }

  proc gen_root(ss : sseed, ps : pseed, ad : adrs) : dgstblock = {
    var root : dgstblock;
    var leaves : dgstblock list;

    leaves <@ leaves_from_sspsad(ss, ps, set_ltidx ad (d - 1) 0);
    root <- val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhxtype) (list2tree leaves);

    return root;
  }

  (* ---- +C DELTA 1: each layer's WOTS+C signature carries its counter. ---- *)
  proc sign(sk : sseed * pseed * adrs, m : msgFLSLXMSSMTTW, idx : index) : sigFLSLXMSSMTTWC = {
    var ss : sseed;
    var ps : pseed;
    var ad : adrs;
    var tidx, kpidx : int;
    var skWOTS : skWOTS;
    var sigWOTS : sigWOTS;
    var counter : cntr;
    var leaves : dgstblock list;
    var ap : apFLXMSSTW;
    var sapl : sigFLSLXMSSMTTWC;
    var root : dgstblock;

    (ss, ps, ad) <- sk;

    root <- m;
    sapl <- [];
    (tidx, kpidx) <- (Index.val idx, 0);
    while (size sapl < d) {
      (tidx, kpidx) <- edivz tidx l';

      (* WOTS+C: derive the chain secret key, then sign WITH the ground counter. *)
      skWOTS <@ WOTS_TW_ES.gen_skWOTS(ss, ps, set_kpidx (set_typeidx (set_ltidx ad (size sapl) tidx) chtype) kpidx);
      (sigWOTS, counter) <@ WOTS_C_ES.sign((skWOTS, ps, set_kpidx (set_typeidx (set_ltidx ad (size sapl) tidx) chtype) kpidx), root);

      leaves <@ leaves_from_sspsad(ss, ps, (set_ltidx ad (size sapl) tidx));
      ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhxtype) (list2tree leaves) kpidx;
      root <- val_bt_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhxtype) (list2tree leaves);

      sapl <- rcons sapl ((sigWOTS, counter), ap);
    }

    return sapl;
  }

  (* ---- +C DELTA 2: re-derive the WOTS pk from (m, counter) AND evaluate the
          +C constant-sum gate.  Mirrors WOTS_C_ES.verify's loop. ---- *)
  proc pkWOTS_from_sigWOTS_C(m : dgstblock, sigWOTS : sigWOTS, counter : cntr,
                             ps : pseed, ad : adrs) : pkWOTS * bool = {
    var em : EmsgWOTS.emsgWOTS;
    var pkWOTS_l : dgstblock list;
    var em_ele : int;
    var sig_ele : dgstblock;
    var pkWOTS_ele : dgstblock;
    var okC : bool;

    em <- encode_msgWOTS_C ps ad m counter;

    pkWOTS_l <- [];
    while (size pkWOTS_l < len) {
      sig_ele <- nth witness (DBLL.val sigWOTS) (size pkWOTS_l);
      em_ele <- BaseW.val em.[size pkWOTS_l];
      pkWOTS_ele <- cf ps (set_chidx ad (size pkWOTS_l)) em_ele (w - 1 - em_ele) (DigestBlock.val sig_ele);
      pkWOTS_l <- rcons pkWOTS_l pkWOTS_ele;
    }

    okC <- predC (ThC ps ad m counter);

    return (DBLL.insubd pkWOTS_l, okC);
  }

  proc root_from_sigC(m : msgFLSLXMSSMTTW, sig : sigFLSLXMSSMTTWC, idx : index,
                      ps : pseed, ad : adrs) : dgstblock * bool = {
    var root : dgstblock;
    var tidx, kpidx : int;
    var i : int;
    var sigWOTS : sigWOTS;
    var counter : cntr;
    var sc : sigWOTS * cntr;
    var ap : apFLXMSSTW;
    var pkWOTS : pkWOTS;
    var leaf : dgstblock;
    var okC, allOkC : bool;

    i <- 0;
    root <- m;
    allOkC <- true;
    (tidx, kpidx) <- (Index.val idx, 0);
    while (i < d) {
      (tidx, kpidx) <- edivz tidx l';

      (sc, ap) <- nth witness sig i;
      sigWOTS <- sc.`1;
      counter <- sc.`2;

      (pkWOTS, okC) <@ pkWOTS_from_sigWOTS_C(root, sigWOTS, counter, ps,
                          set_kpidx (set_typeidx (set_ltidx ad i tidx) chtype) kpidx);
      allOkC <- allOkC /\ okC;

      leaf <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad i tidx) pkcotype) kpidx) (flatten (map DigestBlock.val (DBLL.val pkWOTS)));
      root <- val_ap_trh ps (set_typeidx (set_ltidx ad i tidx) trhxtype) ap kpidx leaf;

      i <- i + 1;
    }

    return (root, allOkC);
  }

  proc verify(pk : dgstblock * pseed * adrs, m : msgFLSLXMSSMTTW,
              sig : sigFLSLXMSSMTTWC, idx : index) : bool = {
    var root, root' : dgstblock;
    var ps : pseed;
    var ad : adrs;
    var allOkC : bool;

    (root, ps, ad) <- pk;
    (root', allOkC) <@ root_from_sigC(m, sig, idx, ps, ad);

    (* size gate replaces MM45's size-d subtype; +C gate is the new conjunct *)
    return size sig = d /\ root' = root /\ allOkC;
  }
}.

(* ==========================================================================
   CORRECTNESS GATE -- PROVEN.

   A scheme module that nothing is proven about is barely more constrained than
   the abstract real it replaces.  `verify` demands `size sig = d`: if `sign` did
   not emit exactly `d` layers the scheme would never verify anything.  So
   `sign_size_d` is the minimal structural check that the +C loop is wired right.

   MM45 is a security-ONLY development -- it proves NO correctness lemma anywhere
   (`grep '^lemma .*correct'` over both FV trees is empty), so there is no spec to
   reuse.  In `hoare`, a call to a CONCRETE procedure needs an explicit spec
   (`call (: true)` is the `equiv` form, for abstract modules).  Hence the
   bottom-up chain below.  Nothing is admitted.
   ========================================================================== *)

(* Leaves of the chain: pure loops, no procedure calls. *)
lemma gen_skWOTS_h : hoare[WOTS_TW_ES.gen_skWOTS : true ==> true].
proof. proc; while (true); auto. qed.

lemma pkWOTS_from_skWOTS_h : hoare[WOTS_TW_ES.pkWOTS_from_skWOTS : true ==> true].
proof. proc; while (true); auto. qed.

lemma wotsc_sign_h : hoare[WOTS_C_ES.sign : true ==> true].
proof. proc; while (true); auto. qed.

(* One level up: leaves_from_sspsad calls the two above. *)
lemma leaves_h : hoare[FL_SL_XMSS_MT_C_ES.leaves_from_sspsad : true ==> true].
proof.
proc; while (true).
+ by wp; call pkWOTS_from_skWOTS_h; call gen_skWOTS_h; auto.
by auto.
qed.

(* THE GATE: `sign` emits exactly `d` layers -- the size `verify` demands. *)
lemma sign_size_d :
  hoare[FL_SL_XMSS_MT_C_ES.sign : true ==> size res = d].
proof.
proc.
while (0 <= size sapl /\ size sapl <= d).
+ wp; call leaves_h; call wotsc_sign_h; call gen_skWOTS_h; auto.
  smt(size_rcons).
auto; smt(ge1_d size_ge0).
qed.

(* --------------------------------------------------------------------------
   SECOND GATE: the signer terminates with probability 1.  A scheme whose
   `sign` might not terminate is broken regardless of its security bound; this
   also carries the WOTS+C counter search (`WOTS_C_ES_sign_ll`, PROVEN in
   WOTS_C_Scheme.ec) through the d-layer composition.
   -------------------------------------------------------------------------- *)
lemma gen_skWOTS_ll : islossless WOTS_TW_ES.gen_skWOTS.
proof. proc; while (true) (len - size skWOTS); auto; smt(size_rcons). qed.

lemma pkWOTS_from_skWOTS_ll : islossless WOTS_TW_ES.pkWOTS_from_skWOTS.
proof. proc; while (true) (len - size pkWOTS); auto; smt(size_rcons). qed.

lemma leaves_ll : islossless FL_SL_XMSS_MT_C_ES.leaves_from_sspsad.
proof.
proc; while (true) (l' - size leaves).
+ move=> z; wp; call pkWOTS_from_skWOTS_ll; call gen_skWOTS_ll; auto; smt(size_rcons).
by auto; smt().
qed.

lemma sign_ll : islossless FL_SL_XMSS_MT_C_ES.sign.
proof.
proc; while (true) (d - size sapl).
+ move=> z; wp; call leaves_ll; call WOTS_C_ES_sign_ll; call gen_skWOTS_ll;
    auto; smt(size_rcons).
by auto; smt().
qed.
