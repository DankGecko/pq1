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
require import BinaryTrees MerkleTrees.
require import BitEncoding.
import BS2Int.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.

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
   TREE-COLLISION REDUCTIONS FOR THE WOTS+C HYPERTREE (SECOND ler_add branch).

   +C analogs of MM45's two XMSS-MT tree-collision reductions
   (FV-SPHINCSPLUS-EC/proofs/FL_SL_XMSS_MT_ES.ec:2130-2715):

     * R_SMDTTCRCPKCO_C  = analog of R_SMDTTCRCPKCO_EUFNAGCMA (:2130-2414).
       Routes pkco collisions to the FSSLXMTWES.PKCOC_TCR SM-DT-TCR-C oracle.
     * R_SMDTTCRCTRH_C   = analog of R_SMDTTCRCTRH_EUFNAGCMA  (:2415-2715).
       Routes trh collisions to the FSSLXMTWES.TRHC_TCR SM-DT-TCR-C oracle.

   They feed the SECOND ler_add branch of the hypertree bound:
       res /\ !valid_WOTSTWES  <=  pkco_TCR + trh_TCR.

   +C DELTAS (the SAME mechanical counter-threading used by the C/V games above,
   and by the leaf reduction R_MEUFGCMAWOTSC_EUFNAGCMA_C):
     * hypertree signature is the plain `sigFLSLXMSSMTTWC` list (no size-d
       subtype; size-d enforced by the aliased +C verify), so `sig <- sapl`
       (no `insubd`) and `sig'` is read WITHOUT `val`;
     * the ONE encode site becomes grindC + encode_msgWOTS_C at the WOTS keypair
       chtype address (exactly WOTS_C_ES.sign / the C/V games :1021-1022) --
       relocated from `pick` to `find(pp)`, see GRIND-IN-FIND below;
     * per-leaf counters carried in a PARALLEL `counterstd` cube (layer/tree/leaf),
       bundled into each hypertree sig element as `((sigWOTS, counter), ap)`;
     * forgery per-layer reconstruction via +C `pkWOTS_from_sigWOTS_C` (re-derives
       pk from (root, sigWOTS, counter) AND evaluates okC, which the 3 collision
       flags discard -- exactly the counter-independence the seam relies on).
   Everything else is byte-for-byte MM45 modulo the FSSLXMTWES clone renames
   (nr_nodes -> nr_nodesx, trhtype -> trhxtype) and the outer-context `val`
   qualifications (DigestBlock.val / DBLL.val / DBHPL.val / Index.val), all of
   which are already fixed by R_MEUFGCMAWOTSC_EUFNAGCMA_C in this same file.

   GRIND-IN-FIND (soundness fix, 2026-07-19; supersedes the earlier
   "DEFERRED-PUBLIC-SEED" design).  The SM-DT-TCR-C game reveals `pp` only at
   `find(pp)`; during `pick()` the reduction holds ONLY the oracles O/OC, not
   the seed.  MM45's tree reductions are seed-INDEPENDENT in `pick`
   (`em <- encode_msgWOTS root`), but the +C encode site is seed-DEPENDENT
   (`grindC ps` / `encode_msgWOTS_C ps`).

   An earlier draft resolved this by grinding in `pick` against a MODULE VARIABLE
   `ps`.  That was UNSOUND and has been removed: the module var is witness-valued
   at `pick` and can never provably equal the game's freshly sampled `pp`, so the
   "deferral to the downstream byequiv" was a debt that could not be paid.

   The fix rests on a structural fact about WOTS+C: each chain is walked FULLY to
   `w-1`, and the encoding `em` only selects which INTERMEDIATE is REVEALED as
   `sigWOTS`.  Hence the WOTS public key -- and therefore every leaf, every
   Merkle node, every root, and every TCR target input -- is grind-INDEPENDENT.
   `pick` never needed the seed at all.

   So:
     * `pick` is MM45's pick with the seed-dependent PURE assignments deleted
       (grindC, encode_msgWOTS_C, both em-pluck conditionals, the sigWOTS/counter
       accumulators).  None of those made an oracle call, so the pick TRANSCRIPT
       is EXACTLY MM45's: `dist_tweaks`, `disj_lists` and the `fidx` index
       arithmetic carry over unchanged, and BOTH branches run on the STOCK games
       with NO new assumption.  There is no module-var `ps` any more.
     * `find(pp)` -- which DOES receive the public seed -- opens with an additive
       prologue that rebuilds what `pick` no longer computes: `counterstd` (via
       `grindC pp`), `em` (via `encode_msgWOTS_C pp`, bridged to `encode_msgWOTS
       (ThC ...)` downstream by `hencb`), and `sigWOTStd` (pure `cf` chain walks
       READING pick's sampled `skWOTStd` -- never resampling, which would desync
       from pick's oracle-built `pkWOTStd`/`leavestd`).  The element line is
       LITERALLY the honest `EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V` sigWOTS line, so
       the rebuilt cube is the honest signature cube by construction.
     * `find` makes ZERO oracle calls, so it adds ZERO transcript pollution.
       This is type-ENFORCED, not merely inspected: `Adv_SMDTTCRC` declares
       `proc find(pp : pp_t) : int * in_t {}` (TweakableHashFunctions.eca:715).
       Verified by negative control: injecting a single `OC.query` into either
       `find` makes EasyCrypt reject the module with "procedure `find' is not
       compatible: the function is not allowed to use OC.query".

   Mechanical check of the "pick transcript = MM45's" claim: normalising both
   pick bodies (strip comments/whitespace, undo the clone renames nr_nodesx ->
   nr_nodes / trhxtype -> trhtype and the outer-context `val` qualifications)
   and diffing against MM45 yields DELETIONS ONLY -- no statement is added, and
   the subset consisting of every oracle call with its address and input
   arguments, every `<$` sampling, and every loop bound is IDENTICAL for both
   reductions (pkco: chain + leaf via O.query + nodes via OC.query; trh: chain +
   leaf via OC.query + nodes via O.query).

   Two retained-but-dead lines in `pick`: the local `root` (declared, unused) and
   `rootsntp <- last ml rootstd` (assigned, no longer read, since its only reader
   was the deleted encode site).  Both are kept deliberately so the statement
   list stays aligned with MM45's for the downstream proof port; they are pure
   and transcript-neutral.  MM45 itself likewise carries dead co-declarations
   (`skWOTSntp`, `pkWOTSntp`, `leavesntp`, `nodestd`).

   Architecture precedent: `R_multi_STCRC` (WOTS_C_Multi.ec:186-196) and the leaf
   batch reduction (WOTS_C_Reduction.ec:66-90), which likewise "defer keypair/
   signature construction to find(pp) where the public seed is revealed".
   ========================================================================== *)

(* Reduction adversary against SM-DT-TCR-C of pkco (WOTS+C hypertree). *)
module (R_SMDTTCRCPKCO_C (A : Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF) : FSSLXMTWES.PKCOC_TCR.Adv_SMDTTCRC)
       (O : FSSLXMTWES.PKCOC_TCR.Oracle_SMDTTCR, OC : FSSLXMTWES.PKCOC.Oracle_THFC) = {
  var ad : adrs
  var ml : msgFLSLXMSSMTTW list
  (* NB: NO module-var `ps`.  Under grind-in-find the ONLY seed this reduction
     ever touches is `find`'s parameter, i.e. the SM-DT-TCR-C game's own `pp`. *)
  var skWOTStd : skWOTS list list list
  var pkWOTStd : pkWOTS list list list
  (* Built in `find` (they are seed-dependent), NOT in `pick`. *)
  var sigWOTStd : sigWOTS list list list
  var counterstd : cntr list list list
  var leavestd : dgstblock list list list
  var rootstd : dgstblock list list

  (* Collection-oracle wrapper handed to A.  Typed as the TRHC.Oracle_THFC that A
     expects; forwards to OC (a PKCOC.Oracle_THFC).  The two share {init,query,
     get_tweaks} over the same adrs/dgst/dgstblock types, so the PKCOC-oracle-
     through-TRHC-wrapper typechecks (byte-identical to MM45:2143). *)
  module O_THFC : FSSLXMTWES.TRHC.Oracle_THFC = {
    var ads : adrs list
    var xs : dgst list

    proc init(psi : pseed) : unit = {
      ads <- [];
      xs <- [];
    }

    proc query(adq : adrs, x : dgst) : dgstblock = {
      var y : dgstblock;
      y <@ OC.query(adq, x);
      ads <- rcons ads adq;
      xs <- rcons xs x;
      return y;
    }

    proc get_tweaks() : adrs list = {
      return ads;
    }
  }

  proc pick() : unit = {
    var ch_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var pkWOTS : dgstblock list;
    var pkWOTSlp : pkWOTS list;
    var pkWOTSnt : pkWOTS list list;
    var leaf : dgstblock;
    var leaveslp : dgstblock list;
    var leavesnt : dgstblock list list;
    var root : dgstblock;
    var rootsnt, rootsntp : dgstblock list;
    var lnode, rnode, node : dgstblock;
    var nodespl, nodescl : dgstblock list;
    var nodes : dgstblock list list;
    var i : int;

    (* Initialize (wrapper around) collection oracle *)
    O_THFC.init(witness);

    (* Ask adversary to provide list of messages to sign (A queries OC via wrapper) *)
    ml <@ A(O_THFC).choose();

    (* Initialize address *)
    ad <- adz;

    (* Build/store the SEED-INDEPENDENT part of the WOTS+C cube: secret keys,
       public keys, (inner tree) leaves, and (inner tree) roots.  Signatures and
       +C counters are seed-DEPENDENT and are rebuilt in `find(pp)`.
       This block is MM45's R_SMDTTCRCPKCO_EUFNAGCMA.pick body (:2196-2295) with
       the em/sigWOTS/counter pure assignments deleted; every oracle call, its
       address argument, its input argument, and every loop bound is unchanged. *)
    skWOTStd <- [];
    pkWOTStd <- [];
    leavestd <- [];
    rootstd <- [];
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      pkWOTSnt <- [];
      leavesnt <- [];
      rootsnt <- [];
      rootsntp <- last ml rootstd;
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        pkWOTSlp <- [];
        leaveslp <- [];
        while (size skWOTSlp < l') {
          skWOTS <- [];
          pkWOTS <- [];
          while (size skWOTS < len) {
            ch_ele <$ ddgstblock;
            skWOTS <- rcons skWOTS ch_ele;

            (* FULL chain walk to w-1: the +C encoding only selects which
               INTERMEDIATE is revealed as sigWOTS, so pkWOTS (and hence the
               leaf, the nodes and the roots) is grind-INDEPENDENT. *)
            i <- 0;
            while (i < w - 1) {
              ch_ele <@ OC.query(set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype)
                                                                (size skWOTSlp)) (size pkWOTS)) i,
                                 DigestBlock.val ch_ele);

              i <- i + 1;
            }

            pkWOTS <- rcons pkWOTS ch_ele;
          }

          (* Query the challenge oracle to compress the WOTS+C public key to a leaf (pkco) *)
          leaf <@ O.query(set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) pkcotype) (size skWOTSlp),
                          flatten (map DigestBlock.val pkWOTS));

          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
          pkWOTSlp <- rcons pkWOTSlp (DBLL.insubd pkWOTS);
          leaveslp <- rcons leaveslp leaf;
        }

        nodes <- [];
        while (size nodes < h') {
          nodespl <- last leaveslp nodes;

          nodescl <- [];
          while (size nodescl < nr_nodesx (size nodes + 1)) {
            lnode <- nth witness nodespl (2 * size nodescl);
            rnode <- nth witness nodespl (2 * size nodescl + 1);

            (* Merkle node via trh (collection oracle) *)
            node <@ OC.query(set_thtbidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) trhxtype)
                                         (size nodes + 1) (size nodescl),
                             DigestBlock.val lnode ++ DigestBlock.val rnode);

            nodescl <- rcons nodescl node;
          }
          nodes <- rcons nodes nodescl;
        }
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
        pkWOTSnt <- rcons pkWOTSnt pkWOTSlp;
        leavesnt <- rcons leavesnt leaveslp;
        rootsnt <- rcons rootsnt (nth witness (nth witness nodes (h' - 1)) 0);
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
      pkWOTStd <- rcons pkWOTStd pkWOTSnt;
      leavestd <- rcons leavestd leavesnt;
      rootstd <- rcons rootstd rootsnt;
    }
  }

  proc find(ps : pseed) : int * dgst = {
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
    var leaf, leaf' : dgstblock;
    var leaves : dgstblock list;
    var cidx, fidx : int;
    var pkWOTSs, pkWOTSs' : pkWOTS list;
    var leavess, leavess' : dgstblock list;
    var okC : bool;
    (* --- locals for the seed-dependent rebuild (grind-in-find) --- *)
    var em : EmsgWOTS.emsgWOTS;
    var em_ele : int;
    var counter : cntr;
    var skWOTSr : dgstblock list;
    var sigWOTS : dgstblock list;
    var sigWOTS_ele : dgstblock;
    var sigWOTSlp : sigWOTS list;
    var sigWOTSnt : sigWOTS list list;
    var counterlp : cntr list;
    var counternt : cntr list list;
    var rootsntp : dgstblock list;

    (* ====================================================================
       GRIND-IN-FIND.  `pick` could not compute the +C counters or the WOTS+C
       signatures: both are functions of the PUBLIC SEED, which the SM-DT-TCR-C
       game reveals only here.  Rebuild them now, against the GAME's `ps`.

       Everything read here was produced by `pick` and is grind-INDEPENDENT:
       `skWOTStd` (the sampled chain seeds) and `rootstd` (the to-be-signed
       roots).  The element line is LITERALLY the honest game's
       (EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V, this file) sigWOTS line, with the
       `<$ ddgstblock` sample replaced by a READ of the seed `pick` sampled --
       so the rebuilt cube is the honest signature cube by construction.

       ZERO oracle calls (also type-enforced: `find` is `{}`-restricted in
       Adv_SMDTTCRC), hence ZERO added transcript pollution.
       ==================================================================== *)
    sigWOTStd <- [];
    counterstd <- [];
    while (size sigWOTStd < d) {
      sigWOTSnt <- [];
      counternt <- [];
      (* pick evaluated `last ml rootstd` when rootstd held `size skWOTStd`
         layers; here rootstd is complete, so take the same prefix. *)
      rootsntp <- last ml (take (size sigWOTStd) rootstd);
      while (size sigWOTSnt < nr_trees (size sigWOTStd)) {
        sigWOTSlp <- [];
        counterlp <- [];
        while (size sigWOTSlp < l') {
          root <- nth witness rootsntp (size sigWOTSnt * l' + size sigWOTSlp);

          (* +C: grind the counter and encode via Th+C at the WOTS keypair
             (chtype) address -- exactly WOTS_C_ES.sign / the C/V games. *)
          counter <- grindC ps (set_kpidx (set_typeidx (set_ltidx ad (size sigWOTStd) (size sigWOTSnt)) chtype) (size sigWOTSlp)) root;
          em <- encode_msgWOTS_C ps (set_kpidx (set_typeidx (set_ltidx ad (size sigWOTStd) (size sigWOTSnt)) chtype) (size sigWOTSlp)) root counter;

          (* READ the chain seeds pick sampled -- never resample. *)
          skWOTSr <- DBLL.val (nth witness (nth witness (nth witness skWOTStd (size sigWOTStd)) (size sigWOTSnt)) (size sigWOTSlp));

          sigWOTS <- [];
          while (size sigWOTS < len) {
            em_ele <- BaseW.val em.[size sigWOTS];

            sigWOTS_ele <- cf ps (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size sigWOTStd) (size sigWOTSnt)) chtype)
                                                       (size sigWOTSlp)) (size sigWOTS))
                              0 em_ele (DigestBlock.val (nth witness skWOTSr (size sigWOTS)));

            sigWOTS <- rcons sigWOTS sigWOTS_ele;
          }

          sigWOTSlp <- rcons sigWOTSlp (DBLL.insubd sigWOTS);
          counterlp <- rcons counterlp counter;
        }
        sigWOTSnt <- rcons sigWOTSnt sigWOTSlp;
        counternt <- rcons counternt counterlp;
      }
      sigWOTStd <- rcons sigWOTStd sigWOTSnt;
      counterstd <- rcons counterstd counternt;
    }

    (* Sign adversary-chosen messages using computed leaves/(signatures,counters) *)
    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);

      sapl <- [];
      (tidx, kpidx) <- (size sigl, 0);
      while (size sapl < d) {
        (tidx, kpidx) <- edivz tidx l';

        sigc <- (nth witness (nth witness (nth witness sigWOTStd (size sapl)) tidx) kpidx,
                 nth witness (nth witness (nth witness counterstd (size sapl)) tidx) kpidx);

        leaves <- nth witness (nth witness leavestd (size sapl)) tidx;

        ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhxtype) (list2tree leaves) kpidx;

        sapl <- rcons sapl (sigc, ap);
      }

      sig <- sapl;
      sigl <- rcons sigl sig;
    }

    root <- nth witness (nth witness rootstd (d - 1)) 0;

    (* Ask adversary to provide a forgery (given public key and list of signatures) *)
    (m', sig', idx') <@ A(O_THFC).forge((root, ps, ad), sigl);

    (tidx, kpidx) <- (Index.val idx', 0);
    root' <- m';
    tkpidxs <- [];
    pkWOTSs <- [];
    leavess <- [];
    pkWOTSs' <- [];
    leavess' <- [];
    while (size pkWOTSs' < d) {
      (tidx, kpidx) <- edivz tidx l';

      (sigc', ap') <- nth witness sig' (size pkWOTSs');

      (pkWOTS', okC) <@ FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C(root', sigc'.`1, sigc'.`2, ps,
                          (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) chtype) kpidx));
      pkWOTS <- nth witness (nth witness (nth witness pkWOTStd (size pkWOTSs')) tidx) kpidx;

      leaf' <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) pkcotype) kpidx)
                    (flatten (map DigestBlock.val (DBLL.val pkWOTS')));
      leaf <- nth witness (nth witness (nth witness leavestd (size pkWOTSs')) tidx) kpidx;

      root' <- val_ap_trh ps (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) trhxtype) ap' kpidx leaf';
      root <- nth witness (nth witness rootstd (size pkWOTSs')) tidx;

      tkpidxs <- rcons tkpidxs (tidx, kpidx);
      pkWOTSs <- rcons pkWOTSs pkWOTS;
      leavess <- rcons leavess leaf;
      pkWOTSs' <- rcons pkWOTSs' pkWOTS';
      leavess' <- rcons leavess' leaf';
    }

    (* Find (first) index where leaves/WOTS+C public keys constitute a pkco collision *)
    cidx <- find (fun (x : ((_ *  _) * _) * _) => x.`1.`1.`1 = x.`1.`1.`2 /\ x.`1.`2 <> x.`2)
                 (zip (zip (zip leavess' leavess) pkWOTSs') pkWOTSs);

    (tidx, kpidx) <- nth witness tkpidxs cidx;

    fidx <- StdBigop.Bigint.BIA.bigi predT (fun i => nr_trees i) 0 cidx * l' + tidx * l' + kpidx;

    pkWOTS' <- nth witness pkWOTSs' cidx;

    return (fidx, flatten (map DigestBlock.val (DBLL.val pkWOTS')));
  }
}.

(* Reduction adversary against SM-DT-TCR-C of trh (WOTS+C hypertree). *)
module (R_SMDTTCRCTRH_C (A : Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF) : FSSLXMTWES.TRHC_TCR.Adv_SMDTTCRC)
       (O : FSSLXMTWES.TRHC_TCR.Oracle_SMDTTCR, OC : FSSLXMTWES.TRHC.Oracle_THFC) = {
  var ad : adrs
  var ml : msgFLSLXMSSMTTW list
  (* NB: NO module-var `ps` (grind-in-find); see R_SMDTTCRCPKCO_C above. *)
  var skWOTStd : skWOTS list list list
  var pkWOTStd : pkWOTS list list list
  (* Built in `find` (they are seed-dependent), NOT in `pick`. *)
  var sigWOTStd : sigWOTS list list list
  var counterstd : cntr list list list
  var leavestd : dgstblock list list list
  var nodestd : dgstblock list list list list
  var rootstd : dgstblock list list

  (* Collection-oracle wrapper handed to A (here OC already IS a TRHC.Oracle_THFC). *)
  module O_THFC : FSSLXMTWES.TRHC.Oracle_THFC = {
    var ads : adrs list
    var xs : dgst list

    proc init(psi : pseed) : unit = {
      ads <- [];
      xs <- [];
    }

    proc query(adq : adrs, x : dgst) : dgstblock = {
      var y : dgstblock;
      y <@ OC.query(adq, x);
      ads <- rcons ads adq;
      xs <- rcons xs x;
      return y;
    }

    proc get_tweaks() : adrs list = {
      return ads;
    }
  }

  proc pick() : unit = {
    var ch_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var pkWOTS : dgstblock list;
    var pkWOTSlp : pkWOTS list;
    var pkWOTSnt : pkWOTS list list;
    var leaf : dgstblock;
    var leaveslp : dgstblock list;
    var leavesnt : dgstblock list list;
    var root : dgstblock;
    var rootsnt, rootsntp : dgstblock list;
    var lnode, rnode, node : dgstblock;
    var nodespl, nodescl : dgstblock list;
    var nodes : dgstblock list list;
    var i : int;

    (* Initialize (wrapper around) collection oracle *)
    O_THFC.init(witness);

    (* Ask adversary to provide list of messages to sign *)
    ml <@ A(O_THFC).choose();

    (* Initialize address *)
    ad <- adz;

    (* Seed-INDEPENDENT cube only (see R_SMDTTCRCPKCO_C.pick above).  This is
       MM45's R_SMDTTCRCTRH_EUFNAGCMA.pick body with the em/sigWOTS/counter pure
       assignments deleted; every oracle call, its address argument, its input
       argument, and every loop bound is unchanged. *)
    skWOTStd <- [];
    pkWOTStd <- [];
    leavestd <- [];
    rootstd <- [];
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      pkWOTSnt <- [];
      leavesnt <- [];
      rootsnt <- [];
      rootsntp <- last ml rootstd;
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        pkWOTSlp <- [];
        leaveslp <- [];
        while (size skWOTSlp < l') {
          skWOTS <- [];
          pkWOTS <- [];
          while (size skWOTS < len) {
            ch_ele <$ ddgstblock;
            skWOTS <- rcons skWOTS ch_ele;

            (* FULL chain walk to w-1 -> pkWOTS is grind-INDEPENDENT. *)
            i <- 0;
            while (i < w - 1) {
              ch_ele <@ OC.query(set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype)
                                                                (size skWOTSlp)) (size pkWOTS)) i,
                                 DigestBlock.val ch_ele);

              i <- i + 1;
            }

            pkWOTS <- rcons pkWOTS ch_ele;
          }

          (* Compress the WOTS+C public key to a leaf via the collection oracle (pkco) *)
          leaf <@ OC.query(set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) pkcotype) (size skWOTSlp),
                           flatten (map DigestBlock.val pkWOTS));

          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
          pkWOTSlp <- rcons pkWOTSlp (DBLL.insubd pkWOTS);
          leaveslp <- rcons leaveslp leaf;
        }

        nodes <- [];
        while (size nodes < h') {
          nodespl <- last leaveslp nodes;

          nodescl <- [];
          while (size nodescl < nr_nodesx (size nodes + 1)) {
            lnode <- nth witness nodespl (2 * size nodescl);
            rnode <- nth witness nodespl (2 * size nodescl + 1);

            (* Merkle node via trh (CHALLENGE oracle) *)
            node <@ O.query(set_thtbidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) trhxtype)
                                        (size nodes + 1) (size nodescl),
                            DigestBlock.val lnode ++ DigestBlock.val rnode);

            nodescl <- rcons nodescl node;
          }
          nodes <- rcons nodes nodescl;
        }
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
        pkWOTSnt <- rcons pkWOTSnt pkWOTSlp;
        leavesnt <- rcons leavesnt leaveslp;
        rootsnt <- rcons rootsnt (nth witness (nth witness nodes (h' - 1)) 0);
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
      pkWOTStd <- rcons pkWOTStd pkWOTSnt;
      leavestd <- rcons leavestd leavesnt;
      rootstd <- rcons rootstd rootsnt;
    }
  }

  proc find(ps : pseed) : int * dgst = {
    var m : msgFLSLXMSSMTTW;
    var sigc, sigc' : sigWOTS * cntr;
    var pkWOTS' : pkWOTS;
    var ap, ap' : apFLXMSSTW;
    var sapl : sigFLSLXMSSMTTWC;
    var sig : sigFLSLXMSSMTTWC;
    var sigl : sigFLSLXMSSMTTWC list;
    var m' : msgFLSLXMSSMTTW;
    var sig' : sigFLSLXMSSMTTWC;
    var idx' : index;
    var root, root' : dgstblock;
    var tidx, kpidx, hidx, bidx : int;
    var tkpidxs : (int * int) list;
    var leaf, leaf' : dgstblock;
    var leaves : dgstblock list;
    var leavess, leavess' : dgstblock list;
    var rootss, rootss' : dgstblock list;
    var cidx, fidx : int;
    var okC : bool;
    var cr;
    var cnode : dgst;
    (* --- locals for the seed-dependent rebuild (grind-in-find) --- *)
    var em : EmsgWOTS.emsgWOTS;
    var em_ele : int;
    var counter : cntr;
    var skWOTSr : dgstblock list;
    var sigWOTS : dgstblock list;
    var sigWOTS_ele : dgstblock;
    var sigWOTSlp : sigWOTS list;
    var sigWOTSnt : sigWOTS list list;
    var counterlp : cntr list;
    var counternt : cntr list list;
    var rootsntp : dgstblock list;

    (* ====================================================================
       GRIND-IN-FIND (identical to R_SMDTTCRCPKCO_C.find above; see the full
       rationale there).  `pick` is seed-free and its transcript is MM45's; the
       seed-dependent +C counters and WOTS+C signatures are rebuilt HERE, under
       the game's revealed `ps`, out of pick's grind-INDEPENDENT `skWOTStd` and
       `rootstd`.  ZERO oracle calls.
       ==================================================================== *)
    sigWOTStd <- [];
    counterstd <- [];
    while (size sigWOTStd < d) {
      sigWOTSnt <- [];
      counternt <- [];
      rootsntp <- last ml (take (size sigWOTStd) rootstd);
      while (size sigWOTSnt < nr_trees (size sigWOTStd)) {
        sigWOTSlp <- [];
        counterlp <- [];
        while (size sigWOTSlp < l') {
          root <- nth witness rootsntp (size sigWOTSnt * l' + size sigWOTSlp);

          counter <- grindC ps (set_kpidx (set_typeidx (set_ltidx ad (size sigWOTStd) (size sigWOTSnt)) chtype) (size sigWOTSlp)) root;
          em <- encode_msgWOTS_C ps (set_kpidx (set_typeidx (set_ltidx ad (size sigWOTStd) (size sigWOTSnt)) chtype) (size sigWOTSlp)) root counter;

          (* READ the chain seeds pick sampled -- never resample. *)
          skWOTSr <- DBLL.val (nth witness (nth witness (nth witness skWOTStd (size sigWOTStd)) (size sigWOTSnt)) (size sigWOTSlp));

          sigWOTS <- [];
          while (size sigWOTS < len) {
            em_ele <- BaseW.val em.[size sigWOTS];

            sigWOTS_ele <- cf ps (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size sigWOTStd) (size sigWOTSnt)) chtype)
                                                       (size sigWOTSlp)) (size sigWOTS))
                              0 em_ele (DigestBlock.val (nth witness skWOTSr (size sigWOTS)));

            sigWOTS <- rcons sigWOTS sigWOTS_ele;
          }

          sigWOTSlp <- rcons sigWOTSlp (DBLL.insubd sigWOTS);
          counterlp <- rcons counterlp counter;
        }
        sigWOTSnt <- rcons sigWOTSnt sigWOTSlp;
        counternt <- rcons counternt counterlp;
      }
      sigWOTStd <- rcons sigWOTStd sigWOTSnt;
      counterstd <- rcons counterstd counternt;
    }

    (* Sign adversary-chosen messages using computed leaves/(signatures,counters) *)
    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);

      sapl <- [];
      (tidx, kpidx) <- (size sigl, 0);
      while (size sapl < d) {
        (tidx, kpidx) <- edivz tidx l';

        sigc <- (nth witness (nth witness (nth witness sigWOTStd (size sapl)) tidx) kpidx,
                 nth witness (nth witness (nth witness counterstd (size sapl)) tidx) kpidx);

        leaves <- nth witness (nth witness leavestd (size sapl)) tidx;

        ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhxtype) (list2tree leaves) kpidx;

        sapl <- rcons sapl (sigc, ap);
      }

      sig <- sapl;
      sigl <- rcons sigl sig;
    }

    root <- nth witness (nth witness rootstd (d - 1)) 0;

    (* Ask adversary to provide a forgery (given public key and list of signatures) *)
    (m', sig', idx') <@ A(O_THFC).forge((root, ps, ad), sigl);

    (tidx, kpidx) <- (Index.val idx', 0);
    root' <- m';
    tkpidxs <- [];
    leavess <- [];
    rootss <- [];
    leavess' <- [];
    rootss' <- [];
    while (size leavess' < d) {
      (tidx, kpidx) <- edivz tidx l';

      (sigc', ap') <- nth witness sig' (size leavess');

      (pkWOTS', okC) <@ FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C(root', sigc'.`1, sigc'.`2, ps,
                          (set_kpidx (set_typeidx (set_ltidx ad (size leavess') tidx) chtype) kpidx));

      leaf' <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad (size leavess') tidx) pkcotype) kpidx)
                    (flatten (map DigestBlock.val (DBLL.val pkWOTS')));
      leaf <- nth witness (nth witness (nth witness leavestd (size leavess')) tidx) kpidx;

      root' <- val_ap_trh ps (set_typeidx (set_ltidx ad (size leavess') tidx) trhxtype) ap' kpidx leaf';
      root <- nth witness (nth witness rootstd (size leavess')) tidx;

      tkpidxs <- rcons tkpidxs (tidx, kpidx);
      rootss <- rcons rootss root;
      leavess <- rcons leavess leaf;
      rootss' <- rcons rootss' root';
      leavess' <- rcons leavess' leaf';
    }

    (* First authentication path (in the forgery) that yields a trh collision *)
    cidx <- find (fun (x : ((_ *  _) * _) * _) => x.`1.`1.`1 = x.`1.`1.`2 /\ x.`1.`2 <> x.`2)
                 (zip (zip (zip rootss' rootss) leavess') leavess);

    (* Authentication path and leaf that allow to extract a collision *)
    (sigc', ap') <- nth witness sig' cidx;
    leaf' <- nth witness leavess' cidx;

    (tidx, kpidx) <- nth witness tkpidxs cidx;

    leaves <- nth witness (nth witness leavestd cidx) tidx;

    cr <- extract_coll_bt_ap_trh ps (set_typeidx (set_ltidx ad cidx tidx) trhxtype)
                                 (list2tree leaves) (DBHPL.val ap') (rev (int2bs h' kpidx)) leaf' h' 0;

    cnode <- (DigestBlock.val cr.`3) ++ (DigestBlock.val cr.`4);
    (hidx, bidx) <- cr.`5;

    fidx <- StdBigop.Bigint.BIA.bigi predT (fun i => nr_trees i) 0 cidx * (2 ^ h' - 1) + tidx * (2 ^ h' - 1) +
            StdBigop.Bigint.BIA.bigi predT (fun i => nr_nodesx i) 1 hidx + bidx;

    return (fidx, cnode);
  }
}.
