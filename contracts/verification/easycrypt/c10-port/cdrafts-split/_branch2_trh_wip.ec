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



(* --------------------------------------------------------------------------
   HONEST +C SIG-CUBE ELEMENT (pure operators).

   Under GRIND-IN-FIND the reduction's `pick` does NOT build sigWOTStd; `find`
   rebuilds it from pick's skWOTStd/rootstd once the public seed is revealed.
   The byequiv therefore cannot align sigWOTStd at the cube-build seq -- it must
   instead carry a CHARACTERIZATION of the honest game's sigWOTStd{1} as a pure
   function of (ps, ad, ml, rootstd, skWOTStd), and then observe that find's
   rebuild computes literally that same function.

   These operators name that function.  They transcribe, index-for-index, the
   honest V-game element lines (this file, EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V):
     ht_root : the to-be-signed root  `nth witness rootsntp (j * l' + u)` with
               `rootsntp = last ml rootstd` taken at layer i, i.e. over the
               i-element PREFIX of rootstd (find takes `take i rootstd` for
               exactly this reason);
     ht_chad : the WOTS keypair (chtype) address of leaf (i,j,u);
     ht_cnt  : the ground-grinded +C counter at that address;
     ht_sigc : the cube element `(DBLL.insubd sigWOTS, counter)`, whose t-th
               chain value is the V-game's `cf ps (set_chidx .. t) 0
               (BaseW.val em.[t]) (DigestBlock.val skWOTS[t])`.
   -------------------------------------------------------------------------- *)
op ht_chad (a : adrs) (i j u : int) : adrs =
  set_kpidx (set_typeidx (set_ltidx a i j) chtype) u.

op ht_root (mlst : msgFLSLXMSSMTTW list) (rtd : dgstblock list list) (i j u : int) : dgstblock =
  nth witness (last mlst (take i rtd)) (j * l' + u).

op ht_cnt (p : pseed) (a : adrs) (mlst : msgFLSLXMSSMTTW list) (rtd : dgstblock list list)
          (i j u : int) : cntr =
  grindC p (ht_chad a i j u) (ht_root mlst rtd i j u).

op ht_sigc (p : pseed) (a : adrs) (mlst : msgFLSLXMSSMTTW list) (rtd : dgstblock list list)
           (skd : skWOTS list list list) (i j u : int) : sigWOTS * cntr =
  (DBLL.insubd
     (mkseq (fun (t : int) =>
        cf p (set_chidx (ht_chad a i j u) t) 0
             (BaseW.val (encode_msgWOTS_C p (ht_chad a i j u) (ht_root mlst rtd i j u)
                                            (ht_cnt p a mlst rtd i j u)).[t])
             (DigestBlock.val
                (nth witness (DBLL.val (nth witness (nth witness (nth witness skd i) j) u)) t)))
      len),
   ht_cnt p a mlst rtd i j u).

(* --------------------------------------------------------------------------
   LOCAL (IN-PROGRESS-LAYER) FORM OF THE SAME OPERATOR.

   `ht_sigc` reads the WOTS secret key out of the FINISHED cube `skd` and the
   to-be-signed root out of the FINISHED root cube `rtd`.  Inside the cube-BUILD
   (ADMIT-1a) neither exists yet: at layer `i` the honest game holds the current
   layer's keys in the local `skWOTSnt` / `skWOTSlp` and the current layer's
   to-be-signed roots in the local `rootsntp`.  `ht_sigc_at` is the same function
   with those two reads turned into parameters, so it can be stated as a loop
   invariant at every nesting level; `ht_sigcE` is the (definitional) bridge that
   turns it back into `ht_sigc` once the layer is `rcons`ed into the cube.

   Soundness of the conversion at the rcons point:
     * `ht_root mlst (rcons rtd rt) i j u = nth witness (last mlst rtd) (j*l'+u)`
       when `i = size rtd`, because `take i (rcons rtd rt) = rtd`;  and it is
       UNCHANGED for every already-finished `i < size rtd`, because
       `take i (rcons rtd rt) = take i rtd` there.  Hence the outer-level
       invariant is stable under the layer `rcons` -- the reason `ht_root` was
       defined with the `take i` prefix in the first place.
     * `nth .. (rcons skd sk) i .. = nth .. skd i ..` for `i < size skd`, and the
       new layer's entry is exactly the local `skWOTSnt` entry.
   -------------------------------------------------------------------------- *)
op ht_sigc_at (p : pseed) (a : adrs) (rt : dgstblock) (i j u : int)
              (sk : dgstblock list) : sigWOTS * cntr =
  (DBLL.insubd
     (mkseq (fun (t : int) =>
        cf p (set_chidx (ht_chad a i j u) t) 0
             (BaseW.val (encode_msgWOTS_C p (ht_chad a i j u) rt
                                            (grindC p (ht_chad a i j u) rt)).[t])
             (DigestBlock.val (nth witness sk t)))
      len),
   grindC p (ht_chad a i j u) rt).

lemma ht_sigcE (p : pseed) (a : adrs) (mlst : msgFLSLXMSSMTTW list)
               (rtd : dgstblock list list) (skd : skWOTS list list list) (i j u : int) :
    ht_sigc p a mlst rtd skd i j u
  = ht_sigc_at p a (ht_root mlst rtd i j u) i j u
               (DBLL.val (nth witness (nth witness (nth witness skd i) j) u)).
proof. by rewrite /ht_sigc /ht_sigc_at /ht_cnt. qed.

(* The two stability facts the cube-build's layer `rcons` needs, isolated. *)
lemma ht_root_rcons_lt (mlst : msgFLSLXMSSMTTW list) (rtd : dgstblock list list)
                       (rt : dgstblock list) (i j u : int) :
  i <= size rtd => ht_root mlst (rcons rtd rt) i j u = ht_root mlst rtd i j u.
proof. by move=> le_i; rewrite /ht_root -cats1 take_catl. qed.

lemma ht_root_rcons_eq (mlst : msgFLSLXMSSMTTW list) (rtd : dgstblock list list)
                       (rt : dgstblock list) (j u : int) :
  ht_root mlst (rcons rtd rt) (size rtd) j u
  = nth witness (last mlst rtd) (j * l' + u).
proof. by rewrite /ht_root -cats1 take_size_cat. qed.

(* The two directions the cube-build's LAYER `rcons` needs, at `ht_sigc` level:
   already-finished layers are unaffected, and the layer just appended equals the
   local (`ht_sigc_at`) form the middle-level loop invariant carries. *)
lemma ht_sigc_rcons_lt (p : pseed) (a : adrs) (mlst : msgFLSLXMSSMTTW list)
                       (rtd : dgstblock list list) (rt : dgstblock list)
                       (skd : skWOTS list list list) (sk : skWOTS list list) (i j u : int) :
     0 <= i < size skd
  => size rtd = size skd
  =>   ht_sigc p a mlst (rcons rtd rt) (rcons skd sk) i j u
     = ht_sigc p a mlst rtd skd i j u.
proof.
move=> [ge0_i lti] eqsz.
by rewrite !ht_sigcE ht_root_rcons_lt 1:/# nth_rcons iftrue 1:/#.
qed.

lemma ht_sigc_rcons_eq (p : pseed) (a : adrs) (mlst : msgFLSLXMSSMTTW list)
                       (rtd : dgstblock list list) (rt : dgstblock list)
                       (skd : skWOTS list list list) (sk : skWOTS list list) (j u : int) :
     size rtd = size skd
  =>   ht_sigc p a mlst (rcons rtd rt) (rcons skd sk) (size rtd) j u
     = ht_sigc_at p a (nth witness (last mlst rtd) (j * l' + u)) (size rtd) j u
                  (DBLL.val (nth witness (nth witness sk j) u)).
proof.
move=> eqsz.
by rewrite ht_sigcE ht_root_rcons_eq nth_rcons eqsz iffalse 1:// iftrue 1://.
qed.

(* --------------------------------------------------------------------------
   THE TRANSITIVITY STEP, as a checked lemma rather than prose.

   `seq 7 7` (PART 1a) pins the honest cube: sigWOTStd{1} = ht_sigc (a PAIR).
   `seq 0 4` (PART 2)  pins the reduction's two cubes: R.sigWOTStd = ht_sigc.`1
                       and R.counterstd = ht_sigc.`2.
   The signing-loop simulation in ADMIT-1b-rest reads `sigcins` on side 1 and
   the pair `(nth .. R.sigWOTStd .., nth .. R.counterstd ..)` on side 2; this is
   exactly the equality it needs, and it is where the grind-in-find
   restructuring is PAID FOR rather than deferred.  Note the index-range
   hypotheses: MM45 gets the corresponding step for free (its two cubes are
   equal as LISTS), so establishing 0 <= tidx < nr_trees .. / 0 <= kpidx < l'
   from the `edivz` chain is a genuine added obligation of the +C port.
   ANTI-VACUITY CONTROL (run): dropping the `hR` rewrite from the proof fails
   with "[by]: cannot close goals", so the R-side sig characterization is
   load-bearing and the lemma is not closing by pair-eta alone.
   -------------------------------------------------------------------------- *)
lemma ht_sigcube_transitivity
        (sgL : (sigWOTS * cntr) list list list)
        (sgR : sigWOTS list list list) (cnR : cntr list list list)
        (p : pseed) (a : adrs) (mlst : msgFLSLXMSSMTTW list)
        (rtd : dgstblock list list) (skd : skWOTS list list list) (i j u : int) :
     0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l'
  => (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
        nth witness (nth witness (nth witness sgL i) j) u
        = ht_sigc p a mlst rtd skd i j u)
  => (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
        nth witness (nth witness (nth witness sgR i) j) u
        = (ht_sigc p a mlst rtd skd i j u).`1)
  => (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
        nth witness (nth witness (nth witness cnR i) j) u
        = (ht_sigc p a mlst rtd skd i j u).`2)
  =>   nth witness (nth witness (nth witness sgL i) j) u
     = (nth witness (nth witness (nth witness sgR i) j) u,
        nth witness (nth witness (nth witness cnR i) j) u).
proof.
move=> rng_i rng_j rng_u hL hR hC.
by rewrite hL // hR // hC.
qed.

(* Pointwise-to-`mkseq` bridge: a list whose length is `n` and whose every entry
   is `f` at that index IS `mkseq f n`.  This is what turns the chain-loop's
   per-index invariant into the `mkseq` inside `ht_sigc`. *)
lemma eq_mkseq_of_nth (s : dgstblock list) (f : int -> dgstblock) (n : int) :
     0 <= n
  => size s = n
  => (forall (t : int), 0 <= t < n => nth witness s t = f t)
  => s = mkseq f n.
proof.
move=> ge0_n szs nths.
apply (eq_from_nth witness); 1: by rewrite size_mkseq /#.
by move=> t rng; rewrite nth_mkseq /#.
qed.

(* --------------------------------------------------------------------------
   TELESCOPING CONTRADICTION (pure logic; +C-independent).

   The combinatorial core of MM45's zero case (FL_SL_XMSS_MT_ES.ec:5327-5336):
   if the reconstructed top root matches, the forged message is fresh, and NONE
   of the three per-layer collision flags fires, then walking DOWN from layer d
   to layer 0 forces `m' = mi`, contradicting freshness.

   Extracted as a standalone lemma (MM45 inlines it) because the +C `is_valid`
   carries the EXTRA conjuncts `size sig' = d` and `allOkC`.  `size sig' = d`
   mentions `d`, so MM45's in-place `elim: d` produces an induction hypothesis
   whose antecedent pins `size sg = dd` while the step supplies `size sg = dd+1`
   -- the IH is then unusable.  Abstracting the telescope away from `sig'`
   removes that spurious coupling; `allOkC` is simply dropped (it only makes the
   antecedent harder to satisfy, so discarding it strengthens this lemma).
   -------------------------------------------------------------------------- *)
lemma ht_telescope_contra (dx : int) (m' mi : msgFLSLXMSSMTTW)
                          (rs rs' lfs lfs' : dgstblock list)
                          (pkw pkw' : pkWOTS list) :
  0 <= dx =>
  nth witness (m' :: rs') dx = nth witness (mi :: rs) dx =>
  m' <> mi =>
  ! (exists (i : int), 0 <= i < dx /\ nth witness pkw' i = nth witness pkw i
       /\ nth witness (m' :: rs') i <> nth witness (mi :: rs) i) =>
  ! (exists (i : int), 0 <= i < dx /\ nth witness lfs' i = nth witness lfs i
       /\ nth witness pkw' i <> nth witness pkw i) =>
  ! (exists (i : int), 0 <= i < dx /\ nth witness (m' :: rs') (i + 1) = nth witness (mi :: rs) (i + 1)
       /\ nth witness lfs' i <> nth witness lfs i) =>
  false.
proof. by elim: dx => /#. qed.

(* ==========================================================================
   SEAM: SECOND ler_add branch byequiv (pkco / trh collision buckets).
   +C port of MM45 FL_SL_XMSS_MT_ES.ec:4697-6298 (the second branch).

   TARGET
   ------
     Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A_ht, FC.O_THFC_Default).main() @ &m :
          res /\ !EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES]
     <= Pr[PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(A_ht), ..).main() @ &m : res]
      + Pr[TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(A_ht), ..).main() @ &m : res]

   The LHS instantiation `OC := FC.O_THFC_Default` is FORCED: seam_branch1_WOTSC
   (drafts/_seam_byequiv_wip.ec:1889) bounds the SAME probability with that
   instantiation, and both branches must be summands of one `ler_add` on one
   `Pr[..]`.  The RHS inner collection oracles are the per-clone defaults
   (FSSLXMTWES.PKCOC.O_THFC_Default / FSSLXMTWES.TRHC.O_THFC_Default), related
   to FC.O_THFC_Default by the byequiv invariant exactly as in MM45 (which
   likewise crosses O_THFC_Default{1} ~ PKCOC.O_THFC_Default{2}).

   SHAPE (MM45 :4697/:5326)
   ------------------------
     rewrite Pr[mu_split valid_TCRPKCO] ler_add.
     + <PKCO byequiv>                                   (* MM45 :4698-5325 *)
     rewrite Pr[mu_split valid_TCRTRH] ler_naddr.
     + <zero case: res /\ !vw /\ !vp /\ !vt is IMPOSSIBLE>   (* MM45 :5327-5336 *)
     <TRH byequiv>                                      (* MM45 :5338-6298 *)

   +C DELTA THAT MATTERS FOR ALL THREE PARTS (the ONE genuine rework)
   ------------------------------------------------------------------
   MM45 builds the WHOLE cube -- INCLUDING sigWOTStd -- inside the reduction's
   `pick`, because MM45's WOTS signature is seed-independent given skWOTS.  Our
   reductions are GRIND-IN-FIND: `pick` builds skWOTStd/pkWOTStd/leavestd/rootstd
   only, and `find(pp)` rebuilds sigWOTStd + counterstd from pick's skWOTStd.
   Consequence for the byequiv: after the cube-build `seq`, the invariant can
   align skWOTStd/pkWOTStd/leavestd/rootstd but NOT sigWOTStd/counterstd; those
   are re-established by an ADDITIONAL prologue `seq` at the head of the
   find-portion (pure, oracle-free, and by construction equal to the honest
   V-game cube -- the element line is literally the V-game's sigWOTS line with
   the `<$ ddgstblock` sample replaced by a read of pick's sampled seed).

   STATUS: see the per-admit residual block at the end of this file.
   ========================================================================== *)
lemma seam_branch2
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -FC.O_THFC_Default,
             -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default }) &m :
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    hoare[ A_ht(R_SMDTTCRCPKCO_C(A_ht, FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                                 FSSLXMTWES.PKCOC.O_THFC_Default).O_THFC).choose :
             R_SMDTTCRCPKCO_C.O_THFC.ads = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads ] =>
    hoare[ A_ht(R_SMDTTCRCTRH_C(A_ht, FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                                FSSLXMTWES.TRHC.O_THFC_Default).O_THFC).choose :
             R_SMDTTCRCTRH_C.O_THFC.ads = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads ] =>
    Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A_ht, FC.O_THFC_Default).main() @ &m :
         res /\ !EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES]
    <=
    Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(A_ht),
         FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
    +
    Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(A_ht),
         FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res].
proof.
move=> hencb allnpkcoads allntrhads.
rewrite Pr[mu_split EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_TCRPKCO] RealOrder.ler_add.
+ (* ======================================================================
     PKCO BRANCH (MM45 :4698-5325).
     ====================================================================== *)
  byequiv => //.
  proc.
  inline{2} 5; inline{2} 4.
  swap{1} 1 3.
  inline{1} 2; inline{2} 3; inline{2} 2; inline{2} 8.
  swap{2} 7 4.
  (* ---- PART 0: choose alignment (MM45 :4703-4735).
          NOTE the CROSS-CLONE oracle hop FC.O_THFC_Default{1} ~ PKCOC.O_THFC_Default{2}.
          It is sound because BOTH are `Collection` clones instantiated with the SAME
          collection function (`op fc <- thfc`, `op get_diff <- size`:
          WOTS_TW_ES.ec:450-455 and FL_SL_XMSS_MT_ES.ec:407-412), so the two `query`
          bodies are literally `df <- size x; y <- thfc df pp tw x; tws <- rcons tws tw`.
          MM45 makes the same hop (its unqualified O_THFC_Default is TRHC's, related to
          PKCOC's here); our LHS is FC's because seam_branch1_WOTSC fixed that
          instantiation and both branches must split ONE probability. ---- *)
  seq 5 10 : (   ={glob A_ht}
              /\ ps{1} = pp{2}
              /\ ps{1} = FC.O_THFC_Default.pp{1}
              /\ pp{2} = PKCOC_TCR.O_SMDTTCR_Default.pp{2}
              /\ pp{2} = PKCOC.O_THFC_Default.pp{2}
              /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCPKCO_C.O_THFC.ads{2}
              /\ ml{1} = R_SMDTTCRCPKCO_C.ml{2}
              /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}).
  - call (:   ={glob A_ht, arg}
           /\ FC.O_THFC_Default.pp{1} = PKCOC.O_THFC_Default.pp{2}
           /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCPKCO_C.O_THFC.ads{2}
           /\ R_SMDTTCRCPKCO_C.O_THFC.ads{2} = PKCOC.O_THFC_Default.tws{2}
           /\ R_SMDTTCRCPKCO_C.O_THFC.ads{2} = []
           ==>
              ={glob A_ht, res}
           /\ FC.O_THFC_Default.pp{1} = PKCOC.O_THFC_Default.pp{2}
           /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCPKCO_C.O_THFC.ads{2}
           /\ R_SMDTTCRCPKCO_C.O_THFC.ads{2} = PKCOC.O_THFC_Default.tws{2}
           /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}).
    * conseq (: ={glob A_ht, arg} /\ FC.O_THFC_Default.pp{1} = PKCOC.O_THFC_Default.pp{2} /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCPKCO_C.O_THFC.ads{2} /\ R_SMDTTCRCPKCO_C.O_THFC.ads{2} = PKCOC.O_THFC_Default.tws{2}
                ==>
                ={glob A_ht, res} /\ FC.O_THFC_Default.pp{1} = PKCOC.O_THFC_Default.pp{2} /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCPKCO_C.O_THFC.ads{2} /\ R_SMDTTCRCPKCO_C.O_THFC.ads{2} = PKCOC.O_THFC_Default.tws{2})
             _
             (: R_SMDTTCRCPKCO_C.O_THFC.ads = []
                ==>
                all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads) => //.
      proc (FC.O_THFC_Default.pp{1} = PKCOC.O_THFC_Default.pp{2} /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCPKCO_C.O_THFC.ads{2} /\ R_SMDTTCRCPKCO_C.O_THFC.ads{2} = PKCOC.O_THFC_Default.tws{2}) => //.
      proc; inline{2} 1.
      by wp; skip.
    by wp; rnd; skip.
  (* ---- PART 1: cube-build seq (MM45 :4736-4765 post; :4766-5100 proof).
          MM45 is `seq 7 8`; ours is `seq 7 7` because R's `pick` has NO
          `sigWOTStd <- []` (grind-in-find defers the whole sig cube to `find`).
          Two consequences for the POST:
            (a) MM45's `sigWOTStd{1} = R.sigWOTStd{2}` conjunct is DELETED -- at
                this point R.sigWOTStd is still the (unassigned) module var;
            (b) it is REPLACED by a CHARACTERIZATION of the honest sigWOTStd{1}
                as `ht_sigc ps ad ml rootstd skWOTStd`, which is exactly what
                find's rebuild loop recomputes.  Without (b) the alignment of
                `sigl` at the signing loop -- and hence `={arg}` at A.forge --
                is unreachable, so (b) is load-bearing, not decorative. ---- *)
  seq 7 7 : (   #pre
             /\ ad{1} = adz
             /\ ad{1} = R_SMDTTCRCPKCO_C.ad{2}
             /\ skWOTStd{1} = R_SMDTTCRCPKCO_C.skWOTStd{2}
             /\ pkWOTStd{1} = R_SMDTTCRCPKCO_C.pkWOTStd{2}
             /\ leavestd{1} = R_SMDTTCRCPKCO_C.leavestd{2}
             /\ rootstd{1} = R_SMDTTCRCPKCO_C.rootstd{2}
             /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness (nth witness (nth witness sigWOTStd{1} i) j) u
                   =
                   ht_sigc ps{1} ad{1} ml{1} rootstd{1} skWOTStd{1} i j u)
             /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.leavestd{2} i) j) u
                   =
                   pkco PKCOC_TCR.O_SMDTTCR_Default.pp{2}
                        (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} i j) pkcotype) u)
                        (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.pkWOTStd{2} i) j) u)))))
             /\ (forall (adx : adrs * dgst),
                   adx \in PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                   <=>
                   (exists (i j u : int), 0 <= i < d /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
                     adx = nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                             (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)))
             /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                       (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
                   =
                   (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} i j) pkcotype) u,
                    flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.pkWOTStd{2} i) j) u)))))
             /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = pkcotype) PKCOC_TCR.O_SMDTTCR_Default.ts{2}
             /\ uniq (unzip1 PKCOC_TCR.O_SMDTTCR_Default.ts{2})
             /\ size PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                = StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 d).
  - (* ---- PART 1a: cube-build ESTABLISHMENT (+C port of MM45 :4766-5100). ---- *)
    while (   ={glob A_ht}
           /\ ps{1} = pp{2}
           /\ ps{1} = FC.O_THFC_Default.pp{1}
           /\ ps{1} = PKCOC_TCR.O_SMDTTCR_Default.pp{2}
           /\ ps{1} = PKCOC.O_THFC_Default.pp{2}
           /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCPKCO_C.O_THFC.ads{2}
           /\ ad{1} = adz
           /\ ad{1} = R_SMDTTCRCPKCO_C.ad{2}
           /\ ml{1} = R_SMDTTCRCPKCO_C.ml{2}
           /\ skWOTStd{1} = R_SMDTTCRCPKCO_C.skWOTStd{2}
           /\ pkWOTStd{1} = R_SMDTTCRCPKCO_C.pkWOTStd{2}
           /\ leavestd{1} = R_SMDTTCRCPKCO_C.leavestd{2}
           /\ rootstd{1} = R_SMDTTCRCPKCO_C.rootstd{2}
           /\ (forall (i j u : int), 0 <= i < size skWOTStd{1} => 0 <= j < nr_trees i => 0 <= u < l' =>
                 nth witness (nth witness (nth witness sigWOTStd{1} i) j) u
                 =
                 ht_sigc ps{1} ad{1} ml{1} rootstd{1} skWOTStd{1} i j u)
           /\ (forall (i j u : int), 0 <= i < size skWOTStd{1} => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.leavestd{2} i) j) u
                   =
                   pkco PKCOC_TCR.O_SMDTTCR_Default.pp{2}
                        (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} i j) pkcotype) u)
                        (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.pkWOTStd{2} i) j) u)))))
           /\ (forall (adx : adrs * dgst),
                   adx \in PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                   <=>
                   (exists (i j u : int), 0 <= i < size skWOTStd{1} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
                     adx = nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                             (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)))
           /\ (forall (i j u : int), 0 <= i < size skWOTStd{1} => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                       (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
                   =
                   (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} i j) pkcotype) u,
                    flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.pkWOTStd{2} i) j) u)))))
           /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = pkcotype) PKCOC_TCR.O_SMDTTCR_Default.ts{2}
           /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}
           /\ uniq (unzip1 PKCOC_TCR.O_SMDTTCR_Default.ts{2})
           /\ size PKCOC_TCR.O_SMDTTCR_Default.ts{2} = StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 (size skWOTStd{1})
           /\ size skWOTStd{1} = size sigWOTStd{1}
           /\ size R_SMDTTCRCPKCO_C.skWOTStd{2} = size R_SMDTTCRCPKCO_C.pkWOTStd{2}
           /\ size R_SMDTTCRCPKCO_C.skWOTStd{2} = size R_SMDTTCRCPKCO_C.leavestd{2}
           /\ size R_SMDTTCRCPKCO_C.skWOTStd{2} = size R_SMDTTCRCPKCO_C.rootstd{2}
           /\ size skWOTStd{1} <= d).
    * wp => /=.
      while (   ={skWOTSnt, pkWOTSnt, leavesnt, rootsnt}
             /\ rootsntp{1} = rootsntp0{2}
             /\ ={glob A_ht}
             /\ ps{1} = pp{2}
             /\ ps{1} = FC.O_THFC_Default.pp{1}
             /\ ps{1} = PKCOC_TCR.O_SMDTTCR_Default.pp{2}
             /\ ps{1} = PKCOC.O_THFC_Default.pp{2}
             /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCPKCO_C.O_THFC.ads{2}
             /\ ad{1} = adz
             /\ ad{1} = R_SMDTTCRCPKCO_C.ad{2}
             /\ ml{1} = R_SMDTTCRCPKCO_C.ml{2}
             /\ skWOTStd{1} = R_SMDTTCRCPKCO_C.skWOTStd{2}
             /\ pkWOTStd{1} = R_SMDTTCRCPKCO_C.pkWOTStd{2}
             /\ leavestd{1} = R_SMDTTCRCPKCO_C.leavestd{2}
             /\ rootstd{1} = R_SMDTTCRCPKCO_C.rootstd{2}
             /\ rootsntp{1} = last ml{1} rootstd{1}
             /\ (forall (i j u : int), 0 <= i < size skWOTStd{1} => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness (nth witness (nth witness sigWOTStd{1} i) j) u
                   =
                   ht_sigc ps{1} ad{1} ml{1} rootstd{1} skWOTStd{1} i j u)
             /\ (forall (j u : int), 0 <= j < size skWOTSnt{1} => 0 <= u < l' =>
                   nth witness (nth witness sigWOTSnt{1} j) u
                   =
                   ht_sigc_at ps{1} ad{1} (nth witness rootsntp{1} (j * l' + u))
                              (size skWOTStd{1}) j u
                              (DBLL.val (nth witness (nth witness skWOTSnt{1} j) u)))
             /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_C.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.leavestd{2} i) j) u
                   =
                   pkco PKCOC_TCR.O_SMDTTCR_Default.pp{2}
                        (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} i j) pkcotype) u)
                        (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.pkWOTStd{2} i) j) u)))))
             /\ (forall (j u : int), 0 <= j < size skWOTSnt{2} => 0 <= u < l' =>
                   nth witness (nth witness leavesnt{2} j) u
                   =
                   pkco PKCOC_TCR.O_SMDTTCR_Default.pp{2}
                        (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} (size R_SMDTTCRCPKCO_C.skWOTStd{2}) j) pkcotype) u)
                        (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness pkWOTSnt{2} j) u)))))
             /\ (forall (adx : adrs * dgst),
                   adx \in PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                   <=>
                   (exists (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_C.skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
                     adx = nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u))
                   \/
                   (exists (j u : int), 0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\
                     adx = nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCPKCO_C.skWOTStd{2}) * l' + j * l' + u)))
             /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_C.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
                   =
                   (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} i j) pkcotype) u,
                    flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.pkWOTStd{2} i) j) u)))))
             /\ (forall (j u : int), 0 <= j < size skWOTSnt{2} => 0 <= u < l' =>
                   nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCPKCO_C.skWOTStd{2}) * l' + j * l' + u)
                   =
                   (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} (size R_SMDTTCRCPKCO_C.skWOTStd{2}) j) pkcotype) u,
                    flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness pkWOTSnt{2} j) u)))))
             /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = pkcotype) PKCOC_TCR.O_SMDTTCR_Default.ts{2}
             /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}
             /\ uniq (unzip1 PKCOC_TCR.O_SMDTTCR_Default.ts{2})
             /\ size PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                = StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 (size R_SMDTTCRCPKCO_C.skWOTStd{2})
                  + size skWOTSnt{2} * l'
             /\ size skWOTSnt{1} = size sigWOTSnt{1}
             /\ size skWOTSnt{2} = size pkWOTSnt{2}
             /\ size skWOTSnt{2} = size leavesnt{2}
             /\ size skWOTSnt{2} = size rootsnt{2}
             /\ size skWOTStd{1} = size sigWOTStd{1}
             /\ size R_SMDTTCRCPKCO_C.skWOTStd{2} = size R_SMDTTCRCPKCO_C.pkWOTStd{2}
             /\ size R_SMDTTCRCPKCO_C.skWOTStd{2} = size R_SMDTTCRCPKCO_C.leavestd{2}
             /\ size R_SMDTTCRCPKCO_C.skWOTStd{2} = size R_SMDTTCRCPKCO_C.rootstd{2}
             /\ size skWOTSnt{1} <= nr_trees (size skWOTStd{1})
             /\ size skWOTStd{1} < d).
      + (* ADMIT-1a-INNERTREE: one inner tree (MM45 :4853-5170). *)
        wp => /=.
        (* ---- (a) the side-2-only tree-hash `nodes` loop (MM45 :4854-4943).
                PURE MM45 PORT, no +C content: relates side 2's per-node
                `OC.query` walk to side 1's `val_bt_trh (list2tree leaveslp)`.
                Renames: trhtype -> trhxtype, nr_nodes -> nr_nodesx. ---- *)
        while{2} (   R_SMDTTCRCPKCO_C.ad{2} = adz
                  /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}
                  /\ (forall (i j : int), 0 <= i < size nodes{2} => 0 <= j < nr_nodesx (i + 1) =>
                        nth witness (nth witness nodes{2} i) j
                        =
                        let leaveslpp = take (2 ^ (i + 1)) (drop (j * (2 ^ (i + 1))) leaveslp{2}) in
                          val_bt_trh_gen PKCOC.O_THFC_Default.pp{2}
                            (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} (size R_SMDTTCRCPKCO_C.skWOTStd{2}) (size skWOTSnt{2})) trhxtype)
                            (list2tree leaveslpp) (i + 1) j)
                  /\ size R_SMDTTCRCPKCO_C.skWOTStd{2} < d
                  /\ size skWOTSnt{2} < nr_trees (size R_SMDTTCRCPKCO_C.skWOTStd{2})
                  /\ size leaveslp{2} = l'
                  /\ size nodes{2} <= h')
                 (h' - size nodes{2}).
        - move => _ z.
          wp => /=.
          while (   R_SMDTTCRCPKCO_C.ad = adz
                 /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws
                 /\ nodespl = last leaveslp nodes
                 /\ (forall (i j : int), 0 <= i < size nodes => 0 <= j < nr_nodesx (i + 1) =>
                       nth witness (nth witness nodes i) j
                       =
                       let leaveslpp = take (2 ^ (i + 1)) (drop (j * (2 ^ (i + 1))) leaveslp) in
                         val_bt_trh_gen PKCOC.O_THFC_Default.pp
                           (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad (size R_SMDTTCRCPKCO_C.skWOTStd) (size skWOTSnt)) trhxtype)
                           (list2tree leaveslpp) (i + 1) j)
                 /\ (forall (j : int), 0 <= j < size nodescl =>
                       nth witness nodescl j
                       =
                       let leaveslpp = take (2 ^ (size nodes + 1)) (drop (j * (2 ^ (size nodes + 1))) leaveslp) in
                         val_bt_trh_gen PKCOC.O_THFC_Default.pp
                           (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad (size R_SMDTTCRCPKCO_C.skWOTStd) (size skWOTSnt)) trhxtype)
                           (list2tree leaveslpp) (size nodes + 1) j)
                 /\ size R_SMDTTCRCPKCO_C.skWOTStd < d
                 /\ size skWOTSnt < nr_trees (size R_SMDTTCRCPKCO_C.skWOTStd)
                 /\ size leaveslp = l'
                 /\ size nodescl <= nr_nodesx (size nodes + 1)
                 /\ size nodes < h')
                (nr_nodesx (size nodes + 1) - size nodescl).
          * move=> z'.
            inline 3.
            wp; skip => /> &2 allnpkcotws nthnds ntndscl ltd_szsktd ltnt_szsknt eqlp_szlfslp _ lthp_sznds ltnn_szndscl.
            rewrite size_rcons -cats1 all_cat allnpkcotws /= -!andbA andbA; split => [| /#].
            rewrite gettype_setalltrh 1:valx_adz; 1..4: smt(size_ge0).
            split => [| j ge0_j ltszndscl1_j]; 1: smt(dist_adrstypes).
            rewrite nth_rcons; case (j < size nodescl{2}) => [/# | neqszj].
            have eqszj : j = size nodescl{2} by smt(size_rcons).
            rewrite eqszj /= size_cat ?DigestBlock.valP /= (: 2 ^ (size nodes{2} + 1) = 2 ^ (size nodes{2}) + 2 ^ (size nodes{2})).
            + by rewrite exprD_nneg 1:size_ge0 //= expr1 /#.
            rewrite take_take_drop_cat 1,2:IntOrder.expr_ge0 //=.
            rewrite drop_drop 1:IntOrder.expr_ge0 //= 1:IntOrder.mulr_ge0 1:size_ge0 1:IntOrder.addr_ge0 1,2:IntOrder.expr_ge0 //=.
            have ge1_2aszn2szncl : 1 <= 2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1.
            + rewrite 2!IntOrder.ler_subr_addr /=.
              rewrite &(IntOrder.ler_trans (2 + 2 * (nr_nodesx (size nodes{2} + 1) - 1))) 1:/#.
              by rewrite /nr_nodesx mulzDr /= -{1}(expr1 2) -exprD_nneg // /#.
            rewrite -nth_last (list2treeS (size nodes{2})) 1:size_ge0.
            + rewrite size_take 1:IntOrder.expr_ge0 1:// size_drop 1:IntOrder.mulr_ge0 1:size_ge0 1:IntOrder.addr_ge0 1,2:IntOrder.expr_ge0 //.
              rewrite eqlp_szlfslp /l' (: 2 ^ h' = 2 ^ (h' - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
              pose szn2 := 2 ^ (size nodes{2}).
              rewrite (: 2 ^ (h' - size nodes{2}) * szn2 - size nodescl{2} * (szn2 + szn2) = (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2}) * szn2) 1:/#.
              pose mx := max _ _; rewrite (: 2 ^ (size nodes{2}) < mx) // /mx.
              pose sb := ((_ - _ * _) * _)%Int; rewrite &(IntOrder.ltr_le_trans sb) /sb 2:IntOrder.maxrr.
              by rewrite IntOrder.ltr_pmull 1:IntOrder.expr_gt0 // /#.
            + rewrite size_take 1:IntOrder.expr_ge0 1:// size_drop 1:IntOrder.addr_ge0 1:IntOrder.expr_ge0 // 1:IntOrder.mulr_ge0 1:size_ge0 1:IntOrder.addr_ge0 1,2:IntOrder.expr_ge0 //.
              rewrite eqlp_szlfslp /l' (: 2 ^ h' = 2 ^ (h' - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
              pose szn2 := 2 ^ (size nodes{2}).
              rewrite (: 2 ^ (h' - size nodes{2}) * szn2 - (szn2 + size nodescl{2} * (szn2 + szn2)) = (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) 1:/#.
              pose sb := ((_ - _ - _) * _)%Int.
              move: ge1_2aszn2szncl; rewrite lez_eqVlt => -[eq1_2as | gt1_2as].
              - by rewrite /sb -eq1_2as /= lez_maxr 1:IntOrder.expr_ge0.
              rewrite lez_maxr /sb 1:IntOrder.mulr_ge0 2:IntOrder.expr_ge0 //= 1:IntOrder.subr_ge0 1:IntOrder.ler_subr_addr.
              - rewrite &(IntOrder.ler_trans (1 + 2 * (nr_nodesx (size nodes{2} + 1) - 1))) 1:/#.
                by rewrite /nr_nodesx mulzDr -{1}(expr1 2) -exprD_nneg // /#.
              rewrite (: szn2 < (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) //.
              by rewrite IntOrder.ltr_pmull 1:IntOrder.expr_gt0.
            rewrite /= /val_bt_trh_gen /trhi /trh /updhbidx /=; congr => [/# |].
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
          by wp; skip => /> &2; smt(IntOrder.expr_ge0 nth_rcons size_rcons).
        (* ---- (b) the two-sided l' loop (MM45 :4944-5170).
                +C DELTAS at this level:
                  * side 2's `pick` has NO sigWOTSlp (grind-in-find), so MM45's
                    `={sigWOTSlp}` is REPLACED by a one-sided ht_sigc_at
                    characterization of sigWOTSlp{1};
                  * MM45's `size skWOTSlp{2} = size sigWOTSlp{2}` becomes
                    `size skWOTSlp{1} = size sigWOTSlp{1}`. ---- *)
        wp => /=.
        while (   ={skWOTSlp, pkWOTSlp, leaveslp}
               /\ ps{1} = PKCOC_TCR.O_SMDTTCR_Default.pp{2}
               /\ ps{1} = PKCOC.O_THFC_Default.pp{2}
               /\ ad{1} = adz
               /\ ad{1} = R_SMDTTCRCPKCO_C.ad{2}
               /\ (forall (u : int), 0 <= u < size sigWOTSlp{1} =>
                     nth witness sigWOTSlp{1} u
                     =
                     ht_sigc_at ps{1} ad{1} (nth witness rootsntp{1} (size skWOTSnt{1} * l' + u))
                                (size skWOTStd{1}) (size skWOTSnt{1}) u
                                (DBLL.val (nth witness skWOTSlp{1} u)))
               /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_C.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                     nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.leavestd{2} i) j) u
                     =
                     pkco PKCOC_TCR.O_SMDTTCR_Default.pp{2} (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} i j) pkcotype) u)
                          (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.pkWOTStd{2} i) j) u)))))
               /\ (forall (j u : int), 0 <= j < size skWOTSnt{2} => 0 <= u < l' =>
                     nth witness (nth witness leavesnt{2} j) u
                     =
                     pkco PKCOC_TCR.O_SMDTTCR_Default.pp{2} (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} (size R_SMDTTCRCPKCO_C.skWOTStd{2}) j) pkcotype) u)
                          (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness pkWOTSnt{2} j) u)))))
               /\ (forall (u : int), 0 <= u < size skWOTSlp{2} =>
                     nth witness leaveslp{2} u
                     =
                     pkco PKCOC_TCR.O_SMDTTCR_Default.pp{2} (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} (size R_SMDTTCRCPKCO_C.skWOTStd{2}) (size skWOTSnt{2})) pkcotype) u)
                          (flatten (map DigestBlock.val (DBLL.val (nth witness pkWOTSlp{2} u)))))
               /\ (forall (adx : adrs * dgst),
                     adx \in PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                     <=>
                     (exists (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_C.skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
                       adx = nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u))
                     \/
                     (exists (j u : int), 0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\
                       adx = nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCPKCO_C.skWOTStd{2}) * l' + j * l' + u))
                     \/
                     (exists (u : int), 0 <= u < size skWOTSlp{2} /\
                       adx = nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCPKCO_C.skWOTStd{2}) * l'
                             + size skWOTSnt{2} * l' + u)))
               /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_C.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                     nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
                     =
                     (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} i j) pkcotype) u,
                      flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.pkWOTStd{2} i) j) u)))))
               /\ (forall (j u : int), 0 <= j < size skWOTSnt{2} => 0 <= u < l' =>
                     nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCPKCO_C.skWOTStd{2}) * l' + j * l' + u)
                     =
                     (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} (size R_SMDTTCRCPKCO_C.skWOTStd{2}) j) pkcotype) u,
                      flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness pkWOTSnt{2} j) u)))))
               /\ (forall (u : int), 0 <= u < size skWOTSlp{2} =>
                     nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCPKCO_C.skWOTStd{2}) * l' + size skWOTSnt{2} * l' + u)
                     =
                     (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} (size R_SMDTTCRCPKCO_C.skWOTStd{2}) (size skWOTSnt{2})) pkcotype) u,
                      flatten (map DigestBlock.val (DBLL.val (nth witness pkWOTSlp{2} u)))))
               /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = pkcotype) PKCOC_TCR.O_SMDTTCR_Default.ts{2}
               /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}
               /\ uniq (unzip1 PKCOC_TCR.O_SMDTTCR_Default.ts{2})
               /\ size PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                  =
                  StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 (size R_SMDTTCRCPKCO_C.skWOTStd{2})
                  + size skWOTSnt{2} * l'
                  + size skWOTSlp{2}
               /\ size skWOTSlp{1} = size sigWOTSlp{1}
               /\ size skWOTSlp{2} = size pkWOTSlp{2}
               /\ size skWOTSlp{2} = size leaveslp{2}
               /\ size skWOTSnt{1} = size skWOTSnt{2}
               /\ size skWOTSnt{2} = size pkWOTSnt{2}
               /\ size skWOTSnt{2} = size leavesnt{2}
               /\ size skWOTSnt{2} = size rootsnt{2}
               /\ size skWOTStd{1} = size R_SMDTTCRCPKCO_C.skWOTStd{2}
               /\ size R_SMDTTCRCPKCO_C.skWOTStd{2} = size R_SMDTTCRCPKCO_C.pkWOTStd{2}
               /\ size R_SMDTTCRCPKCO_C.skWOTStd{2} = size R_SMDTTCRCPKCO_C.leavestd{2}
               /\ size R_SMDTTCRCPKCO_C.skWOTStd{2} = size R_SMDTTCRCPKCO_C.rootstd{2}
               /\ size skWOTSlp{1} <= l'
               /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
               /\ size skWOTStd{1} < d).
        + (* ---- one WOTS+C keypair.  MM45 :5019-5162.
                  +C DELTA: side 2's chain walk is a PLAIN full 0..w-1 walk --
                  `pick` has no `em` and builds no signature, so MM45's
                  `if (i0 = em_ele)` sig-reveal branches are DELETED (not ported)
                  and the `exists* sigWOTS0{2}` freeze is unnecessary.  Side 1's
                  two-step `cf .. 0 em_ele` then `cf .. em_ele (w-1-em_ele)` is
                  reconciled with it by ch_comp. ---- *)
          inline{2} 4.
          wp => /=.
          while (   ={skWOTS}
                 /\ ps{1} = PKCOC.O_THFC_Default.pp{2}
                 /\ ad{1} = adz
                 /\ ad{1} = R_SMDTTCRCPKCO_C.ad{2}
                 /\ pkWOTS{1} = pkWOTS0{2}
                 /\ (forall (t : int), 0 <= t < size sigWOTS{1} =>
                       nth witness sigWOTS{1} t
                       =
                       cf ps{1} (set_chidx (ht_chad ad{1} (size skWOTStd{1}) (size skWOTSnt{1}) (size skWOTSlp{1})) t)
                            0 (BaseW.val em{1}.[t]) (DigestBlock.val (nth witness skWOTS{1} t)))
                 /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}
                 /\ size skWOTS{2} = size pkWOTS0{2}
                 /\ size skWOTS{1} = size sigWOTS{1}
                 /\ size skWOTStd{1} = size R_SMDTTCRCPKCO_C.skWOTStd{2}
                 /\ size skWOTSnt{1} = size skWOTSnt{2}
                 /\ size skWOTSlp{1} = size skWOTSlp{2}
                 /\ size skWOTS{1} <= len
                 /\ size skWOTSlp{1} < l'
                 /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
                 /\ size skWOTStd{1} < d).
          - wp => /=.
            while{2} (   R_SMDTTCRCPKCO_C.ad{2} = adz
                      /\ ch_ele{2}
                         =
                         cf PKCOC.O_THFC_Default.pp{2}
                            (set_chidx (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_C.ad{2} (size R_SMDTTCRCPKCO_C.skWOTStd{2}) (size skWOTSnt{2})) chtype) (size skWOTSlp{2})) (size pkWOTS0{2}))
                            0 i0{2} (DigestBlock.val (nth witness skWOTS{2} (size pkWOTS0{2})))
                      /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}
                      /\ size pkWOTS0{2} < len
                      /\ size skWOTSlp{2} < l'
                      /\ size skWOTSnt{2} < nr_trees (size R_SMDTTCRCPKCO_C.skWOTStd{2})
                      /\ size R_SMDTTCRCPKCO_C.skWOTStd{2} < d
                      /\ 0 <= i0{2} <= w - 1)
                     (w - 1 - i0{2}).
            * move=> _ z.
              inline 1.
              wp; skip => /> &2 allnpkcotws ltlen_szpk ltlp_szsklp ltnt_szsknt ltd_szsktd ge0_i _ ltw1_i.
              rewrite DigestBlock.valP /=.
              rewrite /cf (chS _ _ _ _ (i0{2} + 1)) 1:validxadrs_validwadrs_setallch 2..5,7:// 1:valx_adz 1:DigestBlock.valP 1:// 1,2:/# /f /=.
              rewrite -cats1 all_cat allnpkcotws /=.
              by rewrite gettype_setallch 1:valx_adz 3..5://; smt(size_ge0 dist_adrstypes).
            wp; rnd; wp; skip => /> &1 &2 nthsig allnpkcotws eqszskpk eqszsksig eqszsksktd eqszsksknt eqszsksklp lelen_szsk ltlp_szsklp ltnt_szsknt ltd_szsktd ltlen_szsk skwele skwelein.
            rewrite -eqszskpk.
            split.
            + rewrite nth_rcons /=.
              rewrite /cf ch0 1:validxadrs_validwadrs_setallch 1:valx_adz 5:DigestBlock.valP 5,6://; 1..4: smt(size_ge0).
              by rewrite DigestBlock.valKd /=; smt(val_w).
            move=> tws i.
            split => [| gew1_i allnpkcotwsp _ _ _ _ ge0_i lew1_i]; 1: smt().
            split.
            + congr.
              rewrite nth_rcons /= eqszsksktd eqszsksknt eqszsksklp.
              rewrite (: i = BaseW.val em{1}.[size skWOTS{2}] + (w - 1 - BaseW.val em{1}.[size skWOTS{2}])) 1:/#.
              rewrite /cf (ch_comp _ _ _ 0).
              + by apply validxadrs_validwadrs_setallch; smt(size_ge0 valx_adz).
              + by rewrite DigestBlock.valP.
              + smt().
              + smt(BaseW.valP).
              + smt(BaseW.valP val_w).
              + smt(BaseW.valP val_w).
              by smt().
            split.
            + move=> t ge0_t; rewrite size_rcons => ltt.
              rewrite ?nth_rcons -eqszsksig.
              case (t < size skWOTS{2}) => [ltt' | nltt]; 1: by rewrite nthsig 1:/# /ht_chad.
              have -> /= : t = size skWOTS{2} by smt().
              by rewrite /ht_chad.
            by rewrite ?size_rcons; smt().
          wp; skip => /> &1 &2 nthsiglp lfsnth lfsnth1 lfsnth2 tsdef tsnth tsnth1 tsnth2 allpkcots allnpkcotws uqunz1ts szts
                        eqszsksiglp eqszskpklp eqszsklfslp eqszsksknt eqszskpknt eqszsklfsnt eqszskrsnt
                        eqszsksktd eqszskpktd eqszsklfstd eqszskrstd _ ltnt_szsknt ltd_szsktd ltlp_szsklp.
          split; 1: smt(ge2_len).
          move=> sigw tws pkw skw _ gelen_szskw nthsigw allnpkcotwsp eqszskpkw eqszsksigw lelen_szskw.
          move: nthsiglp; rewrite eqszsksktd eqszsksknt => nthsiglp.
          move: nthsigw; rewrite eqszsksktd eqszsksknt => nthsigw.
          rewrite /nr_nodes_ht /nr_nodesx /= -/l' -StdBigop.Bigint.BIA.mulr_suml in szts.
          rewrite ?size_rcons.
          (* (1) the leaf equality: pure address alignment, now definitional. *)
          split; 1: done.
          (* (2) +C: the sigWOTSlp characterization -- the eq_mkseq_of_nth crux
                 (identical to the one already closed in PART 2). *)
          split.
          + move=> u ge0_u ltu.
            rewrite ?nth_rcons -eqszsksiglp.
            case (u < size skWOTSlp{2}) => [ltu' | nltu]; 1: by rewrite nthsiglp 1:/#.
            have -> /= : u = size skWOTSlp{2} by smt().
            rewrite /ht_sigc_at /ht_chad /=; congr.
            rewrite DBLL.insubdK 1:/#.
            apply (eq_mkseq_of_nth _ _ len); [smt(ge2_len) | smt() | ].
            by move=> t rng; rewrite /= nthsigw 1:/# /ht_chad.
          (* (3)-(11): MM45 :5100-5162 verbatim (ts bookkeeping). *)
          split => [u ge0_i|]; 1: by rewrite ?nth_rcons -eqszskpklp -eqszsklfslp; 1: smt(DBLL.insubdK).
          split => [adx |]; 1: rewrite mem_rcons /=; 1: split.
          - elim => [-> | /tsdef].
            * right; right; exists (size skWOTSlp{2}).
              by split; [smt(size_ge0) | rewrite nth_rcons /#].
            elim => [[i j u [ir] [jr] [ur adval]]|].
            * by left; exists i j u; rewrite ir jr ur /= nth_rcons szts ltbignrt_i.
            elim => [[j u [jr] [ur adval]]|].
            * right; left; exists j u; rewrite jr ur /= nth_rcons szts.
              pose igl := _ + j * l' + _; pose igr := _ + size skWOTSnt{2} * l' + _.
              rewrite (: igl < igr) /igl /igr 2://.
              rewrite -2!addrA IntOrder.ler_lt_add 1://.
              suff /#: j * l' + u < size skWOTSnt{2} * l' /\ 0 <= size skWOTSlp{2}.
              by rewrite size_ge0 /= (: size skWOTSnt{2} = size skWOTSnt{2} - 1 + 1) 1:// mulrDl IntOrder.ler_lt_add 2:// /#.
            elim => [u [ur adval]].
            * right; right; exists u; split; 1: smt(size_ge0).
              by rewrite nth_rcons szts /#.
          - case; 2: case.
            * elim=> i j u [rng_i [rng_j [rng_u]]].
              by rewrite nth_rcons szts ltbignrt_i 1..5:// /= tsdef /#.
            * elim=> j u [rng_j [rng_u]].
              rewrite nth_rcons szts.
              pose igl := _ + j * l' + _; pose igr := _ + size skWOTSnt{2} * l' + _.
              rewrite (: igl < igr) /igl /igr 2:/= 2:tsnth1 //.
              + rewrite -2!addrA IntOrder.ler_lt_add 1://.
                suff /#: j * l' + u < size skWOTSnt{2} * l' /\ 0 <= size skWOTSlp{2}.
                by rewrite size_ge0 /= (: size skWOTSnt{2} = size skWOTSnt{2} - 1 + 1) 1:// mulrDl IntOrder.ler_lt_add 2:// /#.
              by rewrite tsdef /#.
            by elim=> u [rng_u]; rewrite nth_rcons szts /#.
          split => [* | ]; 1: by rewrite nth_rcons szts ltbignrt_i // /= tsnth.
          split => [j u * | ]; 1: rewrite nth_rcons szts.
          - pose igl := _ + j * l' + _; pose igr := _ + size skWOTSnt{2} * l' + _.
            rewrite (: igl < igr) /igl /igr 2:/= 2:tsnth1 //.
            rewrite -2!addrA IntOrder.ler_lt_add 1://.
            suff /#: j * l' + u < size skWOTSnt{2} * l' /\ 0 <= size skWOTSlp{2}.
            by rewrite size_ge0 /= (: size skWOTSnt{2} = size skWOTSnt{2} - 1 + 1) 1:// mulrDl IntOrder.ler_lt_add 2:// /#.
          split => [u | ]; 1: rewrite ?nth_rcons szts => ge0_u ltsz1_u.
          - rewrite -eqszskpklp; case (u < size skWOTSlp{2}) => [ltszsk_u | nltszsk_u].
            + by rewrite tsnth2 // /#.
            by rewrite (: u = size skWOTSlp{2}) 1:/# /= DBLL.insubdK /#.
          split; 1: rewrite -cats1 all_cat allpkcots /=.
          - by rewrite gettype_setkptypeltchpkco 1:valx_adz 3,4://; 1,2:smt(size_ge0).
          split.
          + rewrite map_rcons rcons_uniq /= uqunz1ts /= mapP negb_exists => adx /=.
            rewrite negb_and -implybE => /tsdef.
            case; 2: case.
            - elim=> i j u [rng_i [rng_j [rng_u]]].
              rewrite tsnth 1..3:// => -> /=.
              rewrite -HA.eq_adrs_idxs (neq_from_nth witness _ _ 5) 2://.
              by rewrite neqlidx_setkptypelt 1:valx_adz 4..7,9://; smt(size_ge0).
            - elim=> j u [rng_j [rng_u]].
              rewrite tsnth1 1..2:// => -> /=.
              rewrite -HA.eq_adrs_idxs (neq_from_nth witness _ _ 4) 2://.
              by rewrite neqtidx_setkptypelt 1:valx_adz 4..7,9://; smt(size_ge0).
            elim=> u [rng_u].
            rewrite tsnth2 1:// => -> /=.
            rewrite -HA.eq_adrs_idxs (neq_from_nth witness _ _ 2) 2://.
            by apply (neqkpidx_setkptypelt (size R_SMDTTCRCPKCO_C.skWOTStd{2}) (size R_SMDTTCRCPKCO_C.skWOTStd{2}) (size skWOTSnt{2}) (size skWOTSnt{2}) pkcotype (size skWOTSlp{2}) u adz); smt(size_ge0 valx_adz).
          by rewrite /nr_nodes_ht /nr_nodesx /= -/l' -StdBigop.Bigint.BIA.mulr_suml; smt().
        (* REMAINING IN 1a: the l'-loop entry/exit + nodes-loop entry/exit leaf
           (MM45 :5163-5177) plus our extra ht_sigc_at (sigWOTSnt) conjunct. *)
        admit.
      (* LAYER-RCONS ADEQUACY: middle-loop entry + exit ==> the outer invariant.
         This is where `ht_sigc_at` is converted back to `ht_sigc` (ht_sigc_rcons_eq)
         and where the already-finished layers survive the cube `rcons`
         (ht_sigc_rcons_lt). *)
      wp; skip => /> &1 &2 nthsigtd lfsdef tsdef tsnth allpkcots allnpkcotws uqunz1ts szts
                           eqszsigtd eqszskpktd eqszsklfstd eqszskrtstd
                           _ ltd_szskwtd.
      split=> [| sigWOTSnt_L tws_R ts_R leavesnt_R pkWOTSnt_R rootsnt_R skWOTSnt_R
                 /lezNgt gent_szskwnt _].
      + by do! split; smt(StdOrder.IntOrder.expr_ge0).
      move=> nthsignt lfsntnth tspdef tspnth tspnth1 allpkcotsp allnpkcotwsp uqun1ts sztsp
             eqszsigwnt eqszpkskwnt eqszskwlfsnt eqszskwrsnt lent_szskwnt.
      (* (C1) the NEW ht_sigc conjunct: old layers survive the cube rcons
              (ht_sigc_rcons_lt), the fresh layer converts from its local
              ht_sigc_at form (ht_sigc_rcons_eq). *)
      split.
      + move=> i j u ge0_i; rewrite size_rcons => lti ge0_j ltj ge0_u ltu.
        case (i < size R_SMDTTCRCPKCO_C.skWOTStd{2}) => [lti' | nlti].
        - rewrite nth_rcons iftrue 1:/# ht_sigc_rcons_lt 1:/# 1:/#.
          by smt().
        have eqi : i = size R_SMDTTCRCPKCO_C.skWOTStd{2} by smt().
        rewrite eqi eqszskrtstd nth_rcons iffalse 1:/# iftrue 1:/#.
        rewrite ht_sigc_rcons_eq 1:/# -eqszskrtstd.
        by rewrite nthsignt 1:/# 1:/#.
      (* (C2) leaves characterization -- MM45 :5185-5189 verbatim. *)
      split => [i j u | ].
      + rewrite size_rcons ?nth_rcons -eqszsklfstd -eqszskpktd => *.
        case (i < size R_SMDTTCRCPKCO_C.skWOTStd{2}) => [/#| ?].
        rewrite (: i = size R_SMDTTCRCPKCO_C.skWOTStd{2}) 1:/# /=.
        by rewrite lfsntnth 1:/#.
      (* (C3) ts membership -- MM45 :5190 verbatim. *)
      split => [adx | ].
      + by split => [/tspdef | i j u]; smt(size_ge0 nth_rcons size_rcons).
      (* (C4) ts nth characterization -- MM45 :5180-5184 verbatim. *)
      split => [i j u | ].
      + rewrite size_rcons ?nth_rcons => *.
        case (i < size R_SMDTTCRCPKCO_C.pkWOTStd{2}) => [/#| ?].
        rewrite (: i = size R_SMDTTCRCPKCO_C.pkWOTStd{2}) 1:/# /=.
        by rewrite -eqszskpktd tspnth1 1:/#.
      (* (C5) ts size -- MM45 :5178 verbatim. *)
      split; 1: by rewrite sztsp size_rcons StdBigop.Bigint.BIA.big_int_recr 1:size_ge0 //= /#.
      by do! split; smt(size_rcons).
    (* ADEQUACY GATE: cube-build entry + exit ==> the `seq 7 7` post.
       This is the step that CERTIFIES the outer invariant is strong enough --
       in particular that the ONE new (ht_sigc) conjunct, carried at bound
       `size skWOTStd{1}`, really does yield the post's bound-`d` form. *)
    wp; skip => /> &2 allnpkcotws.
    split; 1: smt(StdBigop.Bigint.BIA.big_geq ge1_d).
    move=> sigWOTStd_L leavestd_R pkWOTStd_R rootstd_R skWOTStd_R tws_R ts_R.
    move=> nltd _ nthsig nthlfs tsdef tsnth allpkcots allnpkcotws2 uqts szts
           eqszsig eqszpk eqszlfs eqszrs led.
    have eqd : size skWOTStd_R = d by smt().
    move: nthsig nthlfs tsdef tsnth szts; rewrite eqd => nthsig nthlfs tsdef tsnth szts.
    by do! split; smt().
  (* ---- PART 2 (= 1b(i)): FIND-PROLOGUE ABSORPTION.  NO MM45 COUNTERPART.
          RHS-only `seq 0 4`: `ps <- pp`, the two cube inits, and the
          grind-in-find rebuild loop.  ORACLE-FREE (`find` is `{}`-restricted in
          Adv_SMDTTCRC), so this is a pure one-sided `while{2}`.  The post
          characterizes R.sigWOTStd / R.counterstd as the `ht_sigc` image, which
          is the SAME operator the `seq 7 7` post pins sigWOTStd{1} to; the two
          cubes are therefore equal by transitivity at the point of use. ---- *)
  seq 0 4 : (   #pre
             /\ ps{2} = pp{2}
             /\ size R_SMDTTCRCPKCO_C.sigWOTStd{2} = d
             /\ size R_SMDTTCRCPKCO_C.counterstd{2} = d
             /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.sigWOTStd{2} i) j) u
                   =
                   (ht_sigc ps{2} R_SMDTTCRCPKCO_C.ad{2} R_SMDTTCRCPKCO_C.ml{2}
                            R_SMDTTCRCPKCO_C.rootstd{2} R_SMDTTCRCPKCO_C.skWOTStd{2} i j u).`1)
             /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.counterstd{2} i) j) u
                   =
                   (ht_sigc ps{2} R_SMDTTCRCPKCO_C.ad{2} R_SMDTTCRCPKCO_C.ml{2}
                            R_SMDTTCRCPKCO_C.rootstd{2} R_SMDTTCRCPKCO_C.skWOTStd{2} i j u).`2)).
  - while{2} (   0 <= size R_SMDTTCRCPKCO_C.sigWOTStd{2} <= d
              /\ size R_SMDTTCRCPKCO_C.counterstd{2} = size R_SMDTTCRCPKCO_C.sigWOTStd{2}
              /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_C.sigWOTStd{2} =>
                                        0 <= j < nr_trees i => 0 <= u < l' =>
                    nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.sigWOTStd{2} i) j) u
                    =
                    (ht_sigc ps{2} R_SMDTTCRCPKCO_C.ad{2} R_SMDTTCRCPKCO_C.ml{2}
                             R_SMDTTCRCPKCO_C.rootstd{2} R_SMDTTCRCPKCO_C.skWOTStd{2} i j u).`1)
              /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_C.sigWOTStd{2} =>
                                        0 <= j < nr_trees i => 0 <= u < l' =>
                    nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.counterstd{2} i) j) u
                    =
                    (ht_sigc ps{2} R_SMDTTCRCPKCO_C.ad{2} R_SMDTTCRCPKCO_C.ml{2}
                             R_SMDTTCRCPKCO_C.rootstd{2} R_SMDTTCRCPKCO_C.skWOTStd{2} i j u).`2))
             (d - size R_SMDTTCRCPKCO_C.sigWOTStd{2}).
    (* --- outer body: one hypertree layer --- *)
    * move=> _ z.
      wp => /=.
      while (   0 <= size R_SMDTTCRCPKCO_C.sigWOTStd < d
             /\ size R_SMDTTCRCPKCO_C.counterstd = size R_SMDTTCRCPKCO_C.sigWOTStd
             /\ rootsntp = last R_SMDTTCRCPKCO_C.ml (take (size R_SMDTTCRCPKCO_C.sigWOTStd) R_SMDTTCRCPKCO_C.rootstd)
             /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_C.sigWOTStd => 0 <= j < nr_trees i => 0 <= u < l' =>
                  nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.sigWOTStd i) j) u
                  = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd i j u).`1)
             /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_C.sigWOTStd => 0 <= j < nr_trees i => 0 <= u < l' =>
                  nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.counterstd i) j) u
                  = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd i j u).`2)
             /\ 0 <= size sigWOTSnt <= nr_trees (size R_SMDTTCRCPKCO_C.sigWOTStd)
             /\ size counternt = size sigWOTSnt
             /\ (forall (j u : int), 0 <= j < size sigWOTSnt => 0 <= u < l' =>
                  nth witness (nth witness sigWOTSnt j) u
                  = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd (size R_SMDTTCRCPKCO_C.sigWOTStd) j u).`1)
             /\ (forall (j u : int), 0 <= j < size counternt => 0 <= u < l' =>
                  nth witness (nth witness counternt j) u
                  = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd (size R_SMDTTCRCPKCO_C.sigWOTStd) j u).`2))
            (nr_trees (size R_SMDTTCRCPKCO_C.sigWOTStd) - size sigWOTSnt).
      + (* --- middle body: one inner tree --- *)
        move=> z1.
        wp => /=.
        while (   0 <= size R_SMDTTCRCPKCO_C.sigWOTStd < d
                 /\ size R_SMDTTCRCPKCO_C.counterstd = size R_SMDTTCRCPKCO_C.sigWOTStd
                 /\ rootsntp = last R_SMDTTCRCPKCO_C.ml (take (size R_SMDTTCRCPKCO_C.sigWOTStd) R_SMDTTCRCPKCO_C.rootstd)
                 /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_C.sigWOTStd => 0 <= j < nr_trees i => 0 <= u < l' =>
                      nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.sigWOTStd i) j) u
                      = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd i j u).`1)
                 /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_C.sigWOTStd => 0 <= j < nr_trees i => 0 <= u < l' =>
                      nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.counterstd i) j) u
                      = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd i j u).`2)
                 /\ 0 <= size sigWOTSnt < nr_trees (size R_SMDTTCRCPKCO_C.sigWOTStd)
                 /\ size counternt = size sigWOTSnt
                 /\ (forall (j u : int), 0 <= j < size sigWOTSnt => 0 <= u < l' =>
                      nth witness (nth witness sigWOTSnt j) u
                      = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd (size R_SMDTTCRCPKCO_C.sigWOTStd) j u).`1)
                 /\ (forall (j u : int), 0 <= j < size counternt => 0 <= u < l' =>
                      nth witness (nth witness counternt j) u
                      = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd (size R_SMDTTCRCPKCO_C.sigWOTStd) j u).`2)
                 /\ 0 <= size sigWOTSlp <= l'
                 /\ size counterlp = size sigWOTSlp
                 /\ (forall (u : int), 0 <= u < size sigWOTSlp =>
                      nth witness sigWOTSlp u
                      = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd (size R_SMDTTCRCPKCO_C.sigWOTStd) (size sigWOTSnt) u).`1)
                 /\ (forall (u : int), 0 <= u < size counterlp =>
                      nth witness counterlp u
                      = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd (size R_SMDTTCRCPKCO_C.sigWOTStd) (size sigWOTSnt) u).`2))
              (l' - size sigWOTSlp).
        - (* --- l' body: one WOTS+C keypair --- *)
          move=> z2.
          wp => /=.
          while (   0 <= size R_SMDTTCRCPKCO_C.sigWOTStd < d
                     /\ size R_SMDTTCRCPKCO_C.counterstd = size R_SMDTTCRCPKCO_C.sigWOTStd
                     /\ rootsntp = last R_SMDTTCRCPKCO_C.ml (take (size R_SMDTTCRCPKCO_C.sigWOTStd) R_SMDTTCRCPKCO_C.rootstd)
                     /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_C.sigWOTStd => 0 <= j < nr_trees i => 0 <= u < l' =>
                          nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.sigWOTStd i) j) u
                          = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd i j u).`1)
                     /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_C.sigWOTStd => 0 <= j < nr_trees i => 0 <= u < l' =>
                          nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.counterstd i) j) u
                          = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd i j u).`2)
                     /\ 0 <= size sigWOTSnt < nr_trees (size R_SMDTTCRCPKCO_C.sigWOTStd)
                     /\ size counternt = size sigWOTSnt
                     /\ (forall (j u : int), 0 <= j < size sigWOTSnt => 0 <= u < l' =>
                          nth witness (nth witness sigWOTSnt j) u
                          = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd (size R_SMDTTCRCPKCO_C.sigWOTStd) j u).`1)
                     /\ (forall (j u : int), 0 <= j < size counternt => 0 <= u < l' =>
                          nth witness (nth witness counternt j) u
                          = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd (size R_SMDTTCRCPKCO_C.sigWOTStd) j u).`2)
                     /\ 0 <= size sigWOTSlp < l'
                     /\ size counterlp = size sigWOTSlp
                     /\ (forall (u : int), 0 <= u < size sigWOTSlp =>
                          nth witness sigWOTSlp u
                          = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd (size R_SMDTTCRCPKCO_C.sigWOTStd) (size sigWOTSnt) u).`1)
                     /\ (forall (u : int), 0 <= u < size counterlp =>
                          nth witness counterlp u
                          = (ht_sigc ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd R_SMDTTCRCPKCO_C.skWOTStd (size R_SMDTTCRCPKCO_C.sigWOTStd) (size sigWOTSnt) u).`2)
                     /\ root = ht_root R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd (size R_SMDTTCRCPKCO_C.sigWOTStd) (size sigWOTSnt) (size sigWOTSlp)
                     /\ counter = ht_cnt ps R_SMDTTCRCPKCO_C.ad R_SMDTTCRCPKCO_C.ml R_SMDTTCRCPKCO_C.rootstd (size R_SMDTTCRCPKCO_C.sigWOTStd) (size sigWOTSnt) (size sigWOTSlp)
                     /\ em = encode_msgWOTS_C ps (ht_chad R_SMDTTCRCPKCO_C.ad (size R_SMDTTCRCPKCO_C.sigWOTStd) (size sigWOTSnt) (size sigWOTSlp)) root counter
                     /\ skWOTSr = DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_C.skWOTStd (size R_SMDTTCRCPKCO_C.sigWOTStd)) (size sigWOTSnt)) (size sigWOTSlp))
                     /\ 0 <= size sigWOTS <= len
                     /\ (forall (t : int), 0 <= t < size sigWOTS =>
                          nth witness sigWOTS t
                          = cf ps (set_chidx (ht_chad R_SMDTTCRCPKCO_C.ad (size R_SMDTTCRCPKCO_C.sigWOTStd) (size sigWOTSnt) (size sigWOTSlp)) t) 0 (BaseW.val em.[t])
                               (DigestBlock.val (nth witness skWOTSr t))))
                (len - size sigWOTS).
          * (* --- chain body: one WOTS chain --- *)
            move=> z3.
            wp; skip => /> &hr *.
            rewrite /ht_chad !size_rcons.
            smt(nth_rcons size_ge0).
          (* l'-body prologue + chain-loop exit *)
          wp; skip => /> &hr ge0_sztd ltd_sztd eqsz_cntd nthtd nthcntd
                        ge0_sznt ltnt_sznt eqsz_cnnt nthnt nthcnnt
                        ge0_szlp lel_szlp eqsz_cnlp nthlp nthcnlp ltl_szlp.
          split; 1: smt(ge2_len).
          move=> sigWOTS0; split; 1: smt().
          move=> nltlen eqroot eqcnt eqem ge0_szsw lelen_szsw nthsw.
          rewrite !size_rcons.
          split; last by smt().
          split; 1: smt(size_ge0).
          split; 1: smt().
          split.
          + move=> u ge0_u ltu.
            rewrite nth_rcons.
            case (u < size sigWOTSlp{hr}) => [ltu' | nltu]; 1: by smt().
            have -> /= : u = size sigWOTSlp{hr} by smt().
            rewrite /ht_sigc /=; congr.
            apply (eq_mkseq_of_nth _ _ len); [smt(ge2_len) | smt() | ].
            by move=> t rng; rewrite nthsw 1:/# /ht_chad.
          move=> u ge0_u ltu.
          rewrite nth_rcons.
          case (u < size counterlp{hr}) => [ltu' | nltu]; 1: by smt().
          have -> /= : u = size counterlp{hr} by smt().
          by rewrite eqsz_cnlp /ht_sigc /ht_cnt /ht_chad /ht_root.
        (* middle-body prologue + l'-loop exit *)
        wp; skip => /> &hr ge0_sztd ltd_sztd eqsz_cntd nthtd nthcntd
                      ge0_sznt lent_sznt eqsz_cnnt nthnt nthcnnt ltnt_sznt.
        split; 1: smt(ge2_lp).
        move=> counterlp0 sigWOTSlp0; split; 1: smt().
        move=> nltl ge0_szlp lel_szlp eqsz_cnlp nthlp nthcnlp.
        rewrite !size_rcons.
        split; last by smt().
        split; 1: smt(size_ge0).
        split; 1: smt().
        split.
        + move=> j u ge0_j ltj ge0_u ltu.
          rewrite nth_rcons.
          case (j < size sigWOTSnt{hr}) => [ltj' | nltj]; 1: by smt().
          have -> /= : j = size sigWOTSnt{hr} by smt().
          by smt().
        move=> j u ge0_j ltj ge0_u ltu.
        rewrite nth_rcons.
        case (j < size counternt{hr}) => [ltj' | nltj]; 1: by smt().
        have -> /= : j = size counternt{hr} by smt().
        by smt().
      (* outer-body prologue + middle-loop exit *)
      wp; skip => /> &hr ge0_sztd led_sztd eqsz_cntd nthtd nthcntd ltd_sztd.
      split; 1: (rewrite /nr_trees; smt(StdOrder.IntOrder.expr_ge0)).
      move=> counternt0 sigWOTSnt0; split; 1: smt().
      move=> nltnt ge0_sznt lent_sznt eqsz_cnnt nthnt nthcnnt.
      rewrite !size_rcons.
      split; last by smt().
      split; 1: smt(size_ge0).
      split; 1: smt().
      split.
      + move=> i j u ge0_i lti ge0_j ltj ge0_u ltu.
        rewrite nth_rcons.
        case (i < size R_SMDTTCRCPKCO_C.sigWOTStd{hr}) => [lti' | nlti]; 1: by smt().
        have eqi : i = size R_SMDTTCRCPKCO_C.sigWOTStd{hr} by smt().
        rewrite eqi /=; smt().
      move=> i j u ge0_i lti ge0_j ltj ge0_u ltu.
      rewrite nth_rcons.
      case (i < size R_SMDTTCRCPKCO_C.counterstd{hr}) => [lti' | nlti]; 1: by smt().
      have eqi : i = size R_SMDTTCRCPKCO_C.counterstd{hr} by smt().
      rewrite eqi /=; smt().
    (* prologue inits + outer-loop entry/exit *)
    wp; skip => /> &1 &2 ????????.
    split; 1: smt(ge1_d).
    move=> counterstd_R sigWOTStd_R; split; 1: smt().
    move=> nltd ge0_sz led_sz eqsz nthsig nthcnt.
    have eqd : size sigWOTStd_R = d by smt().
    move: nthsig nthcnt; rewrite eqd => nthsig nthcnt.
    by smt().
  (* ADMIT-1b-rest: signing sim, forge, reconstruction, collision extraction;
     MM45 :5101-5325. *) admit.
rewrite Pr[mu_split EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_TCRTRH] RealOrder.ler_naddr.
+ (* ZERO CASE (MM45 :5327-5336): res /\ !vw /\ !vp /\ !vt is IMPOSSIBLE. *)
  rewrite RealOrder.ler_eqVlt; left.
  byphoare => //.
  proc.
  swap 16 11.
  wp.
  conseq (: _ ==> false); 2: by hoare.
  move=> _ _ ok idx' lfs lfs' m' ml pkw pkw' rs rs' sg.
  split => //.
  move=> [[[[[_ [rooteq _]] fresh] nvw] nvp] nvt].
  apply (ht_telescope_contra d m' (nth witness ml (Index.val idx')) rs rs' lfs lfs' pkw pkw') => //.
  smt(ge1_d).
(* ADMIT-3 (TRH byequiv) *) admit.
qed.

(* ==========================================================================
   BRANCH-2 STATUS / PER-ADMIT RESIDUAL  (2026-07-20, B3 session)

   ec-certify.sh drafts/_seam_branch2_wip.ec
     => compile=OK   admit-tactics=3   axiom-decls=0

   The admit COUNT is unchanged from the previous session (3), but ADMIT-1a
   shrank from the whole inner-tree body to a SINGLE LEAF: this session closed
   the side-2-only tree-hash `nodes` loop (MM45 :4854-4943) and the ENTIRE
   two-sided l' loop (MM45 :4944-5162) -- invariant, per-keypair body (len loop
   + chain walk) and per-keypair leaf -- 0-admit.  Only the l'-entry/exit +
   nodes-entry/exit leaf (MM45 :5163-5177) is left inside 1a.

   CLOSED IN EARLIER SESSIONS (0-admit)
   ------------------------------------
   * ht_telescope_contra + the seam_branch2 combining scaffold (both mu_splits,
     ler_add / ler_naddr chaining) + the ZERO CASE.
   * PKCO PART 0 (choose alignment, MM45 :4703-4735) incl. the cross-clone
     FC.O_THFC_Default{1} ~ PKCOC.O_THFC_Default{2} oracle hop.
   * PKCO PART 1 SPLIT: the `seq 7 7`.

   CLOSED IN THE B2 SESSION (0-admit, each with a RUN anti-vacuity control)
   ------------------------------------------------------------------------
   1. PKCO PART 2 = the whole of former ADMIT-1b(i): the GRIND-IN-FIND prologue
      `seq 0 4` (RHS-only `ps <- pp`, the two cube inits, and find's rebuild
      loop).  Proved as a 4-deep one-sided `while{2}` (d / nr_trees / l' / len).
      This is the step with NO MM45 counterpart, and it is the step that makes
      `={arg}` at A.forge reachable.
      Crux: at the len-loop exit, `DBLL.insubd sigWOTS = (ht_sigc ..).`1`, via
      the new `eq_mkseq_of_nth` (pointwise -> mkseq) bridge.
      CONTROL: swapping j<->u inside the outer while{2}'s ht_sigc index makes the
      outer-body leaf fail "cannot prove goal (strict)".
      NOTE (settled): `hencb` is NOT consumed anywhere in this step.
   2. New pure operators/lemmas (all 0-admit): ht_sigc_at, ht_sigcE,
      ht_root_rcons_lt / ht_root_rcons_eq, ht_sigc_rcons_lt / ht_sigc_rcons_eq,
      eq_mkseq_of_nth.  All reduction-agnostic (they serve the TRH admit too).
   3. PKCO PART 1a OUTER LEVEL: the per-layer two-sided `while` invariant
      (MM45 :4765-4795) + its ADEQUACY GATE (cube-build entry + loop exit ==> the
      `seq 7 7` post).  CONTROL: weakening `size skWOTStd{1} <= d` to `<= d + 1`
      makes the gate fail "cannot prove goal (strict)".
   4. PKCO PART 1a MIDDLE LEVEL: the per-inner-tree two-sided `while` invariant
      (MM45 :4796-4853) + the LAYER-RCONS CLOSING.  CONTROL: shifting the
      ht_sigc_at root index to `j * l' + u + 1` makes the closing fail.

   CLOSED IN THE B3 SESSION (0-admit) -- inside ADMIT-1a-INNERTREE
   ---------------------------------------------------------------
   5. (a) THE SIDE-2-ONLY TREE-HASH `nodes` LOOP (MM45 :4854-4943).  A pure MM45
      port with NO +C content: it relates side 2's per-node `OC.query` walk to
      side 1's `val_bt_trh (list2tree leaveslp)`.  Renames: trhtype -> trhxtype,
      nr_nodes -> nr_nodesx (and MM45's stray `/nr_nodesf` unfold is `/nr_nodesx`
      here).
   6. (b) THE WHOLE TWO-SIDED l' LOOP (MM45 :4944-5162): its invariant, the
      per-keypair body (len loop + chain walk), and the per-keypair leaf.
      The +C content, PAID FOR rather than assumed:
        * side 2's `pick` has NO `em` and builds NO signature (grind-in-find), so
          the chain-walk `while{2}` is a PLAIN 0..w-1 walk.  MM45's
          `if (i0 = em_ele)` sig-reveal branches are DELETED (not ported) and
          MM45's `exists* sigWOTS0{2}; elim* => sigwb` freeze is unnecessary --
          it exists only to state that reveal.  Side 1's two-step
          `cf .. 0 em_ele` / `cf .. em_ele (w-1-em_ele)` is reconciled with side
          2's single full chain by `ch_comp`.
        * MM45's `={sigWOTSlp}` is REPLACED by a one-sided `ht_sigc_at`
          characterization of `sigWOTSlp{1}`, and MM45's
          `size skWOTSlp{2} = size sigWOTSlp{2}` by
          `size skWOTSlp{1} = size sigWOTSlp{1}`.  The l'-exit discharges the new
          conjunct with the SAME `eq_mkseq_of_nth` crux already used in PART 2,
          plus `DBLL.insubdK`.
      The ts / uniq / leaves bookkeeping (MM45 :5100-5162) ported verbatim.

   PORT DELTAS FOUND (cumulative)
   ------------------------------
   * VARIABLE RENAMING after the inlines: `find` claims the unsuffixed names, so
     inside `pick` on side 2 the locals are `rootsntp0`, `root0`, `leaf0`,
     `pkWOTS0` and `i0`.  Use `rootsntp0{2}`.
   * MM45 does `import IntOrder Bigint BIA`; WE DO NOT.  Every bare IntOrder
     lemma therefore needs the `IntOrder.` prefix -- expr_ge0, expr_gt0,
     ltr_pmull, mulr_ge0, addr_ge0, subr_ge0, ler_subr_addr, maxrr, ler_lt_add --
     but `lez_maxr` must stay BARE (`IntOrder.lez_maxr` does not exist).
     `mulr_suml` is `StdBigop.Bigint.BIA.mulr_suml`; `bigi` is
     `StdBigop.Bigint.BIA.bigi`; `eq_adrs_idxs` is `HA.eq_adrs_idxs`;
     `valP`/`valKd`/`insubdK` must be qualified (DigestBlock. / DBLL.).
   * `take_cat'` does not exist (use `take_catl` / `take_size_cat`).
   * EasyCrypt has no `rewrite <lemma> in <hyp>`; use `move: H; rewrite eq => H`
     -- and note that this form rewrites the CONCLUSION as well, so a following
     `rewrite eq` on the goal fails with "nothing to rewrite".
   * `cf` is an op abbreviation for `ch f`; `rewrite (ch_comp ..)` / `(chS ..)`
     do NOT fire on a folded `cf` goal -- unfold with `/cf` first.

   METHOD WARNING (cost me a full compile cycle; do not repeat)
   -----------------------------------------------------------
   `easycrypt cli` (what ec-goal.sh drives) does NOT abort on a failed rewrite:
   it prints "nothing to rewrite" and CONTINUES with the unchanged goal.  A clean
   goal dump from ec-goal.sh is therefore NOT evidence of closure, and a grep for
   "error|cannot|unknown" misses that message entirely.  Only `scratch-ecc.sh` /
   `ec-certify.sh` (batch `easycrypt compile`, which exits non-zero) is the gate.

   REMAINING ADMITS (3)
   --------------------
   ADMIT-1a-INNERTREE-LEAF  (MM45 :5163-5177)
     LOCATION: the last tactic of the ADMIT-1a-INNERTREE `+` bullet, immediately
     after the two-sided l' `while`.
     PENDING GOAL (`wp; skip` has NOT been applied; the admit sits on the raw
     equiv): the remaining program is
       LHS  skWOTSlp <- []; pkWOTSlp <- []; sigWOTSlp <- []; leaveslp <- []
       RHS  skWOTSlp <- []; pkWOTSlp <- []; leaveslp <- []; nodes <- []
     and the post is the conjunction of (i) the l' loop invariant at ENTRY,
     (ii) the l' loop EXIT ==> the `nodes` loop invariant at ENTRY, and
     (iii) the `nodes` loop EXIT ==> the middle-level (per-inner-tree) invariant
     after the four/five `rcons`es.
     WHAT IS MISSING: MM45 :5163-5177, i.e.
       (a) `split => [| tws ts lfslp pkwlp sigwlp skwlp /lezNgt gelp_szskwlp _]`
           with `by split; smt(ge2_lp)` for the l' ENTRY (our extra sigWOTSlp
           conjunct is VACUOUS there, sigWOTSlp = []);
       (b) `split=> [| tws' nds]; 1: smt(ge1_hp)` for the `nodes` ENTRY;
       (c) the `nodes` EXIT: `congr; rewrite ndsnth 2:IntOrder.expr_gt0 2,3:// 2:/=;
           1: smt(ge1_hp)` then `rewrite drop0 -/l' -eqlp_szlfslp take_size /#`
           -- this is what turns `nth (nth nodes (h'-1)) 0` into
           `val_bt_trh .. (list2tree leaveslp)`;
       (d) the ONE +C conjunct MM45 does not have: re-establishing the middle
           invariant's `ht_sigc_at` characterization of `sigWOTSnt{1}` across the
           inner-tree `rcons`.  For `j < size skWOTSnt{1}` it is the incoming
           hypothesis; for `j = size skWOTSnt{1}` it is exactly the l'-loop's
           exit characterization of `sigWOTSlp{1}` (already proved), re-indexed
           by `nth_rcons` -- the same shape as the already-closed LAYER-RCONS
           step one level up, so no new mathematics is expected here.
     STATUS: the intro pattern and the hypothesis order were machine-checked
     (`&1 &2 nthsigtd nthsignt lfsnth lfsnth1 tsdef tsnth tsnth1 allpkcots
     allnpkcotws uqunz1ts szts eqszsksignt eqszskpknt eqszsklfsnt eqszskrsnt
     eqszsigtd eqszskpktd eqszsklfstd eqszskrstd _ ltd_szsktd ltnt_szsknt`), but
     the leaf itself is NOT proved.


   ADMIT-1b-rest  (MM45 :5101-5325)
     LOCATION: after PART 2's `seq 0 4`.
     PENDING GOAL: equiv of
       LHS: root <- nth (nth rootstd (d-1)) 0; pk <- (root,ps,ad); sigl <- [];
            while (size sigl < l) {..}; (m',sig',idx') <@ A.forge(pk, sigl);
            is_fresh <- ..; reconstruction loop; the three flags; is_valid
       RHS: sigl <- []; while (size sigl < l) {..}; root <- nth (nth rootstd (d-1)) 0;
            (m',sig',idx') <@ A.forge((root,ps,ad), sigl); reconstruction loop;
            cidx <- find ..; fidx <- ..; return (fidx, ..)
       ==> the byequiv post (res{1} => res{2}).
     WHAT IS MISSING:
       (i)  a `swap{2}` for the ROOT REORDERING: LHS computes `root` BEFORE the
            signing loop, RHS's find computes it AFTER.
       (ii) the signing-loop simulation.  Its ONE +C step is now available: side 1
            reads `sigcins <- nth .. sigWOTStd{1} ..` (a (sigWOTS,cntr) PAIR) while
            side 2 reads the pair `(nth .. R.sigWOTStd .., nth .. R.counterstd ..)`;
            they agree by TRANSITIVITY -- `seq 7 7`'s post pins sigWOTStd{1} to
            ht_sigc, PART 2's post pins R.sigWOTStd/R.counterstd to the same
            ht_sigc's `.1`/`.2`.  Both are stated over the SAME index range
            (0<=i<d, 0<=j<nr_trees i, 0<=u<l'), so the signing loop must first
            establish `0 <= tidx < nr_trees (size sapl)` and `0 <= kpidx < l'`
            from the `edivz` chain -- MM45 gets these for free (its cubes are
            equal as LISTS), so this is a genuine, small added obligation.
       (iii) forge call, reconstruction loop, and the pkco collision extraction +
            `fidx` index arithmetic (MM45 :5150-5325).  Per the grind-in-find
            header these carry over from MM45 UNCHANGED, because `pick`'s
            transcript is exactly MM45's.

   ADMIT-3  (TRH byequiv; MM45 :5338-6298)
     LOCATION: the last tactic of seam_branch2.
     PENDING GOAL:
       Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A_ht, FC.O_THFC_Default).main() @ &m :
            ((res /\ !valid_WOTSTWES) /\ !valid_TCRPKCO) /\ valid_TCRTRH]
       <= Pr[TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(A_ht),
                TRHC_TCR.O_SMDTTCR_Default, TRHC.O_THFC_Default).main() @ &m : res]
     WHAT IS MISSING: the entire byequiv; NOT STARTED.  It is the larger of the
     two (MM45 :5338-6298 vs :4698-5325) because the target set is the INNER
     Merkle nodes, so `ts` is indexed by (i,j,u,v) over `nr_nodesx (u+1)` and the
     extraction runs through `extract_coll_bt_ap_trh` / `sub_bt` /
     `val_bt_trh_gen` instead of a single pkco input.
     WHAT NOW TRANSFERS FROM THE PKCO BRANCH (this is the cheap part):
       * PART 0 (choose alignment) verbatim modulo
         pkcotype -> trhxtype, PKCOC -> TRHC, R_SMDTTCRCPKCO_C -> R_SMDTTCRCTRH_C;
       * PART 2 (`seq 0 4` find prologue) verbatim -- R_SMDTTCRCTRH_C.find carries
         the IDENTICAL grind-in-find rebuild, so the same 4-deep `while{2}` with
         the same ht_sigc characterizations applies;
       * the outer/middle ht_sigc machinery (ht_sigc_at, the four rcons lemmas)
         is reduction-agnostic and applies unchanged;
       * the `rootsntp0 / root0 / leaf0 / pkWOTS0 / i0` renaming caveat applies.

   ASSEMBLY TASK (outside this branch, unchanged)
   ---------------------------------------------
   seam_branch1_WOTSC (drafts/_seam_byequiv_wip.ec) and seam_branch2 (here) live
   in SEPARATE files with SEPARATE premise lists.  The final combiner -- the
   `Pr[mu_split .. valid_WOTSTWES] ler_add` step that consumes both -- needs them
   in one scope with a UNION-COMPATIBLE premise set.  The two statements were
   deliberately written over the IDENTICAL instantiation
   `EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A_ht, FC.O_THFC_Default)` and the identical
   flag carrier `EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_*`, so they chain; the
   premise UNION (branch 1 additionally carries c <= p_tgts, embdisj/embinj, the
   three dfC separations and A_wf_ht) is a known, not-yet-done assembly step.

   NOT CLAIMED
   -----------
   * ADMIT-1a-INNERTREE-LEAF, ADMIT-1b-rest and ADMIT-3 are NOT proved.  In
     particular seam_branch2 as a whole is NOT a theorem yet, and PART 1a is NOT
     closed: its outer and middle invariants are proved ADEQUATE and its
     inner-tree BODY is now proved INVARIANT except for the one entry/exit leaf
     above, which is exactly what makes the body's post reachable from the
     programs.  Until that leaf closes, the `seq 7 7` post is still not DERIVED.
   * The `seq 7 7` post is now VALIDATED (the outer adequacy gate consumes it,
     0-admit) but the outer while's BODY is still admitted, so the post is not
     yet DERIVED from the programs.  Concretely: 1a's outer and middle invariants
     are proved ADEQUATE (they imply what the next level up needs) but not yet
     proved INVARIANT (the inner-tree body is the open obligation).
   * The premise list of seam_branch2 (hencb, allnpkcoads, allntrhads) is the MM45
     premise set plus the +C encode bridge.  `hencb` is now KNOWN to be unused by
     PART 2; whether 1a-INNERTREE / 1b-rest / 3 need it (or need branch-1's dfC
     separations) is still open -- the expectation remains that they do not,
     because this branch never touches the WOTS-chain axis, but that is a
     conjecture until those close.
   ========================================================================== *)


(* ==========================================================================
   ==========================================================================
   TRH BRANCH  (= ADMIT-3 of seam_branch2 above; MM45 :5338-6298).

   SELF-CONTAINED BLOCK -- everything below this banner is new in this file and
   is meant to be transplanted back into drafts/_seam_branch2_wip.ec as ONE text
   block.  See the TRANSPLANT NOTE at the very end of the file.
   ==========================================================================
   ========================================================================== *)

lemma seam_branch2_trh
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -FC.O_THFC_Default,
             -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default }) &m :
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    hoare[ A_ht(R_SMDTTCRCTRH_C(A_ht, FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                                FSSLXMTWES.TRHC.O_THFC_Default).O_THFC).choose :
             R_SMDTTCRCTRH_C.O_THFC.ads = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads ] =>
    Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(A_ht, FC.O_THFC_Default).main() @ &m :
         ((res /\ !EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES)
              /\ !EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_TCRPKCO)
          /\ EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_TCRTRH]
    <=
    Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(A_ht),
         FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res].
proof.
move=> hencb allntrhads.
byequiv => //.
proc.
inline{2} 5; inline{2} 4.
swap{1} 1 3.
inline{1} 2; inline{2} 3; inline{2} 2; inline{2} 8.
swap{2} 7 4.
(* ---- PART 0: choose alignment (MM45 :5344-5373).
        Structurally IDENTICAL to the PKCO branch's PART 0 above, modulo the
        four renames pkcotype -> trhxtype, PKCOC_TCR -> TRHC_TCR,
        PKCOC -> TRHC, R_SMDTTCRCPKCO_C -> R_SMDTTCRCTRH_C.  The SAME
        cross-clone oracle hop FC.O_THFC_Default{1} ~ TRHC.O_THFC_Default{2}
        applies and is sound for the same reason (both are `Collection` clones
        over the same collection function, so the two `query` bodies are
        literally the same three assignments). ---- *)
seq 5 10 : (   ={glob A_ht}
            /\ ps{1} = pp{2}
            /\ ps{1} = FC.O_THFC_Default.pp{1}
            /\ pp{2} = TRHC_TCR.O_SMDTTCR_Default.pp{2}
            /\ pp{2} = TRHC.O_THFC_Default.pp{2}
            /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCTRH_C.O_THFC.ads{2}
            /\ ml{1} = R_SMDTTCRCTRH_C.ml{2}
            /\ all (fun (ad : adrs) => get_typeidx ad <> trhxtype) TRHC.O_THFC_Default.tws{2}).
- call (:   ={glob A_ht, arg}
         /\ FC.O_THFC_Default.pp{1} = TRHC.O_THFC_Default.pp{2}
         /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCTRH_C.O_THFC.ads{2}
         /\ R_SMDTTCRCTRH_C.O_THFC.ads{2} = TRHC.O_THFC_Default.tws{2}
         /\ R_SMDTTCRCTRH_C.O_THFC.ads{2} = []
         ==>
            ={glob A_ht, res}
         /\ FC.O_THFC_Default.pp{1} = TRHC.O_THFC_Default.pp{2}
         /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCTRH_C.O_THFC.ads{2}
         /\ R_SMDTTCRCTRH_C.O_THFC.ads{2} = TRHC.O_THFC_Default.tws{2}
         /\ all (fun (ad : adrs) => get_typeidx ad <> trhxtype) TRHC.O_THFC_Default.tws{2}).
  * conseq (: ={glob A_ht, arg} /\ FC.O_THFC_Default.pp{1} = TRHC.O_THFC_Default.pp{2} /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCTRH_C.O_THFC.ads{2} /\ R_SMDTTCRCTRH_C.O_THFC.ads{2} = TRHC.O_THFC_Default.tws{2}
              ==>
              ={glob A_ht, res} /\ FC.O_THFC_Default.pp{1} = TRHC.O_THFC_Default.pp{2} /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCTRH_C.O_THFC.ads{2} /\ R_SMDTTCRCTRH_C.O_THFC.ads{2} = TRHC.O_THFC_Default.tws{2})
           _
           (: R_SMDTTCRCTRH_C.O_THFC.ads = []
              ==>
              all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads) => //.
    proc (FC.O_THFC_Default.pp{1} = TRHC.O_THFC_Default.pp{2} /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCTRH_C.O_THFC.ads{2} /\ R_SMDTTCRCTRH_C.O_THFC.ads{2} = TRHC.O_THFC_Default.tws{2}) => //.
    proc; inline{2} 1.
    by wp; skip.
  by wp; rnd; skip.
(* ---- PART 1: cube-build seq (MM45 :5374-5412 post; :5413-6116 proof).
        MM45 is `seq 7 8`; ours is `seq 7 7` for the SAME reason as the PKCO
        branch: R_SMDTTCRCTRH_C.pick has no `sigWOTStd <- []` (grind-in-find
        defers the whole sig cube to `find`).  Consequences for the POST:
          (a) MM45's `sigWOTStd{1} = R.sigWOTStd{2}` conjunct is DELETED;
          (b) it is REPLACED by the SAME `ht_sigc` characterization of the
              honest sigWOTStd{1} used on the PKCO side -- the operator is
              reduction-agnostic, and R_SMDTTCRCTRH_C.find's rebuild loop is
              literally R_SMDTTCRCPKCO_C.find's, so the same characterization
              is what makes `={arg}` at A.forge reachable here too.
        Everything else is MM45-TRH verbatim modulo trhtype -> trhxtype,
        nr_nodes -> nr_nodesx, bigi -> StdBigop.Bigint.BIA.bigi, val ->
        DigestBlock.val, R_SMDTTCRCTRH_EUFNAGCMA -> R_SMDTTCRCTRH_C.
        NOTE the shape change vs PKCO's post: there the target set held the
        pkco LEAF inputs (indexed (i,j,u) over l'); here it holds the INNER
        MERKLE NODE inputs, indexed (i,j,u,v) with 0 <= u < h' and
        0 <= v < nr_nodesx (u+1), and the leaf cube enters only through its
        SIZE (l', so `list2tree` is fully balanced) and through the roots'
        `val_bt_trh` characterization. ---- *)
seq 7 7 : (   #pre
           /\ ad{1} = adz
           /\ ad{1} = R_SMDTTCRCTRH_C.ad{2}
           /\ skWOTStd{1} = R_SMDTTCRCTRH_C.skWOTStd{2}
           /\ pkWOTStd{1} = R_SMDTTCRCTRH_C.pkWOTStd{2}
           /\ leavestd{1} = R_SMDTTCRCTRH_C.leavestd{2}
           /\ rootstd{1} = R_SMDTTCRCTRH_C.rootstd{2}
           /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                 nth witness (nth witness (nth witness sigWOTStd{1} i) j) u
                 =
                 ht_sigc ps{1} ad{1} ml{1} rootstd{1} skWOTStd{1} i j u)
           /\ (forall (i j : int), 0 <= i < d => 0 <= j < nr_trees i =>
                 size (nth witness (nth witness R_SMDTTCRCTRH_C.leavestd{2} i) j) = l')
           /\ (forall (i j : int), 0 <= i < d => 0 <= j < nr_trees i =>
                 nth witness (nth witness R_SMDTTCRCTRH_C.rootstd{2} i) j
                 =
                 val_bt_trh TRHC_TCR.O_SMDTTCR_Default.pp{2}
                            (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype)
                            (list2tree (nth witness (nth witness R_SMDTTCRCTRH_C.leavestd{2} i) j)))
           /\ (forall (adx : adrs * dgst),
                 adx \in TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 <=>
                 (exists (i j u v : int), 0 <= i < d /\ 0 <= j < nr_trees i /\ 0 <= u < h' /\ 0 <= v < nr_nodesx (u + 1) /\
                   adx
                   =
                   nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                       (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                        StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v)))
           /\ (forall (i j u v : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < h' => 0 <= v < nr_nodesx (u + 1) =>
                 nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                     (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                      StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v)
                 =
                 (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype) (u + 1) v,
                  let leaveslp = nth witness (nth witness R_SMDTTCRCTRH_C.leavestd{2} i) j in
                    DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype)
                                        (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                    ++
                    DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype)
                                        (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
           /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = trhxtype) TRHC_TCR.O_SMDTTCR_Default.ts{2}
           /\ uniq (unzip1 TRHC_TCR.O_SMDTTCR_Default.ts{2})
           /\ size TRHC_TCR.O_SMDTTCR_Default.ts{2}
              = StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => nr_trees d') 0 d * (2 ^ h' - 1)).
- (* ---- PART 1a: cube-build ESTABLISHMENT (+C port of MM45 :5413-6116). ----
       Same 3-level shape as the PKCO branch (outer = layers, middle = inner
       trees, inner = the side-2-only `nodes` loop THEN the two-sided l' loop --
       textually in that order because EC walks the program backwards).
       TRH-vs-PKCO deltas in the two invariants below:
         * the pkco-leaf characterization is replaced by (i) `size leaveslp = l'`
           (so `list2tree` is fully balanced) and (ii) the roots' `val_bt_trh`
           relation -- on this branch the leaf is an OC (collection) query, not a
           challenge query, so its VALUE is not tracked, only its shape;
         * the target set `ts` is indexed by (i,j,u,v) over
           0 <= u < h' /\ 0 <= v < nr_nodesx (u+1) instead of (i,j,u) over l',
           and its size grows by `2^h' - 1` per inner tree instead of `l'`;
         * MM45's sig-cube conjuncts (`sigWOTStd{1} = R.sigWOTStd{2}` and
           `size R.skWOTStd = size R.sigWOTStd`) are DELETED and replaced by the
           reduction-agnostic ht_sigc / ht_sigc_at characterizations, exactly as
           on the PKCO side. ---- *)
  while (   ={glob A_ht}
         /\ ps{1} = pp{2}
         /\ ps{1} = FC.O_THFC_Default.pp{1}
         /\ ps{1} = TRHC_TCR.O_SMDTTCR_Default.pp{2}
         /\ ps{1} = TRHC.O_THFC_Default.pp{2}
         /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCTRH_C.O_THFC.ads{2}
         /\ ad{1} = adz
         /\ ad{1} = R_SMDTTCRCTRH_C.ad{2}
         /\ ml{1} = R_SMDTTCRCTRH_C.ml{2}
         /\ skWOTStd{1} = R_SMDTTCRCTRH_C.skWOTStd{2}
         /\ pkWOTStd{1} = R_SMDTTCRCTRH_C.pkWOTStd{2}
         /\ leavestd{1} = R_SMDTTCRCTRH_C.leavestd{2}
         /\ rootstd{1} = R_SMDTTCRCTRH_C.rootstd{2}
         /\ (forall (i j u : int), 0 <= i < size skWOTStd{1} => 0 <= j < nr_trees i => 0 <= u < l' =>
               nth witness (nth witness (nth witness sigWOTStd{1} i) j) u
               =
               ht_sigc ps{1} ad{1} ml{1} rootstd{1} skWOTStd{1} i j u)
         /\ (forall (i j : int), 0 <= i < size skWOTStd{1} => 0 <= j < nr_trees i =>
               size (nth witness (nth witness R_SMDTTCRCTRH_C.leavestd{2} i) j) = l')
         /\ (forall (i j : int), 0 <= i < size skWOTStd{1} => 0 <= j < nr_trees i =>
               nth witness (nth witness R_SMDTTCRCTRH_C.rootstd{2} i) j
               =
               val_bt_trh TRHC_TCR.O_SMDTTCR_Default.pp{2}
                          (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype)
                          (list2tree (nth witness (nth witness R_SMDTTCRCTRH_C.leavestd{2} i) j)))
         /\ (forall (adx : adrs * dgst),
               adx \in TRHC_TCR.O_SMDTTCR_Default.ts{2}
               <=>
               (exists (i j u v : int), 0 <= i < size skWOTStd{1} /\ 0 <= j < nr_trees i /\ 0 <= u < h' /\ 0 <= v < nr_nodesx (u + 1) /\
                 adx
                 =
                 nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                     (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                      StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v)))
         /\ (forall (i j u v : int), 0 <= i < size skWOTStd{1} => 0 <= j < nr_trees i => 0 <= u < h' => 0 <= v < nr_nodesx (u + 1) =>
               nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                   (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                    StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v)
               =
               (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype) (u + 1) v,
                let leaveslp = nth witness (nth witness R_SMDTTCRCTRH_C.leavestd{2} i) j in
                  DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype)
                                      (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                  ++
                  DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype)
                                      (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
         /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = trhxtype) TRHC_TCR.O_SMDTTCR_Default.ts{2}
         /\ all (fun (ad : adrs) => get_typeidx ad <> trhxtype) TRHC.O_THFC_Default.tws{2}
         /\ uniq (unzip1 TRHC_TCR.O_SMDTTCR_Default.ts{2})
         /\ size TRHC_TCR.O_SMDTTCR_Default.ts{2}
            = StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => nr_trees d') 0 (size skWOTStd{1}) * (2 ^ h' - 1)
         /\ size skWOTStd{1} = size sigWOTStd{1}
         /\ size R_SMDTTCRCTRH_C.skWOTStd{2} = size R_SMDTTCRCTRH_C.pkWOTStd{2}
         /\ size R_SMDTTCRCTRH_C.skWOTStd{2} = size R_SMDTTCRCTRH_C.leavestd{2}
         /\ size R_SMDTTCRCTRH_C.skWOTStd{2} = size R_SMDTTCRCTRH_C.rootstd{2}
         /\ size skWOTStd{1} <= d).
  * wp => /=.
    while (   ={skWOTSnt, pkWOTSnt, leavesnt, rootsnt}
           /\ rootsntp{1} = rootsntp0{2}
           /\ ={glob A_ht}
           /\ ps{1} = pp{2}
           /\ ps{1} = FC.O_THFC_Default.pp{1}
           /\ ps{1} = TRHC_TCR.O_SMDTTCR_Default.pp{2}
           /\ ps{1} = TRHC.O_THFC_Default.pp{2}
           /\ FC.O_THFC_Default.tws{1} = R_SMDTTCRCTRH_C.O_THFC.ads{2}
           /\ ad{1} = adz
           /\ ad{1} = R_SMDTTCRCTRH_C.ad{2}
           /\ ml{1} = R_SMDTTCRCTRH_C.ml{2}
           /\ skWOTStd{1} = R_SMDTTCRCTRH_C.skWOTStd{2}
           /\ pkWOTStd{1} = R_SMDTTCRCTRH_C.pkWOTStd{2}
           /\ leavestd{1} = R_SMDTTCRCTRH_C.leavestd{2}
           /\ rootstd{1} = R_SMDTTCRCTRH_C.rootstd{2}
           /\ rootsntp{1} = last ml{1} rootstd{1}
           /\ (forall (i j u : int), 0 <= i < size skWOTStd{1} => 0 <= j < nr_trees i => 0 <= u < l' =>
                 nth witness (nth witness (nth witness sigWOTStd{1} i) j) u
                 =
                 ht_sigc ps{1} ad{1} ml{1} rootstd{1} skWOTStd{1} i j u)
           /\ (forall (j u : int), 0 <= j < size skWOTSnt{1} => 0 <= u < l' =>
                 nth witness (nth witness sigWOTSnt{1} j) u
                 =
                 ht_sigc_at ps{1} ad{1} (nth witness rootsntp{1} (j * l' + u))
                            (size skWOTStd{1}) j u
                            (DBLL.val (nth witness (nth witness skWOTSnt{1} j) u)))
           /\ (forall (i j : int), 0 <= i < size R_SMDTTCRCTRH_C.skWOTStd{2} => 0 <= j < nr_trees i =>
                 size (nth witness (nth witness R_SMDTTCRCTRH_C.leavestd{2} i) j) = l')
           /\ (forall (j : int), 0 <= j < size skWOTSnt{2} =>
                 size (nth witness leavesnt{2} j) = l')
           /\ (forall (i j : int), 0 <= i < size R_SMDTTCRCTRH_C.skWOTStd{2} => 0 <= j < nr_trees i =>
                 nth witness (nth witness R_SMDTTCRCTRH_C.rootstd{2} i) j
                 =
                 val_bt_trh TRHC_TCR.O_SMDTTCR_Default.pp{2}
                            (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype)
                            (list2tree (nth witness (nth witness R_SMDTTCRCTRH_C.leavestd{2} i) j)))
           /\ (forall (j : int), 0 <= j < size skWOTSnt{2} =>
                 nth witness rootsnt{2} j
                 =
                 val_bt_trh TRHC_TCR.O_SMDTTCR_Default.pp{2}
                            (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} (size R_SMDTTCRCTRH_C.skWOTStd{2}) j) trhxtype)
                            (list2tree (nth witness leavesnt{2} j)))
           /\ (forall (adx : adrs * dgst),
                 adx \in TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 <=>
                 (exists (i j u v : int), 0 <= i < size R_SMDTTCRCTRH_C.skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < h' /\ 0 <= v < nr_nodesx (u + 1) /\
                   adx
                   =
                   nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                       (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                        StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v))
                 \/
                 (exists (j u v : int), 0 <= j < size skWOTSnt{2} /\ 0 <= u < h' /\ 0 <= v < nr_nodesx (u + 1) /\
                   adx
                   =
                   nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                       (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_C.skWOTStd{2}) * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                        StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v)))
           /\ (forall (i j u v : int), 0 <= i < size R_SMDTTCRCTRH_C.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < h' => 0 <= v < nr_nodesx (u + 1) =>
                 nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                     (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                      StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v)
                 =
                 (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype) (u + 1) v,
                  let leaveslp = nth witness (nth witness R_SMDTTCRCTRH_C.leavestd{2} i) j in
                    DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype)
                                        (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                    ++
                    DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype)
                                        (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
           /\ (forall (j u v : int), 0 <= j < size skWOTSnt{2} => 0 <= u < h' => 0 <= v < nr_nodesx (u + 1) =>
                 nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                     (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_C.skWOTStd{2}) * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                      StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v)
                 =
                 (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} (size R_SMDTTCRCTRH_C.skWOTStd{2}) j) trhxtype) (u + 1) v,
                  let leaveslp = nth witness leavesnt{2} j in
                    DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} (size R_SMDTTCRCTRH_C.skWOTStd{2}) j) trhxtype)
                                        (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                    ++
                    DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} (size R_SMDTTCRCTRH_C.skWOTStd{2}) j) trhxtype)
                                        (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
           /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = trhxtype) TRHC_TCR.O_SMDTTCR_Default.ts{2}
           /\ all (fun (ad : adrs) => get_typeidx ad <> trhxtype) TRHC.O_THFC_Default.tws{2}
           /\ uniq (unzip1 TRHC_TCR.O_SMDTTCR_Default.ts{2})
           /\ size TRHC_TCR.O_SMDTTCR_Default.ts{2}
              = StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => nr_trees d') 0 (size R_SMDTTCRCTRH_C.skWOTStd{2}) * (2 ^ h' - 1)
                + size skWOTSnt{2} * (2 ^ h' - 1)
           /\ size skWOTSnt{1} = size sigWOTSnt{1}
           /\ size skWOTSnt{2} = size pkWOTSnt{2}
           /\ size skWOTSnt{2} = size leavesnt{2}
           /\ size skWOTSnt{2} = size rootsnt{2}
           /\ size skWOTStd{1} = size sigWOTStd{1}
           /\ size R_SMDTTCRCTRH_C.skWOTStd{2} = size R_SMDTTCRCTRH_C.pkWOTStd{2}
           /\ size R_SMDTTCRCTRH_C.skWOTStd{2} = size R_SMDTTCRCTRH_C.leavestd{2}
           /\ size R_SMDTTCRCTRH_C.skWOTStd{2} = size R_SMDTTCRCTRH_C.rootstd{2}
           /\ size skWOTSnt{1} <= nr_trees (size skWOTStd{1})
           /\ size skWOTStd{1} < d).
    + (* ---- ONE INNER TREE (MM45 :5545-6070). ----
           EC walks the program backwards, so the side-2-only `nodes` loop (the
           LAST loop in the body) is handled FIRST, then the two-sided l' loop.
           The ts facts do NOT travel through the l' invariant -- they are not
           in it, exactly as in MM45 -- because the l' loop only calls OC
           (collection), never O (challenge), so `ts` is untouched there; they
           reach the nodes-loop entry through the LEAF `wp; skip`, whose
           precondition is the middle-loop invariant. ---- *)
      wp => /=.
      (* ---- (a) the side-2-only tree-hash `nodes` loop (MM45 :5546-5950).
              THIS is the genuinely new part of the TRH branch: unlike the PKCO
              branch's nodes loop (which walks OC and carries NO target-set
              bookkeeping), here every node is an O.query, so the loop must
              maintain the (i,j,u,v) ts membership/nth/uniq/size discipline for
              a THIRD index block (the in-progress inner tree, `size nodes{2}`
              levels deep) on top of the finished-layers and finished-trees
              blocks. ---- *)
      while{2} (   TRHC_TCR.O_SMDTTCR_Default.pp{2} = TRHC.O_THFC_Default.pp{2}
                /\ R_SMDTTCRCTRH_C.ad{2} = adz
                /\ (forall (adx : adrs * dgst),
                      adx \in TRHC_TCR.O_SMDTTCR_Default.ts{2}
                      <=>
                      (exists (i j u v : int), 0 <= i < size R_SMDTTCRCTRH_C.skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < h' /\ 0 <= v < nr_nodesx (u + 1) /\
                        adx
                        =
                        nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                           (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                            StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v))
                      \/
                      (exists (j u v : int), 0 <= j < size skWOTSnt{2} /\ 0 <= u < h' /\ 0 <= v < nr_nodesx (u + 1) /\
                        adx
                        =
                        nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                            (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_C.skWOTStd{2}) * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                             StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v))
                      \/
                      (exists (u v : int), 0 <= u < size nodes{2} /\ 0 <= v < nr_nodesx (u + 1) /\
                        adx
                        =
                        nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                            (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_C.skWOTStd{2}) * (2 ^ h' - 1) + (size skWOTSnt{2}) * (2 ^ h' - 1) +
                             StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v)))
                /\ (forall (i j u v : int), 0 <= i < size R_SMDTTCRCTRH_C.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < h' => 0 <= v < nr_nodesx (u + 1) =>
                      nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                           StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v)
                      =
                      (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype) (u + 1) v,
                       let leaveslpx = nth witness (nth witness R_SMDTTCRCTRH_C.leavestd{2} i) j in
                         DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype)
                                             (oget (sub_bt (list2tree leaveslpx) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                         ++
                         DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i j) trhxtype)
                                             (oget (sub_bt (list2tree leaveslpx) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
                /\ (forall (j u v : int), 0 <= j < size skWOTSnt{2} => 0 <= u < h' => 0 <= v < nr_nodesx (u + 1) =>
                      nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_C.skWOTStd{2}) * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                           StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v)
                      =
                      (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} (size R_SMDTTCRCTRH_C.skWOTStd{2}) j) trhxtype) (u + 1) v,
                       let leaveslpx = nth witness leavesnt{2} j in
                         DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} (size R_SMDTTCRCTRH_C.skWOTStd{2}) j) trhxtype)
                                             (oget (sub_bt (list2tree leaveslpx) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                         ++
                         DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} (size R_SMDTTCRCTRH_C.skWOTStd{2}) j) trhxtype)
                                             (oget (sub_bt (list2tree leaveslpx) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
                /\ (forall (u v : int), 0 <= u < size nodes{2} => 0 <= v < nr_nodesx (u + 1) =>
                      nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_C.skWOTStd{2}) * (2 ^ h' - 1) + (size skWOTSnt{2}) * (2 ^ h' - 1) +
                           StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v)
                      =
                      (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} (size R_SMDTTCRCTRH_C.skWOTStd{2}) (size skWOTSnt{2})) trhxtype) (u + 1) v,
                         DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} (size R_SMDTTCRCTRH_C.skWOTStd{2}) (size skWOTSnt{2})) trhxtype)
                                             (oget (sub_bt (list2tree leaveslp{2}) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                         ++
                         DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} (size R_SMDTTCRCTRH_C.skWOTStd{2}) (size skWOTSnt{2})) trhxtype)
                                             (oget (sub_bt (list2tree leaveslp{2}) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
                /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = trhxtype) TRHC_TCR.O_SMDTTCR_Default.ts{2}
                /\ uniq (unzip1 TRHC_TCR.O_SMDTTCR_Default.ts{2})
                /\ size TRHC_TCR.O_SMDTTCR_Default.ts{2}
                   =
                   StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => nr_trees d') 0 (size R_SMDTTCRCTRH_C.skWOTStd{2}) * (2 ^ h' - 1)
                   +
                   size skWOTSnt{2} * (2 ^ h' - 1)
                   +
                   StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (size nodes{2} + 1)
                /\ (forall (u v : int), 0 <= u < size nodes{2} => 0 <= v < nr_nodesx (u + 1) =>
                      nth witness (nth witness nodes{2} u) v
                      =
                      val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} (size R_SMDTTCRCTRH_C.skWOTStd{2}) (size skWOTSnt{2})) trhxtype)
                                     (oget (sub_bt (list2tree leaveslp{2}) (rev (int2bs (h' - u - 1) v)))) (u + 1) v)
                /\ size R_SMDTTCRCTRH_C.skWOTStd{2} < d
                /\ size skWOTSnt{2} < nr_trees (size R_SMDTTCRCTRH_C.skWOTStd{2})
                /\ size leaveslp{2} = l'
                /\ size nodes{2} <= h')
               (h' - size nodes{2}).
      - (* ---- 1a-NODESBODY: ONE TREE-HASH LEVEL -- the inner `nodescl` loop
               plus its target-set bookkeeping (MM45 :5625-5950).  This is the
               single largest block of the TRH branch and has NO PKCO analogue
               (PKCO's nodes loop is OC-only and carries no target set): here
               every node is an O.query, so the loop maintains the (i,j,u,v) ts
               membership / nth / uniq / size discipline for a FOURTH index
               block (the in-progress level, `size nodescl` wide) on top of the
               finished-layers, finished-trees and finished-levels blocks.
               PURE MM45 PORT, no +C content -- the WOTS axis is untouched
               here.  Renames: trhtype -> trhxtype, nr_nodes -> nr_nodesx
               (MM45's stray `/nr_nodesf` unfold included),
               R_SMDTTCRCTRH_EUFNAGCMA -> R_SMDTTCRCTRH_C, val ->
               DigestBlock.val, bigi/big_*/sumr_ge0 -> StdBigop.Bigint.BIA.*,
               bare IntOrder lemmas -> IntOrder.* (but `lez_maxr` stays BARE),
               eq_adrs_idxs -> HA.eq_adrs_idxs. ---- *)
        move=> _ z.
        wp => /=.
        while (   TRHC_TCR.O_SMDTTCR_Default.pp = TRHC.O_THFC_Default.pp
               /\ R_SMDTTCRCTRH_C.ad = adz
               /\ (forall (adx : adrs * dgst),
                     adx \in TRHC_TCR.O_SMDTTCR_Default.ts
                     <=>
                     (exists (i j u v : int), 0 <= i < size R_SMDTTCRCTRH_C.skWOTStd /\ 0 <= j < nr_trees i /\ 0 <= u < h' /\ 0 <= v < nr_nodesx (u + 1) /\
                       adx
                       =
                       nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                          (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                           StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v))
                     \/
                     (exists (j u v : int), 0 <= j < size skWOTSnt /\ 0 <= u < h' /\ 0 <= v < nr_nodesx (u + 1) /\
                       adx
                       =
                       nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                           (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_C.skWOTStd) * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                            StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v))
                     \/
                     (exists (u v : int), 0 <= u < size nodes /\ 0 <= v < nr_nodesx (u + 1) /\
                       adx
                       =
                       nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                           (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_C.skWOTStd) * (2 ^ h' - 1) + (size skWOTSnt) * (2 ^ h' - 1) +
                            StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v))
                     \/
                     (exists (v : int), 0 <= v < size nodescl /\
                       adx
                       =
                       nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                           (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_C.skWOTStd) * (2 ^ h' - 1) + (size skWOTSnt) * (2 ^ h' - 1) +
                            StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (size nodes + 1) + v)))
               /\ (forall (i j u v : int), 0 <= i < size R_SMDTTCRCTRH_C.skWOTStd => 0 <= j < nr_trees i => 0 <= u < h' => 0 <= v < nr_nodesx (u + 1) =>
                     nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                         (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                          StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v)
                     =
                     (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad i j) trhxtype) (u + 1) v,
                      let leaveslpx = nth witness (nth witness R_SMDTTCRCTRH_C.leavestd i) j in
                        DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad i j) trhxtype)
                                            (oget (sub_bt (list2tree leaveslpx) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                        ++
                        DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad i j) trhxtype)
                                            (oget (sub_bt (list2tree leaveslpx) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
               /\ (forall (j u v : int), 0 <= j < size skWOTSnt => 0 <= u < h' => 0 <= v < nr_nodesx (u + 1) =>
                     nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                         (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_C.skWOTStd) * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                          StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v)
                     =
                     (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad (size R_SMDTTCRCTRH_C.skWOTStd) j) trhxtype) (u + 1) v,
                      let leaveslpx = nth witness leavesnt j in
                        DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad (size R_SMDTTCRCTRH_C.skWOTStd) j) trhxtype)
                                            (oget (sub_bt (list2tree leaveslpx) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                        ++
                        DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad (size R_SMDTTCRCTRH_C.skWOTStd) j) trhxtype)
                                            (oget (sub_bt (list2tree leaveslpx) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
               /\ (forall (u v : int), 0 <= u < size nodes => 0 <= v < nr_nodesx (u + 1) =>
                     nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                         (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_C.skWOTStd) * (2 ^ h' - 1) + (size skWOTSnt) * (2 ^ h' - 1) +
                          StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (u + 1) + v)
                     =
                     (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad (size R_SMDTTCRCTRH_C.skWOTStd) (size skWOTSnt)) trhxtype) (u + 1) v,
                        DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad (size R_SMDTTCRCTRH_C.skWOTStd) (size skWOTSnt)) trhxtype)
                                            (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                        ++
                        DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad (size R_SMDTTCRCTRH_C.skWOTStd) (size skWOTSnt)) trhxtype)
                                            (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
               /\ (forall (v : int), 0 <= v < size nodescl =>
                     nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                         (StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_C.skWOTStd) * (2 ^ h' - 1) + (size skWOTSnt) * (2 ^ h' - 1) +
                          StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (size nodes + 1) + v)
                     =
                     (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad (size R_SMDTTCRCTRH_C.skWOTStd) (size skWOTSnt)) trhxtype) (size nodes + 1) v,
                        DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad (size R_SMDTTCRCTRH_C.skWOTStd) (size skWOTSnt)) trhxtype)
                                            (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - size nodes) (2 * v))))) (size nodes) (2 * v))
                        ++
                        DigestBlock.val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad (size R_SMDTTCRCTRH_C.skWOTStd) (size skWOTSnt)) trhxtype)
                                            (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - size nodes) (2 * v + 1))))) (size nodes) (2 * v + 1))))
               /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = trhxtype) TRHC_TCR.O_SMDTTCR_Default.ts
               /\ uniq (unzip1 TRHC_TCR.O_SMDTTCR_Default.ts)
               /\ size TRHC_TCR.O_SMDTTCR_Default.ts
                  =
                  StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => nr_trees d') 0 (size R_SMDTTCRCTRH_C.skWOTStd) * (2 ^ h' - 1)
                  +
                  size skWOTSnt * (2 ^ h' - 1)
                  +
                  StdBigop.Bigint.BIA.bigi predT (fun (m : int) => nr_nodesx m) 1 (size nodes + 1)
                  +
                  size nodescl
               /\ (forall (u v : int), 0 <= u < size nodes => 0 <= v < nr_nodesx (u + 1) =>
                     nth witness (nth witness nodes u) v
                     =
                     val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad (size R_SMDTTCRCTRH_C.skWOTStd) (size skWOTSnt)) trhxtype)
                                    (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u - 1) v)))) (u + 1) v)
               /\ (forall (v : int), 0 <= v < size nodescl =>
                     nth witness nodescl v
                     =
                     val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad (size R_SMDTTCRCTRH_C.skWOTStd) (size skWOTSnt)) trhxtype)
                                    (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - size nodes - 1) v)))) (size nodes + 1) v)
               /\ nodespl = last leaveslp nodes
               /\ size R_SMDTTCRCTRH_C.skWOTStd < d
               /\ size skWOTSnt < nr_trees (size R_SMDTTCRCTRH_C.skWOTStd)
               /\ size leaveslp = l'
               /\ size nodescl <= nr_nodesx (size nodes + 1)
               /\ size nodes < h')
              (nr_nodesx (size nodes + 1) - size nodescl).
        * move=> z'.
          inline 3.
          wp; skip => /> &2 tsdef tsnth tsnth1 tsnth2 tsnth3 alltrhts uqunz1ts
                            szts nthnds nthndscl ltd_szskw ltnt_szskwnt
                            eqlp_szlfslp _ lthp_sznds ltnn_szndscl.
          rewrite ?size_rcons !andbA -andbA; split => [| /#].
          rewrite -!andbA; split => [adx | ].
          + rewrite mem_rcons /=; split.
            - elim => [-> | /tsdef].
              * right; right; right; exists (size nodescl{2}).
                by split; [smt(size_ge0) | rewrite nth_rcons /#].
              elim => [[i j u v [ir] [jr] [ur [vr adval]]]|].
              * left; exists i j u v; rewrite ir jr ur vr /= nth_rcons szts.
                by rewrite ltbignn_i.
              elim => [[j u v [jr] [ur [vr adval]]]|].
              * right; left; exists j u v; rewrite jr ur vr /= nth_rcons szts.
                pose igl := _ + j * _ + _ + _; pose igr := _ + size skWOTSnt{2} * _ + _ + _.
                rewrite (: igl < igr) /igl /igr 2://.
                rewrite -4!addrA IntOrder.ler_lt_add 1://.
                suff /#:
                  j * (2 ^ h' - 1) + (StdBigop.Bigint.BIA.bigi predT nr_nodesx 1 (u + 1) + v) < size skWOTSnt{2} * (2 ^ h' - 1)
                  /\
                  0 <= StdBigop.Bigint.BIA.bigi predT nr_nodesx 1 (size nodes{2} + 1) + size nodescl{2}.
                rewrite IntOrder.addr_ge0 3:/= 2:size_ge0 1:StdBigop.Bigint.sumr_ge0 => [? _ |]; 1: by rewrite IntOrder.expr_ge0.
                rewrite (: size skWOTSnt{2} = size skWOTSnt{2} - 1 + 1) 1:// mulrDl IntOrder.ler_lt_add 2:// 2:/=.
                + by rewrite IntOrder.ler_pmul2r 1:IntOrder.ltr_subr_addl /= 1:ltzE /= 1:IntOrder.ler_eexpr 2://; smt(ge1_hp).
                by rewrite ltnn1_bignn.
              elim => [[u v [ur] [vr adval]]|].
              * right; right; left.
                exists u v; split; 1: smt(size_ge0).
                rewrite nth_rcons szts.
                pose igl := _ + size skWOTSnt{2} * _ + _ + _; pose igr := _ + size skWOTSnt{2} * _ + _ + _.
                rewrite (: igl < igr) /igl /igr 2://.
                rewrite -addrA -(addrA _ _ (size nodescl{2})) IntOrder.ler_lt_add 1://.
                suff /#:
                  StdBigop.Bigint.BIA.bigi predT nr_nodesx 1 (u + 1) + v < StdBigop.Bigint.BIA.bigi predT nr_nodesx 1 (size nodes{2} + 1)
                  /\
                  0 <= size nodescl{2}.
                rewrite size_ge0 /= 1:(StdBigop.Bigint.BIA.big_cat_int (u + 1) _ (size nodes{2} + 1)) 1,2:/#.
                rewrite IntOrder.ler_lt_add // (StdBigop.Bigint.BIA.big_cat_int (u + 2)) 1,2:/#.
                rewrite StdBigop.Bigint.BIA.big_int1; suff /#: 0 <= StdBigop.Bigint.BIA.bigi predT nr_nodesx (u + 2) (size nodes{2} + 1).
                by rewrite StdBigop.Bigint.sumr_ge0 => ? _; rewrite IntOrder.expr_ge0.
              elim => [v [vr adval]].
              right; right; right.
              exists v; split; 1: smt(size_ge0).
              by rewrite nth_rcons szts /#.
            case; 2: case; 3: case.
            - elim=> i j u v [rng_i [rng_j [rng_u [rng_v]]]].
              rewrite nth_rcons szts.
              pose igl := (_ + _ + _ + _)%Int; pose igr := (_ + _ + _ + _)%Int.
              rewrite (: igl < igr) /igl /igr 2:// /= 1:ltbignn_i 1..7://.
              by rewrite tsnth 1..4:// => ->; right; rewrite tsdef; left; exists i j u v => /#.
            - elim=> j u v [rng_j [rng_u [rng_v]]].
              rewrite nth_rcons szts.
              pose igl := (_ + _ + _ + _)%Int; pose igr := (_ + _ + _ + _)%Int.
              rewrite (: igl < igr) /igl /igr 2:/= 2:tsnth1 //.
              + rewrite -4!addrA IntOrder.ler_lt_add 1://.
                suff /#:
                  j * (2 ^ h' - 1) + (StdBigop.Bigint.BIA.bigi predT nr_nodesx 1 (u + 1) + v) < size skWOTSnt{2} * (2 ^ h' - 1)
                  /\
                  0 <= StdBigop.Bigint.BIA.bigi predT nr_nodesx 1 (size nodes{2} + 1) + size nodescl{2}.
                rewrite IntOrder.addr_ge0 3:/= 2:size_ge0 1:StdBigop.Bigint.sumr_ge0 => [? _ |]; 1: by rewrite IntOrder.expr_ge0.
                rewrite (: size skWOTSnt{2} = size skWOTSnt{2} - 1 + 1) 1:// mulrDl IntOrder.ler_lt_add 2:// 2:/=.
                + by rewrite IntOrder.ler_pmul2r 1:IntOrder.ltr_subr_addl /= 1:ltzE /= 1:IntOrder.ler_eexpr 2://; smt(ge1_hp).
                by rewrite ltnn1_bignn.
              by rewrite tsdef /#.
            - elim=> u v [rng_u [rng_v]].
              rewrite nth_rcons szts.
              pose igl := (_ + _ + _ + _)%Int; pose igr := (_ + _ + _ + _)%Int.
              rewrite (: igl < igr) /igl /igr 2:/= 2:tsnth2 //.
              + rewrite -addrA -(addrA _ _ (size nodescl{2})) IntOrder.ler_lt_add 1://.
                suff /#:
                  StdBigop.Bigint.BIA.bigi predT nr_nodesx 1 (u + 1) + v < StdBigop.Bigint.BIA.bigi predT nr_nodesx 1 (size nodes{2} + 1)
                  /\
                  0 <= size nodescl{2}.
                rewrite size_ge0 /= 1:(StdBigop.Bigint.BIA.big_cat_int (u + 1) _ (size nodes{2} + 1)) 1,2:/#.
                rewrite IntOrder.ler_lt_add // (StdBigop.Bigint.BIA.big_cat_int (u + 2)) 1,2:/#.
                rewrite StdBigop.Bigint.BIA.big_int1; suff /#: 0 <= StdBigop.Bigint.BIA.bigi predT nr_nodesx (u + 2) (size nodes{2} + 1).
                by rewrite StdBigop.Bigint.sumr_ge0 => ? _; rewrite IntOrder.expr_ge0.
              by rewrite tsdef /#.
            by elim=> v [rng_v]; rewrite nth_rcons szts /#.
          split => [i j u v ge0_i ltszsktd_i ge0_j ltnti_j ge0_u lthp_u ge0_v ltnnu1_v|].
          + by rewrite nth_rcons szts ltbignn_i 8:tsnth.
          split => [j u v ge0_j ltnti_j ge0_u lthp_u ge0_v ltnnu1_v|].
          + rewrite nth_rcons szts.
            pose igl := (_ + _ + _ + _)%Int; pose igr := (_ + _ + _ + _)%Int.
            rewrite (: igl < igr) /igl /igr 2:/= 2:tsnth1 //.
            rewrite -4!addrA IntOrder.ler_lt_add 1://.
            suff /#:
              j * (2 ^ h' - 1) + (StdBigop.Bigint.BIA.bigi predT nr_nodesx 1 (u + 1) + v) < size skWOTSnt{2} * (2 ^ h' - 1)
              /\
              0 <= StdBigop.Bigint.BIA.bigi predT nr_nodesx 1 (size nodes{2} + 1) + size nodescl{2}.
            rewrite IntOrder.addr_ge0 3:/= 2:size_ge0 1:StdBigop.Bigint.sumr_ge0 => [? _ |]; 1: by rewrite IntOrder.expr_ge0.
            rewrite (: size skWOTSnt{2} = size skWOTSnt{2} - 1 + 1) 1:// mulrDl IntOrder.ler_lt_add 2:// 2:/=.
            + by rewrite IntOrder.ler_pmul2r 1:IntOrder.ltr_subr_addl /= 1:ltzE /= 1:IntOrder.ler_eexpr 2://; smt(ge1_hp).
            by rewrite ltnn1_bignn.
          split => [u v ge0_u lthp_u ge0_v ltnnu1_v|].
          + rewrite nth_rcons szts.
            pose igl := (_ + _ + _ + _)%Int; pose igr := (_ + _ + _ + _)%Int.
            rewrite (: igl < igr) /igl /igr 2:/= 2:tsnth2 //.
            suff /#:
              StdBigop.Bigint.BIA.bigi predT nr_nodesx 1 (u + 1) + v < StdBigop.Bigint.BIA.bigi predT nr_nodesx 1 (size nodes{2} + 1)
              /\
              0 <= size nodescl{2}.
            rewrite size_ge0 /= 1:(StdBigop.Bigint.BIA.big_cat_int (u + 1) _ (size nodes{2} + 1)) 1,2:/#.
            rewrite IntOrder.ler_lt_add // (StdBigop.Bigint.BIA.big_cat_int (u + 2)) 1,2:/#.
            rewrite StdBigop.Bigint.BIA.big_int1; suff /#: 0 <= StdBigop.Bigint.BIA.bigi predT nr_nodesx (u + 2) (size nodes{2} + 1).
            by rewrite StdBigop.Bigint.sumr_ge0 => ? _; rewrite IntOrder.expr_ge0.
          split => [v ge0_v ltnnu1_v|].
          + rewrite nth_rcons szts /=.
            case (v < size nodescl{2}) => [ltszncl_v /# | nltszncl_v].
            rewrite (: v = size nodescl{2}) 1:/# /=.
            have rngszndscl : 0 <= 2 * size nodescl{2} + 1 < nr_nodesx (size nodes{2}).
            - split => [|_]; 1: smt(size_ge0).
              rewrite (IntOrder.ler_lt_trans (nr_nodesx (size nodes{2}) - 1)) 2:/#.
              rewrite (: nr_nodesx (size nodes{2}) = 2 * nr_nodesx (size nodes{2} + 1)) 2:/#.
              by rewrite -(expr1 2) /nr_nodesx -exprD_nneg 1:// 1,2:/#.
            rewrite -nth_last; case (size nodes{2} = 0) => [eq0_sznds | neq0_sznds].
            - rewrite eq0_sznds /= (nth_out _ _ (-1)) 1://.
              rewrite 2?(subbt_list2tree_idx_leaf witness) 2,5://; 1..4: smt(ge1_hp).
              by rewrite oget_some.
            rewrite -(nth_change_dfl leaveslp{2} witness); 1:smt(size_ge0).
            by rewrite ?nthnds /= 4:// ; smt(size_ge0).
          split; 1: rewrite -cats1 all_cat alltrhts /=.
          + by rewrite gettype_setalltrh 1:valx_adz 1,2,4,5://; smt(size_ge0).
          split; 2: split; 2: by rewrite szts addrA.
          + rewrite map_rcons rcons_uniq /= uqunz1ts /= mapP negb_exists => adx /=.
            rewrite negb_and -implybE => /tsdef.
            case; 2: case.
            - elim=> i j u v [rng_i [rng_j [rng_u [rng_v]]]].
              rewrite tsnth 1..4:// => -> /=.
              rewrite -HA.eq_adrs_idxs (neq_from_nth witness _ _ 5) 2://.
              by rewrite neqlidx_setthtypelt 1:valx_adz 1,3,4,7,8,10://; smt(size_ge0).
            - elim=> j u v [rng_j [rng_u [rng_v]]].
              rewrite tsnth1 1..3:// => -> /=.
              rewrite -HA.eq_adrs_idxs (neq_from_nth witness _ _ 4) 2://.
              by rewrite neqtidx_setthtypelt 1:valx_adz 1,3,4,7,8,10://; smt(size_ge0).
            case; elim=> [u v [rng_u [rng_v]] | u [rng_u]].
            - rewrite tsnth2 1,2:// => -> /=.
              rewrite -HA.eq_adrs_idxs (neq_from_nth witness _ _ 1) 2://.
              by rewrite neqthidx_setthtypelt 1:valx_adz 1,3,4,7,8,10://; smt(size_ge0).
            rewrite tsnth3 1:// => -> /=.
            rewrite -HA.eq_adrs_idxs (neq_from_nth witness _ _ 0) 2://.
            by rewrite neqtbidx_setthtypelt 1:valx_adz 1,3,4,7,8,10://; smt(size_ge0).
          move=> v ge0_v ltsz1_v; rewrite nth_rcons.
          case (v < size nodescl{2}) => [/# | nltszndscl_v].
          rewrite (: v = size nodescl{2}) 1:/# /=.
          have rngszndscl : 0 <= 2 * size nodescl{2} + 1 < nr_nodesx (size nodes{2}).
          + split => [|_]; 1: smt(size_ge0).
            rewrite (IntOrder.ler_lt_trans (nr_nodesx (size nodes{2}) - 1)) 2:/#.
            rewrite (: nr_nodesx (size nodes{2}) = 2 * nr_nodesx (size nodes{2} + 1)) 2:/#.
            by rewrite -(expr1 2) /nr_nodesx -exprD_nneg 1:// 1,2:/#.
          rewrite -nth_last; case (size nodes{2} = 0) => [eq0_sznds | neq0_sznds].
          + rewrite eq0_sznds /= (nth_out _ _ (-1)) 1://.
            rewrite subbt_list2tree_takedrop 1:ge1_hp 1:// 1:size_ge0 1:/# 1://.
            rewrite expr1 {3}(: 2 = 1 + 1) 1:// take_take_drop_cat 1,2://.
            rewrite drop_drop 1:// 1:/# ?(take1_head witness) 1,2:size_drop 1..4:/#.
            rewrite (list2treeS 0) 1:// 1,2:expr0 1,2://.
            rewrite /val_bt_trh_gen /= /trhi.
            by rewrite 2?list2tree1 /= -2?nth0_head 2?nth_drop 2,4:// /#.
          rewrite -(nth_change_dfl leaveslp{2} witness); 1:smt(size_ge0).
          rewrite ?nthnds /= 4://; 1..3: smt(size_ge0).
          rewrite eq_sym (: h' - size nodes{2} - 1 = h' - (size nodes{2} + 1)) 1:/#.
          rewrite subbt_list2tree_takedrop 2:size_ge0 2:/# 2:eqlp_szlfslp 2://; 1: smt(size_ge0).
          rewrite (: 2 ^ (size nodes{2} + 1) = 2 ^ (size nodes{2}) + 2 ^ (size nodes{2})) 1:exprD_nneg 1,2:// 1:expr1 1:/#.
          rewrite take_take_drop_cat 1,2:IntOrder.expr_ge0 1,2://.
          have ge1_2aszn2szncl : 1 <= 2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1.
          + rewrite 2!IntOrder.ler_subr_addr /=.
            rewrite &(IntOrder.ler_trans (2 + 2 * (nr_nodesx (size nodes{2} + 1) - 1))) 1:/#.
            by rewrite /nr_nodesx mulzDr /= -{1}(expr1 2) -exprD_nneg // /#.
          rewrite (list2treeS (size nodes{2})) 1://.
          + rewrite size_take 1:IntOrder.expr_ge0 1:// size_drop 1:IntOrder.mulr_ge0 1:size_ge0 1:IntOrder.addr_ge0 1,2:IntOrder.expr_ge0 //.
            rewrite eqlp_szlfslp /l' (: 2 ^ h' = 2 ^ (h' - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
            pose szn2 := 2 ^ (size nodes{2}).
            rewrite (: 2 ^ (h' - size nodes{2}) * szn2 - size nodescl{2} * (szn2 + szn2) = (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2}) * szn2) 1:/#.
            pose mx := max _ _; rewrite (: 2 ^ (size nodes{2}) < mx) // /mx.
            pose sb := ((_ - _ * _) * _)%Int; rewrite &(IntOrder.ltr_le_trans sb) /sb 2:IntOrder.maxrr.
            by rewrite IntOrder.ltr_pmull 1:IntOrder.expr_gt0 // /#.
          + rewrite drop_drop 1:IntOrder.expr_ge0 1:// 1,2:// 1:IntOrder.mulr_ge0 1:size_ge0 1:IntOrder.addr_ge0 1,2:IntOrder.expr_ge0 1,2://.
            rewrite size_take 1:IntOrder.expr_ge0 1:// size_drop 1:IntOrder.addr_ge0 1:IntOrder.expr_ge0 // 1:IntOrder.mulr_ge0 1:size_ge0 1:IntOrder.addr_ge0 1,2:IntOrder.expr_ge0 //.
            rewrite eqlp_szlfslp /l' (: 2 ^ h' = 2 ^ (h' - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
            pose szn2 := 2 ^ (size nodes{2}).
            rewrite (: 2 ^ (h' - size nodes{2}) * szn2 - (szn2 + size nodescl{2} * (szn2 + szn2)) = (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) 1:/#.
            pose sb := ((_ - _ - _) * _)%Int.
            move: ge1_2aszn2szncl; rewrite lez_eqVlt => -[eq1_2as | gt1_2as].
            - by rewrite /sb -eq1_2as /= lez_maxr 1:IntOrder.expr_ge0.
            rewrite lez_maxr /sb 1:IntOrder.mulr_ge0 2:IntOrder.expr_ge0 //= 1:IntOrder.subr_ge0 1:IntOrder.ler_subr_addr.
            - rewrite &(IntOrder.ler_trans (1 + 2 * (nr_nodesx (size nodes{2} + 1) - 1))) 1:/#.
              by rewrite /nr_nodesx mulzDr -{1}(expr1 2) -exprD_nneg // /#.
            rewrite (: szn2 < (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) //.
            by rewrite IntOrder.ltr_pmull 1:IntOrder.expr_gt0.
          rewrite /val_bt_trh_gen /= /trhi /=; congr.
          rewrite (: h' - (size nodes{2} - 1) - 1 = h' - (size nodes{2})) 1:/#.
          rewrite 2?subbt_list2tree_takedrop 3,5,6:// 1,3:size_ge0 /= 1..3:/#.
          by rewrite drop_drop 1:IntOrder.expr_ge0 1,2:// 1:IntOrder.mulr_ge0 1:size_ge0 1:IntOrder.addr_ge0 1,2:IntOrder.expr_ge0 1,2:// /#.
        wp; skip => /> &2 tsdef tsnth tsnth1 tsnth2 alltrhts uqunz1ts szts nthnds
                          ltd_szskw ltnt_szskwnt eqlp_szlfslp _ lthp_sznds.
        split => [| ts ndscl]; 1: smt(IntOrder.expr_ge0).
        split => [/# | /lezNgt genn_szndscl].
        move=> tspdef tspnth tspnth1 tspnth2 tspnth3 alltrhtsp uqunz1tsp sztsp ndsclnth lenn_szndscl.
        rewrite ?size_rcons !andbA -andbA; split => [| /#].
        rewrite -!andbA; split => [adx |].
        + rewrite tspdef; split.
          - do 2! (elim => [-> // |]); elim => [/#|].
            elim => v [rng_v ->].
            by right; right; exists (size nodes{2}) v; smt(size_ge0).
          do 2! (elim => [-> // |]).
          elim => u v [rng_u [rng_v ->]].
          case (u < size nodes{2}) => [? | nltszu].
          - by right; right; left; exists u v => /#.
          by right; right; right; exists v => /#.
        split => [u v ge0_u ltsz1_u ge0_v ltnn_v |].
        + case (u < size nodes{2}) => [/# | nltszu].
          by rewrite (: u = size nodes{2}) 1:/# tspnth3 1:/#.
        split => [| u v ge0_u ltsz1_u ge0_v ltnn_vc]; 1: rewrite sztsp -addrA.
        + by congr; rewrite eq_sym StdBigop.Bigint.BIA.big_int_recr; smt(size_ge0).
        rewrite nth_rcons; case (u < size nodes{2}) => [/# | nltszu].
        by rewrite (: u = size nodes{2}) 1:/# /= ndsclnth 1:/#.
      wp => /=.
      (* ---- (b) the two-sided l' loop (MM45 :5952-6059).
              SIMPLER than the PKCO branch's l' loop: on this branch the leaf is
              an OC (collection) query, so there is NO ts bookkeeping here at
              all -- MM45's l' invariant carries none either.  The +C deltas are
              exactly the PKCO ones: side 2 has no sigWOTSlp (grind-in-find), so
              MM45's `={sigWOTSlp}` becomes a one-sided ht_sigc_at
              characterization of sigWOTSlp{1}, and `size skWOTSlp{2} = size
              sigWOTSlp{2}` becomes `size skWOTSlp{1} = size sigWOTSlp{1}`. ---- *)
      while (   ={skWOTSlp, pkWOTSlp, leaveslp}
             /\ rootsntp{1} = rootsntp0{2}
             /\ ps{1} = TRHC_TCR.O_SMDTTCR_Default.pp{2}
             /\ ps{1} = TRHC.O_THFC_Default.pp{2}
             /\ ad{1} = adz
             /\ ad{1} = R_SMDTTCRCTRH_C.ad{2}
             /\ (forall (u : int), 0 <= u < size sigWOTSlp{1} =>
                   nth witness sigWOTSlp{1} u
                   =
                   ht_sigc_at ps{1} ad{1} (nth witness rootsntp{1} (size skWOTSnt{1} * l' + u))
                              (size skWOTStd{1}) (size skWOTSnt{1}) u
                              (DBLL.val (nth witness skWOTSlp{1} u)))
             /\ all (fun (ad : adrs) => get_typeidx ad <> trhxtype) TRHC.O_THFC_Default.tws{2}
             /\ size skWOTSlp{1} = size skWOTSlp{2}
             /\ size skWOTSlp{2} = size pkWOTSlp{2}
             /\ size skWOTSlp{2} = size leaveslp{2}
             /\ size skWOTSlp{1} = size sigWOTSlp{1}
             /\ size skWOTSnt{1} = size skWOTSnt{2}
             /\ size skWOTSnt{2} = size pkWOTSnt{2}
             /\ size skWOTSnt{2} = size leavesnt{2}
             /\ size skWOTSnt{1} = size sigWOTSnt{1}
             /\ size skWOTSnt{2} = size rootsnt{2}
             /\ size skWOTStd{1} = size R_SMDTTCRCTRH_C.skWOTStd{2}
             /\ size R_SMDTTCRCTRH_C.skWOTStd{2} = size R_SMDTTCRCTRH_C.pkWOTStd{2}
             /\ size R_SMDTTCRCTRH_C.skWOTStd{2} = size R_SMDTTCRCTRH_C.leavestd{2}
             /\ size skWOTStd{1} = size sigWOTStd{1}
             /\ size R_SMDTTCRCTRH_C.skWOTStd{2} = size R_SMDTTCRCTRH_C.rootstd{2}
             /\ size skWOTSlp{1} <= l'
             /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
             /\ size skWOTStd{1} < d).
      + (* ---- one WOTS+C keypair.  MM45 :5975-6059.
             +C DELTA (identical to the PKCO branch's): side 2's chain walk is a
             PLAIN full 0..w-1 walk -- `pick` has no `em` and builds no
             signature, so MM45's `if (i0 < em_ele)` sig-reveal branches are
             DELETED and its `exists* sigWOTS0{2}` freeze is unnecessary.  Side
             1's two-step `cf .. 0 em_ele` / `cf .. em_ele (w-1-em_ele)` is
             reconciled by ch_comp.
             TRH-vs-PKCO DELTA: the leaf is an OC (collection) query here, not a
             challenge query, so there is NO ts bookkeeping -- instead the leaf
             must (i) be shown to agree with side 1's `pkco` via the
             collection-input LENGTH bridge (MM45 :6054-6057) and (ii) preserve
             `all (<> trhxtype) tws`. ---- *)
        inline{2} 4.
        wp => /=.
        while (   ={skWOTS}
               /\ ps{1} = TRHC.O_THFC_Default.pp{2}
               /\ ad{1} = adz
               /\ ad{1} = R_SMDTTCRCTRH_C.ad{2}
               /\ ={pkWOTS}
               /\ (forall (t : int), 0 <= t < size sigWOTS{1} =>
                     nth witness sigWOTS{1} t
                     =
                     cf ps{1} (set_chidx (ht_chad ad{1} (size skWOTStd{1}) (size skWOTSnt{1}) (size skWOTSlp{1})) t)
                          0 (BaseW.val em{1}.[t]) (DigestBlock.val (nth witness skWOTS{1} t)))
               /\ all (fun (ad : adrs) => get_typeidx ad <> trhxtype) TRHC.O_THFC_Default.tws{2}
               /\ size skWOTS{2} = size pkWOTS{2}
               /\ size skWOTS{1} = size sigWOTS{1}
               /\ size skWOTStd{1} = size R_SMDTTCRCTRH_C.skWOTStd{2}
               /\ size skWOTSnt{1} = size skWOTSnt{2}
               /\ size skWOTSlp{1} = size skWOTSlp{2}
               /\ size skWOTS{1} <= len
               /\ size skWOTSlp{1} < l'
               /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
               /\ size skWOTStd{1} < d).
        - wp => /=.
          while{2} (   R_SMDTTCRCTRH_C.ad{2} = adz
                    /\ ch_ele{2}
                       =
                       cf TRHC.O_THFC_Default.pp{2}
                          (set_chidx (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} (size R_SMDTTCRCTRH_C.skWOTStd{2}) (size skWOTSnt{2})) chtype) (size skWOTSlp{2})) (size pkWOTS{2}))
                          0 i0{2} (DigestBlock.val (nth witness skWOTS{2} (size pkWOTS{2})))
                    /\ all (fun (ad : adrs) => get_typeidx ad <> trhxtype) TRHC.O_THFC_Default.tws{2}
                    /\ size pkWOTS{2} < len
                    /\ size skWOTSlp{2} < l'
                    /\ size skWOTSnt{2} < nr_trees (size R_SMDTTCRCTRH_C.skWOTStd{2})
                    /\ size R_SMDTTCRCTRH_C.skWOTStd{2} < d
                    /\ 0 <= i0{2} <= w - 1)
                   (w - 1 - i0{2}).
          * move=> _ z.
            inline 1.
            wp; skip => /> &2 allntrhtws ltlen_szpk ltlp_szsklp ltnt_szsknt ltd_szsktd ge0_i _ ltw1_i.
            rewrite DigestBlock.valP /=.
            rewrite /cf (chS _ _ _ _ (i0{2} + 1)) 1:validxadrs_validwadrs_setallch 2..5,7:// 1:valx_adz 1:DigestBlock.valP 1:// 1,2:/# /f /=.
            rewrite -cats1 all_cat allntrhtws /=.
            by rewrite gettype_setallch 1:valx_adz 3..5://; smt(size_ge0 dist_adrstypes).
          wp; rnd; wp; skip => /> &1 &2 nthsig allntrhtws eqszskpk eqszsksig eqszsksktd eqszsksknt eqszsksklp lelen_szsk ltlp_szsklp ltnt_szsknt ltd_szsktd ltlen_szsk skwele skwelein.
          rewrite -eqszskpk.
          split.
          + rewrite nth_rcons /=.
            rewrite /cf ch0 1:validxadrs_validwadrs_setallch 1:valx_adz 5:DigestBlock.valP 5,6://; 1..4: smt(size_ge0).
            by rewrite DigestBlock.valKd /=; smt(val_w).
          move=> tws i.
          split => [| gew1_i allntrhtwsp _ _ _ _ ge0_i lew1_i]; 1: smt().
          split.
          + congr.
            rewrite nth_rcons /= eqszsksktd eqszsksknt eqszsksklp.
            rewrite (: i = BaseW.val em{1}.[size skWOTS{2}] + (w - 1 - BaseW.val em{1}.[size skWOTS{2}])) 1:/#.
            rewrite /cf (ch_comp _ _ _ 0).
            + by apply validxadrs_validwadrs_setallch; smt(size_ge0 valx_adz).
            + by rewrite DigestBlock.valP.
            + smt().
            + smt(BaseW.valP).
            + smt(BaseW.valP val_w).
            + smt(BaseW.valP val_w).
            by smt().
          split.
          + move=> t ge0_t; rewrite size_rcons => ltt.
            rewrite ?nth_rcons -eqszsksig.
            case (t < size skWOTS{2}) => [ltt' | nltt]; 1: by rewrite nthsig 1:/# /ht_chad.
            have -> /= : t = size skWOTS{2} by smt().
            by rewrite /ht_chad.
          by rewrite ?size_rcons; smt().
        (* ---- 1a-KEYPAIRLEAF (CLOSED): the len-loop entry/exit leaf.  Three
               pieces: (i) MM45 :6054-6057's collection-input LENGTH bridge
               turning OC's `thfc (size input)` leaf into side 1's
               `pkco = thfc (8 * n * len)`; (ii) the +C sigWOTSlp ht_sigc_at
               characterization via eq_mkseq_of_nth + DBLL.insubdK (the PKCO
               branch's step (2), verbatim modulo the TRH renames); (iii)
               `all (<> trhxtype) tws` across the leaf rcons via
               gettype_setkptypeltchpkco (needs dist_adrstypes: the leaf address
               is pkcotype, and pkcotype <> trhxtype).  MM45's `!andbA -3!andbA`
               conjunct juggling is replaced by PKCO's sequential splits, since
               our conjunct COUNT differs (the +C conjunct is inserted). ---- *)
        wp; skip => /> &1 &2 nthsiglp allntrhtws eqszskpklp eqszsklfslp eqszsksiglp
                             eqszsksknt eqszskpknt eqszsklfsnt eqszsksignt eqszskrsnt
                             eqszsksktd eqszskpktd eqszsklfstd eqszsigtd eqszskrstd
                             _ ltnt_szsknt ltd_szsktd ltlp_szsklp.
        split; 1: smt(ge2_len).
        move=> sigw tws pkw skw /lezNgt gelen_szskw _ nthsigw allntrhtwsp eqszskpkw
               eqszsksigw lelen_szskw.
        (* (i) the LENGTH bridge (this is our own `size_pkco_input`, inlined for
               the raw `pkw : dgstblock list` the loop exit hands us). *)
        have szfl : size (flatten (map DigestBlock.val pkw)) = 8 * n * len.
        + rewrite size_flatten -map_comp StdBigop.Bigint.sumzE /= StdBigop.Bigint.BIA.big_map /(\o) /predT /= -/predT.
          rewrite (StdBigop.Bigint.BIA.eq_bigr _ _ (fun (_ : DigestBlock.sT) => 8 * n)) 1:/=.
          - by move=> ? _; rewrite DigestBlock.valP.
          by rewrite StdBigop.Bigint.big_constz count_predT; smt().
        rewrite szfl ?size_rcons.
        split; 1: by rewrite eqszsksktd eqszsksknt /pkco.
        (* (ii) the +C conjunct: side 2 builds NO signature, so sigWOTSlp{1} is
                characterized one-sidedly.  Same eq_mkseq_of_nth crux as PART 2. *)
        split.
        + move=> u ge0_u ltu.
          rewrite ?nth_rcons -eqszsksiglp.
          case (u < size skWOTSlp{2}) => [ltu' | nltu]; 1: by rewrite nthsiglp 1:/#.
          have -> /= : u = size skWOTSlp{2} by smt().
          rewrite /ht_sigc_at /ht_chad /=; congr.
          rewrite DBLL.insubdK 1:/#.
          apply (eq_mkseq_of_nth _ _ len); [smt(ge2_len) | smt() | ].
          by move=> t rng; rewrite /= nthsigw 1:/# /ht_chad.
        (* (iii) the leaf address is pkcotype, hence never trhxtype. *)
        split.
        + rewrite -cats1 all_cat allntrhtwsp /=.
          by rewrite gettype_setkptypeltchpkco 1:valx_adz 3,4://; smt(size_ge0 dist_adrstypes).
        by rewrite ?size_rcons; smt().
      (* ---- 1a-INNERTREE-LEAF (CLOSED): the l'-entry/exit + nodes-entry/exit
             leaf (MM45 :6060-6091) plus the ONE +C conjunct MM45 does not have
             (re-establishing ht_sigc_at for sigWOTSnt across the inner-tree
             rcons).  Skeleton = the PKCO branch's closed 1a-INNERTREE-LEAF
             (four pieces (a) l'-ENTRY / (b) nodes-ENTRY / (c) nodes-EXIT / (d)
             the +C conjunct); the CLOSING REWRITES are MM45-TRH's, not PKCO's:
             our `ndsnth` is stated with `sub_bt .. (rev (int2bs (h'-u-1) v))`
             (MM45-TRH), where the PKCO branch used a take/drop form. ---- *)
      wp; skip => /> &1 &2 nthsigtd nthsignt lfsszs lfsszs1 rsnth rsnth1 tsdef tsnth tsnth1
                           alltrhts allntrhtws uqunz1ts szts
                           eqszsksignt eqszskpknt eqszsklfsnt eqszskrsnt
                           eqszsigtd eqszskpktd eqszsklfstd eqszskrstd _
                           ltd_szsktd ltnt_szsknt.
      (* (a) l'-ENTRY.  Our extra sigWOTSlp conjunct is VACUOUS here
             (sigWOTSlp = [], so the `u < 0` guard is unsatisfiable). *)
      split => [| sigwlp tws lfslp pkwlp skwlp /lezNgt gelp_szskwlp _].
      + by split; smt(ge2_lp).
      move=> nthsigwlp allntrhtwsp eqszskpkwlp eqszsklfslp eqszsksigwlp lelp_szskwlp.
      (* (b) nodes-ENTRY (`bigi .. 1 1 = 0` first, exactly as MM45 :6063-6065). *)
      rewrite (range_geq 1 1) 1:// /=.
      split => [| ts nds]; 1: smt(ge1_hp).
      split=> [/# | /lezNgt gehp_sznds tspdef tspnth tspnth1 tspnth2 alltrhtsp
                    uqunz1tsp sztsp ndsnth eqlp_szlfslp lehp_sznds].
      (* (c) nodes-EXIT: turn side 2's `nth (nth nds (h'-1)) 0` into side 1's
             `val_bt_trh .. (list2tree leaveslp)`.  MM45 :6071-6073. *)
      split.
      + congr; rewrite ndsnth 2:IntOrder.expr_gt0 2,3:// 2:/=; 1: smt(ge1_hp).
        (* PORT DELTA vs MM45 :6072: `congr` leaves ONE goal here, not two --
           after `/>` substituted ad{1} := adz the two address arguments are
           syntactically identical, so MM45's `congr => [/#|]` is a
           "not the right number of intro-patterns (got 2, expecting 1)". *)
        rewrite /val_bt_trh /val_bt_trh_gen; congr.
        by rewrite (: h' - (h' - 1) - 1 = 0) 1:/# int2bs0s rev_nil subbt_empty oget_some.
      (* (d) THE +C CONJUNCT (no MM45 counterpart): re-establish the middle
             invariant's ht_sigc_at characterization of sigWOTSnt{1} across the
             inner-tree rcons.  j < size: the incoming `nthsignt`; j = size: the
             l'-loop's exit characterization `nthsigwlp`, re-indexed. *)
      split.
      + move=> j u ge0_j; rewrite size_rcons => ltj ge0_u ltu.
        rewrite !nth_rcons -eqszsksignt.
        case (j < size skWOTSnt{2}) => [ltjsz | /lezNgt gejsz].
        - by rewrite nthsignt 1:/# 1:/#.
        have eqj : j = size skWOTSnt{2} by smt().
        by rewrite eqj /= nthsigwlp 1:/#.
      (* the leaves / roots / ts bookkeeping (MM45 :6074-6080) *)
      split; 1: smt(size_ge0 nth_rcons size_rcons).
      split => [j ge0_j |]; 1: rewrite ?nth_rcons ?size_rcons => ltsz1_j.
      + rewrite -eqszskrsnt -eqszsklfsnt.
        case (j < size skWOTSnt{2}) => [/#| ?].
        rewrite (: j = size skWOTSnt{2}) 1:/# /= ndsnth 2:IntOrder.expr_gt0 2,3://; 1: smt(ge1_hp).
        by rewrite (: h' - (h' - 1) - 1 = 0) 1:/# int2bs0s rev_nil subbt_empty oget_some.
      rewrite andbA; split; 1: smt(size_ge0 nth_rcons size_rcons).
      split; last by rewrite ?size_rcons; smt().
      (* the ts SIZE conjunct: one finished inner tree adds `2 ^ h' - 1`
         targets, i.e. `bigi predT nr_nodesx 1 (h' + 1) = 2 ^ h' - 1`.
         MM45 :6081-6091 (the induction ports verbatim -- `nr_nodesx h'' =
         2 ^ (h' - h'')` is definitionally MM45's `nr_nodes`). *)
      rewrite sztsp size_rcons mulrDl /= addrA.
      congr; rewrite (: size nds = h') 1:/# /nr_nodesx /=.
      have: 1 <= h' by smt(ge1_hp).
      case (0 <= h') => [ |/#]; elim: h' => [/#| i ge0_i].
      case (i = 0) => [-> /= | neq0_i]; 1: by rewrite rangeS StdBigop.Bigint.BIA.big_seq1 /= expr0 expr1.
      rewrite {1}StdBigop.Bigint.BIA.big_seq => ih ge1_i1; have ge1_i: 1 <= i by smt().
      rewrite StdBigop.Bigint.BIA.big_int_recr 1:/# /= expr0 StdBigop.Bigint.BIA.big_seq /=.
      rewrite (StdBigop.Bigint.BIA.eq_bigr _ _ (fun h'' => 2 ^ (i - h'') * 2)).
      + move=> j /mem_range rng_j /=.
        by rewrite addrAC exprD_nneg 1:/# 1:// expr1.
      by rewrite -StdBigop.Bigint.BIA.mulr_suml ih 1:// mulrDl exprD_nneg 1,2:// expr1.
    (* LAYER-RCONS ADEQUACY: middle-loop entry + exit ==> the outer invariant
       (MM45 :6092-6113 for the ts/leaves/roots conjuncts; the ht_sigc
       conversion (C1) has no MM45 counterpart).  Decomposed with PKCO's
       sequential `split`s rather than MM45's `rewrite !andbA -4!andbA`, because
       our conjunct COUNT differs (the +C ht_sigc conjunct is inserted). *)
    wp; skip => /> &1 &2 nthsigtd lfsszs rsdef tsdef tsnth alltrhts allntrhtws uqunz1ts szts
                         eqszsigtd eqszskpktd eqszsklfstd eqszskrtstd
                         _ ltd_szskwtd.
    split=> [| sigWOTSnt_L tws_R ts_R leavesnt_R pkWOTSnt_R rootsnt_R skWOTSnt_R
               /lezNgt gent_szskwnt _].
    + by do! split; smt(StdOrder.IntOrder.expr_ge0).
    move=> nthsignt lfsntszs rsntnth tspdef tspnth tspnth1 alltrhtsp allntrhtwsp uqun1ts sztsp
           eqszsigwnt eqszpkskwnt eqszskwlfsnt eqszskwrsnt lent_szskwnt.
    (* (C1) the +C ht_sigc conjunct: old layers survive the cube rcons
            (ht_sigc_rcons_lt), the fresh layer converts from its local
            ht_sigc_at form (ht_sigc_rcons_eq). *)
    split.
    + move=> i j u ge0_i; rewrite size_rcons => lti ge0_j ltj ge0_u ltu.
      case (i < size R_SMDTTCRCTRH_C.skWOTStd{2}) => [lti' | nlti].
      - rewrite nth_rcons iftrue 1:/# ht_sigc_rcons_lt 1:/# 1:/#.
        by smt().
      have eqi : i = size R_SMDTTCRCTRH_C.skWOTStd{2} by smt().
      rewrite eqi eqszskrtstd nth_rcons iffalse 1:/# iftrue 1:/#.
      rewrite ht_sigc_rcons_eq 1:/# -eqszskrtstd.
      by rewrite nthsignt 1:/# 1:/#.
    (* (C2) leaves SIZE (MM45 :6107-6109). *)
    split => [i j | ].
    + rewrite size_rcons ?nth_rcons -eqszsklfstd => ge0_i ltsz1i ge0_j ltnt_j.
      case (i < size R_SMDTTCRCTRH_C.skWOTStd{2}) => [/#| ?].
      rewrite (: i = size R_SMDTTCRCTRH_C.skWOTStd{2}) 1:/# /=.
      by rewrite lfsntszs 1:/#.
    (* (C3) roots = val_bt_trh (MM45 :6110-6112). *)
    split => [i j | ].
    + rewrite size_rcons ?nth_rcons -eqszsklfstd -eqszskrtstd => ge0_i ltsz1i ge0_j ltnt_j.
      case (i < size R_SMDTTCRCTRH_C.skWOTStd{2}) => [/#| ?].
      rewrite (: i = size R_SMDTTCRCTRH_C.skWOTStd{2}) 1:/# /=.
      by rewrite rsntnth 1:/#.
    (* (C4) ts membership (MM45 :6113). *)
    split => [adx | ].
    + by split => [/tspdef | i j u v]; smt(size_ge0 nth_rcons size_rcons).
    (* (C5) ts nth characterization (MM45 :6101-6105). *)
    split => [i j u v | ].
    + rewrite size_rcons ?nth_rcons => *.
      case (i < size R_SMDTTCRCTRH_C.leavestd{2}) => [/#| ?].
      rewrite (: i = size R_SMDTTCRCTRH_C.leavestd{2}) 1:/# /=.
      by rewrite -eqszsklfstd tspnth1 1:/#.
    (* (C6) ts size (MM45 :6099). *)
    split; 1: by rewrite sztsp size_rcons StdBigop.Bigint.BIA.big_int_recr 1:size_ge0 //= /#.
    by do! split; smt(size_rcons).
  (* ADEQUACY GATE: cube-build entry + outer-loop exit ==> the `seq 7 7` post
     (MM45 :6114-6116, plus the +C ht_sigc conjunct which MM45 has no analogue
     for).  This is the step that CERTIFIES the outer invariant is strong
     enough: in particular that the ht_sigc conjunct, carried at bound
     `size skWOTStd{1}`, really does yield the post's bound-`d` form. *)
  wp; skip => /> &2 allntrhtws.
  split; 1: smt(StdBigop.Bigint.BIA.big_geq ge1_d).
  move=> sigWOTStd_L leavestd_R pkWOTStd_R rootstd_R skWOTStd_R tws_R ts_R.
  move=> nltd _ nthsig lfsszs rsdef tsdef tsnth alltrhts allntrhtws2 uqts szts
         eqszsig eqszpk eqszlfs eqszrs led.
  have eqd : size skWOTStd_R = d by smt().
  move: nthsig lfsszs rsdef tsdef tsnth szts; rewrite eqd => nthsig lfsszs rsdef tsdef tsnth szts.
  by do! split; smt().
(* NOTE (transplanted verbatim from the PKCO branch, rename-only):
   R_SMDTTCRCTRH_C.find carries the IDENTICAL grind-in-find rebuild loop as
   R_SMDTTCRCPKCO_C.find (same locals, same bounds, same pure element line,
   ZERO oracle calls), so this whole step is the PKCO PART 2 text with
   R_SMDTTCRCPKCO_C -> R_SMDTTCRCTRH_C.  It contains NO reference to the
   challenge-oracle target set, so nothing about pkco-vs-trh enters here. *)
(* ---- PART 2 (= 1b(i)): FIND-PROLOGUE ABSORPTION.  NO MM45 COUNTERPART.
        RHS-only `seq 0 4`: `ps <- pp`, the two cube inits, and the
        grind-in-find rebuild loop.  ORACLE-FREE (`find` is `{}`-restricted in
        Adv_SMDTTCRC), so this is a pure one-sided `while{2}`.  The post
        characterizes R.sigWOTStd / R.counterstd as the `ht_sigc` image, which
        is the SAME operator the `seq 7 7` post pins sigWOTStd{1} to; the two
        cubes are therefore equal by transitivity at the point of use. ---- *)
seq 0 4 : (   #pre
           /\ ps{2} = pp{2}
           /\ size R_SMDTTCRCTRH_C.sigWOTStd{2} = d
           /\ size R_SMDTTCRCTRH_C.counterstd{2} = d
           /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                 nth witness (nth witness (nth witness R_SMDTTCRCTRH_C.sigWOTStd{2} i) j) u
                 =
                 (ht_sigc ps{2} R_SMDTTCRCTRH_C.ad{2} R_SMDTTCRCTRH_C.ml{2}
                          R_SMDTTCRCTRH_C.rootstd{2} R_SMDTTCRCTRH_C.skWOTStd{2} i j u).`1)
           /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                 nth witness (nth witness (nth witness R_SMDTTCRCTRH_C.counterstd{2} i) j) u
                 =
                 (ht_sigc ps{2} R_SMDTTCRCTRH_C.ad{2} R_SMDTTCRCTRH_C.ml{2}
                          R_SMDTTCRCTRH_C.rootstd{2} R_SMDTTCRCTRH_C.skWOTStd{2} i j u).`2)).
- while{2} (   0 <= size R_SMDTTCRCTRH_C.sigWOTStd{2} <= d
            /\ size R_SMDTTCRCTRH_C.counterstd{2} = size R_SMDTTCRCTRH_C.sigWOTStd{2}
            /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCTRH_C.sigWOTStd{2} =>
                                      0 <= j < nr_trees i => 0 <= u < l' =>
                  nth witness (nth witness (nth witness R_SMDTTCRCTRH_C.sigWOTStd{2} i) j) u
                  =
                  (ht_sigc ps{2} R_SMDTTCRCTRH_C.ad{2} R_SMDTTCRCTRH_C.ml{2}
                           R_SMDTTCRCTRH_C.rootstd{2} R_SMDTTCRCTRH_C.skWOTStd{2} i j u).`1)
            /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCTRH_C.sigWOTStd{2} =>
                                      0 <= j < nr_trees i => 0 <= u < l' =>
                  nth witness (nth witness (nth witness R_SMDTTCRCTRH_C.counterstd{2} i) j) u
                  =
                  (ht_sigc ps{2} R_SMDTTCRCTRH_C.ad{2} R_SMDTTCRCTRH_C.ml{2}
                           R_SMDTTCRCTRH_C.rootstd{2} R_SMDTTCRCTRH_C.skWOTStd{2} i j u).`2))
           (d - size R_SMDTTCRCTRH_C.sigWOTStd{2}).
  (* --- outer body: one hypertree layer --- *)
  * move=> _ z.
    wp => /=.
    while (   0 <= size R_SMDTTCRCTRH_C.sigWOTStd < d
           /\ size R_SMDTTCRCTRH_C.counterstd = size R_SMDTTCRCTRH_C.sigWOTStd
           /\ rootsntp = last R_SMDTTCRCTRH_C.ml (take (size R_SMDTTCRCTRH_C.sigWOTStd) R_SMDTTCRCTRH_C.rootstd)
           /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCTRH_C.sigWOTStd => 0 <= j < nr_trees i => 0 <= u < l' =>
                nth witness (nth witness (nth witness R_SMDTTCRCTRH_C.sigWOTStd i) j) u
                = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd i j u).`1)
           /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCTRH_C.sigWOTStd => 0 <= j < nr_trees i => 0 <= u < l' =>
                nth witness (nth witness (nth witness R_SMDTTCRCTRH_C.counterstd i) j) u
                = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd i j u).`2)
           /\ 0 <= size sigWOTSnt <= nr_trees (size R_SMDTTCRCTRH_C.sigWOTStd)
           /\ size counternt = size sigWOTSnt
           /\ (forall (j u : int), 0 <= j < size sigWOTSnt => 0 <= u < l' =>
                nth witness (nth witness sigWOTSnt j) u
                = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd (size R_SMDTTCRCTRH_C.sigWOTStd) j u).`1)
           /\ (forall (j u : int), 0 <= j < size counternt => 0 <= u < l' =>
                nth witness (nth witness counternt j) u
                = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd (size R_SMDTTCRCTRH_C.sigWOTStd) j u).`2))
          (nr_trees (size R_SMDTTCRCTRH_C.sigWOTStd) - size sigWOTSnt).
    + (* --- middle body: one inner tree --- *)
      move=> z1.
      wp => /=.
      while (   0 <= size R_SMDTTCRCTRH_C.sigWOTStd < d
               /\ size R_SMDTTCRCTRH_C.counterstd = size R_SMDTTCRCTRH_C.sigWOTStd
               /\ rootsntp = last R_SMDTTCRCTRH_C.ml (take (size R_SMDTTCRCTRH_C.sigWOTStd) R_SMDTTCRCTRH_C.rootstd)
               /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCTRH_C.sigWOTStd => 0 <= j < nr_trees i => 0 <= u < l' =>
                    nth witness (nth witness (nth witness R_SMDTTCRCTRH_C.sigWOTStd i) j) u
                    = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd i j u).`1)
               /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCTRH_C.sigWOTStd => 0 <= j < nr_trees i => 0 <= u < l' =>
                    nth witness (nth witness (nth witness R_SMDTTCRCTRH_C.counterstd i) j) u
                    = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd i j u).`2)
               /\ 0 <= size sigWOTSnt < nr_trees (size R_SMDTTCRCTRH_C.sigWOTStd)
               /\ size counternt = size sigWOTSnt
               /\ (forall (j u : int), 0 <= j < size sigWOTSnt => 0 <= u < l' =>
                    nth witness (nth witness sigWOTSnt j) u
                    = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd (size R_SMDTTCRCTRH_C.sigWOTStd) j u).`1)
               /\ (forall (j u : int), 0 <= j < size counternt => 0 <= u < l' =>
                    nth witness (nth witness counternt j) u
                    = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd (size R_SMDTTCRCTRH_C.sigWOTStd) j u).`2)
               /\ 0 <= size sigWOTSlp <= l'
               /\ size counterlp = size sigWOTSlp
               /\ (forall (u : int), 0 <= u < size sigWOTSlp =>
                    nth witness sigWOTSlp u
                    = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd (size R_SMDTTCRCTRH_C.sigWOTStd) (size sigWOTSnt) u).`1)
               /\ (forall (u : int), 0 <= u < size counterlp =>
                    nth witness counterlp u
                    = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd (size R_SMDTTCRCTRH_C.sigWOTStd) (size sigWOTSnt) u).`2))
            (l' - size sigWOTSlp).
      - (* --- l' body: one WOTS+C keypair --- *)
        move=> z2.
        wp => /=.
        while (   0 <= size R_SMDTTCRCTRH_C.sigWOTStd < d
                   /\ size R_SMDTTCRCTRH_C.counterstd = size R_SMDTTCRCTRH_C.sigWOTStd
                   /\ rootsntp = last R_SMDTTCRCTRH_C.ml (take (size R_SMDTTCRCTRH_C.sigWOTStd) R_SMDTTCRCTRH_C.rootstd)
                   /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCTRH_C.sigWOTStd => 0 <= j < nr_trees i => 0 <= u < l' =>
                        nth witness (nth witness (nth witness R_SMDTTCRCTRH_C.sigWOTStd i) j) u
                        = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd i j u).`1)
                   /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCTRH_C.sigWOTStd => 0 <= j < nr_trees i => 0 <= u < l' =>
                        nth witness (nth witness (nth witness R_SMDTTCRCTRH_C.counterstd i) j) u
                        = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd i j u).`2)
                   /\ 0 <= size sigWOTSnt < nr_trees (size R_SMDTTCRCTRH_C.sigWOTStd)
                   /\ size counternt = size sigWOTSnt
                   /\ (forall (j u : int), 0 <= j < size sigWOTSnt => 0 <= u < l' =>
                        nth witness (nth witness sigWOTSnt j) u
                        = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd (size R_SMDTTCRCTRH_C.sigWOTStd) j u).`1)
                   /\ (forall (j u : int), 0 <= j < size counternt => 0 <= u < l' =>
                        nth witness (nth witness counternt j) u
                        = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd (size R_SMDTTCRCTRH_C.sigWOTStd) j u).`2)
                   /\ 0 <= size sigWOTSlp < l'
                   /\ size counterlp = size sigWOTSlp
                   /\ (forall (u : int), 0 <= u < size sigWOTSlp =>
                        nth witness sigWOTSlp u
                        = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd (size R_SMDTTCRCTRH_C.sigWOTStd) (size sigWOTSnt) u).`1)
                   /\ (forall (u : int), 0 <= u < size counterlp =>
                        nth witness counterlp u
                        = (ht_sigc ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd R_SMDTTCRCTRH_C.skWOTStd (size R_SMDTTCRCTRH_C.sigWOTStd) (size sigWOTSnt) u).`2)
                   /\ root = ht_root R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd (size R_SMDTTCRCTRH_C.sigWOTStd) (size sigWOTSnt) (size sigWOTSlp)
                   /\ counter = ht_cnt ps R_SMDTTCRCTRH_C.ad R_SMDTTCRCTRH_C.ml R_SMDTTCRCTRH_C.rootstd (size R_SMDTTCRCTRH_C.sigWOTStd) (size sigWOTSnt) (size sigWOTSlp)
                   /\ em = encode_msgWOTS_C ps (ht_chad R_SMDTTCRCTRH_C.ad (size R_SMDTTCRCTRH_C.sigWOTStd) (size sigWOTSnt) (size sigWOTSlp)) root counter
                   /\ skWOTSr = DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCTRH_C.skWOTStd (size R_SMDTTCRCTRH_C.sigWOTStd)) (size sigWOTSnt)) (size sigWOTSlp))
                   /\ 0 <= size sigWOTS <= len
                   /\ (forall (t : int), 0 <= t < size sigWOTS =>
                        nth witness sigWOTS t
                        = cf ps (set_chidx (ht_chad R_SMDTTCRCTRH_C.ad (size R_SMDTTCRCTRH_C.sigWOTStd) (size sigWOTSnt) (size sigWOTSlp)) t) 0 (BaseW.val em.[t])
                             (DigestBlock.val (nth witness skWOTSr t))))
              (len - size sigWOTS).
        * (* --- chain body: one WOTS chain --- *)
          move=> z3.
          wp; skip => /> &hr *.
          rewrite /ht_chad !size_rcons.
          smt(nth_rcons size_ge0).
        (* l'-body prologue + chain-loop exit *)
        wp; skip => /> &hr ge0_sztd ltd_sztd eqsz_cntd nthtd nthcntd
                      ge0_sznt ltnt_sznt eqsz_cnnt nthnt nthcnnt
                      ge0_szlp lel_szlp eqsz_cnlp nthlp nthcnlp ltl_szlp.
        split; 1: smt(ge2_len).
        move=> sigWOTS0; split; 1: smt().
        move=> nltlen eqroot eqcnt eqem ge0_szsw lelen_szsw nthsw.
        rewrite !size_rcons.
        split; last by smt().
        split; 1: smt(size_ge0).
        split; 1: smt().
        split.
        + move=> u ge0_u ltu.
          rewrite nth_rcons.
          case (u < size sigWOTSlp{hr}) => [ltu' | nltu]; 1: by smt().
          have -> /= : u = size sigWOTSlp{hr} by smt().
          rewrite /ht_sigc /=; congr.
          apply (eq_mkseq_of_nth _ _ len); [smt(ge2_len) | smt() | ].
          by move=> t rng; rewrite nthsw 1:/# /ht_chad.
        move=> u ge0_u ltu.
        rewrite nth_rcons.
        case (u < size counterlp{hr}) => [ltu' | nltu]; 1: by smt().
        have -> /= : u = size counterlp{hr} by smt().
        by rewrite eqsz_cnlp /ht_sigc /ht_cnt /ht_chad /ht_root.
      (* middle-body prologue + l'-loop exit *)
      wp; skip => /> &hr ge0_sztd ltd_sztd eqsz_cntd nthtd nthcntd
                    ge0_sznt lent_sznt eqsz_cnnt nthnt nthcnnt ltnt_sznt.
      split; 1: smt(ge2_lp).
      move=> counterlp0 sigWOTSlp0; split; 1: smt().
      move=> nltl ge0_szlp lel_szlp eqsz_cnlp nthlp nthcnlp.
      rewrite !size_rcons.
      split; last by smt().
      split; 1: smt(size_ge0).
      split; 1: smt().
      split.
      + move=> j u ge0_j ltj ge0_u ltu.
        rewrite nth_rcons.
        case (j < size sigWOTSnt{hr}) => [ltj' | nltj]; 1: by smt().
        have -> /= : j = size sigWOTSnt{hr} by smt().
        by smt().
      move=> j u ge0_j ltj ge0_u ltu.
      rewrite nth_rcons.
      case (j < size counternt{hr}) => [ltj' | nltj]; 1: by smt().
      have -> /= : j = size counternt{hr} by smt().
      by smt().
    (* outer-body prologue + middle-loop exit *)
    wp; skip => /> &hr ge0_sztd led_sztd eqsz_cntd nthtd nthcntd ltd_sztd.
    split; 1: (rewrite /nr_trees; smt(StdOrder.IntOrder.expr_ge0)).
    move=> counternt0 sigWOTSnt0; split; 1: smt().
    move=> nltnt ge0_sznt lent_sznt eqsz_cnnt nthnt nthcnnt.
    rewrite !size_rcons.
    split; last by smt().
    split; 1: smt(size_ge0).
    split; 1: smt().
    split.
    + move=> i j u ge0_i lti ge0_j ltj ge0_u ltu.
      rewrite nth_rcons.
      case (i < size R_SMDTTCRCTRH_C.sigWOTStd{hr}) => [lti' | nlti]; 1: by smt().
      have eqi : i = size R_SMDTTCRCTRH_C.sigWOTStd{hr} by smt().
      rewrite eqi /=; smt().
    move=> i j u ge0_i lti ge0_j ltj ge0_u ltu.
    rewrite nth_rcons.
    case (i < size R_SMDTTCRCTRH_C.counterstd{hr}) => [lti' | nlti]; 1: by smt().
    have eqi : i = size R_SMDTTCRCTRH_C.counterstd{hr} by smt().
    rewrite eqi /=; smt().
  (* prologue inits + outer-loop entry/exit.
     PORT DELTA vs the PKCO branch: NINE anonymous intros, not eight -- the TRH
     `seq 7 7` post carries one conjunct more than PKCO's (PKCO has a single
     pkco-leaf characterization where TRH has BOTH `size leaveslp = l'` and the
     `rootstd = val_bt_trh` relation).  Machine-determined, not guessed: 10
     gives "nothing to introduce", 7 gives "cannot apply split/None". *)
  wp; skip => /> &1 &2 ?????????.
  split; 1: smt(ge1_d).
  move=> counterstd_R sigWOTStd_R; split; 1: smt().
  move=> nltd ge0_sz led_sz eqsz nthsig nthcnt.
  have eqd : size sigWOTStd_R = d by smt().
  move: nthsig nthcnt; rewrite eqd => nthsig nthcnt.
  by smt().

  (* (i) ROOT REORDERING: side 1 computes `root`/`pk` BEFORE the signing loop,
         side 2's `find` computes `root` AFTER it. *)
  swap{1} [1..2] 2.
  (* (ii) THE SIGNING-LOOP SIMULATION. *)
  seq 2 2 : (#pre /\ ={sigl}).
  - while (#pre /\ ={sigl} /\ size sigl{1} <= l).
    * wp => /=.
      while (   #pre
             /\ ={sapl, tidx, kpidx}
             /\ size sapl{1} <= d
             /\ 0 <= tidx{1}
             /\ (size sapl{1} < d => tidx{1} < nr_trees (size sapl{1}) * l')).
      + seq 2 2 : (   #pre
                   /\ sigcins{1} = sigc{2}
                   /\ (size sapl{1} < d => tidx{1} < nr_trees (size sapl{1}))).
        - wp; skip => /> &1 &2 allntrhtws nthsigtd lfsszs rsnth tsdef tsnth alltrhts
                       uqunz1ts szts szsigtd szcntd nthsigR nthcntR
                       lel_szsigl ltl_szsigl led_szsapl ge0_tidx tidxrng ltd_szsapl.
          have gt0_lp : 0 < l' by smt(ge2_lp).
          have ltnt_tidx : tidx{2} < nr_trees (size sapl{2}) * l' by apply tidxrng.
          have rng_t : 0 <= tidx{2} %/ l' < nr_trees (size sapl{2}).
          + by rewrite divz_ge0 1:// ge0_tidx /= ltz_divLR 1://.
          have rng_k : 0 <= tidx{2} %% l' < l' by smt(modz_ge0 ltz_pmod).
          have cube :
            nth witness (nth witness (nth witness sigWOTStd{1} (size sapl{2}))
                          (tidx{2} %/ l')) (tidx{2} %% l')
            =
            (nth witness (nth witness (nth witness R_SMDTTCRCTRH_C.sigWOTStd{2}
                            (size sapl{2})) (tidx{2} %/ l')) (tidx{2} %% l'),
             nth witness (nth witness (nth witness R_SMDTTCRCTRH_C.counterstd{2}
                            (size sapl{2})) (tidx{2} %/ l')) (tidx{2} %% l')).
          + by apply (ht_sigcube_transitivity sigWOTStd{1}
                        R_SMDTTCRCTRH_C.sigWOTStd{2} R_SMDTTCRCTRH_C.counterstd{2}
                        TRHC.O_THFC_Default.pp{2} adz R_SMDTTCRCTRH_C.ml{2}
                        R_SMDTTCRCTRH_C.rootstd{2} R_SMDTTCRCTRH_C.skWOTStd{2}
                        (size sapl{2}) (tidx{2} %/ l') (tidx{2} %% l'));
              [smt(size_ge0) | exact rng_t | exact rng_k
               | exact nthsigtd | exact nthsigR | exact nthcntR].
          by do! split; smt().
        wp; skip => /> &1 &2 allntrhtws nthsigtd lfsszs rsnth tsdef tsnth alltrhts
                     uqunz1ts szts szsigtd szcntd nthsigR nthcntR
                     lel_szsigl ltl_szsigl led_szsapl ge0_tidx tidxrng ltd_szsapl
                     tidxsharp.
        rewrite ?size_rcons.
        split; 1: smt().
        move=> ltd1.
        have -> : nr_trees (size sapl{2} + 1) * l' = nr_trees (size sapl{2}).
        + by rewrite /nr_trees /l' -exprD_nneg; smt(ge1_hp).
        by apply tidxsharp; smt().
      (* inner-loop entry/exit: `nr_trees 0 * l' = l` is what makes the top-level
         `tidx = size sigl < l` an admissible starting index. *)
      wp; skip => /> &1 &2 allntrhtws nthsigtd lfsszs rsnth tsdef tsnth alltrhts
                   uqunz1ts szts szsigtd szcntd nthsigR nthcntR
                   lel_szsigl ltl_szsigl.
      have nrt0 : nr_trees 0 * l' = l.
      + by rewrite /nr_trees /l' /l /h -exprD_nneg; smt(ge1_hp ge1_d).
      split; 1: smt(size_ge0 ge1_d).
      by move=> *; smt(size_rcons).
    by wp; skip => /> *; smt(size_ge0).
  (* ---- (iii) FORGE + RECONSTRUCTION LOOP + trh COLLISION EXTRACTION.
          +C port of MM45 :6127-6298.  STATEMENT NUMBERING (read off the actual
          frontier goal, not guessed): side 1 has 19 statements, side 2 has 25.
          Side 1 is MM45's V + ONE statement (`allOkC <- true` at 7), so every
          side-1 index from 7 on is MM45's + 1; side 2 is statement-identical to
          MM45's R_SMDTTCRCTRH_EUFNAGCMA.find tail, so its indices port verbatim.
          Hence MM45's `swap{1} [15..16] 1` / `wp 15 22` become
          `swap{1} [16..17] 1` / `wp 16 22` -- the SAME +1 offset the PKCO branch
          needed (MM45 `swap{1} 15 1`/`wp 15 17` -> ours `swap{1} 16 1`/`wp 16 17`).
          The swap moves valid_WOTSTWES/valid_TCRPKCO PAST valid_TCRTRH so the
          conseq can keep valid_TCRTRH and wp away the other three flags. ---- *)
  inline{2} 25; inline{2} 24; inline{2} 23; inline{2} 22; inline{2} 21.
  swap{1} [16..17] 1.
  wp 16 22 => /=.
  conseq (:   is_fresh{1}
           /\ EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_TCRTRH{1}
           =>
              0 <= i{2} < StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => nr_trees d') 0 d * (2 ^ h' - 1)
           /\ 0 <= size TRHC_TCR.O_SMDTTCR_Default.ts{2}
                <= StdBigop.Bigint.BIA.bigi predT (fun (d' : int) => nr_trees d') 0 d * (2 ^ h' - 1)
           /\ x'{2} <> x{2}
           /\ trh pp{2} tw{2} x{2} = trh pp{2} tw{2} x'{2}).
  (* conseq side-condition.  The `/>`-normalized goal drops MM45's `dist`
     conjunct all by itself (it is literally `uqunz1ts`, closed by assumption
     during `/>`), leaving FIVE: the i-range, the ts-size range, x <> x', the
     trh equality, and disj_lists.  Same five the PKCO branch handles. *)
  - move=> /> &1 &2 allntrhtws nthsigtd lfsszs rsnth tsdef tsnth alltrhts uqunz1ts szts
                    szsigtd szcntd nthsigR nthcntR
                    vTCR allOk idx isf lfs lfs' m pkw pkw' rs rs' sg i tw x x'
                    hnew szsg eqrt allokT isfT nvW nvP vTCRT.
    move: (hnew _); 1: by rewrite isfT vTCRT.
    move=> [rngi [rngts [neqx eqtrh]]].
    rewrite szts /=.
    split; 1: smt().
    split; 1: smt().
    split; 1: by rewrite eq_sym.
    split; 1: by apply eqtrh.
    (* disj_lists: every ts tweak is trhxtype, every OC tweak is not. *)
    rewrite hasPn => ad0 /mapP [adx /= [+ ->]].
    rewrite implybE -negb_and -negP => -[adin adxin].
    by move: allntrhtws => /allP /(_ adx.`1 adxin) /=; smt(allP).
  wp => /=.
  while (   ={ps, m', sig', idx', leavess, rootss, leavess', rootss', tkpidxs, tidx, kpidx, root'}
         /\ ad{1} = R_SMDTTCRCTRH_C.ad{2}
         /\ leavestd{1} = R_SMDTTCRCTRH_C.leavestd{2}
         /\ rootstd{1} = R_SMDTTCRCTRH_C.rootstd{2}
         /\ 0 <= tidx{2}
         /\ (size leavess'{2} < d =>
               tidx{2} < nr_trees (size leavess'{2}) * l')
         /\ (size leavess'{2} < d =>
                tidx{2} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (Index.val idx'{2}, 0) (size leavess'{2})).`1 /\
                kpidx{2} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (Index.val idx'{2}, 0) (size leavess'{2})).`2)
         /\ (forall (i : int), 0 <= i < size leavess'{2} =>
               nth witness leavess{2} i
               =
               nth witness (nth witness (nth witness R_SMDTTCRCTRH_C.leavestd{2} i) (nth witness tkpidxs{2} i).`1) (nth witness tkpidxs{2} i).`2)
         /\ (forall (i : int), 0 <= i < size leavess'{2} =>
               nth witness rootss{2} i
               =
               nth witness (nth witness R_SMDTTCRCTRH_C.rootstd{2} i) (nth witness tkpidxs{2} i).`1)
         /\ (forall (i : int), 0 <= i < size leavess'{2} =>
               nth witness rootss'{2} i
               =
               val_ap_trh ps{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_C.ad{2} i (nth witness tkpidxs{2} i).`1) trhxtype) (nth witness sig'{2} i).`2 (nth witness tkpidxs{2} i).`2 (nth witness leavess'{2} i))
         /\ (forall (i : int), 0 <= i < size tkpidxs{2} =>
               (nth witness tkpidxs{2} i).`1 = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (Index.val idx'{2}, 0) (i + 1)).`1 /\
               (nth witness tkpidxs{2} i).`2 = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (Index.val idx'{2}, 0) (i + 1)).`2)
         /\ (forall (i : int), 0 <= i < size tkpidxs{2} =>
               0 <= (nth witness tkpidxs{2} i).`1 < nr_trees i /\
               0 <= (nth witness tkpidxs{2} i).`2 < l')
         /\ size pkWOTSs'{1} = size leavess'{2}
         /\ size leavess'{2} = size leavess{2}
         /\ size leavess'{2} = size rootss{2}
         /\ size leavess'{2} = size rootss'{2}
         /\ size leavess'{2} = size tkpidxs{2}
         /\ size leavess'{2} <= d).
  (* reconstruction-loop BODY -- MM45 :6172-6210 verbatim modulo /nr_nodes ->
     /nr_nodesx.  The ONE +C statement on side 1 (`allOkC <- allOkC /\ okC`)
     is absorbed by `wp` (allOkC is not in the invariant); the pair-returning
     +C `pkWOTS_from_sigWOTS_C` still yields ONE `={res}` hypothesis, so the
     `=> pkwc` after MM45's `rewrite eqszlfsppkwp /=` is unchanged. *)
  * wp => /=.
    call (: true); 1: by sim.
    wp; skip => /> &1 &2 ge0_ti ltnt_ti tkpicdef lfsrel rsrel lfspdef tkpidef tkpirng
                         eqszlfsppkwp eqszlfsplfs eqszlfsprs eqszlfsprsp eqszlfsptkpi
                         _ ltd_szpkwp ltd_szlfsp.
    rewrite eqszlfsppkwp /= => pkwc.
    rewrite ?nth_rcons ?size_rcons -!andbA.
    split; 1: by rewrite divz_ge0; smt(ge2_lp).
    split => [ltd_szpk1 |].
    + rewrite ltz_divLR; 1: smt(ge2_lp).
      move: (ltnt_ti _); 1: smt().
      rewrite /nr_nodes_ht /nr_trees /nr_nodesx /l'.
      by rewrite /= -?exprD_nneg ?addr_ge0 ?mulr_ge0 ?ge1_hp; smt(ge1_hp).
    split => [ltd_szpk1 |]; 1: by rewrite foldS 1:// /= /#.
    split => [j ge0_j ltsz1_j |].
    + rewrite ?nth_rcons -eqszlfsplfs -eqszlfsptkpi.
      by case (j < size leavess'{2}) => /#.
    split => [j ge0_j ltsz1_j |].
    + rewrite ?nth_rcons -eqszlfsprs -eqszlfsptkpi.
      by case (j < size leavess'{2}) => /#.
    split => [j ge0_j ltsz1_j |].
    + rewrite ?nth_rcons -eqszlfsprsp -eqszlfsptkpi.
      by case (j < size leavess'{2}) => /#.
    split => [j ge0_j ltsz1_j |]; rewrite ?nth_rcons -eqszlfsptkpi.
    + case (j < size leavess'{2}) => [/# | nltszpkj].
      by rewrite (: j = size leavess'{2}) 1:/# /= foldS 1:// /= /#.
    split => [j ge0_j ltsz1_j |]; 2: smt(size_rcons).
    rewrite ?nth_rcons -eqszlfsptkpi.
    case (j < size leavess'{2}) => [/# | nltszpkj].
    rewrite (: j = size leavess'{2}) 1:/# /= divz_ge0 2:modz_ge0 3:ltz_pmod 4:/=; 1..3: smt(ge2_lp).
    by rewrite ge0_ti /= ltz_divLR; smt(ge2_lp).
  (* loop ENTRY/EXIT + the trh COLLISION EXTRACTION + the `fidx` index
     arithmetic -- MM45 :6218-6298.  The intro structure ports EXACTLY (the
     `/>`-normalized exit branch binds the same seven program variables
     `pkws lfs lfs' rs rs' ti tkpi` and the same fifteen hypotheses); the +C
     deltas are name-level only:
       * FOUR extra #pre hypotheses in the `/>` list (nthsigtd from `seq 7 7`,
         szsigtd/szcntd/nthsigR/nthcntR from PART 2) -- none is used here;
       * `val msigidx.`2` -> `msigidx.`2` (the +C hypertree signature is a plain
         list, not a size-d subtype) and the auth path needs `DBHPL.val`;
       * trhtype -> trhxtype, nr_nodes -> nr_nodesx, and the qualification
         conventions of this file (StdBigop.Bigint.BIA.bigi / .big_geq,
         StdBigop.Bigint.sumr_ge0, IntOrder.expr_ge0 / .ler_subr_addr,
         DBHPL.valP / DigestBlock.valP).
     The extracted target is an INNER MERKLE NODE, so `fidx` is the four-block
     (i,j,u,v) index that PART 1a's `tsnth` fixes, and `ltbignn_i` (NOT the
     PKCO branch's `ltbignrt_i`) is what bounds it. *)
  wp => /=.
  call (: true).
  wp; skip => /> &1 &2 allntrhtws nthsigtd lfsszs rsnth tsdef tsnth alltrhts uqunz1ts szts
                       szsigtd szcntd nthsigR nthcntR msigidx.
  split => [| pkws lfs lfs' rs rs' ti tkpi /lezNgt ged_szpkw /lezNgt ged_szlfs ge0ti].
  * rewrite andbA; split; 2: smt(ge1_d fold0).
    split => [| gt0_d]; 1: smt(Index.valP).
    move: (Index.valP (msigidx.`3)) => [_ @/l @/h @/l'].
    by rewrite -exprD_nneg ?mulr_ge0; smt(ge1_hp).
  move=> lfsrel rsrel rspdef tkpidef tkpirng eqszpkwslfsp eqszlfsp eqszlfsprs eqszlfsprsp
         eqszlfsptkpi led_szlfsp neqm i ge0_i ltd_i.
  rewrite (: i + 1 <> 0) 1:/# /= => eqirs neqilfs.
  pose zs := zip _ _; pose cidx := find _ _.
  have hascidx :
    has (fun (x : ((dgstblock * dgstblock) * dgstblock) * dgstblock) =>
                  x.`1.`1.`1 = x.`1.`1.`2 /\ x.`1.`2 <> x.`2) zs.
  * rewrite -(has_nthP _ _ (((witness, witness), witness), witness)) /=.
    exists i; rewrite -(: d = size zs) 1:/zs 1:?size_zip /= 1:/#.
    split => [/#|].
    rewrite /zs ?nth_zip_cond ?size_zip ?lez_minl 1..7:/#.
    by rewrite (: i < size rs') 1:/#.
  have ge0_cidx : 0 <= cidx by rewrite find_ge0.
  have ltd_cidx : cidx < d.
  * by rewrite /cidx (: d = size zs) 1:/zs 1:?size_zip /= 1:/# -has_find.
  move /(nth_find (((witness, witness), witness), witness)): (hascidx) => /= @-/cidx.
  rewrite /zs ?nth_zip_cond ?size_zip ?lez_minl 1..7:/#.
  rewrite (: cidx < size rs') 1:/# /= => -[eqrs neqlfs].
  move: (ecbtapP (trhi TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx adz cidx (nth witness tkpi cidx).`1) trhxtype))
                 updhbidx
                 (list2tree (nth witness (nth witness R_SMDTTCRCTRH_C.leavestd{2} cidx) (nth witness tkpi cidx).`1))
                 (DBHPL.val (nth witness msigidx.`2 cidx).`2)
                 (rev (int2bs h' (nth witness tkpi cidx).`2))
                 (nth witness lfs' cidx)
                 (nth witness lfs cidx)
                 (h', 0)).
  move: (ecbtap_vals (trhi TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx adz cidx (nth witness tkpi cidx).`1) trhxtype))
                     updhbidx
                     (list2tree (nth witness (nth witness R_SMDTTCRCTRH_C.leavestd{2} cidx) (nth witness tkpi cidx).`1))
                     (DBHPL.val (nth witness msigidx.`2 cidx).`2)
                     (rev (int2bs h' (nth witness tkpi cidx).`2))
                     (nth witness lfs' cidx)
                     (nth witness lfs cidx)
                     (h', 0)).
  move: (ecbtabp_props (trhi TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx adz cidx (nth witness tkpi cidx).`1) trhxtype))
                       updhbidx
                       (list2tree (nth witness (nth witness R_SMDTTCRCTRH_C.leavestd{2} cidx) (nth witness tkpi cidx).`1))
                       (DBHPL.val (nth witness msigidx.`2 cidx).`2)
                       (rev (int2bs h' (nth witness tkpi cidx).`2))
                       (nth witness lfs' cidx)
                       (nth witness lfs cidx)
                       (h', 0)).
  rewrite (list2tree_fullybalanced _ h') 3:/=; 1: smt(ge1_hp).
  + by rewrite lfsszs 1:// 1:/#.
  rewrite ?DBHPL.valP size_rev size_int2bs -(: h' = max 0 h') 2:/=; 1: smt(ge1_hp).
  rewrite (list2tree_height _ h') 2:lfsszs 2,4:// 3:/=; 1,2: smt(ge1_hp).
  rewrite neqlfs /=; move: eqrs; rewrite rsrel 2:rspdef 3:rsnth 1..4:/#.
  rewrite /val_ap_trh /val_ap_trh_gen /val_bt_trh => -> /=.
  rewrite list2tree_lvb; 1..3: smt(ge1_hp).
  rewrite (onth_nth witness) 2:lfsrel 1,2:/# /=.
  rewrite /extract_coll_bt_ap_trh; pose ec := extract_collision_bt_ap _ _ _ _ _ _ _.
  case: ec => /= [x1 x1' x2 x2' hbidx l r bs].
  move=> [#] eqhlr eqszhl lthphl lthpszbs.
  move=> [#] x1val x1pval x2val x2pval.
  rewrite take_rev_int2bs; 1: smt(size_ge0).
  rewrite foldlupdhbidx size_int2bs lez_maxr 1:/#.
  rewrite (: h' - (h' - size bs - 1) =  size bs + 1) 1:/# /=.
  move=> hbidxval lval rval bsval.
  move => [#] neqin eqout.
  rewrite size_ge0 szts /=.
  split; 1: rewrite hbidxval /=; 1: split => [| _].
  (* `0 <= fidx`.  MM45 :6273-6274 drives this with a bare `?addr_ge0
     ?mulr_ge0` cascade and then focuses goals 1..5; under our qualification
     (we do NOT `import IntOrder`) the BARE names are no-ops inside `?...`, so
     the cascade never fires and the focus indices are invalid.  Proving the
     four summands nonneg by name instead is insensitive to how the cascade
     splits, and needs no focus index at all. *)
  + have hbt : 0 <= StdBigop.Bigint.BIA.bigi predT nr_trees 0 cidx.
    - by rewrite StdBigop.Bigint.sumr_ge0 => ? _; rewrite IntOrder.expr_ge0.
    have hbn : 0 <= StdBigop.Bigint.BIA.bigi predT nr_nodesx 1 (size bs + 1).
    - by rewrite StdBigop.Bigint.sumr_ge0 => ? _; rewrite IntOrder.expr_ge0.
    have hex : 0 <= 2 ^ h' - 1 by smt(IntOrder.expr_gt0).
    have hkp : 0 <= (nth witness tkpi cidx).`1 by smt().
    have h1 : 0 <= StdBigop.Bigint.BIA.bigi predT nr_trees 0 cidx * (2 ^ h' - 1)
      by smt(IntOrder.mulr_ge0).
    have h2 : 0 <= (nth witness tkpi cidx).`1 * (2 ^ h' - 1)
      by smt(IntOrder.mulr_ge0).
    smt(bs2int_ge0).
  (* `fidx < bigi nr_trees 0 d * (2^h'-1)`: pad the bound into ltbignn_i's exact
     four-block shape and apply it at (i',j',u',v') = (d,0,0,0).  PORT DELTA vs
     MM45 :6276, which pads with `0 * (2 ^ h - 1)`: writing that literally here
     is a HARD ERROR, because BARE `h` is ambiguous in our context --
     `Top.SPHINCS_PLUS.FSSLXMTWES.h` vs `Top.SPHINCS_PLUS.h` (RUN: restoring
     MM45's text gives "more that one variable or constant matches `h").  The
     padded factor multiplies 0, so its value is irrelevant; `2 ^ h' - 1` is
     used because it is unambiguous AND matches ltbignn_i's `j' * (2 ^ h' - 1)`
     slot syntactically.  A disambiguated `2 ^ FSSLXMTWES.h - 1` ALSO compiles
     (RUN, `easycrypt compile` EXIT 0), so EC's matcher is factor-agnostic
     under the `j' := 0` coefficient exactly as MM45's own text implies: the
     ONLY thing that had to change here is the QUALIFICATION of `h`, not the
     factor.  An earlier draft of this note claimed the factor had to be
     `2 ^ h' - 1` "for the rewrite to unify" -- that is RETRACTED; it was an
     inference, and the run contradicts it. *)
  + rewrite -(addr0 (StdBigop.Bigint.BIA.bigi predT nr_trees 0 d * _)).
    rewrite {3}(: 0 = 0 * (2 ^ h' - 1) + StdBigop.Bigint.BIA.bigi predT nr_nodesx 1 (0 + 1) + 0)
      1:StdBigop.Bigint.BIA.big_geq 1,2://.
    rewrite ?addrA (ltbignn_i _ _ _ 0) 1,3,4,5,7:// 1:/#.
    rewrite bs2int_ge0 /=; pose i2bs := int2bs _ _.
    rewrite (: nr_nodesx (size bs + 1) = 2 ^ (size i2bs)) 2:bs2int_le2Xs.
    by rewrite /nr_nodesx /i2bs size_int2bs /#.
  pose nthtsc := nth _ _ (_ + _ + _ + _)%Int.
  move: (tsnth cidx (nth witness tkpi cidx).`1 (hbidx.`1 - 1) hbidx.`2 _ _ _ _); 1..3: smt(size_ge0).
  + rewrite hbidxval /= bs2int_ge0 /nr_nodesx /=; pose i2bs := int2bs _ _.
    by rewrite (: h' - (size bs + 1) = size i2bs) 1:size_int2bs 1:/# bs2int_le2Xs.
  pose vb := val_bt_trh_gen _ _ _ _ _; pose vb' := val_bt_trh_gen _ _ _ _ _.
  suff: x1 = vb /\ x1' = vb'.
  + move => [<- <-]; rewrite /nthtsc => -> /=.
    move: eqout => @/trhi -> /=.
    rewrite eqseq_cat 1:2!DigestBlock.valP 1://.
    move: neqin; rewrite 2!negb_and => neqxor.
    by move: neqxor
             (DigestBlock.val_inj x1 x2)
             (DigestBlock.val_inj x1' x2') => + /contra + /contra /#.
  rewrite x1val /vb x1pval /vb' hbidxval /val_bt_trh_gen lval rval /=.
  split; congr => [| // | | //]; congr; congr.
  + rewrite -rev_cons -{2}(expr1 2) int2bs_mulr_pow2 1:/#.
    rewrite nseq1 cat1s; pose i2bs := int2bs _ (_ %/ _).
    by rewrite (: h' - size bs - 1 = size i2bs) 1:size_int2bs 1:/# bs2intK.
  rewrite (int2bs_cat 1 (h' - size bs)) 1:/# {2}/int2bs mkseq1 /= expr0 divz1.
  rewrite -modzDm modzMr /= expr1 divzDl 1:dvdz_mulr 1:dvdzz.
  rewrite mulrC divMr 1:dvdzz /= rev_cons; pose i2bs := int2bs _ (_ %/ _).
  by rewrite (: h' - size bs - 1 = size i2bs) 1:size_int2bs 1:/# bs2intK.
qed.

(* ==========================================================================
   TRH-BRANCH STATUS / PER-ADMIT RESIDUAL + TRANSPLANT NOTE
   (2026-07-20, T2/TRH-ADMITS session; UPDATE 2026-07-20 TRH-LAST session)

   UPDATE 2026-07-20 (TRH-LAST) -- `lemma seam_branch2_trh` IS NOW 0-ADMIT.
   ------------------------------------------------------------------------
   ec-certify.sh drafts/_branch2_trh_wip.ec
     => compile=OK   admit-tactics=3   axiom-decls=0     (was 4)

   ALL THREE remaining admits are the STALE seam_branch2 COPY (lines 2365-3218
   of this file: :2945, :3203, :3217) -- that lemma has since been carried
   further in drafts/_seam_branch2_wip.ec, so do NOT read this file's copy as
   its current state; it is discarded at integration.  The TRH block below the
   banner at :3438 -- `lemma seam_branch2_trh`, :3446-4998 -- now carries
   ZERO admits, so the WHOLE second `ler_add` summand
     Pr[V(A_ht,FC.O_THFC_Default) : res /\ !valid_WOTSTWES /\ !valid_TCRPKCO
                                        /\ valid_TCRTRH]
       <= Pr[TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(A_ht), ..) : res]
   is derived end to end from the two programs.

   ANTI-VACUITY EVIDENCE for the (iii) closure (each a RUN, not an argument)
     * ABSORPTION: inserting ONE MORE `admit.` immediately before the `qed.` of
       seam_branch2_trh yields `[critical] all goals are closed` -- so (iii)
       closes every goal and absorbs nothing.  (This is the k+1 rung; the k
       rung is the real file's qed, which refuses an incomplete proof.)
     * WRONG INDEX LEMMA: swapping the TRH four-block `ltbignn_i` for the PKCO
       branch's three-block `ltbignrt_i` FAILS -- the (i,j,u,v) index
       arithmetic is genuinely load-bearing, not a rewrite that any bound
       would satisfy.
     * THE `2^h'` PORT DELTA: restoring MM45's literal `0 * (2 ^ h - 1)`
       padding FAILS here -- but the failure is a NAME AMBIGUITY of bare `h`
       (`FSSLXMTWES.h` vs `SPHINCS_PLUS.h`), NOT the unification argument an
       earlier draft of this note gave.  The delta is real; the reason recorded
       at the site is now the measured one.  Whether a disambiguated
       `2 ^ FSSLXMTWES.h - 1` would also work is UNRESOLVED and irrelevant to
       the closure (the factor multiplies 0).
     * Two further failures were hit and fixed during the port (MM45's bare
       `?addr_ge0 ?mulr_ge0` cascade is a silent no-op under our
       no-`import IntOrder` convention, which made its focus indices invalid),
       i.e. the block was never trivially green.

   CLOSED IN THIS SESSION (each gated by a full `easycrypt compile` + the
   admit-tactic count decrementing by one; qed refuses an incomplete proof)
   ---------------------------------------------------------------------
   1. ADMIT-TRH-1a-INNERTREE-LEAF (MM45 :6060-6091 + one +C conjunct).
      CONTROL: swapping the l'-exit characterization `nthsigwlp` for the
      incoming `nthsignt` in the +C conjunct leaves the goal OPEN.
   2. ADMIT-TRH-1a-KEYPAIRLEAF (MM45 :6049-6059 + the +C sigWOTSlp step).
      CONTROL: swapping `nthsigw` for `nthsiglp` in the eq_mkseq_of_nth
      pointwise step leaves the goal OPEN.
   3. ADMIT-TRH-1a-NODESBODY (MM45 :5625-5950) -- the ~326-line nodescl level
      with the four-index-block ts bookkeeping.  PURE MM45 port.
   => TRH PART 1a IS NOW 0-ADMIT AT ALL THREE LEVELS, so the `seq 7 7`
      cube-build post is DERIVED from the programs, not merely adequate.
   4. ADMIT-TRH-1b-rest (i) ROOT REORDERING + (ii) THE SIGNING-LOOP SIMULATION.
      ABSORPTION GATE: with the (iii) admit in place, ONE MORE trailing admit
      yields "[critical] all goals are closed" -- so (iii) absorbs nothing.

   ADMIT-TRH-1b-rest-(iii) -- CLOSED 2026-07-20 (TRH-LAST).  The record below
   is the pre-closure residual note, KEPT because the shape it describes is
   exactly what was built; the "WHAT IS MISSING" / "NOT STARTED" wording is
   HISTORICAL.  How each of (a)/(b)/(c) actually went:
     (a) NO cross-clone `call` hop was needed after all.  The forge call is
         discharged by a plain `call (: true)` -- `Adv_EUFNAGCMA_..._.forge` is
         declared with an EMPTY oracle annotation, so A cannot append to the
         collection oracle across it and no oracle subgoal is emitted (the same
         structural reason the PKCO branch records).  PART 0's hop is only
         needed for `choose`, which DOES take the oracle.
     (b) ported UNCHANGED from MM45 :6172-6210, as predicted; the one +C
         statement on side 1 (`allOkC <- allOkC /\ okC`) is absorbed by `wp`
         because allOkC is not in the loop invariant.
     (c) ported from MM45 :6218-6298 with THREE real deltas, not just renames:
         the `?addr_ge0 ?mulr_ge0` nonnegativity cascade, the `ltbignn_i`
         padding factor, and the conseq conjunct count.  All three are recorded
         at their sites and each is backed by a RUN control (see the UPDATE
         block at the top of this banner).
     STATEMENT NUMBERING (the piece that had to be measured, not guessed):
         side 1 has 19 statements and side 2 has 25 at the frontier; side 1 is
         MM45's V plus ONE (`allOkC <- true` at 7) and side 2 is
         statement-identical to MM45's find tail, so MM45's
         `swap{1} [15..16] 1` / `wp 15 22` became `swap{1} [16..17] 1` /
         `wp 16 22`.
     LOCATION: last tactic of seam_branch2_trh, after the closed `seq 2 2`.
     PENDING GOAL: equiv of the two post-signing-loop tails under
       #pre /\ ={sigl}, i.e.
         LHS  root <- nth (nth rootstd (d-1)) 0; pk <- (root,ps,ad);
              (m',sig',idx') <@ A_ht(FC.O_THFC_Default).forge(pk, sigl);
              is_fresh <- ..; (tidx,kpidx) <- (val idx',0); root' <- m';
              allOkC <- true; the d-step reconstruction loop; the three
              valid_* flags; is_valid
         RHS  root <- nth (nth R.rootstd (d-1)) 0;
              (m',sig',idx') <@ A_ht(R_SMDTTCRCTRH_C(..).O_THFC).forge((root,ps,R.ad), sigl);
              the same reconstruction loop; cidx <- find ..; the trh extraction
              cr <- extract_coll_bt_ap_trh ..; cnode <- val cr.`3 ++ val cr.`4;
              (hidx,bidx) <- cr.`5; fidx <- bigi nr_trees 0 cidx * (2^h'-1)
                                            + tidx * (2^h'-1)
                                            + bigi nr_nodesx 1 hidx + bidx;
              (i,x') <- (fidx,cnode); the four O_SMDTTCR_Default getters
       ==> the byequiv post (res{1} => res{2}).
     WHAT IS MISSING:
       (a) the `call` for A_ht.forge (the two oracle instances differ:
           FC.O_THFC_Default{1} vs R_SMDTTCRCTRH_C(..).O_THFC{2} -- the same
           cross-clone hop already discharged in PART 0, so this is expected to
           be mechanical);
       (b) the d-step reconstruction loop (identical on both sides -- MM45
           :6140-6210 carries over UNCHANGED, because `pick`'s transcript is
           exactly MM45's under grind-in-find);
       (c) the TRH COLLISION EXTRACTION + `fidx` index arithmetic (MM45
           :6211-6298).  This is the genuinely large part and is STRICTLY
           BIGGER than the PKCO branch's still-open (iii): the target is an
           INNER MERKLE NODE, so the extraction runs through
           extract_coll_bt_ap_trh / sub_bt / val_bt_trh_gen and the `fidx`
           arithmetic must match the (i,j,u,v) indexing that PART 1a's
           `tsnth`/`tsdef` fix, instead of the single pkco input index.
       NOTE the SM-DT-TCR-C post carries SIX conjuncts, not four (same delta the
       PKCO branch documents): MM45's conseq states the four interesting ones
       and discharges `dist` (from uqunz1ts) and `disj_lists twsO twsOC` (from
       alltrhts + allntrhtws via hasPn/allP).
     NOT STARTED.

   PREMISES OF seam_branch2_trh (asked for by the integration task)
   ----------------------------------------------------------------
   The lemma carries EXACTLY TWO premises, unchanged by this session:
     P1  hencb      : forall p a x cc, encode_msgWOTS_C p a x cc
                                       = encode_msgWOTS (ThC p a x cc)
     P2  allntrhads : hoare[ A_ht(R_SMDTTCRCTRH_C(..).O_THFC).choose :
                               R_SMDTTCRCTRH_C.O_THFC.ads = []
                               ==> all (fun ad => get_typeidx ad <> trhxtype)
                                       R_SMDTTCRCTRH_C.O_THFC.ads ]
   plus the module restriction on A_ht in the statement header.  NO NEW PREMISE
   was forced by any closure in this session (the whole TRH branch is
   type-disjoint from the WOTS-chain axis, so none of branch 1's dfC
   separations, c <= p_tgts, or embdisj/embinj are needed).
   MACHINE-CHECKED (re-run against the CURRENT file, i.e. AFTER 1b-(i)+(ii) was
   spliced in -- the first run of this check predated that splice and would only
   have covered through PART 2): inserting `clear hencb.` immediately after
   `move=> hencb allntrhads.` still compiles (exit 0), so P1 is NOT consumed by
   ANYTHING closed so far -- PART 0, PART 1/1a (all three levels), PART 2 and
   1b-(i)+(ii).  This matters because (ii) contains `smt()` calls, which pull in
   every context hypothesis, so non-consumption there is a real check and not a
   syntactic one.  P2 IS consumed, silently, by PART 0's
   `conseq (..) _ (: ads = [] ==> all ..) => //` (the `//` closes that goal by
   assumption).  Whether (iii) needs P1 is OPEN; the expectation is that it does
   not, for the same type-disjointness reason.

   UPDATE 2026-07-20 (TRH-LAST) -- P1 IS NOT CONSUMED, (iii) INCLUDED.
   The `clear hencb.` check was re-run against the CURRENT file (i.e. with the
   full (iii) block spliced in): **`easycrypt compile` EXIT 0** on the whole
   file.  (The first attempts at this check reported exit 1 with no diagnostic
   and were nearly mis-read as "P1 is consumed after all"; that was the
   FALSE-RED artifact documented below -- the control lived in
   `drafts/_trhlast/`, which the container could not write, so the run failed
   on the `.eco` write while the PROOF SUCCEEDED.  The directory is now
   chmod 777 and the re-run gives the clean exit 0 quoted here.  Do not weaken
   this to the no-`[critical]` heuristic; the clean rc is the evidence.)
   CONCLUSION: `seam_branch2_trh` still carries EXACTLY TWO premises, P1
   (unused, kept for interface parity with seam_branch2) and P2 (consumed by
   PART 0).  The (iii) closure forced NO new premise -- as expected, since the
   TRH branch is type-disjoint from the WOTS-chain axis.

   TRANSPLANT NOTE (how this block goes back into drafts/_seam_branch2_wip.ec)
   --------------------------------------------------------------------------
   * Everything from the banner at :3438 to the `qed.` of seam_branch2_trh is
     ONE self-contained text block; the material ABOVE that banner in this file
     is a (now stale) copy of seam_branch2 and must NOT be transplanted.
   * seam_branch2_trh MUST BE REORDERED **BEFORE** seam_branch2 in the target
     file.  seam_branch2's ADMIT-3 is the TRH byequiv itself, and it sits INSIDE
     seam_branch2's proof, so it cannot forward-reference a lemma stated later:
     the block has to be pasted ABOVE `lemma seam_branch2`, and ADMIT-3 then
     becomes `by apply (seam_branch2_trh A_ht &m hencb allntrhads).` (modulo the
     premise names in scope there).
   * seam_branch2 already carries `hencb` and an `allnpkcoads`-style premise;
     seam_branch2_trh needs `hencb` (carried but so far unused) and the
     `allntrhads` TYPE-premise, which is a DIFFERENT statement from
     `allnpkcoads` (trhxtype vs pkcotype, and the R_SMDTTCRCTRH_C oracle
     instance).  The combined lemma therefore needs BOTH type-premises in its
     header -- that is the one premise-union item this branch adds.
   * The pure operators/lemmas this block uses (ht_sigc, ht_sigc_at, ht_sigcE,
     ht_root_rcons_*, ht_sigc_rcons_*, eq_mkseq_of_nth, ht_sigcube_transitivity)
     are already in the target file and are reduction-agnostic; nothing in the
     block redefines them.

   METHOD HAZARD FOUND IN THE TRH-LAST SESSION -- THE **FALSE RED**
   ----------------------------------------------------------------
   The documented hazards are all about false GREENs.  This is the mirror
   image, and it cost this session several runs.  The ec-grind container runs
   as uid 1001; `drafts/` is mode 777 so it can write there, but a NEW private
   scratch subdir created from the host (`drafts/_trhlast/`, mode 775 owned by
   the host user) is NOT writable by it.  EasyCrypt then TYPE-CHECKS THE WHOLE
   FILE SUCCESSFULLY, fails only when it goes to write the `.eco`, and exits 1
   **with no diagnostic whatsoever** -- progress reaches 100%, stdout/stderr
   contain no `[critical]`, no `error`, nothing.  Read naively that is an
   apparent proof failure, and it will make you "fix" a proof that was already
   correct.
   DISCRIMINATOR: `rc=1` WITHOUT a `[critical] ...` line means the FILE
   COMPILED and the .eco write failed; `rc=1` WITH one is a real failure.
   FIX: `chmod 777` the scratch subdir before using it (done for
   `drafts/_trhlast/`).  Second-order trap that hid this: `bash
   scratch-ecc.sh F | tail -n` makes `$?` the exit status of `tail`, i.e.
   ALWAYS 0 -- capture the rc with a redirect, not a pipe.  (`ec-certify.sh`
   gets this right; it is the reliable gate.)

   PORT DELTAS FOUND THIS SESSION (add to the cumulative list)
   ----------------------------------------------------------
   * `sumr_ge0` is NOT in BIA: it is `StdBigop.Bigint.sumr_ge0` (like `sumzE`
     and `big_constz`), NOT `StdBigop.Bigint.BIA.sumr_ge0`.
   * MM45 :6072's `congr => [/#|]` is a hard error here ("not the right number
     of intro-patterns (got 2, expecting 1)"): after `/>` substitutes
     ad{1} := adz the two address arguments are syntactically identical, so
     `congr` leaves ONE goal.
   * METHOD (sharper than the existing warning): `easycrypt cli` prints NOTHING
     AT ALL on a failed tactic -- no message, no marker; it silently leaves the
     goal unchanged and continues.  A probe transcript is therefore only
     readable through (a) the identity of the final pending goal and (b) the
     "Current goal (remaining: N)" count.  Grepping a cli transcript for
     "error|cannot|unknown" is worthless; the batch `easycrypt compile` (which
     DOES print `[critical] ..`) is the only tactic-level gate.
   ========================================================================== *)
