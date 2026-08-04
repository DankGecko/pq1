(* ==========================================================================
   WOTS_C_Scheme.ec  --  The WOTS+C scheme (keygen / sign / verify) as a REAL
                         module reusing the FV-SPHINCSPLUS-EC chain machinery.

   FOURTH-INCREMENT ARTIFACT.  These are DEFINITIONS (zero admits): the WOTS+C
   scheme differs from WOTS-TW (WOTS_TW_ES_NPRF, WOTS_TW_ES.ec:2176) in exactly
   two faithful ways (paper SPHINCS+C Sec 3.3 / Alg 3-4):

     (1) the message encoding is `encode_msgWOTS_C ps ad m counter`
         (= base_w of Th+C(P,adrs,m,counter)) instead of `encode_msgWOTS m`;
         the counter is grinded (proved total `grindC`) to make the encoding
         constant-sum, REPLACING WOTS-TW's checksum chains;
     (2) the signature carries the counter: `sig : sigWOTS * cntr`, and `verify`
         recomputes the encoding from (m, counter) and checks BOTH the public-key
         match AND the +C predicate on the recomputed digest (so a forgery can
         neither swap the counter freely nor evade the constant-sum gate).

   The chain walk itself (`cf` / `set_chidx` / `BaseW.val`) is reused VERBATIM
   from the repo — WOTS+C touches only the encoding, which is the whole point of
   the reduction (the 6314-line WOTS-TW proof is never reopened).
   ========================================================================== *)

require import AllCore List Distr.
require import SPHINCS_PLUS.
require WOTS_C_Real.

import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import EmsgWOTS.   (* bring the emsgWOTS `.[]` word-indexing operator into scope *)

module WOTS_C_ES = {
  (* keygen is identical to WOTS-TW (the +C change is only in the encoding). *)
  proc keygen(ps : pseed, ad : adrs) : pkWOTSTW * (skWOTS * pseed * adrs) = {
    var r : pkWOTSTW * (skWOTS * pseed * adrs);
    r <@ WOTS_TW_ES_NPRF.keygen(ps, ad);
    return r;
  }

  (* Sign: grind the counter, encode via Th+C, chain-walk, append the counter. *)
  proc sign(sk : skWOTS * pseed * adrs, m : dgstblock) : sigWOTS * cntr = {
    var ps : pseed;
    var ad : adrs;
    var skWOTS : skWOTS;
    var em : EmsgWOTS.emsgWOTS;
    var sig : dgstblock list;
    var em_ele : int;
    var sk_ele : dgstblock;
    var sig_ele : dgstblock;
    var counter : cntr;

    skWOTS <- sk.`1;
    ps <- sk.`2;
    ad <- sk.`3;

    counter <- grindC ps ad m;                    (* proved total grind *)
    em <- encode_msgWOTS_C ps ad m counter;        (* base_w(Th+C(P,ad,m,counter)) *)

    sig <- [];
    while (size sig < len) {
      sk_ele <- nth witness (DBLL.val skWOTS) (size sig);
      em_ele <- BaseW.val em.[size sig];
      sig_ele <- cf ps (set_chidx ad (size sig)) 0 em_ele (DigestBlock.val sk_ele);
      sig <- rcons sig sig_ele;
    }

    return (DBLL.insubd sig, counter);
  }

  (* Verify: recompute the encoding from (m, counter), rebuild the pk, and
     require BOTH pk-match AND the +C constant-sum gate on the recomputed digest. *)
  proc verify(pk : pkWOTSTW, m : dgstblock, sigc : sigWOTS * cntr) : bool = {
    var ps : pseed;
    var ad : adrs;
    var pkWOTS, pkWOTS' : pkWOTS;
    var sig : sigWOTS;
    var counter : cntr;
    var em : EmsgWOTS.emsgWOTS;
    var pkWOTS_l : dgstblock list;
    var em_ele : int;
    var sig_ele : dgstblock;
    var pkWOTS_ele : dgstblock;
    var okC : bool;

    pkWOTS  <- pk.`1;
    ps      <- pk.`2;
    ad      <- pk.`3;
    sig     <- sigc.`1;
    counter <- sigc.`2;

    em <- encode_msgWOTS_C ps ad m counter;

    pkWOTS_l <- [];
    while (size pkWOTS_l < len) {
      sig_ele <- nth witness (DBLL.val sig) (size pkWOTS_l);
      em_ele <- BaseW.val em.[size pkWOTS_l];
      pkWOTS_ele <- cf ps (set_chidx ad (size pkWOTS_l)) em_ele (w - 1 - em_ele) (DigestBlock.val sig_ele);
      pkWOTS_l <- rcons pkWOTS_l pkWOTS_ele;
    }

    okC <- predC (ThC ps ad m counter);             (* +C gate (constant-sum) *)

    return DBLL.insubd pkWOTS_l = pkWOTS /\ okC;
  }
}.

(* A PROVED property of the WOTS+C scheme (zero admits): every honestly-produced
   signature carries a counter whose digest satisfies the +C predicate — i.e. a
   WOTS+C signature always passes its own constant-sum gate.  This threads the
   discharged grinding (wotsc_grind_targets_predC / grind_correct) through the
   scheme's `sign`, and is a prerequisite fact for the Alg-9/Alg-10 reductions
   (they rely on the signer's counter being Prop-satisfying). *)
lemma sign_counter_predC (skW : skWOTS) (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock) :
  (exists c, predC (ThC ps0 ad0 m0 c)) =>
  hoare[WOTS_C_ES.sign :
          sk = (skW, ps0, ad0) /\ m = m0 ==> predC (ThC ps0 ad0 m0 res.`2)].
proof.
  move=> hex; proc.
  while (predC (ThC ps0 ad0 m0 counter)).
  + by auto.
  auto => />; rewrite /grindC.
  exact: (wotsc_grind_targets_predC ps0 ad0 m0 hex).
qed.

(* ==========================================================================
   The WOTS+C d-EU-naCMA game `M_EUF_GCMA_WOTSC_NPRF` — the LHS of Thm D.1.
   Mirrors M_EUF_GCMA_WOTSTWESNPRF (WOTS_TW_ES.ec:2323) with the signature type
   `sigWOTS * cntr` and verify/sign routed through WOTS_C_ES.  Pure definitions
   (zero admits); the collection oracle OC is the REAL `FC.Oracle_THFC`.
   ========================================================================== *)

module type Oracle_MEUFGCMA_WOTSC = {
  proc init(ps_init : pseed) : unit
  proc query(wad : wadrs, m : dgstblock) : pkWOTS * (sigWOTS * cntr)
  proc get(i : int) : adrs * dgstblock * pkWOTS * (sigWOTS * cntr)
  proc get_addresses() : adrs list
  proc nr_queries() : int
  proc dist_addresses() : bool
}.

module type Adv_MEUFGCMA_WOTSC(O : Oracle_MEUFGCMA_WOTSC, OC : FC.Oracle_THFC) = {
  proc choose() : unit { O.query, OC.query }
  proc forge(ps : pseed) : int * dgstblock * (sigWOTS * cntr) {}
}.

module O_MEUFGCMA_WOTSC_Default : Oracle_MEUFGCMA_WOTSC = {
  var ps : pseed
  var qs : (adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) list

  proc init(ps_init : pseed) : unit = {
    ps <- ps_init;
    qs <- [];
  }

  proc query(wad : wadrs, m : dgstblock) : pkWOTS * (sigWOTS * cntr) = {
    var pk : pkWOTSTW;
    var sk : skWOTS * pseed * adrs;
    var sigc : sigWOTS * cntr;

    (pk, sk) <@ WOTS_C_ES.keygen(ps, WAddress.val wad);
    sigc <@ WOTS_C_ES.sign(sk, m);
    qs <- rcons qs (WAddress.val wad, m, pk.`1, sigc);
    return (pk.`1, sigc);
  }

  proc get(i : int) : adrs * dgstblock * pkWOTS * (sigWOTS * cntr) = {
    return nth witness qs i;
  }

  proc get_addresses() : adrs list = {
    return map (fun (q : adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) => q.`1) qs;
  }

  proc nr_queries() : int = {
    return size qs;
  }

  proc dist_addresses() : bool = {
    return uniq_wgpidxs (map (fun (q : adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) => q.`1) qs);
  }
}.

module M_EUF_GCMA_WOTSC_NPRF(A : Adv_MEUFGCMA_WOTSC, O : Oracle_MEUFGCMA_WOTSC, OC : FC.Oracle_THFC) = {
  module A = A(O, OC)

  proc main() : bool = {
    var ps : pseed;
    var ad : adrs;
    var pkWOTS : pkWOTS;
    var i : int;
    var m, m' : dgstblock;
    var sigc, sigc' : sigWOTS * cntr;
    var adlO, adlOC : adrs list;
    var nrqs : int;
    var is_valid, is_fresh, dist_wgpidxs : bool;

    ps <$ dpseed;
    O.init(ps);
    OC.init(ps);

    A.choose();
    (i, m', sigc') <@ A.forge(ps);

    (ad, m, pkWOTS, sigc) <@ O.get(i);

    is_valid <@ WOTS_C_ES.verify((pkWOTS, ps, ad), m', sigc');
    is_fresh <- m' <> m;

    nrqs <@ O.nr_queries();
    dist_wgpidxs <@ O.dist_addresses();
    adlO <@ O.get_addresses();
    adlOC <@ OC.get_tweaks();

    return 0 <= nrqs <= c /\ 0 <= i < nrqs /\
           is_valid /\ is_fresh /\ dist_wgpidxs /\ disj_wgpidxs adlO adlOC;
  }
}.

(* Losslessness of the WOTS+C scheme procs + signing oracle (zero admits) —
   standard reduction prerequisites (the reductions run these procs and need
   them terminating).  The chain walks are bounded by `len`; keygen's only
   sampling is `dskWOTS` (lossless, dskWOTS_ll). *)
lemma pkfs_ll : islossless WOTS_TW_ES_NPRF.pkWOTS_from_skWOTS.
proof. by islossless; while true (len - size pkWOTS); auto; smt(size_rcons). qed.

lemma keygenR_ll : islossless WOTS_TW_ES_NPRF.keygen.
proof. by proc; call pkfs_ll; auto; smt(dskWOTS_ll). qed.

lemma WOTS_C_ES_keygen_ll : islossless WOTS_C_ES.keygen.
proof. by proc; call keygenR_ll; auto. qed.

lemma WOTS_C_ES_sign_ll : islossless WOTS_C_ES.sign.
proof. by islossless; while true (len - size sig); auto; smt(size_rcons). qed.

lemma O_MEUFGCMA_WOTSC_query_ll : islossless O_MEUFGCMA_WOTSC_Default.query.
proof. by proc; wp; call WOTS_C_ES_sign_ll; call WOTS_C_ES_keygen_ll; auto. qed.
