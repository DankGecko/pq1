(* ==========================================================================
   WOTS_C_Bridge.ec  --  The FC <-> STCRC_WC.Col / MM45 bridge.

   Connects Thm D.1's LOCAL multi-instance WOTS-TW term
     `M_EUF_NACMA_WOTSTW_L(R_multi_WOTSTW(A), STCRC_WC.Col.O_THFC_Default)`
   (WOTS_C_Multi.ec, the disjointness-FREE d-EU-naCMA game over the S-TCR(+C)
   collection `STCRC_WC.Col`) to MM45's ACTUAL multi-instance WOTS-TW security
   theorem
     `M_EUF_GCMA_WOTSTWESNPRF(., O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default)`
   (WOTS_TW_ES.ec:2323, adaptive M-EUF-GCMA over the chain-hash collection `FC`,
   the black box discharged by `MEUFGCMA_WOTSTWESNPRF` at WOTS_TW_ES.ec:6269).

   This is the FC <-> STCRC_WC.Col unification deferred already in C.2
   (WOTS_C_Reduction.ec ~line 340: "unifying this with the repo's FC (one
   Th_lambda over both the chain hash f and Th+C) is the remaining structural
   reconciliation") and again in D.1 (WOTS_C_Multi.ec: the labelled bridge debt).

   --------------------------------------------------------------------------
   THE PRECISE GAP (three coupled differences, one root cause).

   Let FC be the repo collection (WOTS_TW_ES.ec:450):
       diff_t = int,  in_t = dgst,  fc = thfc  ( thfc : int -> pseed -> adrs
       -> dgst -> dgstblock ),  and the chain hash f = thfc (8*n).  Its comment
       (WOTS_TW_ES.ec:427) says FC "contains ALL tweakable hash functions used
       in WOTS-TW, XMSS, and SPHINCS+" -- i.e. FC is the UNIFIED Th_lambda.
   Let STCRC_WC.Col be the S-TCR(+C) collection (STCR_C.ec:96):
       diff_t = unit,  in_t = msgWOTS * cntr,
       fc = (fun _ pp tw (x : msgWOTS*cntr) => ThC pp tw x.`1 x.`2)   ( = Th+C ).

   (G1) COLLECTION.  MM45's family oracle OC is `FC.Oracle_THFC` (chain-hash
        thfc over `dgst` inputs).  D.1's local OC is `STCRC_WC.Col.Oracle_THFC`
        (Th+C over `msgWOTS*cntr` inputs).  Different clones, different input
        types, different functions.  The unification claim is exactly that Th+C
        is ONE MORE member of the thfc family (FC.in_collection only gives the
        chain hash f = thfc(8*n); Th+C being a member is a SEPARATE modelling
        fact, not derivable from the existing axioms).

   (G2) O/OC SEPARATION + DISJOINTNESS.  MM45 signs through a SEPARATE oracle O
        and REQUIRES `disj_wgpidxs adlO adlOC` (signing addresses disjoint from
        family-oracle tweaks).  D.1's local game has NO O oracle (it signs
        in-game via WOTS_TW_ES_NPRF.keygen/sign) and -- crucially -- is
        disjointness-FREE: the SOUNDNESS-FIX note in WOTS_C_Multi.ec records
        that the composed reduction `R_multi_WOTSTW` grinds via OC at the SAME
        instance addresses `WAddress.val wad` it signs at (pp is naCMA-hidden),
        so in the SINGLE-collection local world `adlO subset adlOC` and the MM45
        disjointness conjunct is identically FALSE.  That is WHY the conjunct
        had to be dropped locally -- and is the OBSTRUCTION a naive
        same-collection map to MM45 hits.

   (G3) ADAPTIVITY.  MM45 is adaptive M-EUF-GCMA (A calls O.query during
        choose()).  D.1 is non-adaptive d-EU-naCMA (A commits a `qC list` in
        choose(), receives all keypairs+sigs at forge()).  Bridgeable: commit
        upfront, then replay committed queries into O.

   ROOT CAUSE.  G1 and G2 are the SAME fact viewed twice.  In the real SPHINCS+
   address scheme the chain hash f and the message-compression Th+C are
   computed at DIFFERENT SPHINCS+ address TYPES; therefore the grind's Th+C
   tweaks and the chain-hash SIGNING tweaks have DISJOINT wgpidx prefixes.
   Splitting the single local collection STCRC_WC.Col back onto FC (via the
   embedding below) simultaneously (a) realises Th+C inside thfc [closes G1] and
   (b) sends the grind tweaks to a wgpidx-disjoint address range so MM45's
   `disj_wgpidxs adlO adlOC` HOLDS [closes G2].

   --------------------------------------------------------------------------
   WHY THE DIRECTION IS SOUND (the trap, avoided).

   `M_EUF_NACMA_WOTSTW_L` is disjointness-FREE, hence has the LARGER winning
   set: for a FIXED arbitrary adversary B,
       Pr[M_EUF_NACMA_WOTSTW_L(B)] >= Pr[MEUFGCMA_WOTSTWESNPRF(B-analog)],
   so a standalone `Pr[..._L(B)] <= Pr[MEUFGCMA_..]` is FALSE (wrong direction).
   We therefore do NOT state a generic-adversary bound.  We state it for the
   COMPOSED adversary `R_multi_WOTSTW(A)` and route its honest grind through
   MM45's O/OC SEPARATION: the reduction `R_bridge_WOTSTW(A)` (below)
     * replays the committed signing queries through MM45's SIGNING oracle O
       (so `adlO` = the instance addresses), and
     * forwards the WOTS+C forger's grind Th+C-queries to MM45's FAMILY oracle
       OC AT THE EMBEDDED (message-compression) ADDRESSES `emb_tw wad`,
   so OC stays grind-only and, by `emb_disj_wgpidxs` below, `adlO` is disjoint
   from `adlOC`.  Every local win maps to an MM45 win; hence the SOUND
   direction  Pr[local(R_multi_WOTSTW(A))] <= Pr[MM45(R_bridge(A))].
   This is "the composed adversary carrying the source game's disj constraint,
   via MM45's O/OC separation" -- both routes the coordinator sanctioned, taken
   together.

   --------------------------------------------------------------------------
   HONESTY / NON-VACUITY.

   * The embedding `emb_tw`, `emb_in` are ABSTRACT ops (declared, undefined).
     Their required properties are the TWO lemma HYPOTHESES `emb_thfc_ThC` and
     `emb_disj_wgpidxs` below -- NOT easycrypt `axiom`s.  They are the explicit,
     reviewable modelling facts (Th+C is a thfc member; message-compression
     addresses are wgpidx-disjoint from chain addresses) that make the paper's
     proof work.  They are SATISFIABLE by the real SPHINCS+ scheme (Th+C is a
     genuine member of the thfc family at its own input length; the SPHINCS+
     address type field separates message-compression from chain addresses), so
     the bridge is a genuine CONDITIONAL theorem, not vacuous via a false
     premise.  Discharging them for the concrete encoding is flagged residual
     work (see FLAG-1 / FLAG-2).

   * Non-vacuity of the RHS: `Pr[M_EUF_GCMA_WOTSTWESNPRF(R_bridge_WOTSTW(A),..)]`
     is NOT identically 0 -- R_bridge forwards A's forgery and, under
     `emb_disj_wgpidxs`, the disjointness conjunct holds, so any A that wins the
     local game yields an MM45 win.  (Checked below in the header of the lemma.)

   * The probability step is a `byequiv` reducing to a per-oracle game
     equivalence, PROVED IN FULL (2026-07-08) — ZERO admits — as a five-block
     ladder:
       - Block A: ps-sampling + the four oracle inits.
       - Block 1a (the hard leg, PROVED): emb-map oracle coupling of A0.choose +
         the two-sided grind while-loop.  Its conceptual core is the per-query
         lemma `qeq`: `Col.O_THFC.query ~ OC_emb.query` returns the SAME digest by
         `emb_thfc_ThC` (thfc at `emb_tw` addr on `emb_in` input = Th+C) and grows
         FC.tws by the `emb_tw`-image (FC.tws = map emb_tw Col.tws).  A0.choose is
         coupled by `call (: pp/tws invariant)` discharged by qeq; the nested
         grind loops couple step-for-step via qeq (same committed `qres`/`sds`).
       - Block 1b (PROVED): committed-signing coupling (LHS keygen/sign loop ~ RHS
         replay through MM45's O; keygen randomness shared via `sim`).
       - Block 1c (PROVED): forge relay (oracle-free A0.forge on identical wcks
         via `call (: true)`, relay at the coupled `R_multi.qs`).
       - Block E (PROVED): the ENTIRE success-bit entailment `res{1} => res{2}`,
         including MM45's extra `disj_wgpidxs adlO adlOC` conjunct discharged LIVE
         through the real `emb_disj_wgpidxs_lists` (adlO all valid_wadrs via
         `all_valid_map_val`, adlOC = the emb_tw-images of the grind tweaks) and
         the verify/freshness/count coupling both in-range and out-of-range.
     The bridge is now a fully-compiled CONDITIONAL theorem: it holds outright
     under the two flagged embedding hypotheses (`emb_thfc_ThC`, `emb_disj_wgpidxs`)
     — no `admit`, no `sorry`, no `axiom`.  A soundness note: an earlier draft of
     the invariant carried a FALSE conjunct `R_multi.qs = qs` (the game's local
     `qs` is the grind OUTPUT `qres`, distinct from A0's committed list
     `R_multi.qs`); it was masked only while block 1a was an `admit`.  The honest
     proof closes with the TRUE `={R_multi.qs}` and refuses the false one — the
     kernel's anti-vacuity guarantee in action.
   ========================================================================== *)

require import AllCore List Distr.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Reduction WOTS_C_Multi.

import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import WOTS_C_Reduction.
import WOTS_C_Multi.

(* ==========================================================================
   The SPHINCS+ address / input embedding realising Th+C inside FC's thfc.

   emb_tw : the SPHINCS+ message-compression address for a WOTS instance
            address `wad` (a DISTINCT address type from the chain walk).
   emb_in : the `dgst` that Th+C compresses for a (message, counter) pair.
   Abstract here; concretely instantiated by the SPHINCS+ address scheme +
   the Th+C input serialisation.  See FLAG-1 / FLAG-2 for the discharge.

   NOTE (2026-07-08): `emb_tw`, `emb_in` are now DECLARED UPSTREAM in
   WOTS_C_Real.ec, where `ThC` is DEFINED as `thfc` at `emb_tw`/`emb_in`.
   This discharges FLAG-1 (`emb_thfc_ThC`) definitionally — see
   WOTS_C_EmbDischarge.ec.  FLAG-2 (`emb_disj_wgpidxs`) stays a hypothesis
   (blocked at this abstract-address layer; see WOTS_C_EmbDischarge.ec header).
   The bridge lemmas below are UNCHANGED — they still take both predicates as
   explicit premises, so this file's 0-admit proof is preserved verbatim.
   ========================================================================== *)

(* ==========================================================================
   FLAG-1  (emb_thfc_ThC):  Th+C is a member of the FC thfc family, realised at
   the embedded address `emb_tw tw` and embedded input `emb_in x`.
   Reviewable modelling fact; NOT an easycrypt axiom -- a hypothesis of the
   bridge lemma.  Discharge = show the concrete Th+C serialisation is thfc at
   input length `size (emb_in x)`.
   ========================================================================== *)
pred emb_thfc_ThC =
  forall (ps : pseed) (tw : adrs) (x : msgWOTS * cntr),
    thfc (size (emb_in x)) ps (emb_tw tw) (emb_in x) = ThC ps tw x.`1 x.`2.

(* ==========================================================================
   FLAG-2  (emb_disj_wgpidxs):  NO valid WOTS-TW (chain-hash signing) address
   shares a wgpidx global part with ANY message-compression image `emb_tw b`.
   This is the SPHINCS+ address-TYPE separation; it is what makes MM45's
   `disj_wgpidxs adlO adlOC` hold even though the LOCAL single-collection game
   had adlO subset adlOC.  Reviewable modelling fact; a hypothesis, NOT an axiom.

   POINTWISE + GUARDED form (deliberate).  The naive `forall adl, disj_wgpidxs
   adl (map emb_tw adl)` is UNCONDITIONALLY FALSE: taking `adl = [a; emb_tw a]`
   puts `emb_tw a` in BOTH lists, so `get_wgpidxs (emb_tw a)` self-collides and
   `disj_wgpidxs = false` for EVERY `emb_tw` -- a false premise that would make
   the bridge vacuously true (caught in review).  Guarding by `valid_wadrs a`
   (so `adl` holds only genuine signing addresses, never emb-images) and
   separating `emb_tw`'s CODOMAIN from `valid_wadrs` at the `get_wgpidxs` level
   is SATISFIABLE: the SPHINCS+ address TYPE field forces the global parts of a
   valid WOTS chain address and a message-compression image to differ, and
   `thfc`/`ThC`/`emb_tw` are unconstrained abstract ops (so a consistent model
   realising both this and `emb_thfc_ThC` exists).  Discharge = read the concrete
   SPHINCS+ address encoding's type field (FLAG-2 residual).
   ========================================================================== *)
pred emb_disj_wgpidxs =
  forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b).

(* FLAG-2 IS NOW A THEOREM, not a hypothesis (rebase 2026-07-09).  `emb_tw` is
   concrete and the stack sits on the concrete `FSSLXMTWES.WTWES`, so the
   pointwise fact proven in WOTS_C_Real.ec discharges the predicate outright. *)
lemma emb_disj_wgpidxs_holds : emb_disj_wgpidxs.
proof. by rewrite /emb_disj_wgpidxs => a b va; exact: emb_disj_concrete. qed.

(* From the pointwise/guarded fact, the list-level disjointness MM45 needs, for
   any list `adl` of valid signing addresses and ANY grind-address list `adl'`.
   REAL lemma (zero admit) -- also the concrete non-vacuity witness that the
   fixed `emb_disj_wgpidxs` is USABLE, not just non-false. *)
lemma emb_disj_wgpidxs_lists (adl adl' : adrs list) :
  emb_disj_wgpidxs => all valid_wadrs adl =>
  disj_wgpidxs adl (map emb_tw adl').
proof.
  move=> + hv; rewrite /emb_disj_wgpidxs /disj_wgpidxs => h.
  rewrite hasPn => x /mapP [a [ha ->]].
  have va : valid_wadrs a by move: hv => /allP; apply.
  rewrite -map_comp mapP negb_exists => b /=.
  by rewrite /(\o) negb_and; right; exact: (h a b va).
qed.

(* Every address of the form `WAddress.val wad` (an image of the wadrs subtype)
   is a valid WOTS-TW signing address.  Used to discharge the `all valid_wadrs`
   premise of `emb_disj_wgpidxs_lists` for the RHS signing-address list adlO
   (which O_MEUFGCMA records as exactly `val wad` per committed query).
   REAL lemma (zero admit). *)
lemma all_valid_map_val (qs : qC list) :
  all valid_wadrs (map (fun (q : qC) => WAddress.val q.`1) qs).
proof.
  by rewrite allP => x /mapP [q [_ ->]] /=; exact: WAddress.valP.
qed.

(* MM45's signing oracle O records, per committed query k, the 4-tuple
   `(val wad_k, m_k, pk_k, sig_k)` with `(pk_k, sig_k) = ks_k`.  Hence the
   address projection of O's query list equals the local honest-signing address
   list `adlO = map (val . `1) qs`.  Packaged so the Block-E tail entailment
   (dist_wgpidxs and disj_wgpidxs coupling) is a one-liner.  Zero admit. *)
lemma oqs_adlO_eq (qs : qC list) (ks : (pkWOTS * sigWOTS) list)
                  (oqs : (adrs * msgWOTS * pkWOTS * sigWOTS) list) :
  size oqs = size qs =>
  (forall (j : int), 0 <= j < size qs =>
     nth witness oqs j
     = (WAddress.val (nth witness qs j).`1, (nth witness qs j).`2,
        (nth witness ks j).`1, (nth witness ks j).`2)) =>
  map (fun (e : adrs * msgWOTS * pkWOTS * sigWOTS) => e.`1) oqs
  = map (fun (q : qC) => WAddress.val q.`1) qs.
proof.
  move=> hsz hnth; apply (eq_from_nth witness); 1: by rewrite !size_map hsz.
  rewrite size_map => j hj.
  have hjq : 0 <= j < size qs by rewrite -hsz.
  by rewrite (nth_map witness) //= (nth_map witness) //= hnth.
qed.

(* ==========================================================================
   R_bridge_WOTSTW(A) : the FC/MM45 reduction adversary.

   Re-hosts the composed local WOTS-TW naCMA adversary `R_multi_WOTSTW(A)`
   (an Adv_MnaCMA_WOTSTW over STCRC_WC.Col) as an Adv_MEUFGCMA_WOTSTWESNPRF
   over MM45's (O, FC.OC):
     * `OC_emb` presents an STCRC_WC.Col.Oracle_THFC to R_multi_WOTSTW(A),
       forwarding each Th+C grind-query (tw, x) to MM45's FAMILY oracle OC at
       the message-compression address `emb_tw tw` on input `emb_in x`
       (so OC records `emb_tw tw` -- grind-only, wgpidx-disjoint from signing);
     * choose() commits R_multi_WOTSTW(A)'s query list, then replays each
       committed (wad, m) through MM45's SIGNING oracle O (so O records the
       instance addresses = adlO);
     * forge() relays R_multi_WOTSTW(A)'s forgery unchanged.

   Concrete, zero-`admit` MODULE (the admit is only in the probability lemma).
   ========================================================================== *)
module (R_bridge_WOTSTW (A : Adv_MnaCMA_WOTSC) : Adv_MEUFGCMA_WOTSTWESNPRF)
       (O : Oracle_MEUFGCMA_WOTSTWESNPRF, OC : FC.Oracle_THFC) = {
  (* Wrapper collection oracle: Th+C queries -> FC thfc at the embedded addrs. *)
  module OC_emb : STCRC_WC.Col.Oracle_THFC = {
    var tws : adrs list

    proc init(pp_init : pseed) : unit = {
      tws <- [];
    }

    proc query(tw : adrs, x : msgWOTS * cntr) : dgstblock = {
      var y : dgstblock;

      y <@ OC.query(emb_tw tw, emb_in x);   (* records `emb_tw tw` in OC *)
      tws <- rcons tws tw;

      return y;
    }

    proc get_tweaks() : adrs list = {
      return tws;
    }
  }

  module AA = R_multi_WOTSTW(A, OC_emb)

  var qs : qC list
  var ks : (pkWOTS * sigWOTS) list

  proc choose() : unit = {
    var wad : wadrs;
    var m : msgWOTS;
    var pksig : pkWOTS * sigWOTS;
    var k : int;

    OC_emb.init(witness);
    qs <@ AA.choose();

    (* Replay the committed queries through MM45's SIGNING oracle O. *)
    ks <- []; k <- 0;
    while (k < size qs) {
      wad <- (nth witness qs k).`1;
      m   <- (nth witness qs k).`2;
      pksig <@ O.query(wad, m);
      ks <- rcons ks pksig;
      k <- k + 1;
    }
  }

  proc forge(ps : pseed) : int * msgWOTS * sigWOTS = {
    var r : int * msgWOTS * sigWOTS;

    r <@ AA.forge(ps, ks);
    return r;
  }
}.

(* ==========================================================================
   THE BRIDGE LEMMA (faithful, sound direction, PROVED — zero admit).

   For the WOTS+C forger A, the composed LOCAL WOTS-TW naCMA advantage is
   bounded by MM45's ACTUAL M-EUF-GCMA-WOTS-TW advantage of `R_bridge_WOTSTW(A)`,
   UNDER the two flagged embedding hypotheses (Th+C is a thfc member; the
   message-compression addresses are wgpidx-disjoint from signing addresses).

   Direction sound (see header): the bound is on the COMPOSED adversary, routed
   through MM45's O/OC separation so the disjointness the RHS requires is
   established by `emb_disj_wgpidxs`, NOT assumed away on the disjointness-free
   LHS.

   NON-VACUITY (checked, twice).
   (a) The PREMISE `emb_disj_wgpidxs` is SATISFIABLE (not a false premise): it is
       the guarded pointwise form (see FLAG-2), realisable by the SPHINCS+
       address type-field separation; `emb_disj_wgpidxs_lists` above is a REAL
       proof that it delivers the list-level disjointness -- so the hypothesis
       is usable, not vacuous.
   (b) The RHS is not identically 0.  `M_EUF_GCMA_WOTSTWESNPRF`'s success bit is
         0 <= nrqs <= c /\ 0 <= i < nrqs /\ is_valid /\ is_fresh
         /\ dist_wgpidxs /\ disj_wgpidxs adlO adlOC,
       and by `emb_disj_wgpidxs_lists` (adlO = the valid instance signing
       addresses, adlOC = map emb_tw (grind addrs)) the last conjunct is NOT
       identically false; R_bridge forwards A's forgery unchanged, so a local win
       (valid+fresh+distinct) becomes an MM45 win.

   PROOF STATUS (2026-07-08): PROVED IN FULL — ZERO admits.  The probability step
   is a `byequiv` ladder of five PROVED blocks: reduction to `res{1} => res{2}`;
   Block A (ps + 4 oracle inits); 1a (the hard emb_thfc_ThC oracle-embedding
   coupling of A0.choose + the two-sided grind loop, via the per-query lemma
   `qeq`); 1b (committed-signing coupling via MM45's O, keygen randomness shared
   by `sim`); 1c (forge relay via `call (: true)`); and Block E (the full
   success-bit entailment — verify/freshness/count coupling in- and out-of-range,
   MM45's `disj_wgpidxs adlO adlOC` discharged LIVE via `emb_disj_wgpidxs_lists` +
   `all_valid_map_val`).  No `admit`, `sorry`, or `axiom`; the reduction module
   stays concrete/admit-free.  The whole leg is now a compiled conditional theorem
   under the two flagged embedding hypotheses.
   ========================================================================== *)
lemma D1_bridge_WOTSTW
  (A <: Adv_MnaCMA_WOTSC{-R_multi_WOTSTW, -R_bridge_WOTSTW, -G0_MULTI,
                         -STCRC_WC.O_STCRC_Default, -STCRC_WC.Col.O_THFC_Default,
                         -O_MEUFGCMA_WOTSTWESNPRF, -FC.O_THFC_Default}) &m :
    emb_thfc_ThC =>
    emb_disj_wgpidxs =>
    Pr[M_EUF_NACMA_WOTSTW_L(R_multi_WOTSTW(A),
                            STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
  <= Pr[M_EUF_GCMA_WOTSTWESNPRF(R_bridge_WOTSTW(A),
                                O_MEUFGCMA_WOTSTWESNPRF,
                                FC.O_THFC_Default).main() @ &m : res].
proof.
  move=> emb_eval emb_disj.
  byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
  proc.
  (* Expand R_bridge and, on both sides, the inner R_multi_WOTSTW (grind+forge). *)
  inline{2} R_bridge_WOTSTW(A, O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).choose.
  inline{2} R_bridge_WOTSTW(A, O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).forge.
  inline{1} R_multi_WOTSTW(A, STCRC_WC.Col.O_THFC_Default).choose.
  inline{1} R_multi_WOTSTW(A, STCRC_WC.Col.O_THFC_Default).forge.
  inline{2} R_multi_WOTSTW(A,
              R_bridge_WOTSTW(A, O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).OC_emb).choose.
  inline{2} R_multi_WOTSTW(A,
              R_bridge_WOTSTW(A, O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).OC_emb).forge.
  (* --------------------------------------------------------------------------
     Block A (PROVEN):  ps sampling + the four oracle inits.  Establishes the
     public seed / empty-list base state on both collections and MM45's signing
     oracle O. *)
  seq 2 4 : (={glob A, ps}
             /\ STCRC_WC.Col.O_THFC_Default.pp{1} = ps{1}
             /\ STCRC_WC.Col.O_THFC_Default.tws{1} = []
             /\ FC.O_THFC_Default.pp{2} = ps{2}
             /\ FC.O_THFC_Default.tws{2} = []
             /\ O_MEUFGCMA_WOTSTWESNPRF.qs{2} = []
             /\ O_MEUFGCMA_WOTSTWESNPRF.ps{2} = ps{2}).
  + inline{1} STCRC_WC.Col.O_THFC_Default.init.
    inline{2} O_MEUFGCMA_WOTSTWESNPRF.init.
    inline{2} FC.O_THFC_Default.init.
    inline{2} R_bridge_WOTSTW(A, O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).OC_emb.init.
    auto.
  (* --------------------------------------------------------------------------
     Block 1a (PROVED — the hard leg): emb-map oracle coupling of A0.choose + the
     grind loop.  Couple A0(STCRC_WC.Col.O_THFC_Default){1}
     with A0(OC_emb){2} (and the R_multi grind while-loop) under the relational
     invariant  FC.tws{2} = map emb_tw Col.tws{1}  /\  Col.pp{1} = FC.pp{2}.
     The per-query obligation is discharged by the local equiv `qeq` from
     emb_thfc_ThC (thfc at emb addr = Th+C ⇒ equal digests), so A0 and the grind
     couple step-for-step ⇒ equal committed query list `qs` and grinded `sds`,
     and FC records exactly the emb_tw-images of the local grind tweaks.
     [multi-week FC↔STCRC reconciliation; the emb_thfc_ThC content of the leg.] *)
  seq 6 6 : (={glob A, ps}
             /\ qs{1} = R_bridge_WOTSTW.qs{2}
             /\ R_multi_WOTSTW.qs{1} = R_multi_WOTSTW.qs{2}
             /\ O_MEUFGCMA_WOTSTWESNPRF.qs{2} = []
             /\ O_MEUFGCMA_WOTSTWESNPRF.ps{2} = ps{2}
             /\ FC.O_THFC_Default.tws{2}
                = map emb_tw STCRC_WC.Col.O_THFC_Default.tws{1}
             /\ R_multi_WOTSTW.sds{1} = R_multi_WOTSTW.sds{2}).
  + (* the emb per-query coupling: Col.query ~ OC_emb.query returns the SAME
       digest (emb_thfc_ThC) and grows FC.tws by the emb_tw-image. *)
    have qeq : equiv[ STCRC_WC.Col.O_THFC_Default.query ~
                      R_bridge_WOTSTW(A, O_MEUFGCMA_WOTSTWESNPRF,
                                      FC.O_THFC_Default).OC_emb.query :
        ={arg}
        /\ STCRC_WC.Col.O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
        /\ FC.O_THFC_Default.tws{2}
           = map emb_tw STCRC_WC.Col.O_THFC_Default.tws{1}
        ==> ={res}
        /\ STCRC_WC.Col.O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
        /\ FC.O_THFC_Default.tws{2}
           = map emb_tw STCRC_WC.Col.O_THFC_Default.tws{1} ].
    + proc; inline{2} FC.O_THFC_Default.query.
      wp; skip => &1 &2 [harg [hpp htws]].
      move: emb_eval; rewrite /emb_thfc_ThC => E.
      move: harg => [-> ->] /=.
      by rewrite hpp (E FC.O_THFC_Default.pp{2} tw{2} x{2}) htws map_rcons.
    (* couple A0.choose across the two oracles *)
    seq 1 1 : (={glob A, ps} /\ R_multi_WOTSTW.qs{1} = R_multi_WOTSTW.qs{2}
               /\ STCRC_WC.Col.O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
               /\ FC.O_THFC_Default.tws{2}
                  = map emb_tw STCRC_WC.Col.O_THFC_Default.tws{1}
               /\ O_MEUFGCMA_WOTSTWESNPRF.qs{2} = []
               /\ O_MEUFGCMA_WOTSTWESNPRF.ps{2} = ps{2}).
    + call (: STCRC_WC.Col.O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
              /\ FC.O_THFC_Default.tws{2}
                 = map emb_tw STCRC_WC.Col.O_THFC_Default.tws{1}).
      + conseq qeq => /#.
      skip => /#.
    (* PROVEN 2026-07-08: the two-sided grind while-loop coupling — outer
       per-instance loop + inner counter-scan, each OC.query coupled by `qeq`
       (emb_thfc_ThC).  Equal committed `qres`/`sds`; FC.tws = map emb_tw Col.tws. *)
    sp.
    seq 1 1 : (={glob A, ps, qres, R_multi_WOTSTW.qs, R_multi_WOTSTW.sds}
               /\ STCRC_WC.Col.O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
               /\ FC.O_THFC_Default.tws{2}
                  = map emb_tw STCRC_WC.Col.O_THFC_Default.tws{1}
               /\ O_MEUFGCMA_WOTSTWESNPRF.qs{2} = []
               /\ O_MEUFGCMA_WOTSTWESNPRF.ps{2} = ps{2}).
    + while (={glob A, ps, k0, qres, R_multi_WOTSTW.qs, R_multi_WOTSTW.sds}
             /\ STCRC_WC.Col.O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
             /\ FC.O_THFC_Default.tws{2}
                = map emb_tw STCRC_WC.Col.O_THFC_Default.tws{1}
             /\ O_MEUFGCMA_WOTSTWESNPRF.qs{2} = []
             /\ O_MEUFGCMA_WOTSTWESNPRF.ps{2} = ps{2}).
      + sp.
        wp.
        call qeq.
        while (={found, sd, cs, glob A, ps, k0, qres,
                 R_multi_WOTSTW.qs, R_multi_WOTSTW.sds}
               /\ wad0{1} = wad0{2} /\ m0{1} = m1{2}
               /\ STCRC_WC.Col.O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
               /\ FC.O_THFC_Default.tws{2}
                  = map emb_tw STCRC_WC.Col.O_THFC_Default.tws{1}
               /\ O_MEUFGCMA_WOTSTWESNPRF.qs{2} = []
               /\ O_MEUFGCMA_WOTSTWESNPRF.ps{2} = ps{2}).
        + wp.
          call qeq.
          wp; skip => /> /#.
        skip => /> /#.
      skip => /> /#.
    wp; skip => />.
  (* --------------------------------------------------------------------------
     BRIDGE-ADMIT-1b  (committed-signing coupling).  Couple the LHS honest
     keygen/sign while-loop (WOTS_TW_ES_NPRF) with the RHS replay loop through
     MM45's signing oracle O (which internally runs the identical keygen/sign):
     per committed index k, O records `(val wad_k, m_k, pk_k, sig_k)` with
     `(pk_k, sig_k) = ks_k`, so `ks{1} = R_bridge.ks{2}` and O's query list is
     exactly the honest signing list.  FC.tws / Col.tws untouched (keygen/sign
     use the pure chain hash cf, never the collection oracle). *)
  seq 4 3 : (={glob A, ps}
             /\ qs{1} = R_bridge_WOTSTW.qs{2}
             /\ R_multi_WOTSTW.qs{1} = R_multi_WOTSTW.qs{2}
             /\ FC.O_THFC_Default.tws{2}
                = map emb_tw STCRC_WC.Col.O_THFC_Default.tws{1}
             /\ R_multi_WOTSTW.sds{1} = R_multi_WOTSTW.sds{2}
             /\ ks{1} = R_bridge_WOTSTW.ks{2}
             /\ adlO{1} = map (fun (q : qC) => WAddress.val q.`1) qs{1}
             /\ size ks{1} = size qs{1}
             /\ size O_MEUFGCMA_WOTSTWESNPRF.qs{2} = size qs{1}
             /\ (forall (j : int), 0 <= j < size qs{1} =>
                   nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2} j
                   = (WAddress.val (nth witness qs{1} j).`1,
                      (nth witness qs{1} j).`2,
                      (nth witness ks{1} j).`1,
                      (nth witness ks{1} j).`2))).
  + (* PROVEN 2026-07-08: committed-signing coupling.  Inline MM45's O.query
       (which runs the identical keygen/sign) and couple it with the LHS honest
       loop; the shared randomness of keygen (sim) gives equal (pk,sig), so
       ks{1} = R_bridge.ks{2} and O records the honest signing tuples. *)
    inline{2} O_MEUFGCMA_WOTSTWESNPRF.query.
    sp.
    while (={glob A, ps, k}
           /\ qs{1} = R_bridge_WOTSTW.qs{2}
           /\ R_multi_WOTSTW.qs{1} = R_multi_WOTSTW.qs{2}
           /\ O_MEUFGCMA_WOTSTWESNPRF.ps{2} = ps{2}
           /\ FC.O_THFC_Default.tws{2}
              = map emb_tw STCRC_WC.Col.O_THFC_Default.tws{1}
           /\ R_multi_WOTSTW.sds{1} = R_multi_WOTSTW.sds{2}
           /\ 0 <= k{1} <= size qs{1}
           /\ ks{1} = R_bridge_WOTSTW.ks{2}
           /\ size ks{1} = k{1}
           /\ size O_MEUFGCMA_WOTSTWESNPRF.qs{2} = k{1}
           /\ adlO{1} = map (fun (q : qC) => WAddress.val q.`1) (take k{1} qs{1})
           /\ (forall (j : int), 0 <= j < k{1} =>
                 nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2} j
                 = (WAddress.val (nth witness qs{1} j).`1, (nth witness qs{1} j).`2,
                    (nth witness ks{1} j).`1, (nth witness ks{1} j).`2))).
    + sp.
      wp.
      call (_ : ={arg} ==> ={res}); first by sim.
      call (_ : ={arg} ==> ={res}); first by sim.
      skip => /> *;
        smt(nth_rcons size_rcons take_nth map_rcons nth_map size_map size_take size_ge0).
    skip => /> *; smt(take0 take_size size_ge0 size_map).
  (* --------------------------------------------------------------------------
     BRIDGE-ADMIT-1c  (forge relay).  Both sides reconstruct the same `wcks`
     (WOTS-TW sig + grinded counter) from `ks`+`sds` and run the SAME oracle-free
     A0.forge on identical inputs ⇒ identical `(i, m', sig')` after the identical
     relay `(i, ThC ps wad_i m' c', sig')`.  Provable by a `call (: true)`
     wrapped in the wcks-loop coupling; sub-admitted to keep the seq skeleton. *)
  seq 7 9 : (={glob A, ps, i, m', sig'}
             /\ qs{1} = R_bridge_WOTSTW.qs{2}
             /\ FC.O_THFC_Default.tws{2}
                = map emb_tw STCRC_WC.Col.O_THFC_Default.tws{1}
             /\ ks{1} = R_bridge_WOTSTW.ks{2}
             /\ adlO{1} = map (fun (q : qC) => WAddress.val q.`1) qs{1}
             /\ size ks{1} = size qs{1}
             /\ size O_MEUFGCMA_WOTSTWESNPRF.qs{2} = size qs{1}
             /\ (forall (j : int), 0 <= j < size qs{1} =>
                   nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2} j
                   = (WAddress.val (nth witness qs{1} j).`1,
                      (nth witness qs{1} j).`2,
                      (nth witness ks{1} j).`1,
                      (nth witness ks{1} j).`2))).
  + (* PROVEN 2026-07-08: forge relay.  wcks reconstructed identically from
       ks(=ks0=R_bridge.ks) + the shared grinded sds; the oracle-free A0.forge
       runs on identical (ps, wcks); the relay maps at the shared R_multi.qs. *)
    sp.
    seq 1 1 : (={wcks, ps} /\ ps0{1} = ps1{2} /\ (glob A){1} = (glob A){2}
               /\ R_multi_WOTSTW.qs{1} = R_multi_WOTSTW.qs{2}
               /\ qs{1} = R_bridge_WOTSTW.qs{2}
               /\ FC.O_THFC_Default.tws{2}
                  = map emb_tw STCRC_WC.Col.O_THFC_Default.tws{1}
               /\ ks{1} = R_bridge_WOTSTW.ks{2}
               /\ adlO{1} = map (fun (q : qC) => WAddress.val q.`1) qs{1}
               /\ size ks{1} = size qs{1}
               /\ size O_MEUFGCMA_WOTSTWESNPRF.qs{2} = size qs{1}
               /\ (forall (j : int), 0 <= j < size qs{1} =>
                     nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2} j
                     = (WAddress.val (nth witness qs{1} j).`1,
                        (nth witness qs{1} j).`2,
                        (nth witness ks{1} j).`1,
                        (nth witness ks{1} j).`2))).
    + while (={wcks, k1, ps} /\ ks0{1} = ks{2} /\ ps0{1} = ps1{2}
             /\ (glob A){1} = (glob A){2}
             /\ R_multi_WOTSTW.sds{1} = R_multi_WOTSTW.sds{2}
             /\ R_multi_WOTSTW.qs{1} = R_multi_WOTSTW.qs{2}
             /\ qs{1} = R_bridge_WOTSTW.qs{2}
             /\ FC.O_THFC_Default.tws{2}
                = map emb_tw STCRC_WC.Col.O_THFC_Default.tws{1}
             /\ ks{1} = R_bridge_WOTSTW.ks{2}
             /\ adlO{1} = map (fun (q : qC) => WAddress.val q.`1) qs{1}
             /\ size ks{1} = size qs{1}
             /\ size O_MEUFGCMA_WOTSTWESNPRF.qs{2} = size qs{1}
             /\ (forall (j : int), 0 <= j < size qs{1} =>
                   nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2} j
                   = (WAddress.val (nth witness qs{1} j).`1,
                      (nth witness qs{1} j).`2,
                      (nth witness ks{1} j).`1,
                      (nth witness ks{1} j).`2))).
      + auto => />; smt().
      skip => />; smt().
    wp; call (: true); skip => />; smt().
  (* --------------------------------------------------------------------------
     Block E (PROVEN):  the success-bit entailment res{1} => res{2}, INCLUDING
     MM45's extra `disj_wgpidxs adlO adlOC` conjunct discharged through the REAL
     `emb_disj_wgpidxs_lists` (adlO all valid_wadrs via all_valid_map_val;
     adlOC = map emb_tw of the grind tweaks).  Same verify proc both sides;
     in-range couples validity, out-of-range makes res{1} false. *)
  inline{2} O_MEUFGCMA_WOTSTWESNPRF.get.
  inline{2} O_MEUFGCMA_WOTSTWESNPRF.nr_queries.
  inline{2} O_MEUFGCMA_WOTSTWESNPRF.dist_addresses.
  inline{2} O_MEUFGCMA_WOTSTWESNPRF.get_addresses.
  inline{1} STCRC_WC.Col.O_THFC_Default.get_tweaks.
  inline{2} FC.O_THFC_Default.get_tweaks.
  case (0 <= i{1} < size qs{1}).
  + (* in range: couple the (identical) verify calls on equal arguments *)
    wp.
    call (_ : ={arg} ==> ={res}); first by sim.
    wp; skip => &1 &2 [pre hir].
    have hoq : map (fun (e : adrs * msgWOTS * pkWOTS * sigWOTS) => e.`1)
                   O_MEUFGCMA_WOTSTWESNPRF.qs{2}
             = map (fun (q : qC) => WAddress.val q.`1) qs{1}.
    + by apply (oqs_adlO_eq qs{1} ks{1}); move: pre => />.
    (* recorded O-tuple at index i (in range): identifies verify args + m_i *)
    have htpl : nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2} i{2}
              = (WAddress.val (nth witness qs{1} i{2}).`1, (nth witness qs{1} i{2}).`2,
                 (nth witness ks{1} i{2}).`1, (nth witness ks{1} i{2}).`2)
      by move: pre => [#] *; smt().
    (* the disjointness conjunct — discharged through the REAL list lemma *)
    have hdisj : disj_wgpidxs
                   (map (fun (e : adrs * msgWOTS * pkWOTS * sigWOTS) => e.`1)
                        O_MEUFGCMA_WOTSTWESNPRF.qs{2})
                   FC.O_THFC_Default.tws{2}.
    + rewrite hoq; move: pre => [#] *.
      have -> : FC.O_THFC_Default.tws{2} = map emb_tw STCRC_WC.Col.O_THFC_Default.tws{1} by smt().
      by apply emb_disj_wgpidxs_lists; [exact emb_disj | exact all_valid_map_val].
    rewrite htpl /=; move: pre => [#] *.
    by rewrite hoq; do ! split; smt().
  (* out of range: res{1} is false (0 <= i < nrqs fails) *)
  wp.
  call{1} verifytw_ll.
  call{2} verifytw_ll.
  wp; skip => /> &1 &2 *; smt().
qed.

(* ==========================================================================
   COMPOSITION COROLLARY — D.1 with the WOTS-TW term REPLACED by MM45's real
   `M_EUF_GCMA_WOTSTWESNPRF` (the roadmap shape at WOTS_C_Real.ec:105).

   Chains D.1 (WOTS_C_Multi.D1_MEUFNACMA_WOTSC) with the bridge by transitivity.
   This forces the bridge's LHS to syntactically MATCH D.1's WOTS-TW term (it
   does) and stands the whole leg on the two flagged embedding hypotheses.
   Under emb_thfc_ThC + emb_disj_wgpidxs it is the intended two-term bound:
     InSec^{d-EU-naCMA}(WOTS+C) <= InSec^{S-TCR(+C)}(Th+C) + InSec^{GCMA}(WOTS-TW).
   ========================================================================== *)
lemma D1_MEUFNACMA_WOTSC_MM45
  (A <: Adv_MnaCMA_WOTSC{-R_multi_STCRC, -R_multi_WOTSTW, -R_bridge_WOTSTW,
                         -G0_MULTI, -STCRC_WC.O_STCRC_Default,
                         -STCRC_WC.Col.O_THFC_Default,
                         -O_MEUFGCMA_WOTSTWESNPRF, -FC.O_THFC_Default}) &m :
    c <= p_tgts =>
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    emb_thfc_ThC =>
    emb_disj_wgpidxs =>
    Pr[M_EUF_NACMA_WOTSC_L(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
  <=   Pr[STCRC_WC.S_TCR_C(R_multi_STCRC(A),
                           STCRC_WC.O_STCRC_Default,
                           STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
     + Pr[M_EUF_GCMA_WOTSTWESNPRF(R_bridge_WOTSTW(A),
                                  O_MEUFGCMA_WOTSTWESNPRF,
                                  FC.O_THFC_Default).main() @ &m : res].
proof.
  move=> hc encb he hd.
  have hD1  := D1_MEUFNACMA_WOTSC A &m hc encb.
  have hbr  := D1_bridge_WOTSTW  A &m he hd.
  smt().
qed.
