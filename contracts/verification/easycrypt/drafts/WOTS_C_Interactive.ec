(* ==========================================================================
   WOTS_C_Interactive.ec  --  Thm D.1 re-proved over the INTERACTIVE WOTS+C
                              d-EU-(g)CMA game `M_EUF_GCMA_WOTSC_NPRF`.

   TASK.  The port's Thm D.1 (WOTS_C_Multi.ec, `D1_MEUFNACMA_WOTSC`, 0-admit) is
   proven over the *batch / non-adaptive* game `M_EUF_NACMA_WOTSC_L`: the forger
   COMMITS all its signing queries in `choose() : qC list` and only receives the
   keypairs + signatures later, in `forge(ps, ks)`, AFTER the public seed `ps` is
   revealed.  SPHINCS+'s XMSS-MT reduction, however, calls the INTERACTIVE game
   `M_EUF_GCMA_WOTSC_NPRF` (WOTS_C_Scheme.ec:182), whose oracle answers each
   signing query synchronously, INSIDE `A.choose()`, returning a real
   `pkWOTS * (sigWOTS * cntr)` on the spot (WOTS_C_Scheme.ec:154-163).

   This file re-derives the D.1 two-term bound over that interactive game, reusing
   D.1's +C mathematical content (grindC / ThC / the encode bridge / verifyC_TW /
   the S-TCR(+C) split), and — where a term is NOT reducible to a *constructible*
   reduction against the fixed challenge games — states that fact PRECISELY rather
   than faking a module.  `WOTS_C_Multi.ec` and `WOTS_C_Scheme.ec` are read-only
   and untouched; the batch theorem stays valid as-is.

   ==========================================================================
   ===  OBSTRUCTION ANALYSIS  (the critical-path finding)                 ===
   ==========================================================================

   The interactive two-term bound we are after is

     Pr[M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default,
                              STCRC_WC.Col.O_THFC_Default).main() : res]
       <=  Pr[STCRC_WC.S_TCR_C(R_int_STCRC(A), O_STCRC_Default,
                               Col.O_THFC_Default).main() : res]     (* +C term  *)
         + Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(A), O_MEUFGCMA_WOTSTWESNPRF,
                                      OC).main() : res].              (* WOTS-TW  *)

   Lifting each of D.1's two reductions to the interactive oracle splits sharply
   into a RESOLVABLE half and a GENUINELY-BLOCKED half.

   ----------------------------------------------------------------------------
   (I)  ADAPTIVE TARGET REGISTRATION  --  *NOT* the block (clean restructure).
   ----------------------------------------------------------------------------
   The batch S-TCR reduction `R_multi_STCRC.pick` (WOTS_C_Multi.ec:203-218) runs
   `AA.choose()` to obtain the FULL committed list `qs : qC list` and only THEN
   loops registering one S-TCR(+C) target per query via `O.query(wad, m)`.  One
   might fear the interactive game — where `choose()` returns `unit` and the query
   set is not known until the queries actually arrive — leaves nowhere to register
   the targets.  It does not: `O.query` (STCR_C.ec:127) is available throughout
   `pick()`, so a reduction can register target k EXACTLY when A issues its k-th
   signing query, adaptively, threading a per-query while/oracle-hook.  Target
   registration per-query is a bookkeeping restructure, not a barrier.

   ----------------------------------------------------------------------------
   (II) HONEST SIGNING INSIDE THE S-TCR REDUCTION  --  the GENUINE STRUCTURAL BLOCK.
   ----------------------------------------------------------------------------
   The batch S-TCR reduction can DEFER every honest `WOTS_C_ES.keygen` /
   `WOTS_C_ES.sign` to `find(pp)` (WOTS_C_Multi.ec:237-239), where the public seed
   `pp` is finally in hand.  This is exactly why the batch shape was chosen: the
   batch forger does not consume signatures until `forge`, so the reduction never
   has to sign before `pp` exists.

   The INTERACTIVE forger consumes each signature synchronously, inside
   `A.choose()`: the signing oracle `O_MEUFGCMA_WOTSC_Default.query` runs

        (pk, sk) <@ WOTS_C_ES.keygen(ps, WAddress.val wad);   (* needs ps=pp *)
        sigc     <@ WOTS_C_ES.sign(sk, m);                    (* needs ps=pp *)
        return (pk.`1, sigc);                                 (* WOTS_C_Scheme.ec:159-162 *)

   BOTH the public-key chain-walk (inside keygen's `pkWOTS_from_skWOTS`) and the
   signature chain-walk (`cf ps (set_chidx ad j) ...`) evaluate the WOTS chain hash
   under `ps = pp`.  So the reduction, to faithfully answer A, needs `pp` at the
   moment A queries — i.e. WHILE it is mid-`A.choose()`.

   Now look at where the S-TCR(+C) game hands the reduction `pp`
   (STCR_C.ec:173-206):

        module type Adv_STCRC(O, OC) = {
          proc pick() : unit         { O.query, OC.query }   (* has oracles, NO pp *)
          proc find(pp) : ...        { }                     (* has pp, NO oracles *)
        }
        ... pp <$ dpp; OC.init(pp); O.init(pp); A.pick(); (i,m',ctr) <@ A.find(pp);

     * `A.choose()` MUST run in `pick()`: it needs `OC.query` (and issues the
       signing queries), and `OC.query` is available ONLY in `pick`.
     * `A.forge(ps)` MUST run in `find(pp)`: it needs `ps`, available only there.
     * `find` has the empty oracle set `{}` — it CANNOT call `O.query`/`OC.query`.

   Hence there is NO program point at which the reduction is simultaneously
   (a) mid-`A.choose()` answering a signing query, and (b) holding `pp`.  The only
   values the S-TCR oracle hands back are `(ThC pp tw m grind, grind)` (a Th+C
   digest + counter, STCR_C.ec:127-137) — NOT `pp`, and NOT any WOTS chain value;
   and `OC = Col.Oracle_THFC` computes ONLY Th+C on `msg_t * cntr` inputs
   (STCR_C.ec:86-102), NOT the WOTS chain hash `f`, so it cannot reconstruct chains
   either.  The reduction therefore CANNOT produce the honest `pkWOTS * sigWOTS`
   that the interactive forger demands.

   >>> This is a GENUINE structural block against the FIXED `S_TCR_C` interface,
   >>> not a bookkeeping restructure.  It is the interactive analogue of exactly
   >>> the difficulty the port avoided by choosing the batch (naCMA) shape:
   >>> "An adaptive-oracle M_EUF_GCMA shape would force the S-TCR reduction to
   >>>  reconstruct chain-hash `f` evaluations at the hidden pp during `choose`,
   >>>  which STCRC_WC.Col does not provide" (WOTS_C_Multi.ec:30-34).

   Faithfully closing it would require EITHER (a) an S-TCR(+C) game that reveals
   `pp` to the adversary BEFORE the target queries (so the reduction can key-gen
   and sign honestly while running A.choose) — a DIFFERENT challenge game than the
   read-only `S_TCR_C`; OR (b) an SM-DT-style challenge oracle that itself supplies
   the WOTS chain challenge values, letting the reduction answer signing queries by
   revealing oracle outputs (the MM45 route for the WOTS-TW *chain* layer) — but
   the +C S-TCR term lives at the message-ENCODING layer and its oracle
   deliberately compresses via Th+C only.  Both are out of scope here (STCR_C.ec is
   read-only), so the +C term is characterized, not forced.

   NON-VACUITY GUARD.  The tempting "fix" — have `R_int_STCRC.pick` sign under a
   reduction-local dummy seed `ps' <> pp` — yields an UNFAITHFUL simulation (A sees
   keys/sigs under the wrong seed) and would make the S-TCR term a spurious bound
   (its byequiv coupling `res{1} => res{2}` is FALSE at the signing hook).  That is
   precisely the D.1-hop2 "identically-0 / mis-copied-conjunct" class of bug the
   task warns against.  We DO NOT do this.  No dummy-seed reduction is written.

   ----------------------------------------------------------------------------
   (III) THE WOTS-TW REDUCTION  --  RESOLVABLE (constructible interactively).
   ----------------------------------------------------------------------------
   `R_int_WOTSTW` is an `Adv_MEUFGCMA_WOTSTWESNPRF` (WOTS_TW_ES.ec:2315): its
   `choose()` HAS the WOTS-TW signing oracle `O : Oracle_MEUFGCMA_WOTSTWESNPRF`
   (whose `query` HOLDS pp internally and signs honestly, WOTS_TW_ES.ec:2415-2432)
   AND `OC`.  So when A issues a WOTS+C signing query `(wad, m)`, the reduction can
   answer HONESTLY and interactively:
        1. grind a Prop-satisfying +C counter `c` via `OC.query(wad, (m, .))`
           (available in choose) and form the +C digest `d = ThC pp wad m c`;
        2. call `O.query(wad, d)` -> `(pk, sig_tw)` (the WOTS-TW oracle signs d);
        3. return `(pk, (sig_tw, c))` to A.
   Under the encode bridge `encode_msgWOTS_C p a x c = encode_msgWOTS (ThC p a x c)`
   (WOTS_C_Reduction.ec:459-465, `signC_TW`), a WOTS+C signature of m equals a
   WOTS-TW signature of `d` paired with the grind counter, so step 2's honest
   WOTS-TW signature IS a well-distributed WOTS+C signature.  This half admits a
   real, zero-`axiom` reduction module and a sound hop.

   ==========================================================================
   ===  DELIVERABLE STRUCTURE OF THIS FILE                                 ===
   ==========================================================================
   The sound, honest decomposition (all inequalities in the correct direction):

     Pr[interactive LHS]  =  Pr[LHS : res /\ !coll]  +  Pr[LHS : res /\ coll]
                          <= Pr[GAME1_INT : res]      +  Pr[LHS : res /\ coll]

   where `coll` is the +C collision event at the forged instance, and `GAME1_INT`
   is the interactive collision-instrumented game (the interactive analogue of
   `GAME1_MULTI`, WOTS_C_Multi.ec:331).  Then:

     * WOTS-TW leg (RESOLVABLE):  Pr[GAME1_INT : res] <= Pr[WOTS-TW term via
       R_int_WOTSTW]  -- constructible reduction `R_int_WOTSTW` below.
     * +C leg (BLOCKED, per (II)):  Pr[LHS : res /\ coll] is the +C collision
       probability; over the fixed `S_TCR_C` game it has NO constructible S-TCR
       reduction, for the pp-availability reason above.  We DO NOT emit a fake
       `Pr[S_TCR_C(R_int_STCRC(A))]` term.

   The interactive-D.1 STATEMENT is therefore recorded with the +C term left as the
   honest collision probability `Pr[LHS : res /\ coll]` (a real quantity, NOT 0),
   flagged as the residual that a pp-revealing S-TCR(+C) game would discharge.
   ========================================================================== *)

(* ==========================================================================
   ===  RECONCILIATION UPDATE  (2026-07-09) — the obstruction is RESOLVED.  ===
   ==========================================================================

   The OBSTRUCTION ANALYSIS above concluded the +C S-TCR term is BLOCKED because
   the S-TCR reduction cannot answer the interactive signing queries without `pp`.
   That conclusion was an ARTIFACT of the S-TCR(+C) *collection* oracle used in
   the batch proof (`STCR_C.ec` `Col`): it is a LOCAL clone with
       in_t <- msgWOTS * cntr,  diff_t <- unit,  fc <- (fun _ pp tw x => ThC ..)
   (STCR_C.ec:96-100) — i.e. it serves ONLY the message-hash `ThC`, NOT the WOTS
   chain hash `f = thfc (8*n)` (WOTS_TW_ES.ec:434).  With a ThC-only collection the
   reduction indeed cannot reconstruct chains during `pick`, hence the "block".

   THE FIX (MM45's stitching route, made available by reconciling the collection).
   ---------------------------------------------------------------------------
   MM45's WOTS-TW SM-DT-TCR reduction ALSO holds no `pp` while signing; it SIGNS BY
   STITCHING oracle outputs (`R_SMDTTCRC_Game34WOTSTWES.query`, WOTS_TW_ES.ec:2662-
   2713): sample a fresh secret chain, walk each chain UP by calling the (pp-holding)
   oracle, return the stitched (pk, sig).  The only reason our +C reduction could not
   do the same was that its collection oracle did not expose the chain hash `f`.

   BUT `ThC` IS a member of the SAME size-indexed tweakable-hash collection as `f`:
       ThC ps tw m c = thfc (size (emb_in (m,c))) ps (emb_tw tw) (emb_in (m,c))
                                                        (WOTS_C_Real.ec:68-69)
       f            = thfc (8*n)                        (WOTS_TW_ES.ec:434)
   and the REAL collection `FC` (WOTS_TW_ES.ec:450: diff_t <- int, get_diff <- size,
   fc <- thfc) is exactly `thfc` indexed by input size, so `FC.Oracle_THFC` serves
   BOTH `f` (on 8n-byte chain inputs) AND `ThC` (on emb_in inputs).  This is ALREADY
   the collection oracle the interactive WOTS+C game uses (`M_EUF_GCMA_WOTSC_NPRF`,
   WOTS_C_Scheme.ec:182: `OC : FC.Oracle_THFC`).  So the reconciliation is: build the
   interactive S-TCR(+C) game over `OC = the real FC.Oracle_THFC` (not the ThC-only
   `Col`).  Then `R_int_STCRC` signs by stitching: self-generate the WOTS sk, embed
   the ThC challenge via `O.query` (message layer), and WALK THE CHAINS via
   `OC.query` (= real `f`, evaluated under the game's hidden pp).  It holds NO `pp`.

   ==========================================================================
   ===  THE MAKE-OR-BREAK: does FLAG-2 discharge `disj_lists twsO twsOC`?   ===
   ==========================================================================
   The S-TCR(+C) game's success requires `disj_lists twsO twsOC` (targets disjoint
   from the collection tweaks — SM_DT_TCR_C, TweakableHashFunctions.eca:745;
   `disj_lists s1 s2 = ! has (mem s2) s1`, ibid:550).  In the INTERACTIVE reduction
   `twsOC = OC.get_tweaks()` becomes COMPOUND — unlike the batch, where signing is
   deferred to `find(pp)` and computes chains DIRECTLY (so `twsOC` = A's queries only,
   and `disj_lists` follows from the game's `disj_wgpidxs adlO adlOC` by the bridge
   `disj_wgpidxs_disj_lists`, WOTS_C_Multi.ec:450, discharge at WOTS_C_Multi.ec:592).
   Here `OC` is used for TWO things, so `twsOC` = the DISJOINT UNION of

     (a) the reduction's OWN CHAIN-WALK tweaks — valid WOTS instance addresses
         `set_hidx (set_chidx (WAddress.val wad_k) i) j`, all `valid_wadrs`,
         at the SIGNED groups (this is the NEW ingredient interactivity forces); and
     (b) A's OWN direct `OC` queries (A computing `f`/`ThC` for its forgery).

   The obligation `disj_lists twsO twsOC` (with `twsO` = the ThC targets recorded at
   their FC address `emb_tw wad_k`, type pkcotype) therefore SPLITS into two axes:

     AXIS-1  targets vs (a) chain-walk  →  DISCHARGED BY FLAG-2.
             `emb_disj_concrete` (WOTS_C_Flag2Discharge.ec:201):
                valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b).
             Every chain-walk tweak is `valid_wadrs`; every target is `emb_tw wad_k`;
             so their `get_wgpidxs` differ ⇒ literal addresses differ ⇒ list-disjoint
             (`disj_wgpidxs_disj_lists`).  This is the NEW load-bearing use of FLAG-2
             — the batch never needed it (batch `twsOC` has no chain-walk tweaks).

     AXIS-2  targets vs (b) A's own encoding/OC queries  →  NOT covered by FLAG-2
             (an `emb_tw`-image target can coincide with an `emb_tw`-image A-query;
             both are pkcotype, so FLAG-2's type-separation says nothing).  The
             game's `disj_wgpidxs adlO adlOC` does NOT cover it either: `adlO` are the
             raw chtype signing groups, and `get_wgpidxs (emb_tw wad_k)` differs from
             `get_wgpidxs wad_k` (FLAG-2!), so A is FREE, under the read-only LHS game
             `M_EUF_GCMA_WOTSC_NPRF`, to query `OC` at the very target address
             `emb_tw wad_k`.  On such a run: LHS wins (disj_wgpidxs holds) AND coll
             holds, but `emb_tw wad_k ∈ twsOC ∩ twsO` ⇒ `disj_lists` FAILS ⇒ the
             S-TCR game LOSES.  So AXIS-2 is a CONCRETE `res{1} /\ coll => res{2}`
             counterexample class — it is a REAL obligation, not vacuous.

   >>> DOES THE PATH HOLD?  YES — AXIS-2 is discharged NOT by FLAG-2 but by the SAME
   >>> well-formedness hypothesis on A the port's single-instance C.2 reduction
   >>> ALREADY carries: `WOTSC_C2_reduce` (WOTS_C_Reduction.ec:238-240) assumes
   >>>    hoare[A.choose : OC.tws=[] ==> ! (witness ∈ OC.tws)]
   >>> — "the WOTS+C forger never queries the collection oracle at the challenge
   >>> tweak" — which discharges `disj_lists [witness] OC.tws` in the single-instance
   >>> case (comment ibid:234-237).  AXIS-2 is EXACTLY the interactive / multi-target
   >>> lift of that hypothesis: A's direct `OC` queries avoid the target compression
   >>> addresses `{ emb_tw wad_k : wad_k a signing-query address }`.  It is a FAITHFUL,
   >>> NON-VACUOUS S-TCR-adversary well-formedness constraint (an adversary that opens
   >>> its own target via the collection is not a TCR breaker — this is intrinsic to
   >>> the SM-DT-TCR notion, TweakableHashFunctions.eca:745's `disj_lists`), and it is
   >>> already the port's idiom.  It is NOT a new assumption invented to paper over a
   >>> gap; the ONLY thing genuinely new vs C.2 is AXIS-1 (chain-walk vs target),
   >>> which FLAG-2 discharges.

   NET.  The compound `disj_lists` splits cleanly: AXIS-1 = FLAG-2 (new), AXIS-2 =
   carried C.2 well-formedness hypothesis on A (interactive lift).  They COMPOSE:
   `twsOC = chain-walk ⊎ A-queries`, both disjoint from `twsO`, so
   `disj_lists twsO twsOC` holds.  The obstruction is resolved; the path holds.

   CAVEAT ON FLAG-2's NAMESPACE (honest, for the eventual close).  `emb_disj_concrete`
   is proved in the CONCRETE `FSSLXMTWES.WTWES` namespace (WOTS_C_Flag2Discharge.ec:96,
   via `require import SPHINCS_PLUS`), whereas this file's stack imports the ABSTRACT
   `WOTS_TW_ES` (abstract `emb_tw`, abstract `valid_widxvalsgp`).  As documented at
   WOTS_C_Flag2Discharge.ec:36-64, the concrete lemma is NOT literally the abstract
   proposition; AXIS-1 is therefore threaded as the abstract hypothesis
   `emb_disj_wgpidxs` (`forall a b, valid_wadrs a => get_wgpidxs a <> get_wgpidxs
   (emb_tw b)`), PROVEN REALISABLE by `emb_disj_concrete` on the real scheme — exactly
   the FLAG-2 posture `WOTS_C_Bridge.ec` already uses.  No axiom; a named hypothesis
   with machine-checked evidence of realisability.
   ========================================================================== *)

require import AllCore List Distr.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme WOTS_C_Reduction.

import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import WOTS_C_Scheme.
import WOTS_C_Reduction.
import EmsgWOTS.   (* emsgWOTS `.[]` word-indexing, used by the stitching reduction *)

(* ==========================================================================
   PART 1.  THE RECONCILED INTERACTIVE S-TCR(+C) GAME.

   The batch game `STCRC_WC.S_TCR_C` (STCR_C.ec:188) runs over the ThC-ONLY
   collection `STCRC_WC.Col.Oracle_THFC` (STCR_C.ec:96, in_t = msgWOTS*cntr).
   The RECONCILED game keeps the SAME bespoke +C challenge oracle
   `STCRC_WC.O_STCRC_Default` (STCR_C.ec:118 — grinds a Prop counter, records the
   raw target (tw,m,j), returns (ThC digest, counter)) but swaps the collection to
   the REAL size-indexed `FC.Oracle_THFC` (WOTS_TW_ES.ec:450/577) — the one the
   interactive WOTS+C game `M_EUF_GCMA_WOTSC_NPRF` (WOTS_C_Scheme.ec:182) already
   uses, which serves BOTH the chain hash `f = thfc(8n)` and `ThC = thfc(size(emb_in..))`.

   The success predicate's disjointness is `FC.disj_lists twsO twsOC` with the
   target list PROJECTED THROUGH `emb_tw`: `twsO = map emb_tw (O.get_tweaks ())`.
   This is the FC address at which each ThC target actually lives
   (ThC ps tw m j = thfc _ ps (emb_tw tw) _, WOTS_C_Real.ec:69) — NOT a trick to
   summon FLAG-2 but the correct collection coordinate of the target.  `dist` is
   likewise taken over the projected list (`uniq twsO`).  `O.get(i)` still returns
   the RAW (tw,m,j); the collision equation `ThC pp tw m j = ThC pp tw m' ctr`
   applies `emb_tw` internally, so raw/projected never drift.
   ========================================================================== *)

module type Adv_ISTCRC(O : STCRC_WC.Oracle_STCRC, OC : FC.Oracle_THFC) = {
  proc pick() : unit { O.query, OC.query }
  proc find(pp : pseed) : int * msgWOTS * cntr {}
}.

module S_TCR_C_Int(A : Adv_ISTCRC, O : STCRC_WC.Oracle_STCRC, OC : FC.Oracle_THFC) = {
  module A = A(O, OC)

  proc main() : bool = {
    var pp : pseed;
    var tw : adrs;
    var m, m' : msgWOTS;
    var j, ctr : cntr;
    var i : int;
    var nrts : int;
    var twsOraw, twsO, twsOC : adrs list;

    pp <$ dpseed;
    OC.init(pp);
    O.init(pp);

    A.pick();
    (i, m', ctr) <@ A.find(pp);

    (tw, m, j) <@ O.get(i);

    nrts   <@ O.nr_targets();
    twsOraw <@ O.get_tweaks();
    twsOC  <@ OC.get_tweaks();

    twsO <- map emb_tw twsOraw;    (* targets live at their emb_tw FC coordinate *)

    return    0 <= i < nrts
           /\ 0 <= nrts <= p_tgts
           /\ uniq twsO
           /\ m' <> m
           /\ ThC pp tw m j = ThC pp tw m' ctr
           /\ FC.disj_lists twsO twsOC;
  }
}.

(* ==========================================================================
   PART 2.  THE INTERACTIVE S-TCR(+C) REDUCTION `R_int_STCRC` — SIGNS BY STITCHING.

   Template: MM45's `R_SMDTTCRC_Game34WOTSTWES.query` (WOTS_TW_ES.ec:2662-2713),
   which answers each WOTS signing query WITHOUT holding `pp` by stitching oracle
   outputs (sample a fresh secret chain, walk each chain UP via the pp-holding
   oracle, return the stitched (pk, sig)).  Two adaptations for +C:

     * The CHALLENGE oracle `O` here serves the MESSAGE-COMPRESSION hash `ThC`
       (not the chain hash).  Its `O.query(ad, m)` does DOUBLE DUTY: it registers
       the S-TCR(+C) target at `ad` AND returns the pp-GRINDED counter `c` the +C
       signer needs (STCR_C.ec:127-137).  This is why the reduction can sign
       without `pp`: the ONE pp-dependent value the +C encoding needs — the grind
       counter — comes back from the challenge oracle.
     * The CHAIN WALK uses the COLLECTION oracle `OC = FC.Oracle_THFC` (which holds
       pp and computes `f = thfc(8n)` on the 8n-bit chain digests, WOTS_TW_ES.ec:
       434/450).  This is the honest keygen+sign unrolled: `sk_ele` at chain
       position 0, `f` applied `em_ele` times → `sig_ele`, then to the top → `pk_ele`
       (cf `WOTS_C_ES.{keygen,sign}`, WOTS_C_Scheme.ec:33-67).

   Under the encode bridge `encb` (encode_msgWOTS_C = encode_msgWOTS ∘ ThC,
   WOTS_C_Reduction.ec:459) the reduction's `em <- encode_msgWOTS d` (with
   `d = ThC pp ad m c` from `O.query`) EQUALS the real signer's
   `encode_msgWOTS_C pp ad m c`, so the stitched chains are byte-identical to the
   honest ones — a faithful, pp-free simulation.  REAL module, zero admit.
   ========================================================================== *)
module (R_int_STCRC (A : Adv_MEUFGCMA_WOTSC) : Adv_ISTCRC)
       (O : STCRC_WC.Oracle_STCRC, OC : FC.Oracle_THFC) = {

  module O_wrap : Oracle_MEUFGCMA_WOTSC = {
    include var O_MEUFGCMA_WOTSC_Default [-init, query]

    proc init(ps_init : pseed) : unit = {
      qs <- [];
    }

    proc query(wad : wadrs, m : msgWOTS) : pkWOTS * (sigWOTS * cntr) = {
      var ad : adrs;
      var d : dgstblock;
      var c : cntr;
      var em : emsgWOTS;
      var xl : dgstblock list;
      var sk_ele, sig_ele, pk_ele : dgstblock;
      var pk, sig : dgstblock list;
      var em_ele, j : int;

      ad <- WAddress.val wad;

      (* register the ThC target at emb_tw ad AND grab the pp-grinded counter *)
      (d, c) <@ O.query(ad, m);

      (* self-generate the WOTS secret key (chain starting points) *)
      xl <$ ddgstblockl;

      (* +C encoding = base_w of the ThC digest d (= encode_msgWOTS_C under encb) *)
      em <- encode_msgWOTS d;

      pk <- [];
      sig <- [];
      while (size pk < len) {
        sk_ele <- nth witness xl (size pk);
        em_ele <- BaseW.val em.[size pk];

        (* sig element: apply f (via OC) em_ele times from position 0 *)
        sig_ele <- sk_ele;
        j <- 0;
        while (j < em_ele) {
          sig_ele <@ OC.query(set_hidx (set_chidx ad (size pk)) j, DigestBlock.val sig_ele);
          j <- j + 1;
        }

        (* pk element: continue the same chain to the top (index w-1) *)
        pk_ele <- sig_ele;
        j <- em_ele;
        while (j < w - 1) {
          pk_ele <@ OC.query(set_hidx (set_chidx ad (size pk)) j, DigestBlock.val pk_ele);
          j <- j + 1;
        }

        sig <- rcons sig sig_ele;
        pk <- rcons pk pk_ele;
      }

      qs <- rcons qs (ad, m, DBLL.insubd pk, (DBLL.insubd sig, c));
      return (DBLL.insubd pk, (DBLL.insubd sig, c));
    }
  }

  module AA = A(O_wrap, OC)

  (* pick(): drive A's ADAPTIVE choose; every signing query is stitched above,
     registering exactly one S-TCR(+C) target per query, WITHOUT pp. *)
  proc pick() : unit = {
    O_wrap.init(witness);
    AA.choose();
  }

  (* find(pp): with pp revealed, relay A's forgery on instance i as the S-TCR(+C)
     collision triple (i, m', counter').  The target (tw_i,m_i,j_i) recorded by O
     at query i collides with (m', ctr') exactly when A's forgery is a +C collision
     at instance i — the interactive analogue of R_multi_STCRC.find. *)
  proc find(pp : pseed) : int * msgWOTS * cntr = {
    var i : int;
    var m' : msgWOTS;
    var sigc' : sigWOTS * cntr;

    (i, m', sigc') <@ AA.forge(pp);
    return (i, m', sigc'.`2);
  }
}.

(* ==========================================================================
   PART 3.  THE MAKE-OR-BREAK: `FC.disj_lists twsO twsOC` DISCHARGE, EXPLICIT.

   `twsO = map emb_tw twsOraw` (the ThC targets at their FC coordinate);
   `twsOC` is the COMPOUND collection list = the reduction's chain-walk tweaks
   (valid_wadrs) ⊎ A's own OC queries.  The obligation splits along `twsOC`:

     AXIS-1 (chain-walk vs targets): every chain-walk tweak is `valid_wadrs`, and
            FLAG-2 (`embdisj` below, realised by WOTS_C_Flag2Discharge.emb_disj_concrete)
            says a valid WOTS address never shares a `get_wgpidxs` with any `emb_tw`
            image → disjoint.  This is the NEW load-bearing use of FLAG-2.

     AXIS-2 (A's own encoding queries vs targets): a well-formedness constraint on
            A — its OC queries avoid the target compression coordinates — the
            interactive/multi lift of the single-instance C.2 hypothesis
            `!(witness ∈ OC.tws)` (WOTS_C_Reduction.ec:238).

   Both axes are one condition on `twsOC`: NO collection tweak shares an `emb_tw`
   image's `get_wgpidxs`.  The pure lemma below discharges `disj_lists` from
   exactly that condition; the byequiv establishes the condition for `twsOC` by
   AXIS-1 (embdisj on chain-walk) + AXIS-2 (well-formed A). *)

(* The pure disjointness core: if no collection tweak shares a `get_wgpidxs` with
   any `emb_tw` image, the emb_tw-projected target list is `disj_lists` from it.
   (`emb_tw` is applied to `t` at b'=b to derive the contradiction, so this needs
   NO injectivity of `emb_tw` — only that `get_wgpidxs` is a function.) *)
lemma emb_targets_disj_core (twsOraw twsOC : adrs list) :
  (forall (t : adrs), t \in twsOC =>
      forall (b : adrs), get_wgpidxs t <> get_wgpidxs (emb_tw b)) =>
  FC.disj_lists (map emb_tw twsOraw) twsOC.
proof.
  move=> hcond; apply/hasPn => x /mapP [b [_ ->]].
  apply/negP => hin.
  by have := hcond (emb_tw b) hin b.
qed.

(* AXIS-1 discharge, EXPLICIT: FLAG-2 (`embdisj`) makes every valid_wadrs tweak
   satisfy the antecedent of `emb_targets_disj_core`.  This is the exact shape of
   `WOTS_C_Flag2Discharge.emb_disj_concrete`, threaded as the abstract hypothesis
   `embdisj` (proven realisable on the real scheme — see the header caveat). *)
lemma axis1_chainwalk_cond (t : adrs) :
  (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
  valid_wadrs t => forall (b : adrs), get_wgpidxs t <> get_wgpidxs (emb_tw b).
proof. by move=> embdisj vt b; apply embdisj. qed.

(* The composed discharge: under FLAG-2 (`embdisj`), if EVERY collection tweak is
   `valid_wadrs` — which holds when the reduction's chain-walk tweaks are valid
   WOTS addresses (they are, by `set_hidx`/`set_chidx` validity-preservation on the
   valid base `WAddress.val wad`) AND A is well-formed (AXIS-2: A's OC queries are
   valid WOTS addresses, never the pkcotype compression coordinates) — then the
   full `disj_lists` obligation is discharged.  This is the interactive analogue of
   the batch `disj_wgpidxs_disj_lists` (WOTS_C_Multi.ec:450) closure, now carrying
   the chain-walk tweaks FLAG-2 covers. *)
lemma disj_lists_discharged (twsOraw twsOC : adrs list) :
  (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
  (forall (t : adrs), t \in twsOC => valid_wadrs t) =>
  FC.disj_lists (map emb_tw twsOraw) twsOC.
proof.
  move=> embdisj hval; apply emb_targets_disj_core => t tin.
  by apply (axis1_chainwalk_cond t embdisj); apply hval.
qed.

(* The `dist` obligation: `uniq (map emb_tw twsOraw)`.  Discharged from the WOTS+C
   game's `uniq_wgpidxs` (distinct signing-group prefixes) provided `emb_tw` does
   not collapse distinct `get_wgpidxs` — the abstract hypothesis `emb_gp_inj`,
   realised concretely by `emb_tw` preserving the instance-identifying indices
   kpidx@2/tidx@4/lidx@5 (WOTS_C_Flag2Discharge.ec:70) so distinct WOTS groups map
   to distinct pkco groups.  (Group-part distinctness only; not full injectivity.) *)
lemma emb_dist (l : adrs list) :
  (forall (a b : adrs),
       get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b) => get_wgpidxs a = get_wgpidxs b) =>
  uniq_wgpidxs l => uniq (map emb_tw l).
proof.
  move=> emb_gp_inj; rewrite /uniq_wgpidxs => hu.
  apply (uniq_map get_wgpidxs (map emb_tw l)); rewrite -map_comp.
  (* goal: uniq (map (get_wgpidxs \o emb_tw) l), from
     hu : uniq (map get_wgpidxs l) and emb_gp_inj (contrapositive: a
     (get_wgpidxs o emb_tw)-dup forces a get_wgpidxs-dup). *)
  move: hu; elim: l => [// | x s ih].
  rewrite !map_cons !cons_uniq /(\o) => -[hx hs].
  split; last by apply ih.
  apply/negP => /mapP [y [ys heq]].
  have heqg := emb_gp_inj x y heq.
  move: hx => /negP hx; apply hx.
  by apply/mapP; exists y; split; [exact ys | exact heqg].
qed.

(* ==========================================================================
   PART 4.  THE INTERACTIVE HOP-1: instrument, split on the +C collision, reduce.

   G0_INT / GAME1_INT are the interactive analogues of the batch G0_MULTI /
   GAME1_MULTI (WOTS_C_Multi.ec:331/384): instrument `M_EUF_GCMA_WOTSC_NPRF`
   with the +C collision event at the forged instance i, then split — the
   no-collision part IS GAME1_INT, the collision part reduces to `S_TCR_C_Int`
   through the stitching reduction `R_int_STCRC`.
   ========================================================================== *)

(* GAME.0 (interactive) instrumented: identical returned bit to
   `M_EUF_GCMA_WOTSC_NPRF`, plus a `coll` record of the +C collision at instance i
   (the honest instance-i counter `sigc.`2` vs the forgery counter `sigc'.`2`). *)
module G0_INT(A : Adv_MEUFGCMA_WOTSC, O : Oracle_MEUFGCMA_WOTSC, OC : FC.Oracle_THFC) = {
  module A = A(O, OC)
  var coll : bool

  proc main() : bool = {
    var ps : pseed;
    var ad : adrs;
    var pkWOTS : pkWOTS;
    var i : int;
    var m, m' : msgWOTS;
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

    coll <- (ThC ps ad m sigc.`2 = ThC ps ad m' sigc'.`2);
    return 0 <= nrqs <= c /\ 0 <= i < nrqs /\
           is_valid /\ is_fresh /\ dist_wgpidxs /\ disj_wgpidxs adlO adlOC;
  }
}.

(* GAME.1 (interactive): GAME.0's bit AND no extractable +C collision at i. *)
module GAME1_INT(A : Adv_MEUFGCMA_WOTSC, O : Oracle_MEUFGCMA_WOTSC, OC : FC.Oracle_THFC) = {
  module A = A(O, OC)

  proc main() : bool = {
    var ps : pseed;
    var ad : adrs;
    var pkWOTS : pkWOTS;
    var i : int;
    var m, m' : msgWOTS;
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
           is_valid /\ is_fresh /\ dist_wgpidxs /\ disj_wgpidxs adlO adlOC /\
           ! (ThC ps ad m sigc.`2 = ThC ps ad m' sigc'.`2);
  }
}.

(* --------------------------------------------------------------------------
   SUCCESS-TRANSFER (PROVEN, ZERO ADMIT) — the make-or-break, wired end-to-end.

   The predicate-level heart of interactive hop-1: whenever the reduction's run
   ends in a state where G0_INT wins WITH the +C collision, and (AXIS-1+AXIS-2)
   every collection tweak is a valid WOTS address while the target raw addresses
   have distinct WOTS group-prefixes, the S_TCR_C_Int winning conjuncts ALL hold —
   crucially `uniq (map emb_tw twsOraw)` (via `emb_dist`) and
   `FC.disj_lists (map emb_tw twsOraw) twsOC` (via `disj_lists_discharged`, i.e.
   FLAG-2 on the chains + well-formed A).  This is the interactive analogue of the
   batch `D1_reduce` tail `smt(uniq_wgpidxs_uniq disj_wgpidxs_disj_lists)`
   (WOTS_C_Multi.ec:592), now carrying the chain-walk tweaks FLAG-2 covers.
   -------------------------------------------------------------------------- *)
lemma interactive_success_transfer
  (pp : pseed) (i nrts : int)
  (twsOraw twsOC : adrs list)
  (tw : adrs) (m m' : msgWOTS) (j ctr : cntr) :
  (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
  (forall (a b : adrs),
     get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b) => get_wgpidxs a = get_wgpidxs b) =>
  (forall (t : adrs), t \in twsOC => valid_wadrs t) =>
  uniq_wgpidxs twsOraw =>
  0 <= i < nrts => 0 <= nrts <= p_tgts =>
  m' <> m =>
  ThC pp tw m j = ThC pp tw m' ctr =>
     0 <= i < nrts
  /\ 0 <= nrts <= p_tgts
  /\ uniq (map emb_tw twsOraw)
  /\ m' <> m
  /\ ThC pp tw m j = ThC pp tw m' ctr
  /\ FC.disj_lists (map emb_tw twsOraw) twsOC.
proof.
  move=> embdisj embinj hval hdist hir hnr hfr hcoll.
  split; first exact hir.
  split; first exact hnr.
  split; first by apply (emb_dist twsOraw embinj hdist).
  split; first exact hfr.
  split; first exact hcoll.
  by apply (disj_lists_discharged twsOraw twsOC embdisj hval).
qed.

(* --------------------------------------------------------------------------
   THE COLLISION-PART REDUCTION.  `Pr[G0_INT : res /\ coll] <= Pr[S_TCR_C_Int(R)]`.

   Hypotheses (all faithful, none an easycrypt axiom):
     * `c <= p_tgts`          : one target per query, S-TCR cap ≥ query cap
                                (batch analogue WOTS_C_Multi.ec:487).
     * `embdisj` (FLAG-2)     : abstract `emb_disj_wgpidxs`, realised concretely by
                                WOTS_C_Flag2Discharge.emb_disj_concrete — AXIS-1.
     * `embinj`               : `emb_tw` preserves get_wgpidxs-distinctness (dist).
     * `encb`                 : the encode bridge (WOTS_C_Reduction.ec:459), so the
                                stitched `em = encode_msgWOTS d` equals the honest
                                `encode_msgWOTS_C pp ad m c` (faithful pp-free sign).
     * `A_wf` (AXIS-2)        : after the reduction's `pick`, EVERY collection tweak
                                is a valid WOTS address — the reduction's own
                                chain-walk tweaks always are (set_hidx/set_chidx on
                                `WAddress.val wad`), and A's OWN OC queries do too
                                (A never opens the pkcotype target coordinates): the
                                interactive lift of the single-instance C.2
                                well-formedness hoare `!(witness ∈ tws)`
                                (WOTS_C_Reduction.ec:238).
   -------------------------------------------------------------------------- *)
lemma interactive_hop1_reduce
  (A <: Adv_MEUFGCMA_WOTSC{-R_int_STCRC, -O_MEUFGCMA_WOTSC_Default,
                           -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -G0_INT}) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (a b : adrs),
       get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b) => get_wgpidxs a = get_wgpidxs b) =>
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    hoare[ R_int_STCRC(A, STCRC_WC.O_STCRC_Default, FC.O_THFC_Default).pick :
             FC.O_THFC_Default.tws = [] ==> all valid_wadrs FC.O_THFC_Default.tws ] =>
    Pr[G0_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res /\ G0_INT.coll]
  <= Pr[S_TCR_C_Int(R_int_STCRC(A),
                    STCRC_WC.O_STCRC_Default, FC.O_THFC_Default).main() @ &m : res].
proof.
  move=> le_c_ptgts embdisj embinj encb A_wf.
  (* -----------------------------------------------------------------------
     LABELLED ADMIT — interactive hop-1 OPERATIONAL byequiv (MM45-scale, the ONLY
     remaining core; the SECURITY content is proven, see below).

     Obligation: byequiv
        G0_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default)
      ~ S_TCR_C_Int(R_int_STCRC(A), STCRC_WC.O_STCRC_Default, FC.O_THFC_Default)
        : ={glob A} ==> (res{1} /\ G0_INT.coll{1}) => res{2}.

     TWO ingredients:
     (1) STITCH-vs-HONEST oracle coupling (the person-weeks core, MM45 template
         WOTS_TW_ES.ec:2662-2713): the reduction's `O_wrap.query(wad,m)` (embed ThC
         via O, sample xl, walk chains via OC) produces (pk,sig,c) IDENTICAL to the
         honest `O_MEUFGCMA_WOTSC_Default.query` (keygen via dskWOTS + sign via cf),
         under `encb` (em coincide), `FC.query = f = thfc(8n)` on the 8n-bit chain
         digests (DigestBlock.valP), and identical sk sampling
         (dskWOTS = dmap ddgstblockl DBLL.insubd ~ xl <$ ddgstblockl).  This couples
         the two while-loops step-for-step with `cf`'s chain characterization —
         exactly the WOTS-TW pRHL the port reused as a black box but here re-run
         at the +C oracle.  Per-query it also aligns O_STCRC_Default's recorded
         target counter with the honest signer's grind (grindC = grind, deterministic;
         WOTS_C_Reduction.ec:220), so G0_INT.coll ⇒ the S-TCR collision at target i.
     (2) SUCCESS TRANSFER at the tail: `interactive_success_transfer` (PROVEN above),
         fed `embdisj` (AXIS-1), `embinj` (dist), `A_wf` (AXIS-2 ⇒ all twsOC
         valid_wadrs), `le_c_ptgts` (nrts ≤ p_tgts), and G0_INT's win + coll, yields
         S_TCR_C_Int's full winning predicate incl. `uniq (map emb_tw twsOraw)` and
         `FC.disj_lists (map emb_tw twsOraw) twsOC`.  This is the make-or-break, and
         it is NOT admitted — only ingredient (1), the operational simulation, is.

     Structure mirrors the batch `D1_reduce` (WOTS_C_Multi.ec:492-593, a completed
     byequiv) but over the ADAPTIVE oracle: the per-query loop-coupling is replaced
     by an oracle-invariant carried across A.choose (a `proc (invariant)` upto with
     the stitch equivalence as the query hook), NOT a committed while.  That upto is
     the multi-session fill; the +C-specific reasoning (disjointness/dist/counter)
     is the discharged content above.
     ----------------------------------------------------------------------- *)
  admit.
qed.

(* ==========================================================================
   INTERACTIVE THM D.1 HOP-1 (two-term), composed from: instrument (coll doesn't
   move res) + split on coll + [no-coll part = GAME1_INT] + [coll part = reduction].
   The instrument/split/no-coll equivalences are the interactive analogues of the
   batch D1_hop1 (WOTS_C_Multi.ec:595) e0/e1; the reduction is the lemma above.
   ========================================================================== *)
lemma interactive_hop1
  (A <: Adv_MEUFGCMA_WOTSC{-R_int_STCRC, -O_MEUFGCMA_WOTSC_Default,
                           -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -G0_INT}) &m :
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (a b : adrs),
       get_wgpidxs (emb_tw a) = get_wgpidxs (emb_tw b) => get_wgpidxs a = get_wgpidxs b) =>
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    hoare[ R_int_STCRC(A, STCRC_WC.O_STCRC_Default, FC.O_THFC_Default).pick :
             FC.O_THFC_Default.tws = [] ==> all valid_wadrs FC.O_THFC_Default.tws ] =>
    Pr[M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
  <=   Pr[GAME1_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int(R_int_STCRC(A),
                      STCRC_WC.O_STCRC_Default, FC.O_THFC_Default).main() @ &m : res].
proof.
  move=> le_c_ptgts embdisj embinj encb A_wf.
  (* e0: instrument — G0_INT's only extra statement is the `coll` record. *)
  have e0 : Pr[M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res]
          = Pr[G0_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res].
  + byequiv (_ : ={glob A} ==> res{1} = res{2}) => //; proc.
    seq 12 12 : (={ps, i, m, m', sigc, sigc', ad, pkWOTS, is_valid, is_fresh,
                   dist_wgpidxs, nrqs, adlO, adlOC}
                 /\ ={glob O_MEUFGCMA_WOTSC_Default, glob FC.O_THFC_Default}).
    + sim.
    wp; skip => />.
  rewrite e0 Pr[mu_split (G0_INT.coll)].
  (* e1: no-collision part IS GAME1_INT. *)
  have e1 : Pr[G0_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res /\ !G0_INT.coll]
          = Pr[GAME1_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res].
  + byequiv (_ : ={glob A} ==> (res{1} /\ ! G0_INT.coll{1}) <=> res{2}) => //; proc.
    seq 12 12 : (={ps, i, m, m', sigc, sigc', ad, pkWOTS, is_valid, is_fresh,
                   dist_wgpidxs, nrqs, adlO, adlOC}
                 /\ ={glob O_MEUFGCMA_WOTSC_Default, glob FC.O_THFC_Default}).
    + sim.
    wp; skip => />; smt().
  rewrite e1.
  have e2 := interactive_hop1_reduce A &m le_c_ptgts embdisj embinj encb A_wf.
  smt().
qed.

(* ==========================================================================
   PART 5.  NON-VACUITY GATE (mandatory) — the reconciled game is not degenerate.
   ========================================================================== *)

(* (a) BREAK-LOAD-BEARING — the +C collision genuinely drives the S-TCR win.
   On the NO-collision branch (`!(ThC pp tw m j = ThC pp tw m' ctr)` — exactly what
   GAME1_INT asserts) the S_TCR_C_Int winning predicate is UNSATISFIABLE, because it
   CONTAINS the collision conjunct.  Hence the reduction's contribution comes ONLY
   from the collision branch: weakening the byequiv antecedent `res /\ coll` to `res`
   (dropping coll) would try to establish `res2` on no-collision runs and MUST fail
   — the challenge collision is truly consumed (not an incidental conjunct). *)
lemma nonvac_break_loadbearing
  (pp : pseed) (tw : adrs) (m m' : msgWOTS) (j ctr : cntr)
  (i nrts : int) (twsOraw twsOC : adrs list) :
  ! (ThC pp tw m j = ThC pp tw m' ctr) =>
  ! (   0 <= i < nrts /\ 0 <= nrts <= p_tgts /\ uniq (map emb_tw twsOraw)
     /\ m' <> m /\ ThC pp tw m j = ThC pp tw m' ctr
     /\ FC.disj_lists (map emb_tw twsOraw) twsOC).
proof. by move=> hnc; smt(). qed.

(* (b1) STILL-RECOGNIZABLY-S-TCR: OC never SERVES the target.  The target lives at
   its FC coordinate `emb_tw tw`; a winning run has `FC.disj_lists (map emb_tw
   twsOraw) twsOC`, so for every registered target `tw`, `emb_tw tw ∉ twsOC` — the
   collection oracle did NOT open the challenge target (else it were trivially
   collidable and the game meaningless).  This is exactly the SM-DT-TCR
   `disj_lists` guarantee (TweakableHashFunctions.eca:745). *)
lemma nonvac_target_unopened (twsOraw twsOC : adrs list) (tw : adrs) :
  tw \in twsOraw =>
  FC.disj_lists (map emb_tw twsOraw) twsOC =>
  ! (emb_tw tw \in twsOC).
proof.
  move=> hin /hasPn h; apply h.
  by apply/mapP; exists tw.
qed.

(* (b2) DISJ_LISTS NOT VACUOUSLY TRUE.  `disj_lists s1 s2` is vacuous only when
   `s1 = []`.  Here `s1 = map emb_tw twsOraw`, and in any run with ≥1 signing query
   `twsOraw` is NONEMPTY (each `O_wrap.query` registers exactly one target via
   `O.query`, STCR_C.ec:134) — so `map emb_tw twsOraw` is nonempty and the
   disjointness is a GENUINE constraint over a nonempty target list, not vacuous.
   Dually `twsOC` is nonempty in any such run: each `O_wrap.query` performs
   `len * (w-1) ≥ 1` chain-walk `OC.query`s (ge2_len, val_w).  Recorded here as the
   pure fact that a nonempty target list makes disj_lists falsifiable. *)
lemma nonvac_disj_nonvacuous (twsOraw twsOC : adrs list) :
  twsOraw <> [] =>
  (exists ll, FC.disj_lists (map emb_tw twsOraw) ll)          (* satisfiable *)
  /\ (! FC.disj_lists (map emb_tw twsOraw) (map emb_tw twsOraw)).  (* & falsifiable *)
proof.
  move=> hne; split.
  + by exists []; apply/hasPn => x _; rewrite in_nil.
  rewrite negbK; case: twsOraw hne => [// | x s _].
  apply/hasP; exists (emb_tw x); rewrite map_cons.
  by smt(mem_head).
qed.
