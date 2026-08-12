(* ==========================================================================
   prf_hop_wip.ec -- The NPRF -> PRF hop (SKG / secret-key-generation) for the
   WOTS+C hypertree, ITEM 4 of the SPHINCS+C EUF-CMA port.

   WHY THIS FILE EXISTS
   --------------------
   The consolidated component theorem `EUFNAGCMA_FLSLXMSSMTTWCESNPRF`
   (drafts/XmssmtCC_All.ec) bounds the EUF-NAGCMA advantage of the WOTS+C
   hypertree in the *NPRF* game `EUF_NAGCMA_FLSLXMSSMTTWCESNPRF`, whose keygen
   samples the ENTIRE WOTS secret-key cube UNIFORMLY (`skWOTS_ele <$ ddgstblock`,
   XmssmtCC_All.ec:189).  The REAL scheme `FL_SL_XMSS_MT_C_ES`
   (drafts/XMSSMT_C_Scheme.ec) instead DERIVES those keys with the secret-key
   generation PRF `skg` (via `WOTS_TW_ES.gen_skWOTS`, which computes
   `skg ss (ps, set_hidx (set_chidx ad i) 0)`).  To make the component-theorem
   bound account for the real scheme, this file adds the SKG PRF hop: it pays one
   `SKG_PRF`-distinguishing term to replace the uniform cube with the skg-derived
   cube.

   TEMPLATE (ported, +C-invariant): MM45's full-scheme SKG hop, i.e.
     - reduction module   R_SKGPRF_EUFCMA          SPHINCS_PLUS.ec:1063-1211
     - PRF assumption      SKG_PRF = SKG.PRF        (KeyedHashFunctions.eca:1585,
                                                     cloned at SPHINCS_PLUS.ec:401)
     - advantage equality  EqAdv_...PRFPRF_NPRFPRF_SKGPRF  SPHINCS_PLUS.ec:2668
   Key generation is UNTOUCHED by +C (WOTS keygen is identical; the +C deltas are
   the per-layer counter in sign and the constant-sum gate in verify, neither of
   which touches skg), so the reduction body ports with scheme-name substitution.

   SCOPE HONESTY (what this hop DOES and DOES NOT cover)
   ----------------------------------------------------
   * IN SCOPE -- the WOTS/SKG hop AT THE HYPERTREE LEVEL.  This is exactly the
     level the component theorem lives at.  The hop is stated between the two
     hypertree games and proved via a hypertree-specialised R_SKGPRF (WOTS keys
     only, no FORS keys).
   * MKG IS NOT APPLICABLE HERE.  MM45's message-key-generation PRF hop (R_MKGPRF,
     term `mkg`) is a SCHEME-level term: `mkg` is queried in SPHINCS+ signing to
     derive the message key, and neither the hypertree game
     `EUF_NAGCMA_FLSLXMSSMTTWCESNPRF` nor the hypertree module
     `FL_SL_XMSS_MT_C_ES{,_NPRF}` references `mkg`/`mseed` at all (verified: `mkg`
     occurs in XmssmtCC_All.ec only inside the FORS/R_top scheme region, :9392+).
     So there is NO MKG term to pay at this level; it is deferred WITH the full
     scheme, NOT silently omitted.
   * DOES NOT YET COMPOSE TO A FULL-SCHEME PRF HOP.  A scheme-level SKG hop must
     additionally cover the FORS+C secret keys (same `skg`, different -- trhftype
     -- addresses), which are a SEPARATE port item (FORS+C).  It also pairs with
     the deferred MKG term.  So the bound proved here is precisely the hypertree's
     WOTS-key-derivation hop; reading it as the scheme-level SKG term would be
     wrong until FORS+C is wired.
   * MATERIALIZATION BRIDGE (separate, deferred).  This hop compares two
     *materialized-cube* games (PRF-cube vs NPRF-cube).  Tying the PRF-cube game
     to the literal on-demand REAL scheme `FL_SL_XMSS_MT_C_ES` (which re-derives
     each WOTS key inside `sign` rather than storing a cube) is a deterministic
     recomputation equivalence -- the exact analog of MM45's
     `Eqv_EUF_CMA_SPHINCSPLUSTW_Orig_FSPRFPRF` (SPHINCS_PLUS.ec:2243) -- and is
     deliberately kept OUT of this hop lemma.  `skg` is deterministic in `ss`, so
     the materialized cube and the on-demand derivations coincide; that bridge is
     stated as a named TODO below, not proved here.

   STATUS: see the GATE RECORD at the bottom.
   ========================================================================== *)

require import AllCore List Distr StdBigop StdOrder IntDiv.
require import FMap.
require import DList DMap.
require import BinaryTrees MerkleTrees.
require import BitEncoding.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.

import BS2Int.
(*---*) import StdOrder.IntOrder StdBigop.Bigint StdBigop.Bigint.BIA.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.


(* --------------------------------------------------------------------------
   STEP 1: the PRF-keyed hypertree keygen + game.

   `FL_SL_XMSS_MT_C_ES_PRF` is BYTE-IDENTICAL to `FL_SL_XMSS_MT_C_ES_NPRF`
   (XmssmtCC_All.ec:146) EXCEPT that its keygen's innermost cube element is the
   skg-derived value `skg ss (ps, <the WOTS chain address>)` instead of the
   uniform sample `<$ ddgstblock`.  `ss` is drawn once from `dsseed`.  The chain
   address is MM45's exact expression
     set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad layer tree) chtype)
                          leaf) chain) 0
   i.e. `gen_skWOTS` unrolled (WOTS_TW_ES.ec:2039).  sign/verify are ALIASED to
   the NPRF module, so the two games differ ONLY in keygen -- every other
   statement is identical and discharges by `sim` in both hop legs.
   -------------------------------------------------------------------------- *)
module FL_SL_XMSS_MT_C_ES_PRF = {
  proc keygen(ps : pseed, ad : adrs) : pkFLSLXMSSMTTW * (skWOTS list list list * pseed * adrs) = {
    var root : dgstblock;
    var ss : sseed;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var pk : pkFLSLXMSSMTTW;
    var sk : skWOTS list list list * pseed * adrs;

    ss <$ dsseed;

    skWOTStd <- [];
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        while (size skWOTSlp < l') {
          skWOTS <- [];
          while (size skWOTS < len) {
            skWOTS_ele <- skg ss (ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) (size skWOTS)) 0);
            skWOTS <- rcons skWOTS skWOTS_ele;
          }
          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
        }
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
    }

    skWOTSlp <- nth witness (nth witness skWOTStd (d - 1)) 0;
    leaves <@ FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (d - 1) 0);

    root <- val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhxtype) (list2tree leaves);

    pk <- (root, ps, ad);
    sk <- (skWOTStd, ps, ad);

    return (pk, sk);
  }

  proc sign   = FL_SL_XMSS_MT_C_ES_NPRF.sign
  proc verify = FL_SL_XMSS_MT_C_ES_NPRF.verify
}.

(* EUF-NAGCMA for the WOTS+C hypertree with PRF-DERIVED (skg) keys.  Identical to
   `EUF_NAGCMA_FLSLXMSSMTTWCESNPRF` (XmssmtCC_All.ec:278) except the keygen call.
   Same adversary interface (`Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF`). *)
module EUF_NAGCMA_FLSLXMSSMTTWCESPRF (A : Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF, OC : FSSLXMTWES.TRHC.Oracle_THFC) = {
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

    ad <- adz;
    ps <$ dpseed;

    OC.init(ps);

    ml <@ A(OC).choose();

    (pk, sk) <@ FL_SL_XMSS_MT_C_ES_PRF.keygen(ps, ad);

    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);
      sig <@ FL_SL_XMSS_MT_C_ES_PRF.sign(sk, m, Index.insubd (size sigl));
      sigl <- rcons sigl sig;
    }

    (m', sig', idx') <@ A(OC).forge(pk, sigl);

    is_valid <@ FL_SL_XMSS_MT_C_ES_PRF.verify(pk, m', sig', idx');

    is_fresh <- m' <> nth witness ml (Index.val idx');

    return is_valid /\ is_fresh;
  }
}.


(* --------------------------------------------------------------------------
   STEP 2: the reduction to SKG PRF.

   `R_SKGPRF_FLSLXMSSMTC(A)` is an `SKG_PRF.Adv_PRF`.  It reproduces the hypertree
   EUF-NAGCMA game, but builds the WOTS cube by QUERYING the PRF oracle `O` at
   each chain address instead of keygen's sampling/derivation.  Because the game
   is NON-adaptive (the adversary commits messages in `choose`, is handed the
   signatures, then forges), the reduction needs NO module variables -- unlike
   MM45's adaptive `R_SKGPRF_EUFCMA`, whose signing oracle forced module state.
   The tweakable-hash oracle handed to `A` is the game's own `FC.O_THFC_Default`.

     b = false : O.query(ps, x) = skg k x  (k <$ dsseed)  => cube = skg cube
                 => distinguish reproduces EUF_NAGCMA_...PRF (with ss = k).
     b = true  : O.query lazily samples a fresh ddgstblock per NEW address into a
                 map; all cube addresses are DISTINCT (distinct (layer,tree,leaf,
                 chain) => distinct adrs, via eq_adrs_idxs), so lazy = eager
                 => distinguish reproduces EUF_NAGCMA_...NPRF.
   -------------------------------------------------------------------------- *)
module (R_SKGPRF_FLSLXMSSMTC (A : Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF) (OC : FSSLXMTWES.TRHC.Oracle_THFC) : SKG_PRF.Adv_PRF) (O : SKG_PRF.Oracle_PRF) = {
  proc distinguish() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pk : pkFLSLXMSSMTTW;
    var root : dgstblock;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var ml : msgFLSLXMSSMTTW list;
    var sigl : sigFLSLXMSSMTTWC list;
    var m, m' : msgFLSLXMSSMTTW;
    var sig, sig' : sigFLSLXMSSMTTWC;
    var idx' : index;
    var is_valid, is_fresh : bool;

    ad <- adz;
    ps <$ dpseed;

    OC.init(ps);

    ml <@ A(OC).choose();

    (* Build the WOTS cube from the PRF oracle at the WOTS chain addresses. *)
    skWOTStd <- [];
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        while (size skWOTSlp < l') {
          skWOTS <- [];
          while (size skWOTS < len) {
            skWOTS_ele <@ O.query(ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) (size skWOTS)) 0);
            skWOTS <- rcons skWOTS skWOTS_ele;
          }
          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
        }
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
    }

    skWOTSlp <- nth witness (nth witness skWOTStd (d - 1)) 0;
    leaves <@ FL_SL_XMSS_MT_C_ES_NPRF.leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (d - 1) 0);
    root <- val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhxtype) (list2tree leaves);
    pk <- (root, ps, ad);

    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);
      sig <@ FL_SL_XMSS_MT_C_ES_NPRF.sign((skWOTStd, ps, ad), m, Index.insubd (size sigl));
      sigl <- rcons sigl sig;
    }

    (m', sig', idx') <@ A(OC).forge(pk, sigl);

    is_valid <@ FL_SL_XMSS_MT_C_ES_NPRF.verify(pk, m', sig', idx');
    is_fresh <- m' <> nth witness ml (Index.val idx');

    return is_valid /\ is_fresh;
  }
}.


(* --------------------------------------------------------------------------
   STEP 3: the hop.

   `EqPr_PRF_false`  : PRF-game  = PRF(R).main(false)   [b=false leg]
   `EqPr_NPRF_true`  : NPRF-game = PRF(R).main(true)    [b=true  leg]
   `SKGPRF_hop`      : PRF-game <= NPRF-game + |PRF(false) - PRF(true)|
   `SKGPRF_hop_composed` : PRF-game <= (component-theorem bound) + |PRF term|

   The two byequiv legs are the porting work; the hop and composition are pure
   arithmetic on top of them and the in-scope component theorem.
   -------------------------------------------------------------------------- *)

(* b = false leg.  OC kept ABSTRACT (adversary-call rule needs an abstract
   oracle); instantiated to FC.O_THFC_Default only in the composition. *)
lemma EqPr_PRF_false
  (A  <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -SKG_PRF.O_PRF_Default })
  (OC <: FSSLXMTWES.TRHC.Oracle_THFC{ -A, -SKG_PRF.O_PRF_Default }) &m :
  Pr[EUF_NAGCMA_FLSLXMSSMTTWCESPRF(A, OC).main() @ &m : res]
  =
  Pr[SKG_PRF.PRF(R_SKGPRF_FLSLXMSSMTC(A, OC), SKG_PRF.O_PRF_Default).main(false) @ &m : res].
proof.
(* ------------------------------------------------------------------------
   PROOF (b=false leg).  `byequiv` in four parts.

   The pinch: the reduction fills its cube from `O_PRF_Default` (an O_PRF-GLOBAL
   key k, one-sided flag b=false), while the PRF game samples ss into a keygen
   LOCAL, and the non-adaptive game runs the ABSTRACT `OC.init` + `A.choose`
   BEFORE keygen.  `sim` carries only relational equalities; the direct abstract
   `OC.init` rejects `call (: ={glob OC})` (documented at XmssmtCC_All.ec:4683);
   so neither ss{1}=k{2} (LOCAL=GLOBAL) nor !b{2} (one-sided) can be carried
   across the abstract prefix by sim.

   Resolution (no fact ever crosses OC.init):
   1. swap{2} the RHS init block [b_init<-b; O_PRF.b<-; O_PRF.k<$; O_PRF.m<-empty]
      DOWN past the abstract prefix, so the coupling is set up AT the cube
      (standard early-vs-late sampling swap).
   2. prefix `seq 4 4`: ad<-adz; ps<$dpseed; OC.init; A.choose is now purely
      relational -> `sim`, EXCEPT b{2}=false, which is carried by a 3-arg conseq
      splitting off a side-2 hoare `b=false ==> b=false` (frame; the fragment
      never touches b) -- the Reprogramming.ec:312 idiom.
   3. coupling `seq 3 4`: couple ss{1} ~ O_PRF.k{2} (identity rnd), derive
      !O_PRF.b{2} from b{2}=false, at the cube boundary.
   4. cube `seq 8 6`: 4 nested whiles; innermost inline{2} O.query; rcondf{2}
      (b=false) => query = skg k; carries ss{1}=k{2} so the cube elements match.
   5. tail: explicit sign-loop while for the cross-form sk{1}=(skWOTStd,ps,ad){2}
      (PRF.sign = NPRF.sign alias), then wp; sim for forge/verify/fresh. *)
byequiv => //.
proc.
inline{1} FL_SL_XMSS_MT_C_ES_PRF.keygen.
inline{2} 1.
inline{2} R_SKGPRF_FLSLXMSSMTC(A, OC, SKG_PRF.O_PRF_Default).distinguish.
(* Move RHS init block (b_init<-b; O_PRF.b<-; O_PRF.k<$dsseed; O_PRF.m<-empty)
   down past the abstract prefix (ad<-adz; ps<$dpseed; OC.init; A.choose) so the
   coupling ss{1}=k{2} /\ !b{2} is established at the cube -- no one-sided fact
   ever has to cross the direct OC.init call. *)
swap{2} [1..4] 4.
seq 4 4 : (={ml, glob A, glob OC, ps, ad} /\ b{2} = false).
- conseq (: _ ==> ={ml, glob A, glob OC, ps, ad}) _ (: b = false ==> b = false).
  + by move=> />.
  + call (: true).
    + by auto.
    + by call (: true); auto.
  + by sim.
(* COUPLING: establish ss{1}=k{2} /\ !b{2} at the cube boundary.
   LHS: ps0<-ps; ad0<-ad; ss<$dsseed   RHS: b_init<-b; O_PRF.b<-b_init; O_PRF.k<$dsseed; O_PRF.m<-empty *)
seq 3 4 : (   ={ml, glob A, glob OC} /\ ps0{1} = ps{2} /\ ad0{1} = ad{2}
           /\ ss{1} = SKG_PRF.O_PRF_Default.k{2} /\ ! SKG_PRF.O_PRF_Default.b{2}).
- wp; rnd; wp; skip => />.
(* CUBE + leaves/root/pk: relate the skg-derived cube (LHS) to the O.query cube
   (RHS, b=false => query = skg k). *)
seq 8 6 : (   ={ml, pk, glob A, glob OC} /\ sk{1} = (skWOTStd{2}, ps{2}, ad{2})).
- wp.
  call (: ={arg} ==> ={res}); 1: by sim.
  wp.
  while (   ={ml, glob A, glob OC, skWOTStd} /\ ss{1} = SKG_PRF.O_PRF_Default.k{2}
         /\ ! SKG_PRF.O_PRF_Default.b{2} /\ ps0{1} = ps{2} /\ ad0{1} = ad{2}).
  + wp.
    while (   ={ml, glob A, glob OC, skWOTStd, skWOTSnt} /\ ss{1} = SKG_PRF.O_PRF_Default.k{2}
           /\ ! SKG_PRF.O_PRF_Default.b{2} /\ ps0{1} = ps{2} /\ ad0{1} = ad{2}).
    * wp.
      while (   ={ml, glob A, glob OC, skWOTStd, skWOTSnt, skWOTSlp} /\ ss{1} = SKG_PRF.O_PRF_Default.k{2}
             /\ ! SKG_PRF.O_PRF_Default.b{2} /\ ps0{1} = ps{2} /\ ad0{1} = ad{2}).
      + wp.
        while (   ={ml, glob A, glob OC, skWOTStd, skWOTSnt, skWOTSlp, skWOTS} /\ ss{1} = SKG_PRF.O_PRF_Default.k{2}
               /\ ! SKG_PRF.O_PRF_Default.b{2} /\ ps0{1} = ps{2} /\ ad0{1} = ad{2}).
        * inline{2} SKG_PRF.O_PRF_Default.query.
          rcondf{2} 2; 1: by auto.
          by auto.
        by auto.
      by auto.
    by auto.
  by auto.
(* TAIL: the sign loop carries the cross-form sk{1}=(skWOTStd,ps,ad){2}
   (PRF.sign = NPRF.sign alias); forge/verify/fresh are relational. *)
seq 2 2 : (={ml, pk, sigl, glob A, glob OC}).
- while (   ={ml, sigl, pk, glob A, glob OC}
         /\ sk{1} = (skWOTStd{2}, ps{2}, ad{2})).
  + wp.
    call (: ={arg} ==> ={res}); 1: by sim.
    by auto.
  by auto.
wp.
sim.
qed.

(* b = true leg. *)
lemma EqPr_NPRF_true
  (A  <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -SKG_PRF.O_PRF_Default })
  (OC <: FSSLXMTWES.TRHC.Oracle_THFC{ -A, -SKG_PRF.O_PRF_Default }) &m :
  Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A, OC).main() @ &m : res]
  =
  Pr[SKG_PRF.PRF(R_SKGPRF_FLSLXMSSMTC(A, OC), SKG_PRF.O_PRF_Default).main(true) @ &m : res].
proof.
(* BYEQUIV LEG (b=true): eager uniform cube (NPRF) ~ R with a lazy random-function
   oracle.  Port of SPHINCS_PLUS.ec:2746-2899 (true side), WOTS-only (FORS disjunct
   dropped).  Setup is the mirror of the false leg (b=true; the one-sided k<$dsseed
   is a dead throwaway rnd{2}; O.m starts empty and seeds the cube domain invariant). *)
byequiv => //.
proc.
inline{1} FL_SL_XMSS_MT_C_ES_NPRF.keygen.
inline{2} 1.
inline{2} R_SKGPRF_FLSLXMSSMTC(A, OC, SKG_PRF.O_PRF_Default).distinguish.
swap{2} [1..4] 4.
seq 4 4 : (={ml, glob A, glob OC, ps, ad} /\ ad{2} = adz /\ b{2} = true).
- conseq (: _ ==> ={ml, glob A, glob OC, ps, ad}) _ (: b = true ==> ad = adz /\ b = true).
  + by move=> />.
  + call (: true).
    + by auto.
    + by call (: true); auto.
  + by sim.
(* init: LHS ps0<-ps; ad0<-ad; skWOTStd<-[]   RHS b_init<-b; O_PRF.b<-; O_PRF.k<$; O_PRF.m<-empty; skWOTStd<-[] *)
seq 3 5 : (   ={ml, glob A, glob OC, skWOTStd} /\ ps0{1} = ps{2} /\ ad0{1} = ad{2}
           /\ ad{2} = adz /\ skWOTStd{2} = []
           /\ SKG_PRF.O_PRF_Default.b{2} /\ SKG_PRF.O_PRF_Default.m{2} = empty).
- wp; rnd{2}; wp; skip => />; smt(dsseed_ll).
(* CUBE: eager uniform cube (LHS NPRF) ~ lazy random-function O.query (RHS b=true).
   Each queried WOTS chain address is FRESH in O.m (rcondt via address-injectivity),
   so the lazy draw = the NPRF eager draw.  Domain invariant mirrors MM45's mdom
   disjunction, WOTS-only (no FORS family). *)
seq 7 5 : (   ={ml, pk, glob A, glob OC} /\ sk{1} = (skWOTStd{2}, ps{2}, ad{2})).
- wp.
  call (: ={arg} ==> ={res}); 1: by sim.
  wp.
  while (   ={ml, glob A, glob OC, skWOTStd}
         /\ ps0{1} = ps{2} /\ ad0{1} = ad{2} /\ ad{2} = adz
         /\ SKG_PRF.O_PRF_Default.b{2}
         /\ (forall (psad : pseed * adrs),
              psad \in SKG_PRF.O_PRF_Default.m{2}
              <=>
              (exists (i j u v : int),
                 0 <= i < size skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\
                 psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0)))
         /\ size skWOTStd{1} <= d).
  + wp => /=.
    while (   ={skWOTSnt}
           /\ ad{2} = adz /\ SKG_PRF.O_PRF_Default.b{2}
           /\ skWOTStd{1} = skWOTStd{2} /\ ps0{1} = ps{2} /\ ad0{1} = ad{2}
           /\ (forall (psad : pseed * adrs),
                psad \in SKG_PRF.O_PRF_Default.m{2}
                <=>
                ((exists (i j u v : int),
                    0 <= i < size skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\
                    psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))
                 \/ (exists (j u v : int),
                     0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\ 0 <= v < len /\
                     psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) j) chtype) u) v) 0))))
           /\ size skWOTStd{1} < d
           /\ size skWOTSnt{1} <= nr_trees (size skWOTStd{1})).
    * wp => /=.
      while (   ={skWOTSnt, skWOTSlp}
             /\ ad{2} = adz /\ SKG_PRF.O_PRF_Default.b{2}
             /\ skWOTStd{1} = skWOTStd{2} /\ ps0{1} = ps{2} /\ ad0{1} = ad{2}
             /\ (forall (psad : pseed * adrs),
                  psad \in SKG_PRF.O_PRF_Default.m{2}
                  <=>
                  ((exists (i j u v : int),
                      0 <= i < size skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\
                      psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))
                   \/ (exists (j u v : int),
                       0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\ 0 <= v < len /\
                       psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) j) chtype) u) v) 0))
                   \/ (exists (u v : int),
                       0 <= u < size skWOTSlp{2} /\ 0 <= v < len /\
                       psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) (size skWOTSnt{2})) chtype) u) v) 0))))
             /\ size skWOTStd{1} < d
             /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
             /\ size skWOTSlp{1} <= l').
      + wp => /=.
        while (   ={skWOTSnt, skWOTSlp, skWOTS}
               /\ ad{2} = adz /\ SKG_PRF.O_PRF_Default.b{2}
               /\ skWOTStd{1} = skWOTStd{2} /\ ps0{1} = ps{2} /\ ad0{1} = ad{2}
               /\ (forall (psad : pseed * adrs),
                    psad \in SKG_PRF.O_PRF_Default.m{2}
                    <=>
                    ((exists (i j u v : int),
                        0 <= i < size skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\
                        psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))
                     \/ (exists (j u v : int),
                         0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\ 0 <= v < len /\
                         psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) j) chtype) u) v) 0))
                     \/ (exists (u v : int),
                         0 <= u < size skWOTSlp{2} /\ 0 <= v < len /\
                         psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) (size skWOTSnt{2})) chtype) u) v) 0))
                     \/ (exists (v : int),
                         0 <= v < size skWOTS{2} /\
                         psad = (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size skWOTStd{2}) (size skWOTSnt{2})) chtype) (size skWOTSlp{2})) v) 0))))
               /\ size skWOTStd{1} < d
               /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
               /\ size skWOTSlp{1} < l'
               /\ size skWOTS{1} <= len).
        - inline{2} 1.
          rcondt{2} 2; 1: by auto.
          rcondt{2} 2.
          * auto => /> &2 bt mdom *.
            pose psad := (_, set_hidx _ _).
            move/iffLR /contra: (mdom psad) => -> //=.
            rewrite ?negb_or; split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 5 => @/HA.eq_idx.
              by rewrite ?setalladzch_getlidx 1..8:// /#.
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 4 => @/HA.eq_idx.
              by rewrite ?setalladzch_gettidx 1..8:// /valid_tidx /#.
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 2 => @/HA.eq_idx.
              by rewrite ?setalladzch_getkpidx 1..8:// /valid_tidx /#.
            do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
            rewrite -HA.eq_adrs_idxsq negb_forall /=; exists 1 => @/HA.eq_idx.
            by rewrite ?setallchadz_getchidx 1..8:// /valid_tidx /#.
          wp; rnd; wp; skip => /> &2 bt mdom *.
          rewrite -!andbA andbA; split; 2: smt(size_rcons).
          rewrite get_set_sameE oget_some /= => psad.
          split => [/mem_set [| -> /=]|]; 1,2: smt(size_ge0 size_rcons).
          move=> mdomrc; rewrite mem_set /=.
          case (psad \in SKG_PRF.O_PRF_Default.m{2}) => [// | /= ninm].
          move/iffRL /contra: (mdom psad) mdomrc => /(_ ninm) /=.
          rewrite ?negb_or => [#] -> -> -> /=; rewrite negb_exists => /= ninskw /=.
          move=> -[v]; rewrite size_rcons => -[rng_v psadval /=].
          case (v = size skWOTS{2}) => [ // | neqszv].
          by move: (ninskw v); rewrite negb_and (: 0 <= v && v < size skWOTS{2}) /#.
        wp; skip => /> &2 *.
        split => [* | psdbmap skw ? _ psdbmapdef ?]; 1: smt(ge2_len).
        split => [psad |]; 2: smt(size_rcons).
        by split => [/psdbmapdef | ]; smt(size_rcons size_ge0).
      wp; skip => /> &2 *.
      split => [* | psdbmap skw ? _ psdbmapdef ?]; 1: smt(ge2_lp).
      split => [psad |]; 2: smt(size_rcons).
      by split => [/psdbmapdef | ]; smt(size_rcons size_ge0).
    wp; skip => /> &2 bT mdef _ ltd_szsktd.
    split => [ * | psdbmap skw ? _ psdbmapdef ?]; 1: rewrite expr_ge0 1:// 1:/=.
    * by move => psad; split => [/mdef |] /#.
    split => [psad |]; 2: smt(size_rcons).
    by split => [/psdbmapdef | ]; smt(size_rcons size_ge0).
  wp; skip => /> &2 *; smt(ge1_d mem_empty).
(* TAIL: sign loop carries sk{1}=(skWOTStd,ps,ad){2}; forge/verify/fresh relational. *)
seq 2 2 : (={ml, pk, sigl, glob A, glob OC}).
- while (   ={ml, sigl, pk, glob A, glob OC}
         /\ sk{1} = (skWOTStd{2}, ps{2}, ad{2})).
  + wp.
    call (: ={arg} ==> ={res}); 1: by sim.
    by auto.
  by auto.
wp.
sim.
qed.

(* THE HOP: pay one SKG-PRF-distinguishing term to move from uniform to
   skg-derived WOTS keys.  Pure arithmetic on the two legs (a <= b + |a - b|). *)
lemma SKGPRF_hop
  (A  <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -SKG_PRF.O_PRF_Default })
  (OC <: FSSLXMTWES.TRHC.Oracle_THFC{ -A, -SKG_PRF.O_PRF_Default }) &m :
  Pr[EUF_NAGCMA_FLSLXMSSMTTWCESPRF(A, OC).main() @ &m : res]
  <=   Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF(A, OC).main() @ &m : res]
     + `|  Pr[SKG_PRF.PRF(R_SKGPRF_FLSLXMSSMTC(A, OC), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
         - Pr[SKG_PRF.PRF(R_SKGPRF_FLSLXMSSMTC(A, OC), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |.
proof.
have hf := EqPr_PRF_false A OC &m.
have ht := EqPr_NPRF_true A OC &m.
smt().
qed.

(* COMPOSED: fold the hop into the in-scope component theorem so the WOTS-key-
   derivation PRF term appears alongside the leaf + TCR terms.  Premises are the
   component theorem's, verbatim (they constrain only A / the game oracles). *)
lemma SKGPRF_hop_composed
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V,
             -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default,
             -SKG_PRF.O_PRF_Default }) &m :
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
    hoare[ A_ht(R_SMDTTCRCPKCO_C(A_ht, FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                                 FSSLXMTWES.PKCOC.O_THFC_Default).O_THFC).choose :
             R_SMDTTCRCPKCO_C.O_THFC.ads = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads ] =>
    hoare[ A_ht(R_SMDTTCRCTRH_C(A_ht, FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                                FSSLXMTWES.TRHC.O_THFC_Default).O_THFC).choose :
             R_SMDTTCRCTRH_C.O_THFC.ads = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads ] =>
    Pr[EUF_NAGCMA_FLSLXMSSMTTWCESPRF(A_ht, FC.O_THFC_Default).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
                         STCRC_WC.O_STCRC_Default).main() @ &m : res]
     + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(A_ht),
            FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
            FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
     + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(A_ht),
            FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
            FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res]
     + `|  Pr[SKG_PRF.PRF(R_SKGPRF_FLSLXMSSMTC(A_ht, FC.O_THFC_Default), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
         - Pr[SKG_PRF.PRF(R_SKGPRF_FLSLXMSSMTC(A_ht, FC.O_THFC_Default), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |.
proof.
move=> hc hembdisj hembinj hencb hdf8n hdflen hdf2 A_wf_ht allnchads allnpkcoads allntrhads.
have hhop := SKGPRF_hop A_ht FC.O_THFC_Default &m.
have hcomp := EUFNAGCMA_FLSLXMSSMTTWCESNPRF A_ht &m hc hembdisj hembinj hencb
                hdf8n hdflen hdf2 A_wf_ht allnchads allnpkcoads allntrhads.
smt().
qed.


(* ==========================================================================
   MATERIALIZATION BRIDGE (named TODO, deliberately NOT proved here)

   lemma Eqv_ondemand_materialized (A <: ...) &m :
     Pr[<EUF-NAGCMA over the on-demand REAL FL_SL_XMSS_MT_C_ES>.main() @ &m : res]
     = Pr[EUF_NAGCMA_FLSLXMSSMTTWCESPRF(A, FC.O_THFC_Default).main() @ &m : res].

   This is a deterministic-recomputation equivalence (`skg` is a function of `ss`;
   the materialized cube stores exactly the values the on-demand signer recomputes
   per layer).  It is the +C analog of MM45's on-demand->materialized bridge
   `Eqv_EUF_CMA_SPHINCSPLUSTW_Orig_FSPRFPRF` (SPHINCS_PLUS.ec:2243).  It is a
   SEPARATE item from the PRF hop and is not required for the hop's correctness.
   ========================================================================== *)


(* ==========================================================================
   GATE RECORD  (bash ec-certify.sh drafts/prf_hop_wip.ec)
     => compile=OK   admit-tactics=0   axiom-decls=0   => CERTIFIED-0-ADMIT

   BOTH BYEQUIV LEGS CLOSED -- the whole file is admit-free / axiom-free (0 new
   premise).  Verified by a real recompile (scratch-ecc deletes the target .eco)
   and a trailing `lemma : false` canary that the gate correctly REJECTS.
   * The PRF-keyed game `EUF_NAGCMA_FLSLXMSSMTTWCESPRF` and the reduction
     `R_SKGPRF_FLSLXMSSMTC : SKG_PRF.Adv_PRF` are DEFINED and TYPECHECK against
     the in-scope SKG PRF theory (SPHINCS_PLUS.SKG_PRF) and both in-scope hypertree
     modules.  The PRF game is byte-identical to the NPRF game except keygen; the
     reduction has no module state (the game is non-adaptive).
   * `EqPr_PRF_false` (b=false leg) -- MACHINE-CHECKED.  swap-down + a 3-arg conseq
     (side-2 hoare frames b=false past the direct abstract OC.init) + cube coupling
     ss{1}=k{2} + explicit sign-loop while.  See the proof header.
   * `EqPr_NPRF_true` (b=true leg) -- MACHINE-CHECKED.  Eager-uniform NPRF cube ~
     lazy random-function O.query; MM45's map-domain invariant ported WOTS-only
     (FORS disjunct dropped); per-query freshness `rcondt{2}` discharged by
     `HA.eq_adrs_idxsq` + `setalladzch_{getlidx,gettidx,getkpidx}` /
     `setallchadz_getchidx` address-injectivity.
   * `SKGPRF_hop`          -- Pr[PRF-game] <= Pr[NPRF-game] + |SKG-PRF term|, now
     UNCONDITIONAL (both legs admit-free).
   * `SKGPRF_hop_composed` -- folds the hop into the in-scope component theorem
     `EUFNAGCMA_FLSLXMSSMTTWCESNPRF`, giving
        Pr[PRF-game] <= (WOTS-leaf + S_TCR + PKCO-TCR + TRH-TCR) + |SKG-PRF term|
     -- UNCONDITIONAL (premises are the component theorem's, verbatim).

   SCOPE (unchanged): this is the WOTS/SKG hop AT THE HYPERTREE LEVEL only.  The
   scheme-level SKG term additionally needs the FORS+C secret keys (separate item)
   and pairs with the deferred MKG term; and the materialization bridge to the
   on-demand REAL scheme is the named TODO above.  See the header's SCOPE HONESTY.
   ========================================================================== *)
