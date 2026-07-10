(* ==========================================================================
   FORS_C_Multi.ec  --  MULTI-instance FORS+C d-EU-CMA.

   The FORS analogue of Thm D.1 (WOTS_C_Multi.ec): it lifts the single-instance
   `EUFCMA_FORSC` (drafts/FORS_C.ec) to the MULTI-instance setting SPHINCS+ uses,
   where ONE FORS keypair contains a POOL of d FORS instances and the message
   hash routes each signing query to one of them.

   TEMPLATE (MM45's multi-instance FORS-TW):
     FV-SPHINCSPLUS-EC/proofs/FORS_ES.ec
       * scheme      : M_FORS_ES_NPRF            (keygen builds s*l = d instances)
       * top game    : EUF_CMA_MFORSTWESNPRF     (line 2007; single ADAPTIVE game)
       * top theorem : EUFCMA_MFORSTWESNPRF      (line 6531)
           Pr[EUF_CMA_MFORSTWESNPRF] <=
               Pr[ MCO_ITSR.ITSR ]              (* interleaved-target subset res. *)
             + <OpenPRE cluster of f>           (* DSPR + 3*TCR of the leaf hash  *)
             + Pr[ TRHC_TCR ]                   (* SM-DT-TCR-C of the tree hash    *)
             + Pr[ TRCOC_TCR ].                 (* SM-DT-TCR-C of the root compr   *)
     Here `mco : mkey -> msg -> msgFORSTW * index` returns BOTH the compressed
     message and an INSTANCE index; the sign oracle routes to instance `val idx`
     (FORS_ES:2080 `edivz (val idx) l`) and `g` (FORS_ES:421) emits, for each of
     the k FORS trees, a tuple `(val idx, tree_i, leaf_i)` -- the FIRST coordinate
     is the selected instance.  So MM45's ITSR is ALREADY over interleaved,
     multi-instance targets; the "multi" in FORS lives in the message->index
     routing, not in a list of separately-committed instances.

   ------------------------------------------------------------------------
   WHY THIS LIFT DIFFERS FROM D.1 (WOTS+C, WOTS_C_Multi.ec).  Two structural
   contrasts, both faithfully reflected below:

   (1) ADAPTIVE, NOT non-adaptive.  D.1 modeled WOTS+C d-EU-naCMA NON-adaptively
       (adversary COMMITS d queries in `choose`, receives d keypairs) BECAUSE the
       S-TCR reduction had to grind chain-hash `f` evaluations at a pseed hidden
       until `forge`.  FORS has NO such obstruction: the ITSR(+C) oracle only
       SAMPLES the per-message key `mk <$ dmkey` (it never needs `pseed`), and the
       reduction generates the FORS sk-pool ITSELF, so it can answer signing
       queries ADAPTIVELY.  MM45's `EUF_CMA_MFORSTWESNPRF` is exactly one adaptive
       game.  We therefore keep the multi-instance FORS+C game ADAPTIVE -- that IS
       the faithful notion (contrast: forcing non-adaptivity here would be an
       unmotivated weakening).

   (2) NO disjointness conjunct in the winning condition -- and this is NOT the
       D.1-hop2 trap, it is a genuine structural difference.  D.1's `M_EUF_..._L`
       carried `disj_wgpidxs adlO adlOC` because WOTS+C has d SEPARATELY ADDRESSED
       instances and the S-TCR collection oracle grinds at those addresses (an
       earlier draft MIS-COPIED that conjunct into the WOTS-TW term game, making it
       identically 0 / the theorem false -- see WOTS_C_Multi.ec:165-181).  FORS
       selects ONE pooled instance PER MESSAGE via the message hash; MM45's game
       success is just `is_valid /\ is_fresh` (FORS_ES:2036) and its ITSR winning
       condition (MCO_ITSR.ITSR) is coverage + freshness with NO disjointness term.
       We REUSE `F.ITSRC` (drafts/FORS_C.ec) UNCHANGED: its winning condition is
       `predC_fors(digest) /\ coverage /\ freshness` (FORS_C.ec:297-299), already
       disjointness-free and already interleaved-target aware.  Reusing it is the
       faithful choice, not a shortcut -- see the NON-VACUITY block before the hop.

   ------------------------------------------------------------------------
   WHAT THE LIFT ADDS over FORS_C.ec (the genuine multi-instance content):
     * the scheme keygen builds a POOL `pkFORS list * skFORS list` of d instances
       (`mkeygen`, the abstract analogue of M_FORS_ES_NPRF.keygen -- FORS_C.ec's
       `fkeygen` collapsed the pool into ONE abstract keypair);
     * sign/verify ROUTE to instance `idx_of y` where `y` is the (grinded) digest;
     * `idx_of` is DEFINED FROM `g` -- `idx_of y = (nth witness (g y) 0).`1` -- so
       the instance that SIGNS is provably the SAME value the coverage tuples name
       (MM45's `val idx`), never a second free notion of "which instance".
   The three tree-layer terms (leaf-hash OpenPRE cluster, tree-hash TCR,
   root-compression TCR) are UNCHANGED by +C AND by the pool routing: the +C
   change and the idx-routing both rewrite the message->index map, never the
   per-instance Merkle-tree / root-compression layer beneath it (paper 2022/778
   Sec 4.1.1, "the security follows verbatim").  Carried as abstract non-negative
   reals `mtree_*`, exactly as FORS_C.ec carries `tree_*`.
   ========================================================================== *)

require import AllCore List Distr FMap FinType.
require Grind.
require FORS_C.

abstract theory MFORSC.

(* Import the single-instance FORS+C machinery: parameters (k, a, t), types
   (mkey, msg, out_t, cntr, pseed, adrs, pkFORS, skFORS, sigFORSTW, sigFORSC),
   the message hash `mco` + index extractor `g` + `predC_fors`, the total grind
   `G`/`gc`/`mco_C` (+ the PROVED `mco_C_predC`), the coverage map `hC`, and --
   crucially -- the BESPOKE interleaved ITSR(+C) game `ITSRC` with oracle
   `O_ITSRC_Default` and adversary class `Adv_ITSRC`.  All are reused verbatim. *)
clone import FORS_C.FORSC as F.

(* ------------------------------------------------------------------------ *)
(* Multi-instance parameter: d FORS instances in one keypair (MM45: s*l).    *)
(* ------------------------------------------------------------------------ *)
const d : { int | 1 <= d } as ge1_d.

(* Instance router, DEFINED FROM g (advisor fix -- not a free op).  g y has
   length k >= 1 (ge1_k) and every tuple shares the same first coordinate = the
   selected instance index (MM45 `g`, FORS_ES:421-424: mkseq (fun i => (val idx,
   i, leaf_i)) k).  So `idx_of y` is exactly MM45's `val idx`, and the instance
   that SIGNS below is provably the value the coverage tuples name. *)
op idx_of (y : out_t) : int = (nth witness (g y) 0).`1.

(* ------------------------------------------------------------------------ *)
(* Multi-instance FORS+C scheme.  keygen builds a POOL of d instances; the    *)
(* per-instance tree layer (fsign/fverify) is the ABSTRACT one imported from  *)
(* F -- +C never touches it, and the pool routing selects the instance from   *)
(* the digest index.                                                          *)
(* ------------------------------------------------------------------------ *)
op mkeygen : pseed -> adrs -> pkFORS list * skFORS list.   (* d instances *)

(* Full multi +C verify: recompute the digest from the carried counter, require
   it forces leaf 0 in the last tree (predC_fors), route to instance `idx_of y`
   in the public-key pool, then run the per-instance tree-layer check.  A
   sigFORSC = mkey * cntr * sigFORSTW (imported from F). *)
op mverifyC (pks : pkFORS list) (ps : pseed) (ad : adrs)
            (m : msg) (s : sigFORSC) : bool =
  let (mk, c, sf) = s in
  let y = mco mk m c in
    predC_fors y /\ fverify (nth witness pks (idx_of y)) ps ad y sf.

(* ------------------------------------------------------------------------ *)
(* EUF-CMA game for multi-instance FORS+C (mirrors EUF_CMA_MFORSTWESNPRF --   *)
(* single ADAPTIVE game over the pool).                                       *)
(* ------------------------------------------------------------------------ *)
module type SOracle_CMA_MFORSC = {
  proc sign(m : msg) : sigFORSC
}.

module type Oracle_CMA_MFORSC = {
  proc init(sks_init : skFORS list, ps_init : pseed, ad_init : adrs) : unit
  proc sign(m : msg) : sigFORSC
  proc fresh(m : msg) : bool
}.

module type Adv_EUFCMA_MFORSC (O : SOracle_CMA_MFORSC) = {
  proc forge(pk : pkFORS list * pseed * adrs) : msg * sigFORSC
}.

(* Default pool CMA oracle: samples the per-message key, grinds the canonical
   counter, routes to instance `idx_of y`, signs, records the queried message. *)
module O_CMA_MFORSC : Oracle_CMA_MFORSC = {
  var sks : skFORS list
  var ps : pseed
  var ad : adrs
  var qs : msg list
  var mmap : (msg, mkey) fmap

  proc init(sks_init : skFORS list, ps_init : pseed, ad_init : adrs) : unit = {
    sks <- sks_init;
    ps <- ps_init;
    ad <- ad_init;
    qs <- [];
    mmap <- empty;
  }

  proc sign(m : msg) : sigFORSC = {
    var mk : mkey;
    var c  : cntr;
    var y  : out_t;
    var sf : sigFORSTW;

    if (m \notin mmap) {
      mk <$ dmkey;
      mmap.[m] <- mk;
    }
    mk <- oget mmap.[m];

    c  <- gc mk m;                          (* canonical grind counter (M1) *)
    y  <- mco mk m c;                       (* == mco_C mk m                *)
    sf <- fsign (nth witness sks (idx_of y)) ps ad y;   (* route by index   *)

    qs <- rcons qs m;
    return (mk, c, sf);
  }

  proc fresh(m : msg) : bool = {
    return ! (m \in qs);
  }
}.

module EUF_CMA_MFORSC (A : Adv_EUFCMA_MFORSC, O : Oracle_CMA_MFORSC) = {
  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pks : pkFORS list;
    var sks : skFORS list;
    var m' : msg;
    var sig' : sigFORSC;
    var is_valid, is_fresh : bool;

    ad <- adz;
    ps <$ dpseed;
    (pks, sks) <- mkeygen ps ad;

    O.init(sks, ps, ad);
    (m', sig') <@ A(O).forge((pks, ps, ad));

    is_valid <- mverifyC pks ps ad m' sig';
    is_fresh <@ O.fresh(m');

    return is_valid /\ is_fresh;
  }
}.

(* ------------------------------------------------------------------------ *)
(* R_ITSRC_MFORSC: the multi-instance ITSR(+C) reduction (FORS+C analogue of  *)
(* MM45's R_ITSR_EUFCMA, FORS_ES:2176).  It generates the FORS sk-POOL itself, *)
(* fetches per-message keys ADAPTIVELY from the ITSR(+C) oracle, routes each   *)
(* honest signature to instance `idx_of y` (the recorded canonical counter     *)
(* matches, grind is deterministic), and relays the forgery triple             *)
(* (mk', m', c') with the FORGER's FREE counter c' -- so coverage lands on the  *)
(* forger's actual digest, sound against the permissive verifier (M2).         *)
(* ------------------------------------------------------------------------ *)
module (R_ITSRC_MFORSC (A : Adv_EUFCMA_MFORSC) : F.Adv_ITSRC)
       (O : Oracle_ITSRC) = {
  var ps : pseed
  var ad : adrs
  var sks : skFORS list
  var mmap : (msg, mkey) fmap

  module O_CMA : SOracle_CMA_MFORSC = {
    proc sign(m : msg) : sigFORSC = {
      var mk : mkey;
      var c  : cntr;
      var y  : out_t;
      var sf : sigFORSTW;

      if (m \notin mmap) {
        mk <@ O.query(m);          (* ITSR(+C) oracle samples key + grinds gc *)
        mmap.[m] <- mk;
      }
      mk <- oget mmap.[m];

      c  <- gc mk m;               (* canonical counter, matches the target   *)
      y  <- mco mk m c;
      sf <- fsign (nth witness sks (idx_of y)) ps ad y;

      return (mk, c, sf);
    }
  }

  proc find() : mkey * msg * cntr = {
    var pks : pkFORS list;
    var m' : msg;
    var sig' : sigFORSC;

    ad <- adz;
    ps <$ dpseed;
    (pks, sks) <- mkeygen ps ad;
    mmap <- empty;

    (m', sig') <@ A(O_CMA).forge((pks, ps, ad));

    return (sig'.`1, m', sig'.`2);   (* (mk', m', c') from the forged sig     *)
  }
}.

(* ------------------------------------------------------------------------ *)
(* The three UNCHANGED tree-layer terms (the MULTI-instance SM_DT games over   *)
(* d*k*t targets -- FORS_ES: t_smdtopenpre = t_smdttcr = d*k*t):               *)
(*   mtree_openpre := Pr[ F_OpenPRE.SM_DT_OpenPRE(R_FSMDTOpenPRE_EUFCMA(A)) ]  *)
(*   mtree_trh     := Pr[ TRHC_TCR.SM_DT_TCR_C   (R_TRHSMDTTCRC_EUFCMA(A))   ] *)
(*   mtree_trco    := Pr[ TRCOC_TCR.SM_DT_TCR_C  (R_TRCOSMDTTCRC_EUFCMA(A))  ] *)
(*                                                                            *)
(* They are NOT abstract `op`s: they are UNIVERSALLY-QUANTIFIED parameters of  *)
(* `EUFCMA_MFORSC`, and the tree bound is an EXPLICIT PREMISE of that lemma.   *)
(* See the long note in FORS_C.ec (same section) -- as free abstract ops in an *)
(* ABSTRACT theory the old `admit` was FALSE-as-stated (a legal clone with     *)
(* `mtree_* <- 0%r` collapses it to `Pr[... /\ !covered] <= 0%r`), and dually  *)
(* `<- 1%r` made the bound vacuous.  Adversarial review 2026-07-09.           *)
(* ------------------------------------------------------------------------ *)

(* ==========================================================================
   INSTRUMENTATION (mirror FORS_C.ec:517-616).  A ghost target list `ts`
   recording (mk, m, gc mk m) ONCE PER UNIQUE queried message (the freshness
   invariant `map snd ts <= qs` depends on this once-per-unique placement --
   advisor flag #2), plus the coverage boolean `covered`.  The ghost never
   feeds a returned value, so the instrumented game has the SAME advantage.
   ========================================================================== *)
module O_CMA_MFORSC_I : Oracle_CMA_MFORSC = {
  var sks : skFORS list
  var ps : pseed
  var ad : adrs
  var qs : msg list
  var mmap : (msg, mkey) fmap
  var ts : (mkey * msg * cntr) list

  proc init(sks_init : skFORS list, ps_init : pseed, ad_init : adrs) : unit = {
    sks <- sks_init;
    ps <- ps_init;
    ad <- ad_init;
    qs <- [];
    mmap <- empty;
    ts <- [];
  }

  proc sign(m : msg) : sigFORSC = {
    var mk : mkey;
    var c  : cntr;
    var y  : out_t;
    var sf : sigFORSTW;

    if (m \notin mmap) {
      mk <$ dmkey;
      mmap.[m] <- mk;
      ts <- rcons ts (mk, m, gc mk m);   (* once per UNIQUE message *)
    }
    mk <- oget mmap.[m];

    c  <- gc mk m;
    y  <- mco mk m c;
    sf <- fsign (nth witness sks (idx_of y)) ps ad y;

    qs <- rcons qs m;
    return (mk, c, sf);
  }

  proc fresh(m : msg) : bool = {
    return ! (m \in qs);
  }
}.

module EUF_CMA_MFORSC_I (A : Adv_EUFCMA_MFORSC) = {
  var covered : bool

  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pks : pkFORS list;
    var sks : skFORS list;
    var m' : msg;
    var sig' : sigFORSC;
    var is_valid, is_fresh : bool;

    ad <- adz;
    ps <$ dpseed;
    (pks, sks) <- mkeygen ps ad;

    O_CMA_MFORSC_I.init(sks, ps, ad);
    (m', sig') <@ A(O_CMA_MFORSC_I).forge((pks, ps, ad));

    is_valid <- mverifyC pks ps ad m' sig';
    is_fresh <@ O_CMA_MFORSC_I.fresh(m');

    covered <-
      all (fun x => x \in flatten (map (fun (tmc : mkey * msg * cntr) => hC tmc.`1 tmc.`2 tmc.`3)
                                       O_CMA_MFORSC_I.ts))
          (hC sig'.`1 m' sig'.`2);

    return is_valid /\ is_fresh;
  }
}.

(* Instrumentation is res-preserving (mirror eufcma_forsc_I_eq). *)
lemma eufcma_mforsc_I_eq
  (A <: Adv_EUFCMA_MFORSC{-O_CMA_MFORSC, -O_CMA_MFORSC_I, -EUF_CMA_MFORSC_I}) &m :
    Pr[EUF_CMA_MFORSC(A, O_CMA_MFORSC).main() @ &m : res]
  = Pr[EUF_CMA_MFORSC_I(A).main() @ &m : res].
proof.
  byequiv => //.
  proc.
  inline{1} O_CMA_MFORSC.init O_CMA_MFORSC.fresh.
  inline{2} O_CMA_MFORSC_I.init O_CMA_MFORSC_I.fresh.
  wp.
  call (:   ={qs, mmap}(O_CMA_MFORSC, O_CMA_MFORSC_I)
         /\ O_CMA_MFORSC.sks{1} = O_CMA_MFORSC_I.sks{2}
         /\ O_CMA_MFORSC.ps{1} = O_CMA_MFORSC_I.ps{2}
         /\ O_CMA_MFORSC.ad{1} = O_CMA_MFORSC_I.ad{2}).
  + proc.
    if => //; auto.
  wp; rnd; wp; skip => />.
qed.

(* ==========================================================================
   NON-VACUITY CHECK (the D.1-hop2 trap, adjudicated for THIS lift).
   The reused winning condition F.ITSRC.main (FORS_C.ec:297-299) is
       predC_fors (mco mk' m' c')                       (i)
       /\ (forall x, x \in cover_f => x \in cover_q)     (ii)
       /\ ! (mk', m', c') \in ts.                        (iii)
   We check EACH conjunct is SATISFIABLE by R_ITSRC_MFORSC -- none is spuriously
   0 / unsatisfiable-by-the-reduction:
     (i)   supplied by `is_valid` = mverifyC, whose FIRST clause IS predC_fors on
           the forgery digest.  The reduction relays the forger's (mk', m', c')
           unchanged, so (i) holds exactly when the forgery is valid.  Satisfiable.
     (ii)  the COVERED branch of the split.  In multi-instance, coverage requires
           every one of the k tuples (idx_of y', tree_j, leaf_j) of the forgery
           digest to appear among the recorded targets' tuples.  This is winnable:
           an adversary querying instance idx_of y' enough to cover the first k-1
           trees forges (the last tree is +C-forced to leaf 0, the DarkSide 1/t'
           term) -- exactly ITSR(+C) hardness, NOT identically true nor false.
     (iii) `is_fresh` gives m' \notin qs; the loop invariant `map snd ts <= qs`
           (recorded once per unique message) forces m' \notin (map snd ts), hence
           (mk', m', c') \notin ts (every recorded triple's 2nd coord is a queried
           message).  Satisfiable.
   CRUCIALLY there is NO disjointness conjunct here (unlike D.1's WOTS-TW term
   game), so the exact bug pattern that made a D.1 term identically 0 CANNOT
   arise: we did not copy any address-disjointness conjunct into this game,
   because FORS's pooled single-instance-per-message routing does not have one.
   LHS is winnable (a real EUF-CMA forger exists); RHS ITSR(+C) is not
   identically 0 (see (ii)); the three tree reals are abstract placeholders.
   ========================================================================== *)

(* The ITSR(+C) hop: the COVERAGE part of multi-instance FORS+C EUF-CMA is caught
   by ITSR(+C) through R_ITSRC_MFORSC.  d-query-pool lift of FORS_C.ec:626-657.
   The reduction's per-message key comes from the ITSR(+C) oracle (samples +
   grinds + records the canonical target); the honest counter matches the target;
   the forgery triple carries the forger's FREE counter (M2).  Instance routing
   `idx_of y` is a deterministic function of the (equal) digest on both sides, so
   it does not break the coupling. *)
lemma ITSRC_hop_M
  (A <: Adv_EUFCMA_MFORSC{-R_ITSRC_MFORSC, -O_CMA_MFORSC_I, -O_ITSRC_Default, -EUF_CMA_MFORSC_I}) &m :
    Pr[EUF_CMA_MFORSC_I(A).main() @ &m : res /\ EUF_CMA_MFORSC_I.covered]
  <= Pr[ITSRC(R_ITSRC_MFORSC(A), O_ITSRC_Default).main() @ &m : res].
proof.
  byequiv (_ : ={glob A} ==> (res{1} /\ EUF_CMA_MFORSC_I.covered{1}) => res{2}) => //.
  proc.
  inline{2} R_ITSRC_MFORSC(A, O_ITSRC_Default).find.
  inline{2} O_ITSRC_Default.init O_ITSRC_Default.get_targets.
  inline{1} O_CMA_MFORSC_I.init O_CMA_MFORSC_I.fresh.
  swap{2} 1 2.
  wp.
  call (:   ={mmap}(O_CMA_MFORSC_I, R_ITSRC_MFORSC)
         /\ O_CMA_MFORSC_I.sks{1} = R_ITSRC_MFORSC.sks{2}
         /\ O_CMA_MFORSC_I.ps{1} = R_ITSRC_MFORSC.ps{2}
         /\ O_CMA_MFORSC_I.ad{1} = R_ITSRC_MFORSC.ad{2}
         /\ O_CMA_MFORSC_I.ts{1} = O_ITSRC_Default.ts{2}
         /\ (forall x, x \in map (fun (tmc : mkey * msg * cntr) => tmc.`2)
                                 O_CMA_MFORSC_I.ts{1}
                       => x \in O_CMA_MFORSC_I.qs{1})).
  + proc.
    inline{2} O_ITSRC_Default.query.
    wp.
    if => //.
    - auto; smt(map_rcons mem_rcons).
    - auto; smt(mem_rcons).
  wp; rnd; wp; skip => />.
  rewrite /mverifyC /hC /=.
  smt(allP mapP mem_rcons).
qed.

(* ==========================================================================
   THEOREM (multi-instance FORS+C d-EU-CMA), paper 2022/778 Sec 4.1.1, the FORS
   analogue of Thm D.1.  FAITHFUL to MM45's EUFCMA_MFORSTWESNPRF with the single
   substitution ITSR -> ITSR(+C); sound-direction (LHS <= sum of RHS terms);
   NO p_nu term (see FORS_C.ec verdict (E)).

   Proved FRESH from `eufcma_mforsc_I_eq` + `ITSRC_hop_M` + one labelled tree
   admit -- NOT routed through the cloned single-instance `F.EUFCMA_FORSC`
   (which carries its own tree admit), so the multi result is not circular
   through an admitted single-instance fact (advisor flag #1).

   HYPOTHESIS (explicit, paper-level; NOT an EasyCrypt `axiom`):
   - good_counter_exists: for every (mk, m), SOME counter forces the last tree to
     leaf 0.  Paper's r = lambda "a good counter always exists" (App. C), the
     discharged form of p_nu; its failure is a COMPLETENESS defect (Grind.grind_
     fails), never a security-advantage term.  (Unused by the two proved hops --
     it is a composition-side honest-completeness hypothesis, threaded here to
     match the single-instance statement's surface; the bound holds without it,
     but we keep it to mirror FORS_C.ec's EUFCMA_FORSC exactly.)
   ========================================================================== *)
lemma EUFCMA_MFORSC
  (A <: Adv_EUFCMA_MFORSC{-R_ITSRC_MFORSC, -O_CMA_MFORSC, -O_CMA_MFORSC_I,
                          -O_ITSRC_Default, -EUF_CMA_MFORSC_I})
  (mtree_openpre mtree_trh mtree_trco : real)
  &m :
    (forall (mk : mkey) (m : msg), exists c, predC_fors (mco mk m c)) =>
    (* (H-TREE-MULTI) EXPLICIT PREMISE.  Discharge by instantiating with the
       three FORS_ES multi-instance tree advantages for THIS adversary A. *)
    (   Pr[EUF_CMA_MFORSC_I(A).main() @ &m : res /\ !EUF_CMA_MFORSC_I.covered]
     <= mtree_openpre + mtree_trh + mtree_trco) =>
    Pr[EUF_CMA_MFORSC(A, O_CMA_MFORSC).main() @ &m : res]
  <=   Pr[ITSRC(R_ITSRC_MFORSC(A), O_ITSRC_Default).main() @ &m : res]
     + mtree_openpre + mtree_trh + mtree_trco.
proof.
  move=> _ htree.
  rewrite (eufcma_mforsc_I_eq A &m).
  rewrite Pr[mu_split EUF_CMA_MFORSC_I.covered].
  have hop := ITSRC_hop_M A &m.
  (* (H-TREE-MULTI) is now the premise `htree`, NOT an admit.  The residual
     NON-coverage part (some forgery leaf tuple was NEVER a target) is caught by
     the MULTI-instance leaf-hash OpenPRE cluster + tree-hash TCR + root-
     compression TCR -- MM45's R_FSMDTOpenPRE_EUFCMA / R_TRHSMDTTCRC_EUFCMA /
     R_TRCOSMDTTCRC_EUFCMA over d*k*t targets (FORS_ES:2244/2448/2643).  The +C
     change and the pool routing rewrite only the message->index map, never the
     per-instance Merkle-tree / root-compression layer, so these port VERBATIM
     from FORS_ES.  Discharging the premise = porting that tree layer.  NO p_nu
     term. *)
  smt().
qed.

end MFORSC.
