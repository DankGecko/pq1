(* ==========================================================================
   FORS_C10_Multi.ec  --  MULTI-instance FORS+C d-EU-CMA, C10-FAITHFUL.

   The C10 analogue of FORS_C_Multi.ec.  It lifts the C10-faithful
   single-instance ITSR(+C) machinery of `FORS_C10.ec` (`FORSC10`) to the
   MULTI-instance setting SPHINCS+ uses, where ONE FORS keypair contains a POOL
   of d FORS instances and the message hash routes each signing query to one of
   them.  The paper-model sibling this MIRRORS is `FORS_C_Multi.ec` (theory
   `MFORSC`); read that file first for the FORS-TW / MM45 template.

   ------------------------------------------------------------------------
   WHY A SEPARATE C10 MULTI FILE (do not fold into FORS_C_Multi.ec).

   `FORS_C_Multi.ec` clones the PAPER's FORS+C (`FORS_C.FORSC`):

       op  mco : mkey -> msg -> cntr -> out_t     (* 3-arg; counter ground   *)
       O.query(m): mk <$ dmkey; c <- gc mk m; ...  (* key UNIFORM, memoized  *)

   C10 does the OPPOSITE (see the FORS_C10.ec header):

       op  mco : mkey -> msg -> out_t             (* 2-arg; NO counter       *)
       O.query(m): mk <$ dcond dmkey (good m); ... (* key CONDITIONED, fresh *)

   In C10 the ITSR message KEY is the randomiser `R`, drawn FRESH per signing
   call (`secure/src/crypto.rs:130-142` draws a fresh opt_rand every signature)
   and CONDITIONED on the +C predicate.  Nothing over the paper model transfers
   without this re-base.  We therefore clone `FORS_C10.FORSC10` (the C10 model)
   here and lift IT, not the paper model.

   THREE STRUCTURAL CONSEQUENCES vs FORS_C_Multi.ec, all deliberate:

     (1) TARGETS ARE PAIRS (mkey * msg), not triples (mkey * msg * cntr): C10
         carries no counter, so ITSR(+C)/C10's target list is over pairs and the
         reduction relays the forger's (mk', m') with NO free counter.

     (2) THE CMA ORACLE IS NON-MEMOIZED and draws the CONDITIONED key
         `mk <$ dcond dmkey (good m)` per SIGNATURE -- matching production, and
         matching `F.O_ITSRC10_Default.query` EXACTLY.  There is therefore NO
         `mmap` invariant to carry in the hop (a SIMPLIFICATION over the paper's
         memoized coupling): the coupling is purely on the target list `ts`.

     (3) NO `good_counter_exists` PREMISE.  The paper's multi theorem
         (EUFCMA_MFORSC) carries the honest-completeness hypothesis
         `forall mk m, exists c, predC_fors (mco mk m c)`.  C10 has no counter to
         grind; the existence obligation is discharged upstream by the axiom
         `good_pos` in FORS_C10.ec (which is LOAD-BEARING there via `query_ll`),
         so this theorem carries NO such premise.  Freshness stays on the PAIR
         `(mk', m')`, exactly as `F.ITSRC10` does.

   ------------------------------------------------------------------------
   WHAT STAYS OPEN (unchanged from FORS_C10.ec -- NOT touched here).

   The RHS term `Pr[ITSRC10(R_ITSRC10_MFORSC10(A), O_ITSRC10_Default).main()]`
   is the C10 model's game from FORS_C10.ec.  It is an UNREDUCED game
   probability: the NAMED, NONSTANDARD `ITSRC10` ASSUMPTION.  It is NOT bounded
   here and MUST NOT be -- the FORS_C10.ec header documents that the black-box
   route to MM45's uniform-key ITSR loses ~102 bits and the direct DarkSide route
   needs a concentration inequality EasyCrypt lacks.  That is OPEN and stays
   open.  The REAL content proved here is the multi->single REDUCTION
   `R_ITSRC10_MFORSC10` + its hop `ITSRC10_hop_M` (the C10 analogue of the
   paper's `ITSRC_hop_M`) + the covered/!covered split.  This file turns NO open
   assumption into a proven-looking bound; the ITSRC10 term is carried verbatim.

   ------------------------------------------------------------------------
   WHAT THE LIFT ADDS over FORS_C10.ec.  FORS_C10.ec is ONLY the message-hash +
   ITSR(+C)/C10 game; it has NO scheme layer.  So this file introduces the
   tree-layer scheme surface (pseed/adrs/pkFORS/skFORS/sigFORSTW + dpseed/adz +
   mkeygen/fsign/fverify), EXACTLY as FORS_C.ec provides it and FORS_C_Multi.ec
   inherits it (there the same surface is behind the `FORS_C.FORSC` clone).  The
   three tree-layer terms (leaf-hash OpenPRE cluster, tree-hash TCR, root-
   compression TCR) are UNCHANGED by +C AND by the pool routing -- the +C change
   and the idx-routing both rewrite only the message->index map, never the
   per-instance Merkle-tree / root-compression layer beneath it.  Carried as the
   forall-bound reals `mtree_*`, exactly as FORS_C_Multi.ec carries them.
   ========================================================================== *)

require import AllCore List Distr.
require FORS_C10.

abstract theory MFORSC10.

(* Import the C10-faithful single-instance FORS+C machinery: parameters
   (k, a, t), types (mkey, msg, out_t), the 2-arg message hash `mco`, the index
   extractor `g` (+ its structural axioms size_g/eqiks_g/neqisvs_g/rng_g/uniq_g),
   `predC_fors`, `good`, the LOAD-BEARING `good_pos` (= p_nu), the coverage map
   `hC`, and -- crucially -- the CONDITIONED, NON-MEMOIZED ITSR(+C)/C10 game
   `ITSRC10` with oracle `O_ITSRC10_Default` and adversary class `Adv_ITSRC10`.
   All are reused verbatim; the ITSRC10 game is carried as the open assumption. *)
clone import FORS_C10.FORSC10 as F.

(* ------------------------------------------------------------------------ *)
(* Tree-layer scheme surface.  FORS_C10.ec (unlike FORS_C.ec) is purely the   *)
(* message-hash + ITSR game and does NOT declare these -- so we introduce them *)
(* here, structurally IDENTICAL to FORS_C.ec's declarations (which            *)
(* FORS_C_Multi.ec inherits behind its `FORS_C.FORSC` clone).  +C never       *)
(* touches this layer; it is abstract exactly as in the paper model.          *)
(* ------------------------------------------------------------------------ *)
type pseed.       (* public seed                                             *)
type adrs.        (* hash address                                            *)
type pkFORS.      (* FORS public key   (per instance)                        *)
type skFORS.      (* FORS secret key   (per instance)                        *)
type sigFORSTW.   (* FORS auth-path signature (tree layer)                   *)

(* Public-seed distribution and fixed initial address (mirror FORS_C.ec's
   `op [lossless] dpseed` / `op adz`).  The `[lossless]` annotation adds the
   benign `dpseed_ll`, structurally identical to FORS_C.ec's -- see the axiom
   note at the end of this file. *)
op [lossless] dpseed : pseed distr.
op adz : adrs.

(* ------------------------------------------------------------------------ *)
(* Multi-instance parameter: d FORS instances in one keypair (MM45: s*l).    *)
(* ------------------------------------------------------------------------ *)
const d : { int | 1 <= d } as ge1_d.

(* Instance router, DEFINED FROM g (not a free op).  g y has length k >= 1
   (ge1_k) and every tuple shares the same first coordinate = the selected
   instance index (MM45 `g`: the k tuples are (val idx, tree_i, leaf_i)).  So
   `idx_of y` is exactly MM45's `val idx`, and the instance that SIGNS below is
   provably the value the coverage tuples name -- never a second free notion. *)
op idx_of (y : out_t) : int = (nth witness (g y) 0).`1.

(* A C10 FORS+C signature carries the randomiser mk (= R) and the tree-layer
   auth-path signature.  NO counter (contrast FORS_C.ec's mkey * cntr *
   sigFORSTW): C10 grinds R, not a counter, and stores R in SIG_R. *)
type sigFORSC10 = mkey * sigFORSTW.

(* Pool keygen builds a POOL of d instances (analogue of M_FORS_ES_NPRF.keygen).*)
op mkeygen : pseed -> adrs -> pkFORS list * skFORS list.

(* Per-instance tree layer (abstract; +C does not change it). *)
op fsign  : skFORS -> pseed -> adrs -> out_t -> sigFORSTW.
op fverify : pkFORS -> pseed -> adrs -> out_t -> sigFORSTW -> bool.

(* Full multi +C verify (C10): recompute the digest from the carried R (= mk),
   require it forces leaf 0 in the last tree (predC_fors), route to instance
   `idx_of y` in the public-key pool, then run the per-instance tree check.
   NO counter recomputation. *)
op mverifyC (pks : pkFORS list) (ps : pseed) (ad : adrs)
            (m : msg) (s : sigFORSC10) : bool =
  let (mk, sf) = s in
  let y = mco mk m in
    predC_fors y /\ fverify (nth witness pks (idx_of y)) ps ad y sf.

(* ------------------------------------------------------------------------ *)
(* EUF-CMA game for multi-instance FORS+C, C10-faithful (mirrors             *)
(* EUF_CMA_MFORSC -- single ADAPTIVE game over the pool).                    *)
(* ------------------------------------------------------------------------ *)
module type SOracle_CMA_MFORSC10 = {
  proc sign(m : msg) : sigFORSC10
}.

module type Oracle_CMA_MFORSC10 = {
  proc init(sks_init : skFORS list, ps_init : pseed, ad_init : adrs) : unit
  proc sign(m : msg) : sigFORSC10
  proc fresh(m : msg) : bool
}.

module type Adv_EUFCMA_MFORSC10 (O : SOracle_CMA_MFORSC10) = {
  proc forge(pk : pkFORS list * pseed * adrs) : msg * sigFORSC10
}.

(* Default pool CMA oracle, C10.  Draws the CONDITIONED randomiser
   `mk <$ dcond dmkey (good m)` FRESH per signature (NON-memoized -- matching
   production and F.O_ITSRC10_Default.query), routes to instance `idx_of y`,
   signs, records the queried message.  There is NO mmap and NO counter. *)
module O_CMA_MFORSC10 : Oracle_CMA_MFORSC10 = {
  var sks : skFORS list
  var ps : pseed
  var ad : adrs
  var qs : msg list

  proc init(sks_init : skFORS list, ps_init : pseed, ad_init : adrs) : unit = {
    sks <- sks_init;
    ps <- ps_init;
    ad <- ad_init;
    qs <- [];
  }

  proc sign(m : msg) : sigFORSC10 = {
    var mk : mkey;
    var y  : out_t;
    var sf : sigFORSTW;

    mk <$ dcond dmkey (good m);                     (* fresh, conditioned    *)
    y  <- mco mk m;
    sf <- fsign (nth witness sks (idx_of y)) ps ad y;   (* route by index    *)

    qs <- rcons qs m;
    return (mk, sf);
  }

  proc fresh(m : msg) : bool = {
    return ! (m \in qs);
  }
}.

module EUF_CMA_MFORSC10 (A : Adv_EUFCMA_MFORSC10, O : Oracle_CMA_MFORSC10) = {
  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pks : pkFORS list;
    var sks : skFORS list;
    var m' : msg;
    var sig' : sigFORSC10;
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
(* R_ITSRC10_MFORSC10: the multi-instance ITSR(+C)/C10 reduction (C10         *)
(* analogue of R_ITSRC_MFORSC).  Generates the FORS sk-POOL itself, fetches   *)
(* per-signature CONDITIONED keys ADAPTIVELY from the ITSR(+C)/C10 oracle      *)
(* (NON-memoized -- one O.query per signing call), routes each honest          *)
(* signature to instance `idx_of y`, and relays the forgery PAIR (mk', m')     *)
(* -- NO free counter (C10 carries none).  find returns a mkey * msg pair,      *)
(* matching F.Adv_ITSRC10.                                                      *)
(* ------------------------------------------------------------------------ *)
module (R_ITSRC10_MFORSC10 (A : Adv_EUFCMA_MFORSC10) : F.Adv_ITSRC10)
       (O : Oracle_ITSRC10) = {
  var ps : pseed
  var ad : adrs
  var sks : skFORS list

  module O_CMA : SOracle_CMA_MFORSC10 = {
    proc sign(m : msg) : sigFORSC10 = {
      var mk : mkey;
      var y  : out_t;
      var sf : sigFORSTW;

      mk <@ O.query(m);       (* ITSR(+C)/C10 oracle: conditioned draw + record *)
      y  <- mco mk m;
      sf <- fsign (nth witness sks (idx_of y)) ps ad y;

      return (mk, sf);
    }
  }

  proc find() : mkey * msg = {
    var pks : pkFORS list;
    var m' : msg;
    var sig' : sigFORSC10;

    ad <- adz;
    ps <$ dpseed;
    (pks, sks) <- mkeygen ps ad;

    (m', sig') <@ A(O_CMA).forge((pks, ps, ad));

    return (sig'.`1, m');    (* (mk', m') from the forged sig -- NO counter *)
  }
}.

(* ==========================================================================
   GATE 3 (non-degeneracy of the reduction's target registration).  The exact
   spurious-0 bug class this guards against: a reduction that registers ZERO
   targets (coverage `forall x, x \in [] => ...` VACUOUSLY true, win-set
   degenerate) or DUPLICATE targets under the wrong addresses (the D.1 `R_trco`
   over-registration that made a term identically 0).  Machine-checked here:
   `F.O_ITSRC10_Default.query` appends EXACTLY ONE (mk, m) pair per call, and the
   reduction's `O_CMA.sign` invokes `O.query` EXACTLY ONCE per signature (visible
   in R_ITSRC10_MFORSC10.O_CMA above -- non-memoized, one query per sign).  So
   the recorded target list is neither empty nor over-registered.  Together with
   NEGATIVE CONTROL #2 (replacing the RHS Pr[ITSRC10 ...] by 0%r fails to
   compile, so the win-set is not provably 0) this closes the spurious-0 gate. *)
lemma query_registers_exactly_one (n : int) :
  hoare[O_ITSRC10_Default.query :
          size O_ITSRC10_Default.ts = n ==> size O_ITSRC10_Default.ts = n + 1].
proof. proc; auto => />; smt(size_rcons). qed.

(* ==========================================================================
   INSTRUMENTATION (mirror FORS_C_Multi.ec:276-368).  A ghost target list `ts`
   recording (mk, m) ONCE PER SIGNATURE (non-memoized -- matching the C10
   oracle, contrast the paper's once-per-UNIQUE-message), plus the coverage
   boolean `covered`.  The ghost never feeds a returned value, so the
   instrumented game has the SAME advantage (`eufcma_mforsc10_I_eq`).
   ========================================================================== *)
module O_CMA_MFORSC10_I : Oracle_CMA_MFORSC10 = {
  var sks : skFORS list
  var ps : pseed
  var ad : adrs
  var qs : msg list
  var ts : (mkey * msg) list

  proc init(sks_init : skFORS list, ps_init : pseed, ad_init : adrs) : unit = {
    sks <- sks_init;
    ps <- ps_init;
    ad <- ad_init;
    qs <- [];
    ts <- [];
  }

  proc sign(m : msg) : sigFORSC10 = {
    var mk : mkey;
    var y  : out_t;
    var sf : sigFORSTW;

    mk <$ dcond dmkey (good m);
    ts <- rcons ts (mk, m);            (* ghost target -- once per SIGNATURE *)
    y  <- mco mk m;
    sf <- fsign (nth witness sks (idx_of y)) ps ad y;

    qs <- rcons qs m;
    return (mk, sf);
  }

  proc fresh(m : msg) : bool = {
    return ! (m \in qs);
  }
}.

module EUF_CMA_MFORSC10_I (A : Adv_EUFCMA_MFORSC10) = {
  var covered : bool

  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pks : pkFORS list;
    var sks : skFORS list;
    var m' : msg;
    var sig' : sigFORSC10;
    var is_valid, is_fresh : bool;

    ad <- adz;
    ps <$ dpseed;
    (pks, sks) <- mkeygen ps ad;

    O_CMA_MFORSC10_I.init(sks, ps, ad);
    (m', sig') <@ A(O_CMA_MFORSC10_I).forge((pks, ps, ad));

    is_valid <- mverifyC pks ps ad m' sig';
    is_fresh <@ O_CMA_MFORSC10_I.fresh(m');

    covered <-
      all (fun x => x \in flatten (map (fun (km : mkey * msg) => hC km.`1 km.`2)
                                       O_CMA_MFORSC10_I.ts))
          (hC sig'.`1 m');

    return is_valid /\ is_fresh;
  }
}.

(* Instrumentation is res-preserving (mirror eufcma_mforsc_I_eq).  The ghost
   `ts` and boolean `covered` never feed a returned value, so the instrumented
   game induces the same res distribution.  The oracle bodies differ ONLY in the
   ghost `ts <- rcons ts (mk,m)`; both draw the same conditioned key and record
   the same qs, so a straight `proc; auto` couples them (no memoization branch,
   contrast the paper's `if => //; auto`). *)
lemma eufcma_mforsc10_I_eq
  (A <: Adv_EUFCMA_MFORSC10{-O_CMA_MFORSC10, -O_CMA_MFORSC10_I, -EUF_CMA_MFORSC10_I}) &m :
    Pr[EUF_CMA_MFORSC10(A, O_CMA_MFORSC10).main() @ &m : res]
  = Pr[EUF_CMA_MFORSC10_I(A).main() @ &m : res].
proof.
  byequiv => //.
  proc.
  inline{1} O_CMA_MFORSC10.init O_CMA_MFORSC10.fresh.
  inline{2} O_CMA_MFORSC10_I.init O_CMA_MFORSC10_I.fresh.
  wp.
  call (:   ={qs}(O_CMA_MFORSC10, O_CMA_MFORSC10_I)
         /\ O_CMA_MFORSC10.sks{1} = O_CMA_MFORSC10_I.sks{2}
         /\ O_CMA_MFORSC10.ps{1} = O_CMA_MFORSC10_I.ps{2}
         /\ O_CMA_MFORSC10.ad{1} = O_CMA_MFORSC10_I.ad{2}).
  + proc; auto.
  wp; rnd; wp; skip => />.
qed.

(* ==========================================================================
   NON-VACUITY CHECK (the D.1-hop2 trap, adjudicated for THIS C10 lift).
   The reused winning condition `F.ITSRC10.main` (FORS_C10.ec:293-296) is
       predC_fors (mco mk' m')                          (i)
       /\ (forall x, x \in cover_f => x \in cover_q)     (ii)
       /\ ! (mk', m') \in ts.                            (iii)
   We check EACH conjunct is SATISFIABLE by R_ITSRC10_MFORSC10 -- none is
   spuriously 0 / unsatisfiable-by-the-reduction:
     (i)   supplied by `is_valid` = mverifyC, whose FIRST clause IS predC_fors on
           the forgery digest mco mk' m'.  The reduction relays the forger's
           (mk', m') unchanged, so (i) holds exactly when the forgery is valid.
           Satisfiable.
     (ii)  the COVERED branch of the split.  Coverage requires each of the k
           tuples (idx_of y', tree_j, leaf_j) of the forgery digest to appear
           among the recorded targets' tuples.  Winnable at ITSR(+C)/C10 hardness
           (the last tree is +C-forced to leaf 0, the DarkSide term) -- NOT
           identically true nor false.
     (iii) `is_fresh` gives m' \notin qs; the loop invariant `map snd ts <= qs`
           (recorded per signature) forces m' \notin (map snd ts), hence
           (mk', m') \notin ts.  Satisfiable.
   CRUCIALLY there is NO disjointness conjunct here (unlike D.1's WOTS-TW term
   game), and the reduction registers EXACTLY ONE target per O.query (no
   duplicate registration a la R_trco): the exact bug patterns that made a D.1
   term identically 0 CANNOT arise.  We REUSE F.ITSRC10's win condition
   VERBATIM, adding NO conjunct.  That the ITSRC10 term is genuinely load-bearing
   (win-set not identically 0) is machine-confirmed by NEGATIVE CONTROL #2
   (replacing the RHS Pr[ITSRC10 ...] with 0%r fails to compile).
   ========================================================================== *)

(* The ITSR(+C)/C10 hop: the COVERAGE part of multi-instance FORS+C EUF-CMA is
   caught by ITSR(+C)/C10 through R_ITSRC10_MFORSC10.  The reduction's
   per-signature key comes from the ITSR(+C)/C10 oracle (conditioned draw +
   record); the honest digest matches; the forgery PAIR (mk', m') is relayed.
   Because the oracle is NON-memoized, both sides draw `dcond dmkey (good m)` in
   lockstep per signature and the coupling is purely on `ts` -- there is NO mmap
   invariant (a simplification over the paper's `ITSRC_hop_M`).  Instance routing
   `idx_of y` is a deterministic function of the (equal) digest on both sides, so
   it does not break the coupling. *)
lemma ITSRC10_hop_M
  (A <: Adv_EUFCMA_MFORSC10{-R_ITSRC10_MFORSC10, -O_CMA_MFORSC10_I, -O_ITSRC10_Default, -EUF_CMA_MFORSC10_I}) &m :
    Pr[EUF_CMA_MFORSC10_I(A).main() @ &m : res /\ EUF_CMA_MFORSC10_I.covered]
  <= Pr[ITSRC10(R_ITSRC10_MFORSC10(A), O_ITSRC10_Default).main() @ &m : res].
proof.
  byequiv (_ : ={glob A} ==> (res{1} /\ EUF_CMA_MFORSC10_I.covered{1}) => res{2}) => //.
  proc.
  inline{2} R_ITSRC10_MFORSC10(A, O_ITSRC10_Default).find.
  inline{2} O_ITSRC10_Default.init O_ITSRC10_Default.get_targets.
  inline{1} O_CMA_MFORSC10_I.init O_CMA_MFORSC10_I.fresh.
  swap{2} 1 2.
  wp.
  call (:   O_CMA_MFORSC10_I.sks{1} = R_ITSRC10_MFORSC10.sks{2}
         /\ O_CMA_MFORSC10_I.ps{1} = R_ITSRC10_MFORSC10.ps{2}
         /\ O_CMA_MFORSC10_I.ad{1} = R_ITSRC10_MFORSC10.ad{2}
         /\ O_CMA_MFORSC10_I.ts{1} = O_ITSRC10_Default.ts{2}
         /\ (forall x, x \in map (fun (km : mkey * msg) => km.`2)
                                 O_CMA_MFORSC10_I.ts{1}
                       => x \in O_CMA_MFORSC10_I.qs{1})).
  + proc.
    inline{2} O_ITSRC10_Default.query.
    auto => />.
    smt(map_rcons mem_rcons).
  wp; rnd; wp; skip => />.
  rewrite /mverifyC /hC /=.
  smt(allP mapP mem_rcons).
qed.

(* ==========================================================================
   THEOREM (multi-instance FORS+C d-EU-CMA, C10-faithful), the C10 analogue of
   FORS_C_Multi.ec's EUFCMA_MFORSC.  FAITHFUL to MM45's EUFCMA_MFORSTWESNPRF
   with the substitution ITSR -> ITSR(+C)/C10; sound-direction (LHS <= sum of
   RHS terms); NO p_nu term; NO good_counter_exists premise (the existence
   obligation is discharged upstream by the LOAD-BEARING axiom `good_pos` in
   FORS_C10.ec).

   The RHS `Pr[ITSRC10(R_ITSRC10_MFORSC10(A), O_ITSRC10_Default).main()]` is
   the C10 model's game -- an UNREDUCED game probability, the NAMED NONSTANDARD
   `ITSRC10` ASSUMPTION.  It is CARRIED, never bounded (see the header and the
   FORS_C10.ec header): the black-box route loses ~102 bits and the direct route
   needs a concentration inequality EasyCrypt lacks.  This theorem is an HONEST
   CONDITIONAL, not a proof of C10 FORS security.

   HYPOTHESIS (explicit, paper-level; NOT an EasyCrypt `axiom`):
   - (H-TREE-MULTI) the residual NON-coverage part (some forgery leaf tuple was
     NEVER a target) is caught by the MULTI-instance leaf-hash OpenPRE cluster +
     tree-hash TCR + root-compression TCR -- MM45's R_FSMDTOpenPRE_EUFCMA /
     R_TRHSMDTTCRC_EUFCMA / R_TRCOSMDTTCRC_EUFCMA over d*k*t targets.  The +C
     change and the pool routing rewrite only the message->index map, never the
     per-instance Merkle-tree / root-compression layer, so these port VERBATIM.
     Discharging the premise = porting that tree layer.  Carried as an EXPLICIT
     PREMISE over forall-bound reals (as FORS_C_Multi.ec carries it), NOT a
     hidden admit: a legal clone with mtree_* <- 0%r would collapse it if it were
     a bare bound, so it must be a hypothesis.
   ========================================================================== *)
lemma EUFCMA_MFORSC10
  (A <: Adv_EUFCMA_MFORSC10{-R_ITSRC10_MFORSC10, -O_CMA_MFORSC10, -O_CMA_MFORSC10_I,
                            -O_ITSRC10_Default, -EUF_CMA_MFORSC10_I})
  (mtree_openpre mtree_trh mtree_trco : real)
  &m :
    (* (H-TREE-MULTI) EXPLICIT PREMISE, carried exactly as FORS_C_Multi.ec does. *)
    (   Pr[EUF_CMA_MFORSC10_I(A).main() @ &m : res /\ !EUF_CMA_MFORSC10_I.covered]
     <= mtree_openpre + mtree_trh + mtree_trco) =>
    Pr[EUF_CMA_MFORSC10(A, O_CMA_MFORSC10).main() @ &m : res]
  <=   Pr[ITSRC10(R_ITSRC10_MFORSC10(A), O_ITSRC10_Default).main() @ &m : res]
     + mtree_openpre + mtree_trh + mtree_trco.
proof.
  move=> htree.
  rewrite (eufcma_mforsc10_I_eq A &m).
  rewrite Pr[mu_split EUF_CMA_MFORSC10_I.covered].
  have hop := ITSRC10_hop_M A &m.
  (* covered part <= Pr[ITSRC10] (the PROVED hop); !covered part <= mtree sum
     (the premise `htree`).  The ITSRC10 term stays UNREDUCED. *)
  smt().
qed.

end MFORSC10.
