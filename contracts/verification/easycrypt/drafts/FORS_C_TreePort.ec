(* ==========================================================================
   FORS_C_TreePort.ec  --  The FORS+C tree-layer +C-VARIANT reduction PORT.

   GOAL.  Replace FORS_C.ec's SOLE tree-layer admit `htree`
        Pr[EUF_CMA_FORSC_I(A) : res /\ !covered] <= tree_openpre+tree_trh+tree_trco
   -- whose RHS is three ABSTRACT non-negative reals with NO game behind them
   (FORS_C.ec:486-488) -- by CONCRETE `Pr[subgame_i(R_i(A))]` terms over three
   +C-VARIANT tree-layer reductions, and PROVE the assembly (union bound + three
   labelled per-hop extraction admits) so the three terms have real meaning.

   This is the first leg of the multi-week port scoped in FORS_C_Tree.ec (READ
   THAT FIRST -- it is the gap characterization / design spec).  This pass is a
   SOUND DESIGN + faithful statements + honest partial proof, NOT closure.

   Relationship to FORS_C_Tree.ec.  That file argued (correctly) that there is
   NO sound, non-vacuous, typechecking tie to the EXISTING FORS_ES tree
   reductions "tonight" (gaps G1-G4: the ES modules are hard-wired to the
   counter-FREE digest, the ES theorem is `local`, single-vs-multi + abstract-vs-
   concrete type clashes).  This file does NOT tie to those ES modules.  Instead
   it builds the +C-VARIANT tree-layer development SELF-CONTAINED over the abstract
   FORSC tree vocabulary -- exactly the "WHAT A FAITHFUL FULL TIE WOULD NEED"
   programme (FORS_C_Tree.ec:141-158), started here.  The three sub-games are
   faithful mirrors of TweakableHashFunctions.eca's SM_DT_OpenPRE (leaf hash) and
   SM_DT_TCR_C (tree/root hashes); the three reductions record the CANONICAL grind
   digest and extract at the forger's FREE counter (the sound decomposition below).

   ==========================================================================
   THE SOUND DECOMPOSITION  (the design decision -- read before the code).
   ==========================================================================
   The event `res /\ !covered` (a valid+fresh FORS+C forgery whose FORS leaf set
   is NOT fully covered by the signed leaves) is the "tree-layer break".  The
   +C-variant tree layer decomposes it EXACTLY as FORS-TW does (paper Sec 4.1.1:
   "the security analysis follows verbatim" for the Merkle/root layer), with the
   counter threaded consistently:

     * SIGNING / RECORDING side  --  the honest FORS+C signer (O_CMA_FORSC_I) and
       every reduction's simulated signing oracle sign & record over the CANONICAL
       grind digest  mco mk m (gc mk m)  ( == FC.mco_C mk m ).  This is the SAME
       idiom as FORS_C.ec's honest signer and its ITSR(+C) oracle: the recorded
       leaf set is g(mco_C mk m).

     * FORGERY-EXTRACTION side  --  the reduction reads the forgery's leaf set and
       located tree/root nodes off the forger's FREE-counter digest
         mco mk' m' c'      (c' carried in the +C signature, NOT re-ground),
       so the extracted collision / preimage lands on the forger's ACTUAL digest
       (sound against the paper's PERMISSIVE verifier -- FORS_C.ec (M2)).

   WHY THIS DIRECTION IS SOUND (the union bound is the EASY direction).
   We prove   Pr[res /\ !covered] <= Pr[OP(R_op)] + Pr[TRH(R_trh)] + Pr[TRCO(R_trco)].
   The `res/\!covered` break is partitioned (union bound, EXACT below over an
   instrumented game) into: (op) a leaf-hash open-preimage, (trh) a tree-hash
   collision, (trco) the RESIDUAL root-compression collision.  Each reduction R_i
   is a TOTAL simulation whose sub-game WIN predicate is IMPLIED BY (a superset of)
   its break sub-event -- the standard OpenPRE / TCR win predicates
   (`!opened /\ dist /\ f pp tw x = y` ;  `dist /\ x<>x' /\ f pp tw x = f pp tw x'`)
   are satisfied by a genuine tree break, so Pr[subgame_i win] >= Pr[break_i].
   Hence the <= does NOT flip (the WOTS-bridge FLAG-2 flip-trap is checked, below).

   ==========================================================================
   HONESTY / FIDELITY FLAGS  (each hypothesis satisfiable + flagged for review).
   ==========================================================================
   (F-STRUCT)  The abstract FORSC `fverify` is refined to the structural Merkle
       recompute-and-compare over abstract leaf/tree/root hashes f_lf/trh/trco.
       Stated as the CLEAN EXTENSIONAL hypothesis `fverify_structural` -- it
       mentions NO coverage / collision (it is NOT the pigeonhole conclusion; that
       is the admitted TREE-SPLIT content).  SATISFIABLE: the real FORS scheme's
       fverify IS this recompute; f_lf/trh/trco/recompute/root_of are unconstrained
       abstract ops so a model exists.  NOT an EasyCrypt `axiom` -- a lemma
       hypothesis, WOTS-bridge style.

   (F-EXTRACT-{OP,TRH,TRCO})  the three per-hop pRHL bounds (that each reduction's
       forgery-extraction wins the sub-game) are the multi-week FORS_ES:3910-6590
       tree-hop re-derivations over the +C digest.  Deferred as three precisely
       labelled admits.  NOT smuggled into the reduction modules (which are
       concrete and admit-free), exactly as the WOTS bridge deferred BRIDGE-ADMIT-1.
       Each F-EXTRACT bound is true ONLY under the intended realization of the
       (unconstrained) classifier / extractor ops -- see the ROBUSTNESS LIMIT note
       above those ops for the exact caveat (brk=false collapses the split;
       brk=true would falsify F-EXTRACT-OP).  The static, non-circular
       non-degeneracy of the enumeration ops IS lifted (`enum_nondegen`).

   NON-INERTNESS.  Unlike the placeholder REMOVED from FORS_C_Tree.ec (three fresh
   abstract reals + a monotonicity lemma), the three terms here are REAL
   `Pr[game(reduction)]` over modules with behaviour, and the union assembly is a
   REAL proof.  An `op` cannot be substituted by a `Pr[...]`; a `Pr[...]` over a
   module I define is a definite value -- this is the difference.
   ========================================================================== *)

require import AllCore List Distr FMap FinType StdOrder.
require FORS_C.

(* Concrete handle on the abstract FORS+C theory: the LHS is FORS_C.ec's REAL
   EUF_CMA_FORSC_I game, not a lookalike. *)
clone import FORS_C.FORSC as FC.

(* ==========================================================================
   The +C-VARIANT abstract tree layer.

   f_lf : leaf hash        (FORS_ES.ec:455  f    = thfc (8*n)   )
   trh  : Merkle tree hash (FORS_ES.ec:591  trh  = thfc (8*n*2) )
   trco : root compression (FORS_ES.ec:623  trco = thfc (8*n*k) )
   +C never touches this layer: none of f_lf/trh/trco takes a counter or a
   message -- they operate on tree nodes BELOW the digest->index map.  This is
   the mechanical content of "follows verbatim" (the +C-invariance anchor
   `record_digest_canonical` below).
   ========================================================================== *)
type dgst.        (* tree-hash input   (concrete: bit string)  *)
type node.        (* tree-hash output  (concrete: dgstblock)   *)

op f_lf : pseed -> adrs -> dgst -> node.   (* leaf hash        *)
op trh  : pseed -> adrs -> dgst -> node.   (* tree  hash       *)
op trco : pseed -> adrs -> dgst -> node.   (* root  compression*)

(* Structural recompute of the FORS root pk-candidate from a digest y (which
   selects the opened leaves) and an auth-path signature sf, using f_lf/trh/trco.
   root_of extracts the committed root from the public key.  Both abstract -- the
   concrete Merkle-path walk of the real scheme.  See (F-STRUCT). *)
op recompute : pseed -> adrs -> out_t -> sigFORSTW -> node.
(* root_of takes (ps, ad) because the committed FORS root is RECOMPUTED under the
   verification tweaks in the real scheme (needed for the trco-factoring fidelity
   fact RK below to be REAL-scheme-satisfiable -- a fixed committed root would make
   `root_of pk = trco ps ad ...` false for the wrong (ps,ad)). *)
op root_of   : pseed -> adrs -> pkFORS -> node.

(* (F-STRUCT).  Clean extensional refinement of FORSC.fverify to the structural
   recompute-and-compare.  Mentions NO coverage / collision.  SATISFIABLE (real
   fverify is exactly this).  NOT an axiom -- a hypothesis of every lemma using it. *)
pred fverify_structural =
  forall (pk : pkFORS) (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW),
    fverify pk ps ad y sf = (recompute ps ad y sf = root_of ps ad pk).

(* ==========================================================================
   Sub-game 1:  SM-DT-OpenPRE of the leaf hash f_lf  (mirror of
   TweakableHashFunctions.SMDTOpenPRE.SM_DT_OpenPRE, FORS_ES F_OpenPRE).
   The adversary picks a target-tweak list, receives the images ys (leaf hashes
   of random unknown preimages), and outputs (i, x) : an UNOPENED target index i
   and a preimage x with f_lf pp tw_i x = y_i.
   ========================================================================== *)
op [lossless] dop_in : dgst distr.       (* preimage distribution (ddgstblocklift) *)
const t_op : { int | 1 <= t_op } as ge1_t_op.   (* FORS_ES: d*k*t >= 1 *)

module type OP_Oracle = {
  proc init(pp_init : pseed) : unit
  proc pick(tws : adrs list) : node list
  proc open(i : int) : dgst
  proc get(i : int) : adrs * node
  proc nr_targets() : int
  proc dist_tweaks() : bool
  proc opened(i : int) : bool
}.

module O_OP_Default : OP_Oracle = {
  var pp : pseed
  var ts : (adrs * node) list       (* (tweak, image) targets *)
  var xs : dgst list                (* the hidden preimages   *)
  var os : int list                 (* opened indices         *)

  proc init(pp_init : pseed) : unit = { pp <- pp_init; ts <- []; xs <- []; os <- []; }

  proc pick(tws : adrs list) : node list = {
    var x : dgst; var i : int;
    ts <- []; xs <- []; i <- 0;
    while (i < size tws) {
      x <$ dop_in;
      ts <- rcons ts (nth witness tws i, f_lf pp (nth witness tws i) x);
      xs <- rcons xs x;
      i  <- i + 1;
    }
    return unzip2 ts;
  }

  proc open(i : int) : dgst = { os <- i :: os; return nth witness xs i; }
  proc get(i : int) : adrs * node = { return nth witness ts i; }
  proc nr_targets() : int = { return size ts; }
  proc dist_tweaks() : bool = { return uniq (unzip1 ts); }
  proc opened(i : int) : bool = { return i \in os; }
}.

module type Adv_OP (O : OP_Oracle) = {
  proc pick() : adrs list
  proc find(pp : pseed, ys : node list) : int * dgst
}.

module SM_DT_OpenPRE (A : Adv_OP, O : OP_Oracle) = {
  proc main() : bool = {
    var pp : pseed; var tws : adrs list; var ys : node list;
    var i : int; var x : dgst; var tw : adrs; var y : node;
    var nrts : int; var dist, opened : bool;

    pp <$ dpseed;
    O.init(pp);
    tws <@ A(O).pick();
    ys  <@ O.pick(tws);
    (i, x) <@ A(O).find(pp, ys);
    (tw, y) <@ O.get(i);
    nrts   <@ O.nr_targets();
    dist   <@ O.dist_tweaks();
    opened <@ O.opened(i);
    return 0 <= i < nrts /\ 0 <= nrts <= t_op /\ !opened /\ dist /\ f_lf pp tw x = y;
  }
}.

(* ==========================================================================
   Sub-games 2 & 3:  SM-DT-TCR-C of the tree hash trh and root compression trco
   (mirror of TweakableHashFunctions.SMDTTCRC.SM_DT_TCR_C, FORS_ES TRHC_TCR /
   TRCOC_TCR).  Two oracles: O records TARGETS the adversary queries (tweak,x)->y;
   OC is the collection oracle (family queries at DISJOINT tweaks).  The adversary
   outputs a target index i and a SECOND preimage x' colliding at that tweak.  The
   win adds the collection-disjointness conjunct `disj_lists twsO twsOC`.
   ========================================================================== *)
const t_tcr : { int | 1 <= t_tcr } as ge1_t_tcr.   (* FORS_ES: d*k*(t-1), d >= 1 *)

op disj_lists (s1 s2 : adrs list) : bool = ! has (mem s2) s1.

module type TCR_Oracle = {
  proc init(pp_init : pseed) : unit
  proc query(tw : adrs, x : dgst) : node
  proc get(i : int) : adrs * dgst
  proc nr_targets() : int
  proc dist_tweaks() : bool
  proc get_tweaks() : adrs list
}.

module type THFC_Oracle = {
  proc init(pp_init : pseed) : unit
  proc query(tw : adrs, x : dgst) : node
  proc get_tweaks() : adrs list
}.

(* trh-instance target oracle. *)
module O_TRH_Default : TCR_Oracle = {
  var pp : pseed
  var ts : (adrs * dgst) list

  proc init(pp_init : pseed) : unit = { pp <- pp_init; ts <- []; }
  proc query(tw : adrs, x : dgst) : node = { ts <- rcons ts (tw, x); return trh pp tw x; }
  proc get(i : int) : adrs * dgst = { return nth witness ts i; }
  proc nr_targets() : int = { return size ts; }
  proc dist_tweaks() : bool = { return uniq (unzip1 ts); }
  proc get_tweaks() : adrs list = { return unzip1 ts; }
}.

module O_TRH_THFC : THFC_Oracle = {
  var pp : pseed
  var tws : adrs list
  proc init(pp_init : pseed) : unit = { pp <- pp_init; tws <- []; }
  proc query(tw : adrs, x : dgst) : node = { tws <- rcons tws tw; return trh pp tw x; }
  proc get_tweaks() : adrs list = { return tws; }
}.

module type Adv_TRH (O : TCR_Oracle, OC : THFC_Oracle) = {
  proc pick() : unit
  proc find(pp : pseed) : int * dgst
}.

module SM_DT_TCR_C_TRH (A : Adv_TRH, O : TCR_Oracle, OC : THFC_Oracle) = {
  proc main() : bool = {
    var pp : pseed; var i : int; var x, x' : dgst; var tw : adrs;
    var nrts : int; var dist : bool; var twsO, twsOC : adrs list;

    pp <$ dpseed;
    OC.init(pp);
    O.init(pp);
    A(O, OC).pick();
    (i, x') <@ A(O, OC).find(pp);
    (tw, x) <@ O.get(i);
    nrts  <@ O.nr_targets();
    dist  <@ O.dist_tweaks();
    twsO  <@ O.get_tweaks();
    twsOC <@ OC.get_tweaks();
    return 0 <= i < nrts /\ 0 <= nrts <= t_tcr /\ dist /\ x <> x'
        /\ trh pp tw x = trh pp tw x' /\ disj_lists twsO twsOC;
  }
}.

(* trco-instance target oracle (root compression). *)
module O_TRCO_Default : TCR_Oracle = {
  var pp : pseed
  var ts : (adrs * dgst) list

  proc init(pp_init : pseed) : unit = { pp <- pp_init; ts <- []; }
  proc query(tw : adrs, x : dgst) : node = { ts <- rcons ts (tw, x); return trco pp tw x; }
  proc get(i : int) : adrs * dgst = { return nth witness ts i; }
  proc nr_targets() : int = { return size ts; }
  proc dist_tweaks() : bool = { return uniq (unzip1 ts); }
  proc get_tweaks() : adrs list = { return unzip1 ts; }
}.

module O_TRCO_THFC : THFC_Oracle = {
  var pp : pseed
  var tws : adrs list
  proc init(pp_init : pseed) : unit = { pp <- pp_init; tws <- []; }
  proc query(tw : adrs, x : dgst) : node = { tws <- rcons tws tw; return trco pp tw x; }
  proc get_tweaks() : adrs list = { return tws; }
}.

module type Adv_TRCO (O : TCR_Oracle, OC : THFC_Oracle) = {
  proc pick() : unit
  proc find(pp : pseed) : int * dgst
}.

module SM_DT_TCR_C_TRCO (A : Adv_TRCO, O : TCR_Oracle, OC : THFC_Oracle) = {
  proc main() : bool = {
    var pp : pseed; var i : int; var x, x' : dgst; var tw : adrs;
    var nrts : int; var dist : bool; var twsO, twsOC : adrs list;

    pp <$ dpseed;
    OC.init(pp);
    O.init(pp);
    A(O, OC).pick();
    (i, x') <@ A(O, OC).find(pp);
    (tw, x) <@ O.get(i);
    nrts  <@ O.nr_targets();
    dist  <@ O.dist_tweaks();
    twsO  <@ O.get_tweaks();
    twsOC <@ OC.get_tweaks();
    return 0 <= i < nrts /\ 0 <= nrts <= t_tcr /\ dist /\ x <> x'
        /\ trco pp tw x = trco pp tw x' /\ disj_lists twsO twsOC;
  }
}.

(* ==========================================================================
   PORT-RESIDUAL abstract ops (the concrete tree enumeration / extraction; the
   multi-week FORS_ES:2135-2815 +C-port compressed into flagged ops).  Each is
   an unconstrained abstract op -> a MODEL exists (non-vacuity), and its concrete
   realisation is the deferred work discharged by the F-EXTRACT admits.

   NON-VACUITY ROLE.  The reduction signing oracles CALL the *_targets ops to
   register real targets in O (so nrts > 0 whenever A signs) -- WITHOUT this a
   never-querying reduction would force nrts=0, Pr[subgame]=0, and the EXTRACT
   admit would be FALSE (identically-0 RHS).  This is the TRCO degeneracy the
   coordinator flagged; the enumeration ops close it.
   ========================================================================== *)
(* OpenPRE (leaf-hash) reduction residuals *)
op all_leaf_tweaks   : adrs -> adrs list.
op opened_leaf_idxs  : pseed -> adrs -> out_t -> int list.
op sim_sig_op        : pseed -> adrs -> node list -> out_t -> sigFORSTW.
op pk_of_leaves      : pseed -> adrs -> node list -> pkFORS.
(* extract_op is DEFINED concretely below (after the leaf-level exposure ops +
   leaf_targets it is grounded in) -- see the `op extract_op = ...` definition in the
   LEAF-HASH OPEN-PREIMAGE WITNESS SPINE.  Like extract_trh/extract_trco it is no longer
   a free op: the index-fidelity port pins its index to the REGISTERED leaf target
   `index (leaf_tw .., cleaf_out ..) (leaf_targets ..)` and its preimage to the forger's
   revealed leaf value `fleaf_in ..`. *)
(* TRH / TRCO (tree/root-hash) reduction residuals *)
op trh_targets       : pseed -> adrs -> out_t -> sigFORSTW -> (adrs * dgst) list.
op trco_targets      : pseed -> adrs -> out_t -> sigFORSTW -> (adrs * dgst) list.
(* extract_trh is DEFINED concretely below (after the interior-exposure ops +
   honest_nodes/div_level it is grounded in) -- see the `op extract_trh = ...`
   definition following `trh_collision_at_div`.  Like extract_trco it is no longer a
   free op: the index-fidelity port pins its index to the REGISTERED honest interior
   target `index (inode_tw ..,cin_at ..) (honest_nodes ..)` and its 2nd-preimage to
   the forger interior input `fin_at ..`. *)
(* extract_trco is DEFINED concretely below (after the structural exposure ops it
   is grounded in) -- see the `op extract_trco = ...` definition following
   `leaf_div`.  It is no longer a free op: the index-fidelity port pins its node
   component to the TRUSTED `roots_dgst (froots_of ..)`. *)
(* break classifiers (the case-split characterization; TREE-SPLIT residual).
   FREE ops -- but PINNED structurally by `brk_structural` (below): they are
   DEFINED as a genuine 3-way partition of the break over the structural recompute
   (froots_of/croots_of/leaf_div), NOT left arbitrary.  See the ROBUSTNESS note. *)
op brk_op  : pkFORS -> pseed -> adrs -> msg -> sigFORSC -> (mkey * msg * cntr) list -> bool.
op brk_trh : pkFORS -> pseed -> adrs -> msg -> sigFORSC -> (mkey * msg * cntr) list -> bool.

(* ==========================================================================
   STRUCTURAL Merkle-recompute exposure ops (the refinement that PINS the
   classifiers).  These are the +C-invariant tree-layer structure of the abstract
   `recompute`: a valid FORS verify walks each of the k trees from its revealed
   leaf up to a PER-TREE ROOT (froots_of), then trco-COMPRESSES the encoded root
   list (roots_dgst) into the FORS root.  `croots_of` exposes the SAME per-tree
   roots as committed in pk; `leaf_div` is the leaf-vs-interior locator used only
   when the forger's per-tree roots MATCH the committed ones.  All are counter-FREE
   (the +C-invariance anchor) and carry the SAME structural-fidelity residual as
   `fverify_structural` -- faithful to the real Merkle recompute, satisfiable by the
   real scheme.  They are the ONLY new trust surface, and it is of the SAME family
   as (F-STRUCT); crucially it is built from the TRUSTED recompute/root_of/trco --
   NOT from the deferred extract_* ops (which would relocate trust onto the very
   objects the F-EXTRACT admits defer). *)
op froots_of  : pseed -> adrs -> out_t -> sigFORSTW -> node list.  (* forger    per-tree roots *)
op croots_of  : pseed -> adrs -> pkFORS -> node list.              (* committed per-tree roots *)
op roots_dgst : node list -> dgst.                                (* encode k roots as trco input *)
op leaf_div   : pseed -> adrs -> out_t -> sigFORSTW -> pkFORS -> bool. (* leaf-vs-interior locator *)

(* ==========================================================================
   extract_trco  --  CONCRETE index-fidelity extractor (the trco F-EXTRACT port).
   ==========================================================================
   Grounded ENTIRELY in the TRUSTED exposure ops (froots_of / roots_dgst) + FC.mco
   -- NOT a fresh free op that would relocate the gap.  Two components:
     * NODE (2nd trco preimage) = roots_dgst (froots_of ps ad (mco ..) sig'.`3),
       i.e. the encoding of the FORGER's per-tree roots -- the DISTINCT input
       whose trco-collision with the committed encoding is proved by
       `trco_collision_core`.
     * INDEX = 0.  At THIS abstraction layer trco is called EXACTLY ONCE per FORS
       instance (it compresses the k FIXED per-tree roots into pk; every signature
       shares those same k roots), so R_trco registers the committed-root target
       ONCE in find() and O_TRCO_Default.ts is a SINGLETON.  The byequiv PROVES
       ts = [that target], so index 0 NAMES the registered collision target -- this
       is DERIVED (bookkeeping discharged in-proof), NOT an assumed extraction
       outcome.  The multi-target locating (which of many interior nodes) lives one
       layer up (the hypertree), not here. *)
op extract_trco (pk : pkFORS) (ps : pseed) (ad : adrs) (m' : msg) (sig' : sigFORSC)
  : int * dgst =
  (0, roots_dgst (froots_of ps ad (mco sig'.`1 m' sig'.`2) sig'.`3)).

(* ==========================================================================
   ###  HONESTY  --  ROBUSTNESS OF THE THREE-WAY SPLIT  (footgun NARROWED).
   ==========================================================================
   PRIOR FOOTGUN (now closed).  An earlier revision left brk_op/brk_trh as
   UNCONSTRAINED free ops.  That was a landmine for whoever later discharges the
   F-EXTRACT admits: an individual admit was FALSE for some instantiation --
       - brk_op := brk_trh := (fun _ => false)  made F-EXTRACT-OP / -TRH read
         `Pr[.. /\ false] = 0 <= Pr[..]` (trivially true) and DUMPED the whole
         break into F-EXTRACT-TRCO (three terms collapse to one; the trco admit
         becomes `Pr[whole break] <= Pr[TRCO]`, FALSE for a leaf-preimage forgery);
       - brk_op := (fun _ => true)  made F-EXTRACT-OP read `Pr[whole break] <=
         Pr[OP(R_op)]`, FALSE for a trh-collision forgery.
   The ASSEMBLY's statement was classifier-independent and SYSTEM-soundness held
   (no single brk discharges all three vacuously), but each F-EXTRACT admit being
   false-for-some-instantiation is a trap.

   THE FIX (`brk_structural`, below).  We PIN what brk_op/brk_trh COMPUTE -- NOT
   the extraction outcome -- via a top-level STRUCTURAL case-split over the trusted
   recompute exposure ops (froots_of/croots_of/roots_dgst/leaf_div + trco):
       ebop  := (froot-list = croot-list) /\   leaf_div    (in-tree, LEAF level)
       ebtrh := (froot-list = croot-list) /\ ! leaf_div    (in-tree, INTERIOR)
       residual (trco) := (froot-list <> croot-list)       (roots differ but, on a
                          valid forgery, trco-compress equal -> a genuine trco
                          collision -- BY CONSTRUCTION, not by assumption).
   This is MUTUALLY-EXCLUSIVE and EXHAUSTIVE by the SHAPE of the split (proved as
   `brk_genuine_partition`): the trco residual is `froots <> croots`, NOT "whatever
   is left over".  Hence BOTH degenerate instantiations above are EXCLUDED
   simultaneously -- the op AND trco admits are non-falsifiable AT ONCE (the
   coordinator's discriminating test), and no constant brk satisfies brk_structural.

   WHY THIS IS NOT CIRCULAR (the KEY distinction).  brk_structural constrains what
   the classifiers COMPUTE (a definition, from the structural recompute).  It says
   NOTHING about the game state (nrts / opened / dist / O_*.ts) -- so the step
   `ebop => R_op wins OpenPRE` STILL requires the reduction's simulation invariant
   (the multi-week pRHL).  We do NOT lift the extraction OUTCOME (break => R_i wins)
   -- that is the pigeonhole CONCLUSION and assuming it is the circularity trap; it
   STAYS an admit.  (Sanity: adding brk_structural does NOT let one `qed` any
   F-EXTRACT -- the win-predicate game facts are simply absent from it.)

   RESIDUAL (narrowed, honest).  The footgun is NOT reduced to nothing: it is
   NARROWED to the STRUCTURAL-RECOMPUTE FIDELITY of {froots_of, croots_of,
   roots_dgst, leaf_div} -- "these ops faithfully model the real Merkle recompute"
   (RC/RK in brk_structural tie them to the trusted recompute/root_of/trco).  This
   residual is of the SAME family as (F-STRUCT)/fverify_structural, satisfiable by
   the real FORS scheme (the real recompute IS trco-of-encoded-per-tree-roots), and
   is flagged for review identically.  Crucially it is grounded in the TRUSTED
   recompute/root_of -- NOT in the deferred extract_* ops (grounding brk in
   extract_* would merely RELOCATE the freedom onto the objects the F-EXTRACT
   admits defer).

   We ALSO retain the static, non-circular NON-DEGENERACY of the enumeration ops
   (below), which removes the identically-0-RHS falsification route (a
   never-querying reduction => nrts=0 => Pr[subgame]=0 => false admit).
   ========================================================================== *)

(* Static, non-circular, SATISFIABLE non-degeneracy of the enumeration ops:
   every honest signature registers >= 1 target in the sub-game oracle (so the
   RHS is not structurally 0).  Witness realisation: the real FORS scheme
   enumerates >= 1 leaf / >= k-1 trh nodes / 1 trco root per FORS instance.
   A hypothesis of the F-EXTRACT bounds (NOT an axiom); flagged for review. *)
pred enum_nondegen =
     (forall (ad : adrs), all_leaf_tweaks ad <> [])
  /\ (forall (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW),
        trh_targets ps ad y sf <> [])
  /\ (forall (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW),
        trco_targets ps ad y sf <> []).

(* ==========================================================================
   brk_structural  --  PIN the classifiers to a genuine structural 3-way split.
   ==========================================================================
   Closes the prior footgun (free brk_op/brk_trh; see the ROBUSTNESS note above).
   FOUR conjuncts, ALL of the (F-STRUCT) family (constrain what ops COMPUTE, never
   an extraction outcome / probability):

   (RC)  forger fidelity   -- recompute factors through the per-tree roots + trco.
   (RK)  committed fidelity -- root_of factors through the committed roots + trco.
         (Both TIE the new exposure ops to the TRUSTED recompute/root_of, so the
          new ops cannot be chosen degenerately -- no footgun relocation.)
   (DEF-OP), (DEF-TRH)  -- brk_op / brk_trh DEFINED as the leaf / interior branch
         of the in-tree case (froots = croots), leaving the trco residual EXACTLY
         (froots <> croots).  Definitions of the FREE ops brk_op / brk_trh -- NOT
         an assumption about the game or the reduction.
   SATISFIABLE (non-vacuous): the constrained ops recompute, root_of, brk_op,
   brk_trh are all FREE and appear only on the LHS of these defining equations, so
   for ANY realisation of the RHS ops (trco, roots_dgst, froots_of, croots_of,
   leaf_div, f_lf, mco) a model exists -- and the INTENDED model is the real FORS
   scheme (real recompute = trco-of-encoded-per-tree-roots; real root_of = the same
   over the committed roots).  Not an EasyCrypt `axiom` -- a lemma hypothesis. *)
pred brk_structural =
     (* (RC) forger per-tree roots factor recompute through the trco compression *)
     (forall (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW),
        recompute ps ad y sf = trco ps ad (roots_dgst (froots_of ps ad y sf)))
     (* (RK) committed per-tree roots factor root_of through the trco compression *)
  /\ (forall (ps : pseed) (ad : adrs) (pk : pkFORS),
        root_of ps ad pk = trco ps ad (roots_dgst (croots_of ps ad pk)))
     (* (DEF-OP) brk_op fires EXACTLY on the in-tree LEAF-level divergence *)
  /\ (forall (pk : pkFORS) (ps : pseed) (ad : adrs) (m' : msg) (sig' : sigFORSC)
             (ts : (mkey * msg * cntr) list),
        brk_op pk ps ad m' sig' ts
        = (   froots_of ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 = croots_of ps ad pk
           /\ leaf_div ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 pk))
     (* (DEF-TRH) brk_trh fires EXACTLY on the in-tree INTERIOR-level divergence *)
  /\ (forall (pk : pkFORS) (ps : pseed) (ad : adrs) (m' : msg) (sig' : sigFORSC)
             (ts : (mkey * msg * cntr) list),
        brk_trh pk ps ad m' sig' ts
        = (   froots_of ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 = croots_of ps ad pk
           /\ ! leaf_div ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 pk)).

(* GENUINE 3-WAY PARTITION (the anti-footgun core -- a REAL proof, zero admit).
   Under brk_structural's DEF-OP/DEF-TRH, the three break-cases ebop / ebtrh /
   residual are MUTUALLY EXCLUSIVE and EXHAUSTIVE, and the trco residual is pinned
   to `froots <> croots` -- NOT "whatever is left over".  This is precisely what
   makes BOTH the op admit and the trco RESIDUAL admit non-falsifiable AT ONCE:
   no constant classifier (brk := true / false) can satisfy this shape, so neither
   degenerate collapse of the old free-op footgun survives. *)
lemma brk_genuine_partition (froots croots : node list) (L : bool) :
     (* mutual exclusion *)
     (((froots = croots) /\ L) => ! ((froots = croots) /\ ! L))
     (* residual is EXACTLY the trco case (roots differ), not the whole leftover *)
  /\ ( (! ((froots = croots) /\ L) /\ ! ((froots = croots) /\ ! L))
       <=> froots <> croots ).
proof. by rewrite negb_and /#. qed.

(* ==========================================================================
   roots_dgst_inj  --  FLAGGED STRUCTURAL-FIDELITY HYPOTHESIS (fverify_structural
   family).  The k-root encoding `roots_dgst` (k per-tree roots -> the trco input)
   is INJECTIVE.
   SATISFIABLE (non-vacuous): the real scheme's roots_dgst is the fixed-width
   byte-concatenation of the k per-tree roots -- manifestly injective.  Grounded in
   the TRUSTED encoding op `roots_dgst` ALONE -- NOT in any deferred extract_* op
   (so it does not relocate the extraction freedom).  NOT an EasyCrypt `axiom` -- a
   lemma hypothesis, exactly like fverify_structural / brk_structural. *)
pred roots_dgst_inj =
  forall (rs rs' : node list), roots_dgst rs = roots_dgst rs' => rs = rs'.

(* ==========================================================================
   trco_collision_core  --  the MATHEMATICAL HEART of the trco S-TCR-C hop
   (REAL PROOF, zero admit).
   ==========================================================================
   On a VALID FORS+C forgery whose forger per-tree roots DIFFER from the committed
   roots -- i.e. the trco RESIDUAL case  (! ebop /\ ! ebtrh  <=>  froots <> croots,
   by brk_genuine_partition) -- validity FORCES the two DISTINCT trco-inputs to
   compress to the SAME trco output.  That is a genuine target-collision on trco:
       roots_dgst (froots_of ..)  <>  roots_dgst (croots_of ..)      (distinct inputs)
    /\ trco ps ad (roots_dgst (froots_of ..)) = trco ps ad (roots_dgst (croots_of ..)).

   DERIVATION (all TRUSTED, no extract_* op, NO assumed extraction outcome):
     validity  =>  fverify pk ps ad y sf                        (verifyC)
               =>  recompute ps ad y sf = root_of ps ad pk      (fverify_structural)
     RC/RK (brk_structural)  factor both sides through trco:
               =>  trco ps ad (roots_dgst (froots_of ..))
                     = trco ps ad (roots_dgst (croots_of ..))
     roots_dgst_inj + (froots <> croots)  =>  the trco-inputs are DISTINCT.

   This is the WITNESS half of "residual => R_trco wins TCR-C": it produces the
   colliding pair with NO circularity (it never assumes R_trco wins, never touches
   extract_trco / O_TRCO state).  What it deliberately does NOT supply -- and what
   the extract_trco residual admit still owes -- is that `extract_trco` NAMES the
   REGISTERED O_TRCO_Default index of THIS collision (the index-fidelity /
   bookkeeping half of the win predicate). *)
lemma trco_collision_core (pk : pkFORS) (ps : pseed) (ad : adrs)
                          (m' : msg) (sig' : sigFORSC) :
     fverify_structural =>
     brk_structural =>
     roots_dgst_inj =>
     verifyC pk ps ad m' sig' =>
     froots_of ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 <> croots_of ps ad pk =>
       roots_dgst (froots_of ps ad (mco sig'.`1 m' sig'.`2) sig'.`3)
         <> roots_dgst (croots_of ps ad pk)
     /\ trco ps ad (roots_dgst (froots_of ps ad (mco sig'.`1 m' sig'.`2) sig'.`3))
        = trco ps ad (roots_dgst (croots_of ps ad pk)).
proof.
  rewrite /fverify_structural /brk_structural /roots_dgst_inj.
  move=> fvs [rc [rk _]] rdi hvld hne.
  split.
  + by apply/negP => heq; apply hne; apply (rdi _ _ heq).
  have fv : recompute ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 = root_of ps ad pk.
  + move: hvld hne; case: sig' => mk c sf /= hvld _.
    by move: hvld; rewrite /verifyC /= fvs; smt().
  by rewrite rc rk in fv; exact fv.
qed.

(* ==========================================================================
   trco_residual_collision  --  ASSEMBLY of the classifier residual to the trco
   collision witness (REAL PROOF, zero admit).
   ==========================================================================
   Directly the content G_Tree's ghosts feed: on a VALID forgery in the classifier
   RESIDUAL (! brk_op /\ ! brk_trh), a genuine DISTINCT-input trco collision holds.
   Ties three proven pieces with NO extraction outcome assumed:
     * brk_structural DEF-OP/DEF-TRH   -- ! brk_op /\ ! brk_trh unfolds to
       ! (froots=croots /\ leaf_div) /\ ! (froots=croots /\ ! leaf_div),
     * brk_genuine_partition           -- that pair is EXACTLY (froots <> croots),
     * trco_collision_core             -- froots <> croots + validity => collision.
   This is the classifier-level statement the extract_trco residual rests on; the
   ONLY thing left after it is that `extract_trco` NAMES the registered O_TRCO index
   of this collision (index-fidelity) -- everything else is now a real proof. *)
lemma trco_residual_collision (pk : pkFORS) (ps : pseed) (ad : adrs)
                              (m' : msg) (sig' : sigFORSC)
                              (ts : (mkey * msg * cntr) list) :
     fverify_structural =>
     brk_structural =>
     roots_dgst_inj =>
     verifyC pk ps ad m' sig' =>
     ! brk_op  pk ps ad m' sig' ts =>
     ! brk_trh pk ps ad m' sig' ts =>
       roots_dgst (froots_of ps ad (mco sig'.`1 m' sig'.`2) sig'.`3)
         <> roots_dgst (croots_of ps ad pk)
     /\ trco ps ad (roots_dgst (froots_of ps ad (mco sig'.`1 m' sig'.`2) sig'.`3))
        = trco ps ad (roots_dgst (croots_of ps ad pk)).
proof.
  move=> fvs bs rdi vld nbop nbtrh.
  move: (bs); rewrite /brk_structural => -[_ [_ [defop deftrh]]].
  move: nbop nbtrh;
    rewrite (defop pk ps ad m' sig' ts) (deftrh pk ps ad m' sig' ts) => nbop nbtrh.
  have hne : froots_of ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 <> croots_of ps ad pk.
  + have gp := brk_genuine_partition
                 (froots_of ps ad (mco sig'.`1 m' sig'.`2) sig'.`3)
                 (croots_of ps ad pk)
                 (leaf_div ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 pk).
    by move: gp => [_ h]; rewrite -h; split.
  exact (trco_collision_core pk ps ad m' sig' fvs bs rdi vld hne).
qed.

(* ==========================================================================
   ###  THE INTERIOR TRH S-TCR-C WITNESS SPINE  (the trh analogue of the trco
   `trco_collision_core` chain -- REAL PROOFS, zero admit).
   ==========================================================================
   trco was a SINGLE compression per FORS instance, so its collision witness was a
   one-liner (RC/RK factor recompute/root_of through ONE trco call; distinct inputs
   from roots_dgst_inj).  trh is an INTERIOR Merkle FOLD: the forger and the honest
   signer walk the SAME tree from (different) leaves up to the SAME per-tree root, so
   the collision is at an a-priori-UNKNOWN divergence level.  The witness therefore
   needs a genuine PIGEONHOLE over the level chain, not a one-liner.  We build it in
   three real-qed pieces mirroring the trco spine:
     (1) first_merge            -- pure list/int pigeonhole (the mathematical heart).
     (2) trh_interior_structural -- the interior structural-exposure FIDELITY layer
                                    (fverify_structural / brk_structural family:
                                    constrains what the chain ops COMPUTE, grounded
                                    in TRUSTED trh -- NOT a collision-existence and
                                    NOT any extract_* op).
     (3) trh_collision_core / trh_residual_collision -- validity + ebtrh => a genuine
                                    distinct-input trh collision at a LOCATED interior
                                    node (the trco_collision_core / _residual analogue).
   ========================================================================== *)

(* Interior Merkle tree height for one FORS tree (>= 1 so an interior step exists). *)
const H_tree : { int | 1 <= H_tree } as ge1_H_tree.

(* ==========================================================================
   first_merge  --  the PIGEONHOLE (pure, real qed, no scheme dependence).
   ==========================================================================
   Two level-indexed value chains fv, cv that DIFFER at the bottom (level 0) but
   MEET at the top (level h) must have a FIRST-MERGE level j in [0,h): the running
   values still differ at j but have become equal at j+1.  This is the abstract
   content of "two Merkle paths to the same root from different leaves collide
   somewhere".  Proved by ordinary nat induction on h (base is vacuous: fv 0 <> cv 0
   contradicts fv 0 = cv 0). *)
lemma first_merge (fv cv : int -> node) (h : int) :
     0 <= h =>
     fv 0 <> cv 0 =>
     fv h = cv h =>
     exists j, 0 <= j < h /\ fv j <> cv j /\ fv (j + 1) = cv (j + 1).
proof.
  move=> ge0h neq0; move: ge0h; elim/intind: h.
  + by move=> h0; move: neq0; rewrite h0.
  + move=> i ge0i IH hSi.
    case: (fv i = cv i) => hi.
    - have [j [hj1 [hj2 hj3]]] := IH hi.
      by exists j; smt().
    - by exists i; smt().
qed.

(* ==========================================================================
   Interior structural-exposure ops (the trh analogue of froots_of/croots_of).
   ==========================================================================
   Along the FORGER's tree path (the crux the reviewer flagged: the honest side is
   compared AT THE FORGER-PATH POSITION, so its ops depend on (y, sf), NOT just pk):
     frun     -- the FORGER's running trh value at level j (bottom = leaf-hash out).
     crun     -- the HONEST tree's value at the forger-path node at level j.
     inode_tw -- the interior-node tweak (address) at level j on the forger path
                 (a function of the leaf index carried by y -- the same address the
                 honest signer registers for that node).
     fin_at / cin_at -- the forger / honest trh-INPUT at level j (the (child‖sibling)
                 encoding).  All counter-FREE (+C-invariance) and of the SAME trust
                 family as froots_of/croots_of: grounded in the TRUSTED trh recompute,
                 NEVER in extract_*. *)
op frun     : pseed -> adrs -> out_t -> sigFORSTW -> int -> node.
op crun     : pseed -> adrs -> out_t -> sigFORSTW -> pkFORS -> int -> node.
op inode_tw : pseed -> adrs -> out_t -> int -> adrs.
op fin_at   : pseed -> adrs -> out_t -> sigFORSTW -> int -> dgst.
op cin_at   : pseed -> adrs -> out_t -> sigFORSTW -> pkFORS -> int -> dgst.

(* ==========================================================================
   trh_interior_structural  --  FLAGGED STRUCTURAL-FIDELITY HYPOTHESIS
   (fverify_structural / brk_structural / roots_dgst_inj family).
   ==========================================================================
   FIVE conjuncts, ALL constraining what the chain ops COMPUTE (a definition from the
   trusted trh recompute), NONE asserting a collision / a registered index:
     (IC-F)   forger chain step  -- level j+1 value is trh of the forger input at j.
     (IC-C)   honest chain step  -- ditto along the forger path (SAME tweak inode_tw).
     (IC-INJ) input fidelity     -- distinct running values => distinct trh-INPUTS
              (the (child‖sibling) encoding is injective in the child; roots_dgst_inj
              family, grounded in the trusted encoding -- NOT a collision).
     (IC-TOP) equal per-tree roots => the two chains MEET at the top level H_tree.
     (IC-BOT) interior (not leaf) divergence => the two chains DIFFER at level 0
              (the structural MEANING of `! leaf_div`: the divergence sits in the trh
              interior, so the leaf-hash outputs already differ -- an INEQUALITY of
              honest values, NOT a collision).
   SATISFIABLE (non-vacuous): the INTENDED model is the real FORS Merkle tree with a
   forgery.  frun/crun/inode_tw/fin_at/cin_at are FREE and appear on the LHS of the
   defining/fidelity equations; for the real tree, IC-F/IC-C hold by the definition
   of the Merkle walk, IC-INJ by fixed-width concatenation, and IC-TOP/IC-BOT are
   genuinely INHABITED (a fresh forgery whose k per-tree roots equal the committed
   ones but whose opened leaves differ has frun 0 <> crun 0 AND frun H_tree =
   crun H_tree -- ebtrh is not empty).  NOT an EasyCrypt `axiom` -- a lemma
   hypothesis, exactly like fverify_structural / brk_structural / roots_dgst_inj. *)
pred trh_interior_structural =
     (* (IC-F) forger chain step *)
     (forall (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW) (j : int),
        0 <= j < H_tree =>
          frun ps ad y sf (j + 1)
        = trh ps (inode_tw ps ad y j) (fin_at ps ad y sf j))
     (* (IC-C) honest chain step along the forger path *)
  /\ (forall (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW) (pk : pkFORS) (j : int),
        0 <= j < H_tree =>
          crun ps ad y sf pk (j + 1)
        = trh ps (inode_tw ps ad y j) (cin_at ps ad y sf pk j))
     (* (IC-INJ) distinct running values => distinct trh-inputs *)
  /\ (forall (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW) (pk : pkFORS) (j : int),
        0 <= j < H_tree =>
        frun ps ad y sf j <> crun ps ad y sf pk j =>
        fin_at ps ad y sf j <> cin_at ps ad y sf pk j)
     (* (IC-TOP) equal per-tree roots => chains meet at the top *)
  /\ (forall (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW) (pk : pkFORS),
        froots_of ps ad y sf = croots_of ps ad pk =>
        frun ps ad y sf H_tree = crun ps ad y sf pk H_tree)
     (* (IC-BOT) interior (not leaf) divergence => chains differ at the bottom *)
  /\ (forall (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW) (pk : pkFORS),
        ! leaf_div ps ad y sf pk =>
        frun ps ad y sf 0 <> crun ps ad y sf pk 0).

(* ==========================================================================
   trh_collision_core  --  the MATHEMATICAL HEART of the trh interior S-TCR-C hop
   (REAL PROOF, zero admit; the trco_collision_core analogue).
   ==========================================================================
   In the ebtrh case (froots = croots /\ ! leaf_div): the forger and honest chains
   MEET at the top (IC-TOP) but DIFFER at the bottom (IC-BOT), so by first_merge there
   is a level j where the running values still differ but merge at j+1.  The two chain
   steps (IC-F, IC-C) at that j feed the SAME tweak inode_tw and produce the SAME
   output (frun (j+1) = crun (j+1)); IC-INJ makes their INPUTS distinct.  That is a
   genuine distinct-input trh collision at a LOCATED interior tweak -- with NO
   circularity (never assumes R_trh wins, never touches extract_trh / O_TRH state). *)
lemma trh_collision_core (ps : pseed) (ad : adrs) (y : out_t)
                         (sf : sigFORSTW) (pk : pkFORS) :
     trh_interior_structural =>
     froots_of ps ad y sf = croots_of ps ad pk =>
     ! leaf_div ps ad y sf pk =>
     exists j, 0 <= j < H_tree
       /\ cin_at ps ad y sf pk j <> fin_at ps ad y sf j
       /\ trh ps (inode_tw ps ad y j) (cin_at ps ad y sf pk j)
          = trh ps (inode_tw ps ad y j) (fin_at ps ad y sf j).
proof.
  rewrite /trh_interior_structural.
  move=> [icf [icc [icinj [ictop icbot]]]] hroots hleaf.
  have htop : frun ps ad y sf H_tree = crun ps ad y sf pk H_tree by apply ictop.
  have hbot : frun ps ad y sf 0 <> crun ps ad y sf pk 0 by apply icbot.
  have ge0H : 0 <= H_tree by smt(ge1_H_tree).
  have [j [hj1 [hj2 hj3]]] :=
    first_merge (fun k => frun ps ad y sf k) (fun k => crun ps ad y sf pk k) H_tree
                ge0H hbot htop.
  move: hj2 hj3 => /= hne hmerge.
  have hinj : fin_at ps ad y sf j <> cin_at ps ad y sf pk j
    by apply (icinj ps ad y sf pk j); smt().
  have hf : frun ps ad y sf (j + 1)
          = trh ps (inode_tw ps ad y j) (fin_at ps ad y sf j) by apply icf; smt().
  have hc : crun ps ad y sf pk (j + 1)
          = trh ps (inode_tw ps ad y j) (cin_at ps ad y sf pk j) by apply icc; smt().
  exists j; split; first smt().
  split; first smt().
  by rewrite -hc -hf hmerge.
qed.

(* ==========================================================================
   trh_residual_collision  --  assemble the ebtrh classifier to the interior
   collision witness (REAL PROOF, zero admit; the trco_residual_collision analogue).
   ==========================================================================
   From brk_structural DEF-TRH, `brk_trh` fires EXACTLY on (froots = croots /\
   ! leaf_div) over the FORGER digest mco sig'.`1 m' sig'.`2 -- feed that straight to
   trh_collision_core.  This is the classifier-level statement the extract_trh residual
   rests on; the only thing left after it is that `extract_trh` NAMES a registered
   O_TRH_Default index for this collision (the multi-target index-fidelity). *)
lemma trh_residual_collision (pk : pkFORS) (ps : pseed) (ad : adrs)
                             (m' : msg) (sig' : sigFORSC)
                             (ts : (mkey * msg * cntr) list) :
     brk_structural =>
     trh_interior_structural =>
     brk_trh pk ps ad m' sig' ts =>
     exists j, 0 <= j < H_tree
       /\ cin_at ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 pk j
            <> fin_at ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 j
       /\ trh ps (inode_tw ps ad (mco sig'.`1 m' sig'.`2) j)
                 (cin_at ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 pk j)
          = trh ps (inode_tw ps ad (mco sig'.`1 m' sig'.`2) j)
                   (fin_at ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 j).
proof.
  move=> bs tis btrh.
  move: (bs); rewrite /brk_structural => -[_ [_ [_ deftrh]]].
  move: btrh; rewrite (deftrh pk ps ad m' sig' ts) => -[hroots hleaf].
  exact (trh_collision_core ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 pk tis hroots hleaf).
qed.

(* ==========================================================================
   ###  THE INDEX-FIDELITY LAYER  (the trh analogue of the trco singleton trick).
   ==========================================================================
   trco named its collision index by a SINGLETON (index 0).  trh cannot: the honest
   interior targets are MANY.  Register-once fix (mirrors R_trco's find()-time
   registration): R_trh registers the WHOLE honest interior-node set `honest_nodes`
   ONCE in find() (it knows sk from fkeygen), so O_TRH_Default.ts is a FIXED list with
   DISTINCT tweaks (dist holds -- the per-sign loop that DESTROYED dist is gone) and
   nrts = size honest_nodes <= t_tcr = d*k*(t-1).  The forger's divergence node is one
   of those honest positions, so its registered index is `index (inode_tw, cin_at)
   honest_nodes` -- NAMEABLE, not a singleton. *)

(* Full honest interior-node target set of ONE FORS instance: (tweak, trh-input) for
   every interior node of all k trees.  Registered ONCE in R_trh.find(). *)
op honest_nodes : pseed -> adrs -> pkFORS -> (adrs * dgst) list.

(* Concrete first-merge level: the first index in [0,H_tree) at which the forger and
   honest running chains still differ but merge one level up.  DEFINED from the trusted
   frun/crun via `find` over the level range -- NOT a free choice op; its merge property
   is DERIVED from first_merge (real qed) in the ebtrh case. *)
op div_level (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW) (pk : pkFORS) : int =
  find (fun (j : int) =>    frun ps ad y sf j       <> crun ps ad y sf pk j
                         /\ frun ps ad y sf (j + 1)  = crun ps ad y sf pk (j + 1))
       (iota_ 0 H_tree).

(* ==========================================================================
   trh_registration  --  FLAGGED STRUCTURAL-FIDELITY HYPOTHESIS (fverify_structural
   / trh_interior_structural family).  The honest-target REGISTRATION coverage.
   ==========================================================================
   THREE conjuncts, all about the HONEST tree registration (grounded in the trusted
   honest_nodes / inode_tw / cin_at -- NOT extract_*, NOT a collision):
     (REG-MEM)  every interior node ON A FORGER PATH is a registered honest target
                carrying the HONEST trh-input (the honest tree covers every position).
     (REG-UNIQ) the honest target tweaks are DISTINCT (distinct tree-node addresses)
                -> the game's `dist = uniq (unzip1 ts)` holds.
     (REG-SIZE) the honest target count is within the TCR budget t_tcr (= d*k*(t-1)).
   SATISFIABLE (non-vacuous): the real FORS scheme registers all k*(t-1) interior
   nodes ONCE per instance, at distinct addresses, and every forger-path node is such
   an interior node with the honest value the signer stored there.  NOT an EasyCrypt
   `axiom` -- a lemma hypothesis, exactly like trh_interior_structural. *)
pred trh_registration =
     (forall (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW) (pk : pkFORS) (j : int),
        0 <= j < H_tree =>
        (inode_tw ps ad y j, cin_at ps ad y sf pk j) \in honest_nodes ps ad pk)
  /\ (forall (ps : pseed) (ad : adrs) (pk : pkFORS),
        uniq (unzip1 (honest_nodes ps ad pk)))
  /\ (forall (ps : pseed) (ad : adrs) (pk : pkFORS),
        size (honest_nodes ps ad pk) <= t_tcr).

(* ==========================================================================
   trh_collision_at_div  --  the CONCRETE-WITNESS interior collision (REAL PROOF,
   zero admit).  Same content as trh_collision_core but at the NAMED level
   `div_level` (so it feeds the concrete extract_trh index directly). *)
lemma trh_collision_at_div (ps : pseed) (ad : adrs) (y : out_t)
                           (sf : sigFORSTW) (pk : pkFORS) :
     trh_interior_structural =>
     froots_of ps ad y sf = croots_of ps ad pk =>
     ! leaf_div ps ad y sf pk =>
     let j = div_level ps ad y sf pk in
       0 <= j < H_tree
     /\ cin_at ps ad y sf pk j <> fin_at ps ad y sf j
     /\ trh ps (inode_tw ps ad y j) (cin_at ps ad y sf pk j)
        = trh ps (inode_tw ps ad y j) (fin_at ps ad y sf j).
proof.
  rewrite /trh_interior_structural.
  move=> [icf [icc [icinj [ictop icbot]]]] hroots hleaf.
  pose P := fun (j : int) =>    frun ps ad y sf j       <> crun ps ad y sf pk j
                             /\ frun ps ad y sf (j + 1)  = crun ps ad y sf pk (j + 1).
  have htop : frun ps ad y sf H_tree = crun ps ad y sf pk H_tree by apply ictop.
  have hbot : frun ps ad y sf 0 <> crun ps ad y sf pk 0 by apply icbot.
  have ge0H : 0 <= H_tree by smt(ge1_H_tree).
  have [j0 [hj0 [hne0 hm0]]] :=
    first_merge (fun k => frun ps ad y sf k) (fun k => crun ps ad y sf pk k) H_tree
                ge0H hbot htop.
  move: hne0 hm0 => /= hne0 hm0.
  have hhas : has P (iota_ 0 H_tree).
  + by apply/List.hasP; exists j0; rewrite mem_iota /P /=; smt().
  (* div_level = find P (iota 0 H); it lands on a genuine merge level in [0,H) *)
  have hlt : find P (iota_ 0 H_tree) < size (iota_ 0 H_tree) by rewrite -has_find.
  have hge : 0 <= find P (iota_ 0 H_tree) by apply find_ge0.
  have hsz : size (iota_ 0 H_tree) = H_tree by rewrite size_iota; smt().
  have hdl : div_level ps ad y sf pk = find P (iota_ 0 H_tree) by rewrite /div_level /P.
  have hrng : 0 <= div_level ps ad y sf pk < H_tree by smt().
  have hnth : nth witness (iota_ 0 H_tree) (find P (iota_ 0 H_tree))
            = div_level ps ad y sf pk by rewrite hdl nth_iota; smt().
  have hP : P (div_level ps ad y sf pk).
  + by have := nth_find witness P (iota_ 0 H_tree) hhas; rewrite hnth.
  move: hP; rewrite /P => -[hned hmd].
  pose d := div_level ps ad y sf pk.
  have hinj : fin_at ps ad y sf d <> cin_at ps ad y sf pk d
    by apply (icinj ps ad y sf pk d); smt().
  have hf : frun ps ad y sf (d + 1)
          = trh ps (inode_tw ps ad y d) (fin_at ps ad y sf d) by apply icf; smt().
  have hc : crun ps ad y sf pk (d + 1)
          = trh ps (inode_tw ps ad y d) (cin_at ps ad y sf pk d) by apply icc; smt().
  rewrite /=; split; first smt().
  split; first smt().
  by rewrite -hc -hf hmd.
qed.

(* ==========================================================================
   extract_trh  --  CONCRETE index-fidelity extractor (the trh F-EXTRACT port).
   ==========================================================================
   Grounded in the TRUSTED interior-exposure ops (inode_tw / cin_at / fin_at) +
   honest_nodes + div_level -- NOT a fresh free op.  Two components:
     * INDEX = `index (inode_tw ps ad y d, cin_at ps ad y sf pk d) (honest_nodes ps ad pk)`
       where d = div_level: the REGISTERED position of the honest interior node at the
       forger's first-merge level (nameable by REG-MEM, in-range by index_mem).
     * NODE (2nd trh-preimage) = `fin_at ps ad y sf d`: the FORGER's interior input at
       that level -- the DISTINCT input whose trh-collision with the honest input
       cin_at is proved by trh_collision_at_div. *)
op extract_trh (pk : pkFORS) (ps : pseed) (ad : adrs) (m' : msg) (sig' : sigFORSC)
  : int * dgst =
  let y  = mco sig'.`1 m' sig'.`2 in
  let sf = sig'.`3 in
  let d  = div_level ps ad y sf pk in
  (index (inode_tw ps ad y d, cin_at ps ad y sf pk d) (honest_nodes ps ad pk),
   fin_at ps ad y sf d).

(* ==========================================================================
   trh_extract_wins  --  the FULL WIN-PREDICATE CONTENT of the trh S-TCR-C hop,
   packaged as a PURE lemma (REAL PROOF, zero admit; no game / byequiv).
   ==========================================================================
   On an ebtrh forgery (brk_trh true), the CONCRETE `extract_trh` output (i, x') and
   the registered honest target set `honest_nodes ps ad pk` jointly satisfy EVERY
   conjunct of SM_DT_TCR_C_TRH's win predicate EXCEPT the collection-disjointness
   (which is trivial: the THFC oracle is never queried):
     * INDEX-RANGE  0 <= i < size hn        (i = index of the registered divergence node)
     * BUDGET       0 <= size hn <= t_tcr   (REG-SIZE)
     * DISTINCT-TWEAKS  uniq (unzip1 hn)     (REG-UNIQ -- the register-once dist fix)
     * SECOND-PREIMAGE  (nth .. i).`2 <> x'  (honest input vs forger input; hne)
     * COLLISION    trh ps (nth..i).`1 (nth..i).`2 = trh ps (nth..i).`1 x'  (hcoll)
   Every step is TRUSTED-op / real-qed grounded (trh_collision_at_div + trh_registration
   + index_ge0/index_mem/nth_index) -- NO game state, NO circular "R wins" assumption.
   The byequiv below reduces the game win to a citation of THIS lemma. *)

(* disj_lists against the empty collection list is trivially true (the THFC oracle
   OC is never queried in R_trh, so twsOC = []). *)
lemma disj_nil (s : adrs list) : disj_lists s [].
proof. by rewrite /disj_lists; smt(List.hasP). qed.

lemma trh_extract_wins (ps : pseed) (ad : adrs) (pk : pkFORS)
                       (m' : msg) (sig' : sigFORSC) (ts0 : (mkey * msg * cntr) list) :
     trh_interior_structural =>
     brk_structural =>
     trh_registration =>
     brk_trh pk ps ad m' sig' ts0 =>
       0 <= (extract_trh pk ps ad m' sig').`1 < size (honest_nodes ps ad pk)
     /\ 0 <= size (honest_nodes ps ad pk) <= t_tcr
     /\ uniq (unzip1 (honest_nodes ps ad pk))
     /\ (nth witness (honest_nodes ps ad pk) (extract_trh pk ps ad m' sig').`1).`2
          <> (extract_trh pk ps ad m' sig').`2
     /\ trh ps (nth witness (honest_nodes ps ad pk) (extract_trh pk ps ad m' sig').`1).`1
              (nth witness (honest_nodes ps ad pk) (extract_trh pk ps ad m' sig').`1).`2
        = trh ps (nth witness (honest_nodes ps ad pk) (extract_trh pk ps ad m' sig').`1).`1
                (extract_trh pk ps ad m' sig').`2.
proof.
  move=> tis bs treg btrh.
  rewrite /extract_trh /=.
  pose y  := mco sig'.`1 m' sig'.`2.
  pose sf := sig'.`3.
  pose d  := div_level ps ad y sf pk.
  pose HN := honest_nodes ps ad pk.
  (* froots = croots /\ ! leaf_div from the ebtrh classifier (brk_structural DEF-TRH) *)
  move: (bs); rewrite {1}/brk_structural => -[_ [_ [_ deftrh]]].
  move: btrh; rewrite (deftrh pk ps ad m' sig' ts0) -/y -/sf => -[hroots hleaf].
  (* the interior collision at the NAMED level d = div_level *)
  have HC := trh_collision_at_div ps ad y sf pk tis hroots hleaf.
  move: HC => /=; rewrite -/d => -[hrng [hne hcoll]].
  (* registration facts (coverage + distinct tweaks + budget) *)
  move: (treg); rewrite {1}/trh_registration => -[regmem [requniq reqsize]].
  have hmem : (inode_tw ps ad y d, cin_at ps ad y sf pk d) \in HN
    by rewrite /HN; apply (regmem ps ad y sf pk d); exact hrng.
  have hnth : nth witness HN (index (inode_tw ps ad y d, cin_at ps ad y sf pk d) HN)
            = (inode_tw ps ad y d, cin_at ps ad y sf pk d) by rewrite nth_index.
  rewrite hnth /=.
  smt(index_ge0 index_mem size_ge0).
qed.

(* ==========================================================================
   ###  THE LEAF-HASH OPEN-PREIMAGE WITNESS SPINE  (the OP analogue of the trco
   `trco_collision_core` / trh `trh_collision_core` chains -- REAL PROOFS, zero admit).
   ==========================================================================
   trco/trh are TCR-C hops (a SECOND preimage colliding at a registered target); the
   leaf hash f_lf is an OpenPRE hop (a preimage of an UNOPENED committed leaf image).
   The witness therefore differs in TWO structural ways from trco/trh:

     (i)  ONE level BELOW the trh interior.  trh's chains start at frun 0 = the f_lf
          OUTPUT; the OP hop lives at f_lf itself -- its INPUT (the revealed leaf value).
          In the ebop case (froots = croots /\ leaf_div) the forger's revealed leaf value
          `fleaf_in`, folded up the SAME auth path as the committed leaf image `cleaf_out`,
          reaches the SAME FORS root (validity).  Injectivity of that single-leaf fold
          (`croot_from_leaf`) then forces  f_lf(fleaf_in) = cleaf_out  -- a genuine
          PREIMAGE of the committed leaf image.  This mirrors trco_collision_core:
          validity => recompute = root_of (fverify_structural -- validity USED), then
          factor BOTH sides through the trusted fold and INVERT it.  NO distinctness is
          needed (OpenPRE is `f pp tw x = y`, not `x <> x'`).

     (ii) The `!opened` conjunct has NO trh/trco analogue.  OpenPRE additionally requires
          the forgery's leaf index to be a registered AND never-opened target.  That is a
          GAME-level freshness fact (os = the opened index set accumulated by R_op.Osign
          via opened_leaf_idxs = the k COVERED leaves of each signed digest), DERIVED from
          G_Tree's `!covered` -- NOT provable in the pure spine.  op_extract_wins below
          therefore proves the FOUR game-independent win conjuncts (index-range / budget /
          dist / preimage); the fifth (`!opened`) is supplied by the byequiv from `!covered`
          + the opened_leaf_idxs fidelity (flagged in the extract_op label).

   All leaf-exposure ops are grounded in the TRUSTED recompute/root_of Merkle walk (same
   family as froots_of/croots_of/roots_dgst) -- NEVER in the deferred extract_op/sim_sig_op
   (grounding them there would relocate the extraction freedom, the trco/trh discipline).
   ========================================================================== *)

(* Leaf-level structural-exposure ops (the OP analogue of froots_of/croots_of and
   inode_tw/fin_at/cin_at, but ONE level below the trh interior: at the f_lf leaf hash).
     leaf_tw         -- the diverging leaf's tweak (address) on the forger path.
     fleaf_in        -- the forger's REVEALED leaf value at that position (the f_lf input
                        = the OpenPRE preimage the extraction outputs).
     cleaf_out       -- the COMMITTED leaf image at that position (the f_lf output the
                        honest tree stores there; the registered OpenPRE target image).
     croot_from_leaf -- the single-leaf path fold: recompute the FORS root as a function
                        of ONE leaf image, holding the rest of the auth structure fixed. *)
op leaf_tw         : pseed -> adrs -> out_t -> sigFORSTW -> pkFORS -> adrs.
op fleaf_in        : pseed -> adrs -> out_t -> sigFORSTW -> pkFORS -> dgst.
op cleaf_out       : pseed -> adrs -> out_t -> sigFORSTW -> pkFORS -> node.
op croot_from_leaf : pseed -> adrs -> out_t -> sigFORSTW -> pkFORS -> node -> node.

(* Full leaf-target set of ONE FORS instance: (tweak, committed image) for every leaf
   of all k trees.  The registered OpenPRE targets; the byequiv pins O_OP_Default.ts to it. *)
op leaf_targets    : pseed -> adrs -> pkFORS -> (adrs * node) list.

(* ==========================================================================
   leaf_openpre_structural  --  FLAGGED STRUCTURAL-FIDELITY HYPOTHESIS
   (fverify_structural / brk_structural / trh_interior_structural family).
   ==========================================================================
   THREE conjuncts, ALL constraining what the leaf ops COMPUTE (a definition from the
   trusted recompute/root_of walk), NONE asserting a preimage / a registered index:
     (LC)   forger fidelity   -- recompute factors through f_lf of the revealed leaf value,
            folded up by croot_from_leaf (in the leaf_div case).
     (LK)   committed fidelity -- root_of factors through the committed leaf image, folded
            up by the SAME croot_from_leaf.
     (LINJ) fold injectivity  -- croot_from_leaf is injective in the leaf-image slot (the
            fixed-width Merkle path is injective in its leaf; roots_dgst_inj family).
   SATISFIABLE (non-vacuous): the INTENDED model is the real FORS Merkle tree -- recompute
   IS the fold from the leaf hash, root_of the same over the committed leaf, and a
   fixed-width path fold is injective in its leaf.  LC/LK are FACTORINGS (like brk_structural
   RC/RK), so validity's recompute = root_of descends to the leaf -- validity is genuinely
   LOAD-BEARING (op_preimage_core USES it, not idle).  Grounded in the TRUSTED
   recompute/root_of/f_lf -- NOT in extract_op/sim_sig_op.  NOT an EasyCrypt `axiom`. *)
pred leaf_openpre_structural =
     (* (LC) forger: recompute factors through f_lf of the revealed leaf value *)
     (forall (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW) (pk : pkFORS),
        leaf_div ps ad y sf pk =>
          recompute ps ad y sf
        = croot_from_leaf ps ad y sf pk
            (f_lf ps (leaf_tw ps ad y sf pk) (fleaf_in ps ad y sf pk)))
     (* (LK) committed: root_of factors through the committed leaf image *)
  /\ (forall (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW) (pk : pkFORS),
        leaf_div ps ad y sf pk =>
          root_of ps ad pk
        = croot_from_leaf ps ad y sf pk (cleaf_out ps ad y sf pk))
     (* (LINJ) the single-leaf path fold is injective in the leaf-image slot *)
  /\ (forall (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW) (pk : pkFORS) (a b : node),
        croot_from_leaf ps ad y sf pk a = croot_from_leaf ps ad y sf pk b => a = b).

(* ==========================================================================
   op_preimage_core  --  the MATHEMATICAL HEART of the leaf-hash OpenPRE hop
   (REAL PROOF, zero admit; the trco_collision_core / trh_collision_core analogue).
   ==========================================================================
   In the leaf_div (ebop) case: validity forces recompute = root_of (fverify_structural),
   and LC/LK factor BOTH sides through the SAME single-leaf fold croot_from_leaf; LINJ
   inverts it, forcing f_lf(fleaf_in) = cleaf_out -- a genuine preimage of the committed
   leaf image.  NO circularity (never assumes R_op wins, never touches extract_op /
   O_OP state); validity is load-bearing (drop it and recompute = root_of is unavailable). *)
lemma op_preimage_core (pk : pkFORS) (ps : pseed) (ad : adrs)
                       (m' : msg) (sig' : sigFORSC) :
     fverify_structural =>
     leaf_openpre_structural =>
     verifyC pk ps ad m' sig' =>
     leaf_div ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 pk =>
       f_lf ps (leaf_tw ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 pk)
                (fleaf_in ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 pk)
       = cleaf_out ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 pk.
proof.
  rewrite /fverify_structural /leaf_openpre_structural.
  move=> fvs [lc [lk linj]] hvld hleaf.
  (* validity => recompute = root_of  (fverify_structural -- validity USED) *)
  have fv : recompute ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 = root_of ps ad pk.
  + move: hvld; case: sig' hleaf => mk c sf /= hleaf hvld.
    by move: hvld; rewrite /verifyC /= fvs; smt().
  have hc := lc ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 pk hleaf.
  have hk := lk ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 pk hleaf.
  apply (linj ps ad (mco sig'.`1 m' sig'.`2) sig'.`3 pk).
  by rewrite -hc -hk; exact fv.
qed.

(* ==========================================================================
   op_registration  --  FLAGGED STRUCTURAL-FIDELITY HYPOTHESIS (trh_registration
   family).  The leaf-target REGISTRATION coverage.
   ==========================================================================
   THREE conjuncts, all about the HONEST leaf registration (grounded in the trusted
   leaf_targets / leaf_tw / cleaf_out -- NOT extract_op, NOT a preimage):
     (OREG-MEM)  the diverging leaf (tweak, committed image) is a registered leaf target.
     (OREG-UNIQ) the registered leaf tweaks are DISTINCT -> the game's `dist` holds.
     (OREG-SIZE) the registered leaf-target count is within the OpenPRE budget t_op.
   SATISFIABLE (non-vacuous): the real scheme registers all d*k*t leaf targets ONCE per
   instance, at distinct addresses, and every forger-path leaf is such a target carrying
   the committed image the signer stored there.  NOT an EasyCrypt `axiom`. *)
pred op_registration =
     (forall (ps : pseed) (ad : adrs) (y : out_t) (sf : sigFORSTW) (pk : pkFORS),
        (leaf_tw ps ad y sf pk, cleaf_out ps ad y sf pk) \in leaf_targets ps ad pk)
  /\ (forall (ps : pseed) (ad : adrs) (pk : pkFORS),
        uniq (unzip1 (leaf_targets ps ad pk)))
  /\ (forall (ps : pseed) (ad : adrs) (pk : pkFORS),
        size (leaf_targets ps ad pk) <= t_op).

(* ==========================================================================
   extract_op  --  CONCRETE index-fidelity extractor (the OP F-EXTRACT port).
   ==========================================================================
   Grounded in the TRUSTED leaf-exposure ops (leaf_tw / cleaf_out / fleaf_in) +
   leaf_targets -- NOT a fresh free op.  Two components (the extract_trh analogue):
     * INDEX = `index (leaf_tw .., cleaf_out ..) (leaf_targets ps ad pk)`: the REGISTERED
       position of the honest leaf target at the forger's leaf-divergence (nameable by
       OREG-MEM, in-range by index_mem).
     * PREIMAGE = `fleaf_in ps ad y sf pk`: the FORGER's revealed leaf value -- the
       OpenPRE preimage whose f_lf-image is the committed target (proved by op_preimage_core). *)
op extract_op (pk : pkFORS) (ps : pseed) (ad : adrs) (m' : msg) (sig' : sigFORSC)
  : int * dgst =
  let y  = mco sig'.`1 m' sig'.`2 in
  let sf = sig'.`3 in
  (index (leaf_tw ps ad y sf pk, cleaf_out ps ad y sf pk) (leaf_targets ps ad pk),
   fleaf_in ps ad y sf pk).

(* ==========================================================================
   op_extract_wins  --  the game-independent win-predicate content of the leaf-hash
   OpenPRE hop (REAL PROOF, zero admit; the trh_extract_wins analogue).
   ==========================================================================
   On an ebop forgery (brk_op true) the CONCRETE `extract_op` output (i, x) and the
   registered leaf-target set `leaf_targets ps ad pk` jointly satisfy the FOUR
   game-independent conjuncts of SM_DT_OpenPRE's win predicate:
     * INDEX-RANGE  0 <= i < size lt        (i = index of the registered divergence leaf)
     * BUDGET       0 <= size lt <= t_op    (OREG-SIZE)
     * DISTINCT-TWEAKS  uniq (unzip1 lt)    (OREG-UNIQ)
     * PREIMAGE     f_lf ps (nth..i).`1 x = (nth..i).`2   (op_preimage_core)
   The fifth conjunct `!opened` is the OpenPRE-specific freshness fact with no trh/trco
   analogue -- supplied by the byequiv from G_Tree's `!covered` (see the spine header + the
   extract_op label), NOT part of this pure lemma.  Every step is TRUSTED-op / real-qed
   grounded (op_preimage_core + op_registration + index_ge0/index_mem/nth_index) -- NO game
   state, NO circular "R_op wins" assumption. *)
lemma op_extract_wins (ps : pseed) (ad : adrs) (pk : pkFORS)
                      (m' : msg) (sig' : sigFORSC) (ts0 : (mkey * msg * cntr) list) :
     fverify_structural =>
     brk_structural =>
     leaf_openpre_structural =>
     op_registration =>
     verifyC pk ps ad m' sig' =>
     brk_op pk ps ad m' sig' ts0 =>
       0 <= (extract_op pk ps ad m' sig').`1 < size (leaf_targets ps ad pk)
     /\ 0 <= size (leaf_targets ps ad pk) <= t_op
     /\ uniq (unzip1 (leaf_targets ps ad pk))
     /\ f_lf ps (nth witness (leaf_targets ps ad pk) (extract_op pk ps ad m' sig').`1).`1
              (extract_op pk ps ad m' sig').`2
        = (nth witness (leaf_targets ps ad pk) (extract_op pk ps ad m' sig').`1).`2.
proof.
  move=> fvs bs los oreg hvld bop.
  rewrite /extract_op /=.
  pose y  := mco sig'.`1 m' sig'.`2.
  pose sf := sig'.`3.
  pose LT := leaf_targets ps ad pk.
  (* ebop => froots = croots /\ leaf_div  (brk_structural DEF-OP) *)
  move: (bs); rewrite {1}/brk_structural => -[_ [_ [defop _]]].
  move: bop; rewrite (defop pk ps ad m' sig' ts0) -/y -/sf => -[hroots hleaf].
  (* the leaf preimage at the diverging leaf (op_preimage_core) *)
  have HP := op_preimage_core pk ps ad m' sig' fvs los hvld _.
  + by rewrite -/y -/sf.
  move: HP; rewrite -/y -/sf => HP.
  (* registration facts (coverage + distinct tweaks + budget) *)
  move: (oreg); rewrite {1}/op_registration => -[regmem [requniq reqsize]].
  have hmem : (leaf_tw ps ad y sf pk, cleaf_out ps ad y sf pk) \in LT
    by rewrite /LT; apply (regmem ps ad y sf pk).
  have hnth : nth witness LT
                (index (leaf_tw ps ad y sf pk, cleaf_out ps ad y sf pk) LT)
            = (leaf_tw ps ad y sf pk, cleaf_out ps ad y sf pk) by rewrite nth_index.
  rewrite hnth /=.
  smt(index_ge0 index_mem size_ge0).
qed.

(* ==========================================================================
   sim_sig_op_fidelity  --  SANCTIONED simulator STRUCTURAL-fidelity hypothesis (the
   task's ALLOWED list; NOT the crux -- see the extract_op REFRAME note below).
   ==========================================================================
   R_op is KEY-FREE (unlike the key-KNOWING R_trh/R_trco): its Osign cannot call
   `fsign sk` -- it has no sk -- so it opens the k covered leaves through O and produces
   the tree signature via the ABSTRACT simulator `sim_sig_op ps ad ys y`.  This hypothesis
   PINS what sim_sig_op COMPUTES: given the leaf images `ys` of the honest key sk (i.e.
   pk = pk_of_leaves ps ad ys = the keygen pk), the simulated transcript is BYTE-IDENTICAL
   to the honest `fsign sk ps ad y`.  Constrains a COMPUTATION (grounded in the trusted
   leaf-hash/opening structure: the auth paths are folds of the public ys, the opened
   preimages are O's leaves), NOT an OUTCOME of winning.  SATISFIABLE: a real OpenPRE
   reduction reconstructs the auth paths from the public leaf hashes and reveals the opened
   preimages -- byte-identical to the honest signer.  NOT an EasyCrypt `axiom`. *)
pred sim_sig_op_fidelity =
  forall (sk : skFORS) (ps : pseed) (ad : adrs) (ys : node list) (y : out_t),
    pk_of_leaves ps ad ys = (fkeygen ps ad).`1 =>
    (fkeygen ps ad).`2 = sk =>
      sim_sig_op ps ad ys y = fsign sk ps ad y.

(* ==========================================================================
   ###  extract_op  --  THE REFRAME + the NARROWED, honest residual (assessed below,
   confirmed against the byequiv wall).
   ==========================================================================
   THE REFRAME (report this prominently).  The task called `sim_sig_op` fidelity the crux.
   It is NOT.  `sim_sig_op = fsign` is the task's SANCTIONED hypothesis (sim_sig_op_fidelity
   above, ALLOWED list) and it closes the SIGNING coupling cleanly.  The genuine wall is one
   level up -- the KEYGEN DISTRIBUTION COUPLING:

     * side 1 (G_Tree):  pk = (fkeygen ps ad).`1   -- a DETERMINISTIC op; the only key
       randomness is `ps <$ dpseed`.
     * side 2 (OpenPRE): pk = pk_of_leaves ps ad ys where ys = O.pick's leaf images of
       freshly SAMPLED preimages xs <$ dop_in (in O_OP_Default.pick's loop).

   To feed A the SAME pk both sides the byequiv needs `pk_of_leaves ps ad ys = (fkeygen ps
   ad).`1` for the SAMPLED ys.  Any hypothesis forcing this for all sampled ys is EITHER
   FALSE (the real pk depends on its leaves -- pk_of_leaves is not constant in ys) OR
   VACUOUS (pk_of_leaves constant in ys), so it is NOT a satisfiable fidelity hypothesis --
   it would be exactly the "relocate the gap onto a free pass" the task FORBIDS.  The real
   FORS_ES OpenPRE proof couples fkeygen's INTERNAL leaf-secret sampling to the O.pick
   sampling; here `fkeygen` is an OPAQUE DETERMINISTIC op in FORS_C.ec (which this file may
   NOT edit), so that internal randomness is SEALED and cannot be re-sampled to couple with
   dop_in.  THIS is the irreducible residual of the OP hop, and it is a DISTINCT obstruction
   from the trh/trco hops (whose key-KNOWING reductions sidestep it by using fkeygen's own
   sk directly, giving the trivial `proc; if => //; auto` sign coupling).

   WHAT IS DISCHARGED as REAL qed (this file, NOT deferred; both empirically load-bearing):
     * WITNESS half   -- op_preimage_core: ebop + validity => genuine f_lf preimage
       f_lf(fleaf_in) = cleaf_out (the trco_collision_core / trh_collision_core analogue).
     * INDEX-FIDELITY -- op_extract_wins: the CONCRETE extract_op names the registered leaf
       target and satisfies the FOUR game-independent OpenPRE win conjuncts (the
       trh_extract_wins analogue), incl. the register-once `dist`.
   WHAT IS ASSUMED (a hypothesis, NOT discharged -- entangled with R-KEY below):
     * SIGNING coupling -- sim_sig_op_fidelity (sanctioned) gives sim_sig_op = fsign, but
       its antecedent `pk_of_leaves ps ad ys = (fkeygen ps ad).`1` IS R-KEY, so the
       signing coupling only fires ONCE the keygen coupling is resolved.

   WHAT REMAINS in the admit (the SOLE residual, narrowed):
     (R-KEY)  the keygen distribution coupling above (deterministic fkeygen leaf-sampling
              <-> O.pick dop_in sampling) -- unopenable without editing FORS_C.ec's opaque
              fkeygen; and
     (R-OPEN) the OpenPRE-specific `!opened` freshness conjunct: the byequiv must derive
              `extract_op index \notin O_OP_Default.os` from G_Tree's `!covered` via the
              opened_leaf_idxs = covered-leaves fidelity (Osign opens exactly opened_leaf_idxs
              per signed digest).  This is game-state bookkeeping the R-KEY coupling gates.
   Both are the multi-week FORS_ES:3909-4090 OpenPRE-hop content; NEITHER is the witness or
   the index-fidelity (those are the proven pure lemmas above).  The label below records
   this precisely -- it is a NARROWED admit, not a whole-hop admit. *)

(* ==========================================================================
   The three +C-VARIANT tree-layer reductions (concrete, admit-FREE modules).

   Sound-decomposition discipline (same in all three):
     * the simulated signing oracle records the CANONICAL grind digest
       mco mk m (gc mk m) and registers the honest tree-node targets;
     * forgery-extraction (via extract_op/trh/trco) reads the forger's FREE
       counter sig'.`2.
   ========================================================================== *)

(* --- Leaf-hash open-preimage reduction (key-FREE: leaves come from O). --- *)
module (R_op (A : Adv_EUFCMA_FORSC) : Adv_OP) (O : OP_Oracle) = {
  var ps : pseed
  var ad : adrs
  var pk : pkFORS
  var ys : node list
  var mmap : (msg, mkey) fmap

  module Osign : SOracle_CMA_FORSC = {
    proc sign(m : msg) : sigFORSC = {
      var mk : mkey; var c : cntr; var y : out_t; var sf : sigFORSTW;
      var idxs : int list; var j : int; var xj : dgst;

      if (m \notin mmap) { mk <$ dmkey; mmap.[m] <- mk; }
      mk <- oget mmap.[m];
      c  <- gc mk m;                       (* canonical grind (record side)      *)
      y  <- mco mk m c;
      idxs <- opened_leaf_idxs ps ad y;    (* open the k covered leaves          *)
      j <- 0;
      while (j < size idxs) { xj <@ O.open(nth witness idxs j); j <- j + 1; }
      sf <- sim_sig_op ps ad ys y;
      return (mk, c, sf);
    }
  }

  proc pick() : adrs list = { return all_leaf_tweaks adz; }

  proc find(pp : pseed, ys0 : node list) : int * dgst = {
    var m' : msg; var sig' : sigFORSC;
    ps <- pp; ad <- adz; ys <- ys0; mmap <- empty;
    pk <- pk_of_leaves ps ad ys;
    (m', sig') <@ A(Osign).forge((pk, ps, ad));
    return extract_op pk ps ad m' sig';     (* reads sig'.`2 = free counter c'  *)
  }
}.

(* --- Tree-hash TCR-C reduction (key-KNOWING: signs honestly, registers trh). --- *)
(* trco-style REGISTER-ONCE (closes the dist footgun the per-sign loop caused): the
   reduction knows sk/pk from fkeygen, so it registers the WHOLE honest interior-node
   target set `honest_nodes ps ad pk` ONCE in find() BEFORE forge.  O_TRH_Default.ts is
   then a FIXED list with DISTINCT tweaks (dist holds), and Osign signs A honestly
   byte-identically to O_CMA_FORSC_I.sign (NO per-sign target loop -- which would have
   DESTROYED dist with duplicate interior tweaks across signatures). *)
module (R_trh (A : Adv_EUFCMA_FORSC) : Adv_TRH) (O : TCR_Oracle, OC : THFC_Oracle) = {
  var ps : pseed
  var ad : adrs
  var sk : skFORS
  var pk : pkFORS
  var mmap : (msg, mkey) fmap

  module Osign : SOracle_CMA_FORSC = {
    proc sign(m : msg) : sigFORSC = {
      var mk : mkey; var c : cntr; var y : out_t; var sf : sigFORSTW;

      if (m \notin mmap) { mk <$ dmkey; mmap.[m] <- mk; }
      mk <- oget mmap.[m];
      c  <- gc mk m;                        (* canonical grind (record side)     *)
      y  <- mco mk m c;
      sf <- fsign sk ps ad y;               (* honest key-knowing signature      *)
      return (mk, c, sf);
    }
  }

  proc pick() : unit = { }

  proc find(pp : pseed) : int * dgst = {
    var m' : msg; var sig' : sigFORSC;
    var hn : (adrs * dgst) list; var j : int; var t0 : node;
    ps <- pp; ad <- adz;
    (pk, sk) <- fkeygen ps ad;
    mmap <- empty;
    (* register the full honest interior-node target set ONCE (distinct tweaks) *)
    hn <- honest_nodes ps ad pk;
    j  <- 0;
    while (j < size hn) {
      t0 <@ O.query((nth witness hn j).`1, (nth witness hn j).`2);
      j  <- j + 1;
    }
    (m', sig') <@ A(Osign).forge((pk, ps, ad));
    return extract_trh pk ps ad m' sig';    (* names the registered divergence node *)
  }
}.

(* --- Root-compression TCR-C reduction (key-KNOWING; registers ONE trco target).
   trco compresses the k FIXED per-tree roots into pk and is called ONCE per FORS
   instance, so the committed-root target is registered EXACTLY ONCE (in find(),
   before forge -- the reduction knows pk from keygen), giving a SINGLETON
   O_TRCO_Default.ts (hence `dist = uniq [ad] = true`, which per-sign registration
   would have DESTROYED with N duplicate `ad` tweaks).  Osign then signs A honestly,
   byte-identical to O_CMA_FORSC_I.sign (no per-sign target loop). --- *)
module (R_trco (A : Adv_EUFCMA_FORSC) : Adv_TRCO) (O : TCR_Oracle, OC : THFC_Oracle) = {
  var ps : pseed
  var ad : adrs
  var sk : skFORS
  var pk : pkFORS
  var mmap : (msg, mkey) fmap

  module Osign : SOracle_CMA_FORSC = {
    proc sign(m : msg) : sigFORSC = {
      var mk : mkey; var c : cntr; var y : out_t; var sf : sigFORSTW;

      if (m \notin mmap) { mk <$ dmkey; mmap.[m] <- mk; }
      mk <- oget mmap.[m];
      c  <- gc mk m;
      y  <- mco mk m c;
      sf <- fsign sk ps ad y;               (* honest key-knowing signature      *)
      return (mk, c, sf);
    }
  }

  proc pick() : unit = { }

  proc find(pp : pseed) : int * dgst = {
    var m' : msg; var sig' : sigFORSC; var t0 : node;
    ps <- pp; ad <- adz;
    (pk, sk) <- fkeygen ps ad;
    mmap <- empty;
    (* register the committed-root target ONCE: (ad, encoding of the committed
       per-tree roots).  O returns trco ps ad (roots_dgst (croots_of ps ad pk))
       = root_of ps ad pk; the forger's divergent root-list is the 2nd preimage. *)
    t0 <@ O.query(ad, roots_dgst (croots_of ps ad pk));
    (m', sig') <@ A(Osign).forge((pk, ps, ad));
    return extract_trco pk ps ad m' sig';
  }
}.

(* ==========================================================================
   Instrumented tree-break game.  Byte-identical to FORS_C.ec's EUF_CMA_FORSC_I
   (same FC.O_CMA_FORSC_I signing, same `covered`), plus two GHOST break
   classifiers ebop / ebtrh.  The ghosts never feed `res`, so it is
   res/!covered-preserving (INSTR below).  The trco break is the RESIDUAL
   (res /\ !covered /\ !ebop /\ !ebtrh) -- no third ghost needed.
   ========================================================================== *)
module G_Tree (A : Adv_EUFCMA_FORSC) = {
  var covered : bool
  var ebop : bool
  var ebtrh : bool

  proc main() : bool = {
    var ad : adrs; var ps : pseed; var pk : pkFORS; var sk : skFORS;
    var m' : msg; var sig' : sigFORSC; var is_valid, is_fresh : bool;

    ad <- adz;
    ps <$ dpseed;
    (pk, sk) <- fkeygen ps ad;

    O_CMA_FORSC_I.init(sk, ps, ad);
    (m', sig') <@ A(O_CMA_FORSC_I).forge((pk, ps, ad));

    is_valid <- verifyC pk ps ad m' sig';
    is_fresh <@ O_CMA_FORSC_I.fresh(m');

    covered <-
      all (fun x => x \in flatten (map (fun (tmc : mkey * msg * cntr) => hC tmc.`1 tmc.`2 tmc.`3)
                                       O_CMA_FORSC_I.ts))
          (hC sig'.`1 m' sig'.`2);
    ebop  <- brk_op  pk ps ad m' sig' O_CMA_FORSC_I.ts;
    ebtrh <- brk_trh pk ps ad m' sig' O_CMA_FORSC_I.ts;

    return is_valid /\ is_fresh;
  }
}.

(* ==========================================================================
   INSTR  --  instrumentation equivalence (REAL proof, zero admit).
   G_Tree is byte-identical to FORS_C.ec's EUF_CMA_FORSC_I except for the two
   GHOST classifiers ebop/ebtrh (which never feed res).  Hence it induces the
   SAME (res /\ !covered) probability.  This is the analogue of FORS_C.ec's
   `eufcma_forsc_I_eq`.
   ========================================================================== *)
lemma instr_eq
  (A <: Adv_EUFCMA_FORSC{-O_CMA_FORSC_I, -EUF_CMA_FORSC_I, -G_Tree}) &m :
    Pr[EUF_CMA_FORSC_I(A).main() @ &m : res /\ !EUF_CMA_FORSC_I.covered]
  = Pr[G_Tree(A).main() @ &m : res /\ !G_Tree.covered].
proof.
  byequiv => //.
  proc.
  inline{1} O_CMA_FORSC_I.init O_CMA_FORSC_I.fresh.
  inline{2} O_CMA_FORSC_I.init O_CMA_FORSC_I.fresh.
  wp.
  call (: ={glob O_CMA_FORSC_I}).
  + proc; if => //; auto.
  wp; rnd; wp; skip => />.
qed.

(* ==========================================================================
   The three per-hop EXTRACTION bounds  (F-EXTRACT-OP / TRH / TRCO -- LABELLED
   ADMITS).  Each is the +C-variant re-derivation of one FORS_ES tree hop
   (ES:3910-6590 pRHL, re-run over the FREE-counter digest mco mk' m' c').  The
   reduction is a TOTAL simulation (concrete admit-free module above); the sub-
   game WIN predicate is IMPLIED BY the break sub-event (direction sound, no
   flip).  Deferred exactly like the WOTS bridge's BRIDGE-ADMIT-1 -- NOT smuggled
   into the modules.  Premise `fverify_structural` is genuinely USED (the
   extraction reads the structural recompute to locate the collision/preimage) --
   not an idle hypothesis.
   ========================================================================== *)

(* F-EXTRACT-OP: leaf-hash open-preimage.  break `ebop` -> R_op wins SM_DT_OpenPRE. *)
lemma extract_op
  (A <: Adv_EUFCMA_FORSC{-O_CMA_FORSC_I, -EUF_CMA_FORSC_I, -G_Tree, -R_op, -O_OP_Default}) &m :
    fverify_structural =>
    enum_nondegen =>
    brk_structural =>
    leaf_openpre_structural =>
    op_registration =>
    sim_sig_op_fidelity =>
    Pr[G_Tree(A).main() @ &m : (res /\ !G_Tree.covered) /\ G_Tree.ebop]
  <= Pr[SM_DT_OpenPRE(R_op(A), O_OP_Default).main() @ &m : res].
proof.
  (* ========================================================================
     F-EXTRACT-OP (NARROWED, evidence-grounded -- see the REFRAME block above R_op).
     ========================================================================
     DISCHARGED as REAL qed (NOT deferred; both empirically load-bearing -- dropping
     `verifyC` fails op_preimage_core with `cannot close goals`, dropping `brk_op` fails
     op_extract_wins with `unknown variable bop`):
       * WITNESS       -- op_preimage_core: ebop + validity => genuine f_lf preimage
                          f_lf(fleaf_in) = cleaf_out  (trco/trh_collision_core analogue).
       * INDEX-FIDELITY -- op_extract_wins: the CONCRETE extract_op names the registered
                          leaf target + satisfies the FOUR game-independent OpenPRE win
                          conjuncts (index-range / budget / dist / preimage)
                          (trh_extract_wins analogue).

     ASSUMED, NOT discharged (fires only ONCE R-KEY holds -- entangled with the residual):
       * SIGNING coupling -- sim_sig_op_fidelity (task's SANCTIONED hypothesis):
                          sim_sig_op = fsign, but ONLY under the antecedent
                          `pk_of_leaves ps ad ys = (fkeygen ps ad).`1` -- which is exactly
                          R-KEY.  So the signing coupling is CONTINGENT on the residual,
                          not independently closed; it is a hypothesis, not a proof.

     SOLE RESIDUAL (the admit; empirically CONFIRMED against the byequiv, NOT predicted):
       (R-KEY)  the keygen DISTRIBUTION coupling.  The byequiv setup (proc; inline both
                sides; the one-sided O.pick while{2}; wp/rnd coupling ps{1}=pp{2})
                TYPECHECKS all the way to the A.forge `call` precondition -- which then
                requires the SAME forge argument both sides, i.e.
                  pk{1} = (fkeygen ps adz).`1   =   pk_of_leaves ps adz ys{2}
                for the SAMPLED ys{2} (O.pick's xs <$ dop_in leaf images).  This is
                UNPROVABLE: pk_of_leaves depends on its leaves (so it cannot equal the
                deterministic fkeygen pk for random ys unless it is constant in ys, which
                is vacuous/false).  The real FORS_ES OpenPRE proof couples fkeygen's
                INTERNAL leaf-secret sampling to O.pick; here `fkeygen` is an OPAQUE
                DETERMINISTIC op in FORS_C.ec (which this file may NOT edit), so that
                randomness is SEALED and cannot be re-sampled to couple with dop_in.
       (R-OPEN) the OpenPRE-specific `!opened` freshness conjunct (extract_op index \notin
                O_OP_Default.os), which the byequiv derives from G_Tree's `!covered` via
                the opened_leaf_idxs = covered-leaves fidelity -- game-state bookkeeping
                the R-KEY coupling gates.
     NEITHER residual is the witness or the index-fidelity (those are the proven pure
     lemmas above); this is a NARROWED admit, not a whole-hop admit.  It is a DISTINCT
     obstruction from trh/trco (whose key-KNOWING reductions sidestep R-KEY entirely). *)
  move=> struct nd bs los oreg simfid.
  admit. (* F-EXTRACT-OP (NARROWED): sole residual R-KEY = keygen distribution coupling
            (deterministic sealed fkeygen <-> O.pick dop_in sampling) + R-OPEN !opened
            bookkeeping.  WITNESS=op_preimage_core, INDEX=op_extract_wins (both qed),
            SIGNING=sim_sig_op_fidelity (sanctioned); see the REFRAME block above R_op. *)
qed.

(* F-EXTRACT-TRH: tree-hash collision (guarded by !ebop).  break `ebtrh` ->
   R_trh wins SM_DT_TCR_C_TRH. *)
lemma extract_trh
  (A <: Adv_EUFCMA_FORSC{-O_CMA_FORSC_I, -EUF_CMA_FORSC_I, -G_Tree, -R_trh,
                         -O_TRH_Default, -O_TRH_THFC}) &m :
    fverify_structural =>
    enum_nondegen =>
    brk_structural =>
    trh_interior_structural =>
    trh_registration =>
    Pr[G_Tree(A).main() @ &m : ((res /\ !G_Tree.covered) /\ !G_Tree.ebop) /\ G_Tree.ebtrh]
  <= Pr[SM_DT_TCR_C_TRH(R_trh(A), O_TRH_Default, O_TRH_THFC).main() @ &m : res].
proof.
  move=> struct nd bs tis treg.
  (* SIMULATION INVARIANT (REAL, byequiv): R_trh signs A HONESTLY (Osign byte-identical
     to O_CMA_FORSC_I.sign -- NO per-sign target loop now), registering the WHOLE honest
     interior-node target set ONCE in find() before forge.  The `call` invariant PINS
     O_TRH_Default.ts{2} to `honest_nodes ps ad pk` (Osign never touches ts, so it holds
     throughout A.forge).  The WITNESS half is the real qed lemma trh_collision_at_div
     (ebtrh => distinct-input trh collision at the NAMED level div_level), and
     INDEX-FIDELITY is DERIVED from trh_registration: the collision node is a registered
     honest target, so `index (..) (honest_nodes ..)` (returned by extract_trh) NAMES it
     -- discharged in-proof, not assumed. *)
  byequiv (_ : ={glob A} ==>
     (((res{1} /\ !G_Tree.covered{1}) /\ !G_Tree.ebop{1}) /\ G_Tree.ebtrh{1})
       => res{2}) => //.
  proc.
  inline{2} R_trh(A, O_TRH_Default, O_TRH_THFC).find.
  inline{2} R_trh(A, O_TRH_Default, O_TRH_THFC).pick.
  inline{2} O_TRH_Default.init O_TRH_Default.query O_TRH_Default.get O_TRH_Default.nr_targets
            O_TRH_Default.dist_tweaks O_TRH_Default.get_tweaks.
  inline{2} O_TRH_THFC.init O_TRH_THFC.get_tweaks.
  inline{1} O_CMA_FORSC_I.init O_CMA_FORSC_I.fresh.
  wp.
  call (:   O_CMA_FORSC_I.mmap{1} = R_trh.mmap{2}
         /\ O_CMA_FORSC_I.sk{1}   = R_trh.sk{2}
         /\ O_CMA_FORSC_I.ps{1}   = R_trh.ps{2}
         /\ O_CMA_FORSC_I.ad{1}   = R_trh.ad{2}
         /\ O_TRH_Default.ts{2}
            = honest_nodes R_trh.ps{2} R_trh.ad{2} R_trh.pk{2}).
  + proc; if => //; auto.
  (* one-sided register-once loop (side 2): ts{2} accumulates to honest_nodes *)
  while{2} (   0 <= j{2} <= size hn{2}
            /\ hn{2} = honest_nodes R_trh.ps{2} R_trh.ad{2} R_trh.pk{2}
            /\ O_TRH_Default.ts{2} = take j{2} hn{2})
           (size hn{2} - j{2}).
  + move=> &m0 z; wp; skip => &hr />; smt(take_nth cats1 size_ge0).
  wp; rnd; wp; skip => &1 &2 hpre hb1 hb2.
  (* clear the sampling-support conjuncts (hb1 \in dpseed = hb2 ; hb1 = hb1) *)
  rewrite hb2 /=.
  pose pkR := (fkeygen hb1 adz).`1.
  (* register-once loop BASE: ts = take 0 hn = [] *)
  split; first by rewrite take0.
  (* register-once loop CONTINUATION: for every exit state ts_R (= honest_nodes) ... *)
  move=> tsR jR; split; first by smt().
  move=> hng [hjr htk].
  have htsR : tsR = honest_nodes hb1 adz pkR.
  + rewrite htk.
    have -> : jR = size (honest_nodes hb1 adz pkR) by smt().
    by rewrite take_size.
  (* the call precondition (invariant equalities incl. ts_R = honest_nodes) *)
  split; first by rewrite htsR /pkR /=.
  (* the coupled forgery: same (m',sig') both sides; the break => the game win *)
  (* every exit-state forgery: the ebtrh break => the game win, via trh_extract_wins.
     progress blasts the forall-coupling-break nest; each win-conjunct then follows
     from the pure lemma trh_extract_wins (+ disj_nil for the trivial disjointness). *)
  progress; smt(trh_extract_wins disj_nil).
qed.

(* F-EXTRACT-TRCO: residual root-compression collision (PIGEONHOLE: a break that
   is neither a leaf-preimage nor a tree-hash collision MUST be a root collision).
   break `res/\!covered/\!ebop/\!ebtrh` -> R_trco wins SM_DT_TCR_C_TRCO. *)
lemma extract_trco
  (A <: Adv_EUFCMA_FORSC{-O_CMA_FORSC_I, -EUF_CMA_FORSC_I, -G_Tree, -R_trco,
                         -O_TRCO_Default, -O_TRCO_THFC}) &m :
    fverify_structural =>
    enum_nondegen =>
    brk_structural =>
    roots_dgst_inj =>
    Pr[G_Tree(A).main() @ &m : ((res /\ !G_Tree.covered) /\ !G_Tree.ebop) /\ !G_Tree.ebtrh]
  <= Pr[SM_DT_TCR_C_TRCO(R_trco(A), O_TRCO_Default, O_TRCO_THFC).main() @ &m : res].
proof.
  move=> struct nd bs rdi.
  (* SIMULATION INVARIANT (REAL, byequiv): R_trco signs A HONESTLY (Osign byte-
     identical to O_CMA_FORSC_I.sign -- NO per-sign target loop now), registering the
     committed-root target ONCE in find() before forge.  The `call` invariant PINS
     O_TRCO_Default.ts{2} to the SINGLETON [(ad, roots_dgst (croots_of ps ad pk))]:
     Osign never touches ts, so it holds throughout A.forge.  The WITNESS half of the
     final entailment is the real qed lemma `trco_residual_collision`
     (validity + !ebop /\ !ebtrh => distinct-input trco collision), and INDEX-FIDELITY
     is now DERIVED: ts is the singleton, so index 0 (returned by extract_trco) NAMES
     the registered collision target -- discharged in-proof, not assumed. *)
  byequiv (_ : ={glob A} ==>
     (((res{1} /\ !G_Tree.covered{1}) /\ !G_Tree.ebop{1}) /\ !G_Tree.ebtrh{1})
       => res{2}) => //.
  proc.
  inline{2} R_trco(A, O_TRCO_Default, O_TRCO_THFC).find.
  inline{2} R_trco(A, O_TRCO_Default, O_TRCO_THFC).pick.
  inline{2} O_TRCO_Default.init O_TRCO_Default.query O_TRCO_Default.get
            O_TRCO_Default.nr_targets O_TRCO_Default.dist_tweaks O_TRCO_Default.get_tweaks.
  inline{2} O_TRCO_THFC.init O_TRCO_THFC.get_tweaks.
  inline{1} O_CMA_FORSC_I.init O_CMA_FORSC_I.fresh.
  wp.
  call (:   O_CMA_FORSC_I.mmap{1} = R_trco.mmap{2}
         /\ O_CMA_FORSC_I.sk{1}   = R_trco.sk{2}
         /\ O_CMA_FORSC_I.ps{1}   = R_trco.ps{2}
         /\ O_CMA_FORSC_I.ad{1}   = R_trco.ad{2}
         /\ O_TRCO_Default.ts{2}
            = [(R_trco.ad{2},
                roots_dgst (croots_of R_trco.ps{2} R_trco.ad{2} R_trco.pk{2}))]).
  + proc; if => //; auto.
  wp; rnd; wp; skip => />.
  move=> psR pkR adR mR sfR hval hfr hcov hbop hbtrh.
  (* WITNESS (audited): the residual (!ebop /\ !ebtrh) valid forgery yields a genuine
     DISTINCT-input trco collision -- committed-root encoding vs forger-root encoding,
     at tweak ad.  All 6 subject args are INFERRED from hval (=verifyC..) + hbop/hbtrh. *)
  have [hdist hcoll] :=
    trco_residual_collision _ _ _ _ _ _ struct bs rdi hval hbop hbtrh.
  (* INDEX-FIDELITY (derived): O_TRCO_Default.ts is the SINGLETON committed-root target,
     so extract_trco's index 0 NAMES it; the trailing smt is pure singleton bookkeeping
     (nth/size/uniq/disj on the concrete list + 1 <= t_tcr). *)
  smt(ge1_t_tcr).
qed.

(* ==========================================================================
   THE TREE-LAYER PORT BOUND  (primary deliverable).  Replaces FORS_C.ec's
   `htree` admit RHS (three abstract reals) with three CONCRETE
   `Pr[subgame_i(R_i(A))]`.  PROVED by: INSTR (real) + the two-way mu_split union
   partition (real, EXACT) + the three EXTRACT admits.  Only the three tree-hop
   pRHLs are admitted -- the assembly is a real proof.
   ========================================================================== *)
lemma fors_c_tree_port
  (A <: Adv_EUFCMA_FORSC{-O_CMA_FORSC_I, -EUF_CMA_FORSC_I, -G_Tree,
                         -R_op, -O_OP_Default, -R_trh, -O_TRH_Default, -O_TRH_THFC,
                         -R_trco, -O_TRCO_Default, -O_TRCO_THFC}) &m :
    fverify_structural =>
    enum_nondegen =>
    brk_structural =>
    roots_dgst_inj =>
    trh_interior_structural =>
    trh_registration =>
    leaf_openpre_structural =>
    op_registration =>
    sim_sig_op_fidelity =>
    Pr[EUF_CMA_FORSC_I(A).main() @ &m : res /\ !EUF_CMA_FORSC_I.covered]
  <=   Pr[SM_DT_OpenPRE(R_op(A), O_OP_Default).main() @ &m : res]
     + Pr[SM_DT_TCR_C_TRH(R_trh(A), O_TRH_Default, O_TRH_THFC).main() @ &m : res]
     + Pr[SM_DT_TCR_C_TRCO(R_trco(A), O_TRCO_Default, O_TRCO_THFC).main() @ &m : res].
proof.
  move=> struct nd bs rdi tis treg los oreg simfid.
  rewrite (instr_eq A &m).
  (* EXACT union partition of the break event: two mu_splits (left-bracketed,
     matching the EXTRACT event forms) + ler_add.  No monotonicity, no slack.
     brk_structural is threaded to each EXTRACT bound (it PINS the ebop/ebtrh
     ghosts to the genuine structural partition -- brk_genuine_partition);
     roots_dgst_inj + trh_interior_structural + trh_registration are threaded to the
     trco / trh bounds (distinctness + interior collision + index-fidelity);
     leaf_openpre_structural + op_registration + sim_sig_op_fidelity to the op bound. *)
  rewrite Pr[mu_split G_Tree.ebop] -RField.addrA.
  apply RealOrder.ler_add; first by apply (extract_op A &m struct nd bs los oreg simfid).
  rewrite Pr[mu_split G_Tree.ebtrh].
  by apply RealOrder.ler_add;
     [apply (extract_trh A &m struct nd bs tis treg)
     |apply (extract_trco A &m struct nd bs rdi)].
qed.

(* ==========================================================================
   NON-VACUITY  (the coordinator's hard mandate: no side degenerate).
   ==========================================================================
   (NV-1) The OpenPRE sub-game WIN predicate is SATISFIABLE (not identically
   false): a leaf preimage witness exists.  f_lf is NOT required injective, so a
   preimage relation is realisable -- the RHS leaf-hash term is not structurally
   zero.  REAL proof.  [For the two TCR terms we deliberately do NOT assert
   "a collision exists": that would CONTRADICT target-collision-resistance (the
   very hardness the term measures).  Their non-degeneracy is structural instead
   -- see (NV-2).] *)
lemma op_win_satisfiable :
  exists (pp : pseed) (tw : adrs) (x : dgst) (i nrts : int) (dist opened : bool) (y : node),
    0 <= i < nrts /\ 0 <= nrts <= t_op /\ !opened /\ dist /\ f_lf pp tw x = y.
proof.
  exists witness witness witness 0 1 true false (f_lf witness witness witness).
  smt(ge1_t_op).
qed.

(* (NV-2) STRUCTURAL non-degeneracy of the three RHS terms.  A never-querying
   reduction would force nrts = 0, hence Pr[subgame] = 0 and a FALSE EXTRACT
   admit (the TRCO degeneracy flagged in review).

   TRCO (now CLOSED) -- non-degeneracy is now MACHINE-CHECKED, not just flagged:
   R_trco registers the committed-root target UNCONDITIONALLY in find() (before A
   even runs), so O_TRCO_Default.ts is the SINGLETON [(ad, roots_dgst (croots_of ..))]
   and nrts = 1 > 0 on EVERY run -- independent of whether the forger signs.  The
   trco RHS is therefore structurally non-zero by construction, and the closed
   `extract_trco` no longer relies on `enum_nondegen`'s trco clause (that clause is
   now vestigial for trco; the hypothesis is retained only for uniformity with the
   still-open trh/op bounds).  ANTI-VACUITY of the closed bound is additionally
   witnessed empirically: with the break antecedent weakened to `true` the trco
   `smt` close FAILS (the validity/!ebop/!ebtrh hyps are load-bearing), and the node
   component of `extract_trco` is the real `roots_dgst (froots_of ..)`, not a constant.

   TRH / OP (still open) -- for these two the OLD discipline still applies: the
   reductions query O on EVERY honest signature (via all_leaf_tweaks / trh_targets),
   so under any faithful realisation of those enumeration ops (witness: the real FORS
   scheme enumerates >= 1 leaf / >= k-1 trh nodes per FORS instance) nrts > 0 whenever
   the forger signs.  This is the WOTS-bridge discipline (abstract emb ops made
   non-vacuous by satisfiable realisation), NOT a proof; flagged for review as the
   enumeration-op fidelity residual. *)

(* (NV-3) +C-INVARIANCE ANCHOR (the mechanical content of "follows verbatim").
   The counter enters the whole development ONLY through the message hash: the
   honest RECORDING digest is exactly the canonical grind mco_C, and NONE of
   f_lf / trh / trco takes a counter (visible in their signatures).  REAL proof
   of the recording invariant; the tree-op counter-freeness is by construction. *)
lemma record_digest_canonical (mk : mkey) (m : msg) :
  mco mk m (gc mk m) = mco_C mk m.
proof. by rewrite /mco_C. qed.
