(* ==========================================================================
   FORS_C10.ec -- a C10-FAITHFUL model of FORS+C's message hash, and its
   ITSR-style game.  This is step (c) of the bottom-up path to a real SPHINCS+C
   scheme module:

       (a) WOTS+C                    DONE, unconditional  (WOTS_C_Scheme)
       (b) hypertree over WOTS+C     DONE, gated          (XMSSMT_C_Scheme)
       (c) FORS+C, C10-faithful      THIS FILE  (model + game; the tight
                                                 security argument is OPEN)
       (d) SPHINCS+C = (b) + (c)     then `p_sphincs_c := Pr[EUF_CMA(...)]`

   ---------------------------------------------------------------------------
   WHY A SECOND FORS+C FILE (do not delete FORS_C.ec)

   `FORS_C.ec` models the PAPER's FORS+C:

       op mco : mkey -> msg -> cntr -> out_t          (* 3-arg              *)
       O.query(m) = { mk <$ dmkey;                    (* key UNIFORM         *)
                      c <- gc mk m;                   (* COUNTER ground      *)
                      ts <- rcons ts (mk, m, c); ... }

   matching the paper's implementation note ("we simply added an extra 4 bytes
   counter value ... We store the counter value that we found as part of the
   signature").

   C10 does the OPPOSITE.  It grinds the randomiser `R` and carries NO counter:

       sphincs-c10/src/params.rs:73
         SIG_FORS_TOTAL = SIG_R + SIG_FORS_SECRETS + SIG_FORS_AUTH
         (the 4-byte count in SIG_HT_LAYER is the WOTS+C counter, not FORS's)
       sphincs-c10/src/fors.rs:98 grind_r()
         for nonce in 0..10_000_000 {
           R = trunc(H(sk_seed || "R_grind" || [opt_rand] || m || nonce))
           digest = h_msg(pk_seed, pk_root, R, m)
           if read_bits_le(digest, (K-1)*A, A) == 0 { return (R, digest) } }

   So in C10 the ITSR message KEY is `R`, and it is the CONDITIONED object.
   Nothing proven over `FORS_C.ec` transfers to C10 without this re-base.
   (Adversarial review 2026-07-09; the 4th of four model/implementation
   mismatches found that day.)

   ---------------------------------------------------------------------------
   THE MODELLING DECISION, STATED PLAINLY

   C10's `R` is DETERMINISTIC in `(sk_seed, m)`: it is the first nonce whose
   digest satisfies the predicate.  We model it as `R` drawn from `dmkey`
   CONDITIONED on `predC_fors (mco R m)`, realised OPERATIONALLY as a rejection
   sampler (below) rather than with a `dcond` combinator.  Two consequences,
   both deliberate:

     * This is a random-oracle idealisation of the keyed derivation `H(sk||...)`.
       It is the same idealisation MM45 makes for `mco`'s key (its ITSR oracle
       samples `k <$ dkey`), so the +C delta is isolated to the CONDITIONING.
     * The rejection sampler is well-defined iff a good key has POSITIVE
       PROBABILITY.  That is exactly the paper's p_nu assumption, and here it
       appears WHERE IT BELONGS -- as the quantitative axiom
       `good_pos (m) : 0%r < mu dmkey (good m)`, not an existential hand-wave.
       (Until 2026-07-10 this header CLAIMED that hypothesis while the file never
       stated it -- our own claim-vs-code drift, caught by external review.  It is
       now stated, and made load-bearing by `good_exists`.)  Compare the paper:
       "we assume that it is always possible to find a good counter and the
       adversary can not depend its behavior on the existence of a fitting counter."

     * The oracle MEMOIZES the per-message key.  C10's R is deterministic in
       (sk, m) when opt_rand = None, and MM45's FORS signing oracle likewise
       carries `mmap : (msg, mkey) fmap`.  An earlier version resampled on every
       query and so modelled NEITHER.

   ---------------------------------------------------------------------------
   WHAT IS OPEN (and why the obvious route is a DEAD END -- do not retry it)

   The security content is: bound `Pr[ITSRC10]` for this game.  The obvious move
   is a black-box reduction to MM45's plain ITSR (`KeyedHashFunctions.eca:1519`,
   whose oracle samples `k <$ dkey` UNIFORMLY).  It EXISTS and is sound -- the
   reduction rejection-samples on the uniform oracle; coverage transfers because
   the reduction's target list is a superset and coverage is monotone in it, and
   freshness transfers because rejected targets carry `!predC` while the forgery
   carries `predC`, so they can never collide.

   But it is QUANTITATIVELY USELESS: it registers ~t = 2^11 targets per query, so
   at C10's 2^16 per-chain cap the reduction's game has 2^27 registered targets.
   The bound is ~28.1 bits, versus ~130.6 bits for FORS+C by the direct argument:
   ~102 BITS LOST.  Recomputed by `make -C contracts/verification verify-forsc-margin`
   in the PQSigner_OS repo (script: contracts/verification/scripts/forsc_grinding_margin.py;
   it is NOT in this checkout -- this repo is deliberately standalone).

   (Those figures were themselves corrected on 2026-07-10: the first version of the
   script used a high-probability MAX per-instance load, which is not a cryptographic
   bound.  The correct object is the binomial mixture over a FRESH candidate's own
   instance load, G ~ Bin(qs, 1/2^18), with a (q_h+1) union bound.)

   => Closing this file's OPEN OBLIGATION requires mechanising the DIRECT, tight,
   non-black-box DarkSide argument.  The published SPHINCS+C paper does not prove
   it (IEEE S&P 2023 §IV: "we can use the previous ITSR analysis"; §V: "the usage
   of FORS+C is straightforward") -- there is no reduction and no theorem to port.
   This is original work, and it is deliberately NOT admitted here.

   TWO NOTES ON WHAT THIS GAME IS NOT (external review, 2026-07-10):

     * FRESHNESS here is on the PAIR `(mk', m')`, not on the message.  So the game
       admits "sign m, then output (R', m) for a different good R'", which is NOT an
       EUF-CMA forgery.  This is NOT unsound as an upper-bound target -- message
       freshness implies pair freshness, so this is a LARGER event -- and MM45's
       generic ITSR is pair-fresh too (KeyedHashFunctions.eca:1523-1561).  But it is
       a generic ITSR-shaped game, not an EUF game.  An EUF-specific variant would
       carry `m' \notin signed_messages`.

     * There is NO q_h bound: `mco` is a public pure op and the adversary may grind
       for free.  So no concrete bit-level bound is STATABLE for this game as such.
       That is not a defect relative to the standard: MM45's plain ITSR has exactly
       the same shape (its `g` is a pure op too, and it carries no q_h).  It is
       precisely why ITSR is ASSUMED rather than bounded -- MM45's final theorem
       carries `Pr[MCO_ITSR.ITSR(...)]` as an UNREDUCED term, and no lemma anywhere
       in MM45 bounds it.  The concrete bound lives on paper, as it does for us.

   STATUS: model + game + 5 proven structural lemmas.  NO admit.  Axioms: the benign
   `dmkey_ll`, the structural `size_g`/`eqiks_g`/`neqisvs_g`/`rng_g` on the index
   extractor (mirroring MM45's), and `good_pos` (= p_nu).  The tight bound is OPEN.
   ========================================================================== *)

require import AllCore List Distr FMap.

abstract theory FORSC10.

(* ------------------------------------------------------------------------ *)
(* FORS parameters (mirror FORS_ES.ec / FORS_C.ec: k trees, a = log2 leaves). *)
(* C10: k = 13, a = 11.                                                       *)
(* ------------------------------------------------------------------------ *)
const k : { int | 1 <= k } as ge1_k.
const a : { int | 1 <= a } as ge1_a.
const t : int = 2 ^ a.   (* leaves per FORS tree; C10: 2^11 = 2048 *)

type mkey.   (* the randomiser R -- the GROUND object in C10 *)
type msg.
type out_t.

(* Message-key distribution.  MM45's ITSR oracle samples its key from `dkey`;
   ours samples from `dmkey` and then CONDITIONS on the +C predicate. *)
op dmkey : mkey distr.
axiom dmkey_ll : is_lossless dmkey.

(* C10's message hash: NO counter argument (contrast FORS_C.ec's 3-arg `mco`). *)
op mco : mkey -> msg -> out_t.

(* Index extraction: the k (instance, tree, leaf) tuples of a digest.

   STRUCTURAL AXIOMS (added 2026-07-10 after an external adversarial review).
   Without these, `g` is an arbitrary op and a LEGAL clone may set `g y = []`:
   then `cover_f = []`, coverage `forall x, x \in [] => ...` is VACUOUSLY TRUE,
   and `predC_fors` reads `nth witness [] (k-1) = witness`.  The abstract theory
   would admit degenerate models unrelated to FORS.  This is exactly the
   abstract-theory-instantiation attack that killed the FORS tree admits.
   Mirrors MM45's constraints on its own `g` (KeyedHashFunctions.eca:1454-1467). *)
op g : out_t -> (int * int * int) list.

(* one tuple per FORS tree *)
axiom size_g (y : out_t) : size (g y) = k.
(* all tuples name the SAME FORS instance *)
axiom eqiks_g (x x' : int * int * int) (y : out_t) :
  x \in g y => x' \in g y => x.`1 = x'.`1.
(* distinct tuples name DISTINCT trees *)
axiom neqisvs_g (x x' : int * int * int) (y : out_t) :
  x \in g y => x' \in g y => x <> x' => x.`2 <> x'.`2.
(* leaf indices are in range *)
axiom rng_g (y : out_t) (x : int * int * int) :
  x \in g y => 0 <= x.`3 < t.

(* The +C predicate: the LAST FORS tree opens leaf 0.
   C10: `read_bits_le(digest, (K-1)*A, A) == 0` (fors.rs:126), enforced by BOTH
   verifiers -- hypertree.rs:374 and SPHINCsC10Asm.sol:86. *)
op predC_fors (y : out_t) : bool =
  (nth witness (g y) (k - 1)).`3 = 0.

(* A key is `good` for m iff its digest satisfies the +C predicate. *)
op good (m : msg) (mk : mkey) : bool = predC_fors (mco mk m).

(* THE p_nu ASSUMPTION, stated (2026-07-10).  The header used to CLAIM this
   hypothesis while the file never stated it -- claim-vs-code drift, ours, caught
   by external review.  It is what makes the rejection sampler well-defined: a
   good key exists with POSITIVE PROBABILITY.  Compare the paper: "we assume that
   it is always possible to find a good counter". *)
axiom good_pos (m : msg) : 0%r < mu dmkey (good m).

(* Coverage tuples of a (key, message) pair -- note: NO counter. *)
op hC (mk : mkey) (m : msg) : (int * int * int) list = g (mco mk m).

(* ------------------------------------------------------------------------ *)
(* The ITSR(+C) oracle for C10: sample the message key, REJECT until it is
   good, then record the target.  This is the operational reading of "R drawn
   uniformly, conditioned on predC".                                          *)
(* ------------------------------------------------------------------------ *)
module type Oracle_ITSRC10 = {
  proc init() : unit
  proc query(m : msg) : mkey
  proc get_targets() : (mkey * msg) list
}.

module O_ITSRC10_Default : Oracle_ITSRC10 = {
  var ts   : (mkey * msg) list
  var mmap : (msg, mkey) fmap

  proc init() : unit = {
    ts   <- [];
    mmap <- empty;
  }

  (* MEMOIZED (2026-07-10).  Signing the same message twice must return the SAME
     key: C10 derives R = H(sk||"R_grind"||m||nonce), deterministic in (sk,m) when
     opt_rand = None.  MM45's FORS signing oracle likewise carries
     `mmap : (msg, mkey) fmap` (FORS_ES.ec:2043-2046).  The previous version
     resampled on every query and so modelled NEITHER. *)
  proc query(m : msg) : mkey = {
    var mk : mkey;

    if (m \notin mmap) {
      mk <$ dmkey;
      while (! good m mk) {
        mk <$ dmkey;
      }
      mmap.[m] <- mk;
      ts <- rcons ts (mk, m);
    }

    return oget mmap.[m];
  }

  proc get_targets() : (mkey * msg) list = {
    return ts;
  }
}.

module type Adv_ITSRC10 (O : Oracle_ITSRC10) = {
  proc find() : mkey * msg { O.query }
}.

(* ------------------------------------------------------------------------ *)
(* The game.  Identical to MM45's ITSR (coverage + freshness) with ONE added
   conjunct -- the +C predicate on the forgery's digest -- and the conditioned
   oracle above.  Those two changes are the whole of the FORS+C delta.        *)
(* ------------------------------------------------------------------------ *)
module ITSRC10 (A : Adv_ITSRC10, O : Oracle_ITSRC10) = {
  proc main() : bool = {
    var mk' : mkey;
    var m'  : msg;
    var ts  : (mkey * msg) list;
    var cover_f, cover_q : (int * int * int) list;

    O.init();
    (mk', m') <@ A(O).find();

    cover_f <- hC mk' m';
    ts      <@ O.get_targets();
    cover_q <- flatten (map (fun (km : mkey * msg) => hC km.`1 km.`2) ts);

    (* (i) the forgery digest is +C-valid (BOTH C10 verifiers enforce this);
       (ii) its coverage tuples are covered by the recorded targets;
       (iii) the forgery pair is fresh. *)
    return    predC_fors (mco mk' m')
           /\ (forall x, x \in cover_f => x \in cover_q)
           /\ ! (mk', m') \in ts;
  }
}.

(* The same game WITHOUT the +C conjunct: MM45's plain-ITSR win condition, over
   the SAME conditioned oracle.  Used only to state the win-set inclusion. *)
module ITSRC10_noC (A : Adv_ITSRC10, O : Oracle_ITSRC10) = {
  proc main() : bool = {
    var mk' : mkey;
    var m'  : msg;
    var ts  : (mkey * msg) list;
    var cover_f, cover_q : (int * int * int) list;

    O.init();
    (mk', m') <@ A(O).find();

    cover_f <- hC mk' m';
    ts      <@ O.get_targets();
    cover_q <- flatten (map (fun (km : mkey * msg) => hC km.`1 km.`2) ts);

    return    (forall x, x \in cover_f => x \in cover_q)
           /\ ! (mk', m') \in ts;
  }
}.

(* ==========================================================================
   STRUCTURAL LEMMAS (proven).  These are the model's sanity gates -- the
   analogue of XMSSMT_C_Scheme's `sign_size_d`: they catch a mis-wired model,
   which is the bug class that has bitten this port four times.
   ========================================================================== *)

(* GATE 1.  Every target the oracle records is +C-valid.  If this failed, the
   game would be recording targets the C10 verifiers would reject, i.e. the
   model would not be modelling C10.  (Mirrors FORS_C.ec's O_ITSRC_query_good,
   but here the +C-validity comes from the REJECTION LOOP's exit condition
   rather than from a ground counter.) *)
lemma query_targets_good :
  hoare[O_ITSRC10_Default.query :
          all (fun (km : mkey * msg) => good km.`2 km.`1) O_ITSRC10_Default.ts
          ==>
          all (fun (km : mkey * msg) => good km.`2 km.`1) O_ITSRC10_Default.ts].
proof.
proc.
if.
+ wp.
  while (all (fun (km : mkey * msg) => good km.`2 km.`1) O_ITSRC10_Default.ts).
  + by auto.
  by auto => />; smt(allP mem_rcons).
by auto.
qed.

(* GATE 0a.  `good_pos` is LOAD-BEARING, not decorative: it is exactly what makes
   the rejection sampler well-defined (a good key exists at all).  Proving the
   existential from it also shows the axiom is not vacuous. *)
lemma good_exists (m : msg) : exists (mk : mkey), good m mk.
proof. smt(witness_support good_pos). qed.

(* GATE 0b.  `size_g` is LOAD-BEARING: coverage is over a length-k list, so the
   degenerate `g y = []` model (under which coverage would be VACUOUSLY TRUE and
   `predC_fors` would read `nth witness []`) is excluded.  This is the anti-
   degeneracy gate; without it the whole game is meaningless. *)
lemma hC_size (mk : mkey) (m : msg) : size (hC mk m) = k.
proof. by rewrite /hC size_g. qed.

lemma hC_nonempty (mk : mkey) (m : msg) : hC mk m <> [].
proof. by have := hC_size mk m; smt(ge1_k size_eq0). qed.

(* GATE 2.  The +C conjunct only SHRINKS the win set: an ITSRC10 winner is a
   winner of the plain-ITSR-shaped game over the same oracle.  So FORS+C is
   never easier to break than the corresponding un-gated game -- the direction
   the paper's informal argument claims, here machine-checked at the game level.

   RENAMED 2026-07-10 (`..._SAME_ORACLE`) after external review pointed out the old
   name invited exactly the wrong reading.  What this does NOT say: the two games
   share the CONDITIONED oracle, so this is NOT a bound against MM45's
   uniform-oracle ITSR, and it is NOT the inequality `DS_g^(k-1)/t <= DS_g^k`.
   It is event inclusion, nothing more.  Bridging to MM45's ITSR is the open
   obligation, and the black-box route is the ~102-bit dead end (header). *)
lemma ITSRC10_le_noC_SAME_ORACLE (A <: Adv_ITSRC10{-O_ITSRC10_Default}) &m :
  Pr[ITSRC10(A, O_ITSRC10_Default).main() @ &m : res]
  <= Pr[ITSRC10_noC(A, O_ITSRC10_Default).main() @ &m : res].
proof.
byequiv (: ={glob A} ==> res{1} => res{2}) => //.
proc.
seq 2 2 : (={glob A, glob O_ITSRC10_Default, mk', m'}); 1: by sim.
inline *; wp; skip => /> /#.
qed.

end FORSC10.
