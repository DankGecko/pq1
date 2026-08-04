(* ==========================================================================
   STCR_C.ec  --  Special Target Collision Resistance, predicate-parameterized
                  ( "S-TCR(Prop)", paper Def C.1 ), with the grinding oracle
                  O^{+C}.  RECONCILED to the real FV-SPHINCSPLUS-EC theories.

   SECOND-INCREMENT ARTIFACT for the C10 (SPHINCS+C) EUF-CMA mechanization.

   CHANGES vs the first standalone draft (all three land the advisor's asks):

   (1) The collection oracle Th_lambda ( == Oracle_THFC ) and the whole
       tweakable-hash collection are NO LONGER mirrored locally.  This theory
       now `require import`s the REAL
         FV-SPHINCSPLUS-EC/proofs/TweakableHashFunctions.eca
       and instantiates it with in_t := msg_t * cntr and f := Th+C on the pair,
       so `Col.Oracle_THFC` / `Col.O_THFC_Default` ARE the repo's, definitionally.

   (2) The grinding oracle no longer rests on an unconditional `axiom grindP`.
       It calls `G.grind`, the TOTAL deterministic search from Grind.ec whose
       correctness (`grind_correct`) and losslessness (`GrindSearch_search_ll`)
       are PROVED there.  Gap #1 (App-D grinding termination) is discharged, not
       assumed.  `query_targets_predC` below re-exports the discharged fact.

   (3) The ONE irreducible +C novelty is kept and justified: the challenge
       oracle RETURNS (digest, counter) (paper's O_Prop returns {Th(P,T,M||i),i}),
       whereas the repo's `Oracle_SMDTTCR.query` returns only the digest.  So the
       +C challenge oracle is genuinely bespoke; it is built on TOP of the real
       collection, reusing `Col.disj_lists` and `Col.Oracle_THFC`.

   SOURCE  : Hulsing et al., "SPHINCS+C", IACR ePrint 2022/778 / PQCrypto'22,
             Def C.1 (S-TCR(Prop)) and the O_Prop grinding oracle (Sec 5.1).
   ========================================================================== *)

require import AllCore List Distr.
require (*--*) TweakableHashFunctions.
require Grind.

abstract theory STCRC.
  (* -- +C parameters (mirror the SPHINCS+ instantiation of Th+C) -- *)
  type pp_t.            (* public parameter  (SPHINCS+: pseed)             *)
  type tw_t.            (* tweak             (SPHINCS+: adrs)              *)
  type msg_t.           (* message part      (WOTS+C: n-bit root, msgWOTS) *)
  type cntr.            (* counter/grind value (WOTS+C: r=32-bit word)     *)
  type out_t.           (* hash output       (SPHINCS+: dgstblock)         *)

  (* Th+C : P x T x {0,1}^n x {0,1}^r -> {0,1}^n  (paper Thm 5.2 table). *)
  op ThC : pp_t -> tw_t -> msg_t -> cntr -> out_t.

  (* The +C predicate `Prop` (WOTS+C: constant-sum + leading-zeros). *)
  op predC : out_t -> bool.

  (* Distribution on public parameters. *)
  op dpp : pp_t distr.
  axiom dpp_ll : is_lossless dpp.

  (* Number of targets p (paper Def C.1: p <= |T|). *)
  const p_stcr : { int | 0 <= p_stcr } as ge0_pstcr.

  (* ----------------------------------------------------------------------
     (2) Grinding oracle O^{+C}: the counter search is the PROVED total op
     `G.grind` from Grind.ec — no `axiom grindP`.  Cloning Grind carries in the
     finiteness of `cntr` (`G.CntrFT.enum_spec`, a modelling fact: the real
     counter is a 32-bit word) and re-exports `grind_correct` / the operational
     losslessness `GrindSearch_search_ll`.
     ---------------------------------------------------------------------- *)
  clone import Grind.Grind as G with
    type pp_t  <- pp_t,
    type tw_t  <- tw_t,
    type msg_t <- msg_t,
    type out_t <- out_t,
    type cntr  <- cntr,
    op   f     <- ThC,
    op   prop  <- predC.

  (* Every recorded target satisfies the +C predicate — the discharged
     grinding fact (was the unconditional `grindP` axiom).  Holds whenever a
     good counter exists (the paper's p_nu assumption; its failure is the
     carried term Grind.grind_fails). *)
  lemma query_targets_predC (pp : pp_t) (tw : tw_t) (m : msg_t) :
    (exists c, predC (ThC pp tw m c)) => predC (ThC pp tw m (grind pp tw m)).
  proof. exact: grind_correct. qed.

  (* ----------------------------------------------------------------------
     (1) The REAL tweakable-hash collection, instantiated for +C.
         in_t := msg_t * cntr ;  f := Th+C on the pair.
     ---------------------------------------------------------------------- *)
  clone import TweakableHashFunctions as THF with
    type pp_t  <- pp_t,
    type tw_t  <- tw_t,
    type in_t  <- msg_t * cntr,
    type out_t <- out_t,
    op   f    <- (fun pp tw (x : msg_t * cntr) => ThC pp tw x.`1 x.`2),
    op   dpp  <- dpp
  proof dpp_ll.
  realize dpp_ll by exact dpp_ll.

  clone import THF.Collection as Col with
    type diff_t   <- unit,
    op   get_diff <- (fun (_ : msg_t * cntr) => tt),
    op   fc       <- (fun (_ : unit) pp tw (x : msg_t * cntr) => ThC pp tw x.`1 x.`2)
  proof in_collection.
  realize in_collection.
  proof. by exists tt; apply fun_ext => pp; apply fun_ext => tw; apply fun_ext => x. qed.

  (* ----------------------------------------------------------------------
     (3) The bespoke +C challenge oracle.  Grinds a Prop-satisfying counter
     via the PROVED `grind`, records (T_k, M_k, j_k) (paper's set Q), and
     RETURNS { Th(P,T,M||i), i } — the counter-returning novelty.
     ---------------------------------------------------------------------- *)
  module type Oracle_STCRC = {
    proc init(pp_init : pp_t) : unit
    proc query(tw : tw_t, m : msg_t) : out_t * cntr
    proc get(i : int) : tw_t * msg_t * cntr
    proc get_tweaks() : tw_t list
    proc nr_targets() : int
    proc dist_tweaks() : bool
  }.

  module O_STCRC_Default : Oracle_STCRC = {
    var pp : pp_t
    var ts : (tw_t * msg_t * cntr) list

    proc init(pp_init : pp_t) : unit = {
      pp <- pp_init;
      ts <- [];
    }

    proc query(tw : tw_t, m : msg_t) : out_t * cntr = {
      var i : cntr;
      var y : out_t;

      i <- grind pp tw m;          (* O_Prop: counter with predC(y) = 1 *)
      y <- ThC pp tw m i;

      ts <- rcons ts (tw, m, i);   (* record (T_k, M_k, j_k) of paper's Q  *)

      return (y, i);
    }

    proc get(i : int) : tw_t * msg_t * cntr = {
      return nth witness ts i;
    }

    proc get_tweaks() : tw_t list = {
      return map (fun (tmc : tw_t * msg_t * cntr) => tmc.`1) ts;
    }

    proc nr_targets() : int = {
      return size ts;
    }

    proc dist_tweaks() : bool = {
      return uniq (map (fun (tmc : tw_t * msg_t * cntr) => tmc.`1) ts);
    }
  }.

  (* The grinding oracle records only Prop-satisfying targets — game-level
     form of the discharged fact (given good counters exist). *)
  lemma O_STCRC_query_good (pp0 : pp_t) (tw0 : tw_t) (m0 : msg_t) :
    hoare[O_STCRC_Default.query :
            O_STCRC_Default.pp = pp0 /\ tw = tw0 /\ m = m0
            /\ (exists c, predC (ThC pp0 tw0 m0 c))
            ==> predC (ThC pp0 tw0 m0 res.`2)].
  proof.
    proc; wp; skip => &hr [#] 3!-> hex /=.
    exact: (grind_correct pp0 tw0 m0 hex).
  qed.

  (* ----------------------------------------------------------------------
     The adversary against S-TCR(Prop).  As in the repo's SMDTTCRC (Adv at
     TweakableHashFunctions.eca:712) it ALSO gets the collection oracle
     OC : Col.Oracle_THFC ( == Th_lambda ) — the REAL one now.
     ---------------------------------------------------------------------- *)
  module type Adv_STCRC(O : Oracle_STCRC, OC : Col.Oracle_THFC) = {
    proc pick() : unit { O.query, OC.query }
    proc find(pp : pp_t) : int * msg_t * cntr {}
  }.

  (* ----------------------------------------------------------------------
     The S-TCR(Prop) game.  Mirrors the repo's SM_DT_TCR_C
     (TweakableHashFunctions.eca:717) but the forgery is a triple
     (i, M, counter) and success is a COLLISION on the i-th recorded target's
     tweak with fresh (M, counter):

        Th(P,T_i,M_i||j_i) = Th(P,T_i,M||counter) /\ M <> M_i /\ DIST /\ disj.

     `Col.disj_lists` is the REAL collection separation predicate.
     ---------------------------------------------------------------------- *)
  module S_TCR_C(A : Adv_STCRC, O : Oracle_STCRC, OC : Col.Oracle_THFC) = {
    module A = A(O, OC)

    proc main() : bool = {
      var pp : pp_t;
      var tw : tw_t;
      var m, m' : msg_t;      (* M_i (recorded) and M (forgery)             *)
      var j, ctr : cntr;      (* j_i (recorded) and counter (forgery)       *)
      var i : int;
      var nrts : int;
      var dist : bool;
      var twsO, twsOC : tw_t list;

      pp <$ dpp;
      OC.init(pp);
      O.init(pp);

      A.pick();
      (i, m', ctr) <@ A.find(pp);

      (tw, m, j) <@ O.get(i);

      nrts  <@ O.nr_targets();
      dist  <@ O.dist_tweaks();
      twsO  <@ O.get_tweaks();
      twsOC <@ OC.get_tweaks();

      return    0 <= i < nrts
             /\ 0 <= nrts <= p_stcr
             /\ dist
             /\ m' <> m
             /\ ThC pp tw m j = ThC pp tw m' ctr
             /\ Col.disj_lists twsO twsOC;
    }
  }.
end STCRC.
