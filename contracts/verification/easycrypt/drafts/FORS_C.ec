(* ==========================================================================
   FORS_C.ec  --  The FORS+C security leg of the SPHINCS+C (C10) EUF-CMA
                  mechanization.  Second few-time-signature primitive, sibling
                  of the WOTS+C leg (drafts/WOTS_C_*.ec).

   TEMPLATE (FORS-TW, the standard-FORS formalization we mirror):
     FV-SPHINCSPLUS-EC/proofs/FORS_ES.ec
       * top game    : EUF_CMA_MFORSTWESNPRF                 (line ~2007)
       * top theorem : EUFCMA_MFORSTWESNPRF_OPRE            (line ~3829)
         Pr[EUF_CMA_MFORSTWESNPRF] <=
             Pr[ MCO_ITSR.ITSR    ]      (* interleaved-target subset resil. *)
           + Pr[ F_OpenPRE        ]      (* SM-DT-OpenPRE of the leaf hash f  *)
           + Pr[ TRHC_TCR         ]      (* SM-DT-TCR-C of the tree hash trh  *)
           + Pr[ TRCOC_TCR        ].     (* SM-DT-TCR-C of the root compr trco*)
     The message hash is  mco : mkey -> msg -> msgFORSTW * index  and
       g : (msgFORSTW*index) -> (int*int*int) list
     extracts the k FORS leaf indices.  ITSR is over  h = g o mco.

   FORS+C DELTA (paper: SPHINCS+C, IACR ePrint 2022/778 / NIST-PQC'22 version,
   Section 4 "FORS+C").  The signer hashes a COUNTER concatenated with the
   message and enumerates counters until the digest forces the LAST FORS tree
   to open leaf 0 (its last b' output bits are zero).  The last authentication
   path is then omitted; only the counter is stored.  Paper Section 4.1.1:
   "The security analysis is the same as the security analysis of FORS ...
   the security of our scheme follows verbatim" with the improved DarkSide
   bound (last tree contributes 1/t', independent of the number of signatures).

   FAITHFUL FORS+C THEOREM (this file, `EUFCMA_FORSC`):  identical to the
   FORS-TW theorem with the single substitution
        ITSR(mco)  -->  ITSR(+C)(mco_C)
   where mco_C is the counter-composed message hash and ITSR(+C) is ITSR of
   mco_C (the interleaved-target subset resilience over the +C-constrained
   digests, whose last coordinate is fixed to 0).  The three tree-layer terms
   (OpenPRE, TRH-TCR, TRCO-TCR) are UNCHANGED: the +C change only rewrites the
   message->index map, never the Merkle-tree / root-compression layer beneath
   it.  This mirrors exactly how WOTS+C's Thm C.2/D.1 added a single S-TCR(+C)
   term to WOTS-TW and left the WOTS-TW term otherwise intact.

   CROSS-CHECK with the SPHINCS+C top-level bound (paper Theorem 5.2): the ONLY
   +C-labelled term there is  InSec_{S-TCR(+C)}(Th+C)  (the WOTS+C term, on
   Th+C : P x T x {0,1}^n x {0,1}^r -> {0,1}^n).  The FORS+C contribution is
   folded into the standard  InSec_itsr(Hmsg)  as the *tighter* DarkSide bound,
   NOT a separate additive term -- consistent with "ITSR -> ITSR(+C)" here.

   ==========================================================================
   ###  CRITICAL:  THE FORS+C GRIND-ABORT / p_nu QUESTION  (flagged for review)
   ==========================================================================
   ASSIGNED QUESTION.  WOTS+C's apparent p_nu obstacle turned out to be a
   REDUCTION ARTIFACT (dissolved by uniform embedding; the grind is total).
   Does FORS+C's R-grind carry a GENUINE grind-failure abort term p_nu, or is
   it likewise total?  Evidence-backed characterization below -- NOT a
   unilateral verdict; the parent must adjudicate.

   (A) WHERE THE GRIND-FAILURE BRANCH IS.
       Paper, FORS+C Sign (the Alg-5 analogue; the WOTS+C Sign, Algorithm 2/5,
       states it verbatim): "Sample a salt s ... until d = H(s||m) satisfies the
       ... conditions (IF NON EXISTS THEN ABORT)."  For FORS+C the condition is
       "the last b' bits of the digest are zero" (last tree opens leaf 0).  The
       failure branch is: the signer enumerates counters over the finite space
       {0,1}^r and NO counter yields a predC_fors-satisfying digest.  This is
       the same shape as WOTS+C's constant-sum grind: enumerate a finite counter
       space, stop at the first predicate-satisfying counter, else "abort".

   (B) TOTAL-BY-MODELING (the shared idiom).  In EasyCrypt the grind is the
       TOTAL op  Grind.grind pp tw m = head witness (good_ctrs pp tw m)  -- it
       returns a `witness` counter on the empty filter, so it is a genuine
       function, never a partial/diverging search.  Grind.ec PROVES:
         grind_correct : (exists c, predC(...c)) => predC(... grind ...)   and
         grind_fails / grind_fails_iff : the failure event is exactly
                 good_ctrs = []  <=>  no counter satisfies the predicate.
       So there is NO reduction abort: the reduction always has a counter to
       commit (the witness one on failure), exactly as WOTS+C does.

   (C) WHY THE PAPER CARRIES NO ADDITIVE p_nu TERM.  Paper (WOTS+C-in-SPHINCS+
       setup, reused for FORS+C) sets the counter-space size r := lambda (the
       security parameter): "This requirement allows us to assume that there
       always exists a counter that satisfies the ... conditions. See appendix
       C for more details."  With r = lambda and per-counter success prob
       p ~ 2^{-b'} (b' << lambda), Pr[grind_fails] = (1-p)^{2^r} is
       double-exponentially small and the paper DISSOLVES it (assumes existence)
       rather than carrying it.  Theorem 5.2's SPHINCS+C bound has NO p_nu term.

   (D) THE ONE HONEST FORS-SPECIFIC NUANCE (vs WOTS+C).  In WOTS+C, a "wrong"
       counter still yields a WOTS-TW-verifiable signature (WOTS-TW verifies ANY
       encoded digest), so grind-failure is a pure no-op for BOTH correctness
       and the reduction.  In FORS+C the VERIFIER checks the digest forces
       leaf 0 in the last tree (predC_fors) -- it reconstructs the omitted last
       auth path assuming leaf 0.  Hence on grind-failure the honest signer
       cannot produce a VALID signature: grind-failure is a *completeness*
       (correctness) defect, not merely a no-op.  BUT this defect is present
       IDENTICALLY in the real EUF-CMA game and in the reduction's simulated
       signing oracle, so it introduces NO distinguishing gap in the EUF-CMA
       *advantage* -- the security reduction is unaffected.  p_nu therefore does
       NOT enter the security bound; it would only appear in a separate
       CORRECTNESS/completeness statement (Pr[honest sig verifies] >= 1 - p_nu).

   (E) VERDICT (for parent review).  The FORS+C grind is TOTAL in the model
       (same `head witness (good_ctrs)` idiom as WOTS+C) and p_nu is NOT a
       genuine additive term of the FORS+C SECURITY reduction: it is dissolved
       by the r = lambda counter-space choice (paper line ~739, App. C), exactly
       as in WOTS+C.  The FORS-specific twist (verifier requires last-index = 0,
       so grind-failure breaks *completeness* rather than being a no-op) is a
       CORRECTNESS concern, not a security-advantage term.  Accordingly this
       file carries NO p_nu term in `EUFCMA_FORSC`.  Where the analysis needs
       "a good counter exists", it is an EXPLICIT HYPOTHESIS on the lemma
       (`good_counter_exists` below) with this comment -- NOT an EasyCrypt
       `axiom`, NOT a baked-in "p_nu admit as settled".  IF the parent judges
       the permissive verifier (accepts ANY predC_fors counter, not only the
       canonical grind one) demands an extra term, that is a *collision/second-
       counter* term on mco, not a grind-abort term -- see modeling note (M2).

   ==========================================================================
   MODELING NOTES (flagged for review).
   (M1) CANONICAL GRIND FOR THE SIGNER; FREE COUNTER FOR THE FORGER.  The
        honest signer uses the canonical (first predC_fors-satisfying) counter
        gc mk m = Grind.grind tt mk m (as WOTS+C folds `encode o ThC`), and the
        signature CARRIES it (it replaces the omitted last auth path).  Crucially
        the ITSR(+C) game is BESPOKE (not a vanilla in_t=msg ITSR clone): its
        oracle records the canonical target (mk, m, gc mk m) but the FORGERY
        carries a FREE counter c', with coverage evaluated at the forger's actual
        digest g(mco mk' m' c').  This mirrors STCR_C.ec exactly (O_STCRC grinds
        + returns the counter; the forgery triple carries a free counter).
   (M2) PERMISSIVE VERIFY -- DISSOLVED BY THE BESPOKE GAME (was a soundness bug
        in an earlier in_t=msg deterministic-fold draft).  The paper's verifier
        accepts ANY counter whose digest satisfies predC_fors (it recomputes the
        digest "directly in the resulting digest value", paper Sec 4.1) -- it
        never re-grinds.  A deterministic fold that evaluated coverage at the
        CANONICAL digest gc mk' m' would be UNSOUND for a forger using c' !=
        gc mk' m' (different digest, uncovered).  Carrying the free counter c'
        into the ITSR(+C) forgery (as above) makes coverage land on the forger's
        real digest, so NO extra collision term is needed and the single ITSR(+C)
        term covers the permissive verifier.  This also sidesteps the
        key-sampling-before-grind circularity a naive in_t = msg x cntr clone
        would hit (the key is a function of the message alone; the oracle samples
        it per message, then grinds).  RESOLVED; retained here as a flagged
        record of the modeling decision for parent review.
   ========================================================================== *)

require import AllCore List Distr FMap FinType.
require Grind.

abstract theory FORSC.

(* ------------------------------------------------------------------------ *)
(* FORS parameters (mirror FORS_ES.ec: k trees, a = log2 leaves).           *)
(* ------------------------------------------------------------------------ *)
const k : { int | 1 <= k } as ge1_k.   (* number of FORS trees              *)
const a : { int | 1 <= a } as ge1_a.   (* log2 of leaves per tree           *)
const t : int = 2 ^ a.                  (* leaves per tree                   *)

(* ------------------------------------------------------------------------ *)
(* Types (abstract; the tree layer is uninterpreted -- +C never touches it).*)
(* ------------------------------------------------------------------------ *)
type mkey.        (* message-compression key (FORS-TW: mkey)                *)
type msg.         (* message                                                *)
type out_t.       (* compressed digest (FORS-TW: msgFORSTW * index)         *)
type cntr.        (* grind counter (finite -- the +C counter space {0,1}^r) *)

type pseed.       (* public seed                                            *)
type adrs.        (* hash address                                           *)
type pkFORS.      (* FORS public key                                        *)
type skFORS.      (* FORS secret key                                        *)
type sigFORSTW.   (* FORS auth-path signature (tree layer)                  *)

(* Distributions. *)
op [lossless] dmkey : mkey distr.
op [lossless] dpseed : pseed distr.

(* Fixed initial address (FORS_ES: adz). *)
op adz : adrs.

(* ------------------------------------------------------------------------ *)
(* Message compression.  mco takes the message AND a counter (paper hashes  *)
(* counter||message); g extracts the k FORS leaf indices.                   *)
(* ------------------------------------------------------------------------ *)
op mco : mkey -> msg -> cntr -> out_t.
op g   : out_t -> (int * int * int) list.

(* +C predicate on a digest: the LAST FORS tree opens leaf 0 (index 0).
   (paper: "the last b' bits of the digest are all zeros" == last tree's
   selected leaf index is 0). *)
op predC_fors (y : out_t) : bool =
  (nth witness (g y) (k - 1)).`3 = 0.

(* ------------------------------------------------------------------------ *)
(* (B) TOTAL grind (from Grind.ec).  pp := unit, tw := mkey, msg := msg.     *)
(* Carries the finiteness of `cntr` and re-exports grind_correct /          *)
(* grind_fails -- no `axiom grindP`.                                         *)
(* ------------------------------------------------------------------------ *)
clone import Grind.Grind as G with
  type pp_t  <- unit,
  type tw_t  <- mkey,
  type msg_t <- msg,
  type out_t <- out_t,
  type cntr  <- cntr,
  op   f     <- (fun (_ : unit) (mk : mkey) (m : msg) (c : cntr) => mco mk m c),
  op   prop  <- predC_fors.

(* Deterministic-grind fold (M1): the signer's canonical counter for (mk,m). *)
op gc (mk : mkey) (m : msg) : cntr = G.grind tt mk m.

(* The counter-composed message hash used by ITSR(+C). *)
op mco_C (mk : mkey) (m : msg) : out_t = mco mk m (gc mk m).

(* Specialization of the PROVED grind_correct: whenever SOME counter forces
   the last tree to leaf 0, the canonical grind counter does too.  This is the
   discharged form of the paper's "a good counter exists" (p_nu) assumption --
   here a PROVED conditional, not an axiom. *)
lemma mco_C_predC (mk : mkey) (m : msg) :
  (exists c, predC_fors (mco mk m c)) => predC_fors (mco_C mk m).
proof.
  move=> ex; rewrite /mco_C /gc.
  have := G.grind_correct tt mk m _.
  + by move: ex => [c hc]; exists c.
  by [].
qed.

(* ------------------------------------------------------------------------ *)
(* ITSR(+C):  a BESPOKE interleaved-target-subset-resilience game for the +C  *)
(* message hash.  It is NOT a vanilla clone of KeyedHashFunctions.ITSR --     *)
(* mirroring STCR_C.ec's O_STCRC (which grinds and RETURNS the counter, and   *)
(* whose forgery carries a FREE counter), the FORS+C forgery must carry a     *)
(* FREE counter c' so the reduction stays SOUND against the paper's PERMISSIVE *)
(* verifier (which accepts ANY predC_fors-counter, recomputing the digest     *)
(* "directly in the resulting digest value", paper Sec 4.1).  A deterministic *)
(* fold (in_t = msg, coverage at the canonical gc-digest) would be UNSOUND for *)
(* non-canonical forgery counters c' != gc mk' m'.  See modeling note (M2).    *)
(*                                                                            *)
(* Differences from FORS_ES.ec's MCO_ITSR (which this game specialises):      *)
(*  - the oracle grinds the CANONICAL counter gc mk m for each queried msg    *)
(*    (honest signatures use it) and records (mk, m, gc mk m);                *)
(*  - the coverage map hC is over a (key, msg, counter) TRIPLE (free counter);*)
(*  - the winning condition ADDS the +C constraint predC_fors on the forgery  *)
(*    digest -- the last tree opens leaf 0.                                    *)
(* ------------------------------------------------------------------------ *)

(* Coverage tuples of a (key, message, counter): g applied to the digest. *)
op hC (mk : mkey) (m : msg) (c : cntr) : (int * int * int) list =
  g (mco mk m c).

module type Oracle_ITSRC = {
  proc init() : unit
  proc query(m : msg) : mkey
  proc get_targets() : (mkey * msg * cntr) list
}.

module O_ITSRC_Default : Oracle_ITSRC = {
  var ts : (mkey * msg * cntr) list

  proc init() : unit = {
    ts <- [];
  }

  (* Sample the per-message key, grind the canonical counter, record the
     target (mk, m, gc mk m), return the key. *)
  proc query(m : msg) : mkey = {
    var mk : mkey;
    var c  : cntr;

    mk <$ dmkey;
    c  <- gc mk m;
    ts <- rcons ts (mk, m, c);

    return mk;
  }

  proc get_targets() : (mkey * msg * cntr) list = {
    return ts;
  }
}.

module type Adv_ITSRC (O : Oracle_ITSRC) = {
  proc find() : mkey * msg * cntr { O.query }
}.

module ITSRC (A : Adv_ITSRC, O : Oracle_ITSRC) = {
  proc main() : bool = {
    var mk' : mkey;
    var m'  : msg;
    var c'  : cntr;
    var ts  : (mkey * msg * cntr) list;
    var cover_f, cover_q : (int * int * int) list;

    O.init();

    (* Adversary specifies targets by querying O, then outputs a forgery
       (mk', m', c') with a FREE counter c'. *)
    (mk', m', c') <@ A(O).find();

    cover_f <- hC mk' m' c';
    ts      <@ O.get_targets();
    cover_q <- flatten (map (fun (tmc : mkey * msg * cntr) => hC tmc.`1 tmc.`2 tmc.`3) ts);

    (* Success iff: (i) the forgery digest is +C-valid (last tree opens leaf 0);
       (ii) its coverage tuples are all covered by the recorded targets;
       (iii) the forgery triple is fresh. *)
    return    predC_fors (mco mk' m' c')
           /\ (forall x, x \in cover_f => x \in cover_q)
           /\ ! (mk', m', c') \in ts;
  }
}.

(* Game-level form of the discharged grind fact (mirrors STCR_C's
   O_STCRC_query_good): under good_counter_exists, every target the ITSR(+C)
   oracle records is +C-valid -- its canonical digest forces leaf 0 in the last
   tree.  This is the discharged form of the paper's p_nu "a good counter
   exists" (verdict (E)); it is PROVED (not assumed) via mco_C_predC. *)
lemma O_ITSRC_query_good (m0 : msg) :
  hoare[O_ITSRC_Default.query :
          m = m0 /\ (forall (mk : mkey), exists c, predC_fors (mco mk m0 c))
          ==> predC_fors (mco_C res m0)].
proof.
  proc; auto => /> *; smt(mco_C_predC).
qed.

(* ------------------------------------------------------------------------ *)
(* FORS+C scheme.  Tree layer (fkeygen/fsign/fverify) is ABSTRACT -- +C does *)
(* not change it.  The message-hash / grind / last-index-0 layer is concrete.*)
(* A +C signature carries (mk, counter, tree-sig): the counter replaces the  *)
(* omitted last authentication path.                                          *)
(* ------------------------------------------------------------------------ *)
type sigFORSC = mkey * cntr * sigFORSTW.

op fkeygen : pseed -> adrs -> pkFORS * skFORS.
(* fsign: given the compressed digest (which selects the leaves), produce the
   auth-path signature over the first k-1 trees (the last is omitted). *)
op fsign  : skFORS -> pseed -> adrs -> out_t -> sigFORSTW.
(* fverify: recompute roots from (digest, auth paths) and match pk -- the last
   tree is reconstructed from leaf 0.  ABSTRACT tree-layer check. *)
op fverify : pkFORS -> pseed -> adrs -> out_t -> sigFORSTW -> bool.

(* Full +C verify: recompute the digest from the carried counter, require it
   forces leaf 0 in the last tree (predC_fors), then run the tree-layer check. *)
op verifyC (pk : pkFORS) (ps : pseed) (ad : adrs)
           (m : msg) (s : sigFORSC) : bool =
  let (mk, c, sf) = s in
  let y = mco mk m c in
    predC_fors y /\ fverify pk ps ad y sf.

(* ------------------------------------------------------------------------ *)
(* EUF-CMA game for FORS+C (mirrors EUF_CMA_MFORSTWESNPRF).                   *)
(* ------------------------------------------------------------------------ *)
module type SOracle_CMA_FORSC = {
  proc sign(m : msg) : sigFORSC
}.

module type Oracle_CMA_FORSC = {
  proc init(sk_init : skFORS, ps_init : pseed, ad_init : adrs) : unit
  proc sign(m : msg) : sigFORSC
  proc fresh(m : msg) : bool
}.

module type Adv_EUFCMA_FORSC (O : SOracle_CMA_FORSC) = {
  proc forge(pk : pkFORS * pseed * adrs) : msg * sigFORSC
}.

(* Default CMA oracle: samples the per-message key, grinds the canonical
   counter, records the queried message, and produces the +C signature. *)
module O_CMA_FORSC : Oracle_CMA_FORSC = {
  var sk : skFORS
  var ps : pseed
  var ad : adrs
  var qs : msg list
  var mmap : (msg, mkey) fmap

  proc init(sk_init : skFORS, ps_init : pseed, ad_init : adrs) : unit = {
    sk <- sk_init;
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

    c  <- gc mk m;            (* canonical grind counter (M1)               *)
    y  <- mco mk m c;         (* == mco_C mk m                              *)
    sf <- fsign sk ps ad y;

    qs <- rcons qs m;
    return (mk, c, sf);
  }

  proc fresh(m : msg) : bool = {
    return ! (m \in qs);
  }
}.

module EUF_CMA_FORSC (A : Adv_EUFCMA_FORSC, O : Oracle_CMA_FORSC) = {
  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pk : pkFORS;
    var sk : skFORS;
    var m' : msg;
    var sig' : sigFORSC;
    var is_valid, is_fresh : bool;

    ad <- adz;
    ps <$ dpseed;
    (pk, sk) <- fkeygen ps ad;

    O.init(sk, ps, ad);
    (m', sig') <@ A(O).forge((pk, ps, ad));

    is_valid <- verifyC pk ps ad m' sig';
    is_fresh <@ O.fresh(m');

    return is_valid /\ is_fresh;
  }
}.

(* ------------------------------------------------------------------------ *)
(* R_ITSRC_FORSC:  the ITSR(+C) reduction (FORS+C analogue of R_ITSR_EUFCMA).*)
(* Simulates FORS+C signing by fetching per-message keys from the ITSR(+C)   *)
(* oracle; returns the forgery's (key, message) as the ITSR(+C) forgery.     *)
(* ------------------------------------------------------------------------ *)
module (R_ITSRC_FORSC (A : Adv_EUFCMA_FORSC) : Adv_ITSRC)
       (O : Oracle_ITSRC) = {
  var ps : pseed
  var ad : adrs
  var sk : skFORS
  var mmap : (msg, mkey) fmap

  module O_CMA : SOracle_CMA_FORSC = {
    proc sign(m : msg) : sigFORSC = {
      var mk : mkey;
      var c  : cntr;
      var y  : out_t;
      var sf : sigFORSTW;

      if (m \notin mmap) {
        mk <@ O.query(m);       (* ITSR(+C) oracle samples key + grinds gc   *)
        mmap.[m] <- mk;
      }
      mk <- oget mmap.[m];

      c  <- gc mk m;            (* canonical counter, matches the target      *)
      y  <- mco mk m c;
      sf <- fsign sk ps ad y;

      return (mk, c, sf);
    }
  }

  (* Returns the forgery triple (mk', m', c') with the FORGER's counter c'
     (free), so coverage is evaluated at the forger's actual digest -- sound
     against the permissive verifier (M2). *)
  proc find() : mkey * msg * cntr = {
    var pk : pkFORS;
    var m' : msg;
    var sig' : sigFORSC;

    ad <- adz;
    ps <$ dpseed;
    (pk, sk) <- fkeygen ps ad;
    mmap <- empty;

    (m', sig') <@ A(O_CMA).forge((pk, ps, ad));

    return (sig'.`1, m', sig'.`2);   (* (mk', m', c') from the forged sig    *)
  }
}.

(* ------------------------------------------------------------------------ *)
(* Abstract carriers for the THREE UNCHANGED tree-layer terms (paper: FORS+C *)
(* security "follows verbatim" for the Merkle-tree / root-compression layer).*)
(* Documented as the FORS_ES.ec advantages:                                  *)
(*   tree_openpre := Pr[ F_OpenPRE.SM_DT_OpenPRE(R_FSMDTOpenPRE_EUFCMA(A)) ]  *)
(*   tree_trh     := Pr[ TRHC_TCR.SM_DT_TCR_C   (R_TRHSMDTTCRC_EUFCMA(A))   ] *)
(*   tree_trco    := Pr[ TRCOC_TCR.SM_DT_TCR_C  (R_TRCOSMDTTCRC_EUFCMA(A))  ] *)
(* ------------------------------------------------------------------------ *)
(* NOT abstract `op`s.  They are UNIVERSALLY-QUANTIFIED lemma parameters of   *)
(* `EUFCMA_FORSC`, and the tree bound is an EXPLICIT PREMISE of that lemma.   *)
(*                                                                            *)
(* WHY (adversarial review 2026-07-09).  They used to be free abstract ops    *)
(* `op tree_openpre : { real | 0%r <= tree_openpre }` inside this ABSTRACT    *)
(* theory, with the tree bound closed by `admit`.  That admit was FALSE, not  *)
(* merely unproven: a legal clone may instantiate all three to `0%r` (the     *)
(* only realization obligation being `0%r <= 0%r`), under which the admitted  *)
(* step reads `Pr[... /\ !covered] <= 0%r` -- false in general.  Dually,      *)
(* instantiating them to `1%r` made the whole bound trivially true, so the    *)
(* theorem constrained nothing.  Mechanically demonstrated by cloning MFORSC  *)
(* with `mtree_* <- 0%r` and deriving `Pr[EUF_CMA] <= Pr[ITSR(+C)]` (EXIT 0). *)
(*                                                                            *)
(* A constant cannot bound a `forall A` probability, so "finish the tree-layer*)
(* port" would NOT have discharged that admit -- the statement had to change. *)
(* As a premise over `forall`-bound reals the theorem is TRUE and conditional,*)
(* the admit is GONE, and the obligation is visible in the statement.  The    *)
(* discharge is to instantiate the premise with the FORS_ES advantages above. *)
(* ------------------------------------------------------------------------ *)

(* ==========================================================================
   THE ITSR(+C) GAME-HOP  (primary deliverable -- the +C-specific hop, mirror
   of WOTS+C's `WOTSC_C2_hop1` / Thm D.1's `D1_hop1`, and of FORS_ES.ec's
   `valid_ITSR` summand inside `EUFCMA_MFORSTWESNPRF_OPRE` (lines 3849-3908)).

   DECOMPOSITION (identical to FORS-TW).
     * `covered` = FORS_ES's `valid_ITSR` event: EVERY coverage tuple of the
       forgery digest g(mco mk' m' c') is already covered by the recorded
       targets.  COVERAGE-ONLY -- freshness is carried separately, exactly as
       FORS_ES splits valid_ITSR into the coverage predicate (line 3341/3559)
       and threads `! ((k,x) \in kxl)` into the ITSR postcondition (line 3900).
     * instrumented game `EUF_CMA_FORSC_I` records the ITSR target list `ts`
       of triples (mk, m, gc mk m) -- ONE entry per UNIQUE queried message,
       exactly as `O_ITSRC_Default.query` records -- and the boolean `covered`.
       The `ts` list is a GHOST: it never touches `res`, so
       Pr[EUF_CMA_FORSC : res] = Pr[EUF_CMA_FORSC_I : res] (`eufcma_forsc_I_eq`).
     * the hop (`ITSRC_hop`):
         Pr[EUF_CMA_FORSC_I : res /\ covered] <= Pr[ITSR(+C)].

   HONESTY NOTE.  The hop does NOT use `good_counter_exists` / `O_ITSRC_query_good`:
   forgery validity (predC_fors) is supplied by `verifyC` / `is_valid` on the
   game side, and `ITSRC.main` checks predC_fors ONLY on the forgery digest
   (line 297), never on recorded targets.  Those two lemmas are COMPOSITION-side
   (the honest-completeness leg), so NO machinery is threaded here to manufacture
   a use.  An unused hypothesis would be dishonest -- the hop carries none.
   ========================================================================== *)

(* Instrumented CMA oracle: O_CMA_FORSC plus a GHOST target list `ts` recording
   (mk, m, gc mk m) for each UNIQUE queried message.  Signing behaviour is
   byte-identical (the ghost never enters a returned value), so it induces the
   same res distribution -- see `eufcma_forsc_I_eq`. *)
module O_CMA_FORSC_I : Oracle_CMA_FORSC = {
  var sk : skFORS
  var ps : pseed
  var ad : adrs
  var qs : msg list
  var mmap : (msg, mkey) fmap
  var ts : (mkey * msg * cntr) list

  proc init(sk_init : skFORS, ps_init : pseed, ad_init : adrs) : unit = {
    sk <- sk_init;
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
      ts <- rcons ts (mk, m, gc mk m);
    }
    mk <- oget mmap.[m];

    c  <- gc mk m;
    y  <- mco mk m c;
    sf <- fsign sk ps ad y;

    qs <- rcons qs m;
    return (mk, c, sf);
  }

  proc fresh(m : msg) : bool = {
    return ! (m \in qs);
  }
}.

(* The instrumented EUF-CMA game: identical to EUF_CMA_FORSC but records the
   coverage boolean `covered` (FORS_ES's valid_ITSR event) after the forgery. *)
module EUF_CMA_FORSC_I (A : Adv_EUFCMA_FORSC) = {
  var covered : bool

  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pk : pkFORS;
    var sk : skFORS;
    var m' : msg;
    var sig' : sigFORSC;
    var is_valid, is_fresh : bool;

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

    return is_valid /\ is_fresh;
  }
}.

(* Instrumentation is res-preserving: the ghost `ts` and boolean `covered` never
   feed a returned value, so the instrumented game has the SAME advantage. *)
lemma eufcma_forsc_I_eq
  (A <: Adv_EUFCMA_FORSC{-O_CMA_FORSC, -O_CMA_FORSC_I, -EUF_CMA_FORSC_I}) &m :
    Pr[EUF_CMA_FORSC(A, O_CMA_FORSC).main() @ &m : res]
  = Pr[EUF_CMA_FORSC_I(A).main() @ &m : res].
proof.
  byequiv => //.
  proc.
  inline{1} O_CMA_FORSC.init O_CMA_FORSC.fresh.
  inline{2} O_CMA_FORSC_I.init O_CMA_FORSC_I.fresh.
  wp.
  call (:   ={qs, mmap}(O_CMA_FORSC, O_CMA_FORSC_I)
         /\ O_CMA_FORSC.sk{1} = O_CMA_FORSC_I.sk{2}
         /\ O_CMA_FORSC.ps{1} = O_CMA_FORSC_I.ps{2}
         /\ O_CMA_FORSC.ad{1} = O_CMA_FORSC_I.ad{2}).
  + proc.
    if => //; auto.
  wp; rnd; wp; skip => />.
qed.

(* -------------------------------------------------------------------------- *)
(* The ITSR(+C) hop: the coverage part of FORS+C EUF-CMA is caught by ITSR(+C) *)
(* through R_ITSRC_FORSC.  The reduction's per-message key comes from the      *)
(* ITSR(+C) oracle (which samples + grinds + records the canonical target),    *)
(* the honest counter matches the recorded target, and the forgery triple      *)
(* (mk', m', c') carries the forger's FREE counter (M2) -- so coverage lands   *)
(* on the forger's actual digest, sound against the permissive verifier.       *)
(* -------------------------------------------------------------------------- *)
lemma ITSRC_hop
  (A <: Adv_EUFCMA_FORSC{-R_ITSRC_FORSC, -O_CMA_FORSC_I, -O_ITSRC_Default, -EUF_CMA_FORSC_I}) &m :
    Pr[EUF_CMA_FORSC_I(A).main() @ &m : res /\ EUF_CMA_FORSC_I.covered]
  <= Pr[ITSRC(R_ITSRC_FORSC(A), O_ITSRC_Default).main() @ &m : res].
proof.
  byequiv (_ : ={glob A} ==> (res{1} /\ EUF_CMA_FORSC_I.covered{1}) => res{2}) => //.
  proc.
  inline{2} R_ITSRC_FORSC(A, O_ITSRC_Default).find.
  inline{2} O_ITSRC_Default.init O_ITSRC_Default.get_targets.
  inline{1} O_CMA_FORSC_I.init O_CMA_FORSC_I.fresh.
  swap{2} 1 2.
  (* one linear pass (WOTSC_C2_reduce shape): wp the tail, couple the forge, then
     the prefix; the final skip discharges prefix-coupling + the ITSR(+C) win. *)
  wp.
  call (:   ={mmap}(O_CMA_FORSC_I, R_ITSRC_FORSC)
         /\ O_CMA_FORSC_I.sk{1} = R_ITSRC_FORSC.sk{2}
         /\ O_CMA_FORSC_I.ps{1} = R_ITSRC_FORSC.ps{2}
         /\ O_CMA_FORSC_I.ad{1} = R_ITSRC_FORSC.ad{2}
         /\ O_CMA_FORSC_I.ts{1} = O_ITSRC_Default.ts{2}
         /\ (forall x, x \in map (fun (tmc : mkey * msg * cntr) => tmc.`2)
                                 O_CMA_FORSC_I.ts{1}
                       => x \in O_CMA_FORSC_I.qs{1})).
  + proc.
    inline{2} O_ITSRC_Default.query.
    wp.
    if => //.
    - auto; smt(map_rcons mem_rcons).
    - auto; smt(mem_rcons).
  wp; rnd; wp; skip => />.
  rewrite /verifyC /hC /=.
  smt(allP mapP mem_rcons).
qed.

(* ==========================================================================
   THE FORS+C SECURITY THEOREM (faithful to FORS-TW + the ITSR->ITSR(+C)
   substitution).  NO p_nu term (see the grind-abort analysis, verdict (E)).

   HYPOTHESES (explicit, paper-level; none is an EasyCrypt `axiom`):
   - good_counter_exists : for every (mk, m) queried, SOME counter forces the
     last tree to leaf 0.  This is the paper's r = lambda "a good counter
     always exists" condition (App. C) made explicit as a lemma hypothesis --
     the discharged form of p_nu (see verdict (E)); its failure is the
     completeness defect Grind.grind_fails, NOT a security-advantage term.

   STATUS: ZERO admit.  The ITSR(+C) hop is PROVED (`ITSRC_hop`).  The three
   +C-INVARIANT tree hops (leaf-hash OpenPRE + tree-hash TCR + root-compression
   TCR, i.e. FORS_ES's R_FSMDTOpenPRE_EUFCMA / R_TRHSMDTTCRC_EUFCMA /
   R_TRCOSMDTTCRC_EUFCMA) are carried as the EXPLICIT PREMISE `htree` over
   forall-bound reals -- an honest conditional, not a hidden admit.  See the
   ge0/`op` note above for why the previous `admit` was FALSE-as-stated.
   ========================================================================== *)
lemma EUFCMA_FORSC
  (A <: Adv_EUFCMA_FORSC{-R_ITSRC_FORSC, -O_CMA_FORSC, -O_CMA_FORSC_I,
                         -O_ITSRC_Default, -EUF_CMA_FORSC_I})
  (tree_openpre tree_trh tree_trco : real)
  &m :
    (* good_counter_exists: discharged form of p_nu (verdict (E)) -- NOT an axiom.
       Faithful to the paper, which writes: "we assume that it is always possible
       to find a good counter and the adversary can not depend its behavior on
       the existence of a fitting counter." *)
    (forall (mk : mkey) (m : msg), exists c, predC_fors (mco mk m c)) =>
    (* (H-TREE) EXPLICIT PREMISE.  Discharge by instantiating the three reals with
       the FORS_ES tree advantages for THIS adversary A (they are A-dependent --
       which is exactly why constants could never bound them). *)
    (   Pr[EUF_CMA_FORSC_I(A).main() @ &m : res /\ !EUF_CMA_FORSC_I.covered]
     <= tree_openpre + tree_trh + tree_trco) =>
    Pr[EUF_CMA_FORSC(A, O_CMA_FORSC).main() @ &m : res]
  <=   Pr[ITSRC(R_ITSRC_FORSC(A), O_ITSRC_Default).main() @ &m : res]
     + tree_openpre + tree_trh + tree_trco.
proof.
  move=> _ htree.
  (* (H-ITSRC) is a PROVED game-hop (`ITSRC_hop`, zero admit): instrument the
     game (`eufcma_forsc_I_eq`), split on the coverage event `covered`, and bound
     the covered part by ITSR(+C).  (H-TREE) is now the premise `htree`. *)
  rewrite (eufcma_forsc_I_eq A &m).
  rewrite Pr[mu_split EUF_CMA_FORSC_I.covered].
  have hop := ITSRC_hop A &m.
  smt().
qed.

end FORSC.
