(* ==========================================================================
   DarkSide.ec -- the FIXED-LOAD combinatorial core of the FORS / FORS+C
   coverage argument, as a PURE PROBABILITY statement.

   No scheme, no adversary, no ROM, no game.  Just:

       DS gam  =  Pr[ a uniform leaf index is among `gam` uniformly revealed ones ]
               =  1 - (1 - 1/t)^gam

   This is the paper's `DarkSide_gamma`.  It is the first mechanizable milestone
   of the direct FORS+C argument: everything else (the k-fold product, the
   binomial mixture over instance load, the (q_h+1) union bound) is built on it.

   WHY THIS IS THE RIGHT FIRST STEP
   --------------------------------
   The published SPHINCS+C paper has no FORS+C security theorem, and MM45 never
   BOUNDS ITSR -- its final theorem carries `Pr[MCO_ITSR.ITSR(...)]` as an
   UNREDUCED term, and no lemma anywhere in MM45 bounds it.  So the concrete
   coverage arithmetic has never been mechanized by anyone, in either work.  It
   is also the only part that needs no ROM and no adversary, and EasyCrypt's
   stdlib has NO concentration inequalities (no Chernoff/Hoeffding/Chebyshev),
   so the rest of the argument must be built by hand on top of exactly this.

   WHAT IS PROVEN HERE
   -------------------
     miss_pr  : Pr[the candidate leaf misses all gam revealed leaves] = (1-1/t)^gam
     cover_pr : Pr[the candidate leaf is covered]                     = DS gam
     ds_mono  : DS is monotone in gam           (sanity)
     ds_ge_1t : DS gam >= 1/t for gam >= 1      (the engine of "FORS+C <= FORS")
     ds_0     : DS 0 = 0                        (nothing revealed => never covered)

   UPDATE 2026-08-11 — TWO OF THE THREE MILESTONES BELOW ARE NOW PROVEN, and
   this header had gone stale claiming otherwise.  Caught by adversarial review
   (Kimi K3 and GPT-5.6 independently) while costing the ITSRC10 routes; the
   original text is kept beneath so the history stays readable.

     PROVEN NOW
       * cover_all_pr  (:204) — the k-fold product over independent trees.
       * cover_some_le (:236) — the union bound over the adversary's candidate
         leaf-vectors, i.e. the (q_h + 1)-style factor.  Pure finite
         subadditivity over cover_all_pr; no concentration inequality needed.
       * ds_le_linear  (:285) — DS gam <= gam/t.  Not on the original list at
         all, so it was under-claimed rather than over-claimed.

     STILL OPEN — and this one is the hard half, so do not read the above as
     "the combinatorial core is done":
       * the binomial mixture over a fresh candidate's instance load
         (G ~ Bin(qs, 1/2^18)).  The remark at :234 says the same thing at the
         point of use.  EasyCrypt's stdlib has no concentration inequalities, so
         this is hand-built.

   WHAT THE WHOLE FILE IS AND IS NOT, since two reviewers had to reconstruct it:
   this is the PURE COMBINATORIAL core of the direct ("DarkSide") FORS+C
   argument.  Even completed it does NOT discharge the ITSRC10 assumption.  Two
   further pieces stand between here and that: a concrete numeric instantiation,
   and the ROM / query-budget game plus a coupling theorem — the ITSRC10 game as
   currently axiomatized has an abstract `mco` and no query bound, so there is a
   legal model in which it is won with probability 1.  "Mechanise this
   arithmetic" is NOT the remaining work.

   [STALE — SUPERSEDED 2026-08-11, kept for history.  The paragraph below was
   true when written and was made false by the promotion commit LATER THE SAME
   DAY; the staleness was caught by Kimi K3 adversarial review, not by a gate.
   CURRENT STATE: DarkSide.ec is closure member #30 of closure-c10-split.txt.
   It is compiled by PHASE 1, require-checked by PHASE 1d, run under both drivers
   by PHASE 1e, censused by PHASE 2, and NINE of its lemmas are statement-digest
   pinned in cert-statements-split.tsv (ds_ge_1t, forsc_le_fors, cover_all_pr,
   cover_some_le, ds_le_linear, mixture_le_moment, mixture_le_moment_finite_ex,
   plus the two c10_* in DarkSideC10.ec).  An axiom-ification would trip PHASE 2;
   a weakened statement would trip PHASE 1c.]
   | AND NOTHING GATES THIS FILE.  DarkSide.ec is required by no closure member and
   | is absent from closure-c10-split.txt, so it is outside the certified cone and
   | outside the identity hash: it compiles admit-free today, but no gate run would
   | notice if that stopped being true.  Promoting it is a prerequisite for the
   | hybrid route, not an afterthought.

   ORIGINAL TEXT, now partly stale — kept deliberately:
   | NOT proven here (the next milestones, deliberately not admitted):
   |   * the k-fold product over independent trees:  DS^(k-1) * (1/t)
   |   * the binomial mixture over a fresh candidate's instance load
   |   * the (q_h + 1) union bound over the adversary's hash queries
   ========================================================================== *)

require import AllCore List FSet Distr DList DInterval StdBigop StdOrder.
require import RealExp.
require import Finite.
import RField RealOrder.
import Bigreal Bigreal.BRM.

abstract theory DarkSide.

(* Leaves per FORS tree.  C10: t = 2^11 = 2048. *)
const t : { int | 1 <= t } as ge1_t.

(* A uniform leaf index in [0, t-1]. *)
op dleaf : int distr = dinter 0 (t - 1).

lemma dleaf_ll : is_lossless dleaf.
proof. by rewrite /dleaf dinter_ll; smt(ge1_t). qed.

lemma supp_dleaf (x : int) : x \in dleaf <=> 0 <= x < t.
proof. by rewrite /dleaf supp_dinter; smt(). qed.

lemma dleaf1E (x : int) : 0 <= x < t => mu1 dleaf x = 1%r / t%r.
proof. by move=> hx; rewrite /dleaf dinter1E; smt(ge1_t). qed.

(* The paper's DarkSide_gamma. *)
op DS (gam : int) : real = 1%r - (1%r - 1%r / t%r) ^ gam.

(* ==========================================================================
   THE CORE IDENTITY.

   `gam` leaves are revealed, each an independent uniform draw (that is exactly
   the FORS model: each signature opens one uniformly-selected leaf per tree).
   A fixed candidate leaf `c` misses all of them with probability (1-1/t)^gam.
   ========================================================================== *)

(* one draw misses a fixed c with probability 1 - 1/t *)
lemma mu_dleaf_neq (c : int) :
  0 <= c < t => mu dleaf (fun (x : int) => x <> c) = 1%r - 1%r / t%r.
proof.
move=> hc.
have -> : (fun (x : int) => x <> c) = predC (pred1 c).
+ by apply/fun_ext => x; rewrite /predC /pred1 /=; smt().
rewrite mu_not.
have -> : weight dleaf = 1%r by smt(dleaf_ll).
by rewrite dleaf1E.
qed.

lemma miss_pr (c gam : int) :
  0 <= c < t => 0 <= gam =>
  mu (dlist dleaf gam) (fun l => ! (c \in l)) = (1%r - 1%r / t%r) ^ gam.
proof.
move=> hc hg.
(* on the support (size l = gam), "c is not in l" is "every position differs" *)
rewrite (mu_eq_support _ _
  (fun (l : int list) => forall i, 0 <= i && i < gam => (nth 0 l i) <> c)).
+ move=> l; rewrite supp_dlist // => -[hsz _] /=; smt(nthP mem_nth).
rewrite (dlistE 0 dleaf (fun (_ : int) (x : int) => x <> c) gam) /=.
rewrite (eq_bigr _ _ (fun (_ : int) => 1%r - 1%r / t%r)).
+ by move=> i _ /=; apply mu_dleaf_neq.
by rewrite mulr_const size_range; smt().
qed.

lemma cover_pr (c gam : int) :
  0 <= c < t => 0 <= gam =>
  mu (dlist dleaf gam) (fun l => c \in l) = DS gam.
proof.
move=> hc hg; rewrite /DS -(miss_pr c gam hc hg).
have -> : (fun (l : int list) => c \in l)
        = predC (fun (l : int list) => ! (c \in l)).
+ by apply/fun_ext => l; rewrite /predC /=; smt().
rewrite mu_not.
have -> : weight (dlist dleaf gam) = 1%r by smt(dlist_ll dleaf_ll).
done.
qed.

(* ==========================================================================
   SANITY / STRUCTURE (the facts the rest of the argument leans on).
   ========================================================================== *)
lemma ds_0 : DS 0 = 0%r.
proof. by rewrite /DS expr0. qed.

lemma ge0_1t : 0%r <= 1%r - 1%r / t%r < 1%r.
proof. smt(ge1_t). qed.

(* every DS is a probability *)
lemma ds_bnd (gam : int) : 0 <= gam => 0%r <= DS gam <= 1%r.
proof.
move=> hg; rewrite /DS; have [h1 h2] := ge0_1t.
smt(expr_ge0 exprn_ile1 ge1_t).
qed.

(* DS gam >= 1/t for gam >= 1 -- with equality at gam = 1.  This is the engine of
   the "FORS+C is never weaker than plain FORS" inequality
   (DS^(k-1)/t_last <= DS^k  iff  1/t_last <= DS). *)
lemma ds_1 : DS 1 = 1%r / t%r.
proof. by rewrite /DS expr1; smt(). qed.

lemma ds_mono (g1 g2 : int) : 0 <= g1 <= g2 => DS g1 <= DS g2.
proof.
move=> [h1 h2]; rewrite /DS ler_add2l ler_opp2.
have [ha hb] := ge0_1t.
by apply ler_wiexpn2l; smt().
qed.

lemma ds_ge_1t (gam : int) : 1 <= gam => 1%r / t%r <= DS gam.
proof. by move=> hg; rewrite -ds_1; apply ds_mono; smt(). qed.

(* ==========================================================================
   THE PAPER'S CENTRAL FORS+C CLAIM, MECHANIZED (per-tree / fixed-load form).

   SPHINCS+C (IEEE S&P 2023 §IV) argues informally:

       "(DarkSide_g)^(k-1) * 1/t'  <=  (DarkSide_g)^k   when t' >= t,
        hence we can use the previous ITSR analysis to bound FORS+C."

   with NO reduction and NO theorem.  Here it is a machine-checked inequality over
   the DarkSide probability we just PROVED is the coverage probability -- not an
   opaque real.  `t' = t` (C10's case) is the equality boundary; `ds_ge_1t` is the
   engine, and it is where `gam >= 1` is needed (at gam = 0 nothing is revealed and
   both sides are 0).

   FORS+C's last tree is forced to leaf 0, which every signature reveals -- but the
   candidate digest must still HIT it, costing the 1/t factor.  That is the
   `1%r / t%r` below.
   ========================================================================== *)
lemma forsc_le_fors (k gam : int) :
  1 <= k => 1 <= gam =>
  DS gam ^ (k - 1) * (1%r / t%r) <= DS gam ^ k.
proof.
move=> hk hg.
have hk1 : 0 <= k - 1 by smt().
have hds : 1%r / t%r <= DS gam by apply ds_ge_1t.
have hb  : 0%r <= DS gam <= 1%r by apply ds_bnd; smt().
have e : k - 1 + 1 = k by smt().
have hkk := exprSr (DS gam) (k - 1) hk1.
rewrite e in hkk.
rewrite hkk.
by apply ler_wpmul2l; [ smt(expr_ge0) | exact hds ].
qed.

(* NOTE: an earlier draft of this file carried a lemma labelled "Strictness for
   gam >= 2" whose STATEMENT was `<=`, not `<`.  Deleted rather than shipped: a
   name that overclaims its own statement is the exact defect class this port has
   been correcting all week.  A genuine strict version is provable (for gam >= 2,
   `1/t < DS gam` and `DS gam ^ (k-1) > 0`), but it is not needed by anything and
   is not asserted here. *)

(* ==========================================================================
   THE K-FOLD PRODUCT OVER INDEPENDENT TREES.

   The first "NOT proven here" milestone from the header, now DISCHARGED.

   FORS uses `nt` INDEPENDENT trees.  Each tree independently reveals `gam`
   uniformly-drawn leaves, so the whole reveal is one draw from
   `dlist (dlist dleaf gam) nt` (a length-`nt` list of trees, each a length-`gam`
   list of uniform leaves).  A fixed candidate names ONE valid leaf per tree:
   `cs`, a length-`nt` leaf-vector with every entry in [0,t).  The candidate is
   "covered" when, in EVERY tree i, its i-th named leaf `nth 0 cs i` appears
   among that tree's revealed leaves `nth [] trees i`.

   The joint all-covered probability is the genuine INDEPENDENCE PRODUCT
   `DS gam ^ nt` -- an EQUALITY, not a bound, and it carries the full
   independence content: `dlistE` factors the joint `mu` over the outer
   `dlist ... nt` into the product, over trees, of each tree's per-tree coverage
   `mu`, and each factor is exactly `cover_pr = DS gam`.  For `nt = k` (or the
   `k-1` productive trees plus the forced last one) this is the `DS^(k-1)*(1/t)`
   vs `DS^k` arithmetic of `forsc_le_fors`, now resting on a proven joint law
   rather than an assumed one. *)
lemma cover_all_pr (cs : int list) (gam nt : int) :
  0 <= gam => 0 <= nt => size cs = nt =>
  all (fun (c : int) => 0 <= c /\ c < t) cs =>
  mu (dlist (dlist dleaf gam) nt)
     (fun (trees : int list list) =>
        forall i, 0 <= i && i < nt => (nth 0 cs i) \in (nth [] trees i))
  = DS gam ^ nt.
proof.
move=> hg hnt hsz hall.
have hbound : forall i, 0 <= i < nt => 0 <= nth 0 cs i < t.
+ move=> i hi; move: hall => /allP hall'.
  have hm : nth 0 cs i \in cs by apply mem_nth; smt().
  have := hall' _ hm; smt().
rewrite (dlistE [] (dlist dleaf gam)
          (fun (i : int) (tree : int list) => (nth 0 cs i) \in tree) nt) /=.
rewrite (eq_big_seq _ (fun (_ : int) => DS gam)).
+ move=> i /mem_range hi /=.
  by apply cover_pr; [ apply hbound | exact hg ].
by rewrite mulr_const size_range; smt().
qed.

(* ==========================================================================
   THE (q_h+1) UNION BOUND (pure-probability form) -- the 2nd "NOT proven here"
   milestone from the header, built on `cover_all_pr`.

   Charges the winning probability to a UNION over the adversary's candidate
   leaf-vectors: if ANY candidate in `cands` is covered in ALL nt trees, the
   union bound charges each at the per-candidate coverage `DS gam ^ nt`.  So
   Pr[some candidate covered] <= |cands| * DS gam ^ nt.  Pure finite subadditivity
   over the proven `cover_all_pr` -- no concentration inequality needed here (the
   binomial mixture over instance load is the remaining, harder piece; this is the
   (q_h+1)-style union factor). *)
lemma cover_some_le (cands : int list list) (gam nt : int) :
  0 <= gam => 0 <= nt =>
  (forall c, c \in cands => size c = nt /\ all (fun (x : int) => 0 <= x /\ x < t) c) =>
  mu (dlist (dlist dleaf gam) nt)
     (fun (trees : int list list) =>
        has (fun (c : int list) =>
               forall i, 0 <= i && i < nt => (nth 0 c i) \in (nth [] trees i)) cands)
  <= (size cands)%r * DS gam ^ nt.
proof.
move=> hg hnt; elim: cands => [| c cs ih] hvalid.
+ have -> : (fun (trees : int list list) =>
              has (fun (c0 : int list) =>
                     forall i, 0 <= i && i < nt => nth 0 c0 i \in nth [] trees i) [])
           = pred0 by apply/fun_ext => trees.
  rewrite mu0 /=; smt(expr_ge0 ds_bnd).
+ have [hcsz hcall] : size c = nt /\ all (fun (x : int) => 0 <= x /\ x < t) c
    by apply hvalid; rewrite mem_head.
  have hcs : forall c0, c0 \in cs =>
               size c0 = nt /\ all (fun (x : int) => 0 <= x /\ x < t) c0
    by move=> c0 hc0; apply hvalid; rewrite in_cons hc0.
  pose PA := fun (trees : int list list) =>
               forall i, 0 <= i && i < nt => nth 0 c i \in nth [] trees i.
  pose PB := fun (trees : int list list) =>
               has (fun (c0 : int list) =>
                      forall i, 0 <= i && i < nt => nth 0 c0 i \in nth [] trees i) cs.
  have -> : (fun (trees : int list list) =>
              has (fun (c0 : int list) =>
                     forall i, 0 <= i && i < nt => nth 0 c0 i \in nth [] trees i) (c :: cs))
          = predU PA PB by apply/fun_ext => trees.
  apply (ler_trans (mu (dlist (dlist dleaf gam) nt) PA
                  + mu (dlist (dlist dleaf gam) nt) PB)).
  + rewrite mu_or; smt(ge0_mu).
  have -> : mu (dlist (dlist dleaf gam) nt) PA = DS gam ^ nt
    by rewrite /PA; exact (cover_all_pr c gam nt hg hnt hcsz hcall).
  have hih : mu (dlist (dlist dleaf gam) nt) PB <= (size cs)%r * DS gam ^ nt
    by rewrite /PB; exact (ih hcs).
  have hsz : (size (c :: cs))%r = (size cs)%r + 1%r by smt().
  apply (ler_trans (DS gam ^ nt + (size cs)%r * DS gam ^ nt)).
  + by rewrite ler_add2l; exact hih.
  rewrite hsz mulrDl mul1r; smt().
qed.

(* --------------------------------------------------------------------------
   LINEARISATION `DS gam <= gam/t` (Bernoulli).  The paper's DarkSide analysis
   uses `DS_gamma ~ gamma/t` for small gamma; this is the rigorous one-sided
   bound `DS gam <= gam * (1/t)`, the handle that makes the binomial mixture over
   instance load `E_{G~dbin(1/N, qs)}[DS(G)^(k-1)]` tractable (the remaining, and
   last, milestone).  Proof: induction on gam with the per-step Bernoulli step
   `(1-p)^(n+1) = (1-p)^n - (1-p)^n * p >= (1 - n*p) - p`. *)
lemma ds_le_linear (gam : int) : 0 <= gam => DS gam <= gam%r / t%r.
proof.
elim: gam => [|n hn ih]; first by rewrite /DS expr0; smt(ge1_t).
rewrite /DS exprSr 1:/#.
have ha0 : 0%r <= (1%r - 1%r/t%r) ^ n by smt(expr_ge0 ge1_t).
have ha1 : (1%r - 1%r/t%r) ^ n <= 1%r by smt(exprn_ile1 ge1_t).
have hap : (1%r - 1%r/t%r) ^ n * (1%r / t%r) <= 1%r / t%r.
+ by rewrite -{2}(mul1r (1%r/t%r)); apply ler_wpmul2r; [ smt(ge1_t) | exact ha1 ].
have hexp : (1%r - 1%r/t%r) ^ n * (1%r - 1%r/t%r)
          = (1%r - 1%r/t%r) ^ n - (1%r - 1%r/t%r) ^ n * (1%r / t%r) by ring.
move: ih; rewrite /DS => ih.
rewrite hexp fromintD.
smt().
qed.

(* ==========================================================================
   THE MIXTURE STEP -- (A) OF THE REMAINING MILESTONE.

   `ds_le_linear` is the HANDLE (this file's word for it, :317).  This lemma is
   the USE of that handle: it discharges the mixture over instance load down to
   a RAW MOMENT, for an ARBITRARY finitely-supported distribution on the
   non-negative integers.

     E_G[ DS(G)^m ]  <=  E_G[ (G/t)^m ]

   WHAT IT IS NOT.  It does NOT evaluate that moment, and it says nothing about
   the binomial in particular -- the instantiation G ~ Bin(qs, 1/N) and its 12th
   moment are the SEPARATE remaining piece.  Naming it `mixture_le_moment` and
   not anything with "binomial" or "bound" in it is deliberate.

   WHY `is_finite (support dG)` RATHER THAN `hasE`.  It is the premise a caller
   can actually discharge: any binomial has finite support, and `hasE_finite`
   then supplies BOTH summability obligations internally.  Stating it with a bare
   `hasE` would have been a true theorem whose premise no caller could obviously
   meet -- see mixture_le_moment_finite_ex below, which discharges it at a
   concrete distribution rather than asserting it is dischargeable. *)
lemma mixture_le_moment (dG : int distr) (m : int) :
     0 < m
  => is_finite (support dG)
  => (forall g, g \in dG => 0 <= g)
  => E dG (fun g => DS g ^ m) <= E dG (fun g => (g%r / t%r) ^ m).
proof.
move=> hm hfin hsupp.
apply (in_ler_exp _ _ _ (hasE_finite _ _ hfin) (hasE_finite _ _ hfin)).
move=> g hg /=.
have hg0 : 0 <= g by apply hsupp.
have hd  : 0%r <= DS g <= 1%r by apply ds_bnd.
have hlin : DS g <= g%r / t%r by apply ds_le_linear.
have hge : 0%r <= g%r / t%r by smt(ge1_t).
by apply ler_pexp; smt().
qed.

(* THE PREMISE IS DISCHARGEABLE -- shown, not asserted.  A lemma whose hypothesis
   no caller can meet is a theorem about nothing; this session already produced
   one of those (a capstone with no consumer) and the lesson is to supply the
   witness in the same commit.  `dinter 0 n` is finitely supported and
   non-negative, so both premises fall out and the mixture bound applies. *)
lemma mixture_le_moment_finite_ex (n m : int) :
     0 < m
  => 0 <= n
  => E (dinter 0 n) (fun g => DS g ^ m)
     <= E (dinter 0 n) (fun g => (g%r / t%r) ^ m).
proof.
move=> hm hn.
apply mixture_le_moment => //.
+ by apply finite_dinter.
+ by move=> g; rewrite supp_dinter /#.
qed.

end DarkSide.
