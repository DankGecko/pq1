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

   NOT proven here (the next milestones, deliberately not admitted):
     * the k-fold product over independent trees:  DS^(k-1) * (1/t)
     * the binomial mixture over a fresh candidate's instance load
     * the (q_h + 1) union bound over the adversary's hash queries
   ========================================================================== *)

require import AllCore List FSet Distr DList DInterval StdBigop StdOrder.
require import RealExp.
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

end DarkSide.
