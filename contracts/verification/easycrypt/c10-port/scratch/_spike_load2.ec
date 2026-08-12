(* SPIKE 2 (2026-08-11) -- ATTEMPT the load law, do not merely state it.
   NOT A DELIVERABLE.  Ungated scratch.  Records a MEASUREMENT.

   WHAT IS PROVEN HERE: `head_split`, the RECURSION STEP of the load law --
   the step I had called "the risky one" when claiming the load law was
   feasible-but-unattempted.  It is proven, no admit, in-container (r2026.02).

   WHAT IS NOT PROVEN: the load law itself
       dmap (dlist (dbiased p) n) cnt = dbin p n
   still needs (i) the n=0 base case and (ii) the k-boundary arithmetic
   (k<0, k=0, k=n+1) around binSn.  See the note at the bottom -- (ii) has a
   real subtlety, not a formality.

   Route, from primary sources read in-container:
     dmap1E   Distr.ec:1196     dmapE      Distr.ec:1224
     dprod_dlet Distr.ec:1891   dletE_bool Distr.ec:1049
     dlistS   DList.ec:20       dbin1E     Distr.ec:2797
     binSn    Binomial.ec:75    dbiased1E  DBool.ec:53
     count    List.ec:453 (structural recursion -- reduces under /=)          *)
require import AllCore List Distr DBool DList StdBigop StdOrder RealExp.
require import Binomial.
import RField RealOrder.
import Biased.

op cnt (l : bool list) = count (fun (b : bool) => b) l.

(* THE RECURSION STEP -- PROVEN.
   NOTE the hypothesis `0%r <= p <= 1%r`.  My first version of this statement
   OMITTED it and still compiled with an `admit`; the goal dump then showed a
   residual `clamp p = p`, i.e. the lemma as first stated is FALSE outside
   [0,1].  Found by dumping the goal rather than by reasoning about it.       *)
lemma head_split (p : real) (n k : int) :
  0 <= n => 0%r <= p <= 1%r =>
    mu (dlist (dbiased p) (n+1)) (fun l => cnt l = k)
  = p * mu (dlist (dbiased p) n) (fun l => cnt l = k-1)
  + (1%r - p) * mu (dlist (dbiased p) n) (fun l => cnt l = k).
proof.
move=> ge0_n rg_p.
have hc : clamp p = p by smt(clamp_id).
have hd : forall (a:bool),
  dlet (dlist (dbiased p) n) (fun b => dunit (a,b))
  = dmap (dlist (dbiased p) n) (fun b => (a,b)).
- by move=> a; rewrite /dmap.
rewrite dlistS // dmapE /(\o) /=.
rewrite dprod_dlet dletE_bool !dbiased1E /= !hd !dmapE /(\o) /= !hc.
congr.
- by congr; apply mu_eq => l /=; rewrite /cnt /= /#.
by congr; apply mu_eq => l /=; rewrite /cnt /= /#.
qed.

(* ---------------------------------------------------------------------------
   WHAT REMAINS, stated precisely so the cost is not guessed again.

   Base (n = 0): dlist0 gives dunit [], so LHS = b2r (0 = k); RHS = dbin1E at
   n=0.  Routine.

   Step: combine head_split with dbin1E on both sides.  The identity is
     p*bin n (k-1)*p^(k-1)*(1-p)^(n-k+1) + (1-p)*bin n k*p^k*(1-p)^(n-k)
   = bin (n+1) k * p^k * (1-p)^(n+1-k)
   which is binSn (Binomial.ec:75) after factoring.  BUT binSn requires
   0 <= n /\ 0 <= m, so k <= 0 must be split off (bin is 0 there), and the
   factoring p^k = p * p^(k-1) needs k >= 1.

   THE ONE REAL SUBTLETY, not a formality: at k = n+1 the term (1-p)^(n-k)
   has a NEGATIVE exponent.  EasyCrypt's real `^` with an int exponent is
   inverse-valued there, so when p = 1 this is a division by zero and the
   naive factoring is unsound at that edge.  Either split k = n+1 separately
   or avoid ever introducing (1-p)^(n-k).  This is the part that would eat the
   time, and it is why "ordinary induction" was too glib a description.
   --------------------------------------------------------------------------- *)
