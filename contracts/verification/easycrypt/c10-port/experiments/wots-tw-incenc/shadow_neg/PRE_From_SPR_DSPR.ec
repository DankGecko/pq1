require import AllCore List Distr.
require import FinType Finite.
require StdBigop StdOrder DMap.

require KeyedHashFunctions.


op max (x y : real) =
  if x < y then y else x.

lemma max_gel (x y : real) :
  x <= max x y.
proof. by case (x < y) => /#. qed.

lemma max_ger (x y : real) :
  y <= max x y.
proof. by case (x < y) => /#. qed.


type key.

type input.

clone import FinType as Input with
  type t <= input.

type output.


op f : key -> input -> output.


op [lossless] dkey : key distr.
op [lossless full uniform] dinput : input distr.


clone import KeyedHashFunctions as F with
  type key_t <- key,
  type in_t <- input,
  type out_t <- output,

  op f <- f

  proof *.

clone import PRE as F_PRE with
  op dkey <- dkey,
  op din <- dinput

  proof *.
  realize dkey_ll by exact: dkey_ll.
  realize din_ll by exact: dinput_ll.

clone import SPR as F_SPR with
  op dkey <- dkey,
  op din <- dinput

  proof *.
  realize dkey_ll by exact: dkey_ll.
  realize din_ll by exact: dinput_ll.

clone import DSPR as F_DSPR with
  op dkey <- dkey,
  op din <- dinput

  proof *.
  realize dkey_ll by exact: dkey_ll.
  realize din_ll by exact: dinput_ll.



module R_SPR_PRE (A : Adv_PRE) : Adv_SPR  = {
  proc find(k : key, x : input) : input = {
    var x' : input;

    x' <@ A.find(k, f k x);

    return x';
  }
}.


module R_DSPR_PRE (A : Adv_PRE) : Adv_DSPR = {
  proc guess(k : key, x : input) : bool = {
    var x' : input;

    x' <@ A.find(k, f k x);

    return x' <> x;
  }
}.


section Proof_PRE_From_DSPR_SPR.

import RField DMap MRat RealSeries.
import StdBigop.Bigreal BRA.
import StdOrder.RealOrder.


local lemma mem_size_ge1 (s : 'a list) (x : 'a) :
  x \in s => 1 <= size s.
proof. elim: s => //; smt(size_ge0). qed.

local lemma mem_size_ge2 (s : 'a list) (x x' : 'a) :
  x \in s => x' \in s => x <> x' => 2 <= size s.
proof. elim: s => //; smt(size_ge0). qed.

local lemma uniq_size_ge2_mem (s : 'a list) :
  uniq s => 2 <= size s =>
    exists (x x' : 'a), x <> x' /\ x \in s /\ x' \in s.
proof. elim: s => // /#. qed.



local op is_pre_f (k : key) (y : output) : input -> bool =
  fun (x : input) => f k x = y.

local op pre_f_l (k : key) (y : output) : input list =
  to_seq (is_pre_f k y).

local lemma is_finite_ispref (k : key) (y : output) :
  is_finite (is_pre_f k y).
proof. by rewrite (finite_leq predT) 2:-/finite_type 2:is_finite. qed.

local lemma ltcard_szprefl (k : key) (y : output) :
  size (pre_f_l k y) <= card.
proof. by rewrite card_size_to_seq sub_size_to_seq 2:-/finite_type 2:is_finite. qed.


local lemma rngprefl_image (k : key) (x : input) :
  1 <= size (pre_f_l k (f k x)) <= card.
proof.
split => [| _]; 2: by apply ltcard_szprefl.
apply (mem_size_ge1 _ x).
by rewrite mem_to_seq 1:is_finite_ispref.
qed.

local lemma eqv_spex_szprefl (k : key) (x : input) :
  spexists k x <=> 2 <= size (pre_f_l k (f k x)).
proof.
split=> [| @/pre_f_l ge2_szprefl].
+ elim => x' [neqx_xp eqfkx_fkxp].
  by apply (mem_size_ge2 _ x' x) => //; rewrite mem_to_seq 1:is_finite_ispref.
move: (uniq_to_seq (is_pre_f k (f k x))).
move/uniq_size_ge2_mem => /(_ ge2_szprefl) -[x' x''] [#] neqxp_xpp xpin xppin.
case (x' = x) => [eqx_xp | neqx_xp].
+ exists x''; split; 1: by rewrite -eqx_xp eq_sym.
  by move: xppin; rewrite mem_to_seq 1:is_finite_ispref.
exists x'; rewrite neqx_xp /=.
by move: xpin; rewrite mem_to_seq 1:is_finite_ispref.
qed.

local lemma eqv_img_prefl (k : key) (x x' : input) :
  f k x = f k x' <=> pre_f_l k (f k x) = pre_f_l k (f k x').
proof.
split => [-> // | @/pre_f_l eq_prefl].
move: (to_seq_finite (is_pre_f k (f k x)) _); 1: by apply is_finite_ispref.
rewrite uniq_to_seq  /= => /(_ x') /iffLR /(_ _).
+ by rewrite eq_prefl to_seq_finite 1:is_finite_ispref.
by rewrite /is_pre_f => ->.
qed.

local lemma eqv_img_mem (k : key) (x x' : input) :
  f k x = f k x' <=> x' \in pre_f_l k (f k x).
proof. by rewrite to_seq_finite 1:is_finite_ispref /is_pre_f; split => ->. qed.

local lemma eqv_prefl_mem (k : key) (x x' : input) :
  x' \in pre_f_l k (f k x) <=> pre_f_l k (f k x) = pre_f_l k (f k x').
proof. by rewrite -eqv_img_mem eqv_img_prefl. qed.

declare module A <: Adv_PRE.
declare axiom A_find_ll : islossless A.find.


local module Si = {
  var x, x' : input

  proc main(i : int) : bool = {
    var k : key;
    var y : output;

    k <$ dkey;
    x <$ dinput;

    y <- f k x;

    x' <@ A.find(k, y);

    return size (pre_f_l k y) = i /\ f k x' = y;
  }
}.

local module Fi = {
  proc main(i : int) : bool = {
    var k : key;
    var x, x' : input;
    var y : output;

    k <$ dkey;
    x <$ dinput;

    y <- f k x;

    x' <@ A.find(k, y);

    return size (pre_f_l k y) = i /\ f k x' <> y;
  }
}.


local module PREg = {
  var k : key
  var y : output

  proc main() : bool = {
    var x : input;
    var x' : input;

    k <$ dkey;
    x <$ dinput;
    y <- f k x;
    x' <@ A.find(k, y);

    return f k x' = y;
  }
}.

local module SPRg = {
  var k : key
  var x, x' : input

  proc main() : bool = {

    k <$ dkey;
    x <$ dinput;

    x' <@ A.find(k, f k x);

    return x' <> x /\ f k x' = f k x;
  }
}.

local module DSPRg = {
  var k : key
  var x, x' : input

  proc main() : bool = {
    var b : bool;

    k <$ dkey;
    x <$ dinput;

    x' <@ A.find(k, f k x);

    b <- x' <> x;

    return spexists k x = b;
  }
}.

local module SPprobA = {
  var k : key
  var x, x' : input

  proc main() : bool = {
    k <$ dkey;
    x <$ dinput;

    x' <@ A.find(k, f k x);

    return spexists k x;
  }
}.

local module Si_early_fail = {
  var x, x' : input

  proc sample(i : int, k : key) : input * output * bool = {
    var xt : input;
    var y : output;
    var r : bool;

    xt <$ dinput;

    if (size (pre_f_l k (f k xt)) = i) {
      y <- f k xt;
      r <- true;
    } else {
      xt <- witness;
      y <- witness;
      r <- false;
    }

    return (xt, y, r);
  }

  proc main(i : int) : bool = {
    var k : key;
    var y : output;
    var r : bool;

    k <$ dkey;

    (x, y, r) <@ sample(i, k);

    x' <@ A.find(k, y);

    return r /\ (f k x' = y);
  }
}.

local proc op Si_early_fail_sample_sem = Si_early_fail.sample.

local module Si_inverse_sample = {
  var x, x' : input

  proc sample(i : int, k : key) = {
    var xt : input;
    var y : output;
    var r : bool;

    y <$ dmap dinput (f k);

    if (size (pre_f_l k y) = i) {
      xt <$ drat (pre_f_l k y);
      r <- true;
    } else {
      xt <- witness;
      y <- witness;
      r <- false;
    }

    return (xt, y, r);
  }

  proc main(i : int) : bool = {
    var k : key;
    var y : output;
    var r : bool;

    k <$ dkey;

    (x, y, r) <@ sample(i, k);

    x' <@ A.find(k, y);

    return r /\ (f k x' = y);
  }
}.

local proc op Si_inverse_sample_sample_sem = Si_inverse_sample.sample.


lemma fin_sum_type (s : 'a -> real) :
     is_finite predT<:'a>
  => sum s = big predT s (to_seq predT<:'a>).
proof. by apply (fin_sum_cond predT s). qed.

lemma sumr_const_val (P : 'a -> bool) (F : 'a -> real) (x : real) (s : 'a list):
     (forall (i : 'a), P i => F i = x)
  => big P F s = (count P s)%r * x.
proof. by rewrite -sumr_const &(eq_bigr). qed.

lemma sumr_const_val_seq (P : 'a -> bool) (F : 'a -> real) (x : real) (s : 'a list):
     (forall (i : 'a), i \in s /\ P i => F i = x)
  => big P F s = (count P s)%r * x.
proof.
move=> ?; rewrite -sumr_const big_mkcond eq_sym big_mkcond.
apply eq_big_seq => i' ipin /= /#.
qed.


local lemma Si_eq_sem i k:
    Si_early_fail_sample_sem i k
  = Si_inverse_sample_sample_sem i k.
proof.
rewrite /Si_early_fail_sample_sem /Si_inverse_sample_sample_sem /=.
rewrite dlet_dmap /= /dmap /(\o) eq_distr => -[b x y] /=; rewrite 2?dlet1E.
case (i <= 0) => [le0_i | /ltzNge gt0_i].
+ apply eq_sum => x' /=.
  rewrite (: size (pre_f_l k (f k x')) <> i) /=; 1: smt(rngprefl_image).
  by congr; rewrite dmap1E /(\o) /pred1 /= /#.
do 2! (rewrite (sumE_fin _ enum) 1:enum_uniq => [? _ |]; 1: by rewrite enumP).
case ((b, x, y) = (false, witness, witness)) => [-> /= | neql].
+ apply eq_bigr => z _ /=; congr.
  case (size (pre_f_l k (f k z)) = i) => ? /=.
  - rewrite dlet_dlet /= dlet1E dunit1E /= sum0_eq // => x' /=.
    rewrite mulf_eq0; right.
    by rewrite dmap1E /pred1 /(\o) dunitE.
  by rewrite dmap1E /= /pred1 /(\o) /= 2?dunitE //.
case (y = f k x /\ b) => [[-> ->] | /negb_and neqfkx_y]; last first.
+ rewrite ?big1 // => z _ /=.
  - by case (size (pre_f_l k (f k z)) = i) => ? /=; rewrite dunit1E /#.
  case (size (pre_f_l k (f k z)) = i) => ? /=.
  - rewrite dlet_dlet /= dlet1E sum0_eq //=.
    move=> z'; rewrite dmap1E /pred1 /(\o) /=.
    rewrite mulf_eq0; case (z' \in (pre_f_l k (f k z))) => zpin; [right | left].
    * rewrite dunitE /=; case (z' = x) => [->> | //] /=.
      by rewrite (: f k z = f k x) 1:eqv_img_mem // /#.
    by rewrite prratE count_uniq_mem 1:uniq_to_seq  /#.
  by rewrite dmap1E /pred1 /(\o) dunitE /#.
pose flundenum := flatten (undup (map (fun z => pre_f_l k (f k z)) enum)).
have permenum: perm_eq enum flundenum.
+ rewrite perm_eqP_pred1 => x'; rewrite enum_spec eq_sym.
  rewrite count_flatten StdBigop.Bigint.sumzE StdBigop.Bigint.BIA.big_mapT /(\o).
  rewrite (StdBigop.Bigint.BIA.bigD1 _ _ (pre_f_l k (f k x'))) 2:undup_uniq.
  - by rewrite mem_undup mapP; exists x'; rewrite enumP.
  rewrite StdBigop.Bigint.BIA.big1_seq /=; 1: move => xl -[@/predC1 neqxl].
  - rewrite mem_undup mapP => -[z /= [zin ->>]].
    by rewrite count_uniq_mem 1:uniq_to_seq /=; smt(eqv_prefl_mem).
  by rewrite count_uniq_mem 2:to_seq_finite 1:uniq_to_seq 1:is_finite_ispref.
rewrite (eq_big_perm _ _ _ flundenum) // eq_sym (eq_big_perm _ _ _ flundenum) //.
rewrite ?big_flatten ?big_seq &(eq_bigr) => s /=.
rewrite mem_undup mapP => -[z /= [zin ->]]; rewrite 2?big_seq.
case (size (pre_f_l k (f k z)) = i) => [eqi_szfkz | neqi_szfkz]; last first.
+ rewrite &(eq_bigr) => z' /= zpin; congr.
  rewrite (: size (pre_f_l k (f k z')) <> i) /=; 1: smt(eqv_prefl_mem).
  by rewrite dmap1E dunit1E /pred1 /(\o) dunitE.
case (x \in pre_f_l k (f k z)) => [xin | xnin]; last first.
+ rewrite big1 2:eq_sym 1:/predT /= => [z' ^ /eqv_prefl_mem <- zpin |].
  - rewrite eqi_szfkz /= dlet_dlet dlet1E sum0_eq // => z'' /=.
    rewrite mulf_eq0; right; rewrite dlet1E sum0_eq // => r /=.
    case (r = (true, z'', f k z')) => [-> | neqr] /=; last first.
    * by rewrite mulf_eq0; left; rewrite dunit1E [_ = r]eq_sym neqr.
    by rewrite mulf_eq0; right; rewrite dunit1E; smt(eqv_img_mem).
  rewrite big1 // => z' zpin /=; rewrite mulf_eq0 /=.
  right; move/eqv_prefl_mem: (zpin) => <-.
  by rewrite eqi_szfkz /= dunit1E; smt(eqv_img_mem).
rewrite &(eq_trans _ (inv card%r)) 2:eq_sym; last first.
+ rewrite (bigD1_cond _ _ _ x) 1,2:// 1:uniq_to_seq /=.
  rewrite -(addr0 (inv card%r)); congr; 1: rewrite -(mulr1 (inv card%r)).
  - congr; 1: rewrite mu1_uni_ll 1:dinput_uni 1:dinput_ll dinput_fu /=.
    * rewrite card_size_to_seq; do 4! congr.
      by rewrite fun_ext => ? @/predT; rewrite eqT dinput_fu.
    by move/eqv_prefl_mem: (xin) => <-; rewrite dunit1E eqi_szfkz.
  rewrite big1 /predI /predC1 // => z' [^ zpin /eqv_prefl_mem eqprefl neqxzp] /=.
  by rewrite mulf_eq0; right; rewrite dunit1E -eqprefl eqi_szfkz /= neqxzp.
rewrite (sumr_const_val _ _ ((inv card%r) * (inv i%r))) /= => [z' ^ zpin /eqv_prefl_mem <-| ].
+ rewrite eqi_szfkz /= invfM; congr.
  - rewrite mu1_uni_ll 1:dinput_uni 1:dinput_ll dinput_fu /=.
    rewrite card_size_to_seq; do 4! congr.
    by rewrite fun_ext => ? @/predT; rewrite eqT dinput_fu.
  rewrite dlet_dlet dlet1E /= (sumE_fin _ (pre_f_l k (f k z))).
  - by rewrite uniq_to_seq is_finite_ispref.
  - move=> z'' /=; apply contraLR => /= znin.
    by rewrite prratE /= count_uniq_mem 1:uniq_to_seq  znin /b2i.
  rewrite (bigD1 _ _ x) 1:// 1:uniq_to_seq  /=.
  rewrite -(addr0 (inv i%r)); congr; last first.
  - apply big1_seq => z'' @/predC1 [neqxzpp zppin] /=.
    by rewrite mulf_eq0; right; rewrite dmap1E /pred1 /(\o) dunitE /= neqxzpp.
  rewrite -(mulr1 (inv i%r)); congr.
  - by rewrite prratE count_uniq_mem 1:uniq_to_seq  xin eqi_szfkz /b2i.
  rewrite dmap1E dunitE /pred1 /(\o) /=.
  by move/eqv_img_mem: xin zpin => <- /eqv_img_mem <-.
by rewrite count_predT_eq_in 1:// eqi_szfkz /= mulrC invfM -mulrA mulVf 1:/#.
qed.


local clone import DMapSampling as DMS with
  type t1 <- input,
  type t2 <- output

  proof *.

local module Si_inverse_sample_alt = {
  var x, x' : input
  var k : key
  var y : output

  proc orig_sm(i : int) : bool = {
    k <$ dkey;

    y <@ S.map(dinput, f k);

    x' <@ A.find(k, y);

    return size (pre_f_l k y) = i /\ f k x' = y;
  }

  proc orig_ss(i : int) : bool = {
    k <$ dkey;

    y <@ S.sample(dinput, f k);

    x' <@ A.find(k, y);

    return size (pre_f_l k y) = i /\ f k x' = y;
  }

  proc orig_invs(i : int) : bool = {
    k <$ dkey;
    y <$ dmap dinput (f k);

    x' <@ A.find(k, y);

    return size (pre_f_l k y) = i /\ f k x' = y;
  }

  proc main(i : int) : bool = {
    var r : bool;

    r <@ orig_invs(i);

    x <$ drat (pre_f_l k y);

    return r;
  }
}.


local lemma pr_Si_Sief (j : int) &m:
  Pr[Si.main(j) @ &m : res /\ Si.x' <> Si.x]
  =
  Pr[Si_early_fail.main(j) @ &m : res /\ Si_early_fail.x' <> Si_early_fail.x].
proof.
byequiv (: _ ==> ={res} /\ (res{1} => ={x, x'}(Si, Si_early_fail))) => [| // | /#].
proc; inline *.
seq 3 6 : (   (r{2} => ={k, y} /\ ={x}(Si, Si_early_fail))
           /\ (r{2} <=> (size (pre_f_l k{1} y{1}) = i{1}))
           /\ ={glob A, i}).
+ by auto.
case (r{2}).
+ call (: true).
  by skip => />.
conseq (: size (pre_f_l k{1} y{1}) <> i{1} /\ !r{2}) => />.
call{1} A_find_ll; call{2} A_find_ll.
by skip.
qed.

local lemma pr_Sief_Siis (j : int) &m:
  Pr[Si_early_fail.main(j) @ &m : res /\ Si_early_fail.x' <> Si_early_fail.x]
  =
  Pr[Si_inverse_sample.main(j) @ &m : res /\ Si_inverse_sample.x' <> Si_inverse_sample.x].
proof.
case (0 < j) => [gt0_j | /lezNgt le0_j]; last first.
+ have ->:
    Pr[Si_early_fail.main(j) @ &m : res /\ Si_early_fail.x' <> Si_early_fail.x] = 0%r.
  - byphoare (: arg <= 0 ==> _) => //=.
    hoare.
    proc; inline *.
    seq 4 : (i0 <= 0); first by auto.
    rcondf 1; 1: by skip; smt(rngprefl_image).
    sp; conseq (: _ ==> true) => />.
    by call (: true).
+ byphoare (: arg <= 0 ==> _) => //=.
  hoare.
  proc; inline *.
  rcondf 5.
  - rnd.
    wp.
    rnd.
    by wp; skip => />; smt(supp_dmap rngprefl_image).
  seq 8 : (!r); first by auto.
  sp; conseq (: _ ==> true) => />.
  by call (: true).
byequiv=> //=.
proc.
call (: true).
sp.
seq 1 1 : (#pre /\ ={i, k} /\ i{1} = j); first by auto.
call (: ={i, k} /\ 0 < arg{1}.`1 ==> ={res}); last first.
+ by skip.
bypr (res{1}) (res{2}) => //=.
move=> &1 &2 /> -[] x y r eq_i eq_k gt0_i.
rewrite Si_early_fail_sample_sem_opsem Si_inverse_sample_sample_sem_opsem.
rewrite eq_i eq_k; congr; smt(Si_eq_sem).
qed.

local lemma pr_Siis_Siisa (j : int) &m:
  Pr[Si_inverse_sample.main(j) @ &m : res /\ Si_inverse_sample.x' <> Si_inverse_sample.x]
  =
  Pr[Si_inverse_sample_alt.main(j) @ &m : res /\ Si_inverse_sample_alt.x' <> Si_inverse_sample_alt.x].
proof.
byequiv (: _ ==> res{1} /\ Si_inverse_sample.x'{1} <> Si_inverse_sample.x{1}
                 <=>
                 res{2} /\ Si_inverse_sample_alt.x'{2} <> Si_inverse_sample_alt.x{2}) => //.
proc; inline *.
seq 4 3 : (   ={glob A, i, i0}
           /\ k0{1} = k{1}
           /\ k0{1} = Si_inverse_sample_alt.k{2}
           /\ y0{1} = Si_inverse_sample_alt.y{2}
           /\ i0{1} = i{1}
           /\ Si_inverse_sample_alt.y{2} \in dmap dinput (f Si_inverse_sample_alt.k{2})).
+ by rnd; wp; rnd; wp; skip.
if{1}.
+ swap{2} 3 -2.
  wp; call (: true); wp => /=.
  by rnd; skip.
seq 4 0 : (   ={glob A, i}
           /\ i0{2} = i{2}
           /\ !r{1}
           /\ k{1} = Si_inverse_sample_alt.k{2}
           /\ size (pre_f_l Si_inverse_sample_alt.k{2} Si_inverse_sample_alt.y{2}) <> i{2}
           /\ Si_inverse_sample_alt.y{2} \in dmap dinput (f Si_inverse_sample_alt.k{2})).
+ by auto.
swap{2} 2 1; wp.
conseq (: _ ==> true) => />.
rnd{2}.
call{1} A_find_ll; call{2} A_find_ll.
skip => /> _ &2 _ _ /supp_dmap -[x [_ ->]].
by apply drat_ll; smt(rngprefl_image).
qed.


local lemma pr_cond_neqxxp_Si (j : int) &m:
  Pr[Si.main(j) @ &m : res /\ Si.x' <> Si.x]
  =
  (j%r - 1%r) / j%r * Pr[Si.main(j) @ &m : res].
proof.
case (j <= 0) => [le0_j | /ltzNge gt0_j].
+ rewrite (: Pr[Si.main(j) @ &m : res] = 0%r) 2:mulr0.
  - byphoare (_: arg <= 0 ==> _) => //=.
    hoare.
    proc.
    call (: true).
    wp => /=.
    by conseq (_ : _ ==> true) => // />; smt(size_ge0 rngprefl_image).
  byphoare (_: arg <= 0 ==> _) => //=.
  hoare.
  proc.
  call (: true).
  wp => /=.
  by conseq (_ : _ ==> true) => // />; smt(size_ge0 rngprefl_image).
rewrite pr_Si_Sief pr_Sief_Siis pr_Siis_Siisa mulrC.
pose prsi := Pr[Si.main(j) @ &m : res]; pose j1dj := (j%r - 1%r) / j%r.
byphoare (: (glob A) = (glob A){m} /\ arg = j ==> _) => //=.
proc.
seq 1 : r prsi j1dj _ 0%r
        (   r = (size (pre_f_l Si_inverse_sample_alt.k Si_inverse_sample_alt.y) = j
         /\ f Si_inverse_sample_alt.k Si_inverse_sample_alt.x' = Si_inverse_sample_alt.y)) => //.
+ inline *.
  wp; call (: true).
  rnd; rnd.
  by wp; skip.
+ call (_ : (glob A) = (glob A){m} /\ arg = j ==> res) => //.
  rewrite /prsi; bypr => //= &m' [eq_glob ->].
  byequiv=> //=; symmetry.
  transitivity Si_inverse_sample_alt.orig_ss (={glob A, arg} ==> ={res})
                                             (={glob A, arg} ==> ={res}) => //=.
  - by move=> />; exists (glob A){m} j => /#.
  - transitivity Si_inverse_sample_alt.orig_sm (={glob A, arg} ==> ={res})
                                               (={glob A, arg} ==> ={res}) => //=.
    * by move=> /> &2; exists (glob A){2} arg{2} => /#.
    * proc; inline *.
      call (: true).
      by wp; rnd; wp; rnd; skip => />.
    * proc.
      call (: true).
      symmetry.
      call sample.
      by rnd; skip => />.
  proc; inline *.
  call (: true).
  by wp; rnd; wp; rnd; skip => />.
+ rnd; skip => /= &1 -[-> [eqszpfl_i eqy_fkx]].
  rewrite eqszpfl_i eqy_fkx /=.
  have ->:
    (fun (x : input) => Si_inverse_sample_alt.x'{1} <> x)
    =
    predC (pred1 Si_inverse_sample_alt.x'{1}).
  - by rewrite fun_ext => x @/predC /#.
  rewrite mu_not drat_ll 1:-eqy_fkx; 1: by smt(rngprefl_image).
  rewrite dratE count_uniq_mem 1:to_seq_finite 1:is_finite_ispref /b2i.
  rewrite (: Si_inverse_sample_alt.x'{1} \in pre_f_l Si_inverse_sample_alt.k{1} Si_inverse_sample_alt.y{1}) /=.
  -  by rewrite mem_to_seq 1:is_finite_ispref.
  rewrite eqszpfl_i /j1dj {1}(: 1%r = j%r / j%r) 1:mulfV 1:/# //.
  by rewrite -{2}(mul1r (inv j%r)) -mulrBl.
hoare.
by rnd; skip => />.
qed.

local lemma pr_SPprob_bigSi &m:
  Pr[SPprob(R_DSPR_PRE(A)).main() @ &m : res]
  =
  bigi predT (fun (i : int) => Pr[Si.main(i) @ &m : res]) 2 (card + 1)
  +
  bigi predT (fun (i : int) => Pr[Fi.main(i) @ &m : res]) 2 (card + 1).
proof.
rewrite (: Pr[SPprob(R_DSPR_PRE(A)).main() @ &m : res] = Pr[SPprobA.main() @ &m : res]).
+ byequiv=> //.
  proc; inline {1} 3.
  by sim.
have ->:
  Pr[SPprobA.main() @ &m : res]
  =
  Pr[SPprobA.main() @ &m : 2 <= size (pre_f_l SPprobA.k (f SPprobA.k SPprobA.x)) <= card].
+ byequiv => //=.
  proc.
  call (: true).
  rnd; rnd.
  skip => |> k kin x xin.
  split => [x' neqx_xp eqfkx_fkxp|].
  - split => [|_]; 2: by rewrite ltcard_szprefl.
    by rewrite -eqv_spex_szprefl; exists x'.
  by rewrite eqv_spex_szprefl.
suff:
  forall (i : int),
    0 <= i =>
      Pr[SPprobA.main() @ &m : 2 <= size (pre_f_l SPprobA.k (f SPprobA.k SPprobA.x)) <= i]
      =
      bigi predT (fun (i : int) => Pr[Si.main(i) @ &m : res]) 2 (i + 1)
      +
      bigi predT (fun (i : int) => Pr[Fi.main(i) @ &m : res]) 2 (i + 1).
+ by move=> /(_ card _); 1: smt(card_gt0).
elim => [/= | i ge0_i ih].
+ rewrite range_geq // 2!big_nil /=.
  by byphoare (: true ==> false) => // /#.
case (i = 0) => [-> | neq0_i].
+ rewrite range_geq // 2!big_nil /=.
  by byphoare (: true ==> false) => // /#.
rewrite rangeSr 1:/# 2!big_rcons /predT /= -/predT.
rewrite Pr[mu_split (size (pre_f_l SPprobA.k (f SPprobA.k SPprobA.x)) <> i + 1)].
have <-:
  Pr[SPprobA.main() @ &m : 2 <= size (pre_f_l SPprobA.k (f SPprobA.k SPprobA.x)) <= i]
  =
  Pr[SPprobA.main() @ &m : 2 <= size (pre_f_l SPprobA.k (f SPprobA.k SPprobA.x)) <= i + 1
                            /\ size (pre_f_l SPprobA.k (f SPprobA.k SPprobA.x)) <> i + 1].
+ byequiv (: _ ==> ={glob SPprobA}) => [ | // | /#].
  proc.
  call (: true).
  rnd; rnd.
  by skip.
rewrite ih; field; rewrite addrC /= addr_eq0 opprB /= addrC.
rewrite Pr[mu_split (f SPprobA.k SPprobA.x = f SPprobA.k SPprobA.x')].
congr.
+ byequiv => //=.
  proc.
  call (: true).
  wp; rnd; rnd.
  by skip => /> /#.
byequiv => //=.
proc.
call (: true).
wp; rnd; rnd.
by skip => /> /#.
qed.

local lemma pr_DSPR_bigSiFi &m :
  Pr[DSPR(R_DSPR_PRE(A)).main() @ &m : res]
  =
  Pr[Si.main(1) @ &m : res]
  +
  bigi predT (fun (i : int) => (i%r - 1%r) / i%r * Pr[Si.main(i) @ &m : res]) 2 (card + 1)
  +
  bigi predT (fun (i : int) => Pr[Fi.main(i) @ &m : res]) 2 (card + 1).
proof.
rewrite (: Pr[DSPR(R_DSPR_PRE(A)).main() @ &m : res] = Pr[DSPRg.main() @ &m : res]).
+ by byequiv=> //=; proc; inline *; sim.
rewrite Pr[mu_split (1 <= size (pre_f_l DSPRg.k (f DSPRg.k DSPRg.x)) <= card)].
rewrite -(addr0 (big _ _ _)) addrA -addrA (addrC 0%r) addrA; congr; last first.
+ byphoare (: _ ==> false) => //= &0.
  by rewrite rngprefl_image.
have prsp :
  forall (i : int), 0 <= i =>
    Pr[DSPRg.main() @ &m : res /\ 1 <= size (pre_f_l DSPRg.k (f DSPRg.k DSPRg.x)) <= i]
    =
    bigi predT (fun (j : int) => Pr[DSPRg.main() @ &m : res /\ size (pre_f_l DSPRg.k (f DSPRg.k DSPRg.x)) = j]) 1 (i + 1).
+ elim => [/= | i ge0_i ih].
  - rewrite range_geq // big_nil.
    by byphoare (: _ ==> false) => // /#.
  rewrite rangeSr 1:/# big_rcons /predT /= -/predT -ih.
  rewrite Pr[mu_split (size (pre_f_l DSPRg.k (f DSPRg.k DSPRg.x)) <> i + 1)]; congr.
  - by byequiv (: _ ==> ={res, glob DSPRg}); [sim | trivial | smt()].
  by byequiv (: _ ==> ={res, glob DSPRg}); [sim | trivial | smt()].
rewrite prsp 2:range_ltn; 1,2: smt(card_gt0).
rewrite big_cons /predT /= -/predT -addrA; congr.
+ byequiv => //=.
  proc.
  wp.
  call (: true).
  wp; rnd; rnd.
  by skip => />; smt(eqv_spex_szprefl).
rewrite -big_split /= &(eq_big_seq) => i /mem_range rng_i /=.
rewrite Pr[mu_split (f DSPRg.k DSPRg.x' =f DSPRg.k DSPRg.x)]; congr; last first.
+ byequiv => //=.
  proc.
  wp.
  call (: true).
  wp; rnd; rnd.
  by skip => />; smt(eqv_spex_szprefl).
rewrite -mulrAC.
have ->:
  Pr[DSPRg.main() @ &m : (res /\ size (pre_f_l DSPRg.k (f DSPRg.k DSPRg.x)) = i)
                             /\ f DSPRg.k DSPRg.x' = f DSPRg.k DSPRg.x]
  =
  Pr[Si.main(i) @ &m : res /\ Si.x' <> Si.x].
+ byequiv => //.
  proc.
  wp.
  call (: true).
  wp; rnd; rnd.
  by skip => />; smt(eqv_spex_szprefl).
by apply pr_cond_neqxxp_Si.
qed.


local lemma pr_PRE_bigSi &m :
  Pr[PRE(A).main() @ &m : res]
  =
  Pr[Si.main(1) @ &m : res]
  +
  bigi predT (fun (i : int) => Pr[Si.main(i) @ &m : res]) 2 (card + 1).
proof.
have ->: Pr[PRE(A).main() @ &m : res] = Pr[PREg.main() @ &m : res].
+ by byequiv=> //=; sim.
rewrite (: Pr[Si.main(1) @ &m : res] = (fun (i : int) => Pr[Si.main(i) @ &m : res]) 1) //.
rewrite -big_consT -range_ltn; 1: smt(card_gt0).
rewrite Pr[mu_split (1 <= size (pre_f_l PREg.k PREg.y) <= card)] -(addr0 (big _ _ _)).
congr; last first.
+ byphoare => //=.
  hoare.
  proc.
  call (: true).
  wp; rnd; rnd; skip => /> k kin x xin x'.
  by rewrite rngprefl_image.
suff:
  forall (i : int),
    0 <= i =>
      Pr[PREg.main() @ &m : res /\ 1 <= size (pre_f_l PREg.k PREg.y) <= i]
      =
      bigi predT (fun (i : int) => Pr[Si.main(i) @ &m : res]) 1 (i + 1).
+ by move => /(_ card); smt(size_ge0).
elim => /= [ | i ge0_i ih].
+ rewrite range_geq 1:// big_nil.
  by byphoare (: _ ==> false) => // /#.
rewrite (: i + 2 = i + 1 + 1) 1:// rangeSr 1:/# big_rcons /predT /= -/predT.
rewrite -ih Pr[mu_split (size (pre_f_l PREg.k PREg.y) = i + 1)] addrC.
congr; last first.
+ byequiv => //=.
  proc.
  call (: true).
  wp; rnd; rnd; skip => /> /#.
byequiv => //=.
proc.
call (: true).
by wp; rnd; rnd; skip => /> /#.
qed.

local lemma pr_DSPRSPprob_bigSi &m :
  Pr[DSPR(R_DSPR_PRE(A)).main() @ &m : res] - Pr[SPprob(R_DSPR_PRE(A)).main() @ &m : res]
  =
  Pr[Si.main(1) @ &m : res]
  -
  bigi predT (fun (i : int) => 1%r / i%r * Pr[Si.main(i) @ &m : res]) 2 (card + 1).
proof.
rewrite pr_DSPR_bigSiFi pr_SPprob_bigSi.
field; rewrite -big_split /= subr_eq0 &(eq_big_seq) => i /mem_range rng_i /=.
by rewrite -mulrDl -{1}mul1r /= !mulrDl /= 1:/#.
qed.

local lemma pr_SPR_bigSi &m :
  Pr[SPR(R_SPR_PRE(A)).main() @ &m : res]
  =
  bigi predT (fun (i : int) => (i%r - 1%r) / i%r * Pr[Si.main(i) @ &m : res]) 2 (card + 1).
proof.
rewrite (: Pr[SPR(R_SPR_PRE(A)).main() @ &m : res] = Pr[SPRg.main() @ &m : res]).
+ byequiv => //=.
  proc; inline *.
  wp.
  call (: true).
  wp; rnd; rnd.
  by skip => /> /#.
have ->:
  Pr[SPRg.main() @ &m : res]
  =
  bigi predT (fun (i : int) => Pr[Si.main(i) @ &m : res /\ Si.x' <> Si.x]) 2 (card + 1).
+ rewrite Pr[mu_split (2 <= size (pre_f_l SPRg.k (f SPRg.k SPRg.x)) <= card)].
  rewrite -(addr0 (big _ _ _)); congr; last first.
  - byphoare => //.
    hoare.
    proc; inline *.
    wp.
    call (: true).
    wp; rnd; rnd.
    skip => /> k kin x xin x'.
    rewrite negb_and /= -implybE => [#] neqx_xp eqfkx_fkxp.
    rewrite -eqv_spex_szprefl ltcard_szprefl /=.
    by exists x'.
  suff:
    forall (i : int),
      0 <= i =>
        Pr[SPRg.main() @ &m : res /\ 2 <= size (pre_f_l SPRg.k (f SPRg.k SPRg.x)) <= i]
        =
        bigi predT (fun (i : int) => Pr[Si.main(i) @ &m : res /\ Si.x' <> Si.x]) 2 (i + 1).
  - by move=> /(_ card _).
  elim => [/= | i ge0_i ih].
  - rewrite range_geq // big_nil.
    by byphoare (: _ ==> false) => // /#.
  case (i = 0) => [-> | neq0_i].
  - rewrite range_geq // big_nil.
    by byphoare (: _ ==> false) => // /#.
  rewrite rangeSr 1:/# big_rcons /predT /= -/predT.
  rewrite Pr[mu_split (size (pre_f_l SPRg.k (f SPRg.k SPRg.x)) <> i + 1)]; congr.
  + by rewrite -ih; byequiv (: _ ==> ={glob SPRg, res}); [sim | | smt()].
  byequiv => //=.
  proc; inline *.
  wp.
  call (: true).
  wp; rnd; rnd.
  by skip => /> /#.
apply eq_big_seq => i /mem_range rng_i /=; rewrite mulrAC.
by apply pr_cond_neqxxp_Si.
qed.


lemma PRE_From_DSPR_SPR &m :
  Pr[PRE(A).main() @ &m : res]
  <=
  max 0%r (Pr[DSPR(R_DSPR_PRE(A)).main() @ &m : res] - Pr[SPprob(R_DSPR_PRE(A)).main() @ &m : res])
  +
  3%r * Pr[SPR(R_SPR_PRE(A)).main() @ &m : res].
proof.
apply (ler_trans
        (Pr[DSPR(R_DSPR_PRE(A)).main() @ &m : res] - Pr[SPprob(R_DSPR_PRE(A)).main() @ &m : res] +
         3%r * Pr[SPR(R_SPR_PRE(A)).main() @ &m : res])); last first.
+ by apply ler_add; 1: rewrite max_ger.
rewrite pr_PRE_bigSi pr_DSPRSPprob_bigSi pr_SPR_bigSi.
rewrite -addrA &(ler_add) 1:// addrC mulrC mulr_suml sumrB /=.
apply ler_sum_seq => i /mem_range rng_i _ /=.
rewrite mulrC 2!mulrA mulrDr /= divrr 1:/# /=.
rewrite mulrAC mulrDl /= 2!mulNr /= mulrC -mulrBr.
by rewrite &(ler_pemulr) 1:Pr[mu_ge0] // /#.
qed.

end section Proof_PRE_From_DSPR_SPR.
