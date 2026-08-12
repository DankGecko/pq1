require import AllCore List IntDiv BitEncoding.
(*---*) import BS2Int.

(* -- Types -- *)
type 'a bintree = [  
    Leaf of 'a
  | Node of 'a bintree & 'a bintree 
].


(* -- Basic properties -- *)
(* 
  Computes height of a binary tree, i.e.,
  the number of levels/edges from the root to the furthest leaf 
*)
op height (bt : 'a bintree) : int =
  with bt = Leaf _ => 0
  with bt = Node l r => 1 + max (height l) (height r).

(* Height of a binary tree is always greater than or equal to 0 *)
lemma ge0_height (bt : 'a bintree):
  0 <= height bt.
proof. by elim: bt => /#. qed.

(* Characterize trees of height 0 *)
lemma height_eq0 ['a] (bt : 'a bintree):
  height bt = 0 => exists x, bt = Leaf x.
proof. by case: bt => /= [x|t1 t2]; [exists x | smt(ge0_height)]. qed.

(* Characterize trees of non-zero height *)
lemma height_gt0 ['a] (bt : 'a bintree):
  0 < height bt => exists t1 t2, bt = Node t1 t2.
proof. by case: bt => [x| t1 t2] => // _; exists t1 t2. qed.

(* 
  Determines whether a binary tree is fully balanced, i.e., 
  whether all leaves are on the same level 
*)
op fully_balanced (bt : 'a bintree) : bool =
  with bt = Leaf _ => true
  with bt = Node l r => height l = height r /\ fully_balanced l /\ fully_balanced r.

(* Characterize balanced trees of non-zero height *)
lemma height_balanced_gt0 ['a] (bt : 'a bintree):
  0 < height bt => fully_balanced bt => exists t1 t2,
       (bt = Node t1 t2)
    /\ (height t1 = height bt - 1)
    /\ (height t2 = height bt - 1)
    /\ fully_balanced t1
    /\ fully_balanced t2.
proof.
by case: bt => //= t1 t2 _ -[eqh [b1 b2]]; exists t1 t2 => //#.
qed.


(* -- Operations -- *)
(* 
  Gets the subtree of which the root is a node located at the end of a path
  represented by a boolean list. Starting from the left of the boolean list,
  each entry indicates whether the left or right subtree of the current binary tree
  is to be considered next. Specifically, a 0 entry indicates that the left-hand side
  subtree is to be considered next, while a 1 entry indicates that the right-hand side
  subtree is to be considered next. When all of the entries have been considered,
  the resulting subtree is returned.
*)
op sub_bt (bt : 'a bintree) (bs : bool list) : 'a bintree option =
  with bt = Leaf _  , bs = []      => Some bt
  with bt = Leaf _  , bs = _ :: _  => None
  with bt = Node _ _, bs = []      => Some bt
  with bt = Node l r, bs = b :: bs' => sub_bt (if b then r else l) bs'.

(* The subtree at the end of an empty path is the currently considered binary tree *)
lemma subbt_empty (bt : 'a bintree) :
  sub_bt bt [] = Some bt.
proof. by case bt. qed.

 
(* 
  Extracts the (hash) value from a leaf; returns None if the given binary tree is not a leaf 
*)
op val_lf (bt : 'a bintree) : 'a option =
  with bt = Leaf x => Some x
  with bt = Node _ _ => None.

(* 
  Extracts the (hash) value from a leaf located at the end of a path 
  represented by a boolean list 
*)
op vallf_subbt (bt : 'a bintree) (bs : bool list) : 'a option =
  obind val_lf (sub_bt bt bs).

lemma vallf_subbt_Leaf ['a] (x : 'a) :
  vallf_subbt (Leaf x) [] = Some x.
proof. by []. qed.

lemma vallf_subbt_Node ['a] (t1 t2 : 'a bintree) b bs:
  vallf_subbt (Node t1 t2) (b :: bs) =
    if b then vallf_subbt t2 bs else vallf_subbt t1 bs.
proof. by case: b. qed.


(* --- List to tree conversion --- *)
(* Conversion operator between lists and binary trees *)
op list2tree_pred ['a] (s : 'a list) (t : 'a bintree) =
   let e = height t in
      size s = 2 ^ e
   /\ fully_balanced t
   /\ (forall idx, 0 <= idx < size s => vallf_subbt t (rev (int2bs e idx)) = onth s idx).

lemma list2tree_spec ['a] (s : 'a list) (e : int) :
  0 <= e => size s = 2 ^ e => exists t, list2tree_pred s t.
proof.
move=> ge0_e; elim: e ge0_e s => /= [|e ge0_e ih] s.
- rewrite expr0 => /size_eq1[x ->>] /=; exists (Leaf x).
  do! split => //=; first by rewrite expr0.
  move=> idx; rewrite ltz1 -StdOrder.IntOrder.eqr_le => <<- /=.
  by rewrite int2bs0 nseq0 rev_nil /= vallf_subbt_Leaf.
move=> sz_s; have /eq_sym := cat_take_drop (2 ^ e) s.
(pose s1 := take _ _; pose s2 := drop _ _) => sE.
have gt: 2 ^ e < 2 ^ (e + 1).
- by rewrite exprS // StdOrder.IntOrder.ltr_pmull // StdOrder.IntOrder.expr_gt0.
have sz_s1: size s1 = 2 ^ e.
- by rewrite /s1 size_take 1:StdOrder.IntOrder.expr_ge0 // sz_s gt.
have sz_s2: size s2 = 2 ^ e.
- rewrite /s2 size_drop 1:StdOrder.IntOrder.expr_ge0 // sz_s.
  rewrite exprS // (_ : 2 * 2^e - 2^e = 2 ^ e) 1:/#.
  by rewrite lez_maxr 1:StdOrder.IntOrder.expr_ge0.
case: (ih s1 sz_s1); last case: (ih s2 sz_s2).
move=> @/list2tree_pred /= t2 [# h2 b2 n2] t1 [# h1 b1 n1].
- move: h1 h2; rewrite !(sz_s1, sz_s2) => h1 h2.
  have inj := StdOrder.IntOrder.ieexprIn 2 _ _ => //.
  have et1 := inj e (height t1) ge0_e _ h1; 1: exact/ge0_height.
  have et2 := inj e (height t2) ge0_e _ h2; 1: exact/ge0_height.
move=> {inj}; exists (Node t1 t2); do! split => //=; 1,2:smt().
move=> idx; rewrite sz_s exprS // => -[ge0_idx lt_idx].
rewrite -et1 -et2 StdOrder.IntOrder.ler_maxr // [1+_]addrC int2bsS // rev_rcons.
pose c := (idx %/ (2 ^ e)).
move: lt_idx; rewrite -ltz_divLR 1:StdOrder.IntOrder.expr_gt0 // -/c => ltc.
have ge0_c: 0 <= c by rewrite divz_ge0 // StdOrder.IntOrder.expr_gt0.
have {ltc ge0_c} cE: (c = 0) \/ (c = 1) by smt().
rewrite vallf_subbt_Node onth_nth_map sE map_cat.
rewrite nth_cat size_map; case: cE => ^ + -> /= - @/c => {c}.
- rewrite -divz_eq0 1:StdOrder.IntOrder.expr_gt0 // => -[_ lt_idx].
  by rewrite et1 n1 sz_s1 lt_idx //= -onth_nth_map.
move=> idxE; rewrite {-1}[idx](divz_eq _ (2 ^ e)) idxE /=.
rewrite sz_s1 StdOrder.IntOrder.ltrNge StdOrder.IntOrder.ler_addl modn_ge0 //= addrAC /=.
rewrite -int2bs_mod et2 n2 -1:onth_nth_map //.
by rewrite modn_ge0 //= sz_s2 -et2 ltz_pmod // StdOrder.IntOrder.expr_gt0.
qed.

op list2tree ['a] (s : 'a list) : 'a bintree =
  if   (exists e, 0 <= e /\ size s = 2 ^ e)
  then choiceb (list2tree_pred s) witness
  else witness.

lemma list2tree_spec_ok ['a] (s : 'a list) (e : int) :
     0 <= e
  => size s = 2 ^ e 
  => list2tree_pred s (list2tree s).
proof.
move=> ge0_e szs; rewrite /list2tree.
pose b := exists e, 0 <= e /\ size s = 2 ^ e.
have ^bT -> /=: b by exists e.
apply: (choicebP (list2tree_pred s) witness _).
by apply: (list2tree_spec s e).
qed.

lemma list2tree_ok ['a] (s : 'a list) (e : int) :
     0 <= e
  => size s = 2 ^ e 
  =>    height (list2tree s) = e
     /\ fully_balanced (list2tree s)
     /\ (forall idx, 0 <= idx < size s => vallf_subbt (list2tree s) (rev (int2bs e idx)) = onth s idx).
proof.
move=> ge0_e szs; have := list2tree_spec_ok _ _ ge0_e szs.
move: (list2tree _) => t @/list2tree_pred /= [# h1 h2 h3].
have htE: height t = e.
- have inj := StdOrder.IntOrder.ieexprIn 2 _ _ => //.
  by move: h1; rewrite szs eq_sym &(inj) // &(ge0_height).
by do! split=> //; rewrite -htE.
qed.

(*
  Constructing a tree from a list (of which the size is a power of 2) through list2tree 
  results in a tree of which the leaf at breadth position i has (hash) value x, 
  where x is the (hash) value in the list at index i.
*)
lemma list2tree_lvb (s : 'a list) (idx : int) (e : int) :
     0 <= e
  => size s = 2 ^ e 
  => 0 <= idx < size s
  => vallf_subbt (list2tree s) (rev (int2bs e idx)) = onth s idx.
proof. smt(list2tree_ok). qed.

(* 
  Constructing a tree from a list (of which the size is a power of 2, say 2 ^ e)
  through list2tree results in a tree with height e.
*)
lemma list2tree_height (s : 'a list) (e : int) :
     0 <= e
  => size s = 2 ^ e
  => height (list2tree s) = e.
proof. smt(list2tree_ok). qed.

(*
  Constructing a tree from a list (of which the size is a power of 2) through list2tree 
  results in a fully balanced tree
*)
lemma list2tree_fullybalanced (s : 'a list) (e : int) :
     0 <= e
  => size s = 2 ^ e
  => fully_balanced (list2tree s).
proof. smt(list2tree_ok). qed.

(* 
  Constructing a tree from a list that holds a single entry gives 
  a Leaf that holds the value of that entry
*)
lemma list2tree1 (x : 'a) :
  list2tree [x] = Leaf x.
proof.
move: (list2tree_lvb [x] 0 0 _) => //.
rewrite expr0 /= int2bs0s rev_nil.
by case: (list2tree [x]).
qed.

lemma list2tree_uniq2 ['a] (e : int) (s : 'a list) (t1 t2 : 'a bintree) :
     0 <= e
  => size s = 2 ^ e
  => list2tree_pred s t1
  => list2tree_pred s t2
  => t1 = t2.
proof.
move=> ge0_e szs @/list2tree_pred /= [# h1 f1 n1] [# h2 f2 n2].
have inj := StdOrder.IntOrder.ieexprIn 2 _ _ => //.
have hg1E: height t1 = e.
- by apply/eq_sym/inj => //; [apply: ge0_height | rewrite -szs].
have hg2E: height t2 = e.
- by apply/eq_sym/inj => //; [apply: ge0_height | rewrite -szs].
move=> {h1 h2}; elim: e ge0_e s szs t1 f1 n1 hg1E t2 f2 n2 hg2E.
- move=> s; rewrite expr0 => /size_eq1[x] ->> t1 _ n1 h1 t2 _ n2 h2.
  case/height_eq0: h1=> x1 ->>; case/height_eq0: h2=> x2 ->>.
  (have := n1 0 _) => //=; (have := n2 0 _) => //=.
  by rewrite int2bs0 nseq0 rev_nil !vallf_subbt_Leaf.
move=> e ge0_e ih s szs t1 b1 n1 h1 t2 b2 n2 h2.
have := height_balanced_gt0 t1 _ b1; first by smt().
case=> [tl1 tr1] [# ->> hl1 hr1 bl1 br1].
have := height_balanced_gt0 t2 _ b2; first by smt().
case=> [tl2 tr2] [# ->> hl2 hr2 bl2 br2].
pose s1 := take (2 ^ e) s; pose s2 := drop (2 ^ e) s.
have sz_s1: size s1 = 2 ^ e.
- rewrite /s1 size_take 1:StdOrder.IntOrder.expr_ge0 // szs.
  by rewrite exprS // StdOrder.IntOrder.ltr_pmull // StdOrder.IntOrder.expr_gt0.
have sz_s2: size s2 = 2 ^ e.
- rewrite /s1 size_drop 1:StdOrder.IntOrder.expr_ge0 // szs exprS //.
  rewrite (_ : 2 * 2 ^ e - 2 ^ e = 2 ^ e) 1:/#.
  by rewrite lez_maxr // StdOrder.IntOrder.expr_ge0.
rewrite h1 /= in hl1; rewrite h1 /= in hr1.
rewrite h2 /= in hl2; rewrite h2 /= in hr2.
congr; [apply (ih s1) | apply (ih s2)] => {ih} //.
- move=> idx [ge0_idx lt_idx]; have := n1 idx _.
  - by rewrite szs exprS // -sz_s1; smt(size_ge0).
  rewrite h1 int2bsS // rev_rcons vallf_subbt_Node.
  rewrite pdiv_small 1:-sz_s1 //= hl1.
  rewrite -[s](cat_take_drop (2 ^ e)) -/s1 -/s2.
  by rewrite !onth_nth_map map_cat nth_cat size_map lt_idx.
- move=> idx [ge0_idx lt_idx]; have := n2 idx _.
  - by rewrite szs exprS // -sz_s1; smt(size_ge0).
  rewrite h2 int2bsS // rev_rcons vallf_subbt_Node.
  rewrite pdiv_small 1:-sz_s1 //= hl2.
  rewrite -[s](cat_take_drop (2 ^ e)) -/s1 -/s2.
  by rewrite !onth_nth_map map_cat nth_cat size_map lt_idx.
- move=> idx [ge0_idx lt_idx]; have := n1 (size s1 + idx) _.
  - by rewrite szs exprS // -sz_s1; smt(size_ge0).
  rewrite h1 int2bsS // rev_rcons vallf_subbt_Node.
  rewrite sz_s1 (divzMDl 1 _ (2 ^ e)).
  - by rewrite StdOrder.IntOrder.gtr_eqF // StdOrder.IntOrder.expr_gt0.
  rewrite pdiv_small 1:-sz_s2 //= hr1.
  rewrite -{1}int2bs_mod modzDl pmod_small 1:-sz_s2 //.
  rewrite -[s](cat_take_drop (2 ^ e)) -/s1 -/s2.
  rewrite !onth_nth_map map_cat nth_cat size_map.
  by rewrite StdOrder.IntOrder.ltrNge sz_s1 StdOrder.IntOrder.ler_addl ge0_idx /= addrAC.
- move=> idx [ge0_idx lt_idx]; have := n2 (size s1 + idx) _.
  - by rewrite szs exprS // -sz_s2; smt(size_ge0).
  rewrite h2 int2bsS // rev_rcons vallf_subbt_Node.
  rewrite sz_s1 (divzMDl 1 _ (2 ^ e)).
  - by rewrite StdOrder.IntOrder.gtr_eqF // StdOrder.IntOrder.expr_gt0.
  rewrite pdiv_small 1:-sz_s2 //= hr2.
  rewrite -{1}int2bs_mod modzDl pmod_small 1:-sz_s2 //.
  rewrite -[s](cat_take_drop (2 ^ e)) -/s1 -/s2.
  rewrite !onth_nth_map map_cat nth_cat size_map.
  by rewrite StdOrder.IntOrder.ltrNge sz_s1 StdOrder.IntOrder.ler_addl ge0_idx /= addrAC.
qed.

lemma list2tree_uniq ['a] (e : int) (s : 'a list) (t : 'a bintree) :
     0 <= e
  => size s = 2 ^ e
  => list2tree_pred s t
  => list2tree s = t.
proof.
move=> ge0_e szs h; apply: (list2tree_uniq2 e s) => //.
by apply: (list2tree_spec_ok _ e).
qed.

lemma list2tree_pred0 ['a] (x : 'a) :
  list2tree_pred [x] (Leaf x).
proof.
do! split => //=; first by rewrite expr0.
move=> idx; rewrite ltz1 -StdOrder.IntOrder.eqr_le => <<-.
by rewrite int2bs0 nseq0 rev_nil /= vallf_subbt_Leaf.
qed.

lemma list2tree0 ['a] (x : 'a) : list2tree [x] = Leaf x.
proof.
apply: (list2tree_uniq 0) => //=.
- by rewrite expr0. 
- by apply: list2tree_pred0.
qed.

lemma list2tree_predS ['a] (s1 s2 : 'a list) (t1 t2 : 'a bintree) :
     list2tree_pred s1 t1
  => list2tree_pred s2 t2
  => height t1 = height t2
  => list2tree_pred (s1 ++ s2) (Node t1 t2).
proof.
move=> + + eq_h - @/list2tree_pred /=; rewrite -eq_h.
move: (height t1) (ge0_height t1) => e ge0_e {eq_h}.
move=> [# h1 b1 n1] [# h2 b2 n2].
rewrite lez_maxr //; do! split => //.
- by rewrite size_cat [1 + _]addrC exprS //#.
move=> idx; rewrite size_cat => -[ge0_idx lt_idx].
rewrite [1+_]addrC int2bsS // rev_rcons.
have := divz_eq idx (2 ^ e); pose c := _ %/ _.
have lt2_c: c < 2 by rewrite /c ltz_divLR 1:StdOrder.IntOrder.expr_gt0 //#.
have ge0_c: 0 <= c by rewrite divz_ge0 // StdOrder.IntOrder.expr_gt0.
have {ge0_c lt2_c} eq_c: (c = 0) \/ (c = 1) by smt().
move=> -> {lt_idx}; rewrite vallf_subbt_Node.
rewrite onth_nth_map map_cat nth_cat -!onth_nth_map size_map.
case: eq_c => -> /=; rewrite !(h1, h2).
- rewrite ltz_pmod 1:StdOrder.IntOrder.expr_gt0 //= &(n1) h1.
  by rewrite modn_ge0 //= ltz_pmod // StdOrder.IntOrder.expr_gt0.
- rewrite -int2bs_mod modzDl modz_mod ltzNge lez_addl.
  rewrite modn_ge0 //= addrAC /= &(n2).
  by rewrite modn_ge0 //= h2 ltz_pmod // StdOrder.IntOrder.expr_gt0.
qed.

lemma list2treeS ['a] (e : int) (s1 s2 : 'a list) :
     0 <= e
  => size s1 = 2 ^ e
  => size s2 = 2 ^ e
  => list2tree (s1 ++ s2) = Node (list2tree s1) (list2tree s2).
proof.
move=> ge0_e sz1 sz2; apply: (list2tree_uniq (e + 1)).
- smt(). 
- by rewrite size_cat exprS //#.
apply: list2tree_predS => //; 1,2: by apply: (list2tree_spec_ok _ e).
by rewrite !(list2tree_height _ e).
qed.

lemma subbt_list2tree_cons (ls : 'a list) (b : bool) (bs : bool list) (e : int) :
     0 <= e
  => size ls = 2 ^ e
  => size bs < e
  => sub_bt (list2tree ls) (b :: bs)
     =
     if b
     then
       sub_bt (list2tree (drop (size ls %/ 2) ls)) bs
     else
       sub_bt (list2tree (take (size ls %/ 2) ls)) bs.
proof.
move=> ge0_e; elim: e ge0_e b bs => [|e ge0_e ih] b bs.
- by rewrite ltzNge size_ge0.
move=> ^szls -> szbs; rewrite exprS // mulKz //.
rewrite -{1}(cat_take_drop (2 ^ e)).
pose s2 := drop _ _; pose s1 := take _ _.
have sz_s1: size s1 = 2 ^ e.
- rewrite /s1 size_take 1:StdOrder.IntOrder.expr_ge0 // szls.
  by rewrite exprS // StdOrder.IntOrder.ltr_pmull // StdOrder.IntOrder.expr_gt0.
have sz_s2: size s2 = 2 ^ e.
- rewrite /s1 size_drop 1:StdOrder.IntOrder.expr_ge0 // szls exprS //.
  rewrite (_ : 2 * 2 ^ e - 2 ^ e = 2 ^ e) 1:/#.
  by rewrite lez_maxr // StdOrder.IntOrder.expr_ge0.
by rewrite (list2treeS e) //= fun_if2.
qed.


lemma subbt_list2tree_takedrop (ls : 'a list) (e i j : int) :
      0 <= i <= e
   => 0 <= j < 2 ^ (e - i)
   => size ls = 2 ^ e
   => sub_bt (list2tree ls) (rev (int2bs (e - i) j))
      = 
      Some (list2tree (take (2 ^ i) (drop (j * (2 ^ i)) ls))).
proof.
move=> [ge0_i lee_i] []; have ge0_e: 0 <= e by smt().
elim: e ge0_e ls i j ge0_i lee_i => /= [ls i j ? ? ? |]. 
+ rewrite (: i = 0) 1:/# /= expr0 size_eq1 => lt1_j -[x ->].
  by rewrite (: j = 0) 1:/# /= int2bs0s rev_nil list2tree0.
move=> e ge0_e ih ls i j ge0_i lte1_i.
case (i = e + 1) => [->  /= |].
+ rewrite expr0 int2bs0s rev_nil /= => ? ? <-.
  by rewrite (: j = 0) 1:/# /= drop0 take_size subbt_empty.
move=> neqe1_i ge0_j; rewrite -addrA (addrC 1) addrA => lt2ei1_j szls.
rewrite int2bsS 1:/# rev_rcons.
rewrite (subbt_list2tree_cons _ _ _ (e + 1)) 1:/# 1:// 1:size_rev 1:size_int2bs 1:/#. 
have szlsd2: size ls %/ 2 = 2 ^ e by rewrite -{1}(expr1 2) szls expz_div 1:/#.
case (j %/ 2 ^ (e - i) %% 2 <> 0) => /= [msb1 | msb0].
+ rewrite -int2bs_mod ih 1:// 1:/# 1:modz_ge0 2:ltz_pmod; 1,2: smt(StdOrder.IntOrder.expr_gt0). 
  - rewrite size_drop 1:divz_ge0 1:// 1:szls 1:StdOrder.IntOrder.expr_ge0 1://.
    rewrite szlsd2 szls exprD_nneg 1,2:// expr1; smt(StdOrder.IntOrder.expr_ge0).
  rewrite drop_drop 1:StdOrder.IntOrder.mulr_ge0 1:modz_ge0 2:StdOrder.IntOrder.expr_ge0 3:divz_ge0 2..4://; 1: smt(StdOrder.IntOrder.expr_gt0).
  do 3! congr; rewrite szlsd2. 
  rewrite {2}(divz_eq j (2 ^ (e - i))) mulrDl /= addrC; congr. 
  suff: j %/ 2 ^ (e - i) = 1 by move=> -> /=; rewrite -exprD_nneg 1:/# 1:// /#. 
  by rewrite exprS in lt2ei1_j; smt(edivzP).
have lt2e1_j : j < 2 ^ (e - i) by rewrite exprS in lt2ei1_j; smt(edivzP).
have ltszlsd2 : size ls %/ 2 < size ls.
+ rewrite szlsd2 szls exprD_nneg 1,2://.
  by rewrite StdOrder.IntOrder.ltr_pmulr 1:StdOrder.IntOrder.expr_gt0 1:// expr1.
rewrite ih 1:// 1:/# 1,2:// 1:size_take 1:divz_ge0 1:// 1:size_ge0 1:ltszlsd2 1://.
rewrite -{3}(cat_take_drop (size ls %/ 2) ls) drop_cat 1:size_take 1:divz_ge0 1:// 1:size_ge0.
rewrite ltszlsd2 /= szlsd2 (: j * 2 ^ i < 2 ^ e) 2:/=.
+ rewrite (: 2 ^ e = 2 ^ (e - i) * 2 ^ i) 1:-exprD_nneg 1:/# 1:// 1:/#.
  by rewrite StdOrder.IntOrder.ltr_pmul2r 1:StdOrder.IntOrder.expr_gt0.
rewrite take_cat 1:size_drop 1:StdOrder.IntOrder.mulr_ge0 2:StdOrder.IntOrder.expr_ge0 1,2://.
have le2ei_j2i: j * 2 ^ i <= 2 ^ e - 2 ^ i.
+ rewrite StdOrder.IntOrder.ler_subr_addr -{2}(mul1r (2 ^ i)) -mulrDl.
  by rewrite -lez_divRL 1:StdOrder.IntOrder.expr_gt0 // expz_div 2:// /#.
rewrite lez_maxr 1:size_take 1:StdOrder.IntOrder.expr_ge0 1:// 1:/#.
rewrite size_take 1:StdOrder.IntOrder.expr_ge0 1:// -szlsd2 ltszlsd2 /= szlsd2.
case (2 ^ i < 2 ^ e - j * 2 ^ i) => [// | /lezNgt ge2ej2i_2i].
rewrite (: 2 ^ e - j * 2 ^ i = 2 ^ i) 1:/# /= take0 cats0.
pose dr := drop _ _; rewrite (: 2 ^ i = size dr) 2:take_size 2://.
by rewrite size_drop 1:/# size_take 1:StdOrder.IntOrder.expr_ge0 1:// /#.
qed.

lemma subbt_list2tree_idx_leaf (x0 : 'a) (ls : 'a list) (idx e : int) :
     0 <= e
  => size ls = 2 ^ e
  => 0 <= idx < size ls
  => sub_bt (list2tree ls) (rev (int2bs e idx)) = Some (Leaf (nth x0 ls idx)).
proof.
move=> ge0_e; elim: e ge0_e ls idx.
+ rewrite expr0 => ls idx ^ /size_eq1 [x ->] sz1 rng_idx.
  by rewrite (: idx = 0) 1:/# int2bs0s rev_nil subbt_empty list2tree1.
move=> e ge0_e ih ls idx szls rng_idx.
rewrite int2bsS 1:// rev_rcons.
rewrite (subbt_list2tree_cons _ _ _ (e + 1)) 1:/# 1:szls // 1:size_rev 1:size_int2bs 1:/#.
have szlsd2: size ls %/ 2 = 2 ^ e by rewrite -{1}(expr1 2) szls expz_div 1:/#.
have ge0_szld2: 0 <= size ls %/ 2 by rewrite szlsd2 StdOrder.IntOrder.expr_ge0.
have szmsz2_2e : size ls - size ls %/ 2 = 2 ^ e.
+ rewrite szlsd2 szls exprD_nneg 1,2:// expr1 1:/#.
have ltszls_szlsd2: size ls %/ 2 < size ls by smt(StdOrder.IntOrder.expr_gt0).
case (idx %/ 2 ^ e %% 2 <> 0) => [msb1 | /= msb0].
+ rewrite -{1}int2bs_mod ih 1,2:size_drop 1,3:// 1,2:szmsz2_2e 1,2:lez_maxr 2:// 1,2:StdOrder.IntOrder.expr_ge0 1,2://. 
  - by rewrite modz_ge0 2:ltz_pmod; 1,2: smt(StdOrder.IntOrder.expr_gt0).
  rewrite modzE nth_drop 1:// 1:StdOrder.IntOrder.subr_ge0 1:lez_floor; 1: smt(StdOrder.IntOrder.expr_gt0).
  do 3! congr; rewrite szlsd2 eq_sym {1 2}(divz_eq idx (2 ^ e)).
  rewrite (: idx %/ 2 ^ e = 1) 2:/#; 1: by rewrite exprS in szls => //; smt(edivzP).
have ltszlsd2_idx : idx < size ls %/ 2 by rewrite exprS in szls => //; smt(edivzP).
by rewrite ih 1,2:size_take 1,3:// 1,2:ltszls_szlsd2 1:// 1:/= 1:/# nth_take.
qed.
