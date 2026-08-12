require import AllCore List BinaryTrees BitEncoding.
(*---*) import BS2Int.

op val_bt (trh : 'b -> 'a -> 'a -> 'a)
          (updct : 'b -> bool -> 'b)
          (bt : 'a bintree)
          (ct : 'b) : 'a =
  with bt = Leaf x => x
  with bt = Node l r =>
    trh ct (val_bt trh updct l (updct ct false)) (val_bt trh updct r (updct ct true)).
  
op cons_ap (trh : 'b -> 'a -> 'a -> 'a)
           (updct : 'b -> bool -> 'b)
           (bt : 'a bintree) 
           (bs : bool list) 
           (ct : 'b) : 'a list =
  with bt = Leaf _, bs = [] => []
  with bt = Leaf _, bs = _ :: _ => witness
  with bt = Node _ _, bs = [] => witness
  with bt = Node l r, bs = b :: bs' =>
    (val_bt trh updct (if !b then r else l) (updct ct (!b))) 
     :: cons_ap trh updct (if b then r else l) bs' (updct ct b). 

op val_ap (trh : 'b -> 'a -> 'a -> 'a)
          (updct : 'b -> bool -> 'b)
          (ap : 'a list) 
          (bs : bool list)
          (leaf : 'a) 
          (ct : 'b) : 'a = 
  with ap = [], bs = [] => leaf
  with ap = [], bs = _ :: _ => witness 
  with ap = _ :: _, bs = [] => witness
  with ap = x :: ap', bs = b :: bs' =>
    trh ct 
        (if b then x else val_ap trh updct ap' bs' leaf (updct ct false))
        (if b then val_ap trh updct ap' bs' leaf (updct ct true) else x).

lemma size_consap (trh : 'b -> 'a -> 'a -> 'a)
                  (updct : 'b -> bool -> 'b)
                  (bt : 'a bintree) 
                  (bs : bool list) 
                  (ct : 'b) :
     fully_balanced bt
  => height bt = size bs
  => size (cons_ap trh updct bt bs ct) = size bs.
proof.
elim: bs bt ct; 1: by move => bt ? /= _ /height_eq0 [x ->].  
by move=> b bs' ih [? /= | l r ct /= [eqh [fbl fbr]] eqhsz]; smt(size_ge0).
qed.
                  
lemma nth_consap (trh : 'b -> 'a -> 'a -> 'a)
                 (updct : 'b -> bool -> 'b)
                 (bt : 'a bintree) 
                 (bs : bool list) 
                 (ct : 'b)
                 (i : int) :
     fully_balanced bt
  => height bt = size bs
  => 0 <= i < size bs
  => nth witness (cons_ap trh updct bt bs ct) i
     =
     val_bt trh updct (oget (sub_bt bt (rcons (take i bs) (! (nth witness bs i)))))
                  (foldl updct ct (rcons (take i bs) (! (nth witness bs i)))).
proof.
elim: bs bt ct i => [/= /# | b bs' ih [? ? ? /= | l r ct i /=]]; 1: smt(size_ge0).
move=> [eqh [fbl fbr] eqhsz rngi].
case (i = 0) => [-> | neq0i] /=; 1: by rewrite subbt_empty.
rewrite (: ! i <= 0) 1:/# /= ih // /#.
qed.
        
lemma eq_valbt_valap (trh : 'b -> 'a -> 'a -> 'a)
                     (updct : 'b -> bool -> 'b)
                     (bt : 'a bintree)
                     (ap : 'a list)
                     (bs : bool list)
                     (leaf : 'a)
                     (ct : 'b) :
     fully_balanced bt
  => height bt = size ap
  => size ap = size bs
  => Some leaf = vallf_subbt bt bs
  => (forall (i : int), 0 <= i < size ap =>
        nth witness ap i 
        = 
        val_bt trh updct (oget (sub_bt bt (rcons (take i bs) (! (nth witness bs i)))))
                  (foldl updct ct (rcons (take i bs) (! (nth witness bs i)))))
  => val_bt trh updct bt ct = val_ap trh updct ap bs leaf ct.
proof.
elim: ap bs bt ct => /=.
+ move=> bs bt ct ? /height_eq0 [x ->] /eq_sym /size_eq0 -> /= + _.
  by rewrite vallf_subbt_Leaf eq_sym &(someI).
move=> x ap' ih [? ? ? ? /= | b bs' [? ? ? /= | l r ct /= [eqh [fbl fbr]]]]; 1,2: smt(size_ge0).
move=> eqhszap eqszs; rewrite vallf_subbt_Node.
case b => [bT | bF] eqlf eqnthi.
+ move: (eqnthi 0 _) => /=; 1: smt(size_ge0).
  rewrite subbt_empty oget_some => ->. 
  rewrite (ih bs' r (updct ct true)) 1:fbr 1,2:/# 1:eqlf 1,3:// => i rngi.
  move: (eqnthi (i + 1) _); 1: smt().
  by rewrite (: ! i + 1 = 0) 2:(: ! i + 1 <= 0) 1,2:/#.
move: (eqnthi 0 _) => /=; 1: smt(size_ge0).
rewrite subbt_empty oget_some => ->. 
rewrite (ih bs' l (updct ct false)) 1:fbl 1,2:/# 1:eqlf 1,3:// => i rngi.
move: (eqnthi (i + 1) _); 1: smt().
by rewrite (: ! i + 1 = 0) 2:(: ! i + 1 <= 0) 1,2:/#.
qed.

op extract_collision_bt_ap (trh : 'b -> 'a -> 'a -> 'a) 
                           (updct : 'b -> bool -> 'b)
                           (bt : 'a bintree)
                           (ap : 'a list) 
                           (bs : bool list)
                           (leaf : 'a) 
                           (ct : 'b) : 'a * 'a * 'a * 'a * 'b * 'a bintree * 'a bintree * bool list =
  with bt = Leaf _, ap = [], bs = [] => witness
  with bt = Leaf _, ap = [], bs = b :: bs' => witness
  with bt = Leaf _, ap = x :: ap', bs = [] => witness
  with bt = Leaf _, ap = x :: ap', bs = b :: bs' => witness
  with bt = Node _ _, ap = [], bs = [] => witness
  with bt = Node _ _, ap = [], bs = b :: bs' => witness
  with bt = Node _ _, ap = x :: ap', bs = [] => witness
  with bt = Node l r, ap = x :: ap', bs = b :: bs' =>
    if b
    then
      if    (val_bt trh updct l (updct ct false), val_bt trh updct r (updct ct true)) 
            <> 
            (x, val_ap trh updct ap' bs' leaf (updct ct true))
         /\ val_bt trh updct bt ct = val_ap trh updct ap bs leaf ct
      then (val_bt trh updct l (updct ct false), 
            val_bt trh updct r (updct ct true), 
            x, 
            val_ap trh updct ap' bs' leaf (updct ct true), 
            ct,
            l,
            r,
            bs')
      else extract_collision_bt_ap trh updct r ap' bs' leaf (updct ct true)
    else
      if    (val_bt trh updct l (updct ct false), val_bt trh updct r (updct ct true)) 
            <> 
            (val_ap trh updct ap' bs' leaf (updct ct false), x)
         /\ val_bt trh updct bt ct = val_ap trh updct ap bs leaf ct
      then (val_bt trh updct l (updct ct false), 
            val_bt trh updct r (updct ct true), 
            val_ap trh updct ap' bs' leaf (updct ct false),
            x,  
            ct,
            l,
            r,
            bs')
      else extract_collision_bt_ap trh updct l ap' bs' leaf (updct ct false).

lemma ecbtapP (trh : 'b -> 'a -> 'a -> 'a) 
              (updct : 'b -> bool -> 'b)
              (bt : 'a bintree)
              (ap : 'a list) 
              (bs : bool list)
              (leaf leaf' : 'a) 
              (ct : 'b) :
     fully_balanced bt
  => size ap = size bs
  => height bt = size ap
  => leaf <> leaf'
  => val_bt trh updct bt ct = val_ap trh updct ap bs leaf ct
  => vallf_subbt bt bs = Some leaf'
  => let (x1, x1', x2, x2', ct', l, r, _) = extract_collision_bt_ap trh updct bt ap bs leaf ct in
        (x1, x1') <> (x2, x2') /\ trh ct' x1 x1' = trh ct' x2 x2'.
proof.
move=> + + + neq_lf.
elim: ap bs bt ct => [bs bt ct fb_bt | x ap ih].
+ rewrite eq_sym size_eq0 => -> /=.
  by case: bt fb_bt => /= /#.
case=> [| b bs]; 1: smt(size_ge0).
by case=> /#.
qed.

lemma ecbtabp_props (trh : 'b -> 'a -> 'a -> 'a)
                    (updct : 'b -> bool -> 'b)
                    (bt : 'a bintree)
                    (ap : 'a list) 
                    (bs : bool list)
                    (leaf leaf' : 'a) 
                    (ct : 'b) :
     fully_balanced bt
  => size ap = size bs
  => height bt = size ap
  => leaf <> leaf'
  => val_bt trh updct bt ct = val_ap trh updct ap bs leaf ct
  => vallf_subbt bt bs = Some leaf'
  => let (x1, x1', x2, x2', ct', l, r, bs') = extract_collision_bt_ap trh updct bt ap bs leaf ct in
          height l = height r
       /\ height l = size bs'
       /\ height l < height bt
       /\ size bs' < size bs.
proof.
move=> + + + neq_lf.
elim: ap bs bt ct => [bs bt ct fb_bt | x ap ih].
+ by rewrite eq_sym size_eq0 => -> /#.
by case=> [| b bs]; [smt(size_ge0) | case=> /#].
qed.

(*
Can be used instead of @List in the smt calls below       
lemma drop_size_le (s : 'a list) (n : int) : 
  size (drop n s) <= size s. 
proof. 
case (n <= 0) => [? | /ltzNge gt0_n]; 1: by rewrite drop_le0.
by rewrite size_drop 1:/#; smt(size_ge0). 
qed.
*)

(* (oget (sub_bt bt (rcons (take (height bt - i) bs) true))) (i - 1) (2 * j + 1) *)
lemma ecbtap_vals (trh : 'b -> 'a -> 'a -> 'a)
                  (updct : 'b -> bool -> 'b)
                  (bt : 'a bintree)
                  (ap : 'a list) 
                  (bs : bool list)
                  (leaf leaf' : 'a) 
                  (ct : 'b) :
     fully_balanced bt
  => size ap = size bs
  => height bt = size ap
  => leaf <> leaf'
  => val_bt trh updct bt ct = val_ap trh updct ap bs leaf ct
  => vallf_subbt bt bs = Some leaf'
  => let (x1, x1', x2, x2', ct', l, r, bs') = extract_collision_bt_ap trh updct bt ap bs leaf ct in
          x1 = val_bt trh updct l (updct ct' false)
       /\ x1' = val_bt trh updct r (updct ct' true)
       /\ x2 = (if nth witness bs (size bs - size bs' - 1) 
                then nth witness ap (size bs - size bs' - 1) 
                else val_ap trh updct (drop (size bs - size bs') ap) (drop (size bs - size bs') bs) leaf (updct ct' false))
       /\ x2' = (if nth witness bs (size bs - size bs' - 1) 
                 then val_ap trh updct (drop (size bs - size bs') ap) (drop (size bs - size bs') bs) leaf (updct ct' true)
                 else nth witness ap (size bs - size bs' - 1))
       /\ ct' = foldl updct ct (take (size bs - size bs' - 1) bs)
       /\ l = oget (sub_bt bt (rcons (take (size bs - size bs' - 1) bs) false))
       /\ r = oget (sub_bt bt (rcons (take (size bs - size bs' - 1) bs) true))
       /\ bs' = drop (size bs - size bs') bs.
proof.
move=> + + + neq_lf.
elim: ap bs bt ct => [bs bt ct fb_bt | x ap ih].
+ rewrite eq_sym size_eq0 => -> /=.
  by case: bt fb_bt => /= /#.
case=> [| b bs]; 1: smt(size_ge0).
case=> [/# | l r ct /= [#]].
move=> eqhei fb_l fb_r eqsz eqhesz.
pose val_l := val_bt trh _ l _.
pose val_r := val_bt trh _ r _.
pose val_ap_l := val_ap _ _ _ _ _ (updct ct false).
pose val_ap_r := val_ap _ _ _ _ _ (updct ct true).
elim: b => /= eqtrh /= eqlfp; rewrite eqtrh.
+ case (val_l = x /\ val_r = val_ap_r) => /= eqvalxap />.
  - move=> x1 x1' x2 x2' ct' bt1 bt2 bs' ecoll.
    move: (ecbtabp_props trh updct r ap bs leaf leaf' (updct ct true)).
    move=> /(_ fb_r _ _ neq_lf _ _); 1..4: smt().
    rewrite ecoll; move=> [#] eqhe lthe ltsz.
    move: (ih bs r (updct ct true) fb_r _ _ _ _) => /=; 1..4: smt().
    rewrite ecoll => [#] -> -> -> -> -> -> -> eqbs' /=.
    rewrite eqbs' size_drop; 1: smt(@List). 
    rewrite (: size bs - (size bs - size bs') = size bs') 1:/#.
    rewrite (: max 0 (size bs') = size bs'); 1: smt(size_ge0).
    rewrite (: ! (1 + size bs - size bs' <= 0)) /=; 1: smt(@List).
    rewrite (: ! (1 + size bs - size bs' - 1 <= 0)) /= 1:/#.
    rewrite (: 1 + size bs - size bs' - 1 <> 0) /= 1:/#.
    rewrite (: 1 + size bs - size bs' - 2 = size bs - size bs' - 1) 1:/#.
    by rewrite (: 1 + size bs - size bs' - 1 = size bs - size bs') 1:/#.
  rewrite (: ! (1 + size bs - size bs <= 0)) 1:/# /=.
  rewrite (: 1 + size bs - size bs - 1 = 0) 1:/# /=.
  by rewrite ?take0 ?drop0 /= 2!subbt_empty 2!oget_some.
case (val_l = val_ap_l /\ val_r = x) => /= eqvalxap />.
- move=> x1 x1' x2 x2' ct' bt1 bt2 bs' ecoll.
  move: (ecbtabp_props trh updct l ap bs leaf leaf' (updct ct false)).
  move=> /(_ fb_l _ _ neq_lf _ _); 1..4: smt().
  rewrite ecoll; move=> [#] eqhe lthe ltsz.
  move: (ih bs l (updct ct false) fb_l _ _ _ _) => /=; 1..4: smt().
  rewrite ecoll => [#] -> -> -> -> -> -> -> eqbs' /=.
  rewrite eqbs' size_drop; 1: smt(@List). 
  rewrite (: size bs - (size bs - size bs') = size bs') 1:/#.
  rewrite (: max 0 (size bs') = size bs'); 1: smt(size_ge0).
  rewrite (: ! (1 + size bs - size bs' <= 0)) /=; 1: smt(@List).
  rewrite (: ! (1 + size bs - size bs' - 1 <= 0)) /= 1:/#.
  rewrite (: 1 + size bs - size bs' - 1 <> 0) /= 1:/#.
  rewrite (: 1 + size bs - size bs' - 2 = size bs - size bs' - 1) 1:/#.
  by rewrite (: 1 + size bs - size bs' - 1 = size bs - size bs') 1:/#.
rewrite (: ! (1 + size bs - size bs <= 0)) 1:/# /=.
rewrite (: 1 + size bs - size bs - 1 = 0) 1:/# /=.
by rewrite ?take0 ?drop0 /= 2!subbt_empty 2!oget_some.
qed.
