require import AllCore List FMap SPHINCS_PLUS.

lemma foldtest (ps2 : pseed) (skFORSnt2 : FTWES.skFORS list list) (skFORSlp2 : FTWES.skFORS list) (m2 : (pseed * adrs, dgstblock) fmap) :
  size skFORSlp2 = l' =>
  (forall (psad : pseed * adrs),
     psad \in m2 <=>
     ((exists (i j u v : int), 0 <= i < size skFORSnt2 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\
        psad = (ps2, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))
      \/ (exists (j u v : int), 0 <= j < size skFORSlp2 /\ 0 <= u < k /\ 0 <= v < t /\
        psad = (ps2, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size skFORSnt2)) j) 0 (u * t + v))))) =>
  (forall (psad : pseed * adrs),
     psad \in m2 <=>
     (exists (i j u v : int), 0 <= i < size skFORSnt2 + 1 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\
        psad = (ps2, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))).
proof.
move=> hsz hmdom psad.
split => [hin | hin2].
+ have hiff := hmdom psad.
  move: hin; rewrite hiff.
  case.
  - move=> -[i j u v hp1].
    exists i; exists j; exists u; exists v. by (clear hiff hmdom; smt()).
  - move=> -[j u v hp2].
    exists (size skFORSnt2); exists j; exists u; exists v.
    split; 1: smt().
    split; 1: smt().
    split; 1: smt().
    split; 1: smt().
    smt().
+ have hiff := hmdom psad.
  rewrite -hiff.
  move: hin2.
  case.
  - move=> -[i j u v hp].
    case (i < size skFORSnt2) => [lti | nlti].
    * left. exists i; exists j; exists u; exists v. by (clear hiff hmdom; smt()).
    * right. exists j, u, v.
      have -> : i = size skFORSnt2 by smt().
      smt().
  - move=> -[j u v hp2].
    right. exists j; exists u; exists v. by (clear hiff hmdom; smt()).
qed.
