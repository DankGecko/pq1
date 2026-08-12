require import AllCore List FMap SPHINCS_PLUS.
lemma conjtest2 (ps2 : pseed) (skFORSnt2 : FTWES.skFORS list list) (skFORSlp2 : FTWES.skFORS list) (psad : pseed * adrs) (j u v : int) :
  size skFORSlp2 = l' =>
  0 <= j < size skFORSlp2 /\ 0 <= u < k /\ 0 <= v < t /\
    psad = (ps2, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size skFORSnt2)) j) 0 (u * t + v)) =>
  0 <= size skFORSnt2 < size skFORSnt2 + 1 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\
    psad = (ps2, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size skFORSnt2)) j) 0 (u * t + v)).
proof. by smt(). qed.
