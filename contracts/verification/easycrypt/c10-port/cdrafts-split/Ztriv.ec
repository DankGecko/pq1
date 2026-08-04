require import AllCore List SPHINCS_PLUS.
lemma triv (skFORSnt2 : FTWES.skFORS list list) : 0 <= size skFORSnt2 < size skFORSnt2 + 1.
proof. by smt(). qed.
lemma triv2 (j : int) (skFORSlp2 : FTWES.skFORS list) :
  size skFORSlp2 = l' => 0 <= j < size skFORSlp2 => 0 <= j < l'.
proof. by smt(). qed.
