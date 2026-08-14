require import AllCore List StdBigop.
require import VecDP CountDS.

op fsS : int list = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0].
op fuS : int list = [0; 0; 0; 0; 0].
lemma size_fsS : size fsS = 12. proof. by []. qed.
lemma size_fuS : size fuS = 5.  proof. by []. qed.

lemma kernelS : nth 0 (runs 8 fuS (vinit fsS)) 0 = 1470.
proof. by []. qed.

lemma countS : count_ds 5 8 12 = 1470.
proof.
have ge0_8 : 0 <= 8.
+ by [].
by rewrite -size_fuS -size_fsS (count_ds_kernel 8 fuS fsS ge0_8) kernelS.
qed.
