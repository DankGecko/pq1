require import AllCore List IntDiv Ring StdOrder StdBigop.
require import VecDP CountDS.

op fs204 : int list = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0].
op fu43  : int list = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0].
lemma size_fs204 : size fs204 = 204. proof. by []. qed.
lemma size_fu43  : size fu43  = 43.  proof. by []. qed.

(* TRUE, computed by reduction: at target sum 204 the count is a DIFFERENT
   number.  Proving it here is what makes the control below fail CLEANLY
   (literal vs literal) rather than by resource exhaustion. *)
lemma kernel204 : nth 0 (runs 8 fu43 (vinit fs204)) 0 = 28514064623780545018184935565382140.
proof. by []. qed.

(* MUST-FAIL NEGATIVE CONTROL -- target sum perturbed 205 -> 204, value left
   at the 205 constant.  A green compile here would mean `c10_surface_count`
   is not actually sensitive to the target sum. *)
lemma ctl_sum204 : count_ds 43 8 204 = 22169393903687611906220091621190388.
proof.
have ge0_8 : 0 <= 8.
+ by [].
by rewrite -size_fu43 -size_fs204 (count_ds_kernel 8 fu43 fs204 ge0_8) kernel204.
qed.
