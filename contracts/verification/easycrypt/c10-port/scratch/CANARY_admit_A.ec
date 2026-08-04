(* CANARY FIXTURE A (2026-08-02, run 10).  Pairs with CANARY_admit_B.ec.
   PHASE 2c asserts the census gives these two DIFFERENT `admit:` digests.
   This is the round-10 kill shot in miniature: the two files differ only in a
   PREMISE of the admitted lemma, which is exactly the edit that used to leave
   the census row byte-identical.  Without this canary, a regression in
   _stmt_digest (or an enclosing-declaration miss that degrades it to the
   constant `nostmt`) would silently un-pin every admitted statement again. *)
require import AllCore.

op P : int -> bool.
op Q : int -> bool.

lemma canary_admit_stmt (x : int) : P x => Q x => 0 <= x.
proof. admit. qed.
