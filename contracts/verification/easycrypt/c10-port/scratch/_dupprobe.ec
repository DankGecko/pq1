require import AllCore List.

(* The exact goal shape of GprocT1Opre.ec:1427, isolated:
   from `! all p hh`, derive `has (fun x => ! p x) hh`, deterministically. *)
lemma cand_A (c hh : (int * int * int) list) :
  ! all (fun (x : int * int * int) => x \in c) hh =>
  has (fun (x : int * int * int) => ! (x \in c)) hh.
proof.
move=> hna.
by have := has_predC (fun (x : int * int * int) => x \in c) hh; rewrite /predC /= => ->.
qed.

lemma cand_B (c hh : (int * int * int) list) :
  ! all (fun (x : int * int * int) => x \in c) hh =>
  has (fun (x : int * int * int) => ! (x \in c)) hh.
proof. by move=> hna; rewrite -/(predC _) has_predC. qed.
