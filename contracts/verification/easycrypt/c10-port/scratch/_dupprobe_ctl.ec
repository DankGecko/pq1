require import AllCore List.
(* MUST-FAIL CONTROL: same conclusion with the HYPOTHESIS DELETED.  If this compiled,
   the candidate proof would not be using `hna` and would prove nothing about the real
   goal at GprocT1Opre.ec:1427. *)
lemma ctl_no_hyp (c hh : (int * int * int) list) :
  has (fun (x : int * int * int) => ! (x \in c)) hh.
proof. by rewrite -/(predC _) has_predC. qed.
