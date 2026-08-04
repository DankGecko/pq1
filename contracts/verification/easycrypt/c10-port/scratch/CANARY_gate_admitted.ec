require import AllCore.
lemma proof_of_false : false.
proof. admitted.
(* PERMANENT GATE-REGRESSION CANARY (added 2026-07-26).
   `ec-certify.sh scratch/CANARY_gate_admitted.ec` MUST report NOT-CERTIFIED.
   If it ever reports CERTIFIED-0-ADMIT, the admit sweep has regressed: EasyCrypt's
   proof terminator `admitted.` is NOT matched by a regex anchored `admit\b`
   (the trailing `t` is a word character), so a proof of `false` sails through.
   Found 2026-07-26 by an adversarial audit; the chain was CLEAN at the time
   (no file used `admitted`), so no result was invalidated -- but the gate that
   underpins every CERTIFIED-0-ADMIT claim in this repo had the hole. *)
