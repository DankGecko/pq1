(* Shadowing canary: `nhchwcoll_hchwpre_msg` exists ONLY in the chain copy of
   WOTS_TW_ES. If this file compiles, `-I chain` really does shadow the
   vendored proofs dir, and any chain result is trustworthy. If it fails with
   an unknown-identifier error, every chain result is a FALSE PASS. *)
require import AllCore.
require import WOTS_TW_ES.

lemma shadow_is_effective : true.
proof. by have ? := nhchwcoll_hchwpre_msg; trivial. qed.
