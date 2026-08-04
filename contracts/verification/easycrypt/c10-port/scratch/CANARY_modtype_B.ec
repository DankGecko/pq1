(* CANARY FIXTURE B (2026-08-02, run 10).  Pairs with CANARY_modtype_A.ec.
   PHASE 2c asserts the census gives these two DIFFERENT module-type digests.
   Removal-fatality only detects a category VANISHING; it cannot detect a digest
   that has stopped DISCRIMINATING (e.g. a _decl_span regression that truncates
   the span before the restriction).  Same argument that justifies the
   `admitted.` canary in PHASE 2b. *)
require import AllCore.

type msgc.
type sigc.

module type SOracleC = { proc sign(m : msgc) : sigc }.

module type AdvC (O : SOracleC) = {
  proc forge() : msgc * sigc { }
}.
