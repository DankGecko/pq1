-- [sphincs_c10] external declarations for the merkle extraction.
-- th_pair is THE tweakable-hash boundary of rank 6 (SHA-256 compress inside),
-- axiomatized as a TOTAL pure function in the keccak256_pure pattern: an
-- uninterpreted `th_pair_pure` + a total `def` wrapper, so ⦃⦄ triples step
-- through hash calls without interpreting the hash. Discharge artifact: the
-- Rust th_pair KATs via the full sign/verify round-trip vectors
-- (contracts/smart-wallet/test/c10_test_vectors.json).
import Aeneas
import Extracted.Merkle.Types
open Aeneas Aeneas.Std Result

open sphincs_c10

/-- Pure uninterpreted tweakable pair-hash: (seed, adrs, left32, right32) ↦ n16. -/
axiom th_pair_pure :
  Array Std.U8 32#usize → Array Std.U8 32#usize → Array Std.U8 32#usize →
    Array Std.U8 32#usize → Array Std.U8 16#usize

/-- [sphincs_c10::hash::th_pair]: total wrapper over the pure axiom. -/
@[rust_fun "sphincs_c10::hash::th_pair"]
noncomputable def hash.th_pair
  (seed adrs a b : Array Std.U8 32#usize) : Result (Array Std.U8 16#usize) :=
  ok (th_pair_pure seed adrs a b)

/-- Step spec: th_pair always succeeds and returns the pure axiom's value. -/
@[step] theorem hash.th_pair_spec (seed adrs a b : Array Std.U8 32#usize) :
    hash.th_pair seed adrs a b ⦃ r => r = th_pair_pure seed adrs a b ⦄ := by
  simp [hash.th_pair, WP.spec_ok]
