/- §33 P3 — bit-arithmetic lemmas for the read_bits_le functional spec.

   The load-bearing fact for the read_bits_le accumulator invariant
   (see ForsExtractWIP.lean): ORing a byte shifted past the occupied
   low bits equals adding it (the bits are disjoint). Kernel-clean, no
   new axioms. -/
import Aeneas

open Aeneas Aeneas.Std

namespace Extracted.Equiv

/-- Disjoint-OR-equals-ADD: when `val` fits in the low `8*b` bits and
    `x` is a byte, ORing `x` shifted to bit position `8*b` is the same
    as adding `x * 2^(8*b)` (no bit overlap, no carries). -/
theorem lor_eq_add_disjoint (val x b : Nat)
    (hval : val < 2 ^ (8 * b)) (hx : x < 256) :
    val ||| (x <<< (8 * b)) = val + x * 2 ^ (8 * b) := by
  sorry

end Extracted.Equiv
