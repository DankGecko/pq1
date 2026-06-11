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
  -- bitwise: both sides are the "concatenation" of x above the low 8*b bits of
  -- val. Core's append lemma `Nat.testBit_two_pow_mul_add` gives the RHS bits.
  have hsum : val + x * 2 ^ (8 * b) = 2 ^ (8 * b) * x + val := by ring
  rw [hsum]
  apply Nat.eq_of_testBit_eq
  intro j
  rw [Nat.testBit_lor, Nat.testBit_shiftLeft,
      Nat.testBit_two_pow_mul_add x hval j]
  rcases Nat.lt_or_ge j (8 * b) with hj | hj
  · -- low bits: the shifted byte contributes nothing
    simp [hj, Nat.not_le.mpr hj]
  · -- high bits: val contributes nothing (val < 2^(8*b) ≤ 2^j)
    have hv : val.testBit j = false :=
      Nat.testBit_lt_two_pow
        (Nat.lt_of_lt_of_le hval (Nat.pow_le_pow_right (by norm_num) hj))
    simp [hv, hj, Nat.not_lt.mpr hj, Nat.le_of_lt]

end Extracted.Equiv
