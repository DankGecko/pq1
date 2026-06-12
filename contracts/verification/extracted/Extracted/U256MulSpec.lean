/- §33 rank 10 — U256::saturating_mul_u64: FUNCTIONAL spec (statement only).

   The fee-budget multiply (`max_fee * gas_limit`) rendered on the trusted
   display. Exact saturation semantics: the product is correct iff it fits in
   256 bits, else clamps to U256::MAX with the overflow flag raised — the flag
   must NEVER be wrong in either direction (a silent wrap would show the user
   a tiny fee for a huge one).

   Proof plan: loop invariant over the indexed LS-first carry multiply —
   after j steps (bytes 31 down to 32-j processed),
     beValue (out.drop (32-j)) + carry * 256^j = beValue (self.drop (32-j)) * rhs
   with carry < 2^64 (u128 product of u8*u64 + carry never overflows).
   Final: drop 0 = whole array; overflow ⟺ carry ≠ 0 ⟺ product ≥ 2^256.
   Reuses beValue from RlpIntSpec.lean. -/
import Extracted.U256Mul.Funs
import Extracted.RlpIntSpec

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open pqsigner_tx_core

/-- **Functional spec**: exact product + exact saturation, both directions.
    - no overflow: `beValue out = beValue self * rhs` (and it fits in 2^256)
    - overflow:    `out = 0xFF…FF` and the true product is ≥ 2^256. -/
theorem saturating_mul_u64_spec (self : eip1559.U256) (rhs : Std.U64) :
    eip1559.U256.saturating_mul_u64 self rhs
      ⦃ p =>
        (p.2 = false →
          beValue p.1.val = beValue self.val * rhs.val ∧
          beValue self.val * rhs.val < 2 ^ 256) ∧
        (p.2 = true →
          p.1.val = List.replicate 32 255#u8 ∧
          2 ^ 256 ≤ beValue self.val * rhs.val) ⦄ := by
  sorry

end Extracted.Equiv
