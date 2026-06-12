/- §33 rank 7 — RLP canonical big-endian integer decode: FUNCTIONAL specs
   (statements only; proofs via the LeanLoop grind + frontier queue).

   bytes_to_u64 / bytes_to_u256 are the canonical-RLP integer boundary: length
   cap, leading-zero rejection, and the accumulator loop `acc = acc*256 + b`
   (bytes_to_u64) / left-padded copy (bytes_to_u256). The specs pin all three
   result branches exactly.

   Leaf-lemma plan (the grindable pieces):
     (a) beValue_append_byte : beValue (l ++ [b]) = beValue l * 256 + b.val
     (b) beValue_lt          : l.length ≤ k → beValue l < 256 ^ k
     (c) the loop invariant  : after consuming i bytes, acc = beValue (l.take i)
         (uses lor_shiftLeft_add from WotsDigits.lean for acc<<<8 ||| b = ADD)
     (d) u256 path: SetSliceLemmas-style left-pad layout
         (List.replicate (32-n) 0 ++ bytes). -/
import Extracted.Rlp.Funs
import Extracted.WotsDigits

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open pqsigner_tx_core

/-- Big-endian value of a byte list, Horner form — mirrors the Rust
    accumulator `acc = (acc << 8) | b` exactly. -/
def beValue (l : List Std.U8) : Nat := l.foldl (fun acc b => acc * 256 + b.val) 0

/-- `beValue` is bounded by `256^len` (needed for the no-overflow argument:
    len ≤ 8 → beValue < 2^64). -/
theorem beValue_lt (l : List Std.U8) : beValue l < 256 ^ l.length := by
  sorry

/-- **Functional spec** for `bytes_to_u64`: the three result branches, exactly.
    - length > 8                      → `Err IntTooLarge`
    - non-empty with leading 0 byte   → `Err LeadingZero`
    - otherwise                       → `Ok (beValue bytes)`. -/
theorem bytes_to_u64_spec (bytes : Slice Std.U8) :
    rlp.bytes_to_u64 bytes
      ⦃ r =>
        (bytes.val.length > 8 → r = core.result.Result.Err rlp.RlpError.IntTooLarge) ∧
        (bytes.val.length ≤ 8 →
          (∃ b0 tl, bytes.val = b0 :: tl ∧ b0.val = 0) →
            r = core.result.Result.Err rlp.RlpError.LeadingZero) ∧
        (bytes.val.length ≤ 8 →
          (∀ b0 tl, bytes.val = b0 :: tl → b0.val ≠ 0) →
            ∃ v, r = core.result.Result.Ok v ∧ v.val = beValue bytes.val) ⦄ := by
  sorry

/-- **Functional spec** for `bytes_to_u256`: same gates (cap 32), and the `Ok`
    payload is the 32-byte LEFT-PADDED big-endian array
    `replicate (32-n) 0 ++ bytes`. -/
theorem bytes_to_u256_spec (bytes : Slice Std.U8) :
    rlp.bytes_to_u256 bytes
      ⦃ r =>
        (bytes.val.length > 32 → r = core.result.Result.Err rlp.RlpError.IntTooLarge) ∧
        (bytes.val.length ≤ 32 →
          (∃ b0 tl, bytes.val = b0 :: tl ∧ b0.val = 0) →
            r = core.result.Result.Err rlp.RlpError.LeadingZero) ∧
        (bytes.val.length ≤ 32 →
          (∀ b0 tl, bytes.val = b0 :: tl → b0.val ≠ 0) →
            ∃ out, r = core.result.Result.Ok out ∧
              out.val = List.replicate (32 - bytes.val.length) 0#u8 ++ bytes.val) ⦄ := by
  sorry

end Extracted.Equiv
