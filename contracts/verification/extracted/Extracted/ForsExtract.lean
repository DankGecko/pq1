/- §33 P3 — read_bits_le FUNCTIONAL spec (verification-target catalog rank 1).

   Panic-freedom + range are proven (ForsLoop.lean). This states the exact
   VALUE: `read_bits_le digest off n` equals bits [off, off+n) of the digest
   interpreted as a 256-bit word (bit 0 = LSB of digest[31] — the same word the
   EVM loads, so the Yul `and(shr(143, digest), 0x3FFFF)` composes at rank 2).

   Decomposition (executably sanity-checked on 6 shapes incl. unaligned-57 and
   past-the-end):
     (A) ofDigits_byte   — byte p of a base-256 digit list = the p-th digit
     (B) mod_window_step — split the top byte off a mod-window
     (L) the loop-accumulator induction: val = (digestWord >>> 8q) % 2^(8·bn),
         OR→ADD at each step via Bits.lor_eq_add_disjoint (PROVEN)
     (F) the final (val >>> bit_in_byte) & mask arithmetic. -/
import Extracted.ForsLoop
import Extracted.Bits
import Mathlib.Data.Nat.Digits.Defs

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open sphincs_c10

/-- The digest as the 256-bit word the firmware and the EVM agree on:
    byte 31 is least significant. `ofDigits 256 [d31, d30, …, d0]`. -/
def digestWord (digest : Std.Array Std.U8 32#usize) : Nat :=
  Nat.ofDigits 256 ((List.range 32).map (fun i => (digest.val[31 - i]!).val))

/-! ### Reusable bit/byte arithmetic (A), (B) -/

/-- Dividing `ofDigits` by `base^(p+1)` drops the head digit and divides the
    tail by `base^p` (when the head is a real byte). -/
private theorem ofDigits_div_cons (d : Nat) (tl : List Nat) (p : Nat) (hd : d < 256) :
    Nat.ofDigits 256 (d :: tl) / 256 ^ (p + 1) = Nat.ofDigits 256 tl / 256 ^ p := by
  rw [Nat.ofDigits_cons, show (256:Nat) ^ (p + 1) = 256 * 256 ^ p by rw [pow_succ]; ring,
      ← Nat.div_div_eq_div_mul, Nat.add_comm d, Nat.mul_add_div (by norm_num),
      Nat.div_eq_of_lt hd, Nat.add_zero]

/-- (A) Byte `p` of a bounded base-256 digit list equals the `p`-th digit
    (0 past the end). `>>> (8*p)` then `% 256` is exactly digit extraction. -/
theorem ofDigits_byte (L : List Nat) (p : Nat) (hb : ∀ d ∈ L, d < 256) :
    (Nat.ofDigits 256 L >>> (8 * p)) % 256 = L.getD p 0 := by
  rw [Nat.shiftRight_eq_div_pow, show (2:Nat) ^ (8 * p) = 256 ^ p by rw [pow_mul]; norm_num]
  induction p generalizing L with
  | zero =>
    cases L with
    | nil => simp [Nat.ofDigits_nil, List.getD]
    | cons d tl =>
      simp only [pow_zero, Nat.div_one, Nat.ofDigits_cons, List.getD_cons_zero]
      rw [Nat.add_mul_mod_self_left]
      exact Nat.mod_eq_of_lt (hb d (by simp))
  | succ p ih =>
    cases L with
    | nil => simp [Nat.ofDigits_nil, List.getD]
    | cons d tl =>
      rw [ofDigits_div_cons d tl p (hb d (by simp)), ih tl (fun x hx => hb x (by simp [hx])),
          List.getD_cons_succ]

/-- (B) Peel the top byte off a `2^(8·k)`-wide mod-window. -/
theorem mod_window_step (X a c : Nat) :
    X % 2 ^ (a + c) = X % 2 ^ a + ((X >>> a) % 2 ^ c) * 2 ^ a := by
  rw [Nat.shiftRight_eq_div_pow, pow_add, Nat.mod_mul]; ring

/-! ### The functional spec (main goal) -/

/-- Functional spec: the result IS the `num_bits`-wide window at `bit_offset`
    of the digest word. Preconditions mirror `read_bits_le_terminates`. -/
theorem read_bits_le_spec (digest : Std.Array Std.U8 32#usize)
    (bit_offset num_bits : Std.Usize)
    (hpos : 0 < num_bits.val) (h : num_bits.val ≤ 57) (hoff : bit_offset.val ≤ 248) :
    fors.read_bits_le digest bit_offset num_bits
      ⦃ r => r.val = (digestWord digest >>> bit_offset.val) % 2 ^ num_bits.val ⦄ := by
  sorry

end Extracted.Equiv
