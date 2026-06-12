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

/-- The `i`-th digit of `digestWord` is the byte `digest[31-i]` (all < 256). -/
theorem digestWord_digits_lt (digest : Std.Array Std.U8 32#usize) :
    ∀ d ∈ (List.range 32).map (fun i => (digest.val[31 - i]!).val), d < 256 := by
  intro d hd
  simp only [List.mem_map, List.mem_range] at hd
  obtain ⟨i, _, rfl⟩ := hd
  have := (digest.val[31 - i]!).hBounds
  simp only [Std.U8.size] at this ⊢; omega

theorem digestWord_getD (digest : Std.Array Std.U8 32#usize) (p : Nat) (hp : p < 32) :
    ((List.range 32).map (fun i => (digest.val[31 - i]!).val)).getD p 0
      = (digest.val[31 - p]!).val := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hp]; rfl

/-- Byte `p` of `digestWord` = `digest[31-p]` (0 past the end). Combines (A)
    `ofDigits_byte` with the digit↔index identity. -/
theorem digestWord_byte (digest : Std.Array Std.U8 32#usize) (p : Nat) :
    (digestWord digest >>> (8 * p)) % 256 = if p < 32 then (digest.val[31 - p]!).val else 0 := by
  rw [digestWord, ofDigits_byte _ _ (digestWord_digits_lt digest)]
  split
  · exact digestWord_getD digest p ‹_›
  · rw [List.getD_eq_getElem?_getD, List.getElem?_map,
        List.getElem?_eq_none (by simp only [List.length_range]; omega)]; rfl

/-! ### `wrapping_sub` value (the loop's `byte_start - b` index, platform-generic) -/

theorem usize_wsub_val (a b : Std.Usize) :
    (core.num.Usize.wrapping_sub a b).val
      = (a.val + (2 ^ System.Platform.numBits - b.val)) % 2 ^ System.Platform.numBits := by
  simp only [core.num.Usize.wrapping_sub, UScalar.wrapping_sub, UScalar.val, UScalar.bv,
             UScalarTy.Usize, BitVec.toNat_sub,
             show UScalarTy.Usize.numBits = System.Platform.numBits from rfl]
  congr 1; omega

/-- In-range index: `byte_start - b` when `b ≤ byte_start` (≤ 31). -/
theorem wsub_eq_of_le (a b : Std.Usize) (hb : b.val ≤ a.val) (ha : a.val ≤ 31) :
    (core.num.Usize.wrapping_sub a b).val = a.val - b.val := by
  rw [usize_wsub_val]
  have h32 : (32:Nat) ≤ 2 ^ System.Platform.numBits := by
    rcases System.Platform.numBits_eq with h | h <;> rw [h] <;> norm_num
  rw [show a.val + (2 ^ System.Platform.numBits - b.val)
        = 2 ^ System.Platform.numBits + (a.val - b.val) by omega,
      Nat.add_mod_left, Nat.mod_eq_of_lt (by omega)]

/-- Out-of-range: `b > byte_start` wraps to a huge value, so `¬ idx < 32`. -/
theorem not_wsub_lt32_of_gt (a b : Std.Usize) (ha : a.val ≤ 31) (hbs : b.val ≤ 8)
    (h : a.val < b.val) : ¬ (core.num.Usize.wrapping_sub a b).val < 32 := by
  rw [usize_wsub_val]
  have h32 : (2:Nat) ^ 32 ≤ 2 ^ System.Platform.numBits := by
    rcases System.Platform.numBits_eq with h | h <;> rw [h] <;> norm_num
  rw [Nat.mod_eq_of_lt (by omega)]; omega

/-! ### The loop accumulator invariant (L) -/

-- abbreviation for the windowed word
private def W (digest : Std.Array Std.U8 32#usize) (byte_start : Nat) : Nat :=
  digestWord digest >>> (8 * (31 - byte_start))

set_option maxHeartbeats 4000000 in
theorem read_bits_le_loop_value
    (iter : core.ops.range.Range Std.Usize) (digest : Std.Array Std.U8 32#usize)
    (byte_start : Std.Usize) (val : Std.U64) (bn : Nat)
    (hbs : byte_start.val ≤ 31) (hbn : bn ≤ 8)
    (hend : iter.«end».val = bn) (hle : iter.start.val ≤ bn)
    (hval : val.val = W digest byte_start.val % 2 ^ (8 * iter.start.val)) :
    fors.read_bits_le_loop iter digest byte_start val
      ⦃ r => r.val = W digest byte_start.val % 2 ^ (8 * bn) ⦄ := by
  unfold fors.read_bits_le_loop
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize × Std.U64) => s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize × Std.U64) =>
      s.1.«end».val = bn ∧ s.1.start.val ≤ bn ∧
      s.2.val = W digest byte_start.val % 2 ^ (8 * s.1.start.val))
  · rintro ⟨it, v⟩ ⟨hbnd, hslt, hvinv⟩
    simp only at hbnd hslt hvinv
    unfold fors.read_bits_le_loop.body
    simp only []
    let* ⟨o, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨b, it', heq, hb, hlt, hend', hstart'⟩
    · subst ho; simp only [WP.spec_ok]
      have hbeq : it.start.val = bn := by omega
      rw [← hbeq]; exact hvinv
    · simp only [Prod.mk.injEq] at heq; obtain ⟨rfl, rfl⟩ := heq
      have hsb : it.start.val < bn := by omega
      have hs7 : it.start.val ≤ 7 := by omega
      simp only [lift, hb, bind_tc_ok]
      -- common: end=bn, start+1≤bn, measure decreases
      have hwbnd : (W digest byte_start.val >>> (8 * it.start.val)) % 256
          = (digestWord digest >>> (8 * (31 - byte_start.val + it.start.val))) % 256 := by
        rw [W, ← Nat.shiftRight_add]; congr 2; omega
      -- the mod-window step at this byte
      have hstep : W digest byte_start.val % 2 ^ (8 * (it.start.val + 1))
          = W digest byte_start.val % 2 ^ (8 * it.start.val)
            + ((W digest byte_start.val >>> (8 * it.start.val)) % 256) * 2 ^ (8 * it.start.val) := by
        rw [show 8 * (it.start.val + 1) = 8 * it.start.val + 8 by ring, mod_window_step]; norm_num
      by_cases hcase : it.start.val ≤ byte_start.val
      · -- in-range: reads digest[byte_start - it.start]
        have hidx : (core.num.Usize.wrapping_sub byte_start it.start).val < 32 := by
          rw [wsub_eq_of_le _ _ hcase hbs]; omega
        have hp32 : 31 - byte_start.val + it.start.val < 32 := by omega
        rw [if_pos (by scalar_tac)]
        have hp32 : 31 - byte_start.val + it.start.val < 32 := by omega
        have hbyte : 31 - (31 - byte_start.val + it.start.val) = byte_start.val - it.start.val := by omega
        have hidxv : (core.num.Usize.wrapping_sub byte_start it.start).val = byte_start.val - it.start.val :=
          wsub_eq_of_le _ _ hcase hbs
        have hlen : digest.val.length = 32 := by have h := digest.property; simpa using h
        step*
        have hi_lt : i.val < 256 := by have := i.hBounds; simp only [Std.U8.size] at this; omega
        -- the byte read equals digit (byte_start - it.start)
        have hival : i.val = (digest.val[byte_start.val - it.start.val]!).val := by
          rw [i_post, getElem!_pos digest.val _ (by rw [hlen]; omega)]
          congr 1
          simp only [hidxv]
        refine ⟨by rw [hend']; exact hbnd, by rw [hstart']; omega, ?_, by rw [hend', hstart']; omega⟩
        rw [hstart']
        have hfrom : (core.convert.num.FromU64U8.from i).val = i.val := by scalar_tac
        have h2bd : i.val * 2 ^ (8 * it.start.val) < 2 ^ 64 :=
          calc i.val * 2 ^ (8 * it.start.val)
                ≤ 255 * 2 ^ 56 := Nat.mul_le_mul (by omega) (Nat.pow_le_pow_right (by norm_num) (by omega))
            _ < 2 ^ 64 := by norm_num
        have hi3v : i3.val = i.val * 2 ^ (8 * it.start.val) := by
          rw [i3_post1, hfrom, i2_post, Nat.shiftLeft_eq,
              show it.start.val * 8 = 8 * it.start.val by ring,
              show U64.size = 2 ^ 64 by simp [U64.size, U64.numBits], Nat.mod_eq_of_lt h2bd]
        have hvlt : v.val < 2 ^ (8 * it.start.val) := by
          rw [hvinv]; exact Nat.mod_lt _ (Nat.two_pow_pos _)
        rw [UScalar.val_or, hi3v, ← Nat.shiftLeft_eq,
            lor_eq_add_disjoint v.val i.val it.start.val hvlt hi_lt,
            hstep, hwbnd, digestWord_byte, if_pos hp32, hbyte, hvinv, hival]
      · -- out of range: byte is 0, val unchanged
        have hidx := not_wsub_lt32_of_gt byte_start it.start hbs (by omega) (by omega)
        rw [if_neg (by scalar_tac)]
        simp only [WP.spec_ok]
        refine ⟨by simp [hend', hbnd], by simp only [hstart']; omega, ?_, by simp only [hstart', hend', hbnd]; omega⟩
        simp only [hstart']
        rw [hstep, hwbnd, digestWord_byte, if_neg (by omega), Nat.zero_mul, Nat.add_zero]
        exact hvinv
  · exact ⟨hend, hle, hval⟩

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
