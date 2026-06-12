/- §33 rank 4 — wots::extract_digits FUNCTIONAL spec. An INDEPENDENT
   bit-extractor (single-byte + two-byte-spanning paths) proven to compute
   the SAME closed-form window as read_bits_le: digit j = (digestWord >> j*3)
   % 8. Reuses digestWord_byte/window_shift/mod_window_step from rank 1. -/
import Extracted.Wots.Funs
import Extracted.ForsExtract
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10

theorem lor_shiftLeft_add (val x k : Nat) (hval : val < 2 ^ k) :
    val ||| (x <<< k) = val + x * 2 ^ k := by
  have hsum : val + x * 2 ^ k = 2 ^ k * x + val := by ring
  rw [hsum]; apply Nat.eq_of_testBit_eq; intro j
  rw [Nat.testBit_lor, Nat.testBit_shiftLeft, Nat.testBit_two_pow_mul_add x hval j]
  rcases Nat.lt_or_ge j k with hj | hj
  · simp [hj, Nat.not_le.mpr hj]
  · have hv : val.testBit j = false :=
      Nat.testBit_lt_two_pow (Nat.lt_of_lt_of_le hval (Nat.pow_le_pow_right (by norm_num) hj))
    simp [hv, hj, Nat.not_lt.mpr hj, Nat.le_of_lt]

theorem twobyte_digit (B0 B1 bb : Nat) (h0 : B0 < 256) (h1 : B1 < 256)
    (h6 : 6 ≤ bb) (h8 : bb < 8) :
    ((B0 >>> bb) ||| ((B1 <<< (8 - bb)) % 256)) % 8 = ((B0 + 256 * B1) >>> bb) % 8 := by
  have hk : 2 ^ bb * 2 ^ (8 - bb) = 256 := by rw [← pow_add, show bb + (8 - bb) = 8 by omega]; norm_num
  have hhi : (B1 <<< (8 - bb)) % 256 = (B1 % 2 ^ bb) <<< (8 - bb) := by
    rw [Nat.shiftLeft_eq, Nat.shiftLeft_eq, ← hk, Nat.mul_mod_mul_right]
  have hlo : B0 >>> bb < 2 ^ (8 - bb) := by
    rw [Nat.shiftRight_eq_div_pow]; apply Nat.div_lt_of_lt_mul; rw [hk]; exact h0
  rw [hhi, lor_shiftLeft_add _ _ _ hlo, Nat.shiftRight_eq_div_pow, Nat.shiftRight_eq_div_pow]
  rcases (show bb = 6 ∨ bb = 7 by omega) with rfl | rfl <;> norm_num <;> omega

set_option maxHeartbeats 4000000 in
theorem extract_digits_loop_value
    (iter : core.ops.range.Range Std.Usize) (digest : Std.Array Std.U8 32#usize)
    (digits : Std.Array Std.U8 43#usize) (hb : iter.«end».val = 43)
    (hinit : ∀ j, j < iter.start.val → (digits.val[j]!).val = (digestWord digest >>> (j * 3)) % 8) :
    wots.extract_digits_loop iter digest digits
      ⦃ r => ∀ j, j < 43 → (r.val[j]!).val = (digestWord digest >>> (j * 3)) % 8 ⦄ := by
  unfold wots.extract_digits_loop
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize × Std.Array Std.U8 43#usize) =>
       s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize × Std.Array Std.U8 43#usize) =>
       s.1.«end».val = 43 ∧ ∀ j, j < s.1.start.val → (s.2.val[j]!).val = (digestWord digest >>> (j * 3)) % 8)
  · rintro ⟨it, dg⟩ ⟨hend, hinv⟩
    unfold wots.extract_digits_loop.body
    simp only []
    let* ⟨o, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hle⟩ | ⟨b, it', heq, hb', hlt, hend', hstart⟩
    · subst ho; simp only [WP.spec_ok]; exact fun j hj => hinv j (by scalar_tac)
    · simp only [Prod.mk.injEq] at heq; obtain ⟨rfl, rfl⟩ := heq
      have hbeq : b.val = it.start.val := by rw [hb']
      have h42 : b.val ≤ 42 := by scalar_tac
      have hlen : digest.val.length = 32 := by have := digest.property; simpa using this
      simp only [params.LOG_W, params.W_MASK, params.W]
      step*
      · -- SINGLE-BYTE branch: digit = (digest[byte_idx] >> bib) & 7
        have hq : i1.val = b.val * 3 / 8 := by rw [i1_post, bit_offset_post]
        have hbib : bit_in_byte.val = b.val * 3 % 8 := by rw [bit_in_byte_post, bit_offset_post]
        have hbidx : byte_idx.val = 31 - b.val * 3 / 8 := by rw [byte_idx_post1, hq]
        have hcond : b.val * 3 % 8 + 3 ≤ 8 := by rw [← hbib]; scalar_tac
        have hB0 : i3.val = (digestWord digest >>> (8 * (b.val * 3 / 8))) % 2 ^ 8 := by
          rw [show (2:Nat) ^ 8 = 256 by norm_num, digestWord_byte, if_pos (by omega),
              i3_post, getElem!_pos digest.val _ (by rw [hlen]; omega)]
          congr 1; simp only [hbidx]
        have htarget : (digestWord digest >>> (b.val * 3)) % 8
            = ((digestWord digest >>> (8 * (b.val * 3 / 8))) >>> (b.val * 3 % 8)) % 8 := by
          conv_lhs => rw [show b.val * 3 = 8 * (b.val * 3 / 8) + b.val * 3 % 8 from by omega,
                          Nat.shiftRight_add]
        have hmask : (UScalar.cast UScalarTy.U8 x).val = 7 := by
          rw [UScalar.cast_val_eq, x_post1]; decide
        have hdigit : i6.val = (digestWord digest >>> (b.val * 3)) % 8 := by
          rw [i6_post1, UScalar.val_and, hmask, i4_post1, hbib,
              show (7:Nat) = 2 ^ 3 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod, hB0,
              window_shift _ _ _ _ (by omega), show (2:Nat) ^ 3 = 8 by norm_num, ← htarget]
        refine ⟨by rw [hend']; exact hend, fun j hj => ?_, by rw [hend', hstart]; omega⟩
        rw [a_post, Array.set_val_eq]
        have hlen43 : dg.val.length = 43 := by have := dg.property; simp_all
        by_cases hjb : j = b.val
        · subst hjb; rw [List.set_getElem!_eq _ b.val b.val i6 ⟨by omega, rfl⟩]; exact hdigit
        · rw [List.set_getElem!_ne _ b.val j i6 (by simp only [Nat.not_eq]; omega)]
          rw [hbeq] at hjb
          have hj' : j < it.start.val + 1 := by rw [hstart] at hj; exact hj
          apply hinv j; show j < it.start.val; omega
      · -- TWO-BYTE branch: digit = ((B0>>bib) | (B1<<(8-bib))) & 7, spanning two bytes
        have hq : i1.val = b.val * 3 / 8 := by rw [i1_post, bit_offset_post]
        have hbib : bit_in_byte.val = b.val * 3 % 8 := by rw [bit_in_byte_post, bit_offset_post]
        have hbidx : byte_idx.val = 31 - b.val * 3 / 8 := by rw [byte_idx_post1, hq]
        have hbpos : (0#usize) < byte_idx := by
          have : byte_idx.val = 31 - b.val * 3 / 8 := hbidx; scalar_tac
        have hcond : 6 ≤ b.val * 3 % 8 := by rw [← hbib]; scalar_tac
        rw [if_pos hbpos]
        let* ⟨bm1, hbm1⟩ ← Std.Usize.sub_spec
        let* ⟨byte1, hbyte1⟩ ← Array.index_usize_spec
        let* ⟨sh, hsh⟩ ← Std.Usize.sub_spec
        step*
        -- B0 = byte at q, B1 = byte at q+1
        have hlt : b.val * 3 / 8 ≤ 15 := by omega
        have hB0 : i3.val = (digestWord digest >>> (8 * (b.val * 3 / 8))) % 2 ^ 8 := by
          rw [show (2:Nat) ^ 8 = 256 by norm_num, digestWord_byte, if_pos (by omega),
              i3_post, getElem!_pos digest.val _ (by rw [hlen]; omega)]
          congr 1; simp only [hbidx]
        have hbm1eq : bm1.val = 31 - (b.val * 3 / 8 + 1) := by rw [hbm1, hbidx]; omega
        have hB1 : byte1.val = (digestWord digest >>> (8 * (b.val * 3 / 8 + 1))) % 2 ^ 8 := by
          rw [show (2:Nat) ^ 8 = 256 by norm_num, digestWord_byte, if_pos (by omega),
              hbyte1, getElem!_pos digest.val _ (by rw [hlen]; omega)]
          congr 1; simp only [hbm1eq]
        have hB0lt : i3.val < 256 := by have := i3.hBounds; simp only [Std.U8.size] at this; omega
        have hB1lt : byte1.val < 256 := by have := byte1.hBounds; simp only [Std.U8.size] at this; omega
        have hcomb : i3.val + 256 * byte1.val = (digestWord digest >>> (8 * (b.val * 3 / 8))) % 2 ^ 16 := by
          rw [hB0, hB1, show (16:Nat) = 8 + 8 from rfl, mod_window_step,
              show 8 * (b.val * 3 / 8 + 1) = 8 * (b.val * 3 / 8) + 8 by ring, Nat.shiftRight_add]
          ring
        have htarget : (digestWord digest >>> (b.val * 3)) % 8
            = ((digestWord digest >>> (8 * (b.val * 3 / 8))) >>> (b.val * 3 % 8)) % 8 := by
          conv_lhs => rw [show b.val * 3 = 8 * (b.val * 3 / 8) + b.val * 3 % 8 from by omega,
                          Nat.shiftRight_add]
        have hmask : (UScalar.cast UScalarTy.U8 x).val = 7 := by
          rw [UScalar.cast_val_eq, x_post1]; decide
        have hwin : (((digestWord digest >>> (8 * (b.val * 3 / 8))) % 2 ^ 16) >>> (b.val * 3 % 8)) % 8
            = ((digestWord digest >>> (8 * (b.val * 3 / 8))) >>> (b.val * 3 % 8)) % 8 := by
          have h := window_shift (digestWord digest >>> (8 * (b.val * 3 / 8))) (b.val * 3 % 8) 3 16 (by omega)
          simpa only [show (2:Nat) ^ 3 = 8 by norm_num] using h
        have hdigit : i6.val = (digestWord digest >>> (b.val * 3)) % 8 := by
          rw [i6_post1, UScalar.val_and, hmask, i4_post1, UScalar.val_or, lo_post1, hi_post1,
              hsh, hbib, show U8.size = 256 by simp [U8.size, U8.numBits],
              show (7:Nat) = 2 ^ 3 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod,
              show (2:Nat) ^ 3 = 8 by norm_num,
              twobyte_digit _ _ _ hB0lt hB1lt hcond (by omega), hcomb, hwin, ← htarget]
        refine ⟨by rw [hend']; exact hend, fun j hj => ?_, by rw [hend', hstart]; omega⟩
        rw [a_post, Array.set_val_eq]
        have hlen43 : dg.val.length = 43 := by have := dg.property; simp_all
        by_cases hjb : j = b.val
        · subst hjb; rw [List.set_getElem!_eq _ b.val b.val i6 ⟨by omega, rfl⟩]; exact hdigit
        · rw [List.set_getElem!_ne _ b.val j i6 (by simp only [Nat.not_eq]; omega)]
          rw [hbeq] at hjb
          have hj' : j < it.start.val + 1 := by rw [hstart] at hj; exact hj
          apply hinv j; show j < it.start.val; omega
  · exact ⟨hb, hinit⟩

open sphincs_c10 in
set_option maxHeartbeats 4000000 in
/-- **Functional spec**: every WOTS digit is the exact `LOG_W`-bit window of the
    digest word — `extract_digits digest [j] = (digestWord >> j*3) mod 8` for all
    j < 43 (and hence < W=8). An INDEPENDENT bit-extractor from read_bits_le
    (single-byte fast path + two-byte slow path), proven to agree with the same
    closed form. -/
theorem extract_digits_spec (digest : Std.Array Std.U8 32#usize) :
    wots.extract_digits digest
      ⦃ r => ∀ j, j < 43 → (r.val[j]!).val = (digestWord digest >>> (j * 3)) % 8 ⦄ := by
  unfold wots.extract_digits
  simp only [params.L]
  apply extract_digits_loop_value _ _ _ rfl
  intro j hj
  exact absurd hj (by simp)

/-- Corollary: every digit is in `[0, W) = [0, 8)`. -/
theorem extract_digits_lt (digest : Std.Array Std.U8 32#usize) :
    wots.extract_digits digest ⦃ r => ∀ j, j < 43 → (r.val[j]!).val < 8 ⦄ := by
  apply WP.spec_mono (extract_digits_spec digest)
  intro r hr j hj
  rw [hr j hj]; exact Nat.mod_lt _ (by norm_num)

end Extracted.Equiv
