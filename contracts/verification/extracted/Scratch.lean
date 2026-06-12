import Extracted.Bip39RoundtripSpec
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv

-- (a) byte reassembly: for V < 2^24, the three extracted bytes recombine to V.
--     Shifts/ands converted to div/mod, then omega (div/mod by literals).
theorem reassemble24 (V : Nat) (hV : V < 2 ^ 24) :
    ((V >>> 16) &&& 255) <<< 16 ||| (((V >>> 8) &&& 255) <<< 8 ||| (V &&& 255)) = V := by
  have h255 : (255 : Nat) = 2 ^ 8 - 1 := by norm_num
  have hc : V &&& 255 < 2 ^ 8 := by
    rw [h255, Nat.and_two_pow_sub_one_eq_mod]; exact Nat.mod_lt _ (by norm_num)
  have hinner : ((V >>> 8) &&& 255) <<< 8 ||| (V &&& 255)
      = (V &&& 255) + ((V >>> 8) &&& 255) * 2 ^ 8 := by
    rw [Nat.lor_comm, lor_shiftLeft_add _ _ _ hc]
  have hinner_lt : (V &&& 255) + ((V >>> 8) &&& 255) * 2 ^ 8 < 2 ^ 16 := by
    have hb : (V >>> 8) &&& 255 < 2 ^ 8 := by
      rw [h255, Nat.and_two_pow_sub_one_eq_mod]; exact Nat.mod_lt _ (by norm_num)
    omega
  rw [hinner, Nat.lor_comm, lor_shiftLeft_add _ _ _ hinner_lt,
      h255, Nat.and_two_pow_sub_one_eq_mod, Nat.and_two_pow_sub_one_eq_mod,
      Nat.and_two_pow_sub_one_eq_mod, Nat.shiftRight_eq_div_pow, Nat.shiftRight_eq_div_pow]
  norm_num
  omega

-- (b) the shift cancel + mask: ((value <<< top) >>> top) &&& 2047 = value
theorem shift_cancel_mask (value top : Nat) (hv : value < 2 ^ 11) :
    ((value <<< top) >>> top) &&& 2047 = value := by
  rw [Nat.shiftLeft_eq, Nat.shiftRight_eq_div_pow, Nat.mul_div_cancel _ (Nat.two_pow_pos top),
      show (2047 : Nat) = 2 ^ 11 - 1 by norm_num, Nat.and_two_pow_sub_one_eq_mod,
      Nat.mod_eq_of_lt hv]

open sphincs_tz_bip39 in
set_option maxHeartbeats 8000000 in
theorem roundtrip_11_id' (value : Std.U16) (bit : Std.Usize)
    (hv : value.val < 2 ^ 11) (hb : bit.val ≤ 253) :
    full.roundtrip_11 value bit ⦃ r => r = value ⦄ := by
  unfold full.roundtrip_11 full.write_11_bits read_11_bits
  simp only [BITS_PER_WORD]
  step* <;> first | scalar_tac | skip
  simp only [lift]
  step* <;> first | scalar_tac | skip
  split
  · -- byte+2 < 33 (three-byte write)
    step* <;> first | scalar_tac | skip
    split
    · -- read also sees byte+2 < 33
      step* <;> first | scalar_tac | skip
      apply UScalar.eq_of_val_eq
      simp only [UScalar.cast_val_eq, UScalar.val_and, UScalar.val_or,
                 Array.val_to_slice, Slice.len_val, Array.repeat_val,
                 Nat.zero_or] at *
      simp_lists at *
      have hfold : ([0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8] : List Std.U8) = List.replicate 33 0#u8 := by rfl
      simp only [hfold] at *
      simp_lists at *
      trace_state
      all_goals sorry
    · -- contradiction: write had byte+2 < 33, read len is the same 33
      exfalso
      scalar_tac
  · -- byte+2 ≥ 33 (two-byte write, byte = 31)
    step* <;> first | scalar_tac | skip
    all_goals sorry

end Extracted.Equiv
