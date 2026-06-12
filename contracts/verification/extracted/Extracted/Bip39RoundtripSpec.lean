/- §33 rank 9 — bip39 11-bit pack/unpack round-trip: FUNCTIONAL spec
   (statement only). The bug-prone part of BIP-39 mnemonic ↔ entropy is the
   MSB-first 11-bit packing arithmetic (top = 24 - shift - 11): an off-by-one
   there silently corrupts entropy on every recovery. roundtrip_11 writes an
   11-bit value into a fresh 33-byte buffer and reads it back; the spec is
   that this is the identity for in-range values at any in-bounds offset —
   i.e. write_11_bits and read_11_bits are exact inverses, the lemma the full
   24-word from_entropy/to_entropy bijection composes from.

   Proof plan: unfold roundtrip_11; write_11_bits is a sequence of `buf[k] |=`
   (setSlice!-on-single-bytes / Array.update with OR); read_11_bits loads the
   same ≤3 bytes big-endian and masks the window. The combined 24-bit value
   after write has `value << (24-shift-11)` in the touched bytes (disjoint OR
   into a zero buffer = ADD, lor_shiftLeft_add); read shifts back by the same
   `top` and masks 0x7FF, recovering value (value < 2^11). A window-arithmetic
   proof in the rank-1 family (digestWord_byte-style byte assembly + mask). -/
import Extracted.Bip39.Funs
import Extracted.WotsDigits   -- lor_shiftLeft_add

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open sphincs_tz_bip39

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

theorem shift_cancel_mask (value top : Nat) (hv : value < 2 ^ 11) :
    ((value <<< top) >>> top) &&& 2047 = value := by
  rw [Nat.shiftLeft_eq, Nat.shiftRight_eq_div_pow, Nat.mul_div_cancel _ (Nat.two_pow_pos top),
      show (2047 : Nat) = 2 ^ 11 - 1 by norm_num, Nat.and_two_pow_sub_one_eq_mod,
      Nat.mod_eq_of_lt hv]

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 32768 in
/-- Write into the zero buffer: the three touched bytes hold the windows of
    `V = value <<< (13 - bit%8)`; everything else (incl. length) preserved. -/
theorem write_11_bits_zero (s : Slice Std.U8) (bit : Std.Usize) (value : Std.U16)
    (hs : s.val = List.replicate 33 0#u8) (hv : value.val < 2 ^ 11) (hb : bit.val ≤ 253) :
    full.write_11_bits s bit value
      ⦃ out =>
        out.val.length = 33 ∧
        (out.val[bit.val / 8]!).val = ((value.val <<< (13 - bit.val % 8)) >>> 16) &&& 255 ∧
        (out.val[bit.val / 8 + 1]!).val = ((value.val <<< (13 - bit.val % 8)) >>> 8) &&& 255 ∧
        (bit.val / 8 + 2 < 33 →
          (out.val[bit.val / 8 + 2]!).val = (value.val <<< (13 - bit.val % 8)) &&& 255) ⦄ := by
  have hslen : s.val.length = 33 := by rw [hs]; simp
  unfold full.write_11_bits
  simp only [BITS_PER_WORD, lift]
  step* <;> first | scalar_tac | skip
  all_goals (
    have hfrom : (core.convert.num.FromU32U16.from value).val = value.val := by scalar_tac
    have htop : top.val = 13 - bit.val % 8 := by
      rw [top_post1, i_post1, shift_post]; omega
    have hvlt : value.val <<< top.val < 2 ^ 32 := by
      rw [Nat.shiftLeft_eq]
      calc value.val * 2 ^ top.val ≤ 2 ^ 11 * 2 ^ 13 := by
             apply Nat.mul_le_mul (by omega) (Nat.pow_le_pow_right (by norm_num) (by omega))
        _ < 2 ^ 32 := by norm_num
    have hvv : v.val = value.val <<< (13 - bit.val % 8) := by
      rw [v_post1, hfrom, ← htop, Nat.mod_eq_of_lt (by simpa [U32.size, U32.numBits] using hvlt)]
    have hi5v : i5 = 0#u8 := by
      rw [i5_post, ← getElem!_pos _ _ (by omega), hs]
      exact List.getElem!_replicate _ (by omega)
    have hl1 : (buf1.val).length = 33 := by
      rw [buf1_post]; simp only [Slice.set_val_eq, List.length_set]; exact hslen
    have hl2 : (buf2.val).length = 33 := by
      rw [buf2_post]; simp only [Slice.set_val_eq, List.length_set]; exact hl1
    have hi11v : i11 = 0#u8 := by
      rw [i11_post, ← getElem!_pos _ _ (by rw [hl1]; omega), buf1_post]
      simp only [Slice.set_val_eq]
      rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega), hs]
      exact List.getElem!_replicate _ (by omega)
    refine ⟨?_, ?_, ?_, fun h2 => ?_⟩ <;>
      first
      | (simp only [out_post, buf2_post, buf1_post, Slice.set_val_eq,
                    List.length_set, hslen]; done)
      | (simp only [buf2_post, buf1_post, Slice.set_val_eq, List.length_set, hslen]; done)
      | (exfalso; clear hs hvv hvlt hi5v hi11v; scalar_tac)
      | (-- byte-value goals: walk the set-chain, land on the OR, do the val math
         first
           | simp only [out_post, buf2_post, buf1_post, Slice.set_val_eq]
           | simp only [buf2_post, buf1_post, Slice.set_val_eq]
         repeat first
           | rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega)]
           | rw [List.set_getElem!_eq _ _ _ _
                  ⟨by simp only [List.length_set, hslen]; omega, by omega⟩]
         first
           | (-- a write that DID happen: value is the OR term
              first
                | rw [hi5v]
                | rw [hi11v]
                | (have hi17v : i17 = 0#u8 := by
                     rw [i17_post, ← getElem!_pos _ _ (by rw [hl2]; omega),
                         buf2_post, buf1_post]
                     simp only [Slice.set_val_eq]
                     rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega),
                         List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega),
                         hs]
                     exact List.getElem!_replicate _ (by omega)
                   rw [hi17v])
              simp only [UScalar.val_or, UScalar.cast_val_eq, UScalar.val_and,
                         show UScalarTy.U8.numBits = 8 from rfl,
                         show ((0#u8) : Std.U8).val = 0 from rfl, Nat.zero_or]
              first
                | rw [i2_post1]
                | rw [i7_post1]
                | skip
              rw [hvv]
              simp only [show ((255#u32) : Std.U32).val = 255 from rfl]
              exact Nat.mod_eq_of_lt (lt_of_le_of_lt Nat.and_le_right (by norm_num)))
           | skip)
      | skip)
  all_goals (trace_state; sorry)


set_option maxHeartbeats 4000000 in
set_option maxRecDepth 32768 in
/-- Read from a buffer whose three window bytes hold V's byte windows:
    returns the 11-bit window of V at the in-byte offset. -/
theorem read_11_bits_windows (s : Slice Std.U8) (bit : Std.Usize) (V : Nat)
    (hlen : s.val.length = 33) (hb : bit.val ≤ 253) (hV : V < 2 ^ 24)
    (h0 : (s.val[bit.val / 8]!).val = (V >>> 16) &&& 255)
    (h1 : (s.val[bit.val / 8 + 1]!).val = (V >>> 8) &&& 255)
    (h2 : bit.val / 8 + 2 < 33 → (s.val[bit.val / 8 + 2]!).val = V &&& 255)
    (h2' : ¬ bit.val / 8 + 2 < 33 → V &&& 255 = 0) :
    read_11_bits s bit ⦃ r => r.val = (V >>> (13 - bit.val % 8)) &&& 2047 ⦄ := by
  unfold read_11_bits
  simp only [BITS_PER_WORD, lift]
  step* <;> first | (exfalso; omega) | omega | skip
  have hival : i.val = (V >>> 16) &&& 255 := by
    rw [i_post, ← getElem!_pos _ _ (by rw [hlen]; omega), byte_post]; exact h0
  have hi2val : i2.val = (V >>> 8) &&& 255 := by
    rw [i2_post, ← getElem!_pos _ _ (by rw [hlen]; omega), i1_post, byte_post]; exact h1
  have hfrom : ∀ z : Std.U8, (core.convert.num.FromU32U8.from z).val = z.val := by
    intro z; scalar_tac
  have hb255 : (V >>> 16) &&& 255 ≤ 255 := Nat.and_le_right
  have hb255' : (V >>> 8) &&& 255 ≤ 255 := Nat.and_le_right
  split <;> rename_i hcond <;> (step* <;> first | (exfalso; omega) | omega | skip) <;>
    (first
     | (-- three-byte branch: x = third byte
        have hc1 : bit.val / 8 + 2 < 33 := by
          have h' : i3.val < (Slice.len s).val := hcond
          rw [Slice.len_val] at h'
          have h'' : (Slice.length s) = (33:Nat) := hlen
          omega
        have hxval : (core.convert.num.FromU32U8.from x).val = V &&& 255 := by
          rw [hfrom, x_post, ← getElem!_pos _ _ (by rw [hlen]; omega), i3_post, byte_post]
          exact h2 hc1
        have hi5v : i5.val = ((V >>> 16) &&& 255) <<< 16 := by
          rw [i5_post1, hfrom, hival, Nat.mod_eq_of_lt]
          rw [Nat.shiftLeft_eq, show U32.size = 2 ^ 32 by simp [U32.size, U32.numBits]]
          calc ((V >>> 16) &&& 255) * 2 ^ 16 ≤ 255 * 2 ^ 16 := Nat.mul_le_mul_right _ hb255
            _ < 2 ^ 32 := by norm_num
        have hi6v : i6.val = ((V >>> 8) &&& 255) <<< 8 := by
          rw [i6_post1, hfrom, hi2val, Nat.mod_eq_of_lt]
          rw [Nat.shiftLeft_eq, show U32.size = 2 ^ 32 by simp [U32.size, U32.numBits]]
          calc ((V >>> 8) &&& 255) * 2 ^ 8 ≤ 255 * 2 ^ 8 := Nat.mul_le_mul_right _ hb255'
            _ < 2 ^ 32 := by norm_num
        have htopv : top.val = 13 - bit.val % 8 := by
          rw [top_post1, i8_post1, shift_post]; omega
        rw [UScalar.cast_val_eq, UScalar.val_and, i9_post1, UScalar.val_or, UScalar.val_or,
            hi5v, hi6v, hxval, show ((2047#u32) : Std.U32).val = 2047 from rfl,
            Nat.lor_assoc, reassemble24 V hV, htopv]
        exact Nat.mod_eq_of_lt (lt_of_le_of_lt Nat.and_le_right (by norm_num)))
     | (-- two-byte branch: third operand 0, V's low byte is 0
        have hnc : ¬ bit.val / 8 + 2 < 33 := by
          intro hlt
          apply hcond
          show i3.val < (Slice.len s).val
          rw [Slice.len_val]
          have h'' : (Slice.length s) = (33:Nat) := hlen
          omega
        have hz : V &&& 255 = 0 := h2' hnc
        have hi5v : i5.val = ((V >>> 16) &&& 255) <<< 16 := by
          rw [i5_post1, hfrom, hival, Nat.mod_eq_of_lt]
          rw [Nat.shiftLeft_eq, show U32.size = 2 ^ 32 by simp [U32.size, U32.numBits]]
          calc ((V >>> 16) &&& 255) * 2 ^ 16 ≤ 255 * 2 ^ 16 := Nat.mul_le_mul_right _ hb255
            _ < 2 ^ 32 := by norm_num
        have hi6v : i6.val = ((V >>> 8) &&& 255) <<< 8 := by
          rw [i6_post1, hfrom, hi2val, Nat.mod_eq_of_lt]
          rw [Nat.shiftLeft_eq, show U32.size = 2 ^ 32 by simp [U32.size, U32.numBits]]
          calc ((V >>> 8) &&& 255) * 2 ^ 8 ≤ 255 * 2 ^ 8 := Nat.mul_le_mul_right _ hb255'
            _ < 2 ^ 32 := by norm_num
        have htopv : top.val = 13 - bit.val % 8 := by
          rw [top_post1, i8_post1, shift_post]; omega
        rw [UScalar.cast_val_eq, UScalar.val_and, i9_post1, UScalar.val_or, UScalar.val_or,
            hi5v, hi6v, show ((0#u32) : Std.U32).val = 0 from rfl, ← hz,
            show ((2047#u32) : Std.U32).val = 2047 from rfl,
            Nat.lor_assoc, reassemble24 V hV, htopv]
        exact Nat.mod_eq_of_lt (lt_of_le_of_lt Nat.and_le_right (by norm_num))))

set_option maxHeartbeats 4000000 in
open sphincs_tz_bip39 in
/-- **rank 9**: the 11-bit pack/unpack round-trip is the identity. -/
theorem roundtrip_11_id (value : Std.U16) (bit : Std.Usize)
    (hv : value.val < 2 ^ 11) (hb : bit.val ≤ 253) :
    full.roundtrip_11 value bit ⦃ r => r = value ⦄ := by
  unfold full.roundtrip_11
  let* ⟨st, back, hst, hback⟩ ← Array.to_slice_mut_spec
  have hs0 : st.val = List.replicate 33 0#u8 := by
    rw [hst]; simp [Array.repeat_val]
  let* ⟨out, hlen33, h0, h1, h2⟩ ← write_11_bits_zero st bit value hs0 hv hb
  have hbackv : ((back out).to_slice).val = out.val := by
    rw [hback, Array.val_to_slice, Array.from_slice_val _ _ (by rw [hlen33]; scalar_tac)]
  -- the read sees the same bytes
  have hV24 : value.val <<< (13 - bit.val % 8) < 2 ^ 24 := by
    rw [Nat.shiftLeft_eq]
    calc value.val * 2 ^ (13 - bit.val % 8) ≤ (2 ^ 11 - 1) * 2 ^ 13 := by
           apply Nat.mul_le_mul (by omega) (Nat.pow_le_pow_right (by norm_num) (by omega))
      _ < 2 ^ 24 := by norm_num
  simp only [lift, bind_tc_ok]
  apply WP.spec_mono (read_11_bits_windows ((back out).to_slice) bit
        (value.val <<< (13 - bit.val % 8))
        (by rw [hbackv]; exact hlen33) hb hV24
        (by rw [hbackv]; exact h0) (by rw [hbackv]; exact h1)
        (fun hin => by rw [hbackv]; exact h2 hin)
        (fun hout => by
          have h8 : 8 ≤ 13 - bit.val % 8 := by omega
          rw [show (255:Nat) = 2 ^ 8 - 1 from by norm_num,
              Nat.and_two_pow_sub_one_eq_mod, Nat.shiftLeft_eq]
          exact Nat.dvd_iff_mod_eq_zero.mp
            (Dvd.dvd.mul_left (pow_dvd_pow 2 h8) _)))
  intro r hr
  apply UScalar.eq_of_val_eq
  rw [hr, shift_cancel_mask _ _ hv]

end Extracted.Equiv
