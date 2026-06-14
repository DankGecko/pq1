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
import Extracted.SetSliceLemmas

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open pqsigner_tx_core

/-- Big-endian value of a byte list, Horner form — mirrors the Rust
    accumulator `acc = (acc << 8) | b` exactly. -/
def beValue (l : List Std.U8) : Nat := l.foldl (fun acc b => acc * 256 + b.val) 0

/-- `beValue` is bounded by `256^len` (needed for the no-overflow argument:
    len ≤ 8 → beValue < 2^64). -/
theorem beValue_append_byte (l : List Std.U8) (b : Std.U8) :
    beValue (l ++ [b]) = beValue l * 256 + b.val := by
  simp [beValue, List.foldl_append]

theorem beValue_lt_aux (l : List Std.U8) :
    ∀ acc, l.foldl (fun a b => a * 256 + b.val) acc < (acc + 1) * 256 ^ l.length := by
  induction l with
  | nil => intro acc; simp
  | cons b tl ih =>
    intro acc
    simp only [List.foldl_cons, List.length_cons]
    calc tl.foldl (fun a b => a * 256 + b.val) (acc * 256 + b.val)
        < (acc * 256 + b.val + 1) * 256 ^ tl.length := ih _
      _ ≤ (acc + 1) * 256 ^ (tl.length + 1) := by
          have hb : b.val < 256 := by have := b.hBounds; simp [Std.U8.size] at this; omega
          rw [pow_succ]
          have : acc * 256 + b.val + 1 ≤ (acc + 1) * 256 := by omega
          calc (acc * 256 + b.val + 1) * 256 ^ tl.length
              ≤ ((acc + 1) * 256) * 256 ^ tl.length := Nat.mul_le_mul_right _ this
            _ = (acc + 1) * (256 ^ tl.length * 256) := by ring
      _ = (acc + 1) * 256 ^ (tl.length + 1) := by rw [pow_succ]

theorem beValue_lt (l : List Std.U8) : beValue l < 256 ^ l.length := by
  have h := beValue_lt_aux l 0
  simpa [beValue] using h

-- slice-iter next: the Std def unfolded into a step spec
theorem sliceIter_next_spec (it : core.slice.iter.Iter Std.U8) :
    core.slice.iter.IteratorSliceIter.next it
      ⦃ p =>
        (¬ it.i < it.slice.val.length ∧ p.1 = none ∧ p.2 = it) ∨
        (it.i < it.slice.val.length ∧
          (∃ h : it.i < it.slice.val.length, p.1 = some (it.slice.val[it.i]'h)) ∧
          p.2 = { it with i := it.i + 1 }) ⦄ := by
  unfold core.slice.iter.IteratorSliceIter.next
  split
  · rename_i h
    simp only [WP.spec_ok]
    right
    refine ⟨h, ⟨h, ?_⟩, ?_⟩ <;> first | rfl | trivial
  · rename_i h
    simp only [WP.spec_ok]
    left
    refine ⟨h, ?_, ?_⟩ <;> first | rfl | trivial

open pqsigner_tx_core in
set_option maxHeartbeats 8000000 in
/-- The BE accumulator loop: from state (slice, k) with acc = beValue(take k),
    returns beValue(whole slice). Works for BOTH loop0 and loop1 (identical
    bodies). -/
theorem bytes_to_u64_loop1_value
    (it : core.slice.iter.Iter Std.U8) (acc : Std.U64)
    (hlen : it.slice.val.length ≤ 8) (hik : it.i ≤ it.slice.val.length)
    (hacc : acc.val = beValue (it.slice.val.take it.i)) :
    rlp.bytes_to_u64_loop1 it acc
      ⦃ r => r.val = beValue it.slice.val ⦄ := by
  unfold rlp.bytes_to_u64_loop1
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.slice.iter.Iter Std.U8 × Std.U64) =>
       s.1.slice.val.length - s.1.i)
    (inv := fun (s : core.slice.iter.Iter Std.U8 × Std.U64) =>
       s.1.slice = it.slice ∧ s.1.i ≤ it.slice.val.length ∧
       s.2.val = beValue (it.slice.val.take s.1.i))
  · rintro ⟨jt, a⟩ ⟨hsl, hji, hjacc⟩
    simp only at hsl hji hjacc
    unfold rlp.bytes_to_u64_loop1.body
    simp only [lift]
    let* ⟨o, iter1, hpost⟩ ← sliceIter_next_spec
    rcases hpost with ⟨hdone, ho, hit⟩ | ⟨hlt, ⟨hb, ho⟩, hit⟩
    · -- exhausted: take i = whole list
      subst ho
      simp only [WP.spec_ok]
      rw [hsl] at hdone
      have hge : it.slice.val.length ≤ jt.i := by omega
      rw [hjacc, List.take_of_length_le hge]
    · -- continue: acc' = acc*256 + b
      subst ho
      simp only []
      step* <;> first | scalar_tac | skip
      have hblt : ((jt.slice.val)[jt.i]'hb).val < 256 := by
        have := ((jt.slice.val)[jt.i]'hb).hBounds
        simp only [Std.U8.size] at this; omega
      have htake : jt.i ≤ 7 := by
        have := hlt; rw [hsl] at this; omega
      have halt : a.val < 256 ^ jt.i := by
        rw [hjacc]
        have h := beValue_lt (it.slice.val.take jt.i)
        rwa [List.length_take, Nat.min_eq_left hji] at h
      have hsh : i.val = a.val * 256 := by
        rw [i_post1, Nat.shiftLeft_eq, Nat.mod_eq_of_lt]
        rw [show U64.size = 2 ^ 64 by simp [U64.size, U64.numBits]]
        calc a.val * 2 ^ 8 < 256 ^ jt.i * 2 ^ 8 := by
               exact (Nat.mul_lt_mul_right (by norm_num)).mpr halt
          _ ≤ 256 ^ 7 * 2 ^ 8 := by
               exact Nat.mul_le_mul_right _ (Nat.pow_le_pow_right (by norm_num) htake)
          _ ≤ 2 ^ 64 := by norm_num
      have hi1 : iter1.i = jt.i + 1 := by rw [hit]
      have hs1 : iter1.slice = jt.slice := by rw [hit]
      refine ⟨by rw [hs1]; exact hsl,
              by rw [hi1]; rw [← hsl]; omega,
              ?_,
              by rw [hi1, hs1]; omega⟩
      rw [UScalar.val_or, UScalar.cast_val_eq, hi1]
      rw [show ((jt.slice.val)[jt.i]'hb).val % 2 ^ UScalarTy.U64.numBits
            = ((jt.slice.val)[jt.i]'hb).val from Nat.mod_eq_of_lt (by
              have := hblt
              have : ((jt.slice.val)[jt.i]'hb).val < 2 ^ 64 := by omega
              simpa using this)]
      have hadd : ((jt.slice.val)[jt.i]'hb).val ||| (a.val <<< 8)
          = ((jt.slice.val)[jt.i]'hb).val + a.val * 2 ^ 8 :=
        lor_shiftLeft_add _ _ _ (by omega)
      rw [hsh, Nat.lor_comm, show (256:Nat) = 2 ^ 8 from by norm_num,
          ← Nat.shiftLeft_eq, hadd]
      rw [← hsl]
      rw [List.take_succ_eq_append_getElem hb]
      rw [beValue_append_byte]
      have hja : a.val = beValue (jt.slice.val.take jt.i) := by rw [hjacc, hsl]
      rw [hja]
      ring
  · exact ⟨rfl, hik, hacc⟩


open pqsigner_tx_core in
set_option maxHeartbeats 8000000 in
/-- The BE accumulator loop: from state (slice, k) with acc = beValue(take k),
    returns beValue(whole slice). Works for BOTH loop0 and loop1 (identical
    bodies). -/
theorem bytes_to_u64_loop0_value
    (it : core.slice.iter.Iter Std.U8) (acc : Std.U64)
    (hlen : it.slice.val.length ≤ 8) (hik : it.i ≤ it.slice.val.length)
    (hacc : acc.val = beValue (it.slice.val.take it.i)) :
    rlp.bytes_to_u64_loop0 it acc
      ⦃ r => r.val = beValue it.slice.val ⦄ := by
  unfold rlp.bytes_to_u64_loop0
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.slice.iter.Iter Std.U8 × Std.U64) =>
       s.1.slice.val.length - s.1.i)
    (inv := fun (s : core.slice.iter.Iter Std.U8 × Std.U64) =>
       s.1.slice = it.slice ∧ s.1.i ≤ it.slice.val.length ∧
       s.2.val = beValue (it.slice.val.take s.1.i))
  · rintro ⟨jt, a⟩ ⟨hsl, hji, hjacc⟩
    simp only at hsl hji hjacc
    unfold rlp.bytes_to_u64_loop0.body
    simp only [lift]
    let* ⟨o, iter1, hpost⟩ ← sliceIter_next_spec
    rcases hpost with ⟨hdone, ho, hit⟩ | ⟨hlt, ⟨hb, ho⟩, hit⟩
    · -- exhausted: take i = whole list
      subst ho
      simp only [WP.spec_ok]
      rw [hsl] at hdone
      have hge : it.slice.val.length ≤ jt.i := by omega
      rw [hjacc, List.take_of_length_le hge]
    · -- continue: acc' = acc*256 + b
      subst ho
      simp only []
      step* <;> first | scalar_tac | skip
      have hblt : ((jt.slice.val)[jt.i]'hb).val < 256 := by
        have := ((jt.slice.val)[jt.i]'hb).hBounds
        simp only [Std.U8.size] at this; omega
      have htake : jt.i ≤ 7 := by
        have := hlt; rw [hsl] at this; omega
      have halt : a.val < 256 ^ jt.i := by
        rw [hjacc]
        have h := beValue_lt (it.slice.val.take jt.i)
        rwa [List.length_take, Nat.min_eq_left hji] at h
      have hsh : i.val = a.val * 256 := by
        rw [i_post1, Nat.shiftLeft_eq, Nat.mod_eq_of_lt]
        rw [show U64.size = 2 ^ 64 by simp [U64.size, U64.numBits]]
        calc a.val * 2 ^ 8 < 256 ^ jt.i * 2 ^ 8 := by
               exact (Nat.mul_lt_mul_right (by norm_num)).mpr halt
          _ ≤ 256 ^ 7 * 2 ^ 8 := by
               exact Nat.mul_le_mul_right _ (Nat.pow_le_pow_right (by norm_num) htake)
          _ ≤ 2 ^ 64 := by norm_num
      have hi1 : iter1.i = jt.i + 1 := by rw [hit]
      have hs1 : iter1.slice = jt.slice := by rw [hit]
      refine ⟨by rw [hs1]; exact hsl,
              by rw [hi1]; rw [← hsl]; omega,
              ?_,
              by rw [hi1, hs1]; omega⟩
      rw [UScalar.val_or, UScalar.cast_val_eq, hi1]
      rw [show ((jt.slice.val)[jt.i]'hb).val % 2 ^ UScalarTy.U64.numBits
            = ((jt.slice.val)[jt.i]'hb).val from Nat.mod_eq_of_lt (by
              have := hblt
              have : ((jt.slice.val)[jt.i]'hb).val < 2 ^ 64 := by omega
              simpa using this)]
      have hadd : ((jt.slice.val)[jt.i]'hb).val ||| (a.val <<< 8)
          = ((jt.slice.val)[jt.i]'hb).val + a.val * 2 ^ 8 :=
        lor_shiftLeft_add _ _ _ (by omega)
      rw [hsh, Nat.lor_comm, show (256:Nat) = 2 ^ 8 from by norm_num,
          ← Nat.shiftLeft_eq, hadd]
      rw [← hsl]
      rw [List.take_succ_eq_append_getElem hb]
      rw [beValue_append_byte]
      have hja : a.val = beValue (jt.slice.val.take jt.i) := by rw [hjacc, hsl]
      rw [hja]
      ring
  · exact ⟨rfl, hik, hacc⟩

open pqsigner_tx_core in
set_option maxHeartbeats 8000000 in

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
  unfold rlp.bytes_to_u64
  simp only [SharedASlice.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter, lift]
  step* <;> first | scalar_tac | skip
  · -- empty path (¬ len>8, is_empty true)
    rename_i hb_eq
    have hempty : bytes.val.length = 0 := by
      have h := b_post
      rw [hb_eq] at h
      have h3 := (show (true = true) = (bytes.length = 0) from h)
      simp at h3
      simpa using h3
    let* ⟨acc, hacc⟩ ← bytes_to_u64_loop0_value ⟨bytes, 0⟩ 0#u64
      (by simpa using by omega) (by simpa using by omega) (by simp [beValue])
    try simp only [WP.spec_ok]
    refine ⟨fun hgt => absurd hgt (by omega), fun _ hex => ?_, fun _ _ => ⟨acc, rfl, by simpa using hacc⟩⟩
    obtain ⟨b0, tl, heq, _⟩ := hex
    exfalso
    rw [heq] at hempty
    simp at hempty
  · -- Err LeadingZero branch (nonempty, first byte 0)
    rename_i hnb hz
    have hnonempty : bytes.val.length ≠ 0 := by
      intro h0
      apply hnb
      have hlen0 : bytes.length = 0 := by simpa using h0
      exact Eq.mp b_post.symm hlen0
    have hnenil : bytes.val ≠ [] := by
      intro hnil
      exact hnonempty (by rw [hnil]; rfl)
    refine ⟨fun hgt => ?_, by first | exact trivial | (intro _ _; rfl) | (intro _ _; trivial),
            fun _ hforall => ?_⟩
    · exfalso; scalar_tac
    · exfalso
      obtain ⟨b0, tl, heq⟩ := List.exists_cons_of_ne_nil hnenil
      apply hforall b0 tl heq
      have hb0 : i1 = b0 := by
        rw [i1_post, ← getElem!_pos _ _ (by omega), heq, List.getElem!_cons_zero]
      rw [← hb0, hz]
      rfl
  · -- Ok branch via loop1
    rename_i hnb hnz
    let* ⟨acc, hacc⟩ ← bytes_to_u64_loop1_value ⟨bytes, 0⟩ 0#u64
      (by simpa using by scalar_tac) (by simpa using by omega) (by simp [beValue])
    try simp only [WP.spec_ok]
    refine ⟨fun hgt => ?_, fun _ hex => ?_, fun _ _ => ⟨acc, rfl, by simpa using hacc⟩⟩
    · exfalso; scalar_tac
    · exfalso
      obtain ⟨b0, tl, heq, hb00⟩ := hex
      apply hnz
      have hb0 : i1 = b0 := by
        rw [i1_post, ← getElem!_pos _ _ (by rw [heq]; simp), heq, List.getElem!_cons_zero]
      rw [hb0]
      apply UScalar.eq_of_val_eq
      simpa using hb00

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
  unfold rlp.bytes_to_u256
  step* <;> first | scalar_tac | skip
  · -- goal 1: empty-Ok
    have hb_eq : b = true := ‹_›
    have hlen0 : bytes.val.length = 0 := by
      have h := b_post
      rw [hb_eq] at h
      have h3 := (show (true = true) = (bytes.length = 0) from h)
      simp at h3
      simpa using h3
    refine ⟨fun hgt => by exfalso; omega, fun hle hex => ?_, fun hle hall => ?_⟩
    · exfalso
      obtain ⟨b0, tl, heq, _⟩ := hex
      rw [heq] at hlen0
      simp at hlen0
    · refine ⟨index_mut_back s1, rfl, ?_⟩
      rw [s_post3, s1_post]
      simp only [Array.repeat_val]
      norm_num
      rw [Extracted.SetSlice.rightAlign_word off.val bytes.val (by scalar_tac) (by scalar_tac)]
      have hoffv : off.val = 32 - bytes.val.length := by scalar_tac
      rw [hoffv]
  · -- goal 2: Err LeadingZero
    have hnb : ¬ b = true := ‹_›
    have hz : i1 = 0#u8 := ‹_›
    have hnonempty : bytes.val.length ≠ 0 := by
      intro h0
      apply hnb
      have hl0 : bytes.length = 0 := by simpa using h0
      exact Eq.mp b_post.symm hl0
    have hnenil : bytes.val ≠ [] := by
      intro hnil
      exact hnonempty (by rw [hnil]; rfl)
    refine ⟨fun hgt => by exfalso; scalar_tac,
            by first | exact trivial | (intro _ _; rfl) | (intro _ _; trivial),
            fun _ hforall => ?_⟩
    exfalso
    obtain ⟨b0, tl, heq⟩ := List.exists_cons_of_ne_nil hnenil
    apply hforall b0 tl heq
    have hb0 : i1 = b0 := by
      rw [i1_post, ← getElem!_pos _ _ (by omega), heq, List.getElem!_cons_zero]
    rw [← hb0, hz]
    rfl
  · -- goal 3: nonempty-Ok
    have hnz : ¬ i1 = 0#u8 := ‹_›
    refine ⟨fun hgt => by exfalso; scalar_tac, fun hle hex => ?_, fun hle hall => ?_⟩
    · exfalso
      obtain ⟨b0, tl, heq, hb00⟩ := hex
      apply hnz
      have hb0 : i1 = b0 := by
        rw [i1_post, ← getElem!_pos _ _ (by rw [heq]; simp), heq, List.getElem!_cons_zero]
      rw [hb0]
      apply UScalar.eq_of_val_eq
      simpa using hb00
    · refine ⟨index_mut_back s1, rfl, ?_⟩
      rw [s_post3, s1_post]
      simp only [Array.repeat_val]
      norm_num
      rw [Extracted.SetSlice.rightAlign_word off.val bytes.val (by scalar_tac) (by scalar_tac)]
      have hoffv : off.val = 32 - bytes.val.length := by scalar_tac
      rw [hoffv]

end Extracted.Equiv
