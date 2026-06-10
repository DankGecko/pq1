/- §33 P3 — `next_usize_spec` PROVEN (the foundational loop lemma).

   `Aeneas.Std.IteratorRange.next` ships as a DEF with no step-spec, so
   no `Range`-iterating loop could be reasoned about. This file proves
   that spec (kernel-clean, no sorry), tagged `@[step]` so `step*`
   consumes it. It unblocks EVERY `0..n` loop in the C10 code
   (read_bits_le, the WOTS/FORS/merkle/hypertree tree walks).

   `read_bits_le_loop_terminates` (panic-freedom of the FORS bit-reader
   loop) is then within reach via `Aeneas.Std.loop.spec_decr_nat`
   (measure = range length; invariant bounds start.val ≤ 8 so the
   body's `it.start * 8` can't overflow — see ForsExtractWIP.lean). The
   loop STRUCTURE + the `next` step are done; what remains is `@[step]`
   specs for the body's remaining primitives — `FromU64U8.from`
   (u8→u64 widening, total), `<<<` (u64 shift), `|||` (u64 or) — each a
   one-line lemma, then the overflow + measure-decrease close by
   `scalar_tac`. Pure primitive plumbing — AI-loop fodder. -/
import Extracted.Fors.Funs

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

set_option maxHeartbeats 4000000 in
@[step]
theorem next_usize_spec (it : core.ops.range.Range Std.Usize) :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize it
      ⦃ r => (r.1 = none ∧ it.«end».val ≤ it.start.val) ∨
             (∃ b it', r = (some b, it') ∧ b = it.start ∧ it.start.val < it.«end».val ∧
                it'.«end» = it.«end» ∧ it'.start.val = it.start.val + 1) ⦄ := by
  unfold core.iter.range.IteratorRange.next
  simp only [core.iter.range.StepUsize, core.cmp.PartialOrdUsize,
             core.clone.CloneUsize, core.iter.range.StepUsize.forward_checked,
             core.clone.impls.CloneUsize.clone, core.cmp.impls.PartialOrdUsize.lt,
             liftFun1, liftFun2, bind_tc_ok]
  have hb : it.«end».val ≤ Std.Usize.max := by scalar_tac
  split
  · rename_i hlt
    have hadd := Std.Usize.checked_add_bv_spec it.start 1#usize
    split
    · rename_i hnone
      rw [hnone] at hadd
      simp only [WP.spec_fail]
      scalar_tac
    · rename_i n hsome
      rw [hsome] at hadd
      simp only [WP.spec_ok]
      right
      exact ⟨it.start, _, rfl, rfl, by scalar_tac, rfl, by scalar_tac⟩
  · rename_i hge
    simp only [WP.spec_ok]
    left
    refine ⟨?_, ?_⟩ <;> first | trivial | scalar_tac

open sphincs_c10 in
set_option maxHeartbeats 8000000 in
/-- Panic-freedom of the FORS bit-reader loop — PROVEN (no sorry). The
    first complete loop-reasoning proof of the track: `loop.spec_decr_nat`
    (measure = range length), `next_usize_spec` for the iterator step,
    `it.start < it.end ≤ 8 ⟹ it.start ≤ 7` to discharge the body's
    `it.start * 8` / shift bounds, and the @[step] specs for
    mul/shift/or/from. -/
@[step]
theorem read_bits_le_loop_terminates
    (iter : core.ops.range.Range Std.Usize) (digest : Std.Array Std.U8 32#usize)
    (byte_start : Std.Usize) (val : Std.U64) (hb8 : iter.«end».val ≤ 8) :
    fors.read_bits_le_loop iter digest byte_start val ⦃ _ => True ⦄ := by
  unfold fors.read_bits_le_loop
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize × Std.U64) => s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize × Std.U64) => s.1.«end».val ≤ 8)
  · rintro ⟨it, v⟩ hend8
    unfold fors.read_bits_le_loop.body
    simp only []
    let* ⟨o, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hle⟩ | ⟨b, it', heq, hb, hlt, hend, hstart⟩
    · simp_all
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have h7 : it.start.val ≤ 7 := by scalar_tac
      simp only [lift]
      step* <;>
        first
        | scalar_tac
        | (refine ⟨?_, ?_⟩ <;> scalar_tac)
        | simp_all
        | trivial
  · exact hb8


open sphincs_c10 in
set_option maxHeartbeats 8000000 in
theorem read_bits_le_terminates (digest : Std.Array Std.U8 32#usize)
    (bit_offset num_bits : Std.Usize)
    (hpos : 0 < num_bits.val) (h : num_bits.val ≤ 57) (hoff : bit_offset.val ≤ 248) :
    fors.read_bits_le digest bit_offset num_bits ⦃ _ => True ⦄ := by
  unfold fors.read_bits_le
  have hp : (0:Nat) < 2 ^ num_bits.val := Nat.two_pow_pos _
  have hlt64 : (2:Nat) ^ num_bits.val < U64.size := by
    have hsz : U64.size = 2 ^ 64 := by simp [U64.size, U64.numBits]
    rw [hsz]
    calc (2:Nat) ^ num_bits.val ≤ 2 ^ 57 := Nat.pow_le_pow_right (by norm_num) h
      _ < 2 ^ 64 := Nat.pow_lt_pow_right (by norm_num) (by norm_num)
  step* <;>
    first
    | scalar_tac
    | (rw [Nat.shiftLeft_eq, Nat.one_mul, Nat.mod_eq_of_lt hlt64]; omega)
    | simp_all
    | trivial

attribute [step] read_bits_le_terminates

open sphincs_c10 in
set_option maxHeartbeats 8000000 in
theorem extract_ht_index_terminates (digest : Std.Array Std.U8 32#usize) :
    fors.extract_ht_index digest ⦃ _ => True ⦄ := by
  unfold fors.extract_ht_index
  simp only [params.K, params.A, params.H]
  step* <;>
    first
    | (apply read_bits_le_terminates <;> scalar_tac)
    | scalar_tac
    | trivial

end Extracted.Equiv
