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

set_option maxHeartbeats 4000000 in
/-- Panic-freedom of the FORS bit-reader loop. Structure + the `next`
    step are done; blocked on a few primitive `@[step]` specs (header). -/
theorem read_bits_le_loop_terminates
    (iter : core.ops.range.Range Std.Usize) (digest : Std.Array Std.U8 32#usize)
    (byte_start : Std.Usize) (val : Std.U64) (hb8 : iter.«end».val ≤ 8) :
    sphincs_c10.fors.read_bits_le_loop iter digest byte_start val ⦃ _ => True ⦄ := by
  sorry

end Extracted.Equiv
