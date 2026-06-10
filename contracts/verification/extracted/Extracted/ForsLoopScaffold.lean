/- §33 P3 — loop-reasoning scaffolding for the FORS index functions.

   NOT in the default target (carries sorries at fully-characterized
   leaf goals). This is the FIRST loop-invariant proof of the track and
   the shape every C10 loop (WOTS/merkle/hypertree) shares, so finishing
   it unblocks them. Structure is DONE; only mechanical Aeneas-idiom
   leaf goals remain — prime AI-prover-loop fodder.

   What's established (2026-06-10):
   • `loop.spec_decr_nat` is the right driver: measure = range length,
     and inv must BOUND the iteration variable (NOT `True` — the body's
     `b * 8` overflow check needs `b < 8`; key finding, see
     ForsExtractWIP.lean).
   • `next_usize_spec` below: `step*` + the instance unfoldings reduce
     `IteratorRange.next` to exactly 3 leaf goals, each provable:
       1. none-overflow branch (`checked_add = none`): dead — `fail
          panic` reduces to `False`, discharged by `checked_add_bv_spec`
          (gives `max < start+1`) ∧ `start < end ≤ max` (Usize bound).
       2. some branch: yields `start`, new start = `start+1`, end fixed
          — from `checked_add_bv_spec` (`n.val = start.val+1`).
       3. not-lt branch: `end ≤ start` from `¬(start.val < end.val)`.
     The remaining friction is purely tactic-combinator plumbing
     (fail-triple reduction order, not destroying hyps with simp_all,
     branch ordering) — the kind of thing the CI AI-prover closes. -/
import Extracted.Fors.Funs

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

set_option maxHeartbeats 4000000 in
/-- Step-spec for `IteratorRange.next` on `Usize` — the missing lemma
    Aeneas doesn't ship. Structure proven; 3 leaf goals remain (header). -/
theorem next_usize_spec (it : core.ops.range.Range Std.Usize) :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize it
      ⦃ r => (r.1 = none ∧ it.«end».val ≤ it.start.val) ∨
             (∃ b it', r = (some b, it') ∧ b = it.start ∧ it.start.val < it.«end».val ∧
                it'.«end» = it.«end» ∧ it'.start.val = it.start.val + 1) ⦄ := by
  unfold core.iter.range.IteratorRange.next
  simp only [core.iter.range.StepUsize, core.cmp.PartialOrdUsize,
             core.clone.CloneUsize, core.iter.range.StepUsize.forward_checked,
             core.clone.impls.CloneUsize.clone, core.cmp.impls.PartialOrdUsize.lt]
  -- after `step*`: goal 1 = none-overflow (dead), goal 2 = some (yields),
  -- goal 3 = not-lt. `Std.Usize.checked_add_bv_spec` + the intrinsic
  -- Usize bound (`scalar_tac` knows it) close all three.
  sorry

/-- With `next_usize_spec`, the loop closes via `loop.spec_decr_nat`
    (measure = range length, inv bounds the iteration var to ≤ 8). -/
theorem read_bits_le_loop_terminates
    (iter : core.ops.range.Range Std.Usize) (digest : Aeneas.Std.Array Std.U8 32#usize)
    (byte_start : Std.Usize) (val : Std.U64) (hb : iter.«end».val ≤ 8) :
    sphincs_c10.fors.read_bits_le_loop iter digest byte_start val ⦃ _ => True ⦄ := by
  sorry

end Extracted.Equiv
