/- §33 axiom-collapse — `hash.chain_hash` spec: the extracted loop (per-step
   ADRS chain-position tweak at bytes [24..28) + `th` + `pad16`) computes
   exactly `chain_hash_pure`'s fold, for `start + steps ≤ u32::MAX` (the
   per-step `start_pos + step` would panic past that; the WOTS+C caller
   passes start = digit ≤ 7, steps = 7 − digit). -/
import Extracted.HashSpecs.Th
import Extracted.HashSpecs.WotsDigest

set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false
set_option maxHeartbeats 8000000

open Aeneas Aeneas.Std Result
open Extracted.SetSlice

namespace sphincs_c10

/-- `Range<u32>` iterator step — clone of `Extracted.Equiv.next_usize_spec`
    for the extraction-local `U32.Insts.CoreIterRangeStep` instance. -/
theorem next_u32_spec (it : core.ops.range.Range Std.U32) :
    core.iter.range.IteratorRange.next U32.Insts.CoreIterRangeStep it
      ⦃ r => (r.1 = none ∧ it.«end».val ≤ it.start.val) ∨
             (∃ b it', r = (some b, it') ∧ b = it.start ∧ it.start.val < it.«end».val ∧
                it'.«end» = it.«end» ∧ it'.start.val = it.start.val + 1) ⦄ := by
  unfold core.iter.range.IteratorRange.next
  simp only [U32.Insts.CoreIterRangeStep, core.cmp.PartialOrdU32,
             core.clone.CloneU32, U32.Insts.CoreIterRangeStep.forward_checked,
             core.clone.impls.CloneU32.clone, core.cmp.impls.PartialOrdU32.lt,
             liftFun1, liftFun2, bind_tc_ok]
  have hb : it.«end».val ≤ U32.max := by scalar_tac
  have h1v : (1#usize).val = 1 := by scalar_tac
  split
  · rename_i hlt
    simp only [decide_eq_true_eq] at hlt
    have hfits : it.start.val + (1#usize).val ≤ U32.max := by
      rw [h1v]; omega
    split
    · -- forward_checked = none: contradicts hfits
      rename_i hnone
      rw [if_pos hfits] at hnone
      simp at hnone
    · rename_i n hsome
      rw [if_pos hfits] at hsome
      injection hsome with hn
      simp only [WP.spec_ok]
      right
      refine ⟨it.start, _, rfl, rfl, by scalar_tac, rfl, ?_⟩
      show n.val = it.start.val + 1
      rw [← hn]
      show (BitVec.ofNat 32 (it.start.val + (1#usize).val)).toNat = it.start.val + 1
      rw [BitVec.toNat_ofNat, h1v]
      exact Nat.mod_eq_of_lt (by scalar_tac)
  · rename_i hge
    simp only [decide_eq_true_eq] at hge
    simp only [WP.spec_ok]
    left
    refine ⟨?_, ?_⟩ <;> first | trivial | rfl | scalar_tac

/-- Local (non-`@[step]`) pad16 spec against `pad16Pure` — applied
    explicitly so it cannot race the `pad16p`-valued `@[step] pad16_spec`
    in `MerkleVerifySpec.lean`. -/
theorem pad16_pure_spec (v : Std.Array Std.U8 16#usize) :
    hash.pad16 v ⦃ r => r = pad16Pure v ⦄ := by
  have hv : v.val.length = 16 := by have := v.property; simp_all
  unfold hash.pad16
  step* <;>
    first
    | scalar_tac
    | (simp only [params.N, Slice.length, Array.length_to_slice]; scalar_tac)
    | (simp only [params.N, Slice.length, Array.length_to_slice] at *; scalar_tac)
    | skip
  apply Subtype.ext
  rw [pad16Pure_val]
  have h := setSlice!_append_replicate ([] : List Std.U8) 32 v.val 0#u8
    (by rw [hv]; omega)
  simp only [List.nil_append, List.length_nil, hv] at h
  simp_all [params.N]

/-- `setSlice!` of 4 bytes at offset 24 in a 32-byte list, decomposed. -/
theorem setSlice24 (l w : List Std.U8) (hl : l.length = 32) (hw : w.length = 4) :
    l.setSlice! 24 w = l.take 24 ++ w ++ l.drop 28 := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, hl, hw]
  intro j
  by_cases h0 : j < 24
  · simp_lists [*]
  by_cases h1 : j < 28
  · simp_lists [*] <;> simp [Nat.min_def]
  by_cases h2 : j < 32
  · simp_lists [*]
    have hlw : (List.take 24 l ++ w).length = 28 := by simp [hl, hw]
    simp only [hlw]
    congr 1
    omega
  · simp_lists [*]

/-- `u32beBytes` is 4 bytes long. -/
theorem u32beBytes_length (n : Nat) : (u32beBytes n).length = 4 := by
  simp [u32beBytes]

/-- `chainAdrs` preserves the first 24 bytes. -/
theorem chainAdrs_take24 (adrs : Std.Array Std.U8 32#usize) (p : Nat) :
    (chainAdrs adrs p).val.take 24 = adrs.val.take 24 := by
  have h : adrs.val.length = 32 := by have := adrs.property; simp_all
  have h24 : (adrs.val.take 24).length = 24 := by simp [h]
  rw [chainAdrs_val, List.append_assoc, List.take_left' h24]

/-- `chainAdrs` preserves the last 4 bytes. -/
theorem chainAdrs_drop28 (adrs : Std.Array Std.U8 32#usize) (p : Nat) :
    (chainAdrs adrs p).val.drop 28 = adrs.val.drop 28 := by
  have h : adrs.val.length = 32 := by have := adrs.property; simp_all
  have h28 : (adrs.val.take 24 ++ u32beBytes p).length = 28 := by
    simp [h, u32beBytes_length]
  rw [chainAdrs_val, List.drop_left' h28]

/-- Chain loop: each iteration writes BE(start+k) into the ADRS chain-pos
    field and folds one `th`; the running value is `chain_hash_pure`'s fold
    prefix, and the ADRS side fields are preserved across iterations. -/
theorem chain_hash_loop_value
    (seed adrs0 : Std.Array Std.U8 32#usize) (x : Std.Array Std.U8 16#usize)
    (start_pos steps : Std.U32) (iter : core.ops.range.Range Std.U32)
    (current a : Std.Array Std.U8 32#usize)
    (hend : iter.«end» = steps)
    (hle : iter.start.val ≤ steps.val)
    (hovf : start_pos.val + steps.val ≤ U32.max)
    (hcur : current = (List.range iter.start.val).foldl
        (fun cur i => pad16Pure (th_pure seed (chainAdrs adrs0 (start_pos.val + i)) cur))
        (pad16Pure x))
    (ht24 : a.val.take 24 = adrs0.val.take 24)
    (hd28 : a.val.drop 28 = adrs0.val.drop 28) :
    hash.chain_hash_loop iter seed start_pos current a
      ⦃ r => r = (List.range steps.val).foldl
          (fun cur i => pad16Pure (th_pure seed (chainAdrs adrs0 (start_pos.val + i)) cur))
          (pad16Pure x) ⦄ := by
  unfold hash.chain_hash_loop
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.U32 ×
        Std.Array Std.U8 32#usize × Std.Array Std.U8 32#usize) =>
       s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.U32 ×
        Std.Array Std.U8 32#usize × Std.Array Std.U8 32#usize) =>
       s.1.«end» = steps ∧ s.1.start.val ≤ steps.val ∧
       s.2.1 = (List.range s.1.start.val).foldl
         (fun cur i => pad16Pure (th_pure seed (chainAdrs adrs0 (start_pos.val + i)) cur))
         (pad16Pure x) ∧
       s.2.2.val.take 24 = adrs0.val.take 24 ∧
       s.2.2.val.drop 28 = adrs0.val.drop 28)
  · rintro ⟨it, cur, av⟩ ⟨hbnd, hsle, hcurv, h24, h28⟩
    simp only at hbnd hsle hcurv h24 h28
    unfold hash.chain_hash_loop.body
    let* ⟨ob, iter1, hpost⟩ ← next_u32_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨stp, it', heq, hstp, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      have hbv : it.«end».val = steps.val := by rw [hbnd]
      rw [hcurv, show it.start.val = steps.val from by omega]
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      subst hstp
      have hklt : it.start.val < steps.val := by
        have hbv : it.«end».val = steps.val := by rw [hbnd]
        omega
      have hav32 : av.val.length = 32 := by have := av.property; simp_all
      step* <;> first | scalar_tac | skip
      -- the written-back ADRS is exactly chainAdrs adrs0 pos
      have ha2 : index_mut_back s2 = chainAdrs adrs0 pos.val := by
        apply Subtype.ext
        rw [s_post3, s2_post, s1_post, Array.val_to_slice, a1_post,
            u32_toBEBytes_map_mk pos,
            setSlice24 _ _ hav32 (u32beBytes_length _), h24, h28, chainAdrs_val]
      -- the pad16 of the new chain value
      let* ⟨cur1, hcur1⟩ ← pad16_pure_spec
      have hebv : iter1.«end».val = it.«end».val := by rw [hend']
      refine ⟨by rw [hend']; exact hbnd, by omega, ?_,
              by rw [ha2]; exact chainAdrs_take24 _ _,
              by rw [ha2]; exact chainAdrs_drop28 _ _,
              by omega⟩
      -- fold prefix extends by one step
      rw [hcur1, a3_post, ha2, pos_post, hcurv, hstart',
          List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
  · exact ⟨hend, hle, hcur, ht24, hd28⟩

/-- **`chain_hash` spec** — for `start + steps ≤ u32::MAX` (the WOTS+C caller
    passes start = digit ≤ 7, steps = 7 − digit), the extracted body computes
    exactly `chain_hash_pure`'s `th`-fold with the per-step ADRS tweak. -/
@[step] theorem hash.chain_hash_spec (seed adrs : Std.Array Std.U8 32#usize)
    (x : Std.Array Std.U8 16#usize) (start steps : Std.U32)
    (hovf : start.val + steps.val ≤ U32.max) :
    hash.chain_hash seed adrs x start steps
      ⦃ r => r = chain_hash_pure seed adrs x start steps ⦄ := by
  unfold hash.chain_hash
  let* ⟨c0, hc0⟩ ← pad16_pure_spec
  let* ⟨c1, hc1⟩ ← chain_hash_loop_value seed adrs x start steps
    { start := 0#u32, «end» := steps } c0 adrs rfl (by scalar_tac) hovf
    (by rw [hc0]; rfl) rfl rfl
  step*
  rw [chain_hash_pure_def, r_post, hc1]

end sphincs_c10
