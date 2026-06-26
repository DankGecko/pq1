/- §33 rank (FV-#2 sequel) — `domain::slot_entropy` byte-layout.

   `slot_entropy` is THE chain-binding step of the slot-key derivation
   (invariant #8): it must hash exactly `master_entropy ‖ "slot_entropy" ‖
   chain_id_be ‖ slot_index_be`, so a slot key is unique per (chain_id,
   slot_index) and an attacker who learns a slot key on chain A cannot replay
   it on chain B. The FV-#2 refactor funneled this through the single-shot
   `sha256_bytes`, making it Aeneas-extractable; this rank proves the extracted
   code hashes exactly that canonical preimage in the documented order.

   Proof shape mirrors `AdrsEquiv.make_adrs_spec` (the same `Array.index_mut` +
   `copy_from_slice` buffer-building): `unfold; step*` then reduce the buffer
   ops to a byte concatenation. The function ends in the opaque single-shot
   hash, so the spec characterises the PREIMAGE (it holds for any pure hash).

   Kernel-clean modulo the disclosed `sha256_pure_bytes` hash axiom (the
   FV-#2 `sha256_bytes` boundary) — same status as the project's `sha256_pure`. -/
import Extracted.SlotKdf.Funs
import Extracted.AdrsEquiv

set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

/-- ASCII bytes of the `"slot_entropy"` domain label. -/
def slotEntropyLabel : List Nat :=
  [115, 108, 111, 116, 95, 101, 110, 116, 114, 111, 112, 121]

/-- Canonical 56-byte preimage `slot_entropy` SHA-256's:
    `master[32] ‖ "slot_entropy"[12] ‖ chain_id_be[8] ‖ slot_index_be[4]`. -/
def slotEntropyPreimage (master : List Nat) (chain slot : Nat) : List Nat :=
  master ++ slotEntropyLabel ++ u64be chain ++ u32be slot

/-- The four nested `setSlice!`s the extracted buffer-building performs collapse
    to the segment concatenation, given the segment lengths (32 ‖ 12 ‖ 8 ‖ 4 = 56)
    and any 56-byte base: the four segments cover `[0,56)` contiguously, so the
    base content is fully overwritten and irrelevant. Base-generic so the caller
    needn't reduce the `Array.repeat`-derived base's literal coercions. -/
theorem setSlice56_layout
    (base m lbl c s : List Nat) (hbase : base.length = 56)
    (hm : m.length = 32) (hl : lbl.length = 12) (hc : c.length = 8) (hs : s.length = 4) :
    ((((base.setSlice! 0 m).setSlice! 32 lbl).setSlice! 44 c).setSlice! 52 s)
      = m ++ lbl ++ c ++ s := by
  simp only [List.setSlice!, hm, hl, hc, hs, hbase,
             List.length_append, List.take_append, List.drop_append,
             List.append_assoc]
  simp +arith [List.take_of_length_le, List.drop_eq_nil_of_le, hm, hl, hc, hs, hbase,
               List.length_append, List.take_append, List.drop_append, List.drop_drop]

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 1000000 in
/-- **`slot_entropy` hashes exactly the canonical chain-bound preimage**
    (invariant #8 byte-layout). For all inputs, the extracted `slot_entropy`
    returns `sha256(master ‖ "slot_entropy" ‖ chain_be ‖ slot_be)` — the
    chain_id and slot_index are bound into the hash preimage in the documented
    order, so slot keys are per-(chain,slot) unique. -/
theorem slot_entropy_hashes_canonical_preimage
    (master : Std.Array U8 32#usize) (chain : U64) (slot : U32) :
    pqsigner_domain.slot_entropy master chain slot ⦃ r =>
      ∃ pre : Slice U8,
        pre.val.map (·.val)
          = slotEntropyPreimage (master.val.map (·.val)) chain.val slot.val
        ∧ r = sha256_pure_bytes pre ⦄ := by
  -- The input array's byte-length, needed to resolve the take/drop the
  -- setSlice! expansion produces (master fills bytes [0..32)).
  have l_master : master.val.length = 32 := by have := master.property; simp_all
  unfold pqsigner_domain.slot_entropy
  simp only [sha256_bytes]
  step*
  refine ⟨_, ?_, rfl⟩
  -- `s12 = to_slice buf4`, so strip the `to_slice` (Array.val_to_slice) IN THE
  -- SAME pass that applies the setSlice-writer post hyps, else the wrapper
  -- blocks them (make_adrs returns the array directly and needs no strip).
  -- `Array.make` unfolds the literal "slot_entropy" label; `Array.length_to_slice`
  -- + `l_master` give the lengths the take/drop need.
  -- Strip to_slice + distribute the outer `map` into each `setSlice!` (keeping
  -- setSlice! intact) + reduce each segment (label via Array.make, chain/slot
  -- via toBEBytes*). Leaves the 4 nested setSlice!s over a 56-zero base.
  simp only [*, Array.val_to_slice, Array.length_to_slice, List.map_setSlice!,
             Array.repeat_val, List.map_replicate, Array.make, map_val_mk,
             toBEBytes64_map_toNat, toBEBytes32_map_toNat]
  -- Collapse the nested setSlice!s to the segment concatenation (helper):
  -- base, m, lbl, c, s inferred; lengths discharged by simp.
  rw [setSlice56_layout _ _ _ _ _
        (by simp) (by rw [List.length_map]; exact l_master) (by simp)
        (by simp [u64be]) (by simp [u32be])]
  simp [slotEntropyPreimage, slotEntropyLabel]

end Extracted.Equiv
