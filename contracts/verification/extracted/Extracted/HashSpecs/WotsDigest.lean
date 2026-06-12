/- §33 axiom-collapse — `hash.wots_digest` spec: the extracted body (fresh
   128-zero buffer; seed at [0..32), wots_adrs at [32..64), msg_hash at
   [64..96), `count.to_be_bytes()` at [124..128), the [96..124) gap left
   zero; full 32-byte sha256 — no truncate) returns exactly
   `wots_digest_pure seed adrs padded count`. -/
import Extracted.Hash.Funs
import Extracted.HashPure
import Extracted.SetSliceLemmas
import Extracted.AdrsEquiv

set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false
set_option linter.unreachableTactic false
set_option linter.unnecessarySeqFocus false
set_option linter.unnecessarySimpa false

open Aeneas Aeneas.Std Result
open Extracted.SetSlice

namespace sphincs_c10

/-- Bridge: Aeneas's `u32::to_be_bytes` byte list (`bv.toBEBytes.map mk`)
    is the pure `u32beBytes`. -/
theorem u32_toBEBytes_map_mk (x : Std.U32) :
    x.bv.toBEBytes.map (@UScalar.mk .U8) = u32beBytes x.val := by
  have h : ∀ k : Nat,
      (UScalar.mk ((x.bv >>> k).setWidth 8) : Std.U8) = ⟨BitVec.ofNat 8 (x.val >>> k)⟩ := by
    intro k
    congr 1
  have h0 : (UScalar.mk (x.bv.setWidth 8) : Std.U8) = ⟨BitVec.ofNat 8 x.val⟩ := by
    have hk := h 0
    simpa using hk
  simp only [BitVec.toBEBytes, Extracted.Equiv.toLEBytes32_eq, List.reverse_cons,
             List.reverse_nil, List.nil_append, List.cons_append, List.map_cons,
             List.map_nil, u32beBytes, h, h0]

set_option maxRecDepth 16384 in
/-- The wots_digest 128-B preimage buffer: seed/adrs/msg words at 0/32/64,
    the count word at 124, the [96..124) gap untouched zeros. -/
theorem wotsBuf_eq (a b c w : List Std.U8)
    (ha : a.length = 32) (hb : b.length = 32) (hc : c.length = 32) (hw : w.length = 4) :
    ((((List.replicate 128 0#u8).setSlice! 0 a).setSlice! 32 b).setSlice! 64 c).setSlice! 124 w
      = a ++ b ++ c ++ (List.replicate 28 0#u8 ++ w) := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, List.length_append, List.length_replicate, *]
  intro j
  by_cases h0 : j < 32
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, ha, hb, hc, hw] <;> omega
  by_cases h1 : j < 64
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, ha, hb, hc, hw] <;> omega
  by_cases h2 : j < 96
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, ha, hb, hc, hw] <;> omega
  by_cases h3 : j < 124
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, ha, hb, hc, hw] <;> omega
  by_cases h4 : j < 128
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, ha, hb, hc, hw] <;> omega
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, ha, hb, hc, hw] <;> omega

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 16384 in
@[step] theorem hash.wots_digest_spec (seed adrs padded : Std.Array Std.U8 32#usize) (count : Std.U32) :
    hash.wots_digest seed adrs padded count ⦃ r => r = wots_digest_pure seed adrs padded count ⦄ := by
  have l_seed : seed.val.length = 32 := by have := seed.property; simp_all
  have l_adrs : adrs.val.length = 32 := by have := adrs.property; simp_all
  have l_pad : padded.val.length = 32 := by have := padded.property; simp_all
  have l_w : (count.bv.toBEBytes.map (@UScalar.mk .U8)).length = 4 := by
    rw [List.length_map, BitVec.toBEBytes_length]
  unfold hash.wots_digest
  step* <;>
    first
    | scalar_tac
    | (simp only [Slice.length, Array.length_to_slice] at *; scalar_tac)
    | skip
  have hbuf : (s12 : List Std.U8)
      = seed.val ++ adrs.val ++ padded.val
        ++ (List.replicate 28 0#u8 ++ u32beBytes count.val) := by
    simp only [s12_post, s11_post, s10_post, s9_post3, s8_post, s7_post, s6_post3,
               s5_post, s4_post, s3_post3, s2_post, s1_post, s_post3, a_post,
               Array.val_to_slice, Array.repeat_val]
    norm_num
    rw [wotsBuf_eq _ _ _ _ l_seed l_adrs l_pad l_w, u32_toBEBytes_map_mk]
    simp only [List.append_assoc]
  rw [r_post, hbuf, wots_digest_pure_def]

end sphincs_c10
