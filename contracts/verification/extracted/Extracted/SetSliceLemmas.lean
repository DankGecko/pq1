/- §33 — reusable `List.setSlice!` reductions for the byte-layout
   equivalence proofs. These turn the `setSlice!` towers that Aeneas
   emits for fixed-offset buffer assembly (ADRS, userOpHash, and the
   P3 wots/fors/merkle serializers) into plain list concatenations.

   All kernel-clean (no sorry, no extra axioms). -/
import Extracted.UserOp.Funs

open Aeneas Aeneas.Std Result

namespace Extracted.SetSlice

/-- Writing a word at the boundary of a prefix inside `pre ++ replicate
    m x` appends it and shrinks the zero tail. The atomic step of every
    fixed-offset buffer assembly. -/
theorem setSlice!_append_replicate {α} (pre : List α) (m : Nat) (w : List α)
    (x : α) (hw : w.length ≤ m) :
    (pre ++ List.replicate m x).setSlice! pre.length w
      = pre ++ w ++ List.replicate (m - w.length) x := by
  simp only [List.setSlice!]
  have e1 : List.take pre.length (pre ++ List.replicate m x) = pre := by
    simp [List.take_append]
  have e2 : (pre ++ List.replicate m x).length - pre.length = m := by simp
  rw [e1, e2]
  have e3 : min w.length m = w.length := by omega
  rw [e3, List.take_of_length_le (by omega), List.drop_append]
  simp [List.drop_replicate, List.append_assoc]

set_option maxRecDepth 16384 in
/-- A `u64`/address right-aligned into a fresh 32-zero word. -/
theorem rightAlign_word (k : Nat) (cb : List U8) (hc : cb.length = 32 - k)
    (hk : k ≤ 32) :
    (List.replicate 32 0#u8).setSlice! k cb = List.replicate k 0#u8 ++ cb := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, *]
  intro j
  by_cases hjk : j < k
  · simp_lists [List.length_replicate, *]
  by_cases hj32 : j < 32
  · simp_lists [List.length_replicate, *] <;> (try (congr 1 <;> omega)) <;> (try omega)
  · simp_lists [List.length_replicate, *]

set_option maxRecDepth 16384 in
/-- The 10-word `compute_user_op_hash` inner buffer (`hashStruct`
    preimage): sender (20 B) right-aligned at 12, then nine 32-B words
    at 32, 64, …, 288 = the concatenation. -/
theorem innerBuf_eq
    (sd no ic cd cg vg pv mf mp pd : List U8)
    (h0 : sd.length = 20) (h1 : no.length = 32) (h2 : ic.length = 32)
    (h3 : cd.length = 32) (h4 : cg.length = 32) (h5 : vg.length = 32)
    (h6 : pv.length = 32) (h7 : mf.length = 32) (h8 : mp.length = 32)
    (h9 : pd.length = 32) :
    ((((((((((List.replicate 320 0#u8).setSlice! 12 sd).setSlice! 32 no).setSlice! 64 ic).setSlice! 96 cd).setSlice! 128 cg).setSlice! 160 vg).setSlice! 192 pv).setSlice! 224 mf).setSlice! 256 mp).setSlice! 288 pd
      = (List.replicate 12 0#u8 ++ sd) ++ no ++ ic ++ cd ++ cg ++ vg ++ pv ++ mf ++ mp ++ pd := by
  apply List.ext_getElem!
  · simp only [List.length_setSlice!, List.length_replicate, List.length_append, *]
  intro j
  by_cases h12 : j < 12
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h32 : j < 32
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h64 : j < 64
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h96 : j < 96
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h128 : j < 128
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h160 : j < 160
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h192 : j < 192
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h224 : j < 224
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h256 : j < 256
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h288 : j < 288
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h320 : j < 320
  · simp_lists [List.length_replicate, List.length_append, *]
  · simp_lists [List.length_replicate, List.length_append, *]

set_option maxRecDepth 16384 in
/-- The 3-region `compute_user_op_hash` outer buffer
    (`abi.encode(inner, entryPoint, chainId)`): inner (32) at 0,
    entryPoint (20) right-aligned at 44, chainId word at 64. -/
theorem outerBuf_eq (inner ep cb : List U8)
    (hi : inner.length = 32) (he : ep.length = 20) (hc : cb.length = 8) :
    (((List.replicate 96 0#u8).setSlice! 0 inner).setSlice! 44 ep).setSlice! 64
        (List.replicate 24 0#u8 ++ cb)
      = inner ++ (List.replicate 12 0#u8 ++ ep) ++ (List.replicate 24 0#u8 ++ cb) := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, *]
  intro j
  by_cases h32 : j < 32
  · simp_lists [List.length_replicate, List.length_append, *] <;> (try (congr 1 <;> omega)) <;> (try omega)
  by_cases h44 : j < 44
  · simp_lists [List.length_replicate, List.length_append, *] <;> (try (congr 1 <;> omega)) <;> (try omega)
  by_cases h64 : j < 64
  · simp_lists [List.length_replicate, List.length_append, *] <;> (try (congr 1 <;> omega)) <;> (try omega)
  by_cases h96 : j < 96
  · simp_lists [List.length_replicate, List.length_append, *] <;> (try (congr 1 <;> omega)) <;> (try omega)
  · simp_lists [List.length_replicate, List.length_append, *] <;> (try (congr 1 <;> omega)) <;> (try omega)

set_option maxRecDepth 16384 in
/-- The untouched [64,96) slot of the userOpHash outer buffer is zeros
    (both prior writes land in [0,32) and [44,64)). -/
theorem outerSlot_zero (inner ep : List U8) (hi : inner.length = 32) (he : ep.length = 20) :
    List.slice 64 96 (((List.replicate 96 0#u8).setSlice! 0 inner).setSlice! 44 ep)
      = List.replicate 32 0#u8 := by
  apply List.ext_getElem!
  · simp [List.slice, List.length_setSlice!, *]
  intro j
  simp only [List.slice]
  by_cases hj : j < 32
  · simp_lists [List.length_replicate, List.length_append, *]
  · simp_lists [List.length_replicate, List.length_append, *]

end Extracted.SetSlice
