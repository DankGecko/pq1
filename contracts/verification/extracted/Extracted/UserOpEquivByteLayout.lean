/- §33 P2 — full byte-layout equivalence for `compute_user_op_hash`,
   PROVEN 2026-06-10. This is the FIRMWARE SIDE of the firmware↔chain
   binding (§33 goal theorem 1): the firmware's userOpHash equals the
   EntryPoint v0.6 double-keccak over the exact abi.encode preimage, for
   ALL inputs.

   keccak-256 is the single uninterpreted axiom (`keccak256_pure`, the
   FunsExternal model mirroring AXIOM_STATUS A1). Axiom closure of
   `compute_user_op_hash_spec` = [keccak256_pure, propext,
   Classical.choice, Quot.sound] — no sorryAx.

   The setSlice!→concatenation reductions live in `SetSliceLemmas.lean`
   (reusable by the P3 wots/fors/merkle serializers). The v4.22→v4.30
   import bridge to the wallet model's userOpHash is P1. -/
import Extracted.UserOp.Funs
import Extracted.UserOpEquiv
import Extracted.SetSliceLemmas

set_option linter.unusedSimpArgs false

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open pqsigner_aa
open Extracted.SetSlice

def padWord (row : List U8) : List U8 := List.replicate (32 - row.length) 0#u8 ++ row
def specInner (p : userop.AaUserOpParams) (cdh : Array U8 32#usize) : List U8 :=
  padWord p.sender.val ++ p.nonce.val ++ p.init_code_hash.val ++ cdh.val ++
  p.call_gas_limit.val ++ p.verification_gas_limit.val ++
  p.pre_verification_gas.val ++ p.max_fee_per_gas.val ++
  p.max_priority_fee_per_gas.val ++ p.paymaster_and_data_hash.val
def specOuter (inner : Array U8 32#usize) (p : userop.AaUserOpParams) : List U8 :=
  inner.val ++ padWord p.entry_point.val ++
  padWord ((p.chain_id.bv.toBEBytes).map (@UScalar.mk .U8))
theorem specInner_length (p) (cdh : Array U8 32#usize) : (specInner p cdh).length = 320 := by
  simp [specInner, padWord]
theorem specOuter_length (inner : Array U8 32#usize) (p) : (specOuter inner p).length = 96 := by
  simp [specOuter, padWord]
def innerSlice (p : userop.AaUserOpParams) (cdh : Array U8 32#usize) : Slice U8 :=
  ⟨specInner p cdh, by rw [specInner_length]; scalar_tac⟩
def outerSlice (inner : Array U8 32#usize) (p : userop.AaUserOpParams) : Slice U8 :=
  ⟨specOuter inner p, by rw [specOuter_length]; scalar_tac⟩

set_option maxHeartbeats 8000000 in
set_option maxRecDepth 16384 in
theorem compute_user_op_hash_spec (p : userop.AaUserOpParams) (cdh : Array U8 32#usize) :
    userop.compute_user_op_hash p cdh
      ⦃ h => h = keccak256_pure (outerSlice (keccak256_pure (innerSlice p cdh)) p) ⦄ := by
  have l_sender : p.sender.val.length = 20 := by have := p.sender.property; simp_all
  have l_ep : p.entry_point.val.length = 20 := by have := p.entry_point.property; simp_all
  have l_no : p.nonce.val.length = 32 := by have := p.nonce.property; simp_all
  have l_ic : p.init_code_hash.val.length = 32 := by have := p.init_code_hash.property; simp_all
  have l_cdh : cdh.val.length = 32 := by have := cdh.property; simp_all
  have l_cg : p.call_gas_limit.val.length = 32 := by have := p.call_gas_limit.property; simp_all
  have l_vg : p.verification_gas_limit.val.length = 32 := by have := p.verification_gas_limit.property; simp_all
  have l_pv : p.pre_verification_gas.val.length = 32 := by have := p.pre_verification_gas.property; simp_all
  have l_mf : p.max_fee_per_gas.val.length = 32 := by have := p.max_fee_per_gas.property; simp_all
  have l_mp : p.max_priority_fee_per_gas.val.length = 32 := by have := p.max_priority_fee_per_gas.property; simp_all
  have l_pd : p.paymaster_and_data_hash.val.length = 32 := by have := p.paymaster_and_data_hash.property; simp_all
  unfold userop.compute_user_op_hash
  step* <;>
    first
    | scalar_tac
    | (simp only [userop.WORD, Slice.length, Array.length_to_slice] at *; scalar_tac)
    | simp only [userop.WORD]
    | skip
  -- Inner: s10 = innerSlice p cdh
  have hs10 : s10 = innerSlice p cdh := by
    apply Subtype.ext
    simp only [s10_post, Array.val_to_slice, buf10_post, buf9_post, buf8_post, buf7_post,
               buf6_post, buf5_post, buf4_post, buf3_post, buf2_post, buf1_post,
               s9_post, s8_post, s7_post, s6_post, s5_post, s4_post, s3_post, s2_post,
               s1_post, s_post, Array.val_to_slice, Array.length_to_slice,
               l_sender, l_no, l_ic, l_cdh, l_cg, l_vg, l_pv, l_mf, l_mp, l_pd,
               Array.repeat_val]
    norm_num
    rw [innerBuf_eq _ _ _ _ _ _ _ _ _ _ l_sender l_no l_ic l_cdh l_cg l_vg l_pv l_mf l_mp l_pd]
    simp only [innerSlice, specInner, padWord, l_sender]
  -- inner: rewrite inner = keccak256_pure (innerSlice p cdh)
  have l_inner : inner.val.length = 32 := by have := inner.property; simp_all
  have hinner : inner = keccak256_pure (innerSlice p cdh) := by rw [inner_post, hs10]
  -- outer slice equality
  have hi3 : (3:Nat) * 32 = 96 := by norm_num
  have hcb : (List.map (@UScalar.mk .U8) p.chain_id.bv.toBEBytes).length = 8 := by
    simp [List.length_map, BitVec.toBEBytes_length]
  have hs19 : s19 = outerSlice inner p := by
    apply Subtype.ext
    simp only [s19_post, Array.val_to_slice, s17_post3, s18_post, s17_post1,
               s14_post3, s16_post, s15_post, s11_post3, s13_post, s12_post,
               Array.val_to_slice, Array.repeat_val, i1_post, i2_post, i3_post,
               i_post1, userop.WORD]
    norm_num
    have hbb : p.chain_id.bv.toBEBytes.length = 8 := by simp [BitVec.toBEBytes_length]
    have hcb8 : (List.map (@UScalar.mk .U8) p.chain_id.bv.toBEBytes).length = 8 := by
      rw [List.length_map, hbb]
    have hslot := rightAlign_word 24 (List.map (@UScalar.mk .U8) p.chain_id.bv.toBEBytes)
      (by rw [hcb8]) (by omega)
    have houter := outerBuf_eq inner.val p.entry_point.val
      (List.map (@UScalar.mk .U8) p.chain_id.bv.toBEBytes) l_inner l_ep hcb8
    rw [outerSlot_zero inner.val p.entry_point.val l_inner l_ep, hslot, houter]
    simp only [outerSlice, specOuter, padWord, l_ep, l_inner, hcb8]
  rw [h_post, hs19, hinner]

end Extracted.Equiv
