/- §33 rank 3 — eip1271 byte-layout functional specs (clone of the
   compute_user_op_hash method; SetSliceLemmas reductions). -/
import Extracted.Eip1271.Funs
import Extracted.SetSliceLemmas
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open pqsigner_aa Extracted.SetSlice

set_option maxRecDepth 16384 in
theorem domainBuf_eq (th nm ve cb vc : List Std.U8)
    (hth : th.length = 32) (hnm : nm.length = 32) (hve : ve.length = 32)
    (hcb : cb.length = 8) (hvc : vc.length = 20) :
    ((((((List.replicate 160 0#u8).setSlice! 0 th).setSlice! 32 nm).setSlice! 64 ve).setSlice! 120 cb).setSlice! 140 vc)
      = th ++ nm ++ ve ++ List.replicate 24 0#u8 ++ cb ++ List.replicate 12 0#u8 ++ vc := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, List.length_append, List.length_replicate, *]
  intro j
  by_cases h0 : j < 32
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hth, hnm, hve, hcb, hvc] <;> omega
  by_cases h1 : j < 64
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hth, hnm, hve, hcb, hvc] <;> omega
  by_cases h2 : j < 96
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hth, hnm, hve, hcb, hvc] <;> omega
  by_cases h3 : j < 120
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hth, hnm, hve, hcb, hvc] <;> omega
  by_cases h4 : j < 128
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hth, hnm, hve, hcb, hvc] <;> omega
  by_cases h5 : j < 140
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hth, hnm, hve, hcb, hvc] <;> omega
  by_cases h6 : j < 160
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hth, hnm, hve, hcb, hvc] <;> omega
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hth, hnm, hve, hcb, hvc] <;> omega

/-- abi.encode(typehash, nameHash, versionHash, chainId, verifyingContract). -/
def domainSlice (chain_id : Std.U64) (vc : Std.Array Std.U8 20#usize) : Slice Std.U8 :=
  ⟨eip1271.EIP712_DOMAIN_TYPEHASH.val ++ eip1271.NAME_HASH.val ++ eip1271.VERSION_HASH.val
    ++ List.replicate 24 0#u8 ++ (List.map (@UScalar.mk .U8) chain_id.bv.toBEBytes)
    ++ List.replicate 12 0#u8 ++ vc.val, by
    have l1 : eip1271.EIP712_DOMAIN_TYPEHASH.val.length = 32 := by
      have := eip1271.EIP712_DOMAIN_TYPEHASH.property; simp_all
    have l2 : eip1271.NAME_HASH.val.length = 32 := by
      have := eip1271.NAME_HASH.property; simp_all
    have l3 : eip1271.VERSION_HASH.val.length = 32 := by
      have := eip1271.VERSION_HASH.property; simp_all
    have l5 : vc.val.length = 20 := by have := vc.property; simp_all
    simp only [List.length_append, List.length_replicate, List.length_map,
               BitVec.toBEBytes_length, l1, l2, l3, l5, Std.U64.numBits]
    scalar_tac⟩

set_option maxHeartbeats 4000000 in
theorem domain_separator_spec (chain_id : Std.U64) (vc : Std.Array Std.U8 20#usize) :
    eip1271.domain_separator chain_id vc
      ⦃ r => r = keccak256_pure (domainSlice chain_id vc) ⦄ := by
  have l_vc : vc.val.length = 20 := by have := vc.property; simp_all
  have l_th : eip1271.EIP712_DOMAIN_TYPEHASH.val.length = 32 := by
    have := eip1271.EIP712_DOMAIN_TYPEHASH.property; simp_all
  have l_nm : eip1271.NAME_HASH.val.length = 32 := by have := eip1271.NAME_HASH.property; simp_all
  have l_ve : eip1271.VERSION_HASH.val.length = 32 := by have := eip1271.VERSION_HASH.property; simp_all
  have l_cb : (List.map (@UScalar.mk .U8) chain_id.bv.toBEBytes).length = 8 := by
    rw [List.length_map, BitVec.toBEBytes_length]
  unfold eip1271.domain_separator
  step* <;>
    first
    | scalar_tac
    | (simp only [Slice.length, Array.length_to_slice] at *; scalar_tac)
    | skip
  have hslice : s15 = domainSlice chain_id vc := by
    apply Subtype.ext
    simp only [s15_post, s14_post, s13_post, s12_post3, s11_post, s10_post, a_post,
               s9_post3, s8_post, s7_post, s6_post3, s5_post, s4_post, s3_post3,
               s2_post, s1_post, s_post3, i_post, i1_post,
               Array.val_to_slice, Array.repeat_val]
    norm_num
    rw [domainBuf_eq _ _ _ _ _ l_th l_nm l_ve l_cb l_vc]
    simp only [domainSlice]
  rw [r_post, hslice]

/-! ### replay_safe_hash — the nested-EIP-712 wrap (composes domain_separator_spec) -/

set_option maxRecDepth 16384 in
theorem structBuf_eq (th fh : List Std.U8) (hth : th.length = 32) (hfh : fh.length = 32) :
    (((List.replicate 64 0#u8).setSlice! 0 th).setSlice! 32 fh) = th ++ fh := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, List.length_append, List.length_replicate, *]
  intro j
  by_cases h0 : j < 32
  · simp_lists [List.length_replicate, *]
  by_cases h1 : j < 64
  · simp_lists [List.length_replicate, *] <;> (try congr 1) <;> simp only [List.length_append, hth, hfh] <;> omega
  · simp_lists [List.length_replicate, *]

set_option maxRecDepth 16384 in
theorem replayBuf_eq (pre ds sh : List Std.U8) (hpre : pre.length = 2)
    (hds : ds.length = 32) (hsh : sh.length = 32) :
    (((List.replicate 66 0#u8).setSlice! 0 pre).setSlice! 2 ds).setSlice! 34 sh = pre ++ ds ++ sh := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, List.length_append, List.length_replicate, *]
  intro j
  by_cases h0 : j < 2
  · simp_lists [List.length_replicate, *]
  by_cases h1 : j < 34
  · simp_lists [List.length_replicate, *] <;> (try congr 1) <;> simp only [List.length_append, hpre, hds, hsh] <;> omega
  by_cases h2 : j < 66
  · simp_lists [List.length_replicate, *] <;> (try congr 1) <;> simp only [List.length_append, hpre, hds, hsh] <;> omega
  · simp_lists [List.length_replicate, *]

def structSlice (final_hash : Std.Array Std.U8 32#usize) : Slice Std.U8 :=
  ⟨eip1271.PERSONAL_SIGN_TYPEHASH.val ++ final_hash.val, by
    have l1 : eip1271.PERSONAL_SIGN_TYPEHASH.val.length = 32 := by
      have := eip1271.PERSONAL_SIGN_TYPEHASH.property; simp_all
    have l2 : final_hash.val.length = 32 := by have := final_hash.property; simp_all
    simp only [List.length_append, l1, l2]; scalar_tac⟩

def replaySlice (ds sh : Std.Array Std.U8 32#usize) : Slice Std.U8 :=
  ⟨[25#u8, 1#u8] ++ ds.val ++ sh.val, by
    have l1 : ds.val.length = 32 := by have := ds.property; simp_all
    have l2 : sh.val.length = 32 := by have := sh.property; simp_all
    simp only [List.length_append, l1, l2, List.length_cons, List.length_nil]; scalar_tac⟩

attribute [step] domain_separator_spec

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 100000 in
theorem replay_safe_hash_spec (chain_id : Std.U64) (vc : Std.Array Std.U8 20#usize)
    (final_hash : Std.Array Std.U8 32#usize) :
    eip1271.replay_safe_hash chain_id vc final_hash
      ⦃ r => r = keccak256_pure (replaySlice
               (keccak256_pure (domainSlice chain_id vc))
               (keccak256_pure (structSlice final_hash))) ⦄ := by
  have l_pst : eip1271.PERSONAL_SIGN_TYPEHASH.val.length = 32 := by
    have := eip1271.PERSONAL_SIGN_TYPEHASH.property; simp_all
  have l_fh : final_hash.val.length = 32 := by have := final_hash.property; simp_all
  have l_ds : ∀ d : Std.Array Std.U8 32#usize, d.val.length = 32 := fun d => by have := d.property; simp_all
  unfold eip1271.replay_safe_hash
  step* <;>
    first
    | scalar_tac
    | (simp only [Slice.length, Array.length_to_slice] at *; scalar_tac)
    | skip
  have hs6 : s6 = structSlice final_hash := by
    apply Subtype.ext
    simp only [s6_post, s5_post, s4_post, s3_post3, s2_post, s1_post, s_post3,
               Array.val_to_slice, Array.repeat_val]
    norm_num
    rw [structBuf_eq _ _ l_pst l_fh]
    simp only [structSlice]
  have hs16 : s16 = replaySlice domain_sep struct_hash := by
    apply Subtype.ext
    simp only [s16_post, s15_post, s14_post, s13_post3, s12_post, s11_post, s10_post3,
               s9_post, s8_post, s7_post3, Array.val_to_slice, Array.repeat_val, Array.make]
    norm_num
    rw [replayBuf_eq _ _ _ (by decide) (l_ds domain_sep) (l_ds struct_hash)]
    simp only [replaySlice]
  rw [r_post, hs16, domain_sep_post, struct_hash_post, hs6]

end Extracted.Equiv
