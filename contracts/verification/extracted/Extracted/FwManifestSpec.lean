/- §33 rank 12 — fw-manifest signed_preimage: FUNCTIONAL spec (statement only).

   The 75-byte FW-update signing preimage, frozen by design (see "What NOT to
   do": do not expand it): "PQFW_V1" || fw_version_be(4) || secure_hash(32) ||
   nonsecure_hash(32). Any auditor must be able to reconstruct it from
   (version, secure.elf, nonsecure.elf) alone, so the byte layout IS the spec.

   Proof plan: identical to rank 3 (Eip1271Equiv.lean) — a fwmanBuf_eq
   by-index ext_getElem!/simp_lists lemma over the 4-slot setSlice! chain on
   the 75-zero buffer, then step* + Subtype.ext. No hash, no axioms. -/
import Extracted.FwManifest.Funs
import Extracted.SetSliceLemmas

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open Extracted.SetSlice

set_option maxRecDepth 16384 in
theorem fwmanBuf_eq (tag ver sh nh : List Std.U8)
    (htag : tag.length = 7) (hver : ver.length = 4)
    (hsh : sh.length = 32) (hnh : nh.length = 32) :
    ((((List.replicate 75 0#u8).setSlice! 0 tag).setSlice! 7 ver).setSlice! 11 sh).setSlice! 43 nh
      = tag ++ ver ++ sh ++ nh := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, List.length_append, List.length_replicate, *]
  intro j
  by_cases h0 : j < 7
  · simp_lists [List.length_replicate, *] <;> (try congr 1) <;>
      simp only [List.length_append, htag, hver, hsh, hnh] <;> omega
  by_cases h1 : j < 11
  · simp_lists [List.length_replicate, *] <;> (try congr 1) <;>
      simp only [List.length_append, htag, hver, hsh, hnh] <;> omega
  by_cases h2 : j < 43
  · simp_lists [List.length_replicate, *] <;> (try congr 1) <;>
      simp only [List.length_append, htag, hver, hsh, hnh] <;> omega
  by_cases h3 : j < 75
  · simp_lists [List.length_replicate, *] <;> (try congr 1) <;>
      simp only [List.length_append, htag, hver, hsh, hnh] <;> omega
  · simp_lists [List.length_replicate, *] <;> (try congr 1) <;>
      simp only [List.length_append, htag, hver, hsh, hnh] <;> omega

open fw_manifest

/-- **Functional spec**: the preimage is the exact 75-byte concatenation
    `DOMAIN_TAG ++ fw_version_be ++ secure_hash ++ nonsecure_hash`. -/
theorem signed_preimage_spec (fw_version : Std.U32)
    (secure_hash nonsecure_hash : Std.Array Std.U8 32#usize) :
    signed_preimage fw_version secure_hash nonsecure_hash
      ⦃ out => out.val = DOMAIN_TAG.val
          ++ (List.map (@UScalar.mk .U8) fw_version.bv.toBEBytes)
          ++ secure_hash.val ++ nonsecure_hash.val ⦄ := by
  have l_tag : DOMAIN_TAG.val.length = 7 := by have := DOMAIN_TAG.property; simp_all
  have l_sh : secure_hash.val.length = 32 := by have := secure_hash.property; simp_all
  have l_nh : nonsecure_hash.val.length = 32 := by have := nonsecure_hash.property; simp_all
  have l_ver : (List.map (@UScalar.mk .U8) fw_version.bv.toBEBytes).length = 4 := by
    rw [List.length_map, BitVec.toBEBytes_length]
  unfold signed_preimage
  step* <;>
    first
    | scalar_tac
    | (simp only [Slice.length, Array.length_to_slice] at *; scalar_tac)
    | skip
  have hslen : s.len.val = 7 := by
    rw [s_post]; simp only [Slice.len_val, Array.length_to_slice, l_tag]
    scalar_tac
  simp only [s12_post, s11_post, s10_post3, s9_post, s8_post, s7_post3, s6_post, s5_post,
             a_post, s4_post3, s3_post, s2_post, s1_post3, s_post,
             Array.val_to_slice, Array.repeat_val, hslen, sec_off_post, ns_off_post]
  norm_num
  rw [fwmanBuf_eq _ _ _ _ l_tag l_ver l_sh l_nh]
  simp [List.append_assoc]

end Extracted.Equiv
