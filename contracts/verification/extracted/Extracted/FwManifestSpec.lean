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

/-! ## Supply-chain integrity of the signed preimage

CLAUDE.md ("What NOT to do"): the FW-update signed preimage is intentionally the
fixed 75 bytes `PQFW_V1 ‖ version ‖ secure_hash ‖ nonsecure_hash`, "so any auditor
can reconstruct it from (version, secure.elf, nonsecure.elf) alone." fw-manifest
(`lib.rs`): the `PQFW_V1` domain tag "stops cross-protocol signature reuse." The
75-byte *size* is already enforced by `signed_preimage`'s return type
(`Array Std.U8 75#usize`). The two prose claims that the type does NOT capture —
**domain-tag separation** and **firmware-authorization integrity** — are given
kernel backing below. All SHA-opaque (statements about the *preimage*, before
hashing); the cross-hash collision step is the separate cited hardness assumption. -/

/-- **Layout injectivity (pure).** The 75-byte layout determines its three
    variable fields uniquely (fixed widths 7 / 4 / 32 / 32). The combinatorial
    core of "a signed preimage authorizes exactly one firmware tuple." -/
theorem preimage_layout_injective {vb1 vb2 s1 s2 n1 n2 : List Std.U8}
    (hvb : vb1.length = vb2.length) (hs : s1.length = s2.length)
    (h : DOMAIN_TAG.val ++ vb1 ++ s1 ++ n1 = DOMAIN_TAG.val ++ vb2 ++ s2 ++ n2) :
    vb1 = vb2 ∧ s1 = s2 ∧ n1 = n2 := by
  simp only [List.append_assoc] at h
  obtain ⟨_, h1⟩ := List.append_inj h rfl
  obtain ⟨hvbeq, h2⟩ := List.append_inj h1 hvb
  obtain ⟨hseq, hneq⟩ := List.append_inj h2 hs
  exact ⟨hvbeq, hseq, hneq⟩

/-- **Domain-tag prefix (pure).** The layout always begins with the 7-byte
    `PQFW_V1` tag — so any signed value whose preimage does NOT start with
    `PQFW_V1` (a UserOp `sphincsDigest`, an EIP-712 hash, …) is a structurally
    distinct byte-string. This is the cross-protocol-reuse separation at the
    preimage layer (the cross-hash collision step is the cited hardness
    assumption). -/
theorem layout_domain_tag_prefix (vb s n : List Std.U8) :
    (DOMAIN_TAG.val ++ vb ++ s ++ n).take 7 = DOMAIN_TAG.val := by
  have l_tag : DOMAIN_TAG.val.length = 7 := by have := DOMAIN_TAG.property; simp_all
  simp only [List.append_assoc]
  exact List.take_left' l_tag

/-- **Authorization integrity (signed_preimage-level).** A FW-update signed
    preimage authorizes EXACTLY ONE firmware tuple: equal `signed_preimage`
    outputs ⇒ equal version-bytes and equal secure / nonsecure hashes. Composes
    the (already-proven) `signed_preimage_spec` (output `=` the 75-byte layout)
    with `preimage_layout_injective` (the layout is injective). -/
theorem signed_preimage_authorizes_one_firmware
    (v1 v2 : Std.U32) (s1 s2 n1 n2 : Std.Array Std.U8 32#usize)
    (o : Std.Array Std.U8 75#usize)
    (h1 : signed_preimage v1 s1 n1 = ok o)
    (h2 : signed_preimage v2 s2 n2 = ok o) :
    (List.map (@UScalar.mk .U8) v1.bv.toBEBytes)
        = (List.map (@UScalar.mk .U8) v2.bv.toBEBytes)
    ∧ s1.val = s2.val ∧ n1.val = n2.val := by
  have spec1 := signed_preimage_spec v1 s1 n1
  have spec2 := signed_preimage_spec v2 s2 n2
  simp only [h1] at spec1   -- spec1 : o.val = layout1 (the ⦃⦄ match reduced by `ok o`)
  simp only [h2] at spec2   -- spec2 : o.val = layout2
  have l_ver1 : (List.map (@UScalar.mk .U8) v1.bv.toBEBytes).length = 4 := by
    rw [List.length_map, BitVec.toBEBytes_length]
  have l_ver2 : (List.map (@UScalar.mk .U8) v2.bv.toBEBytes).length = 4 := by
    rw [List.length_map, BitVec.toBEBytes_length]
  have l_s1 : s1.val.length = 32 := by have := s1.property; simp_all
  have l_s2 : s2.val.length = 32 := by have := s2.property; simp_all
  exact preimage_layout_injective (by rw [l_ver1, l_ver2]) (by rw [l_s1, l_s2])
    (spec1.symm.trans spec2)

end Extracted.Equiv
