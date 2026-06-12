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

open fw_manifest

/-- **Functional spec**: the preimage is the exact 75-byte concatenation
    `DOMAIN_TAG ++ fw_version_be ++ secure_hash ++ nonsecure_hash`. -/
theorem signed_preimage_spec (fw_version : Std.U32)
    (secure_hash nonsecure_hash : Std.Array Std.U8 32#usize) :
    signed_preimage fw_version secure_hash nonsecure_hash
      ⦃ out => out.val = DOMAIN_TAG.val
          ++ (List.map (@UScalar.mk .U8) fw_version.bv.toBEBytes)
          ++ secure_hash.val ++ nonsecure_hash.val ⦄ := by
  sorry

end Extracted.Equiv
