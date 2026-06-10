/- §33 P1 — the VERSION BRIDGE: firmware theorems meet the actual
   on-chain spec (SphincsCVerify), not just local restatements.

   SphincsCVerify is mathlib-free v4.22.0; this project is mathlib +
   v4.30.0-rc2 (Aeneas). They can't share a lake build, so the spec is
   VENDORED verbatim in `SpecVendored.lean` (CI-diff-guarded against
   the source). This file proves the §33 local restatements EQUAL the
   vendored spec, and composes that with the firmware equivalence —
   yielding `firmware_make_adrs_matches_vendored`: the extracted
   firmware `make_adrs` produces exactly the bytes the on-chain ADRS
   spec defines, for ALL inputs.

   Trust now: extracted Rust = vendored on-chain spec (machine-checked),
   modulo (a) the Aeneas translation, (b) the vendored copy being a
   faithful transcription of the v4.22 source — a small auditable diff,
   CI-guarded by `make verify-spec-vendored-fidelity`. -/
import Extracted.AdrsEquiv
import Extracted.SpecVendored

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

theorem and255_mod (n : Nat) : (n % 256) &&& 255 = n % 256 := by
  have e : (255 : Nat) = 2 ^ 8 - 1 := by norm_num
  rw [e, Nat.and_two_pow_sub_one_eq_mod]; omega

theorem specMakeAdrs_eq_vendored (layer atype kp ci cp ha : UInt32) (tree : UInt64) :
    (SphincsCVerify.Spec.Adrs.make layer tree atype kp ci cp ha).data.toList.map UInt8.toNat
      = specMakeAdrs layer.toNat tree.toNat atype.toNat kp.toNat ci.toNat cp.toNat ha.toNat := by
  simp only [SphincsCVerify.Spec.Adrs.make, SphincsCVerify.Spec.ByteVec.cast,
        SphincsCVerify.Spec.ByteVec.append, SphincsCVerify.Spec.ByteVec.ofU32BE,
        SphincsCVerify.Spec.ByteVec.ofU64BE, specMakeAdrs, u32be, u64be,
        Array.toList_append, List.map_append, List.map_cons, List.map_nil,
        UInt8.toNat_ofNat, Nat.shiftRight_eq_div_pow]
  norm_num [and255_mod, Nat.shiftRight_eq_div_pow]

-- COMPOSED: the extracted firmware make_adrs, when its args come from the
-- same Nat values, matches the VENDORED SphincsCVerify spec's bytes.
-- (make_adrs_spec already gives extracted = specMakeAdrs over the U32/U64
--  .val; specMakeAdrs_eq_vendored gives vendored = specMakeAdrs over
--  matching .toNat. Composed: firmware ≡ on-chain spec for ADRS.)
theorem firmware_make_adrs_matches_vendored
    (layer : Aeneas.Std.U32) (tree : Aeneas.Std.U64) (atype kp ci cp ha : Aeneas.Std.U32)
    (vl : UInt32) (vt : UInt64) (va vk vc vp vh : UInt32)
    (e0 : layer.val = vl.toNat) (e1 : tree.val = vt.toNat) (e2 : atype.val = va.toNat)
    (e3 : kp.val = vk.toNat) (e4 : ci.val = vc.toNat) (e5 : cp.val = vp.toNat)
    (e6 : ha.val = vh.toNat) :
    sphincs_c10.address.make_adrs layer tree atype kp ci cp ha
      ⦃ a => a.val.map (·.val) =
          (SphincsCVerify.Spec.Adrs.make vl vt va vk vc vp vh).data.toList.map UInt8.toNat ⦄ := by
  rw [specMakeAdrs_eq_vendored, ← e0, ← e1, ← e2, ← e3, ← e4, ← e5, ← e6]
  exact make_adrs_spec layer tree atype kp ci cp ha

end Extracted.Equiv
