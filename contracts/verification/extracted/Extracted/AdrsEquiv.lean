/- §33 P0 go/no-go theorems — PROVEN 2026-06-10.

   The Aeneas-extracted `address.rs` functions never panic and compute
   exactly the byte layout the SphincsCVerify spec defines.

   The spec below is a LOCAL RESTATEMENT of
   `SphincsCVerify/Spec/Adrs.lean` (which lives on Lean v4.22.0 and
   cannot be imported into this v4.30.0-rc2 project yet — bridge
   tracked in work-todo §33 P1). It must stay 1:1 with that file:

     bytes [0..4)    layer         (u32 BE)
     bytes [4..12)   tree          (u64 BE)
     bytes [12..16)  address_type  (u32 BE)
     bytes [16..20)  keypair       (u32 BE)
     bytes [20..24)  chain_index   (u32 BE)
     bytes [24..28)  chain_pos     (u32 BE)
     bytes [28..32)  hash_address  (u32 BE)

   Trust framing (work-todo §33): kernel-checked modulo the Aeneas
   translation (Charon nightly-2026.06.08 / Aeneas nightly-2026.06.10,
   `--cfg lean_extract` shape) and rustc. -/
import Extracted.Adrs

set_option linter.unusedSimpArgs false

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

/-! ## Byte-level helpers: `BitVec.toBEBytes` ↔ Nat arithmetic -/

/-- Byte `i` of the little-endian byte decomposition. -/
theorem toLEBytes_byte {w : Nat} (x : BitVec w) (i : Nat) :
    x.toLEBytes[i]! = (x >>> (8 * i)).setWidth 8 := by
  rw [BitVec.eq_iff]
  intro j hj
  rw [BitVec.getElem!_toLEBytes _ _ _ hj]
  simp [hj, Nat.add_comm, BitVec.getElem!_eq_testBit_toNat, BitVec.getLsbD]

/-- Closed form of `toLEBytes` at width 32. -/
theorem toLEBytes32_eq (x : BitVec 32) :
    x.toLEBytes = [x.setWidth 8, (x >>> 8).setWidth 8,
                   (x >>> 16).setWidth 8, (x >>> 24).setWidth 8] := by
  apply List.ext_getElem! (by simp)
  intro n
  by_cases hn : n < 4
  · obtain rfl | rfl | rfl | rfl : n = 0 ∨ n = 1 ∨ n = 2 ∨ n = 3 := by omega
    all_goals (rw [toLEBytes_byte]; simp)
  · rw [List.getElem!_length_le _ _ (by simp; omega),
        List.getElem!_length_le _ _ (by simp; omega)]

/-- Closed form of `toLEBytes` at width 64. -/
theorem toLEBytes64_eq (x : BitVec 64) :
    x.toLEBytes = [x.setWidth 8, (x >>> 8).setWidth 8,
                   (x >>> 16).setWidth 8, (x >>> 24).setWidth 8,
                   (x >>> 32).setWidth 8, (x >>> 40).setWidth 8,
                   (x >>> 48).setWidth 8, (x >>> 56).setWidth 8] := by
  apply List.ext_getElem! (by simp)
  intro n
  by_cases hn : n < 8
  · obtain rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl :
        n = 0 ∨ n = 1 ∨ n = 2 ∨ n = 3 ∨ n = 4 ∨ n = 5 ∨ n = 6 ∨ n = 7 := by omega
    all_goals (rw [toLEBytes_byte]; simp)
  · rw [List.getElem!_length_le _ _ (by simp; omega),
        List.getElem!_length_le _ _ (by simp; omega)]

/-! ## The spec (local restatement of `SphincsCVerify.Spec.Adrs`) -/

/-- Big-endian byte decomposition of a 32-bit value, as `Nat`s. -/
def u32be (x : Nat) : List Nat :=
  [x / 2 ^ 24 % 256, x / 2 ^ 16 % 256, x / 2 ^ 8 % 256, x % 256]

/-- Big-endian byte decomposition of a 64-bit value, as `Nat`s. -/
def u64be (x : Nat) : List Nat :=
  [x / 2 ^ 56 % 256, x / 2 ^ 48 % 256, x / 2 ^ 40 % 256, x / 2 ^ 32 % 256,
   x / 2 ^ 24 % 256, x / 2 ^ 16 % 256, x / 2 ^ 8 % 256, x % 256]

/-- The 32-byte ADRS layout — restatement of `Spec.Adrs.make`. -/
def specMakeAdrs (layer tree atype kp ci cp ha : Nat) : List Nat :=
  u32be layer ++ u64be tree ++ u32be atype ++ u32be kp ++
  u32be ci ++ u32be cp ++ u32be ha

/-- Bytes [20..24) replaced — restatement of `Spec.Adrs.setChainIndex`. -/
def specSetChainIndex (a : List Nat) (idx : Nat) : List Nat :=
  a.take 20 ++ u32be idx ++ a.drop 24

/-! ## Bridging lemmas -/

theorem toBEBytes32_map_toNat (x : BitVec 32) :
    x.toBEBytes.map BitVec.toNat = u32be x.toNat := by
  simp [BitVec.toBEBytes, toLEBytes32_eq, u32be, Nat.shiftRight_eq_div_pow]

theorem toBEBytes64_map_toNat (x : BitVec 64) :
    x.toBEBytes.map BitVec.toNat = u64be x.toNat := by
  simp [BitVec.toBEBytes, toLEBytes64_eq, u64be, Nat.shiftRight_eq_div_pow]

theorem val_comp_mk :
    ((fun (x : U8) => x.val) ∘ @UScalar.mk .U8) = BitVec.toNat := by
  funext b; rfl

theorem map_val_mk (l : List Byte) :
    (l.map (@UScalar.mk .U8)).map (·.val) = l.map BitVec.toNat := by
  simp only [List.map_map]
  rfl

/-! ## The go/no-go theorems -/

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 8192 in
/-- The Rust `make_adrs` never panics and computes exactly the spec
    layout, for ALL inputs. -/
theorem make_adrs_spec (layer : U32) (tree : U64) (atype kp ci cp ha : U32) :
    sphincs_c10.address.make_adrs layer tree atype kp ci cp ha
      ⦃ a => a.val.map (·.val) =
          specMakeAdrs layer.val tree.val atype.val kp.val ci.val cp.val ha.val ⦄ := by
  unfold sphincs_c10.address.make_adrs
  step*
  simp only [*]
  simp only [List.map_setSlice!, Array.repeat_val, Array.val_to_slice, map_val_mk,
             toBEBytes32_map_toNat, toBEBytes64_map_toNat]
  simp only [specMakeAdrs, List.setSlice!]
  simp only [a_post, a1_post, a2_post, a3_post, a4_post, a5_post, a6_post,
             map_val_mk, toBEBytes32_map_toNat, toBEBytes64_map_toNat]
  simp [u32be, u64be]

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 8192 in
/-- The Rust `set_chain_index` never panics and computes exactly the
    spec layout, for ALL inputs. -/
theorem set_chain_index_spec (adrs : Std.Array U8 32#usize) (idx : U32) :
    sphincs_c10.address.set_chain_index adrs idx
      ⦃ a => a.val.map (·.val) = specSetChainIndex (adrs.val.map (·.val)) idx.val ⦄ := by
  unfold sphincs_c10.address.set_chain_index
  step*
  simp only [*]
  simp only [List.map_setSlice!, Array.val_to_slice, map_val_mk, toBEBytes32_map_toNat]
  simp only [specSetChainIndex, List.setSlice!]
  simp [u32be, List.map_take, List.map_drop]
  simp only [a_post, ← List.map_map, map_val_mk, toBEBytes32_map_toNat]
  simp [u32be]

end Extracted.Equiv
