/- §33 — computable SHA-256 adapter over the vendored FIPS 180-4
   implementation (`Sha256Vendored.lean`).

   `sha256_pure` is the COMPUTABLE counterpart of the `keccak256_pure`
   axiom in `UserOp/FunsExternal.lean`: same I/O shape (Aeneas bytes in,
   `Array U8 32#usize` out), but no axiom — it runs the vendored
   SphincsCVerify SHA-256 and carries a structural proof that the
   digest serialization is exactly 32 bytes (`sha256Bytes_size`,
   proven by induction in the vendored file; no `native_decide`).

   `sha256_pure` is marked `@[irreducible]` at the END of this file —
   after the length lemma, the controlled-unfolding lemma
   `sha256_pure_val`, and the KAT guards — so existing rank proofs that
   treat hash results opaquely can never accidentally unfold a 64-round
   compression. Proof-layer code that NEEDS the definition goes through
   `sha256_pure_val`.

   KAT mechanism: `#guard` (compiled, `#eval`-style evaluation; no
   axioms — NOT `native_decide`). Kernel `decide` is not an option
   here: the vendored `messageSchedule.expand` / `runRounds.go` /
   `wordsToBytes.go` are well-founded recursions (`termination_by`),
   which are compiled via `WellFounded.fix` and do not reduce
   definitionally in the kernel — `decide` gets stuck on `Acc.rec`
   long before any 60-second budget matters. A failing `#guard` is an
   elaboration error, so the KATs are enforced at build time. -/
import Aeneas
import Extracted.Sha256Vendored

open Aeneas Aeneas.Std

namespace Sha256Pure

open SphincsCVerify.Spec.Sha256Impl

/-- Lower a list of Aeneas `U8` scalars to the vendored
    implementation's byte type. -/
def toUInt8Array (data : List Std.U8) : Array UInt8 :=
  (data.map (fun b => UInt8.ofNat b.val)).toArray

/-- Lift a vendored-implementation byte back to an Aeneas `U8`. -/
def ofUInt8 (b : UInt8) : Std.U8 :=
  ⟨BitVec.ofNat 8 b.toNat⟩

/-- The digest of `data` under the vendored FIPS 180-4 SHA-256, as a
    list of Aeneas `U8` scalars. -/
def digestList (data : List Std.U8) : List Std.U8 :=
  (sha256Bytes (toUInt8Array data)).toList.map ofUInt8

/-- THE length lemma: the vendored digest serialization produces
    exactly 32 bytes, lifted through the Aeneas byte adapters. Rests on
    the structural (inductive) `sha256Bytes_size` from the vendored
    file — no `native_decide`, no axioms. -/
theorem digestList_length (data : List Std.U8) :
    (digestList data).length = 32 := by
  unfold digestList
  rw [List.length_map, Array.length_toList, sha256Bytes_size]

end Sha256Pure

/-- Computable SHA-256 over Aeneas bytes: runs the vendored
    SphincsCVerify FIPS 180-4 implementation and packages the digest as
    an Aeneas 32-byte array (length proof from
    `Sha256Pure.digestList_length`). -/
def sha256_pure (data : List Std.U8) : Std.Array Std.U8 32#usize :=
  ⟨Sha256Pure.digestList data, by rw [Sha256Pure.digestList_length]; scalar_tac⟩

/-- Controlled unfolding for the proof layer: the underlying list of
    `sha256_pure` is exactly the vendored digest. Proven BEFORE
    `sha256_pure` is made irreducible; use this instead of `unfold`. -/
theorem sha256_pure_val (data : List Std.U8) :
    (sha256_pure data).val = Sha256Pure.digestList data := rfl

/-- `sha256_pure` always returns exactly 32 bytes (survives the
    `@[irreducible]` below — it only needs the subtype invariant). -/
theorem sha256_pure_val_length (data : List Std.U8) :
    (sha256_pure data).val.length = 32 := by
  rw [sha256_pure_val, Sha256Pure.digestList_length]

/-! ## NIST FIPS 180-4 / CAVS known-answer tests

Build-time-enforced via `#guard` (see the header comment for why not
kernel `decide`). Vectors: SHA-256(""), SHA-256("abc"), and the NIST
two-block message. -/

namespace Sha256Pure

/-- KAT helper: ASCII message text → Aeneas bytes. -/
def katMsg (s : String) : List Std.U8 :=
  s.toUTF8.toList.map ofUInt8

/-- KAT helper: digest of `data` as plain `Nat`s for comparison. -/
def katDigest (data : List Std.U8) : List Nat :=
  (sha256_pure data).val.map (fun b => b.val)

#guard katDigest (katMsg "") =
  [0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
   0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
   0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
   0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55]

#guard katDigest (katMsg "abc") =
  [0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
   0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
   0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
   0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad]

#guard katDigest
    (katMsg "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") =
  [0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
   0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
   0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
   0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1]

end Sha256Pure

/- Opaque from here on: rank proofs treat hash results as black boxes;
   nothing may accidentally unfold a 64-round compression. -/
attribute [irreducible] sha256_pure
