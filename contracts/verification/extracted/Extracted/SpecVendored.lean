/- §33 P1 — version bridge to SphincsCVerify (the on-chain proof).

   SphincsCVerify is DELIBERATELY mathlib-free and pinned to Lean
   v4.22.0; this extracted-code project needs mathlib + v4.30.0-rc2
   (Aeneas's toolchain). The two can't share a lake build, so a literal
   `import` is impossible. Instead this file VENDORS the relevant
   SphincsCVerify spec definitions verbatim (a faithful transcription),
   so the equivalence theorems can be proven against the actual spec
   shape rather than only a local restatement.

   Fidelity of the vendored copy to the source is CI-guarded:
   `make verify-spec-vendored-fidelity` diffs the definitions below
   against
   `contracts/verification/lean/SphincsCVerify/Spec/{Bytes,Adrs}.lean`.

   `SpecBridge.lean` then proves the §33 local restatements
   (`Extracted.Equiv.specMakeAdrs` etc.) EQUAL these vendored specs —
   turning "human-checked 1:1" into a machine-checked correspondence,
   modulo the (small, auditable, drift-guarded) verbatim copy. -/

namespace SphincsCVerify.Spec

/-- VENDORED from `Spec/Bytes.lean` (verbatim). -/
structure ByteVec (n : Nat) where
  data : Array UInt8
  size_eq : data.size = n
deriving DecidableEq

namespace ByteVec

@[inline]
def cast {m n : Nat} (h : m = n) (v : ByteVec m) : ByteVec n :=
  ⟨v.data, h ▸ v.size_eq⟩

def append {m n : Nat} (xs : ByteVec m) (ys : ByteVec n) : ByteVec (m + n) :=
  ⟨xs.data ++ ys.data, by
    simp [xs.size_eq, ys.size_eq]⟩

instance {m n : Nat} : HAppend (ByteVec m) (ByteVec n) (ByteVec (m + n)) where
  hAppend := ByteVec.append

def ofU32BE (x : UInt32) : ByteVec 4 :=
  let b0 : UInt8 := UInt8.ofNat (((x.toNat >>> 24)) &&& 0xFF)
  let b1 : UInt8 := UInt8.ofNat (((x.toNat >>> 16)) &&& 0xFF)
  let b2 : UInt8 := UInt8.ofNat (((x.toNat >>>  8)) &&& 0xFF)
  let b3 : UInt8 := UInt8.ofNat ((x.toNat) &&& 0xFF)
  ⟨#[b0, b1, b2, b3], by simp⟩

def ofU64BE (x : UInt64) : ByteVec 8 :=
  let b0 : UInt8 := UInt8.ofNat (((x.toNat >>> 56)))
  let b1 : UInt8 := UInt8.ofNat (((x.toNat >>> 48)) &&& 0xFF)
  let b2 : UInt8 := UInt8.ofNat (((x.toNat >>> 40)) &&& 0xFF)
  let b3 : UInt8 := UInt8.ofNat (((x.toNat >>> 32)) &&& 0xFF)
  let b4 : UInt8 := UInt8.ofNat (((x.toNat >>> 24)) &&& 0xFF)
  let b5 : UInt8 := UInt8.ofNat (((x.toNat >>> 16)) &&& 0xFF)
  let b6 : UInt8 := UInt8.ofNat (((x.toNat >>>  8)) &&& 0xFF)
  let b7 : UInt8 := UInt8.ofNat ((x.toNat) &&& 0xFF)
  ⟨#[b0, b1, b2, b3, b4, b5, b6, b7], by simp⟩

end ByteVec

open ByteVec

/-- VENDORED from `Spec/Adrs.lean` (verbatim). -/
def Adrs : Type := ByteVec 32

namespace Adrs

def make
    (layer : UInt32) (tree : UInt64) (atype : UInt32) (kp : UInt32)
    (ci : UInt32) (cp : UInt32) (ha : UInt32) : Adrs :=
  cast (by decide)
    (ofU32BE layer
      |>.append (ofU64BE tree)
      |>.append (ofU32BE atype)
      |>.append (ofU32BE kp)
      |>.append (ofU32BE ci)
      |>.append (ofU32BE cp)
      |>.append (ofU32BE ha))

def setChainIndex (a : Adrs) (idx : UInt32) : Adrs :=
  let prefix4 : ByteVec 20 :=
    ⟨a.data.extract 0 20, by
      have : a.data.size = 32 := a.size_eq
      simp [Array.size_extract, this]⟩
  let suffix : ByteVec 8 :=
    ⟨a.data.extract 24 32, by
      have : a.data.size = 32 := a.size_eq
      simp [Array.size_extract, this]⟩
  cast (by decide) (prefix4.append (ofU32BE idx) |>.append suffix)

end Adrs

end SphincsCVerify.Spec
