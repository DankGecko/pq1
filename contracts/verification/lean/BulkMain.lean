/-
Driver for `lake exe verify-bulk` — the BULK executable-spec differential.

Runs the executable Lean `Spec.Signature.verify` over a broad random corpus
(contracts/verification/bulk_vectors.json, embedded by
`scripts/gen_bulk_lean.py`) and asserts it agrees with the Rust reference
signer's verdict (`expectValid`) on every vector. This is the
many-vector extension of `verify-test-vectors`: where the 10-vector KAT pins
the digest/htIdx ground truth and the 4 valid + 6 negative cases, this corpus
(8 keypairs × 24 messages × {valid, single-byte-mutation}) exercises hundreds
of distinct hypertree-leaf positions and merkle-path lengths — including the
signature-offset-3992 boundary read fixed in the 2026-06-13 A3.1 work.

Hard check: any mismatch between the Lean spec and the Rust oracle returns a
non-zero exit code, so CI catches a reconstruction-layer regression that the
small KAT might miss.
-/

import SphincsCVerify
import SphincsCVerify.BulkVectors

open SphincsCVerify.Spec
open SphincsCVerify.Spec.ByteVec
open SphincsCVerify.BulkVectors

def hexNibble (c : Char) : UInt8 :=
  if '0' ≤ c ∧ c ≤ '9' then (c.toNat - '0'.toNat).toUInt8
  else if 'a' ≤ c ∧ c ≤ 'f' then (c.toNat - 'a'.toNat + 10).toUInt8
  else if 'A' ≤ c ∧ c ≤ 'F' then (c.toNat - 'A'.toNat + 10).toUInt8
  else 0

def hexToBytes (s : String) : Array UInt8 := Id.run do
  let arr := (s.toList.drop 2).toArray
  let mut out : Array UInt8 := #[]
  let mut i := 0
  while h : i + 1 < arr.size do
    out := out.push (hexNibble arr[i]! * 16 + hexNibble arr[i + 1]!)
    i := i + 2
  pure out

def toBV (n : Nat) (a : Array UInt8) : ByteVec n :=
  ⟨(a ++ Array.replicate n 0).extract 0 n, by
    simp [Array.size_extract, Array.size_append, Array.size_replicate]
    omega⟩

def runOne (v : BulkVector) : Bool :=
  let pkSeed16 : ByteVec 16 := (toBV 32 (hexToBytes v.pkSeed)).take 16 (by decide)
  let pkRoot16 : ByteVec 16 := (toBV 32 (hexToBytes v.pkRoot)).take 16 (by decide)
  let msgBV : ByteVec 32 := toBV 32 (hexToBytes v.message)
  let sigBV : ByteVec SignatureLen := toBV SignatureLen (hexToBytes v.signature)
  let r : Bool := Signature.verify ⟨pkSeed16, pkRoot16⟩ msgBV sigBV
  r == v.expectValid

def main : IO UInt32 := do
  IO.println "=== Bulk Lean ↔ Rust-oracle differential (verify-bulk) ==="
  IO.println s!"vectors = {vectors.length}"
  let mut mismatches : Nat := 0
  let mut validChecked : Nat := 0
  let mut negChecked : Nat := 0
  for v in vectors do
    if v.expectValid then validChecked := validChecked + 1 else negChecked := negChecked + 1
    if !runOne v then
      mismatches := mismatches + 1
      IO.eprintln s!"  MISMATCH on {v.label} (expectValid={v.expectValid})"
  IO.println s!"valid accepted-or-checked : {validChecked}"
  IO.println s!"negatives checked         : {negChecked}"
  IO.println s!"mismatches                : {mismatches}"
  IO.println ""
  if mismatches > 0 then
    IO.eprintln s!"FAIL: Lean Spec.Signature.verify disagreed with the Rust oracle on {mismatches} vector(s)."
    return 1
  IO.println s!"OK: Lean spec matches the Rust oracle on all {vectors.length} bulk vectors."
  return 0
