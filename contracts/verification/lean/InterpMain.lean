/-
Driver for `lake exe verify-interp` — the empirical interpreter↔bytecode bridge.

This is the advisor's load-bearing validation milestone for the full-(a)
interpreter-refinement plan (`docs/A3_1_CLOSURE_PATH.md` §8): run the SAME KAT +
bulk corpus the existing `verify-test-vectors` / `verify-bulk` runners use, but
THROUGH the transcribed Yul interpreter `C10.execC10Asm` (under the real
computable `Spec.Sha256Impl` SHA-256 oracle), and assert, per vector:

  (A) `execC10Asm` == `Spec.Signature.verify`  — the interpreter agrees with the
      declarative spec it will later be PROVEN equal to (the refinement target);
  (B) `execC10Asm` == `expectValid`             — the interpreter reproduces the
      deployed-bytecode KAT ground truth (accept the 4 valid, reject the
      negatives; reproduce all 384 bulk verdicts).

Passing (A)+(B) on the whole corpus empirically pins (i) AST transcription
faithfulness and (ii) `execStmt`↔EVM semantics against ground truth, BEFORE any
phase-refinement proof — exactly the condition that makes the eventual
`execC10Asm = verifyYulModel` a genuine trust-base reduction rather than a tidy
unvalidated model. HARD CHECK: non-zero exit on any mismatch.
-/

import SphincsCVerify
import SphincsCVerify.KatVectors
import SphincsCVerify.BulkVectors
import SphincsCVerify.Interpreter.C10Program

open SphincsCVerify.Spec
open SphincsCVerify.Spec.ByteVec
open SphincsCVerify.Interpreter

/-- Decode one hex nibble. -/
def hexNibble (c : Char) : UInt8 :=
  if '0' ≤ c ∧ c ≤ '9' then (c.toNat - '0'.toNat).toUInt8
  else if 'a' ≤ c ∧ c ≤ 'f' then (c.toNat - 'a'.toNat + 10).toUInt8
  else if 'A' ≤ c ∧ c ≤ 'F' then (c.toNat - 'A'.toNat + 10).toUInt8
  else 0

/-- Parse a "0x..."-prefixed hex string into an `Array UInt8`. -/
def hexToBytes (s : String) : Array UInt8 := Id.run do
  let arr := (s.toList.drop 2).toArray
  let mut out : Array UInt8 := #[]
  let mut i := 0
  while h : i + 1 < arr.size do
    out := out.push (hexNibble arr[i]! * 16 + hexNibble arr[i + 1]!)
    i := i + 2
  pure out

/-- Total decoder to a fixed-length `ByteVec` (right-pad / truncate to `n`). -/
def toBV (n : Nat) (a : Array UInt8) : ByteVec n :=
  ⟨(a ++ Array.replicate n 0).extract 0 n, by
    simp [Array.size_extract, Array.size_append, Array.size_replicate]
    omega⟩

/-- One vector through both paths. Returns `(agreesWithSpec, matchesGroundTruth)`. -/
def checkOne (pkSeedHex pkRootHex msgHex sigHex : String) (expectValid : Bool) : Bool × Bool :=
  let pkSeed32 : ByteVec 32 := toBV 32 (hexToBytes pkSeedHex)
  let pkRoot32 : ByteVec 32 := toBV 32 (hexToBytes pkRootHex)
  let msgBV : ByteVec 32 := toBV 32 (hexToBytes msgHex)
  let sigBV : ByteVec SignatureLen := toBV SignatureLen (hexToBytes sigHex)
  let interp : Bool := C10.execC10Asm pkSeed32 pkRoot32 msgBV sigBV
  let spec : Bool :=
    Signature.verify ⟨pkSeed32.take 16 (by decide), pkRoot32.take 16 (by decide)⟩ msgBV sigBV
  (interp == spec, interp == expectValid)

def main : IO UInt32 := do
  IO.println "=== interpreter ↔ bytecode/spec differential (verify-interp) ==="
  IO.println s!"SignatureLen = {SphincsCVerify.Spec.SignatureLen}"
  IO.println s!"KAT vectors = {SphincsCVerify.KatVectors.vectors.length}, bulk vectors = {SphincsCVerify.BulkVectors.vectors.length}"
  IO.println ""
  let mut katSpecMismatch := 0
  let mut katGtMismatch := 0
  -- KAT corpus (verbose, per-vector)
  IO.println "KAT vectors (interp vs Spec.Signature.verify, interp vs expectValid):"
  for v in SphincsCVerify.KatVectors.vectors do
    let (agreeSpec, matchGt) := checkOne v.pkSeed v.pkRoot v.message v.signature v.expectValid
    if !agreeSpec then katSpecMismatch := katSpecMismatch + 1
    if !matchGt then katGtMismatch := katGtMismatch + 1
    let pad := v.label ++ String.mk (List.replicate (max 0 (34 - v.label.length)) ' ')
    let a := if agreeSpec then " spec=OK " else " spec≠   "
    let b := if matchGt then " gt=OK " else " gt≠   "
    IO.println s!"{pad} {a} {b}"
  IO.println ""
  -- Bulk corpus (aggregate only)
  let mut bulkSpecMismatch := 0
  let mut bulkGtMismatch := 0
  for v in SphincsCVerify.BulkVectors.vectors do
    let (agreeSpec, matchGt) := checkOne v.pkSeed v.pkRoot v.message v.signature v.expectValid
    if !agreeSpec then bulkSpecMismatch := bulkSpecMismatch + 1
    if !matchGt then bulkGtMismatch := bulkGtMismatch + 1
  let katN := SphincsCVerify.KatVectors.vectors.length
  let bulkN := SphincsCVerify.BulkVectors.vectors.length
  IO.println s!"KAT  : interp==spec {katN - katSpecMismatch}/{katN}   interp==expectValid {katN - katGtMismatch}/{katN}  (HARD CHECK)"
  IO.println s!"bulk : interp==spec {bulkN - bulkSpecMismatch}/{bulkN}   interp==expectValid {bulkN - bulkGtMismatch}/{bulkN}  (HARD CHECK)"
  IO.println ""
  if katSpecMismatch > 0 || bulkSpecMismatch > 0 then
    IO.eprintln "FAIL: execC10Asm disagrees with Spec.Signature.verify on some vector."
    return 1
  if katGtMismatch > 0 || bulkGtMismatch > 0 then
    IO.eprintln "FAIL: execC10Asm disagrees with the KAT/bulk ground-truth verdict."
    return 1
  IO.println "OK: the transcribed Yul interpreter reproduces Spec.Signature.verify AND the"
  IO.println "    deployed-bytecode accept/reject verdict on every KAT + bulk vector."
  IO.println "    (Empirical interpreter↔bytecode bridge — the full-(a) precondition.)"
  return 0
