/-
Driver for `lake exe verify-test-vectors`.

## What this runner actually does (2026-06-11 — made real)

Previous versions of this file only printed a few constants — the
"Lean leg" of the advertised three-way Rust ↔ Solidity ↔ Lean KAT
differential was a STUB; the Lean spec had never been executed on a
concrete signature. This runner replays the 10 shared KAT vectors
(`contracts/smart-wallet/test/c10_test_vectors.json`, embedded via
`SphincsCVerify/KatVectors.lean`) through the executable Lean spec and
reports, per vector and in aggregate, exactly what the Lean spec
reproduces and what it does not:

  (1) hMsg DIGEST layer — `Spec.Hash.hMsg` recomputed from the spec is
      compared to the FIPS-180-4 ground truth embedded by
      `scripts/gen_kat_vectors.py`. A match certifies the Lean SHA-256
      reference (`Spec.Sha256Impl`) and the digest preimage layout
      against the same digest the deployed verifier computes.

  (2) htIdx layer — `Util.extractHtIndex` vs the embedded ground truth.

  (3) FULL functional verify — `Spec.Signature.verify` over the
      byte-decoded signature, compared to the vector's `expectValid`.

### Honest result (current)

Layers (1) and (2) MATCH on every vector — the Lean digest/index
sub-layer is byte-faithful to the deployed bytecode. Layer (3) does
NOT yet match: `Spec.Signature.verify` returns `false` on the VALID
vectors, because the WOTS+C / hypertree RECONSTRUCTION layer
(`Spec.Wots.pkFromSig` → `digitSum ≠ TargetSum`) was specified to
mirror the Rust signer but was never executed, and its ADRS bit-layout
diverges from the deployed Yul. This is the named A3.1 residual (see
`docs/AXIOM_STATUS.json` A3.1 and `docs/A3_1_VERIFIER_GAP.md`): the
verifier's full functional equivalence is carried EMPIRICALLY by the
on-bytecode KAT + the ~250-mutant wrong-accept screen, NOT by an
executable Lean differential.

This runner is wired so the digest/index differential is a HARD CHECK
(non-zero exit on drift — a real regression guard on the Lean SHA-256
and preimage), while the full-verify column is reported but not yet
asserted green, so the artifact tells the truth instead of hiding the
gap. When the reconstruction layer is made faithful, flip
`requireFullVerify` to `true` to promote it to a hard check.
-/

import SphincsCVerify
import SphincsCVerify.KatVectors

open SphincsCVerify.Spec
open SphincsCVerify.Spec.ByteVec
open SphincsCVerify.Spec.Hypertree
open SphincsCVerify.Util
open SphincsCVerify.KatVectors

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

/-- Lowercase hex of a byte array, "0x"-prefixed. -/
def bytesToHex (a : Array UInt8) : String := Id.run do
  let digits := "0123456789abcdef".toList.toArray
  let mut s := "0x"
  for b in a do
    s := s.push digits[(b.toNat / 16)]!
    s := s.push digits[(b.toNat % 16)]!
  pure s

structure Outcome where
  digestOk : Bool
  htIdxOk : Bool
  verifyMatches : Bool

def runVector (v : KatVector) : Outcome :=
  let pkSeed16 : ByteVec 16 := (toBV 32 (hexToBytes v.pkSeed)).take 16 (by decide)
  let pkRoot16 : ByteVec 16 := (toBV 32 (hexToBytes v.pkRoot)).take 16 (by decide)
  let msgBV : ByteVec 32 := toBV 32 (hexToBytes v.message)
  let sigBV : ByteVec SignatureLen := toBV SignatureLen (hexToBytes v.signature)
  let rVal : ByteVec 16 := (Signature.deserialise sigBV).r
  let digest : ByteVec 32 := hMsg (pad16 pkSeed16) (pad16 pkRoot16) (pad16 rVal) msgBV
  let digestOk : Bool := bytesToHex digest.data == v.expectedDigestHex
  let htIdxOk : Bool := extractHtIndex digest == v.expectedHtIdx
  let verifyResult : Bool := Signature.verify ⟨pkSeed16, pkRoot16⟩ msgBV sigBV
  ⟨digestOk, htIdxOk, verifyResult == v.expectValid⟩

/-- Full-verify column is a HARD CHECK as of 2026-06-13: the WOTS+C /
    hypertree reconstruction layer was made executably faithful to the
    deployed bytecode (two fixes — `chainHash` now writes the ADRS
    chain_pos field, and `loadWord32` zero-pads partial tail reads like
    `calldataload`). `lake exe verify-test-vectors` reports full-verify
    10/10; A3.1 is discharged on the functional layer. -/
def requireFullVerify : Bool := true

def main : IO UInt32 := do
  IO.println "=== Lean ↔ bytecode KAT differential (verify-test-vectors) ==="
  IO.println s!"SignatureLen = {SphincsCVerify.Spec.SignatureLen}, vectors = {vectors.length}"
  IO.println ""
  IO.println "label                              digest  htIdx  full-verify"
  IO.println "---------------------------------- ------  -----  -----------"
  let mut digestFails := 0
  let mut htIdxFails := 0
  let mut verifyMismatch := 0
  for v in vectors do
    let o := runVector v
    if !o.digestOk then digestFails := digestFails + 1
    if !o.htIdxOk then htIdxFails := htIdxFails + 1
    if !o.verifyMatches then verifyMismatch := verifyMismatch + 1
    let pad := v.label ++ String.mk (List.replicate (max 0 (34 - v.label.length)) ' ')
    let d := if o.digestOk then "  OK  " else " FAIL "
    let h := if o.htIdxOk then " OK  " else "FAIL "
    let f := if o.verifyMatches then "  match  " else " MISMATCH"
    IO.println s!"{pad} {d}  {h}  {f}"
  IO.println ""
  IO.println s!"digest layer : {vectors.length - digestFails}/{vectors.length} match FIPS ground truth (HARD CHECK)"
  IO.println s!"htIdx layer  : {vectors.length - htIdxFails}/{vectors.length} match ground truth (HARD CHECK)"
  IO.println s!"full verify  : {vectors.length - verifyMismatch}/{vectors.length} match expectValid (HARD CHECK)"
  IO.println ""
  if digestFails > 0 || htIdxFails > 0 then
    IO.eprintln "FAIL: the Lean digest/index sub-layer drifted from the bytecode ground truth."
    return 1
  if requireFullVerify && verifyMismatch > 0 then
    IO.eprintln "FAIL: full-verify differential required but mismatched."
    return 1
  IO.println "OK: digest + htIdx + full functional verify are byte-faithful to the"
  IO.println "    deployed verifier on all 10 KAT vectors (A3.1 functional layer"
  IO.println "    discharged 2026-06-13). The executable Lean Spec.Signature.verify"
  IO.println "    accepts the 4 valid vectors and rejects the 6 negatives, matching"
  IO.println "    the deployed bytecode."
  return 0
