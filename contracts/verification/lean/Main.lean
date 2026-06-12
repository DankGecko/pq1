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

### Result (since 2026-06-12)

ALL THREE layers match on every vector. The reconstruction-layer gap
(the A3.1 residual of 2026-06-11) was localised by
`scripts/gap1_differential.py` to a SINGLE divergence: `chainHash`
advanced the WOTS chain position via `Adrs.setChainIndex` (ADRS bytes
[20..24)), where the Rust signer and the deployed Yul thread the
position through the `chain_pos` field (bytes [24..28)) and preserve
the chain index. Everything upstream — digest, FORS forest, forsPk,
layer-0 WOTS digest + digit sum — was already byte-faithful (the
earlier "digit-sum gate fails first" diagnosis in the gap doc was a
downstream symptom at layer 1, not the cause). With `setChainPos` in
place, `Spec.Signature.verify` reproduces the deployed bytecode's
accept/reject decision on all 10 vectors.

Both the digest/index differential AND the full functional verify are
HARD CHECKS (non-zero exit on drift): this runner is now a real
executable Lean ↔ bytecode differential for the complete verifier,
which is what makes A3.1's functional leg dischargeable on the corpus
(the ∀-signature symbolic equivalence remains GAP-2 — Verity/KEVM).
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

/-- The full-verify column is a HARD CHECK: the reconstruction layer was
    made executably faithful on 2026-06-12 (the `chainHash` chain-pos
    field fix — see `Spec/Hash.lean` and docs/A3_1_VERIFIER_GAP.md), and
    `Spec.Signature.verify` now matches the deployed bytecode on all 10
    KAT vectors. Any drift fails the build. -/
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
  IO.println "OK: the executable Lean spec (digest, htIdx, AND full functional verify)"
  IO.println "    is byte-faithful to the deployed verifier on the complete KAT corpus."
  IO.println "    The ∀-signature symbolic equivalence remains the separate GAP-2"
  IO.println "    (Verity / KEVM); see docs/MISSING_FOR_FULL_BYTECODE_PROOF.md."
  return 0
