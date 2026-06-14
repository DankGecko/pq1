/-
Driver for `lake exe verify-cavp` — NIST CAVP SHA-256 conformance.

`Spec/Sha256Impl.lean` is the FIPS 180-4 transcription that the whole
digest layer of the Lean development leans on. Until now it was pinned
empirically by only the 10 project KATs (`verify-test-vectors`). This
runner replays the OFFICIAL NIST CAVP byte-oriented SHA-256 suite
(`contracts/verification/cavp/*.rsp`, embedded via
`SphincsCVerify/CavpVectors.lean` by `scripts/gen_cavp_vectors.py`):

  * SHA256ShortMsg.rsp — every (Msg, MD) pair, Len 0..512 bits;
  * SHA256LongMsg.rsp  — every (Msg, MD) pair, Len 1304..51200 bits;
  * SHA256Monte.rsp    — the full SHAVS Monte Carlo procedure: seed the
    three-register state with `Seed`, run 1000 iterations of
    MD[i] = SHA-256(MD[i-3] ‖ MD[i-2] ‖ MD[i-1]) per checkpoint, check
    all 100 checkpoints, re-seeding from each checkpoint.

All comparisons happen in the COMPILED executable (IO-level), not via
kernel `decide` — there are hundreds of vectors and 100,000 Monte
hashes. Exit code is non-zero on ANY mismatch so CI can gate on it.

Run via `make verify-cavp` in `contracts/verification/` (regenerates the
embedded vectors idempotently first).
-/

import SphincsCVerify.Spec.Sha256Impl
import SphincsCVerify.CavpVectors

open SphincsCVerify.Spec.Sha256Impl
open SphincsCVerify.CavpVectors

/-- Decode one hex nibble. -/
def hexNibble (c : Char) : UInt8 :=
  if '0' ≤ c ∧ c ≤ '9' then (c.toNat - '0'.toNat).toUInt8
  else if 'a' ≤ c ∧ c ≤ 'f' then (c.toNat - 'a'.toNat + 10).toUInt8
  else if 'A' ≤ c ∧ c ≤ 'F' then (c.toNat - 'A'.toNat + 10).toUInt8
  else 0

/-- Parse a plain (un-prefixed) hex string into an `Array UInt8`.
    The empty string decodes to the empty array (the CAVP `Len = 0`
    vector — the .rsp's `Msg = 00` placeholder is already dropped by
    the generator). -/
def hexToBytes (s : String) : Array UInt8 := Id.run do
  let arr := s.toList.toArray
  let mut out : Array UInt8 := #[]
  let mut i := 0
  while _h : i + 1 < arr.size do
    out := out.push (hexNibble arr[i]! * 16 + hexNibble arr[i + 1]!)
    i := i + 2
  pure out

/-- Lowercase hex of a byte array, no prefix (matches the .rsp `MD`
    field encoding). -/
def bytesToHex (a : Array UInt8) : String := Id.run do
  let digits := "0123456789abcdef".toList.toArray
  let mut s := ""
  for b in a do
    s := s.push digits[(b.toNat / 16)]!
    s := s.push digits[(b.toNat % 16)]!
  pure s

/-- Run one ShortMsg/LongMsg section through `sha256Bytes`; returns the
    number of FAILING vectors (printing each failure). -/
def runMsgSection (name : String) (vs : List CavpVector) : IO Nat := do
  let mut fails := 0
  for v in vs do
    let got := bytesToHex (sha256Bytes (hexToBytes v.msgHex))
    if got != v.mdHex then
      fails := fails + 1
      IO.eprintln s!"  FAIL {name} Len={v.lenBits}: got {got} want {v.mdHex}"
  IO.println s!"{name}: {vs.length - fails}/{vs.length} pass"
  pure fails

/-- SHAVS Monte Carlo procedure (CAVS 11.x, byte-oriented):

    for j in 0..99:
      MD₀ := MD₁ := MD₂ := Seed
      for i in 3..1002: MDᵢ := SHA-256(MDᵢ₋₃ ‖ MDᵢ₋₂ ‖ MDᵢ₋₁)
      checkpoint j := MD₁₀₀₂ ; Seed := MD₁₀₀₂

    Returns the number of FAILING checkpoints. -/
def runMonte : IO Nat := do
  let mut seed := hexToBytes monteSeedHex
  let mut fails := 0
  let mut j := 0
  for expected in monteCheckpoints do
    let mut a := seed
    let mut b := seed
    let mut c := seed
    for _ in [0:1000] do
      let md := sha256Bytes ((a ++ b) ++ c)
      a := b
      b := c
      c := md
    let got := bytesToHex c
    if got != expected then
      fails := fails + 1
      IO.eprintln s!"  FAIL Monte COUNT={j}: got {got} want {expected}"
    seed := c
    j := j + 1
  IO.println s!"Monte: {monteCheckpoints.length - fails}/{monteCheckpoints.length} checkpoints pass"
  pure fails

def main : IO UInt32 := do
  IO.println "=== NIST CAVP SHA-256 conformance (verify-cavp) ==="
  IO.println "Implementation under test: SphincsCVerify.Spec.Sha256Impl.sha256Bytes"
  IO.println ""
  let shortFails ← runMsgSection "ShortMsg" shortMsgVectors
  let longFails ← runMsgSection "LongMsg" longMsgVectors
  let monteFails ← runMonte
  let total := shortMsgVectors.length + longMsgVectors.length
    + monteCheckpoints.length
  let fails := shortFails + longFails + monteFails
  IO.println ""
  IO.println s!"TOTAL: {total - fails}/{total} CAVP checks pass"
  if fails > 0 then
    IO.eprintln s!"FAIL: {fails} CAVP mismatch(es) — the FIPS 180-4 spec drifted from the official suite."
    return 1
  IO.println "OK: Spec.Sha256Impl matches the full NIST CAVP byte-oriented SHA-256 suite."
  return 0
