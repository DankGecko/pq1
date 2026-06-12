/-
Driver for `lake exe verify-mutant-corpus` — mutant-scale Lean ↔ bytecode
functional differential (A3.1 / GAP-1 hardening).

Replays the shared adversarial corpus
`contracts/smart-wallet/test/c10_mutant_corpus.json` (246 entries: 4
positive controls + 242 near-miss mutants; generated deterministically by
`scripts/gen_mutant_corpus.py`) through the executable Lean spec
`Spec.Signature.verify` and asserts the accept/reject decision equals the
corpus' `expectValid` for EVERY entry — a HARD CHECK (non-zero exit on
any mismatch).

The corpus' `expectValid` column is deployed-bytecode ground truth: the
forge suite `test/SPHINCsC10AsmMutantCorpus.t.sol` asserts the deployed
verifier bytecode returns exactly these values (both directions —
wrong-accept AND wrong-reject fail). So a green run here certifies
`Spec.Signature.verify` ≡ deployed bytecode on all 246 corpus points,
including dense sweeps of the two historic GAP-1 defect sites (the
calldataload straddling-read tail [3992,4008) and both per-layer WOTS+C
count fields).

`Lean.Data.Json` is imported HERE only (executable), never by the
`SphincsCVerify` proof library — the kernel-checked development stays
free of the Lean-package dependency.
-/

import SphincsCVerify
import Lean.Data.Json

open SphincsCVerify.Spec
open SphincsCVerify.Spec.ByteVec
open Lean (Json)

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

structure Entry where
  label : String
  pkSeed : String
  pkRoot : String
  message : String
  signature : String
  expectValid : Bool

def parseEntry (j : Json) : Except String Entry := do
  let label ← j.getObjValAs? String "label"
  let pkSeed ← j.getObjValAs? String "pkSeed"
  let pkRoot ← j.getObjValAs? String "pkRoot"
  let message ← j.getObjValAs? String "message"
  let signature ← j.getObjValAs? String "signature"
  let expectValid ← j.getObjValAs? Bool "expectValid"
  pure ⟨label, pkSeed, pkRoot, message, signature, expectValid⟩

def runEntry (e : Entry) : Bool :=
  let pkSeed16 : ByteVec 16 := (toBV 32 (hexToBytes e.pkSeed)).take 16 (by decide)
  let pkRoot16 : ByteVec 16 := (toBV 32 (hexToBytes e.pkRoot)).take 16 (by decide)
  let msgBV : ByteVec 32 := toBV 32 (hexToBytes e.message)
  let sigBV : ByteVec SignatureLen := toBV SignatureLen (hexToBytes e.signature)
  Signature.verify ⟨pkSeed16, pkRoot16⟩ msgBV sigBV

def defaultCorpusPath : String :=
  "../../smart-wallet/test/c10_mutant_corpus.json"

def main (args : List String) : IO UInt32 := do
  let path := args.headD defaultCorpusPath
  IO.println "=== Lean ↔ bytecode MUTANT-CORPUS differential (verify-mutant-corpus) ==="
  IO.println s!"corpus: {path}"
  let raw ← IO.FS.readFile path
  let json ← match Json.parse raw with
    | .ok j => pure j
    | .error e => do
      IO.eprintln s!"FAIL: corpus JSON parse error: {e}"
      return 1
  let entriesJson ← match json.getObjVal? "entries" with
    | .ok (Json.arr a) => pure a
    | _ => do
      IO.eprintln "FAIL: corpus has no .entries array"
      return 1
  let mut mismatches := 0
  let mut positives := 0
  let mut total := 0
  for ej in entriesJson do
    match parseEntry ej with
    | .error e => do
      IO.eprintln s!"FAIL: malformed corpus entry: {e}"
      return 1
    | .ok entry => do
      total := total + 1
      if entry.expectValid then positives := positives + 1
      let got := runEntry entry
      if got != entry.expectValid then
        mismatches := mismatches + 1
        IO.eprintln s!"MISMATCH: {entry.label} — bytecode \
          {if entry.expectValid then "accepts" else "rejects"}, Lean spec \
          {if got then "accepts" else "rejects"}"
  IO.println s!"entries      : {total} ({positives} positive controls, {total - positives} rejects)"
  IO.println s!"agreement    : {total - mismatches}/{total} match the deployed bytecode (HARD CHECK)"
  if total < 240 then
    IO.eprintln "FAIL: corpus unexpectedly small — regenerate with scripts/gen_mutant_corpus.py"
    return 1
  if positives != 4 then
    IO.eprintln "FAIL: expected exactly the 4 positive controls (vacuity guard)"
    return 1
  if mismatches > 0 then
    IO.eprintln s!"FAIL: {mismatches} Lean ↔ bytecode disagreement(s) — the executable spec drifted."
    return 1
  IO.println "OK: Spec.Signature.verify reproduces the deployed verifier's accept/reject"
  IO.println "    decision on the full mutant corpus (incl. the GAP-1 defect-site sweeps)."
  return 0
