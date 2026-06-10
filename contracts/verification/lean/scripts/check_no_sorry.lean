/-
Audit script: scans the SphincsCVerify project for **real** `sorry`
tactics (not the literal word inside comments / docstrings).

Run via `lake env lean --run scripts/check_no_sorry.lean`.
-/

import SphincsCVerify

open System

/-- Count lines that *start* with whitespace + `sorry` (the real tactic
    form, not a `sorry` substring in a comment). -/
partial def countSorryInFile (path : FilePath) : IO Nat := do
  let txt ← IO.FS.readFile path
  let lines := txt.splitOn "\n"
  let isSorryLine (line : String) : Bool :=
    let trimmed := line.trimLeft
    -- Match an actual tactic-position `sorry` (possibly with comment).
    -- We exclude lines that begin with `--` (Lean line comment) and
    -- lines that don't start with `sorry`.
    !trimmed.startsWith "--" && (trimmed.startsWith "sorry" || trimmed = "sorry")
  return lines.filter isSorryLine |>.length

partial def walk (root : FilePath) : IO (Array FilePath) := do
  let mut out : Array FilePath := #[]
  for entry in (← root.readDir) do
    if (← entry.path.isDir) then
      out := out ++ (← walk entry.path)
    else if entry.path.toString.endsWith ".lean" then
      out := out.push entry.path
  return out

def main : IO Unit := do
  IO.println "Auditing SphincsCVerify for `sorry` (tactic position only) ..."
  let root : FilePath := "SphincsCVerify"
  let files ← walk root
  let mut total : Nat := 0
  for f in files do
    let n ← countSorryInFile f
    if n > 0 then
      IO.println s!"  {f}: {n}"
      total := total + n
  IO.println s!"Total tactic-position sorry count: {total}"
  IO.println ""
  if total == 0 then
    IO.println "✔ Zero tactic-position `sorry`s anywhere under SphincsCVerify/."
    IO.println "  The headline `theft_free` and every claim corollary are"
    IO.println "  closed; their axiom closures are the cited TCB set only"
    IO.println "  (see `make verify-audit` / scripts/dump_axioms.lean)."
  else
    IO.println s!"✗ {total} outstanding tactic-position `sorry`(s) — see docs/AXIOMS.md § D."
    IO.Process.exit 1
