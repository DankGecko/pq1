import Lake
open Lake DSL

/- §33 P0/P1 — Lean project for Aeneas-extracted sphincs-c10 code +
   equivalence theorems against the SphincsCVerify specs.

   Pinned to the SAME Lean toolchain as the Aeneas backend library
   (v4.30.0-rc2); SphincsCVerify (../lean) is on v4.22.0, so the spec
   bridge is deferred — see work-todo §33 P1. The `aeneas` dependency
   is the Lean support library shipped in the AeneasVerif/aeneas repo
   under backends/lean, pinned to the nightly matching the binaries
   that generated the extraction. -/
require aeneas from git
  "https://github.com/AeneasVerif/aeneas.git" @ "nightly-2026.06.10" / "backends/lean"

package «extracted» {}

@[default_target] lean_lib «Extracted» {}
