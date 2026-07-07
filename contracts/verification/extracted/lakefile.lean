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

/- Heavy carve-out (NON-default): `Extracted.FormatDecimal.FormatDecimalSpec`
   (the end-to-end WYSIWYS `format_decimal_spec`) kernel-typechecks at ~42 GB
   RSS — over the 16 GB CI runner (measured 2026-07-07; a per-bind peel was
   tried + reverted as ineffective). It is a real `qed` (closure
   [propext, Classical.choice, Quot.sound]); only its build SCHEDULING is
   carved out. It is NOT reachable from the default `Extracted` root, so a bare
   `lake build` (and hence `make verify-extracted`) never builds it and stays
   under 16 GB. Build + axiom-gate it on adequate RAM with
   `make verify-extracted-heavy` (→ `lake build ExtractedFormatDecimalHeavy`).
   Its transitive imports (Div10/Extract/Round/Trim/Emit specs, Funs) live in
   the default `Extracted` lib and are shared. -/
lean_lib «ExtractedFormatDecimalHeavy» where
  globs := #[Glob.one `Extracted.FormatDecimal.FormatDecimalSpec,
             Glob.one `Extracted.AxiomCheckFormatDecimal]
