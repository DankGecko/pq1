/- Axiom-discipline check for the format_decimal Track-1 M7 END-TO-END WYSIWYS
   composition — CARVED OUT of the default `AxiomCheck.lean` / `Extracted` lib.

   WHY SEPARATE (not a proof defect): kernel-typechecking the single
   `format_decimal_spec` declaration (the `U256.format_decimal` WP-monad
   composition proof term) peaks at ~42 GB RSS / ~1470 s — measured
   2026-07-07 (`/usr/bin/time -v`, profiler: the ONLY `[Kernel]` decl above
   threshold is `FormatDecimalSpec.format_decimal_spec`). That is over the
   16 GB `ubuntu-latest` CI runner. It is a real `qed` — the three theorems
   below close over EXACTLY [propext, Classical.choice, Quot.sound] (no
   `sorryAx`), same discipline as every other §33 rank. Only its CI/build
   *scheduling* differs: it is built + gated via the non-default
   `ExtractedFormatDecimalHeavy` lakefile lib, exercised by
   `make verify-extracted-heavy` on a machine with adequate RAM (local dev +
   cache-hit CI). See `.github/workflows/lean-extracted.yml` (⚠ MEMORY) and
   `docs/work-todo.md`.

   HISTORY: a per-bind "peel" (splitting the WP `let*` seams into separate
   stage lemmas) was attempted 2026-07-07 and MEASURED — it left
   `format_decimal_spec`'s own kernel-TC unchanged at ~42 GB (the peeled
   stages typecheck in <500 ms, but the outer decl still reduces the full
   WP chain), so it was reverted. This carve-out is the honest resolution. -/
import Extracted.FormatDecimal.FormatDecimalSpec

-- `round_post_facts` is the PURE round/no-round case analysis lifted out of
-- the `format_decimal_spec` monolith. All three close over
-- [propext, Classical.choice, Quot.sound] — no hash axiom, no `sorryAx`.
#print axioms FormatDecimalSpec.round_post_facts
#print axioms FormatDecimalSpec.format_decimal_spec
#print axioms FormatDecimalSpec.u256_format_decimal_spec
