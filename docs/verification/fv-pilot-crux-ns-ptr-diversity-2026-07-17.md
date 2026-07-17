# FV pilot — crux-mir implementation-diversity check on the NS-pointer validator — 2026-07-17

> **Scope, first (F9).** A crux-mir (Galois symbolic-simulation) cross-check of the NS-pointer
> window validator, run through a **second engine** (independent of the existing Kani
> harnesses) and against an **independently-written oracle**. It checks a copy of the pure
> arithmetic (`ns_{read,write}_window_ok`), not the deployed `shared` crate directly — the
> copy↔source link is a keep-in-sync cited-TCB gap. The ARMv8-M `TT`/SAU hardware
> re-classification is NOT modeled (no host model; the firmware ANDs it in separately) — same
> boundary as the Kani harnesses.

## Why a diversity check here (the roadmap caveat: value only if it finds/confirms something)

`shared/src/ns_ptr_validate.rs` is already Kani-proven, but the Kani harnesses prove only the
**soundness** direction: `accept ⟹ range ⊆ NS window`. Two things they don't give:
1. **Completeness** — that the validator does NOT spuriously *reject* an in-window range.
2. **Engine diversity** — a second, independent symbolic engine (crux-mir vs Kani/CBMC),
   guarding against an engine-specific soundness bug.

This pilot adds both by proving full **equivalence** `real == oracle` over all symbolic inputs.

## What it does (`contracts/verification/crux/ns_ptr_diversity/`)

- `ns_{read,write}_window_ok` + `NsRegions` copied **verbatim / behaviour-identical** from
  `shared/src/ns_ptr_validate.rs` (keep in sync).
- An **independent u64 oracle** (`oracle_{read,write}_ok`) re-expressing "range ⊆ NS window"
  in wide `u64` arithmetic with `saturating_add` — NO `checked_add`, NO `usize→u32` cast, a
  genuinely different implementation.
- crux-mir tests (`cargo crux-test`) over **symbolic** `ptr: u32`, `len: usize`:
  `ns_read_window_ok(&NS_MAP, ptr, len) == oracle_read_ok(...)` and the write analogue, plus a
  concrete non-vacuity test (accepts a valid in-SRAM range; rejects a secure-flash range and a
  mailbox-straddling range).

## Result — Valid, and it FOUND something

- **`Overall status: Valid` (8 goals proved, 0 disproved).** crux-mir independently confirms
  the validator is **equivalent** to the independent oracle for every `(ptr, len)` — so it is
  both **sound** (⊆-window) *and* **complete** (no spurious rejection), verified on a second
  engine. This is genuinely complementary to Kani, not a duplicate.
- **A real finding surfaced first (the non-vacuity that matters):** crux-mir initially
  **DISPROVED** the equivalence against a *naive* u64 oracle (`p + len as u64`, no
  overflow-safety) — a naive re-implementation **overflows `u64`** for a `len` near `u64::MAX`,
  exactly where the real validator is careful (it guards `len ≤ u32::MAX` and uses
  `checked_add`). So the validator's overflow handling is **load-bearing**: a plausible naive
  rewrite would be wrong, and crux-mir catches it. This also proves crux-mir genuinely *bites*
  (the diversity check is not vacuous). Making the oracle overflow-safe (`saturating_add`, an
  independent mechanism) then yields the Valid equivalence above.

## Honest scope / residuals

- **Copy, not the live crate.** crux-mir runs on a verbatim copy of the two functions (the
  `shared` crate carries `no_std` raw-pointer/volatile code crux-mir would not ingest cleanly).
  The copy↔`ns_ptr_validate.rs` correspondence is inspection-cited (keep-in-sync), the same
  class of gap as any host extraction; a divergence would be caught by re-diffing.
- **Pure arithmetic only.** The ARMv8-M `TT`/SAU silicon re-classification is out of frame (no
  host model) — the firmware ANDs it in; identical boundary to the Kani harnesses and the P1.9
  memory-map pilot.
- **`NS_MAP` is the stm32u585 map** (matches `proto/src/lib.rs` + the P1.9 Lean `MemoryMap`);
  the equivalence is `∀ ptr, len` at that concrete map.

## Reproduce

`source contracts/verification/scripts/fv-external-tools.env` then, in
`contracts/verification/crux/ns_ptr_diversity/`, `CRUX_RUST_LIBRARY_PATH=~/repos/mir-json/rlibs
cargo crux-test`. Needs the schema-8 mir-json + SAW-bundle `crux-mir-comp` (see
`reference` in the env file). Verus/SAW/crux tool set-up: `fv-external-tools.env`.

## Files

- `contracts/verification/crux/ns_ptr_diversity/{Cargo.toml, src/lib.rs}`.
