# Draft upstream reports for AeneasVerif (NOT yet filed)

Findings from extracting a real-world `no_std` crypto crate
(SPHINCS+C10, ~2 kloc) with charon `nightly-2026.06.08` (v0.1.212) +
aeneas `nightly-2026.06.10`, Lean backend. Each repro is a `shape_*`
fn in `src/lib.rs` of this probe crate (build/extract instructions in
`Cargo.toml`). File as separate issues; review before posting.

## 1. Array `==` poisons translation of every later loop in the function

`if seed == &[0u8; 32] { return ...; }` followed (anywhere later in the
same function) by a loop ⇒ "The join of nested borrows is not
supported yet", with the error span pointing at the LOOP, not the
comparison. Removing the comparison (or replacing it with a manual
byte-fold) makes the identical loops translate fine.

Repro: `shape_h`/`shape_k` (fail) vs `shape_m`/`shape_n` (identical
except the comparison → pass).

Suggested title: `Lean backend: array equality followed by a loop
fails with "join of nested borrows" pointing at the loop`

## 2. Constant-index nested-array write poisons later loops ("Unimplemented")

`rows[K - 1] = v` where `rows: [[u8; N]; K]` and `K - 1` is a
const-evaluable index (MIR emits a constant projection), followed by a
loop over `rows` ⇒ "Unimplemented", span on the loop. The same write
with a runtime index (`rows[t] = v`, or routed through
`fn set_row(rows: &mut ..., i: usize, v: ...)`) is fine.

Repro: bisected on the real crate (sphincs-c10 `sign_inner`,
fors_secrets[K-1] write); probe shape pending extraction-shape
minimization.

Suggested title: `Lean backend: constant-index write into nested array
followed by a loop over the same array fails with "Unimplemented"`

## 3. Local opaque types are "Unimplemented"

`--opaque crate::module::LocalType` on a LOCAL struct ⇒
`[Error] Unimplemented` + an internal dump mentioning
`Generated_Types.ItemOpaque` with `is_local = true`. Opaque works for
foreign crates only. Either support local opaques or reject the
pattern with a clear message.

## 4. charon `--exclude` does not match inherent-impl methods

Neither `crate::Type::method` nor `crate::{impl crate::Type}::method`
nor `crate::{crate::Type}::method` excludes an inherent-impl method
(the item still reaches the LLBC; aeneas then errors on its
signature). Free functions match fine. The error name aeneas prints
for the item is `sphincs_c10::{sphincs_c10::SigningKey}::sign_with_shuffle`.

## Notes for the report

- All findings reproduce with `--preset=aeneas`, opt-level 3 and 0.
- Workarounds we shipped (may be useful for the docs): byte OR-fold
  instead of array `==`; helper-fn call boundary for const-index
  nested-array writes; `cfg`-gating `fn(u8)`-typed params out of the
  extraction shape.
- Positive note worth passing along: with those workarounds a real
  2 kloc crypto crate extracts with zero errors, and `step*` discharged
  every panic/bounds obligation of the first verified functions
  automatically.
