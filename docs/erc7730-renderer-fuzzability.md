# ERC-7730 renderer fuzzability — extraction status + follow-up

**Status: v1 + v2 LANDED (2026-07-02 / 2026-07-04).** v1 extracted the pure
row-buffer byte-writers (`primitives`). **v2 moved the ENTIRE renderer**
(`Pages`/`MAX_PAGES` substrate + the five ERC-7730 render files) into
`pqsigner_erc7730::display`, so the full per-`FormatOp` dispatch now host-links.
`fuzz/fuzz_targets/erc7730_render_dispatch.rs` drives the contract renderer plus
both EIP-712 typed-data entry points directly. The repaired harness keeps
authenticated IR and attacker-controlled payload mutations in separate input
regions, dispatches with selectors/type hashes that occur in the IR, and
synthesizes exact all-static and canonical sole-tail frames so the ABI preflight
does not make the campaign vacuous.

`make fuzz-seed-erc7730-render` deterministically regenerates a **disposable**
seed corpus from the pinned catalogue. The hundreds of `seed_leaf_*` files and
coverage-evolved corpus are intentionally not committed; regenerate them for
each root.

Two current-root receipts are deliberately separate. The
`FUZZ_TIME=30 make fuzz-all` merge gate used the existing local per-target
corpora, completed all **12 fuzz targets**, and the renderer reached
**21,470,422 executions** with `cov: 108` / `ft: 167`; the fail-closed sweep
found **zero files of any kind** under every artifact directory. A separate
catalogue-seeded supplemental renderer run reached **473,192 executions** with
`cov: 2321` / `ft: 9471`. The supplemental numbers demonstrate deeper
semantic reach but do not describe or substantiate the ordinary merge gate.
On the pre-transplant 2026-07-12 source tree, the repaired seeded harness
also completed **5,989,862 executions in 120 seconds with no artifacts**
(coverage 2,389 after corpus initialization, 2,594 final); that remains dated
source-tree evidence only. Optimized ClusterFuzz builds now explicitly keep
`overflow-checks = true`, matching the secure firmware's arithmetic-panic
semantics. The successful current-root run kept network isolation enabled and used
`/usr/bin/llvm-symbolizer-17` because this host's `llvm-symbolizer-18` cannot
load its missing `libLLVM-18.so.18.1`; that is an environment repair, not a
change to the target or corpus. The secure crate
keeps thin re-export shims (`tx::display::erc7730` + `tx::display::{Pages,
MAX_PAGES}`); the `display_under_test` scaffold + secure renderers now share the
one host `Pages` type. The follow-up section below is the ORIGINAL v1 plan,
preserved for the record — it is now DONE.

Fuzzing's claim is deliberately narrow: under exercised inputs and sanitizers,
the host renderer returned `Ok`/`Err` without a panic, overflow, OOB access, or
memory artifact. It does **not** prove Merkle/binding authority, display
faithfulness, semantic completeness, constant-time behavior, or absence of a
rare unexecuted panic. Those properties remain with bundle/binding tests,
differential render tests, Kani harnesses, source review, and physical LCD/FI
validation.

## Motivation

`secure/src/tx/display/` is gated `#[cfg(not(test))]` — not because the
renderers are impure, but because the parent `mod.rs` imports the hardware-only
`crate::ui::confirm::Page`. That single import drags the whole per-renderer tree
(≈8.6k lines) out of the host build, so the `pqsigner-fuzz` crate cannot link
the render path. Two host-test scaffolds exist only to work around this: the
`#[cfg(test)] mod ui` shim in `main.rs` and the `display_under_test`
`#[path]`-mount tree.

The render path is worth fuzzing: the firmware release profile sets
`overflow-checks = true`, and the amount writers scale an **attacker-controlled
`U256`** (the value comes straight from calldata) through decimal formatting and
`checked_sub` column-budget arithmetic. A slip there is a panic = DoS on the
trusted-display path — exactly where the wallet must never abort. The older
descriptor-side parser/walker harnesses never exercised this byte arithmetic;
the full dispatch harness now does, while the primitive writers retain their
separate focused target.

## v1 — what landed

The `primitives` byte-writers are **Pages-independent**: every one takes a
`&mut [u8; DISPLAY_COLS]` row buffer plus values (`U256`, `Erc20Metadata`,
`chain_id`), never a `Pages`. That makes them cleanly extractable:

- **Moved** `secure/src/tx/display/primitives.rs` →
  `pqsigner-erc7730/src/display/primitives.rs` (visibility widened
  `pub(super)`→`pub`; imports repointed to `pqsigner_tx` / `pqsigner_tx_core`).
  `DISPLAY_COLS` is redeclared in `pqsigner_erc7730::display` (= 16, pinned by a
  `const _: () = assert!(…)`); since it equals the secure constant, the row
  buffers callers pass (`[u8; 16]`) are the same concrete type the moved helpers
  take — no call-site churn.
- **Shim:** `secure/src/tx/display/primitives.rs` is now
  `pub use pqsigner_erc7730::display::primitives::*;`. All ~17 on-device call
  sites keep calling `super::primitives::*` unchanged; `display_under_test`
  re-exports the module instead of `#[path]`-mounting it.
- **Fuzz target:** `fuzz/fuzz_targets/erc7730_display_primitives.rs` hammers the
  amount/token/fee/address writers with adversarial `value × decimals ×
  frac_digits × unit-len` combinations. Non-vacuous — the fuzzer controls each
  dimension independently and reaches the 0/6/18/255 decimal boundaries and
  empty→overflowing unit strings. `make fuzz-erc7730-display-primitives`.

Verification: workspace host build + all 2089 secure host tests (byte-identical
render output) + device `cargo check --target thumbv8m` + the fuzz target builds
under `cargo fuzz` and runs clean (285k runs, cov 398/ft 847, zero
crash/panic/OOM artifacts). The `libLLVM`/`libstdc++` friction seen locally is an
environment quirk (`LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libstdc++.so.6`), not a
target defect.

## Follow-up — host-linking the full `Pages` dispatch (bounded, NOT blocked)

The remaining out-of-scope path is the per-`FormatOp` **emission into `Pages`**
(`render_erc7730_pages` + `formatters.rs`). This is **not blocked by a wall** —
it is a bounded, mechanical move:

1. **Move `Pages` / `MAX_PAGES`** (from `secure/src/tx/display/mod.rs`) into the
   host crate alongside `primitives`. `Page = [[u8; DISPLAY_COLS]; DISPLAY_ROWS]`
   is a pure array type.
2. **Widen `Pages` fields `pub(super)` → `pub`.** The whole `tx::display` tree
   writes `Pages` directly — **~415** raw `.buf`/`.len` field accesses across ~13
   renderer files. Those accessors stay in the secure crate; they keep compiling
   **cross-crate the moment the fields are `pub`** (no methodization, no
   whole-tree move). This is a modest encapsulation *hygiene* widening, not a
   security boundary change: `Pages` is internal firmware plumbing, not an
   attacker-reachable constructor. **Precedent:** the `display_under_test` mirror
   *already* declares `Pages` with `pub` fields, so the host build has run with
   this exact shape the whole time.
3. **Move the five ERC-7730 render files** (`erc7730/{mod,formatters,intent,
   nested,calldata_nested}.rs`) into `pqsigner-erc7730` (deps already host: the
   render resolvers live there, `Erc20Metadata`/`NameResolver`/`Eip1559Tx` are in
   `pqsigner-tx`/`-tx-core`). The secure `tx::display::erc7730` becomes a
   re-export shim; the secure dispatcher `pick_sign_pages` (which pulls
   `cowswap_display`/`safe` — genuinely secure-coupled) stays and calls the host
   entry.
4. **Point `erc7730_render_dispatch`** at the now-host `render_erc7730_pages`;
   delete the `display_under_test` ERC-7730 mount + the `main.rs` `#[cfg(test)]
   mod ui` mirror.

Gates for that move (it is a pure relocation, so verification is
build-parity, not new adversarial review): workspace + device `cargo check` +
all secure host tests byte-identical + the render golden tests unchanged + the
new dispatch fuzz target builds and runs clean.

The cohesion note: `primitives`/`Pages` are *general* display substrate, not
ERC-7730-specific; they live in `pqsigner-erc7730` to avoid a new workspace
crate. If the display substrate grows, extracting a dedicated `pqsigner-display`
crate (with `pqsigner-erc7730` depending on it) is the clean end state.

**UPDATE 2026-07-04 — the move is DONE (M2 of the formatter-∀ track).** Steps
1–4 landed as `d932d9ab` (`Pages`/`MAX_PAGES`/`ascii_str` →
`pqsigner_erc7730::display`, fields widened `pub`) + `695c1e8b` (the five render
files → `pqsigner_erc7730::display::render`; `secure/src/tx/display/erc7730/`
is now a 3-entry re-export shim, `pick_sign_pages` stays secure-side and calls
the host entry; `display_under_test` re-exports the host `Pages`/`render`
instead of `#[path]`-mounting, so `erc7730_render_pure_tests` drives the exact
code the device links), with the dispatch fuzz target repointed at the host
`render_erc7730_pages` in `5533bb25`. Gates re-verified on `e510768e`
(post-EIP-55 + label-truncation): all 3 golden-grid hashes byte-identical
(erc7730/cowswap/safe), 59 erc7730 render tests + full secure host suite
2065/0/1-ignored green, `pqsigner-erc7730` 133/0 green, device
`cargo check --target thumbv8m` (ui-noop,mock-se) clean, `cargo kani
-p pqsigner-erc7730 --only-codegen` clean. Two deliberate deviations from the
step-4 wording: the `main.rs` `#[cfg(test)] mod ui` stub STAYS (its
`DISPLAY_COLS`/`DISPLAY_ROWS`/`show_status` still feed the other mounted
renderers + `nsc/trailer.rs`; only the now-dead `confirm::Page` alias and the
PANICKING `ascii_str` mirror were deleted — the host crate carries the
production `unwrap_or("?")` semantics), and `nested.rs` keeps a direct `sha3`
dep (already in the workspace via `tx-core`) because `hash_struct_array`'s
streaming keccak fold has no buffer to hand the one-shot
`tx_core::hash::keccak256`. Next milestones: M3 Tier-P0 formatter ∀, M4
amount-decision factoring (see the "ERC-7730 formatter-∀
faithfulness" issue on `EthereumPhone/PQ1`, label `source:work-todo`).
