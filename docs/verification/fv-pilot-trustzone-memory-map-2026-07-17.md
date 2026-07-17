# FV pilot — TrustZone memory-map disjointness + source-binding gate (P1.9) — 2026-07-17

> **Scope, first (F9).** Mechanizes the STATIC region-interval disjointness of the
> shipping `stm32u585` memory map (`SAU-NS ∩ secure = ∅` and the `accept ⟹ ∉ secure`
> composition) and binds the Lean literals to the three source-of-truth families with
> a CI gate. It does NOT prove silicon enforcement (no ARMv8-M model; GTZC is
> ST-proprietary — validated only by `make gtzc-enforcement-hw`) and does NOT encode a
> veneer⊆secure theorem (build/silicon-time, QEMU-divergent). `decide` over `u32`
> literals witnesses the interval-algebra SHAPE, not that the literals equal the real
> config registers.

## The two gaps (from the scouting pass)

1. **A confirmed UNGUARDED drift.** The region numbers are triplicated by hand across
   `nonsecure/`+`secure/memory-stm32u585.x` (linker MEMORY), `proto/src/lib.rs` (NS
   windows + mailbox), and `secure/src/sau.rs` (SAU NS regions) — with **no gate**
   cross-checking them. Editing a `.x` MEMORY number without updating `proto`/`sau.rs`
   silently overlaps secure data into an SAU-NS region (a window-"valid" NS pointer
   resolving to a SECURE byte), and nothing catches it.
2. **An unmechanized step.** The Kani-proven NS-pointer validator
   (`shared/src/ns_ptr_validate.rs`) establishes only `accept ⟹ range ⊆ NS-window`. The
   security-relevant `accept ⟹ range ∉ secure` rests on `SAU-NS ∩ secure = ∅`, which
   lived only as prose + two Rust `const _` NS-side subset-asserts (neither ever
   introduces a secure-region literal).

## Deliverable

**Lean (`SphincsCVerify/Platform/MemoryMap.lean`, mathlib-free, `decide`/`omega`,
standalone import — NOT on `theft_free`'s path, zero named axioms):**
- `sauNs{Flash,Sram}_disjoint_secure{Flash,Ram}` — the SAU NS regions are disjoint from
  both secure regions (the previously-unmechanized fact).
- `ns{Flash,Sram}Window_subset_sauNs*` — proto windows ⊆ SAU-NS (the `sau.rs` asserts,
  now theorems); `mailbox_subset_nsSram` + `mailbox_disjoint_secure*`.
- `linkerNs{Flash,Ram}_eq_protoNs*` — the `.x` NS regions EQUAL the proto windows.
- **`accepted_range_disjoint_secure`** — the composition: any range the validator would
  accept (⊆ an NS window) is disjoint from every secure region (`accept ⟹ ∉ secure`),
  via `subset_disjoint`.

**Gate (`contracts/verification/scripts/check_linker_memory_map.py`, source-parse, no
build):** binds all three source families to each other AND to the Lean literals —
`.x` NS == proto NS (drift guard), proto ⊆ SAU-NS, `SAU-NS ∩ secure = ∅` (secure from
`.x`), mailbox ⊆ NS-SRAM, and every `MemoryMap.lean` `def` == its source-derived value.
`--self-test` is a negative control that injects a `.x` NS-FLASH origin INTO the secure
region (the exact silent overlap) and asserts the check fires. Current tree: gate PASSES,
self-test fires (2 failures).

## Result

- Gate on the consistent tree: **OK** (`.x == proto == sau.rs == Lean; SAU-NS ∩ secure =
  ∅`). Self-test: **fires** (drift caught). So the confirmed drift is now guarded and the
  Lean disjointness proof is bound to the real map (not a stale copy).
- `lake build SphincsCVerify` clean; `make -C contracts/verification
  verify-ledger-consistency` passes (MemoryMap is standalone — no tracked closure moves).

## Honest ceiling / residuals

- **Silicon enforcement** (SAU/IDAU/GTZC on the die) stays a HW-receipt assumption
  (`make gtzc-enforcement-hw`); this is interval algebra over literals.
- **`secureFlash` = SECWM1 watermark footprint, not the linker allocation
  (adversarial-review fix 2026-07-17).** The secure region is modeled as the FULL
  1 MB of bank-1 (`0x0C000000..0x0C100000`), which the `.x` documents as the SECWM1
  watermark ("covers all 128 pages of bank 1") — the HARDWARE-secure extent, a
  superset of the 984K the linker allocates. Modeling the full watermark is the
  SOUND direction for `∉ secure` (under-approximating "secure" would let a pointer in
  the tail pages 123–127 read as "not secure" while the silicon rejects it); the gate
  binds to the SECWM1 footprint and sanity-checks that the linker allocation fits
  inside it.
- **No veneer⊆secure** theorem: FALSE on QEMU (NSC at `0x103FF000`, NS-MPC territory)
  and build-time-only on hardware (`__veneer_base/limit` are link-time symbols absent
  from `.x`). Out of frame by design.
- **Higher-fidelity follow-up (flagged, not done):** the strongest form adds
  secure-region consts + a disjointness const-assert INTO the already-Kani-proven
  `ns_ptr_validate.rs` predicate, upgrading `accept ⟹ ⊆ NS-window` to `accept ⟹ ∉ secure`
  in the mechanized proof itself (vs this Lean re-statement of the interval arithmetic).
- **Makefile wiring deferred:** a concurrent session is mid-edit on
  `contracts/verification/Makefile` (adding `verify-tla`); wiring `verify-linker-map`
  now would swallow that uncommitted change. The gate runs standalone
  (`python3 contracts/verification/scripts/check_linker_memory_map.py [--self-test]`);
  add the `verify-linker-map` target (self-test + run) once the `verify-tla` change lands.

## Files

- `contracts/verification/lean/SphincsCVerify/Platform/MemoryMap.lean` (new) +
  `SphincsCVerify.lean` (standalone import).
- `contracts/verification/scripts/check_linker_memory_map.py` (new, self-testing).
