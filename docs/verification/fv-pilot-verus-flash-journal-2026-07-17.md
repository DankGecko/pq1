# FV pilot — Verus flash-journal crash-safety (page-123), all-length — 2026-07-17

> **Scope, first — read before citing.** This is a **fresh pure Verus (verified Rust)
> MODEL** of the page-123 log-structured off-chain signature-counter journal — **NOT**
> the deployed `secure/src/offchain_state.rs` / `secure/src/hw/flash.rs` (unsafe
> flash-MMIO Rust that Verus cannot verify). It proves **a crash property of a Rust
> model of the journal, under named STM32 flash silicon axioms**. The **model ↔
> firmware correspondence is cited-TCB** — argued by construction/inspection against
> the cited `flash.rs` line ranges, not machine-checked (same class as the Lean
> work). Do not read the theorem as "Verus proved the page-123 journal crash-safe";
> read it as "proved a faithful Rust model crash-safe under AX-\*".

## What it adds over the bounded TLA+/TLC pilot

The TLA+/TLC pilot (`contracts/verification/tla/Page123Compaction.tla`) model-checked
the SIGS-first replay ordering over **small-scope** traces (and its negative controls:
`SigsLast` → VIOLATED, `MayValid`-torn → VIOLATED = Finding 1). This Verus pilot proves
the same core property **for all lengths** — unbounded log, unbounded counts (`nat`),
unbounded slots — as a deductive theorem, under an explicitly **assumed** atomic-erase
precondition. Division of labour (per the advisor): **Verus proves the positive
all-length theorem; the non-atomic-erase counterexample stays a TLC job** (Verus proves,
it does not search for counterexamples).

## The model (`contracts/verification/verus/src/lib.rs`)

- `Qw ∈ {Blank, Torn, Entry{slot, ty, count}}` — a decoded 16-byte quadword
  (`parse_entry`, `flash.rs:1398-1440`); `Ty ∈ {Cnt, Uo, Sigs}` (`flash.rs:1354-1367`).
- `proj(log, slot, ty)` = MAX `count` over decodable matching entries (the reader's
  reconstruction, `scan_page_into_table` MAX-merge `flash.rs:1587-1602`, and `userop_sigs_read`
  `flash.rs:2191-2200` — both `count > cur || !found ⇒ cur = count` = MAX-else-0) — defined
  **recursively over the log prefix with `decreases`**, so `proj(push)` is one unfold. (`proj`
  models the max-merge VALUE and abstracts the forward reader's stop-at-first-blank boundary;
  sound here because a torn replay prefix is contiguous/blank-free, and the deployed F-12
  forward-vs-reverse cross-check fails closed on any entry-after-blank.)
- `registered(log, slot)` = ∃ a decodable entry for the slot (`is_registered_forward`,
  `flash.rs:1996-2008`).

## What is proven (`make -C contracts/verification verify-verus` → 8 verified, 0 errors)

- **`sigs_first_no_rollback` (HEADLINE, `INV_SIGS_COMPACTION_LOCAL`, all-length).** In a
  SIGS-first replay, any crash-prefix `replay[0..k]` that leaves a slot **registered *and*
  carrying a replayed `USEROP_SIGS` cell** already has its SIGS durable at the pre-compaction
  value — a torn compaction can never roll such a slot's SIGS below its snapshot. Proof:
  registration in the prefix exhibits an s-cell at `j < k`; SIGS-first forces `j ≥ j0` (the
  SIGS cell), so the prefix contains it; `proj_ge_at` gives `proj_sigs ≥ v`. (SCOPE: a slot
  registered ONLY by the count-0 `USEROP` register marker has no SIGS cell — outside this
  theorem, and trivially safe: `proj_sigs` stays `0`.)
- Supporting lemmas: `proj_push` (append updates proj by max-if-match), `proj_monotone_push`
  (append never decreases proj — counters don't go backwards), `proj_entry_lower_bound`
  (a written entry is a durable lower bound — the model of "release ⟹ prior durable
  charge"), `proj_ge_at` (proj lower-bounds any contained matching entry, by induction).
- **`sigs_last_rolls_back` (NEGATIVE CONTROL — the order is load-bearing).** An
  *exhibited* counterexample: under a SIGS-*last* order, `replay = [Entry(s,Uo,0),
  Entry(s,Sigs,3)]` with crash-prefix `k=1` leaves `s` registered (by the `USEROP`
  marker) yet `proj_sigs = 0 < 3` — rolled back. The honest Verus form of the TLC
  `SigsLast` VIOLATED control (a machine-checked existential; Verus doesn't "run → fail").
- **`witness_reachable` (ANTI-VACUITY).** A concrete log where a slot is registered with
  `proj_sigs = 5`, so the theorem isn't vacuous over an unreachable state (the Verus
  analogue of the `assume(false)` detonation check). Soundness: **no `assume` / `admit`
  / `external_body`** anywhere — every one of the 8 is a genuine proof.

## Conditional on / out of scope (named, loud — STM32U5 flash)

- **AX-TORN-SKIP** (load-bearing): a power-interrupted quadword reads back UNDECODABLE and
  is skipped. Under the alternative "a torn QW may decode as a rogue valid entry" the
  theorem is FALSE (TLA+ Finding 1); the 16-byte format has no CRC/commit-marker, so this
  is silicon, not derivable.
- **AX-ERASE-ATOMIC** (assumed precondition): the 8 KiB page erase is one indivisible step.
  A torn **partial** erase (brownout) breaks the property — that is the TLC pilot's job
  and `flash.rs:1669`'s commit-marker residual, deliberately **not** in this positive
  theorem. Adding a `PartialErase` action to the TLA+ model is the tracked follow-up.
- **AX-QW-WRITE-ONCE / AX-NOR**: 128-bit quadword program, 1→0-only, re-program faults;
  erase → all-0xFF.
- **Out of scope (availability, not safety):** whether a torn-QW ECC read is silent-skippable
  or **traps (NMI → crash-loop brick)** is genuinely undetermined for STM32U5 (repo-doc-cited
  AN5342/RM0456, unconfirmed). The safety model assumes silent-skippable (AX-TORN-SKIP); the
  ECC-trap branch is an unresolved availability residual, not a case in this proof.
- **Compaction-LOCAL, not global.** A crash BEFORE the SIGS cell leaves the slot
  unregistered → invariant #9 forces a Type-1 re-registration; that total-loss branch is the
  accepted residual (TLA+ Finding 2), correctly **not** claimed here.

## Toolchain / reproduce

`make -C contracts/verification verify-verus` (needs the local Verus install — set
`VERUS_DIR` or `source contracts/verification/scripts/fv-external-tools.env`). Verus
`0.2026.07.12` (rustc-pinned), `vstd = 0.0.0-2026-07-12-0122`. Standalone crate
`contracts/verification/verus/` (its own `[workspace]`, not the firmware build).

## Files

- `contracts/verification/verus/{Cargo.toml, src/lib.rs, .gitignore}` — the model + proofs.
- `contracts/verification/Makefile` — `verify-verus` target.
