# Off-chain signing + counter adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for an adversarial code-review pass over PQSigner's off-chain signing (EIP-1271 / ERC-6492) and the off-chain counter state machine — `secure/src/nsc/cmd_sign_offchain.rs`, `aa/src/{eip1271,eip6492}.rs`, `secure/src/offchain_state.rs`, and page-123 flash. The property everything here defends is **invariant #9 + the anti-forgery binding**:

> **The firmware — never the companion — performs the `replaySafeHash` (Solady-nested EIP-712) nesting for every off-chain kind, so every off-chain signed value is computationally separated from any on-chain `sphincsDigest` (equal images ⇒ a keccak-256/SHA-256 cross-collision, `∨ BreaksHash`).** This is not a convenience: the on-chain UserOp path verifies a **bare** C10 sig over a SHA-256 `sphincsDigest`, so a firmware that bare-signed a companion-chosen 32-byte value would be a **UserOp-forgery oracle** (`raw32(sphincsDigest(drainOp))` → a valid Type-2 sig → drain behind a blind page). Plus: a per-slot off-chain counter (page-123, log-structured) bounds unbacked sigs at `MAX_OFFCHAIN_GAP=100` and the combined budget at `slotUses[i]+offchainSigCount[i] < 65536`.

**How this differs from the bench red-team.** [`docs/security/red-teaming.md`](../red-teaming.md) covers the bench/counter view. **This playbook is the code-review counterpart** — walking the nesting binding and the counter state machine against invariant #9, hunting a companion-nesting path (the historic HIGH), a counter that loses/dupes an increment under fault, a gap/cap bypass, or an unregistered-slot acceptance. Same discipline as the [FV playbook](../../verification/fv-adversarial-review-playbook.md); the *display* of an EIP-1271 request is the [clear-signing playbook](./clear-signing-adversarial-review.md), the *counter FI* overlaps [sca-fi](./sca-fi-adversarial-review.md) — this playbook owns the **binding + the state machine**.

> **Honesty note.** The forgery-oracle class was a **real fixed HIGH** (the pre-2026-06-11 RAW32 design had the companion pre-nest). Every row's `Status` names the test/sweep proving the current closure. Most are defended-by-construction; the disclosed residual is the torn compaction rollback (OC3), bounded by on-chain monotonicity.

---

## Part A — The off-chain failure catalog (OC1–OC9)

| # | Failure mode | What it looks like | Status (this tree) | Detection | Auto? |
|---|---|---|---|---|---|
| OC1 | **Companion pre-nests a hash → UserOp forgery oracle** | firmware bare-signs a companion-chosen 32-byte value that equals a `sphincsDigest` | **DEFENDED (the historic HIGH, closed for ALL kinds).** Firmware always calls `aa::eip1271::replay_safe_hash` (`eip1271.rs:163-181`): RAW32 (`cmd_sign_offchain.rs:758`), PERSONAL_SIGN (`:761`), EIP712_TYPED / _V3 (`:594`). For V3 the `nested_blob` is **display-only** — the signed digest is byte-identical to kind=2 (render call `:603-613`, digest `:548-598`). **Boundary note (2026-07-17 sweep, see OC11):** for kind=2/3 the *inner* EIP-712 structure is companion-composed; anti-forgery rests on the OUTER nesting + the ERC-7730 binding proof, not on firmware computing the whole structure | Regression `aa/tests/offchain_raw32_forgery.rs` (feeds a real drain `sphincsDigest` as the raw32 payload, asserts `replay_safe_hash(H) != H`); unit `eip1271.rs:317-336` | ✅ regression + unit |
| OC2 | **A raw32 value collides with a `sphincsDigest` structure** | some off-chain value happens to equal an on-chain signable digest | **STRUCTURALLY IMPOSSIBLE.** Off-chain values are `keccak256("\x19\x01"‖domainSep‖structHash)` bound to `(chainId, verifyingContract)`; the on-chain digest is a **bare SHA-256** (`PQSmartWallet.sol:374-391`). A keccak-nest can never equal a SHA-256 digest | Confirm the on-chain digest is SHA-256 and the off-chain domain constants match the deployed impl (`eip1271.rs:51-65` vs `PQSmartWallet.sol:578-585`) | ✅ (by hash disjointness) |
| OC3 | **Counter compaction loses / duplicates an increment** | a fault or power-loss during page-123 compaction rolls the count back | **DEFENDED (with a disclosed bound).** `compact_page` fails closed on >256 slots *before* erasing (flag set `flash.rs:1563-1571`, refuse `:1636-1638`); replay order (USEROP_SIGS → USEROP → COUNT per slot) makes a torn compaction unable to roll a *registered* slot's few-time tally to 0 (replay loop `:1671-1700`). **Residual (disclosed `:1668-1670`)**: a torn COUNT/USEROP rollback is still possible but bounded by on-chain `_setOffchainSigCount` monotonicity + gap ≤ 100 + on-chain `slotUses`. Reads F-12 hardened (fwd+rev double scan, halt on mismatch) | Rainbow `fault_sweep_flashctr.py` (770 rollbacks pre-fix → ~10 residual post-fix); aim FI at the erase-then-replay window | ✅ FI sweep (residual bounded) |
| OC4 | **Gap check bypass** | more than `MAX_OFFCHAIN_GAP` unbacked off-chain sigs slip through | **DEFENDED.** `gap = local_offchain.saturating_sub(last_userop); if gap >= 100 { OffchainGapExceeded }` (kernel `aa/src/offchain_gate.rs:141-143`, invoked `cmd_sign_offchain.rs:343`), with double-read halt-on-mismatch inputs (`:287-303`) and an F-10 recheck after another `wait_random` (`:366-378`) | Rainbow `fault_sweep_cap.py` (mirrors the gap+cap gates verbatim) | ✅ FI sweep |
| OC5 | **Combined-cap overflow** | `slotUses + offchainSigCount` exceeds the cap via wrap or a stale read | **DEFENDED.** `checked_add(1)` + `saturating_add` cap check (kernel `offchain_gate.rs:146-153`) + `OFFCHAIN_COUNT_CEILING = MAX_SLOT_USES-1` funnels every durable writer (`offchain_state.rs:104-121`); on-chain mirror `PQSmartWallet.sol:479`. **Note to probe**: the `userop_sigs` double-read (`cmd_sign_offchain.rs:322-329`) does *not* reject `== u64::MAX` (unlike the other two reads); it is fail-closed only because a glitched max saturates the cap — confirm no path uses it un-saturated | `fault_sweep_cap.py`; the xtask drift gate (`xtask/src/main.rs:1661-1663` fails on `MAX_OFFCHAIN_GAP` drift) | ✅ FI sweep + drift gate |
| OC6 | **Unregistered-slot off-chain sig accepted post-restore** | after a restore, a slot with no on-chain registration gets an off-chain sig | **DEFENDED.** `if !offchain_count_is_registered(slot_key)` only the ERC-6492 counterfactual (`!account_deployed && slot_index==0`) may proceed; every other unregistered slot → `OffchainSlotUnregistered` (`cmd_sign_offchain.rs:266-276`), forcing a Type-1 rotation via `CMD_SIGN_USEROP` first | Probe an FI flip of `offchain_count_is_registered` (mitigated by the F-12 double scan `flash.rs:1978-1994`) | ✅ (F-12 + gate) |
| OC7 | **ERC-6492 `slot_index != 0` accepted** | the counterfactual path signs for a slot the factory never seeds | **DEFENDED.** Rejected twice: early `!account_deployed && slot_index != 0` (`cmd_sign_offchain.rs:178-181`) and inside the unregistered probe (`:272`); the larger 8616-B write is re-validated inside the counterfactual branch (`:185-191,:1001-1020`) to bind it to the larger extent (guards a single-fault deployed→counterfactual flip) | Probe a single-fault flip of `slot_index` / `account_deployed` between the two checks | ✅ (double-checked) |
| OC8 | **Counterfactual sign without auto-register** | a never-deployed wallet gets an off-chain sig with no slot-0 registration | **DEFENDED.** Slot-0 auto-registration is the post-confirm durable bump (`cmd_sign_offchain.rs:977`); MEDIUM-3 explicitly *removed* the early pre-write (`:249-255`) so no durable state lands before the confirm | Verify no early durable write exists before the confirm | ✅ (MEDIUM-3 fix) |
| OC10 | **Counter-commit elision under FI** | a skipped `offchain_count_bump` call (or faulted `Result` read) releases a sig whose durable count never landed → same `new_count` re-issued next request | **CANDIDATE (2026-07-17 sweep, pre-adjudication; LOW, FI-gated).** `cmd_sign_offchain.rs:977` guards the bump only by the callee's internal read-back (`flash.rs:2075-2083`); the handler never independently proves the call ran before the response write. No amplification (one sig per landed fault); OC3 covers compaction rollback, not commit-elision. Fix: after the bump, re-read the count in the handler through an FI sentinel and compare to `new_count` before the first response byte | Rainbow skip on the `offchain_count_bump` call site | ❌ found-this-surface (candidate) |
| OC11 | **kind=2/3 trust boundary misstated** | the catalog's "firmware always nests" framing reads as if the whole EIP-712 structure were firmware-computed | **DOCUMENTED 2026-07-17.** For kind=2/3 the *inner* structure (`domain_separator`, `primary_type_hash`, `encoded_data`) is fully companion-composed; anti-forgery rests solely on the OUTER `replay_safe_hash` + the ERC-7730 binding proof. True nesting holds for kinds 0/1. State this boundary wherever the anti-forgery claim is made | n/a (documentation row) | ✅ documentation |
| OC9 | **`last_userop` desync → unbounded gap growth** | a stale-low `last_userop` lets the gap grow without bound | **BOUNDED.** Repair promotes `local` up to `last_userop` (`:304-312`); `saturating_sub` prevents a negative gap; a stale-low `last_userop` grows the gap until it hits `MAX_OFFCHAIN_GAP` and refuses (`:331-335`). The MEDIUM-2 durable `userop_sigs` tally independently bounds combined slot-key emissions even if publishing UserOps are withheld | `cmd_offchain_sync.rs` (clamps + confirms companion floor bumps); `fault_sweep_cap.py` | ✅ FI sweep |

**Read this catalog as the answer to "can a hostile companion turn the off-chain path into a UserOp-forgery oracle or blow past the caps?"** The forgery oracle (OC1/OC2) is closed **for all kinds** by the on-device `replaySafeHash` nesting + hash disjointness, with a regression test that feeds a real drain digest. The counter machine (OC3–OC9) is defended, with the one disclosed residual (OC3 torn-compaction rollback) bounded by on-chain monotonicity. The sharpest probe targets: the erase-then-replay window (OC3) and the `userop_sigs` un-saturated-read asymmetry (OC5).

---

## Part B — The existing defenses (Layer 1)

1. **The binding invariant.** `aa::eip1271::replay_safe_hash` (`eip1271.rs:163-181`) — `keccak256("\x19\x01"‖domainSep‖keccak256(PERSONAL_SIGN_TYPEHASH‖H))`, bound to `(chainId, proxy_address)`. Called for every kind (`cmd_sign_offchain.rs:572/699/702`). The rationale is documented verbatim (`eip1271.rs:148-161`).
2. **The forgery regression.** `aa/tests/offchain_raw32_forgery.rs` + `eip1271.rs:220-336` (Solady-nesting equivalence, personal-sign equivalence, never-returns-input, domain-binding); `aa/tests/negative_assumptions.rs:474-489` (chain/contract sensitivity).
3. **The counter store.** `offchain_state.rs` + `hw/flash.rs:1259-1746` — page-123 log-structured (COUNT/USEROP/USEROP_SIGS records, 16 B/QW, 7-byte-BE count), crash-atomic compaction (replay order), F-12 double-scan reads, `MAX_DISTINCT_SLOTS=128` brick defense, `OFFCHAIN_COUNT_CEILING` value-inflation defense.
4. **The gap + cap gates.** `cmd_sign_offchain.rs:278-356` (gap < 100, combined cap, checked/saturating arithmetic, F-10 recheck) + the on-chain mirror `PQSmartWallet.sol:479`.
5. **FI sweeps + drift gate.** `fault_sweep_cap.py` (gap+cap mirror), `fault_sweep_flashctr.py` (counter rollback); `xtask` fails the build on `MAX_OFFCHAIN_GAP` drift. Frozen-format tests pin `EIP6492_MAGIC` + `MAX_OFFCHAIN_GAP`. **Kani (added 2026-07-03, work-todo §12e):** the counter *policy* is now bounded-model-checked — the gap + combined-cap gate is extracted to `aa/src/offchain_gate.rs::check_offchain_gate` (Kani-proven fail-closed/monotonic/overflow-free, **used in place** by `cmd_sign_offchain.rs`) plus a `SlotLedger`/`OffchainLedger` model carrying sequence/interleave harnesses (2-step gap+cap limit-slicing, single-op monotonicity, slot isolation, and *both* bricks unreachable — value-inflation sync-no-brick + distinct-slot graceful cap), anti-vacuity-guarded by three `kani_mutations.json` entries and bound to the shipped mock backend by a differential host test (`positive_offchain_gate_model_matches_mock_backend`). **Residual boundary** (stated on purpose): this proves the counter *policy* over adversarial op-orderings; it does **not** reach the flash **crash-atomicity** of the log-structured page-123 store — torn-compaction rollback (OC3) lives below the `check_offchain_gate` seam in `hw::flash::compact_page` and stays covered by the `fault_sweep_*.py` single-fault sweeps, not Kani.

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS's off-chain signing (EIP-1271/6492) +
counter state machine. Your job is to BREAK invariant #9 and the anti-forgery binding — turn
the off-chain path into a UserOp-forgery oracle, or blow past the gap/combined cap, or corrupt
the counter — NOT to confirm them. Default to "the companion controls what gets signed and
the counter can be rolled back until I prove otherwise." The forgery oracle was a REAL fixed
HIGH; treat the nesting as the thing to re-break.

TARGET (read first, in this order):
  - docs/security/adversarial-review/offchain-signing-adversarial-review.md §A — OC1–OC9.
  - secure/src/nsc/cmd_sign_offchain.rs — the handler, the per-kind nesting, the gap/cap gates.
  - aa/src/eip1271.rs + aa/src/eip6492.rs — the replaySafeHash binding + the 6492 blob.
  - secure/src/offchain_state.rs + secure/src/hw/flash.rs (page-123 store + compaction).
  - contracts/smart-wallet/src/PQSmartWallet.sol — the on-chain isValidSignature + combined cap.
  - aa/tests/offchain_raw32_forgery.rs — the forgery regression.
SCOPE THIS RUN: {{e.g. "the per-kind nesting — is ANY kind bare-signed?" | "the counter
  compaction crash-atomicity" | "the gap+combined-cap gates + the userop_sigs read asymmetry"
  | "the ERC-6492 counterfactual constraints"}}.

ATTACK PROTOCOL — walk EVERY OC1–OC9 mode against each surface in scope:
  OC1 companion pre-nests → forgery oracle · OC2 raw32↔sphincsDigest collision · OC3
  compaction loses/dupes an increment · OC4 gap bypass · OC5 combined-cap overflow · OC6
  unregistered-slot accepted · OC7 6492 slot_index≠0 · OC8 counterfactual without auto-register
  · OC9 last_userop desync.

For each candidate finding you MUST produce a FALSIFIABLE PoC, one of:
  - a path reaching c10_sign over a companion-supplied 32-byte value WITHOUT a replaySafeHash
    nest (the forgery oracle) — check ALL kinds incl EIP712_TYPED_V3's display-only blob;
  - a fault/power-loss sequence in compaction that rolls a registered slot's count back;
  - a gap/cap arithmetic path that wraps or uses an un-saturated read;
  - an unregistered/6492 acceptance that shouldn't happen.
  No PoC ⇒ list under "suspicions, unverified".

RULES:
  - Verify against the CURRENT tree; confirm on-chain sphincsDigest is SHA-256 and off-chain is
    keccak-nested (the disjointness OC2 rests on).
  - A green counter unit test is not a green fault sweep — state which you ran.
  - For each candidate: OC-mode, file:line, PoC, provisional severity, stable
    candidate ID, and proposed fix (flag if it
    would let the companion nest, weaken a cap, or break compaction crash-atomicity).
    Do not assign a finding disposition.

OUTPUT — return an external candidate packet to the coordinator. Do not modify
the repository, write a canonical findings report, or update catalogue/status
fields. Include every candidate and the honest residual. The coordinator freezes
the raw packet and gives the complete union to the exact Partner-A/Partner-B
pair; only their symmetric cross-adjudication may assign dispositions. An
authorized maintainer records the adjudicated result afterward.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. "What I tried to break and COULDN'T" — per surface, esp. the nesting per kind.
  2. "What I did NOT look at" — kinds/paths not walked, the offchain_state Kani gap.
  3. "PROVENANCE — did this pass RUN fault_sweep_cap/flashctr / the forgery regression, or
     read source only?"
  Never imply "the rest is fine."
```

**Running it as a swarm.** Use ≥3 independent discovery reviewers per scope
across two model backends. Quorum only corroborates/prioritizes discovery; it
does not set a disposition, and sub-quorum variants remain in the packet. Give
every candidate and origin variant to the exact Partner-A/Partner-B pair in
[`../../planning-and-review-workflow.md`](../../planning-and-review-workflow.md);
only their symmetric cross-adjudication may disposition it, with disagreement
preserved. Split the four kinds one-per-reviewer for OC1 (each proves its kind
nests).

---

## Part D — Cadence + honest boundary

- **Per-PR touching `cmd_sign_offchain.rs`, `aa/eip1271.rs`, `offchain_state.rs`, or the caps:** the forgery regression + the counter host tests + `fault_sweep_cap.py` if the gates changed. A new off-chain kind ships with a proof it routes through `replay_safe_hash` or it does not ship.
- **Per-milestone:** the full rainbow sweep (cap + flashctr) + a fresh Part-C pass on the nesting; consider adding a Kani harness over `offchain_state` (the current gap).
- **The one-line gut check:** *does every off-chain kind pass through `replaySafeHash` on-device, and can any counter increment be rolled back under a single fault?* If a kind bare-signs, or a rollback survives the sweep, invariant #9 is broken.

**The boundary, stated on purpose.** This playbook can tell you that no off-chain kind bare-signs and the caps hold under the run sweeps, as of the last executing pass. It **cannot** tell you the torn-compaction residual (OC3) is fully unreachable (it is bounded, not eliminated), that a kind you didn't walk nests, or that the on-chain domain constants match the deployed bytecode (that is the [on-chain playbook](./onchain-contracts-adversarial-review.md) + the codehash-freeze test). Those are the sweep's + the on-chain review's job.
