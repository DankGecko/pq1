# FV pilot — combined budget-lifetime composition (P1.5) — 2026-07-17

> **Scope, first (F9).** A bounded TLA+/TLC **composition model** that joins the
> two seams the review left un-joined, to answer **Finding 2** of the page-123
> crash-atomicity pilot precisely. It is a MODEL of the composition — not the
> Rust (`aa/src/offchain_gate.rs`), not the Solidity (`PQMultiOwnable.sol`), not
> the silicon — checked by TLC over small constants, not a universal proof.

## The question (Finding 2)

The page-123 pilot showed a torn compaction can **reset** the local per-slot
counters, and left open: *does the on-chain combined cap actually bound the
few-time-key budget across such a reset?* This is the boundary between two things
the review verified separately:

- the **local, resettable** counter policy — `aa/src/offchain_gate.rs`, whose own
  header (lines 48–55) Kani-proves gap/combined-cap/monotonicity **but explicitly
  scopes OUT** the torn-compaction rollback "below the seam"; and
- the **on-chain, monotonic** cap — `PQMultiOwnable.sol`: `_bumpSlotUses`
  (`require(slotUses+1 <= cap)`) + `_setOffchainSigCount` (`revert` if
  `newCount < prev`, `revert` if `slotUses+newCount > cap`).

## The model

`contracts/verification/tla/CombinedBudget.tla` (+ `.cfg`s, `run_combined.sh`).
State = local `(offchain, last_userop, userop_sigs, registered)` + on-chain
`(slotUses, offchainSigCount)` + a **ghost `margin`** = total **slot-key** C10
sigs ever RELEASED. Actions, with the distinctions that matter:

- **`SignOffchain`** (EIP-1271): VIEW-ONLY — gated locally (registration per
  invariant #9, the gap gate, the local combined cap over the *resettable* local
  counters); erodes `margin`; **never touches the on-chain counters**.
- **`SignUserop`** (Type-2): the firmware RELEASES it if the *local* cap passes
  (`margin++`), then it either **LANDS** on-chain (both on-chain gates pass →
  `slotUses++`, `offchainSigCount` reconciled) or **REVERTS** (no on-chain effect).
- **`OffchainSync`** / **`Type1Register`**: the documented post-reset recovery
  (companion restores the `last_userop` floor from the true on-chain count; Type-1
  re-registration is signed by the **bootstrap** key — a *separate* budget, so it
  does **not** erode the slot-key `margin`).
- **`TornReset`**: local counters → 0, unregistered; **on-chain untouched**.

## Result (self-checked by `run_combined.sh`)

`MaxSlotUses=3, MaxGap=2`. Reproduce: `TLA2TOOLS=/path/to/tla2tools.jar
contracts/verification/tla/run_combined.sh`.

| Invariant | Resets | TLC | Meaning |
|---|---|---|---|
| `INV_ONCHAIN_CAP` (`slotUses+offchainSigCount ≤ MaxSlotUses`) | **ON** | **HOLD** (625 states) | ✅ the on-chain cap is preserved by **every** action **including torn resets** — the backstop for fund-moving sigs |
| `INV_MARGIN_BOUNDED` (`margin ≤ MaxSlotUses`) | **OFF** | **HOLD** (14 states) | negative control: without resets the local cap bounds the slot-key margin ⇒ the violation below is **caused by** the reset, not a modeling artifact |
| `INV_MARGIN_BOUNDED` | **ON** | **VIOLATED** | the residual: a torn reset zeroes the local cap inputs, so more view-only slot-key sigs are RELEASED than the cap ever sees |

## What this establishes (closes Finding 2)

1. **The on-chain combined cap is the confirmed backstop for fund-moving sigs.**
   `INV_ONCHAIN_CAP` holds unconditionally — a torn reset never touches the
   monotonic on-chain counters, and the `_bumpSlotUses`/`_setOffchainSigCount`
   reverts keep `slotUses + offchainSigCount ≤ MaxSlotUses` forever. So the number
   of Type-2 sigs that **land / validate on-chain** is bounded by `MAX_SLOT_USES`
   regardless of any number of torn resets. This is the load-bearing safety.

2. **The local combined cap works when counters are not reset.** The negative
   control (`INV_MARGIN_BOUNDED`, resets OFF) holds — so the residual is precisely
   attributable to the reset, not to the gate.

3. **The residual is the few-time-key MARGIN, released UNCAPPED on-chain via
   EIP-1271.** With torn resets, `margin` exceeds `MaxSlotUses`: a reset lets the
   firmware RELEASE more slot-key sigs than the on-chain cap tracks. These are
   EIP-1271 signatures — validated **on-chain** by `wallet.isValidSignature` (a
   `view` call) but never bumping the on-chain counters — so they are NOT bounded by
   the `slotUses + offchainSigCount` cap. This machine-confirms `flash.rs`'s own
   statement that `USEROP_SIGS` (the off-chain/withheld tally) has **no on-chain
   backstop**.

## Residual + mitigations OUTSIDE this model (stated honestly)

The margin erosion is **bounded per reset** by mechanisms outside the model:
- a reset requires a **physical torn compaction** (page fill → compact → power-cut
  at the exact replay window — the page-123 pilot's surface);
- each reset unregisters the slot, so invariant #9 forces a **Type-1
  re-registration**, which spends the separate **bootstrap** few-time budget
  (`MAX_BOOTSTRAP_USES`) — bounding the number of resets.

> **CORRECTION (2026-07-17, adversarial review).** An earlier version of this bullet
> and the commit `4d8d4f47` message claimed the excess off-chain sigs "do not validate
> on-chain (the wallet's `isValidSignature` still enforces the cap)". **That is false.**
> `isValidSignature` / `_erc1271IsValidSignatureNowCalldata` is `view`-only and **never
> reads** `slotUses`/`offchainSigCount` (`PQSmartWallet.sol:573-576, 599-648`) — so the
> excess slot-key sigs released after a torn reset **do** validate on-chain (return the
> `0x1626ba7e` magic for any valid C10 sig, authorizing Permit2 / CoW-presign /
> Safe-cosign flows). The residual is therefore bounded ONLY by the two mechanisms above
> (physical reset rate + bootstrap re-registration budget), and its impact is
> **birthday-margin erosion of the slot key** (releasing more few-time C10 sigs than
> the cap intends), NOT a dismissable few-time-margin bookkeeping concern. Its exact
> quantification is the open refinement below.

Quantifying the exact worst-case erosion (resets × `MAX_OFFCHAIN_GAP`, and whether
it stays within the C10 birthday margin at the shipped `MAX_SLOT_USES=65536`) is
the next refinement — it needs the bootstrap-budget and physical-reset-rate bounds
added to this model.

## Files

- `contracts/verification/tla/CombinedBudget.tla` — the composition model.
- `contracts/verification/tla/cb_*.cfg` + `run_combined.sh` — the 3 pinned checks (self-asserting; the negative control MUST hold).
