# RESIDUAL — bootstrap-key few-time budget aggregates across chains

> **STATUS: AWAITING OWNER DECISION (raised 2026-07-26).** This is *not* marked accepted.
> Project policy (`docs/planning-and-review-workflow.md:493`) requires a **separate, exact owner
> acceptance** per residual; the existing `GET_INIT_CODE` acceptance
> (`docs/VULN-getinitcode-bootstrap-fewtime-oracle.md`, 2026-06-30) is scoped to that oracle and
> **does not** cover this. Nothing here is a demonstrated weakness or an attack.

**Classification: documentation/claim accuracy, not a security fix.** Two independent adversarial
reviewers (GPT-5.6, Kimi K3) converged on that wording independently.

## The fact

- The **bootstrap/master key is chain-INDEPENDENT**: `master = HMAC-SHA512("sphincs-c6-v1", bip39_seed)`
  — no `chain_id` (`domain/src/lib.rs:537,556-566`). Invariant #6 *requires* this: the CREATE2 salt is
  `sha256(masterPkSeed ‖ masterPkRoot)`, so the same 24 words must give the same address on every chain.
- The cap **`bootstrapUses < 65,536` is PER CHAIN** (proxy-local storage; `PQMultiOwnable.sol:22`,
  bumped in `validateUserOp`).
- Therefore a single bootstrap key's budget across `C` chains is **`C × 65,536`**, not `65,536`.
- Slot keys are unaffected — they *are* chain-bound (`slot_entropy` binds `chain_id_be8`), so their
  65,536 cap is a true per-key cap.

**This was already known and documented** as "P14 (cross-chain caveat)" with its own theorem
(`advantage_floor_within_bootstrap_cap_crosschain`) in `Quantitative.lean:172-205`. What was wrong was
the *headline prose* in `CLAUDE.md` / `README.md` / `proto/src/lib.rs`, which stated the margin
per-chain, and one mislabeled modality in the Lean docstring. All four are now corrected.

## Margins (reproduced independently from `contracts/verification/scripts/forsc_grinding_margin.py`)

| C chains at full cap | q | FORS+C work factor | generic multi-target floor |
|---|---|---|---|
| 1 | 2^16 | 130.57 b | 96 b |
| ~1.5 | 99,376 | **128.00 b** | ~95 b |
| 2 | 2^17 | 126.16 b | **94 b** |
| 4 | 2^18 | 121.02 b | 92 b |
| 16 | 2^20 | ~108 b | 88 b |

**Calibration that matters:** the project's own adopted floor is **96 bits**
(`WORK_FLOOR_BITS = 96`; binding Lean floor 96), not 128. Against 96 the work-factor model crosses at
**~43 chains at full cap**. The "crosses at ~1.5 chains" figure is against a 128-bit target stricter
than anything this project claims.

## Why the practical exposure is far below the cap

- Bootstrap signatures are **slot rotations only** — tens per device lifetime, not ordinary transactions.
- Counted Type-1 signatures are **user-confirmed on the trusted display AND gas-paid on-chain**.
  Reaching q = 2^17 means ~131k affirmative confirmations plus ~131k on-chain transactions.
- That path is strictly **harder** than the already-accepted uncounted `GET_INIT_CODE` oracle
  (~80 sigs/unlock, no confirm), whose harvest is "measured in centuries".

## Options considered — and why the tempting ones were rejected

| # | Option | Verdict |
|---|---|---|
| (a) | **Correct the documented claim (per-KEY, not per-chain)** | **DONE** — `CLAUDE.md`, `README.md`, `proto/src/lib.rs`, `Quantitative.lean` |
| (b) | Lower the per-chain cap (65,536 → 4,096) | **Not a standalone fix.** No finite `C` is enforced anywhere (firmware accepts an arbitrary `u64` chain id), so a lower constant bounds nothing unless `C_max` is also enforced and *every* release path counted. Low value, churns frozen-constant tests. |
| (c) | Device-side global bootstrap counter | **REJECTED — and this is the one the two reviewers disagreed on.** Kimi proposed it as "the real fix"; GPT-5.6 refuted it and the refutation verifies: page 123 is **device-local flash**, while the bootstrap key is re-derived from the **mnemonic**. Restoring the same seed on a fresh device yields the *identical key with a zeroed counter*. It therefore **cannot** be a lifetime per-key cap across recovery or cloned devices. It could still serve as a per-device rate limit — but it must not be *called* a lifetime cap, which would just be a new false claim. |
| (d) | Chain-bind the bootstrap key | **RULED OUT** by invariant #6 — the master pk determines the CREATE2 salt, so a chain-bound key gives a different address per chain, breaking cross-chain address stability. Both reviewers concur. |
| (e) | Per-chain domain separation of the Type-1 message | **REFUTED.** Messages *already* bind the chain (`sphincsDigest` includes `block.chainid`; `factory_digest` includes `chain_id`), and domain separation **does not reduce q** — FORS few-time coverage accumulates over all signatures under one key regardless of message domain. |

## The only coherent "real fix", if unconditional ≥128-bit lifetime assurance is ever made non-negotiable

Split the roles (GPT-5.6): a **chain-independent identity key** that determines the CREATE2 salt and
certifies **one chain-bound operational admin key per chain**, which becomes owner 0. The identity key
then signs ~once per chain, and every operational bootstrap key gets an independent budget. This is a
**substantial factory + wallet + firmware redesign** (today one key serves salt, deploy verification,
and owner 0) and is only warranted if the ≥128-bit lifetime bound becomes a hard requirement.

## Additional true statement that belongs in the record

This cap bounds **accepted on-chain submissions, not signatures produced**. The factory deploy
signature, `CMD_GET_INIT_CODE`, and ERC-6492 counterfactual signatures all release bootstrap-key
signatures the counter never sees. It was never a lifetime per-key signature bound.

## Recommendation put to the owner

Accept as a documented residual on the strength of: realistic usage is tens of signatures; the
practical path is dominated by the already-accepted oracle; and the project's own 96-bit floor is not
approached until ~43 chains at full cap. **No code change is recommended.** If instead an unconditional
≥128-bit lifetime bound is wanted, the identity/admin key split above is the only coherent route.
