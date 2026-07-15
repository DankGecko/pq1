# Lifecycle, provisioning, persistent-state, recovery, and RMA adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for adversarially
reviewing the state transitions that span more than one PQSigner subsystem:
factory/transit state, first boot, wallet provisioning, normal use, update,
wipe/restore, recovery, RMA/refurbishment, and decommissioning. The review
target is the *composition* of STM32 flash/option-byte/OTP/TAMP state with
OPTIGA and SE050 objects, not merely whether each local driver works.

> **Current state (2026-07-14).** The adopted design ships at RDP0 so a user can
> inspect the device, then self-locks to RDP2 on first field boot before the
> BHK first-write and TRNG-salted OPTIGA/SE050 key rotation. That flow is
> tracked by `docs/work-todo.md` item 36 and has an **implemented candidate
> behind `rdp2-self-lock`, but is not production-approved or authorized for
> execution**. A review may compile it and run host-only simulations;
> this playbook does not authorize option-byte burns, key rotation, destructive
> wipe, or RMA access.

> **Target claim.** Every lifecycle transition has one authoritative state
> machine; validates every reversible prerequisite before an irreversible
> step; is power-cut-safe and idempotently resumable; never exposes, clones, or
> silently reuses secret state; and leaves the user in a truthful, recoverable
> state or an explicit terminal state. No untrusted command may convert finite
> storage or a recoverable mismatch into a durable signing brick without the
> required consent.

**Sibling boundaries.** The [silicon-lockdown playbook](./silicon-lockdown-adversarial-review.md)
owns the correctness of individual RDP/WRP/HDP/OTP/LcsO burns; the
[secure-element playbook](./secure-element-adversarial-review.md) owns each
chip's local policy; the [firmware-update playbook](./firmware-update-secure-boot-adversarial-review.md)
owns image acceptance and A/B boot; and the [off-chain playbook](./offchain-signing-adversarial-review.md)
owns counter semantics. **This playbook owns ordering, atomicity, ownership,
recovery, migration, and end-of-life across those boundaries.** Bench-side
power-cut and destructive tests remain in [`red-teaming.md`](../red-teaming.md)
and require an explicitly designated sacrificial device.

---

## Part A — The lifecycle / durable-state failure catalog (LC1–LC10)

| # | Failure mode | What to try to prove | Status / anchor in this tree | Detection | Auto? |
|---|---|---|---|---|---|
| LC1 | **Ambiguous lifecycle authority** | Device/fixture/user components infer different states (blank, factory, transit-verifiable, first-boot-in-progress, provisioned, recovery, RMA), so a privileged step runs from the wrong state | **OPEN for item 36.** The device-side candidate state machine and journal are implemented, but the authenticated per-unit factory handoff/receipt and production lifecycle authority are not closed. Existing `is_provisioned()` checks remain local observations rather than a cross-device lifecycle authority. Include connect-under-reset ship-state verification and the deliberate residual for a user who powers a transit-reflashed unit before verifying it. | Enumerate state predicates and produce two actors/stores whose classifications disagree | ❌ adversary/model |
| LC2 | **Irreversible step before complete preflight** | RDP/LcsO/key rotation/counter advance happens before image, power, UID, option-byte, storage, and downstream-key checks succeed | **SHIP-BLOCKING IMPLEMENTATION/VALIDATION RISK.** The item-36 candidate performs preflight before RDP2 and uses commit-last journaling after rotation, but E140 lifecycle ordering and silicon cut-point evidence remain open. A BHK/pairing root created while RDP0 still supplies the shared DHUK may become unusable or retain the wrong security identity after the final transition. The legacy firmware-update floor ordering is a concrete warning (`VULN-fwcommit-otp-before-commit-brick.md`). | Dependency DAG + fail-before/fail-after injection at every irreversible edge | ⚠ model; silicon later |
| LC3 | **Cross-store partial commit / half-provision** | STM32, OPTIGA, and SE050 disagree after reset; retry selects the wrong credentials or cannot erase the first write | **KNOWN CLASS, WITH A CURRENT LOCAL INSTANCE.** `VULN-provision-halfwrite-softbrick.md` records one rollback fix and a remaining silicon/credential residual. Separately, `secure/src/hw/bhk.rs::provision` writes two ciphertext quadwords without a commit marker while `is_provisioned()` accepts any non-`0xFF` byte. A cut after QW0 makes a torn BHK authoritative and prevents retry (`docs/work-todo.md` `sh-3`). The new first-boot rotation also re-opens the cross-store composition question. | Host fault injection around every durable write; require commit-last records; power-cut matrix on an authorized sacrificial device | ✅ host / ⚠ HW |
| LC4 | **Non-idempotent resume or false completion receipt** | A torn journal, stale marker, discarded backend error, or duplicate command skips/repeats work or declares READY/WIPED early | **OPEN item-36 requirement plus a SOURCE-CONFIRMED REVIEW TARGET.** The boot block containing `"Wipe-in-progress flag set"` in `secure/src/main.rs` and `secure/src/nsc/cmd_request_unlock.rs::trigger_lockout_wipe` discard `factory_reset_admin()` errors, reset the MCU attempt counter, and display `WALLET WIPED`; a failed SE wipe can therefore be presented as success. Pairing-key rotation must also authenticate under the new keyset before commit—marker write alone is not proof. | Cut-point model + force every backend failure; success UI/receipt only after all postconditions | ✅ host/model + ⚠ HW |
| LC5 | **Persistent-address / ownership collision** | Two features erase or reinterpret the same page, object, OID, OTP word, or backup register | **HISTORICAL INSTANCE STRUCTURALLY FIXED; CLASS REMAINS LIVE.** The persistent firmware-failure counter and its page-126 collision were removed; `secure/src/hw/flash.rs` and `secure/src/hw/bhk.rs` now assign page 126 only to BHK. Reconcile the now-stale `VULN-page126-bhk-fwfail-collision-brick.md` separately. Pages 123–127 and all SE objects still need one generated global ownership ledger. | Generate an ownership map from linker/config/constants; reject overlaps and unversioned aliases | ✅ structural |
| LC6 | **Untrusted durable resource exhaustion** | A host can consume flash entries, SE objects, counter budget, erase endurance, or retry budget until normal signing is permanently wedged | **TWO FIXED WITNESSES, CLASS REMAINS LIVE.** The page-123 distinct-slot and value-inflation bricks are fixed, but show that local authorization checks miss global durability. | Stateful fuzzing with capacity/endurance bounds; prove reclamation or explicit terminal behavior | ✅ model/fuzz |
| LC7 | **Wipe/reset/restore scope error** | Wipe leaves a usable secret/binding behind, destroys a non-recoverable transport/admin credential too early, or restores a wallet under stale counters/metadata | **PARTIALLY DEFENDED, CROSS-STORE PROOF ABSENT.** Admin-wipe and recovery paths exist, but no single executable postcondition covers MCU + both SEs + anti-rollback + duress. `make factory-reset` explicitly leaves OPTIGA objects and option bytes, so it is not a sanitization/decommission receipt despite “full device” wording. | Snapshot every durable store before/after each reset kind; assert ceremony-specific allowlist postconditions | ✅ host + ⚠ HW |
| LC8 | **Schema, migration, rollback, or clone split-brain** | New firmware interprets old bytes differently; downgrade/restore resurrects authority; interrupted migration is neither old nor new; restoring onto a second device loses few-time/off-chain counter history while the old device remains live | **REASONED-LATENT.** Several stores use fixed pages/domains and device-local counter state while the update architecture is being replaced. Compatibility, clone/old-device behavior, re-registration, and migration ownership must be explicit before first shipment. | Golden images + upgrade/downgrade/power-cut matrix; restore to a second device and exercise old/new wallets | ✅ host/model |
| LC9 | **Ownership-transfer/RMA/refurbishment/decommission secret revival** | A transferred/returned unit exposes seed material, pairing keys, PIN/counter state, user metadata, or can be reissued with an old identity | **POLICY/EVIDENCE GAP.** Wallet reset, restore, ownership transfer, RMA, refurbishment, and decommission require different postconditions. No completed RMA authority/sanitization receipt or stranded-SCP03/PBS/BHK state taxonomy is identified in `STATUS.md`; RDP2 changes diagnostic options. | Numbered fail-closed RMA states + access matrix + sacrificial teardown + negative re-enrollment | ❌ process / ⚠ HW |
| LC10 | **Availability excluded from the security contract** | A review calls a permanent signing brick “out of scope” even though an untrusted host can cause it or recovery destroys funds/access | **CLAIM TENSION.** Durable-brick vulnerabilities are rated HIGH in `docs/security/vulns/`, while portions of the threat-model posture historically deprioritize bricking. Every review must state the S6/recoverability policy it applies. | Reconcile threat claims with the findings ledger; classify consent, recovery cost, and fund impact | ❌ review |

**Catalog rule.** A local rollback handler is not enough to close LC3/LC4/LC7:
the proof obligation is the *combined* durable state after any reset at any
write boundary. Likewise, an availability finding is not dismissed merely
because it does not reveal a signing key; the report must show whether the
attacker is remote/physical, whether genuine consent was present, and what
recovery costs or destroys.

---

## Part B — The existing defenses (Layer 1)

1. **Known-failure regression corpus.** Start with
   [`docs/security/vulns/README.md`](../vulns/README.md), especially the
   half-written provisioning, page-126 collision, firmware-commit ordering,
   and page-123 exhaustion reports. Their fixes are regression seeds, not a
   proof that the failure class is exhausted.
   A wipe is not complete until every required backend reports its
   postcondition; callers must not clear retry state or display success after
   discarding a backend wipe error.
2. **Local rollback and state checks.** `secure/src/crypto.rs`,
   `secure/src/dual_se.rs`, the admin-wipe paths, off-chain store, PIN counter,
   BHK store, and firmware-update journals contain local recovery logic. Build
   one cross-store transition table before trusting any of them in isolation.
3. **Structural storage ownership.** The persistent FW-failure counter was
   removed, and the current flash/BHK source now assigns page 126 only to BHK.
   `negative_invalid_manifest_can_never_wipe_or_write_persistent_state` pins
   the absence of persistent writes from malformed update input. Preserve that
   fixed witness while extending one generated ownership ledger across every
   flash page, option-byte/OTP field, TAMP backup register, SE050 object ID,
   and OPTIGA OID; comments alone are not a collision fence.
4. **Adopted first-boot requirements.** `docs/work-todo.md` item 36 and
   `docs/firmware/feature-flags.md` define the RDP0 shipment and post-lock key
   rotation ordering. An executing candidate now exists behind
   `rdp2-self-lock`; treat it as unapproved until authenticated handoff,
   recovery/KVN semantics, E140 ordering, cut-point tests, and authorized
   silicon receipts close.
5. **Sibling evidence.** Image/rollback checks, SE policy tests, option-byte
   receipts, USB authorization, and off-chain counter models remain owned by
   their respective playbooks. Import their results into the lifecycle model;
   do not silently convert “local test passed” into “composition passed.”

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS lifecycle and persistent state.
Break the composition across factory/transit, first boot, provisioning, normal use,
update, wipe/restore, recovery, RMA/refurbishment, and decommissioning. Do not merely
review each driver's happy path. Do NOT execute irreversible burns, key rotations,
destructive wipes, or RMA procedures unless the irreversible-action gate in
docs/planning-and-review-workflow.md is satisfied by a separate owner instruction
naming the exact operation and sacrificial board/device. Without that authority,
limit execution to source review, host-only simulations, and isolated scratch state.

TARGET (read first, in this order):
  - docs/security/adversarial-review/lifecycle-persistent-state-adversarial-review.md
    §A — LC1–LC10.
  - docs/work-todo.md item 36 + docs/firmware/feature-flags.md — adopted RDP0→RDP2
    first-boot ordering; distinguish target design from implemented evidence.
  - docs/security/vulns/README.md and the five durable-brick/provision reports.
  - secure/src/{crypto,dual_se,offchain_state}.rs, secure/src/hw/{bhk,otp}.rs,
    secure/src/fw_update/, secure/src/nsc/.
  - docs/provisioning/provisioning-reference.md, docs/production-todo.md, and
    docs/security/threat-model.md — ceremonies, authority, and residuals.
SCOPE THIS RUN: {{a lifecycle transition, store set, or recovery path}}.

ATTACK PROTOCOL — walk EVERY LC1–LC10 mode:
  LC1 authority ambiguity · LC2 irreversible-before-preflight · LC3 partial commit ·
  LC4 bad resume/receipt · LC5 ownership collision · LC6 durable exhaustion ·
  LC7 wipe/restore scope · LC8 migration/rollback split-brain · LC9 RMA/decommission ·
  LC10 availability-policy mismatch.

First construct a state/store matrix. Rows are lifecycle states and transitions. Columns
must include STM32 flash pages 123–127 and boot/update pages, option bytes, OTP, TAMP/BHK,
OPTIGA OIDs/metadata/LcsO, SE050 objects/SCP03/UserID, and any external binding receipt.
For every transition identify: authority, preconditions, reversible writes, irreversible
writes, commit marker, retry behavior, and user-visible recovery.

Treat wallet reset, restore, ownership transfer, RMA/refurbishment, and decommission as
separate ceremonies with separate allowed residuals. For pairing rotation, prove both the
old and candidate keysets' expected authentication behavior before committing. For restore,
keep the old device live, restore onto a second one, and exercise registered/unregistered
few-time slots, withheld/off-chain signatures, account/chain changes, counter loss,
reorganizations, and any Type-1 re-registration path.

For each candidate finding produce a FALSIFIABLE PoC, one of:
  - a reset/fault cut point yielding an unreachable or falsely-complete combined state;
  - two components classifying the same snapshot differently;
  - a concrete overlapping owner/address or incompatible schema decoder;
  - a bounded host command sequence that exhausts durable capacity or endurance;
  - a wipe/restore/RMA snapshot retaining or destroying a forbidden object.
  - a discarded backend error followed by counter reset, READY/WIPED UI, or a success receipt.
No PoC => list under "suspicions, unverified". A purely hypothetical power cut without
the exact before/after writes is not a finding.

RULES:
  - Separate IMPLEMENTED, TESTED, TARGET-DESIGN, FACTORY-RECEIPT, and SILICON-ONLY claims.
  - Treat LC2/LC3/LC4 as a dependency graph; never recommend moving a one-way write earlier
    just to simplify recovery.
  - Preserve anti-rollback and PIN/duress invariants; a recovery path that reopens forgery
    or leaks a seed is not a recovery.
  - Cross-link sibling findings instead of duplicating their local root cause. This report
    owns the composition failure and the exact inconsistent combined state.
  - Cite unique symbols/strings plus file paths; line numbers alone rot.

FIRST-PASS OUTPUT — use the raw-report schema in
docs/planning-and-review-workflow.md §8; do not use the post-cross canonical
docs/security/adversarial-review/findings/TEMPLATE.md:
  Return lifecycle-persistent-state-<YYYY-MM-DD>-<partner-or-run>.md in external/isolated scratch output;
  do not edit the frozen repository or findings index. After both first passes and
  both cross-reviews freeze, an authorized maintainer may archive byte-for-byte
  copies in a separate reporting commit; only the frozen cross matrix feeds the
  canonical findings catalogue. Each candidate needs LC-mode, severity,
  exact state snapshot/transition, falsifiable PoC, and proposed minimal correction.
  First-pass discovery must not assign canonical disposition or finding Status; the
  required exact partner pair does that only through symmetric cross-adjudication.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. What I tried to break and COULDN'T — including the strongest cut point attempted.
  2. What I did NOT inspect — stores, lifecycle states, migrations, RMA policy, or silicon.
  3. PROVENANCE — source/model/tests actually executed vs documents only; board identity
     and authorization for any destructive evidence.
  Never imply that source review proves a one-way silicon operation or power-cut safety.
```

**Running it as a swarm.** Split reviewers by (1) first-boot/provisioning,
(2) update/migration/rollback, and (3) wipe/recovery/RMA, then have a fourth
reviewer attack the merged state/store matrix for missing owners and cut points.
These are supplemental lanes: apply the exact dual-partner, mutually withheld
first-pass, and symmetric cross-adjudication procedure in
[`docs/planning-and-review-workflow.md`](../../planning-and-review-workflow.md);
swarm quorum never replaces either required partner or resolves its blocker.

---

## Part D — Cadence + honest boundary

- **Per-PR touching a persistent write, erase, lifecycle predicate, recovery
  path, or storage constant:** update the ownership/state matrix and run a
  scoped cut-point pass.
- **Before implementing item 36:** freeze the transition DAG and receipt format;
  independently review every irreversible edge before code authority is granted.
- **Per-release:** replay supported old durable images through the new firmware
  and test wipe/restore/update interactions, not just fresh provisioning.
- **Before RMA/refurbishment is offered:** approve a separate access and
  sanitization policy, then validate it on sacrificial returns.
- **The one-line gut check:** *after power disappears on either side of any
  durable write, can the device truthfully determine what happened and either
  resume without repeating a one-way step or reach an explicit safe terminal
  state?*

**The boundary, stated on purpose.** This playbook can expose contradictory
state predicates, unsafe ordering, missing ownership, and modelled cut-point
failures. It cannot prove flash/option-byte/SE interruption semantics, endurance,
or data remanence without authorized silicon work; it also grants no authority
to perform an irreversible lifecycle transition.
