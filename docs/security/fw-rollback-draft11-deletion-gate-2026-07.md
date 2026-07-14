# Rollback Draft 1.1 bounded deletion gate

**Date:** 2026-07-14

**Scope:** host-only architecture research; no production or hardware authority

**Draft input:** commit `93da75679a06b0bd289d49bdb511a7d3cd1acac7`

**Draft SHA-256:** `743bc156417ff84b5ac201996b07c97db1e53526e2f9a2f59e44a6681ce3d7ad`

Draft 1.1 remained byte-identical during this experiment. The executable model
is deliberately disposable and shares no implementation with the FSBL or
secure runtime.

## Results

1. **`RecoverySameEpoch`: availability benefit, not a demonstrated safety
   requirement.** In the bounded abstraction, `Aborted -> service/RMA`
   preserves the floor and the model's assumed exact-floor source. The
   field-recovery variant can restore a newer same-epoch candidate while
   preserving the same floor, performing zero Route-1/OTP writes, requiring
   the modeled in-trace stage/arm/attempt sequence, and allowing at most one
   candidate handoff. Whether that availability justifies the extra policy and
   state remains an owner/product decision.
2. **`FloorBoundAccepted`: availability benefit, not a demonstrated safety
   requirement.** Without it, loss of one or both terminal replicas can safely
   require service. With it, degraded acceptance is possible only from an
   exact, consumed proof bound to the artifact, authoritative committed group,
   snapshot, and current boot; the reconstructed robust candidate then follows
   the ordinary `(E, R, slot-A)` order. Supporting this terminal-loss recovery
   remains an owner/product decision.
3. **The tested two-ladder deletion candidate fails.** With only a
   manifest-resident one-way ATTEMPTED word, an all-`0xFF` observation cannot
   distinguish a virgin first probation from a torn write that may have
   launched. Retry is necessary for the virgin case but forbidden for the torn
   cell; exclusion/reinstall is safe but prevents first probation. An
   independent retained attempt witness therefore remains provisionally
   justified. This does not close the TAMP hardware or durability gates.
4. **Exact byte formats: no verdict.** The model contains only a policy check
   that refuses a freeze without signed-tool interoperability, executed cut
   properties, physical-backend closure, and combined FLASH/RAM/stack fit. It
   provides none of that evidence and therefore neither approves nor rejects
   Draft 1.1's proposed byte-level formats.

## Validation

- `draft11_deletion_experiments`: 7 passed, 0 failed.
- Enrolled rollback host suites: 65 passed, 0 failed.
- Historical `fw-manifest` Draft-0.9 model: 10 passed, 0 failed.
- Focused Clippy with `-D warnings`: passed.
- Two focused read-only re-reviews found no remaining model-validity must-fix.

## Limits and disposition

The model uses small abstract identities and opaque typed observations. It does
not parse manifests, verify signatures or images, emulate ECC, model retention,
program flash/TAMP/OTP, measure resources, or authorize hardware work. The
recovery graph is bounded and fails with `NO VERDICT` if its state cap is
exceeded; passing is not a proof of the complete Draft 1.1 architecture.

Draft 1.1 remains a preserved normative research candidate, not an
implementation-approved production contract. Do not start a Draft 1.2 prose
cycle from this receipt. Revisit the production specification once, after the
owner resolves the two availability choices and separately authorized backend,
resource, and silicon evidence exists; reopen architecture only for a concrete
unsafe trace, an unimplementable requirement, or a measured resource failure.
