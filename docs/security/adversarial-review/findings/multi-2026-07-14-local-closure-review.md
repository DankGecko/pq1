---
surface: multi
run_date: 2026-07-14
reviewer_role: supplemental
reviewer_identity: "/root; /root/known_baseline; /root/entrypoint_coverage; /root/state_config_probe; /root/catalog_planner"
effort: "local read-only source validation"
backend: "local repository-review tasks; no external reviewer report accepted"
scope: "Novel and materially new closure paths found by a full-project, all-playbook source sweep; known findings and process-only leads deduplicated"
stage: implementation
frozen_identity: "sha256:694e703ab4edf9a3149ee28fb5870745d88bfee5f136a62e919fda2c93bf831e"
status: open
---

# Adversarial-review findings — multi-surface local closure review — 2026-07-14

## Summary

This supplemental pass promotes four closure records: one novel vector and
three materially new paths through known finding classes. The records are
written for remediation: they state the affected boundary, prerequisite class,
consequence, exact source anchors, confidence, safe validation receipt, and
falsifiable closure criteria. They intentionally omit payloads, operational
sequences, and procedural misuse instructions.

The review was performed by the local task names recorded in frontmatter.
An attempted Claude Code Opus 4.8 report ended incomplete at timeout. An
attempted GPT-5.6 SOL report ended after repeated visibility filtering. Neither
attempt produced an accepted report, neither is counted as a completed
independent pass, and this supplemental record does not satisfy the required
dual-partner workflow.

## Reviewer and frozen-target receipt

- **Local reviewer tasks:** `/root`, `/root/known_baseline`,
  `/root/entrypoint_coverage`, `/root/state_config_probe`, and
  `/root/catalog_planner`.
- **Reviewed repository:** branch
  `fix/sweep-2026-07-14-findings`, HEAD
  `ddc7cefc35cb54e324dac94330c6ee86f9383c90`.
- **Tracked-diff digest:**
  `9e7b43a7e4023a32a48e1588270c5cc41948dd0e72b04b9ef765a3052729dfa9`.
- **Staged-diff digest:**
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- **Frozen aggregate identity:**
  `694e703ab4edf9a3149ee28fb5870745d88bfee5f136a62e919fda2c93bf831e`.
- **Closure-validation receipt:** local read-only source validation,
  460 lines, SHA-256
  `16ec68575b53c7f41dfb600a3a6129963d299709522788f9b7771375c3574585`.
- **Mutation boundary:** the reviewed target remained read-only during
  validation. This report and its catalogue row are a later documentation-only
  mutation.
- **External-review status:** no Opus or GPT first-pass report was accepted;
  no external model verdict or completed identity is asserted.

## Evidence and authority boundary

| Evidence | Result | Authority |
|---|---|---|
| Current source and configuration trace | Completed for the promoted records and deduplication candidates | E0 source evidence |
| Known findings, audits, STATUS, and TODO baseline | Cross-read before promotion | Deduplication evidence only |
| Protocol host suite | 109 tests passed | E1 for current protocol constants; not evidence for the promoted runtime records |
| Configuration dry-run inspection | Confirmed a non-promoted projection discrepancy | E0 process/config evidence |
| Trailmark structural analysis | Unavailable in the environment | No graph-based completeness claim |
| Compiler-backed zeroization audit | Preflight blocked by the intentional FSBL safety gate | No optimized-artifact erasure claim |
| Target build, QEMU, hardware, factory, release, or destructive checks | Not performed | No E3–E7, silicon, merge, or shipment authority |

## Stage-specific recommendations

| Stage | Recommendation | Subject | Remaining gate |
|---|---|---|---|
| Architecture | unavailable | supplemental source review | Required independent pair was not completed |
| Implementation | NO-GO for claiming the affected records closed | frozen aggregate identity above | F1–F4 closure criteria and a new frozen review |
| Merge | unavailable | no fix candidate reviewed | Exact implementation and evidence do not exist in this report |
| Production shipment | NO-GO | current project state | Existing release blockers plus F1–F4 and required physical/release evidence |

## Promoted closure records

### F1 — OPTIGA final-state policy is accepted without full policy identity

- **Status:** 🔲 OPEN
- **Mode / severity:** SE6 · LC1 · LC4 · SL5 · HIGH
- **Boundary:** Provisioning and lockdown treat an already
  `Operational` object as acceptable before proving that its complete
  security policy and, where applicable, object identity match the intended
  final state.
- **Prerequisite class:** Pre-existing secure-element object state originating
  before trusted first-field provisioning, including manufacturing, transit,
  prior lifecycle, or interrupted-provisioning state.
- **Consequence:** Fresh PIN-derived or seed-share material can be committed
  under an unverified immutable policy. Trust-anchor lockdown can also report
  success without proving the intended anchor or neutralized state.
- **Exact source anchors:**
  - `secure/src/optiga/mod.rs::verify_and_lock`
    (`:833-892`; final-state return at `:867-875`; policy comparator at
    `:876`).
  - `secure/src/optiga/mod.rs::provision_auth_ref`
    (`:904-1028`).
  - `secure/src/optiga/mod.rs::provision_user_oid`
    (`:1038-1079`).
  - `secure/src/optiga/mod.rs` counter and optional-object provisioning
    (`:1088-1113`, `:1184-1269`, `:1760-1794`).
  - `secure/src/optiga/mod.rs::lockdown_ta_pool`
    (`:1837-1910`).
  - `secure/src/optiga/apdu.rs::is_metadata_operational` and
    `metadata_matches_expected` (`:1306-1343`).
  - Lifecycle reachability:
    `secure/src/optiga/mod.rs:1920-2093`,
    `secure/src/dual_se.rs:139-185`, and
    `secure/src/main.rs:3484-3514`.
- **Confidence:** High for control flow and first-boot reachability; silicon
  behavior and final policy bytes remain unverified.
- **Duplicate disposition:** Novel. Full-sweep F8 owns the trust-anchor OID
  manifest, while S-1/S-2/S-3 own specific policy and trust-root weaknesses.
  None owns generic acceptance of unverified final state across provisioning
  and lockdown.
- **Safe validation receipt:** E0 source predicate review recorded in
  closure-validation SHA-256
  `16ec68575b53c7f41dfb600a3a6129963d299709522788f9b7771375c3574585`.
  No device state was changed and no operational reproducer was created.
- **Closure criteria:**
  1. Validate every affected object before writing secret or user payload.
  2. Require exact equality of every security-relevant expected metadata tag
     before accepting an already-final object.
  3. Verify trust-anchor/certificate identity or the exact intended neutralized
     state before accepting a skip.
  4. Fail closed on metadata, content, and lockdown write/read-back failures.
  5. Add safe host predicates for incomplete or permissive final metadata for
     every affected object class.
  6. Obtain sacrificial-silicon read-back receipts before final closure.

### F2 — Firmware STATUS and ABORT omit the guard that excludes idle cleanup

- **Status:** 🔲 OPEN
- **Mode / severity:** RT2 · FW5 · TZ8 · MED
- **Boundary:** Two firmware-update veneers access or replace the shared
  `FW_UPDATE` slot without entering the guard used to exclude SysTick-driven
  sensitive-state cleanup.
- **Prerequisite class:** An unlocked firmware-update session reaching an idle
  cleanup boundary while STATUS or ABORT is active.
- **Consequence:** The secure world can observe invalid shared-state lifetime,
  overlapping mutation/drop, availability loss, or update-state corruption.
  Source evidence does not establish secret disclosure.
- **Exact source anchors:**
  - `secure/src/nsc/cmd_fw_status.rs:20-76`.
  - `secure/src/nsc/cmd_fw_abort.rs:23-41`.
  - `secure/src/main.rs:3772-3785`.
  - `secure/src/nsc/state.rs:153-199`.
  - `secure/src/nsc/mod.rs::HandlerGuard` (`:777-829`).
- **Confidence:** High at source level; no exception-schedule or target-silicon
  execution was performed.
- **Duplicate disposition:** Materially new sibling path. The May C-2 record
  closed this class for CHUNK, not STATUS or ABORT. Earlier firmware and
  gateway reviews treated these paths as discharged.
- **Safe validation receipt:** E0 shared-state and guard-coverage trace in
  closure-validation SHA-256
  `16ec68575b53c7f41dfb600a3a6129963d299709522788f9b7771375c3574585`.
- **Closure criteria:**
  1. Establish the handler guard before either veneer touches PIN or update
     state.
  2. Enforce a source-level invariant that every veneer touching
     `FW_UPDATE` is guarded.
  3. Add a deterministic schedule model covering each access and drop boundary
     at idle transition.

### F3 — Firmware COMMIT reaches reset without complete sensitive-state cleanup

- **Status:** 🔲 OPEN
- **Mode / severity:** RT7 · RT9 · FW5 · LC7 · LOW current / MED latent
- **Boundary:** The successful firmware COMMIT path clears only update context
  before a delayed or direct software reset, while boot cleanup assumes
  software-reset callers already performed full cleanup.
- **Prerequisite class:** A successful firmware-update commit in a build where
  the replacement update backend is enabled. Current production output remains
  separately quarantined.
- **Consequence:** Unlocked master/session state can remain live until reset and
  during the pre-reset interval. This record makes no claim about physical
  recovery without artifact and silicon evidence.
- **Exact source anchors:**
  - `secure/src/nsc/cmd_fw_commit.rs:275-309`.
  - `secure/src/hw/usb_hw.rs:314-345`.
  - `secure/src/main.rs:963-976`.
  - Cleanup exemplars:
    `secure/src/hw/hash.rs:186-203`,
    `secure/src/main.rs:3940-3973`, and
    `secure/src/hw/tzic.rs:220-267`.
- **Confidence:** High for source ordering; memory residue and recovery impact
  remain conditional.
- **Duplicate disposition:** Materially new supporting path through
  full-sweep F9 and F12. It does not replace the independent SRAM-reset or
  secret-lifetime records.
- **Safe validation receipt:** E0 reset-callsite and cleanup-order trace in
  closure-validation SHA-256
  `16ec68575b53c7f41dfb600a3a6129963d299709522788f9b7771375c3574585`.
- **Closure criteria:**
  1. Apply complete sensitive runtime cleanup and the required barrier before
     both reset arms and before any pre-reset delay.
  2. Replace the global software-reset assumption with an API- or
     source-order-enforced cleanup contract.
  3. Bind the replacement firmware-update backend to the same reset contract.
  4. Validate the exact linked target artifact before elevating the evidence
     beyond source level.

### F4 — SCP03 keyed state and plaintext intermediates lack guaranteed wiping

- **Status:** 🔲 OPEN
- **Mode / severity:** EK10 · FI8 · RT7 · MED
- **Boundary:** The secure-element transport creates keyed AES/CMAC state and
  plaintext command/response intermediates in ordinary storage without
  zeroizing-on-drop guarantees across success and error exits.
- **Prerequisite class:** Secret-bearing SE050 transport operations followed by
  a memory-residue observation capability. No physical recovery is asserted by
  this source-only record.
- **Consequence:** Expanded keyed state, PIN material, provisioned object data,
  or decrypted response bytes can outlive the operation that required them.
- **Exact source anchors:**
  - `secure/Cargo.toml:54-55`.
  - `secure/src/scp03_logic.rs:68-126`.
  - `secure/src/se050/scp03.rs::wrap_apdu` (`:390-418`).
  - `secure/src/se050/scp03.rs::unwrap_response` (`:674-741`).
  - `secure/src/se050/apdu.rs::ApduBuf` (`:144-166`).
  - Secret-bearing APDU paths:
    `secure/src/se050/apdu.rs:313-348`,
    `:643-667`, `:729-753`, and `:791-832`.
  - Final caller cleanup:
    `secure/src/se050/mod.rs:2461-2537`.
- **Confidence:** High for source and dependency-feature state. Optimized
  residue and physical recovery impact require exact-artifact evidence.
- **Duplicate disposition:** Materially reopens the scope of full-sweep F12.
  F12 correctly covered static ENC/MAC/DEK state and the PUT KEY buffer, but
  not expanded cipher schedules or these plaintext intermediates.
- **Safe validation receipt:** E0 dependency-feature and buffer-lifetime trace
  in closure-validation SHA-256
  `16ec68575b53c7f41dfb600a3a6129963d299709522788f9b7771375c3574585`.
  The compiler-backed zeroization workflow did not pass preflight, so no
  optimized-erasure result is claimed.
- **Closure criteria:**
  1. Give `ApduBuf` zeroizing-on-drop semantics.
  2. Use zeroizing storage for all secret-bearing command, response, PIN,
     provisioned-object, and decrypted intermediates on every exit.
  3. Enable the AES and CMAC zeroization features.
  4. Add structural gates for the affected buffer classes.
  5. Run compiler-backed zeroization analysis on the exact shipping target,
     profile, LTO settings, and final artifact.

## Complete playbook coverage matrix

Every Part-A ID in the active index is named below. “No promoted record” means
the local E0 review found no novel or materially new path after comparison with
the known baseline; it is not a claim that the mode is sound.

| Surface | Every catalog ID | Disposition in this pass |
|---|---|---|
| Clear signing | CS1, CS2, CS3, CS4, CS5, CS6, CS7, CS8, CS9, CS10 | No promoted record; known clear-signing findings and accepted residuals remain with their owners |
| TrustZone gateway | TZ1, TZ2, TZ3, TZ4, TZ5, TZ6, TZ7, TZ8, TZ9 | TZ8 composes into F2; TZ1–TZ7 and TZ9 produced no promoted record after baseline deduplication |
| Secure element | SE1, SE2, SE3, SE4, SE5, SE6, SE7, SE8, SE9 | SE6 composes into F1; SE1–SE5 and SE7–SE9 produced no additional promoted record |
| SCA/FI | FI1, FI2, FI3, FI4, FI5, FI6, FI7, FI8, FI9, FI10 | FI8 composes into F4; all other IDs produced no promoted record; no physical FI/SCA work was performed |
| Firmware update and secure boot | FW1, FW2, FW3, FW4, FW5, FW6, FW7, FW8, FW9, FW10 | FW5 composes into F2 and F3; the other IDs were baseline duplicates or produced no promoted record |
| USB and hostile companion | UC1, UC2, UC3, UC4, UC5; Part-A2 hostile-companion map; prose-only UC6 lead | No promoted record; the UC6 catalogue omission and map maintenance are retained as process-only leads |
| Off-chain signing | OC1, OC2, OC3, OC4, OC5, OC6, OC7, OC8, OC9 | No promoted record after baseline deduplication |
| On-chain contracts | SOL1, SOL2, SOL3, SOL4, SOL5, SOL6, SOL7, SOL8 | No promoted record; existing open harness/authorization/deployment boundaries remain baseline |
| Trusted UI | UI1, UI2, UI3, UI4, UI5, UI6, UI7, UI8 | No promoted record after baseline deduplication |
| Silicon lockdown | SL1, SL2, SL3, SL4, SL5, SL6, SL7 | SL5 composes into F1; remaining IDs are known blockers, accepted/deferred layers, or produced no promoted record |
| Lifecycle and persistent state | LC1, LC2, LC3, LC4, LC5, LC6, LC7, LC8, LC9, LC10 | LC1 and LC4 compose into F1; LC7 composes into F3; remaining IDs were baseline duplicates or produced no promoted record |
| Entropy and key lifecycle | EK1, EK2, EK3, EK4, EK5, EK6, EK7, EK8, EK9, EK10, EK11 | EK10 composes into F4; EK6/EK11 remain known item-36 blockers; all other IDs produced no promoted record |
| Secure runtime and resources | RT1, RT2, RT3, RT4, RT5, RT6, RT7, RT8, RT9, RT10, RT11 | RT2 composes into F2; RT7/RT9 compose into F3 and F4; remaining IDs were baseline duplicates or produced no promoted record |
| Production configuration and prodtest | PC1, PC2, PC3, PC4, PC5, PC6, PC7, PC8, PC9, PC10, PC11, PC12 | PC1 remains a known release blocker; PC4/PC9/PC11 have non-promoted corroboration below; all other IDs produced no promoted record |
| Build, release, provenance, and custody | BR1, BR2, BR3, BR4, BR5, BR6, BR7, BR8, BR9, BR10, BR11, BR12 | BR4 has non-promoted corroboration below; all other IDs remain baseline/process/release owners or produced no promoted record |
| Formal-verification assurance | V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11; G1, G2, G3, G4, G5 | No promoted record; no FV checker was freshly executed, so this is source/provenance coverage only |

## Non-promoted duplicate and process-only appendix

These items remain auditable but are not counted as new attack vectors:

1. **Secure/non-secure feature projection and reproducibility profile.**
   Concrete configuration evidence corroborates BR4 and PC4, including a
   generic paired-feature projection omission and a default-profile
   reproducibility result. The canonical factory target supplies its paired
   feature explicitly, so this is assurance/configuration evidence rather than
   a distinct current vector.
2. **CMD/INS and wire-regression inventory completeness.** Live feature-gated
   values are absent from some claimed-complete uniqueness and range lists.
   Current values were compared and no collision was found; the protocol host
   suite passed 109 tests. This remains PC9/PC11 test-coverage work.
3. **RDP0-to-RDP2 first-field transition.** Source and owner documents confirm
   that the adopted transition remains unimplemented. This is already owned by
   full-sweep F17, LC1/LC2, PC1, EK6/EK11, and work-todo item 36.
4. **Review-process drift.** Several older playbook prompts still instruct a
   reviewer to mutate the findings catalogue while the current workflow
   requires immutable external first passes. The TrustZone prompt names
   TZ1–TZ8 despite a TZ9 row; the USB prose names UC6 without a catalogue row;
   on-chain and FV scope prose contains stale coverage statements. These are
   process/coverage maintenance items, not promoted runtime vectors.
5. **Existing July full sweep.** Its ten fixed and eight deferred records remain
   unchanged. This report adds closure paths without rewriting that frozen
   evidence.

## Honest residual

1. This was a local supplemental E0/E1-limited review, not the workflow's
   required independent Opus/GPT pair. Both external attempts ended without an
   accepted report.
2. No hardware, external service, network, provisioning, option-byte,
   secure-element lifecycle, factory, signing, deployment, or destructive
   operation was performed.
3. Trailmark was unavailable. The compiler-backed zeroization audit stopped at
   its preflight gate. No graph completeness or optimized-erasure claim follows.
4. No production-shaped linked artifact, final stack/RAM receipt, target
   disassembly, QEMU integration, silicon schedule, physical FI/SCA,
   sacrificial-part policy read-back, reproducible release, custody, or
   distribution evidence was obtained.
5. “No promoted record” in the coverage matrix means only that no novel,
   safely supported path survived deduplication at the recorded evidence level.
   It does not close the playbook ID or replace its existing owner.
6. A later fix must be reviewed against a new exact identity. This report
   authorizes no source change, merge, shipment, or irreversible action.
