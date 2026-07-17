# PQ1 ERC-7730 architecture — symmetric cross-adjudication packet

You are performing the architecture-stage symmetric cross-adjudication required by `docs/planning-and-review-workflow.md` for the frozen PQ1 ERC-7730 forced-blind candidate. Both independent first-pass reports are now frozen. This is not a new first pass, an implementation authorization, an owner decision, or a production recommendation.

## Immutable reviewed target

- Target: `/tmp/pq1-erc7730-arch-review-9647b79`
- HEAD: `9647b79374d5e2e10445254492308101b8be708b`
- Expected tracked modifications only:
  - `docs/erc7730-implementation-review-2026-07.md`
  - `docs/work-todo.md`
- Expected untracked files: none
- Expected ignored files: none
- Frozen binary diff SHA-256: `b8e270747a5c16eafde0b74fe94f34be9ab4504d91559234fb2a1ca056d59c25`
- Target is recursively non-writable. Do not edit its source, index, permissions, hardware, or external state. Non-destructive reads and checks are allowed. If you need an executable counterexample, use a distinct scratch copy and disclose it.

## Frozen first-pass inputs

Read both reports completely before answering. Do not modify them.

- Partner A V5 replacement (the accepted A leg; V4 is audit-only and must not be paired):
  - `/tmp/pq1-erc7730-partner-a-first-pass-v5.md`
  - SHA-256 `4b34ae5f1459d2d6dbfe21a1a9019235b74344cb0440aac76551efe6823a884c`
- Partner B V4 (the accepted B leg):
  - `/tmp/pq1-erc7730-partner-b-first-pass-v4.md`
  - SHA-256 `bcb8a52e7dba0ecf49e651467615a9c47da2a2a0756563d4362252dde5f1110f`

Runtime receipts:

- A post-launch V5: `/tmp/pq1-erc7730-partner-a-postlaunch-v5.txt`, SHA-256 `b070c7331366781a1d5d30729613f2ece08f5cfeb1388ce62f68de551a6440c2`
- B post-launch V4: `/tmp/pq1-erc7730-partner-b-postlaunch-v4.txt`, SHA-256 `dbcdf3ed459d41ae07a9933445ed3b8fc88d8a89deb3c421cddcd12c637cf4d3`

Process fact for PB-PROC-013: Partner B correctly disclosed that its own attempted supplemental Claude call failed before inference. That does not invalidate its frozen technical evidence. For the workflow pairing, however, the separately receipted Partner A leg ran Claude Opus 4.8/1M/ultracode/xhigh, personally adjudicated three completed bounded Opus lanes, and Partner B ran literal `gpt-5.6-sol`/ultra with three completed Codex lanes. The coordinator accepted those as the two required independent backend legs. Adjudicate whether PB-PROC-013 is therefore cured for this pair, narrowed to its original report's self-attestation boundary, or remains unresolved; do not silently omit it.

## Required method

1. Recompute both first-pass hashes and the frozen target identity before substantive work.
2. Read the other partner's complete report and re-open the cited plan/source/evidence needed to test it. Do not defer to reviewer reputation or apparent consensus.
3. For every stable ID below, give exactly one disposition from `CONFIRMED`, `REFUTED`, `NARROWED`, or `UNRESOLVED`, with concise evidence, the required correction or precise residual, and architecture/implementation/production stage impact. This includes your own first-pass IDs: state whether cross-evidence changes your original position.
4. Reproduce, refute, or narrow every blocker and major finding. Explicitly identify where the other reviewer inherited the plan's framing or accepted an unsupported claim.
5. Preserve disagreement. Do not vote, average severities, accept a correctness contradiction as a product preference, or treat an owner trade-off as already decided.
6. Reconcile the competing gas-page proposals, including whether one handler owner suffices and what independent FI proof is still needed. Reconcile Bloom `filter-positive` versus exact membership, bad/root-misbound proof policy, paymaster representation, two-stage receipt independence, resource construction, and fatal routing.
7. Give a minimum revised architecture as a closed state machine/outcome taxonomy, an exact forced transcript schema, authorization receipt sequence, resource ownership model, exhaustive fatal exclusions, and falsifiable acceptance evidence. Separate architecture requirements from target/physical evidence that may legitimately remain an implementation or production gate.
8. State the exact owner decisions and owner-document amendments required. Forced blind is not clear signing; current default/rollback remains refusal unless an authorized owner later amends the conflicting contracts.
9. New cross finding: use stable IDs prefixed `XA-` for Partner A or `XB-` for Partner B. Raise one only for a concrete scope-intersecting defect, with evidence and stage impact. It will receive one bounded counterpart response after both cross reports freeze. Do not recursively expand scope.
10. Repeat the target identity/drift checks at the end and give revised stage-specific verdicts for architecture, implementation, merge, and production. A favorable architecture verdict must be conditional on explicit redlines where the frozen text itself is defective; it grants no implementation authority for a materially revised, as-yet-unreviewed artifact.

## Complete ID inventory

Partner A: `PA5-1`, `PA5-2`, `PA5-3`, `PA5-4`, `PA5-5`, `PA5-6`, `PA5-7`, `PA5-8`, `PA5-9`, `PA5-10`, `PA5-11`.

Partner B: `PB-AR-001`, `PB-AR-002`, `PB-AR-003`, `PB-AR-004`, `PB-AR-005`, `PB-AR-006`, `PB-AR-007`, `PB-AR-008`, `PB-AS-009`, `PB-BR-010`, `PB-DOC-011`, `PB-UX-012`, `PB-PROC-013`.

No ID may disappear merely because it duplicates another. Cross-reference duplicates but retain a separate row and explicit disposition.

## Required report shape

- Runtime and frozen-input receipt
- Initial target identity
- Complete disposition table: stable ID; origin claim/severity/stage; your disposition; reproduced/refuted evidence; correction/residual; stage impact; owner decision if any
- Agreements and explicit disagreements
- Inherited framing / unsupported assumptions in the counterpart report
- Minimum revised architecture and acceptance evidence
- New `XA-*` or `XB-*` findings, or explicit `none`
- Revised stage-specific verdicts and honest residual
- Final target identity/drift result

Use the workflow's cross-adjudication semantics, not free-form `agree/disagree`. Source-only reasoning must remain labeled source-only. Do not claim hardware, optimized-ELF, stack, FI, usability, provenance, merge, shipment, or irreversible-action evidence that was not executed.
