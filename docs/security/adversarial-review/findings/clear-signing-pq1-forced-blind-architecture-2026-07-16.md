---
report_kind: canonical-post-cross-adjudication
surface: multi
run_date: 2026-07-16
target_identity: "HEAD 9647b79374d5e2e10445254492308101b8be708b; binary diff b8e270747a5c16eafde0b74fe94f34be9ab4504d91559234fb2a1ca056d59c25"
cross_adjudication_sha256: 214763b83d44fbd2d6c278edbfef625076a3a99a0d3aa326b28de012e09c6415
scope: "PQ1 optional forced-blind ERC-7730 UserOp architecture, routing, trusted UI/FI receipts, resources, lifecycle, provenance, and production configuration"
status: in-review
---

# Canonical adversarial-review findings — PQ1 forced-blind architecture — 2026-07-16

> This is the post-cross-adjudication repository record. The reviewed candidate
> is **NO-GO**. This record grants no implementation, merge, shipment, release,
> risk-acceptance, publication, hardware, or irreversible-action authority.

## Evidence inputs

- [Partner A first pass](./clear-signing-pq1-forced-blind-architecture-2026-07-16-partner-a-first.md) —
  SHA-256 `4b34ae5f1459d2d6dbfe21a1a9019235b74344cb0440aac76551efe6823a884c`.
- [Partner B first pass](./clear-signing-pq1-forced-blind-architecture-2026-07-16-partner-b-first.md) —
  SHA-256 `bcb8a52e7dba0ecf49e651467615a9c47da2a2a0756563d4362252dde5f1110f`.
- [Partner A cross pass](./clear-signing-pq1-forced-blind-architecture-2026-07-16-partner-a-cross.md) —
  SHA-256 `d11bf34e8b6ece6eac442ef26674ea7604c816bbc8dd50804539327f32186e70`.
- [Partner B cross pass](./clear-signing-pq1-forced-blind-architecture-2026-07-16-partner-b-cross.md) —
  SHA-256 `8f2310602fbd36f09994ed1de794c332f0bf1ea85dbd98f6dc1a0f00c6a2e193`.
- [Partner A bounded response](./clear-signing-pq1-forced-blind-architecture-2026-07-16-partner-a-bounded.md) —
  SHA-256 `d6617979ec0c877e7501c8921beb37041c03db5aef3f53732f96ab32f3311aa7`.
- [Partner B bounded response](./clear-signing-pq1-forced-blind-architecture-2026-07-16-partner-b-bounded.md) —
  SHA-256 `ff7eb9eab04c8090329349023da7f786e99b9dc172a171a7db3b9d90d9e746e1`.
- [Complete cross matrix](./clear-signing-pq1-forced-blind-architecture-2026-07-16-cross-matrix.md) —
  SHA-256 `214763b83d44fbd2d6c278edbfef625076a3a99a0d3aa326b28de012e09c6415`.
- [Prompts and runtime receipts](./evidence/clear-signing-pq1-forced-blind-architecture-2026-07-16/) —
  byte-identical copies of the frozen request/runtime evidence.

## Summary

Both partners independently returned **NO-GO** on the frozen architecture.
The 27 raw matrix rows contain 13 `CONFIRMED`, 10 `NARROWED`, 3
`UNRESOLVED`, and 1 `REFUTED` dispositions. The 20 canonical groups below
contain 11 confirmed, 7 narrowed, and 2 unresolved items; the refuted
“two-attester policy is unsourced” challenge is preserved under F17.

The option remains viable only as a materially revised candidate: refusal is
default and rollback; only clean structural descriptor absence on a
filter-positive, steady-state, direct single Type-2 UserOp may qualify; every
bad/root-misbound/render/resource/paymaster/lifecycle/batch/off-chain/Safe/CoW/
fault case remains fatal; and the route uses a fixed raw transcript plus two
request-bound physical receipts. That candidate has not inherited approval and
requires fresh mutually withheld review.

## Findings

### F1 — Metadata causes collapse before eligibility

- **Origin IDs:** `PA5-1`, `PB-AR-001`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** CONFIRMED
- **Cross evidence:** Matrix rows `PA5-1` and `PB-AR-001`; both cross reports
  reproduce the handler's `Option::None` collapse.
- **Mode / severity / stage impact:** CS2/FI/hostile companion · CRITICAL ·
  architecture blocker and implementation/merge/production gate
- **Location / stable anchor:** `secure/src/nsc/cmd_sign_userop.rs:563` metadata
  parse/bind block
- **Claim and mechanism:** Clean absence, invalid bundle, and failed A/B
  binding checks lose their cause before dispatch. Eligibility inferred from
  that negative value could convert a detected fault into authority.
- **Prerequisites:** Host controls trailer bytes; forced tier exists; cause is
  not preserved.
- **Consequence:** A proof or FI/CFI failure could become signable.
- **Introduced here?:** NO — existing representation, exposed by the proposal.
- **Failure-path trace:** Trailer/bind result → `None` → proposed eligible
  branch → warning/transcript → signature.
- **PoC / refutation:** Source-exact four-cause collapse; no runtime exploit
  executed.
- **Evidence provenance:** Source-only frozen target; counterpart reproduced.
- **Classification:** FIX NOW
- **Required correction or residual:** Closed handler-owned evidence; fatal
  default; only affirmative FI-protected clean absence may mint eligibility.
- **Resolution:** Pending the fresh material-redline review and implementation.

### F2 — Render failures and owner doctrine cannot authorize downgrade

- **Origin IDs:** `PA5-2`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** CONFIRMED
- **Cross evidence:** Both cross reports confirm current `Reject`, `NoFormat`,
  and `PageBudget` handling is fatal; the proposed easy resource exploit was
  not reproduced.
- **Mode / severity / stage impact:** CS2/CS8 · HIGH · architecture blocker
- **Location / stable anchor:** `secure/src/tx/display/dispatch.rs:211`
  verified-descriptor render branch
- **Claim and mechanism:** “Cannot completely render” was too broad and
  contradicted current integrity/resource doctrine.
- **Prerequisites:** Verified descriptor reaches a render failure.
- **Consequence:** Integrity/resource failure could be reclassified as user
  choice.
- **Introduced here?:** YES — in the frozen plan wording.
- **Failure-path trace:** Verified/bound descriptor → `RenderErr` → proposed
  forced review instead of fatal refusal.
- **PoC / refutation:** Normative/source contradiction reproduced; no resource
  exploit established.
- **Evidence provenance:** Source/document only.
- **Classification:** SIMPLIFY
- **Required correction or residual:** All existing `RenderErr` values remain
  fatal in PQ1. A future typed unsupported-capability class is separate and
  material.
- **Resolution:** Pending material-redline review.

### F3 — Forced eligibility must be a terminal handler route

- **Origin IDs:** `PA5-3`, `PB-AR-001`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** NARROWED
- **Cross evidence:** A confirms structural refusal sites; B narrows the claim
  because a terminal typed outcome can preserve them.
- **Mode / severity / stage impact:** CS1/CS2 · HIGH · frozen architecture
  blocker
- **Location / stable anchor:** `secure/src/tx/display/dispatch.rs:382`
  lower generic ladder
- **Claim and mechanism:** Transporting a permissive flag above the dispatcher
  can reach ERC-20, typed-call, selector-name, or generic blind fallbacks.
- **Prerequisites:** Forced result re-enters ordinary dispatch.
- **Consequence:** Failed clear signing silently receives a weaker renderer.
- **Introduced here?:** YES — proposal control-flow shape.
- **Failure-path trace:** Known/filter-positive failure → permissive data value
  → generic ladder → sign.
- **PoC / refutation:** Existing fallthrough graph reproduced; safe terminal
  alternative remains viable.
- **Evidence provenance:** Source-only.
- **Classification:** FIX NOW
- **Required correction or residual:** Immediately consume a private non-`Copy`
  eligible reason in the direct single-handler forced flow; never expose it to
  generic dispatch.
- **Resolution:** Pending material-redline review.

### F4 — Prompt-abuse control is unresolved

- **Origin IDs:** `PA5-4`, `PA5-10`, `PB-UX-012`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** UNRESOLVED
- **Cross evidence:** Both confirm uncharged warnings and physical-button timer
  refresh. A treats the exact device control as an owner trade-off; B requires
  one at architecture stage.
- **Mode / severity / stage impact:** trusted UI/lifecycle · MEDIUM · blocks
  favorable architecture convergence while policy is open
- **Location / stable anchor:** `secure/src/crypto.rs:84`;
  `secure/src/ui/confirm.rs:81-118`
- **Claim and mechanism:** Cancelled warning prompts consume no sign budget,
  can occur before deterministic refusal, and real warning-button activity
  refreshes the unlocked window.
- **Prerequisites:** Host repeatedly submits eligible-looking requests; user
  interacts.
- **Consequence:** Habituation, extended exposure window, or fail-closed DoS
  from a countermeasure.
- **Introduced here?:** YES — the extra severe ceremony.
- **Failure-path trace:** Request → warning → cancel/failure → no sign charge →
  repeat; button event resets activity.
- **PoC / refutation:** Source path reproduced; no usability/hardware study.
- **Evidence provenance:** Source-only.
- **Classification:** OPEN RESEARCH
- **Required correction or residual:** Complete every deterministic preflight
  before warning. Owner must select budget/cooldown/lock/deadline semantics and
  record the host-DoS/habituation consequence.
- **Resolution:** Pending explicit owner decision and fresh review.

### F5 — EntryPoint is signed but unpinned

- **Origin IDs:** `PA5-5`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** CONFIRMED
- **Cross evidence:** Both partners trace `snap[32..52]` into the digest and
  find no production pin/display.
- **Mode / severity / stage impact:** WYSIWYS/FI · MEDIUM ·
  implementation/merge/production gate
- **Location / stable anchor:** `secure/src/nsc/cmd_sign_userop.rs:237`;
  `aa/src/userop.rs:702`
- **Claim and mechanism:** A hostile wire EntryPoint changes the signed domain
  without a trusted-display fact.
- **Prerequisites:** Companion supplies noncanonical EntryPoint.
- **Consequence:** At minimum unusable signatures; future/custom routing could
  create domain confusion.
- **Introduced here?:** NO — current hardening gap.
- **Failure-path trace:** Wire field → digest params → signature; no equality
  gate.
- **PoC / refutation:** Source trace only.
- **Evidence provenance:** Independently reproduced by both reviewers.
- **Classification:** FIX NOW
- **Required correction or residual:** FI-harden equality to exact v0.6, then
  feed the firmware constant into all single/batch T1/T2 digests.
- **Resolution:** Queued as independent PQ1 fail-closed hardening.

### F6 — Auto-confirm E2E cannot prove physical consent

- **Origin IDs:** `PA5-6`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** NARROWED
- **Cross evidence:** Auto-confirm reproduced; production feature fences
  narrow it from bypass to evidence gap.
- **Mode / severity / stage impact:** trusted UI/prodtest · MEDIUM ·
  implementation/merge assurance gate
- **Location / stable anchor:** `secure/src/ui/confirm.rs:59`
- **Claim and mechanism:** The main E2E configuration returns confirmation
  without physical input.
- **Prerequisites:** Test evidence is used to claim two-user-consent behavior.
- **Consequence:** False assurance, not a shipping bypass by itself.
- **Introduced here?:** NO.
- **Failure-path trace:** E2E feature → immediate confirmed sentinel → test
  passes without exercising buttons/order.
- **PoC / refutation:** Source reproduction; production fence confirmed.
- **Evidence provenance:** Source-only.
- **Classification:** FIX NOW
- **Required correction or residual:** Scripted non-auto-confirm state-machine
  lane for warning/final cancel, idle, replay, and order.
- **Resolution:** Pending implementation evidence.

### F7 — Two stages need request-bound receipts

- **Origin IDs:** `PA5-9`, `PB-AR-003`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** NARROWED
- **Cross evidence:** Direct stale-`r0` exploit was not reproduced; both
  partners preserve the stage/order/binding gap.
- **Mode / severity / stage impact:** FI/trusted UI · HIGH/MEDIUM disagreement ·
  architecture redline
- **Location / stable anchor:** `secure/src/ui/confirm.rs`;
  `secure/src/fi.rs:296`
- **Claim and mechanism:** Two identical result shapes do not prove distinct
  warning and final authorization for the same request under FI.
- **Prerequisites:** Future tier reuses an undifferentiated sentinel/result.
- **Consequence:** Stage skip, reorder, or stale authorization may release a
  signature.
- **Introduced here?:** YES — proposed two-stage flow.
- **Failure-path trace:** warning confirm → transcript → final confirm → release
  without stage/request-bound receipts.
- **PoC / refutation:** Specific stale-register story refuted; specification
  gap remains source-only.
- **Evidence provenance:** Both cross reports.
- **Classification:** FIX NOW
- **Required correction or residual:** Separate fail-initialized slots,
  domain/stage tags, request digest, ordered CFI, single consumption, and
  optimized target evidence.
- **Resolution:** Pending material-redline review.

### F8 — Gas has two producers and no global uniqueness proof

- **Origin IDs:** `PA5-7`, `PB-AR-006`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** CONFIRMED
- **Cross evidence:** Both partners reproduce renderer plus handler emission
  and the local-only proof.
- **Mode / severity / stage impact:** WYSIWYS/FI/resources · MEDIUM ·
  implementation/merge/production gate
- **Location / stable anchor:** `pqsigner-erc7730/src/display/render/mod.rs:805`;
  `secure/src/tx/display/userop_gas_lane.rs:90`
- **Claim and mechanism:** Duplicate ownership can show two gas pages; current
  proof establishes insertion at one slot, not exactly one globally.
- **Prerequisites:** ERC-7730 render path plus handler splice.
- **Consequence:** Duplicated/conflicting trusted facts and page-budget loss.
- **Introduced here?:** NO — existing behavior.
- **Failure-path trace:** Renderer appends gas → handler appends gas → local
  proof → confirmation.
- **PoC / refutation:** Source reproduction.
- **Evidence provenance:** Both cross reports.
- **Classification:** SIMPLIFY
- **Required correction or residual:** Handler is sole producer; independent
  pre-scan zero, insertion, post-scan exactly one exact content, CFI-complete
  before every confirmation.
- **Resolution:** Queued as independent PQ1 hardening.

### F9 — Differential glue does not independently cover handler gas

- **Origin IDs:** `PB-AS-009`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** UNRESOLVED
- **Cross evidence:** B confirms omission at the corrected path; A found it
  plausible but did not finish reproduction.
- **Mode / severity / stage impact:** assurance · MEDIUM · implementation/merge
  gate
- **Location / stable anchor:**
  `secure/src/display_under_test/wysiwys_dispatch_differential_tests.rs:278`
- **Claim and mechanism:** `drive_glue` does not model the final handler gas
  transformation despite header wording.
- **Prerequisites:** Harness result is used as final page-set evidence.
- **Consequence:** Exactly-one regressions can escape the advertised
  differential.
- **Introduced here?:** NO.
- **Failure-path trace:** Dispatcher model omits handler splice → comparison
  passes → real final set differs.
- **PoC / refutation:** One partner source-reproduced; the other did not
  complete inspection.
- **Evidence provenance:** Source-only, disagreement preserved.
- **Classification:** FIX NOW
- **Required correction or residual:** Extend the model and add executable
  exact sequence/count tests; obtain independent re-review.
- **Resolution:** Pending implementation evidence.

### F10 — Catalogue and semantic facts drift outside guards

- **Origin IDs:** `PA5-8`, `PB-DOC-011`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** CONFIRMED
- **Cross evidence:** Tuple/Bloom/omission gaps and the live `NftName` opcode
  mismatch were reproduced.
- **Mode / severity / stage impact:** provenance/docs · LOW/MEDIUM ·
  assurance/merge/production gate
- **Location / stable anchor:**
  `docs/companion/companion-erc7730-implementation-guide.md:1051`;
  `pqsigner-erc7730/src/ir.rs:224`
- **Claim and mechanism:** Root/count/size checks alone do not pin semantic
  opcode, renderer, tuple, Bloom, omission, or digest behavior.
- **Prerequisites:** Documentation or source changes independently.
- **Consequence:** Companions/reviewers follow stale security semantics.
- **Introduced here?:** NO.
- **Failure-path trace:** Source/generator changes → stale prose remains green.
- **PoC / refutation:** `NftName=0x09` prose versus source `0x04`.
- **Evidence provenance:** Source/document comparison.
- **Classification:** FIX NOW
- **Required correction or residual:** Generated/checkable catalogue and
  semantic receipts, including mandatory ERC-8213 pages.
- **Resolution:** Remediation exists in the current working tree; it remains
  uncommitted and outside the frozen target.

### F11 — Forced transcript was non-injective

- **Origin IDs:** `PB-AR-004`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** CONFIRMED
- **Cross evidence:** Both partners confirm raw-word differences can share a
  rounded friendly display; plan omitted fees and EntryPoint treatment.
- **Mode / severity / stage impact:** WYSIWYS · HIGH · architecture blocker
- **Location / stable anchor:** `tx-core/src/eip1559.rs:134`;
  `secure/src/tx/display/blind_sign.rs`
- **Claim and mechanism:** Friendly decimal pages round distinct signed values;
  omitted fee/paymaster/domain fields are not visibly bound.
- **Prerequisites:** Proposed forced renderer reuses friendly display as the
  sole representation.
- **Consequence:** Different signed requests can produce identical trusted
  transcripts.
- **Introduced here?:** YES — frozen transcript requirements.
- **Failure-path trace:** Raw U256s → rounded text/omitted field → same pages →
  signature.
- **PoC / refutation:** Source-level `1 ETH + 1 wei` versus `+2 wei` collision
  at six fractional digits.
- **Evidence provenance:** Source-only, independently checked.
- **Classification:** FIX NOW
- **Required correction or residual:** Fixed raw schema for every signed word,
  full ERC-8213 and final signing digests; friendly pages cannot replace raw.
- **Resolution:** Pending material-redline review.

### F12 — Raw renderer is safe only if it is not a decoder

- **Origin IDs:** `PA5-11`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** NARROWED
- **Cross evidence:** Both partners reject the claim that any renderer is
  automatically a CS9 decoder, while requiring a strict typed boundary.
- **Mode / severity / stage impact:** CS9 · LOW/MEDIUM · architecture/test gate
- **Location / stable anchor:** proposed `ForcedTranscriptInput`
- **Claim and mechanism:** A second ABI/metadata walk could disagree with the
  signing path; a pure painter over one canonical struct does not.
- **Prerequisites:** Future renderer reparses bytes or receives semantic
  metadata.
- **Consequence:** Competing interpretation of signed inputs.
- **Introduced here?:** YES.
- **Failure-path trace:** Signed bytes → second parser → pages disagree with
  digest input.
- **PoC / refutation:** No implementation exists; definition narrowed.
- **Evidence provenance:** Architecture/source reasoning only.
- **Classification:** SIMPLIFY
- **Required correction or residual:** Type accepts canonical raw fields only;
  no descriptor/resolver/ABI/selector-name path; differential byte-flip tests.
- **Resolution:** Pending material-redline review.

### F13 — Bloom result is filter-positive, not membership

- **Origin IDs:** `PB-AR-002`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** CONFIRMED
- **Cross evidence:** Both partners reproduce all seven positions for a
  non-registry tuple whose bits are set.
- **Mode / severity / stage impact:** CS2/FI · MEDIUM · architecture
  terminology/proof blocker
- **Location / stable anchor:** `pqsigner-erc7730/src/known_calls.rs:47`;
  `secure/data/erc7730-known-calls.bloom`
- **Claim and mechanism:** A probabilistic filter cannot establish exact
  registry inclusion.
- **Prerequisites:** False-positive tuple.
- **Consequence:** Incorrect “known/exact” security claim; no additional
  authority if the result only selects stricter raw review.
- **Introduced here?:** YES — plan terminology.
- **Failure-path trace:** Tuple → all Bloom bits set → “known” label.
- **PoC / refutation:** Executed collision positions
  `[99335,23186,78109,1960,56883,111806,35657]`.
- **Evidence provenance:** Executed pure recomputation in both cross legs.
- **Classification:** FIX NOW
- **Required correction or residual:** Call it `filter-positive`; mint a
  positive FI receipt. Exact membership needs a separate authenticated set.
- **Resolution:** Pending owner policy and material-redline review.

### F14 — Short Safe-shaped calldata can fall through

- **Origin IDs:** `PB-AR-005`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** CONFIRMED
- **Cross evidence:** Both partners reproduce the selector-plus-minimum-length
  conjunct in single and batch paths.
- **Mode / severity / stage impact:** CS2/routing · HIGH · existing fail-closed
  defect and architecture/implementation/merge gate
- **Location / stable anchor:** `secure/src/nsc/cmd_sign_userop.rs:1105`;
  `secure/src/nsc/cmd_sign_userop_batch.rs:910`
- **Claim and mechanism:** Selector-shaped `execTransaction` shorter than the
  canonical ABI minimum is not caught by the reserved-shape refusal.
- **Prerequisites:** Host supplies short selector-shaped Safe call.
- **Consequence:** Reserved Safe shape reaches typed/generic blind fallback.
- **Introduced here?:** NO — existing route.
- **Failure-path trace:** Selector matches + length short → refusal conjunct
  false → ordinary ladder.
- **PoC / refutation:** Source-exact branch; no QEMU execution yet.
- **Evidence provenance:** Both cross reports.
- **Classification:** FIX NOW
- **Required correction or residual:** Selector-only claim classifier; any
  claimed-but-unverified Safe execution is fatal before other routing,
  including batch.
- **Resolution:** Queued as independent PQ1 fail-closed hardening.

### F15 — Stack/resource safety cannot rely on lexical lifetime

- **Origin IDs:** `PB-AR-007`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** NARROWED
- **Cross evidence:** `Pages` is exactly 1,988 bytes on ARM32; no overflow was
  proven; both move physical proof to implementation.
- **Mode / severity / stage impact:** secure runtime/resources · MEDIUM ·
  construction redline and implementation/production evidence gate
- **Location / stable anchor:** `pqsigner-erc7730/src/display/mod.rs:76`
- **Claim and mechanism:** Rust lexical `drop` does not guarantee optimized
  stack-slot reuse.
- **Prerequisites:** Two page-owning phases inline into one frame.
- **Consequence:** Stack/exception headroom exhaustion.
- **Introduced here?:** YES — proposed warning/transcript construction.
- **Failure-path trace:** warning `Pages` + transcript `Pages` lifetimes →
  optimized frame high-water.
- **PoC / refutation:** Size arithmetic verified; target stack overflow not
  executed.
- **Evidence provenance:** Source/ABI reasoning only.
- **Classification:** FIX NOW
- **Required correction or residual:** One cleared buffer or non-inlined
  page-owning phases; post-LTO map, MSPLIM, high-water, and exception evidence.
- **Resolution:** Pending implementation.

### F16 — Current owner contracts forbid the proposed tier

- **Origin IDs:** `PB-AR-008`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** CONFIRMED
- **Cross evidence:** Both partners confirm conflicts across `CLAUDE.md`, CS2,
  guide, integration, root policy, and ERC-8176 status.
- **Mode / severity / stage impact:** authority/policy · HIGH · blocks all
  stages
- **Location / stable anchor:** `CLAUDE.md:14`;
  `docs/security/adversarial-review/clear-signing-adversarial-review.md:20`
- **Claim and mechanism:** Existing owners say missing/bad/unrenderable
  filter-positive calls hard-refuse.
- **Prerequisites:** Implementer treats user idea or plan as silent amendment.
- **Consequence:** Unauthorized weakening of the trusted-display contract.
- **Introduced here?:** YES — proposed product direction.
- **Failure-path trace:** Candidate prose → behavior change without owner
  amendments.
- **PoC / refutation:** Document contradiction reproduced.
- **Evidence provenance:** Source-of-truth documents, both reviewers.
- **Classification:** FIX NOW
- **Required correction or residual:** Record owner authorization and amend all
  intersecting owners with “Forced blind is not clear signing”; default and
  rollback remain refusal.
- **Resolution:** User direction authorizes continued design exploration only;
  formal normative amendments remain gated on favorable fresh review.

### F17 — ERC-8176 readiness checker can false-green one attester

- **Origin IDs:** `PB-BR-010`, `X-A-2` (raw `XB-2`, refuted challenge)
- **Status:** 🔬 REVIEWED
- **Cross disposition:** CONFIRMED
- **Cross evidence:** A confirmed the mechanism; B's bounded response refuted
  the “threshold unsourced” challenge with exact policy anchors.
- **Mode / severity / stage impact:** build/release provenance · HIGH ·
  production blocker
- **Location / stable anchor:** `tools/erc8176_eas_coverage.py:102`;
  `secure/data/erc7730/policy.toml:15-17,35`
- **Claim and mechanism:** Nonempty trusted intersection counted as covered,
  while frozen policy requires two distinct trusted attesters per descriptor.
- **Prerequisites:** Advisory checker run with at least one trusted attester per
  descriptor.
- **Consequence:** False production-flip recommendation.
- **Introduced here?:** NO.
- **Failure-path trace:** `{A}` intersects trusted `{A,B}` → covered → every
  descriptor “covered” → “Safe to flip,” despite `1 < 2`.
- **PoC / refutation:** Pure counterexample and source comparison; no live EAS.
- **Evidence provenance:** Source-only; policy premise independently fixed by
  bounded response.
- **Classification:** FIX NOW
- **Required correction or residual:** Per-descriptor distinct threshold,
  authenticated offline policy/snapshot, real verifier; advisory CLI can never
  authorize production.
- **Resolution:** Threshold false-green remediation exists in the current
  working tree with five offline tests; production verifier/ecosystem remain
  open.

### F18 — Lifecycle modes were not excluded

- **Origin IDs:** `X-B-1` (raw `XB-001`)
- **Status:** 🔬 REVIEWED
- **Cross disposition:** NARROWED
- **Cross evidence:** B raised the missing deployment/rotation exclusion; A
  confirmed flags and dual-frame rotation, narrowing because existing rotation
  has its own consent and companion quarantine.
- **Mode / severity / stage impact:** lifecycle/routing · HIGH · sharpens
  architecture block and implementation tests
- **Location / stable anchor:** `secure/src/nsc/cmd_sign_userop.rs:271`;
  `proto/src/lib.rs:1260,1281`
- **Claim and mechanism:** “Single UserOp” did not mean exactly one steady-state
  Type-2 artifact; deployment folds initCode and rotation emits Type-1 plus
  Type-2.
- **Prerequisites:** Lifecycle flag plus otherwise eligible forced request.
- **Consequence:** Transcript omits lifecycle effects/artifacts.
- **Introduced here?:** YES — frozen scope omission.
- **Failure-path trace:** Lifecycle flag → separate/extra signed data →
  forced transcript designed for one steady-state call.
- **PoC / refutation:** Source contract/ceremony trace; no emitted-byte runtime
  trace.
- **Evidence provenance:** Source-only, bounded counterpart response.
- **Classification:** FIX NOW
- **Required correction or residual:** FI-re-read flags both false and exactly
  one steady-state Type-2 signature; all lifecycle modes fatal for PQ1.
- **Resolution:** Pending material-redline review.

### F19 — Partner B citation paths required a corrigendum

- **Origin IDs:** `X-A-1` (raw `XB-1`)
- **Status:** 🔬 REVIEWED
- **Cross disposition:** CONFIRMED
- **Cross evidence:** B's bounded response confirms eight unique nonexistent
  path literals / nine affected location blocks and supplies corrected paths.
- **Mode / severity / stage impact:** review provenance · MEDIUM · evidence
  traceability gate, not product vulnerability
- **Location / stable anchor:** Partner B first pass location blocks
- **Claim and mechanism:** Stale paths impaired independent reproduction.
- **Prerequisites:** Raw report consumed without corrigendum.
- **Consequence:** Inefficient or failed reproduction; underlying claims were
  largely real.
- **Introduced here?:** YES — report quality.
- **Failure-path trace:** Finding → nonexistent path → reviewer cannot locate
  mechanism.
- **PoC / refutation:** Filesystem existence and symbol-resolution audit.
- **Evidence provenance:** B bounded response, source-only.
- **Classification:** FIX NOW
- **Required correction or residual:** Canonical matrix uses the corrected map;
  raw report remains immutable. No fabrication finding.
- **Resolution:** Corrected in the canonical matrix/report; raw evidence
  preserved byte-identically.

### F20 — Reviewer identity needed coordinator receipts

- **Origin IDs:** `PB-PROC-013`
- **Status:** 🔬 REVIEWED
- **Cross disposition:** NARROWED
- **Cross evidence:** Both partners accept launcher/control-plane receipts as
  curing this exact pair while preserving self-attestation limits.
- **Mode / severity / stage impact:** process · gate · no remaining technical
  stage impact for this pair
- **Location / stable anchor:** archived pre/post runtime receipts
- **Claim and mechanism:** A reviewer cannot truthfully self-attest a model
  identity not exposed inside its report.
- **Prerequisites:** Pairing relies only on report self-description.
- **Consequence:** Unproven backend diversity.
- **Introduced here?:** YES — first-pass receipt boundary.
- **Failure-path trace:** Hidden runtime → report says not exposed → pairing
  lacks external receipt.
- **PoC / refutation:** Coordinator launcher/session receipts bind A and B.
- **Evidence provenance:** Control-plane/session evidence, not model
  self-report.
- **Classification:** DROP
- **Required correction or residual:** Preserve historical limitation; use
  coordinator receipts for this pair.
- **Resolution:** Cured for this exact review pair; no transfer to future runs.

## Explicit disagreements and unresolved defeaters

1. The exact prompt-abuse budget/cooldown/lock/deadline policy remains
   unresolved. Preflight-before-warning is agreed; host-DoS and habituation
   consequences require an owner decision.
2. Partner A treats stage-separated receipts as a mandatory redline; Partner B
   treats their absence as a standalone architecture blocker. The mechanism is
   required either way.
3. `PB-AS-009` remains unresolved because only B completed the source
   reproduction. The implementation must conservatively update and execute the
   full handler differential.
4. B left an owner-approved unsupported-capability class conceptually open; A
   keeps every existing `RenderErr` fatal. The conservative PQ1 candidate
   selects fatal and defers any expansion.
5. No favorable conclusion transfers to a materially changed plan, source, or
   build artifact.

## Honest residual

1. **What both reviewers tried to break and could not:** neither established
   the simple stale-`r0` exploit across a complete warning/transcript/final
   sequence; current physical button release state is a real defense. Bloom
   false positives do not grant more authority if they only enter a stricter
   forced review.
2. **What neither reviewer established:** no forced-tier implementation exists;
   no optimized Thumb register/spill proof, stack high-water, FI campaign,
   physical NV3007/scroll/two-consent evidence, authenticated EAS snapshot,
   production verifier, prodtest parity, rollback closure, or release
   provenance was established.
3. **Provenance:** the cross review was source/document analysis plus a pure
   Bloom recomputation and identity/hash checks. No build, QEMU, fuzz, Kani,
   Miri, hardware, live EAS, release, or irreversible action ran.
4. **Authority boundary:** the reviewed candidate is NO-GO. Recommendations
   are not owner risk acceptance, implementation, merge, release, or shipment
   authority. Current refusal and every independent production blocker remain.
