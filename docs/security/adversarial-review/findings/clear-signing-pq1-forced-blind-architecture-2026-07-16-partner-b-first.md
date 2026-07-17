# Partner B raw first-pass report

**Review decision: NO-GO for the frozen Phase-B architecture.**

The per-request forced-blind concept is potentially viable, but the frozen proposal does not yet define a fail-closed eligibility taxonomy, injective transcript, independent two-confirmation receipts, closed routing policy, unique gas-page ownership, or credible secure-stack construction. Those are architecture defects, not implementation polish.

No Partner A findings or verdict were available to or inferred by this review.

## 1. Runtime and independence receipt

| Property | Receipt |
|---|---|
| Requested model | `gpt-5.6-sol` |
| Requested reasoning effort | `ultra` |
| Model/effort actually exposed to reviewer | `NOT_EXPOSED` — cannot be truthfully self-attested |
| Sandbox | Read-only |
| Review target mutation | None |
| Partner A material | Withheld and unseen |
| Discovery lanes | Three: classification/routing/gas; UI/FI/resources; hostile-host/lifecycle/provenance |
| Personal adjudication | Completed; lane conclusions were not accepted automatically |
| Second backend | Attempted, but failed before inference |

The supplemental second-backend attempt used Claude CLI `2.1.211`, Opus/xhigh, read-only plan mode. It failed with `ENOTFOUND`, session `d3700b4a-5806-42d3-9773-eaeb342b0c24`, with zero input/output inference tokens. Therefore this report **does not satisfy an independently attestable two-backend lane requirement**. The separately running, withheld Partner A review cannot be counted inside this first pass.

This is a review-process gate, recorded as PB-PROC-013 below.

## 2. Frozen-target identity receipt

Initial and final checks both matched the packet contract:

- HEAD: `9647b79374d5e2e10445254492308101b8be708b`
- Expected tracked modifications only:
  - `docs/erc7730-implementation-review-2026-07.md`
  - `docs/work-todo.md`
- Untracked inventory: empty
- Ignored-untracked inventory: empty
- Binary diff SHA-256: `b8e270747a5c16eafde0b74fe94f34be9ab4504d91559234fb2a1ca056d59c25`
- `git diff --check`: clean

Final command output:

```text
9647b79374d5e2e10445254492308101b8be708b
 M docs/erc7730-implementation-review-2026-07.md
 M docs/work-todo.md
 M docs/erc7730-implementation-review-2026-07.md
 M docs/work-todo.md
b8e270747a5c16eafde0b74fe94f34be9ab4504d91559234fb2a1ca056d59c25  -
```

The duplicate `M` lines are the same two files printed by `status --short` and then by `status --porcelain=v1`; the two inventory commands produced no output.

## 3. Stage-specific verdicts

| Stage | Verdict | Basis |
|---|---|---|
| Architecture | **NO-GO** | PB-AR-001 through PB-AR-008 and the unresolved process gate |
| Implementation | **UNAVAILABLE / not approved** | The escape hatch is not implemented; source inspection only assessed current integration hazards |
| Merge | **NO-GO** | No approved architecture, implementation evidence, dual-review convergence, or merge packet |
| Production | **NO-GO / unavailable** | No implementation or artifact evidence; existing production gates remain independently fail-closed |
| Irreversible action | **Not authorized** | No merge, signing, flashing, deployment, root rotation, publication, or shipment action was performed or approved |

The production verdict is not a claim that the unimplemented feature has a production vulnerability. It means there is no basis to approve such a feature for production.

## 4. Finding summary

| ID | Severity | Architecture blocker | Production blocker |
|---|---:|---:|---:|
| PB-AR-001 | High | Yes | Yes |
| PB-AR-002 | Medium | Yes | Yes |
| PB-AR-003 | High | Yes | Yes |
| PB-AR-004 | High | Yes | Yes |
| PB-AR-005 | High | Yes | Yes |
| PB-AR-006 | Medium | Yes | Yes |
| PB-AR-007 | Medium | Yes | Yes |
| PB-AR-008 | High | Yes | Yes |
| PB-AS-009 | Medium | No independently | Yes before merge |
| PB-BR-010 | High | No for this escape-hatch concept | Yes |
| PB-DOC-011 | Low | No independently | Yes before assurance claims |
| PB-UX-012 | Medium residual | No if explicitly accepted | Requires usability evidence |
| PB-PROC-013 | Review gate | Yes for convergence | Yes |

## 5. Detailed findings

### PB-AR-001 — Eligibility is derived from ambiguous negative evidence

- **Severity:** High
- **Location:** [architecture plan](/tmp/pq1-erc7730-arch-review-9647b79/docs/erc7730-implementation-review-2026-07.md:450), `secure/src/tx/display/dispatch.rs`, `secure/src/tx/erc7730/render/mod.rs::RenderErr`, and the outer ERC-7730 parsing block in `secure/src/handlers.rs`.
- **Mechanism:** The proposal groups descriptor absence, invalid or misbound metadata, and inability to render into an eligibility concept without freezing a closed classification. Current code already collapses several well-framed bundle verification failures to the same absence value. Meanwhile `RenderErr::Reject` spans malformed ABI/TLV/path data, short heads, invalid offsets, padding/trailing bytes, must-match failures, nested-call rejection, arithmetic/width failures, “no visible fields,” and internal invariants. Mapping `None`, generic verification failure, or `Reject` to forced-blind eligibility would turn negative evidence—and potentially a skipped check—into authority.
- **Prerequisites:** A hostile host omits or corrupts metadata, supplies a valid outer frame with invalid inner material, reaches an unsupported formatter branch, or a fault suppresses a verification result.
- **Consequence:** A parser, binding, CFI, or completeness failure can downgrade into a signable path instead of remaining fatal.
- **Falsifiable evidence/counterexample:** Current outer frame-length failure is fatal, but multiple well-framed verification/binding failures become indistinguishable from absence. A future `if verified.is_none() { eligible }` therefore cannot prove why the value is absent.
- **Required correction:** Freeze a closed outcome type such as:
  - `Clear(Pages)`
  - `BlindEligible(BlindReason)`
  - `Fatal(FatalReason)`

  `BlindReason` must contain only explicitly reviewed reasons. No wildcard, permissive `From`, generic `Reject`, invalid discriminant, A/B disagreement, or inverted failure proof may enter it. Use positive protected evidence for filter-positive status. Unknown future reasons are fatal.

  A defensible initial set is:

  - clean metadata absence for a positively filter-positive single/direct tuple;
  - explicitly owner-approved, well-framed but cryptographically unavailable metadata, after discarding every supplied byte;
  - verified-and-bound descriptor with a specifically enumerated unsupported capability, such as `NoMatchingFormat`.

  Root mismatch and bad-proof behavior still require the owner resolution in PB-AR-008.
- **Architecture block:** Yes.
- **Evidence class:** Executed source inspection plus control-flow reasoning.

### PB-AR-002 — “Known call” is not established by the Bloom filter

- **Severity:** Medium
- **Location:** `secure/src/tx/known_calls.rs::may_contain` and `secure/data/erc7730-known-calls.bloom`; plan wording at [line 450](/tmp/pq1-erc7730-arch-review-9647b79/docs/erc7730-implementation-review-2026-07.md:450).
- **Mechanism:** The catalogue check is a Bloom filter. It proves only filter-positive membership, not exact catalogue membership. The plan simultaneously speaks of “known calls” and says no heuristic may grant permission.
- **Prerequisites:** Any Bloom false positive.
- **Consequence:** The normative eligibility contract cannot be implemented literally. Implementations and tests could disagree about whether exact catalogue membership or filter positivity is authoritative.
- **Executed counterexample:** For:
  - chain: `18446744073709551615`
  - contract: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
  - selector: `00001d4f`

  the seven calculated positions were:

  ```text
  [99335, 23186, 78109, 1960, 56883, 111806, 35657]
  ```

  All corresponding bits were set. Repository search found no matching literal registry entry. The collision was found after 7,504 trials.
- **Required correction:** Choose one normative meaning:
  1. Rename the policy to **filter-positive** and explicitly accept false positives; or
  2. Add an exact secure set or authenticated membership witness.

  Partner B favors the first for this scope: a false-positive unknown call is routed into a stricter two-consent raw flow rather than acquiring more authority than generic blind signing. The classifier must nevertheless produce a positive FI-protected `filter_positive` receipt; never infer it from `prove_unknown != OK`.
- **Architecture block:** Yes, until terminology and proof semantics are fixed.
- **Evidence class:** Executed data-level collision test and source inspection.
- **Minority lane view retained:** One lane preferred exact catalogue membership. That remains a legitimate owner choice.

### PB-AR-003 — Two dialogs do not yet constitute independent authorization receipts

- **Severity:** High
- **Location:** `secure/src/confirm.rs::confirm_checked`, [secure/src/fi.rs](/tmp/pq1-erc7730-arch-review-9647b79/secure/src/fi.rs:296) `scrub_sentinel_register`, and [secure/src/hw/buttons.rs](/tmp/pq1-erc7730-arch-review-9647b79/secure/src/hw/buttons.rs:243).
- **Mechanism:** Every current `confirm_checked` ceremony returns the same `(Confirmed, OK_SENTINEL)` shape. Calling it twice does not prove that two different security stages ran. The FI code itself documents a stale-register attack window around sentinel-returning calls.
- **Prerequisites:** Optimized-code branch/store skip, stale return register, spilled sentinel reuse, duplicated outcome, or missing binding between the first acknowledgment and the request ultimately signed.
- **Consequence:** A fault may satisfy the final release condition with one ceremony, one stale token, or a token from a different request.
- **Falsifiable evidence:** The source provides no domain-separated warning token, final-confirm token, request-digest binding, or caller-owned independent fail-initialized slots. Conversely, the button driver waits for release before completing long/chord confirmation, so one continuous physical hold does **not** trivially approve two honest dialogs.
- **Required correction:** Use distinct warning/final receipt types and constants, separate volatile fail-initialized caller-owned outputs, separate CFI steps, request-digest binding for the warning receipt, single consumption, and a final release predicate that checks both receipts and the exact sequence. Validate optimized Thumb code for skipped stores, stale registers, spills, ABI return placement, and branch faults.
- **Architecture block:** Yes.
- **Evidence class:** Executed source inspection; optimized-ELF exploitability remains unexecuted.

### PB-AR-004 — The proposed forced transcript is not demonstrably injective

- **Severity:** High
- **Location:** `secure/src/tx/display/blind_sign.rs`, `secure/src/tx/erc7730/formatter.rs`, symbol `U256::format_decimal`, and `secure/src/tx/erc8213.rs`.
- **Mechanism:** Existing decimal formatting deliberately rounds or truncates at selected display precision. The plan names value, chain, selector/length, signer, gas, and ERC-8213 digest, but does not freeze exact representations for all signed outer fields—especially `maxFeePerGas` and `maxPriorityFeePerGas`. ERC-8213 hashes the inner calldata, not those outer fields.
- **Prerequisites:** Two requests differ only below the displayed decimal precision or differ in an omitted outer field.
- **Consequence:** Distinct signed requests can produce the same visible transcript, violating WYSIWYS.
- **Concrete counterexamples:**
  - `1 ETH + 1 wei` and `1 ETH + 2 wei` both render as `1.000000 ETH` at six fractional digits.
  - Fee values `1 wei` and `2 wei` both render as `0.000 gwei` at three fractional digits.
  - Large values can converge on the same overflow presentation.
  - The full calldata digest does not distinguish changes to value or fee fields.
- **Required correction:** Freeze a dedicated, static forced-blind page schema containing, at minimum:
  - persistent `FORCED BLIND / UNVERIFIED` marker;
  - full signer/account;
  - full raw target, without resolver substitutions;
  - numeric chain identifier;
  - exact raw U256 value;
  - selector/short-calldata status and exact calldata length;
  - exact raw U256 `maxFeePerGas` and `maxPriorityFeePerGas`;
  - exact gas triple;
  - exact complete nonce representation;
  - an explicit owner decision for paymaster representation;
  - complete two-page ERC-8213 calldata digest;
  - final confirmation.

  Friendly decimal forms may be supplemental only. Exact representations must fit or the request is fatal. Failed descriptor data, names, selector labels, and host strings must not be passed to this renderer.
- **Architecture block:** Yes.
- **Evidence class:** Executed source inspection plus arithmetic counterexamples.

### PB-AR-005 — Fatal exclusions are not closed across routing surfaces

- **Severity:** High
- **Location:** `secure/src/tx/display/dispatch.rs`, the single and batch paths in `secure/src/handlers.rs`, and the `EXEC_TRANSACTION_MIN_CALLDATA_LEN` gate.
- **Mechanism:** CoW, Safe and ERC-7730 are prioritized, but the current Safe `execTransaction` hard refusal requires both its selector and a minimum calldata length. A selector-only or short malformed `execTransaction` can fall through to ordinary dispatch. The new outcome also needs explicit handling in batch and every alternate route.
- **Prerequisites:** Short or malformed Safe calldata, request reshaping, batch routing, or an unhandled future dispatch outcome.
- **Consequence:** A surface the architecture declares fatal may reach typed, ERC-20, generic blind, or the forced-blind flow.
- **Falsifiable counterexample:** `execTransaction` selector with length below `EXEC_TRANSACTION_MIN_CALLDATA_LEN` does not satisfy the existing Safe refusal predicate. `approveHash` and CoW gates are already stricter, showing the inconsistency.
- **Required correction:** Freeze an exhaustive pre-dispatch exclusion classifier. Safe/CoW selectors and targets, `approveHash`, `execTransaction`, MultiSend, delegatecall, malformed envelopes, batch, off-chain requests, nested exclusions, and page overflow must remain fatal regardless of short length or later formatter behavior. Batch must explicitly map every `BlindEligible` outcome to fatal, including one-element batches. The permit type should be private to the single/direct handler, non-`Copy`, request-bound, and consumable once.
- **Architecture block:** Yes.
- **Evidence class:** Executed source control-flow inspection.

### PB-AR-006 — Exactly-one gas-page ownership is underdefined

- **Severity:** Medium
- **Location:** `secure/src/tx/display/userop_gas_lane.rs`, the ERC-7730 renderer, and the handler insertion block around `secure/src/handlers.rs:1345`.
- **Mechanism:** The renderer already appends an exact canonical gas page; the handler also inserts one at a deterministic position. Existing proof logic establishes “prior count plus one,” not global uniqueness.
- **Prerequisites:** ERC-7730 rendering followed by normal handler augmentation, or a future retry/idempotent path.
- **Consequence:** Duplicate gas pages, needless page-budget failure, inconsistent placement, and a false exactly-one assurance claim.
- **Evidence:** Both producers were observed in source. The differential glue model in PB-AS-009 does not model the handler insertion.
- **Required correction:** Prefer one owner: remove the renderer append and let the handler synthesize the page from signed words. If idempotence is retained, recompute the exact canonical page, scan all visible pages, insert only on count zero, leave count one unchanged, reject count greater than one or near-shaped conflicts, and prove exactly one immediately before every confirmation.
- **Architecture block:** Yes because exactly one page is normative.
- **Evidence class:** Executed source inspection.
- **Adjudicated lane disagreement:** A discovery lane required provenance tagging. Partner B concludes provenance is unnecessary if globally unique exact content is recomputed from the signed inputs and every page is scrolled. One-producer ownership is still simpler and preferred.

### PB-AR-007 — Lexical `drop` is not a secure-stack argument

- **Severity:** Medium
- **Location:** The warning/raw-page lifetime proposal in [the architecture plan](/tmp/pq1-erc7730-arch-review-9647b79/docs/erc7730-implementation-review-2026-07.md:439) and the `Pages` representation.
- **Mechanism:** A target `Pages` value occupies approximately `31 × 64 + 4 = 1,988` bytes even when few pages are visible. Lexically dropping the warning value does not guarantee optimized stack-slot reuse or prove that warning, transcript, handler locals, exception frame, and signing state fit simultaneously.
- **Prerequisites:** Compiler retains separate slots, inlining expands the parent frame, or an interrupt/exception consumes remaining headroom.
- **Consequence:** Stack overflow, corruption, reset, or a fault-sensitive control path during signing.
- **Falsifiable evidence:** No target map, stack-usage report, optimized disassembly, MSPLIM margin, or hardware high-water measurement was supplied. This is an unresolved feasibility suspicion rather than a demonstrated overflow.
- **Required correction:** Architect one fully cleared reusable `Pages` buffer, or a thin parent owning no `Pages` that calls separate non-inlined warning and transcript child phases. Require post-LTO static stack evidence, exception headroom, stack canary/high-water evidence, and optimized call-shape inspection.
- **Architecture block:** Yes until construction and evidence requirements are frozen.
- **Evidence class:** Source/type-size reasoning; target verification unexecuted.

### PB-AR-008 — The proposal conflicts with current owner contracts

- **Severity:** High
- **Location:** [CLAUDE.md](/tmp/pq1-erc7730-arch-review-9647b79/CLAUDE.md), the companion integration guide, root-rotation policy rule 3, integration requirements, ERC-8176 status owner, and `CS2` in the clear-signing adversarial playbook.
- **Mechanism:** Current policy hard-refuses a filter-positive known-call path without an exact trusted descriptor and hard-refuses mismatched roots or unknown root/payload pairing. The proposal allows at least some unavailable, bad, or misbound metadata to enter the new forced tier, but its owner-amendment list does not consistently include every contradictory owner.
- **Prerequisites:** Implementation proceeds using the plan while existing owner documents remain normative.
- **Consequence:** Two incompatible security contracts govern the same request; reviewers and implementations can each appear compliant while making opposite decisions.
- **Evidence:** Root-rotation policy lines 42–52 require hard refusal, while the plan includes bad/misbound proof among contemplated unavailable cases. The current integration guide and CS2 also state hard refusal.
- **Required correction:** Obtain explicit owner decisions and amend, at minimum:
  - the trusted-display invariant in `CLAUDE.md`;
  - companion guide sections 1, 9 and 10;
  - the companion integration contract;
  - clear-signing playbook CS2;
  - root-rotation policy rule 3;
  - the ERC-8176 status owner.

  The amendment should say that filter-positive calls never silently fall through to ordinary typed/ERC-20/generic blind signing. They either clear-sign, fatal-refuse, or—only for enumerated single/direct reasons—enter a distinct on-device forced-blind tier after a severe warning, fixed raw transcript, and independent final confirmation. Forced blind is not clear signing.

  For bad/misbound proof, the owner must explicitly choose between preserving hard refusal or intentionally superseding it. Partner B recommends preserving root-mismatch refusal unless the owner affirmatively accepts the broader override.
- **Architecture block:** Yes.
- **Evidence class:** Executed full owner-document comparison.

### PB-AS-009 — Differential assurance omits actual gas-page glue

- **Severity:** Medium
- **Location:** `secure/tests/wysiwys_dispatch_differential_tests.rs`, especially its header and `drive_glue` model, versus the handler gas insertion around `secure/src/handlers.rs:1345`.
- **Mechanism:** The test claims to model handler splice order but omits the gas insertion performed by the handler.
- **Prerequisites:** Tests are relied upon as end-to-end evidence for page identity or order.
- **Consequence:** Renderer/handler divergence and duplicate gas pages can pass the model.
- **Evidence:** Source comparison; tests were not executed.
- **Required correction:** Model the complete handler transformation and assert exact page sequence/count at the final confirmation boundary. Add properties for zero/one/two gas pages, full-page idempotence, insertion failure, batch rejection, and every eligibility/fatal reason.
- **Architecture block:** No independently, but required before implementation or merge approval.
- **Evidence class:** Executed source/test inspection.

### PB-BR-010 — ERC-8176 readiness reporting can produce a false green

- **Severity:** High for provenance/production
- **Location:** [tools/erc8176_eas_coverage.py](/tmp/pq1-erc7730-arch-review-9647b79/tools/erc8176_eas_coverage.py:102), particularly the coverage intersection test and “Safe to flip” output.
- **Mechanism:** The script marks a descriptor covered if it has any attestation from the trusted set. Policy requires at least two qualifying attesters per descriptor. “Every descriptor has one” does not imply “every descriptor satisfies the threshold.”
- **Prerequisites:** Each descriptor has one trusted attester, with the overall trusted set containing at least two identities.
- **Consequence:** A readiness report can recommend enabling production ingestion before the per-descriptor threshold is met.
- **Falsifiable counterexample:** Descriptor A attested only by trusted signer X and descriptor B only by trusted signer Y. Every descriptor intersects the trusted set, yet neither has two attesters.
- **Additional contradiction:** The status owner says remaining blockage is ecosystem rather than code, while the database generator explicitly refuses production policy because the real verifier is not implemented.
- **Required correction:** Count distinct qualifying attesters per descriptor, bind the trust list and threshold to authenticated policy, consume a reproducible signed snapshot, implement the production verifier, and keep all current fail-closed gates until artifact evidence proves the complete chain.
- **Architecture block:** No for the local forced-blind design itself.
- **Production block:** Yes.
- **Evidence class:** Executed script/source reasoning. No live EAS query was performed.

### PB-DOC-011 — Proposed catalogue drift guards are too narrow

- **Severity:** Low
- **Location:** The companion guide, `secure/src/tx/erc7730/ir.rs`, ERC-7730 formatter `NftName` branch, and `secure/src/tx/erc8213.rs`.
- **Mechanism:** Root/count/size checks detect some drift but not semantic opcode or formatter-policy drift.
- **Evidence:**
  - Current guide data is stale: approximately `2000 B`, five leaves and an old `2c4f…` root, versus the frozen E2E database at 3,917 bytes, eight entries and `cbd0b771…0238e9`.
  - The guide says `NftName` is opcode `0x09`; source assigns `NftName = 0x04` and `Unit = 0x09`.
  - The dated review says `nftName` rejects, while the formatter renders a raw token ID.
  - The ERC-8213 helper comment suggests callers may silently drop the digest although current signing handlers treat it as mandatory.
  - `td-2` specifies a legacy partial SHA-256 page even though the full two-page ERC-8213 digest is already mandatory.
- **Required correction:** Add semantic manifest/corpus guards for opcode assignments, supported formatter behavior and mandatory digest use. Remove `td-2` as a forced-tier prerequisite and omit the legacy partial hash from the forced renderer.
- **Architecture block:** No independently.
- **Evidence class:** Executed source/document comparison.

Artifact receipts obtained during this check:

- Production database:
  - size `334827`
  - SHA-256 `d5ed95960a3c84dc65b534dbe1dfd8d6e6b1e766605bdd45a8f332b26f995099`
  - count `420`
  - observed root abbreviated `048fd2f1…6ab142`
- E2E database:
  - size `3917`
  - SHA-256 `5d6ee030da3bb5d1c65192badeb5378aab44d8cd60303b5836e53a52c90ad486`
  - count `8`
  - observed root abbreviated `cbd0b771…0238e9`

The abbreviated roots are descriptive, not exact root attestations.

### PB-UX-012 — Warning fatigue remains a bounded but real residual

- **Severity:** Medium residual
- **Location:** Per-request/session-toggle alternatives in the architecture plan and lifecycle/security playbooks.
- **Mechanism:** A hostile host can repeatedly omit metadata and cause the severe warning on every eligible call. Cancelled prompts do not consume a signing-rate attempt. Repetition can habituate the user.
- **Prerequisites:** Malicious or broken host plus repeated user interaction.
- **Consequence:** Reduced warning salience and availability degradation, although no automatic signature follows.
- **Correction:** Keep the per-request on-device choice, static severe text, persistent unverified banner, and independent final confirmation. Treat comprehension/habituation as a usability evidence requirement. Do not add a host flag, persistent permission, or automatic downgrade.
- **Architecture block:** No if explicitly accepted and tested.
- **Adjudication:** The plan understates the session-toggle benefit: it can save `N-1` warnings, not merely one. It also creates reusable SRAM authority, stale/interleaving/FI problems, and still needs final confirmation. Per-request remains the smaller authority for PQ1. A device attempt budget could reduce fatigue but also creates host-driven denial of service and new state, so it is not mandated here.
- **Evidence class:** Threat-model reasoning; no panel or usability test.

### PB-PROC-013 — Required two-backend review coverage is not attestably complete

- **Severity:** Review-process gate
- **Location:** [common review packet](/tmp/pq1-erc7730-architecture-review-common.md) multi-lane/backend requirement.
- **Mechanism:** Three discovery lanes completed, but their backend model identity was not exposed. The explicit second-backend CLI attempt failed before inference.
- **Consequence:** This raw report may be used as adverse evidence, but cannot be counted as a fully conforming favorable dual-backend review or as convergence evidence.
- **Correction:** Run the required supplemental lane on an independently attested backend and preserve this report unchanged for cross-adjudication. Validate the requested Partner B model/effort from launcher or control-plane logs.
- **Architecture block:** It blocks review convergence, not the technical concept by itself.

## 6. Minimum acceptable revised architecture

A revised design should freeze this flow:

```text
Strict parse and protected exclusion classification
    -> fatal on malformed/excluded/internal disagreement
    -> verified and completely renderable: clear-sign
    -> positively proven, enumerated eligible reason only
    -> static severe warning
    -> request-bound warning receipt
    -> clear/reuse warning resources
    -> fixed raw transcript with persistent unverified banner
    -> independent final-confirm receipt
    -> recheck reason + both receipts + exact sequence
    -> single signature release
```

Additional invariants:

- Default and rollback behavior remain the current hard refusal.
- No new host command, wire flag, persistent field, session permission, or automatic downgrade.
- Failed metadata bytes are discarded before the forced renderer is called.
- Batch, off-chain, Safe, CoW, malformed, nested/delegatecall and overflow paths remain fatal.
- Every final `Pages` set contains exactly one canonical gas page.
- Every enum variant, CFI disagreement and future unknown reason fails closed.
- Cancel, reset, exception or disconnect destroys the request-local capability.
- The capability is private, non-`Copy`, request-digest-bound and consumed exactly once.

## 7. Scope disposition

### KEEP

- Per-request, on-device permission only.
- Current refusal as default and rollback.
- Separate forced-blind renderer.
- Severe warning followed by an independent final confirmation.
- Single/direct requests only.
- Full ERC-8213 calldata digest.
- No persistent state or wire-protocol change.
- Existing production fail-closed gates.

### SIMPLIFY

- Give the gas page one owner, preferably the handler.
- Reuse one cleared `Pages` buffer or isolate page-owning child frames.
- Remove `td-2` partial-hash prerequisite.
- Consolidate duplicated owner contracts after explicit approval.

### FIX NOW

- Closed typed eligibility/fatal taxonomy.
- Positive FI-protected filter-positive proof.
- Domain-separated request-bound confirmation receipts.
- Exact injective transcript schema.
- Exhaustive Safe/CoW/batch/malformed routing.
- Exactly-one gas-page invariant.
- Stack construction and required target evidence.
- Explicit owner-document amendments and acceptance matrix.

### DEFER

- Batch/off-chain/Safe-inner support.
- Session status/query command.
- Native-asset list expansion.
- NFT/nested/multitail/intent rendering.
- Production ERC-8176 ingestion until its separate gates pass.

### DROP FOR PQ1

- Host-controlled, persistent or automatic permission.
- Session-wide permission.
- Display of failed metadata, descriptor names or resolver-derived labels.
- Legacy partial calldata hash in the forced transcript.

### OPEN RESEARCH / OWNER DECISION

- Exact membership versus explicitly filter-positive semantics.
- Whether bad or root-misbound metadata remains fatal.
- Warning habituation and device-side attempt budgeting.
- Optimized ELF/FI/stack/hardware behavior.
- Paymaster exact-display commitment.
- Upstream normalization and future nested/multitail support.

## 8. Contradiction ledger

1. Current trusted-display contract says hard refusal; proposal introduces an override tier.
2. Root mismatch/unknown pairing is currently fatal; the proposal contemplates treating it as unavailable.
3. “Known” is asserted from a probabilistic Bloom filter.
4. “No heuristic grants permission” conflicts with Bloom-only membership and any inverted negative proof.
5. Exactly one gas page conflicts with two current producers.
6. Differential glue tests claim handler fidelity but omit handler gas insertion.
7. `td-2` partial hash duplicates a stronger mandatory ERC-8213 digest.
8. E2E guide root/count/size is stale.
9. Guide opcode and `nftName` behavior disagree with source.
10. ERC-8176 status says ecosystem-only blocker while production verification code is absent.
11. ERC-8176 reporting checks one attester while policy requires two per descriptor.
12. Lexical resource `drop` is presented as stack mitigation without compiler/target evidence.

## 9. Mandatory adversarial-question coverage

### Clear signing — CS1–CS10

- **CS1:** Gap. The exact forced transcript is not frozen; PB-AR-004.
- **CS2:** Fail. Existing hard-refusal owner contract conflicts with the proposal; PB-AR-008.
- **CS3:** Gap. Eligibility must be established by a positive protected proof, not missing/failed evidence; PB-AR-001/002.
- **CS4:** Fail. Rounded value and fee rendering is not injective; PB-AR-004.
- **CS5:** Conditional. Failed metadata must be absent from UI; no-visible-fields and completeness failures remain fatal.
- **CS6:** Pass as proposed only if nested paths remain exhaustively fatal.
- **CS7:** Gap. Safe/delegatecall exclusions are not closed for short/malformed inputs; PB-AR-005.
- **CS8:** Gap. Page overflow is fatal, but stack/page ownership evidence is incomplete; PB-AR-006/007.
- **CS9:** Gap. The forced renderer must be separate and incapable of generic formatter fallback.
- **CS10:** Conditional. Static unverified text is acceptable; descriptor/resolver/host names are not.

### USB companion — UC questions and ten-row threat map

The inspected playbook labels UC1–UC6 but does not provide named UC7–UC10 questions. That indexing gap was not treated as permission to skip the ten threat-map rows.

- **UC1 / lying calldata:** Full raw signed fields and calldata digest are needed; host can intentionally omit metadata.
- **UC2 / pointers and lengths:** Outer framing, pointers, offsets, padding and trailing bytes must remain fatal.
- **UC3 / compromised firmware:** Secure-boot/firmware trust is unchanged and outside this feature’s authority.
- **UC4 / off-chain ambiguity:** Off-chain requests remain fatal.
- **UC5 / wrong chain/account/slot:** Numeric chain and full signer/target must be shown; no resolver substitution.
- **UC6 / substitution hotspot:** Full calldata digest protects calldata, but omitted/rounded outer fields remain vulnerable.

Ten threat-map rows:

1. Host lies about calldata: caught only by device parsing and full digest.
2. Host exploits pointers/lengths: fatal parse, never eligibility.
3. Host supplies malicious firmware: unchanged secure-boot boundary.
4. Host reshapes as off-chain request: fatal.
5. Host substitutes chain/account: full numeric/raw display required.
6. Host substitutes hash or unhashed field: PB-AR-004 must be fixed.
7. Host spams PIN/prompts: no automatic signing, but fatigue/DoS remains.
8. Host spoofs confirmation progression: distinct request-bound receipts required.
9. Host creates origin confusion: static unverified banner plus full target/signer required.
10. Host causes denial of service: possible by repeated warning prompts; no signing authority follows.

### Trusted UI — UI1–UI8

- **UI1:** Fail. Warning and final confirmation lack distinct receipts.
- **UI2:** Existing secure-display fencing is unchanged; forced pages must stay inside it.
- **UI3:** No end-to-end target evidence exists.
- **UI4:** Positive source result: button code requires release, preventing one continuous hold from approving two honest ceremonies.
- **UI5:** Warning copy/timing is not frozen. If scrolling is a security claim, use at least two warning pages.
- **UI6:** Gap. Signature release must prove both stages occurred in order.
- **UI7:** Fail. Rounded/omitted fields violate WYSIWYS.
- **UI8:** No new secret output is proposed; failed metadata/host strings must remain excluded.

### SCA and fault injection — FI1–FI10

- **FI1:** Gap. Final release lacks two domain-separated receipts.
- **FI2:** Existing redundant signing checks are unchanged; the new authorization checks need equal redundancy.
- **FI3:** No new secret-dependent formatting decision is needed; all proposed classifiers concern public data.
- **FI4:** Eligibility and rendering decisions must remain public-data-only.
- **FI5:** PIN policy is unchanged; warning cancellation must not weaken it.
- **FI6:** Fail. Reuse of `OK_SENTINEL` permits stale-token reasoning; PB-AR-003.
- **FI7:** RNG behavior is unchanged.
- **FI8:** Gap. Request-local permit cleanup/consumption is not frozen.
- **FI9:** Existing masking/blinding assumptions are unchanged.
- **FI10:** Missing. Post-LTO Thumb disassembly, register/spill and fault sweeps are required.

### Lifecycle and persistent state — LC1–LC10

- **LC1:** Pass if no persistent permission is added.
- **LC2:** No provisioning change.
- **LC3:** Rollback/default remains hard refusal.
- **LC4:** No persistent migration or schema change.
- **LC5:** No new long-lived secret.
- **LC6:** Host can trigger the warning condition by withholding metadata; it cannot approve it.
- **LC7:** Reset/disconnect must destroy local authorization.
- **LC8:** No persistent schema should be introduced.
- **LC9:** No RMA/factory bypass or setting.
- **LC10:** Warning fatigue and prompt-driven availability remain; PB-UX-012.

### Secure runtime/resources — RT1–RT11

- **RT1:** No new unsafe code is needed.
- **RT2:** Large fixed page buffers require explicit ownership.
- **RT3:** Exceptions between the two dialogs must invalidate the first receipt.
- **RT4:** Fail/gap. Stack construction lacks evidence; PB-AR-007.
- **RT5:** No new DMA ownership proposed.
- **RT6:** Longer UI sequence needs watchdog/timeout evaluation.
- **RT7:** Fault, panic or reset must fail closed and erase permit/receipts.
- **RT8:** Page, length and retry bounds must be explicit.
- **RT9:** Warning buffer and request-local capability require guaranteed cleanup.
- **RT10:** Blast radius remains one request only if session/persistence is excluded.
- **RT11:** Missing target ELF/map/high-water/hardware evidence.

### Production configuration/prodtest — PC1–PC12

- **PC1:** The new consent tier requires explicit production owner approval.
- **PC2:** No developer/test flag may implicitly enable it.
- **PC3:** All relevant build/configuration axes require differential tests.
- **PC4:** No protocol ABI change is currently proposed.
- **PC5:** Production/test configuration equivalence is unproven.
- **PC6:** Failure or missing configuration must preserve current refusal.
- **PC7:** Development catalogue/root handling must not bleed into production.
- **PC8:** FI/test hooks must not alter production confirmation behavior.
- **PC9:** Catalogue/guide drift exists; PB-DOC-011.
- **PC10:** No hardware execution evidence.
- **PC11:** Root/enrollment policy conflicts must be resolved.
- **PC12:** No production artifact or prodtest result exists.

### Build/release/provenance — BR1–BR12

- **BR1:** Frozen source identity was verified initially and finally.
- **BR2:** No implementation artifact exists.
- **BR3:** No dependency addition was proposed or inspected.
- **BR4:** No reproducible-build claim was tested.
- **BR5:** Catalogue/provenance reporting has a false-green defect; PB-BR-010.
- **BR6:** No package/SBOM evidence for this feature.
- **BR7:** No signing-key operation was performed.
- **BR8:** No custody or root-rotation action was performed.
- **BR9:** No release approval exists.
- **BR10:** Future manifests must bind semantic catalogue policy, not just file size/count/root.
- **BR11:** No CI or release workflow was executed.
- **BR12:** No publication or distribution action was authorized.

## 10. Failed attacks and negative results

These attempted arguments did **not** produce findings:

- Worktree drift or hidden files: initial and final receipts matched; untracked and ignored inventories were empty.
- One continuous button hold approving both honest dialogs: current button logic requires release before returning.
- Calldata substitution with an otherwise correct full ERC-8213 display: the complete two-page calldata digest detects it. This does not protect omitted outer fields.
- A Bloom false positive gaining more authority than ordinary blind signing: under explicit filter-positive semantics, it receives a stricter warning/transcript/final-confirm route. The finding is the semantic contradiction, not an automatic signature bypass.
- False ERC-8176 readiness immediately enabling production: existing independent production gates remain fail-closed. PB-BR-010 is a future provenance/readiness blocker.
- Host-controlled persistence/session permission: none exists in current state and it should not be added.
- Display manipulation through failed descriptor names: preventable by structurally discarding all failed metadata before constructing forced pages.

Successful counterexamples are recorded in the findings: Bloom collision, rounded-field collision, short Safe fallthrough, duplicate gas ownership, identical confirmation sentinel, and the one-attester ERC-8176 false green.

## 11. Executed versus reasoning-only evidence

Executed:

- Full controlling-document and changed-diff review.
- Full applicable adversarial-playbook review.
- Targeted current-source and test inspection.
- Initial/final Git identity and dirty-state checks.
- `git diff --check`.
- Bloom false-positive calculation and repository search.
- Database size/hash/count/root inspection.
- Three independent discovery lanes followed by Partner B adjudication.
- Second-backend launch attempt, which failed before inference.

Not executed or not inspected:

- No builds, unit/integration tests, QEMU, fuzzing, Kani or Miri.
- No optimized Thumb ELF, map, stack-usage, ABI spill, disassembly or fault sweep.
- No target hardware, button-panel, watchdog, exception, FI or usability run.
- No live EAS/network query or upstream Ambire execution.
- No production artifact, reproducibility, SBOM, signing, merge, flashing or deployment.
- No complete unrelated crypto, transport or firmware audit.
- No Partner A report or cross-adjudication.
- Formatter/render/handler inspection was targeted to intersecting paths; this report does not claim exhaustive line-by-line review of all unrelated source.
- Literal model, reasoning effort and collaborator backend identities were not exposed to the reviewer.

## 12. Residual risk after the required corrections

Even a corrected architecture would retain:

- Human comprehension and warning-habituation risk.
- A policy choice around Bloom false positives.
- Compiler-, ABI- and silicon-specific FI uncertainty until target evidence exists.
- Secure-stack and exception-headroom uncertainty until measured.
- Catalogue/provenance dependence and future ERC-8176 verifier work.
- Host-driven prompt denial of service.
- Deferred nested, NFT, multitail and upstream-normalization ambiguity.
- The possibility that users intentionally approve a malicious raw transaction; forced blind signing can make that decision explicit but cannot infer intent.

## Final Phase-B recommendation

**NO-GO.**

Do not begin security-sensitive implementation from this frozen architecture. Revise PB-AR-001 through PB-AR-008, resolve the owner-contract amendments, freeze falsifiable acceptance tests, and repeat the exact required independent architecture-review configuration—including an attestable second backend—before implementation authorization.