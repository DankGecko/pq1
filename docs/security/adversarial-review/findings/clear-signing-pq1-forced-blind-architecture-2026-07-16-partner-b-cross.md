# Partner B — raw symmetric cross-adjudication report V1

## 1. Cross verdict

**Frozen architecture: NO-GO as worded.**

**Revised design direction: conditionally viable after the closed redlines below, explicit owner decisions, and review of the materially revised artifact.**

This cross-adjudication grants no implementation, merge, production, release, or irreversible-action authority. Partner A’s cross result was neither available nor sought.

## 2. Runtime and frozen-input receipt

| Item | Receipt |
|---|---|
| Partner B runtime | Accepted literal `gpt-5.6-sol`, `model_reasoning_effort="ultra"`, read-only |
| B runtime receipt | SHA-256 `dbcdf3ed459d41ae07a9933445ed3b8fc88d8a89deb3c421cddcd12c637cf4d3` |
| Partner A runtime | Claude Opus 4.8, 1M, `ultracode`, `xhigh`, read-only |
| A runtime receipt | SHA-256 `b070c7331366781a1d5d30729613f2ece08f5cfeb1388ce62f68de551a6440c2` |
| Partner A accepted report | V5, SHA-256 `4b34ae5f1459d2d6dbfe21a1a9019235b74344cb0440aac76551efe6823a884c` |
| Partner B accepted report | V4, SHA-256 `bcb8a52e7dba0ecf49e651467615a9c47da2a2a0756563d4362252dde5f1110f` |
| Reports read | Both completely |
| New discovery fan-out | None |
| Adjudication | Performed personally |
| Partner A cross result | Not accessed or inferred |
| Target/report edits | None |

All four supplied report/runtime hashes matched the cross packet before substantive work.

## 3. Initial target identity

- HEAD: `9647b79374d5e2e10445254492308101b8be708b`
- Tracked modifications only:
  - `docs/erc7730-implementation-review-2026-07.md`
  - `docs/work-todo.md`
- Untracked inventory: empty
- Ignored-file inventory: empty
- Binary diff SHA-256: `b8e270747a5c16eafde0b74fe94f34be9ab4504d91559234fb2a1ca056d59c25`
- Result: **MATCH**

Stage abbreviations below are A = architecture, I = implementation, M = merge, P = production.

## 4. Complete Partner A disposition table

| ID | Origin claim/severity/stage | Disposition | Reproduced/refuted evidence | Required correction or residual | Stage impact | Owner decision |
|---|---|---|---|---|---|---|
| `PA5-1` | Critical A blocker: absent, bad proof and detected binding/CFI failure collapse to identical `None`. | **CONFIRMED** | [cmd_sign_userop.rs](/tmp/pq1-erc7730-arch-review-9647b79/secure/src/nsc/cmd_sign_userop.rs:563) maps absent trailer, bundle `Err`, `bind_gate_a` failure and `bind_gate_b` failure to `None` before dispatch. | Preserve the cause in a closed handler-owned evidence type. Any CFI/FI disagreement is fatal. Do not derive eligibility from `Option::None`. | Blocks A; required I/M/P. | Whether ordinary invalid/misbound metadata is eligible remains an explicit product decision. Partner B recommends fatal. |
| `PA5-2` | High A blocker: “cannot completely render” conflicts with all verified-render failures being fatal. | **CONFIRMED** | [dispatch.rs](/tmp/pq1-erc7730-arch-review-9647b79/secure/src/tx/display/dispatch.rs:211) maps `Reject`, `NoFormat` and `PageBudget` to fatal. `RenderErr` documents these as diagnostic, not downgrade authority. `MAX_ARRAY_RENDER=8` defeats the suggested easy inflation attack but not the normative contradiction. | Split expected unsupported capability from integrity/resource failure. `Reject` and `PageBudget` stay fatal. Only explicitly enumerated unsupported capability may be considered. | Blocks A; I/M/P gate. | Owner must authorize any `NoFormat`/unsupported-capability override and amend current doctrine. |
| `PA5-3` | High A blocker: structural known-call refusal would become data flow immediately above generic fallback. | **NARROWED** | The five refusal sites and lower ladder at `dispatch.rs:382–425` are real. A typed outcome need not weaken them if it returns to the handler rather than falling through. | `ForcedCandidate` must be a separate terminal dispatcher outcome, never a flag that allows selector/ERC-20/generic blind continuation. | Frozen wording blocks A; corrected structure is viable. | No additional decision beyond approving the new trust tier. |
| `PA5-4` | Medium: unlimited zero-cost warning habituation; warning can precede later gas refusal. | **CONFIRMED** | Signing-rate charge occurs inside [crypto.rs](/tmp/pq1-erc7730-arch-review-9647b79/secure/src/crypto.rs:84). The plan orders warning before constructing the forced transcript, while current gas enforcement follows rendering. Cancelled warnings consume no sign budget. | Complete deterministic preflight and build the final transcript before warning. Add an explicit secure-side forced-prompt abuse control; do not rely solely on the signature limiter. | A redline; I/M UX and negative-test gate; P usability evidence. | Owner must select prompt budget/cooldown/lock behavior and accept its host-DoS trade-off. |
| `PA5-5` | Medium: companion-supplied `entry_point` is signed but unshown and unpinned. | **CONFIRMED** | Parsed at `cmd_sign_userop.rs:237`, included in `compute_sphincs_digest_v06` at [aa/src/userop.rs](/tmp/pq1-erc7730-arch-review-9647b79/aa/src/userop.rs:702), and not used by display code. Canonical `ENTRY_POINT_V06` exists but is not enforced in production. A wrong value normally wastes a signature because the wallet hashes its immutable EntryPoint. | For PQ1, FI-hardened equality-pin to `ENTRY_POINT_V06`; any mismatch is fatal. If custom EntryPoints are later supported, show the full address and re-review. | A transcript requirement; I/M/P gate. | Owner decision only if noncanonical EntryPoints are desired. |
| `PA5-6` | Medium assurance gap: `e2e-test` auto-confirms, so it cannot prove two consents. | **NARROWED** | [confirm.rs](/tmp/pq1-erc7730-arch-review-9647b79/secure/src/ui/confirm.rs:59) returns `Confirmed/OK_SENTINEL` automatically. Production fences exclude this feature, so it is not itself a shipping bypass. Other test configurations can discharge the claim. | Add a scripted non-auto-confirm UI/state-machine configuration with cancel, idle, replay and out-of-order controls. Keep `e2e-test` evidence explicitly non-authoritative for consent. | I/M assurance gate; P feature/configuration gate. | None. |
| `PA5-7` | Simplify: one gas owner; exact uniqueness and FI-independent proof still required. | **CONFIRMED** | ERC-7730 emits the exact gas page; single and batch handlers append it again. Current proof establishes “one newly inserted page,” not global exactly-one. | Delete renderer ownership. Handler pre-scans for zero exact matches, inserts once, then independently A/B-proves global count one and exact content immediately before confirm. | A mechanism redline; I/M/P gate. | None. |
| `PA5-8` | Medium documentation drift: proposed guard omits tuple SHA/count, Bloom occupancy and omission count. | **CONFIRMED** | [erc7730-integration.md](/tmp/pq1-erc7730-arch-review-9647b79/docs/companion/erc7730-integration.md:33) records 4,542 tuples, tuple SHA, 28,235/131,072 occupancy and 274 omissions. The plan guards only guide root/count/size. | Generate or verify all catalogue receipts from one manifest, including omission reason totals/digest. | I/M documentation-assurance gate; P provenance gate. | None. |
| `PA5-9` | Downgraded: stale-`r0` attack refuted; shared sentinel still needs FI10 evidence. | **NARROWED** | Fresh `seen_last` state and button-release behavior provide honest physical separation. The exact stale-`r0` story is not established because substantial work separates ceremonies. However the future two-stage code does not exist, and one undifferentiated sentinel does not prove stage order under FI. | Use separate fail-initialized stage slots, stage tags/constants, ordered CFI and a request-bound commitment. Optimized-ELF evidence remains I/P, not source-proven. | Frozen A wording remains insufficient; physical/FI validation is I/M/P. | None. |
| `PA5-10` | New: real button presses during companion prompts reopen HIGH-13 unlocked-window extension. | **NARROWED** | `confirm.rs:81–118` deliberately does not reset on entry and resets only after a real physical event. This does not recreate the host-only HIGH-13 attack: the user must remain present and press a button. It does amplify prompt-habituation/activity-extension risk. | Retain real-button activity semantics. Address abuse with preflight and a forced-prompt budget/cooldown rather than suppressing legitimate activity. | A/I UX control; not an independent critical blocker. | Same prompt-control decision as `PA5-4`. |
| `PA5-11` | New: distinct forced renderer is a second decoder and therefore CS9. | **NARROWED** | CS9 concerns a competing walker/decoder of signed encodings. A raw renderer over one already parsed canonical struct is not a second decoder by definition. The plan does not yet constrain it that tightly. | Accept only a typed canonical `ForcedTranscriptInput`; forbid ABI, metadata, resolver or trailer parsing in the forced renderer. Add every-signed-field flip tests. | A redline and I/M test gate; no independent blocker after that. | None. |

## 5. Complete Partner B disposition table

| ID | Origin claim/severity/stage | Disposition | Reproduced/refuted evidence | Required correction or precise residual | Stage impact | Owner decision |
|---|---|---|---|---|---|---|
| `PB-AR-001` | High A blocker: eligibility derives from ambiguous negative evidence. | **NARROWED** | The claim is strengthened by `PA5-1`: the cause is destroyed in `cmd_sign_userop`, earlier than my original dispatcher-focused correction accounted for. My original possible eligible set was too broad. | Introduce the typed evidence outcome in the handler. In the minimum architecture below, only clean absence and owner-approved verified unsupported capability are eligible; bad/misbound proof and every CFI disagreement are fatal. | Blocks A; I/M/P. | Bad/misbound policy requires an explicit decision; broader behavior requires re-review. |
| `PB-AR-002` | Medium A blocker: Bloom positive is not exact “known” membership. | **CONFIRMED** | Source-exact reproduction using the domain and Kirsch–Mitzenmacher double hash gave positions `[99335,23186,78109,1960,56883,111806,35657]`; all bits are set for the reported non-registry tuple. | Normatively say `filter-positive`, or add exact authenticated membership. Never infer positivity from a failed nonmembership proof. | A terminology/proof block; I/M/P. | Partner B recommends explicit filter-positive semantics; owner must sign that policy. |
| `PB-AR-003` | High A blocker: two dialogs with one sentinel are not independent receipts. | **NARROWED** | The blanket stale-`r0` mechanism is not reproduced, and honest physical dialogs have fresh state. The architecture still lacks stage-separated, request-bound FI receipts and ordered release proof. | Separate stage slots/tags plus CFI and request commitment; optimized proof later. Distinct constants are strongly preferred but equivalent stage-tagged receipts are acceptable. | A redline; I/M/P evidence. | None. |
| `PB-AR-004` | High A blocker: forced transcript is not injective. | **CONFIRMED** | Existing blind rendering rounds native value and fees; two differing raw words can render identically. The plan omits fees, full paymaster digest and EntryPoint treatment. ERC-8213 binds inner calldata only. `PA5-5` adds EntryPoint. | Use the exact fixed schema in §11, show raw signed words and paymaster digest, pin EntryPoint, and include the final signing digest. | Blocks A; I/M/P. | Paymaster must either show its full signed digest or be fatal. Presence-only is insufficient. |
| `PB-AR-005` | High A blocker: fatal routing is not exhaustive. | **CONFIRMED** | `execTransaction` refusal requires selector plus `EXEC_TRANSACTION_MIN_CALLDATA_LEN`; a short selector-shaped request can fall through. Batch uses the same dispatcher and needs explicit forced-outcome refusal. | Early exhaustive mode/exclusion classifier; selector-shaped malformed Safe is fatal; batch/off-chain/lifecycle modes cannot receive a forced capability. | Blocks A; I/M/P. | None. |
| `PB-AR-006` | Medium A blocker: exactly-one gas-page mechanism underdefined. | **CONFIRMED** | Both producers and the local-insertion-only proof were reproduced. Partner A independently withdrew provenance/position requirements and agreed one owner is enough. | One handler owner plus global count/content A/B proof. No provenance tag is required. | Blocks frozen A wording; I/M/P. | None. |
| `PB-AR-007` | Medium A blocker: lexical `drop` is not a stack proof. | **NARROWED** | `Pages` is 1,988 bytes on 32-bit target. Lexical lifetime does not guarantee slot reuse, but target stack/map evidence is legitimately an implementation gate. | Architecture must mandate one `Pages` plus static warning pages or non-inlined page-owning children. Map/high-water/exception evidence moves to I/M/P. | Frozen resource wording blocks A; physical proof does not. | None. |
| `PB-AR-008` | High A blocker: owner contracts conflict. | **CONFIRMED** | `CLAUDE.md`, companion guide, CS2 and [root-rotation policy](/tmp/pq1-erc7730-arch-review-9647b79/docs/erc7730-root-rotation-and-update-policy.md:42) require hard refusal. The plan acknowledges only part of the conflict and leaves root mismatch ambiguous. | Explicit amendments listed in §14. Forced blind must be named as a separate trust tier, not clear signing. | Blocks A and every later stage. | Owner must authorize the new tier and exact eligible classes. |
| `PB-AS-009` | Medium I/M: WYSIWYS differential omits handler gas insertion. | **CONFIRMED** | [wysiwys_dispatch_differential_tests.rs](/tmp/pq1-erc7730-arch-review-9647b79/secure/src/display_under_test/wysiwys_dispatch_differential_tests.rs:16) lists paymaster, signer, target, nonce and fingerprint, but `drive_glue` omits gas. | Model the complete final handler page set and exact uniqueness proof. | I/M gate; P evidence dependency. | None. |
| `PB-BR-010` | High P: ERC-8176 checker can emit false production readiness. | **CONFIRMED** | [erc8176_eas_coverage.py](/tmp/pq1-erc7730-arch-review-9647b79/tools/erc8176_eas_coverage.py:102) counts any trusted intersection, while policy requires at least two per descriptor. `dbgen` states production verification is not implemented. | Per-descriptor threshold, authenticated trust policy and reproducible signed snapshot; retain current compile-time refusal. | Not a forced-blind A blocker; blocks P. | Production provenance owner. |
| `PB-DOC-011` | Low documentation/assurance drift. | **CONFIRMED** | Guide says `NftName=0x09`; source has `NftName=0x04`, `Unit=0x09`. Dated review says `nftName` rejects though it renders. ERC-8213 comment permits silent drop despite current fatal callers. | Semantic manifest guards; fix the comment and stale behavior claims; remove legacy `td-2` prerequisite. | I/M documentation gate; P assurance dependency. | None. |
| `PB-UX-012` | Medium residual: warning fatigue and session alternative. | **NARROWED** | Partner A supplied the concrete zero-cost prompt path and post-warning-refusal ordering. Treating it only as later UX evidence was too weak. Session permission remains the larger authority. | Preflight before warning and add a device-local prompt-abuse control. Keep permission per request. | A redline plus I/P usability evidence. | Owner must choose the abuse-control policy. |
| `PB-PROC-013` | Review-process gate: B could not self-attest a second backend. | **NARROWED** | The original first-pass disclosure was correct within that report. The accepted launcher receipts now establish B as `gpt-5.6-sol`/ultra and the separate accepted A leg as Opus 4.8/1M/ultracode/xhigh. The coordinator accepts these as the two independent legs. | Historical self-attestation limitation remains recorded; no further correction is required for this pairing. | **Cured for this cross pair; no remaining A/M/P impact.** | None. |

No frozen ID disappeared.

## 6. Agreements

Both first passes, after cross-testing, support these conclusions:

- The frozen prose is not implementation-ready.
- Eligibility cannot be reconstructed from the current `Option<VerifiedDescriptor>`.
- Detected CFI/FI failure must never become forced-blind eligibility.
- Generic `RenderErr` cannot be an authorization reason.
- Forced blind is a separate loud trust tier, not clear signing.
- Current refusal remains the default and rollback.
- No host flag, persistent permission, automatic fallback or reusable session authority belongs in PQ1.
- Batch, off-chain, Safe, CoW, malformed and delegatecall surfaces remain excluded.
- One handler-owned gas page is sufficient; position/provenance is not intrinsically security-bearing.
- Exactly-one gas content still needs an independent global FI proof.
- Target stack, optimized ELF, physical UI and FI evidence were not established by either source-only review.
- Production ERC-8176 and rollback gates remain independent.

## 7. Explicit disagreements and their adjudication

### Confirmation independence

Partner A’s refutation defeats the simple assertion that a stale `r0` from the first ceremony necessarily survives through a complete transcript build. Partner B’s broader concern survives: the frozen architecture gives no mechanism proving two distinct stages and request identity under FI.

Adjudicated split:

- Honest physical separation: source-supported.
- Direct stale-`r0` exploit: not reproduced.
- FI-independent stage authorization: unresolved until separate slots/tags and ordered CFI exist.
- Optimized-ELF/silicon strength: implementation/production evidence.

### Bloom membership

Partner A inherited “known tuple” wording without resolving probabilistic membership. The executed collision confirms that exact membership is not available from the current filter.

Partner B recommendation: define the route as **filter-positive**. A false positive then receives a stricter raw review than ordinary unknown blind signing. If the owner requires actual registry membership, add an authenticated exact set or witness.

### Bad or root-misbound metadata

The frozen plan treats absence, bad proof and misbinding similarly. Current owner documents do not.

Partner B’s minimum safe policy is:

- Clean absence: potentially eligible.
- Invalid bundle: fatal.
- Root mismatch: fatal.
- Chain/target misbinding: fatal.
- Any binding/CFI disagreement: fatal.
- Verified expected unsupported capability: potentially eligible after owner amendment.

A broader override is a material product change requiring an explicit owner signature and another review.

### Gas page

One handler owner suffices, but not with the current “insert and prove the new slot” predicate. Required proof is:

1. independently compute expected page from frozen signed gas words;
2. A/B scan the entire pre-handler page set and require zero exact matches;
3. insert once;
4. independently recompute and A/B scan the final set;
5. require exactly one exact match, correct length, and no near-shaped conflicting page;
6. bind proof completion into caller-owned CFI before confirm.

No provenance marker is required.

### Habituation

The original Partner B residual was too permissive. Deterministic failure after a completed severe warning and unlimited uncharged warning attempts are architecture concerns. A prompt budget introduces host-DoS/state trade-offs, but that trade-off must be decided rather than deferred as generic UX evidence.

### Resource construction

Partner B’s concern is valid, but target stack evidence is not itself an architecture prerequisite once the architecture mandates a construction with only one `Pages`. The actual map/high-water/silicon proof remains later-stage evidence.

### Forced renderer and CS9

A raw renderer is not a second decoder if it accepts one canonical parsed struct and performs no metadata or ABI walk. It becomes a CS9 surface only if it reparses signed bytes differently from the signing path.

## 8. Counterpart inherited framing and unsupported assumptions

### Partner A

- Treated “known tuple” as exact without resolving Bloom false positives.
- Missed rounded value/fee collisions and paymaster-hash omission.
- “Independence holds” was stronger than the source evidence; only honest ceremony separation was shown.
- “Second renderer is a decoder by definition” is unsupported.
- Treated unread `state.rs` as an architecture GO blocker. It is now read: current `SecureState` contains no forced-blind permission. Future token lifetime remains implementation evidence.
- Did not trace the short-`execTransaction` fallthrough or batch outcome mapping.
- Correctly identified EntryPoint omission, the earlier loss of metadata-cause information, and the concrete habituation path.

### Partner B

- Original citations named `secure/src/handlers.rs` and `secure/src/tx/known_calls.rs`; the actual paths are `secure/src/nsc/cmd_sign_userop.rs` and `pqsigner-erc7730/src/known_calls.rs`.
- Focused the eligibility fix too late in dispatch; the handler has already destroyed the cause.
- Overstated the stale-sentinel mechanism and initially made distinct constants sound solely sufficient.
- Treated stack target evidence as part of the architecture verdict instead of separating required construction from later proof.
- Initially classified habituation as a bounded residual despite a source-supported uncharged prompt path.
- Correctly identified Bloom semantics, transcript collisions, Safe routing, gas ownership, owner-contract conflict, assurance drift and ERC-8176 false readiness.

The USB playbook itself defines UC1–UC5 plus a separately named UC6 hotspot; it does not define UC7–UC10. Both reviews appropriately walked the complete hostile-companion map rather than treating the packet’s numbering drift as permission to omit threats.

## 9. New cross finding

### `XB-001` — Forced-blind mode does not exclude deployment and slot rotation

- **Severity:** High
- **Evidence:** The frozen plan says “single-UserOp” but does not explicitly require both lifecycle flags to be clear. [cmd_sign_userop.rs](/tmp/pq1-erc7730-arch-review-9647b79/secure/src/nsc/cmd_sign_userop.rs:271) accepts either `FLAG_INCLUDE_INIT_CODE` or `FLAG_REGISTER_SLOT`. The same handler can generate a factory/initCode artifact, a Type-1 `addOwnerBytes` signature, and the Type-2 user transaction. Rotation UI occurs before `pick_sign_pages`; signatures are produced later.
- **Prerequisites:** One lifecycle flag set and a Type-2 call classified as forced-blind eligible.
- **Mechanism:** A request-local forced capability designed for one raw transaction can coexist with deployment or owner-rotation effects and multiple signing artifacts. The proposed forced transcript does not cover the initCode digest, added owner material or Type-1 digest.
- **Consequence:** “Single request” can be mistaken for “single signing artifact,” expanding authority and ceremony composition beyond the reviewed scope.
- **Correction:** Forced blind is available only when:
  - `include_init_code == false`;
  - `register_slot == false`;
  - the handler will emit exactly one steady-state Type-2 signature.

  Any lifecycle mode is fatal for the forced tier. Future lifecycle support requires a separate design and review.
- **Stage impact:** Architecture blocker; mandatory I/M/P route tests.
- **Owner decision:** None for PQ1; expansion is deferred.
- **Evidence class:** Source-only.
- **Counterpart response:** Pending the bounded post-freeze counterpart step.

No other new `XB-*` finding is raised.

## 10. Minimum revised closed architecture

### 10.1 Typed states

```rust
enum RequestMode {
    SingleSteadyType2,
    Fatal(FatalModeReason),
}

enum MetadataEvidence<'a> {
    Absent,
    Verified(VerifiedDescriptor<'a>),
    InvalidBundle,
    RootMismatch,
    BindingMismatch,
    FatalEvidenceFault(EvidenceFault),
}

enum VerifiedRenderFailure {
    Unsupported(UnsupportedReason),
    Integrity(IntegrityReason),
    Resource(ResourceReason),
}

enum DispatchOutcome {
    Clear(Pages),
    GenericUnknown(Pages),
    ForcedCandidate(ForcedReason),
    Fatal(FatalReason),
}

enum ForcedReason {
    FilterPositiveDescriptorAbsent,
    VerifiedUnsupported(UnsupportedReason),
}
```

Requirements:

- Closed enums; no wildcard arm at a security decision.
- No permissive `From`, default-to-eligible conversion or invalid-discriminant recovery.
- `Fatal` is the default representation.
- `ForcedReason` is non-`Copy`, private to the single steady-state handler and consumed once.
- A/B/CFI disagreement always constructs `Fatal`.
- Failed metadata bytes are not retained in `ForcedReason` or passed to rendering.

### 10.2 Eligibility matrix

| Condition | Outcome |
|---|---|
| Strict framing/pointer/mode failure | `Fatal` |
| Batch, off-chain or lifecycle mode | `Fatal` |
| Filter-negative tuple | Existing generic ladder; never forced |
| Filter-positive + verified/bound + complete render | `Clear` |
| Filter-positive + clean descriptor absence | `ForcedCandidate(FilterPositiveDescriptorAbsent)` |
| Filter-positive + invalid/bad/root-mismatched/misbound proof | `Fatal` under Partner B recommendation |
| Verified descriptor + explicitly enumerated expected unsupported capability | `ForcedCandidate(VerifiedUnsupported(...))`, only after owner amendment |
| `Reject`, no-visible-fields, ABI mismatch, trailing/padding error, nested integrity failure | `Fatal` |
| `PageBudget`, numeric width, stack/resource or mandatory-page failure | `Fatal` |
| CFI/FI disagreement, skipped proof evidence, corrupt outcome | `Fatal` |
| Unknown future reason | `Fatal` |

A broader bad/misbound policy must not be inserted into this matrix without a new owner decision and review.

### 10.3 Routing rule

`ForcedCandidate` returns directly to the single handler. It cannot reach:

- ERC-20 known/unknown;
- typed-call;
- selector-name fallback;
- existing generic blind renderer;
- Safe/CoW inner renderers;
- batch member or summary paths;
- off-chain/EIP-712 paths.

## 11. Exact forced transcript schema

The forced transcript is built from one frozen canonical Type-2 struct—the same values used to construct the final signing digest. It performs no ABI, metadata, name or resolver parsing.

All 32-byte words use fixed big-endian lowercase hexadecimal, 64 characters over four 16-column rows. No rounding, truncation or overflow marker is permitted.

| Page(s) | Required content |
|---|---|
| 0 | `! FORCED BLIND` / `UNVERIFIED CALL` / drain warning / continue |
| 1 | Account index, slot owner index, full derived signer address |
| 2 | Full raw target address |
| 3 | Exact numeric chain ID; `EntryPoint v0.6 PINNED` |
| 4 | `Single Type-2`; selector in hex; exact calldata length |
| 5–6 | `Value raw`; full 32-byte value |
| 7–8 | `Nonce raw`; full 32-byte nonce |
| 9–10 | `MaxFee raw`; full `maxFeePerGas` |
| 11–12 | `MaxPriority raw`; full `maxPriorityFeePerGas` |
| 13–14 | `CallGas raw`; full `callGasLimit` |
| 15–16 | `VerifyGas raw`; full `verificationGasLimit` |
| 17–18 | `PreVerGas raw`; full `preVerificationGas` |
| 19–20 | Paymaster state plus full `paymasterAndData` SHA-256 digest, including the empty digest when absent |
| 21–22 | Complete ERC-8213 inner-calldata digest |
| 23–24 | Complete final Type-2 SPHINCS signing digest |
| 25 | `FORCED BLIND` / `UNVERIFIED` / `L=Cancel` / `R=Sign` |

Additional rules:

- `entry_point != ENTRY_POINT_V06` is fatal.
- `include_init_code` or `register_slot` is fatal.
- Calldata shorter than four bytes is fatal for this filter-positive function-call tier.
- Contract creation is fatal.
- No descriptor text, selector name, ENS/address resolver, token symbol or host string enters the transcript.
- No optional friendly decimal page is included in PQ1. Adding one later must not replace a raw page.
- A nonempty paymaster without its complete digest is fatal; a presence-only page is insufficient.
- Every page is part of the scroll-to-end gate.
- The final page repeats the forced/unverified trust state.

This fixed schema uses 26 of 31 available pages and leaves bounded headroom without sacrificing exactness.

## 12. Authorization receipt sequence

1. Snapshot and strictly parse the request once.
2. FI-harden flags, EntryPoint, exclusion routing and metadata evidence.
3. Reconstruct the exact steady-state Type-2 calldata and final signing digest before user interaction.
4. Build and prove the complete final transcript before showing the severe warning.
5. Charge/check the secure forced-prompt abuse budget.
6. Show at least two static warning pages from read-only storage; require scroll-to-end and physical long confirmation.
7. Publish `WarningReceipt { stage, request_digest }` into a distinct caller-owned fail-initialized slot and CFI step.
8. Confirm the already-built raw transcript.
9. Publish `FinalReceipt { stage, request_digest }` into a separate fail-initialized slot and CFI step.
10. Recompute/recheck the request digest and require:
    - eligible-reason receipt;
    - warning receipt;
    - final receipt;
    - exact CFI sequence;
    - no cancel/idle/reset/error;
    - same request digest in all receipts.
11. Consume the non-`Copy` permit and sign exactly once.
12. On every return path, drop/invalidate the permit and both receipts.

Distinct warning/final constants are preferred. An equivalent design is acceptable only if stage identity is independently encoded in each caller-owned receipt and covered by the CFI transcript.

## 13. Resource and gas ownership model

### Pages

- Allocate exactly one `Pages` value for the final transcript.
- Warning pages are static constant `Page` slices in flash, not another `Pages`.
- Build the final transcript before warning, so deterministic page/numeric failure cannot habituate the user and then refuse.
- Do not rely on lexical `drop` for stack reuse.
- No `Pages` value is stored in persistent/global state.

### Gas

- Remove ERC-7730’s gas-triple page emission.
- The handler is the only gas-page producer for every confirmation set.
- Before insertion, independent scans require zero exact canonical matches.
- After insertion, independent scans require exactly one exact match globally.
- Expected bytes are independently recomputed from the signed gas words.
- Near-shaped conflicts, more than one match, full buffer, width failure or CFI disagreement are fatal.
- Apply the invariant separately to every batch-member/final confirmation still supported outside the forced tier.
- Provenance and fixed position are not security requirements; deterministic position remains a UX/test requirement.

## 14. Exhaustive fatal exclusions

The revised architecture must explicitly enumerate at least:

- malformed outer length, pointer, trailer, cursor, padding or trailing bytes;
- unsupported wire version;
- output pointer/revalidation failure;
- missing target or calldata shorter than selector width;
- contract creation;
- invalid, root-mismatched or context-misbound proof;
- any FI/CFI disagreement;
- `RenderErr::Reject`;
- `RenderErr::PageBudget`;
- all-visible/completeness failure;
- exact-value or page-width failure;
- Safe `approveHash`;
- Safe `execTransaction`, including selector-only and short malformed forms;
- verified or claimed Safe context;
- MultiSend and every delegatecall;
- CoW `setPreSignature`, direct or Safe-wrapped;
- batch, including a one-element batch;
- all off-chain/EIP-712 commands;
- deployment/initCode;
- slot registration/rotation;
- forced-prompt budget exhaustion;
- feature disabled;
- unknown enum/discriminant/reason;
- stack/resource preflight failure.

## 15. Falsifiable acceptance evidence

### Architecture evidence required before approving a revised packet

- Closed state-transition and eligibility tables matching §10.
- Explicit owner-approved eligible reasons.
- Fixed transcript byte layout and page budget.
- Explicit prompt-abuse policy.
- Owner-document redlines.
- Explicit exclusion of lifecycle modes.
- No unresolved policy contradiction.

### Implementation/merge evidence

- Exhaustive table tests for every evidence, render, mode and fatal enum variant.
- Mutation control proving default/future variants remain fatal.
- Tests showing binding gate A/B failure cannot become absence.
- Bloom false-positive vector above.
- Exact-member/filter-negative controls.
- Invalid/root-mismatch/misbound proof tests.
- Short Safe `execTransaction`, selector-only Safe, Safe/CoW/MultiSend/delegatecall tests.
- One-element batch and off-chain rejection tests.
- Deploy/rotation flag rejection tests.
- Every-signed-field flip tests over:
  - signer/account;
  - EntryPoint;
  - chain;
  - nonce;
  - target;
  - value;
  - calldata;
  - all gas fields;
  - both fee fields;
  - paymaster digest.
- Full transcript compared against the final Type-2 signing digest.
- Gas zero/one/two/near-match/full-buffer/permutation tests.
- Complete handler-glue differential including gas.
- Warning cancel, final cancel, idle, replay, out-of-order and stale-receipt tests.
- Interactive non-auto-confirm test configuration.
- Prompt-budget exhaustion/reset tests.
- Feature/profile differential proving no dev/test auto-confirm in production-shaped builds.
- Target release build, stack map and exception-headroom receipt.

### Physical/production evidence

- Post-LTO Thumb disassembly and ABI spill review.
- Instruction-skip/stuck-at sweeps of classifier, receipts, gas proof and release gate.
- Hardware stack high-water/MSPLIM evidence.
- NV3007 clipping, stale-row and scroll-to-end capture.
- Real-button two-ceremony evidence.
- Warning comprehension/habituation study.
- Production configuration/prodtest parity.
- ERC-8176 provenance threshold and verifier closure.
- Reproducible release artifact, signing/custody and rollback closure.

Source tests do not replace these target/physical gates.

## 16. Required owner decisions and document amendments

### Decisions

1. Authorize or reject a separate forced-blind trust tier.
2. Define membership as filter-positive or require exact authenticated membership.
3. Approve the exact eligible reasons.
4. Decide whether bad, root-mismatched or misbound metadata remains fatal. Partner B recommends fatal.
5. Approve `VerifiedUnsupported` reasons, if any.
6. Select the forced-prompt abuse budget/cooldown/lock behavior.
7. Approve canonical EntryPoint pinning.
8. Accept full paymaster-digest display or make paymaster-bearing forced requests fatal.
9. Confirm deployment and rotation remain excluded.
10. Decide whether the feature is compile-time gated and default-off until production approval.

### Amendments

At minimum:

- `CLAUDE.md` trusted-display invariant and scope statement.
- `docs/companion/companion-erc7730-implementation-guide.md` mental model, failure matrix and root/version behavior.
- `docs/companion/erc7730-integration.md`.
- `docs/erc7730-root-rotation-and-update-policy.md` rule 3 if any root-mismatch override is approved.
- Clear-signing playbook CS2; CS9 should clarify that the raw renderer does not decode.
- `docs/STATUS.md`.
- The frozen architecture plan and `docs/work-todo.md`.
- Production feature/configuration documentation.
- ERC-8176 status/readiness documentation for `PB-BR-010`.

Required owner language:

> Forced blind is not clear signing. A filter-positive call never silently reaches the ordinary ERC-20, typed-call, or generic blind ladder. It either clear-signs, fatal-refuses, or—only for explicitly enumerated single steady-state Type-2 reasons—enters a separate on-device forced-blind ceremony. The default and rollback remain refusal.

## 17. Revised stage-specific verdicts

| Stage | Verdict |
|---|---|
| Frozen architecture | **NO-GO** |
| Revised design direction in this report | **Conditionally viable**, but only after owner decisions, exact redlines, and review of the revised artifact |
| Implementation | **UNAVAILABLE / not authorized** |
| Merge | **NO-GO / unavailable** |
| Production | **NO-GO / unavailable** |
| Review pairing process | Two-backend requirement accepted as satisfied; `PB-PROC-013` cured for this pair |
| Irreversible actions | Not authorized |

## 18. Honest residual

- This cross pass was source/document analysis plus a reproduced Bloom calculation and identity/hash checks.
- No build, test suite, QEMU, fuzz, Kani, Miri or differential harness was executed.
- No optimized ELF, stack map, disassembly, FI campaign or hardware run was executed.
- No physical UI, usability or warning-habituation evidence exists.
- No live EAS query or provenance snapshot was executed.
- No implementation exists for the proposed tier.
- Partner A’s cross result remains unknown.
- `XB-001` awaits its single bounded counterpart response.
- Current short-Safe fallthrough was assessed only as intersecting architecture evidence; this report does not replace the project’s canonical vulnerability/findings workflow.
- Reading current `state.rs` shows no existing forced permission, but cannot prove a future implementation’s cleanup.
- No merge, release, signing, flashing, publication or external-state change occurred.

## 19. Final target identity and drift result

Final output:

```text
9647b79374d5e2e10445254492308101b8be708b
 M docs/erc7730-implementation-review-2026-07.md
 M docs/work-todo.md
 M docs/erc7730-implementation-review-2026-07.md
 M docs/work-todo.md
b8e270747a5c16eafde0b74fe94f34be9ab4504d91559234fb2a1ca056d59c25  -
4b34ae5f1459d2d6dbfe21a1a9019235b74344cb0440aac76551efe6823a884c  /tmp/pq1-erc7730-partner-a-first-pass-v5.md
bcb8a52e7dba0ecf49e651467615a9c47da2a2a0756563d4362252dde5f1110f  /tmp/pq1-erc7730-partner-b-first-pass-v4.md
```

Untracked and ignored-file inventories remained empty. The duplicate modification lines are the two expected files printed by two status formats.

**Final drift result: MATCH. Target and both frozen first-pass reports remained unchanged.**