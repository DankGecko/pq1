# PQ1 ERC-7730 Phase-B architecture review packet

You are one of the two exact independent adversarial review partners required by
`docs/planning-and-review-workflow.md`. This is an ARCHITECTURE-stage review,
not an implementation, merge, or production-shipment review. Attempt to refute
the plan. Do not reward it for sounding cautious.

## Immutable target

- Worktree: `/tmp/pq1-erc7730-arch-review-9647b79`
- Base HEAD: `9647b79374d5e2e10445254492308101b8be708b`
- Expected dirty files only:
  `docs/erc7730-implementation-review-2026-07.md` and `docs/work-todo.md`
- Expected target diff SHA-256:
  `b8e270747a5c16eafde0b74fe94f34be9ab4504d91559234fb2a1ca056d59c25`
- Expected untracked and ignored inventories: empty.

At the beginning and immediately before reporting, verify HEAD, ordinary
status, untracked/ignored inventory, and the binary diff digest. If they differ,
stop and report TARGET DRIFT. Do not edit the target, its index, hardware, or
external state. Non-destructive source inspection is expected. If executable
evidence is useful, build only with explicit output paths outside the target or
use an isolated scratch copy and report it separately.

## Required reading and authority

Read these completely before verdict:

1. `AGENTS.md`, `CLAUDE.md`, `docs/STATUS.md`, and
   `docs/planning-and-review-workflow.md`.
2. The dated `PQ1 productization plan freeze (2026-07-16)` in
   `docs/erc7730-implementation-review-2026-07.md` and the matching
   `PQ1 ERC-7730 productization campaign` in `docs/work-todo.md`.
3. `docs/companion/companion-erc7730-implementation-guide.md`,
   `docs/companion/erc7730-integration.md`,
   `docs/erc7730-root-rotation-and-update-policy.md`, and
   `docs/erc8176-attestation-status.md`.
4. Every applicable playbook below, including its complete Part A attack
   catalogue, Part C prompt and cadence/honest-boundary requirements:
   - `docs/security/adversarial-review/clear-signing-adversarial-review.md`
   - `docs/security/adversarial-review/usb-companion-adversarial-review.md`
   - `docs/security/adversarial-review/trusted-ui-adversarial-review.md`
   - `docs/security/adversarial-review/sca-fi-adversarial-review.md`
   - `docs/security/adversarial-review/lifecycle-persistent-state-adversarial-review.md`
   - `docs/security/adversarial-review/secure-runtime-resource-adversarial-review.md`
   - `docs/security/adversarial-review/production-configuration-prodtest-adversarial-review.md`
   - `docs/security/adversarial-review/build-release-provenance-adversarial-review.md`
5. The current implementation and tests needed to trace the proposal, at least:
   - `secure/src/tx/display/{dispatch,blind_sign,userop_gas_lane}.rs`
   - `pqsigner-erc7730/src/display/render/mod.rs`
   - `secure/src/nsc/{cmd_sign_userop,cmd_sign_userop_batch,state}.rs`
   - `secure/src/ui/confirm.rs`, `proto/src/lib.rs`, and relevant
     `secure/src/display_under_test/` regressions.

Prior reports and the plan are untrusted inputs. The reference Ambire and
upstream-registry clones are comparison material only, not PQSigner authority.

## Objective under review

The user wants the option to blind-sign when ERC-7730 clear signing is
unavailable, after a warning, while retaining today's refusal as the default.
The selected PQ1 candidate is a device-local, one-transaction escape hatch:

1. A known tuple with missing/bad/mis-bound ERC-7730 proof, or a verified
   descriptor that cannot completely render, produces a typed blind-eligible
   reason instead of generic fallback.
2. The device presents a separate severe-warning interstitial. Scroll-to-end,
   long-press confirmation and an FI sentinel are required.
3. Only then is a distinct forced-blind transcript built. It ignores all failed
   descriptor/selector-name text and shows exact raw signed context plus the
   complete ERC-8213 calldata digest.
4. The existing final signing confirmation and its independent sentinel remain
   mandatory. Permission is local to that handler call and dies on every return.
5. PQ1 scope is single UserOp only. Batch, EIP-712/off-chain, Safe approveHash,
   CoW setPreSignature, malformed Safe/MultiSend, delegatecall, malformed
   envelope/pointers and mandatory-page overflow remain fatal.

The same plan proposes idempotent gas-page enforcement: independently accept a
pre-existing byte-exact canonical gas-triple page, or insert and prove one when
absent. It also records catalogue-doc drift, upstream fixture/provenance/status
work and bounded later coverage items.

## Mandatory adversarial questions

Walk every relevant CS1-CS10, UC1-UC10/map entry, UI1-UI8, FI1-FI10,
LC1-LC10, RT1-RT11, PC1-PC12 and BR1-BR12 mode. At minimum answer:

1. Is this requirement compatible with an honest amendable trusted-display
   contract, or does it destroy a property PQ1 must retain? State the exact
   redline amendments needed if architecture may proceed.
2. Is per-request on-device consent really the smallest safe design? Try to
   falsify the claim that a session toggle adds risk without material benefit.
   Separately attack the rejected persistent and host-controlled alternatives.
3. Define the only eligible failure classes. Should malformed, missing,
   mis-bound, wrong-chain/target, Bloom-positive, `Reject`, `NoFormat`, and
   `PageBudget` cases all be treated alike? Identify attacker-induced errors,
   internal invariant failures and resource failures that must stay fatal.
4. Trace every single and batch call path. Can any typed outcome, discriminant
   fault, `?`/`Err` conversion, retry, re-entry or stale local accidentally
   reach ERC-20, typed-call, selector-name or ordinary blind fallback?
5. Can a hostile companion turn every known call into repeated warning prompts
   and normalize the danger UI? Is warning fatigue a blocker, a bounded
   residual, or mitigable without a host trust assumption?
6. Prove or refute that the two consent ceremonies are independent under one
   skipped branch/stuck-at value/register reuse. Require a fatal default and
   concrete optimized-ELF/on-silicon evidence boundaries.
7. Specify the minimum forced-blind transcript. Does the existing full
   handler-appended ERC-8213 digest make `td-2` merely duplicate UI, or must
   `td-2` still block the feature? Check target/value/chain/signer/gas/selector,
   fees, calldata length, full hash and trust-tier copy.
8. Attack page lifetime, `MAX_PAGES`, stack high-water, warning-buffer drop,
   batch summary and UI clipping/scroll semantics. Can refusal or a required
   page be lost under pressure?
9. Review gas-page idempotence as an FI proof, not only deduplication. Is
   accepting an exact match anywhere in `Pages` sound, or must provenance,
   uniqueness, position, count, pre-state or a receipt be bound? Construct a
   near-match/duplicate/full-buffer/skipped-call counterexample if possible.
10. Decide whether single-only support is coherent or creates single/batch
    policy confusion exploitable by request reshaping. State the safe expansion
    gate.
11. Attack the catalogue-doc drift test, upstream-fixture strategy,
    provenance/status split, native-currency list, NFT identity,
    interpolated-intent, nested calldata and multi-tail ordering. Identify
    duplicated owners, incorrect current-state claims, premature scope, or a
    higher-value PQ1 prerequisite the plan missed.
12. Verify that ERC-8176, rollback, wire, release, prodtest, hardware UI/FI and
    irreversible-action gates remain honest and are not weakened by wording.

## Discovery and evidence rules

The clear-signing and USB/UI/FI playbooks require at least three independent
discovery reviewers per scope across two backends. Use at least three genuinely
separate discovery lanes/subagents for this architecture (recommended split:
state/error taxonomy; trusted-UI/FI; hostile companion/resources/provenance).
You, the named partner, must personally inspect and adjudicate their evidence.
Quorum does not assign disposition and minority candidates remain visible.

For each finding give stable ID, severity, exact path plus symbol/string,
mechanism, prerequisites, consequence, falsifiable evidence or counterexample,
required correction, and whether it blocks architecture. Separate executed
evidence from source reasoning. No PoC means label it suspicion/unverified.

## Required first-pass output

Produce a raw external partner report, not a canonical findings file. Include:

- initial and final identity/drift receipts;
- actual observed reviewer configuration and session/runtime receipt fields
  available to you (the coordinator will independently freeze launcher logs;
  self-report alone is not runtime attestation);
- distinct verdicts for architecture, implementation, merge and production
  shipment (`UNAVAILABLE` where not reviewed);
- a KEEP / SIMPLIFY / FIX NOW / DEFER / DROP / OPEN RESEARCH classification;
- every finding and unresolved contradiction;
- the strongest attacks attempted that failed;
- exactly what was not inspected or executed;
- an honest residual and an explicit recommendation: GO or NO-GO for the
  Phase-B owner stage decision on this architecture only.

Do not see or infer the other partner's findings before both first-pass reports
are frozen. Do not create or edit a canonical findings record. Symmetric
cross-adjudication happens later.
