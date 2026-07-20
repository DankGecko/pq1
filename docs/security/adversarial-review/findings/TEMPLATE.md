---
report_kind: canonical-post-cross-adjudication
surface: <clear-signing | trustzone-gateway | secure-element | sca-fi | firmware-update-secure-boot | usb-companion | offchain-signing | onchain-contracts | trusted-ui | silicon-lockdown | lifecycle-persistent-state | entropy-key-lifecycle | secure-runtime-resource | production-configuration-prodtest | build-release-provenance | fv | multi>
run_date: YYYY-MM-DD
target_identity: <commit/tree/spec digest and hardware identity, as applicable>
cross_adjudication_sha256: <SHA-256 of the completed CROSS_ADJUDICATION_TEMPLATE report>
scope: <the specific claims / files / modes reviewed>
status: in-review   # post-cross items start REVIEWED; see findings/README.md
---

> **NOTE (2026-07-20):** This canonical-post-cross-adjudication template is
> **historical / specially-authorized-only** under the current workflow.
> `docs/planning-and-review-workflow.md` §7/§7b now prescribes ONE
> simultaneous three-reviewer wave (gpt-5.6-sol `ultra` / Opus 4.8 `xhigh` /
> Kimi K3) with coordinator triage and **no** Partner-A/Partner-B
> cross-adjudication step; triaged findings are tracked as GitHub issues.
> Use this template only when a task-specific owner gate explicitly requires
> the old exact-pair canonical-record lifecycle. The template body below is
> frozen and left unchanged.

# Canonical adversarial-review findings — <surface> — YYYY-MM-DD

> This is the post-cross-adjudication repository record. Do not use it as a
> raw first-pass report or as the cross-adjudication worksheet. Those artifacts
> freeze outside the reviewed target first; cite their exact digests below.

## Evidence inputs

- Partner A first pass: `<path/receipt>` — SHA-256 `<digest>`
- Partner B first pass: `<path/receipt>` — SHA-256 `<digest>`
- Partner A cross pass: `<path/receipt>` — SHA-256 `<digest>`
- Partner B cross pass: `<path/receipt>` — SHA-256 `<digest>`
- Cross-adjudication matrix: `<path/receipt>` — SHA-256 `<digest>`
- Execution and identity receipts: `<exact commands/logs/digests>`

## Summary

<One-line stage recommendation and count by CONFIRMED / REFUTED / NARROWED /
UNRESOLVED. Preserve separate Partner-A and Partner-B recommendations when they
differ. State whether checks executed or the pass was source-only.>

## Findings

<!-- One block per canonical item. Stable IDs and raw origin IDs must trace back
     to the cross-adjudication matrix. Delete this comment/example when filing. -->

### F1 — <short title>
- **Origin IDs:** `<raw namespace/origin IDs from both first passes>`
- **Status:** 🔬 REVIEWED   <!-- post-cross default; then ✅ FIXED · ☑️ ACCEPTED · 🚫 INVALID · ⏸ DEFERRED -->
- **Cross disposition:** CONFIRMED | REFUTED | NARROWED | UNRESOLVED
- **Cross evidence:** `<matrix row + both cross-report digests; no majority vote>`
- **Mode / severity / stage impact:** <catalog id> · <INFO | LOW | MED | HIGH | CRITICAL> · <impact>
- **Location / stable anchor:** `path/to/file.rs:line` + <unique symbol/string/policy>
- **Claim and mechanism:** <what was claimed, the violated invariant, and the concrete defect/gap>
- **Prerequisites:** <attacker capability, lifecycle/configuration/state, and required prior failures>
- **Consequence:** <confidentiality/integrity/availability/claim impact and affected asset>
- **Introduced here?:** <YES / NO / UNKNOWN — evidence and first known snapshot>
- **Failure-path trace:** <input/authority crossing through states, branches, writes, reset/resource/fallback edges to the bad outcome>
- **PoC / refutation:** <falsifiable artifact and result; preserve contradictory evidence>
- **Evidence provenance:** <what actually ran vs what was inspected; exact cfg/artifact/log digest>
- **Classification:** KEEP | SIMPLIFY | FIX NOW | DEFER | DROP | OPEN RESEARCH
- **Required correction or residual:** <minimal falsifiable correction, or the exact residual if narrowed/unresolved>
- **Resolution:** <FILLED WHEN HANDLED — action + commit/date, or invalid/deferred tracking. ACCEPTED additionally requires an owner-only record naming owner, date, exact finding, target and report digests, accepted consequence, and scope. Reviewer agreement is not risk acceptance.>

<!-- ### F2 — … -->

## Explicit disagreements and unresolved defeaters

<List every surviving disagreement, unexecuted modality, and evidence gap. Do
not collapse disagreement into a consensus severity or silently omit it.>

## Honest residual

1. **What both reviewers tried to break and could not** — strongest failed PoC per claim.
2. **What neither reviewer established** — unreviewed modes/files/hardware and assumptions.
3. **Provenance** — exactly what executed, what was source-only, and where evidence lives.
4. **Authority boundary** — recommendations are not merge/ship/risk-acceptance authority.
