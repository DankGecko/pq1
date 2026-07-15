---
report_kind: symmetric-cross-adjudication
surface: <surface>
workflow_stage: <architecture | implementation | validation | release>
run_date: YYYY-MM-DD
target_identity: <commit/tree/spec digest and hardware identity, as applicable>
partner_a_first_sha256: <digest>
partner_b_first_sha256: <digest>
partner_a_cross_sha256: <digest>
partner_b_cross_sha256: <digest>
status: open
---

# Symmetric cross-adjudication — <surface> — YYYY-MM-DD

> Complete this only after both independent first-pass reports and both
> symmetric cross-review reports are frozen. This worksheet preserves evidence
> and disagreement; it does not vote, average severity, accept risk, or grant
> implementation/merge/shipment authority.

## Frozen inputs and runtime receipts

| Artifact | Partner/model/effort | Path or immutable receipt | SHA-256 |
|---|---|---|---|
| First pass A | <exact identity> | `<external path>` | `<digest>` |
| First pass B | <exact identity> | `<external path>` | `<digest>` |
| A reviews B | <exact identity> | `<external path>` | `<digest>` |
| B reviews A | <exact identity> | `<external path>` | `<digest>` |
| Lossless raw union, if used | n/a | `<external path>` | `<digest>` |

Record commands, tool versions, effort levels, exit status, timeouts, and
whether each pass executed tests or inspected evidence only. Preserve each
partner's honest residual verbatim or by immutable digest.

## Target identity and drift checks

- Initial target identity: `<HEAD/tree/spec/working-diff/manifest digests>`
- Initial repository and hardware state: `<dirty/index/hardware identity>`
- Final target identity: `<same recipe after all four reports>`
- Drift result: MATCH | DRIFTED — `<details>`

## Complete disposition matrix

Every first-pass candidate and every new cross-pass candidate gets a stable row.
The only cross dispositions are `CONFIRMED`, `REFUTED`, `NARROWED`, and
`UNRESOLVED`. A disagreement stays `UNRESOLVED`; reviewer count, confidence,
or severity averaging cannot decide it.

| Stable ID / raw origin IDs | Source report + initial claim | Partner A cross result + evidence | Partner B cross result + evidence | Cross disposition | Required correction or precise residual | Stage impact |
|---|---|---|---|---|---|---|
| `<id / origins>` | `<digest + claim>` | `<result>` | `<result>` | `<one of four>` | `<minimal action/residual>` | `<blocker/recommendation>` |

## New findings raised during cross-review

<Add them to the matrix above with origin and evidence. Cross-review is not a
license to omit a late candidate or to reopen unrelated scope without the
workflow's scope-expansion trigger.>

## Explicit disagreements

<Quote or precisely summarize each disagreement. State what evidence would
resolve it and who, if anyone, has authority to make the needed owner decision.>

## Revised stage recommendations

- Partner A: `<recommendation, scope, blockers, honest residual>`
- Partner B: `<recommendation, scope, blockers, honest residual>`
- Coordinator summary: `<common ground plus preserved disagreement; no new vote>`

An owner decision, risk acceptance, irreversible action, implementation start,
merge, or shipment authorization must be recorded separately under the
applicable workflow/task-specific authority. It cannot be inferred here.

## Final evidence boundary

<What was not executed or established: hardware, production configuration,
dynamic stack, provenance, physical UI/FI, external state, and so on.>
