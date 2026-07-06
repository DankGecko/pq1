# `contracts/verification/docs/` — proof-artifact documentation

**These docs describe the verification *artifacts* in this tree** (`../lean/`,
`../halmos/`, `../kontrol/`, `../proverif/`, `../tamarin/`, `../cryptoverif/`,
`../extracted/`) and are co-located with them on purpose — Lean docstrings, the
`Makefile`, and `../scripts/` reference these files by relative path, so they
stay here next to the proofs.

> **Naming note (read this if you landed here by mistake).** There are **two**
> "verification" doc homes, with a clean split:
> - **`contracts/verification/docs/` (here)** — *proof-artifact* docs: what is
>   claimable, the axiom/TCB inventory, per-proof audits, open obligations.
> - **[`/docs/verification/`](../../../docs/verification/)** — *program /
>   strategy / research* docs: the tooling SOTA survey, the soundness roadmap,
>   research notes, extraction handoffs. Read those for "where is FV going."

## Source of truth

- **[`THE_CLAIM.md`](./THE_CLAIM.md)** — the SSOT for what may and may not be
  claimed. Cite this, not any other doc, for the claimable boundary.
- **[`TRUST_ASSUMPTIONS.md`](./TRUST_ASSUMPTIONS.md)** + **[`AXIOMS.md`](./AXIOMS.md)**
  + **[`AXIOM_STATUS.json`](./AXIOM_STATUS.json)** — the TCB / axiom inventory
  (A1–A6), per-axiom location, type, discharge, elimination path.

## Map of the rest

- **Faithfulness / honesty:** [`FAITHFULNESS_AUDIT_2026-06-14.md`](./FAITHFULNESS_AUDIT_2026-06-14.md)
  (mutation testing + coverage matrix), [`EUF_CMA_INCONSISTENCY.md`](./EUF_CMA_INCONSISTENCY.md)
  (the 2026-06-14 soundness self-catch), [`two-specs-faithfulness.md`](./two-specs-faithfulness.md),
  [`FV_VALUE_AND_GAPS.md`](./FV_VALUE_AND_GAPS.md) (empirical "has FV paid for
  itself" calibration — defers to `THE_CLAIM.md`).
- **A3.1 verifier equivalence:** [`A3_1_CLOSURE_PATH.md`](./A3_1_CLOSURE_PATH.md),
  [`A3_1_VERIFIER_GAP.md`](./A3_1_VERIFIER_GAP.md),
  [`findings/A3_1_ADVERSARIAL_REVIEW_2026-06-18.md`](./findings/A3_1_ADVERSARIAL_REVIEW_2026-06-18.md).
- **Bytecode discharge:** [`PINNED_CODEHASHES.md`](./PINNED_CODEHASHES.md),
  [`DEPLOYED_BYTECODE_PIN_CAVEAT.md`](./DEPLOYED_BYTECODE_PIN_CAVEAT.md),
  [`MISSING_FOR_FULL_BYTECODE_PROOF.md`](./MISSING_FOR_FULL_BYTECODE_PROOF.md),
  [`KONTROL_SCOPING.md`](./KONTROL_SCOPING.md).
- **Remaining work:** [`OPEN_PROOF_OBLIGATIONS.md`](./OPEN_PROOF_OBLIGATIONS.md),
  [`DISCHARGE_PLAN.md`](./DISCHARGE_PLAN.md), [`BLOCKERS.md`](./BLOCKERS.md),
  [`handoff-verify-signs-completeness.md`](./handoff-verify-signs-completeness.md).
- **Overview:** [`PROOF_MAP.md`](./PROOF_MAP.md),
  [`ASSURANCE_CASE.md`](./ASSURANCE_CASE.md),
  [`THREE_CLAIMS_PROOF.md`](./THREE_CLAIMS_PROOF.md), and the parent
  [`../README.md`](../README.md) (status + how the discharge runs).
