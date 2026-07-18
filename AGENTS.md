# PQSigner OS agent entry point

This file is a router, not a duplicate project specification.

Before non-trivial work:

1. Read [`CLAUDE.md`](CLAUDE.md) for the project invariants, security contract,
   platform constraints, and code conventions.
2. Read [`docs/STATUS.md`](docs/STATUS.md) for the current evidence and ship
   frontier; follow its owner links rather than trusting duplicated status.
3. Follow
   [`docs/planning-and-review-workflow.md`](docs/planning-and-review-workflow.md)
   for planning, scope changes, convergence, and adversarial review.
4. For security-sensitive work, use the existing playbook index at
   [`docs/security/adversarial-review/README.md`](docs/security/adversarial-review/README.md)
   and cover every existing playbook whose surface intersects the task under
   the workflow's combined-review rules. Do not substitute one matching
   playbook for another additive lens; record a coverage gap if a required lens
   has no playbook. Unrelated playbooks need not be run.

## Focus and review-cadence routing

Before implementation, name one active product surface, the current workflow
phase, the bounded slice set, and the next review boundary. Treat an explicit
user focus instruction as a scope cap: bank unrelated discoveries in the
appropriate owner TODO and do not let review/process cleanup displace the
active product work unless it is a concrete blocker for that work.

The workflow linked above solely owns phase-boundary review batching, batch
bounds, per-slice evidence, and early-stop triggers. Follow those rules rather
than initiating a full adversarial pair by habit after every slice. Do not start
a second product surface before the active phase reaches its recorded stopping
point.

Once Phase D starts, enter the workflow's **closure mode**. Treat its recorded
completion checklist as closed: run the stage-relevant mandatory gates, freeze,
review, remediate stage-blocking findings, re-freeze/re-review when required,
and land. Do not add optional reviewers, broader assurance campaigns, process
rewrites, documentation polish, or unrelated hardening unless the user or a
task-specific owner gate required it before the freeze, or a concrete workflow
expansion trigger makes it a blocker. If closure stalls, report the exact
blockers and shortest compliant path before starting more work.

Multiple intersecting playbooks do not by themselves create multiple review
campaigns or phase boundaries. Use them as mandatory coverage floors within the
single review of the active surface. Reviewers must still derive threats from
the source and invariants independently, seek failures outside the catalogs,
and treat playbook status claims as hypotheses rather than accepted facts.
Non-blocking observations are banked through the workflow; they do not keep the
active phase open merely because they are security-adjacent.

## Security-review surface routing

Five cross-cutting playbooks complement the subsystem-specific and formal-
verification playbooks:

- [lifecycle, provisioning, persistent state, recovery, and RMA](docs/security/adversarial-review/lifecycle-persistent-state-adversarial-review.md)
- [entropy, key generation, derivation, nonce, and key lifecycle](docs/security/adversarial-review/entropy-key-lifecycle-adversarial-review.md)
- [secure runtime, resources, exceptions, concurrency, and unsafe code](docs/security/adversarial-review/secure-runtime-resource-adversarial-review.md)
- [production configuration, prodtest, and assurance fidelity](docs/security/adversarial-review/production-configuration-prodtest-adversarial-review.md)
- [build, release, provenance, signing-key custody, and distribution](docs/security/adversarial-review/build-release-provenance-adversarial-review.md)

These lenses are additive to every intersecting subsystem playbook. Return
review evidence under the indexed findings workflow; a source-only pass must
retain the playbook's honest residual and must not imply hardware, merge,
shipment, or irreversible-action authority.

Task-specific normative specifications, authorization boundaries, and explicit
owner decisions take precedence over the generic workflow and may require
additional reviewers or evidence.

The workflow is the sole owner of the project's YAGNI/exploration balance,
scope-expansion triggers, evidence ladder, exact dual-review runtime
configurations (model/context, orchestration profile, and reasoning effort),
cross-adjudication procedure, review-batching rules, convergence rules, and
irreversible-action planning gates. Do not restate or weaken those rules here.
Before starting a security-sensitive implementation or review, identify and
follow the applicable workflow stage and any stricter task-specific gate.

If this file conflicts with a more specific owner document, stop and surface
the conflict rather than choosing silently.
