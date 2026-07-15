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
   and apply every existing playbook whose surface intersects the task. Do not
   substitute one matching playbook for another additive lens; record a
   coverage gap if a required lens has no playbook. Unrelated playbooks need
   not be run.

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
cross-adjudication procedure, convergence rules, and irreversible-action
planning gates. Do not restate or weaken those rules here. Before starting a
security-sensitive implementation or review, identify and follow the applicable
workflow stage and any stricter task-specific gate.

If this file conflicts with a more specific owner document, stop and surface
the conflict rather than choosing silently.
