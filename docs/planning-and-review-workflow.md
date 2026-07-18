# Engineering planning and dual-review workflow

**Status:** active project process

**Owner:** this document

**Applies to:** non-trivial design, implementation, security, migration, and
hardware-facing work

This document defines how PQSigner work moves from an idea to a reviewed,
owner-authorized stage. It is intentionally shorter than a feature
specification: plans and review receipts point here instead of recreating the
process for every task.

Project invariants remain owned by [`../CLAUDE.md`](../CLAUDE.md). Current
security state remains routed through [`STATUS.md`](STATUS.md). Surface-specific
attack catalogs and finding formats remain owned by
[`security/adversarial-review/`](security/adversarial-review/README.md). This
document owns only planning, scope change, convergence, and the required
two-partner review protocol.

Task-specific specifications, explicit owner decisions, and surface playbooks
may impose stricter gates. They take precedence for their scope; this generic
workflow cannot weaken them or grant authority they withhold.

Preserved research candidates may contain the review choreography that was
current when they were frozen. Those embedded process clauses are historical
unless an explicit owner decision re-adopts them: this document controls the
current partner configuration, runtime receipts, withheld first passes,
symmetric cross-adjudication, and finding-status authority. This rule changes
no technical requirement inside the preserved candidate.

## 1. Operating principles

1. **Security and correctness outrank elegance, schedule, and line count.** A
   mechanism forced by a named invariant or demonstrated failure mode is not
   overengineering merely because it is complex.
2. **Explore freely; accept selectively.** Agents and reviewers may investigate
   broad alternatives, new threats, and stronger requirements. YAGNI governs
   what becomes an accepted requirement or implementation, not what a model is
   allowed to consider.
3. **Choose the smallest design that satisfies the evidence-backed
   requirements.** Optional hardening remains visible in
   [`work-todo.md`](work-todo.md); it does not silently accrete into the active
   plan.
4. **Prefer reversible evidence before irreversible action.** Source analysis,
   host models, fault-injection models, resource spikes, QEMU, and
   non-destructive silicon checks precede OTP, option-byte, lifecycle, or
   factory-state mutations.
5. **Claims stop at the evidence boundary.** A host model does not prove
   silicon behavior; a link receipt does not prove worst-case stack; a model
   review does not approve production shipment.
6. **Preserve research without making it authority by accident.** Superseded
   designs remain clearly labelled as historical or research inputs. The
   selected plan names its exact authoritative artifacts.
7. **Review recommendations belong to an exact snapshot and stage.**
   Architecture, implementation, merge, and production recommendations are
   separate. None is inherited by a changed digest, and none replaces the
   owner or authorized maintainer's stage-transition decision.
8. **Batch implementation review at explicit phase boundaries.** A bounded,
   reversible Phase C campaign may contain several related implementation
   slices under one recorded scope and fail-closed authority contract. Each
   slice still earns proportionate executable evidence, but the complete
   playbook/dual-review ceremony runs on the frozen combined Phase D candidate,
   not after every commit or formatter addition. Expansion and authority
   triggers still stop the batch immediately. Keep one batch to a coherent
   feature family and normally **2–5 slices**; a larger campaign needs an
   explicit smaller review boundary rather than accumulating an open-ended
   diff.
9. **Playbooks are coverage floors, not the threat model.** Reviewers derive
   assets, trust boundaries, failure paths, and novel attacks from the frozen
   source, requirements, and invariants before using the applicable playbooks
   as a completeness check. A catalog row, status label, or claimed defense is
   an untrusted hypothesis to reproduce or falsify, not a premise or an
   exhaustive list of what may be wrong.
10. **Finish the active stage before improving the process around it.** Once a
    candidate enters Phase D, the closure checklist is closed. Optional
    assurance, reviewer additions, documentation polish, tooling cleanup, and
    adjacent hardening are banked unless they were already a named gate or a
    concrete Section-5 trigger makes them stage-blocking. Review ceremony must
    remain proportionate to the stage being decided.

The practical rule is: **do not suppress exploration, and do not implement
speculation as if it were a requirement.**

## 2. Classify the work before planning it

| Class | Typical examples | Minimum process |
|---|---|---|
| Routine and reversible | Local refactor, typo, isolated test, non-authoritative tooling | Scoped plan or direct change; proportionate tests and ordinary review |
| Security-sensitive or invariant-adjacent | Signing, parsing, trusted display, TrustZone, SE protocols, update selection, counters, wire formats | Written plan, threat/invariant mapping, executable evidence, and the dual-review protocol below |
| Immutable, irreversible, or production-authority-bearing | FSBL, OTP, WRP/RDP/option bytes, SE lifecycle locks, factory keys, on-chain frozen interfaces | Dual review of architecture and implementation, explicit owner authorization for irreversible actions, resource and physical evidence, and a distinct shipment verdict |

If classification is uncertain, use the higher class until evidence narrows it.
Classification raises review depth; it does not grant authority to perform a
destructive action.

## 3. Required plan packet

A non-trivial plan must make the following reviewable before implementation:

1. **Objective and observable outcome.** State what becomes true when the task
   is complete.
2. **Baseline identity.** Record repository, branch, `HEAD`, dirty/untracked
   manifest, and any input document or artifact digest.
3. **Sources-of-truth preflight.** Follow `STATUS.md` owner links and record the
   path, revision or digest, authority scope, stated status, and evidence date
   for every requirement, task specification, surface playbook, hardware
   source, and prior receipt used by the plan. Check those active inputs for
   conflicting requirements, authority, gates, or evidence claims before
   freezing the packet. Neither document class nor publication date silently
   wins: quote any material conflict, identify the affected gate, and stop
   until the named owner resolves it or explicitly carries it as an open
   decision. Do not copy facts into a second owner.
4. **Named invariants and threats.** Say which invariant each mechanism serves
   and the concrete failure if it is absent.
5. **Scope and non-goals.** Name what may change, what is deliberately deferred,
   and the required stopping point.
6. **Assumptions, open decisions, and unknown physics.** Separate verified
   facts, model assumptions, product choices, and hardware questions.
7. **Alternatives and deletion candidates.** Include the smallest credible
   design, the selected design, and any mechanism whose necessity should be
   falsified before it becomes expensive.
8. **Authority and reversibility.** List external writes, deployment, flashing,
   OTP/lifecycle mutations, or factory operations. Identify which require a
   fresh owner decision.
9. **Resource and compatibility envelopes.** Record FLASH, RAM, stack,
   performance, wire/schema, persistent-state, and migration constraints that
   can disqualify a candidate.
10. **Implementation slices.** Prefer independently testable stages and keep
    physical backends behind pure interfaces until their evidence exists.
11. **Validation matrix.** Map each requirement and cut/failure point to an
    executable test, model, measurement, or deliberately open gate.
12. **Review and convergence gates.** State when the artifact freezes, which
    reviews are required, what blocks the next stage, and what gets banked.
    Include a closed, ordered Phase-D completion checklist. Mark each evidence
    item as mandatory for the requested stage, reusable unchanged evidence, or
    a later production/hardware gate; only the first category may delay that
    stage.
13. **Preservation and rollback.** Protect existing work, define the commit or
    branch strategy, and explain how a failed experiment is removed cleanly.

Plans may be concise. Completeness means every applicable question is answered,
not that every plan becomes a large specification.

## 4. Explore, decide, implement, and land

### Phase A — baseline and exploration

- Freeze or record the starting tree before parallel work.
- Read the source, tests, errata, and prior findings before proposing new
  mechanisms.
- Generate competing hypotheses and attack the assumptions behind them.
- Use disposable host models, deletion experiments, protocol sketches, or
  resource spikes when prose cannot decide the question.
- Mark every conclusion with its evidence level and every unanswered question
  as open.

Exploration may be broad and may discover new requirements. Exploratory code is
not production authority and should not be shared with immutable production
paths unless it passes the implementation process independently.

### Phase B — candidate selection and plan freeze

- Select the smallest candidate that satisfies the current named requirements.
- Explain why each non-obvious mechanism is retained.
- Record rejected alternatives and the evidence that rejected them.
- Freeze the review packet: plan/spec digest, prompt digest, repository identity,
  tests already executed, and open gates.
- For security-sensitive work that establishes or changes signing authority,
  fallback policy, a trust boundary, persistent-state semantics, or an
  irreversible interface, obtain favorable architecture recommendations from
  both review partners, then record the owner or authorized maintainer's stage
  decision before production-shared implementation.
- A maintainer may instead authorize a bounded Phase C implementation campaign
  under an already-selected authority and fail-closed contract. The packet must
  enumerate its slice IDs, cumulative compatibility/resource envelope, and
  Phase D stopping point. This permits implementation and testing, not merge or
  production claims, and it cannot be used to smuggle an unresolved product
  decision into code.

### Phase C — implementation and evidence

- Implement in reviewable slices; keep commits buildable and fail-closed.
- Keep one named product surface active. Record the included slice IDs and bank
  unrelated findings rather than switching campaigns mid-phase.
- Test behavior rather than source strings wherever behavior can be executed.
- Inject reset, torn-write, malformed-input, boundary, and fault cases wherever
  the threat model makes them relevant.
- Measure final combined artifacts rather than adding estimates from different
  worktrees or profiles.
- Preserve user changes and unrelated work; do not use broad cleanup or
  formatting as part of a security fix.
- Record exactly what was executed and what was only inspected.
- Do not launch a complete adversarial-review pair after each bounded slice.
  Accumulate relevant playbook coverage, tests, generated artifacts, resource
  deltas, and residuals for the combined Phase D packet.

The Phase C batch stops and returns to Phase B (or pauses for owner direction)
if a slice introduces any of the following outside the recorded campaign
envelope: new signing eligibility or downgrade/fallback authority; a new trust
boundary or host-controlled security fact; persistent-state or recovery
semantics; a wire/schema change requiring ecosystem migration rather than a
root-pinned compatible extension; an irreversible/external action; a failed
resource envelope; or another Section-5 expansion trigger. Ordinary root
rotation, compatible authenticated-IR extensions, additional fail-closed
formatters, tests, and catalogue coverage may remain in the same batch when the
packet explicitly allowed them.

### Phase D — frozen implementation review

- Stop all writers and freeze one exact candidate identity.
- Run the same required gates from a clean or isolated environment.
- Give both adversarial partners the same core packet and questions.
- Resolve findings, re-freeze, and apply the material/non-material re-review
  rule in Section 10.

Phase D is **closure mode**, not another exploration or implementation phase:

- Freeze the exact ordered checklist before launching reviewers. It contains
  only stage-relevant mandatory evidence, target identity, the required review
  legs, blocker remediation, re-review when required, landing, and the minimal
  owner-status/TODO receipt.
- Do not add a test campaign, reviewer, playbook campaign, formal-method track,
  documentation rewrite, or cleanup merely because it would improve assurance.
  Bank it unless it was already required for the requested verdict or a
  concrete Section-5 trigger makes it stage-blocking.
- Run focused tests while correcting findings and run the frozen combined gate
  set once on the candidate that will be reviewed. Do not repeatedly run the
  complete evidence matrix after every correction.
- Evidence is stage-fit. A merge review records absent production, hardware,
  factory, and destructive evidence as honest residuals unless the changed
  surface or a stricter gate specifically requires that evidence for merge.
  It does not collect shipment evidence merely because a playbook names it.
- Parallelize independent mandatory gates and review legs. Receipt generation
  and archival are bookkeeping, not new product slices, and should use the
  existing templates/scripts.
- If Phase D cannot progress on its recorded checklist, stop adding work and
  report the exact blocker, its evidence, and the shortest compliant route to
  either convergence or an owner decision.
- Every new checklist item needs a cited Section-5 trigger or stricter owner
  gate and a statement of why it cannot be banked. Without that receipt, the
  next action must come from the existing checklist.

The Phase D target is the combined Phase C candidate. Apply every intersecting
playbook as an additive lens inside one combined review of that complete
surface; do not substitute narrow per-slice reviews or separate per-playbook
campaigns for inspection of the composed behavior and resource envelope. A
separate campaign is justified only by a stricter task-specific requirement or
a concrete finding that triggers Section 5 scope expansion. Combining the
lenses never permits an applicable catalog, stricter gate, or honest residual
to be omitted.

### Phase E — landing and handoff

- Distinguish a reviewer recommendation of `GO for merge` from `GO for
  production shipment`; neither performs or authorizes the action by itself.
- Land all load-bearing tracked and untracked inputs atomically.
- Re-run the identity and drift checks immediately before staging and after
  landing.
- Put reversible residual work in [`work-todo.md`](work-todo.md); put
  irreversible factory/silicon work in
  [`production-todo.md`](production-todo.md).
- Record the evidence receipt and the exact remaining blockers.

## 5. Requirements and scope may expand

Reviewers are explicitly authorized to question the architecture, propose
deletions, explore stronger defenses, and surface missing requirements. Do not
prompt them to stay inside a possibly-wrong design merely to preserve schedule
or sunk cost.

A proposed expansion becomes a **candidate** when at least one of these applies:

- a concrete unsafe trace, exploit, counterexample, or reproducible failure;
- a named invariant or threat is uncovered or violated;
- verified silicon, errata, protocol, or deployment evidence invalidates an
  assumption;
- a requirement is unimplementable as written;
- measured FLASH, RAM, stack, timing, endurance, or power fails its envelope;
- a frozen interface, compatibility, migration, or recovery constraint requires
  it;
- the owner explicitly adds a product or assurance requirement.

Except for an explicit owner-added requirement, a candidate expansion enters
the accepted plan only after its trigger is independently substantiated at the
applicable evidence level and adjudicated. Destructive E6/E7 evidence is never
repeated merely to satisfy this sentence; it requires the separate authority
in Section 11. For security-sensitive work, substantiation includes the
applicable independent/cross-review step; a single reviewer's unverified trace
or factual assertion is not enough.

For an expansion, record:

1. the trigger and evidence;
2. the smallest remedy and at least one deletion/simplification alternative;
3. the added trusted-computing-base, state, resource, test, and review cost;
4. which prior review recommendations and digests are invalidated;
5. whether new authority or an owner choice is required.

Ideas without one of these triggers are not discarded. Classify them as
optional hardening, research, or future product work and bank them. This is the
YAGNI boundary: it prevents speculative accretion while leaving the models free
to discover something important.

Material expansion beyond the user's authorized outcome, or any new
irreversible/external action, pauses implementation for owner approval. A new
security requirement within the existing outcome may be investigated safely
and presented with evidence before that decision.

## 6. Evidence and authority ladder

| Level | Evidence | What it can establish |
|---|---|---|
| E0 | Source reading, grep, design reasoning | Candidate mechanisms and questions; no execution claim |
| E1 | Unit tests, host models, property tests | Pure-logic behavior under the modeled assumptions |
| E2 | Fuzzing, mutation, formal/symbolic checks | Properties covered by the exact harness/model and bounds |
| E3 | Target link, binary inspection, FLASH/static-RAM/stack receipts | Properties of the exact build/profile measured |
| E4 | QEMU or emulator end-to-end | Integration behavior within the emulator model |
| E5 | Non-destructive target-silicon tests | Observed behavior on named hardware without irreversible mutation |
| E6 | Owner-authorized destructive/sacrificial tests | Observed irreversible behavior for the named parts, revisions, and procedure |
| E7 | Factory/release evidence | Production ceremony, custody, reproducibility, and shipment gates |

Higher levels do not automatically subsume different lower-level properties.
For example, a silicon smoke test does not replace a parser property test.
Reports must name the exact level actually reached.

## 7. Required adversarial review partners

For security-sensitive architecture and implementation, use both partners:

- **Partner A:** Claude Code **Opus 4.8** with 1M context. Select the
  **`ultracode` mode**, resolving to the required orchestration profile and
  **`xhigh`** reasoning effort. If the backend exposes separate selectors, set
  and attest both; if one control-plane selector sets both, record that selector
  plus the resolved settings rather than claiming a second manual control was
  used. `ultracode` is not itself the literal reasoning-effort field. Use `max`
  only when a task-specific technical reason favors it; record that reason
  before review starts. `max` never substitutes for the required `ultracode`
  mode.
- **Partner B:** literal model **`gpt-5.6-sol`** with
  **`model_reasoning_effort="ultra"`**.
- **Optional supplemental reviewer K (non-substitutive):** **Kimi K3** through
  Kimi Code, selected with CLI model alias **`kimi-code/k3`**. Request maximum
  supported thinking effort and the 1M context ceiling. The post-launch
  control-plane receipt must resolve the alias to provider/model `kimi`/`k3`
  and attest `thinkingEffort="max"`. Kimi is additional adversarial-discovery
  signal only: it does not replace either required partner, change the minimum
  independent pair, assign cross dispositions, or cure an unavailable
  mandatory leg. Run it only when the user, a task-specific gate, or a recorded
  unresolved technical question names the expected value before Phase D
  launches. It is not a standing default and its absence must not delay the
  mandatory pair or landing. When run, freeze its first pass independently.
  After both required first passes freeze, give its complete raw report and
  digest to both required partners as supplemental candidate input.

**Local access points for the partner legs (2026-07-17).** Partner A is
reachable through the `claude` CLI (`~/.local/bin/claude`, Claude Code 2.x);
Partner B through the `codex` CLI (`~/.local/bin/codex`) or the Codex MCP
server; the repo kit is
[`contracts/verification/adversarial-review/run_review.py`](../contracts/verification/adversarial-review/README.md)
(`--backend {claude,codex,generic}`). An orchestrator-spawned single-backend
reviewer swarm (any model, incl. Kimi subagents) is a **Phase-A discovery input
only**: its candidate packet — however convergent — goes through the
Partner-A/B protocol above before any disposition, canonical finding, or
"verified" claim. It is not a standing prerequisite and must not be launched
after the Phase-D checklist freezes unless that checklist already names the
unresolved question it is expected to answer.

Before any required or supplemental first pass starts, the coordinator MUST
freeze a **pre-launch request receipt** for each leg: role, executable and CLI/harness version,
redacted argv/config, working directory, prompt digest, requested literal model
identifier, context selector, reasoning-effort setting, orchestration profile,
sandbox, allowed fan-out or subagents, and every planned substitution.

After the session starts, and before its report is accepted or disclosed, the
coordinator MUST freeze a **post-launch runtime receipt** from the launcher,
harness, provider response, or durable session log. It binds the session ID,
target identity, report digest, observed model/provider, effort and context
selector when exposed, actual fan-out/profile, sandbox, harness version, and
every deviation. A command line alone is request evidence, not runtime
attestation. Runtime configuration is a control-plane fact: model self-report
is not required and MUST NOT be the sole attestation. If a required selector is
absent from every trusted post-launch/control-plane record, that review leg is
unavailable; non-required fields may be `NOT_EXPOSED` with a source and reason.

Receipts should be compact and machine-generated where possible. One immutable
record plus its digest may satisfy every later citation; do not reproduce the
same configuration as parallel prose in prompts, reports, matrices, status,
and TODO files.

For Kimi, the trusted post-launch source is a Kimi Code export or durable
wire/session log. It must bind the CLI version, session ID, report digest,
observed model alias, provider/model, thinking effort, context ceiling,
permission mode, active tool/MCP profile, completion outcome, and deviations.
An `llm.request` record, command line, or model self-report is not a completed
runtime receipt. A failed or unattested Kimi leg is recorded as
supplemental-unavailable and does not weaken or complete the mandatory pair.

If either exact partner is unavailable, do not silently substitute a weaker or
different review and call the pair complete. Record the missing leg and ask the
owner whether to wait or authorize a named substitute.

These two partners are the minimum independent pair, not a cap. A task-specific
specification or surface playbook may require additional reviewers, formal
tools, domain specialists, or hardware evidence. Either partner may also use
subagents, provided the named partner personally adjudicates the result.

### Independent first pass

Both reviewers receive:

- the same frozen artifact and repository identity;
- the same threat/invariant questions and acceptance gates;
- the same evidence packet and list of known open decisions;
- an immutable-target instruction: no edit to the canonical source/index,
  hardware, or external state;
- a required initial and final digest/drift check.

“Immutable target” does not mean source-only review. Reviewers may run
non-destructive commands, build into external target directories, and create or
mutate PoCs in an isolated scratch copy. They must record those actions and
must never report scratch state as the reviewed identity.

Reviewers write raw reports to distinct, no-clobber paths outside the immutable
target and freeze each report with its own digest. Review commands SHOULD set
`PYTHONDONTWRITEBYTECODE=1` (or equivalent), and the initial/final identity
receipt records ignored files as well as ordinary Git status so an ignored
cache cannot masquerade as an immutable target. After both first passes and
cross-adjudications are frozen,
a coordinator may file byte-identical copies in a separate reporting
commit/worktree. That archival commit is not the reviewed target and MUST NOT
be described as inheriting its recommendation. Any substantive edit to a raw
report creates a new report digest and remains visibly distinct from the frozen
original.

Use neutral mutual disclosure without sharing conclusions:

- Tell Opus: **“GPT-5.6 SOL (`gpt-5.6-sol`,
  `model_reasoning_effort="ultra"`) is independently reviewing this same frozen
  packet. Do not infer its verdict or defer to it.”**
- Tell GPT-5.6: **“Claude Code Opus 4.8 with 1M context, `ultracode`
  orchestration, and `xhigh` reasoning effort is independently reviewing this
  same frozen packet. Do not infer its verdict or defer to it.”**
- When Kimi runs, additionally tell both required partners: **“Kimi K3 (Kimi
  Code alias `kimi-code/k3`, maximum thinking effort) is also running a
  supplemental, non-dispositive pass on this frozen packet. Do not infer its
  findings or defer to it.”** Tell Kimi: **“The exact Opus 4.8 and GPT-5.6 SOL
  pair is independently reviewing this frozen packet and exclusively owns
  symmetric cross-dispositions. Your pass is supplemental; do not infer their
  verdicts or defer to them.”**

Do not provide either partner with the other's findings or verdict before both
first-pass reports are frozen. The disclosure prevents a model from being
presented as the sole authority; withholding the result prevents anchoring and
premature consensus.

Reviewers may use their own subagents, tools, and exploratory attacks. They are
not limited to the plan author's threat list. They must distinguish an executed
finding from a reasoned suspicion and must not mutate the review target.

To resist prompt anchoring, each first pass has two distinguishable parts:

1. **Independent source-first discovery.** Derive the attacker, assets, trust
   boundaries, authority transitions, composed failure paths, and resource
   hazards from the frozen implementation and normative requirements. Hunt for
   novel defects without treating playbook catalogs, prior findings, or
   `DEFENDED` labels as premises.
2. **Playbook coverage reconciliation.** After that open-ended analysis, walk
   every applicable catalog and stricter requirement as a coverage audit;
   reproduce or challenge its claims, identify gaps, and record anything the
   independent pass found outside the catalogs.

The report must keep those two parts visible even when the same evidence serves
both. This is one combined review, not one campaign per playbook, and it does
not require inventing a novel finding when the independent pass finds none.

### Symmetric cross-adjudication

After both first-pass reports freeze:

Any frozen supplemental Kimi report is candidate input, not a third
disposition vote. Give its complete report and digest to both required
partners at this stage. Both must disposition every Kimi blocker, major, or
other candidate that could change the requested stage verdict. Lower-severity
supplemental observations may be grouped and banked unless either required
partner promotes one with a concrete stage-impacting trace.

1. Give each reviewer the other complete report and both report digests.
2. Require each to reproduce, refute, or narrow every blocker/major finding.
3. Require each to identify where the other reviewer inherited the plan's
   framing, anchored on a playbook catalog, or accepted an unsupported claim,
   and to name any shared blind spot outside the supplied catalogs.
4. Preserve disagreements explicitly; do not average severities or decide by
   majority language.
5. A confirmed or unresolved blocker/major finding, or an unresolved `NO-GO`
   from either partner, prevents a favorable recommendation or owner transition
   for that stage. The owner
   may accept a product trade-off only after the residual and consequence are
   written plainly; an unresolved correctness contradiction cannot be accepted
   by preference.

Cross-adjudication produces one durable matrix with one row for every
stage-impacting first-pass finding. Each row records the stable finding ID,
originating severity and stage impact, Partner A's disposition and evidence,
Partner B's disposition and evidence, the resulting correction or residual,
and whether an owner decision remains. Low/informational findings with no
plausible combined stage impact may be grouped in a banked appendix with origin
and rationale; they do not require a separate counterpart round. Either partner
may promote a grouped item by supplying a concrete unsafe trace or other
Section-5 trigger.
Use only `CONFIRMED`, `REFUTED`, `NARROWED`, or `UNRESOLVED` as cross
dispositions.

A new finding discovered during cross-adjudication receives a stable `X-*` ID
and one bounded response from the counterpart. If that response does not
resolve it, record it as `UNRESOLVED`; do not start a recursive discussion
loop. The matrix header binds the target identity and both first-pass and
cross-report digests. Its footer records the final target drift check and each
partner's revised stage-specific verdict.

The partner identities provide model diversity; the reproduce/refute phase is
what turns two opinions into adversarial evidence.

## 8. Review packet and required output

The packet should include only relevant material, but it must be sufficient to
reproduce the claims:

- objective, scope, non-goals, and stage being adjudicated;
- exact `HEAD`, branch, tracked diff hash, untracked manifest/hash, and aggregate
  identity recipe;
- plan/spec and prompt digests;
- named invariants, threats, decisions, and open gates;
- implementation diff or file list and the source-of-truth documents;
- commands, logs, resource receipts, and hardware receipts actually available;
- previous findings that remain open or whose fixes are being re-adjudicated;
- one applicable-playbook coverage map that includes every task-relevant Part-C
  question, reviewer-count/cadence requirement, required command, and honest
  boundary. Present the playbooks as additive coverage lenses for the combined
  review, label their status claims as untrusted inputs, and deduplicate common
  instructions without dropping a stricter requirement. The generic workflow
  never substitutes for a stricter playbook, and the number of intersecting
  playbooks does not itself create separate campaigns.

Do not manufacture evidence for a stage that is not being decided. The packet
must distinguish: (a) evidence required for the requested verdict, (b) unchanged
evidence reused by exact digest/reference, and (c) production/hardware residuals
that are intentionally outside this stage. Category (c) is disclosed, not run
as a precautionary side campaign.

Each reviewer report must contain:

1. **Identity and drift result.** Initial and final snapshot identity.
2. **Reviewer-configuration receipt.** Digests/references for the frozen
   pre-launch request and post-launch runtime receipts; the observed model and
   provider, effort and context selector when exposed, profile/fan-out,
   harness/backend version, session ID, sandbox, deviations, and any
   `NOT_EXPOSED` fields. The raw model report need not introspect control-plane
   facts itself.
3. **Stage-specific verdicts.** Architecture, implementation, merge, and
   production shipment are stated separately; unavailable stages say so.
4. **Findings.** Stable ID, severity, file/line, mechanism, prerequisites,
   consequence, whether introduced here, falsifiable evidence/PoC, and required
   correction.
5. **Invariant and failure-path trace.** Especially power cuts, malformed
   states, trust-boundary crossings, resource exhaustion, and downgrade/fallback
   paths applicable to the change.
6. **Executed versus inspected evidence.** Tests not rerun are never presented
   as fresh evidence.
7. **KEEP / SIMPLIFY / FIX NOW / DEFER / DROP / OPEN RESEARCH.** Optional ideas
   are classified rather than smuggled into a red-line.
8. **Honest residual.** What resisted attack, what was not reviewed, tool or
   model limits, and the exact remaining gates.

Every security review governed by the surface playbooks first freezes its raw
partner reports externally. Symmetric adjudication then uses
[`security/adversarial-review/findings/CROSS_ADJUDICATION_TEMPLATE.md`](security/adversarial-review/findings/CROSS_ADJUDICATION_TEMPLATE.md);
only the post-cross canonical record uses
[`security/adversarial-review/findings/TEMPLATE.md`](security/adversarial-review/findings/TEMPLATE.md)
and its
[`status lifecycle`](security/adversarial-review/findings/README.md).
Formal-verification work also follows
[`verification/fv-adversarial-review-playbook.md`](verification/fv-adversarial-review-playbook.md).

A reviewer may recommend risk acceptance but may not set a finding to
`☑️ ACCEPTED`. That status is owner-only and requires a recorded owner decision
naming the owner, date, exact finding and target/report digests, accepted
consequence, and scope. Ordinary implementation/merge authority delegated to a
maintainer does not include security-risk acceptance. Model consensus is not
acceptance authority.

## 9. Reviewer recommendation meanings

These labels are evidence for a separate owner or authorized-maintainer stage
decision. A model never authorizes implementation, merge, shipment, hardware
mutation, or an external write.

- **`NO-GO`:** a blocker, unresolved correctness contradiction, target drift,
  or missing mandatory evidence prevents the named stage.
- **`APPROVE WITH RED-LINES`:** named mandatory corrections block the requested
  stage until a new frozen snapshot is reviewed successfully.
- **`APPROVE FOR OPEN-DECISION CLOSURE`:** the architecture is coherent enough
  to resolve explicitly listed decisions; it is not implementation approval.
- **`APPROVE FOR IMPLEMENTATION`:** the reviewer recommends that the exact
  architecture is closed enough for the stated implementation scope; the owner
  or authorized maintainer still decides whether implementation starts.
- **`GO FOR MERGE`:** the reviewer recommends that the exact tested
  implementation may land for its stated purpose. An authorized maintainer
  makes the merge decision. This is not shipment approval.
- **`GO FOR PRODUCTION SHIPMENT`:** the reviewer found the submitted software,
  resource, hardware, factory, provenance, and owner-gate evidence complete for
  the exact release artifact. The owner/release authority still makes the
  shipment decision.

Every verdict names its subject and exact digest. “Looks good” is not a verdict.

## 10. Convergence and stopping discipline

The default convergence loop is:

1. one independent first-pass pair;
2. symmetric cross-adjudication;
3. fix confirmed blockers and mandatory red-lines;
4. freeze a new digest;
5. classify the change as material or non-material;
6. review the new exact digest under the rule below.

A change is **material** when it affects an authority rule, state transition,
byte/schema format, trust boundary, failure response, resource envelope,
security claim, or the substance of a blocker/mandatory red-line. A material
change starts fresh, mutually withheld first-pass reviews in fresh contexts on
the new digest, followed by cross-adjudication. Prior findings remain explicit
acceptance criteria, but neither partner sees the other's new report before its
own freezes.

That re-review rule applies once a snapshot has entered Phase D or carries a
review recommendation. It does not require a full review after every material
commit made inside the initial authorized Phase C batch. Likewise, when a Phase
D review produces several material corrections, implement and test the related
corrections as one bounded remediation batch, then freeze and review their
combined result once. No prior recommendation transfers to the changed digest
during that interval, and no merge/production claim is available until the
next Phase D review converges.

For a remediation snapshot that stays inside the original authority, trust
boundaries, compatibility envelope, and product surface, the fresh withheld
pair may be **remediation-focused**: it must re-check every prior blocker,
changed file, affected caller/consumer, composed failure path, resource delta,
and applicable playbook question whose answer could have changed. It need not
repeat unrelated catalogue questions or unchanged evidence solely to recreate
the first packet's volume. A new authority, trust boundary, fallback, persistent
state, incompatible wire change, or Section-5 trigger requires a full combined
review instead.

A **non-material** change is limited to editorial correction, link/receipt
repair, or a mechanically equivalent test/document update that changes no
authority, behavior, evidence claim, or acceptance gate. Both partners and the
owner/authorized maintainer must agree on that classification; only then may a
delta-focused re-review replace fresh full first passes.

This is a default, not an arbitrary cap. Continue when a re-review produces a
new concrete expansion trigger from Section 5. Stop when only editorial
preferences, duplicate defenses without a named threat, or optional hardening
remain; bank those items instead of creating another draft by accretion.

Do not declare convergence merely because review is expensive. Conversely, do
not reopen an accepted architecture merely because a reviewer can imagine an
additional defense. The deciding question is whether new evidence changes a
requirement, invalidates an assumption, or makes the selected design unsafe or
unimplementable.

No recommendation transfers across a changed artifact. Even a permitted narrow
delta review binds its conclusion to the new exact digest.

## 11. Irreversible and external actions

No plan or model review authorizes destructive hardware or an external
deployment. Before OTP, option-byte, RDP/WRP, SE lifecycle, credential, factory,
or production-release mutation, obtain an explicit owner instruction naming:

- the exact board/part and revision or external target;
- the cells, objects, keys, lifecycle states, or deployment affected;
- the exact artifact, source, toolchain, ceremony/procedure, and dual-review
  report digests being authorized;
- the named operator, authorization window, and exact single attempt covered;
- the pre-state capture and recovery limits;
- the expected irreversible result and stop conditions;
- the evidence that the non-destructive prerequisites passed.

Absence of authorization is a hard stop, not an assumption to fill in. The
authorization is consumed when the first irreversible command may have
launched, including a timeout, reset, error, or partial execution. It cannot be
replayed for a retry, replacement part, broader cell/object range, changed
artifact, changed procedure, or later window; each requires fresh owner
authorization.

## 12. Reusable reviewer prompt preamble

Use the same body for both partners and change only the role line and neutral
disclosure. Attach every applicable surface playbook's task-relevant Part-C
questions and stricter requirements as a coverage appendix; do not concatenate
them into repetitive prompts that displace open-ended analysis. This generic
preamble never replaces an applicable lens.

```text
You are independent adversarial review Partner <A|B> for PQSigner OS.
Run with <Opus 4.8, 1M context, ultracode orchestration, xhigh reasoning |
literal gpt-5.6-sol, model_reasoning_effort="ultra">.
Record the actual runtime configuration receipt required by Sections 7 and 8.
<Neutral counterpart-disclosure sentence from Section 7.>

Keep the canonical review target immutable: do not edit its repository or
index, access hardware, or perform external writes. You may run non-destructive
commands, use external build directories, and create executable PoCs in an
isolated scratch copy; report them separately from the reviewed identity.
Verify the canonical snapshot identity before reading and immediately before
reporting. Treat prior recommendations as non-transferable and attempt to
refute both the architecture and its implementation.

Begin with an independent source-first attack: derive the assets, attacker,
trust boundaries, authority transitions, composed failure paths, and resource
hazards from the frozen implementation and normative requirements. Seek novel
defects outside the supplied threat list. Do not treat a playbook catalog,
status label, prior finding, or claimed defense as a premise or as exhaustive.
Then use every applicable playbook in the coverage appendix to audit what the
independent pass may have missed and to challenge each relevant claim. Keep the
source-first results and the playbook reconciliation distinguishable. Multiple
playbooks are additive lenses in this one review, not separate campaigns,
unless the packet names a stricter task-specific requirement.

Return the output required by Sections 8 and 9 of
docs/planning-and-review-workflow.md. Require falsifiable evidence for findings,
separate executed from inspected evidence, state honest residuals, and keep
architecture, implementation, merge, and production verdicts distinct. State
what you explored outside the catalogs and identify any inherited framing,
even if that exploration yields no additional finding.

<Objective, scope, frozen identity recipe/digests, invariants, evidence,
mandatory questions, open gates, and exact files follow.>
```

After both first passes freeze, issue a separate cross-adjudication prompt with
both complete reports and require the Section-7 disposition matrix, report
digests, final drift result, and revised stage-specific verdicts.
