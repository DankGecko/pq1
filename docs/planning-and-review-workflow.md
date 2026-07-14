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
3. **Sources of truth.** Link the owning requirements, threat model, interface,
   and hardware documentation. Do not copy facts into a second owner.
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
- For security-sensitive work, obtain favorable architecture recommendations
  from both review partners, then record the owner or authorized maintainer's
  stage decision before production-shared implementation.

### Phase C — implementation and evidence

- Implement in reviewable slices; keep commits buildable and fail-closed.
- Test behavior rather than source strings wherever behavior can be executed.
- Inject reset, torn-write, malformed-input, boundary, and fault cases wherever
  the threat model makes them relevant.
- Measure final combined artifacts rather than adding estimates from different
  worktrees or profiles.
- Preserve user changes and unrelated work; do not use broad cleanup or
  formatting as part of a security fix.
- Record exactly what was executed and what was only inspected.

### Phase D — frozen implementation review

- Stop all writers and freeze one exact candidate identity.
- Run the same required gates from a clean or isolated environment.
- Give both adversarial partners the same core packet and questions.
- Resolve findings, re-freeze, and apply the material/non-material re-review
  rule in Section 10.

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
the accepted plan only after its trigger is reproduced and adjudicated. For
security-sensitive work, this includes the applicable independent/cross-review
step; a single reviewer's unverified trace or factual assertion is not enough.

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

- **Partner A:** Claude Code **Opus 4.8**, 1M context when available, at
  **`ultracode`** effort. Use `max` only when `ultracode` is unavailable or a
  task-specific technical reason favors `max`; record that reason before the
  review starts.
- **Partner B:** **GPT-5.6 SOL** at **`ultra`** effort.

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

Use neutral mutual disclosure without sharing conclusions:

- Tell Opus: **“GPT-5.6 SOL at ultra effort is independently reviewing this
  same frozen packet. Do not infer its verdict or defer to it.”**
- Tell GPT-5.6: **“Claude Code Opus 4.8 at ultracode effort is independently
  reviewing this same frozen packet. Do not infer its verdict or defer to it.”**

Do not provide either partner with the other's findings or verdict before both
first-pass reports are frozen. The disclosure prevents a model from being
presented as the sole authority; withholding the result prevents anchoring and
premature consensus.

Reviewers may use their own subagents, tools, and exploratory attacks. They are
not limited to the plan author's threat list. They must distinguish an executed
finding from a reasoned suspicion and must not mutate the review target.

### Symmetric cross-adjudication

After both first-pass reports freeze:

1. Give each reviewer the other complete report and both report digests.
2. Require each to reproduce, refute, or narrow every blocker/major finding.
3. Require each to identify where the other reviewer inherited the plan's
   framing or accepted an unsupported claim.
4. Preserve disagreements explicitly; do not average severities or decide by
   majority language.
5. A confirmed blocker, or an unresolved `NO-GO` from either partner, prevents
   a favorable recommendation or owner transition for that stage. The owner
   may accept a product trade-off only after the residual and consequence are
   written plainly; an unresolved correctness contradiction cannot be accepted
   by preference.

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
- every applicable surface playbook, including its Part-C attack catalog,
  reviewer-count/cadence requirements, and required commands. The generic
  workflow is additive and never substitutes for a stricter playbook.

Each reviewer report must contain:

1. **Identity and drift result.** Initial and final snapshot identity.
2. **Stage-specific verdicts.** Architecture, implementation, merge, and
   production shipment are stated separately; unavailable stages say so.
3. **Findings.** Stable ID, severity, file/line, mechanism, prerequisites,
   consequence, whether introduced here, falsifiable evidence/PoC, and required
   correction.
4. **Invariant and failure-path trace.** Especially power cuts, malformed
   states, trust-boundary crossings, resource exhaustion, and downgrade/fallback
   paths applicable to the change.
5. **Executed versus inspected evidence.** Tests not rerun are never presented
   as fresh evidence.
6. **KEEP / SIMPLIFY / FIX NOW / DEFER / DROP / OPEN RESEARCH.** Optional ideas
   are classified rather than smuggled into a red-line.
7. **Honest residual.** What resisted attack, what was not reviewed, tool or
   model limits, and the exact remaining gates.

Every security review governed by the surface playbooks files a durable report
using the surface-specific finding template at
[`security/adversarial-review/findings/TEMPLATE.md`](security/adversarial-review/findings/TEMPLATE.md)
and its
[`status lifecycle`](security/adversarial-review/findings/README.md).
Formal-verification work also follows
[`verification/fv-adversarial-review-playbook.md`](verification/fv-adversarial-review-playbook.md).

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
- the pre-state capture and recovery limits;
- the expected irreversible result and stop conditions;
- the evidence that the non-destructive prerequisites passed.

Absence of authorization is a hard stop, not an assumption to fill in.

## 12. Reusable reviewer prompt preamble

Use the same body for both partners and change only the role line and neutral
disclosure. Append every applicable surface playbook's Part-C prompt and
requirements; this generic preamble never replaces them.

```text
You are independent adversarial review Partner <A|B> for PQSigner OS.
Run at <Opus 4.8 ultracode, 1M context | GPT-5.6 SOL ultra>.
<Neutral counterpart-disclosure sentence from Section 7.>

Keep the canonical review target immutable: do not edit its repository or
index, access hardware, or perform external writes. You may run non-destructive
commands, use external build directories, and create executable PoCs in an
isolated scratch copy; report them separately from the reviewed identity.
Verify the canonical snapshot identity before reading and immediately before
reporting. Treat prior recommendations as non-transferable and attempt to
refute both the architecture and its implementation. You may explore outside
the author's threat list.

Return the output required by Sections 8 and 9 of
docs/planning-and-review-workflow.md. Require falsifiable evidence for findings,
separate executed from inspected evidence, state honest residuals, and keep
architecture, implementation, merge, and production verdicts distinct.

<Objective, scope, frozen identity recipe/digests, invariants, evidence,
mandatory questions, open gates, and exact files follow.>
```

After both first passes freeze, issue a separate cross-adjudication prompt with
both complete reports and require the Section-7 reproduce/refute procedure.
