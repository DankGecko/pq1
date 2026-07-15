# Adversarial-review findings — the catalogue

This folder is the **single repository home for canonical, post-cross-adjudication
finding records** produced under the playbooks in the parent directory and the
[FV playbook](../../../verification/fv-adversarial-review-playbook.md). Raw
first passes and cross passes freeze outside the reviewed target; their digests
and disposition matrix are cited here afterward. Consistent headers and
per-finding status make it obvious which adjudicated findings have been worked
through and which remain open.

> **Sibling — confirmed-vuln writeups.** Individual *confirmed-and-fixed* vulnerability reports live in [`../../vulns/`](../../vulns/) (their own established folder, each with a fix). Those are a distinct flavor from adversarial-review *pass* reports; this folder catalogues the passes. (Consolidating `vulns/` into here is a possible future cleanup — it is heavily cross-referenced, so left separate for now.)

Reports explicitly labelled **historical**, **imported**, **pre-workflow**, or
**supplemental** in the catalogue are preserved byte-for-byte evidence from
before this canonical workflow. Their older frontmatter/status vocabulary does
not grant exact-pair completion or a current recommendation; do not rewrite
their frozen bytes merely to resemble the current template.

## How reviewed findings become repository state

1. Both required partners write and digest independent first-pass reports
   **outside the reviewed target**. Preserve every candidate, raw origin ID,
   diagnostic, and honest residual.
2. Each partner receives the other's complete first-pass report and writes a
   separate cross-review. Freeze and digest both cross-reviews.
3. Record all four reports in
   [`CROSS_ADJUDICATION_TEMPLATE.md`](./CROSS_ADJUDICATION_TEMPLATE.md). Every
   candidate gets exactly one of `CONFIRMED`, `REFUTED`, `NARROWED`, or
   `UNRESOLVED`; disagreement is preserved, never majority-voted away.
4. Only after that matrix freezes, copy [`TEMPLATE.md`](./TEMPLATE.md) to
   `docs/security/adversarial-review/findings/<surface>-<YYYY-MM-DD>[-<run>].md`
   for the canonical post-cross record. Cite the exact first-pass, cross-pass,
   matrix, and target digests. Because cross-adjudication is already complete,
   every canonical item starts with `Status: 🔬 REVIEWED`; later resolution
   marks confirmed/narrowed items fixed, accepted, or deferred and refuted
   items invalid with evidence.
5. An authorized maintainer files the byte-identical evidence/canonical report
   in a separate reporting commit and adds a row to the catalogue. End with the
   mandatory honest residual and cross-link actionable work to
   `docs/work-todo.md`.

The report is self-describing (frontmatter + per-finding status). From this
directory,
`grep -rlE --exclude='*TEMPLATE.md' '^status: (open|in-review)([[:space:]]|$)' .`
lists filed reports with unhandled work, and
`grep -rnE --exclude='*TEMPLATE.md' '^[-*] \*\*Status:\*\* (🔲 OPEN|🔬 REVIEWED)' .`
lists their individual findings that are not closed out.

## Status lifecycle — so "handled" is unmistakable

**Per finding** (the `Status:` line on each `Fn`):

| Status | Meaning |
|---|---|
| `🔲 OPEN` | surfaced in a pre-cross/imported record, not yet cross-adjudicated |
| `🔬 REVIEWED` | cross-adjudicated — `CONFIRMED` / `REFUTED` / `NARROWED` / `UNRESOLVED` is recorded with both partners' evidence, but the item is not yet closed out |
| `✅ FIXED` | a fix landed — the **Resolution** line names the commit + date |
| `☑️ ACCEPTED` | explicit owner-only risk acceptance — the **Resolution** records owner, date, exact finding, target + frozen-report digests, accepted consequence, and scope; a reviewer, model, or ordinarily authorized maintainer cannot set this status |
| `🚫 INVALID` | false positive on re-review — the **Resolution** line says why |
| `⏸ DEFERRED` | real, but blocked (needs hardware / a design decision / another dependency) — Resolution names the blocker + the tracking item |

**Per report** (the frontmatter `status:`):

| Status | Meaning |
|---|---|
| `open` | one or more findings are still `🔲 OPEN` |
| `in-review` | all findings triaged (`🔬`/beyond), some not yet closed |
| `resolved` | **every** finding is `✅ FIXED` / `☑️ ACCEPTED` / `🚫 INVALID` / `⏸ DEFERRED` (with a tracking link) |
| `fixes-landed-production-blocked` | every code finding is handled, but a named deferred ship blocker still forbids production authority |

**When you work through a report:** for each finding you handle, change its `Status:` line, append a one-line **Resolution** (what you did / a commit SHA + date, or why invalid/deferred), and — when nothing is left `🔲 OPEN` / `🔬 REVIEWED` — flip the report frontmatter `status:` to `resolved` (or `fixes-landed-production-blocked` when a named deferred finding still forbids shipping). Only an explicit owner decision may set `☑️ ACCEPTED`; record the owner, date, exact finding, target and frozen-report digests, accepted consequence, and scope. Ordinary maintainer authority does not include risk acceptance. Reviewer consensus is recommendation evidence, never acceptance authority. Cross-link the real work to `docs/work-todo.md` (which stays the master task list); this folder is the *review record*, work-todo is the *action list*.

The raw first-pass reports, lossless union (if used), cross-reviews, and
cross-adjudication matrix are distinct artifacts. A union is an evidence
envelope, not a consensus engine. The reporting commit is not the reviewed
target and does not inherit its recommendation. Later resolution edits must
preserve all frozen input and matrix digests.

## Catalogue

Newest first. Add a row when you file a report; update the Status/Findings cells as you work through it.

| Report | Surface | Date | Report status | Findings (open / handled) |
|---|---|---|---|---|
| [multi-2026-07-15-deterministic-second-round](./multi-2026-07-15-deterministic-second-round.md) | multi (deterministic second-round validation; source-review legs discarded after visibility guard) | 2026-07-15 | `resolved` (0 new findings; does not resolve earlier reports or satisfy the required exact-pair workflow) | 0 open / 0 handled |
| [multi-2026-07-14-local-closure-review](./multi-2026-07-14-local-closure-review.md) | multi (supplemental local all-playbook closure review; no external first pass accepted) | 2026-07-14 | `open` (pre-workflow evidence; not canonical cross-adjudication or workflow completion) | 4 open / 0 handled (1 novel, 3 materially new closure paths) |
| [full-project-sweep-2026-07-14](./full-project-sweep-2026-07-14.md) | multi (full PQSigner_OS sweep; supplemental pre-workflow evidence—the required identified partner pair was not completed) | 2026-07-14 | `fixes-landed-production-blocked` (historical/imported; not workflow completion) | 0 open / 18 handled (10 fixed, 8 deferred) |
| [clear-signing-2026-07-10](./clear-signing-2026-07-10.md) | clear-signing (ERC-7730 compiler, renderer, dispatch + FI; validation continued 2026-07-12) | 2026-07-10 | `in-review` | 1 reviewed / 29 handled (28 fixed, 1 deferred; F11 awaits an owner decision) |
| [2026-07-adversarial-review-engagement](./2026-07-adversarial-review-engagement.md) | multi (playbook family build-out) | 2026-07-02..04 | `in-review` | 1 reviewed / 10 handled (7 fixed, 3 deferred; F5 awaits an owner decision) |
| [clear-signing-2026-07-02](./clear-signing-2026-07-02.md) | clear-signing (ERC-7730 + render ladder) | 2026-07-02 | `resolved` | historical pass — live bugs fixed, tracked in the clear-signing playbook + work-todo |
