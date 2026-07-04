# Adversarial-review findings — the catalogue

This folder is the **single home for every finding report** produced by an adversarial-review pass (per the playbooks in the parent directory + the [FV playbook](../../../verification/fv-adversarial-review-playbook.md)). Putting all reports here — one file per pass, with a consistent header and a per-finding status — makes them easy to find, easy to catalogue, and, most importantly, makes it obvious **which findings have been worked through and which are still open**.

## How a pass files its findings

1. Copy [`TEMPLATE.md`](./TEMPLATE.md) to `docs/security/adversarial-review/findings/<surface>-<YYYY-MM-DD>[-<run>].md` (e.g. `clear-signing-2026-08-01.md`, or `-r2` for a second run that day).
2. Fill the frontmatter (`surface`, `run_date`, `reviewer`, `scope`, report-level `status: open`).
3. Record each finding as `F1`, `F2`, … — **every finding carries its own `Status:`** line (starts `🔲 OPEN`).
4. Add one row to the [Catalogue](#catalogue) table below.
5. End with the mandatory **Honest residual** (what survived, what wasn't looked at, provenance).

The report is self-describing (frontmatter + per-finding status), so `grep -rl 'status: open' findings/` lists every report with unhandled work, and `grep -rn 'Status: 🔲 OPEN' findings/` lists every open finding across all reports.

## Status lifecycle — so "handled" is unmistakable

**Per finding** (the `Status:` line on each `Fn`):

| Status | Meaning |
|---|---|
| `🔲 OPEN` | surfaced, not yet worked through |
| `🔬 REVIEWED` | triaged — a disposition is set (confirmed / false-positive / already-fixed) but not yet closed out |
| `✅ FIXED` | a fix landed — the **Resolution** line names the commit + date |
| `☑️ ACCEPTED` | risk-accepted / by-design / deferred-by-design — the **Resolution** line says why |
| `🚫 INVALID` | false positive on re-review — the **Resolution** line says why |
| `⏸ DEFERRED` | real, but blocked (needs hardware / a design decision / another dependency) — Resolution names the blocker + the tracking item |

**Per report** (the frontmatter `status:`):

| Status | Meaning |
|---|---|
| `open` | one or more findings are still `🔲 OPEN` |
| `in-review` | all findings triaged (`🔬`/beyond), some not yet closed |
| `resolved` | **every** finding is `✅ FIXED` / `☑️ ACCEPTED` / `🚫 INVALID` / `⏸ DEFERRED` (with a tracking link) |

**When you work through a report:** for each finding you handle, change its `Status:` line, append a one-line **Resolution** (what you did / a commit SHA + date, or why accepted/invalid), and — when nothing is left `🔲 OPEN` / `🔬 REVIEWED` — flip the report frontmatter `status:` to `resolved`. Cross-link the real work to `docs/work-todo.md` (which stays the master task list); this folder is the *review record*, work-todo is the *action list*.

## Catalogue

Newest first. Add a row when you file a report; update the Status/Findings cells as you work through it.

| Report | Surface | Date | Report status | Findings (open / handled) |
|---|---|---|---|---|
| [2026-07-adversarial-review-engagement](./2026-07-adversarial-review-engagement.md) | multi (playbook family build-out) | 2026-07-02..04 | `resolved` | 0 open / 11 handled (7 fixed, 1 accepted, 3 deferred) |
