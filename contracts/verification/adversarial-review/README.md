# FV adversarial-review kit (framework-agnostic)

The Ethereum-Foundation LLM swarm found real gaps in proofs and firmware we
*believed* were sound. This kit lets you re-run that adversarial pass **on
demand, with any LLM framework** — Claude Code, Codex, or a raw API — so the
review is not locked to one tool. It is the operational arm of
[`docs/fv-adversarial-review-playbook.md`](../docs/fv-adversarial-review-playbook.md).

It is the *judgement* layer. The *mechanical* anti-vacuity layer (which needs no
LLM and runs in CI) is the two gates `make verify-ledger-consistency` and
`make verify-proof-mutation`. Use both: the gates stop you re-discovering the
same vacuity; the swarm finds the next one.

## What's here

| file | role |
|------|------|
| `PROMPT.md` | the framework-neutral reviewer persona + the V1–V11 green-but-hollow catalog + strict output schema + a worked example. **The linchpin** — any backend reads this. |
| `protocol.json` | machine-readable: review **angles** (lean-vacuity, ledger-honesty, spec-faithfulness, crypto-soundness, firmware-fi), their target globs, reviewer/quorum defaults, backend command templates, the findings JSON schema. |
| `run_review.py` | thin backend-agnostic orchestrator: assemble prompt → run N reviewer passes via `$CMD` → parse JSON → cross-vote → `out/report.md`. Pure stdlib. |
| `backends/{claude,codex,generic}.sh` | example invocations per framework (also usable as `--cmd` targets). |
| `tests/canned_findings.json` | fixture for the no-LLM self-test. |

## Run it

```bash
cd contracts/verification/adversarial-review

# 0. Self-test the orchestration (no LLM, no cost) — proves the pipe + parse + vote works:
python3 run_review.py --backend generic --cmd 'cat tests/canned_findings.json' --self-test-ok

# 1. Claude Code (agent with file tools — reads the targets itself):
python3 run_review.py --backend claude

# 2. Codex CLI:
python3 run_review.py --backend codex

# 3. One angle only, stronger cross-vote (3 passes, majority):
python3 run_review.py --backend claude --angle ledger-honesty --reviewers 3 --quorum 2

# 4. A raw API with no file tools — embed file contents:
python3 run_review.py --backend generic --inline-files \
    --cmd 'bash backends/generic.sh {prompt_file}'

# Inspect exactly what a backend will see (no call):
python3 run_review.py --dry-run --angle lean-vacuity
```

Output lands in `out/report.md` (confirmed vs sub-quorum findings, grouped by
angle, **with every reviewer's honest-residual block**) and `out/findings.json`.

## How it works (and why it's portable)

A **backend** is any shell command that reads the assembled prompt (the
`{prompt_file}` placeholder is substituted with a temp path) and writes a JSON
answer to stdout. That's the entire contract. `claude -p` and `codex exec`
satisfy it as agents that read the listed target files themselves; a raw model
satisfies it with `--inline-files` (contents embedded). To add a framework, add
one line to `protocol.json` → `backends`, or pass `--cmd`.

The **schema is the portability primitive**, not the orchestrator. Every backend
must emit `{ "findings": [...], "honest_residual": "..." }` per `PROMPT.md`. The
mandatory `honest_residual` enforces the eliminative-argumentation discipline:
the review names what it could *not* check, so "it found nothing" never reads as
"there is nothing."

## Cadence

- **Every PR touching proofs/firmware-gates:** the two mechanical gates in CI.
- **Before a release / after a big proof refactor / quarterly:** this swarm,
  `--reviewers 3 --quorum 2`, ideally across **two** backends (Claude *and*
  Codex) so a single model's blind spot doesn't become yours.
- **The honest residuals are the to-verify list.** Triage them; promote real
  ones to `docs/work-todo.md`. Do not file the report and feel safe.

## What this does NOT do

It surfaces candidates; it does not gate and it is not a proof. **V7** (a
latent-FALSE axiom that still type-checks) and **V11** (the proof is sound but of
the *wrong* property) survive any single pass — no tool catches them; only
diverse, repeated, genuinely-external review narrows them. Treat a clean report
as "this pass found nothing," never as "the system is sound."
