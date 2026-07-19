# FV adversarial-review kit (framework-agnostic)

The Ethereum-Foundation LLM swarm found real gaps in proofs and firmware we
*believed* were sound. This kit lets you re-run that adversarial pass **on
demand, with any LLM framework** — Claude Code, Codex, or a raw API — so the
review is not locked to one tool. It is the operational arm of
[`docs/verification/fv-adversarial-review-playbook.md`](../../../docs/verification/fv-adversarial-review-playbook.md).

It is a *discovery* layer. The *mechanical* anti-vacuity layer (which needs no
LLM and runs in CI) is the two gates `make verify-ledger-consistency` and
`make verify-proof-mutation`. Use both: the gates stop you re-discovering the
same vacuity; the swarm finds the next one.

## What's here

| file | role |
|------|------|
| `PROMPT.md` | the framework-neutral reviewer persona + the V1–V11 green-but-hollow catalog + strict output schema + a worked example. **The linchpin** — any backend reads this. |
| `protocol.json` | machine-readable: review **angles** (lean-vacuity, ledger-honesty, spec-faithfulness, crypto-soundness, firmware-fi, kani-decoder-vacuity), their target globs, discovery-reviewer/quorum defaults, backend command templates, the findings JSON schema. |
| `run_review.py` | thin backend-agnostic orchestrator: freeze target + prompt receipts → run N discovery passes via `$CMD` → parse strict JSON → corroborate/prioritize → final drift check → exclusive descriptor-relative publication with `completion.json` written last. It also creates deterministic lossless raw unions without re-voting. Pure stdlib. |
| `backends/{claude,codex,generic}.sh` | example invocations per framework (also usable as `--cmd` targets). |
| `tests/canned_findings.json` | fixture for the no-LLM self-test. |
| `tests/test_run_review.py` | pure-stdlib regressions for parsing, schema rejection, lossless receipts, namespaces, quorum bounds, and discovery-only authority. |

## Run it

```bash
cd contracts/verification/adversarial-review
OUT_ROOT="$(mktemp -d)" # MUST resolve outside the repository

# 0. Self-test the orchestration (no LLM, no cost) — proves the pipe + parse + corroboration path works:
python3 run_review.py --backend generic \
  --cmd 'cat tests/canned_findings.json' --self-test-ok \
  --run-id self-test --out "$OUT_ROOT"

# Also run the pure-stdlib regression suite:
python3 -m unittest discover -s tests -p 'test_*.py'

# 1. Claude Code (agent with file tools — reads the targets itself):
python3 run_review.py --backend claude --run-id partner-a-discovery \
  --out "$OUT_ROOT"

# 2. Codex CLI:
python3 run_review.py --backend codex --run-id partner-b-discovery \
  --out "$OUT_ROOT"

# 3. One angle only, broader discovery (3 passes, quorum 2):
python3 run_review.py --backend claude --angle ledger-honesty \
  --reviewers 3 --quorum 2 --run-id ledger-round-1 --out "$OUT_ROOT"

# 4. A raw API with no file tools — embed file contents:
python3 run_review.py --backend generic --inline-files \
  --cmd 'bash backends/generic.sh {prompt_file}' \
  --run-id raw-api-round-1 --out "$OUT_ROOT"

# 5. Preserve two completed raw receipts in one deterministic envelope.
# Use the exact namespaced paths printed by the two runs above.
CLAUDE_RAW="$(find "$OUT_ROOT/claude" -name raw.json -print -quit)"
CODEX_RAW="$(find "$OUT_ROOT/codex" -name raw.json -print -quit)"
python3 run_review.py --union-raw \
  "$CLAUDE_RAW" "$CODEX_RAW" --out "$OUT_ROOT"

# Inspect exactly what a backend will see (no call):
python3 run_review.py --dry-run --angle lean-vacuity
```

For an executing run, `--out` is mandatory and must resolve outside the
repository. Output lands under
`<out>/<backend>/<run-id>-<receipt-digest>/{report.md,findings.json,raw.json,completion.json}`.
Creating an existing run directory is an error: a rerun cannot overwrite prior
evidence. A successful normal run writes `completion.json` last, after it has
bound the length and SHA-256 of every preceding artifact. A directory without
that terminal marker is incomplete. A failed, timed-out, invalid-output, or
drifted run writes only `raw.json` plus a failed `completion.json`; it never
publishes or prints success-shaped `findings.json` / `report.md` output.

`raw.json` preserves every candidate, honest residual, byte-exact
stdout/stderr as base64 + SHA-256 + length receipts, return code, timeout and
parse status, all invocation settings, selected-angle/prompt/target hashes,
Git HEAD/tree/status, and the final drift check. Invalid UTF-8 is retained but
never replacement-decoded into a parseable answer. Each raw finding
receives a deterministic `_origin_id`; within-run aggregation retains every
variant and origin ID so fuzzy grouping cannot erase disagreement.

The initial/final comparison detects endpoint drift; it cannot prove that a
concurrent writer did not change bytes and restore them between captures.
Therefore the planning workflow's **stop all writers** rule is load-bearing,
not replaced by this receipt.

Origin IDs are namespaced by backend and `--run-id`. Give every invocation a
distinct, stable `--run-id`. `--union-raw` accepts only the current explicit
non-self-test raw format and requires each input to be the `raw.json` beside a
terminal `completion.json` that binds its namespace, invocation, byte length,
and SHA-256. It rejects legacy/unclassified receipts and duplicate run
namespaces, sorts by namespace, embeds each complete raw payload and its source
SHA-256, and writes a content-addressed union with exclusive-create semantics.
It performs **no cross-run grouping, voting, or disposition**. The envelope may
intentionally contain completed failed, timed-out, or drifted discovery runs
and is not an attestation that every enclosed review succeeded. Repeating the
same union therefore refuses to clobber the first copy rather than silently
replacing it.

`--self-test-ok` is a separate fixture mode. It may use the canned command that
does not read a prompt, but its receipt is marked `self_test_only`, it emits no
normal findings/report artifacts, and `--union-raw` rejects it. Every executing
normal backend template must contain the literal `{prompt_file}` placeholder;
requested angles are exact (any unknown ID rejects the whole run) and retain
the caller's first-occurrence order.

The runner can prove that it supplied the prompt file, not that an arbitrary
operator-supplied `generic --cmd` actually used its contents. Backend-command
provenance therefore remains a coordinator trust boundary. The built-in canned
fixture has a reserved finding ID and is rejected from normal discovery even
if a wrapper reads and discards the prompt before emitting it.

## Discovery is not disposition

`--quorum` is a discovery-prioritization threshold only. A corroborated
candidate is not thereby `CONFIRMED`, and a sub-quorum candidate is not thereby
`REFUTED` or discarded. This kit never emits cross-review dispositions and
never authorizes implementation, merge, acceptance, or shipment.

For security-sensitive architecture and implementation, send **every**
candidate, retained variant, origin ID, and honest residual to the exact
Partner-A/Partner-B pair required by
[`docs/planning-and-review-workflow.md`](../../../docs/planning-and-review-workflow.md).
Only that pair's symmetric cross-adjudication may assign
`CONFIRMED`/`REFUTED`/`NARROWED`/`UNRESOLVED`, with disagreements preserved. A
majority of swarm passes cannot replace or override that protocol.

## How it works (and why it's portable)

A **backend** is any shell command that reads the assembled prompt (the
required `{prompt_file}` placeholder is shell-safely substituted with a temp
path) and writes one
strict UTF-8 JSON answer to stdout. Runtime logs must go to stderr; any
non-whitespace stdout wrapper, fence, preamble, trailer, second value, or
truncated value rejects the pass. That's the entire contract. `claude -p` and `codex exec`
satisfy it as agents that read the listed target files themselves; a raw model
satisfies it with `--inline-files` (contents embedded). To add a framework, add
one line to `protocol.json` → `backends`, or pass `--cmd`.

The **schema is the portability primitive**, not the orchestrator. Every backend
must emit exactly one unwrapped `{ "findings": [...], "honest_residual": "..." }`
object per `PROMPT.md`. Nested/wrapped/fenced answers, multiple answers, a
valid answer followed by any other value or malformed fragment, and unknown
fields are rejected. In particular,
discovery output cannot smuggle disposition, status, approval, or stage-verdict
authority. The mandatory `honest_residual` enforces the eliminative-argumentation
discipline: the review names what it could *not* check, so "it found nothing"
never reads as "there is nothing."

## Cadence

- **Every PR touching proofs/firmware-gates:** the two mechanical gates in CI.
- **Before a release / after a big proof refactor / quarterly:** this discovery
  swarm, `--reviewers 3 --quorum 2`, ideally across **two** backends (Claude
  *and* Codex) so a single model's blind spot doesn't become yours; then submit
  the union to the required exact dual-review pair for disposition.
- **The honest residuals are the to-verify list.** Triage them; promote real
  ones to GitHub issues on `EthereumPhone/PQ1` (label `source:work-todo`, plus
  `priority:*` / `surface:*` as relevant). Do not file the report and feel safe.

## What this does NOT do

It surfaces discovery candidates; it neither dispositions nor gates them, and
it is not a proof. **V7** (a
latent-FALSE axiom that still type-checks) and **V11** (the proof is sound but of
the *wrong* property) survive any single pass — no tool catches them; only
diverse, repeated, genuinely-external review narrows them. Treat a clean report
as "this pass found nothing," never as "the system is sound."
