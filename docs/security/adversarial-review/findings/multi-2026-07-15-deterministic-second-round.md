---
surface: multi
run_date: 2026-07-15
reviewer_role: supplemental
reviewer_identity: "Codex orchestrator — deterministic local verification only"
effort: "second-round executing gate sweep"
backend: "rustc/cargo 1.96.0-nightly; GNU Make 4.4.1; cargo-deny 0.19.9; repository-local verification tools"
scope: "Second round after multi-2026-07-14-local-closure-review; only additional confirmed mechanisms or materially new paths were eligible"
stage: implementation
frozen_identity: "sha256:6f87599b59303603254453480fde8542016bd06eef5dc625b3abc5eb3a626eb7"
status: resolved
---

# Multi-surface deterministic second round — 2026-07-15

## Result

**No additional confirmed finding was promoted.** The four open records in
[`multi-2026-07-14-local-closure-review.md`](./multi-2026-07-14-local-closure-review.md)
remain the live output of the preceding source review; this round neither
duplicates nor closes them.

This is an executing, deterministic follow-up, not a claim that the unexecuted
surfaces are sound. Two attempted LLM source-review legs were stopped after the
conversation visibility guard recurred. Their partial scratch output was
discarded and did not contribute evidence. The accepted evidence below comes
only from local commands with pass/fail receipts.

## Frozen target

| Field | Value |
|---|---|
| Branch | `fix/sweep-2026-07-14-findings` |
| HEAD | `ddc7cefc35cb54e324dac94330c6ee86f9383c90` |
| Tracked-diff SHA-256 | `05c626813fe90368880241f4ad2c1228cd2da1bbb38dc01c3849e5bf208e72e2` |
| Staged-diff SHA-256 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Untracked manifest/content SHA-256 | `19bb1212df8d6b5c13f1ec246e33e3b9eec5ae880edf9bed4095638803ff9a84` |
| STM32CubeU5 sibling | `a21e4110cd5a500b4223067652758129f030a6e8` (clean) |
| ERC-7730 registry sibling | `784c87c925e8438e7b4736b2af85a501f8d2a265` (clean) |
| Aggregate identity | `6f87599b59303603254453480fde8542016bd06eef5dc625b3abc5eb3a626eb7` |
| Final pre-catalogue drift check | `NO DRIFT` |

The target includes the pre-existing dirty worktree. Only the report and
catalogue mutation occur after the final drift check.

## Executed evidence ledger

| Check | Result | Defensive interpretation |
|---|---|---|
| `make test-unit` | PASS; 3,542 passed / 0 failed across emitted Rust test summaries | Broad host regression suite stayed green. |
| `cargo test -p pqsigner-proto --locked` | PASS; 109 / 0 | Protocol constants, framing, and negative cases stayed green. |
| `cargo test -p pqsigner-tx --locked` | PASS; 131 / 0 | Transaction parsing/formatting unit surface stayed green. |
| `cargo test -p pqsigner-erc7730 --tests --locked` | PASS; 192 / 0 | ERC-7730 parser/compiler/runtime unit surface stayed green. |
| `make invariant-gates` | PASS | Repository invariant checks accepted the frozen target. |
| `make verify-gate-enforcement` | PASS | Current workflow-to-gate enforcement manifest stayed consistent. |
| `make check-erc7730-descriptors` | PASS | Generated descriptor artifacts matched their sources. |
| `make check-solidity-constants` | PASS | Generated firmware/contract constants matched. |
| `make prod-feature-check` | PASS | Required/forbidden production feature checks remained active. |
| `make check-codegen` | PASS | Committed generated code matched regeneration checks. |
| `make test-formal-verification` | PASS | The repository formal-verification aggregate returned success. |
| `make test-solidity` | PASS; 115 / 0 | Contract test aggregate stayed green. |
| `cargo deny --offline check advisories` | PASS | The locally available advisory database reported no advisory error. This is not an online freshness claim. |
| `make checkct` | Expected non-zero | The documented Fisher-Yates negative control reported its by-design non-constant-time access pattern; the remaining emitted drivers reported secure. This is baseline FI4 behavior, not a new finding. |
| `make prod-check` | Expected non-zero | The aggregate stopped at the already-catalogued rollback/backend production fence. It did not silently produce a shipping-ready result. |

The aggregate SHA-256 over the sorted scratch-log digest manifest is
`97ea1009268c6802950eaf8d41b67edf43b2ff32ab487ed2f0de0e1dc43e8ccb`.

## Tool capability and stop receipts

| Capability | Disposition |
|---|---|
| Trailmark structural analysis | **NOT EXECUTED.** Neither `trailmark` nor the `uv run` fallback was available. Per the skill, nothing was installed and no manual graph result is presented as equivalent. |
| zeroize-audit | **STOPPED AT PREFLIGHT.** Root-manifest `cargo check` failed, so the skill correctly emitted no source/MIR/IR/assembly verdict. Preflight artifact: `/tmp/zeroize-audit-20260714220050-r2`, SHA-256 `660a9fbeab48c83e06eee028cb8afaeb66c81ef8077ae402718aba6ca6251a7c`. |
| LLM source-review legs | **DISCARDED.** Both were interrupted after the visibility guard recurred; no partial result was treated as evidence. |
| Hardware, FI injection, bus capture, SRAM remanence, and irreversible lifecycle work | **NOT EXECUTED.** No board or external state was touched. |

## Candidate disposition

No candidate met the threshold for a new `F1` record.

| Observed signal | Disposition |
|---|---|
| Aggregate constant-time target returned non-zero | Duplicate of the documented FI4 negative control; no regression in the other emitted drivers. |
| Aggregate production check returned non-zero | Duplicate of the known production rollback/backend release blocker. |
| Full offline `cargo deny check` reported license/source-policy errors | Not an advisory result and not promoted; the advisory-only check passed. License/source-policy cleanup remains a build-governance concern, not a newly demonstrated attack vector. |
| Prior four open closure records | Baseline; deliberately not refiled. |

## Coverage map

| Playbook family | Evidence exercised in this round | Honest boundary |
|---|---|---|
| Clear signing / off-chain / trusted UI | transaction and ERC-7730 suites; descriptor and constant regeneration | No independent display-on-hardware or new descriptor semantic walk. |
| USB / TrustZone gateway / runtime resources | protocol and broad unit suites; invariant gates | No independent CMSE source walk, interrupt injection, or USB stress run. |
| Firmware update / boot / lifecycle / silicon lockdown | production feature/fence checks and broad unit suite | No target boot, power-cut, option-byte, or SRAM-retention experiment. |
| Secure elements / entropy and key lifecycle | broad unit suite only | zeroize-audit stopped at preflight; no bus capture, silicon state, or compiler residue verdict. |
| SCA/FI | machine-code checkct aggregate rerun | The documented shuffle negative control remains intentional; no physical FI/TVLA. |
| On-chain / build-release / production configuration | 115 contract tests, formal aggregate, generated constants, gate enforcement, production feature checks, offline advisory check | No deployment, signing authority, publication, or network action. |
| Formal verification | repository formal aggregate and gate-enforcement check | A successful aggregate is not a new theorem audit or independent proof review. |

## What this round tried and could not falsify

- The host-visible protocol, transaction, ERC-7730, contract, generated-data,
  production-feature, and enrolled invariant gates remained green on the frozen
  packet.
- The production aggregate continued to stop at its known ship blocker.
- The constant-time aggregate continued to distinguish the documented negative
  control from the secure drivers.
- The locally available dependency advisory check returned clean.

These statements are limited to the named executions. They do not imply that
other code paths or physical behaviors are safe.

## Honest residual

- Trailmark graph analysis did not run.
- zeroize-audit produced no source, MIR, IR, or assembly findings because its
  mandatory build preflight failed.
- The visibility guard prevented completion of independent LLM source-review
  legs; no substitute identity or fabricated cross-review is claimed.
- No fuzz campaign, long-duration stress run, target cross-build matrix,
  QEMU end-to-end signing flow, hardware action, FI campaign, bus capture,
  deployment, network lookup, or irreversible ceremony ran.
- Existing open findings and release blockers remain open exactly as catalogued.

## Final disposition

Report status is `resolved` because this pass produced **0 findings**. It does
not resolve or supersede any earlier report.
