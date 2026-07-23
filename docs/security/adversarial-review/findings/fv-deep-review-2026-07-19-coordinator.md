---
surface: fv
run_date: 2026-07-19
reviewer_role: supplemental
reviewer_identity: "Kimi K3 coordinator-led deep review (6 executing sub-agent passes + coordinator reproduction), with mutually withheld refutation passes by Claude Opus 4.8 and GPT-5.6 SOL; remediation executed same-day"
effort: "executing full-stack review: gates, registries, CI wiring, Lean claim-vs-theorem, Kani census, protocol/crypto models, git archaeology; plus a four-lane external SOTA research sweep; plus full remediation of all 13 findings"
backend: "Kimi Code (K3); Claude Code 2.1.215 (opus); codex-cli 0.144.5 (gpt-5.6-sol, ultra); Lean 4 v4.22.0 (elan); Kani; ProVerif 2.05; Tamarin 1.12.0; Verus; TLC; charon/aeneas (nightly-2026.06); halmos 0.3.4.dev0 + z3 4.16.0; gh"
scope: "Nine-surface FV/assurance stack post-2026-07-15 remediation: F1–F11 remediation status, gate/CI enforcement, claim-vs-theorem fidelity, Kani/mutation coverage, protocol-model pins, doc/tracker sync"
stage: assurance-review (no implementation candidate)
frozen_identity: "review froze master HEAD fba805ce; remediation landed on the live tree (see per-finding Resolutions)"
status: resolved
---

# FV deep adversarial review — coordinator synthesis — 2026-07-19

## Summary

This review re-examined the FV stack four days after the 2026-07-15 full-stack
review's remediation commit (`90867499`) and the 2026-07-16→17 expansion
pilots, with execution wherever cheap (gates, self-tests, live prover runs,
`gh`, git, Kani harnesses, one TLC config, one Verus build), followed by
mutually withheld refutation passes from Opus 4.8 and GPT-5.6 SOL over the
12-candidate packet. **All 13 findings were remediated the same day** — see
the per-finding Status/Resolution lines and the Resolution log. The remaining
residuals are external or filed follow-ups: CI billing (#456), the live
Kontrol prover run (#197), nanoda_lib (#466), and the Aeneas digest
extraction (#467).

Calibrated conclusion:

- **Proof content:** strong where scoped. The Lean headline closures match the
  ledger exactly (live `#print axioms` on 13 theorems); the F3 `Evil : False`
  canary fires; protocol models pass live (ProVerif 6/6, Tamarin 3/3); the
  EasyCrypt docker gate compiles the closure as targets with zero skips; the
  Kani census is accurate; the Verus flash-journal model verifies 8/8. The
  12 pilot docs are unusually honest and their artifacts exist as cited.
- **Assurance system at review time:** **failing at the top.** Every GitHub CI
  workflow failed in 3–5 s on an account billing outage since ~2026-07-16
  (nightly since ~2026-06-30), and the `verify-extraction-freshness` gate was
  red on master with 65 commits on top.
- **Assurance system after same-day remediation:** the freshness gate is
  **green** (16 fresh + 1 loudly waived; re-extraction proved the drift was
  docstring-only), the registry is floor-guarded and self-policing, both new
  extract targets regen byte-exactly, the digest pin is three-way
  (Rust↔Solidity↔Lean), the Kani gap on `format_decimal` is closed with a
  mutation-pinned exact harness, the Halmos floor + receipt now cover all 42
  wired rules on both profiles, the Kontrol identity baseline pins all 33
  proofs, the docs/ledger contradictions are corrected, and the LeanLoop
  `vet` misclassification is fixed (113/113 tests).
- **Promotion verdict:** upgraded to **blocked-on-CI-execution only** — the
  gates are green *locally*; until GitHub Actions is restored and one full
  nightly + one clean per-PR run execute, "CI-gated" remains a local-run claim
  (F1 residual, external). No implementation candidate was reviewed; no
  merge/production authority follows.
- **The remaining frontier is correspondence, not more provers:** the
  Aeneas-generated digest bridge (#467) and the nanoda_lib axiom-allowlist
  (#466) are filed as the two follow-up research items.

Refutation outcome: **12/12 candidates CONFIRMED or CONFIRMED-with-narrowing by
at least one partner; none REFUTED** (one Verus sub-item of C11 was refuted by
both partners and dropped). Two genuinely new defects came back from the
partners (folded into F5 and F13). A third-party count correction landed
during remediation: the 2026-07-18 sweep's "38 Kontrol `prove_` functions" was
a **miscount** — the tree has 33 (KONTROL_SCOPING's 33/33 was right all
along).

## Resolution log (2026-07-19, same-day remediation)

| Finding | Disposition | Tracker |
|---|---|---|
| F1 dead CI | ✅ FIXED in-repo (STATUS evidence-gap banner + local pre-merge gate list); billing restoration is external | #456 (open, commented) |
| F2 red freshness gate | ✅ FIXED — re-extracted aa-userop (drift was `Source:` docstring lines only; V6 batch functions outside the extraction closure); lake build + `verify-extracted` green; re-pinned; gate exits 0 | #194 closed |
| F3 registry deletion-tolerant | ✅ FIXED — required_targets floor, zip length-match hard fail, on-disk completeness floor, per-target `--update` refusing silent re-pin of waived entries, registry in its own CI paths + polices_paths; 6 self-test negatives fire | #457 closed |
| F4 PinState/SlotKdf unpoliced | ✅ FIXED — `extract-pinstate`/`extract-slotkdf` targets regen byte-exactly (PinState re-baselined after the TROPIC01-removal move; bodies byte-identical, proofs green); registry + polices_paths enrolled | #458 closed |
| F5 lean4checker decorative+incapable | ✅ FIXED (honest-scope) — relabeled independent kernel/environment replay (NOT closure recomputation), enrolled `local_documented`, claims corrected in script/Makefile/ledger/THE_CLAIM; nanoda_lib allowlist follow-up filed | #459 closed; #466 filed |
| F6 Lean preimage unpinned | ✅ FIXED (gate half) — field-order pin is now three-way (Rust↔Solidity↔Lean) with a firing Lean-swap negative; stale docstring citation fixed; Aeneas digest extraction filed | #460 closed; #467 filed |
| F7 BreaksHash entailment unstated | ✅ FIXED — entailment paragraph in THE_CLAIM.md + the axiom's ledger detail | #461 closed |
| F8 README A3.1 contradiction | ✅ FIXED — README corrected to discharged-bytecode (tier C corpus); ledger headline prose SUPERSEDED-marked; JSON re-validated | #462 closed |
| F9 Halmos/Kontrol receipts+floors | ✅ FIXED — `run_halmos.sh` pins EXPECTED_RULES=42 across 8 named harnesses (inventory + per-harness execution + total floor + self-test); **full receipt run: 42/42 PASS on both profiles** incl. G8/EIP-1271 (`halmos/sessions/halmos-session-2026-07-19.txt`); `run_kontrol.sh` pins all 33 expected proof ids (count floor + per-id grep + fixture-validated self-test); counts reconciled (33, not the sweep's 38) | #463 closed; #197 open for the live run |
| F10 format_decimal weak evidence | ✅ FIXED — new `format_decimal_exact_on_boundaries` Kani harness (12 boundary cases, SUCCESSFUL) + 3 mutation pins each proven to fail it (the old charset harness proven blind as the vacuity control); census lock 163/26, file enrolled | (no issue; evidence in-tree) |
| F11 doc drift | ✅ FIXED — STATUS.md (counts, CI banner, EasyCrypt UPDATE), FV_SURFACE_MAP.md (snapshot + fixed rows + 7 pilot rows), OPEN_PROOF_OBLIGATIONS.md aligned | #464 closed |
| F12 LeanLoop vet misclassification | ✅ FIXED — `spec_vet.py` RED now requires exit 0 + no error text (exit codes threaded through `run_scratch_file`); 3 new regression tests; full suite 113/113 | LeanLoop repo |
| F13 gate self-policing + floors | ✅ FIXED — census lock, mutations manifest, extraction registry added to their gates' polices_paths; completeness floor (16/16 modules pinned); 28-gate manifest green | #465 closed |
| (carried) FV15-F3/F5/F7/F8/F11 | ✅ closed with the 2026-07-16 remediation evidence + 2026-07-19 re-verification | #413–#417 closed |

## Method and evidence receipts

Six adversarial sub-agent passes (Lean tree; gates/registries/CI; Kani census;
protocol/crypto models; pilot docs; git archaeology), each required to execute
negative controls; coordinator re-execution of the load-bearing claims; four
web-research lanes (delivered separately in
[`docs/verification/fv-sota-newly-possible-2026-07-19.md`](../../../verification/fv-sota-newly-possible-2026-07-19.md)).

Raw packets (frozen outside the reviewed target, per the catalogue rules):
candidate packet `/tmp/fv-review-2026-07-19/candidates.md` SHA-256
`f6fa756a537f4d987659348d92fd8be7f80aafedcef2c0809936b85c9b482abf`;
Opus refutation `/tmp/fv-review-2026-07-19/opus-refutation.md` SHA-256
`fc3279f38aada79bd3dbc98e59be279eada111e4be2677c3b090a01f8d43f54a`;
GPT-5.6 SOL refutation `/tmp/fv-review-2026-07-19/gpt-refutation.md` SHA-256
`508076bb43a88e1111a877cc7f11e33853410fcbcc3232aff5debbab6894fa82`.
The passes were mutually withheld; both refuters had the same bounded prompt
(refute, verify against the live tree, read-only).

| Execution | Result |
|---|---|
| `check_extraction_freshness.py` on master | **exit 1 at review time** (`extract-aa-userop` drifted) → **exit 0 after remediation** (16 fresh + 1 loudly waived; registry floors OK) |
| `gh run list` (ci.yml, nightly.yml) | all recent runs fail in 4–5 s; nightly dead since ~2026-06-30; zero runs on the last 4 master commits (coordinator run; re-executed by Opus incl. the billing annotation) |
| `git log 94bb2e9a..HEAD` | **65 commits** landed on the red gate (coordinator run; re-executed by GPT-5.6) |
| registry deletion PoCs | empty registry → exit 0; deleting the drifted entry → exit 0; emptied pin list → exit 0 (agent-executed; re-executed in-memory by both partners) — **all three now fail the new floors** |
| Live `#print axioms` (13 theorems) | closures exactly match `AXIOM_STATUS.json`; `execC10Asm_eq` and `reachable_implies_combinedCap` kernel-only (agent-executed) |
| `check_axiom_closure.py --manifest` + `AxiomCheckNegativeControl.lean` | `Evil : False` rejected; dropped headline rejected; clean 66-headline dump accepted (agent-executed; re-verified after re-extraction) |
| `check_protocol_models.py --self-test`; live ProVerif/Tamarin | self-test negatives all fire; ProVerif 6/6 models, Tamarin 3/3 models pass live (agent-executed) |
| `cargo verus verify` | 8 verified, 0 errors, live (agent-executed; 7 `proof fn`s + the recursive `proj` termination obligation = Verus's 8) |
| TLC on one pinned config | 84,776 states, no error (agent-executed) |
| Kani: `rollback_boundary`; census; `format_decimal_exact_on_boundaries` | `VERIFICATION:- SUCCESSFUL` (both harnesses); census 163/26 matches `kani_census.py` |
| `check_sphincs_digest_field_order.py{,--self-test}` | three-way pin live (Rust↔Solidity↔Lean); Lean-swap negative fires (new, F6) |
| EasyCrypt `--self-test` + docker receipt | semantic pins fire (`dmkey_ll:false` caught); 21-file closure compiled as targets, zero skips, 3 controls fired (2026-07-17 receipt; pins re-verified live) |
| `verify-extraction-regen` (post-remediation) | 16 fresh targets re-extract + diff clean (incl. new `extract-pinstate`/`extract-slotkdf`); tx-merkle waiver unchanged |
| LeanLoop `pytest tests/` (post-remediation) | 113/113 pass, incl. 3 new F12 regression tests (unsolved-goals/timeout/nonzero-exit → skip, never RED) |
| `make verify-ledger-consistency verify-fv-lints` (post-remediation) | every advertised closure/count/status/headline pin matches the live Lean truth; all four FV lints green |
| Halmos full suite (post-remediation) | **42/42 PASS on both profiles** (default + deploy), codehash certification green, incl. the 3 G8/EIP-1271 rules; receipt `halmos/sessions/halmos-session-2026-07-19.txt`; floor fixtures: zero-PASS and missing-harness both rejected |

## 2026-07-15 F1–F11 remediation status (the follow-up the catalogue lacked)

| Finding | Status now | Evidence |
|---|---|---|
| F1 extraction freshness | **FIXED** | tripwire + registry built in `90867499`; the 2026-07-18 aa-userop drift re-extracted + re-pinned 2026-07-19 (gate green); registry floor-guarded (F3) |
| F2 headline proves tooling hash | **PARTIAL → gate-half FIXED** | theorem relabeled tooling-only (`90867499`); Rust↔Solidity↔Lean field-order pin live (F6); Aeneas digest extraction filed as #467 |
| F3 arbitrary axiom accepted | **FIXED (verified live)** | per-headline manifest + `Evil` canary, executed |
| F4 legacy PQFW_V1 as current | **FIXED (docs)** | LEGACY/NONSHIPPING labels in `ASSURANCE_CASE.md`; V4/V6 owner conflict still open by design |
| F5 EasyCrypt skips/count-pins | **FIXED** | `--full` zero-skip; semantic axiom pins; docker gate; enrolled as `local_documented` |
| F6 WOTS excludes C10 params | **PARTIAL (research, advanced)** | C10-concrete capstone vendored + container-gated; seam branch certified 0-admit; FORS+C leg open; conditional composition |
| F7 protocol driver | **FIXED (scoped)** | exit codes enforced; per-query identity pins; **F52 (tracker #197) carries the Kontrol leg** |
| F8 deletion-tolerant registries | **FIXED** | ledger floors (`90867499`) + extraction-registry floors (2026-07-19, F3/F13) |
| F9 claim precision | **FIXED (docs)** | corrections landed; the 2026-07-19 drift instances fixed in F11 |
| F10 LeanLoop `vet` misclassification | **FIXED 2026-07-19 (F12)** | `spec_vet.py` requires exit 0 + no error text for RED; 113/113 tests |
| F11 Kani census incomplete | **FIXED** | source-generated census + lock, CI per-PR (inoperative while F1-CI stands) |

## Findings

Dispositions: coordinator-confirmed with executed PoCs, cross-checked by two
mutually withheld refutation passes (per-finding verdicts in the table at the
end). Overlaps with the 2026-07-18 sweep (F49–F54) are named. Resolutions
name the exact correction and its evidence.

### F1 — The entire CI enforcement layer is dead; every "CI-gated/blocking" claim is currently advisory

- **Status:** ✅ FIXED (in-repo half) — **Resolution:** STATUS.md now carries the 2026-07-19 evidence-gap banner (CI dead since ~2026-07-16, nightly since ~2026-06-30; all "CI-gated" rows are local-run claims until the first green run after restoration) and the local pre-merge gate list below. The external half (billing restoration + one full nightly + clean per-PR run) is outside repository authority and stays tracked in issue #456 (commented).
- **Mode / severity:** G1/G4 (gate-enforcement vacuity, one level up) · **HIGH**
- **Location:** `.github/workflows/` (8 workflows; the FV-critical ones are `ci.yml`, `lean-fv.yml`, `lean-extracted.yml`, `nightly.yml`).
- **Mechanism:** the FV workflows fail in 3–5 s on every trigger since ~2026-07-16 (nightly since ~2026-06-30) with a billing annotation ("The job was not started because recent account payments have failed" — Opus re-executed); jobs never start. Recent master commits (`94bb2e9a`, `4c76a6a6`, `5382df8f`, `fba805ce`) have **zero** CI runs.
- **Consequence:** Kani nightly (163 harnesses + 37 mutations), Miri, census, protocol models, verify-repro, ledger consistency — none have executed for ~3 weeks. The entire ERC-7730 wave (+15 harnesses) has never been Kani'd in CI.
- **PoC:** `gh run list --workflow {ci,nightly}.yml --limit 4` — 4–5 s failures (coordinator + Opus, independently).
- **Classification:** FIX NOW (external: billing; in-repo: document honestly).
- **Local pre-merge gate list (while CI is down)** — run on the exact candidate:
  ```
  python3 scripts/check_gate_enforcement.py                 # G1 wiring
  (cd contracts/verification && python3 scripts/check_extraction_freshness.py --self-test && python3 scripts/check_extraction_freshness.py)
  python3 scripts/kani_census.py
  make -C contracts/verification verify-ledger-consistency verify-fv-lints verify-audit
  make -C contracts/verification verify-transcription verify-extracted
  python3 contracts/verification/scripts/check_protocol_models.py   # needs proverif/tamarin
  cargo test -p sphincs-tz-secure --tests --release
  make prod-check
  # nightly-class when the diff touches their surfaces:
  make kani ; make miri ; make verify-kani-mutation ; make verify-repro
  ```

### F2 — The F1 freshness gate is red on master and 65 commits merged over it (dup sweep-F49 / tracker #194 — re-confirmed live)

- **Status:** ✅ FIXED — **Resolution:** re-extracted `aa-userop` with the pinned toolchain (2026-07-19): the regen diff was **`Source:` docstring line numbers only** — the V6 batch-commitment functions are outside the `compute_user_op_hash` extraction closure (zero non-docstring diff). `lake build` green (1767 jobs), `make verify-extracted` green (66/66 headline closures + the Evil:False control), re-pinned via `--update extract-aa-userop`. `check_extraction_freshness.py` now exits 0. Closes #194. The process question (how 65 commits merged over a red gate) is answered structurally by F1's checklist + the registry's self-policing paths (F3/F13): the gate now also fires on registry-only edits.
- **Mode / severity:** G1/V9 · **HIGH**
- **Location:** `extraction_registry.json`, `aa/src/userop.rs`, `contracts/verification/extracted/Extracted/UserOp/`.
- **Mechanism (at review time):** `94bb2e9a` (2026-07-18) rewrote `userop.rs` (+366 lines incl. the V6 batch-commitment functions) without re-extracting or re-pinning; the committed `Extracted/UserOp` proved a pre-V6 artifact. The gate was declared `per_pr_blocking`; 65 commits landed since. (GPT's scope note: coarse whole-file sha256 drift; theorem-body drift not demonstrated — confirmed by the regen: none existed.)
- **PoC:** `python3 contracts/verification/scripts/check_extraction_freshness.py` → exit 1 (coordinator + GPT-5.6, independently, at review time); exit 0 after remediation.

### F3 — The extraction registry is deletion-tolerant and self-referential

- **Status:** ✅ FIXED — **Resolution:** `check_extraction_freshness.py` now hard-fails on (a) a shrunk registry (`required_targets` floor), (b) list length mismatch (no more `zip` truncation), (c) any on-disk `Extracted/*/Funs.lean` missing from the registry (completeness floor); `--update` requires a target and refuses to silently re-pin waived entries (`--waived-ok` override); `extraction_registry.json` is in `lean-extracted.yml` paths + the gate's `polices_paths`; pins extended to `Types.lean`/`FunsExternal.lean` for every module (F54, incl. the load-bearing `UserOp/Types.lean`). Six self-test negatives fire; live gate green. Closes #457 and #199.
- **Mode / severity:** G1 · **MED-HIGH**
- **Location:** `contracts/verification/scripts/check_extraction_freshness.py`, `extraction_registry.json`, `.github/workflows/lean-extracted.yml`.
- **Mechanism (at review time, each executed by at least two parties):** (a) no required-ID floor — an empty registry exited 0; deleting the drifted entry flipped red→green; (b) `zip()` silently truncated a dropped pin; (c) `--update` re-pinned all entries including the waived one; (d) the registry appeared in no CI `paths:` and no `polices_paths`. GPT's sharpening folded in: `-split-files` outputs diffed only `Funs.lean` while `UserOp/Types.lean:24-38` defines the load-bearing parameter structure.

### F4 — SlotKdf (and low-stakes PinState) extractions are outside the freshness system — prospective, not current, staleness

- **Status:** ✅ FIXED — **Resolution:** `extract-pinstate` and `extract-slotkdf` Makefile targets exist and produce **byte-exact diffs** (`verify-extraction-regen` runs 16 fresh targets green incl. both). SlotKdf was byte-identical on first regen; PinState was re-baselined (the 06-26 extraction predated the TROPIC01 removal and its `Chunks` impl needed the project-standard hand-completion, now reproduced by the target's sed — function bodies byte-identical throughout, `lake build` + `PinStateSpec` green, no proof edits). Registry entries carry Types/FunsExternal symmetry pins and "freshness ESTABLISHED 2026-07-19" notes; `domain/src/**` is in the gate's `polices_paths`. Closes #458.
- **Mode / severity:** V9/G1 · **MED**
- **Location:** `contracts/verification/extracted/Extracted/{PinState,SlotKdf}/`; `domain/src/`; `contracts/verification/Makefile`.
- **Mechanism (at review time):** no `extract-*` target, no registry entry; `lean-extracted.yml:36` triggered on `domain/src/**` but the gate had nothing to compare ("vacuous, not unwired", Opus). GPT verified current bodies matched the extractions (no stale-proof defect existed); PinState is a non-production parser (one theorem), SlotKdf the load-bearing gap.

### F5 — The `#print axioms` under-report backstop is unenrolled, stale, and structurally incapable of the job it's named for

- **Status:** ✅ FIXED (honest-scope) — **Resolution:** lean4checker is now relabeled everywhere as an **independent kernel/environment replay, NOT an axiom-closure recomputation** (`run_lean4checker.sh` header, `check_ledger_consistency.py` scope note, `contracts/verification/Makefile` comment + target help, `THE_CLAIM.md`); enrolled in `gate_enforcement.json` as `local_documented` (28-gate manifest green); the ledger records that the tree now has 59 modules with the last replay at 58 (exact-HEAD replay pending). The follow-up replacement — nanoda_lib with a 3-axiom `permitted_axioms` allowlist in CI — is filed as issue #466. Closes #459.
- **Mode / severity:** G1/G4 · **MED-HIGH**
- **Location:** `contracts/verification/Makefile`, `contracts/verification/scripts/run_lean4checker.sh`, `check_ledger_consistency.py`, `scripts/gate_enforcement.json`.
- **Mechanism (at review time):** (a) enrolled nowhere (grep-verified); (b) manual and stale (last recorded replay 07-15 over 58 modules); (c) structurally incapable (GPT, source-verified): `run_lean4checker.sh` checks only replay exit status and lean4checker's Replay re-adds referenced `.axiomInfo` as legal axioms — the #8840 omission shape survives it.

### F6 — The Lean digest `theft_free` quantifies over is hand-mirrored; no machine pin binds it to Rust/Solidity (gate gap, not a live mismatch)

- **Status:** ✅ FIXED (gate half) — **Resolution:** `check_sphincs_digest_field_order.py` now parses all three sources — Rust `compute_sphincs_digest_v06`, Solidity `sphincsDigest`, and Lean `sphincsDigestPreimage` — and fails on any one-sided reorder/insert/delete (live: three orders match; self-test: the Lean `call_gas_limit`/`verification_gas_limit` swap fires, F6's exact gap). The stale Lean docstring citation ("Solidity lines 326-343") is replaced by a reference to the gate. The full fix (Aeneas extraction of `compute_sphincs_digest_v06`, generating the Lean def from Rust) is filed as issue #467. Closes #460.
- **Mode / severity:** V9 · **MED**
- **Location:** `contracts/verification/lean/SphincsCVerify/Wallet/ValidateUserOp.lean:254-279`; `contracts/verification/scripts/check_sphincs_digest_field_order.py`.
- **Mechanism (at review time):** the field-order gate pinned Rust↔Solidity only; `SphincsDigestSpec.lean` proves properties relative to the same Lean definition; an equal-width reorder in the Lean def escaped every gate. Opus verified the order is currently correct three ways (gate gap, not a live bug).

### F7 — The `∨ BreaksHash` axiom family is standard-model-trivial; the claims docs never state the entailment

- **Status:** ✅ FIXED — **Resolution:** `THE_CLAIM.md` now carries the entailment paragraph ("What the `∨ BreaksHash` shape means — read this before quoting the binding theorems") and `AXIOM_STATUS.json`'s `sha256_collision_resistance` ledger detail carries the same note: the axiom set entails `BreaksHash` in the standard model (pigeonhole over the concrete kernel `sha256`), so every `X ∨ BreaksHash` theorem is a **constructive reduction** ("`X`, or an exhibited hash break"), never unconditional assurance. Closes #461.
- **Mode / severity:** V11 (honesty/scope) · **MED** (not soundness — no kernel detonation)
- **Location:** `contracts/verification/lean/SphincsCVerify/Crypto/Assumptions.lean:204`, `contracts/verification/docs/{THE_CLAIM.md,AXIOM_STATUS.json}`.
- **Mechanism:** `sha256_collision_resistance` quantifies over the concrete kernel `sha256`; distinct same-length colliding inputs exist in every model (2^264 → 2^256), so instantiating the axiom at a colliding pair yields `false ∨ BreaksHash`. The axiom's docstring already went halfway; the claims docs never stated the consequence.

### F8 — `contracts/verification/README.md` still declares the A3.1 axiom "false as stated", contradicting its own resolution records

- **Status:** ✅ FIXED — **Resolution:** README's A3.1 rows now read `discharged-bytecode` (**tier C — corpus**) with the 2026-06-13 closure named (`chainHash` ADRS field; `loadWord32` tail window) and the ∀-symbolic ceiling as the honest residual; the stale ⚠️ block (README:231-242) is corrected; `AXIOM_STATUS.json`'s `headline_status_explanation` is prefixed SUPERSEDED with the pointer to the resolved per-axiom status. JSON re-validated. Closes #462.
- **Mode / severity:** V5 (ledger honesty) · **MED**
- **Location:** `contracts/verification/README.md:57-68, 231-242`; `contracts/verification/docs/AXIOM_STATUS.json:191`.
- **Mechanism (at review time):** the headline README asserted "contradicted by a concrete KAT vector" one field away from records saying the opposite, and was internally self-contradictory (Opus: `:204-217` vs `:233`).

### F9 — Halmos receipts trail the wired rules (42 vs 38); the runner has no PASS-count floor; Kontrol has no identity baseline

- **Status:** ✅ FIXED — **Resolution:** (a) `run_halmos.sh` now pins `EXPECTED_RULES=42` across the 8 named harnesses — pre-run tree-vs-pin inventory check, per-harness execution assertion, total `[PASS]` floor, and a `--self-test` (zero-PASS and missing-harness fixtures both fail); the executed set and the floor can't drift (the `--match-contract` regex is derived from the pinned list). (b) **Full receipt run executed: 42/42 PASS on both profiles** (default + deploy, halmos 0.3.4.dev0 + z3 4.16.0, codehash certification green) incl. the 3 G8/EIP-1271 rules — receipt at `contracts/verification/halmos/sessions/halmos-session-2026-07-19.txt`. (c) `run_kontrol.sh` now pins all 33 expected proof ids with a count floor + per-id grep + a fixture-validated `--self-test`. (d) Count truth established: **33 `prove_` functions** (ValidateUserOp 7, Execute 8, OwnerTable 9, Factory 6, BootstrapUnremovable 3) — the 2026-07-18 sweep's "38" was a **miscount** (grep-verified by two independent parties); KONTROL_SCOPING.md's 33/33 and STATUS.md are reconciled. Closes #463; the live Kontrol prover run stays in #197.
- **Mode / severity:** G1/G4 · **MED**
- **Location:** `contracts/verification/halmos/{run_halmos.sh,sessions/,README.md}`; `contracts/verification/kontrol/run_kontrol.sh`.
- **Mechanism (at review time):** 42 rules wired, newest receipt 38 (2026-06-11) predating `HalmosIsValidSignature.t.sol` (3 G8 rules); `run_halmos.sh` never asserted a PASS identity/count (green-at-zero hinges on Halmos's zero-match exit, untested); Kontrol had no committed receipts and no identity baseline (sweep-F52); three counts for one claim (STATUS 30/30, KONTROL_SCOPING 33/33, sweep's miscounted 38).

### F10 — `U256::format_decimal`: the Kani harness and mutation manifest are its weak instruments (narrowed)

- **Status:** ✅ FIXED — **Resolution:** new `format_decimal_exact_on_boundaries` Kani harness (12 boundary cases with byte-exact assertions — rounding-at-5, carry ripple, trim collapse, zero, `u64::MAX`) verified `SUCCESSFUL` in 41.6 s; three tier-default mutations enrolled (`>= 5`→`> 5`, drop-digit index `-`→`/`, carry `&&`→`||`) and each proven to FAIL the new harness — while the old charset harness stays green on the `> 5` mutant (the vacuity control, F10's exact PoC). A 19.4M-tuple differential additionally proved five of the seven stale missed-mutants are output-equivalent (unkillable by any output assertion — the third pin is structural via the unwind bound, documented honestly in the manifest). Census lock regenerated: 163/26, the file no longer outside mutation (7/5 outside remain). `cargo test -p pqsigner-tx-core` green.
- **Mode / severity:** G3/V1 · **MED**
- **Location:** `tx-core/src/eip1559.rs:626-717` (new harness), `scripts/kani_mutations.json` (3 new entries), `scripts/kani_census.lock.json`.
- **Mechanism (at review time):** the harness asserted charset-only over a concrete value (cannot redden on digit-aliasing/collapse); the file had no mutation pin; the 2026-06-26 missed mutants clustered here. GPT's narrowing: boundary KATs (`:807-875`) and the universal extracted theorem `FormatDecimalSpec.lean` already existed — the gap was Kani-level decision coverage + a mutation pin, both now closed.

### F11 — Status and inventory docs drifted again, in both directions (over- and under-claim)

- **Status:** ✅ FIXED — **Resolution:** STATUS.md corrected (ProVerif 33 queries/6 models; Kontrol 33/33; Halmos 42 receipted/42 wired; the EasyCrypt 10/21 row carries the docker-gate UPDATE; Kani 163; and the CI evidence-gap banner, F1) with the dated blockquotes preserved and annotated; `FV_SURFACE_MAP.md` snapshot bumped to 2026-07-19 with rows 4/6/9 corrected and a 7-row post-snapshot expansion section (the pilot surface); `OPEN_PROOF_OBLIGATIONS.md` aligned to `sphincsDigest` + the wallet-balance-decrease shape (the Group-T wording was checked against the real theorem). The standing sync owner is named in §"Proposed tracker items" (the security-frontier-reconcile workflow on an FV cadence). Closes #464.
- **Mode / severity:** G2 · **MED**
- **Location:** `docs/STATUS.md`; `contracts/verification/docs/{FV_SURFACE_MAP.md,OPEN_PROOF_OBLIGATIONS.md}`.
- **Refuted sub-item (dropped at refutation):** the "Verus 8 proofs vs 7 proof fns" nit — Verus counts 7 `proof fn`s + the recursive `proj` termination obligation = 8; the pilot doc's count is tool-accurate (both partners).

### F12 — LeanLoop `vet` still classifies unsolved-goal errors as "NEGATION PROVED" (carried 2026-07-15 F10)

- **Status:** ✅ FIXED — **Resolution (LeanLoop repo, `~/repos/LeanLoop`):** `run_scratch_file` now returns `(exit_code, output)` (the code was previously discarded), and `spec_vet.py`'s `judge` issues RED only on a clean run — exit 0 AND no error text AND no sorry warning; anything else is `skip` (no-signal). Three new regression tests pin the exact failure shapes (`error: unsolved goals` → skip; timeout → skip; nonzero exit without error text → skip). Full suite: 113/113 pass.
- **Mode / severity:** G4 · **MED**
- **Location:** `~/repos/LeanLoop/leanloop/{spec_vet.py:132-180,lean_runner.py:120-139,cli.py:692-693}`; `tests/test_spec_vet.py`.
- **Mechanism (at review time, both partners):** the guard required literal `"_vet_neg_"` in the error output, so a timeout or `error: unsolved goals` fell through to RED *"NEGATION PROVED … (kernel-checked)"*; behavior was enshrined in a test.

### F13 — Gates do not police their own registry/lock/manifest files (systemic; both partners' top "missed" item)

- **Status:** ✅ FIXED — **Resolution:** `kani_census.lock.json`, `kani_mutations.json`, and `contracts/verification/extraction_registry.json` are now in their gates' `polices_paths`; the freshness checker carries the completeness floor (every on-disk `Extracted/*/Funs.lean` pinned — 16/16) and the required-ID floor; `check_gate_enforcement.py` is green with 28 gates. Closes #465.
- **Mode / severity:** G1 · **MED-HIGH**
- **Location:** `scripts/gate_enforcement.json` (`polices_paths` sets), `scripts/kani_census.lock.json`, `scripts/kani_mutations.json`, `contracts/verification/extraction_registry.json`.
- **Mechanism (at review time, Opus's discovery):** `verify-kani-census` was `per_pr_blocking` but did not police the lock file you'd edit to fake the count; the ledger/proof-mutation self-policing pattern was never generalized; 16 `Funs.lean` on disk vs 15 pinned entries.

## Positive controls that held (do not re-litigate without new evidence)

- `theft_free` closure = exactly the 11-axiom ledger set; `theft_free_bytecode{,_reachable}` = 12 with the reachability pin; `execC10Asm_eq` kernel-only — all live-verified.
- F3 remediation: the `Evil : False` canary is quarantined, wired, and fires; clean 66-headline dump passes.
- Protocol surface: vendor-derived OPTIGA model is the pinned one (inj-agreement pinned FALSE); live ProVerif 6/6 + Tamarin 3/3 runs green; self-tests fire on exit-42, tautology substitution, verdict flip.
- EasyCrypt: zero-skip docker gate (22 files as targets), semantic axiom pins, 130.6-bit FORS+C query work factor honestly labeled arithmetic-not-reduction; ITSRC10 honestly a named nonstandard assumption.
- Kani: census accurate (163/26; 156/21; 43 groups); enrolled core is genuinely strong (biconditional + accept/reject controls: fw-manifest, ns_ptr_validate, erc20/calldata, aa gate, multisend, resolve byte-binding); mutation runner has real anti-vacuity teeth.
- The 12 pilot docs: artifacts exist as cited; three self-corrections landed in-doc (EIP-1271 view-only correction; EasyCrypt grind-via-OC kill; BINSEC-thumb withdrawal). The pilots localized three real residuals now precisely stated: the **EIP-1271 view-only margin** (uncapped, validates on-chain, bounded only by reset-rate + bootstrap budget — the combined-budget TLA model's VIOLATED margin invariant), the **partial-erase page-123 premise** (non-atomic 8 KiB erase breaks SIGS-first), and the **PIN-reconcile residuals** (SE-silicon-reset undetected; leg-glitch bypass).

## Pair-refutation record

| Candidate | Opus 4.8 | GPT-5.6 SOL | Coordinator final |
|---|---|---|---|
| C1 dead CI (F1) | CONFIRMED (billing annotation quoted) | NARROWED (its sandbox had no network; verified gate declarations; noted 8 workflows) | CONFIRMED (two independent executions) |
| C2 red gate (F2) | CONFIRMED | CONFIRMED (+ whole-file vs theorem-body scope note) | CONFIRMED |
| C3 registry (F3) | CONFIRMED (all four; (d) sharpened) | CONFIRMED (in-memory PoCs) | CONFIRMED |
| C4 PinState/SlotKdf (F4) | CONFIRMED (correction: domain IS in trigger paths — vacuous, not unwired) | NARROWED (no current stale bodies; PinState low-stakes; SlotKdf prospective) | CONFIRMED as narrowed |
| C5 lean4checker (F5) | CONFIRMED | NARROWED (manual runs exist; 59 modules now) + structural incapability finding | CONFIRMED, elevated |
| C6 Lean preimage (F6) | CONFIRMED as gate gap; NARROWED not-a-live-bug (+ stale docstring citation) | CONFIRMED (equal-width reorder escapes) | CONFIRMED as narrowed |
| C7 BreaksHash triviality (F7) | CONFIRMED, strengthened; NARROWED docs half | CONFIRMED (no independent theft_free collapse) | CONFIRMED (honesty scope) |
| C8 README A3.1 (F8) | CONFIRMED (+ self-contradiction, AXIOM_STATUS:191) | CONFIRMED | CONFIRMED |
| C9 Halmos/Kontrol (F9) | NARROWED (G8 wired; receipt-currency) / CONFIRMED (floor, Kontrol) | CONFIRMED | CONFIRMED as narrowed |
| C10 format_decimal (F10) | CONFIRMED (+ honest-docstring note) | NARROWED (boundary KATs + FormatDecimalSpec.lean exist) | CONFIRMED as narrowed |
| C11 doc drift (F11) | 6/8 CONFIRMED; Verus sub-item REFUTED | NARROWED (42 not 41; Verus 8 explained) | CONFIRMED as narrowed |
| C12 vet (F12) | CONFIRMED (+ exact mechanism + test enshrinement) | CONFIRMED (+ exact mechanism) | CONFIRMED |
| MISSED | census-lock self-policing gap; registry completeness floor | split-files Types.lean unpinned; lean4checker not-a-closure-check | → F13 (new); folded into F3/F5 |

## Honest residual

1. **What survived attack:** the scoped kernel results (`theft_free` family, A3.1 model↔spec, the pilot artifacts); the protocol models as pinned; the EasyCrypt gate as configured; the Kani enrolled core; the ledger/mutation self-test machinery. No rogue axiom, sorry, or vacuous headline was found in the current tree. Two independent refuters found no candidate to be wrong as filed (narrowings were about scope/framing, one sub-item dropped).
2. **What this pass did NOT do:** no full `lake build` from clean of the main tree (the extracted project rebuilt green post-remediation), no full Kani campaign (2/163 harnesses executed), no live Kontrol prover run (the identity baseline is fixture-validated; tracked #197), no crux execution, no EasyCrypt compile (receipt + pins only), no 16-of-17 TLC configs, no hardware, no binary analysis, no release-artifact review, no exact-HEAD lean4checker/nanoda replay (59-module tree). The Lean interpreter internals (`Phases.lean`, 6.3k lines) were trusted via kernel + `#print`, not proof-read. GPT's leg could not execute `gh` (network-sandboxed) — C1 rests on coordinator + Opus executions.
3. **Provenance:** mixed executing/source review — each finding names its execution level. The CI-outage and red-gate claims are coordinator-executed and partner-re-executed; the registry mechanisms are triply executed; doc-drift claims are grep-verified by three parties; remediation validations are quoted per finding.
4. **Authority boundary:** this review grants no merge, shipment, or risk-acceptance authority. Findings landed on the tracker (`label:finding`); CONFIRMED here is coordinator+refutation evidence, not an owner decision. This record is a coordinator-led deep review with refutation passes, not the mandated frozen-pair sweep; if a stage decision is requested, run the full exact-pair workflow.

## Proposed tracker items (status after 2026-07-19 remediation)

1. F1 dead-CI — #456 stays open until billing restoration + first green nightly (commented)
2. F2 re-extract aa-userop — #194 **closed**
3. F3 registry floors + F54 file coverage — #457, #199 **closed**
4. F4 enroll PinState/SlotKdf — #458 **closed**
5. F5 lean4checker honest fix — #459 **closed**; nanoda_lib follow-up **#466 filed**
6. F6 three-way digest pin — #460 **closed**; Aeneas digest extraction **#467 filed**
7. F7 BreaksHash-entailment paragraph — #461 **closed**
8. F8 README A3.1 correction — #462 **closed**
9. F9 Halmos floor + receipt; Kontrol identity baseline — #463 **closed**; #197 stays open for the live Kontrol prover run (commented)
10. F10 format_decimal — fixed in-tree (harness + 3 mutation pins + census lock); no issue needed
11. F11 doc sync — #464 **closed**; the standing sync owner = security-frontier-reconcile on an FV cadence (named in STATUS.md's "How this was built" section)
12. F12 LeanLoop vet — fixed in LeanLoop (`~/repos/LeanLoop`), 113/113 tests
13. F13 gate self-policing — #465 **closed**
14. FV15-F3/F5/F7/F8/F11 — #413–#417 **closed** with remediation evidence
