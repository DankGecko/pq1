# FV assurance/verification surface map

**Snapshot: 2026-07-19** (reconciled after the 2026-07-19 deep review; previously 2026-07-15). This map owns the current inventory of proof and
proof-adjacent assurance surfaces. It deliberately includes non-formal evidence
such as Miri, fuzzing, differential tests, and physical/tool receipts, but labels
their evidence tier instead of calling every row formal verification. A green
row proves only the property, artifact, and configuration named in that row.

## Current surface

| # | Surface | Strongest honest evidence | Enforcement at this snapshot | Main residual / current review result |
|---|---|---|---|---|
| 1 | Lean on-chain safety and SPHINCS+C verifier specification | Kernel-built theorem tree; exact advertised closures for selected headlines; proof mutations; independent `lean4checker` replay of 58 modules | Lean build/audit/lints per FV workflows; mutations partly nightly/local | No new kernel inconsistency found. Theorem intent and exact-closure policy remain distinct: independent kernel replay accepts kernel-valid project axioms unless a separate allowlist rejects them. |
| 2 | Solidity/Yul/model/deployed-bytecode correspondence (A3.1/A3.x) | Kernel model→spec interpreter refinement; structural source→AST parse; KAT/mutant differential; Halmos/Kontrol sessions and pinned codehashes | Mixed per-PR and local/manual; consult gate manifest and receipts | Model→spec is universally proved. Exact deployed-bytecode/source/session correspondence and property-specific Kontrol scope remain the boundary; public “transcription-free” wording is broader than the validate-wrapper evidence. |
| 3 | Aeneas-extracted Rust | Kernel theorems over committed generated Lean; selected Rust/extracted differentials | Default extracted build in CI; regeneration targets are not comprehensively triggered | **False-green freshness reproduced.** Current Tx-Merkle Rust differs semantically from committed extraction; regeneration fails. A Rust domain-tag mutation passes both extraction gates. The default closure check also accepts an arbitrary new project axiom. |
| 4 | Firmware Kani bounded proofs | 163 active `#[kani::proof]` harnesses in 26 files (census-locked by `scripts/kani_census.py` + `kani_census.lock.json`) | Nightly/default tiers plus a curated mutation manifest | 156 harnesses in 21 files reside in mutation-enrolled files; seven harnesses in five files do not. Default/nightly runs 40/43 mutation groups; three are full-only. NOTE (2026-07-19): the nightly has not executed since ~2026-06-30 (CI billing outage) — this row is currently local-run evidence. The three ERC-7730 Phase-D parameter harnesses were individually verified with Kani 0.67.0; no fresh full Kani campaign was run. Bounded harnesses are not architecture-wide proofs. |
| 5 | Firmware Miri and unsafe-code assurance | Host-reachable Miri checks plus source-level unsafe controls | Per configured host workflows | Host reachability excludes target-only CMSE/MMIO/interrupt/concurrency behavior. Treat as dynamic UB evidence, not formal verification or a whole-target guarantee. |
| 6 | ProVerif, Tamarin, and CryptoVerif protocol models | Symbolic/computational model results plus selected reachability witnesses | Mixed nightly/local | FIXED 2026-07-16 (F7): the driver enforces zero exit codes and pins per-query/per-lemma identities; the vendor-derived OPTIGA model is the pinned one (inj-agreement FALSE). Residual: the Kontrol/KEVM leg has no identity baseline (fv-deep-review-2026-07-19 F9). Deployed directionality, conditioned distributions, lifecycle, and code refinement remain explicit interfaces. |
| 7 | Constant-time, side-channel, and fault assurance | Selected source/object binary analyses, fault sweeps, and separate physical plans/receipts | Mostly local/manual; configuration-specific | Bind every result to exact symbols/bytes/profile and analyzer semantics. Selected binary CT is not physical leakage resistance; bounded instruction faults are not voltage/clock/EM/laser evidence. |
| 8 | Differential and fuzz assurance | Cross-implementation corpora and continuous fuzzing over selected parsers/render paths | Mixed continuous/local | Valuable regression evidence, not a universal proof. Record corpus provenance/coverage and unsupported paths; regenerate from current source where freshness is claimed. |
| 9 | EasyCrypt C10 cryptographic reductions | Partial WOTS+C/FORS+C games, combinatorial lemmas, and arithmetic guardrails | Semantic axiom pins + zero-skip full mode; container gate (`verify-easycrypt-docker`, receipt 2026-07-17); enrolled as `local_documented` in the 27-entry gate-enforcement manifest | FIXED 2026-07-16/17 (F5): full mode fails on any skip; axioms pinned by name+type; docker gate compiled the 21-file closure as targets with zero skips. Imported WOTS parameters exclude C10 (`w=8`, `log2_w=3`, `l=43`, no checksum). Adaptive WOTS, concrete FORS/tree/scheme, bounded grinding, and common-adversary composition remain open research. |

`verify-gate-enforcement` checks entries already declared in
`scripts/gate_enforcement.json`; it is not a reverse-discovery proof that every
proof target, model, script, or surface is enrolled. At this snapshot EasyCrypt
is enrolled as `local_documented` (the semantic-pin and docker gates remain
host-side; no workflow runs them — fv-deep-review-2026-07-19 F11).

## Post-snapshot expansion (added 2026-07-19)

The 2026-07-16→17 pilots landed these surfaces, which this map now owns (each row's evidence lives in `docs/verification/fv-pilot-*.md`):

| # | Surface | Strongest honest evidence | Main residual |
|---|---|---|---|
| 10 | TLA+ lifecycle models (page-123 crash-atomicity, combined budget, directional PIN reconcile) | 3 specs, 17 pinned cfgs, self-asserting harnesses, TLC traces on disk | bounded (small constants); silicon premises (torn-QW, erase atomicity) are assumptions; no inductive (Apalache) evidence |
| 11 | Verus flash-journal model | 8 verified, 0 errors (deductive, all-length, zero assume/external_body) | fresh model ≠ deployed firmware (cited-TCB correspondence); AX-* named axioms |
| 12 | crux-mir NS-pointer diversity | 8 goals Valid, 0 disproved (second engine vs Kani) | copy↔crate keep-in-sync is cited-TCB |
| 13 | Lean platform/quantitative refinements | `Platform/MemoryMap.lean` disjointness (decide) + linker-map drift gate; cross-hash 128-bit claw floor; seed-split 2^-256 floor; CREATE2 TCB-shape refinement | literal↔register binding is a gate, not extraction; silicon enforcement is a HW receipt |
| 14 | Hardware-assumption ledger | `HW_ASSUMPTIONS.json` (12 rows) + `verify-hw-assumptions` CI gate | only 3/12 rows have a runnable falsifying test |
| 15 | Signed-digest correspondence (F2 fix) | Rust↔Solidity source field-order pin + per-field Solidity mutations + Forge vector | Lean model preimage still hand-mirrored (fv-deep-review-2026-07-19 F6); no Aeneas extraction of `compute_sphincs_digest_v06` |
| 16 | Kani signed-intent canonicity (ERC-20, CoW owner-UID) | production-wired proofs + enrolled anti-vacuity mutants | bounded (≤104 B / fixed layouts); remaining render arms open |

## Review provenance

The 2026-07-15 review is the first current nine-surface full-stack pass using the
mandated mutually withheld Opus 4.8 and GPT-5.6 SOL first passes followed by
symmetric cross-adjudication. The immutable reports and digests live in the
global adversarial-review findings catalogue; `REVIEW_PROVENANCE.md` records
execution depth. Older source-read or executing passes remain historical
evidence for their exact snapshots and must not be promoted to current coverage
without a new identity-bound receipt.

## Expansion order

1. Repair current-source freshness, semantic query/axiom pins, subprocess
   failure propagation, skip behavior, enrollment completeness, and receipts.
2. Prove the production `compute_sphincs_digest_v06` ↔ Solidity
   `sphincsDigest` bridge and the signed-intent/display policy projection.
3. Model durable generated/charged/released query accounting and crash-consistent
   page state; then compose firmware rollback and lifecycle models through
   explicit stable interfaces.
4. Formalize an owner-approved current firmware schema only after the V4/V6
   owner-document conflict is resolved.
5. Strengthen exact release-artifact, EntryPoint, selected TrustZone/linker, and
   selected shipping-profile binary correspondence.

The dated
[`formal-verification-assurance-expansion-2026-07-15.md`](../../../docs/verification/formal-verification-assurance-expansion-2026-07-15.md)
gives costs, tool pilots, limits, and EasyCrypt stop/go criteria; the
[`coordinator report`](../../../docs/security/adversarial-review/findings/fv-full-stack-2026-07-15-coordinator.md)
owns findings and acceptance tests. This map owns inventory; it does not
duplicate that roadmap or the action list in `docs/work-todo.md`.
