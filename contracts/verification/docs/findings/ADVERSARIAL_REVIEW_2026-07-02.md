---
status: resolved   # historical FV review round, filed under the findings convention 2026-07-06
catalogue: ../REVIEW_PROVENANCE.md  # authoritative per-round verdict + handled-state
note: confirmed findings tracked in AXIOM_STATUS.json / STATUS.md / docs/work-todo.md
---

<!-- Adversarial FV-SOUNDNESS review — run per docs/verification/fv-adversarial-review-playbook.md Part C.
Method: an EXECUTING round (the residual the 2026-07-01 source-read rounds named) — the full verify-* gate
battery + lean4checker completeness backstop RUN, plus the first adversarial pass on the 5 never-reviewed
surfaces (Aeneas §33, protocol models, Kani/Miri, CT/SCA, fuzz/differential) and a re-attack on the Lean tree.
~30 agents, V1-V11 + G1-G5 catalog, PoC-required, independent-refuter cross-vote. Scope: FV SOUNDNESS ONLY
(is a proof/gate/model/ledger-claim hollow, unenforced, or overstated) — NOT a security/vulnerability audit.
No fixes applied in this pass; this doc is the finding record. -->

# FV Adversarial-Soundness Review — 2026-07-02 (executing round, full-surface first pass)

## 1. Verdict

**The headline theorems are sound; the assurance *system* around them overstates.** Every confirmed
MEDIUM+ finding is an **enforcement (G1)**, **ledger-integrity (V5)**, or **model≠deployed-artifact (V9)**
gap — not one hollows a headline soundness theorem. This is the frontier-shift the playbook's own §A2
(G1–G5) predicted: once the theorem-level vacuity classes hold, what overstates next is the system.

Two firsts this round retire the prior rounds' biggest ceilings:

- **`theft_free` is kernel-sound at the strongest available level.** `make verify-lean4checker` — the
  external-kernel completeness backstop that had **never run** (the 2026-07-01 round's #1 residual, open
  because `#print axioms` under-reports in Lean v4.22.0) — was executed to completion: **kernel re-check
  ACCEPTED every declaration across all 55 modules (exit 0)**, including all of `Crypto/*` where the axioms
  live. Combined with the executed `verify-audit` (live 92-entry dump matches `AXIOM_STATUS.json` exactly on
  the 7 target theorems; exactly 15 `axiom` decls, all ledger-accounted; zero `native_decide`/`ofReduceBool`/
  `@[extern]` on any proof path), the smuggled-axiom / under-report doubt is now **empirically closed** for the
  Lean on-chain tree.
- **The 5 never-reviewed FV surfaces got a first adversarial pass** (Aeneas §33, protocol models, Kani/Miri,
  CT/SCA, fuzz/differential). Every mechanical theorem-level vacuity class attacked on them **held** where
  the artifact itself was the claim; the confirmed findings are all in the CI-enforcement and doc/ledger
  layers around them.

**Honest bottom line:** the math is real and now externally kernel-checked. The recurring defect is that
several proofs/models are advertised as *enforced*, *current*, or *faithful to the deployed artifact* when a
gate never fires on the surface it polices, a ledger field describes a shape the code has moved past, or a
model proves a stronger property than the code implements.

## 2. Confirmed findings (survived independent-refuter cross-vote), by class

### G1 — advertised gates that do not fire (the dominant class)

| ID | Sev | What overstates |
|----|-----|-----------------|
| **exec-lean F1 · three-claims gate dead** | HIGH | `make verify-three-claims` (the advertised end-to-end "ALL THREE CLAIMS VERIFIED" bundle) (a) **deterministically FAILs** SIGPIPE-141 at step 2/8 on the current tree (`verify-three-claims.sh:19` `set -o pipefail` + `:38` `grep\|head -20` over the now-92-entry dump), so its terminal banner is unreachable; (b) its advertised CI job lives at `contracts/.github/workflows/verify-three-claims.yml` — a **nested `.github` path GitHub Actions never executes** (zero hits in the root `.github/workflows/`), so `THREE_CLAIMS_PROOF.md`'s "runs the same pipeline on every PR" has been false since inception; (c) it is **absent from `gate_enforcement.json`'s 11-gate manifest**, so the G1 lint built to catch exactly this cannot see it. Fail-*closed* (loud red), and its wrapped components run individually in `lean-fv.yml`/`ci.yml`. |
| **exec-extracted F1 · §33 CI enforcement fictional** | HIGH | `FV_SURFACE_MAP` row 3 claims the three extracted-tree gates run "nightly" and are "asserted mechanically by `verify-gate-enforcement`". Reality: `lean-extracted.yml` has **no `schedule:`**, runs only `verify-extracted`, and its `paths:` exclude the Rust crates the extraction mirrors; `verify-extract-differential` / `verify-spec-vendored-fidelity` / all 14 `extract-*` regen-diff gates appear in **no** workflow; `gate_enforcement.json` omits every §33 gate. PoC: **two `extract-*` regen-diffs (`aa-userop`, `txcore-rlp`) are RED on the current tree** (drifting since 2026-06-17 / 07-01) and merged with all CI green because the workflow never triggered on `aa/**`/`tx-core/**`. Same "merged diff without gate" shape as the 2026-07-01 HIGH F1, on a different surface. |
| **claims-inventory · HALMOS "fast CI gate" false** | MED | `THE_CLAIM`/`AXIOM_STATUS` advertise Halmos as "**the fast CI gate**" for A3.2/A3.2-exec/A3.3/A3.4 (7×), and `FV_SURFACE_MAP` row 2 claims per-PR `ci.yml` enforcement of `bytecode` — but `ci.yml` itself declares `verify-bytecode`+`kontrol` "**Intentionally NOT in CI**", no workflow invokes them, and the G1 manifest has no bytecode/halmos/kontrol entry. Only the codehash-freeze forge test fires on drift; nothing forces a Halmos re-run after a re-pin. |
| **assurance-system G1META-1 · G1 manifest incomplete** | MED | `gate_enforcement.json` enrolls 11 gates but omits `verify-transcription` (the *only* CI-enforced A3.1 gate / row-2 "active front"), `verify-extracted`, and the cflite/fuzz differential; `check_gate_enforcement.py` has **no manifest-completeness assertion**, so `FV_SURFACE_MAP:32`'s "enforcement per row is asserted mechanically" is false for rows 2/3/8 and the G1 lint is silently self-limiting. |
| **assurance-system G1META-2 · G1 checker blind to `paths-ignore`** | MED | `check_gate_enforcement.py`'s F1 path-coverage check — its raison d'être — reads only `on[push].paths`, never `paths-ignore`; a `paths-ignore`-only workflow (which `ci.yml` **is**) yields `[]`, treated as "no filter ⇒ covers everything", **skipping the F1 loop**. Live output prints the false line `[ok] miri … no-path-filter` for a workflow that has an exclusion filter. Latent today (miri's policed paths aren't currently ignored) but the meta-certificate is vacuous for the exact mechanism (`ci.yml paths-ignore`) implicated in the founding F1 incident. |
| **assurance-system G1META-3 · parser job-level-only** | LOW | The checker reads `continue-on-error`/`if:` only at **job** level; a step-level `workflow_dispatch` guard or `continue-on-error` on the `make verify-X` step, and `uses:`-reusable-workflow / matrix-exclusion indirection, defeat detection (fail-closed for `uses:`). No live gate uses these shapes. |
| **fuzz F1 · CI fuzzing seedless / corpus untracked** | MED | `cflite-batch.yml` claims runs "start from the committed `fuzz/corpus/` seeds", but `fuzz/corpus/` is **git-untracked** (`git log --all` empty), so CI clones start blank; the selector-gated targets (`multisend_decode`, `tx_erc20_parse_calldata`) never reach their decode body seedless. **Executed:** 40M seedless runs of `multisend_decode` plateau at cov 106, selector `0x8d80ff0a` never appears; +one seed → cov 136. So the coverage-guided legs of those two targets are near-vacuous in CI. |

### V5 — ledger fields the live tree has moved past

| ID | Sev | What overstates |
|----|-----|-----------------|
| **exec-lean F3 · `cannot_remove_bootstrap` untracked** | MED | The only Claim-2 corollary in `AXIOM_STATUS.json` `claim_corollaries` **absent** from both `dump_axioms.lean`'s 101 `#print` targets and the 15-key `closures` block, so `verify-audit` and `verify-ledger-consistency` structurally can't see it. Live closure is kernel-only today (no current unsoundness); a rewrite onto an *existing* documented axiom would turn nothing red while the ledger keeps advertising a kernel corollary over the Lean Storage model. |
| **claims-inventory · A3.1 stale in the two "SSOT" docs** | MED | The 2026-07-01 a31 fix (A3.1 was advertised as the `= verifyYulModel` shape the live Lean labels "FALSE as a ∀") reached only `AXIOM_STATUS.json` + `ASSURANCE_CASE.md`. `THE_CLAIM.md:215-217` (self-declared "single source of truth for public claims") and `TRUST_ASSUMPTIONS.md:101` (self-declared "authoritative inventory") **still state `= verifyYulModel`** — the exact universal the source calls false. No soundness impact (`theft_free` consumes `= execC10Asm`); the two most-quotable docs describe the bridge axiom in a shape the tree disowns. |
| **quant-crypto · A5 quantitative bound uncited/contradicted** | LOW | `TRUST_ASSUMPTIONS.md:164-166` states a concrete `ε(A) + Q·2^-128` bound with no citation deriving it for the C10 parameter set, contradicting `AXIOM_STATUS` ("Pr≤ε not formalised; no public bit-security number for C10") and the project's own kernel floor of **96 bits** (`min(143,112,96)`, `Quantitative.lean`). Qualitative shadow presented as a quantitative number (G5). |

### V9 — model / harness proves something other than the deployed artifact

| ID | Sev | What overstates |
|----|-----|-----------------|
| **protocol PM-1 · PIN-lockstep model ≠ deployed reconcile** | MED | `tamarin/pin_lockstep.spthy` proves a **symmetric** reconcile (`Boot_Wipe` on *any* counter disagreement; lemma `zero_synced_means_all_reset` proves a partial reset always wipes) and its README amplifies "a single-side reset is always caught." The deployed `reconcile_pin_attempts` (`nsc/mod.rs:1084`) is **directional** (`se_count > mcu`, not `!=`) and catches strictly less. **Verified** (tamarin-prover 1.12.0 all-lemmas-proved + code read): a benign→(0,0) reset of *both* SE counters gives `tamper=false` (no wipe) while the model *proves* that trace wipes — a genuine model≠code gap on an advertised FV surface. (Reconcile is a defense-in-depth cross-check; the primary MCU page-124 + per-SE silicon lockout still bound the attacker — so this is a false lemma/README claim about the deployed reconcile, not a fund-drain.) |
| **symbolic-harnesses · Kontrol A3.2-validate transcription NOT retired** | MED | `AXIOM_STATUS`/`THE_CLAIM`/`KONTROL_SCOPING`/`ASSURANCE_CASE` all state Kontrol "**retires the `LeanModel.sol` hand-transcription element from the TCB**" for A3.2. But `KontrolValidateUserOp.t.sol`'s 4 `prove_` rules use a **concrete, canonically well-formed wrapper** (`abi.encode(uint256(k), new bytes(4008))`), so the wrapper-decode / selector-role-split / full-frame transcription — which lives only in the Halmos mirror `LeanValidateUserOpModel.sol` — is **not** independently re-established. A `LeanModel.sol`↔Lean-file decode-gate divergence would survive both engines. (A3.4/A3.3/A3.2-exec-single *do* carry independent symbolic content — scoped to A3.2-validate + A3.2-exec-batch.) |
| **bridge-a31 · `verify-interp` mislabels the bytecode leg** | LOW | `InterpMain.lean` presents its 384 bulk vectors as "the deployed-bytecode KAT ground truth", but `checkOne` never touches bytecode: check(B) is interpreter-vs-**Rust-signer**, and check(A) is a kernel corollary of `execC10Asm_eq` on the all-N-masked corpus (can't fail). The genuine bytecode evidence (KAT forge + ~250-mutant screen) exists *separately*; the label overstates what these 384 vectors prove. |
| **symbolic-harnesses · Kontrol gate not codehash-anchored** | LOW | `run_kontrol.sh` runs `kontrol build`+`prove` over fresh instances with **no in-flow codehash certification**, unlike `run_halmos.sh` (PinnedCodehashes/ImmutableLemma/ReproCheck). "Directly on the deployed bytecode" is anchored only externally (the `contracts` CI codehash-freeze), not within the Kontrol gate. |

### V10 / V4 / V1 — theorem-level classes that *did* surface a gap

| ID | Sev | What overstates |
|----|-----|-----------------|
| **exec-extracted F2 · extracted diffs evade the escape-hatch lints (V10)** | MED | `lint_fv_invariants.sh` scans `extracted/` but runs only via `verify-fv-lints` in `lean-fv.yml`, whose `paths:` **exclude** `extracted/**`; `lean-extracted.yml` runs only `verify-extracted` (a `sorry`/`sorryAx` grep — no closure-set or escape-hatch check). A `native_decide`/`@[extern]`/new-axiom proof in an extracted rank theorem merges green. (Distinct from the lean/ tree, which lean4checker just cleared.) |
| **exec-lean F2 · Claim-1 corollary carries dead theft-hypotheses (V4)** | MED | `theft_free_with_calldata_binding` (the doc-mapped "signature-to-execution binding" headline) has **4 unused execution hypotheses** (`σ'`, `effects`, `hExec`, `hDecrease` — build emits `unused variable` warnings); the proof consumes only `hSameDigest`. **Executed deletion PoC:** the conclusion re-proves from `hSameDigest` alone (closure drops even `Classical.choice`). It is pure digest-collision-freeness dressed as theft framing; the docstring's "Composes I-1 + the bridge axioms" is false (closure has neither). `ASSURANCE_CASE` (EF-#15) scopes it correctly as one link of a 4-link chain — but the dead hypotheses + false in-file composition claim are undisclosed. |
| **protocol PM-2 · `dual_se_unlock.pv` has no reachability witness (V1)** | MED | The seed-split-secrecy ProVerif model has **no `query event(...)` reachability/liveness query** attesting its honest legs (optiga/se050/sworld) run; its "load-bearing positive control" (`out(bus,hoP) | out(bus,heP)`) exercises only `reconstruct`-derivability, not the protocol. A future dead-leg regression would leave all three secrecy verdicts vacuously "secret" and the count-only `verify-protocol-models` gate green. (Contrast `fw_update_authenticity.pv`, which *has* the correct `query event(Install(m))` anti-vacuity witness.) |
| **exec-extracted F3 · SlotKdf/PinState uncovered + stale (V9)** | MED | The two newest security-headline extractions (SlotKdf = invariant-#8 KDF layout; PinState) have **no `extract-*` regen-diff gate at all**, and the committed SlotKdf extraction is **already stale** vs the 2026-07-01 zeroize edits to `domain/src/lib.rs` (a fresh re-extraction of `slot_entropy` contains a `zeroize` step the committed body lacks). Benign today (zeroize of a local doesn't change output); a *functional* drift would rot the invariant-#8 theorems with nothing able to redden. |
| **ct-sca CT-1 · checkct runs the wrong compilation profile (V9)** | MED | The binsec CT proof builds at the cargo-checkct template default (`opt-level=3`, LTO off, cu=16), **not** the shipped firmware profile (`opt-level="s"`, LTO on, cu=1), yet `work-todo P6` + `security-tooling-sota:61` credit it with guarding "a branch reappearing after LTO/`opt-level=s`" — the exact codegen it never exercises. The one in-scope driver with real secret-dependent control flow (`driver_saes` → `cmac.rs:41` MSB branch) is certified at a profile the device never ships. Undisclosed profile mismatch. |

### Also confirmed (LOW/INFO, disclosed or safe-direction)

`exec-lean F4` (KeyHistory guard lemmas ungated — the two-part malicious-edit fence; disclosed in the
2026-07-01 §5 residual + work-todo), `exec-extracted F4/F5` (extracted-tree axioms `sha256_pure_bytes`/
`hmac_sha512_pure_bytes` under-disclosed in the ledgers; `verify-spec-vendored-fidelity` checks 4/8 vendored
defs), `quant-crypto delta-audit-stale-R-preimage` (the C10↔FIPS-205 delta-audit records a pre-hardening R
preimage the code fixed 2026-06-13; safe-direction under-doc), `bridge-a31 A3.1-RHS-unpinned` (a
`= verifyYulModel` revert is a 3-site edit that passes green — filed, statement-SHA pin not yet built),
`protocol PM-3` (SCP03/shield handshakes single-session, no `!` replication → cross-session claims say less),
`protocol PM-4` (`fw_update_authenticity.pv` cites an anti-rollback "near-mirror" model that doesn't exist).

## 3. What was attacked and HELD (could-not-break)

- **`theft_free` conjunct-1** is a genuine ∀-over-adversary-`op` non-bypass theorem (no well-formedness
  restriction on `op.signature`/`op.callData`); lean4checker accepts its full closure.
- **The EUF-CMA restatement is genuinely non-vacuous:** `BreaksHash` is an opaque `Prop` (not `False`, not
  assumed-false); the 2026-06-14 detonator no longer type-checks; the guard lemmas are kernel-only; the
  reduction shapes conclude the honest `∨ BreaksHash`. `Spec.Signer.sign` is a full reference signer, not a
  stub; `honest_consistent` is a real round-trip.
- **The `c10Program` transcription** spot-diffed clean against `SPHINCsC10Asm.sol` across all loop bounds,
  memory offsets, the four masks, the two N-mask input guards, and the `staticcall(0x02)→sha256` mapping;
  `execC10Asm_eq` composes over the *real* byte-addressed memory model (not a simplified one).
- **The quantitative floor** theorems are concrete `by decide` over the real params (N=16,A=11,K=13,cap=2^16 →
  96 bits), not symbolic-uninstantiated; `forsCBits` matches the upstream accounting.
- **No smuggled axioms:** exactly 15 `axiom` decls tree-wide (all ledger-accounted), zero banned tactics on
  proof paths, mathlib-free lakefile (no foreign transitively-imported tree) — and lean4checker independently
  re-verified all 55 modules.
- **`miri` PASS** on the host-reachable unsafe (NS-ptr typestate + tree-borrows deref twin).

## 4. What was NOT looked at (next-round targets)

- `verify-proof-mutation` (any tier) was **not run** this round (would have raced the lean4checker replay) —
  "has the full tier ever run / does the canary trip" stays execution-unverified.
- Halmos/Kontrol `.t.sol` bodies were **source-read, not executed** (`verify-bytecode`/`verify-kontrol` are
  heavy + local-only); the pass counts are taken from session logs. The `LeanValidateUserOpModel.sol` ↔
  `Wallet/ValidateUserOp.lean` clause-by-clause transcription (the MED-vs-HIGH line for the Kontrol finding)
  was **not** fully diffed.
- Protocol-model **query bodies** beyond the reachability-witness check (V2 tautology risk across the 17
  ProVerif RESULTs / 8 Tamarin lemmas) — only headers + PM-1/PM-2 legs were walked.
- `Interpreter/Phases.lean` (6325 lines) + `HypertreePhase.lean` internals, `Sha256Bridge`/`Memory` aliasing
  edges — read only in fragments.
- **GitHub org branch-protection / required-status-checks** — uninspectable from this environment; every
  "per-PR blocking" severity assumes standard path-filter semantics and that `lean-fv.yml`/`ci.yml` are
  required checks on `master`.
- The `extracted/` v4.30 tree has no confirmed lean4checker analog (only lean/ v4.22 was re-checked) — a
  smuggled axiom invisible to `#print axioms` there would evade both the executed AxiomCheck and the grep.

## 5. Provenance

**EXECUTING round** (the residual the 2026-07-01 source-read rounds named as their biggest gap). Ran on the
live working tree: the full Lean `verify-*` gate battery (build/audit/fv-lints/ledger-consistency/
gate-enforcement/transcription/exec-gate/lean-proto-domain/interp/cavp/storage-mutators — all PASS except
`verify-three-claims` FAIL-141), **`verify-lean4checker` to completion (55/55 modules ACCEPTED)**, the §33
extracted gates + 6 `extract-*` regen-diffs (2 DRIFT), `make miri` PASS, `proverif`/`tamarin-prover` on the
protocol models, and live libFuzzer smoke runs. Doc/ledger/CI-wiring findings verified by source-read of the
live workflow YAML + Makefiles + ledgers. Findings cross-voted by independent default-to-refute refuters;
disclosed-with-accurate-severity items downgraded to INFO. This is a FV-**soundness** pass — every finding is
"a proof/gate/model/claim is hollow, unenforced, or overstated", not a vulnerability.
