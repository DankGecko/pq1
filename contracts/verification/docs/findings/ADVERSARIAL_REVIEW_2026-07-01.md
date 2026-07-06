---
status: resolved   # historical FV review round, filed under the findings convention 2026-07-06
catalogue: ../REVIEW_PROVENANCE.md  # authoritative per-round verdict + handled-state
note: confirmed findings tracked in AXIOM_STATUS.json / STATUS.md / docs/work-todo.md
---

<!-- Adversarial FV-soundness review — run per docs/verification/fv-adversarial-review-playbook.md Part C.
Method: 5 angle-scoped adversarial reviewers (mixed opus/sonnet) walking the V1–V11 catalog against the
claims inventory (ASSURANCE_CASE / THE_CLAIM / AXIOM_STATUS.json / PROOF_MAP / OPEN_PROOF_OBLIGATIONS +
the SphincsCVerify Lean tree), PoC-required, then a cross-vote (a 2nd model refutes each confirmed
finding), then synthesis. 15 confirmed/open findings cross-voted; 9 refuted. SOURCE-READ ONLY — no
`lake build`/`#print axioms`/`lean4checker` this pass (the biggest residual; see §5).
Applied fixes (commit of 2026-07-01): F1 (lean-fv.yml paths += docs/**), storage-mutators wired into
lean-fv.yml, AXIOM_STATUS.json A3.1/A5 field syncs, ASSURANCE_CASE G2 sync. Filed (work-todo §35):
OPEN_OBLIGATIONS/PROOF_MAP signer-status sync, F2 closures entries, birthdayBits rename, bridge-axiom
statement-SHA pin, F1 nightly belt-and-braces. -->

# FV Adversarial-Soundness Review — Final Report

## 1. Verdict

**No confirmed finding hollows a headline soundness claim.** Every mechanical vacuity class that would actually break `theft_free` — V1 (vacuous conditional / unsatisfiable `isForgery`), V4 (dead conjunct dropping A5), V7 (the retired `→ False` detonator / latent-false universal axioms), V6 (stub signer) — was attacked and **held**. `theft_free`'s load-bearing conjunct-1 is a genuine ∀-over-adversary-calldata non-bypass theorem; the corrected `= execC10Asm` bridge is what the proof actually consumes.

What survived cross-vote is **entirely ledger / CI-automation / gate-coverage / doc-integrity gaps**, not math soundness holes. The single most serious is a **HIGH-severity meta-gap (F1)**: a CI path-filter miss that lets `AXIOM_STATUS.json`-only edits merge to `master` *without ever triggering the `verify-ledger-consistency` gate advertised to police exactly those edits* — demonstrated on three real merged commits. This is a process/anti-drift hole (acute given the repo is LLM-edited), not a Lean unsoundness. Honest bottom line: **mechanical classes held; no new headline soundness gap; the residual is that several "kernel-proven"/"authoritative-ledger" assurances are guarded by manual or unwired scripts, and several ledger/assurance-case fields advertise shapes the live Lean has since corrected.**

## 2. UPHELD findings (survived cross-vote), ranked by severity

None is a live math-soundness hole. Severity reflects assurance-process / ledger-integrity impact.

### HIGH — F1 · ledger gate never fires on ledger-only edits (V5-META)
- **Claim hollowed:** `AXIOM_STATUS.json` `closures_doc:16` ("`verify-ledger-consistency` … FAILS on any drift") + `ASSURANCE_CASE.md:48-62` (advertised as the vacuity-closing gate).
- **file:line:** `.github/workflows/lean-fv.yml:22-35` (`paths:` filter omits `contracts/verification/docs/**`); `ci.yml:35-45` `paths-ignore`s all of `contracts/verification/**`; `nightly.yml` never invokes the gate (only site is `lean-fv.yml:76`).
- **PoC:** `86bfa494`, `d558fbd3`, `76f70f5e`/`1b39d65d` each edit **only** `AXIOM_STATUS.json` → none match `lean-fv.yml`'s positive path filter, all are path-ignored by `ci.yml`, nightly never calls the check. 8/20 recent `AXIOM_STATUS.json` commits touched zero `lean/` files. Undisclosed (not in `OPEN_PROOF_OBLIGATIONS.md`).
- **Fix + risks:** add `contracts/verification/docs/**` to `lean-fv.yml` `paths` (push+PR) and a `verify-ledger-consistency` step to `nightly.yml`. Risk: doc-only ledger edits now pay a `lake build` restore — mitigate with the existing warm-cache key; nightly needs restore-only cache discipline to avoid flaky reds.

### MEDIUM — a31 · A3.1 bridge axiom advertised as the false `= verifyYulModel` ∀ (V7)
- **Claim hollowed:** `AXIOM_STATUS.json:202-203` (`lean_type`/`description`) + `ASSURANCE_CASE.md:220-221` (G2) advertise `SPHINCsC10Asm.verify = verifyYulModel ∀ sig`. Live axiom is `= Interpreter.C10.execC10Asm` (`Bridge/Refinement.lean:202-205`); the Lean's own comment (`Refinement.lean:196-198`) calls `= verifyYulModel` **"FALSE as a ∀"** — `verifyRefined` does `pkSeed.take 16`/`pkRoot.take 16` with no N-mask reject (`Verifier/Refined.lean:143-148`) while the bytecode runs two `and(key,N_MASK)==key` guards.
- **Not a soundness hole:** `theft_free` consumes the corrected form (`EntryPoint.lean:79-82` `deployedVerifier := execC10Asm`). This is ledger/assurance-case integrity **plus a gate-coverage gap**: `signature_pins` pins only `theft_free`; C1 diffs axiom *names* not RHS, so a silent revert of the axiom + `deployedVerifier` back to the truncating `verifyYulModel` passes green.
- **Fix + risks:** sync `lean_type`/`description`/G2 to `= execC10Asm`; add a bridge-axiom statement-SHA pin. Risk: pin the **corrected** form, else the new gate enshrines the bug. Pure doc/gate edit.

### MEDIUM — F2 · two prose "closure=" claims sit outside the machine-checked `closures` block (V5)
- **Claim hollowed:** `closures_doc:16` ("AUTHORITATIVE … FAILS on any drift"). `AXIOM_STATUS.json:413` asserts `unauthorized_userop_breaks_hash` ("closure = A5 + kernel, NO new axiom") and `honest_consistent` ("kernel-clean {propext, Classical.choice, Quot.sound}") — **neither is a key** in the 15-key `closures` block.
- **file:line:** `AXIOM_STATUS.json:17-94` + `:413`; `check_ledger_consistency.py:157-175` (C1) and `:227-242` (C3) iterate only `ledger["closures"]`. Both theorems are already `#print axioms`-tracked (`dump_axioms.lean:132`, `:256`), so enrolling costs nothing. C8's `sorryAx` substring grep would miss a silently-added non-kernel axiom in either closure.
- **Fix + risks:** add both theorems (and audit ~5-6 other prose "kernel-clean/kernel-only" phrasings) to `closures`, seeded from a live dump, not the prose. Low risk; must seed the first pin from the actual dump.

### MEDIUM — storage-mutators · reachability completeness precondition guarded only by an unwired script (V5)
- **Claim hollowed:** `ASSURANCE_CASE.md:153-156` (G4) + A3.2/P1 — `reachable_implies_combinedCap` is sound only if the `Reachable` constructors are the **complete** set of cap-counter mutators; "backstopped by `scripts/check_storage_mutators.sh`."
- **file:line:** `grep -rn 'storage-mutators\|check_storage' .github/` → 0 hits; `Makefile` `verify-storage-mutators` (~:56) unwired, not a dep of default `verify`. Cross-vote also found `FAITHFULNESS_AUDIT_2026-06-14.md:63-64` **falsely** claims "Gap-1 (closed-world) — DONE (CI lint)." No current break (5 constructors == today's 5 mutators: `empty/initialised/bumpBootstrap/bumpSlot/setOffchain`). Other green gates (closures/ledger/proof-mutation) structurally cannot catch a new-mutator regression.
- **Fix + risks:** add `verify-storage-mutators` to `lean-fv.yml`; optionally kernel-check a `Storage` closed-world lemma. None to proofs.

### LOW — ledger-lean_type · `A5-EUFCMA.lean_type` reproduces the retired `→ False` shape (V7)
`AXIOM_STATUS.json:410` still prints `isForgery … → False`; live axiom concludes `→ BreaksHash` (`EUFCMA.lean:157-163`); adjacent `lean_type_note:412` is correct → self-contradiction. Field is ungated (no consumer). No soundness impact (safe direction: under-trust). Fix: sync field + add a `lean_type`-vs-source check.

### LOW — open-obligations-stale-signer · inventory says the signer is a broken stub (V6)
`OPEN_PROOF_OBLIGATIONS.md:206` (also `:65/:85-88`) claims `consistent` is "provably FALSE for the all-zero placeholder stub" — stale: `Spec/Signer.lean:127-205` is the full reference signer, `honest_consistent` (`HonestConsistent.lean:147`) discharges it, and `AXIOM_STATUS.json` A5 itself flags this phrasing "STALE." Under-claim. Fix: update the inventory rows.

### LOW — birthdayBits-naming-inverted · linear/quadratic term names swapped (V11)
`Quantitative.lean:234` `birthdayBits := n-qBits` is the **linear** q·2⁻ⁿ term; `multiTargetBits:237` `n-2·qBits` is the quadratic birthday term — names inverted vs convention and vs the same file's `:35-38`/`birthday_term_at_slot_cap:136-139`. Zero soundness effect (`Nat.min` symmetric; `min=96` unchanged). Auditor-misleading only. Fix: rename.

### LOW — F3-proofmap-stale · PROOF_MAP contradicts the newer ledger (doc-drift)
`PROOF_MAP.md:36-44` seven rows still read "⏳ Placeholder … future Group V work" (blame `d9e4014e1`, 2026-05-18) while `Signer.lean` (`b75e5a47`) + `honest_consistent` landed 2026-06-29 and `AXIOM_STATUS.json` says "SIGNER-COMPLETENESS CLOSED." Under-claim. Fix: update rows or add an "amend, don't duplicate" pointer.

## 3. Refuted / downgraded (nothing silently dropped)

- **C9-witness-isolated-hypothesis-theater (V1)** — REFUTED: `theft_free_bytecode` genuinely non-vacuous; gate + its own SCOPE note certify per-hypothesis inhabitance only, exactly as designed; one loose "why" clause = doc-precision nit.
- **lean4checker-not-in-CI (V10)** — REFUTED: the `#print axioms` under-report caveat is disclosed in the exact cited ledger field + Makefile + playbook + work-todo; deliberate manual pre-release gate, not an undisclosed gap.
- **eufcma-dead-conjunct-gate-gap (V4)** — REFUTED: rediscovery of already-resolved P9 (`3da1409b`); conjunct-2 decorativeness documented in 4 docs; "V4 closed" only ever claimed the mechanical unused-axiom class.
- **quant-floor-arith-isolated (V11)** — REFUTED: `ASSURANCE_CASE.md:263-270` already tags it "(K, standalone) … not a reduction … does not connect to BreaksHash" in the same bullet; caveat not buried.
- **universal-axioms-latent-false-under-¬BreaksHash (V7)** — REFUTED: disclosed design already CI-gated by `lint_fv_invariants.sh` sub-lint (b) `¬BreaksHash` firewall + (c) exact-closure; blast radius is 2 corollaries, and `theft_free`'s closure excludes both axioms.
- **eufcma-p9-isForgery-unsatisfiable (V1)** — REFUTED: disclosed + triaged as P9 (irreducible non-PPT ceiling), instantiated corollary added 2026-06-29; not new.
- **p14-bootstrap-crosschain-uncapped (V11)** — REFUTED: this *is* the theorem's own disclosed P14 conditional (`hC : C ≤ 2^16`, added by EF pass `e33861b9`); honest conditional margin.
- **claim4-G1-tag-overreads (V8)** — SELF-DISPOSED FALSE_POSITIVE: the model-only/trace-supplied-verifier/existential-σ limitation is disclosed in P13; caveat-placement, not vacuity.
- **theft_free-conjunct2-detached-forgery-rider (V8)** — SELF-DISPOSED FALSE_POSITIVE: disclosed as D9/P9; only `ASSURANCE_CASE.md` G0's compressed one-liner reads cleaner than the mechanized rider.

## 4. What we could NOT break (survived, strongest failed attack)

- **`theft_free` conjunct-1 is op-bound, not detached.** Tried to decrease wallet balance without a verify-true installed-owner sig; blocked — `handleOp` mutates balance only on the `validateSignature`-success branch (`EntryPoint.lean:116-120`), A2 forces success from any decrement, I-1 forces the deployed verifier true over `sphincsDigest(op)`.
- **`reachable_implies_combinedCap` is a sound inductive invariant.** No listed transition breaks `slotUses[i]+offchainSigCount[i] ≤ MaxSlotUses`; `validate` uses the strict precondition, `execStep`'s `setOffchain` guard pins the bound, `≤` correctly models the frozen `=MaxSlotUses` state.
- **A5 hardness shapes + `BreaksHash` are genuine opaque Props**, not `∀_,True`; `sha256_collision_resistance` is the honest `= ∨ BreaksHash` reduction (Assumptions.lean). The 2026-06-14 detonator is truly closed — the old `example : False := cannot_forge_without_breaking_SHA256 …` no longer type-checks; `BreaksHash` is not constructively provable, so the `∨BreaksHash` reductions don't collapse.
- **`Spec.Signer.sign` is a full reference signer** (grindR/findCount/FORS+C/WOTS+C/2-layer hypertree, `Signer.lean:127-205`); `honest_consistent` is a real round-trip proof, not vacuous.
- **`execC10Asm_eq` keystone survives** as a genuine Bool-decidable ∀ (~200-line kernel proof peeling each Yul statement); `theft_free`'s `rw [hbridge]; exact hverify` closes because `deployedVerifier := execC10Asm`; the `verifyYulModel` strings in the proof body are stale non-load-bearing comments.
- **The gates have teeth where checked.** `check_ledger_consistency.py --self-test` caught all 12 injected corruptions; the 5 `signature_pins` recomputed and matched; exactly 15 tree-wide `axiom` decls, all ledger-accounted (no phantom/undocumented); A3.4 has zero theorem consumers; the proof-mutation canary (`subst hExec`, first tactic at `Theorems.lean:306`) and the P1 load-bearing mutation are genuinely material; `witness_coverage` witnesses are concrete non-circular `∃` closed by `simp`/`decide` with no axiom; no `native_decide`/`ofReduceBool` in `Crypto/`.

## 5. What we did NOT look at — next-round targets (MANDATORY)

- **No live kernel run.** Nobody executed `lake build` / `#print axioms` / `lean4checker` this pass — every closure claim (`theft_free`'s 11, `reachable_implies_combinedCap`'s `[propext,Quot.sound]`, `executeBatch_faithful` kernel-only, `honest_consistent`'s set) was **source-read only**, inheriting the admitted `#print axioms` under-report ceiling. A smuggled axiom (`native_decide`/`ofReduceBool`/`@[implemented_by]`/`@[extern]` in a transitively-imported file) could evade both `#print` and a source read. **This is the single biggest residual.**
- **Gate script bodies partially unread:** `check_proof_mutations.py` / `proof_mutations.json` (are mutations material; does the canary trip; has the "full" tier — A3.2/A3.3/Gap3-keccak/A5-collision — *ever run*?), `lint_fv_invariants.sh` (does the grep cover the full smuggling set), `dump_axioms.lean` live output, `run_lean4checker.sh`. (`check_ledger_consistency.py` **was** read + `--self-test` run; 5 pins recomputed.)
- **Guard-lemma / KeyHistory ungated:** `keyHistory_empty_signs_nothing` + `honest_sig_not_forgery` are pinned by no gate — a two-part malicious edit (drop `signed_recorded` + delete both guards) would make `BreaksHash` provable undetected. Whether `verify-proof-mutation` can catch a `KeyHistory` weakening is untraced.
- **Wallet ledger internals:** `Execute.lean` E-1..E-8, `CreditLedger.lean` (`sumOver`/`creditConservation`/`exec_count_le_validate_count`) — `executeBatch` credit require/consume/frame fidelity + global-aggregate-vs-per-index story unaudited; `TxFlow.applyValidateSuccess` possible over-stamp vs deployed `_stampValidatedCredit` unclosed.
- **Bridge/axiom types at source:** A1/A4/A3.2/A3.3/A3.4 not confirmed opaque-content (vs `: True`) at `Bridge/Refinement.lean`; `SphincsDigestSpec.lean` field-binding; `OffchainBinding.lean` `keccak_sha256_cross_separation`; `SplitSecrecy.lean` XOR bijection / `[u8;32]`↔`BitVec 256` endianness boundary.
- **Bytecode transcription:** `c10Program` (272 lines) NOT diffed line-by-line vs deployed Yul `SPHINCsC10Asm.sol:26-201`; `check_c10_transcription.py`'s `staticcall→0x02` assumption unverified; `execC10Asm_eq` closure not ledger-pinned.
- **Symbolic harness source:** `HalmosValidateUserOpEquiv.t.sol`, `LeanValidateUserOpModel.sol`, `KontrolValidateUserOp.t.sol`, `HalmosExecute/Factory/MultiOwnable.t.sol` — ledger PASS counts taken at face value; A3.2/A3.2-exec/A3.3/A3.4 deployed-bytecode legs + the unset-partition concrete-reps ceiling not re-derived (a V9/V11 gap could live entirely in a `.t.sol`).
- **SHA-256 byte-memory:** `Sha256Bridge.lean` / `Memory.lean` vs EVM `calldataload`/`mstore` aliasing/overrun edges; `Phases.lean` (6325 lines) + `HypertreePhase.lean` read only in fragments; `verifyRefined_eq_spec`'s top-level `rfl` not confirmed type-checking.
- **Round-trip / quantitative leaves:** `ForsRoundtrip`/`HypertreeRoundtrip`/`WotsRoundtrip`, `SignerPost` (`grindR_post`/`findCount_post`), `Treehash` not vetted for own V1/V3 vacuity; `advantage_floor_*`/`c10_cap_is_load_bearing` not fully opened; `forsCBits` formula vs upstream `SECURITY-ANALYSIS.md §2.3` not cross-checked; `#reduce SM_DT_TCR_F_Shape` not run.
- **Un-audited ledger surface:** remaining ~85 `#print axioms` targets in `dump_axioms.lean` beyond the 15 tracked + 2 flagged; other prose "closure=/kernel-clean" phrasings beyond F2's two.
- **Docs not read:** `TRUST_ASSUMPTIONS.md`, `AXIOMS.md`, `DISCHARGE_PLAN.md`, `KONTROL_SCOPING.md`, `DEPLOYED_BYTECODE_PIN_CAVEAT.md`, `THREE_CLAIMS_PROOF.md`, `two-specs-faithfulness.md`, `BLOCKERS.md`, the `A3_1_*.md` family, `MISSING_FOR_FULL_BYTECODE_PROOF.md`.
- **Out of scope entirely:** Tamarin/ProVerif protocol models, §33 Aeneas `extracted/` mathlib track, Kani firmware `verify-kani-mutation` mirror, KDF domain-tag separation (`domain/src/lib.rs`) vs any Lean lemma, and **GitHub org branch-protection required-status-checks** (F1's HIGH severity assumes standard path-filter semantics; an org-level required-check override could not be inspected from this environment — verify before acting on F1).