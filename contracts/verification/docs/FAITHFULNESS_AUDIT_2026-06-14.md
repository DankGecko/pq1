# Faithfulness audit of the Lean verification — 2026-06-14

This audit answers a *different* question from the recurring consistency loop.
The loop (and `make verify-extracted` / `dump_axioms`) answers **discipline**:
no `sorry`, no escape hatches, the axiom set is consistent (can't derive
`False`), closures stable. That is mechanical and gateable.

This audit answers **faithfulness-to-intent** (semantic, judgment): does
`theft_free` actually capture "no unauthorized fund movement"? Are the axioms
the right assumptions, stated correctly? Is each theorem *strong enough that a
real bug would break it*? This is exactly where the EUF-CMA inconsistency and
the false `sha256_injective` hid — both passed every consistency gate and were
wrong only in spirit.

Method: three adversarial techniques run as a 12-agent workflow.
1. **Mutation testing** (gold standard) — inject a *genuine* defect into the
   verified models in an isolated worktree, rebuild the whole `lean/` project +
   the executable KAT, and record **KILLED** (a proof/KAT broke → the
   verification is sensitive to that bug) vs **SURVIVED** (the bug passed → a
   faithfulness hole).
2. **Threat-model → theorem coverage matrix** — every CLAUDE.md non-negotiable
   invariant mapped to a theorem / Halmos rule / cited-TCB axiom / NOT COVERED.
3. **Per-axiom falsifiability review** — for each axiom: the real-world fact +
   "what observation would prove it false?" + PASS/FAIL.

All findings below were reproduced kernel-side against a clean HEAD worktree
(`8377628`); none is a worktree/test artifact.

> ## ✅ Both action items RESOLVED 2026-06-14 (same day)
>
> - **P1 survivor (cap-bootstrap) — CLOSED.** Added
>   `capOk_bootstrap_implies_strict` + `validateSignature_bootstrap_cap_strict`
>   (Invariants.lean, kernel-clean `{propext, Quot.sound}`), the bootstrap
>   mirror of the slot path's `capOk_slot_implies_strict`. **Verified the fix
>   kills the mutant:** re-applying `<`→`≤` at ValidateUserOp.lean:298 now fails
>   to compile (`unsolved goals` in the new lemma). Two-gate parity restored.
> - **Gap-3 (replaySafeHash domain separation) — MODELED.** New
>   `Wallet/OffchainBinding.lean`: models Solady's keccak-nested `replaySafeHash`
>   + the nested EIP-1271 entry point, and proves
>   `offchain_nested_disjoint_from_userop_digest` — an off-chain-signed value is
>   never any UserOp `sphincsDigest` (∨ BreaksHash). Reduces to ONE new cited
>   axiom `keccak_sha256_cross_separation` (cross-hash separation, same
>   `∨ BreaksHash` reduction shape as `sha256_collision_resistance`; `keccak256`
>   is `opaque`, not a named axiom). **`theft_free`'s 11-axiom closure is
>   unchanged** (verified); the new axiom enters only the disjointness
>   corollary. AXIOM_STATUS.json updated (A6).
>
> ## ✅ P2/P3 follow-ups also landed 2026-06-14 (A4 held for review)
>
> - **Gap-4 (upgrade_path_unreachable) — DONE.** New `Wallet/UpgradeSafety.lean`
>   composes the two already-proven pieces (`Execute.execute_rejects_self_target`
>   + `executeBatch_rejects_self_target` + `StorageLayout`
>   impl-slot-disjointness) into the named conjunction `upgrade_path_unreachable`
>   (kernel-only, no new axiom, no re-proof).
> - **Gap-2 (per-call attribution) — DONE (honest scope).** Added per-execute-
>   STEP injective attribution to `TxFlow.lean`
>   (`growing_executes_le_verified_validates`: `#call-steps ≤
>   #verifier-true-validates`, via a token-`ledger` proven to agree with the real
>   `runTrace`). Rules out the existential gate's blind spot (1 validate → 2
>   executes). **Honest scope:** per-execute-STEP, NOT per-call-ELEMENT (batch
>   appends many calls under one validate; a literal per-call provenance map needs
>   a model change). Builds on the EXISTING trace model; kernel-clean; no new axiom.
> - **Gap-1 (closed-world) — DONE (CI lint).** `check_storage_mutators.sh` +
>   `make verify-storage-mutators` pin the 5-mutator allow-list; tested
>   positive (pass) + negative (a fake `evilReset` trips it). Build-side gate
>   (Lean has no sound in-kernel "all Storage mutators" reflection), strictly
>   stronger than the prior comment.
> - **A4 (give `evm_bytecode_executes_correctly` content) — DONE (user-approved);
>   wording corrected by pass-2.** Restated `: True` → `∀ c, evmDeliversCall c`
>   (opaque predicate), which *names* the EVM-delivery assumption (the real gain).
>   `theft_free` references it via a `have _a4_delivers` binding so it appears in
>   the closure, but **pass-2 corrected the earlier "now load-bearing" claim:**
>   the binding is NOT consumed by the safety proof (deleting it, axiom retained,
>   leaves `theft_free` proven → 9 genuine premises). A4/A1 are non-consumed TCB
>   markers in the 11-name closure, not semantic premises. Closes the
>   falsifiability FAIL (no more `: True`); `lint_axioms` reports **zero
>   `: True`-typed axioms**. AXIOM_STATUS A4 updated (`placeholder_true_typed` 1→0).
>
> Verified integrated: full `lake build` 0-sorry; `theft_free` closure unchanged;
> all new theorems kernel-clean; detonator type-errors; KATs 10/10 + 384/384.
>
> The remaining items (the out-of-scope device invariants #1–#4 + trusted
> display) stay tracked in `docs/work-todo.md`.

---

## 1. Mutation battery — 8/9 killed-good, 1 survivor (P1)

| Mutant | Injected defect | Result |
|---|---|---|
| `cap-slot` | delete the slot combined-cap conjunct in `capOk` | **KILLED** — `capOk_slot_implies_strict` (Invariants.lean:549) fails to compile; takes `combinedCap_inductive` with it |
| `exec-self-target` | delete `if target = σ.selfAddress then none` in `executeWithOffchainCount` | **KILLED** — `exec_passes_guards` / `exec_post_state` / `execute_rejects_self_target` break |
| `exec-credit-index` | delete the `validatedOwnerPlusOne - 1 ≠ ownerIndex` guard | **KILLED** — `execute_requires_token_match` (audit H-3) breaks |
| `verifier-digitsum` | WOTS+C `TargetSum` 205 → 204 | **KILLED** — KAT drops to full-verify 6/10 (valid vectors rejected) |
| `adrs-chainpos` | re-introduce the historical CWE-347 ADRS `setChainPos`→`setChainIndex` bug | **KILLED** — KAT drops to 6/10 |
| `verifier-lastfors` | remove the "last FORS index = 0" forced-zero reject | **KILLED** — `verify_rejects_nonzero_last_fors_idx` / `verify_rejects_bad_digit_sum` break |
| `eufcma-tofalse` | revert the EUF_CMA conclusion `BreaksHash` → `False` (the prior inconsistent shape) | **KILLED** — static **type error at the use site** in `theft_free` (`Theorems.lean:345`: `has type False, expected BreaksHash`). Caught by `lake build`, the strongest gate — *stronger than predicted*: the hardening made the regression a compile error, not merely a closure/probe finding. |
| `keyhistory-weaken` | delete the `signed_recorded` completeness field of `KeyHistory` | **KILLED** — `keyHistory_empty_signs_nothing` / `honest_sig_not_forgery` fail to elaborate |
| **`cap-bootstrap`** | **weaken the bootstrap few-time cap `bootstrapUses < MaxBootstrapUses` → `≤` (off-by-one)** | **SURVIVED — faithfulness hole (P1)** |

**Reassurance from the 8 kills:** the verification is genuinely sensitive to
real money-moving bugs — cap evasion, self-re-entry, owner-substitution, the
WOTS+C forced-sum gate, the ADRS field bug we fixed before, the FORS forced-zero
constraint, and *both* crypto-trust-base regressions are all caught, most at
compile time before the KAT even runs. In particular the 2026-06-14 EUF-CMA
hardening is now **structurally enforced by the type-checker**: reverting to the
inconsistent `→ False` shape is a static type error, because `theft_free`'s
conjunct 2 is typed `… → Crypto.BreaksHash` and discharged by
`cannot_forge_without_breaking_SHA256` at the use site.

### The survivor — `cap-bootstrap` off-by-one (P1, confirmed)

Weakening `capOk`'s bootstrap branch
(`ValidateUserOp.lean:298`, `decide (s.bootstrapUses < MaxBootstrapUses)`) to
`≤` — an off-by-one that accepts one use **past** `MAX_BOOTSTRAP_USES` —
**compiles clean (`lake build` exit 0) and passes all 10 KAT vectors.** The
boundary probe confirms the semantic change: at `bootstrapUses == MaxBootstrapUses`
the original `capOk` rejects, the mutant accepts.

**Root cause — a proof-coverage asymmetry between the two cap paths:**

- The **slot** path is double-protected. `capOk_slot_implies_strict`
  (Invariants.lean:549) proves `capOk = true ⇒ slotUses i + offchainSigCount i <
  MaxSlotUses`, and feeds `combinedCap_inductive`. Deleting the slot cap
  conjunct therefore **detonates that proof** (mutant `cap-slot`, killed-good).
- The **bootstrap** path has **no `capOk_bootstrap_implies_strict` analog.**
  `capOk` is load-bearing for model success (`validateSignature:353` gates on
  it; `validateSignature_success_iff:329` carries `capOk … = true`), but its
  bootstrap **strictness is never asserted by any theorem.**
  `validateSignature_bootstrap_monotonic` (Invariants.lean:137) proves only
  `≤` non-decrease, not the ceiling.

So `capOk`'s bootstrap conjunct is a **faithful copy of whatever the Solidity
gate says** — the Lean model provides *zero proof coverage* of its strictness.
The end-to-end model stays observationally safe today **only** because of a
*second, redundant* belt-and-braces gate: `Storage.bumpBootstrap`'s
`if s.bootstrapUses + 1 > cap then none` (MultiOwnable.lean:30, proved by
`bumpBootstrap_capped`). That single non-redundant gate is the only thing
holding invariant #7 for the bootstrap path.

**Impact:** a *real* Solidity off-by-one in the deployed
`bootstrapUses < MAX_BOOTSTRAP_USES` gate would survive this verification
identically — the verification would not catch it. This is a true blind spot on
a non-negotiable cap invariant (#7), exactly symmetric to a property the slot
path *does* prove.

**Why P1, not P0:** invariant #7 is **not** violated in the current tree (HEAD
is strict; the bump gate masks any single-gate off-by-one observationally), and
bootstrap-cap exceedance is a few-time-cap overrun, not a direct
signature-forgery/drain. But it should be closed for two-gate parity with the
slot path.

**Fix (APPLIED + verified 2026-06-14):** added
`capOk_bootstrap_implies_strict` (mirror of `capOk_slot_implies_strict`, peeling
the `ownerIndex = 0` conjunct) and a load-bearing consumer
`validateSignature_bootstrap_cap_strict` (the bootstrap counterpart of
`combinedCap_inductive`: a bootstrap op is accepted only if
`bootstrapUses < MaxBootstrapUses` strictly — the precondition the post-state
`bumpBootstrap_capped` bound does not give). Both kernel-clean
(`{propext, Quot.sound}`). **Verified the fix kills the mutant:** re-applying
`<`→`≤` at ValidateUserOp.lean:298 now fails to compile (`unsolved goals` in
`capOk_bootstrap_implies_strict`).

---

## 2. Coverage matrix — on-chain contract proven; 5 of 9 device invariants out of scope

The Lean project models the **on-chain contract layer + the SPHINCS+C10 spec
only.** It contains *zero* model of firmware / secure-world / hardware.

**COVERED (proven):** the headline `theft_free` / `theft_free_bytecode`; field
binding (`theft_free_with_calldata_binding`); the wallet invariants I-1…I-8
(non-bypass, cap monotonicity, no-reset, bootstrap-unremovable, init-once,
combined cap, CREATE2 chain-independence, factory squat-defence); the off-chain
EIP-1271 bootstrap-forbidden rule; executeBatch faithfulness. The wallet-state
half is kernel-clean (`{propext, Quot.sound}`); the bytecode link is discharged
by Halmos (A3.2/A3.2-exec/A3.3/A3.4) + the corpus-bound A3.1.

**NOT COVERED (out of scope — silicon E2E + security-review docs only):**

| CLAUDE.md invariant | Status |
|---|---|
| #1 Dual-chip XOR seed split | **NOT COVERED** (firmware-only) |
| #2 Hardware PIN three-way lockstep / 10-attempt brick | **NOT COVERED** (firmware/SE-only) |
| #3 E2E SE tunnels (Shielded Connection / SCP03) | **NOT COVERED** (firmware/SE-only) |
| #4 TrustZone secret isolation + NS-ptr TOCTOU | **NOT COVERED** (GTZC is silicon-validated, not Lean) |
| Trusted-display clear-signing (EIP-712 SafeTx/CoW + Groth16) | **NOT COVERED** (secure-world UI/zk) |
| #9 firmware half — `MAX_OFFCHAIN_GAP=100` unbacked-sig refusal, page-123 counter | **PARTIAL** (on-chain combined cap proven; firmware gap-refusal not modeled) |

This is the single largest honest gap **by surface area**. The Lean proof's
claim surface is the on-chain contract; the device's own security model is not
formally proven. Readers must not over-read "theft_free proven" as a
device-wide guarantee.

**On-chain-adjacent coverage gaps (smaller, but proof-relevant):**

- **Gap-3 (highest-value) — RESOLVED 2026-06-14.** Was: `replaySafeHash` EIP-712
  nesting not modeled (`Wallet/IsValidSignature.lean` fed the raw `hash` straight
  to `verify_fn`). Now modeled in `Wallet/OffchainBinding.lean`: the keccak-nested
  `replaySafeHash` + nested entry point + the proven theorem
  `offchain_nested_disjoint_from_userop_digest` (off-chain value ≠ any
  `sphincsDigest`, ∨ BreaksHash), grounded on the cited cross-hash separation
  axiom `keccak_sha256_cross_separation`. The firmware-not-companion nesting and
  its domain separation are now **proven** (modulo the cited cross-hash
  assumption), not assumed.
- **Gap-2:** `every_call_gated_by_verifier` (Claim 4) is **existential, not
  per-call** — proves *some* verifier-true validate appeared when the callStack
  grew, not that *each* external call is individually attributable. The
  docstring flags this as an OPEN_PROOF_OBLIGATION.
- **Gap-4:** `upgrade_path_unreachable` is **partial** — only StorageLayout
  slot-disjointness is proven; self-target rejection exists (Execute E-2) but
  the two are not assembled into the named end-to-end theorem.
- **Gap-1:** `no_reset_path` proves the 5 *known* mutators are non-decreasing;
  "these are the only mutators" is an out-of-Lean closed-world assertion
  (mitigated on the bytecode side by A3.2/A3.4 Halmos equivalence).
- **Gap-8:** A3.1 ∀-signature equivalence is corpus-only (10-KAT + 384-bulk +
  ~250-mutant screen), not a symbolic ∀ proof — intractable under uninterpreted
  SHA-256. Already disclosed in `A3_1_VERIFIER_GAP.md`.
- **Gap-11:** the Halmos discharges (A3.*) are cited solver sessions in the TCB,
  not kernel-checked; A3.2's UNSET-ownerIndex partition is concrete-rep-only.

---

## 3. Per-axiom falsifiability — 2 FAIL (non-falsifiable as stated, both benign)

PASS (falsifiable + believed true): A1 (precompile=FIPS), A2 (entrypoint_honest
— PASS but bridged-by-citation, not bytecode), A3.1–A3.4 (Halmos-discharged;
A3.1 form stronger than its finite-corpus evidence), A5-EUFCMA, A5-SMTCR,
A5-ITSR, A5-RO (opaque Props, citation to Barbosa et al.; qualitative shadow
only — no `Pr ≤ ε`), **A5-collision-resistance** (the `= ∨ BreaksHash` reduction
— confirmed the *only* crypto axiom in `theft_free_with_calldata_binding`'s
closure), + the kernel trio.

**FAIL — non-falsifiable as stated (both sound, but worth recording):**

- **A4 `evm_bytecode_executes_correctly` — was `: True`, RESOLVED 2026-06-14.**
  The `True`-typed placeholder carried zero propositional content (hostile
  removal broke no proof), yet it is the EVM-execution boundary through which
  `theft_free` routes *every* actual value movement (the emitted-CALL byte
  delivery on the execute path). It is now restated as
  `∀ c, evmDeliversCall c` (opaque predicate naming the EVM-delivery
  assumption) — implementing this section's own recommendation ("replace
  `: True` with an explicit, documented kernel-TCB statement that names what is
  assumed"). It is surfaced in `theft_free`'s closure as a NON-CONSUMED TCB
  marker (a `have` binding), NOT a semantic premise — pass-2 corrected the
  initial "consumed/load-bearing" wording (deleting the binding leaves
  `theft_free` proven over its 9 genuine premises). Same cited-TCB strength;
  the `lint_axioms` gate now reports zero `: True` axioms.
- **`keccak256_pure` (extracted, FunsExternal.lean:14)** — an uninterpreted
  total-function postulate `Slice U8 → Array U8 32`. Asserts only existence of a
  total deterministic 32-byte function; does **not** assert equality with real
  keccak-256, so no observation about real keccak could refute it. Benign and
  standard for Aeneas hash boundaries (the §33 equivalence proofs need only
  totality + determinism; the faithful-keccak binding is cited externally via
  Rust KATs + EVM conformance), but non-falsifiable as a real-world claim.

**Confirmed retired from the live closure** (verified via `dump_axioms`): the
old false `sha256_injective_on_fixed_length`, the `EUF_CMA … → False` detonator,
and the dangling+latent-false `entrypoint_no_replay`. The mutation battery
re-confirmed the regression fences (`eufcma-tofalse` + `keyhistory-weaken` both
killed-good).

---

## 4. Bottom line

**The verification is faithful to "no unauthorized fund movement" within its
declared scope, with one confirmed P1 transcription hole and a well-understood
scope boundary.**

- The **signature layer** (no balance move without a valid C10 sig over an
  installed owner's `sphincsDigest`) is strongly proven and **mutation-robust**
  — 8/9 real defects caught, most at compile time.
- The **few-time-cap layer** is proven for slots but, for **bootstrap**, leans
  on a single non-redundant gate rather than the two-gate defense the slot path
  enjoys — the P1 survivor. One lemma closes it.
- The proof's **claim surface is the on-chain contract + C10 spec only.** Five
  of nine device invariants (#1–#4 + trusted display) are covered by silicon E2E
  + security-review docs, **not** formal proof. State this in any headline.
- Two axioms (A4, `keccak256_pure`) are **non-falsifiable as stated** but sound;
  the rest are honest cited assumptions. No false / vacuous / inconsistent axiom
  remains.

### Methods that would bite next (none is a tight loop)
Mutation testing (run periodically, expand the battery — especially once the P1
lemma lands, to keep it killed); a per-call attribution proof (Gap-2);
`replaySafeHash` domain-separation modeling (Gap-3); a diverse third oracle
(patched Python signer) in the Rust↔Solidity↔Lean differential; and
Kontrol/KEVM for the A3.1 ∀-signature gap.
