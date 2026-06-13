# Trust Assumptions — PQSmartWallet Three-Claim Proof

This document is the **single, authoritative inventory** of everything that
lives in the TCB of the SphincsCVerify formal-verification stack.

The headline theorem is `theft_free` in `Spec/Theorems.lean`. Three
per-claim corollaries cover the user-facing statements:

| Claim | Corollary | Location |
|-------|-----------|----------|
| 1. Signature-to-execution binding | `theft_free_with_calldata_binding` | `Spec/Theorems.lean` |
| 2. Owner-set integrity + init atomicity | `initialize_called_exactly_once`, `owner_set_nonempty_after_init`, `cannot_remove_bootstrap` | `Wallet/Invariants.lean` |
| 3. Execution faithfulness + value flow | `executeBatch_faithful` (composes E-1..E-8) | `Spec/Theorems.lean` + `Wallet/Execute.lean` |

The contrapositive of each: any unauthorised drain / owner mutation /
execution-faithfulness violation implies one of the assumptions below
is false.

---

## A1. SHA-256 precompile (EVM `0x02`) implements FIPS 180-4

* **Lean.** `Bridge/Refinement.lean::precompile_0x02_is_FIPS_180_4`
* **Type.** `∀ input, DeployedBytecode.SHA256_precompile input = Spec.sha256 input`
  (post-Phase-0 refactor: opaque-equality shape; real propositional content).
* **Scope.** Every `staticcall(0x02, ...)` in `SPHINCsC10Asm.verify`
  returns the FIPS 180-4 hash of its input.
* **Discharge.** Cited universal Ethereum TCB (consensus-client
  conformance: geth, reth, erigon, nethermind). Empirically backed by
  the Foundry parity test
  `test/PinnedCodehashes.t.sol::test_sha256_precompile_{abc,empty}_kat`.
* **Elimination path.** Verify the SHA-256 implementation in a
  consensus client (Appel/VST-style). Universal Ethereum trust;
  outside any single contract project.

## A2. EntryPoint v0.6 is unhackable

* **Lean.** `Bridge/EntryPoint.lean::entrypoint_honest`
* **Scope.** The deployed EntryPoint v0.6 contract at
  `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`:
  * only invokes wallet execution after `wallet.validateUserOp`
    returned the success sentinel;
  * does not itself transfer wallet value;
  * supplies `userOpHash` per ERC-4337 v0.6.
* **Discharge.** Cited; per user decision A2 stays as a Lean fiction
  (no Kontrol-against-deployed-bytecode discharge). The OZ /
  ChainSecurity / Spearbit audits + 18+ months mainnet operation are
  the trust basis.
* **Elimination path.** Model EntryPoint v0.6 in Lean and discharge
  against KEVM. 8-12 month engagement; out of current scope.

### A2-noreplay. EntryPoint enforces `(sender, nonce)` uniqueness

* **Lean.** `Bridge/EntryPoint.lean::entrypoint_no_replay`
* **Scope.** A second `handleOp` with the same `(sender, nonce)` after
  the first was accepted leaves the state unchanged.
* **Discharge.** Same as A2 (cited EntryPoint v0.6 audits).

## A3. `solc 0.8.28` compiles the four PQ contracts correctly

Post-Phase 0 refactor: A3 is split into four per-contract sub-axioms,
each an `opaque + axiom-equality` shape that asserts the deployed
bytecode matches the Lean model. Removing any one would leave the
per-claim corollaries unprovable.

> **CURRENT (2026-06-13).** `AXIOM_STATUS.json` + `PINNED_CODEHASHES.md` are
> the AUTHORITATIVE source for codehashes and discharge artifacts; the
> entries below are kept in sync with them. The A3.* axioms are
> `discharged-bytecode`: the full Halmos suite (38 rules) passes on BOTH the
> `default` (runs=200) and `deploy` (runs=999999) profiles' bytecode, and the
> deploy-profile build reproduces the live Base Mainnet contracts exactly
> (`test/DeployedBytecodeReproCheck.t.sol`). Codehashes are shown as
> `default / deploy`. (Historical note: a prior 2026-05-27 snapshot pinned
> stale hashes — A3.2 `0xdc2aa6c4…`, A3.3 `0x604e4000…`, A3.1 `0x919cf8ef…` —
> and attributed A3.3/A3.4 to Certora; those have been superseded by the
> Halmos discharge below.)

### A3.1. `solidityVerifier_compiles_correctly`

* **Lean.** `DeployedBytecode.SPHINCsC10Asm_verify = verifyYulModel`
* **Pinned codehash.** `0xf1ef4ccee22e6b39446723232fe39761f089c7195941b2c12576956b38fcfef5` (default) / `0xeb1e3fcd38c7cd5f7b08352c298b34bd114d83f7dbd755b122c41eda2aab2cc5` (deploy — **byte-identical to on-chain Base Mainnet verifier `0xdDE4D290…`**)
* **Discharge.** Halmos input-gate rules (`test/halmos/HalmosVerifier.t.sol`,
  length / N-mask) + **full-functional** executable Lean↔FIPS↔bytecode KAT
  (`lake exe verify-test-vectors` full-verify 10/10) + bulk 384/384
  (`verify-bulk`) + ~250-mutant wrong-accept screen. ∀-signature symbolic
  equivalence is the standing ceiling (uninterpreted SHA-256 = A1).

### A3.2. `solidityWallet_compiles_correctly` (+ A3.2-exec)

* **Lean.** `DeployedBytecode.PQSmartWallet_validateUserOp = validateSignature`
  (+ `executeWithOffchainCount` / `executeBatchWithOffchainCount`), on
  reachable states (combined-cap invariant).
* **Pinned codehash.** `0x43c65420691792d7f0f63dab95f47ab7adb649df4c83f432bd3cf2c95db3a06a` (default) / `0x551c4e03bbd433a5929828ab19caac13a94ca9e2be6074cf3e18c7d926034c22` (deploy)
* **Discharge.** Halmos pointwise-equivalence — primary
  `test/halmos/HalmosValidateUserOpEquiv.t.sol` + `HalmosExecuteEquiv.t.sol`;
  per-property corollaries `HalmosValidateUserOp.t.sol` + `HalmosExecute.t.sol`.

### A3.3. `solidityFactory_compiles_correctly`

* **Lean.** `DeployedBytecode.PQSmartWalletFactory_createAccount_passes ↔ Factory.createAccountPrecondition`
* **Pinned codehash.** `0xfa2922b4fadb81b4475307504890d68f2e3d9be97c7e5e9aeeba6e84110d7c3c` (default) / `0x5feb7955252e54bcbbf44062295bdeb45f3dea13c4ef7fb1ba579196d84da4b9` (deploy)
* **Discharge.** Halmos `test/halmos/HalmosFactory.t.sol` (5 rules) — the
  prior Certora rule-set `certora/PQSmartWalletFactory.spec` is an
  alternative path.

### A3.4. `solidityMultiOwnable_compiles_correctly`

* **Lean.** `DeployedBytecode.PQMultiOwnable_ownerAtIndex s i = s.ownerAtIndex i`
* **Pinned codehash.** `0x43c654…a06a` / `0x551c4e…34c22` (embedded in `PQSmartWallet`; no independent deploy)
* **Discharge.** Halmos `test/halmos/HalmosMultiOwnable.t.sol` (7 rules) —
  REPLACED the prior Certora artifact `certora/PQMultiOwnable.spec`, which had
  been pinned to a stale codehash and never re-run.

## A4. EVM bytecode executes per specification

* **Lean.** `Bridge/Refinement.lean::evm_bytecode_executes_correctly`
* **Type.** `True` (per user decision, A4 stays as a cited-TCB marker;
  not refactored to opaque-equality).
* **Scope.** Every opcode the deployed bytecode uses executes per the
  EVM spec (Cancun / per-chain configuration).
* **Discharge.** Cited universal Ethereum TCB; KEVM is the
  formal-EVM-semantics referent.

## A5. SPHINCS+C10 is EUF-CMA secure

* **Lean.** `Crypto/EUFCMA.lean::EUF_CMA_SPHINCSplusC` plus the three
  shape axioms in `Crypto/Assumptions.lean` (`SM_DT_TCR_F`, `ITSR_F`,
  `hMsg_random_oracle`) and the new corollary
  `sha256_injective_on_fixed_length`.
* **Scope.** For every PPT adversary `A` making at most `Q` signing
  queries, `A`'s forgery probability is bounded by
  `ε(A) + Q · 2^-128`.
* **Discharge.** Barbosa/Dupressoir/Hülsing/Meijers/Strub ASIACRYPT
  2024 (ePrint 2024/910) for SPHINCS+; Hülsing PQC2022 for the
  WOTS+C/FORS+C variant.
* **Elimination path.** Extend the Barbosa et al. EasyCrypt
  development to SPHINCS+C. Multi-person-year research.

### A5-injective. SHA-256 collision-free on equal-length inputs

* **Lean.** `Crypto/Assumptions.lean::sha256_injective_on_fixed_length`
* **Scope.** Named corollary of SM_DT_TCR_F (when restricted to the
  empty ADRS tweak). Used by Claim 1's
  `sphincsDigest_field_binding` lemma.

## A6. Lean 4 kernel checks proofs correctly

* **Scope.** The Lean 4 kernel (pinned in `lean-toolchain`) faithfully
  checks every closed `theorem` in this project.
* **Built-ins.** `propext`, `Classical.choice`, `Quot.sound`.

---

## Per-claim trust footprint

| Claim | Axioms cited in `#print axioms` of the corollary |
|-------|--------------------------------------------------|
| 1. Signature-to-execution binding | A6 (kernel), A5-injective (`sha256_injective_on_fixed_length`). The full `theft_free` adds A1, A2, A3.1, A4, A5 (4 sub-axioms). |
| 2. Owner-set integrity + init atomicity | A6 only (`initialize_called_exactly_once` and `owner_set_nonempty_after_init` are purely structural). For bytecode-level enforcement, A3.4 (MultiOwnable) + A3.2 (Wallet) + A3.3 (Factory) are discharged by Certora. |
| 3. Execution faithfulness + value flow | A6 only (`executeBatch_faithful` is purely operational). For bytecode-level enforcement, A3.2 (Wallet) is discharged by Halmos against pinned `PQSmartWallet` codehash. |

The minimal TCB shared by all three claims:
**A6 (Lean kernel) + A5 (SPHINCS+C10 + the named injective corollary)
+ A1 (SHA-256 precompile) + A2 (EntryPoint v0.6) + A4 (EVM bytecode)
+ A3.1-A3.4 (per-contract solc correctness, each discharged by a
Halmos session, Certora rule-set, or differential test).**

---

## Out of scope (not in TCB, deliberately excluded)

These are *not* trusted; they are *omitted from the model* entirely.
Their failure does not invalidate the three claims — they are simply
outside their scope.

* **Firmware** (Rust under `secure/`, `nonsecure/`, workspace crates).
  The proof says nothing about whether the firmware actually keeps the
  secret keys secret; if the secret keys leak, the adversary holds an
  "installed owner key" and the theorem is vacuously satisfied.
* **Side-channel security** of firmware signing.
* **Gas / DoS / griefing** — covered empirically by Foundry tests,
  not by these proofs.
* **MEV / bundler manipulation** — the theorem speaks only about
  whether a UserOp was authorised, not about ordering or
  front-running.
* **Frontend / companion app** — `tools/wallet_run_hw.py`, the WebHID
  companion, RPC providers. Adversarial frontends cannot forge sigs
  (A5) but can refuse to forward valid ones (liveness, not safety).
* **Cross-chain replay** — the chain-id binding is part of
  `sphincsDigest`'s preimage; cross-chain replay would be a forgery
  (contradicts A5).

---

## Three-claim headline statement

> *Given* A1–A6 (with the per-contract A3 sub-axioms discharged by
> Halmos and Certora against pinned codehashes), for any deployed
> `PQSmartWallet` proxy `W`:
>
> 1. **Signature-to-execution binding.** No successful
>    `executeWithOffchainCount` / `executeBatchWithOffchainCount` runs
>    without a SPHINCS+C10 signature valid under an installed owner
>    key of `W` over a `sphincsDigest` that commits to the exact
>    chainId, sender, nonce, and calldata being executed.
>
> 2. **Owner-set integrity + initialization atomicity.** The owner
>    set is mutated only by self-call originating from a validated
>    UserOp; never empty after `initialize`; `initialize` runs
>    exactly once; the UUPS upgrade path is unreachable.
>
> 3. **Execution faithfulness under batching and value flow.**
>    `executeBatchWithOffchainCount` performs exactly the signed
>    `(target, value, data)` tuples in order; only EntryPoint reaches
>    the executor; total ETH outflow equals the signed batch sum;
>    no callback can alter the remainder of the batch.

See [`AXIOM_STATUS.json`](AXIOM_STATUS.json) for the machine-checkable
discharge-artifact tracking,
[`PINNED_CODEHASHES.md`](PINNED_CODEHASHES.md) for the bytecode pins,
and [`OPEN_PROOF_OBLIGATIONS.md`](OPEN_PROOF_OBLIGATIONS.md) for the
remaining work to tighten each cited-TCB axiom into a discharged one.
