# Open Proof Obligations — Proving Assets Cannot Be Stolen from `PQSmartWallet`

> **Historical-plan notice — 2026-07-15.** This is the May closeout plan, not
> the authoritative current obligation inventory. The Lean reference signer is
> now implemented in the model (`Signer.sign`, `findCount_post`, component
> roundtrips, and `honest_consistent`); the open obligation is production
> Rust/firmware signer and serialization→model refinement. The authorization
> digest is `PQSmartWallet.sphincsDigest(userOp)`, not EntryPoint's canonical
> keccak `userOpHash`; the deployed wallet ignores the supplied canonical hash.
> Current status is routed through [`FV_SURFACE_MAP.md`](FV_SURFACE_MAP.md),
> [`FV_VALUE_AND_GAPS.md`](FV_VALUE_AND_GAPS.md), and the
> [2026-07-15 findings](../../../docs/security/adversarial-review/findings/fv-full-stack-2026-07-15-coordinator.md).

This document records the **historical remaining work** proposed to take the SphincsCVerify
project from its current state to a kernel-checked formal-verification result
for the single goal:

> **Theft-freedom.** No adversary — without knowledge of the firmware-resident
> SPHINCS+C10 secret keys — can cause value held by a deployed `PQSmartWallet`
> proxy to be transferred to an address they control.

Everything in this project exists to discharge that one statement.

## Trusted assumptions

The proof rests on these axioms. Anything outside them is in scope and must
be discharged in the single phase below.

| # | Assumption | Where |
|---|---|---|
| A1 | The SHA-256 EVM precompile at `0x02` implements FIPS 180-4. | `Bridge/Refinement.lean::precompile_0x02_is_FIPS_180_4` |
| A2 | EntryPoint v0.6 is unhackable: it only calls `wallet.validateUserOp` with well-formed UserOps, only proceeds to execution if `validateUserOp` returned success, and does not itself move wallet value. | `Bridge/EntryPoint.lean::entrypoint_honest` |
| A3 | `solc 0.8.28` compiles `PQSmartWallet`, `PQMultiOwnable`, `PQSmartWalletFactory`, and `SPHINCsC10Asm` to EVM bytecode that faithfully implements their Yul/Solidity-source semantics. | `Bridge/Refinement.lean::solidityVerifier_compiles_correctly` (generalised) |
| A4 | EVM bytecode executes per the EVM specification. | `Bridge/Refinement.lean::evm_bytecode_executes_correctly` |
| A5 | SPHINCS+C10 is EUF-CMA secure (composed bound from SHA-256 SM-DT-TCR + ITSR + random-oracle modelling of `H_msg`). | `Crypto/EUFCMA.lean::EUF_CMA_SPHINCSplusC` plus the three SHA-256 axioms in `Crypto/Assumptions.lean` |
| A6 | The Lean 4 kernel checks proofs correctly. | Universal. |

> **Deferred by decision — stylistic, NOT owed (2026-06-29).** A2's in-Lean
> `entrypoint_honest` is a *tautology over the `handleOp` model* (its conclusion
> follows from `handleOp`'s definition); it is an `axiom` only to surface A2 in
> `theft_free`'s `#print axioms` closure. It *could* be restated as an opaque
> non-consumed marker (like A4's `evmDeliversCall`) so the closure **names** the
> deployed-EntryPoint + prefund assumption instead of showing a provable tautology.
> This is **deliberately not done**: the gain is marginal — the tautology is
> already disclosed (`TRUST_ASSUMPTIONS.md` A2, `ASSURANCE_CASE.md` §4, the axiom
> docstring), and `make verify-proof-mutation` (A2-load-bearing) +
> `verify-ledger-consistency` now characterize A2 mechanically — while the cost is a
> change to `theft_free`'s **pinned** closure (re-pin `verify-ledger-consistency`
> `signature_pins` + `lint_fv` c.2 + `dump_axioms` + ~7 docs in lockstep). Revisit
> only if a concrete need arises that this cannot meet a better way.

The hardware-wallet firmware, side-channel resistance, MEV/bundler griefing,
gas/DoS bounds, and frontend key management are out of scope.

---

## The single phase

Everything is one phase. It contains every theorem that has to close for the
top-level theft-freedom statement to type-check.

The phase is organised by source-file area only because work-items in
different files are independent and can be parallelised. There is no internal
ordering: any work-item that doesn't reference a `sorry` from another can be
attacked first. Total: **~6–9 person-months** for one engineer.

### Group V — Verifier and signer correspondence (current correction)

The committed Lean model now contains the reference signer, `findCount_post`,
component roundtrip lemmas, `honest_consistent`, a concrete deserialiser, the
kernel-computable SHA-256 model, and the model-side verifier refinement. Those
historical subgoals are closed in the model.

The remaining load-bearing work is different:

* prove current production Rust/firmware signing and serialization refines the
  Lean signer/model rather than relying only on KAT/corpus agreement;
* prove the parsed handler path passes exactly
  `compute_sphincs_digest_v06` to signing and connect it to the contract's
  `sphincsDigest`;
* make all mirrored-source extraction freshness fail closed; and
* retain deployed source/bytecode→committed Lean execution-model identity as a
  separate, explicit boundary.

Output (target): current-source, exact-artifact correspondence for the signer,
serialization, signed digest, and verifier layers. Do not reopen the completed
model signer or describe it as a stub.
### Group W — Wallet invariants

The wallet logic must route every successful UserOp through the verifier
and must not allow counter-bypass or owner-table manipulation that would
let unauthorized signers control the wallet.

Lean files live under `SphincsCVerify/Wallet/` (currently legacy, but
back **in scope** under this revised plan). Discharge:

* `Wallet/Invariants.lean::validateSignature_only_via_verify` (I-1,
  non-bypass) — every path to `Result.success` threads through
  `verify_fn _ _ _ _ = true` on `sphincsDigest op` under
  `ownerAtIndex(ownerIndex)`. Currently blocked on a real
  `decodeWrappedSig`; finish that decoder (lives in
  `Wallet/ValidateUserOp.lean`) then case-split each early return.
* `Wallet/Invariants.lean::validateSignature_bootstrap_monotonic` and
  `validateSignature_slot_monotonic` (I-2) — every successful transition
  increases the relevant counter; the off-path branches preserve state.
* I-3 (no reset) — structural: prove no `Storage`-API method decreases
  any counter. Closed by inspection if the API stays as it is; add a
  meta-theorem listing every state-mutating method and showing it.
* `Wallet/Invariants.lean::cannot_remove_bootstrap` (I-4) — already closed
  via `MultiOwnable.bootstrap_unremovable`.
* `Wallet/Invariants.lean::combinedCap_preserved_*` (I-5) — ✅ CLOSED (P1):
  `Invariants.Reachable` + `reachable_implies_combinedCap` assemble the
  preservation lemmas + the init base case into the full inductive invariant
  across the gated transition system (kernel-only `[propext, Quot.sound]`);
  `Spec.Theorems.theft_free_bytecode_reachable` is the headline conditioned on
  `Reachable` instead of the bald cap. Stays conditional on reachability by
  design (the bytecode reverts off-cap with no characterising axiom).
* New theorem `eip1271_forbids_bootstrap` (I-6) — `_erc1271IsValidSignatureNowCalldata`
  rejects `ownerIndex == 0` for every input.
* `Wallet/Invariants.lean::create2_address_chain_independent` (I-7) — pins the
  SALT preimage's chain-freeness (kernel). The address-level leg is now modelled
  (P11) by `create2Address_chain_independent`, which names the CREATE2 address
  `keccak256(0xff ‖ deployer ‖ salt ‖ keccak256(initCode))` and proves
  chain-independence CONDITIONAL on the EVM-TCB facts `deployer1 = deployer2`
  (singleton CREATE2 factory deployed to one address per chain) and
  `initCodeHash1 = initCodeHash2` (frozen initCode). OPEN residual: the
  chain-freeness of the deployer address and `keccak256(initCode)` is cited-TCB,
  not modelled in Lean.
  **UPDATE 2026-07-17 — `ich1 = ich2` TCB decomposed.**
  `create2Address_chain_independent_via_impl` replaces the opaque
  `initCodeHash1 = initCodeHash2` premise with the structural model
  `initCodeHash proxyCode implementation = keccak256(proxyCode ‖ implementation)`
  (`PQSmartWalletFactory.sol:93`, `LibClone.createDeterministicERC1967` — the
  initCode carries NO chainId and NO chain-bound slot key; slot 0 is seeded by a
  separate post-deploy write) + the homogeneous `impl1 = impl2` premise. So the
  initCode-preimage chain-freeness is now Lean-PROVEN (kernel-only
  `[propext, Quot.sound]`, `initCodeHash_eq_of_impl_eq`); the cited-TCB surface
  shrinks to TWO homogeneous deterministic-deployment address identities
  (`factory1 = factory2`, `impl1 = impl2`), each the SAME CREATE2-determinism
  receipt (Arachnid `0x4e59…`, salt 0), discharged for the live Base deployment by
  `test/DeployedBytecodeReproCheck.t.sol` (factory `0xe8CE78CD…`, impl
  `0x31e49D24…` reproduced by CREATE2 replay). Cross-chain deployment identity is
  genuinely not a pure-Lean fact; this is the maximal Lean shrink of I-7's TCB.
* New theorem `factory_requires_bootstrap_sig` (I-8) — `createAccount`
  fails unless the bootstrap C10 signature over `addSlot0Digest(chainId,
  slot0PkSeed, slot0PkRoot)` verifies.
* Storage-collision freedom — model the ERC-7201 slot derivation and
  prove the wallet's storage slots are disjoint from any namespace
  reachable via `execute*`.
* No upgrade path — model the ERC-1967 proxy slot and prove no
  external call from `execute*` can write it.

Output: I-1 through I-8 closed; the wallet is proven to admit value
transfers only via owner-authorized UserOps.

### Group B — Bridge to deployed bytecode

* `Bridge/EntryPoint.lean` (new) — state A2 (`entrypoint_honest`) as a
  named axiom with the precise interface contract: EntryPoint only
  invokes execution after `validateUserOp` returned the success
  sentinel, never moves wallet balance directly, and passes
  `userOpHash` derived per ERC-4337 v0.6.
* `Bridge/Refinement.lean::solidityVerifier_compiles_correctly` —
  generalise from "verifier only" to cover `PQSmartWallet`,
  `PQMultiOwnable`, `PQSmartWalletFactory`, and `SPHINCsC10Asm`. Stays
  an axiom (A3) under this scope. The elimination path (Verity / KEVM
  bytecode equivalence) is documented but not required for the headline
  result.

Output: A2 and A3 stated; everything else in this group is already in
place (A1, A4 in `Bridge/Refinement.lean`).

### Group C — Cryptographic axioms (no change)

`Crypto/Assumptions.lean` and `Crypto/EUFCMA.lean` already carry the
needed axioms. The single `sorry` in `cannot_forge_without_breaking_SHA256`
is the in-Lean wiring between the EUF-CMA game and the verifier's accept
predicate — close it as the headline composes.

### Group T — Top-level theorem

* `Spec/Theorems.lean::theft_free` (new) — the composite. Statement:
  for any reachable wallet state `s` and any UserOp `op` such that
  `(EntryPoint.handleOp s op).balance(adversary) > s.balance(adversary)`,
  either (a) `op.signature` is a SPHINCS+C10 forgery against an
  installed owner key (contradicting A5), or (b) one of A1–A4 fails.

  Proof: A2 gives `validateUserOp` returned success → I-1 gives the
  signature verified → `verify_signs` + I-2/I-5 (counter discipline) +
  EUF-CMA (A5) gives that the signature was produced by the holder of
  the owner key. The CREATE2 / squat defences (I-7, I-8) close the
  cross-chain and counterfactual-deployment cases.

Output: a single closed theorem in `Spec/Theorems.lean` that quotes
A1–A6 as its only non-Lean-kernel dependencies.

---

## Done criteria

* `make verify-build` succeeds. ✅
* `make verify-audit` reports `0` `sorry`s anywhere under
  `SphincsCVerify/` (the `cannot_forge_without_breaking_SHA256` sorry is
  closed as part of Group C). ✅ As of 2026-05-18 the audit reports
  **0** `sorry`s — see [`BLOCKERS.md`](BLOCKERS.md) for the close-out.
* `#print axioms SphincsCVerify.Spec.Theorems.theft_free` lists exactly
  A1–A5 plus Lean kernel built-ins (`propext`, `Classical.choice`,
  `Quot.sound`). No additional axioms. ✅ Verified 2026-05-17.
* CI fails on any new `axiom` declaration outside the A1–A5 set.

## Status snapshot (2026-05-18)

| Group | Status |
|---|---|
| B — Bridge to deployed bytecode | ✅ `entrypoint_honest` added; `solidityVerifier_compiles_correctly` generalised. |
| C — Cryptographic axioms / EUF-CMA wiring | ✅ `cannot_forge_without_breaking_SHA256` closed; restructured `EUF_CMA_SPHINCSplusC` takes the three primitives as preconditions. |
| W — Wallet invariants | ⚠️ partial. I-1, I-2, I-3, I-4, I-6, I-8 closed; decoder concretised. **I-5 (combined cap): now kernel-discharged via reachability (P1).** The cross-counter preservation lemmas (`combinedCap_preserved_by_bumpSlot` / `combinedCap_preserved_by_setOffchain` / `combinedCap_preserved_by_bumpBootstrap`) + the inductive step `combinedCap_inductive` + the init base case are now ASSEMBLED into `Invariants.Reachable` (genesis + the gated EntryPoint transitions) and `Invariants.reachable_implies_combinedCap : Reachable s → ∀ i, combinedCapInvariant s i MaxSlotUses` — **kernel-only `[propext, Quot.sound]`, no axiom**. The discharged headline `Spec.Theorems.theft_free_bytecode_reachable` takes `Reachable σ.walletStorage` instead of the bald `hInv` and derives the cap (its `#print axioms` equals `theft_free_bytecode`'s — no new axiom). So the reachability is no longer a fuzz-backed assumption; the Foundry suite (`PQSmartWalletInvariants.t.sol::invariant_combined_cap_*`) now CORROBORATES it. The theorem stays correctly CONDITIONAL on `Reachable` (not unconditional — off the cap the bytecode reverts with no characterising axiom). Transition-set completeness rests on `check_storage_mutators.sh`. Residual: the raw-`hInv` `theft_free_bytecode` is retained for the A3.2-axiom statement; the model↔bytecode fidelity of the `Reachable` transitions is the same TCB layer as A3.2 itself. **I-7 (address determinism): open at the address level — only the SALT is proven chain-independent** (`create2_address_chain_independent`, `rfl`); full CREATE2-address chain-independence (`create2Address_chain_independent`) is a *conditional* theorem whose `deployer = deployer` / `initCodeHash = initCodeHash` premises are cited EVM-TCB facts (singleton factory address + frozen `initCode`), not modelled in Lean. **UPDATE 2026-07-17:** `create2Address_chain_independent_via_impl` decomposes the `initCodeHash` premise structurally (`initCodeHash proxyCode impl = keccak256(proxyCode ‖ impl)`, no chainId — Lean-proven `initCodeHash_eq_of_impl_eq`), shrinking I-7's cited-TCB to two homogeneous deterministic-deployment address identities (factory + impl, the same Arachnid/salt-0 CREATE2 receipt, discharged by `DeployedBytecodeReproCheck.t.sol`). |
| T — Top-level | ✅ `theft_free` closed with the required axiom set. |
| V — Verifier functional correctness | ⚠️ **Zero `sorry`s as of 2026-05-18, but read the round-trip caveat.** `verifyRefined_eq_spec` is closed (`rfl`); `Spec/Hash.lean::sha256` is now kernel-computable (FIPS 180-4 port from Trail of Bits scroll-fv), sealed `@[irreducible]` so the crypto axioms remain unchanged; NIST CAVS test vectors verify. **UPDATE (FV review F9e, 2026-07-16): `verify_signs`'s `consistent sk` hypothesis is now DISCHARGED for honest keys — the prior "stub" wording below is STALE.** `Spec/Signer.lean` is the COMPLETED reference signer (no all-zero placeholder stub remains), and `honest_consistent` (`Verifier/HonestConsistent.lean:147`) proves `WellFormed sk → consistent sk` with a real proof in the sorry-free tree (`make verify-audit`). So the earlier claim that "`consistent` is provably FALSE for the placeholder `Spec.Signer.sign` stub (all-zero WOTS+ chains, `count = 0`, digit-sum ≠ `TargetSum`)" no longer holds — that stub was replaced. Residual: `Spec.Signer.sign` is noncomputable / verifier-derived and is cross-checked against the Rust reference signer's 10-vector KAT + bulk tests rather than kernel-anchored to the firmware signer (bridge-(b), still open). Round-trip correctness today rests on the Rust reference signer's 10-vector KAT + bulk tests, **not** a kernel proof. None of this is in the dependency closure of `theft_free`, which uses only the accept ⇒ verifier-returned-true direction plus A5. |

## What this proves and what it does not

**Proves** (modulo A1–A6):

> For any deployed `PQSmartWallet` proxy at address `W`, for any EVM
> state transition `σ → σ'` triggered by a UserOp accepted by
> EntryPoint v0.6, if `balance(σ', W) < balance(σ, W)`, then the
> UserOp's `signature` field carries a SPHINCS+C10 signature, valid
> under an installed owner key of `W`, over the canonical
> `userOpHash`.

**Does not prove**:

* That the firmware actually keeps the secret keys secret (out of
  scope — firmware verification is a separate effort).
* Bounds on gas / griefing / DoS.
* That the EntryPoint v0.6 contract itself is bug-free (A2 assumes it).
* Anything about the EVM precompile, EVM semantics, or `solc`
  (A1, A3, A4 assume those).
* Side-channel security of firmware signing.

These are not workarounds — they are the trust boundary. They are
listed precisely in [`TRUST_ASSUMPTIONS.md`](TRUST_ASSUMPTIONS.md) and
[`AXIOMS.md`](AXIOMS.md).
