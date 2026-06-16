/-
Audit script: prints every axiom used by the headline theorems.

Run via `lake env lean scripts/dump_axioms.lean`.

This is the mechanical equivalent of Verity's `--trust-report`: every
axiom transitively used by the project's claimed theorems appears here.
-/

import SphincsCVerify

-- (Run as `lake env lean scripts/dump_axioms.lean` so the `#print axioms`
-- commands are elaborated and their output appears.)

#print axioms SphincsCVerify.Spec.signatureLen_eq_4008
#print axioms SphincsCVerify.Spec.maxUses_lt_positions

-- Quantitative security-margin layer (Crypto/Quantitative.lean): the on-chain
-- usage cap turned into kernel-checked bit-security floors. All axiom-free
-- (pure `decide`) except the antitone lemma ({propext, Quot.sound}).
#print axioms SphincsCVerify.Crypto.Quantitative.advantage_floors_within_slot_cap
#print axioms SphincsCVerify.Crypto.Quantitative.c10_security_floor_at_slot_cap
#print axioms SphincsCVerify.Crypto.Quantitative.c10_cap_is_load_bearing
#print axioms SphincsCVerify.Crypto.Quantitative.securityFloor_antitone_in_qBits

-- A3.1 deductive-closure track (Interpreter/Memory.lean): byte-addressed memory
-- frame/disjointness lemmas (residual R2). Kernel-only, mathlib-free, NO new
-- content axiom (the precompile hash is a parameter). See A3_1_CLOSURE_PATH.md.
#print axioms SphincsCVerify.Interpreter.writeRegion_comm
#print axioms SphincsCVerify.Interpreter.mstore32_get
#print axioms SphincsCVerify.Interpreter.staticcallSha256_frame
#print axioms SphincsCVerify.Interpreter.hashPair_assembled
#print axioms SphincsCVerify.Interpreter.hashPairStep_frame
#print axioms SphincsCVerify.Interpreter.mload32_mstore32_self
#print axioms SphincsCVerify.Interpreter.mload32_hashPairStep
#print axioms SphincsCVerify.Interpreter.climbMem_eq_specClimb

#print axioms SphincsCVerify.Spec.Theorems.verify_deterministic
#print axioms SphincsCVerify.Spec.Theorems.verify_rejects_wrong_length
#print axioms SphincsCVerify.Wallet.MultiOwnable.bumpBootstrap_monotonic
#print axioms SphincsCVerify.Wallet.MultiOwnable.bumpSlot_monotonic
#print axioms SphincsCVerify.Wallet.MultiOwnable.bootstrap_unremovable
#print axioms SphincsCVerify.Wallet.Invariants.combinedCap_preserved_by_bumpSlot
#print axioms SphincsCVerify.Wallet.Invariants.create2_address_chain_independent
#print axioms SphincsCVerify.Wallet.Invariants.validateSignature_only_via_verify
#print axioms SphincsCVerify.Wallet.Invariants.validateSignature_unset_index_uniform
#print axioms SphincsCVerify.Wallet.Invariants.validateSignature_result_local
#print axioms SphincsCVerify.Wallet.Invariants.combinedCap_inductive
#print axioms SphincsCVerify.Wallet.Invariants.eip1271_forbids_bootstrap
#print axioms SphincsCVerify.Wallet.Invariants.factory_requires_bootstrap_sig
#print axioms SphincsCVerify.Crypto.cannot_forge_without_breaking_SHA256
#print axioms SphincsCVerify.Bridge.yul_eq_refined
-- Headline theorem — should depend on exactly:
--   propext, Classical.choice, Quot.sound  (Lean kernel)
--   SM_DT_TCR_F, ITSR_F, hMsg_random_oracle, EUF_CMA_SPHINCSplusC  (A5)
--   precompile_0x02_is_FIPS_180_4 (A1), entrypoint_honest (A2),
--   solidityVerifier_compiles_correctly (A3.1), evm_bytecode_executes_correctly (A4)
#print axioms SphincsCVerify.Spec.Theorems.theft_free

-- Bytecode-transported headline — theft_free's closure plus
-- solidityWallet_compiles_correctly (A3.2): the EntryPoint transition's
-- wallet step is the opaque deployed-bytecode symbol.
#print axioms SphincsCVerify.Spec.Theorems.theft_free_bytecode

-- Bytecode-transported squat-defence (I-8) — exactly
-- solidityFactory_compiles_correctly (A3.3) + kernel.
#print axioms SphincsCVerify.Spec.Theorems.factory_squat_defence_bytecode

-- Claim 1 corollary — adds sha256_collision_resistance to the closure.
#print axioms SphincsCVerify.Spec.Theorems.theft_free_with_calldata_binding

-- Claim 3 corollary — composes the 6 Wallet.Execute theorems.
#print axioms SphincsCVerify.Spec.Theorems.executeBatch_faithful

-- Claim 2 corollaries — owner-set integrity + initialization atomicity
-- (covered by I-4 + initialize_called_exactly_once + owner_set_nonempty_after_init).
#print axioms SphincsCVerify.Wallet.Invariants.initialize_called_exactly_once
#print axioms SphincsCVerify.Wallet.Invariants.owner_set_nonempty_after_init
#print axioms SphincsCVerify.Wallet.Invariants.storage_mutations_preserve_impl_slot_disjointness

-- Claim 4 — execution-gate non-bypass: no wallet-initiated external call
-- in σ'.callStack without a successful verifier-true validate earlier in
-- the trace. Closure: propext + I-1 (validateSignature_only_via_verify
-- via validateSignature_success_iff) + E-8 (execute_only_validateSig_authorises)
-- composed with the applyStep token-write lemma. No new axioms.
#print axioms SphincsCVerify.Spec.Theorems.every_call_gated_by_verifier
#print axioms SphincsCVerify.Spec.Theorems.no_call_without_prior_verifier_acceptance
#print axioms SphincsCVerify.Wallet.TxFlow.callstack_grew_implies_some_verify_true

-- Claim 4 / Gap-2 (credits model) — per-index exactly-once anti-replay:
-- every money-moving external-call step consumes its OWN per-index credit,
-- which only a verifier-true validate can have stamped. Closure: kernel-only
-- {propext, Classical.choice, Quot.sound} — same as the existential gate.
#print axioms SphincsCVerify.Spec.Theorems.every_call_consumes_its_own_validated_credit
#print axioms SphincsCVerify.Spec.Theorems.credit_lift_implies_verified_validate

-- Claim 4, transported to the deployed EXECUTE bytecode (A3.2-exec): a
-- successful deployed executeWithOffchainCount / executeBatchWithOffchainCount
-- required the matching validated-owner token on entry. Closure adds
-- solidityWalletExecute_compiles_correctly (resp. ...Batch...) — the
-- execute bridge axioms discharged by test/halmos/HalmosExecuteEquiv.t.sol.
#print axioms SphincsCVerify.Spec.Theorems.deployed_execute_requires_prior_token
#print axioms SphincsCVerify.Spec.Theorems.deployed_executeBatch_requires_prior_token

-- (I-7 bootstrap) Bootstrap few-time cap enforced at the validation gate —
-- the faithfulness-audit (2026-06-14) P1 fix that makes capOk's bootstrap
-- strictness proof-load-bearing (two-gate parity with the slot path). Closure
-- = {propext, Quot.sound} only (kernel-clean, no new axiom).
#print axioms SphincsCVerify.Wallet.Invariants.validateSignature_bootstrap_cap_strict

-- (Gap-3) Off-chain/on-chain domain separation — the RAW32 forgery-oracle
-- defense: an off-chain replaySafeHash-nested value is never equal to any
-- UserOp sphincsDigest. Closure adds exactly ONE new cited axiom,
-- keccak_sha256_cross_separation (cross-hash separation, same `… ∨ BreaksHash`
-- reduction shape as sha256_collision_resistance); keccak256 is `opaque`
-- (Classical.choice), not a named axiom. Never concludes False.
#print axioms SphincsCVerify.Wallet.OffchainBinding.offchain_nested_disjoint_from_userop_digest

-- (Gap-4) UUPS upgrade-path unreachable — the named end-to-end assembly.
-- COMPOSES the two already-proven pieces (Execute self-target rejection +
-- StorageLayout impl-slot disjointness). No new proof, no new axiom.
-- Closure: kernel-only {propext, Classical.choice, Quot.sound}.
#print axioms SphincsCVerify.Wallet.UpgradeSafety.upgrade_path_unreachable
