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

-- A3.1 Sha256Bridge (Interpreter/Sha256Bridge.lean): the byte-array ↔
-- big-endian-word isomorphism connecting interpreter words to spec ByteVecs.
-- beByte_mload32 (load-then-extract recovers the stored byte) needs only
-- [propext, Quot.sound]; beByte_wordOf is the round-trip to Spec.ByteVec.
#print axioms SphincsCVerify.Interpreter.beByte_mload32
#print axioms SphincsCVerify.Interpreter.beByte_wordOf

-- A3.1 proof-phase foundations: phase-split composition (Yul.lean) + the reusable
-- input-assembly bridge (Sha256Bridge.lean) — when memory holds the segments at
-- consecutive 32-byte windows, the precompile input slice = the spec's ByteSeg.flatten.
#print axioms SphincsCVerify.Interpreter.execList_append
#print axioms SphincsCVerify.Interpreter.execFor_invariant
-- Bounded loop-induction engine: `hstep` may assume `cur < N`, so a per-iteration
-- obligation bounded by the index (e.g. the FORS climb's `h < A` `H_adrs`/`H_sib`) is
-- dischargeable — the fix that makes `fors_climb`/`fors_tree_body` non-vacuous.
#print axioms SphincsCVerify.Interpreter.execFor_invariant_lt
#print axioms SphincsCVerify.Interpreter.slice_toArray_eq_flatten
#print axioms SphincsCVerify.Interpreter.C10.c10Oracle_holdsSegs

-- A3.1 first PHASE proof (Interpreter/Phases.lean): running the transcribed H_msg
-- fragment yields env "digest" = wordOf (Spec.hMsg …) — the deductive refinement
-- of the verifier's first phase, the template for FORS/WOTS/hypertree.
#print axioms SphincsCVerify.Interpreter.C10.hmsg_digest

-- A3.1 FORS Merkle climb refinement (the canonical climb, reused by the hypertree):
-- the interpreter's A=11-level inner forRange refines Spec.Fors.reconstructRoot
-- (env "node" = wordOf (pad16 (reconstructRoot …))), via execFor_invariant + the
-- masked-oracle helper + the forIn→foldl bridge.
#print axioms SphincsCVerify.Interpreter.C10.fors_climb
#print axioms SphincsCVerify.Interpreter.C10.mload_masked_eq_wordOf_pad16
#print axioms SphincsCVerify.Interpreter.C10.reconstructRoot_eq_foldl
#print axioms SphincsCVerify.Interpreter.C10.fors_tree_body
-- Non-vacuity guards: the bounded `H_adrs`/`H_sib` that `fors_tree_body` carries are
-- INHABITED (the regression that fences out re-introducing an unsatisfiable hyp).
#print axioms SphincsCVerify.Interpreter.C10.H_adrs_dischargeable
#print axioms SphincsCVerify.Interpreter.C10.H_sib_dischargeable
#print axioms SphincsCVerify.Interpreter.C10.wordOf_make
#print axioms SphincsCVerify.Interpreter.C10.wordOf_forsNode

-- A3.1 FORS phase (Interpreter/Phases.lean): the K-1 normal-tree i-loop, the forced-zero
-- last tree, the 13-root compression, and the capstone composing all three from the
-- post-H_msg VM (env "forsPk" = wordOf (pad16 (reconstructForsPk …)) / revert on the
-- forced-zero violation).  Plus the readBitsLe↔word-shift index bridge underpinning the
-- extractForsIndices/extractHtIndex alignment.  All kernel-only.
#print axioms SphincsCVerify.Interpreter.C10.readBitsLe_eq_wordShift
#print axioms SphincsCVerify.Interpreter.C10.extractForsIndices_eq_wordShift
#print axioms SphincsCVerify.Interpreter.C10.extractHtIndex_eq_wordShift
#print axioms SphincsCVerify.Interpreter.C10.fors_normal_trees
#print axioms SphincsCVerify.Interpreter.C10.fors_last_tree
#print axioms SphincsCVerify.Interpreter.C10.fors_root_compress
#print axioms SphincsCVerify.Interpreter.C10.fors_phase

-- A3.1 WOTS+C phase capstone: the per-layer WOTS interp fragment refines
-- Spec.Wots.pkFromSig (digit-sum≠205 → revert; else env "wotsPk" = wordOf (pad16 wpk)
-- with pkFromSig … = some wpk). Non-vacuity witnessed by wots_pkfromsig_nonvacuous.
#print axioms SphincsCVerify.Interpreter.C10.wots_pkfromsig

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

-- A3.1 hypertree phase (Interpreter/HypertreePhase.lean): verifyAuthPath as a foldl.
#print axioms SphincsCVerify.Interpreter.C10.verifyAuthPath_eq_foldl
#print axioms SphincsCVerify.Interpreter.C10.ht_climb
#print axioms SphincsCVerify.Interpreter.C10.forIn_yield_eq_foldl_pointwise
#print axioms SphincsCVerify.Interpreter.C10.verifyHypertree_eq_foldl

-- A3.1 GRAND COMPOSITION + faithful-form bridge composite (directly gated per the
-- 2026-06-18 adversarial review, H-3). `execC10Asm_eq` is the kernel keystone — the
-- transcribed deployed Yul equals the declarative spec modulo the two N-mask guards;
-- it MUST stay kernel-only {propext, Classical.choice, Quot.sound} (a sorry/native_decide
-- regression here was previously caught only by the full rebuild). `deployed_verifier_refines_spec`
-- composes A3.1 (`solidityVerifier_compiles_correctly`) with `execC10Asm_eq`; its closure
-- must be exactly {kernel triple, solidityVerifier_compiles_correctly}.
#print axioms SphincsCVerify.Interpreter.C10.execC10Asm_eq
#print axioms SphincsCVerify.Bridge.deployed_verifier_refines_spec
-- A3.1 generic env-frame (Interpreter/EnvFrame.lean): a var assigned nowhere is preserved.
#print axioms SphincsCVerify.Interpreter.execStmt_env_frame
#print axioms SphincsCVerify.Interpreter.execList_env_frame
#print axioms SphincsCVerify.Interpreter.execFor_env_frame
