/-
Focused axiom dump for Claim 4 — execution-gate non-bypass.

Run via `make verify-exec-gate` (from `contracts/verification/`) or
`lake env lean scripts/dump_axioms_claim4.lean` (from `contracts/verification/lean/`).

Expected closure (kernel-only): `propext, Classical.choice, Quot.sound`.
Any cryptographic axiom, bridge axiom, or `sorry` appearing here would
indicate the proof has drifted off the intended dep chain.
-/

import SphincsCVerify

#print axioms SphincsCVerify.Wallet.TxFlow.applyStep_token_set_only_by_validate_success
#print axioms SphincsCVerify.Wallet.TxFlow.validate_step_preserves_callstack
#print axioms SphincsCVerify.Wallet.TxFlow.execute_step_requires_prior_token
#print axioms SphincsCVerify.Wallet.TxFlow.executeBatch_step_requires_prior_token
#print axioms SphincsCVerify.Wallet.TxFlow.callstack_grew_implies_some_verify_true
#print axioms SphincsCVerify.Wallet.TxFlow.any_call_implies_some_verify_true
#print axioms SphincsCVerify.Spec.Theorems.every_call_gated_by_verifier
#print axioms SphincsCVerify.Spec.Theorems.no_call_without_prior_verifier_acceptance

-- Gap-2 — per-step (injective) attribution. Expected closure: kernel-only.
#print axioms SphincsCVerify.Wallet.TxFlow.stepVerified_of_token_change
#print axioms SphincsCVerify.Wallet.TxFlow.token_lift_traces_to_validate
#print axioms SphincsCVerify.Wallet.TxFlow.step_ledger_ineq
#print axioms SphincsCVerify.Wallet.TxFlow.ledger_invariant
#print axioms SphincsCVerify.Wallet.TxFlow.growing_executes_le_verified_validates
#print axioms SphincsCVerify.Wallet.TxFlow.stampsB_is_verified
#print axioms SphincsCVerify.Wallet.TxFlow.growsB_is_exec
#print axioms SphincsCVerify.Spec.Theorems.every_call_attributed_to_distinct_validate
#print axioms SphincsCVerify.Spec.Theorems.call_traces_to_authorising_validate
