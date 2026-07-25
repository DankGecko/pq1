/-
Focused axiom dump for Claim 4 — execution-gate non-bypass.

Run via `make verify-exec-gate` (from `contracts/verification/`) or
`lake env lean scripts/dump_axioms_claim4.lean` (from `contracts/verification/lean/`).

Expected closure (kernel-only): `propext, Classical.choice, Quot.sound`.
Any cryptographic axiom, bridge axiom, or `sorry` appearing here would
indicate the proof has drifted off the intended dep chain.
-/

import SphincsCVerify

#print axioms SphincsCVerify.Wallet.TxFlow.applyStep_credit_lift_only_by_validate_success
#print axioms SphincsCVerify.Wallet.TxFlow.validate_step_preserves_callstack
#print axioms SphincsCVerify.Wallet.TxFlow.execute_step_requires_prior_credit
#print axioms SphincsCVerify.Wallet.TxFlow.executeBatch_step_requires_prior_credit
#print axioms SphincsCVerify.Wallet.TxFlow.callstack_grew_implies_some_verify_true
#print axioms SphincsCVerify.Wallet.TxFlow.any_call_implies_some_verify_true
#print axioms SphincsCVerify.Spec.Theorems.every_call_gated_by_verifier
#print axioms SphincsCVerify.Spec.Theorems.no_call_without_prior_verifier_acceptance

-- Gap-2 (credits model) — per-index exactly-once anti-replay. Expected
-- closure: kernel-only. (The pre-credits single-token ledger lemmas —
-- token_lift_traces_to_validate / ledger_invariant / growing_executes_le_
-- verified_validates — were retired when the GAP-11 credits refactor's model
-- replaced the single `validatedOwnerPlusOne` transient with a per-index
-- `credits` map; the per-index require/consume lemmas live in Execute.lean.)
#print axioms SphincsCVerify.Wallet.Execute.execute_consumes_credit
#print axioms SphincsCVerify.Wallet.Execute.execute_preserves_other_credits
#print axioms SphincsCVerify.Spec.Theorems.every_call_consumes_its_own_validated_credit
#print axioms SphincsCVerify.Spec.Theorems.credit_lift_implies_verified_validate

-- Gap-2 (credits model) — GLOBAL aggregate completeness complement (work-todo
-- FV-#5): `#executes ≤ #validates` over any successful clean-transient trace,
-- via a mathlib-free finite-support credit sum. Expected closure: kernel-only.
#print axioms SphincsCVerify.Wallet.CreditLedger.creditConservation
#print axioms SphincsCVerify.Wallet.CreditLedger.exec_count_le_validate_count
#print axioms SphincsCVerify.Spec.Theorems.exec_count_le_validate_count
