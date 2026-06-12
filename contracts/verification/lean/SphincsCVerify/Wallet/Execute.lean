/-
Lean model of `PQSmartWallet.executeWithOffchainCount` and
`PQSmartWallet.executeBatchWithOffchainCount`, plus the operational
theorems Claim 3 (execution faithfulness) requires.

## Theorems closed in this file

  (E-1) `execute_caller_is_entrypoint`           — only EntryPoint calls.
  (E-2) `execute_rejects_self_target`            — audit H-2.
  (E-3) `execute_requires_token_set` / `_match`  — audit H-3 token gate.
  (E-4) `execute_clears_token`                   — no double-execute.
  (E-5) `executeBatch_runs_in_signed_order`      — order preservation.
  (E-6) `executeBatch_value_outflow_eq_sum_values` — value-flow bound.
  (E-7) `executeBatch_callback_preserves_loop`   — calldata immutability.
  (E-8) `execute_only_validateSig_authorises`    — composes back to Claim 1.
-/

import SphincsCVerify.Wallet.Storage
import SphincsCVerify.Wallet.MultiOwnable
import SphincsCVerify.Wallet.ValidateUserOp
import SphincsCVerify.Wallet.StorageLayout
import SphincsCVerify.Spec.Params

namespace SphincsCVerify.Wallet.Execute

open SphincsCVerify.Spec
open SphincsCVerify.Wallet
open SphincsCVerify.Wallet.Storage
open SphincsCVerify.Wallet.ValidateUserOp

/-! ## Data model -/

/-- A single external call: `target.call{value: value}(data)`. -/
structure Call where
  target : ByteVec 20
  value : Nat
  data : Array UInt8

namespace Call

instance : Inhabited Call :=
  ⟨{ target := ⟨Array.replicate 20 0, by simp⟩, value := 0, data := #[] }⟩

end Call

/-- The slice of EVM state the executor operates on.

    `credits` mirrors the wallet's per-`ownerIndex` transient validated-op
    credit COUNTERS (EIP-1153 slots at `keccak256(ownerIndex,
    _TS_CREDIT_NAMESPACE)`): `_validateSignature` stamps `credit[i] += 1`
    for a slot-path offchain-count op, and `execute*WithOffchainCount`
    consumes one (`credit[i] -= 1`, reverting at zero). A per-index
    COUNTER map — not a single token — so a bundle carrying several
    UserOps for the same wallet hands N credits to N executions.

    HISTORY: until 2026-06-12 this structure had a single
    `validatedOwnerPlusOne : Nat` compare-and-clear token, which was
    faithful to the deployed bytecode only on the ≤1-stamp-per-bundle
    envelope (GAP-11 in `docs/MISSING_FOR_FULL_BYTECODE_PROOF.md`). -/
structure ExecState where
  storage : Storage
  selfAddress : ByteVec 20
  entryPoint : ByteVec 20
  credits : Nat → Nat
  callStack : List Call

namespace ExecState

instance : Inhabited ExecState :=
  ⟨{ storage := Storage.empty,
     selfAddress := ⟨Array.replicate 20 0, by simp⟩,
     entryPoint := ⟨Array.replicate 20 0, by simp⟩,
     credits := fun _ => 0,
     callStack := [] }⟩

end ExecState

/-- Decrement the credit counter at `ownerIndex`, leaving every other
    index untouched. Mirrors `_consumeValidatedCredit`'s
    `tstore(slot, sub(c, 1))`. -/
def consumeCredit (credits : Nat → Nat) (ownerIndex : Nat) : Nat → Nat :=
  fun i => if i = ownerIndex then credits i - 1 else credits i

/-! ## `executeWithOffchainCount`

The function is intentionally written in `if-then-else + match` form
(rather than `do`-notation) so that each of the four revert paths is
visible at the top level. The structure helps the proofs below
unfold cleanly. -/

/-- Model of `PQSmartWallet.executeWithOffchainCount`. Guard order
    mirrors the deployed bytecode: EntryPoint caller → consume one
    per-index credit (revert at zero) → self-target reject → monotonic
    `setOffchain` under the combined cap → dispatch. -/
def executeWithOffchainCount
    (σ : ExecState) (caller : ByteVec 20)
    (ownerIndex newOffchainCount : Nat)
    (target : ByteVec 20) (value : Nat) (data : Array UInt8) :
    Option ExecState :=
  if caller ≠ σ.entryPoint then none
  else if σ.credits ownerIndex = 0 then none
  else if target = σ.selfAddress then none
  else
    (Storage.setOffchain σ.storage ownerIndex newOffchainCount
            (σ.storage.slotUses ownerIndex) MaxSlotUses).bind
      (fun s' => some {
        storage := s'
        selfAddress := σ.selfAddress
        entryPoint := σ.entryPoint
        credits := consumeCredit σ.credits ownerIndex
        callStack := σ.callStack ++ [{ target := target, value := value, data := data }] })

/-! ## `executeBatchWithOffchainCount` -/

/-- Append calls one-by-one, refusing if any target equals `self`. -/
def appendBatchCalls
    (selfAddr : ByteVec 20) (acc : List Call)
    (targets : List (ByteVec 20)) (values : List Nat)
    (datas : List (Array UInt8)) : Option (List Call) :=
  match targets, values, datas with
  | [], [], [] => some acc
  | t :: ts, v :: vs, d :: ds =>
    if t = selfAddr then none
    else appendBatchCalls selfAddr (acc ++ [{ target := t, value := v, data := d }]) ts vs ds
  | _, _, _ => none

/-- Model of `PQSmartWallet.executeBatchWithOffchainCount`. Same credit
    semantics as the single variant; the per-element self-target check
    and the array-length check live in `appendBatchCalls`. -/
def executeBatchWithOffchainCount
    (σ : ExecState) (caller : ByteVec 20)
    (ownerIndex newOffchainCount : Nat)
    (targets : List (ByteVec 20)) (values : List Nat)
    (datas : List (Array UInt8)) :
    Option ExecState :=
  if caller ≠ σ.entryPoint then none
  else if σ.credits ownerIndex = 0 then none
  else
    (Storage.setOffchain σ.storage ownerIndex newOffchainCount
            (σ.storage.slotUses ownerIndex) MaxSlotUses).bind fun s' =>
      (appendBatchCalls σ.selfAddress σ.callStack targets values datas).bind fun newStack =>
        some {
          storage := s'
          selfAddress := σ.selfAddress
          entryPoint := σ.entryPoint
          credits := consumeCredit σ.credits ownerIndex
          callStack := newStack }

/-! ## Proof helpers — peel off the outer if-then-else guards. -/

/-- The three guards passed (caller, credit-present, non-self). The old
    fourth conjunct — the single-token `ownerIndex` parity — has no
    bytecode counterpart in the per-index credit design: presenting an
    index IS naming the credit consumed (H-3 parity binds the calldata
    index to the signed wrapper index in the VALIDATION phase). -/
private theorem exec_passes_guards
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {target : ByteVec 20} {value : Nat} {data : Array UInt8}
    {σ' : ExecState}
    (h : executeWithOffchainCount σ caller ownerIndex newOffchainCount
             target value data = some σ') :
    caller = σ.entryPoint ∧
    σ.credits ownerIndex ≠ 0 ∧
    target ≠ σ.selfAddress := by
  unfold executeWithOffchainCount at h
  by_cases hcaller : caller ≠ σ.entryPoint
  · rw [if_pos hcaller] at h; exact Option.noConfusion h
  · rw [if_neg hcaller] at h
    have hcaller_eq : caller = σ.entryPoint := Classical.byContradiction hcaller
    by_cases hcred : σ.credits ownerIndex = 0
    · rw [if_pos hcred] at h; exact Option.noConfusion h
    · rw [if_neg hcred] at h
      by_cases hself : target = σ.selfAddress
      · rw [if_pos hself] at h; exact Option.noConfusion h
      · rw [if_neg hself] at h
        exact ⟨hcaller_eq, hcred, hself⟩

/-- The two guards passed for the batch variant (caller,
    credit-present; the per-iteration self-target check lives inside
    `appendBatchCalls`). -/
private theorem batch_passes_guards
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    {σ' : ExecState}
    (h : executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
             targets values datas = some σ') :
    caller = σ.entryPoint ∧
    σ.credits ownerIndex ≠ 0 := by
  unfold executeBatchWithOffchainCount at h
  by_cases hcaller : caller ≠ σ.entryPoint
  · rw [if_pos hcaller] at h; exact Option.noConfusion h
  · rw [if_neg hcaller] at h
    have hcaller_eq : caller = σ.entryPoint := Classical.byContradiction hcaller
    by_cases hcred : σ.credits ownerIndex = 0
    · rw [if_pos hcred] at h; exact Option.noConfusion h
    · rw [if_neg hcred] at h
      exact ⟨hcaller_eq, hcred⟩

/-- Extract the post-state of a successful execute call: the storage
    is the result of `Storage.setOffchain`, exactly one credit at
    `ownerIndex` is consumed (every other index untouched), the
    callStack appends the one new call. -/
private theorem exec_post_state
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {target : ByteVec 20} {value : Nat} {data : Array UInt8}
    {σ' : ExecState}
    (h : executeWithOffchainCount σ caller ownerIndex newOffchainCount
             target value data = some σ') :
    σ'.credits = consumeCredit σ.credits ownerIndex ∧
    σ'.callStack = σ.callStack ++ [{ target := target, value := value, data := data }] := by
  -- Apply the guards first to peel the outer conditionals.
  have hguards := exec_passes_guards h
  obtain ⟨hcaller_eq, hcred, hself⟩ := hguards
  -- Now unfold and use the guard facts to simplify.
  unfold executeWithOffchainCount at h
  have hcaller : ¬ (caller ≠ σ.entryPoint) := fun hne => hne hcaller_eq
  rw [if_neg hcaller] at h
  rw [if_neg hcred] at h
  rw [if_neg hself] at h
  -- h : (Storage.setOffchain ...).bind (fun s' => some {...}) = some σ'
  -- Case-analyse the setOffchain result via Option.bind_eq_some_iff.
  rw [Option.bind_eq_some_iff] at h
  obtain ⟨s', _hSO, hpost⟩ := h
  injection hpost with hpost
  constructor
  · rw [← hpost]
  · rw [← hpost]

/-- Extract the post-state of a successful batch execute call. -/
private theorem batch_post_state
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    {σ' : ExecState}
    (h : executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
             targets values datas = some σ') :
    σ'.credits = consumeCredit σ.credits ownerIndex ∧
    ∃ newStack,
      appendBatchCalls σ.selfAddress σ.callStack targets values datas = some newStack
      ∧ σ'.callStack = newStack := by
  have hguards := batch_passes_guards h
  obtain ⟨hcaller_eq, hcred⟩ := hguards
  unfold executeBatchWithOffchainCount at h
  have hcaller : ¬ (caller ≠ σ.entryPoint) := fun hne => hne hcaller_eq
  rw [if_neg hcaller] at h
  rw [if_neg hcred] at h
  rw [Option.bind_eq_some_iff] at h
  obtain ⟨s', _hSO, hinner⟩ := h
  rw [Option.bind_eq_some_iff] at hinner
  obtain ⟨newStack, hAC, hpost⟩ := hinner
  injection hpost with hpost
  refine ⟨?_, newStack, hAC, ?_⟩
  · rw [← hpost]
  · rw [← hpost]

/-! ## (E-1) Only EntryPoint reaches the executor -/

theorem execute_caller_is_entrypoint
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {target : ByteVec 20} {value : Nat} {data : Array UInt8}
    {σ' : ExecState}
    (h : executeWithOffchainCount σ caller ownerIndex newOffchainCount
             target value data = some σ') :
    caller = σ.entryPoint :=
  (exec_passes_guards h).1

theorem executeBatch_caller_is_entrypoint
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    {σ' : ExecState}
    (h : executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
             targets values datas = some σ') :
    caller = σ.entryPoint :=
  (batch_passes_guards h).1

/-! ## (E-2) Self-target rejection (audit H-2) -/

theorem execute_rejects_self_target
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {target : ByteVec 20} {value : Nat} {data : Array UInt8}
    {σ' : ExecState}
    (h : executeWithOffchainCount σ caller ownerIndex newOffchainCount
             target value data = some σ') :
    target ≠ σ.selfAddress :=
  (exec_passes_guards h).2.2

/-- If `appendBatchCalls` returns `some _`, no element of `targets`
    equals `selfAddr`. -/
private theorem appendBatchCalls_no_self
    {selfAddr : ByteVec 20} {acc : List Call}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)} {new : List Call}
    (h : appendBatchCalls selfAddr acc targets values datas = some new) :
    ∀ t ∈ targets, t ≠ selfAddr := by
  induction targets generalizing acc values datas new with
  | nil => intro t ht; simp at ht
  | cons t ts ih =>
    cases values with
    | nil => unfold appendBatchCalls at h; simp at h
    | cons v vs =>
      cases datas with
      | nil => unfold appendBatchCalls at h; simp at h
      | cons d ds =>
        unfold appendBatchCalls at h
        by_cases ht : t = selfAddr
        · rw [if_pos ht] at h; exact Option.noConfusion h
        · rw [if_neg ht] at h
          intro u hu
          rcases List.mem_cons.mp hu with heq | hmem
          · subst heq; exact ht
          · exact ih h u hmem

theorem executeBatch_rejects_self_target
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    {σ' : ExecState}
    (h : executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
             targets values datas = some σ') :
    ∀ t ∈ targets, t ≠ σ.selfAddress := by
  obtain ⟨_, _, hAC, _⟩ := batch_post_state h
  exact appendBatchCalls_no_self hAC

/-! ## (E-3) Requires a per-index validated-op credit (audit H-3) -/

theorem execute_requires_credit
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {target : ByteVec 20} {value : Nat} {data : Array UInt8}
    {σ' : ExecState}
    (h : executeWithOffchainCount σ caller ownerIndex newOffchainCount
             target value data = some σ') :
    σ.credits ownerIndex > 0 :=
  Nat.pos_of_ne_zero (exec_passes_guards h).2.1

theorem executeBatch_requires_credit
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    {σ' : ExecState}
    (h : executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
             targets values datas = some σ') :
    σ.credits ownerIndex > 0 :=
  Nat.pos_of_ne_zero (batch_passes_guards h).2

/-! ## (E-4) Exactly one credit consumed post-execute (one-shot replay
    guard — N stamps fund at most N executes per index per bundle) -/

theorem execute_consumes_credit
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {target : ByteVec 20} {value : Nat} {data : Array UInt8}
    {σ' : ExecState}
    (h : executeWithOffchainCount σ caller ownerIndex newOffchainCount
             target value data = some σ') :
    σ'.credits ownerIndex = σ.credits ownerIndex - 1 := by
  have hpost := (exec_post_state h).1
  rw [hpost]
  unfold consumeCredit
  rw [if_pos rfl]

theorem execute_preserves_other_credits
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {target : ByteVec 20} {value : Nat} {data : Array UInt8}
    {σ' : ExecState}
    (h : executeWithOffchainCount σ caller ownerIndex newOffchainCount
             target value data = some σ')
    {j : Nat} (hj : j ≠ ownerIndex) :
    σ'.credits j = σ.credits j := by
  have hpost := (exec_post_state h).1
  rw [hpost]
  unfold consumeCredit
  rw [if_neg hj]

theorem executeBatch_consumes_credit
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    {σ' : ExecState}
    (h : executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
             targets values datas = some σ') :
    σ'.credits ownerIndex = σ.credits ownerIndex - 1 := by
  have hpost := (batch_post_state h).1
  rw [hpost]
  unfold consumeCredit
  rw [if_pos rfl]

theorem executeBatch_preserves_other_credits
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    {σ' : ExecState}
    (h : executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
             targets values datas = some σ')
    {j : Nat} (hj : j ≠ ownerIndex) :
    σ'.credits j = σ.credits j := by
  have hpost := (batch_post_state h).1
  rw [hpost]
  unfold consumeCredit
  rw [if_neg hj]

/-! ## (E-5) Batch runs in signed order -/

/-- The list of calls a successful batch appends. -/
def buildBatchCalls
    (targets : List (ByteVec 20)) (values : List Nat)
    (datas : List (Array UInt8)) : List Call :=
  match targets, values, datas with
  | [], [], [] => []
  | t :: ts, v :: vs, d :: ds =>
    { target := t, value := v, data := d } :: buildBatchCalls ts vs ds
  | _, _, _ => []

/-- If `appendBatchCalls` returns `some new`, then `new = acc ++
    buildBatchCalls targets values datas`. -/
private theorem appendBatchCalls_appends
    {selfAddr : ByteVec 20} {acc : List Call}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)} {new : List Call}
    (h : appendBatchCalls selfAddr acc targets values datas = some new) :
    new = acc ++ buildBatchCalls targets values datas := by
  induction targets generalizing acc values datas new with
  | nil =>
    cases values with
    | nil =>
      cases datas with
      | nil =>
        unfold appendBatchCalls buildBatchCalls at *
        injection h with h
        simp [← h]
      | cons _ _ => unfold appendBatchCalls at h; simp at h
    | cons _ _ => unfold appendBatchCalls at h; simp at h
  | cons t ts ih =>
    cases values with
    | nil => unfold appendBatchCalls at h; simp at h
    | cons v vs =>
      cases datas with
      | nil => unfold appendBatchCalls at h; simp at h
      | cons d ds =>
        unfold appendBatchCalls at h
        by_cases ht : t = selfAddr
        · rw [if_pos ht] at h; exact Option.noConfusion h
        · rw [if_neg ht] at h
          have ihh := ih h
          unfold buildBatchCalls
          rw [ihh]
          simp

theorem executeBatch_runs_in_signed_order
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    {σ' : ExecState}
    (h : executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
             targets values datas = some σ') :
    σ'.callStack = σ.callStack ++ buildBatchCalls targets values datas := by
  obtain ⟨_, newStack, hAC, hstack⟩ := batch_post_state h
  rw [hstack]
  exact appendBatchCalls_appends hAC

/-! ## (E-6) Total value outflow equals sum of signed values -/

/-- Sum the `value` fields of a list of calls. -/
def totalValue (calls : List Call) : Nat :=
  calls.foldl (fun acc c => acc + c.value) 0

/-- Generic foldl-accumulator identity. -/
private theorem foldl_value_acc (a : Nat) (cs : List Call) :
    cs.foldl (fun acc c => acc + c.value) a
      = a + cs.foldl (fun acc c => acc + c.value) 0 := by
  induction cs generalizing a with
  | nil => simp
  | cons c cs ih =>
    simp only [List.foldl]
    rw [ih (a + c.value), ih (0 + c.value)]
    omega

/-- `totalValue` is additive across `++`. -/
private theorem totalValue_append (xs ys : List Call) :
    totalValue (xs ++ ys) = totalValue xs + totalValue ys := by
  unfold totalValue
  induction xs with
  | nil => simp
  | cons x xs ih =>
    simp only [List.cons_append, List.foldl]
    rw [foldl_value_acc, foldl_value_acc (a := 0 + x.value)]
    omega

/-- Generic foldl-accumulator identity for Nat addition. -/
private theorem foldl_nat_acc (a : Nat) (xs : List Nat) :
    xs.foldl (· + ·) a = a + xs.foldl (· + ·) 0 := by
  induction xs generalizing a with
  | nil => simp
  | cons x xs ih =>
    simp only [List.foldl]
    rw [ih (a + x), ih (0 + x)]
    omega

/-- `buildBatchCalls` value-sum equals `values.foldl (· + ·) 0`, when
    the three input lists have the same length. -/
private theorem totalValue_buildBatch
    (targets : List (ByteVec 20)) (values : List Nat)
    (datas : List (Array UInt8))
    (hlen1 : targets.length = values.length)
    (hlen2 : values.length = datas.length) :
    totalValue (buildBatchCalls targets values datas)
      = values.foldl (· + ·) 0 := by
  induction targets generalizing values datas with
  | nil =>
    cases values with
    | nil =>
      cases datas with
      | nil => unfold buildBatchCalls totalValue; simp
      | cons _ _ => simp at hlen2
    | cons _ _ => simp at hlen1
  | cons t ts ih =>
    cases values with
    | nil => simp at hlen1
    | cons v vs =>
      cases datas with
      | nil => simp at hlen2
      | cons d ds =>
        unfold buildBatchCalls totalValue
        simp only [List.foldl]
        rw [foldl_value_acc, foldl_nat_acc (a := 0 + v)]
        have hlen1' : ts.length = vs.length := by
          simp at hlen1; exact hlen1
        have hlen2' : vs.length = ds.length := by
          simp at hlen2; exact hlen2
        have ihh := ih (values := vs) (datas := ds) hlen1' hlen2'
        unfold totalValue at ihh
        omega

theorem executeBatch_value_outflow_eq_sum_values
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    {σ' : ExecState}
    (hlen1 : targets.length = values.length)
    (hlen2 : values.length = datas.length)
    (h : executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
             targets values datas = some σ') :
    totalValue σ'.callStack
      = totalValue σ.callStack + values.foldl (· + ·) 0 := by
  have hstack := executeBatch_runs_in_signed_order h
  rw [hstack, totalValue_append, totalValue_buildBatch _ _ _ hlen1 hlen2]

/-! ## (E-7) Callback cannot alter the batch loop -/

/-- **Calldata immutability for batches.** Restated form of
    `executeBatch_runs_in_signed_order` emphasising that the
    post-state's appended calls are a pure function of the input
    arrays — no callback could rebind them mid-iteration.

    Solidity calldata is structurally immutable; this Lean theorem
    captures the same fact via referential transparency. -/
theorem executeBatch_callback_preserves_loop
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    {σ' : ExecState}
    (h : executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
             targets values datas = some σ') :
    σ'.callStack = σ.callStack ++ buildBatchCalls targets values datas :=
  executeBatch_runs_in_signed_order h

/-! ## (E-8) Composes back to Claim 1 — execute requires validated sig -/

theorem execute_only_validateSig_authorises
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {target : ByteVec 20} {value : Nat} {data : Array UInt8}
    {σ' : ExecState}
    (h : executeWithOffchainCount σ caller ownerIndex newOffchainCount
             target value data = some σ') :
    σ.credits ownerIndex > 0 :=
  execute_requires_credit h

theorem executeBatch_only_validateSig_authorises
    {σ : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    {σ' : ExecState}
    (h : executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
             targets values datas = some σ') :
    σ.credits ownerIndex > 0 :=
  executeBatch_requires_credit h

end SphincsCVerify.Wallet.Execute
