/-
Per-transaction flow model for `PQSmartWallet`, and the headline
**execution-gate non-bypass** theorem (Claim 4):

  No wallet-initiated external call exists in any reachable post-state
  unless an earlier step in the same transaction was a `validate` whose
  `verify_fn` returned `true` on the appropriate `(pkSeed, pkRoot,
  sphincsDigest, innerSig)`.

The existing modules give us the static pieces:

  * `ValidateUserOp.validateSignature` — the role-split + cap + verifier
    check returning `(Result, Storage)`; the success direction is
    characterised by `validateSignature_success_iff`.
  * `Wallet.Invariants.validateSignature_only_via_verify` (I-1) — a
    successful validate implies `verify_fn` returned `true`.
  * `Wallet.Execute.execute{,Batch}_only_validateSig_authorises` (E-8) —
    a successful execute requires `validatedOwnerPlusOne = ownerIndex+1`
    on entry.

This module composes them into a **transaction-level** statement by
modelling a sequence of `Step`s the EntryPoint can drive against the
wallet and a `runTrace` function that threads `ExecState` through them.
Key load-bearing lemmas:

  * `applyStep_token_set_only_by_validate_success` — the transient
    `validatedOwnerPlusOne` field can only transition from `0` to a
    non-zero value via a successful slot-path `validate` step.
  * `validate_step_preserves_callstack` — `validate` never appends.
  * `callstack_grew_implies_some_verify_true` — trace-level: any
    growth in `σ'.callStack` implies the trace contained at least one
    `validate` step whose `verify_fn` returned `true` on the
    `sphincsDigest` of the validated UserOp.

`Spec.Theorems.every_call_gated_by_verifier` is the top-level corollary
that exposes the result alongside `theft_free` and `executeBatch_faithful`.
-/

import SphincsCVerify.Wallet.Storage
import SphincsCVerify.Wallet.MultiOwnable
import SphincsCVerify.Wallet.ValidateUserOp
import SphincsCVerify.Wallet.Execute
import SphincsCVerify.Wallet.Invariants

namespace SphincsCVerify.Wallet.TxFlow

open SphincsCVerify.Spec
open SphincsCVerify.Spec.Signature
open SphincsCVerify.Wallet
open SphincsCVerify.Wallet.Storage
open SphincsCVerify.Wallet.ValidateUserOp
open SphincsCVerify.Wallet.Execute
open SphincsCVerify.Wallet.Invariants

/-! ## Step model

A `Step` represents one EntryPoint-driven call into the wallet within a
single ERC-4337 transaction. The three constructors cover every
external-call-producing wallet entry-point in scope of the call-graph
non-bypass claim:

  * `validate` — `wallet.validateUserOp(...)`.
  * `execute` — `wallet.executeWithOffchainCount(...)`.
  * `executeBatch` — `wallet.executeBatchWithOffchainCount(...)`.

`addOwnerBytes` and `removeOwnerAtIndex` only mutate storage (no
external calls), so they are outside the call-graph scope; their
non-bypass facts are covered by Claim 2 (`Wallet.Invariants`). -/
inductive Step where
  | validate
      (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
      (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 →
                   ByteVec SignatureLen → Bool)
  | execute
      (caller : ByteVec 20)
      (ownerIndex newOffchainCount : Nat)
      (target : ByteVec 20) (value : Nat) (data : Array UInt8)
  | executeBatch
      (caller : ByteVec 20)
      (ownerIndex newOffchainCount : Nat)
      (targets : List (ByteVec 20)) (values : List Nat)
      (datas : List (Array UInt8))

/-! ## Step semantics

For `validate`, the model intentionally returns `some σ` (state
unchanged) when validation fails — a failing validate in EIP-4337 v0.6
makes the EntryPoint reject the UserOp without mutating the wallet, so
the transaction trace simply continues with the same `ExecState`.

For `validate` *success* on the slot path (`ownerIndex ≠ 0`), we set
`validatedOwnerPlusOne := ownerIndex + 1` to mirror the
`tstore(_TS_VALIDATED_OWNER_INDEX_PLUS_ONE, ...)` write in
`_validateSignature`. The bootstrap path (`ownerIndex = 0`) sets the
`_TS_PENDING_BOOTSTRAP_BUMP` transient instead — not the
`validatedOwnerPlusOne` token — and so does NOT enable the execute
guard. We mirror that by leaving `validatedOwnerPlusOne` untouched in
the bootstrap branch.

The if-then-else structure (rather than nested `match`) mirrors the
proof-friendly form used by `Execute.executeWithOffchainCount`. -/

/-- Helper: post-validate state mutation, factored out so the proof can
    case on individual sub-conditions. -/
def applyValidateSuccess
    (σ : ExecState) (s' : Storage) (d : DecodedSig) : ExecState :=
  if d.ownerIndex = 0 then { σ with storage := s' }
  else { σ with storage := s', validatedOwnerPlusOne := d.ownerIndex + 1 }

def applyStep (σ : ExecState) : Step → Option ExecState
  | .validate op entryPoint chainId verify_fn =>
      let r := validateSignature σ.storage op entryPoint chainId verify_fn
      if r.1 = Result.success then
        match decodeWrappedSig op.signature with
        | none => some σ
        | some d => some (applyValidateSuccess σ r.2 d)
      else some σ
  | .execute caller ownerIndex newOffchainCount target value data =>
      executeWithOffchainCount σ caller ownerIndex newOffchainCount
        target value data
  | .executeBatch caller ownerIndex newOffchainCount targets values datas =>
      executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
        targets values datas

/-- Run a sequence of steps; abort on the first one that returns `none`
    (a revert). The threaded state carries storage, transient gating
    bits, and the accumulated external call stack. -/
def runTrace (σ : ExecState) : List Step → Option ExecState
  | [] => some σ
  | s :: rest => (applyStep σ s).bind (fun σ' => runTrace σ' rest)

/-! ## Step-level lemmas -/

/-- `applyValidateSuccess` preserves the callStack. -/
private theorem applyValidateSuccess_preserves_callstack
    (σ : ExecState) (s' : Storage) (d : DecodedSig) :
    (applyValidateSuccess σ s' d).callStack = σ.callStack := by
  unfold applyValidateSuccess
  by_cases h : d.ownerIndex = 0
  · rw [if_pos h]
  · rw [if_neg h]

/-- A `validate` step never appends to the callStack. -/
theorem validate_step_preserves_callstack
    {σ σ' : ExecState}
    {op : UserOperation} {ep : ByteVec 20} {cid : Nat}
    {vfn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool}
    (h : applyStep σ (.validate op ep cid vfn) = some σ') :
    σ'.callStack = σ.callStack := by
  simp only [applyStep] at h
  by_cases hsucc :
      (validateSignature σ.storage op ep cid vfn).1 = Result.success
  · rw [if_pos hsucc] at h
    -- Inner match on decodeWrappedSig.
    cases hdec : decodeWrappedSig op.signature with
    | none =>
        rw [hdec] at h
        injection h with h
        rw [← h]
    | some d =>
        rw [hdec] at h
        injection h with h
        rw [← h]
        exact applyValidateSuccess_preserves_callstack σ _ d
  · rw [if_neg hsucc] at h
    injection h with h
    rw [← h]

/-- An execute step that succeeds requires the *incoming* state to have
    `validatedOwnerPlusOne = ownerIndex + 1` — i.e. some earlier step
    must have stamped the token. Repackages
    `Execute.execute_only_validateSig_authorises` through the
    `applyStep` wrapper. -/
theorem execute_step_requires_prior_token
    {σ σ' : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {target : ByteVec 20} {value : Nat} {data : Array UInt8}
    (h : applyStep σ (.execute caller ownerIndex newOffchainCount target value data)
         = some σ') :
    σ.validatedOwnerPlusOne = ownerIndex + 1 := by
  simp only [applyStep] at h
  exact execute_only_validateSig_authorises h

/-- Same for the batch variant. -/
theorem executeBatch_step_requires_prior_token
    {σ σ' : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    (h : applyStep σ (.executeBatch caller ownerIndex newOffchainCount
                        targets values datas) = some σ') :
    σ.validatedOwnerPlusOne = ownerIndex + 1 := by
  simp only [applyStep] at h
  exact executeBatch_only_validateSig_authorises h

/-! ## Token-write monotonicity

The transient `validatedOwnerPlusOne` can ONLY transition from `0` to a
non-zero value via a `validate` step whose `validateSignature` returned
success and whose decoded `ownerIndex` was non-zero (i.e. a slot-path
sig). Execute steps clear the token (zero it). -/

/-- Successful `validate` step that lifts the token from zero must be a
    slot-path validate with a decoded sig and the storage updated by
    `bumpForOwner`. The conclusion is packaged as the same `∃` the
    Invariants module uses, so I-1 (`validateSignature_only_via_verify`)
    plugs in directly downstream. -/
theorem applyStep_token_set_only_by_validate_success
    {σ σ' : ExecState} {step : Step}
    (h : applyStep σ step = some σ')
    (hwas : σ.validatedOwnerPlusOne = 0)
    (hnow : σ'.validatedOwnerPlusOne ≠ 0) :
    ∃ (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
      (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 →
                   ByteVec SignatureLen → Bool)
      (d : DecodedSig) (owner : OwnerBytes),
      step = .validate op entryPoint chainId verify_fn ∧
      validateSignatureOk σ.storage op entryPoint chainId verify_fn d owner ∧
      bumpForOwner σ.storage d.ownerIndex = some σ'.storage ∧
      d.ownerIndex ≠ 0 ∧
      σ'.validatedOwnerPlusOne = d.ownerIndex + 1 := by
  cases hs : step with
  | validate op ep cid vfn =>
      subst hs
      simp only [applyStep] at h
      by_cases hsucc :
          (validateSignature σ.storage op ep cid vfn).1 = Result.success
      · rw [if_pos hsucc] at h
        -- Reconstruct the success witness.
        have hpair :
            validateSignature σ.storage op ep cid vfn
              = (Result.success, (validateSignature σ.storage op ep cid vfn).2) := by
          rw [← hsucc]
        -- Inner match on decode.
        cases hdec : decodeWrappedSig op.signature with
        | none =>
            rw [hdec] at h
            injection h with h
            rw [← h] at hnow
            exact absurd hwas hnow
        | some d =>
            rw [hdec] at h
            injection h with h
            -- h : applyValidateSuccess σ (validateSignature ...).2 d = σ'
            -- Decompose applyValidateSuccess into the two sub-cases.
            by_cases hd0 : d.ownerIndex = 0
            · -- Bootstrap branch: applyValidateSuccess returns σ with only
              -- storage updated; validatedOwnerPlusOne unchanged.
              have hv : σ'.validatedOwnerPlusOne = σ.validatedOwnerPlusOne := by
                rw [← h]
                unfold applyValidateSuccess
                rw [if_pos hd0]
              rw [hwas] at hv
              exact absurd hv hnow
            · -- Slot branch: validatedOwnerPlusOne becomes d.ownerIndex + 1,
              -- storage becomes the bumped value.
              have hv : σ'.validatedOwnerPlusOne = d.ownerIndex + 1 := by
                rw [← h]
                unfold applyValidateSuccess
                rw [if_neg hd0]
              have hst : σ'.storage = (validateSignature σ.storage op ep cid vfn).2 := by
                rw [← h]
                unfold applyValidateSuccess
                rw [if_neg hd0]
              -- Use validateSignature_success_iff to extract validateSignatureOk + bump-eq.
              have hsucc_pair :
                  validateSignature σ.storage op ep cid vfn
                    = (Result.success,
                       (validateSignature σ.storage op ep cid vfn).2) := hpair
              rw [validateSignature_success_iff] at hsucc_pair
              obtain ⟨d', owner, hOk, hBumpEq⟩ := hsucc_pair
              -- d' = d (both come from decoding the same op.signature).
              have hd_eq : d' = d := by
                have h1 : (some d' : Option DecodedSig) = some d := by
                  rw [← hOk.1, hdec]
                exact Option.some.inj h1
              -- Use d' as the witness, rewriting back to d where needed.
              refine ⟨op, ep, cid, vfn, d', owner, rfl, hOk, ?_, ?_, ?_⟩
              · rw [hst]; exact hBumpEq
              · rw [hd_eq]; exact hd0
              · rw [hd_eq]; exact hv
      · rw [if_neg hsucc] at h
        injection h with h
        rw [← h] at hnow
        exact absurd hwas hnow
  | execute caller oi noc t v d =>
      subst hs
      have htok := execute_step_requires_prior_token h
      rw [hwas] at htok
      exact absurd htok.symm (Nat.succ_ne_zero _)
  | executeBatch caller oi noc ts vs ds =>
      subst hs
      have htok := executeBatch_step_requires_prior_token h
      rw [hwas] at htok
      exact absurd htok.symm (Nat.succ_ne_zero _)

/-! ## Trace-level: callstack growth implies a verifier-true validate -/

/-- The verifier-truth predicate at a particular pre-state: there is a
    decoded sig and an installed owner against which the supplied
    `verify_fn` returned `true` over `sphincsDigest`. This is exactly
    the existential I-1 (`validateSignature_only_via_verify`) hands
    back, repackaged so trace-level reasoning can quote it cleanly. -/
def StepVerified (σ : ExecState) (step : Step) : Prop :=
  ∃ (op : UserOperation) (ep : ByteVec 20) (cid : Nat)
    (vfn : ByteVec 32 → ByteVec 32 → ByteVec 32 →
           ByteVec SignatureLen → Bool)
    (d : DecodedSig) (owner : OwnerBytes),
    step = .validate op ep cid vfn ∧
    decodeWrappedSig op.signature = some d ∧
    σ.storage.ownerAtIndex d.ownerIndex = some owner ∧
    vfn (owner.raw.take 32 (by decide))
        (owner.raw.drop 32 (by decide))
        (sphincsDigest op ep cid) d.innerSig = true

/-- Bridge from `applyStep_token_set_only_by_validate_success` to the
    `StepVerified` packaging: a slot-path validate that lifts the token
    is verified at the pre-state. -/
private theorem stepVerified_of_token_lift
    {σ σ' : ExecState} {step : Step}
    (h : applyStep σ step = some σ')
    (hwas : σ.validatedOwnerPlusOne = 0)
    (hnow : σ'.validatedOwnerPlusOne ≠ 0) :
    StepVerified σ step := by
  obtain ⟨op, ep, cid, vfn, d, owner, hstep, hOk, _hbump, _hd0, _hvop⟩ :=
    applyStep_token_set_only_by_validate_success h hwas hnow
  refine ⟨op, ep, cid, vfn, d, owner, hstep, hOk.1, hOk.2.1, hOk.2.2.2.1⟩

/-- **Trace-level non-bypass.** If `σ0.validatedOwnerPlusOne = 0` (the
    standard boundary at transaction entry — EIP-1153 transients zero
    at tx start) and `runTrace σ0 trace = some σ'` with `σ'.callStack`
    strictly longer than `σ0.callStack`, then `trace` contains at
    least one *successful* `validate` step whose `verify_fn` returned
    `true` on the appropriate `(pkSeed, pkRoot, sphincsDigest, innerSig)`.

    This is the headline non-bypass: a wallet-initiated external call
    cannot appear in the post-state unless the firmware signed off,
    the wallet decoded a wrapped sig, the on-chain `c10Verifier.verify`
    returned `true` over `sphincsDigest`, and the slot-path branch was
    taken. -/
theorem callstack_grew_implies_some_verify_true
    (σ0 σ' : ExecState) (trace : List Step)
    (hrun : runTrace σ0 trace = some σ')
    (hinit : σ0.validatedOwnerPlusOne = 0)
    (hgrew : σ0.callStack.length < σ'.callStack.length) :
    ∃ (σ_pre : ExecState) (step : Step),
      step ∈ trace ∧ StepVerified σ_pre step := by
  -- Strengthen to an inductive statement carrying the trace prefix.
  suffices aux :
      ∀ (σ : ExecState) (tr : List Step) (σf : ExecState),
        runTrace σ tr = some σf →
        σ.validatedOwnerPlusOne = 0 →
        σ.callStack.length < σf.callStack.length →
        ∃ σ_pre step, step ∈ tr ∧ StepVerified σ_pre step by
    exact aux σ0 trace σ' hrun hinit hgrew
  intro σ tr σf hrun hzero hgrew
  induction tr generalizing σ with
  | nil =>
      -- Empty trace ⇒ σf = σ, so callStack lengths are equal. Contradiction.
      unfold runTrace at hrun
      injection hrun with hrun
      rw [← hrun] at hgrew
      exact absurd hgrew (Nat.lt_irrefl _)
  | cons step rest ih =>
      unfold runTrace at hrun
      rw [Option.bind_eq_some_iff] at hrun
      obtain ⟨σ_mid, hStep, hRest⟩ := hrun
      -- Case-split: did this step grow the callStack?
      by_cases hmid : σ.callStack.length < σ_mid.callStack.length
      · -- Growth happened on `step`. Case-analyse by step shape.
        cases step with
        | validate op ep cid vfn =>
            -- A validate step preserves callStack — impossible.
            have hpres := validate_step_preserves_callstack hStep
            rw [hpres] at hmid
            exact absurd hmid (Nat.lt_irrefl _)
        | execute caller oi noc t v d =>
            -- An execute step requires σ.validatedOwnerPlusOne = oi + 1,
            -- contradicting hzero (= 0).
            have htok := execute_step_requires_prior_token hStep
            rw [hzero] at htok
            exact absurd htok.symm (Nat.succ_ne_zero _)
        | executeBatch caller oi noc ts vs ds =>
            have htok := executeBatch_step_requires_prior_token hStep
            rw [hzero] at htok
            exact absurd htok.symm (Nat.succ_ne_zero _)
      · -- Growth must come later in `rest`. Convert ¬ < to ≤.
        have hmid_le : σ_mid.callStack.length ≤ σ.callStack.length :=
          Nat.le_of_not_lt hmid
        by_cases htoken : σ_mid.validatedOwnerPlusOne = 0
        · -- Token still zero. Apply IH on `rest` starting from σ_mid.
          have hgrew_mid : σ_mid.callStack.length < σf.callStack.length := by
            calc σ_mid.callStack.length
                ≤ σ.callStack.length := hmid_le
              _ < σf.callStack.length := hgrew
          obtain ⟨σ_pre, s, hMem, hVer⟩ := ih σ_mid hRest htoken hgrew_mid
          exact ⟨σ_pre, s, List.mem_cons.mpr (Or.inr hMem), hVer⟩
        · -- Token became non-zero on this step ⇒ verifier-true validate.
          exact ⟨σ, step, List.mem_cons.mpr (Or.inl rfl),
                 stepVerified_of_token_lift hStep hzero htoken⟩

/-- Convenience corollary: a `σ0` with empty callStack reaching a
    non-empty `σ'.callStack` implies a successful `validate` somewhere
    in the trace. -/
theorem any_call_implies_some_verify_true
    (σ0 σ' : ExecState) (trace : List Step)
    (hrun : runTrace σ0 trace = some σ')
    (hinit : σ0.validatedOwnerPlusOne = 0)
    (hempty : σ0.callStack = [])
    (hsome : σ'.callStack ≠ []) :
    ∃ (σ_pre : ExecState) (step : Step),
      step ∈ trace ∧ StepVerified σ_pre step := by
  apply callstack_grew_implies_some_verify_true σ0 σ' trace hrun hinit
  rw [hempty, List.length_nil]
  exact List.length_pos_iff.mpr hsome

/-! ## Per-call attribution (Gap-2)

The `callstack_grew_implies_some_verify_true` theorem above is
EXISTENTIAL: a stack-growing trace contains *at least one*
verifier-true validate. This section strengthens that to a genuine
**per-step (injective) attribution**: every stack-growing external-call
step is backed by its OWN distinct verifier-true validate. The
load-bearing invariant is the EIP-1153 transient-token discipline:

  * a verifier-true slot-`validate` is the only step that can raise the
    `validatedOwnerPlusOne` transient to a non-zero value (it never
    appends a call);
  * every `execute`/`executeBatch` step REQUIRES the transient to be
    non-zero on entry and CLEARS it to `0` on exit (it consumes the
    stamp);

so the same stamp can authorise at most one money-moving execute. This
yields two complementary results:

  1. `token_lift_traces_to_validate` — STRUCTURAL: any non-zero
     transient at the end of a run traces back to the unique most-recent
     verifier-true validate, with NO `execute` step in between (the
     authorising validate of whatever consumes that stamp next).
  2. `growing_executes_le_verified_validates` — QUANTITATIVE: the number
     of stack-growing `execute`/`executeBatch` steps in a run is `≤` the
     number of verifier-true validate steps. This is injective
     attribution stated as a pigeonhole: `n` external-call steps need
     `n` distinct authorising validates. A purely existential gate
     (`≥ 1`) does NOT imply this `≥ n` bound — e.g. one validate followed
     by two executes is ruled out, because the first execute zeroes the
     transient and the second has nothing to consume.

Strict per-CALL (rather than per-execute-STEP) attribution — a distinct
validate for each *element* of `σ'.callStack` — is intentionally NOT
claimed: an `executeBatch` appends many calls under a single validate,
so calls within one batch share one authorising validate. Per-step is
the faithful granularity; see the module note and AXIOM_STATUS.json. -/

/-- `step.isExec` — the step is a money-moving execute-family entry-point
    (`execute` / `executeBatch`), as opposed to a `validate`. -/
def Step.isExec : Step → Bool
  | .validate .. => false
  | .execute .. => true
  | .executeBatch .. => true

/-- A step that grows the callStack is an execute-family step
    (`validate` never appends). -/
theorem grew_step_is_exec
    {σ σ' : ExecState} {step : Step}
    (h : applyStep σ step = some σ')
    (hgrew : σ.callStack.length < σ'.callStack.length) :
    step.isExec = true := by
  cases step with
  | validate op ep cid vfn =>
      have hpres := validate_step_preserves_callstack h
      rw [hpres] at hgrew; exact absurd hgrew (Nat.lt_irrefl _)
  | execute caller oi noc t v d => rfl
  | executeBatch caller oi noc ts vs ds => rfl

/-- An execute-family step that succeeds clears the transient token to 0. -/
theorem exec_step_clears_token
    {σ σ' : ExecState} {step : Step}
    (h : applyStep σ step = some σ') (hexec : step.isExec = true) :
    σ'.validatedOwnerPlusOne = 0 := by
  cases step with
  | validate op ep cid vfn => simp [Step.isExec] at hexec
  | execute caller oi noc t v d => simp only [applyStep] at h; exact execute_clears_token h
  | executeBatch caller oi noc ts vs ds =>
      simp only [applyStep] at h; exact executeBatch_clears_token h

/-- An execute-family step that succeeds requires a non-zero transient
    on entry (it consumes a stamp). -/
theorem exec_step_requires_token
    {σ σ' : ExecState} {step : Step}
    (h : applyStep σ step = some σ') (hexec : step.isExec = true) :
    σ.validatedOwnerPlusOne ≠ 0 := by
  cases step with
  | validate op ep cid vfn => simp [Step.isExec] at hexec
  | execute caller oi noc t v d =>
      simp only [applyStep] at h
      rw [execute_only_validateSig_authorises h]; exact Nat.succ_ne_zero _
  | executeBatch caller oi noc ts vs ds =>
      simp only [applyStep] at h
      rw [executeBatch_only_validateSig_authorises h]; exact Nat.succ_ne_zero _

/-- **Generalised token-change attribution.** A step whose post-state
    transient DIFFERS from its pre-state transient and is non-zero must
    be a verifier-true slot-path `validate`. Generalises
    `stepVerified_of_token_lift` (which required the pre-state token to
    be exactly `0`) to any token *change* to a non-zero value — needed
    because the most-recent stamping validate in a trace may overwrite a
    stamp left by an earlier validate. -/
theorem stepVerified_of_token_change
    {σ σ' : ExecState} {step : Step}
    (h : applyStep σ step = some σ')
    (hchg : σ'.validatedOwnerPlusOne ≠ σ.validatedOwnerPlusOne)
    (hnow : σ'.validatedOwnerPlusOne ≠ 0) :
    StepVerified σ step := by
  cases hs : step with
  | validate op ep cid vfn =>
      subst hs
      simp only [applyStep] at h
      by_cases hsucc :
          (validateSignature σ.storage op ep cid vfn).1 = Result.success
      · rw [if_pos hsucc] at h
        have hpair :
            validateSignature σ.storage op ep cid vfn
              = (Result.success, (validateSignature σ.storage op ep cid vfn).2) := by
          rw [← hsucc]
        cases hdec : decodeWrappedSig op.signature with
        | none =>
            rw [hdec] at h; injection h with h; rw [← h] at hchg; exact absurd rfl hchg
        | some d =>
            rw [hdec] at h; injection h with h
            by_cases hd0 : d.ownerIndex = 0
            · have hv : σ'.validatedOwnerPlusOne = σ.validatedOwnerPlusOne := by
                rw [← h]; unfold applyValidateSuccess; rw [if_pos hd0]
              exact absurd hv hchg
            · have hsucc_pair :
                  validateSignature σ.storage op ep cid vfn
                    = (Result.success, (validateSignature σ.storage op ep cid vfn).2) := hpair
              rw [validateSignature_success_iff] at hsucc_pair
              obtain ⟨d', owner, hOk, _hBumpEq⟩ := hsucc_pair
              exact ⟨op, ep, cid, vfn, d', owner, rfl, hOk.1, hOk.2.1, hOk.2.2.2.1⟩
      · rw [if_neg hsucc] at h; injection h with h; rw [← h] at hchg; exact absurd rfl hchg
  | execute caller oi noc t v d =>
      subst hs; simp only [applyStep] at h
      exact absurd (execute_clears_token h) hnow
  | executeBatch caller oi noc ts vs ds =>
      subst hs; simp only [applyStep] at h
      exact absurd (executeBatch_clears_token h) hnow

/-! ### Run-splitting helpers -/

/-- Split a `runTrace` over an append into the two sub-runs. -/
theorem runTrace_append (σ : ExecState) (xs ys : List Step) (σf : ExecState)
    (h : runTrace σ (xs ++ ys) = some σf) :
    ∃ σm, runTrace σ xs = some σm ∧ runTrace σm ys = some σf := by
  induction xs generalizing σ with
  | nil => exact ⟨σ, rfl, by simpa using h⟩
  | cons s rest ih =>
      simp only [List.cons_append, runTrace] at h
      rw [Option.bind_eq_some_iff] at h
      obtain ⟨σ', hStep, hRest⟩ := h
      obtain ⟨σm, hxs, hys⟩ := ih σ' hRest
      refine ⟨σm, ?_, hys⟩
      simp only [runTrace]; rw [Option.bind_eq_some_iff]; exact ⟨σ', hStep, hxs⟩

/-- `runTrace` over a singleton is `applyStep`. -/
theorem runTrace_single (σ : ExecState) (s : Step) (σf : ExecState) :
    runTrace σ [s] = some σf ↔ applyStep σ s = some σf := by
  constructor
  · intro h
    simp only [runTrace] at h; rw [Option.bind_eq_some_iff] at h
    obtain ⟨σ', h1, h2⟩ := h; rw [← (Option.some.inj h2)]; exact h1
  · intro h; simp only [runTrace]; rw [Option.bind_eq_some_iff]; exact ⟨σf, h, rfl⟩

/-- **Structural per-step attribution.** If a run from `σ0` (clean
    transient) reaches a state with a non-zero transient, the trace
    splits as `a ++ v :: b` where `v` is a verifier-true validate run
    from the state `σv` reached by `a`, and `b` contains NO execute step.
    I.e. the live stamp is owned by the most-recent verifier-true
    validate, with nothing having consumed it since — exactly the
    validate that authorises whatever execute consumes the stamp next. -/
theorem token_lift_traces_to_validate
    (tr : List Step) (σ0 σf : ExecState)
    (hrun : runTrace σ0 tr = some σf)
    (hinit : σ0.validatedOwnerPlusOne = 0)
    (hnz : σf.validatedOwnerPlusOne ≠ 0) :
    ∃ (a : List Step) (v : Step) (b : List Step) (σv : ExecState),
      tr = a ++ v :: b
      ∧ runTrace σ0 a = some σv
      ∧ StepVerified σv v
      ∧ (∀ s ∈ b, s.isExec = false) := by
  rcases tr.eq_nil_or_concat with htr | ⟨init, last, htr⟩
  · subst htr
    simp only [runTrace] at hrun
    rw [← (Option.some.inj hrun)] at hnz
    exact absurd hinit hnz
  · have hlen : init.length < tr.length := by rw [htr, List.length_concat]; omega
    rw [htr, List.concat_eq_append] at hrun
    obtain ⟨σm, hInitRun, hLastRun⟩ := runTrace_append σ0 init [last] σf hrun
    rw [runTrace_single] at hLastRun
    by_cases hchg : σf.validatedOwnerPlusOne = σm.validatedOwnerPlusOne
    · have hmnz : σm.validatedOwnerPlusOne ≠ 0 := by rw [← hchg]; exact hnz
      have hlast_ne : last.isExec = false := by
        cases h : last.isExec with
        | false => rfl
        | true =>
            have := exec_step_clears_token hLastRun h
            rw [this] at hchg; exact absurd hchg.symm hmnz
      obtain ⟨a, v, b, σv, hsplit, hArun, hVer, hb⟩ :=
        token_lift_traces_to_validate init σ0 σm hInitRun hinit hmnz
      refine ⟨a, v, b ++ [last], σv, ?_, hArun, hVer, ?_⟩
      · rw [htr, List.concat_eq_append, hsplit]; simp
      · intro s hs
        rcases List.mem_append.mp hs with h1 | h2
        · exact hb s h1
        · rcases List.mem_singleton.mp h2 with rfl; exact hlast_ne
    · refine ⟨init, last, [], σm, ?_, hInitRun, ?_, ?_⟩
      · rw [htr, List.concat_eq_append]
      · exact stepVerified_of_token_change hLastRun hchg hnz
      · intro s hs; simp at hs
termination_by tr.length
decreasing_by exact hlen

/-! ### Quantitative (injective) attribution via a transient-token ledger -/

/-- A step "stamps" iff it changes the transient to a non-zero value —
    i.e. it is a verifier-true slot-validate (`stepVerified_of_token_change`). -/
def stampsB (σ σ' : ExecState) : Bool :=
  decide (σ'.validatedOwnerPlusOne ≠ σ.validatedOwnerPlusOne) &&
  decide (σ'.validatedOwnerPlusOne ≠ 0)

/-- A step "grows" iff it appends to the callStack — i.e. it is a
    money-moving execute-family step (`grew_step_is_exec`). -/
def growsB (σ σ' : ExecState) : Bool :=
  decide (σ.callStack.length < σ'.callStack.length)

/-- `tokenBit σ` = 1 if the transient is live, else 0. -/
def tokenBit (σ : ExecState) : Nat := if σ.validatedOwnerPlusOne = 0 then 0 else 1

/-- Walk a trace, counting `(stamp, grow)` events along the run. Returns
    `(finalState, #stamps, #grows)`, or `none` on revert. -/
def ledger (σ : ExecState) : List Step → Option (ExecState × Nat × Nat)
  | [] => some (σ, 0, 0)
  | s :: rest =>
      match applyStep σ s with
      | none => none
      | some σ' =>
          match ledger σ' rest with
          | none => none
          | some (σf, nv, ne) =>
              some (σf, nv + (if stampsB σ σ' then 1 else 0),
                        ne + (if growsB σ σ' then 1 else 0))

/-- The local ledger inequality: across one step, `grow + tokenBit_after
    ≤ stamp + tokenBit_before`. The three cases are the token discipline:
    a stamp raises the bit (and never grows); a grow needs the bit live
    and clears it (and never stamps); anything else preserves the slack. -/
theorem step_ledger_ineq {σ σ' : ExecState} {s : Step}
    (h : applyStep σ s = some σ') :
    (if growsB σ σ' then 1 else 0) + tokenBit σ'
      ≤ (if stampsB σ σ' then 1 else 0) + tokenBit σ := by
  have htb_nonneg : ∀ τ : ExecState, tokenBit τ ≤ 1 := by
    intro τ; unfold tokenBit; split <;> omega
  cases s with
  | validate op ep cid vfn =>
      have hpres := validate_step_preserves_callstack h
      have hg : growsB σ σ' = false := by
        unfold growsB; rw [hpres]; exact decide_eq_false (Nat.lt_irrefl _)
      by_cases hch : σ'.validatedOwnerPlusOne = σ.validatedOwnerPlusOne
      · have hs : stampsB σ σ' = false := by unfold stampsB; simp [hch]
        simp only [hg, hs, Bool.false_eq_true, if_false]
        unfold tokenBit; rw [hch]; omega
      · by_cases hz : σ'.validatedOwnerPlusOne = 0
        · simp only [hg, Bool.false_eq_true, if_false]
          have ht' : tokenBit σ' = 0 := by unfold tokenBit; rw [if_pos hz]
          rw [ht']; have := htb_nonneg σ; omega
        · have hs : stampsB σ σ' = true := by unfold stampsB; simp [hch, hz]
          simp only [hg, hs, Bool.false_eq_true, if_false, if_true]
          have ht' : tokenBit σ' = 1 := by unfold tokenBit; rw [if_neg hz]
          rw [ht']; have := htb_nonneg σ; omega
  | execute caller oi noc t v d =>
      have hz := execute_clears_token (by simpa only [applyStep] using h)
      have hreq : σ.validatedOwnerPlusOne ≠ 0 := by
        rw [execute_only_validateSig_authorises (by simpa only [applyStep] using h)]
        exact Nat.succ_ne_zero _
      have hs : stampsB σ σ' = false := by unfold stampsB; simp [hz]
      have ht' : tokenBit σ' = 0 := by unfold tokenBit; rw [if_pos hz]
      have htσ : tokenBit σ = 1 := by unfold tokenBit; rw [if_neg hreq]
      simp only [hs, Bool.false_eq_true, if_false, ht', htσ]
      split <;> omega
  | executeBatch caller oi noc ts vs ds =>
      have hz := executeBatch_clears_token (by simpa only [applyStep] using h)
      have hreq : σ.validatedOwnerPlusOne ≠ 0 := by
        rw [executeBatch_only_validateSig_authorises (by simpa only [applyStep] using h)]
        exact Nat.succ_ne_zero _
      have hs : stampsB σ σ' = false := by unfold stampsB; simp [hz]
      have ht' : tokenBit σ' = 0 := by unfold tokenBit; rw [if_pos hz]
      have htσ : tokenBit σ = 1 := by unfold tokenBit; rw [if_neg hreq]
      simp only [hs, Bool.false_eq_true, if_false, ht', htσ]
      split <;> omega

/-- The ledger reaches the same final state as `runTrace`. -/
theorem ledger_state :
    ∀ (tr : List Step) (σ σf : ExecState) (nv ne : Nat),
      ledger σ tr = some (σf, nv, ne) → runTrace σ tr = some σf := by
  intro tr
  induction tr with
  | nil =>
      intro σ σf nv ne h; simp only [ledger] at h
      injection h with h1; injection h1 with h1 _
      simp only [runTrace]; rw [h1]
  | cons s rest ih =>
      intro σ σf nv ne h
      simp only [ledger] at h
      cases hstep : applyStep σ s with
      | none => rw [hstep] at h; simp at h
      | some σ' =>
          rw [hstep] at h; simp only [] at h
          cases hled : ledger σ' rest with
          | none => rw [hled] at h; simp at h
          | some triple =>
              rw [hled] at h
              obtain ⟨σf', nv', ne'⟩ := triple
              injection h with h1; injection h1 with hσ _
              simp only [runTrace]; rw [Option.bind_eq_some_iff]
              refine ⟨σ', hstep, ?_⟩; rw [← hσ]
              exact ih σ' σf' nv' ne' hled

/-- Every successful run admits a ledger walk. -/
theorem ledger_of_runTrace :
    ∀ (tr : List Step) (σ σf : ExecState),
      runTrace σ tr = some σf → ∃ nv ne, ledger σ tr = some (σf, nv, ne) := by
  intro tr
  induction tr with
  | nil =>
      intro σ σf h; simp only [runTrace] at h
      refine ⟨0, 0, ?_⟩; simp only [ledger]; rw [Option.some.inj h]
  | cons s rest ih =>
      intro σ σf h
      simp only [runTrace] at h; rw [Option.bind_eq_some_iff] at h
      obtain ⟨σ', hstep, hrest⟩ := h
      obtain ⟨nv, ne, hled⟩ := ih σ' σf hrest
      refine ⟨nv + (if stampsB σ σ' then 1 else 0), ne + (if growsB σ σ' then 1 else 0), ?_⟩
      simp only [ledger]; rw [hstep]; simp only []; rw [hled]

/-- The global ledger invariant: `#grows + tokenBit_final ≤ #stamps +
    tokenBit_initial`. Folded `step_ledger_ineq`. -/
theorem ledger_invariant :
    ∀ (tr : List Step) (σ σf : ExecState) (nv ne : Nat),
      ledger σ tr = some (σf, nv, ne) →
      ne + tokenBit σf ≤ nv + tokenBit σ := by
  intro tr
  induction tr with
  | nil =>
      intro σ σf nv ne h; simp only [ledger] at h
      injection h with h1; injection h1 with hσ h2; injection h2 with hnv hne
      rw [← hσ, ← hnv, ← hne]; omega
  | cons s rest ih =>
      intro σ σf nv ne h
      simp only [ledger] at h
      cases hstep : applyStep σ s with
      | none => rw [hstep] at h; simp at h
      | some σ' =>
          rw [hstep] at h; simp only [] at h
          cases hled : ledger σ' rest with
          | none => rw [hled] at h; simp at h
          | some triple =>
              rw [hled] at h
              obtain ⟨σf', nv', ne'⟩ := triple
              injection h with h1; injection h1 with hσf h2; injection h2 with hnv hne
              have ihr := ih σ' σf' nv' ne' hled
              have hstepineq := step_ledger_ineq hstep
              rw [← hσf, ← hne, ← hnv]; omega

/-- **Quantitative (injective) per-step attribution.** For a run from a
    clean transient (`σ0.validatedOwnerPlusOne = 0`), the number of
    stack-growing execute-family steps is `≤` the number of verifier-true
    validate steps. Each money-moving external-call step is therefore
    backed by its OWN distinct authorising validate: `n` such calls force
    `n` distinct verifier-true validates. (`#grows` counts exactly the
    stack-growing executes — `grew_step_is_exec`; `#stamps` counts exactly
    the verifier-true validates — `stepVerified_of_token_change`.) -/
theorem growing_executes_le_verified_validates
    (σ0 σf : ExecState) (tr : List Step) (nv ne : Nat)
    (hledger : ledger σ0 tr = some (σf, nv, ne))
    (hinit : σ0.validatedOwnerPlusOne = 0) :
    ne ≤ nv := by
  have hinv := ledger_invariant tr σ0 σf nv ne hledger
  have h0 : tokenBit σ0 = 0 := by unfold tokenBit; rw [if_pos hinit]
  have hf : 0 ≤ tokenBit σf := Nat.zero_le _
  rw [h0] at hinv; omega

/-! ### Ledger counts ARE the security-meaningful counts.

These two lemmas pin down that `growing_executes_le_verified_validates`
is genuine per-step attribution, not a numeric coincidence: every step
the ledger counts as a `stamp` is a verifier-true `validate`
(`StepVerified`), and every step it counts as a `grow` is a money-moving
execute (`isExec`). So `ne ≤ nv` literally reads "#external-call steps ≤
#verifier-true validates". -/

/-- A `stamp`-counted step is a verifier-true validate at its pre-state. -/
theorem stampsB_is_verified
    {σ σ' : ExecState} {s : Step}
    (h : applyStep σ s = some σ') (hstamp : stampsB σ σ' = true) :
    StepVerified σ s := by
  unfold stampsB at hstamp
  rw [Bool.and_eq_true] at hstamp
  exact stepVerified_of_token_change h
    (of_decide_eq_true hstamp.1) (of_decide_eq_true hstamp.2)

/-- A `grow`-counted step is a money-moving execute-family step. -/
theorem growsB_is_exec
    {σ σ' : ExecState} {s : Step}
    (h : applyStep σ s = some σ') (hgrow : growsB σ σ' = true) :
    s.isExec = true := by
  unfold growsB at hgrow
  exact grew_step_is_exec h (of_decide_eq_true hgrow)


end SphincsCVerify.Wallet.TxFlow
