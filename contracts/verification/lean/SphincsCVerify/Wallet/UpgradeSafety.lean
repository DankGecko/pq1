/-
UUPS upgrade-path unreachability — the named end-to-end theorem.

## Background (faithfulness-audit 2026-06-14, Gap-4)

The `PQSmartWallet` is an ERC-1967 proxy that does NOT override Solady's
`_authorizeUpgrade` (which reverts unconditionally), so there is no
intended in-band upgrade path. The remaining worry is an *out-of-band*
one: could a UserOp reach `upgradeToAndCall` (which lives on the wallet
itself, at `address(this)`), or could a namespaced-storage write corrupt
the ERC-1967 implementation pointer? Two independently-proven facts rule
both out:

  * **No self-call.** Every external call dispatched by
    `executeWithOffchainCount` / `executeBatchWithOffchainCount` refuses a
    `target = address(this)` (audit H-2). Since `upgradeToAndCall` is a
    method *of the wallet*, the only way `execute*` could invoke it is by
    targeting the wallet's own address — which every execute path rejects.
    Proven by `Execute.execute_rejects_self_target` and
    `Execute.executeBatch_rejects_self_target`.

  * **Disjoint storage.** The ERC-7201 `pqsigner.storage.PQMultiOwnable`
    namespace slot is distinct from the ERC-1967 implementation slot, so
    no owner-set / counter mutation in our `Storage` model can alias and
    overwrite the proxy's implementation pointer. Proven by
    `StorageLayout.pq_storage_disjoint_from_erc1967_impl`.

The audit (FAITHFULNESS_AUDIT §2 Gap-4) noted both pieces existed but were
not *assembled* into a single named theorem. This module does exactly that
— it COMPOSES the existing, already-kernel-clean theorems (it does not
re-prove them) into `upgrade_path_unreachable`. No new axiom is
introduced; the closure is the union of the two pieces' closures
(`{propext, Classical.choice, Quot.sound}`, kernel-only).

What this theorem captures (and what it does NOT):
  * It DOES capture: no `execute*` / `executeBatch*` call lands at the
    wallet's own address (so `upgradeToAndCall` is unreachable via a
    self-call), AND the PQ namespace storage is disjoint from the
    ERC-1967 impl slot (so wallet mutations never touch it).
  * It does NOT add a model of `_authorizeUpgrade` reverting, nor of the
    proxy delegatecall dispatcher; those remain Solidity-side facts
    (Solady `UUPSUpgradeable`) cross-checked by the bytecode-equivalence
    bridge, not re-derived here. The Lean claim is scoped to the executor
    surface + storage layout, exactly the two surfaces this project models.
-/

import SphincsCVerify.Wallet.Execute
import SphincsCVerify.Wallet.StorageLayout

namespace SphincsCVerify.Wallet.UpgradeSafety

open SphincsCVerify.Wallet

/-! ## Component restatements (thin aliases over the proven pieces)

Each of these is *definitionally* one of the two already-proven theorems —
no new proof content. They exist only to give the composite a single,
readable name per component. -/

/-- **(component 1a)** A successful single-call execute never targets the
    wallet's own address. Alias of `Execute.execute_rejects_self_target`. -/
theorem execute_never_self_target
    {σ : Execute.ExecState} {caller : SphincsCVerify.Spec.ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {target : SphincsCVerify.Spec.ByteVec 20} {value : Nat} {data : Array UInt8}
    {σ' : Execute.ExecState}
    (h : Execute.executeWithOffchainCount σ caller ownerIndex newOffchainCount
             target value data = some σ') :
    target ≠ σ.selfAddress :=
  Execute.execute_rejects_self_target h

/-- **(component 1b)** A successful batch execute targets no element equal
    to the wallet's own address. Alias of
    `Execute.executeBatch_rejects_self_target`. -/
theorem executeBatch_never_self_target
    {σ : Execute.ExecState} {caller : SphincsCVerify.Spec.ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (SphincsCVerify.Spec.ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    {σ' : Execute.ExecState}
    (h : Execute.executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
             targets values datas = some σ') :
    ∀ t ∈ targets, t ≠ σ.selfAddress :=
  Execute.executeBatch_rejects_self_target h

/-- **(component 2)** The PQ namespace storage slot is disjoint from the
    ERC-1967 implementation slot. Alias of
    `StorageLayout.pq_storage_disjoint_from_erc1967_impl`. -/
theorem pq_storage_never_aliases_impl_slot :
    StorageLayout.PQ_MULTI_OWNABLE_STORAGE_SLOT
      ≠ StorageLayout.ERC1967_IMPLEMENTATION_SLOT :=
  StorageLayout.pq_storage_disjoint_from_erc1967_impl

/-! ## The composite theorem -/

/-- **`upgrade_path_unreachable` — UUPS upgrade path is unreachable.**

    The named end-to-end assembly the faithfulness audit (Gap-4) asked
    for. It is the conjunction of the two independently-proven facts that
    together rule out any unintended upgrade:

    1. **No execute path lands at the wallet's own address.** Both
       `executeWithOffchainCount` (single) and
       `executeBatchWithOffchainCount` (batch), on every successful run,
       refuse `target = σ.selfAddress`. Because `upgradeToAndCall` is a
       method *of the wallet itself* (`address(this)`), an `execute*`
       cannot invoke it without self-targeting — which is exactly what
       these guards forbid. Hence the ERC-1967 implementation slot is
       never written via a self-call routed through the executor.

    2. **PQ storage is disjoint from the ERC-1967 implementation slot.**
       The ERC-7201 `pqsigner.storage.PQMultiOwnable` namespace is a
       different 32-byte slot from the ERC-1967 impl slot, so no owner /
       counter mutation can alias and clobber the implementation pointer.

    Composed from `Execute.execute_rejects_self_target`,
    `Execute.executeBatch_rejects_self_target`, and
    `StorageLayout.pq_storage_disjoint_from_erc1967_impl` — no new proof
    obligation, no new axiom. Closure: kernel-only
    `{propext, Classical.choice, Quot.sound}`. -/
theorem upgrade_path_unreachable :
    -- (1) no single-call execute lands at the wallet's own address
    (∀ {σ : Execute.ExecState} {caller : SphincsCVerify.Spec.ByteVec 20}
       {ownerIndex newOffchainCount : Nat}
       {target : SphincsCVerify.Spec.ByteVec 20} {value : Nat} {data : Array UInt8}
       {σ' : Execute.ExecState},
       Execute.executeWithOffchainCount σ caller ownerIndex newOffchainCount
           target value data = some σ' →
       target ≠ σ.selfAddress)
    ∧
    -- (1') no batch execute lands at the wallet's own address
    (∀ {σ : Execute.ExecState} {caller : SphincsCVerify.Spec.ByteVec 20}
       {ownerIndex newOffchainCount : Nat}
       {targets : List (SphincsCVerify.Spec.ByteVec 20)} {values : List Nat}
       {datas : List (Array UInt8)}
       {σ' : Execute.ExecState},
       Execute.executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
           targets values datas = some σ' →
       ∀ t ∈ targets, t ≠ σ.selfAddress)
    ∧
    -- (2) PQ storage layout is disjoint from the ERC-1967 impl slot
    (StorageLayout.PQ_MULTI_OWNABLE_STORAGE_SLOT
      ≠ StorageLayout.ERC1967_IMPLEMENTATION_SLOT) :=
  ⟨fun h => Execute.execute_rejects_self_target h,
   fun h => Execute.executeBatch_rejects_self_target h,
   StorageLayout.pq_storage_disjoint_from_erc1967_impl⟩

end SphincsCVerify.Wallet.UpgradeSafety
