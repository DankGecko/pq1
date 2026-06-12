// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";
import {PqsignerProto} from "../../src/generated/PqsignerProto.sol";

/// @notice Clause-for-clause Solidity transcription of the Lean model
///         `SphincsCVerify.Wallet.Execute.executeWithOffchainCount` /
///         `executeBatchWithOffchainCount`
///         (contracts/verification/lean/SphincsCVerify/Wallet/Execute.lean).
///
///         PURPOSE — bridge axioms A3.2-exec
///         (`solidityWalletExecute_compiles_correctly` /
///         `solidityWalletExecuteBatch_compiles_correctly`,
///         Bridge/Refinement.lean) assert pointwise equality between the
///         deployed execute bytecode and the Lean `Execute` model. Halmos
///         cannot consume a Lean term, so this contract IS the Lean term,
///         transcribed clause-for-clause (each block cites the Lean line it
///         mirrors), and `HalmosExecuteEquiv` proves the deployed execute
///         bytecode pointwise-equal to THIS contract over the documented
///         envelope. The residual transcription gap (this file <-> the Lean
///         file) is a side-by-side syntactic correspondence over ~40 lines
///         of first-order code.
///
///         MODEL-STATE CORRESPONDENCE (part of the axiom's documented TCB,
///         mirrored from the A3.2 storage correspondence):
///           * `σ.storage`            <-> the wallet's ERC-7201 storage,
///             read through the same public getters the bytecode reads;
///           * `σ.credits ownerIndex` <-> the wallet's per-index transient
///             credit counter (`keccak256(ownerIndex, _TS_CREDIT_NAMESPACE)`
///             EIP-1153 slot), supplied by the HARNESS as `creditAtIndex`
///             (transient storage has no external getter; the harness knows
///             the ground truth because it performed the stamping
///             `validateUserOp` calls itself, and the stamp<->consume
///             bytecode pairing is separately proven by the
///             `HalmosExecute` + `HalmosExecuteEquiv` credit rules,
///             including the multi-stamp counter rule). Since 2026-06-12 the
///             Lean model carries the SAME per-index counter map the
///             bytecode does (`ExecState.credits : Nat → Nat`,
///             stamp = `+1`, consume = `-1`) — the previous single-token
///             abstraction and its <=1-stamp envelope are gone (GAP-11);
///           * the Lean `Option ExecState` codomain <-> (revert ⟺ `none`);
///             the appended `callStack` entry <-> the dispatched EVM call,
///             observable via the recorder rule when the target records.
///
///         GUARD-ORDER NOTE: both the deployed bytecode and the Lean model
///         check caller → credit → self-target → setOffchain (the old
///         model's separate token-set / token-match clauses collapsed into
///         the single per-index credit-present check — presenting an index
///         IS naming the credit consumed; H-3 parity binds calldata index
///         to wrapper index in the VALIDATION phase).
contract LeanExecuteModel {
    uint256 public constant MAX_SLOT_USES = PqsignerProto.MAX_SLOT_USES;

    /// @dev Mirrors the Lean `σ.entryPoint` field — must be the same
    ///      EntryPoint address the wallet under test was constructed with.
    address public immutable entryPointAddr;

    constructor(address entryPoint_) {
        entryPointAddr = entryPoint_;
    }

    /// The model's output, projected onto the fields the bytecode can
    /// observably change. On failure the Lean model returns `none`
    /// (bytecode: revert, state unchanged), so the post field carries no
    /// information and is zeroed; meaningful only when `success`.
    struct Prediction {
        bool success; // Lean `some σ'` vs `none`
        uint256 postOffchainAtOwnerIndex; // σ'.storage.offchainSigCount ownerIndex
    }

    /// @notice The Lean `executeWithOffchainCount σ caller ownerIndex
    ///         newOffchainCount target value data` (Execute.lean),
    ///         with `σ.storage` read through the wallet's getters,
    ///         `σ.credits ownerIndex = creditAtIndex` (harness ground
    ///         truth for the PRESENTED index), `σ.selfAddress =
    ///         address(wallet)`, and `σ.entryPoint = entryPointAddr`.
    ///         `value`/`data` only flow into the appended `Call` (checked
    ///         by the recorder rule), not into the accept/reject decision,
    ///         so they are not parameters here.
    function predictExecute(
        PQSmartWallet wallet,
        uint256 creditAtIndex,
        address caller,
        uint256 ownerIndex,
        uint256 newOffchainCount,
        address target
    ) external view returns (Prediction memory p) {
        // Lean: `if caller ≠ σ.entryPoint then none`
        if (caller != entryPointAddr) return p;
        // Lean: `if σ.credits ownerIndex = 0 then none`
        if (creditAtIndex == 0) return p;
        // Lean: `if target = σ.selfAddress then none`
        if (target == address(wallet)) return p;
        // Lean: `Storage.setOffchain σ.storage ownerIndex newOffchainCount
        //          (σ.storage.slotUses ownerIndex) MaxSlotUses`
        return _setOffchain(wallet, ownerIndex, newOffchainCount);
    }

    /// @notice The Lean `executeBatchWithOffchainCount` (Execute.lean).
    ///         `targets` participates in the per-element self-target check
    ///         (`appendBatchCalls`); `values`/`datas` only flow into the
    ///         appended calls, so only their LENGTHS (the `| _, _, _ =>
    ///         none` length-mismatch arm) matter here.
    function predictExecuteBatch(
        PQSmartWallet wallet,
        uint256 creditAtIndex,
        address caller,
        uint256 ownerIndex,
        uint256 newOffchainCount,
        address[] calldata targets,
        uint256 valuesLen,
        uint256 datasLen
    ) external view returns (Prediction memory p) {
        // Lean: `if caller ≠ σ.entryPoint then none`
        if (caller != entryPointAddr) return p;
        // Lean: `if σ.credits ownerIndex = 0 then none`
        if (creditAtIndex == 0) return p;
        // Lean `appendBatchCalls`: the `| _, _, _ => none` arm fires on any
        // length mismatch...
        if (valuesLen != targets.length || datasLen != targets.length) return p;
        // ...and the `if t = selfAddr then none` arm on any self-target.
        for (uint256 i; i < targets.length; i++) {
            if (targets[i] == address(wallet)) return p;
        }
        // Lean: `Storage.setOffchain ... ownerIndex newOffchainCount
        //          (σ.storage.slotUses ownerIndex) MaxSlotUses`
        return _setOffchain(wallet, ownerIndex, newOffchainCount);
    }

    /// Lean `Storage.setOffchain s ownerIndex newCount slotUsesNow cap`
    /// (Storage.lean:96-103). The Lean conjuncts are over ℕ; the
    /// comparisons below are the overflow-free uint256 transliteration
    /// (`slotUsesNow + newCount > cap` ⟺ `newCount > cap - slotUsesNow`
    /// given `slotUsesNow <= cap`, which the harness establishes via the
    /// kernel-proven reachable-state invariant — the same combined-cap
    /// hypothesis A3.2 carries).
    function _setOffchain(PQSmartWallet wallet, uint256 ownerIndex, uint256 newCount)
        private
        view
        returns (Prediction memory p)
    {
        // Lean: `let prev := s.offchainSigCount ownerIndex`
        uint256 prev = wallet.offchainSigCount(ownerIndex);
        // Lean: `if newCount < prev then none`
        if (newCount < prev) return p;
        // Lean: `else if slotUsesNow + newCount > cap then none`
        uint256 slotUsesNow = wallet.slotUses(ownerIndex);
        if (slotUsesNow > MAX_SLOT_USES || newCount > MAX_SLOT_USES - slotUsesNow) return p;
        // Lean: `else some { s with offchainSigCount := fun i =>
        //          if i = ownerIndex then newCount else ... }`
        p.success = true;
        p.postOffchainAtOwnerIndex = newCount;
    }
}
