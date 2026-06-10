// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";
import {HalmosWalletBase} from "./HalmosWalletBase.sol";

/// @notice Halmos symbolic-execution rules for the **money-moving**
///         surface — `executeWithOffchainCount` /
///         `executeBatchWithOffchainCount` — executed against the deployed
///         runtime bytecode. These discharge the execution surface of
///         `solidityWallet_compiles_correctly` (A3.2) and are the bytecode
///         analogue of Lean Claim 3 / Claim 4 (`executeBatch_faithful`,
///         `every_call_gated_by_verifier`): no wallet-initiated external
///         call without a prior verifier-true validate stamping the
///         matching owner-index credit.
///
///         Run: `halmos --contract HalmosExecute`.
contract HalmosExecute is HalmosWalletBase {
    function setUp() public {
        wallet = _deployWalletSha256Free();
    }

    /// @dev Run a real validate step that stamps the execution-phase credit
    ///      for `ownerIndex` (slot path). Uses the genuine `validateUserOp`
    ///      bytecode (so the credit is stamped exactly as in production).
    function _validate(uint256 ownerIndex, bytes memory callData) internal {
        bytes memory wrappedSig = abi.encode(ownerIndex, new bytes(4008));
        c10.setValid(true);
        vm.prank(ENTRY_POINT_ADDR);
        wallet.validateUserOp(_op(callData, wrappedSig), bytes32(0), 0);
    }

    // ──────────────────────────────────────────────────────────────────
    // The core gate: NO execute without a prior verifier-true validate.
    // ──────────────────────────────────────────────────────────────────

    /// **E-3 — execute without a prior validate reverts.** No credit was
    /// stamped, so the executor must reject (anti-impersonation).
    function check_execute_without_validate_reverts() public {
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(1, 0, address(0xc0ffee), 0, "") returns (bytes memory) {
            assertTrue(false, "bytecode (E-3): execute without validate accepted");
        } catch {
            // expected: OwnerIndexMismatch (no validated credit)
        }
    }

    /// **E-1 — only the EntryPoint reaches the executor.**
    function check_execute_rejects_non_entrypoint_caller(address caller) public {
        vm.assume(caller != ENTRY_POINT_ADDR);
        vm.prank(caller);
        try wallet.executeWithOffchainCount(1, 0, address(0xc0ffee), 0, "") returns (bytes memory) {
            assertTrue(false, "bytecode (E-1): non-EntryPoint reached executor");
        } catch {
            // expected: NotFromEntryPoint
        }
    }

    /// **E-3 — owner-index mismatch reverts.** A credit stamped for
    /// `sigIdx` cannot be consumed by an execute claiming a different
    /// `calldataIdx` (the validation-phase H-3 parity already forces
    /// sigIdx==calldataIdx, so the cross-index credit never exists).
    function check_execute_rejects_owner_index_mismatch(uint256 calldataIdx) public {
        vm.assume(calldataIdx != 1);
        // Validate for slot 1 with matching calldata (so a credit[1] exists).
        _validate(1, abi.encodeCall(
            wallet.executeWithOffchainCount, (uint256(1), uint256(0), address(0xc0ffee), uint256(0), bytes("")))
        );
        // Execute claiming a DIFFERENT ownerIndex — no credit[calldataIdx].
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(calldataIdx, 0, address(0xc0ffee), 0, "") returns (bytes memory) {
            assertTrue(false, "bytecode (E-3): ownerIndex mismatch accepted");
        } catch {
            // expected: OwnerIndexMismatch
        }
    }

    /// **E-4 — credit is one-shot: a second execute in the same tx reverts.**
    function check_execute_no_replay() public {
        _validate(1, abi.encodeCall(
            wallet.executeWithOffchainCount, (uint256(1), uint256(0), address(0xc0ffee), uint256(0), bytes("")))
        );
        vm.prank(ENTRY_POINT_ADDR);
        wallet.executeWithOffchainCount(1, 0, address(0xc0ffee), 0, "");
        // Second execute (no new validate) must revert: credit consumed.
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(1, 0, address(0xc0ffee), 0, "") returns (bytes memory) {
            assertTrue(false, "bytecode (E-4): double-execute accepted");
        } catch {
            // expected: OwnerIndexMismatch (credit was cleared)
        }
    }

    /// **E-2 — self-target is rejected (audit H-2: no upgrade/owner-mint
    /// via the execute self-call).**
    function check_execute_rejects_self_target() public {
        _validate(1, abi.encodeCall(
            wallet.executeWithOffchainCount, (uint256(1), uint256(0), address(wallet), uint256(0), bytes("")))
        );
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(1, 0, address(wallet), 0, "") returns (bytes memory) {
            assertTrue(false, "bytecode (E-2): self-target accepted");
        } catch {
            // expected: SelfCallForbidden
        }
    }

    /// **E-2 (batch) — any self-target in a batch is rejected.** The
    /// self-target position (`selfIdx`) is symbolic over {0,1,2}; the
    /// concrete-branch construction keeps the array STORE index concrete
    /// (Halmos forks on `selfIdx`), so this proves rejection regardless of
    /// where in the batch the self-target sits.
    function check_executeBatch_rejects_any_self_target(uint256 selfIdx) public {
        vm.assume(selfIdx < 3);
        address[] memory targets = new address[](3);
        targets[0] = address(0xc0ffee);
        targets[1] = address(0xc0ffee);
        targets[2] = address(0xc0ffee);
        if (selfIdx == 0) {
            targets[0] = address(wallet);
        } else if (selfIdx == 1) {
            targets[1] = address(wallet);
        } else {
            targets[2] = address(wallet);
        }
        uint256[] memory values = new uint256[](3);
        bytes[] memory datas = new bytes[](3);

        _validate(1, abi.encodeCall(
            wallet.executeBatchWithOffchainCount, (uint256(1), uint256(0), targets, values, datas))
        );
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeBatchWithOffchainCount(1, 0, targets, values, datas) {
            assertTrue(false, "bytecode (E-2 batch): self-target in batch accepted");
        } catch {
            // expected: SelfCallForbidden
        }
    }
}
