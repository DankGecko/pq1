// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {PQMultiOwnable} from "../src/PQMultiOwnable.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

/// @notice REGRESSION: the bootstrap few-time-usage cap (`bootstrapUses`,
///         invariant #7) counts EVERY accepted Type-1 signature.
///
///         `_validateSignature` accepts a bootstrap (ownerIndex 0) UserOp the
///         moment its C10 signature verifies — that signature has already
///         consumed a position on the master key's SPHINCS+ few-time forest,
///         and is public on-chain in the UserOp calldata. The counter bump is
///         therefore done in the VALIDATION phase, atomically with acceptance,
///         so it is revert-proof: ERC-4337 v0.6's execution phase is
///         revert-tolerant (`handleOps` swallows a reverting `callData`,
///         emits `UserOperationRevertReason`, and keeps validation-phase
///         state), so a count done in execution would be lost.
///
///         History: the original audit M-1 fix DEFERRED the bump to
///         `addOwnerBytes`, gated on `_addOwner` succeeding. Because a
///         duplicate-owner registration reverts in execution (trivially
///         forced — the firmware is stateless and cannot refuse a "duplicate"),
///         an attacker who can drive the device to emit bootstrap signatures
///         (a malicious/compromised companion app) could run the master key
///         past its few-time budget while the on-chain cap read far below the
///         true count, re-opening the SPHINCS+ forgery surface the caps exist
///         to close. These tests lock in the revert-proof validation-phase
///         count.
contract PQBootstrapCapEvasionTest is Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);

    MockSPHINCSVerifier internal c10;
    PQSmartWallet internal impl;
    PQSmartWalletFactory internal factory;

    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    function setUp() public {
        c10 = new MockSPHINCSVerifier();
        impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        factory = new PQSmartWalletFactory(address(impl), c10);
    }

    function _deployWallet() internal returns (PQSmartWallet) {
        c10.setValid(true);
        return factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, SLOT0_PK_SEED, SLOT0_PK_ROOT, uint64(block.chainid), hex"aaaa"
        );
    }

    function _bootstrapOp(address sender, bytes memory callData)
        internal
        pure
        returns (UserOperation06 memory op)
    {
        op.sender = sender;
        op.callData = callData;
        op.signature = abi.encode(uint256(0), new bytes(4008)); // ownerIndex 0 = bootstrap
    }

    /// Faithfully models one v0.6 `handleOps` op: validate (must accept), then
    /// execute (EntryPoint swallows a reverting callData). Returns the
    /// validation result so the caller can assert the signature was accepted.
    function _runBootstrapOp(PQSmartWallet w, bytes memory callData) internal returns (uint256 validationData) {
        vm.prank(ENTRY_POINT_ADDR);
        validationData = w.validateUserOp(_bootstrapOp(address(w), callData), bytes32(0), 0);

        if (validationData == 0) {
            // Execution phase. In production the EntryPoint catches a revert
            // here (emits UserOperationRevertReason) and proceeds.
            vm.prank(ENTRY_POINT_ADDR);
            try w.addOwnerBytes(_decodeOwner(callData)) {} catch {}
        }
    }

    function _decodeOwner(bytes memory callData) internal pure returns (bytes memory owner) {
        // callData = addOwnerBytes.selector ++ abi.encode(bytes owner)
        bytes memory tail = new bytes(callData.length - 4);
        for (uint256 i = 0; i < tail.length; i++) tail[i] = callData[i + 4];
        owner = abi.decode(tail, (bytes));
    }

    // ──────────────────────────────────────────────────────────────────────
    // A single accepted bootstrap signature is counted even when execution
    // reverts (the duplicate-owner case).
    // ──────────────────────────────────────────────────────────────────────

    function test_acceptedBootstrapSig_isCounted_evenWhenAddOwnerReverts() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // `dup` is already an owner: the factory installed it at index 1.
        bytes memory dup = abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT);
        assertTrue(w.isOwnerBytes(dup), "slot0 is already an owner");
        assertEq(w.bootstrapUses(), 0, "precondition");

        bytes memory cd = abi.encodeCall(w.addOwnerBytes, (dup));

        // The bootstrap signature is ACCEPTED at validation (validationData==0):
        // the master key has signed; a few-time position is spent.
        uint256 vd = _runBootstrapOp(w, cd);
        assertEq(vd, 0, "bootstrap signature was ACCEPTED by validateUserOp");

        // ...and the cap counter advanced, even though `_addOwner` reverted.
        assertEq(
            w.bootstrapUses(), 1,
            "accepted bootstrap signature is counted against the cap"
        );
    }

    /// Drive it N times: N accepted bootstrap signatures, cap reads N.
    function test_everyAcceptedSig_isCounted() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        bytes memory dup = abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT);
        bytes memory cd = abi.encodeCall(w.addOwnerBytes, (dup));

        uint256 n = 64;
        for (uint256 i = 0; i < n; i++) {
            assertEq(_runBootstrapOp(w, cd), 0, "each bootstrap sig accepted");
        }

        // 64 accepted master-key signatures; the on-chain few-time budget
        // counter reflects all of them.
        assertEq(w.bootstrapUses(), n, "every accepted sig counted");
        assertEq(w.nextOwnerIndex(), 2, "no owner actually added (all duplicates)");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Bundle: each accepted signature counts, even when one op reverts in the
    // execution phase.
    // ──────────────────────────────────────────────────────────────────────

    function test_bundle_countsEachAcceptedSig_evenWhenOneReverts() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // Two bootstrap UserOps in one bundle, BOTH registering the SAME new
        // owner X (in production: two different nonces, two distinct valid
        // master-key signatures). Validation does not dedup, so both are
        // accepted.
        bytes memory ownerX =
            abi.encodePacked(bytes32(uint256(0x1111) << 240), bytes32(uint256(0x2222) << 240));
        bytes memory cd = abi.encodeCall(w.addOwnerBytes, (ownerX));

        // PHASE 1: validate ALL (v0.6 order). Both signatures accepted AND
        // counted in the validation phase.
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_bootstrapOp(address(w), cd), bytes32(0), 0), 0, "op A accepted");
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_bootstrapOp(address(w), cd), bytes32(0), 0), 0, "op B accepted");
        assertEq(w.bootstrapUses(), 2, "both accepted sigs counted at validation");

        // PHASE 2: execute ALL. A installs X (success); B now sees X as a
        // duplicate and reverts (EntryPoint swallows it). The count does not
        // change in execution.
        vm.prank(ENTRY_POINT_ADDR);
        w.addOwnerBytes(ownerX);
        vm.prank(ENTRY_POINT_ADDR);
        try w.addOwnerBytes(ownerX) {} catch {}

        // TWO bootstrap signatures were accepted; the cap reflects two.
        assertEq(w.bootstrapUses(), 2, "2 accepted bootstrap sigs counted as 2");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Control — the slot path has always counted in the validation phase;
    // confirm the bootstrap path now matches it.
    // ──────────────────────────────────────────────────────────────────────

    function test_control_slotPathCountsEvenWhenExecutionReverts() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // A slot-1 op whose target call reverts in execution.
        RevertingTarget t = new RevertingTarget();
        bytes memory cd = abi.encodeCall(w.executeWithOffchainCount, (1, 1, address(t), 0, hex"00"));

        UserOperation06 memory op;
        op.sender = address(w);
        op.callData = cd;
        op.signature = abi.encode(uint256(1), new bytes(4008));

        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(op, bytes32(0), 0), 0, "slot op accepted");
        assertEq(w.slotUses(1), 1, "slotUses bumped in VALIDATION -- counted up front");

        vm.prank(ENTRY_POINT_ADDR);
        try w.executeWithOffchainCount(1, 1, address(t), 0, hex"00") {} catch {}

        // Even though execution reverted, the accepted slot signature stayed
        // counted -- the behaviour the bootstrap path now also has.
        assertEq(w.slotUses(1), 1, "slot signature remains counted after an execution revert");
    }
}

contract RevertingTarget {
    fallback() external payable {
        revert("nope");
    }
}
