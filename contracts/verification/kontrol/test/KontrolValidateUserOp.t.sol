// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../../../smart-wallet/src/PQSmartWallet.sol";
import {MockSPHINCSVerifier} from "../../../smart-wallet/test/mocks/MockSPHINCSVerifier.sol";

/// @notice **A3.2-validate — Kontrol/KEVM port (the non-bypass property, I-1).**
///         Proves `validateUserOp` / `_validateSignature` DIRECTLY on the
///         deployed PQSmartWallet bytecode under KEVM symbolic execution —
///         engine independent of Halmos, NO LeanValidateUserOpModel.sol mirror —
///         the transcription-free discharge of the validate half of bridge axiom
///         A3.2 (`solidityWallet_compiles_correctly`). Mirrors
///         `test/halmos/HalmosValidateUserOpEquiv.t.sol`; asserts the Lean
///         `Wallet.Invariants.validateSignature_only_via_verify` (I-1) directly:
///         validateUserOp returns SUCCESS (0) IFF the role-split `capOk` gate
///         holds AND the verifier accepted — so in particular a successful
///         validate IMPLIES the verifier returned true (no bypass).
///
///         SYMBOLIC ENVELOPE — stated exactly. The `sphincsDigest` hashes the op
///         FIELDS, not `op.signature`, so the op + the signature WRAPPER are kept
///         CONCRETE (digest computes via KEVM's `[concrete]` SHA-256 rewrite; the
///         wrapper-decode gates — length/offset/innerLen/tailPad — pass by
///         construction) and the verifier ANSWER (mock `valid` ← symbolic
///         `verdict`) + the few-time COUNTERS are symbolic. The wrapper
///         `ownerIndex` is concrete PER RULE (the slot role at 1, the bootstrap
///         role at 0, an unset index at 2) — a symbolic `ownerIndex` lives in
///         the dynamic `op.signature` and trips the same KEVM symbolic-calldata
///         limitation the batch/factory harnesses document; the role-split is
///         covered by the per-role rules instead. The non-bypass + the cap gate
///         are thus proven ∀-verdict, ∀-counters per role.
contract KontrolValidateUserOp is Test {
    address internal constant ENTRY_POINT_ADDR = address(0x4337);
    address internal constant CODELESS_TARGET = address(0xC0DE1E55);

    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    bytes32 internal constant PQ_SLOT_BASE =
        0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000;

    PQSmartWallet internal wallet;
    MockSPHINCSVerifier internal c10;
    uint256 internal MAX;
    uint256 internal MAX_BOOT;

    function setUp() public {
        vm.chainId(31337);
        c10 = new MockSPHINCSVerifier();
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        wallet = PQSmartWallet(payable(LibClone.deployERC1967(address(impl))));
        wallet.initialize(
            abi.encodePacked(MASTER_PK_SEED, MASTER_PK_ROOT),
            abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT)
        );
        MAX = wallet.MAX_SLOT_USES();
        MAX_BOOT = wallet.MAX_BOOTSTRAP_USES();
    }

    function _op(bytes memory callData, bytes memory sig)
        internal
        view
        returns (UserOperation06 memory op)
    {
        op.sender = address(wallet);
        op.initCode = abi.encodePacked(bytes32(0));
        op.callData = callData;
        op.paymasterAndData = abi.encodePacked(bytes32(0));
        op.signature = sig;
    }

    function _storeSlotCounters(uint256 slotUses1, uint256 offchain1) internal {
        uint256 base = uint256(PQ_SLOT_BASE);
        vm.store(address(wallet), keccak256(abi.encode(uint256(1), base + 5)), bytes32(slotUses1));
        vm.store(address(wallet), keccak256(abi.encode(uint256(1), base + 6)), bytes32(offchain1));
    }

    function _storeBootstrapUses(uint256 b) internal {
        vm.store(address(wallet), bytes32(uint256(PQ_SLOT_BASE) + 4), bytes32(b));
    }

    // ── I-1 non-bypass, SLOT role (ownerIndex 1) ────────────────────────────

    /// **validateUserOp success ⟺ capOk(slot) ∧ verifier-accepts**, ∀ symbolic
    /// counters + verdict. In particular success ⇒ the verifier returned true
    /// (no bypass) — the bytecode analogue of `validateSignature_only_via_verify`.
    function prove_validate_slot_nonbypass(uint256 slotUses1, uint256 offchain1, bool verdict) public {
        vm.assume(slotUses1 <= MAX);
        vm.assume(offchain1 <= MAX - slotUses1); // reachable combined-cap state
        _storeSlotCounters(slotUses1, offchain1);
        c10.setValid(verdict);

        // A slot-allowed op whose calldata ownerIndex (first arg) == 1.
        bytes memory callData = abi.encodeCall(
            wallet.executeWithOffchainCount,
            (uint256(1), uint256(0), CODELESS_TARGET, uint256(0), bytes(""))
        );
        bytes memory wrappedSig = abi.encode(uint256(1), new bytes(4008));

        bool capOk = slotUses1 + offchain1 < MAX;
        bool want = capOk && verdict;

        vm.prank(ENTRY_POINT_ADDR);
        uint256 vres = wallet.validateUserOp(_op(callData, wrappedSig), bytes32(0), 0);
        bool success = (vres == 0);

        assertEq(success, want, "A3.2-validate slot: success != (capOk && verifier-accepts)");
        if (success) {
            assertTrue(verdict, "I-1 BYPASS: validate succeeded WITHOUT verifier acceptance");
            // cap bumped on success (slotUses[1] += 1).
            assertEq(wallet.slotUses(1), slotUses1 + 1, "A3.2-validate slot: slotUses not bumped");
        } else {
            assertEq(wallet.slotUses(1), slotUses1, "A3.2-validate slot fail: slotUses moved");
        }
    }

    // ── I-1 non-bypass, BOOTSTRAP role (ownerIndex 0) ───────────────────────

    /// **validateUserOp success ⟺ bootstrapUses < MAX ∧ verifier-accepts** for a
    /// Type-1 (ownerIndex 0, `addOwnerBytes`) op, ∀ symbolic bootstrapUses +
    /// verdict. Success ⇒ verifier accepted (no bypass).
    function prove_validate_bootstrap_nonbypass(uint256 bootUses, bool verdict) public {
        vm.assume(bootUses <= MAX_BOOT);
        _storeBootstrapUses(bootUses);
        c10.setValid(verdict);

        // ownerIndex 0 requires the addOwnerBytes selector (a concrete N-masked
        // new owner; its content is irrelevant to validation).
        bytes memory newOwner = abi.encodePacked(bytes32(uint256(0xeeee) << 240), bytes32(uint256(0xffff) << 240));
        bytes memory callData = abi.encodeCall(wallet.addOwnerBytes, (newOwner));
        bytes memory wrappedSig = abi.encode(uint256(0), new bytes(4008));

        bool capOk = bootUses < MAX_BOOT;
        bool want = capOk && verdict;

        vm.prank(ENTRY_POINT_ADDR);
        uint256 vres = wallet.validateUserOp(_op(callData, wrappedSig), bytes32(0), 0);
        bool success = (vres == 0);

        assertEq(success, want, "A3.2-validate bootstrap: success != (capOk && verifier-accepts)");
        if (success) {
            assertTrue(verdict, "I-1 BYPASS: bootstrap validate succeeded WITHOUT verifier acceptance");
            assertEq(wallet.bootstrapUses(), bootUses + 1, "A3.2-validate bootstrap: bootstrapUses not bumped");
        } else {
            assertEq(wallet.bootstrapUses(), bootUses, "A3.2-validate bootstrap fail: bootstrapUses moved");
        }
    }

    // ── Unset owner ⇒ always fail (even if the verifier accepts) ────────────

    /// validateUserOp for an UNSET owner index (no installed key) returns
    /// FAILURE regardless of the verifier — the `ownerBytes.length != 64` gate,
    /// Lean `s.ownerAtIndex i = none`. (Concrete unset index 2; a symbolic index
    /// rides in the dynamic wrapper — see the envelope note.)
    function prove_validate_rejects_unset_owner(bool verdict) public {
        c10.setValid(verdict);
        bytes memory callData = abi.encodeCall(
            wallet.executeWithOffchainCount,
            (uint256(2), uint256(0), CODELESS_TARGET, uint256(0), bytes(""))
        );
        bytes memory wrappedSig = abi.encode(uint256(2), new bytes(4008));
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vres = wallet.validateUserOp(_op(callData, wrappedSig), bytes32(0), 0);
        assertTrue(vres != 0, "A3.2-validate: accepted an unset owner index");
    }

    // ── EntryPoint-only access gate (∀ non-EP caller) ───────────────────────

    function prove_validate_rejects_non_entrypoint(address caller) public {
        vm.assume(caller != ENTRY_POINT_ADDR);
        c10.setValid(true);
        bytes memory callData = abi.encodeCall(
            wallet.executeWithOffchainCount,
            (uint256(1), uint256(0), CODELESS_TARGET, uint256(0), bytes(""))
        );
        bytes memory wrappedSig = abi.encode(uint256(1), new bytes(4008));
        vm.prank(caller);
        try wallet.validateUserOp(_op(callData, wrappedSig), bytes32(0), 0) {
            assertTrue(false, "A3.2-validate: non-EntryPoint caller accepted");
        } catch {}
    }
}
