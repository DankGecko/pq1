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

    // ── Wrapper-decode structural gates: ∀-symbolic REJECTS ──────────────────
    //
    // The `prove_validate_*_nonbypass` rules above pass the *canonical* wrapper
    // `abi.encode(uint256, new bytes(4008))`, so the three structural decode gates
    // in `_validateSignature` (offsetField==0x40, innerLen==C10_SIG_LEN, tailPad==0)
    // hold BY CONSTRUCTION — they were never exercised ∀-symbolically (the honest
    // gap the 2026-07-02 KONTROL_SCOPING NOTE recorded). The three rules below close
    // that: each makes exactly ONE wrapper word symbolic-and-malformed and proves
    // `validateUserOp` returns FAILURE for EVERY such value. These gates fire at
    // `_validateSignature` L428/L429/L433 — BEFORE the verifier CALL and the
    // `sphincsDigest` SHA-256 — so the rules are hash-free (Kontrol's fast class).
    //
    // NON-VACUITY: each rule sets `c10.setValid(true)` and a well-formed slot
    // callData, so the ONLY reason for rejection is the malformed word — the
    // canonical-wrapper `prove_validate_slot_nonbypass` (verdict=true) is the
    // "well-formed ⇒ success" other half of the contrast. So "∀ malformed ⇒ reject"
    // rejects BECAUSE of the field, not because the op is otherwise junk.

    /// Build a 4128-byte `SignatureWrapper` with symbolic words at the exact decode
    /// offsets. Layout (sig-offset relative): [0]=ownerIndex, [32]=offsetField,
    /// [64]=innerLen, [96..4104)=innerSig(4008), [4104..4128)=tail-pad(24). The word
    /// at +4096 (`lastWord`) holds the last 8 innerSig bytes (high) + the 24 tail
    /// bytes (low), matching the wallet's masked read. 32+32+32+4000+32 = 4128.
    function _sigWithFields(uint256 ownerIndex, uint256 offsetField, uint256 innerLen, bytes32 lastWord)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes32(ownerIndex), bytes32(offsetField), bytes32(innerLen), new bytes(4000), lastWord
        );
    }

    /// **∀ malformed ABI offset word ⇒ REJECT.** For every `offsetField != 0x40`,
    /// `validateUserOp` returns FAILURE — even with the verifier accepting. Fires at
    /// `_validateSignature` L428 (`offsetField != 0x40`), before verify/hash.
    function prove_validate_rejects_bad_offset(uint256 offsetField) public {
        vm.assume(offsetField != 0x40);
        c10.setValid(true); // reject is the decode gate's, not the verifier's
        bytes memory callData = abi.encodeCall(
            wallet.executeWithOffchainCount,
            (uint256(1), uint256(0), CODELESS_TARGET, uint256(0), bytes(""))
        );
        bytes memory wrappedSig = _sigWithFields(1, offsetField, 4008, bytes32(0));
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vres = wallet.validateUserOp(_op(callData, wrappedSig), bytes32(0), 0);
        assertTrue(vres != 0, "A3.2-validate: accepted a malformed ABI offset word");
    }

    /// **∀ malformed inner length ⇒ REJECT.** For every `innerLen != C10_SIG_LEN`
    /// (4008), `validateUserOp` returns FAILURE. Fires at `_validateSignature` L429.
    function prove_validate_rejects_bad_innerlen(uint256 innerLen) public {
        vm.assume(innerLen != 4008); // C10_SIG_LEN
        c10.setValid(true);
        bytes memory callData = abi.encodeCall(
            wallet.executeWithOffchainCount,
            (uint256(1), uint256(0), CODELESS_TARGET, uint256(0), bytes(""))
        );
        bytes memory wrappedSig = _sigWithFields(1, 0x40, innerLen, bytes32(0));
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vres = wallet.validateUserOp(_op(callData, wrappedSig), bytes32(0), 0);
        assertTrue(vres != 0, "A3.2-validate: accepted a malformed inner length");
    }

    /// **∀ nonzero ABI tail-pad ⇒ REJECT.** For every `lastWord` whose low 24 bytes
    /// (the ABI tail-pad, positions [4104..4128), masked by `2^192 - 1`) are nonzero,
    /// `validateUserOp` returns FAILURE. Fires at `_validateSignature` L433. Closes
    /// the wrapper-malleability gate (Audit L-1) ∀-symbolically.
    function prove_validate_rejects_bad_tailpad(bytes32 lastWord) public {
        // low 24 bytes nonzero == the wallet's masked tail-pad != 0
        vm.assume(uint256(lastWord) & ((uint256(1) << 192) - 1) != 0);
        c10.setValid(true);
        bytes memory callData = abi.encodeCall(
            wallet.executeWithOffchainCount,
            (uint256(1), uint256(0), CODELESS_TARGET, uint256(0), bytes(""))
        );
        bytes memory wrappedSig = _sigWithFields(1, 0x40, 4008, lastWord);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vres = wallet.validateUserOp(_op(callData, wrappedSig), bytes32(0), 0);
        assertTrue(vres != 0, "A3.2-validate: accepted a nonzero ABI tail pad");
    }
}
