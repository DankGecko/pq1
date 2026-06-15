// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../../../smart-wallet/src/PQSmartWallet.sol";
import {MockSPHINCSVerifier} from "../../../smart-wallet/test/mocks/MockSPHINCSVerifier.sol";

/// A target that always reverts — for the atomicity rule.
contract KRevertingTarget {
    function anything() external pure {
        revert("nope");
    }
    fallback() external payable {
        revert("nope");
    }
}

/// @notice **A3.2-exec — Kontrol/KEVM port.** Proves `executeWithOffchainCount`
///         and `executeBatchWithOffchainCount` semantics DIRECTLY on the
///         deployed `PQSmartWallet` runtime bytecode (KEVM symbolic execution),
///         an engine independent of Halmos with NO hand-written
///         `LeanExecuteModel.sol` mirror in the loop — the transcription-free
///         discharge of the execute half of bridge axiom A3.2. Mirrors the
///         rules in `test/halmos/HalmosExecuteEquiv.t.sol`, asserting the Lean
///         `Wallet/Execute.lean` gates directly:
///           caller == EntryPoint; a validated transient CREDIT for `ownerIndex`
///           is present (anti-impersonation / one-shot); target != self;
///           `setOffchain` gate (newCount ≥ prev ∧ slotUses+newCount ≤ MAX);
///           offchainSigCount[i] := newCount; atomic on a reverting target.
///
///         The transient credit is stamped by running the REAL validation-phase
///         bytecode over a CONCRETE op with the mock verifier valid (KEVM
///         computes the concrete `sphincsDigest` SHA-256 via its `[concrete]`
///         precompile rewrite — no symbolic-hash wall; A3.1's ∀-signature is
///         out of scope here). Few-time counters are made symbolic (under the
///         reachable-state combined-cap invariant) via `vm.store` at the
///         ERC-7201 slots, exactly as the Halmos harness does.
contract KontrolExecute is Test {
    address internal constant ENTRY_POINT_ADDR = address(0x4337);
    // A codeless target: `target.call` succeeds trivially (no code), isolating
    // the credit / setOffchain / self-target control flow (the "callOk ≡ true"
    // world; the emitted CALL byte-delivery itself is axiom A4).
    address internal constant CODELESS_TARGET = address(0xC0DE1E55);

    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    // ERC-7201 PQMultiOwnable storage base (see PQMultiOwnable.sol).
    bytes32 internal constant PQ_SLOT_BASE =
        0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000;

    PQSmartWallet internal wallet;
    MockSPHINCSVerifier internal c10;
    uint256 internal MAX;

    function setUp() public {
        vm.chainId(31337); // KEVM default chainid is 1; mock M14 guard is local-only.
        c10 = new MockSPHINCSVerifier();
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        wallet = PQSmartWallet(payable(LibClone.deployERC1967(address(impl))));
        wallet.initialize(
            abi.encodePacked(MASTER_PK_SEED, MASTER_PK_ROOT),
            abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT)
        );
        MAX = wallet.MAX_SLOT_USES();
        // Cover any bounded symbolic `value` transfer to a codeless target.
        vm.deal(address(wallet), type(uint128).max);
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

    /// Stamp ONE validated-op credit at wrapper ownerIndex 1 by running the real
    /// validation-phase bytecode over a concrete op + valid mock verifier.
    /// (Counters are fresh here, so the validate succeeds and bumps slotUses[1];
    /// the credit-dependent rules overwrite the counters afterwards.)
    function _stampCreditAt1() internal {
        bytes memory callData = abi.encodeCall(
            wallet.executeWithOffchainCount,
            (uint256(1), uint256(0), CODELESS_TARGET, uint256(0), bytes(""))
        );
        bytes memory wrappedSig = abi.encode(uint256(1), new bytes(4008));
        c10.setValid(true);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vres = wallet.validateUserOp(_op(callData, wrappedSig), bytes32(0), 0);
        require(vres == 0, "stamp: validate did not succeed");
    }

    /// Set slotUses[1] / offchainSigCount[1] to symbolic values under the
    /// reachable-state combined-cap invariant.
    function _storeSymCounters(uint256 slotUses1, uint256 offchain1) internal {
        vm.assume(slotUses1 <= MAX);
        vm.assume(offchain1 <= MAX - slotUses1);
        uint256 base = uint256(PQ_SLOT_BASE);
        vm.store(address(wallet), keccak256(abi.encode(uint256(1), base + 5)), bytes32(slotUses1));
        vm.store(address(wallet), keccak256(abi.encode(uint256(1), base + 6)), bytes32(offchain1));
    }

    // ── Rule 1: access gate — EntryPoint only (∀ non-EP caller) ──────────────

    function prove_execute_requires_entrypoint(
        address caller, uint256 ownerIndex, uint256 newCount, uint256 value, bytes calldata data
    ) public {
        vm.assume(caller != ENTRY_POINT_ADDR);
        vm.prank(caller);
        try wallet.executeWithOffchainCount(ownerIndex, newCount, CODELESS_TARGET, value, data) {
            assertTrue(false, "execute: non-EntryPoint accepted");
        } catch {}
    }

    // ── Rule 2: anti-impersonation — no credit ⇒ revert (∀ ownerIndex) ───────

    /// A direct EntryPoint call with NO preceding validate (no stamped credit)
    /// reverts for EVERY ownerIndex — Lean `validatedOwnerPlusOne = 0 ⇒ none`.
    function prove_execute_no_credit_reverts(
        uint256 ownerIndex, uint256 newCount, uint256 value, bytes calldata data
    ) public {
        uint256 preOff = wallet.offchainSigCount(ownerIndex);
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(ownerIndex, newCount, CODELESS_TARGET, value, data) {
            assertTrue(false, "execute: ran without a validated credit");
        } catch {
            assertEq(wallet.offchainSigCount(ownerIndex), preOff, "no-credit: offchain moved");
        }
    }

    // ── Rule 3: self-target reject (credit present) ──────────────────────────

    function prove_execute_rejects_self_target(uint256 newCount, uint256 value, bytes calldata data) public {
        _stampCreditAt1();
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(1, newCount, address(wallet), value, data) {
            assertTrue(false, "execute: self-target accepted");
        } catch {}
    }

    // ── Rule 4: pointwise setOffchain gate + monotone update + frame ─────────

    /// **`executeWithOffchainCount(1, newCount, codeless, …)` pointwise.**
    /// Accepts iff the Lean `setOffchain` gate holds (newCount ≥ prev ∧
    /// slotUses[1] + newCount ≤ MAX); on accept `offchainSigCount[1] := newCount`
    /// and bootstrapUses / slotUses[1] / offchainSigCount[2] are unmoved.
    function prove_execute_pointwise(
        uint256 slotUses1, uint256 offchain1, uint256 newCount, uint256 value, bytes calldata data
    ) public {
        vm.assume(value <= type(uint128).max);
        // The off-chain count is cap-bounded (combined cap ⇒ ≤ MAX); a newCount
        // above MAX is uniformly rejected (cap gate, or a checked-add overflow
        // in `slotUsesNow + newCount`) — bounding it keeps full boundary
        // coverage of both setOffchain gates without the 2^256-overflow artifact.
        vm.assume(newCount <= MAX);
        _stampCreditAt1();
        _storeSymCounters(slotUses1, offchain1);

        bool wantSuccess = newCount >= offchain1 && slotUses1 + newCount <= MAX;

        uint256 preBoot = wallet.bootstrapUses();
        uint256 preOff2 = wallet.offchainSigCount(2);

        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(1, newCount, CODELESS_TARGET, value, data) {
            assertTrue(wantSuccess, "A3.2-exec: succeeded outside the setOffchain gate");
            assertEq(wallet.offchainSigCount(1), newCount, "A3.2-exec: offchainSigCount[1] != newCount");
            assertEq(wallet.slotUses(1), slotUses1, "A3.2-exec frame: slotUses[1] moved");
            assertEq(wallet.bootstrapUses(), preBoot, "A3.2-exec frame: bootstrapUses moved");
            assertEq(wallet.offchainSigCount(2), preOff2, "A3.2-exec frame: offchain[2] moved");
        } catch {
            assertTrue(!wantSuccess, "A3.2-exec: reverted inside the setOffchain gate");
            assertEq(wallet.offchainSigCount(1), offchain1, "A3.2-exec fail: offchain[1] moved");
            assertEq(wallet.slotUses(1), slotUses1, "A3.2-exec fail: slotUses[1] moved");
        }
    }

    // ── Rule 5: credit is one-shot — a second execute (no re-stamp) reverts ──

    function prove_execute_credit_one_shot(uint256 value, bytes calldata data) public {
        vm.assume(value <= type(uint128).max);
        _stampCreditAt1();
        // First execute consumes the single credit (newCount 0 ≥ prev 0, cap ok).
        vm.prank(ENTRY_POINT_ADDR);
        wallet.executeWithOffchainCount(1, 0, CODELESS_TARGET, value, data);
        // Second execute at the same index, no new stamp ⇒ no credit ⇒ revert.
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(1, 0, CODELESS_TARGET, value, data) {
            assertTrue(false, "execute: credit re-used (not one-shot)");
        } catch {}
    }

    // ── Rule 6: atomicity — a reverting target reverts the whole call ────────

    function prove_execute_atomic_on_reverting_target(uint256 newCount, bytes calldata data) public {
        _stampCreditAt1();
        KRevertingTarget rt = new KRevertingTarget();
        uint256 preOff1 = wallet.offchainSigCount(1);
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(1, newCount, address(rt), 0, data) {
            assertTrue(false, "execute: succeeded despite a reverting target");
        } catch {
            assertEq(wallet.offchainSigCount(1), preOff1, "atomicity: offchain[1] mutated by a reverted call");
        }
    }

    // ── Rule 7: batch — self-target reject + offchain update ─────────────────

    function prove_executeBatch_rejects_self_target(uint256 newCount, bytes calldata d0) public {
        _stampCreditAt1();
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);
        targets[0] = CODELESS_TARGET;
        targets[1] = address(wallet); // self in the second element
        datas[0] = d0;
        datas[1] = "";
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeBatchWithOffchainCount(1, newCount, targets, values, datas) {
            assertTrue(false, "executeBatch: self-target element accepted");
        } catch {}
    }

    /// **`executeBatchWithOffchainCount` success path — 2-element dispatch +
    /// setOffchain runs ONCE + frame**, on the real bytecode (concrete instance).
    ///
    /// DECOMPOSITION + a KEVM limitation, stated honestly:
    ///  * The batch's setOffchain gate is the *identical*
    ///    `_setOffchainSigCount(ownerIndex, newCount, slotUses[ownerIndex], MAX)`
    ///    call as single-execute, proven ∀-counters by `prove_execute_pointwise`.
    ///  * The batch loop's distinctive per-element self-target guard is proven
    ///    (∀) by `prove_executeBatch_rejects_self_target`.
    ///  * What remains batch-specific is: on the SUCCESS path, setOffchain runs
    ///    exactly once (offchain[1] ends at newCount, not n·newCount) and BOTH
    ///    elements dispatch. A symbolic `newCount` makes the whole batch calldata
    ///    symbolic, and on the success path KEVM reads each element's CALL
    ///    `value` (= `values[i]`) via a `#range` over that symbolic calldata
    ///    buffer it cannot simplify to 0 (a KEVM symbolic-calldata-dynamic-array
    ///    limitation — the self-target rule dodges it by reverting before the
    ///    value read). So this success witness uses a CONCRETE `newCount`; the
    ///    ∀ gate coverage is delegated as above.
    function prove_executeBatch_pointwise() public {
        _stampCreditAt1();
        uint256 preSlot1 = wallet.slotUses(1);          // post-stamp (= 1)
        uint256 preBoot = wallet.bootstrapUses();
        uint256 newCount = preSlot1 + 6;                // concrete; ≥ offchain[1]=0 and slotUses[1]+newCount ≤ MAX

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);
        targets[0] = CODELESS_TARGET;
        targets[1] = CODELESS_TARGET;
        datas[0] = "";
        datas[1] = "";

        vm.prank(ENTRY_POINT_ADDR);
        wallet.executeBatchWithOffchainCount(1, newCount, targets, values, datas);

        // setOffchain ran exactly once (offchain[1] == newCount, not 2·newCount);
        // slotUses + bootstrap untouched (frame).
        assertEq(wallet.offchainSigCount(1), newCount, "A3.2-exec batch: offchain[1] != newCount");
        assertEq(wallet.slotUses(1), preSlot1, "A3.2-exec batch frame: slotUses[1] moved");
        assertEq(wallet.bootstrapUses(), preBoot, "A3.2-exec batch frame: bootstrapUses moved");
    }
}
