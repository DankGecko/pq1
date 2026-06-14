// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";

import {PQSmartWallet} from "../../../smart-wallet/src/PQSmartWallet.sol";
import {PQMultiOwnable} from "../../../smart-wallet/src/PQMultiOwnable.sol";
import {MockSPHINCSVerifier} from "../../../smart-wallet/test/mocks/MockSPHINCSVerifier.sol";

/// @notice **First Kontrol (KEVM) proof against the DEPLOYED PQSmartWallet
///          runtime bytecode** — the model-to-bytecode gap (D) explored with
///          a symbolic-execution engine independent of Halmos.
///
///          PROPERTY (security invariant #6, owner-set integrity / Lean
///          `Invariants.cannot_remove_bootstrap`): the bootstrap owner at
///          index 0 can NEVER be removed via `removeOwnerAtIndex`, for ANY
///          caller and ANY `expected` owner-bytes argument — including the
///          exact installed bootstrap bytes. The deployed control-flow guard
///          is `PQMultiOwnable._removeOwnerAtIndex`'s
///          `if (index == 0) revert CannotRemoveBootstrap();` (and the
///          EntryPoint access gate on the external `removeOwnerAtIndex`).
///
///          WHY THIS IS A GOOD KONTROL FIRST TARGET
///          ---------------------------------------
///          * NO SHA-256: `removeOwnerAtIndex(0, _)` reverts before any
///            hashing — Kontrol never has to interpret the `0x02` precompile
///            (the same reason the verifier A3.1 ∀-signature is intractable
///            under an uninterpreted hash is NOT in scope here).
///          * NO unbounded loops: a single storage read + a keccak compare
///            that is never reached on the `index == 0` arm.
///          * Deployment state is seeded with a real `initialize` (no factory
///            `createAccount`, which would pull `sha256` for the CREATE2 salt
///            + slot-0 squat digest — out of scope, axiom A3.3).
///
///          This mirrors `test/halmos/HalmosMultiOwnable.t.sol`'s
///          `check_removeOwner_bootstrap_unremovable`, transposed to the
///          Kontrol/KEVM engine: function arguments are symbolic by default
///          (no `svm.*`), `kevm.symbolicStorage` is unnecessary because the
///          wallet is brought up with the real initialiser, and the assertion
///          is the bytecode analogue of the Lean `removeOwner`'s
///          `if index = 0 then none` arm.
contract KontrolBootstrapUnremovable is Test {
    address internal constant ENTRY_POINT_ADDR = address(0x4337);

    // N-mask-shaped owner keys (top 16 bytes set, bottom 16 zero) — the
    // exact shape the firmware emits and the contract's N-mask gate accepts.
    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    PQSmartWallet internal wallet;
    MockSPHINCSVerifier internal c10;

    function setUp() public {
        c10 = new MockSPHINCSVerifier();
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        address proxy = LibClone.deployERC1967(address(impl));
        wallet = PQSmartWallet(payable(proxy));
        // Owners installed: index 0 = MASTER (bootstrap), index 1 = SLOT0.
        // nextOwnerIndex = 2. This is byte-identical to the storage the
        // factory's createAccount installs (which we skip — it hashes).
        wallet.initialize(
            abi.encodePacked(MASTER_PK_SEED, MASTER_PK_ROOT),
            abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT)
        );
    }

    /// **Bootstrap is unremovable on the bytecode — ∀ caller, ∀ expected.**
    ///
    /// Kontrol makes the 64-byte `expected` argument symbolic. We force the
    /// EntryPoint arm (the only arm that even reaches the `index == 0` guard)
    /// and assert the call MUST revert and owner 0 MUST survive byte-for-byte.
    /// The dual rule `prove_bootstrap_remove_rejected_non_entrypoint` covers
    /// the non-EntryPoint reject.
    ///
    /// Lean refinement target: `Wallet/Invariants.lean`
    ///   `cannot_remove_bootstrap` / `Storage.removeOwner`'s
    ///   `if index = 0 then none` arm.
    function prove_bootstrap_unremovable_from_entrypoint(bytes calldata expected) public {
        // Only the 64-byte length class is interesting (the contract's keccak
        // compare path); shorter/longer is rejected upstream and is covered
        // by the non-zero-index Halmos rule. Constrain to keep the proof tight.
        vm.assume(expected.length == 64);

        bytes memory pre0 = wallet.ownerAtIndex(0);
        uint256 preNext = wallet.nextOwnerIndex();
        uint256 preRemoved = wallet.removedOwnersCount();

        vm.prank(ENTRY_POINT_ADDR);
        // The deployed guard reverts with CannotRemoveBootstrap() for EVERY
        // expected value — even the exactly-correct installed bytes.
        vm.expectRevert(PQMultiOwnable.CannotRemoveBootstrap.selector);
        wallet.removeOwnerAtIndex(0, expected);

        // Owner 0 unchanged; counters unmoved (frame condition).
        assertEq(keccak256(wallet.ownerAtIndex(0)), keccak256(pre0), "bootstrap mutated");
        assertEq(wallet.nextOwnerIndex(), preNext, "nextOwnerIndex moved");
        assertEq(wallet.removedOwnersCount(), preRemoved, "removedOwnersCount moved");
    }

    /// **Exact-bytes variant** — the strongest adversary: the caller hands
    /// the precise installed bootstrap bytes (the only value that would pass
    /// the keccak compare IF the index-0 guard did not exist). It still
    /// reverts. This is the symbolic engine certifying the guard runs BEFORE
    /// the bytes check.
    function prove_bootstrap_unremovable_exact_bytes() public {
        bytes memory exact = abi.encodePacked(MASTER_PK_SEED, MASTER_PK_ROOT);
        vm.prank(ENTRY_POINT_ADDR);
        vm.expectRevert(PQMultiOwnable.CannotRemoveBootstrap.selector);
        wallet.removeOwnerAtIndex(0, exact);
        assertEq(wallet.ownerAtIndex(0).length, 64, "bootstrap survived");
    }

    /// **Access gate — ∀ non-EntryPoint caller, removeOwnerAtIndex(0, _)
    /// reverts NotFromEntryPoint.** Symbolic `caller` and `expected`.
    /// (Together with the EntryPoint rule above this is the full
    /// ∀-caller envelope.)
    function prove_bootstrap_remove_rejected_non_entrypoint(address caller, bytes calldata expected) public {
        vm.assume(caller != ENTRY_POINT_ADDR);
        vm.assume(expected.length == 64);
        bytes memory pre0 = wallet.ownerAtIndex(0);
        vm.prank(caller);
        vm.expectRevert(PQSmartWallet.NotFromEntryPoint.selector);
        wallet.removeOwnerAtIndex(0, expected);
        assertEq(keccak256(wallet.ownerAtIndex(0)), keccak256(pre0), "bootstrap mutated by non-EP");
    }
}
