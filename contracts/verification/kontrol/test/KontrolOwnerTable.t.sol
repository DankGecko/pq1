// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";

import {PQSmartWallet} from "../../../smart-wallet/src/PQSmartWallet.sol";
import {PQMultiOwnable} from "../../../smart-wallet/src/PQMultiOwnable.sol";
import {MockSPHINCSVerifier} from "../../../smart-wallet/test/mocks/MockSPHINCSVerifier.sol";

/// @notice **A3.4 (owner-table) — Kontrol/KEVM port.** Proves the PQMultiOwnable
///         owner-table mutators + reads pointwise against the Lean
///         `Storage.{addOwner,removeOwner,tryInitialize,ownerAtIndex}` model,
///         DIRECTLY on the deployed `PQSmartWallet` runtime bytecode (KEVM
///         symbolic execution) — an engine independent of Halmos, with no
///         hand-written `LeanModel.sol` mirror in the loop. This is the
///         transcription-free discharge of bridge axiom A3.4
///         (`solidityMultiOwnable_compiles_correctly`); it mirrors the rules in
///         `test/halmos/HalmosMultiOwnable.t.sol` rule-for-rule. The
///         bootstrap-unremovable arm lives in `KontrolBootstrapUnremovable.t.sol`.
///
///         SYMBOLIC ENVELOPE: owner CONTENT is a symbolic `bytes calldata` arg
///         (KEVM makes it symbolic by default); we constrain the LENGTH per
///         class via `vm.assume` (a symbolic byte-length explodes the path
///         space — the same engine limit Halmos documents). N-mask layout and
///         duplicate membership stay fully symbolic; callers symbolic in the
///         access-gate rules; counters asserted in the frames.
contract KontrolOwnerTable is Test {
    address internal constant ENTRY_POINT_ADDR = address(0x4337);

    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    PQSmartWallet internal wallet;
    MockSPHINCSVerifier internal c10;

    function setUp() public {
        // KEVM default chainid is 1; MockSPHINCSVerifier's M14 deploy guard
        // reverts off a local chain (see KontrolBootstrapUnremovable for the
        // full note). Set the local chainid before any deploy.
        vm.chainId(31337);
        c10 = new MockSPHINCSVerifier();
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        wallet = PQSmartWallet(payable(LibClone.deployERC1967(address(impl))));
        // index 0 = MASTER (bootstrap), index 1 = SLOT0; nextOwnerIndex = 2.
        wallet.initialize(
            abi.encodePacked(MASTER_PK_SEED, MASTER_PK_ROOT),
            abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT)
        );
    }

    /// Lean `OwnerBytes.hasNMaskLayout` / `Factory.nMasked`: the bottom 128 bits
    /// of each 32-byte word are zero (bytes [16..32) and [48..64)).
    function _nMasked64(bytes memory o) internal pure returns (bool) {
        bytes32 seed;
        bytes32 root;
        assembly ("memory-safe") {
            seed := mload(add(o, 32))
            root := mload(add(o, 64))
        }
        return uint128(uint256(seed)) == 0 && uint128(uint256(root)) == 0;
    }

    // ── Rule 1: addOwnerBytes ≡ Lean addOwner-model (length-64 arm) ──────────

    /// **`addOwnerBytes` pointwise (∀ symbolic 64-byte content).** Accepts iff
    /// the Lean model accepts (N-masked ∧ not already an owner); on accept,
    /// installs verbatim at the pre `nextOwnerIndex` and bumps it; existing
    /// owners + counters unmoved on both arms.
    function prove_addOwner_len64_pointwise(bytes calldata newOwner) public {
        vm.assume(newOwner.length == 64);
        bool wantSuccess = _nMasked64(newOwner) && !wallet.isOwnerBytes(newOwner);

        uint256 preNext = wallet.nextOwnerIndex();
        uint256 preRemoved = wallet.removedOwnersCount();
        bytes32 preOwner0 = keccak256(wallet.ownerAtIndex(0));
        bytes32 preOwner1 = keccak256(wallet.ownerAtIndex(1));

        vm.prank(ENTRY_POINT_ADDR);
        try wallet.addOwnerBytes(newOwner) {
            assertTrue(wantSuccess, "A3.4 add: bytecode accepted what the Lean model rejects");
            assertEq(keccak256(wallet.ownerAtIndex(preNext)), keccak256(newOwner),
                "A3.4 add: owner not installed verbatim (read parity)");
            assertEq(wallet.nextOwnerIndex(), preNext + 1, "A3.4 add: nextOwnerIndex");
            assertTrue(wallet.isOwnerBytes(newOwner), "A3.4 add: isOwner not set");
        } catch {
            assertTrue(!wantSuccess, "A3.4 add: bytecode rejected what the Lean model accepts");
            assertEq(wallet.nextOwnerIndex(), preNext, "add fail-path: nextOwnerIndex moved");
        }
        assertEq(keccak256(wallet.ownerAtIndex(0)), preOwner0, "add frame: owner 0");
        assertEq(keccak256(wallet.ownerAtIndex(1)), preOwner1, "add frame: owner 1");
        assertEq(wallet.removedOwnersCount(), preRemoved, "add frame: removedOwnersCount");
    }

    /// **Wrong length is rejected** — the deployed length gate (Lean
    /// `newOwner.size ≠ 64 → none`). Boundary representatives 63 / 65.
    function prove_addOwner_rejects_len63(bytes calldata newOwner) public {
        vm.assume(newOwner.length == 63);
        uint256 preNext = wallet.nextOwnerIndex();
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.addOwnerBytes(newOwner) {
            assertTrue(false, "A3.4 add: accepted a 63-byte owner");
        } catch {
            assertEq(wallet.nextOwnerIndex(), preNext, "add len63: nextOwnerIndex moved");
        }
    }

    function prove_addOwner_rejects_len65(bytes calldata newOwner) public {
        vm.assume(newOwner.length == 65);
        uint256 preNext = wallet.nextOwnerIndex();
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.addOwnerBytes(newOwner) {
            assertTrue(false, "A3.4 add: accepted a 65-byte owner");
        } catch {
            assertEq(wallet.nextOwnerIndex(), preNext, "add len65: nextOwnerIndex moved");
        }
    }

    // ── Rule 2: removeOwnerAtIndex ≡ Lean Storage.removeOwner ────────────────

    /// **`removeOwnerAtIndex(1, expected)` pointwise (∀ symbolic 64-byte
    /// `expected`).** Removes iff `expected` keccak-matches the installed SLOT0
    /// bytes (Lean `decide (o = expected)` under keccak injectivity); on remove,
    /// clears the slot + bumps `removedOwnersCount`; owner 0 + nextOwnerIndex
    /// unmoved on both arms.
    function prove_removeOwner_installed_pointwise(bytes calldata expected) public {
        vm.assume(expected.length == 64);
        bool wantSuccess =
            keccak256(expected) == keccak256(abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT));

        uint256 preRemoved = wallet.removedOwnersCount();
        uint256 preNext = wallet.nextOwnerIndex();
        bytes32 preOwner0 = keccak256(wallet.ownerAtIndex(0));

        vm.prank(ENTRY_POINT_ADDR);
        try wallet.removeOwnerAtIndex(1, expected) {
            assertTrue(wantSuccess, "A3.4 rm: removed with mismatched expected bytes");
            assertEq(wallet.ownerAtIndex(1).length, 0, "A3.4 rm: slot not cleared (read parity)");
            assertTrue(!wallet.isOwnerBytes(expected), "A3.4 rm: isOwner not cleared");
            assertEq(wallet.removedOwnersCount(), preRemoved + 1, "A3.4 rm: removedOwnersCount");
        } catch {
            assertTrue(!wantSuccess, "A3.4 rm: rejected the matching expected bytes");
            assertEq(wallet.ownerAtIndex(1).length, 64, "rm fail-path: owner 1 mutated");
            assertEq(wallet.removedOwnersCount(), preRemoved, "rm fail-path: removedOwnersCount moved");
        }
        assertEq(keccak256(wallet.ownerAtIndex(0)), preOwner0, "rm frame: owner 0");
        assertEq(wallet.nextOwnerIndex(), preNext, "rm frame: nextOwnerIndex");
    }

    /// **Unset indices (∀ index ≥ 2) reject removal** — Lean
    /// `match s.ownerAtIndex index with | none => none`.
    function prove_removeOwner_unset_rejects(uint256 index, bytes calldata expected) public {
        vm.assume(index >= 2);
        vm.assume(expected.length == 64);
        uint256 preRemoved = wallet.removedOwnersCount();
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.removeOwnerAtIndex(index, expected) {
            assertTrue(false, "A3.4 rm: removed from an unset index");
        } catch {
            assertEq(wallet.removedOwnersCount(), preRemoved, "rm unset: removedOwnersCount moved");
        }
    }

    // ── Rule 3: initialize one-shot + fresh-install pointwise ────────────────

    /// **`initialize` on an initialised wallet reverts (∀ args)** — Lean
    /// `tryInitialize`'s `if s.nextOwnerIndex ≠ 0 then none` /
    /// `Invariants.initialize_called_exactly_once`.
    function prove_initialize_one_shot(bytes calldata a, bytes calldata b) public {
        vm.assume(a.length == 64);
        vm.assume(b.length == 64);
        bytes32 preOwner0 = keccak256(wallet.ownerAtIndex(0));
        try wallet.initialize(a, b) {
            assertTrue(false, "Claim 2: re-initialize accepted");
        } catch {
            assertEq(keccak256(wallet.ownerAtIndex(0)), preOwner0, "re-init: owner 0 mutated");
            assertEq(wallet.nextOwnerIndex(), 2, "re-init: nextOwnerIndex moved");
        }
    }

    /// **Fresh-proxy `initialize` ≡ gated `tryInitialize`** (∀ symbolic 64-byte
    /// boot/slot0). Succeeds iff both are N-masked and distinct; installs
    /// verbatim at indices 0 and 1.
    function prove_initialize_fresh_pointwise(bytes calldata boot, bytes calldata slot0) public {
        vm.assume(boot.length == 64);
        vm.assume(slot0.length == 64);
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        PQSmartWallet fresh = PQSmartWallet(payable(LibClone.deployERC1967(address(impl))));

        bool wantSuccess =
            _nMasked64(boot) && _nMasked64(slot0) && keccak256(boot) != keccak256(slot0);

        try fresh.initialize(boot, slot0) {
            assertTrue(wantSuccess, "init: accepted outside the Lean gates");
            assertEq(keccak256(fresh.ownerAtIndex(0)), keccak256(boot), "init: bootstrap not verbatim");
            assertEq(keccak256(fresh.ownerAtIndex(1)), keccak256(slot0), "init: slot0 not verbatim");
            assertEq(fresh.nextOwnerIndex(), 2, "init: nextOwnerIndex != 2");
        } catch {
            assertTrue(!wantSuccess, "init: rejected inside the Lean gates");
            assertEq(fresh.nextOwnerIndex(), 0, "init fail-path: partial install");
        }
    }

    // ── Rule 4: access gates — EntryPoint-only (∀ non-EP caller) ─────────────

    function prove_addOwner_rejects_non_entrypoint(address caller, bytes calldata newOwner) public {
        vm.assume(caller != ENTRY_POINT_ADDR);
        vm.assume(newOwner.length == 64);
        uint256 preNext = wallet.nextOwnerIndex();
        vm.prank(caller);
        try wallet.addOwnerBytes(newOwner) {
            assertTrue(false, "gate: non-EntryPoint addOwnerBytes accepted");
        } catch {
            assertEq(wallet.nextOwnerIndex(), preNext, "gate add: nextOwnerIndex moved");
        }
    }

    function prove_removeOwner_rejects_non_entrypoint(address caller, bytes calldata expected) public {
        vm.assume(caller != ENTRY_POINT_ADDR);
        vm.assume(expected.length == 64);
        uint256 preRemoved = wallet.removedOwnersCount();
        vm.prank(caller);
        try wallet.removeOwnerAtIndex(1, expected) {
            assertTrue(false, "gate: non-EntryPoint removeOwnerAtIndex accepted");
        } catch {
            assertEq(wallet.removedOwnersCount(), preRemoved, "gate rm: removedOwnersCount moved");
        }
    }
}
