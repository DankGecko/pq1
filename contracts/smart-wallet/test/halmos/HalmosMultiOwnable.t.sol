// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {LibClone} from "solady/utils/LibClone.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";
import {HalmosWalletBase} from "./HalmosWalletBase.sol";

/// @notice **Owner-table (PQMultiOwnable) bytecode discharge** — replaces
///         the stale Certora artifacts for bridge axiom A3.4
///         (`solidityMultiOwnable_compiles_correctly`) and supplies the
///         bytecode-level witnesses for the Claim-2 owner-set-integrity
///         theorems (`cannot_remove_bootstrap`, owner-install verbatim,
///         `initialize_called_exactly_once`).
///
///         Discharge map:
///           * **A3.4 (read parity)** — every rule below asserts
///             `ownerAtIndex(i)` returns byte-for-byte what the Lean
///             `Storage.ownerAtIndex` holds after the mirrored mutation
///             (verbatim-install / verbatim-survive / empty-after-remove),
///             with the mutation performed by the REAL deployed mutator
///             bytecode.
///           * **Mutator pointwise equality** — `addOwnerBytes`,
///             `removeOwnerAtIndex`, and `initialize` against the Lean
///             `Storage.addOwner` / `Storage.removeOwner` /
///             `Storage.tryInitialize` (Wallet/Storage.lean), composed with
///             the deployed gates the wallet-boundary models in
///             `Bridge/Refinement.lean` (A3.2-owner axioms) make explicit:
///             EntryPoint caller, 64-byte length, N-mask layout, duplicate
///             rejection. (The Lean `Storage.addOwner` core deliberately
///             models only the duplicate gate; the boundary model
///             `OwnerOps.addOwnerBytesModel` carries the rest — this
///             harness checks the COMPOSITION, which is what the deployed
///             selector dispatches.)
///
///         SYMBOLIC ENVELOPE: owner CONTENT fully symbolic at every length
///         class {0, 32, 63, 64, 65}; the remove index symbolic over the
///         unset partition (>= 2) with the installed indices {0, 1} as the
///         remaining concrete singletons (a symbolic INSTALLED index would
///         make the stored bytes' length path-dependent — the same engine
///         limit the validate-equiv harness documents); callers fully
///         symbolic in the access-gate rules; counters untouched (asserted
///         in the frames).
///
///         Run: `make -C contracts/verification verify-bytecode`.
contract HalmosMultiOwnable is HalmosWalletBase {
    function setUp() public {
        wallet = _deployWalletSha256Free();
        // Owners installed: index 0 = MASTER (bootstrap), index 1 = SLOT0.
        // nextOwnerIndex = 2; indices >= 2 unset.
    }

    function _ownerSweep(uint256 lenSel, string memory tag) internal view returns (bytes memory) {
        vm.assume(lenSel < 5);
        if (lenSel == 0) return new bytes(0);
        if (lenSel == 1) return svm.createBytes(32, string.concat(tag, "32"));
        if (lenSel == 2) return svm.createBytes(63, string.concat(tag, "63"));
        if (lenSel == 3) return svm.createBytes(64, string.concat(tag, "64"));
        return svm.createBytes(65, string.concat(tag, "65"));
    }

    /// Lean `OwnerBytes.hasNMaskLayout` (Storage.lean:35-38) /
    /// `Factory.nMasked`: bytes [16..32) and [48..64) zero — i.e. the
    /// bottom 128 bits of both words.
    function _nMasked64(bytes memory o) internal pure returns (bool) {
        bytes32 seed;
        bytes32 root;
        assembly ("memory-safe") {
            seed := mload(add(o, 32))
            root := mload(add(o, 64))
        }
        return uint128(uint256(seed)) == 0 && uint128(uint256(root)) == 0;
    }

    // ──────────────────────────────────────────────────────────────────
    // Rule 1 — addOwnerBytes pointwise vs the Lean boundary model.
    // ──────────────────────────────────────────────────────────────────

    /// **`addOwnerBytes` ≡ OwnerOps.addOwnerBytesModel** (caller = EP arm;
    /// the caller gate is Rule 4). Lean clauses cited inline.
    function check_addOwnerBytes_pointwise_equals_lean_model(uint256 lenSel) public {
        bytes memory newOwner = _ownerSweep(lenSel, "ao");

        // Lean `OwnerOps.addOwnerBytesModel` (Bridge boundary model):
        //   if newOwner.size ≠ 64 → none
        //   if ¬nMaskedB o → none
        //   Storage.addOwner: if s.isOwner o → none, else install at
        //   nextOwnerIndex, bump nextOwnerIndex.
        bool wantSuccess = newOwner.length == 64 && _nMasked64(newOwner)
            && !wallet.isOwnerBytes(newOwner);

        uint256 preNext = wallet.nextOwnerIndex();
        uint256 preRemoved = wallet.removedOwnersCount();
        bytes32 preOwner0 = keccak256(wallet.ownerAtIndex(0));
        bytes32 preOwner1 = keccak256(wallet.ownerAtIndex(1));
        uint256 preBoot = wallet.bootstrapUses();

        vm.prank(ENTRY_POINT_ADDR);
        try wallet.addOwnerBytes(newOwner) {
            assertTrue(wantSuccess, "A3.4 add: bytecode accepted what the Lean model rejects");
            // Lean post-state: installed verbatim at the pre nextOwnerIndex.
            assertEq(
                keccak256(wallet.ownerAtIndex(preNext)),
                keccak256(newOwner),
                "A3.4 add: owner bytes not installed verbatim (read parity)"
            );
            assertEq(wallet.nextOwnerIndex(), preNext + 1, "A3.4 add: nextOwnerIndex");
            assertTrue(wallet.isOwnerBytes(newOwner), "A3.4 add: isOwner not set");
        } catch {
            assertTrue(!wantSuccess, "A3.4 add: bytecode rejected what the Lean model accepts");
            assertEq(wallet.nextOwnerIndex(), preNext, "add fail-path: nextOwnerIndex moved");
        }
        // Frame (both arms): existing owners, removal count, counters.
        assertEq(keccak256(wallet.ownerAtIndex(0)), preOwner0, "add frame: owner 0");
        assertEq(keccak256(wallet.ownerAtIndex(1)), preOwner1, "add frame: owner 1");
        assertEq(wallet.removedOwnersCount(), preRemoved, "add frame: removedOwnersCount");
        assertEq(wallet.bootstrapUses(), preBoot, "add frame: bootstrapUses");
    }

    // ──────────────────────────────────────────────────────────────────
    // Rule 2 — removeOwnerAtIndex pointwise vs Lean Storage.removeOwner.
    // ──────────────────────────────────────────────────────────────────

    /// **`removeOwnerAtIndex` ≡ Storage.removeOwner** over the installed
    /// index 1 with fully symbolic `expected` bytes (the keccak comparison
    /// in the bytecode ⟺ the Lean `decide (o = expected)` under keccak
    /// injectivity), plus Lean's index-0 and unset arms in Rule 2b/2c.
    function check_removeOwner_installed_pointwise(uint256 lenSel) public {
        bytes memory expected = _ownerSweep(lenSel, "rm");

        // Lean `Storage.removeOwner s 1 expected` (Storage.lean:116-128):
        //   index ≠ 0 ✓; ownerAtIndex 1 = some SLOT0 ✓;
        //   `if decide (o = expected) = false then none`.
        bool wantSuccess =
            keccak256(expected) == keccak256(abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT));

        uint256 preRemoved = wallet.removedOwnersCount();
        uint256 preNext = wallet.nextOwnerIndex();
        bytes32 preOwner0 = keccak256(wallet.ownerAtIndex(0));

        vm.prank(ENTRY_POINT_ADDR);
        try wallet.removeOwnerAtIndex(1, expected) {
            assertTrue(wantSuccess, "A3.4 rm: removed with mismatched expected bytes");
            // Lean post-state: ownerAtIndex 1 := none; isOwner cleared;
            // removedOwnersCount + 1.
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

    /// **Bootstrap is unremovable on the bytecode** — Lean
    /// `Storage.removeOwner`'s `if index = 0 then none` arm /
    /// `Invariants.cannot_remove_bootstrap`, for EVERY expected-bytes value
    /// including the exact installed bootstrap bytes.
    function check_removeOwner_bootstrap_unremovable(bool exactBytes) public {
        bytes memory expected = exactBytes
            ? abi.encodePacked(MASTER_PK_SEED, MASTER_PK_ROOT)
            : _ownerSweep(3, "rb");
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.removeOwnerAtIndex(0, expected) {
            assertTrue(false, "Claim 2: bootstrap key removed");
        } catch {
            assertEq(wallet.ownerAtIndex(0).length, 64, "bootstrap survived check");
        }
    }

    /// **Unset indices reject removal, for EVERY index >= 2** (the Lean
    /// `match s.ownerAtIndex index with | none => none` arm; symbolic
    /// index over the entire unset partition — installed {0, 1} are the
    /// concrete singletons of the other rules).
    function check_removeOwner_unset_index_rejects(uint256 index) public {
        vm.assume(index >= 2);
        uint256 preRemoved = wallet.removedOwnersCount();
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.removeOwnerAtIndex(index, _ownerSweep(3, "ru")) {
            assertTrue(false, "A3.4 rm: removed from an unset index");
        } catch {
            assertEq(wallet.removedOwnersCount(), preRemoved, "rm unset: removedOwnersCount moved");
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Rule 3 — initialize: one-shot + gated verbatim install.
    // ──────────────────────────────────────────────────────────────────

    /// **`initialize` on an initialised wallet reverts for ALL arguments**
    /// — Lean `Storage.tryInitialize`'s `if s.nextOwnerIndex ≠ 0 then none`
    /// arm / `Invariants.initialize_called_exactly_once` on the bytecode.
    function check_initialize_one_shot(uint256 lenSelA, uint256 lenSelB) public {
        bytes32 preOwner0 = keccak256(wallet.ownerAtIndex(0));
        try wallet.initialize(_ownerSweep(lenSelA, "i0"), _ownerSweep(lenSelB, "i1")) {
            assertTrue(false, "Claim 2: re-initialize accepted");
        } catch {
            assertEq(keccak256(wallet.ownerAtIndex(0)), preOwner0, "re-init: owner 0 mutated");
            assertEq(wallet.nextOwnerIndex(), 2, "re-init: nextOwnerIndex moved");
        }
    }

    /// **Fresh-proxy `initialize` ≡ gated Storage.tryInitialize** over
    /// fully symbolic 64-byte owner contents: succeeds iff both owners are
    /// N-masked and distinct (the `_initializeOwners` →
    /// `_addOwnerAtIndex` gates mirrored by the Lean factory
    /// precondition's install-time conjuncts), installing verbatim at
    /// indices 0 and 1.
    function check_initialize_fresh_pointwise() public {
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        PQSmartWallet fresh = PQSmartWallet(payable(LibClone.deployERC1967(address(impl))));

        bytes memory boot = svm.createBytes(64, "fiBoot");
        bytes memory slot0 = svm.createBytes(64, "fiSlot0");

        // Lean: tryInitialize (nextOwnerIndex = 0 ✓ fresh) + the install
        // gates: nMasked(boot) ∧ nMasked(slot0) ∧ slot0 ≠ boot.
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

    // ──────────────────────────────────────────────────────────────────
    // Rule 4 — access gates: EntryPoint-only, for EVERY caller.
    // ──────────────────────────────────────────────────────────────────

    function check_owner_mutators_reject_non_entrypoint(address caller, bool which) public {
        vm.assume(caller != ENTRY_POINT_ADDR);
        vm.prank(caller);
        if (which) {
            try wallet.addOwnerBytes(_ownerSweep(3, "ne")) {
                assertTrue(false, "gate: non-EntryPoint addOwnerBytes accepted");
            } catch {}
        } else {
            try wallet.removeOwnerAtIndex(1, _ownerSweep(3, "nr")) {
                assertTrue(false, "gate: non-EntryPoint removeOwnerAtIndex accepted");
            } catch {}
        }
    }
}
