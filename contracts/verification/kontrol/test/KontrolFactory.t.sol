// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";

import {PQSmartWallet} from "../../../smart-wallet/src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../../../smart-wallet/src/PQSmartWalletFactory.sol";
import {MockSPHINCSVerifier} from "../../../smart-wallet/test/mocks/MockSPHINCSVerifier.sol";

/// @notice **A3.3 (factory) — Kontrol/KEVM port.** Proves
///         `PQSmartWalletFactory.createAccount` DIRECTLY on the deployed
///         bytecode (KEVM symbolic execution), an engine independent of Halmos
///         with NO hand-written model mirror — the transcription-free discharge
///         of bridge axiom A3.3 (`solidityFactory_compiles_correctly`). Mirrors
///         `test/halmos/HalmosFactory.t.sol`, stated as the BICONDITIONAL the
///         axiom names: `createAccount` succeeds IFF the Lean
///         `Factory.createAccountPrecondition` holds (right chain ∧ verifier
///         accepts the bootstrap sig over `addSlot0Digest` ∧ N-masked ∧
///         distinct), plus the deploy postconditions, plus the already-deployed
///         early-return.
///
///         SYMBOLIC ENVELOPE — stated exactly:
///          * iff rule: chainId + the verifier's answer are SYMBOLIC; both key
///            pairs are CONCRETE (N-masked, distinct). The master halves must
///            be concrete because the CREATE2 salt is `sha256(master‖master)` —
///            a symbolic salt makes the deploy address symbolic. The mask /
///            duplicate precondition conjuncts are each witnessed false by a
///            dedicated concrete reject rule.
///          * The verifier is the `MockSPHINCSVerifier` with a SYMBOLIC
///            `valid` (set from a symbolic `verdict` arg) — a symbolic-but-
///            deterministic verifier answer, which is what the factory's
///            control-flow iff needs. (Kontrol has no `svm`/Oracle equivalent
///            of the Halmos input-dependent verifier; the digest's *byte
///            binding* to `addSlot0Digest` is a separate squat-defence concern
///            carried by the Lean `factory_requires_bootstrap_sig` — the CODE
///            still computes + passes the real digest, KEVM just runs it.)
contract KontrolFactory is Test {
    address internal constant ENTRY_POINT_ADDR = address(0x4337);

    // Concrete N-masked keys (bottom 16 bytes zero), master ≠ slot0.
    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    PQSmartWalletFactory internal factory;
    MockSPHINCSVerifier internal mock;

    function setUp() public {
        vm.chainId(31337); // KEVM default chainid is 1; mock M14 guard is local-only.
        mock = new MockSPHINCSVerifier();
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), mock);
        factory = new PQSmartWalletFactory(address(impl), mock);
    }

    // ── The central iff (fresh-deploy arm) ──────────────────────────────────

    /// **`createAccount` succeeds ⟺ Lean `createAccountPrecondition`.** Concrete
    /// N-masked + distinct keys ⇒ the mask/duplicate conjuncts hold by
    /// construction, so the precondition reduces to `chainOk ∧ verifierAccepts`,
    /// both symbolic. On success the proxy deploys at the predicted CREATE2
    /// address with bootstrap + slot-0 installed verbatim.
    function prove_createAccount_iff(uint64 chainId, bool verdict) public {
        bytes32 ms = MASTER_PK_SEED;
        bytes32 mr = MASTER_PK_ROOT;
        bytes32 s0s = SLOT0_PK_SEED;
        bytes32 s0r = SLOT0_PK_ROOT;
        mock.setValid(verdict);

        bool precondition = (chainId == uint64(block.chainid)) && verdict;
        address predicted = factory.getAddress(ms, mr);

        try factory.createAccount(ms, mr, s0s, s0r, chainId, "") returns (PQSmartWallet acct) {
            assertTrue(precondition, "A3.3: createAccount succeeded outside the Lean precondition");
            assertEq(address(acct), predicted, "A3.3: deployed off the predicted CREATE2 address");
            assertEq(keccak256(acct.ownerAtIndex(0)), keccak256(abi.encodePacked(ms, mr)),
                "A3.3: bootstrap owner not installed verbatim");
            assertEq(keccak256(acct.ownerAtIndex(1)), keccak256(abi.encodePacked(s0s, s0r)),
                "A3.3: slot-0 owner not installed verbatim");
            assertEq(acct.nextOwnerIndex(), 2, "A3.3: unexpected owner count after init");
        } catch {
            assertTrue(!precondition, "A3.3: reverted despite the Lean precondition");
        }
    }

    // ── Per-conjunct reject witnesses (verifier forced to accept, right chain) ─

    /// Non-N-masked slot-0 key ⇒ no deploy (slot-0 `InvalidNMaskLayout`).
    function prove_createAccount_rejects_non_nmasked_slot0() public {
        bytes32 badS0s = bytes32((uint256(0xcccc) << 240) | 1); // bottom bit set ⇒ not N-masked
        mock.setValid(true);
        try factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, badS0s, SLOT0_PK_ROOT, uint64(block.chainid), ""
        ) returns (PQSmartWallet) {
            assertTrue(false, "A3.3: deployed with a non-N-masked slot-0 key");
        } catch {}
    }

    /// Non-N-masked bootstrap key ⇒ no deploy (master `InvalidNMaskLayout`).
    /// Master halves concrete (salt stays a fixed term) but bottom-bit
    /// contaminated; verifier accepts, right chain — must still revert.
    function prove_createAccount_rejects_non_nmasked_master() public {
        bytes32 badMs = bytes32((uint256(0xaaaa) << 240) | 1);
        mock.setValid(true);
        try factory.createAccount(
            badMs, MASTER_PK_ROOT, SLOT0_PK_SEED, SLOT0_PK_ROOT, uint64(block.chainid), ""
        ) returns (PQSmartWallet) {
            assertTrue(false, "A3.3: deployed with a non-N-masked bootstrap key");
        } catch {}
    }

    /// Duplicate slot-0 (slot-0 bytes == bootstrap bytes) ⇒ no deploy
    /// (the `¬(slot0 = master)` conjunct; reverts at the second _addOwner).
    function prove_createAccount_rejects_duplicate_slot0() public {
        mock.setValid(true);
        try factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, MASTER_PK_SEED, MASTER_PK_ROOT, uint64(block.chainid), ""
        ) returns (PQSmartWallet) {
            assertTrue(false, "A3.3: deployed with slot-0 == bootstrap");
        } catch {}
    }

    /// Wrong chain id ⇒ revert (the `chainOk` conjunct), ∀ symbolic chainId ≠ local.
    function prove_createAccount_rejects_wrong_chain(uint64 chainId) public {
        vm.assume(chainId != uint64(block.chainid));
        mock.setValid(true);
        try factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, SLOT0_PK_SEED, SLOT0_PK_ROOT, chainId, ""
        ) returns (PQSmartWallet) {
            assertTrue(false, "A3.3: deployed on the wrong chain");
        } catch {}
    }

    // ── Already-deployed early-return arm ────────────────────────────────────

    /// **Re-`createAccount` on a deployed wallet returns it unmodified ⟺ the
    /// chain id is right** — regardless of the new slot-0 halves or the
    /// verifier's answer (the early-return never consults the verifier).
    function prove_createAccount_already_deployed_returns_existing(
        uint64 chainId2, bytes32 s0s2, bytes32 s0r2, bool verdict2
    ) public {
        bytes32 ms = MASTER_PK_SEED;
        bytes32 mr = MASTER_PK_ROOT;
        mock.setValid(true);
        PQSmartWallet first =
            factory.createAccount(ms, mr, SLOT0_PK_SEED, SLOT0_PK_ROOT, uint64(block.chainid), "");
        bytes32 owner0 = keccak256(first.ownerAtIndex(0));
        bytes32 owner1 = keccak256(first.ownerAtIndex(1));

        mock.setValid(verdict2);
        try factory.createAccount(ms, mr, s0s2, s0r2, chainId2, "") returns (PQSmartWallet second) {
            assertEq(chainId2, uint64(block.chainid), "already-deployed: wrong chain accepted");
            assertEq(address(second), address(first), "already-deployed: different address");
            assertEq(keccak256(first.ownerAtIndex(0)), owner0, "already-deployed: owner 0 mutated");
            assertEq(keccak256(first.ownerAtIndex(1)), owner1, "already-deployed: owner 1 mutated");
            assertEq(first.nextOwnerIndex(), 2, "already-deployed: owner count changed");
        } catch {
            assertTrue(chainId2 != uint64(block.chainid), "already-deployed: spurious revert");
        }
    }
}
