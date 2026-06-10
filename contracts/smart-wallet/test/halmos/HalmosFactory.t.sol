// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../../src/PQSmartWalletFactory.sol";
import {MockSPHINCSVerifier} from "../mocks/MockSPHINCSVerifier.sol";
import {OracleSPHINCSVerifier} from "./OracleSPHINCSVerifier.sol";

/// @notice Halmos rules for `PQSmartWalletFactory.createAccount` — the
///         bytecode-level discharge of bridge axiom A3.3
///         (`solidityFactory_compiles_correctly`), stated as the BICONDITIONAL
///         the axiom names: `createAccount` succeeds **iff** the Lean
///         `Factory.createAccountPrecondition` holds (right chain, and the
///         verifier accepts the bootstrap signature over `addSlot0Digest`),
///         plus the success-path postconditions (deployment at the predicted
///         CREATE2 address, owners installed exactly as supplied).
///
///         SYMBOLIC ENVELOPE — stated exactly: in the central iff rule,
///         chainId and every factory-signature byte (incl. the empty/4008
///         length shapes) are fully symbolic; the verifier is the GENERIC
///         (input-dependent uninterpreted) `OracleSPHINCSVerifier`, so the
///         digest preimage and signature bytes handed to the verifier are
///         bound byte-for-byte. BOTH key pairs are CONCRETE in the iff
///         rule: the master halves because they determine the CREATE2 salt
///         (a symbolic salt makes the deploy address symbolic —
///         `NotConcreteError`), and the slot-0 halves because a symbolic
///         owner half makes the engine havoc the proxy's owner storage on
///         the phantom already-deployed CREATE2 fork. The key-dependent
///         precondition conjuncts (N-mask × 2, duplicate) are instead each
///         witnessed by a dedicated reject rule below, and the slot-0
///         halves ARE fully symbolic in the already-deployed rule (where
///         no deploy fork exists). The iff over the key space is therefore
///         concrete-point + per-conjunct witnesses, NOT a symbolic ∀ —
///         the honest residual of A3.3's discharge.
///
///         Run: `make -C contracts/verification verify-bytecode`.
contract HalmosFactory is SymTest, Test {
    address internal constant ENTRY_POINT_ADDR = address(0x4337);

    PQSmartWalletFactory internal factory;
    OracleSPHINCSVerifier internal oracle;

    PQSmartWalletFactory internal factoryMock;
    MockSPHINCSVerifier internal mock;

    function setUp() public {
        oracle = new OracleSPHINCSVerifier();
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), oracle);
        factory = new PQSmartWalletFactory(address(impl), oracle);

        mock = new MockSPHINCSVerifier();
        PQSmartWallet implM = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), mock);
        factoryMock = new PQSmartWalletFactory(address(implM), mock);

        // NB: SHA-256 (`0x02`) is left as the patched uninterpreted
        // function — the honest A1 boundary, exactly as the wallet
        // equivalence harness treats it. The salt (`sha256` of 64 bytes)
        // and squat digest (`sha256` of 98 bytes) are non-empty, so the
        // empty-input case never arises here, and Halmos deploys the
        // proxy on the fresh CREATE2 arm.
    }

    // Concrete N-masked bootstrap key. CONCRETE on purpose: the CREATE2
    // salt is `sha256(masterPkSeed‖masterPkRoot)` and SHA-256 is an
    // uninterpreted function in Halmos, so a symbolic master would make
    // the deploy address symbolic and `createDeterministicERC1967` fork
    // on its `extcodesize` probe (havocing a phantom already-deployed
    // wallet). A concrete master pins the salt to a single fixed term, so
    // the proxy deploys on the fresh CREATE2 arm with no spurious fork —
    // exactly as the slot-0 keys (which never enter the salt) stay
    // symbolic. The non-N-masked-master reject is a separate concern
    // (`check_createAccount_rejects_non_nmasked_master`).
    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    // Concrete N-masked slot-0 key, distinct from the master. Kept
    // concrete in the iff rule for the same reason as the master: a
    // SYMBOLIC owner half makes Halmos havoc the proxy's owner storage on
    // the (phantom) already-deployed CREATE2 fork, which no post-state
    // gate can soundly exclude. The mask / duplicate conjuncts of the
    // precondition are instead each witnessed false by a dedicated
    // concrete reject rule below.
    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    /// @dev Lean `Factory.nMasked`: bottom 16 bytes of the half are zero.
    function _nMasked(bytes32 half) internal pure returns (bool) {
        return uint128(uint256(half)) == 0;
    }

    // ──────────────────────────────────────────────────────────────────
    // A3.3 as an iff — fresh-deploy arm.
    // ──────────────────────────────────────────────────────────────────

    /// **`createAccount` succeeds ⟺ Lean `createAccountPrecondition`.**
    /// With concrete N-masked-and-distinct keys, the mask + duplicate
    /// conjuncts hold by construction (and the proxy's owner storage is
    /// never havoc'd on the phantom already-deployed CREATE2 fork), so the
    /// precondition reduces to `chainOk ∧ verifierAccepts`. chainId, the
    /// empty/non-empty signature shape, and every signature byte are
    /// symbolic, so this rule proves the full iff plus the deploy
    /// postconditions over ALL chains and ALL signatures. The mask and
    /// duplicate conjuncts are each witnessed false by a dedicated
    /// concrete reject rule below.
    function check_createAccount_iff_lean_precondition(uint64 chainId, bool sigEmpty) public {
        bytes32 ms = MASTER_PK_SEED;
        bytes32 mr = MASTER_PK_ROOT;
        bytes32 s0s = SLOT0_PK_SEED;
        bytes32 s0r = SLOT0_PK_ROOT;
        bytes memory factorySig = sigEmpty ? new bytes(0) : svm.createBytes(4008, "factorySig");

        // The Lean `createAccountPrecondition` on the SAME uninterpreted
        // verifier instance (identical argument bytes => identical answer
        // term, by congruence). Mask + distinct hold by the concrete key
        // choice; the residual content is chain ∧ verifier.
        bytes32 digest = factory.addSlot0Digest(chainId, s0s, s0r);
        bool verifierAccepts = oracle.verify(ms, mr, digest, factorySig);
        bool chainOk = chainId == uint64(block.chainid);
        bool precondition = chainOk && verifierAccepts;

        address predicted = factory.getAddress(ms, mr);

        try factory.createAccount(ms, mr, s0s, s0r, chainId, factorySig)
        returns (PQSmartWallet acct) {
            // success ⇒ precondition + postconditions. Concrete keys mean
            // no owner-storage havoc, so the early-return fork cannot fake
            // a fresh result here.
            assertTrue(precondition, "A3.3: createAccount succeeded outside the Lean precondition");
            assertEq(address(acct), predicted, "A3.3: deployed off the predicted CREATE2 address");
            assertEq(
                keccak256(acct.ownerAtIndex(0)),
                keccak256(abi.encodePacked(ms, mr)),
                "A3.3: bootstrap owner bytes not installed verbatim"
            );
            assertEq(
                keccak256(acct.ownerAtIndex(1)),
                keccak256(abi.encodePacked(s0s, s0r)),
                "A3.3: slot-0 owner bytes not installed verbatim"
            );
            assertEq(acct.nextOwnerIndex(), 2, "A3.3: unexpected owner count after init");
        } catch {
            // failure ⇒ ¬precondition.
            assertTrue(!precondition, "A3.3: reverted despite the Lean precondition");
        }
    }

    /// **Non-N-masked slot-0 key ⇒ no deploy** (the slot-0 side
    /// `InvalidNMaskLayout` conjunct). Concrete keys (master valid, slot-0
    /// seed contaminated), verifier forced to accept, right chain — must
    /// still revert.
    function check_createAccount_rejects_non_nmasked_slot0() public {
        bytes32 badS0s = bytes32((uint256(0xcccc) << 240) | 1);
        mock.setValid(true);
        try factoryMock.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, badS0s, SLOT0_PK_ROOT,
            uint64(block.chainid), svm.createBytes(4008, "sigNS")
        ) returns (PQSmartWallet) {
            assertTrue(false, "A3.3: deployed with a non-N-masked slot-0 key");
        } catch {
            // expected: InvalidNMaskLayout
        }
    }

    /// **Duplicate slot-0 (slot-0 bytes == bootstrap bytes) ⇒ no deploy**
    /// (the `¬(slot0 = master)` conjunct). Concrete keys, verifier accepts,
    /// right chain — must revert at the second `_addOwner` (AlreadyOwner).
    function check_createAccount_rejects_duplicate_slot0() public {
        mock.setValid(true);
        try factoryMock.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, MASTER_PK_SEED, MASTER_PK_ROOT,
            uint64(block.chainid), svm.createBytes(4008, "sigDup")
        ) returns (PQSmartWallet) {
            assertTrue(false, "A3.3: deployed with slot-0 == bootstrap");
        } catch {
            // expected: AlreadyOwner
        }
    }
    /// **Non-N-masked bootstrap key ⇒ no deploy** (the master-side
    /// `InvalidNMaskLayout` conjunct of the precondition). Master halves
    /// are concrete (so the salt stays a fixed term, no deploy fork) but
    /// chosen non-N-masked; with the verifier forced to accept and the
    /// right chain, `createAccount` must still revert — the Lean
    /// precondition's `nMasked masterPkSeed ∧ nMasked masterPkRoot`
    /// conjuncts, witnessed false. Uses the mock verifier so "accepts" is
    /// unconditional.
    function check_createAccount_rejects_non_nmasked_master(
        bytes32 slot0PkSeed,
        bytes32 slot0PkRoot
    ) public {
        // bottom-128-bit contamination on the seed ⇒ not N-masked.
        bytes32 badMs = bytes32((uint256(0xaaaa) << 240) | 1);
        bytes32 mr = MASTER_PK_ROOT;
        mock.setValid(true);

        try factoryMock.createAccount(
            badMs, mr, slot0PkSeed, slot0PkRoot, uint64(block.chainid), svm.createBytes(4008, "sigNM")
        ) returns (PQSmartWallet) {
            assertTrue(false, "A3.3: deployed a wallet with a non-N-masked bootstrap key");
        } catch {
            // expected: InvalidNMaskLayout at initialize
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Already-deployed arm: the early return must hand back the existing
    // wallet untouched, for EVERY later argument tuple.
    // ──────────────────────────────────────────────────────────────────

    /// **Re-`createAccount` on a deployed wallet returns it unmodified ⟺
    /// the chain id is right** — regardless of the new slot-0 halves, the
    /// new signature, or the verifier's answer (the early-return arm never
    /// consults the verifier).
    function check_createAccount_already_deployed_returns_existing(
        uint64 chainId2,
        bytes32 s0s2,
        bytes32 s0r2,
        bool verdict2
    ) public {
        bytes32 ms = bytes32(uint256(0xaaaa) << 240);
        bytes32 mr = bytes32(uint256(0xbbbb) << 240);
        bytes32 s0s1 = bytes32(uint256(0xcccc) << 240);
        bytes32 s0r1 = bytes32(uint256(0xdddd) << 240);

        mock.setValid(true);
        PQSmartWallet first = factoryMock.createAccount(
            ms, mr, s0s1, s0r1, uint64(block.chainid), svm.createBytes(4008, "sig1")
        );
        bytes32 owner0 = keccak256(first.ownerAtIndex(0));
        bytes32 owner1 = keccak256(first.ownerAtIndex(1));

        mock.setValid(verdict2);
        try factoryMock.createAccount(ms, mr, s0s2, s0r2, chainId2, svm.createBytes(4008, "sig2"))
        returns (PQSmartWallet second) {
            assertEq(chainId2, uint64(block.chainid), "already-deployed: wrong chain accepted");
            assertEq(address(second), address(first), "already-deployed: different address");
            assertEq(keccak256(first.ownerAtIndex(0)), owner0, "already-deployed: owner 0 mutated");
            assertEq(keccak256(first.ownerAtIndex(1)), owner1, "already-deployed: owner 1 mutated");
            assertEq(first.nextOwnerIndex(), 2, "already-deployed: owner count changed");
        } catch {
            // Only the chain-id guard sits before the early return.
            assertTrue(chainId2 != uint64(block.chainid), "already-deployed: spurious revert");
        }
    }
}
