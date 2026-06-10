// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../../src/PQSmartWalletFactory.sol";
import {MockSPHINCSVerifier} from "../mocks/MockSPHINCSVerifier.sol";

/// @notice Halmos symbolic-execution rules for
///         `PQSmartWalletFactory.createAccount` — discharges the
///         squat-defence surface of `solidityFactory_compiles_correctly`
///         (A3.3) against the deployed factory runtime bytecode.
///
///         The bootstrap C10 signature is checked by an arbitrary
///         (symbolic-result) verifier, the SAME abstraction the Lean
///         `Factory.createAccountPrecondition` uses. Proves I-8: no proxy
///         is deployed unless the bootstrap signature verifies over the
///         slot-0 squat-defence digest.
///
///         Run: `halmos --contract HalmosFactory`.
contract HalmosFactory is SymTest, Test {
    address internal constant ENTRY_POINT_ADDR = address(0x4337);

    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    PQSmartWalletFactory internal factory;
    MockSPHINCSVerifier internal c10;

    function setUp() public {
        c10 = new MockSPHINCSVerifier();
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        factory = new PQSmartWalletFactory(address(impl), c10);
    }

    /// **I-8 (squat-defence) — `createAccount` succeeds only if the
    /// bootstrap signature verifies.** The verifier's answer is symbolic;
    /// Halmos proves there is no path where a fresh wallet is created while
    /// the verifier rejected the bootstrap sig over `addSlot0Digest`.
    function check_createAccount_requires_bootstrap_sig() public {
        bool verifierResult = svm.createBool("factoryVerifierResult");
        c10.setValid(verifierResult);

        try factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, SLOT0_PK_SEED, SLOT0_PK_ROOT, uint64(block.chainid), hex"aa"
        ) returns (PQSmartWallet) {
            // Deployment + initialize succeeded → the verifier MUST have
            // accepted the bootstrap signature (squat-defence held).
            assertTrue(verifierResult, "I-8 bytecode: createAccount succeeded without bootstrap-sig accept");
        } catch {
            // Reverted (InvalidFactorySignature on a rejecting verifier, or
            // a benign deploy-path revert) — no wallet created.
        }
    }

    /// **Wrong chain id is rejected** (the digest binds `chainId`, and the
    /// guard rejects a mismatched supplied chain).
    function check_createAccount_rejects_wrong_chainid(uint64 chainId) public {
        vm.assume(chainId != block.chainid);
        c10.setValid(true);
        try factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, SLOT0_PK_SEED, SLOT0_PK_ROOT, chainId, hex"aa"
        ) returns (PQSmartWallet) {
            assertTrue(false, "bytecode: createAccount accepted wrong chainId");
        } catch {
            // expected: WrongChainId
        }
    }
}
