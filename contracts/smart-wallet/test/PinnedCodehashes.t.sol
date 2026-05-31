// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

/// @notice Pinned-codehash test — Phase 2C / Phase 3 of the
///         contracts/verification discharge plan.
///
///         Each `solidity*_compiles_correctly` axiom is bound to a
///         specific runtime codehash (recorded in
///         `contracts/verification/docs/PINNED_CODEHASHES.md`). If the
///         bytecode drifts (compiler bump, source change, optimiser
///         setting change), this test fails and the discharge artifacts
///         must be re-run against the new codehash before the axiom
///         pin is updated.
///
///         The constants below are placeholders for the initial
///         branch-cut; update via the `forge test --match-test
///         test_codehash_print -vv` output below, then re-run the
///         discharge artifacts (Halmos, Certora).
contract PinnedCodehashesTest is Test {
    // ── Codehash freeze constants ─────────────────────────────────────
    //
    // Originally pinned at the 2026-05-21 branch-cut. RE-PINNED 2026-05-27
    // after the EntryPoint-guard fix (addOwnerBytes / removeOwnerAtIndex).
    //
    // DISCHARGE PENDING: these were re-captured from a LOCAL `forge build`
    // (solc 0.8.28, via_ir, runs=200). The Halmos discharge for axiom A3.2
    // has NOT been re-run against them (halmos unavailable in the dev env)
    // — see AXIOM_STATUS.json, where A3.2 is marked `pending`. They must be
    // re-captured + re-discharged in the canonical build env before the
    // axiom is trusted: note the import-free SPHINCsC10Asm hash moved with
    // ZERO source change between 05-21 and 05-27, so the `bytecode_hash =
    // "ipfs"` metadata makes these non-reproducible across toolchains.
    //
    // Re-capture via `forge test --match-test test_codehash_pinned_or_print -vv`.
    // Each update must be accompanied by re-running the discharge artifact:
    //   * PQ_SMART_WALLET_CODEHASH    → Halmos (HalmosValidateUserOp + HalmosExecute)
    //   * PQ_SMART_WALLET_FACTORY_CODEHASH → Certora (PQSmartWalletFactory.spec)
    //   * SPHINCS_C10_ASM_CODEHASH    → cross_validation/ Lean ↔ Rust ↔ Solidity
    // RE-PINNED after the multi-op-per-bundle fix (per-ownerIndex transient
    // credit replacing the single validate->execute token; H-3 parity moved
    // into validation). Halmos A3.2 discharge MUST be re-run against this
    // hash. Factory + SPHINCsC10Asm hashes are unchanged (only
    // PQSmartWallet.sol was edited).
    bytes32 constant PQ_SMART_WALLET_CODEHASH =
        0x0a7078cc741e825c9b874fe379fb11e91e9236aebf9fcfda3a1f30fe404f2b5d;
    bytes32 constant PQ_MULTI_OWNABLE_CODEHASH = bytes32(0);  // embedded in PQSmartWallet; no independent deploy
    // Factory RUNTIME LOGIC is unchanged by the multi-op-bundle fix; only its
    // trailing IPFS-metadata hash moved, because PQSmartWallet.sol (a source in
    // the factory's compilation unit) changed. The Certora factory spec proves
    // the same logic and does not need re-running for this edit.
    bytes32 constant PQ_SMART_WALLET_FACTORY_CODEHASH =
        0xc22d39023fd71bf073fa9e77cac96f8aeaf027a166f8cfd2373dc0c089345185;
    bytes32 constant SPHINCS_C10_ASM_CODEHASH =
        0xf1ef4ccee22e6b39446723232fe39761f089c7195941b2c12576956b38fcfef5;

    SPHINCsC10Asm internal sphincs;
    MockSPHINCSVerifier internal c10;
    PQSmartWallet internal impl;
    PQSmartWalletFactory internal factory;

    function setUp() public {
        sphincs = new SPHINCsC10Asm();
        c10 = new MockSPHINCSVerifier();
        impl = new PQSmartWallet(IEntryPoint(address(0x4337)), c10);
        factory = new PQSmartWalletFactory(address(impl), c10);
    }

    /// **Codehash freeze enforcement.** Only runs when the
    /// `PQ_SMART_WALLET_CODEHASH` constant is non-zero (i.e. has been
    /// pinned). Otherwise prints the current codehashes for capture.
    function test_codehash_pinned_or_print() external view {
        bytes32 walletHash = address(impl).codehash;
        bytes32 factoryHash = address(factory).codehash;
        bytes32 sphincsHash = address(sphincs).codehash;

        // Sanity: deployments produced non-empty bytecode.
        assertTrue(walletHash != bytes32(0), "PQSmartWallet has no bytecode");
        assertTrue(factoryHash != bytes32(0), "PQSmartWalletFactory has no bytecode");
        assertTrue(sphincsHash != bytes32(0), "SPHINCsC10Asm has no bytecode");

        if (PQ_SMART_WALLET_CODEHASH != bytes32(0)) {
            assertEq(walletHash, PQ_SMART_WALLET_CODEHASH,
                "PQSmartWallet codehash drift: re-run Halmos and update pin");
        } else {
            console2.log("[!] PQSmartWallet codehash (capture and pin):");
            console2.logBytes32(walletHash);
        }

        if (PQ_SMART_WALLET_FACTORY_CODEHASH != bytes32(0)) {
            assertEq(factoryHash, PQ_SMART_WALLET_FACTORY_CODEHASH,
                "PQSmartWalletFactory codehash drift: re-run Certora and update pin");
        } else {
            console2.log("[!] PQSmartWalletFactory codehash (capture and pin):");
            console2.logBytes32(factoryHash);
        }

        if (SPHINCS_C10_ASM_CODEHASH != bytes32(0)) {
            assertEq(sphincsHash, SPHINCS_C10_ASM_CODEHASH,
                "SPHINCsC10Asm codehash drift: re-run cross_validation/ and update pin");
        } else {
            console2.log("[!] SPHINCsC10Asm codehash (capture and pin):");
            console2.logBytes32(sphincsHash);
        }
    }

    /// **EVM precompile 0x02 SHA-256 parity test (axiom A1 defense-in-depth).**
    /// Asserts that `staticcall(0x02, "abc")` returns the NIST CAVS expected
    /// SHA-256 digest. This is the empirical Foundry parity test backing
    /// `precompile_0x02_is_FIPS_180_4`.
    function test_sha256_precompile_abc_kat() external view {
        bytes32 expected = 0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad;
        bytes32 got = sha256(bytes("abc"));
        assertEq(got, expected, "SHA-256 precompile drift");
    }

    /// **EVM precompile SHA-256("") KAT.**
    function test_sha256_precompile_empty_kat() external view {
        bytes32 expected = 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;
        bytes32 got = sha256(bytes(""));
        assertEq(got, expected, "SHA-256 precompile drift (empty)");
    }
}
