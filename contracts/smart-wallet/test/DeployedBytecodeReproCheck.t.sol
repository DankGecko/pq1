// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";
import {ISPHINCSVerifier} from "../src/verifiers/ISPHINCSVerifier.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";

/// @notice **Deployed-bytecode reproducibility check (Base Mainnet).**
///
///         Proves that the live Base Mainnet wallet impl, factory, and
///         verifier are *byte-for-byte reproducible* from this repo's
///         pinned source + `foundry.lock` lib set — including the deployed
///         **addresses** and full runtime **codehashes**, not merely modulo
///         immutables. It does so by re-running the exact production deploy:
///         the Arachnid deterministic CREATE2 deployer
///         (`0x4e59…`, salt = 0) under the production optimiser profile and
///         the real deploy chain (Base, chainId 8453).
///
///         This is the artifact that closes
///         `contracts/verification/docs/DEPLOYED_BYTECODE_PIN_CAVEAT.md`:
///         the Halmos `solidity{Wallet,Factory}_compiles_correctly`
///         discharges are pinned to test-harness instances and transported
///         to the deployed contracts by `PinnedBytecodeImmutableLemma`
///         (runtime differs only in immutable windows). This test grounds
///         that transport against the *actual on-chain bytecode*: the only
///         differences between a local rebuild and the chain are exactly the
///         Solady EIP-712 immutable cache (cached domain separator,
///         `address(this)`, cached chainId) for the wallet and the
///         implementation-address immutable (×3) for the factory — and
///         reconstructing at the real address + chainId makes even those
///         coincide, yielding the on-chain codehash exactly.
///
///         RECOVERY PROVENANCE: the deploy-time lib that this depends on is
///         **account-abstraction `f54584e` (ERC-4337 v0.9 release)**, whose
///         `contracts/legacy/v06/` differs from the v0.8.0 tag. Building
///         with the v0.8.0 pin yields a *different* impl/factory codehash;
///         only `f54584e` reproduces both the audited pins and the chain.
///         solady (`90db92ce`) is bytecode-irrelevant here — its consumed
///         files (LibClone/ERC1271/EIP712/SignatureCheckerLib) are unchanged
///         from 2025-12-04 to HEAD. See `foundry.lock`.
///
///         DEPLOY-PROFILE ONLY: the production contracts were cut from
///         `[profile.deploy]` (runs=999999). Under any other profile the
///         creation code differs, so this test self-skips.
contract DeployedBytecodeReproCheckTest is Test {
    // Arachnid deterministic-deployment proxy (calldata = salt(32) || initcode).
    address constant ARACHNID = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes constant ARACHNID_RUNTIME =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    uint256 constant BASE_CHAIN_ID = 8453;
    address constant ENTRY_POINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    ISPHINCSVerifier constant DEPLOYED_VERIFIER =
        ISPHINCSVerifier(0xdDE4D290d646097ECeEA1e33Bf8C9Fa6dd589cbB);

    // Live Base Mainnet deployment (deployments/base-mainnet.json), verified
    // against https://mainnet.base.org via `cast code | cast keccak`.
    address constant ONCHAIN_IMPL = 0x31e49D24370bFa487dF1D6687A1aca5a34183590;
    address constant ONCHAIN_FACTORY = 0xe8CE78CD976497447FF8B76c71b59aE42Af0d452;
    address constant ONCHAIN_VERIFIER = 0xdDE4D290d646097ECeEA1e33Bf8C9Fa6dd589cbB;

    bytes32 constant ONCHAIN_IMPL_CODEHASH =
        0xdc9a082f92033d1ce86e64981034ffaa414e79c05a6c2917a93855b62f836994;
    bytes32 constant ONCHAIN_FACTORY_CODEHASH =
        0x045bb5e49f0c0c8ba2daef064c3cdf522ff86a1d03d2b0c13f59faab6255ba9a;
    bytes32 constant ONCHAIN_VERIFIER_CODEHASH =
        0xeb1e3fcd38c7cd5f7b08352c298b34bd114d83f7dbd755b122c41eda2aab2cc5;

    function _isDeployProfile() internal view returns (bool) {
        return keccak256(bytes(vm.envOr("FOUNDRY_PROFILE", string("default"))))
            == keccak256(bytes("deploy"));
    }

    function _create2(bytes memory initcode) internal returns (address a) {
        (bool ok, bytes memory ret) =
            ARACHNID.call(abi.encodePacked(bytes32(0), initcode));
        require(ok, "CREATE2 deploy failed");
        a = address(bytes20(ret));
    }

    /// Replays the production deploy and asserts the on-chain addresses and
    /// codehashes are reproduced exactly.
    function test_deployed_base_mainnet_bytecode_is_reproducible() external {
        if (!_isDeployProfile()) {
            emit log("SKIP: run under FOUNDRY_PROFILE=deploy (production profile)");
            vm.skip(true);
            return;
        }

        // Deploy on the real chain id so the EIP-712 immutable cache matches.
        vm.chainId(BASE_CHAIN_ID);
        vm.etch(ARACHNID, ARACHNID_RUNTIME);

        // (1) verifier — no immutables, address-independent.
        address verifier = _create2(type(SPHINCsC10Asm).creationCode);
        assertEq(verifier.codehash, ONCHAIN_VERIFIER_CODEHASH, "verifier codehash != chain");

        // (2) wallet implementation — immutables (_entryPoint, c10Verifier).
        address impl = _create2(
            abi.encodePacked(
                type(PQSmartWallet).creationCode,
                abi.encode(IEntryPoint(ENTRY_POINT_V06), DEPLOYED_VERIFIER)
            )
        );
        assertEq(impl, ONCHAIN_IMPL, "impl address != chain");
        assertEq(impl.codehash, ONCHAIN_IMPL_CODEHASH, "impl codehash != chain");

        // (3) factory — immutable (implementation address, c10Verifier).
        address factory = _create2(
            abi.encodePacked(
                type(PQSmartWalletFactory).creationCode,
                abi.encode(impl, DEPLOYED_VERIFIER)
            )
        );
        assertEq(factory, ONCHAIN_FACTORY, "factory address != chain");
        assertEq(factory.codehash, ONCHAIN_FACTORY_CODEHASH, "factory codehash != chain");

        // The deployed verifier address constant matches the one baked into
        // the wallet/factory immutables (sanity on the JSON record).
        assertEq(ONCHAIN_VERIFIER, address(DEPLOYED_VERIFIER), "verifier addr record");
    }
}
