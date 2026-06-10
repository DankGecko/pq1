// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

/// @notice Profile-aware pinned-codehash constants, shared by
///         `PinnedCodehashes.t.sol` (the freeze test) and
///         `PinnedBytecodeImmutableLemma.t.sol` (the immutable-window
///         lemma).
///
///         The compiled runtime depends on the optimiser profile, so each
///         profile gets its own pin set:
///
///           * `default` — foundry.toml main profile (runs=200, via_ir,
///             prague). The fast-iteration build the test suite and the
///             Halmos sessions run against by default.
///           * `deploy`  — [profile.deploy] (runs=999999, via_ir, prague).
///             The bytecode production deployments are cut from.
///             `make -C contracts/verification verify-bytecode` runs the
///             FULL symbolic suite against BOTH profiles, so every
///             discharge holds for the production build too, not just the
///             dev build.
///
///         A zero constant means "not yet pinned": the freeze test prints
///         the live value for capture instead of asserting.
abstract contract PinnedCodehashSelector is Test {
    // ── default profile (runs=200) — re-pinned 2026-06-10 ─────────────
    bytes32 internal constant WALLET_CODEHASH_DEFAULT =
        0x43c65420691792d7f0f63dab95f47ab7adb649df4c83f432bd3cf2c95db3a06a;
    bytes32 internal constant FACTORY_CODEHASH_DEFAULT =
        0xfa2922b4fadb81b4475307504890d68f2e3d9be97c7e5e9aeeba6e84110d7c3c;
    bytes32 internal constant VERIFIER_CODEHASH_DEFAULT =
        0xf1ef4ccee22e6b39446723232fe39761f089c7195941b2c12576956b38fcfef5;

    // ── deploy profile (runs=999999) — pinned 2026-06-10 ──────────────
    bytes32 internal constant WALLET_CODEHASH_DEPLOY =
        0x551c4e03bbd433a5929828ab19caac13a94ca9e2be6074cf3e18c7d926034c22;
    bytes32 internal constant FACTORY_CODEHASH_DEPLOY =
        0x5feb7955252e54bcbbf44062295bdeb45f3dea13c4ef7fb1ba579196d84da4b9;
    bytes32 internal constant VERIFIER_CODEHASH_DEPLOY =
        0xeb1e3fcd38c7cd5f7b08352c298b34bd114d83f7dbd755b122c41eda2aab2cc5;

    function _isDeployProfile() internal view returns (bool) {
        return keccak256(bytes(vm.envOr("FOUNDRY_PROFILE", string("default"))))
            == keccak256(bytes("deploy"));
    }

    function _pinnedWallet() internal view returns (bytes32) {
        return _isDeployProfile() ? WALLET_CODEHASH_DEPLOY : WALLET_CODEHASH_DEFAULT;
    }

    function _pinnedFactory() internal view returns (bytes32) {
        return _isDeployProfile() ? FACTORY_CODEHASH_DEPLOY : FACTORY_CODEHASH_DEFAULT;
    }

    function _pinnedVerifier() internal view returns (bytes32) {
        return _isDeployProfile() ? VERIFIER_CODEHASH_DEPLOY : VERIFIER_CODEHASH_DEFAULT;
    }
}
