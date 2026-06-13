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
    // ── default profile (runs=200) — RE-PINNED 2026-06-13 ─────────────
    // Re-pinned to a reproducible foundry.lock build (account-abstraction
    // v0.8.0 4cbc060 + solady 90db92ce + solc 0.8.28/via_ir, forge 1.7.1)
    // after the lock was repaired (its prior AA v0.7.0 pin did not compile).
    // The prior wallet/factory pins (0x43c654…/0xfa2922…) were bound to a dev
    // build whose exact lib commits were never recorded in foundry.lock and
    // are not reproducible from current public solady; the Halmos discharge
    // was RE-RUN against these new codehashes (see PINNED_CODEHASHES.md).
    // VERIFIER codehashes are UNCHANGED (the verifier imports no libraries;
    // the deploy-profile value also matches the on-chain Base Mainnet
    // verifier 0xdDE4D290…).
    bytes32 internal constant WALLET_CODEHASH_DEFAULT =
        0xaa85654b8bcd6e63983907bfe3332d6f543e7a32839f7afd9f22b69ba1983730;
    bytes32 internal constant FACTORY_CODEHASH_DEFAULT =
        0xa2cfb800ea3766f03da2288ee31dc7e470edf3a1f39e3dbca50104f6079ee6aa;
    bytes32 internal constant VERIFIER_CODEHASH_DEFAULT =
        0xf1ef4ccee22e6b39446723232fe39761f089c7195941b2c12576956b38fcfef5;

    // ── deploy profile (runs=999999) — RE-PINNED 2026-06-13 ───────────
    bytes32 internal constant WALLET_CODEHASH_DEPLOY =
        0x8c6baad3e5ddbb132d3d26d81ad35a85f608fdb2b8a2f5980171839539c4f490;
    bytes32 internal constant FACTORY_CODEHASH_DEPLOY =
        0x4d1e1edfdd55f0a9021d3f8406ba27540c7373d4019b49759b5e8e8c5e058a02;
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
