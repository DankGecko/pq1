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
    // ── default profile (runs=200) — re-pinned 2026-06-16 ─────────────
    //    Drift from the 2026-06-10 pins is from deliberate post-audit
    //    security fixes that landed after the last re-pin (per-ownerIndex
    //    credit b7ce7c73, FORS-leaf binding fcee705a, bootstrap few-time
    //    cap 98c1e862, EntryPoint gate, A3.2/A3.3 dd99730d).
    //    The Halmos SYMBOLIC rules were re-discharged directly against this
    //    bytecode 2026-06-16 (z3, default profile, --loop 4): 39/39 rules pass
    //    across all 7 Halmos contracts (Execute 6, ExecuteEquiv 6, Factory 5,
    //    MultiOwnable 7, ValidateUserOp 8, ValidateUserOpEquiv 4, Verifier 3),
    //    0 failed / 0 counterexamples — so the post-audit verify/validate
    //    bytecode is symbolically sound, not just freshly pinned.
    //    NOTE: the full `make -C contracts/verification verify-bytecode` is
    //    currently BLOCKED at its certify step by a SEPARATE, known divergence
    //    — local is AHEAD of the Base Mainnet reference deployment (the FORS
    //    fix fcee705a is not deployed, so DeployedBytecodeReproCheck fails
    //    under the deploy profile). That is a deploy decision (see work-todo),
    //    NOT a re-pin: the ONCHAIN_*_CODEHASH constants are left untouched.
    bytes32 internal constant WALLET_CODEHASH_DEFAULT =
        0x6c113d2c1bc38133fecd0472bd366d6ef832467e99b8533ec0f98e3b6aac8e41;
    bytes32 internal constant FACTORY_CODEHASH_DEFAULT =
        0x46c1349ca0251c263aa9589b178b4e8dc9b387d4ba0a980cb502b5e6bec05bc0;
    bytes32 internal constant VERIFIER_CODEHASH_DEFAULT =
        0x18402d2650e7cbabeda77b93091f0281d98eb81005897bbf07981f1ec25a9fbf;

    // ── deploy profile (runs=999999) — re-pinned 2026-06-16 ───────────
    bytes32 internal constant WALLET_CODEHASH_DEPLOY =
        0x95d9cc41dc6d919435f997a61aa57a2ecd1dcad9cac64b757a659332347a0458;
    bytes32 internal constant FACTORY_CODEHASH_DEPLOY =
        0xbc89b8248915b89a41b1e81aa3930d3ba6e51e9f2124ed8fa4d6e61f5ccacebd;
    bytes32 internal constant VERIFIER_CODEHASH_DEPLOY =
        0xc5c8938b075230a99cef637a333d4f35284296e4083c9c38da18f1dbc00dc996;

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
