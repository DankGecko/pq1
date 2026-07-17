// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

/// @title EntryPoint v0.6 codehash receipt — the `T-EP-NONCE` cited-TCB leaf.
/// @notice The wallet's same-nonce Type-2 replay protection rests WHOLLY on the
///         deployed EntryPoint v0.6 `NonceManager` (`entrypoint_no_replay` was
///         removed as dangling+latent-false; `PQSmartWallet` never reads `op.nonce`
///         except as a `sphincsDigest` input). That is a cited-TCB assumption bound
///         to the EntryPoint at `0x5FF1…789`. Until now the binding pinned only the
///         ADDRESS; this pins the deployed runtime `codehash`, so a substitution or
///         a wrong-version EntryPoint at that address is caught.
///
///         VERIFIED 2026-07-17: `keccak256(eth_getCode(0x5FF1…789))` is IDENTICAL
///         across Ethereum (1), Base (8453), Optimism (10), and Arbitrum (42161) —
///         `0xc93c…8e70`, the same 23,690-byte singleton — confirming it is the one
///         canonical deployment. (`cast code 0x5FF1…789 --rpc-url <chain> | cast keccak`.)
///
///         Fork-gated: set `ENTRYPOINT_RPC_URL` to re-verify against a live chain
///         (`forge test --match-contract EntryPointCodehashReceipt`); self-skips —
///         no false green — when unset. The pinned constant is the durable receipt
///         either way. This does NOT discharge the NonceManager assumption (it stays
///         cited-TCB / defeater D2 open); it makes the leaf's binding checkable.
contract EntryPointCodehashReceiptTest is Test {
    /// @dev The canonical ERC-4337 v0.6 EntryPoint singleton.
    address internal constant ENTRY_POINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    /// @dev `keccak256(deployed runtime bytecode)` — identical on Ethereum / Base /
    ///      Optimism / Arbitrum (verified 2026-07-17). This is what `EXTCODEHASH`
    ///      (`address(...).codehash`) returns for the account.
    bytes32 internal constant ENTRY_POINT_V06_CODEHASH =
        0xc93c806e738300b5357ecdc2e971d6438d34d8e4e17b99b758b1f9cac91c8e70;

    function test_entrypoint_v06_codehash_pinned() public {
        string memory url = vm.envOr("ENTRYPOINT_RPC_URL", string(""));
        if (bytes(url).length == 0) {
            emit log(
                "ENTRYPOINT_RPC_URL unset -- skipping live EntryPoint codehash fork check "
                "(the pinned ENTRY_POINT_V06_CODEHASH constant is the receipt of record)"
            );
            vm.skip(true);
            return;
        }
        vm.createSelectFork(url);
        assertEq(
            ENTRY_POINT_V06.codehash,
            ENTRY_POINT_V06_CODEHASH,
            "EntryPoint v0.6 codehash != pinned receipt (substitution / wrong version at 0x5FF1..789)"
        );
    }
}
