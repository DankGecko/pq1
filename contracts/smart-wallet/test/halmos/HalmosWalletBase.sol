// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";
import {MockSPHINCSVerifier} from "../mocks/MockSPHINCSVerifier.sol";

/// @notice Shared base for the Halmos symbolic-execution harnesses that
///         discharge `solidityWallet_compiles_correctly` (A3.2) against
///         the **deployed PQSmartWallet runtime bytecode**.
///
///         The wallet proxy is brought up WITHOUT the factory's
///         `createAccount` path: that path computes `sha256` for the
///         CREATE2 salt + the slot-0 squat-defence digest, which Halmos
///         models as an uninterpreted `f_sha256_*` and (in 0.3.3) hits a
///         Z3 sort error on the 64-byte salt input. Owner-set bring-up
///         (`initialize`) uses no `sha256`, so we deploy a bare ERC-1967
///         proxy and `initialize` it directly — the resulting storage
///         (bootstrap at index 0, slot 0 at index 1) is byte-identical to
///         what the factory installs. The squat-defence `sha256` path is
///         a separate axiom (A3.3, factory) and is out of scope here.
///
///         The C10 verifier is the controllable `MockSPHINCSVerifier`.
///         This is the SAME abstraction the Lean model uses: the Lean
///         `validateSignature` is parameterised by an arbitrary
///         `verify_fn : … → Bool`, and the on-chain wallet calls an
///         arbitrary external verifier. Making the mock's result SYMBOLIC
///         lets Halmos prove the non-bypass property (success ⇒ verifier
///         returned true) over EVERY possible verifier answer — exactly
///         the bytecode analogue of Lean's
///         `validateSignature_only_via_verify` (I-1).
abstract contract HalmosWalletBase is SymTest, Test {
    address internal constant ENTRY_POINT_ADDR = address(0x4337);

    // N-mask-shaped owner keys (top 16 bytes set, bottom 16 zero).
    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    PQSmartWallet internal wallet;
    MockSPHINCSVerifier internal c10;

    /// @dev Bring up an initialised wallet proxy with NO `sha256` calls.
    function _deployWalletSha256Free() internal returns (PQSmartWallet w) {
        c10 = new MockSPHINCSVerifier();
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        address proxy = LibClone.deployERC1967(address(impl));
        w = PQSmartWallet(payable(proxy));
        w.initialize(
            abi.encodePacked(MASTER_PK_SEED, MASTER_PK_ROOT),
            abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT)
        );
    }

    /// @dev Replace the `0x02` (SHA-256) precompile with a stub that
    ///      returns a constant 32 bytes. `sphincsDigest` (the only thing
    ///      that hashes inside `validateUserOp`) is irrelevant to every
    ///      property proved here — the mock verifier ignores the digest
    ///      and the counter bumps don't depend on it — so abstracting
    ///      SHA-256 to a constant is sound. The reason we must: Halmos
    ///      0.3.3 models the SHA-256 precompile as an uninterpreted
    ///      function whose declared domain sort is inconsistent with the
    ///      applied sort (`f_sha256_N : BitVec N` vs an applied
    ///      `BitVec 8N`), crashing Z3 on any success path that reaches
    ///      `sphincsDigest`. The stub's runtime is
    ///      `PUSH1 0x20 PUSH1 0x00 RETURN` → returns memory[0:32] = 0.
    ///      The SHA-256-correctness of the digest is a *separate* axiom
    ///      (A1, precompile_0x02_is_FIPS_180_4), not part of the wallet's
    ///      authorisation logic (A3.2).
    function _stubSha256() internal {
        vm.etch(address(uint160(2)), hex"60206000f3");
    }

    /// @dev Build a UserOp. `initCode` / `paymasterAndData` are non-empty
    ///      32-byte constants: the wallet only *hashes* these fields inside
    ///      `sphincsDigest`, and Halmos 0.3.3 models the `sha256` precompile
    ///      over a 0-byte input as a `BitVec(0)` (Z3 rejects), so an empty
    ///      field would crash the symbolic engine on the success path
    ///      without changing any wallet control flow. Their *content* is
    ///      irrelevant to every property proved here (the verifier is a
    ///      mock that ignores the digest; counter bumps don't depend on it).
    function _op(bytes memory callData, bytes memory sig)
        internal
        view
        returns (UserOperation06 memory op)
    {
        op.sender = address(wallet);
        op.nonce = 0;
        op.initCode = abi.encodePacked(bytes32(0));
        op.callData = callData;
        op.callGasLimit = 0;
        op.verificationGasLimit = 0;
        op.preVerificationGas = 0;
        op.maxFeePerGas = 0;
        op.maxPriorityFeePerGas = 0;
        op.paymasterAndData = abi.encodePacked(bytes32(0));
        op.signature = sig;
    }
}
