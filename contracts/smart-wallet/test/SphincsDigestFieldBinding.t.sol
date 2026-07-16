// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {ISPHINCSVerifier} from "../src/verifiers/ISPHINCSVerifier.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

/// @notice FV surface `actual-signed-digest-correspondence` (roadmap P1.7),
///         the *non-vacuity* half of the F2 fix.
///
///         `PQSmartWalletRealSig.t.sol::test_digestMatches` already binds the
///         on-chain `sphincsDigest` to a single Rust-generated digest (one
///         positive vector). That alone does not prove the digest actually
///         COMMITS to every field — a `sphincsDigest` that ignored, say,
///         `nonce` or `paymasterAndData` would still pass that one vector while
///         letting an attacker substitute that field under the same signature.
///
///         This asserts the digest is SENSITIVE to every one of the 12 fields
///         of the `compute_sphincs_digest_v06` / `sphincsDigest` preimage:
///         mutating any single field (or the two wallet/chain context inputs)
///         changes the digest. Combined with the Rust↔Solidity positive vector
///         and the source-level field-order pin
///         (`scripts/check_sphincs_digest_field_order.py`), this closes F2's
///         "connect exact Rust/Solidity layouts + per-field mutations" clause.
///
///         SCOPE (F9): this is on-chain-digest evidence over a concrete op plus
///         a per-field difference argument — it is NOT the ∀-over-layout Lean
///         extraction of `compute_sphincs_digest_v06` (blocked by the sha2
///         streaming API; that stronger follow-up is noted in the report). The
///         sha2 streaming≡concat equivalence stays a named assumption, same
///         tier as the `sha256_pure` axiom.
contract SphincsDigestFieldBindingTest is Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);
    address constant OTHER_ENTRY_POINT = address(0x1234);

    PQSmartWallet internal wallet; // called directly; sphincsDigest is a pure view over (op, _entryPoint, chainid)

    function setUp() public {
        MockSPHINCSVerifier v = new MockSPHINCSVerifier();
        wallet = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), ISPHINCSVerifier(address(v)));
    }

    /// A non-trivial baseline op — every field nonzero / nonempty so a mutation
    /// of ANY field is a genuine change (a mutation off an all-zero baseline can
    /// only ever increase, which is fine, but nonzero is a stronger witness).
    function _baseline() internal pure returns (UserOperation06 memory op) {
        op.sender = address(0xA11CE);
        op.nonce = 7;
        op.initCode = hex"deadbeef";
        op.callData = hex"cafe0011";
        op.callGasLimit = 100000;
        op.verificationGasLimit = 200000;
        op.preVerificationGas = 21000;
        op.maxFeePerGas = 30 gwei;
        op.maxPriorityFeePerGas = 2 gwei;
        op.paymasterAndData = hex"00112233";
        op.signature = ""; // sphincsDigest ignores the signature
    }

    function _clone(UserOperation06 memory a) internal pure returns (UserOperation06 memory b) {
        b.sender = a.sender;
        b.nonce = a.nonce;
        b.initCode = a.initCode;
        b.callData = a.callData;
        b.callGasLimit = a.callGasLimit;
        b.verificationGasLimit = a.verificationGasLimit;
        b.preVerificationGas = a.preVerificationGas;
        b.maxFeePerGas = a.maxFeePerGas;
        b.maxPriorityFeePerGas = a.maxPriorityFeePerGas;
        b.paymasterAndData = a.paymasterAndData;
        b.signature = a.signature;
    }

    /// Every op-derived field of the 360-byte preimage: a single-field mutation
    /// must change the digest (the digest commits to it → no field substitution).
    function test_everyOpFieldIsCommitted() public view {
        UserOperation06 memory base = _baseline();
        bytes32 d0 = wallet.sphincsDigest(base);

        UserOperation06 memory m;

        m = _clone(base); m.sender = address(0xB0B);
        assertTrue(wallet.sphincsDigest(m) != d0, "sender not committed");

        m = _clone(base); m.nonce = base.nonce + 1;
        assertTrue(wallet.sphincsDigest(m) != d0, "nonce not committed");

        m = _clone(base); m.initCode = hex"deadbeef00"; // changes sha256(initCode)
        assertTrue(wallet.sphincsDigest(m) != d0, "initCode not committed");

        m = _clone(base); m.callData = hex"cafe0012"; // changes sha256(callData)
        assertTrue(wallet.sphincsDigest(m) != d0, "callData not committed");

        m = _clone(base); m.callGasLimit = base.callGasLimit + 1;
        assertTrue(wallet.sphincsDigest(m) != d0, "callGasLimit not committed");

        m = _clone(base); m.verificationGasLimit = base.verificationGasLimit + 1;
        assertTrue(wallet.sphincsDigest(m) != d0, "verificationGasLimit not committed");

        m = _clone(base); m.preVerificationGas = base.preVerificationGas + 1;
        assertTrue(wallet.sphincsDigest(m) != d0, "preVerificationGas not committed");

        m = _clone(base); m.maxFeePerGas = base.maxFeePerGas + 1;
        assertTrue(wallet.sphincsDigest(m) != d0, "maxFeePerGas not committed");

        m = _clone(base); m.maxPriorityFeePerGas = base.maxPriorityFeePerGas + 1;
        assertTrue(wallet.sphincsDigest(m) != d0, "maxPriorityFeePerGas not committed");

        m = _clone(base); m.paymasterAndData = hex"00112234"; // changes sha256(paymasterAndData)
        assertTrue(wallet.sphincsDigest(m) != d0, "paymasterAndData not committed");
    }

    /// The two context inputs (wallet `_entryPoint` immutable, `block.chainid`)
    /// are also part of the preimage — the digest is domain-separated by them.
    function test_entryPointAndChainIdAreCommitted() public {
        UserOperation06 memory base = _baseline();
        bytes32 d0 = wallet.sphincsDigest(base);

        // entryPoint: a wallet bound to a different EntryPoint yields a
        // different digest for the same op (the address(_entryPoint) field).
        MockSPHINCSVerifier v = new MockSPHINCSVerifier();
        PQSmartWallet otherEp = new PQSmartWallet(IEntryPoint(OTHER_ENTRY_POINT), ISPHINCSVerifier(address(v)));
        assertTrue(otherEp.sphincsDigest(base) != d0, "entryPoint not committed");

        // chainId: block.chainid is folded in (cross-chain replay defence).
        uint256 saved = block.chainid;
        vm.chainId(saved == 8453 ? 1 : 8453);
        assertTrue(wallet.sphincsDigest(base) != d0, "chainId not committed");
        vm.chainId(saved);
    }

    /// A distinct-inputs → distinct-digest spot check across independent ops
    /// (collision-freedom witness on the tested corpus, not a proof).
    function test_distinctOpsDistinctDigests() public view {
        UserOperation06 memory a = _baseline();
        UserOperation06 memory b = _baseline();
        b.sender = address(0xBEEF);
        b.nonce = 99;
        assertTrue(wallet.sphincsDigest(a) != wallet.sphincsDigest(b), "distinct ops collided");
    }
}
