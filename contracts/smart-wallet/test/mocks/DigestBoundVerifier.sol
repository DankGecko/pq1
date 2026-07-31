// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISPHINCSVerifier} from "../../src/verifiers/ISPHINCSVerifier.sol";

/// @notice A verifier mock that accepts ONLY the exact
///         `(pkSeed, pkRoot, message)` triples it has been armed with.
///
///         WHY NOT `MockSPHINCSVerifier`. That mock returns a global yes/no and
///         ignores its arguments, which is right for dispatcher control-flow
///         tests and useless for any test whose property IS the digest: with an
///         accept-everything verifier, an assertion like "this signature must
///         not verify on another chain" passes for the wrong reason — it would
///         pass even if `replaySafeHash` ignored `chainId` entirely, because
///         nothing downstream ever looks at the hash.
///
///         Arming makes the digest load-bearing in both directions. A test
///         computes the digest it believes the wallet will ask about, arms
///         exactly that, and asserts acceptance: the POSITIVE assertion is then
///         simultaneously a proof that the test's formula equals the wallet's.
///         The matching negative (arm the other chain's digest, expect refusal)
///         cannot be satisfied by an accident.
///
///         A set, not a single triple, because real flows legitimately verify
///         more than one signature. The ERC-6492 counterfactual path is the
///         motivating case: one `eth_call` first runs the factory's
///         `createAccount` — which checks a BOOTSTRAP signature over
///         `addSlot0Digest(chainId, slot0PkSeed, slot0PkRoot)` — and only then
///         the wallet's EIP-1271 check of a SLOT signature over the
///         replay-safe hash. Two different keys, two different digests, one
///         call. A single-triple mock cannot express that, and forcing the test
///         to fall back to an accept-all mock would silently discard the very
///         property the test exists to pin.
///
///         Same M14 guard as `MockSPHINCSVerifier`: refuse to exist off a local
///         chain, so an accidental production deployment reverts at construction
///         rather than accepting signatures.
contract DigestBoundVerifier is ISPHINCSVerifier {
    mapping(bytes32 => bool) internal _armed;

    /// @notice Number of `verify` calls that were REFUSED. A test that expects
    ///         a refusal can assert this moved, distinguishing "the wallet
    ///         asked and we said no" from "the wallet never asked" — which are
    ///         very different failures wearing the same red.
    uint256 public refusals;

    error MockNotAllowedOnChain(uint256 chainId);

    constructor() {
        uint256 cid = block.chainid;
        if (cid != 31337 && cid != 1337 && cid != 0) {
            revert MockNotAllowedOnChain(cid);
        }
    }

    function _key(bytes32 pkSeed, bytes32 pkRoot, bytes32 message) internal pure returns (bytes32) {
        return keccak256(abi.encode(pkSeed, pkRoot, message));
    }

    function arm(bytes32 pkSeed, bytes32 pkRoot, bytes32 message) external {
        _armed[_key(pkSeed, pkRoot, message)] = true;
    }

    function disarm(bytes32 pkSeed, bytes32 pkRoot, bytes32 message) external {
        _armed[_key(pkSeed, pkRoot, message)] = false;
    }

    function isArmed(bytes32 pkSeed, bytes32 pkRoot, bytes32 message) external view returns (bool) {
        return _armed[_key(pkSeed, pkRoot, message)];
    }

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata)
        external
        view
        override
        returns (bool)
    {
        return _armed[_key(pkSeed, pkRoot, message)];
    }
}
