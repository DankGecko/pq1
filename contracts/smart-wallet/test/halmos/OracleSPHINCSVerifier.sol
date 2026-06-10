// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISPHINCSVerifier} from "../../src/verifiers/ISPHINCSVerifier.sol";

/// @notice A *generic-function* verifier for the Halmos pointwise-equivalence
///         harness (`HalmosValidateUserOpEquiv`).
///
///         The answer is a fixed-but-arbitrary deterministic function of the
///         FULL argument tuple `(pkSeed, pkRoot, digest, sig)`: under Halmos,
///         `keccak256` is modelled as an uninterpreted function (with
///         injectivity axioms), so `verify` denotes "some unknown Boolean
///         function f of the inputs" — exactly the `verify_fn` parameter the
///         Lean model `ValidateUserOp.validateSignature` is quantified over,
///         and exactly the role the deployed `SPHINCsC10Asm.verify` plays in
///         bridge axiom A3.2 (whose own discharge is A3.1).
///
///         Why input-DEPENDENT instead of the constant-answer
///         `MockSPHINCSVerifier`: with a constant answer, the equivalence
///         rule could NOT detect the wallet handing the verifier different
///         bytes than the model (a wrong digest preimage, a mis-sliced inner
///         signature) — both sides would still agree. With f(args), any path
///         on which the wallet's argument tuple differs from the model's
///         yields two unconstrained-and-therefore-distinguishable answers,
///         so the solver finds a counterexample. A passing rule therefore
///         certifies, per path: (a) the wallet calls the verifier iff the
///         model does, (b) on byte-identical arguments, and (c) handles both
///         answer values identically — i.e. functional equality of
///         everything around the verifier.
contract OracleSPHINCSVerifier is ISPHINCSVerifier {
    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 digest, bytes calldata sig)
        external
        pure
        override
        returns (bool)
    {
        return uint256(keccak256(abi.encodePacked(pkSeed, pkRoot, digest, sig))) & 1 == 1;
    }
}

/// @notice An always-reverting verifier: drives the wallet's `try/catch`
///         fallback arm. The Lean model treats the verifier as a TOTAL
///         Boolean function; the Solidity `catch` maps a reverting verifier
///         to `SIG_VALIDATION_FAILED`, i.e. the model interpretation
///         `verify_fn ≡ false`. `check_equiv_reverting_verifier` proves on
///         the bytecode that this arm returns failure and leaves storage
///         untouched — the same observable behaviour the model assigns.
contract RevertingSPHINCSVerifier is ISPHINCSVerifier {
    error AlwaysReverts();

    function verify(bytes32, bytes32, bytes32, bytes calldata)
        external
        pure
        override
        returns (bool)
    {
        revert AlwaysReverts();
    }
}
