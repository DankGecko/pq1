// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";

import {SPHINCsC10Asm} from "../../src/verifiers/SPHINCsC10Asm.sol";

/// @notice Halmos symbolic-execution rules for the **input-validation
///         gates** of the deployed SPHINCS+C10 verifier bytecode
///         (`solidityVerifier_compiles_correctly`, A3.1).
///
///         SCOPE / honesty: the verifier's FULL functional behaviour is
///         SHA-256-heavy (thousands of `staticcall(0x02)` over a 4008-byte
///         signature, nested Merkle/WOTS loops) and is NOT symbolically
///         tractable — that part of A3.1 is discharged by the Lean
///         refinement (`Verifier/Equivalence.lean::verifyRefined_eq_spec`,
///         including the FORS htIdx ADRS binding) plus the 10-vector
///         Rust ↔ Solidity ↔ Lean differential (`test_verifyAllKatVectors`).
///         Here Halmos proves, ON THE BYTECODE, the early-return gates that
///         execute BEFORE any hashing — exactly the gates the Lean spec
///         (`verifyRefined`) also enforces:
///           * wrong signature length reverts;
///           * a non-N-masked `pkSeed` / `pkRoot` returns false (not revert).
///
///         Run: `halmos --contract HalmosVerifier`.
contract HalmosVerifier is SymTest, Test {
    // N_MASK = top 16 bytes set, bottom 16 bytes zero.
    bytes32 internal constant NMASKED = bytes32(uint256(0x1234) << 240);

    SPHINCsC10Asm internal v;

    function setUp() public {
        v = new SPHINCsC10Asm();
    }

    /// **Wrong signature length reverts** ("Invalid sig length"). The check
    /// is the first thing the Yul does, before any hash. Representative
    /// wrong length (one below the required 4008).
    function check_verify_reverts_on_wrong_length() public {
        bytes memory sig = new bytes(4007);
        try v.verify(NMASKED, NMASKED, bytes32(0), sig) returns (bool) {
            assertTrue(false, "A3.1 bytecode: verifier accepted a non-4008 signature length");
        } catch {
            // expected: revert("Invalid sig length")
        }
    }

    /// **Non-N-masked `pkSeed` returns false** (audit I-2 in-verifier
    /// enforcement). The check sits above the H_msg hash, so this path
    /// never reaches a SHA-256 call: a fully concrete reject.
    function check_verify_rejects_non_nmasked_pkSeed(bytes32 pkSeed) public {
        // bottom 16 bytes non-zero ⇒ not N-masked.
        vm.assume(uint128(uint256(pkSeed)) != 0);
        bytes memory sig = new bytes(4008);
        bool ok = v.verify(pkSeed, NMASKED, bytes32(0), sig);
        assertTrue(!ok, "A3.1 bytecode: verifier accepted a non-N-masked pkSeed");
    }

    /// **Non-N-masked `pkRoot` returns false.**
    function check_verify_rejects_non_nmasked_pkRoot(bytes32 pkRoot) public {
        vm.assume(uint128(uint256(pkRoot)) != 0);
        bytes memory sig = new bytes(4008);
        bool ok = v.verify(NMASKED, pkRoot, bytes32(0), sig);
        assertTrue(!ok, "A3.1 bytecode: verifier accepted a non-N-masked pkRoot");
    }
}
