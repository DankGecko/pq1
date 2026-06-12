// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";

/// @notice **Exact-value parity of the deployed C10 verifier bytecode
///         against the shared mutant corpus (A3.1 functional layer).**
///
///         `test/c10_mutant_corpus.json` (generated deterministically by
///         `contracts/verification/scripts/gen_mutant_corpus.py`) carries
///         246 entries: 4 positive controls (the valid KAT vectors) and
///         242 adversarial near-misses mirroring the
///         `SPHINCsC10AsmAdversarial.t.sol` mutation classes plus dense
///         coverage of the two historic GAP-1 defect sites (the
///         calldataload straddling-read tail [3992,4008) and both
///         per-layer WOTS+C count fields).
///
///         This suite asserts the deployed bytecode returns EXACTLY the
///         corpus' `expectValid` for every entry — both directions
///         (wrong-accept AND wrong-reject are failures), strictly stronger
///         than the adversarial screen's reject-only direction. The same
///         corpus is replayed through the executable Lean spec by
///         `lake exe verify-mutant-corpus` (hard check), which is what
///         lifts the Lean <-> bytecode functional differential from the
///         10-vector KAT to mutant scale.
contract SPHINCsC10AsmMutantCorpusTest is Test {
    SPHINCsC10Asm internal verifier;

    /// Fields in ALPHABETICAL key order — required by forge's
    /// parseJson -> abi.decode struct coercion.
    struct Entry {
        bool expectValid;
        string label;
        bytes32 message;
        bytes32 pkRoot;
        bytes32 pkSeed;
        bytes signature;
    }

    function setUp() public {
        verifier = new SPHINCsC10Asm();
    }

    function _accepted(bytes32 s, bytes32 r, bytes32 m, bytes memory sig)
        internal
        view
        returns (bool)
    {
        (bool ok, bytes memory ret) =
            address(verifier).staticcall(abi.encodeWithSelector(verifier.verify.selector, s, r, m, sig));
        return ok && ret.length == 32 && abi.decode(ret, (bool));
    }

    function test_mutantCorpus_exactParity() public view {
        string memory json = vm.readFile("test/c10_mutant_corpus.json");
        Entry[] memory entries = abi.decode(vm.parseJson(json, ".entries"), (Entry[]));
        require(entries.length >= 240, "corpus unexpectedly small");

        uint256 positives = 0;
        for (uint256 i = 0; i < entries.length; i++) {
            Entry memory e = entries[i];
            bool got = _accepted(e.pkSeed, e.pkRoot, e.message, e.signature);
            if (got != e.expectValid) {
                revert(string.concat(
                    "CORPUS PARITY FAIL: ", e.label,
                    " expected ", e.expectValid ? "accept" : "reject",
                    ", bytecode ", got ? "accepted" : "rejected"
                ));
            }
            if (e.expectValid) positives++;
        }
        // The positive controls keep a reject-everything verifier from
        // passing vacuously.
        assertEq(positives, 4, "expected exactly 4 positive controls");
    }
}
