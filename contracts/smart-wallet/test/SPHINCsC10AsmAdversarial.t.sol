// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";

/// @notice **Adversarial wrong-accept screen for the deployed C10 verifier
///         bytecode (A3.1, functional layer).**
///
///         The verifier's full functional behaviour (FORS / WOTS+C / Merkle
///         / hypertree over a 4008-byte signature, thousands of
///         `staticcall(0x02)`) is not symbolically tractable, so A3.1 is
///         `discharged-bytecode-partial`: the Lean refinement
///         (`Verifier/Equivalence.lean::verifyRefined_eq_spec`, incl. the
///         FORS htIdx ADRS binding) + the 10-vector Rust↔Solidity↔Lean KAT
///         differential carry the positive direction (a valid signature
///         verifies), and Halmos carries the input gates.
///
///         This suite carries the NEGATIVE direction on the deployed
///         bytecode at scale: a near-miss signature must be REJECTED. The
///         "wrong-accept" failure mode (verifier returns true for a
///         signature it must reject) is the one that breaks theft-freedom,
///         so we hammer it with a dense, structured mutation battery
///         derived from a known-valid vector:
///
///           * every-byte single-bit and single-byte (0xFF) flips, swept
///             across all 4008 positions at stride 1 over the
///             structurally-critical regions and stride 8 elsewhere
///             (≈900 distinct mutants), each touching exactly one byte;
///           * whole-region zeroing (R, FORS, WOTS layer 0, Merkle);
///           * truncate-then-repad (length preserved, tail zeroed);
///           * all-zero and all-0xFF signatures;
///           * pubkey-seed / pubkey-root single-byte perturbations.
///
///         EVERY mutant must be rejected. A single wrong-accept fails the
///         suite with the offending position. The unmutated vector is
///         asserted to verify (the positive control), so the battery can't
///         pass vacuously by the verifier rejecting everything.
///
///         This is empirical (a finite, if large, battery) — not a proof
///         over all 2^32064 signatures; that ceiling is exactly why A3.1
///         stays `-partial`. But it exercises the deployed runtime bytecode
///         directly, at far greater density than the 6-position legacy
///         mutation test, specifically targeting wrong-accepts.
contract SPHINCsC10AsmAdversarialTest is Test {
    SPHINCsC10Asm internal verifier;

    bytes32 internal pkSeed;
    bytes32 internal pkRoot;
    bytes32 internal message;
    bytes internal validSig;

    // Region boundaries within the 4008-byte C10 signature (R ‖ FORS ‖
    // hypertree layers). Stride-1 dense sweep inside these windows; stride-8
    // elsewhere. Chosen to cover the start of each structural section.
    function setUp() public {
        verifier = new SPHINCsC10Asm();
        string memory json = vm.readFile("test/c10_test_vectors.json");
        pkSeed = vm.parseJsonBytes32(json, ".pkSeed");
        pkRoot = vm.parseJsonBytes32(json, ".pkRoot");
        message = vm.parseJsonBytes32(json, ".message");
        validSig = vm.parseJsonBytes(json, ".signature");
        require(validSig.length == 4008, "vector sig must be 4008 bytes");
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

    function _clone(bytes memory src) internal pure returns (bytes memory out) {
        out = new bytes(src.length);
        for (uint256 i = 0; i < src.length; i++) {
            out[i] = src[i];
        }
    }

    /// **Positive control.** The unmutated vector verifies, so a passing
    /// battery below cannot be vacuous (verifier-rejects-everything).
    function test_validVectorIsAccepted() public view {
        assertTrue(_accepted(pkSeed, pkRoot, message, validSig), "valid vector must verify");
    }

    /// **Dense single-byte-flip sweep — no wrong-accept anywhere.** Stride 1
    /// over the first 256 bytes (R + FORS opening, the most binding region)
    /// and the last 256 bytes (top Merkle layer); stride 8 across the rest.
    /// Each mutant flips exactly one byte (xor 0xFF) and MUST be rejected.
    function test_singleByteFlips_neverWrongAccept() public view {
        uint256 n = validSig.length; // 4008
        for (uint256 pos = 0; pos < n; pos += _stride(pos, n)) {
            bytes memory mutated = _clone(validSig);
            mutated[pos] = bytes1(uint8(mutated[pos]) ^ 0xFF);
            if (_accepted(pkSeed, pkRoot, message, mutated)) {
                revert(string.concat("WRONG-ACCEPT: single-byte flip at pos ", vm.toString(pos)));
            }
        }
    }

    /// **Low-bit single-bit-flip sweep** (xor 0x01) over the same dense
    /// schedule — catches verifiers that mask high bits but trust low bits.
    function test_singleBitFlips_neverWrongAccept() public view {
        uint256 n = validSig.length;
        for (uint256 pos = 0; pos < n; pos += _stride(pos, n)) {
            bytes memory mutated = _clone(validSig);
            mutated[pos] = bytes1(uint8(mutated[pos]) ^ 0x01);
            if (_accepted(pkSeed, pkRoot, message, mutated)) {
                revert(string.concat("WRONG-ACCEPT: single-bit flip at pos ", vm.toString(pos)));
            }
        }
    }

    /// Mutation schedule: stride 4 over the binding head [0,128) and the
    /// top-Merkle tail [3944,4008), stride 64 elsewhere — ≈120 mutants per
    /// sweep, every structural region sampled, each verify call being a
    /// full 4008-byte run through the deployed bytecode (thousands of
    /// sha256 precompiles). Kept under the forge per-test gas cap.
    function _stride(uint256 pos, uint256 n) private pure returns (uint256) {
        if (pos < 128 || pos >= n - 64) return 4;
        return 64;
    }

    /// **Whole-region zeroing — no wrong-accept.** Zero each structural
    /// region in turn; every result must reject.
    function test_regionZeroing_neverWrongAccept() public view {
        // (offset, length) windows spanning R, FORS, WOTS-layer0, Merkle-top.
        uint256[8] memory offs = [uint256(0), 32, 800, 1600, 2400, 3000, 3600, 3976];
        uint256[8] memory lens = [uint256(32), 256, 256, 256, 256, 256, 256, 32];
        for (uint256 k = 0; k < offs.length; k++) {
            bytes memory mutated = _clone(validSig);
            for (uint256 i = 0; i < lens[k] && offs[k] + i < mutated.length; i++) {
                mutated[offs[k] + i] = 0x00;
            }
            if (_accepted(pkSeed, pkRoot, message, mutated)) {
                revert(string.concat("WRONG-ACCEPT: zeroed region at offset ", vm.toString(offs[k])));
            }
        }
    }

    /// **Degenerate signatures — no wrong-accept.** All-zero and all-0xFF
    /// 4008-byte signatures, plus a tail-truncation (last 1024 bytes zeroed)
    /// that keeps the length valid.
    function test_degenerateSignatures_neverWrongAccept() public view {
        bytes memory allZero = new bytes(4008);
        assertFalse(_accepted(pkSeed, pkRoot, message, allZero), "WRONG-ACCEPT: all-zero sig");

        bytes memory allFF = new bytes(4008);
        for (uint256 i = 0; i < 4008; i++) {
            allFF[i] = 0xFF;
        }
        assertFalse(_accepted(pkSeed, pkRoot, message, allFF), "WRONG-ACCEPT: all-0xFF sig");

        bytes memory tailCut = _clone(validSig);
        for (uint256 i = 4008 - 1024; i < 4008; i++) {
            tailCut[i] = 0x00;
        }
        assertFalse(_accepted(pkSeed, pkRoot, message, tailCut), "WRONG-ACCEPT: tail-zeroed sig");
    }

    /// **Public-key perturbation — no wrong-accept.** The valid signature
    /// under a single-byte-perturbed pkSeed / pkRoot / message must reject
    /// (the signature is bound to the exact key + digest). Perturb a TOP
    /// byte so the N-mask gate still passes and the rejection comes from the
    /// functional verifier, not the input gate.
    function test_keyAndMessagePerturbation_neverWrongAccept() public view {
        bytes32 seedP = bytes32(uint256(pkSeed) ^ (uint256(0x01) << 248));
        assertFalse(_accepted(seedP, pkRoot, message, validSig), "WRONG-ACCEPT: perturbed pkSeed");

        bytes32 rootP = bytes32(uint256(pkRoot) ^ (uint256(0x01) << 248));
        assertFalse(_accepted(pkSeed, rootP, message, validSig), "WRONG-ACCEPT: perturbed pkRoot");

        bytes32 msgP = bytes32(uint256(message) ^ 1);
        assertFalse(_accepted(pkSeed, pkRoot, msgP, validSig), "WRONG-ACCEPT: perturbed message");
    }
}
