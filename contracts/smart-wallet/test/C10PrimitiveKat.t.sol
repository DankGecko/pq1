// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";

/// @title C10PrimitiveKat — on-chain leg of the per-primitive component KAT (ETHFALCON-port R1).
/// @notice Reconstructs each VERIFY-SIDE C10 tweakable-hash primitive exactly as
///         `SPHINCsC10Asm.sol` builds its SHA-256 preimage, computes it via the
///         SHA-256 precompile (address 0x02, the same the Yul verifier uses), and
///         asserts the committed golden output in `test/c10_primitive_kat_vectors.json`.
///
///         Third leg of the Rust <-> Python <-> Yul cross-check. Covers the 6 primitives the
///         on-chain verifier computes: th, th_pair, th_multi, h_msg, chain_hash, wots_digest.
///         (wots_secret / fors_secret are signing-side PRFs — the verifier never sees sk_seed
///         — so they are cross-checked Rust <-> Python only.)
///
///         HONEST SCOPE: validates that the documented preimage BYTE-LAYOUT is SHA-256-correct
///         and matches the golden numerically — complementing the positional transcription lint
///         (`check_c10_transcription.py`). The tie to the DEPLOYED verifier bytecode for these
///         primitives remains the whole-signature `SPHINCsC10AsmTest.test_verifyAllKatVectors`
///         (transitive) + the Lean `execC10Asm_eq` proof. These vectors localize a divergence to
///         the exact primitive; self-generated + N-way cross-checked, NOT externally conformant
///         (C10 shares only raw SHA-256 with any standard — that layer is anchored to NIST CAVP).
contract C10PrimitiveKatTest is Test {
    string internal json;

    function setUp() public {
        json = vm.readFile("test/c10_primitive_kat_vectors.json");
    }

    // ── helpers ─────────────────────────────────────────────────────────────
    // This Foundry build has no `[*]` array-wildcard support, so we read the
    // per-primitive count from the top-level `.counts` object and index each
    // element with a scalar getter (robust across parseJson type inference).
    function _count(string memory prim) internal view returns (uint256) {
        return vm.parseJsonUint(json, string.concat(".counts.", prim));
    }
    function _p(string memory prim, uint256 i, string memory field)
        internal
        pure
        returns (string memory)
    {
        return string.concat(".", prim, "[", vm.toString(i), "].", field);
    }
    function _bytes(string memory prim, uint256 i, string memory field)
        internal
        view
        returns (bytes memory)
    {
        return vm.parseJsonBytes(json, _p(prim, i, field));
    }
    function _uint(string memory prim, uint256 i, string memory field)
        internal
        view
        returns (uint256)
    {
        return vm.parseJsonUint(json, _p(prim, i, field));
    }
    function _label(string memory prim, uint256 i) internal view returns (string memory) {
        return vm.parseJsonString(json, _p(prim, i, "label"));
    }
    // load first 16/32 bytes of a dynamic `bytes` into a fixed word
    function _b16(bytes memory b) internal pure returns (bytes16 r) {
        require(b.length == 16, "expected 16-byte value");
        assembly {
            r := mload(add(b, 0x20))
        }
    }
    function _b32(bytes memory b) internal pure returns (bytes32 r) {
        require(b.length == 32, "expected 32-byte word");
        assembly {
            r := mload(add(b, 0x20))
        }
    }

    // ── th: sha256(seed || adrs || val)[0..16] ──────────────────────────────
    function test_th() public view {
        uint256 n = _count("th");
        assertGt(n, 0, "no th vectors");
        for (uint256 i = 0; i < n; i++) {
            bytes16 got = bytes16(
                sha256(abi.encodePacked(_bytes("th", i, "seed"), _bytes("th", i, "adrs"), _bytes("th", i, "val")))
            );
            assertEq(bytes32(got), bytes32(_b16(_bytes("th", i, "out"))), _label("th", i));
        }
    }

    // ── th_pair: sha256(seed || adrs || left || right)[0..16] ────────────────
    function test_thPair() public view {
        uint256 n = _count("th_pair");
        assertGt(n, 0, "no th_pair vectors");
        for (uint256 i = 0; i < n; i++) {
            bytes16 got = bytes16(
                sha256(
                    abi.encodePacked(
                        _bytes("th_pair", i, "seed"),
                        _bytes("th_pair", i, "adrs"),
                        _bytes("th_pair", i, "left"),
                        _bytes("th_pair", i, "right")
                    )
                )
            );
            assertEq(bytes32(got), bytes32(_b16(_bytes("th_pair", i, "out"))), _label("th_pair", i));
        }
    }

    // ── th_multi: sha256(seed || adrs || pad32(v0) || pad32(v1) ...)[0..16] ──
    function test_thMulti() public view {
        uint256 n = _count("th_multi");
        assertGt(n, 0, "no th_multi vectors");
        for (uint256 i = 0; i < n; i++) {
            bytes[] memory vals = vm.parseJsonBytesArray(json, _p("th_multi", i, "vals"));
            bytes memory enc = abi.encodePacked(_bytes("th_multi", i, "seed"), _bytes("th_multi", i, "adrs"));
            for (uint256 j = 0; j < vals.length; j++) {
                // each N-value (16 bytes) is right-zero-padded to a 32-byte word.
                enc = abi.encodePacked(enc, vals[j], bytes16(0));
            }
            bytes16 got = bytes16(sha256(enc));
            assertEq(bytes32(got), bytes32(_b16(_bytes("th_multi", i, "out"))), _label("th_multi", i));
        }
    }

    // ── h_msg: sha256(seed || root || R || msg || 0xFF..FF) (full 32 bytes) ──
    function test_hMsg() public view {
        uint256 n = _count("h_msg");
        assertGt(n, 0, "no h_msg vectors");
        for (uint256 i = 0; i < n; i++) {
            bytes32 got = sha256(
                abi.encodePacked(
                    _bytes("h_msg", i, "seed"),
                    _bytes("h_msg", i, "root"),
                    _bytes("h_msg", i, "r"),
                    _bytes("h_msg", i, "msg"),
                    bytes32(type(uint256).max)
                )
            );
            assertEq(got, _b32(_bytes("h_msg", i, "out")), _label("h_msg", i));
        }
    }

    // ── chain_hash: iterate th; chain_pos in ADRS bytes [24..28) = start+step ─
    function test_chainHash() public view {
        uint256 n = _count("chain_hash");
        assertGt(n, 0, "no chain_hash vectors");
        // chain_pos occupies ADRS bits [32..63] (bytes [24..28)); clear then set.
        uint256 CP_CLEAR = ~(uint256(0xFFFFFFFF) << 32);
        for (uint256 i = 0; i < n; i++) {
            bytes memory seed = _bytes("chain_hash", i, "seed");
            uint256 base = uint256(_b32(_bytes("chain_hash", i, "adrs_base"))) & CP_CLEAR;
            uint256 start = _uint("chain_hash", i, "start");
            uint256 steps = _uint("chain_hash", i, "steps");
            bytes32 cur = bytes32(_b16(_bytes("chain_hash", i, "val"))); // pad32(val)
            for (uint256 s = 0; s < steps; s++) {
                uint256 a = base | ((start + s) << 32);
                cur = bytes32(bytes16(sha256(abi.encodePacked(seed, bytes32(a), cur))));
            }
            assertEq(bytes32(bytes16(cur)), bytes32(_b16(_bytes("chain_hash", i, "out"))), _label("chain_hash", i));
        }
    }

    // ── wots_digest: sha256(seed || wotsAdrs || msg || count_u256) (32 bytes) ─
    function test_wotsDigest() public view {
        uint256 n = _count("wots_digest");
        assertGt(n, 0, "no wots_digest vectors");
        for (uint256 i = 0; i < n; i++) {
            bytes32 got = sha256(
                abi.encodePacked(
                    _bytes("wots_digest", i, "seed"),
                    _bytes("wots_digest", i, "wots_adrs"),
                    _bytes("wots_digest", i, "msg"),
                    _uint("wots_digest", i, "count")
                )
            );
            assertEq(got, _b32(_bytes("wots_digest", i, "out")), _label("wots_digest", i));
        }
    }
}
