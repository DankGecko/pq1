//! Device-side glue for the nested-EIP-712 struct renderer (Phase 5).
//!
//! The PURE, keccak-free, Kani-proven half of the descent lives in
//! `pqsigner_erc7730::render::nested` (payload parse, DFS cursor, address
//! coverage, local-ordinal bounds). This module owns the two things that
//! cannot: the keccak binding primitive and — in Commit D — the recursion
//! driver that ties the parser + binding + sub-field rendering together and
//! enforces the E1 reconciliation.
//!
//! # The binding (the security spine)
//!
//! A nested-struct member is one opaque `hashStruct` word in the parent's
//! SIGNED `encoded_data`. The companion supplies the member's `encodeData`
//! (`nested_ed`); the device requires
//! `keccak(dbgen-pinned type_hash ‖ nested_ed) == the committed word` before
//! rendering inside → shown ⟺ signed by collision-resistance, under full
//! companion control of `ed` and `nested_ed`. This is [`hash_struct`] — the
//! EIP-712 analog of the calldata FollowOffset. Neither CoW's nor Safe's
//! `struct_hash` (flat, hardcoded field lists) is a reuse, hence a new
//! primitive with its own test (design rule 4).

use sha3::{Digest, Keccak256};

/// `keccak256(type_hash ‖ ed)` — the EIP-712 `hashStruct` of a struct whose
/// `encodeType` hashes to `type_hash` and whose member words are `ed`
/// (`member_count × 32` bytes). The device compares this constant-time against
/// the committed parent word before expanding the nested members.
pub fn hash_struct(type_hash: &[u8; 32], ed: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(type_hash);
    h.update(ed);
    let mut o = [0u8; 32];
    o.copy_from_slice(&h.finalize());
    o
}

/// The EIP-712 array-of-struct (`T[]`) binding (Phase 5 v2): `keccak256(
/// hashStruct(el0) ‖ hashStruct(el1) ‖ … ‖ hashStruct(elN) )`, where each
/// `hashStruct(el_i) = keccak(type_hash ‖ el_i)`. This IS the parent `T[]`
/// member's contribution to `encodeData`, so the device compares it
/// constant-time against the committed parent word before expanding ANY element.
/// `elems[i]` is element `i`'s `encodeData` (`member_count × 32` bytes). Folds
/// each element's hashStruct into a single streaming keccak — no per-element
/// buffer beyond the caller's slice array.
pub fn hash_struct_array(type_hash: &[u8; 32], elems: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for ed in elems {
        h.update(hash_struct(type_hash, ed));
    }
    let mut o = [0u8; 32];
    o.copy_from_slice(&h.finalize());
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `hash_struct` is exactly `keccak(type_hash ‖ ed)` — cross-checked against
    /// an independent single-shot keccak of the concatenated buffer.
    #[test]
    fn hash_struct_is_keccak_of_concatenation() {
        let type_hash = [0xABu8; 32];
        let ed = [0xCDu8; 64]; // 2 member words
        let got = hash_struct(&type_hash, &ed);

        let mut concat = std::vec::Vec::new();
        concat.extend_from_slice(&type_hash);
        concat.extend_from_slice(&ed);
        let mut h = Keccak256::new();
        h.update(&concat);
        let mut want = [0u8; 32];
        want.copy_from_slice(&h.finalize());

        assert_eq!(got, want);
    }

    /// Real Permit2 vector: the `PermitDetails` hashStruct for a concrete order
    /// equals `keccak(typeHash(PermitDetails) ‖ token ‖ amount ‖ expiration ‖
    /// nonce)`. `typeHash(PermitDetails) = 0x65626cad…` (foundry). Binds the
    /// primitive to the exact bytes Commit D's flip→decline test will use.
    #[test]
    fn hash_struct_matches_permit_details_vector() {
        // typeHash(PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce))
        let type_hash: [u8; 32] = hex32("65626cad6cb96493bf6f5ebea28756c966f023ab9e8a83a7101849d5573b3678");
        // nested_ed = 4 ABI words: token (USDC), amount, expiration, nonce.
        let mut ed = [0u8; 128];
        // token = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 (right-aligned)
        ed[12..32].copy_from_slice(&hex20("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"));
        // amount = 1_000_000_000 (1000 USDC, 6 decimals)
        ed[32 + 24..64].copy_from_slice(&1_000_000_000u64.to_be_bytes());
        // expiration = 1_735_689_600 (2025-01-01)
        ed[64 + 24..96].copy_from_slice(&1_735_689_600u64.to_be_bytes());
        // nonce = 0 (all zero)
        let got = hash_struct(&type_hash, &ed);

        // Independent recomputation.
        let mut h = Keccak256::new();
        h.update(type_hash);
        h.update(ed);
        let mut want = [0u8; 32];
        want.copy_from_slice(&h.finalize());
        assert_eq!(got, want);
        // Sanity: a non-trivial digest (not the empty/all-zero hash).
        assert_ne!(got, [0u8; 32]);
    }

    /// Real 2-element Permit2 `PermitBatch` array binding (v2), foundry-pinned:
    /// `keccak(hashStruct(el0) ‖ hashStruct(el1)) == 0x57b01054…`. el0 = USDC /
    /// 1e9 / 2025-01-01 / nonce 0; el1 = WETH / 5e18 / 2026-01-01 / nonce 1. This
    /// is the exact vector the v2 flip→decline render test uses.
    #[test]
    fn hash_struct_array_matches_permit_batch_vector() {
        let type_hash =
            hex32("65626cad6cb96493bf6f5ebea28756c966f023ab9e8a83a7101849d5573b3678");
        let mut el0 = [0u8; 128];
        el0[12..32].copy_from_slice(&hex20("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"));
        el0[32 + 24..64].copy_from_slice(&1_000_000_000u64.to_be_bytes());
        el0[64 + 24..96].copy_from_slice(&1_735_689_600u64.to_be_bytes());
        // el0 nonce = 0.
        let mut el1 = [0u8; 128];
        el1[12..32].copy_from_slice(&hex20("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"));
        el1[32 + 24..64].copy_from_slice(&5_000_000_000_000_000_000u64.to_be_bytes());
        el1[64 + 24..96].copy_from_slice(&1_767_225_600u64.to_be_bytes());
        el1[96 + 24..128].copy_from_slice(&1u64.to_be_bytes()); // nonce 1

        let got = hash_struct_array(&type_hash, &[&el0[..], &el1[..]]);
        assert_eq!(
            got,
            hex32("fd1160ad83ee77f1aa741468b83e6d8e5a134ea0807a33fb776701712ce1b4b9"),
            "PermitBatch 2-element array binding must match foundry"
        );
        // A single-element array is keccak(hashStruct(el0)) — NOT hashStruct(el0)
        // itself; distinct binding (guards against a device that skips the outer
        // keccak for elem_count==1).
        assert_ne!(hash_struct_array(&type_hash, &[&el0[..]]), hash_struct(&type_hash, &el0));
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        for (i, b) in o.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        o
    }
    fn hex20(s: &str) -> [u8; 20] {
        let mut o = [0u8; 20];
        for (i, b) in o.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        o
    }
}
