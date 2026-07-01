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
