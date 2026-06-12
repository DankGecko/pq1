//! EIP-1271 / Solady nested-EIP-712 hash construction for the
//! `CMD_SIGN_OFFCHAIN` PersonalSign mode.
//!
//! Mirrors what `Solady.ERC1271._erc1271IsValidSignatureViaNestedEIP712`
//! computes on chain when no TypedDataSign appended-data is present in
//! the signature (which is always the case for sigs produced by this
//! firmware — our `SignatureWrapper` carries no appended data, so the
//! on-chain dispatcher always falls into the PersonalSign branch).
//!
//! ```text
//!   prefixed   = keccak256("\x19Ethereum Signed Message:\n" || itoa(len) || msg)
//!   structHash = keccak256(_PERSONAL_SIGN_TYPEHASH || prefixed)
//!   domainSep  = keccak256(EIP712_DOMAIN_TYPEHASH ||
//!                          keccak256("PQSmartWallet") ||
//!                          keccak256("1") ||
//!                          chainId ||
//!                          verifyingContract)
//!   final      = keccak256("\x19\x01" || domainSep || structHash)
//! ```
//!
//! `verifyingContract` is the proxy address derived from the bootstrap
//! C10 pubkey for `account_index` via the same CREATE2 formula
//! `cmd_get_wallet_address` uses; the bootstrap pubkey lives in
//! the secure-state cache across the unlock session.

use pqsigner_proto::{PQ_SMART_WALLET_FACTORY, PROXY_INIT_CODE_HASH};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

/// `keccak256("PersonalSign(bytes prefixed)")` — matches Solady's
/// `_PERSONAL_SIGN_TYPEHASH` in `lib/solady/src/accounts/ERC1271.sol`.
pub const PERSONAL_SIGN_TYPEHASH: [u8; 32] = [
    0x98, 0x3e, 0x65, 0xe5, 0x14, 0x8e, 0x57, 0x0c,
    0xd8, 0x28, 0xea, 0xd2, 0x31, 0xee, 0x75, 0x9a,
    0x8d, 0x79, 0x58, 0x72, 0x1a, 0x76, 0x8f, 0x93,
    0xbc, 0x44, 0x83, 0xba, 0x00, 0x5c, 0x32, 0xde,
];

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,
///                          address verifyingContract)")` — Solady's
/// `_DOMAIN_TYPEHASH` in `lib/solady/src/utils/EIP712.sol`.
pub const EIP712_DOMAIN_TYPEHASH: [u8; 32] = [
    0x8b, 0x73, 0xc3, 0xc6, 0x9b, 0xb8, 0xfe, 0x3d,
    0x51, 0x2e, 0xcc, 0x4c, 0xf7, 0x59, 0xcc, 0x79,
    0x23, 0x9f, 0x7b, 0x17, 0x9b, 0x0f, 0xfa, 0xca,
    0xa9, 0xa7, 0x5d, 0x52, 0x2b, 0x39, 0x40, 0x0f,
];

/// `keccak256("PQSmartWallet")` — the `name` field on
/// `PQSmartWallet._domainNameAndVersion`.
pub const NAME_HASH: [u8; 32] = [
    0x38, 0x5f, 0x8e, 0x06, 0xf7, 0x4d, 0x47, 0x93,
    0x2d, 0xe0, 0x6f, 0xb7, 0x65, 0x0c, 0x82, 0x75,
    0x1c, 0xef, 0x05, 0xac, 0xf6, 0xc1, 0xe7, 0xb5,
    0x0d, 0x9f, 0x82, 0x06, 0x84, 0x0d, 0xf7, 0x2f,
];

/// `keccak256("1")` — the `version` field on
/// `PQSmartWallet._domainNameAndVersion`.
pub const VERSION_HASH: [u8; 32] = [
    0xc8, 0x9e, 0xfd, 0xaa, 0x54, 0xc0, 0xf2, 0x0c,
    0x7a, 0xdf, 0x61, 0x28, 0x82, 0xdf, 0x09, 0x50,
    0xf5, 0xa9, 0x51, 0x63, 0x7e, 0x03, 0x07, 0xcd,
    0xcb, 0x4c, 0x67, 0x2f, 0x29, 0x8b, 0x8b, 0xc6,
];

/// Compute the CREATE2 proxy address from the bootstrap C10 pubkey
/// halves.
///
/// `pk_seed_32 || pk_root_32` are the same 64 bytes
/// `derive_c10_master_keypair_from_entropy` returns; the helper at
/// `cmd_get_wallet_address::run` uses the identical formula.
#[must_use]
pub fn proxy_address(pk_seed_32: &[u8; 32], pk_root_32: &[u8; 32]) -> [u8; 20] {
    let mut salt_in = [0u8; 64];
    salt_in[..32].copy_from_slice(pk_seed_32);
    salt_in[32..].copy_from_slice(pk_root_32);
    let salt: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(salt_in);
        h.finalize().into()
    };
    let mut pre = [0u8; 1 + 20 + 32 + 32];
    pre[0] = 0xff;
    pre[1..21].copy_from_slice(&PQ_SMART_WALLET_FACTORY);
    pre[21..53].copy_from_slice(&salt);
    pre[53..85].copy_from_slice(&PROXY_INIT_CODE_HASH);
    let digest: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(pre);
        h.finalize().into()
    };
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&digest[12..]);
    addr
}

/// EIP-712 domain separator for the wallet at `verifying_contract` on
/// `chain_id`, using the firmware-baked `(name, version)` constants.
#[must_use]
pub fn domain_separator(chain_id: u64, verifying_contract: &[u8; 20]) -> [u8; 32] {
    // abi.encode(typehash, nameHash, versionHash, chainId, verifyingContract)
    // — five 32-byte slots.
    let mut buf = [0u8; 5 * 32];
    buf[..32].copy_from_slice(&EIP712_DOMAIN_TYPEHASH);
    buf[32..64].copy_from_slice(&NAME_HASH);
    buf[64..96].copy_from_slice(&VERSION_HASH);
    // chainId left-padded to uint256.
    buf[96 + 24..128].copy_from_slice(&chain_id.to_be_bytes());
    // verifyingContract left-padded to address (20-byte right-aligned in 32).
    buf[128 + 12..160].copy_from_slice(verifying_contract);
    // one-shot keccak over the assembled buffer (byte-identical to the
    // incremental form; routed through the tx-core one-shot so the Aeneas
    // model is `keccak256_pure(buf)` — see contracts/verification §33 rank 3).
    pqsigner_tx_core::hash::keccak256(&buf)
}

/// `prefixed = keccak256("\x19Ethereum Signed Message:\n" || itoa(len) || msg)`.
#[must_use]
pub fn personal_sign_prefixed_hash(msg: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(b"\x19Ethereum Signed Message:\n");
    let mut len_buf = [0u8; 20];
    let n = decimal_str(msg.len(), &mut len_buf);
    h.update(&len_buf[..n]);
    h.update(msg);
    h.finalize().into()
}

/// Solady's `replaySafeHash` — the nested-EIP-712 wrap of an
/// already-final 32-byte digest `final_hash` (the exact value a dapp
/// passes to `isValidSignature`). This is the PersonalSign-workflow
/// wrap WITHOUT any inner EIP-191 prefix:
///
/// ```text
///   structHash = keccak256(PERSONAL_SIGN_TYPEHASH || final_hash)
///   final      = keccak256("\x19\x01" || domainSep || structHash)
/// ```
///
/// matching `Solady.ERC1271._erc1271IsValidSignatureViaNestedEIP712`'s
/// PersonalSign branch (`lib/solady/src/accounts/ERC1271.sol:240-290`):
/// when our `SignatureWrapper` carries no appended TypedDataSign data
/// the on-chain dispatcher computes
/// `_hashTypedData(keccak256(PERSONAL_SIGN_TYPEHASH, hash))` and verifies
/// the C10 sig against THAT. So a firmware sig over `replay_safe_hash(H)`
/// validates when a dapp calls `isValidSignature(H, sig)`.
///
/// # Why this exists (security — raw32 UserOp-forgery fix)
///
/// The firmware MUST perform this nesting itself for every off-chain
/// signing kind (RAW32 + EIP712_TYPED) rather than letting the companion
/// supply a pre-nested 32-byte value. The on-chain Type 1/2 UserOp path
/// verifies a slot/bootstrap C10 sig over a **bare** SHA-256
/// `sphincsDigest` (`PQSmartWallet.sphincsDigest`). A firmware that
/// bare-signs a companion-chosen 32-byte value is therefore a
/// UserOp-forgery oracle: `raw32(sphincsDigest(drainOp))` would be a
/// valid Type 2 signature, draining the wallet behind a blind "raw
/// 32-byte" page. Routing every off-chain hash through
/// `replay_safe_hash` guarantees the signed value is keccak-nested with
/// this wallet's EIP-712 domain and can never coincide with a SHA-256
/// `sphincsDigest`.
#[must_use]
pub fn replay_safe_hash(
    chain_id: u64,
    verifying_contract: &[u8; 20],
    final_hash: &[u8; 32],
) -> [u8; 32] {
    // structHash = keccak256(PERSONAL_SIGN_TYPEHASH || final_hash)
    let mut sbuf = [0u8; 64];
    sbuf[..32].copy_from_slice(&PERSONAL_SIGN_TYPEHASH);
    sbuf[32..64].copy_from_slice(final_hash);
    let struct_hash = pqsigner_tx_core::hash::keccak256(&sbuf);

    // final = keccak256("\x19\x01" || domainSep || structHash)
    let domain_sep = domain_separator(chain_id, verifying_contract);
    let mut fbuf = [0u8; 66];
    fbuf[..2].copy_from_slice(b"\x19\x01");
    fbuf[2..34].copy_from_slice(&domain_sep);
    fbuf[34..66].copy_from_slice(&struct_hash);
    pqsigner_tx_core::hash::keccak256(&fbuf)
}

/// Final hash signed by the firmware on the PersonalSign workflow.
///
/// Equivalent to
/// `replay_safe_hash(chain_id, vc, &personal_sign_prefixed_hash(msg))`:
/// the message is EIP-191 personal-sign-prefixed first, then nested. A
/// standard dapp computes `H = personal_sign_prefixed_hash(msg)` and
/// calls `isValidSignature(H, sig)`, so this round-trips on chain.
#[must_use]
pub fn personal_sign_replay_safe_hash(
    chain_id: u64,
    verifying_contract: &[u8; 20],
    msg: &[u8],
) -> [u8; 32] {
    let prefixed = personal_sign_prefixed_hash(msg);
    replay_safe_hash(chain_id, verifying_contract, &prefixed)
}

/// Format `n` into `out` as left-aligned ASCII decimal. Returns the
/// number of digits written. `out` must be ≥ 20 bytes (covers u64).
fn decimal_str(mut n: usize, out: &mut [u8]) -> usize {
    if n == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0usize;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    for j in 0..i {
        out[j] = tmp[i - 1 - j];
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: NAME_HASH = keccak256("PQSmartWallet")
    #[test]
    fn name_hash_is_keccak_of_pqsmartwallet() {
        let expected: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"PQSmartWallet");
            h.finalize().into()
        };
        assert_eq!(NAME_HASH, expected);
    }

    /// Sanity: VERSION_HASH = keccak256("1")
    #[test]
    fn version_hash_is_keccak_of_1() {
        let expected: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"1");
            h.finalize().into()
        };
        assert_eq!(VERSION_HASH, expected);
    }

    /// Sanity: PERSONAL_SIGN_TYPEHASH = keccak256("PersonalSign(bytes prefixed)")
    #[test]
    fn personal_sign_typehash_is_correct() {
        let expected: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"PersonalSign(bytes prefixed)");
            h.finalize().into()
        };
        assert_eq!(PERSONAL_SIGN_TYPEHASH, expected);
    }

    /// Sanity: EIP712_DOMAIN_TYPEHASH matches the standard string.
    #[test]
    fn eip712_domain_typehash_is_correct() {
        let expected: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(
                b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
            );
            h.finalize().into()
        };
        assert_eq!(EIP712_DOMAIN_TYPEHASH, expected);
    }

    /// `replay_safe_hash(H)` equals Solady's PersonalSign-branch wrap of a
    /// raw 32-byte digest `H` — `keccak(0x1901 || domainSep ||
    /// keccak(PERSONAL_SIGN_TYPEHASH || H))`, with NO inner EIP-191 prefix.
    #[test]
    fn replay_safe_hash_matches_solady_nesting() {
        let chain_id: u64 = 8453;
        let verifying: [u8; 20] = [0xCDu8; 20];
        let h: [u8; 32] = [0x42u8; 32];

        let struct_hash: [u8; 32] = {
            let mut k = Keccak256::new();
            k.update(PERSONAL_SIGN_TYPEHASH);
            k.update(h);
            k.finalize().into()
        };
        let dsep = domain_separator(chain_id, &verifying);
        let expected: [u8; 32] = {
            let mut k = Keccak256::new();
            k.update(b"\x19\x01");
            k.update(dsep);
            k.update(struct_hash);
            k.finalize().into()
        };

        assert_eq!(replay_safe_hash(chain_id, &verifying, &h), expected);
    }

    /// Refactor equivalence + kind=1 unchanged:
    /// `personal_sign_replay_safe_hash(msg) == replay_safe_hash(prefixed(msg))`.
    #[test]
    fn personal_sign_is_replay_safe_of_prefixed() {
        let chain_id: u64 = 1;
        let verifying: [u8; 20] = [0x11u8; 20];
        let msg = b"login nonce 12345";
        let prefixed = personal_sign_prefixed_hash(msg);
        assert_eq!(
            personal_sign_replay_safe_hash(chain_id, &verifying, msg),
            replay_safe_hash(chain_id, &verifying, &prefixed),
        );
    }

    /// Anti-forgery core: the firmware NEVER signs the companion's raw
    /// 32 bytes verbatim — `replay_safe_hash(X) != X` for any X. This is
    /// what prevents a `raw32` off-chain request with `X =
    /// sphincsDigest(drainOp)` from yielding a sig the on-chain Type 2
    /// path (which verifies a bare slot sig over `sphincsDigest`) accepts.
    #[test]
    fn replay_safe_hash_never_returns_input() {
        let chain_id: u64 = 8453;
        let verifying: [u8; 20] = [0x99u8; 20];
        // A value shaped exactly like an on-chain Type-2 digest target.
        let sphincs_digest_like: [u8; 32] = [0xABu8; 32];
        assert_ne!(
            replay_safe_hash(chain_id, &verifying, &sphincs_digest_like),
            sphincs_digest_like,
        );
        // Domain-bound: same H, different wallet/chain → different signed
        // value, so a captured sig can't be replayed across wallets/chains.
        assert_ne!(
            replay_safe_hash(1, &verifying, &sphincs_digest_like),
            replay_safe_hash(2, &verifying, &sphincs_digest_like),
        );
        assert_ne!(
            replay_safe_hash(chain_id, &[0x01u8; 20], &sphincs_digest_like),
            replay_safe_hash(chain_id, &[0x02u8; 20], &sphincs_digest_like),
        );
    }
}
