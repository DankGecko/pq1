//! Wire format and verifier for the ERC20 metadata bundle that the
//! non-secure world attaches to a `CMD_SIGN_USEROP` request when its local
//! ERC20 DB has a hit on `(chain_id, contract)`.
//!
//! The bundle is what makes "trust the firmware DB" meet "store the
//! DB in non-secure rodata to save secure flash". The non-secure
//! world reads from a much larger embedded blob, picks the entry that
//! matches the recipient contract, and forwards the canonical
//! metadata bytes plus a Merkle proof. The secure world re-derives
//! the leaf hash and walks the proof up to the supplied
//! `root: &[u8; 32]` (typically the embedded `db_roots::ERC20_DB_ROOT`)
//! before letting any of the supplied bytes anywhere near the trusted
//! UI.
//!
//! ## Wire layout
//!
//! ```text
//!   chain_id      u64 LE                  ( 8 B)
//!   contract      [u8; 20]                (20 B)
//!   decimals      u8                      ( 1 B)
//!   name_len      u8                      ( 1 B)
//!   name          [u8; name_len]
//!   symbol_len    u8                      ( 1 B)
//!   symbol        [u8; symbol_len]
//!   leaf_index    u32 LE                  ( 4 B)
//!   proof_depth   u32 LE                  ( 4 B)
//!   proof         [u8; proof_depth * 32]
//! ```
//!
//! Strings are length-prefixed bytes; the verifier rejects any
//! `name_len`/`symbol_len` greater than 64 bytes (cosmetic display
//! limit) and rejects any non-ASCII byte (anti-spoof: a malicious DB
//! row can't sneak homoglyphs onto the OLED). It also rejects any
//! `decimals` greater than [`MAX_DISPLAY_DECIMALS`] — an over-large
//! `decimals` would scale a balance-draining amount down toward
//! `0.000000` on the trusted display (a WYSIWYS hidden-magnitude
//! hazard; see the constant's docs).
//!
//! ## Cross-checks before trusting the metadata
//!
//! After Merkle verification succeeds, the caller MUST also check that
//! the bundle's `chain_id` and `contract` fields match the parsed
//! `tx.chain_id` and `tx.to` it's about to sign. Without this, NS
//! could supply a perfectly valid `(USDC mainnet, 6)` bundle while
//! signing a transaction targeting an attacker contract on a different
//! chain. The cross-check lives at the call site, not here, so the
//! bundle stays a pure verifier.

use super::merkle::verify_proof;
use crate::wire::{is_clean_ascii, read_u32_le, read_u64_le};

/// Decoded + Merkle-verified ERC20 metadata. Borrows from the gateway
/// buffer the bundle was copied into; the lifetime is tied to that
/// buffer's stack frame.
#[derive(Clone, Copy, Debug)]
pub struct Erc20Metadata<'a> {
    pub chain_id: u64,
    pub contract: [u8; 20],
    pub decimals: u8,
    pub name: &'a [u8],
    pub symbol: &'a [u8],
}

/// Maximum total bundle size, used to bound the secure-side stack
/// buffer that holds the copy. 8+20+1+1+64+1+32+4+4 + 32 levels of
/// proof = ~1.2 KB. Capped well below MAX_TX_LEN.
pub const MAX_ERC20_BUNDLE_LEN: usize = 64 + 1024 + 32;

/// Cosmetic upper bound on token name and symbol lengths. Anything
/// the OLED can't render is pointless and a foothold for spoofing.
const MAX_DISPLAY_FIELD: usize = 64;

/// Defence-in-depth upper bound on a token's `decimals`.
///
/// The trusted-UI amount formatter renders `amount / 10^decimals`, so an
/// over-large `decimals` shrinks a cryptographically-bound, balance-draining
/// `amount` toward `0.000000` on the OLED — a WYSIWYS hidden-magnitude
/// hazard if the offloaded DB ever commits an inflated value. The DB
/// `decimals` is sourced from third-party token lists (`build_erc20_db.py`
/// takes `t["decimals"]` verbatim), **not** an on-chain `decimals()` call,
/// so a buggy/poisoned list entry is the realistic threat.
///
/// `decimals` is itself Merkle-bound (it is part of the leaf), so this cap
/// is not a binding check — a forged value already fails `verify_proof`.
/// It is a curation-independent floor against *absurd / garbage* values
/// (corrupt bytes, list typos, obviously-bogus 50–255 entries): a bundle
/// above the cap fails verification and the caller falls back to the
/// raw-hex render (`AddrHex` for CoW legs, `Erc20Unknown` for transfers),
/// which shows magnitude faithfully.
///
/// 36 is 2× the ERC-20 standard (18) and comfortably above the highest
/// value in real clear-signing use (bridged NEAR = 24), so no legitimate
/// token is rejected. NOTE: a cap cannot catch *in-range* inflation (e.g.
/// a DB `decimals` of 24 for a token whose on-chain value is 18) — closing
/// that requires a build-time on-chain `decimals()` cross-check.
const MAX_DISPLAY_DECIMALS: u8 = 36;

/// Verify a bundle copied from the NS gateway buffer against `root`.
/// On success, returns the decoded metadata. On failure, returns
/// `None`.
///
/// `bundle` MUST be the exact bytes the non-secure world wrote — no
/// length prefix, no padding. The caller is responsible for handling
/// the optional/length-prefix wrapping at the gateway boundary.
pub fn verify_erc20_bundle<'a>(bundle: &'a [u8], root: &[u8; 32]) -> Option<Erc20Metadata<'a>> {
    let mut off = 0usize;

    // Header fields.
    if bundle.len() < off + 8 + 20 + 1 + 1 {
        return None;
    }
    let chain_id = read_u64_le(bundle, off)?;
    off += 8;
    let contract: [u8; 20] = bundle.get(off..off + 20)?.try_into().ok()?;
    off += 20;
    let decimals = *bundle.get(off)?;
    off += 1;

    // Defence-in-depth WYSIWYS floor: refuse an absurd `decimals` rather
    // than let the display scale a draining `amount` down to "0.000000".
    // `decimals` is Merkle-bound below, so a forged value cannot pass
    // regardless; rejecting here also fails fast on a corrupt/garbage leaf.
    // See `MAX_DISPLAY_DECIMALS` for why a cap is a floor (not a complete
    // fix) against in-range inflation.
    if decimals > MAX_DISPLAY_DECIMALS {
        return None;
    }

    // Name (length-prefixed).
    let name_len = *bundle.get(off)? as usize;
    off += 1;
    if name_len == 0 || name_len > MAX_DISPLAY_FIELD {
        return None;
    }
    let name = bundle.get(off..off + name_len)?;
    off += name_len;
    if !is_clean_ascii(name) {
        return None;
    }

    // Symbol (length-prefixed).
    if bundle.len() < off + 1 {
        return None;
    }
    let symbol_len = *bundle.get(off)? as usize;
    off += 1;
    if symbol_len == 0 || symbol_len > MAX_DISPLAY_FIELD {
        return None;
    }
    let symbol = bundle.get(off..off + symbol_len)?;
    off += symbol_len;
    if !is_clean_ascii(symbol) {
        return None;
    }

    // Merkle proof header.
    if bundle.len() < off + 4 + 4 {
        return None;
    }
    let leaf_index = read_u32_le(bundle, off)? as usize;
    off += 4;
    let proof_depth = read_u32_le(bundle, off)? as usize;
    off += 4;

    // Practical bound: 4 GiB worth of leaves never happen, and
    // accepting unbounded depths means a hostile NS can force the
    // secure verifier into a long hash chain.
    if proof_depth > 32 {
        return None;
    }

    let proof_size = proof_depth * 32;
    if bundle.len() != off + proof_size {
        // Reject any trailing bytes — we want exactly the bundle.
        return None;
    }
    let proof = bundle.get(off..off + proof_size)?;

    // 1. Re-derive the canonical leaf bytes from the supplied fields.
    //    MUST match dbgen::erc20::canonical_erc20_leaf byte-for-byte.
    //    `name_len`/`symbol_len` are each bounded by `MAX_DISPLAY_FIELD`
    //    above, so `canonical_len` cannot exceed the buffer size.
    let canonical_len = 8 + 20 + 1 + 1 + name_len + 1 + symbol_len;
    let mut canonical = [0u8; 8 + 20 + 1 + 1 + MAX_DISPLAY_FIELD + 1 + MAX_DISPLAY_FIELD];
    let mut p = 0usize;
    canonical[p..p + 8].copy_from_slice(&chain_id.to_le_bytes());
    p += 8;
    canonical[p..p + 20].copy_from_slice(&contract);
    p += 20;
    canonical[p] = decimals;
    p += 1;
    canonical[p] = name_len as u8;
    p += 1;
    canonical[p..p + name_len].copy_from_slice(name);
    p += name_len;
    canonical[p] = symbol_len as u8;
    p += 1;
    canonical[p..p + symbol_len].copy_from_slice(symbol);
    p += symbol_len;
    debug_assert_eq!(p, canonical_len);

    // 2. Walk the Merkle proof up to the supplied root.
    if !verify_proof(
        &canonical[..canonical_len],
        leaf_index,
        proof,
        proof_depth,
        root,
    ) {
        return None;
    }

    Some(Erc20Metadata {
        chain_id,
        contract,
        decimals,
        name,
        symbol,
    })
}

