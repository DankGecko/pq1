//! WYSIWYS end-to-end glue harness — render ↔ signed-buffer identity.
//!
//! # What this binds (and what it does not)
//!
//! The per-decoder and per-renderer layers are separately proven (Kani
//! byte-bindings, render-faithfulness host tests, golden grids), but until
//! 2026-07-06 the DISPATCHER GLUE had no harness: `pick_sign_pages` (the
//! priority ladder + the dispatcher-level value/gas splice gates) had never
//! executed on a host, and nothing bound "the pages the user confirms" to
//! "the bytes `cmd_sign_userop` hashes into the SPHINCS digest".
//!
//! This harness drives, for a corpus of frozen-wire sign requests
//! (`docs`/CLAUDE.md "Unified sign input"), BOTH consumers of the handler's
//! single parse:
//!
//!   * the display path — the REAL `pick_sign_pages` body (mounted at
//!     `super::dispatch`), followed by the handler's real splice gates in
//!     handler order (`enforce_paymaster_page`, mandatory From page,
//!     ERC-8213 fingerprint);
//!   * the signature path — the REAL `reconstruct_execute_calldata` +
//!     `compute_sphincs_digest_v06` (pqsigner-aa, the exact functions the
//!     handler calls at §10/§14).
//!
//! and then checks them against each other through an INDEPENDENT oracle:
//!
//!   * the signed `executeWithOffchainCount(...)` calldata is re-decoded by
//!     a test-local strict ABI decoder (selector recomputed from the
//!     Solidity signature via keccak — not imported from production);
//!   * every load-bearing value shown on the returned pages (recipient
//!     EIP-55 rows, ETH amount, token amount, selector hex, the ERC-8213
//!     fingerprint rows) is asserted equal to the value decoded FROM THE
//!     SIGNED BYTES — not from the wire input — so any glue-level
//!     divergence (render buffer A, hash buffer B) fails the suite;
//!   * the SPHINCS digest is recomputed by a test-local sha2 chain over the
//!     documented preimage, from the mirror-parsed wire fields and a
//!     test-local re-encoding of the exec calldata.
//!
//! The handler's inline glue (§6 `tx_for_display` construction, §8 render
//! order, §10/§14 digest inputs) cannot itself be linked on host (it lives
//! inside the `unsafe` CMSE handler), so this file REPLICATES it and pins
//! the replication against the handler source with whitespace-normalised
//! `include_str!` fragments — if the handler glue drifts, the pins fire.
//!
//! ## Honest scope — what this does NOT bind
//!
//!   * The handler's §4 wire parse itself (offsets → locals). Structurally
//!     the handler parses ONCE and both paths consume the same locals, so a
//!     parse bug shifts display and digest together; the wire offsets are
//!     additionally pinned by `nsc_sign_userop_pure_tests`.
//!   * Deploy / rotation extras (initCode, Type-1 `addOwnerBytes` digest)
//!     and the batch handler's per-tx nonce/digest loop.
//!   * Lossy display conversions, permanent residuals by design:
//!     `display_nonce` shows only `nonce[24..32]` (the 64-bit seq; the
//!     192-bit key is not rendered) and `display_gas_limit` is a saturated
//!     sum. The digest commits the full values.
//!   * CoW v3 / Safe v1 (approveHash) / ERC-7730 ladder rungs (need heavier
//!     fixtures; their verify+bind layers carry their own host suites).
//!   * pages → pixels (`confirm_checked`, LCD) — te-2 golden-grid + the
//!     firmware `ui/golden.rs` gate own that layer.

#![cfg(test)]

use sha2::{Digest as _, Sha256};
use sha3::{Digest as _, Keccak256};

use super::dispatch::pick_sign_pages;
use super::erc8213;
use super::value_page::{
    enforce_from_page, enforce_paymaster_page, enforce_target_page, from_page_proof,
    target_page_proof,
};
use super::Pages;
use crate::aa::userop::{
    compute_sphincs_digest_v06, reconstruct_execute_calldata, sha256_bytes,
    AaUserOpParamsV06Sha256, SHA256_EMPTY,
};
use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use crate::tx::eip1559::{Eip1559Tx, U256, UserOpDisplayFields};
use crate::ui::DISPLAY_COLS;
use sphincs_tz_shared::{EXEC_TRANSACTION_SELECTOR, SIGN_USEROP_HEADER_LEN};

// ─────────────────────────────────────────────────────────────────────
// Wire corpus: the frozen "Unified sign input" layout
// ─────────────────────────────────────────────────────────────────────

/// A sign request in the frozen wire layout (header fields only — the
/// trailers are out of scope for the ladder rungs this corpus drives;
/// absent trailers are legal).
#[derive(Clone)]
struct WireSignRequest {
    chain_id: u64,
    account_index: u32,
    slot_index: u32,
    sender: [u8; 20],
    entry_point: [u8; 20],
    nonce: [u8; 32],
    call_gas_limit: [u8; 32],
    verification_gas_limit: [u8; 32],
    pre_verification_gas: [u8; 32],
    max_fee_per_gas: [u8; 32],
    max_priority_fee_per_gas: [u8; 32],
    paymaster_and_data_hash: [u8; 32],
    to: [u8; 20],
    value: [u8; 32],
    data: Vec<u8>,
}

fn be_u256_from_u64(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

impl WireSignRequest {
    /// A plausible normal (non-deploy, non-rotation) T2 sign request.
    fn base() -> Self {
        WireSignRequest {
            chain_id: 8453, // Base
            account_index: 0,
            slot_index: 0,
            sender: [0x51; 20],
            entry_point: [0x5F; 20],
            nonce: be_u256_from_u64(7),
            call_gas_limit: be_u256_from_u64(200_000),
            verification_gas_limit: be_u256_from_u64(3_000_000),
            pre_verification_gas: be_u256_from_u64(60_000),
            max_fee_per_gas: be_u256_from_u64(30_000_000_000), // 30 gwei
            max_priority_fee_per_gas: be_u256_from_u64(1_500_000_000),
            paymaster_and_data_hash: SHA256_EMPTY,
            to: [0x12; 20],
            value: [0u8; 32],
            data: Vec::new(),
        }
    }

    /// Encode per the frozen "Unified sign input" offset table. Written
    /// from the spec, NOT from the handler source.
    fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; SIGN_USEROP_HEADER_LEN + self.data.len()];
        buf[0..8].copy_from_slice(&self.chain_id.to_be_bytes());
        // flags: no INCLUDE_INIT_CODE / REGISTER_SLOT; account index in bits
        // 29..22, slot index in bits 21..0.
        let flags: u32 = ((self.account_index & 0xff) << 22)
            | (self.slot_index & 0x003F_FFFF);
        buf[8..12].copy_from_slice(&flags.to_be_bytes());
        buf[12..32].copy_from_slice(&self.sender);
        buf[32..52].copy_from_slice(&self.entry_point);
        buf[52..84].copy_from_slice(&self.nonce);
        buf[84..116].copy_from_slice(&self.call_gas_limit);
        buf[116..148].copy_from_slice(&self.verification_gas_limit);
        buf[148..180].copy_from_slice(&self.pre_verification_gas);
        buf[180..212].copy_from_slice(&self.max_fee_per_gas);
        buf[212..244].copy_from_slice(&self.max_priority_fee_per_gas);
        buf[244..276].copy_from_slice(&self.paymaster_and_data_hash);
        buf[276..296].copy_from_slice(&self.to);
        buf[296..328].copy_from_slice(&self.value);
        buf[328..330].copy_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf[330..].copy_from_slice(&self.data);
        buf
    }
}

/// Independent mirror parse of the frozen wire layout. Deliberately a
/// SECOND implementation of the offset table (assertions between this
/// and the builder catch harness self-inconsistency; the handler's own
/// offsets are pinned by `nsc_sign_userop_pure_tests`).
struct MirrorParsed {
    chain_id: u64,
    account_index: u32,
    slot_index: u32,
    sender: [u8; 20],
    entry_point: [u8; 20],
    nonce: [u8; 32],
    gas: [[u8; 32]; 5], // call, verification, pre_verification, max_fee, max_prio
    paymaster_and_data_hash: [u8; 32],
    to: [u8; 20],
    value: [u8; 32],
    inner: Vec<u8>,
}

fn mirror_parse(buf: &[u8]) -> MirrorParsed {
    assert!(buf.len() >= SIGN_USEROP_HEADER_LEN, "short wire buffer");
    let take = |lo: usize, hi: usize| -> Vec<u8> { buf[lo..hi].to_vec() };
    let arr32 = |lo: usize| -> [u8; 32] { buf[lo..lo + 32].try_into().unwrap() };
    let arr20 = |lo: usize| -> [u8; 20] { buf[lo..lo + 20].try_into().unwrap() };
    let flags = u32::from_be_bytes(buf[8..12].try_into().unwrap());
    let data_len = u16::from_be_bytes(buf[328..330].try_into().unwrap()) as usize;
    assert_eq!(
        buf.len(),
        SIGN_USEROP_HEADER_LEN + data_len,
        "corpus buffers carry no trailers"
    );
    MirrorParsed {
        chain_id: u64::from_be_bytes(buf[0..8].try_into().unwrap()),
        account_index: (flags >> 22) & 0xff,
        slot_index: flags & 0x003F_FFFF,
        sender: arr20(12),
        entry_point: arr20(32),
        nonce: arr32(52),
        gas: [arr32(84), arr32(116), arr32(148), arr32(180), arr32(212)],
        paymaster_and_data_hash: arr32(244),
        to: arr20(276),
        value: arr32(296),
        inner: take(SIGN_USEROP_HEADER_LEN, SIGN_USEROP_HEADER_LEN + data_len),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Handler-glue replication (§6 display shim, §8 render order,
// §10/§14 digest inputs) — pinned against the handler source below.
// ─────────────────────────────────────────────────────────────────────

/// Fixed per-slot off-chain count for the corpus. In the handler this
/// comes from flash page 123; it is baked into the signed calldata but
/// (by design) never displayed — a documented residual of this harness.
const NEW_OFFCHAIN_COUNT: u64 = 41;

/// Mirror of the handler's private `u128_saturating_from_u256`.
fn u128_saturating_from_u256(bytes: &[u8; 32]) -> u128 {
    for &b in &bytes[0..16] {
        if b != 0 {
            return u128::MAX;
        }
    }
    u128::from_be_bytes(bytes[16..32].try_into().unwrap())
}

/// Replicates the handler's §6 `tx_for_display` construction.
fn tx_for_display(p: &MirrorParsed) -> Eip1559Tx {
    let display_nonce = u64::from_be_bytes(p.nonce[24..32].try_into().unwrap());
    let call_gas_u128 = u128_saturating_from_u256(&p.gas[0]);
    let ver_gas_u128 = u128_saturating_from_u256(&p.gas[1]);
    let pre_ver_u128 = u128_saturating_from_u256(&p.gas[2]);
    let display_gas_limit: u64 = ver_gas_u128
        .saturating_add(call_gas_u128)
        .saturating_add(pre_ver_u128)
        .min(u64::MAX as u128) as u64;
    Eip1559Tx {
        chain_id: p.chain_id,
        nonce: display_nonce,
        max_priority_fee_per_gas: U256(p.gas[4]),
        max_fee_per_gas: U256(p.gas[3]),
        gas_limit: display_gas_limit,
        to: Some(p.to),
        value: U256(p.value),
        data_len: p.inner.len(),
        access_list_count: 0,
        signing_hash: [0u8; 32],
        userop_fields: Some(UserOpDisplayFields {
            nonce: U256(p.nonce),
            call_gas_limit: U256(p.gas[0]),
            verification_gas_limit: U256(p.gas[1]),
            pre_verification_gas: U256(p.gas[2]),
        }),
    }
}

/// Optional verified contexts for the ladder rungs this corpus drives.
#[derive(Default)]
struct Contexts<'a> {
    erc20: Option<Erc20Metadata<'a>>,
    safe_exec_calldata: bool,
}

struct GlueOutcome {
    pages: Pages,
    t2_exec: Vec<u8>,
    digest: [u8; 32],
}

/// Drive both consumers of the (mirror-parsed) request exactly the way
/// `cmd_sign_userop::run` does: REAL `pick_sign_pages` → REAL
/// `enforce_paymaster_page` → REAL ERC-8213 fingerprint append for the
/// display side; REAL `reconstruct_execute_calldata` → REAL
/// `compute_sphincs_digest_v06` for the signature side.
fn drive_glue(p: &MirrorParsed, ctx: &Contexts<'_>) -> GlueOutcome {
    let tx = tx_for_display(p);
    let resolver = NameResolver::new();

    // Safe execTransaction context — through the REAL verifier the
    // handler calls (§7c-bis), not a hand-built struct.
    let safe_exec = if ctx.safe_exec_calldata {
        let v = crate::tx::eip712::safe::exec_decode::verify_and_bind_exec(
            &p.inner, p.chain_id, &p.to,
        );
        assert!(v.is_some(), "corpus execTransaction must verify");
        v
    } else {
        None
    };

    // §8 — render + splice gates, in handler order.
    let mut pages = pick_sign_pages(
        &tx,
        &p.inner,
        None,
        None,
        safe_exec.as_ref(),
        None,
        ctx.erc20.as_ref(),
        None,
        &resolver,
    )
    .expect("corpus renders must not refuse");
    enforce_paymaster_page(&mut pages, &p.paymaster_and_data_hash)
        .expect("paymaster page must fit");
    let signer_pages_before = pages.len;
    enforce_from_page(&mut pages, p.account_index, &p.sender)
        .expect("mandatory signer page must fit");
    assert_eq!(
        from_page_proof(&pages, signer_pages_before, p.account_index, &p.sender),
        crate::fi::OK_SENTINEL,
        "mandatory signer page must match parsed account/address"
    );
    let target_pages_before = pages.len;
    enforce_target_page(&mut pages, &p.to).expect("mandatory target page must fit");
    assert_eq!(
        target_page_proof(&pages, target_pages_before, &p.to),
        crate::fi::OK_SENTINEL,
        "mandatory target page must match parsed target"
    );
    let calldata_fingerprint = pqsigner_tx_core::erc8213::calldata_digest(&p.inner);
    erc8213::append_fingerprint_page(
        &mut pages,
        erc8213::Kind::CalldataDigest(calldata_fingerprint),
    )
    .expect("fingerprint pages must fit");

    // §10 + §14 — the signed bytes and the SPHINCS digest.
    let t2_owner_index = u64::from(p.slot_index) + 1;
    let t2_exec = reconstruct_execute_calldata(t2_owner_index, NEW_OFFCHAIN_COUNT, &tx, &p.inner)
        .expect("corpus exec calldata must reconstruct");
    let t2_call_digest = sha256_bytes(t2_exec.as_slice());
    let t2_params = AaUserOpParamsV06Sha256 {
        sender: p.sender,
        entry_point: p.entry_point,
        chain_id: p.chain_id,
        nonce: U256(p.nonce),
        init_code_digest: SHA256_EMPTY,
        call_gas_limit: U256(p.gas[0]),
        verification_gas_limit: U256(p.gas[1]),
        pre_verification_gas: U256(p.gas[2]),
        max_fee_per_gas: U256(p.gas[3]),
        max_priority_fee_per_gas: U256(p.gas[4]),
        paymaster_and_data_digest: p.paymaster_and_data_hash,
    };
    let digest = compute_sphincs_digest_v06(&t2_params, &t2_call_digest);

    GlueOutcome {
        pages,
        t2_exec: t2_exec.as_slice().to_vec(),
        digest,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Independent oracle — keccak/sha2 recomputations, test-local ABI
// decode of the SIGNED calldata, test-local EIP-55.
// ─────────────────────────────────────────────────────────────────────

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

fn selector_of(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4].try_into().unwrap()
}

struct OracleExec {
    owner_index: u64,
    new_offchain_count: u64,
    target: [u8; 20],
    value: [u8; 32],
    data: Vec<u8>,
}

/// Strict, test-local decode of `executeWithOffchainCount(uint256,
/// uint256,address,uint256,bytes)` calldata — the bytes whose SHA-256
/// is folded into the signed SPHINCS digest.
fn oracle_decode_execute(cd: &[u8]) -> OracleExec {
    let sel = selector_of("executeWithOffchainCount(uint256,uint256,address,uint256,bytes)");
    assert!(cd.len() >= 4 + 6 * 32, "exec calldata too short");
    assert_eq!(&cd[..4], &sel, "signed calldata selector mismatch");
    let word = |i: usize| -> [u8; 32] { cd[4 + i * 32..4 + (i + 1) * 32].try_into().unwrap() };
    let word_u64 = |w: [u8; 32]| -> u64 {
        assert!(w[..24].iter().all(|&b| b == 0), "u64 word overflow");
        u64::from_be_bytes(w[24..32].try_into().unwrap())
    };
    let owner_index = word_u64(word(0));
    let new_offchain_count = word_u64(word(1));
    let target_word = word(2);
    assert!(
        target_word[..12].iter().all(|&b| b == 0),
        "non-canonical target address padding"
    );
    let target: [u8; 20] = target_word[12..32].try_into().unwrap();
    let value = word(3);
    let offset = word_u64(word(4));
    assert_eq!(offset, 0xa0, "bytes head offset must be 0xa0");
    let data_len = word_u64(word(5)) as usize;
    let data_start = 4 + 6 * 32;
    let padded = (data_len + 31) & !31usize;
    assert_eq!(cd.len(), data_start + padded, "exact ABI framing");
    let data = cd[data_start..data_start + data_len].to_vec();
    assert!(
        cd[data_start + data_len..].iter().all(|&b| b == 0),
        "tail padding must be zero"
    );
    OracleExec {
        owner_index,
        new_offchain_count,
        target,
        value,
        data,
    }
}

/// Test-local re-encoding of the exec calldata from oracle values —
/// asserted byte-equal against the production reconstruction so the
/// digest recomputation below covers the whole preimage.
fn oracle_encode_execute(o: &OracleExec) -> Vec<u8> {
    let sel = selector_of("executeWithOffchainCount(uint256,uint256,address,uint256,bytes)");
    let padded = (o.data.len() + 31) & !31usize;
    let mut cd = vec![0u8; 4 + 6 * 32 + padded];
    cd[..4].copy_from_slice(&sel);
    cd[4 + 24..4 + 32].copy_from_slice(&o.owner_index.to_be_bytes());
    cd[36 + 24..36 + 32].copy_from_slice(&o.new_offchain_count.to_be_bytes());
    cd[68 + 12..68 + 32].copy_from_slice(&o.target);
    cd[100..132].copy_from_slice(&o.value);
    cd[132 + 31] = 0xa0;
    cd[164 + 24..164 + 32].copy_from_slice(&(o.data.len() as u64).to_be_bytes());
    cd[196..196 + o.data.len()].copy_from_slice(&o.data);
    cd
}

/// Test-local SPHINCS digest chain per the documented v0.6 preimage.
#[allow(clippy::too_many_arguments)]
fn oracle_sphincs_digest(p: &MirrorParsed, exec_calldata: &[u8]) -> [u8; 32] {
    let empty_sha: [u8; 32] = Sha256::digest([]).into();
    let call_data_digest: [u8; 32] = Sha256::digest(exec_calldata).into();
    let mut chain_word = [0u8; 32];
    chain_word[24..32].copy_from_slice(&p.chain_id.to_be_bytes());
    let mut h = Sha256::new();
    h.update(p.sender);
    h.update(p.nonce);
    h.update(empty_sha); // no initCode in the corpus
    h.update(call_data_digest);
    h.update(p.gas[0]);
    h.update(p.gas[1]);
    h.update(p.gas[2]);
    h.update(p.gas[3]);
    h.update(p.gas[4]);
    h.update(p.paymaster_and_data_hash);
    h.update(p.entry_point);
    h.update(chain_word);
    h.finalize().into()
}

/// ERC-8213 calldata digest recomputed test-locally:
/// `keccak256(uint256(len) || data)`.
fn oracle_erc8213_digest(data: &[u8]) -> [u8; 32] {
    let mut pre = vec![0u8; 32 + data.len()];
    pre[24..32].copy_from_slice(&(data.len() as u64).to_be_bytes());
    pre[32..].copy_from_slice(data);
    keccak256(&pre)
}

/// Test-local EIP-55 checksummed hex of an address (mixed case) — the
/// format `write_addr_full` paints when no name-DB entry matches.
fn oracle_eip55(addr: &[u8; 20]) -> String {
    let lower: String = addr.iter().map(|b| format!("{b:02x}")).collect();
    let h = keccak256(lower.as_bytes());
    lower
        .chars()
        .enumerate()
        .map(|(i, c)| {
            let nibble = (h[i / 2] >> (4 * (1 - (i % 2)))) & 0x0F;
            if c.is_ascii_alphabetic() && nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

// ─── Page-text helpers ───────────────────────────────────────────────

fn row_str(row: &[u8; DISPLAY_COLS]) -> String {
    let end = row.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
    String::from_utf8(row[..end].to_vec()).expect("rows are ASCII by construction")
}

/// All rows of all used pages, flattened in display order.
fn all_rows(pages: &Pages) -> Vec<String> {
    pages
        .as_slice()
        .iter()
        .flat_map(|page| page.iter().map(row_str))
        .collect()
}

fn rows_contain(rows: &[String], needle: &str) -> bool {
    rows.iter().any(|r| r.contains(needle))
}

/// The three rows `write_addr_full` paints for `addr` (EIP-55, split
/// 0x+14 / 16 / 10) — recomputed test-locally.
fn oracle_addr_rows(addr: &[u8; 20]) -> [String; 3] {
    let hex = oracle_eip55(addr);
    [
        format!("0x{}", &hex[0..14]),
        hex[14..30].to_string(),
        hex[30..40].to_string(),
    ]
}

/// Assert the full 40-hex EIP-55 address is painted somewhere on the
/// pages as three consecutive rows within one page (rows 1..3, after a
/// label row).
fn assert_addr_shown(pages: &Pages, addr: &[u8; 20], what: &str) {
    let want = oracle_addr_rows(addr);
    let found = pages.as_slice().iter().any(|page| {
        (0..2).any(|start| {
            row_str(&page[start + 1]) == want[0]
                && row_str(&page[start + 2]) == want[1]
                && page.len() > start + 3
                && row_str(&page[start + 3]) == want[2]
        }) || (row_str(&page[1]) == want[0]
            && row_str(&page[2]) == want[1]
            && row_str(&page[3]) == want[2])
    });
    assert!(
        found,
        "{what}: address rows {want:?} not found on any page:\n{:#?}",
        all_rows(pages)
    );
}

fn assert_signer_page_shown(pages: &Pages, account_index: u32, sender: &[u8; 20]) {
    let label = format!("Signer acct #{account_index}");
    let want = oracle_addr_rows(sender);
    let found = pages.as_slice().iter().any(|page| {
        row_str(&page[0]) == label
            && row_str(&page[1]) == want[0]
            && row_str(&page[2]) == want[1]
            && row_str(&page[3]) == want[2]
    });
    assert!(
        found,
        "signer page {label} + {want:?} not found:\n{:#?}",
        all_rows(pages)
    );
}

fn assert_target_page_shown(pages: &Pages, target: &[u8; 20]) {
    let want = oracle_addr_rows(target);
    let found = pages.as_slice().iter().any(|page| {
        row_str(&page[0]) == "Target contract:"
            && row_str(&page[1]) == want[0]
            && row_str(&page[2]) == want[1]
            && row_str(&page[3]) == want[2]
    });
    assert!(
        found,
        "mandatory target page {want:?} not found:\n{:#?}",
        all_rows(pages)
    );
}

/// Assert the final two pages are the ERC-8213 banner + the exact hash
/// rows of `digest` (lowercase hex, 8 bytes per row).
fn assert_fingerprint_pages(pages: &Pages, digest: &[u8; 32]) {
    let slice = pages.as_slice();
    assert!(slice.len() >= 2, "need banner + hash page");
    let banner = &slice[slice.len() - 2];
    assert_eq!(row_str(&banner[0]), "8213 Fingerprint");
    assert_eq!(row_str(&banner[1]), "CalldataDigest");
    let hash_page = &slice[slice.len() - 1];
    for (i, row) in hash_page.iter().enumerate() {
        let want: String = digest[i * 8..(i + 1) * 8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            row_str(row),
            want,
            "fingerprint hash row {i} diverges from the SIGNED calldata digest"
        );
    }
}

/// Full differential check shared by every corpus flow: decode the
/// SIGNED bytes with the independent oracle and bind wire ↔ signed ↔
/// shown ↔ digest.
fn assert_core_bindings(p: &MirrorParsed, out: &GlueOutcome) -> OracleExec {
    // (1) The signed calldata decodes strictly and its embedded fields
    //     equal the wire fields the display shim was built from.
    let oracle = oracle_decode_execute(&out.t2_exec);
    assert_eq!(oracle.owner_index, u64::from(p.slot_index) + 1);
    assert_eq!(oracle.new_offchain_count, NEW_OFFCHAIN_COUNT);
    assert_eq!(oracle.target, p.to, "signed target != wire to");
    assert_eq!(oracle.value, p.value, "signed value != wire value");
    assert_eq!(oracle.data, p.inner, "signed data != wire inner data");

    // (2) Re-encoding the oracle view reproduces the production bytes
    //     exactly, so the digest recomputation covers the whole preimage.
    assert_eq!(
        oracle_encode_execute(&oracle),
        out.t2_exec,
        "independent exec re-encode != production reconstruct_execute_calldata"
    );

    // (3) Independent SPHINCS-digest recomputation from wire fields.
    assert_eq!(
        oracle_sphincs_digest(p, &out.t2_exec),
        out.digest,
        "independent digest chain != production compute_sphincs_digest_v06"
    );

    // (4) The ERC-8213 fingerprint pages show the digest OF THE SIGNED
    //     BYTES (recomputed test-locally from the oracle-decoded data).
    assert_fingerprint_pages(&out.pages, &oracle_erc8213_digest(&oracle.data));

    // (5) The signed target is painted in full EIP-55 on some page.
    assert_addr_shown(&out.pages, &oracle.target, "signed exec target");

    // (6) The account selector and mnemonic-derived/bound sender are painted
    //     together on their mandatory full-address identity page.
    assert_signer_page_shown(&out.pages, p.account_index, &p.sender);
    assert_target_page_shown(&out.pages, &oracle.target);

    oracle
}

// ─────────────────────────────────────────────────────────────────────
// Corpus flows
// ─────────────────────────────────────────────────────────────────────

#[test]
fn wysiwys_value_transfer_binds_pages_to_signed_bytes() {
    let mut req = WireSignRequest::base();
    req.value = be_u256_from_u64(1_000_000_000_000_000_000); // 1 ETH
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());
    let oracle = assert_core_bindings(&p, &out);

    let rows = all_rows(&out.pages);
    // The signed native value renders with the fixed-width ETH format on
    // the renderer's Value page AND the dispatcher's loud splice page.
    assert!(oracle.value == be_u256_from_u64(1_000_000_000_000_000_000));
    assert!(rows_contain(&rows, "Send ETH?"), "value-transfer banner");
    assert!(rows_contain(&rows, "1.000000 ETH"), "signed 1 ETH amount shown");
    assert!(rows_contain(&rows, "! NATIVE ETH"), "dispatcher value splice");
    // No paymaster in this flow → no paymaster page.
    assert!(!rows_contain(&rows, "PAYMASTER"), "no phantom paymaster page");
}

#[test]
fn wysiwys_erc20_unknown_transfer_binds_recipient_from_signed_bytes() {
    let recipient: [u8; 20] = [0xB7; 20];
    let mut req = WireSignRequest::base();
    req.to = [0xAA; 20]; // token contract
    let mut data = vec![0u8; 4 + 64];
    data[..4].copy_from_slice(&selector_of("transfer(address,uint256)"));
    data[4 + 12..4 + 32].copy_from_slice(&recipient);
    data[4 + 32 + 24..4 + 64].copy_from_slice(&500_000u64.to_be_bytes());
    req.data = data;
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());
    let oracle = assert_core_bindings(&p, &out);

    // Independent decode of the transfer INSIDE the signed calldata.
    assert_eq!(&oracle.data[..4], &selector_of("transfer(address,uint256)"));
    let signed_recipient: [u8; 20] = oracle.data[16..36].try_into().unwrap();
    assert_eq!(signed_recipient, recipient);

    let rows = all_rows(&out.pages);
    assert!(rows_contain(&rows, "! Unknown token"), "unknown-token banner");
    assert!(rows_contain(&rows, "Recipient:"), "recipient label");
    assert_addr_shown(&out.pages, &signed_recipient, "signed ERC-20 recipient");
}

#[test]
fn wysiwys_erc20_known_metadata_binds_amount_and_recipient() {
    let token = [0xAA; 20];
    let recipient: [u8; 20] = [0xB7; 20];
    let mut req = WireSignRequest::base();
    req.to = token;
    let mut data = vec![0u8; 4 + 64];
    data[..4].copy_from_slice(&selector_of("transfer(address,uint256)"));
    data[4 + 12..4 + 32].copy_from_slice(&recipient);
    data[4 + 32 + 24..4 + 64].copy_from_slice(&500_000u64.to_be_bytes());
    req.data = data;
    let p = mirror_parse(&req.encode());
    let ctx = Contexts {
        erc20: Some(Erc20Metadata {
            chain_id: 8453,
            contract: token,
            decimals: 6,
            name: b"USD Coin",
            symbol: b"USDC",
        }),
        ..Default::default()
    };
    let out = drive_glue(&p, &ctx);
    let oracle = assert_core_bindings(&p, &out);

    // 500000 raw at 6 decimals = 0.5 — fixed 6-frac policy.
    let signed_amount = u64::from_be_bytes(oracle.data[60..68].try_into().unwrap());
    assert_eq!(signed_amount, 500_000);
    let rows = all_rows(&out.pages);
    assert!(rows_contain(&rows, "0.500000 USDC"), "signed token amount shown");
    let signed_recipient: [u8; 20] = oracle.data[16..36].try_into().unwrap();
    assert_addr_shown(&out.pages, &signed_recipient, "signed ERC-20 recipient");
}

/// The dispatcher's direct-path metadata gate: metadata for token T must
/// NOT label a transfer whose signed target is token Y (glue-level
/// mis-attribution — audit 2026-06-28).
#[test]
fn wysiwys_erc20_metadata_contract_mismatch_downgrades_to_unknown() {
    let mut req = WireSignRequest::base();
    req.to = [0x99; 20]; // signed target: token Y
    let mut data = vec![0u8; 4 + 64];
    data[..4].copy_from_slice(&selector_of("transfer(address,uint256)"));
    data[4 + 12..4 + 32].copy_from_slice(&[0xB7; 20]);
    data[4 + 32 + 24..4 + 64].copy_from_slice(&500_000u64.to_be_bytes());
    req.data = data;
    let p = mirror_parse(&req.encode());
    let ctx = Contexts {
        // Metadata claims token T ([0xAA;20]) — does NOT match tx.to.
        erc20: Some(Erc20Metadata {
            chain_id: 8453,
            contract: [0xAA; 20],
            decimals: 6,
            name: b"USD Coin",
            symbol: b"USDC",
        }),
        ..Default::default()
    };
    let out = drive_glue(&p, &ctx);
    assert_core_bindings(&p, &out);

    let rows = all_rows(&out.pages);
    assert!(
        rows_contain(&rows, "! Unknown token"),
        "mismatched metadata must downgrade to the unknown-token render"
    );
    assert!(
        !rows_contain(&rows, "USDC"),
        "token T's symbol must never label a transfer signed for token Y"
    );
}

#[test]
fn wysiwys_blind_sign_shows_signed_selector_and_fingerprint() {
    let mut req = WireSignRequest::base();
    req.value = be_u256_from_u64(250_000_000_000_000_000); // 0.25 ETH rides along
    req.data = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03];
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());
    let oracle = assert_core_bindings(&p, &out);

    let rows = all_rows(&out.pages);
    // Selector row is painted from the same bytes that got signed.
    assert_eq!(&oracle.data[..4], &[0xde, 0xad, 0xbe, 0xef]);
    assert!(rows_contain(&rows, "Sel: 0xdeadbeef"), "signed selector shown");
    // The native value on a blind-signed call is the C-1 drain class —
    // the dispatcher splice must fire.
    assert!(rows_contain(&rows, "! NATIVE ETH"), "value splice on blind sign");
    assert!(rows_contain(&rows, "0.250000 ETH"), "signed 0.25 ETH shown");
}

/// Runtime regression for the firmware-pinned known-call membership gate.
///
/// WETH `deposit()` is present in the compiled ERC-7730 catalogue. A hostile
/// companion that strips (or supplies a malformed proof for) that descriptor
/// leaves `erc7730 == None` at dispatch. The request must hard-refuse instead
/// of downgrading the known call to a reassuring value/typed/blind page set.
#[test]
fn wysiwys_known_weth_deposit_without_descriptor_hard_refuses() {
    let mut req = WireSignRequest::base();
    req.chain_id = 1;
    req.to = [
        0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e,
        0x5c, 0x4f, 0x27, 0xea, 0xd9, 0x08, 0x3c, 0x75, 0x6c, 0xc2,
    ];
    req.data = vec![0xd0, 0xe3, 0x0d, 0xb0]; // deposit()
    let parsed = mirror_parse(&req.encode());
    let tx = tx_for_display(&parsed);
    let resolver = NameResolver::new();

    let outcome = pick_sign_pages(
        &tx,
        &parsed.inner,
        None,
        None,
        None,
        None, // companion omitted / failed to verify the descriptor
        None,
        None,
        &resolver,
    );
    assert!(
        outcome.is_err(),
        "known WETH deposit without its Merkle proof must never reach blind-sign"
    );
}

#[test]
fn wysiwys_safe_exec_renders_safe_surface_with_spliced_gas_pages() {
    let safe_addr = [0x5A; 20];
    let inner_to: [u8; 20] = [0xC3; 20];
    let inner_value = be_u256_from_u64(50_000_000_000_000_000); // 0.05 ETH
    let exec_calldata = encode_exec_transaction(
        &inner_to,
        &inner_value,
        &[],
        0,
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 20],
        &[0u8; 20],
        &[0x41; 65],
    );
    let mut req = WireSignRequest::base();
    req.to = safe_addr;
    req.data = exec_calldata;
    let p = mirror_parse(&req.encode());
    let ctx = Contexts {
        safe_exec_calldata: true,
        ..Default::default()
    };
    let out = drive_glue(&p, &ctx);
    let oracle = assert_core_bindings(&p, &out);

    // Independent re-decode of the SafeTx fields from the SIGNED bytes.
    assert_eq!(&oracle.data[..4], &EXEC_TRANSACTION_SELECTOR);
    let signed_inner_to: [u8; 20] = oracle.data[4 + 12..4 + 32].try_into().unwrap();
    let signed_inner_value: [u8; 32] = oracle.data[4 + 32..4 + 64].try_into().unwrap();
    assert_eq!(signed_inner_to, inner_to);
    assert_eq!(signed_inner_value, inner_value);

    let rows = all_rows(&out.pages);
    // The Safe surface renders (not a generic blind-sign of the exec
    // calldata) and the inner target/value come from the signed bytes.
    assert!(
        rows.iter().any(|r| r.contains("Safe")),
        "Safe surface banner expected:\n{rows:#?}"
    );
    assert_addr_shown(&out.pages, &signed_inner_to, "signed Safe inner target");
    assert!(rows_contain(&rows, "0.050000 ETH"), "signed inner ETH shown");
    // The dispatcher's gas splice must fire for the Safe surface (the
    // renderer itself is gas-less; hiding fees is the 2026-06-19 fee-bomb).
    assert!(rows_contain(&rows, "Max fee:"), "gas pages spliced for Safe");
    assert!(rows_contain(&rows, "Worst-case:"), "worst-case fee page spliced");
}

#[test]
fn wysiwys_paymaster_page_spliced_iff_hash_nonempty() {
    // With a paymaster: loud page present, and the digest commits the hash.
    let mut req = WireSignRequest::base();
    req.value = be_u256_from_u64(1);
    req.paymaster_and_data_hash = [0x77; 32];
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());
    assert_core_bindings(&p, &out);
    let rows = all_rows(&out.pages);
    assert!(
        rows.iter().any(|r| r.contains("PAYMASTER")),
        "paymaster page must be spliced when the signed hash is non-empty:\n{rows:#?}"
    );

    // Digest sensitivity: the same request without the paymaster signs a
    // DIFFERENT digest (the hash is inside the signed preimage).
    let mut req2 = req.clone();
    req2.paymaster_and_data_hash = SHA256_EMPTY;
    let p2 = mirror_parse(&req2.encode());
    let out2 = drive_glue(&p2, &Contexts::default());
    assert_core_bindings(&p2, &out2);
    assert_ne!(out.digest, out2.digest, "paymaster hash must move the digest");
    let rows2 = all_rows(&out2.pages);
    assert!(
        !rows2.iter().any(|r| r.contains("PAYMASTER")),
        "no phantom paymaster page when the signed hash is SHA256_EMPTY"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Divergence probes (non-vacuity): every byte the user sees moves the
// digest, and every displayed-fact flip is caught.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn divergence_probe_inner_data_byte_flip_moves_digest_and_fingerprint() {
    let mut req = WireSignRequest::base();
    req.data = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03];
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());

    let mut req2 = req.clone();
    req2.data[6] ^= 0x01; // flip one byte of the signed inner data
    let p2 = mirror_parse(&req2.encode());
    let out2 = drive_glue(&p2, &Contexts::default());

    assert_ne!(out.digest, out2.digest, "inner-data flip must move the digest");
    // The fingerprint page — the display-side commitment to the signed
    // calldata — must move with it.
    let fp1 = all_rows(&out.pages);
    let fp2 = all_rows(&out2.pages);
    let tail1: Vec<_> = fp1.iter().rev().take(4).collect();
    let tail2: Vec<_> = fp2.iter().rev().take(4).collect();
    assert_ne!(tail1, tail2, "fingerprint page must move with the signed bytes");
}

#[test]
fn divergence_probe_recipient_flip_moves_both_pages_and_digest() {
    let mut req = WireSignRequest::base();
    req.value = be_u256_from_u64(1_000_000_000_000_000_000);
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());

    let mut req2 = req.clone();
    req2.to[19] ^= 0x01;
    let p2 = mirror_parse(&req2.encode());
    let out2 = drive_glue(&p2, &Contexts::default());

    assert_ne!(out.digest, out2.digest, "target flip must move the digest");
    // The displayed To-page rows must differ (the flipped address renders
    // differently) — a dispatcher that kept showing the OLD address while
    // signing the new one is exactly the divergence this harness exists
    // to catch.
    assert_addr_shown(&out.pages, &p.to, "original target");
    assert_addr_shown(&out2.pages, &p2.to, "flipped target");
    assert_target_page_shown(&out.pages, &p.to);
    assert_target_page_shown(&out2.pages, &p2.to);
    assert_ne!(
        oracle_addr_rows(&p.to),
        oracle_addr_rows(&p2.to),
        "sanity: rows differ"
    );
}

#[test]
fn divergence_probe_value_flip_moves_value_page_and_digest() {
    let mut req = WireSignRequest::base();
    req.value = be_u256_from_u64(1_000_000_000_000_000_000); // 1 ETH
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());

    let mut req2 = req.clone();
    req2.value = be_u256_from_u64(2_000_000_000_000_000_000); // 2 ETH
    let p2 = mirror_parse(&req2.encode());
    let out2 = drive_glue(&p2, &Contexts::default());

    assert_ne!(out.digest, out2.digest, "value flip must move the digest");
    let rows = all_rows(&out.pages);
    let rows2 = all_rows(&out2.pages);
    assert!(rows_contain(&rows, "1.000000 ETH") && !rows_contain(&rows, "2.000000 ETH"));
    assert!(rows_contain(&rows2, "2.000000 ETH") && !rows_contain(&rows2, "1.000000 ETH"));
}

#[test]
fn divergence_probe_account_flip_moves_mandatory_from_page() {
    let req = WireSignRequest::base();
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());

    let mut req2 = req.clone();
    req2.account_index = 1;
    let p2 = mirror_parse(&req2.encode());
    let out2 = drive_glue(&p2, &Contexts::default());

    assert_signer_page_shown(&out.pages, 0, &p.sender);
    assert_signer_page_shown(&out2.pages, 1, &p2.sender);
    assert_ne!(
        out.pages.as_slice(),
        out2.pages.as_slice(),
        "changing only account_index must change confirmed display bytes"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Handler-source pins — hold the replicated glue honest. If
// `cmd_sign_userop.rs` changes how it builds `tx_for_display`, routes
// the render, or assembles the digest inputs, these fire and the
// replication above must be re-audited.
// ─────────────────────────────────────────────────────────────────────

const HANDLER_SRC: &str = include_str!("../nsc/cmd_sign_userop.rs");

fn squash_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn pin_handler_display_shim_construction_matches_replication() {
    let src = squash_ws(HANDLER_SRC);
    assert!(
        src.contains(&squash_ws(
            "let tx_for_display = Eip1559Tx { chain_id, nonce: display_nonce,
             max_priority_fee_per_gas: display_max_prio, max_fee_per_gas: display_max_fee,
             gas_limit: display_gas_limit, to: Some(to_address), value: U256(value),
             data_len, access_list_count: 0, signing_hash: [0u8; 32],
             userop_fields: Some(UserOpDisplayFields { nonce: U256(nonce),
             call_gas_limit: U256(call_gas_limit),
             verification_gas_limit: U256(verification_gas_limit),
             pre_verification_gas: U256(pre_verification_gas), }), };"
        )),
        "handler §6 tx_for_display construction drifted — re-audit tx_for_display() here"
    );
}

#[test]
fn pin_handler_render_and_digest_glue_matches_replication() {
    let src = squash_ws(HANDLER_SRC);
    for (frag, why) in [
        (
            "let mut pages = match pick_sign_pages( &tx_for_display, inner_data,
             zk_v3_verified.as_ref(), safe_v1_verified.as_ref(), safe_exec_verified.as_ref(),
             erc7730_verified.as_ref(), verified_meta.as_ref(), selector_verified.as_ref(),
             &resolver, )",
            "handler §8 render dispatch drifted",
        ),
        (
            "if crate::tx::display::enforce_paymaster_page(&mut pages, &paymaster_and_data_hash).is_err()",
            "handler §8 paymaster splice drifted",
        ),
        (
            "if crate::tx::display::enforce_from_page(&mut pages, account_index, &sender).is_err()",
            "handler §8 mandatory signer-page splice drifted",
        ),
        (
            "if crate::tx::display::from_page_proof( &pages, signer_pages_before,
             account_index, &sender, ) != crate::fi::OK_SENTINEL",
            "handler §8 signer-page FI proof drifted",
        ),
        (
            "if crate::tx::display::enforce_target_page(&mut pages, &to_address).is_err()",
            "handler §8 mandatory target-page splice drifted",
        ),
        (
            "if crate::tx::display::target_page_proof(&pages, target_pages_before, &to_address)
             != crate::fi::OK_SENTINEL",
            "handler §8 target-page FI proof drifted",
        ),
        (
            "let calldata_fingerprint = pqsigner_tx_core::erc8213::calldata_digest(inner_data);",
            "handler §8 fingerprint input drifted",
        ),
        (
            "let t2_exec = match reconstruct_execute_calldata( t2_owner_index,
             new_offchain_count, &tx_for_display, inner_data, )",
            "handler §10 signed-calldata inputs drifted",
        ),
        (
            "let t2_call_digest = sha256_bytes(t2_exec.as_slice());",
            "handler §14 calldata digest drifted",
        ),
        (
            "let t2_digest = compute_sphincs_digest_v06(&t2_params, &t2_call_digest);",
            "handler §14 digest call drifted",
        ),
        (
            "let t2_params = AaUserOpParamsV06Sha256 { sender, entry_point, chain_id,
             nonce: U256(type2_nonce), init_code_digest: t2_init_code_digest,
             call_gas_limit: U256(call_gas_limit),
             verification_gas_limit: U256(verification_gas_limit),
             pre_verification_gas: U256(pre_verification_gas),
             max_fee_per_gas: U256(max_fee_per_gas),
             max_priority_fee_per_gas: U256(max_priority_fee_per_gas),
             paymaster_and_data_digest: paymaster_and_data_hash, };",
            "handler §14 digest params drifted",
        ),
        (
            "let t2_owner_index = (slot_index as u64) + 1;",
            "handler §10 owner-index derivation drifted",
        ),
    ] {
        assert!(src.contains(&squash_ws(frag)), "{why}: `{frag}`");
    }
}

/// The exec selector the on-chain wallet dispatches on equals
/// keccak("executeWithOffchainCount(uint256,uint256,address,uint256,bytes)")
/// — pins the production encoder's magic constant to the Solidity
/// signature (independent recomputation).
#[test]
fn pin_exec_selector_matches_solidity_signature() {
    let tx = tx_for_display(&mirror_parse(&WireSignRequest::base().encode()));
    let exec = reconstruct_execute_calldata(1, 0, &tx, &[]).unwrap();
    assert_eq!(
        &exec.as_slice()[..4],
        &selector_of("executeWithOffchainCount(uint256,uint256,address,uint256,bytes)"),
    );
    // Same pin for the Safe exec selector used by the corpus.
    assert_eq!(
        EXEC_TRANSACTION_SELECTOR,
        selector_of(
            "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)"
        ),
    );
}

// ─────────────────────────────────────────────────────────────────────
// Safe execTransaction test encoder (test-local; layout per the Safe
// v1.3.0 ABI, independent of `exec_decode.rs`).
// ─────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn encode_exec_transaction(
    to: &[u8; 20],
    value: &[u8; 32],
    data: &[u8],
    operation: u8,
    safe_tx_gas: &[u8; 32],
    base_gas: &[u8; 32],
    gas_price: &[u8; 32],
    gas_token: &[u8; 20],
    refund_receiver: &[u8; 20],
    signatures: &[u8],
) -> Vec<u8> {
    let head_len = 10 * 32;
    let data_padded = (data.len() + 31) & !31usize;
    let sigs_padded = (signatures.len() + 31) & !31usize;
    let data_off = head_len;
    let sigs_off = head_len + 32 + data_padded;
    let total = 4 + head_len + 32 + data_padded + 32 + sigs_padded;
    let mut cd = vec![0u8; total];
    cd[..4].copy_from_slice(&EXEC_TRANSACTION_SELECTOR);
    let head = &mut cd[4..];
    let w = |i: usize| i * 32;
    head[w(0) + 12..w(0) + 32].copy_from_slice(to);
    head[w(1)..w(1) + 32].copy_from_slice(value);
    head[w(2) + 24..w(2) + 32].copy_from_slice(&(data_off as u64).to_be_bytes());
    head[w(3) + 31] = operation;
    head[w(4)..w(4) + 32].copy_from_slice(safe_tx_gas);
    head[w(5)..w(5) + 32].copy_from_slice(base_gas);
    head[w(6)..w(6) + 32].copy_from_slice(gas_price);
    head[w(7) + 12..w(7) + 32].copy_from_slice(gas_token);
    head[w(8) + 12..w(8) + 32].copy_from_slice(refund_receiver);
    head[w(9) + 24..w(9) + 32].copy_from_slice(&(sigs_off as u64).to_be_bytes());
    // tails
    let data_tail = 4 + head_len;
    cd[data_tail + 24..data_tail + 32].copy_from_slice(&(data.len() as u64).to_be_bytes());
    cd[data_tail + 32..data_tail + 32 + data.len()].copy_from_slice(data);
    let sigs_tail = 4 + sigs_off;
    cd[sigs_tail + 24..sigs_tail + 32].copy_from_slice(&(signatures.len() as u64).to_be_bytes());
    cd[sigs_tail + 32..sigs_tail + 32 + signatures.len()].copy_from_slice(signatures);
    cd
}
