//! Render-faithfulness tests for the Safe transaction renderer
//! (`crate::tx::display::safe_display`), mounted host-side 2026-06-30.
//!
//! Closes the second half of item 1 of the 2026-06-29 coverage audit:
//! `safe_display` (the largest trusted-display renderer, 1575 LoC) had ZERO
//! host render tests — its ERC-20-in-Safe / exec / multiSend-record text was
//! pinned only by page *count*, so wrong text at the right count passed.
//!
//! These tests go through the REAL `verify_and_bind_trailer` decode (not a
//! bypass) to build a `VerifiedSafeV1`, then render it and assert the
//! ERC-20-inner amount DIGITS + the recipient HEX + the Safe address — the
//! same WYSIWYS bug class the audit flagged. The amount/recipient are read
//! from the bound `raw_data` (which `verify_and_bind_trailer` cross-checks
//! against the canonical `data_hash`), so the assertions bind the SIGNED
//! bytes to the screen. `negative_*_nonvacuous` flips the inner amount.

extern crate alloc;

use alloc::vec::Vec;

use sphincs_tz_shared::{
    APPROVE_HASH_CALLDATA_LEN, APPROVE_HASH_SELECTOR, SAFE_OFF_CHAIN_ID, SAFE_OFF_DATA_HASH,
    SAFE_OFF_OPERATION, SAFE_OFF_NONCE, SAFE_OFF_SAFE_ADDRESS, SAFE_OFF_TO, SAFE_V1_CANONICAL_LEN,
};

use super::safe_display::render_safe_v1_pages;
use super::Pages;
use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use crate::tx::eip712::keccak;
use crate::tx::eip712::safe::{compute_safe_tx_hash, verify_and_bind_trailer};
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

const CHAIN_ID: u64 = 1;
const SAFE_ADDR: [u8; 20] = [
    0x5a, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
];
// The inner ERC-20 token contract (matches the `Erc20Metadata.contract` so the
// renderer classifies the inner as a known-token transfer).
const TOKEN: [u8; 20] = [
    0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e, 0xb0, 0xce,
    0x36, 0x06, 0xeb, 0x48,
];

fn row_str(row: &[u8; DISPLAY_COLS]) -> String {
    for &b in row.iter() {
        assert!((0x20..=0x7e).contains(&b), "non-printable byte {b:#x} on a rendered row");
    }
    row.iter().map(|&b| b as char).collect::<String>().trim_end().to_string()
}

fn all_text(pages: &Pages) -> String {
    (0..pages.len)
        .flat_map(|p| (0..DISPLAY_ROWS).map(move |r| (p, r)))
        .map(|(p, r)| row_str(&pages.buf[p][r]))
        .collect::<Vec<_>>()
        .join("\n")
}

/// All ASCII-hex digits across every row of every page, lowercased — so a
/// full 40-hex address (split across rows, with "0x"/space framing) matches.
fn all_hex(pages: &Pages) -> String {
    all_text(pages)
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_lowercase()
}

/// Build the verifier trailer bundle + approveHash calldata for an inner
/// `transfer(recipient, amount)` on `TOKEN`. Returns `(bundle, calldata)`;
/// `verify_and_bind_trailer` borrows `raw_data` out of `bundle`, so the caller
/// must keep `bundle` alive across the render.
fn build_trailer(recipient: [u8; 20], amount: u64) -> (Vec<u8>, [u8; APPROVE_HASH_CALLDATA_LEN]) {
    // Inner calldata: ERC-20 transfer(recipient, amount) = selector ‖ arg1 ‖ arg2.
    let mut raw = [0u8; 68];
    raw[0..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]); // transfer(address,uint256)
    raw[16..36].copy_from_slice(&recipient); // 20-byte recipient, right-aligned
    raw[60..68].copy_from_slice(&amount.to_be_bytes()); // amount in the low 8 bytes

    // Canonical SafeTx whose data_hash binds the inner calldata.
    let mut c = [0u8; SAFE_V1_CANONICAL_LEN];
    c[SAFE_OFF_CHAIN_ID..SAFE_OFF_CHAIN_ID + 8].copy_from_slice(&CHAIN_ID.to_be_bytes());
    c[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20].copy_from_slice(&SAFE_ADDR);
    c[SAFE_OFF_TO..SAFE_OFF_TO + 20].copy_from_slice(&TOKEN);
    c[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32].copy_from_slice(&keccak(&raw));
    c[SAFE_OFF_OPERATION] = 0; // CALL
    let mut nonce = [0u8; 32];
    nonce[31] = 42;
    c[SAFE_OFF_NONCE..SAFE_OFF_NONCE + 32].copy_from_slice(&nonce);

    // approveHash(safeTxHash) calldata (the on-chain call being signed).
    let h = compute_safe_tx_hash(&c).expect("safe tx hash");
    let mut cd = [0u8; APPROVE_HASH_CALLDATA_LEN];
    cd[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    cd[4..36].copy_from_slice(&h);

    // Trailer bundle = canonical ‖ raw_len(2 BE) ‖ raw_data.
    let mut b = Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2 + raw.len());
    b.extend_from_slice(&c);
    b.extend_from_slice(&(raw.len() as u16).to_be_bytes());
    b.extend_from_slice(&raw);
    (b, cd)
}

fn usdc_meta() -> Erc20Metadata<'static> {
    Erc20Metadata { chain_id: CHAIN_ID, contract: TOKEN, decimals: 6, name: b"USD Coin", symbol: b"USDC" }
}

#[test]
fn positive_safe_erc20_inner_binds_amount_recipient_and_safe_address() {
    let recipient: [u8; 20] = core::array::from_fn(|i| 0xabu8.wrapping_add(i as u8));
    let (bundle, cd) = build_trailer(recipient, 250_000_000); // 250.000000 USDC
    let v = verify_and_bind_trailer(&bundle, &cd, CHAIN_ID, &SAFE_ADDR)
        .expect("trailer must verify+bind");
    let meta = usdc_meta();
    let resolver = NameResolver::new();
    let pages = render_safe_v1_pages(&v, None, Some(&meta), &resolver).expect("render");

    let text = all_text(&pages);
    let hex = all_hex(&pages);

    // Inner ERC-20 amount digits + symbol (read from the bound raw_data).
    assert!(text.contains("250"), "Safe-wrapped ERC-20 amount must render 250; pages:\n{text}");
    assert!(text.contains("USDC"), "inner token symbol must render; pages:\n{text}");

    // Full 40-hex recipient (the destination of funds).
    let recip_hex: String = recipient.iter().map(|b| format!("{b:02x}")).collect();
    assert!(hex.contains(&recip_hex), "recipient {recip_hex} must render in full");

    // The Safe address must be shown (the user must see WHICH Safe is signing).
    let safe_hex: String = SAFE_ADDR.iter().map(|b| format!("{b:02x}")).collect();
    assert!(hex.contains(&safe_hex), "the Safe address {safe_hex} must render");
}

#[test]
fn positive_safe_golden_grid_hash() {
    // te-2: full-grid golden over the canonical Safe-wrapped ERC-20 render.
    // The per-substring asserts above check that specific fields render; this
    // binds EVERY rendered cell, so a layout / divider / truncation / page-
    // count regression anywhere on the page trips here even if the checked
    // substrings survive. Re-bless GOLDEN only for an INTENTIONAL layout change.
    let recipient: [u8; 20] = core::array::from_fn(|i| 0xabu8.wrapping_add(i as u8));
    let (bundle, cd) = build_trailer(recipient, 250_000_000);
    let v = verify_and_bind_trailer(&bundle, &cd, CHAIN_ID, &SAFE_ADDR).expect("bind");
    let meta = usdc_meta();
    let resolver = NameResolver::new();
    let pages = render_safe_v1_pages(&v, None, Some(&meta), &resolver).expect("render");
    let h = super::golden_grid_hash(&pages);

    // Non-vacuity: a different inner amount MUST change the digest, proving
    // the hash actually binds rendered content (not a constant).
    let (b2, cd2) = build_trailer(recipient, 999_000_000);
    let v2 = verify_and_bind_trailer(&b2, &cd2, CHAIN_ID, &SAFE_ADDR).expect("bind");
    let h2 =
        super::golden_grid_hash(&render_safe_v1_pages(&v2, None, Some(&meta), &resolver).expect("render"));
    assert_ne!(h, h2, "golden hash must bind rendered content (amount change did not move it)");

    const GOLDEN: [u8; 32] = [
        164, 215, 245, 20, 203, 214, 152, 231, 107, 230, 63, 80, 106, 79, 146, 71, 56, 161, 72,
        99, 45, 196, 201, 250, 246, 124, 168, 70, 35, 203, 23, 76,
    ];
    assert_eq!(h, GOLDEN, "Safe render golden changed — re-bless if intentional. got={h:?}");
}

#[test]
fn negative_safe_erc20_amount_nonvacuous() {
    // Flip the inner amount: the rendered digits must track the bound raw_data,
    // not be a constant. 250 vs 777 USDC; neither appears in the fixed addresses.
    let recipient = [0x33u8; 20];
    let render_amount = |amount: u64| -> String {
        let (bundle, cd) = build_trailer(recipient, amount);
        let v = verify_and_bind_trailer(&bundle, &cd, CHAIN_ID, &SAFE_ADDR).expect("verify");
        let meta = usdc_meta();
        let resolver = NameResolver::new();
        let pages = render_safe_v1_pages(&v, None, Some(&meta), &resolver).expect("render");
        all_text(&pages)
    };
    let t250 = render_amount(250_000_000); // 250 USDC
    let t777 = render_amount(777_000_000); // 777 USDC
    assert!(t250.contains("250") && !t250.contains("777"));
    assert!(t777.contains("777") && !t777.contains("250"));
}
