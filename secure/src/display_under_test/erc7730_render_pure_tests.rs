//! End-to-end render tests for the ERC-7730 / ERC-8213 display renderers.
//!
//! Each test builds a realistic transaction (chain + to + calldata),
//! verifies the firmware-pinned bundle via `verify_erc7730_bundle`, then
//! runs the on-device renderer at `super::erc7730::render_erc7730_pages`
//! and asserts the resulting 4-row × 16-col display pages line-by-line
//! against the strings a user would actually see on the device.
//!
//! Why this exists: existing tests cover the host pipeline (`dbgen`),
//! the bundle verifier, the path walker, the parameter parser, and the
//! per-formatter row primitives. Until now there was no test that
//! plumbed a full `(tx, calldata, descriptor) -> Pages -> rendered
//! strings` round-trip end-to-end. A regression that breaks the user-
//! visible row text (truncation, intent label, decimal alignment, ticker
//! lookup) would not have been caught by any unit test.
//!
//! Inputs are NOT hand-rolled IR fixtures — they come straight from the
//! seed-corpus JSON via `dbgen::erc7730::build_db`, the same pipeline
//! that produces the firmware-pinned `ERC7730_DESCRIPTORS_ROOT`. So
//! these tests would also catch a host-side compiler regression that
//! ships subtly broken IR into the catalog without anyone noticing,
//! since "broken IR" surfaces as a wrong rendered string.

use std::path::PathBuf;

use pqsigner_erc7730::bundle::{verify_erc7730_bundle, VerifiedDescriptor};
use pqsigner_erc7730::ir::{ContextKind, Erc7730Ir};
use pqsigner_tx_core::hash::keccak256;

use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::ui::DISPLAY_COLS;

use super::erc7730::render_erc7730_pages;
use super::erc8213::{append_fingerprint_page, Kind as Erc8213Kind};
use super::Pages;

// ───────────────────────────────────────────────────────────────────────
// One-shot seed-corpus build, cached across every test in this module.
// ───────────────────────────────────────────────────────────────────────

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Compile the checked-in seed corpus into a Merkle catalog. Doing this
/// per-test is cheap (the seed dir is now a tiny synthetic-only render-test
/// corpus) and keeps each test self-contained — no `static` / `OnceLock`
/// plumbing required.
fn build_seed() -> dbgen::erc7730::Erc7730BuildResult {
    let root = workspace_root();
    let dir = root.join("secure/data/erc7730");
    let policy = dir.join("policy.toml");
    dbgen::erc7730::build_db(&dir, &policy).expect("compile seed corpus")
}

/// The PROD catalog — the vendored upstream registry, built tolerantly
/// (the corpus switch). This is what `tools/companion-stub/erc7730_db.bin`
/// and the firmware-pinned `ERC7730_DESCRIPTORS_ROOT` are built from, so a
/// render test that exercises a REAL protocol descriptor (Aave/Tether/WETH/
/// wstETH/…) must drive it from THIS root, not a hand-authored duplicate.
///
/// The 776-leaf registry build is several hundred ms, and ~16 tests use it,
/// so memoize it in a `OnceLock` — built once per test binary, not per test.
/// Returns a `&'static`, so callers pass it straight to `find_leaf(res, …)`
/// (NOT `&res`) and read `res.blob` / `res.root` directly.
fn build_registry() -> &'static dbgen::erc7730::Erc7730BuildResult {
    static REGISTRY: std::sync::OnceLock<dbgen::erc7730::Erc7730BuildResult> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| {
        let root = workspace_root();
        let reg = root.join("secure/data/erc7730-registry");
        let policy = root.join("secure/data/erc7730/policy.toml");
        let (res, _skips) = dbgen::erc7730::build_db_tolerant(
            &reg.join("registry"),
            &policy,
            Some(&reg),
        )
        .expect("build registry corpus");
        res
    })
}

/// Locate a leaf by `(source filename, chain_id)` so a multi-chain
/// descriptor (USDT on mainnet vs Polygon) is unambiguous.
fn find_leaf<'a>(
    res: &'a dbgen::erc7730::Erc7730BuildResult,
    source_name: &str,
    chain_id: u64,
) -> &'a dbgen::erc7730::Emitted {
    res.entries
        .iter()
        .find(|e| {
            e.chain_id == chain_id
                && e.source
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map_or(false, |n| n == source_name)
        })
        .unwrap_or_else(|| {
            panic!(
                "no leaf for {source_name} on chain {chain_id}; entries: {:?}",
                res.entries
                    .iter()
                    .map(|e| (e.source.display().to_string(), e.chain_id))
                    .collect::<Vec<_>>()
            )
        })
}

/// Reconstruct the bundle the companion would ship for the on-wire
/// verifier. Mirrors `dbgen/tests/erc7730_roundtrip.rs::synth_bundle`
/// (kept inline here so this module doesn't depend on the dbgen test
/// helpers).
fn synth_bundle(blob: &[u8], ir_bytes: &[u8], leaf_index: usize) -> Vec<u8> {
    let proof_depth =
        u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize;
    let proofs_off =
        u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;
    let proof_base = proofs_off + leaf_index * proof_depth * 32;

    let mut buf =
        Vec::with_capacity(2 + ir_bytes.len() + 4 + 4 + proof_depth * 32);
    buf.extend_from_slice(&(ir_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(ir_bytes);
    buf.extend_from_slice(&(leaf_index as u32).to_be_bytes());
    buf.extend_from_slice(&(proof_depth as u32).to_be_bytes());
    for j in 0..proof_depth {
        let off = proof_base + j * 32;
        buf.extend_from_slice(&blob[off..off + 32]);
    }
    buf
}

// ───────────────────────────────────────────────────────────────────────
// Tx + calldata builders.
// ───────────────────────────────────────────────────────────────────────

fn u256_from_u64(n: u64) -> U256 {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    U256(out)
}

/// "Approve max" — the value that triggers the unlimited-amount branch
/// in tokenAmount rendering against the descriptor's threshold param.
fn u256_max() -> U256 {
    U256([0xFFu8; 32])
}

/// Plain receiver-tx envelope. ERC-7730 path expects `tx.to ==
/// descriptor.contract`; the caller fills `to` with the real contract
/// address per-test.
fn envelope(chain_id: u64, contract: [u8; 20]) -> Eip1559Tx {
    let mut tx = Eip1559Tx::default();
    tx.chain_id = chain_id;
    tx.nonce = 7;
    tx.to = Some(contract);
    tx.value = U256::default();
    tx.gas_limit = 100_000;
    tx.max_fee_per_gas = u256_from_u64(30_000_000_000);
    tx.max_priority_fee_per_gas = u256_from_u64(1_500_000_000);
    tx
}

/// ERC-20 `transfer(address,uint256)` calldata.
fn calldata_transfer(to: [u8; 20], amount: U256) -> Vec<u8> {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    let mut to_padded = [0u8; 32];
    to_padded[12..].copy_from_slice(&to);
    data.extend_from_slice(&to_padded);
    data.extend_from_slice(&amount.0);
    data
}

/// ERC-20 `approve(address,uint256)` calldata.
fn calldata_approve(spender: [u8; 20], amount: U256) -> Vec<u8> {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]);
    let mut sp_padded = [0u8; 32];
    sp_padded[12..].copy_from_slice(&spender);
    data.extend_from_slice(&sp_padded);
    data.extend_from_slice(&amount.0);
    data
}

/// `WETH9.deposit()` — zero-argument call. The amount the user is
/// wrapping is `@.value` (envelope's `value`), which the descriptor
/// pulls from the container path.
fn calldata_deposit() -> Vec<u8> {
    vec![0xd0, 0xe3, 0x0d, 0xb0]
}

/// Aave V3 `borrow(address asset, uint256 amount, uint256 interestRateMode,
/// uint16 referralCode, address onBehalfOf)` — all-static 5-word head.
/// Used to exercise the `enum` formatter on `interestRateMode`.
fn calldata_borrow(
    asset: [u8; 20],
    amount: U256,
    interest_rate_mode: U256,
    referral_code: u16,
    on_behalf_of: [u8; 20],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 5 * 32);
    let sel = keccak256(b"borrow(address,uint256,uint256,uint16,address)");
    data.extend_from_slice(&sel[..4]);
    let mut asset_w = [0u8; 32];
    asset_w[12..].copy_from_slice(&asset);
    data.extend_from_slice(&asset_w);
    data.extend_from_slice(&amount.0);
    data.extend_from_slice(&interest_rate_mode.0);
    let mut ref_w = [0u8; 32];
    ref_w[30..].copy_from_slice(&referral_code.to_be_bytes());
    data.extend_from_slice(&ref_w);
    let mut obo_w = [0u8; 32];
    obo_w[12..].copy_from_slice(&on_behalf_of);
    data.extend_from_slice(&obo_w);
    data
}

/// Re-confirm the function selector we synthesised actually keccaks to
/// what the descriptor expects. Catches a "we mis-built the calldata"
/// bug before the renderer ever sees it. Mirrors the firmware's own
/// selector dispatch.
fn assert_selector_matches(ir: &Erc7730Ir<'_>, calldata: &[u8], text_sig: &str) {
    let sel = keccak256(text_sig.as_bytes());
    assert_eq!(
        &sel[..4],
        &calldata[..4],
        "test bug: calldata selector != keccak256({text_sig:?})[..4]"
    );
    let key: [u8; 4] = calldata[..4].try_into().unwrap();
    ir.find_format_by_selector(&key)
        .expect("ir format table well-formed")
        .unwrap_or_else(|| panic!("no format for {text_sig:?} in descriptor"));
}

// ───────────────────────────────────────────────────────────────────────
// Row assertion helpers — string-trim then compare.
// ───────────────────────────────────────────────────────────────────────

fn row_str(row: &[u8; DISPLAY_COLS]) -> String {
    let end = row.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
    String::from_utf8(row[..end].to_vec())
        .expect("rendered rows must be printable ASCII")
}

fn page_strs(pages: &Pages, page: usize) -> [String; 4] {
    let p = &pages.buf[page];
    [row_str(&p[0]), row_str(&p[1]), row_str(&p[2]), row_str(&p[3])]
}

fn dump_pages(pages: &Pages) -> String {
    let mut out = String::new();
    for (i, page) in pages.as_slice().iter().enumerate() {
        out.push_str(&format!("--- page {i} ---\n"));
        for row in page.iter() {
            out.push_str(&format!("| {} |\n", row_str(row)));
        }
    }
    out
}

fn assert_all_pages_printable(pages: &Pages) {
    for (p, page) in pages.as_slice().iter().enumerate() {
        for (r, row) in page.iter().enumerate() {
            for (c, &b) in row.iter().enumerate() {
                assert!(
                    (0x20..=0x7E).contains(&b),
                    "page {p} row {r} col {c} byte {:#x} not printable\n{}",
                    b,
                    dump_pages(pages),
                );
            }
        }
    }
}

/// Find the first page whose row 0 trims to exactly `label`. Used to
/// locate a field page when the field-order is descriptor-driven and a
/// test doesn't want to over-pin on page indices.
fn find_page_by_label(pages: &Pages, label: &str) -> usize {
    for (i, page) in pages.as_slice().iter().enumerate() {
        if row_str(&page[0]) == label {
            return i;
        }
    }
    panic!(
        "no page with row 0 == {label:?}; full dump:\n{}",
        dump_pages(pages)
    );
}

// ───────────────────────────────────────────────────────────────────────
// Per-corpus tests. One per representative descriptor + format.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_seed_corpus_compiles() {
    // `secure/data/erc7730/` is now a synthetic-only render-test corpus: the
    // protocol fixtures that used to live here were duplicates of the vendored
    // registry (the PROD corpus, exercised via `build_registry()` in the
    // repointed render tests). Only the synthetic non-registry fixtures remain,
    // so the floor is ≥1.
    let res = build_seed();
    assert!(
        res.leaf_count >= 1,
        "seed corpus has shrunk below the sanity floor ({} leaves)",
        res.leaf_count
    );
}

#[test]
#[ignore = "diagnostic — run with `--ignored` to dump the seed-corpus IR layout"]
fn diagnostic_dump_seed_corpus_path_offsets() {
    let res = build_seed();
    for entry in &res.entries {
        let ir =
            Erc7730Ir::parse(&entry.ir_bytes).expect("seed IR parses");
        eprintln!(
            "== {} chain={} ctx={:?}",
            entry.source.display(),
            entry.chain_id,
            ir.context_kind
        );
        for fmt in ir.format_iter() {
            let fmt = fmt.expect("format header");
            let sel = fmt.selector;
            eprintln!(
                "  fmt sel=0x{:02x}{:02x}{:02x}{:02x} intent={:?}",
                sel[0],
                sel[1],
                sel[2],
                sel[3],
                core::str::from_utf8(fmt.intent).unwrap_or("?")
            );
            for field in fmt.fields() {
                let field = field.expect("field");
                eprintln!(
                    "    field op={:#04x} label={:?} path_off={} param_off={}",
                    field.format_op,
                    core::str::from_utf8(field.label).unwrap_or("?"),
                    field.path_off,
                    field.param_off
                );
            }
        }
    }
}

// ───────────────────────────────────────────────────────────────────────
// `path_off == 0` collision fix landed in `dbgen::erc7730::Pool::new`:
// the pool now reserves byte 0 with a 1-byte filler so the first
// interned path program lands at offset 1. The on-device walker and
// renderer's `path_off == 0` / `param_off == 0` "no path" sentinels
// stay intact, and the descriptors that previously fell through to
// blind-sign (weth.deposit, tether-usdt.transfer/approve, every
// aave-v3-pool.* and circle-usdc-*) now render their full clear-sign
// page sequence.
//
// The three tests below assert the user-visible display text end-to-end.

#[test]
fn positive_usdt_transfer_mainnet_renders_send_intent() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    assert!(matches!(
        verified.ir.context_kind,
        ContextKind::Contract
    ));

    let amount = u256_from_u64(100_000_000); // 100.00 USDT (6 decimals)
    let recipient = [0x33u8; 20];
    let calldata = calldata_transfer(recipient, amount);
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "transfer(address,uint256)",
    );

    let tx = envelope(1, entry.contract);
    let usdt_meta = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(
        &tx,
        &calldata,
        &verified,
        Some(&usdt_meta),
        &resolver,
    )
    .expect("render");

    assert_all_pages_printable(&pages);

    // Page 0: intent banner.
    let [r0, r1, r2, r3] = page_strs(&pages, 0);
    assert_eq!(r0, "Send");
    assert_eq!(r1, "Tether Limited");
    assert_eq!(r2, "Tether USD");
    assert_eq!(r3, "> next");

    // Amount page — labelled "Amount", value should render as
    // "100" / "USDT" across two rows.
    let amount_page = find_page_by_label(&pages, "Amount");
    let amount_rows = page_strs(&pages, amount_page);
    assert!(
        amount_rows[1].contains("100"),
        "amount row 1 should carry the integer part: rows={amount_rows:?}",
    );
    assert!(
        amount_rows[1].contains("USDT") || amount_rows[2].contains("USDT"),
        "USDT ticker missing from amount: rows={amount_rows:?}",
    );

    // To page — labelled "To".
    let to_page = find_page_by_label(&pages, "To");
    let to_rows = page_strs(&pages, to_page);
    let recipient_hex_head = "3333";
    assert!(
        to_rows.iter().any(|r| r.contains(recipient_hex_head)),
        "recipient hex prefix missing: rows={to_rows:?}",
    );
}

#[test]
fn positive_usdt_approve_unlimited_renders_approve_intent() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // U256::MAX is the canonical "approve unlimited" sentinel; the
    // descriptor sets `threshold` to 0x8000...0000 (top bit) — any
    // value above renders as "unlimited" via tokenAmount.
    let calldata = calldata_approve([0x44u8; 20], u256_max());
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "approve(address,uint256)",
    );

    let tx = envelope(1, entry.contract);
    let usdt_meta = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(
        &tx,
        &calldata,
        &verified,
        Some(&usdt_meta),
        &resolver,
    )
    .expect("render");

    assert_all_pages_printable(&pages);

    let [intent_r0, _, _, _] = page_strs(&pages, 0);
    assert_eq!(intent_r0, "Approve");

    // Spender page must be present (labelled "Spender" per the
    // descriptor).
    let _spender_page = find_page_by_label(&pages, "Spender");

    // Amount page — for U256::MAX with the descriptor's threshold set,
    // `render_token_amount` short-circuits the digit formatter and
    // writes "unlimited <ticker>" on row 1. No `!AMOUNT OVERFLOW`
    // banner, no truncated decimal soup — just the human-readable
    // sentinel.
    let amount_page = find_page_by_label(&pages, "Amount");
    let amount_rows = page_strs(&pages, amount_page);
    let amount_blob = amount_rows.join("\n");
    assert!(
        amount_blob.to_lowercase().contains("unlimited"),
        "approve(MAX) should render 'unlimited', got:\n{amount_blob}",
    );
    assert!(
        amount_blob.contains("USDT"),
        "unlimited row should carry the ticker, got:\n{amount_blob}",
    );
    assert!(
        !amount_blob.contains("AMOUNT OVERFLOW"),
        "threshold check must short-circuit before the overflow fallback, got:\n{amount_blob}",
    );
}

#[test]
fn positive_usdt_approve_unlimited_unbound_renders_unlimited_not_overflow() {
    // review 4.5: an unlimited approval of an UNKNOWN (unbound) token used to
    // render "!AMOUNT OVERFLOW" — the raw 2^256-1 overflows the amount
    // formatter, an alarming banner with no meaning for the single most
    // dangerous action, exactly when trust is LOWEST. It must now render
    // "unlimited" + "(unverified)". Same REAL USDT approve descriptor
    // (threshold set), but NO metadata supplied → the token cannot bind.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata = calldata_approve([0x44u8; 20], u256_max());
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let amount_page = find_page_by_label(&pages, "Amount");
    let amount_blob = page_strs(&pages, amount_page).join("\n");
    assert!(
        amount_blob.to_lowercase().contains("unlimited"),
        "unbound approve(MAX) must render 'unlimited', got:\n{amount_blob}"
    );
    assert!(
        !amount_blob.contains("OVERFLOW"),
        "must NOT render the alarming overflow banner for an unlimited approve:\n{amount_blob}"
    );
    assert!(
        amount_blob.contains("(unverified)"),
        "unbound must mark the missing token identity:\n{amount_blob}"
    );
}

/// Multi-chain chain-pinning: USDT's registry descriptor carries Mainnet (1)
/// AND Polygon (137) deployments under the SAME JSON. Picking the chain-137
/// leaf (contract 0xc2132D…8e8F, the bridged Polygon USDT) proves the
/// renderer + bundle verifier bind to the right `(chain_id, contract)` leaf —
/// a Mainnet tx must never render against the Polygon leaf and vice-versa.
/// Replaces the deleted vacuous `circle-usdc` chain-pinning test, which fed
/// an EIP-712 descriptor calldata it could never render (its
/// `find_format_by_selector` guard early-returned, asserting nothing).
#[test]
fn positive_usdt_transfer_polygon_chain_pinning() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 137);
    // The chain-137 leaf is the bridged Polygon USDT, a different address
    // from Mainnet's 0xdAC17… — proves we picked the right deployment.
    let polygon_usdt =
        hex::decode("c2132D05D31c914a87C6611C10748AEb04B58e8F").unwrap();
    assert_eq!(
        &entry.contract[..],
        &polygon_usdt[..],
        "chain-137 leaf must bind the Polygon USDT contract"
    );

    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    assert_eq!(verified.ir.chain_id, 137, "verified leaf is chain 137");
    assert_eq!(&verified.ir.contract, &polygon_usdt[..], "verified leaf contract");

    let calldata = calldata_transfer([0x33u8; 20], u256_from_u64(100_000_000));
    assert_selector_matches(&verified.ir, &calldata, "transfer(address,uint256)");

    let tx = envelope(137, entry.contract);
    let usdt_meta = Erc20Metadata {
        chain_id: 137,
        contract: entry.contract,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, Some(&usdt_meta), &resolver)
        .expect("render");
    assert_all_pages_printable(&pages);

    // The Polygon leaf renders the same "Send" intent as Mainnet.
    let [r0, ..] = page_strs(&pages, 0);
    assert_eq!(r0, "Send");
}

#[test]
fn positive_weth_deposit_pulls_value_from_envelope() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-weth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // deposit() is the zero-arg selector — the "Amount" field is
    // sourced from `@.value` (container), not the calldata.
    let calldata = calldata_deposit();
    assert_selector_matches(&verified.ir, &calldata, "deposit()");

    let mut tx = envelope(1, entry.contract);
    tx.value = u256_from_u64(500_000_000_000_000_000); // 0.5 ETH

    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver)
        .expect("render");

    assert_all_pages_printable(&pages);

    let [intent_r0, owner_r, contract_r, _] = page_strs(&pages, 0);
    assert_eq!(intent_r0, "Wrap");
    assert_eq!(owner_r, "WETH");
    assert_eq!(contract_r, "WETH");

    // Amount page — 0.5 ETH at 18 decimals. review 4.3: the amount now prefers
    // a SINGLE row ("0.5 ETH") instead of the old split ("0" / ".5 ETH").
    let amount_page = find_page_by_label(&pages, "Amount");
    let amount_rows = page_strs(&pages, amount_page);
    assert_eq!(
        amount_rows[1], "0.5 ETH",
        "amount must render on a single row (4.3), got:\n{amount_rows:?}",
    );
}

#[test]
fn positive_native_amount_uses_chain_ticker_not_eth_on_polygon() {
    // review 3.5: the `amount` format defaults to the chain's NATIVE ticker,
    // not always "ETH". A Polygon (137) descriptor must render "POL". (The WETH
    // deposit test above covers the chain-1 → ETH case by render.)
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-native-amount.json", 137);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let mut calldata = keccak256(b"pay(uint256)")[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(500_000_000_000_000_000).0); // 0.5
    assert_selector_matches(&verified.ir, &calldata, "pay(uint256)");
    let tx = envelope(137, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");

    let amount_page = find_page_by_label(&pages, "Amount");
    let rows = page_strs(&pages, amount_page).join(" ");
    assert!(rows.contains("POL"), "Polygon native amount must render POL:\n{rows}");
    assert!(!rows.contains("ETH"), "must NOT render ETH on Polygon:\n{rows}");
}

// NOTE: The corresponding EIP-712 path (`render_erc7730_eip712_pages`)
// would be the right way to exercise USDC's TransferWithAuthorization
// descriptor — but the firmware-side EIP-712 entry point requires the
// 32-byte primaryTypeHash + ABI-encoded data buffer that the
// `cmd_sign_offchain` handler computes from the dapp's typed payload,
// and that scaffolding is wired through the on-device sign command
// rather than the renderer's public API. A future test pass that
// reaches into `cmd_sign_offchain` would close that gap; for now we
// limit coverage to the contract-context path above.
//
// (Multi-chain chain-pinning is now exercised by
// `positive_usdt_transfer_polygon_chain_pinning` above, against the real
// registry USDT descriptor's chain-137 leaf. The former
// `positive_usdc_transfer_polygon_uses_correct_chain_pinning` was vacuous:
// it fed `transfer` calldata to an EIP-712 `circle-usdc` descriptor whose
// `find_format_by_selector` guard always early-returned, asserting nothing.)

#[test]
fn negative_unknown_selector_returns_no_format() {
    // The renderer must NOT try to fall through to a "best-guess"
    // format — an unknown selector means "blind sign should handle
    // this", which the dispatcher achieves by getting `RenderErr::
    // NoFormat` back from us and proceeding down the ladder.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-weth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // 0xdeadbeef — selector not in the registry WETH descriptor (deposit only).
    let calldata = vec![0xde, 0xad, 0xbe, 0xef];
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    match render_erc7730_pages(&tx, &calldata, &verified, None, &resolver) {
        Err(crate::tx::erc7730_render::RenderErr::NoFormat) => {}
        Err(other) => panic!(
            "expected RenderErr::NoFormat for unknown selector, got {other:?}"
        ),
        Ok(_) => panic!("unknown selector must not render"),
    }
}

#[test]
fn negative_short_calldata_rejects() {
    // Less than 4 bytes — can't even extract a selector. The renderer
    // must reject cleanly so the caller falls through to blind-sign.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-weth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata: Vec<u8> = vec![0xab, 0xcd]; // 2 bytes
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    match render_erc7730_pages(&tx, &calldata, &verified, None, &resolver) {
        Err(crate::tx::erc7730_render::RenderErr::NoFormat) => {}
        Err(other) => panic!("expected NoFormat, got {other:?}"),
        Ok(_) => panic!("short calldata must not render"),
    }
}

#[test]
fn positive_intent_truncation_is_safe() {
    // The intent banner now wraps the intent across two rows (up to 32 chars,
    // a visible `~` marker beyond that) instead of the old 10-char "Sign: "
    // prefix form, so an intent of ANY length renders safely (no silent clip).
    // Verify the seed corpus' intents stay within the host-pipeline ASCII cap
    // (≤ 254 B) and that every rendered row stays within DISPLAY_COLS = 16.
    let res = build_seed();
    for entry in &res.entries {
        let bundle =
            synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &res.root)
            .expect("seed corpus entries verify");
        if !matches!(verified.ir.context_kind, ContextKind::Contract) {
            continue;
        }
        for fmt in verified.ir.format_iter() {
            let fmt = fmt.expect("format header parses");
            assert!(
                fmt.intent.len() <= 254,
                "intent exceeds the host-pipeline ASCII cap: {:?}",
                core::str::from_utf8(fmt.intent).unwrap_or("<bin>")
            );
            // The banner caps every row at DISPLAY_COLS and marks truncation
            // with `~`; the row-length invariant is asserted at the page level
            // via `assert_all_pages_printable` (and the wrap/marker behaviour by
            // `positive_long_intent_wraps_and_marks_truncation`).
        }
    }
}

#[test]
fn positive_long_intent_wraps_and_marks_truncation() {
    // review 4.1: the intent banner drops the old "Sign: " prefix and wraps the
    // intent across rows 0-1 (32 chars). A >32-char intent gets a visible `~`
    // marker in the last cell — never a silent clip.
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-long-intent.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let mut calldata = keccak256(b"f(uint256)")[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(1).0);
    assert_selector_matches(&verified.ir, &calldata, "f(uint256)");

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    // "Withdraw Collateral from the Morpho Market" (42 chars) → rows 0-1.
    let [r0, r1, ..] = page_strs(&pages, 0);
    assert_eq!(r0, "Withdraw Collate", "row 0 = first 16 chars, no `Sign:` prefix");
    assert!(
        r1.starts_with("ral from the"),
        "row 1 = intent continuation, got {r1:?}"
    );
    assert!(r1.ends_with('~'), "row 1 must mark truncation with `~`, got {r1:?}");
}

#[test]
fn positive_medium_intent_wraps_two_rows_no_marker() {
    // review 4.1: a 17..32-char intent uses both rows with NO marker.
    // "Request stETH withdrawal" (24 chars) → "Request stETH wi" / "thdrawal".
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-uint256-array-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata = rw_calldata(&[u256_from_u64(1_000_000_000_000_000_000)], [0x55u8; 20]);
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");

    let [r0, r1, ..] = page_strs(&pages, 0);
    assert_eq!(r0, "Request stETH wi");
    assert_eq!(r1, "thdrawal");
    assert!(!r1.contains('~'), "24 chars fits two rows → no marker");
}

#[test]
fn positive_erc8213_fingerprint_renders_full_hash() {
    // The ERC-8213 fingerprint page is independent of the descriptor —
    // it just renders the 32-byte hash. Smoke-test it produces exactly
    // 2 pages and the rendered hex matches the input bytewise.
    let mut pages = Pages::empty_with_len(0);

    let hash: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    append_fingerprint_page(&mut pages, Erc8213Kind::CalldataDigest(hash))
        .expect("fingerprint fits");

    assert_eq!(pages.len, 2, "fingerprint renders exactly 2 pages");
    assert_all_pages_printable(&pages);

    // Banner: row 0 "8213 Fingerprint", row 1 "CalldataDigest".
    assert_eq!(row_str(&pages.buf[0][0]), "8213 Fingerprint");
    assert_eq!(row_str(&pages.buf[0][1]), "CalldataDigest");
    assert_eq!(row_str(&pages.buf[0][3]), "> verify off-dev");

    // Hash page: 8 bytes per row × 4 rows = full 32 B.
    let hash_page = &pages.buf[1];
    let rendered: String = hash_page
        .iter()
        .map(|r| row_str(r))
        .collect::<Vec<_>>()
        .join("");
    let expected_hex: String =
        hash.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        rendered, expected_hex,
        "fingerprint rows must spell out the full 32-byte hash bytewise"
    );
}

#[test]
fn positive_erc8213_labels_cover_every_kind() {
    // Pin the label text on every Kind variant. Surfaces a regression
    // where someone renames the label in `erc8213.rs::Kind::label`
    // without updating the doc + tests in lockstep.
    for (kind, expected_label) in [
        (Erc8213Kind::CalldataDigest([0u8; 32]), "CalldataDigest"),
        (Erc8213Kind::Eip712Final([0u8; 32]), "EIP-712 Final"),
        (Erc8213Kind::Raw32([0u8; 32]), "Raw32 Hash"),
        (Erc8213Kind::SafeTxHash([0u8; 32]), "SafeTxHash"),
    ] {
        let mut pages = Pages::empty_with_len(0);
        append_fingerprint_page(&mut pages, kind).expect("fits");
        assert_eq!(
            row_str(&pages.buf[0][1]),
            expected_label,
            "label row for {:?}",
            std::any::type_name_of_val(&kind)
        );
    }
}

// ───────────────────────────────────────────────────────────────────────
// Enum formatter (FormatOp 0x08) — Aave V3 `borrow`. This is the FIRST and
// only descriptor that emits an enum table, so these two tests are the
// sole end-to-end coverage of the host `encode_enum_table` → on-device
// `enums::lookup_enum_label` → `render_enum` round trip. The dbgen
// round-trip / Kani suites NEVER render a page, so without these a broken
// `render_enum` would ship green.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_aave_borrow_renders_enum_label() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-lpv3.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // interestRateMode = 2 → "variable" in the descriptor's enum.
    let calldata = calldata_borrow(
        [0x11u8; 20],
        u256_from_u64(500),
        u256_from_u64(2),
        0,
        [0x44u8; 20],
    );
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "borrow(address,uint256,uint256,uint16,address)",
    );

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let [r0, ..] = page_strs(&pages, 0);
    assert_eq!(r0, "Borrow");

    // The enum page must show the RESOLVED label "variable", not the bare
    // index "2" (audit M-7). The registry's field label is "Interest Rate
    // mode" (18 chars); row 0 is truncated to DISPLAY_COLS (16), so the page
    // header reads "Interest Rate mo".
    let enum_page = find_page_by_label(&pages, "Interest Rate mo");
    let rows = page_strs(&pages, enum_page);
    assert!(
        rows[1].contains("variable"),
        "enum index 2 must resolve to label 'variable': rows={rows:?}",
    );
    assert!(
        !rows.iter().any(|r| r.trim() == "2"),
        "must not render the bare enum index: rows={rows:?}",
    );
}

#[test]
fn positive_aave_borrow_unknown_enum_value_renders_raw_index_loudly() {
    // review 3.3: interestRateMode = 7 is outside the declared set {0,1,2}. The
    // OLD behaviour declined the WHOLE tx to blind-sign; the spec says render
    // the raw value. Now the enum field renders the exact index (7) with a loud
    // `! enum: unknown` marker — WYSIWYS-honest (the real signed value is shown,
    // not a substituted gloss) and strictly better than blind-signing.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-lpv3.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata = calldata_borrow(
        [0x11u8; 20],
        u256_from_u64(500),
        u256_from_u64(7),
        0,
        [0x44u8; 20],
    );
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver)
        .expect("unknown enum value must now RENDER (loud raw index), not decline");
    assert_all_pages_printable(&pages);

    // Locate the enum field page by its (truncated) label and assert BOTH the
    // raw index and the loud unknown marker appear ON THAT PAGE (not elsewhere
    // — the envelope nonce is also 7).
    let enum_page = find_page_by_label(&pages, "Interest Rate mo");
    let rows = page_strs(&pages, enum_page).join(" ");
    assert!(rows.contains('7'), "raw enum index 7 must render:\n{rows}");
    assert!(
        rows.contains("enum: unknown"),
        "loud unknown-enum marker must render:\n{rows}"
    );
}

#[test]
fn positive_nftname_renders_small_token_id_as_decimal_real_leaf() {
    // review 3.2: nftName no longer declines the whole tx. The spec fallback is
    // "a raw int token ID"; with no NFT-name DB we render it plainly. Real leaf:
    // flyingtulip PftNft `approve(address to, uint256 tokenId)` where tokenId is
    // the nftName "Position". A small id renders as a decimal + a loud no-name
    // marker (verified BY RENDER on a real registry descriptor).
    let res = build_registry();
    let entry = find_leaf(res, "calldata-PftNft.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata = calldata_approve([0x11u8; 20], u256_from_u64(1036));
    assert_selector_matches(&verified.ir, &calldata, "approve(address,uint256)");
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver)
        .expect("nftName must now render, not decline the tx");
    assert_all_pages_printable(&pages);

    let dump = dump_pages(&pages);
    assert!(dump.contains("1036"), "raw token id 1036 must render:\n{dump}");
    assert!(dump.contains("raw nft id"), "loud raw-id marker must render:\n{dump}");
}

#[test]
fn positive_nftname_large_id_shows_all_bytes_never_overflow_real_leaf() {
    // THE load-bearing case (advisor): a large / structured token id (ERC-1155
    // style) must show EVERY byte, NEVER a magnitude-hiding "!OVERFLOW" that
    // clear-signs while hiding WHICH nft — the false-confidence class. A token
    // id is an identifier, not an amount, so it must not route through the
    // amount path.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-PftNft.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // Full-width id with a nonzero HIGH byte → forces the faithful raw path.
    let mut id = [0u8; 32];
    id[0] = 0xAB;
    id[31] = 0xCD;
    let calldata = calldata_approve([0x11u8; 20], U256(id));
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let dump = dump_pages(&pages);
    assert!(
        !dump.contains("OVERFLOW"),
        "a large token id must NOT overflow-hide (would clear-sign hiding the nft):\n{dump}"
    );
    assert!(dump.contains("ab"), "high byte 0xAB must render:\n{dump}");
    assert!(dump.contains("cd"), "low byte 0xCD must render:\n{dump}");
}

/// Pack-expansion sanity: the registry Lido `wstETH.wrap(uint256)`
/// descriptor renders the right intent + field label. A render test
/// (not just round-trip) catches descriptor-authoring slips — wrong
/// path, selector, or label — that re-parse + Merkle-verify can't.
#[test]
fn positive_wsteth_wrap_renders_intent_and_amount_label() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-wstETH.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let mut calldata = keccak256(b"wrap(uint256)")[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(1_500_000_000_000_000_000).0); // 1.5e18
    assert_selector_matches(&verified.ir, &calldata, "wrap(uint256)");

    let tx = envelope(1, entry.contract);
    // The registry wrap field is `tokenAmount` with `token` = stETH
    // (0xae7ab9…), so supply stETH ERC-20 metadata (18 decimals) for the
    // amount to render — mirrors how the USDT tests pass `Some(erc20)`.
    let steth: [u8; 20] = hex::decode("ae7ab96520DE3A18E5e111B5EaAb095312D7fE84")
        .unwrap()
        .try_into()
        .unwrap();
    let steth_meta = Erc20Metadata {
        chain_id: 1,
        contract: steth,
        decimals: 18,
        name: b"Liquid staked Ether 2.0",
        symbol: b"stETH",
    };
    let resolver = NameResolver::new();
    let pages =
        render_erc7730_pages(&tx, &calldata, &verified, Some(&steth_meta), &resolver)
            .expect("render");
    assert_all_pages_printable(&pages);

    let [r0, ..] = page_strs(&pages, 0);
    assert_eq!(r0, "Wrap stETH");
    // The amount field must render under its authored label (proves
    // `#._stETHAmount` resolved to the right static-head slot).
    let _amt_page = find_page_by_label(&pages, "stETH amount");
}

/// Constant-annotation field (path-less `{value, label}`): the registry
/// yield.xyz USDe-vault `deposit(uint256,address)` descriptor carries
/// `{ "label": "Share ticker", "format": "raw", "value":
/// "$.metadata.constants.vaultTicker" }`, which the host resolves to the
/// literal "stk-USDe" and the device renders verbatim under its label — no
/// calldata binding. This is the construct the ERC-4626/7540 vault templates
/// use (the registry coverage lever that took render-coverage 40% -> 76%).
#[test]
fn positive_wsteth_wrap_renders_constant_annotation_field() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-yieldxyz-usde-vault.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // deposit(uint256 _underlying, address receiver).
    let mut calldata = keccak256(b"deposit(uint256,address)")[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(1_000_000).0); // _underlying
    let mut recv = [0u8; 32];
    recv[12..].copy_from_slice(&[0x55u8; 20]); // receiver
    calldata.extend_from_slice(&recv);
    assert_selector_matches(&verified.ir, &calldata, "deposit(uint256,address)");

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let page = find_page_by_label(&pages, "Share ticker");
    let rows = page_strs(&pages, page);
    assert!(
        rows.iter().any(|r| r.contains("stk-USDe")),
        "constant-annotation field must render the resolved string: rows={rows:?}",
    );
}

// ───────────────────────────────────────────────────────────────────────
// Dynamic-array walker (sole-dynamic-array `<arg>.[]` render-all).
// Security-critical: it follows the dynamic calldata tail, the slot-
// confusion attack surface. All of the resolution safety lives in
// `formatters::resolve_array`; these tests drive it directly with crafted
// HOSTILE bodies (the descriptor is the trusted/pinned input, the calldata
// body is attacker-controlled) and diff it against the Kani-proven `walk`.
// ───────────────────────────────────────────────────────────────────────

/// Canonical `requestWithdrawals(uint256[],address)` calldata BODY (no
/// selector): `offset(0x40) | owner | length | amounts…`.
fn rw_body(amounts: &[U256], owner: [u8; 20]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&u256_from_u64(64).0); // offset to _amounts
    let mut ow = [0u8; 32];
    ow[12..].copy_from_slice(&owner);
    b.extend_from_slice(&ow); // _owner
    b.extend_from_slice(&u256_from_u64(amounts.len() as u64).0); // length
    for a in amounts {
        b.extend_from_slice(&a.0);
    }
    b
}

fn rw_calldata(amounts: &[U256], owner: [u8; 20]) -> Vec<u8> {
    let mut d = keccak256(b"requestWithdrawals(uint256[],address)")[..4].to_vec();
    d.extend_from_slice(&rw_body(amounts, owner));
    d
}

/// The Lido `_amounts.[]` array field + the format's `static_head_words`,
/// from the trusted/pinned descriptor.
fn lido_array_field<'a>(
    ir: &'a Erc7730Ir<'a>,
) -> (crate::tx::erc7730::FieldEntry<'a>, u16) {
    let sel = keccak256(b"requestWithdrawals(uint256[],address)");
    let s4: [u8; 4] = sel[..4].try_into().unwrap();
    let format = ir.find_format_by_selector(&s4).unwrap().unwrap();
    let field = format
        .fields()
        .filter_map(Result::ok)
        .find(|f| f.label == b"Amount")
        .expect("the `_amounts.[]` array field");
    (field, format.static_head_words)
}

#[test]
fn positive_lido_request_withdrawals_renders_every_element() {
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-uint256-array-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // 1.0 / 2.5 / 0.3 stETH (18 decimals).
    let amounts = [
        u256_from_u64(1_000_000_000_000_000_000),
        u256_from_u64(2_500_000_000_000_000_000),
        u256_from_u64(300_000_000_000_000_000),
    ];
    let owner = [0x55u8; 20];
    let calldata = rw_calldata(&amounts, owner);
    assert_selector_matches(&verified.ir, &calldata, "requestWithdrawals(uint256[],address)");

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let dump = dump_pages(&pages);
    // Header makes the count explicit. `write_amount_two_rows` splits an
    // amount across an integer row + a fraction row, so 2.5 → "2" / ".5".
    assert!(dump.contains("3 items"), "count header missing:\n{dump}");
    assert!(dump.contains(".5"), "amount 2.5 (fraction) missing:\n{dump}");
    assert!(dump.contains(".3"), "amount 0.3 (fraction) missing:\n{dump}");
    // ARRAY-TAIL-HIDING CLOSED, asserted concretely: one header page + EXACTLY
    // one page per element (3) all labelled "Amount" — never fewer.
    let amount_pages = pages
        .as_slice()
        .iter()
        .filter(|p| row_str(&p[0]) == "Amount")
        .count();
    assert_eq!(
        amount_pages, 4,
        "expected 1 header + 3 element pages (every element shown):\n{dump}"
    );
    // owner page present.
    let _ = find_page_by_label(&pages, "Owner");
}

/// review finding 1.2 — a `raw`-formatted ARRAY ELEMENT must show EVERY signed
/// byte. The old array Raw arm passed two 16-byte slices to `write_hex_word`
/// (caps at 8 bytes/row), silently dropping bytes 8..16 and 24..32 — so a value
/// living there rendered as all-zeros (WYSIWYS magnitude-hiding, the array
/// sibling of the fixed scalar `render_raw` bug). This feeds an element word
/// with a nonzero byte in BOTH dropped ranges (byte 8 = 0xAA, byte 31 = 0x7B)
/// and asserts both appear on the rendered pages — they would BOTH be invisible
/// under the old form.
#[test]
fn positive_raw_array_element_shows_all_bytes_not_zeros() {
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-raw-array.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // One bytes32 element: byte[8]=0xAA (in the dropped 8..16 range) and
    // byte[31]=0x7B (in the dropped 24..32 range); everything else zero.
    let mut elem = [0u8; 32];
    elem[8] = 0xAA;
    elem[31] = 0x7B;
    let calldata = {
        let mut d = Vec::with_capacity(4 + 3 * 32);
        d.extend_from_slice(&keccak256(b"record(bytes32[])")[..4]);
        d.extend_from_slice(&u256_from_u64(0x20).0); // offset to the array
        d.extend_from_slice(&u256_from_u64(1).0); // length = 1
        d.extend_from_slice(&elem); // element 0
        d
    };
    assert_selector_matches(&verified.ir, &calldata, "record(bytes32[])");

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages);

    // Both previously-dropped bytes must now render.
    assert!(
        dump.contains("aa"),
        "byte 8 (0xAA, range 8..16) must render — the old form dropped it:\n{dump}"
    );
    assert!(
        dump.contains("7b"),
        "byte 31 (0x7B, low word, range 24..32) must render — the old form \
         dropped it, hiding any BE value < 2^64 as all-zeros:\n{dump}"
    );
}

/// review finding 1.1 — field-level `$ref` into `$.display.definitions` must
/// resolve, verified BY RENDER (not just "it compiled to a leaf", the exact
/// failure mode that shipped the degraded 1inch/paraswap routers). The
/// referenced `tokenAmount` FORMAT (from the definition) and the field-local
/// `tokenPath` param (the reference's own params) must BOTH reach the IR, so
/// the field renders a bound token amount rather than the blank-label 64-hex
/// raw dump the pre-fix silent `$ref`-drop produced. Also pins the `label`
/// merge in both directions: field 1 inherits the definition's "Amount to
/// Send" (it carries no label); field 2 overrides it with "Min Received".
#[test]
fn positive_synthetic_ref_field_renders_bound_token_amount() {
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-ref-token-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // srcToken == the bound USDC metadata below; the send field's
    // `tokenPath:"srcToken"` must resolve to it so "Amount to Send" binds.
    let usdc: [u8; 20] = hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
        .unwrap()
        .try_into()
        .unwrap();
    let dst = [0x77u8; 20];
    let calldata = {
        let mut d = Vec::with_capacity(4 + 4 * 32);
        d.extend_from_slice(&keccak256(b"swap(address,address,uint256,uint256)")[..4]);
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&usdc);
        d.extend_from_slice(&w); // srcToken
        let mut w2 = [0u8; 32];
        w2[12..].copy_from_slice(&dst);
        d.extend_from_slice(&w2); // dstToken
        d.extend_from_slice(&u256_from_u64(1_500_000).0); // sendAmount = 1.5 USDC (6 dp)
        d.extend_from_slice(&u256_from_u64(900_000).0); // minReceive
        d
    };
    assert_selector_matches(&verified.ir, &calldata, "swap(address,address,uint256,uint256)");

    let tx = envelope(1, entry.contract);
    let usdc_meta = Erc20Metadata {
        chain_id: 1,
        contract: usdc,
        decimals: 6,
        name: b"USD Coin",
        symbol: b"USDC",
    };
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, Some(&usdc_meta), &resolver)
        .expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages);

    // Field 1: definition's label inherited (the field carries none).
    let send_page = find_page_by_label(&pages, "Amount to Send");
    // `$ref` resolved to `tokenAmount` (format from def) AND kept the field's
    // `tokenPath:"srcToken"` (params merge) → a bound USDC amount, not a raw
    // 64-hex dump. Both survivals are proven by the ticker + scaled value.
    let send_rows = page_strs(&pages, send_page).join(" ");
    assert!(
        send_rows.contains("USDC"),
        "send amount must bind the USDC ticker (proves format-from-def + tokenPath-from-field both survived $ref):\n{dump}"
    );
    assert!(
        send_rows.contains(".5"),
        "send amount 1.5 (fraction row) missing — field degraded to raw?:\n{dump}"
    );

    // Field 2: field-local label OVERRIDES the definition's "Amount to Receive".
    let _ = find_page_by_label(&pages, "Min Received");
    assert!(
        !dump.contains("Amount to Receive"),
        "field-local `label` must override the definition's label:\n{dump}"
    );
}

/// The REAL registry Lido `requestWithdrawals` leaf — a `tokenAmount` `uint256[]`
/// array (the synthetic fixture uses `format:amount`; EVERY registry `uint256[]`
/// uses `tokenAmount`, so this is the shape the synthetic cannot exercise, and
/// the render-faithfulness spot-check on a real registry descriptor).
/// BOUND branch: with Merkle-verified stETH metadata the shared token is
/// resolved ONCE and every element renders as a scaled `stETH` amount.
#[test]
fn positive_registry_lido_tokenamount_array_bound_renders_steth() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-WithdrawalQueueERC721.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // 1.0 / 2.5 / 0.3 stETH (18 decimals).
    let amounts = [
        u256_from_u64(1_000_000_000_000_000_000),
        u256_from_u64(2_500_000_000_000_000_000),
        u256_from_u64(300_000_000_000_000_000),
    ];
    let calldata = rw_calldata(&amounts, [0x55u8; 20]);
    assert_selector_matches(&verified.ir, &calldata, "requestWithdrawals(uint256[],address)");

    // Registry `token` is the stETH constant (0xae7ab9…); supply its metadata.
    let steth: [u8; 20] = hex::decode("ae7ab96520DE3A18E5e111B5EaAb095312D7fE84")
        .unwrap()
        .try_into()
        .unwrap();
    let steth_meta = Erc20Metadata {
        chain_id: 1,
        contract: steth,
        decimals: 18,
        name: b"Liquid staked Ether 2.0",
        symbol: b"stETH",
    };
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, Some(&steth_meta), &resolver)
        .expect("render");
    assert_all_pages_printable(&pages);

    let dump = dump_pages(&pages);
    assert!(dump.contains("3 items"), "count header missing:\n{dump}");
    assert!(dump.contains(".5"), "amount 2.5 fraction missing:\n{dump}");
    // WYSIWYS: EXACTLY the 3 element pages (label "Amount") show the bound
    // symbol — proves the shared token was Merkle-bound and applied per element
    // (not declined-to-blind), and array-tail-hiding stays closed (all shown).
    let steth_element_pages = pages
        .as_slice()
        .iter()
        .filter(|p| row_str(&p[0]) == "Amount" && (1..=2).any(|r| row_str(&p[r]).contains("stETH")))
        .count();
    assert_eq!(steth_element_pages, 3, "every element must render as stETH:\n{dump}");
    // Bound → no UNVERIFIED token page.
    let unverified = pages
        .as_slice()
        .iter()
        .filter(|p| row_str(&p[0]).contains("UNVERIFIE"))
        .count();
    assert_eq!(unverified, 0, "bound token must not show UNVERIFIED:\n{dump}");
    let _ = find_page_by_label(&pages, "Beneficiary");
}

/// Same registry leaf, UNBOUND branch (audit M-4 + M-1): with NO Merkle-verified
/// metadata each element renders as a loud RAW integer (never a scaled decimal
/// with an assumed scale) and the token identity is named EXACTLY ONCE — not
/// per element.
#[test]
fn positive_registry_lido_tokenamount_array_unbound_raw_and_one_token_page() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-WithdrawalQueueERC721.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let amounts = [
        u256_from_u64(1_000_000_000_000_000_000),
        u256_from_u64(2_500_000_000_000_000_000),
    ];
    let calldata = rw_calldata(&amounts, [0x55u8; 20]);
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    // No stETH metadata supplied → unbound.
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let dump = dump_pages(&pages);
    // M-4: every element footer is the loud raw/unknown-scale marker.
    let raw_footers = pages
        .as_slice()
        .iter()
        .filter(|p| row_str(&p[3]).contains("raw, dec=?"))
        .count();
    assert_eq!(raw_footers, 2, "both unbound elements must render loud raw:\n{dump}");
    // M-1: the token is named EXACTLY ONCE (a per-element page would be noise
    // and could push the array past the page budget).
    let token_pages = pages
        .as_slice()
        .iter()
        .filter(|p| row_str(&p[0]).contains("UNVERIFIE"))
        .count();
    assert_eq!(token_pages, 1, "unbound token must be named exactly once:\n{dump}");
}

/// COMPLETENESS + FAITHFULNESS over the WHOLE prod registry: enumerates every
/// compiled sole-dynamic-array (`<arg>.[]`) field across all 776 leaves and
/// checks two things the roundtrip/Kani tests can't (they never render):
///
/// 1. **Coverage guard** — every compiled array's element `format_op` has a
///    `render_array_element` arm (`Raw`/`Amount`/`TokenAmount`/`AddressName`).
///    If a `unit`/`calldata`/nested array ever slips the dbgen gate into the
///    corpus, it would silently decline-to-blind on a real user tx; this fails
///    loudly instead. (This is the durable regression guard.)
/// 2. **End-to-end render** — the sole-dynamic arrays whose siblings my generic
///    calldata satisfies actually RENDER every element (array-tail-hiding
///    closed). `visible:never` arrays (e.g. `setAllowedTargets`, Raw+hidden)
///    and multi-field functions my stub calldata can't fully satisfy simply
///    don't reach the ≥4-page bar — that's fine, they're covered by (1) and
///    must not crash.
#[test]
fn all_compiled_registry_array_leaves_render() {
    // render_array_element arms: Raw=0x01, Amount=0x02, TokenAmount=0x03,
    // AddressName=0x07, Unit=0x09 (see pqsigner_erc7730::ir::FormatOp).
    const HANDLED: &[u8] = &[0x01, 0x02, 0x03, 0x07, 0x09];
    let res = build_registry();
    let mut all_arrays: Vec<(String, u8)> = Vec::new();
    let mut rendered: Vec<(String, u8)> = Vec::new();

    for entry in res.entries.iter() {
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let Ok(verified) = verify_erc7730_bundle(&bundle, &res.root) else {
            continue;
        };
        let mut arrays: Vec<([u8; 4], usize, Vec<u8>, u8)> = Vec::new();
        for format in verified.ir.format_iter() {
            let Ok(format) = format else { continue };
            for field in format.fields() {
                let Ok(field) = field else { continue };
                let is_arr = super::erc7730::formatters::path_ends_with_array_all(
                    &verified.ir,
                    field.path_off,
                )
                .unwrap_or(false);
                if is_arr {
                    arrays.push((
                        format.selector,
                        format.static_head_words as usize,
                        field.label.to_vec(),
                        field.format_op,
                    ));
                }
            }
        }

        for (selector, shw, label, fmt_op) in arrays {
            let key = format!(
                "{}  sel={}  elem_fmt={}",
                entry.source.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
                hex::encode(selector),
                fmt_op,
            );
            all_arrays.push((key.clone(), fmt_op));

            // Canonical SOLE-dynamic-array calldata: selector + head (all words
            // = head_end, so the array's offset slot reads `offset == head_end`
            // whichever slot it is, and every other head field renders that
            // value as a scalar) + tail `[count=3][1][2][3]`.
            let head_end = shw * 32;
            let mut cd = selector.to_vec();
            for _ in 0..shw {
                cd.extend_from_slice(&u256_from_u64(head_end as u64).0);
            }
            cd.extend_from_slice(&u256_from_u64(3).0); // count
            for i in 1..=3u64 {
                cd.extend_from_slice(&u256_from_u64(i).0);
            }

            let tx = envelope(entry.chain_id, entry.contract);
            let resolver = NameResolver::new();
            let want_bytes = &label[..label.len().min(DISPLAY_COLS)];
            let want = String::from_utf8_lossy(want_bytes);
            let want = want.trim_end();
            // A render must never CRASH on a corpus leaf; a decline (Err) or a
            // hidden/unsatisfied field (0 label pages) is acceptable here.
            if let Ok(pages) = render_erc7730_pages(&tx, &cd, &verified, None, &resolver) {
                let label_pages = pages.as_slice().iter().filter(|p| row_str(&p[0]) == want).count();
                if label_pages >= 4 {
                    // header + 3 element pages: every element shown.
                    rendered.push((key, fmt_op));
                }
            }
        }
    }

    // (1) Coverage guard — the durable regression check.
    let unhandled: Vec<&(String, u8)> =
        all_arrays.iter().filter(|(_, f)| !HANDLED.contains(f)).collect();
    assert!(
        unhandled.is_empty(),
        "compiled ArrayAll field(s) whose element format has NO render_array_element arm \
         (would silently decline-to-blind if visible — add the arm or tighten the dbgen \
         gate):\n{unhandled:#?}",
    );

    // (2) End-to-end non-vacuity — real sole-dynamic arrays render every element.
    eprintln!(
        "compiled registry array fields: {} total, {} rendered end-to-end",
        all_arrays.len(),
        rendered.len()
    );
    for (k, _f) in &rendered {
        eprintln!("  RENDER  {k}");
    }
    assert!(
        rendered.len() >= 6,
        "expected several sole-dynamic array leaves to render every element, found {}",
        rendered.len()
    );
}

// ───────────────────────────────────────────────────────────────────────
// C1 — dynamic `bytes`/`string` leaf (FollowOffset). The value lives in the
// calldata tail; the device follows the ABI offset at the arg's head slot and
// reads the length-prefixed blob — the SAME position the contract decodes.
// ───────────────────────────────────────────────────────────────────────

/// `f(bytes arg)` calldata: selector + `[offset=32][len][data padded to 32]`.
fn calldata_sole_bytes(sig: &[u8], data: &[u8]) -> Vec<u8> {
    let mut cd = keccak256(sig)[..4].to_vec();
    cd.extend_from_slice(&u256_from_u64(32).0); // offset to the bytes arg
    cd.extend_from_slice(&u256_from_u64(data.len() as u64).0); // length
    if !data.is_empty() {
        let mut padded = data.to_vec();
        while padded.len() % 32 != 0 {
            padded.push(0);
        }
        cd.extend_from_slice(&padded);
    }
    cd
}

/// WYSIWYS value-equality: a printable `bytes` payload renders as the exact
/// ASCII text — differential over several payloads (celo `addStorageRoot(bytes
/// url)`, chain 42220, the real registry leaf).
#[test]
fn c1_dynamic_bytes_renders_exact_text() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-celo_accounts.json", 42220);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let tx = envelope(42220, entry.contract);
    let resolver = NameResolver::new();

    for url in [&b"a"[..], b"https://ex.io/s", b"ipfs://Qm12345"] {
        let calldata = calldata_sole_bytes(b"addStorageRoot(bytes)", url);
        assert_selector_matches(&verified.ir, &calldata, "addStorageRoot(bytes)");
        let pages =
            render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
        assert_all_pages_printable(&pages);
        let dump = dump_pages(&pages);
        assert!(
            dump.contains(core::str::from_utf8(url).unwrap()),
            "C1 must render the exact payload {url:?} (value-equality):\n{dump}"
        );
        let _ = find_page_by_label(&pages, "Storage Root URL");
    }
}

/// The opaque-bytes rule: non-printable / oversized `bytes` render as their
/// LENGTH + a loud marker — never a misleading full-hex wall.
#[test]
fn c1_opaque_bytes_renders_length_and_loud_marker() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-celo_accounts.json", 42220);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let tx = envelope(42220, entry.contract);
    let resolver = NameResolver::new();

    let payload = [0xFFu8; 40]; // binary, 40 bytes → opaque
    let calldata = calldata_sole_bytes(b"addStorageRoot(bytes)", &payload);
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages);
    assert!(dump.contains("40 bytes"), "opaque bytes must show length:\n{dump}");
    assert!(dump.contains("opaque"), "opaque bytes must be loudly marked:\n{dump}");
}

/// C2 — dynamic-tuple member navigation (FieldIdx → FollowOffset → FieldIdx).
/// WYSIWYS value-equality: the device follows the tuple's offset into the tail
/// and reads each member at the SAME position the contract decodes. Synthetic
/// `setConfig((uint256 amount, address target, bytes note) cfg)` (dynamic tuple
/// via the `bytes note` member) at a non-registry address — full value control.
#[test]
fn c2_dynamic_tuple_members_render_exact_values() {
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-dynamic-tuple.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // calldata: selector + [offset=32] + tuple[amount, target, note_off=96]
    //           + [note_len][note].
    let target = [0x77u8; 20];
    let mut cd = keccak256(b"setConfig((uint256,address,bytes))")[..4].to_vec();
    cd.extend_from_slice(&u256_from_u64(32).0); // offset → cfg tuple region
    cd.extend_from_slice(&u256_from_u64(0xABCDE).0); // cfg.amount (tuple slot 0)
    let mut t = [0u8; 32];
    t[12..].copy_from_slice(&target);
    cd.extend_from_slice(&t); // cfg.target (tuple slot 1)
    cd.extend_from_slice(&u256_from_u64(96).0); // cfg.note offset (rel. to tuple)
    cd.extend_from_slice(&u256_from_u64(2).0); // note len
    cd.extend_from_slice(&{
        let mut n = [0u8; 32];
        n[..2].copy_from_slice(b"hi");
        n
    });
    assert_selector_matches(&verified.ir, &cd, "setConfig((uint256,address,bytes))");

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &cd, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    // cfg.amount = 0xABCDE (raw hex word) — proves the tuple member was read.
    assert!(dump.contains("abcde"), "cfg.amount not read from the tuple:\n{dump}");
    // cfg.target = 0x7777…77 (addressName, unresolved → raw address).
    assert!(dump.contains("7777"), "cfg.target not read from the tuple:\n{dump}");
    let _ = find_page_by_label(&pages, "Amount");
    let _ = find_page_by_label(&pages, "Target");
}

/// C3 — MULTI-dynamic array (relaxed `MultiInTail` placement). Two `<arg>.[]`
/// arrays in one function: the exact-placement "whole tail" pin no longer holds,
/// so each array follows its signature-fixed offset into the tail. WYSIWYS
/// value-equality: every element of BOTH arrays renders from the exact decoded
/// position. Synthetic `batchTransfer(uint256[] amounts, address[] recipients)`
/// at a non-registry address.
#[test]
fn c3_multi_dynamic_arrays_render_exact_elements() {
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-multi-array.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // head [off_amounts=64][off_recipients=160]
    // tail amounts:[2][7][9]  recipients:[1][0xAA…AA]
    let mut cd = keccak256(b"batchTransfer(uint256[],address[])")[..4].to_vec();
    cd.extend_from_slice(&u256_from_u64(64).0); // offset → amounts
    cd.extend_from_slice(&u256_from_u64(160).0); // offset → recipients
    cd.extend_from_slice(&u256_from_u64(2).0); // amounts.len = 2
    cd.extend_from_slice(&u256_from_u64(7).0); // amounts[0]
    cd.extend_from_slice(&u256_from_u64(9).0); // amounts[1]
    cd.extend_from_slice(&u256_from_u64(1).0); // recipients.len = 1
    let mut rec = [0u8; 32];
    rec[12..].copy_from_slice(&[0xAAu8; 20]);
    cd.extend_from_slice(&rec); // recipients[0]
    assert_selector_matches(&verified.ir, &cd, "batchTransfer(uint256[],address[])");

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &cd, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages);
    // Both element counts (array-tail-hiding closed) + the exact element values.
    assert!(dump.contains("2 items"), "amounts count missing:\n{dump}");
    assert!(dump.contains("1 items"), "recipients count missing:\n{dump}");
    // amounts 7 and 9 render (amount format, 18 decimals → tiny fractions, but
    // the integer digits 7 and 9 appear); recipients 0xAA… renders.
    assert!(dump.contains('7') && dump.contains('9'), "amount elements missing:\n{dump}");
    assert!(dump.to_lowercase().contains("aaaa"), "recipient element missing:\n{dump}");
    let _ = find_page_by_label(&pages, "Amounts");
    let _ = find_page_by_label(&pages, "Recipients");
}

/// Morpho Blue `borrow` — the nested static-tuple GROUP (`marketParams`)
/// unlocked by field-group flattening. Drives the REAL shipping registry leaf
/// (`calldata-MorphoBlue.json`, mainnet). WYSIWYS differential value-equality:
/// every member of the 5-word `marketParams` tuple AND every post-tuple
/// argument renders from its EXACT ABI head-word slot — `assets` at head word
/// 5, `receiver` at head word 8 (the non-leading-static-tuple slots the
/// slot-confusion fix guards). If the flatten mis-computed any member's slot,
/// the rendered value would differ from the encoded word and this fails.
#[test]
fn morpho_borrow_nested_tuple_group_renders_exact_values() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-MorphoBlue.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // Distinct, recognizable words at each of the 9 head slots.
    let addr_word = |a: [u8; 20]| {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    };
    let loan = [0x11u8; 20];
    let collat = [0x22u8; 20];
    let oracle = [0x33u8; 20];
    let irm = [0x44u8; 20];
    let on_behalf = [0x66u8; 20];
    let receiver = [0x77u8; 20];

    let types_sig =
        "borrow((address,address,address,address,uint256),uint256,uint256,address,address)";
    let mut cd = keccak256(types_sig.as_bytes())[..4].to_vec();
    cd.extend_from_slice(&addr_word(loan)); // slot 0: loanToken
    cd.extend_from_slice(&addr_word(collat)); // slot 1: collateralToken
    cd.extend_from_slice(&addr_word(oracle)); // slot 2: oracle
    cd.extend_from_slice(&addr_word(irm)); // slot 3: irm
    cd.extend_from_slice(&u256_from_u64(0xBEEF).0); // slot 4: lltv
    cd.extend_from_slice(&u256_from_u64(0xA55E5).0); // slot 5: assets (AFTER tuple)
    cd.extend_from_slice(&u256_from_u64(0).0); // slot 6: shares
    cd.extend_from_slice(&addr_word(on_behalf)); // slot 7: onBehalf
    cd.extend_from_slice(&addr_word(receiver)); // slot 8: receiver
    // Confirms the selector matches AND `borrow` actually compiled into the IR.
    assert_selector_matches(&verified.ir, &cd, types_sig);

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &cd, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();

    // Tuple members read from their exact slots (addresses not in ERC20_DB/ENS
    // render as the raw calldata address — still faithful to the signed word).
    assert!(dump.contains("1111"), "loanToken (tuple slot 0) not read:\n{dump}");
    assert!(dump.contains("2222"), "collateralToken (tuple slot 1) not read:\n{dump}");
    assert!(dump.contains("3333"), "oracle (tuple slot 2) not read:\n{dump}");
    assert!(dump.contains("4444"), "irm (tuple slot 3) not read:\n{dump}");
    assert!(dump.contains("beef"), "lltv (tuple slot 4) not read:\n{dump}");
    // Post-tuple args at their WIDTH-AWARE head slots (not logical ordinals).
    assert!(
        dump.contains("a55e5"),
        "assets (head slot 5, AFTER the 5-word tuple) not read:\n{dump}"
    );
    assert!(dump.contains("6666"), "onBehalf (head slot 7) not read:\n{dump}");
    assert!(dump.contains("7777"), "receiver (head slot 8) not read:\n{dump}");
    // Labels the descriptor declares are present.
    let _ = find_page_by_label(&pages, "Loan Token");
    let _ = find_page_by_label(&pages, "Assets");
    let _ = find_page_by_label(&pages, "Receiver");
}

#[test]
fn array_resolve_matches_walk_differential() {
    // When the Kani-proven `walk` accepts the body, our resolver must agree
    // EXACTLY on (element-start, count). (Not the converse — we are stricter.)
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-uint256-array-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let (field, shw) = lido_array_field(&verified.ir);

    let parsed =
        pqsigner_tx::typed_call::parser::parse_text_sig(b"requestWithdrawals(uint256[],address)")
            .unwrap();

    for amounts in [
        vec![],
        vec![u256_from_u64(7)],
        vec![u256_from_u64(7), u256_from_u64(8), u256_from_u64(9)],
    ] {
        let body = rw_body(&amounts, [0x11u8; 20]);
        let walked = pqsigner_tx::typed_call::abi::walk(&parsed, &body).expect("walk accepts");
        let amounts_arg = walked.args[0]; // body_off = the length word
        let (elems_start, count) =
            super::erc7730::formatters::resolve_array(&field, &verified.ir, &body, shw)
                .expect("resolver accepts the same canonical body");
        assert_eq!(count, amounts_arg.count as usize, "count disagrees with walk");
        assert_eq!(
            elems_start,
            amounts_arg.body_off + 32,
            "element-start disagrees with walk (walk body_off is the length word)"
        );
        // element words must be byte-identical to what walk points at.
        for i in 0..count {
            let mine = &body[elems_start + i * 32..elems_start + i * 32 + 32];
            assert_eq!(mine, &amounts[i].0, "element {i} word mismatch");
        }
    }
}

/// Minimal IR blob carrying just `pool` (CTX_CONTRACT, empty formats) so a
/// test can drive `path_ends_with_array_all` over hand-built path programs.
fn ir_bytes_with_pool(pool: &[u8]) -> Vec<u8> {
    let hl = pqsigner_erc7730::ir::HEADER_LEN;
    let pool_len = pool.len() as u16;
    let mut buf = vec![0u8; hl];
    buf[0] = pqsigner_erc7730::ir::SCHEMA_VER;
    buf[1] = 0x01; // CTX_CONTRACT
    buf[2..10].copy_from_slice(&1u64.to_be_bytes());
    buf[126..128].copy_from_slice(&(hl as u16).to_be_bytes()); // metadata_off
    buf[128..130].copy_from_slice(&((hl as u16) + pool_len).to_be_bytes()); // formats_off
    buf[130..132].copy_from_slice(&pool_len.to_be_bytes()); // pool_len
    buf[132..134].copy_from_slice(&1u16.to_be_bytes()); // formats_len (count byte)
    buf.extend_from_slice(pool);
    buf.push(0u8); // format count = 0
    buf
}

#[test]
fn array_routing_is_structural_not_last_byte() {
    // A SCALAR path [Root][FieldIdx(arg=0x0024)] ends in the byte 0x24, which
    // == PathOp::ArrayAll — but it is NOT an array path. The structural router
    // must return false (→ scalar dispatch / clear-sign), NOT misroute it to
    // render_array (which would needlessly blind-sign a clear-signable field).
    let mut pool = vec![0xFFu8]; // offset-0 filler
    let scalar_off = pool.len() as u16;
    pool.push(4);
    pool.extend_from_slice(&[0x10, 0x20, 0x00, 0x24]); // Root, FieldIdx(0x0024)
    let array_off = pool.len() as u16;
    pool.push(5);
    pool.extend_from_slice(&[0x10, 0x20, 0x00, 0x00, 0x24]); // Root, FieldIdx(0), ArrayAll
    let bytes = ir_bytes_with_pool(&pool);
    let ir = pqsigner_erc7730::ir::Erc7730Ir::parse(&bytes).unwrap();

    assert!(
        !super::erc7730::formatters::path_ends_with_array_all(&ir, scalar_off).unwrap(),
        "scalar FieldIdx whose arg low byte is 0x24 must NOT route to render_array"
    );
    assert!(
        super::erc7730::formatters::path_ends_with_array_all(&ir, array_off).unwrap(),
        "a real Root+FieldIdx+ArrayAll path routes to render_array"
    );
    // PathOp::ArrayAll is the wire constant the router + dbgen agree on.
    assert_eq!(pqsigner_erc7730::ir::PathOp::ArrayAll as u8, 0x24);
}

#[test]
fn adversarial_array_resolve_declines_hostile_bodies() {
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-uint256-array-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let (field, shw) = lido_array_field(&verified.ir);
    let ir = &verified.ir;
    let resolve =
        |body: &[u8]| super::erc7730::formatters::resolve_array(&field, ir, body, shw);

    // Baseline: a canonical 2-element body resolves to (elems_start=96, count=2).
    let canon = rw_body(&[u256_from_u64(1), u256_from_u64(2)], [0x11u8; 20]);
    assert_eq!(resolve(&canon).unwrap(), (96, 2));

    // (1) offset word top-28-bytes nonzero (huge offset) → decline.
    let mut b = canon.clone();
    b[0] = 0x01;
    assert!(resolve(&b).is_err(), "huge offset must decline");

    // (2) offset != head-end (gap after the head) → decline.
    let mut b = canon.clone();
    b[31] = 96; // offset 0x60 instead of 0x40
    assert!(resolve(&b).is_err(), "non-head-end offset must decline");

    // (3) offset points INTO the head (alias the owner word) → decline.
    let mut b = canon.clone();
    b[31] = 32;
    assert!(resolve(&b).is_err(), "offset-into-head must decline");

    // (4a) length word top-28-bytes nonzero → decline.
    let mut b = canon.clone();
    b[64] = 0x01; // first byte of the length word (at offset 64)
    assert!(resolve(&b).is_err(), "huge length (top bytes) must decline");

    // (4b) length > MAX_DYNAMIC_LEN → decline.
    let mut b = rw_body(&[u256_from_u64(1)], [0x11u8; 20]);
    // overwrite the length word (offset 64) with MAX_DYNAMIC_LEN + 1.
    let big = (1u32 << 20) + 1;
    b[64 + 28..64 + 32].copy_from_slice(&big.to_be_bytes());
    assert!(resolve(&b).is_err(), "length over the cap must decline");

    // (5a) length OVER-claims (says 3, body holds 2) → decline (not whole tail).
    let mut b = canon.clone();
    b[64 + 31] = 3;
    assert!(resolve(&b).is_err(), "length over-claim must decline");

    // (5b) length UNDER-claims (says 1, body holds 2) → decline (not whole tail).
    let mut b = canon.clone();
    b[64 + 31] = 1;
    assert!(resolve(&b).is_err(), "length under-claim must decline");

    // (6) body truncated mid-element (drop the last 16 bytes of a 2-elem body).
    let b = &canon[..canon.len() - 16];
    assert!(resolve(b).is_err(), "truncated-mid-element must decline");

    // (7) body length not a multiple of 32 (drop 1 byte) → decline.
    let b = &canon[..canon.len() - 1];
    assert!(resolve(b).is_err(), "non-32-aligned body must decline");

    // (8) count == 0 → VALID (renders an empty page, no panic); resolver Ok(_, 0).
    let empty = rw_body(&[], [0x11u8; 20]);
    assert_eq!(resolve(&empty).unwrap().1, 0, "empty array is valid, count 0");

    // (9) count large-but-in-bounds (9 > MAX_ARRAY_RENDER=8) → decline, not 9 pages.
    let nine: Vec<U256> = (0..9).map(|i| u256_from_u64(i)).collect();
    let b = rw_body(&nine, [0x11u8; 20]);
    assert!(resolve(&b).is_err(), "over-cap element count must decline");

    // (10) head absent entirely (body shorter than the static head) → decline.
    let b = &canon[..16];
    assert!(resolve(b).is_err(), "short-head must decline");

    // none of the above panicked — the decline-or-safe property holds over all
    // crafted bodies (no UB, no slice-OOB), the core adversarial guarantee.
}

// ───────────────────────────────────────────────────────────────────────
// WYSIWYS belt — VULN-erc7730-visible-never-noparam-clearsign.
//
// A contract-context format that DECLARES a field but renders NONE (the
// field is `visible:"never"`) must be refused on-device so the dispatcher
// falls through to the honest blind-sign ladder instead of a parameter-less
// clear-sign. The build-time visibility gate refuses to COMPILE an
// all-`never` format, so this drives the belt directly: compile a valid
// one-field format with the field `visible:"optional"` (passes the gate and
// emits a visibility TLV), flip that TLV to `never` in the IR bytes, and
// render the patched descriptor — the exact bad-DB shape the belt exists to
// catch even though the gate makes it unshippable.
// ───────────────────────────────────────────────────────────────────────
#[test]
fn belt_rejects_all_hidden_contract_format() {
    use pqsigner_erc7730::ir::HEADER_LEN;

    // 1. Compile a valid one-field descriptor (field visible → passes gate).
    let dir = std::env::temp_dir().join(format!("pq_erc7730_belt_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let contract = [0xABu8; 20];
    let addr_hex: String = contract.iter().map(|b| format!("{b:02x}")).collect();
    let desc = format!(
        r#"{{
          "context": {{ "contract": {{ "deployments": [
            {{ "chainId": 1, "address": "0x{addr_hex}" }}
          ] }} }},
          "metadata": {{ "owner": "Belt", "contractName": "Belt" }},
          "display": {{ "formats": {{
            "poke(uint256 amount)": {{
              "intent": "Poke",
              "fields": [
                {{ "path": "amount", "label": "Amount", "format": "raw", "visible": "optional" }}
              ]
            }}
          }} }}
        }}"#
    );
    std::fs::write(dir.join("belt.json"), desc).expect("write desc");
    let policy = workspace_root().join("secure/data/erc7730/policy.toml");
    let res = dbgen::erc7730::build_db(&dir, &policy).expect("compile one-field descriptor");
    let _ = std::fs::remove_dir_all(&dir);
    let mut ir_bytes = res.entries[0].ir_bytes.clone();

    // 2. Flip the field's visibility TLV `optional (0x02)` → `never (0x01)`.
    //    Search past the fixed header only (its sha256 descriptor_hash could
    //    coincidentally hold the 3-byte pattern). push_tlv layout is
    //    `[kind=0x3F][len=0x01][value]`.
    let pat = [0x3Fu8, 0x01, 0x02];
    let hits: Vec<usize> = (HEADER_LEN..ir_bytes.len().saturating_sub(2))
        .filter(|&i| ir_bytes[i..i + 3] == pat)
        .collect();
    assert_eq!(hits.len(), 1, "exactly one visibility TLV to flip, found {hits:?}");
    ir_bytes[hits[0] + 2] = 0x01; // VIS_NEVER

    // 3. Render the patched IR directly (bypass Merkle verify — we test only
    //    the belt, and VerifiedDescriptor.ir is a public field).
    let ir = Erc7730Ir::parse(&ir_bytes).expect("patched IR still parses");
    assert!(matches!(ir.context_kind, ContextKind::Contract));
    let verified = VerifiedDescriptor { ir };

    let mut calldata = Vec::new();
    calldata.extend_from_slice(&keccak256(b"poke(uint256)")[..4]);
    calldata.extend_from_slice(&u256_from_u64(42).0);
    let tx = envelope(1, contract);
    let resolver = NameResolver::new();

    match render_erc7730_pages(&tx, &calldata, &verified, None, &resolver) {
        Err(crate::tx::erc7730_render::RenderErr::Reject(msg)) => {
            assert!(msg.contains("no visible fields"), "belt reject message: {msg}");
        }
        Err(other) => panic!("expected belt Reject, got a different RenderErr: {other:?}"),
        Ok(_) => panic!(
            "all-hidden contract format must be belt-rejected, but it rendered clear-sign pages"
        ),
    }
}

// ───────────────────────────────────────────────────────────────────────
// VULN-erc7730-eip712-nested-struct-address-hide — on-device belt.
//
// A pinned EIP-712 descriptor whose primary type has a nested struct member
// (a single opaque `hashStruct` word this renderer cannot expand) MUST be
// declined to blind-sign, not partially clear-signed or mis-resolved. Driven
// by the REAL Uniswap Permit2 descriptor from the vendored registry (its
// `PermitSingle` / `PermitTransferFrom` nest a `PermitDetails` /
// `TokenPermissions` struct), so the test also proves dbgen emitted the
// `PARAM_NESTED_STRUCT` marker into the firmware-pinned catalog.
// ───────────────────────────────────────────────────────────────────────
#[test]
fn v2_kind_declines_nested_permit2() {
    // Post-Phase-5: a nested-struct format signed via the OLD kind
    // (`render_erc7730_eip712_pages`, no `nested_blob`) MUST still decline — the
    // descent finds no DFS record to bind the `PermitDetails` hashStruct word,
    // so the whole render Rejects. A companion must use the V3 entry. This keeps
    // the "old kind never clear-signs a nested format" guarantee.
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-uniswap-permit2.json", 1);
    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
    assert!(matches!(ir.context_kind, ContextKind::Eip712));

    let fmt = ir
        .format_iter()
        .next()
        .expect("≥1 Permit2 format")
        .expect("valid format header");
    let pth = fmt.type_hash;
    let encoded_data = std::vec![0u8; fmt.static_head_words as usize * 32];

    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    match super::erc7730::render_erc7730_eip712_pages(
        1,
        &[0u8; 20],
        &pth,
        &encoded_data,
        &verified,
        None,
        &resolver,
    ) {
        Err(crate::tx::erc7730_render::RenderErr::Reject(_)) => {}
        Err(other) => panic!("expected a nested Reject, got {other:?}"),
        Ok(_) => panic!("nested Permit2 format must NOT clear-sign via the V2 (no-nested-blob) path"),
    }
}

// ───────────────────────────────────────────────────────────────────────
// THE DECISIVE nested-EIP-712 test (design §3 rule 6): a REAL Permit2
// PermitSingle typed message drives the V3 render path. (a) proves the nested
// members render (amount + expiration date + spender shown; nonce + sigDeadline
// hidden); (b) proves the binding is NON-VACUOUS — flipping ANY nested word
// (shown OR hidden) OR the committed top-level `details` word flips to DECLINE.
// (a) alone would pass even if the keccak binding were never checked; (b) is
// what proves shown ⟺ signed.
// ───────────────────────────────────────────────────────────────────────

// typeHash(PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)) — foundry.
const PERMIT_DETAILS_TYPEHASH: [u8; 32] = [
    0x65, 0x62, 0x6c, 0xad, 0x6c, 0xb9, 0x64, 0x93, 0xbf, 0x6f, 0x5e, 0xbe, 0xa2, 0x87, 0x56, 0xc9,
    0x66, 0xf0, 0x23, 0xab, 0x9e, 0x8a, 0x83, 0xa7, 0x10, 0x18, 0x49, 0xd5, 0x57, 0x3b, 0x36, 0x78,
];

/// Build a valid PermitSingle (top `encoded_data`, `nested_blob`) for a concrete
/// order. `nested_ed` = token | amount | expiration | nonce (4 words); the top
/// `details` word is the REAL `hashStruct(PermitDetails)` = the device's binding
/// target. Returns `(top_ed[96], nested_blob[2+128])`.
fn permit_single_vectors(
    token: [u8; 20],
    amount: u64,
    expiration: u64,
    nonce: u64,
    spender: [u8; 20],
    sig_deadline: u64,
) -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let mut nested_ed = std::vec![0u8; 128];
    nested_ed[12..32].copy_from_slice(&token);
    nested_ed[32 + 24..64].copy_from_slice(&amount.to_be_bytes());
    nested_ed[64 + 24..96].copy_from_slice(&expiration.to_be_bytes());
    nested_ed[96 + 24..128].copy_from_slice(&nonce.to_be_bytes());

    // The committed word IS the real hashStruct — the same primitive the device
    // recomputes and binds against (not circular: the device uses the IR-pinned
    // type_hash + the blob's nested_ed; a flip in either breaks the equality).
    let details_hs = super::erc7730::nested::hash_struct(&PERMIT_DETAILS_TYPEHASH, &nested_ed);

    let mut top_ed = std::vec![0u8; 96];
    top_ed[0..32].copy_from_slice(&details_hs);
    top_ed[32 + 12..64].copy_from_slice(&spender);
    top_ed[64 + 24..96].copy_from_slice(&sig_deadline.to_be_bytes());

    let mut nested_blob = std::vec![0u8; 2];
    nested_blob[0..2].copy_from_slice(&(nested_ed.len() as u16).to_be_bytes());
    nested_blob.extend_from_slice(&nested_ed);

    (top_ed, nested_blob)
}

#[test]
fn v3_permit_single_renders_nested_members() {
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-uniswap-permit2.json", 1);
    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
    // PermitSingle primary-type hash (the only surviving Permit2 format).
    let pth: [u8; 32] = [
        0xf3, 0x84, 0x1c, 0xd1, 0xff, 0x00, 0x85, 0x02, 0x6a, 0x63, 0x27, 0xb6, 0x20, 0xb6, 0x79,
        0x97, 0xce, 0x40, 0xf2, 0x82, 0xc8, 0x8a, 0x8e, 0x90, 0x5a, 0x7a, 0x56, 0x26, 0xe3, 0x10,
        0xf3, 0xd0,
    ];
    let token = [0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e,
        0x9E, 0xb0, 0xcE, 0x36, 0x06, 0xeB, 0x48]; // USDC
    let spender = [0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5,
        0xa6, 0xcC, 0x9D, 0x4B, 0x2b, 0x7F, 0xAD]; // Universal Router
    let (top_ed, nested_blob) =
        permit_single_vectors(token, 1_000_000_000, 1_735_689_600, 0, spender, 1_735_689_600);

    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    let pages = super::erc7730::render_erc7730_eip712_pages_v3(
        1,
        &[0u8; 20],
        &pth,
        &top_ed,
        &nested_blob,
        &verified,
        None,
        &resolver,
    )
    .expect("valid PermitSingle clear-signs via V3");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    // spender (top-level, shown).
    assert!(dump.contains("3fc9"), "spender must be shown:\n{dump}");
    // nested amount = 1_000_000_000 → without token metadata it renders raw
    // (`! raw, dec=?`); the digits must appear.
    assert!(dump.contains("1000000000"), "nested amount must render:\n{dump}");
    // nested expiration is a timestamp date → a 2025 date renders.
    assert!(dump.contains("2025"), "nested expiration date must render:\n{dump}");
}

#[test]
fn v3_permit_single_binding_is_non_vacuous() {
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-uniswap-permit2.json", 1);
    let pth: [u8; 32] = [
        0xf3, 0x84, 0x1c, 0xd1, 0xff, 0x00, 0x85, 0x02, 0x6a, 0x63, 0x27, 0xb6, 0x20, 0xb6, 0x79,
        0x97, 0xce, 0x40, 0xf2, 0x82, 0xc8, 0x8a, 0x8e, 0x90, 0x5a, 0x7a, 0x56, 0x26, 0xe3, 0x10,
        0xf3, 0xd0,
    ];
    let token = [0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e,
        0x9E, 0xb0, 0xcE, 0x36, 0x06, 0xeB, 0x48];
    let spender = [0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5,
        0xa6, 0xcC, 0x9D, 0x4B, 0x2b, 0x7F, 0xAD];
    let (top_ed, nested_blob) =
        permit_single_vectors(token, 1_000_000_000, 1_735_689_600, 0, spender, 1_735_689_600);

    let render = |ed: &[u8], blob: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &pth, ed, blob, &verified, None, &resolver,
        )
    };

    // Baseline: renders.
    assert!(render(&top_ed, &nested_blob).is_ok(), "baseline must render");

    // (b1) Flip EVERY byte of EVERY nested word (shown token/amount/expiration
    // AND hidden nonce) — each flip breaks keccak(type_hash‖nested_ed) ==
    // committed → DECLINE. Proves the binding covers the COMPLETE member, not
    // just the shown subset.
    for word in 0..4usize {
        for byte in 0..32usize {
            let mut blob = nested_blob.clone();
            blob[2 + word * 32 + byte] ^= 0x01; // flip one bit inside nested_ed
            assert!(
                render(&top_ed, &blob).is_err(),
                "flipping nested word {word} byte {byte} must decline (binding is live)"
            );
        }
    }

    // (b2) Flip the committed top-level `details` hashStruct word → the device's
    // recomputed hashStruct no longer matches → DECLINE.
    for byte in 0..32usize {
        let mut ed = top_ed.clone();
        ed[byte] ^= 0x01;
        assert!(
            render(&ed, &nested_blob).is_err(),
            "flipping committed details word byte {byte} must decline"
        );
    }
}

// PermitSingle primary-type hash (foundry) — shared by the reconciliation tests.
const PERMIT_SINGLE_TYPEHASH: [u8; 32] = [
    0xf3, 0x84, 0x1c, 0xd1, 0xff, 0x00, 0x85, 0x02, 0x6a, 0x63, 0x27, 0xb6, 0x20, 0xb6, 0x79, 0x97,
    0xce, 0x40, 0xf2, 0x82, 0xc8, 0x8a, 0x8e, 0x90, 0x5a, 0x7a, 0x56, 0x26, 0xe3, 0x10, 0xf3, 0xd0,
];

fn permit_single_valid_vectors() -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let token = [0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e,
        0x9E, 0xb0, 0xcE, 0x36, 0x06, 0xeB, 0x48];
    let spender = [0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5,
        0xa6, 0xcC, 0x9D, 0x4B, 0x2b, 0x7F, 0xAD];
    permit_single_vectors(token, 1_000_000_000, 1_735_689_600, 0, spender, 1_735_689_600)
}

/// Walk an EIP-712 IR's formats section and return the byte offset of the
/// `nested_descent_count` byte of the format whose `type_hash == target`.
/// Mirrors `ir::FormatIter` (fixed prefix 9 B: selector(4) field_count(1)
/// intent_len(1) static_head_words(2) nested_descent_count(1); then intent;
/// then type_hash(32) for EIP-712; then `field_count` FieldEntry records).
fn eip712_format_ndc_offset(ir_bytes: &[u8], target: &[u8; 32]) -> Option<usize> {
    let formats_off = u16::from_be_bytes([ir_bytes[128], ir_bytes[129]]) as usize;
    let count = *ir_bytes.get(formats_off)? as usize;
    let mut p = formats_off + 1;
    for _ in 0..count {
        let entry_start = p;
        let field_count = *ir_bytes.get(p + 4)? as usize;
        let intent_len = *ir_bytes.get(p + 5)? as usize;
        p += 9 + intent_len; // fixed prefix + intent
        let th = ir_bytes.get(p..p + 32)?;
        let matched = th == target;
        p += 32; // EIP-712 type_hash
        for _ in 0..field_count {
            let label_len = *ir_bytes.get(p + 1)? as usize;
            p += 2 + label_len + 4; // format_op + label_len + label + path_off + param_off
        }
        if matched {
            return Some(entry_start + 8);
        }
    }
    None
}

/// THE reconciliation tripwire test (advisor blocker #1 — the E1 pinned-count
/// control). The flip→decline tests all reject at the BINDING (step 6), which
/// returns before render_fields completes, so they never exercise the
/// reconciliation's REJECT path. Here the blob binds correctly (render_fields
/// completes, records_consumed == 1) but the format header's PINNED
/// `nested_descent_count` is hand-patched to a WRONG value → the after-render
/// `records_consumed != nested_descent_count` check FIRES → decline. Proves the
/// pinned count is actually compared (the control is NON-tautological + the path
/// is reachable), mirroring the dbgen byte-patch test style. In production the
/// IR is Merkle-pinned so this byte can't be forged; the test proves the device
/// logic catches a (future) dbgen regression that emits the wrong count.
#[test]
fn v3_reconciliation_rejects_wrong_pinned_descent_count() {
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-uniswap-permit2.json", 1);
    let (top_ed, nested_blob) = permit_single_valid_vectors();

    // Locate PermitSingle's format header nested_descent_count byte. The permit2
    // leaf now carries three formats (PermitSingle, PermitTransferFrom,
    // PermitBatch), so we WALK the formats section to find PermitSingle's entry
    // (by its type_hash) rather than assuming it is first. Within a format entry
    // the fixed prefix is selector(4)+field_count(1)+intent_len(1)+
    // static_head_words(2) = 8, so nested_descent_count sits at entry_start + 8.
    let ndc_off = eip712_format_ndc_offset(&leaf.ir_bytes, &PERMIT_SINGLE_TYPEHASH)
        .expect("PermitSingle format present in the permit2 leaf");

    let render_patched = |ndc: u8| {
        let mut ir_bytes = leaf.ir_bytes.clone();
        assert_eq!(ir_bytes[ndc_off], 1, "PermitSingle pins exactly one descent point");
        ir_bytes[ndc_off] = ndc;
        let ir = Erc7730Ir::parse(&ir_bytes).expect("patched IR still parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &PERMIT_SINGLE_TYPEHASH, &top_ed, &nested_blob, &verified, None, &resolver,
        )
    };

    // Claim TWO descent points but only one record binds → 1 != 2 → decline.
    assert!(
        render_patched(2).is_err(),
        "records_consumed(1) != pinned nested_descent_count(2) must decline"
    );
    // Claim ZERO → 1 != 0 → decline (a regression that stopped emitting the pin).
    assert!(
        render_patched(0).is_err(),
        "records_consumed(1) != pinned nested_descent_count(0) must decline"
    );
}

/// The other half of E4-3 (total consumption): a valid nested_blob plus one
/// trailing byte → after the DFS binds the single record, cursor != blob.len()
/// → decline. (nested_blob is display-only/unsigned, so padding is hygiene not a
/// live exploit — but the cursor check must fire.)
#[test]
fn v3_reconciliation_rejects_trailing_nested_blob() {
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-uniswap-permit2.json", 1);
    let (top_ed, mut nested_blob) = permit_single_valid_vectors();
    nested_blob.push(0xEE); // one unconsumed trailing byte

    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    assert!(
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &PERMIT_SINGLE_TYPEHASH, &top_ed, &nested_blob, &verified, None, &resolver,
        )
        .is_err(),
        "cursor != nested_blob.len() (trailing byte) must decline"
    );
}

// typeHash(TokenPermissions(address token,uint256 amount)) — foundry.
const TOKEN_PERMISSIONS_TYPEHASH: [u8; 32] = [
    0x61, 0x83, 0x58, 0xac, 0x3d, 0xb8, 0xdc, 0x27, 0x4f, 0x0c, 0xd8, 0x82, 0x9d, 0xa7, 0xe2, 0x34,
    0xbd, 0x48, 0xcd, 0x73, 0xc4, 0xa7, 0x40, 0xae, 0xde, 0x1a, 0xde, 0xc9, 0x84, 0x6d, 0x06, 0xa1,
];
// typeHash(PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)...) — foundry.
const PERMIT_TRANSFER_FROM_TYPEHASH: [u8; 32] = [
    0x93, 0x9c, 0x21, 0xa4, 0x8a, 0x8d, 0xbe, 0x3a, 0x9a, 0x24, 0x04, 0xa1, 0xd4, 0x66, 0x91, 0xe4,
    0xd3, 0x9f, 0x65, 0x83, 0xd6, 0xec, 0x6b, 0x35, 0x71, 0x46, 0x04, 0xc9, 0x86, 0xd8, 0x01, 0x06,
];

/// The MINIMAL nested binding: Permit2 `PermitTransferFrom` (`TokenPermissions`,
/// 2 members) — unlocked by the `nonce` curation. Proves the v0x03 machinery
/// handles a smaller struct than PermitSingle end-to-end: the nested amount +
/// token render, top-level spender + deadline show, `nonce` (top word 2) hides,
/// AND flipping the committed `permitted` word declines (binding is live for the
/// 2-member shape too).
#[test]
fn v3_permit_transfer_from_renders_and_flip_declines() {
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-uniswap-permit2.json", 1);
    let token = [0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e,
        0x9E, 0xb0, 0xcE, 0x36, 0x06, 0xeB, 0x48]; // USDC
    let spender = [0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5,
        0xa6, 0xcC, 0x9D, 0x4B, 0x2b, 0x7F, 0xAD];

    // nested_ed (TokenPermissions) = token | amount (2 words).
    let mut nested_ed = std::vec![0u8; 64];
    nested_ed[12..32].copy_from_slice(&token);
    nested_ed[32 + 24..64].copy_from_slice(&500_000_000u64.to_be_bytes()); // 500 USDC
    let permitted_hs = super::erc7730::nested::hash_struct(&TOKEN_PERMISSIONS_TYPEHASH, &nested_ed);

    // top_ed (PermitTransferFrom) = permitted | spender | nonce | deadline (4 words).
    let mut top_ed = std::vec![0u8; 128];
    top_ed[0..32].copy_from_slice(&permitted_hs);
    top_ed[32 + 12..64].copy_from_slice(&spender);
    top_ed[64 + 24..96].copy_from_slice(&42u64.to_be_bytes()); // nonce (HIDDEN)
    top_ed[96 + 24..128].copy_from_slice(&1_735_689_600u64.to_be_bytes()); // deadline (SHOWN)

    let mut nested_blob = std::vec![0u8; 2];
    nested_blob[0..2].copy_from_slice(&(nested_ed.len() as u16).to_be_bytes());
    nested_blob.extend_from_slice(&nested_ed);

    let render = |ed: &[u8], blob: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &PERMIT_TRANSFER_FROM_TYPEHASH, ed, blob, &verified, None, &resolver,
        )
    };

    let pages = render(&top_ed, &nested_blob).expect("valid PermitTransferFrom clear-signs");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    assert!(dump.contains("3fc9"), "spender must be shown:\n{dump}");
    assert!(dump.contains("500000000"), "nested amount must render:\n{dump}");
    assert!(dump.contains("2025"), "deadline date must render:\n{dump}");
    assert!(!dump.contains("hidden"), "sanity");

    // Flip the committed `permitted` hashStruct word → decline (binding live).
    for byte in [0usize, 15, 31] {
        let mut ed = top_ed.clone();
        ed[byte] ^= 0x01;
        assert!(
            render(&ed, &nested_blob).is_err(),
            "flipping committed permitted word byte {byte} must decline"
        );
    }
    // Flip a nested word → decline.
    let mut blob = nested_blob.clone();
    blob[2 + 40] ^= 0x01; // inside the amount word
    assert!(render(&top_ed, &blob).is_err(), "flipping nested amount must decline");
}

// PermitBatch primary-type hash (foundry).
const PERMIT_BATCH_TYPEHASH: [u8; 32] = [
    0xaf, 0x1b, 0x0d, 0x30, 0xd2, 0xca, 0xb0, 0x38, 0x0e, 0x68, 0xf0, 0x68, 0x90, 0x07, 0xe3, 0x25,
    0x49, 0x93, 0xc5, 0x96, 0xf2, 0xfd, 0xd0, 0xaa, 0xa7, 0xf4, 0xd0, 0x4f, 0x79, 0x44, 0x08, 0x63,
];

/// A REAL 2-element Permit2 `PermitBatch` (v2 array-of-struct). el0 = USDC/1e9/
/// 2025-01-01/nonce0, el1 = WETH/5e18/2026-01-01/nonce1. The committed `details`
/// word is the foundry-pinned array binding `keccak(hashStruct(el0)‖hashStruct(el1))
/// = 0x57b01054…` (recomputed here via the SAME device primitive — not circular:
/// the device recomputes from the IR-pinned type_hash + the blob; a flip in
/// either breaks the equality). Returns `(top_ed[96], nested_blob)`.
fn permit_batch_vectors() -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let usdc = [0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e,
        0x9E, 0xb0, 0xcE, 0x36, 0x06, 0xeB, 0x48];
    let weth = [0xC0u8, 0x2a, 0xaA, 0x39, 0xb2, 0x23, 0xFE, 0x8D, 0x0A, 0x0e, 0x5C, 0x4F, 0x27,
        0xeA, 0xD9, 0x08, 0x3C, 0x75, 0x6C, 0xc2];
    let spender = [0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5,
        0xa6, 0xcC, 0x9D, 0x4B, 0x2b, 0x7F, 0xAD];

    let mut el0 = std::vec![0u8; 128];
    el0[12..32].copy_from_slice(&usdc);
    el0[32 + 24..64].copy_from_slice(&1_000_000_000u64.to_be_bytes());
    el0[64 + 24..96].copy_from_slice(&1_735_689_600u64.to_be_bytes());
    let mut el1 = std::vec![0u8; 128];
    el1[12..32].copy_from_slice(&weth);
    el1[32 + 24..64].copy_from_slice(&5_000_000_000_000_000_000u64.to_be_bytes());
    el1[64 + 24..96].copy_from_slice(&1_767_225_600u64.to_be_bytes());
    el1[96 + 24..128].copy_from_slice(&1u64.to_be_bytes());

    let details_word =
        super::erc7730::nested::hash_struct_array(&PERMIT_DETAILS_TYPEHASH, &[&el0[..], &el1[..]]);
    let mut top_ed = std::vec![0u8; 96];
    top_ed[0..32].copy_from_slice(&details_word);
    top_ed[32 + 12..64].copy_from_slice(&spender);
    top_ed[64 + 24..96].copy_from_slice(&1_735_689_600u64.to_be_bytes());

    // nested_blob = [u16 elem_count=2] [u16 128][el0] [u16 128][el1].
    let mut blob = std::vec![0u8, 2]; // elem_count = 2
    blob.extend_from_slice(&128u16.to_be_bytes());
    blob.extend_from_slice(&el0);
    blob.extend_from_slice(&128u16.to_be_bytes());
    blob.extend_from_slice(&el1);
    (top_ed, blob)
}

#[test]
fn v3_permit_batch_array_renders_both_elements() {
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-uniswap-permit2.json", 1);
    let (top_ed, blob) = permit_batch_vectors();
    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    let pages = super::erc7730::render_erc7730_eip712_pages_v3(
        1, &[0u8; 20], &PERMIT_BATCH_TYPEHASH, &top_ed, &blob, &verified, None, &resolver,
    )
    .expect("valid 2-element PermitBatch clear-signs");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    // Both element amounts render (raw, no token metadata → `! raw, dec=?`; a
    // 19-digit value splits across two display rows, so match the leading run).
    assert!(dump.contains("1000000000"), "element 0 (USDC 1e9) amount:\n{dump}");
    assert!(dump.contains("5000000000000000"), "element 1 (WETH 5e18) amount:\n{dump}");
    // Distinct token addresses (unverified pages) prove per-element resolution.
    assert!(dump.contains("a0b86991c6218b"), "element 0 token (USDC):\n{dump}");
    assert!(dump.contains("c02aaa39"), "element 1 token (WETH):\n{dump}");
    // The "Item 1 of 2" / "Item 2 of 2" dividers.
    assert!(dump.contains("item 1 of 2"), "element 0 divider:\n{dump}");
    assert!(dump.contains("item 2 of 2"), "element 1 divider:\n{dump}");
    // Both element expiration dates.
    assert!(dump.contains("2025"), "element 0 expiration:\n{dump}");
    assert!(dump.contains("2026"), "element 1 expiration:\n{dump}");
}

#[test]
fn v3_permit_batch_array_binding_is_non_vacuous() {
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-uniswap-permit2.json", 1);
    let (top_ed, blob) = permit_batch_vectors();

    let render = |ed: &[u8], b: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &PERMIT_BATCH_TYPEHASH, ed, b, &verified, None, &resolver,
        )
    };
    assert!(render(&top_ed, &blob).is_ok(), "baseline renders");

    // (a) Flip ONE bit inside EACH element word (both elements, shown + hidden
    // words) → the concat hashStruct no longer matches `committed` → DECLINE.
    // `blob` layout: elem_count(2) then [len(2) el0(128)] [len(2) el1(128)];
    // element bytes start at offset 4 (el0) and 4+128+2=134 (el1).
    for (base, label) in [(4usize, "el0"), (134usize, "el1")] {
        for word in 0..4usize {
            let mut b = blob.clone();
            b[base + word * 32] ^= 0x01;
            assert!(
                render(&top_ed, &b).is_err(),
                "flipping {label} word {word} must decline (array binding is live)"
            );
        }
    }
    // (b) Flip the committed `details` array word → DECLINE.
    for byte in [0usize, 31] {
        let mut ed = top_ed.clone();
        ed[byte] ^= 0x01;
        assert!(render(&ed, &blob).is_err(), "flipping committed array word byte {byte} declines");
    }
    // (c) Lie about elem_count (claim 1) — the concat over 1 element != committed
    // (which bound 2) → DECLINE (element-count is implicitly bound by the hash).
    let mut b = blob.clone();
    b[0] = 0;
    b[1] = 1;
    assert!(render(&top_ed, &b).is_err(), "lying elem_count=1 must decline");
    // (d) elem_count = 0 → explicit decline (the empty-batch attack).
    let mut b0 = blob.clone();
    b0[0] = 0;
    b0[1] = 0;
    assert!(render(&top_ed, &b0).is_err(), "elem_count=0 must decline (empty batch)");
}

/// EIP-2612 Permit `owner` allowlist (`hidden_address_allow`): the canonical
/// Ledger permit template hides `owner` (== the signer) + `nonce` and shows
/// `spender` / `value` / `deadline`. Without the allowlist entry rule 2 refuses
/// it and all 74 token permits blind-sign; with it, they clear-sign. This drives
/// a REAL restored permit (LINK) through the EIP-712 render path and proves the
/// effect-bearing `spender` renders while `owner` stays hidden — the exact
/// WYSIWYS content of the allowlist decision.
#[test]
fn erc2612_permit_renders_spender_hides_owner() {
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-permit-ethereum-link.json", 1);
    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit IR parses");
    assert!(matches!(ir.context_kind, ContextKind::Eip712));
    let fmt = ir.format_iter().next().expect("≥1 format").expect("valid header");
    let pth = fmt.type_hash;

    // encoded_data = owner | spender | value | nonce | deadline (5 head words).
    let mut ed = std::vec![0u8; 5 * 32];
    ed[12..32].copy_from_slice(&[0x11u8; 20]); // owner   (HIDDEN, == signer)
    ed[44..64].copy_from_slice(&[0x22u8; 20]); // spender (SHOWN)
    ed[64 + 29..96].copy_from_slice(&[0x0A, 0xBC, 0xDE]); // value = 0x0abcde (SHOWN)
    ed[96 + 24..128].copy_from_slice(&0x6767_6767u64.to_be_bytes()); // deadline ts (SHOWN)

    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    let pages = super::erc7730::render_erc7730_eip712_pages(
        1, &[0u8; 20], &pth, &ed, &verified, None, &resolver,
    )
    .expect("permit clear-signs (owner allowlisted)");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    assert!(dump.contains("2222"), "spender must be shown:\n{dump}");
    assert!(
        !dump.contains("1111"),
        "owner is allowlist-hidden and must NOT appear:\n{dump}"
    );
}

// ───────────────────────────────────────────────────────────────────────
// Tier B: tokenPath byte-slice / array-index resolver — Uniswap swaps.
//
// The token IDENTITY for a swap amount lives packed inside a dynamic leg:
// `exactInput` `params.path.[0:20]` (input token) / `[-20:]` (output token),
// and V2 `swapExactTokensForTokens` `path.[0]` / `[-1]`. These tests drive REAL
// ABI-encoded multi-hop calldata and assert the resolved token — proving the
// slice extracts the correct 20 bytes end-to-end: the ERC-20 symbol renders on a
// leg's amount page ONLY when the slice matches that leg's real token (a wrong
// extraction would miss the metadata and fall to raw). The magnitude is asserted
// too (the amount itself resolves through the dynamic tuple / static head).
// ───────────────────────────────────────────────────────────────────────
const UNI_V3: [u8; 20] = [
    0x68, 0xb3, 0x46, 0x58, 0x33, 0xfb, 0x72, 0xa7, 0x0e, 0xcd, 0xf4, 0x85, 0xe0, 0xe4, 0xc7, 0xbd,
    0x86, 0x65, 0xfc, 0x45,
];
const TOKEN_IN: [u8; 20] = [0x11; 20];
const TOKEN_MID: [u8; 20] = [0xAB; 20];
const TOKEN_OUT: [u8; 20] = [0x22; 20];

fn meta(contract: [u8; 20], decimals: u8, symbol: &'static [u8]) -> Erc20Metadata<'static> {
    Erc20Metadata {
        chain_id: 1,
        contract,
        decimals,
        name: symbol,
        symbol,
    }
}

/// Uniswap V3 packed path: `token0 ‖ fee(3B) ‖ token1`.
fn packed_v3_path(token0: [u8; 20], fee: u32, token1: [u8; 20]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&token0);
    p.extend_from_slice(&fee.to_be_bytes()[1..4]); // 3-byte fee
    p.extend_from_slice(&token1);
    p
}

/// `exactInput((bytes path, address recipient, uint256 amountIn, uint256 amountOutMinimum))`.
fn calldata_exact_input(
    token0: [u8; 20],
    fee: u32,
    token1: [u8; 20],
    recipient: [u8; 20],
    amount_in: U256,
    amount_out_min: U256,
) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&[0xb8, 0x58, 0x18, 0x3f]); // exactInput selector
    d.extend_from_slice(&u256_from_u64(0x20).0); // offset to params tuple
    // params tuple head (4 words): path-offset, recipient, amountIn, amountOutMin.
    d.extend_from_slice(&u256_from_u64(128).0); // path offset (relative to tuple start)
    let mut rec = [0u8; 32];
    rec[12..].copy_from_slice(&recipient);
    d.extend_from_slice(&rec);
    d.extend_from_slice(&amount_in.0);
    d.extend_from_slice(&amount_out_min.0);
    // path blob: [len][packed, padded to 32].
    let path = packed_v3_path(token0, fee, token1);
    d.extend_from_slice(&u256_from_u64(path.len() as u64).0);
    let mut padded = path;
    while padded.len() % 32 != 0 {
        padded.push(0);
    }
    d.extend_from_slice(&padded);
    d
}

/// `swap*ForTokens(uint256 a0, uint256 a1, address[] path, address to)`
/// (same layout for `swapExactTokensForTokens` / `swapTokensForExactTokens`).
fn calldata_v2_swap(
    selector: [u8; 4],
    a0: U256,
    a1: U256,
    path: &[[u8; 20]],
    to: [u8; 20],
) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&selector);
    d.extend_from_slice(&a0.0);
    d.extend_from_slice(&a1.0);
    d.extend_from_slice(&u256_from_u64(128).0); // offset to path array (4-word head)
    let mut t = [0u8; 32];
    t[12..].copy_from_slice(&to);
    d.extend_from_slice(&t);
    d.extend_from_slice(&u256_from_u64(path.len() as u64).0); // element count
    for a in path {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(a);
        d.extend_from_slice(&w);
    }
    d
}

fn render_uni(calldata: &[u8], token: Option<&Erc20Metadata<'_>>) -> Pages {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    render_erc7730_pages(&tx, calldata, &verified, token, &resolver).expect("render")
}

#[test]
fn uniswap_exact_input_binds_input_token_from_head_slice() {
    // `[0:20]` = input token. amountIn 1.5 TKA (6 decimals).
    let calldata = calldata_exact_input(
        TOKEN_IN,
        3000,
        TOKEN_OUT,
        [0x33; 20],
        u256_from_u64(1_500_000),
        u256_from_u64(4_000_000_000_000_000_000),
    );
    let m = meta(TOKEN_IN, 6, b"TKA");
    let pages = render_uni(&calldata, Some(&m));
    assert_all_pages_printable(&pages);

    let p = find_page_by_label(&pages, "Amount to Send");
    let rows = page_strs(&pages, p);
    assert!(
        rows.iter().any(|r| r.contains("TKA")),
        "input token id from params.path.[0:20] must bind → TKA: {rows:?}"
    );
    // The amount wraps across the two value rows on the 16-col display.
    let val = format!("{}{}", rows[1], rows[2]);
    assert!(
        val.contains("1.5"),
        "amountIn magnitude must resolve through the dynamic tuple: {rows:?}"
    );
    // Per-leg: the OUTPUT leg (token1 != TKA metadata) must NOT show TKA.
    let po = find_page_by_label(&pages, "Minimum to Recei");
    let ro = page_strs(&pages, po);
    assert!(
        !ro.iter().any(|r| r.contains("TKA")),
        "output leg must not inherit the input token's symbol: {ro:?}"
    );
}

#[test]
fn uniswap_exact_input_binds_output_token_from_tail_slice() {
    // `[-20:]` = output token. amountOutMinimum 4 TKB (18 decimals).
    let calldata = calldata_exact_input(
        TOKEN_IN,
        3000,
        TOKEN_OUT,
        [0x33; 20],
        u256_from_u64(1_500_000),
        u256_from_u64(4_000_000_000_000_000_000),
    );
    let m = meta(TOKEN_OUT, 18, b"TKB");
    let pages = render_uni(&calldata, Some(&m));
    let p = find_page_by_label(&pages, "Minimum to Recei");
    let rows = page_strs(&pages, p);
    assert!(
        rows.iter().any(|r| r.contains("TKB")),
        "output token id from params.path.[-20:] must bind → TKB: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains('4')),
        "amountOutMinimum magnitude must resolve: {rows:?}"
    );
}

#[test]
fn uniswap_v2_swap_binds_first_and_last_array_element() {
    // 3-hop path so `[-1]` genuinely selects the LAST element, not index 1.
    let path = [TOKEN_IN, TOKEN_MID, TOKEN_OUT];
    // `swapExactTokensForTokens`: amountIn tokenPath = path.[0].
    let cd_in = calldata_v2_swap(
        [0x47, 0x2b, 0x43, 0xf3],
        u256_from_u64(1_500_000),
        u256_from_u64(1),
        &path,
        [0x33; 20],
    );
    let ma = meta(TOKEN_IN, 6, b"TKA");
    let pages = render_uni(&cd_in, Some(&ma));
    let p = find_page_by_label(&pages, "Amount to Send");
    let rows = page_strs(&pages, p);
    assert!(
        rows.iter().any(|r| r.contains("TKA")),
        "path.[0] must bind the first element → TKA: {rows:?}"
    );

    // `swapTokensForExactTokens`: amountOut tokenPath = path.[-1] (last element).
    // amountOut = 4 TKB (18 decimals); amountInMax's path.[0] leg stays unbound.
    let cd_out = calldata_v2_swap(
        [0x42, 0x71, 0x2a, 0x67],
        u256_from_u64(4_000_000_000_000_000_000),
        u256_from_u64(1_500_000),
        &path,
        [0x33; 20],
    );
    let mb = meta(TOKEN_OUT, 18, b"TKB");
    let pages2 = render_uni(&cd_out, Some(&mb));
    let p2 = find_page_by_label(&pages2, "Amount to Receiv");
    let rows2 = page_strs(&pages2, p2);
    assert!(
        rows2.iter().any(|r| r.contains("TKB")),
        "path.[-1] must bind the LAST element (3-hop) → TKB: {rows2:?}"
    );
    // Non-vacuity: the last element is TOKEN_OUT, not TOKEN_MID.
    assert!(
        !rows2.iter().any(|r| r.contains("TKM")),
        "path.[-1] must not pick the middle element: {rows2:?}"
    );
}

#[test]
fn uniswap_slice_binding_is_non_vacuous_decoy_token() {
    // A decoy token NOT in the path must NOT bind — proves the symbol renders
    // only when the extracted slice equals the metadata contract (a wrong slice
    // would silently fall to the raw-amount fallback, never a wrong symbol).
    let calldata = calldata_exact_input(
        TOKEN_IN,
        3000,
        TOKEN_OUT,
        [0x33; 20],
        u256_from_u64(1_500_000),
        u256_from_u64(4_000_000_000_000_000_000),
    );
    let decoy = meta([0x99; 20], 6, b"DEC");
    let pages = render_uni(&calldata, Some(&decoy));
    let dump = dump_pages(&pages);
    assert!(
        !dump.contains("DEC"),
        "decoy token (not in path) must never bind:\n{dump}"
    );
}

// ───────────────────────────────────────────────────────────────────────
// v3 DEEP NESTING + NESTED-ARRAY-IN-STRUCT — UniswapX ExclusiveDutchOrder.
//
// Signed struct: PermitWitnessTransferFrom(TokenPermissions permitted, address
// spender, uint256 nonce, uint256 deadline, ExclusiveDutchOrder witness). The
// `witness` is a depth-1 nested struct that ITSELF contains a nested struct
// `info` (OrderInfo, depth 2 — curated to SHOW reactor/swapper/validationContract)
// and a nested array-of-struct `outputs` (DutchOutput[], depth 2). The binding
// chains keccak(typeHash ‖ ed) top-down to the signed digest at EVERY level:
//   top_ed[0]=hashStruct(permitted), top_ed[4]=hashStruct(witness);
//   witness_ed[0]=hashStruct(info), witness_ed[8]=hashStructArray(outputs).
// DFS blob order = device descent order = permitted | witness | info |
// {elem_count=2, out0, out1} (info before outputs = the curated field order).
// ───────────────────────────────────────────────────────────────────────

/// Parse a 64-char hex string into a `[u8; 32]` (test-local; the foundry-pinned
/// typeHashes are easier to read as hex than as byte arrays).
fn hx32(s: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    for (i, b) in o.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    o
}

// PermitWitnessTransferFrom(...ExclusiveDutchOrder witness) primary type hash
// (the value dbgen emits into the format header; see erc7730.review.txt).
const EXCLUSIVE_DUTCH_PRIMARY: &str =
    "2846b6ca8e0ecdbc9ca7696f16bdf77b3baf48504ac14d6a541484ec197e91eb";

/// Build a valid 2-output UniswapX `ExclusiveDutchOrder`: `(top_ed[160],
/// nested_blob)`. Every committed word is the REAL chained `hashStruct`
/// (recomputed via the device primitive — NOT circular: the device rebuilds each
/// from the IR-pinned typeHash + the companion blob; a flip in either breaks the
/// equality). `nested_blob` is the device's DFS descent order.
fn exclusive_dutch_vectors() -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    use super::erc7730::nested::{hash_struct, hash_struct_array};
    let order_info_th = hx32("7daca11202c64729871927c37d75933f1852e430627cd4b8f4844087e312e94b");
    let dutch_output_th = hx32("45058f030836a1ec7cb9636dad15d25676157364aaf76d8dad81a6b2c267610f");
    let edo_th = hx32("24d8514d0b2bd650779acf204b79c73859aaafd6fd011c00669d143a7b891419");
    let token_permissions_th =
        hx32("618358ac3db8dc274f0cd8829da7e234bd48cd73c4a740aede1adec9846d06a1");

    let word_addr = |a: [u8; 20]| {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    };
    let word_u = |n: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&n.to_be_bytes());
        w
    };
    let usdc = [0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e,
        0x9E, 0xb0, 0xcE, 0x36, 0x06, 0xeB, 0x48];
    let weth = [0xC0u8, 0x2a, 0xaA, 0x39, 0xb2, 0x23, 0xFE, 0x8D, 0x0A, 0x0e, 0x5C, 0x4F, 0x27,
        0xeA, 0xD9, 0x08, 0x3C, 0x75, 0x6C, 0xc2];
    let dai = [0x6Bu8, 0x17, 0x54, 0x74, 0xE8, 0x90, 0x94, 0xC4, 0x4D, 0xa9, 0x8b, 0x95, 0x4E,
        0xed, 0xeA, 0xC4, 0x95, 0x27, 0x1d, 0x0F];

    // permitted_ed (TokenPermissions: token, amount).
    let mut permitted_ed = std::vec![0u8; 64];
    permitted_ed[0..32].copy_from_slice(&word_addr(usdc));
    permitted_ed[32..64].copy_from_slice(&word_u(5_000_005)); // approve amount
    let permitted_word = hash_struct(&token_permissions_th, &permitted_ed);

    // info_ed (OrderInfo: reactor, swapper, nonce, deadline, validationContract, validationData).
    let mut info_ed = std::vec![0u8; 192];
    info_ed[0..32].copy_from_slice(&word_addr([0x22; 20])); // reactor (SHOWN)
    info_ed[32..64].copy_from_slice(&word_addr([0x33; 20])); // swapper (SHOWN)
    info_ed[64..96].copy_from_slice(&word_u(42)); // nonce (hidden)
    info_ed[96..128].copy_from_slice(&word_u(1_700_000_000)); // deadline (hidden)
    info_ed[128..160].copy_from_slice(&word_addr([0x44; 20])); // additionalValidationContract (SHOWN)
    info_ed[160..192].copy_from_slice(&[0xAB; 32]); // additionalValidationData word (hidden bytes hash)
    let info_word = hash_struct(&order_info_th, &info_ed);

    // out_i_ed (DutchOutput: token, startAmount, endAmount, recipient).
    let mk_out = |token: [u8; 20], end: u64, recip: [u8; 20]| {
        let mut o = std::vec![0u8; 128];
        o[0..32].copy_from_slice(&word_addr(token));
        o[32..64].copy_from_slice(&word_u(1)); // startAmount (hidden)
        o[64..96].copy_from_slice(&word_u(end)); // endAmount (SHOWN)
        o[96..128].copy_from_slice(&word_addr(recip)); // recipient (SHOWN)
        o
    };
    let out0 = mk_out(dai, 2_000_002, [0x66; 20]);
    let out1 = mk_out(usdc, 3_000_003, [0x66; 20]);
    let outputs_word = hash_struct_array(&dutch_output_th, &[&out0[..], &out1[..]]);

    // witness_ed (ExclusiveDutchOrder, 9 words).
    let mut witness_ed = std::vec![0u8; 288];
    witness_ed[0..32].copy_from_slice(&info_word); // info (depth-2 struct)
    witness_ed[32..64].copy_from_slice(&word_u(1_699_000_000)); // decayStartTime (hidden)
    witness_ed[64..96].copy_from_slice(&word_u(1_699_500_000)); // decayEndTime (hidden)
    witness_ed[96..128].copy_from_slice(&word_addr([0x55; 20])); // exclusiveFiller (SHOWN)
    witness_ed[128..160].copy_from_slice(&word_u(0)); // exclusivityOverrideBps (hidden)
    witness_ed[160..192].copy_from_slice(&word_addr(weth)); // inputToken (covered via tokenPath)
    witness_ed[192..224].copy_from_slice(&word_u(1_000_001)); // inputStartAmount (SHOWN)
    witness_ed[224..256].copy_from_slice(&word_u(900_000)); // inputEndAmount (hidden)
    witness_ed[256..288].copy_from_slice(&outputs_word); // outputs (depth-2 array)
    let witness_word = hash_struct(&edo_th, &witness_ed);

    // top_ed (PermitWitnessTransferFrom, 5 words).
    let mut top_ed = std::vec![0u8; 160];
    top_ed[0..32].copy_from_slice(&permitted_word); // permitted
    top_ed[32..64].copy_from_slice(&word_addr([0x11; 20])); // spender (SHOWN)
    top_ed[64..96].copy_from_slice(&word_u(7)); // nonce (hidden)
    top_ed[96..128].copy_from_slice(&word_u(1_735_689_600)); // deadline 2025-01-01 (SHOWN date)
    top_ed[128..160].copy_from_slice(&witness_word); // witness

    // nested_blob DFS: permitted | witness | info | {elem_count=2, out0, out1}.
    let mut blob = std::vec::Vec::new();
    let push_rec = |blob: &mut std::vec::Vec<u8>, ed: &[u8]| {
        blob.extend_from_slice(&(ed.len() as u16).to_be_bytes());
        blob.extend_from_slice(ed);
    };
    push_rec(&mut blob, &permitted_ed);
    push_rec(&mut blob, &witness_ed);
    push_rec(&mut blob, &info_ed);
    blob.extend_from_slice(&2u16.to_be_bytes()); // outputs elem_count
    push_rec(&mut blob, &out0);
    push_rec(&mut blob, &out1);

    (top_ed, blob)
}

/// (a) The decisive DEPTH-2 render: a real 2-output ExclusiveDutchOrder clear-signs
/// through the recursive descent — top spender, the depth-2 `info` addresses
/// (reactor/swapper/validationContract, curated SHOW), the depth-1 exclusiveFiller,
/// the nested `outputs[]` array (per-element endAmount + recipient with dividers),
/// the tokenAmounts, and the deadline date. A decline here means the DFS order /
/// recursion / chained binding is wrong (the render `.expect()`s success).
#[test]
fn v3_exclusive_dutch_order_renders_deep_nested() {
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-UniswapX-ExclusiveDutchOrder.json", 1);
    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("ExclusiveDutchOrder IR parses");
    let pth = hx32(EXCLUSIVE_DUTCH_PRIMARY);
    let (top_ed, blob) = exclusive_dutch_vectors();
    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    let pages = super::erc7730::render_erc7730_eip712_pages_v3(
        1, &[0u8; 20], &pth, &top_ed, &blob, &verified, None, &resolver,
    )
    .expect("valid ExclusiveDutchOrder clear-signs via V3 (depth-2 recursion)");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    // top-level spender (0x11..).
    assert!(dump.contains("1111111111111111"), "spender must be shown:\n{dump}");
    // depth-2 OrderInfo addresses (the curated SHOW — reactor/swapper/validation).
    assert!(dump.contains("2222222222222222"), "info.reactor must render (depth 2):\n{dump}");
    assert!(dump.contains("3333333333333333"), "info.swapper must render (depth 2):\n{dump}");
    assert!(dump.contains("4444444444444444"), "info.validationContract must render (depth 2):\n{dump}");
    // depth-1 exclusiveFiller (curated SHOW).
    assert!(dump.contains("5555555555555555"), "exclusiveFiller must render:\n{dump}");
    // depth-2 nested-array outputs: recipients + per-element endAmounts + dividers.
    assert!(dump.contains("6666666666666666"), "output recipient must render:\n{dump}");
    assert!(dump.contains("2000002"), "out0 endAmount must render:\n{dump}");
    assert!(dump.contains("3000003"), "out1 endAmount must render:\n{dump}");
    assert!(dump.contains("item 1 of 2"), "output element 0 divider:\n{dump}");
    assert!(dump.contains("item 2 of 2"), "output element 1 divider:\n{dump}");
    // witness.inputStartAmount ("Spend max") + permitted amount + deadline date.
    assert!(dump.contains("1000001"), "inputStartAmount must render:\n{dump}");
    assert!(dump.contains("5000005"), "permitted amount must render:\n{dump}");
    assert!(dump.contains("2025"), "deadline date must render:\n{dump}");
}

/// (b) THE decisive DEPTH-2 non-vacuity proof: the chained binding must be live
/// at EVERY depth. Flipping ANY single bit of the `nested_blob` (any word of
/// permitted / witness / info / either output element — shown OR hidden — or any
/// record length / elem_count) OR either top-level committed word (permitted @0,
/// witness @4) flips the render to DECLINE. If any flip still rendered, that byte
/// would be signed-bound but unchecked — the WYSIWYS break this test exists to
/// catch. (a) alone passes even if the deep binding is never verified; (b) proves
/// shown ⟺ signed through the whole tree.
#[test]
fn v3_exclusive_dutch_binding_is_non_vacuous() {
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-UniswapX-ExclusiveDutchOrder.json", 1);
    let pth = hx32(EXCLUSIVE_DUTCH_PRIMARY);
    let (top_ed, blob) = exclusive_dutch_vectors();

    let render = |ed: &[u8], b: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("EDO IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &pth, ed, b, &verified, None, &resolver,
        )
    };

    assert!(render(&top_ed, &blob).is_ok(), "baseline must render");

    // (b1) Flip EVERY byte of the WHOLE nested_blob (every ed word at depths 1
    // AND 2 — shown and hidden — plus every record-length header and the
    // elem_count). Each is bound: an ed flip breaks a chained hashStruct; a
    // length/count flip mis-parses a record → length mismatch / OOB. All DECLINE.
    for i in 0..blob.len() {
        let mut b = blob.clone();
        b[i] ^= 0x01;
        assert!(
            render(&top_ed, &b).is_err(),
            "flipping nested_blob byte {i} must decline (binding live at all depths)"
        );
    }

    // (b2) Flip every byte of the two TOP-LEVEL committed words (permitted @word0,
    // witness @word4) — the roots of the two binding chains. DECLINE.
    for byte in (0..32).chain(128..160) {
        let mut ed = top_ed.clone();
        ed[byte] ^= 0x01;
        assert!(
            render(&ed, &blob).is_err(),
            "flipping top committed byte {byte} must decline"
        );
    }
}

/// (c) The E1 reconciliation FIRES at depth 2: the ExclusiveDutchOrder pins
/// `nested_descent_count = 4` (permitted + witness + info + outputs — counted
/// RECURSIVELY). Patch that byte to a wrong value → the after-render
/// `records_consumed(4) != nested_descent_count` check declines. This is the ONLY
/// exerciser of the reconciliation reject path at depth 2 (every blob-flip in (b)
/// rejects at a BINDING first). Proves dbgen counts sub-anchors recursively AND
/// the device compares the pinned count.
#[test]
fn v3_exclusive_dutch_reconciliation_rejects_wrong_pinned_descent_count() {
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-UniswapX-ExclusiveDutchOrder.json", 1);
    let pth = hx32(EXCLUSIVE_DUTCH_PRIMARY);
    let (top_ed, blob) = exclusive_dutch_vectors();
    let ndc_off = eip712_format_ndc_offset(&leaf.ir_bytes, &pth)
        .expect("ExclusiveDutchOrder format present in the shipped DB");

    let render_patched = |ndc: u8| {
        let mut ir_bytes = leaf.ir_bytes.clone();
        assert_eq!(
            ir_bytes[ndc_off], 4,
            "ExclusiveDutchOrder pins FOUR descent points (permitted+witness+info+outputs, recursive)"
        );
        ir_bytes[ndc_off] = ndc;
        let ir = Erc7730Ir::parse(&ir_bytes).expect("patched IR still parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &pth, &top_ed, &blob, &verified, None, &resolver,
        )
    };
    // Under-count (3, e.g. a regression that failed to count the depth-2 `info`
    // sub-anchor) and over-count (5) both mismatch records_consumed(4) → decline.
    assert!(render_patched(3).is_err(), "records_consumed(4) != pinned 3 must decline");
    assert!(render_patched(5).is_err(), "records_consumed(4) != pinned 5 must decline");
}

/// (d) Cross-struct DFS slot-confusion at depth 2 (E4-2, one level deeper than v1):
/// reordering the interior DFS records — feeding the `outputs` section where the
/// device expects the `info` record — must DECLINE. The device reads the next
/// record's `[u16 len]` (here the outputs `elem_count` = 2) as `info`'s length,
/// which ≠ OrderInfo's `member_count × 32` (192) → decline. A companion cannot
/// swap sub-trees behind a passing outer binding.
#[test]
fn v3_exclusive_dutch_reordered_records_decline() {
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-UniswapX-ExclusiveDutchOrder.json", 1);
    let pth = hx32(EXCLUSIVE_DUTCH_PRIMARY);
    let (top_ed, blob) = exclusive_dutch_vectors();
    // Blob layout: permitted[0..66] | witness[66..356] | info[356..550] | outputs[550..].
    // Swap the info record and the outputs section.
    let mut reordered = std::vec::Vec::new();
    reordered.extend_from_slice(&blob[0..356]); // permitted + witness (unchanged)
    reordered.extend_from_slice(&blob[550..]); // outputs section, now where info was
    reordered.extend_from_slice(&blob[356..550]); // info record, now last
    assert_eq!(reordered.len(), blob.len(), "reorder preserves total length");

    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("EDO IR parses");
    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    assert!(
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &pth, &top_ed, &reordered, &verified, None, &resolver,
        )
        .is_err(),
        "reordered interior DFS records (outputs where info expected) must decline"
    );
}

/// v3 second shipped descriptor: UniswapX plain `DutchOrder` (no exclusiveFiller /
/// exclusivityOverrideBps — a 7-member witness, otherwise identical machinery to
/// ExclusiveDutchOrder). Proves the recursion + curation are not EDO-specific: the
/// depth-2 `info` addresses + nested `outputs[]` array + tokenAmounts render, and a
/// flip of a depth-2 word (info) OR the top witness commitment declines.
#[test]
fn v3_dutch_order_renders_deep_nested_and_flip_declines() {
    use super::erc7730::nested::{hash_struct, hash_struct_array};
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-UniswapX-DutchOrder.json", 1);
    // PermitWitnessTransferFrom(...DutchOrder witness) primary type hash.
    let pth = hx32("f69aa722d3ed4edcfb9d5a29bf72a4d1fd0a2b90c570c4791dcde3f5dcd89c0b");
    let order_info_th = hx32("7daca11202c64729871927c37d75933f1852e430627cd4b8f4844087e312e94b");
    let dutch_output_th = hx32("45058f030836a1ec7cb9636dad15d25676157364aaf76d8dad81a6b2c267610f");
    let dutch_order_th = hx32("701a429bb9f0181256c459ce5000b7e7677ccc459ebb6229e1bd778e024a5973");
    let token_permissions_th =
        hx32("618358ac3db8dc274f0cd8829da7e234bd48cd73c4a740aede1adec9846d06a1");

    let wa = |a: [u8; 20]| {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    };
    let wu = |n: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&n.to_be_bytes());
        w
    };
    let weth = [0xC0u8, 0x2a, 0xaA, 0x39, 0xb2, 0x23, 0xFE, 0x8D, 0x0A, 0x0e, 0x5C, 0x4F, 0x27,
        0xeA, 0xD9, 0x08, 0x3C, 0x75, 0x6C, 0xc2];
    let dai = [0x6Bu8, 0x17, 0x54, 0x74, 0xE8, 0x90, 0x94, 0xC4, 0x4D, 0xa9, 0x8b, 0x95, 0x4E,
        0xed, 0xeA, 0xC4, 0x95, 0x27, 0x1d, 0x0F];

    // permitted (TokenPermissions: token, amount).
    let mut permitted_ed = std::vec![0u8; 64];
    permitted_ed[0..32].copy_from_slice(&wa(weth));
    permitted_ed[32..64].copy_from_slice(&wu(7_000_007));
    let permitted_word = hash_struct(&token_permissions_th, &permitted_ed);

    // info (OrderInfo, 6 words) — reactor/swapper/validationContract SHOWN.
    let mut info_ed = std::vec![0u8; 192];
    info_ed[0..32].copy_from_slice(&wa([0x2Au8; 20])); // reactor
    info_ed[32..64].copy_from_slice(&wa([0x3Au8; 20])); // swapper
    info_ed[64..96].copy_from_slice(&wu(9)); // nonce (hidden)
    info_ed[96..128].copy_from_slice(&wu(1_700_000_000)); // deadline (hidden)
    info_ed[128..160].copy_from_slice(&wa([0x4Au8; 20])); // validationContract
    info_ed[160..192].copy_from_slice(&[0xCD; 32]); // validationData word (hidden)
    let info_word = hash_struct(&order_info_th, &info_ed);

    // one output (DutchOutput: token, startAmount, endAmount, recipient).
    let mut out0 = std::vec![0u8; 128];
    out0[0..32].copy_from_slice(&wa(dai));
    out0[32..64].copy_from_slice(&wu(1));
    out0[64..96].copy_from_slice(&wu(4_000_004)); // endAmount SHOWN
    out0[96..128].copy_from_slice(&wa([0x6Au8; 20])); // recipient SHOWN
    let outputs_word = hash_struct_array(&dutch_output_th, &[&out0[..]]);

    // witness (DutchOrder, 7 words): info(0), decayStart(1), decayEnd(2),
    // inputToken(3), inputStartAmount(4), inputEnd(5), outputs(6).
    let mut witness_ed = std::vec![0u8; 224];
    witness_ed[0..32].copy_from_slice(&info_word);
    witness_ed[32..64].copy_from_slice(&wu(1_699_000_000));
    witness_ed[64..96].copy_from_slice(&wu(1_699_500_000));
    witness_ed[96..128].copy_from_slice(&wa(weth)); // inputToken (via tokenPath)
    witness_ed[128..160].copy_from_slice(&wu(8_000_008)); // inputStartAmount SHOWN
    witness_ed[160..192].copy_from_slice(&wu(7_000_000));
    witness_ed[192..224].copy_from_slice(&outputs_word);
    let witness_word = hash_struct(&dutch_order_th, &witness_ed);

    // top (PermitWitnessTransferFrom, 5 words).
    let mut top_ed = std::vec![0u8; 160];
    top_ed[0..32].copy_from_slice(&permitted_word);
    top_ed[32..64].copy_from_slice(&wa([0x1Au8; 20])); // spender SHOWN
    top_ed[64..96].copy_from_slice(&wu(11)); // nonce hidden
    top_ed[96..128].copy_from_slice(&wu(1_735_689_600)); // deadline 2025 SHOWN
    top_ed[128..160].copy_from_slice(&witness_word);

    // DFS blob: permitted | witness | info | {elem_count=1, out0}.
    let mut blob = std::vec::Vec::new();
    let push_rec = |b: &mut std::vec::Vec<u8>, ed: &[u8]| {
        b.extend_from_slice(&(ed.len() as u16).to_be_bytes());
        b.extend_from_slice(ed);
    };
    push_rec(&mut blob, &permitted_ed);
    push_rec(&mut blob, &witness_ed);
    push_rec(&mut blob, &info_ed);
    blob.extend_from_slice(&1u16.to_be_bytes()); // elem_count = 1
    push_rec(&mut blob, &out0);

    let render = |ed: &[u8], b: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("DutchOrder IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &pth, ed, b, &verified, None, &resolver,
        )
    };

    let pages = render(&top_ed, &blob).expect("valid DutchOrder clear-signs (depth-2)");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    assert!(dump.contains("2a2a2a2a2a2a"), "info.reactor (depth 2):\n{dump}");
    assert!(dump.contains("3a3a3a3a3a3a"), "info.swapper (depth 2):\n{dump}");
    assert!(dump.contains("4a4a4a4a4a4a"), "info.validationContract (depth 2):\n{dump}");
    assert!(dump.contains("6a6a6a6a6a6a"), "output recipient (depth 2):\n{dump}");
    assert!(dump.contains("4000004"), "out0 endAmount:\n{dump}");
    assert!(dump.contains("8000008"), "inputStartAmount:\n{dump}");
    assert!(dump.contains("item 1 of 1"), "single-output divider:\n{dump}");

    // Flip a depth-2 info word → info binding breaks → decline. Blob layout:
    // permitted[2..66] | witness[68..292] | info[294..486] | ...
    let mut b = blob.clone();
    b[300] ^= 0x01; // inside info_ed (reactor word)
    assert!(render(&top_ed, &b).is_err(), "flip depth-2 info word declines");
    // Flip the top witness commitment → decline.
    let mut ed = top_ed.clone();
    ed[140] ^= 0x01; // inside witness_word (top word 4)
    assert!(render(&ed, &blob).is_err(), "flip top witness commitment declines");
}

/// v3 corpus-wide safety: the recursive descent is a GENERAL capability, so it
/// also recompiled other pre-existing nested EIP-712 descriptors (e.g. Rarible
/// ExchangeV2 `makeAsset`/`takeAsset`) from flat records into v0x03 anchors. This
/// asserts the whole corpus's nested-EIP-712 leaves are PANIC-SAFE and fail-closed:
/// every format carrying a nested anchor, fed a benign-but-wrong `nested_blob`
/// (empty / zeros / all-0xFF adversarial lengths), must return a `Result`
/// (Ok or a decline) WITHOUT panicking / OOB — the recursion + `read_next_nested_ed`
/// bounds-checks hold for every shipped descriptor, not just the UniswapX targets.
#[test]
fn v3_all_nested_eip712_leaves_are_panic_safe_and_fail_closed() {
    let res = build_registry();
    let resolver = NameResolver::new();
    let mut nested_leaf_formats = 0usize;
    for entry in res.entries.iter() {
        let Ok(ir) = Erc7730Ir::parse(&entry.ir_bytes) else { continue };
        if !matches!(ir.context_kind, ContextKind::Eip712) {
            continue;
        }
        let chain = ir.chain_id;
        let contract = ir.contract;
        for format in ir.format_iter() {
            let Ok(fmt) = format else { continue };
            if fmt.nested_descent_count == 0 {
                continue; // no nested anchor in this format
            }
            nested_leaf_formats += 1;
            let pth = fmt.type_hash;
            let ed = std::vec![0u8; fmt.static_head_words as usize * 32];
            for blob in [
                std::vec::Vec::new(),
                std::vec![0u8; 64],
                std::vec![0xFFu8; 300],
            ] {
                let verified = VerifiedDescriptor {
                    ir: Erc7730Ir::parse(&entry.ir_bytes).unwrap(),
                };
                // A wrong blob must decline (Err), never render a mis-bound page and
                // never panic. We assert only "does not panic + returns Result";
                // the render function's own bounds-checks do the rest.
                let _ = super::erc7730::render_erc7730_eip712_pages_v3(
                    chain, &contract, &pth, &ed, &blob, &verified, None, &resolver,
                );
            }
        }
    }
    // permit2 (Single/Batch/TransferFrom) + UniswapX Dutch/ExclusiveDutch + Rarible
    // ExchangeV2/wrapper/erc-721/erc-1155 × many chains → dozens of nested formats.
    assert!(
        nested_leaf_formats >= 8,
        "expected many nested EIP-712 leaf-formats across the corpus, got {nested_leaf_formats}"
    );
}

/// v3 third shipped order: UniswapX `LimitOrder`. Element struct is
/// `OutputToken(token, amount, recipient)` — 3 members (no decay/startAmount);
/// witness `LimitOrder(info, inputToken, inputAmount, outputs)` — 4 members.
/// Same depth-2 recursion + curation as the Dutch orders; proves the machinery
/// handles a different element/witness shape.
#[test]
fn v3_limit_order_renders_deep_nested_and_flip_declines() {
    use super::erc7730::nested::{hash_struct, hash_struct_array};
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-UniswapX-LimitOrder.json", 1);
    let pth = hx32("e35e6a28e8d076114130d5989df14ccf68b92dc3ed629938e43f54ab543d79bb");
    let order_info_th = hx32("7daca11202c64729871927c37d75933f1852e430627cd4b8f4844087e312e94b");
    let output_token_th = hx32("46cd70b1b585091773aef9064bdcdd0dbe1268072af330b4abfccf1bdf7b4d7b");
    let limit_order_th = hx32("a7d1cc35867af6b68aad3c7171d2f51fc824592dd93d17c26bb4c65da6cec678");
    let token_permissions_th =
        hx32("618358ac3db8dc274f0cd8829da7e234bd48cd73c4a740aede1adec9846d06a1");
    let wa = |a: [u8; 20]| {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    };
    let wu = |n: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&n.to_be_bytes());
        w
    };
    let weth = [0xC0u8, 0x2a, 0xaA, 0x39, 0xb2, 0x23, 0xFE, 0x8D, 0x0A, 0x0e, 0x5C, 0x4F, 0x27,
        0xeA, 0xD9, 0x08, 0x3C, 0x75, 0x6C, 0xc2];
    let dai = [0x6Bu8, 0x17, 0x54, 0x74, 0xE8, 0x90, 0x94, 0xC4, 0x4D, 0xa9, 0x8b, 0x95, 0x4E,
        0xed, 0xeA, 0xC4, 0x95, 0x27, 0x1d, 0x0F];

    let mut permitted_ed = std::vec![0u8; 64];
    permitted_ed[0..32].copy_from_slice(&wa(weth));
    permitted_ed[32..64].copy_from_slice(&wu(6_000_006));
    let permitted_word = hash_struct(&token_permissions_th, &permitted_ed);

    let mut info_ed = std::vec![0u8; 192];
    info_ed[0..32].copy_from_slice(&wa([0x2b; 20])); // reactor
    info_ed[32..64].copy_from_slice(&wa([0x3b; 20])); // swapper
    info_ed[64..96].copy_from_slice(&wu(5));
    info_ed[96..128].copy_from_slice(&wu(1_700_000_000));
    info_ed[128..160].copy_from_slice(&wa([0x4b; 20])); // validationContract
    info_ed[160..192].copy_from_slice(&[0xEE; 32]);
    let info_word = hash_struct(&order_info_th, &info_ed);

    // OutputToken: token, amount, recipient (3 words).
    let mut out0 = std::vec![0u8; 96];
    out0[0..32].copy_from_slice(&wa(dai));
    out0[32..64].copy_from_slice(&wu(5_000_005)); // amount SHOWN
    out0[64..96].copy_from_slice(&wa([0x6b; 20])); // recipient SHOWN
    let outputs_word = hash_struct_array(&output_token_th, &[&out0[..]]);

    // LimitOrder: info, inputToken, inputAmount, outputs (4 words).
    let mut witness_ed = std::vec![0u8; 128];
    witness_ed[0..32].copy_from_slice(&info_word);
    witness_ed[32..64].copy_from_slice(&wa(weth)); // inputToken (tokenPath)
    witness_ed[64..96].copy_from_slice(&wu(9_000_009)); // inputAmount SHOWN
    witness_ed[96..128].copy_from_slice(&outputs_word);
    let witness_word = hash_struct(&limit_order_th, &witness_ed);

    let mut top_ed = std::vec![0u8; 160];
    top_ed[0..32].copy_from_slice(&permitted_word);
    top_ed[32..64].copy_from_slice(&wa([0x1b; 20])); // spender SHOWN
    top_ed[64..96].copy_from_slice(&wu(13));
    top_ed[96..128].copy_from_slice(&wu(1_735_689_600)); // deadline SHOWN
    top_ed[128..160].copy_from_slice(&witness_word);

    let mut blob = std::vec::Vec::new();
    let push_rec = |b: &mut std::vec::Vec<u8>, ed: &[u8]| {
        b.extend_from_slice(&(ed.len() as u16).to_be_bytes());
        b.extend_from_slice(ed);
    };
    push_rec(&mut blob, &permitted_ed);
    push_rec(&mut blob, &witness_ed);
    push_rec(&mut blob, &info_ed);
    blob.extend_from_slice(&1u16.to_be_bytes());
    push_rec(&mut blob, &out0);

    let render = |ed: &[u8], b: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("LimitOrder IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &pth, ed, b, &verified, None, &resolver,
        )
    };
    let pages = render(&top_ed, &blob).expect("valid LimitOrder clear-signs (depth-2)");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    assert!(dump.contains("2b2b2b2b2b2b"), "info.reactor:\n{dump}");
    assert!(dump.contains("3b3b3b3b3b3b"), "info.swapper:\n{dump}");
    assert!(dump.contains("4b4b4b4b4b4b"), "info.validationContract:\n{dump}");
    assert!(dump.contains("6b6b6b6b6b6b"), "output recipient:\n{dump}");
    assert!(dump.contains("5000005"), "OutputToken.amount:\n{dump}");
    assert!(dump.contains("9000009"), "inputAmount:\n{dump}");
    assert!(dump.contains("item 1 of 1"), "single-output divider:\n{dump}");
    // Blob: permitted[2..66] | witness[68..196] | info[198..390] | ...
    let mut b = blob.clone();
    b[200] ^= 0x01; // inside info_ed (reactor word)
    assert!(render(&top_ed, &b).is_err(), "flip depth-2 info word declines");
    let mut ed = top_ed.clone();
    ed[140] ^= 0x01; // inside witness_word (top word 4)
    assert!(render(&ed, &blob).is_err(), "flip top witness commitment declines");
}

/// v3 fourth shipped order: UniswapX `V2DutchOrder`. Adds a `cosigner` address
/// (curated SHOW, like exclusiveFiller) and `baseInput*`/`baseOutputs` naming;
/// element struct is `DutchOutput` (4 words). Same depth-2 recursion + curation.
#[test]
fn v3_v2_dutch_order_renders_deep_nested_and_flip_declines() {
    use super::erc7730::nested::{hash_struct, hash_struct_array};
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-uniswap-V2DutchOrder.json", 1);
    let pth = hx32("a8cc1ce2c3d1c6f1ff0072b7a47d6e2876fef4f7f92648cd166fdd6dec0a7465");
    let order_info_th = hx32("7daca11202c64729871927c37d75933f1852e430627cd4b8f4844087e312e94b");
    let dutch_output_th = hx32("45058f030836a1ec7cb9636dad15d25676157364aaf76d8dad81a6b2c267610f");
    let v2_dutch_th = hx32("329eaec63622cb5aa75f27611d76543f9d296718b239698143334aac9a0ea378");
    let token_permissions_th =
        hx32("618358ac3db8dc274f0cd8829da7e234bd48cd73c4a740aede1adec9846d06a1");
    let wa = |a: [u8; 20]| {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    };
    let wu = |n: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&n.to_be_bytes());
        w
    };
    let weth = [0xC0u8, 0x2a, 0xaA, 0x39, 0xb2, 0x23, 0xFE, 0x8D, 0x0A, 0x0e, 0x5C, 0x4F, 0x27,
        0xeA, 0xD9, 0x08, 0x3C, 0x75, 0x6C, 0xc2];
    let dai = [0x6Bu8, 0x17, 0x54, 0x74, 0xE8, 0x90, 0x94, 0xC4, 0x4D, 0xa9, 0x8b, 0x95, 0x4E,
        0xed, 0xeA, 0xC4, 0x95, 0x27, 0x1d, 0x0F];

    let mut permitted_ed = std::vec![0u8; 64];
    permitted_ed[0..32].copy_from_slice(&wa(weth));
    permitted_ed[32..64].copy_from_slice(&wu(6_000_006));
    let permitted_word = hash_struct(&token_permissions_th, &permitted_ed);

    let mut info_ed = std::vec![0u8; 192];
    info_ed[0..32].copy_from_slice(&wa([0x2c; 20]));
    info_ed[32..64].copy_from_slice(&wa([0x3c; 20]));
    info_ed[64..96].copy_from_slice(&wu(5));
    info_ed[96..128].copy_from_slice(&wu(1_700_000_000));
    info_ed[128..160].copy_from_slice(&wa([0x4c; 20]));
    info_ed[160..192].copy_from_slice(&[0xEE; 32]);
    let info_word = hash_struct(&order_info_th, &info_ed);

    // DutchOutput: token, startAmount(hidden), endAmount, recipient (4 words).
    let mut out0 = std::vec![0u8; 128];
    out0[0..32].copy_from_slice(&wa(dai));
    out0[32..64].copy_from_slice(&wu(1));
    out0[64..96].copy_from_slice(&wu(4_000_004)); // endAmount SHOWN
    out0[96..128].copy_from_slice(&wa([0x6c; 20])); // recipient SHOWN
    let outputs_word = hash_struct_array(&dutch_output_th, &[&out0[..]]);

    // V2DutchOrder: info, cosigner, baseInputToken, baseInputStartAmount,
    // baseInputEndAmount, baseOutputs (6 words).
    let mut witness_ed = std::vec![0u8; 192];
    witness_ed[0..32].copy_from_slice(&info_word);
    witness_ed[32..64].copy_from_slice(&wa([0x5c; 20])); // cosigner SHOWN
    witness_ed[64..96].copy_from_slice(&wa(weth)); // baseInputToken (tokenPath)
    witness_ed[96..128].copy_from_slice(&wu(8_000_008)); // baseInputStartAmount SHOWN
    witness_ed[128..160].copy_from_slice(&wu(7_000_000)); // baseInputEndAmount (hidden)
    witness_ed[160..192].copy_from_slice(&outputs_word);
    let witness_word = hash_struct(&v2_dutch_th, &witness_ed);

    let mut top_ed = std::vec![0u8; 160];
    top_ed[0..32].copy_from_slice(&permitted_word);
    top_ed[32..64].copy_from_slice(&wa([0x1c; 20])); // spender SHOWN
    top_ed[64..96].copy_from_slice(&wu(13));
    top_ed[96..128].copy_from_slice(&wu(1_735_689_600));
    top_ed[128..160].copy_from_slice(&witness_word);

    let mut blob = std::vec::Vec::new();
    let push_rec = |b: &mut std::vec::Vec<u8>, ed: &[u8]| {
        b.extend_from_slice(&(ed.len() as u16).to_be_bytes());
        b.extend_from_slice(ed);
    };
    push_rec(&mut blob, &permitted_ed);
    push_rec(&mut blob, &witness_ed);
    push_rec(&mut blob, &info_ed);
    blob.extend_from_slice(&1u16.to_be_bytes());
    push_rec(&mut blob, &out0);

    let render = |ed: &[u8], b: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("V2DutchOrder IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &pth, ed, b, &verified, None, &resolver,
        )
    };
    let pages = render(&top_ed, &blob).expect("valid V2DutchOrder clear-signs (depth-2)");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    assert!(dump.contains("2c2c2c2c2c2c"), "info.reactor:\n{dump}");
    assert!(dump.contains("3c3c3c3c3c3c"), "info.swapper:\n{dump}");
    assert!(dump.contains("4c4c4c4c4c4c"), "info.validationContract:\n{dump}");
    assert!(dump.contains("5c5c5c5c5c5c"), "cosigner (curated SHOW):\n{dump}");
    assert!(dump.contains("6c6c6c6c6c6c"), "output recipient:\n{dump}");
    assert!(dump.contains("4000004"), "baseOutputs endAmount:\n{dump}");
    assert!(dump.contains("8000008"), "baseInputStartAmount:\n{dump}");
    assert!(dump.contains("item 1 of 1"), "single-output divider:\n{dump}");
    // Blob: permitted[2..66] | witness[68..260] | info[262..454] | ...
    let mut b = blob.clone();
    b[264] ^= 0x01; // inside info_ed
    assert!(render(&top_ed, &b).is_err(), "flip depth-2 info word declines");
    let mut ed = top_ed.clone();
    ed[140] ^= 0x01; // inside witness_word
    assert!(render(&ed, &blob).is_err(), "flip top witness commitment declines");
}

/// Nested `tokenAmount` FULL vocabulary (threshold + message) in a top-level
/// array-of-struct: flyingtulip SessionManager `Session(...AssetLimit[] limits...)`.
/// Each `AssetLimit(token, limit)` renders `limit` as a tokenAmount whose
/// `threshold = max-uint` maps to the message "Unlimited" — the same "approve
/// unlimited" display the top-level path has, now reachable inside a nested
/// element. Proves the dbgen nested-subfield vocabulary extension end-to-end
/// (element 0 = a normal limit renders the number; element 1 = max-uint renders
/// "Unlimited").
#[test]
fn v3_session_manager_nested_tokenamount_threshold_renders_unlimited() {
    use super::erc7730::nested::{hash_struct, hash_struct_array};
    let res = build_registry();
    let leaf = find_leaf(res, "eip712-SessionManager-FT.json", 1);
    let pth = hx32("10e2e916a5d944a9c9fa82748951934e444783850c4cb366694967607dbd2fc5");
    let asset_limit_th = hx32("269888c0029efe9424c548a264e5ee66803094ad203b068ca44e278b02db9d6f");
    let wa = |a: [u8; 20]| {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    };
    let wu = |n: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&n.to_be_bytes());
        w
    };
    let usdc = [0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e,
        0x9E, 0xb0, 0xcE, 0x36, 0x06, 0xeB, 0x48];
    let weth = [0xC0u8, 0x2a, 0xaA, 0x39, 0xb2, 0x23, 0xFE, 0x8D, 0x0A, 0x0e, 0x5C, 0x4F, 0x27,
        0xeA, 0xD9, 0x08, 0x3C, 0x75, 0x6C, 0xc2];

    // AssetLimit: token, limit (2 words). el0 normal, el1 = max-uint → "Unlimited".
    let mut el0 = std::vec![0u8; 64];
    el0[0..32].copy_from_slice(&wa(usdc));
    el0[32..64].copy_from_slice(&wu(1_000_001)); // a finite limit
    let mut el1 = std::vec![0u8; 64];
    el1[0..32].copy_from_slice(&wa(weth));
    el1[32..64].copy_from_slice(&[0xFFu8; 32]); // max-uint => >= threshold => "Unlimited"
    let limits_word = hash_struct_array(&asset_limit_th, &[&el0[..], &el1[..]]);
    let _ = hash_struct; // (single-struct primitive unused here; array path only)

    // Session top_ed (8 words): owner, delegate, validAfter, validUntil, maxCalls,
    // maxFeeBps, limits, salt.
    let mut top_ed = std::vec![0u8; 256];
    top_ed[0..32].copy_from_slice(&wa([0x71; 20])); // owner
    top_ed[32..64].copy_from_slice(&wa([0x72; 20])); // delegate
    top_ed[64..96].copy_from_slice(&wu(1_735_689_600)); // validAfter (2025)
    top_ed[96..128].copy_from_slice(&wu(1_767_225_600)); // validUntil (2026)
    top_ed[128..160].copy_from_slice(&wu(50)); // maxCalls
    top_ed[160..192].copy_from_slice(&wu(30)); // maxFeeBps
    top_ed[192..224].copy_from_slice(&limits_word); // limits (array)
    top_ed[224..256].copy_from_slice(&[0xAB; 32]); // salt (hidden)

    // nested_blob: the single `limits` array descent — [elem_count=2][el0][el1].
    let mut blob = std::vec::Vec::new();
    blob.extend_from_slice(&2u16.to_be_bytes());
    blob.extend_from_slice(&64u16.to_be_bytes());
    blob.extend_from_slice(&el0);
    blob.extend_from_slice(&64u16.to_be_bytes());
    blob.extend_from_slice(&el1);

    let render = |ed: &[u8], b: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("SessionManager IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &pth, ed, b, &verified, None, &resolver,
        )
    };
    let pages = render(&top_ed, &blob).expect("valid SessionManager clear-signs");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    assert!(dump.contains("7171717171"), "owner shown:\n{dump}");
    assert!(dump.contains("7272727272"), "delegate shown:\n{dump}");
    assert!(dump.contains("2025") && dump.contains("2026"), "validAfter/Until dates:\n{dump}");
    assert!(dump.contains("1000001"), "element 0 finite limit renders the number:\n{dump}");
    assert!(dump.contains("unlimited"), "element 1 (max-uint) renders the threshold message 'Unlimited':\n{dump}");
    assert!(dump.contains("item 1 of 2") && dump.contains("item 2 of 2"), "per-element dividers:\n{dump}");
    // Flip a nested word (element 1's limit) → array binding breaks → decline.
    let mut b = blob.clone();
    b[2 + 2 + 64 + 2 + 40] ^= 0x01; // inside el1's limit word
    assert!(render(&top_ed, &b).is_err(), "flip el1 limit declines");
}
